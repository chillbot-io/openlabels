#!/bin/bash
# Run OpenLabels tests with proper infrastructure
# Usage: ./scripts/run-tests.sh [pytest args...]
# Example: ./scripts/run-tests.sh tests/server/ -v

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}OpenLabels Test Runner${NC}"
echo "======================"

PG_READY=false
REDIS_READY=false

# ---------------------------------------------------------------------------
# Strategy 1: Try Docker Compose
# ---------------------------------------------------------------------------
start_docker_infra() {
    if ! command -v docker-compose &> /dev/null && ! command -v docker &> /dev/null; then
        return 1
    fi

    # Use 'docker compose' (v2) or 'docker-compose' (v1)
    if docker compose version &> /dev/null 2>&1; then
        COMPOSE_CMD="docker compose"
    else
        COMPOSE_CMD="docker-compose"
    fi

    echo -e "\n${YELLOW}Starting test infrastructure via Docker...${NC}"
    cd "$PROJECT_ROOT"
    if ! $COMPOSE_CMD -f docker-compose.test.yml up -d 2>/dev/null; then
        echo -e "${YELLOW}Docker Compose failed, will try system services${NC}"
        return 1
    fi

    sleep 3

    # Check PostgreSQL via Docker
    for i in {1..15}; do
        if $COMPOSE_CMD -f docker-compose.test.yml exec -T postgres pg_isready -U postgres &> /dev/null; then
            echo -e "${GREEN}PostgreSQL is ready (Docker)${NC}"
            PG_READY=true
            break
        fi
        sleep 1
    done

    # Check Redis via Docker
    for i in {1..15}; do
        if $COMPOSE_CMD -f docker-compose.test.yml exec -T redis redis-cli ping &> /dev/null; then
            echo -e "${GREEN}Redis is ready (Docker)${NC}"
            REDIS_READY=true
            break
        fi
        sleep 1
    done

    $PG_READY && $REDIS_READY
}

# ---------------------------------------------------------------------------
# Strategy 2: Use system PostgreSQL
# ---------------------------------------------------------------------------
start_system_postgres() {
    if ! command -v pg_isready &> /dev/null; then
        return 1
    fi

    echo -e "\n${YELLOW}Setting up system PostgreSQL...${NC}"

    # Fix SSL key permissions if needed (PostgreSQL refuses to start if the
    # private key is group/world-readable and not owned by root).
    SSL_KEY="/etc/ssl/private/ssl-cert-snakeoil.key"
    if [ -f "$SSL_KEY" ]; then
        PERMS=$(stat -c '%a' "$SSL_KEY" 2>/dev/null || true)
        OWNER=$(stat -c '%U' "$SSL_KEY" 2>/dev/null || true)
        if [ "$OWNER" != "root" ] && [ "$PERMS" != "600" ]; then
            chmod 600 "$SSL_KEY" 2>/dev/null || true
            echo "Fixed SSL key permissions"
        fi
    fi

    # Ensure pg_hba.conf allows local trust auth for postgres user.
    # If 'peer' appears before 'trust' for postgres, PostgreSQL will reject
    # local connections when the OS user is not 'postgres'.
    for PG_VER in 16 15; do
        HBA="/etc/postgresql/${PG_VER}/main/pg_hba.conf"
        if [ -f "$HBA" ]; then
            if grep -q '^local.*postgres.*peer' "$HBA" 2>/dev/null; then
                sed -i 's/^local\(.*postgres.*\)peer/# local\1peer  # commented out for trust auth/' "$HBA" 2>/dev/null || true
                # Preserve ownership so PostgreSQL can read the file
                chown --reference=/etc/postgresql/${PG_VER}/main/postgresql.conf "$HBA" 2>/dev/null || true
                echo "Fixed pg_hba.conf: commented out peer auth for postgres"
            fi
            break
        fi
    done

    # Start PostgreSQL if not running
    if ! pg_isready -h localhost -p 5432 &> /dev/null; then
        echo "Starting PostgreSQL..."
        pg_ctlcluster 16 main start 2>/dev/null || pg_ctlcluster 15 main start 2>/dev/null || true
        sleep 2
    fi

    # Wait for PostgreSQL
    for i in {1..15}; do
        if pg_isready -h localhost -p 5432 &> /dev/null; then
            echo -e "${GREEN}PostgreSQL is running${NC}"
            break
        fi
        if [ $i -eq 15 ]; then
            echo -e "${RED}PostgreSQL failed to start${NC}"
            return 1
        fi
        sleep 1
    done

    # Ensure postgres role has the test password and test database exists.
    # Try local socket first (trust/peer), fall back to TCP with password.
    if psql -U postgres -d postgres -c "SELECT 1" &> /dev/null; then
        PSQL_CMD="psql -U postgres -d postgres"
    elif PGPASSWORD=test psql -h localhost -U postgres -d postgres -c "SELECT 1" &> /dev/null; then
        PSQL_CMD="PGPASSWORD=test psql -h localhost -U postgres -d postgres"
    else
        echo -e "${RED}Cannot connect to PostgreSQL as postgres user${NC}"
        return 1
    fi

    # Set password (idempotent)
    eval $PSQL_CMD -c "ALTER ROLE postgres WITH PASSWORD 'test';" &> /dev/null

    # Create test database if it doesn't exist
    if ! eval $PSQL_CMD -c "SELECT 1 FROM pg_database WHERE datname='openlabels_test'" | grep -q 1; then
        eval $PSQL_CMD -c "CREATE DATABASE openlabels_test;" &> /dev/null
        echo -e "${GREEN}Created openlabels_test database${NC}"
    fi

    # Verify TCP connection with password works
    if PGPASSWORD=test psql -h localhost -U postgres -d openlabels_test -c "SELECT 1" &> /dev/null; then
        echo -e "${GREEN}PostgreSQL is ready (system)${NC}"
        PG_READY=true
    else
        echo -e "${RED}PostgreSQL TCP connection failed${NC}"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Strategy 2b: Use system Redis
# ---------------------------------------------------------------------------
start_system_redis() {
    if ! command -v redis-cli &> /dev/null; then
        return 1
    fi

    # Start Redis if not running
    if ! redis-cli ping &> /dev/null 2>&1; then
        echo "Starting Redis..."
        redis-server --daemonize yes 2>/dev/null || true
        sleep 1
    fi

    if redis-cli ping &> /dev/null 2>&1; then
        echo -e "${GREEN}Redis is ready (system)${NC}"
        REDIS_READY=true
    fi
}

# ---------------------------------------------------------------------------
# Main: try Docker first, fall back to system services
# ---------------------------------------------------------------------------
if ! start_docker_infra; then
    # Docker failed or unavailable, try system services
    if ! $PG_READY; then
        start_system_postgres || true
    fi
    if ! $REDIS_READY; then
        start_system_redis || true
    fi
fi

# Final checks
if ! $PG_READY; then
    echo -e "${RED}Error: PostgreSQL is not available${NC}"
    echo "Either start Docker or install PostgreSQL locally."
    exit 1
fi

if ! $REDIS_READY; then
    echo -e "${YELLOW}Warning: Redis not available, some tests may be skipped${NC}"
fi

# Set environment variables
export TEST_DATABASE_URL="postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"
export REDIS_URL="redis://localhost:6379"
export PYTHONPATH="$PROJECT_ROOT/src:$PYTHONPATH"

echo -e "\n${YELLOW}Environment:${NC}"
echo "  TEST_DATABASE_URL=$TEST_DATABASE_URL"
echo "  REDIS_URL=$REDIS_URL"

# Run tests
echo -e "\n${YELLOW}Running tests...${NC}"
cd "$PROJECT_ROOT"

# Use venv python if available, otherwise system python
PYTHON="python"
if [ -f "$PROJECT_ROOT/.venv/bin/python" ]; then
    PYTHON="$PROJECT_ROOT/.venv/bin/python"
fi

if [ $# -eq 0 ]; then
    # Default: run all tests except auth (which needs special setup)
    $PYTHON -m pytest tests/ --ignore=tests/auth -v "$@"
else
    $PYTHON -m pytest "$@"
fi

TEST_EXIT_CODE=$?

echo -e "\n${YELLOW}Test infrastructure is still running.${NC}"
echo "To stop Docker services: docker-compose -f docker-compose.test.yml down"
echo "To stop system PostgreSQL: pg_ctlcluster 16 main stop"

exit $TEST_EXIT_CODE
