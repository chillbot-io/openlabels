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

# Check if docker-compose is available
if ! command -v docker-compose &> /dev/null && ! command -v docker &> /dev/null; then
    echo -e "${RED}Error: docker or docker-compose not found${NC}"
    echo "Please install Docker to run integration tests."
    exit 1
fi

# Use 'docker compose' (v2) or 'docker-compose' (v1)
if docker compose version &> /dev/null 2>&1; then
    COMPOSE_CMD="docker compose"
else
    COMPOSE_CMD="docker-compose"
fi

# Start test infrastructure
echo -e "\n${YELLOW}Starting test infrastructure...${NC}"
cd "$PROJECT_ROOT"
$COMPOSE_CMD -f docker-compose.test.yml up -d

# Wait for services to be healthy
echo -e "\n${YELLOW}Waiting for services to be ready...${NC}"
sleep 3

# Check PostgreSQL
for i in {1..30}; do
    if $COMPOSE_CMD -f docker-compose.test.yml exec -T postgres pg_isready -U postgres &> /dev/null; then
        echo -e "${GREEN}PostgreSQL is ready${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}PostgreSQL failed to start${NC}"
        exit 1
    fi
    sleep 1
done

# Check Redis
for i in {1..30}; do
    if $COMPOSE_CMD -f docker-compose.test.yml exec -T redis redis-cli ping &> /dev/null; then
        echo -e "${GREEN}Redis is ready${NC}"
        break
    fi
    if [ $i -eq 30 ]; then
        echo -e "${RED}Redis failed to start${NC}"
        exit 1
    fi
    sleep 1
done

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

if [ $# -eq 0 ]; then
    # Default: run all tests except auth (which needs special setup)
    python -m pytest tests/ --ignore=tests/auth -v "$@"
else
    python -m pytest "$@"
fi

TEST_EXIT_CODE=$?

echo -e "\n${YELLOW}Test infrastructure is still running.${NC}"
echo "To stop: docker-compose -f docker-compose.test.yml down"
echo "To stop and remove data: docker-compose -f docker-compose.test.yml down -v"

exit $TEST_EXIT_CODE
