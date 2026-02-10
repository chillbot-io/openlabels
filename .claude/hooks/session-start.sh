#!/bin/bash
set -euo pipefail

# Only run in remote (Claude Code on the web) environments
if [ "${CLAUDE_CODE_REMOTE:-}" != "true" ]; then
  exit 0
fi

PROJECT_DIR="${CLAUDE_PROJECT_DIR:-/home/user/openlabels}"

# -------------------------------------------------------
# 1. Install Python dependencies via uv
# -------------------------------------------------------
echo "Installing Python dependencies..."
cd "$PROJECT_DIR"
uv pip install -e ".[dev]" 2>&1 || true

# -------------------------------------------------------
# 2. Start PostgreSQL 16
# -------------------------------------------------------
echo "Setting up PostgreSQL..."

# Ensure pg_hba.conf allows trust auth for postgres and claude users
PG_HBA="/etc/postgresql/16/main/pg_hba.conf"
if [ -f "$PG_HBA" ]; then
  # Check if trust entry for postgres already exists
  if ! grep -q "^local.*all.*postgres.*trust" "$PG_HBA" 2>/dev/null; then
    # Insert trust lines before the default peer line
    sed -i '/^local\s\+all\s\+all\s\+peer/i local   all             postgres                                trust\nlocal   all             claude                                  trust' "$PG_HBA" 2>/dev/null || true
  fi
fi

# Start PostgreSQL if not running
if command -v pg_ctlcluster &> /dev/null; then
  if ! pg_isready -h localhost -p 5432 &> /dev/null 2>&1; then
    echo "Starting PostgreSQL 16..."
    pg_ctlcluster 16 main start 2>&1 || true
    # Wait for it to be ready
    for i in $(seq 1 15); do
      if pg_isready -h localhost -p 5432 &> /dev/null 2>&1; then
        break
      fi
      sleep 1
    done
  fi
fi

# Configure postgres role and test database
if pg_isready -h localhost -p 5432 &> /dev/null 2>&1; then
  echo "Configuring PostgreSQL for tests..."
  # Set password for postgres user (uses trust auth via local socket)
  psql -U postgres -d postgres -c "ALTER ROLE postgres WITH PASSWORD 'test';" 2>/dev/null || true
  # Create test database if it doesn't exist
  psql -U postgres -d postgres -c "SELECT 1 FROM pg_database WHERE datname='openlabels_test'" 2>/dev/null | grep -q 1 || \
    psql -U postgres -d postgres -c "CREATE DATABASE openlabels_test;" 2>/dev/null || true
  echo "PostgreSQL is ready."
else
  echo "WARNING: PostgreSQL failed to start."
fi

# -------------------------------------------------------
# 3. Start Redis
# -------------------------------------------------------
echo "Setting up Redis..."
if command -v redis-server &> /dev/null; then
  if ! redis-cli ping &> /dev/null 2>&1; then
    redis-server --daemonize yes 2>/dev/null || true
    sleep 1
  fi
  if redis-cli ping &> /dev/null 2>&1; then
    echo "Redis is ready."
  else
    echo "WARNING: Redis failed to start."
  fi
fi

# -------------------------------------------------------
# 4. Export environment variables for the session
# -------------------------------------------------------
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo 'export TEST_DATABASE_URL="postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"' >> "$CLAUDE_ENV_FILE"
  echo 'export REDIS_URL="redis://localhost:6379"' >> "$CLAUDE_ENV_FILE"
  echo "export PYTHONPATH=\"$PROJECT_DIR/src:\${PYTHONPATH:-}\"" >> "$CLAUDE_ENV_FILE"
fi

echo "Session start hook completed successfully."
