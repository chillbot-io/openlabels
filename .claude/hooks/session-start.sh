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
# 1b. Build Rust extension (openlabels_matcher) if rustc is available
# -------------------------------------------------------
RUST_EXT_DIR="$PROJECT_DIR/src/openlabels/core/_rust"
if command -v rustc &> /dev/null && [ -f "$RUST_EXT_DIR/Cargo.toml" ]; then
  echo "Building Rust pattern matcher..."
  uv pip install -e "$RUST_EXT_DIR" 2>&1 || echo "WARNING: Rust extension build failed (Python fallback will be used)"
else
  echo "Rust toolchain not found, skipping openlabels_matcher build (Python fallback will be used)"
fi

# -------------------------------------------------------
# 2. Purge orphaned PostgreSQL and Redis instances
# -------------------------------------------------------
echo "Purging orphaned processes..."

# Stop any orphaned PostgreSQL instances cleanly, then kill stragglers
if command -v pg_ctlcluster &> /dev/null; then
  pg_ctlcluster 16 main stop -- -m immediate 2>/dev/null || true
fi
# Kill any remaining postgres processes (orphaned from previous sessions)
pkill -9 -x postgres 2>/dev/null || true
# Remove stale pid and socket files
rm -f /var/run/postgresql/16-main.pid 2>/dev/null || true
rm -f /var/run/postgresql/.s.PGSQL.5432* 2>/dev/null || true
rm -f /var/lib/postgresql/16/main/postmaster.pid 2>/dev/null || true
sleep 1

# Kill any orphaned redis-server processes
pkill -9 -x redis-server 2>/dev/null || true
rm -f /var/run/redis/redis-server.pid 2>/dev/null || true
rm -f /tmp/redis.sock 2>/dev/null || true
sleep 1

echo "Orphaned processes purged."

# -------------------------------------------------------
# 3. Start PostgreSQL 16
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

# Start PostgreSQL fresh
echo "Starting PostgreSQL 16..."
if command -v pg_ctlcluster &> /dev/null; then
  pg_ctlcluster 16 main start 2>&1 || true
  # Wait for it to be ready
  for i in $(seq 1 15); do
    if pg_isready -h localhost -p 5432 &> /dev/null 2>&1; then
      break
    fi
    sleep 1
  done
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
# 4. Start Redis
# -------------------------------------------------------
echo "Setting up Redis..."
if command -v redis-server &> /dev/null; then
  redis-server --daemonize yes 2>/dev/null || true
  sleep 1
  if redis-cli ping &> /dev/null 2>&1; then
    echo "Redis is ready."
  else
    echo "WARNING: Redis failed to start."
  fi
fi

# -------------------------------------------------------
# 5. Export environment variables for the session
# -------------------------------------------------------
if [ -n "${CLAUDE_ENV_FILE:-}" ]; then
  echo 'export TEST_DATABASE_URL="postgresql+asyncpg://postgres:test@localhost:5432/openlabels_test"' >> "$CLAUDE_ENV_FILE"
  echo 'export REDIS_URL="redis://localhost:6379"' >> "$CLAUDE_ENV_FILE"
  echo "export PYTHONPATH=\"$PROJECT_DIR/src:\${PYTHONPATH:-}\"" >> "$CLAUDE_ENV_FILE"
fi

echo "Session start hook completed successfully."
