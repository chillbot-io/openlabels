# OpenLabels API Server
# Multi-stage build for smaller production image

# ── Build stage ─────────────────────────────────────────────────────────
FROM python:3.11-slim AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and source, then install
COPY pyproject.toml README.md ./
COPY src/ src/

RUN pip install --no-cache-dir --prefix=/install .

# ── Production stage ────────────────────────────────────────────────────
FROM python:3.11-slim

WORKDIR /app

# Install runtime dependencies only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    libmupdf-dev \
    tesseract-ocr \
    tesseract-ocr-eng \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy installed packages from builder
COPY --from=builder /install /usr/local

# Copy migration assets
COPY alembic/ alembic/
COPY alembic.ini .

# Copy source for alembic env.py imports
COPY src/ src/

# Create non-root user
RUN useradd -m -u 1000 openlabels && \
    chown -R openlabels:openlabels /app
USER openlabels

# Database migrations should be run as a separate pre-deploy step or
# init container, NOT combined with the app server startup.  This
# prevents races when multiple replicas start simultaneously.
#
# Run migrations:  docker run --rm <image> alembic upgrade head
# Start server:    docker run <image>  (uses CMD below)

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "openlabels.server.app:app", "--host", "0.0.0.0", "--port", "8000"]
