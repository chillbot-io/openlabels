# OpenLabels API Server
FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    # For psycopg2
    libpq-dev \
    # For PDF processing
    libmupdf-dev \
    # For OCR
    tesseract-ocr \
    tesseract-ocr-eng \
    # For healthcheck
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy project metadata and source, then install
COPY pyproject.toml .
COPY README.md .
COPY src/ src/

RUN pip install --no-cache-dir .

# Copy migration assets
COPY alembic/ alembic/
COPY alembic.ini .

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
