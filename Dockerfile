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
COPY src/ src/

RUN pip install --no-cache-dir .

# Copy migration assets
COPY alembic/ alembic/
COPY alembic.ini .

# Create non-root user
RUN useradd -m -u 1000 openlabels && \
    chown -R openlabels:openlabels /app
USER openlabels

# Run database migrations and start server
CMD ["sh", "-c", "alembic upgrade head && uvicorn openlabels.server.app:app --host 0.0.0.0 --port 8000"]

EXPOSE 8000
