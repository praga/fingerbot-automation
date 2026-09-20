FROM python:3.11-slim

# Install system dependencies for userspace USB Bluetooth & libusb
RUN apt-get update && apt-get install -y --no-install-recommends \
    libusb-1.0-0 \
    libatomic1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy dependency definition
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source code
COPY backend/ ./backend/
COPY frontend/ ./frontend/

# Create persistent data directory
RUN mkdir -p /app/data && chown -R 1000:1000 /app

ENV DATA_DIR=/app/data
ENV PYTHONUNBUFFERED=1

EXPOSE 8085

HEALTHCHECK --interval=30s --timeout=10s --retries=3 --start-period=15s \
  CMD curl -f http://localhost:8085/api/status || exit 1

CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8085"]
