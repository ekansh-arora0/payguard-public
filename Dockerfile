# Multi-stage build for PayGuard backend
# Stage 1: Install dependencies
FROM python:3.11-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    python3-dev \
    libomp-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

RUN pip install --no-cache-dir --upgrade pip

COPY requirements.txt /build/

# Install CPU-only torch first (saves ~1GB vs full torch)
RUN pip install --no-cache-dir \
    torch==2.0.1 \
    torchvision==0.15.2 \
    --index-url https://download.pytorch.org/whl/cpu || \
    pip install --no-cache-dir torch==2.0.1 torchvision==0.15.2
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime image
FROM python:3.11-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV PYTHONPATH=/app

# Runtime-only system deps (no build-essential)
RUN apt-get update && apt-get install -y --no-install-recommends \
    tesseract-ocr \
    libgl1 \
    libglib2.0-0 \
    libomp5 \
    && rm -rf /var/lib/apt/lists/*

# Copy installed Python packages from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

WORKDIR /app

# Install playwright browsers (optional, ~400MB; set to "false" to skip)
ARG INSTALL_PLAYWRIGHT=true
RUN if [ "$INSTALL_PLAYWRIGHT" = "true" ]; then \
      playwright install chromium && playwright install-deps chromium; \
    fi

# Copy application code
COPY backend/ /app/backend/
COPY models/ /app/models/
COPY bert_phishing_detector/ /app/bert_phishing_detector/
COPY requirements.txt /app/

EXPOSE 8002

CMD ["uvicorn", "backend.server:app", "--host", "0.0.0.0", "--port", "8002"]
