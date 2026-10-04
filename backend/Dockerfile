# UniGuard Backend Container (Milestone 15)
# Python 3.12 slim image with non-root security execution

FROM python:3.12-slim

# Install system dependencies (libpcap for network capture/scapy, curl for container healthcheck)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpcap-dev \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged system user and group
RUN groupadd -g 1001 uniguard && \
    useradd -u 1001 -g uniguard -m -s /bin/bash uniguard

WORKDIR /app

# Install Python requirements
COPY backend/requirements.txt /app/backend/requirements.txt
RUN pip install --no-cache-dir -r /app/backend/requirements.txt

# Copy backend source code
COPY backend/ /app/backend/

# Create and set permissions for isolated PCAP storage
RUN mkdir -p /app/pcap_uploads && \
    chown -R uniguard:uniguard /app

ENV PYTHONPATH=/app
ENV PYTHONUNBUFFERED=1

# Run as non-root user
USER uniguard

EXPOSE 8000

# Healthcheck against liveness endpoint
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/api/health || exit 1

CMD ["uvicorn", "backend.app.main:app", "--host", "0.0.0.0", "--port", "8000"]
