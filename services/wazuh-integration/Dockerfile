# ============================================================================
# Wazuh Integration Service - Dockerfile
# AI-Augmented SOC
#
# FastAPI webhook receiver for Wazuh alerts with AI-powered analysis
# ============================================================================

FROM python:3.11-slim

# Metadata
LABEL maintainer="AI-SOC Team <z@onyxlab.ai>"
LABEL description="Wazuh-AI Integration Service: Intelligent alert webhook receiver"
LABEL version="1.0.0"

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    curl \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create non-root user
RUN useradd -m -u 1000 wazuh-integration && \
    chown -R wazuh-integration:wazuh-integration /app

USER wazuh-integration

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:8002/health || exit 1

# Expose port
EXPOSE 8002

# Run application
CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8002", "--log-level", "info"]
