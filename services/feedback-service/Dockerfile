# Feedback Service - Dockerfile
# AI-Augmented SOC - Alert Persistence & Analyst Feedback

FROM python:3.11-slim

LABEL maintainer="abdul.bari8019@coyote.csusb.edu"
LABEL version="1.0.0"
LABEL description="Alert persistence and analyst feedback service"

WORKDIR /app

RUN apt-get update && apt-get install -y \
    curl \
    gcc \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 feedbackuser && chown -R feedbackuser:feedbackuser /app
USER feedbackuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=15s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "2"]
