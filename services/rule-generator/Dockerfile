# Rule Generator Service - Dockerfile
# AI-Augmented SOC - LLM-Generated Detection Rules

FROM python:3.11-slim

LABEL version="1.0.0"
LABEL description="LLM-powered Sigma detection rule generator"

WORKDIR /app

RUN apt-get update && apt-get install -y curl gcc && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

RUN useradd -m -u 1000 ruleuser && chown -R ruleuser:ruleuser /app
USER ruleuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=10s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
