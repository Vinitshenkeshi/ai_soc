# Wazuh Integration Service

AI-powered webhook receiver for Wazuh alerts with intelligent triage and enrichment.

## Overview

This service bridges Wazuh SIEM with AI-powered alert analysis:

1. **Receives** Wazuh alerts via webhook (POST /webhook)
2. **Transforms** alerts to standardized format
3. **Analyzes** with Alert Triage LLM service
4. **Enriches** high-severity alerts (>= 8) with RAG context
5. **Returns** structured analysis with recommendations

## Architecture

```
Wazuh Manager -> Integration Service -> Alert Triage LLM
                      | (if severity >= 8)
                   RAG Service (MITRE enrichment)
```

## Configuration

Environment variables (loaded from .env):

| Variable | Default | Description |
|----------|---------|-------------|
| `WAZUH_MANAGER_URL` | `http://wazuh-manager:55000` | Wazuh API endpoint |
| `API_USERNAME` | `wazuh-wui` | Wazuh API username |
| `API_PASSWORD` | - | Wazuh API password (required) |
| `MIN_SEVERITY` | `7` | Minimum rule level to process |
| `RAG_SEVERITY_THRESHOLD` | `8` | Trigger RAG enrichment threshold |
| `ALERT_TRIAGE_URL` | `http://alert-triage:8000` | Alert Triage service |
| `RAG_SERVICE_URL` | `http://rag-service:8001` | RAG service |

## Wazuh Integrator Configuration

Configure Wazuh to send alerts to this webhook:

### Option 1: Custom Integration (ossec.conf)

Edit `/var/ossec/etc/ossec.conf` on Wazuh Manager:

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://wazuh-integration:8002/webhook</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

Restart Wazuh Manager:
```bash
systemctl restart wazuh-manager
```

### Option 2: Integratord Custom Script

Create `/var/ossec/integrations/ai-soc-webhook`:

```bash
#!/bin/bash
# AI-SOC Webhook Integration

WEBHOOK_URL="http://wazuh-integration:8002/webhook"
ALERT_FILE=$1

curl -X POST "$WEBHOOK_URL" \
  -H "Content-Type: application/json" \
  -d @"$ALERT_FILE"
```

Make executable:
```bash
chmod 750 /var/ossec/integrations/ai-soc-webhook
chown root:wazuh /var/ossec/integrations/ai-soc-webhook
```

Configure in `ossec.conf`:
```xml
<integration>
  <name>ai-soc-webhook</name>
  <hook_url>http://wazuh-integration:8002/webhook</hook_url>
  <level>7</level>
  <alert_format>json</alert_format>
</integration>
```

### Option 3: Logstash/Filebeat Pipeline

Use Filebeat to ship alerts:

```yaml
# filebeat.yml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true

output.http:
  hosts: ["http://wazuh-integration:8002/webhook"]
  headers:
    Content-Type: application/json
```

## API Endpoints

### POST /webhook

Receive and analyze Wazuh alert.

**Request Body:**
```json
{
  "timestamp": "2025-01-13T14:30:45.123+0000",
  "rule": {
    "level": 10,
    "description": "Multiple failed login attempts",
    "id": "5710",
    "mitre": {
      "id": ["T1110"],
      "tactic": ["Credential Access"],
      "technique": ["Brute Force"]
    }
  },
  "agent": {
    "id": "001",
    "name": "web-server-01",
    "ip": "10.0.1.50"
  },
  "id": "1705155045.123456",
  "data": {
    "srcip": "203.0.113.42",
    "srcuser": "admin"
  },
  "full_log": "Jan 13 14:30:45 web-server-01 sshd[12345]: Failed password..."
}
```

**Response (200 OK):**
```json
{
  "wazuh_alert_id": "1705155045.123456",
  "wazuh_rule_level": 10,
  "wazuh_rule_description": "Multiple failed login attempts",
  "ai_severity": "high",
  "ai_category": "intrusion_attempt",
  "ai_confidence": 0.92,
  "ai_summary": "Brute force SSH attack from 203.0.113.42",
  "ai_is_true_positive": true,
  "investigation_priority": 2,
  "ai_recommendations": [
    {
      "action": "Block source IP 203.0.113.42",
      "priority": 1,
      "rationale": "Active brute force attack in progress"
    }
  ],
  "rag_enrichment_applied": true,
  "mitre_context": "T1110 - Brute Force: Adversaries may use brute force...",
  "processing_timestamp": "2025-01-13T14:30:46.500Z"
}
```

### GET /alerts

Fetch recent alerts from Wazuh Manager and analyze.

**Query Parameters:**
- `limit` (int, default: 10) - Max alerts to fetch
- `min_level` (int, default: from config) - Min rule level
- `time_range` (str, default: "1h") - Time range (e.g., "1h", "24h", "7d")

**Example:**
```bash
curl "http://localhost:8002/alerts?limit=5&time_range=24h"
```

### GET /health

Service health check with dependency status.

**Response:**
```json
{
  "status": "healthy",
  "service": "wazuh-integration",
  "version": "1.0.0",
  "timestamp": "2025-01-13T14:30:00Z",
  "dependencies": {
    "wazuh_manager": true,
    "alert_triage": true,
    "rag_service": true
  },
  "configuration": {
    "min_severity": 7,
    "rag_threshold": 8
  }
}
```

## Docker Deployment

Included in `docker-compose/ai-services.yml`:

```yaml
services:
  wazuh-integration:
    build: ../services/wazuh-integration
    container_name: wazuh-integration
    environment:
      - WAZUH_MANAGER_URL=http://wazuh-manager:55000
      - API_USERNAME=wazuh-wui
      - API_PASSWORD=${API_PASSWORD}
      - MIN_SEVERITY=7
      - RAG_SEVERITY_THRESHOLD=8
    ports:
      - "8002:8002"
    networks:
      - ai-soc-network
    depends_on:
      - alert-triage
      - rag-service
```

Start service:
```bash
docker-compose -f docker-compose/ai-services.yml up -d wazuh-integration
```

## Testing

### Manual Webhook Test

```bash
curl -X POST http://localhost:8002/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2025-01-13T14:30:45.123+0000",
    "rule": {
      "level": 10,
      "description": "Multiple failed login attempts",
      "id": "5710"
    },
    "agent": {
      "id": "001",
      "name": "test-server",
      "ip": "10.0.1.50"
    },
    "id": "test-alert-001",
    "data": {
      "srcip": "203.0.113.42",
      "srcuser": "admin"
    },
    "full_log": "Test alert"
  }'
```

### Fetch Real Alerts

```bash
curl http://localhost:8002/alerts?limit=5
```

## Severity Filtering Logic

| Rule Level | Wazuh Severity | Processing |
|------------|----------------|------------|
| 0-6 | Low/Medium | Filtered out (not processed) |
| 7-9 | High | AI Triage only |
| 10-15 | Critical | AI Triage + RAG enrichment |

**Rationale:**
- **Level 7+**: High-priority alerts requiring analyst attention
- **Level 8+**: Critical alerts benefit from MITRE context and historical incident data

## Logging

Structured JSON logs to stdout:

```json
{
  "event": "webhook_alert_received",
  "timestamp": "2025-01-13T14:30:45.123Z",
  "level": "info",
  "alert_id": "1705155045.123456",
  "rule_level": 10,
  "rule_description": "Multiple failed login attempts"
}
```

View logs:
```bash
docker logs -f wazuh-integration
```

## Security Considerations

1. **Network Isolation**: Service runs on internal Docker network
2. **No External Exposure**: Webhook accessible only from Wazuh Manager
3. **Authentication**: Wazuh API credentials from environment variables
4. **SSL/TLS**: Disable SSL verification for internal communication (configurable)

## Troubleshooting

### Wazuh Manager Connection Failed

Check Wazuh API accessibility:
```bash
curl -k -u wazuh-wui:$API_PASSWORD http://wazuh-manager:55000/
```

### Alert Triage Service Unreachable

Verify service is running:
```bash
curl http://alert-triage:8000/health
```

### RAG Enrichment Not Applied

Check:
1. Alert severity >= 8?
2. RAG service healthy: `curl http://rag-service:8001/health`

### No Alerts Received

Verify Wazuh integration configuration:
```bash
# On Wazuh Manager
cat /var/ossec/etc/ossec.conf | grep -A 5 "<integration>"
tail -f /var/ossec/logs/ossec.log | grep integration
```

## Performance

**Expected throughput:**
- **Triage-only** (severity 7-9): ~10 alerts/sec
- **Triage + RAG** (severity 10+): ~5 alerts/sec

**Latency:**
- Triage analysis: ~500-1000ms
- RAG enrichment: +500-1000ms

## Future Enhancements

- [ ] Batch processing for high-volume environments
- [ ] Alert deduplication
- [ ] Integration with TheHive/SOAR platforms
- [ ] Custom enrichment plugins
- [ ] Alert correlation engine

## License

Part of AI-Augmented SOC platform.

## Maintainer

Vinit Shenkeshi is an AI/ML Engineer with over 4 years of experience developing end-to-end machine learning and AI solutions. Specializing in NLP, RAG, and LLM deployment, he focuses on building scalable, production-ready systems that integrate advanced analytics into security workflows.

Contact:
- Email: vinitshenkeshi1@gmail.com
- LinkedIn: https://www.linkedin.com/in/vinitshenkeshi/