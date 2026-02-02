# Wazuh Integration Guide

Complete guide for configuring Wazuh to send alerts to the AI-powered integration service.

## Architecture Overview

```
┌─────────────────┐
│  Wazuh Manager  │
│  (Alert Gen)    │
└────────┬────────┘
         │ HTTP POST
         ↓
┌──────────────────────┐
│ Wazuh Integration    │
│ Service (Port 8002)  │
└──────────┬───────────┘
           │
    ┌──────┴──────┐
    ↓             ↓
┌─────────┐  ┌──────────┐
│ Alert   │  │   RAG    │
│ Triage  │  │ Service  │
│ (LLM)   │  │(severity │
│         │  │  >= 8)   │
└─────────┘  └──────────┘
```

## Prerequisites

1. Wazuh Manager 4.x deployed
2. AI-SOC services running (`docker-compose -f docker-compose/ai-services.yml up -d`)
3. Network connectivity between Wazuh Manager and integration service
4. API credentials configured in `.env`

## Configuration Methods

### Method 1: Native Wazuh Integration (Recommended)

**Pros:**
- Built-in reliability and retry logic
- Officially supported by Wazuh
- Automatic JSON formatting

**Steps:**

1. **SSH into Wazuh Manager container/server:**
   ```bash
   docker exec -it wazuh-manager bash
   # OR
   ssh user@wazuh-manager-host
   ```

2. **Edit `/var/ossec/etc/ossec.conf`:**
   ```xml
   <ossec_config>
     <!-- Add inside <ossec_config> block -->
     <integration>
       <name>custom-webhook</name>
       <hook_url>http://wazuh-integration:8002/webhook</hook_url>
       <level>7</level>
       <alert_format>json</alert_format>
       <options>{"data": "all"}</options>
     </integration>
   </ossec_config>
   ```

3. **Verify configuration syntax:**
   ```bash
   /var/ossec/bin/verify-agent-conf
   ```

4. **Restart Wazuh Manager:**
   ```bash
   systemctl restart wazuh-manager
   # OR (inside Docker container)
   /var/ossec/bin/wazuh-control restart
   ```

5. **Monitor integration logs:**
   ```bash
   tail -f /var/ossec/logs/ossec.log | grep integration
   ```

### Method 2: Custom Integration Script

For advanced filtering or pre-processing.

**Steps:**

1. **Create integration script `/var/ossec/integrations/ai-soc-webhook`:**
   ```bash
   #!/bin/bash
   # AI-SOC Webhook Integration Script
   # Called by Wazuh integratord for each alert

   WEBHOOK_URL="http://wazuh-integration:8002/webhook"
   ALERT_FILE="$1"

   # Optional: Add custom headers, authentication, or filtering
   RULE_LEVEL=$(jq -r '.rule.level' "$ALERT_FILE")

   # Only send if level >= 7
   if [ "$RULE_LEVEL" -ge 7 ]; then
       curl -X POST "$WEBHOOK_URL" \
         -H "Content-Type: application/json" \
         -H "X-Wazuh-Alert: true" \
         --max-time 10 \
         --retry 3 \
         --retry-delay 2 \
         -d @"$ALERT_FILE" \
         --silent \
         --output /dev/null \
         --write-out "%{http_code}\n" >> /var/ossec/logs/integrations.log 2>&1
   fi
   ```

2. **Set permissions:**
   ```bash
   chmod 750 /var/ossec/integrations/ai-soc-webhook
   chown root:wazuh /var/ossec/integrations/ai-soc-webhook
   ```

3. **Configure in `ossec.conf`:**
   ```xml
   <integration>
     <name>ai-soc-webhook</name>
     <hook_url>http://wazuh-integration:8002/webhook</hook_url>
     <level>7</level>
     <alert_format>json</alert_format>
   </integration>
   ```

4. **Test script manually:**
   ```bash
   # Generate test alert
   echo '{"timestamp":"2025-01-13T14:30:45Z","rule":{"level":10,"description":"Test alert","id":"99999"},"id":"test-001","agent":{"id":"000","name":"test"}}' > /tmp/test_alert.json

   # Run script
   /var/ossec/integrations/ai-soc-webhook /tmp/test_alert.json

   # Check response code in logs
   tail /var/ossec/logs/integrations.log
   ```

### Method 3: Filebeat/Logstash Pipeline

For centralized log shipping infrastructure.

**Filebeat Configuration (`filebeat.yml`):**

```yaml
filebeat.inputs:
  - type: log
    enabled: true
    paths:
      - /var/ossec/logs/alerts/alerts.json
    json.keys_under_root: true
    json.add_error_key: true
    processors:
      # Filter by severity
      - drop_event:
          when:
            range:
              rule.level:
                lt: 7

output.http:
  hosts: ["http://wazuh-integration:8002/webhook"]
  headers:
    Content-Type: application/json
  timeout: 30
  max_retries: 3
  backoff.init: 1s
  backoff.max: 30s
```

**Deploy Filebeat:**

```bash
# Download and install Filebeat
curl -L -O https://artifacts.elastic.co/downloads/beats/filebeat/filebeat-8.11.0-amd64.deb
sudo dpkg -i filebeat-8.11.0-amd64.deb

# Copy configuration
sudo cp filebeat.yml /etc/filebeat/filebeat.yml

# Start service
sudo systemctl enable filebeat
sudo systemctl start filebeat

# Verify
sudo systemctl status filebeat
sudo tail -f /var/log/filebeat/filebeat
```

## Network Configuration

### Docker Network Setup

**If Wazuh Manager is in Docker Compose:**

Add to Wazuh's `docker-compose.yml`:

```yaml
services:
  wazuh-manager:
    # ... existing config ...
    networks:
      - wazuh-network
      - ai-network  # Add this

networks:
  wazuh-network:
    driver: bridge
  ai-network:
    external: true  # Reference AI services network
```

**If Wazuh Manager is external:**

Expose integration service:

```yaml
# In docker-compose/ai-services.yml
services:
  wazuh-integration:
    ports:
      - "8002:8002"  # Expose to host
```

Use host IP in Wazuh config:
```xml
<hook_url>http://192.168.1.100:8002/webhook</hook_url>
```

### Firewall Rules

**Allow traffic from Wazuh Manager to integration service:**

```bash
# Linux iptables
sudo iptables -A INPUT -p tcp -s <wazuh-manager-ip> --dport 8002 -j ACCEPT

# UFW
sudo ufw allow from <wazuh-manager-ip> to any port 8002

# Firewalld
sudo firewall-cmd --permanent --add-rich-rule='rule family="ipv4" source address="<wazuh-manager-ip>" port protocol="tcp" port="8002" accept'
sudo firewall-cmd --reload
```

## Severity Filtering Configuration

The integration service filters alerts by Wazuh rule level:

| Rule Level | Severity | Processing |
|------------|----------|------------|
| 0-6 | Low/Medium | **Rejected** (400 Bad Request) |
| 7-9 | High | AI Triage only |
| 10-15 | Critical | AI Triage + RAG enrichment |

**Adjust thresholds in `.env`:**

```bash
# Minimum severity to process (reject below this)
MIN_SEVERITY=7

# Trigger RAG enrichment at this level
RAG_SEVERITY_THRESHOLD=8
```

**Or in Wazuh configuration (pre-filter):**

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://wazuh-integration:8002/webhook</hook_url>
  <level>10</level>  <!-- Only send critical alerts -->
  <alert_format>json</alert_format>
</integration>
```

## Rule Group Filtering

**Filter by specific rule groups:**

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://wazuh-integration:8002/webhook</hook_url>
  <level>7</level>
  <group>authentication_failed,attack,exploit</group>
  <alert_format>json</alert_format>
</integration>
```

**Common useful groups:**
- `authentication_failed` - Failed login attempts
- `attack` - Active attacks
- `exploit` - Exploit attempts
- `malware` - Malware detection
- `intrusion_attempt` - Intrusion attempts
- `web_attack` - Web application attacks
- `privilege_escalation` - Privilege escalation

## Testing the Integration

### 1. Verify Service Health

```bash
curl http://localhost:8002/health
```

**Expected response:**
```json
{
  "status": "healthy",
  "service": "wazuh-integration",
  "dependencies": {
    "wazuh_manager": true,
    "alert_triage": true,
    "rag_service": true
  }
}
```

### 2. Send Test Alert

```bash
curl -X POST http://localhost:8002/webhook \
  -H "Content-Type: application/json" \
  -d '{
    "timestamp": "2025-01-13T14:30:45.123+0000",
    "rule": {
      "level": 10,
      "description": "Multiple failed SSH login attempts",
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
    "id": "test-alert-12345",
    "data": {
      "srcip": "203.0.113.42",
      "srcuser": "admin"
    },
    "full_log": "Failed password for admin from 203.0.113.42"
  }'
```

**Verify enriched response includes:**
- `ai_severity`, `ai_category`, `ai_summary`
- `ai_recommendations[]`
- `rag_enrichment_applied: true` (for level 10)

### 3. Generate Real Wazuh Alert

Trigger a test alert in Wazuh:

```bash
# SSH brute force simulation (from external host)
for i in {1..6}; do
  ssh invalid_user@wazuh-agent-host
done

# Or use Wazuh's built-in alert tester
/var/ossec/bin/wazuh-logtest
# Paste a sample log, check rule match
```

### 4. Monitor Logs

**Integration service:**
```bash
docker logs -f wazuh-integration
```

**Wazuh Manager:**
```bash
tail -f /var/ossec/logs/ossec.log | grep integration
tail -f /var/ossec/logs/alerts/alerts.json
```

## Troubleshooting

### Issue: "Connection refused" from Wazuh

**Symptoms:**
```
ERROR: Failed to send alert to webhook: Connection refused
```

**Solutions:**

1. **Verify service is running:**
   ```bash
   docker ps | grep wazuh-integration
   curl http://localhost:8002/health
   ```

2. **Check Docker networks:**
   ```bash
   docker network inspect ai-network
   # Verify wazuh-integration is listed
   ```

3. **Test connectivity from Wazuh Manager:**
   ```bash
   docker exec -it wazuh-manager curl http://wazuh-integration:8002/health
   ```

### Issue: "400 Bad Request - Below minimum severity"

**Symptoms:**
```json
{
  "detail": "Alert severity 5 below minimum threshold 7"
}
```

**Solution:**

Either:
1. Lower `MIN_SEVERITY` in `.env` to accept lower-severity alerts
2. Adjust Wazuh integration level: `<level>7</level>`

### Issue: RAG enrichment not applied

**Symptoms:**
```json
{
  "rag_enrichment_applied": false
}
```

**Checklist:**

1. **Verify alert severity >= threshold:**
   ```bash
   # Check RAG_SEVERITY_THRESHOLD in .env (default: 8)
   # Ensure alert rule.level >= 8
   ```

2. **Check RAG service health:**
   ```bash
   curl http://localhost:8300/health
   docker logs rag-service
   ```

3. **RAG failures are non-fatal** - triage will still complete

### Issue: Wazuh integration not triggering

**Symptoms:**
No alerts in integration logs, no webhook calls.

**Debug steps:**

1. **Verify integration is configured:**
   ```bash
   docker exec -it wazuh-manager cat /var/ossec/etc/ossec.conf | grep -A 10 integration
   ```

2. **Check Wazuh logs for integration errors:**
   ```bash
   docker exec -it wazuh-manager tail -f /var/ossec/logs/ossec.log
   ```

3. **Verify alerts are being generated:**
   ```bash
   docker exec -it wazuh-manager tail -f /var/ossec/logs/alerts/alerts.json
   ```

4. **Test integration manually:**
   ```bash
   docker exec -it wazuh-manager /var/ossec/bin/wazuh-integratord -t
   ```

## Performance Tuning

### High-Volume Environments

**Adjust worker processes in `main.py`:**

```python
if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        "main:app",
        host="0.0.0.0",
        port=8002,
        workers=4,  # Increase for high load
        log_level="info"
    )
```

**Or via Docker Compose:**

```yaml
services:
  wazuh-integration:
    command: uvicorn main:app --host 0.0.0.0 --port 8002 --workers 4
```

### Rate Limiting in Wazuh

Prevent overwhelming the service:

```xml
<integration>
  <name>custom-webhook</name>
  <hook_url>http://wazuh-integration:8002/webhook</hook_url>
  <level>7</level>
  <max_log>100</max_log>  <!-- Max alerts per timeframe -->
  <alert_format>json</alert_format>
</integration>
```

## Security Best Practices

1. **Use internal Docker network** (no external exposure)
2. **Enable HTTPS** for production (add TLS termination proxy)
3. **Implement authentication** (add API key validation)
4. **Audit logs** regularly
5. **Rotate API credentials** quarterly

## Integration with SOAR/TheHive

Forward enriched alerts to TheHive:

```python
# Add to main.py after enrichment
async def forward_to_thehive(enriched_alert):
    thehive_url = "http://thehive:9000/api/alert"
    headers = {"Authorization": f"Bearer {THEHIVE_API_KEY}"}

    payload = {
        "title": enriched_alert.ai_summary,
        "severity": map_severity(enriched_alert.ai_severity),
        "source": "Wazuh-AI",
        "tags": [enriched_alert.ai_category],
        "description": enriched_alert.ai_detailed_analysis
    }

    async with httpx.AsyncClient() as client:
        await client.post(thehive_url, json=payload, headers=headers)
```

## Next Steps

1. **Configure Wazuh** using Method 1 (native integration)
2. **Test** with sample alerts
3. **Monitor** logs for 24 hours
4. **Tune** severity thresholds based on alert volume
5. **Integrate** with incident response workflow (SOAR/TheHive)

## Support

For issues, check:
- Service logs: `docker logs wazuh-integration`
- Wazuh logs: `/var/ossec/logs/ossec.log`
- Health endpoint: `http://localhost:8002/health`
