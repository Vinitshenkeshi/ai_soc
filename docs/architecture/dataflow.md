# Data Flow & Integration Patterns

Comprehensive documentation of data flows, integration patterns, and message formats across the AI-SOC platform.

---

## Overview

The AI-SOC platform processes security telemetry through multiple integrated data flows. This document describes the end-to-end data journeys from ingestion through detection, analysis, and response.

**Key Data Flow Categories:**
1. **Log Ingestion & Correlation** - Raw events to indexed alerts
2. **ML-Powered Classification** - Alert to prediction
3. **AI-Augmented Triage** - Alert to enriched case
4. **SOAR Orchestration** - Case to automated response
5. **Observability Pipeline** - Service metrics to dashboards

---

## 1. Log Ingestion & Correlation Flow

### High-Level Flow

```
External Sources → Wazuh Manager → Rule Engine → Indexer → Storage
                                   ↓
                            Alert Generation
                                   ↓
                        Webhook → TheHive/AI Services
```

### Detailed Flow Diagram

```
┌────────────────────────────────────────────────────────────┐
│                  External Data Sources                      │
├────────────────────────────────────────────────────────────┤
│                                                             │
│  • Suricata EVE JSON (network alerts)                      │
│  • Zeek connection logs (network metadata)                 │
│  • System logs (syslog, Windows Event Log)                 │
│  • Application logs (web servers, databases)               │
│  • Cloud security logs (AWS CloudTrail, Azure Activity)    │
│                                                             │
└─────────────┬──────────────────────────────────────────────┘
              │
              ▼
┌─────────────────────────────────────────────────────────────┐
│           Transport Layer (Protocol Selection)              │
├─────────────────────────────────────────────────────────────┤
│                                                             │
│  • TCP/1514: Wazuh Agent (encrypted)                       │
│  • UDP/514: Syslog                                          │
│  • Filebeat → Wazuh Manager API                            │
│  • Direct API: HTTP POST to Wazuh Manager                  │
│                                                             │
└─────────────┬───────────────────────────────────────────────┘
              │
              ▼
┌──────────────────────────────────────────────────────────────┐
│          Wazuh Manager: Event Processing Pipeline           │
├──────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Input Reception                                          │
│     └─► Buffer: 16KB per event                              │
│                                                              │
│  2. Decoding                                                 │
│     └─► Log format detection                                │
│     └─► Field extraction (src_ip, dst_ip, etc.)             │
│                                                              │
│  3. Rule Matching                                            │
│     └─► 3,000+ detection rules                              │
│     └─► Regex pattern matching                              │
│     └─► Composite rule chaining                             │
│                                                              │
│  4. Correlation                                              │
│     └─► Time-based correlation (frequency, sequences)       │
│     └─► Statistical anomaly detection                       │
│                                                              │
│  5. Enrichment                                               │
│     └─► GeoIP lookup                                        │
│     └─► MITRE ATT&CK technique mapping                      │
│     └─► Alert metadata injection                            │
│                                                              │
└─────────────┬────────────────────────────────────────────────┘
              │
              ├─────────────────────────────────┐
              │                                 │
              ▼                                 ▼
┌──────────────────────┐          ┌────────────────────────┐
│  Wazuh Indexer       │          │  Alert Generation      │
│  (OpenSearch)        │          │  (Webhooks)            │
├──────────────────────┤          ├────────────────────────┤
│                      │          │                        │
│  • Bulk indexing     │          │  • Severity ≥ 7        │
│  • Daily indices     │          │  • TheHive webhook     │
│  • 30-day retention  │          │  • Custom webhooks     │
│  • Searchable        │          │                        │
│                      │          └─────────────┬──────────┘
└──────────────────────┘                        │
                                                ▼
                                    ┌───────────────────────┐
                                    │   Downstream Systems  │
                                    ├───────────────────────┤
                                    │  • TheHive (SOAR)     │
                                    │  • AI Services        │
                                    │  • Custom SIEM        │
                                    └───────────────────────┘
```

### Data Format Evolution

**Input (Raw Log):**
```
Oct 24 10:15:32 webserver nginx: 192.168.1.100 - - [24/Oct/2025:10:15:32 +0000] "GET /admin HTTP/1.1" 404 156 "-" "Mozilla/5.0"
```

**After Decoding:**
```json
{
  "timestamp": "2025-10-24T10:15:32.000Z",
  "hostname": "webserver",
  "program": "nginx",
  "src_ip": "192.168.1.100",
  "request_method": "GET",
  "request_uri": "/admin",
  "response_code": 404,
  "user_agent": "Mozilla/5.0"
}
```

**After Rule Matching:**
```json
{
  ... (decoded fields) ...,
  "rule": {
    "id": 31101,
    "level": 7,
    "description": "Multiple web authentication failures",
    "mitre": {
      "technique": ["T1110"],
      "tactic": ["Credential Access"]
    }
  }
}
```

**Final Alert (Indexed):**
```json
{
  "timestamp": "2025-10-24T10:15:32.000Z",
  "agent": {
    "id": "001",
    "name": "webserver",
    "ip": "10.0.1.50"
  },
  "rule": {
    "id": 31101,
    "level": 7,
    "description": "Multiple web authentication failures",
    "groups": ["web", "authentication_failed"],
    "mitre": {
      "technique": ["T1110"],
      "tactic": ["Credential Access"]
    }
  },
  "data": {
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.1.50",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "url": "/admin"
  },
  "location": "/var/log/nginx/access.log",
  "decoder": {
    "name": "nginx-access"
  },
  "geoip": {
    "country_name": "United States",
    "city_name": "San Francisco",
    "latitude": 37.7749,
    "longitude": -122.4194
  }
}
```

### Performance Characteristics

| Stage | Latency | Throughput | Resource Usage |
|-------|---------|------------|----------------|
| Input Reception | <1ms | 15,000 events/sec | Negligible |
| Decoding | 1-5ms | Limited by CPU | ~10% CPU |
| Rule Matching | 5-20ms | 10,000 events/sec | ~30% CPU |
| Correlation | Variable | 5,000 events/sec | ~20% CPU |
| Indexing | 10-50ms | 50,000 events/sec | ~40% CPU, ~2GB RAM |

**Total End-to-End Latency:** 20-100ms (event to indexed alert)

---

## 2. ML-Powered Classification Flow

### Flow Diagram

```
Wazuh Alert → Feature Extraction → ML Inference → Prediction
                                         ↓
                               Risk Score + Confidence
                                         ↓
                           Alert Enrichment → Wazuh Indexer
```

### Detailed Process

**Step 1: Feature Extraction**

The ML service subscribes to Wazuh alerts and extracts 79 CICIDS2017 features:

```python
# Feature extraction from Wazuh alert
features = extract_features(alert_data)
# Returns: [Flow Duration, Fwd Packet Length Mean, Flow Bytes/s, ...]
```

**CICIDS2017 Feature Categories:**
1. **Flow Characteristics (13 features):** Duration, bytes, packets
2. **Forward Direction Stats (14 features):** Packet sizes, IAT
3. **Backward Direction Stats (14 features):** Packet sizes, IAT
4. **Bidirectional Stats (10 features):** Ratios, flags
5. **Time-Based (8 features):** Active/Idle periods
6. **Protocol (5 features):** TCP flags, headers
7. **Application Layer (15 features):** Payload statistics

**Step 2: ML Inference API Request**

```http
POST http://ml-inference:8500/predict
Content-Type: application/json

{
  "features": [
    120.5,    # Flow Duration (seconds)
    564.23,   # Fwd Packet Length Mean
    4687.9,   # Flow Bytes/s
    ... (76 more features)
  ],
  "model_name": "random_forest"
}
```

**Step 3: Model Prediction**

```
Input Vector [79 dimensions]
     ↓
Scaling (StandardScaler)
     ↓
Random Forest (500 trees)
     ↓
Voting (majority class)
     ↓
Prediction: ATTACK
Confidence: 0.9856
```

**Step 4: Response**

```json
{
  "prediction": "ATTACK",
  "confidence": 0.9856,
  "model": "random_forest",
  "inference_time_ms": 0.8,
  "feature_importance": {
    "Fwd Packet Length Mean": 0.152,
    "Flow Bytes/s": 0.128,
    "Flow Packets/s": 0.113
  }
}
```

**Step 5: Alert Enrichment**

The original Wazuh alert is enriched with ML prediction:

```json
{
  ... (original alert) ...,
  "ml_classification": {
    "prediction": "ATTACK",
    "confidence": 0.9856,
    "model": "random_forest",
    "timestamp": "2025-10-24T10:15:33.120Z"
  },
  "risk_score": 95  # Calculated: 0.9856 * 100
}
```

### Multi-Model Ensemble

The system can query multiple models for consensus:

```
Alert → Random Forest → ATTACK (0.9856)
     ↓
     → XGBoost      → ATTACK (0.9821)
     ↓
     → Decision Tree → ATTACK (0.9512)
     ↓
Ensemble Vote: ATTACK
Average Confidence: 0.9730
```

### Performance

- **Latency:** <1ms per prediction (Random Forest)
- **Throughput:** 1,250 predictions/second (single container)
- **Accuracy:** 99.28% (Random Forest), 99.21% (XGBoost)
- **False Positive Rate:** 0.25% (Random Forest), 0.09% (XGBoost)

---

## 3. AI-Augmented Triage Flow

### Complete Flow Diagram

```
Wazuh Alert
     │
     ▼
Alert Triage Service
     │
     ├─────────────────┬─────────────────┬───────────────┐
     │                 │                 │               │
     ▼                 ▼                 ▼               ▼
ML Inference      RAG Service      Ollama LLM    Rule-Based
(Classification)  (MITRE Context)  (Analysis)    (Risk Calc)
     │                 │                 │               │
     │                 │                 │               │
     └─────────────────┴─────────────────┴───────────────┘
                             │
                             ▼
                  Enriched Alert Response
                  (Risk Score, Classification,
                   MITRE Techniques, Summary)
                             │
                             ▼
                       TheHive Case
```

### Step-by-Step Process

**Step 1: Alert Ingestion**

```http
POST http://alert-triage:8100/triage
Content-Type: application/json

{
  "alert_data": {
    "rule_id": 31101,
    "rule_description": "Multiple web authentication failures",
    "src_ip": "192.168.1.100",
    "dst_ip": "10.0.1.50",
    "src_port": 54321,
    "dst_port": 443,
    "protocol": "TCP",
    "severity": 7,
    "mitre_technique": ["T1110"]
  }
}
```

**Step 2: Parallel Processing**

The Alert Triage Service makes concurrent requests:

```python
# Parallel execution
async def triage_alert(alert_data):
    ml_task = call_ml_inference(alert_data)
    rag_task = retrieve_mitre_context(alert_data)
    llm_task = analyze_with_llm(alert_data)

    results = await asyncio.gather(ml_task, rag_task, llm_task)

    return combine_results(results)
```

**2a. ML Inference Request**

```http
POST http://ml-inference:8000/predict
{
  "features": [...],  # Extracted from alert_data
  "model_name": "random_forest"
}

Response:
{
  "prediction": "ATTACK",
  "confidence": 0.9856
}
```

**2b. RAG Service Request**

```http
POST http://rag-service:8000/retrieve
{
  "query": "brute force credential access web authentication",
  "top_k": 3
}

Response:
{
  "results": [
    {
      "technique_id": "T1110",
      "technique_name": "Brute Force",
      "similarity_score": 0.92,
      "description": "Adversaries may use brute force techniques...",
      "tactics": ["Credential Access"],
      "detection": "Monitor authentication logs for patterns..."
    },
    {
      "technique_id": "T1110.001",
      "technique_name": "Brute Force: Password Guessing",
      "similarity_score": 0.89
    },
    {
      "technique_id": "T1078",
      "technique_name": "Valid Accounts",
      "similarity_score": 0.74
    }
  ]
}
```

**2c. LLM Analysis Request**

```http
POST http://ollama-server:11434/api/generate
{
  "model": "llama3.1:8b",
  "prompt": "Analyze this security alert and provide a risk assessment:\n\nAlert: Multiple web authentication failures\nSource IP: 192.168.1.100\nTarget: 10.0.1.50:443\nProtocol: HTTPS\n\nMITRE Context: T1110 (Brute Force)\n\nProvide:\n1. Attack classification\n2. Recommended actions\n3. Executive summary",
  "stream": false
}

Response:
{
  "response": "**Attack Classification:** Brute Force Credential Attack\n\n**Recommended Actions:**\n1. Immediately block source IP 192.168.1.100 at firewall\n2. Force password reset for affected accounts\n3. Enable multi-factor authentication\n4. Review access logs for successful attempts\n\n**Executive Summary:**\nHigh-confidence brute force attack detected against web authentication. Attacker systematically attempting credential guessing from IP 192.168.1.100. Immediate blocking recommended to prevent account compromise.",
  "tokens_evaluated": 1024
}
```

**Step 3: Result Aggregation**

The Alert Triage Service combines all results:

```python
def calculate_risk_score(ml_conf, rag_similarity, severity):
    """
    Risk Score Calculation:
    - ML Confidence: 40% weight
    - MITRE Similarity: 30% weight
    - Alert Severity: 30% weight
    """
    risk = (
        ml_conf * 0.4 +
        rag_similarity * 0.3 +
        (severity / 15) * 0.3  # Normalize severity (0-15 scale)
    ) * 100

    return int(risk)

# Example calculation:
ml_conf = 0.9856
rag_similarity = 0.92
severity = 7

risk_score = calculate_risk_score(ml_conf, rag_similarity, severity)
# Result: 85
```

**Step 4: Final Response**

```json
{
  "risk_score": 85,
  "classification": "Brute Force Credential Attack",
  "mitre_techniques": [
    {
      "id": "T1110",
      "name": "Brute Force",
      "confidence": 0.92
    },
    {
      "id": "T1110.001",
      "name": "Password Guessing",
      "confidence": 0.89
    }
  ],
  "recommended_actions": [
    "Block source IP 192.168.1.100 at firewall",
    "Force password reset for affected accounts",
    "Enable multi-factor authentication",
    "Review access logs for successful attempts"
  ],
  "executive_summary": "High-confidence brute force attack detected against web authentication. Attacker systematically attempting credential guessing from IP 192.168.1.100. Immediate blocking recommended to prevent account compromise.",
  "ml_prediction": {
    "prediction": "ATTACK",
    "confidence": 0.9856,
    "model": "random_forest"
  },
  "processing_time_ms": 3250,
  "components_used": ["ml_inference", "rag_service", "ollama_llm"]
}
```

### Performance Profile

| Component | Latency | Contribution |
|-----------|---------|--------------|
| Feature Extraction | 50ms | 1.5% |
| ML Inference | 0.8ms | <1% |
| RAG Retrieval | 45ms | 1.4% |
| LLM Analysis | 3000ms | 92% |
| Aggregation | 20ms | 0.6% |
| **Total** | **~3250ms** | **100%** |

**Bottleneck:** LLM inference dominates latency.

**Optimization Strategies:**
1. Batch processing: Queue alerts, process in batches
2. Async execution: Non-blocking LLM calls
3. Caching: Cache LLM responses for similar alerts
4. Model optimization: Use smaller/faster LLM (7B → 3B params)

---

## 4. SOAR Orchestration Flow

### Automated Response Workflow

```
Enriched Alert (from AI Triage)
     │
     ▼
TheHive Case Creation
     │
     ├──► Observable Extraction (IP, domain, hash, email)
     │
     ▼
Cortex Analysis (Parallel)
     │
     ├─► AbuseIPDB (IP reputation)
     ├─► VirusTotal (File hash)
     ├─► MaxMind GeoIP (Geolocation)
     └─► Shodan (Port scan history)
     │
     └──► Results → TheHive Observables
     │
     ▼
Shuffle Workflow Trigger
     │
     ├──► Condition: Risk Score ≥ 80
     │      │
     │      ├─► Action: Block IP on firewall
     │      ├─► Action: Create ticket in ServiceNow
     │      └─► Action: Send Slack notification
     │
     └──► Condition: Risk Score < 80
            │
            └─► Action: Assign to analyst queue
```

### Data Flow Through SOAR

**Step 1: TheHive Case Creation**

Webhook from Wazuh → TheHive:

```http
POST http://thehive:9010/api/v1/alert
Authorization: Bearer API_KEY

{
  "type": "wazuh",
  "source": "AI-SOC",
  "sourceRef": "wazuh-alert-12345",
  "title": "Brute Force Attack - 192.168.1.100",
  "description": "High-confidence brute force attack detected...",
  "severity": 3,  # Critical
  "tlp": 2,       # Amber
  "pap": 2,       # Amber
  "tags": ["brute_force", "T1110", "credential_access"],
  "customFields": {
    "risk_score": 85,
    "ml_confidence": 0.9856,
    "mitre_techniques": ["T1110", "T1110.001"]
  },
  "observables": [
    {
      "dataType": "ip",
      "data": "192.168.1.100",
      "tags": ["src_ip", "attacker"],
      "ioc": true
    },
    {
      "dataType": "ip",
      "data": "10.0.1.50",
      "tags": ["dst_ip", "victim"]
    }
  ]
}
```

**Step 2: Cortex Analysis**

TheHive automatically triggers Cortex analyzers for each observable:

```
Observable: 192.168.1.100 (IP)
     │
     ├─► AbuseIPDB Analyzer
     │     └─► Result: Malicious (Confidence: 95%, Reports: 147)
     │
     ├─► MaxMind GeoIP
     │     └─► Result: Russia, Moscow (ISP: Suspected Proxy)
     │
     └─► Shodan
           └─► Result: Open ports 22, 80, 443, 3389 (RDP exposed)
```

**Cortex API Call:**
```http
POST http://cortex:9001/api/analyzer/AbuseIPDB/run
Authorization: Bearer API_KEY

{
  "data": "192.168.1.100",
  "dataType": "ip",
  "tlp": 2,
  "pap": 2
}

Response:
{
  "status": "Success",
  "artifacts": [
    {
      "type": "abuse_confidence",
      "value": 95
    },
    {
      "type": "total_reports",
      "value": 147
    },
    {
      "type": "country_code",
      "value": "RU"
    }
  ]
}
```

**Step 3: Shuffle Workflow Execution**

Webhook trigger from TheHive → Shuffle:

```http
POST http://shuffle-backend:5001/api/v1/hooks/thehive_alert
{
  "case_id": "~41216",
  "title": "Brute Force Attack - 192.168.1.100",
  "severity": 3,
  "customFields": {
    "risk_score": 85
  },
  "observables": [
    {
      "dataType": "ip",
      "data": "192.168.1.100",
      "tags": ["attacker"],
      "cortex_results": {
        "abuseipdb": {"confidence": 95}
      }
    }
  ]
}
```

**Shuffle Workflow Execution:**

```yaml
Workflow: High-Risk Alert Response

Trigger: TheHive Case (Risk Score ≥ 80)

Actions:
  1. Extract Variables:
     - attacker_ip = case.observables[0].data
     - risk_score = case.customFields.risk_score

  2. Condition Check: risk_score ≥ 80

  3a. If TRUE (High Risk):
     - Call Firewall API: block_ip(attacker_ip)
     - Create ServiceNow Ticket:
         Priority: Critical
         Assignment: Security Team
     - Send Slack Notification:
         Channel: #security-incidents
         Message: "Critical: Brute force attack blocked. IP: {attacker_ip}"
     - Update TheHive Case:
         Status: Resolved
         Resolution: Automated blocking

  3b. If FALSE (Medium Risk):
     - Assign to Analyst Queue
     - Send Email Notification
```

**Step 4: Response Actions**

**Firewall Block (pfSense API):**
```http
POST https://firewall.example.com/api/v2/firewall/rule
Authorization: Bearer FIREWALL_API_KEY

{
  "type": "block",
  "interface": "wan",
  "ipprotocol": "inet",
  "protocol": "any",
  "src": "192.168.1.100/32",
  "dst": "any",
  "descr": "Blocked by AI-SOC: Brute force attack (Case ~41216)",
  "log": true
}
```

**ServiceNow Ticket:**
```http
POST https://company.service-now.com/api/now/table/incident
Authorization: Basic SERVICE_NOW_CREDS

{
  "short_description": "Security Incident: Brute Force Attack Blocked",
  "description": "AI-SOC automatically blocked brute force attack from 192.168.1.100...",
  "urgency": "1",
  "impact": "1",
  "priority": "1",
  "assignment_group": "Security Operations",
  "category": "Security",
  "subcategory": "Intrusion Detection"
}
```

**Slack Notification:**
```http
POST https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXX
{
  "channel": "#security-incidents",
  "username": "AI-SOC",
  "icon_emoji": ":robot_face:",
  "attachments": [
    {
      "color": "danger",
      "title": "Critical Security Incident",
      "text": "Brute Force Attack Automatically Blocked",
      "fields": [
        {"title": "Attacker IP", "value": "192.168.1.100", "short": true},
        {"title": "Risk Score", "value": "85/100", "short": true},
        {"title": "MITRE Technique", "value": "T1110 (Brute Force)", "short": true},
        {"title": "Action Taken", "value": "IP Blocked + Ticket Created", "short": true}
      ],
      "footer": "AI-SOC Autonomous Response",
      "ts": 1729775732
    }
  ]
}
```

### End-to-End Timing

| Stage | Duration | Cumulative |
|-------|----------|------------|
| Alert → TheHive Case | 500ms | 500ms |
| Cortex Analysis (parallel) | 2-5s | 3-5.5s |
| Shuffle Workflow Trigger | 200ms | 3.2-5.7s |
| Firewall API Call | 300ms | 3.5-6s |
| ServiceNow Ticket | 800ms | 4.3-6.8s |
| Slack Notification | 200ms | 4.5-7s |
| **Total (Alert to Response)** | **~5-7 seconds** | - |

---

## 5. Observability Pipeline

### Metrics Flow

```
All Services → Prometheus Exporters → Prometheus → Grafana
                                           ↓
                                     Alert Rules
                                           ↓
                                     AlertManager
                                           ↓
                               Email/Slack/Shuffle
```

### Service Metrics Collection

**Example: ML Inference Metrics**

The ML Inference service exposes Prometheus metrics:

```python
# Python (FastAPI + prometheus_client)
from prometheus_client import Counter, Histogram

# Metric definitions
predictions_total = Counter(
    'ml_predictions_total',
    'Total ML predictions',
    ['model', 'prediction']
)

inference_latency = Histogram(
    'ml_inference_latency_seconds',
    'ML inference latency',
    ['model']
)

# Usage in code
@app.post("/predict")
async def predict(request: PredictionRequest):
    start_time = time.time()

    prediction = model.predict(request.features)

    # Record metrics
    latency = time.time() - start_time
    inference_latency.labels(model='random_forest').observe(latency)
    predictions_total.labels(
        model='random_forest',
        prediction=prediction
    ).inc()

    return {"prediction": prediction}
```

**Exposed Metrics (GET /metrics):**
```
# HELP ml_predictions_total Total ML predictions
# TYPE ml_predictions_total counter
ml_predictions_total{model="random_forest",prediction="ATTACK"} 15234.0
ml_predictions_total{model="random_forest",prediction="BENIGN"} 8912.0
ml_predictions_total{model="xgboost",prediction="ATTACK"} 5621.0

# HELP ml_inference_latency_seconds ML inference latency
# TYPE ml_inference_latency_seconds histogram
ml_inference_latency_seconds_bucket{le="0.001",model="random_forest"} 8524.0
ml_inference_latency_seconds_bucket{le="0.005",model="random_forest"} 15230.0
ml_inference_latency_seconds_sum{model="random_forest"} 19.348
ml_inference_latency_seconds_count{model="random_forest"} 24146.0
```

### Prometheus Scraping

```yaml
# prometheus.yml
scrape_configs:
  - job_name: 'ml-inference'
    scrape_interval: 15s
    static_configs:
      - targets: ['ml-inference:8000']
    metrics_path: /metrics
```

**Scrape Result:**
```
Timestamp: 2025-10-24T10:15:45.000Z
Job: ml-inference
Instance: ml-inference:8000

Metrics:
  ml_predictions_total{model="random_forest",prediction="ATTACK"} 15234
  ml_inference_latency_seconds_sum{model="random_forest"} 19.348
  ...
```

### Alert Rule Evaluation

```yaml
# alerts/ai-soc-alerts.yml
groups:
  - name: ml_performance
    interval: 30s
    rules:
      - alert: HighMLInferenceLatency
        expr: |
          histogram_quantile(0.95,
            rate(ml_inference_latency_seconds_bucket[5m])
          ) > 0.005
        for: 5m
        labels:
          severity: warning
          component: ml_inference
        annotations:
          summary: "ML inference latency above threshold"
          description: "95th percentile latency is {{ $value }}s (threshold: 0.005s)"

      - alert: MLPredictionImbalance
        expr: |
          sum(rate(ml_predictions_total{prediction="ATTACK"}[5m]))
          /
          sum(rate(ml_predictions_total[5m]))
          > 0.5
        for: 10m
        labels:
          severity: warning
          component: ml_inference
        annotations:
          summary: "Abnormal prediction distribution"
          description: "{{ $value | humanizePercentage }} of predictions are ATTACK"
```

### AlertManager Routing

```yaml
# alertmanager.yml
route:
  receiver: 'default'
  routes:
    - match:
        component: ml_inference
      receiver: 'ai-team'

receivers:
  - name: 'ai-team'
    email_configs:
      - to: 'ai-team@example.com'
        subject: '[AI-SOC] ML Service Alert: {{ .GroupLabels.alertname }}'
    slack_configs:
      - api_url: 'https://hooks.slack.com/...'
        channel: '#ai-soc-alerts'
        title: '{{ .GroupLabels.alertname }}'
        text: '{{ range .Alerts }}{{ .Annotations.description }}{{ end }}'
```

### Grafana Dashboards

**Data Source Configuration:**
```yaml
# grafana/provisioning/datasources/prometheus.yml
apiVersion: 1
datasources:
  - name: Prometheus
    type: prometheus
    access: proxy
    url: http://prometheus:9090
    isDefault: true
```

**Dashboard Query Example:**

Panel: "ML Inference Latency (p95)"
```promql
histogram_quantile(0.95,
  rate(ml_inference_latency_seconds_bucket{model="random_forest"}[5m])
)
```

Panel: "Predictions per Second"
```promql
sum(rate(ml_predictions_total[5m])) by (model, prediction)
```

---

## 6. End-to-End Integration Example

### Complete Flow: Attack Detection to Automated Response

**Scenario:** SQL Injection attack against web application

```
┌──────────────────────────────────────────────────────────────┐
│ T+0ms: Attack Execution                                      │
├──────────────────────────────────────────────────────────────┤
│ Attacker sends: GET /products?id=1' OR '1'='1               │
│ Target: Web Application (10.0.1.50:443)                     │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ T+10ms: Network Detection (Suricata)                         │
├──────────────────────────────────────────────────────────────┤
│ Rule Match: ET WEB_SPECIFIC_APPS SQL Injection Attempt      │
│ Severity: High                                               │
│ EVE JSON log created: /var/log/suricata/eve.json            │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ T+50ms: Log Shipping (Filebeat)                             │
├──────────────────────────────────────────────────────────────┤
│ Filebeat reads eve.json → sends to Wazuh Manager            │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ T+100ms: SIEM Correlation (Wazuh Manager)                   │
├──────────────────────────────────────────────────────────────┤
│ 1. Decoding: Extract src_ip, dst_ip, payload                │
│ 2. Rule Match: 31106 (SQL injection attempt)                │
│ 3. Enrichment: GeoIP, MITRE T1190                           │
│ 4. Alert Generation: Severity 12                            │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ├──► Wazuh Indexer (Storage)
                              │
                              └──► Webhook → AI Services
                                      │
                                      ▼
┌──────────────────────────────────────────────────────────────┐
│ T+200ms: AI Triage (Parallel Processing)                    │
├──────────────────────────────────────────────────────────────┤
│ • ML Inference: ATTACK (Confidence: 0.9912)                 │
│ • RAG Retrieval: T1190 (Initial Access - Exploit Public)    │
│ • LLM Analysis: "SQL injection attack attempt detected..."  │
│                                                              │
│ Risk Score: 92/100                                           │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ T+3500ms: TheHive Case Creation                             │
├──────────────────────────────────────────────────────────────┤
│ Case #~41217: SQL Injection Attack                          │
│ Severity: Critical                                           │
│ Observables: src_ip=203.0.113.42, dst_ip=10.0.1.50         │
│ Tags: sql_injection, T1190, web_attack                      │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ T+4000ms: Cortex Analysis (Parallel)                        │
├──────────────────────────────────────────────────────────────┤
│ • AbuseIPDB: Malicious (Confidence: 87%)                    │
│ • GeoIP: China, Beijing (ISP: Hosting Provider)             │
│ • URLhaus: Payload matches known exploit kit                │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ T+5000ms: Shuffle Workflow (Automated Response)             │
├──────────────────────────────────────────────────────────────┤
│ Condition: Risk ≥ 90 AND sql_injection tag                  │
│                                                              │
│ Actions Executed:                                            │
│ 1. Block IP at WAF (Cloudflare API)                         │
│ 2. Add to threat feed (MISP)                                │
│ 3. Create ServiceNow P1 incident                            │
│ 4. Notify #security-incidents (Slack)                       │
│ 5. Update TheHive case: Status = Responded                  │
└─────────────────────────────┬────────────────────────────────┘
                              │
                              ▼
┌──────────────────────────────────────────────────────────────┐
│ T+7000ms: Response Confirmation                             │
├──────────────────────────────────────────────────────────────┤
│ • WAF: IP 203.0.113.42 blocked (confirmed)                  │
│ • MISP: IOC published to threat feed                        │
│ • ServiceNow: INC0012345 created                            │
│ • Slack: Team notified                                      │
│                                                              │
│ Attack Neutralized: 7 seconds from detection to mitigation  │
└──────────────────────────────────────────────────────────────┘
```

**Total Timeline:**
- **Detection:** 10ms (Suricata)
- **Correlation:** 100ms (Wazuh)
- **AI Analysis:** 3.5s (ML + RAG + LLM)
- **Response:** 7s (End-to-end)

**Manual SOC Response (Typical):**
- Detection: 10ms (same)
- Analyst notification: 5-15 minutes
- Investigation: 10-30 minutes
- Response approval: 5-15 minutes
- **Total: 20-60 minutes**

**Improvement:** 171x - 514x faster response time with AI-SOC automation

---

## Summary

**Key Data Flows Documented:**
1. **Log Ingestion** - External sources → Wazuh → OpenSearch
2. **ML Classification** - Alert → Feature extraction → Prediction
3. **AI Triage** - Alert → ML + RAG + LLM → Enriched case
4. **SOAR Orchestration** - Case → Analysis → Automated response
5. **Observability** - Service metrics → Prometheus → Grafana

**Performance Characteristics:**
- Log Ingestion: 20-100ms latency
- ML Inference: <1ms
- AI Triage: ~3s (LLM-dominated)
- SOAR Response: 4-7s
- End-to-End: 5-10s (detection to mitigation)

**Data Formats:**
- Syslog, JSON (Suricata/Zeek EVE)
- Wazuh Alert Format (JSON)
- MITRE ATT&CK (JSON schema)
- Prometheus Metrics (OpenMetrics)
- REST APIs (JSON over HTTP)

---

**Data Flow Documentation Version:** 1.0
**Last Updated:** October 24, 2025
**Maintained By:** AI-SOC Architecture Team
