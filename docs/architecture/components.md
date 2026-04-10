# Component Design

Detailed technical specifications for all AI-SOC platform components.

---

## Overview

The AI-SOC platform consists of 40+ containerized services organized into six integrated stacks. Each component is independently deployable via Docker Compose with defined resource limits, health checks, and monitoring endpoints.

**Stacks:**

| Stack | Components | Purpose |
|-------|-----------|---------|
| SIEM Core | 4 | Log ingestion, correlation, threat detection |
| AI Services | 10 | ML inference, LLM analysis, RAG, correlation |
| SOAR | 5 | Case management, analysis, orchestration |
| Monitoring | 5 | Metrics, dashboards, alerting, log aggregation |
| Network Analysis | 2 | IDS/IPS, traffic metadata |
| Command & Control | 2 | Dashboard UI, GUI launcher |

---

## SIEM Stack

### Wazuh Manager

**Purpose:** Central log aggregation, correlation engine, and threat detection.

| Spec | Value |
|------|-------|
| Version | 4.8.2 |
| Image | `wazuh/wazuh:4.8.2` |
| Memory | 2GB (1GB reserved) |
| CPU | 2.0 cores |
| Ports | 1514/TCP (agents), 1515/TCP (enrollment), 514/UDP (syslog), 55000/TCP (API) |

**Capabilities:**

- 3,000+ built-in detection rules with custom rule support
- File Integrity Monitoring (FIM)
- CVE vulnerability detection
- Compliance modules (PCI-DSS, HIPAA, GDPR, NIST)
- Active response / automated blocking
- Webhook integration with AI services via Wazuh Integration Service

**Performance:** 15,000 events/sec sustained, 10,000 agent capacity, <100ms API response (p95)

---

### Wazuh Indexer

**Purpose:** Distributed search and analytics engine (OpenSearch 2.x).

| Spec | Value |
|------|-------|
| Version | 4.8.2 |
| Image | `wazuh/wazuh-indexer:4.8.2` |
| Memory | 4GB (JVM heap: 2GB) |
| CPU | 2.0 cores |
| Ports | 9200/TCP (REST), 9300/TCP (inter-node), 9600/TCP (perf analyzer) |

**Index Templates:** `wazuh-alerts-*` (daily), `wazuh-archives-*` (raw), `wazuh-monitoring-*` (health)

**Performance:** 50,000 events/sec indexing (single node), <500ms query latency (p90), 10:1 compression

---

### Wazuh Dashboard

**Purpose:** Web-based visualization and investigation interface (Kibana fork).

| Spec | Value |
|------|-------|
| Version | 4.8.2 |
| Image | `wazuh/wazuh-dashboard:4.8.2` |
| Memory | 1GB |
| CPU | 1.0 core |
| Ports | 443/TCP (HTTPS, maps to 5601 internal) |

**Features:** Pre-built security dashboards, MITRE ATT&CK visualization, Discover interface, PDF/CSV reporting, RBAC via OpenSearch Security plugin.

---

## AI Services Stack

The AI services layer is the core intelligence engine. All services are Python/FastAPI microservices communicating over the `ai-network` Docker bridge (172.35.0.0/24).

### ML Inference API

**Purpose:** Real-time intrusion detection using trained CICIDS2017 models.

| Spec | Value |
|------|-------|
| Framework | FastAPI + scikit-learn |
| Image | Custom (Python 3.11-slim) |
| Memory | 1GB (512MB reserved) |
| CPU | 1.0 core |
| Port | 8500 (maps to 8000 internal) |

**Loaded Models:**

| Model | File | Size | Accuracy | Inference |
|-------|------|------|----------|-----------|
| Random Forest (primary) | `random_forest_ids.pkl` | 3MB | 99.28% | 0.8ms |
| XGBoost (low FP) | `xgboost_ids.pkl` | 188KB | 99.21% | 0.3ms |
| Decision Tree (interpretable) | `decision_tree_ids.pkl` | 35KB | 99.10% | 0.2ms |

**Supporting files:** `scaler.pkl` (StandardScaler), `label_encoder.pkl` (BENIGN/ATTACK), `feature_names.pkl` (77 CICIDS2017 features)

**Endpoints:**

- `POST /predict` — classify network flow (model selectable per request)
- `GET /health` — model count, uptime
- `GET /metrics` — Prometheus endpoint
- `GET /docs` — OpenAPI interactive docs

**Performance:** 1,250 predictions/sec, 0.8ms avg latency, 1.8ms p99. Stateless — horizontally scalable behind a load balancer. CPU-optimized (no GPU required).

---

### Alert Triage Service

**Purpose:** LLM-powered alert analysis, severity classification, and response recommendations.

| Spec | Value |
|------|-------|
| LLM | LLaMA 3.2:3b via Ollama |
| Framework | FastAPI |
| Memory | 2GB |
| CPU | 2.0 cores |
| Port | 8100 |

**Dependencies:** ML Inference API, RAG Service, Ollama Server

**Key Modules:**

| Module | Purpose |
|--------|---------|
| `main.py` | FastAPI application and endpoints |
| `llm_client.py` | Ollama integration with structured prompting |
| `ml_client.py` | ML Inference API communication |
| `context_manager.py` | Alert context tracking across sessions |
| `worker_pool.py` | Async worker thread pool with circuit breaker |
| `models.py` | Pydantic request/response schemas |

**Capabilities:**

- Risk scoring (0-100 scale)
- Severity classification (Critical / High / Medium / Low / Info)
- IOC extraction (IPs, domains, hashes)
- MITRE ATT&CK technique mapping
- True/false positive detection
- Natural language executive summaries
- Response action recommendations

**Processing Pipeline:**

```
Alert → ML Classification (BENIGN/ATTACK)
     → RAG Retrieval (MITRE context + runbooks)
     → LLM Analysis (structured reasoning)
     → Risk Score + Severity + IOCs
     → Response: Enriched alert with recommendations
```

**Performance:** 2-5 sec latency (LLM-dominant), ~500 tokens/alert, circuit breaker for fault tolerance.

---

### RAG Service

**Purpose:** Retrieval-Augmented Generation for context-grounded LLM responses with cyber threat intelligence.

| Spec | Value |
|------|-------|
| Vector DB | ChromaDB |
| Embeddings | sentence-transformers/all-MiniLM-L6-v2 (384 dims) |
| Framework | FastAPI + LangChain |
| Memory | 1GB |
| CPU | 1.0 core |
| Port | 8300 |

**Knowledge Base Sources:**

| Source | Records | Purpose |
|--------|---------|---------|
| MITRE ATT&CK | 835 techniques | Tactic/technique context |
| CVE Database | CVSS >= 9.0 | Vulnerability intelligence |
| Incident History | TheHive cases | Organizational context |
| Security Runbooks | 8 playbooks | Response procedures |

**Key Modules:**

| Module | Purpose |
|--------|---------|
| `knowledge_base.py` | ChromaDB knowledge management |
| `vector_store.py` | Embedding storage and retrieval |
| `embeddings.py` | Sentence-transformer encoding |
| `mitre_ingest.py` | MITRE ATT&CK data ingestion |
| `runbooks/` | Incident response playbooks |

**Endpoints:**

- `POST /retrieve` — semantic search with top-k and confidence threshold
- `POST /ingest` — populate knowledge base from MITRE ATT&CK JSON
- `GET /health` — vector count and status

**Performance:** <50ms retrieval (top-5), 100+ queries/sec, cosine similarity search, 30-40% hallucination reduction vs. raw LLM.

---

### Correlation Engine

**Purpose:** Alert-to-incident grouping, kill chain tracking, attack path prediction, and swarm intelligence research.

| Spec | Value |
|------|-------|
| Framework | FastAPI + SQLAlchemy |
| Database | PostgreSQL |
| LLM | Ollama (for swarm simulation) |
| Memory | 512MB |
| CPU | 0.5 core |
| Port | 8600 |

This is the largest and most research-active service in the platform.

**Core Correlation Features:**

- **Alert Grouping:** IP affinity + temporal proximity clustering
- **Kill Chain Tracking:** Maps correlated alerts to MITRE ATT&CK progression stages
- **Markov Chain Prediction:** Forecasts likely next attack steps based on observed kill chain state

**Key Modules:**

| Module | Purpose |
|--------|---------|
| `correlator.py` | Core correlation logic (IP affinity, temporal clustering) |
| `predictor.py` | Markov chain attack path forecasting |
| `risk_scorer.py` | Host vulnerability and exposure scoring |

**Swarm Intelligence Research Framework:**

The Correlation Engine also houses the swarm intelligence research platform — a multi-agent LLM simulation framework for automated threat modeling against real infrastructure.

| Module | Purpose |
|--------|---------|
| `swarm.py` | Hierarchical leader/follower swarm architecture |
| `simulator.py` | Attack campaign simulation engine |
| `environment.py` | Infrastructure topology model |
| `wazuh_environment.py` | Live Wazuh environment import |
| `actions.py` | Attack action definitions and outcomes |
| `archetypes.py` | Attacker archetypes (Opportunist, APT, Ransomware, Insider) |
| `defender_archetypes.py` | Defender agents (SOC Analyst, Incident Responder, Threat Hunter) |
| `run_experiments.py` | Experiment orchestration |
| `research_metrics.py` | Statistical evaluation metrics |
| `generate_figures.py` | Research paper figure generation |
| `dataset_generator.py` | Synthetic attack data generation |

**Swarm Architecture:**

- 12 LLM leaders per batch (3 per archetype × 4 archetypes)
- Up to 500 rule-based followers per leader (37,575 total agents)
- Monte Carlo statistical aggregation across batches
- Environment randomization (15% defense flip, 20% CVE variance)
- Emergent attack path discovery

**Research Findings:**

- 14B-parameter model produces 6× more unique strategies than 3B
- LLM-powered defenders reduce compromise rates by 44% overall, 93% on monitored hosts
- Swarm predictions converge at 500 followers per archetype

---

### Wazuh Integration Service

**Purpose:** Webhook bridge between Wazuh alerts and the AI services pipeline.

| Spec | Value |
|------|-------|
| Framework | FastAPI |
| Memory | 256MB |
| CPU | 0.25 core |
| Port | 8002 |

**Key Modules:**

| Module | Purpose |
|--------|---------|
| `main.py` | Webhook endpoint and routing logic |
| `wazuh_client.py` | Wazuh REST API communication |
| `ai_client.py` | Upstream AI service client |
| `models.py` | Request/response schemas |

**Behavior:**

- Receives Wazuh webhook alerts in real-time
- Filters by severity threshold (MIN_SEVERITY=7)
- Routes alerts to Alert Triage for LLM analysis
- Enriches high-severity alerts (>=8) with RAG context
- Transforms raw Wazuh JSON into structured format for downstream services

---

### Feedback Service

**Purpose:** Alert persistence and analyst feedback collection for continuous learning.

| Spec | Value |
|------|-------|
| Framework | FastAPI + SQLAlchemy |
| Database | PostgreSQL (port 5435) |
| Memory | 256MB |
| CPU | 0.25 core |
| Port | 8400 |

**Key Modules:**

| Module | Purpose |
|--------|---------|
| `main.py` | REST API for feedback CRUD |
| `database.py` | PostgreSQL ORM models (alerts, feedback, metrics) |
| `models.py` | Pydantic schemas |

**Capabilities:**

- Persists all analyzed alerts with full context
- Captures analyst verdicts (true positive / false positive)
- Stores analyst confidence ratings
- Triggers retraining pipeline when sufficient feedback accumulates
- Provides alert history and accuracy metrics

---

### Rule Generator

**Purpose:** AI-powered Sigma detection rule generation from attack descriptions.

| Spec | Value |
|------|-------|
| Framework | FastAPI + Ollama LLM |
| Memory | 256MB |
| CPU | 0.25 core |
| Port | 8700 |

**Capabilities:**

- LLM-generated Sigma rules from natural language attack descriptions
- Historical back-testing against known events
- Analyst approval queue before deployment
- Rule versioning and rollback

---

### Retraining Service

**Purpose:** Continuous ML model improvement via analyst feedback loop.

| Spec | Value |
|------|-------|
| Framework | Python + scikit-learn + XGBoost |
| Trigger | Feedback Service threshold |

**Pipeline:**

```
Analyst Feedback → Feedback Service → Retraining Service
  → Retrain RF, XGBoost, Decision Tree
  → Champion/challenger evaluation
  → Model versioning with rollback
  → Hot-reload in ML Inference API
```

---

### ChromaDB

**Purpose:** AI-native vector database for semantic search.

| Spec | Value |
|------|-------|
| Image | `chromadb/chroma:latest` |
| Memory | 2GB |
| CPU | 1.0 core |
| Port | 8200 (maps to 8000 internal) |
| Storage | `chromadb-data` volume (~20MB) |

**Algorithm:** HNSW for approximate nearest neighbor. <10ms query latency.

---

### Ollama Server

**Purpose:** Local LLM inference runtime.

| Spec | Value |
|------|-------|
| Image | `ollama/ollama:latest` |
| Model | LLaMA 3.2:3b (Q4_0, ~2GB) |
| Memory | 8GB |
| CPU | 4.0 cores |
| GPU | Optional (CUDA support) |
| Port | 11434 |

**Performance:** 15-25 tokens/sec (CPU), 50-100 (GPU). Sequential request processing.

---

### Common Library

**Purpose:** Shared utilities across all AI services.

| Module | Purpose |
|--------|---------|
| `ollama_client.py` | Reusable Ollama API client |
| `logging_config.py` | Structured JSON logging |
| `metrics.py` | Prometheus metrics wrapper |
| `security.py` | Input validation and prompt injection detection |
| `auth.py` | Authentication utilities |
| `integration.py` | Service-to-service communication |
| `pipeline.py` | Data processing pipeline |
| `rate_limit.py` | Rate limiting |

---

## SOAR Stack

### TheHive

**Purpose:** Collaborative security incident response platform.

| Spec | Value |
|------|-------|
| Version | 5.2.9 |
| Image | `strangebee/thehive:5.2.9` |
| Memory | 2GB |
| CPU | 2.0 cores |
| Port | 9010 |
| Backend | Cassandra 4.1.3, MinIO (S3) |

**Features:** Case management, multi-analyst collaboration, observable tracking (IOCs, hashes, IPs), task management, Cortex integration, webhook integration with Wazuh/Shuffle, predefined case templates.

---

### Cortex

**Purpose:** Observable analysis engine with 100+ analyzers.

| Spec | Value |
|------|-------|
| Version | 3.1.7 |
| Image | `thehiveproject/cortex:3.1.7` |
| Memory | 1.5GB |
| CPU | 2.0 cores |
| Port | 9011 |

**Analyzers:** VirusTotal, AbuseIPDB, OTX, ClamAV, Yara, Shodan, MaxMind GeoIP, Google SafeBrowsing, PhishTank, and more.

**Responders:** Firewall block, EDR host isolation, email/Slack/PagerDuty notification.

---

### Shuffle

**Purpose:** Security workflow automation and orchestration (no-code SOAR).

| Spec | Value |
|------|-------|
| Version | 1.4.0 |
| Components | Frontend (3001), Backend (5001), Orborus (worker) |
| Database | OpenSearch 2.11.1 |

**Features:** Drag-and-drop workflows, 100+ integrations, webhook triggers, conditional logic, scheduling, data transformation.

**Example Workflow:**

```
Wazuh Alert (High Severity)
  → Create TheHive Case
  → Run Cortex Analyzers (IP reputation, geo-location)
  → If malicious → Block IP + Slack notification
  → If benign → Create low-priority ticket
```

---

## Monitoring Stack

### Prometheus

**Purpose:** Time-series metrics database and alerting engine.

| Spec | Value |
|------|-------|
| Version | 2.48.0 |
| Memory | 2GB |
| CPU | 1.0 core |
| Port | 9090 |
| Retention | 30 days |

**Scrape Targets (13):** Prometheus, Node Exporter, cAdvisor, Wazuh Manager, Wazuh Indexer, TheHive, Cortex, ML Inference, Alert Triage, RAG Service, ChromaDB, Grafana, AlertManager.

---

### Grafana

**Purpose:** Metrics visualization and dashboarding.

| Spec | Value |
|------|-------|
| Version | 10.2.2 |
| Memory | 512MB |
| CPU | 0.5 core |
| Port | 3000 |
| Datasources | Prometheus, Loki |

**Pre-built Dashboards:** AI-SOC Overview, SIEM Stack, ML Performance, Container Metrics, Host Metrics.

---

### AlertManager

**Purpose:** Alert routing, grouping, deduplication, and multi-channel delivery.

| Spec | Value |
|------|-------|
| Version | 0.26.0 |
| Memory | 256MB |
| CPU | 0.25 core |
| Port | 9093 |

**Routing:** Severity-based routing to email, Slack, PagerDuty, and Shuffle webhooks. Supports grouping, inhibition, and silencing.

---

### Loki + Promtail

**Purpose:** Log aggregation and shipping for troubleshooting.

| Component | Version | Port |
|-----------|---------|------|
| Loki | 2.9.3 | 3100 |
| Promtail | 2.9.3 | — |

Promtail ships Docker container logs to Loki. 7-day retention.

---

### Node Exporter + cAdvisor

| Component | Port | Metrics |
|-----------|------|---------|
| Node Exporter | 9100 | 800+ host-level metrics (CPU, memory, disk, network) |
| cAdvisor | 8080 | Per-container CPU, memory, network, disk |

---

## Network Analysis Stack

### Suricata

**Purpose:** Network-based intrusion detection and prevention.

| Spec | Value |
|------|-------|
| Version | 7.0.2 |
| Network Mode | `host` (promiscuous capture) |
| Memory | 2GB |
| CPU | 2.0 cores |
| Rules | Emerging Threats Open (30,000+) |

Outputs EVE JSON logs (alerts, HTTP, DNS, TLS, flows) shipped via Filebeat to Wazuh.

**Limitation:** Requires Linux host — Windows Docker Desktop incompatible.

---

### Zeek

**Purpose:** Passive network traffic analyzer and metadata extractor.

| Spec | Value |
|------|-------|
| Version | 6.0.3 |
| Network Mode | `host` |
| Memory | 2GB |
| CPU | 2.0 cores |

**Output Logs:** `conn.log`, `http.log`, `dns.log`, `ssl.log`, `files.log`

**Limitation:** Requires Linux host.

---

## Command & Control

### Dashboard (Command Center)

**Purpose:** Unified web interface and API gateway for all AI services.

| Spec | Value |
|------|-------|
| Framework | Flask + Jinja2 |
| Port | 5050 |

**Features:**

- Reverse proxy to all 7 AI microservices (eliminates CORS)
- Service health status monitoring
- Quick links to Grafana, Wazuh Dashboard, Prometheus, ChromaDB, Ollama
- Long timeouts (180s) for LLM endpoints
- Service registry with auto-discovery

---

### AI-SOC Launcher

**Purpose:** Desktop GUI for deployment and monitoring.

| Spec | Value |
|------|-------|
| Framework | Python Tkinter |
| File | `AI-SOC-Launcher.py` |

**Features:**

- Prerequisites checking (Docker, Python, etc.)
- One-click deployment of each stack
- Real-time service health visualization
- Log viewing for all containers

---

## Deployment Summary

**Resource Requirements (Full Deployment):**

| Resource | Value |
|----------|-------|
| Total Components | 40+ |
| Total Memory | ~28GB |
| Total CPU | ~18 cores |
| Docker Images | ~10GB compressed |
| Persistent Volumes | 18+ |

**Docker Compose Files:**

| File | Stack |
|------|-------|
| `phase1-siem-core.yml` | Wazuh Manager, Indexer, Dashboard, Filebeat |
| `phase1-siem-core-windows.yml` | Windows-compatible SIEM variant |
| `phase2-soar-stack.yml` | TheHive, Cortex, Shuffle, Cassandra, MinIO |
| `ai-services.yml` | All AI microservices + Ollama + ChromaDB + PostgreSQL |
| `monitoring-stack.yml` | Prometheus, Grafana, AlertManager, Loki, Promtail |
| `network-analysis-stack.yml` | Suricata, Zeek |
| `dev-environment.yml` | Development configuration |
| `integrated-stack.yml` | Full stack integration |

---

**Last Updated:** March 2026
**Maintained By:** Abdul Bari
