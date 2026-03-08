# AI Services Layer

**AI-Augmented SOC - LLM-Powered Security Operations**

Intelligent automation for alert triage, log summarization, and threat analysis using state-of-the-art large language models.

---

## Overview

This directory contains the core AI services that power the AI-Augmented SOC platform. Each service is containerized, independently scalable, and communicates via REST APIs.

**Architecture Principles:**
- **Microservices:** Each service has a single responsibility
- **API-First:** All services expose FastAPI REST endpoints
- **Observability:** Prometheus metrics, structured logging
- **Security:** Input validation, prompt injection protection
- **Resilience:** Automatic retries, fallback models

---

## Services

### 1. Alert Triage Service (alert-triage/)

**Purpose:** LLM-powered security alert analysis and prioritization

**Technology Stack:**
- FastAPI
- Ollama (Foundation-Sec-8B / LLaMA 3.1)
- Pydantic (structured outputs)

**API Endpoints:**
- POST /analyze - Analyze single alert
- POST /batch - Batch process alerts
- GET /health - Health check
- GET /metrics - Prometheus metrics

**Key Features:**
- Severity classification (Critical/High/Medium/Low/Info)
- IOC extraction (IPs, domains, hashes)
- MITRE ATT&CK mapping
- True/false positive detection
- Confidence scoring
- Actionable recommendations

**Performance Targets:**
- F1 Score: >0.