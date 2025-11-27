"""
Pydantic Models - Wazuh Integration Service
AI-Augmented SOC

Models for Wazuh alert parsing and transformation to Alert Triage format.
"""

from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class WazuhRule(BaseModel):
    """Wazuh rule information from alert"""
    level: int = Field(..., description="Wazuh rule level (0-15)")
    description: str = Field(..., description="Rule description")
    id: str = Field(..., description="Wazuh rule ID")
    mitre: Optional[Dict[str, List[str]]] = Field(None, description="MITRE ATT&CK mapping")
    groups: Optional[List[str]] = Field(None, description="Rule groups")
    firedtimes: Optional[int] = Field(None, description="Times this rule has fired")


class WazuhAgent(BaseModel):
    """Agent information from Wazuh alert"""
    id: str = Field(..., description="Agent ID")
    name: Optional[str] = Field(None, description="Agent hostname")
    ip: Optional[str] = Field(None, description="Agent IP address")


class WazuhData(BaseModel):
    """Data section from Wazuh alert (varies by rule)"""
    srcip: Optional[str] = None
    srcport: Optional[int] = None
    dstip: Optional[str] = None
    dstport: Optional[int] = None
    srcuser: Optional[str] = None
    dstuser: Optional[str] = None
    protocol: Optional[str] = None

    # Windows EventLog fields
    win: Optional[Dict[str, Any]] = None

    # Generic fields
    data: Optional[str] = None


class WazuhAlert(BaseModel):
    """
    Wazuh alert JSON structure.

    Based on Wazuh 4.x alert format from /var/ossec/logs/alerts/alerts.json
    """
    timestamp: str = Field(..., description="Alert timestamp")
    rule: WazuhRule = Field(..., description="Triggered rule details")
    agent: Optional[WazuhAgent] = Field(None, description="Source agent info")
    manager: Optional[Dict[str, str]] = Field(None, description="Wazuh manager info")

    id: str = Field(..., description="Unique alert ID")
    full_log: Optional[str] = Field(None, description="Original log line")
    decoder: Optional[Dict[str, str]] = Field(None, description="Decoder information")
    data: Optional[WazuhData] = Field(None, description="Parsed log data")
    location: Optional[str] = Field(None, description="Log source location")

    # Additional fields
    previous_output: Optional[str] = Field(None, description="Previous related log")

    class Config:
        json_schema_extra = {
            "example": {
                "timestamp": "2025-01-13T14:30:45.123+0000",
                "rule": {
                    "level": 10,
                    "description": "Multiple failed login attempts",
                    "id": "5710",
                    "mitre": {
                        "id": ["T1110"],
                        "tactic": ["Credential Access"],
                        "technique": ["Brute Force"]
                    },
                    "groups": ["authentication_failed", "pci_dss_10.2.4"]
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
                "full_log": "Jan 13 14:30:45 web-server-01 sshd[12345]: Failed password for admin from 203.0.113.42 port 45678 ssh2"
            }
        }


class EnrichedAlert(BaseModel):
    """
    Combined response: Wazuh alert + AI Triage + RAG enrichment.

    This is the final output returned to webhook callers.
    """
    # Original Wazuh data
    wazuh_alert_id: str
    wazuh_rule_level: int
    wazuh_rule_description: str

    # AI Triage Analysis
    ai_severity: str = Field(..., description="AI-assessed severity")
    ai_category: str = Field(..., description="Alert category")
    ai_confidence: float = Field(..., description="Model confidence")
    ai_summary: str = Field(..., description="Human-readable summary")
    ai_is_true_positive: bool
    ai_recommendations: List[Dict[str, Any]]
    investigation_priority: int

    # RAG Enrichment (conditional)
    mitre_context: Optional[str] = Field(None, description="MITRE ATT&CK context from RAG")
    similar_incidents: Optional[List[str]] = Field(None, description="Similar past incidents")
    kb_references: Optional[List[str]] = Field(None, description="Knowledge base articles")

    # Correlation Engine (incident grouping)
    incident_id: Optional[str] = Field(None, description="Correlated incident ID")
    incident_is_new: Optional[bool] = Field(None, description="Whether this created a new incident")
    incident_alert_count: Optional[int] = Field(None, description="Total alerts in this incident")
    kill_chain_stage: Optional[str] = Field(None, description="Current kill chain stage")

    # Processing metadata
    processing_timestamp: datetime = Field(default_factory=datetime.utcnow)
    rag_enrichment_applied: bool = False

    class Config:
        json_schema_extra = {
            "example": {
                "wazuh_alert_id": "1705155045.123456",
                "wazuh_rule_level": 10,
                "wazuh_rule_description": "Multiple failed login attempts",
                "ai_severity": "high",
                "ai_category": "intrusion_attempt",
                "ai_confidence": 0.92,
                "ai_summary": "Brute force SSH attack from 203.0.113.42 targeting admin account",
                "ai_is_true_positive": True,
                "investigation_priority": 2,
                "rag_enrichment_applied": True
            }
        }
