"""
Risk Scorer - Attack Campaign Simulator
AI-Augmented SOC

Aggregates results from multiple simulation runs into per-host
risk scores. Each host gets a score (0-100) based on how often
it was compromised, by which attacker archetypes, through which
attack paths.
"""

import logging
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Kill chain stage ordering (used for depth calculation)
# ---------------------------------------------------------------------------

_STAGE_ORDER = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "lateral_movement",
    "collection",
    "command_and_control",
    "exfiltration",
    "impact",
]

# ---------------------------------------------------------------------------
# Criticality multipliers
# ---------------------------------------------------------------------------

_CRITICALITY_MULTIPLIER: Dict[str, float] = {
    "critical": 1.0,
    "high": 0.8,
    "medium": 0.6,
    "low": 0.4,
}

# ---------------------------------------------------------------------------
# Mitigation templates keyed by action type
# ---------------------------------------------------------------------------

_MITIGATION_MAP: Dict[str, str] = {
    "exploit_public_service": "Patch externally exposed services and apply WAF rules",
    "brute_force_creds": "Enable MFA and enforce strong password policies",
    "exploit_weak_password": "Enforce password complexity; deploy a PAM solution",
    "bypass_edr": "Update EDR signatures and enable tamper-protection mode",
    "credential_dump": "Enable Credential Guard; restrict LSASS access",
    "deploy_payload": "Deploy EDR and application whitelisting",
    "pivot_to_host": "Implement micro-segmentation and host-based firewalls",
    "lateral_movement": "Implement least-privilege access and network segmentation",
    "persistence": "Monitor scheduled tasks, services, and registry run keys",
    "exfiltrate_data": "Enable DLP controls and monitor outbound traffic",
    "ransomware_encrypt": "Maintain offline backups and enable immutable storage",
    "scan_network": "Deploy network IDS/IPS; alert on reconnaissance patterns",
    "do_nothing": "No specific mitigation required",
}

_DEFAULT_MITIGATION = "Review host configuration and apply security hardening baseline"


@dataclass
class HostRiskScore:
    """Risk assessment for a single host across all ingested simulations."""

    host_ip: str
    hostname: str
    criticality: str
    risk_score: int  # 0-100
    compromise_rate: float  # fraction of simulations where this host was compromised
    primary_attack_vector: str  # most common action that led to compromise
    primary_attacker_type: str  # archetype that compromises this most
    attack_paths_to_host: List[dict]  # up to 5 representative paths that reach this host
    recommended_mitigations: List[str]
    simulations_analyzed: int

    def to_dict(self) -> dict:
        return {
            "host_ip": self.host_ip,
            "hostname": self.hostname,
            "criticality": self.criticality,
            "risk_score": self.risk_score,
            "compromise_rate": round(self.compromise_rate, 4),
            "primary_attack_vector": self.primary_attack_vector,
            "primary_attacker_type": self.primary_attacker_type,
            "attack_paths_to_host": self.attack_paths_to_host,
            "recommended_mitigations": self.recommended_mitigations,
            "simulations_analyzed": self.simulations_analyzed,
        }


class RiskScorer:
    """
    Aggregates simulation reports into per-host risk scores.

    Maintains an internal history of ingested campaign reports and
    recomputes scores on demand.
    """

    def __init__(self):
        self._simulation_history: List[dict] = []

    # ------------------------------------------------------------------
    # Ingestion
    # ------------------------------------------------------------------

    def ingest_simulation(self, campaign_report: dict):
        """Add a simulation report to the scoring history."""
        if not campaign_report:
            return
        self._simulation_history.append(campaign_report)
        logger.debug(
            "RiskScorer: ingested simulation %s (total=%d)",
            campaign_report.get("simulation_id", "?"),
            len(self._simulation_history),
        )

    def clear_history(self):
        """Remove all ingested simulations."""
        self._simulation_history.clear()

    @property
    def simulation_count(self) -> int:
        return len(self._simulation_history)

    # ------------------------------------------------------------------
    # Score computation
    # ------------------------------------------------------------------

    def compute_risk_scores(self) -> List[HostRiskScore]:
        """
        Compute risk scores for all hosts across all ingested simulations.

        Score calculation:
        - Base: compromise_rate * 100 (0-100)
        - Criticality multiplier: critical=1.0, high=0.8, medium=0.6, low=0.4
        - Defense factor: reduce score if defenses blocked most attempts
        - Archetype diversity: +bonus if multiple archetype types succeed

        Returns sorted by risk_score descending.
        """
        if not self._simulation_history:
            return []

        total_sims = len(self._simulation_history)

        # ------------------------------------------------------------------
        # Collect per-host statistics across all simulations
        # ------------------------------------------------------------------

        # host_ip -> count of simulations where this host was compromised
        compromise_count: Counter = Counter()
        # host_ip -> (hostname, criticality) from environment summary
        host_meta: Dict[str, dict] = {}
        # host_ip -> Counter of actions that led to compromise of this host
        host_vectors: Dict[str, Counter] = defaultdict(Counter)
        # host_ip -> Counter of archetypes that compromised this host
        host_archetypes: Dict[str, Counter] = defaultdict(Counter)
        # host_ip -> list of attack paths (from campaigns that compromised this host)
        host_paths: Dict[str, List[dict]] = defaultdict(list)
        # host_ip -> defense block counts (approximated from defense_validation)
        host_defense_blocks: Dict[str, int] = defaultdict(int)
        host_defense_attempts: Dict[str, int] = defaultdict(int)

        for report in self._simulation_history:
            # Collect host metadata from environment_summary (limited) and campaigns
            env_summary = report.get("environment_summary", {})

            # Pull host details from weakest_points if available
            for wp in report.get("weakest_points", []):
                vuln_str = wp.get("vulnerability", "")
                # Format: "10.0.0.10 (web-server-01): CVE-..."
                if "(" in vuln_str and ")" in vuln_str:
                    ip_part = vuln_str.split("(")[0].strip()
                    hostname_part = vuln_str.split("(")[1].split(")")[0].strip()
                    if ip_part not in host_meta:
                        host_meta[ip_part] = {"hostname": hostname_part, "criticality": "medium"}

            # Process per-agent campaigns
            for camp in report.get("campaigns", []):
                archetype = camp.get("archetype", "unknown")
                compromised_ips = camp.get("hosts_compromised", [])
                attack_path = camp.get("attack_path", [])

                for ip in compromised_ips:
                    compromise_count[ip] += 1
                    host_archetypes[ip][archetype] += 1

                    # Collect attack paths that reached this host
                    relevant_steps = [
                        step for step in attack_path
                        if step.get("target") == ip and step.get("result") in ("success", "detected")
                    ]
                    if relevant_steps and len(host_paths[ip]) < 5:
                        host_paths[ip].append({
                            "archetype": archetype,
                            "steps": relevant_steps[:5],
                        })

                    # Tally action vectors
                    for step in attack_path:
                        if step.get("target") == ip and step.get("result") in ("success", "detected"):
                            action = step.get("action", "unknown")
                            host_vectors[ip][action] += 1

            # Tally defense statistics (defense_validation block in report)
            defense_val = report.get("defense_validation", {})
            # defense_validation is per-defense-type, not per-host — use as aggregate signal
            total_blocked = sum(v.get("blocked", 0) for v in defense_val.values() if isinstance(v, dict))
            total_attempts = total_blocked + sum(
                v.get("bypassed", 0) for v in defense_val.values() if isinstance(v, dict)
            )
            # We distribute this signal equally to all known hosts for simplicity
            for ip in compromise_count:
                host_defense_blocks[ip] += total_blocked
                host_defense_attempts[ip] += total_attempts

        # ------------------------------------------------------------------
        # Build host list from all known IPs (compromised or mentioned)
        # ------------------------------------------------------------------

        all_ips = set(compromise_count.keys()) | set(host_meta.keys())
        # Also collect from host_paths to catch hosts mentioned in paths
        for ip in list(host_vectors.keys()):
            all_ips.add(ip)

        scores: List[HostRiskScore] = []

        for ip in all_ips:
            meta = host_meta.get(ip, {})
            hostname = meta.get("hostname", ip)
            criticality = meta.get("criticality", "medium")
            crit_mult = _CRITICALITY_MULTIPLIER.get(criticality, 0.6)

            compromised_times = compromise_count.get(ip, 0)
            compromise_rate = compromised_times / total_sims

            # Base score from compromise rate
            base_score = compromise_rate * 100.0

            # Apply criticality multiplier
            weighted_score = base_score * crit_mult

            # Defense factor: if defenses blocked most attempts, reduce score slightly
            attempts = host_defense_attempts.get(ip, 0)
            blocked = host_defense_blocks.get(ip, 0)
            if attempts > 0:
                block_rate = blocked / attempts
                # Reduce by up to 10 points if defenses are highly effective
                defense_reduction = block_rate * 10.0
                weighted_score = max(0.0, weighted_score - defense_reduction)

            # Archetype diversity bonus: if 3+ archetypes succeed, add up to 10 points
            arch_count = len(host_archetypes.get(ip, {}))
            diversity_bonus = min(arch_count * 3.0, 10.0) if arch_count > 1 else 0.0
            weighted_score = min(100.0, weighted_score + diversity_bonus)

            risk_score = round(weighted_score)

            # Primary attack vector
            vectors = host_vectors.get(ip, Counter())
            primary_vector = vectors.most_common(1)[0][0] if vectors else "unknown"

            # Primary attacker archetype
            archs = host_archetypes.get(ip, Counter())
            primary_arch = archs.most_common(1)[0][0] if archs else "unknown"

            # Recommended mitigations (up to 3, deduped)
            mitigations: List[str] = []
            for action, _ in vectors.most_common(5):
                mitigation = _MITIGATION_MAP.get(action, _DEFAULT_MITIGATION)
                if mitigation not in mitigations:
                    mitigations.append(mitigation)
                if len(mitigations) >= 3:
                    break
            if not mitigations:
                mitigations = [_DEFAULT_MITIGATION]

            scores.append(HostRiskScore(
                host_ip=ip,
                hostname=hostname,
                criticality=criticality,
                risk_score=risk_score,
                compromise_rate=compromise_rate,
                primary_attack_vector=primary_vector,
                primary_attacker_type=primary_arch,
                attack_paths_to_host=host_paths.get(ip, []),
                recommended_mitigations=mitigations,
                simulations_analyzed=total_sims,
            ))

        scores.sort(key=lambda s: s.risk_score, reverse=True)
        return scores

    # ------------------------------------------------------------------
    # Summary
    # ------------------------------------------------------------------

    def get_risk_summary(self) -> dict:
        """
        Overall risk summary across all hosts and simulations.

        Returns:
        - total_simulations_analyzed
        - average_risk_score
        - highest_risk_hosts (top 5)
        - most_common_successful_technique
        - most_effective_defense (blocked most attacks)
        - overall_security_posture_rating (A-F)
        """
        if not self._simulation_history:
            return {
                "total_simulations_analyzed": 0,
                "message": "No simulations ingested yet. Run /risk-scores/refresh to populate.",
            }

        scores = self.compute_risk_scores()

        avg_risk = (
            round(sum(s.risk_score for s in scores) / len(scores), 1)
            if scores else 0.0
        )

        # Aggregate technique counts across all reports
        technique_counter: Counter = Counter()
        defense_block_counter: Counter = Counter()
        defense_attempt_counter: Counter = Counter()

        for report in self._simulation_history:
            for camp in report.get("campaigns", []):
                for step in camp.get("attack_path", []):
                    if step.get("result") in ("success", "detected"):
                        tech = step.get("mitre", "")
                        if tech and tech != "-":
                            technique_counter[tech] += 1

            defense_val = report.get("defense_validation", {})
            for defense_name, stats in defense_val.items():
                if isinstance(stats, dict):
                    defense_block_counter[defense_name] += stats.get("blocked", 0)
                    defense_attempt_counter[defense_name] += (
                        stats.get("blocked", 0) + stats.get("bypassed", 0)
                    )

        most_common_technique = (
            technique_counter.most_common(1)[0][0]
            if technique_counter else "N/A"
        )

        # Most effective defense = highest block rate with meaningful sample
        most_effective_defense = "N/A"
        best_block_rate = 0.0
        for defense, blocked in defense_block_counter.items():
            attempts = defense_attempt_counter.get(defense, 0)
            if attempts >= 2:
                rate = blocked / attempts
                if rate > best_block_rate:
                    best_block_rate = rate
                    most_effective_defense = defense

        # Security posture rating (A-F) based on average risk score
        posture = self._score_to_grade(avg_risk)

        return {
            "total_simulations_analyzed": len(self._simulation_history),
            "total_hosts_tracked": len(scores),
            "average_risk_score": avg_risk,
            "highest_risk_hosts": [
                {
                    "host_ip": s.host_ip,
                    "hostname": s.hostname,
                    "risk_score": s.risk_score,
                    "criticality": s.criticality,
                }
                for s in scores[:5]
            ],
            "most_common_successful_technique": most_common_technique,
            "most_effective_defense": most_effective_defense,
            "most_effective_defense_block_rate": round(best_block_rate, 4),
            "overall_security_posture_rating": posture,
        }

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _score_to_grade(avg_score: float) -> str:
        """Convert an average risk score (0-100) to an A-F letter grade."""
        if avg_score <= 10:
            return "A"
        if avg_score <= 25:
            return "B"
        if avg_score <= 45:
            return "C"
        if avg_score <= 65:
            return "D"
        return "F"
