"""
Swarm History Store - Persistent Time-Series Storage
AI-Augmented SOC

Stores swarm simulation results as JSONL (one record per line) for both
production monitoring (risk trends over time) and research benchmarking
(scale comparison). No external database dependencies.

Supports both Track A queries (time-series for risk trends) and Track B
queries (config-filtered for benchmark comparison).
"""

import hashlib
import json
import logging
from dataclasses import dataclass, asdict
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

logger = logging.getLogger(__name__)


@dataclass
class SwarmSnapshot:
    """Compact summary of a swarm simulation run."""
    snapshot_id: str
    timestamp: str
    trigger: str  # "manual" | "scheduled" | "benchmark"
    config: Dict
    environment_hash: str
    environment_diff: Optional[Dict]
    metrics: Dict
    full_report_path: Optional[str] = None


class HistoryStore:
    """
    JSONL-based append-only store for swarm simulation results.

    Provides time-series queries for risk trend monitoring and
    config-filtered queries for research benchmark comparison.
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.history_file = self.data_dir / "swarm_history.jsonl"
        self._cache: Optional[List[Dict]] = None

    def append(
        self,
        swarm_report: Dict,
        trigger: str = "manual",
        env_snapshot: Optional[Dict] = None,
    ) -> SwarmSnapshot:
        """Extract metrics from a swarm report and persist as a snapshot."""
        metrics = self._extract_metrics(swarm_report)
        env_hash = self._compute_env_hash(env_snapshot) if env_snapshot else ""

        # Compute environment diff from previous run
        env_diff = None
        prev = self.get_latest()
        if prev and env_snapshot and prev.get("environment_hash"):
            env_diff = self._compute_env_diff_from_snapshots(prev, env_snapshot)

        snapshot = SwarmSnapshot(
            snapshot_id=swarm_report.get("swarm_id", "unknown"),
            timestamp=swarm_report.get("timestamp", datetime.utcnow().isoformat()),
            trigger=trigger,
            config=swarm_report.get("config", {}),
            environment_hash=env_hash,
            environment_diff=env_diff,
            metrics=metrics,
        )

        # Append to JSONL
        with open(self.history_file, "a") as f:
            f.write(json.dumps(asdict(snapshot), default=str) + "\n")

        self._cache = None  # invalidate
        logger.info(f"Stored swarm snapshot: {snapshot.snapshot_id} (trigger={trigger})")
        return snapshot

    def get_trend(
        self, last_n: Optional[int] = None, since: Optional[str] = None
    ) -> List[Dict]:
        """Get time-ordered snapshots for trend charts."""
        snapshots = self._load_all()

        if since:
            snapshots = [s for s in snapshots if s.get("timestamp", "") >= since]

        snapshots.sort(key=lambda s: s.get("timestamp", ""))

        if last_n:
            snapshots = snapshots[-last_n:]

        return snapshots

    def get_by_config(
        self,
        trigger: Optional[str] = None,
        swarm_size: Optional[int] = None,
        leaders_per_archetype: Optional[int] = None,
    ) -> List[Dict]:
        """Filter snapshots by config parameters (for benchmark comparison)."""
        snapshots = self._load_all()
        result = []
        for s in snapshots:
            cfg = s.get("config", {})
            if trigger and s.get("trigger") != trigger:
                continue
            if swarm_size is not None and cfg.get("swarm_size") != swarm_size:
                continue
            if leaders_per_archetype is not None and cfg.get("leaders_per_archetype") != leaders_per_archetype:
                continue
            result.append(s)
        return result

    def get_latest(self) -> Optional[Dict]:
        """Most recent snapshot."""
        snapshots = self._load_all()
        if not snapshots:
            return None
        snapshots.sort(key=lambda s: s.get("timestamp", ""))
        return snapshots[-1]

    def detect_risk_spike(self, threshold: float = 0.20) -> Optional[Dict]:
        """Compare latest two snapshots. Alert if compromise rate jumped."""
        snapshots = self.get_trend(last_n=2)
        if len(snapshots) < 2:
            return None

        prev, curr = snapshots[0], snapshots[1]
        prev_rates = prev.get("metrics", {}).get("host_compromise_rates", {})
        curr_rates = curr.get("metrics", {}).get("host_compromise_rates", {})

        spikes = []
        for ip in curr_rates:
            old_rate = prev_rates.get(ip, 0)
            new_rate = curr_rates[ip]
            if new_rate - old_rate > threshold:
                spikes.append({
                    "host": ip,
                    "previous_rate": round(old_rate, 4),
                    "current_rate": round(new_rate, 4),
                    "increase": round(new_rate - old_rate, 4),
                })

        if spikes:
            return {
                "alert": "risk_spike",
                "timestamp": curr.get("timestamp"),
                "spikes": spikes,
                "environment_diff": curr.get("environment_diff"),
            }
        return None

    # --- Internal helpers ---

    def _load_all(self) -> List[Dict]:
        """Load all snapshots from JSONL file."""
        if self._cache is not None:
            return self._cache

        snapshots = []
        if self.history_file.exists():
            with open(self.history_file) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        try:
                            snapshots.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        self._cache = snapshots
        return snapshots

    def _extract_metrics(self, report: Dict) -> Dict:
        """Extract compact metrics from a full swarm report."""
        heatmap = report.get("host_risk_heatmap", {})
        arch_stats = report.get("archetype_statistics", {})
        confidence = report.get("statistical_confidence", {})
        cross_batch = report.get("cross_batch_intelligence", {})
        emergent = report.get("emergent_discoveries", [])

        # Overall compromise rate (average across hosts)
        rates = [h.get("compromise_rate", 0) for h in heatmap.values()]
        overall_rate = sum(rates) / len(rates) if rates else 0

        return {
            "overall_compromise_rate": round(overall_rate, 4),
            "host_compromise_rates": {
                ip: round(h.get("compromise_rate", 0), 4)
                for ip, h in heatmap.items()
            },
            "archetype_success_rates": {
                name: round(s.get("success_rate_mean", 0), 4)
                for name, s in arch_stats.items()
            },
            "convergence_achieved": confidence.get("convergence_achieved", False),
            "convergence_batch": confidence.get("convergence_batch", -1),
            "emergent_discovery_count": len(emergent),
            "unique_paths_discovered": cross_batch.get("total_unique_strategies", 0),
            "strategic_diversity_score": cross_batch.get("strategic_diversity_score", 0),
            "attacker_learning_trend": cross_batch.get("attacker_learning_trend", "unknown"),
            "duration_ms": report.get("duration_ms", 0),
            "total_agent_runs": report.get("total_agent_runs", 0),
        }

    def _compute_env_hash(self, env_snapshot: Dict) -> str:
        """Deterministic hash of environment configuration."""
        canonical = json.dumps(env_snapshot, sort_keys=True, default=str)
        return hashlib.md5(canonical.encode()).hexdigest()[:12]

    def _compute_env_diff_from_snapshots(
        self, prev_snapshot: Dict, current_env: Dict
    ) -> Dict:
        """Identify what changed between two environment states."""
        # We don't store the full env in the snapshot, so this is best-effort
        # based on the environment hash change
        prev_hash = prev_snapshot.get("environment_hash", "")
        curr_hash = self._compute_env_hash(current_env)

        if prev_hash == curr_hash:
            return {"changed": False, "details": []}

        return {
            "changed": True,
            "previous_hash": prev_hash,
            "current_hash": curr_hash,
            "details": ["Environment configuration changed between runs"],
        }
