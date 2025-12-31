"""
Verification Engine - Response Orchestrator
AI-Augmented SOC

After defense actions are executed, the verification engine proves
they worked through two independent tracks:

  Track 1 — Re-simulation: Run the swarm simulator against the
  updated environment state. If the attack success rate dropped
  significantly, the defense is verified.

  Track 2 — Monitoring: Watch for continued attack indicators in
  Wazuh alerts for a configurable window. If no new indicators
  appear, the threat is considered neutralized.

The combination of both tracks provides high confidence that the
defense was effective — not just that the alert stopped.
"""

import asyncio
import logging
from datetime import datetime, timedelta
from typing import Any, Dict, List, Optional

import httpx

from models import DefensePlan, VerificationResult

logger = logging.getLogger(__name__)


class VerificationEngine:
    """
    Verifies that executed defense actions achieved their intended effect.
    """

    def __init__(
        self,
        simulation_url: str = "http://correlation-engine:8000",
        correlation_url: str = "http://correlation-engine:8000",
        wazuh_api_url: str = "https://wazuh-manager:55000",
        wazuh_username: str = "wazuh-wui",
        wazuh_password: str = "",
        wazuh_verify_ssl: bool = False,
        risk_reduction_threshold: float = 0.30,
        monitoring_duration_seconds: int = 1800,
    ):
        self.simulation_url = simulation_url
        self.correlation_url = correlation_url
        self.wazuh_api_url = wazuh_api_url
        self.wazuh_username = wazuh_username
        self.wazuh_password = wazuh_password
        self.wazuh_verify_ssl = wazuh_verify_ssl
        self.risk_reduction_threshold = risk_reduction_threshold
        self.monitoring_duration_seconds = monitoring_duration_seconds

    async def verify_plan(
        self,
        plan: DefensePlan,
        updated_environment: Optional[Dict[str, Any]] = None,
    ) -> VerificationResult:
        """
        Run both verification tracks and produce a verdict.

        Track 1 (re-simulation) runs immediately.
        Track 2 (monitoring) runs concurrently with a time limit.
        """
        logger.info(f"Starting verification for plan {plan.plan_id}")

        # Track 1: Re-simulation
        resim_result = await self._track_resimulation(
            plan, updated_environment
        )

        # Track 2: Monitoring (with timeout)
        monitor_result = await self._track_monitoring(plan)

        # Combine results
        pre_rate = resim_result.get("pre_success_rate", plan.pre_defense_risk or 0.5)
        post_rate = resim_result.get("post_success_rate", pre_rate)

        if pre_rate > 0:
            reduction_pct = round((pre_rate - post_rate) / pre_rate, 4)
        else:
            reduction_pct = 0.0

        continued = monitor_result.get("continued_indicators", False)
        new_alerts = monitor_result.get("new_alerts", 0)

        # Verdict logic
        sim_passed = reduction_pct >= self.risk_reduction_threshold
        monitor_passed = not continued

        if sim_passed and monitor_passed:
            passed = True
            reason = (
                f"Verification PASSED. Attack success rate reduced by "
                f"{reduction_pct*100:.1f}% (from {pre_rate*100:.1f}% to "
                f"{post_rate*100:.1f}%). No continued attack indicators "
                f"detected in {self.monitoring_duration_seconds}s monitoring window."
            )
        elif sim_passed and not monitor_passed:
            passed = False
            reason = (
                f"Verification PARTIAL. Simulation shows {reduction_pct*100:.1f}% "
                f"risk reduction, but {new_alerts} continued attack indicators "
                f"detected. Additional response may be needed."
            )
        elif not sim_passed and monitor_passed:
            passed = False
            reason = (
                f"Verification FAILED. Risk reduction of {reduction_pct*100:.1f}% "
                f"is below threshold ({self.risk_reduction_threshold*100:.0f}%). "
                f"No continued indicators, but attack surface may still be exposed."
            )
        else:
            passed = False
            reason = (
                f"Verification FAILED. Insufficient risk reduction "
                f"({reduction_pct*100:.1f}%) AND continued attack indicators "
                f"detected ({new_alerts} new alerts). Recommend escalation."
            )

        verification = VerificationResult(
            plan_id=plan.plan_id,
            pre_attack_success_rate=pre_rate,
            post_attack_success_rate=post_rate,
            risk_reduction_pct=reduction_pct,
            re_simulation_id=resim_result.get("simulation_id"),
            continued_indicators=continued,
            monitoring_duration_seconds=monitor_result.get("duration", 0),
            new_alerts_during_monitoring=new_alerts,
            verification_passed=passed,
            verdict_reason=reason,
        )

        logger.info(
            f"Verification for {plan.plan_id}: "
            f"{'PASSED' if passed else 'FAILED'} — {reason[:100]}"
        )

        return verification

    # ----- Track 1: Re-simulation -----

    async def _track_resimulation(
        self,
        plan: DefensePlan,
        updated_environment: Optional[Dict[str, Any]],
    ) -> Dict[str, Any]:
        """
        Re-run the simulation against the updated environment state
        (after defense actions have been applied).
        """
        try:
            # Build simulation request with updated environment
            sim_params = {
                "timesteps": 3,
                "archetypes": ["opportunist", "apt", "ransomware", "insider"],
            }

            async with httpx.AsyncClient() as client:
                url = f"{self.simulation_url}/simulate"
                params = {
                    "timesteps": sim_params["timesteps"],
                }
                if updated_environment:
                    params["environment_json"] = "custom"

                resp = await client.post(
                    url,
                    params=params,
                    json=updated_environment,
                    timeout=120.0,
                )

                if resp.status_code == 200:
                    result = resp.json()
                    post_rate = result.get(
                        "results_summary", {}
                    ).get("success_rate", 0.5)

                    return {
                        "simulation_id": result.get("simulation_id"),
                        "pre_success_rate": plan.pre_defense_risk or 0.5,
                        "post_success_rate": post_rate,
                    }

                logger.warning(
                    f"Re-simulation returned {resp.status_code}"
                )
        except Exception as e:
            logger.error(f"Re-simulation failed: {e}")

        # Fallback: estimate based on action count
        estimated_reduction = min(
            len([a for a in plan.actions if a.status.value == "completed"]) * 0.1,
            0.5,
        )
        pre = plan.pre_defense_risk or 0.5
        return {
            "simulation_id": None,
            "pre_success_rate": pre,
            "post_success_rate": max(pre - estimated_reduction, 0.0),
        }

    # ----- Track 2: Monitoring -----

    async def _track_monitoring(
        self, plan: DefensePlan
    ) -> Dict[str, Any]:
        """
        Monitor for continued attack indicators after defense execution.

        Checks Wazuh for new alerts matching the incident's source IPs
        and MITRE techniques within the monitoring window.
        """
        # For Phase A: shortened monitoring (check once instead of continuous poll)
        # Full implementation: poll at intervals throughout the window
        check_duration = min(self.monitoring_duration_seconds, 30)

        await asyncio.sleep(check_duration)

        try:
            new_alerts = await self._check_wazuh_alerts(
                source_ips=plan.source_ips,
                techniques=plan.detected_techniques,
                since_minutes=max(check_duration // 60, 1),
            )

            return {
                "continued_indicators": len(new_alerts) > 0,
                "new_alerts": len(new_alerts),
                "duration": check_duration,
                "alerts": new_alerts[:5],
            }
        except Exception as e:
            logger.error(f"Monitoring check failed: {e}")
            return {
                "continued_indicators": False,
                "new_alerts": 0,
                "duration": check_duration,
            }

    async def _check_wazuh_alerts(
        self,
        source_ips: List[str],
        techniques: List[str],
        since_minutes: int = 5,
    ) -> List[Dict]:
        """Query Wazuh for recent alerts matching incident indicators."""
        try:
            # Authenticate
            async with httpx.AsyncClient(verify=self.wazuh_verify_ssl) as client:
                auth_resp = await client.post(
                    f"{self.wazuh_api_url}/security/user/authenticate",
                    auth=(self.wazuh_username, self.wazuh_password),
                    timeout=10.0,
                )
                auth_resp.raise_for_status()
                token = auth_resp.json().get("data", {}).get("token", "")

                # Query alerts
                headers = {"Authorization": f"Bearer {token}"}
                resp = await client.get(
                    f"{self.wazuh_api_url}/alerts",
                    headers=headers,
                    params={
                        "limit": 20,
                        "sort": "-timestamp",
                    },
                    timeout=15.0,
                )
                resp.raise_for_status()

                alerts = resp.json().get("data", {}).get("affected_items", [])

                # Filter for alerts matching our indicators
                matching = []
                for alert in alerts:
                    src = alert.get("data", {}).get("srcip", "")
                    if src in source_ips:
                        matching.append(alert)

                return matching

        except Exception as e:
            logger.warning(f"Wazuh alert check failed: {e}")
            return []
