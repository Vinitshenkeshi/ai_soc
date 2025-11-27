"""
Firewall Adapter - Action Execution Layer
AI-Augmented SOC

Adapter for firewall integrations (pfSense, Palo Alto, AWS Security Groups).
Phase A: Stub implementation that logs actions and returns success.
Production: Replace with real API calls.
"""

import logging
from typing import Any, Dict, Optional

from adapters.base import BaseAdapter, AdapterResult

logger = logging.getLogger(__name__)


class FirewallAdapter(BaseAdapter):
    """
    Firewall API adapter for network-level defense actions.

    Supports: block_ip, network_segment, sinkhole_domain
    Production targets: pfSense API, Palo Alto PAN-OS, AWS Security Groups
    """

    def __init__(
        self,
        firewall_type: str = "stub",
        api_url: str = "",
        api_key: str = "",
    ):
        super().__init__(name="firewall")
        self.firewall_type = firewall_type
        self.api_url = api_url
        self.api_key = api_key

    async def execute(
        self, action_type: str, target: str, params: Optional[Dict] = None
    ) -> AdapterResult:
        """Execute a firewall-level defense action."""
        params = params or {}

        if action_type == "block_ip":
            return await self._block_ip(target, params)
        elif action_type == "network_segment":
            return await self._segment_network(target, params)
        elif action_type == "sinkhole_domain":
            return await self._sinkhole_domain(target, params)

        return AdapterResult(
            success=False,
            action_type=action_type,
            target=target,
            adapter=self.name,
            detail=f"Unsupported action for firewall adapter: {action_type}",
            error="Unsupported action",
        )

    async def _block_ip(self, target: str, params: Dict) -> AdapterResult:
        """Block an IP at the perimeter firewall."""
        direction = params.get("direction", "both")  # inbound, outbound, both
        duration = params.get("duration_hours", 24)

        self.logger.info(
            f"[FIREWALL] Block IP {target} direction={direction} "
            f"duration={duration}h type={self.firewall_type}"
        )

        # Stub: In production, call pfSense/PAN-OS/AWS API
        return AdapterResult(
            success=True,
            action_type="block_ip",
            target=target,
            adapter=self.name,
            detail=f"IP {target} blocked at {self.firewall_type} firewall "
                   f"({direction}, {duration}h TTL)",
            raw_response={
                "firewall_type": self.firewall_type,
                "rule_direction": direction,
                "ttl_hours": duration,
            },
        )

    async def _segment_network(self, target: str, params: Dict) -> AdapterResult:
        """Modify network segmentation rules."""
        source_segment = params.get("source_segment", "")
        dest_segment = params.get("dest_segment", "")

        self.logger.info(
            f"[FIREWALL] Segment: block {source_segment} -> {dest_segment}"
        )

        return AdapterResult(
            success=True,
            action_type="network_segment",
            target=target,
            adapter=self.name,
            detail=f"Network segmentation rule applied: "
                   f"{source_segment} cannot reach {dest_segment}",
            raw_response={
                "source_segment": source_segment,
                "dest_segment": dest_segment,
            },
        )

    async def _sinkhole_domain(self, target: str, params: Dict) -> AdapterResult:
        """Sinkhole a malicious domain via DNS policy."""
        domain = params.get("domain", target)

        self.logger.info(f"[FIREWALL] Sinkhole domain: {domain}")

        return AdapterResult(
            success=True,
            action_type="sinkhole_domain",
            target=domain,
            adapter=self.name,
            detail=f"Domain {domain} sinkholed — DNS resolves to 0.0.0.0",
        )

    async def dry_run(
        self, action_type: str, target: str, params: Optional[Dict] = None
    ) -> AdapterResult:
        """Detailed dry-run showing exactly what API calls would be made."""
        params = params or {}
        api_calls = {
            "block_ip": {
                "method": "POST",
                "endpoint": f"{self.api_url}/api/v1/firewall/rules" if self.api_url else "/api/v1/firewall/rules",
                "body": {
                    "action": "block", "source": target,
                    "direction": params.get("direction", "both"),
                    "ttl_hours": params.get("duration_hours", 24),
                },
                "description": f"Add {self.firewall_type} rule to block {target}",
            },
            "network_segment": {
                "method": "POST",
                "endpoint": "/api/v1/firewall/rules",
                "body": {
                    "action": "deny",
                    "source_zone": params.get("source_segment", ""),
                    "dest_zone": params.get("dest_segment", ""),
                },
                "description": f"Add inter-segment deny rule via {self.firewall_type}",
            },
            "sinkhole_domain": {
                "method": "POST",
                "endpoint": "/api/v1/dns/overrides",
                "body": {"domain": params.get("domain", target), "target": "0.0.0.0"},
                "description": f"Sinkhole DNS for {params.get('domain', target)}",
            },
        }
        call = api_calls.get(action_type, {
            "description": f"Unknown action {action_type}",
            "method": "N/A", "endpoint": "N/A", "body": {},
        })
        return AdapterResult(
            success=True,
            action_type=action_type,
            target=target,
            adapter=self.name,
            detail=f"[DRY RUN] {call['description']}",
            raw_response={"would_call": call, "firewall_type": self.firewall_type},
            rollback_capable=True,
        )

    async def verify(
        self, action_type: str, target: str, params: Optional[Dict] = None
    ) -> AdapterResult:
        """Verify firewall rule is active."""
        return AdapterResult(
            success=True,
            action_type=action_type,
            target=target,
            adapter=self.name,
            detail=f"Firewall rule for {target} verified active",
        )

    async def rollback(
        self, action_type: str, target: str, params: Optional[Dict] = None
    ) -> AdapterResult:
        """Remove firewall rule."""
        self.logger.info(f"[FIREWALL] Rollback {action_type} for {target}")
        return AdapterResult(
            success=True,
            action_type=action_type,
            target=target,
            adapter=self.name,
            detail=f"Firewall rule for {target} removed",
        )
