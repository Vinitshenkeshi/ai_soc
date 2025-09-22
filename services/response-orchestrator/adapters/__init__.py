"""
Action Execution Layer - Response Orchestrator
AI-Augmented SOC

Adapter pattern for translating abstract defense actions into concrete
API calls against real infrastructure. Each adapter implements:

  execute()  — Perform the defense action
  verify()   — Confirm the action took effect
  rollback() — Reverse the action if verification fails
  dry_run()  — Simulate without executing (for plan preview)

Adapters are stateless — all state is in the PlannedAction model.
"""

from adapters.base import BaseAdapter, AdapterResult
from adapters.wazuh import WazuhAdapter
from adapters.firewall import FirewallAdapter
from adapters.edr import EDRAdapter
from adapters.identity import IdentityAdapter

__all__ = [
    "BaseAdapter",
    "AdapterResult",
    "WazuhAdapter",
    "FirewallAdapter",
    "EDRAdapter",
    "IdentityAdapter",
]
