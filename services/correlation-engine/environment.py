"""
Infrastructure Environment Model - Attack Campaign Simulator
AI-Augmented SOC

Represents the target organization's infrastructure as a state machine.
Hosts, network segments, defenses, and vulnerabilities form the attack
surface. State mutations track compromise progression during simulation.

Loaded from JSON config. Future: auto-populate from Wazuh agent API.
"""

import copy
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Set

logger = logging.getLogger(__name__)


@dataclass
class ServiceInfo:
    """A running service on a host."""
    name: str
    port: int
    version: str = ""
    protocol: str = "tcp"
    exposed_externally: bool = False
    cves: List[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "port": self.port,
            "version": self.version,
            "exposed_externally": self.exposed_externally,
            "cves": self.cves,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "ServiceInfo":
        return cls(
            name=data["name"],
            port=data["port"],
            version=data.get("version", ""),
            protocol=data.get("protocol", "tcp"),
            exposed_externally=data.get("exposed_externally", False),
            cves=data.get("cves", []),
        )


@dataclass
class HostDefenses:
    """Security controls present on a host."""
    edr_present: bool = False
    mfa_enabled: bool = False
    firewall_enabled: bool = True
    patched: bool = True
    wazuh_agent: bool = False

    def to_dict(self) -> dict:
        return {
            "edr_present": self.edr_present,
            "mfa_enabled": self.mfa_enabled,
            "firewall_enabled": self.firewall_enabled,
            "patched": self.patched,
            "wazuh_agent": self.wazuh_agent,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "HostDefenses":
        return cls(**{k: v for k, v in data.items() if k in cls.__dataclass_fields__})


@dataclass
class Host:
    """A single host in the infrastructure."""
    ip: str
    hostname: str
    os_type: str = "linux"
    criticality: str = "medium"  # low, medium, high, critical
    services: List[ServiceInfo] = field(default_factory=list)
    defenses: HostDefenses = field(default_factory=HostDefenses)

    # Mutable state — changes during simulation
    compromised: bool = False
    admin_access: bool = False
    persistence_installed: bool = False
    credentials_dumped: bool = False
    isolated: bool = False  # Defender isolated this host from network

    def has_cves(self) -> bool:
        return any(svc.cves for svc in self.services)

    def get_cves(self) -> List[str]:
        cves = []
        for svc in self.services:
            cves.extend(svc.cves)
        return cves

    def has_exposed_services(self) -> bool:
        return any(svc.exposed_externally for svc in self.services)

    def to_dict(self) -> dict:
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "os": self.os_type,
            "criticality": self.criticality,
            "services": [s.to_dict() for s in self.services],
            "defenses": self.defenses.to_dict(),
            "compromised": self.compromised,
            "admin_access": self.admin_access,
            "persistence_installed": self.persistence_installed,
        }

    def to_observation(self, discovered: bool = False) -> dict:
        """What an attacker can see about this host."""
        obs = {"ip": self.ip, "hostname": self.hostname, "os": self.os_type}
        if discovered:
            obs["criticality"] = self.criticality
            obs["services"] = [
                {"name": s.name, "port": s.port, "version": s.version}
                for s in self.services
            ]
            obs["has_cves"] = self.has_cves()
            obs["edr_present"] = self.defenses.edr_present
            obs["mfa_enabled"] = self.defenses.mfa_enabled
        return obs

    @classmethod
    def from_dict(cls, ip: str, data: dict) -> "Host":
        services = [ServiceInfo.from_dict(s) for s in data.get("services", [])]
        defenses = HostDefenses.from_dict(data.get("defenses", {}))
        return cls(
            ip=ip,
            hostname=data.get("hostname", ip),
            os_type=data.get("os", "linux"),
            criticality=data.get("criticality", "medium"),
            services=services,
            defenses=defenses,
        )


@dataclass
class NetworkSegment:
    """A network segment containing hosts."""
    name: str
    host_ips: List[str] = field(default_factory=list)
    reachable_from: List[str] = field(default_factory=list)

    @classmethod
    def from_dict(cls, name: str, data: dict) -> "NetworkSegment":
        return cls(
            name=name,
            host_ips=data.get("hosts", []),
            reachable_from=data.get("reachable_from", []),
        )


class Environment:
    """
    The target infrastructure environment.

    Contains hosts organized into network segments with reachability rules.
    Provides methods for querying infrastructure state and building
    observations for attacker agents.
    """

    def __init__(
        self,
        hosts: Dict[str, Host],
        segments: Dict[str, NetworkSegment],
        name: str = "default",
    ):
        self.hosts = hosts
        self.segments = segments
        self.name = name
        self._initial_state = None
        # Defender-mutable state
        self.blocked_ips: Set[str] = set()
        self.isolated_hosts: Set[str] = set()
        self.credentials_revoked: bool = False

    def save_initial_state(self):
        """Save initial state for reset."""
        self._initial_state = {
            ip: {
                "compromised": h.compromised,
                "admin_access": h.admin_access,
                "persistence_installed": h.persistence_installed,
                "credentials_dumped": h.credentials_dumped,
                "isolated": h.isolated,
            }
            for ip, h in self.hosts.items()
        }

    def reset(self):
        """Restore all hosts to initial state."""
        if self._initial_state:
            for ip, state in self._initial_state.items():
                host = self.hosts.get(ip)
                if host:
                    host.compromised = state["compromised"]
                    host.admin_access = state["admin_access"]
                    host.persistence_installed = state["persistence_installed"]
                    host.credentials_dumped = state["credentials_dumped"]
                    host.isolated = state.get("isolated", False)
        self.blocked_ips = set()
        self.isolated_hosts = set()
        self.credentials_revoked = False

    def get_host(self, ip: str) -> Optional[Host]:
        return self.hosts.get(ip)

    def get_all_hosts(self) -> List[Host]:
        return list(self.hosts.values())

    def get_externally_exposed(self) -> List[Host]:
        """Hosts with at least one externally exposed service."""
        return [h for h in self.hosts.values() if h.has_exposed_services()]

    def get_segment_for_host(self, ip: str) -> Optional[NetworkSegment]:
        for seg in self.segments.values():
            if ip in seg.host_ips:
                return seg
        return None

    def get_reachable_hosts(self, from_ip: str) -> List[Host]:
        """
        Get hosts reachable from a given IP based on network topology.
        A host can reach all hosts in its own segment plus hosts in
        segments that list its segment in reachable_from.
        """
        source_segment = self.get_segment_for_host(from_ip)
        if not source_segment:
            return []

        reachable_ips: Set[str] = set()

        # Hosts in the same segment
        reachable_ips.update(source_segment.host_ips)

        # Hosts in segments reachable from this segment
        for seg in self.segments.values():
            if source_segment.name in seg.reachable_from:
                reachable_ips.update(seg.host_ips)

        # Remove self
        reachable_ips.discard(from_ip)

        # Remove isolated hosts (defender action)
        reachable_ips -= self.isolated_hosts

        # If source is isolated, it can't reach anything
        if from_ip in self.isolated_hosts:
            return []

        return [self.hosts[ip] for ip in reachable_ips if ip in self.hosts]

    def snapshot(self) -> dict:
        """Full serializable state of the environment."""
        return {
            "name": self.name,
            "hosts": {ip: h.to_dict() for ip, h in self.hosts.items()},
            "segments": {
                name: {"hosts": seg.host_ips, "reachable_from": seg.reachable_from}
                for name, seg in self.segments.items()
            },
            "compromised_hosts": [
                ip for ip, h in self.hosts.items() if h.compromised
            ],
            "isolated_hosts": list(self.isolated_hosts),
            "blocked_ips": list(self.blocked_ips),
            "credentials_revoked": self.credentials_revoked,
        }

    def to_observation(self, discovered_ips: Set[str]) -> dict:
        """Build observation dict for an attacker agent."""
        obs = {
            "known_hosts": [],
            "externally_exposed": [],
            "compromised_hosts": [],
        }

        for ip in discovered_ips:
            host = self.hosts.get(ip)
            if host:
                obs["known_hosts"].append(host.to_observation(discovered=True))
                if host.compromised:
                    obs["compromised_hosts"].append(ip)

        for host in self.get_externally_exposed():
            if host.ip not in discovered_ips:
                obs["externally_exposed"].append(
                    {"ip": host.ip, "hostname": host.hostname}
                )

        return obs

    def to_defender_observation(self, alerts: List[dict], defender_state) -> dict:
        """Build observation for a defender agent.

        Defenders see alerts from detection systems, host status for monitored
        hosts, and their own prior actions. They do NOT see undetected compromise
        or attacker identities.
        """
        obs = {
            "alerts": alerts,
            "monitored_hosts": [],
            "isolated_hosts": list(self.isolated_hosts),
            "blocked_ips": list(self.blocked_ips),
            "credentials_revoked": self.credentials_revoked,
            "prior_actions": {
                "investigated": list(defender_state.investigated_hosts),
                "blocked": list(defender_state.blocked_ips),
                "isolated": list(defender_state.isolated_hosts),
                "edr_deployed": list(defender_state.edr_deployed),
            },
        }

        # Defenders can only see host status for hosts with detection capability
        for ip, host in self.hosts.items():
            if host.defenses.wazuh_agent or host.defenses.edr_present:
                host_info = {
                    "ip": ip,
                    "hostname": host.hostname,
                    "os": host.os_type,
                    "criticality": host.criticality,
                    "edr_present": host.defenses.edr_present,
                    "wazuh_agent": host.defenses.wazuh_agent,
                    "isolated": host.isolated,
                }
                # Investigation reveals compromise state
                if ip in defender_state.investigated_hosts:
                    host_info["compromised"] = host.compromised
                    host_info["admin_access"] = host.admin_access
                    host_info["persistence_installed"] = host.persistence_installed
                obs["monitored_hosts"].append(host_info)

        return obs

    @classmethod
    def load_from_json(cls, path: str) -> "Environment":
        """Load environment from a JSON configuration file."""
        config_path = Path(path)
        if not config_path.exists():
            raise FileNotFoundError(f"Environment config not found: {path}")

        with open(config_path) as f:
            data = json.load(f)

        hosts = {}
        for ip, host_data in data.get("hosts", {}).items():
            hosts[ip] = Host.from_dict(ip, host_data)

        segments = {}
        for seg_name, seg_data in data.get("segments", {}).items():
            segments[seg_name] = NetworkSegment.from_dict(seg_name, seg_data)

        env = cls(
            hosts=hosts,
            segments=segments,
            name=data.get("name", "default"),
        )
        env.save_initial_state()

        logger.info(
            f"Loaded environment '{env.name}': "
            f"{len(hosts)} hosts, {len(segments)} segments"
        )
        return env

    @classmethod
    def from_dict(cls, data: dict) -> "Environment":
        """Load environment from a dict (for API requests)."""
        hosts = {}
        for ip, host_data in data.get("hosts", {}).items():
            hosts[ip] = Host.from_dict(ip, host_data)

        segments = {}
        for seg_name, seg_data in data.get("segments", {}).items():
            segments[seg_name] = NetworkSegment.from_dict(seg_name, seg_data)

        env = cls(
            hosts=hosts,
            segments=segments,
            name=data.get("name", "api-provided"),
        )
        env.save_initial_state()
        return env
