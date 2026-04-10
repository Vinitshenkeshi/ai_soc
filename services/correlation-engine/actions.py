"""
Attack Action Space - Attack Campaign Simulator
AI-Augmented SOC

20 attack actions mapped to MITRE ATT&CK techniques. Each action has
prerequisites, a probabilistic success evaluator, observability score,
and state mutations. The LLM selects actions. The evaluator determines outcomes.

Defense layers reduce success probability multiplicatively:
  EDR, MFA, firewall, patching, and monitoring each contribute.
  No defense is 100% effective. No attack is guaranteed.
"""

import random
import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import List, Dict, Optional, Set

logger = logging.getLogger(__name__)


class ActionResult(str, Enum):
    SUCCESS = "success"
    FAILURE = "failure"
    DETECTED = "detected"       # succeeded but SOC saw it
    BLOCKED = "blocked"         # defense actively prevented it


@dataclass
class ActionOutcome:
    action_id: str
    result: ActionResult
    target_ip: str
    detail: str
    detected: bool
    kill_chain_stage: str
    mitre_technique_id: str
    data: Dict = field(default_factory=dict)  # returned info (e.g., open ports)


@dataclass
class AgentState:
    """Tracks what an attacker agent knows and has achieved."""
    discovered_hosts: Set[str] = field(default_factory=set)
    discovered_services: Dict[str, List[Dict]] = field(default_factory=dict)  # ip -> [{port, service}]
    compromised_hosts: Set[str] = field(default_factory=set)
    admin_hosts: Set[str] = field(default_factory=set)
    credentials_dumped: Set[str] = field(default_factory=set)
    persistence_hosts: Set[str] = field(default_factory=set)
    edr_bypassed: Set[str] = field(default_factory=set)
    exfiltrated: bool = False
    starting_access: Optional[str] = None  # For insider archetype


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _is_detected(observability: float) -> bool:
    """Roll detection based on observability score."""
    return random.random() < observability


def _resolve_result(success: bool, detected: bool) -> ActionResult:
    """Map success + detected flags to a canonical ActionResult."""
    if success and detected:
        return ActionResult.DETECTED
    if success:
        return ActionResult.SUCCESS
    return ActionResult.FAILURE


def _defense_success_probability(host, action_type: str) -> float:
    """Calculate probability of action success based on host defenses.

    Each defense layer multiplies the base success rate down.
    Multiple defenses compound — fully defended hosts are hard but not impossible.
    This creates realistic variance for Monte Carlo exploration.

    Returns a probability in [0.02, base_rate].
    """
    BASE_RATES = {
        "exploit_public_service": 0.85,
        "brute_force_creds": 0.70,
        "pivot_to_host": 0.75,
        "pass_the_hash": 0.80,
        "exploit_local_vuln": 0.80,
        "deploy_payload": 0.75,
        "credential_dump": 0.70,
    }

    prob = BASE_RATES.get(action_type, 0.70)
    defenses = host.defenses

    if defenses.edr_present:
        prob *= 0.50
    if defenses.mfa_enabled:
        if action_type in ("brute_force_creds", "pass_the_hash"):
            prob *= 0.15  # MFA devastating for credential attacks
        else:
            prob *= 0.85
    if defenses.firewall_enabled:
        if action_type in ("pivot_to_host", "pass_the_hash", "exploit_public_service"):
            prob *= 0.55  # firewall blocks many network actions
        else:
            prob *= 0.90
    if defenses.patched:
        if action_type in ("exploit_public_service", "exploit_local_vuln"):
            prob *= 0.10  # patched = huge reduction for CVE exploits
        else:
            prob *= 0.90
    if defenses.wazuh_agent:
        prob *= 0.85

    return max(prob, 0.02)  # floor at 2% — nothing is impossible


# ---------------------------------------------------------------------------
# Action definitions
# ---------------------------------------------------------------------------

def _build_port_scan() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        # Always available — attacker just needs a target list
        return len(env.get_all_hosts()) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.6
        detected = _is_detected(observability)

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="port_scan",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Target {target_ip} not reachable",
                detected=False,
                kill_chain_stage="reconnaissance",
                mitre_technique_id="T1046",
                data={},
            )

        # Record discovery
        agent_state.discovered_hosts.add(target_ip)
        open_ports = [
            {"port": svc.port, "service": svc.name, "version": svc.version}
            for svc in host.services
        ]
        agent_state.discovered_services[target_ip] = open_ports

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="port_scan",
            result=result,
            target_ip=target_ip,
            detail=f"Discovered {len(open_ports)} open ports on {target_ip}",
            detected=detected,
            kill_chain_stage="reconnaissance",
            mitre_technique_id="T1046",
            data={"open_ports": open_ports},
        )

    return {
        "action_id": "port_scan",
        "name": "Port Scan",
        "description": "Enumerate open ports and running services on target host",
        "kill_chain_stage": "reconnaissance",
        "mitre_technique": "T1046",
        "mitre_name": "Network Service Discovery",
        "observability": 0.6,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_osint_enum() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(env.get_externally_exposed()) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.1
        detected = _is_detected(observability)

        exposed_hosts = env.get_externally_exposed()
        exposed_ips = [h.ip for h in exposed_hosts]

        agent_state.discovered_hosts.update(exposed_ips)
        services_found = {}
        for host in exposed_hosts:
            svc_list = [
                {"port": svc.port, "service": svc.name, "version": svc.version, "cves": svc.cves}
                for svc in host.services
                if svc.exposed_externally
            ]
            services_found[host.ip] = svc_list
            agent_state.discovered_services[host.ip] = svc_list

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="osint_enum",
            result=result,
            target_ip=target_ip,
            detail=f"OSINT enumeration revealed {len(exposed_ips)} externally exposed hosts",
            detected=detected,
            kill_chain_stage="reconnaissance",
            mitre_technique_id="T1593",
            data={"exposed_hosts": exposed_ips, "services": services_found},
        )

    return {
        "action_id": "osint_enum",
        "name": "OSINT Enumeration",
        "description": "Passively enumerate publicly exposed services and metadata",
        "kill_chain_stage": "reconnaissance",
        "mitre_technique": "T1593",
        "mitre_name": "Search Open Websites/Domains",
        "observability": 0.1,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_exploit_public_service() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        # Need at least one discovered host with a known CVE
        for ip in agent_state.discovered_hosts:
            try:
                host = env.get_host(ip)
                for svc in host.services:
                    if svc.cves:
                        return True
            except Exception:
                continue
        return False

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.7
        detected = _is_detected(observability)

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="exploit_public_service",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1190",
            )

        # Need a CVE-bearing service to attempt exploit
        vulnerable_svc = next(
            (svc for svc in host.services if svc.cves),
            None,
        )

        if vulnerable_svc is None:
            return ActionOutcome(
                action_id="exploit_public_service",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No known CVEs found on {target_ip}",
                detected=detected,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1190",
            )

        # Probabilistic success based on host defenses
        prob = _defense_success_probability(host, "exploit_public_service")
        success = random.random() < prob

        if not success:
            return ActionOutcome(
                action_id="exploit_public_service",
                result=ActionResult.BLOCKED,
                target_ip=target_ip,
                detail=(
                    f"Exploit attempt against {vulnerable_svc.cves[0]} on {target_ip} "
                    f"was blocked by defenses (p={prob:.0%})"
                ),
                detected=detected,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1190",
            )

        # Exploit succeeds — mark host compromised
        host.compromised = True
        agent_state.compromised_hosts.add(target_ip)
        agent_state.discovered_hosts.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="exploit_public_service",
            result=result,
            target_ip=target_ip,
            detail=(
                f"Exploited {vulnerable_svc.name} on port {vulnerable_svc.port} "
                f"via {vulnerable_svc.cves[0]} on {target_ip} (p={prob:.0%})"
            ),
            detected=detected,
            kill_chain_stage="initial_access",
            mitre_technique_id="T1190",
            data={"exploited_cve": vulnerable_svc.cves[0], "service": vulnerable_svc.name,
                  "success_probability": round(prob, 4)},
        )

    return {
        "action_id": "exploit_public_service",
        "name": "Exploit Public-Facing Application",
        "description": "Exploit a known CVE in an externally exposed service",
        "kill_chain_stage": "initial_access",
        "mitre_technique": "T1190",
        "mitre_name": "Exploit Public-Facing Application",
        "observability": 0.7,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_brute_force_creds() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.discovered_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.8
        detected = _is_detected(observability)

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="brute_force_creds",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1110",
            )

        # Probabilistic: MFA heavily reduces but doesn't eliminate (token theft, MFA fatigue)
        prob = _defense_success_probability(host, "brute_force_creds")
        success = random.random() < prob

        if not success:
            reason = "MFA blocked authentication" if host.defenses.mfa_enabled else "Brute force unsuccessful"
            return ActionOutcome(
                action_id="brute_force_creds",
                result=ActionResult.BLOCKED if host.defenses.mfa_enabled else ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"{reason} on {target_ip} (p={prob:.0%})",
                detected=detected,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1110",
            )

        host.compromised = True
        agent_state.compromised_hosts.add(target_ip)
        agent_state.discovered_hosts.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="brute_force_creds",
            result=result,
            target_ip=target_ip,
            detail=f"Credential brute force succeeded on {target_ip} (p={prob:.0%})",
            detected=detected,
            kill_chain_stage="initial_access",
            mitre_technique_id="T1110",
            data={"success_probability": round(prob, 4)},
        )

    return {
        "action_id": "brute_force_creds",
        "name": "Brute Force Credentials",
        "description": "Systematically guess credentials on an accessible service",
        "kill_chain_stage": "initial_access",
        "mitre_technique": "T1110",
        "mitre_name": "Brute Force",
        "observability": 0.8,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_phishing() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(env.get_all_hosts()) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.4
        detected = _is_detected(observability)

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="phishing",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1566",
            )

        # Base success probability; lower if host has security-aware config
        base_prob = 0.4
        # If the environment marks security training (use wazuh_agent as a proxy
        # for a hardened/monitored endpoint — if present, users are more alert)
        if host.defenses.wazuh_agent:
            base_prob *= 0.6

        success = random.random() < base_prob

        if not success:
            return ActionOutcome(
                action_id="phishing",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Phishing attempt against {target_ip} was unsuccessful — user did not click",
                detected=detected,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1566",
            )

        host.compromised = True
        agent_state.compromised_hosts.add(target_ip)
        agent_state.discovered_hosts.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="phishing",
            result=result,
            target_ip=target_ip,
            detail=f"Phishing email clicked on {target_ip}; initial foothold established",
            detected=detected,
            kill_chain_stage="initial_access",
            mitre_technique_id="T1566",
        )

    return {
        "action_id": "phishing",
        "name": "Phishing",
        "description": "Send malicious email to gain initial access via user interaction",
        "kill_chain_stage": "initial_access",
        "mitre_technique": "T1566",
        "mitre_name": "Phishing",
        "observability": 0.4,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_exploit_weak_password() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.discovered_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.5
        detected = _is_detected(observability)

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="exploit_weak_password",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1078",
            )

        # Requires no MFA and host is not patched (patched implies hardened creds policy)
        has_weak_creds = not host.defenses.mfa_enabled and not host.defenses.patched
        if not has_weak_creds:
            return ActionOutcome(
                action_id="exploit_weak_password",
                result=ActionResult.BLOCKED,
                target_ip=target_ip,
                detail=f"No default/weak credentials found on {target_ip}",
                detected=detected,
                kill_chain_stage="initial_access",
                mitre_technique_id="T1078",
            )

        host.compromised = True
        agent_state.compromised_hosts.add(target_ip)
        agent_state.discovered_hosts.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="exploit_weak_password",
            result=result,
            target_ip=target_ip,
            detail=f"Default/weak credentials exploited on {target_ip}",
            detected=detected,
            kill_chain_stage="initial_access",
            mitre_technique_id="T1078",
        )

    return {
        "action_id": "exploit_weak_password",
        "name": "Exploit Weak Password",
        "description": "Authenticate using default or weak credentials on target service",
        "kill_chain_stage": "initial_access",
        "mitre_technique": "T1078",
        "mitre_name": "Valid Accounts",
        "observability": 0.5,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_execute_command() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.compromised_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.5
        detected = _is_detected(observability)

        if target_ip not in agent_state.compromised_hosts:
            return ActionOutcome(
                action_id="execute_command",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No foothold on {target_ip}; cannot execute commands",
                detected=False,
                kill_chain_stage="execution",
                mitre_technique_id="T1059",
            )

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="execute_command",
            result=result,
            target_ip=target_ip,
            detail=f"Remote command executed successfully on {target_ip}",
            detected=detected,
            kill_chain_stage="execution",
            mitre_technique_id="T1059",
            data={"shell": "cmd/bash"},
        )

    return {
        "action_id": "execute_command",
        "name": "Execute Command",
        "description": "Run arbitrary commands on compromised host via interpreter",
        "kill_chain_stage": "execution",
        "mitre_technique": "T1059",
        "mitre_name": "Command and Scripting Interpreter",
        "observability": 0.5,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_deploy_payload() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        # Needs a compromised host where EDR is absent or bypassed
        for ip in agent_state.compromised_hosts:
            try:
                host = env.get_host(ip)
                if not host.defenses.edr_present or ip in agent_state.edr_bypassed:
                    return True
            except Exception:
                continue
        return False

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.6
        detected = _is_detected(observability)

        if target_ip not in agent_state.compromised_hosts:
            return ActionOutcome(
                action_id="deploy_payload",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No foothold on {target_ip}",
                detected=False,
                kill_chain_stage="execution",
                mitre_technique_id="T1105",
            )

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="deploy_payload",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="execution",
                mitre_technique_id="T1105",
            )

        edr_blocked = host.defenses.edr_present and target_ip not in agent_state.edr_bypassed
        if edr_blocked:
            return ActionOutcome(
                action_id="deploy_payload",
                result=ActionResult.BLOCKED,
                target_ip=target_ip,
                detail=f"EDR on {target_ip} blocked payload execution",
                detected=True,
                kill_chain_stage="execution",
                mitre_technique_id="T1105",
            )

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="deploy_payload",
            result=result,
            target_ip=target_ip,
            detail=f"Payload transferred and executed on {target_ip}",
            detected=detected,
            kill_chain_stage="execution",
            mitre_technique_id="T1105",
        )

    return {
        "action_id": "deploy_payload",
        "name": "Deploy Payload",
        "description": "Transfer and execute malicious payload on compromised host",
        "kill_chain_stage": "execution",
        "mitre_technique": "T1105",
        "mitre_name": "Ingress Tool Transfer",
        "observability": 0.6,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_install_backdoor() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.compromised_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.4
        detected = _is_detected(observability)

        if target_ip not in agent_state.compromised_hosts:
            return ActionOutcome(
                action_id="install_backdoor",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No foothold on {target_ip}",
                detected=False,
                kill_chain_stage="persistence",
                mitre_technique_id="T1547",
            )

        try:
            host = env.get_host(target_ip)
            host.persistence_installed = True
        except Exception:
            pass

        agent_state.persistence_hosts.add(target_ip)
        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="install_backdoor",
            result=result,
            target_ip=target_ip,
            detail=f"Backdoor implant installed for persistent access on {target_ip}",
            detected=detected,
            kill_chain_stage="persistence",
            mitre_technique_id="T1547",
        )

    return {
        "action_id": "install_backdoor",
        "name": "Install Backdoor",
        "description": "Plant a boot/logon autostart entry for persistent access",
        "kill_chain_stage": "persistence",
        "mitre_technique": "T1547",
        "mitre_name": "Boot or Logon Autostart Execution",
        "observability": 0.4,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_create_scheduled_task() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.admin_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.5
        detected = _is_detected(observability)

        if target_ip not in agent_state.admin_hosts:
            return ActionOutcome(
                action_id="create_scheduled_task",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Requires admin access on {target_ip}",
                detected=False,
                kill_chain_stage="persistence",
                mitre_technique_id="T1053",
            )

        try:
            host = env.get_host(target_ip)
            host.persistence_installed = True
        except Exception:
            pass

        agent_state.persistence_hosts.add(target_ip)
        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="create_scheduled_task",
            result=result,
            target_ip=target_ip,
            detail=f"Scheduled task created for persistence on {target_ip}",
            detected=detected,
            kill_chain_stage="persistence",
            mitre_technique_id="T1053",
        )

    return {
        "action_id": "create_scheduled_task",
        "name": "Create Scheduled Task",
        "description": "Schedule a task or cron job to maintain persistent execution",
        "kill_chain_stage": "persistence",
        "mitre_technique": "T1053",
        "mitre_name": "Scheduled Task/Job",
        "observability": 0.5,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_exploit_local_vuln() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        for ip in agent_state.compromised_hosts:
            try:
                host = env.get_host(ip)
                for svc in host.services:
                    if svc.cves:
                        return True
            except Exception:
                continue
        return False

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.4
        detected = _is_detected(observability)

        if target_ip not in agent_state.compromised_hosts:
            return ActionOutcome(
                action_id="exploit_local_vuln",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No foothold on {target_ip}; local exploit requires prior access",
                detected=False,
                kill_chain_stage="privilege_escalation",
                mitre_technique_id="T1068",
            )

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="exploit_local_vuln",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="privilege_escalation",
                mitre_technique_id="T1068",
            )

        local_cve = next(
            (cve for svc in host.services for cve in svc.cves),
            None,
        )
        if local_cve is None:
            return ActionOutcome(
                action_id="exploit_local_vuln",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No exploitable local CVEs found on {target_ip}",
                detected=detected,
                kill_chain_stage="privilege_escalation",
                mitre_technique_id="T1068",
            )

        # Probabilistic: EDR/patching reduce local exploit success
        prob = _defense_success_probability(host, "exploit_local_vuln")
        success = random.random() < prob

        if not success:
            return ActionOutcome(
                action_id="exploit_local_vuln",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Local exploit {local_cve} failed on {target_ip} — defenses intervened (p={prob:.0%})",
                detected=detected,
                kill_chain_stage="privilege_escalation",
                mitre_technique_id="T1068",
            )

        host.admin_access = True
        agent_state.admin_hosts.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="exploit_local_vuln",
            result=result,
            target_ip=target_ip,
            detail=f"Local privilege escalation via {local_cve} on {target_ip} (p={prob:.0%})",
            detected=detected,
            kill_chain_stage="privilege_escalation",
            mitre_technique_id="T1068",
            data={"cve_used": local_cve, "success_probability": round(prob, 4)},
        )

    return {
        "action_id": "exploit_local_vuln",
        "name": "Exploit Local Vulnerability",
        "description": "Use a local CVE to escalate from user to admin/root privileges",
        "kill_chain_stage": "privilege_escalation",
        "mitre_technique": "T1068",
        "mitre_name": "Exploitation for Privilege Escalation",
        "observability": 0.4,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_credential_dump() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.admin_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.7
        detected = _is_detected(observability)

        if target_ip not in agent_state.admin_hosts:
            return ActionOutcome(
                action_id="credential_dump",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Admin access required on {target_ip} for credential dump",
                detected=False,
                kill_chain_stage="privilege_escalation",
                mitre_technique_id="T1003",
            )

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="credential_dump",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="privilege_escalation",
                mitre_technique_id="T1003",
            )

        # Credential Guard or EDR (if not bypassed) blocks dump
        edr_active = host.defenses.edr_present and target_ip not in agent_state.edr_bypassed
        if edr_active:
            return ActionOutcome(
                action_id="credential_dump",
                result=ActionResult.BLOCKED,
                target_ip=target_ip,
                detail=f"EDR/Credential Guard on {target_ip} blocked credential dump",
                detected=True,
                kill_chain_stage="privilege_escalation",
                mitre_technique_id="T1003",
            )

        host.credentials_dumped = True
        agent_state.credentials_dumped.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="credential_dump",
            result=result,
            target_ip=target_ip,
            detail=f"LSASS/SAM credentials dumped from {target_ip}",
            detected=detected,
            kill_chain_stage="privilege_escalation",
            mitre_technique_id="T1003",
            data={"credentials_from": target_ip},
        )

    return {
        "action_id": "credential_dump",
        "name": "Credential Dump",
        "description": "Extract credential material from LSASS, SAM, or /etc/shadow",
        "kill_chain_stage": "privilege_escalation",
        "mitre_technique": "T1003",
        "mitre_name": "OS Credential Dumping",
        "observability": 0.7,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_bypass_edr() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        for ip in agent_state.compromised_hosts:
            try:
                host = env.get_host(ip)
                if host.defenses.edr_present and ip not in agent_state.edr_bypassed:
                    return True
            except Exception:
                continue
        return False

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.3
        detected = _is_detected(observability)

        if target_ip not in agent_state.compromised_hosts:
            return ActionOutcome(
                action_id="bypass_edr",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No foothold on {target_ip}",
                detected=False,
                kill_chain_stage="persistence",
                mitre_technique_id="T1562",
            )

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="bypass_edr",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="persistence",
                mitre_technique_id="T1562",
            )

        if not host.defenses.edr_present:
            return ActionOutcome(
                action_id="bypass_edr",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No EDR product present on {target_ip}",
                detected=False,
                kill_chain_stage="persistence",
                mitre_technique_id="T1562",
            )

        # Probabilistic bypass — 50% base success rate
        bypass_success = random.random() < 0.5

        if not bypass_success:
            return ActionOutcome(
                action_id="bypass_edr",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"EDR bypass attempt failed on {target_ip}",
                detected=detected,
                kill_chain_stage="persistence",
                mitre_technique_id="T1562",
            )

        agent_state.edr_bypassed.add(target_ip)
        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="bypass_edr",
            result=result,
            target_ip=target_ip,
            detail=f"EDR tampered and disabled on {target_ip}",
            detected=detected,
            kill_chain_stage="persistence",
            mitre_technique_id="T1562",
        )

    return {
        "action_id": "bypass_edr",
        "name": "Bypass EDR",
        "description": "Tamper with or disable the EDR agent on the compromised host",
        "kill_chain_stage": "persistence",
        "mitre_technique": "T1562",
        "mitre_name": "Impair Defenses",
        "observability": 0.3,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_clear_logs() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.admin_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.2
        detected = _is_detected(observability)

        if target_ip not in agent_state.admin_hosts:
            return ActionOutcome(
                action_id="clear_logs",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Admin access required to clear logs on {target_ip}",
                detected=False,
                kill_chain_stage="persistence",
                mitre_technique_id="T1070",
            )

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="clear_logs",
            result=result,
            target_ip=target_ip,
            detail=f"Security event logs cleared on {target_ip}",
            detected=detected,
            kill_chain_stage="persistence",
            mitre_technique_id="T1070",
        )

    return {
        "action_id": "clear_logs",
        "name": "Clear Logs",
        "description": "Delete or tamper with event logs to remove forensic evidence",
        "kill_chain_stage": "persistence",
        "mitre_technique": "T1070",
        "mitre_name": "Indicator Removal",
        "observability": 0.2,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_pivot_to_host() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        if not agent_state.compromised_hosts:
            return False
        # Check at least one reachable new host exists from any compromised host
        for src_ip in agent_state.compromised_hosts:
            try:
                reachable = env.get_reachable_hosts(src_ip)
                for h in reachable:
                    if h.ip not in agent_state.compromised_hosts:
                        return True
            except Exception:
                continue
        return False

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.5
        detected = _is_detected(observability)

        # Verify the source of pivot — any compromised host must be able to reach target
        source_ip = next(
            (
                src
                for src in agent_state.compromised_hosts
                if any(h.ip == target_ip for h in env.get_reachable_hosts(src))
            ),
            None,
        )

        if source_ip is None:
            return ActionOutcome(
                action_id="pivot_to_host",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"{target_ip} is not reachable from any compromised host",
                detected=False,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1021",
            )

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="pivot_to_host",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1021",
            )

        # Probabilistic: firewalls, EDR, monitoring reduce pivot success
        prob = _defense_success_probability(host, "pivot_to_host")
        success = random.random() < prob

        if not success:
            return ActionOutcome(
                action_id="pivot_to_host",
                result=ActionResult.BLOCKED,
                target_ip=target_ip,
                detail=f"Lateral movement to {target_ip} blocked by defenses (p={prob:.0%})",
                detected=detected,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1021",
            )

        host.compromised = True
        agent_state.compromised_hosts.add(target_ip)
        agent_state.discovered_hosts.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="pivot_to_host",
            result=result,
            target_ip=target_ip,
            detail=f"Pivoted from {source_ip} to {target_ip} via lateral movement (p={prob:.0%})",
            detected=detected,
            kill_chain_stage="lateral_movement",
            mitre_technique_id="T1021",
            data={"pivot_source": source_ip, "success_probability": round(prob, 4)},
        )

    return {
        "action_id": "pivot_to_host",
        "name": "Pivot to Host",
        "description": "Laterally move to a new host via remote service (RDP/SSH/SMB)",
        "kill_chain_stage": "lateral_movement",
        "mitre_technique": "T1021",
        "mitre_name": "Remote Services",
        "observability": 0.5,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_pass_the_hash() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        if not agent_state.credentials_dumped:
            return False
        # Need at least one reachable host not yet compromised
        for src_ip in agent_state.compromised_hosts:
            try:
                reachable = env.get_reachable_hosts(src_ip)
                for h in reachable:
                    if h.ip not in agent_state.compromised_hosts:
                        return True
            except Exception:
                continue
        return False

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.6
        detected = _is_detected(observability)

        if not agent_state.credentials_dumped:
            return ActionOutcome(
                action_id="pass_the_hash",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="No credential hashes available; run credential_dump first",
                detected=False,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1550",
            )

        # Confirm target is reachable from a compromised host
        source_ip = next(
            (
                src
                for src in agent_state.compromised_hosts
                if any(h.ip == target_ip for h in env.get_reachable_hosts(src))
            ),
            None,
        )

        if source_ip is None:
            return ActionOutcome(
                action_id="pass_the_hash",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"{target_ip} is not reachable from any compromised host",
                detected=False,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1550",
            )

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="pass_the_hash",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1550",
            )

        # Probabilistic: MFA heavily reduces PtH, EDR/firewall also help
        prob = _defense_success_probability(host, "pass_the_hash")
        success = random.random() < prob

        if not success:
            return ActionOutcome(
                action_id="pass_the_hash",
                result=ActionResult.BLOCKED,
                target_ip=target_ip,
                detail=f"Pass-the-Hash blocked on {target_ip} (p={prob:.0%})",
                detected=detected,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1550",
            )

        host.compromised = True
        host.admin_access = True
        agent_state.compromised_hosts.add(target_ip)
        agent_state.admin_hosts.add(target_ip)
        agent_state.discovered_hosts.add(target_ip)

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="pass_the_hash",
            result=result,
            target_ip=target_ip,
            detail=f"Pass-the-Hash succeeded against {target_ip} from {source_ip} (p={prob:.0%})",
            detected=detected,
            kill_chain_stage="lateral_movement",
            mitre_technique_id="T1550",
            data={"credential_source": list(agent_state.credentials_dumped)[0],
                  "success_probability": round(prob, 4)},
        )

    return {
        "action_id": "pass_the_hash",
        "name": "Pass the Hash",
        "description": "Authenticate to remote host using captured NTLM credential hashes",
        "kill_chain_stage": "lateral_movement",
        "mitre_technique": "T1550",
        "mitre_name": "Use Alternate Authentication Material",
        "observability": 0.6,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_exfil_data() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        for ip in agent_state.compromised_hosts:
            try:
                host = env.get_host(ip)
                if host.criticality not in ("low", "minimal"):
                    return True
            except Exception:
                continue
        return False

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.7
        detected = _is_detected(observability)

        if target_ip not in agent_state.compromised_hosts:
            return ActionOutcome(
                action_id="exfil_data",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No foothold on {target_ip}",
                detected=False,
                kill_chain_stage="exfiltration",
                mitre_technique_id="T1041",
            )

        try:
            host = env.get_host(target_ip)
        except Exception:
            return ActionOutcome(
                action_id="exfil_data",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Target host not found",
                detected=False,
                kill_chain_stage="exfiltration",
                mitre_technique_id="T1041",
            )

        if host.criticality in ("low", "minimal"):
            return ActionOutcome(
                action_id="exfil_data",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Host {target_ip} has insufficient data value (criticality: {host.criticality})",
                detected=detected,
                kill_chain_stage="exfiltration",
                mitre_technique_id="T1041",
            )

        agent_state.exfiltrated = True
        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="exfil_data",
            result=result,
            target_ip=target_ip,
            detail=f"Data exfiltrated over C2 channel from {target_ip} (criticality: {host.criticality})",
            detected=detected,
            kill_chain_stage="exfiltration",
            mitre_technique_id="T1041",
            data={"host_criticality": host.criticality},
        )

    return {
        "action_id": "exfil_data",
        "name": "Exfiltrate Data",
        "description": "Transmit sensitive data to attacker-controlled infrastructure",
        "kill_chain_stage": "exfiltration",
        "mitre_technique": "T1041",
        "mitre_name": "Exfiltration Over C2 Channel",
        "observability": 0.7,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_dns_tunnel_c2() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return len(agent_state.compromised_hosts) > 0

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.3
        detected = _is_detected(observability)

        if target_ip not in agent_state.compromised_hosts:
            return ActionOutcome(
                action_id="dns_tunnel_c2",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"No foothold on {target_ip}",
                detected=False,
                kill_chain_stage="command_and_control",
                mitre_technique_id="T1071",
            )

        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="dns_tunnel_c2",
            result=result,
            target_ip=target_ip,
            detail=f"DNS tunneling C2 channel established from {target_ip}",
            detected=detected,
            kill_chain_stage="command_and_control",
            mitre_technique_id="T1071",
            data={"channel": "dns_tunnel"},
        )

    return {
        "action_id": "dns_tunnel_c2",
        "name": "DNS Tunnel C2",
        "description": "Establish covert command-and-control channel via DNS tunneling",
        "kill_chain_stage": "command_and_control",
        "mitre_technique": "T1071",
        "mitre_name": "Application Layer Protocol",
        "observability": 0.3,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_encrypt_files() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        # Requires both admin access AND persistence on at least one host
        return bool(agent_state.admin_hosts & agent_state.persistence_hosts)

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        observability = 0.9
        detected = _is_detected(observability)

        if target_ip not in agent_state.admin_hosts:
            return ActionOutcome(
                action_id="encrypt_files",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Admin access required on {target_ip} for ransomware deployment",
                detected=False,
                kill_chain_stage="impact",
                mitre_technique_id="T1486",
            )

        if target_ip not in agent_state.persistence_hosts:
            return ActionOutcome(
                action_id="encrypt_files",
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail=f"Persistence required on {target_ip} before encrypting files",
                detected=False,
                kill_chain_stage="impact",
                mitre_technique_id="T1486",
            )

        # Ransomware encryption almost always triggers detection
        result = ActionResult.DETECTED if detected else ActionResult.SUCCESS
        return ActionOutcome(
            action_id="encrypt_files",
            result=result,
            target_ip=target_ip,
            detail=f"Files encrypted with ransomware on {target_ip}; ransom note dropped",
            detected=detected,
            kill_chain_stage="impact",
            mitre_technique_id="T1486",
        )

    return {
        "action_id": "encrypt_files",
        "name": "Encrypt Files",
        "description": "Deploy ransomware payload to encrypt files and demand ransom",
        "kill_chain_stage": "impact",
        "mitre_technique": "T1486",
        "mitre_name": "Data Encrypted for Impact",
        "observability": 0.9,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


def _build_do_nothing() -> dict:
    def check_prerequisites(env, agent_state: AgentState) -> bool:
        return True

    def evaluate(env, target_ip: str, agent_state: AgentState) -> ActionOutcome:
        return ActionOutcome(
            action_id="do_nothing",
            result=ActionResult.SUCCESS,
            target_ip=target_ip,
            detail="Agent chose to wait and observe",
            detected=False,
            kill_chain_stage="reconnaissance",
            mitre_technique_id="-",
        )

    return {
        "action_id": "do_nothing",
        "name": "Do Nothing",
        "description": "Wait and observe; useful when all options carry too much risk",
        "kill_chain_stage": "reconnaissance",
        "mitre_technique": "-",
        "mitre_name": "N/A",
        "observability": 0.0,
        "check_prerequisites": check_prerequisites,
        "evaluate": evaluate,
    }


# ---------------------------------------------------------------------------
# Registry construction
# ---------------------------------------------------------------------------

def get_action_registry() -> Dict[str, dict]:
    """Return all 20 actions as a dict keyed by action_id."""
    actions = [
        _build_port_scan(),
        _build_osint_enum(),
        _build_exploit_public_service(),
        _build_brute_force_creds(),
        _build_phishing(),
        _build_exploit_weak_password(),
        _build_execute_command(),
        _build_deploy_payload(),
        _build_install_backdoor(),
        _build_create_scheduled_task(),
        _build_exploit_local_vuln(),
        _build_credential_dump(),
        _build_bypass_edr(),
        _build_clear_logs(),
        _build_pivot_to_host(),
        _build_pass_the_hash(),
        _build_exfil_data(),
        _build_dns_tunnel_c2(),
        _build_encrypt_files(),
        _build_do_nothing(),
    ]
    return {a["action_id"]: a for a in actions}


# Module-level singleton — built once, reused everywhere
_ACTION_REGISTRY: Dict[str, dict] = {}


def _get_registry() -> Dict[str, dict]:
    global _ACTION_REGISTRY
    if not _ACTION_REGISTRY:
        _ACTION_REGISTRY = get_action_registry()
    return _ACTION_REGISTRY


def get_available_actions(env, agent_state: AgentState) -> List[str]:
    """Return action_ids whose prerequisites are met given current state."""
    registry = _get_registry()
    available = []
    for action_id, action in registry.items():
        try:
            if action["check_prerequisites"](env, agent_state):
                available.append(action_id)
        except Exception as exc:
            logger.debug(
                "prerequisite_check_error",
                extra={"action_id": action_id, "error": str(exc)},
            )
    return available


def format_actions_for_prompt(available_action_ids: List[str]) -> str:
    """Format available actions as text for LLM prompt."""
    registry = _get_registry()
    lines = ["Available actions:"]
    for action_id in available_action_ids:
        action = registry.get(action_id)
        if action is None:
            continue
        lines.append(
            f"  - {action_id}: [{action['mitre_technique']}] {action['name']} "
            f"(stage={action['kill_chain_stage']}) — {action['description']}"
        )
    return "\n".join(lines)


def execute_action(
    action_id: str,
    env,
    target_ip: str,
    agent_state: AgentState,
) -> ActionOutcome:
    """Execute an action and return the outcome."""
    registry = _get_registry()
    action = registry.get(action_id)

    # --- Defender state checks (Phase 2: Red vs Blue) ---
    # Blocked IPs: defenders can block IPs at firewall
    if hasattr(env, 'blocked_ips') and target_ip in env.blocked_ips:
        return ActionOutcome(
            action_id=action_id,
            result=ActionResult.BLOCKED,
            target_ip=target_ip,
            detail=f"IP {target_ip} has been blocked by defenders",
            detected=True,
            kill_chain_stage=action.get("kill_chain_stage", "reconnaissance") if action else "reconnaissance",
            mitre_technique_id=action.get("mitre_technique", "N/A") if action else "N/A",
        )

    # Isolated hosts: defenders can isolate hosts from network
    if hasattr(env, 'isolated_hosts') and target_ip in env.isolated_hosts:
        return ActionOutcome(
            action_id=action_id,
            result=ActionResult.BLOCKED,
            target_ip=target_ip,
            detail=f"Host {target_ip} has been isolated from network by defenders",
            detected=True,
            kill_chain_stage=action.get("kill_chain_stage", "reconnaissance") if action else "reconnaissance",
            mitre_technique_id=action.get("mitre_technique", "N/A") if action else "N/A",
        )

    # Revoked credentials: pass_the_hash and credential_dump degraded
    if hasattr(env, 'credentials_revoked') and env.credentials_revoked:
        if action_id == "pass_the_hash":
            return ActionOutcome(
                action_id=action_id,
                result=ActionResult.BLOCKED,
                target_ip=target_ip,
                detail="Pass-the-hash failed — credentials have been revoked by defenders",
                detected=True,
                kill_chain_stage="lateral_movement",
                mitre_technique_id="T1550.002",
            )
        if action_id == "credential_dump":
            return ActionOutcome(
                action_id=action_id,
                result=ActionResult.FAILURE,
                target_ip=target_ip,
                detail="Credential dump returned revoked credentials — unusable",
                detected=True,
                kill_chain_stage="credential_access",
                mitre_technique_id="T1003",
            )

    if action is None:
        logger.error(
            "unknown_action",
            extra={"action_id": action_id, "target_ip": target_ip},
        )
        return ActionOutcome(
            action_id=action_id,
            result=ActionResult.FAILURE,
            target_ip=target_ip,
            detail=f"Unknown action '{action_id}'",
            detected=False,
            kill_chain_stage="reconnaissance",
            mitre_technique_id="unknown",
        )

    try:
        outcome = action["evaluate"](env, target_ip, agent_state)
        logger.info(
            "action_executed",
            extra={
                "action_id": action_id,
                "target_ip": target_ip,
                "result": outcome.result.value,
                "detected": outcome.detected,
                "kill_chain_stage": outcome.kill_chain_stage,
            },
        )
        return outcome
    except Exception as exc:
        logger.error(
            "action_execution_error",
            extra={"action_id": action_id, "target_ip": target_ip, "error": str(exc)},
        )
        return ActionOutcome(
            action_id=action_id,
            result=ActionResult.FAILURE,
            target_ip=target_ip,
            detail=f"Action raised exception: {exc}",
            detected=False,
            kill_chain_stage=action.get("kill_chain_stage", "reconnaissance"),
            mitre_technique_id=action.get("mitre_technique", "unknown"),
        )
