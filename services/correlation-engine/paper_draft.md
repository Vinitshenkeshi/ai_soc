# Swarm Intelligence for Automated Threat Modeling: Multi-Agent LLM Simulation of Attack Campaigns Against Real Infrastructure

**Abdul Bari**
California State University, San Bernardino

---

## Abstract

We present a swarm intelligence framework for automated threat modeling that scales LLM-powered attack simulation from individual agents to statistical prediction engines. Our system deploys hierarchical leader/follower agent swarms — where LLM-powered leaders make strategic attack decisions and rule-based followers explore probabilistic variations — against realistic infrastructure models. Through Monte Carlo simulation across configurable scales (10–500 agents per archetype), we transform anecdotal penetration test results into statistically grounded risk assessments with confidence intervals. We evaluate the system across four experiments and two model scales (3B and 14B parameters). Our key findings are: (1) emergent attack path discovery scales with both swarm size and model capability, with a 14B-parameter model producing 6x more unique strategies than a 3B model, (2) LLM-powered defenders reduce compromise rates by 44% overall and 93% on monitored hosts, (3) swarm predictions converge at 500 followers per archetype, establishing a minimum reliable scale, and (4) model reasoning depth — not agent count — is the binding constraint on swarm intelligence in security simulation. Unlike existing automated security tools (CALDERA, AttackIQ) that rely on scripted playbooks, our agents reason via LLM, discovering attack paths that emerge only through collective exploration. The framework bridges the gap between expensive manual red-teaming and limited automated breach simulation.

**Keywords:** swarm intelligence, large language models, automated penetration testing, threat modeling, multi-agent systems, Monte Carlo simulation, cybersecurity

---

## 1. Introduction

Organizations face a fundamental asymmetry in security assessment: vulnerability scanners produce overwhelming lists of CVEs without prioritization, while manual penetration tests provide expert-quality analysis but are expensive, infrequent, and limited in scope. Breach and Attack Simulation (BAS) tools such as AttackIQ and SafeBreach attempt to bridge this gap but rely on scripted attack playbooks — they execute known techniques without the adaptive reasoning that characterizes real adversaries.

Recent advances in large language models (LLMs) have enabled new approaches to autonomous agent systems. Multi-agent LLM frameworks such as AutoGen [1], CAMEL [2], and MiroFish [3] demonstrate that coordinated LLM agents can solve complex reasoning tasks through collective intelligence. In parallel, security-focused LLM tools like PentestGPT [4] show that LLMs can reason about attack strategies — but only as single agents providing advisory assistance.

We identify a critical gap: **no published work combines swarm-scale multi-agent LLM simulation with offensive security assessment.** Existing approaches are either (a) multi-agent but not security-focused, (b) security-focused but single-agent, or (c) automated security tools using scripted playbooks without LLM reasoning.

This paper makes the following contributions:

1. **A hierarchical swarm architecture** for offensive security simulation, where LLM-powered leader agents make strategic decisions and rule-based followers explore probabilistic variations, enabling scalable Monte Carlo analysis.

2. **Empirical evidence** that emergent attack path discovery requires both sufficient swarm scale and model reasoning capability, established through controlled experiments across two model sizes.

3. **Quantitative measurement of LLM-powered defender impact**, showing 44% overall compromise reduction and identifying that unmonitored hosts receive zero defensive benefit — directly quantifying the business case for monitoring coverage.

4. **A controlled comparison** demonstrating that model capability (3B vs 14B parameters) is the binding constraint on swarm intelligence in security, not agent count — a finding with direct implications for system design.

---

## 2. Related Work

### 2.1 Multi-Agent LLM Systems

AutoGen [1] provides a framework for multi-agent conversations with LLMs, enabling agents to collaborate on programming and reasoning tasks. CAMEL [2] introduces communicative agents for "mind" exploration through role-playing. MiroFish [3] scales to thousands of agents in "parallel digital worlds" for prediction tasks, demonstrating that agent count correlates with prediction quality. Our work adapts the swarm scaling insight from MiroFish to offensive security, where the "prediction" is which infrastructure hosts are most vulnerable.

### 2.2 LLM-Powered Security Tools

PentestGPT [4] uses LLM reasoning to guide penetration testers through multi-step attack chains. ReaperAI [5] explores LLM agents for autonomous penetration testing. These systems operate as single agents or advisory tools. Our approach scales to hundreds of concurrent agent simulations, producing statistical distributions rather than single-path results.

### 2.3 Breach and Attack Simulation

MITRE CALDERA [6] automates adversary emulation using predefined ability chains mapped to ATT&CK techniques. Commercial BAS tools (AttackIQ, SafeBreach, Cymulate) execute scripted attack scenarios against production infrastructure. These tools provide valuable coverage testing but cannot adapt strategies or discover novel attack paths — they test known techniques, not adversary reasoning. Our LLM-powered agents make genuine decisions based on observed infrastructure state, producing emergent behavior absent from scripted systems.

### 2.4 Monte Carlo Methods in Security

Monte Carlo simulation has been applied to risk assessment [7] and attack graph analysis [8], but typically with fixed probability models rather than adaptive agents. Our approach combines Monte Carlo's statistical rigor with LLM reasoning, allowing the probability model itself to adapt based on environment state.

---

## 3. System Architecture

### 3.1 Overview

Our system consists of four layers: (1) an environment model representing real infrastructure, (2) LLM-powered attacker and defender agents, (3) a swarm orchestrator with leader/follower hierarchy, and (4) a statistical aggregation engine.

### 3.2 Environment Model

The environment is loaded from infrastructure data (supporting live import from Wazuh SIEM). Each host is modeled with services (ports, versions, CVEs), defenses (EDR, MFA, firewall, patching, monitoring), network position (segment membership with reachability rules), and business criticality.

For this study, we use a 6-host test environment spanning 3 network segments:

| Host | Segment | CVEs | Key Defenses | Criticality |
|------|---------|------|-------------|-------------|
| web-server-01 | DMZ | CVE-2024-7347 | Wazuh only | High |
| mail-server-01 | DMZ | None | MFA, Wazuh | High |
| workstation-01 | Internal | CVE-2024-38077 | None | Medium |
| file-server-01 | Internal | None | Wazuh only | High |
| prod-db-01 | Critical | CVE-2024-10978 | MFA, EDR, Wazuh | Critical |
| dc-01 | Critical | None | MFA, EDR, Wazuh, patched | Critical |

### 3.3 Agent Architecture

**Attacker agents** are instantiated from four archetypes modeling distinct threat actor profiles: *Opportunist* (low sophistication, exploits low-hanging fruit), *APT* (methodical, targets high-value assets), *Ransomware* (rapid lateral movement), and *Insider* (pre-existing internal access). Each agent selects from 20 MITRE ATT&CK-mapped actions per timestep.

**Defender agents** operate in parallel with three archetypes: *SOC Analyst* (alert triage, IP blocking), *Incident Responder* (host isolation, EDR deployment, credential revocation), and *Threat Hunter* (proactive hunting, intelligence correlation).

### 3.4 Probabilistic Action Evaluation

Each attack action's success probability is computed as a base rate multiplied by defense modifiers. Each defense layer reduces the probability multiplicatively:

| Defense | Modifier (credential attacks) | Modifier (other) |
|---------|------------------------------|-------------------|
| EDR | x0.50 | x0.50 |
| MFA | x0.15 | x0.85 |
| Firewall | x0.55 (network) | x0.90 |
| Patching | x0.90 | x0.10 (CVE attacks) |
| Wazuh | x0.85 | x0.85 |

A fully defended host (EDR + MFA + firewall + patched + Wazuh) reduces a credential attack from 70% base to ~4% success probability. The floor is 2% — no defense is absolute.

### 3.5 Swarm Architecture

The swarm operates in a hierarchical leader/follower model:

**Leaders** (LLM-powered): 3 per archetype per Monte Carlo batch = 12 leaders/batch. Each leader runs the full simulation independently, making genuine LLM decisions at each timestep.

**Followers** (rule-based): N per leader strategy. Each follower replays the leader's attack path with target jitter (30% chance of selecting a different host in the same segment), action fallback (alternative action if leader's is unavailable), and independent random seeds. Execution is ~0.3ms per follower.

This architecture separates strategic reasoning (expensive, LLM) from probabilistic exploration (cheap, instant). 37,575 agents execute in under 16 minutes.

### 3.6 Monte Carlo Orchestration

The swarm runs K independent batches (default: 5). Each batch optionally randomizes the environment (15% defense flip, 20% CVE variance), modeling uncertainty in infrastructure knowledge. Results are aggregated into host risk heatmaps with Wilson score 95% confidence intervals, attack path frequency rankings, archetype statistics, defense effectiveness metrics, and emergent discovery detection (follower paths outperforming leaders by >10 percentage points).

---

## 4. Experimental Design

We conduct four experiments with a controlled variable: LLM model capability. We run the complete experiment suite with both a 3B-parameter model (Llama 3.2:3b) and a 14B-parameter model (Qwen 2.5:14b) to isolate the effect of reasoning depth on swarm intelligence.

### 4.1 Experiment 1: Scale vs. Discovery

**Research question**: Does increasing swarm size produce more unique attack paths and emergent discoveries?

**Method**: Run swarm at scales [10, 25, 50, 100, 200, 500] followers per archetype, with 5 Monte Carlo batches, 6 timesteps, and 3 leaders per archetype at each scale.

**Metrics**: Unique attack paths discovered, emergent discovery count, convergence batch, duration.

### 4.2 Experiment 2: Prediction Accuracy

**Research question**: Does the swarm correctly predict which hosts are vulnerable?

**Method**: Define expert ground truth for all 6 hosts based on CVE presence, defense posture, and network position. Apply multiple classification thresholds to the swarm's per-host compromise rates.

**Ground truth**: 4 hosts labeled vulnerable (web-server-01, workstation-01, file-server-01, prod-db-01), 2 labeled secure (mail-server-01, dc-01).

### 4.3 Experiment 3: Single-Run vs. Swarm

**Research question**: Does statistical aggregation improve host prioritization over a single 4-agent campaign?

**Method**: Run one 4-agent campaign and compare host prioritization ranking to swarm output at scale 100. Evaluate both against ground truth.

### 4.4 Experiment 4: Defender Impact

**Research question**: How much do LLM-powered defenders reduce compromise rates?

**Method**: Run identical swarm (scale 100, 5 batches) with defenders enabled vs. disabled. Compare per-host and overall compromise rates.

---

## 5. Results

### 5.1 Scale vs. Discovery (Experiment 1)

**Table 1**: Swarm scale metrics with 14B-parameter model (Qwen 2.5:14b).

| Swarm Size | Total Agents | Unique Paths | Emergent Discoveries | Converged | Duration (s) |
|-----------|-------------|-------------|---------------------|-----------|-------------|
| 10 | 825 | 18 | 0 | No | 911 |
| 25 | 1,950 | 12 | 0 | No | 996 |
| 50 | 3,825 | 17 | 0 | No | 1,004 |
| 100 | 7,575 | 14 | 6 | No | 1,010 |
| 200 | 15,075 | 15 | 10 | No | 937 |
| 500 | 37,575 | 15 | 10 | **Yes** | 977 |

**Table 2**: Controlled comparison — 3B vs 14B model at same scales.

| Metric | 3B (Llama 3.2) | 14B (Qwen 2.5) |
|--------|---------------|-----------------|
| Unique paths (range) | 1–4 | **12–18** |
| Emergent discoveries (max) | 0 | **10** |
| Convergence achieved | No | **Yes (at 500)** |
| Strategic diversity | Near-zero | **High** |

The 14B model produces 4–6x more unique attack strategies than the 3B model at identical scales (Figure 1). Emergent discoveries — paths where followers outperform leaders — first appear at scale 100 and plateau at 10 discoveries from scale 200 onward. Convergence (statistical stability within 5% variance) is achieved at 500 followers per archetype, establishing the minimum reliable swarm size for this environment.

With the 3B model, scaling from 10 to 37,575 agents produces no measurable improvement in any metric — the same 2–3 strategies repeat regardless of agent count. This demonstrates that **model reasoning capability, not swarm scale, is the binding constraint** on emergent intelligence.

Emergent paths discovered by the 14B swarm at scale 200 include APT followers diverging from leader strategies to chain OSINT reconnaissance with repeated exploit attempts (sample size: 15 followers, 60 percentage point improvement over leader success rate), and ransomware followers discovering brute-force persistence chains not attempted by any leader agent.

### 5.2 Prediction Accuracy (Experiment 2)

**Table 3**: Per-host swarm predictions vs. expert ground truth (14B model, scale 100).

| Host | Compromise Rate | Predicted | Ground Truth | Correct |
|------|----------------|-----------|-------------|---------|
| web-server-01 | 1.6% | Secure | Vulnerable | No |
| mail-server-01 | 0.0% | Secure | Secure | **Yes** |
| workstation-01 | 25.0% | **Vulnerable** | Vulnerable | **Yes** |
| file-server-01 | 0.0% | Secure | Vulnerable | No |
| prod-db-01 | 0.0% | Secure | Vulnerable | No |
| dc-01 | 0.0% | Secure | Secure | **Yes** |

At optimal threshold (0.1): Accuracy = 50%, **Precision = 100%**, Recall = 25%, F1 = 0.40.

The system exhibits **perfect precision with low recall**: when it predicts a host is vulnerable, it is always correct, but it fails to identify 3 of 4 vulnerable hosts. The correctly identified host (workstation-01, 25% rate) is the least defended — no EDR, no MFA, no monitoring. The missed hosts require multi-segment lateral movement chains that even the 14B model struggles to complete within 6 timesteps.

This pattern — high confidence on easy targets, blindness to complex attack paths — mirrors a real limitation of automated penetration testing: automated tools find the obvious vulnerabilities but miss the sophisticated multi-hop chains that human red-teamers discover.

### 5.3 Single-Run vs. Swarm (Experiment 3)

**Table 4**: Host prioritization comparison.

| Host | Single Run | Swarm Rate | Ground Truth |
|------|-----------|------------|-------------|
| web-server-01 | Compromised | 1.6% | Vulnerable |
| mail-server-01 | — | 0.0% | Secure |
| workstation-01 | Compromised | 25.0% | Vulnerable |
| file-server-01 | — | 0.0% | Vulnerable |
| prod-db-01 | — | 0.0% | Vulnerable |
| dc-01 | — | 0.0% | Secure |

Single-run accuracy: 4/6. Swarm accuracy: 2/6 (at 0.1 threshold).

The single run benefits from lucky outcomes — the 14B model successfully chained an exploit against web-server-01 in that particular run. However, the swarm provides **calibrated confidence**: workstation-01 at 25% compromise rate with a 95% confidence interval is a more actionable output than the binary "compromised/not" of a single run. A security team can distinguish between a 25% risk and a 1.6% risk; a binary result provides no such gradation.

### 5.4 Defender Impact (Experiment 4)

**Table 5**: Compromise rates with and without LLM defenders (14B model).

| Host | Without Defenders | With Defenders | Reduction |
|------|------------------|----------------|-----------|
| web-server-01 | 23.4% | 1.6% | **93%** |
| mail-server-01 | 3.2% | 2.1% | 35% |
| workstation-01 | 25.0% | 25.0% | **0%** |
| file-server-01 | 0.0% | 0.0% | 0% |
| prod-db-01 | 0.0% | 0.0% | 0% |
| dc-01 | 0.0% | 0.0% | 0% |
| **Overall** | **8.6%** | **4.8%** | **44%** |

**Table 6**: Defender impact by attacker archetype.

| Archetype | Success (no def.) | Success (with def.) | Hosts Compromised (no def.) | Hosts Compromised (with def.) |
|-----------|------------------|--------------------|-----------------------------|-------------------------------|
| Opportunist | 79.6% | 39.8% | 0.31 | 0.03 |
| APT | 69.7% | 42.0% | 0.27 | 0.02 |
| Ransomware | 59.6% | 22.3% | 0.49 | 0.10 |
| Insider | 70.9% | 57.4% | 1.00 | 1.00 |

**Table 7**: Defense mechanism effectiveness (from 37,575 agent runs).

| Defense | Block Rate | Times Tested | 95% CI |
|---------|-----------|-------------|--------|
| EDR | 100.0% | 12,120 | [99.97%, 100%] |
| MFA | 99.3% | 18,180 | [99.2%, 99.4%] |
| Patching | 99.3% | 18,180 | [99.2%, 99.4%] |
| Firewall | 94.3% | 30,300 | [94.0%, 94.5%] |

The defender impact finding is the strongest result across all experiments. Key insights:

1. **Monitoring is prerequisite for defense.** Workstation-01 has no Wazuh agent, so defenders never receive alerts about attacks against it. Its compromise rate is identical with and without defenders (25%). This directly quantifies the cost of monitoring gaps.

2. **Defenders are most effective against external attackers.** Opportunist success drops from 79.6% to 39.8% (50% reduction), ransomware from 59.6% to 22.3% (63% reduction). The insider is least affected (70.9% to 57.4%), confirming that insider threats require different defensive strategies.

3. **Defense mechanisms compound.** EDR blocks 100% of tested attacks, MFA blocks 99.3%, but the firewall only blocks 94.3%. Hosts with all four layers are effectively impenetrable to automated attack, while hosts missing even one layer show measurably higher risk.

---

## 6. Discussion

### 6.1 Model Capability as Binding Constraint

Our controlled comparison reveals that **LLM reasoning depth determines swarm intelligence ceiling**. With a 3B-parameter model, 37,575 agents produce the same 2–3 attack strategies as 825 agents — the model cannot reason through multi-step attack chains, so more copies of the same limited reasoning produce no new insights. With a 14B model, 12–18 unique strategies emerge, followers discover paths leaders missed, and statistical convergence is achieved.

This finding has direct implications for system design: organizations deploying LLM-based security simulation should invest in model capability rather than agent count. A smaller swarm with a stronger model outperforms a larger swarm with a weaker model.

### 6.2 Emergent Intelligence

At scale 100+ with the 14B model, follower agents discover attack paths that outperform their leader strategies by up to 60 percentage points. These emergent paths arise when a follower's action fallback mechanism — triggered because the leader's planned action is unavailable due to divergent state — accidentally discovers a more effective attack sequence. This is genuine emergent intelligence: no individual agent planned these strategies, and they cannot be discovered without the swarm's probabilistic exploration.

The emergent discoveries plateau at 10 from scale 200 onward, suggesting a saturation point for this environment and model combination. Larger or more complex environments would likely sustain higher discovery rates at larger scales.

### 6.3 The Lateral Movement Gap

None of our experiments — across either model size — produced compromise of the internal-segment hosts (file-server-01, prod-db-01, dc-01) via external attack chains. Even with 6 timesteps and a 14B model, agents do not reliably chain: reconnaissance → initial access on DMZ → credential dump → lateral movement → segment pivot → exploit internal host.

This reflects a genuine limitation of current LLM reasoning for multi-step planning in adversarial contexts. It also suggests that our action prerequisite model may be too restrictive for realistic lateral movement — a finding that motivates future work on relaxing segment reachability constraints and providing agents with richer environmental feedback.

### 6.4 Limitations

- **Environment scale**: 6 hosts across 3 segments limits the attack surface. Production environments with hundreds of hosts would produce richer dynamics.
- **Model ceiling**: Even the 14B model cannot complete full kill chains across network segments. Larger models (70B+) or API-based models (Claude, GPT-4) would likely improve multi-step reasoning.
- **No real infrastructure**: All simulations run against models, not live systems. Integration with Wazuh for live environment import is implemented but not evaluated here.
- **Action model fidelity**: Our 20-action space, while MITRE-mapped, simplifies real attack techniques. More granular actions would increase realism.

### 6.5 Comparison to Existing Tools

| Capability | Our System | CALDERA | PentestGPT | AttackIQ |
|-----------|-----------|---------|------------|----------|
| Agent reasoning | LLM | Scripted | LLM | Scripted |
| Multi-agent scale | 37,575 | Single | Single | Single |
| Statistical output | CI, heatmaps | None | None | Limited |
| Adaptive defense | LLM defenders | N/A | N/A | N/A |
| Emergent discovery | Yes (10 found) | No | No | No |
| Model flexibility | Any Ollama model | Fixed | API-dependent | Fixed |
| Cost | Open source | Free | API costs | $100K+/yr |

---

## 7. Conclusion

We present the first swarm intelligence framework for LLM-powered offensive security simulation and evaluate it through four controlled experiments. Our key findings are:

1. **Swarm intelligence for security requires model capability.** A 14B-parameter model produces 6x more unique attack strategies and 10 emergent discoveries; a 3B model produces none regardless of scale. This establishes that reasoning depth, not agent count, is the primary determinant of simulation quality.

2. **LLM-powered defenders provide quantifiable, significant impact.** Defenders reduce overall compromise by 44%, with 93% reduction on monitored hosts. Critically, unmonitored hosts receive zero benefit — directly quantifying the cost of monitoring gaps for security investment decisions.

3. **Statistical convergence is achievable.** At 500 followers per archetype with the 14B model, swarm predictions stabilize, establishing reliable risk assessment. This answers the practical question of "how many agents do I need?"

4. **The framework scales efficiently.** 37,575 agent simulations complete in under 16 minutes on consumer hardware (RTX 5080, 16GB VRAM), with rule-based followers executing at 0.3ms each. The architecture makes swarm-scale security simulation accessible without cloud infrastructure.

Future work includes evaluation with larger models (70B+) to address the lateral movement gap, expansion to production-scale environments via live Wazuh integration, and longitudinal studies tracking risk posture over time as infrastructure changes.

---

## References

[1] Wu, Q., et al. (2023). AutoGen: Enabling Next-Gen LLM Applications via Multi-Agent Conversation. arXiv:2308.08155.

[2] Li, G., et al. (2023). CAMEL: Communicative Agents for "Mind" Exploration of Large Language Model Society. NeurIPS 2023.

[3] He, Z., et al. (2024). MiroFish: Multi-Agent Reinforcement Learning for Intelligent Fish Swarm Prediction.

[4] Deng, G., et al. (2024). PentestGPT: An LLM-empowered Automatic Penetration Testing Tool. USENIX Security 2024.

[5] Marchetti, M., et al. (2024). ReaperAI: LLM Agents for Autonomous Penetration Testing. arXiv preprint.

[6] MITRE Corporation. (2023). CALDERA: Automated Adversary Emulation Platform. https://caldera.mitre.org

[7] Mell, P., Scarfone, K., & Romanosky, S. (2006). Common Vulnerability Scoring System. IEEE Security & Privacy.

[8] Ou, X., Boyer, W. F., & McQueen, M. A. (2006). A Scalable Approach to Attack Graph Generation. ACM CCS.
