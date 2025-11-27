# DoS/DDoS Attack Response

## Scope

This runbook covers the detection and mitigation of Denial of Service (DoS) and Distributed Denial of Service (DDoS) attacks that impact the availability of systems and services.

**Applies to:** All internet-facing services, network infrastructure, and on-premises systems.
**MITRE ATT&CK:** T1498 - Network Denial of Service, T1499 - Endpoint Denial of Service

## Detection

Indicators of DoS/DDoS activity:

- Dramatic spike in inbound network traffic (bandwidth or packet rate)
- Service response times degrading or services becoming unavailable
- Wazuh alert: High rate of connection attempts from single or multiple IPs
- Firewall/IDS alert: SYN flood, UDP flood, ICMP flood, HTTP flood
- Unusual volume of specific request types (DNS amplification, NTP amplification)
- Server CPU/memory resource exhaustion with no legitimate traffic explanation
- Application layer attack: HTTP request flood targeting specific endpoints
- CDN or ISP notifications of volumetric attack
- Monitoring alert: Service health check failures, increased error rate

## Investigation Steps

1. **Characterize the attack:**
   ```bash
   # Measure inbound traffic volume
   iftop -i eth0  # Real-time bandwidth usage
   nethogs        # Per-process network usage

   # Check connection counts per source
   netstat -an | grep ESTABLISHED | awk '{print $5}' | cut -d: -f1 | sort | uniq -c | sort -rn | head -20

   # Packet capture for analysis
   tcpdump -i eth0 -nn -c 10000 -w /tmp/attack.pcap
   ```

2. **Classify the attack type:**
   - **Volumetric:** Bandwidth saturation (UDP flood, amplification)
   - **Protocol:** Exploits protocol weaknesses (SYN flood, fragmented packets)
   - **Application Layer:** Targets application resources (HTTP GET/POST flood)
   - **Amplification:** Uses open resolvers/services to amplify traffic (DNS, NTP, memcached)

3. **Identify attack source:**
   ```bash
   # Top source IPs
   tcpdump -r /tmp/attack.pcap -nn | awk '{print $3}' | cut -d. -f1-4 | sort | uniq -c | sort -rn | head -20

   # GeoIP lookup for source countries
   # Note: in true DDoS, sources will be widely distributed (botnet)
   ```

4. **Determine what's being targeted:**
   - Which IP/service is the destination?
   - What port/protocol is being flooded?
   - Is this targeted at infrastructure or application layer?

5. **Estimate impact:**
   - What services are affected?
   - What is the current availability/response time?
   - Estimated time to impact customers/operations if not mitigated?

## Containment

**Immediate mitigation:**

1. **Contact ISP/upstream provider for volumetric attacks:**
   - Request traffic scrubbing or null routing if attack exceeds your capacity
   - Provide attack details: source ASNs, destination IP, attack type

2. **Activate CDN/DDoS protection service** (Cloudflare, AWS Shield, Akamai):
   - Enable "Under Attack" mode
   - Enable rate limiting rules
   - Activate WAF rules for application layer attacks

3. **Network-level mitigations:**
   ```bash
   # SYN flood - enable SYN cookies
   sysctl -w net.ipv4.tcp_syncookies=1
   sysctl -w net.ipv4.tcp_max_syn_backlog=2048

   # Rate limit connections per IP
   iptables -A INPUT -p tcp --dport 80 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
   iptables -A INPUT -p tcp --dport 80 -j DROP

   # Block specific attack sources
   iptables -A INPUT -s <ATTACKER_IP_RANGE> -j DROP
   ```

4. **Application layer mitigations:**
   - Enable CAPTCHA challenges for suspicious traffic
   - Implement rate limiting per IP at load balancer
   - Cache static content to reduce backend load
   - Enable request queuing

5. **Horizontal scaling** if resources allow:
   - Spin up additional servers to distribute load
   - Increase auto-scaling thresholds

## Remediation

1. **Post-attack analysis:**
   - Analyze attack pcap to understand method and volume
   - Identify any infrastructure weaknesses exploited

2. **Strengthen rate limiting and access controls:**
   - Implement persistent rate limiting rules based on attack patterns
   - Configure connection limits per IP at firewall/load balancer

3. **Close amplification vectors:**
   - Disable open DNS resolver if exposed: restrict recursion to internal clients only
   - Disable NTP monlist: restrict to internal clients
   - Block memcached external access (port 11211)

4. **Implement BCP38 egress filtering** to prevent being used in amplification attacks

5. **Update DDoS runbook** with lessons learned from this attack

## Prevention

- Subscribe to DDoS protection service (Cloudflare, AWS Shield Advanced, Akamai)
- Deploy CDN for internet-facing services to absorb volumetric attacks
- Implement rate limiting at multiple layers (firewall, load balancer, application)
- Enable SYN cookies on all internet-facing Linux servers
- Close open DNS resolvers, NTP monlist, and other amplification vectors
- Implement anycast routing to distribute attack traffic across multiple POPs
- Establish ISP relationship and contact for emergency traffic scrubbing
- Conduct regular DDoS simulation tests (with ISP coordination)
- Develop and test scaling playbooks for rapid capacity expansion
- Monitor bandwidth utilization and set alerts for unusual spikes
- Implement BGP blackholing capability for extreme volumetric attacks
