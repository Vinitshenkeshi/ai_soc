# SSH Brute Force Response

## Scope

This runbook covers detection, investigation, and remediation of SSH brute force attacks targeting Linux and Unix systems. A brute force attack involves repeated authentication attempts using automated tooling to guess credentials.

**Applies to:** All systems with SSH exposed (internal or external).
**MITRE ATT&CK:** T1110 - Brute Force, T1110.001 - Password Guessing, T1110.003 - Password Spraying

## Detection

Indicators of SSH brute force activity:

- More than 10 failed SSH authentication attempts from a single IP within 60 seconds
- Wazuh rule IDs: 5710, 5711, 5712, 5716, 5720
- `/var/log/auth.log` entries: `Failed password for`, `Invalid user`, `Connection closed by authenticating user`
- Rapid sequential login attempts across multiple usernames
- Authentication attempts for non-existent users (e.g., root, admin, test)
- Source IP from known threat intelligence blocklists

## Investigation Steps

1. **Identify the attacking IP(s):**
   ```
   grep "Failed password" /var/log/auth.log | awk '{print $(NF-3)}' | sort | uniq -c | sort -rn | head -20
   ```

2. **Check if any attempts succeeded:**
   ```
   grep "Accepted password\|Accepted publickey" /var/log/auth.log | grep -v "your-known-admin-ip"
   ```

3. **Determine targeted usernames:**
   ```
   grep "Failed password" /var/log/auth.log | awk '{print $9}' | sort | uniq -c | sort -rn
   ```

4. **Check for concurrent suspicious sessions:**
   ```
   who && last | head -20
   ```

5. **Verify attack timeframe and volume:**
   - Query Wazuh dashboard for rule ID 5710-5720 in the affected timeframe
   - Correlate with firewall logs for connection attempts

6. **Threat intelligence lookup:**
   - Query source IP against AbuseIPDB, VirusTotal, Shodan
   - Check if IP is a known Tor exit node or VPN provider

7. **Assess if compromise occurred:**
   - Review `/var/log/auth.log` for `session opened` entries from attacking IP
   - Check for new user accounts: `cat /etc/passwd | grep -v nologin`
   - Review recently modified files: `find / -newer /tmp/.last_check -type f 2>/dev/null`

## Containment

**Immediate (within 15 minutes):**

1. **Block the attacking IP at the firewall:**
   ```bash
   # iptables
   iptables -A INPUT -s <ATTACKING_IP> -j DROP

   # firewalld
   firewall-cmd --add-rich-rule="rule family='ipv4' source address='<ATTACKING_IP>' drop" --permanent
   firewall-cmd --reload
   ```

2. **Block via fail2ban (if available):**
   ```bash
   fail2ban-client set sshd banip <ATTACKING_IP>
   ```

3. **If compromise is suspected - isolate the system:**
   - Disconnect from network (notify team first)
   - Preserve memory dump if forensics required
   - Do NOT power off (destroys volatile evidence)

4. **Revoke any compromised credentials:**
   - Lock affected user accounts: `passwd -l <username>`
   - Invalidate SSH keys if shared: rotate authorized_keys

## Remediation

1. **Harden SSH configuration** (`/etc/ssh/sshd_config`):
   ```
   PermitRootLogin no
   PasswordAuthentication no
   MaxAuthTries 3
   LoginGraceTime 20
   AllowUsers specific_user_only
   ```

2. **Enable and configure fail2ban:**
   ```bash
   apt install fail2ban
   # /etc/fail2ban/jail.local
   [sshd]
   enabled = true
   maxretry = 5
   findtime = 300
   bantime = 3600
   ```

3. **Implement port knocking or move SSH to non-standard port**

4. **Enable SSH key-based authentication only:**
   ```bash
   ssh-keygen -t ed25519
   ssh-copy-id user@server
   # Then set PasswordAuthentication no
   ```

5. **Configure IP allowlisting for SSH access**

6. **Deploy/tune Wazuh active response for automatic IP blocking**

## Prevention

- Use SSH key-based authentication exclusively; disable password auth
- Implement Multi-Factor Authentication (MFA) for SSH
- Deploy a VPN or bastion host; do not expose SSH directly to internet
- Configure fail2ban with aggressive settings (maxretry=3, bantime=86400)
- Enable geoblocking for SSH if users are in known regions only
- Regularly audit authorized_keys files across all systems
- Use Wazuh active response to automatically block brute force sources
- Implement network segmentation to limit SSH access scope
- Monitor and alert on SSH from new/unusual source IPs
- Periodically scan for exposed SSH services using internal scanners
