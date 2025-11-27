# Privilege Escalation Response

## Scope

This runbook covers detection and response to privilege escalation attempts, where an attacker or insider threat gains elevated access (root, SYSTEM, Domain Admin) beyond their authorized level.

**Applies to:** All systems (Linux, Windows, Active Directory).
**MITRE ATT&CK:** T1068 - Exploitation for Privilege Escalation, T1078 - Valid Accounts, T1548 - Abuse Elevation Control Mechanism

## Detection

Indicators of privilege escalation:

- Wazuh alert: User executed `sudo` command with unusual parameters
- Wazuh rule IDs: 5400, 5401, 5402, 5403 (sudo events)
- New member added to privileged group (Administrators, Domain Admins, sudoers, wheel)
- Process running as root/SYSTEM spawned by unprivileged parent process
- SUID/SGID binary abuse detected (Linux)
- UAC bypass technique detected (Windows)
- Token impersonation or privilege abuse (Windows - SeDebugPrivilege, SeImpersonatePrivilege)
- Unexpected use of `su`, `sudo`, `runas`, `psexec`
- Kernel exploit attempt detected by IDS/EDR

## Investigation Steps

1. **Identify the escalation event:**
   ```bash
   # Linux - review sudo history
   grep sudo /var/log/auth.log | tail -100
   grep sudo /var/log/secure | tail -100

   # Check for SUID abuse
   find / -perm -4000 -type f 2>/dev/null

   # Check who is in sudoers
   cat /etc/sudoers && ls -la /etc/sudoers.d/
   ```

2. **Windows - review security events:**
   ```powershell
   # Event ID 4672 - Special privileges assigned to new logon
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4672} | Select -First 50

   # Event ID 4728 - Member added to security-enabled global group
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4728} | Select -First 20

   # Event ID 4697 - A service was installed in the system
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4697} | Select -First 20
   ```

3. **Determine the escalation vector:**
   - CVE exploitation of local kernel/service?
   - Misconfigured SUID binary or sudo rule?
   - Stolen/compromised privileged credentials?
   - Scheduled task or service abuse?
   - DLL hijacking or PATH manipulation (Windows)?

4. **Review what privileged actions were taken:**
   ```bash
   # Linux - bash history for root
   cat /root/.bash_history
   journalctl -u <service> --since "2 hours ago"

   # Check for new accounts or sudo entries created
   grep useradd /var/log/auth.log
   grep visudo /var/log/auth.log
   ```

5. **Check for persistence established with elevated privileges:**
   - New scheduled tasks, cron jobs, services created as root/SYSTEM
   - SSH keys added to root's authorized_keys
   - New backdoor accounts created
   - Rootkit installation attempted (check for hidden processes/files)

6. **Assess blast radius:**
   - What data/systems are accessible at the escalated privilege level?
   - Were domain admin credentials obtained (AD)?
   - Was any data accessed, exfiltrated, or modified?

## Containment

**Immediate (within 30 minutes):**

1. **Lock the affected account:**
   ```bash
   # Linux
   passwd -l <username>
   usermod -L <username>

   # Windows
   Disable-ADAccount -Identity <username>
   ```

2. **Terminate suspicious privileged sessions:**
   ```bash
   # Linux - kill root sessions from suspicious TTY
   pkill -KILL -t pts/1

   # Windows - log off suspicious sessions
   logoff <session_id>
   ```

3. **Revert unauthorized group membership:**
   ```bash
   # Linux
   gpasswd -d <username> sudo
   gpasswd -d <username> wheel

   # Windows
   Remove-ADGroupMember -Identity "Domain Admins" -Members <username> -Confirm:$false
   ```

4. **Network isolation** if attacker is using elevated access for lateral movement

5. **Preserve forensic evidence** before remediation (memory dump, log export)

## Remediation

1. **Patch the escalation vulnerability:**
   - Apply kernel/OS patches if CVE exploitation occurred
   - Fix misconfigured sudo rules
   - Remove unnecessary SUID bits: `chmod u-s /path/to/binary`

2. **Audit and harden privileged access:**
   ```bash
   # Review and tighten sudoers
   visudo -c
   # Remove wildcard entries, require full paths, add NOEXEC where appropriate

   # Remove unnecessary SUID binaries
   find / -perm -4000 -type f 2>/dev/null | xargs ls -la
   ```

3. **Reset all potentially compromised credentials:**
   - All accounts that had privilege interaction with attacker
   - Service account passwords
   - KRBTGT password twice (if AD Golden Ticket suspected)

4. **Review and remove unauthorized persistence:**
   - Scheduled tasks/cron jobs created during attack window
   - New service accounts or backdoor accounts
   - SSH authorized_keys for privileged accounts

5. **Verify system integrity:**
   - Run rootkit detection: `chkrootkit` or `rkhunter`
   - Verify critical binary hashes against known-good

## Prevention

- Implement Privileged Access Workstations (PAW) for admin tasks
- Apply principle of least privilege; regularly audit group membership
- Enable just-in-time (JIT) privileged access (Azure PIM, CyberArk)
- Deploy Privileged Access Management (PAM) solution
- Enable detailed audit logging for all privileged operations
- Monitor for SUID binary changes with Wazuh FIM
- Keep OS and kernel patched (privilege escalation CVEs)
- Implement sudoers best practices: explicit commands, no wildcards
- Enable User Account Control (UAC) on Windows and keep at highest setting
- Deploy application control to prevent exploitation tools
- Regular vulnerability scanning focusing on local privilege escalation
- Enable Credential Guard on Windows to protect against token theft
