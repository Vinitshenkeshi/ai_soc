# Unauthorized Access Response

## Scope

This runbook covers detection and response to unauthorized access to systems, applications, or data. This includes both external attackers who gained initial access and insiders accessing resources beyond their authorization.

**Applies to:** All systems, applications, and data repositories.
**MITRE ATT&CK:** T1078 - Valid Accounts, T1133 - External Remote Services, T1190 - Exploit Public-Facing Application

## Detection

Indicators of unauthorized access:

- Authentication from unusual geographic location or IP address
- Login outside of normal business hours for the account
- Access to resources the user has never accessed before
- Wazuh alert: Multiple failed logins followed by success (T1110)
- Impossible travel: Login from two geographically distant locations in short timeframe
- Access to sensitive systems/data outside user's role
- Alert from UEBA (User Entity Behavior Analytics) for anomalous behavior
- VPN connection from new device or location
- Service account used interactively (should only be used by services)
- Alert on admin account login during non-business hours

## Investigation Steps

1. **Confirm the unauthorized access:**
   ```
   # Gather login events for the suspected account
   # Check: source IP, user agent, time, MFA status, location

   # Active Directory
   Get-ADUser <username> -Properties LastLogonDate,LastLogonTimestamp,BadPwdCount,BadPasswordTime

   # Linux
   last <username> | head -20
   grep <username> /var/log/auth.log | grep "Accepted" | tail -20
   ```

2. **Determine if credentials were compromised:**
   - Was there a failed password reset recently?
   - Is the user's password in a breach database? (check HaveIBeenPwned API)
   - Was the account targeted in a phishing campaign?
   - Any prior suspicious email activity?

3. **Map the session activity:**
   ```
   # What did the attacker do during the unauthorized session?
   # Review: commands executed, files accessed, data downloaded, network connections

   # Windows - process creation during session
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4688} | Where-Object {$_.TimeCreated -gt <session_start>}

   # Linux - bash history, auth log, syslog during session window
   grep -A5 "session opened for user <username>" /var/log/auth.log
   ```

4. **Check for account modifications:**
   - New email forwarding rules
   - New OAuth applications authorized
   - Changes to MFA methods
   - Password changes
   - Added SSH keys

5. **Check for lateral movement:**
   - Connections from the compromised account to other internal systems
   - Kerberoasting or AS-REP Roasting attempts (AD)
   - Pass-the-hash or Pass-the-ticket indicators

6. **Interview the legitimate user:**
   - Verify they did not make these accesses
   - Check if they shared credentials or have been phished
   - Confirm their current physical location vs. login location

## Containment

**Immediate (within 30 minutes):**

1. **Terminate active unauthorized session(s):**
   ```powershell
   # Office 365
   Revoke-AzureADUserAllRefreshToken -ObjectId <user_object_id>

   # Active Directory
   Invoke-ADAccountLockout -Identity <username>
   ```

2. **Disable the compromised account:**
   ```bash
   # Active Directory
   Disable-ADAccount -Identity <username>

   # Linux
   usermod -L <username>
   ```

3. **Revoke all active sessions and tokens:**
   - Invalidate all OAuth tokens
   - Terminate VPN sessions
   - Log out all SSO sessions

4. **Block source IP at firewall if external:**
   ```bash
   iptables -A INPUT -s <ATTACKER_IP> -j DROP
   ```

5. **Preserve forensic evidence:**
   - Export authentication logs for the account
   - Capture network flow data for the session
   - Document timeline before any remediation

## Remediation

1. **Reset account credentials:**
   - Force password reset on next login
   - Do not allow user to choose similar password
   - Verify password complexity requirements are enforced

2. **Re-enroll MFA devices:**
   - Revoke existing MFA registrations
   - Re-enroll using a verified device
   - Consider phishing-resistant MFA (FIDO2)

3. **Audit and revert unauthorized changes:**
   - Remove email forwarding rules added during unauthorized session
   - Remove unauthorized OAuth app grants
   - Revert any configuration changes made

4. **Implement conditional access policies if not present:**
   - Require MFA for all logins
   - Block legacy authentication protocols
   - Require compliant device for sensitive access

5. **User education:**
   - Inform the user about the incident
   - Phishing awareness training
   - Explain importance of not sharing credentials

## Prevention

- Enforce Multi-Factor Authentication (MFA) for all user accounts
- Implement Zero Trust Network Access (ZTNA) principles
- Deploy Identity Threat Detection and Response (ITDR) solution
- Enable Conditional Access policies (Azure AD, Okta, etc.)
- Block legacy authentication protocols (basic auth, NTLM where possible)
- Implement UEBA to detect anomalous login patterns automatically
- Enable impossible travel detection and alert
- Regular access reviews; remove unnecessary permissions promptly
- Implement privileged access workstations for admin access
- Deploy Privileged Access Management (PAM) for privileged accounts
- Enable detailed audit logging for all authentication events
- Monitor for credential exposure in breach databases (HaveIBeenPwned API)
- Implement session recording for privileged access sessions
