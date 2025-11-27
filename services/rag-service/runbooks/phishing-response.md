# Phishing Incident Response

## Scope

This runbook covers the detection and response to phishing attacks targeting employees via email, SMS (smishing), or voice calls (vishing). Phishing is the primary initial access vector for most security incidents.

**Applies to:** All users and email systems.
**MITRE ATT&CK:** T1566 - Phishing, T1566.001 - Spearphishing Attachment, T1566.002 - Spearphishing Link

## Detection

Indicators of a phishing campaign:

- User reports suspicious email to security team
- Email gateway alert (spam score, malicious URL, attachment sandbox detonation)
- SIEM alert for mass email delivery or unusual sender patterns
- DNS query to known phishing domain from internal hosts
- Wazuh alert for document macro execution or script download
- User account accessing credential harvesting page (proxy logs)
- Multiple users reporting same suspicious email (coordinated campaign)
- Anti-phishing tool alert (Microsoft Defender, Proofpoint, Mimecast)

## Investigation Steps

1. **Collect the phishing email:**
   - Obtain original email with full headers (as .eml file)
   - Do not click links or open attachments in production environment
   - Use email admin console to preserve a copy before deleting

2. **Analyze email headers:**
   ```
   # Key headers to examine:
   - Return-Path vs From address (spoofing indicator)
   - Received: chain (trace sending servers)
   - X-Originating-IP (actual sender IP)
   - DKIM-Signature (verify or note absence)
   - SPF and DMARC results (check Authentication-Results header)
   ```

3. **Investigate URLs and attachments (in sandbox):**
   - Submit URLs to VirusTotal, URLScan.io, or internal sandbox
   - Detonate attachments in isolated sandbox (Cuckoo, Any.run)
   - Extract IOCs: domains, IPs, file hashes, C2 URLs

4. **Identify all affected recipients:**
   ```
   # Query email gateway/Exchange/Office365 for recipients
   # Office 365 (PowerShell):
   Search-UnifiedAuditLog -StartDate <date> -EndDate <date> -Operations "Send" -UserIds <sender>
   Get-MessageTrace -SenderAddress <phishing_sender> -StartDate <date>
   ```

5. **Determine if any users clicked/interacted:**
   - Review proxy/web gateway logs for connections to phishing URLs
   - Check email gateway for open/click tracking events
   - Query EDR for script execution or file downloads matching IOC hashes
   - Review Office365 sign-in logs for unusual authentication events

6. **Assess credential compromise:**
   - Check for Office365/Active Directory login anomalies post-click
   - Look for impossible travel (login from different geography)
   - Verify no MFA bypass or new MFA device enrollment

## Containment

**Immediate (within 1 hour):**

1. **Block the phishing infrastructure:**
   - Block sending domain in email gateway
   - Block phishing URLs in web proxy
   - Add IOC hashes to EDR blocklist
   - Update DNS sinkhole with phishing domains

2. **Purge phishing emails from all mailboxes:**
   ```powershell
   # Office 365 - Search and Purge
   New-ComplianceSearch -Name "PhishPurge" -ExchangeLocation All -ContentMatchQuery 'Subject:"<phishing_subject>"'
   Start-ComplianceSearch -Identity "PhishPurge"
   New-ComplianceSearchAction -SearchName "PhishPurge" -Purge -PurgeType SoftDelete
   ```

3. **Reset credentials for users who clicked:**
   - Force password reset for affected accounts
   - Revoke all active sessions (OAuth tokens)
   - Temporarily disable accounts pending investigation if compromise confirmed

4. **Enable enhanced monitoring on affected accounts:**
   - Enable detailed audit logging
   - Set up alerts for any forwarding rules, new OAuth app consents
   - Monitor for data exfiltration patterns

## Remediation

1. **Complete credential rotation** for all affected users

2. **Revoke and re-issue MFA tokens** if MFA was potentially bypassed

3. **Review and remove:**
   - Email forwarding rules added to affected mailboxes
   - New OAuth application grants
   - Inbox rules that may hide attacker activity
   - New mailbox delegates or permissions

4. **Patch or update vulnerable email clients** if exploitation occurred

5. **Update email security controls:**
   - Tune spam/phishing filters based on attack patterns
   - Add new rules to detect similar campaigns
   - Update DMARC policy to reject if currently set to none/quarantine

6. **Notify affected users** with specific guidance on what to watch for

## Prevention

- Implement DMARC, DKIM, and SPF for all owned domains (policy: reject)
- Deploy advanced email security gateway with URL rewriting and sandboxing
- Enable MFA for all user accounts, particularly email and VPN access
- Use phishing-resistant MFA (FIDO2/WebAuthn) where possible
- Conduct quarterly phishing simulation campaigns and training
- Configure email clients to display external sender warning banners
- Implement DNS filtering to block known phishing infrastructure
- Enable Microsoft Defender for Office 365 Safe Links and Safe Attachments
- Restrict macro execution; require signed macros from trusted publishers
- Implement browser isolation for high-risk user groups
- Create clear incident reporting process (phishing@company.com button)
