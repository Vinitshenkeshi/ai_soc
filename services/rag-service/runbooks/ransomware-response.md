# Ransomware Response

## Scope

This runbook covers the response to ransomware infections, where malicious software encrypts files and demands payment for decryption. Ransomware incidents are critical and require immediate, decisive action.

**Applies to:** All endpoints, servers, and network shares.
**MITRE ATT&CK:** T1486 - Data Encrypted for Impact, T1490 - Inhibit System Recovery, T1489 - Service Stop

## Detection

Indicators of ransomware activity:

- Mass file extension changes to unusual extensions (.locked, .encrypted, .crypt, etc.)
- Wazuh FIM alerts: Massive file modification events in short timeframe
- Ransom note files appearing (README.txt, DECRYPT_INSTRUCTIONS.html, HOW_TO_RECOVER.txt)
- Volume shadow copies being deleted: `vssadmin delete shadows /all /quiet`
- Windows Event ID 7045: New service installed (ransomware payload)
- High disk I/O from unknown process
- Process attempting to terminate backup software, security tools, databases
- Network shares being enumerated and accessed from a single host
- EDR alert for ransomware behavior pattern

## Investigation Steps

1. **Identify the scope immediately:**
   ```bash
   # Find recently modified/created files with unusual extensions
   find /shared-data -newer /tmp/.baseline -name "*.locked" -o -name "*.encrypted" 2>/dev/null | wc -l

   # Windows - find ransom notes
   Get-ChildItem -Path C:\ -Recurse -Include "README.txt","HELP_*.txt","RECOVER*" -ErrorAction SilentlyContinue
   ```

2. **Identify the ransomware variant:**
   - Examine ransom note for variant name, contact email, Tor site
   - Submit sample file to ID Ransomware (https://id-ransomware.malwarehunterteam.com)
   - Check No More Ransom project (https://www.nomoreransom.org) for free decryptors
   - Submit sample to VirusTotal for family identification

3. **Determine patient zero:**
   ```
   # Find earliest encrypted files (this is near the start of encryption)
   # Check process creation events around that time
   # Look for: phishing email, RDP brute force, exploit kit, malicious macro
   ```

4. **Identify patient zero host:**
   - Compare file modification timestamps across systems to find earliest affected host
   - Check network logs for lateral movement from suspect host

5. **Assess backup status:**
   ```bash
   # Are backups intact? Check backup server
   # Were VSS/shadow copies deleted?
   vssadmin list shadows

   # Check backup integrity (do NOT restore yet - during containment phase)
   ```

6. **Determine if data was exfiltrated before encryption (double extortion):**
   - Review network logs for large outbound transfers 24-48 hours before encryption
   - Many ransomware groups exfiltrate first, then encrypt

## Containment

**IMMEDIATE - Within 15 minutes. Speed is critical:**

1. **ISOLATE ALL AFFECTED SYSTEMS NOW:**
   ```bash
   # Physically unplug network cables or disable network adapters
   # Do NOT shut down - may destroy encryption keys in memory

   # Windows - disable network adapter
   Get-NetAdapter | Disable-NetAdapter -Confirm:$false

   # Linux - bring down interface
   ip link set eth0 down
   ```

2. **Block lateral movement at network level:**
   - Block SMB (445) and RDP (3389) between internal subnets immediately
   - Block affected subnet from accessing backup servers
   - Activate emergency network segmentation if available

3. **Identify and disconnect ALL affected systems:**
   - File servers, workstations, domain controllers
   - Any system that accesses affected network shares
   - Use network flow analysis to map infected hosts rapidly

4. **Do NOT:**
   - Power off systems (may destroy decryption keys)
   - Pay ransom without executive and legal approval
   - Attempt recovery before containment is complete
   - Delete ransom notes or encrypted files (needed for investigation)

5. **Activate Incident Response team and executive escalation:**
   - CISO, Legal, Communications must be notified immediately
   - Consider engaging external IR firm (Mandiant, CrowdStrike, etc.)

## Remediation

1. **Eradication (after full containment):**
   - Wipe and rebuild all confirmed infected systems from clean images
   - Do NOT restore potentially infected OS; rebuild from scratch
   - Ensure ransomware persistence mechanisms are removed

2. **Recovery from clean backups:**
   - Verify backup integrity before restoration
   - Restore from backups predating the infection (account for exfiltration window)
   - Test restored systems in isolated environment before reconnecting

3. **If no clean backups:**
   - Check No More Ransom for decryptors for the specific variant
   - Consider professional decryption services
   - Prioritize restoration by business criticality

4. **Patch the initial access vector:**
   - Close the entry point that allowed ransomware in
   - If RDP: patch, restrict, implement MFA
   - If phishing: update filters, user training
   - If unpatched vulnerability: patch all systems

5. **Harden environment before reconnecting:**
   - Reset ALL credentials (domain-wide if domain was compromised)
   - Reset KRBTGT password twice if domain controllers affected
   - Implement network segmentation improvements

## Prevention

- Maintain offline/air-gapped backups; test restoration quarterly
- Implement 3-2-1 backup rule (3 copies, 2 media types, 1 offsite)
- Enable VSS shadow copies and protect with backup operator account only
- Patch operating systems and software within 30 days of critical patches
- Restrict RDP: require MFA, use VPN gateway, limit to specific IPs
- Implement network segmentation to limit ransomware spread
- Disable SMBv1; restrict SMB access between workstations
- Deploy EDR with behavioral ransomware detection
- Enable Controlled Folder Access (Windows Defender) on endpoints
- Implement email security with attachment sandboxing
- Block PowerShell execution policy for non-admin users
- Regular tabletop exercises simulating ransomware scenarios
- Have IR retainer with external firm for rapid response capability
