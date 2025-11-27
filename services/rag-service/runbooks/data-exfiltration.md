# Data Exfiltration Response

## Scope

This runbook covers detection and response to unauthorized data transfer or theft from the organization's network. Data exfiltration is typically the final objective of an attacker after establishing persistence and moving laterally.

**Applies to:** All systems, networks, and cloud environments.
**MITRE ATT&CK:** T1041 - Exfiltration Over C2 Channel, T1048 - Exfiltration Over Alternative Protocol, T1567 - Exfiltration Over Web Service

## Detection

Indicators of data exfiltration:

- Large volume of outbound data to external IP (DLP alert, anomaly detection)
- Unusual access to sensitive data repositories (file servers, databases, SharePoint)
- DNS tunneling patterns (high volume of TXT queries, long subdomain strings)
- Unusual use of cloud storage (Dropbox, Google Drive, OneDrive) from corporate endpoints
- Data transferred over non-standard ports (443/80 mimicry, ICMP tunneling)
- Wazuh alert: Bulk file access or download from sensitive share
- SIEM correlation: User accessing many files rapidly across multiple directories
- Email with large attachment to personal email address
- FTP/SCP/rsync to external hosts
- Encrypted archive creation followed by outbound transfer

## Investigation Steps

1. **Quantify the suspected exfiltration:**
   ```
   # Review firewall/proxy logs for large outbound transfers
   # Look for: bytes_sent > 100MB in single session, or > 1GB daily
   # Identify destination IP/domain and geolocation
   ```

2. **Identify the source host and user:**
   ```bash
   # Correlate outbound traffic with internal DHCP/NAT logs
   # Map source IP to hostname and last logged-in user
   grep <source_ip> /var/log/dhcpd.log
   ```

3. **Determine what data was accessed:**
   ```bash
   # Linux - check recently accessed files
   find /sensitive-data -atime -1 -type f 2>/dev/null

   # Windows - check file access audit events (Event ID 4663)
   Get-WinEvent -FilterHashtable @{LogName='Security'; Id=4663} | Where-Object {$_.Message -match "sensitive"}

   # Database - check query logs for bulk SELECT
   # Application - check access logs for bulk export operations
   ```

4. **Analyze network traffic patterns:**
   - Extract flows from SIEM/NetFlow/Zeek for the suspect source
   - Identify total bytes transferred per destination
   - Check for DNS tunneling: query `dig` for domains with long subdomains
   - Look for HTTPS to unusual certificate-less servers

5. **Check for exfiltration staging:**
   ```bash
   # Find compressed/encrypted archives created recently
   find / -name "*.zip" -o -name "*.tar.gz" -o -name "*.7z" -newer /etc/passwd 2>/dev/null
   find /tmp /home -name "*.enc" -o -name "*.gpg" 2>/dev/null
   ```

6. **Review cloud sync activity:**
   - Check Dropbox, OneDrive, Google Drive sync clients for recent large uploads
   - Review Office 365 audit logs for SharePoint/OneDrive mass downloads
   - Check email gateway for large outbound attachments

7. **Identify if insider threat or external compromise:**
   - Was user account compromised first (check for prior indicators)?
   - Was access from normal work hours and location?
   - Does the accessed data align with user's role?

## Containment

**Immediate (within 1 hour):**

1. **Block outbound traffic to exfiltration destination:**
   ```bash
   # Firewall block
   iptables -A OUTPUT -d <DESTINATION_IP> -j DROP

   # Or block entire suspect host outbound
   iptables -A FORWARD -s <SUSPECT_HOST> -j DROP
   ```

2. **Isolate the compromised host** from network (if external compromise)

3. **Suspend the user account** pending investigation:
   ```bash
   # Active Directory
   Disable-ADAccount -Identity <username>

   # Linux
   usermod -L <username>
   passwd -l <username>
   ```

4. **Revoke cloud access tokens and OAuth grants** if cloud services were used

5. **Block USB/removable media** if physical exfiltration suspected:
   ```
   # Windows Group Policy: Computer Config > Admin Templates > System > Removable Storage
   # Linux: modprobe -r usb_storage
   ```

6. **Notify legal and compliance teams** - data breach notification requirements may apply

## Remediation

1. **Identify and catalog all data potentially exfiltrated:**
   - Data classification (PII, financial, IP, credentials)
   - Estimate record counts if personal data involved
   - Document for breach notification assessment

2. **Eradicate the exfiltration channel:**
   - Remove malware enabling the exfiltration (if applicable)
   - Revoke compromised credentials
   - Patch the initial access vulnerability

3. **Implement DLP controls to prevent recurrence:**
   - Block upload to personal cloud storage from corporate devices
   - Implement email DLP with sensitive data pattern detection
   - Enable endpoint DLP (USB blocking, print monitoring)

4. **Complete forensic investigation:**
   - Preserve all evidence (logs, pcap, disk images)
   - Engage legal/HR for insider threat cases
   - Consider law enforcement engagement for significant breaches

5. **Breach notification assessment:**
   - Determine if GDPR, HIPAA, PCI-DSS, or state breach notification applies
   - Engage DPO/legal counsel
   - Prepare notification within required timeline (GDPR: 72 hours to supervisory authority)

## Prevention

- Implement Data Loss Prevention (DLP) across email, web, and endpoint
- Apply network segmentation; sensitive data in isolated VLANs
- Enable data classification and labeling (Microsoft Purview, Varonis)
- Monitor and alert on bulk data access (UEBA/behavioral analytics)
- Control and audit removable media and cloud sync clients
- Implement egress filtering; whitelist approved external services only
- Enable and monitor audit logging for all sensitive data repositories
- Deploy CASB (Cloud Access Security Broker) for cloud data visibility
- Conduct regular data access reviews; enforce need-to-know
- Monitor DNS for tunneling patterns (Zeek dns.log analysis)
- Implement UEBA to detect abnormal user data access patterns
