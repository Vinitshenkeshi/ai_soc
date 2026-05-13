"""
Knowledge Base Manager - RAG Service
AI-Augmented SOC

Manages ingestion of security knowledge bases:
- MITRE ATT&CK framework
- CVE database (NVD API v2)
- Historical incident data
- Security runbooks
"""

import logging
import json
import time
import re
from typing import List, Dict, Any, Optional
from pathlib import Path
import requests

logger = logging.getLogger(__name__)

# NVD API v2 base URL
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

# Rate limit: 5 requests per 30 seconds without API key
NVD_RATE_LIMIT_REQUESTS = 5
NVD_RATE_LIMIT_WINDOW = 30  # seconds
NVD_REQUEST_DELAY = NVD_RATE_LIMIT_WINDOW / NVD_RATE_LIMIT_REQUESTS  # 6 seconds between requests


class KnowledgeBaseManager:
    """
    Manages security knowledge base ingestion and updates.

    Handles:
    - MITRE ATT&CK technique embedding
    - CVE vulnerability data (NVD API v2)
    - TheHive incident history
    - Security playbooks and runbooks
    """

    def __init__(self, vector_store):
        """
        Initialize knowledge base manager.

        Args:
            vector_store: VectorStore instance
        """
        self.vector_store = vector_store
        self._nvd_request_count = 0
        self._nvd_window_start = time.time()
        logger.info("KnowledgeBaseManager initialized")

    async def ingest_mitre_attack(self, data_path: Optional[str] = None) -> Dict[str, Any]:
        """
        Ingest MITRE ATT&CK framework.

        Args:
            data_path: Path to MITRE ATT&CK JSON (optional, can download)

        Returns:
            Dict with ingestion statistics
        """
        logger.info("Ingesting MITRE ATT&CK framework")

        try:
            if not data_path:
                logger.info("Downloading MITRE ATT&CK data from GitHub...")
                data_path = await self._download_mitre_attack()

            with open(data_path) as f:
                attack_data = json.load(f)

            logger.info(f"Loaded {len(attack_data['objects'])} MITRE ATT&CK objects")

            self.vector_store.create_collection(
                name='mitre_attack',
                metadata={'source': 'mitre-attack', 'version': 'enterprise'}
            )

            techniques = []
            for obj in attack_data['objects']:
                if obj['type'] == 'attack-pattern':
                    external_refs = obj.get('external_references', [])
                    technique_id = external_refs[0]['external_id'] if external_refs else 'Unknown'

                    kill_chain = obj.get('kill_chain_phases', [])
                    tactics = [phase['phase_name'] for phase in kill_chain]
                    primary_tactic = tactics[0] if tactics else 'Unknown'

                    platforms = obj.get('x_mitre_platforms', [])
                    data_sources = obj.get('x_mitre_data_sources', [])

                    doc = f"""Technique: {technique_id} - {obj.get('name', 'Unknown')}
Tactics: {', '.join(tactics)}
Description: {obj.get('description', '')}
Platforms: {', '.join(platforms)}
Data Sources: {', '.join(data_sources)}"""

                    metadata = {
                        'technique_id': technique_id,
                        'name': obj.get('name', 'Unknown'),
                        'tactic': primary_tactic,
                        'tactics': json.dumps(tactics),
                        'platforms': json.dumps(platforms),
                        'type': 'mitre_technique'
                    }

                    techniques.append({
                        'document': doc,
                        'metadata': metadata,
                        'id': technique_id
                    })

            logger.info(f"Extracted {len(techniques)} attack techniques")

            batch_size = 50
            total_ingested = 0

            for i in range(0, len(techniques), batch_size):
                batch = techniques[i:i+batch_size]

                await self.vector_store.add_documents(
                    collection_name='mitre_attack',
                    documents=[t['document'] for t in batch],
                    metadatas=[t['metadata'] for t in batch],
                    ids=[t['id'] for t in batch]
                )

                total_ingested += len(batch)
                logger.info(f"Ingested batch {i//batch_size + 1}: {total_ingested}/{len(techniques)} techniques")

            logger.info(f"Successfully ingested {total_ingested} MITRE ATT&CK techniques")

            return {
                "status": "success",
                "techniques_ingested": total_ingested,
                "message": "MITRE ATT&CK framework ingested successfully"
            }

        except Exception as e:
            logger.error(f"Failed to ingest MITRE ATT&CK: {e}")
            logger.exception(e)
            return {
                "status": "error",
                "techniques_ingested": 0,
                "message": str(e)
            }

    async def ingest_cve_database(self, severity_filter: str = "CRITICAL") -> Dict[str, Any]:
        """
        Ingest CVE vulnerability database from NVD API v2.

        Queries NVD for CRITICAL and HIGH severity CVEs, creates embeddings,
        and stores in ChromaDB cve_database collection.

        NVD API v2: https://services.nvd.nist.gov/rest/json/cves/2.0
        Rate limit: 5 requests per 30 seconds without API key.

        Args:
            severity_filter: "CRITICAL" fetches critical only; "HIGH" fetches critical + high

        Returns:
            Dict with ingestion statistics
        """
        logger.info(f"Ingesting CVE database (filter: {severity_filter})")

        severities_to_fetch = ["CRITICAL"]
        if severity_filter == "HIGH":
            severities_to_fetch = ["CRITICAL", "HIGH"]

        self.vector_store.create_collection(
            name='cve_database',
            metadata={'source': 'nvd-api-v2', 'severity_filter': severity_filter}
        )

        all_cves = []
        total_ingested = 0
        errors = []

        for severity in severities_to_fetch:
            logger.info(f"Fetching {severity} CVEs from NVD API v2...")

            params = {
                "cvssV3Severity": severity,
                "resultsPerPage": 100,
                "startIndex": 0
            }

            try:
                self._nvd_rate_limit()
                response = requests.get(
                    NVD_API_URL,
                    params=params,
                    timeout=30,
                    headers={"Accept": "application/json"}
                )
                response.raise_for_status()
                data = response.json()
            except requests.exceptions.RequestException as e:
                logger.error(f"Failed to fetch {severity} CVEs: {e}")
                errors.append(str(e))
                continue

            total_results = data.get("totalResults", 0)
            results_per_page = data.get("resultsPerPage", 100)
            logger.info(f"Total {severity} CVEs available: {total_results}")

            page_cves = self._parse_nvd_response(data, severity)
            all_cves.extend(page_cves)

            # Fetch up to 4 more pages (500 CVEs per severity) to respect rate limits
            max_pages = min(5, (total_results + results_per_page - 1) // results_per_page)
            for page in range(1, max_pages):
                start_index = page * results_per_page
                params["startIndex"] = start_index

                try:
                    self._nvd_rate_limit()
                    response = requests.get(
                        NVD_API_URL,
                        params=params,
                        timeout=30,
                        headers={"Accept": "application/json"}
                    )
                    response.raise_for_status()
                    page_data = response.json()
                    page_cves = self._parse_nvd_response(page_data, severity)
                    all_cves.extend(page_cves)
                    logger.info(f"Fetched page {page + 1}/{max_pages} for {severity} CVEs ({len(all_cves)} total)")
                except requests.exceptions.RequestException as e:
                    logger.warning(f"Failed to fetch page {page} of {severity} CVEs: {e}")
                    errors.append(str(e))
                    break

        logger.info(f"Total CVEs collected: {len(all_cves)}")

        batch_size = 50
        for i in range(0, len(all_cves), batch_size):
            batch = all_cves[i:i + batch_size]
            try:
                await self.vector_store.add_documents(
                    collection_name='cve_database',
                    documents=[c['document'] for c in batch],
                    metadatas=[c['metadata'] for c in batch],
                    ids=[c['id'] for c in batch]
                )
                total_ingested += len(batch)
                logger.info(f"Ingested CVE batch {i // batch_size + 1}: {total_ingested}/{len(all_cves)}")
            except Exception as e:
                logger.error(f"Failed to ingest CVE batch: {e}")
                errors.append(str(e))

        status = "success" if total_ingested > 0 else "error"
        message = f"Ingested {total_ingested} CVEs"
        if errors:
            message += f" ({len(errors)} errors encountered)"

        return {
            "status": status,
            "cves_ingested": total_ingested,
            "severity_filter": severity_filter,
            "message": message,
            "errors": errors[:5] if errors else []
        }

    def _nvd_rate_limit(self):
        """
        Enforce NVD API rate limit: 5 requests per 30 seconds without API key.
        Sleeps if necessary to stay within limits.
        """
        now = time.time()
        elapsed = now - self._nvd_window_start

        if elapsed >= NVD_RATE_LIMIT_WINDOW:
            self._nvd_window_start = now
            self._nvd_request_count = 0

        if self._nvd_request_count >= NVD_RATE_LIMIT_REQUESTS:
            sleep_time = NVD_RATE_LIMIT_WINDOW - elapsed
            if sleep_time > 0:
                logger.info(f"NVD rate limit reached, sleeping {sleep_time:.1f}s...")
                time.sleep(sleep_time)
            self._nvd_window_start = time.time()
            self._nvd_request_count = 0
        elif self._nvd_request_count > 0:
            time.sleep(NVD_REQUEST_DELAY)

        self._nvd_request_count += 1

    def _parse_nvd_response(self, data: Dict[str, Any], severity: str) -> List[Dict[str, Any]]:
        """
        Parse NVD API v2 response into document format for ChromaDB.

        Args:
            data: Raw NVD API response
            severity: The severity level queried

        Returns:
            List of document dicts with id, document text, and metadata
        """
        documents = []
        vulnerabilities = data.get("vulnerabilities", [])

        for item in vulnerabilities:
            cve = item.get("cve", {})
            cve_id = cve.get("id", "UNKNOWN")

            descriptions = cve.get("descriptions", [])
            description = next(
                (d["value"] for d in descriptions if d.get("lang") == "en"),
                descriptions[0]["value"] if descriptions else "No description available"
            )

            metrics = cve.get("metrics", {})
            cvss_score = 0.0
            cvss_vector = ""
            actual_severity = severity

            for cvss_version in ["cvssMetricV31", "cvssMetricV30"]:
                if cvss_version in metrics and metrics[cvss_version]:
                    cvss_data = metrics[cvss_version][0].get("cvssData", {})
                    cvss_score = cvss_data.get("baseScore", 0.0)
                    cvss_vector = cvss_data.get("vectorString", "")
                    actual_severity = metrics[cvss_version][0].get("baseSeverity", severity)
                    break

            affected_products = []
            configurations = cve.get("configurations", [])
            for config in configurations:
                for node in config.get("nodes", []):
                    for cpe_match in node.get("cpeMatch", []):
                        cpe_name = cpe_match.get("criteria", "")
                        parts = cpe_name.split(":")
                        if len(parts) >= 5:
                            vendor = parts[3]
                            product = parts[4]
                            if vendor != "*" and product != "*":
                                affected_products.append(f"{vendor}:{product}")

            affected_products = list(set(affected_products))[:10]

            references = cve.get("references", [])
            ref_urls = [r.get("url", "") for r in references[:5]]

            published_date = cve.get("published", "")
            if published_date:
                published_date = published_date[:10]

            doc = f"""CVE ID: {cve_id}
Severity: {actual_severity}
CVSS Score: {cvss_score}
CVSS Vector: {cvss_vector}
Published: {published_date}

Description: {description}

Affected Products: {', '.join(affected_products) if affected_products else 'Not specified'}

References: {', '.join(ref_urls) if ref_urls else 'None'}"""

            metadata = {
                "cve_id": cve_id,
                "cvss_score": float(cvss_score),
                "severity": actual_severity,
                "published_date": published_date,
                "affected_products": json.dumps(affected_products),
                "type": "cve"
            }

            documents.append({
                "id": cve_id,
                "document": doc,
                "metadata": metadata
            })

        return documents

    async def ingest_incident_history(
        self,
        thehive_url: Optional[str] = None,
        api_key: Optional[str] = None,
        min_cases: int = 50
    ) -> Dict[str, Any]:
        """
        Ingest resolved TheHive cases for historical context.

        NOTE: Requires TheHive deployment - post-MVP.
        """
        logger.info("Ingesting incident history from TheHive")
        return {
            "status": "not_implemented",
            "cases_ingested": 0,
            "message": "Incident history ingestion requires TheHive deployment (post-MVP)"
        }

    async def ingest_security_runbooks(self, runbooks_dir: str) -> Dict[str, Any]:
        """
        Ingest security runbooks and playbooks from markdown files.

        Parses markdown runbooks, splits into sections (## headings), and embeds
        into ChromaDB security_runbooks collection.

        Args:
            runbooks_dir: Directory containing runbook markdown files

        Returns:
            Dict with ingestion statistics
        """
        logger.info(f"Ingesting security runbooks from {runbooks_dir}")

        runbooks_path = Path(runbooks_dir)
        if not runbooks_path.exists():
            return {
                "status": "error",
                "runbooks_ingested": 0,
                "message": f"Runbooks directory not found: {runbooks_dir}"
            }

        md_files = list(runbooks_path.glob("*.md"))
        if not md_files:
            return {
                "status": "error",
                "runbooks_ingested": 0,
                "message": f"No markdown files found in {runbooks_dir}"
            }

        logger.info(f"Found {len(md_files)} runbook files")

        self.vector_store.create_collection(
            name='security_runbooks',
            metadata={'source': 'security-runbooks', 'version': '1.0'}
        )

        all_sections = []
        runbooks_processed = 0

        for md_file in md_files:
            try:
                with open(md_file, 'r', encoding='utf-8') as f:
                    content = f.read()
                sections = self._parse_runbook(md_file, content)
                all_sections.extend(sections)
                runbooks_processed += 1
                logger.info(f"Parsed runbook: {md_file.name} ({len(sections)} sections)")
            except Exception as e:
                logger.error(f"Failed to parse runbook {md_file.name}: {e}")
                continue

        if not all_sections:
            return {
                "status": "error",
                "runbooks_ingested": 0,
                "message": "No sections could be extracted from runbooks"
            }

        batch_size = 50
        total_ingested = 0
        errors = []

        for i in range(0, len(all_sections), batch_size):
            batch = all_sections[i:i + batch_size]
            try:
                await self.vector_store.add_documents(
                    collection_name='security_runbooks',
                    documents=[s['document'] for s in batch],
                    metadatas=[s['metadata'] for s in batch],
                    ids=[s['id'] for s in batch]
                )
                total_ingested += len(batch)
                logger.info(f"Ingested runbook batch {i // batch_size + 1}: {total_ingested}/{len(all_sections)} sections")
            except Exception as e:
                logger.error(f"Failed to ingest runbook batch: {e}")
                errors.append(str(e))

        status = "success" if total_ingested > 0 else "error"
        return {
            "status": status,
            "runbooks_ingested": runbooks_processed,
            "sections_ingested": total_ingested,
            "message": f"Ingested {runbooks_processed} runbooks with {total_ingested} sections",
            "errors": errors[:3] if errors else []
        }

    def _parse_runbook(self, md_file: Path, content: str) -> List[Dict[str, Any]]:
        """
        Parse a markdown runbook into sections for embedding.

        Args:
            md_file: Path to the markdown file
            content: File content as string

        Returns:
            List of section dicts ready for ChromaDB
        """
        sections = []

        title_match = re.search(r'^#\s+(.+)$', content, re.MULTILINE)
        title = title_match.group(1).strip() if title_match else md_file.stem.replace('-', ' ').title()

        runbook_id = md_file.stem.lower().replace(' ', '-').replace('_', '-')
        category = self._categorize_runbook(title, runbook_id)

        section_pattern = re.compile(r'^##\s+(.+)$', re.MULTILINE)
        section_matches = list(section_pattern.finditer(content))

        if not section_matches:
            sections.append({
                "id": f"{runbook_id}-full",
                "document": f"Runbook: {title}\n\n{content}",
                "metadata": {
                    "runbook_id": runbook_id,
                    "title": title,
                    "category": category,
                    "section": "full",
                    "type": "runbook"
                }
            })
            return sections

        for idx, match in enumerate(section_matches):
            section_title = match.group(1).strip()
            section_start = match.end()
            section_end = section_matches[idx + 1].start() if idx + 1 < len(section_matches) else len(content)
            section_body = content[section_start:section_end].strip()

            if not section_body:
                continue

            doc = f"""Runbook: {title}
Category: {category}
Section: {section_title}

{section_body}"""

            # Build safe ChromaDB ID
            section_id = f"{runbook_id}-{section_title.lower().replace(' ', '-')}"
            section_id = re.sub(r'[^a-z0-9-]', '', section_id)[:100]

            sections.append({
                "id": section_id,
                "document": doc,
                "metadata": {
                    "runbook_id": runbook_id,
                    "title": title,
                    "category": category,
                    "section": section_title,
                    "type": "runbook"
                }
            })

        return sections

    def _categorize_runbook(self, title: str, runbook_id: str) -> str:
        """Derive incident category from runbook title or ID."""
        text = (title + " " + runbook_id).lower()
        categories = {
            "brute-force": "Credential Attack",
            "brute_force": "Credential Attack",
            "ssh": "Credential Attack",
            "malware": "Malware",
            "phishing": "Social Engineering",
            "privilege": "Privilege Escalation",
            "exfiltration": "Data Loss",
            "ransomware": "Ransomware",
            "unauthorized": "Unauthorized Access",
            "access": "Unauthorized Access",
        }
        for keyword, category in categories.items():
            if keyword in text:
                return category
        return "General Security"

    async def _download_mitre_attack(self) -> str:
        """
        Download latest MITRE ATT&CK data from GitHub.

        Returns:
            Path to downloaded JSON file
        """
        from pathlib import Path

        url = "https://raw.githubusercontent.com/mitre/cti/master/enterprise-attack/enterprise-attack.json"
        output_path = Path("/tmp/mitre-attack.json")

        try:
            logger.info(f"Downloading MITRE ATT&CK from {url}")
            response = requests.get(url, timeout=30)
            response.raise_for_status()

            output_path.parent.mkdir(parents=True, exist_ok=True)
            with open(output_path, 'w') as f:
                json.dump(response.json(), f)

            logger.info(f"Downloaded MITRE ATT&CK to {output_path}")
            return str(output_path)

        except Exception as e:
            logger.error(f"Failed to download MITRE ATT&CK: {e}")
            raise

    async def update_knowledge_base(self, collection: str) -> Dict[str, Any]:
        """
        Update existing knowledge base by deleting and re-ingesting.

        Args:
            collection: Collection name to update

        Returns:
            Dict with update statistics
        """
        logger.info(f"Updating knowledge base: {collection}")

        try:
            self.vector_store.delete_collection(collection)
            logger.info(f"Deleted collection: {collection}")

            if collection == "cve_database":
                result = await self.ingest_cve_database(severity_filter="CRITICAL")
            elif collection == "security_runbooks":
                runbooks_dir = Path(__file__).parent / "runbooks"
                result = await self.ingest_security_runbooks(str(runbooks_dir))
            elif collection == "mitre_attack":
                result = await self.ingest_mitre_attack()
            else:
                return {
                    "status": "error",
                    "message": f"Unknown collection: {collection}. Supported: cve_database, security_runbooks, mitre_attack"
                }

            return {
                "status": result.get("status", "unknown"),
                "collection": collection,
                "message": f"Collection {collection} updated: {result.get('message', '')}",
                "details": result
            }

        except Exception as e:
            logger.error(f"Failed to update knowledge base {collection}: {e}")
            logger.exception(e)
            return {
                "status": "error",
                "collection": collection,
                "message": str(e)
            }
