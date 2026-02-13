import json
import os
from datetime import datetime
from typing import Any, Dict, List

from utils import (
    OWASP_IOT_TOP10,
    VULN_TO_OWASP,
    ZAP_ALERT_TO_OWASP,
    get_credentials_for_vendor,
    load_default_credentials,
    load_env,
)


class ReportGenerator:
    """IoT security report generator."""

    def __init__(self, output_dir: str):
        """Initializes the report generator."""
        self.output_dir = output_dir
        self.results: Dict[str, Any] = {}
        self.vulnerabilities: List[Dict] = []
        self.timestamp = datetime.now().isoformat()
        self.vendor = ""

        env = load_env()
        wordlist_base = env["WORDLIST_PATH"]
        default_creds_csv = os.path.join(wordlist_base, env["WORDLIST_DEFAULT_CREDS"])
        self.credentials_by_vendor = load_default_credentials(default_creds_csv)

    def add_scan_results(self, module: str, results: Dict) -> None:
        """Adds results from a scan module."""
        self.results[module] = results

        if module == "information_gathering" and not self.vendor:
            self.vendor = results.get("vendor", "")

        self._extract_vulnerabilities(module, results)

    def _extract_vulnerabilities(self, module: str, results: Dict) -> None:
        """Extracts vulnerabilities from each module's results."""
        if module == "information_gathering":
            self._extract_from_nmap(results)
        elif module == "traffic_analyzer":
            self._extract_from_traffic(results)
        elif module == "vulnerability_detection":
            self._extract_from_vuln_detection(results)

    def _extract_from_nmap(self, results: Dict) -> None:
        """Extracts vulnerabilities from nmap scan."""
        for host in results.get("hosts", []):
            for port_info in host.get("ports", []):
                service = port_info.get("service", "").lower()

                if service in ["telnet", "ftp"]:
                    self.vulnerabilities.append(
                        {
                            "type": f"{service}_enabled",
                            "source": "nmap",
                            "severity": "high",
                            "host": host.get("ip"),
                            "port": port_info.get("port"),
                            "service": service,
                            "description": f"{service.upper()} service enabled (cleartext)",
                        }
                    )

    def _extract_from_traffic(self, results: Dict) -> None:
        """Extracts vulnerabilities from traffic analysis."""
        for finding in results.get("security_findings", []):
            self.vulnerabilities.append(
                {
                    "type": finding.get("type", "unknown"),
                    "source": "traffic_analyzer",
                    "severity": "high",
                    "description": finding.get("description", ""),
                    "details": finding,
                }
            )

    def _extract_from_vuln_detection(self, results: Dict) -> None:
        """Extracts vulnerabilities from the detection module."""
        # ZAP scan
        for alert in results.get("web_scan", {}).get("vulnerabilities", []):
            self.vulnerabilities.append(
                {
                    "type": "web_vulnerability",
                    "source": "zap",
                    "severity": self._map_zap_risk(alert.get("risk", "")),
                    "name": alert.get("name", ""),
                    "description": alert.get("description", ""),
                    "url": alert.get("url", ""),
                    "solution": alert.get("solution", ""),
                    "confidence": alert.get("confidence", ""),
                    "cweid": alert.get("cweid", ""),
                    "wascid": alert.get("wascid", ""),
                }
            )

        # Firmware analysis
        fw = results.get("firmware_analysis", {})
        if fw:
            # Hashes found
            for h in fw.get("hashes", []):
                self.vulnerabilities.append(
                    {
                        "type": "exposed_hash",
                        "source": "firmware",
                        "severity": "high",
                        "username": h.get("username"),
                        "description": f"Password hash found for user {h.get('username')}",
                    }
                )

            # Cracked passwords
            for crack in fw.get("cracked_passwords", []):
                self.vulnerabilities.append(
                    {
                        "type": "cracked_password",
                        "source": "firmware",
                        "severity": "critical",
                        "username": crack.get("username"),
                        "description": f"Password cracked for user {crack.get('username')}",
                    }
                )

            # Hardcoded credentials
            for cred in fw.get("hardcoded_credentials", []):
                matches = cred.get("matches", [])
                self.vulnerabilities.append(
                    {
                        "type": "hardcoded_credentials",
                        "source": "firmware",
                        "severity": "medium",
                        "file": cred.get("file"),
                        "match_count": len(matches),
                        "matches": matches,
                        "description": f"Possible hardcoded credentials ({len(matches)} occurrences)",
                    }
                )

            # Exposed certificates/keys
            for cert in fw.get("certificates", []):
                cert_type = cert.get("type", "")
                if cert_type == ".key":
                    self.vulnerabilities.append(
                        {
                            "type": "exposed_private_key",
                            "source": "firmware",
                            "severity": "critical",
                            "file": cert.get("file"),
                            "description": "Private key exposed in firmware",
                        }
                    )
                else:
                    self.vulnerabilities.append(
                        {
                            "type": "exposed_certificate",
                            "source": "firmware",
                            "severity": "medium",
                            "file": cert.get("file"),
                            "description": f"Certificate ({cert_type}) exposed in firmware",
                        }
                    )

        # Brute force
        for bf in results.get("brute_force", []):
            username = bf.get("username", "")
            password = bf.get("password", "")
            service = bf.get("service")

            credential_pair = f"{username}:{password}"
            vendor_credentials = get_credentials_for_vendor(
                self.credentials_by_vendor, self.vendor
            )
            is_default = credential_pair in vendor_credentials

            vuln_type = "default_credentials" if is_default else "brute_force_success"
            description = (
                f"Default credential in use: {username} ({self.vendor or 'generic'})"
                if is_default
                else f"Weak credential found via brute force: {username}"
            )

            self.vulnerabilities.append(
                {
                    "type": vuln_type,
                    "source": "hydra",
                    "severity": "critical",
                    "service": service,
                    "username": username,
                    "description": description,
                    "vendor": self.vendor if is_default else None,
                }
            )

        # CVEs
        for cve_entry in results.get("cve_lookup", []):
            for cve in cve_entry.get("cves", []):
                self.vulnerabilities.append(
                    {
                        "type": "known_cve",
                        "source": "nvd",
                        "severity": self._map_cvss_severity(cve.get("cvss_score")),
                        "cve_id": cve.get("cve_id"),
                        "cvss_score": cve.get("cvss_score"),
                        "service": cve_entry.get("service"),
                        "version": cve_entry.get("version"),
                        "description": cve.get("description", ""),
                    }
                )

    def _map_zap_risk(self, risk: str) -> str:
        """Maps ZAP risk to severity."""
        mapping = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info",
        }
        return mapping.get(risk, "info")

    def _map_cvss_severity(self, score: float) -> str:
        """Maps CVSS score to severity."""
        if not score:
            return "unknown"
        if score >= 9.0:
            return "critical"
        if score >= 7.0:
            return "high"
        if score >= 4.0:
            return "medium"
        return "low"

    def categorize_owasp_iot(self) -> Dict:
        """Categorizes vulnerabilities by OWASP IoT Top 10."""
        categories = {cat: [] for cat in OWASP_IOT_TOP10.keys()}

        for vuln in self.vulnerabilities:
            vuln_type = vuln.get("type", "")
            owasp_cat = None

            # Try to map by type
            if vuln_type in VULN_TO_OWASP:
                owasp_cat = VULN_TO_OWASP[vuln_type]

            # If web vuln, try to map by ZAP alert name
            elif vuln_type == "web_vulnerability":
                name = vuln.get("name", "")
                for key, cat in ZAP_ALERT_TO_OWASP.items():
                    if key.lower() in name.lower():
                        owasp_cat = cat
                        break
                if not owasp_cat:
                    owasp_cat = "I3"  # Default for web vulns

            # If finding has owasp_iot
            elif "owasp_iot" in vuln.get("details", {}):
                owasp_cat = vuln["details"]["owasp_iot"]

            if owasp_cat and owasp_cat in categories:
                vuln["owasp_category"] = owasp_cat
                categories[owasp_cat].append(vuln)

        return categories

    def calculate_severity(self) -> Dict:
        """Calculates vulnerability severity distribution."""
        severity_count = {
            "critical": 0,
            "high": 0,
            "medium": 0,
            "low": 0,
            "info": 0,
            "unknown": 0,
        }

        for vuln in self.vulnerabilities:
            severity = vuln.get("severity", "unknown")
            if severity in severity_count:
                severity_count[severity] += 1
            else:
                severity_count["unknown"] += 1

        total_score = (
            severity_count["critical"] * 10
            + severity_count["high"] * 7
            + severity_count["medium"] * 4
            + severity_count["low"] * 1
        )

        risk_level = "low"
        if total_score >= 50:
            risk_level = "critical"
        elif total_score >= 30:
            risk_level = "high"
        elif total_score >= 15:
            risk_level = "medium"

        return {
            "counts": severity_count,
            "total_vulnerabilities": len(self.vulnerabilities),
            "total_score": total_score,
            "risk_level": risk_level,
        }

    def _get_recommendations(self, owasp_cat: str) -> List[str]:
        """Returns mitigation recommendations by OWASP category."""
        recommendations = {
            "I1": [
                "Implement strong password policy",
                "Remove all hardcoded credentials from code/firmware",
                "Force default password change on first access",
                "Implement lockout after failed login attempts",
            ],
            "I2": [
                "Disable unused services",
                "Use secure protocols",
                "Implement firewall to restrict port access",
            ],
            "I3": [
                "Implement input validation on all interfaces",
                "Configure security headers",
            ],
            "I4": [
                "Implement digital signature verification for updates",
                "Use secure channel (HTTPS) for update downloads",
                "Notify user about available updates",
                "Protection against version downgrade",
            ],
            "I5": [
                "Maintain software component inventory",
                "Monitor CVEs for used components",
                "Implement regular update process",
                "Replace unsupported components",
            ],
            "I6": [
                "Implement encryption for sensitive data",
                "Minimize personal data collection",
                "Implement data access control",
            ],
            "I7": [
                "Use encryption for communications",
                "Encrypt sensitive data before storage",
                "Do not transmit credentials in cleartext",
            ],
            "I9": [
                "Force default password change on first access",
                "Change all default settings",
                "Disable unnecessary services",
                "Document recommended secure configurations",
            ],
        }
        return recommendations.get(owasp_cat, [])

    def generate_json(self) -> str:
        """Generates report in JSON format."""
        print("[*] Generating JSON report")

        owasp_categories = self.categorize_owasp_iot()
        severity = self.calculate_severity()

        report = {
            "metadata": {
                "generated_at": self.timestamp,
                "tool": "IoT Device Vulnerability Detection Tool",
                "version": "1.0",
            },
            "summary": {
                "total_vulnerabilities": severity["total_vulnerabilities"],
                "risk_level": severity["risk_level"],
                "severity_distribution": severity["counts"],
                "total_score": severity["total_score"],
            },
            "owasp_iot_top10": {},
            "vulnerabilities": self.vulnerabilities,
            "raw_results": self.results,
        }

        for cat_id, vulns in owasp_categories.items():
            cat_info = OWASP_IOT_TOP10[cat_id]
            report["owasp_iot_top10"][cat_id] = {
                "name": cat_info["name"],
                "description": cat_info["description"],
                "vulnerabilities_count": len(vulns),
                "vulnerabilities": vulns,
                "recommendations": self._get_recommendations(cat_id) if vulns else [],
            }

        os.makedirs(self.output_dir, exist_ok=True)
        filepath = os.path.join(self.output_dir, "security_report.json")

        with open(filepath, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2, ensure_ascii=False)

        print(f"[+] JSON report: {filepath}")
        return filepath

    def generate_html(self) -> str:
        """Generates report in HTML format."""
        print("[*] Generating HTML report")

        owasp_categories = self.categorize_owasp_iot()
        severity = self.calculate_severity()

        css = """
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }
            .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }
            h1 { color: #333; border-bottom: 2px solid #007bff; padding-bottom: 10px; }
            h2 { color: #444; margin-top: 30px; }
            h3 { color: #555; }
            .summary { display: flex; gap: 20px; flex-wrap: wrap; margin: 20px 0; }
            .summary-card { background: #f8f9fa; padding: 15px; border-radius: 8px; min-width: 150px; text-align: center; }
            .summary-card.critical { border-left: 4px solid #dc3545; }
            .summary-card.high { border-left: 4px solid #fd7e14; }
            .summary-card.medium { border-left: 4px solid #ffc107; }
            .summary-card.low { border-left: 4px solid #28a745; }
            .summary-card .count { font-size: 2em; font-weight: bold; }
            .risk-critical { color: #dc3545; }
            .risk-high { color: #fd7e14; }
            .risk-medium { color: #ffc107; }
            .risk-low { color: #28a745; }
            .category { margin: 20px 0; padding: 15px; border: 1px solid #ddd; border-radius: 8px; }
            .category-header { display: flex; justify-content: space-between; align-items: center; }
            .category-count { background: #007bff; color: white; padding: 5px 10px; border-radius: 20px; }
            .category-count.zero { background: #28a745; }
            .vuln-list { margin-top: 15px; }
            .vuln-item { background: #f8f9fa; padding: 10px; margin: 10px 0; border-radius: 4px; border-left: 4px solid #ddd; }
            .vuln-item.critical { border-left-color: #dc3545; }
            .vuln-item.high { border-left-color: #fd7e14; }
            .vuln-item.medium { border-left-color: #ffc107; }
            .vuln-item.low { border-left-color: #28a745; }
            .severity-badge { padding: 2px 8px; border-radius: 4px; font-size: 0.8em; color: white; }
            .severity-badge.critical { background: #dc3545; }
            .severity-badge.high { background: #fd7e14; }
            .severity-badge.medium { background: #ffc107; color: #333; }
            .severity-badge.low { background: #28a745; }
            .recommendations { background: #e7f3ff; padding: 15px; border-radius: 4px; margin-top: 15px; }
            .recommendations ul { margin: 10px 0; padding-left: 20px; }
            table { width: 100%; border-collapse: collapse; margin: 15px 0; }
            th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
            th { background: #f8f9fa; }
            .timestamp { color: #666; font-size: 0.9em; }
        </style>
        """

        risk_class = f"risk-{severity['risk_level']}"
        if severity["risk_level"] == "critical":
            risk_class = "risk-critical"
        elif severity["risk_level"] == "high":
            risk_class = "risk-high"
        elif severity["risk_level"] == "medium":
            risk_class = "risk-medium"
        else:
            risk_class = "risk-low"

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IoT Security Report</title>
    {css}
</head>
<body>
    <div class="container">
        <h1>IoT Security Report</h1>
        <p class="timestamp">Generated at: {self.timestamp}</p>

        <h2>Executive Summary</h2>
        <div class="summary">
            <div class="summary-card">
                <div class="count">{severity["total_vulnerabilities"]}</div>
                <div>Vulnerabilities</div>
            </div>
            <div class="summary-card">
                <div class="count {risk_class}">{severity["risk_level"].upper()}</div>
                <div>Risk Level</div>
            </div>
            <div class="summary-card critical">
                <div class="count">{severity["counts"]["critical"]}</div>
                <div>Critical</div>
            </div>
            <div class="summary-card high">
                <div class="count">{severity["counts"]["high"]}</div>
                <div>High</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{severity["counts"]["medium"]}</div>
                <div>Medium</div>
            </div>
            <div class="summary-card low">
                <div class="count">{severity["counts"]["low"]}</div>
                <div>Low</div>
            </div>
        </div>

        <h2>OWASP IoT Top 10 Categorization</h2>
"""

        # Add each OWASP category
        for cat_id in sorted(OWASP_IOT_TOP10.keys()):
            cat_info = OWASP_IOT_TOP10[cat_id]
            vulns = owasp_categories.get(cat_id, [])
            count_class = "zero" if len(vulns) == 0 else ""

            html += f"""
        <div class="category">
            <div class="category-header">
                <h3>{cat_id}: {cat_info["name"]}</h3>
                <span class="category-count {count_class}">{len(vulns)}</span>
            </div>
            <p>{cat_info["description"]}</p>
"""

            if vulns:
                html += '<div class="vuln-list">'
                for vuln in vulns[:10]:
                    sev = vuln.get("severity", "unknown")
                    html += f"""
                <div class="vuln-item {sev}">
                    <strong>{vuln.get("type", "N/A")}</strong>
                    <span class="severity-badge {sev}">{sev.upper()}</span>
                    <p>{vuln.get("description", "No description")}</p>
                </div>
"""
                if len(vulns) > 10:
                    html += f"<p><em>... and {len(vulns) - 10} more vulnerabilities</em></p>"
                html += "</div>"

                recommendations = self._get_recommendations(cat_id)
                if recommendations:
                    html += '<div class="recommendations"><strong>Recommendations:</strong><ul>'
                    for rec in recommendations:
                        html += f"<li>{rec}</li>"
                    html += "</ul></div>"

            html += "</div>"

        html += """
        <h2>Complete Vulnerability List</h2>
        <table>
            <thead>
                <tr>
                    <th>Type</th>
                    <th>Severity</th>
                    <th>Source</th>
                    <th>Description</th>
                </tr>
            </thead>
            <tbody>
"""

        for vuln in self.vulnerabilities:
            sev = vuln.get("severity", "unknown")
            html += f"""
                <tr>
                    <td>{vuln.get("type", "N/A")}</td>
                    <td><span class="severity-badge {sev}">{sev.upper()}</span></td>
                    <td>{vuln.get("source", "N/A")}</td>
                    <td>{vuln.get("description", "N/A")[:100]}...</td>
                </tr>
"""

        html += """
            </tbody>
        </table>
    </div>
</body>
</html>
"""

        os.makedirs(self.output_dir, exist_ok=True)
        filepath = os.path.join(self.output_dir, "security_report.html")

        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)

        print(f"[+] HTML report: {filepath}")
        return filepath

    def generate(self) -> Dict[str, str]:
        """Generates reports in all formats."""
        return {
            "json": self.generate_json(),
            "html": self.generate_html(),
        }
