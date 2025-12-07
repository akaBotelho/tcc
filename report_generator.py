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
    """Gerador de relatórios de segurança IoT."""

    def __init__(self, output_dir: str):
        """Inicializa o gerador de relatórios."""
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
        """Adiciona resultados de um módulo de scan."""
        self.results[module] = results

        if module == "information_gathering" and not self.vendor:
            self.vendor = results.get("vendor", "")

        self._extract_vulnerabilities(module, results)

    def _extract_vulnerabilities(self, module: str, results: Dict) -> None:
        """Extrai vulnerabilidades dos resultados de cada módulo."""
        if module == "information_gathering":
            self._extract_from_nmap(results)
        elif module == "traffic_analyzer":
            self._extract_from_traffic(results)
        elif module == "vulnerability_detection":
            self._extract_from_vuln_detection(results)

    def _extract_from_nmap(self, results: Dict) -> None:
        """Extrai vulnerabilidades do scan nmap."""
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
                            "description": f"Serviço {service.upper()} habilitado (texto claro)",
                        }
                    )

    def _extract_from_traffic(self, results: Dict) -> None:
        """Extrai vulnerabilidades da análise de tráfego."""
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
        """Extrai vulnerabilidades do módulo de detecção."""
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
            # Hashes encontrados
            for h in fw.get("hashes", []):
                self.vulnerabilities.append(
                    {
                        "type": "exposed_hash",
                        "source": "firmware",
                        "severity": "high",
                        "username": h.get("username"),
                        "description": f"Hash de senha encontrado para usuário {h.get('username')}",
                    }
                )

            # Senhas quebradas
            for crack in fw.get("cracked_passwords", []):
                self.vulnerabilities.append(
                    {
                        "type": "cracked_password",
                        "source": "firmware",
                        "severity": "critical",
                        "username": crack.get("username"),
                        "description": f"Senha quebrada para usuário {crack.get('username')}",
                    }
                )

            # Credenciais hardcoded
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
                        "description": f"Possíveis credenciais hardcoded ({len(matches)} ocorrências)",
                    }
                )

            # Certificados/chaves expostos
            for cert in fw.get("certificates", []):
                cert_type = cert.get("type", "")
                if cert_type == ".key":
                    self.vulnerabilities.append(
                        {
                            "type": "exposed_private_key",
                            "source": "firmware",
                            "severity": "critical",
                            "file": cert.get("file"),
                            "description": "Chave privada exposta no firmware",
                        }
                    )
                else:
                    self.vulnerabilities.append(
                        {
                            "type": "exposed_certificate",
                            "source": "firmware",
                            "severity": "medium",
                            "file": cert.get("file"),
                            "description": f"Certificado ({cert_type}) exposto no firmware",
                        }
                    )

        # Força bruta
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
                f"Credencial padrão em uso: {username} ({self.vendor or 'generic'})"
                if is_default
                else f"Credencial fraca encontrada via força bruta: {username}"
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
        """Mapeia risco do ZAP para severidade."""
        mapping = {
            "High": "high",
            "Medium": "medium",
            "Low": "low",
            "Informational": "info",
        }
        return mapping.get(risk, "info")

    def _map_cvss_severity(self, score: float) -> str:
        """Mapeia score CVSS para severidade."""
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
        """Categoriza vulnerabilidades pelo OWASP IoT Top 10."""
        categories = {cat: [] for cat in OWASP_IOT_TOP10.keys()}

        for vuln in self.vulnerabilities:
            vuln_type = vuln.get("type", "")
            owasp_cat = None

            # Tenta mapear pelo tipo
            if vuln_type in VULN_TO_OWASP:
                owasp_cat = VULN_TO_OWASP[vuln_type]

            # Se for vuln web, tenta mapear pelo nome do alerta ZAP
            elif vuln_type == "web_vulnerability":
                name = vuln.get("name", "")
                for key, cat in ZAP_ALERT_TO_OWASP.items():
                    if key.lower() in name.lower():
                        owasp_cat = cat
                        break
                if not owasp_cat:
                    owasp_cat = "I3"  # Default para vulns web

            # Se tiver owasp_iot no próprio finding
            elif "owasp_iot" in vuln.get("details", {}):
                owasp_cat = vuln["details"]["owasp_iot"]

            if owasp_cat and owasp_cat in categories:
                vuln["owasp_category"] = owasp_cat
                categories[owasp_cat].append(vuln)

        return categories

    def calculate_severity(self) -> Dict:
        """Calcula distribuição de severidade das vulnerabilidades."""
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

        risk_level = "baixo"
        if total_score >= 50:
            risk_level = "crítico"
        elif total_score >= 30:
            risk_level = "alto"
        elif total_score >= 15:
            risk_level = "médio"

        return {
            "counts": severity_count,
            "total_vulnerabilities": len(self.vulnerabilities),
            "total_score": total_score,
            "risk_level": risk_level,
        }

    def _get_recommendations(self, owasp_cat: str) -> List[str]:
        """Retorna recomendações de mitigação por categoria OWASP."""
        recommendations = {
            "I1": [
                "Implementar política de senhas fortes",
                "Remover todas as credenciais hardcoded do código/firmware",
                "Forçar troca de senha padrão no primeiro acesso",
                "Implementar bloqueio após tentativas de login falhas",
            ],
            "I2": [
                "Desabilitar serviços não utilizados",
                "Usar protocolos seguros",
                "Implementar firewall para restringir acesso às portas",
            ],
            "I3": [
                "Implementar validação de entrada em todas as interfaces",
                "Configurar headers de segurança",
            ],
            "I4": [
                "Implementar verificação de assinatura digital em updates",
                "Usar canal seguro (HTTPS) para download de atualizações",
                "Notificação ao usuário sobre updates disponíveis",
                "Proteção contra downgrade de versão",
            ],
            "I5": [
                "Manter inventário de componentes de software",
                "Monitorar CVEs para componentes utilizados",
                "Implementar processo de atualização regular",
                "Substituir componentes sem suporte",
            ],
            "I6": [
                "Implementar criptografia para dados sensíveis",
                "Minimizar coleta de dados pessoais",
                "Implementar controle de acesso aos dados",
            ],
            "I7": [
                "Usar criptografia para as comunicações",
                "Criptografar dados sensíveis antes de armazenar",
                "Não transmitir credenciais em texto claro",
            ],
            "I9": [
                "Forçar troca de senha padrão no primeiro acesso",
                "Alterar todas as configurações padrão",
                "Desabilitar serviços desnecessários",
                "Documentar configurações seguras recomendadas",
            ],
        }
        return recommendations.get(owasp_cat, [])

    def generate_json(self) -> str:
        """Gera relatório em formato JSON."""
        print("[*] Gerando relatório JSON")

        owasp_categories = self.categorize_owasp_iot()
        severity = self.calculate_severity()

        report = {
            "metadata": {
                "generated_at": self.timestamp,
                "tool": "Ferramenta de Detecção de Vulnerabilidades em Dispositivos IoT",
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

        print(f"[+] Relatório JSON: {filepath}")
        return filepath

    def generate_html(self) -> str:
        """Gera relatório em formato HTML."""
        print("[*] Gerando relatório HTML")

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

        risk_class = f"risk-{severity['risk_level'].replace('í', 'i').replace('é', 'e').replace('á', 'a')}"
        if severity["risk_level"] == "crítico":
            risk_class = "risk-critical"
        elif severity["risk_level"] == "alto":
            risk_class = "risk-high"
        elif severity["risk_level"] == "médio":
            risk_class = "risk-medium"
        else:
            risk_class = "risk-low"

        html = f"""<!DOCTYPE html>
<html lang="pt-BR">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Relatório de Segurança IoT</title>
    {css}
</head>
<body>
    <div class="container">
        <h1>Relatório de Segurança IoT</h1>
        <p class="timestamp">Gerado em: {self.timestamp}</p>

        <h2>Resumo Executivo</h2>
        <div class="summary">
            <div class="summary-card">
                <div class="count">{severity['total_vulnerabilities']}</div>
                <div>Vulnerabilidades</div>
            </div>
            <div class="summary-card">
                <div class="count {risk_class}">{severity['risk_level'].upper()}</div>
                <div>Nível de Risco</div>
            </div>
            <div class="summary-card critical">
                <div class="count">{severity['counts']['critical']}</div>
                <div>Críticas</div>
            </div>
            <div class="summary-card high">
                <div class="count">{severity['counts']['high']}</div>
                <div>Altas</div>
            </div>
            <div class="summary-card medium">
                <div class="count">{severity['counts']['medium']}</div>
                <div>Médias</div>
            </div>
            <div class="summary-card low">
                <div class="count">{severity['counts']['low']}</div>
                <div>Baixas</div>
            </div>
        </div>

        <h2>Categorização OWASP IoT Top 10</h2>
"""

        # Adiciona cada categoria OWASP
        for cat_id in sorted(OWASP_IOT_TOP10.keys()):
            cat_info = OWASP_IOT_TOP10[cat_id]
            vulns = owasp_categories.get(cat_id, [])
            count_class = "zero" if len(vulns) == 0 else ""

            html += f"""
        <div class="category">
            <div class="category-header">
                <h3>{cat_id}: {cat_info['name']}</h3>
                <span class="category-count {count_class}">{len(vulns)}</span>
            </div>
            <p>{cat_info['description']}</p>
"""

            if vulns:
                html += '<div class="vuln-list">'
                for vuln in vulns[:10]:
                    sev = vuln.get("severity", "unknown")
                    html += f"""
                <div class="vuln-item {sev}">
                    <strong>{vuln.get('type', 'N/A')}</strong>
                    <span class="severity-badge {sev}">{sev.upper()}</span>
                    <p>{vuln.get('description', 'Sem descrição')}</p>
                </div>
"""
                if len(vulns) > 10:
                    html += (
                        f"<p><em>... e mais {len(vulns) - 10} vulnerabilidades</em></p>"
                    )
                html += "</div>"

                recommendations = self._get_recommendations(cat_id)
                if recommendations:
                    html += '<div class="recommendations"><strong>Recomendações:</strong><ul>'
                    for rec in recommendations:
                        html += f"<li>{rec}</li>"
                    html += "</ul></div>"

            html += "</div>"

        html += """
        <h2>Lista Completa de Vulnerabilidades</h2>
        <table>
            <thead>
                <tr>
                    <th>Tipo</th>
                    <th>Severidade</th>
                    <th>Fonte</th>
                    <th>Descrição</th>
                </tr>
            </thead>
            <tbody>
"""

        for vuln in self.vulnerabilities:
            sev = vuln.get("severity", "unknown")
            html += f"""
                <tr>
                    <td>{vuln.get('type', 'N/A')}</td>
                    <td><span class="severity-badge {sev}">{sev.upper()}</span></td>
                    <td>{vuln.get('source', 'N/A')}</td>
                    <td>{vuln.get('description', 'N/A')[:100]}...</td>
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

        print(f"[+] Relatório HTML: {filepath}")
        return filepath

    def generate(self) -> Dict[str, str]:
        """Gera relatórios em todos os formatos."""
        return {
            "json": self.generate_json(),
            "html": self.generate_html(),
        }
