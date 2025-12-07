import json
import os
import subprocess
import sys
import time
from typing import Dict, List, Optional

import nmap
from netdiscover import Discover

from utils import BRUTE_FORCE_SERVICES, load_env, save_results


class InformationGathering:
    def __init__(self, target: Optional[str]):
        self.env = load_env()
        self.target = target
        self.vendor = ""
        self.nd = Discover()
        self.nm = nmap.PortScanner()
        self.has_web_interface = False
        self.web_services = []
        self.brute_force_services = []

    def network_discovery(self, ip_range: str = "192.168.0.1/24") -> List[Dict]:
        """Descobre hosts ativos na rede."""
        print(f"[*] Descobrindo hosts em {ip_range}")
        try:
            hosts = self.nd.scan(ip_range=ip_range, output=["ip", "mac", "vendor"])
            print(f"[+] {len(hosts)} hosts encontrados")
            return hosts
        except Exception as e:
            print(f"[-] Erro na descoberta: {e}")
            return []

    def nmap_scan(self) -> Dict:
        """Realiza varredura de rede completa."""
        print(f"[*] Varredura nmap em {self.target}")
        start_time = time.time()

        try:
            self.nm.scan(self.target, arguments="-sS -sV -O -v")
        except Exception as e:
            print(f"[-] Erro no nmap: {e}")
            return {"duration": 0, "hosts": [], "vendor": self.vendor}

        scan_results = {
            "duration": time.time() - start_time,
            "hosts": [],
            "vendor": self.vendor,
        }

        for host in self.nm.all_hosts():
            host_info = {"ip": host, "ports": [], "os": [], "vendor": self.vendor}

            # Portas
            for proto in self.nm[host].all_protocols():
                for port in self.nm[host][proto].keys():
                    port_data = self.nm[host][proto][port]
                    if "open" in port_data["state"]:
                        service_name = port_data["name"].lower()
                        port_info = {
                            "port": f"{port}/{proto}",
                            "state": port_data["state"],
                            "service": port_data["name"],
                            "product": port_data.get("product", ""),
                            "version": port_data.get("version", ""),
                            "cpe": port_data.get("cpe", ""),
                        }
                        host_info["ports"].append(port_info)

                        # Detecta serviços web (http/https)
                        if "http" in service_name:
                            self.has_web_interface = True
                            protocol = (
                                "https"
                                if "https" in service_name or port == 443
                                else "http"
                            )
                            self.web_services.append(
                                {
                                    "port": port,
                                    "protocol": protocol,
                                    "service": port_data["name"],
                                    "product": port_data.get("product", ""),
                                    "version": port_data.get("version", ""),
                                    "cpe": port_data.get("cpe", ""),
                                }
                            )

                        # Detecta serviços para força bruta
                        if service_name in BRUTE_FORCE_SERVICES:
                            self.brute_force_services.append(
                                {
                                    "service": service_name,
                                    "port": port,
                                    "product": port_data.get("product", ""),
                                    "version": port_data.get("version", ""),
                                    "cpe": port_data.get("cpe", ""),
                                }
                            )

            # Detecção de SO
            os_vendor = ""
            if "osmatch" in self.nm[host]:
                for osmatch in self.nm[host]["osmatch"]:
                    if osmatch.get("osclass"):
                        for osclass in osmatch["osclass"]:
                            os_vendor = osclass.get("vendor", "")
                            os_info = {
                                "family": osclass.get("osfamily", ""),
                                "vendor": os_vendor,
                                "type": osclass.get("type", ""),
                                "cpe": osclass.get("cpe", []),
                            }
                            host_info["os"].append(os_info)

            # Usa fabricante do OS se não tiver fabricante do network_discovery
            if not host_info["vendor"] and os_vendor:
                host_info["vendor"] = os_vendor

            scan_results["hosts"].append(host_info)

        # Atualiza self.vendor se detectado pelo OS
        if not self.vendor and scan_results["hosts"]:
            for host in scan_results["hosts"]:
                if host.get("vendor"):
                    self.vendor = host["vendor"]
                    scan_results["vendor"] = self.vendor
                    break

        scan_results["has_web_interface"] = self.has_web_interface
        scan_results["web_services"] = self.web_services
        scan_results["brute_force_services"] = self.brute_force_services

        print(f"[+] Varredura concluída em {scan_results['duration']:.1f}s")
        return scan_results

    def web_scan(self, output_dir: str = None) -> List[Dict]:
        """Realiza varredura web com WhatWeb."""
        print(f"[*] Varredura web em {self.target}")

        if not output_dir:
            output_dir = os.path.join(self.env["OUTPUT_DIR"], self.target)
        os.makedirs(output_dir, exist_ok=True)

        filename = f"whatweb_{self.target}.json"
        filepath = os.path.join(output_dir, filename)
        try:
            command = [
                "whatweb",
                "-v",
                "-a",
                "3",
                self.target,
                f"--log-json-verbose={filepath}",
            ]
            result = subprocess.run(command, capture_output=True, text=True)

            if result.returncode == 0:
                json_data = []
                with open(filepath, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if line:
                            json_data.append(json.loads(line))

                return [{"type": "WebScan", "details": json_data}]
            else:
                print(f"[-] WhatWeb falhou: {result.stderr}")
        except Exception as e:
            print(f"[-] Erro no web_scan: {e}")

        return []


def main():
    ip_range = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1/24"

    gatherer = InformationGathering(None)
    hosts = gatherer.network_discovery(ip_range)

    if not hosts:
        print("[-] Nenhum host encontrado")
        return

    print("\n[*] Hosts disponíveis:")
    for i, host in enumerate(hosts):
        print(f"  [{i}] {host['ip']} - {host.get('vendor', 'N/A')}")

    try:
        idx = int(input("\n[?] Selecione o alvo (número): "))
        target_host = hosts[idx]
        target_ip = target_host["ip"]
        target_vendor = target_host.get("vendor", "")
    except (ValueError, IndexError):
        print("[-] Seleção inválida")
        return

    output_dir = os.path.join(gatherer.env["OUTPUT_DIR"], target_ip)
    print(f"\n[*] Alvo selecionado: {target_ip}")
    print(f"[*] Resultados serão salvos em: {output_dir}/")

    gatherer.target = target_ip
    gatherer.vendor = target_vendor

    results_nmap = gatherer.nmap_scan()
    save_results(output_dir, "01", "nmap_scan", results_nmap)

    results_ww = gatherer.web_scan(output_dir=output_dir)
    save_results(output_dir, "02", "web_scan", results_ww)

    print(f"\n[+] Coleta finalizada. Resultados em: {output_dir}/")


if __name__ == "__main__":
    main()
