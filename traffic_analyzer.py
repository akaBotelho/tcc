import base64
import os
import socket
from collections import Counter
from typing import Dict, List, Optional

import pyshark

from utils import (CONFIG_EXTENSIONS, CREDENTIAL_EXTENSIONS, DB_EXTENSIONS,
                   FIRMWARE_EXTENSIONS, MIME_MAP, load_env, save_results)


class TrafficAnalyzer:
    def __init__(self, pcap_file: str = None):
        self.env = load_env()
        self.pcap_file = pcap_file
        self.cap = None
        self._dns_cache: Dict[str, str] = {}
        self.security_findings: List[Dict] = []

        if self.pcap_file and os.path.exists(self.pcap_file):
            self._load_pcap()

    def _load_pcap(self):
        """Carrega PCAP para análise."""
        if self.pcap_file is None:
            print("[!] Nenhum pcap_file definido")
            return

        if not os.path.exists(self.pcap_file):
            print(f"[!] Arquivo não encontrado: {self.pcap_file}")
            return

        try:
            self.cap = pyshark.FileCapture(self.pcap_file, keep_packets=True)
            print(f"[+] PCAP carregado: {self.pcap_file}")
        except Exception as e:
            print(f"[!] Erro ao carregar PCAP: {e}")
            self.cap = None

    def _resolve_hostname(self, ip: str) -> str:
        """Resolve IP para hostname com cache."""
        if ip in self._dns_cache:
            return self._dns_cache[ip]
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            self._dns_cache[ip] = hostname
            return hostname
        except:
            self._dns_cache[ip] = ip
            return ip

    def _classify_file(self, filename: str) -> Optional[str]:
        """Classifica arquivo por extensão."""
        ext = os.path.splitext(filename.lower())[1]
        if ext in FIRMWARE_EXTENSIONS:
            return "firmware"
        if ext in CONFIG_EXTENSIONS:
            return "config"
        if ext in CREDENTIAL_EXTENSIONS:
            return "credential"
        if ext in DB_EXTENSIONS:
            return "database"
        return None

    def capture_live(
        self, interface: str = None, output_file: str = None, ip_filter: str = None, output_dir: str = None
    ):
        """Captura pacotes em tempo real."""
        if self.cap:
            print("[*] PCAP já carregado, ignorando captura em tempo real")
            return

        interface = interface or self.env["DEFAULT_INTERFACE"]
        timeout = self.env["CAPTURE_TIMEOUT"]
        base_output = output_dir or os.path.join(self.env["OUTPUT_DIR"], ip_filter)
        os.makedirs(base_output, exist_ok=True)
        output_file = os.path.join(base_output, output_file or f"capture_{ip_filter}.pcap")

        bpf_filter = f"host {ip_filter}" if ip_filter else None

        print(f"[*] Capturando em {interface} por {timeout}s")
        if bpf_filter:
            print(f"[+] Filtro: {bpf_filter}")

        live_cap = pyshark.LiveCapture(
            interface=interface, output_file=output_file, bpf_filter=bpf_filter
        )

        try:
            live_cap.sniff(timeout=timeout)
        except KeyboardInterrupt:
            print("[!] Captura interrompida")

        print(f"[+] Salvo em: {output_file}")
        self.pcap_file = output_file
        self._load_pcap()

    def list_endpoints(self) -> List[Dict]:
        """Lista endpoints com contagem de pacotes."""
        if self.cap is None:
            print("[-] Nenhum PCAP carregado")
            return []

        endpoints = Counter()
        for pkt in self.cap:
            if "ip" in pkt:
                endpoints[pkt.ip.src] += 1
                endpoints[pkt.ip.dst] += 1

        results = []
        for ip, count in endpoints.most_common():
            results.append(
                {"ip": ip, "hostname": self._resolve_hostname(ip), "packets": count}
            )

        print(f"[+] {len(results)} endpoints encontrados")
        return results

    def list_destinations_ports(self) -> List[Dict]:
        """Lista destinos e portas com contagem."""
        if self.cap is None:
            print("[-] Nenhum PCAP carregado")
            return []

        dests = Counter()
        for pkt in self.cap:
            if "ip" not in pkt:
                continue
            ip_dst = pkt.ip.dst
            if "tcp" in pkt:
                port = pkt.tcp.dstport
                proto = "tcp"
            elif "udp" in pkt:
                port = pkt.udp.dstport
                proto = "udp"
            else:
                continue
            dests[(ip_dst, port, proto)] += 1

        results = []
        for (ip, port, proto), count in dests.most_common():
            results.append(
                {
                    "ip": ip,
                    "hostname": self._resolve_hostname(ip),
                    "port": port,
                    "protocol": proto,
                    "packets": count,
                }
            )

        print(f"[+] {len(results)} destinos encontrados")
        return results

    def protocol_hierarchy(self) -> List[Dict]:
        """Retorna hierarquia de protocolos."""
        if self.cap is None:
            print("[-] Nenhum PCAP carregado")
            return []

        hierarchy = Counter()
        for pkt in self.cap:
            for layer in pkt.layers:
                hierarchy[layer.layer_name] += 1

        results = [
            {"protocol": proto, "count": count}
            for proto, count in hierarchy.most_common()
        ]
        print(f"[+] {len(results)} protocolos identificados")
        return results

    def export_http_objects(self, output_folder: str) -> List[Dict]:
        """Exporta objetos HTTP e detecta arquivos sensíveis."""
        if self.pcap_file is None:
            print("[-] Nenhum PCAP definido")
            return []

        print(f"[*] Exportando objetos HTTP para {output_folder}")
        os.makedirs(output_folder, exist_ok=True)

        http_cap = pyshark.FileCapture(self.pcap_file, display_filter="http")
        exported = []

        for pkt in http_cap:
            if not hasattr(pkt.http, "file_data"):
                continue
            try:
                content_type = (
                    getattr(pkt.http, "content_type", "").split(";")[0].strip().lower()
                )
                ext = MIME_MAP.get(content_type, None)

                if ext is None:
                    continue

                uri = getattr(pkt.http, "request_uri", "") or ""
                original_name = os.path.basename(uri.split("?")[0]) if uri else None

                raw = base64.b64decode(pkt.http.file_data)
                if original_name and "." in original_name:
                    filename = original_name
                else:
                    filename = f"object_{len(exported)}{ext}"

                filepath = os.path.join(output_folder, filename)

                with open(filepath, "wb") as f:
                    f.write(raw)

                file_type = self._classify_file(filename)
                entry = {
                    "filename": filename,
                    "path": filepath,
                    "size": len(raw),
                    "type": file_type,
                    "src_ip": pkt.ip.src if "ip" in pkt else None,
                    "dst_ip": pkt.ip.dst if "ip" in pkt else None,
                }
                exported.append(entry)

                if file_type:
                    self.security_findings.append(
                        {
                            "type": "insecure_transfer",
                            "description": f"Arquivo {file_type} transferido via HTTP (não criptografado)",
                            "file": filename,
                            "owasp_iot": "I7",
                        }
                    )
            except:
                pass

        http_cap.close()
        print(f"[+] {len(exported)} objetos exportados")
        return exported

    def extract_http_fields(self) -> List[Dict]:
        """Extrai campos HTTP e detecta credenciais em texto claro."""
        if self.pcap_file is None:
            print("[-] Nenhum PCAP definido")
            return []

        print("[*] Extraindo campos HTTP")
        http_cap = pyshark.FileCapture(self.pcap_file, display_filter="http")
        results = []

        for pkt in http_cap:
            try:
                http = pkt.http
            except:
                continue

            entry = {
                "uri": getattr(http, "request_uri", None),
                "method": getattr(http, "request_method", None),
                "host": getattr(http, "host", None),
                "authorization": getattr(http, "authorization", None),
                "cookie": getattr(http, "cookie", None),
                "content_type": getattr(http, "content_type", None),
                "src_ip": pkt.ip.src if "ip" in pkt else None,
                "dst_ip": pkt.ip.dst if "ip" in pkt else None,
            }
            results.append(entry)

            if entry["authorization"]:
                self.security_findings.append(
                    {
                        "type": "cleartext_credentials",
                        "description": "Credenciais HTTP Authorization em texto claro",
                        "uri": entry["uri"],
                        "host": entry["host"],
                        "owasp_iot": "I7",
                    }
                )

        http_cap.close()
        print(f"[+] {len(results)} requisições HTTP extraídas")
        return results

    def get_security_findings(self) -> List[Dict]:
        """Retorna descobertas de segurança para vulnerability_detection."""
        return self.security_findings

    def analyze(self, target: str = None, output_folder: str = None) -> Dict:
        """Executa todas as análises de tráfego."""
        print("[*] Iniciando análise de tráfego")

        if not output_folder:
            output_folder = os.path.join(self.env["OUTPUT_DIR"], target)
        os.makedirs(output_folder, exist_ok=True)

        if self.cap is None:
            self.capture_live(ip_filter=target, output_dir=output_folder)

        if self.cap is None:
            print("[-] Falha ao obter tráfego para análise")
            return {}

        http_objects_folder = os.path.join(output_folder, "http_objects")

        results = {
            "endpoints": self.list_endpoints(),
            "destinations": self.list_destinations_ports(),
            "protocols": self.protocol_hierarchy(),
            "http_objects": self.export_http_objects(http_objects_folder),
            "http_fields": self.extract_http_fields(),
            "security_findings": self.get_security_findings(),
        }

        save_results(output_folder, "traffic", "analysis", results)
        print(
            f"[+] Análise concluída: {len(results['security_findings'])} vulnerabilidades encontradas"
        )
        return results


def main():
    target_ip = "192.168.0.111"
    analyzer = TrafficAnalyzer()
    output_dir = os.path.join(analyzer.env["OUTPUT_DIR"], target_ip)
    results = analyzer.analyze(target=target_ip, output_folder=output_dir)


if __name__ == "__main__":
    main()
