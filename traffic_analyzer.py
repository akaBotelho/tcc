import base64
import os
import socket
from collections import Counter
from typing import Dict, List, Optional

import pyshark

from utils import (
    CONFIG_EXTENSIONS,
    CREDENTIAL_EXTENSIONS,
    DB_EXTENSIONS,
    FIRMWARE_EXTENSIONS,
    MIME_MAP,
    load_env,
    save_results,
)


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
        """Loads PCAP for analysis."""
        if self.pcap_file is None:
            print("[!] No pcap_file defined")
            return

        if not os.path.exists(self.pcap_file):
            print(f"[!] File not found: {self.pcap_file}")
            return

        try:
            self.cap = pyshark.FileCapture(self.pcap_file, keep_packets=True)
            print(f"[+] PCAP loaded: {self.pcap_file}")
        except Exception as e:
            print(f"[!] Error loading PCAP: {e}")
            self.cap = None

    def _resolve_hostname(self, ip: str) -> str:
        """Resolves IP to hostname with cache."""
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
        """Classifies file by extension."""
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
        self,
        interface: str = None,
        output_file: str = None,
        ip_filter: str = None,
        output_dir: str = None,
    ):
        """Captures packets in real time."""
        if self.cap:
            print("[*] PCAP already loaded, skipping live capture")
            return

        interface = interface or self.env["DEFAULT_INTERFACE"]
        timeout = self.env["CAPTURE_TIMEOUT"]
        base_output = output_dir or os.path.join(self.env["OUTPUT_DIR"], ip_filter)
        os.makedirs(base_output, exist_ok=True)
        output_file = os.path.join(
            base_output, output_file or f"capture_{ip_filter}.pcap"
        )

        bpf_filter = f"host {ip_filter}" if ip_filter else None

        print(f"[*] Capturing on {interface} for {timeout}s")
        if bpf_filter:
            print(f"[+] Filter: {bpf_filter}")

        live_cap = pyshark.LiveCapture(
            interface=interface, output_file=output_file, bpf_filter=bpf_filter
        )

        try:
            live_cap.sniff(timeout=timeout)
        except KeyboardInterrupt:
            print("[!] Capture interrupted")

        print(f"[+] Saved to: {output_file}")
        self.pcap_file = output_file
        self._load_pcap()

    def list_endpoints(self) -> List[Dict]:
        """Lists endpoints with packet count."""
        if self.cap is None:
            print("[-] No PCAP loaded")
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

        print(f"[+] {len(results)} endpoints found")
        return results

    def list_destinations_ports(self) -> List[Dict]:
        """Lists destinations and ports with count."""
        if self.cap is None:
            print("[-] No PCAP loaded")
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

        print(f"[+] {len(results)} destinations found")
        return results

    def protocol_hierarchy(self) -> List[Dict]:
        """Returns protocol hierarchy."""
        if self.cap is None:
            print("[-] No PCAP loaded")
            return []

        hierarchy = Counter()
        for pkt in self.cap:
            for layer in pkt.layers:
                hierarchy[layer.layer_name] += 1

        results = [
            {"protocol": proto, "count": count}
            for proto, count in hierarchy.most_common()
        ]
        print(f"[+] {len(results)} protocols identified")
        return results

    def export_http_objects(self, output_folder: str) -> List[Dict]:
        """Exports HTTP objects and detects sensitive files."""
        if self.pcap_file is None:
            print("[-] No PCAP defined")
            return []

        print(f"[*] Exporting HTTP objects to {output_folder}")
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
                            "description": f"{file_type} file transferred via HTTP (unencrypted)",
                            "file": filename,
                            "owasp_iot": "I7",
                        }
                    )
            except:
                pass

        http_cap.close()
        print(f"[+] {len(exported)} objects exported")
        return exported

    def extract_http_fields(self) -> List[Dict]:
        """Extracts HTTP fields and detects cleartext credentials."""
        if self.pcap_file is None:
            print("[-] No PCAP defined")
            return []

        print("[*] Extracting HTTP fields")
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
                        "description": "HTTP Authorization credentials in cleartext",
                        "uri": entry["uri"],
                        "host": entry["host"],
                        "owasp_iot": "I7",
                    }
                )

        http_cap.close()
        print(f"[+] {len(results)} HTTP requests extracted")
        return results

    def get_security_findings(self) -> List[Dict]:
        """Returns security findings for vulnerability_detection."""
        return self.security_findings

    def analyze(self, target: str = None, output_folder: str = None) -> Dict:
        """Runs all traffic analyses."""
        print("[*] Starting traffic analysis")

        if not output_folder:
            output_folder = os.path.join(self.env["OUTPUT_DIR"], target)
        os.makedirs(output_folder, exist_ok=True)

        if self.cap is None:
            self.capture_live(ip_filter=target, output_dir=output_folder)

        if self.cap is None:
            print("[-] Failed to obtain traffic for analysis")
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
            f"[+] Analysis complete: {len(results['security_findings'])} vulnerabilities found"
        )
        return results


def main():
    target_ip = "192.168.0.111"
    analyzer = TrafficAnalyzer()
    output_dir = os.path.join(analyzer.env["OUTPUT_DIR"], target_ip)
    results = analyzer.analyze(target=target_ip, output_folder=output_dir)


if __name__ == "__main__":
    main()
