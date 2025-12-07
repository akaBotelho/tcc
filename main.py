#!/usr/bin/env python3

import os
import sys
from typing import Dict, List, Optional

from simple_term_menu import TerminalMenu

from information_gathering import InformationGathering
from report_generator import ReportGenerator
from traffic_analyzer import TrafficAnalyzer
from utils import load_env, save_results
from vulnerability_detection import VulnerabilityDetection


def clear_screen():
    """Limpa a tela do terminal."""
    os.system("cls" if os.name == "nt" else "clear")


def print_banner():
    """Exibe o banner da ferramenta."""
    banner = """
╔══════════════════════════════════════════════════════════════╗
║        Ferramenta de Detecção de Vulnerabilidades IoT        ║
╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)


def select_target(hosts: List[Dict]) -> Optional[Dict]:
    """Exibe menu interativo para seleção do alvo."""
    if not hosts:
        print("[-] Nenhum host encontrado na rede")
        return None

    options = []
    for host in hosts:
        ip = host.get("ip", "N/A")
        mac = host.get("mac", "N/A")
        vendor = host.get("vendor", "Desconhecido")
        options.append(f"{ip:<16} │ {mac:<18} │ {vendor}")

    header = f"{'IP':<16} │ {'MAC':<18} │ {'Fabricante'}"
    separator = "─" * 65

    print(f"\n{header}")
    print(separator)

    menu = TerminalMenu(
        options,
        title="\n[↑/↓] Selecione o alvo │ [Enter] Confirmar │ [q] Sair\n",
        menu_cursor="▶ ",
        menu_cursor_style=("fg_green", "bold"),
        menu_highlight_style=("fg_green", "bold"),
    )

    idx = menu.show()

    if idx is None:
        return None

    return hosts[idx]


def confirm_action(message: str) -> bool:
    """Confirmação simples de ação."""
    options = ["Sim", "Não"]
    menu = TerminalMenu(
        options,
        title=f"\n{message}\n",
        menu_cursor="▶ ",
        menu_cursor_style=("fg_yellow", "bold"),
    )
    return menu.show() == 0


def run_pipeline(target_ip: str, env: Dict):
    """Executa o pipeline completo."""
    output_dir = os.path.join(env["OUTPUT_DIR"], target_ip)
    os.makedirs(output_dir, exist_ok=True)

    all_results = {}

    print("\n" + "=" * 65)
    print("ETAPA 1: Coleta de Informações")
    print("=" * 65)

    gatherer = InformationGathering(target_ip)

    nmap_results = gatherer.nmap_scan()
    save_results(output_dir, "01", "nmap_scan", nmap_results)
    all_results["information_gathering"] = nmap_results

    if gatherer.has_web_interface:
        web_results = gatherer.web_scan(output_dir=output_dir)
        save_results(output_dir, "02", "web_scan", web_results)
        all_results["web_scan"] = web_results

    print("\n" + "=" * 65)
    print("ETAPA 2: Análise de Tráfego")
    print("=" * 65)

    print(f"[*] Captura ao vivo para {target_ip}")
    print("[!] Pressione Ctrl+C para interromper a captura")

    analyzer = TrafficAnalyzer()
    traffic_results = analyzer.analyze(target=target_ip, output_folder=output_dir)

    if traffic_results:
        all_results["traffic_analyzer"] = traffic_results

    print("\n" + "=" * 65)
    print("ETAPA 3: Detecção de Vulnerabilidades")
    print("=" * 65)

    vuln_detector = VulnerabilityDetection()
    vuln_results = vuln_detector.analyze(
        target=target_ip,
        scan_results=nmap_results,
        output_dir=output_dir,
        http_objects=traffic_results.get("http_objects", []) if traffic_results else [],
    )
    all_results["vulnerability_detection"] = vuln_results

    print("\n" + "=" * 65)
    print("ETAPA 4: Geração de Relatório")
    print("=" * 65)

    report_gen = ReportGenerator(output_dir)

    if "information_gathering" in all_results:
        report_gen.add_scan_results(
            "information_gathering", all_results["information_gathering"]
        )

    if "traffic_analyzer" in all_results:
        report_gen.add_scan_results("traffic_analyzer", all_results["traffic_analyzer"])

    if "vulnerability_detection" in all_results:
        report_gen.add_scan_results(
            "vulnerability_detection", all_results["vulnerability_detection"]
        )

    report_paths = report_gen.generate()

    print("\n" + "=" * 65)
    print("RESUMO")
    print("=" * 65)

    severity = report_gen.calculate_severity()

    print(f"\n[+] Alvo analisado: {target_ip}")
    print(f"[+] Total de vulnerabilidades: {severity['total_vulnerabilities']}")
    print(f"[+] Nível de risco: {severity['risk_level'].upper()}")
    print(f"\n    Críticas: {severity['counts']['critical']}")
    print(f"    Altas:    {severity['counts']['high']}")
    print(f"    Médias:   {severity['counts']['medium']}")
    print(f"    Baixas:   {severity['counts']['low']}")
    print(f"\n[+] Relatórios gerados em: {output_dir}/")
    print(f"    - JSON: {report_paths['json']}")
    print(f"    - HTML: {report_paths['html']}")


def main():
    clear_screen()
    print_banner()

    env = load_env()

    ip_range = sys.argv[1] if len(sys.argv) > 1 else "192.168.0.1/24"

    print("[*] Iniciando descoberta de rede...")

    gatherer = InformationGathering(None)
    hosts = gatherer.network_discovery(ip_range)

    if not hosts:
        print("[-] Nenhum host encontrado na rede")
        print("[!] Verifique o range de IP ou suas permissões de rede")
        sys.exit(1)

    target = select_target(hosts)

    if not target:
        print("[-] Nenhum alvo selecionado. Encerrando.")
        sys.exit(0)

    target_ip = target["ip"]
    print(f"\n[+] Alvo selecionado: {target_ip}")
    print(f"[+] Output: {env['OUTPUT_DIR']}/{target_ip}/")

    if not confirm_action("[?] Iniciar análise?"):
        print("[-] Operação cancelada pelo usuário")
        sys.exit(0)

    try:
        run_pipeline(target_ip, env)
    except KeyboardInterrupt:
        print("\n\n[!] Operação interrompida pelo usuário")
        sys.exit(1)
    except Exception as e:
        print(f"\n[-] Erro durante execução: {e}")
        sys.exit(1)

    print("\n[+] Análise concluída com sucesso!")


if __name__ == "__main__":
    main()
