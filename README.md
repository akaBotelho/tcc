# IoT Vulnerability Detection Tool

A comprehensive security assessment toolkit for identifying vulnerabilities in IoT devices. It automates the process of network discovery, port scanning, traffic analysis, web vulnerability scanning, firmware analysis, and credential testing, generating detailed reports categorized by the [OWASP IoT Top 10](https://owasp.org/www-project-internet-of-things/).

## Features

- **Network Discovery & Port Scanning** -- Discovers active hosts on the network and performs detailed Nmap scans to identify open ports, running services, and OS fingerprinting.
- **Web Application Scanning** -- Integrates with OWASP ZAP (Spider, Ajax Spider, Active Scan) and WhatWeb for web interface fingerprinting and vulnerability detection.
- **Traffic Analysis** -- Captures and analyzes network traffic (live or from PCAP files) to identify endpoints, protocols, HTTP objects, and cleartext credentials.
- **Firmware Analysis** -- Extracts and inspects firmware images using Binwalk, searching for hardcoded credentials, exposed certificates/keys, password hashes, configuration files, and databases.
- **Credential Testing** -- Performs brute force attacks using Hydra against discovered services (SSH, FTP, Telnet), testing vendor default credentials and cracked password hashes.
- **Password Cracking** -- Cracks password hashes extracted from firmware using John the Ripper.
- **CVE Lookup** -- Queries the NVD (National Vulnerability Database) API to find known CVEs for detected services and versions.
- **Report Generation** -- Produces detailed security reports in JSON and HTML formats, with vulnerabilities categorized by the OWASP IoT Top 10 framework, severity distribution, and mitigation recommendations.

## Architecture

```
main.py                      # CLI entry point with interactive target selection
information_gathering.py     # Network discovery (netdiscover) and port scanning (Nmap/WhatWeb)
traffic_analyzer.py          # Network traffic capture and analysis (pyshark)
vulnerability_detection.py   # ZAP scanning, firmware analysis, brute force, CVE lookup
report_generator.py          # JSON and HTML report generation with OWASP IoT Top 10 mapping
utils.py                     # Constants, helpers, and shared utilities
```

## Prerequisites

### System Tools

The following tools must be installed and available in your `PATH`:

| Tool                                                  | Purpose                                       |
| ----------------------------------------------------- | --------------------------------------------- |
| [Nmap](https://nmap.org/)                             | Network scanning and service detection        |
| [OWASP ZAP](https://www.zaproxy.org/)                 | Web application vulnerability scanning        |
| [WhatWeb](https://github.com/urbanadventurer/WhatWeb) | Web application fingerprinting                |
| [Hydra](https://github.com/vanhauser-thc/thc-hydra)   | Credential brute forcing                      |
| [John the Ripper](https://www.openwall.com/john/)     | Password hash cracking                        |
| [Binwalk](https://github.com/ReFirmLabs/binwalk)      | Firmware extraction and analysis              |
| [tshark](https://www.wireshark.org/)                  | Network traffic capture (required by pyshark) |

### Wordlists

This tool uses [SecLists](https://github.com/danielmiessler/SecLists) for password and username wordlists:

```bash
git clone https://github.com/danielmiessler/SecLists.git /usr/share/seclists
```

## Setup

1. **Install Python dependencies:**

   ```bash
   pip install -r requirements.txt
   ```

2. **Configure environment variables:**

   ```bash
   cp .env.example .env
   ```

   Edit the `.env` file with your settings. Key configurations:
   - `ZAP_API_KEY` -- Your OWASP ZAP API key
   - `NVD_API_KEY` -- NVD API key ([request one here](https://nvd.nist.gov/developers/request-an-api-key))
   - `WORDLIST_PATH` -- Path to SecLists directory
   - `DEFAULT_INTERFACE` -- Network interface for live capture
   - `FIRMWARE_PATH` -- (Optional) Path to a firmware image file

3. **Run (requires root privileges):**

   ```bash
   sudo python3 main.py [IP_RANGE]
   ```

   The default IP range is `192.168.0.1/24` if not specified.

## Usage

1. The tool starts by discovering active hosts on the network.
2. An interactive menu lets you select the target device.
3. After confirmation, it runs the full analysis pipeline:
   - **Step 1:** Information gathering (Nmap + WhatWeb)
   - **Step 2:** Traffic analysis (live capture or PCAP)
   - **Step 3:** Vulnerability detection (ZAP, firmware analysis, brute force, CVE lookup)
   - **Step 4:** Report generation (JSON + HTML)
4. Results are saved to `./output/<target_ip>/`.

## Output

Reports are generated in the `output/<target_ip>/` directory:

| File                        | Description                                                       |
| --------------------------- | ----------------------------------------------------------------- |
| `security_report.json`      | Full report with all findings, raw data, and OWASP categorization |
| `security_report.html`      | Visual HTML report with executive summary and severity breakdown  |
| `01_nmap_scan.json`         | Nmap scan results                                                 |
| `02_web_scan.json`          | WhatWeb scan results                                              |
| `03_zap_scan.json`          | OWASP ZAP scan results                                            |
| `04_firmware_analysis.json` | Firmware analysis findings                                        |
| `05_cracked_hashes.json`    | Cracked password hashes                                           |
| `06_brute_force.json`       | Brute force results                                               |
| `07_cve_lookup.json`        | CVE lookup results                                                |

## OWASP IoT Top 10 Coverage

The tool maps findings to the following OWASP IoT Top 10 categories:

| ID  | Category                           | Detection Method                                           |
| --- | ---------------------------------- | ---------------------------------------------------------- |
| I1  | Weak/Hardcoded Passwords           | Firmware analysis, brute force, default credential testing |
| I2  | Insecure Network Services          | Nmap (Telnet, FTP detection)                               |
| I3  | Insecure Ecosystem Interfaces      | OWASP ZAP web scanning                                     |
| I5  | Insecure/Outdated Components       | NVD CVE lookup                                             |
| I7  | Insecure Data Transfer and Storage | Traffic analysis, firmware certificate/key inspection      |

## License

This project was developed as an academic capstone project.
