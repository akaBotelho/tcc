import contextlib
import io
import json
import os
import re
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from dotenv import load_dotenv

# Constantes
FIRMWARE_EXTENSIONS = [".bin", ".img", ".fw", ".hex"]
CONFIG_EXTENSIONS = [".ini", ".conf", ".xml", ".json", ".yaml"]
DB_EXTENSIONS = [".db", ".sqlite", ".sql"]
CREDENTIAL_EXTENSIONS = [".pem", ".crt", ".key", ".p12", ".pfx", ".jks"]
CREDENTIAL_PATTERNS = ["password", "passwd", "secret", "api_key", "token", "credential"]
BRUTE_FORCE_SERVICES = ["ssh", "ftp", "telnet"]

MIME_MAP = {
    # PDF
    "application/pdf": ".pdf",
    "application/x-pdf": ".pdf",
    # BZIP
    "application/bz2": ".bz2",
    "application/bzip2": ".bz2",
    "application/x-bz2": ".bz2",
    "application/x-bzip": ".bz2",
    "application/x-bzip2": ".bz2",
    # GZIP
    "application/gzip": ".gz",
    "application/x-gzip": ".gz",
    "application/x-gzip-compressed": ".gz",
    "application/x-tgz": ".tgz",
    # RAR
    "application/rar": ".rar",
    "application/x-rar": ".rar",
    "application/x-rar-compressed": ".rar",
    # RPM
    "application/x-redhat-package-manager": ".rpm",
    "application/x-rpm": ".rpm",
    # ZIP
    "application/zip": ".zip",
    "application/x-zip": ".zip",
    "application/x-zip-compressed": ".zip",
    "application/vnd.ms-cab-compressed": ".cab",
    "application/x-7z-compressed": ".7z",
    "application/epub+zip": ".epub",
    "application/x-cab": ".cab",
    "application/x-cab-compressed": ".cab",
    # Binaries
    "application/octet-stream": ".bin",
    "application/bin": ".bin",
    "application/binary": ".bin",
    "application/octetstring": ".bin",
    "application/self-extracting": ".bin",
    "application/x-binary": ".bin",
    "application/x-download": ".bin",
    "application/x-octet-stream": ".bin",
    "application/x-octetstream": ".bin",
    "binary/octet-stream": ".bin",
    "applicatin-octet-stream": ".bin",
    "application/octect-stream": ".bin",
    "application/octest-stream": ".bin",
    # XML
    "text/xml": ".xml",
    "application/xml": ".xml",
    # CGI / Code
    "application/cgi": ".cgi",
    "application/x-cgi": ".cgi",
    "text/x-c++": ".cpp",
    "text/x-c++src": ".cpp",
    "text/html": ".html",
    # PHP
    "application/x-httpd-php": ".php",
    "application/x-httpd-php-source": ".phps",
    "application/x-httpd-php3": ".php3",
    "application/x-httpd-php3-preprocessed": ".php3",
    "application/x-httpd-php4": ".php4",
    "application/x-php": ".php",
    # Configurations
    "application/isf.sharing.config": ".conf",
    "application/vnd.centra.client.configuration": ".conf",
    # DEB
    "application/vnd.debian.binary-package": ".deb",
    "application/x-deb": ".deb",
    "application/x-debian-package": ".deb",
    # E-mail
    "application/email": ".eml",
    "application/x-email": ".eml",
    "message/rfc822": ".eml",
    # Images
    "image/bmp": ".bmp",
    "image/x-bmp": ".bmp",
    "image/x-win-bitmap": ".bmp",
    "image/gif": ".gif",
    "image/jpeg": ".jpg",
    "image/jpg": ".jpg",
    "image/png": ".png",
    "image/x-png": ".png",
    # JAR
    "application/jar": ".jar",
    "application/java-archive": ".jar",
    "application/x-jar": ".jar",
    "application/x-java-archive": ".jar",
    # JS
    "application/javascript": ".js",
    "application/x-javascript": ".js",
    "text/javascript": ".js",
    "text/x-javascript": ".js",
    "text/x-js": ".js",
    # Video / Audio
    "video/x-msvideo": ".avi",
    "video/mp4": ".mp4",
    "audio/wav": ".wav",
    "audio/mpeg": ".mp3",
    "audio/x-wav": ".wav",
    "video/x-flv": ".flv",
    "application/x-flv": ".flv",
    # MS Office (legacy)
    "application/msword": ".doc",
    "application/vnd.ms-word": ".doc",
    "application/vnd.ms-powerpoint": ".ppt",
    "application/vnd.ms-excel": ".xls",
    "application/msexcel": ".xls",
    # MS Office (modern)
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document": ".docx",
    "application/vnd.openxmlformats-officedocument.presentationml.presentation": ".pptx",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet": ".xlsx",
    # RTF
    "application/rtf": ".rtf",
    "text/rtf": ".rtf",
    # WordPerfect
    "application/vnd.wordperfect": ".wpd",
    # Executables
    "application/exe": ".exe",
    "application/x-exe": ".exe",
    "application/x-msdownload": ".exe",
    "application/x-dosexec": ".exe",
}

# OWASP IoT Top 10 Categories
OWASP_IOT_TOP10 = {
    "I1": {
        "name": "Weak/Hardcoded Passwords",
        "description": "Use of weak, hardcoded, or publicly available credentials",
    },
    "I2": {
        "name": "Insecure Network Services",
        "description": "Unnecessary or insecure network services exposed",
    },
    "I3": {
        "name": "Insecure Ecosystem Interfaces",
        "description": "Insecure web, mobile, or API interfaces",
    },
    "I4": {
        "name": "Lack of Secure Update Mechanism",
        "description": "Lack of secure firmware update mechanism",
    },
    "I5": {
        "name": "Insecure/Outdated Components",
        "description": "Use of outdated or insecure software components",
    },
    "I6": {
        "name": "Insufficient Privacy Protection",
        "description": "User data collected/stored insecurely",
    },
    "I7": {
        "name": "Insecure Data Transfer and Storage",
        "description": "Lack of encryption for data in transit or at rest",
    },
    "I8": {
        "name": "Lack of Device Management",
        "description": "Lack of support for secure device management",
    },
    "I9": {
        "name": "Insecure Default Settings",
        "description": "Devices with insecure default settings",
    },
    "I10": {
        "name": "Lack of Physical Hardening",
        "description": "Lack of physical protection measures (out of scope)",
    },
}

# Vulnerability type to OWASP IoT mapping
VULN_TO_OWASP = {
    # I1: Weak/Hardcoded Passwords
    "hardcoded_credentials": "I1",
    "default_credentials": "I1",
    "brute_force_success": "I1",
    "cracked_password": "I1",
    # I2: Insecure Network Services
    "telnet_enabled": "I2",
    "ftp_enabled": "I2",
    # I3: Insecure Ecosystem Interfaces
    "web_vulnerability": "I3",
    # I5: Insecure/Outdated Components
    "known_cve": "I5",
    # I7: Insecure Data Transfer and Storage
    "cleartext_credentials": "I7",
    "insecure_transfer": "I7",
    "exposed_certificate": "I7",
    "exposed_private_key": "I7",
    "exposed_hash": "I7",
}

# ZAP alert to OWASP IoT mapping
ZAP_ALERT_TO_OWASP = {
    "Cross Site Scripting": "I3",
    "XSS": "I3",
    "SQL Injection": "I3",
    "Command Injection": "I3",
    "Path Traversal": "I3",
    "Remote File Inclusion": "I3",
    "CSRF": "I3",
    "Authentication": "I1",
    "Session": "I3",
    "Information Disclosure": "I6",
    "Cookie": "I3",
    "SSL": "I7",
    "TLS": "I7",
    "Certificate": "I7",
    "Encryption": "I7",
    "X-Frame-Options": "I3",
    "Content-Security-Policy": "I3",
    "X-Content-Type-Options": "I3",
}


@contextlib.contextmanager
def suppress_stderr():
    """Context manager to suppress stderr output."""
    stderr = sys.stderr
    sys.stderr = io.StringIO()
    try:
        yield
    finally:
        sys.stderr = stderr


def load_env() -> Dict[str, str]:
    """Loads settings from .env file."""
    load_dotenv()
    return {
        "ZAP_API_KEY": os.getenv("ZAP_API_KEY", ""),
        "ZAP_HOST": os.getenv("ZAP_HOST", "127.0.0.1"),
        "ZAP_PORT": int(os.getenv("ZAP_PORT", "8090")),
        "NVD_API_KEY": os.getenv("NVD_API_KEY", ""),
        "DEFAULT_INTERFACE": os.getenv("DEFAULT_INTERFACE", "eth0"),
        "CAPTURE_TIMEOUT": int(os.getenv("CAPTURE_TIMEOUT", "600")),
        "WORDLIST_PATH": os.getenv("WORDLIST_PATH", "/usr/share/seclists"),
        "WORDLIST_PASSWORDS": os.getenv(
            "WORDLIST_PASSWORDS",
            "Passwords/Common-Credentials/10-million-password-list-top-10000.txt",
        ),
        "WORDLIST_USERS": os.getenv(
            "WORDLIST_USERS", "Usernames/top-usernames-shortlist.txt"
        ),
        "WORDLIST_DEFAULT_CREDS": os.getenv(
            "WORDLIST_DEFAULT_CREDS",
            "Passwords/Default-Credentials/default-passwords.csv",
        ),
        "OUTPUT_DIR": os.getenv("OUTPUT_DIR", "./output"),
        "FIRMWARE_PATH": os.getenv("FIRMWARE_PATH", ""),
    }


def parse_passwd_file(content: str) -> List[Dict]:
    """Parses /etc/passwd content and returns user list."""
    users = []
    for line in content.strip().split("\n"):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 7:
            users.append(
                {
                    "username": parts[0],
                    "password_hash": parts[1],
                    "uid": parts[2],
                    "gid": parts[3],
                    "info": parts[4],
                    "home": parts[5],
                    "shell": parts[6],
                }
            )
    return users


def parse_shadow_file(content: str) -> List[Dict]:
    """Parses /etc/shadow content and returns hash list."""
    hashes = []
    for line in content.strip().split("\n"):
        if not line or line.startswith("#"):
            continue
        parts = line.split(":")
        if len(parts) >= 2 and parts[1] and parts[1] not in ["*", "!", "!!", "x"]:
            hashes.append(
                {
                    "username": parts[0],
                    "hash": parts[1],
                    "last_change": parts[2] if len(parts) > 2 else "",
                }
            )
    return hashes


def search_patterns(
    path: str, patterns: List[str], extensions: Optional[List[str]] = None
) -> List[Dict]:
    """Searches for patterns in files within a directory, grouped by file."""
    files_with_matches = {}
    path_obj = Path(path)

    if not path_obj.exists():
        return []

    compiled = [re.compile(p, re.IGNORECASE) for p in patterns]

    for file_path in path_obj.rglob("*"):
        if not file_path.is_file():
            continue

        if extensions and file_path.suffix.lower() not in extensions:
            continue

        try:
            content = file_path.read_text(errors="ignore")
            file_matches = []

            for i, line in enumerate(content.split("\n"), 1):
                for pattern in compiled:
                    if pattern.search(line):
                        file_matches.append(
                            {
                                "line_number": i,
                                "content": line.strip()[:200],
                                "pattern": pattern.pattern,
                            }
                        )
                        break

            if file_matches:
                files_with_matches[str(file_path)] = file_matches

        except Exception:
            continue

    return [
        {"file": file_path, "matches": matches}
        for file_path, matches in files_with_matches.items()
    ]


def load_default_credentials(csv_path: str) -> Dict[str, List[str]]:
    """Loads default credentials from CSV grouped by vendor."""
    credentials_by_vendor = {}

    if not os.path.exists(csv_path):
        print(f"[-] File not found: {csv_path}")
        return {}

    try:
        with open(csv_path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()

                if not line or line.startswith("#") or line.startswith("Vendor,"):
                    continue

                parts = line.split(",")
                if len(parts) >= 3:
                    vendor = parts[0].strip().lower()
                    username = parts[1].strip()
                    password = parts[2].strip()

                    credential = f"{username}:{password}"

                    if vendor not in credentials_by_vendor:
                        credentials_by_vendor[vendor] = []
                    credentials_by_vendor[vendor].append(credential)

        print("[+] Default credentials loaded")
    except Exception as e:
        print(f"[-] Error loading default credentials: {e}")
        return {}

    return credentials_by_vendor


def get_credentials_for_vendor(
    credentials_by_vendor: Dict[str, List[str]], vendor: str
) -> List[str]:
    """Returns credentials for a specific vendor."""
    if not vendor:
        return []

    vendor_lower = vendor.lower()

    if vendor_lower in credentials_by_vendor:
        return credentials_by_vendor[vendor_lower]

    for key in credentials_by_vendor.keys():
        if key in vendor_lower or vendor_lower in key:
            return credentials_by_vendor[key]

    return []


def save_results(output_dir: str, prefix: str, name: str, data: Any) -> str:
    """Saves results to JSON file."""
    os.makedirs(output_dir, exist_ok=True)
    filepath = os.path.join(output_dir, f"{prefix}_{name}.json")
    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    print(f"[+] Saved: {filepath}")
    return filepath
