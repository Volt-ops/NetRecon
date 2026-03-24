#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════╗
║                         N E T R E C O N                              ║
║              Network Security Enumeration Tool v1.0                  ║
║                                                                      ║
║  Author   : Aaryajith PS                                             ║
║  License  : MIT                                                      ║
║  GitHub   : https://github.com/aaryajithps/netrecon                 ║
║  Purpose  : Automated enumeration of FTP, SSH, HTTP, SMB services   ║
║                                                                      ║
║  LEGAL NOTICE: Use only on systems you own or have explicit          ║
║  written authorisation to test. Unauthorised use is illegal.         ║
╚══════════════════════════════════════════════════════════════════════╝
"""

import subprocess
import socket
import ftplib
import requests
import re
import sys
import os
import json
import argparse
from datetime import datetime

# ── Optional SSH support ──────────────────────────────────────────────
try:
    import paramiko
    SSH_AVAILABLE = True
except ImportError:
    SSH_AVAILABLE = False

# ── ANSI colour codes ─────────────────────────────────────────────────
class C:
    RED    = "\033[91m"
    GREEN  = "\033[92m"
    YELLOW = "\033[93m"
    BLUE   = "\033[94m"
    CYAN   = "\033[96m"
    WHITE  = "\033[97m"
    BOLD   = "\033[1m"
    DIM    = "\033[2m"
    RESET  = "\033[0m"

    @staticmethod
    def disable():
        for attr in ["RED","GREEN","YELLOW","BLUE","CYAN","WHITE","BOLD","DIM","RESET"]:
            setattr(C, attr, "")

# ── Global findings store ─────────────────────────────────────────────
findings: list = []

# ── Logging helpers ───────────────────────────────────────────────────
LEVEL_FMT = {
    "CRITICAL": (C.RED,    "🚨"),
    "HIGH":     (C.YELLOW, "⚠ "),
    "INFO":     (C.CYAN,   "ℹ "),
    "OK":       (C.GREEN,  "✔ "),
    "FAIL":     (C.RED,    "✖ "),
}

def log(level: str, service: str, message: str) -> None:
    color, icon = LEVEL_FMT.get(level, (C.WHITE, "·"))
    ts = datetime.now().strftime("%H:%M:%S")
    print(
        f"  {C.DIM}[{ts}]{C.RESET} "
        f"{color}{icon} [{level:<8}]{C.RESET} "
        f"{C.BOLD}{service:<6}{C.RESET} {message}"
    )
    findings.append({
        "level":   level,
        "service": service,
        "message": message,
        "time":    ts,
    })

def banner() -> None:
    print(f"""
{C.CYAN}{C.BOLD}
  ███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
  ████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
  ██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
  ██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
  ██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
  ╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{C.RESET}
  {C.WHITE}Network Security Enumeration Tool{C.RESET}  {C.DIM}v1.0  |  github.com/aaryajithps/netrecon{C.RESET}
  {C.DIM}Author: Aaryajith PS  |  License: MIT{C.RESET}
  {C.YELLOW}⚠  Use only on systems you own or have explicit permission to test{C.RESET}
""")

def section(title: str) -> None:
    print(f"\n{C.BLUE}{C.BOLD}  {'─' * 56}{C.RESET}")
    print(f"{C.BLUE}{C.BOLD}  🔍  {title}{C.RESET}")
    print(f"{C.BLUE}{C.BOLD}  {'─' * 56}{C.RESET}")

# ── Module 1: Host Discovery ──────────────────────────────────────────
def host_discovery(target: str) -> bool:
    section("HOST DISCOVERY")
    try:
        result = subprocess.run(
            ["ping", "-c", "3", "-W", "1", target],
            capture_output=True, text=True, timeout=10
        )
        if result.returncode == 0:
            log("OK",   "HOST", f"{target} is ALIVE (ping responded)")
        else:
            log("FAIL", "HOST", f"{target} is not responding to ping")
            return False

        try:
            hostname = socket.gethostbyaddr(target)[0]
            log("INFO", "HOST", f"Reverse DNS: {hostname}")
        except socket.herror:
            log("INFO", "HOST", "No reverse DNS entry found")

        return True

    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        log("FAIL", "HOST", f"Ping error: {e}")
        return False

# ── Module 2: Port Scanner ────────────────────────────────────────────
COMMON_PORTS = {
    21:   "FTP",        22:   "SSH",
    23:   "Telnet",     25:   "SMTP",
    53:   "DNS",        80:   "HTTP",
    110:  "POP3",       139:  "NetBIOS",
    143:  "IMAP",       443:  "HTTPS",
    445:  "SMB",        993:  "IMAPS",
    1099: "Java-RMI",   3306: "MySQL",
    5432: "PostgreSQL", 5900: "VNC",
    6667: "IRC",        8009: "AJP",
    8180: "HTTP-Alt",
}

def port_scan(target: str, timeout: float = 0.5) -> list[tuple[int, str]]:
    section("PORT SCANNING")
    open_ports: list[tuple[int, str]] = []
    print(f"  {C.DIM}Scanning {len(COMMON_PORTS)} common ports on {target} ...{C.RESET}\n")

    for port, service in sorted(COMMON_PORTS.items()):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        if sock.connect_ex((target, port)) == 0:
            log("OK", f"{port}/{service}", f"OPEN")
            open_ports.append((port, service))
        sock.close()

    print()
    if not open_ports:
        log("FAIL", "PORTS", "No open ports found")

    return open_ports

# ── Module 3: FTP Enumeration ─────────────────────────────────────────
DEFAULT_FTP_CREDS = [
    ("anonymous", ""),
    ("msfadmin",  "msfadmin"),
    ("admin",     "admin"),
    ("ftp",       "ftp"),
    ("root",      "root"),
]

def enum_ftp(target: str) -> None:
    section("FTP ENUMERATION  (Port 21)")
    try:
        ftp = ftplib.FTP(timeout=5)
        ftp.connect(target, 21)
        welcome = ftp.getwelcome()
        log("INFO", "FTP", f"Banner: {welcome}")

        # Known vulnerable version check
        if "2.3.4" in welcome:
            log("CRITICAL", "FTP", "vsftpd 2.3.4 detected — Backdoor CVE-2011-2523!")

        # Anonymous login
        try:
            ftp.login("anonymous", "")
            log("CRITICAL", "FTP", "Anonymous login ENABLED — no credentials required!")
            try:
                files = ftp.nlst()
                log("INFO", "FTP", f"Directory listing: {files[:8]}")
            except ftplib.error_perm:
                log("INFO", "FTP", "Directory listing denied")

            # Write access check
            try:
                ftp.mkd("netrecon_write_test")
                ftp.rmd("netrecon_write_test")
                log("CRITICAL", "FTP", "Write access ENABLED — can upload files!")
            except ftplib.error_perm:
                log("INFO", "FTP", "Write access denied (read-only)")
            ftp.quit()
        except ftplib.error_perm:
            log("OK", "FTP", "Anonymous login disabled")

        # Default credential brute-force
        for user, passwd in DEFAULT_FTP_CREDS[1:]:  # skip anonymous
            try:
                f2 = ftplib.FTP(timeout=3)
                f2.connect(target, 21)
                f2.login(user, passwd)
                log("CRITICAL", "FTP", f"Default credentials accepted: {user}:{passwd}")
                f2.quit()
                break
            except ftplib.error_perm:
                pass
            except Exception:
                break

    except ConnectionRefusedError:
        log("FAIL", "FTP", "Port 21 closed or filtered")
    except Exception as e:
        log("FAIL", "FTP", f"Error: {e}")

# ── Module 4: SSH Enumeration ─────────────────────────────────────────
DEFAULT_SSH_CREDS = [
    ("msfadmin",  "msfadmin"),
    ("root",      "root"),
    ("admin",     "admin"),
    ("ubuntu",    "ubuntu"),
    ("postgres",  "postgres"),
    ("user",      "user"),
]

def enum_ssh(target: str) -> None:
    section("SSH ENUMERATION  (Port 22)")

    # Banner grab
    try:
        sock = socket.socket()
        sock.settimeout(5)
        sock.connect((target, 22))
        raw_banner = sock.recv(256).decode(errors="ignore").strip()
        sock.close()
        log("INFO", "SSH", f"Banner: {raw_banner}")

        if any(v in raw_banner for v in ["OpenSSH_3", "OpenSSH_4"]):
            log("CRITICAL", "SSH", "OpenSSH < 5.x detected — severely outdated, multiple CVEs!")
        elif any(v in raw_banner for v in ["OpenSSH_5", "OpenSSH_6", "OpenSSH_7"]):
            log("HIGH", "SSH", "Outdated OpenSSH version detected")
        else:
            log("INFO", "SSH", "SSH version appears current")

    except Exception as e:
        log("FAIL", "SSH", f"Banner grab failed: {e}")
        return

    # Credential testing via paramiko
    if not SSH_AVAILABLE:
        log("INFO", "SSH", "paramiko not installed — skipping credential test")
        log("INFO", "SSH", "Install: pip install paramiko")
        return

    print(f"\n  {C.DIM}Testing {len(DEFAULT_SSH_CREDS)} default credential pairs ...{C.RESET}\n")
    for user, passwd in DEFAULT_SSH_CREDS:
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                target, port=22,
                username=user, password=passwd,
                timeout=4,
                look_for_keys=False,
                allow_agent=False,
                disabled_algorithms={"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]},
            )
            log("CRITICAL", "SSH", f"Login SUCCESS — {user}:{passwd}")

            for cmd in ["whoami", "uname -a", "id"]:
                _, stdout, _ = client.exec_command(cmd)
                out = stdout.read().decode().strip()
                log("INFO", "SSH", f"  [{cmd}] → {out}")
            client.close()
            break

        except paramiko.AuthenticationException:
            log("INFO", "SSH", f"  {user}:{passwd} — failed")
        except Exception:
            break

# ── Module 5: HTTP Enumeration ────────────────────────────────────────
SENSITIVE_PATHS = [
    "/phpMyAdmin/", "/phpmyadmin/", "/phpinfo.php",
    "/dvwa/",       "/mutillidae/",  "/tikiwiki/",
    "/admin/",      "/administrator/", "/webdav/",
    "/doc/",        "/test/",        "/backup/",
    "/.htaccess",   "/robots.txt",   "/server-status",
    "/config.php",  "/wp-admin/",    "/login.php",
    "/manager/",    "/.env",
]

def enum_http(target: str) -> None:
    section("HTTP ENUMERATION  (Port 80)")
    base = f"http://{target}"
    try:
        r = requests.get(base, timeout=5)
        server  = r.headers.get("Server",       "Unknown")
        powered = r.headers.get("X-Powered-By", "Unknown")
        log("INFO", "HTTP", f"Server: {server}")
        log("INFO", "HTTP", f"X-Powered-By: {powered}")

        # EOL version checks
        if "Apache/2.2" in server:
            log("CRITICAL", "HTTP", "Apache 2.2.x is End-of-Life — multiple remote CVEs!")
        if "PHP/5" in powered:
            log("CRITICAL", "HTTP", "PHP 5.x is End-of-Life — RCE vulnerabilities exist!")

        # Security headers audit
        REQUIRED_HEADERS = {
            "X-Frame-Options":         "Clickjacking protection MISSING",
            "X-Content-Type-Options":  "MIME sniffing protection MISSING",
            "Content-Security-Policy": "Content Security Policy MISSING",
            "Strict-Transport-Security": "HSTS MISSING",
        }
        for header, msg in REQUIRED_HEADERS.items():
            if header not in r.headers:
                log("HIGH", "HTTP", f"Missing header: {header} — {msg}")

        # HTTP TRACE
        try:
            tr = requests.request("TRACE", base, timeout=3)
            if tr.status_code == 200:
                log("HIGH", "HTTP", "HTTP TRACE enabled — Cross-Site Tracing (XST) possible!")
        except Exception:
            pass

        # Sensitive path enumeration
        print(f"\n  {C.DIM}Probing {len(SENSITIVE_PATHS)} sensitive paths ...{C.RESET}\n")
        for path in SENSITIVE_PATHS:
            try:
                resp = requests.get(f"{base}{path}", timeout=3)
                if resp.status_code == 200:
                    log("CRITICAL", "HTTP", f"EXPOSED: {path}  [HTTP 200]")
                elif resp.status_code == 403:
                    log("HIGH",     "HTTP", f"Exists but restricted: {path}  [HTTP 403]")
            except Exception:
                pass

    except requests.ConnectionError:
        log("FAIL", "HTTP", "Port 80 closed or not responding")
    except Exception as e:
        log("FAIL", "HTTP", f"Error: {e}")

# ── Module 6: SMB Enumeration ─────────────────────────────────────────
def enum_smb(target: str) -> None:
    section("SMB ENUMERATION  (Port 139/445)")
    try:
        result = subprocess.run(
            [
                "nmap", "-p", "139,445",
                "--script",
                "smb-os-discovery,smb-enum-shares,"
                "smb-security-mode,smb-vuln-ms17-010",
                "--script-args",
                f"smbusername=msfadmin,smbpassword=msfadmin",
                target,
            ],
            capture_output=True, text=True, timeout=60,
        )
        output = result.stdout

        # Parse OS
        m = re.search(r"OS:\s+(.+)", output)
        if m:
            log("INFO", "SMB", f"OS: {m.group(1).strip()}")

        # Samba version
        v = re.search(r"Samba smbd ([\d.]+)", output)
        if v:
            ver = v.group(1)
            log("INFO", "SMB", f"Samba version: {ver}")
            if ver.startswith(("3.0", "3.1", "3.2")):
                log("CRITICAL", "SMB",
                    f"Samba {ver} — CVE-2007-2447 Unauthenticated RCE!")

        # EternalBlue
        if "VULNERABLE" in output and "ms17-010" in output.lower():
            log("CRITICAL", "SMB", "MS17-010 EternalBlue — Remote Code Execution!")

        # Shares
        for share in re.findall(r"\\\\.+\\(\w[\w\$]*)", output):
            log("INFO", "SMB", f"Share found: {share}")

        # Print raw nmap output
        if output.strip():
            print(f"\n  {C.DIM}Raw nmap SMB output:{C.RESET}")
            for line in output.splitlines():
                if line.strip() and not line.startswith(("Starting", "Nmap done")):
                    print(f"    {C.DIM}{line}{C.RESET}")

    except FileNotFoundError:
        log("FAIL", "SMB", "nmap not found — install: sudo pacman -S nmap  (or apt/dnf)")
    except Exception as e:
        log("FAIL", "SMB", f"Error: {e}")

# ── Report Generator ──────────────────────────────────────────────────
def generate_report(target: str, open_ports: list[tuple[int, str]]) -> None:
    section("FINAL SECURITY REPORT")

    critical = [f for f in findings if f["level"] == "CRITICAL"]
    high     = [f for f in findings if f["level"] == "HIGH"]
    info     = [f for f in findings if f["level"] == "INFO"]

    score = len(critical) * 10 + len(high) * 5

    if score >= 50:
        risk_label = f"{C.RED}{C.BOLD}CRITICAL{C.RESET}"
    elif score >= 25:
        risk_label = f"{C.YELLOW}{C.BOLD}HIGH{C.RESET}"
    elif score >= 10:
        risk_label = f"{C.CYAN}{C.BOLD}MEDIUM{C.RESET}"
    else:
        risk_label = f"{C.GREEN}{C.BOLD}LOW{C.RESET}"

    print(f"""
  {C.BOLD}{C.WHITE}  TARGET   :{C.RESET} {C.CYAN}{target}{C.RESET}
  {C.BOLD}{C.WHITE}  DATE     :{C.RESET} {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  {C.BOLD}{C.WHITE}  PORTS    :{C.RESET} {", ".join(f"{p}/{s}" for p, s in open_ports)}

  {C.RED}🚨 CRITICAL : {len(critical)}{C.RESET}
  {C.YELLOW}⚠  HIGH     : {len(high)}{C.RESET}
  {C.CYAN}ℹ  INFO     : {len(info)}{C.RESET}
""")

    if critical:
        print(f"  {C.RED}{C.BOLD}══ CRITICAL FINDINGS ══{C.RESET}")
        for i, f in enumerate(critical, 1):
            print(f"  {C.RED}  {i:2}. [{f['service']}] {f['message']}{C.RESET}")

    if high:
        print(f"\n  {C.YELLOW}{C.BOLD}══ HIGH FINDINGS ══{C.RESET}")
        for i, f in enumerate(high, 1):
            print(f"  {C.YELLOW}  {i:2}. [{f['service']}] {f['message']}{C.RESET}")

    print(f"\n  {C.BOLD}RISK RATING : {risk_label}")
    print(f"  {C.BOLD}RISK SCORE  : {C.WHITE}{score}/100{C.RESET}")

    # JSON export
    report_data = {
        "tool":       "NetRecon v1.0",
        "author":     "Aaryajith PS",
        "github":     "https://github.com/aaryajithps/netrecon",
        "target":     target,
        "date":       datetime.now().isoformat(),
        "open_ports": [{"port": p, "service": s} for p, s in open_ports],
        "findings":   findings,
        "summary": {
            "critical":   len(critical),
            "high":       len(high),
            "info":       len(info),
            "risk_score": score,
        },
    }
    fname = f"recon_{target.replace('.', '_')}_{datetime.now().strftime('%Y%m%d_%H%M%S')}.json"
    with open(fname, "w") as fh:
        json.dump(report_data, fh, indent=2)

    print(f"\n  {C.GREEN}✔  JSON report saved → {fname}{C.RESET}")
    print(f"  {C.DIM}{'─' * 56}{C.RESET}\n")

# ── Argument Parser ───────────────────────────────────────────────────
def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="net_recon.py",
        description="NetRecon — Network Security Enumeration Tool v1.0",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python3 net_recon.py 192.168.56.102
  python3 net_recon.py 10.10.10.5 --timeout 1.0
  python3 net_recon.py 192.168.1.100 --no-color --output report.json
  python3 net_recon.py 192.168.56.102 --services ftp ssh http

Legal notice:
  Only use on systems you own or have explicit written permission to test.
  Unauthorised use is illegal under the Computer Misuse Act and equivalent laws.
        """,
    )
    parser.add_argument("target",
        help="Target IP address or hostname")
    parser.add_argument("--timeout", "-t",
        type=float, default=0.5,
        help="Port scan connection timeout in seconds (default: 0.5)")
    parser.add_argument("--services", "-s",
        nargs="+",
        choices=["ftp", "ssh", "http", "smb"],
        default=["ftp", "ssh", "http", "smb"],
        help="Services to enumerate (default: all)")
    parser.add_argument("--no-color",
        action="store_true",
        help="Disable colour output")
    parser.add_argument("--output", "-o",
        type=str, default=None,
        help="Custom output filename for JSON report")
    parser.add_argument("--yes", "-y",
        action="store_true",
        help="Skip confirmation prompt")
    return parser.parse_args()

# ── Main ──────────────────────────────────────────────────────────────
def main() -> None:
    args = parse_args()

    if args.no_color:
        C.disable()

    banner()

    target = args.target

    print(f"  {C.WHITE}Target  : {C.CYAN}{target}{C.RESET}")
    print(f"  {C.WHITE}Services: {C.CYAN}{', '.join(args.services).upper()}{C.RESET}")
    print(f"  {C.WHITE}Timeout : {C.CYAN}{args.timeout}s{C.RESET}\n")

    if not args.yes:
        confirm = input(
            f"  {C.YELLOW}Confirm you have authorisation to scan {target}? (yes/no): {C.RESET}"
        ).strip().lower()
        if confirm != "yes":
            print(f"\n  {C.RED}Aborted.{C.RESET}\n")
            sys.exit(0)

    start = datetime.now()

    # Run modules
    alive      = host_discovery(target)
    if not alive:
        print(f"\n  {C.YELLOW}Host appears down. {C.RESET}", end="")
        if not args.yes:
            if input("Continue anyway? (yes/no): ").strip().lower() != "yes":
                sys.exit(0)

    open_ports = port_scan(target, timeout=args.timeout)
    port_nums  = {p for p, _ in open_ports}

    svc = set(args.services)
    if "ftp"  in svc and 21  in port_nums: enum_ftp(target)
    if "ssh"  in svc and 22  in port_nums: enum_ssh(target)
    if "http" in svc and 80  in port_nums: enum_http(target)
    if "smb"  in svc and (445 in port_nums or 139 in port_nums):
        enum_smb(target)

    elapsed = (datetime.now() - start).seconds
    print(f"\n  {C.CYAN}⏱  Scan completed in {elapsed}s{C.RESET}")

    generate_report(target, open_ports)


if __name__ == "__main__":
    main()
