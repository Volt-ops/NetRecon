<div align="center">

```
███╗   ██╗███████╗████████╗██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
████╗  ██║██╔════╝╚══██╔══╝██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
██╔██╗ ██║█████╗     ██║   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██║╚██╗██║██╔══╝     ██║   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║ ╚████║███████╗   ██║   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═══╝╚══════╝   ╚═╝   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
```

**Network Security Enumeration Tool**

[![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)](https://python.org)
[![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)](LICENSE)
[![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS-lightgrey?style=flat-square)](https://github.com/aaryajithps/netrecon)
[![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)](https://github.com/aaryajithps/netrecon)
[![Author](https://img.shields.io/badge/Author-Aaryajith%20PS-navy?style=flat-square)](https://github.com/aaryajithps)

*Automated enumeration of FTP · SSH · HTTP · SMB — in one command*

</div>

---

## Overview

**NetRecon** is an open-source Python network security enumeration tool that automates the complete reconnaissance pipeline against a target system. It performs host discovery, port scanning, and deep service-specific enumeration for FTP, SSH, HTTP, and SMB — producing a colour-coded terminal report and a structured JSON export.

Built as part of an internship cybersecurity project and released publicly under the MIT licence for educational and authorised security testing use.

> ⚠ **Legal Notice:** Only use NetRecon on systems you own or have **explicit written authorisation** to test. Unauthorised use is illegal under the Computer Misuse Act and equivalent legislation worldwide.

---

## Features

- **Host Discovery** — Ping sweep with reverse DNS lookup
- **Port Scanning** — TCP connect scan across 19 common ports
- **FTP Enumeration** — Anonymous login detection, write-access test, default credential testing, version vulnerability check (CVE-2011-2523)
- **SSH Enumeration** — Banner grabbing, version analysis, weak cipher detection, default credential testing via paramiko
- **HTTP Enumeration** — Server/PHP version detection, security header audit, HTTP TRACE check, 20 sensitive path probes
- **SMB Enumeration** — Samba version detection, share enumeration, CVE-2007-2447 check, MS17-010 check via nmap NSE scripts
- **Risk Scoring** — Automatic severity-weighted risk score calculation
- **JSON Report Export** — Machine-readable structured output for further processing
- **Colour Terminal Output** — ANSI-coded severity levels (disableable with `--no-color`)
- **Selective Scanning** — Target specific services with `--services`

---

## Quick Start

```bash
# 1. Clone the repository
git clone https://github.com/volt-ops/netrecon.git
cd netrecon

# 2. Install dependencies
pip install -r requirements.txt

# 3. Run against your lab target
python3 net_recon.py <Target IP>
```

---

## Installation

### Prerequisites

- Python 3.8 or higher
- `nmap` installed on your system (required for SMB module)
- Linux or macOS recommended

### Arch Linux

```bash
sudo pacman -S nmap python
pip install paramiko requests --break-system-packages
```

### Ubuntu / Debian / Kali

```bash
sudo apt update && sudo apt install nmap python3-pip -y
pip install paramiko requests
```

### macOS

```bash
brew install nmap python3
pip3 install paramiko requests
```

### Python dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

### Basic scan (all services)

```bash
python3 net_recon.py <Target IP>
```

### Scan specific services only

```bash
python3 net_recon.py <Target IP> --services ftp ssh
python3 net_recon.py <Target IP> --services http smb
```

### Adjust port scan timeout

```bash
python3 net_recon.py <Target IP> --timeout 1.0
```

### Skip confirmation prompt (automation / CI)

```bash
python3 net_recon.py <Target IP> --yes
```

### Disable colour output

```bash
python3 net_recon.py <Target IP> --no-color
```

### All options

```
usage: net_recon.py [-h] [--timeout TIMEOUT] [--services {ftp,ssh,http,smb} ...]
                    [--no-color] [--output OUTPUT] [--yes]
                    target

positional arguments:
  target                Target IP address or hostname

options:
  -h, --help            show this help message and exit
  --timeout, -t         Port scan connection timeout in seconds (default: 0.5)
  --services, -s        Services to enumerate: ftp ssh http smb (default: all)
  --no-color            Disable colour terminal output
  --output, -o          Custom filename for JSON report output
  --yes, -y             Skip confirmation prompt
```

---

## Output Example

```
  [15:02:25] ✔  [OK      ] HOST   192.168.56.102 is ALIVE
  [15:02:33] ✔  [OK      ] 21/FTP  OPEN
  [15:02:33] ✔  [OK      ] 22/SSH  OPEN
  [15:02:33] ✔  [OK      ] 80/HTTP OPEN
  [15:02:33] ✔  [OK      ] 445/SMB OPEN

  [15:02:33] 🚨 [CRITICAL] FTP    vsftpd 2.3.4 detected — Backdoor CVE-2011-2523!
  [15:02:33] 🚨 [CRITICAL] FTP    Anonymous login ENABLED
  [15:02:33] 🚨 [CRITICAL] SSH    Login SUCCESS — msfadmin:msfadmin
  [15:02:34] 🚨 [CRITICAL] HTTP   Apache 2.2.x End-of-Life — multiple CVEs!
  [15:02:34] 🚨 [CRITICAL] HTTP   EXPOSED: /phpMyAdmin/
  [15:02:39] 🚨 [CRITICAL] SMB    Samba 3.0.20 — CVE-2007-2447 RCE!

  RISK RATING : CRITICAL
  RISK SCORE  : 155/100
  ✔  JSON report saved → recon_192_168_56_102_20260323_150239.json
```

---

## JSON Report Structure

```json
{
  "tool": "NetRecon v1.0",
  "author": "Aaryajith PS",
  "target": "192.168.56.102",
  "date": "2026-03-23T15:02:39",
  "open_ports": [
    { "port": 21, "service": "FTP" },
    { "port": 22, "service": "SSH" }
  ],
  "findings": [
    {
      "level": "CRITICAL",
      "service": "FTP",
      "message": "Anonymous login ENABLED",
      "time": "15:02:33"
    }
  ],
  "summary": {
    "critical": 13,
    "high": 5,
    "info": 19,
    "risk_score": 155
  }
}
```

---

## Module Architecture

```
netrecon/
├── net_recon.py          # Main tool — all modules in one file
├── requirements.txt      # Python dependencies
├── README.md             # This file
├── LICENSE               # MIT licence
├── CHANGELOG.md          # Version history
├── CONTRIBUTING.md       # Contribution guide
├── .gitignore            # Git ignore rules
├── docs/
│   └── USAGE.md          # Extended usage documentation
└── examples/
    └── sample_output.json  # Example JSON report output
```

---

## Modules

| Module | Function | Key Libraries |
|--------|----------|---------------|
| `host_discovery` | Ping + reverse DNS | `subprocess`, `socket` |
| `port_scan` | TCP connect scan (19 ports) | `socket` |
| `enum_ftp` | Anonymous login, write test, CVE check | `ftplib` |
| `enum_ssh` | Banner, version, cipher, cred test | `paramiko` |
| `enum_http` | Headers, paths, TRACE, EOL check | `requests` |
| `enum_smb` | Version, shares, CVE-2007-2447, MS17-010 | `subprocess` + nmap |
| `generate_report` | Colour terminal + JSON export | `json`, `datetime` |

---

## Tested Against

| Target | OS | Notes |
|--------|----|-------|
| Metasploitable 2 | Ubuntu 8.04 | Primary test target |
| Metasploitable 3 | Ubuntu 14.04 | Extended testing |
| DVWA | Various | HTTP module |
| VulnHub machines | Various | Community testing |

> Always test in an isolated lab environment (VirtualBox / VMware host-only network)

---

## CVEs Detected

NetRecon checks for the following known vulnerabilities:

| CVE | Service | Description |
|-----|---------|-------------|
| CVE-2011-2523 | FTP (vsftpd 2.3.4) | Backdoor remote code execution |
| CVE-2007-2447 | SMB (Samba 3.0.x) | Username map script RCE |
| MS17-010 | SMB | EternalBlue remote code execution |

---

## Contributing

Contributions are welcome! Please read [CONTRIBUTING.md](CONTRIBUTING.md) before submitting a pull request.

```bash
# Fork the repo, then:
git clone https://github.com/YOUR_USERNAME/netrecon.git
cd netrecon
git checkout -b feature/your-feature-name
# make changes
git commit -m "feat: add your feature"
git push origin feature/your-feature-name
# Open a Pull Request
```

**Ideas for contributions:**
- Add more service modules (SMTP, MySQL, VNC, RDP)
- Add HTML report export
- Improve CVE detection coverage
- Add Nessus / OpenVAS integration
- Write unit tests

---

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for full version history.

**v1.0.0** — March 23, 2026
- Initial public release
- FTP, SSH, HTTP, SMB enumeration modules
- JSON report export
- Risk scoring system
- CLI argument parser

---

## Disclaimer

NetRecon is provided **for educational purposes and authorised security testing only**.

The author takes **no responsibility** for any misuse or damage caused by this tool. By using NetRecon you agree to use it only against systems you own or have received explicit written permission to test.

Unauthorised scanning, enumeration, or exploitation of computer systems is **illegal** under:
- Computer Misuse Act 1990 (UK)
- Computer Fraud and Abuse Act (USA)
- IT Act 2000 (India)
- And equivalent laws in all jurisdictions

---

## Licence

```
MIT License

Copyright (c) 2026 Aaryajith PS

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND.
```

---

## Author

**Aaryajith PS**
Internship Cybersecurity Project — 2026

---

<div align="center">

⭐ Star this repo if you found it useful — it helps others discover the tool

</div>
