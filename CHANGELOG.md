# Changelog

All notable changes to NetRecon are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).

---

## [1.0.0] — 2026-03-23

### Added
- Initial public release
- `host_discovery` module — ping sweep + reverse DNS
- `port_scan` module — TCP connect scan across 19 common ports
- `enum_ftp` module — anonymous login, write access, CVE-2011-2523 detection
- `enum_ssh` module — banner grabbing, version analysis, default credential testing via paramiko
- `enum_http` module — server version, security headers, TRACE, 20 sensitive path probes
- `enum_smb` module — Samba version, share enumeration, CVE-2007-2447, MS17-010 via nmap NSE
- `generate_report` — colour-coded terminal output + JSON export
- Severity-weighted risk scoring system (0–100+)
- CLI argument parser with `--services`, `--timeout`, `--no-color`, `--yes` flags
- MIT licence

---

## Roadmap

### [1.1.0] — Planned
- [ ] HTML report export
- [ ] SMTP enumeration module
- [ ] MySQL enumeration module
- [ ] VNC detection module

### [1.2.0] — Planned
- [ ] Full subnet scan mode (`--subnet`)
- [ ] Unit test suite
- [ ] Docker image

### [2.0.0] — Future
- [ ] Web dashboard UI
- [ ] Plugin architecture for custom modules
- [ ] CVE API integration (NVD)
