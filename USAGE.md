# NetRecon — Extended Usage Guide

## Setting Up a Lab Environment

Before running NetRecon, always test in an **isolated lab**:

1. Download [Metasploitable 2](https://sourceforge.net/projects/metasploitable/)
2. Import into VirtualBox or VMware
3. Set network adapter to **Host-Only**
4. Note the target IP: usually `192.168.56.102`
5. Run NetRecon from your attacker machine on the same host-only network

---

## All Command Examples

```bash
# Full scan — all services
python3 net_recon.py 192.168.56.102

# FTP only
python3 net_recon.py 192.168.56.102 --services ftp

# SSH + HTTP only
python3 net_recon.py 192.168.56.102 --services ssh http

# Slower timeout (better for slow networks)
python3 net_recon.py 192.168.56.102 --timeout 2.0

# No colour (for piping to file)
python3 net_recon.py 192.168.56.102 --no-color > scan.txt

# Skip prompt (for scripting)
python3 net_recon.py 192.168.56.102 --yes

# All flags combined
python3 net_recon.py 192.168.56.102 --services ftp ssh --timeout 1.0 --yes --no-color
```

---

## Understanding the Output

### Severity Levels

| Level | Icon | Meaning |
|-------|------|---------|
| CRITICAL | 🚨 | Immediately exploitable — direct system access possible |
| HIGH | ⚠ | Significant risk — should be fixed urgently |
| INFO | ℹ | Informational — useful context, not a direct risk |
| OK | ✔ | Check passed — service is configured correctly |
| FAIL | ✖ | Module error or port closed |

### Risk Score

```
Score = (CRITICAL count × 10) + (HIGH count × 5)

CRITICAL  = score ≥ 50
HIGH      = score ≥ 25
MEDIUM    = score ≥ 10
LOW       = score < 10
```

---

## JSON Report

Every scan produces a JSON file:

```
recon_192_168_56_102_20260323_150239.json
```

You can parse this with any tool:

```bash
# View with jq
cat recon_*.json | jq '.summary'
cat recon_*.json | jq '.findings[] | select(.level == "CRITICAL")'

# Count critical findings
cat recon_*.json | jq '.summary.critical'
```

---

## Troubleshooting

### SSH: "no matching host key type"

```bash
# NetRecon handles this automatically via paramiko
# If connecting manually:
ssh -o "HostKeyAlgorithms=+ssh-rsa" user@target
```

### SMB: "nmap not found"

```bash
# Arch Linux
sudo pacman -S nmap

# Ubuntu / Kali
sudo apt install nmap

# macOS
brew install nmap
```

### paramiko not installed

```bash
pip install paramiko --break-system-packages   # Arch
pip install paramiko                            # Ubuntu / Kali
```

### "Permission denied" on ping

```bash
# Run with sudo if ping requires it
sudo python3 net_recon.py 192.168.56.102
```
