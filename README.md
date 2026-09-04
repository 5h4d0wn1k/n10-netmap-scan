# N10 — Netmap Scanner

ARP scan, hostname resolution, vendor detection, and network topology mapping.

## Overview

This project implements a network mapper that:
- Discovers live hosts via ARP scan, ping sweep, or ARP table reading
- Resolves hostnames via reverse DNS
- Identifies device vendors via OUI lookup
- Classifies hosts into topology roles (router, switch, host)
- Prints ASCII topology diagrams

## Features

- **Multi-method scanning**: ARP (arping), ping sweep, ARP table
- **OUI vendor lookup**: 80+ vendor entries
- **Hostname resolution**: Reverse DNS for discovered hosts
- **Topology classification**: Routers, switches, and hosts
- **ASCII topology map**: Visual network diagram
- **Auto-detection**: Finds default interface and subnet

## Installation

No external dependencies — uses only the Python standard library + system tools.

```bash
# For ARP scanning, install arping
sudo apt install arping iputils-arping
```

## Usage

```bash
# Auto-detect and scan local network
python3 netmap_scan.py

# Specify interface and target
python3 netmap_scan.py --interface eth0 --target 192.168.1.0

# Use ping sweep instead of ARP
python3 netmap_scan.py --method ping

# Read existing ARP table only
python3 netmap_scan.py --method table

# Show topology
python3 netmap_scan.py --topology

# ASCII topology map
python3 netmap_scan.py --map
```

## Example Output

```
╔═══════════════════════════════════════╗
║     N10 — Netmap Scanner              ║
╚═══════════════════════════════════════╝
Interface: eth0

[+] Found 8 hosts in 12.3s

============================================================
  NETWORK TOPOLOGY
============================================================

  ROUTERS/GATEWAYS:
    192.168.1.1       AA:BB:CC:DD:EE:01 Cisco         gateway

  HOSTS (7):
    192.168.1.10      AA:BB:CC:DD:EE:10 Intel         laptop
    192.168.1.20      B8:27:EB:AA:BB:CC Raspberry Pi  pi-home
    ...

  ASCII Topology Map
  ========================================
         [192.168.1.1]
            |
            |--- [laptop]
            |--- [pi-home]
            `--- [phone]
```

## Legal Disclaimer

**IMPORTANT: Read before use.**

This project is provided for **educational and authorized security testing purposes only**.

### Authorization Requirements
- You MUST have explicit written permission from the network owner before using this tool
- Unauthorized interception of network communications is illegal under federal and state laws
- This tool should ONLY be used on networks you own or have written authorization to test

### Legal Framework
- **Computer Fraud and Abuse Act (CFAA)**: Unauthorized access to computer systems is a federal crime
- **Wiretap Act (18 U.S.C. § 2511)**: Interception of electronic communications without consent is illegal
- **State Laws**: Many states have additional computer crime and wiretapping statutes
- **GDPR/CCPA**: Data collection may be subject to privacy regulations

### Acceptable Use
- Testing security of your own networks
- Authorized penetration testing with written scope
- Academic research in controlled lab environments
- Security education and training

### Prohibited Use
- Intercepting communications on networks you do not own
- Attacking infrastructure without authorization
- Any activity that violates applicable laws or regulations
- Commercial use without proper licensing

### No Warranty
This software is provided "AS IS" without warranty of any kind. The author is not responsible for any misuse or damage caused by this software.

### Responsible Disclosure
If you discover vulnerabilities using this tool, follow responsible disclosure practices:
1. Report to the vendor/owner privately
2. Allow reasonable time for remediation
3. Do not exploit beyond proof of concept

## License

MIT
