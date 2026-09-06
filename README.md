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

## Tests

No network access, no root, no external dependencies:

```bash
python3 -m unittest discover -s tests -v
```

## Offline Demo

```bash
cd firmware
python3 netmap_scan.py --demo        # exit 0
python3 netmap_scan.py --harness     # legacy fixture harness, exit 0
python3 netmap_scan.py --help
```

The demo scans the reserved documentation range `192.0.2.0/64` from a
fixture in `arp`, `ping`, and `table` modes and asserts the resulting host
lists are consistent. It never sends a packet or reads a live interface.

## Live Lab Test Plan

Performed in an **isolated, self-owned lab** only (documentation range
`192.0.2.0/24`, MAC `00:11:22:33:44:55` reserved placeholders). Never run
against third-party networks.

1. **Setup** — Create an isolated VLAN with one partner host acting as
   gateway at the documented gateway placeholder.
2. **ARP scan (arping)** — `sudo python3 netmap_scan.py -i lab-eth0 -t 192.0.2.0 -m arp`
   → expect every powered-on host in the lab to appear with a MAC/vendor.
3. **Ping sweep** — `python3 netmap_scan.py -i lab-eth0 -t 192.0.2.0 -m ping`
   → same host set (may omit hosts that block ICMP).
4. **ARP table read** — `python3 netmap_scan.py -i lab-eth0 -t 192.0.2.0 -m table`
   → reads the kernel ARP table; host set is a subset of active sessions.
5. **Consistency** — compare host lists across arp/ping/table on the same
   lab; the tool's own demo asserts this exact consistency offline.
6. **Topology / map** — `--topology` and `--map` should classify the
   documented gateway placeholder as router and list remaining hosts.
7. **Cleanup** — verify no ARP-table residue and only-lab MACs were touched.

## Metrics

- Hosts discovered: count of unique IPs found per scan method.
- MAC/vendor resolution rate: `hosts with OUI match / total hosts`.
- Scan latency: wall-clock time for a full `/24` sweep.
- Mode consistency: Jaccard similarity between arp, ping, and table host sets.
- False positives/negatives: hosts wrongly present or missing vs. a manual lab inventory.

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
