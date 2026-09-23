> **⚠️ EDUCATIONAL USE ONLY — AUTHORIZED TESTING ONLY.**
> This project exists for education, research, and **defense of systems you own
> or hold explicit written authorization to assess**. Unauthorized use is
> prohibited and may be illegal. Read [ETHICS.md](ETHICS.md) and
> [SCOPE.md](SCOPE.md) before use. Use at your own risk; **AS IS**, no warranty.

# N10 — Netmap Scanner

![License: MIT](https://img.shields.io/badge/license-MIT-blue.svg)
![GitHub Stars](https://img.shields.io/github/stars/5h4d0wn1k/n10-netmap-scan)
![Last Commit](https://img.shields.io/github/last-commit/5h4d0wn1k/n10-netmap-scan)
![GitHub Issues](https://img.shields.io/github/issues/5h4d0wn1k/n10-netmap-scan)

> **Network mapper and scanner** — ARP scan, ping sweep, reverse-DNS hostname
> resolution, OUI vendor lookup, and ASCII topology maps for network discovery
> and network forensics on systems you own.

## Why

Knowing what is actually on a network — and how hosts relate — is the first
step in both offensive reconnaissance and defensive asset inventory. N10 maps
live hosts through three techniques (ARP via `arping`, ICMP ping sweep, and a
read of the local kernel ARP table), resolves hostnames, identifies vendors
through an OUI database, and classifies devices as router/switch/host before
printing an ASCII topology diagram. The whole tool runs offline against a
bundled fixture in the reserved documentation range, so the logic is testable
without touching a wire — then rehearsable in an isolated, self-owned lab only.

## Features

- **Multi-method discovery** — `--method arp|ping|table` (default `arp`).
- **OUI vendor lookup** — 80+ vendor entries for discovered MACs.
- **Hostname resolution** — reverse DNS for discovered hosts.
- **Topology classification** — routers, switches, and hosts.
- **ASCII topology map** — `--map` renders the network as a tree.
- **Auto-detection** — finds the default interface and subnet when omitted.
- **Offline demo** — `--demo` scans the documentation range
  `192.0.2.0/64` from a fixture and asserts mode consistency.

## Quickstart

```bash
# Optional system tool for ARP mode
sudo apt install arping iputils-arping

# Offline demo (no packets sent, exit 0)
cd firmware && python3 netmap_scan.py --demo

# Auto-detect and scan the local network
python3 netmap_scan.py

# Scan a specific interface/subnet
python3 netmap_scan.py --interface eth0 --target 192.168.1.0

# Use a ping sweep instead of ARP
python3 netmap_scan.py --method ping

# Read the existing kernel ARP table only
python3 netmap_scan.py --method table

# Show topology classification + ASCII map
python3 netmap_scan.py --topology --map
```

## Tests

```bash
python3 -m unittest discover -s tests -v
```

No network access, no root, and no external dependencies are needed for the
test suite.

## Project structure

```
firmware/netmap_scan.py   # scanner engine + CLI
tests/                    # offline unit tests (no network/root)
ETHICS.md                 # ethics/authorized-use policy (read first)
SCOPE.md                  # defined assessment scope
```

## Documentation

- [ETHICS.md](ETHICS.md) — ethical-use policy, read first
- [SCOPE.md](SCOPE.md) — authorized-scope definition
- [CONTRIBUTING.md](CONTRIBUTING.md) — how to contribute
- [SECURITY.md](SECURITY.md) — vulnerability reporting

## Contributing

Additional OUI entries, scan methods, and topology heuristics are welcome. See
[CONTRIBUTING.md](CONTRIBUTING.md); the tool must remain usable offline.

## License

MIT — see [LICENSE](LICENSE).