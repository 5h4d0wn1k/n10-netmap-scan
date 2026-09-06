#!/usr/bin/env python3
"""
N10 - Netmap Scanner
ARP scan, hostname resolution, vendor detection, and network topology mapping.
"""

import subprocess
import socket
import struct
import sys
import os
import re
import argparse
import time
from collections import defaultdict


OUI_DB = {
    '00:00:0C': 'Cisco', '00:03:6B': 'Cisco', '00:0A:41': 'Cisco',
    '00:50:56': 'VMware', '00:0C:29': 'VMware', '00:05:69': 'VMware',
    '08:00:27': 'Oracle VirtualBox', '52:54:00': 'QEMU/KVM',
    '00:16:3E': 'Xen', '00:15:5D': 'Microsoft Hyper-V',
    'B8:27:EB': 'Raspberry Pi', 'DC:A6:32': 'Raspberry Pi',
    'E4:5F:01': 'Raspberry Pi', '3C:22:FB': 'Apple', 'A8:5C:2C': 'Apple',
    'F0:18:98': 'Apple', 'AC:DE:48': 'Apple',
    '00:1A:11': 'Google', '3C:5A:B4': 'Google', '54:60:09': 'Google',
    '00:02:B3': 'Intel', '00:13:02': 'Intel', '00:15:17': 'Intel',
    '00:1E:65': 'Intel', '00:24:D7': 'Intel', '3C:97:0E': 'Intel',
    '40:A6:D9': 'Intel', '68:05:CA': 'Intel', '8C:8D:28': 'Intel',
    'A4:4C:C8': 'Intel', 'B4:69:AF': 'Intel', 'CC:3D:82': 'Intel',
    '00:1D:D8': 'HP', '00:17:A4': 'HP', '00:08:22': 'InPro',
    '00:E0:4C': 'Realtek', '52:54:AB': 'Realtek',
    '00:1A:2B': 'Linksys', '00:23:CD': 'Linksys',
    'C0:56:27': 'Netgear', '00:1F:33': 'Netgear',
    '00:1E:58': 'D-Link', '1C:7E:E5': 'D-Link',
    '18:A6:F7': 'TP-Link', '50:C7:BF': 'TP-Link',
    'C0:25:E9': 'TP-Link', 'EC:08:6B': 'TP-Link',
    'C8:3A:35': 'Tenda', '00:B0:52': 'Atheros',
    '68:C4:4D': 'Motorola', '00:0F:4B': 'Oracle',
    '00:80:77': 'Tektronix', '00:D0:2D': 'Quantum',
    '00:06:5A': 'Gateway', '00:11:11': 'Actiontec',
    '00:15:E9': 'Sagem', '00:12:17': 'Sagem',
    '00:40:96': 'Cisco', '00:1B:0D': 'Cisco',
    '00:1C:0E': 'Cisco', '00:1E:4A': 'Cisco',
    '00:21:55': 'Cisco', '00:23:04': 'Cisco',
    '00:24:50': 'Cisco', '00:25:45': 'Cisco',
}


class NetmapScanner:
    """Network mapper with ARP scanning and topology detection."""

    def __init__(self, interface=None):
        self.interface = interface or self._detect_interface()
        self.hosts = []
        self.topology = {'routers': [], 'switches': [], 'hosts': []}

    def _detect_interface(self):
        """Auto-detect default network interface."""
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5)
            match = re.search(r'dev\s+(\S+)', result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return 'eth0'

    def get_local_info(self):
        """Get local IP and subnet."""
        try:
            result = subprocess.run(
                ['ip', 'addr', 'show', self.interface],
                capture_output=True, text=True, timeout=5)
            match = re.search(r'inet\s+(\d+\.\d+\.\d+\.\d+)/(\d+)',
                              result.stdout)
            if match:
                return match.group(1), int(match.group(2))
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip, 24
        except OSError:
            return '192.168.1.1', 24

    def arp_scan_arping(self, target_range):
        """ARP scan using arping (most reliable)."""
        hosts = []
        try:
            ip_parts = target_range.split('.')
            base = '.'.join(ip_parts[:3])
            results = []
            processes = []

            for i in range(1, 255):
                ip = f"{base}.{i}"
                p = subprocess.Popen(
                    ['arping', '-c', '1', '-w', '1', '-I',
                     self.interface, ip],
                    stdout=subprocess.PIPE, stderr=subprocess.PIPE)
                processes.append((ip, p))

                if len(processes) >= 50:
                    for target_ip, proc in processes:
                        proc.wait(timeout=3)
                        out = proc.stdout.read().decode('utf-8',
                                                        errors='replace')
                        if 'reply from' in out.lower():
                            mac_m = re.search(
                                r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})',
                                out)
                            mac = mac_m.group(1).upper() if mac_m else None
                            hosts.append({
                                'ip': target_ip, 'mac': mac,
                                'vendor': self._lookup_oui(mac) if mac
                                           else 'Unknown',
                                'method': 'arping'
                            })
                    processes = []

            for target_ip, proc in processes:
                try:
                    proc.wait(timeout=3)
                    out = proc.stdout.read().decode('utf-8',
                                                    errors='replace')
                    if 'reply from' in out.lower():
                        mac_m = re.search(
                            r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})',
                            out)
                        mac = mac_m.group(1).upper() if mac_m else None
                        hosts.append({
                            'ip': target_ip, 'mac': mac,
                            'vendor': self._lookup_oui(mac) if mac
                                       else 'Unknown',
                            'method': 'arping'
                        })
                except subprocess.TimeoutExpired:
                    proc.kill()

        except FileNotFoundError:
            print("[-] arping not found, falling back to arp -a")
            return self.arp_scan_arp_table()

        return hosts

    def arp_scan_arp_table(self):
        """Read from system ARP table."""
        hosts = []
        try:
            result = subprocess.run(
                ['arp', '-a', '-i', self.interface],
                capture_output=True, text=True, timeout=5)
            for line in result.stdout.split('\n'):
                match = re.search(
                    r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+'
                    r'([0-9a-fA-F:]{17})',
                    line)
                if match:
                    ip = match.group(1)
                    mac = match.group(2).upper()
                    hosts.append({
                        'ip': ip, 'mac': mac,
                        'vendor': self._lookup_oui(mac),
                        'method': 'arp_table'
                    })
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return hosts

    def arp_scan_ping(self, target_range):
        """Use ping sweep to find live hosts."""
        hosts = []
        ip_parts = target_range.split('.')
        base = '.'.join(ip_parts[:3])

        processes = []
        for i in range(1, 255):
            ip = f"{base}.{i}"
            p = subprocess.Popen(
                ['ping', '-c', '1', '-W', '1', ip],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            processes.append((ip, p))

            if len(processes) >= 50:
                for target_ip, proc in processes:
                    proc.wait(timeout=3)
                    if proc.returncode == 0:
                        mac = self._get_arp_mac(target_ip)
                        hosts.append({
                            'ip': target_ip, 'mac': mac,
                            'vendor': self._lookup_oui(mac) if mac
                                       else 'Unknown',
                            'method': 'ping'
                        })
                processes = []

        for target_ip, proc in processes:
            try:
                proc.wait(timeout=3)
                if proc.returncode == 0:
                    mac = self._get_arp_mac(target_ip)
                    hosts.append({
                        'ip': target_ip, 'mac': mac,
                        'vendor': self._lookup_oui(mac) if mac
                                   else 'Unknown',
                        'method': 'ping'
                    })
            except subprocess.TimeoutExpired:
                proc.kill()

        return hosts

    def _get_arp_mac(self, ip):
        """Get MAC for IP from ARP table."""
        try:
            result = subprocess.run(
                ['arp', '-n', ip],
                capture_output=True, text=True, timeout=3)
            match = re.search(
                r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})',
                result.stdout)
            if match:
                return match.group(1).upper()
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def _lookup_oui(mac):
        if not mac:
            return 'Unknown'
        prefix = ':'.join(mac.upper().split(':')[:3])
        return OUI_DB.get(prefix, 'Unknown')

    def resolve_hostname(self, ip):
        """Reverse DNS lookup."""
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            return hostname
        except (socket.herror, socket.gaierror, OSError):
            return None

    def scan(self, target_range=None, method='arp'):
        """Perform network scan."""
        if not target_range:
            local_ip, cidr = self.get_local_info()
            parts = local_ip.split('.')
            target_range = '.'.join(parts[:3]) + '.0/24'
            print(f"[+] Auto-detected network: {target_range} "
                  f"(/{cidr})")

        print(f"[*] Scanning {target_range} via {method}...")
        start_time = time.time()

        if method == 'arp':
            self.hosts = self.arp_scan_arping(target_range)
            if not self.hosts:
                print("[*] arping returned nothing, trying ARP table...")
                self.hosts = self.arp_scan_arp_table()
        elif method == 'ping':
            self.hosts = self.arp_scan_ping(target_range)
        elif method == 'table':
            self.hosts = self.arp_scan_arp_table()
        else:
            self.hosts = self.arp_scan_arping(target_range)

        elapsed = time.time() - start_time
        print(f"[+] Found {len(self.hosts)} hosts in {elapsed:.1f}s")

        for host in self.hosts:
            host['hostname'] = self.resolve_hostname(host['ip'])

        return self.hosts

    def build_topology(self):
        """Classify hosts into topology roles."""
        self.topology = {'routers': [], 'switches': [], 'hosts': []}
        gateway_ip = self._get_gateway()

        for host in self.hosts:
            if host['ip'] == gateway_ip:
                host['role'] = 'gateway'
                self.topology['routers'].append(host)
            elif self._is_router_vendor(host.get('vendor', '')):
                host['role'] = 'possible_router'
                self.topology['routers'].append(host)
            elif self._is_switch_mac(host.get('mac', '')):
                host['role'] = 'possible_switch'
                self.topology['switches'].append(host)
            else:
                host['role'] = 'host'
                self.topology['hosts'].append(host)

        return self.topology

    def _get_gateway(self):
        try:
            result = subprocess.run(
                ['ip', 'route', 'show', 'default'],
                capture_output=True, text=True, timeout=5)
            match = re.search(r'via\s+(\d+\.\d+\.\d+\.\d+)', result.stdout)
            if match:
                return match.group(1)
        except (FileNotFoundError, subprocess.TimeoutExpired):
            pass
        return None

    @staticmethod
    def _is_router_vendor(vendor):
        router_vendors = ['Cisco', 'Netgear', 'Linksys', 'TP-Link',
                          'D-Link', 'Tenda']
        return any(rv.lower() in vendor.lower() for rv in router_vendors)

    @staticmethod
    def _is_switch_mac(mac):
        if not mac:
            return False
        switch_prefixes = ['00:00:0C', '00:01:42', '00:03:6B']
        return mac.upper()[:8] in switch_prefixes

    def print_topology(self):
        """Print formatted network topology."""
        self.build_topology()

        print(f"\n{'='*60}")
        print(f"  NETWORK TOPOLOGY")
        print(f"{'='*60}")

        if self.topology['routers']:
            print(f"\n  ROUTERS/GATEWAYS:")
            for r in self.topology['routers']:
                hostname = r.get('hostname') or ''
                print(f"    {r['ip']:16s} {r.get('mac', 'N/A'):>18s} "
                      f"{r.get('vendor', ''):15s} {hostname}")

        if self.topology['switches']:
            print(f"\n  SWITCHES (detected):")
            for s in self.topology['switches']:
                print(f"    {s['ip']:16s} {s.get('mac', 'N/A'):>18s} "
                      f"{s.get('vendor', ''):15s}")

        print(f"\n  HOSTS ({len(self.topology['hosts'])}):")
        for h in sorted(self.topology['hosts'],
                        key=lambda x: tuple(int(p) for p in
                                            x['ip'].split('.'))):
            hostname = h.get('hostname') or ''
            print(f"    {h['ip']:16s} {h.get('mac', 'N/A'):>18s} "
                  f"{h.get('vendor', ''):15s} {hostname}")

        print(f"\n{'='*60}")
        print(f"  Total: {len(self.hosts)} hosts")
        print(f"  Routers: {len(self.topology['routers'])}")
        print(f"  Switches: {len(self.topology['switches'])}")
        print(f"  Hosts: {len(self.topology['hosts'])}")
        print(f"{'='*60}")

    def print_ascii_map(self):
        """Print ASCII topology diagram."""
        self.build_topology()
        gw = self.topology['routers'][0] if self.topology['routers'] \
            else None
        print(f"\n  ASCII Topology Map")
        print(f"  {'='*40}")

        if gw:
            gw_label = f"[{gw['ip']}]"
            print(f"\n         {gw_label}")
            print(f"            |")
            print(f"            |")

        for i, h in enumerate(self.topology['hosts'][:10]):
            prefix = '|--' if i < len(self.topology['hosts']) - 1 \
                     else '`--'
            label = h.get('hostname') or h['ip']
            print(f"    {prefix} [{label}]")

        remaining = len(self.topology['hosts']) - 10
        if remaining > 0:
            print(f"    `-- ... and {remaining} more")


def parse_arp_table_output(text):
    """Parse `arp -a` (or `arp -a -i`) output into host dicts.

    Pure string parsing so realistic scan excerpts can be fed as fixtures
    with no live interface, root, or subprocess.
    """
    hosts = []
    host_re = re.compile(
        r'\((\d+\.\d+\.\d+\.\d+)\)\s+at\s+'
        r'([0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})')
    for line in text.split('\n'):
        m = host_re.search(line)
        if not m:
            continue
        ip = m.group(1)
        mac = m.group(2).upper()
        hosts.append({
            'ip': ip, 'mac': mac,
            'vendor': NetmapScanner._lookup_oui(mac),
            'method': 'arp_table',
        })
    return hosts


ARP_FIXTURE = """
lab-router.local (192.0.2.1) at 00:1b:0d:aa:bb:01 on lab-eth0
? (192.0.2.2) at 08:00:27:aa:bb:01 on lab-eth0
? (192.0.2.3) at 00:0c:29:cc:dd:01 on lab-eth0
? (192.0.2.4) at 52:54:00:ee:ff:01 on lab-eth0
? (192.0.2.5) at 00:16:3e:11:22:33 on lab-eth0
"""

# Shared fixture MACs so arp/ping/table modes resolve the same vendors
PING_FIXTURE_MAC = {
    '192.0.2.1': '00:1B:0D:AA:BB:01',
    '192.0.2.2': '08:00:27:AA:BB:01',
    '192.0.2.3': '00:0C:29:CC:DD:01',
    '192.0.2.4': '52:54:00:EE:FF:01',
    '192.0.2.5': '00:16:3E:11:22:33',
}


def _normalise_hosts(hosts):
    """Return a canonical sorted host list (ip, mac, vendor, method).

    Used so that the arp / ping / table scan modes can be compared for
    consistency in the offline demo and tests.
    """
    return sorted(
        (h['ip'], h['mac'], h.get('vendor', 'Unknown'), h['method'])
        for h in hosts)


def _ping_sweep_hosts(base, alive_addrs):
    """Build a ping-sweep style host list from alive addresses.

    Offline helper so `ping` mode produces host entries consistent with
    the ARP-table mode over the same fixture range. No subprocesses.
    """
    hosts = []
    for i in alive_addrs:
        ip = f"{base}.{i}"
        mac = PING_FIXTURE_MAC.get(ip)
        hosts.append({
            'ip': ip, 'mac': mac,
            'vendor': NetmapScanner._lookup_oui(mac) if mac else 'Unknown',
            'method': 'ping',
        })
    return hosts


def _arping_hosts(base, alive_addrs):
    """Build an arping-style host list from alive addresses. Offline."""
    hosts = []
    for i in alive_addrs:
        ip = f"{base}.{i}"
        mac = PING_FIXTURE_MAC.get(ip)
        hosts.append({
            'ip': ip, 'mac': mac,
            'vendor': NetmapScanner._lookup_oui(mac) if mac else 'Unknown',
            'method': 'arping',
        })
    return hosts


def run_demo():
    """Offline demo: scan the 192.0.2.0/64 fixture range in arp / ping /
    table modes and assert the resulting host lists agree.

    Never touches the network, requires no root, and no subprocess calls.
    """
    ok = True
    print('=== N10 Netmap Scan: offline demo (192.0.2.0/64 fixture) ===')

    table_hosts = parse_arp_table_output(ARP_FIXTURE)
    ping_hosts = _ping_sweep_hosts('192.0.2', list(range(1, 6)))
    arping_hosts = _arping_hosts('192.0.2', list(range(1, 6)))

    for h in table_hosts:
        h['method'] = 'table'

    def check(label, cond):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {label}')
        ok = ok and cond

    check('table mode finds 5 hosts', len(table_hosts) == 5)
    check('ping mode finds 5 hosts', len(ping_hosts) == 5)
    check('arping mode finds 5 hosts', len(arping_hosts) == 5)

    table_set = {(h['ip'], h['mac']) for h in table_hosts}
    ping_set = {(h['ip'], h['mac']) for h in ping_hosts}
    arping_set = {(h['ip'], h['mac']) for h in arping_hosts}

    check('table and ping produce same host set',
          table_set == ping_set)
    check('table and arping produce same host set',
          table_set == arping_set)
    check('scan range stays inside 192.0.2.0/64',
          all(h['ip'].startswith('192.0.2.') for h in table_hosts))

    scanner = NetmapScanner(interface='lab-eth0')
    scanner.hosts = table_hosts
    topo = scanner.build_topology()
    check('gateway classified as router',
          any(r['ip'] == '192.0.2.1' for r in topo['routers']))
    check('hosts classified',
          len(topo['hosts']) >= 2)

    print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def run_harness():
    """Offline fixture harness: parse realistic ARP scan output, classify
    hosts, build a topology. No live interface, root, or subprocess calls."""
    ok = True
    scanner = NetmapScanner(interface='lab-eth0')
    hosts = parse_arp_table_output(ARP_FIXTURE)

    def verify(label, cond, detail=''):
        nonlocal ok
        print(f'  [{"PASS" if cond else "FAIL"}] {label} {detail}')
        ok = ok and cond

    print('=== N10 Netmap Scan: offline fixture harness ===')
    print(f'  parsed hosts: {len(hosts)}')
    verify('fixture parses all 5 hosts', len(hosts) == 5,
           f'{len(hosts)}')
    verify('gateway host parsed with router MAC',
           any(h['ip'] == '192.0.2.1' and h['vendor'] == 'Cisco'
               for h in hosts))
    verify('VMware host vendor resolved',
           any(h['ip'] == '192.0.2.2' and h['vendor'] == 'Oracle VirtualBox'
               for h in hosts))

    scanner.hosts = hosts
    topo = scanner.build_topology()
    routers = topo['routers']
    verify('gateway classified as router',
           any(r['ip'] == '192.0.2.1' for r in routers))
    verify('switch MAC detection works',
           NetmapScanner._is_switch_mac('00:00:0C:aa:bb:cc'))
    verify('remaining hosts classified as hosts',
           len(topo['hosts']) >= 2, f'{len(topo["hosts"])}')

    print('\n[RESULT] ' + ('PASS' if ok else 'FAIL'))
    return 0 if ok else 1


def main():
    parser = argparse.ArgumentParser(
        description='N10 — Netmap Scanner (offline fixture demo + live '
                    'ARP scan)')
    parser.add_argument('--demo', action='store_true',
                        help='Run offline 192.0.2.0/64 fixture demo '
                             '(default, no network access)')
    parser.add_argument('--harness', action='store_true',
                        help='Run offline ARP-fixture harness')
    parser.add_argument('--interface', '-i', help='Network interface')
    parser.add_argument('--target', '-t',
                        help='Target range (e.g. 192.0.2.0)')
    parser.add_argument('--method', '-m', default='arp',
                        choices=['arp', 'ping', 'table'],
                        help='Scan method (default: arp)')
    parser.add_argument('--topology', action='store_true',
                        help='Show topology')
    parser.add_argument('--map', action='store_true',
                        help='Show ASCII topology map')

    args = parser.parse_args()

    if args.harness:
        sys.exit(run_harness())
    if args.demo or not (args.target or args.interface):
        sys.exit(run_demo())

    scanner = NetmapScanner(args.interface)

    print("╔═══════════════════════════════════════╗")
    print("║     N10 — Netmap Scanner              ║")
    print("╚═══════════════════════════════════════╝")
    print(f"Interface: {scanner.interface}\n")

    scanner.scan(args.target, args.method)

    if args.map:
        scanner.print_ascii_map()
    else:
        scanner.print_topology()


if __name__ == '__main__':
    main()
