"""Tests for the N10 Netmap Scanner offline fixture parsing."""

import os
import sys
import unittest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'firmware'))

import netmap_scan as ns


class ArpTableParsingTests(unittest.TestCase):

    def test_parses_all_fixture_hosts(self):
        hosts = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        self.assertEqual(len(hosts), 5)

    def test_ips_within_test_range(self):
        hosts = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        for h in hosts:
            self.assertTrue(h['ip'].startswith('192.0.2.'))

    def test_vendor_lookup_cisco(self):
        hosts = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        gw = next(h for h in hosts if h['ip'] == '192.0.2.1')
        self.assertEqual(gw['vendor'], 'Cisco')

    def test_vendor_lookup_vmware(self):
        hosts = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        vm = next(h for h in hosts if h['ip'] == '192.0.2.2')
        self.assertEqual(vm['vendor'], 'Oracle VirtualBox')

    def test_mac_uppercased(self):
        hosts = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        for h in hosts:
            self.assertEqual(h['mac'], h['mac'].upper())


class ModeConsistencyTests(unittest.TestCase):

    def setUp(self):
        self.base = '192.0.2'
        self.table = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        for h in self.table:
            h['method'] = 'table'
        self.ping = ns._ping_sweep_hosts(self.base, list(range(1, 6)))
        self.arping = ns._arping_hosts(self.base, list(range(1, 6)))

    def test_all_modes_find_five_hosts(self):
        self.assertEqual(len(self.table), 5)
        self.assertEqual(len(self.ping), 5)
        self.assertEqual(len(self.arping), 5)

    def test_modes_produce_consistent_host_sets(self):
        table_set = {(h['ip'], h['mac']) for h in self.table}
        ping_set = {(h['ip'], h['mac']) for h in self.ping}
        arping_set = {(h['ip'], h['mac']) for h in self.arping}
        self.assertEqual(table_set, ping_set)
        self.assertEqual(table_set, arping_set)

    def test_normalise_hosts_canonical(self):
        a = ns._normalise_hosts(self.table)
        b = ns._normalise_hosts(list(reversed(self.table)))
        self.assertEqual(a, b)


class TopologyTests(unittest.TestCase):

    def test_gateway_classified_as_router(self):
        scanner = ns.NetmapScanner(interface='lab-eth0')
        scanner.hosts = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        topo = scanner.build_topology()
        router_ips = [r['ip'] for r in topo['routers']]
        self.assertIn('192.0.2.1', router_ips)

    def test_router_vendor_detection(self):
        self.assertTrue(ns.NetmapScanner._is_router_vendor('Cisco'))
        self.assertTrue(ns.NetmapScanner._is_router_vendor('TP-Link'))
        self.assertFalse(ns.NetmapScanner._is_router_vendor('Intel'))

    def test_switch_mac_detection(self):
        self.assertTrue(ns.NetmapScanner._is_switch_mac('00:00:0c:aa:bb:cc'))
        self.assertFalse(ns.NetmapScanner._is_switch_mac('08:00:27:aa:bb:cc'))

    def test_hosts_classified(self):
        scanner = ns.NetmapScanner(interface='lab-eth0')
        scanner.hosts = ns.parse_arp_table_output(ns.ARP_FIXTURE)
        topo = scanner.build_topology()
        self.assertGreaterEqual(len(topo['hosts']), 2)


if __name__ == '__main__':
    unittest.main()
