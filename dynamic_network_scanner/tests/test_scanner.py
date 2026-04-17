import unittest

from dynamic_network_scanner.scanner import assess_risk, expand_targets, parse_ports


class ParsePortsTests(unittest.TestCase):
    def test_parse_ports_ranges_and_values(self):
        self.assertEqual(parse_ports("22,80,1000-1002"), [22, 80, 1000, 1001, 1002])

    def test_invalid_port_raises(self):
        with self.assertRaises(ValueError):
            parse_ports("0")


class ExpandTargetsTests(unittest.TestCase):
    def test_expand_cidr(self):
        self.assertEqual(expand_targets("192.168.1.0/30", max_hosts=10), ["192.168.1.1", "192.168.1.2"])

    def test_expand_ip(self):
        self.assertEqual(expand_targets("127.0.0.1", max_hosts=10), ["127.0.0.1"])


class AssessRiskTests(unittest.TestCase):
    def test_risk_scoring(self):
        score, notes = assess_risk([22, 443, 3306])
        self.assertGreaterEqual(score, 35)
        self.assertGreaterEqual(len(notes), 2)


if __name__ == "__main__":
    unittest.main()
