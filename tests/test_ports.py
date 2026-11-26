#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""端口预设与端口字典解析。"""

import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cybercensus  # noqa: E402


class TestPorts(unittest.TestCase):
    def test_parse_mixed(self):
        self.assertEqual(cybercensus.parse_ports("80,443 8000-8002\n8080 # web"),
                         [80, 443, 8000, 8001, 8002, 8080])

    def test_parse_file(self):
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "ports.txt")
            with open(p, "w", encoding="utf-8") as f:
                f.write("# web\n80\n443,8443\n9000-9001\n")
            self.assertEqual(cybercensus.parse_ports_file(p),
                             [80, 443, 8443, 9000, 9001])

    def test_top_presets(self):
        self.assertEqual(len(cybercensus.top_ports(100)), 100)
        self.assertEqual(len(cybercensus.top_ports(1000)), 1000)
        self.assertIn(80, cybercensus.top_ports(100))
        self.assertIn(443, cybercensus.top_ports(100))

    def test_top_10000_capped(self):
        ports = cybercensus.top_ports(10000)
        self.assertGreater(len(ports), 5000)
        self.assertEqual(len(ports), len(set(ports)))


if __name__ == "__main__":
    unittest.main()
