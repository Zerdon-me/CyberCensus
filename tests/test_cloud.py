#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""云资产识别 + 关联资产扩展（证书 O= 精确反查）。"""

import argparse
import os
import sys
import tempfile
import unittest
from unittest import mock

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import cybercensus as c  # noqa: E402


def make_engine():
    return c.Engine(argparse.Namespace(
        beian="", threads=2, timeout=3,
        out=tempfile.mkdtemp(prefix="cc_test_"),
        output_formats="html", no_probe=True))


class TestDetectCloud(unittest.TestCase):
    def test_asn_exact(self):
        self.assertEqual(c.detect_cloud("45090", ""), "腾讯云")
        self.assertEqual(c.detect_cloud("AS13335", ""), "Cloudflare")
        self.assertEqual(c.detect_cloud("16509", ""), "AWS")

    def test_org_keyword(self):
        self.assertEqual(c.detect_cloud("", "Hangzhou Alibaba Advertising Co."), "阿里云")
        self.assertEqual(c.detect_cloud("", "Amazon Technologies Inc."), "AWS")
        self.assertEqual(c.detect_cloud("", "tencent cloud computing"), "腾讯云")

    def test_cname(self):
        self.assertEqual(c.detect_cloud("", "", "foo.cdn.cloudflare.net"), "CDN/云加速")

    def test_non_cloud_empty(self):
        self.assertEqual(c.detect_cloud("12345", "Some Random Corp"), "")
        self.assertEqual(c.detect_cloud("", "", ""), "")


class TestExpandRelated(unittest.TestCase):
    def test_cert_org_expands_known_and_new_domains(self):
        e = make_engine()
        e.names = ["某公司"]
        e.anchor["orgs"] = {"某公司", "某公司科技有限公司"}
        e.anchor["domains"] = {"example.com"}
        e.domains = {"example.com"}

        fake = {"www.example.com", "api.example.com",
                "brand-new-domain.cn", "sub.brand-new-domain.cn"}
        with mock.patch.object(c, "crt_by_org", return_value=fake):
            e.expand_related_assets()

        hosts = {a.host for a in e.assets.values()}
        self.assertIn("www.example.com", hosts)          # 已知锚点域子域
        self.assertIn("api.example.com", hosts)
        self.assertIn("brand-new-domain.cn", hosts)      # 新根域入资产
        self.assertIn("brand-new-domain.cn", e.anchor["weak_domains"])

    def test_skips_names_already_searched(self):
        e = make_engine()
        e.names = ["某公司"]
        # org 里只有与主体名完全相同的，应被跳过（collect_passive 已反查过）
        e.anchor["orgs"] = {"某公司"}
        e.anchor["domains"] = set()
        e.domains = set()
        with mock.patch.object(c, "crt_by_org") as m:
            e.expand_related_assets()
            m.assert_not_called()

    def test_empty_orgs_noop(self):
        e = make_engine()
        e.names = []
        e.anchor["orgs"] = set()
        with mock.patch.object(c, "crt_by_org") as m:
            e.expand_related_assets()
            m.assert_not_called()


if __name__ == "__main__":
    unittest.main()
