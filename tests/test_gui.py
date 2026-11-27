#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_gui.py —— GUI 纯辅助函数的单元测试（不弹窗口）

asm_gui.pyw 不能被普通 import，用 importlib 按路径加载。
运行： python -m unittest discover tests -v
"""

import importlib.util
import os
import sys
import unittest

BASE = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, BASE)


def _load_gui():
    spec = importlib.util.spec_from_file_location(
        "asm_gui", os.path.join(BASE, "asm_gui.pyw"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


gui = _load_gui()


class TestParseTargets(unittest.TestCase):
    def test_mixed_input(self):
        names, domains, ips, errors = gui.parse_targets(
            "某某市人民医院 xx.gov.cn 1.2.3.4, 1.2.3.0/24")
        self.assertEqual(names, ["某某市人民医院"])
        self.assertEqual(domains, {"xx.gov.cn"})
        self.assertIn("1.2.3.4", ips)
        self.assertIn("1.2.3.1", ips)
        self.assertEqual(len(ips), 254)  # /24 展开去重（1.2.3.4 已含在内）
        self.assertEqual(errors, [])

    def test_oversized_cidr_error(self):
        names, domains, ips, errors = gui.parse_targets("1.2.3.0/16")
        self.assertEqual(len(errors), 1)
        self.assertIn("过大", errors[0])

    def test_empty_and_separators(self):
        names, domains, ips, errors = gui.parse_targets("  ，, ;; ")
        self.assertEqual((names, domains, ips, errors), ([], set(), set(), []))
        self.assertEqual(gui.parse_targets("")[0], [])

    def test_bare_word_is_name(self):
        names, domains, ips, errors = gui.parse_targets("abc")
        self.assertEqual(names, ["abc"])

    def test_garbage_cidr_is_name(self):
        # "abc/24" 无法解析为网段，按名称处理（与 CLI classify_target 一致）
        names, _, _, errors = gui.parse_targets("abc/24")
        self.assertEqual(names, ["abc/24"])
        self.assertEqual(errors, [])


class TestAssetRows(unittest.TestCase):
    def test_rows_sorted_and_translated(self):
        import argparse
        e = gui.cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        a1 = e.add_asset("b.example.com", 443, "https", source="anchor")
        a1.title = "确认站"
        a1.beian = "京ICP备12345678号"
        a1.findings.add("/.git/config|Git仓库泄露(.git)")
        e.anchor["beian"].add("京ICP备12345678号")
        a2 = e.add_asset("a.example.com", None, None, source="passive")
        e.evaluate()
        rows = gui.asset_rows(e)
        self.assertEqual(len(rows), 2)
        # 排序：确认在前
        self.assertEqual(rows[0][0], "确认")
        self.assertEqual(rows[0][1], "b.example.com")
        # 敏感发现列：去掉路径前缀只留说明
        self.assertIn("Git仓库泄露", rows[0][5])
        self.assertEqual(rows[1][5], "")
        # 归属说明是白话（含"备案号"字样），不是原始 A| 证据串
        self.assertIn("备案号", rows[0][6])
        # 云资产列（默认为空）
        self.assertEqual(rows[0][7], "")
        # tag 映射正确
        self.assertEqual(rows[0][8], "confirmed")
        self.assertEqual(rows[1][8], "unknown")

    def test_empty_engine(self):
        import argparse
        e = gui.cybercensus.Engine(argparse.Namespace(beian="", threads=10, timeout=5))
        self.assertEqual(gui.asset_rows(e), [])


class TestBuildArgs(unittest.TestCase):
    def test_passive_mode(self):
        args = gui.build_args("passive", ["fofa"])
        self.assertTrue(args.no_probe)
        self.assertFalse(args.active)
        self.assertFalse(args.verify)
        self.assertEqual(args.providers, ["fofa"])
        self.assertFalse(args.no_providers)
        self.assertTrue(args.yes)  # 授权由界面勾选框承担

    def test_verify_mode(self):
        args = gui.build_args("verify", ["hunter"])
        self.assertTrue(args.verify)
        self.assertFalse(args.active)
        self.assertFalse(args.no_probe)

    def test_active_mode_with_cscan(self):
        args = gui.build_args("active", [], cscan=True)
        self.assertTrue(args.active)
        self.assertTrue(args.cscan)

    def test_cscan_ignored_without_active(self):
        args = gui.build_args("verify", [], cscan=True)
        self.assertFalse(args.cscan)
        self.assertFalse(args.active)

    def test_no_platforms_local_only(self):
        args = gui.build_args("standard", [])
        self.assertTrue(args.no_providers)
        self.assertIsNone(args.providers)

    def test_output_formats(self):
        args = gui.build_args("standard", [])
        self.assertEqual(args.output_formats, "md,csv,html")
        args = gui.build_args("standard", [], formats=["md"])
        self.assertEqual(args.output_formats, "md")
        args = gui.build_args("standard", [], formats=["html", "csv"])
        self.assertEqual(args.output_formats, "html,csv")

    def test_webhook_passthrough(self):
        args = gui.build_args("standard", [], webhook="https://hook.example/x")
        self.assertEqual(args.webhook, "https://hook.example/x")

    def test_provider_keyword_passthrough(self):
        self.assertTrue(gui.build_args(
            "standard", [], provider_keyword=True).provider_keyword)
        self.assertFalse(gui.build_args("standard", []).provider_keyword)

    def test_paths_passthrough(self):
        self.assertFalse(gui.build_args("standard", []).no_paths)
        self.assertTrue(gui.build_args("standard", [], paths=False).no_paths)

    def test_fast_mode_passthrough(self):
        self.assertTrue(gui.build_args("standard", [], fast=True).fast)
        self.assertFalse(gui.build_args("standard", []).fast)

    def test_intel_passthrough(self):
        args = gui.build_args("standard", [], intel="C:/x/intel.json")
        self.assertEqual(args.intel, "C:/x/intel.json")
        self.assertEqual(gui.build_args("standard", []).intel, "")

    def test_packages_passthrough(self):
        args = gui.build_args("standard", [], packages=["a.apk", "C:/pkgs"])
        self.assertEqual(args.app_packages, ["a.apk", "C:/pkgs"])
        args = gui.build_args("standard", [])
        self.assertEqual(args.app_packages, [])

    def test_ext_tools(self):
        args = gui.build_args("standard", [])
        self.assertFalse(args.no_ext)
        self.assertIsNone(args.ext_tools)
        args = gui.build_args("standard", [], ext=False)
        self.assertTrue(args.no_ext)

    def test_asn_and_watch_passthrough(self):
        args = gui.build_args("standard", [], asn="AS64500, AS64501",
                              scan_asn=True, watch=30)
        self.assertEqual(args.asn, ["AS64500", "AS64501"])
        self.assertTrue(args.scan_asn)
        self.assertTrue(args.active)   # 扫描 ASN 隐含主动
        self.assertEqual(args.watch, 30)
        args = gui.build_args("standard", [])
        self.assertEqual(args.asn, [])
        self.assertFalse(args.scan_asn)
        self.assertEqual(args.watch, 0)

    def test_ports_priority(self):
        args = gui.build_args("standard", [], top=5)
        self.assertEqual(args.ports_list, list(gui.cybercensus.top_ports(5)))
        args = gui.build_args("standard", [], ports="80,443")
        self.assertEqual(args.ports_list, [80, 443])
        args = gui.build_args("standard", [], top=5, ports="8000-8002")
        # 自定义端口优先于 top
        self.assertEqual(args.ports_list, [8000, 8001, 8002])
        args = gui.build_args("standard", [])
        self.assertEqual(args.ports_list, list(gui.cybercensus.DEFAULT_PORTS))


class TestAssetHelpers(unittest.TestCase):
    def _asset(self, host, port=None, scheme=None):
        class A(object):
            pass
        a = A()
        a.host, a.ip, a.port, a.scheme = host, "", port, scheme
        return a

    def test_asset_url_default_ports(self):
        self.assertEqual(gui.App._asset_url(None, self._asset("a.com", 443, "https")),
                         "https://a.com")
        self.assertEqual(gui.App._asset_url(None, self._asset("a.com", 80, "http")),
                         "http://a.com")
        self.assertEqual(gui.App._asset_url(None, self._asset("a.com", 8443, "https")),
                         "https://a.com:8443")
        self.assertEqual(gui.App._asset_url(None, self._asset("a.com", None, None)),
                         "http://a.com")

    def test_sel_key(self):
        self.assertEqual(gui.App._sel_key(self._asset("a.com", 443, "https")),
                         "a.com|443")


if __name__ == "__main__":
    unittest.main(verbosity=2)
