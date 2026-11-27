#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
pivots.py —— 可插拔关联源（Pivot Sources）

设计（对应「关联资产扩展」的插件化）：
  · 每个 PivotSource 是一个独立关联源：给它引擎上下文，它产出 (来源标签, 候域名/资产) 候选
  · 候选一律交给引擎 _verify_candidate_domain 互证后才入锚点（插件只负责"找"，不负责"信"）
  · 内置源：
      CertOrgPivot        证书 O= / RDAP 注册人 / IP 归属组织 → crt.sh 精确反查
      ReverseWhoisPivot   注册人邮箱/组织名反查（whois fallback best-effort）
      CloudAffinityPivot  同云厂商 + 同 /24 邻居候选（供平台/同 IP 证据复核）
      PassiveDnsPivot     RapidDNS/hackertarget 历史解析强化（同 NS 邻居）
  · 第三方可注册自定义源：cybercensus.PIVOT_REGISTRY.register(MyPivot())
  · 可选数据源（需账号/接口）以 AVAILABLE=False 标注，默认不启用，
    拿到凭据后由适配器实现类自行开启——CyberCensus 不内置任何凭据。
"""

import re
import time

_QM_UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
          "(KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36")

try:
    from cybercensus import (crt_by_org, reverse_ip, rapiddns_sameip,
                             root_domain, log)
except Exception:          # 独立使用时允许降级
    def log(m, level="*"):
        print("[%s] %s" % (level, m))

    def crt_by_org(org, timeout=25):
        return set()

    def reverse_ip(ip, timeout=20):
        return set()

    def rapiddns_sameip(ip, timeout=20):
        return set()

    def root_domain(host):
        host = (host or "").strip().lower()
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) > 2 else host


class PivotSource(object):
    """关联源基类：子类实现 discover(ctx) 返回候选列表。"""
    name = "base"
    label = "基础关联源"
    # 需要账号/接口的源标 False；CyberCensus 不内置凭据
    available = True

    def discover(self, ctx):
        """ctx = Engine；返回 [(子来源标签, 候选域名 或 (域名, 说明)), ...]"""
        return []


class CertOrgPivot(PivotSource):
    """证书 O= / RDAP 注册人 / IP 归属组织 → crt.sh 精确反查。

    解决「集团用独立品牌、独立域名、云托管」的分散资产发现。
    """
    name = "cert-org"
    label = "证书O=精确反查"

    def discover(self, ctx):
        out = []
        names_lower = {n.strip().lower() for n in ctx.names if n and n.strip()}
        orgs = [o for o in sorted(set(ctx.anchor["orgs"]))
                if o and len(o) >= 4 and o.strip().lower() not in names_lower]
        for org in orgs[:4]:
            try:
                for h in crt_by_org(org):
                    h = str(h).strip().lower().rstrip(".")
                    if h and "." in h:
                        out.append(("cert-org:" + org[:30], h))
            except Exception:
                continue
        return out


class ReverseWhoisPivot(PivotSource):
    """注册人邮箱 / 组织名反查（best-effort）。

    从锚点 RDAP 结果提取注册邮箱，把同注册人的其他域名带出来。
    RDAP 响应里 emails/vCard 都可能有；失败静默返回空。
    """
    name = "reverse-whois"
    label = "注册人反查"

    def discover(self, ctx):
        out = []
        emails = set()
        for dom in list(ctx.anchor["domains"])[:3]:
            rd = ctx._rdap_for(dom) or {}
            for e in (rd.get("emails") or []):
                e = str(e).strip().lower()
                if "@" in e and not e.endswith(("example.com", "example.org")):
                    emails.add(e)
        if not emails:
            return out
        log("注册人反查：候选邮箱 %s" % "、".join(sorted(emails)[:3]))
        # 免费的 reverse-whois 公共源有限，先靠 crt.sh 的 mail= 查询兜底
        for e in list(emails)[:2]:
            try:
                from cybercensus import http_get
                url = ("https://crt.sh/?q=" + e.replace("@", "%40") + "&output=json")
                import json as _json
                import urllib.parse as _up
                data = _json.loads(http_get(url, timeout=25, retries=1))
                for rec in data or []:
                    for n in str(rec.get("name_value", "")).split("\n"):
                        n = n.strip().lower().lstrip("*.")
                        if n and "." in n:
                            out.append(("reverse-whois:" + e, n))
            except Exception:
                continue
        return out


class CloudAffinityPivot(PivotSource):
    """同云厂商 + 同 /24 邻居：把云托管资产的「邻居」列出来供平台证据复核。

    注意：邻居不等于同主体！这里只产出候选，由引擎的平台命中/页面证据把关。
    """
    name = "cloud-affinity"
    label = "同云邻居候选"

    def discover(self, ctx):
        out = []
        seen_net = set()
        for ip in list(ctx.anchor["ips"])[:8]:
            m = re.match(r"^(\d+\.\d+\.\d+)\.\d+$", ip or "")
            if not m:
                continue
            net = m.group(1)
            if net in seen_net:
                continue
            seen_net.add(net)
            # 快速同 IP 反查 + RapidDNS sameip（两者都是免费公开源）
            try:
                for h in reverse_ip(ip):
                    out.append(("cloud-sameip:" + ip, str(h).strip().lower()))
            except Exception:
                pass
            try:
                for h in rapiddns_sameip(ip):
                    out.append(("cloud-sameip:" + ip, str(h).strip().lower()))
            except Exception:
                pass
            time.sleep(0.5)      # 公共源节奏
        return out


class PassiveDnsPivot(PivotSource):
    """PassiveDNS 强化：对已确认锚点域再拉一次 RapidDNS 子域（含历史）。"""
    name = "passive-dns"
    label = "PassiveDNS 强化"

    def discover(self, ctx):
        out = []
        try:
            from cybercensus import rapiddns_subdomains
        except Exception:
            return out
        strong = sorted(set(ctx.anchor["domains"])
                        - set(ctx.anchor.get("weak_domains") or ()))
        for d in strong[:3]:
            try:
                for h in rapiddns_subdomains(d):
                    h = str(h).strip().lower().rstrip(".")
                    if h and "." in h:
                        out.append(("pdns:" + d, h))
            except Exception:
                continue
            time.sleep(0.8)
        return out


class OptionalAppchinaPivot(PivotSource):
    """应用汇 appchina.com 的公开 APP 搜索页（无需账号，HTML 解析 best-effort）。

    反爬较严、页面结构易变：失败静默返回空，不影响主流程。
    """
    name = "appchina"
    label = "应用汇 APP（公开页）"

    def discover(self, ctx):
        out = []
        try:
            from cybercensus import http_get
        except Exception:
            return out
        for name in list(ctx.names)[:2]:
            try:
                url = ("http://www.appchina.com/search/?keyword="
                       + urllib_parse_quote(name))
                html = http_get(url, timeout=15, retries=1)
            except Exception:
                continue
            # 提取包名（com.xxx.yyy）与标题；归属过滤交给引擎
            for m in re.finditer(r'href="[^"]*/app/([a-z0-9_.]+)"[^>]*>', html):
                pkg = m.group(1)
                if pkg and pkg not in out:
                    out.append(("appchina-pkg", pkg))
        return out


class QimaiWebPivot(PivotSource):
    """七麦数据 qimai.cn 网页版公开搜索页（无需账号，best-effort）。

    https://www.qimai.cn/search/index/m/search?k=<关键词>
    - 公开页可看到 APP 名称与厂商字段（部分数据需会员，这里只取公开渲染部分）
    - 反爬较严（UA/频率），失败静默返回空
    - 拿到的是「APP 名称 + 厂商」文本对，归属过滤交给引擎
    """
    name = "qimai-web"
    label = "七麦数据（网页版公开页）"

    def discover(self, ctx):
        out = []
        try:
            from cybercensus import http_get
        except Exception:
            return out
        for name in list(ctx.names)[:2]:
            try:
                url = ("https://www.qimai.cn/search/index/m/search?k="
                       + urllib_parse_quote(name))
                html = http_get(url, timeout=15, retries=1,
                                headers={"User-Agent": _QM_UA,
                                         "Referer": "https://www.qimai.cn/"})
            except Exception:
                continue
            # 公开列表页结构：APP 名与厂商多在 <a> / <td> 中；宽松提取文本对
            # 只收集「含中文的文本行 + 相邻厂商列」——解析失败即空
            for m in re.finditer(
                    r'<a[^>]+class="[^"]*list[^"]*"[^>]*>([^<]{2,40})</a>', html):
                txt = (m.group(1) or "").strip()
                if txt:
                    out.append(("qimai-app", txt))
        return out


class XiaolanbenWebPivot(PivotSource):
    """小蓝本 xiaolanben.com 企业关联公开页（无需账号部分，best-effort）。

    https://www.xiaolanben.com/pc/search?key=<关键词>
    - 未登录时能看到企业名/域名摘要；登录后数据更全（CyberCensus 不内置凭据）
    - 解析失败/需要登录时静默返回空
    """
    name = "xiaolanben-web"
    label = "小蓝本（企业关联公开页）"

    def discover(self, ctx):
        out = []
        try:
            from cybercensus import http_get
        except Exception:
            return out
        for name in list(ctx.names)[:2]:
            try:
                url = ("https://www.xiaolanben.com/pc/search?key="
                       + urllib_parse_quote(name))
                html = http_get(url, timeout=15, retries=1,
                                headers={"User-Agent": _QM_UA})
            except Exception:
                continue
            # 宽松提取页面里的域名候选（含 icp/企业摘要中出现的主域）
            for m in re.finditer(
                    r'([a-z0-9][a-z0-9\-]{1,40}\.(?:com|cn|net|com\.cn|net\.cn|org\.cn))',
                    html, re.I):
                d = m.group(1).strip().lower()
                if d and "." in d and len(d) > 5:
                    out.append(("xiaolanben-dom", d))
        return out


def urllib_parse_quote(s):
    import urllib.parse
    return urllib.parse.quote(str(s or ""))


# 需要账号/接口的可选源（占位：标注能力与所需凭据，CyberCensus 不内置凭据）
OPTIONAL_SOURCES = [
    {"name": "qimai-vip", "label": "七麦数据（会员接口）",
     "needs": "七麦账号/Cookie", "status": "网页版公开页已内置（qimai-web）"},
    {"name": "xiaohongshu", "label": "小红书企业号", "needs": "小红书 Cookie",
     "status": "反爬较强，建议人工查询"},
    {"name": "xiaolanben-vip", "label": "小蓝本（会员接口）",
     "needs": "小蓝本账号", "status": "网页版公开页已内置（xiaolanben-web）"},
]


class PivotRegistry(object):
    """关联源注册表：内置 + 用户注册，按 available 过滤。"""

    def __init__(self):
        self._sources = []

    def register(self, source):
        if isinstance(source, PivotSource) and source not in self._sources:
            self._sources.append(source)

    def unregister(self, name):
        self._sources = [s for s in self._sources if s.name != name]

    def enabled(self, only=None):
        out = []
        for s in self._sources:
            if not s.available:
                continue
            if only and s.name not in only:
                continue
            out.append(s)
        return out

    def names(self):
        return [s.name for s in self._sources if s.available]

    def describe(self):
        rows = []
        for s in self._sources:
            rows.append((s.name, s.label, "可用" if s.available else "需凭据（未启用）"))
        for o in OPTIONAL_SOURCES:
            rows.append((o["name"], o["label"], o["status"]))
        return rows


class AppSource(PivotSource):
    """APP 发现源基类：search(names) 返回 [(名称, 开发者, 包名, 依据), ...]。"""

    def search(self, names):
        return []


# 默认注册表（模块级单例）：Engine 与外部共享
PIVOT_REGISTRY = PivotRegistry()
PIVOT_REGISTRY.register(CertOrgPivot())
PIVOT_REGISTRY.register(ReverseWhoisPivot())
PIVOT_REGISTRY.register(CloudAffinityPivot())
PIVOT_REGISTRY.register(PassiveDnsPivot())
PIVOT_REGISTRY.register(OptionalAppchinaPivot())
PIVOT_REGISTRY.register(QimaiWebPivot())
PIVOT_REGISTRY.register(XiaolanbenWebPivot())

# APP 发现源注册表：默认空（itunes 内置在 Engine 里）；
# 用户实现 QimaiSource / XiaolanbenSource 并 register() 即可启用可选源
APP_REGISTRY = PivotRegistry()
