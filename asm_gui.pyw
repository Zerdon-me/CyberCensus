#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
asm_gui.pyw —— 互联网暴露面测绘工具 图形界面（现代深色主题）

依赖：customtkinter（双击 启动界面.bat 会自动安装，或手动 pip install customtkinter）

启动方式（任选其一）：
  1. 双击 启动界面.bat
  2. 双击本文件（.pyw 由 pythonw 运行，无黑窗口）
  3. 命令行： pyw -3.11 asm_gui.pyw

自检（构建界面后立即销毁，验证无异常）：
  py -3.11 asm_gui.pyw --smoke

打包成单个 exe（可选）：
  pyinstaller --onefile --windowed --collect-all customtkinter asm_gui.pyw
"""

import argparse
import csv
import json
import os
import queue
import re
import subprocess
import sys
import threading
import time
import traceback
import webbrowser

# PyInstaller 单文件模式下 __file__ 指向临时解压目录（_MEIPASS），
# config.json / 输出目录必须定位到 exe 所在目录
if getattr(sys, "frozen", False):
    BASE_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    BASE_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, BASE_DIR)

import cybercensus                # noqa: E402
import providers as prov_layer  # noqa: E402
import tool_updater               # noqa: E402

try:
    import customtkinter as ctk
except ImportError:
    import tkinter as tk
    from tkinter import messagebox
    _r = tk.Tk()
    _r.withdraw()
    messagebox.showerror(
        "缺少界面依赖",
        "未安装 customtkinter。\n\n请先运行：\n    pip install customtkinter\n\n"
        "或直接双击 启动界面.bat（会自动安装）。")
    raise SystemExit(1)

from tkinter import messagebox, filedialog, Menu, PhotoImage  # noqa: E402

APP_TITLE = "CyberCensus v%s · 互联网暴露面测绘工具" % cybercensus.__version__


def _asset_path(*parts):
    base = getattr(sys, "_MEIPASS", "") if getattr(sys, "frozen", False) else BASE_DIR
    return os.path.join(base, *parts)
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
TERMS_URL = "https://github.com/Zerdon-me/CyberCensus/blob/main/TERMS.md"
TERMS_PATH = os.path.join(BASE_DIR, "TERMS.md")
TERMS_ACCEPTED = os.path.join(BASE_DIR, ".terms_accepted")

# 界面模式选项 -> 流水线模式
MODE_MAP = {"被动": "passive", "标准": "standard", "复核": "verify", "主动": "active"}
MODE_ORDER = ["被动", "标准", "复核", "主动"]
MODE_HINTS = {
    "被动": "不向目标发送任何请求；仅 subfinder 属于纯被动外部工具",
    "标准": "只探测主域名建立锚点，httpx / wafw00f 参与",
    "复核": "对疑似资产补一次 HTTP 复核（会触碰目标）",
    "主动": "端口扫描 + Web 指纹 + 敏感路径 + nuclei（需授权）",
}
# 模式视觉标识：(英文代号, 主色, 悬停色, 一句话说明, 卡片能力标签)
# 主色 = 信号色：模式语义（被动=安全青 / 标准=行动蓝 / 复核=等待琥珀 / 主动=警示红）
MODE_META = {
    "被动": ("PASSIVE", "#2ee6d6", "#5ff0e4", "零触碰 · 纯第三方数据",
             ["零触碰", "subfinder", "8 被动源"]),
    "标准": ("STANDARD", "#4d9fff", "#7db8ff", "锚点探测 · 默认模式",
             ["锚点探测", "httpx", "wafw00f"]),
    "复核": ("VERIFY", "#f5c451", "#ffd97a", "疑似资产存活复核",
             ["存活复核", "httpx", "WAF"]),
    "主动": ("ACTIVE", "#ff7b72", "#ffa198", "端口扫描 + 敏感路径 + nuclei",
             ["端口扫描", "敏感路径", "nuclei"]),
}
# 能力矩阵：模式 -> [(能力, 是否启用), ...]
MODE_CAPS = {
    "被动": [("被动源", True), ("subfinder", True), ("httpx", False),
             ("wafw00f", False), ("端口扫描", False), ("nuclei", False)],
    "标准": [("被动源", True), ("subfinder", True), ("httpx", True),
             ("wafw00f", True), ("端口扫描", False), ("nuclei", False)],
    "复核": [("被动源", True), ("subfinder", True), ("httpx", True),
             ("wafw00f", True), ("端口扫描", False), ("nuclei", False)],
    "主动": [("被动源", True), ("subfinder", True), ("httpx", True),
             ("wafw00f", True), ("端口扫描", True), ("nuclei", True)],
}

PLATFORM_LABELS = [
    ("fofa", "FOFA"),
    ("zerozone", "0.zone 零零信安"),
    ("hunter", "鹰图 Hunter"),
    ("daydaymap", "DayDayMap"),
    ("zoomeye", "ZoomEye 知道创宇"),
    ("quake", "360 Quake"),
    ("shodan", "Shodan"),
    ("censys", "Censys"),
]

# ---- 视觉系统「哨兵 Sentinel」：量子井（默认）/ 晨档 / 荧灰 ----
ACCENT = "#2ee6d6"        # 品牌信号色（量子井）
ACCENT_HOVER = "#5ff0e4"
ACCENT_DIM = "#0f9488"
RED = "#ff7b72"
RED_HOVER = "#ffa198"
GREEN = "#4ade80"
ORANGE = "#f5c451"
GRAY = "#6f8299"          # 次要文字
TEXT = "#d5e2ee"          # 主文字
BG = "#060a0f"            # 窗口底色
PANEL = "#080d13"         # 侧栏
CARD = "#0b1219"          # 卡片
CARD_HI = "#101a24"       # 悬停/选中卡片
STROKE = "#16222e"        # 描边
STROKE_HI = "#24384a"     # 悬停描边
HEADER_BG = "#070b10"     # 头栏
MONO = "Consolas"         # 等宽字体（Windows 自带）

LOG_PALETTE = {
    "dark": {"hdr": "#5ff0e4", "good": "#4ade80", "warn": "#f5c451", "norm": "#a4b8c9"},
}

# 默认主题 token（量子井）；切换主题时 apply_theme() 会整体覆盖这些名字
TREE_BG = "#080d13"
TREE_FG = "#c9d7e3"
TREE_HEAD = "#0d1620"
TREE_SEL = "#104a44"
LOG_NORM = "#a4b8c9"
ON_ACCENT = "#03110f"      # 放在品牌色（ACCENT）上的文字颜色，随主题切换
SIGNAL = "#2ee6d6"         # 选中项左侧信号线颜色

# ---------------------------------------------------------------------------
# 主题系统（原创设计，非参考品复刻）
#
# 设计语言「哨兵 Sentinel」：
#   · 深色主题「量子井」——像一口深井：近黑底 + 微弱纵向渐变层次（井壁），
#     品牌色只用于"信号"（状态点/进度/选中），大面积界面保持安静灰阶
#   · 浅色主题「晨档」——档案纸感：暖白底 + 细分隔线代替卡片描边，
#     强调色降饱和为钢青，适合白天与打印截图
#   · 第三主题「荧灰」——高对比无彩灰 + 单点琥珀强调，给老显示器/投影
#
# 与常见安全工具的区别：我们不用"满屏卡片描边"，而是"分区留白 + 一条
# 2px 信号线"标记选中项；选中态靠"信号线 + 文字变色"而不是整块填充。
# ---------------------------------------------------------------------------
THEMES = {
    "量子井": {
        "ACCENT": "#2ee6d6", "ACCENT_HOVER": "#5ff0e4", "ACCENT_DIM": "#0f9488",
        "RED": "#ff7b72", "RED_HOVER": "#ffa198",
        "GREEN": "#4ade80", "ORANGE": "#f5c451",
        "GRAY": "#6f8299", "TEXT": "#d5e2ee",
        "BG": "#060a0f", "PANEL": "#080d13",
        "CARD": "#0b1219", "CARD_HI": "#101a24",
        "STROKE": "#16222e", "STROKE_HI": "#24384a",
        "HEADER_BG": "#070b10",
        "TREE_BG": "#080d13", "TREE_FG": "#c9d7e3", "TREE_HEAD": "#0d1620",
        "TREE_SEL": "#104a44", "LOG_NORM": "#a4b8c9",
        "ON_ACCENT": "#03110f",
        "SIGNAL": "#2ee6d6",         # 选中项左侧 2px 信号线
        "TITLEBAR": False,
    },
    "晨档": {
        "ACCENT": "#0f6e8c", "ACCENT_HOVER": "#1587ad", "ACCENT_DIM": "#0b556d",
        "RED": "#c2453a", "RED_HOVER": "#d95c50",
        "GREEN": "#2f8a5b", "ORANGE": "#b97f1f",
        "GRAY": "#5c6b7a", "TEXT": "#1d2b38",
        "BG": "#f7f5f1", "PANEL": "#efece6",
        "CARD": "#ffffff", "CARD_HI": "#f2ede4",
        "STROKE": "#ddd8cf", "STROKE_HI": "#b8b2a5",
        "HEADER_BG": "#f7f5f1",
        "TREE_BG": "#ffffff", "TREE_FG": "#1d2b38", "TREE_HEAD": "#efece6",
        "TREE_SEL": "#d7ecf2", "LOG_NORM": "#3d4d5c",
        "ON_ACCENT": "#ffffff",
        "SIGNAL": "#0f6e8c",
        "TITLEBAR": True,
    },
    "荧灰": {
        "ACCENT": "#f5a623", "ACCENT_HOVER": "#ffbe4d", "ACCENT_DIM": "#a67217",
        "RED": "#ff6b6b", "RED_HOVER": "#ff9494",
        "GREEN": "#7dd87d", "ORANGE": "#f5a623",
        "GRAY": "#8a949e", "TEXT": "#e8ecee",
        "BG": "#121417", "PANEL": "#14171a",
        "CARD": "#171b1f", "CARD_HI": "#1d2329",
        "STROKE": "#262c33", "STROKE_HI": "#39424c",
        "HEADER_BG": "#101316",
        "TREE_BG": "#14171a", "TREE_FG": "#d5dde3", "TREE_HEAD": "#1b2025",
        "TREE_SEL": "#3d3208", "LOG_NORM": "#b5c0c9",
        "ON_ACCENT": "#1a1205",
        "SIGNAL": "#f5a623",
        "TITLEBAR": False,
    },
}


def apply_theme(name):
    """把主题 token 写进模块级常量；布局代码引用这些名字，无需改动。"""
    t = THEMES.get(name) or THEMES["量子井"]
    g = sys.modules[__name__]
    for key, val in t.items():
        setattr(g, key, val)
    return t


# ---------------------------------------------------------------------------
# 纯辅助函数（不依赖窗口，便于单元测试）
# ---------------------------------------------------------------------------
def parse_targets(text):
    """把用户输入拆成 (names, domains, ips, errors)。

    支持逗号/分号/空白分隔多个目标，逐个自动识别 名称 / 域名 / IP / CIDR。
    """
    names, domains, ips, errors = [], set(), set(), []
    tokens = [t for t in re.split(r"[,，;；\s]+", (text or "").strip()) if t]
    for t in tokens:
        kind = cybercensus.classify_target(t)
        if kind == "ip":
            ips.add(t)
        elif kind == "cidr":
            err = cybercensus._add_ip_target(ips, t)
            if err:
                errors.append(err)
        elif kind == "domain":
            domains.add(t.lower())
        else:
            names.append(t)
    return names, domains, ips, errors


def build_args(mode, platforms, threads=20, provider_pages=1,
               cscan=False, top=0, ports="", ports_file="", full_ports=False,
               out="cybercensus_out", config=CONFIG_PATH, debug_provider=False,
               formats=None, sensitive=None, probe_interval=0.0, webhook="",
               ext=True, packages=None, intel="", fast=False, paths=True,
               provider_keyword=False, asn="", scan_asn=False, watch=0,
               scope_file="", only_scope=False, keep=0):
    """由界面选择构造 argparse.Namespace（与 CLI 参数一一对应）。

    mode: passive / standard / verify / active
    formats: 输出格式列表（"md"/"csv"/"json" 的子集），空=全部
    sensitive: 敏感路径探测（None=跟随模式：active 开，其它关）
    ext: 调用本机已安装的外部工具（subfinder/httpx/wafw00f/nuclei）
    """
    active = (mode == "active")
    if scan_asn:
        active = True   # 扫描 ASN 网段属于主动行为
    if sensitive is None:
        sensitive = active
    args = argparse.Namespace(
        beian="",
        threads=max(1, int(threads)),
        timeout=10.0,
        scan_timeout=2.5,
        out=out,
        output_formats=(",".join(formats) if formats else "md,csv,html"),
        no_probe=(mode == "passive"),
        no_discover=False,   # 名称模式默认启用搜索引擎官网自举（被动模式自动跳过）
        probe_found=False,
        probe_limit=100,
        probe_interval=float(probe_interval or 0),
        sensitive=bool(sensitive),
        no_sensitive=not sensitive,
        sensitive_limit=200,
        verify=(mode == "verify"),
        verify_limit=0,
        active=active,
        cscan=bool(cscan and active),
        full_ports=bool(full_ports),
        top=int(top),
        ports=ports,
        ports_file=ports_file or "",
        quiet=False,
        providers=(list(platforms) if platforms else None),
        provider_pages=max(1, int(provider_pages)),
        provider_limit=0,
        no_providers=(not platforms),
        config=config,
        debug_provider=bool(debug_provider),
        webhook=webhook or "",
        ext_tools=None,
        no_ext=not bool(ext),
        ext_sub_limit=3000,
        app_packages=list(packages or []),
        intel=intel or "",
        fast=bool(fast),
        no_paths=not bool(paths),
        path_limit=30,
        provider_keyword=bool(provider_keyword),
        asn=[x.strip() for x in re.split(r"[,;\s]+", asn or "") if x.strip()],
        scan_asn=bool(scan_asn),
        watch=max(0, int(watch or 0)),
        scope=[],
        scope_file=scope_file or "",
        only_scope=bool(only_scope),
        keep=max(0, int(keep or 0)),
        yes=True,   # 授权确认由界面勾选框承担，不再走 input()
    )
    # 端口列表（与 CLI main 相同的优先级：字典 > 自定义 > top > 内置全表）
    if ports_file:
        try:
            args.ports_list = cybercensus.parse_ports_file(ports_file)
        except Exception:
            args.ports_list = list(cybercensus.DEFAULT_PORTS)
    elif ports:
        args.ports_list = cybercensus.parse_ports(ports)
    elif args.top > 0:
        args.ports_list = cybercensus.top_ports(args.top)
    else:
        args.ports_list = list(cybercensus.DEFAULT_PORTS)
    if not args.ports_list:
        args.ports_list = list(cybercensus.DEFAULT_PORTS)
    return args


def _to_int(s, default):
    try:
        return int(str(s).strip())
    except Exception:
        return default


def asset_rows(eng, max_evidence=2):
    """从引擎结果提取表格行：[(分类, 主机, IP, 端口, 标题, 敏感发现, 归属说明, 云, tag), ...]。

    按 确认 → 疑似 → 存疑 排序；归属说明用白话证据（截断到 max_evidence 条）。
    纯函数，供界面表格与单元测试共用。
    """
    order = {"确认": 0, "疑似": 1, "存疑": 2}
    tag_map = {"确认": "confirmed", "疑似": "suspect", "存疑": "unknown"}
    rows = []
    for a in eng.assets.values():
        plain = cybercensus.plain_evidence(a.evidence, max_items=max_evidence) or "—"
        findings = "、".join(sorted(f.split("|", 1)[-1] for f in a.findings))
        rows.append((
            a.confidence, a.host or a.ip or "", a.ip or "", str(a.port or ""),
            a.title or "", findings, plain,
            getattr(a, "cloud", "") or "", tag_map.get(a.confidence, "unknown"),
        ))
    rows.sort(key=lambda r: (order.get(r[0], 3), r[1], r[3]))
    return rows


# ---------------------------------------------------------------------------
# 主窗口
# ---------------------------------------------------------------------------
class App(ctk.CTk):
    def __init__(self):
        super().__init__()
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")

        self.title(APP_TITLE)
        try:
            png = _asset_path("docs", "logo.png")
            if os.path.isfile(png):
                self._icon_img = PhotoImage(file=png)
                self.iconphoto(True, self._icon_img)
            else:
                ico = _asset_path("docs", "logo.ico")
                if os.path.isfile(ico):
                    self.iconbitmap(ico)
        except Exception:
            pass
        w, h = 1180, 860
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        self.geometry("%dx%d+%d+%d" % (w, h, max(0, (sw - w) // 2),
                                       max(0, (sh - h) // 2 - 24)))
        self.minsize(1040, 700)
        self.configure(fg_color=BG)

        # 字体阶梯（等宽字体营造终端/仪表盘观感）
        self.f_brand = ctk.CTkFont(family=MONO, size=21, weight="bold")
        self.f_mono = ctk.CTkFont(family=MONO, size=12)
        self.f_mono_sm = ctk.CTkFont(family=MONO, size=10)
        self.f_title = ctk.CTkFont(size=13, weight="bold")
        self.f_body = ctk.CTkFont(size=12)
        self._mode = "标准"

        self._queue = queue.Queue()
        self._worker = None
        self._stop_flag = threading.Event()
        self._last_out_dir = None
        self._last_md_path = None
        self._last_html_path = None
        self._last_engine = None
        self._scan_start = 0.0
        self._eta = None
        self._auto_timer = None
        self._last_watch = 0
        self._checked = set()       # 勾选的资产 key: "host|port"
        self._sort_col = None
        self._sort_rev = False
        self._prog_samples = []      # [(time, pct), ...] 用于按最近速率估算
        self._eta_samples = []       # 最近的原始 ETA，取中位数抗抖动
        self._last_prog_time = 0.0
        self._prog_stage = ""

        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(1, weight=1)

        self._build_header()
        self._build_sidebar()
        self._build_main()
        self._build_advanced_dialog()
        self._refresh_platforms()
        self._select_mode("标准", initial=True)
        self.protocol("WM_DELETE_WINDOW", self._on_close)
        self.bind("<Control-Return>", lambda e: self._on_start())
        self.after(100, self._poll)
        self.after(2000, self._tick_eta)
        self.after(3000, self._cruise_poll)
        self.after(250, self._check_terms)
        # 恢复上次选择的主题（.ui_theme 保存）
        try:
            with open(os.path.join(BASE_DIR, ".ui_theme"), "r",
                      encoding="utf-8") as fh:
                saved = fh.read().strip()
            if saved in THEMES and saved != "量子井":
                self._set_theme(saved)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # 品牌头栏（横贯顶部）
    # ------------------------------------------------------------------
    def _build_header(self):
        bar = ctk.CTkFrame(self, corner_radius=0, fg_color=HEADER_BG)
        self._header = bar
        bar.grid(row=0, column=0, columnspan=2, sticky="ew")
        bar.grid_columnconfigure(1, weight=1)

        ctk.CTkLabel(bar, text="◈", font=ctk.CTkFont(family=MONO, size=28, weight="bold"),
                     text_color=ACCENT).grid(row=0, column=0, rowspan=2, padx=(24, 12),
                                             pady=(10, 8))
        ctk.CTkLabel(bar, text="CYBERCENSUS", font=self.f_brand, text_color=TEXT
                     ).grid(row=0, column=1, sticky="sw", pady=(12, 0))
        ctk.CTkLabel(bar, text="互联网暴露面测绘  //  ATTACK SURFACE INTELLIGENCE",
                     text_color=GRAY, font=self.f_mono_sm
                     ).grid(row=1, column=1, sticky="nw", pady=(0, 12))

        ctk.CTkLabel(bar, text=" V%s " % cybercensus.__version__,
                     font=self.f_mono_sm, text_color=ACCENT,
                     fg_color="#0a2230", corner_radius=4, height=20, padx=6
                     ).grid(row=0, column=2, rowspan=2, padx=(0, 12))

        self.lbl_mode_tag = ctk.CTkLabel(
            bar, text="STANDARD", font=ctk.CTkFont(family=MONO, size=11, weight="bold"),
            text_color=ACCENT, fg_color=CARD, corner_radius=6, height=24, padx=12,
            border_width=1, border_color=STROKE)
        self.lbl_mode_tag.grid(row=0, column=3, rowspan=2, padx=(0, 10))

        # 状态胶囊
        self.var_status = ctk.StringVar(value="● 就绪")
        self.lbl_status = ctk.CTkLabel(
            bar, textvariable=self.var_status, font=ctk.CTkFont(size=12, weight="bold"),
            text_color=GRAY, fg_color=CARD, corner_radius=12, padx=14, height=26,
            border_width=1, border_color=STROKE)
        self.lbl_status.grid(row=0, column=4, rowspan=2, padx=(0, 24))

        # 底部品牌色细线
        ctk.CTkFrame(bar, height=1, fg_color="#123b4a"
                     ).grid(row=2, column=0, columnspan=5, sticky="ew")

    def _set_status(self, text, color):
        self.var_status.set(text)
        self.lbl_status.configure(text_color=color)

    # ------------------------------------------------------------------
    # 侧边栏（紧凑分区：分区徽标 + 无框卡片，降低视觉噪音）
    # ------------------------------------------------------------------
    def _section(self, parent, text):
        ctk.CTkLabel(parent, text=text, font=self.f_mono_sm, text_color=GRAY,
                     anchor="w").pack(fill="x", padx=18, pady=(14, 6))

    def _build_sidebar(self):
        sb = ctk.CTkFrame(self, width=268, corner_radius=0, fg_color=PANEL)
        sb.grid(row=1, column=0, sticky="nsw")
        sb.grid_propagate(False)
        self._sidebar = sb

        # ---- 平台卡片 ----
        self._section(sb, "// 01  PLATFORMS  ·  测绘平台")
        card = ctk.CTkFrame(sb, corner_radius=10, fg_color=CARD,
                            border_width=1, border_color=STROKE)
        card.pack(fill="x", padx=14)
        self.sw_platforms = {}
        self.var_platforms = {}
        for name, label in PLATFORM_LABELS:
            var = ctk.BooleanVar(value=True)
            sw = ctk.CTkSwitch(card, text=label, variable=var, onvalue=True,
                               offvalue=False, font=self.f_body,
                               progress_color=ACCENT, button_color=ACCENT)
            sw.pack(anchor="w", padx=14, pady=5)
            self.sw_platforms[name] = sw
            self.var_platforms[name] = var
        ctk.CTkLabel(card, text="● 未配 Key 也可运行：8 个本地被动源",
                     text_color=GREEN, font=self.f_mono_sm
                     ).pack(anchor="w", padx=14, pady=(6, 12))

        # ---- 本机外部引擎（状态面板）----
        self._section(sb, "// 02  ENGINES  ·  增强引擎（本机安装）")
        card3 = ctk.CTkFrame(sb, corner_radius=10, fg_color=CARD,
                             border_width=1, border_color=STROKE)
        card3.pack(fill="x", padx=14)
        self._engine_rows = {}
        for name in ("subfinder", "httpx", "wafw00f", "nuclei"):
            row = ctk.CTkFrame(card3, fg_color="transparent")
            row.pack(fill="x", padx=14, pady=2)
            dot = ctk.CTkLabel(row, text="○", font=self.f_mono_sm,
                               text_color="#3d5064")
            dot.pack(side="left")
            nm = ctk.CTkLabel(row, text=name, font=self.f_mono,
                              text_color=GRAY)
            nm.pack(side="left", padx=(7, 0))
            st = ctk.CTkLabel(row, text="MISSING", font=self.f_mono_sm,
                              text_color="#3d5064")
            st.pack(side="right")
            self._engine_rows[name] = (dot, nm, st)
        self._refresh_engine_rows()
        ctk.CTkLabel(card3, text="未安装的引擎自动跳过（纯被动仅 subfinder）",
                     text_color=GRAY, font=self.f_mono_sm, wraplength=220,
                     justify="left").pack(anchor="w", padx=14, pady=(6, 4))
        self.btn_update_tools = ctk.CTkButton(
            card3, text="⟳  检查 / 更新增强引擎", height=30, corner_radius=7,
            fg_color="transparent", border_width=1, border_color=STROKE,
            hover_color=CARD_HI, text_color=ACCENT, font=self.f_mono_sm,
            command=self._open_engine_updater)
        self.btn_update_tools.pack(fill="x", padx=12, pady=(0, 12))

        # ---- 操作 ----
        self._section(sb, "// 03  CONFIG  ·  配置")
        card2 = ctk.CTkFrame(sb, corner_radius=10, fg_color=CARD,
                             border_width=1, border_color=STROKE)
        card2.pack(fill="x", padx=14)
        ctk.CTkButton(card2, text="⚙  配置平台 Key…", command=self._open_key_dialog,
                      height=34, corner_radius=8, fg_color="transparent",
                      border_width=1, border_color=STROKE, hover_color=CARD_HI,
                      text_color=TEXT, font=self.f_body
                      ).pack(fill="x", padx=12, pady=(12, 6))
        ctk.CTkButton(card2, text="ⓘ  关于 / 使用条款", command=self._open_about,
                      height=30, corner_radius=8, fg_color="transparent",
                      border_width=1, border_color=STROKE, hover_color=CARD_HI,
                      text_color=GRAY, font=self.f_mono_sm
                      ).pack(fill="x", padx=12, pady=(0, 12))

        # ---- 底部图例 ----
        legend = ctk.CTkFrame(sb, fg_color="transparent")
        legend.pack(side="bottom", fill="x", padx=18, pady=14)
        # 主题切换（量子井 / 晨档 / 荧灰）
        ctk.CTkLabel(legend, text="// THEME  ·  主题", font=self.f_mono_sm,
                     text_color=GRAY, anchor="w").pack(fill="x")
        self.seg_theme = ctk.CTkSegmentedButton(
            legend, values=list(THEMES.keys()), command=self._on_theme_change,
            font=self.f_mono_sm, selected_color=ACCENT,
            selected_hover_color=ACCENT_HOVER, unselected_color=CARD,
            unselected_hover_color=CARD_HI, text_color=TEXT)
        self.seg_theme.set("量子井")
        self.seg_theme.pack(fill="x", pady=(4, 10))
        try:
            with open(os.path.join(BASE_DIR, ".ui_theme"), "r",
                      encoding="utf-8") as fh:
                saved = fh.read().strip()
            if saved in THEMES:
                self.seg_theme.set(saved)
        except Exception:
            pass
        ctk.CTkLabel(legend, text="// EVIDENCE GRADE", font=self.f_mono_sm,
                     text_color=GRAY, anchor="w").pack(fill="x")
        for color, label in ((GREEN, "确认 · 强证据 ≥1"),
                             (ORANGE, "疑似 · 较强证据 ≥2"),
                             (GRAY, "剔除 · 证据不足")):
            ctk.CTkLabel(legend, text="● " + label, font=self.f_mono_sm,
                         text_color=color, anchor="w").pack(fill="x", pady=1)
        ctk.CTkLabel(legend, text="PASSIVE-FIRST · A/B/C GRADING",
                     font=self.f_mono_sm, text_color="#3d5064",
                     anchor="w").pack(fill="x", pady=(8, 0))

    # ------------------------------------------------------------------
    # 主工作区
    # ------------------------------------------------------------------
    def _on_theme_change(self, name):
        try:
            with open(os.path.join(BASE_DIR, ".ui_theme"), "w",
                      encoding="utf-8") as fh:
                fh.write(name)
        except Exception:
            pass
        try:
            self._set_theme(name)
        except Exception:
            pass

    def _refresh_engine_rows(self):
        try:
            avail = set(cybercensus.ext_available())
        except Exception:
            avail = set()
        for name, (dot, nm, st) in getattr(self, "_engine_rows", {}).items():
            on = name in avail
            dot.configure(text="●" if on else "○",
                          text_color=GREEN if on else "#3d5064")
            nm.configure(text_color=TEXT if on else GRAY)
            st.configure(text="READY" if on else "MISSING",
                         text_color=GREEN if on else "#3d5064")

    # ------------------------------------------------------------------
    # 增强引擎检查 / 更新
    # ------------------------------------------------------------------
    def _open_engine_updater(self):
        if self._worker and self._worker.is_alive():
            messagebox.showwarning("正在扫描", "扫描进行中，结束后再更新引擎。")
            return
        win = ctk.CTkToplevel(self)
        win.title("增强引擎 · 检查 / 更新")
        win.geometry("780x580")
        win.configure(fg_color=BG)
        win.transient(self)
        win.after(300, lambda: win.grab_set())
        ctk.CTkLabel(win, text="// ENGINE UPDATE  ·  官方 Release 自动升级",
                     font=self.f_mono, text_color=ACCENT).pack(
                         anchor="w", padx=18, pady=(14, 2))
        ctk.CTkLabel(
            win, text="subfinder / httpx / nuclei 来自 ProjectDiscovery 官方；"
                      "wafw00f 随发布包更新。下载失败会自动尝试镜像。",
            font=self.f_mono_sm, text_color=GRAY, anchor="w",
            wraplength=730, justify="left").pack(anchor="w", padx=18)
        txt = ctk.CTkTextbox(win, fg_color="#08101c", text_color=TEXT,
                             font=self.f_mono_sm, corner_radius=8,
                             border_width=1, border_color=STROKE)
        txt.pack(fill="both", expand=True, padx=18, pady=(10, 8))
        txt.insert("end", "点击「检查更新」查看本地版本与官方最新版本。\n")

        row = ctk.CTkFrame(win, fg_color="transparent")
        row.pack(fill="x", padx=18, pady=(0, 14))
        q = queue.Queue()
        busy = {"v": False}

        def out(msg):
            q.put(("log", str(msg)))

        def poll():
            try:
                while True:
                    kind, val = q.get_nowait()
                    if kind == "log":
                        txt.insert("end", val + "\n")
                        txt.see("end")
                    elif kind == "busy":
                        busy["v"] = bool(val)
                        state = "disabled" if val else "normal"
                        for b in (btn_check, btn_update, btn_tpl):
                            b.configure(state=state)
                    elif kind == "refresh":
                        self._refresh_engine_rows()
            except queue.Empty:
                pass
            try:
                if win.winfo_exists():
                    win.after(120, poll)
            except Exception:
                pass

        def run_job(fn):
            if busy["v"]:
                return
            busy["v"] = True
            q.put(("busy", True))

            def _job():
                try:
                    fn()
                except Exception as e:
                    out("错误: %s" % str(e)[:300])
                finally:
                    q.put(("busy", False))
                    q.put(("refresh", True))
            threading.Thread(target=_job, daemon=True).start()

        def check():
            out("== 检查更新 ==")
            out("（访问 GitHub API，可能需要几秒…）")

            def _fn():
                rows = tool_updater.check_updates(BASE_DIR)
                for r in rows:
                    name = r["name"]
                    cur = r.get("current") or "未安装"
                    latest = r.get("latest") or "?"
                    if name == "wafw00f":
                        out("  %-10s 当前 %-9s 最新 %-9s  %s"
                            % (name, cur, latest, r.get("note", "")))
                    elif r.get("updatable"):
                        out("  %-10s 当前 %-9s 最新 %-9s  ↑ 可更新"
                            % (name, cur, latest))
                    else:
                        out("  %-10s 当前 %-9s 最新 %-9s  已是最新"
                            % (name, cur, latest))
            run_job(_fn)

        def update_all():
            out("== 一键更新（下载→版本校验→备份→替换）==")

            def _fn():
                res = tool_updater.update_all(
                    BASE_DIR, log=out,
                    progress=lambda p, t: out("[%3d%%] %s" % (p, t)))
                for name, ok, msg in res:
                    out(("  [OK] " if ok else "  [FAIL] ") + "%s: %s" % (name, msg))
                out("更新结束。右侧引擎状态已刷新。")
            run_job(_fn)

        def update_tpl():
            out("== 更新 nuclei 模板 ==")

            def _fn():
                ok, msg = tool_updater.update_templates(BASE_DIR, log=out)
                out(("  [OK] " if ok else "  [FAIL] ") + msg)
            run_job(_fn)

        btn_check = ctk.CTkButton(row, text="检查更新", width=110, height=32,
                                  corner_radius=8, fg_color=ACCENT,
                                  text_color=ON_ACCENT, hover_color=ACCENT_HOVER,
                                  command=check, font=self.f_body)
        btn_check.pack(side="left")
        btn_update = ctk.CTkButton(row, text="一键更新", width=110, height=32,
                                   corner_radius=8, fg_color="transparent",
                                   border_width=1, border_color=ACCENT,
                                   text_color=ACCENT, hover_color=CARD_HI,
                                   command=update_all, font=self.f_body)
        btn_update.pack(side="left", padx=(10, 0))
        btn_tpl = ctk.CTkButton(row, text="更新模板", width=110, height=32,
                                corner_radius=8, fg_color="transparent",
                                border_width=1, border_color=STROKE,
                                text_color=TEXT, hover_color=CARD_HI,
                                command=update_tpl, font=self.f_body)
        btn_tpl.pack(side="left", padx=(10, 0))
        ctk.CTkButton(row, text="关闭", width=80, height=32, corner_radius=8,
                      fg_color="transparent", border_width=1, border_color=STROKE,
                      text_color=GRAY, hover_color=CARD_HI,
                      command=win.destroy, font=self.f_body
                      ).pack(side="right")
        win.after(120, poll)
        win.after(400, check)

    def _build_main(self):
        m = ctk.CTkFrame(self, fg_color="transparent")
        m.grid(row=1, column=1, sticky="nsew", padx=20, pady=16)
        self._main = m

        # ---- 目标卡片 ----
        card_t = ctk.CTkFrame(m, corner_radius=10, fg_color=CARD,
                              border_width=1, border_color=STROKE)
        card_t.pack(fill="x")
        head = ctk.CTkFrame(card_t, fg_color="transparent")
        head.pack(fill="x", padx=16, pady=(9, 2))
        ctk.CTkLabel(head, text="// TARGET  ·  测绘目标", font=self.f_mono_sm,
                     text_color=ACCENT).pack(side="left")
        ctk.CTkLabel(head, text="名称 / 域名 / IP / 网段 · 支持多个", font=self.f_mono_sm,
                     text_color=GRAY).pack(side="right")
        self.var_target = ctk.StringVar()
        self.ent_target = ctk.CTkEntry(
            card_t, textvariable=self.var_target, height=42,
            font=ctk.CTkFont(size=14), corner_radius=8, border_color=STROKE,
            fg_color="#080e16",
            placeholder_text="单位名称 / 域名 / IP / 网段 —— 空格或逗号分隔")
        self.ent_target.pack(fill="x", padx=16, pady=(2, 2))
        self.ent_target.bind("<KeyRelease>", lambda e: self._preview_target())
        self.lbl_preview = ctk.CTkLabel(card_t, text="AUTO-DETECT · 自动识别输入类型…",
                                        text_color=GRAY, font=self.f_mono_sm,
                                        anchor="w")
        self.lbl_preview.pack(anchor="w", padx=16, pady=(0, 7))

        # ---- 模式卡片（点击切换，视觉差异明显） ----
        self._section(m, "// MODE  ·  扫描模式（点击卡片切换）")
        frm_modes = ctk.CTkFrame(m, fg_color="transparent")
        frm_modes.pack(fill="x")
        for c in range(len(MODE_ORDER)):
            frm_modes.grid_columnconfigure(c, weight=1, uniform="modes")
        self.mode_cards = {}
        for i, name in enumerate(MODE_ORDER):
            code, color, hover, desc, chips = MODE_META[name]
            card = ctk.CTkFrame(frm_modes, corner_radius=10, fg_color=CARD,
                                border_width=1, border_color=STROKE, cursor="hand2")
            card.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 6, 0))
            card.grid_columnconfigure(0, weight=1)
            top = ctk.CTkFrame(card, fg_color="transparent")
            top.grid(row=0, column=0, sticky="ew", padx=12, pady=(7, 0))
            idx = ctk.CTkLabel(top, text="0%d" % (i + 1), font=self.f_mono_sm,
                               text_color=GRAY)
            idx.pack(side="left")
            dot = ctk.CTkLabel(top, text="●", font=self.f_mono_sm, text_color="#3d5064")
            dot.pack(side="right")
            title = ctk.CTkLabel(card, text=name, font=ctk.CTkFont(size=14, weight="bold"),
                                 text_color=TEXT, anchor="w")
            title.grid(row=1, column=0, sticky="w", padx=12)
            code_lbl = ctk.CTkLabel(card, text=code, font=self.f_mono_sm,
                                    text_color=GRAY, anchor="w")
            code_lbl.grid(row=2, column=0, sticky="w", padx=12)
            chip = ctk.CTkLabel(card, text=" · ".join(chips), font=self.f_mono_sm,
                                text_color=GRAY, anchor="w", justify="left",
                                wraplength=170)
            chip.grid(row=3, column=0, sticky="w", padx=12, pady=(4, 8))
            for w in (card, top, idx, dot, title, code_lbl, chip):
                w.bind("<Button-1>", lambda e, k=name: self._select_mode(k))
            card.bind("<Enter>", lambda e, c=card, k=name: self._mode_hover(c, k, True))
            card.bind("<Leave>", lambda e, c=card, k=name: self._mode_hover(c, k, False))
            self.mode_cards[name] = {"frame": card, "title": title, "code": code_lbl,
                                     "dot": dot, "chip": chip, "index": idx,
                                     "color": color, "hover": hover}

        # ---- 能力矩阵（随模式实时变化） ----
        box = ctk.CTkFrame(m, corner_radius=8, fg_color="#0a1220",
                           border_width=1, border_color=STROKE)
        box.pack(fill="x", pady=(6, 0))
        self.cap_row = ctk.CTkFrame(box, fg_color="transparent")
        self.cap_row.pack(fill="x", padx=14, pady=(6, 1))
        self.cap_labels = {}
        for key in ("被动源", "subfinder", "httpx", "wafw00f", "端口扫描", "nuclei"):
            lbl = ctk.CTkLabel(self.cap_row, text=key, font=self.f_mono_sm,
                               text_color=GRAY)
            lbl.pack(side="left", padx=(0, 16))
            self.cap_labels[key] = lbl
        self.lbl_matrix_note = ctk.CTkLabel(box, text="", font=self.f_mono_sm,
                                            text_color=GRAY, anchor="w")
        self.lbl_matrix_note.pack(fill="x", padx=14, pady=(0, 6))

        self.var_auth = ctk.BooleanVar(value=False)
        self.sw_auth = ctk.CTkSwitch(
            box, text="我已获得书面授权（主动模式必勾）", variable=self.var_auth,
            text_color=RED, progress_color=RED, button_color=RED, font=self.f_mono_sm)

        # ---- 运行行 ----
        frm_run = ctk.CTkFrame(m, fg_color="transparent")
        frm_run.pack(fill="x", pady=(8, 0))
        self.btn_start = ctk.CTkButton(
            frm_run, text="▶  开始测绘 · 标准", width=200, height=42, corner_radius=9,
            font=ctk.CTkFont(size=15, weight="bold"), fg_color=ACCENT,
            hover_color=ACCENT_HOVER, text_color=ON_ACCENT, command=self._on_start)
        self.btn_start.pack(side="left")
        self.btn_stop = ctk.CTkButton(
            frm_run, text="⏹ 停止并输出", width=128, height=42, corner_radius=9,
            fg_color="transparent", border_width=1, border_color=RED,
            text_color=RED, hover_color="#2a1416", state="disabled",
            command=self._on_stop)
        self.btn_stop.pack(side="left", padx=(10, 0))
        self.bar = ctk.CTkProgressBar(frm_run, height=8, corner_radius=4,
                                      progress_color=ACCENT, fg_color=CARD)
        self.bar.set(0)
        self.bar.pack(side="left", fill="x", expand=True, padx=(18, 0))
        self.lbl_progress = ctk.CTkLabel(
            frm_run, text="0% · 待开始", width=300, anchor="w",
            font=self.f_mono_sm, text_color=GRAY)
        self.lbl_progress.pack(side="left", padx=(10, 0))

        # ---- 高级参数（独立窗口，不挤占结果区） ----
        self.btn_adv = ctk.CTkButton(
            m, text="⚙  高级参数 // ADVANCED", width=190, height=26, corner_radius=6,
            fg_color="transparent", hover_color=CARD_HI,
            font=self.f_mono_sm, text_color=GRAY, anchor="w", command=self._open_adv)
        self.btn_adv.pack(anchor="w", pady=(5, 0))

        # ---- 结果卡片 ----
        frm_cards = ctk.CTkFrame(m, fg_color="transparent", height=1)
        frm_cards.pack(fill="x", pady=(8, 4))
        for c in range(3):
            frm_cards.grid_columnconfigure(c, weight=1)
        self.card_confirmed, self.frame_confirmed = self._card(
            frm_cards, 0, "确认资产", GREEN, "A ≥ 1 或 B ≥ 2 · 点击筛选")
        self.card_suspect, self.frame_suspect = self._card(
            frm_cards, 1, "疑似资产", ORANGE, "B = 1 或 C ≥ 1 · 点击筛选")
        self.card_rejected, self.frame_rejected = self._card(
            frm_cards, 2, "剔除（存疑）", GRAY, "无关联证据 · 点击筛选")
        self._card_frames = {
            "确认": (self.frame_confirmed, GREEN),
            "疑似": (self.frame_suspect, ORANGE),
            "存疑": (self.frame_rejected, GRAY),
        }
        self._asset_filter = None
        self._asset_by_iid = {}
        for kind, (fr, _c) in self._card_frames.items():
            self._bind_card(fr, kind)

        # ---- 结果区：资产列表 / 运行日志 ----
        self.tabview = ctk.CTkTabview(
            m, height=190, corner_radius=10, command=self._on_tab_change,
            fg_color=CARD, segmented_button_fg_color=PANEL,
            segmented_button_selected_color=ACCENT,
            segmented_button_selected_hover_color=ACCENT_HOVER)
        self.tabview.pack(fill="both", expand=True, pady=(4, 0))
        tab_assets = self.tabview.add("资产列表")
        tab_apps = self.tabview.add("APP 应用")
        tab_log = self.tabview.add("运行日志")
        tab_cruise = self.tabview.add("定时巡航")

        import tkinter.ttk as ttk
        self.lbl_filter = ctk.CTkLabel(
            tab_assets, text="点击上方卡片筛选；再次点击取消 · 双击资产行可人工复核",
            font=self.f_mono_sm, text_color=GRAY, anchor="w")
        self.lbl_filter.pack(fill="x", padx=8, pady=(2, 1))

        # ---- 批量操作工具栏 ----
        frm_sel = ctk.CTkFrame(tab_assets, fg_color="transparent")
        frm_sel.pack(fill="x", padx=8, pady=(0, 3))
        self.btn_select_all = ctk.CTkButton(
            frm_sel, text="☐ 全选", width=82, height=26, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=ACCENT, hover_color=CARD_HI, font=self.f_mono_sm,
            command=self._toggle_select_all)
        self.btn_select_all.pack(side="left")
        for label, val, color in (("标记确认", "确认", GREEN),
                                  ("标记疑似", "疑似", ORANGE),
                                  ("标记存疑", "存疑", GRAY)):
            ctk.CTkButton(
                frm_sel, text=label, width=76, height=26, corner_radius=6,
                fg_color="transparent", border_width=1, border_color=color,
                text_color=color, hover_color=CARD_HI, font=self.f_mono_sm,
                command=lambda v=val: self._bulk_mark(v)
            ).pack(side="left", padx=(6, 0))
        ctk.CTkButton(
            frm_sel, text="复制URL", width=74, height=26, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=ACCENT,
            text_color=ACCENT, hover_color=CARD_HI, font=self.f_mono_sm,
            command=lambda: self._copy_selected("url")
        ).pack(side="left", padx=(12, 0))
        ctk.CTkButton(
            frm_sel, text="复制主机", width=74, height=26, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, font=self.f_mono_sm,
            command=lambda: self._copy_selected("host")
        ).pack(side="left", padx=(6, 0))
        ctk.CTkButton(
            frm_sel, text="导出选中CSV", width=96, height=26, corner_radius=6,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, font=self.f_mono_sm,
            command=self._export_selected
        ).pack(side="left", padx=(6, 0))
        self.var_asset_search = ctk.StringVar(value="")
        ent_search = ctk.CTkEntry(
            frm_sel, textvariable=self.var_asset_search, width=170, height=26,
            placeholder_text="搜索主机 / IP / 标题…", font=self.f_mono_sm)
        ent_search.pack(side="left", padx=(12, 0))
        ent_search.bind("<KeyRelease>", lambda e: self._render_assets())
        self.lbl_sel = ctk.CTkLabel(frm_sel, text="已选 0", width=70,
                                    anchor="e", font=self.f_mono_sm,
                                    text_color=GRAY)
        self.lbl_sel.pack(side="right")

        cols = ("选", "分类", "主机", "IP", "端口", "标题", "敏感发现", "归属说明", "云")
        widths = (32, 54, 160, 100, 46, 145, 100, 220, 80)
        self.tree = ttk.Treeview(tab_assets, columns=cols, show="headings",
                                 selectmode="browse")
        for c, w in zip(cols, widths):
            self.tree.heading(c, text=c,
                              command=(lambda cc=c: self._sort_by(cc)))
            self.tree.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(tab_assets, orient="vertical", command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        self.tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self.tree.tag_configure("confirmed", foreground=GREEN)
        self.tree.tag_configure("suspect", foreground=ORANGE)
        self.tree.tag_configure("unknown", foreground=GRAY)
        self.tree.tag_configure("cloudtag", foreground=ACCENT)
        self.tree.bind("<Double-1>", self._on_tree_double)
        self.tree.bind("<Button-1>", self._on_tree_click)
        self.tree.bind("<Control-a>", self._on_select_all_key)
        self.tree.bind("<Control-c>", lambda e: self._copy_selected("url"))
        self.tree.bind("<Button-3>", self._on_tree_right)

        # APP 应用标签页（App Store 发现的移动端资产）
        acols = ("应用名", "开发者", "包名", "归属依据")
        awidths = (240, 320, 260, 260)
        self.tree_apps = ttk.Treeview(tab_apps, columns=acols, show="headings",
                                      selectmode="browse")
        for c, w in zip(acols, awidths):
            self.tree_apps.heading(c, text=c)
            self.tree_apps.column(c, width=w, anchor="w")
        avsb = ttk.Scrollbar(tab_apps, orient="vertical", command=self.tree_apps.yview)
        self.tree_apps.configure(yscrollcommand=avsb.set)
        self.tree_apps.pack(side="left", fill="both", expand=True)
        avsb.pack(side="right", fill="y")

        self._style_treeview()

        self.txt_log = ctk.CTkTextbox(tab_log, font=ctk.CTkFont(family=MONO, size=12),
                                      wrap="word", corner_radius=8,
                                      fg_color="#060b11", border_width=0)
        self.txt_log.pack(fill="both", expand=True)
        self.txt_log.configure(state="disabled")
        self._apply_log_palette("dark")
        self._build_cruise_tab(tab_cruise)
        self.tabview.set("运行日志")

        # ---- 底部操作（先 pack 到底部，保证标签页不会把它挤掉） ----
        frm_done = ctk.CTkFrame(m, fg_color="transparent")
        frm_done.pack(side="bottom", fill="x", pady=(8, 0), before=self.tabview)
        self.btn_report = ctk.CTkButton(
            frm_done, text="⬇  生成报告…", width=150, height=38, corner_radius=8,
            fg_color=ACCENT, hover_color=ACCENT_HOVER,
            text_color=ON_ACCENT,
            text_color_disabled="#0b3b45",
            font=ctk.CTkFont(size=13, weight="bold"),
            state="disabled", command=self._open_report_dialog)
        self.btn_report.pack(side="left")
        self.btn_open_out = ctk.CTkButton(
            frm_done, text="📁 打开输出文件夹", width=150, height=38, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, state="disabled",
            command=self._open_out)
        self.btn_open_out.pack(side="left", padx=8)
        self.btn_open_html = ctk.CTkButton(
            frm_done, text="🌐 查看网页报告", width=140, height=38, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, state="disabled",
            command=self._open_html)
        self.btn_open_html.pack(side="left")
        self.btn_open_report = ctk.CTkButton(
            frm_done, text="📄 查看MD报告", width=130, height=38, corner_radius=8,
            fg_color="transparent", border_width=1, border_color=STROKE,
            text_color=TEXT, hover_color=CARD_HI, state="disabled",
            command=self._open_report)
        self.btn_open_report.pack(side="left", padx=8)

    def _card(self, parent, col, caption, color, hint=""):
        f = ctk.CTkFrame(parent, corner_radius=10, fg_color=CARD, height=74,
                         border_width=1, border_color=STROKE)
        f.grid(row=0, column=col, sticky="ew", padx=(0 if col == 0 else 6, 0))
        ctk.CTkFrame(f, width=3, height=1, fg_color=color, corner_radius=2
                     ).pack(side="left", fill="y")
        num = ctk.CTkLabel(f, text="0",
                           font=ctk.CTkFont(family=MONO, size=26, weight="bold"),
                           text_color=color, width=52, anchor="w")
        num.pack(side="left", padx=(12, 2), pady=6)
        txt = ctk.CTkFrame(f, fg_color="transparent")
        txt.pack(side="left", fill="both", expand=True, padx=(0, 10), pady=6)
        ctk.CTkLabel(txt, text=caption, text_color=TEXT, anchor="w",
                     font=ctk.CTkFont(size=12, weight="bold")).pack(anchor="w")
        if hint:
            ctk.CTkLabel(txt, text=hint, text_color=GRAY, anchor="w",
                         font=self.f_mono_sm).pack(anchor="w")
        return num, f

    def _build_advanced_dialog(self):
        win = ctk.CTkToplevel(self)
        win.title("高级参数 · CyberCensus")
        win.geometry("820x650")
        win.configure(fg_color=BG)
        win.withdraw()
        win.protocol("WM_DELETE_WINDOW", win.withdraw)
        self.adv_win = win

        ctk.CTkLabel(win, text="// ADVANCED  ·  高级参数（修改后立即生效）",
                     font=self.f_mono_sm, text_color=ACCENT
                     ).pack(anchor="w", padx=20, pady=(14, 0))

        f = ctk.CTkFrame(win, corner_radius=10, fg_color=CARD,
                         border_width=1, border_color=STROKE)
        f.pack(fill="both", expand=True, padx=16, pady=10)
        ctk.CTkLabel(f, text="并发线程").grid(row=0, column=0, sticky="e", padx=(14, 4), pady=6)
        self.cmb_threads = ctk.CTkComboBox(f, values=["10", "20", "50", "100"],
                                           width=90)
        self.cmb_threads.set("20")
        self.cmb_threads.grid(row=0, column=1, sticky="w")
        ctk.CTkLabel(f, text="平台翻页").grid(row=0, column=2, sticky="e", padx=(16, 4))
        self.cmb_pages = ctk.CTkComboBox(f, values=["1", "2", "3", "5"], width=90)
        self.cmb_pages.set("1")
        self.cmb_pages.grid(row=0, column=3, sticky="w")
        self.var_debug = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="打印平台查询语句（排障）", variable=self.var_debug,
                      progress_color=ACCENT
                      ).grid(row=0, column=4, sticky="w", padx=16)

        ctk.CTkLabel(f, text="常用端口前N").grid(row=1, column=0, sticky="e", padx=(14, 4), pady=6)
        self.cmb_top = ctk.CTkComboBox(
            f, values=["0", "50", "100", "200", "1000", "10000"], width=90)
        self.cmb_top.set("0")
        self.cmb_top.grid(row=1, column=1, sticky="w")
        ctk.CTkLabel(f, text="自定义端口").grid(row=1, column=2, sticky="e", padx=(16, 4))
        self.var_ports = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_ports, width=150,
                     placeholder_text="80,443,8000-8100").grid(row=1, column=3, sticky="w")
        self.var_fullports = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="全端口(慢)", variable=self.var_fullports,
                      progress_color=ACCENT
                      ).grid(row=1, column=4, sticky="w", padx=16)
        self.var_cscan = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="C段扩展(仅主动)", variable=self.var_cscan,
                      progress_color=ACCENT
                      ).grid(row=1, column=5, sticky="w", padx=(8, 14))

        ctk.CTkLabel(f, text="输出目录").grid(row=2, column=0, sticky="e", padx=(14, 4), pady=6)
        self.var_out = ctk.StringVar(value="cybercensus_out")
        ctk.CTkEntry(f, textvariable=self.var_out).grid(row=2, column=1, columnspan=3,
                                                        sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="浏览…", width=70, command=self._browse_out
                      ).grid(row=2, column=4, sticky="w")

        self.var_sensitive = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(f, text="敏感路径探测(.git/.env等，主动模式必查)",
                      variable=self.var_sensitive, progress_color=ACCENT
                      ).grid(row=3, column=0, columnspan=3, sticky="w", padx=(14, 0), pady=2)

        self.var_ext = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(f, text="调用增强引擎(subfinder/httpx/wafw00f/nuclei，本机安装)",
                      variable=self.var_ext, progress_color=ACCENT
                      ).grid(row=3, column=3, columnspan=3, sticky="w", padx=(14, 0), pady=2)

        ctk.CTkLabel(f, text="告警Webhook").grid(row=4, column=0, sticky="e",
                                                 padx=(14, 4), pady=6)
        self.var_webhook = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_webhook, placeholder_text="钉钉/企业微信/飞书机器人 URL（可选）"
                     ).grid(row=4, column=1, columnspan=4, sticky="we", padx=(0, 14))

        ctk.CTkLabel(f, text="APP/小程序包").grid(row=5, column=0, sticky="e",
                                                 padx=(14, 4), pady=6)
        self.var_packages = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_packages,
                     placeholder_text="APK / .wxapkg 文件或目录，多个用 ; 分隔（本地静态扫描）"
                     ).grid(row=5, column=1, columnspan=3, sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="文件…", width=64, command=self._pick_packages
                      ).grid(row=5, column=4, sticky="w")
        ctk.CTkButton(f, text="目录…", width=64, command=self._pick_package_dir
                      ).grid(row=5, column=5, sticky="w", padx=(6, 14))

        ctk.CTkLabel(f, text="理解结果JSON").grid(row=6, column=0, sticky="e",
                                                  padx=(14, 4), pady=6)
        self.var_intel = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_intel,
                     placeholder_text="外部模型/子 agent 产出的 intel.json（别名/查询词/候选域）"
                     ).grid(row=6, column=1, columnspan=4, sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="文件…", width=64, command=self._pick_intel
                      ).grid(row=6, column=5, sticky="w", padx=(6, 14))

        self.var_fast = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="极速模式：跳过慢速阶段、缩短超时、提高并发（覆盖会下降）",
                      variable=self.var_fast, progress_color=ORANGE
                      ).grid(row=7, column=0, columnspan=6, sticky="w",
                             padx=(14, 0), pady=(8, 4))

        self.var_paths = ctk.BooleanVar(value=True)
        ctk.CTkSwitch(f, text="采集路径线索：robots.txt / sitemap.xml / 前端 JS API（主动 GET）",
                      variable=self.var_paths, progress_color=ACCENT
                      ).grid(row=8, column=0, columnspan=6, sticky="w",
                             padx=(14, 0), pady=(0, 4))

        self.var_pkw = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="平台关键词检索：title/body 搜短名（如“双流移动”，仅疑似线索）",
                      variable=self.var_pkw, progress_color=ORANGE
                      ).grid(row=9, column=0, columnspan=6, sticky="w",
                             padx=(14, 0), pady=(0, 6))

        ctk.CTkLabel(f, text="目标 ASN").grid(row=10, column=0, sticky="e",
                                              padx=(14, 4), pady=4)
        self.var_asn = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_asn,
                     placeholder_text="AS12345（可多个，逗号分隔）；只列宣告网段作线索"
                     ).grid(row=10, column=1, columnspan=3, sticky="we", padx=(0, 6))
        self.var_scan_asn = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="扫描这些网段（授权！上限 4096 IP）",
                      variable=self.var_scan_asn, progress_color=RED
                      ).grid(row=10, column=4, columnspan=2, sticky="w", padx=(0, 10))

        ctk.CTkLabel(f, text="持续监控").grid(row=11, column=0, sticky="e",
                                              padx=(14, 4), pady=(4, 10))
        self.var_watch = ctk.StringVar(value="0")
        ctk.CTkEntry(f, textvariable=self.var_watch, width=80,
                     placeholder_text="0").grid(row=11, column=1, sticky="w")
        ctk.CTkLabel(f, text="分钟；0=关闭。每轮扫描结束自动重扫并对比基线（Ctrl+C/关闭窗口停止）",
                     font=self.f_mono_sm, text_color=GRAY
                     ).grid(row=11, column=2, columnspan=4, sticky="w", padx=(0, 10))

        ctk.CTkLabel(f, text="资产范围文件").grid(row=12, column=0, sticky="e",
                                                  padx=(14, 4), pady=6)
        self.var_scope_file = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_scope_file,
                     placeholder_text="每行一个 URL/域名/IP，结果标注为 范围内/相似/无关"
                     ).grid(row=12, column=1, columnspan=4, sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="文件…", width=64, command=self._pick_scope_file
                      ).grid(row=12, column=5, sticky="w", padx=(6, 14))

        self.var_only_scope = ctk.BooleanVar(value=False)
        ctk.CTkSwitch(f, text="只看范围内/相似资产（过滤无关项）",
                      variable=self.var_only_scope, progress_color=ACCENT
                      ).grid(row=13, column=0, columnspan=6, sticky="w",
                             padx=(14, 0), pady=(0, 6))

        ctk.CTkLabel(f, text="报告保留").grid(row=14, column=0, sticky="e",
                                              padx=(14, 4), pady=(0, 6))
        self.var_keep = ctk.StringVar(value="0")
        ctk.CTkEntry(f, textvariable=self.var_keep, width=80,
                     placeholder_text="0").grid(row=14, column=1, sticky="w")
        ctk.CTkLabel(f, text="轮；0=不清理。长期巡航建议 20~50，只删旧报告不动基线",
                     font=self.f_mono_sm, text_color=GRAY
                     ).grid(row=14, column=2, columnspan=4, sticky="w", padx=(0, 10))

        ctk.CTkLabel(f, text="端口字典").grid(row=15, column=0, sticky="e",
                                              padx=(14, 4), pady=(0, 6))
        self.var_ports_file = ctk.StringVar(value="")
        ctk.CTkEntry(f, textvariable=self.var_ports_file,
                     placeholder_text="端口字典文件：每行/逗号分隔，支持 8000-8100 与 # 注释"
                     ).grid(row=15, column=1, columnspan=4, sticky="we", padx=(0, 4))
        ctk.CTkButton(f, text="文件…", width=64, command=self._pick_ports_file
                      ).grid(row=15, column=5, sticky="w", padx=(6, 14))

        ctk.CTkLabel(win, text="提示：平台翻页越多越慢、越费配额；全端口扫描建议仅在授权窗口期使用。",
                     font=self.f_mono_sm, text_color=GRAY
                     ).pack(anchor="w", padx=22, pady=(2, 0))
        frm = ctk.CTkFrame(win, fg_color="transparent")
        frm.pack(fill="x", padx=20, pady=(6, 12))
        ctk.CTkButton(frm, text="完成", width=110, height=32, corner_radius=8,
                      fg_color=ACCENT, hover_color=ACCENT_HOVER, text_color=ON_ACCENT,
                      font=ctk.CTkFont(size=13, weight="bold"),
                      command=win.withdraw).pack(side="right")

    def _open_adv(self):
        self.adv_win.deiconify()
        self.adv_win.lift()
        self.adv_win.focus_force()

    # ---- 模式切换（视觉联动：卡片 / 能力矩阵 / 主按钮 / 进度条 / 标签页）----
    def _mode_hover(self, card, name, on):
        if name == self._mode:
            return
        card.configure(border_color=STROKE_HI if on else STROKE)

    def _select_mode(self, name, initial=False):
        meta = MODE_META.get(name)
        if not meta:
            return
        code, color, hover, desc, chips = meta
        self._mode = name
        for n, w in self.mode_cards.items():
            sel = (n == name)
            w["frame"].configure(fg_color=CARD_HI if sel else CARD,
                                 border_color=w["color"] if sel else STROKE,
                                 border_width=2 if sel else 1)
            w["title"].configure(text_color=w["color"] if sel else TEXT)
            w["code"].configure(text_color=w["color"] if sel else GRAY)
            w["index"].configure(text_color=w["color"] if sel else GRAY)
            w["dot"].configure(text_color=w["color"] if sel else "#3d5064")
            w["chip"].configure(text_color=TEXT if sel else GRAY)
        caps = dict(MODE_CAPS.get(name, ()))
        for key, lbl in self.cap_labels.items():
            on = caps.get(key, False)
            lbl.configure(text=("● " if on else "○ ") + key,
                          text_color=color if on else "#3d5064")
        self.lbl_matrix_note.configure(text="//  " + MODE_HINTS.get(name, ""),
                                       text_color=GRAY)
        self.btn_start.configure(text="▶  开始测绘 · %s" % name,
                                 fg_color=color, hover_color=hover)
        self.btn_report.configure(fg_color=color, hover_color=hover)
        self.bar.configure(progress_color=color)
        self.tabview.configure(segmented_button_selected_color=color,
                               segmented_button_selected_hover_color=hover)
        self.lbl_mode_tag.configure(text=code, text_color=color)
        if name == "主动":
            self.sw_auth.pack(side="right", padx=(0, 6))
        else:
            self.sw_auth.pack_forget()

    # ---- 定时巡航面板（GUI 版 --tasks） ----
    def _build_cruise_tab(self, tab):
        import tkinter.ttk as ttk
        top = ctk.CTkFrame(tab, fg_color="transparent")
        top.pack(fill="x", pady=(4, 4))
        ctk.CTkLabel(top, text="任务文件").pack(side="left", padx=(0, 6))
        self.var_cruise_file = ctk.StringVar(
            value=os.path.join(BASE_DIR, "tasks.json"))
        ctk.CTkEntry(top, textvariable=self.var_cruise_file, width=330
                     ).pack(side="left")
        ctk.CTkButton(top, text="浏览…", width=62, command=self._cruise_pick
                      ).pack(side="left", padx=6)
        ctk.CTkButton(top, text="刷新", width=56, command=self._cruise_reload
                      ).pack(side="left")
        ctk.CTkButton(top, text="+ 当前目标", width=96,
                      command=self._cruise_add_current).pack(side="left", padx=6)
        self.btn_cruise_stop = ctk.CTkButton(
            top, text="■ 停止", width=70, state="disabled",
            command=self._cruise_stop)
        self.btn_cruise_stop.pack(side="right")
        self.btn_cruise_start = ctk.CTkButton(
            top, text="▶ 启动后台巡航", width=124, fg_color=ACCENT,
            text_color=ON_ACCENT, command=self._cruise_start)
        self.btn_cruise_start.pack(side="right", padx=6)
        ctk.CTkButton(top, text="立即执行一次", width=100,
                      command=self._cruise_once).pack(side="right", padx=6)

        self.lbl_cruise = ctk.CTkLabel(tab, text="", font=self.f_mono_sm,
                                       text_color=GRAY, anchor="w")
        self.lbl_cruise.pack(fill="x", pady=(0, 4))

        cols = ("任务", "周期", "上次运行", "下次运行", "状态")
        widths = (220, 80, 150, 150, 260)
        self.tree_cruise = ttk.Treeview(tab, columns=cols, show="headings",
                                        selectmode="browse")
        for c, w in zip(cols, widths):
            self.tree_cruise.heading(c, text=c)
            self.tree_cruise.column(c, width=w, anchor="w")
        vsb = ttk.Scrollbar(tab, orient="vertical",
                            command=self.tree_cruise.yview)
        self.tree_cruise.configure(yscrollcommand=vsb.set)
        self.tree_cruise.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")
        self._cruise_proc = None
        self._cruise_reload()

    def _cruise_pick(self):
        p = filedialog.askopenfilename(
            title="选择定时巡航任务文件",
            filetypes=[("JSON", "*.json"), ("所有文件", "*.*")])
        if p:
            self.var_cruise_file.set(p)
            self._cruise_reload()

    def _cruise_path(self):
        return self.var_cruise_file.get().strip() or os.path.join(BASE_DIR, "tasks.json")

    def _cruise_reload(self):
        if not hasattr(self, "tree_cruise"):
            return
        self.tree_cruise.delete(*self.tree_cruise.get_children())
        p = self._cruise_path()
        if not os.path.isfile(p):
            self.lbl_cruise.configure(text="任务文件不存在：%s" % p, text_color=ORANGE)
            return
        try:
            tasks = cybercensus.load_task_file(p)
        except Exception as e:
            self.lbl_cruise.configure(text="任务文件解析失败：%s" % str(e)[:100],
                                      text_color=RED)
            return
        try:
            with open(p + ".state.json", "r", encoding="utf-8") as f:
                state = json.load(f)
        except Exception:
            state = {}
        now = time.time()
        for i, t in enumerate(tasks):
            name = cybercensus._task_name(t, i)
            st = state.get(name) or {}
            last = float(st.get("last_run") or 0)
            every = cybercensus.parse_interval(t.get("every"), 86400)
            nxt = "待运行" if not last else time.strftime(
                "%Y-%m-%d %H:%M", time.localtime(last + every))
            enabled = t.get("enabled", True) is not False
            argv = cybercensus._task_argv(t)
            if not enabled:
                status = "已停用"
            elif cybercensus._task_is_active(argv) and not t.get("authorized"):
                status = "缺 authorized，不会执行"
            elif st.get("last_rc") not in (None, 0):
                status = "上轮失败 rc=%s" % st.get("last_rc")
            else:
                status = "正常"
            self.tree_cruise.insert("", "end", values=(
                name, str(t.get("every") or "24h"),
                time.strftime("%Y-%m-%d %H:%M", time.localtime(last)) if last else "从未",
                nxt, status))
        self.lbl_cruise.configure(
            text="共 %d 个任务；状态文件：%s.state.json" % (len(tasks), p),
            text_color=GRAY)

    def _cruise_add_current(self):
        target = self.ent_target.get().strip()
        if not target:
            messagebox.showwarning("缺少目标", "请先在目标框输入名称/域名/IP。")
            return
        from tkinter import simpledialog
        name = simpledialog.askstring(
            "加入定时巡航", "任务名称（显示用）：", parent=self,
            initialvalue=target[:24])
        if not name:
            return
        every = simpledialog.askstring(
            "加入定时巡航", "周期：30m / 6h / 1d / 7d", parent=self,
            initialvalue="24h")
        if not every:
            return
        mode = self._mode
        active = (mode == "active")
        if active and not messagebox.askyesno(
                "授权确认", "该任务包含主动扫描，确认你已获得书面授权？"):
            return
        argv = []
        for tok in re.split(r"[\s,;]+", target):
            if not tok:
                continue
            kind = cybercensus.classify_target(tok)
            if kind == "ip" or kind == "cidr":
                argv += ["--ip", tok]
            elif kind == "domain":
                argv += ["-d", tok]
            else:
                argv += ["-n", tok]
        safe = re.sub(r'[\\/:*?"<>|]+', "_", name).strip("._") or "task"
        outdir = os.path.join(self.var_out.get().strip() or "cybercensus_out", safe)
        argv += ["--out", outdir, "--formats", "html,md,csv,json"]
        if mode == "passive":
            argv.append("--no-probe")
        elif mode == "verify":
            argv.append("--verify")
        elif mode == "active":
            argv += ["--active", "--top", "100"]
        keep = _to_int(self.var_keep.get(), 0)
        if keep > 0:
            argv += ["--keep", str(keep)]
        if self.var_ports_file.get().strip():
            argv += ["--ports-file", self.var_ports_file.get().strip()]
        top = _to_int(self.cmb_top.get(), 0)
        if top > 0:
            argv += ["--top", str(top)]
        if self.var_scope_file.get().strip():
            argv += ["--scope-file", self.var_scope_file.get().strip()]
        if self.var_only_scope.get():
            argv.append("--only-scope")
        if self.var_webhook.get().strip():
            argv += ["--webhook", self.var_webhook.get().strip()]
        p = self._cruise_path()
        try:
            if os.path.isfile(p):
                with open(p, "r", encoding="utf-8") as f:
                    data = json.load(f)
            else:
                data = {}
            if not isinstance(data, dict):
                data = {"tasks": data}
            data.setdefault("tasks", []).append({
                "name": name, "argv": argv, "every": every.strip(),
                "enabled": True, "authorized": bool(active),
            })
            os.makedirs(os.path.dirname(p) or ".", exist_ok=True)
            with open(p, "w", encoding="utf-8") as f:
                json.dump(data, f, ensure_ascii=False, indent=1)
        except Exception as e:
            messagebox.showerror("保存失败", str(e))
            return
        self._cruise_reload()
        self.tabview.set("定时巡航")
        self._append_log("已加入定时巡航：%s（%s）" % (name, every), "+")

    def _cruise_cmd(self, once=False):
        p = self._cruise_path()
        args = ["--tasks", p] + (["--tasks-once"] if once else [])
        if getattr(sys, "frozen", False):
            return [sys.executable] + args
        return [sys.executable, os.path.abspath(__file__)] + args

    def _cruise_spawn(self, once=False):
        p = self._cruise_path()
        if not os.path.isfile(p):
            messagebox.showwarning("缺少任务文件", "请先选择或生成 tasks.json")
            return None
        try:
            kw = dict(stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            if os.name == "nt":
                kw["creationflags"] = 0x08000000
            proc = subprocess.Popen(self._cruise_cmd(once), **kw)
            return proc
        except Exception as e:
            messagebox.showerror("启动失败", str(e))
            return None

    def _cruise_start(self):
        if self._cruise_proc and self._cruise_proc.poll() is None:
            return
        proc = self._cruise_spawn(once=False)
        if not proc:
            return
        self._cruise_proc = proc
        self.btn_cruise_start.configure(state="disabled")
        self.btn_cruise_stop.configure(state="normal")
        self.lbl_cruise.configure(
            text="后台巡航运行中（PID %s），日志：cybercensus_cruise.log"
                 % proc.pid, text_color=GREEN)
        self._cruise_reload()

    def _cruise_stop(self):
        if self._cruise_proc and self._cruise_proc.poll() is None:
            try:
                self._cruise_proc.terminate()
            except Exception:
                pass
        self._cruise_proc = None
        self.btn_cruise_start.configure(state="normal")
        self.btn_cruise_stop.configure(state="disabled")
        self.lbl_cruise.configure(text="后台巡航已停止", text_color=GRAY)

    def _cruise_once(self):
        proc = self._cruise_spawn(once=True)
        if proc:
            self.lbl_cruise.configure(
                text="正在执行本轮到期任务（PID %s）…" % proc.pid,
                text_color=ACCENT)

    def _cruise_poll(self):
        if self._cruise_proc and self._cruise_proc.poll() is not None:
            rc = self._cruise_proc.poll()
            self._cruise_proc = None
            self.btn_cruise_start.configure(state="normal")
            self.btn_cruise_stop.configure(state="disabled")
            self.lbl_cruise.configure(
                text="后台巡航已退出（rc=%s）" % rc, text_color=GRAY)
            self._cruise_reload()
        self.after(3000, self._cruise_poll)

    # ---- 表格样式 ----
    def _style_treeview(self):
        """给 ttk.Treeview 套当前主题样式（CTk 不带表格控件，嵌入原生 Treeview）。"""
        import tkinter.ttk as ttk
        bg, fg, head, sel = TREE_BG, TREE_FG, TREE_HEAD, TREE_SEL
        style = ttk.Style(self)
        try:
            style.theme_use("clam")
        except Exception:
            pass
        style.configure("Treeview", background=bg, foreground=fg, fieldbackground=bg,
                        rowheight=28, borderwidth=0, font=("", 12))
        style.configure("Treeview.Heading", background=head, foreground=fg,
                        relief="flat", font=("", 12, "bold"))
        style.map("Treeview", background=[("selected", sel)],
                  foreground=[("selected", "#ffffff" if sel == TREE_SEL and BG[0] == "#"
                               else fg)])
        style.map("Treeview.Heading", background=[("active", head)])

    # ---- 主题切换 ----
    def _set_theme(self, name):
        apply_theme(name)
        t = THEMES[name]
        try:
            ctk.set_appearance_mode("dark" if not t["TITLEBAR"] else "light")
        except Exception:
            pass
        try:
            self.configure(fg_color=BG)
            self._header.configure(fg_color=HEADER_BG)
            self._sidebar.configure(fg_color=PANEL)
        except Exception:
            pass
        for root in (self._header, self._sidebar):
            for w in self._walk_widgets(root):
                self._recolor(w)
        self._style_treeview()
        self._apply_log_palette("dark")
        self._select_mode(self._mode)
        self._apply_card_styles()
        self._render_assets()

    def _walk_widgets(self, root):
        out = []
        stack = [root]
        while stack:
            w = stack.pop()
            out.append(w)
            try:
                stack.extend(w.winfo_children())
            except Exception:
                pass
        return out

    def _recolor(self, w):
        """按控件类型把新主题颜色刷上去（尽力而为，属性不存在就跳过）。"""
        cls = w.winfo_class()
        try:
            if cls == "CTkFrame":
                # 卡片底色 vs 面板底色：卡片画在侧栏/主区内，用 CARD
                w.configure(fg_color=CARD)
            elif cls == "CTkLabel":
                w.configure(text_color=TEXT)
        except Exception:
            pass

    def _on_tab_change(self):
        pass   # 预留：点击标签页时的钩子

    def _bind_card(self, widget, kind):
        """卡片及其子控件都可点击（Tk 子控件不会把点击冒泡给父容器）。"""
        try:
            widget.configure(cursor="hand2")
        except Exception:
            pass
        widget.bind("<Button-1>", lambda e, k=kind: self._toggle_filter(k))
        for child in widget.winfo_children():
            self._bind_card(child, kind)

    def _toggle_filter(self, kind):
        """点卡片只看该类资产；再点同一个卡片恢复全部。"""
        if not self._last_engine:
            return
        self._asset_filter = None if self._asset_filter == kind else kind
        self.tabview.set("资产列表")
        self._apply_card_styles()
        self._render_assets()

    def _apply_card_styles(self):
        """选中卡片：信号线（左缘 2px 品牌色）+ 微亮底，不整块填充。"""
        for kind, (fr, color) in getattr(self, "_card_frames", {}).items():
            selected = (self._asset_filter == kind)
            try:
                fr.configure(border_color=color if selected else STROKE,
                             border_width=1,
                             fg_color=CARD_HI if selected else CARD)
            except Exception:
                pass

    def _update_cards(self):
        counts = {"确认": 0, "疑似": 0, "存疑": 0}
        eng = self._last_engine
        if eng:
            for a in eng.assets.values():
                counts[a.confidence] = counts.get(a.confidence, 0) + 1
        self.card_confirmed.configure(text=str(counts["确认"]))
        self.card_suspect.configure(text=str(counts["疑似"]))
        self.card_rejected.configure(text=str(counts["存疑"]))
        total = sum(counts.values())
        if self._asset_filter:
            shown = counts.get(self._asset_filter, 0)
            self.lbl_filter.configure(
                text="仅显示：%s（%d / 共 %d）· 再次点击卡片恢复全部"
                     % (self._asset_filter, shown, total), text_color=ACCENT)
        else:
            self.lbl_filter.configure(
                text="显示全部 %d 个资产 · 点击卡片筛选；再次点击取消 · 双击资产行可人工复核"
                     % total, text_color=GRAY)
        return counts

    @staticmethod
    def _sel_key(a):
        return "%s|%s" % (a.host or a.ip or "", a.port or "")

    def _asset_url(self, a):
        host = a.host or a.ip or ""
        if not host:
            return ""
        scheme = a.scheme or ("https" if str(a.port) in ("443", "8443", "9443")
                              else "http")
        try:
            port = int(a.port or (443 if scheme == "https" else 80))
        except Exception:
            port = 443 if scheme == "https" else 80
        default = (scheme == "https" and port == 443) or (
            scheme == "http" and port == 80)
        return "%s://%s%s" % (scheme, host, "" if default else ":%s" % port)

    def _visible_assets(self):
        eng = self._last_engine
        if not eng:
            return []
        q = (self.var_asset_search.get() or "").strip().lower()
        items = [a for a in eng.assets.values()
                 if self._asset_filter is None or a.confidence == self._asset_filter]
        if q:
            items = [a for a in items
                     if q in (a.host or "").lower() or q in (a.ip or "").lower()
                     or q in (a.title or "").lower()]
        order = {"确认": 0, "疑似": 1, "存疑": 2}
        col = self._sort_col
        if col and col != "选":
            if col == "分类":
                key = lambda a: (order.get(a.confidence, 3), a.host or "")
            elif col == "主机":
                key = lambda a: (a.host or a.ip or "").lower()
            elif col == "IP":
                key = lambda a: a.ip or ""
            elif col == "端口":
                key = lambda a: int(a.port or 0)
            elif col == "标题":
                key = lambda a: (a.title or "").lower()
            elif col == "敏感发现":
                key = lambda a: len(a.findings)
            elif col == "归属说明":
                key = lambda a: (cybercensus.plain_evidence(a.evidence) or "").lower()
            else:
                key = lambda a: (order.get(a.confidence, 3), a.host or "")
            items.sort(key=key, reverse=self._sort_rev)
        else:
            items.sort(key=lambda a: (order.get(a.confidence, 3),
                                      a.host or a.ip or "", str(a.port or "")))
        return items

    def _render_assets(self):
        """按当前筛选/搜索/排序状态重绘表格。"""
        self.tree.delete(*self.tree.get_children())
        self._asset_by_iid = {}
        eng = self._last_engine
        if not eng:
            self._update_cards()
            return
        tag_map = {"确认": "confirmed", "疑似": "suspect", "存疑": "unknown"}
        items = self._visible_assets()
        for i, a in enumerate(items):
            plain = cybercensus.plain_evidence(a.evidence, max_items=2) or ""
            if a.confidence == "存疑" and a.reject_reason:
                plain = (plain + "；" if plain else "") + "剔除原因：" + a.reject_reason
            plain = plain or "—"
            findings = "、".join(sorted(f.split("|", 1)[-1] for f in a.findings))
            iid = "row%d" % i
            checked = self._sel_key(a) in self._checked
            self.tree.insert("", "end", iid=iid, values=(
                "☑" if checked else "☐",
                a.confidence, a.host or a.ip or "", a.ip or "", str(a.port or ""),
                a.title or "", findings, plain,
                getattr(a, "cloud", "") or ""),
                tags=(tag_map.get(a.confidence, "unknown"),))
            self._asset_by_iid[iid] = a
        self._update_cards()
        self._update_sel_label()

    def _update_sel_label(self):
        n = sum(1 for a in (self._last_engine.assets.values()
                            if self._last_engine else [])
                if self._sel_key(a) in self._checked)
        try:
            self.lbl_sel.configure(
                text="已选 %d" % n, text_color=ACCENT if n else GRAY)
            vis = self._visible_assets()
            all_on = bool(vis) and all(self._sel_key(a) in self._checked
                                       for a in vis)
            self.btn_select_all.configure(
                text="☑ 取消全选" if all_on else "☐ 全选")
        except Exception:
            pass

    def _populate_table(self, eng):
        """把引擎结果填进资产表格（完成扫描后调用）。"""
        self._last_engine = eng
        self._render_assets()

    def _toggle_one(self, a):
        k = self._sel_key(a)
        if k in self._checked:
            self._checked.discard(k)
        else:
            self._checked.add(k)
        self._update_sel_label()

    def _on_tree_click(self, event):
        if self.tree.identify_column(event.x) != "#1":
            return
        iid = self.tree.identify_row(event.y)
        a = self._asset_by_iid.get(iid)
        if not a:
            return
        self._toggle_one(a)
        try:
            vals = list(self.tree.item(iid, "values"))
            vals[0] = "☑" if self._sel_key(a) in self._checked else "☐"
            self.tree.item(iid, values=vals)
        except Exception:
            self._render_assets()
        return "break"

    def _on_tree_right(self, event):
        iid = self.tree.identify_row(event.y)
        a = self._asset_by_iid.get(iid)
        if not a:
            return
        if iid not in self.tree.selection():
            self.tree.selection_set(iid)
        m = Menu(self, tearoff=0)
        m.add_command(label="查看详情 / 人工复核",
                      command=lambda: self._show_asset_detail(a))
        m.add_separator()
        m.add_command(label="标记为确认",
                      command=lambda: self._bulk_mark("确认"))
        m.add_command(label="标记为疑似",
                      command=lambda: self._bulk_mark("疑似"))
        m.add_command(label="标记为存疑（剔除）",
                      command=lambda: self._bulk_mark("存疑"))
        m.add_separator()
        m.add_command(label="复制 URL",
                      command=lambda: self._copy_selected("url"))
        m.add_command(label="复制主机",
                      command=lambda: self._copy_selected("host"))
        try:
            m.tk_popup(event.x_root, event.y_root)
        finally:
            m.grab_release()

    def _toggle_select_all(self):
        items = self._visible_assets()
        if not items:
            return
        all_on = all(self._sel_key(a) in self._checked for a in items)
        for a in items:
            k = self._sel_key(a)
            if all_on:
                self._checked.discard(k)
            else:
                self._checked.add(k)
        self._render_assets()

    def _on_select_all_key(self, event):
        self._toggle_select_all()
        return "break"

    def _selected_assets(self):
        eng = self._last_engine
        if not eng:
            return []
        sel = [a for a in eng.assets.values()
               if self._sel_key(a) in self._checked]
        if not sel:
            # 兼容：没勾选时用表格里的高亮行
            sel = [self._asset_by_iid[i] for i in self.tree.selection()
                   if i in self._asset_by_iid]
        sel.sort(key=lambda a: (a.host or a.ip or "", str(a.port or "")))
        return sel

    def _bulk_mark(self, new):
        items = self._selected_assets()
        if not items:
            messagebox.showinfo("未选择", "请先勾选资产（表格第一列）或选中表格行。")
            return
        changed = 0
        for a in items:
            old = a.confidence
            if old == new:
                continue
            a.confidence = new
            a.evidence = [e for e in a.evidence if not e.startswith("人工复核|")]
            a.evidence.append("人工复核|批量 %s→%s" % (old, new))
            if new != "存疑":
                a.reject_reason = ""
            changed += 1
        self._append_log("批量人工复核：%d 个资产 → %s（共选中 %d 个）"
                         % (changed, new, len(items)), "!")
        self._render_assets()

    def _copy_selected(self, mode="url"):
        items = self._selected_assets()
        if not items:
            messagebox.showinfo("未选择", "请先勾选资产（表格第一列）或选中表格行。")
            return
        lines = []
        for a in items:
            if mode == "host":
                v = a.host or a.ip or ""
                if a.port and v and ":" not in v:
                    v = "%s:%s" % (v, a.port)
            else:
                v = self._asset_url(a)
            if v and v not in lines:
                lines.append(v)
        if not lines:
            messagebox.showinfo("没有可复制内容", "选中资产没有可用的主机/URL。")
            return
        try:
            self.clipboard_clear()
            self.clipboard_append("\n".join(lines))
            self.update_idletasks()
        except Exception as e:
            messagebox.showerror("复制失败", str(e))
            return
        self._append_log("已复制 %d 条%s到剪贴板" %
                         (len(lines), "URL" if mode != "host" else "主机"), "+")
        self._set_status("● 已复制 %d 条" % len(lines), GREEN)

    def _export_selected(self):
        items = self._selected_assets()
        if not items:
            messagebox.showinfo("未选择", "请先勾选资产或选中表格行。")
            return
        path = filedialog.asksaveasfilename(
            title="导出选中资产", defaultextension=".csv",
            initialfile="cybercensus_selected.csv",
            filetypes=[("CSV", "*.csv"), ("所有文件", "*.*")])
        if not path:
            return
        try:
            with open(path, "w", newline="", encoding="utf-8-sig") as f:
                w = csv.writer(f)
                w.writerow(["分类", "主机", "IP", "端口", "协议", "标题",
                            "URL", "归属说明", "证据"])
                for a in items:
                    w.writerow([
                        a.confidence, a.host or "", a.ip or "", a.port or "",
                        a.scheme or "", a.title or "", self._asset_url(a),
                        cybercensus.plain_evidence(a.evidence, max_items=5),
                        ";".join(a.evidence)])
        except Exception as e:
            messagebox.showerror("导出失败", str(e))
            return
        self._append_log("已导出选中资产 %d 条：%s" % (len(items), path), "+")
        self._set_status("● 已导出选中资产", GREEN)

    def _sort_by(self, col):
        if col == "选":
            return
        if self._sort_col == col:
            self._sort_rev = not self._sort_rev
        else:
            self._sort_col = col
            self._sort_rev = False
        # 表头箭头提示
        arrow = " ▼" if self._sort_rev else " ▲"
        for c in self.tree["columns"]:
            base = c
            try:
                self.tree.heading(c, text=base + (arrow if c == col else ""))
            except Exception:
                pass
        self._render_assets()

    def _on_tree_double(self, event):
        if self.tree.identify_column(event.x) == "#1":
            return          # 双击勾选列不打开详情
        iid = self.tree.identify_row(event.y)
        a = self._asset_by_iid.get(iid)
        if a is not None:
            self._show_asset_detail(a)

    def _show_asset_detail(self, a):
        """资产详情 + 人工复核改判（剔除/疑似/存疑可互相调整）。"""
        win = ctk.CTkToplevel(self)
        win.title("资产详情 / 人工复核")
        win.geometry("820x640")
        win.configure(fg_color=BG)
        win.transient(self)
        win.after(250, lambda: win.grab_set())
        txt = ctk.CTkTextbox(win, fg_color="#08101c", text_color=TEXT,
                             font=self.f_mono_sm, corner_radius=8,
                             border_width=1, border_color=STROKE)
        txt.pack(fill="both", expand=True, padx=16, pady=(14, 8))

        def show(msg):
            txt.insert("end", msg + "\n")
            txt.see("end")

        def refresh():
            txt.delete("1.0", "end")
            show("// ASSET DETAIL  ·  双击行查看 / 人工改判")
            show("")
            for label, value in (
                    ("当前分类", a.confidence),
                    ("主机", a.host or ""), ("IP", a.ip or ""),
                    ("端口/协议", "%s / %s" % (a.port or "", a.scheme or "")),
                    ("状态", a.status or ""), ("标题", a.title or ""),
                    ("服务器", a.server or ""), ("技术栈", a.tech or ""),
                    ("证书 O=", a.cert_org or ""),
                    ("RDAP 注册人", a.rdap_org or ""),
                    ("备案号", a.beian or ""), ("信用代码", a.credit_code or ""),
                    ("网站标识码", a.site_code or ""),
                    ("公安备案", a.police_beian or ""),
                    ("ASN", ("%s %s" % (a.asn or "", a.asn_org or "")).strip()),
                    ("邮箱", "、".join(sorted(a.emails)) or ""),
                    ("电话", "、".join(sorted(a.phones)) or ""),
                    ("页脚单位", "、".join(sorted(a.authorities)) or ""),
                    ("统计/像素", "、".join(sorted(a.trackings)) or ""),
                    ("注册号", "、".join(sorted(a.registry_ids)) or ""),
                    ("来源", "、".join(sorted(a.source)) or ""),
                    ("剔除原因", a.reject_reason or "")):
                if value:
                    show("%-10s %s" % (label + "：", value))
            show("")
            show("证据：")
            for ev in (a.evidence or []):
                show("  " + ev)
            if not a.evidence:
                show("  （无）")
            show("")
            show("提示：人工改判只影响本次结果与随后导出的报告；重新扫描会重新自动分级。")

        refresh()

        row = ctk.CTkFrame(win, fg_color="transparent")
        row.pack(fill="x", padx=16, pady=(0, 14))

        def mark(new):
            old = a.confidence
            if new == old:
                return
            a.confidence = new
            a.evidence = [e for e in a.evidence if not e.startswith("人工复核|")]
            a.evidence.append("人工复核|%s→%s" % (old, new))
            if new != "存疑":
                a.reject_reason = ""
            self._append_log("人工复核: %s  %s → %s"
                             % (a.host or a.ip, old, new), "!")
            self._render_assets()
            refresh()

        ctk.CTkLabel(row, text="人工改判：", font=self.f_mono_sm,
                     text_color=GRAY).pack(side="left")
        for label, val, color in (("确认", "确认", GREEN),
                                  ("疑似", "疑似", ORANGE),
                                  ("存疑/剔除", "存疑", GRAY)):
            ctk.CTkButton(row, text=label, width=96, height=30, corner_radius=7,
                          fg_color="transparent", border_width=1,
                          border_color=color, text_color=color,
                          hover_color=CARD_HI,
                          command=lambda v=val: mark(v)
                          ).pack(side="left", padx=(6, 0))
        ctk.CTkButton(row, text="关闭", width=80, height=30, corner_radius=7,
                      fg_color="transparent", border_width=1, border_color=STROKE,
                      text_color=GRAY, hover_color=CARD_HI,
                      command=win.destroy).pack(side="right")

    def _populate_apps(self, eng):
        """把 App Store 发现的应用填进 APP 标签页。"""
        self.tree_apps.delete(*self.tree_apps.get_children())
        for track, seller, bundle, reason in getattr(eng, "apps", []) or []:
            self.tree_apps.insert("", "end",
                                  values=(track, seller, bundle, reason))

    def _apply_log_palette(self, mode):
        pal = dict(LOG_PALETTE[mode])
        pal["norm"] = LOG_NORM     # 跟随主题
        for tag, color in pal.items():
            try:
                self.txt_log.tag_config(tag, foreground=color)
            except Exception:
                pass    # 旧版 CTkTextbox 无 tag 支持，纯色输出

    # ---- 目标解析预览 ----
    def _preview_target(self):
        text = self.ent_target.get()
        if not text.strip():
            self.lbl_preview.configure(text="AUTO-DETECT · 自动识别输入类型…",
                                       text_color=GRAY)
            return
        names, domains, ips, errors = parse_targets(text)
        if errors:
            self.lbl_preview.configure(text=errors[0], text_color=RED)
            return
        parts = []
        if names:
            parts.append("名称×%d" % len(names))
        if domains:
            parts.append("域名×%d" % len(domains))
        if ips:
            parts.append("IP×%d" % len(ips))
        self.lbl_preview.configure(text="识别：" + "、".join(parts), text_color=GREEN)

    # ---- 平台可用性 ----
    def _refresh_platforms(self):
        cfg = prov_layer.load_config(CONFIG_PATH)
        enabled = set(prov_layer.available_providers(cfg))
        for name, label in PLATFORM_LABELS:
            sw = self.sw_platforms[name]
            if name in enabled:
                sw.configure(text=label, state="normal")
                self.var_platforms[name].set(True)
            else:
                sw.configure(text=label + "（未配Key）", state="disabled")
                self.var_platforms[name].set(False)

    # ---- 输出目录浏览 ----
    def _browse_out(self):
        d = filedialog.askdirectory(initialdir=BASE_DIR, title="选择输出目录")
        if d:
            self.var_out.set(d)

    # ---- APP / 小程序包选择（本地静态分析）----
    def _pick_packages(self):
        paths = filedialog.askopenfilenames(
            title="选择 APK / 小程序包（可多选）",
            filetypes=[("APP 包", "*.apk *.wxapkg *.ap"), ("所有文件", "*.*")])
        if paths:
            self.var_packages.set(";".join(paths))

    def _pick_package_dir(self):
        d = filedialog.askdirectory(title="选择包含 APK / .wxapkg 的目录")
        if d:
            cur = self.var_packages.get().strip()
            self.var_packages.set((cur + ";" if cur else "") + d)

    def _pick_ports_file(self):
        p = filedialog.askopenfilename(
            title="选择端口字典（每行/逗号分隔，支持 8000-8100）",
            filetypes=[("文本文件", "*.txt *.lst *.csv"), ("所有文件", "*.*")])
        if p:
            self.var_ports_file.set(p)

    def _pick_scope_file(self):
        p = filedialog.askopenfilename(
            title="选择资产范围文件（每行一个 URL/域名/IP）",
            filetypes=[("文本文件", "*.txt *.csv *.list"), ("所有文件", "*.*")])
        if p:
            self.var_scope_file.set(p)

    def _pick_intel(self):
        p = filedialog.askopenfilename(
            title="选择外部模型/子 agent 产出的理解结果 JSON",
            filetypes=[("JSON", "*.json"), ("所有文件", "*.*")])
        if p:
            self.var_intel.set(p)

    # ---- 首次启动条款确认 ----
    def _open_terms(self):
        if os.path.isfile(TERMS_PATH):
            try:
                os.startfile(TERMS_PATH)   # noqa: S606
                return
            except Exception:
                pass
        webbrowser.open(TERMS_URL)

    def _check_terms(self):
        if os.path.isfile(TERMS_ACCEPTED):
            return
        win = ctk.CTkToplevel(self)
        win.title("使用条款确认 · CyberCensus")
        win.geometry("640x520")
        win.configure(fg_color=BG)
        win.transient(self)
        win.protocol("WM_DELETE_WINDOW", self.destroy)
        win.after(300, lambda: win.grab_set())

        ctk.CTkLabel(win, text="// 使用前请确认", font=self.f_mono,
                     text_color=ACCENT, anchor="w").pack(fill="x", padx=20, pady=(16, 4))
        ctk.CTkLabel(win, text="CyberCensus 仅限自有资产或已获明确书面授权的目标使用",
                     font=ctk.CTkFont(size=15, weight="bold"),
                     text_color=TEXT, anchor="w").pack(fill="x", padx=20)

        txt = ctk.CTkTextbox(win, fg_color="#08101c", text_color=TEXT,
                             font=self.f_mono_sm, corner_radius=8,
                             border_width=1, border_color=STROKE)
        txt.pack(fill="both", expand=True, padx=20, pady=12)
        txt.insert("end",
                   "使用本工具前，请确认：\n\n"
                   "1. 你只对本人拥有所有权的资产，或已取得资产所有者明确、"
                   "书面、可追溯授权的目标进行测绘、扫描或探测；\n"
                   "2. 你已阅读并同意 TERMS.md 中的使用条款与免责声明；\n"
                   "3. 你不得将本工具用于未授权扫描、非法入侵、拒绝服务、"
                   "弱口令爆破、验证码/风控绕过、数据窃取、恶意代码传播等行为；\n"
                   "4. 主动扫描会真实访问目标，请自行控制范围、并发与时间窗口，"
                   "并自行承担合规与操作风险。\n\n"
                   "完整条款：TERMS.md（随程序附带，也可点击下方按钮打开）\n"
                   "项目地址：https://github.com/Zerdon-me/CyberCensus\n")
        txt.configure(state="disabled")

        var = ctk.BooleanVar(value=False)
        ctk.CTkCheckBox(win, text="我已阅读并同意 TERMS.md，且仅对自有或已获书面授权的目标使用",
                        variable=var, font=self.f_body,
                        fg_color=ACCENT, hover_color=ACCENT_HOVER
                        ).pack(anchor="w", padx=22, pady=(0, 8))

        row = ctk.CTkFrame(win, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 16))
        ctk.CTkButton(row, text="阅读完整条款", width=120,
                      fg_color="transparent", border_width=1, border_color=STROKE,
                      text_color=TEXT, hover_color=CARD_HI,
                      command=self._open_terms).pack(side="left")
        ctk.CTkButton(row, text="退出", width=80,
                      fg_color="transparent", border_width=1, border_color=STROKE,
                      text_color=GRAY, hover_color=CARD_HI,
                      command=self.destroy).pack(side="right")
        btn = ctk.CTkButton(row, text="同意并继续", width=120,
                            fg_color=ACCENT, text_color=ON_ACCENT,
                            hover_color=ACCENT_HOVER, state="disabled",
                            command=lambda: self._accept_terms(win))
        btn.pack(side="right", padx=8)
        var.trace_add("write", lambda *_: btn.configure(
            state="normal" if var.get() else "disabled"))

    def _accept_terms(self, win):
        try:
            with open(TERMS_ACCEPTED, "w", encoding="utf-8") as f:
                f.write("accepted %s\n" % cybercensus.__version__)
        except Exception:
            pass
        try:
            win.grab_release()
        except Exception:
            pass
        win.destroy()
        self._append_log("已确认使用条款（仅限自有或已获书面授权的目标）", "+")

    # ---- 关于 ----
    def _open_about(self):
        win = ctk.CTkToplevel(self)
        win.title("关于 CyberCensus")
        win.geometry("560x460")
        win.configure(fg_color=BG)
        win.transient(self)
        win.after(250, lambda: win.grab_set())
        ctk.CTkLabel(win, text="CyberCensus", font=self.f_brand,
                     text_color=TEXT).pack(anchor="w", padx=24, pady=(20, 0))
        ctk.CTkLabel(win, text="互联网暴露面测绘工具 · v%s"
                     % cybercensus.__version__, font=self.f_body,
                     text_color=ACCENT).pack(anchor="w", padx=24, pady=(0, 10))
        for line in (
                "许可证：Apache-2.0",
                "仅限自有资产或已获明确书面授权的目标使用。",
                "默认被动优先；主动扫描会真实访问目标，请先确认授权。",
                "项目：https://github.com/Zerdon-me/CyberCensus",
                "条款：TERMS.md（使用条款与免责声明）"):
            ctk.CTkLabel(win, text=line, font=self.f_mono_sm,
                         text_color=GRAY, wraplength=500, justify="left",
                         anchor="w").pack(fill="x", padx=24, pady=2)
        # 关联源清单（内置 + 可选）
        try:
            from pivots import PIVOT_REGISTRY
            rows = PIVOT_REGISTRY.describe()
        except Exception:
            rows = []
        ctk.CTkLabel(win, text="关联源", font=self.f_body, text_color=TEXT,
                     anchor="w").pack(fill="x", padx=24, pady=(10, 2))
        for name, label, status in rows[:10]:
            dot = "●" if status == "可用" else "○"
            color = GREEN if status == "可用" else GRAY
            ctk.CTkLabel(win, text="%s %s（%s）— %s" % (dot, label, name, status),
                         font=self.f_mono_sm, text_color=color,
                         anchor="w").pack(fill="x", padx=28, pady=1)
        row = ctk.CTkFrame(win, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(16, 12))
        ctk.CTkButton(row, text="打开 TERMS", width=110,
                      fg_color="transparent", border_width=1, border_color=STROKE,
                      text_color=TEXT, hover_color=CARD_HI,
                      command=self._open_terms).pack(side="left")
        ctk.CTkButton(row, text="打开 GitHub", width=110,
                      fg_color="transparent", border_width=1, border_color=STROKE,
                      text_color=ACCENT, hover_color=CARD_HI,
                      command=lambda: webbrowser.open(
                          "https://github.com/Zerdon-me/CyberCensus")
                      ).pack(side="left", padx=8)
        ctk.CTkButton(row, text="关闭", width=80,
                      fg_color=ACCENT, text_color=ON_ACCENT,
                      hover_color=ACCENT_HOVER,
                      command=win.destroy).pack(side="right")

    # ---- Key 配置对话框 ----
    def _open_key_dialog(self):
        win = ctk.CTkToplevel(self)
        win.title("平台 API Key 配置（写入 config.json；环境变量优先于本文件）")
        win.geometry("580x560")
        win.resizable(False, False)
        win.after(300, lambda: win.grab_set())   # CTkToplevel 需等窗口显示后再 grab

        data = {}
        if os.path.isfile(CONFIG_PATH):
            try:
                with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
            except Exception:
                data = {}
        for k in ("fofa", "zerozone", "hunter", "daydaymap",
                  "zoomeye", "quake", "shodan", "censys"):
            data.setdefault(k, {})

        fields = [
            ("FOFA 邮箱", "fofa", "email", False),
            ("FOFA Key", "fofa", "key", True),
            ("0.zone Key", "zerozone", "key", True),
            ("鹰图 Hunter Key", "hunter", "key", True),
            ("DayDayMap Key", "daydaymap", "key", True),
            ("ZoomEye Key", "zoomeye", "key", True),
            ("360 Quake Token", "quake", "key", True),
            ("Shodan Key", "shodan", "key", True),
            ("Censys API ID", "censys", "id", False),
            ("Censys Secret", "censys", "secret", True),
        ]
        entries = []
        for i, (label, sec, key, secret) in enumerate(fields):
            ctk.CTkLabel(win, text=label).grid(row=i, column=0, sticky="e",
                                               padx=(14, 6), pady=7)
            var = ctk.StringVar(value=str(data.get(sec, {}).get(key, "") or ""))
            ent = ctk.CTkEntry(win, textvariable=var, width=340, show="*" if secret else "")
            ent.grid(row=i, column=1, sticky="w", padx=(0, 10))
            entries.append((sec, key, var, ent))

        var_show = ctk.BooleanVar(value=False)

        def _toggle_show():
            show = "" if var_show.get() else "*"
            for sec, key, var, ent in entries:
                if ent.cget("show"):
                    ent.configure(show=show)

        ctk.CTkSwitch(win, text="显示明文", variable=var_show, command=_toggle_show
                      ).grid(row=len(fields), column=1, sticky="w")

        def _save():
            for sec, key, var, ent in entries:
                data.setdefault(sec, {})[key] = var.get().strip()
            try:
                with open(CONFIG_PATH, "w", encoding="utf-8") as fh:
                    json.dump(data, fh, ensure_ascii=False, indent=2)
            except Exception as e:
                messagebox.showerror("保存失败", str(e), parent=win)
                return
            self._refresh_platforms()
            messagebox.showinfo("已保存", "config.json 已更新。", parent=win)
            win.destroy()

        frm = ctk.CTkFrame(win, fg_color="transparent")
        frm.grid(row=len(fields) + 1, column=0, columnspan=2, pady=(10, 4))
        ctk.CTkButton(frm, text="保存", width=100, command=_save).pack(side="left", padx=8)
        ctk.CTkButton(frm, text="取消", width=100, fg_color="gray40",
                      command=win.destroy).pack(side="left", padx=8)

    # ---- 开始/停止 ----
    def _on_start(self):
        if self._worker and self._worker.is_alive():
            return
        names, domains, ips, errors = parse_targets(self.ent_target.get())
        if errors:
            messagebox.showerror("目标解析失败", "\n".join(errors))
            return
        if not names and not domains and not ips:
            messagebox.showwarning("缺少目标",
                                   "请输入单位名称 / 域名 / IP / 网段（可多个，空格或逗号分隔）")
            return
        mode = MODE_MAP.get(self._mode, "standard")
        if mode == "active" and not self.var_auth.get():
            messagebox.showwarning("需要授权确认",
                                   "主动扫描会真实访问并扫描目标，请先勾选书面授权确认。")
            return
        if self.var_fullports.get():
            if not messagebox.askyesno("全端口确认", "全端口 1-65535 非常慢，确定继续？"):
                return
        if self.var_scan_asn.get() and not self.var_auth.get():
            messagebox.showwarning("需要授权", "扫描 ASN 网段属于主动行为，请先勾选书面授权确认。")
            return
        platforms = [n for n, v in self.var_platforms.items() if v.get()]
        packages = [p.strip() for p in re.split(r"[;\n]+", self.var_packages.get())
                    if p.strip()]
        outdir = os.path.abspath(self.var_out.get().strip() or "cybercensus_out")
        args = build_args(
            mode, platforms,
            threads=_to_int(self.cmb_threads.get(), 20),
            provider_pages=_to_int(self.cmb_pages.get(), 1),
            cscan=self.var_cscan.get(),
            top=_to_int(self.cmb_top.get(), 0),
            ports=self.var_ports.get().strip(),
            ports_file=self.var_ports_file.get().strip(),
            full_ports=self.var_fullports.get(),
            out=outdir,
            debug_provider=self.var_debug.get(),
            sensitive=self.var_sensitive.get(),
            probe_interval=0.0,
            webhook=self.var_webhook.get().strip(),
            ext=self.var_ext.get(),
            packages=packages,
            intel=self.var_intel.get().strip(),
            fast=self.var_fast.get(),
            paths=self.var_paths.get(),
            provider_keyword=self.var_pkw.get(),
            asn=self.var_asn.get().strip(),
            scan_asn=self.var_scan_asn.get(),
            watch=_to_int(self.var_watch.get(), 0),
            scope_file=self.var_scope_file.get().strip(),
            only_scope=self.var_only_scope.get(),
            keep=_to_int(self.var_keep.get(), 0),
        )
        self._last_out_dir = args.out
        self._last_watch = max(0, int(getattr(args, "watch", 0) or 0))
        if getattr(self, "_auto_timer", None):
            try:
                self.after_cancel(self._auto_timer)
            except Exception:
                pass
            self._auto_timer = None

        # 重置界面状态
        self.txt_log.configure(state="normal")
        self.txt_log.delete("1.0", "end")
        self.txt_log.configure(state="disabled")
        self.tree.delete(*self.tree.get_children())
        self.tree_apps.delete(*self.tree_apps.get_children())
        self._asset_filter = None
        self._asset_by_iid = {}
        self._checked = set()
        self.var_asset_search.set("")
        self._last_engine = None
        self._apply_card_styles()
        for card in (self.card_confirmed, self.card_suspect, self.card_rejected):
            card.configure(text="…")
        self.btn_report.configure(state="disabled")
        self.btn_open_out.configure(state="disabled")
        self.btn_open_report.configure(state="disabled")
        self.btn_open_html.configure(state="disabled")
        self._last_md_path = None
        self._last_html_path = None
        self.tabview.set("运行日志")

        self._set_running(True)
        self._stop_flag.clear()
        if not platforms:
            self._append_log("未选择任何平台（或未配 Key）：只跑本地被动采集。", "!")
        self._append_log("目标已提交，开始测绘…", "#")
        self.bar.set(0)
        self._scan_start = time.time()
        self._eta = None
        self._prog_samples = []
        self._eta_samples = []
        self._last_prog_time = self._scan_start
        self._prog_stage = ""
        self.lbl_progress.configure(text="0% · 估算中…", text_color=ACCENT)

        cybercensus.LOG_HOOK = lambda msg, level: self._queue.put(("log", msg, level))
        cybercensus.PROGRESS_HOOK = (
            lambda pct, text="": self._queue.put(("progress", pct, text)))
        self._worker = threading.Thread(target=self._run,
                                        args=(args, names, domains, ips),
                                        daemon=True)
        self._worker.start()

    def _run(self, args, names, domains, ips):
        try:
            # 界面模式：只采集+分级，结果先展示在"资产列表"，
            # 报告由用户点"生成报告"时按所选格式再写文件
            eng, _files, _jp, _mp = cybercensus.run_pipeline(
                args, names, domains, ips,
                should_stop=self._stop_flag.is_set, do_output=False)
            self._queue.put(("done", (eng,)))
        except Exception:
            self._queue.put(("error", traceback.format_exc()))

    def _auto_restart(self):
        self._auto_timer = None
        if self._worker and self._worker.is_alive():
            return
        try:
            self._append_log("持续监控：自动开始下一轮扫描…", "#")
            self._on_start()
        except Exception:
            pass

    def _on_stop(self):
        if self._auto_timer:
            try:
                self.after_cancel(self._auto_timer)
            except Exception:
                pass
            self._auto_timer = None
            self.btn_stop.configure(state="disabled", text="⏹ 停止并输出")
            self._append_log("已取消持续监控（本次结果保留）。", "!")
            return
        if not (self._worker and self._worker.is_alive()):
            return
        self._stop_flag.set()
        self.btn_stop.configure(state="disabled")
        self._append_log("已请求停止：当前阶段结束后对已收集数据做分级输出。", "!")

    def _set_running(self, running):
        self.btn_start.configure(state="disabled" if running else "normal")
        self.btn_stop.configure(state="normal" if running else "disabled",
                                text="⏹ 停止并输出")
        if hasattr(self, "btn_update_tools"):
            self.btn_update_tools.configure(state="disabled" if running else "normal")
        if running:
            self._set_status("● 运行中", ORANGE)
        else:
            self.bar.stop()

    # ---- 队列轮询（工作线程 → 界面线程）----
    def _poll(self):
        try:
            while True:
                item = self._queue.get_nowait()
                if item[0] == "log":
                    self._append_log(item[1], item[2])
                elif item[0] == "progress":
                    self._on_progress(item[1], item[2])
                elif item[0] == "done":
                    self._on_done(*item[1])
                elif item[0] == "report_done":
                    self._on_report_done(*item[1])
                elif item[0] == "error":
                    self._on_error(item[1])
        except queue.Empty:
            pass
        self.after(100, self._poll)

    @staticmethod
    def _fmt_dur(sec):
        sec = max(0, int(sec))
        if sec < 60:
            return "%d 秒" % sec
        if sec < 3600:
            return "%d 分 %02d 秒" % (sec // 60, sec % 60)
        return "%d 时 %02d 分" % (sec // 3600, (sec % 3600) // 60)

    def _on_progress(self, pct, text=""):
        try:
            pct = max(0, min(100, int(pct)))
        except Exception:
            return
        now = time.time()
        self.bar.set(pct / 100.0)
        elapsed = max(0.1, now - (self._scan_start or now))
        self._last_prog_time = now
        if text:
            self._prog_stage = text
        if pct >= 100:
            self.lbl_progress.configure(
                text="100%% · 用时 %s" % self._fmt_dur(elapsed),
                text_color=GREEN)
            return
        if pct <= 0:
            self.lbl_progress.configure(text="0% · 估算中…", text_color=ACCENT)
            return

        # 记录最近 90 秒的 (时间, 百分比)，用"最近速率"而不是全程平均：
        # 各阶段耗时差异很大，全程平均会在进入快阶段后严重高估。
        self._prog_samples.append((now, pct))
        self._prog_samples = [(t, p) for t, p in self._prog_samples
                              if now - t <= 90]
        raw = None
        if len(self._prog_samples) >= 2 and elapsed >= 8 and pct >= 3:
            t0, p0 = self._prog_samples[0]
            dt = now - t0
            dp = pct - p0
            if dt >= 5 and dp > 0:
                raw = (100 - pct) * dt / dp
        if raw is not None:
            self._eta_samples.append(raw)
            self._eta_samples = self._eta_samples[-7:]
            ordered = sorted(self._eta_samples)
            med = ordered[len(ordered) // 2]
            # 再做一次轻平滑，避免单次阶段跳变导致数字大幅跳动
            self._eta = med if self._eta is None else self._eta * 0.6 + med * 0.4
        stage = (self._prog_stage or "")[:18]
        if self._eta is None or elapsed < 8 or pct < 3:
            self.lbl_progress.configure(
                text="%d%% · %s · 估算中…" % (pct, stage or "准备"),
                text_color=ACCENT)
        else:
            self.lbl_progress.configure(
                text="%d%% · %s · 约剩 %s"
                     % (pct, stage or "扫描", self._fmt_dur(self._eta)),
                text_color=ACCENT)

    def _tick_eta(self):
        """长时间没有进度上报时（如平台 API 等待），提示而不是让 ETA 乱跳。"""
        try:
            running = self._worker and self._worker.is_alive()
            if (running and self._last_prog_time
                    and time.time() - self._last_prog_time > 40):
                base = self.lbl_progress.cget("text").split(" · 约剩")[0]
                self.lbl_progress.configure(
                    text="%s · 当前阶段较慢…" % base, text_color=ORANGE)
            self.after(2000, self._tick_eta)
        except Exception:
            pass

    def _on_done(self, eng):
        self._set_running(False)
        self.bar.set(1)
        if self._scan_start:
            self.lbl_progress.configure(
                text="100%% · 用时 %s" % self._fmt_dur(time.time() - self._scan_start),
                text_color=GREEN)
        self._last_engine = eng
        counts = {"确认": 0, "疑似": 0, "存疑": 0}
        for a in eng.assets.values():
            counts[a.confidence] = counts.get(a.confidence, 0) + 1
        self.card_confirmed.configure(text=str(counts["确认"]))
        self.card_suspect.configure(text=str(counts["疑似"]))
        self.card_rejected.configure(text=str(counts["存疑"]))
        self._populate_table(eng)
        self._populate_apps(eng)
        self._append_log("=" * 60, "#")
        self._append_log("完成：确认 %d | 疑似 %d | 剔除 %d | 合计 %d"
                         % (counts["确认"], counts["疑似"], counts["存疑"], len(eng.assets)), "#")
        if (self._last_watch and not self._stop_flag.is_set()
                and self.winfo_exists()):
            ms = self._last_watch * 60 * 1000
            self._auto_timer = self.after(ms, self._auto_restart)
            self.btn_stop.configure(state="normal", text="⏹ 停止监控")
            self._append_log("持续监控：%d 分钟后自动进行下一轮（点「停止监控」或关闭窗口可停止）"
                             % self._last_watch, "#")
        extra = []
        if getattr(eng, "apps", None):
            extra.append("APP %d 个" % len(eng.apps))
        if getattr(eng, "packages", None):
            extra.append("APP/小程序包 %d 个" % len(eng.packages))
        if getattr(eng, "js_secrets", None):
            extra.append("JS 密钥线索 %d 处" % len(eng.js_secrets))
        if getattr(eng, "ext_hits", None):
            extra.append("外部工具命中 %d 条" % len(eng.ext_hits))
        if extra:
            self._append_log("其他发现：" + " / ".join(extra) + "（报告中有单独章节）", "+")
        # 即使资产为 0，只要 APP / 包 / 密钥等有结果，也允许生成报告
        has_results = bool(eng.assets or extra)
        if has_results:
            self.btn_report.configure(state="normal")   # 结果就绪，可按需生成报告
            if eng.assets:
                self.tabview.set("资产列表")
            elif getattr(eng, "apps", None):
                self.tabview.set("APP 应用")
            self._set_status("● 扫描完成", GREEN)
        else:
            self._append_log("未发现任何资产或线索，无需生成报告。", "!")
            self._set_status("● 未发现资产", ORANGE)

    def _on_error(self, tb_text):
        self._set_running(False)
        self.bar.set(0)
        self.lbl_progress.configure(text="0% · 出错", text_color=RED)
        self._set_status("● 出错", RED)
        for card in (self.card_confirmed, self.card_suspect, self.card_rejected):
            card.configure(text="0")
        if getattr(self, "_last_engine", None) is not None:
            self.btn_report.configure(state="normal")
        self._append_log("运行出错：", "!")
        for line in tb_text.strip().splitlines()[-8:]:
            self._append_log("  " + line, "!")

    # ---- 生成报告（按需导出，用户选格式）----
    def _open_report_dialog(self):
        eng = getattr(self, "_last_engine", None)
        if eng is None:
            return
        win = ctk.CTkToplevel(self)
        win.title("生成报告")
        win.geometry("600x590")
        win.resizable(False, False)
        win.after(300, lambda: win.grab_set())

        ctk.CTkLabel(win, text="选择要导出的报告格式",
                     font=ctk.CTkFont(size=14, weight="bold")).pack(anchor="w",
                                                                    padx=18, pady=(14, 2))
        ctk.CTkLabel(win, text="可多选；每个格式的用途见括号说明",
                     font=self.f_mono_sm, text_color=GRAY
                     ).pack(anchor="w", padx=20, pady=(0, 6))

        var_html = ctk.BooleanVar(value=True)
        var_pdf = ctk.BooleanVar(value=False)
        var_docx = ctk.BooleanVar(value=False)
        var_txt = ctk.BooleanVar(value=False)
        var_md = ctk.BooleanVar(value=True)
        var_csv = ctk.BooleanVar(value=True)
        var_json = ctk.BooleanVar(value=False)

        opts = [
            (var_html, "网页报告（HTML）—— 带资产关系图，适合交付、浏览器直接查看/打印"),
            (var_pdf, "PDF 报告 —— 由 HTML 无头打印生成，适合邮件、存档、打印（需 Edge/Chrome）"),
            (var_docx, "Word 报告（DOCX）—— 可编辑，适合二次编写、加公司抬头"),
            (var_txt, "纯文本报告（TXT）—— 适合贴聊天工具、工单系统、邮件正文"),
            (var_md, "Markdown 报告（MD）—— 纯文本带排版标记，适合 Git/文档系统"),
            (var_csv, "资产台账（CSV）—— 适合 Excel 管理、筛选、交付客户"),
            (var_json, "原始数据（JSON）—— 完整结构化数据，适合程序二次处理"),
        ]
        for var, label in opts:
            ctk.CTkSwitch(win, text=label, variable=var,
                          font=ctk.CTkFont(size=12)
                          ).pack(anchor="w", padx=22, pady=4)

        ctk.CTkLabel(win, text="提示：PDF 依赖本机 Edge/Chrome；没有浏览器时请选 HTML。",
                     font=self.f_mono_sm, text_color=GRAY
                     ).pack(anchor="w", padx=22, pady=(4, 0))

        frm_dir = ctk.CTkFrame(win, fg_color="transparent")
        frm_dir.pack(fill="x", padx=18, pady=(10, 4))
        ctk.CTkLabel(frm_dir, text="保存到").pack(side="left", padx=(0, 6))
        var_out = ctk.StringVar(value=self.var_out.get().strip() or "cybercensus_out")
        ctk.CTkEntry(frm_dir, textvariable=var_out).pack(side="left", fill="x",
                                                         expand=True, padx=(0, 6))
        ctk.CTkButton(frm_dir, text="浏览…", width=70,
                      command=lambda: var_out.set(
                          filedialog.askdirectory(initialdir=BASE_DIR) or var_out.get())
                      ).pack(side="left")

        def _generate():
            fmts = [k for k, v in (
                ("html", var_html.get()), ("pdf", var_pdf.get()),
                ("docx", var_docx.get()), ("txt", var_txt.get()),
                ("md", var_md.get()), ("csv", var_csv.get()),
                ("json", var_json.get())) if v]
            if not fmts:
                messagebox.showwarning("未选择格式", "请至少选择一种报告格式。", parent=win)
                return
            win.destroy()
            self._generate_report(eng, fmts, var_out.get().strip() or "cybercensus_out")

        ctk.CTkButton(win, text="生成", width=110, command=_generate
                      ).pack(pady=(12, 16))

    def _generate_report(self, eng, fmts, outdir):
        outdir = os.path.abspath(outdir)
        eng.args.output_formats = ",".join(fmts)
        eng.args.out = outdir
        self._last_out_dir = outdir

        def _job():
            try:
                cybercensus.LOG_HOOK = lambda msg, level: self._queue.put(("log", msg, level))
                files, json_path, md_path = eng.output()
                self._queue.put(("report_done", (files, json_path, md_path)))
            except Exception:
                self._queue.put(("error", traceback.format_exc()))

        self.btn_report.configure(state="disabled")
        self._append_log("== 生成报告（%s）==" % "+".join(fmts), "#")
        threading.Thread(target=_job, daemon=True).start()

    def _on_report_done(self, files, json_path, md_path):
        n = len(files) + (1 if json_path else 0) + (1 if md_path else 0)
        if n == 0:
            self._append_log("报告生成失败：没有产生任何文件（PDF 需要本机 Edge/Chrome）", "!")
            self.btn_report.configure(state="normal")
            self._set_status("● 报告生成失败", RED)
            messagebox.showwarning("生成失败",
                                   "没有生成任何文件，请查看运行日志；"
                                   "PDF 需要本机安装 Edge 或 Chrome。")
            return
        self._append_log("报告已生成：%d 个文件" % n, "+")
        if files.get("confirmed"):
            self._append_log("确认台账：%s" % files["confirmed"], "+")
        if md_path:
            self._last_md_path = md_path
            self._append_log("可读报告：%s" % md_path, "+")
        self.btn_report.configure(state="normal")
        if files or json_path or md_path:
            self.btn_open_out.configure(state="normal")
        if md_path:
            self.btn_open_report.configure(state="normal")
        if files.get("html"):
            self._last_html_path = files["html"]
            self.btn_open_html.configure(state="normal")
            self._append_log("网页报告：%s" % files["html"], "+")
        for key, label in (("docx", "Word 报告"), ("pdf", "PDF 报告"),
                           ("txt", "纯文本报告")):
            if files.get(key):
                self._append_log("%s：%s" % (label, files[key]), "+")
        self._set_status("● 报告已生成", GREEN)
        messagebox.showinfo("完成", "报告已生成（%d 个文件），见「打开输出文件夹」。" % n)

    # ---- 打开产物 ----
    def _open_out(self):
        if self._last_out_dir and os.path.isdir(self._last_out_dir):
            os.startfile(self._last_out_dir)   # noqa: S606 (Windows only)

    def _open_report(self):
        if self._last_md_path and os.path.isfile(self._last_md_path):
            os.startfile(self._last_md_path)   # noqa: S606

    def _open_html(self):
        if self._last_html_path and os.path.isfile(self._last_html_path):
            os.startfile(self._last_html_path)   # noqa: S606

    # ---- 日志输出 ----
    def _append_log(self, msg, level="*"):
        tag = {"#": "hdr", "+": "good", "!": "warn"}.get(level, "norm")
        self.txt_log.configure(state="normal")
        try:
            self.txt_log.insert("end", "[%s] %s\n" % (level, msg), tag)
        except Exception:
            self.txt_log.insert("end", "[%s] %s\n" % (level, msg))
        self.txt_log.see("end")
        self.txt_log.configure(state="disabled")

    # ---- 关闭 ----
    def _on_close(self):
        if self._worker and self._worker.is_alive():
            if not messagebox.askyesno(APP_TITLE, "测绘仍在运行，确定退出吗？"):
                return
        cybercensus.LOG_HOOK = None
        if getattr(self, "_cruise_proc", None):
            try:
                if self._cruise_proc.poll() is None:
                    self._cruise_proc.terminate()
            except Exception:
                pass
        self._stop_flag.set()
        if self._auto_timer:
            try:
                self.after_cancel(self._auto_timer)
            except Exception:
                pass
        self.destroy()


def _run_cli_tasks(argv):
    """exe / pyw 的 CLI 模式：后台定时巡航（无窗口，输出写日志）。"""
    log_path = os.path.join(BASE_DIR, "cybercensus_cruise.log")
    log = open(log_path, "a", encoding="utf-8", buffering=1)
    sys.stdout = log
    sys.stderr = log
    sys.argv = ["cybercensus.py"] + list(argv)
    try:
        return cybercensus.main()
    finally:
        try:
            log.flush()
        except Exception:
            pass


def main(argv=None):
    argv = list(sys.argv[1:] if argv is None else argv)
    if argv and argv[0] in ("--tasks", "--tasks-once", "--tasks-status"):
        return _run_cli_tasks(argv)
    if "--smoke" in argv:
        # 自检：构建界面后立即销毁（验证控件/布局无异常）
        app = App()
        app.update_idletasks()
        app.update()
        app.destroy()
        print("GUI smoke OK")
        return 0
    app = App()
    app.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
