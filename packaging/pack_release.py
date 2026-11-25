#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""组装 Windows 免安装发布包（exe + 增强引擎 + nuclei 模板）。

用法：
  py -3.11 packaging/pack_release.py
  py -3.11 packaging/pack_release.py --skip-exe      # 复用已有 dist/CyberCensus.exe
  py -3.11 packaging/pack_release.py --no-templates  # 不打包 nuclei 模板（体积小很多）

产物：
  dist/CyberCensus-win64/CyberCensus.exe
  dist/CyberCensus-win64/tools/{subfinder,httpx,wafw00f,nuclei}.exe
  dist/CyberCensus-win64/nuclei-templates/
  dist/CyberCensus-win64.zip

说明：工具是独立的开源程序，CyberCensus 负责调度；放进同一个文件夹即可
免 PATH、免安装 Python。
"""

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
import time

# GitHub Actions 的 Windows 控制台可能是 cp1252；中文 print 会直接崩，
# 这里让不可编码字符替换输出，保证打包步骤不会因日志编码失败。
try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
# 在临时暂存目录组装，避免用户正开着上一版 CyberCensus.exe 时文件被锁、
# 导致无法删除/覆盖发布目录。
STAGE = os.path.join(DIST, "_pkg_stage_%d" % os.getpid())
PKG = os.path.join(STAGE, "CyberCensus-win64")
TOOLS = os.path.join(PKG, "tools")

TOOL_NAMES = ("subfinder", "httpx", "wafw00f", "nuclei")


def _find_tool(name):
    """优先 dist/ 下准备好的独立 exe，再退回 PATH。

    wafw00f 的 pip 启动器依赖本机 Python，不能直接发给用户，因此必须用
    PyInstaller 冻好的 dist/wafw00f.exe。
    """
    frozen = [os.path.join(DIST, name + ".exe"),
              os.path.join(ROOT, "tools", name + ".exe")]
    for cand in frozen:
        if os.path.isfile(cand):
            return cand
    return shutil.which(name) or ""


def _copy_tools():
    os.makedirs(TOOLS, exist_ok=True)
    missing = []
    for name in TOOL_NAMES:
        src = _find_tool(name)
        if not src:
            missing.append(name)
            continue
        dst = os.path.join(TOOLS, name + ".exe")
        # 杀软会对刚复制的大 exe 短暂加锁，重试几次
        for attempt in range(6):
            try:
                shutil.copy2(src, dst)
                break
            except PermissionError:
                if attempt == 5:
                    raise
                time.sleep(1.0)
        print("  + %-12s %s (%.1f MB)"
              % (name, os.path.basename(src), os.path.getsize(dst) / 1048576.0))
    if missing:
        print("  ! 未找到: %s（发布包中对应功能会自动跳过）"
              % ", ".join(missing))
    return missing


def _copy_templates(templates_dir):
    dst = os.path.join(PKG, "nuclei-templates")
    if os.path.isdir(dst):
        shutil.rmtree(dst)
    if not templates_dir or not os.path.isdir(templates_dir):
        print("  ! 未找到 nuclei 模板目录，跳过（首次运行 nuclei 会提示下载）")
        return False
    print("  + nuclei-templates <- %s（%d 个文件）"
          % (templates_dir, sum(len(fs) for _, _, fs in os.walk(templates_dir))))
    shutil.copytree(templates_dir, dst)
    return True


def _copy_legal_files():
    for name in ("LICENSE", "NOTICE", "THIRD_PARTY_NOTICES.md", "README.md",
                 "README.en.md", "SECURITY.md", "CONTRIBUTING.md",
                 "CODE_OF_CONDUCT.md", "CHANGELOG.md", "COMMERCIAL.md"):
        src = os.path.join(ROOT, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(PKG, name))
            print("  + %s" % name)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _write_checksums():
    lines = []
    for name in ("CyberCensus.exe", "tools/subfinder.exe", "tools/httpx.exe",
                 "tools/wafw00f.exe", "tools/nuclei.exe"):
        p = os.path.join(PKG, name.replace("/", os.sep))
        if os.path.isfile(p):
            lines.append("%s  %s" % (_sha256(p), name))
    if lines:
        text = "\n".join(lines) + "\n"
        with open(os.path.join(PKG, "SHA256SUMS.txt"), "w",
                  encoding="utf-8") as f:
            f.write(text)
        with open(os.path.join(DIST, "SHA256SUMS.txt"), "w",
                  encoding="utf-8") as f:
            f.write(text)


def _write_readme():
    path = os.path.join(PKG, "使用说明.txt")
    with open(path, "w", encoding="utf-8") as f:
        f.write(
            "CyberCensus 免安装版\n"
            "====================\n\n"
            "1. 双击 CyberCensus.exe 直接运行（无需安装 Python）。\n"
            "2. tools/ 里是增强引擎（subfinder / httpx / wafw00f / nuclei），\n"
            "   程序会自动发现并调用，不需要配置 PATH。\n"
            "3. nuclei-templates/ 是官方模板，nuclei 会自动使用。\n"
            "4. 没有 tools/ 时 CyberCensus 仍可正常运行，只是少了这几项增强。\n\n"
            "仅限已获得书面授权的目标使用。\n")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--skip-exe", action="store_true", help="复用现有 dist/CyberCensus.exe")
    ap.add_argument("--no-templates", action="store_true", help="不打包 nuclei 模板")
    ap.add_argument("--templates", default=os.path.join(
        os.path.expanduser("~"), "nuclei-templates"), help="nuclei 模板目录")
    args = ap.parse_args()

    exe = os.path.join(DIST, "CyberCensus.exe")
    if not args.skip_exe:
        print("== 构建 CyberCensus.exe ==")
        cmd = [sys.executable, "-m", "PyInstaller", "--noconfirm", "--onefile",
               "--windowed", "--name", "CyberCensus",
               "--icon", os.path.join(ROOT, "docs", "logo.ico"),
               "--add-data", "docs/logo.png;docs",
               "--collect-all", "customtkinter", "--collect-all", "pypinyin",
               "asm_gui.pyw"]
        subprocess.check_call(cmd, cwd=ROOT)
    if not os.path.isfile(exe):
        raise SystemExit("找不到 %s，请先构建 exe" % exe)

    print("== 组装发布目录 ==")
    os.makedirs(PKG)
    shutil.copy2(exe, os.path.join(PKG, "CyberCensus.exe"))
    print("  + CyberCensus.exe (%.1f MB)" % (os.path.getsize(exe) / 1048576.0))
    _copy_tools()
    if not args.no_templates:
        _copy_templates(args.templates)
    _copy_legal_files()
    _write_checksums()
    _write_readme()

    print("== 压缩 ==")
    zip_base = os.path.join(DIST, "CyberCensus-win64")
    zip_path = zip_base + ".zip"
    if os.path.isfile(zip_path):
        os.remove(zip_path)
    for attempt in range(5):
        try:
            shutil.make_archive(zip_base, "zip", STAGE, "CyberCensus-win64")
            break
        except PermissionError:
            if attempt == 4:
                raise
            time.sleep(1.5)
    size = os.path.getsize(zip_path) / 1048576.0
    shutil.rmtree(STAGE, ignore_errors=True)
    print("完成：%s (%.1f MB)" % (zip_path, size))
    print("解压后双击 CyberCensus.exe 即可使用，无需安装依赖。")


if __name__ == "__main__":
    main()
