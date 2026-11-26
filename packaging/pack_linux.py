#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""组装 Linux 免安装包（CLI + 增强引擎 + nuclei 模板）。

用法：
  python3 packaging/pack_linux.py \
      --tools build_tools --templates nuclei-templates

产物：
  dist/CyberCensus-linux-x86_64.tar.gz
  dist/SHA256SUMS-linux.txt

说明：Linux 包只提供命令行（GUI 依赖桌面环境和 python3-tk，源码运行即可）。
"""

import argparse
import hashlib
import os
import shutil
import sys
import tarfile
import tempfile

try:
    sys.stdout.reconfigure(errors="replace")
    sys.stderr.reconfigure(errors="replace")
except Exception:
    pass

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DIST = os.path.join(ROOT, "dist")
NAME = "CyberCensus-linux-x86_64"
TOOL_NAMES = ("subfinder", "httpx", "nuclei")

TOP_FILES = ("cybercensus.py", "providers.py", "tool_updater.py",
             "port_presets.py", "requirements-cli.txt", "README.md", "README.en.md",
             "LICENSE", "NOTICE", "TERMS.md", "TERMS.en.md",
             "COMMERCIAL.md", "SECURITY.md",
             "CHANGELOG.md")

WRAPPER = """#!/usr/bin/env bash
here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "$here/.venv/bin/python" ]; then
  PY="$here/.venv/bin/python"
else
  PY=python3
fi
exec "$PY" "$here/cybercensus.py" "$@"
"""

INSTALL = """#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"
python3 -m venv .venv
./.venv/bin/pip install -U pip
./.venv/bin/pip install -r requirements-cli.txt
echo
echo "安装完成：./cybercensus -n \\"单位名称\\""
echo "仅限自有资产或已获书面授权的目标使用。"
"""

README = """CyberCensus Linux 版（命令行）
================================

1. 首次运行先装依赖：./install.sh
2. 之后直接用：./cybercensus -n "单位名称"
3. tools/ 里自带 subfinder / httpx / nuclei，程序会自动调用，
   不需要配置 PATH。
4. nuclei-templates/ 是官方模板，nuclei 会自动使用。
5. 需要图形界面时，在装了桌面环境的 Linux 上运行：
   pip3 install customtkinter && python3 asm_gui.pyw
   （部分发行版还需要先安装 python3-tk）

仅限自有资产或已获书面授权的目标使用。
"""


def _copy_tools(tools_dir, dst):
    os.makedirs(dst, exist_ok=True)
    missing = []
    for name in TOOL_NAMES:
        src = os.path.join(tools_dir, name)
        if not os.path.isfile(src):
            missing.append(name)
            continue
        out = os.path.join(dst, name)
        shutil.copy2(src, out)
        os.chmod(out, 0o755)
        print("  + tools/%s (%.1f MB)" % (name, os.path.getsize(out) / 1048576.0))
    if missing:
        print("  ! 未找到: %s（对应功能会自动跳过）" % ", ".join(missing))


def _copy_templates(src, dst):
    if not src or not os.path.isdir(src):
        print("  ! 未找到 nuclei 模板目录，跳过")
        return
    shutil.copytree(src, dst)
    print("  + nuclei-templates（%d 个文件）"
          % sum(len(fs) for _, _, fs in os.walk(dst)))


def _write(path, text, mode=0o644):
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write(text)
    os.chmod(path, mode)


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tools", default=os.path.join(ROOT, "build_tools"),
                    help="包含 subfinder / httpx / nuclei 的目录")
    ap.add_argument("--templates", default=os.path.join(ROOT, "nuclei-templates"),
                    help="nuclei 模板目录")
    args = ap.parse_args()

    os.makedirs(DIST, exist_ok=True)
    stage = tempfile.mkdtemp(prefix="cc_linux_")
    pkg = os.path.join(stage, NAME)
    os.makedirs(pkg)

    print("== 组装 Linux 包 ==")
    for name in TOP_FILES:
        src = os.path.join(ROOT, name)
        if os.path.isfile(src):
            shutil.copy2(src, os.path.join(pkg, name))
            print("  + %s" % name)

    docs = os.path.join(ROOT, "docs")
    if os.path.isdir(docs):
        shutil.copytree(docs, os.path.join(pkg, "docs"))
        print("  + docs/（README 配图）")

    _copy_tools(args.tools, os.path.join(pkg, "tools"))
    _copy_templates(args.templates, os.path.join(pkg, "nuclei-templates"))

    _write(os.path.join(pkg, "cybercensus"), WRAPPER, 0o755)
    _write(os.path.join(pkg, "install.sh"), INSTALL, 0o755)
    _write(os.path.join(pkg, "使用说明.txt"), README)

    tar_path = os.path.join(DIST, NAME + ".tar.gz")
    with tarfile.open(tar_path, "w:gz") as tar:
        tar.add(pkg, arcname=NAME)

    digest = _sha256(tar_path)
    with open(os.path.join(DIST, "SHA256SUMS-linux.txt"), "w",
              encoding="utf-8", newline="\n") as f:
        f.write("%s  %s\n" % (digest, os.path.basename(tar_path)))

    shutil.rmtree(stage, ignore_errors=True)
    print("完成：%s (%.1f MB)" % (tar_path, os.path.getsize(tar_path) / 1048576.0))


if __name__ == "__main__":
    main()
