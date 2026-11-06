#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool_index.py — Phase 0 工具索引（tool-index/1.0）

为什么需要它
------------
atomic-capabilities.md 列出了 54 项原子能力，但“能力”不等于“这台机器上
现在就能调用”。此前 Agent 往往在 Phase 1 解包或 Phase 4 仿真时才撞到
moria / ast-grep / Qiling 缺失，然后临时猜安装命令。这个脚本把“可用性”
提前到 Phase 0，并给出可复现的安装/降级路径。

设计边界
--------
* 只探测工具自身（--version / image inspect / 模块元数据），不读取固件，
  不执行固件，不把目标文件传给被测工具。
* 默认绝不安装。安装是显式动作：--install TOOL --yes；无 --yes 只打印计划。
* 安装配方固定在脚本内，不抓取网页后执行。网页只作为 docs 链接，避免把
  第三方页面内容当成命令。
* 探测失败不伪造版本：找不到就是 missing；找到但版本命令失败是 degraded，
  仍算 found，但 --strict 会拒绝把它当作“已验证版本”。

用法
----
    python scripts/tool_index.py --out fw-audit/<target>/00-tool-index.json
    python scripts/tool_index.py --only moria,ast-grep,qiling --json
    python scripts/tool_index.py --require moria --require ast-grep
    python scripts/tool_index.py --docs --only qiling
    python scripts/tool_index.py --install ast-grep --yes

退出码：0 索引生成/要求满足；1 安装失败；2 用法；3 必需工具缺失
（或 --strict 下版本未知）；4 安装被策略拒绝（没有自动配方）。纯标准库。
"""
from __future__ import annotations

import argparse
import glob
import importlib.metadata as md
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

VERSION = "1.0"
SCHEMA = "tool-index/1.0"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TIMEOUT = 5.0
EXTRA_BIN_DIRS = (
    "~/.local/bin", "~/bin", "~/.cargo/bin",
    "/usr/local/bin", "/opt/homebrew/bin", "/snap/bin",
)
VERSION_RE = re.compile(r"([0-9]+[.][0-9]+(?:[.][0-9]+)?(?:[-+~][0-9A-Za-z.+~-]+)?)")
PHASES = [
    ("P0", "度量与定界"),
    ("P1", "提取与侦察"),
    ("P2", "分层与分配"),
    ("P3", "三层审计"),
    ("P4", "动态验证"),
    ("P5", "门禁与报告"),
]
PHASE_NAMES = dict(PHASES)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _install(kind: str, auto: bool = False, argv: Optional[List[str]] = None,
             shell: str = "", docs: str = "", requires: Optional[List[str]] = None,
             notes: str = "") -> Dict[str, Any]:
    return {
        "kind": kind,
        "auto": bool(auto),
        "argv": list(argv or []),
        "shell": shell,
        "docs": docs,
        "requires": list(requires or []),
        "notes": notes,
    }


def _fallback(tools: List[str], impact: str) -> Dict[str, Any]:
    return {"tools": list(tools), "impact": impact}


def _tool(tool_id: str, kind: str, capabilities: List[str], *,
          argv: Optional[List[str]] = None, alternates: Optional[List[List[str]]] = None,
          module: str = "", images: Optional[List[str]] = None,
          prefix: str = "", prefixes: Optional[List[str]] = None,
          extra_paths: Optional[List[str]] = None,
          required: bool = False, recommended: bool = False,
          docs: str = "", install: Optional[Dict[str, Any]] = None,
          fallback: Optional[Dict[str, Any]] = None, notes: str = "",
          version_must_contain: str = "",
          ok_returncodes: Optional[List[int]] = None) -> Dict[str, Any]:
    return {
        "id": tool_id,
        "kind": kind,
        "capabilities": list(capabilities),
        "argv": list(argv or []),
        "alternates": [list(a) for a in (alternates or [])],
        "module": module,
        "images": list(images or []),
        "prefix": prefix,
        "prefixes": list(prefixes or []),
        "extra_paths": list(extra_paths or []),
        "required": bool(required),
        "recommended": bool(recommended),
        "docs": docs,
        "install": install or _install("manual", docs=docs,
                                       shell="按官方文档安装", notes="没有固定安装配方"),
        "fallback": fallback or _fallback([], "按 atomic-capabilities.md §11 选择替代路径"),
        "notes": notes,
        "version_must_contain": version_must_contain,
        "ok_returncodes": list(ok_returncodes or [0]),
    }


# ── 原子能力（与 references/atomic-capabilities.md §2 对齐）──────────────────
# tools 为空表示该能力没有单一默认工具，或需要物理接触/人工判断；manual 字段
# 写明替代路径，避免把“没有工具”误报成“能力缺失”。
CAPABILITIES: List[Dict[str, Any]] = [
    {"id": "R1", "name": "固件格式识别", "phases": ["P1"], "primary": "file",
     "tools": ["file", "binwalk", "moria"], "manual": "",
     "fallback": "magic bytes 手工核对"},
    {"id": "R2", "name": "熵分布扫描", "phases": ["P1"], "primary": "moria",
     "tools": ["moria", "binwalk"], "manual": "", "fallback": "binwalk -E"},
    {"id": "R3", "name": "头部与分区解析", "phases": ["P1"], "primary": "binwalk",
     "tools": ["binwalk", "moria"], "manual": "", "fallback": "按偏移 dd，手工解析"},
    {"id": "R4", "name": "版本与型号提取", "phases": ["P1"], "primary": "rg",
     "tools": ["rg", "strings"], "manual": "", "fallback": "grep -r / strings"},
    {"id": "E1", "name": "递归解包", "phases": ["P1"], "primary": "unblob",
     "tools": ["unblob", "binwalk", "moria"], "manual": "",
     "fallback": "binwalk v3 递归 / moria -e"},
    {"id": "E2", "name": "SquashFS 解包", "phases": ["P1"], "primary": "unsquashfs",
     "tools": ["unsquashfs", "moria"], "manual": "", "fallback": "moria -e"},
    {"id": "E3", "name": "UBI / UBIFS 解包", "phases": ["P1"],
     "primary": "ubireader_extract_images", "tools": ["ubireader_extract_images", "moria"],
     "manual": "", "fallback": "moria -e"},
    {"id": "E4", "name": "JFFS2 解包", "phases": ["P1"], "primary": "jefferson",
     "tools": ["jefferson", "moria"], "manual": "", "fallback": "moria -e"},
    {"id": "E5", "name": "ext / F2FS / EROFS / cramfs / romfs",
     "phases": ["P1"], "primary": "moria",
     "tools": ["moria", "debugfs", "dump.f2fs", "fsck.erofs", "cramfsck"],
     "manual": "", "fallback": "debugfs / dump.f2fs / fsck.erofs / cramfsck"},
    {"id": "E6", "name": "内核提取", "phases": ["P1"], "primary": "binwalk",
     "tools": ["binwalk", "moria"], "manual": "", "fallback": "按 R3 偏移 dd"},
    {"id": "E7", "name": "DTB / bootargs 提取", "phases": ["P1"], "primary": "dtc",
     "tools": ["dtc"], "manual": "", "fallback": "strings 找 bootargs / uImage 头解析"},
    {"id": "E8", "name": "内核符号恢复", "phases": ["P1"], "primary": "vmlinux-to-elf",
     "tools": ["vmlinux-to-elf"], "manual": "", "fallback": "手工符号恢复，成本高"},
    {"id": "E9", "name": "加密固件判定与解密", "phases": ["P1"], "primary": "",
     "tools": [], "manual": "熵 + 魔数 + 头部规律判据（atomic-capabilities.md §3.1 E 分支）",
     "fallback": "moria -E / binwalk -E 只圈边界，不负责解密"},
    {"id": "C1", "name": "凭据 / 密钥 / 哈希扫描", "phases": ["P3"], "primary": "mithril",
     "tools": ["mithril", "rg", "firmwalker"], "manual": "",
     "fallback": "firmwalker + 自写 rg 规则（可信度下降）"},
    {"id": "C2", "name": "SBOM 生成", "phases": ["P3"], "primary": "mithril",
     "tools": ["mithril"], "manual": "", "fallback": "无等价替代，需人工整理"},
    {"id": "C3", "name": "组件 CVE 比对", "phases": ["P3"], "primary": "mithril",
     "tools": ["mithril"], "manual": "", "fallback": "在线 CVE 查询（注意断网与可信度）"},
    {"id": "C4", "name": "启动与信任姿态", "phases": ["P3"], "primary": "mithril",
     "tools": ["mithril"], "manual": "", "fallback": "读 U-Boot env / 手工检查密钥"},
    {"id": "C5", "name": "许可证与文件来源", "phases": ["P3"], "primary": "mithril",
     "tools": ["mithril"], "manual": "", "fallback": "手工抽样，覆盖不完整"},
    {"id": "C6", "name": "源码 / 脚本结构级扫描", "phases": ["P3"], "primary": "ast-grep",
     "tools": ["ast-grep", "semgrep"], "manual": "",
     "fallback": "rg -U 多行正则（可能漏检/误报）"},
    {"id": "F1", "name": "文件类型清单", "phases": ["P1"], "primary": "fd",
     "tools": ["fd", "file"], "manual": "", "fallback": "find + file"},
    {"id": "F2", "name": "SUID / SGID 与权限异常", "phases": ["P1"], "primary": "fd",
     "tools": ["fd"], "manual": "Windows 上权限位不可靠时用 fw_triage.py",
     "fallback": "find -perm -4000"},
    {"id": "F3", "name": "启动链读取", "phases": ["P1"], "primary": "",
     "tools": [], "manual": "直接读 etc/init.d、rcS、inittab、rc.local",
     "fallback": "rg / less 人工读取"},
    {"id": "F4", "name": "动作关键字枚举", "phases": ["P3"], "primary": "rg",
     "tools": ["rg"], "manual": "", "fallback": "grep -r"},
    {"id": "F5", "name": "硬编码凭据与 URL 面", "phases": ["P3"], "primary": "mithril",
     "tools": ["mithril", "rg"], "manual": "", "fallback": "rg 规则集 + 人工复核"},
    {"id": "F6", "name": "NVRAM / 配置键面", "phases": ["P3"], "primary": "strings",
     "tools": ["strings"], "manual": "", "fallback": "rg -a"},
    {"id": "B1", "name": "架构与 ABI 识别", "phases": ["P3"], "primary": "readelf",
     "tools": ["readelf", "file"], "manual": "", "fallback": "file / Python ELF 解析"},
    {"id": "B2", "name": "符号与导入表", "phases": ["P3"], "primary": "readelf",
     "tools": ["readelf", "nm", "strings"], "manual": "", "fallback": "objdump -T"},
    {"id": "B3", "name": "危险符号与调用点定位", "phases": ["P3"], "primary": "radare2",
     "tools": ["radare2", "objdump"], "manual": "", "fallback": "objdump + nm + strings"},
    {"id": "B4", "name": "反编译与 xref 追链", "phases": ["P3"], "primary": "ida-mcp",
     "tools": ["ida-mcp", "pyghidra-mcp", "ghidra", "radare2", "objdump"],
     "manual": "", "fallback": "Ghidra 无头 → radare2 手工 → objdump + strings"},
    {"id": "B5", "name": "分发入口表枚举", "phases": ["P3"], "primary": "",
     "tools": [], "manual": "找 .cgi/.asp 名表与函数指针数组（fat handler-table / 自写脚本）",
     "fallback": "人工枚举，覆盖不完整"},
    {"id": "B6", "name": "数据流 / 污点追踪", "phases": ["P3"], "primary": "",
     "tools": [], "manual": "人工三跳追链 + IDA MCP / fat taint",
     "fallback": "人工追链，耗时但结论强度不变"},
    {"id": "B7", "name": "跨请求污点配对", "phases": ["P3"], "primary": "",
     "tools": [], "manual": "写面枚举 → 读端枚举 → 反向溯源（SKILL.md Track C）",
     "fallback": "人工，覆盖有限"},
    {"id": "B8", "name": "二进制比对定位补丁", "phases": ["P3"], "primary": "",
     "tools": [], "manual": "BinDiff / Diaphora / Ghidriff / fat inspect update",
     "fallback": "人工 diff / 函数哈希"},
    {"id": "B9", "name": "FLIRT / 库函数识别", "phases": ["P3"], "primary": "ghidra",
     "tools": ["ghidra", "ida-mcp"], "manual": "", "fallback": "手工识别库函数"},
    {"id": "D1", "name": "整机启动", "phases": ["P4"], "primary": "qemu-system",
     "tools": ["qemu-system"], "manual": "", "fallback": "QEMU user + chroot"},
    {"id": "D2", "name": "启动失败诊断", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "读串口输出 / dmesg，按 §3.2 分支定位",
     "fallback": "人工诊断"},
    {"id": "D3", "name": "rootfs 可挂载性修补", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "改 init、补 /dev、stub 硬件依赖、换 root=/mtdparts",
     "fallback": "人工修补"},
    {"id": "D4", "name": "服务可达性探测", "phases": ["P4"], "primary": "nmap",
     "tools": ["nmap", "nc"], "manual": "", "fallback": "curl / nc 手工探测"},
    {"id": "D5", "name": "单二进制运行", "phases": ["P4"], "primary": "qiling-image",
     "tools": ["qiling-image", "qiling", "qemu-user"], "manual": "",
     "fallback": "QEMU user + chroot / Unicorn 手写 harness"},
    {"id": "D6", "name": "依赖打桩", "phases": ["P4"], "primary": "qiling",
     "tools": ["qiling", "qiling-image"], "manual": "", "fallback": "Unicorn 手写 harness"},
    {"id": "D7", "name": "sink 参数真值观测", "phases": ["P4"], "primary": "qiling",
     "tools": ["qiling", "qiling-image"], "manual": "", "fallback": "gdb-multiarch 手工断点"},
    {"id": "D8", "name": "系统调用 / 文件访问追踪", "phases": ["P4"], "primary": "qemu-user",
     "tools": ["qemu-user", "gdb-multiarch"], "manual": "", "fallback": "strace / ltrace"},
    {"id": "D9", "name": "覆盖率采集", "phases": ["P4"], "primary": "qiling",
     "tools": ["qiling", "qiling-image"], "manual": "", "fallback": "AFL++ map"},
    {"id": "D10", "name": "模糊测试", "phases": ["P4"], "primary": "afl-fuzz",
     "tools": ["afl-fuzz", "honggfuzz"], "manual": "", "fallback": "libFuzzer（有源码时）"},
    {"id": "D11", "name": "崩溃 triage", "phases": ["P4"], "primary": "gdb-multiarch",
     "tools": ["gdb-multiarch", "qiling"], "manual": "", "fallback": "手工复现 / 判 PC"},
    {"id": "D12", "name": "插桩与动态调试", "phases": ["P4"], "primary": "gdb-multiarch",
     "tools": ["gdb-multiarch", "frida", "qiling"], "manual": "", "fallback": "Qiling --gdb"},
    {"id": "N1", "name": "端口与协议指纹", "phases": ["P4"], "primary": "nmap",
     "tools": ["nmap"], "manual": "", "fallback": "nc / 协议库手工探测"},
    {"id": "N2", "name": "协议客户端与重放", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "MQTT/CoAP/UPnP 客户端、Scapy、boofuzz 按需",
     "fallback": "手工构造请求"},
    {"id": "N3", "name": "流量拦截代理", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "mitmproxy / IoXY / Burp（需授权）",
     "fallback": "抓包 + 手工重放"},
    {"id": "N4", "name": "主动情报查询", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "Shodan / Censys / ZoomEye / FCC ID（需授权）",
     "fallback": "不做主动查询，仅用被动情报"},
    {"id": "H1", "name": "UART 控制台", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "物理接触：万用表 + screen /dev/ttyUSB0 115200",
     "fallback": "不适用（需硬件）"},
    {"id": "H2", "name": "SPI NOR 读取", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "物理接触：CH341A + flashrom",
     "fallback": "不适用（需硬件）"},
    {"id": "H3", "name": "eMMC / JTAG / SWD", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "物理接触：读卡器 / JTAGulator / OpenOCD / pyOCD",
     "fallback": "不适用（需硬件）"},
    {"id": "H4", "name": "故障注入", "phases": ["P4"], "primary": "",
     "tools": [], "manual": "物理接触：ChipWhisperer（电压/时钟毛刺）",
     "fallback": "不适用（需硬件）"},
]
CAP_BY_ID = {c["id"]: c for c in CAPABILITIES}

# ── 工具注册表 ───────────────────────────────────────────────────────────────
# 只登记能明确探测版本的实现；不确定的“可能有”不写进来，避免制造虚假安全感。
TOOLS: List[Dict[str, Any]] = [
    _tool("python", "python-runtime", ["R4", "B1", "B2"], required=True, recommended=True,
          docs="https://www.python.org/downloads/",
          install=_install("system", docs="https://www.python.org/downloads/",
                           shell="安装 Python 3.8+ 并确保 python 在 PATH",
                           notes="本 skill 的脚本都要求 Python"),
          fallback=_fallback([], "缺少 Python 时本 skill 无法运行"),
          notes="运行本脚本的解释器；版本取 sys.version"),
    _tool("file", "cli", ["R1", "B1"], argv=["file", "--version"], recommended=True,
          docs="https://www.darwinsys.com/file/",
          install=_install("apt", docs="https://www.darwinsys.com/file/",
                           shell="sudo apt install file  # Debian/Ubuntu；macOS 自带",
                           requires=["apt"], notes="Windows 可用 w64devkit / Git Bash"),
          fallback=_fallback(["moria", "binwalk"], "moria/binwalk 的识别结果可替代 file 的魔数判断"),
          notes="R1 首选；没有时仍可用 Python 魔数猜测"),
    _tool("moria", "cli", ["R1", "R2", "R3", "E1", "E2", "E3", "E4", "E5", "E6"],
          argv=["moria", "--version"], alternates=[["moria", "version"]], recommended=True,
          docs="https://github.com/nmatt0/moria",
          install=_install("build-from-source", auto=False, docs="https://github.com/nmatt0/moria",
                           shell="git clone https://github.com/nmatt0/moria.git && cmake -S moria -B moria/build -DCMAKE_BUILD_TYPE=Release && cmake --build moria/build -j && cmake --install moria/build --prefix ~/.local",
                           requires=["git", "cmake", "c++"],
                           notes="官方 release 也提供 .deb；先看 release assets 再决定"),
          fallback=_fallback(["binwalk", "unblob", "unsquashfs"],
                             "E1-E6 覆盖下降；未知块可能丢失，报告需注明降级"),
          notes="单 C++ 二进制，进程内覆盖最全；Phase 1 首选"),
    _tool("binwalk", "cli", ["R1", "R2", "R3", "E1", "E6"],
          argv=["binwalk", "--version"], recommended=True,
          docs="https://github.com/ReFirmLabs/binwalk",
          install=_install("cargo", auto=True, argv=["cargo", "install", "binwalk", "--locked"],
                           docs="https://github.com/ReFirmLabs/binwalk",
                           requires=["cargo"], notes="binwalk v3 是 Rust 实现；旧版 Python 包不要混用"),
          fallback=_fallback(["moria", "unblob"], "R2/E1 可替代，但递归覆盖较弱"),
          notes="R2 熵扫描和 R3 分区列表仍好用"),
    _tool("unblob", "cli", ["E1"], argv=["unblob", "--version"], recommended=True,
          docs="https://github.com/onekey-sec/unblob",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "unblob"],
                           docs="https://github.com/onekey-sec/unblob", requires=["uv"],
                           notes="官方镜像 ghcr.io/onekey-sec/unblob 也适合一次性使用"),
          fallback=_fallback(["binwalk", "moria"], "78+ 格式覆盖下降，未知块 carve 能力变弱"),
          notes="E1 首选；有官方 Docker 镜像"),
    _tool("unsquashfs", "cli", ["E2"], argv=["unsquashfs", "-version"], recommended=True,
          docs="https://github.com/plougher/squashfs-tools",
          install=_install("apt", docs="https://github.com/plougher/squashfs-tools",
                           shell="sudo apt install squashfs-tools  # 非标压缩需 sasquatch 版",
                           requires=["apt"], notes="厂商镜像常用非标压缩，必要时换 sasquatch"),
          fallback=_fallback(["moria"], "moria -e 支持多压缩后端"),
          notes="标准 SquashFS 首选；非标压缩看 sasquatch",
          ok_returncodes=[0, 1]),
    _tool("ubireader_extract_images", "cli", ["E3"],
          argv=["ubireader_extract_images", "--version"], recommended=True,
          docs="https://github.com/jrspruitt/ubi_reader",
          install=_install("pip", auto=False, docs="https://github.com/jrspruitt/ubi_reader",
                           shell="uv tool install ubi_reader  # 或 pip install ubi_reader",
                           requires=["uv"], notes="包名 ubi_reader，命令名带前缀"),
          fallback=_fallback(["moria"], "moria -e 可重建 UBI 卷"),
          notes="E3 首选"),
    _tool("jefferson", "cli", ["E4"], argv=["jefferson", "--version"], recommended=True,
          docs="https://github.com/onekey-sec/jefferson",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "jefferson"],
                           docs="https://github.com/onekey-sec/jefferson", requires=["uv"]),
          fallback=_fallback(["moria"], "moria -e 支持 JFFS2"),
          notes="E4 首选"),
    _tool("debugfs", "cli", ["E5"], argv=["debugfs", "-V"], recommended=False,
          docs="https://e2fsprogs.sourceforge.net/",
          install=_install("apt", docs="https://e2fsprogs.sourceforge.net/",
                           shell="sudo apt install e2fsprogs", requires=["apt"]),
          fallback=_fallback(["moria"], "moria -e 支持 ext2/3/4"),
          notes="ext2/3/4 单文件系统实现"),
    _tool("dump.f2fs", "cli", ["E5"], argv=["dump.f2fs", "-V"], recommended=False,
          docs="https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git",
          install=_install("apt", docs="https://git.kernel.org/pub/scm/linux/kernel/git/jaegeuk/f2fs-tools.git",
                           shell="sudo apt install f2fs-tools", requires=["apt"]),
          fallback=_fallback(["moria"], "moria -e 支持 F2FS"),
          notes="F2FS 单文件系统实现"),
    _tool("fsck.erofs", "cli", ["E5"], argv=["fsck.erofs", "-V"], recommended=False,
          docs="https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git",
          install=_install("apt", docs="https://git.kernel.org/pub/scm/linux/kernel/git/xiang/erofs-utils.git",
                           shell="sudo apt install erofs-utils", requires=["apt"]),
          fallback=_fallback(["moria"], "moria -e 支持 EROFS"),
          notes="EROFS 单文件系统实现"),
    _tool("cramfsck", "cli", ["E5"], argv=["cramfsck", "-V"], recommended=False,
          docs="https://github.com/npitre/cramfs-tools",
          install=_install("apt", docs="https://github.com/npitre/cramfs-tools",
                           shell="sudo apt install cramfsprogs", requires=["apt"]),
          fallback=_fallback(["moria"], "moria -e 支持 cramfs"),
          notes="cramfs 单文件系统实现"),
    _tool("dtc", "cli", ["E7"], argv=["dtc", "--version"], recommended=False,
          docs="https://git.kernel.org/pub/scm/utils/dtc/dtc.git",
          install=_install("apt", docs="https://git.kernel.org/pub/scm/utils/dtc/dtc.git",
                           shell="sudo apt install device-tree-compiler", requires=["apt"]),
          fallback=_fallback(["strings"], "只能找 bootargs，无法反编译 DTB"),
          notes="DTB -> DTS；决定 root= 与 mtdparts"),
    _tool("vmlinux-to-elf", "cli", ["E8"], argv=["vmlinux-to-elf", "--version"],
          recommended=False, docs="https://github.com/marin-m/vmlinux-to-elf",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "vmlinux-to-elf"],
                           docs="https://github.com/marin-m/vmlinux-to-elf", requires=["uv"]),
          fallback=_fallback([], "没有等价替代，手工恢复符号成本高"),
          notes="剥离符号内核的符号恢复"),
    _tool("mithril", "cli", ["C1", "C2", "C3", "C4", "C5", "F5"],
          argv=["mithril", "--version"], recommended=True,
          docs="https://github.com/nmatt0/mithril",
          install=_install("official-release", auto=False, docs="https://github.com/nmatt0/mithril",
                           shell="从 GitHub release 下载对应架构的 mithril 二进制并放到 ~/.local/bin",
                           notes="官方 release 提供 Linux amd64/arm64；不要在审计中在线拉 CVE 镜像"),
          fallback=_fallback(["rg", "firmwalker"],
                             "C1 可部分替代；C2-C5 的 SBOM/KEV/EPSS 关联丢失，可信度下降"),
          notes="C1-C5 首选；CVE 命中只是线索，不是漏洞"),
    _tool("ast-grep", "cli", ["C6"], argv=["ast-grep", "--version"],
          alternates=[["sg", "--version"]], recommended=True,
          docs="https://ast-grep.github.io/",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "ast-grep-cli"],
                           docs="https://ast-grep.github.io/guide/quick-start.html",
                           requires=["uv"], notes="也可 npm i -g @ast-grep/cli；Linux 上 sg 是 setgroups，优先 ast-grep"),
          fallback=_fallback(["semgrep", "rg"],
                             "结构级过滤失效 -> 注释/字符串误报回归；Cross-line 可能漏检"),
          notes="C6 首选；sink_scan.py 的 structural 规则会调用它",
          version_must_contain="ast-grep"),
    _tool("semgrep", "cli", ["C6"], argv=["semgrep", "--version"],
          alternates=[["semgrep", "--disable-version-check", "--version"]], recommended=False,
          docs="https://semgrep.dev/docs/",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "semgrep"],
                           docs="https://semgrep.dev/docs/getting-started/", requires=["uv"]),
          fallback=_fallback(["ast-grep", "rg"], "taint 模式不可用；人工三跳追链"),
          notes="源码类目标的跨函数污点；剥离 ELF 不适用"),
    _tool("rg", "cli", ["R4", "F4", "F5", "C1"], argv=["rg", "--version"],
          recommended=True, docs="https://github.com/BurntSushi/ripgrep",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "ripgrep"],
                           docs="https://github.com/BurntSushi/ripgrep", requires=["uv"],
                           notes="cargo install ripgrep / apt install ripgrep 也可以"),
          fallback=_fallback(["grep"], "grep -r -I；噪声变大、变慢，结论不变"),
          notes="R4/F4/F5 首选；-uu 关忽略、-t 限类型"),
    _tool("fd", "cli", ["F1", "F2"], argv=["fd", "--version"], recommended=False,
          docs="https://github.com/sharkdp/fd",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "fd-find"],
                           docs="https://github.com/sharkdp/fd", requires=["uv"],
                           notes="apt install fd-find；命令名可能是 fdfind"),
          fallback=_fallback(["find"], "find -perm / 语法更长，结论不变"),
          notes="F1/F2 首选"),
    _tool("strings", "cli", ["R4", "F6", "B2"], argv=["strings", "--version"],
          recommended=False, docs="https://sourceware.org/binutils/docs/binutils/strings.html",
          install=_install("apt", docs="https://sourceware.org/binutils/docs/binutils/strings.html",
                           shell="sudo apt install binutils", requires=["apt"]),
          fallback=_fallback(["rg"], "rg -a 可替代大部分字符串搜索"),
          notes="F6 / B2 的轻量入口"),
    _tool("readelf", "cli", ["B1", "B2"], argv=["readelf", "--version"],
          recommended=True, docs="https://sourceware.org/binutils/docs/binutils/readelf.html",
          install=_install("apt", docs="https://sourceware.org/binutils/docs/binutils/readelf.html",
                           shell="sudo apt install binutils", requires=["apt"]),
          fallback=_fallback(["objdump", "file"], "B1/B2 部分字段缺失；结论不变"),
          notes="B1/B2 首选；fw_triage.py 也内置 ELF 解析"),
    _tool("nm", "cli", ["B2"], argv=["nm", "--version"], recommended=False,
          docs="https://sourceware.org/binutils/docs/binutils/nm.html",
          install=_install("apt", docs="https://sourceware.org/binutils/docs/binutils/nm.html",
                           shell="sudo apt install binutils", requires=["apt"]),
          fallback=_fallback(["readelf"], "readelf -s 可替代"),
          notes="导入/导出符号"),
    _tool("objdump", "cli", ["B2", "B3", "B4"], argv=["objdump", "--version"],
          recommended=False, docs="https://sourceware.org/binutils/docs/binutils/objdump.html",
          install=_install("apt", docs="https://sourceware.org/binutils/docs/binutils/objdump.html",
                           shell="sudo apt install binutils", requires=["apt"]),
          fallback=_fallback(["readelf", "radare2"], "反汇编可读性下降，手工成本上升"),
          notes="B3/B4 的最后一道可用替代"),
    _tool("radare2", "cli", ["B3", "B4"], argv=["radare2", "-v"],
          alternates=[["r2", "-v"]], recommended=False,
          docs="https://github.com/radareorg/radare2",
          install=_install("official-release", auto=False, docs="https://github.com/radareorg/radare2",
                           shell="git clone https://github.com/radareorg/radare2 && radare2/sys/install.sh",
                           requires=["git"], notes="也可用发行版包；避免用 pip 的旧包装"),
          fallback=_fallback(["objdump"], "xref/反编译能力下降"),
          notes="B3 首选；可脚本化 axt"),
    _tool("ghidra", "cli", ["B4", "B9"], argv=["analyzeHeadless"],
          extra_paths=["$GHIDRA_HOME/support/analyzeHeadless",
                       "$GHIDRA_HOME/support/analyzeHeadless.bat"],
          recommended=False, docs="https://github.com/NationalSecurityAgency/ghidra",
          install=_install("official-release", auto=False, docs="https://github.com/NationalSecurityAgency/ghidra",
                           shell="从官方 release 解压 Ghidra，设置 GHIDRA_HOME，并安装匹配的 JDK",
                           notes="体积大、需要 JDK；本 skill 不会自动下载 Ghidra"),
          fallback=_fallback(["radare2", "objdump"], "反编译质量下降，xref 需手工"),
          notes="B4 的免费语义级路线；需 GHIDRA_HOME 或 PATH"),
    _tool("ida-mcp", "cli", ["B4", "B9"], argv=["ida-mcp", "--version"],
          recommended=False, docs="https://github.com/mrexodia/ida-pro-mcp",
          install=_install("manual", auto=False, docs="https://github.com/mrexodia/ida-pro-mcp",
                           shell="按官方文档安装 IDA 插件与 MCP server", notes="需要 IDA Pro 授权"),
          fallback=_fallback(["ghidra", "radare2"], "没有 IDA 时走 Ghidra/radare2 链"),
          notes="B4 的最省人力路线；需商业授权"),
    _tool("pyghidra-mcp", "cli", ["B4"], argv=["pyghidra-mcp", "--version"],
          recommended=False, docs="https://github.com/clearbluejar/pyghidra-mcp",
          install=_install("uv-tool", auto=False, argv=["uv", "tool", "install", "pyghidra-mcp"],
                           docs="https://github.com/clearbluejar/pyghidra-mcp", requires=["uv"],
                           notes="仍需本机 Ghidra/JDK；版本兼容性按官方 README"),
          fallback=_fallback(["ghidra"], "MCP 断链，回到 analyzeHeadless 脚本"),
          notes="Ghidra 的 MCP 封装；不是 Ghidra 本体"),
    _tool("qiling", "python-module", ["D5", "D6", "D7", "D9", "D11", "D12"],
          module="qiling", recommended=False, docs="https://docs.qiling.io/",
          install=_install("pip", auto=False,
                           argv=["uv", "pip", "install",
                                 "qiling @ git+https://github.com/qilingframework/qiling@86c927cb329993b14e2586e04d1dd7a90deee5fb"],
                           docs="https://docs.qiling.io/en/latest/install/", requires=["uv", "git"],
                           notes="宿主机安装不等于适配器可用；adapter_qiling.py 固定经 sandbox_run.py 使用镜像"),
          fallback=_fallback(["qiling-image", "qemu-user"], "单二进制 Hook 能力下降"),
          notes="检测的是 python -c import qiling；adapter 实际优先用容器镜像"),
    _tool("qiling-image", "container-image", ["D5", "D6", "D7", "D9", "D11", "D12"],
          images=["iot-fw/qiling:1.4.11", "iot-fw/qiling:latest"], recommended=False,
          docs="https://github.com/qilingframework/qiling",
          install=_install("container-build", auto=True,
                           argv=["{container}", "build", "-t", "iot-fw/qiling:1.4.11",
                                 "{root}/assets/qiling"],
                           docs="https://docs.qiling.io/en/latest/install/",
                           requires=["docker"], notes="推荐路线；构建含 Qiling 1.4.11 的固定镜像"),
          fallback=_fallback(["qiling", "qemu-user"], "无容器运行时则 D5-D7 降级"),
          notes="adapter_qiling.py 的真实执行环境；版本固定为 1.4.11"),
    _tool("qemu-system", "family", ["D1"], prefix="qemu-system-", recommended=False,
          docs="https://www.qemu.org/docs/master/system/",
          install=_install("apt", docs="https://www.qemu.org/download/",
                           shell="sudo apt install qemu-system-mips qemu-system-arm qemu-system-aarch64",
                           requires=["apt"], notes="按目标架构只装需要的包"),
          fallback=_fallback(["qemu-user"], "整机启动不可用，只能证单二进制"),
          notes="D1 整机启动；检测 PATH 中所有 qemu-system-*"),
    _tool("qemu-user", "family", ["D5", "D8"],
          prefixes=["qemu-mips", "qemu-mipsel", "qemu-arm", "qemu-aarch64", "qemu-x86_64"],
          recommended=False, docs="https://www.qemu.org/docs/master/user/",
          install=_install("apt", docs="https://www.qemu.org/download/",
                           shell="sudo apt install qemu-user-static binfmt-support",
                           requires=["apt"]),
          fallback=_fallback(["qiling"], "依赖/系统调用覆盖下降"),
          notes="D5/D8 的轻量替代；qemu-*-static 更适合 chroot"),
    _tool("afl-fuzz", "cli", ["D10"], argv=["afl-fuzz", "-V"], recommended=False,
          docs="https://github.com/AFLplusplus/AFLplusplus",
          install=_install("apt", docs="https://github.com/AFLplusplus/AFLplusplus",
                           shell="sudo apt install afl++  # 或从源码构建", requires=["apt"]),
          fallback=_fallback(["honggfuzz"], "二进制模式支持弱"),
          notes="D10 首选；-Q/-U/-O 模式按目标选",
          ok_returncodes=[0, 1]),
    _tool("honggfuzz", "cli", ["D10"], argv=["honggfuzz", "--version"], recommended=False,
          docs="https://github.com/google/honggfuzz",
          install=_install("apt", docs="https://github.com/google/honggfuzz",
                           shell="sudo apt install honggfuzz", requires=["apt"]),
          fallback=_fallback(["afl-fuzz"], "覆盖与生态较弱"),
          notes="D10 备选"),
    _tool("gdb-multiarch", "cli", ["D8", "D11", "D12"], argv=["gdb-multiarch", "--version"],
          recommended=False, docs="https://sourceware.org/gdb/",
          install=_install("apt", docs="https://sourceware.org/gdb/",
                           shell="sudo apt install gdb-multiarch", requires=["apt"]),
          fallback=_fallback(["qiling"], "断点/寄存器观测能力下降"),
          notes="跨架构崩溃 triage 与调试"),
    _tool("frida", "python-module", ["D12"], module="frida", recommended=False,
          docs="https://frida.re/docs/installation/",
          install=_install("uv-tool", auto=True, argv=["uv", "tool", "install", "frida-tools"],
                           docs="https://frida.re/docs/installation/", requires=["uv"]),
          fallback=_fallback(["gdb-multiarch"], "动态插桩能力下降"),
          notes="D12；需目标架构的 frida-server"),
    _tool("nmap", "cli", ["D4", "N1"], argv=["nmap", "--version"], recommended=False,
          docs="https://nmap.org/book/install.html",
          install=_install("apt", docs="https://nmap.org/book/install.html",
                           shell="sudo apt install nmap", requires=["apt"]),
          fallback=_fallback(["nc"], "服务指纹能力下降"),
          notes="D4/N1；只在授权范围内扫描"),
    _tool("nc", "cli", ["D4"], argv=["nc", "-h"], recommended=False,
          docs="https://nc110.sourceforge.net/",
          install=_install("apt", docs="https://nc110.sourceforge.net/",
                           shell="sudo apt install netcat-openbsd", requires=["apt"]),
          fallback=_fallback([], "用 curl / socat / Python socket 手工探测"),
          notes="D4 的轻量探测；版本命令因实现而异"),
    _tool("docker", "cli", ["D5", "D6", "D7", "D9", "D11", "D12"], argv=["docker", "--version"],
          recommended=True, docs="https://docs.docker.com/engine/install/",
          install=_install("official-release", auto=False, docs="https://docs.docker.com/engine/install/",
                           shell="按官方文档安装 Docker Engine；Windows 用 Docker Desktop/WSL2",
                           notes="本 skill 的沙箱与 Qiling 镜像依赖容器运行时"),
          fallback=_fallback(["podman"], "命令基本兼容；sandbox_run.py 会探测可用运行时"),
          notes="不可信固件执行的基础设施"),
    _tool("podman", "cli", ["D5", "D6", "D7", "D9", "D11", "D12"], argv=["podman", "--version"],
          recommended=False, docs="https://podman.io/docs/installation",
          install=_install("official-release", auto=False, docs="https://podman.io/docs/installation",
                           shell="按官方文档安装 podman", notes="无 root 容器运行时"),
          fallback=_fallback(["docker"], "镜像构建/运行命令可能略有差异"),
          notes="docker 的替代运行时"),
    _tool("uv", "cli", [], argv=["uv", "--version"], recommended=True,
          docs="https://docs.astral.sh/uv/",
          install=_install("official-release", auto=False, docs="https://docs.astral.sh/uv/getting-started/installation/",
                           shell="按官方安装脚本安装 uv；Windows 可用 winget install astral-sh.uv",
                           notes="本 skill 推荐的环境管理器；不是运行必需"),
          fallback=_fallback(["python"], "改用 venv + pip；不影响脚本逻辑"),
          notes="Python 环境与工具安装入口"),
    _tool("firmwalker", "cli", ["C1"], argv=["firmwalker", "--help"], recommended=False,
          docs="https://github.com/craigz28/firmwalker",
          install=_install("manual", auto=False, docs="https://github.com/craigz28/firmwalker",
                           shell="按官方 README 安装 Node 依赖", notes="C1 的降级实现"),
          fallback=_fallback(["rg", "mithril"], "规则覆盖有限，CVE/SBOM 关联缺失"),
          notes="mithril 缺席时的 C1 替代"),
]
TOOL_BY_ID = {t["id"]: t for t in TOOLS}
ALL_PHASES = [p for p, _ in PHASES]
P0_TOOLS = ("python", "file", "uv")


def _tool_phases(tool: Dict[str, Any]) -> List[str]:
    phases = set()
    if tool["id"] in P0_TOOLS:
        phases.add("P0")
    for cid in tool["capabilities"]:
        cap = CAP_BY_ID.get(cid)
        if cap:
            phases.update(cap["phases"])
    return [p for p in ALL_PHASES if p in phases]


def _first_line(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    return text.splitlines()[0].strip()


def _parse_version(text: str) -> Optional[str]:
    m = VERSION_RE.search(text or "")
    if not m:
        return None
    return m.group(1).strip(".,;:")


def _fmt_cmd(argv: List[str]) -> str:
    if not argv:
        return ""
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def _search_dirs() -> List[str]:
    dirs: List[str] = []
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if raw and raw not in dirs:
            dirs.append(raw)
    for raw in EXTRA_BIN_DIRS:
        path = os.path.expanduser(os.path.expandvars(raw))
        if path and path not in dirs:
            dirs.append(path)
    return dirs


def _is_executable(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    if os.name == "nt":
        return True
    return os.access(path, os.X_OK)


def _which(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    candidates = [name]
    if os.name == "nt" and not name.lower().endswith((".exe", ".cmd", ".bat")):
        candidates.extend([name + ".exe", name + ".cmd", name + ".bat"])
    for directory in _search_dirs():
        for candidate in candidates:
            path = os.path.join(directory, candidate)
            if _is_executable(path):
                return path
    return None


def _replace_placeholders(argv: List[str]) -> List[str]:
    container = ""
    for name in ("docker", "podman"):
        if _which(name):
            container = name
            break
    out = []
    for item in argv:
        item = item.replace("{root}", ROOT)
        item = item.replace("{container}", container or "docker")
        out.append(item)
    return out


def _spawn(path: str, args: List[str]) -> List[str]:
    if os.name == "nt" and path.lower().endswith((".cmd", ".bat")):
        comspec = os.environ.get("COMSPEC", "cmd.exe")
        return [comspec, "/d", "/s", "/c", subprocess.list2cmdline([path] + list(args))]
    return [path] + list(args)


def _exec(argv: List[str], timeout: float) -> Dict[str, Any]:
    started = time.monotonic()
    kwargs: Dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(argv, **kwargs)
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "error": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except FileNotFoundError:
        return {"returncode": None, "stdout": "", "stderr": "",
                "error": "not-found", "duration_ms": int((time.monotonic() - started) * 1000)}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "",
                "error": "timeout", "duration_ms": int((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": "",
                "error": "os-error: " + str(exc), "duration_ms": int((time.monotonic() - started) * 1000)}


def _probe_cli(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    candidates = []
    if tool.get("argv"):
        candidates.append(list(tool["argv"]))
    candidates.extend([list(a) for a in tool.get("alternates") or []])
    if not candidates:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [], "returncode": None, "ok": False,
                          "duration_ms": 0, "error": "no-candidate"}}
    checked = []
    for cand in candidates:
        path = _which(cand[0])
        if not path:
            for raw in tool.get("extra_paths") or []:
                expanded = os.path.expandvars(os.path.expanduser(raw))
                if os.path.basename(expanded) == os.path.basename(cand[0]) and os.path.isfile(expanded):
                    path = expanded
                    break
        if not path:
            checked.append(cand)
            continue
        result = _exec(_spawn(path, cand[1:]), timeout)
        text = (result.get("stdout") or "") + ((result.get("stderr") or ""))
        must = (tool.get("version_must_contain") or "").lower()
        if must and must not in text.lower():
            checked.append(cand)
            continue
        version = _parse_version(text)
        ok = result.get("returncode") in (tool.get("ok_returncodes") or [0])
        status = "available" if ok else "degraded"
        return {
            "found": True,
            "status": status,
            "version": version,
            "path": path,
            "probe": {"argv": cand, "returncode": result.get("returncode"), "ok": ok,
                      "duration_ms": result.get("duration_ms"), "error": result.get("error")},
        }
    return {"found": False, "status": "missing", "version": None, "path": None,
            "probe": {"argv": checked[0] if checked else candidates[0], "returncode": None,
                      "ok": False, "duration_ms": 0, "error": "not-found"}}


def _probe_family(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    prefixes = tool.get("prefixes") or ([tool["prefix"]] if tool.get("prefix") else [])
    names: List[str] = []
    for directory in _search_dirs():
        for prefix in prefixes:
            for path in glob.glob(os.path.join(directory, prefix + "*")):
                if _is_executable(path):
                    names.append(path)
    names = sorted(set(names), key=lambda p: os.path.basename(p).lower())
    if not names:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [], "returncode": None, "ok": False,
                          "duration_ms": 0, "error": "not-found"}}
    versions = []
    last = None
    for path in names:
        result = _exec(_spawn(path, ["--version"]), timeout)
        last = result
        text = (result.get("stdout") or "") + (result.get("stderr") or "")
        ver = _parse_version(text)
        if ver and ver not in versions:
            versions.append(ver)
    return {
        "found": True,
        "status": "available" if versions else "degraded",
        "version": ", ".join(versions) if versions else None,
        "path": names[0],
        "probe": {"argv": [names[0], "--version"],
                  "returncode": (last or {}).get("returncode"),
                  "ok": bool(versions),
                  "duration_ms": (last or {}).get("duration_ms"),
                  "error": (last or {}).get("error")},
    }


def _probe_python_module(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    module = tool.get("module") or tool["id"]
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError, ModuleNotFoundError):
        spec = None
    if spec is None:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [sys.executable, "-c", "import " + module],
                          "returncode": None, "ok": False, "duration_ms": 0,
                          "error": "module-not-found"}}
    version = None
    try:
        version = md.version(module)
    except (md.PackageNotFoundError, ValueError):
        version = None
    return {
        "found": True,
        "status": "available" if version else "degraded",
        "version": version,
        "path": getattr(spec, "origin", None),
        "probe": {"argv": [sys.executable, "-c", "import " + module],
                  "returncode": 0, "ok": bool(version), "duration_ms": 0, "error": None},
    }


def _probe_python_runtime(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    return {
        "found": True,
        "status": "available",
        "version": platform.python_version(),
        "path": sys.executable,
        "probe": {"argv": [sys.executable, "--version"], "returncode": 0, "ok": True,
                  "duration_ms": 0, "error": None},
    }


def _probe_container_image(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    runtime = None
    for name in ("docker", "podman"):
        if _which(name):
            runtime = name
            break
    if not runtime:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [tool.get("images", ["image"])[0], "image", "inspect"],
                          "returncode": None, "ok": False, "duration_ms": 0,
                          "error": "container-runtime-not-found"}}
    last = None
    for image in tool.get("images") or []:
        result = _exec([runtime, "image", "inspect", "--format", "{{.Id}}", image], timeout)
        last = result
        if result.get("returncode") == 0:
            return {
                "found": True,
                "status": "available",
                "version": image,
                "path": runtime + " image " + image,
                "probe": {"argv": [runtime, "image", "inspect", image],
                          "returncode": 0, "ok": True,
                          "duration_ms": result.get("duration_ms"), "error": None},
            }
    image = (tool.get("images") or [tool["id"]])[0]
    return {"found": False, "status": "missing", "version": None, "path": runtime,
            "probe": {"argv": [runtime, "image", "inspect", image],
                      "returncode": (last or {}).get("returncode"),
                      "ok": False, "duration_ms": (last or {}).get("duration_ms"),
                      "error": "image-not-found"}}


def probe_tool(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    kind = tool.get("kind")
    if kind == "python-runtime":
        return _probe_python_runtime(tool, timeout)
    if kind == "python-module":
        return _probe_python_module(tool, timeout)
    if kind == "container-image":
        return _probe_container_image(tool, timeout)
    if kind == "family":
        return _probe_family(tool, timeout)
    return _probe_cli(tool, timeout)


def _selected_tools(only: Optional[List[str]], profile: str) -> List[Dict[str, Any]]:
    wanted = set(only or [])
    phases = set(ALL_PHASES if profile == "all" else {
        "phase0": ["P0"], "extract": ["P1"], "static": ["P3"], "dynamic": ["P4"],
    }[profile])
    out = []
    for tool in TOOLS:
        if wanted and tool["id"] not in wanted:
            continue
        if profile != "all" and not (set(_tool_phases(tool)) & phases):
            continue
        out.append(tool)
    return out


def build_index(only: Optional[List[str]] = None, profile: str = "all",
                timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    selected = _selected_tools(only, profile)
    rows = []
    for tool in selected:
        row = dict(tool)
        row.update(probe_tool(tool, timeout))
        row["phases"] = _tool_phases(tool)
        rows.append(row)
    rows_by_id = {r["id"]: r for r in rows}
    selected_ids = set(rows_by_id)
    caps = []
    for cap in CAPABILITIES:
        if profile != "all":
            phase_set = {"phase0": ["P0"], "extract": ["P1"],
                         "static": ["P3"], "dynamic": ["P4"]}[profile]
            if not (set(cap["phases"]) & set(phase_set)):
                continue
        if only and cap["tools"] and not (set(cap["tools"]) & set(only)):
            continue
        if not cap["tools"] and not cap.get("manual"):
            continue
        available_tools = [t for t in cap["tools"]
                           if t in selected_ids and rows_by_id[t].get("found")]
        missing_tools = [t for t in cap["tools"]
                         if t in selected_ids and not rows_by_id[t].get("found")]
        if not cap["tools"]:
            status = "manual"
        elif cap.get("primary") and rows_by_id.get(cap["primary"], {}).get("found"):
            status = "available"
        elif available_tools:
            status = "degraded"
        else:
            status = "missing"
        caps.append({
            "id": cap["id"],
            "name": cap["name"],
            "phases": list(cap["phases"]),
            "status": status,
            "primary": cap.get("primary") or "",
            "available_tools": available_tools,
            "missing_tools": missing_tools,
            "manual": cap.get("manual", ""),
            "fallback": cap.get("fallback", ""),
        })
    phases_out = []
    if profile == "all":
        phase_ids = ["P0", "P1", "P3", "P4"]
    else:
        phase_ids = {"phase0": ["P0"], "extract": ["P1"],
                     "static": ["P3"], "dynamic": ["P4"]}[profile]
    for pid in phase_ids:
        if pid == "P0":
            base = [rows_by_id[t] for t in P0_TOOLS if t in rows_by_id]
            p0_found = [row["id"] for row in base if row.get("found")]
            p0_missing = [row["id"] for row in base if not row.get("found")]
            py = next((row for row in base if row["id"] == "python"), None)
            file_row = next((row for row in base if row["id"] == "file"), None)
            if py is not None and not py.get("found"):
                pstatus = "blocked"
            elif py is not None and file_row is not None and file_row.get("found"):
                pstatus = "ready"
            elif py is not None:
                pstatus = "partial"
            else:
                pstatus = "n/a"
            phases_out.append({
                "id": pid,
                "name": PHASE_NAMES[pid],
                "status": pstatus,
                "available_tools": sorted(p0_found),
                "missing_tools": sorted(p0_missing),
            })
            continue
        phase_caps = [c for c in caps if pid in c["phases"]
                      and c["status"] != "manual"
                      and (not only or ((set(c["available_tools"])
                                         | set(c["missing_tools"])) & set(only)))]
        if not phase_caps:
            pstatus = "n/a"
        elif all(c["status"] == "available" for c in phase_caps):
            pstatus = "ready"
        elif any(c["status"] in ("available", "degraded") for c in phase_caps):
            pstatus = "partial"
        else:
            pstatus = "blocked"
        phases_out.append({
            "id": pid,
            "name": PHASE_NAMES[pid],
            "status": pstatus,
            "available_tools": sorted({t for c in phase_caps for t in c["available_tools"]}),
            "missing_tools": sorted({t for c in phase_caps for t in c["missing_tools"]}),
        })
    summary = {
        "total": len(rows),
        "available": sum(1 for r in rows if r["status"] == "available"),
        "degraded": sum(1 for r in rows if r["status"] == "degraded"),
        "missing": sum(1 for r in rows if r["status"] == "missing"),
    }
    return {
        "schema": SCHEMA,
        "tool_version": VERSION,
        "generated_at": utc_now(),
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "is_windows": os.name == "nt",
        },
        "registry": {"version": "2026-11-06", "tools": len(TOOLS),
                     "source": "scripts/tool_index.py"},
        "profile": profile,
        "summary": summary,
        "tools": rows,
        "capabilities": caps,
        "phases": phases_out,
        "notes": "只做版本探测，不读取固件；安装必须显式 --install TOOL --yes。",
    }


def _install_hint(row: Dict[str, Any]) -> str:
    inst = row.get("install") or {}
    if inst.get("argv"):
        return _fmt_cmd(_replace_placeholders(inst["argv"]))
    if inst.get("shell"):
        return inst["shell"]
    return "见官方文档"


def render_text(index: Dict[str, Any]) -> str:
    s = index["summary"]
    lines = [
        "[工具索引] %d 项：可用 %d / 降级 %d / 缺失 %d" % (
            s["total"], s["available"], s["degraded"], s["missing"]),
        "主机：%s %s %s / Python %s" % (
            index["host"]["os"], index["host"]["release"],
            index["host"]["machine"], index["host"]["python"]),
        "生成：%s（profile=%s）" % (index["generated_at"], index["profile"]),
    ]
    if s["total"] < index["registry"]["tools"]:
        lines.append("注意：本次只探测 %d/%d 项；缺失与阶段结论只针对选中工具，全量请用 --profile all。" % (
            s["total"], index["registry"]["tools"]))
    lines.extend([
        "",
        "阶段就绪度：",
    ])
    for phase in index["phases"]:
        lines.append("  %s %-8s %-8s 缺：%s" % (
            phase["id"], phase["name"], phase["status"],
            ", ".join(phase["missing_tools"][:10]) or "无"))
    missing = [t for t in index["tools"] if not t.get("found")]
    if missing:
        lines.extend(["", "缺失工具（安装/降级）："])
        for row in missing:
            lines.append("  - %s：%s" % (row["id"], row.get("notes") or row["kind"]))
            lines.append("    安装：" + _install_hint(row))
            docs = (row.get("install") or {}).get("docs") or row.get("docs") or ""
            if docs:
                lines.append("    文档：" + docs)
            fb = row.get("fallback") or {}
            if fb.get("tools") or fb.get("impact"):
                lines.append("    降级：%s；%s" % (
                    ", ".join(fb.get("tools") or []) or "无等价工具",
                    fb.get("impact") or ""))
    weak = [c for c in index["capabilities"] if c["status"] in ("degraded", "missing")]
    if weak:
        lines.extend(["", "能力缺口："])
        for cap in weak:
            lines.append("  %s %-22s %-8s 缺：%s；替代：%s" % (
                cap["id"], cap["name"], cap["status"],
                ", ".join(cap["missing_tools"]) or "无",
                cap["fallback"] or cap["manual"] or "无"))
    lines.extend([
        "",
        "下一步：",
        "  python scripts/tool_index.py --out fw-audit/<target>/00-tool-index.json",
        "  python scripts/tool_index.py --require moria --require ast-grep（按目标选路后）",
        "  python scripts/tool_index.py --install <tool> --yes（显式安装；无 --yes 只打印计划）",
    ])
    return chr(10).join(lines)


def _parse_ids(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def _write_json(path: str, obj: Dict[str, Any]) -> int:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            print("[error] 无法创建输出目录：%s" % exc, file=sys.stderr)
            return 2
    try:
        with open(path, "w", encoding="utf-8", newline=chr(10)) as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
            fh.write(chr(10))
    except OSError as exc:
        print("[error] 无法写入 %s：%s" % (path, exc), file=sys.stderr)
        return 2
    return 0


def _require_tools(index: Dict[str, Any], ids: List[str], strict: bool) -> List[str]:
    by_id = {t["id"]: t for t in index["tools"]}
    problems = []
    for tid in ids:
        row = by_id.get(tid)
        if row is None:
            problems.append(tid + "（未包含在本次索引中）")
        elif not row.get("found"):
            problems.append(tid + "（缺失）")
        elif strict and row.get("status") != "available":
            problems.append(tid + "（版本未知/探测降级）")
    return problems


def _precheck_requires(install: Dict[str, Any]) -> List[str]:
    missing = []
    for req in install.get("requires") or []:
        if req == "c++":
            if not (_which("c++") or _which("g++")):
                missing.append("c++/g++")
        elif not _which(req):
            missing.append(req)
    return missing


def run_install(ids: List[str], assume_yes: bool) -> int:
    failures = []
    planned = False
    for tid in ids:
        tool = TOOL_BY_ID.get(tid)
        if tool is None:
            print("[error] 未知工具：%s" % tid, file=sys.stderr)
            return 2
        probe = probe_tool(tool, DEFAULT_TIMEOUT)
        if probe.get("found"):
            print("[skip] %s 已可用：%s" % (tid, probe.get("version") or "版本未知"))
            continue
        inst = tool.get("install") or {}
        argv = _replace_placeholders(inst.get("argv") or [])
        docs = inst.get("docs") or tool.get("docs") or ""
        if not argv:
            print("[manual] %s 没有可自动执行的固定配方，按官方文档安装：" % tid)
            if inst.get("shell"):
                print("  " + inst["shell"])
            if docs:
                print("  " + docs)
            failures.append(tid)
            continue
        if not inst.get("auto"):
            print("[manual] %s 的安装被标记为人工确认；不会自动执行：" % tid)
            print("  " + _fmt_cmd(argv))
            if docs:
                print("  " + docs)
            failures.append(tid)
            continue
        missing = _precheck_requires(inst)
        if missing:
            print("[miss] %s 需要先安装：%s" % (tid, ", ".join(missing)))
            failures.append(tid)
            continue
        print("[install] " + _fmt_cmd(argv))
        if not assume_yes:
            print("[plan] 未加 --yes，未执行。")
            planned = True
            continue
        result = _exec(argv, 600.0)
        out = ((result.get("stdout") or "") + (result.get("stderr") or "")).strip()
        if result.get("returncode") != 0:
            print("[fail] %s rc=%s %s" % (tid, result.get("returncode"), out[-1200:]))
            failures.append(tid)
        else:
            print("[ok] %s 安装命令返回 0" % tid)
    if planned:
        return 2
    return 0 if not failures else 1


def _force_utf8_io() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_io()
    ap = argparse.ArgumentParser(
        description="Phase 0 工具索引：探测 moria/ast-grep/qiling 等实现，给出安装/降级路径")
    ap.add_argument("--out", help="把 tool-index/1.0 写到这个 JSON 路径")
    ap.add_argument("--json", action="store_true", help="把索引 JSON 打到 stdout")
    ap.add_argument("--only", help="只探测这些工具（逗号分隔）")
    ap.add_argument("--require", action="append", default=[], help="必需工具；缺失退出 3（可重复）")
    ap.add_argument("--profile", default="all",
                    choices=["all", "phase0", "extract", "static", "dynamic"],
                    help="按阶段筛选：phase0/extract/static/dynamic/all")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="单次版本探测超时秒数（默认 3）")
    ap.add_argument("--strict", action="store_true", help="--require 的工具必须版本已知")
    ap.add_argument("--docs", action="store_true", help="只打印官方文档链接")
    ap.add_argument("--install", action="append", default=[], help="显式安装工具（可重复）")
    ap.add_argument("--yes", action="store_true", help="与 --install 连用，确认执行安装命令")
    ap.add_argument("--quiet", action="store_true", help="不打印文本摘要")
    args = ap.parse_args(argv)
    if args.timeout < 0.5:
        args.timeout = 0.5
    if args.timeout > 30:
        args.timeout = 30
    only = _parse_ids(args.only)
    unknown = [x for x in only if x not in TOOL_BY_ID]
    if unknown:
        print("[error] 未知工具：%s（可用：%s）" % (", ".join(unknown), ", ".join(TOOL_BY_ID)), file=sys.stderr)
        return 2
    require_ids = []
    for raw in args.require:
        require_ids.extend(_parse_ids(raw))
    unknown = [x for x in require_ids if x not in TOOL_BY_ID]
    if unknown:
        print("[error] 未知工具：%s" % ", ".join(unknown), file=sys.stderr)
        return 2
    install_ids = []
    for raw in args.install:
        install_ids.extend(_parse_ids(raw))
    unknown = [x for x in install_ids if x not in TOOL_BY_ID]
    if unknown:
        print("[error] 未知工具：%s" % ", ".join(unknown), file=sys.stderr)
        return 2
    if args.docs:
        for tid in only or list(TOOL_BY_ID):
            tool = TOOL_BY_ID[tid]
            print("%s	%s" % (tid, tool.get("docs") or (tool.get("install") or {}).get("docs") or ""))
        return 0
    if install_ids:
        return run_install(install_ids, args.yes)
    index = build_index(only or None, args.profile, args.timeout)
    if args.out:
        rc = _write_json(args.out, index)
        if rc:
            return rc
    if args.json:
        print(json.dumps(index, ensure_ascii=False, indent=2))
    elif not args.quiet:
        print(render_text(index))
    if require_ids:
        problems = _require_tools(index, require_ids, args.strict)
        if problems:
            print("[error] 必需工具不满足：%s" % "; ".join(problems), file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
