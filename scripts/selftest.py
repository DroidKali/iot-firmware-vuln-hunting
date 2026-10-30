#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
selftest.py — 自检：生成合成固件 + 合成 rootfs，端到端验证三个脚本

不依赖任何外部工具（不需要 binwalk/unblob/radare2），只用 Python 标准库。
适合在安装后确认「脚本能跑、判据正确」，也适合改动脚本后做回归。

用法：
  python selftest.py                 # 在临时目录里跑，跑完自动清理
  python selftest.py --workdir ./x   # 指定工作目录
  python selftest.py --keep          # 保留生成的样本，便于人工查看
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import json
import os
import random
import re
import shutil
import stat
import struct
import subprocess
import sys
import tempfile
import time

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
FAILS: list = []
TOTAL = 0          # 实际执行的断言数：由脚本自己报，避免文档里的数字靠数日志漂移
NGROUPS = 23       # 组数：与各处 [N/23] 表头一致，末尾会自校验，防止「13 组」再次漂移


def check(name: str, ok: bool, detail: str = "") -> None:
    global TOTAL
    TOTAL += 1
    print(("  PASS  " if ok else "  FAIL  ") + name + (f"  ({detail})" if detail else ""))
    if not ok:
        FAILS.append(name)


# ------------------------------------------------------------------ 样本构造

def build_elf(path: str, *, etype: int, nx: bool, relro: bool, canary: bool,
              machine: int = 62, text_size: int = 0x2000) -> None:
    SHT_NULL, SHT_PROGBITS, SHT_STRTAB, SHT_DYNSYM, SHT_DYNAMIC = 0, 1, 3, 11, 6
    PT_LOAD, PT_GNU_STACK, PT_GNU_RELRO, PT_DYNAMIC = 1, 0x6474E551, 0x6474E552, 2
    TEXT_OFF = 0x400
    names = [b"", b"strcpy", b"sprintf", b"system", b"libc.so.6"]
    if canary:
        names += [b"__stack_chk_fail", b"__sprintf_chk"]
    dynstr = b"\x00".join(names) + b"\x00"
    off_map, cur = {}, 0
    for n in names:
        off_map[n] = cur
        cur += len(n) + 1
    DYNSTR_OFF = TEXT_OFF + text_size
    syms = [(0, 0x12, 0)] + [(off_map[n], 0x12, 0) for n in names[1:]]
    dynsym = b"".join(struct.pack("<IBBHQQ", a, b, c, 0, 0, 0) for a, b, c in syms)
    DYNSYM_OFF = DYNSTR_OFF + len(dynstr)
    dyn = [(24, 0), (1, off_map[b"libc.so.6"]), (0, 0)] if relro else [(0, 0)]
    dynamic = b"".join(struct.pack("<QQ", t, v) for t, v in dyn)
    DYNAMIC_OFF = DYNSYM_OFF + len(dynsym)
    _sh = [b"", b".text", b".dynstr", b".dynsym", b".dynamic", b".shstrtab"]
    shstr = b"\x00".join(_sh) + b"\x00"
    SHSTR_OFF = DYNAMIC_OFF + len(dynamic)
    SOFF = {n.decode(): (shstr.find(n + b"\x00") if n else 0) for n in _sh}
    SHOFF = (SHSTR_OFF + len(shstr) + 7) & ~7
    SHNUM = 6
    buf = bytearray(b"\x00" * (SHOFF + SHNUM * 64))
    buf[0:16] = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    struct.pack_into("<HHIQQQIHHHHHH", buf, 16, etype, machine, 1, 0x1000,
                     64, SHOFF, 0, 64, 56, 3, 64, SHNUM, 5)
    struct.pack_into("<IIQQQQQQ", buf, 64, PT_LOAD, 5, 0, 0, 0,
                     TEXT_OFF + text_size, TEXT_OFF + text_size, 0x1000)
    struct.pack_into("<IIQQQQQQ", buf, 64 + 56, PT_GNU_STACK, 6 if nx else 7,
                     0, 0, 0, 0, 0, 0x10)
    struct.pack_into("<IIQQQQQQ", buf, 64 + 112,
                     PT_GNU_RELRO if relro else PT_DYNAMIC, 4,
                     DYNAMIC_OFF, 0, 0, len(dynamic), len(dynamic), 0x10)
    buf[TEXT_OFF:TEXT_OFF + text_size] = b"\x90" * text_size
    buf[DYNSTR_OFF:DYNSTR_OFF + len(dynstr)] = dynstr
    buf[DYNSYM_OFF:DYNSYM_OFF + len(dynsym)] = dynsym
    buf[DYNAMIC_OFF:DYNAMIC_OFF + len(dynamic)] = dynamic
    buf[SHSTR_OFF:SHSTR_OFF + len(shstr)] = shstr

    def sh(i, name, stype, off, sz, link=0, entsize=0):
        struct.pack_into("<IIQQQQIIQQ", buf, SHOFF + i * 64,
                         SOFF[name], stype, 0, 0, off, sz, link, 0, 1, entsize)
    sh(0, "", SHT_NULL, 0, 0)
    sh(1, ".text", SHT_PROGBITS, TEXT_OFF, text_size)
    sh(2, ".dynstr", SHT_STRTAB, DYNSTR_OFF, len(dynstr))
    sh(3, ".dynsym", SHT_DYNSYM, DYNSYM_OFF, len(dynsym), link=2, entsize=24)
    sh(4, ".dynamic", SHT_DYNAMIC, DYNAMIC_OFF, len(dynamic), entsize=16)
    sh(5, ".shstrtab", SHT_STRTAB, SHSTR_OFF, len(shstr))
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "wb") as f:
        f.write(bytes(buf))


def build_sample(base: str) -> tuple:
    root = os.path.join(base, "01-extract", "rootfs")

    def w(rel: str, data, mode: int = 0o644) -> None:
        p = os.path.join(root, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "wb") as f:
            f.write(data if isinstance(data, bytes) else data.encode())

    build_elf(os.path.join(root, "usr/sbin/httpd"), etype=3, nx=True, relro=True,
              canary=True, text_size=0x30000)
    build_elf(os.path.join(root, "usr/sbin/upnpd"), etype=3, nx=True, relro=True,
              canary=False, text_size=0x14000)
    build_elf(os.path.join(root, "usr/lib/libnvram.so"), etype=3, nx=False,
              relro=False, canary=False, text_size=0x9000)
    build_elf(os.path.join(root, "bin/busybox"), etype=2, nx=False, relro=False,
              canary=False, text_size=0x60000)

    w("etc/init.d/rcS", "#!/bin/sh\nnvram get lan_ipaddr > /tmp/ip\n"
                        "/usr/sbin/httpd -p 80 &\n/usr/sbin/upnpd &\ntelnetd -l /bin/sh &\n")
    w("etc/config/network.conf", "lan_ipaddr=192.168.1.1\ndebug=1\n")
    w("etc/passwd", "root:x:0:0:root:/:/bin/sh\n")
    w("etc/shadow", "root:$1$aaaa$bbbb:19000:0:99999:7:::\n")
    w("var/etc/nvram.default", "default_passwd=admin\nsw_version=1.0.2\n")
    w("www/cgi-bin/ping.cgi", '#!/bin/sh\nIP=`echo "$QUERY_STRING" | cut -d= -f2`\n'
                              'system_result=$(ping -c 1 $IP)\necho "$system_result"\n')
    w("www/index.html", "<html><script>document.write(location.hash)</script></html>")
    w("www/js/jquery.min.js", "/*! jQuery v3.6.0 */(function(a){})(window);")
    w("www/goform/setup.cgi", "SOAPAction: urn:schemas-upnp-org:service:WANIPConnection:1#AddMapping\n")
    w("usr/share/doc/manual.txt", "manual\n")
    w("usr/share/locale/zh_CN/LC_MESSAGES/app.mo", b"\xde\x12\x04\x95" + b"\x00" * 200)
    w("www/img/logo.png", b"\x89PNG\r\n\x1a\n" + bytes(random.getrandbits(8) for _ in range(2048)))

    rnd = random.Random(7)
    img = os.path.join(base, "firmware.bin")
    with open(img, "wb") as f:
        f.write(b"\x1f\x8b\x08\x00" + bytes(rnd.getrandbits(8) for _ in range(600000)))
        f.write(b"hsqs" + bytes(rnd.getrandbits(8) for _ in range(400000)))
        f.write(b"U-Boot 2018.09\nLinux version 4.4.60\n" + b"\x00" * 200000)
        f.write(b"\xff" * 100000)
    return img, root


VERIFIED_FULL = """# 审计结论
## F-001 · CGI 未认证命令注入
- 文件: www/cgi-bin/ping.cgi:3
- 置信度: confirmed
## NOT_FOUND · usr/sbin/httpd
## NOT_FOUND · usr/sbin/upnpd
## NOT_FOUND · bin/busybox
## NOT_FOUND · usr/lib/libnvram.so
## NOT_FOUND · etc/init.d/rcS
## NOT_FOUND · etc/passwd
## NOT_FOUND · etc/shadow
## NOT_FOUND · etc/config/network.conf
## NOT_FOUND · var/etc/nvram.default
## NOT_FOUND · www/goform/setup.cgi
## NOT_FOUND · www/index.html
## NOT_FOUND · www/js/jquery.min.js
"""

VERIFIED_PARTIAL = """# 审计结论
## F-001 · CGI 未认证命令注入
- 文件: www/cgi-bin/ping.cgi:3
"""


def run(args: list, env=None) -> subprocess.CompletedProcess:
    # 子进程一律按 UTF-8 解码：Windows 默认用 GBK，中文/箭头/省略号会把
    # _readerthread 打崩，stdout/stderr 变成 None，断言随后 AttributeError。
    return subprocess.run([PY] + args, capture_output=True, text=True,
                          encoding="utf-8", errors="replace", env=env)


# ------------------------------------------------- 文档 ↔ CLI 一致性（第 14 组）
# 动机：文档里的示例命令曾把布尔开关 `--tier` 当作路径参数传（`--tier <rootfs>`），
# 命令照抄就报错，而单元测试全绿——二进制判据测不出「文档写错了」。
# 这里把文档当被测对象：命令里出现的开关必须在脚本 CLI 里真实存在，
# 且布尔开关后面不得跟取值。

CLI_FLAG_RE = re.compile(r"(?<![\w-])(--[a-z0-9][a-z0-9-]*)")


def cli_flags(script: str) -> set:
    """从脚本的 --help 抽取它真正支持的 --flag 集合。

    有子命令的脚本（如 `taint_graph.py build|recover|stats`）顶层 --help 只列子命令名，
    子命令自己的开关要逐个进去问，否则会把合法用法误判成"文档写错"。"""
    head = run([script, "--help"]).stdout or ""
    out = set(CLI_FLAG_RE.findall(head))
    for group in re.findall(r"\{([a-z0-9_,\-]+)\}", head):
        for sub in group.split(","):
            sub = sub.strip()
            if not sub or sub in ("-h", "--help"):
                continue
            out |= set(CLI_FLAG_RE.findall(run([script, sub, "--help"]).stdout or ""))
    return out


def bool_flags(script: str) -> set:
    """静态抽取 action=store_true / store_false 的开关——这类开关不接取值。"""
    try:
        tree = ast.parse(open(script, encoding="utf-8").read())
    except (OSError, SyntaxError):
        return set()
    out = set()
    for node in ast.walk(tree):
        if not (isinstance(node, ast.Call)
                and isinstance(node.func, ast.Attribute)
                and node.func.attr == "add_argument"):
            continue
        if not node.args or not isinstance(node.args[0], ast.Constant):
            continue
        flag = node.args[0].value
        if not isinstance(flag, str) or not flag.startswith("--"):
            continue
        for kw in node.keywords:
            if (kw.arg == "action" and isinstance(kw.value, ast.Constant)
                    and kw.value.value in ("store_true", "store_false")):
                out.add(flag)
    return out


def doc_commands() -> list:
    """抽出所有文档里 invoke scripts/*.py 的行（续行符已拼接）。"""
    root = os.path.dirname(HERE)
    paths = [os.path.join(root, "README.md"), os.path.join(root, "SKILL.md")]
    for sub in ("references", "assets"):
        d = os.path.join(root, sub)
        if os.path.isdir(d):
            paths += [os.path.join(d, f) for f in sorted(os.listdir(d))
                      if f.endswith(".md")]
    out = []
    for p in paths:
        if not os.path.isfile(p):
            continue
        text = open(p, encoding="utf-8").read()
        for block in re.findall(r"```bash\n(.*?)```", text, re.S):
            for line in re.sub(r"\\\n\s*", " ", block).splitlines():
                m = re.search(r"scripts/([A-Za-z0-9_]+\.py)", line)
                if m:
                    out.append((os.path.basename(p), m.group(1), line))
    return out


def _template_clean() -> bool:
    """报告模板本身不应触发 CVE 纪律违规（防误报）。"""
    tpl = os.path.join(os.path.dirname(HERE), "assets", "report-template.md")
    if not os.path.isfile(tpl):
        return False
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import coverage_gate as cg  # noqa
    return not cg.check_cve_discipline(tpl)["violations"]


def _template_fields_clean() -> bool:
    """报告模板本身不应触发 9 字段违规（防误报）。"""
    tpl = os.path.join(os.path.dirname(HERE), "assets", "report-template.md")
    if not os.path.isfile(tpl):
        return False
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import coverage_gate as cg  # noqa
    r = cg.check_report_fields(tpl)
    return not (r["incomplete"] or r["hypothesis_no_gap"] or r["bad_title"])


# ------------------------------------------------------------------ 主流程

def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--workdir")
    ap.add_argument("--keep", action="store_true")
    args = ap.parse_args()

    # Windows 控制台默认 GBK：标题里的 ↔、→ 等字符会直接把自检打崩，
    # 而崩溃信息又掩盖了真正的断言失败。这里只放宽「不可编码字符」的替换。
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="replace")
        except Exception:
            pass

    base = args.workdir or tempfile.mkdtemp(prefix="fw_selftest_")
    os.makedirs(base, exist_ok=True)
    print(f"[selftest] 工作目录: {base}")

    img, root = build_sample(base)
    metrics = os.path.join(base, "00-metrics.json")
    tiering = os.path.join(base, "02-tiering.json")
    plan = os.path.join(base, "03-audit-plan.md")
    sinks = os.path.join(base, "10-layer1-sinks.json")
    vfull = os.path.join(base, "30-verified-full.md")
    vpart = os.path.join(base, "30-verified-partial.md")
    for p, txt in ((vfull, VERIFIED_FULL), (vpart, VERIFIED_PARTIAL)):
        with open(p, "w", encoding="utf-8", newline="\n") as f:
            f.write(txt)

    print("\n[1/23] fw_triage.py — 度量 / 加固画像 / 分层")
    r = run([os.path.join(HERE, "fw_triage.py"), img, "--rootfs", root, "--tier",
             "--budget", "800", "--out", metrics, "--plan", plan, "--pretty"])
    check("fw_triage 退出码 0", r.returncode == 0, r.stderr.strip()[:200])
    if r.returncode != 0:
        print(r.stdout, r.stderr)
        return 1
    d = json.load(open(metrics, encoding="utf-8"))
    elf = {e["file"]: e for e in d["rootfs_analysis"]["elf_detail"]}
    h = elf.get("usr/sbin/httpd", {})
    n = elf.get("usr/lib/libnvram.so", {})
    b = elf.get("bin/busybox", {})
    check("httpd: NX=True", h.get("nx") is True)
    check("httpd: PIE=True", h.get("pie") is True, h.get("etype", ""))
    check("httpd: Canary=True", h.get("canary") is True)
    check("httpd: RELRO=Full", h.get("relro") == "Full", h.get("relro", ""))
    check("httpd: FORTIFY=True", h.get("fortify") is True)
    check("libnvram.so: NX=False", n.get("nx") is False)
    check("libnvram.so: RELRO=None", n.get("relro") == "None", n.get("relro", ""))
    check("busybox: 非 PIE", b.get("pie") is False, b.get("etype", ""))
    t = d["rootfs_analysis"]["tiering"]
    t1 = set(t["t1_list"])
    check("T1 含 www/cgi-bin/ping.cgi", "www/cgi-bin/ping.cgi" in t1)
    check("T1 含 usr/sbin/httpd", "usr/sbin/httpd" in t1)
    check("SKIP 含 usr/share/doc/manual.txt", "usr/share/doc/manual.txt" in set(t["skip_list"]))
    check("T3 含 www/index.html", "www/index.html" in set(t["t3_list"]))
    check("EALB > 0", t["ealoc_total"] > 0, str(t["ealoc_total"]))

    print("\n[2/23] sink_scan.py — Layer 1 危险模式扫描")
    r = run([os.path.join(HERE, "sink_scan.py"), root, "--json", sinks])
    check("sink_scan 退出码 0", r.returncode == 0, r.stderr.strip()[:200])
    if r.returncode != 0:
        return 1
    sd = json.load(open(sinks, encoding="utf-8"))
    key = {(f["rule_id"], f["file"]) for f in sd["findings"]}
    check("命中 P0-B-001 @ usr/sbin/httpd", ("P0-B-001", "usr/sbin/httpd") in key)
    check("命中 P0-C-002 @ www/cgi-bin/ping.cgi", ("P0-C-002", "www/cgi-bin/ping.cgi") in key)
    check("命中 P1-S-020 @ etc/init.d/rcS", ("P1-S-020", "etc/init.d/rcS") in key)
    check("命中 P1-W-020 @ www/goform/setup.cgi", ("P1-W-020", "www/goform/setup.cgi") in key)
    check("etc/passwd 不再误报 P1-S-020", ("P1-S-020", "etc/passwd") not in key)
    check("文档目录被跳过", not any(f["file"].startswith("usr/share/doc") for f in sd["findings"]))

    print("\n[3/23] coverage_gate.py — 覆盖率门禁（不完整应拒绝）")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vpart, "--tiering", tiering])
    check("不完整输入 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")

    print("\n[4/23] coverage_gate.py — 覆盖率门禁（完整应通过）")
    out = os.path.join(base, "40-coverage.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering, "--out", out])
    check("完整输入 → 退出码 0", r.returncode == 0, r.stdout.strip()[-160:])
    check("门禁报告已生成", os.path.isfile(out))

    print("\n[5/23] coverage_gate.py — CVE 纪律检查（版本命中 ≠ 可利用漏洞）")
    bad_rep = os.path.join(base, "report-bad.md")
    with open(bad_rep, "w", encoding="utf-8") as fh:
        fh.write(
            "## 1. 执行摘要\n\n### 漏洞统计\n\n| 优先级 | confirmed |\n|---|---|\n"
            "| P0 | 2 |\n\n"
            "设备存在 CVE-2023-3028，可被远程攻击，CVSS 9.8，优先级 P0。\n\n"
            "busybox 1.31 存在漏洞 CVE-2021-28831，P1。\n\n## 6. 附录\n")
    out_bad = os.path.join(base, "40-coverage-bad.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", bad_rep, "--out", out_bad])
    check("把版本命中写成漏洞 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    bad_txt = open(out_bad, encoding="utf-8").read()
    check("检出 V1 断言违规", "V1" in bad_txt)
    check("检出 V2 误入漏洞统计", "V2" in bad_txt)
    check("检出 V3 假优先级", "V3" in bad_txt)
    check("检出 V0 缺组件风险区块", "V0" in bad_txt)

    good_rep = os.path.join(base, "report-good.md")
    with open(good_rep, "w", encoding="utf-8") as fh:
        fh.write(
            "## 1. 执行摘要\n\n### 漏洞统计\n\n| 优先级 | confirmed |\n|---|---|\n"
            "| P0 | 1 |\n\n- 组件风险（未验证，不计入合计）：cve-hit 1 条\n\n"
            "## 4. 漏洞详情\n\n"
            "### F-001 · CGI 未认证命令注入\n\n"
            "- 类型: 命令注入\n"
            "- 位置: usr/sbin/httpd @0x2a30\n"
            "- 优先级: P0\n"
            "- 置信度: CONFIRMED\n"
            "- CVSS 3.1: 9.8\n"
            "- Source: HTTP GET /cgi-bin/ping?ip=\n"
            "- Sink: system() @0x2a30\n"
            "- 完整调用链: do_ping -> sprintf -> system\n"
            "- 证据: 0x2a30 bl system\n\n"
            "## 6. 组件风险（未验证）\n\n"
            "> 本节不是漏洞清单，措辞统一为「疑似…尚未验证可达性」。\n\n"
            "| CVE | 组件@版本 | 待验证项 |\n|---|---|---|\n"
            "| CVE-2023-3028 | mqtt 1.0 | 代码是否存在 / 调用链是否存在 |\n\n"
            "疑似存在 CVE-2023-3028，尚未验证可达性。\n\n## 7. 附录\n")
    out_good = os.path.join(base, "40-coverage-good.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", good_rep, "--out", out_good])
    check("规范标注（已单列未验证区块）→ 退出码 0", r.returncode == 0,
          r.stdout.strip()[-160:])
    good_txt = open(out_good, encoding="utf-8").read()
    check("无违规", "V1" not in good_txt and "V0" not in good_txt)
    check("报告模板本身不误报", _template_clean())

    # V4：同一 CVE-ID 不得同时作为 ④ 条目与 ⑥ 未验证线索（应「移动」而非「复制」）
    _f001 = ("### F-001 · 组件漏洞\n\n"
             "- 类型: 命令注入\n"
             "- 位置: /usr/sbin/httpd @0xB8600\n"
             "- 优先级: P1\n"
             "- 置信度: CONFIRMED\n"
             "- CVSS 3.1: 7.3\n"
             "- Source: nvram wget_verchk_pid\n"
             "- Sink: system() @0x41E30\n"
             "- 完整调用链: upload → restore → sub_B8600 → system()\n"
             "- 证据: 命中 CVE-2021-28831，反编译见 30-findings-verified.md\n\n")
    dup_rep = os.path.join(base, "report-dup-cve.md")
    with open(dup_rep, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n" + _f001 +
                 "## 6. 组件风险（未验证）\n\n"
                 "- busybox 1.31：疑似存在 CVE-2021-28831，尚未验证可达性\n\n## 7. 附录\n")
    out_dup = os.path.join(base, "40-coverage-dup.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", dup_rep, "--out", out_dup])
    check("同 CVE-ID 双现（④+⑥）→ 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    check("检出 V4 复制而非移动", "V4" in open(out_dup, encoding="utf-8").read())

    mig_rep = os.path.join(base, "report-mig-cve.md")
    with open(mig_rep, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n" + _f001 +
                 "## 6. 组件风险（未验证）\n\n"
                 "**已验证并升入第 4 区块的条目**：\n\n"
                 "| CVE | 状态 | 依据 |\n|---|---|---|\n"
                 "| CVE-2021-28831 | `cve-reachable` | 函数 @0x1000 + F-001 |\n\n"
                 "## 7. 附录\n")
    out_mig = os.path.join(base, "40-coverage-mig.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", mig_rep, "--out", out_mig])
    check("⑥ 保留指针行（移动语义）→ 退出码 0", r.returncode == 0,
          r.stdout.strip()[-200:])

    print("\n[6/23] coverage_gate.py — 审阅清单三方对齐（计划 ↔ 声明 ↔ 结论）")
    review_bad = os.path.join(base, "25-review-list.md")
    with open(review_bad, "w", encoding="utf-8") as fh:
        fh.write("- [x] `www/cgi-bin/ping.cgi`\n"     # 有结论 → OK
                 "- [x] `usr/sbin/ghost`\n"            # 勾选但无结论 → G3
                 "- [ ] `usr/sbin/upnpd`\n")           # 声明未勾选 → G1
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vpart, "--tiering", tiering,
             "--review-list", review_bad, "--out",
             os.path.join(base, "40-coverage-rl.md")])
    rl_txt = open(os.path.join(base, "40-coverage-rl.md"), encoding="utf-8").read()
    check("审阅清单不一致 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    check("检出 G3（勾选无结论）", "G3" in rl_txt and "usr/sbin/ghost" in rl_txt)
    check("检出 G1（声明未勾选）", "G1" in rl_txt and "usr/sbin/upnpd" in rl_txt)

    # 声明集须覆盖计划内的全部 T1/T2 文件（否则 G2），且勾选者均有结论
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import coverage_gate as _cg  # noqa
    plan_files = sorted({r["file"] for r in _cg.parse_plan(plan)
                         if r["tier"] in ("T1", "T2")})
    review_good = os.path.join(base, "25-review-list-good.md")
    with open(review_good, "w", encoding="utf-8") as fh:
        for pf in plan_files:
            fh.write(f"- [x] `{pf}`\n")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--review-list", review_good, "--out",
             os.path.join(base, "40-coverage-rl2.md")])
    check("审阅清单一致 → 退出码 0", r.returncode == 0,
          r.stdout.strip()[-160:])

    print("\n[7/23] coverage_gate.py — 报告 9 必填字段校验")
    f_bad = os.path.join(base, "report-fields-bad.md")
    with open(f_bad, "w", encoding="utf-8") as fh:
        fh.write(
            "## 4. 漏洞详情\n\n### F-001 · 栈溢出 (Critical)\n\n"
            "- **类型**：stack-buffer-overflow\n"
            "- **位置**：`usr/sbin/httpd:0x2a30`\n"
            "- **优先级**：P0\n\n")   # 缺 6 字段 + 标题含评级
    out_fb = os.path.join(base, "40-coverage-fb.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", f_bad, "--out", out_fb])
    fb_txt = open(out_fb, encoding="utf-8").read()
    check("字段缺失 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    check("检出字段缺失", "缺失字段" in fb_txt and "CVSS 3.1" in fb_txt)
    check("检出标题含评级", "标题含评级括注" in fb_txt)

    f_good = os.path.join(base, "report-fields-good.md")
    with open(f_good, "w", encoding="utf-8") as fh:
        fh.write(
            "## 4. 漏洞详情\n\n### F-001 · 栈溢出\n\n"
            "- **类型**：stack-buffer-overflow\n"
            "- **位置**：`usr/sbin/httpd:0x2a30`\n"
            "- **优先级**：P0\n"
            "- **置信度**：CONFIRMED\n"
            "- **CVSS 3.1**：`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8\n"
            "- **Source**：HTTP Referer\n"
            "- **Sink**：strcpy @0x2a30\n"
            "- **完整调用链**：1. a @0x1\n"
            "- **证据**：`[E1]` disasm\n")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", f_good, "--out", os.path.join(base, "40-coverage-fg.md")])
    check("9 字段齐全 → 退出码 0", r.returncode == 0, r.stdout.strip()[-160:])
    check("报告模板字段不误报", _template_fields_clean())

    print("\n[8/23] coverage_gate.py — G4 入口级覆盖（文件级 100% ≠ 入口级 100%）")
    tj_g4 = os.path.join(base, "02-tiering-g4.json")
    with open(tj_g4, "w", encoding="utf-8") as fh:
        json.dump({"rootfs_analysis": {"tiering": {"shards": [{"items": [
            {"file": "usr/sbin/httpd", "tier": "T1", "text_kb": 888.24},
            {"file": "lib/libcrypto.so.1.1", "tier": "T1", "text_kb": 1159.65},
        ]}]}}}, fh, ensure_ascii=False)
    ep_missing = os.path.join(base, "entrypoints-missing.json")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tj_g4,
             "--entrypoints", ep_missing, "--out", os.path.join(base, "40-g4a.md")])
    check("缺 entrypoints.json → 退出码 1", r.returncode == 1, f"rc={r.returncode}")

    ep_todo = os.path.join(base, "entrypoints-todo.json")
    with open(ep_todo, "w", encoding="utf-8") as fh:
        json.dump({"schema": "entrypoints/v1", "files": [
            {"file": "usr/sbin/httpd", "handler_table_count": 3,
             "handlers": [{"name": "a.cgi", "conclusion": ""},
                          {"name": "b.cgi", "conclusion": ""},
                          {"name": "c.cgi", "conclusion": ""}]}]}, fh, ensure_ascii=False)
    out_g4b = os.path.join(base, "40-g4b.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tj_g4,
             "--entrypoints", ep_todo, "--out", out_g4b])
    g4b = open(out_g4b, encoding="utf-8").read()
    check("枚举齐但 0 处置 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    check("检出 G4 入口审计率不足", "入口级覆盖（G4）" in g4b and "0.0%" in g4b)

    ep_ok = os.path.join(base, "entrypoints-ok.json")
    with open(ep_ok, "w", encoding="utf-8") as fh:
        json.dump({"schema": "entrypoints/v1", "files": [
            {"file": "usr/sbin/httpd", "handler_table_count": 3,
             "handlers": [{"name": "a.cgi", "conclusion": "NOT_FOUND"},
                          {"name": "b.cgi", "conclusion": "F-001"},
                          {"name": "c.cgi", "conclusion": "F-002"}]},
            {"file": "lib/libcrypto.so.1.1", "waiver": {"reason": "库"}}]},
            fh, ensure_ascii=False)
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tj_g4,
             "--entrypoints", ep_ok, "--out", os.path.join(base, "40-g4c.md")])
    check("入口枚举 + 全部处置 → 退出码 0", r.returncode == 0, r.stdout.strip()[-160:])

    print("\n[9/23] coverage_gate.py — G5 绕过矩阵（「有防护」≠「防护有效」）")
    vp_bad = os.path.join(base, "30-claim-bad.md")
    with open(vp_bad, "w", encoding="utf-8") as fh:
        fh.write("# 结论\n\n## F-001 · x\n\n- 影响: 已鉴权，不可利用\n")
    vp_good = os.path.join(base, "30-claim-good.md")
    with open(vp_good, "w", encoding="utf-8") as fh:
        fh.write("# 结论\n\n## F-001 · x\n\n- 影响: 已鉴权\n\nbypass_matrix:\n"
                 + "".join(f"| B{i} | 已测·不可绕过 |\n" for i in range(1, 13)))
    vp_neutral = os.path.join(base, "30-claim-neutral.md")
    with open(vp_neutral, "w", encoding="utf-8") as fh:
        fh.write("# 结论\n\n## F-001 · x\n\n- 影响: 无鉴权，未过滤\n")
    check("防护断言缺矩阵 → 检出",
          len(_cg.check_bypass_matrix(vp_bad)["missing_matrix"]) == 1)
    check("完整 B1–B12 矩阵 → 不报",
          not _cg.check_bypass_matrix(vp_good)["missing_matrix"])
    check("「无鉴权 / 未过滤」不误报",
          not _cg.check_bypass_matrix(vp_neutral)["claims"])

    vcf = os.path.join(base, "30-claim-full.md")
    with open(vcf, "w", encoding="utf-8") as fh:
        fh.write(open(vfull, encoding="utf-8").read()
                 + "\n## F-099 · 测试防护断言\n\n- 文件: `www/cgi-bin/ping.cgi`\n"
                   "- 影响: 已有过滤，不可利用\n")
    out_g5 = os.path.join(base, "40-g5.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vcf, "--tiering", tiering, "--bypass-check",
             "--out", out_g5])
    check("G5 端到端接入 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    check("检出绕过矩阵缺失", "绕过矩阵完备（G5）" in open(out_g5, encoding="utf-8").read())

    print("\n[10/23] coverage_gate.py — G6 跨请求污点溯源（持久化来源须声明写入面）")
    _F = ("- **类型**：命令注入\n- **位置**：`usr/sbin/httpd:0x1`\n- **优先级**：P1\n"
          "- **置信度**：CONFIRMED\n- **CVSS 3.1**：`AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H` = 9.8\n"
          "{src}- **Sink**：system()\n- **完整调用链**：1. a @0x1\n- **证据**：`[E1]` disasm\n")
    xr_bad = os.path.join(base, "report-xreq-bad.md")
    with open(xr_bad, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n### F-001 · nvram 值拼入 shell\n\n"
                 + _F.format(src="- **Source**：nvram `wan_ifname`\n"))
    xr_good = os.path.join(base, "report-xreq-good.md")
    with open(xr_good, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n### F-001 · nvram 值拼入 shell\n\n"
                 + _F.format(src="- **Source**：nvram `wan_ifname`（唯一写入面为恢复配置导入）\n"))
    xr_static = os.path.join(base, "report-xreq-static.md")
    with open(xr_static, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n### F-002 · 静态配置 HTTP 源\n\n"
                 + _F.format(src="- **Source**：`updater.conf` 中的 update_server\n"))
    check("持久化来源缺写入面 → 检出",
          len(_cg.check_cross_request(xr_bad)["violations"]) == 1)
    check("声明写入面 → 不报",
          not _cg.check_cross_request(xr_good)["violations"])
    check("静态配置（.conf）不误报",
          _cg.check_cross_request(xr_static)["findings"] == 0)
    out_g6 = os.path.join(base, "40-g6.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", xr_bad, "--cross-request", "--out", out_g6])
    g6_txt = open(out_g6, encoding="utf-8").read()
    check("G6 端到端接入 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")
    check("检出跨请求污点溯源缺失", "跨请求污点溯源（G6）" in g6_txt)
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", xr_good, "--cross-request", "--out",
             os.path.join(base, "40-g6b.md")])
    check("声明写入面端到端 → 退出码 0", r.returncode == 0, r.stdout.strip()[-160:])

    print("\n[11/23] coverage_gate.py — G1/G2/G3 自动修复 + 类型→Base 命中")
    out_rec = os.path.join(base, "40-recover.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vpart, "--tiering", tiering,
             "--review-list", review_bad, "--auto-recover",
             "--recover-round", "1", "--max-rounds", "2", "--out", out_rec])
    rec_txt = open(out_rec, encoding="utf-8").read()
    check("G2 未声明 → 仍阻断（禁止自动）", r.returncode == 1, f"rc={r.returncode}")
    check("G1/G3 转自动修复计划", "自动修复第 1/2 轮" in rec_txt)
    check("生成 auto-recover.json",
          os.path.isfile(os.path.join(base, "40-recover.auto-recover.json")))
    out_rec3 = os.path.join(base, "40-recover3.md")
    run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
         "--verified", vpart, "--tiering", tiering,
         "--review-list", review_bad, "--auto-recover",
         "--recover-round", "3", "--max-rounds", "2", "--out", out_rec3])
    check("轮次超限 → 回硬门禁",
          "轮次超限" in open(out_rec3, encoding="utf-8").read())

    base_md = os.path.join(os.path.dirname(HERE), "references", "reporting.md")
    tb = _cg.parse_base_table(base_md)
    check("Base 表可解析且 ≥30 行", tb["ok"] and tb["rows"] >= 30, str(tb["rows"]))
    rep_unmapped = os.path.join(base, "report-type-unmapped.md")
    with open(rep_unmapped, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n### F-001 · x\n\n- **类型**：星际传送门滥用\n")
    check("未命中类型 → 报出",
          len(_cg.check_type_base(rep_unmapped, base_md)["unmapped"]) == 1)
    rep_mapped = os.path.join(base, "report-type-mapped.md")
    with open(rep_mapped, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n### F-001 · x\n\n"
                 "- **类型**：硬编码凭据 / 私钥泄露（CWE-798）\n")
    check("可映射类型 → 不报",
          not _cg.check_type_base(rep_mapped, base_md)["unmapped"])

    print("\n[12/23] sink_scan.py — 结构级二次过滤（正则初筛 → 结构确认 / 否定 / 回退）")
    if HERE not in sys.path:
        sys.path.insert(0, HERE)
    import sink_scan as _ss  # noqa
    sf = os.path.join(base, "struct")
    os.makedirs(sf, exist_ok=True)

    def _w(name: str, text: str) -> str:
        p = os.path.join(sf, name)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return p

    def _readtext(p: str) -> str:
        try:
            return open(p, encoding="utf-8", errors="replace").read()
        except OSError:
            return ""

    p_real = _w("real.sh", '#!/bin/sh\neval "$user"\n')                 # 真调用
    p_fake = _w("fake.sh", '#!/bin/sh\n# eval "$a"\necho "eval $a"\n')  # 仅注释 + 字符串
    p_unkn = _w("unknown_script", "import os\nos.system(cmd)\n")        # 无扩展名/无 shebang

    _all = [_ss.compile_rule(r) for r in _ss.load_rules(None)["rules"]]
    thr = _ss.load_rules(None)["thresholds"]
    rs = [r for r in _all if r["id"] == "P0-S-001"]
    rw = [r for r in _all if r["id"] == "P0-W-001"]
    no_eng = {"ast-grep": None, "semgrep": None}
    has_eng = {"ast-grep": os.path.join(sf, "fake-engine"), "semgrep": None}

    def sfile(path: str, rel: str, rules, engines, enabled, fb, st):
        res, _rec = _ss.scan_file(path, rel, rules, thr, [], [], 2, engines, fb, st,
                                  enabled, 5)
        return res

    a = sfile(p_real, "real.sh", rs, no_eng, False, [], {})
    b = sfile(p_fake, "fake.sh", rs, no_eng, False, [], {})
    check("关闭结构引擎 → 正则基线：两文件都命中", len(a) == 1 and len(b) == 1)

    fb, st = [], {}
    b2 = sfile(p_fake, "fake.sh", rs, no_eng, True, fb, st)
    check("引擎缺失 → 回退正则（结果不丢）", len(b2) == 1)
    check("引擎缺失 → 记录 engine-missing",
          any(x["reason"] == "engine-missing" for x in fb),
          json.dumps(fb[:1], ensure_ascii=False))

    fb, st = [], {}
    d = sfile(p_unkn, "unknown_script", rw, has_eng, True, fb, st)
    check("语言不可判 → 回退正则（结果不丢）", len(d) == 1)
    check("语言不可判 → 记录 lang-undetected",
          any(x["reason"] == "lang-undetected" for x in fb),
          json.dumps(fb[:1], ensure_ascii=False))

    _orig_sm = _ss.structural_match
    _ss.structural_match = (lambda eng, binp, lang, pat, path, to:
                            'eval "$user"' in _readtext(path))
    try:
        fb1, st1 = [], {}
        c1 = sfile(p_real, "real.sh", rs, has_eng, True, fb1, st1)
        fb2, st2 = [], {}
        c2 = sfile(p_fake, "fake.sh", rs, has_eng, True, fb2, st2)
        check("结构确认 → 保留命中且标 engine",
              len(c1) == 1 and c1[0]["engine"] == "ast-grep")
        check("结构否定 → 注释/字符串命中被过滤",
              len(c2) == 0 and st2.get("structural_filtered", 0) == 1,
              f"filtered={st2.get('structural_filtered')}")
    finally:
        _ss.structural_match = _orig_sm

    _ss.structural_match = lambda *a, **k: None
    try:
        fb3, st3 = [], {}
        e = sfile(p_real, "real.sh", rs, has_eng, True, fb3, st3)
        check("引擎报错 → 回退正则并记录 engine-error",
              len(e) == 1 and any(x["reason"] == "engine-error" for x in fb3))
    finally:
        _ss.structural_match = _orig_sm

    # ── 13. 扫描完整性 + 门禁严格性（改进计划 §3 / §4 / §6 的回归）──────────
    print("\n[13/23] 扫描完整性与门禁严格性")

    sz = os.path.join(base, "scanint")
    os.makedirs(sz, exist_ok=True)
    with open(os.path.join(sz, "big.bin"), "wb") as fh:
        fh.write(b"\x00" * (9 * 1024 * 1024 + 512 * 1024))   # 8 MiB 之后
        fh.write(b"\x00system\x00strcpy\x00")
        fh.write(b"\x00" * 1024)
    with open(os.path.join(sz, "cross.bin"), "wb") as fh:
        fh.write(b"\x00" * (4 * 1024 * 1024 - 3))            # 起点距 4 MiB 边界 3 字节
        fh.write(b"strcpy\x00")
        fh.write(b"\x00" * 4096)

    sj = os.path.join(sz, "out.json")
    run([os.path.join(HERE, "sink_scan.py"), sz, "--json", sj])
    sd = json.load(open(sj, encoding="utf-8"))
    files = {f["file"] for f in sd["findings"]}
    check("sink_scan：8 MiB 之后的危险串仍被扫到", "big.bin" in files, sorted(files))
    check("sink_scan：跨块边界的字符串不漏检", "cross.bin" in files)
    check("sink_scan：完整扫描时 complete=true",
          sd["scan_integrity"]["complete"] is True,
          json.dumps(sd["scan_integrity"]["skip_reason_counts"], ensure_ascii=False))

    sj2 = os.path.join(sz, "out2.json")
    run([os.path.join(HERE, "sink_scan.py"), sz, "--max-file-mb", "1",
         "--json", sj2])
    si = json.load(open(sj2, encoding="utf-8"))["scan_integrity"]
    check("sink_scan：超大文件跳过记入 too-large",
          si["skip_reason_counts"].get("too-large") == 2,
          json.dumps(si["skip_reason_counts"], ensure_ascii=False))
    check("sink_scan：不完整扫描不声称 complete", si["complete"] is False)

    # ── 13.2 候选处置：结构化 vs 文本 ────────────────────────────────────────
    gd = os.path.join(base, "gatev2")
    os.makedirs(gd, exist_ok=True)

    def _gw(name: str, text: str) -> str:
        p = os.path.join(gd, name)
        with open(p, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return p

    gplan = _gw("plan.md", "# 计划\n\n### A\n\n| 状态 | 文件 | Tier |\n|---|---|---|\n"
                           "| [ ] | `usr/sbin/httpd` | T1 |\n"
                           "| [ ] | `etc/init.d/rcS` | T1 |\n")
    gver = _gw("verified.md", "# 结论\n\n## F-001 · x\n\n- 文件: `usr/sbin/httpd`\n\n"
                             "## NOT_FOUND · y\n\n- 文件: `etc/init.d/rcS`\n")
    gbase = ["--plan", gplan, "--verified", gver]

    ok_cand = _gw("ok.jsonl", json.dumps(
        {"id": "C-001", "status": "confirmed", "evidence": ["0x2a30"]}) + "\n")
    dup_cand = _gw("dup.jsonl", json.dumps(
        {"id": "C-001", "status": "confirmed", "evidence": ["x"]}) + "\n"
        + json.dumps({"id": "C-001", "status": "not_applicable"}) + "\n")
    bad_cand = _gw("bad.jsonl", json.dumps(
        {"id": "C-009", "status": "looks-fine"}) + "\n")
    noev_cand = _gw("noev.jsonl", json.dumps(
        {"id": "C-010", "status": "confirmed"}) + "\n")
    empty_cand = _gw("empty.jsonl", "")

    check("候选：结构化合法 → 通过",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--candidates", ok_cand]).returncode == 0)
    check("候选：重复 ID → 拒绝",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--candidates", dup_cand]).returncode != 0)
    check("候选：未知状态 → 拒绝",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--candidates", bad_cand]).returncode != 0)
    check("候选：confirmed 无证据 → 拒绝",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--candidates", noev_cand]).returncode != 0)
    check("候选：空清单 → 拒绝",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--candidates", empty_cand]).returncode != 0)
    check("候选：空清单 + 显式 --allow-empty-candidates → 通过",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--candidates", empty_cand,
                 "--allow-empty-candidates"]).returncode == 0)
    check("候选：文件不存在 → 拒绝（不按零候选放过）",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--candidates", os.path.join(gd, "nope.jsonl")]).returncode != 0)

    # ── 13.3 profile：未执行的检查必须可见 ───────────────────────────────────
    gmd = os.path.join(gd, "40.md")
    r = run([os.path.join(HERE, "coverage_gate.py")] + gbase + ["--out", gmd])
    txt = open(gmd, encoding="utf-8").read()
    check("standard：未给 --candidates 时 exit 0 但标 SKIPPED",
          r.returncode == 0 and "SKIPPED" in txt)
    check("standard：结论明确提示仍有检查未执行",
          "未执行" in txt or "SKIPPED" in txt)
    check("strict：必需检查未执行 → 失败",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--profile", "strict"]).returncode != 0)

    # ── 13.4 报告缺「漏洞详情」区块不得空集通过 ──────────────────────────────
    nos = _gw("report-nosection.md", "# 报告\n\n## 1. 摘要\n\n无。\n")
    check("报告缺「漏洞详情」区块 → 拒绝",
          run([os.path.join(HERE, "coverage_gate.py")] + gbase
              + ["--report", nos]).returncode != 0)

    # ── 13.5 gate-config.json 记录执行清单 ──────────────────────────────────
    cfg = os.path.join(gd, "gate-config.json")
    run([os.path.join(HERE, "coverage_gate.py")] + gbase
        + ["--candidates", ok_cand, "--out", gmd, "--gate-config", cfg])
    gc = json.load(open(cfg, encoding="utf-8")) if os.path.isfile(cfg) else {}
    check("gate-config.json 生成并含档位与检查清单",
          gc.get("profile") == "standard" and len(gc.get("checks") or []) >= 10,
          f"{len(gc.get('checks') or [])} 项")
    check("gate-config.json 记录输入哈希",
          bool((gc.get("inputs") or {}).get("plan", {}).get("sha256")))
    check("gate-config.json 区分 executed 与 total",
          (gc.get("summary") or {}).get("executed", -1)
          < (gc.get("summary") or {}).get("total", -1))

    # ── 14. 文档 ↔ CLI 一致性：文档里的命令必须真能跑 ────────────────────────
    print(f"\n[14/{NGROUPS}] 文档 ↔ CLI 一致性（命令里出现的开关必须真实存在）")
    cmds = doc_commands()
    root = os.path.dirname(HERE)

    missing_script = sorted({s for _, s, _ in cmds
                             if not os.path.isfile(os.path.join(HERE, s))})
    check("文档引用的 scripts/*.py 全部存在", not missing_script,
          f"{len(cmds)} 条命令" if not missing_script else str(missing_script))

    flag_cache: dict = {}
    bad_flags = []
    for doc, script, line in cmds:
        if script not in flag_cache:
            flag_cache[script] = cli_flags(os.path.join(HERE, script))
        unknown = set(CLI_FLAG_RE.findall(line)) - flag_cache[script]
        if unknown:
            bad_flags.append(f"{doc}:{script} {sorted(unknown)}")
    check("文档里的 --flag 均存在于对应脚本 CLI", not bad_flags,
          "" if not bad_flags else "; ".join(bad_flags[:3]))

    SHELL_TOKENS = {"&&", "||", "|", ";", "\\", ">", "<", ">>"}
    misused = []
    for doc, script, line in cmds:
        script_path = os.path.join(HERE, script)
        bl = bool_flags(script_path)
        toks = line.split()
        for i, t in enumerate(toks):
            if t in bl and i + 1 < len(toks):
                nxt = toks[i + 1]
                if not nxt.startswith("-") and nxt not in SHELL_TOKENS:
                    misused.append(f"{doc}: {t} {nxt}")
    check("布尔开关未被当成带值参数（如 --tier <path>）", not misused,
          "" if not misused else "; ".join(misused[:3]))

    for name in ("README.md", "SKILL.md"):
        t = open(os.path.join(root, name), encoding="utf-8").read() \
            if os.path.isfile(os.path.join(root, name)) else ""
        check(f"{name}：Phase 5 门禁示例用 --profile strict",
              "--profile strict" in t)
        check(f"{name}：分层示例同时给出 --rootfs / --tier / --plan",
              all(k in t for k in ("--rootfs", "--tier", "--plan")))

    n_hdr = len(re.findall(r'print\(\s*f?"\\n\[', open(__file__, encoding="utf-8").read()))
    check("组数常量与表头数量一致", n_hdr == NGROUPS, f"表头 {n_hdr} / 常量 {NGROUPS}")

    # ── 15. 高阶污点图：写面/读面必须分属不同 action ──────────────────────────
    print("\n[15/23] taint_graph.py — 跨请求污点图（BDG/ADG）与 G7 门禁")
    tg = os.path.join(base, "tg")
    os.makedirs(tg, exist_ok=True)
    TG = os.path.join(HERE, "taint_graph.py")

    def _facts(name: str, actions: list, target: str = "demo") -> str:
        p = os.path.join(tg, name)
        with open(p, "w", encoding="utf-8") as fh:
            json.dump({"schema": "taint-facts/1.0", "target": target,
                       "store_type": "nvram_0", "actions": actions}, fh,
                      ensure_ascii=False)
        return p

    # 夹具取自 DIR878 实测（vuln_result.txt 原文），地址与 action 名均非编造：
    #   'lan0_management_link': other_get {prog.cgi: {SetRouterLanSettings: {restart_lan:
    #        {('rc','430d1c'): {command_exec: ['4312cc']}}}, ...}}  set {prog.cgi: {SetNetworkSettings: {'43b57c': None}}}
    W1 = {"key": "lan0_management_link", "func": "nvram_safe_set", "addr": "0x43b57c",
          "evidence": "prog.cgi:0x43b57c nvram_safe_set(\"lan0_management_link\", v)"}

    def _read(key: str, addr: str, sink_addr: str, via: str, sink: str = "system",
              binary: str = "rc", **extra) -> dict:
        d = {"key": key, "func": "nvram_safe_get", "addr": addr, "binary": binary,
             "evidence": f"{binary}:{addr} nvram_safe_get({key})",
             "via_control": {"func": "notify_rc", "value": via} if via else None,
             "sink": {"name": sink, "addr": sink_addr}}
        d.update(extra)
        return d

    hops = _facts("facts-ho.json", [
        {"id": "SetNetworkSettings", "binary": "prog.cgi", "writes": [dict(W1)],
         "ipc_control": [{"func": "notify_rc", "value": "start_vlanwanall",
                          "target_action": "SetVLANSettings", "target_binary": "prog.cgi",
                          "evidence": "prog.cgi:0x430f00 notify_rc(...)"}]},
        {"id": "SetRouterLanSettings", "binary": "prog.cgi",
         "reads": [_read("lan0_management_link", "0x430d1c", "0x4312cc", "restart_lan")]},
        {"id": "SetVLANSettings", "binary": "prog.cgi",
         "reads": [_read("lan0_management_link", "0x430d1c", "0x4312cc", "start_vlanwanall")]},
    ])
    g_ho = os.path.join(tg, "graph-ho.json")
    r = run([TG, "build", "--facts", hops, "--out", g_ho, "--strict"])
    g = json.load(open(g_ho, encoding="utf-8"))
    check("BDG 构图：写请求 ≠ 触发读的请求 → 2 条高阶链",
          r.returncode == 0 and g["summary"]["high_order_chains"] == 2
          and g["summary"]["first_order_chains"] == 0,
          f"rc={r.returncode} high={g['summary']['high_order_chains']}")
    check("读点落在别的进程（rc）且带 via_control → 链成立",
          all(c["read"]["binary"] == "rc" and c["read"]["via_control"]["value"]
              for c in g["chains"]))
    check("ADG 边（notify_rc → 目标 action）入图",
          len(g.get("adg") or []) == 1
          and g["adg"][0]["to"]["action"] == "SetVLANSettings")

    # 实测校正：SysLogRemote_IPAddress 是**一阶**——写与触发都是 SetSysLogSettings，
    # 读点却在 rc（other_get 只说「读在别的二进制」，不等于高阶）
    syslog = _facts("facts-syslog.json", [
        {"id": "SetSysLogSettings", "binary": "prog.cgi",
         "writes": [{"key": "SysLogRemote_IPAddress", "func": "nvram_safe_set",
                     "addr": "0x436450", "evidence": "prog.cgi:0x436450 nvram_safe_set(...)"}],
         "reads": [_read("SysLogRemote_IPAddress", "0x451f00", "0x451fc8",
                         "restart_SystemLog")]}])
    g_syslog = os.path.join(tg, "graph-syslog.json")
    r = run([TG, "build", "--facts", syslog, "--out", g_syslog])
    gs = json.load(open(g_syslog, encoding="utf-8"))
    check("写与触发同一请求（即使读点在 rc）→ 判一阶",
          r.returncode == 0 and gs["summary"]["high_order_chains"] == 0
          and gs["summary"]["first_order_chains"] == 1,
          f"high={gs['summary']['high_order_chains']} first={gs['summary']['first_order_chains']}")

    # C5：跨进程读必须给 via_control，否则「请求 2 能到达读点」只是假设
    novia = json.load(open(hops, encoding="utf-8"))
    novia["actions"][1]["reads"][0].pop("via_control")
    novia_p = os.path.join(tg, "facts-novia.json")
    json.dump(novia, open(novia_p, "w", encoding="utf-8"), ensure_ascii=False)
    g_novia = os.path.join(tg, "graph-novia.json")
    r = run([TG, "build", "--facts", novia_p, "--out", g_novia, "--strict"])
    check("跨进程读缺 via_control → 判失败（请求未证明能到达）",
          r.returncode == 1, f"rc={r.returncode}")

    same = _facts("facts-first.json", [
        {"id": "SetSame", "binary": "prog.cgi", "writes": [dict(W1)],
         "reads": [_read("lan0_management_link", "0x43c000", "0x43c100", "",
                         binary="prog.cgi")]}])
    g_first = os.path.join(tg, "graph-first.json")
    run([TG, "build", "--facts", same, "--out", g_first])
    gf = json.load(open(g_first, encoding="utf-8"))
    check("同一 action 内读写 → 判为一阶而非高阶",
          gf["summary"]["high_order_chains"] == 0
          and gf["summary"]["first_order_chains"] == 1)

    noev = json.load(open(hops, encoding="utf-8"))
    del noev["actions"][0]["writes"][0]["evidence"]
    noev_p = os.path.join(tg, "facts-noev.json")
    json.dump(noev, open(noev_p, "w", encoding="utf-8"), ensure_ascii=False)
    g_noev = os.path.join(tg, "graph-noev.json")
    r = run([TG, "build", "--facts", noev_p, "--out", g_noev, "--strict"])
    check("缺 evidence 的链 → 判失败", r.returncode == 1, f"rc={r.returncode}")

    unre = _facts("facts-unre.json", [
        {"id": "SetX", "binary": "prog.cgi",
         "writes": [{"func": "nvram_safe_set", "addr": "0x10", "evidence": "e"}]}])
    g_unre = os.path.join(tg, "graph-unre.json")
    r = run([TG, "build", "--facts", unre, "--out", g_unre, "--strict"])
    gu = json.load(open(g_unre, encoding="utf-8"))
    check("键未恢复 → defect 且判失败",
          r.returncode == 1
          and any(d["kind"] == "key-unrecovered" for d in gu["defects"]))

    # OD-ICP 轻量版：四条常量恢复规则
    dec = os.path.join(tg, "decomp")
    os.makedirs(dec, exist_ok=True)
    with open(os.path.join(dec, "prog_cgi.c"), "w", encoding="utf-8") as fh:
        fh.write(
            'int SetA(int a1, char *a2)\n{\n'
            '  nvram_safe_set("lit_key", a2);\n'
            '  return 0;\n}\n\n'
            'int SetB(int a1, char *a2)\n{\n'
            '  char *k = "local_key";\n'
            '  char buf[64];\n'
            '  char *v = nvram_safe_get(k);\n'
            '  system(v);\n'
            '  snprintf(buf, 64, "%s_%s", "lan0", "link");\n'
            '  nvram_safe_set(buf, a2);\n'
            '  nvram_safe_set(v9, a2);\n'
            '  return 0;\n}\n')
    f_rec = os.path.join(tg, "facts-rec.json")
    r = run([TG, "recover", "--src", dec, "--out", f_rec, "--target", "demo"])
    fr = json.load(open(f_rec, encoding="utf-8"))
    wl = [w.get("key") for a in fr["actions"] for w in a["writes"]]
    rl = [x.get("key") for a in fr["actions"] for x in a["reads"]]
    check("常量恢复：字面量 + 局部常量 + 缓冲区填充",
          r.returncode == 0 and "lit_key" in wl and "lan0_link" in wl
          and "local_key" in rl, f"W={wl} R={rl}")
    check("常量恢复：拼不出来的记为 unknown（不猜）",
          any(u["func"] == "nvram_safe_set" for u in fr["unrecovered"]))
    check("常量恢复：不再把 process_call 当存储键",
          all(w["func"] != "system" for a in fr["actions"] for w in a["writes"]))
    check("常量恢复：read 的候选 sink 只作提示不入链",
          any(x.get("sink_candidates") for a in fr["actions"] for x in a["reads"])
          and all("sink" not in x for a in fr["actions"] for x in a["reads"]))

    # G7 端到端：好图通过 / 声称高阶却只有一阶 → 失败 / strict 缺图 → 失败
    rep_ho = os.path.join(tg, "report-ho.md")
    with open(rep_ho, "w", encoding="utf-8") as fh:
        fh.write("## 4. 漏洞详情\n\n### F-001 · 高阶命令注入\n\n"
                 "- **类型**：命令注入\n- **位置**：`prog.cgi:0x4312cc`\n"
                 "- **优先级**：P1\n- **置信度**：CONFIRMED\n"
                 "- **CVSS 3.1**：9.8\n"
                 "- **Source**：nvram `lan0_management_link`（写入面 SetNetworkSettings）\n"
                 "- **Sink**：system() @0x4312cc\n- **完整调用链**：写 → 读 → sink\n"
                 "- **证据**：taint-graph H-001\n")
    out_g7 = os.path.join(tg, "40-g7.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--taint-graph", g_ho, "--report", rep_ho, "--out", out_g7])
    check("G7：跨 action 图 → 通过", r.returncode == 0, r.stdout.strip().splitlines()[-1] if r.stdout.strip() else "")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--taint-graph", g_first, "--report", rep_ho,
             "--out", os.path.join(tg, "40-g7b.md")])
    check("G7：报告声称高阶但只有一阶链 → 失败", r.returncode == 1,
          f"rc={r.returncode}")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--taint-graph", g_noev, "--report", rep_ho,
             "--out", os.path.join(tg, "40-g7c.md")])
    check("G7：缺 evidence → 失败", r.returncode == 1, f"rc={r.returncode}")

    cfg_g7 = os.path.join(tg, "gate-config.json")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering,
             "--report", rep_ho, "--profile", "strict",
             "--gate-config", cfg_g7,
             "--out", os.path.join(tg, "40-g7d.md")])
    rows = json.load(open(cfg_g7, encoding="utf-8"))["checks"] \
        if os.path.isfile(cfg_g7) else []
    row = next((x for x in rows if x["name"].startswith("跨请求污点图")), {})
    check("strict：声称高阶但未给图 → G7 记为必需且未执行",
          row.get("status") == "SKIPPED" and row.get("required") is True
          and r.returncode != 0, f"{row.get('status')}/{row.get('required')}")

    # ── 16. 候选输入契约：解析失败必须可见，strict 只吃版本化输入 ─────────────
    print("\n[16/23] 候选输入契约：解析失败可见 / strict 只接受版本化输入")
    cd16 = os.path.join(base, "cand")
    os.makedirs(cd16, exist_ok=True)

    def _cf(name: str, text: str) -> str:
        pth = os.path.join(cd16, name)
        with open(pth, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
        return pth

    def _cf_gate(name: str, extra: list) -> tuple:
        cfg = os.path.join(cd16, name)
        rr = run([os.path.join(HERE, "coverage_gate.py")] + extra
                 + ["--gate-config", cfg])
        doc = json.load(open(cfg, encoding="utf-8")) if os.path.isfile(cfg) else {}
        return rr, doc

    cver = _cf("verif.md", open(gver, encoding="utf-8").read() + "\n- C-999 已处置\n")
    env_ok = _cf("env.json", json.dumps({"schema": "candidates/1.0", "candidates": [
        {"id": "C-001", "status": "confirmed", "evidence": ["0x2a30"]}]}) + "\n")
    bad_line = _cf("badline.jsonl", json.dumps(
        {"id": "C-001", "status": "confirmed", "evidence": ["x"]}) + "\n{oops: 1}\n")
    plain = _cf("plain.txt", "C-999 已处置\n")
    empty_env = _cf("empty-env.json", json.dumps(
        {"schema": "candidates/1.0", "candidates": []}) + "\n")
    rep40 = os.path.join(cd16, "40.md")

    rr, g16 = _cf_gate("gc16.json", gbase + ["--candidates", bad_line, "--out", rep40])
    ci = (g16.get("candidate_input") or {})
    txt16 = open(rep40, encoding="utf-8").read() if os.path.isfile(rep40) else ""
    check("候选：非法 JSON 行 → 整体失败（不再静默跳过）",
          rr.returncode == 1, f"rc={rr.returncode}")
    check("候选：解析错误逐行记录（含行号）",
          ci.get("parse_complete") is False and ci.get("parse_errors") == 1,
          json.dumps(ci, ensure_ascii=False))
    check("候选：报告列出解析失败的行与原因",
          "候选文件解析失败" in txt16 and "| 2 |" in txt16
          and "Expecting" in txt16)
    check("候选：解析失败进入机器可读 blocked",
          any(b.get("code") == "CAND_PARSE_ERROR"
              for b in (g16.get("blocked") or [])))

    rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase
             + ["--candidates", env_ok, "--out", rep40])
    check("候选：envelope（candidates/1.0）→ standard 通过", rr.returncode == 0,
          f"rc={rr.returncode}")

    rr, g16b = _cf_gate("gc16b.json", gbase + [
        "--candidates", env_ok, "--profile", "strict", "--out", rep40])
    row = next((x for x in (g16b.get("checks") or [])
                if x["name"].startswith("候选处置率")), {})
    check("strict：envelope 候选记为 structured 且通过",
          row.get("status") == "PASS"
          and (g16b.get("candidate_input") or {}).get("mode") == "structured",
          json.dumps(row, ensure_ascii=False))

    rr, g16c = _cf_gate("gc16c.json", gbase + [
        "--candidates", ok_cand, "--profile", "strict", "--out", rep40])
    check("strict：未声明 schema 的 JSONL → 阻断为未版本化输入",
          rr.returncode != 0 and any(
              b.get("code") == "CAND_INPUT_INVALID"
              for b in (g16c.get("blocked") or [])),
          json.dumps((g16c.get("candidate_input") or {}), ensure_ascii=False))

    rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase
             + ["--candidates", plain, "--out", rep40])
    check("候选：纯文本未声明兼容模式 → 拒绝", rr.returncode == 1, f"rc={rr.returncode}")
    rr, g16d = _cf_gate("gc16d.json", ["--plan", gplan, "--verified", cver,
                                       "--candidates", plain,
                                       "--legacy-text-candidates", "--out", rep40])
    txt16d = open(rep40, encoding="utf-8").read() if os.path.isfile(rep40) else ""
    check("--legacy-text-candidates：兼容模式可用且在报告里披露",
          rr.returncode == 0
          and (g16d.get("candidate_input") or {}).get("mode") == "legacy-text"
          and "兼容模式" in txt16d,
          json.dumps((g16d.get("candidate_input") or {}), ensure_ascii=False))
    rr, g16e = _cf_gate("gc16e.json", gbase + [
        "--candidates", plain, "--legacy-text-candidates", "--profile", "strict",
        "--out", rep40])
    check("strict：即使显式开启兼容模式也不放行",
          rr.returncode != 0, f"rc={rr.returncode}")

    rr, g16f = _cf_gate("gc16f.json", gbase + [
        "--candidates", empty_env, "--allow-empty-candidates",
        "--profile", "strict", "--out", rep40])
    row = next((x for x in (g16f.get("checks") or [])
                if x["name"].startswith("候选处置率")), {})
    check("strict：合法空清单 + 显式 allow → 候选项通过（旧逻辑永远失败）",
          row.get("status") == "PASS", json.dumps(row, ensure_ascii=False))

    rr, g16g = _cf_gate("gc16g.json", gbase + [
        "--candidates", os.path.join(cd16, "gone.jsonl"),
        "--allow-empty-candidates", "--out", rep40])
    check("候选：文件缺失即使 allow-empty 也失败",
          rr.returncode == 1
          and any(b.get("code") == "CAND_INPUT_INVALID"
                  for b in (g16g.get("blocked") or [])),
          f"rc={rr.returncode}")

    # ── 17. 扫描完整性 / 阶段状态 / 结构引擎：降级可见，且 strict 能阻断 ─────
    print("\n[17/23] 扫描完整性与阶段状态：降级可见、可阻断")
    sd17 = os.path.join(base, "scangate")
    os.makedirs(sd17, exist_ok=True)
    layer1_partial = os.path.join(sz, "out2.json")
    rep17 = os.path.join(sd17, "40.md")

    def _g17(name: str, extra: list) -> tuple:
        cfg = os.path.join(sd17, name)
        rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase + extra
                 + ["--out", rep17, "--gate-config", cfg])
        doc = json.load(open(cfg, encoding="utf-8")) if os.path.isfile(cfg) else {}
        return rr, doc

    rr, g17 = _g17("gc17.json", ["--layer1", layer1_partial])
    sc = (g17.get("scan_integrity") or {})
    check("Layer 1 有截断/跳过 → 门禁失败（不当作没发现）",
          rr.returncode == 1 and sc.get("verdict") == "partial",
          json.dumps(sc, ensure_ascii=False))
    check("扫描缺口写入机器可读 blocked",
          any(b.get("code") == "LAYER1_SCAN_GAP"
              for b in (g17.get("blocked") or [])))
    check("报告披露扫描完整性缺口",
          os.path.isfile(rep17)
          and "扫描完整性与阶段状态" in open(rep17, encoding="utf-8").read())

    wv = os.path.join(sd17, "waiver.json")
    with open(wv, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "scan-waiver/1.0", "files": [
            {"path": "big.bin", "reason": "too-large", "approved_by": "selftest"},
            {"path": "cross.bin", "reason": "too-large",
             "approved_by": "selftest"}]}, fh, ensure_ascii=False, indent=2)
    rr, g17b = _g17("gc17b.json", ["--layer1", layer1_partial, "--scan-waiver", wv])
    check("显式豁免全部缺口 → 通过，但结论是 scoped 而非 complete",
          rr.returncode == 0
          and (g17b.get("scan_integrity") or {}).get("verdict") == "scoped"
          and (g17b.get("scan_integrity") or {}).get("waived", 0) >= 1,
          json.dumps((g17b.get("scan_integrity") or {}), ensure_ascii=False))

    st_bad = os.path.join(sd17, "stages-partial.json")
    with open(st_bad, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "audit-stages/1.0", "stages": [
            {"name": "layer2-auth", "status": "partial",
             "fallback_reason": "未完成认证矩阵"}]}, fh, ensure_ascii=False)
    rr, g17c = _g17("gc17c.json", ["--stages", st_bad])
    check("必需阶段 partial → 阻断（STAGE_NOT_SUCCESS）",
          rr.returncode == 1 and any(
              b.get("code") == "STAGE_NOT_SUCCESS"
              for b in (g17c.get("blocked") or [])),
          f"rc={rr.returncode}")

    st_ok = os.path.join(sd17, "stages-ok.json")
    with open(st_ok, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "audit-stages/1.0", "stages": [
            {"name": "layer2-auth", "status": "success"}]}, fh, ensure_ascii=False)
    rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase
             + ["--stages", st_ok, "--out", rep17])
    check("必需阶段全部 success → 通过", rr.returncode == 0, f"rc={rr.returncode}")

    l1_eng = os.path.join(sd17, "layer1-engine-failed.json")
    with open(layer1_partial, encoding="utf-8") as fh:
        l1d = json.load(fh)
    l1d["engine_status"] = {"structural_enabled": True, "verdict": "failed",
                            "engines": {"ast-grep": True}, "rules_with_structural": 3,
                            "structural_confirmed": 1, "regex_fallback": 2,
                            "fallbacks": [{"file": "usr/sbin/httpd",
                                           "reason": "engine-error"}]}
    with open(l1_eng, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(l1d, fh, ensure_ascii=False)
    rr, g17d = _g17("gc17d.json", ["--layer1", l1_eng])
    rows17 = {x["name"]: x for x in (g17d.get("checks") or [])}
    eng = rows17.get("结构引擎完整性") or {}
    check("结构引擎报错 → 即使未加参数也判失败（不当作成功确认）",
          eng.get("status") == "FAIL" and rr.returncode == 1,
          f"{eng.get('status')} rc={rr.returncode}")

    l1_pt = os.path.join(sd17, "layer1-engine-partial.json")
    l1d["engine_status"] = {"structural_enabled": True, "verdict": "partial",
                            "engines": {"semgrep": True}, "rules_with_structural": 3,
                            "structural_confirmed": 2, "regex_fallback": 1,
                            "fallbacks": []}
    with open(l1_pt, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(l1d, fh, ensure_ascii=False)
    rr, g17d2 = _g17("gc17d2.json", ["--layer1", l1_pt])
    eng2 = next((x for x in (g17d2.get("checks") or [])
                 if x["name"] == "结构引擎完整性"), {})
    check("结构引擎部分降级、未要求严格 → 记为 WARN（不升级为阻断）",
          eng2.get("status") == "WARN",
          f"{eng2.get('status')} rc={rr.returncode}")
    check("gate-config 记录 warn 计数",
          (g17d2.get("summary") or {}).get("warn", 0) >= 1,
          json.dumps((g17d2.get("summary") or {}), ensure_ascii=False))
    rr, g17e = _g17("gc17e.json", ["--layer1", l1_pt, "--require-structural"])
    eng = next((x for x in (g17e.get("checks") or [])
                if x["name"] == "结构引擎完整性"), {})
    check("--require-structural：引擎降级 → 失败",
          rr.returncode == 1 and eng.get("status") == "FAIL",
          f"{eng.get('status')} rc={rr.returncode}")

    cfg17f = os.path.join(sd17, "gc17f.json")
    rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase
             + ["--profile", "strict", "--gate-config", cfg17f,
                "--out", rep17])
    g17f = json.load(open(cfg17f, encoding="utf-8")) if os.path.isfile(cfg17f) else {}
    row = next((x for x in (g17f.get("checks") or [])
                if x["name"].startswith("扫描完整性")), {})
    check("strict：未给 --layer1 → 扫描完整性记为必需且未执行",
          rr.returncode != 0 and row.get("status") == "SKIPPED"
          and row.get("required") is True,
          f"{row.get('status')}/{row.get('required')} rc={rr.returncode}")

    # ── 18. 结构化契约 / 固件清单 / EALB 校准 ────────────────────────────────
    print("\n[18/23] 契约校验（contracts.py）、FirmwareManifest、EALB 校准")
    cd18 = os.path.join(base, "contracts")
    os.makedirs(cd18, exist_ok=True)
    CONTRACTS = os.path.join(HERE, "contracts.py")

    rr = run([CONTRACTS, "--list"])
    check("contracts.py --list 列出受支持的 schema",
          rr.returncode == 0 and "firmware-manifest/1.0" in (rr.stdout or "")
          and "candidates/1.0" in (rr.stdout or ""))

    sha_img = hashlib.sha256(open(img, "rb").read()).hexdigest()
    man_ok = os.path.join(cd18, "manifest.json")
    with open(man_ok, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "firmware-manifest/1.0", "id": "FW-SELFTEST",
                   "vendor": "Demo", "product": "Router", "version": "1.0.0",
                   "arch": "mips",
                   "image": {"path": os.path.relpath(img, cd18),
                             "sha256": sha_img,
                             "size": os.path.getsize(img)}},
                  fh, ensure_ascii=False, indent=2)
    check("contracts.py：合法 FirmwareManifest 通过",
          run([CONTRACTS, "--kind", "firmware-manifest",
               "--file", man_ok]).returncode == 0)

    man_bad = os.path.join(cd18, "manifest-bad-fields.json")
    with open(man_bad, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "firmware-manifest/1.0", "id": "FW-SELFTEST",
                   "image": {"path": "x", "sha256": sha_img}},
                  fh, ensure_ascii=False)
    check("contracts.py：缺 vendor/product/arch → 报错",
          run([CONTRACTS, "--kind", "firmware-manifest",
               "--file", man_bad]).returncode == 1)

    man_hash = os.path.join(cd18, "manifest-bad-hash.json")
    with open(man_hash, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "firmware-manifest/1.0", "id": "FW-SELFTEST",
                   "vendor": "Demo", "product": "Router", "version": "1.0.0",
                   "arch": "mips",
                   "image": {"path": os.path.relpath(img, cd18),
                             "sha256": "0" * 64,
                             "size": os.path.getsize(img)}},
                  fh, ensure_ascii=False)
    cfg18 = os.path.join(cd18, "gc18.json")
    rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase
             + ["--manifest", man_ok, "--out", os.path.join(cd18, "40.md"),
                "--gate-config", cfg18])
    g18 = json.load(open(cfg18, encoding="utf-8")) if os.path.isfile(cfg18) else {}
    mrow = next((x for x in (g18.get("checks") or [])
                 if x["name"].startswith("固件清单契约")), {})
    check("门禁：合法清单 → PASS 且核对镜像哈希",
          rr.returncode == 0 and mrow.get("status") == "PASS"
          and (g18.get("manifest") or {}).get("image_verified") is True,
          json.dumps(mrow, ensure_ascii=False))
    rr, g18b = _cf_gate("gc18b.json", gbase + ["--manifest", man_hash,
                                               "--out", os.path.join(cd18, "41.md")])
    check("门禁：镜像哈希不符 → 阻断（MANIFEST_HASH_MISMATCH）",
          rr.returncode == 1 and any(
              b.get("code") == "MANIFEST_HASH_MISMATCH"
              for b in (g18b.get("blocked") or [])),
          f"rc={rr.returncode}")

    task_ok = os.path.join(cd18, "audit-task.json")
    with open(task_ok, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "audit-task/1.0", "task_id": "AT-SELFTEST",
                   "manifest_id": "FW-SELFTEST", "profile": "strict",
                   "created_at": "2026-01-01T00:00:00Z",
                   "scope": {"t1_count": 3, "t2_count": 2, "skip_count": 0,
                             "ealb_total": 1200},
                   "agents": 2}, fh, ensure_ascii=False, indent=2)
    check("contracts.py：合法 AuditTask 通过",
          run([CONTRACTS, "--kind", "audit-task",
               "--file", task_ok]).returncode == 0)

    cfg18c = os.path.join(cd18, "gc18c.json")
    rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase
             + ["--manifest", man_ok, "--audit-task", task_ok,
                "--gate-config", cfg18c,
                "--out", os.path.join(cd18, "42.md")])
    g18c = json.load(open(cfg18c, encoding="utf-8")) if os.path.isfile(cfg18c) else {}
    arow = next((x for x in (g18c.get("checks") or [])
                 if x["name"].startswith("审计任务契约")), {})
    check("门禁：合法 AuditTask → PASS 且与清单一致",
          rr.returncode == 0 and arow.get("status") == "PASS"
          and (g18c.get("audit_task") or {}).get("task_id") == "AT-SELFTEST",
          json.dumps(arow, ensure_ascii=False))

    task_bad = os.path.join(cd18, "audit-task-mismatch.json")
    with open(task_bad, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "audit-task/1.0", "task_id": "AT-SELFTEST",
                   "manifest_id": "FW-OTHER", "profile": "standard",
                   "created_at": "2026-01-01T00:00:00Z",
                   "scope": {"t1_count": 0, "t2_count": 0, "skip_count": 0,
                             "ealb_total": 0},
                   "agents": 1}, fh, ensure_ascii=False, indent=2)
    cfg18d = os.path.join(cd18, "gc18d.json")
    rr = run([os.path.join(HERE, "coverage_gate.py")] + gbase
             + ["--manifest", man_ok, "--audit-task", task_bad,
                "--gate-config", cfg18d,
                "--out", os.path.join(cd18, "43.md")])
    g18d = json.load(open(cfg18d, encoding="utf-8")) if os.path.isfile(cfg18d) else {}
    check("门禁：AuditTask.manifest_id 与 --manifest 不一致 → 阻断",
          rr.returncode == 1 and any(
              b.get("code") == "AUDIT_TASK_MISMATCH"
              for b in (g18d.get("blocked") or [])),
          f"rc={rr.returncode}")

    EALBC = os.path.join(HERE, "ealb_calib.py")
    ej = os.path.join(cd18, "ealb.json")
    rr = run([EALBC, "predict", "--ealb", "1200", "--json", ej])
    ed = json.load(open(ej, encoding="utf-8")) if os.path.isfile(ej) else {}
    check("EALB：给单点预算与模型状态（heuristic 必须显式）",
          rr.returncode == 0 and ed.get("status") == "heuristic"
          and ed.get("minutes", 0) > 0, json.dumps(ed, ensure_ascii=False))

    meas = os.path.join(os.path.dirname(HERE), "assets",
                        "ealb-measures-sample.jsonl")
    ej2 = os.path.join(cd18, "ealb-eval.json")
    rr = run([EALBC, "evaluate", "--records", meas, "--json", ej2])
    ee = json.load(open(ej2, encoding="utf-8")) if os.path.isfile(ej2) else {}
    check("EALB：实测评估给出 MAE/MAPE 并在样本不足时拒绝称 calibrated",
          rr.returncode == 0 and ee.get("status") == "heuristic"
          and ((ee.get("targets") or {}).get("minutes") or {}).get("mape") is not None,
          json.dumps((ee.get("targets") or {}).get("minutes") or {},
                     ensure_ascii=False))

    print("\n[19/23] sandbox_run.py — 不可信固件的隔离边界（fail-closed）")
    SANDBOX = os.path.join(HERE, "sandbox_run.py")
    sb_dir = os.path.join(base, "sandbox")
    os.makedirs(sb_dir, exist_ok=True)

    rr = run([SANDBOX, "--check"])
    try:
        chk = json.loads(rr.stdout or "{}")
    except ValueError:
        chk = {}
    check("sandbox --check 输出可解析 JSON，且 host_fallback 恒为 false",
          bool(chk) and chk.get("host_fallback") is False
          and chk.get("mode") in ("check", "sandbox", "fail-closed", "host-opt-in"),
          (rr.stderr or "")[-200:])

    sb_auto = os.path.join(sb_dir, "auto.json")
    rr = run([SANDBOX, "--firmware", root, "--cmd", "echo ok",
              "--json", sb_auto, "--timeout", "30"])
    try:
        d_auto = json.load(open(sb_auto, encoding="utf-8"))
    except (OSError, ValueError):
        d_auto = {}
    if chk.get("mode") == "fail-closed":
        check("sandbox：运行时不可用 → 退出 3 且拒绝执行（不回落宿主机）",
              rr.returncode == 3 and d_auto.get("mode") == "fail-closed"
              and d_auto.get("host_fallback") is False
              and d_auto.get("ok") is False,
              f"rc={rr.returncode}")
    else:
        check("sandbox：运行时可用时走隔离链路（成功或命令失败都不是 host 回退）",
              rr.returncode in (0, 1, 124)
              and d_auto.get("host_fallback") is False,
              f"rc={rr.returncode}")

    rr = run([SANDBOX, "--firmware", root, "--mode", "host"])
    check("sandbox：--mode host 缺显式授权 → 拒绝（退出 4）",
          rr.returncode == 4, f"rc={rr.returncode}")

    sb_host = os.path.join(sb_dir, "host.json")
    rr = run([SANDBOX, "--firmware", root, "--mode", "host",
              "--i-understand-host-risk", "--cmd", "echo ok",
              "--json", sb_host, "--timeout", "30"])
    try:
        d_host = json.load(open(sb_host, encoding="utf-8"))
    except (OSError, ValueError):
        d_host = {}
    fw_hash = ((d_host.get("mounts") or {}).get("firmware") or {}).get("sha256") or ""
    check("sandbox：显式授权后执行，JSON 标注 host-opt-in 且 host_fallback=false",
          rr.returncode == 0 and d_host.get("mode") == "host-opt-in"
          and d_host.get("host_fallback") is False,
          f"rc={rr.returncode}")
    check("sandbox：宿主机执行也记录固件指纹（64 位 sha256）",
          bool(re.fullmatch(r"[0-9a-f]{64}", fw_hash)), fw_hash[:16])

    check("contracts.py：sandbox-run JSON 通过契约校验",
          os.path.isfile(sb_host)
          and run([CONTRACTS, "--kind", "sandbox-run",
                   "--file", sb_host]).returncode == 0)

    rr = run([SANDBOX, "--firmware", root, "--out",
              os.path.join(root, "out"), "--mode", "host",
              "--i-understand-host-risk", "--cmd", "echo ok"])
    check("sandbox：--out 落在固件目录内 → 拒绝（挂载重叠）",
          rr.returncode == 4, f"rc={rr.returncode}")

    # ── 20. 基准评估：指标可复算、严格模式不吞未复核标签、回归可阻断 ──────────
    print("\n[20/23] bench_eval.py — 基准评估（precision/recall/回归阻断）")
    BENCH = os.path.join(HERE, "bench_eval.py")
    bench_manifest = os.path.join(os.path.dirname(HERE), "assets", "bench", "manifest.json")
    bd = os.path.join(base, "bench")
    os.makedirs(bd, exist_ok=True)

    check("bench：合成基准集清单存在", os.path.isfile(bench_manifest), bench_manifest)
    if not os.path.isfile(bench_manifest):
        check("bench：基准集清单缺失，无法评估", False)
    else:
        bench_findings = os.path.join(bd, "findings.json")
        with open(bench_findings, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({
                "schema": "layer1-sinks/1.3",
                "tool": "sink_scan",
                "findings": [{
                    "rule_id": "P0-C-001",
                    "priority": "P0",
                    "category": "cmd-exec",
                    "file": "samples/B-001/usr/sbin/httpd",
                    "location": "16",
                    "symbol": "system",
                    "match": "system(cmd);",
                }],
            }, fh, ensure_ascii=False, indent=2)

        b1 = os.path.join(bd, "bench-result.json")
        rr = run([BENCH, "--manifest", bench_manifest, "--findings", bench_findings,
                  "--split", "all", "--json", b1, "--quiet"])
        try:
            d1 = json.load(open(b1, encoding="utf-8"))
        except (OSError, ValueError):
            d1 = {}
        cm = d1.get("confusion_matrix") or {}
        micro = (d1.get("metrics") or {}).get("micro") or {}
        check("bench：合成基准退出码 0", rr.returncode == 0, rr.stderr.strip()[:160])
        check("bench：混淆矩阵为 1 TP / 0 FP / 3 FN",
              cm.get("tp") == 1 and cm.get("fp") == 0 and cm.get("fn") == 3,
              json.dumps(cm, ensure_ascii=False))
        check("bench：precision/recall 可复算",
              micro.get("precision") == 1.0 and micro.get("recall") == 0.25,
              f"P={micro.get('precision')} R={micro.get('recall')}")
        prov = d1.get("provisional") or {}
        check("bench：未复核标签只进 provisional，不冒充权威结论",
              prov.get("authoritative") is False
              and (prov.get("labels_included") or 0) >= 1,
              f"labels_included={prov.get('labels_included')}")

        bs = os.path.join(bd, "bench-strict.json")
        rr = run([BENCH, "--manifest", bench_manifest, "--findings", bench_findings,
                  "--split", "all", "--strict", "--json", bs, "--quiet"])
        try:
            ds = json.load(open(bs, encoding="utf-8"))
        except (OSError, ValueError):
            ds = {}
        check("bench：--strict 不计算 provisional 指标",
              rr.returncode == 0 and ds.get("provisional") is None,
              f"rc={rr.returncode}")

        check("contracts.py：bench-manifest 通过契约校验",
              run([CONTRACTS, "--kind", "bench-manifest",
                   "--file", bench_manifest]).returncode == 0)

        base_out = os.path.join(bd, "bench-baseline.json")
        if d1:
            d1["metrics"]["micro"]["recall"] = 1.0
            d1["metrics"]["micro"]["f1"] = 1.0
            d1["baseline"] = None
            with open(base_out, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(d1, fh, ensure_ascii=False, indent=2)
        br = os.path.join(bd, "bench-regression.json")
        rr = run([BENCH, "--manifest", bench_manifest, "--findings", bench_findings,
                  "--split", "all", "--baseline", base_out, "--json", br, "--quiet"])
        try:
            db = json.load(open(br, encoding="utf-8"))
        except (OSError, ValueError):
            db = {}
        check("bench：相对基线召回暴跌 → 退出码 3 且标记 regression",
              rr.returncode == 3 and db.get("regression") is True,
              f"rc={rr.returncode} reasons={db.get('regression_reasons')}")

    # ── 21. 黑板：契约 / 事件日志 / 快照恢复 / 状态机 ────────────────────────
    print("\n[21/23] board_* — 黑板契约、事件日志、快照恢复与状态转换")
    BOARD = os.path.join(HERE, "board_store.py")
    BEV = os.path.join(HERE, "board_events.py")
    BTR = os.path.join(HERE, "board_transitions.py")
    b21 = os.path.join(base, "board21")
    os.makedirs(b21, exist_ok=True)
    FW21 = "a" * 64
    RUN21 = "RUN-SELFTEST"

    def _wj(name: str, obj) -> str:
        path = os.path.join(b21, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
        return path

    def _rj(path: str):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _pj(text: str):
        try:
            return json.loads(text)
        except (TypeError, ValueError):
            return {}

    fact_ok = _wj("fact.json", {
        "schema": "fact/1.0", "fact_id": "F-21", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "firmware",
        "value": {"id": "FW-21"}, "evidence_refs": ["E-21"],
        "source": {"type": "static", "tool": "selftest"},
        "observed_at": "2026-01-01T00:00:00Z"})
    check("contracts.py：Fact 合法样本通过",
          run([CONTRACTS, "--kind", "fact", "--file", fact_ok]).returncode == 0)
    fact_bad = _wj("fact-bad.json", {
        "schema": "fact/1.0", "fact_id": "F-21", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "firmware",
        "value": {"id": "FW-21"}, "source": {"type": "static"},
        "observed_at": "2026-01-01T00:00:00Z"})
    check("contracts.py：Fact 缺 evidence_refs → 拒绝",
          run([CONTRACTS, "--kind", "fact", "--file", fact_bad]).returncode == 1)

    intent_ok = _wj("intent.json", {
        "schema": "intent/1.0", "intent_id": "I-21", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "dynamic-validation", "status": "open",
        "from": ["F-21"], "description": "验证命令注入", "dedupe_key": "I-21-key",
        "creator": "selftest", "created_at": "2026-01-01T00:00:00Z",
        "target": "usr/sbin/httpd"})
    check("contracts.py：Intent 合法样本通过",
          run([CONTRACTS, "--kind", "intent", "--file", intent_ok]).returncode == 0)
    intent_bad = _wj("intent-bad.json", {
        "schema": "intent/1.0", "intent_id": "I-21", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "dynamic-validation", "status": "claimed",
        "from": ["F-21"], "description": "缺少 worker", "dedupe_key": "I-21-key",
        "creator": "selftest", "created_at": "2026-01-01T00:00:00Z",
        "target": "usr/sbin/httpd"})
    check("contracts.py：claimed Intent 缺 worker/claimed_at → 拒绝",
          run([CONTRACTS, "--kind", "intent", "--file", intent_bad]).returncode == 1)

    emu_ok = _wj("emu.json", {
        "schema": "emulation-result/1.0", "emulation_id": "EM-21",
        "run_id": RUN21, "intent_id": "I-21", "firmware_sha256": FW21,
        "backend": "qiling", "backend_version": "1.4", "status": "SUCCESS",
        "environment": {"arch": "mips"}, "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:01:00Z"})
    check("contracts.py：EmulationResult 合法样本通过",
          run([CONTRACTS, "--kind", "emulation-result", "--file", emu_ok]).returncode == 0)
    emu_bad = _wj("emu-bad.json", {
        "schema": "emulation-result/1.0", "emulation_id": "EM-21",
        "run_id": RUN21, "intent_id": "I-21", "firmware_sha256": FW21,
        "backend": "qiling", "backend_version": "1.4", "status": "TIMED_OUT",
        "environment": {"arch": "mips"}, "finished_at": "2026-01-01T00:01:00Z"})
    check("contracts.py：TIMED_OUT 缺 failure → 拒绝",
          run([CONTRACTS, "--kind", "emulation-result", "--file", emu_bad]).returncode == 1)

    ws21 = os.path.join(b21, "main")
    rr = run([BOARD, "init", "--workspace", ws21, "--run-id", RUN21,
              "--firmware-sha256", FW21, "--manifest-id", "FW-21"])
    check("board_store：init 生成事件日志与快照",
          rr.returncode == 0
          and os.path.isfile(os.path.join(ws21, "audit-events.jsonl"))
          and os.path.isfile(os.path.join(ws21, "audit-board.json")),
          f"rc={rr.returncode}")
    board_json = os.path.join(ws21, "audit-board.json")
    check("contracts.py：初始化后的 BoardState 通过契约",
          run([CONTRACTS, "--kind", "board-state", "--file", board_json]).returncode == 0)
    ev_path = os.path.join(ws21, "audit-events.jsonl")
    event_json = os.path.join(b21, "event.json")
    with open(ev_path, encoding="utf-8") as fh:
        first_event = fh.readline()
    with open(event_json, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(first_event)
    check("contracts.py：BoardEvent 通过契约",
          run([CONTRACTS, "--kind", "board-event", "--file", event_json]).returncode == 0)

    cand21 = _wj("candidate.json", {
        "id": "C-21", "status": "hypothesis", "type": "command-injection",
        "file": "usr/sbin/httpd"})
    run([BOARD, "add", "--workspace", ws21, "--kind", "candidate", "--file", cand21])
    rr = run([BOARD, "add", "--workspace", ws21, "--kind", "candidate",
              "--file", cand21])
    dup = _pj(rr.stdout)
    check("board_store：重复记录同一候选是幂等的（不重复落盘）",
          rr.returncode == 0 and dup.get("duplicate") is True,
          f"rc={rr.returncode}")

    rr = run([BOARD, "transition", "--workspace", ws21, "--candidate", "C-21",
              "--to", "validated", "--reason", "直接跳"])
    check("状态机：hypothesis → validated 被拒绝",
          rr.returncode == 1 and "ILLEGAL_TRANSITION" in rr.stderr,
          f"rc={rr.returncode}")
    check("状态机：hypothesis → pending_static_analysis 合法",
          run([BOARD, "transition", "--workspace", ws21, "--candidate", "C-21",
               "--to", "pending_static_analysis", "--reason", "静态分析"]).returncode == 0)
    check("状态机：pending_static_analysis → pending_dynamic_validation 合法",
          run([BOARD, "transition", "--workspace", ws21, "--candidate", "C-21",
               "--to", "pending_dynamic_validation", "--reason", "进入动态"]).returncode == 0)

    ev21 = _wj("evidence.json", {
        "schema": "evidence/1.1", "evidence_id": "E-21", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "emulation",
        "observed_at": "2026-01-01T00:00:00Z", "status": "parsed",
        "source": {"type": "emulation", "tool": "qiling"},
        "event": {"type": "execve", "trigger": True}})
    check("board_store：记录证据",
          run([BOARD, "add", "--workspace", ws21, "--kind", "evidence",
               "--file", ev21]).returncode == 0)
    policy21 = _wj("policy.json", {
        "vuln_type": "command-injection",
        "criteria": {"sink_reachable": True, "user_controlled_input": True,
                     "command_execution": True}})
    rr = run([BOARD, "transition", "--workspace", ws21, "--candidate", "C-21",
              "--to", "validated", "--reason", "复现成功",
              "--evidence", "E-21", "--policy", policy21])
    shown = _pj(run([BOARD, "show", "--workspace", ws21]).stdout)
    check("状态机：pending_dynamic_validation → validated（证据+类型化判据）",
          rr.returncode == 0, f"rc={rr.returncode}")
    state21 = _rj(board_json)
    check("board_store：validated 写入快照且带转换历史",
          any(c.get("id") == "C-21" and c.get("status") == "validated"
              and c.get("history") for c in state21.get("candidates") or []))
    rr = run([BOARD, "transition", "--workspace", ws21, "--candidate", "C-21",
              "--to", "confirmed", "--reason", "动态复现",
              "--evidence", "E-21", "--policy", policy21])
    state21c = _rj(board_json)
    check("状态机：validated → confirmed（动态复现后进入最终态）",
          rr.returncode == 0
          and any(c.get("id") == "C-21" and c.get("status") == "confirmed"
                  for c in state21c.get("candidates") or []),
          f"rc={rr.returncode}")
    rr = run([BOARD, "transition", "--workspace", ws21, "--candidate", "C-21",
              "--to", "validated", "--reason", "重开"])
    check("状态机：终态不可再转换（TERMINAL_STATE）",
          rr.returncode == 1 and "TERMINAL_STATE" in rr.stderr)
    check("board_store：verify 校验快照与事件链一致",
          run([BOARD, "verify", "--workspace", ws21]).returncode == 0)

    bad_ev = _wj("evidence-bad-run.json", {
        "schema": "evidence/1.1", "evidence_id": "E-BAD", "run_id": "RUN-OTHER",
        "firmware_sha256": FW21, "type": "emulation",
        "observed_at": "2026-01-01T00:00:00Z", "status": "parsed",
        "source": {"type": "emulation", "tool": "qiling"},
        "event": {"type": "execve", "trigger": True}})
    pending = _wj("pending.json", {
        "id": "C-X", "status": "pending_dynamic_validation",
        "type": "command-injection", "run_id": RUN21,
        "firmware_sha256": FW21})
    out21 = os.path.join(b21, "transition-bad.json")
    run([BTR, "check", "--candidate", pending, "--to", "validated",
         "--evidence", bad_ev, "--policy", policy21, "--run-id", RUN21,
         "--firmware-sha256", FW21, "--json", out21, "--quiet"])
    check("状态机：跨 run 证据不得用于 validated（EVIDENCE_NOT_BOUND_TO_RUN）",
          _rj(out21).get("code") == "EVIDENCE_NOT_BOUND_TO_RUN",
          json.dumps(_rj(out21), ensure_ascii=False)[:160])

    static_ev = _wj("evidence-static.json", {
        "schema": "evidence/1.1", "evidence_id": "E-STA", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "static",
        "observed_at": "2026-01-01T00:00:00Z", "status": "parsed",
        "source": {"type": "static", "tool": "sink_scan", "path": "usr/sbin/httpd"}})
    out21b = os.path.join(b21, "transition-static.json")
    run([BTR, "check", "--candidate", pending, "--to", "validated",
         "--evidence", static_ev, "--policy", policy21, "--run-id", RUN21,
         "--firmware-sha256", FW21, "--json", out21b, "--quiet"])
    check("状态机：静态证据不能证明命令执行（MISSING_TRIGGER_CONTEXT）",
          _rj(out21b).get("code") == "MISSING_TRIGGER_CONTEXT",
          _rj(out21b).get("code", ""))
    out21c = os.path.join(b21, "transition-ok.json")
    run([BTR, "check", "--candidate", pending, "--to", "validated",
         "--evidence", ev21, "--policy", policy21, "--run-id", RUN21,
         "--firmware-sha256", FW21, "--json", out21c, "--quiet"])
    check("状态机：同 run 动态证据 + 全判据 → validated",
          _rj(out21c).get("code") == "OK", _rj(out21c).get("code", ""))

    risk_bad = _wj("risk.json", {
        "candidate_id": "C-21", "status": "ACCEPTED_WITH_RISK",
        "reason": "暂缓修复", "approved_by": "owner",
        "evidence_refs": ["E-21"]})
    check("风险处置：ACCEPTED_WITH_RISK 不得写成候选状态",
          run([BTR, "risk", "--file", risk_bad]).returncode == 1)

    ws_bt = os.path.join(b21, "backtrack")
    run([BOARD, "init", "--workspace", ws_bt, "--run-id", RUN21,
         "--firmware-sha256", FW21, "--phase", "P4"])
    run([BOARD, "add", "--workspace", ws_bt, "--kind", "evidence", "--file", ev21])
    rr = run([BOARD, "backtrack", "--workspace", ws_bt, "--from-phase", "P4",
              "--to-phase", "P2", "--reason", "仿真不可用，回到静态复核",
              "--evidence", "E-21"])
    bt_state = _rj(os.path.join(ws_bt, "audit-board.json"))
    check("黑板：BACKTRACK 记录回退并把 phase 置回 P2",
          rr.returncode == 0 and bt_state.get("phase") == "P2"
          and len(bt_state.get("backtracks") or []) == 1,
          f"phase={bt_state.get('phase')} rc={rr.returncode}")
    rr = run([BOARD, "backtrack", "--workspace", ws_bt, "--from-phase", "P4",
              "--to-phase", "P1", "--reason", "阶段声明不符", "--evidence", "E-21"])
    check("黑板：from_phase 与当前阶段不一致 → PHASE_MISMATCH",
          rr.returncode == 1 and "PHASE_MISMATCH" in rr.stderr)

    ws_re = os.path.join(b21, "recover")
    run([BOARD, "init", "--workspace", ws_re, "--run-id", RUN21,
         "--firmware-sha256", FW21])
    run([BOARD, "add", "--workspace", ws_re, "--kind", "candidate", "--file", cand21])
    os.remove(os.path.join(ws_re, "audit-board.json"))
    shown = _pj(run([BOARD, "show", "--workspace", ws_re]).stdout)
    check("黑板：快照删除后从事件日志恢复，并标记 recovered",
          shown.get("recovered") is True and shown.get("revision", 0) >= 2,
          f"recovered={shown.get('recovered')} rev={shown.get('revision')}")
    check("黑板：恢复出的候选仍在",
          os.path.isfile(os.path.join(ws_re, "audit-board.json"))
          and any(c.get("id") == "C-21"
                  for c in _rj(os.path.join(ws_re, "audit-board.json")).get("candidates") or []))

    corrupt = os.path.join(b21, "corrupt.jsonl")
    shutil.copyfile(os.path.join(ws_re, "audit-events.jsonl"), corrupt)
    with open(corrupt, "a", encoding="utf-8", newline="\n") as fh:
        fh.write("{not-json\n")
    rr = run([BEV, "verify", "--events", corrupt])
    check("事件日志：非法行必须报 PARSE_ERROR，不得静默跳过",
          rr.returncode == 1 and "PARSE_ERROR" in rr.stdout)

    imp_ws = os.path.join(b21, "import")
    man21 = _wj("manifest.json", {
        "id": "FW-21", "vendor": "Demo", "product": "Router", "version": "1.0",
        "arch": "arm", "image": {"path": "fw.bin", "sha256": FW21, "size": 1}})
    l1_21 = _wj("layer1.json", {
        "schema": "layer1-sinks/1.3", "tool": "sink_scan", "findings": []})
    cand_doc = os.path.join(b21, "cand.jsonl")
    with open(cand_doc, "w", encoding="utf-8", newline="\n") as fh:
        json.dump({"schema": "candidates/1.0", "candidates": [
            {"id": "C-21", "status": "hypothesis"}]}, fh, ensure_ascii=False)
        fh.write("\n")
    run([BOARD, "init", "--workspace", imp_ws, "--run-id", RUN21,
         "--firmware-sha256", FW21])
    rr1 = run([BOARD, "import", "--workspace", imp_ws, "--manifest", man21,
               "--layer1", l1_21, "--candidates", cand_doc])
    rr2 = run([BOARD, "import", "--workspace", imp_ws, "--manifest", man21,
               "--layer1", l1_21, "--candidates", cand_doc])
    rep1 = _pj(rr1.stdout)
    rep2 = _pj(rr2.stdout)
    check("黑板：Phase 0–5 产物可导入（manifest/layer1/candidates）",
          rr1.returncode == 0
          and (rep1.get("items") or {}).get("candidates", {}).get("added") == 1,
          f"rc={rr1.returncode}")
    check("黑板：重复导入产物不重复落盘",
          rr2.returncode == 0
          and (rep2.get("items") or {}).get("candidates", {}).get("duplicates") == 1)
    check("黑板：导入后 verify 通过且计数一致",
          run([BOARD, "verify", "--workspace", imp_ws]).returncode == 0
          and (rep2.get("summary") or {}).get("counts", {}).get("candidates") == 1)

    fact_store = _wj("fact-store.json", {
        "schema": "fact/1.0", "fact_id": "F-21", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "firmware",
        "value": {"id": "FW-21"}, "evidence_refs": ["E-21"],
        "source": {"type": "static", "tool": "selftest"},
        "observed_at": "2026-01-01T00:00:00Z"})
    check("board_store：记录 Fact 并绑定已有证据",
          run([BOARD, "add", "--workspace", ws21, "--kind", "fact",
               "--file", fact_store]).returncode == 0)

    intent_store = _wj("intent-store.json", {
        "schema": "intent/1.0", "intent_id": "I-21", "run_id": RUN21,
        "firmware_sha256": FW21, "type": "dynamic-validation", "status": "open",
        "from": ["F-21"], "description": "验证命令注入", "dedupe_key": "I-21-key",
        "creator": "selftest", "created_at": "2026-01-01T00:00:00Z",
        "target": "usr/sbin/httpd"})
    rr = run([BOARD, "add", "--workspace", ws21, "--kind", "intent",
              "--file", intent_store])
    check("board_store：记录 Intent 并绑定事实来源", rr.returncode == 0,
          f"rc={rr.returncode}")
    rr = run([BOARD, "intent", "--workspace", ws21, "--intent", "I-21",
              "--to-status", "claimed", "--worker", "worker-1"])
    st21 = _rj(board_json)
    check("黑板：Intent claim 写入 worker 与 claimed_at",
          rr.returncode == 0
          and any(i.get("intent_id") == "I-21" and i.get("status") == "claimed"
                  and i.get("worker") == "worker-1" and i.get("claimed_at")
                  for i in st21.get("intents") or []),
          f"rc={rr.returncode}")

    hint_store = _wj("hint-store.json", {
        "schema": "hint/1.0", "hint_id": "H-21", "run_id": RUN21,
        "firmware_sha256": FW21, "content": "优先检查 upnpd 的 SOAP 处理",
        "creator": "selftest", "created_at": "2026-01-01T00:00:00Z"})
    check("board_store：记录 Hint（提示单独存放，不作为证据）",
          run([BOARD, "add", "--workspace", ws21, "--kind", "hint",
               "--file", hint_store]).returncode == 0)

    emu_store = _wj("emulation-store.json", {
        "schema": "emulation-result/1.0", "emulation_id": "EM-21",
        "run_id": RUN21, "intent_id": "I-21", "firmware_sha256": FW21,
        "backend": "qiling", "backend_version": "1.4", "status": "SUCCESS",
        "environment": {"arch": "mips"}, "observations": [],
        "started_at": "2026-01-01T00:00:00Z",
        "finished_at": "2026-01-01T00:01:00Z"})
    check("board_store：记录 EmulationResult 并关联 Intent",
          run([BOARD, "add", "--workspace", ws21, "--kind", "emulation",
               "--file", emu_store]).returncode == 0)
    st21 = _rj(board_json)
    check("黑板：Fact/Intent/Hint/Emulation 落盘后 verify 仍通过",
          any(e.get("emulation_id") == "EM-21"
              for e in st21.get("emulation_results") or [])
          and run([BOARD, "verify", "--workspace", ws21]).returncode == 0)

    print("\n[22/23] resource_manager.py — 资源准入、并发排队与执行路径清单")
    RM = os.path.join(HERE, "resource_manager.py")
    EXECP = os.path.join(HERE, "exec_paths.py")
    q22 = os.path.join(base, "resource22")
    os.makedirs(q22, exist_ok=True)
    fw22 = os.path.join(q22, "fw")
    os.makedirs(fw22, exist_ok=True)
    with open(os.path.join(fw22, "README"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("synthetic rootfs\n")

    def _w22(name: str, obj) -> str:
        path = os.path.join(q22, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
        return path

    def _r22(path: str):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _env22(extra=None):
        env = os.environ.copy()
        env["PYTHONUTF8"] = "1"
        env.update(extra or {})
        return env

    strict_pol = _w22("policy-strict.json", {
        "schema": "sandbox-policy/1.0", "max_concurrency": 1,
        "queue_timeout_s": 5, "max_total_seconds": 30, "max_timeout_s": 20,
        "max_memory_mb": 512, "max_cpus": 1, "max_pids": 64,
        "allowed_images": ["debian:bookworm-slim"], "allow_host": False})
    rr = run([RM, "validate", "--policy", strict_pol])
    pd = _pj(rr.stdout)
    check("resource_manager：策略通过校验并给出策略 sha256",
          rr.returncode == 0 and pd.get("ok") is True
          and len(str(pd.get("sha256") or "")) == 64,
          f"rc={rr.returncode}")

    bad_pol = _w22("policy-bad.json", {
        "schema": "sandbox-policy/1.0", "max_concurrency": 1,
        "queue_timeout_s": 5, "max_total_seconds": 30, "max_timeout_s": 20,
        "max_memory_mb": 512, "max_cpus": 1, "max_pids": 64,
        "allow_host": True, "surprise": 1})
    rr = run([RM, "validate", "--policy", bad_pol])
    codes = [e.get("code") for e in (_pj(rr.stdout).get("errors") or [])
             if isinstance(e, dict)]
    check("resource_manager：未知策略字段被拒绝（UNKNOWN_FIELD）",
          rr.returncode == 1 and "UNKNOWN_FIELD" in codes,
          f"rc={rr.returncode} codes={codes}")

    # 资源上限逐项拒绝：每项只越过一个上限，确保失败原因可归因。
    def _reject(name, extra, code):
        out = os.path.join(q22, name + ".json")
        args = [SANDBOX, "--firmware", fw22, "--policy", strict_pol,
                "--json", out, "--timeout", "10", "--pids", "64"] + extra
        rr = run(args)
        adm = _r22(out).get("admission") or {}
        check("资源准入：" + name + " → " + code + "（退出 4，未执行）",
              rr.returncode == 4 and adm.get("code") == code,
              f"rc={rr.returncode} code={adm.get('code')}")

    _reject("timeout-limit", ["--timeout", "30"], "TIMEOUT_LIMIT")
    _reject("memory-limit", ["--memory", "2g"], "MEMORY_LIMIT")
    _reject("cpu-limit", ["--cpus", "4"], "CPU_LIMIT")
    _reject("pids-limit", ["--pids", "256"], "PIDS_LIMIT")
    _reject("image-limit", ["--image", "evil:latest"], "IMAGE_NOT_ALLOWED")

    out = os.path.join(q22, "host-forbidden.json")
    rr = run([SANDBOX, "--firmware", fw22, "--mode", "host",
              "--i-understand-host-risk", "--cmd", "echo ok",
              "--policy", strict_pol, "--timeout", "10", "--pids", "64",
              "--json", out])
    adm = _r22(out).get("admission") or {}
    check("资源准入：策略禁止 host 模式 → HOST_FORBIDDEN（不得回落）",
          rr.returncode == 4 and adm.get("code") == "HOST_FORBIDDEN",
          f"rc={rr.returncode} code={adm.get('code')}")

    slot_pol = _w22("policy-slots.json", {
        "schema": "sandbox-policy/1.0", "max_concurrency": 1,
        "queue_timeout_s": 10, "max_total_seconds": 120, "max_timeout_s": 60,
        "max_memory_mb": 1024, "max_cpus": 2, "max_pids": 256,
        "allowed_images": None, "allow_host": True})
    slots = os.path.join(q22, "slots")
    # 用系统自带的等待命令占住槽位：不依赖编译器，也避免 Windows 上
    # cmd /c 对「带空格的解释器路径」加引号时的解析差异。
    cmd_slow = "ping -n 4 127.0.0.1" if os.name == "nt" else "sleep 4"
    host_args = [SANDBOX, "--firmware", fw22, "--mode", "host",
                 "--i-understand-host-risk", "--policy", slot_pol,
                 "--state-dir", slots, "--timeout", "20", "--cmd", cmd_slow]
    p1 = subprocess.Popen([PY] + host_args + ["--json", os.path.join(q22, "p1.json")],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace")
    time.sleep(0.8)
    q_out = os.path.join(q22, "queue-timeout.json")
    rr = run(host_args[:-2] + ["--cmd", "echo ok", "--queue-timeout", "0.2",
                               "--json", q_out])
    qd = _r22(q_out)
    check("资源准入：并发槽位被占用时排队，排队超时 → 退出 5 且未启动命令",
          rr.returncode == 5
          and (qd.get("admission") or {}).get("code") == "QUEUE_TIMEOUT"
          and qd.get("command") == [] and qd.get("exit_code") is None,
          f"rc={rr.returncode} code={(qd.get('admission') or {}).get('code')}")

    q_ok = os.path.join(q22, "queue-ok.json")
    rr = run(host_args[:-2] + ["--cmd", "echo ok", "--queue-timeout", "10",
                               "--json", q_ok])
    qd = _r22(q_ok)
    check("资源准入：排队后获得槽位并执行，wait_s > 0 记入 JSON",
          rr.returncode == 0
          and (qd.get("admission") or {}).get("decision") == "admitted"
          and ((qd.get("admission") or {}).get("slots") or {}).get("wait_s", 0) > 0.05,
          f"rc={rr.returncode} wait={(qd.get('admission') or {}).get('slots', {}).get('wait_s')}")
    p1.communicate(timeout=30)
    check("资源准入：槽位持有进程正常结束（锁可释放）",
          p1.returncode == 0, f"rc={p1.returncode}")

    p2 = subprocess.Popen([PY] + host_args + ["--json", os.path.join(q22, "p2.json")],
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                          text=True, encoding="utf-8", errors="replace")
    time.sleep(0.8)
    b_out = os.path.join(q22, "budget.json")
    rr = run(host_args[:-2] + ["--cmd", "echo ok", "--queue-timeout", "5",
                               "--budget", "1.5", "--json", b_out])
    bd = _r22(b_out)
    check("资源准入：排队耗尽总预算 → 退出 5 且未启动命令",
          rr.returncode == 5
          and (bd.get("admission") or {}).get("code") == "BUDGET_EXHAUSTED"
          and bd.get("command") == [],
          f"rc={rr.returncode} code={(bd.get('admission') or {}).get('code')}")
    p2.communicate(timeout=30)

    fake = os.path.join(q22, "fake_runtime.py")
    with open(fake, "w", encoding="utf-8", newline="\n") as fh:
        fh.write('import json, os, sys, time\n'
                 'def rec(ev):\n'
                 '    p = os.environ.get("FAKE_DOCKER_LOG")\n'
                 '    if p:\n'
                 '        with open(p, "a", encoding="utf-8") as f:\n'
                 '            f.write(json.dumps({"event": ev, "argv": sys.argv[1:]},'
                 ' ensure_ascii=False) + "\\n")\n'
                 'if len(sys.argv) > 1 and sys.argv[1] == "version":\n'
                 '    rec("version"); print("1.0-fake"); sys.exit(0)\n'
                 'if len(sys.argv) > 1 and sys.argv[1] == "run":\n'
                 '    rec("run"); time.sleep(float(os.environ.get("FAKE_SLEEP", "0")));'
                 ' sys.exit(int(os.environ.get("FAKE_EXIT", "0")))\n'
                 'if len(sys.argv) > 1 and sys.argv[1] == "rm":\n'
                 '    rec("rm"); sys.exit(0)\n'
                 'sys.exit(2)\n')
    flog = os.path.join(q22, "fake.log")
    if os.path.isfile(flog):
        os.remove(flog)
    fenv = _env22({"FAKE_DOCKER_LOG": flog})
    s_out = os.path.join(q22, "sandbox-ok.json")
    rr = run([SANDBOX, "--runtime-bin", fake, "--firmware", fw22,
              "--policy", slot_pol, "--state-dir", slots, "--timeout", "10",
              "--json", s_out], env=fenv)
    sd = _r22(s_out)
    check("sandbox：自定义运行时走隔离链路（--runtime-bin 只接受可信配置）",
          rr.returncode == 0 and sd.get("mode") == "sandbox"
          and (sd.get("command") or [])[:2] == [PY, fake]
          and (sd.get("admission") or {}).get("decision") == "admitted",
          f"rc={rr.returncode} mode={sd.get('mode')}")
    check("contracts.py：sandbox-run/1.1（含 admission）通过契约校验",
          os.path.isfile(s_out)
          and run([CONTRACTS, "--kind", "sandbox-run", "--file", s_out]).returncode == 0)

    # 容器固定以 uid 65534 运行，而 bind mount 不做 UID 映射。输出目录若保持
    # 0700/0755，容器内写 /out 会 Permission denied（真实 Ubuntu+Docker 实测过）。
    perm_out = os.path.join(q22, "sandbox-out")
    p_out = os.path.join(q22, "sandbox-perm.json")
    rr = run([SANDBOX, "--runtime-bin", fake, "--firmware", fw22,
              "--out", perm_out, "--policy", slot_pol, "--state-dir", slots,
              "--timeout", "10", "--json", p_out], env=fenv)
    perm_mode = stat.S_IMODE(os.stat(perm_out).st_mode) if os.path.isdir(perm_out) else 0
    check("sandbox：输出目录补 other 写位，容器内 uid 65534 可落产物",
          rr.returncode == 0 and bool(perm_mode & 0o002),
          f"rc={rr.returncode} mode={oct(perm_mode)}")

    t_out = os.path.join(q22, "sandbox-timeout.json")
    rr = run([SANDBOX, "--runtime-bin", fake, "--firmware", fw22,
              "--policy", slot_pol, "--state-dir", slots, "--timeout", "1",
              "--json", t_out],
             env=_env22({"FAKE_DOCKER_LOG": flog, "FAKE_SLEEP": "5"}))
    td = _r22(t_out)
    out_path = ((td.get("mounts") or {}).get("out") or {}).get("path") or ""
    log_text = ""
    if os.path.isfile(flog):
        log_text = open(flog, encoding="utf-8").read()
    check("sandbox：超时 → 退出 124、记录 timed_out、调用 rm 清理容器",
          rr.returncode == 124 and td.get("timed_out") is True
          and '"event": "rm"' in log_text,
          f"rc={rr.returncode} log={log_text[-120:]}")
    check("sandbox：超时后临时输出目录被删除，不在宿主机留下产物",
          bool(out_path) and not os.path.exists(out_path),
          out_path)

    ep_out = os.path.join(q22, "exec-paths.json")
    rr = run([EXECP, "--root", HERE, "--json", ep_out])
    epd = _r22(ep_out)
    counts = epd.get("counts") or {}
    check("exec_paths：执行路径清单完整，sandbox 边界与静态分析器均分类",
          rr.returncode == 0 and epd.get("ok") is True
          and counts.get("sandbox-boundary", 0) >= 3
          and counts.get("host-static-analyzer", 0) >= 2
          and not (epd.get("unclassified") or []),
          f"rc={rr.returncode} counts={counts}")

    badroot = os.path.join(q22, "unclassified")
    os.makedirs(badroot, exist_ok=True)
    with open(os.path.join(badroot, "bad.py"), "w", encoding="utf-8", newline="\n") as fh:
        fh.write("import subprocess\nsubprocess.run(['true'])\n")
    bad_out = os.path.join(q22, "exec-bad.json")
    rr = run([EXECP, "--root", badroot, "--json", bad_out])
    check("exec_paths：出现未分类执行路径时退出 1（新调用点不得静默漏网）",
          rr.returncode == 1 and _r22(bad_out).get("ok") is False,
          f"rc={rr.returncode}")

    print("\n[23/23] adapter_emba.py — 离线解析 EMBA 产物、三类观察与黑板导入")
    ADAPTER = os.path.join(HERE, "adapter_emba.py")
    q23 = os.path.join(base, "emba23")
    src23 = os.path.join(os.path.dirname(HERE), "assets", "emba-sample")
    logs23 = os.path.join(q23, "logs")
    os.makedirs(q23, exist_ok=True)
    shutil.copytree(src23, logs23)
    FW23 = "b" * 64
    RUN23 = "RUN-EMBA-23"

    def _w23(name: str, obj) -> str:
        path = os.path.join(q23, name)
        with open(path, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
        return path

    def _r23(path: str):
        try:
            with open(path, encoding="utf-8") as fh:
                return json.load(fh)
        except (OSError, ValueError):
            return {}

    def _copy23(name: str) -> str:
        dst = os.path.join(q23, name)
        shutil.copytree(logs23, dst)
        return dst

    def _emba(name: str, logs: str = "", extra=None):
        out = os.path.join(q23, name + ".json")
        args = [ADAPTER, "parse", "--logs", logs or logs23,
                "--run-id", RUN23, "--firmware-sha256", FW23,
                "--json", "--out", out] + list(extra or [])
        rr = run(args)
        return rr, _r23(out), out

    rr, d23, emba_ok = _emba("ok")
    facts23 = d23.get("facts") or []
    evid23 = d23.get("evidence") or []
    by_type23 = {}
    for f in facts23:
        by_type23.setdefault(f.get("type"), []).append(f)
    check("adapter_emba：离线解析 EMBA 夹具成功，不启动仿真/EMBA",
          rr.returncode == 0 and d23.get("status") == "parsed"
          and not d23.get("errors"),
          f"rc={rr.returncode} status={d23.get('status')}")
    check("adapter_emba：从 F50 提取 EMBA 版本并绑定 run/固件",
          (d23.get("tool") or {}).get("version") == "1.4.0"
          and d23.get("run_id") == RUN23
          and d23.get("firmware_sha256") == FW23,
          str(d23.get("tool")))
    check("adapter_emba：事实/证据计数与内容一致",
          len(facts23) == 13 and len(evid23) == 13
          and (d23.get("counts") or {}).get("facts") == 13
          and (d23.get("counts") or {}).get("evidence") == 13,
          f"facts={len(facts23)} evidence={len(evid23)}")
    check("adapter_emba：静态服务 / 运行进程 / 端口响应三类事实齐全且类型互异",
          all(by_type23.get(t) for t in
              ("service", "runtime-process", "port-response")),
          str(sorted(by_type23)))
    expect_obs = {"service": "static-discovery",
                  "runtime-process": "runtime-process",
                  "port-response": "port-response"}
    check("adapter_emba：三类观察的 value.observation 与 Fact.type 一一对应",
          all((f.get("value") or {}).get("observation") == want
              for typ, want in expect_obs.items()
              for f in by_type23.get(typ, [])),
          "observation 与 type 必须同源")
    ev_by_id = {e.get("evidence_id"): e for e in evid23}
    expect_ev = {"service": "static", "runtime-process": "emulation",
                 "port-response": "dynamic"}
    check("adapter_emba：三类观察引用不同证据类型，不能互相升级",
          all((ev_by_id.get(ref) or {}).get("type") == want
              for typ, want in expect_ev.items()
              for f in by_type23.get(typ, [])
              for ref in f.get("evidence_refs") or []),
          str(expect_ev))
    pr_val = (by_type23.get("port-response") or [{}])[0].get("value") or {}
    pr_ports = {p.get("port") for p in pr_val.get("ports") or []}
    pr_trigger = any(((ev_by_id.get(r) or {}).get("event") or {}).get("trigger") is True
                     for r in (by_type23.get("port-response") or [{}])[0].get("evidence_refs") or [])
    check("adapter_emba：端口响应解析出 80/tcp 与 443/tcp，且带触发事件",
          pr_ports == {80, 443} and pr_trigger, str(pr_val))

    logs_noport = _copy23("logs-noport")
    l10_noport = os.path.join(logs_noport, "csv_logs", "l10_system_emulation.csv")
    with open(l10_noport, encoding="utf-8", newline="") as fh:
        noport_rows = fh.read().splitlines()
    noport_cols = noport_rows[1].split(";")
    noport_cols[6] = "0"
    noport_cols[7] = ""
    noport_rows[1] = ";".join(noport_cols)
    with open(l10_noport, "w", encoding="utf-8", newline="\n") as fh:
        fh.write("\n".join(noport_rows) + "\n")
    rr_np, d_np, _ = _emba("noport", logs_noport)
    np_types = {f.get("type") for f in d_np.get("facts") or []}
    check("adapter_emba：L10 无开放端口时不生成 port-response，只留限制说明",
          rr_np.returncode == 0 and d_np.get("status") == "parsed"
          and "port-response" not in np_types
          and any("没有开放的端口响应" in x
                  for x in d_np.get("limitations") or []),
          f"rc={rr_np.returncode} types={sorted(np_types)}")

    fw_val = (by_type23.get("firmware") or [{}])[0].get("value") or {}
    stage_val = (by_type23.get("stage") or [{}])[0].get("value") or {}
    check("adapter_emba：真实 F50 的 NA 列填充不污染数字字段与状态值",
          fw_val.get("files") == 1234 and fw_val.get("directories") == 321
          and (fw_val.get("cves") or {}).get("cve_counter") == 5
          and stage_val.get("system_emulation_state") == "booted;IP_DET",
          f"files={fw_val.get('files')} state={stage_val.get('system_emulation_state')}")
    check("adapter_emba：F50 用户态仿真是计数而非状态字符串，标志位保留原样",
          stage_val.get("user_emulation_count") == 2
          and stage_val.get("user_emulation_state_raw") == "2"
          and "IP_DET" in (stage_val.get("system_emulation_flags") or []),
          str(stage_val))
    file_facts = by_type23.get("file") or []
    elf_facts = by_type23.get("elf") or []
    check("adapter_emba：P99 的 PE32 落成 file Fact，不冒充 ELF",
          len(file_facts) == 1
          and (file_facts[0].get("value") or {}).get("format") == "PE32"
          and (file_facts[0].get("value") or {}).get("path") == "usr/bin/setup.exe"
          and all((f.get("value") or {}).get("format") == "ELF"
                  for f in elf_facts),
          str([(f.get("value") or {}).get("path") for f in file_facts + elf_facts]))
    check("adapter_emba：L10 的 IP address / Network mode 展示前缀已剥离",
          pr_val.get("ip") == "192.168.0.1"
          and pr_val.get("network_mode") == "default"
          and (pr_val.get("ip_raw") or "").startswith("IP address:"),
          f"ip={pr_val.get('ip')} mode={pr_val.get('network_mode')}")
    dep_vals = [(d.get("value") or {}) for d in by_type23.get("dependency") or []]
    check("adapter_emba：S09 表头 version_rule 实为 app_name，类型列按 static/emulation 解析",
          {v.get("app_name") for v in dep_vals} == {"dropbear", "libcurl"}
          and all(v.get("mode") == "static" for v in dep_vals),
          str(dep_vals))
    rr2, d23b, emba_ok2 = _emba("ok-again")
    same_bytes = (open(emba_ok, "rb").read() == open(emba_ok2, "rb").read())
    check("adapter_emba：同一份产物重复解析字节稳定（ID/排序/时间不漂移）",
          rr2.returncode == 0 and same_bytes and d23 == d23b)
    check("contracts.py：emba-import 通过契约校验",
          run([CONTRACTS, "--kind", "emba-import",
               "--file", emba_ok]).returncode == 0)
    rr_strict, _, _ = _emba("strict", extra=["--strict"])
    check("adapter_emba：完整产物在 --strict 下仍为 parsed（rc0）",
          rr_strict.returncode == 0, f"rc={rr_strict.returncode}")

    logs_nof50 = _copy23("logs-nof50")
    os.remove(os.path.join(logs_nof50, "csv_logs", "f50_base_aggregator.csv"))
    rr_nf, d_nf, emba_nf = _emba("nof50", logs_nof50)
    nf_codes = [e.get("code") for e in d_nf.get("errors") or []]
    check("adapter_emba：缺 F50 → status=failed + F50_MISSING（rc1）",
          rr_nf.returncode == 1 and d_nf.get("status") == "failed"
          and "F50_MISSING" in nf_codes,
          f"rc={rr_nf.returncode} codes={nf_codes}")
    rr_ver, d_ver, _ = _emba("version", extra=["--expect-version", "9.9.9"])
    ver_codes = [e.get("code") for e in d_ver.get("errors") or []]
    check("adapter_emba：EMBA 版本不符 → EMBA_VERSION_MISMATCH（rc1）",
          rr_ver.returncode == 1 and "EMBA_VERSION_MISMATCH" in ver_codes,
          f"rc={rr_ver.returncode} codes={ver_codes}")
    fw_file = os.path.join(q23, "not-firmware.bin")
    with open(fw_file, "wb") as fh:
        fh.write(b"not the firmware")
    rr_fw, d_fw, _ = _emba("fwmismatch", extra=["--firmware", fw_file])
    fw_codes = [e.get("code") for e in d_fw.get("errors") or []]
    check("adapter_emba：--firmware 实算哈希与声明不符 → FIRMWARE_MISMATCH（rc1）",
          rr_fw.returncode == 1 and "FIRMWARE_MISMATCH" in fw_codes,
          f"rc={rr_fw.returncode} codes={fw_codes}")

    logs_nol10 = _copy23("logs-nol10")
    os.remove(os.path.join(logs_nol10, "csv_logs", "l10_system_emulation.csv"))
    rr_pa, d_pa, _ = _emba("partial", logs_nol10)
    pa_codes = [e.get("code") for e in d_pa.get("errors") or []]
    check("adapter_emba：缺可选日志 → status=partial + MISSING_ARTIFACT（rc0）",
          rr_pa.returncode == 0 and d_pa.get("status") == "partial"
          and "MISSING_ARTIFACT" in pa_codes,
          f"rc={rr_pa.returncode} codes={pa_codes}")
    rr_ps, _, _ = _emba("partial-strict", logs_nol10, ["--strict"])
    check("adapter_emba：partial 在 --strict 下退出 3，不伪装成完整解析",
          rr_ps.returncode == 3, f"rc={rr_ps.returncode}")

    logs_err = _copy23("logs-error")
    with open(os.path.join(logs_err, "emba_error.log"), "w",
              encoding="utf-8", newline="\n") as fh:
        fh.write("qemu: could not load firmware image\n")
    rr_er, d_er, _ = _emba("errlog", logs_err)
    er_codes = [e.get("code") for e in d_er.get("errors") or []]
    check("adapter_emba：非空 emba_error.log → partial + EMBA_ERROR_LOG",
          rr_er.returncode == 0 and d_er.get("status") == "partial"
          and "EMBA_ERROR_LOG" in er_codes,
          f"rc={rr_er.returncode} codes={er_codes}")
    er_stage = [f for f in d_er.get("facts") or []
                if (f.get("value") or {}).get("source") == "emba_error"]
    check("adapter_emba：错误日志事实仍是 static-discovery，并带失败标记",
          len(er_stage) == 1
          and (er_stage[0].get("value") or {}).get("observation") == "static-discovery"
          and (er_stage[0].get("value") or {}).get("failure") is True
          and (er_stage[0].get("value") or {}).get("error_lines") == 1
          and (d_er.get("counts") or {}).get("static-discovery") == 11,
          str(er_stage[0].get("value") if er_stage else None))

    rr_req, d_req, _ = _emba("require-ok", extra=["--require", "p99"])
    check("adapter_emba：--require 显式要求产物满足时记录 satisfied",
          rr_req.returncode == 0
          and (d_req.get("requirements") or {}).get("required") == ["p99"]
          and (d_req.get("requirements") or {}).get("satisfied") == ["p99"]
          and not (d_req.get("requirements") or {}).get("missing"),
          str(d_req.get("requirements")))
    logs_req = _copy23("logs-no-p99")
    os.remove(os.path.join(logs_req, "csv_logs", "p99_prepare_analyzer.csv"))
    rr_rm, d_rm, _ = _emba("require-missing", logs_req, ["--require", "p99"])
    rm_codes = [e.get("code") for e in d_rm.get("errors") or []]
    check("adapter_emba：--require 的产物缺失 → failed + MISSING_REQUIRED_ARTIFACT",
          rr_rm.returncode == 1 and d_rm.get("status") == "failed"
          and "MISSING_REQUIRED_ARTIFACT" in rm_codes
          and (d_rm.get("requirements") or {}).get("missing") == ["p99"],
          f"rc={rr_rm.returncode} codes={rm_codes}")
    rr_rb, _, _ = _emba("require-bad", extra=["--require", "nope"])
    check("adapter_emba：--require 未知角色 → rc2 BAD_REQUIRE，不静默忽略",
          rr_rb.returncode == 2 and "BAD_REQUIRE" in rr_rb.stderr,
          f"rc={rr_rb.returncode} err={rr_rb.stderr.strip()[:120]}")

    ws23 = os.path.join(q23, "board")
    run([BOARD, "init", "--workspace", ws23, "--run-id", RUN23,
         "--firmware-sha256", FW23])
    imp1 = run([BOARD, "import", "--workspace", ws23,
                "--emba", emba_ok])
    rep1 = _pj(imp1.stdout)
    imp2 = run([BOARD, "import", "--workspace", ws23,
                "--emba", emba_ok])
    rep2 = _pj(imp2.stdout)
    item1 = (rep1.get("items") or {}).get("emba") or {}
    item2 = (rep2.get("items") or {}).get("emba") or {}
    check("黑板：EMBA 产物按 evidence→fact 导入，计数与适配器一致",
          imp1.returncode == 0
          and ((item1.get("evidence") or {}).get("added") == 13)
          and ((item1.get("facts") or {}).get("added") == 13),
          f"rc={imp1.returncode} item={item1}")
    check("黑板：重复导入 EMBA 产物全部去重，不重复落盘",
          imp2.returncode == 0
          and ((item2.get("evidence") or {}).get("duplicates") == 13)
          and ((item2.get("facts") or {}).get("duplicates") == 13),
          f"rc={imp2.returncode} item={item2}")
    st23 = _r23(os.path.join(ws23, "audit-board.json"))
    fact_types23 = {f.get("type") for f in st23.get("facts") or []}
    check("黑板：三类观察以不同 Fact.type 共存，verify 通过",
          {"service", "runtime-process", "port-response"} <= fact_types23
          and (st23.get("counters") or {}).get("facts") == 13
          and run([BOARD, "verify", "--workspace", ws23]).returncode == 0,
          str(sorted(fact_types23)))

    ws_bad = os.path.join(q23, "board-run-mismatch")
    run([BOARD, "init", "--workspace", ws_bad, "--run-id", "RUN-OTHER",
         "--firmware-sha256", FW23])
    rr_bad = run([BOARD, "import", "--workspace", ws_bad, "--emba", emba_ok])
    check("黑板：EMBA 产物的 run_id 与黑板不一致 → RUN_MISMATCH（rc1）",
          rr_bad.returncode == 1 and "RUN_MISMATCH" in rr_bad.stderr,
          f"rc={rr_bad.returncode} err={rr_bad.stderr.strip()[:120]}")
    ws_fail = os.path.join(q23, "board-emba-failed")
    run([BOARD, "init", "--workspace", ws_fail, "--run-id", RUN23,
         "--firmware-sha256", FW23])
    rr_fail = run([BOARD, "import", "--workspace", ws_fail, "--emba", emba_nf])
    check("黑板：status=failed 的 EMBA 产物拒绝导入（EMBA_FAILED，rc1）",
          rr_fail.returncode == 1 and "EMBA_FAILED" in rr_fail.stderr,
          f"rc={rr_fail.returncode} err={rr_fail.stderr.strip()[:120]}")

    bad_obs = json.loads(json.dumps(d23))
    for row in bad_obs.get("facts") or []:
        if row.get("type") == "service":
            row["value"]["observation"] = "runtime-process"
            break
    bad_obs_path = _w23("bad-observation.json", bad_obs)
    rr_bo = run([CONTRACTS, "--kind", "emba-import", "--file", bad_obs_path])
    check("contracts.py：把静态服务改写成运行进程 → OBSERVATION_MISMATCH",
          rr_bo.returncode == 1 and "OBSERVATION_MISMATCH" in rr_bo.stdout,
          f"rc={rr_bo.returncode}")

    bad_req = json.loads(json.dumps(d23))
    bad_req["requirements"] = {"required": ["p99"], "satisfied": [],
                               "missing": ["p99"]}
    bad_req_path = _w23("bad-requirements.json", bad_req)
    rr_br = run([CONTRACTS, "--kind", "emba-import", "--file", bad_req_path])
    check("contracts.py：requirements 声称缺失却仍 parsed → REQUIREMENTS_INCONSISTENT",
          rr_br.returncode == 1
          and "REQUIREMENTS_INCONSISTENT" in rr_br.stdout,
          f"rc={rr_br.returncode}")

    print()
    if FAILS:
        print(f"[selftest] 失败 {len(FAILS)}/{TOTAL} 项: {FAILS}")
    else:
        print(f"[selftest] 全部通过（{TOTAL} 条断言 / {NGROUPS} 组）")
    if not args.keep and not args.workdir:
        shutil.rmtree(base, ignore_errors=True)
    else:
        print(f"[selftest] 样本保留在 {base}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
