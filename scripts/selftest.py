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
import json
import os
import random
import re
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
FAILS: list = []
TOTAL = 0          # 实际执行的断言数：由脚本自己报，避免文档里的数字靠数日志漂移
NGROUPS = 15       # 组数：与各处 [N/15] 表头一致，末尾会自校验，防止「13 组」再次漂移


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


def run(args: list) -> subprocess.CompletedProcess:
    return subprocess.run([PY] + args, capture_output=True, text=True)


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

    print("\n[1/15] fw_triage.py — 度量 / 加固画像 / 分层")
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

    print("\n[2/15] sink_scan.py — Layer 1 危险模式扫描")
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

    print("\n[3/15] coverage_gate.py — 覆盖率门禁（不完整应拒绝）")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vpart, "--tiering", tiering])
    check("不完整输入 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")

    print("\n[4/15] coverage_gate.py — 覆盖率门禁（完整应通过）")
    out = os.path.join(base, "40-coverage.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering, "--out", out])
    check("完整输入 → 退出码 0", r.returncode == 0, r.stdout.strip()[-160:])
    check("门禁报告已生成", os.path.isfile(out))

    print("\n[5/15] coverage_gate.py — CVE 纪律检查（版本命中 ≠ 可利用漏洞）")
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

    print("\n[6/15] coverage_gate.py — 审阅清单三方对齐（计划 ↔ 声明 ↔ 结论）")
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

    print("\n[7/15] coverage_gate.py — 报告 9 必填字段校验")
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

    print("\n[8/15] coverage_gate.py — G4 入口级覆盖（文件级 100% ≠ 入口级 100%）")
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

    print("\n[9/15] coverage_gate.py — G5 绕过矩阵（「有防护」≠「防护有效」）")
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

    print("\n[10/15] coverage_gate.py — G6 跨请求污点溯源（持久化来源须声明写入面）")
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

    print("\n[11/15] coverage_gate.py — G1/G2/G3 自动修复 + 类型→Base 命中")
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

    print("\n[12/15] sink_scan.py — 结构级二次过滤（正则初筛 → 结构确认 / 否定 / 回退）")
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
    print("\n[13/15] 扫描完整性与门禁严格性")

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
    print("\n[15/15] taint_graph.py — 跨请求污点图（BDG/ADG）与 G7 门禁")
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
