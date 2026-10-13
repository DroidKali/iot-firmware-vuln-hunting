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
import json
import os
import random
import shutil
import struct
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
PY = sys.executable
FAILS: list = []


def check(name: str, ok: bool, detail: str = "") -> None:
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

    print("\n[1/10] fw_triage.py — 度量 / 加固画像 / 分层")
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

    print("\n[2/10] sink_scan.py — Layer 1 危险模式扫描")
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

    print("\n[3/10] coverage_gate.py — 覆盖率门禁（不完整应拒绝）")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vpart, "--tiering", tiering])
    check("不完整输入 → 退出码 1", r.returncode == 1, f"rc={r.returncode}")

    print("\n[4/10] coverage_gate.py — 覆盖率门禁（完整应通过）")
    out = os.path.join(base, "40-coverage.md")
    r = run([os.path.join(HERE, "coverage_gate.py"), "--plan", plan,
             "--verified", vfull, "--tiering", tiering, "--out", out])
    check("完整输入 → 退出码 0", r.returncode == 0, r.stdout.strip()[-160:])
    check("门禁报告已生成", os.path.isfile(out))

    print("\n[5/10] coverage_gate.py — CVE 纪律检查（版本命中 ≠ 可利用漏洞）")
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

    print("\n[6/10] coverage_gate.py — 审阅清单三方对齐（计划 ↔ 声明 ↔ 结论）")
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

    print("\n[7/10] coverage_gate.py — 报告 9 必填字段校验")
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

    print("\n[8/10] coverage_gate.py — G4 入口级覆盖（文件级 100% ≠ 入口级 100%）")
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

    print("\n[9/10] coverage_gate.py — G5 绕过矩阵（「有防护」≠「防护有效」）")
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

    print("\n[10/10] coverage_gate.py — G1/G2/G3 自动修复 + 类型→Base 命中")
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

    print()
    if FAILS:
        print(f"[selftest] 失败 {len(FAILS)} 项: {FAILS}")
    else:
        print("[selftest] 全部通过")
    if not args.keep and not args.workdir:
        shutil.rmtree(base, ignore_errors=True)
    else:
        print(f"[selftest] 样本保留在 {base}")
    return 1 if FAILS else 0


if __name__ == "__main__":
    sys.exit(main())
