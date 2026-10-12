#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fw_triage.py — IoT 固件度量 / 分层 / 资源分配（Phase 0 与 Phase 2）

纯 Python 标准库，无第三方依赖。功能：
  1) 固件镜像度量：大小、Shannon 熵、分块熵扫描（定位压缩/密文段）、magic 猜测、UPX 痕迹
  2) rootfs 分析：类型/架构直方图、ELF 加固画像（NX/PIE/Canary/RELRO/FORTIFY/.text 大小）、
     权限面（SUID/SGID/全局可写）、攻击面清单、敏感文件清单
  3) Tier 分层（依据 assets/tier-rules.json）+ EALB 计算 + Agent 分片 + 审计计划表

用法：
  # Phase 0：只看固件镜像
  python fw_triage.py firmware.bin --out 00-metrics.json

  # Phase 0+2：分析已提取的 rootfs 并分层
  python fw_triage.py --rootfs 01-extract --tier --budget 800 \
      --out 02-tiering.json --plan 03-audit-plan.md

  # 两者一起（镜像 + rootfs）
  python fw_triage.py firmware.bin --rootfs 01-extract --tier --out metrics.json
"""
from __future__ import annotations

import argparse
import collections
import json
import math
import os
import re
import stat
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ---------------------------------------------------------------- 常量表

MAGICS: List[Tuple[bytes, str]] = [
    (b"\x7fELF", "ELF 可执行文件"),
    (b"\x1f\x8b", "gzip 压缩流"),
    (b"BZh", "bzip2 压缩流"),
    (b"\xfd7zXZ\x00", "xz 压缩流"),
    (b"\x28\xb5\x2f\xfd", "zstd 压缩流"),
    (b"\x04\x22\x4d\x18", "lz4 压缩流"),
    (b"\x5d\x00\x00", "lzma 压缩流"),
    (b"hsqs", "SquashFS (小端)"),
    (b"sqsh", "SquashFS (大端)"),
    (b"\x85\x19", "JFFS2"),
    (b"UBI#", "UBI 卷"),
    (b"\x31\x18", "UBIFS"),
    (b"\x53\xef", "ext2/3/4 超级块"),
    (b"\x45\x3d\xcd\x28", "cramfs (小端)"),
    (b"\x28\xcd\x3d\x45", "cramfs (大端)"),
    (b"070701", "cpio (newc)"),
    (b"070702", "cpio (crc)"),
    (b"ustar", "tar"),
    (b"PK\x03\x04", "ZIP"),
    (b"PK\x05\x06", "ZIP (空)"),
    (b"7z\xbc\xaf\x27\x1c", "7-Zip"),
    (b"-rom1fs-", "romfs"),
    (b"\x27\x05\x19\x56", "U-Boot uImage"),
    (b"HDR0", "TRX 固件头"),
    (b"\xd0\x0d\xfe\xed", "FDT / FIT (device tree)"),
    (b"\x3a\xff\x26\xed", "Android sparse image"),
    (b"ANDROID!", "Android boot image"),
    (b"\x2d\x00\x00\x00", "Windows CE / 其他"),
    (b"CRAMFS", "cramfs (标识字符串)"),
    (b"UBI!", "UBI 擦除计数头"),
    (b"\xff\xff\xff\xff\xff\xff\xff\xff", "全 0xFF（空白 flash）"),
]

ELF_MACHINE = {
    2: "SPARC", 3: "x86", 8: "MIPS", 20: "PowerPC", 21: "PowerPC64",
    40: "ARM", 42: "SuperH", 50: "IA-64", 62: "x86_64", 83: "AVR",
    183: "AArch64", 243: "RISC-V", 258: "LoongArch",
}
ELF_TYPE = {0: "NONE", 1: "REL", 2: "EXEC", 3: "DYN(PIE/共享库)", 4: "CORE"}

PT_LOAD, PT_DYNAMIC = 1, 2
PT_GNU_STACK = 0x6474E551
PT_GNU_RELRO = 0x6474E552
SHT_SYMTAB, SHT_STRTAB, SHT_DYNSYM = 2, 3, 11
DT_BIND_NOW, DT_FLAGS, DT_FLAGS_1 = 24, 30, 0x6FFFFFFB
DF_BIND_NOW, DF_1_NOW = 0x8, 0x1

NET_SERVICE_NAMES = {
    "httpd", "lighttpd", "uhttpd", "boa", "goahead", "webs", "webserver",
    "mini_httpd", "thttpd", "miniupnpd", "upnpd", "wscd", "hnapd",
    "telnetd", "utelnetd", "sshd", "dropbear", "dnsmasq", "dhcpd", "udhcpd",
    "smbd", "nmbd", "ftpd", "vsftpd", "pure-ftpd", "mosquitto", "snmpd",
    "tftpd", "cwmp", "tr069", "acsd", "l2tpd", "pppd", "openvpn", "hostapd",
    "wpa_supplicant", "ntpd", "ntpclient", "ubusd", "netifd",
}
NET_SYMBOLS = {"listen", "accept", "recvfrom", "recv", "bind", "socketpair"}

SENSITIVE_PATTERNS = [
    re.compile(p, re.I) for p in (
        r"(^|/)etc/(passwd|shadow|group|sudoers)$",
        r"(^|/)etc/(hosts\.(allow|deny))$",
        r"\.(pem|key|p12|pfx|jks|keystore)$",
        r"(^|/)(id_rsa|id_dsa|id_ecdsa|authorized_keys|known_hosts)$",
        r"(^|/)(hostapd|wpa_supplicant)\.conf$",
        r"(^|/)nvram",
        r"(^|/)default.*\.cfg$",
        r"(^|/)etc/config/",
        r"(^|/)(\.npmrc|\.netrc|\.git-credentials|\.aws/credentials)$",
        r"(^|/)(web|www)/.*\.(bak|old|orig|save|swp|tmp)$",
    )
]

UPX_MARKERS = [b"UPX!", b"UPX0", b"UPX1", b"UPX2", b"$Info: This file is packed"]


# ---------------------------------------------------------------- 基础工具

def shannon(data: bytes) -> float:
    if not data:
        return 0.0
    counts = collections.Counter(data)
    n = len(data)
    ent = 0.0
    for c in counts.values():
        p = c / n
        ent -= p * math.log2(p)
    return ent


def entropy_segments(data: bytes, block: int = 4096,
                     high: float = 7.5, low: float = 4.0) -> List[Dict[str, Any]]:
    """分块算熵，把连续的高熵/低熵块合并成段。"""
    segs: List[Dict[str, Any]] = []
    total = len(data)
    cur_kind: Optional[str] = None
    cur_start = 0
    cur_vals: List[float] = []

    def flush(end: int) -> None:
        if cur_kind is None or not cur_vals:
            return
        avg = sum(cur_vals) / len(cur_vals)
        segs.append({
            "kind": cur_kind,
            "start": hex(cur_start),
            "end": hex(end),
            "size": end - cur_start,
            "avg_entropy": round(avg, 3),
        })

    for off in range(0, total, block):
        chunk = data[off:off + block]
        if len(chunk) < 32:
            break
        e = shannon(chunk)
        kind = "high" if e >= high else ("low" if e <= low else None)
        if kind != cur_kind:
            flush(off)
            cur_kind, cur_start, cur_vals = kind, off, []
        if kind is not None:
            cur_vals.append(e)
    flush(total)
    # 只保留有意义的段（>=64KB）
    return [s for s in segs if s["size"] >= 65536][:64]


def guess_magic(data: bytes) -> List[str]:
    hits = []
    head = data[:16]
    for magic, name in MAGICS:
        if head.startswith(magic):
            hits.append(name)
    # 在头部 1MB 内找 ustar / squashfs 等（有些固件前面有头）
    if not hits:
        scan = data[: 1 << 20]
        for magic, name in MAGICS:
            if magic in scan:
                hits.append(name + "（非 0 偏移）")
                if len(hits) >= 3:
                    break
    return hits


def detect_upx(data: bytes) -> Dict[str, Any]:
    found = [m.decode("latin1") for m in UPX_MARKERS if m in data[: 4 << 20]]
    return {"markers": found, "packed": bool(found)}


# ---------------------------------------------------------------- ELF 解析

class ElfInfo:
    __slots__ = ("ok", "error", "bits", "endian", "machine", "etype", "flags",
                 "text_size", "nx", "pie", "canary", "relro", "fortify",
                 "needed", "imports", "sections_named")

    def __init__(self) -> None:
        self.ok = False
        self.error = ""
        self.bits = 0
        self.endian = "little"
        self.machine = ""
        self.etype = ""
        self.flags = 0
        self.text_size = 0
        self.nx: Optional[bool] = None
        self.pie = False
        self.canary = False
        self.relro = "None"
        self.fortify = False
        self.needed: List[str] = []
        self.imports: List[str] = []
        self.sections_named = False


def parse_elf(path: str, max_size: int = 64 << 20) -> ElfInfo:
    info = ElfInfo()
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as f:
            data = f.read(min(size, max_size))
    except OSError as e:
        info.error = f"IO: {e}"
        return info
    if len(data) < 64 or data[:4] != b"\x7fELF":
        info.error = "not ELF"
        return info

    bits = 64 if data[4] == 2 else 32
    endian = "little" if data[5] == 1 else "big"
    info.bits, info.endian = bits, endian
    fmt = ("<" if endian == "little" else ">")

    import struct
    if bits == 32:
        hdr = struct.unpack_from(fmt + "HHIIIIIHHHHHH", data, 16)
        (etype, machine, _ver, _entry, phoff, shoff, flags,
         _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = hdr
    else:
        hdr = struct.unpack_from(fmt + "HHIQQQIHHHHHH", data, 16)
        (etype, machine, _ver, _entry, phoff, shoff, flags,
         _ehsize, phentsize, phnum, shentsize, shnum, shstrndx) = hdr

    info.etype = ELF_TYPE.get(etype, str(etype))
    info.machine = ELF_MACHINE.get(machine, f"machine#{machine}")
    info.flags = flags
    info.pie = (etype == 3)

    # ---- program headers ----
    has_relro = False
    seg_load_filesz = 0
    ph_fmt32 = fmt + "IIIIIIII"
    ph_fmt64 = fmt + "IIQQQQQQ"
    for i in range(min(phnum, 512)):
        off = phoff + i * phentsize
        if off + phentsize > len(data):
            break
        if bits == 32:
            p_type, _p_off, _vaddr, _paddr, p_filesz, _memsz, p_flags, _al = \
                struct.unpack_from(ph_fmt32, data, off)
        else:
            p_type, p_flags, _p_off, _vaddr, _paddr, p_filesz, _memsz, _al = \
                struct.unpack_from(ph_fmt64, data, off)
        if p_type == PT_GNU_STACK:
            info.nx = not bool(p_flags & 0x1)          # PF_X
        elif p_type == PT_GNU_RELRO:
            has_relro = True
        elif p_type == PT_LOAD:
            seg_load_filesz += p_filesz
    info.relro = "Partial" if has_relro else "None"

    # ---- sections ----
    sh_fmt32 = fmt + "IIIIIIIIII"
    sh_fmt64 = fmt + "IIQQQQIIQQ"
    sections: List[Tuple[int, int, int, str, int, int]] = []  # name_off,type,off,size,link,entsize
    dyn_sec: Optional[Tuple[int, int]] = None
    if shoff and shnum:
        entsz = sh_fmt32 if bits == 32 else sh_fmt64
        for i in range(min(shnum, 4096)):
            off = shoff + i * shentsize
            if off + shentsize > len(data):
                break
            if bits == 32:
                (sh_name, sh_type, _fl, _addr, sh_off, sh_size,
                 sh_link, _inf, _al, sh_entsize) = struct.unpack_from(sh_fmt32, data, off)
            else:
                (sh_name, sh_type, _fl, _addr, sh_off, sh_size,
                 sh_link, _inf, _al, sh_entsize) = struct.unpack_from(sh_fmt64, data, off)
            sections.append((sh_name, sh_type, sh_off, sh_size, sh_link, sh_entsize))

        # string table
        shstr = b""
        if 0 <= shstrndx < len(sections):
            _, _, o, s, _, _ = sections[shstrndx]
            shstr = data[o:o + s]
        names = {}
        for idx, (nm_off, stype, o, s, link, entsize) in enumerate(sections):
            end = shstr.find(b"\x00", nm_off)
            names[idx] = shstr[nm_off:end].decode("latin1", "replace") if nm_off < len(shstr) else ""
            if names[idx] == ".text":
                info.text_size = s
            if names[idx] == ".dynamic":
                dyn_sec = (o, s)
        info.sections_named = bool(shstr)

        # symbols
        for idx, (_, stype, o, s, link, entsize) in enumerate(sections):
            if stype not in (SHT_DYNSYM, SHT_SYMTAB):
                continue
            strtab = b""
            if 0 <= link < len(sections):
                _, _, so, ss, _, _ = sections[link]
                strtab = data[so:so + ss]
            names_list = _read_symbols(data, o, s, entsize, bits, fmt, strtab)
            if stype == SHT_DYNSYM:
                info.imports = names_list
            if any("__stack_chk" in n for n in names_list):
                info.canary = True
            if any("_chk" in n for n in names_list):
                info.fortify = True

    if not info.text_size:
        # 无节表（strip 掉 section header）时的近似
        info.text_size = int(seg_load_filesz * 0.5) if seg_load_filesz else int(len(data) * 0.4)

    # RELRO 终判：Full = PT_GNU_RELRO 存在 且 dynamic 里有 BIND_NOW；无 PT_GNU_RELRO 一律 None
    if not has_relro:
        info.relro = "None"
    else:
        bind_now = bool(dyn_sec) and _dynamic_has_bind_now(
            data, dyn_sec[0], dyn_sec[1], bits, fmt)
        info.relro = "Full" if bind_now else "Partial"

    info.ok = True
    return info


def _dynamic_has_bind_now(data: bytes, off: int, size: int, bits: int,
                          fmt: str) -> bool:
    esz = 8 if bits == 32 else 16
    for o in range(off, min(off + size, len(data)), esz):
        if o + esz > len(data):
            break
        if bits == 32:
            tag, val = struct_unpack32(data, o, fmt)
        else:
            tag, val = struct_unpack64(data, o, fmt)
        if tag == 0:
            break
        if tag == DT_BIND_NOW:
            return True
        if tag == DT_FLAGS and (val & DF_BIND_NOW):
            return True
        if tag == DT_FLAGS_1 and (val & DF_1_NOW):
            return True
    return False


def struct_unpack32(data: bytes, off: int, fmt: str):
    import struct
    return struct.unpack_from(fmt + "II", data, off)


def struct_unpack64(data: bytes, off: int, fmt: str):
    import struct
    return struct.unpack_from(fmt + "QQ", data, off)


def _read_symbols(data: bytes, off: int, size: int, entsize: int,
                  bits: int, fmt: str, strtab: bytes) -> List[str]:
    import struct
    out: List[str] = []
    if entsize <= 0:
        entsize = 16 if bits == 32 else 24
    n = min(size // entsize, 20000) if entsize else 0
    for i in range(n):
        o = off + i * entsize
        if o + entsize > len(data):
            break
        if bits == 32:
            st_name = struct.unpack_from(fmt + "I", data, o)[0]
        else:
            st_name = struct.unpack_from(fmt + "I", data, o)[0]
        if st_name and st_name < len(strtab):
            end = strtab.find(b"\x00", st_name)
            out.append(strtab[st_name:end].decode("latin1", "replace"))
    return out


def extract_strings(path: str, min_len: int = 4, limit: int = 200000,
                   max_read: int = 8 << 20) -> List[str]:
    try:
        with open(path, "rb") as f:
            data = f.read(max_read)
    except OSError:
        return []
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    out = []
    for m in pat.finditer(data):
        out.append(m.group().decode("latin1"))
        if len(out) >= limit:
            break
    return out


# ---------------------------------------------------------------- 文件类型判定

SCRIPT_EXT = {".sh", ".bash", ".cgi", ".pl", ".py", ".lua", ".awk", ".sed"}
WEB_EXT = {".html", ".htm", ".js", ".php", ".asp", ".aspx", ".jsp", ".json"}
CONFIG_EXT = {".conf", ".cfg", ".ini", ".xml", ".properties", ".cnf", ".yaml", ".yml"}


def detect_file_kind(path: str, head: bytes) -> str:
    ext = os.path.splitext(path)[1].lower()
    base = os.path.basename(path).lower()
    if head[:4] == b"\x7fELF" or head[:2] == b"MZ" or head[:4] in (
            b"\xfe\xed\xfa\xce", b"\xce\xfa\xed\xfe", b"\xca\xfe\xba\xbe"):
        return "binary"
    if ext in SCRIPT_EXT or head[:2] == b"#!" or base in ("rcs", "rc.local", "inittab"):
        return "script"
    if ext in WEB_EXT:
        return "web"
    if ext in CONFIG_EXT or base.startswith("nvram"):
        return "config"
    # 内容判据
    if head and (head.count(b"\x00") > 0 or _nonprint_ratio(head) > 0.30):
        return "binary"
    return "text"


def _nonprint_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    bad = sum(1 for c in b if c < 9 or (13 < c < 32) or c > 126)
    return bad / len(b)


def is_textual(kind: str) -> bool:
    return kind in ("script", "web", "config", "text")


# ---------------------------------------------------------------- Tier 分层

def load_tier_rules(path: Optional[str]) -> Dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    cand = path or os.path.join(here, "..", "assets", "tier-rules.json")
    with open(cand, encoding="utf-8") as f:
        return json.load(f)


def compile_rules(rules: Dict[str, Any]) -> List[Dict[str, Any]]:
    out = []
    for r in rules["rules"]:
        out.append({
            "id": r["id"],
            "tier": r["tier"],
            "reason": r.get("reason", ""),
            "fallback": bool(r.get("fallback")),
            "path_regex": [re.compile(p, re.I) for p in r.get("path_regex", [])],
            "name_regex": [re.compile(p, re.I) for p in r.get("name_regex", [])],
            "content_regex": [re.compile(p, re.I) for p in r.get("content_regex", [])],
            "symbol_any": r.get("symbol_any", []),
        })
    # 兜底永远最后
    out.sort(key=lambda r: r["fallback"])
    return out


def classify(rel: str, elf: Optional[ElfInfo], kind: str,
             strings: Optional[List[str]], rules: List[Dict[str, Any]]) -> Tuple[str, str]:
    rel_l = rel.replace("\\", "/")
    base = os.path.basename(rel_l)
    for r in rules:
        if r["fallback"]:
            continue
        for rx in r["path_regex"]:
            if rx.search(rel_l):
                return r["tier"], f"{r['id']}:path"
        for rx in r["name_regex"]:
            if rx.search(base):
                return r["tier"], f"{r['id']}:name"
        if elf is not None and elf.ok and r["symbol_any"]:
            imports = {s.lower() for s in elf.imports}
            if imports & set(r["symbol_any"]):
                return r["tier"], f"{r['id']}:symbol"
        if elf is not None and elf.ok and r["content_regex"] and strings:
            sample = "\n".join(strings[:4000])
            for rx in r["content_regex"]:
                if rx.search(sample):
                    return r["tier"], f"{r['id']}:content"
    for r in rules:
        if r["fallback"]:
            return r["tier"], f"{r['id']}:fallback"
    return "T2", "R5:fallback"


def text_units(path: str, elf: Optional[ElfInfo], kind: str,
               line_to_kb: int) -> float:
    if elf is not None and elf.ok:
        return round(elf.text_size / 1024.0, 2)
    try:
        sz = os.path.getsize(path)
    except OSError:
        return 0.0
    if is_textual(kind):
        try:
            with open(path, "rb") as f:
                lines = sum(1 for _ in f)
        except OSError:
            lines = 0
        return round(lines / float(line_to_kb), 2)
    return round(sz / 1024.0 * 0.4, 2)


def make_shards(entries: List[Dict[str, Any]], budget: int) -> List[Dict[str, Any]]:
    """首次适应递减（FFD）装箱；同一二进制不切分。"""
    items = sorted(entries, key=lambda e: -e["text_kb"])
    bins: List[Dict[str, Any]] = []
    for it in items:
        placed = False
        for b in bins:
            if b["ealoc"] + it["text_kb"] <= budget:
                b["files"].append(it)
                b["ealoc"] = round(b["ealoc"] + it["text_kb"], 2)
                placed = True
                break
        if not placed:
            bins.append({"id": "", "ealoc": round(it["text_kb"], 2), "files": [it]})
    for i, b in enumerate(bins, 1):
        b["id"] = "S%02d" % i
        b["files"].sort(key=lambda e: (-e["text_kb"]))
    bins.sort(key=lambda b: -b["ealoc"])
    for i, b in enumerate(bins, 1):
        b["id"] = "S%02d" % i
    return bins


# ---------------------------------------------------------------- 主流程

def analyze_image(path: str, block: int = 4096) -> Dict[str, Any]:
    size = os.path.getsize(path)
    with open(path, "rb") as f:
        head = f.read(1 << 20)
    whole = None
    if size <= 256 << 20:
        with open(path, "rb") as f:
            whole = f.read()
    res: Dict[str, Any] = {
        "path": os.path.abspath(path),
        "size": size,
        "sha256_head_note": "如需完整 SHA256：Get-FileHash / sha256sum",
        "magic_guess": guess_magic(head),
    }
    if whole is not None:
        import hashlib
        res["sha256"] = hashlib.sha256(whole).hexdigest()
        res["entropy_overall"] = round(shannon(whole), 3)
        res["entropy_segments"] = entropy_segments(whole, block)
        res["upx"] = detect_upx(whole)
    else:
        res["entropy_overall"] = round(shannon(head), 3)
        res["entropy_segments"] = []
        res["upx"] = detect_upx(head)
        res["note"] = "文件较大，熵扫描仅覆盖前 1MB"
    return res


def analyze_rootfs(rootfs: str, rules: Dict[str, Any], budget: int,
                   with_tier: bool, min_strings: int) -> Dict[str, Any]:
    compiled = compile_rules(rules)
    weights = rules["weights"]
    line_to_kb = int(rules.get("text_line_to_kb", 40))
    skip_dirs = [d.lower() for d in rules.get("skip_dirs", [])]

    files: List[Dict[str, Any]] = []
    kinds = collections.Counter()
    arch = collections.Counter()
    hardening_missing = collections.Counter()
    suid: List[str] = []
    sgid: List[str] = []
    world_writable: List[str] = []
    sensitive: List[str] = []
    attack_surface: List[str] = []
    elfs: List[Dict[str, Any]] = []

    root_abs = os.path.abspath(rootfs)
    perm_reliable = os.name == "posix"

    for dirpath, dirnames, filenames in os.walk(root_abs):
        # 跳过明显的无关大目录，降低遍历成本
        rel_dir = os.path.relpath(dirpath, root_abs).replace("\\", "/").lower()
        if any(sd in rel_dir.split("/") for sd in ("proc", "sys", "dev")):
            dirnames[:] = []
            continue
        for fn in filenames:
            full = os.path.join(dirpath, fn)
            if os.path.islink(full):
                continue
            rel = os.path.relpath(full, root_abs).replace("\\", "/")
            try:
                st = os.stat(full)
            except OSError:
                continue
            if not stat.S_ISREG(st.st_mode):
                continue
            try:
                with open(full, "rb") as f:
                    head = f.read(64)
            except OSError:
                continue
            kind = detect_file_kind(rel, head)
            kinds[kind] += 1

            elf = None
            strings = None
            if head[:4] == b"\x7fELF":
                elf = parse_elf(full)
                if elf.ok:
                    arch[f"{elf.machine}/{elf.bits}-bit/{elf.endian}"] += 1
                    miss = []
                    if elf.nx is False:
                        miss.append("NX")
                    if not elf.pie:
                        miss.append("PIE")
                    if not elf.canary:
                        miss.append("Canary")
                    if elf.relro != "Full":
                        miss.append("RELRO:" + elf.relro)
                    if not elf.fortify:
                        miss.append("FORTIFY")
                    for m in miss:
                        hardening_missing[m] += 1
                    elfs.append({
                        "file": rel, "arch": f"{elf.machine}/{elf.bits}",
                        "etype": elf.etype, "text_kb": round(elf.text_size / 1024.0, 2),
                        "nx": elf.nx, "pie": elf.pie, "canary": elf.canary,
                        "relro": elf.relro, "fortify": elf.fortify,
                        "missing": miss,
                    })
                if with_tier:
                    strings = extract_strings(full, min_strings)

            if perm_reliable:
                if st.st_mode & stat.S_ISUID:
                    suid.append(rel)
                if st.st_mode & stat.S_ISGID:
                    sgid.append(rel)
                if st.st_mode & 0o002:
                    world_writable.append(rel)

            for rx in SENSITIVE_PATTERNS:
                if rx.search(rel):
                    sensitive.append(rel)
                    break

            if with_tier:
                tier, why = classify(rel, elf, kind, strings, compiled)
                tu = text_units(full, elf, kind, line_to_kb)
                rec = {
                    "file": rel, "tier": tier, "why": why, "kind": kind,
                    "text_kb": tu, "size": st.st_size,
                    "weight": weights.get(tier, 0.0),
                }
                if tier in ("T1",) and why.startswith(("R2", "R3")):
                    attack_surface.append(rel)
                files.append(rec)

    result: Dict[str, Any] = {
        "rootfs": root_abs,
        "file_count": sum(kinds.values()),
        "by_kind": dict(kinds),
        "elf_count": len(elfs),
        "arch_histogram": dict(arch),
        "permission_scan_reliable": perm_reliable,
        "permission_note": ("" if perm_reliable else
                            "当前平台非 POSIX，文件权限位不可靠，SUID/SGID/可写扫描结果无效；"
                            "请在 Linux 或容器内重跑。"),
        "suid": sorted(suid)[:500],
        "sgid": sorted(sgid)[:500],
        "world_writable": sorted(world_writable)[:500],
        "sensitive_files": sorted(set(sensitive))[:500],
        "attack_surface": sorted(set(attack_surface))[:1000],
        "elf_hardening": {
            "missing_counter": dict(hardening_missing),
            "unhardened_binaries": sorted(
                elfs, key=lambda e: -len(e["missing"]))[:80],
        },
        "elf_detail": sorted(elfs, key=lambda e: -e["text_kb"])[:400],
    }

    if with_tier:
        by_tier: Dict[str, List[Dict[str, Any]]] = collections.defaultdict(list)
        for f in files:
            by_tier[f["tier"]].append(f)
        ealoc = round(sum(f["weight"] * f["text_kb"] for f in files), 2)
        auditable = [f for f in files if f["tier"] != "SKIP"]
        agents = max(1, int(math.ceil(ealoc / float(budget)))) if ealoc else 1
        # SKIP 不计入 EALB，但计入文件统计
        tiers_summary = {}
        for t in ("T1", "T2", "T3", "SKIP"):
            lst = by_tier.get(t, [])
            tiers_summary[t] = {
                "files": len(lst),
                "text_kb_total": round(sum(x["text_kb"] for x in lst), 2),
                "ealoc_contribution": round(
                    sum(x["weight"] * x["text_kb"] for x in lst), 2),
            }
        shards = make_shards(auditable, budget)
        result["tiering"] = {
            "rules_source": "assets/tier-rules.json",
            "weights": weights,
            "budget_per_agent": budget,
            "agents": agents,
            "ealoc_total": ealoc,
            "raw_agent_count_if_flat": max(1, int(math.ceil(
                sum(f["text_kb"] for f in auditable) / float(budget)))) if auditable else 1,
            "summary": tiers_summary,
            "shards": [{"id": s["id"], "ealoc": s["ealoc"],
                        "files": len(s["files"]),
                        "file_list": [f["file"] for f in s["files"]],
                        "items": [{"file": f["file"], "tier": f["tier"],
                                   "text_kb": f["text_kb"]} for f in s["files"]]}
                       for s in shards],
            "t1_list": [f["file"] for f in by_tier.get("T1", [])],
            "t2_list": [f["file"] for f in by_tier.get("T2", [])],
            "t3_list": [f["file"] for f in by_tier.get("T3", [])],
            "skip_list": [f["file"] for f in by_tier.get("SKIP", [])],
            "tier_basis": [
                {"file": f["file"], "tier": f["tier"], "why": f["why"]}
                for f in files if f["why"].startswith(("R2", "R3")) and f["tier"] == "T1"
            ][:2000],
            "promotions": [],
            "promotions_note": ("本字段由审计者在 Phase 3 期间填写：Layer 1 命中 P0/P1 的动态提升"
                                "（R1）、T2→T1 与 T3→T2 的就地提升（R1b/R1c）。Phase 2 生成时为空。"),
        }
    return result


def write_plan(path: str, tiering: Dict[str, Any]) -> None:
    lines = [
        "# 审计分配计划（Phase 2 产出）",
        "",
        "| 指标 | 值 |",
        "|---|---|",
        f"| EALB 总量 | {tiering['ealoc_total']} |",
        f"| 单 Agent 预算 | {tiering['budget_per_agent']} |",
        f"| 建议 Agent 数 | {tiering['agents']} |",
        f"| 若按原始体量平均分 | {tiering['raw_agent_count_if_flat']} |",
        "",
        "## Tier 汇总",
        "",
        "| Tier | 文件数 | text_kb 合计 | EALB 贡献 |",
        "|---|---|---|---|",
    ]
    for t in ("T1", "T2", "T3", "SKIP"):
        s = tiering["summary"].get(t)
        if s:
            lines.append(f"| {t} | {s['files']} | {s['text_kb_total']} | {s['ealoc_contribution']} |")
    lines += ["", "## 分片与文件清单（逐项打勾）", ""]
    for s in tiering["shards"]:
        lines.append(f"### {s['id']}（EALB {s['ealoc']}，{s['files']} 个文件）")
        lines.append("")
        lines.append("| 完成 | 文件 | Tier | text_kb |")
        lines.append("|---|---|---|---|")
        items = s.get("items") or [{"file": f, "tier": "", "text_kb": ""} for f in s["file_list"]]
        for f in items:
            lines.append("| [ ] | `%s` | %s | %s |" % (f["file"], f.get("tier", ""), f.get("text_kb", "")))
        lines.append("")
    lines += [
        "## 审计要求",
        "",
        "- 每个文件都必须产出结论（finding 或 `NOT_FOUND`），写入 `30-findings-verified.md`",
        "- Tier 深度：T1 全量 8 项 / T2 3 项（数据流 + 敏感操作 + 安全控制）/ T3 3 项模式匹配",
        "- 动态提升要记录到 `02-tiering.json` 的 `promotions` 数组",
        "",
        "## Phase 2.5 用法（审阅清单）",
        "",
        "把本文件的「分片与文件清单」另存为 `25-review-list.md`（或直接复制到该文件），"
        "审计时**读完一个文件就把 `[ ]` 改成 `[x]`**，不要事后补勾。",
        "然后跑 `coverage_gate.py --review-list 25-review-list.md` 做三方对齐：",
        "计划（本文件）↔ 声明（审阅清单打勾）↔ 结论（30-findings-verified.md）。",
        "详情见 SKILL.md 的 Phase 2.5。",
    ]
    with open(path, "w", encoding="utf-8", newline="\n") as f:
        f.write("\n".join(lines) + "\n")


def main() -> int:
    ap = argparse.ArgumentParser(description="IoT 固件度量 / Tier 分层 / EALB 预算")
    ap.add_argument("image", nargs="?", help="固件镜像路径（Phase 0）")
    ap.add_argument("--rootfs", help="已提取的 rootfs 目录（Phase 0/2）")
    ap.add_argument("--tier", action="store_true", help="执行 Tier 分层与 EALB 计算")
    ap.add_argument("--budget", type=int, default=0, help="单 Agent EALB 预算，默认取规则文件")
    ap.add_argument("--rules", help="tier-rules.json 路径")
    ap.add_argument("--out", help="输出 JSON 路径（默认打印到 stdout）")
    ap.add_argument("--plan", help="同时输出审计计划 Markdown 到该路径")
    ap.add_argument("--min-strings", type=int, default=5,
                    help="二进制字符串提取最小长度，默认 5")
    ap.add_argument("--pretty", action="store_true", help="缩进输出")
    args = ap.parse_args()

    if not args.image and not args.rootfs:
        ap.print_help()
        return 2

    out: Dict[str, Any] = {"tool": "fw_triage.py", "version": "1.0"}
    if args.image:
        if not os.path.isfile(args.image):
            print(f"镜像不存在: {args.image}", file=sys.stderr)
            return 2
        out["image"] = analyze_image(args.image)
    if args.rootfs:
        if not os.path.isdir(args.rootfs):
            print(f"rootfs 不存在: {args.rootfs}", file=sys.stderr)
            return 2
        rules = load_tier_rules(args.rules)
        budget = args.budget or int(rules.get("default_budget_per_agent", 800))
        out["rootfs_analysis"] = analyze_rootfs(
            args.rootfs, rules, budget, args.tier, args.min_strings)

    if args.plan and args.tier and args.rootfs:
        t = out["rootfs_analysis"].get("tiering")
        if t:
            write_plan(args.plan, t)

    text = json.dumps(out, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.out:
        d = os.path.dirname(os.path.abspath(args.out))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"[ok] 已写入 {args.out}")
        # 人读摘要
        if args.image:
            im = out["image"]
            print(f"  镜像: {im['size']} bytes, 熵 {im.get('entropy_overall')}, "
                  f"magic {im['magic_guess'][:3]}, UPX={im['upx']['packed']}")
        if args.rootfs:
            ra = out["rootfs_analysis"]
            print(f"  文件 {ra['file_count']} 个，ELF {ra['elf_count']} 个，"
                  f"架构 {list(ra['arch_histogram'].items())[:4]}")
            if args.tier and "tiering" in ra:
                t = ra["tiering"]
                print(f"  EALB {t['ealoc_total']} → {t['agents']} 个 Agent"
                      f"（若平均分需 {t['raw_agent_count_if_flat']} 个）")
                for k in ("T1", "T2", "T3", "SKIP"):
                    s = t["summary"][k]
                    print(f"    {k}: {s['files']} 文件 / {s['text_kb_total']} KB")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
