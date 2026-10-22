#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sink_scan.py — Layer 1 机器扫广度（Phase 3）

数据驱动的多语言危险模式扫描。规则来自 assets/sink-rules.json。
- 二进制：提取 ASCII 字符串后在字符串上匹配（kind=binary-string），绝不声称"代码里调用了 X"
- 文本/脚本/Web/配置：按行匹配（kind=source-line），附行号与 ±N 行上下文
- 排噪：跳过 R0 目录、跳过注释与 import/include、anti 模式排除、同规则同文件只报首个

用法：
  python sink_scan.py 01-extract --rules ../assets/sink-rules.json \
      --json 10-layer1-sinks.json --md 10-layer1-sinks.md
  python sink_scan.py 01-extract --only-priority P0,P1 --context 3
"""
from __future__ import annotations

import argparse
import collections
import json
import os
import re
import shutil
import subprocess
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
try:
    import fw_triage as _tri                      # noqa
except Exception:                                  # pragma: no cover
    _tri = None

PRIORITY_ORDER = {"P0": 0, "P1": 1, "P2": 2, "P3": 3}

SCRIPT_EXT = {".sh", ".bash", ".cgi", ".pl", ".py", ".lua", ".awk", ".sed"}
WEB_EXT = {".html", ".htm", ".js", ".php", ".asp", ".aspx", ".jsp", ".json"}
CONFIG_EXT = {".conf", ".cfg", ".ini", ".xml", ".properties", ".cnf", ".yaml", ".yml"}

COMMENT_LINE = re.compile(r"^\s*(#|//|;|\*|/\*|<!--)")
IMPORT_LINE = re.compile(r"^\s*(#\s*include|import\s|from\s+\w+\s+import|using\s)")


# ------------------------------------------------------------ 文件类型

def nonprint_ratio(b: bytes) -> float:
    if not b:
        return 0.0
    bad = sum(1 for c in b if c < 9 or (13 < c < 32) or c > 126)
    return bad / len(b)


def detect_kind(path: str, head: bytes) -> str:
    if _tri is not None:
        return _tri.detect_file_kind(path, head)
    ext = os.path.splitext(path)[1].lower()
    if head[:4] in (b"\x7fELF", b"MZ"):
        return "binary"
    if ext in SCRIPT_EXT or head[:2] == b"#!":
        return "script"
    if ext in WEB_EXT:
        return "web"
    if ext in CONFIG_EXT:
        return "config"
    if head and (b"\x00" in head or nonprint_ratio(head) > 0.30):
        return "binary"
    return "text"


# ------------------------------------------------------------ 语言判定（结构引擎用）

# kind 到语言的细化：结构引擎（ast-grep / semgrep）需要的是语言而非 kind。
# 固件脚本常无扩展名，靠 shebang 兜底；仍判不出就返回 None → 回退正则并记录。
LANG_BY_EXT = {
    ".sh": "bash", ".bash": "bash", ".ash": "bash", ".ksh": "bash",
    ".pl": "perl", ".pm": "perl",
    ".py": "python", ".lua": "lua",
    ".js": "javascript", ".mjs": "javascript",
    ".php": "php", ".php3": "php", ".php4": "php", ".php5": "php", ".phtml": "php",
}

SHEBANG_LANG = [
    (re.compile(r"/(?:ba|a|da|k)?sh\b|\bbusybox\s+sh\b"), "bash"),
    (re.compile(r"\bpython[0-9.]*\b"), "python"),
    (re.compile(r"\bperl\b"), "perl"),
    (re.compile(r"\blua\b"), "lua"),
    (re.compile(r"\bphp\b"), "php"),
    (re.compile(r"\bnode(js)?\b"), "javascript"),
]


def detect_lang(path: str, head: bytes) -> Optional[str]:
    """细化到语言级；判不出返回 None（调用方回退正则并记录，不静默）。"""
    ext = os.path.splitext(path)[1].lower()
    if ext in LANG_BY_EXT:
        return LANG_BY_EXT[ext]
    if head[:5] == b"<?php":
        return "php"
    if head[:2] == b"#!":
        low = head.split(b"\n", 1)[0].decode("latin1", "replace").lower()
        for pat, lang in SHEBANG_LANG:
            if pat.search(low):
                return lang
    return None


# ------------------------------------------------------------ 结构引擎（二次过滤）

AST_GREP_LANG = {"bash": "bash", "php": "php", "python": "python",
                 "javascript": "javascript", "lua": "lua"}
SEMGREP_LANG = {"bash": "bash", "php": "php", "python": "python",
                "javascript": "javascript", "lua": "lua"}


def find_engine(name: str) -> Optional[str]:
    """解析引擎可执行：含路径分隔符时按显式路径，否则查 PATH。"""
    if not name:
        return None
    if os.sep in name or "/" in name or (os.altsep and os.altsep in name):
        return name if os.path.exists(name) else None
    return shutil.which(name)


def astgrep_match(binp: str, lang: str, pattern: str, path: str,
                  timeout: int) -> Optional[bool]:
    """True=结构命中；False=无命中（注释/字符串误报）；None=引擎不可用/解析失败。"""
    slang = AST_GREP_LANG.get(lang)
    if not slang:
        return None
    try:
        p = subprocess.run([binp, "run", "--pattern", pattern, "--lang", slang,
                            "--json=stream", path],
                           capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    if p.returncode != 0:
        return None
    return bool((p.stdout or "").strip())


def semgrep_match(binp: str, lang: str, pattern: str, path: str,
                  timeout: int) -> Optional[bool]:
    """同上；semgrep 退出码 0=无命中、1=有命中，其余视为错误。"""
    slang = SEMGREP_LANG.get(lang)
    if not slang:
        return None
    try:
        p = subprocess.run([binp, "-e", pattern, "--lang", slang, "--json",
                            "--quiet", "--metrics=off",
                            "--max-target-bytes", str(2 << 20), path],
                           capture_output=True, text=True, timeout=timeout)
    except Exception:
        return None
    if p.returncode not in (0, 1):
        return None
    try:
        d = json.loads(p.stdout or "{}")
    except Exception:
        return None
    return bool(d.get("results"))


def structural_match(engine: str, binp: str, lang: str, pattern: str, path: str,
                     timeout: int) -> Optional[bool]:
    if engine == "semgrep":
        return semgrep_match(binp, lang, pattern, path, timeout)
    return astgrep_match(binp, lang, pattern, path, timeout)


def _bump(stats: Dict[str, int], key: str, n: int = 1) -> None:
    """容错计数：stats 可为普通 dict（不必是 Counter）。"""
    stats[key] = stats.get(key, 0) + n


# ------------------------------------------------------------ 字符串提取（带偏移）
#
# 设计约束（对应改进计划 §6）：
# 1. 全文件分块读取，不再只读文件头。旧实现 f.read(8 << 20) 会在 8 MiB 处静默
#    截断，20 MB 的 CGI 二进制里后半段的危险字符串一个都扫不到，而且输出里看不出来。
# 2. 跨块边界的字符串必须完整保留：用 carry 缓冲把上一块末尾的连续可打印区带到
#    下一块开头，边界不会漏检。
# 3. 每次扫描都产出台账（bytes_total / bytes_scanned / scan_complete /
#    truncation_reason），让"没扫完"变成可见状态而不是默默发生。

DEFAULT_CHUNK = 4 << 20          # 4 MiB 读块
MAX_STRING_BYTES = 64 << 10      # 单条字符串保留上限，超出则重叠切分
STRING_OVERLAP = 512             # 切分时的重叠量，保证跨切点模式仍可命中


def strings_with_offsets(path: str, min_len: int,
                         chunk_size: int = DEFAULT_CHUNK,
                         max_bytes: Optional[int] = None
                         ) -> Tuple[List[Tuple[int, str]], Dict[str, Any]]:
    """分块流式提取可打印字符串。

    返回 (strings, info)：
      strings — [(绝对偏移, 字符串), ...]
      info    — {bytes_total, bytes_scanned, scan_complete,
                 truncation_reason, long_string_split}
    """
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % max(2, min_len))
    out: List[Tuple[int, str]] = []
    info: Dict[str, Any] = {
        "bytes_total": 0,
        "bytes_scanned": 0,
        "scan_complete": False,
        "truncation_reason": None,
        "long_string_split": 0,
    }

    try:
        total = os.path.getsize(path)
    except OSError:
        info["truncation_reason"] = "stat-failed"
        return out, info
    info["bytes_total"] = total

    limit = total if max_bytes is None else min(total, max_bytes)
    if max_bytes is not None and total > max_bytes:
        info["truncation_reason"] = "size-limit"

    carry = b""          # 上一块末尾未闭合的可打印区
    carry_off = 0        # 该区起始的绝对偏移
    pos = 0

    def flush(tail: bytes, off: int) -> None:
        if len(tail) >= max(2, min_len):
            out.append((off, tail.decode("latin1")))

    try:
        with open(path, "rb") as f:
            while pos < limit:
                chunk = f.read(min(chunk_size, limit - pos))
                if not chunk:
                    break
                buf = carry + chunk
                base = carry_off if carry else pos
                pos += len(chunk)
                info["bytes_scanned"] = pos

                # 末尾可能还有未闭合的可打印区（跨块），先切出来留到下一轮。
                # 注意不能用 pat 判尾部：不足 min_len 的短串不会命中正则，
                # 但它可能在下块长成完整危险函数名（如 "sys" + "tem("）。
                ts = len(buf)
                while ts > 0 and 0x20 <= buf[ts - 1] <= 0x7e:
                    ts -= 1
                body, tail = buf[:ts], buf[ts:]

                for m in pat.finditer(body):
                    out.append((base + m.start(), m.group().decode("latin1")))

                if tail and pos < limit:
                    carry, carry_off = tail, base + ts
                    # 超长可打印区（如压缩数据被误判）做重叠切分，控制内存
                    if len(carry) > MAX_STRING_BYTES:
                        cut = MAX_STRING_BYTES - STRING_OVERLAP
                        flush(carry[:cut], carry_off)
                        carry = carry[cut:]
                        carry_off += cut
                        info["long_string_split"] += 1
                else:
                    flush(tail, base + ts)
                    carry, carry_off = b"", 0
    except OSError:
        info["truncation_reason"] = "read-error"

    if carry:
        flush(carry, carry_off)

    named = (info["truncation_reason"] == "size-limit")
    info["scan_complete"] = (not named and pos >= total
                             and info["truncation_reason"] is None)
    if pos < total and info["truncation_reason"] is None:
        info["truncation_reason"] = "short-read"
    return out, info


def read_lines(path: str, max_lines: int = 400000
               ) -> Tuple[List[str], Dict[str, Any]]:
    """按行读取文本；返回 (lines, info)，info 里标记是否被行数上限截断。"""
    info: Dict[str, Any] = {"lines_total": 0, "truncated": False,
                            "truncation_reason": None}
    out: List[str] = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for i, line in enumerate(f):
                info["lines_total"] = i + 1
                if i >= max_lines:
                    info["truncated"] = True
                    info["truncation_reason"] = "line-limit"
                    break
                out.append(line.rstrip("\n").rstrip("\r"))
    except OSError:
        info["truncation_reason"] = "read-error"
        return [], info
    if info["truncated"] and info["lines_total"] > max_lines:
        info["lines_scanned"] = len(out)
    else:
        info["lines_scanned"] = len(out)
    return out, info


# ------------------------------------------------------------ 规则

def load_rules(path: Optional[str]) -> Dict[str, Any]:
    here = os.path.dirname(os.path.abspath(__file__))
    cand = path or os.path.join(here, "..", "assets", "sink-rules.json")
    with open(cand, encoding="utf-8") as f:
        return json.load(f)


def compile_rule(r: Dict[str, Any]) -> Dict[str, Any]:
    def comp(pats: Iterable[str], tag: str) -> List[Any]:
        out = []
        for p in pats:
            try:
                out.append(re.compile(p, re.I))
            except re.error:
                out.append(re.compile(re.escape(p), re.I))  # 编译失败按字面量
        return out
    structural: List[Dict[str, Any]] = []
    for v in (r.get("structural") or []):
        raw = v.get("pattern")
        pats = [raw] if isinstance(raw, str) else [p for p in (raw or []) if p]
        pats = [p for p in pats if p]
        if not pats:
            continue
        structural.append({"engine": str(v.get("engine", "ast-grep")).lower(),
                           "language": str(v.get("language", "")).lower(),
                           "patterns": pats})
    return {
        "id": r["id"], "priority": r["priority"], "category": r.get("category", ""),
        "title": r.get("title", ""), "applies_to": set(r.get("applies_to", ["binary", "text"])),
        "patterns": comp(r.get("patterns", []), "pat"),
        "anti": comp(r.get("anti", []), "anti"),
        "structural": structural,
        "guidance": r.get("guidance", ""),
    }


def in_skip_dir(rel: str, skip_dirs: List[str]) -> bool:
    parts = [p.lower() for p in rel.replace("\\", "/").split("/")]
    for sd in skip_dirs:
        sd_parts = sd.split("/")
        n = len(sd_parts)
        for i in range(len(parts) - n + 1):
            if parts[i:i + n] == sd_parts:
                return True
    return False


def is_stdlib(rel: str, whitelist: List[str]) -> bool:
    r = rel.replace("\\", "/")
    for w in whitelist:
        if w in r:
            return True
    return False


# ------------------------------------------------------------ 扫描

def scan_file(path: str, rel: str, rules: List[Dict[str, Any]],
              thresholds: Dict[str, Any], skip_dirs: List[str],
              whitelist: List[str], ctx: int,
              engines: Dict[str, Optional[str]],
              fallbacks: List[Dict[str, Any]],
              stats: Dict[str, int],
              enable_structural: bool = True,
              timeout: int = 30,
              chunk_size: int = DEFAULT_CHUNK,
              max_lines: int = 400000
              ) -> Tuple[List[Dict[str, Any]], Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return [], {"kind": "unknown", "bytes_total": 0, "bytes_scanned": 0,
                    "scan_complete": False, "truncation_reason": "read-error"}
    kind = detect_kind(rel, head)
    std = is_stdlib(rel, whitelist)
    min_len = int(thresholds.get("min_string_len", 4))
    max_hits = int(thresholds.get("max_hits_per_rule_per_file", 1))

    lines: Optional[List[str]] = None
    strs: Optional[List[Tuple[int, str]]] = None
    lang: Optional[str] = None
    record: Dict[str, Any] = {"kind": kind, "bytes_total": 0, "bytes_scanned": 0,
                              "scan_complete": True, "truncation_reason": None}
    if kind == "binary":
        strs, sinfo = strings_with_offsets(path, min_len, chunk_size)
        record.update({k: sinfo[k] for k in
                       ("bytes_total", "bytes_scanned", "scan_complete",
                        "truncation_reason")})
        record["kind"] = "binary"
        if sinfo.get("long_string_split"):
            record["long_string_split"] = sinfo["long_string_split"]
        if not strs:
            return [], record
    else:
        lines, linfo = read_lines(path, max_lines)
        record["kind"] = kind
        record["lines_total"] = linfo.get("lines_total", 0)
        record["lines_scanned"] = linfo.get("lines_scanned", 0)
        if linfo.get("truncated"):
            record["scan_complete"] = False
            record["truncation_reason"] = linfo.get("truncation_reason")
        if kind in ("script", "web", "text"):
            lang = detect_lang(path, head)

    results: List[Dict[str, Any]] = []
    for r in rules:
        if kind not in r["applies_to"]:
            continue
        hits: List[Dict[str, Any]] = []
        count = 0
        if kind == "binary":
            for i, (off, s) in enumerate(strs):
                if any(a.search(s) for a in r["anti"]):
                    continue
                if any(p.search(s) for p in r["patterns"]):
                    count += 1
                    if len(hits) < max_hits:
                        lo = max(0, i - ctx)
                        hi = min(len(strs), i + ctx + 1)
                        context = " | ".join(x[1] for x in strs[lo:hi])[:400]
                        hits.append({
                            "location": "0x%x" % off,
                            "match": s[:200],
                            "context": context,
                        })
        else:
            for i, line in enumerate(lines or []):
                if COMMENT_LINE.match(line) or IMPORT_LINE.match(line):
                    continue
                if not line.strip():
                    continue
                if any(a.search(line) for a in r["anti"]):
                    continue
                if any(p.search(line) for p in r["patterns"]):
                    count += 1
                    if len(hits) < max_hits:
                        lo = max(0, i - ctx)
                        hi = min(len(lines or []), i + ctx + 1)
                        context = "\n".join(
                            "%d: %s" % (n + 1, (lines or [])[n][:200]) for n in range(lo, hi))[:600]
                        hits.append({
                            "location": "%d" % (i + 1),
                            "match": line.strip()[:200],
                            "context": context,
                        })
        # ---- 结构级二次过滤 ----
        # 只对『正则已命中 + 规则有 structural + 语言可判 + 引擎可用』的脚本/web 文件生效。
        # 语义：结构确认才保留（标注 engine），结构否定则判为注释/字符串误报丢弃；
        # 引擎缺失或解析失败一律回退正则，并在 fallbacks 里显式记录，绝不静默。
        hit_engine = "regex"
        structural = r.get("structural") or []
        if hits and structural and enable_structural and kind in ("script", "web", "text"):
            variant = next((v for v in structural if v["language"] == lang), None)
            if variant is None:
                _bump(stats, "regex_fallback")
                fallbacks.append({"rule_id": r["id"], "file": rel,
                                  "engine": structural[0]["engine"],
                                  "reason": "lang-undetected" if lang is None else "lang-unsupported"})
            else:
                eng = variant["engine"]
                binp = engines.get(eng)
                if not binp:
                    _bump(stats, "regex_fallback")
                    fallbacks.append({"rule_id": r["id"], "file": rel, "engine": eng,
                                      "reason": "engine-missing"})
                else:
                    verdict = False
                    errored = False
                    for pat in variant["patterns"]:
                        v = structural_match(eng, binp, lang, pat, path, timeout)
                        if v is None:
                            errored = True
                            break
                        if v:
                            verdict = True
                            break
                    if errored:
                        _bump(stats, "regex_fallback")
                        fallbacks.append({"rule_id": r["id"], "file": rel, "engine": eng,
                                          "reason": "engine-error"})
                    elif verdict:
                        hit_engine = eng
                        _bump(stats, "structural_confirmed")
                    else:
                        hits = []
                        count = 0
                        _bump(stats, "structural_filtered")
        for h in hits:
            results.append({
                "rule_id": r["id"],
                "priority": r["priority"],
                "category": r["category"],
                "title": r["title"],
                "file": rel,
                "kind": "binary-string" if kind == "binary" else "source-line",
                "location": h["location"],
                "match": h["match"],
                "context": h["context"],
                "occurrences": count,
                "engine": hit_engine,
                "stdlib_component": std,
                "guidance": r["guidance"],
            })
    return results, record


def main() -> int:
    ap = argparse.ArgumentParser(description="Layer 1 危险模式扫描")
    ap.add_argument("target", help="rootfs 目录或单个文件")
    ap.add_argument("--rules", help="sink-rules.json 路径")
    ap.add_argument("--json", dest="json_out", help="输出 JSON 路径")
    ap.add_argument("--md", dest="md_out", help="输出 Markdown 表")
    ap.add_argument("--only-priority", help="只保留指定优先级，如 P0,P1")
    ap.add_argument("--only-rule", help="只跑指定 rule id（逗号分隔）")
    ap.add_argument("--context", type=int, default=-1, help="上下文行数，默认取规则文件")
    ap.add_argument("--include-stdlib", action="store_true",
                    help="包含 libc/busybox 等标准组件（默认包含但会标记）")
    ap.add_argument("--exclude", help="额外排除路径正则")
    ap.add_argument("--max-file-mb", type=float, default=96.0,
                    help="单文件上限 MB（超限整文件跳过，原因记入 scan_integrity）")
    ap.add_argument("--read-chunk-mb", type=float, default=4.0,
                    help="二进制分块读取块大小 MB（默认 4）")
    ap.add_argument("--max-lines", type=int, default=400000,
                    help="文本文件读取行数上限（超限标记 scan_complete=false）")
    ap.add_argument("--ast-grep-bin", default="ast-grep",
                    help="ast-grep 可执行名/路径（结构级二次过滤，默认取 PATH 上的 ast-grep）")
    ap.add_argument("--semgrep-bin", default="semgrep",
                    help="semgrep 可执行名/路径（另一种可选结构引擎）")
    ap.add_argument("--no-structural", action="store_true",
                    help="禁用结构级二次过滤；回退情况仍会写进 engine_status")
    ap.add_argument("--structural-timeout", type=int, default=30,
                    help="单次结构引擎调用超时（秒）")
    ap.add_argument("--strict", action="store_true",
                    help="扫描不完整（verdict=partial/failed）时以退出码 3 结束；"
                         "默认只告警、仍返回 0")
    ap.add_argument("--pretty", action="store_true")
    args = ap.parse_args()

    rj = load_rules(args.rules)
    thresholds = rj.get("thresholds", {})
    ctx = args.context if args.context >= 0 else int(thresholds.get("context_lines", 2))
    skip_dirs = rj.get("skip_dirs", [])
    whitelist = rj.get("stdlib_whitelist", [])
    rules = [compile_rule(r) for r in rj["rules"]]
    if args.only_rule:
        keep = {x.strip() for x in args.only_rule.split(",")}
        rules = [r for r in rules if r["id"] in keep]

    max_bytes = int(args.max_file_mb * 1024 * 1024)
    chunk_size = max(64 << 10, int(args.read_chunk_mb * 1024 * 1024))
    excl = re.compile(args.exclude, re.I) if args.exclude else None

    engines: Dict[str, Optional[str]] = {
        "ast-grep": find_engine(args.ast_grep_bin),
        "semgrep": find_engine(args.semgrep_bin),
    }
    enable_structural = not args.no_structural
    fallbacks: List[Dict[str, Any]] = []
    stats: Dict[str, int] = collections.Counter()
    rules_with_structural = sum(1 for r in rules if r["structural"])

    findings: List[Dict[str, Any]] = []
    skipped_files: List[Dict[str, Any]] = []
    partial_files: List[Dict[str, Any]] = []
    scanned = 0

    def skip(rel: str, reason: str, extra: Optional[Dict[str, Any]] = None) -> None:
        rec: Dict[str, Any] = {"file": rel, "reason": reason}
        if extra:
            rec.update(extra)
        skipped_files.append(rec)

    def handle(path: str, rel: str) -> None:
        nonlocal scanned
        # 四类跳过原因分开记，不再混成一个计数器：
        # 「跳过目录」是设计如此，「超大文件」是能力边界，「stat 失败」是异常，
        # 「正则排除」是调用方选择——它们的风险等级完全不同。
        if in_skip_dir(rel, skip_dirs):
            skip(rel, "skip-dir")
            return
        if excl and excl.search(rel):
            skip(rel, "excluded")
            return
        try:
            size = os.path.getsize(path)
        except OSError:
            skip(rel, "stat-failed")
            return
        if size > max_bytes:
            skip(rel, "too-large",
                 {"bytes_total": size, "limit_bytes": max_bytes})
            return
        scanned += 1
        hits, rec = scan_file(path, rel, rules, thresholds, skip_dirs,
                              whitelist, ctx, engines, fallbacks, stats,
                              enable_structural, args.structural_timeout,
                              chunk_size, args.max_lines)
        findings.extend(hits)
        if not rec.get("scan_complete", True):
            partial_files.append({
                "file": rel,
                "kind": rec.get("kind"),
                "bytes_total": rec.get("bytes_total", 0),
                "bytes_scanned": rec.get("bytes_scanned", 0),
                "lines_total": rec.get("lines_total", 0),
                "lines_scanned": rec.get("lines_scanned", 0),
                "truncation_reason": rec.get("truncation_reason"),
            })

    if os.path.isfile(args.target):
        handle(args.target, os.path.basename(args.target))
    else:
        root = os.path.abspath(args.target)
        for dirpath, dirnames, filenames in os.walk(root):
            for fn in filenames:
                full = os.path.join(dirpath, fn)
                if os.path.islink(full):
                    continue
                handle(full, os.path.relpath(full, root).replace("\\", "/"))

    if args.only_priority:
        keep = {x.strip().upper() for x in args.only_priority.split(",")}
        findings = [f for f in findings if f["priority"] in keep]

    findings.sort(key=lambda f: (PRIORITY_ORDER.get(f["priority"], 9), f["file"], f["rule_id"]))
    summary = collections.Counter(f["priority"] for f in findings)
    by_cat = collections.Counter(f["category"] for f in findings)

    # ── 扫描完整性判定（schema layer1-sinks/1.3）──────────────────────────────
    # complete / scoped / partial / failed 四态与 coverage_gate.py 的判定一一对应：
    # 只有「什么都没跳过」才是 complete；仅跳过规则声明的目录/排除规则是 scoped；
    # 有文件被截断或静默跳过是 partial；有读取/stat 失败是 failed。
    reason_counts = collections.Counter(s["reason"] for s in skipped_files)
    scope = {"skip_dirs": list(skip_dirs),
             "excluded": [args.exclude] if args.exclude else []}
    material = {r: n for r, n in reason_counts.items()
                if r not in ("skip-dir", "excluded")}
    if any(r in ("stat-failed", "read-error") for r in material):
        verdict = "failed"
    elif material or partial_files:
        verdict = "partial"
    elif reason_counts:
        verdict = "scoped"
    else:
        verdict = "complete"

    gaps: List[Dict[str, Any]] = [
        {"file": p["file"], "reason": "partial",
         "detail": str(p.get("truncation_reason") or "scan_complete=false")}
        for p in partial_files
    ]
    gaps += [
        {"file": s["file"], "reason": s["reason"],
         "detail": (f"超过上限 {s.get('limit_bytes', 0)} 字节"
                    if s["reason"] == "too-large" else s["reason"])}
        for s in skipped_files if s["reason"] in material
    ]

    # 结构引擎状态：success / partial / skipped / failed（与门禁同一套语义）
    if not enable_structural:
        engine_verdict = "skipped"
    elif rules_with_structural == 0:
        engine_verdict = "success"      # 规则集不需要结构确认
    elif not any(engines.values()):
        engine_verdict = "skipped"      # 一个引擎都没有 → 全部回退正则
    elif any(f.get("reason") == "engine-error" for f in fallbacks):
        engine_verdict = "failed"
    elif stats.get("regex_fallback", 0) > 0:
        engine_verdict = "partial"
    else:
        engine_verdict = "success"

    out = {
        "tool": "sink_scan.py",
        "schema": "layer1-sinks/1.3",
        "version": "1.3",
        "target": os.path.abspath(args.target),
        "rules_source": args.rules or "assets/sink-rules.json",
        "files_scanned": scanned,
        "files_skipped": len(skipped_files),
        "summary_by_priority": dict(summary),
        "summary_by_category": dict(by_cat),
        "layer1_note": ("Layer 1 只能发现『危险形态的存在』；认证绕过、无验签 OTA、越权等"
                        "『安全控制的缺失』必须由 Layer 2 Track B 发现。binary-string 仅表示"
                        "字符串存在，代码层结论必须由 Layer 3 反汇编确认。"),
        # 扫描完整性台账：让「没扫完 / 整文件没扫」成为可见状态，
        # 而不是用 files_scanned 一个数字掩盖掉。
        "scan_integrity": {
            "schema": "scan-integrity/1.1",
            # complete 只在「零跳过、零截断」时为真；门禁另用 verdict 区分
            # 「范围外排除」(scoped) 与「真的没扫完」(partial/failed)。
            "complete": (not skipped_files and not partial_files),
            "verdict": verdict,
            "scope": scope,
            "gaps": gaps[:1000],
            "files_scanned": scanned,
            "files_skipped": len(skipped_files),
            "files_partial": len(partial_files),
            "limits": {
                "max_file_mb": args.max_file_mb,
                "read_chunk_mb": round(chunk_size / (1024 * 1024), 3),
                "max_lines": args.max_lines,
            },
            "skip_reason_counts": dict(collections.Counter(
                s["reason"] for s in skipped_files)),
            "skipped_files": skipped_files[:1000],
            "partial_files": partial_files[:1000],
            "note": ("files_skipped 含 skip-dir / excluded / too-large / stat-failed 四类；"
                     "partial_files 为读到了但被 size-limit 或 line-limit 截断的文件。"
                     "verdict: complete=未跳过未截断；scoped=仅跳过规则声明的目录/正则；"
                     "partial=有截断或被静默跳过；failed=有 stat/读取失败。"
                     "门禁不得把 incomplete 的扫描结果当作完整覆盖。"),
        },
        "engine_status": {
            "structural_enabled": enable_structural,
            "verdict": engine_verdict,
            "engines": dict(engines),
            "rules_with_structural": rules_with_structural,
            "structural_confirmed": stats.get("structural_confirmed", 0),
            "structural_filtered": stats.get("structural_filtered", 0),
            "regex_fallback": stats.get("regex_fallback", 0),
            "note": ("结构引擎仅作二次过滤：正则初筛命中后才做结构确认，结构否定即判为"
                     "注释/字符串误报丢弃。引擎缺失或解析失败回退正则并记录在 fallbacks。"),
            "fallbacks": fallbacks[:200],
        },
        "findings": findings,
    }

    text = json.dumps(out, ensure_ascii=False, indent=2 if args.pretty else None)
    if args.json_out:
        d = os.path.dirname(os.path.abspath(args.json_out))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
        print(f"[ok] JSON → {args.json_out}")
    else:
        print(text)

    if args.md_out:
        lines = ["# Layer 1 扫描结果", "",
                 f"扫描完整性 **{verdict}**：扫描文件 {scanned} 个，"
                 f"跳过 {len(skipped_files)} 个，部分扫描 {len(partial_files)} 个。",
                 ""]
        if skipped_files or partial_files:
            lines += ["## 扫描完整性提示", "",
                      "本次扫描**未覆盖全部文件**，以下情况必须写入报告，"
                      "不得声称「已完整扫描」：", ""]
            for r, n in sorted(collections.Counter(
                    s["reason"] for s in skipped_files).items()):
                lines.append(f"- 跳过 `{r}`：{n} 个文件")
            for p in partial_files[:50]:
                lines.append(f"- 部分扫描 `{p['file']}`（{p['truncation_reason']}，"
                             f"{p['bytes_scanned']}/{p['bytes_total']} 字节）")
            lines.append("")
        lines += ["| 优先级 | 数量 |", "|---|---|"]
        for p in ("P0", "P1", "P2", "P3"):
            lines.append(f"| {p} | {summary.get(p, 0)} |")
        lines += ["", "| 优先级 | 规则 | 文件 | 位置 | 命中 | 次数 |",
                  "|---|---|---|---|---|---|"]
        for f in findings[:2000]:
            lines.append("| %s | %s | `%s` | %s | `%s` | %d |" % (
                f["priority"], f["rule_id"], f["file"], f["location"],
                f["match"].replace("|", "\\|")[:80], f["occurrences"]))
        with open(args.md_out, "w", encoding="utf-8", newline="\n") as fh:
            fh.write("\n".join(lines) + "\n")
        print(f"[ok] Markdown → {args.md_out}")

    print(f"[summary] P0={summary.get('P0',0)} P1={summary.get('P1',0)} "
          f"P2={summary.get('P2',0)} P3={summary.get('P3',0)}  (scanned={scanned})")
    print(f"[integrity] verdict={verdict}，缺口 {len(gaps)} 个；"
          f"结构引擎={engine_verdict}", file=sys.stderr)
    if verdict in ("partial", "failed"):
        print(f"[warn] 扫描不完整：跳过 {len(skipped_files)} 个、部分扫描 "
              f"{len(partial_files)} 个（详见 scan_integrity）", file=sys.stderr)
        if args.strict:
            print("[error] --strict：扫描不完整，退出码 3（不得当作完整覆盖）",
                  file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    sys.exit(main())
