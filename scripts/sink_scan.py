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

def strings_with_offsets(path: str, min_len: int, max_read: int = 8 << 20
                         ) -> List[Tuple[int, str]]:
    try:
        with open(path, "rb") as f:
            data = f.read(max_read)
    except OSError:
        return []
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % max(2, min_len))
    return [(m.start(), m.group().decode("latin1")) for m in pat.finditer(data)]


def read_lines(path: str, max_lines: int = 400000) -> List[str]:
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            out = []
            for i, line in enumerate(f):
                if i >= max_lines:
                    break
                out.append(line.rstrip("\n").rstrip("\r"))
            return out
    except OSError:
        return []


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
              timeout: int = 30) -> List[Dict[str, Any]]:
    try:
        with open(path, "rb") as f:
            head = f.read(64)
    except OSError:
        return []
    kind = detect_kind(rel, head)
    std = is_stdlib(rel, whitelist)
    min_len = int(thresholds.get("min_string_len", 4))
    max_hits = int(thresholds.get("max_hits_per_rule_per_file", 1))

    lines: Optional[List[str]] = None
    strs: Optional[List[Tuple[int, str]]] = None
    lang: Optional[str] = None
    if kind == "binary":
        strs = strings_with_offsets(path, min_len)
        if not strs:
            return []
    else:
        lines = read_lines(path)
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
    return results


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
    ap.add_argument("--max-file-mb", type=float, default=96.0, help="单文件上限 MB")
    ap.add_argument("--ast-grep-bin", default="ast-grep",
                    help="ast-grep 可执行名/路径（结构级二次过滤，默认取 PATH 上的 ast-grep）")
    ap.add_argument("--semgrep-bin", default="semgrep",
                    help="semgrep 可执行名/路径（另一种可选结构引擎）")
    ap.add_argument("--no-structural", action="store_true",
                    help="禁用结构级二次过滤；回退情况仍会写进 engine_status")
    ap.add_argument("--structural-timeout", type=int, default=30,
                    help="单次结构引擎调用超时（秒）")
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
    scanned = skipped = 0

    def handle(path: str, rel: str) -> None:
        nonlocal scanned, skipped
        if in_skip_dir(rel, skip_dirs):
            skipped += 1
            return
        if excl and excl.search(rel):
            skipped += 1
            return
        try:
            if os.path.getsize(path) > max_bytes:
                skipped += 1
                return
        except OSError:
            skipped += 1
            return
        scanned += 1
        findings.extend(scan_file(path, rel, rules, thresholds, skip_dirs,
                                  whitelist, ctx, engines, fallbacks, stats,
                                  enable_structural, args.structural_timeout))

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

    out = {
        "tool": "sink_scan.py",
        "version": "1.1",
        "target": os.path.abspath(args.target),
        "rules_source": args.rules or "assets/sink-rules.json",
        "files_scanned": scanned,
        "files_skipped": skipped,
        "summary_by_priority": dict(summary),
        "summary_by_category": dict(by_cat),
        "layer1_note": ("Layer 1 只能发现『危险形态的存在』；认证绕过、无验签 OTA、越权等"
                        "『安全控制的缺失』必须由 Layer 2 Track B 发现。binary-string 仅表示"
                        "字符串存在，代码层结论必须由 Layer 3 反汇编确认。"),
        "engine_status": {
            "structural_enabled": enable_structural,
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
                 f"扫描文件 {scanned} 个，跳过 {skipped} 个。",
                 "",
                 "| 优先级 | 数量 |", "|---|---|"]
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
    return 0


if __name__ == "__main__":
    sys.exit(main())
