#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""exec_paths.py — 执行路径清单（ROADMAP M2）

为什么需要它
------------
M2 要求「所有执行路径统一经过 Sandbox Runner」，但仓库里必然还有几类合法的
宿主机子进程：静态解析器要读不可信字节、测试要起子进程、基准工具要调 git。
把「已经容器化」和「仍是宿主机执行」混在一起，安全声明就不可审计。

本工具用 AST 扫描 scripts/*.py 的 subprocess / os.system / os.popen 调用，
输出机器可读清单并给每条路径分类；未知文件的执行路径会让清单失败（退出 1），
避免新脚本悄悄绕过审查。

用法
----
    python scripts/exec_paths.py
    python scripts/exec_paths.py --json exec-paths.json
    python scripts/exec_paths.py --root scripts --quiet

退出码：0 清单完整且分类已知；1 存在未分类执行路径；2 用法/IO 错误。
纯标准库。
"""
from __future__ import annotations

import argparse
import ast
import json
import os
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

VERSION = "1.0"
SCHEMA = "exec-paths/1.0"
TOOL = "exec_paths.py"

#: 已知脚本的分类。新脚本没有登记时，它的执行路径会进入 unclassified 并让
#: 清单失败；这是有意的摩擦，不是配置错误。
KNOWN = {
    "sandbox_run.py": {
        "classification": "sandbox-boundary",
        "input_trust": "untrusted-firmware",
        "note": "不可信固件的唯一执行边界；命令由 build_container_argv 组装并经容器运行",
    },
    "sink_scan.py": {
        "classification": "host-static-analyzer",
        "input_trust": "untrusted-bytes",
        "note": "在宿主机调用 ast-grep / semgrep 读取固件字节；只解析不执行，"
                "但仍属未容器化的残留风险",
    },
    "emu_run.py": {
        "classification": "sandbox-client",
        "input_trust": "untrusted-firmware",
        "note": "只通过 sandbox_run.py 启动 QEMU；自身不组装容器参数、不回退宿主机",
    },
    "bench_eval.py": {
        "classification": "trusted-metadata",
        "input_trust": "trusted-local",
        "note": "调用 git 读取本地提交元数据，不接触固件内容",
    },
    "selftest.py": {
        "classification": "test-harness",
        "input_trust": "test-only",
        "note": "测试框架自身的子进程；不用于生产审计",
    },
    "exec_paths.py": {
        "classification": "inventory",
        "input_trust": "none",
        "note": "本清单工具自身；不执行外部命令",
    },
}
SUBPROCESS_APIS = {"run", "Popen", "call", "check_call", "check_output",
                   "getoutput", "getstatusoutput"}
OS_APIS = {"system", "popen", "spawnl", "spawnle", "spawnlp", "spawnlpe",
           "spawnv", "spawnve", "spawnvp", "spawnvpe", "execv", "execve",
           "execvp", "execvpe"}
MAX_CALL = 240


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _force_utf8_io() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError, OSError):
            pass


def _scope_map(tree: ast.AST) -> Dict[ast.AST, str]:
    """给每个节点找最近的函数/类名，用于报告「在哪个函数里执行」。"""
    parent: Dict[ast.AST, ast.AST] = {}
    for node in ast.walk(tree):
        for child in ast.iter_child_nodes(node):
            parent[child] = node
    scopes: Dict[ast.AST, str] = {}
    for node in ast.walk(tree):
        cur: Optional[ast.AST] = node
        name = ""
        while cur is not None:
            if isinstance(cur, (ast.FunctionDef, ast.AsyncFunctionDef)):
                name = cur.name
                break
            if isinstance(cur, ast.ClassDef):
                name = cur.name
                break
            cur = parent.get(cur)
        if name:
            scopes[node] = name
    return scopes


def _call_name(node: ast.Call, subprocess_names: set, os_names: set) -> Optional[str]:
    func = node.func
    if isinstance(func, ast.Attribute):
        owner = func.value
        if isinstance(owner, ast.Name) and owner.id in subprocess_names:
            if func.attr in SUBPROCESS_APIS:
                return "subprocess." + func.attr
        if isinstance(owner, ast.Name) and owner.id in os_names:
            if func.attr in OS_APIS:
                return "os." + func.attr
    return None


def scan_file(path: str, rel: str) -> List[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            source = fh.read()
    except OSError as exc:
        return [{"file": rel, "line": 0, "api": "read-error",
                 "error": str(exc), "classification": "unclassified"}]
    try:
        tree = ast.parse(source, filename=path)
    except SyntaxError as exc:
        return [{"file": rel, "line": exc.lineno or 0, "api": "parse-error",
                 "error": str(exc), "classification": "unclassified"}]

    subprocess_names = {"subprocess"}
    os_names = {"os"}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name == "subprocess":
                    subprocess_names.add(alias.asname or alias.name)
                elif alias.name == "os":
                    os_names.add(alias.asname or alias.name)
        elif isinstance(node, ast.ImportFrom):
            if node.module == "subprocess":
                subprocess_names.update(alias.asname or alias.name
                                        for alias in node.names)
            elif node.module == "os":
                os_names.update(alias.asname or alias.name
                                for alias in node.names)

    scopes = _scope_map(tree)
    rows: List[Dict[str, Any]] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        api = _call_name(node, subprocess_names, os_names)
        if not api:
            continue
        try:
            snippet = ast.get_source_segment(source, node) or ""
        except Exception:
            snippet = ""
        snippet = " ".join(snippet.split())[:MAX_CALL]
        rows.append({
            "file": rel,
            "line": getattr(node, "lineno", 0),
            "api": api,
            "scope": scopes.get(node, "<module>"),
            "call": snippet,
            "classification": "unclassified",
        })
    return rows


def build_inventory(root: str) -> Dict[str, Any]:
    root = os.path.abspath(root)
    if not os.path.isdir(root):
        return {"ok": False, "error": "目录不存在：%s" % root,
                "schema": SCHEMA, "paths": [], "unclassified": []}

    paths: List[Dict[str, Any]] = []
    files = sorted(f for f in os.listdir(root)
                   if f.endswith(".py") and os.path.isfile(os.path.join(root, f)))
    for name in files:
        rows = scan_file(os.path.join(root, name), name)
        meta = KNOWN.get(name)
        for row in rows:
            if meta:
                row.update(meta)
            else:
                row["classification"] = "unclassified"
                row["input_trust"] = "unknown"
                row["note"] = "未登记的执行路径；请先审查再登记到 exec_paths.KNOWN"
            paths.append(row)

    unclassified = [p for p in paths if p.get("classification") == "unclassified"]
    counts: Dict[str, int] = {}
    for row in paths:
        key = str(row.get("classification"))
        counts[key] = counts.get(key, 0) + 1

    return {
        "schema": SCHEMA,
        "tool": TOOL,
        "version": VERSION,
        "generated_at": utc_now(),
        "root": root,
        "files_scanned": len(files),
        "total_paths": len(paths),
        "counts": counts,
        "ok": not unclassified,
        "paths": paths,
        "unclassified": unclassified,
    }


def render_text(doc: Dict[str, Any]) -> str:
    lines = ["执行路径清单：%s" % doc.get("root"),
             "共 %s 个文件 / %s 条子进程调用" % (doc.get("files_scanned"),
                                                doc.get("total_paths"))]
    for name, count in sorted((doc.get("counts") or {}).items()):
        lines.append("  %-24s %s" % (name, count))
    for row in doc.get("paths") or []:
        lines.append("  %s:%s  %-16s %s  [%s]" % (
            row.get("file"), row.get("line"), row.get("api"),
            (row.get("scope") or "")[:28], row.get("classification")))
    if doc.get("unclassified"):
        lines.append("存在未分类执行路径：")
        for row in doc["unclassified"]:
            lines.append("  %s:%s %s" % (row.get("file"), row.get("line"),
                                         row.get("call") or row.get("error")))
    return "\n".join(lines)


def main(argv=None) -> int:
    _force_utf8_io()
    ap = argparse.ArgumentParser(description="扫描并分类 scripts/*.py 的子进程执行路径")
    ap.add_argument("--root", default=os.path.dirname(os.path.abspath(__file__)),
                    help="待扫描目录（默认本脚本所在目录）")
    ap.add_argument("--json", dest="json_out", help="输出 JSON 路径")
    ap.add_argument("--quiet", action="store_true", help="不打印人类可读摘要")
    args = ap.parse_args(argv)

    doc = build_inventory(args.root)
    if not args.quiet:
        print(render_text(doc))
    if args.json_out:
        try:
            parent = os.path.dirname(os.path.abspath(args.json_out))
            if parent:
                os.makedirs(parent, exist_ok=True)
            with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(doc, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
        except OSError as exc:
            print("[error] 写 JSON 失败：%s" % exc, file=sys.stderr)
            return 2
    if doc.get("error"):
        return 2
    return 0 if doc.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
