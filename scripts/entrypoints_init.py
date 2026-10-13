#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
entrypoints_init.py — 生成入口枚举骨架 entrypoints.json（Phase 3/5，配合门禁 G4）

背景：`coverage_gate.py` 的门禁是「文件级」的——`usr/sbin/httpd` 有结论就 PASS，
哪怕 2923 个函数只读了 5 个、167 个 CGI handler 一个没读。G4 把风险单位从
「文件」提升到「入口」，要求 T1 大服务型二进制逐个枚举入口。

本脚本只做**骨架**：从 02-tiering.json 找出适用文件（T1 且 text_kb 超阈值、
bin/sbin/usr-* 下的 ELF、排除 .so），逐条落 `status: "todo"`。
真正的入口列表（派发表 / SOAP action / socket handler）由审计者补充，或由
反编译器脚本回填（见 `_ida-httpd-handlers.json` 的用法）。

schema: entrypoints/v1
{
  "schema": "entrypoints/v1",
  "target": "...",
  "files": [
    {"file": "usr/sbin/httpd",
     "handler_table_count": 167,              # 权威派发表条目数（必填，除非声明 none）
     "enumerated_from": "IDA 0x186e28..0x187370 六个连续块",
     "handlers": [{"name":"ramain.cgi","addr":"0x4ad44","conclusion":"F-012"}],
     "entrypoints": "none", "reason": "...",  # 声明无入口时用，二者择一
     "waiver": {"reason": "..."}              # 文件级豁免（记录在案，不静默）
    }
  ]
}

用法：
  uv run scripts/entrypoints_init.py --tiering fw-audit/<t>/02-tiering.json \\
      --out fw-audit/<t>/entrypoints.json [--merge 已有文件] [--text-kb-threshold 200]
"""
from __future__ import annotations

import argparse
import json
import os
import sys

SERVICE_EXEC_DIRS = ("bin/", "sbin/", "usr/bin/", "usr/sbin/")


def norm(p: str) -> str:
    p = str(p).strip().replace("\\", "/")
    while p.startswith("./"):
        p = p[2:]
    return p.strip()


def load_items(tiering_path: str) -> dict:
    tj = json.load(open(tiering_path, encoding="utf-8"))
    t = tj.get("tiering") or tj.get("rootfs_analysis", {}).get("tiering") or {}
    items = {}
    for sh in (t.get("shards") or []):
        for it in (sh.get("items") or []):
            f = norm(it.get("file", ""))
            if f:
                items[f] = {"tier": str(it.get("tier", "")),
                            "text_kb": float(it.get("text_kb") or 0)}
    return items


def qualifying(items: dict, threshold: float) -> list:
    out = []
    for f, m in items.items():
        if m["tier"] != "T1" or m["text_kb"] <= threshold:
            continue
        if f.endswith(".so") or ".so." in f:
            continue
        if not f.startswith(SERVICE_EXEC_DIRS):
            continue
        out.append(f)
    return sorted(out)


def main() -> int:
    ap = argparse.ArgumentParser(description="生成 entrypoints.json 骨架")
    ap.add_argument("--tiering", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--merge", help="已有 entrypoints.json，保留其条目（手填数据不丢）")
    ap.add_argument("--target", default="")
    ap.add_argument("--text-kb-threshold", type=float, default=200.0)
    args = ap.parse_args()

    if not os.path.isfile(args.tiering):
        print(f"[error] tiering 不存在: {args.tiering}", file=sys.stderr)
        return 2

    items = load_items(args.tiering)
    files = qualifying(items, args.text_kb_threshold)

    existing = {}
    if args.merge and os.path.isfile(args.merge):
        try:
            for rec in (json.load(open(args.merge, encoding="utf-8")).get("files") or []):
                existing[norm(rec.get("file", ""))] = rec
        except Exception as e:  # noqa
            print(f"[warn] merge 失败，忽略: {e}", file=sys.stderr)

    out_files = []
    for f in files:
        if f in existing:
            out_files.append(existing[f])
        else:
            out_files.append({
                "file": f, "tier": "T1", "text_kb": items[f]["text_kb"],
                "status": "todo",
                "reason": "待枚举入口（派发表 / SOAP action / socket handler / CLI 子命令）",
            })
    # 保留 existing 里不在适用集内的条目
    for f, rec in existing.items():
        if f not in files:
            out_files.append(rec)

    payload = {
        "schema": "entrypoints/v1",
        "target": args.target or os.path.basename(os.path.dirname(os.path.abspath(args.out))),
        "generator": "entrypoints_init.py",
        "text_kb_threshold": args.text_kb_threshold,
        "files": out_files,
    }
    d = os.path.dirname(os.path.abspath(args.out))
    if d:
        os.makedirs(d, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(payload, fh, ensure_ascii=False, indent=2)
    todo = sum(1 for r in out_files if r.get("status") == "todo")
    print(f"[ok] {args.out}  适用文件 {len(files)} 个，其中待枚举 {todo} 个")
    for r in out_files:
        mark = "TODO" if r.get("status") == "todo" else (
            f"{len(r.get('handlers') or [])} 入口" if r.get("handlers")
            else r.get("entrypoints", "done"))
        print(f"  {mark:>10}  {r['file']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
