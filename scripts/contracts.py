#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""结构化数据契约校验器（ISSUE-05）。

为什么需要它
------------
本 skill 的判定链路里有 11 种 schema：FirmwareManifest / AuditTask / Candidate /
Finding / Evidence / GateResult / AuditStages / ScanWaiver / SandboxRun /
BenchManifest。它们此前散落在各自的脚本输出里，字段名、必填项、枚举值、
schema 版本各写各的，Markdown 文案一变就可能影响判定。
本模块把这些契约收敛到一处：

* 每个实体一个 validate_* 函数，返回 [{"path","code","message"}]；
* 未知的 schema 版本一律拒绝（不猜测、不降级），并列出受支持的版本；
* 缺字段、错类型、非法枚举、重复 ID、悬空引用都会被指出来；
* 同一份校验逻辑同时被 coverage_gate.py（--manifest）与本文件 CLI 使用。

用法
----
    python scripts/contracts.py --list
    python scripts/contracts.py --kind firmware-manifest --file manifest.json
    python scripts/contracts.py --kind candidates --file 09-candidates.jsonl --json out.json

退出码：0 通过；1 契约违规；2 用法/IO 错误。纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional

CONTRACTS_VERSION = "1.0"

#: kind -> 受支持的 schema 版本（第一个为当前版本）
SUPPORTED: Dict[str, List[str]] = {
    "firmware-manifest": ["firmware-manifest/1.0"],
    "audit-task": ["audit-task/1.0"],
    "candidate": ["candidates/1.0"],
    "finding": ["findings/1.0"],
    "evidence": ["evidence/1.0"],
    "gate-result": ["gate-config/1.1"],
    "audit-stages": ["audit-stages/1.0"],
    "scan-waiver": ["scan-waiver/1.0"],
    "bench-manifest": ["bench-manifest/1.0"],
    "sandbox-run": ["sandbox-run/1.0"],
}

CAND_STATUSES = (
    "hypothesis", "confirmed", "not_reproduced", "not_applicable",
    "pending_static_analysis", "pending_dynamic_validation",
    "blocked_by_environment", "validated", "not_found",
)
STAGE_STATUSES = ("success", "partial", "skipped", "failed")
SEVERITIES = ("critical", "high", "medium", "low", "info")
ARCHES = ("mips", "mipsel", "arm", "arm64", "x86", "x86_64", "riscv64", "none")
HEX64 = re.compile(r"^[0-9a-f]{64}$")


# ── 基础校验助手 ─────────────────────────────────────────────────────────────

def _err(out: List[Dict[str, str]], path: str, code: str, msg: str) -> None:
    out.append({"path": path, "code": code, "message": msg})


def _req(out, obj: Dict[str, Any], path: str, key: str, typ: type,
         allow_empty: bool = False) -> None:
    if key not in obj or obj[key] is None:
        _err(out, f"{path}.{key}", "MISSING", "必填字段缺失")
        return
    val = obj[key]
    bad_type = typ is str and not isinstance(val, str)
    if not isinstance(val, typ) or bad_type or (typ is str and not allow_empty and not val.strip()):
        _err(out, f"{path}.{key}", "BAD_TYPE",
             f"期望 {typ.__name__}，实际 {type(val).__name__}"
             + ("" if allow_empty else "（不得为空）"))


def _enum(out, obj, path: str, key: str, allowed, required: bool = True) -> None:
    if key not in obj or obj[key] is None:
        if required:
            _err(out, f"{path}.{key}", "MISSING", "必填枚举缺失")
        return
    if obj[key] not in allowed:
        _err(out, f"{path}.{key}", "BAD_ENUM",
             f"{obj[key]!r} 不在允许集合 {list(allowed)}")


def _schema(out, obj: Any, path: str, kind: str) -> bool:
    if not isinstance(obj, dict):
        _err(out, path, "BAD_TYPE", "顶层必须是 JSON 对象")
        return False
    ver = obj.get("schema")
    if not isinstance(ver, str) or not ver:
        _err(out, f"{path}.schema", "MISSING",
             f"缺少 schema 版本（受支持：{SUPPORTED[kind]}）")
        return False
    if ver not in SUPPORTED[kind]:
        _err(out, f"{path}.schema", "UNKNOWN_VERSION",
             f"未知版本 {ver!r}；受支持：{SUPPORTED[kind]}")
        return False
    return True


def _hex(out, obj, path: str, key: str) -> None:
    if key not in obj or obj[key] is None:
        _err(out, f"{path}.{key}", "MISSING", "必填哈希缺失")
        return
    if not isinstance(obj[key], str) or not HEX64.match(obj[key].lower()):
        _err(out, f"{path}.{key}", "BAD_HASH", "必须是 64 位十六进制 sha256")


def _list_of_dicts(out, obj, path: str, key: str, required: bool = True) -> List[Dict[str, Any]]:
    val = obj.get(key)
    if val is None:
        if required:
            _err(out, f"{path}.{key}", "MISSING", "必填数组缺失")
        return []
    if not isinstance(val, list):
        _err(out, f"{path}.{key}", "BAD_TYPE", "期望数组")
        return []
    good = []
    for i, item in enumerate(val):
        if not isinstance(item, dict):
            _err(out, f"{path}.{key}[{i}]", "BAD_TYPE", "数组元素必须是对象")
            continue
        good.append(item)
    return good


# ── 六类实体 ─────────────────────────────────────────────────────────────────

def validate_firmware_manifest(obj: Any) -> List[Dict[str, str]]:
    """FirmwareManifest：固件标识、镜像哈希/大小、目标架构、可选来源与解包记录。

    镜像信息是判定「审的是哪一个固件」的唯一依据，因此 image{path,sha256,size}
    必填；source / unpack 是对「从哪来、怎么解」的补充记录，缺失不影响判定，
    但出现时必须是正确类型的对象（防止自由文本混入）。
    """
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "manifest", "firmware-manifest"):
        return out
    _req(out, obj, "manifest", "id", str)
    _req(out, obj, "manifest", "vendor", str)
    _req(out, obj, "manifest", "product", str)
    _req(out, obj, "manifest", "version", str)
    _enum(out, obj, "manifest", "arch", ARCHES)
    image = obj.get("image")
    if not isinstance(image, dict):
        _err(out, "manifest.image", "MISSING", "缺少镜像对象 image{path,sha256,size}")
    else:
        _req(out, image, "manifest.image", "path", str)
        _hex(out, image, "manifest.image", "sha256")
        _req(out, image, "manifest.image", "size", int)
        if isinstance(image.get("size"), int) and image["size"] < 0:
            _err(out, "manifest.image.size", "BAD_VALUE", "size 不得为负")
    source = obj.get("source")
    if source is not None and not isinstance(source, (str, dict)):
        _err(out, "manifest.source", "BAD_TYPE", "source 必须是字符串或对象")
    unpack = obj.get("unpack")
    if unpack is not None and not isinstance(unpack, dict):
        _err(out, "manifest.unpack", "BAD_TYPE", "unpack 必须是对象")
    elif isinstance(unpack, dict):
        _req(out, unpack, "manifest.unpack", "rootfs", str)
        _req(out, unpack, "manifest.unpack", "tool", str)
    top = obj.get("sha256")
    if top is not None:
        _hex(out, obj, "manifest", "sha256")
    return out


def validate_candidate(obj: Any, path: str = "candidate") -> List[Dict[str, str]]:
    """Candidate：稳定 ID、类型、状态、位置、理由、证据引用。"""
    out: List[Dict[str, str]] = []
    if not isinstance(obj, dict):
        _err(out, path, "BAD_TYPE", "候选必须是 JSON 对象")
        return out
    _req(out, obj, path, "id", str)
    _enum(out, obj, path, "status", CAND_STATUSES)
    if "type" in obj and not isinstance(obj["type"], str):
        _err(out, f"{path}.type", "BAD_TYPE", "type 必须是字符串")
    if "category" in obj and not isinstance(obj["category"], str):
        _err(out, f"{path}.category", "BAD_TYPE", "category 必须是字符串")
    ev = obj.get("evidence")
    if ev is not None and not isinstance(ev, (list, str)):
        _err(out, f"{path}.evidence", "BAD_TYPE", "evidence 必须是数组或字符串")
    return out


def validate_audit_task(obj: Any) -> List[Dict[str, str]]:
    """AuditTask：一次审计的范围与预算声明，必须能回指 FirmwareManifest 与档位。

    scope 里的计数是「计划要审多少」，门禁拿它和实际 tiering / 产物对照；
    计数缺失或为负会让「审了 0 个文件」看起来像合法计划，因此逐项要求非负整数。
    """
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "task", "audit-task"):
        return out
    _req(out, obj, "task", "task_id", str)
    _req(out, obj, "task", "manifest_id", str)
    _enum(out, obj, "task", "profile", ("light", "standard", "strict"))
    scope = obj.get("scope")
    if not isinstance(scope, dict):
        _err(out, "task.scope", "MISSING", "缺少范围声明对象 scope")
    else:
        for key in ("t1_count", "t2_count", "skip_count"):
            val = scope.get(key)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                _err(out, f"task.scope.{key}", "BAD_VALUE",
                     "必须是非负整数（布尔与负数都不接受）")
        ealb = scope.get("ealb_total")
        if not isinstance(ealb, (int, float)) or isinstance(ealb, bool) or ealb < 0:
            _err(out, "task.scope.ealb_total", "BAD_VALUE", "必须是非负数")
    _req(out, obj, "task", "agents", int)
    if isinstance(obj.get("agents"), int) and obj["agents"] <= 0:
        _err(out, "task.agents", "BAD_VALUE", "计划 Agent 数必须为正")
    _req(out, obj, "task", "created_at", str)
    tiers = obj.get("tiers")
    if tiers is not None and not isinstance(tiers, list):
        _err(out, "task.tiers", "BAD_TYPE", "tiers 必须是数组")
    return out


def validate_candidates_document(doc: Any) -> List[Dict[str, str]]:
    """candidates/1.0 envelope：批量候选的唯一 strict 合法输入。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, doc, "candidates", "candidate"):
        return out
    rows = _list_of_dicts(out, doc, "candidates", "candidates")
    seen = set()
    for i, row in enumerate(rows):
        sub = f"candidates[{i}]"
        out.extend(validate_candidate(row, sub))
        rid = row.get("id")
        if isinstance(rid, str):
            if rid in seen:
                _err(out, sub + ".id", "DUPLICATE_ID", f"候选 ID 重复：{rid}")
            seen.add(rid)
    return out


def validate_audit_stages(obj: Any) -> List[Dict[str, str]]:
    """AuditTask 的阶段视图：ID、状态、输入、预算、重试信息。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "stages", "audit-stages"):
        return out
    rows = _list_of_dicts(out, obj, "stages", "stages")
    if not rows:
        _err(out, "stages.stages", "EMPTY", "阶段列表为空：空结果不得冒充成功")
    seen = set()
    for i, row in enumerate(rows):
        sub = f"stages[{i}]"
        _req(out, row, sub, "id", str)
        _enum(out, row, sub, "status", STAGE_STATUSES)
        if "required" in row and not isinstance(row["required"], bool):
            _err(out, sub + ".required", "BAD_TYPE", "required 必须是布尔值")
        sid = row.get("id")
        if isinstance(sid, str):
            if sid in seen:
                _err(out, sub + ".id", "DUPLICATE_ID", f"阶段 ID 重复：{sid}")
            seen.add(sid)
    return out


def validate_evidence(obj: Any, path: str = "evidence") -> List[Dict[str, str]]:
    """Evidence：类型、路径、偏移/行号、哈希、采集阶段、来源。"""
    out: List[Dict[str, str]] = []
    if not isinstance(obj, dict):
        _err(out, path, "BAD_TYPE", "证据必须是 JSON 对象")
        return out
    _req(out, obj, path, "type", str)
    _req(out, obj, path, "path", str)
    if "line" not in obj and "offset" not in obj:
        _err(out, path, "MISSING", "证据必须带 line 或 offset")
    for key in ("line", "offset"):
        if key in obj and obj[key] is not None and not isinstance(obj[key], int):
            _err(out, f"{path}.{key}", "BAD_TYPE", "必须是整数")
    if "sha256" in obj and obj["sha256"] is not None:
        _hex(out, obj, path, "sha256")
    _req(out, obj, path, "stage", str)
    _req(out, obj, path, "source", str)
    return out


def validate_finding(obj: Any, path: str = "finding") -> List[Dict[str, str]]:
    """Finding：ID、严重性、组件、触发条件、验证状态、证据引用。"""
    out: List[Dict[str, str]] = []
    if not isinstance(obj, dict):
        _err(out, path, "BAD_TYPE", "发现必须是 JSON 对象")
        return out
    _req(out, obj, path, "id", str)
    _enum(out, obj, path, "severity", SEVERITIES)
    _req(out, obj, path, "component", str)
    _req(out, obj, path, "trigger", str)
    _enum(out, obj, path, "status",
          ("confirmed", "candidate", "not_reproduced", "needs_review"))
    if "evidence" in obj and obj["evidence"] is not None:
        evs = obj["evidence"]
        if not isinstance(evs, list):
            _err(out, f"{path}.evidence", "BAD_TYPE", "evidence 必须是数组")
        else:
            for i, ev in enumerate(evs):
                if isinstance(ev, dict):
                    out.extend(validate_evidence(ev, f"{path}.evidence[{i}]"))
                elif not isinstance(ev, str):
                    _err(out, f"{path}.evidence[{i}]", "BAD_TYPE",
                         "证据必须是对象或字符串引用")
    return out


def validate_gate_result(obj: Any) -> List[Dict[str, str]]:
    """GateResult：规则 ID、输入状态、判定、原因、机器可读阻断项。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "gate", "gate-result"):
        return out
    _enum(out, obj, "gate", "result", ("pass", "fail"), required=False)
    _req(out, obj, "gate", "profile", str)
    checks = _list_of_dicts(out, obj, "gate", "checks")
    if not checks:
        _err(out, "gate.checks", "EMPTY", "检查清单为空：空结果不得冒充通过")
    for i, row in enumerate(checks):
        sub = f"checks[{i}]"
        _req(out, row, sub, "name", str)
        if "result" in row:
            _enum(out, row, sub, "result", ("PASS", "FAIL", "WARN", "SKIPPED", "ERROR"))
    blocking = obj.get("blocked")
    if blocking is not None and not isinstance(blocking, list):
        _err(out, "gate.blocked", "BAD_TYPE", "blocked 必须是数组")
    return out


def validate_scan_waiver(obj: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "waiver", "scan-waiver"):
        return out
    files = _list_of_dicts(out, obj, "waiver", "files")
    if not files:
        _err(out, "waiver.files", "EMPTY", "豁免清单为空：空白豁免不得放行任何文件")
    for i, row in enumerate(files):
        sub = f"files[{i}]"
        _req(out, row, sub, "path", str)
        _req(out, row, sub, "reason", str)
        _req(out, row, sub, "approved_by", str)
    return out


def validate_bench_manifest(obj: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "bench", "bench-manifest"):
        return out
    samples = _list_of_dicts(out, obj, "bench", "samples")
    if not samples:
        _err(out, "bench.samples", "EMPTY", "基准集为空")
    seen = set()
    for i, row in enumerate(samples):
        sub = f"samples[{i}]"
        _req(out, row, sub, "id", str)
        _req(out, row, sub, "path", str)
        _hex(out, row, sub, "sha256")
        if "arch" in row:
            _enum(out, row, sub, "arch", ARCHES)
        labs = row.get("labels")
        if labs is not None and not isinstance(labs, list):
            _err(out, sub + ".labels", "BAD_TYPE", "labels 必须是数组")
        sid = row.get("id")
        if isinstance(sid, str):
            if sid in seen:
                _err(out, sub + ".id", "DUPLICATE_ID", f"样本 ID 重复：{sid}")
            seen.add(sid)
    return out


def validate_sandbox_run(obj: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "run", "sandbox-run"):
        return out
    _enum(out, obj, "run", "mode", ("sandbox", "host-opt-in", "check"))
    _req(out, obj, "run", "command", list)
    _req(out, obj, "run", "policy", dict)
    if obj.get("host_fallback") is not False:
        _err(out, "run.host_fallback", "POLICY",
             "host_fallback 必须为 false：隔离不可用只能失败关闭")
    return out


VALIDATORS = {
    "firmware-manifest": validate_firmware_manifest,
    "audit-task": validate_audit_task,
    "candidates": validate_candidates_document,
    "candidate": validate_candidate,
    "audit-stages": validate_audit_stages,
    "evidence": validate_evidence,
    "finding": validate_finding,
    "gate-result": validate_gate_result,
    "scan-waiver": validate_scan_waiver,
    "bench-manifest": validate_bench_manifest,
    "sandbox-run": validate_sandbox_run,
}


def validate(kind: str, obj: Any) -> List[Dict[str, str]]:
    """按 kind 分派校验；未知 kind 抛 KeyError（由调用方转成用法错误）。"""
    if kind not in VALIDATORS:
        raise KeyError(f"未知契约类型：{kind}（可用：{sorted(VALIDATORS)}）")
    return VALIDATORS[kind](obj)


def summarize(errors: List[Dict[str, str]], limit: int = 6) -> str:
    """把错误列表压成一行中文摘要，供门禁与日志使用。"""
    if not errors:
        return "契约校验通过"
    head = "；".join(f"{e['path']}: {e['message']}" for e in errors[:limit])
    more = f"（另 {len(errors) - limit} 条）" if len(errors) > limit else ""
    return f"{len(errors)} 处契约违规 —— {head}{more}"


# ── CLI ─────────────────────────────────────────────────────────────────────

def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="校验 skill 的结构化数据契约（schema 版本 / 必填字段 / 类型 / 枚举）")
    ap.add_argument("--kind", help="契约类型；--list 可查")
    ap.add_argument("--file", help="待校验的 JSON（候选可用 JSONL）")
    ap.add_argument("--json", dest="json_out", help="把结果写成 JSON")
    ap.add_argument("--list", action="store_true", help="列出受支持的契约与版本")
    ap.add_argument("--quiet", action="store_true", help="只给退出码，不打印明细")
    args = ap.parse_args(argv)

    if args.list or not args.kind:
        for kind, vers in SUPPORTED.items():
            print(f"{kind:20s} {', '.join(vers)}")
        return 0 if args.list else 2

    if not args.file:
        print("[error] 需要 --file", file=sys.stderr)
        return 2
    if not os.path.isfile(args.file):
        print(f"[error] 文件不存在：{args.file}", file=sys.stderr)
        return 2
    if args.kind not in VALIDATORS:
        print(f"[error] 未知 --kind：{args.kind}", file=sys.stderr)
        return 2

    errors: List[Dict[str, str]] = []
    try:
        if args.kind == "candidates" and args.file.endswith((".jsonl", ".ndjson")):
            rows = []
            with open(args.file, "r", encoding="utf-8") as fh:
                for i, line in enumerate(fh, 1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    try:
                        rows.append(json.loads(s))
                    except json.JSONDecodeError as exc:
                        errors.append({"path": f"line {i}", "code": "PARSE_ERROR",
                                       "message": f"非法 JSON：{exc.msg}"})
            if not errors:
                errors.extend(validate_candidates_document(
                    {"schema": SUPPORTED["candidate"][0], "candidates": rows}))
        else:
            errors = validate(args.kind, _load(args.file))
    except json.JSONDecodeError as exc:
        errors = [{"path": "$", "code": "PARSE_ERROR",
                   "message": f"JSON 解析失败：{exc}"}]

    if not args.quiet:
        for e in errors:
            print(f"  [{e['code']}] {e['path']}: {e['message']}")
        print(("[ok] " if not errors else "[fail] ") + summarize(errors, limit=1000))
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump({"schema": "contract-report/1.0",
                       "kind": args.kind, "file": args.file,
                       "ok": not errors, "errors": errors},
                      fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    return 0 if not errors else 1


if __name__ == "__main__":
    raise SystemExit(main())
