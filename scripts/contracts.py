#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""结构化数据契约校验器（ISSUE-05）。

为什么需要它
------------
本 skill 的判定链路里有 16 种 schema：FirmwareManifest / AuditTask / Candidate /
Finding / Evidence / GateResult / AuditStages / ScanWaiver / SandboxRun /
BenchManifest，以及黑板层的 Fact / Intent / Hint / EmulationResult /
BoardState / BoardEvent。它们此前散落在各自的脚本输出里，字段名、必填项、枚举值、
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
    "evidence": ["evidence/1.1", "evidence/1.0"],
    "gate-result": ["gate-config/1.1"],
    "audit-stages": ["audit-stages/1.0"],
    "scan-waiver": ["scan-waiver/1.0"],
    "bench-manifest": ["bench-manifest/1.0"],
    "sandbox-run": ["sandbox-run/1.1", "sandbox-run/1.0"],
    # ── 黑板（M1）：事实、意图、提示、仿真结果、快照与事件 ──────────────────
    "fact": ["fact/1.0"],
    "intent": ["intent/1.0"],
    "hint": ["hint/1.0"],
    "emulation-result": ["emulation-result/1.0"],
    "board-state": ["board-state/1.0"],
    "board-event": ["board-event/1.0"],
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

# 黑板枚举：拒绝「随便写个字符串」的状态与类型，避免下游只能靠 if/else 猜。
FACT_TYPES = (
    "firmware", "file", "elf", "architecture", "service", "config",
    "credential", "syscall", "api-call", "network", "scan", "stage", "other",
)
SOURCE_TYPES = ("static", "dynamic", "emulation", "tool-report", "manual")
EVIDENCE_TYPES = ("static", "dynamic", "emulation", "fuzzing", "manual")
EMULATION_STATUSES = (
    "SUCCESS", "PARTIAL", "FAILED", "BLOCKED", "NOT_APPLICABLE", "TIMED_OUT",
)
INTENT_TYPES = (
    "triage", "static-analysis", "dynamic-validation", "emulation",
    "verification", "manual-review", "other",
)
INTENT_STATUSES = ("open", "claimed", "done", "failed", "cancelled")
BOARD_EVENT_TYPES = (
    "BOARD_INITIALIZED", "FACT_RECORDED", "CANDIDATE_RECORDED",
    "EVIDENCE_RECORDED", "INTENT_CREATED", "INTENT_STATUS_CHANGED",
    "HINT_RECORDED", "EMULATION_RECORDED", "CANDIDATE_TRANSITIONED", "BACKTRACK",
)
BOARD_PHASES = ("P0", "P1", "P2", "P3", "P4", "P5")


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


def _str_list(out, obj: Dict[str, Any], path: str, key: str,
              required: bool = True, allow_empty: bool = False) -> List[str]:
    """字符串 ID 数组：拒绝空串、重复项与错误类型。"""
    val = obj.get(key)
    if val is None:
        if required:
            _err(out, f"{path}.{key}", "MISSING", "必填字符串数组缺失")
        return []
    if not isinstance(val, list):
        _err(out, f"{path}.{key}", "BAD_TYPE", "期望字符串数组")
        return []
    if not allow_empty and not val:
        _err(out, f"{path}.{key}", "EMPTY", "数组不得为空")
    seen: set = set()
    good: List[str] = []
    for i, item in enumerate(val):
        if not isinstance(item, str) or not item.strip():
            _err(out, f"{path}.{key}[{i}]", "BAD_TYPE", "必须是非空字符串")
            continue
        if item in seen:
            _err(out, f"{path}.{key}[{i}]", "DUPLICATE_ID", f"引用重复：{item}")
            continue
        seen.add(item)
        good.append(item)
    return good


def _opt_int(out, obj, path: str, key: str, *, minimum: int = 0) -> None:
    if key not in obj or obj[key] is None:
        return
    val = obj[key]
    if not isinstance(val, int) or isinstance(val, bool) or val < minimum:
        _err(out, f"{path}.{key}", "BAD_VALUE", f"必须是不小于 {minimum} 的整数")


def _bind(out, obj: Dict[str, Any], path: str, run_id: Any, firmware_sha256: Any) -> None:
    """黑板对象必须绑定同一个 run 与固件：跨 run 的引用不能混进快照。"""
    if not isinstance(obj, dict):
        return
    _req(out, obj, path, "run_id", str)
    _hex(out, obj, path, "firmware_sha256")
    if isinstance(run_id, str) and isinstance(obj.get("run_id"), str) \
            and obj["run_id"] != run_id:
        _err(out, f"{path}.run_id", "RUN_MISMATCH",
             f"对象属于 {obj['run_id']}，快照属于 {run_id}")
    if isinstance(firmware_sha256, str) and isinstance(obj.get("firmware_sha256"), str) \
            and obj["firmware_sha256"].lower() != firmware_sha256.lower():
        _err(out, f"{path}.firmware_sha256", "FIRMWARE_MISMATCH",
             "对象绑定的固件哈希与快照不一致")


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
    """Evidence：兼容两种形态。

    * 带 schema 的对象走 `evidence/1.1` 的归一化校验（绑定 run/固件、来源、hook、
      原始产物）；
    * 无 schema 的历史对象保留旧的轻量校验（type/path/line|offset/stage/source），
      避免把既有 findings 里的证据块全部打断。
    """
    if isinstance(obj, dict) and "schema" in obj:
        return validate_evidence_record(obj, path)
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


def validate_evidence_record(obj: Any, path: str = "evidence") -> List[Dict[str, str]]:
    """归一化 Evidence（evidence/1.1）：来源、运行绑定、事件上下文、原始产物。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, path, "evidence"):
        return out
    if obj.get("schema") != "evidence/1.1":
        _err(out, f"{path}.schema", "UNKNOWN_VERSION",
             "带 schema 的归一化证据必须使用 evidence/1.1（1.0 是无 schema 的历史形态）")
        return out
    _req(out, obj, path, "evidence_id", str)
    _req(out, obj, path, "run_id", str)
    _hex(out, obj, path, "firmware_sha256")
    _enum(out, obj, path, "type", EVIDENCE_TYPES)
    _req(out, obj, path, "observed_at", str)
    _enum(out, obj, path, "status", ("parsed", "partial", "failed"))
    src = obj.get("source")
    if not isinstance(src, dict):
        _err(out, f"{path}.source", "MISSING", "缺少来源对象 source")
    else:
        _enum(out, src, f"{path}.source", "type", SOURCE_TYPES)
        _req(out, src, f"{path}.source", "tool", str)
        if "path" in src and not isinstance(src["path"], str):
            _err(out, f"{path}.source.path", "BAD_TYPE", "path 必须是字符串")
        if "line" in src and (not isinstance(src["line"], int) or src["line"] < 0):
            _err(out, f"{path}.source.line", "BAD_VALUE", "line 必须是非负整数")
    art = obj.get("artifact")
    if art is not None:
        if not isinstance(art, dict):
            _err(out, f"{path}.artifact", "BAD_TYPE", "artifact 必须是对象")
        else:
            _req(out, art, f"{path}.artifact", "path", str)
            _hex(out, art, f"{path}.artifact", "sha256")
            _opt_int(out, art, f"{path}.artifact", "size")
    raw = obj.get("raw_log")
    if raw is not None:
        if not isinstance(raw, dict):
            _err(out, f"{path}.raw_log", "BAD_TYPE", "raw_log 必须是对象")
        else:
            _req(out, raw, f"{path}.raw_log", "path", str)
            _hex(out, raw, f"{path}.raw_log", "sha256")
    hook = obj.get("hook")
    if hook is not None:
        if not isinstance(hook, dict):
            _err(out, f"{path}.hook", "BAD_TYPE", "hook 必须是对象")
        else:
            _enum(out, hook, f"{path}.hook", "mechanism",
                  ("syscall", "api", "libc", "other"))
            _req(out, hook, f"{path}.hook", "name", str)
    flt = obj.get("filter")
    if flt is not None:
        if not isinstance(flt, dict):
            _err(out, f"{path}.filter", "BAD_TYPE", "filter 必须是对象")
        else:
            _req(out, flt, f"{path}.filter", "rule_id", str)
            _req(out, flt, f"{path}.filter", "rule_version", str)
    event = obj.get("event")
    if event is not None:
        if not isinstance(event, dict):
            _err(out, f"{path}.event", "BAD_TYPE", "event 必须是对象")
        else:
            _req(out, event, f"{path}.event", "type", str)
            if "trigger" in event and not isinstance(event["trigger"], bool):
                _err(out, f"{path}.event.trigger", "BAD_TYPE", "trigger 必须是布尔值")
            if "args" in event and not isinstance(event["args"], dict):
                _err(out, f"{path}.event.args", "BAD_TYPE", "args 必须是对象")
    if obj.get("type") in ("dynamic", "emulation") and not isinstance(event, dict):
        _err(out, f"{path}.event", "MISSING", "动态/仿真证据必须带结构化 event")
    if obj.get("type") == "static" and not (
            (isinstance(src, dict) and isinstance(src.get("path"), str))
            or isinstance(art, dict)):
        _err(out, f"{path}.source.path", "MISSING",
             "静态证据必须带 source.path 或 artifact")
    lim = obj.get("limitations")
    if lim is not None:
        if not isinstance(lim, list) or any(not isinstance(x, str) for x in lim):
            _err(out, f"{path}.limitations", "BAD_TYPE", "limitations 必须是字符串数组")
        elif obj.get("status") != "parsed" and not lim:
            _err(out, f"{path}.limitations", "MISSING",
                 "非 parsed 证据必须说明限制，不能把不完整当完整")
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


ADMISSION_DECISIONS = ("admitted", "rejected", "checked",
                       "queue-timeout", "budget-exhausted")


def validate_sandbox_run(obj: Any) -> List[Dict[str, str]]:
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "run", "sandbox-run"):
        return out
    _enum(out, obj, "run", "mode",
          ("sandbox", "host-opt-in", "fail-closed", "check"))
    _req(out, obj, "run", "command", list)
    _req(out, obj, "run", "policy", dict)
    if obj.get("host_fallback") is not False:
        _err(out, "run.host_fallback", "POLICY",
             "host_fallback 必须为 false：隔离不可用只能失败关闭")

    # 1.1 的增量：admission 是机器可读的资源准入结论。没有它就无法区分
    # 「命令失败」和「根本没被允许启动」，1.1 必须要求。
    if obj.get("schema") == "sandbox-run/1.1":
        adm = obj.get("admission")
        if not isinstance(adm, dict):
            _err(out, "run.admission", "MISSING", "1.1 必须带 admission 对象")
            return out
        _enum(out, adm, "run.admission", "decision", ADMISSION_DECISIONS)
        if "code" not in adm:
            _err(out, "run.admission.code", "MISSING", "admission.code 必填（可为 null）")
        elif adm.get("code") is not None and not isinstance(adm.get("code"), str):
            _err(out, "run.admission.code", "BAD_TYPE", "code 必须是字符串或 null")
        _req(out, adm, "run.admission", "policy", dict)
        _hex(out, adm, "run.admission", "policy_sha256")
        slots = adm.get("slots")
        if not isinstance(slots, dict):
            _err(out, "run.admission.slots", "MISSING", "缺少 slots 对象")
        else:
            _opt_int(out, slots, "run.admission.slots", "limit", minimum=1)
            _opt_int(out, slots, "run.admission.slots", "slot")
            wait = slots.get("wait_s")
            if isinstance(wait, bool) or not isinstance(wait, (int, float)):
                _err(out, "run.admission.slots.wait_s", "BAD_TYPE",
                     "wait_s 必须是数字")
            if "queued" in slots and not isinstance(slots.get("queued"), bool):
                _err(out, "run.admission.slots.queued", "BAD_TYPE", "queued 必须是布尔值")
            if not isinstance(slots.get("state_dir"), str) or not slots.get("state_dir"):
                _err(out, "run.admission.slots.state_dir", "MISSING",
                     "state_dir 必须是非空字符串")
        budget = adm.get("budget")
        if not isinstance(budget, dict):
            _err(out, "run.admission.budget", "MISSING", "缺少 budget 对象")
        else:
            for key in ("limit_s", "used_s", "remaining_s"):
                val = budget.get(key)
                if isinstance(val, bool) or not isinstance(val, (int, float)):
                    _err(out, f"run.admission.budget.{key}", "BAD_TYPE",
                         f"{key} 必须是数字")
        req = adm.get("request")
        if not isinstance(req, dict):
            _err(out, "run.admission.request", "MISSING", "缺少 request 对象")
    return out


def validate_fact(obj: Any) -> List[Dict[str, str]]:
    """Fact：有来源、带适用范围、绑定 run 与固件的客观观察。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "fact", "fact"):
        return out
    _req(out, obj, "fact", "fact_id", str)
    _req(out, obj, "fact", "run_id", str)
    _hex(out, obj, "fact", "firmware_sha256")
    _enum(out, obj, "fact", "type", FACT_TYPES)
    value = obj.get("value")
    if not isinstance(value, dict):
        _err(out, "fact.value", "MISSING", "缺少观察值对象 value")
    elif not value:
        _err(out, "fact.value", "EMPTY", "value 不得为空对象")
    _str_list(out, obj, "fact", "evidence_refs")
    src = obj.get("source")
    if not isinstance(src, dict):
        _err(out, "fact.source", "MISSING", "缺少来源对象 source")
    else:
        _enum(out, src, "fact.source", "type", SOURCE_TYPES)
        for key in ("tool", "tool_version", "rule_id", "rule_version"):
            if key in src and not isinstance(src[key], str):
                _err(out, f"fact.source.{key}", "BAD_TYPE", f"{key} 必须是字符串")
        for key in ("path", "location"):
            if key in src and not isinstance(src[key], str):
                _err(out, f"fact.source.{key}", "BAD_TYPE", f"{key} 必须是字符串")
    _req(out, obj, "fact", "observed_at", str)
    if "scope" in obj and obj["scope"] is not None and not isinstance(obj["scope"], dict):
        _err(out, "fact.scope", "BAD_TYPE", "scope 必须是对象")
    for key in ("supersedes", "contradicts"):
        if key in obj and obj[key] is not None:
            _str_list(out, obj, "fact", key, required=False, allow_empty=True)
    return out


def validate_intent(obj: Any) -> List[Dict[str, str]]:
    """Intent：可执行任务，必须由已有事实/候选/证据触发，并带去重键与预算。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "intent", "intent"):
        return out
    _req(out, obj, "intent", "intent_id", str)
    _req(out, obj, "intent", "run_id", str)
    _hex(out, obj, "intent", "firmware_sha256")
    _enum(out, obj, "intent", "type", INTENT_TYPES)
    _enum(out, obj, "intent", "status", INTENT_STATUSES)
    _str_list(out, obj, "intent", "from")
    _req(out, obj, "intent", "description", str)
    _req(out, obj, "intent", "dedupe_key", str)
    _req(out, obj, "intent", "creator", str)
    _req(out, obj, "intent", "created_at", str)
    target = obj.get("target")
    if not isinstance(target, (str, dict)) or (isinstance(target, str) and not target.strip()):
        _err(out, "intent.target", "MISSING", "target 必须是非空字符串或对象")
    if "params" in obj and obj["params"] is not None and not isinstance(obj["params"], dict):
        _err(out, "intent.params", "BAD_TYPE", "params 必须是对象")
    budget = obj.get("budget")
    if budget is not None:
        if not isinstance(budget, dict):
            _err(out, "intent.budget", "BAD_TYPE", "budget 必须是对象")
        else:
            for key in ("seconds", "max_attempts", "tokens"):
                if key in budget:
                    _opt_int(out, budget, "intent.budget", key)
    _opt_int(out, obj, "intent", "timeout_seconds", minimum=1)
    _opt_int(out, obj, "intent", "max_retries")
    for key in ("preconditions", "stop_conditions", "expected_outputs"):
        if key in obj and obj[key] is not None:
            _str_list(out, obj, "intent", key, required=False, allow_empty=True)
    worker = obj.get("worker")
    if worker is not None and not isinstance(worker, str):
        _err(out, "intent.worker", "BAD_TYPE", "worker 必须是字符串或 null")
    if obj.get("status") == "claimed":
        if not isinstance(worker, str) or not worker.strip():
            _err(out, "intent.worker", "MISSING", "claimed 状态必须记录 worker")
        if not isinstance(obj.get("claimed_at"), str) or not obj.get("claimed_at"):
            _err(out, "intent.claimed_at", "MISSING", "claimed 状态必须记录 claimed_at")
    if obj.get("status") in ("done", "failed", "cancelled"):
        if not isinstance(obj.get("concluded_at"), str) or not obj.get("concluded_at"):
            _err(out, "intent.concluded_at", "MISSING",
                 "结束状态必须记录 concluded_at")
    return out


def validate_hint(obj: Any) -> List[Dict[str, str]]:
    """Hint：只影响优先级或触发审查，不是证据；必须有创建者与时间。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "hint", "hint"):
        return out
    _req(out, obj, "hint", "hint_id", str)
    _req(out, obj, "hint", "run_id", str)
    _hex(out, obj, "hint", "firmware_sha256")
    _req(out, obj, "hint", "content", str)
    _req(out, obj, "hint", "creator", str)
    _req(out, obj, "hint", "created_at", str)
    if "active" in obj and not isinstance(obj["active"], bool):
        _err(out, "hint.active", "BAD_TYPE", "active 必须是布尔值")
    if "affects" in obj and obj["affects"] is not None:
        _str_list(out, obj, "hint", "affects", required=False, allow_empty=True)
    return out


def _artifact_list(out, obj, path: str, key: str) -> List[Dict[str, Any]]:
    items = _list_of_dicts(out, obj, path, key, required=False)
    for i, art in enumerate(items):
        sub = f"{path}.{key}[{i}]"
        _req(out, art, sub, "path", str)
        _hex(out, art, sub, "sha256")
        _opt_int(out, art, sub, "size")
    return items


def validate_emulation_result(obj: Any) -> List[Dict[str, str]]:
    """EmulationResult：不同后端共用的结果契约；失败必须与「没发现」区分。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "result", "emulation-result"):
        return out
    _req(out, obj, "result", "emulation_id", str)
    _req(out, obj, "result", "run_id", str)
    _req(out, obj, "result", "intent_id", str)
    _hex(out, obj, "result", "firmware_sha256")
    if "target_sha256" in obj and obj["target_sha256"] is not None:
        _hex(out, obj, "result", "target_sha256")
    _req(out, obj, "result", "backend", str)
    _req(out, obj, "result", "backend_version", str)
    _enum(out, obj, "result", "status", EMULATION_STATUSES)
    if not isinstance(obj.get("environment"), dict):
        _err(out, "result.environment", "MISSING", "缺少环境对象 environment")
    _list_of_dicts(out, obj, "result", "observations", required=False)
    if "evidence_refs" in obj and obj["evidence_refs"] is not None:
        _str_list(out, obj, "result", "evidence_refs",
                  required=False, allow_empty=True)
    _artifact_list(out, obj, "result", "artifacts")
    if "resource_usage" in obj and obj["resource_usage"] is not None \
            and not isinstance(obj["resource_usage"], dict):
        _err(out, "result.resource_usage", "BAD_TYPE", "resource_usage 必须是对象")
    _req(out, obj, "result", "finished_at", str)
    if "started_at" in obj and obj["started_at"] is not None \
            and not isinstance(obj["started_at"], str):
        _err(out, "result.started_at", "BAD_TYPE", "started_at 必须是字符串")
    if "limitations" in obj and obj["limitations"] is not None:
        _str_list(out, obj, "result", "limitations", required=False, allow_empty=True)
    failure = obj.get("failure")
    if obj.get("status") in ("FAILED", "BLOCKED", "TIMED_OUT"):
        if not isinstance(failure, dict):
            _err(out, "result.failure", "MISSING",
                 "失败/阻断/超时必须给出 failure{category,reason,retryable}")
        else:
            _req(out, failure, "result.failure", "category", str)
            _req(out, failure, "result.failure", "reason", str)
            if not isinstance(failure.get("retryable"), bool):
                _err(out, "result.failure.retryable", "BAD_TYPE", "retryable 必须是布尔值")
    elif failure is not None and not isinstance(failure, dict):
        _err(out, "result.failure", "BAD_TYPE", "failure 必须是对象")
    if obj.get("status") == "PARTIAL":
        lim = obj.get("limitations")
        if not isinstance(lim, list) or not lim:
            _err(out, "result.limitations", "MISSING",
                 "PARTIAL 必须列出未覆盖内容，不能静默折叠为成功")
    return out


def _validate_backtrack(out, row, path: str) -> None:
    _req(out, row, path, "from_phase", str)
    _req(out, row, path, "to_phase", str)
    _enum(out, row, path, "from_phase", BOARD_PHASES)
    _enum(out, row, path, "to_phase", BOARD_PHASES)
    _req(out, row, path, "reason", str)
    _str_list(out, row, path, "evidence_refs")
    if "approved_by" in row and row["approved_by"] is not None \
            and not isinstance(row["approved_by"], str):
        _err(out, f"{path}.approved_by", "BAD_TYPE", "approved_by 必须是字符串")


def validate_board_state(obj: Any) -> List[Dict[str, str]]:
    """BoardState：唯一可恢复状态源；所有对象绑定 run/固件，引用不得悬空。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "board", "board-state"):
        return out
    _req(out, obj, "board", "run_id", str)
    _hex(out, obj, "board", "firmware_sha256")
    _opt_int(out, obj, "board", "revision")
    _opt_int(out, obj, "board", "event_count")
    _req(out, obj, "board", "updated_at", str)
    _enum(out, obj, "board", "phase", BOARD_PHASES, required=False)
    if "manifest_id" in obj and obj["manifest_id"] is not None \
            and not isinstance(obj["manifest_id"], str):
        _err(out, "board.manifest_id", "BAD_TYPE", "manifest_id 必须是字符串")
    if "last_event_id" in obj and obj["last_event_id"] is not None \
            and not isinstance(obj["last_event_id"], str):
        _err(out, "board.last_event_id", "BAD_TYPE", "last_event_id 必须是字符串或 null")
    run_id = obj.get("run_id")
    fw = obj.get("firmware_sha256")

    evidence = _list_of_dicts(out, obj, "board", "evidence")
    facts = _list_of_dicts(out, obj, "board", "facts")
    candidates = _list_of_dicts(out, obj, "board", "candidates")
    intents = _list_of_dicts(out, obj, "board", "intents")
    hints = _list_of_dicts(out, obj, "board", "hints")
    emus = _list_of_dicts(out, obj, "board", "emulation_results")
    backtracks = _list_of_dicts(out, obj, "board", "backtracks")

    ids: Dict[str, set] = {}
    for name, rows, id_key, validator in (
            ("evidence", evidence, "evidence_id", validate_evidence_record),
            ("facts", facts, "fact_id", validate_fact),
            ("candidates", candidates, "id", validate_candidate),
            ("intents", intents, "intent_id", validate_intent),
            ("hints", hints, "hint_id", validate_hint),
            ("emulation_results", emus, "emulation_id", validate_emulation_result)):
        seen: set = set()
        ids[name] = seen
        for i, row in enumerate(rows):
            sub = f"board.{name}[{i}]"
            _bind(out, row, sub, run_id, fw)
            out.extend(validator(row))
            rid = row.get(id_key)
            if isinstance(rid, str):
                if rid in seen:
                    _err(out, f"{sub}.{id_key}", "DUPLICATE_ID",
                         f"ID 重复：{rid}")
                seen.add(rid)

    for i, row in enumerate(backtracks):
        _validate_backtrack(out, row, f"board.backtracks[{i}]")

    evidence_ids = ids["evidence"]
    ref_space = (ids["facts"] | ids["candidates"] | ids["evidence"]
                 | ids["intents"])

    for i, row in enumerate(facts):
        for ref in row.get("evidence_refs") or []:
            if isinstance(ref, str) and ref not in evidence_ids:
                _err(out, f"board.facts[{i}].evidence_refs", "DANGLING_REF",
                     f"证据引用不存在：{ref}")
    for i, row in enumerate(intents):
        for ref in row.get("from") or []:
            if isinstance(ref, str) and ref not in ref_space:
                _err(out, f"board.intents[{i}].from", "DANGLING_REF",
                     f"来源引用不存在：{ref}")
    for i, row in enumerate(emus):
        iid = row.get("intent_id")
        if isinstance(iid, str) and iid not in ids["intents"]:
            _err(out, f"board.emulation_results[{i}].intent_id", "DANGLING_REF",
                 f"Intent 不存在：{iid}")
        for ref in row.get("evidence_refs") or []:
            if isinstance(ref, str) and ref not in evidence_ids:
                _err(out, f"board.emulation_results[{i}].evidence_refs",
                     "DANGLING_REF", f"证据引用不存在：{ref}")
    for i, row in enumerate(backtracks):
        for ref in row.get("evidence_refs") or []:
            if isinstance(ref, str) and ref not in evidence_ids:
                _err(out, f"board.backtracks[{i}].evidence_refs", "DANGLING_REF",
                     f"证据引用不存在：{ref}")

    counters = obj.get("counters")
    if counters is not None:
        if not isinstance(counters, dict):
            _err(out, "board.counters", "BAD_TYPE", "counters 必须是对象")
        else:
            for name, rows in (("facts", facts), ("candidates", candidates),
                               ("intents", intents), ("hints", hints),
                               ("evidence", evidence),
                               ("emulation_results", emus)):
                if name in counters and counters[name] != len(rows):
                    _err(out, f"board.counters.{name}", "BAD_VALUE",
                         f"计数 {counters[name]} 与实际 {len(rows)} 不一致")
    return out


def validate_board_event(obj: Any) -> List[Dict[str, str]]:
    """BoardEvent：追加日志的一行；event/seq/dedupe_key 是回放与去重的基础。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "event", "board-event"):
        return out
    _req(out, obj, "event", "event_id", str)
    _req(out, obj, "event", "run_id", str)
    if "seq" not in obj or obj.get("seq") is None:
        _err(out, "event.seq", "MISSING", "事件必须有连续序号 seq")
    _opt_int(out, obj, "event", "seq", minimum=1)
    _enum(out, obj, "event", "type", BOARD_EVENT_TYPES)
    _req(out, obj, "event", "ts", str)
    _req(out, obj, "event", "dedupe_key", str)
    payload = obj.get("payload")
    if not isinstance(payload, dict):
        _err(out, "event.payload", "MISSING", "缺少 payload 对象")
        return out
    typ = obj.get("type")
    run_id = obj.get("run_id")

    def record(key: str, validator, id_key: str) -> None:
        row = payload.get(key)
        if not isinstance(row, dict):
            _err(out, f"event.payload.{key}", "MISSING", f"{key} 必须是对象")
            return
        out.extend(validator(row))
        if isinstance(run_id, str) and isinstance(row.get("run_id"), str) \
                and row["run_id"] != run_id:
            _err(out, f"event.payload.{key}.run_id", "RUN_MISMATCH",
                 f"对象属于 {row['run_id']}，事件属于 {run_id}")
        if isinstance(row.get(id_key), str) and not row[id_key].strip():
            _err(out, f"event.payload.{key}.{id_key}", "BAD_VALUE", "ID 不得为空")

    if typ == "BOARD_INITIALIZED":
        _hex(out, payload, "event.payload", "firmware_sha256")
        if "manifest_id" in payload and payload["manifest_id"] is not None \
                and not isinstance(payload["manifest_id"], str):
            _err(out, "event.payload.manifest_id", "BAD_TYPE", "manifest_id 必须是字符串")
    elif typ == "FACT_RECORDED":
        record("fact", validate_fact, "fact_id")
    elif typ == "CANDIDATE_RECORDED":
        record("candidate", validate_candidate, "id")
    elif typ == "EVIDENCE_RECORDED":
        record("evidence", validate_evidence_record, "evidence_id")
    elif typ == "INTENT_CREATED":
        record("intent", validate_intent, "intent_id")
    elif typ == "HINT_RECORDED":
        record("hint", validate_hint, "hint_id")
    elif typ == "EMULATION_RECORDED":
        record("result", validate_emulation_result, "emulation_id")
    elif typ == "CANDIDATE_TRANSITIONED":
        _req(out, payload, "event.payload", "candidate_id", str)
        _enum(out, payload, "event.payload", "from_state", CAND_STATUSES)
        _enum(out, payload, "event.payload", "to_state", CAND_STATUSES)
        _req(out, payload, "event.payload", "reason", str)
        _str_list(out, payload, "event.payload", "evidence_refs",
                  required=False, allow_empty=True)
        if payload.get("policy") is not None and not isinstance(payload["policy"], dict):
            _err(out, "event.payload.policy", "BAD_TYPE", "policy 必须是对象")
    elif typ == "INTENT_STATUS_CHANGED":
        _req(out, payload, "event.payload", "intent_id", str)
        _enum(out, payload, "event.payload", "from_status", INTENT_STATUSES)
        _enum(out, payload, "event.payload", "to_status", INTENT_STATUSES)
        if "worker" in payload and payload["worker"] is not None \
                and not isinstance(payload["worker"], str):
            _err(out, "event.payload.worker", "BAD_TYPE", "worker 必须是字符串")
    elif typ == "BACKTRACK":
        _validate_backtrack(out, payload, "event.payload")
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
    "fact": validate_fact,
    "intent": validate_intent,
    "hint": validate_hint,
    "emulation-result": validate_emulation_result,
    "board-state": validate_board_state,
    "board-event": validate_board_event,
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
