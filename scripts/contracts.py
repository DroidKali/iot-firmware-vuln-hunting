#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""结构化数据契约校验器（ISSUE-05）。

为什么需要它
------------
本 skill 的判定链路里有 24 种 schema：FirmwareManifest / AuditTask / Candidate /
Finding / Evidence / GateResult / AuditStages / ScanWaiver / SandboxRun /
BenchManifest / EmbaImport / EmulationPlan / QilingPlan / QilingEvent /
QilingImport，黑板层的 Fact / Intent / Hint / EmulationResult / BoardState /
BoardEvent，M7 调度层的 SchedulerRules / SchedulerResult，以及 Phase 0 的
ToolIndex。它们此前散落在各自的脚本输出里，字段名、必填项、枚举值、
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
    "emba-import": ["emba-import/1.0"],
    "emulation-plan": ["emulation-plan/1.0"],
    # ── 黑板（M1）：事实、意图、提示、仿真结果、快照与事件 ──────────────────
    "fact": ["fact/1.0"],
    "intent": ["intent/1.1", "intent/1.0"],
    "hint": ["hint/1.0"],
    "emulation-result": ["emulation-result/1.0"],
    "board-state": ["board-state/1.0"],
    "board-event": ["board-event/1.0"],
    # ── M4 Qiling 定向仿真：计划、事件与导入包 ──────────────────────────
    "qiling-plan": ["qiling-plan/1.0"],
    "qiling-event": ["qiling-event/1.0"],
    "qiling-import": ["qiling-import/1.0"],
    # ── M7 动态调度：确定性规则与执行结果 ────────────────────────────────
    "scheduler-rules": ["scheduler-rules/1.0"],
    "scheduler-result": ["scheduler-result/1.0"],
    # ── Phase 0 工具索引：版本探测、能力缺口与安装/降级路径 ────────────────
    "tool-index": ["tool-index/1.0"],
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
    # M3：EMBA 适配器显式区分三类观察，类型不同才不能被互相「升级」
    "dependency", "runtime-process", "port-response",
)
# EMBA 可选产物角色；--require 只能要求这些，F50 永远必需，不在其中。
EMBA_ARTIFACT_ROLES = ("p99", "s09", "l15", "l10", "s115")
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
# Intent 结果保留 SUCCESS/PARTIAL/... 的区分；PARTIAL 不能被折叠成 success。
INTENT_OUTCOMES = (
    "success", "partial", "failed", "blocked", "not_applicable",
    "timed_out", "cancelled",
)
INTENT_PRIORITY_RANGE = (0, 100)
BOARD_EVENT_TYPES = (
    "BOARD_INITIALIZED", "FACT_RECORDED", "CANDIDATE_RECORDED",
    "EVIDENCE_RECORDED", "INTENT_CREATED", "INTENT_STATUS_CHANGED",
    "HINT_RECORDED", "EMULATION_RECORDED", "CANDIDATE_TRANSITIONED", "BACKTRACK",
    "PHASE_ADVANCED", "INTENT_COMPLETED_WITH_RESULTS", "INTENT_LEASE_RENEWED",
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


def _opt_str(out, obj, path: str, key: str) -> None:
    if key not in obj or obj[key] is None:
        return
    if not isinstance(obj[key], str) or not obj[key].strip():
        _err(out, f"{path}.{key}", "BAD_TYPE", "必须是非空字符串")


def _opt_text(out, obj, path: str, key: str) -> None:
    """可选描述字段：允许空串，但类型必须是字符串。"""
    if key in obj and obj[key] is not None and not isinstance(obj[key], str):
        _err(out, f"{path}.{key}", "BAD_TYPE", "必须是字符串")


def _opt_bool(out, obj, path: str, key: str) -> None:
    if key not in obj or obj[key] is None:
        return
    if not isinstance(obj[key], bool):
        _err(out, f"{path}.{key}", "BAD_TYPE", "必须是布尔值")


def _opt_hex(out, obj, path: str, key: str) -> None:
    if key in obj and obj[key] is not None:
        _hex(out, obj, path, key)


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
        _opt_str(out, src, f"{path}.source", "tool_version")
        _enum(out, src, f"{path}.source", "reliability",
              ("high", "medium", "low", "unknown"), required=False)
    _opt_hex(out, obj, path, "target_sha256")
    _opt_hex(out, obj, path, "content_sha256")
    # 判据语义声明：一条证据凭什么支持某个 required_criterion。状态机不能只看
    # Evidence ID 是否存在；supports 把「调用链 / 输入来源 / sink 执行」拆成
    # 可检查的观察项，避免同一条 execve 被同时当作可达性、输入可控与命令执行。
    supports = obj.get("supports")
    if supports is not None:
        if not isinstance(supports, list) or not supports:
            _err(out, f"{path}.supports", "BAD_TYPE", "supports 必须是非空数组")
        else:
            for j, item in enumerate(supports):
                sub = f"{path}.supports[{j}]"
                if not isinstance(item, dict):
                    _err(out, sub, "BAD_TYPE", "support 必须是对象")
                    continue
                _req(out, item, sub, "criterion", str)
                _req(out, item, sub, "kind", str)
                details = item.get("details")
                if details is not None and not isinstance(details, dict):
                    _err(out, sub + ".details", "BAD_TYPE", "details 必须是对象")
                elif isinstance(details, dict):
                    for key in ("path", "argv"):
                        if key in details:
                            _str_list(out, details, sub + ".details", key,
                                      required=False, allow_empty=False)
    _opt_bool(out, obj, path, "revoked")
    _opt_str(out, obj, path, "revoked_at")
    if obj.get("revoked") is True and not isinstance(obj.get("revoked_at"), str):
        _err(out, f"{path}.revoked_at", "MISSING", "revoked=true 时必须记录 revoked_at")
    _opt_str(out, obj, path, "expires_at")
    _opt_str(out, obj, path, "superseded_by")
    _opt_str(out, obj, path, "conflict_group")
    _str_list(out, obj, path, "supersedes", required=False, allow_empty=True)
    _str_list(out, obj, path, "contradicts", required=False, allow_empty=True)
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


def validate_emba_import(obj: Any) -> List[Dict[str, str]]:
    """EmbaImport：离线解析 EMBA 日志得到的观察包。

    契约重点不是「字段多」，而是三件事：
    * 每条事实都能追到一条已存在的证据，且 run/固件绑定一致；
    * 三类观察的类型与 value.observation 必须匹配，不能把静态服务写成进程或端口；
    * status 与 errors、counts 必须自洽，缺日志不得伪装成 parsed。
    """
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "emba", "emba-import"):
        return out
    _req(out, obj, "emba", "run_id", str)
    _hex(out, obj, "emba", "firmware_sha256")
    _enum(out, obj, "emba", "status", ("parsed", "partial", "failed"))
    adapter = obj.get("adapter")
    if not isinstance(adapter, dict):
        _err(out, "emba.adapter", "MISSING", "缺少 adapter 对象")
    else:
        _req(out, adapter, "emba.adapter", "name", str)
        _req(out, adapter, "emba.adapter", "version", str)
    tool = obj.get("tool")
    if not isinstance(tool, dict):
        _err(out, "emba.tool", "MISSING", "缺少 tool 对象")
    else:
        _req(out, tool, "emba.tool", "name", str)
        _req(out, tool, "emba.tool", "version", str)
    if "expect_version" in obj and obj["expect_version"] is not None \
            and not isinstance(obj["expect_version"], str):
        _err(out, "emba.expect_version", "BAD_TYPE", "expect_version 必须是字符串或 null")

    run_id = obj.get("run_id")
    fw = obj.get("firmware_sha256")

    inputs = _list_of_dicts(out, obj, "emba", "inputs")
    input_keys: set = set()
    for i, row in enumerate(inputs):
        path = f"emba.inputs[{i}]"
        _req(out, row, path, "role", str)
        _req(out, row, path, "path", str)
        _hex(out, row, path, "sha256")
        _opt_int(out, row, path, "size")
        key = (row.get("role"), row.get("path"))
        if key in input_keys:
            _err(out, path, "DUPLICATE_INPUT",
                 f"同一输入被重复声明：{key[0]!r} {key[1]!r}")
        input_keys.add(key)

    requirements = obj.get("requirements")
    if requirements is not None:
        if not isinstance(requirements, dict):
            _err(out, "emba.requirements", "BAD_TYPE", "requirements 必须是对象")
        else:
            req_lists: Dict[str, List[str]] = {}
            for key in ("required", "satisfied", "missing"):
                req_lists[key] = _str_list(out, requirements, "emba.requirements",
                                           key, allow_empty=True)
                for i, role in enumerate(req_lists[key]):
                    if role not in EMBA_ARTIFACT_ROLES:
                        _err(out, f"emba.requirements.{key}[{i}]", "BAD_ENUM",
                             f"未知的产物角色：{role!r}")
            req_set = set(req_lists["required"])
            sat_set = set(req_lists["satisfied"])
            miss_set = set(req_lists["missing"])
            if not sat_set.issubset(req_set):
                _err(out, "emba.requirements.satisfied", "REQUIREMENTS_INCONSISTENT",
                     "satisfied 必须是 required 的子集")
            if not miss_set.issubset(req_set):
                _err(out, "emba.requirements.missing", "REQUIREMENTS_INCONSISTENT",
                     "missing 必须是 required 的子集")
            if sat_set & miss_set:
                _err(out, "emba.requirements", "REQUIREMENTS_INCONSISTENT",
                     "satisfied 与 missing 不得重叠")
            if (sat_set | miss_set) != req_set:
                _err(out, "emba.requirements", "REQUIREMENTS_INCONSISTENT",
                     "required 必须等于 satisfied 与 missing 的并集")
            if miss_set and obj.get("status") != "failed":
                _err(out, "emba.requirements.missing", "REQUIREMENTS_INCONSISTENT",
                     "存在 missing 时 status 必须为 failed")

    evidence = _list_of_dicts(out, obj, "emba", "evidence")
    ev_ids: set = set()
    ev_by_id: Dict[str, Dict[str, Any]] = {}
    for i, row in enumerate(evidence):
        path = f"emba.evidence[{i}]"
        out.extend(validate_evidence_record(row, path))
        eid = row.get("evidence_id")
        if isinstance(eid, str) and eid:
            if eid in ev_ids:
                _err(out, f"{path}.evidence_id", "DUPLICATE_ID",
                     f"证据 ID 重复：{eid}")
            ev_ids.add(eid)
            ev_by_id[eid] = row
        _bind(out, row, path, run_id, fw)

    facts = _list_of_dicts(out, obj, "emba", "facts")
    fact_ids: set = set()
    fact_by_id: Dict[str, Dict[str, Any]] = {}
    for i, row in enumerate(facts):
        path = f"emba.facts[{i}]"
        out.extend(validate_fact(row))
        fid = row.get("fact_id")
        if isinstance(fid, str) and fid:
            if fid in fact_ids:
                _err(out, f"{path}.fact_id", "DUPLICATE_ID",
                     f"事实 ID 重复：{fid}")
            fact_ids.add(fid)
            fact_by_id[fid] = row
        _bind(out, row, path, run_id, fw)
        refs = row.get("evidence_refs")
        if isinstance(refs, list):
            for ref in refs:
                if not isinstance(ref, str):
                    continue
                if ref not in ev_ids:
                    _err(out, f"{path}.evidence_refs", "DANGLING_EVIDENCE",
                         f"事实引用了不存在的证据：{ref!r}")
        typ = row.get("type")
        value = row.get("value") if isinstance(row.get("value"), dict) else {}
        obs_kind = value.get("observation")
        ref_types = {ev_by_id[r].get("type") for r in (refs or [])
                     if isinstance(r, str) and r in ev_by_id}
        if typ == "service":
            if obs_kind != "static-discovery":
                _err(out, f"{path}.value.observation", "OBSERVATION_MISMATCH",
                     "service 只能表示静态发现（static-discovery）")
            if ref_types and "static" not in ref_types:
                _err(out, f"{path}.evidence_refs", "EVIDENCE_TYPE_MISMATCH",
                     "service 必须引用 static 证据")
        elif typ == "runtime-process":
            if obs_kind != "runtime-process":
                _err(out, f"{path}.value.observation", "OBSERVATION_MISMATCH",
                     "runtime-process 必须标记 runtime-process")
            if ref_types and "emulation" not in ref_types:
                _err(out, f"{path}.evidence_refs", "EVIDENCE_TYPE_MISMATCH",
                     "runtime-process 必须引用 emulation 证据")
        elif typ == "port-response":
            if obs_kind != "port-response":
                _err(out, f"{path}.value.observation", "OBSERVATION_MISMATCH",
                     "port-response 必须标记 port-response")
            if ref_types and "dynamic" not in ref_types:
                _err(out, f"{path}.evidence_refs", "EVIDENCE_TYPE_MISMATCH",
                     "port-response 必须引用 dynamic 证据")

    observations = _list_of_dicts(out, obj, "emba", "observations")
    observed_facts: set = set()
    for i, row in enumerate(observations):
        path = f"emba.observations[{i}]"
        _req(out, row, path, "fact_id", str)
        _enum(out, row, path, "type", FACT_TYPES)
        if "observation" in row and row["observation"] is not None \
                and not isinstance(row["observation"], str):
            _err(out, f"{path}.observation", "BAD_TYPE", "observation 必须是字符串")
        fid = row.get("fact_id")
        if isinstance(fid, str) and fid and fid not in fact_ids:
            _err(out, f"{path}.fact_id", "DANGLING_REF",
                 f"observations 引用了不存在的事实：{fid!r}")
        elif isinstance(fid, str) and fid in fact_by_id:
            if fid in observed_facts:
                _err(out, f"{path}.fact_id", "DUPLICATE_OBSERVATION",
                     f"同一事实出现多条 observation：{fid!r}")
            observed_facts.add(fid)
            ftype = fact_by_id[fid].get("type")
            if row.get("type") != ftype:
                _err(out, f"{path}.type", "TYPE_MISMATCH",
                     f"观察类型 {row.get('type')!r} 与事实类型 {ftype!r} 不一致")
    for fid in sorted(fact_ids):
        if fid not in observed_facts:
            _err(out, "emba.observations", "MISSING_OBSERVATION",
                 f"事实缺少对应的 observation：{fid!r}")

    errors = _list_of_dicts(out, obj, "emba", "errors")
    for i, row in enumerate(errors):
        path = f"emba.errors[{i}]"
        _req(out, row, path, "code", str)
        _req(out, row, path, "message", str)
        if "path" in row and row["path"] is not None and not isinstance(row["path"], str):
            _err(out, f"{path}.path", "BAD_TYPE", "path 必须是字符串")
        _opt_int(out, row, path, "line")
    limitations = obj.get("limitations")
    if limitations is not None:
        if not isinstance(limitations, list) \
                or any(not isinstance(x, str) for x in limitations):
            _err(out, "emba.limitations", "BAD_TYPE", "limitations 必须是字符串数组")

    counts = obj.get("counts")
    if not isinstance(counts, dict):
        _err(out, "emba.counts", "MISSING", "缺少 counts 对象")
    else:
        for key, actual in (("evidence", len(evidence)), ("facts", len(facts)),
                            ("errors", len(errors))):
            val = counts.get(key)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                _err(out, f"emba.counts.{key}", "BAD_VALUE",
                     f"{key} 必须是非负整数")
            elif val != actual:
                _err(out, f"emba.counts.{key}", "COUNT_MISMATCH",
                     f"counts.{key}={val}，实际 {actual}")
        by_type = counts.get("by_type")
        if not isinstance(by_type, dict):
            _err(out, "emba.counts.by_type", "MISSING", "缺少 counts.by_type 对象")
        else:
            actual_types: Dict[str, int] = {}
            for row in facts:
                typ = row.get("type")
                if isinstance(typ, str):
                    actual_types[typ] = actual_types.get(typ, 0) + 1
            for typ, val in by_type.items():
                if typ not in FACT_TYPES:
                    _err(out, f"emba.counts.by_type.{typ}", "BAD_ENUM",
                         f"未知事实类型：{typ!r}")
                if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                    _err(out, f"emba.counts.by_type.{typ}", "BAD_VALUE",
                         "类型计数必须是非负整数")
                elif val != actual_types.get(typ, 0):
                    _err(out, f"emba.counts.by_type.{typ}", "COUNT_MISMATCH",
                         f"by_type.{typ}={val}，实际 {actual_types.get(typ, 0)}")
            for typ in sorted(actual_types):
                if typ not in by_type:
                    _err(out, f"emba.counts.by_type.{typ}", "COUNT_MISMATCH",
                         f"缺少类型计数 {typ}")
        for key, kind in (("static-discovery", "static-discovery"),
                          ("runtime-process", "runtime-process"),
                          ("port-response", "port-response")):
            if key not in counts:
                continue
            val = counts.get(key)
            actual = sum(1 for row in facts
                         if (row.get("value") or {}).get("observation") == kind)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                _err(out, f"emba.counts.{key}", "BAD_VALUE",
                     "观察计数必须是非负整数")
            elif val != actual:
                _err(out, f"emba.counts.{key}", "COUNT_MISMATCH",
                     f"counts.{key}={val}，实际 {actual}")

    status = obj.get("status")
    if status == "parsed" and errors:
        _err(out, "emba.status", "STATUS_INCONSISTENT",
             "status=parsed 但 errors 非空")
    if status in ("partial", "failed") and not errors:
        _err(out, "emba.status", "STATUS_INCONSISTENT",
             f"status={status} 但 errors 为空")
    if status == "failed":
        fatal_codes = {"F50_MISSING", "F50_EMPTY", "F50_CORRUPT",
                       "EMBA_VERSION_MISSING", "EMBA_VERSION_MISMATCH",
                       "FIRMWARE_MISMATCH", "MISSING_REQUIRED_ARTIFACT"}
        if not any(row.get("code") in fatal_codes for row in errors):
            _err(out, "emba.status", "STATUS_INCONSISTENT",
                 "status=failed 但没有致命错误码")
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
    # ── intent/1.1：调度所需的优先级、依赖、尝试次数与结果 ──────────────
    if "priority" in obj and obj["priority"] is not None:
        prio = obj["priority"]
        if not isinstance(prio, int) or isinstance(prio, bool) \
                or not (INTENT_PRIORITY_RANGE[0] <= prio <= INTENT_PRIORITY_RANGE[1]):
            _err(out, "intent.priority", "OUT_OF_RANGE",
                 "priority 必须是 0..100 的整数")
    if "depends_on" in obj and obj["depends_on"] is not None:
        _str_list(out, obj, "intent", "depends_on", required=False, allow_empty=True)
    _opt_int(out, obj, "intent", "attempts")
    if "outcome" in obj and obj["outcome"] is not None:
        _enum(out, obj, "intent", "outcome", INTENT_OUTCOMES)
    if "result_refs" in obj and obj["result_refs"] is not None:
        _str_list(out, obj, "intent", "result_refs", required=False, allow_empty=True)
    failure = obj.get("last_failure")
    if failure is not None:
        if not isinstance(failure, dict):
            _err(out, "intent.last_failure", "BAD_TYPE", "last_failure 必须是对象")
        else:
            _req(out, failure, "intent.last_failure", "code", str)
            _req(out, failure, "intent.last_failure", "message", str)
            if "retryable" in failure and not isinstance(failure["retryable"], bool):
                _err(out, "intent.last_failure.retryable", "BAD_TYPE",
                     "retryable 必须是布尔值")
            for key in ("category", "at"):
                if key in failure and not isinstance(failure[key], str):
                    _err(out, f"intent.last_failure.{key}", "BAD_TYPE",
                         f"{key} 必须是字符串")
    for key in ("preconditions", "stop_conditions", "expected_outputs"):
        if key in obj and obj[key] is not None:
            _str_list(out, obj, "intent", key, required=False, allow_empty=True)
    worker = obj.get("worker")
    if worker is not None and not isinstance(worker, str):
        _err(out, "intent.worker", "BAD_TYPE", "worker 必须是字符串或 null")
    lease = obj.get("lease")
    if lease is not None:
        if not isinstance(lease, dict):
            _err(out, "intent.lease", "BAD_TYPE", "lease 必须是对象或 null")
        else:
            for key in ("worker", "acquired_at", "heartbeat_at", "expires_at"):
                if key in lease and not isinstance(lease[key], str):
                    _err(out, f"intent.lease.{key}", "BAD_TYPE",
                         f"lease.{key} 必须是字符串")
            if "ttl_seconds" in lease:
                ttl = lease["ttl_seconds"]
                if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1:
                    _err(out, "intent.lease.ttl_seconds", "OUT_OF_RANGE",
                         "lease.ttl_seconds 必须是 >=1 的整数")
            if isinstance(worker, str) and isinstance(lease.get("worker"), str) \
                    and lease["worker"] != worker:
                _err(out, "intent.lease.worker", "MISMATCH",
                     "lease.worker 必须与 Intent 的 worker 一致")
    if obj.get("status") == "claimed":
        if not isinstance(worker, str) or not worker.strip():
            _err(out, "intent.worker", "MISSING", "claimed 状态必须记录 worker")
        if not isinstance(obj.get("claimed_at"), str) or not obj.get("claimed_at"):
            _err(out, "intent.claimed_at", "MISSING", "claimed 状态必须记录 claimed_at")
        attempts = obj.get("attempts")
        if obj.get("schema") == "intent/1.1" and (
                not isinstance(attempts, int) or isinstance(attempts, bool)
                or attempts < 1):
            _err(out, "intent.attempts", "MISSING",
                 "intent/1.1 的 claimed 状态必须记录第几次尝试 attempts")
    if obj.get("status") in ("done", "failed", "cancelled"):
        if not isinstance(obj.get("concluded_at"), str) or not obj.get("concluded_at"):
            _err(out, "intent.concluded_at", "MISSING",
                 "结束状态必须记录 concluded_at")
    if obj.get("schema") == "intent/1.1" and obj.get("status") == "failed":
        if not failure:
            _err(out, "intent.last_failure", "MISSING",
                 "intent/1.1 失败必须记录 last_failure，不能只写 failed")
        if obj.get("outcome") not in ("failed", "blocked", "timed_out"):
            _err(out, "intent.outcome", "MISSING",
                 "失败必须记录 outcome=failed|blocked|timed_out")
    if obj.get("schema") == "intent/1.1" and obj.get("status") == "done":
        if obj.get("outcome") not in ("success", "partial", "not_applicable"):
            _err(out, "intent.outcome", "MISSING",
                 "完成必须记录 outcome=success|partial|not_applicable")
    return out


def _rule_template(value: Any, path: str, out: List[Dict[str, str]]) -> None:
    """模板只允许 {fact_id}/{fact_type}/{target}/{value.KEY} 这类占位符。

    不在这里做渲染（渲染需要具体 Fact）；只拒绝空占位与未闭合花括号，
    避免规则文件里出现 {value.foo 这种到运行时才炸的拼写错误。
    """
    if not isinstance(value, str):
        _err(out, path, "BAD_TYPE", "模板必须是字符串")
        return
    if not value.strip():
        _err(out, path, "EMPTY", "模板不得为空")
        return
    depth = 0
    for ch in value:
        if ch == "{":
            depth += 1
            if depth > 1:
                _err(out, path, "BAD_TEMPLATE", "模板占位符不得嵌套")
                return
        elif ch == "}":
            depth -= 1
            if depth < 0:
                _err(out, path, "BAD_TEMPLATE", "模板出现未配对的 }")
                return
    if depth != 0:
        _err(out, path, "BAD_TEMPLATE", "模板出现未配对的 {")


def validate_scheduler_rules(obj: Any) -> List[Dict[str, str]]:
    """SchedulerRules：Fact→Intent 的确定性规则；规则是配置，不是脚本。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "rules", "scheduler-rules"):
        return out
    if "version" in obj and obj["version"] is not None \
            and not isinstance(obj["version"], str):
        _err(out, "rules.version", "BAD_TYPE", "version 必须是字符串")
    rows = _list_of_dicts(out, obj, "rules", "rules")
    if not rows:
        _err(out, "rules.rules", "EMPTY", "规则集至少要有一条规则")
    seen = set()
    for i, rule in enumerate(rows):
        path = f"rules.rules[{i}]"
        rid = rule.get("id")
        _req(out, rule, path, "id", str)
        if isinstance(rid, str) and rid:
            if rid in seen:
                _err(out, f"{path}.id", "DUPLICATE_ID", f"规则 ID 重复：{rid}")
            seen.add(rid)
            if not re.match(r"^R-[A-Za-z0-9][A-Za-z0-9._-]*$", rid):
                _err(out, f"{path}.id", "BAD_VALUE",
                     "规则 ID 必须形如 R-<字母数字>，只含字母/数字/._-")
        _req(out, rule, path, "version", str)
        if "enabled" in rule and not isinstance(rule["enabled"], bool):
            _err(out, f"{path}.enabled", "BAD_TYPE", "enabled 必须是布尔值")
        when = rule.get("when")
        if not isinstance(when, dict):
            _err(out, f"{path}.when", "MISSING", "缺少 when 条件对象")
        else:
            ft = when.get("fact_type")
            if isinstance(ft, str):
                types = [ft]
            elif isinstance(ft, list) and ft:
                types = ft
            else:
                _err(out, f"{path}.when.fact_type", "MISSING",
                     "when.fact_type 必须是非空字符串或非空数组")
                types = []
            for j, t in enumerate(types):
                if not isinstance(t, str) or t not in FACT_TYPES:
                    _err(out, f"{path}.when.fact_type[{j}]", "BAD_ENUM",
                         f"{t!r} 不是已知 Fact 类型")
            for key in ("value_present", "value_truthy"):
                if key in when and when[key] is not None:
                    _str_list(out, when, f"{path}.when", key,
                              required=False, allow_empty=True)
            if "value_equals" in when and when["value_equals"] is not None:
                ve = when["value_equals"]
                if not isinstance(ve, dict) or not ve:
                    _err(out, f"{path}.when.value_equals", "BAD_TYPE",
                         "value_equals 必须是非空对象")
                else:
                    for k, v in ve.items():
                        if not isinstance(k, str) or not k:
                            _err(out, f"{path}.when.value_equals", "BAD_KEY",
                                 "value_equals 的键必须是非空字符串")
                        if not isinstance(v, (str, int, float, bool)) and v is not None:
                            _err(out, f"{path}.when.value_equals.{k}", "BAD_TYPE",
                                 "value_equals 只接受标量")
            known = {"fact_type", "value_present", "value_truthy", "value_equals"}
            for key in when:
                if key not in known:
                    _err(out, f"{path}.when.{key}", "UNKNOWN_FIELD",
                         "未知条件字段（拼错的谓词不会被静默忽略）")
        want = rule.get("intent")
        if not isinstance(want, dict):
            _err(out, f"{path}.intent", "MISSING", "缺少 intent 模板对象")
        else:
            _enum(out, want, f"{path}.intent", "type", INTENT_TYPES)
            _req(out, want, f"{path}.intent", "description", str)
            _rule_template(want.get("description"), f"{path}.intent.description", out)
            _req(out, want, f"{path}.intent", "target", str)
            _rule_template(want.get("target"), f"{path}.intent.target", out)
            if "priority" in want and want["priority"] is not None:
                prio = want["priority"]
                if not isinstance(prio, int) or isinstance(prio, bool) \
                        or not (INTENT_PRIORITY_RANGE[0] <= prio <= INTENT_PRIORITY_RANGE[1]):
                    _err(out, f"{path}.intent.priority", "OUT_OF_RANGE",
                         "priority 必须是 0..100 的整数")
            if "params" in want and want["params"] is not None \
                    and not isinstance(want["params"], dict):
                _err(out, f"{path}.intent.params", "BAD_TYPE", "params 必须是对象")
            _opt_int(out, want, f"{path}.intent", "timeout_seconds", minimum=1)
            _opt_int(out, want, f"{path}.intent", "max_retries")
            if isinstance(want.get("max_retries"), int) \
                    and want["max_retries"] > 10:
                _err(out, f"{path}.intent.max_retries", "OUT_OF_RANGE",
                     "max_retries 不得超过 10")
            for key in ("stop_conditions", "expected_outputs"):
                if key in want and want[key] is not None:
                    _str_list(out, want, f"{path}.intent", key,
                              required=False, allow_empty=True)
        if "depends_on" in rule and rule["depends_on"] is not None:
            deps = _str_list(out, rule, path, "depends_on",
                             required=False, allow_empty=True)
            for j, dep in enumerate(deps):
                if dep == rid:
                    _err(out, f"{path}.depends_on[{j}]", "SELF_DEPENDENCY",
                         "规则不得依赖自身")
    # 依赖必须指向同一规则集里的规则；跨文件引用会让调度结果依赖加载顺序。
    for i, rule in enumerate(rows):
        for j, dep in enumerate(rule.get("depends_on") or []):
            if isinstance(dep, str) and dep and dep not in seen:
                _err(out, f"rules.rules[{i}].depends_on[{j}]", "DEPENDENCY_MISSING",
                     f"依赖的规则不存在：{dep}")
    return out


def validate_scheduler_result(obj: Any) -> List[Dict[str, str]]:
    """SchedulerResult：调度执行结果；必须把失败与「没有发现」分开记录。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "result", "scheduler-result"):
        return out
    _req(out, obj, "result", "intent_id", str)
    _req(out, obj, "result", "run_id", str)
    _hex(out, obj, "result", "firmware_sha256")
    _enum(out, obj, "result", "status", EMULATION_STATUSES)
    if "worker" in obj and obj["worker"] is not None:
        _opt_str(out, obj, "result", "worker")
    if "attempt" in obj and obj["attempt"] is not None:
        _opt_int(out, obj, "result", "attempt", minimum=1)
    evidence = _list_of_dicts(out, obj, "result", "evidence", required=False)
    facts = _list_of_dicts(out, obj, "result", "facts", required=False)
    ev_ids, fact_ids = set(), set()
    for i, ev in enumerate(evidence):
        sub = f"result.evidence[{i}]"
        _bind(out, ev, sub, obj.get("run_id"), obj.get("firmware_sha256"))
        for err in validate_evidence_record(ev):
            out.append({"path": f"{sub}.{err['path']}", "code": err["code"],
                        "message": err["message"]})
        eid = ev.get("evidence_id")
        if isinstance(eid, str):
            if eid in ev_ids:
                _err(out, f"{sub}.evidence_id", "DUPLICATE_ID", "证据 ID 重复")
            ev_ids.add(eid)
    for i, fact in enumerate(facts):
        sub = f"result.facts[{i}]"
        _bind(out, fact, sub, obj.get("run_id"), obj.get("firmware_sha256"))
        for err in validate_fact(fact):
            out.append({"path": f"{sub}.{err['path']}", "code": err["code"],
                        "message": err["message"]})
        fid = fact.get("fact_id")
        if isinstance(fid, str):
            if fid in fact_ids:
                _err(out, f"{sub}.fact_id", "DUPLICATE_ID", "事实 ID 重复")
            fact_ids.add(fid)
        for ref in fact.get("evidence_refs") or []:
            if isinstance(ref, str) and ref not in ev_ids:
                _err(out, f"{sub}.evidence_refs", "DANGLING_EVIDENCE",
                     f"事实引用的证据不在结果里：{ref!r}")
    _artifact_list(out, obj, "result", "artifacts")
    if "resource_usage" in obj and obj["resource_usage"] is not None \
            and not isinstance(obj["resource_usage"], dict):
        _err(out, "result.resource_usage", "BAD_TYPE", "resource_usage 必须是对象")
    _req(out, obj, "result", "finished_at", str)
    if "started_at" in obj and obj["started_at"] is not None:
        _opt_str(out, obj, "result", "started_at")
    if "limitations" in obj and obj["limitations"] is not None:
        _str_list(out, obj, "result", "limitations", required=False, allow_empty=True)
    status = obj.get("status")
    failure = obj.get("failure")
    if status in ("FAILED", "BLOCKED", "TIMED_OUT"):
        if not isinstance(failure, dict):
            _err(out, "result.failure", "MISSING",
                 "失败/阻断/超时必须给出 failure{code,message,category,retryable}")
        else:
            for key in ("code", "message", "category"):
                _req(out, failure, "result.failure", key, str)
            if not isinstance(failure.get("retryable"), bool):
                _err(out, "result.failure.retryable", "BAD_TYPE",
                     "retryable 必须是布尔值")
    elif failure is not None and not isinstance(failure, dict):
        _err(out, "result.failure", "BAD_TYPE", "failure 必须是对象")
    if status == "PARTIAL":
        lim = obj.get("limitations")
        if not isinstance(lim, list) or not lim:
            _err(out, "result.limitations", "MISSING",
                 "PARTIAL 必须列出未覆盖内容，不能静默折叠为成功")
    if status in ("SUCCESS", "PARTIAL") and not evidence and not facts:
        _err(out, "result", "RESULT_NO_OUTPUT",
             "成功/部分成功的结果必须至少产生一条 Evidence 或 Fact")
    return out


def validate_tool_index(obj: Any) -> List[Dict[str, str]]:
    """ToolIndex：Phase 0 工具盘点结果；不能让“没探测”伪装成“可用”。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "index", "tool-index"):
        return out
    _req(out, obj, "index", "tool_version", str)
    _req(out, obj, "index", "generated_at", str)
    _req(out, obj, "index", "profile", str)
    _enum(out, obj, "index", "profile",
          ("all", "phase0", "extract", "static", "dynamic"))
    _req(out, obj, "index", "notes", str)
    host = obj.get("host")
    if not isinstance(host, dict):
        _err(out, "index.host", "MISSING", "host 必须是对象")
    else:
        for key in ("os", "release", "machine", "python"):
            _req(out, host, "index.host", key, str)
        _req(out, host, "index.host", "is_windows", bool)
    registry = obj.get("registry")
    if not isinstance(registry, dict):
        _err(out, "index.registry", "MISSING", "registry 必须是对象")
    else:
        _req(out, registry, "index.registry", "version", str)
        _req(out, registry, "index.registry", "tools", int)
        _req(out, registry, "index.registry", "source", str)
    tools = _list_of_dicts(out, obj, "index", "tools")
    tool_ids = set()
    status_counts = {"available": 0, "degraded": 0, "missing": 0}
    kinds = ("cli", "family", "python-module", "python-runtime", "container-image")
    for i, tool in enumerate(tools):
        sub = f"index.tools[{i}]"
        tid = tool.get("id")
        if not isinstance(tid, str) or not tid.strip():
            _err(out, sub + ".id", "BAD_TYPE", "工具 ID 必须是非空字符串")
        elif tid in tool_ids:
            _err(out, sub + ".id", "DUPLICATE_ID", "工具 ID 重复：%r" % tid)
        else:
            tool_ids.add(tid)
        _enum(out, tool, sub, "kind", kinds)
        _req(out, tool, sub, "status", str)
        _enum(out, tool, sub, "status", ("available", "degraded", "missing"))
        _req(out, tool, sub, "found", bool)
        _str_list(out, tool, sub, "capabilities", required=False, allow_empty=True)
        phases = _str_list(out, tool, sub, "phases", required=False, allow_empty=True)
        for pid in phases:
            if pid not in BOARD_PHASES:
                _err(out, sub + ".phases", "BAD_ENUM", "未知阶段：%r" % pid)
        if "version" in tool and tool["version"] is not None:
            _opt_str(out, tool, sub, "version")
        if "path" in tool and tool["path"] is not None:
            _opt_str(out, tool, sub, "path")
        found = tool.get("found")
        status = tool.get("status")
        if found is True and status == "missing":
            _err(out, sub, "STATUS_MISMATCH", "found=true 不能同时 status=missing")
        if found is False and status in ("available", "degraded"):
            _err(out, sub, "STATUS_MISMATCH", "found=false 时 status 只能是 missing")
        if status in status_counts:
            status_counts[status] += 1
        probe = tool.get("probe")
        if probe is not None:
            if not isinstance(probe, dict):
                _err(out, sub + ".probe", "BAD_TYPE", "probe 必须是对象")
            else:
                _str_list(out, probe, sub + ".probe", "argv",
                          required=False, allow_empty=True)
                _req(out, probe, sub + ".probe", "ok", bool)
                _opt_int(out, probe, sub + ".probe", "duration_ms")
                _opt_str(out, probe, sub + ".probe", "error")
                if "returncode" in probe and probe["returncode"] is not None \
                        and (not isinstance(probe["returncode"], int)
                             or isinstance(probe["returncode"], bool)):
                    _err(out, sub + ".probe.returncode", "BAD_TYPE",
                         "returncode 必须是整数或 null")
        inst = tool.get("install")
        if inst is not None:
            if not isinstance(inst, dict):
                _err(out, sub + ".install", "BAD_TYPE", "install 必须是对象")
            else:
                _req(out, inst, sub + ".install", "kind", str)
                _req(out, inst, sub + ".install", "auto", bool)
                _str_list(out, inst, sub + ".install", "argv",
                          required=False, allow_empty=True)
                _str_list(out, inst, sub + ".install", "requires",
                          required=False, allow_empty=True)
                _opt_text(out, inst, sub + ".install", "shell")
                _opt_text(out, inst, sub + ".install", "docs")
                _opt_text(out, inst, sub + ".install", "notes")
        fb = tool.get("fallback")
        if fb is not None:
            if not isinstance(fb, dict):
                _err(out, sub + ".fallback", "BAD_TYPE", "fallback 必须是对象")
            else:
                _str_list(out, fb, sub + ".fallback", "tools",
                          required=False, allow_empty=True)
                _req(out, fb, sub + ".fallback", "impact", str)
    summary = obj.get("summary")
    if not isinstance(summary, dict):
        _err(out, "index.summary", "MISSING", "summary 必须是对象")
    else:
        for key in ("total", "available", "degraded", "missing"):
            val = summary.get(key)
            if not isinstance(val, int) or isinstance(val, bool) or val < 0:
                _err(out, "index.summary." + key, "BAD_VALUE",
                     "必须是非负整数")
        if isinstance(summary.get("total"), int) and summary["total"] != len(tools):
            _err(out, "index.summary.total", "MISMATCH",
                 "total=%r 与 tools 数量 %d 不一致" % (summary["total"], len(tools)))
        total = summary.get("total")
        if isinstance(total, int) and not isinstance(total, bool) \
                and summary.get("available") == status_counts["available"] \
                and summary.get("degraded") == status_counts["degraded"] \
                and summary.get("missing") == status_counts["missing"]:
            pass
        elif isinstance(total, int) and not isinstance(total, bool):
            if summary.get("available") != status_counts["available"]:
                _err(out, "index.summary.available", "MISMATCH",
                     "与 tools.status=available 数量不一致")
            if summary.get("degraded") != status_counts["degraded"]:
                _err(out, "index.summary.degraded", "MISMATCH",
                     "与 tools.status=degraded 数量不一致")
            if summary.get("missing") != status_counts["missing"]:
                _err(out, "index.summary.missing", "MISMATCH",
                     "与 tools.status=missing 数量不一致")
    caps = _list_of_dicts(out, obj, "index", "capabilities", required=False)
    cap_ids = set()
    for i, cap in enumerate(caps):
        sub = f"index.capabilities[{i}]"
        cid = cap.get("id")
        if not isinstance(cid, str) or not cid.strip():
            _err(out, sub + ".id", "BAD_TYPE", "能力 ID 必须是非空字符串")
        elif cid in cap_ids:
            _err(out, sub + ".id", "DUPLICATE_ID", "能力 ID 重复：%r" % cid)
        else:
            cap_ids.add(cid)
        _req(out, cap, sub, "name", str)
        _enum(out, cap, sub, "status", ("available", "degraded", "missing", "manual"))
        phases = _str_list(out, cap, sub, "phases", required=False, allow_empty=True)
        for pid in phases:
            if pid not in BOARD_PHASES:
                _err(out, sub + ".phases", "BAD_ENUM", "未知阶段：%r" % pid)
        _str_list(out, cap, sub, "available_tools", required=False, allow_empty=True)
        _str_list(out, cap, sub, "missing_tools", required=False, allow_empty=True)
        if "primary" in cap and cap["primary"] is not None:
            _opt_text(out, cap, sub, "primary")
        if "manual" in cap and cap["manual"] is not None:
            _opt_text(out, cap, sub, "manual")
        if "fallback" in cap and cap["fallback"] is not None:
            _opt_text(out, cap, sub, "fallback")
    phases_out = _list_of_dicts(out, obj, "index", "phases")
    phase_ids = set()
    for i, phase in enumerate(phases_out):
        sub = f"index.phases[{i}]"
        pid = phase.get("id")
        if pid not in BOARD_PHASES:
            _err(out, sub + ".id", "BAD_ENUM", "未知阶段：%r" % pid)
        elif pid in phase_ids:
            _err(out, sub + ".id", "DUPLICATE_ID", "阶段重复：%r" % pid)
        else:
            phase_ids.add(pid)
        _req(out, phase, sub, "name", str)
        _enum(out, phase, sub, "status", ("ready", "partial", "blocked", "n/a"))
        _str_list(out, phase, sub, "available_tools", required=False, allow_empty=True)
        _str_list(out, phase, sub, "missing_tools", required=False, allow_empty=True)
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


def validate_emulation_plan(obj: Any) -> List[Dict[str, str]]:
    """EmulationPlan：启动前的可复核计划，不代表已经启动成功。

    契约只保证「计划自洽」：ready 必须有内核、镜像和 QEMU argv；blocked 必须
    至少有一个带下一步的阻断项。QEMU 在宿主机不可见不等于计划不可执行——真正
    的二进制在沙箱镜像里，所以 available=false 仍然可以是 ready。
    """
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "plan", "emulation-plan"):
        return out
    for key in ("plan_id", "tool", "version", "status", "rootfs",
                "qemu", "network", "budget"):
        if key not in obj or obj.get(key) is None:
            _err(out, "plan." + key, "MISSING", "必填字段缺失")
    _enum(out, obj, "plan", "status", ("ready", "blocked"))
    for key in ("run_id", "intent_id"):
        if obj.get(key) is not None and not isinstance(obj[key], str):
            _err(out, "plan." + key, "BAD_TYPE", key + " 必须是字符串或 null")
    if obj.get("firmware_sha256") is not None:
        _hex(out, obj, "plan", "firmware_sha256")
    if "firmware_root" in obj and obj["firmware_root"] is not None \
            and not isinstance(obj["firmware_root"], str):
        _err(out, "plan.firmware_root", "BAD_TYPE", "firmware_root 必须是字符串")

    blockers = _list_of_dicts(out, obj, "plan", "blockers", required=False)
    for i, row in enumerate(blockers):
        sub = "plan.blockers[%d]" % i
        _req(out, row, sub, "code", str)
        _req(out, row, sub, "message", str)
        _req(out, row, sub, "next_action", str)
    warnings = obj.get("warnings")
    if warnings is not None and not isinstance(warnings, list):
        _err(out, "plan.warnings", "BAD_TYPE", "warnings 必须是数组")
    elif isinstance(warnings, list):
        for i, item in enumerate(warnings):
            if not isinstance(item, str):
                _err(out, "plan.warnings[%d]" % i, "BAD_TYPE", "警告必须是字符串")
    limitations = obj.get("limitations")
    if limitations is not None and not isinstance(limitations, list):
        _err(out, "plan.limitations", "BAD_TYPE", "limitations 必须是数组")
    elif isinstance(limitations, list):
        for i, item in enumerate(limitations):
            if not isinstance(item, str):
                _err(out, "plan.limitations[%d]" % i, "BAD_TYPE",
                     "限制必须是字符串")

    rootfs = obj.get("rootfs")
    if isinstance(rootfs, dict):
        _req(out, rootfs, "plan.rootfs", "path", str)
        _enum(out, rootfs, "plan.rootfs", "kind", ("directory", "image"))
        if rootfs.get("sha256") is not None:
            _hex(out, rootfs, "plan.rootfs", "sha256")
        _opt_int(out, rootfs, "plan.rootfs", "bytes")
        if rootfs.get("files") is not None:
            _opt_int(out, rootfs, "plan.rootfs", "files")
        if rootfs.get("selected_init") is not None \
                and not isinstance(rootfs["selected_init"], str):
            _err(out, "plan.rootfs.selected_init", "BAD_TYPE",
                 "selected_init 必须是字符串或 null")
        if not isinstance(rootfs.get("init_candidates"), list):
            _err(out, "plan.rootfs.init_candidates", "MISSING",
                 "init_candidates 必须是数组（可为空）")

    kernel = obj.get("kernel")
    if kernel is not None:
        if not isinstance(kernel, dict):
            _err(out, "plan.kernel", "BAD_TYPE", "kernel 必须是对象或 null")
        else:
            for key in ("path", "mount_path", "sha256", "format"):
                _req(out, kernel, "plan.kernel", key, str)
            _opt_int(out, kernel, "plan.kernel", "size")
    image = obj.get("image")
    if image is not None:
        if not isinstance(image, dict):
            _err(out, "plan.image", "BAD_TYPE", "image 必须是对象或 null")
        else:
            _req(out, image, "plan.image", "path", str)
            _req(out, image, "plan.image", "mount_path", str)
            if "exists" in image and not isinstance(image["exists"], bool):
                _err(out, "plan.image.exists", "BAD_TYPE", "exists 必须是布尔值")
            if image.get("sha256") is not None:
                _hex(out, image, "plan.image", "sha256")

    qemu = obj.get("qemu")
    if isinstance(qemu, dict):
        _req(out, qemu, "plan.qemu", "binary", str)
        if not isinstance(qemu.get("argv"), list):
            _err(out, "plan.qemu.argv", "MISSING", "qemu.argv 必须是数组")
        else:
            for i, item in enumerate(qemu["argv"]):
                if not isinstance(item, str):
                    _err(out, "plan.qemu.argv[%d]" % i, "BAD_TYPE",
                         "argv 元素必须是字符串")
            if not qemu["argv"]:
                _err(out, "plan.qemu.argv", "EMPTY", "qemu.argv 不得为空")
        if "available" in qemu and not isinstance(qemu["available"], bool):
            _err(out, "plan.qemu.available", "BAD_TYPE", "available 必须是布尔值")
        if qemu.get("cpu") is not None and not isinstance(qemu["cpu"], str):
            _err(out, "plan.qemu.cpu", "BAD_TYPE", "cpu 必须是字符串或 null")

    net = obj.get("network")
    if isinstance(net, dict):
        _enum(out, net, "plan.network", "mode", ("none", "user"))
        if "hostfwd" in net and not isinstance(net["hostfwd"], list):
            _err(out, "plan.network.hostfwd", "BAD_TYPE", "hostfwd 必须是数组")
    budget = obj.get("budget")
    if isinstance(budget, dict):
        _opt_int(out, budget, "plan.budget", "timeout_s", minimum=1)
        _opt_int(out, budget, "plan.budget", "attempts", minimum=1)
        if "memory" in budget and not isinstance(budget["memory"], str):
            _err(out, "plan.budget.memory", "BAD_TYPE", "memory 必须是字符串")
        if "cpus" in budget and not isinstance(budget["cpus"], (str, int)):
            _err(out, "plan.budget.cpus", "BAD_TYPE", "cpus 必须是字符串或整数")

    if obj.get("status") == "ready":
        if not isinstance(blockers, list) or blockers:
            _err(out, "plan.blockers", "STATUS_INCONSISTENT",
                 "status=ready 时 blockers 必须为空")
        if kernel is None:
            _err(out, "plan.kernel", "MISSING", "ready 计划必须有内核")
        if image is None:
            _err(out, "plan.image", "MISSING", "ready 计划必须有 rootfs 镜像")
    elif obj.get("status") == "blocked":
        if not blockers:
            _err(out, "plan.blockers", "STATUS_INCONSISTENT",
                 "status=blocked 时 blockers 不得为空；不能只写一句警告")
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
        _opt_int(out, payload, "event.payload", "attempts", minimum=1)
        if "outcome" in payload and payload["outcome"] is not None:
            _enum(out, payload, "event.payload", "outcome", INTENT_OUTCOMES)
        if "result_refs" in payload and payload["result_refs"] is not None:
            _str_list(out, payload, "event.payload", "result_refs",
                      required=False, allow_empty=True)
        if "reason" in payload and payload["reason"] is not None \
                and not isinstance(payload["reason"], str):
            _err(out, "event.payload.reason", "BAD_TYPE", "reason 必须是字符串")
        lf = payload.get("last_failure")
        if lf is not None:
            if not isinstance(lf, dict):
                _err(out, "event.payload.last_failure", "BAD_TYPE",
                     "last_failure 必须是对象")
            else:
                _req(out, lf, "event.payload.last_failure", "code", str)
                _req(out, lf, "event.payload.last_failure", "message", str)
                if "retryable" in lf and not isinstance(lf["retryable"], bool):
                    _err(out, "event.payload.last_failure.retryable", "BAD_TYPE",
                         "retryable 必须是布尔值")
    elif typ == "INTENT_LEASE_RENEWED":
        _req(out, payload, "event.payload", "intent_id", str)
        _req(out, payload, "event.payload", "worker", str)
        lease = payload.get("lease")
        if not isinstance(lease, dict):
            _err(out, "event.payload.lease", "MISSING", "续租必须带 lease 对象")
        else:
            for key in ("worker", "acquired_at", "heartbeat_at", "expires_at"):
                _req(out, lease, "event.payload.lease", key, str)
            ttl = lease.get("ttl_seconds")
            if not isinstance(ttl, int) or isinstance(ttl, bool) or ttl < 1:
                _err(out, "event.payload.lease.ttl_seconds", "OUT_OF_RANGE",
                     "ttl_seconds 必须是 >=1 的整数")
    elif typ == "INTENT_COMPLETED_WITH_RESULTS":
        _req(out, payload, "event.payload", "intent_id", str)
        _req(out, payload, "event.payload", "worker", str)
        _opt_int(out, payload, "event.payload", "attempt", minimum=1)
        result = payload.get("result")
        if not isinstance(result, dict):
            _err(out, "event.payload.result", "MISSING",
                 "结果回写必须携带完整 scheduler-result")
        else:
            out.extend(validate_scheduler_result(result))
            if result.get("intent_id") != payload.get("intent_id"):
                _err(out, "event.payload.result.intent_id", "INTENT_MISMATCH",
                     "结果 intent_id 与事件不一致")
            if isinstance(run_id, str) and result.get("run_id") != run_id:
                _err(out, "event.payload.result.run_id", "RUN_MISMATCH",
                     "结果不属于当前黑板 run")
    elif typ == "BACKTRACK":
        _validate_backtrack(out, payload, "event.payload")
    return out


def validate_qiling_plan(obj: Any) -> List[Dict[str, str]]:
    """QilingPlan：定向仿真的只读计划；ready 只表示参数齐全，不代表能跑。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "plan", "qiling-plan"):
        return out
    _req(out, obj, "plan", "tool", str)
    _req(out, obj, "plan", "version", str)
    _req(out, obj, "plan", "plan_id", str)
    if isinstance(obj.get("plan_id"), str) and not re.match(r"^QPL-[0-9a-f]{12}$",
                                                           obj["plan_id"]):
        _err(out, "plan.plan_id", "BAD_VALUE", "plan_id 必须是 QPL- 加 12 位十六进制")
    status = obj.get("status")
    _enum(out, obj, "plan", "status", ("ready", "blocked"))
    _req(out, obj, "plan", "firmware_root", str)
    target = obj.get("target")
    if not isinstance(target, dict):
        _err(out, "plan.target", "MISSING", "缺少 target 对象")
        target = {}
    else:
        _req(out, target, "plan.target", "host_path", str)
        if "container_path" in target and target["container_path"] is not None \
                and not isinstance(target["container_path"], str):
            _err(out, "plan.target.container_path", "BAD_TYPE",
                 "container_path 必须是字符串或 null")
        if target.get("sha256") is not None:
            _hex(out, target, "plan.target", "sha256")
        _opt_int(out, target, "plan.target", "size")
        if target.get("arch") is not None:
            _enum(out, target, "plan.target", "arch", ARCHES)
        if target.get("bits") is not None and target["bits"] not in (32, 64):
            _err(out, "plan.target.bits", "BAD_VALUE", "bits 只能是 32 或 64")
        if target.get("endian") is not None:
            _enum(out, target, "plan.target", "endian", ("little", "big"))
        if target.get("elf_type") is not None and not isinstance(target["elf_type"], str):
            _err(out, "plan.target.elf_type", "BAD_TYPE", "elf_type 必须是字符串")
        if target.get("interpreter") is not None \
                and not isinstance(target["interpreter"], str):
            _err(out, "plan.target.interpreter", "BAD_TYPE",
                 "interpreter 必须是字符串或 null")
        _str_list(out, target, "plan.target", "needed", required=False,
                  allow_empty=True)
        if "inside_rootfs" in target and not isinstance(target["inside_rootfs"], bool):
            _err(out, "plan.target.inside_rootfs", "BAD_TYPE",
                 "inside_rootfs 必须是布尔值")
    rootfs = obj.get("rootfs")
    if not isinstance(rootfs, dict):
        _err(out, "plan.rootfs", "MISSING", "缺少 rootfs 对象")
    else:
        _req(out, rootfs, "plan.rootfs", "host_path", str)
        if "container_path" in rootfs and rootfs["container_path"] is not None \
                and not isinstance(rootfs["container_path"], str):
            _err(out, "plan.rootfs.container_path", "BAD_TYPE",
                 "container_path 必须是字符串或 null")
        _opt_int(out, rootfs, "plan.rootfs", "file_count")
    runtime = obj.get("runtime")
    if not isinstance(runtime, dict):
        _err(out, "plan.runtime", "MISSING", "缺少 runtime 对象")
    else:
        _enum(out, runtime, "plan.runtime", "backend", ("qiling",))
        _req(out, runtime, "plan.runtime", "image", str)
        _enum(out, runtime, "plan.runtime", "network", ("none",))
        _enum(out, runtime, "plan.runtime", "mode", ("sandbox",))
        _req(out, runtime, "plan.runtime", "python", str)
    execution = obj.get("execution")
    if not isinstance(execution, dict):
        _err(out, "plan.execution", "MISSING", "缺少 execution 对象")
    else:
        _str_list(out, execution, "plan.execution", "argv", required=True)
        _req(out, execution, "plan.execution", "guest_argv0", str)
        if "target" in execution and execution["target"] is not None \
                and not isinstance(execution["target"], str):
            _err(out, "plan.execution.target", "BAD_TYPE", "target 必须是字符串或 null")
        if "rootfs" in execution and execution["rootfs"] is not None \
                and not isinstance(execution["rootfs"], str):
            _err(out, "plan.execution.rootfs", "BAD_TYPE", "rootfs 必须是字符串或 null")
        env = execution.get("env")
        if not isinstance(env, dict):
            _err(out, "plan.execution.env", "MISSING", "env 必须是对象")
        else:
            for key, value in env.items():
                if not isinstance(key, str) or not isinstance(value, str):
                    _err(out, "plan.execution.env", "BAD_TYPE",
                         "env 的键和值都必须是字符串")
        for key in ("stdin", "stdin_host"):
            if key in execution and execution[key] is not None \
                    and not isinstance(execution[key], str):
                _err(out, f"plan.execution.{key}", "BAD_TYPE",
                     f"{key} 必须是字符串或 null")
    hooks = _list_of_dicts(out, obj, "plan", "hooks")
    if not hooks:
        _err(out, "plan.hooks", "EMPTY", "hooks 不能为空：没有 Hook 就没有事件")
    seen_hooks = set()
    for i, hook in enumerate(hooks):
        sub = f"plan.hooks[{i}]"
        _enum(out, hook, sub, "mechanism", ("syscall", "api", "libc", "address"))
        _req(out, hook, sub, "name", str)
        _enum(out, hook, sub, "phase", ("enter", "exit"))
        key = (hook.get("mechanism"), hook.get("name"), hook.get("phase"))
        if key in seen_hooks:
            _err(out, sub, "DUPLICATE", f"Hook 重复：{key}")
        seen_hooks.add(key)
        args = _list_of_dicts(out, hook, sub, "args")
        for j, arg in enumerate(args):
            _req(out, arg, f"{sub}.args[{j}]", "name", str)
            _enum(out, arg, f"{sub}.args[{j}]", "kind",
                  ("string", "string_array", "int", "hex", "pointer"))
        sig = hook.get("signature")
        if sig is not None:
            if not isinstance(sig, dict):
                _err(out, f"{sub}.signature", "BAD_TYPE", "signature 必须是对象")
            else:
                for key2, value2 in sig.items():
                    if not isinstance(key2, str) or not isinstance(value2, str):
                        _err(out, f"{sub}.signature", "BAD_TYPE",
                             "signature 的键和值都必须是字符串")
    filters = obj.get("filters")
    if not isinstance(filters, dict):
        _err(out, "plan.filters", "MISSING", "缺少 filters 对象")
    else:
        _req(out, filters, "plan.filters", "version", str)
        _str_list(out, filters, "plan.filters", "trigger_markers",
                  required=False, allow_empty=True)
        _str_list(out, filters, "plan.filters", "sink_hooks",
                  required=False, allow_empty=True)
        _opt_int(out, filters, "plan.filters", "max_events", minimum=1)
        _opt_int(out, filters, "plan.filters", "max_string", minimum=1)
        if status == "ready" and not filters.get("trigger_markers"):
            _err(out, "plan.filters.trigger_markers", "MISSING",
                 "ready 计划必须至少有一个 trigger_marker，否则永远无法区分触发")
        if status == "ready" and not filters.get("sink_hooks"):
            _err(out, "plan.filters.sink_hooks", "MISSING",
                 "ready 计划必须至少有一个 sink_hook")
    budget = obj.get("budget")
    if not isinstance(budget, dict):
        _err(out, "plan.budget", "MISSING", "缺少 budget 对象")
    else:
        _opt_int(out, budget, "plan.budget", "timeout_s", minimum=1)
        if budget.get("timeout_s") is None:
            _err(out, "plan.budget.timeout_s", "MISSING", "必须给出 timeout_s")
    blockers = _list_of_dicts(out, obj, "plan", "blockers")
    for i, blocker in enumerate(blockers):
        sub = f"plan.blockers[{i}]"
        _req(out, blocker, sub, "code", str)
        _req(out, blocker, sub, "message", str)
        _req(out, blocker, sub, "next_action", str)
    if status == "ready" and blockers:
        _err(out, "plan.blockers", "BAD_VALUE", "ready 计划不得带阻断项")
    if status == "blocked" and not blockers:
        _err(out, "plan.blockers", "EMPTY", "blocked 计划必须说明阻断原因")
    if status == "ready":
        if not isinstance(obj.get("run_id"), str) or not obj["run_id"].strip():
            _err(out, "plan.run_id", "MISSING", "ready 计划必须有非空 run_id")
        if not isinstance(obj.get("intent_id"), str) or not obj["intent_id"].strip():
            _err(out, "plan.intent_id", "MISSING", "ready 计划必须有非空 intent_id")
        _hex(out, obj, "plan", "firmware_sha256")
        if isinstance(target, dict) and not target.get("container_path"):
            _err(out, "plan.target.container_path", "MISSING",
                 "ready 计划必须有容器内目标路径")
        if isinstance(rootfs, dict) and not rootfs.get("container_path"):
            _err(out, "plan.rootfs.container_path", "MISSING",
                 "ready 计划必须有容器内 rootfs 路径")
        if isinstance(execution, dict) and not execution.get("argv"):
            _err(out, "plan.execution.argv", "EMPTY", "ready 计划必须有 argv")
    else:
        if obj.get("run_id") is not None and not isinstance(obj["run_id"], str):
            _err(out, "plan.run_id", "BAD_TYPE", "run_id 必须是字符串或 null")
        if obj.get("intent_id") is not None and not isinstance(obj["intent_id"], str):
            _err(out, "plan.intent_id", "BAD_TYPE", "intent_id 必须是字符串或 null")
        if obj.get("firmware_sha256") is not None \
                and not isinstance(obj["firmware_sha256"], str):
            _err(out, "plan.firmware_sha256", "BAD_TYPE",
                 "firmware_sha256 必须是字符串")
    _str_list(out, obj, "plan", "limitations", required=False, allow_empty=True)
    return out


def validate_qiling_event(obj: Any) -> List[Dict[str, str]]:
    """QilingEvent：归一化后的 Hook 观察；sink-hit 必须真的命中过滤标记。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "event", "qiling-event"):
        return out
    _req(out, obj, "event", "event_id", str)
    if isinstance(obj.get("event_id"), str) and not re.match(
            r"^QE-[0-9a-f]{12}$", obj["event_id"]):
        _err(out, "event.event_id", "BAD_VALUE", "event_id 必须是 QE- 加 12 位十六进制")
    _opt_int(out, obj, "event", "seq", minimum=1)
    if obj.get("seq") is None:
        _err(out, "event.seq", "MISSING", "事件必须有 seq")
    _req(out, obj, "event", "run_id", str)
    _hex(out, obj, "event", "firmware_sha256")
    _enum(out, obj, "event", "mechanism", ("syscall", "api", "libc", "other"))
    _req(out, obj, "event", "hook", str)
    _enum(out, obj, "event", "phase", ("enter", "exit", "signal"))
    _enum(out, obj, "event", "classified_as", ("sink-hit", "observed", "failure"))
    if obj.get("phase") == "signal" and obj.get("classified_as") != "failure":
        _err(out, "event.phase", "BAD_VALUE",
             "phase=signal 只能用于 failure 事件")
    if not isinstance(obj.get("trigger"), bool):
        _err(out, "event.trigger", "BAD_TYPE", "trigger 必须是布尔值")
    elif obj.get("classified_as") == "sink-hit" and not obj["trigger"]:
        _err(out, "event.trigger", "BAD_VALUE", "sink-hit 必须 trigger=true")
    elif obj.get("classified_as") in ("observed", "failure") and obj["trigger"]:
        _err(out, "event.trigger", "BAD_VALUE",
             "observed/failure 不得声称 trigger=true")
    if not isinstance(obj.get("args"), dict):
        _err(out, "event.args", "MISSING", "事件缺少 args 对象")
    src = obj.get("source")
    if not isinstance(src, dict):
        _err(out, "event.source", "MISSING", "事件缺少 source")
    else:
        _req(out, src, "event.source", "path", str)
        if "line" in src and (not isinstance(src["line"], int) or src["line"] < 1):
            _err(out, "event.source.line", "BAD_VALUE", "line 必须是正整数")
    flt = obj.get("filter")
    if not isinstance(flt, dict):
        _err(out, "event.filter", "MISSING", "事件缺少 filter 记录")
    else:
        _req(out, flt, "event.filter", "version", str)
        _req(out, flt, "event.filter", "rule_id", str)
        _req(out, flt, "event.filter", "reason", str)
        if obj.get("classified_as") == "sink-hit" and flt.get("rule_id") != "trigger-marker":
            _err(out, "event.filter.rule_id", "BAD_VALUE",
                 "sink-hit 的规则必须是 trigger-marker")
    if "context" in obj and not isinstance(obj["context"], dict):
        _err(out, "event.context", "BAD_TYPE", "context 必须是对象")
    return out


def validate_qiling_import(obj: Any) -> List[Dict[str, str]]:
    """QilingImport：计划、事件、证据、事实与 EmulationResult 的交付包。"""
    out: List[Dict[str, str]] = []
    if not _schema(out, obj, "import", "qiling-import"):
        return out
    adapter = obj.get("adapter")
    if not isinstance(adapter, dict):
        _err(out, "import.adapter", "MISSING", "缺少 adapter 对象")
    else:
        _req(out, adapter, "import.adapter", "name", str)
        _req(out, adapter, "import.adapter", "version", str)
    run_id = obj.get("run_id")
    if not isinstance(run_id, str) or not run_id.strip():
        _err(out, "import.run_id", "MISSING", "缺少非空 run_id")
    intent_id = obj.get("intent_id")
    if not isinstance(intent_id, str) or not intent_id.strip():
        _err(out, "import.intent_id", "MISSING", "缺少非空 intent_id")
    _hex(out, obj, "import", "firmware_sha256")
    status = obj.get("status")
    _enum(out, obj, "import", "status", ("parsed", "partial", "failed"))
    _req(out, obj, "import", "plan_id", str)
    if isinstance(obj.get("plan_id"), str) and not re.match(
            r"^QPL-[0-9a-f]{12}$", obj["plan_id"]):
        _err(out, "import.plan_id", "BAD_VALUE", "plan_id 格式不正确")
    backend = obj.get("backend")
    if not isinstance(backend, dict):
        _err(out, "import.backend", "MISSING", "缺少 backend 对象")
    else:
        _enum(out, backend, "import.backend", "name", ("qiling",))
        _req(out, backend, "import.backend", "version", str)
        _req(out, backend, "import.backend", "image", str)
    execution = obj.get("execution")
    if not isinstance(execution, dict):
        _err(out, "import.execution", "MISSING", "缺少 execution 对象")
    else:
        _enum(out, execution, "import.execution", "mode",
              ("sandbox", "offline"))
        if execution.get("host_fallback") is not False:
            _err(out, "import.execution.host_fallback", "POLICY",
                 "host_fallback 必须为 false：Qiling 不得在宿主机执行")
        if not isinstance(execution.get("sandbox"), dict):
            _err(out, "import.execution.sandbox", "MISSING",
                 "缺少 sandbox 执行记录")
    result = obj.get("result")
    if not isinstance(result, dict):
        _err(out, "import.result", "MISSING", "缺少 EmulationResult")
    else:
        for e in validate_emulation_result(result):
            out.append({"path": "import." + e["path"], "code": e["code"],
                        "message": e["message"]})
        for key in ("run_id", "intent_id", "firmware_sha256"):
            if result.get(key) != obj.get(key):
                _err(out, f"import.result.{key}", "MISMATCH",
                     f"result.{key} 与导入包不一致")
        rstatus = result.get("status")
        if rstatus in ("FAILED", "BLOCKED", "TIMED_OUT") and status != "failed":
            _err(out, "import.status", "MISMATCH",
                 "结果失败/阻断/超时时导入状态必须是 failed")
        if rstatus == "PARTIAL" and status != "partial":
            _err(out, "import.status", "MISMATCH",
                 "结果 PARTIAL 时导入状态必须是 partial")
        if rstatus == "SUCCESS" and status == "failed":
            _err(out, "import.status", "MISMATCH", "结果 SUCCESS 不能标 failed")
    events = obj.get("events")
    if not isinstance(events, list):
        _err(out, "import.events", "MISSING", "缺少 events 数组")
        events = []
    event_ids = set()
    for i, event in enumerate(events):
        sub = f"import.events[{i}]"
        errs = validate_qiling_event(event)
        for e in errs:
            out.append({"path": sub + "." + e["path"].split(".", 1)[-1],
                        "code": e["code"], "message": e["message"]})
        if isinstance(event, dict):
            eid = event.get("event_id")
            if eid in event_ids:
                _err(out, sub, "DUPLICATE", f"事件 ID 重复：{eid}")
            event_ids.add(eid)
            if event.get("run_id") != run_id:
                _err(out, sub + ".run_id", "RUN_MISMATCH",
                     "事件 run_id 与导入包不一致")
            if event.get("firmware_sha256") != obj.get("firmware_sha256"):
                _err(out, sub + ".firmware_sha256", "FIRMWARE_MISMATCH",
                     "事件固件哈希与导入包不一致")
    evidence = obj.get("evidence")
    if not isinstance(evidence, list):
        _err(out, "import.evidence", "MISSING", "缺少 evidence 数组")
        evidence = []
    evidence_ids = set()
    for i, ev in enumerate(evidence):
        sub = f"import.evidence[{i}]"
        for e in validate_evidence_record(ev, sub):
            out.append(e)
        if isinstance(ev, dict):
            eid = ev.get("evidence_id")
            if eid in evidence_ids:
                _err(out, sub, "DUPLICATE", f"证据 ID 重复：{eid}")
            evidence_ids.add(eid)
            if ev.get("run_id") != run_id:
                _err(out, sub + ".run_id", "RUN_MISMATCH",
                     "证据 run_id 与导入包不一致")
            if ev.get("firmware_sha256") != obj.get("firmware_sha256"):
                _err(out, sub + ".firmware_sha256", "FIRMWARE_MISMATCH",
                     "证据固件哈希与导入包不一致")
    facts = obj.get("facts")
    if not isinstance(facts, list):
        _err(out, "import.facts", "MISSING", "缺少 facts 数组")
        facts = []
    fact_ids = set()
    for i, fact in enumerate(facts):
        sub = f"import.facts[{i}]"
        for e in validate_fact(fact):
            out.append({"path": sub + "." + e["path"].split(".", 1)[-1],
                        "code": e["code"], "message": e["message"]})
        if isinstance(fact, dict):
            fid = fact.get("fact_id")
            if fid in fact_ids:
                _err(out, sub, "DUPLICATE", f"事实 ID 重复：{fid}")
            fact_ids.add(fid)
            if fact.get("run_id") != run_id:
                _err(out, sub + ".run_id", "RUN_MISMATCH",
                     "事实 run_id 与导入包不一致")
            if fact.get("firmware_sha256") != obj.get("firmware_sha256"):
                _err(out, sub + ".firmware_sha256", "FIRMWARE_MISMATCH",
                     "事实固件哈希与导入包不一致")
            for ref in fact.get("evidence_refs") or []:
                if ref not in evidence_ids:
                    _err(out, sub + ".evidence_refs", "DANGLING_REF",
                         f"事实引用了不存在的证据：{ref}")
    if isinstance(result, dict):
        for ref in result.get("evidence_refs") or []:
            if ref not in evidence_ids:
                _err(out, "import.result.evidence_refs", "DANGLING_REF",
                     f"结果引用了不存在的证据：{ref}")
    errors = obj.get("errors")
    if not isinstance(errors, list):
        _err(out, "import.errors", "MISSING", "缺少 errors 数组")
        errors = []
    for i, err in enumerate(errors):
        if not isinstance(err, dict):
            _err(out, f"import.errors[{i}]", "BAD_TYPE", "错误项必须是对象")
            continue
        _req(out, err, f"import.errors[{i}]", "code", str)
        _req(out, err, f"import.errors[{i}]", "message", str)
    if status == "parsed" and errors:
        _err(out, "import.status", "MISMATCH",
             "status=parsed 时 errors 必须为空；不完整不得伪装完整")
    _str_list(out, obj, "import", "limitations", required=True)
    filters = obj.get("filters")
    if not isinstance(filters, dict):
        _err(out, "import.filters", "MISSING", "缺少 filters 记录")
    counts = obj.get("counts")
    if not isinstance(counts, dict):
        _err(out, "import.counts", "MISSING", "缺少 counts 汇总")
    else:
        for key in ("events", "sink_hits", "observed", "failure_events",
                    "parse_errors", "evidence", "facts"):
            _opt_int(out, counts, "import.counts", key)
        if counts.get("events") != len(events):
            _err(out, "import.counts.events", "MISMATCH",
                 "counts.events 与实际事件数不一致")
        if counts.get("evidence") != len(evidence):
            _err(out, "import.counts.evidence", "MISMATCH",
                 "counts.evidence 与证据数不一致")
        if counts.get("facts") != len(facts):
            _err(out, "import.counts.facts", "MISMATCH",
                 "counts.facts 与事实数不一致")
        actual_sink = sum(1 for e in events if isinstance(e, dict)
                          and e.get("classified_as") == "sink-hit")
        actual_obs = sum(1 for e in events if isinstance(e, dict)
                         and e.get("classified_as") == "observed")
        actual_fail = sum(1 for e in events if isinstance(e, dict)
                          and e.get("classified_as") == "failure")
        if counts.get("sink_hits") != actual_sink:
            _err(out, "import.counts.sink_hits", "MISMATCH",
                 "counts.sink_hits 与实际 sink-hit 数不一致")
        if counts.get("observed") != actual_obs:
            _err(out, "import.counts.observed", "MISMATCH",
                 "counts.observed 与实际 observed 数不一致")
        if counts.get("failure_events") != actual_fail:
            _err(out, "import.counts.failure_events", "MISMATCH",
                 "counts.failure_events 与实际失败事件数不一致")
        if isinstance(counts.get("by_classification"), dict):
            by = counts["by_classification"]
            if by.get("sink-hit") != actual_sink or by.get("observed") != actual_obs \
                    or by.get("failure") != actual_fail:
                _err(out, "import.counts.by_classification", "MISMATCH",
                     "by_classification 与事件分类不一致")
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
    "emba-import": validate_emba_import,
    "emulation-plan": validate_emulation_plan,
    "fact": validate_fact,
    "intent": validate_intent,
    "hint": validate_hint,
    "emulation-result": validate_emulation_result,
    "board-state": validate_board_state,
    "board-event": validate_board_event,
    "qiling-plan": validate_qiling_plan,
    "qiling-event": validate_qiling_event,
    "qiling-import": validate_qiling_import,
    "scheduler-rules": validate_scheduler_rules,
    "scheduler-result": validate_scheduler_result,
    "tool-index": validate_tool_index,
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