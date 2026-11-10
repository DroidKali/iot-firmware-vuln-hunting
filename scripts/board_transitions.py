#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Candidate / Intent 状态机与漏洞类型专属验证规则（ROADMAP M1）。

为什么需要它
------------
Candidate 的 status 以前只是报告里的一个字符串：`hypothesis` 可以直接写成
`validated`，只要报告文案配合，门禁没有任何理由拒绝。M1 把「什么状态能到什么
状态」和「`validated` / `confirmed` 需要哪些证据」变成可执行规则：

* 状态转换先经过白名单，终态不可重开（重开只能走 BACKTRACK 事件）；
* `validated` / `confirmed` 不是「找到一个疑似点」的同义词，必须给出与漏洞类型
  匹配的证据、验证判据、触发上下文，并绑定同一个 run 与固件；`validated` 是
  静态/仿真链路已闭合，`confirmed` 是动态复现后的最终态；
* `ACCEPTED_WITH_RISK` 只属于风险处置，不属于 Candidate 状态。把它写进
  status 会被拒绝，而不是被当成一种「已验证」；
* 所有失败返回结构化 code，调用方（board_store / 报告 / 门禁）不用解析中文。

用法
----
    python scripts/board_transitions.py graph
    python scripts/board_transitions.py graph --json graph.json
    python scripts/board_transitions.py check --candidate cand.json \
        --to validated --evidence ev.json --policy policy.json \
        --run-id RUN-1 --firmware-sha256 <64hex>

退出码：0 允许；1 拒绝；2 用法/IO 错误。纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

try:
    from contracts import validate_evidence as _validate_evidence
except Exception:  # pragma: no cover - 单独拷走时状态机必须拒绝升级（fail-closed）
    _validate_evidence = None

VERSION = "1.1"
EVIDENCE_SCHEMA = "evidence/1.1"
HEX64 = re.compile(r"^[0-9a-fA-F]{64}$")

#: Candidate 状态转换白名单。终态不在键里：重开必须走 BACKTRACK。
TRANSITIONS: Dict[str, tuple] = {
    "hypothesis": ("pending_static_analysis", "not_applicable",
                   "blocked_by_environment"),
    "pending_static_analysis": ("pending_dynamic_validation", "validated",
                                "not_found", "not_reproduced",
                                "not_applicable", "blocked_by_environment"),
    "pending_dynamic_validation": ("validated", "confirmed", "not_reproduced",
                                   "blocked_by_environment", "not_applicable"),
    "validated": ("confirmed", "not_reproduced", "blocked_by_environment"),
    "blocked_by_environment": ("pending_static_analysis",
                               "pending_dynamic_validation", "not_applicable"),
}

#: 终态：没有出边。若确需重开，记录 BACKTRACK 并新建候选，不修改历史结论。
TERMINAL_STATES = ("confirmed", "not_found", "not_reproduced", "not_applicable")

#: 报告里常用的大写写法。VERIFIED 的持久化写法是 confirmed；validated 是它之前的
#: 静态/仿真闭合态，仍可继续升到 confirmed。
STATE_ALIASES = {
    "VERIFIED": "confirmed",
    "CONFIRMED": "confirmed",
    "HYPOTHESIS": "hypothesis",
    "NOT_REPRODUCED": "not_reproduced",
    "NOT_APPLICABLE": "not_applicable",
    "NOT_FOUND": "not_found",
    "BLOCKED_BY_ENVIRONMENT": "blocked_by_environment",
    "PENDING_STATIC_ANALYSIS": "pending_static_analysis",
    "PENDING_DYNAMIC_VALIDATION": "pending_dynamic_validation",
}

#: 风险处置：与「事实是否成立」正交。不是 Candidate status。
RISK_DISPOSITIONS = ("accepted", "mitigated", "transferred", "avoided", "pending")
RISK_ALIASES = {
    "ACCEPTED_WITH_RISK": "accepted",
    "ACCEPTED": "accepted",
    "MITIGATED": "mitigated",
    "TRANSFERRED": "transferred",
    "AVOIDED": "avoided",
    "PENDING": "pending",
}

#: 每种漏洞类型「算验证成功」的最低证据要求。
#:
#: required_criteria 是调用方必须逐条给出且为 true 的判据；evidence_types 至少
#: 命中一种；trigger_events 用来确认证据里出现过真实触发（system() 只是库函数
#: 调用，execve 才是系统调用，因此两者分开列）。
VERIFICATION_RULES: Dict[str, Dict[str, Any]] = {
    "command-injection": {
        "evidence_types": ("dynamic", "emulation", "static"),
        "required_criteria": ("sink_reachable", "user_controlled_input",
                              "command_execution"),
        "trigger_events": ("execve", "system", "popen", "posix_spawn"),
        "requires_trigger": True,
    },
    "buffer-overflow": {
        "evidence_types": ("dynamic", "emulation", "fuzzing"),
        "required_criteria": ("input_length_unbounded", "memory_write",
                              "crash_or_control"),
        "trigger_events": ("crash", "segfault", "sigsegv", "heap-overflow"),
        "requires_trigger": True,
    },
    "path-traversal": {
        "evidence_types": ("dynamic", "emulation", "static"),
        "required_criteria": ("user_controlled_path", "traversal_reaches_file",
                              "file_access"),
        "trigger_events": ("open", "fopen", "access", "stat"),
        "requires_trigger": True,
    },
    "hardcoded-credential": {
        "evidence_types": ("static", "manual"),
        "required_criteria": ("credential_present", "credential_effective",
                              "not_placeholder"),
        "trigger_events": (),
        "requires_trigger": False,
    },
    "auth-bypass": {
        "evidence_types": ("dynamic", "emulation", "static"),
        "required_criteria": ("protected_endpoint_reachable", "check_bypassed",
                              "unauthorized_access"),
        "trigger_events": ("http-request", "authenticate", "authorize"),
        "requires_trigger": True,
    },
    "ssrf": {
        "evidence_types": ("dynamic", "emulation", "static"),
        "required_criteria": ("url_controlled", "request_issued", "target_reachable"),
        "trigger_events": ("connect", "http-request", "dns-query"),
        "requires_trigger": True,
    },
    "deserialization": {
        "evidence_types": ("dynamic", "emulation", "static"),
        "required_criteria": ("untrusted_data_reaches_parser",
                              "gadget_or_type_confusion", "code_execution"),
        "trigger_events": ("execve", "dlopen", "malloc"),
        "requires_trigger": True,
    },
    "other": {
        "evidence_types": ("static", "dynamic", "emulation", "fuzzing", "manual"),
        "required_criteria": ("evidence_supports_claim", "scope_matched"),
        "trigger_events": (),
        "requires_trigger": False,
    },
}

#: 规则是否要求证据绑定具体目标（ELF / 共享库 / 可执行文件）。
#: hardcoded-credential 可能来自配置文件，other 可能没有二进制目标；这两类只有在
#: 策略或候选显式给出 target_sha256 时才强制绑定。
#:
#: confirmed 是最终结论，不能用静态线索或候选自带的 PoC 字段自证：运行时类漏洞
#: 必须有动态/仿真证据；只有硬编码凭据这类静态事实允许 static/manual。
CONFIRM_EVIDENCE_TYPES: Dict[str, tuple] = {
    "command-injection": ("dynamic", "emulation"),
    "buffer-overflow": ("dynamic", "emulation", "fuzzing"),
    "path-traversal": ("dynamic", "emulation"),
    "hardcoded-credential": ("static", "manual"),
    "auth-bypass": ("dynamic", "emulation"),
    "ssrf": ("dynamic", "emulation"),
    "deserialization": ("dynamic", "emulation"),
    "other": ("dynamic", "emulation", "manual"),
}
for _rule_name, _rule in VERIFICATION_RULES.items():
    _rule["requires_target"] = _rule_name not in ("hardcoded-credential", "other")
    _rule["confirm_evidence_types"] = CONFIRM_EVIDENCE_TYPES[_rule_name]

#: Intent 状态机：open → claimed → done/failed；claim 可以被释放回 open。
INTENT_TRANSITIONS: Dict[str, tuple] = {
    "open": ("claimed", "cancelled"),
    "claimed": ("done", "failed", "cancelled", "open"),
    "done": (),
    "failed": (),
    "cancelled": (),
}


def normalize_state(state: Any) -> str:
    """把报告常用的大写状态归一为持久化的小写状态；未知值原样返回。"""
    if not isinstance(state, str):
        return ""
    s = state.strip()
    return STATE_ALIASES.get(s, STATE_ALIASES.get(s.upper(), s.lower()))


def normalize_risk_disposition(value: Any) -> str:
    """把 ACCEPTED_WITH_RISK 之类的报告措辞归一为风险处置枚举。"""
    if not isinstance(value, str):
        return ""
    s = value.strip()
    return RISK_ALIASES.get(s, RISK_ALIASES.get(s.upper(), s.lower()))


def transitions_from(state: Any) -> List[str]:
    """返回某状态的合法后继；终态返回空列表。"""
    return list(TRANSITIONS.get(normalize_state(state), ()))


def _rule_for(candidate: Dict[str, Any], policy: Dict[str, Any]) -> tuple:
    vuln_type = policy.get("vuln_type") or candidate.get("category") \
        or candidate.get("type") or "other"
    if not isinstance(vuln_type, str):
        return "", None
    return vuln_type, VERIFICATION_RULES.get(vuln_type)


def _result(ok: bool, code: str, message: str, **extra: Any) -> Dict[str, Any]:
    out: Dict[str, Any] = {"ok": ok, "code": code, "message": message}
    out.update(extra)
    return out


def _valid_run_id(value: Any) -> bool:
    """run_id 必须是非空、无空白、无控制字符的字符串，最长 128。"""
    if not isinstance(value, str) or not value or len(value) > 128:
        return False
    if value != value.strip():
        return False
    return all((not ch.isspace()) and ord(ch) >= 0x20 and ord(ch) != 0x7f for ch in value)


def _is_sha256(value: Any) -> bool:
    return isinstance(value, str) and bool(HEX64.match(value))


def _parse_ts(value: Any) -> Optional[datetime]:
    """解析带时区的 ISO-8601；naive 时间视为非法，避免本地时区歧义。"""
    if not isinstance(value, str) or not value.strip():
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        dt = datetime.fromisoformat(text)
    except ValueError:
        return None
    if dt.tzinfo is None:
        return None
    return dt.astimezone(timezone.utc)


def _evidence_signature(ev: Dict[str, Any]) -> str:
    """证据内容签名：优先 content_sha256，否则对判定相关字段做 canonical hash。"""
    content = ev.get("content_sha256")
    if _is_sha256(content):
        return str(content).lower()
    material = {k: ev.get(k) for k in
                ("type", "status", "target_sha256", "event", "artifact", "source")
                if k in ev}
    try:
        blob = json.dumps(material, ensure_ascii=False, sort_keys=True,
                          separators=(",", ":"))
    except (TypeError, ValueError):
        blob = repr(material)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def validate_transition(candidate: Any, to_state: str,
                        evidence: Optional[Sequence[Dict[str, Any]]] = None,
                        policy: Optional[Dict[str, Any]] = None,
                        run_id: Optional[str] = None,
                        firmware_sha256: Optional[str] = None,
                        now: Optional[str] = None) -> Dict[str, Any]:
    """校验一次 Candidate 状态转换，返回 {ok, code, message, ...}。

    * 普通状态只检查白名单与终态；
    * 进入 `validated` / `confirmed` 时执行严格验证：候选自带 run_id 与
      firmware_sha256、证据全部为 evidence/1.1 且同 run 同固件、目标哈希绑定、
      证据生命周期与冲突检查；
    * 任何失败都不修改候选对象，调用方可以安全地先校验再落日志。
    """
    if not isinstance(candidate, dict):
        return _result(False, "BAD_CANDIDATE", "候选必须是 JSON 对象")
    raw_from = candidate.get("status")
    frm = normalize_state(raw_from)
    to = normalize_state(to_state)
    if frm not in TRANSITIONS and frm not in TERMINAL_STATES:
        return _result(False, "BAD_STATE", f"未知的候选状态：{raw_from!r}",
                       **{"from": frm, "to": to})
    if to not in TRANSITIONS and to not in TERMINAL_STATES:
        return _result(False, "BAD_STATE", f"未知的目标状态：{to_state!r}",
                       **{"from": frm, "to": to})
    if frm == to:
        return _result(False, "SAME_STATE", "源状态与目标状态相同，不构成转换",
                       **{"from": frm, "to": to})
    if frm in TERMINAL_STATES:
        return _result(False, "TERMINAL_STATE",
                       f"{frm} 是终态；重开必须走 BACKTRACK 并保留历史",
                       **{"from": frm, "to": to})
    allowed = TRANSITIONS.get(frm, ())
    if to not in allowed:
        return _result(False, "ILLEGAL_TRANSITION",
                       f"不允许 {frm} → {to}；合法后继：{list(allowed)}",
                       **{"from": frm, "to": to, "allowed": list(allowed)})
    if to not in ("validated", "confirmed"):
        return _result(True, "OK", f"允许 {frm} → {to}",
                       **{"from": frm, "to": to})

    # ── validated / confirmed：类型化验证 ───────────────────────────────────
    if _validate_evidence is None:
        return _result(False, "CONTRACT_UNAVAILABLE",
                       "contracts.py 不可用或导入失败，拒绝在没有契约校验时提升候选状态",
                       **{"from": frm, "to": to})

    if policy is not None and not isinstance(policy, dict):
        return _result(False, "POLICY_INVALID",
                       "验证策略必须是 JSON 对象；空对象可以省略，但不能传数组或标量",
                       **{"from": frm, "to": to})
    pol: Dict[str, Any] = policy or {}
    vuln_type, rule = _rule_for(candidate, pol)
    if rule is None:
        return _result(False, "TYPE_RULE_MISSING",
                       f"未知漏洞类型 {vuln_type!r}；没有对应验证规则就不能标 {to}",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})
    cand_type = candidate.get("category") or candidate.get("type")
    if pol.get("vuln_type") and cand_type and pol["vuln_type"] != cand_type:
        return _result(False, "CANDIDATE_TYPE_MISMATCH",
                       f"策略类型 {pol['vuln_type']!r} 与候选类型 {cand_type!r} 不一致",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})

    # 候选自身必须声明审计运行与固件；参数只用于交叉校验，不作为兜底。
    cand_run_raw = candidate.get("run_id")
    if cand_run_raw is None:
        return _result(False, "CANDIDATE_RUN_ID_MISSING",
                       "候选缺少 run_id；提升状态前必须绑定一次审计运行",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})
    if not _valid_run_id(cand_run_raw):
        return _result(False, "CANDIDATE_RUN_ID_INVALID",
                       f"候选 run_id 非法：{cand_run_raw!r}",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})
    cand_run = cand_run_raw
    if run_id is not None and run_id != cand_run:
        return _result(False, "RUN_ID_MISMATCH",
                       f"调用方 run_id {run_id!r} 与候选 {cand_run!r} 不一致",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})

    cand_fw_raw = candidate.get("firmware_sha256")
    if cand_fw_raw is None:
        return _result(False, "CANDIDATE_FIRMWARE_MISSING",
                       "候选缺少 firmware_sha256；提升状态前必须绑定固件哈希",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})
    if not _is_sha256(cand_fw_raw):
        return _result(False, "CANDIDATE_FIRMWARE_INVALID",
                       "候选 firmware_sha256 必须是 64 位十六进制 sha256",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})
    cand_fw = cand_fw_raw.lower()
    if firmware_sha256 is not None:
        if not _is_sha256(firmware_sha256):
            return _result(False, "FIRMWARE_HASH_INVALID",
                           "调用方 firmware_sha256 必须是 64 位十六进制 sha256",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})
        if firmware_sha256.lower() != cand_fw:
            return _result(False, "FIRMWARE_MISMATCH",
                           "调用方 firmware_sha256 与候选不一致",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})

    # 目标哈希：策略与候选可以各自给出，但必须一致；规则要求时必须有。
    target: Optional[str] = None
    pol_target = pol.get("target_sha256")
    if pol_target is not None:
        if not _is_sha256(pol_target):
            return _result(False, "TARGET_HASH_INVALID",
                           "策略 target_sha256 必须是 64 位十六进制 sha256",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})
        target = pol_target.lower()
    cand_target = candidate.get("target_sha256")
    if cand_target is not None:
        if not _is_sha256(cand_target):
            return _result(False, "TARGET_HASH_INVALID",
                           "候选 target_sha256 必须是 64 位十六进制 sha256",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})
        cand_target = cand_target.lower()
        if target is not None and target != cand_target:
            return _result(False, "TARGET_HASH_MISMATCH",
                           "策略与候选的 target_sha256 不一致",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})
        target = target or cand_target
    target_required = bool(rule.get("requires_target")) or target is not None
    if target_required and target is None:
        return _result(False, "TARGET_HASH_REQUIRED",
                       f"{vuln_type} 的验证必须绑定具体目标的 target_sha256",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})

    if evidence is None:
        raw_rows: List[Any] = []
    elif isinstance(evidence, dict):
        raw_rows = [evidence]
    else:
        try:
            raw_rows = list(evidence)
        except TypeError:
            return _result(False, "EVIDENCE_INVALID",
                           "evidence 必须是证据对象或证据对象列表",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})
    if not raw_rows:
        return _result(False, "EVIDENCE_REQUIRED",
                       f"{to} 至少需要一条绑定 run 与固件的证据",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})
    if any(not isinstance(e, dict) for e in raw_rows):
        return _result(False, "EVIDENCE_INVALID",
                       "证据列表中存在非对象元素",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})

    rows: List[Dict[str, Any]] = list(raw_rows)
    accepted_types = (rule.get("confirm_evidence_types")
                      if to == "confirmed" else rule["evidence_types"])
    type_hits: List[str] = []
    trigger = False
    structure_errors: List[Dict[str, str]] = []
    for i, ev in enumerate(rows):
        schema = ev.get("schema")
        if schema != EVIDENCE_SCHEMA:
            code = "EVIDENCE_SCHEMA_REQUIRED" if schema is None else "EVIDENCE_SCHEMA_UNSUPPORTED"
            return _result(False, code,
                           f"证据 {i} 必须是 {EVIDENCE_SCHEMA}；弱格式/旧格式不得用于提升状态",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i, "schema": schema})
        try:
            errs = _validate_evidence(ev)
        except Exception as exc:  # noqa: BLE001 - 契约校验器异常必须 fail-closed
            return _result(False, "EVIDENCE_VALIDATOR_ERROR",
                           f"证据 {i} 契约校验异常：{exc}",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        if not isinstance(errs, list):
            return _result(False, "EVIDENCE_VALIDATOR_ERROR",
                           f"证据 {i} 契约校验器返回了非列表结果",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        for err in errs:
            if not isinstance(err, dict) or not isinstance(err.get("path"), str):
                return _result(False, "EVIDENCE_VALIDATOR_ERROR",
                               f"证据 {i} 契约校验器返回了非法错误项",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i})
            sub = err["path"]
            if sub == "evidence":
                sub = ""
            elif sub.startswith("evidence."):
                sub = sub[len("evidence."):]
            structure_errors.append({"path": f"evidence[{i}]" + (f".{sub}" if sub else ""),
                                     "code": str(err.get("code")),
                                     "message": str(err.get("message"))})

        ev_run = ev.get("run_id")
        if not isinstance(ev_run, str) or ev_run != cand_run:
            return _result(False, "EVIDENCE_NOT_BOUND_TO_RUN",
                           f"证据 {i} 属于 {ev_run!r}，候选属于 {cand_run!r}",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        ev_fw = ev.get("firmware_sha256")
        if not isinstance(ev_fw, str) or not ev_fw:
            return _result(False, "EVIDENCE_FIRMWARE_MISSING",
                           f"证据 {i} 缺少 firmware_sha256",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        if not _is_sha256(ev_fw):
            return _result(False, "EVIDENCE_FIRMWARE_INVALID",
                           f"证据 {i} firmware_sha256 不是 64 位十六进制",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        if ev_fw.lower() != cand_fw:
            return _result(False, "FIRMWARE_MISMATCH",
                           f"证据 {i} 绑定的固件与候选不一致",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})

        ev_target = ev.get("target_sha256")
        if target_required:
            if ev_target is None:
                return _result(False, "TARGET_HASH_REQUIRED",
                               f"证据 {i} 缺少 target_sha256",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i})
            if not _is_sha256(ev_target):
                return _result(False, "TARGET_HASH_INVALID",
                               f"证据 {i} target_sha256 不是 64 位十六进制",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i})
            if ev_target.lower() != target:
                return _result(False, "TARGET_HASH_MISMATCH",
                               f"证据 {i} 的目标哈希与期望不一致",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i})
        elif ev_target is not None and not _is_sha256(ev_target):
            return _result(False, "TARGET_HASH_INVALID",
                           f"证据 {i} target_sha256 不是 64 位十六进制",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})

        if ev.get("type") in accepted_types:
            type_hits.append(str(ev.get("type")))
        event = ev.get("event") if isinstance(ev.get("event"), dict) else {}
        if event.get("trigger") is True or event.get("type") in rule["trigger_events"]:
            trigger = True

    if structure_errors:
        return _result(False, "EVIDENCE_INVALID",
                       "证据不符合 evidence/1.1 契约",
                       **{"from": frm, "to": to, "vuln_type": vuln_type,
                          "errors": structure_errors[:8]})

    # 同一 evidence_id 只能指向同一份内容；重复 ID 且内容不同视为冲突。
    id_signatures: Dict[str, str] = {}
    for i, ev in enumerate(rows):
        eid = ev.get("evidence_id")
        if not isinstance(eid, str) or not eid:
            return _result(False, "EVIDENCE_INVALID",
                           f"证据 {i} 缺少 evidence_id",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        sig = _evidence_signature(ev)
        if eid in id_signatures and id_signatures[eid] != sig:
            return _result(False, "EVIDENCE_ID_CONFLICT",
                           f"evidence_id {eid!r} 对应了不同内容",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_id": eid})
        id_signatures[eid] = sig

    if now is not None:
        now_dt = _parse_ts(now)
        if now_dt is None:
            return _result(False, "NOW_INVALID",
                           "now 必须是带时区的 ISO-8601 时间",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})
    else:
        now_dt = datetime.now(timezone.utc)

    selected_ids = set(id_signatures)
    for i, ev in enumerate(rows):
        eid = ev.get("evidence_id")
        if ev.get("revoked") is True:
            return _result(False, "EVIDENCE_REVOKED",
                           f"证据 {i}（{eid}）已被撤销，不得用于提升状态",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        if ev.get("superseded_by") is not None:
            return _result(False, "EVIDENCE_SUPERSEDED",
                           f"证据 {i}（{eid}）已被 {ev.get('superseded_by')!r} 取代",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        if ev.get("expires_at") is not None:
            expires = _parse_ts(ev.get("expires_at"))
            if expires is None:
                return _result(False, "EVIDENCE_EXPIRY_INVALID",
                               f"证据 {i}（{eid}）expires_at 不是带时区的 ISO-8601",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i})
            if expires <= now_dt:
                return _result(False, "EVIDENCE_EXPIRED",
                               f"证据 {i}（{eid}）已于 {ev.get('expires_at')} 过期",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i})
        if ev.get("status") == "failed":
            return _result(False, "EVIDENCE_FAILED",
                           f"证据 {i}（{eid}）状态为 failed，不能证明漏洞成立",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "evidence_index": i})
        supersedes = ev.get("supersedes")
        if isinstance(supersedes, list):
            hit = [x for x in supersedes if isinstance(x, str) and x in selected_ids and x != eid]
            if hit:
                return _result(False, "EVIDENCE_SUPERSEDES_CONFLICT",
                               f"证据 {i}（{eid}）声明取代同时被选中的 {hit[0]!r}",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i, "conflict_with": hit[0]})
        contradicts = ev.get("contradicts")
        if isinstance(contradicts, list):
            hit = [x for x in contradicts if isinstance(x, str) and x in selected_ids and x != eid]
            if hit:
                return _result(False, "EVIDENCE_CONTRADICTION",
                               f"证据 {i}（{eid}）与同时被选中的 {hit[0]!r} 矛盾",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "evidence_index": i, "conflict_with": hit[0]})

    groups: Dict[str, List[Dict[str, Any]]] = {}
    for i, ev in enumerate(rows):
        group = ev.get("conflict_group")
        if isinstance(group, str) and group:
            groups.setdefault(group, []).append({"index": i, "signature": _evidence_signature(ev)})
    for group, items in groups.items():
        signatures = sorted({item["signature"] for item in items})
        if len(signatures) > 1:
            return _result(False, "EVIDENCE_CONFLICT",
                           f"冲突组 {group!r} 内存在结论不一致的证据",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "conflict_group": group})

    if not type_hits:
        if to == "confirmed":
            return _result(False, "CONFIRM_EVIDENCE_REQUIRED",
                           f"confirmed 需要 {'/'.join(accepted_types)} 证据；"
                           "静态线索或候选自带 PoC 不能作为最终结论",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "accepted_types": list(accepted_types)})
        return _result(False, "EVIDENCE_TYPE_NOT_ACCEPTED",
                       f"{vuln_type} 需要 {'/'.join(accepted_types)} 证据",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})

    criteria = pol.get("criteria") if isinstance(pol.get("criteria"), dict) else {}
    missing = [k for k in rule["required_criteria"] if criteria.get(k) is not True]
    if missing:
        return _result(False, "VALIDATION_CRITERIA_NOT_MET",
                       f"缺少或未满足判据：{missing}",
                       **{"from": frm, "to": to, "vuln_type": vuln_type,
                          "missing_criteria": missing})

    # confirmed 不能只写三个 true：每个判据必须指向本轮已选中的 Evidence ID。
    # 这样报告里的「已验证」可以逐条回溯到具体证据，而不是调用方自述。
    if to == "confirmed":
        mapping = pol.get("criterion_evidence")
        if not isinstance(mapping, dict):
            return _result(False, "CONFIRM_CRITERIA_EVIDENCE_REQUIRED",
                           "confirmed 必须在 policy.criterion_evidence 中为每个判据"
                           "给出对应的 Evidence ID",
                           **{"from": frm, "to": to, "vuln_type": vuln_type,
                              "required_criteria": list(rule["required_criteria"])})
        for criterion in rule["required_criteria"]:
            refs_raw = mapping.get(criterion)
            if isinstance(refs_raw, str):
                refs = [refs_raw]
            elif isinstance(refs_raw, list) and refs_raw:
                refs = refs_raw
            else:
                return _result(False, "CONFIRM_CRITERION_UNBOUND",
                               f"判据 {criterion} 没有绑定 Evidence ID",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "criterion": criterion})
            if any(not isinstance(r, str) or not r for r in refs):
                return _result(False, "CONFIRM_EVIDENCE_REF_INVALID",
                               f"判据 {criterion} 的 Evidence ID 必须是非空字符串",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "criterion": criterion})
            unknown = [r for r in refs if r not in selected_ids]
            if unknown:
                return _result(False, "CONFIRM_EVIDENCE_REF_NOT_FOUND",
                               f"判据 {criterion} 引用了未选中的证据：{unknown}",
                               **{"from": frm, "to": to, "vuln_type": vuln_type,
                                  "criterion": criterion, "missing": unknown})

    has_expected = "expected" in pol
    has_actual = "actual" in pol
    if has_expected != has_actual:
        return _result(False, "EXPECTED_ACTUAL_NOT_SUPPORTED",
                       "expected 与 actual 必须同时给出，单独给一方不是验证",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})
    if has_expected and pol.get("expected") != pol.get("actual"):
        return _result(False, "VALIDATION_CRITERIA_NOT_MET",
                       "expected 与 actual 不一致",
                       **{"from": frm, "to": to, "vuln_type": vuln_type})

    if rule["requires_trigger"] and not trigger:
        # validated 允许候选记录里的 PoC 线索作为待复核上下文；confirmed 不接受：
        # 最终结论必须由证据里的真实触发事件支撑，不能由候选自述。
        has_poc = (to != "confirmed" and bool(
            candidate.get("trigger") or candidate.get("poc")
            or candidate.get("poc_path")))
        if not has_poc:
            return _result(False, "MISSING_TRIGGER_CONTEXT",
                           "验证证据没有触发上下文（event.trigger / 触发事件 / PoC）",
                           **{"from": frm, "to": to, "vuln_type": vuln_type})

    return _result(True, "OK", f"允许 {frm} → {to}（{vuln_type}）",
                   **{"from": frm, "to": to, "vuln_type": vuln_type,
                      "target_sha256": target,
                      "evidence_types": sorted(set(type_hits)),
                      "criteria": list(rule["required_criteria"])})


def validate_risk_disposition(row: Any) -> List[Dict[str, str]]:
    """校验风险处置记录；同时拒绝把处置写成 Candidate status。"""
    out: List[Dict[str, str]] = []
    if not isinstance(row, dict):
        return [{"path": "risk", "code": "BAD_TYPE", "message": "风险处置必须是对象"}]
    cand = row.get("status") or row.get("candidate_status")
    if isinstance(cand, str) and cand in RISK_DISPOSITIONS:
        out.append({"path": "risk.status", "code": "RISK_AS_STATUS",
                    "message": "风险处置不是 Candidate 状态；请写 risk.disposition"})
    if isinstance(cand, str) and cand.upper() == "ACCEPTED_WITH_RISK":
        out.append({"path": "risk.status", "code": "RISK_AS_STATUS",
                    "message": "ACCEPTED_WITH_RISK 只能作为风险处置，不能作为候选状态"})
    disp = row.get("disposition")
    if not isinstance(disp, str) or normalize_risk_disposition(disp) not in RISK_DISPOSITIONS:
        out.append({"path": "risk.disposition", "code": "BAD_ENUM",
                    "message": f"disposition 必须是 {list(RISK_DISPOSITIONS)} 之一"})
    for key in ("candidate_id", "reason", "approved_by"):
        if not isinstance(row.get(key), str) or not row.get(key, "").strip():
            out.append({"path": f"risk.{key}", "code": "MISSING",
                        "message": f"{key} 必须是非空字符串"})
    ev = row.get("evidence_refs")
    if not isinstance(ev, list) or not ev:
        out.append({"path": "risk.evidence_refs", "code": "MISSING",
                    "message": "风险处置必须引用证据"})
    return out


def validate_intent_transition(intent: Any, to_status: str,
                               worker: Optional[str] = None) -> Dict[str, Any]:
    """Intent 状态机：claim 必须带 worker，释放回 open 必须清空 worker。"""
    if not isinstance(intent, dict):
        return _result(False, "BAD_INTENT", "Intent 必须是 JSON 对象")
    frm = normalize_state(intent.get("status"))
    to = to_status.strip().lower() if isinstance(to_status, str) else ""
    if frm not in INTENT_TRANSITIONS:
        return _result(False, "BAD_STATE", f"未知 Intent 状态：{frm!r}",
                       **{"from": frm, "to": to})
    if to not in INTENT_TRANSITIONS:
        return _result(False, "BAD_STATE", f"未知 Intent 目标状态：{to!r}",
                       **{"from": frm, "to": to})
    if frm == to:
        return _result(False, "SAME_STATE", "源状态与目标状态相同",
                       **{"from": frm, "to": to})
    if to not in INTENT_TRANSITIONS[frm]:
        return _result(False, "ILLEGAL_TRANSITION",
                       f"不允许 {frm} → {to}；合法后继：{list(INTENT_TRANSITIONS[frm])}",
                       **{"from": frm, "to": to})
    if to == "claimed" and (not isinstance(worker, str) or not worker.strip()):
        return _result(False, "MISSING_WORKER", "claim 必须记录 worker",
                       **{"from": frm, "to": to})
    return _result(True, "OK", f"允许 {frm} → {to}", **{"from": frm, "to": to})


def graph() -> Dict[str, Any]:
    """可序列化的状态机描述，供文档/审查与 --json 使用。"""
    return {
        "schema": "board-transitions/1.1",
        "version": VERSION,
        "candidate": {
            "transitions": {k: list(v) for k, v in TRANSITIONS.items()},
            "terminal": list(TERMINAL_STATES),
            "aliases": dict(STATE_ALIASES),
        },
        "intent": {"transitions": {k: list(v) for k, v in INTENT_TRANSITIONS.items()}},
        "verification_rules": VERIFICATION_RULES,
        "risk_dispositions": list(RISK_DISPOSITIONS),
    }


def _load(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _load_evidence(path: str) -> List[Dict[str, Any]]:
    doc = _load(path)
    if isinstance(doc, list):
        return [x for x in doc if isinstance(x, dict)]
    if isinstance(doc, dict) and isinstance(doc.get("evidence"), list):
        return [x for x in doc["evidence"] if isinstance(x, dict)]
    return [doc] if isinstance(doc, dict) else []


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="Candidate/Intent 状态机与 validated 的类型化验证规则")
    sub = ap.add_subparsers(dest="cmd")
    g = sub.add_parser("graph", help="输出状态机与验证规则")
    g.add_argument("--json", dest="json_out", help="写到 JSON 文件")
    c = sub.add_parser("check", help="校验一次候选状态转换")
    c.add_argument("--candidate", required=True, help="候选 JSON 文件")
    c.add_argument("--to", required=True, help="目标状态（可写 VERIFIED）")
    c.add_argument("--evidence", action="append", default=[],
                   help="证据 JSON 文件，可重复；也接受 {evidence:[...]} 或数组")
    c.add_argument("--policy", help="验证策略 JSON 文件")
    c.add_argument("--run-id", help="交叉校验候选的 run_id（不再用于兜底）")
    c.add_argument("--firmware-sha256", help="交叉校验候选的固件 sha256（不再用于兜底）")
    c.add_argument("--target-sha256",
                   help="被测目标（ELF/共享库/可执行文件）的 sha256；也接受策略文件里的 target_sha256")
    c.add_argument("--json", dest="json_out", help="把结果写成 JSON")
    c.add_argument("--quiet", action="store_true", help="只给退出码")
    r = sub.add_parser("risk", help="校验风险处置记录")
    r.add_argument("--file", required=True, help="风险处置 JSON 文件")

    args = ap.parse_args(argv)
    cmd = args.cmd or "graph"

    if cmd == "graph":
        doc = graph()
        text = json.dumps(doc, ensure_ascii=False, indent=2)
        if getattr(args, "json_out", None):
            with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text + "\n")
            print(f"[ok] 状态机已写入 {args.json_out}")
        else:
            print(text)
        return 0

    if cmd == "risk":
        errors = validate_risk_disposition(_load(args.file))
        for e in errors:
            print(f"  [{e['code']}] {e['path']}: {e['message']}")
        print("[ok] 风险处置合法" if not errors else f"[fail] {len(errors)} 处风险处置违规")
        return 0 if not errors else 1

    try:
        candidate = _load(args.candidate)
        evidence: List[Dict[str, Any]] = []
        for path in args.evidence:
            evidence.extend(_load_evidence(path))
        policy = _load(args.policy) if args.policy else {}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[error] 读取输入失败：{exc}", file=sys.stderr)
        return 2

    if not isinstance(policy, dict):
        print("[error] --policy 必须是 JSON 对象", file=sys.stderr)
        return 2
    if args.target_sha256:
        existing = policy.get("target_sha256")
        if existing is not None and (
                not isinstance(existing, str)
                or existing.lower() != args.target_sha256.lower()):
            print("[error] --target-sha256 与 --policy 中的 target_sha256 不一致",
                  file=sys.stderr)
            return 2
        policy = dict(policy)
        policy["target_sha256"] = args.target_sha256
    result = validate_transition(candidate, args.to, evidence, policy,
                                 args.run_id, args.firmware_sha256)
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(result, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    if not args.quiet:
        print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0 if result.get("ok") else 1


if __name__ == "__main__":
    raise SystemExit(main())
