#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""确定性黑板调度器：Fact→Intent→准入→执行结果回写（ROADMAP M7）。

设计边界
--------
* 单 Agent、确定性规则：调度器只根据黑板里已经存在的 Fact 生成 Intent，
  不调用模型、不猜下一步、不把 Hint 当证据。Hint 只提高优先级，不能绕过
  依赖、资源准入或状态机。
* 事件日志是真相源：所有 Intent 创建/状态变化都通过 BoardStore 追加事件，
  scheduler-plan 只是这次评估的输出，不是另一份状态。
* 失败必须可区分：执行结果用 SUCCESS/PARTIAL/FAILED/BLOCKED/TIMED_OUT/
  NOT_APPLICABLE 六态；重试由 failure.retryable 与 max_retries 决定，
  不允许把超时或阻断折叠成「没有发现」。
* 资源准入先于领取：claim 调用 resource_manager.check_request；执行阶段
  仍必须经 sandbox_run.py，调度器不是执行器。

子命令：plan / next / claim / complete / backtrack / status / rules。

退出码：0 成功；1 拒绝/校验失败；2 用法或 IO 错误；5 资源准入拒绝。
纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from board_events import BoardEventError, canonical_json, utc_now
    from board_store import BoardStore, StoreError
    from contracts import (validate_intent, validate_scheduler_result,
                           validate_scheduler_rules)
    from resource_manager import AdmissionError, check_request, load_policy
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"无法加载同目录模块：{exc}")

VERSION = "1.0"
SCHEMA = "scheduler-plan/1.0"
TOKEN_RE = re.compile(r"\{([A-Za-z0-9_.]+)\}")
CREATOR_RE = re.compile(r"^rule:(R-[A-Za-z0-9._-]+)@(.+)$")

# 默认规则只覆盖「有明确触发事实」的少数动作；它们不是漏洞判定，
# 只是把 Fact 变成可执行、可审计的验证任务。
DEFAULT_RULES: Dict[str, Any] = {
    "schema": "scheduler-rules/1.0",
    "version": "2026-11-05",
    "rules": [
        {
            "id": "R-SERVICE-DYNAMIC",
            "version": "1",
            "when": {"fact_type": "service", "value_present": ["port"]},
            "intent": {
                "type": "dynamic-validation",
                "description": "验证服务 {value.name} 的端口 {value.port}（{target}）",
                "target": "{target}",
                "priority": 60,
                "params": {"port": "{value.port}", "service": "{value.name}"},
                "timeout_seconds": 120,
                "max_retries": 1,
                "stop_conditions": ["目标端口无响应"],
                "expected_outputs": ["evidence", "fact"],
            },
        },
        {
            "id": "R-PORT-QILING",
            "version": "1",
            "when": {"fact_type": "port-response", "value_truthy": ["open"]},
            "intent": {
                "type": "emulation",
                "description": "对开放端口 {value.port} 做定向仿真（{target}）",
                "target": "{target}",
                "priority": 70,
                "params": {"port": "{value.port}"},
                "timeout_seconds": 180,
                "max_retries": 0,
                "expected_outputs": ["evidence", "fact"],
            },
        },
        {
            "id": "R-ELF-STATIC",
            "version": "1",
            "when": {"fact_type": "elf", "value_present": ["path"]},
            "intent": {
                "type": "static-analysis",
                "description": "静态分析二进制 {value.path}（{target}）",
                "target": "{target}",
                "priority": 40,
                "params": {"binary": "{value.path}"},
                "timeout_seconds": 120,
                "max_retries": 0,
                "expected_outputs": ["evidence", "fact"],
            },
        },
        {
            "id": "R-CREDENTIAL-REVIEW",
            "version": "1",
            "when": {"fact_type": "credential"},
            "intent": {
                "type": "manual-review",
                "description": "人工复核硬编码凭据（{target}）",
                "target": "{target}",
                "priority": 80,
                "timeout_seconds": 60,
                "max_retries": 0,
                "expected_outputs": ["evidence"],
            },
        },
    ],
}


class SchedulerError(Exception):
    """带机器可读 code 与退出码的调度错误。"""

    def __init__(self, code: str, message: str, exit_code: int = 1,
                 details: Optional[List[Dict[str, Any]]] = None) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.details = details or []

    def as_dict(self) -> Dict[str, Any]:
        out = {"ok": False, "code": self.code, "message": self.message}
        if self.details:
            out["details"] = self.details
        return out


class RenderError(Exception):
    """模板占位符无法从 Fact 中解析；规则不得渲染成半个 Intent。"""


def _short(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:12]


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _target_of(fact: Dict[str, Any]) -> str:
    value = fact.get("value") if isinstance(fact.get("value"), dict) else {}
    for key in ("target", "path", "binary", "service", "name", "port"):
        v = value.get(key)
        if isinstance(v, str) and v.strip():
            return v
        if isinstance(v, int) and not isinstance(v, bool):
            return str(v)
    return str(fact.get("fact_id") or "unknown")


def _lookup(fact: Dict[str, Any], path: str) -> Any:
    if path == "fact_id":
        return fact.get("fact_id")
    if path == "fact_type":
        return fact.get("type")
    if path == "target":
        return _target_of(fact)
    if path.startswith("value."):
        cur: Any = fact.get("value")
        for part in path.split(".")[1:]:
            if not isinstance(cur, dict) or part not in cur:
                raise RenderError(f"Fact {fact.get('fact_id')} 缺少 {path}")
            cur = cur[part]
        return cur
    raise RenderError(f"未知模板占位符 {path}")


def render_text(template: str, fact: Dict[str, Any]) -> str:
    if not isinstance(template, str) or not template:
        raise RenderError("模板必须是非空字符串")

    def repl(match: re.Match) -> str:
        value = _lookup(fact, match.group(1))
        if isinstance(value, (dict, list)) or value is None:
            raise RenderError(f"占位符 {match.group(0)} 不是标量")
        return str(value)

    return TOKEN_RE.sub(repl, template)


def render_obj(obj: Any, fact: Dict[str, Any]) -> Any:
    if isinstance(obj, str):
        return render_text(obj, fact)
    if isinstance(obj, list):
        return [render_obj(x, fact) for x in obj]
    if isinstance(obj, dict):
        return {k: render_obj(v, fact) for k, v in obj.items()}
    return obj


def load_rules(path: Optional[str]) -> Tuple[Dict[str, Any], str]:
    if path:
        try:
            doc = _read_json(path)
        except OSError as exc:
            raise SchedulerError("RULES_READ_ERROR", f"无法读取规则文件：{exc}", 2)
        except json.JSONDecodeError as exc:
            raise SchedulerError("RULES_PARSE_ERROR", f"规则文件不是合法 JSON：{exc}", 2)
    else:
        doc = json.loads(json.dumps(DEFAULT_RULES))
    errors = validate_scheduler_rules(doc)
    if errors:
        raise SchedulerError("RULES_INVALID", "调度规则未通过契约校验",
                             details=errors)
    sha = hashlib.sha256(canonical_json(doc).encode("utf-8")).hexdigest()
    return doc, sha


def _rule_order(rules: Sequence[Dict[str, Any]]) -> List[Dict[str, Any]]:
    by_id = {r.get("id"): r for r in rules if isinstance(r, dict)}
    mark: Dict[str, int] = {}
    order: List[Dict[str, Any]] = []

    def visit(rid: str, trail: List[str]) -> None:
        state = mark.get(rid, 0)
        if state == 2:
            return
        if state == 1:
            raise SchedulerError("DEPENDENCY_CYCLE",
                                 "规则依赖成环：" + " → ".join(trail + [rid]))
        mark[rid] = 1
        rule = by_id.get(rid) or {}
        for dep in rule.get("depends_on") or []:
            visit(str(dep), trail + [rid])
        mark[rid] = 2
        if rule:
            order.append(rule)

    for rule in rules:
        visit(str(rule.get("id")), [])
    return order


def _match(rule: Dict[str, Any], fact: Dict[str, Any]) -> bool:
    when = rule.get("when") or {}
    types = when.get("fact_type")
    if isinstance(types, str):
        types = [types]
    if fact.get("type") not in (types or []):
        return False
    value = fact.get("value") if isinstance(fact.get("value"), dict) else {}
    for key in when.get("value_present") or []:
        if key not in value:
            return False
    for key in when.get("value_truthy") or []:
        if key not in value or not value.get(key):
            return False
    for key, want in (when.get("value_equals") or {}).items():
        if value.get(key) != want:
            return False
    return True


def _hint_boost(state: Dict[str, Any], fact: Dict[str, Any],
                target: str) -> Tuple[int, List[str]]:
    boost = 0
    applied: List[str] = []
    for hint in state.get("hints") or []:
        if not isinstance(hint, dict) or hint.get("active") is False:
            continue
        affects = hint.get("affects")
        if not isinstance(affects, list):
            continue
        if (fact.get("fact_id") in affects or target in affects
                or "all" in affects) and boost < 15:
            boost = min(15, boost + 5)
            applied.append(str(hint.get("hint_id")))
    return boost, applied


def build_intent(rule: Dict[str, Any], fact: Dict[str, Any],
                 state: Dict[str, Any]) -> Dict[str, Any]:
    want = rule.get("intent") or {}
    target = render_text(want.get("target"), fact)
    params = render_obj(want.get("params") or {}, fact)
    description = render_text(want.get("description"), fact)
    boost, hints = _hint_boost(state, fact, target)
    base_priority = want.get("priority")
    if not isinstance(base_priority, int):
        base_priority = 0
    priority = max(0, min(100, base_priority + boost))
    dedupe = {
        "rule": rule.get("id"),
        "version": rule.get("version"),
        "type": want.get("type"),
        "target": target,
        "params": params,
    }
    dedupe_key = "sched:" + hashlib.sha256(
        canonical_json(dedupe).encode("utf-8")).hexdigest()
    return {
        "schema": "intent/1.1",
        "intent_id": "I-" + _short(dedupe),
        "run_id": state["run_id"],
        "firmware_sha256": state["firmware_sha256"],
        "type": want.get("type"),
        "status": "open",
        "from": [fact.get("fact_id")],
        "description": description,
        "dedupe_key": dedupe_key,
        "creator": f"rule:{rule.get('id')}@{rule.get('version')}",
        "created_at": utc_now(),
        "target": target,
        "priority": priority,
        "depends_on": [],
        "params": params,
        "timeout_seconds": want.get("timeout_seconds") or 120,
        "max_retries": want.get("max_retries") or 0,
        "stop_conditions": list(want.get("stop_conditions") or []),
        "expected_outputs": list(want.get("expected_outputs") or []),
        "provenance": {
            "rule_id": rule.get("id"),
            "rule_version": rule.get("version"),
            "fact_ids": [fact.get("fact_id")],
            "hint_boost": boost,
            "hints": hints,
        },
    }


def _creator_rule(intent: Dict[str, Any]) -> Optional[str]:
    creator = intent.get("creator")
    if not isinstance(creator, str):
        return None
    m = CREATOR_RE.match(creator)
    return m.group(1) if m else None


def evaluate(store: BoardStore, rules_doc: Dict[str, Any]) -> Dict[str, Any]:
    state = store.state
    rules = [r for r in rules_doc.get("rules") or []
             if isinstance(r, dict) and r.get("enabled", True) is not False]
    order = _rule_order(rules)
    facts = [f for f in state.get("facts") or [] if isinstance(f, dict)]
    existing = {i.get("intent_id"): i for i in state.get("intents") or []
                if isinstance(i, dict)}
    by_rule: Dict[str, List[Dict[str, Any]]] = {}
    for intent in existing.values():
        rid = _creator_rule(intent)
        if rid:
            by_rule.setdefault(rid, []).append(intent)
    created: List[Dict[str, Any]] = []
    deduped: List[Dict[str, Any]] = []
    blocked: List[Dict[str, Any]] = []

    for rule in order:
        rid = rule.get("id")
        for fact in facts:
            if not _match(rule, fact):
                continue
            try:
                intent = build_intent(rule, fact, state)
            except RenderError as exc:
                blocked.append({"rule_id": rid, "fact_id": fact.get("fact_id"),
                                "code": "TEMPLATE_RENDER_FAILED",
                                "message": str(exc)})
                continue
            iid = intent["intent_id"]
            if iid in existing:
                prev = existing[iid]
                if prev.get("dedupe_key") != intent.get("dedupe_key"):
                    blocked.append({"rule_id": rid,
                                    "fact_id": fact.get("fact_id"),
                                    "code": "INTENT_CONFLICT",
                                    "message": f"{iid} 已存在但内容不同"})
                else:
                    deduped.append({"intent_id": iid, "rule_id": rid,
                                    "fact_id": fact.get("fact_id")})
                    if prev not in by_rule.get(rid, []):
                        by_rule.setdefault(rid, []).append(prev)
                continue
            dep_ids: List[str] = []
            dep_missing: List[str] = []
            for dep in rule.get("depends_on") or []:
                candidates = by_rule.get(dep) or []
                if not candidates:
                    dep_missing.append(str(dep))
                else:
                    dep_ids.extend(str(x.get("intent_id")) for x in candidates)
            if dep_missing:
                blocked.append({"rule_id": rid, "fact_id": fact.get("fact_id"),
                                "code": "DEPENDENCY_MISSING",
                                "message": "依赖规则尚未产出 Intent："
                                           + ", ".join(dep_missing)})
                continue
            intent["depends_on"] = sorted(set(dep_ids))
            errors = validate_intent(intent)
            if errors:
                blocked.append({"rule_id": rid, "fact_id": fact.get("fact_id"),
                                "code": "INTENT_INVALID", "details": errors})
                continue
            created.append(intent)
            existing[iid] = intent
            by_rule.setdefault(rid, []).append(intent)

    return {"created": created, "deduped": deduped, "blocked": blocked}


def readiness(intent: Dict[str, Any],
              by_id: Dict[str, Dict[str, Any]]) -> Tuple[str, str]:
    deps = intent.get("depends_on") or []
    if not isinstance(deps, list):
        return "BLOCKED", "DEPENDENCY_INVALID"
    missing, failed, cancelled, waiting = [], [], [], []
    seen = set()
    stack = list(deps)
    while stack:
        dep = stack.pop()
        if not isinstance(dep, str):
            return "BLOCKED", "DEPENDENCY_INVALID"
        if dep in seen:
            continue
        seen.add(dep)
        row = by_id.get(dep)
        if row is None:
            missing.append(dep)
            continue
        status = row.get("status")
        if status == "failed":
            failed.append(dep)
        elif status == "cancelled":
            cancelled.append(dep)
        elif status != "done":
            waiting.append(dep)
        for nxt in row.get("depends_on") or []:
            stack.append(nxt)
    if failed:
        return "BLOCKED", "DEPENDENCY_FAILED:" + ",".join(sorted(failed))
    if cancelled:
        return "BLOCKED", "DEPENDENCY_CANCELLED:" + ",".join(sorted(cancelled))
    if missing:
        return "BLOCKED", "DEPENDENCY_MISSING:" + ",".join(sorted(missing))
    if waiting:
        return "WAITING", "DEPENDENCY_PENDING:" + ",".join(sorted(waiting))
    return "READY", ""


def collect_ready(store: BoardStore) -> List[Dict[str, Any]]:
    intents = [i for i in store.state.get("intents") or [] if isinstance(i, dict)]
    by_id = {i.get("intent_id"): i for i in intents}
    rows = []
    for intent in intents:
        if intent.get("status") != "open":
            continue
        verdict, reason = readiness(intent, by_id)
        rows.append({"intent_id": intent.get("intent_id"),
                     "type": intent.get("type"),
                     "priority": intent.get("priority") or 0,
                     "created_at": intent.get("created_at"),
                     "target": intent.get("target"),
                     "state": verdict, "reason": reason})
    rows.sort(key=lambda r: (-int(r["priority"]), str(r["created_at"]),
                             str(r["intent_id"])))
    return rows


def _resource_errors(intent: Dict[str, Any],
                     policy: Dict[str, Any]) -> List[Dict[str, str]]:
    params = intent.get("params") if isinstance(intent.get("params"), dict) else {}
    timeout = intent.get("timeout_seconds") or params.get("timeout") or 120
    memory = params.get("memory") or "512m"
    cpus = params.get("cpus") or "1"
    pids = params.get("pids") or 128
    image = params.get("image") or "debian:bookworm-slim"
    mode = params.get("mode") or "sandbox"
    try:
        timeout = int(timeout)
    except (TypeError, ValueError):
        return [{"path": "request.timeout", "code": "BAD_TYPE",
                 "message": "timeout 必须是整数秒"}]
    try:
        pids = int(pids)
    except (TypeError, ValueError):
        return [{"path": "request.pids", "code": "BAD_TYPE",
                 "message": "pids 必须是整数"}]
    return check_request(policy, timeout=timeout, memory=str(memory),
                         cpus=str(cpus), pids=pids, image=str(image),
                         mode=str(mode))


def cmd_plan(args: argparse.Namespace) -> Dict[str, Any]:
    store = BoardStore.load(args.workspace)
    rules, rules_sha = load_rules(args.rules)
    result = evaluate(store, rules)
    written = []
    if args.write:
        for intent in result["created"]:
            try:
                res = store.record_intent(intent)
            except StoreError as exc:
                raise SchedulerError(exc.code, exc.message)
            written.append({"intent_id": intent["intent_id"],
                            "duplicate": bool(res.get("duplicate"))})
        store.reload()
    return {"schema": SCHEMA, "ok": True, "run_id": store.state["run_id"],
            "rules_sha256": rules_sha, "written": written,
            "created": result["created"], "deduped": result["deduped"],
            "blocked": result["blocked"],
            "counts": {"created": len(result["created"]),
                       "deduped": len(result["deduped"]),
                       "blocked": len(result["blocked"])}}


def cmd_next(args: argparse.Namespace) -> Dict[str, Any]:
    store = BoardStore.load(args.workspace)
    rows = collect_ready(store)
    if args.limit is not None:
        rows = rows[:args.limit]
    return {"schema": SCHEMA, "ok": True, "intents": rows,
            "ready": sum(1 for r in rows if r["state"] == "READY"),
            "waiting": sum(1 for r in rows if r["state"] == "WAITING"),
            "blocked": sum(1 for r in rows if r["state"] == "BLOCKED")}


def _get_intent(store: BoardStore, intent_id: str) -> Dict[str, Any]:
    return _get_intent_state(store.state, intent_id)


def _get_intent_state(state: Dict[str, Any], intent_id: str) -> Dict[str, Any]:
    for row in state.get("intents") or []:
        if isinstance(row, dict) and row.get("intent_id") == intent_id:
            return row
    raise SchedulerError("INTENT_NOT_FOUND", f"Intent 不存在：{intent_id}")


def cmd_claim(args: argparse.Namespace) -> Dict[str, Any]:
    store = BoardStore.load(args.workspace)
    intent = _get_intent(store, args.intent)
    if intent.get("status") != "open":
        raise SchedulerError("INTENT_NOT_OPEN",
                             f"Intent 当前是 {intent.get('status')}，不能领取")
    by_id = {i.get("intent_id"): i for i in store.state.get("intents") or []
             if isinstance(i, dict)}
    verdict, reason = readiness(intent, by_id)
    if verdict != "READY":
        raise SchedulerError(reason.split(":", 1)[0], reason)
    if not isinstance(args.worker, str) or not args.worker.strip():
        raise SchedulerError("WORKER_REQUIRED", "领取必须指定非空 --worker", 2)
    policy, errors, policy_sha, source = load_policy(args.policy)
    if errors:
        raise SchedulerError("POLICY_INVALID", "资源策略未通过校验",
                             details=errors)
    denied = _resource_errors(intent, policy)
    if denied:
        raise SchedulerError("RESOURCE_DENIED", "资源准入拒绝，Intent 保持 open",
                             5, denied)
    try:
        # expected_status 让「检查 open」与「写 claimed」在同一把黑板锁内完成：
        # 两个 worker 同时 claim 时，后到的那个会看到 claimed 并失败。
        res = store.set_intent_status(args.intent, "claimed", args.worker,
                                      expected_status="open")
    except StoreError as exc:
        raise SchedulerError(exc.code, exc.message)
    updated = _get_intent(store, args.intent)
    return {"schema": SCHEMA, "ok": True,
            "duplicate": bool(res.get("duplicate")),
            "intent_id": args.intent, "worker": args.worker,
            "attempts": updated.get("attempts"),
            "max_retries": updated.get("max_retries") or 0,
            "policy_sha256": policy_sha, "policy_source": source}


def _record_result_rows(store: BoardStore,
                        result: Dict[str, Any]) -> List[str]:
    refs: List[str] = []
    for ev in result.get("evidence") or []:
        if not isinstance(ev, dict):
            continue
        try:
            store.record_evidence(ev)
        except StoreError as exc:
            raise SchedulerError("EVIDENCE_RECORD_FAILED", exc.message)
        refs.append(str(ev.get("evidence_id")))
    for fact in result.get("facts") or []:
        if not isinstance(fact, dict):
            continue
        try:
            store.record_fact(fact)
        except StoreError as exc:
            raise SchedulerError("FACT_RECORD_FAILED", exc.message)
        refs.append(str(fact.get("fact_id")))
    return refs


def cmd_complete(args: argparse.Namespace) -> Dict[str, Any]:
    store = BoardStore.load(args.workspace)
    try:
        result = _read_json(args.result)
    except OSError as exc:
        raise SchedulerError("RESULT_READ_ERROR", f"无法读取结果：{exc}", 2)
    except json.JSONDecodeError as exc:
        raise SchedulerError("RESULT_PARSE_ERROR", f"结果不是合法 JSON：{exc}", 2)
    errors = validate_scheduler_result(result)
    if errors:
        raise SchedulerError("RESULT_INVALID", "执行结果未通过契约校验",
                             details=errors)
    intent = _get_intent(store, result.get("intent_id"))
    if result.get("intent_id") != args.intent:
        raise SchedulerError("INTENT_MISMATCH",
                             "结果里的 intent_id 与 --intent 不一致")
    if result.get("run_id") != store.state.get("run_id"):
        raise SchedulerError("RUN_MISMATCH", "结果不属于当前黑板 run")
    if str(result.get("firmware_sha256", "")).lower() != \
            str(store.state.get("firmware_sha256", "")).lower():
        raise SchedulerError("FIRMWARE_MISMATCH", "结果的固件哈希与黑板不一致")
    if intent.get("status") != "claimed":
        if intent.get("status") in ("done", "failed"):
            prev = set(intent.get("result_refs") or [])
            now = {str(x.get("evidence_id")) for x in result.get("evidence") or []}
            now |= {str(x.get("fact_id")) for x in result.get("facts") or []}
            outcome = {"SUCCESS": "success", "PARTIAL": "partial",
                       "NOT_APPLICABLE": "not_applicable",
                       "FAILED": "failed", "BLOCKED": "blocked",
                       "TIMED_OUT": "timed_out"}.get(result.get("status"))
            # 重试会累积 result_refs；本次结果引用已全部记录过即视为重复。
            # 失败结果可以没有 Evidence/Fact，这时用 outcome 判断是否为同一次终态。
            if (now and now <= prev) or (
                    not now and not prev and intent.get("outcome") == outcome):
                return {"schema": SCHEMA, "ok": True, "duplicate": True,
                        "intent_id": args.intent,
                        "status": intent.get("status"),
                        "outcome": intent.get("outcome")}
        raise SchedulerError("INTENT_NOT_CLAIMED",
                             f"Intent 当前是 {intent.get('status')}，不能回写结果")
    if result.get("worker") is not None and \
            result.get("worker") != intent.get("worker"):
        raise SchedulerError("WORKER_MISMATCH", "结果 worker 与领取者不一致")
    if result.get("attempt") is not None and \
            result.get("attempt") != intent.get("attempts"):
        raise SchedulerError("ATTEMPT_MISMATCH",
                             f"结果 attempt={result.get('attempt')} 与 "
                             f"Intent attempts={intent.get('attempts')} 不一致")
    # 单条 INTENT_COMPLETED_WITH_RESULTS 事件：Evidence/Fact 插入、result_refs
    # 累积和 Intent 状态迁移在同一个 apply_event 里完成，崩溃不会留下半成品。
    try:
        res = store.complete_intent(args.intent, result, intent.get("worker"),
                                    attempt=intent.get("attempts"))
    except StoreError as exc:
        raise SchedulerError(exc.code, exc.message)
    updated = _get_intent_state(res.get("state") or {}, args.intent)
    refs = list(updated.get("result_refs") or [])
    if updated.get("status") == "done":
        return {"schema": SCHEMA, "ok": True,
                "duplicate": bool(res.get("duplicate")),
                "intent_id": args.intent, "status": "done",
                "outcome": updated.get("outcome"), "result_refs": refs}
    if updated.get("status") == "open":
        return {"schema": SCHEMA, "ok": True,
                "duplicate": bool(res.get("duplicate")),
                "intent_id": args.intent, "status": "open", "retry": True,
                "attempts": updated.get("attempts"),
                "max_retries": updated.get("max_retries") or 0,
                "failure": updated.get("last_failure"), "result_refs": refs}
    return {"schema": SCHEMA, "ok": True,
            "duplicate": bool(res.get("duplicate")),
            "intent_id": args.intent, "status": "failed",
            "outcome": updated.get("outcome"),
            "failure": updated.get("last_failure"), "result_refs": refs}


def cmd_backtrack(args: argparse.Namespace) -> Dict[str, Any]:
    store = BoardStore.load(args.workspace)
    refs = list(args.evidence or [])
    if not refs:
        raise SchedulerError("EVIDENCE_REQUIRED", "回退必须带至少一条证据", 2)
    known = {e.get("evidence_id") for e in store.state.get("evidence") or []}
    missing = [r for r in refs if r not in known]
    if missing:
        raise SchedulerError("EVIDENCE_NOT_FOUND", f"证据不存在：{missing}")
    try:
        res = store.backtrack(args.from_phase, args.to_phase, args.reason,
                              refs, args.approved_by)
    except StoreError as exc:
        raise SchedulerError(exc.code, exc.message)
    return {"schema": SCHEMA, "ok": True,
            "duplicate": bool(res.get("duplicate")),
            "phase": store.state.get("phase"), "evidence_refs": refs}


def cmd_status(args: argparse.Namespace) -> Dict[str, Any]:
    store = BoardStore.load(args.workspace)
    intents = [i for i in store.state.get("intents") or [] if isinstance(i, dict)]
    counts: Dict[str, int] = {}
    outcomes: Dict[str, int] = {}
    for row in intents:
        counts[row.get("status")] = counts.get(row.get("status"), 0) + 1
        if row.get("outcome"):
            outcomes[row.get("outcome")] = outcomes.get(row.get("outcome"), 0) + 1
    ready = collect_ready(store)
    return {"schema": SCHEMA, "ok": True, "run_id": store.state.get("run_id"),
            "phase": store.state.get("phase"),
            "revision": store.state.get("revision"),
            "counts": {"intents": len(intents), "by_status": counts,
                       "by_outcome": outcomes,
                       "facts": len(store.state.get("facts") or []),
                       "evidence": len(store.state.get("evidence") or []),
                       "hints": len(store.state.get("hints") or [])},
            "ready": [r for r in ready if r["state"] == "READY"],
            "waiting": [r for r in ready if r["state"] == "WAITING"],
            "blocked": [r for r in ready if r["state"] == "BLOCKED"]}


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="board_scheduler.py",
                                description="确定性 Fact→Intent 调度器（M7）")
    p.add_argument("--version", action="version",
                   version=f"%(prog)s {VERSION}")
    sub = p.add_subparsers(dest="command", required=True)

    q = sub.add_parser("plan", help="按规则评估并可选写入 Intent")
    q.add_argument("--workspace", required=True)
    q.add_argument("--rules")
    q.add_argument("--write", action="store_true")

    q = sub.add_parser("next", help="列出待执行 Intent")
    q.add_argument("--workspace", required=True)
    q.add_argument("--limit", type=int)

    q = sub.add_parser("claim", help="领取 Intent 并通过资源准入")
    q.add_argument("--workspace", required=True)
    q.add_argument("--intent", required=True)
    q.add_argument("--worker", required=True)
    q.add_argument("--policy")

    q = sub.add_parser("complete", help="回写 SchedulerResult")
    q.add_argument("--workspace", required=True)
    q.add_argument("--intent", required=True)
    q.add_argument("--result", required=True)

    q = sub.add_parser("backtrack", help="记录阶段回退")
    q.add_argument("--workspace", required=True)
    q.add_argument("--from-phase", required=True)
    q.add_argument("--to-phase", required=True)
    q.add_argument("--reason", required=True)
    q.add_argument("--evidence", action="append", required=True)
    q.add_argument("--approved-by")

    q = sub.add_parser("status", help="汇总调度状态")
    q.add_argument("--workspace", required=True)

    q = sub.add_parser("rules", help="输出默认或指定规则")
    q.add_argument("--rules")
    return p


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "plan":
            out = cmd_plan(args)
        elif args.command == "next":
            out = cmd_next(args)
        elif args.command == "claim":
            out = cmd_claim(args)
        elif args.command == "complete":
            out = cmd_complete(args)
        elif args.command == "backtrack":
            out = cmd_backtrack(args)
        elif args.command == "status":
            out = cmd_status(args)
        elif args.command == "rules":
            doc, sha = load_rules(args.rules)
            out = {"schema": SCHEMA, "ok": True, "rules_sha256": sha,
                   "rules": doc}
        else:  # pragma: no cover
            return 2
    except SchedulerError as exc:
        print(json.dumps(exc.as_dict(), ensure_ascii=False, indent=2))
        print(f"[scheduler] {exc.code}: {exc.message}", file=sys.stderr)
        return exc.exit_code
    except (StoreError, BoardEventError, AdmissionError) as exc:
        code = getattr(exc, "code", "SCHEDULER_ERROR")
        print(json.dumps({"ok": False, "code": code, "message": str(exc)},
                         ensure_ascii=False, indent=2))
        print(f"[scheduler] {code}: {exc}", file=sys.stderr)
        return getattr(exc, "exit_code", 1)
    print(json.dumps(out, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
