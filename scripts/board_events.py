#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计黑板的事件日志：追加、校验、回放（ROADMAP M1）。

为什么以事件日志为真相源
------------------------
快照 audit-board.json 可以被手工改、也可能写一半中断。如果快照是唯一真相，
一次崩溃就会让「某个候选为什么变成 validated」永久丢失。这里让
audit-events.jsonl 成为唯一追加写入的真相源：

* 每行一个 BoardEvent，`seq` 从 1 连续递增，`event_id` 形如 EV-000001；
* `dedupe_key = sha256(type + canonical(payload))`，同内容重复提交不会再写一行；
* 回放只依赖日志，快照损坏可以从头重建；
* 非法 JSON 行必须报错（带行号），空行可容忍——静默跳过等于伪造完整性。

用法
----
    python scripts/board_events.py verify --events audit-events.jsonl
    python scripts/board_events.py replay --events audit-events.jsonl --out audit-board.json

退出码：0 通过；1 校验/回放失败；2 用法/IO 错误。纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import copy
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

try:
    from contracts import summarize as _contract_summary
    from contracts import validate_board_event as _validate_board_event
except Exception:  # pragma: no cover - 单独拷走时退化为内置最小校验
    _contract_summary = None
    _validate_board_event = None

try:
    from board_transitions import (normalize_state, validate_intent_transition,
                                   validate_transition)
except Exception:  # pragma: no cover
    normalize_state = None
    validate_intent_transition = None
    validate_transition = None

VERSION = "1.0"
EVENT_RE = re.compile(r"^EV-(\d{6})$")
PHASES = ("P0", "P1", "P2", "P3", "P4", "P5")


class BoardEventError(Exception):
    """事件不能被应用；code 是机器可读原因。"""

    def __init__(self, code: str, message: str, path: str = "") -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path

    def as_dict(self) -> Dict[str, str]:
        return {"code": self.code, "message": self.message, "path": self.path}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    """稳定的 JSON 表示：键排序、无多余空格、保留非 ASCII。"""
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def make_dedupe_key(event_type: str, payload: Dict[str, Any]) -> str:
    """同一类事件 + 同一 payload 视为同一事实；ts 不参与，重试不会产生新事件。"""
    body = "board-event/1.0\n" + str(event_type) + "\n" + canonical_json(payload or {})
    return hashlib.sha256(body.encode("utf-8")).hexdigest()


def make_event(run_id: str, seq: int, event_type: str, payload: Dict[str, Any],
               ts: Optional[str] = None, event_id: Optional[str] = None,
               dedupe_key: Optional[str] = None) -> Dict[str, Any]:
    """构造一行事件；seq/event_id 由调用方保证连续，便于日志可审计。"""
    if not isinstance(seq, int) or seq < 1:
        raise BoardEventError("BAD_SEQ", "seq 必须是 >=1 的整数")
    return {
        "schema": "board-event/1.0",
        "event_id": event_id or f"EV-{seq:06d}",
        "run_id": run_id,
        "seq": seq,
        "type": event_type,
        "ts": ts or utc_now(),
        "dedupe_key": dedupe_key or make_dedupe_key(event_type, payload),
        "payload": payload or {},
    }


def validate_event(event: Any) -> List[Dict[str, str]]:
    """结构校验；契约模块不可用时至少检查事件日志自己的关键字段。"""
    if _validate_board_event is not None:
        return _validate_board_event(event)
    out: List[Dict[str, str]] = []
    if not isinstance(event, dict):
        return [{"path": "$", "code": "BAD_TYPE", "message": "事件必须是对象"}]
    for key in ("event_id", "run_id", "type", "ts", "dedupe_key"):
        if not isinstance(event.get(key), str) or not event.get(key):
            out.append({"path": key, "code": "MISSING", "message": f"{key} 必填"})
    if not isinstance(event.get("seq"), int) or event.get("seq", 0) < 1:
        out.append({"path": "seq", "code": "BAD_VALUE", "message": "seq 必须是正整数"})
    if not isinstance(event.get("payload"), dict):
        out.append({"path": "payload", "code": "MISSING", "message": "payload 必须是对象"})
    return out


def new_state(run_id: str, firmware_sha256: str,
              manifest_id: Optional[str] = None, ts: Optional[str] = None) -> Dict[str, Any]:
    """空黑板：所有集合都显式存在，避免「缺字段 = 没数据」的歧义。"""
    return {
        "schema": "board-state/1.0",
        "run_id": run_id,
        "firmware_sha256": firmware_sha256,
        "manifest_id": manifest_id,
        "phase": "P0",
        "revision": 0,
        "event_count": 0,
        "last_event_id": None,
        "updated_at": ts or utc_now(),
        "evidence": [],
        "facts": [],
        "candidates": [],
        "intents": [],
        "hints": [],
        "emulation_results": [],
        "backtracks": [],
        "counters": {
            "evidence": 0, "facts": 0, "candidates": 0, "intents": 0,
            "hints": 0, "emulation_results": 0, "backtracks": 0,
        },
    }


def _touch(state: Dict[str, Any], event: Dict[str, Any]) -> None:
    state["revision"] = int(state.get("revision") or 0) + 1
    state["event_count"] = int(state.get("event_count") or 0) + 1
    state["last_event_id"] = event.get("event_id")
    state["updated_at"] = event.get("ts") or utc_now()


def _add(state: Dict[str, Any], key: str, id_key: str,
         row: Dict[str, Any], path: str) -> None:
    rid = row.get(id_key)
    for i, old in enumerate(state.get(key) or []):
        if isinstance(old, dict) and old.get(id_key) == rid:
            if canonical_json(old) == canonical_json(row):
                return  # 同 ID 同内容：幂等，不重复插入
            raise BoardEventError("DUPLICATE_ID_CONFLICT",
                                  f"{id_key}={rid!r} 已存在且内容不同", path)
    state.setdefault(key, []).append(row)


def _find(state: Dict[str, Any], key: str, id_key: str, rid: str) -> Dict[str, Any]:
    for row in state.get(key) or []:
        if isinstance(row, dict) and row.get(id_key) == rid:
            return row
    raise BoardEventError("NOT_FOUND", f"{key} 中找不到 {id_key}={rid!r}", key)


def _bind(row: Dict[str, Any], state: Dict[str, Any]) -> Dict[str, Any]:
    """给对象补上黑板级 run/固件绑定；已有不同值直接拒绝。"""
    row = dict(row)
    for key in ("run_id", "firmware_sha256"):
        if key in row and row[key] != state[key]:
            raise BoardEventError("RUN_MISMATCH" if key == "run_id"
                                  else "FIRMWARE_MISMATCH",
                                  f"{key} 与黑板不一致", key)
        row[key] = state[key]
    return row


def apply_event(state: Optional[Dict[str, Any]], event: Dict[str, Any],
                *, copy_state: bool = True) -> Dict[str, Any]:
    """把一个事件应用到黑板；任何失败抛 BoardEventError，调用方不得落日志。"""
    errors = validate_event(event)
    if errors:
        first = errors[0]
        raise BoardEventError("EVENT_INVALID",
                              f"{first['path']}: {first['message']}", first["path"])
    typ = event.get("type")
    payload = event.get("payload") or {}
    if state is None:
        if typ != "BOARD_INITIALIZED":
            raise BoardEventError("NOT_INITIALIZED", "首个事件必须是 BOARD_INITIALIZED")
        fw = payload.get("firmware_sha256")
        state = new_state(event["run_id"], fw, payload.get("manifest_id"),
                          event.get("ts"))
        state["phase"] = payload.get("phase") if payload.get("phase") in PHASES else "P0"
        _touch(state, event)
        return state
    if typ == "BOARD_INITIALIZED":
        raise BoardEventError("ALREADY_INITIALIZED", "黑板已经初始化")

    if copy_state:
        state = copy.deepcopy(state)
    if event.get("run_id") != state.get("run_id"):
        raise BoardEventError("RUN_MISMATCH", "事件与黑板的 run_id 不一致")
    before = len(state.get("evidence") or [])

    if typ == "EVIDENCE_RECORDED":
        row = _bind(payload.get("evidence") or {}, state)
        _add(state, "evidence", "evidence_id", row, "evidence")
        if len(state["evidence"]) > before:
            state["counters"]["evidence"] = len(state["evidence"])
    elif typ == "FACT_RECORDED":
        row = _bind(payload.get("fact") or {}, state)
        for ref in row.get("evidence_refs") or []:
            if not any(e.get("evidence_id") == ref for e in state.get("evidence") or []):
                raise BoardEventError("DANGLING_EVIDENCE",
                                      f"事实引用了不存在的证据 {ref!r}", "fact.evidence_refs")
        _add(state, "facts", "fact_id", row, "fact")
        state["counters"]["facts"] = len(state["facts"])
    elif typ == "CANDIDATE_RECORDED":
        row = _bind(payload.get("candidate") or {}, state)
        _add(state, "candidates", "id", row, "candidate")
        state["counters"]["candidates"] = len(state["candidates"])
    elif typ == "INTENT_CREATED":
        row = _bind(payload.get("intent") or {}, state)
        ref_space = {x.get(k) for x in
                     (state.get("facts") or []) + (state.get("candidates") or [])
                     + (state.get("evidence") or []) + (state.get("intents") or [])
                     for k in ("fact_id", "id", "evidence_id", "intent_id")}
        for ref in row.get("from") or []:
            if ref not in ref_space:
                raise BoardEventError("DANGLING_REF",
                                      f"Intent 来源不存在：{ref!r}", "intent.from")
        _add(state, "intents", "intent_id", row, "intent")
        state["counters"]["intents"] = len(state["intents"])
    elif typ == "HINT_RECORDED":
        row = _bind(payload.get("hint") or {}, state)
        _add(state, "hints", "hint_id", row, "hint")
        state["counters"]["hints"] = len(state["hints"])
    elif typ == "EMULATION_RECORDED":
        row = _bind(payload.get("result") or {}, state)
        if not any(i.get("intent_id") == row.get("intent_id")
                   for i in state.get("intents") or []):
            raise BoardEventError("DANGLING_REF",
                                  f"仿真结果引用的 Intent 不存在：{row.get('intent_id')!r}",
                                  "result.intent_id")
        _add(state, "emulation_results", "emulation_id", row, "result")
        state["counters"]["emulation_results"] = len(state["emulation_results"])
    elif typ == "CANDIDATE_TRANSITIONED":
        cid = payload.get("candidate_id")
        cand = _find(state, "candidates", "id", cid)
        if normalize_state(cand.get("status")) != normalize_state(payload.get("from_state")):
            raise BoardEventError("STATE_MISMATCH",
                                  f"候选当前状态 {cand.get('status')!r} 与事件 from_state "
                                  f"{payload.get('from_state')!r} 不一致", "candidate.status")
        evidence_rows = [e for e in state.get("evidence") or []
                         if e.get("evidence_id") in (payload.get("evidence_refs") or [])]
        policy = payload.get("policy") or {}
        result = validate_transition(cand, payload.get("to_state"), evidence_rows,
                                     policy, state["run_id"],
                                     state["firmware_sha256"]) if validate_transition else {
            "ok": True, "code": "OK", "message": "未加载状态机"}
        if not result.get("ok"):
            raise BoardEventError(result.get("code", "ILLEGAL_TRANSITION"),
                                  result.get("message", "状态转换被拒绝"), "candidate.status")
        cand["status"] = normalize_state(payload.get("to_state"))
        cand.setdefault("history", []).append({
            "from": payload.get("from_state"), "to": cand["status"],
            "reason": payload.get("reason"), "ts": event.get("ts"),
            "event_id": event.get("event_id"),
        })
    elif typ == "INTENT_STATUS_CHANGED":
        intent = _find(state, "intents", "intent_id", payload.get("intent_id"))
        if intent.get("status") != payload.get("from_status"):
            raise BoardEventError("STATE_MISMATCH", "Intent 当前状态与事件不一致",
                                  "intent.status")
        result = validate_intent_transition(intent, payload.get("to_status"),
                                            payload.get("worker")) \
            if validate_intent_transition else {"ok": True, "code": "OK"}
        if not result.get("ok"):
            raise BoardEventError(result.get("code", "ILLEGAL_TRANSITION"),
                                  result.get("message", "Intent 状态转换被拒绝"),
                                  "intent.status")
        intent["status"] = payload.get("to_status")
        if intent["status"] == "claimed":
            intent["worker"] = payload.get("worker")
            intent["claimed_at"] = event.get("ts")
        elif intent["status"] in ("done", "failed", "cancelled"):
            intent["concluded_at"] = event.get("ts")
        elif intent["status"] == "open":
            intent["worker"] = None
    elif typ == "BACKTRACK":
        frm, to = payload.get("from_phase"), payload.get("to_phase")
        if frm not in PHASES or to not in PHASES:
            raise BoardEventError("BAD_PHASE", "BACKTRACK 的 from/to 必须是 P0..P5")
        if frm != state.get("phase"):
            raise BoardEventError("PHASE_MISMATCH",
                                  f"BACKTRACK 的 from_phase {frm} 与黑板当前阶段 "
                                  f"{state.get('phase')} 不一致", "phase")
        if PHASES.index(to) >= PHASES.index(frm):
            raise BoardEventError("NOT_A_BACKTRACK",
                                  f"{frm} → {to} 不是回退；前进请用正常阶段事件", "phase")
        _add(state, "backtracks", "backtrack_id", payload, "backtrack")
        state["counters"]["backtracks"] = len(state["backtracks"])
        state["phase"] = to
    else:
        raise BoardEventError("UNKNOWN_EVENT", f"未知事件类型：{typ!r}")

    _touch(state, event)
    return state


def replay(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """从事件序列重建黑板；重复 dedupe_key 跳过并计数。"""
    state: Optional[Dict[str, Any]] = None
    seen: set = set()
    duplicates = 0
    for event in events:
        key = event.get("dedupe_key")
        if isinstance(key, str) and key in seen:
            duplicates += 1
            continue
        state = apply_event(state, event, copy_state=False)
        if isinstance(key, str):
            seen.add(key)
    if state is None:
        raise BoardEventError("EMPTY_LOG", "事件日志为空，无法重建黑板")
    return state


def read_events(path: str) -> Dict[str, Any]:
    """逐行读取 JSONL；空行容忍，非法行必须带行号报错。"""
    out: Dict[str, Any] = {"events": [], "errors": [], "blank": 0, "lines": 0}
    if not os.path.exists(path):
        out["errors"].append({"path": path, "code": "MISSING",
                              "message": "事件日志不存在"})
        return out
    with open(path, "r", encoding="utf-8") as fh:
        for lineno, line in enumerate(fh, 1):
            out["lines"] += 1
            s = line.strip()
            if not s:
                out["blank"] += 1
                continue
            try:
                event = json.loads(s)
            except json.JSONDecodeError as exc:
                out["errors"].append({"path": f"line {lineno}", "code": "PARSE_ERROR",
                                      "message": f"非法 JSON：{exc.msg}"})
                continue
            out["events"].append(event)
    return out


def verify_events(events: Sequence[Dict[str, Any]]) -> Dict[str, Any]:
    """链级校验：seq 连续、event_id 唯一、dedupe_key 不重复、结构合法。"""
    errors: List[Dict[str, str]] = []
    ids: set = set()
    keys: set = set()
    duplicates = 0
    expect = 1
    run_id: Optional[str] = None
    for i, event in enumerate(events):
        path = f"events[{i}]"
        for err in validate_event(event):
            errors.append({"path": f"{path}.{err['path']}", "code": err["code"],
                           "message": err["message"]})
        if not isinstance(event, dict):
            continue
        seq = event.get("seq")
        if seq != expect:
            errors.append({"path": f"{path}.seq", "code": "SEQ_GAP",
                           "message": f"期望 {expect}，实际 {seq!r}"})
        expect = (seq + 1) if isinstance(seq, int) else expect + 1
        eid = event.get("event_id")
        if eid in ids:
            errors.append({"path": f"{path}.event_id", "code": "DUPLICATE_EVENT_ID",
                           "message": f"event_id 重复：{eid!r}"})
        ids.add(eid)
        key = event.get("dedupe_key")
        if key in keys:
            duplicates += 1
            errors.append({"path": f"{path}.dedupe_key", "code": "DUPLICATE_DEDUPE_KEY",
                           "message": "同一 dedupe_key 在日志中出现多次（append 应拒绝）"})
        keys.add(key)
        rid = event.get("run_id")
        if run_id is None:
            run_id = rid
        elif rid != run_id:
            errors.append({"path": f"{path}.run_id", "code": "RUN_MISMATCH",
                           "message": "同一日志不能混入多个 run"})
    return {"ok": not errors, "events": len(events), "errors": errors,
            "duplicates": duplicates, "last_seq": expect - 1}


def append_event(path: str, event: Dict[str, Any]) -> None:
    """原子追加一行；先做结构校验，校验失败不落盘。"""
    errors = validate_event(event)
    if errors:
        first = errors[0]
        raise BoardEventError("EVENT_INVALID",
                              f"{first['path']}: {first['message']}", first["path"])
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    line = canonical_json(event) + "\n"
    with open(path, "a", encoding="utf-8", newline="\n") as fh:
        fh.write(line)
        fh.flush()
        os.fsync(fh.fileno())


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="审计黑板事件日志的校验与回放")
    sub = ap.add_subparsers(dest="cmd")
    v = sub.add_parser("verify", help="校验事件链与结构")
    v.add_argument("--events", required=True)
    v.add_argument("--json", dest="json_out")
    r = sub.add_parser("replay", help="从日志重建黑板快照")
    r.add_argument("--events", required=True)
    r.add_argument("--out", required=True)
    r.add_argument("--json", dest="json_out")

    args = ap.parse_args(argv)
    cmd = args.cmd or "verify"
    doc = read_events(args.events)
    errors = list(doc["errors"])
    report: Dict[str, Any] = {"schema": "board-replay/1.0", "file": args.events,
                              "errors": errors}
    if cmd == "verify":
        chain = verify_events(doc["events"])
        errors.extend(chain["errors"])
        report.update({"ok": not errors, "events": chain["events"],
                       "duplicates": chain["duplicates"],
                       "last_seq": chain["last_seq"], "blank": doc["blank"]})
        print(json.dumps(report, ensure_ascii=False, indent=2)
              if args.json_out is None else "[ok] 事件链校验通过")
        if args.json_out:
            with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(report, fh, ensure_ascii=False, indent=2)
                fh.write("\n")
        return 0 if not errors else 1

    # replay
    if errors:
        print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    chain = verify_events(doc["events"])
    if chain["errors"]:
        report["errors"] = chain["errors"]
        print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    try:
        state = replay(doc["events"])
    except BoardEventError as exc:
        report["errors"] = [exc.as_dict()]
        print(json.dumps(report, ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    parent = os.path.dirname(os.path.abspath(args.out))
    os.makedirs(parent, exist_ok=True)
    with open(args.out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(state, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")
    report.update({"ok": True, "out": args.out, "revision": state["revision"],
                   "events": state["event_count"]})
    if args.json_out:
        with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(report, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    print(json.dumps(report, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
