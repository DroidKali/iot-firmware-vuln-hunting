#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""审计黑板存储：事件日志 + 快照 + 去重 + 导入（ROADMAP M1）。

存储模型
--------
* `audit-events.jsonl` 是真相源：只追加、不可改写，回放能重建全部状态；
* `audit-board.json` 是加速器：每次成功追加后原子替换；损坏可从日志恢复；
* 同 ID 同内容重复记录是幂等的；同 ID 不同内容拒绝（DUPLICATE_ID_CONFLICT）；
* 同 `dedupe_key` 的事件不会重复写日志，重试安全；
* 所有对象绑定同一个 run_id 与 firmware_sha256，跨 run 引用直接拒绝。

Phase 0–5 产物导入
-------------------
manifest / layer1 / stages 各生成一条 evidence + 一条 fact，candidate 逐条导入。
EMBA 适配器产物（emba-import/1.0）按 evidence 先、fact 后的顺序导入；适配器
已经把「静态发现 / 运行进程 / 端口响应」编码成不同 Fact.type，黑板不再做二次解释。
导入不改变原产物，也不改变 coverage_gate 的判定：门禁仍只读原有结构化文件，
黑板只是把「已经发生过什么」变成可回放的事实。

用法
----
    python scripts/board_store.py init --workspace runs/demo --run-id RUN-1 \
        --firmware-sha256 <64hex>
    python scripts/board_store.py import --workspace runs/demo \
        --manifest manifest.json --layer1 layer1.json --candidates cand.jsonl
    python scripts/board_store.py verify --workspace runs/demo
    python scripts/board_store.py show --workspace runs/demo

退出码：0 成功；1 拒绝/校验失败；2 用法或 IO 错误。纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence

try:
    from board_events import (BoardEventError, append_event, apply_event,
                              canonical_json, make_dedupe_key, make_event,
                              new_state, read_events, replay, utc_now,
                              verify_events)
    from board_transitions import (normalize_state, normalize_risk_disposition,
                                   validate_risk_disposition)
    from contracts import summarize as _contract_summary
    from contracts import validate_board_state as _validate_board_state
    from contracts import validate_emba_import as _validate_emba_import
except Exception as exc:  # pragma: no cover
    raise SystemExit(f"无法加载同目录模块：{exc}")

VERSION = "1.0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
EVENTS_NAME = "audit-events.jsonl"
BOARD_NAME = "audit-board.json"


class StoreError(Exception):
    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


def _atomic_json(path: str, obj: Any) -> None:
    """同目录临时文件 + os.replace，避免快照写一半。"""
    parent = os.path.dirname(os.path.abspath(path))
    os.makedirs(parent, exist_ok=True)
    tmp = f"{path}.tmp.{os.getpid()}"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _mtime_iso(path: str) -> str:
    return datetime.fromtimestamp(os.path.getmtime(path), timezone.utc) \
        .isoformat(timespec="seconds").replace("+00:00", "Z")


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _short_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:12]


def _artifact(path: str) -> Dict[str, Any]:
    return {"path": os.path.abspath(path), "sha256": file_sha256(path),
            "size": os.path.getsize(path)}


class BoardStore:
    """一个 run 的黑板；所有写操作都先验证、再写日志、最后替换快照。"""

    def __init__(self, workspace: str, state: Dict[str, Any],
                 recovered: bool = False) -> None:
        self.workspace = os.path.abspath(workspace)
        self.state = state
        self.recovered = recovered
        self.events_path = os.path.join(self.workspace, EVENTS_NAME)
        self.board_path = os.path.join(self.workspace, BOARD_NAME)

    # ── 生命周期 ─────────────────────────────────────────────────────────────
    @classmethod
    def init(cls, workspace: str, run_id: str, firmware_sha256: str,
             manifest_id: Optional[str] = None, force: bool = False,
             ts: Optional[str] = None, phase: str = "P0") -> "BoardStore":
        if not isinstance(run_id, str) or not run_id.strip():
            raise StoreError("BAD_RUN_ID", "run_id 必须是非空字符串")
        if not isinstance(firmware_sha256, str) or not HEX64.match(firmware_sha256.lower()):
            raise StoreError("BAD_FIRMWARE_HASH", "firmware_sha256 必须是 64 位十六进制")
        if phase not in ("P0", "P1", "P2", "P3", "P4", "P5"):
            raise StoreError("BAD_PHASE", "phase 必须是 P0..P5")
        ws = os.path.abspath(workspace)
        events = os.path.join(ws, EVENTS_NAME)
        board = os.path.join(ws, BOARD_NAME)
        if os.path.exists(events) and os.path.getsize(events) > 0 and not force:
            raise StoreError("ALREADY_EXISTS", f"{events} 已存在；如需重建请 --force")
        os.makedirs(ws, exist_ok=True)
        if force:
            for path in (events, board):
                if os.path.exists(path):
                    os.remove(path)
        event = make_event(run_id, 1, "BOARD_INITIALIZED",
                           {"firmware_sha256": firmware_sha256.lower(),
                            "manifest_id": manifest_id,
                            "phase": phase}, ts=ts)
        state = apply_event(None, event)
        append_event(events, event)
        _atomic_json(board, state)
        return cls(ws, state)

    @classmethod
    def load(cls, workspace: str) -> "BoardStore":
        ws = os.path.abspath(workspace)
        events = os.path.join(ws, EVENTS_NAME)
        board = os.path.join(ws, BOARD_NAME)
        doc = read_events(events)
        if doc["errors"]:
            raise StoreError("EVENTS_CORRUPT", doc["errors"][0]["message"])
        chain = verify_events(doc["events"])
        if chain["errors"]:
            raise StoreError("EVENTS_INVALID", chain["errors"][0]["message"])
        try:
            state = replay(doc["events"])
        except BoardEventError as exc:
            raise StoreError(exc.code, exc.message) from exc

        recovered = False
        if os.path.exists(board):
            try:
                snap = _read_json(board)
            except (OSError, json.JSONDecodeError):
                snap = None
            if not isinstance(snap, dict) or \
                    snap.get("revision") != state.get("revision") or \
                    snap.get("event_count") != state.get("event_count") or \
                    snap.get("last_event_id") != state.get("last_event_id"):
                recovered = True
        else:
            recovered = True
        if recovered:
            _atomic_json(board, state)
        return cls(ws, state, recovered=recovered)

    def reload(self) -> None:
        other = BoardStore.load(self.workspace)
        self.state = other.state
        self.recovered = other.recovered

    # ── 追加 ─────────────────────────────────────────────────────────────────
    def _seen_keys(self) -> Dict[str, Dict[str, Any]]:
        doc = read_events(self.events_path)
        return {e.get("dedupe_key"): e for e in doc["events"]
                if isinstance(e, dict) and isinstance(e.get("dedupe_key"), str)}

    def append(self, event_type: str, payload: Dict[str, Any],
               ts: Optional[str] = None,
               dedupe_key: Optional[str] = None) -> Dict[str, Any]:
        """验证 → 去重 → 写日志 → 原子替换快照。返回 {ok,duplicate,event,state}。"""
        key = dedupe_key or make_dedupe_key(event_type, payload)
        seen = self._seen_keys()
        if key in seen:
            return {"ok": True, "duplicate": True, "event": seen[key],
                    "state": self.state}
        seq = int(self.state.get("event_count") or 0) + 1
        event = make_event(self.state["run_id"], seq, event_type, payload,
                           ts=ts, dedupe_key=key)
        try:
            candidate = apply_event(self.state, event)
        except BoardEventError as exc:
            raise StoreError(exc.code, exc.message) from exc
        append_event(self.events_path, event)
        _atomic_json(self.board_path, candidate)
        self.state = candidate
        return {"ok": True, "duplicate": False, "event": event,
                "state": candidate}

    def _bind(self, row: Dict[str, Any]) -> Dict[str, Any]:
        if not isinstance(row, dict):
            raise StoreError("BAD_OBJECT", "记录必须是 JSON 对象")
        out = dict(row)
        for key, want in (("run_id", self.state["run_id"]),
                          ("firmware_sha256", self.state["firmware_sha256"])):
            if key in out and out[key] != want:
                raise StoreError("RUN_MISMATCH" if key == "run_id"
                                 else "FIRMWARE_MISMATCH",
                                 f"{key} 与黑板不一致")
            out[key] = want
        return out

    def record_evidence(self, evidence: Dict[str, Any],
                        ts: Optional[str] = None) -> Dict[str, Any]:
        return self.append("EVIDENCE_RECORDED",
                           {"evidence": self._bind(evidence)}, ts=ts)

    def record_fact(self, fact: Dict[str, Any], ts: Optional[str] = None) -> Dict[str, Any]:
        return self.append("FACT_RECORDED", {"fact": self._bind(fact)}, ts=ts)

    def record_candidate(self, candidate: Dict[str, Any],
                         ts: Optional[str] = None) -> Dict[str, Any]:
        row = self._bind(candidate)
        if not isinstance(row.get("id"), str) or not row["id"].strip():
            raise StoreError("BAD_CANDIDATE_ID", "候选必须有非空 id")
        row.setdefault("status", "hypothesis")
        return self.append("CANDIDATE_RECORDED", {"candidate": row}, ts=ts)

    def record_intent(self, intent: Dict[str, Any],
                      ts: Optional[str] = None) -> Dict[str, Any]:
        return self.append("INTENT_CREATED", {"intent": self._bind(intent)}, ts=ts)

    def record_hint(self, hint: Dict[str, Any], ts: Optional[str] = None) -> Dict[str, Any]:
        return self.append("HINT_RECORDED", {"hint": self._bind(hint)}, ts=ts)

    def record_emulation(self, result: Dict[str, Any],
                         ts: Optional[str] = None) -> Dict[str, Any]:
        return self.append("EMULATION_RECORDED",
                           {"result": self._bind(result)}, ts=ts)

    def transition(self, candidate_id: str, to_state: str, reason: str,
                   evidence_refs: Optional[Sequence[str]] = None,
                   policy: Optional[Dict[str, Any]] = None,
                   ts: Optional[str] = None) -> Dict[str, Any]:
        cand = self._find("candidates", "id", candidate_id)
        payload = {
            "candidate_id": candidate_id,
            "from_state": cand.get("status"),
            "to_state": to_state,
            "reason": reason,
            "evidence_refs": list(evidence_refs or []),
            "policy": policy or {},
        }
        return self.append("CANDIDATE_TRANSITIONED", payload, ts=ts)

    def set_intent_status(self, intent_id: str, to_status: str,
                          worker: Optional[str] = None,
                          ts: Optional[str] = None) -> Dict[str, Any]:
        intent = self._find("intents", "intent_id", intent_id)
        payload = {"intent_id": intent_id, "from_status": intent.get("status"),
                   "to_status": to_status, "worker": worker}
        return self.append("INTENT_STATUS_CHANGED", payload, ts=ts)

    def backtrack(self, from_phase: str, to_phase: str, reason: str,
                  evidence_refs: Sequence[str],
                  approved_by: Optional[str] = None,
                  ts: Optional[str] = None) -> Dict[str, Any]:
        bid = "BT-" + _short_hash({"from": from_phase, "to": to_phase,
                                   "reason": reason,
                                   "evidence": list(evidence_refs)})
        payload = {"backtrack_id": bid, "from_phase": from_phase,
                   "to_phase": to_phase, "reason": reason,
                   "evidence_refs": list(evidence_refs),
                   "approved_by": approved_by}
        return self.append("BACKTRACK", payload, ts=ts)

    # ── 查询 ─────────────────────────────────────────────────────────────────
    def _find(self, key: str, id_key: str, rid: str) -> Dict[str, Any]:
        for row in self.state.get(key) or []:
            if isinstance(row, dict) and row.get(id_key) == rid:
                return row
        raise StoreError("NOT_FOUND", f"{key} 中找不到 {id_key}={rid!r}")

    def summary(self) -> Dict[str, Any]:
        s = self.state
        return {
            "schema": "board-summary/1.0",
            "run_id": s.get("run_id"),
            "firmware_sha256": s.get("firmware_sha256"),
            "manifest_id": s.get("manifest_id"),
            "phase": s.get("phase"),
            "revision": s.get("revision"),
            "event_count": s.get("event_count"),
            "counts": dict(s.get("counters") or {}),
            "recovered": self.recovered,
        }

    def verify(self) -> Dict[str, Any]:
        errors = _validate_board_state(self.state)
        doc = read_events(self.events_path)
        chain = verify_events(doc["events"])
        errors = list(errors) + list(doc["errors"]) + list(chain["errors"])
        return {"ok": not errors, "errors": errors,
                "summary": self.summary(), "duplicates": chain["duplicates"]}

    # ── Phase 0–5 产物导入 ──────────────────────────────────────────────────
    def _import_manifest(self, path: str) -> Dict[str, Any]:
        doc = _read_json(path)
        sha = file_sha256(path)
        eid = "E-FW-" + sha[:12]
        observed = _mtime_iso(path)
        ev = {
            "schema": "evidence/1.1", "evidence_id": eid,
            "run_id": self.state["run_id"],
            "firmware_sha256": self.state["firmware_sha256"],
            "type": "static", "observed_at": observed, "status": "parsed",
            "source": {"type": "tool-report", "tool": "firmware-manifest",
                       "path": os.path.abspath(path)},
            "artifact": _artifact(path),
        }
        self.record_evidence(ev)
        fid = "F-FW-" + sha[:12]
        self.record_fact({
            "schema": "fact/1.0", "fact_id": fid,
            "run_id": self.state["run_id"],
            "firmware_sha256": self.state["firmware_sha256"],
            "type": "firmware", "observed_at": observed,
            "value": {"id": doc.get("id"), "vendor": doc.get("vendor"),
                      "product": doc.get("product"), "version": doc.get("version"),
                      "arch": doc.get("arch")},
            "evidence_refs": [eid],
            "source": {"type": "tool-report", "tool": "firmware-manifest",
                       "path": os.path.abspath(path)},
        })
        return {"evidence": eid, "fact": fid}

    def _import_layer1(self, path: str) -> Dict[str, Any]:
        doc = _read_json(path)
        sha = file_sha256(path)
        eid = "E-L1-" + sha[:12]
        observed = _mtime_iso(path)
        self.record_evidence({
            "schema": "evidence/1.1", "evidence_id": eid,
            "run_id": self.state["run_id"],
            "firmware_sha256": self.state["firmware_sha256"],
            "type": "static", "observed_at": observed, "status": "parsed",
            "source": {"type": "static", "tool": str(doc.get("tool") or "sink-scan"),
                       "path": os.path.abspath(path)},
            "artifact": _artifact(path),
        })
        si = doc.get("scan_integrity") if isinstance(doc.get("scan_integrity"), dict) else {}
        fid = "F-L1-" + sha[:12]
        self.record_fact({
            "schema": "fact/1.0", "fact_id": fid,
            "run_id": self.state["run_id"],
            "firmware_sha256": self.state["firmware_sha256"],
            "type": "scan", "observed_at": observed,
            "value": {"schema": doc.get("schema"), "verdict": si.get("verdict"),
                      "files_total": si.get("files_total"),
                      "files_scanned": si.get("files_scanned"),
                      "findings": len(doc.get("findings") or [])},
            "evidence_refs": [eid],
            "source": {"type": "static", "tool": str(doc.get("tool") or "sink-scan"),
                       "path": os.path.abspath(path)},
        })
        return {"evidence": eid, "fact": fid}

    def _import_stages(self, path: str) -> Dict[str, Any]:
        doc = _read_json(path)
        sha = file_sha256(path)
        eid = "E-ST-" + sha[:12]
        observed = _mtime_iso(path)
        self.record_evidence({
            "schema": "evidence/1.1", "evidence_id": eid,
            "run_id": self.state["run_id"],
            "firmware_sha256": self.state["firmware_sha256"],
            "type": "static", "observed_at": observed, "status": "parsed",
            "source": {"type": "tool-report", "tool": "audit-stages",
                       "path": os.path.abspath(path)},
            "artifact": _artifact(path),
        })
        stages = doc.get("stages") if isinstance(doc.get("stages"), list) else []
        fid = "F-ST-" + sha[:12]
        self.record_fact({
            "schema": "fact/1.0", "fact_id": fid,
            "run_id": self.state["run_id"],
            "firmware_sha256": self.state["firmware_sha256"],
            "type": "stage", "observed_at": observed,
            "value": {"total": len(stages),
                      "success": sum(1 for s in stages
                                     if isinstance(s, dict)
                                     and s.get("status") == "success"),
                      "statuses": sorted({str(s.get("status")) for s in stages
                                          if isinstance(s, dict)})},
            "evidence_refs": [eid],
            "source": {"type": "tool-report", "tool": "audit-stages",
                       "path": os.path.abspath(path)},
        })
        return {"evidence": eid, "fact": fid}


    # ── EMBA 适配器产物导入 ─────────────────────────────────────────────────
    def _check_emba(self, path: str) -> Dict[str, Any]:
        doc = _read_json(path)
        if not isinstance(doc, dict):
            raise StoreError("EMBA_INVALID", f"{path}: 顶层必须是对象")
        errors = _validate_emba_import(doc)
        if errors:
            raise StoreError("EMBA_INVALID",
                             f"{path}: " + _contract_summary(errors))
        if doc.get("run_id") != self.state["run_id"]:
            raise StoreError("RUN_MISMATCH",
                             f"EMBA run_id={doc.get('run_id')!r} 与黑板 "
                             f"{self.state['run_id']!r} 不一致")
        if str(doc.get("firmware_sha256") or "").lower() != \
                str(self.state["firmware_sha256"]).lower():
            raise StoreError("FIRMWARE_MISMATCH",
                             "EMBA firmware_sha256 与黑板不一致")
        if doc.get("status") == "failed":
            codes = [str(e.get("code")) for e in doc.get("errors") or []]
            raise StoreError("EMBA_FAILED",
                             "EMBA 解析失败，拒绝导入黑板：" + ", ".join(codes))
        return doc

    def _import_emba(self, path: str,
                     doc: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        doc = doc if doc is not None else self._check_emba(path)
        ev_added = ev_dup = 0
        for row in doc.get("evidence") or []:
            res = self.record_evidence(row)
            if res.get("duplicate"):
                ev_dup += 1
            else:
                ev_added += 1
        fact_added = fact_dup = 0
        by_type: Dict[str, int] = {}
        for row in doc.get("facts") or []:
            res = self.record_fact(row)
            typ = str(row.get("type"))
            by_type[typ] = by_type.get(typ, 0) + 1
            if res.get("duplicate"):
                fact_dup += 1
            else:
                fact_added += 1
        return {"input": {"evidence": len(doc.get("evidence") or []),
                          "facts": len(doc.get("facts") or [])},
                "evidence": {"added": ev_added, "duplicates": ev_dup},
                "facts": {"added": fact_added, "duplicates": fact_dup},
                "by_type": by_type,
                "status": doc.get("status")}

    def _load_candidates(self, path: str) -> List[Dict[str, Any]]:
        """读取候选：兼容 JSONL 逐行、envelope、裸数组与单个对象。

        .jsonl 里也可能只有一行 envelope（历史夹具就是这样），所以按内容判断
        而不是只看扩展名；任何一行解析失败都直接报错，不能跳过非法行。
        """
        docs: List[Any] = []
        if path.endswith((".jsonl", ".ndjson")):
            with open(path, "r", encoding="utf-8") as fh:
                for lineno, line in enumerate(fh, 1):
                    s = line.strip()
                    if not s or s.startswith("#"):
                        continue
                    try:
                        docs.append(json.loads(s))
                    except json.JSONDecodeError as exc:
                        raise StoreError("CANDIDATE_PARSE_ERROR",
                                         f"{path}:{lineno} 非法 JSON：{exc.msg}") from exc
        else:
            docs = [_read_json(path)]

        rows: List[Dict[str, Any]] = []
        for i, doc in enumerate(docs, 1):
            if isinstance(doc, dict) and isinstance(doc.get("candidates"), list):
                for j, row in enumerate(doc["candidates"]):
                    if not isinstance(row, dict):
                        raise StoreError("CANDIDATE_PARSE_ERROR",
                                         f"{path}: candidates[{j}] 必须是对象")
                    rows.append(row)
                continue
            if isinstance(doc, list):
                for j, row in enumerate(doc):
                    if not isinstance(row, dict):
                        raise StoreError("CANDIDATE_PARSE_ERROR",
                                         f"{path}: [{j}] 必须是对象")
                    rows.append(row)
                continue
            if isinstance(doc, dict):
                rows.append(doc)
                continue
            raise StoreError("CANDIDATE_PARSE_ERROR",
                             f"{path}: 第 {i} 个文档不是候选对象/数组/envelope")
        for i, row in enumerate(rows):
            cid = row.get("id")
            if not isinstance(cid, str) or not cid.strip():
                raise StoreError("CANDIDATE_PARSE_ERROR",
                                 f"{path}: 第 {i + 1} 个候选缺少非空 id")
        return rows

    def _import_candidates(self, path: str,
                           rows: Optional[List[Dict[str, Any]]] = None) -> Dict[str, Any]:
        rows = rows if rows is not None else self._load_candidates(path)
        added = 0
        duplicates = 0
        ids = []
        for row in rows:
            cid = row["id"]
            res = self.record_candidate(row)
            if res.get("duplicate"):
                duplicates += 1
            else:
                added += 1
            ids.append(cid)
        return {"input": len(rows), "added": added,
                "duplicates": duplicates, "ids": ids}

    def import_artifacts(self, manifest: Optional[str] = None,
                         layer1: Optional[str] = None,
                         stages: Optional[str] = None,
                         candidates: Optional[str] = None,
                         emba: Optional[str] = None) -> Dict[str, Any]:
        report: Dict[str, Any] = {"schema": "board-import/1.0",
                                  "workspace": self.workspace, "items": {}}
        # 先解析最容易出错的输入，避免「导入一半才报错」留下半份状态。
        cand_rows = self._load_candidates(candidates) if candidates else None
        emba_doc = self._check_emba(emba) if emba else None
        if manifest:
            report["items"]["manifest"] = self._import_manifest(manifest)
        if layer1:
            report["items"]["layer1"] = self._import_layer1(layer1)
        if stages:
            report["items"]["stages"] = self._import_stages(stages)
        if candidates:
            report["items"]["candidates"] = self._import_candidates(candidates, cand_rows)
        if emba:
            report["items"]["emba"] = self._import_emba(emba, emba_doc)
        report["summary"] = self.summary()
        return report


# ── CLI ─────────────────────────────────────────────────────────────────────

def _load(path: str) -> Any:
    return _read_json(path)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="审计黑板：快照、事件日志与导入")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("init", help="初始化黑板")
    p.add_argument("--workspace", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--firmware-sha256", required=True)
    p.add_argument("--manifest-id")
    p.add_argument("--phase", default="P0", choices=("P0", "P1", "P2", "P3", "P4", "P5"))
    p.add_argument("--force", action="store_true")

    p = sub.add_parser("import", help="导入 Phase 0–5 结构化产物")
    p.add_argument("--workspace", required=True)
    p.add_argument("--manifest")
    p.add_argument("--layer1")
    p.add_argument("--stages")
    p.add_argument("--candidates")
    p.add_argument("--emba", help="adapter_emba.py 输出的 emba-import/1.0")

    p = sub.add_parser("add", help="追加一条记录")
    p.add_argument("--workspace", required=True)
    p.add_argument("--kind", required=True,
                   choices=("evidence", "fact", "candidate", "intent", "hint", "emulation"))
    p.add_argument("--file", required=True)

    p = sub.add_parser("transition", help="候选状态转换")
    p.add_argument("--workspace", required=True)
    p.add_argument("--candidate", required=True)
    p.add_argument("--to", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--evidence", action="append", default=[])
    p.add_argument("--policy")

    p = sub.add_parser("intent", help="创建 Intent 或改变其状态")
    p.add_argument("--workspace", required=True)
    p.add_argument("--file")
    p.add_argument("--intent")
    p.add_argument("--to-status")
    p.add_argument("--worker")

    p = sub.add_parser("backtrack", help="记录阶段回退")
    p.add_argument("--workspace", required=True)
    p.add_argument("--from-phase", required=True)
    p.add_argument("--to-phase", required=True)
    p.add_argument("--reason", required=True)
    p.add_argument("--evidence", action="append", required=True)
    p.add_argument("--approved-by")

    p = sub.add_parser("replay", help="从日志重建快照")
    p.add_argument("--workspace", required=True)

    p = sub.add_parser("verify", help="校验黑板与日志")
    p.add_argument("--workspace", required=True)

    p = sub.add_parser("show", help="显示黑板摘要")
    p.add_argument("--workspace", required=True)
    p.add_argument("--json", dest="json_out")

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        if args.cmd == "init":
            store = BoardStore.init(args.workspace, args.run_id,
                                    args.firmware_sha256, args.manifest_id,
                                    force=args.force, phase=args.phase)
            print(json.dumps(store.summary(), ensure_ascii=False, indent=2))
            return 0

        store = BoardStore.load(args.workspace)
        if args.cmd == "import":
            report = store.import_artifacts(args.manifest, args.layer1,
                                            args.stages, args.candidates,
                                            args.emba)
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "add":
            row = _load(args.file)
            fn = {"evidence": store.record_evidence, "fact": store.record_fact,
                  "candidate": store.record_candidate, "intent": store.record_intent,
                  "hint": store.record_hint, "emulation": store.record_emulation}[args.kind]
            res = fn(row)
            print(json.dumps({"ok": True, "duplicate": res["duplicate"],
                              "event_id": res["event"]["event_id"]},
                             ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "transition":
            policy = _load(args.policy) if args.policy else {}
            res = store.transition(args.candidate, args.to, args.reason,
                                   args.evidence, policy)
            print(json.dumps({"ok": True, "duplicate": res["duplicate"],
                              "event_id": res["event"]["event_id"],
                              "status": store._find("candidates", "id",
                                                    args.candidate)["status"]},
                             ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "intent":
            if args.file:
                res = store.record_intent(_load(args.file))
            elif args.intent and args.to_status:
                res = store.set_intent_status(args.intent, args.to_status, args.worker)
            else:
                print("[error] intent 需要 --file，或 --intent 与 --to-status", file=sys.stderr)
                return 2
            print(json.dumps({"ok": True, "duplicate": res["duplicate"],
                              "event_id": res["event"]["event_id"]},
                             ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "backtrack":
            res = store.backtrack(args.from_phase, args.to_phase, args.reason,
                                  args.evidence, args.approved_by)
            print(json.dumps({"ok": True, "duplicate": res["duplicate"],
                              "event_id": res["event"]["event_id"],
                              "phase": store.state["phase"]},
                             ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "replay":
            store.reload()
            print(json.dumps(store.summary(), ensure_ascii=False, indent=2))
            return 0
        if args.cmd == "verify":
            report = store.verify()
            print(json.dumps(report, ensure_ascii=False, indent=2))
            return 0 if report["ok"] else 1
        if args.cmd == "show":
            doc = store.summary()
            text = json.dumps(doc, ensure_ascii=False, indent=2)
            if args.json_out:
                with open(args.json_out, "w", encoding="utf-8", newline="\n") as fh:
                    fh.write(text + "\n")
            print(text)
            return 0
    except StoreError as exc:
        print(json.dumps({"ok": False, "code": exc.code, "message": exc.message},
                         ensure_ascii=False, indent=2), file=sys.stderr)
        return 1
    except (OSError, json.JSONDecodeError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 2
    return 2


if __name__ == "__main__":
    raise SystemExit(main())