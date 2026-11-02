#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qiling 定向仿真 runner（在沙箱容器内运行）。

这个脚本不负责判定漏洞，只负责：
* 读 /out/qiling-plan.json，按计划安装 syscall / API / 地址 Hook；
* 把命中 Hook 的参数、机制、触发标记写成 /out/qiling-events.jsonl；
* 把运行结果、异常、Qiling 版本写成 /out/qiling-runner.json。

安全边界
--------
* 只在 sandbox_run.py 启动的容器里运行；本脚本不提供宿主执行模式。
* 事件是否算 sink-hit 由 adapter_qiling.py 依据 plan.filters 重新计算；runner 的
  trigger 字段只是提示，不能作为漏洞结论。
* 普通 connect/open 等事件只记为 observed；没有 trigger_marker 的调用不会生成
  sink-hit。

依赖：qiling（容器镜像提供）。没有 Qiling 时写失败报告并以 3 退出，不伪造事件。
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import traceback
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

VERSION = "1.0"
SCHEMA_EVENT = "qiling-runner-event/1.0"
SCHEMA_REPORT = "qiling-runner/1.0"
MAX_ARRAY = 32


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: str, obj: Any) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _safe_text(value: Any, limit: int) -> Any:
    if isinstance(value, str):
        if len(value) > limit:
            return value[:limit] + "...<truncated>"
        return value
    if isinstance(value, bytes):
        return value[:limit].hex()
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    if isinstance(value, (list, tuple)):
        return [_safe_text(v, limit) for v in list(value)[:MAX_ARRAY]]
    if isinstance(value, dict):
        return {str(k): _safe_text(v, limit) for k, v in list(value.items())[:MAX_ARRAY]}
    return str(value)[:limit]


def _flatten_strings(value: Any) -> List[str]:
    out: List[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (list, tuple)):
        for item in value:
            out.extend(_flatten_strings(item))
    elif isinstance(value, dict):
        for item in value.values():
            out.extend(_flatten_strings(item))
    return out


def _marker_hit(args: Dict[str, Any], markers: List[str]) -> bool:
    if not markers:
        return False
    for text in _flatten_strings(args):
        for marker in markers:
            if marker and marker in text:
                return True
    return False


class EventSink:
    def __init__(self, path: str, max_events: int, max_string: int) -> None:
        self.path = path
        self.max_events = max_events
        self.max_string = max_string
        self.count = 0
        self.truncated = False
        self.fh = open(path, "w", encoding="utf-8", newline="\n")
        self.hook_errors: List[Dict[str, str]] = []

    def emit(self, mechanism: str, hook: str, phase: str,
             args: Dict[str, Any], trigger: bool,
             classified_as: str, context: Optional[Dict[str, Any]] = None) -> None:
        if self.count >= self.max_events:
            self.truncated = True
            return
        self.count += 1
        row = {
            "schema": SCHEMA_EVENT,
            "seq": self.count,
            "mechanism": mechanism,
            "hook": hook,
            "phase": phase,
            "trigger": bool(trigger),
            "classified_as": classified_as,
            "args": _safe_text(args, self.max_string),
        }
        if context:
            row["context"] = _safe_text(context, self.max_string)
        self.fh.write(canonical_json(row) + "\n")
        self.fh.flush()

    def close(self) -> None:
        try:
            self.fh.flush()
            os.fsync(self.fh.fileno())
        finally:
            self.fh.close()


def _arch_context(ql: Any) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {}
    try:
        ctx["pc"] = "0x%x" % int(ql.arch.regs.arch_pc)
    except Exception:
        pass
    try:
        ctx["arch"] = str(ql.arch.type.name)
    except Exception:
        pass
    try:
        ctx["bits"] = int(ql.arch.bits)
    except Exception:
        pass
    try:
        tid = getattr(ql.os, "thread_id", None)
        if isinstance(tid, int):
            ctx["tid"] = tid
    except Exception:
        pass
    return ctx


def _read_cstring(ql: Any, addr: Any) -> Any:
    try:
        return ql.os.utils.read_cstring(int(addr))
    except Exception:
        try:
            return ql.mem.string(int(addr))
        except Exception:
            return "<unreadable:0x%x>" % int(addr)


def _read_string_array(ql: Any, addr: Any) -> List[str]:
    out: List[str] = []
    try:
        ptr = int(addr)
        size = max(1, int(getattr(ql.arch, "bits", 32)) // 8)
        for _ in range(MAX_ARRAY):
            if not ptr:
                break
            item = ql.mem.read_ptr(ptr)
            if not item:
                break
            out.append(_read_cstring(ql, item))
            ptr += size
    except Exception:
        if not out:
            out.append("<unreadable-array:0x%x>" % int(addr))
    return out


def _syscall_handler(spec: Dict[str, Any], sink: EventSink,
                     filters: Dict[str, Any]):
    name = str(spec.get("name"))
    mechanisms = str(spec.get("mechanism") or "syscall")
    phase = str(spec.get("phase") or "enter")
    arg_specs = spec.get("args") or []
    sink_hooks = set(filters.get("sink_hooks") or [])
    markers = [str(m) for m in (filters.get("trigger_markers") or []) if str(m)]

    def handler(ql: Any, *raw_args: Any) -> None:
        values: Dict[str, Any] = {}
        for i, item in enumerate(arg_specs):
            key = str(item.get("name") or ("arg%d" % i))
            kind = str(item.get("kind") or "int")
            raw = raw_args[i] if i < len(raw_args) else None
            if kind == "string":
                values[key] = _read_cstring(ql, raw) if raw is not None else None
            elif kind == "string_array":
                values[key] = _read_string_array(ql, raw) if raw is not None else []
            elif kind == "hex":
                try:
                    values[key] = "0x%x" % int(raw)
                except Exception:
                    values[key] = raw
            else:
                try:
                    values[key] = int(raw)
                except Exception:
                    values[key] = raw
        trigger = name in sink_hooks and _marker_hit(values, markers)
        sink.emit(mechanisms, name, phase, values, trigger,
                  "sink-hit" if trigger else "observed", _arch_context(ql))

    return handler


def _api_handler(spec: Dict[str, Any], sink: EventSink,
                 filters: Dict[str, Any]):
    name = str(spec.get("name"))
    mechanism = str(spec.get("mechanism") or "api")
    phase = str(spec.get("phase") or "enter")
    signature = spec.get("signature") or {}
    sink_hooks = set(filters.get("sink_hooks") or [])
    markers = [str(m) for m in (filters.get("trigger_markers") or []) if str(m)]

    def handler(ql: Any) -> None:
        values: Dict[str, Any] = {}
        try:
            from qiling.os.const import INTEGER, POINTER, STRING
            type_map = {"STRING": STRING, "POINTER": POINTER, "INTEGER": INTEGER}
            sig = {str(k): type_map.get(str(v), STRING) for k, v in signature.items()}
            if sig:
                params = ql.os.resolve_fcall_params(sig)
                for key, value in params.items():
                    if isinstance(value, (bytes, bytearray)):
                        value = bytes(value).decode("utf-8", "replace")
                    values[str(key)] = value
        except Exception as exc:
            values["_resolve_error"] = "%s: %s" % (type(exc).__name__, exc)
        trigger = name in sink_hooks and _marker_hit(values, markers)
        sink.emit(mechanism, name, phase, values, trigger,
                  "sink-hit" if trigger else "observed", _arch_context(ql))

    return handler


def _address_handler(spec: Dict[str, Any], sink: EventSink,
                     filters: Dict[str, Any]):
    name = str(spec.get("name") or ("0x%x" % int(spec.get("address") or 0)))
    mechanism = str(spec.get("mechanism") or "libc")
    phase = str(spec.get("phase") or "enter")
    arg_specs = spec.get("args") or []
    sink_hooks = set(filters.get("sink_hooks") or [])
    markers = [str(m) for m in (filters.get("trigger_markers") or []) if str(m)]

    def handler(ql: Any) -> None:
        values: Dict[str, Any] = {}
        for i, item in enumerate(arg_specs):
            key = str(item.get("name") or ("arg%d" % i))
            reg = str(item.get("register") or "")
            try:
                raw = ql.arch.regs.read(reg) if reg else None
            except Exception:
                raw = None
            if str(item.get("kind")) == "string" and raw is not None:
                values[key] = _read_cstring(ql, raw)
            else:
                values[key] = raw
        trigger = name in sink_hooks and _marker_hit(values, markers)
        sink.emit(mechanism, name, phase, values, trigger,
                  "sink-hit" if trigger else "observed", _arch_context(ql))

    return handler


def install_hooks(ql: Any, plan: Dict[str, Any], sink: EventSink) -> Dict[str, Any]:
    from qiling.const import QL_INTERCEPT
    filters = plan.get("filters") or {}
    installed = 0
    failed: List[Dict[str, str]] = []
    for i, spec in enumerate(plan.get("hooks") or []):
        if not isinstance(spec, dict):
            continue
        mechanism = str(spec.get("mechanism") or "")
        name = str(spec.get("name") or "")
        try:
            if mechanism == "syscall":
                ql.os.set_syscall(name, _syscall_handler(spec, sink, filters),
                                  QL_INTERCEPT.ENTER)
            elif mechanism in ("api", "libc"):
                ql.os.set_api(name, _api_handler(spec, sink, filters),
                              QL_INTERCEPT.ENTER)
            elif mechanism == "address":
                addr = int(str(spec.get("address")), 0)
                ql.hook_address(_address_handler(spec, sink, filters), addr)
            else:
                raise ValueError("未知 hook 机制 %r" % mechanism)
            installed += 1
        except Exception as exc:
            # 目标未导入某个 API/libc 符号时 set_api 会抛 TypeError；这是
            # 「该 Hook 不适用于此目标」，不是 guest 执行失败，不能写成 failure
            # 事件，否则会把静态目标误报成一堆执行错误。只记入 hook_errors，
            # 由适配器在结果 limitations 中披露。
            failed.append({"hook": name, "mechanism": mechanism,
                           "error": "%s: %s" % (type(exc).__name__, exc)})
    return {"installed": installed, "failed": failed}


def classify_failure(exc: BaseException) -> Dict[str, Any]:
    text = "%s: %s" % (type(exc).__name__, exc)
    low = text.lower()
    if "importerror" in low or "no module named" in low:
        category = "backend-unavailable"
    elif "filenotfound" in low or "no such file" in low:
        category = "target-missing"
    elif "invalid instruction" in low or "uc_err_invalid_instruction" in low:
        category = "illegal-instruction"
    elif "out of memory" in low or ("memory" in low and "unmapped" in low):
        category = "memory-error"
    elif "timeout" in low:
        category = "timeout"
    else:
        category = "emulation-error"
    return {"category": category, "message": text,
            "retryable": category in ("target-missing", "timeout")}


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="在沙箱内运行 Qiling 并记录 Hook 事件")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--events", default="")
    ap.add_argument("--report", default="")
    ap.add_argument("--version", action="version", version="qiling_runner " + VERSION)
    args = ap.parse_args(argv)

    out_dir = os.path.abspath(args.out)
    os.makedirs(out_dir, exist_ok=True)
    events_path = args.events or os.path.join(out_dir, "qiling-events.jsonl")
    report_path = args.report or os.path.join(out_dir, "qiling-runner.json")
    started = utc_now()
    report: Dict[str, Any] = {
        "schema": SCHEMA_REPORT,
        "tool": "qiling_runner.py",
        "version": VERSION,
        "ok": False,
        "status": "failed",
        "backend": "qiling",
        "qiling_version": None,
        "started_at": started,
        "finished_at": None,
        "target": None,
        "rootfs": None,
        "exit_code": None,
        "event_count": 0,
        "events_truncated": False,
        "hook_errors": [],
        "error": None,
        "python": sys.version.split()[0],
    }
    sink: Optional[EventSink] = None
    streams: List[Any] = []
    try:
        plan = _read_json(args.plan)
        execution = plan.get("execution") or {}
        filters = plan.get("filters") or {}
        target = execution.get("target")
        rootfs = execution.get("rootfs")
        report["target"] = target
        report["rootfs"] = rootfs
        sink = EventSink(events_path, int(filters.get("max_events") or 2000),
                         int(filters.get("max_string") or 512))
        try:
            import qiling
            from qiling import Qiling
            from qiling.const import QL_VERBOSE
        except Exception as exc:
            report["error"] = {
                "category": "backend-unavailable",
                "message": "无法导入 qiling：%s: %s" % (type(exc).__name__, exc),
                "retryable": True,
            }
            report["finished_at"] = utc_now()
            _write_json(report_path, report)
            return 3

        report["qiling_version"] = str(getattr(qiling, "__version__", "unknown"))
        if not isinstance(target, str) or not os.path.isfile(target):
            raise FileNotFoundError("target 不存在或不是普通文件：%r" % target)
        if not isinstance(rootfs, str) or not os.path.isdir(rootfs):
            raise FileNotFoundError("rootfs 不存在或不是目录：%r" % rootfs)
        argv_list = [str(x) for x in (execution.get("argv") or [target])]
        if not argv_list or argv_list[0] != target:
            argv_list = [target] + [x for x in argv_list if x != target]
        env = {str(k): str(v) for k, v in (execution.get("env") or {}).items()}
        ql = Qiling(argv_list, rootfs, env=env, verbose=QL_VERBOSE.DISABLED)

        stdin_path = execution.get("stdin")
        if isinstance(stdin_path, str) and os.path.isfile(stdin_path):
            try:
                stdin_fh = open(stdin_path, "rb")
                ql.os.stdin = stdin_fh
                streams.append(stdin_fh)
            except Exception:
                pass
        stdout_path = os.path.join(out_dir, "qiling-stdout.log")
        stderr_path = os.path.join(out_dir, "qiling-stderr.log")
        try:
            stdout_fh = open(stdout_path, "wb")
            ql.os.stdout = stdout_fh
            streams.append(stdout_fh)
        except Exception:
            pass
        try:
            stderr_fh = open(stderr_path, "wb")
            ql.os.stderr = stderr_fh
            streams.append(stderr_fh)
        except Exception:
            pass

        hooks = install_hooks(ql, plan, sink)
        report["hook_errors"] = hooks["failed"]
        try:
            ql.run()
        except BaseException as exc:
            err = classify_failure(exc)
            report["error"] = err
            report["status"] = "failed"
            report["exit_code"] = 1
            sink.emit("other", "exception", "signal",
                      {"error": err["message"]}, False, "failure",
                      _arch_context(ql))
            report["events_truncated"] = sink.truncated
            report["event_count"] = sink.count
            report["finished_at"] = utc_now()
            _write_json(report_path, report)
            return 1
        try:
            code = int(getattr(ql.os, "exit_code", 0) or 0)
        except Exception:
            code = 0
        report["ok"] = True
        report["status"] = "completed"
        report["exit_code"] = code
        report["finished_at"] = utc_now()
        report["events_truncated"] = sink.truncated
        report["event_count"] = sink.count
        _write_json(report_path, report)
        return 0
    except BaseException as exc:
        report["error"] = classify_failure(exc)
        report["finished_at"] = utc_now()
        if sink is not None:
            report["events_truncated"] = sink.truncated
            report["event_count"] = sink.count
        _write_json(report_path, report)
        return 1
    finally:
        for stream in streams:
            try:
                stream.close()
            except Exception:
                pass
        if sink is not None:
            try:
                sink.close()
            except Exception:
                pass


if __name__ == "__main__":
    raise SystemExit(main())
