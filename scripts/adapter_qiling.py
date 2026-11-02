#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Qiling 定向仿真适配器（ROADMAP M4）。

边界
----
* 只通过 sandbox_run.py 执行；没有宿主回退，沙箱不可用就是 BLOCKED；
* 普通 open/connect 只记 observed；只有命中 trigger_marker 且属于 sink hook
  的调用才生成 sink-hit 证据。重算在适配器里做，不信任 runner 自报；
* system 是 API 层 Hook，execve 是 syscall 层 Hook，机制按计划声明；
* FAILED / BLOCKED / TIMED_OUT 分开，不折叠成「没发现」；
* Qiling 只覆盖用户态；SUCCESS 只表示后端跑完，不等于漏洞。

用法
----
    python scripts/adapter_qiling.py plan --target fw/rootfs/usr/sbin/httpd \
        --firmware-root fw --rootfs fw/rootfs --run-id RUN-1 \
        --intent-id INTENT-1 --firmware-sha256 <64hex> \
        --trigger-marker QLTEST --json qiling-plan.json
    python scripts/adapter_qiling.py run --plan qiling-plan.json --out out/
    python scripts/adapter_qiling.py parse --plan qiling-plan.json \
        --events out/qiling-events.jsonl --runner out/qiling-runner.json

退出码：0 SUCCESS/ready；1 FAILED/PARTIAL；2 用法；3 BLOCKED；4 策略；
5 资源准入；124 TIMED_OUT。纯标准库。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import struct
import subprocess
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Tuple

try:
    from contracts import summarize as _contract_summary
    from contracts import validate_emulation_result as _validate_emulation_result
    from contracts import validate_qiling_import as _validate_qiling_import
    from contracts import validate_qiling_plan as _validate_qiling_plan
except Exception:  # pragma: no cover
    _contract_summary = None
    _validate_emulation_result = None
    _validate_qiling_import = None
    _validate_qiling_plan = None

VERSION = "1.0"
TOOL = "adapter_qiling.py"
SCHEMA_PLAN = "qiling-plan/1.0"
SCHEMA_EVENT = "qiling-event/1.0"
SCHEMA_IMPORT = "qiling-import/1.0"
DEFAULT_IMAGE = "iot-fw/qiling:latest"
DEFAULT_TIMEOUT = 120
DEFAULT_MAX_EVENTS = 2000
DEFAULT_MAX_STRING = 512
SANDBOX_TIMEOUT_PAD = 90
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HERE = os.path.dirname(os.path.abspath(__file__))
SANDBOX_RUN = os.path.join(HERE, "sandbox_run.py")
RUNNER = os.path.join(HERE, "qiling_runner.py")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3
EXIT_POLICY = 4
EXIT_ADMISSION = 5
EXIT_TIMEOUT = 124

NETWORK_HOOKS = {"connect", "socket", "bind", "listen", "accept", "sendto",
                 "recvfrom", "send", "recv", "getaddrinfo", "gethostbyname"}
DEFAULT_SINK_HOOKS = ["system", "popen", "execve", "execl", "execlp",
                      "execvp", "strcpy", "strcat", "sprintf", "snprintf",
                      "memcpy"]
DEFAULT_HOOKS: List[Dict[str, Any]] = [
    {"mechanism": "syscall", "name": "execve", "phase": "enter",
     "args": [{"name": "pathname", "kind": "string"},
              {"name": "argv", "kind": "string_array"},
              {"name": "envp", "kind": "string_array"}]},
    {"mechanism": "syscall", "name": "open", "phase": "enter",
     "args": [{"name": "pathname", "kind": "string"},
              {"name": "flags", "kind": "int"},
              {"name": "mode", "kind": "int"}]},
    {"mechanism": "syscall", "name": "openat", "phase": "enter",
     "args": [{"name": "dirfd", "kind": "int"},
              {"name": "pathname", "kind": "string"},
              {"name": "flags", "kind": "int"},
              {"name": "mode", "kind": "int"}]},
    {"mechanism": "syscall", "name": "unlink", "phase": "enter",
     "args": [{"name": "pathname", "kind": "string"}]},
    {"mechanism": "syscall", "name": "chmod", "phase": "enter",
     "args": [{"name": "pathname", "kind": "string"},
              {"name": "mode", "kind": "int"}]},
    {"mechanism": "syscall", "name": "socket", "phase": "enter",
     "args": [{"name": "domain", "kind": "int"},
              {"name": "type", "kind": "int"},
              {"name": "protocol", "kind": "int"}]},
    {"mechanism": "syscall", "name": "connect", "phase": "enter",
     "args": [{"name": "sockfd", "kind": "int"},
              {"name": "addr", "kind": "hex"},
              {"name": "addrlen", "kind": "int"}]},
    {"mechanism": "syscall", "name": "bind", "phase": "enter",
     "args": [{"name": "sockfd", "kind": "int"},
              {"name": "addr", "kind": "hex"},
              {"name": "addrlen", "kind": "int"}]},
    {"mechanism": "syscall", "name": "listen", "phase": "enter",
     "args": [{"name": "sockfd", "kind": "int"},
              {"name": "backlog", "kind": "int"}]},
    {"mechanism": "syscall", "name": "accept", "phase": "enter",
     "args": [{"name": "sockfd", "kind": "int"},
              {"name": "addr", "kind": "hex"},
              {"name": "addrlen", "kind": "hex"}]},
    {"mechanism": "syscall", "name": "sendto", "phase": "enter",
     "args": [{"name": "sockfd", "kind": "int"},
              {"name": "buf", "kind": "hex"},
              {"name": "len", "kind": "int"},
              {"name": "flags", "kind": "int"},
              {"name": "dest_addr", "kind": "hex"},
              {"name": "addrlen", "kind": "int"}]},
    {"mechanism": "syscall", "name": "recvfrom", "phase": "enter",
     "args": [{"name": "sockfd", "kind": "int"},
              {"name": "buf", "kind": "hex"},
              {"name": "len", "kind": "int"},
              {"name": "flags", "kind": "int"},
              {"name": "src_addr", "kind": "hex"},
              {"name": "addrlen", "kind": "hex"}]},
    {"mechanism": "api", "name": "system", "phase": "enter",
     "signature": {"command": "STRING"},
     "args": [{"name": "command", "kind": "string"}]},
    {"mechanism": "api", "name": "popen", "phase": "enter",
     "signature": {"command": "STRING", "mode": "STRING"},
     "args": [{"name": "command", "kind": "string"},
              {"name": "mode", "kind": "string"}]},
    {"mechanism": "api", "name": "fopen", "phase": "enter",
     "signature": {"path": "STRING", "mode": "STRING"},
     "args": [{"name": "path", "kind": "string"},
              {"name": "mode", "kind": "string"}]},
    {"mechanism": "api", "name": "getenv", "phase": "enter",
     "signature": {"name": "STRING"},
     "args": [{"name": "name", "kind": "string"}]},
    {"mechanism": "libc", "name": "strcpy", "phase": "enter",
     "signature": {"dest": "POINTER", "src": "STRING"},
     "args": [{"name": "dest", "kind": "hex"},
              {"name": "src", "kind": "string"}]},
    {"mechanism": "libc", "name": "strcat", "phase": "enter",
     "signature": {"dest": "POINTER", "src": "STRING"},
     "args": [{"name": "dest", "kind": "hex"},
              {"name": "src", "kind": "string"}]},
    {"mechanism": "libc", "name": "sprintf", "phase": "enter",
     "signature": {"dest": "POINTER", "format": "STRING"},
     "args": [{"name": "dest", "kind": "hex"},
              {"name": "format", "kind": "string"}]},
    {"mechanism": "libc", "name": "snprintf", "phase": "enter",
     "signature": {"dest": "POINTER", "size": "INTEGER", "format": "STRING"},
     "args": [{"name": "dest", "kind": "hex"},
              {"name": "size", "kind": "int"},
              {"name": "format", "kind": "string"}]},
    {"mechanism": "libc", "name": "memcpy", "phase": "enter",
     "signature": {"dest": "POINTER", "src": "POINTER", "n": "INTEGER"},
     "args": [{"name": "dest", "kind": "hex"},
              {"name": "src", "kind": "hex"},
              {"name": "n", "kind": "int"}]},
]


class AdapterError(Exception):
    def __init__(self, code: str, message: str, exit_code: int = 1) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def short_hash(value: Any, n: int = 12) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:n]


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def _read_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _write_json(path: str, obj: Any) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    tmp = path + ".tmp." + str(os.getpid())
    with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _mtime_iso(path: str) -> str:
    return datetime.fromtimestamp(os.path.getmtime(path), timezone.utc) \
        .isoformat(timespec="seconds").replace("+00:00", "Z")


def _artifact(path: str) -> Dict[str, Any]:
    return {"path": os.path.abspath(path), "sha256": file_sha256(path),
            "size": os.path.getsize(path)}


def _container_path(firmware_root: str, path: str) -> Optional[str]:
    root = os.path.abspath(firmware_root)
    target = os.path.abspath(path)
    try:
        rel = os.path.relpath(target, root)
    except ValueError:
        return None
    if rel == os.pardir or rel.startswith(os.pardir + os.sep):
        return None
    return "/firmware/" + rel.replace(os.sep, "/")


def _inside(child: str, parent: str) -> bool:
    try:
        return os.path.commonpath([os.path.abspath(child),
                                   os.path.abspath(parent)]) == os.path.abspath(parent)
    except ValueError:
        return False


def _arch(machine: int, endian: str) -> Optional[str]:
    if machine == 3:
        return "x86"
    if machine == 62:
        return "x86_64"
    if machine == 8:
        return "mipsel" if endian == "<" else "mips"
    if machine == 40:
        return "arm"
    if machine == 183:
        return "arm64"
    if machine == 243:
        return "riscv64"
    return None


def parse_elf(path: str) -> Dict[str, Any]:
    try:
        with open(path, "rb") as fh:
            data = fh.read()
    except OSError as exc:
        return {"ok": False, "code": "ELF_READ_ERROR", "message": str(exc)}
    if len(data) < 52 or data[:4] != b"\x7fELF":
        return {"ok": False, "code": "NOT_ELF", "message": "目标不是 ELF 文件"}
    cls = data[4]
    endian = "<" if data[5] == 1 else ">"
    if cls not in (1, 2):
        return {"ok": False, "code": "ELF_BAD_CLASS", "message": "未知 ELF class"}
    try:
        e_type = struct.unpack_from(endian + "H", data, 16)[0]
        e_machine = struct.unpack_from(endian + "H", data, 18)[0]
        if cls == 1:
            phoff = struct.unpack_from(endian + "I", data, 28)[0]
            phentsize = struct.unpack_from(endian + "H", data, 42)[0]
            phnum = struct.unpack_from(endian + "H", data, 44)[0]
        else:
            phoff = struct.unpack_from(endian + "Q", data, 32)[0]
            phentsize = struct.unpack_from(endian + "H", data, 54)[0]
            phnum = struct.unpack_from(endian + "H", data, 56)[0]
    except struct.error as exc:
        return {"ok": False, "code": "ELF_TRUNCATED", "message": str(exc)}
    loads: List[Tuple[int, int, int, int]] = []
    interp = None
    dynamic = None
    for i in range(phnum):
        off = phoff + i * phentsize
        if off + phentsize > len(data):
            break
        if cls == 1:
            p_type, p_offset, p_vaddr, p_filesz = struct.unpack_from(
                endian + "IIII", data, off)
        else:
            p_type, p_offset, p_vaddr, p_filesz = struct.unpack_from(
                endian + "IIQQ", data, off)
        if p_type == 1:
            loads.append((p_vaddr, p_offset, p_filesz, p_vaddr + p_filesz))
        elif p_type == 3 and p_filesz:
            raw = data[p_offset:p_offset + p_filesz]
            interp = raw.split(b"\x00", 1)[0].decode("utf-8", "replace")
        elif p_type == 2:
            dynamic = (p_offset, p_filesz)

    def to_off(vaddr: int) -> Optional[int]:
        for start, off, filesz, end in loads:
            if start <= vaddr < end:
                delta = vaddr - start
                if delta < filesz:
                    return off + delta
        return None

    needed: List[str] = []
    if dynamic:
        off, size = dynamic
        entsize = 8 if cls == 1 else 16
        fmt = endian + ("II" if cls == 1 else "QQ")
        strtab = None
        strsz = 0
        wanted: List[int] = []
        pos = off
        while pos + entsize <= min(len(data), off + size):
            tag, val = struct.unpack_from(fmt, data, pos)
            pos += entsize
            if tag == 0:
                break
            if tag == 1:
                wanted.append(val)
            elif tag == 5:
                strtab = val
            elif tag == 10:
                strsz = val
        if strtab is not None:
            so = to_off(strtab)
            if so is not None:
                blob = data[so:min(len(data), so + (strsz or 1024 * 1024))]
                for noff in wanted:
                    if noff < len(blob):
                        raw = blob[noff:].split(b"\x00", 1)[0]
                        if raw:
                            needed.append(raw.decode("utf-8", "replace"))
    arch = _arch(e_machine, endian)
    return {"ok": True, "bits": 32 if cls == 1 else 64,
            "endian": "little" if endian == "<" else "big",
            "elf_type": {1: "rel", 2: "exec", 3: "dyn"}.get(e_type, str(e_type)),
            "machine": e_machine, "arch": arch, "interpreter": interp,
            "needed": needed, "dynamic": bool(dynamic)}


def find_library(rootfs: str, name: str) -> Optional[str]:
    base = os.path.basename(name)
    for sub in ("", "lib", "usr/lib", "lib64", "usr/lib64"):
        d = os.path.join(rootfs, sub)
        direct = os.path.join(d, name.lstrip("/") if sub == "" else base)
        if os.path.isfile(direct):
            return direct
        if os.path.isdir(d):
            for entry in os.scandir(d):
                if entry.name == base and entry.is_file():
                    return entry.path
    return None


def _blocker(code: str, message: str, next_action: str) -> Dict[str, str]:
    return {"code": code, "message": message, "next_action": next_action}


def build_plan(target: str, firmware_root: str, rootfs: Optional[str],
               run_id: Optional[str], intent_id: Optional[str],
               firmware_sha256: Optional[str],
               target_sha256: Optional[str] = None,
               extra_args: Optional[List[str]] = None,
               env_pairs: Optional[List[str]] = None,
               stdin_path: Optional[str] = None,
               image: str = DEFAULT_IMAGE,
               timeout_s: int = DEFAULT_TIMEOUT,
               max_events: int = DEFAULT_MAX_EVENTS,
               max_string: int = DEFAULT_MAX_STRING,
               trigger_markers: Optional[List[str]] = None,
               sink_hooks: Optional[List[str]] = None,
               allow_target_outside_rootfs: bool = False) -> Dict[str, Any]:
    fw = os.path.abspath(firmware_root)
    tgt = os.path.abspath(target)
    rfs = os.path.abspath(rootfs or os.path.join(fw, "rootfs"))
    blockers: List[Dict[str, str]] = []
    limitations = [
        "Qiling 只模拟用户态；不覆盖内核、驱动、硬件外设与真实网络。",
        "命中 trigger_marker 只证明参数到达 sink，不等于可利用；漏洞结论仍需候选验证。",
        "SUCCESS 只表示 Qiling 按计划跑完，不表示发现漏洞。",
    ]
    if not os.path.isdir(fw):
        blockers.append(_blocker("FIRMWARE_ROOT_MISSING", "固件根目录不存在：%s" % fw,
                                 "用 --firmware-root 指向已解包的固件目录"))
    if not os.path.isfile(tgt):
        blockers.append(_blocker("TARGET_MISSING", "目标不存在或不是普通文件：%s" % tgt,
                                 "确认目标路径来自 Phase 0/1 的 ELF 清单"))
    if not os.path.isdir(rfs):
        blockers.append(_blocker("ROOTFS_MISSING", "rootfs 不存在或不是目录：%s" % rfs,
                                 "用 --rootfs 指向目标依赖的根文件系统"))
    if not _inside(tgt, fw):
        blockers.append(_blocker("TARGET_OUTSIDE_FIRMWARE", "目标不在 --firmware-root 内",
                                 "把目标放回固件目录，或修正 --firmware-root"))
    if not _inside(rfs, fw):
        blockers.append(_blocker("ROOTFS_OUTSIDE_FIRMWARE", "rootfs 不在 --firmware-root 内",
                                 "把 rootfs 放回固件目录，或修正 --firmware-root"))
    inside_rootfs = _inside(tgt, rfs)
    if not inside_rootfs and not allow_target_outside_rootfs:
        blockers.append(_blocker(
            "TARGET_OUTSIDE_ROOTFS", "目标不在 rootfs 内，Qiling 路径映射不可靠：%s" % tgt,
            "使用 --allow-target-outside-rootfs 明确接受风险，或换用包含目标的 rootfs"))
    if not inside_rootfs and allow_target_outside_rootfs:
        limitations.append("目标位于 rootfs 之外；绝对路径可能无法映射到实际文件。")
    info: Dict[str, Any] = {}
    if os.path.isfile(tgt):
        info = parse_elf(tgt)
        if not info.get("ok"):
            blockers.append(_blocker(str(info.get("code") or "NOT_ELF"),
                                     str(info.get("message") or "目标不是 ELF"),
                                     "确认目标是 Linux ELF 而非脚本或 PE"))
        else:
            if not info.get("arch"):
                blockers.append(_blocker(
                    "ARCH_UNSUPPORTED", "ELF e_machine=%r 不在支持列表" % info.get("machine"),
                    "改用受支持的 MIPS/ARM/x86/RISC-V 目标"))
            interp = info.get("interpreter")
            if interp:
                host_interp = os.path.join(rfs, str(interp).lstrip("/"))
                if not os.path.isfile(host_interp):
                    blockers.append(_blocker(
                        "INTERPRETER_MISSING", "解释器不存在：%s（rootfs 内应为 %s）"
                        % (interp, host_interp),
                        "补齐 rootfs 的动态链接器，或改用静态链接目标"))
            for lib in info.get("needed") or []:
                if not find_library(rfs, str(lib)):
                    blockers.append(_blocker(
                        "LIBRARY_MISSING", "依赖库不存在：%s" % lib,
                        "补齐 rootfs 的 lib/usr/lib，或改用静态链接目标"))
            if target_sha256 and str(target_sha256).lower() != file_sha256(tgt):
                blockers.append(_blocker(
                    "TARGET_HASH_MISMATCH", "目标哈希与 --target-sha256 不一致",
                    "目标可能在计划后被替换；重新解包或重新计算哈希"))
    if not isinstance(run_id, str) or not run_id.strip():
        blockers.append(_blocker("RUN_ID_MISSING", "计划缺少 run_id",
                                 "用 --run-id 绑定本次审计"))
    if not isinstance(intent_id, str) or not intent_id.strip():
        blockers.append(_blocker("INTENT_ID_MISSING", "计划缺少 intent_id",
                                 "用 --intent-id 绑定要验证的 Intent"))
    if not isinstance(firmware_sha256, str) or not HEX64.match(firmware_sha256.lower()):
        blockers.append(_blocker("FIRMWARE_SHA_MISSING",
                                 "--firmware-sha256 必须是 64 位十六进制",
                                 "从固件清单或 sha256sum 取得完整哈希"))
    env: Dict[str, str] = {}
    for pair in env_pairs or []:
        if "=" not in pair:
            blockers.append(_blocker("BAD_ENV", "环境变量必须写成 KEY=VALUE：%r" % pair,
                                     "修正 --env"))
            continue
        key, value = pair.split("=", 1)
        if not key:
            blockers.append(_blocker("BAD_ENV", "环境变量名不得为空", "修正 --env"))
            continue
        env[key] = value
    stdin_info = None
    if stdin_path:
        sp = os.path.abspath(stdin_path)
        if not os.path.isfile(sp):
            blockers.append(_blocker("STDIN_MISSING", "stdin 文件不存在：%s" % sp,
                                     "提供受控输入文件，或去掉 --stdin"))
        else:
            stdin_info = {"host_path": sp, "sha256": file_sha256(sp),
                          "size": os.path.getsize(sp)}
    target_container = _container_path(fw, tgt)
    rootfs_container = _container_path(fw, rfs)
    markers = [str(x) for x in (trigger_markers or []) if str(x)]
    sink_names = [str(x) for x in (sink_hooks or DEFAULT_SINK_HOOKS) if str(x)]
    if not markers:
        blockers.append(_blocker(
            "TRIGGER_MARKERS_MISSING", "计划没有 trigger_marker，无法区分受控触发与普通运行",
            "用 --trigger-marker 指定只在受控输入中出现的字符串"))
    if not sink_names:
        blockers.append(_blocker(
            "SINK_HOOKS_MISSING", "计划没有 sink_hook，事件只能记为 observed",
            "用 --sink-hook 指定要观察的 sink，或使用默认集合"))
    argv = ([target_container] + [str(x) for x in (extra_args or [])]
            if target_container else [])
    plan: Dict[str, Any] = {
        "schema": SCHEMA_PLAN, "tool": TOOL, "version": VERSION,
        "plan_id": "",
        "status": "blocked" if blockers else "ready",
        "run_id": run_id, "intent_id": intent_id,
        "firmware_sha256": (firmware_sha256 or "").lower(),
        "firmware_root": fw,
        "target": {
            "host_path": tgt, "container_path": target_container,
            "sha256": file_sha256(tgt) if os.path.isfile(tgt) else None,
            "size": os.path.getsize(tgt) if os.path.isfile(tgt) else None,
            "arch": info.get("arch"), "bits": info.get("bits"),
            "endian": info.get("endian"), "elf_type": info.get("elf_type"),
            "interpreter": info.get("interpreter"),
            "needed": info.get("needed") or [],
            "inside_rootfs": inside_rootfs,
        },
        "rootfs": {"host_path": rfs, "container_path": rootfs_container,
                   "file_count": sum(len(files) for _, _, files in os.walk(rfs))
                   if os.path.isdir(rfs) else 0},
        "runtime": {"backend": "qiling", "version": "unverified",
                    "image": image, "network": "none", "mode": "sandbox",
                    "python": "python3"},
        "execution": {
            "target": target_container, "rootfs": rootfs_container,
            "argv": argv,
            "guest_argv0": ("/" + os.path.relpath(tgt, rfs).replace(os.sep, "/"))
            if inside_rootfs else target_container,
            "env": env,
            "stdin": ("/out/qiling-stdin.txt" if stdin_info else None),
            "stdin_host": (stdin_info or {}).get("host_path"),
        },
        "hooks": DEFAULT_HOOKS,
        "filters": {
            "version": "qiling-filter/1.0",
            "trigger_markers": markers,
            "sink_hooks": sink_names,
            "max_events": int(max_events), "max_string": int(max_string),
        },
        "budget": {"timeout_s": int(timeout_s)},
        "blockers": blockers, "warnings": [], "limitations": limitations,
    }
    if stdin_info:
        plan["stdin"] = stdin_info
    plan["plan_id"] = "QPL-" + short_hash(
        {k: v for k, v in plan.items() if k != "plan_id"})
    return plan


def validate_plan_doc(plan: Any) -> None:
    if not isinstance(plan, dict):
        raise AdapterError("PLAN_INVALID", "计划顶层必须是对象")
    if _validate_qiling_plan is not None:
        errs = _validate_qiling_plan(plan)
        if errs:
            raise AdapterError("PLAN_INVALID",
                               _contract_summary(errs) if _contract_summary else str(errs),
                               exit_code=2)
    if plan.get("schema") != SCHEMA_PLAN:
        raise AdapterError("PLAN_SCHEMA", "计划 schema 必须是 %s" % SCHEMA_PLAN,
                           exit_code=2)


def verify_plan(plan: Dict[str, Any]) -> List[Dict[str, str]]:
    if plan.get("status") != "ready":
        return list(plan.get("blockers") or [
            _blocker("PLAN_BLOCKED", "计划状态不是 ready", "重新运行 plan")])
    blockers: List[Dict[str, str]] = []
    target = (plan.get("target") or {}).get("host_path")
    rootfs = (plan.get("rootfs") or {}).get("host_path")
    if not isinstance(target, str) or not os.path.isfile(target):
        blockers.append(_blocker("TARGET_MISSING", "目标已不存在：%r" % target,
                                 "重新解包固件或重新生成计划"))
    else:
        expected = (plan.get("target") or {}).get("sha256")
        if expected and file_sha256(target) != expected:
            blockers.append(_blocker("TARGET_HASH_MISMATCH", "目标哈希已变化",
                                     "重新生成计划"))
    if not isinstance(rootfs, str) or not os.path.isdir(rootfs):
        blockers.append(_blocker("ROOTFS_MISSING", "rootfs 已不存在：%r" % rootfs,
                                 "重新解包固件或重新生成计划"))
    stdin_host = (plan.get("stdin") or {}).get("host_path")
    if stdin_host:
        if not os.path.isfile(stdin_host):
            blockers.append(_blocker("STDIN_MISSING", "stdin 文件已不存在：%s" % stdin_host,
                                     "提供受控输入文件"))
        elif file_sha256(stdin_host) != (plan.get("stdin") or {}).get("sha256"):
            blockers.append(_blocker("STDIN_HASH_MISMATCH", "stdin 哈希已变化",
                                     "重新生成计划"))
    return blockers


def _map_mechanism(mechanism: str) -> str:
    return mechanism if mechanism in ("syscall", "api", "libc", "other") else "other"


def _strings(value: Any) -> List[str]:
    out: List[str] = []
    if isinstance(value, str):
        out.append(value)
    elif isinstance(value, (list, tuple)):
        for item in value:
            out.extend(_strings(item))
    elif isinstance(value, dict):
        for item in value.values():
            out.extend(_strings(item))
    return out


def _trigger_hit(args: Dict[str, Any], markers: Sequence[str]) -> bool:
    for text in _strings(args):
        for marker in markers:
            if marker and marker in text:
                return True
    return False


def load_events(path: Optional[str]) -> Tuple[List[Dict[str, Any]], List[Dict[str, str]]]:
    rows: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    if not path:
        return rows, errors
    if not os.path.isfile(path):
        errors.append({"path": path, "code": "EVENTS_MISSING",
                       "message": "事件日志不存在"})
        return rows, errors
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        for lineno, line in enumerate(fh, 1):
            text = line.strip()
            if not text:
                continue
            try:
                row = json.loads(text)
            except json.JSONDecodeError as exc:
                errors.append({"path": "%s:%d" % (path, lineno),
                               "code": "EVENT_PARSE_ERROR",
                               "message": "非法 JSON：%s" % exc.msg})
                continue
            if not isinstance(row, dict):
                errors.append({"path": "%s:%d" % (path, lineno),
                               "code": "EVENT_PARSE_ERROR", "message": "事件必须是对象"})
                continue
            rows.append(row)
    if rows and [r.get("seq") for r in rows] != list(range(1, len(rows) + 1)):
        errors.append({"path": path, "code": "EVENT_SEQ_GAP",
                       "message": "事件 seq 必须从 1 连续"})
    return rows, errors


def normalize_events(raw_events: List[Dict[str, Any]], plan: Dict[str, Any],
                     events_path: str) -> Tuple[List[Dict[str, Any]],
                                                List[Dict[str, str]], List[str]]:
    filters = plan.get("filters") or {}
    markers = [str(x) for x in (filters.get("trigger_markers") or []) if str(x)]
    sink_hooks = set(str(x) for x in (filters.get("sink_hooks") or []))
    out: List[Dict[str, Any]] = []
    errors: List[Dict[str, str]] = []
    warnings: List[str] = []
    for i, raw in enumerate(raw_events, 1):
        hook = str(raw.get("hook") or "")
        if not hook:
            errors.append({"path": events_path, "code": "EVENT_NO_HOOK",
                           "message": "事件缺少 hook 名称"})
            continue
        mechanism = str(raw.get("mechanism") or "other")
        phase = str(raw.get("phase") or "enter")
        args = raw.get("args") if isinstance(raw.get("args"), dict) else {}
        trigger = _trigger_hit(args, markers)
        claimed = str(raw.get("classified_as") or "")
        if claimed == "failure":
            classified = "failure"
        elif hook in sink_hooks and trigger:
            classified = "sink-hit"
        else:
            classified = "observed"
        if claimed == "sink-hit" and classified != "sink-hit":
            warnings.append("runner 声称 %s 是 sink-hit，但未命中 trigger_marker；"
                            "已降级为 observed" % hook)
        event_id = "QE-" + short_hash({"run": plan.get("run_id"), "seq": i,
                                       "hook": hook, "mechanism": mechanism,
                                       "args": args})
        row: Dict[str, Any] = {
            "schema": SCHEMA_EVENT, "event_id": event_id, "seq": i,
            "run_id": plan.get("run_id"),
            "firmware_sha256": plan.get("firmware_sha256"),
            "mechanism": mechanism, "hook": hook, "phase": phase,
            "trigger": bool(trigger and classified == "sink-hit"),
            "classified_as": classified, "args": args,
            "source": {"path": os.path.abspath(events_path), "line": i},
            "filter": {
                "version": str(filters.get("version") or "qiling-filter/1.0"),
                "rule_id": "trigger-marker" if classified == "sink-hit"
                else ("failure" if classified == "failure" else "observe-only"),
                "reason": ("参数命中 trigger_marker 且 hook 属于 sink_hooks"
                           if classified == "sink-hit" else
                           ("runner 失败事件" if classified == "failure"
                            else "无触发标记或非 sink hook，只记录观察")),
            },
        }
        if isinstance(raw.get("context"), dict):
            row["context"] = raw["context"]
        out.append(row)
    return out, errors, warnings


def _evidence_target(plan: Dict[str, Any], target_path: str) -> Dict[str, Any]:
    return {
        "schema": "evidence/1.1",
        "evidence_id": "E-QL-TGT-" + short_hash({"run": plan.get("run_id"),
                                                 "sha": plan.get("target", {}).get("sha256")}),
        "run_id": plan.get("run_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "type": "static", "observed_at": _mtime_iso(target_path),
        "status": "parsed",
        "source": {"type": "manual", "tool": TOOL, "path": target_path},
        "artifact": _artifact(target_path),
        "limitations": ["只证明目标文件字节与架构；不证明它可被 Qiling 执行。"],
    }


def _evidence_run(plan: Dict[str, Any], events_path: str, status: str,
                  rc: Optional[int], parse_errors: int,
                  truncated: bool) -> Dict[str, Any]:
    eid = "E-QL-RUN-" + short_hash({"run": plan.get("run_id"),
                                    "plan": plan.get("plan_id"),
                                    "events": file_sha256(events_path)
                                    if os.path.isfile(events_path) else None})
    ev_status = "parsed"
    lim = ["运行证据只证明 Qiling 进程启动并产生了这些 Hook 事件。"]
    if parse_errors or truncated:
        ev_status = "partial"
        lim.append("事件日志有 %d 条解析错误；截断=%s。" % (parse_errors, truncated))
    if not os.path.isfile(events_path):
        ev_status = "failed"
        lim.append("事件日志不存在，无法复核 Hook 观察。")
    return {
        "schema": "evidence/1.1", "evidence_id": eid,
        "run_id": plan.get("run_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "type": "emulation", "observed_at": utc_now(), "status": ev_status,
        "source": {"type": "emulation", "tool": "qiling", "path": events_path},
        "artifact": _artifact(events_path) if os.path.isfile(events_path) else None,
        "event": {"type": "run", "trigger": False,
                  "args": {"result_status": status, "exit_code": rc}},
        "limitations": lim,
    }


def _evidence_event(plan: Dict[str, Any], event: Dict[str, Any],
                    events_path: str) -> Dict[str, Any]:
    return {
        "schema": "evidence/1.1",
        "evidence_id": "E-QL-EVT-" + short_hash({"run": plan.get("run_id"),
                                                 "event": event.get("event_id")}),
        "run_id": plan.get("run_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "type": "emulation", "observed_at": utc_now(), "status": "parsed",
        "source": {"type": "emulation", "tool": "qiling",
                   "path": os.path.abspath(events_path), "line": event.get("seq")},
        "artifact": _artifact(events_path),
        "hook": {"mechanism": _map_mechanism(str(event.get("mechanism") or "other")),
                 "name": event.get("hook")},
        "event": {"type": event.get("hook"), "trigger": bool(event.get("trigger")),
                  "args": event.get("args") or {}},
        "limitations": [
            "命中 trigger_marker 只证明参数到达该 Hook；不证明可利用或影响范围。",
            "Qiling 用户态 Hook 可能被目标自身实现绕过；未覆盖路径不在本证据内。",
        ],
    }


def _evidence_failure(plan: Dict[str, Any], failure: Dict[str, Any],
                      events_path: str) -> Dict[str, Any]:
    src = {"type": "emulation", "tool": "qiling",
           "path": os.path.abspath(events_path)} if os.path.isfile(events_path) \
        else {"type": "emulation", "tool": "qiling"}
    return {
        "schema": "evidence/1.1",
        "evidence_id": "E-QL-FAIL-" + short_hash({"run": plan.get("run_id"),
                                                  "failure": failure}),
        "run_id": plan.get("run_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "type": "emulation", "observed_at": utc_now(), "status": "parsed",
        "source": src,
        "artifact": _artifact(events_path) if os.path.isfile(events_path) else None,
        "hook": {"mechanism": "other", "name": "exception"},
        "event": {"type": "exception", "trigger": False,
                  "args": {"category": failure.get("category"),
                           "reason": failure.get("reason")}},
        "limitations": ["失败证据只说明这次执行失败的原因；不能据此推断目标没有漏洞。"],
    }


def _fact_target(plan: Dict[str, Any], evidence_id: str,
                 target_path: str) -> Dict[str, Any]:
    target = plan.get("target") or {}
    return {
        "schema": "fact/1.0",
        "fact_id": "F-QL-TGT-" + short_hash({"run": plan.get("run_id"),
                                             "sha": target.get("sha256")}),
        "run_id": plan.get("run_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "type": "elf" if target.get("arch") else "file",
        "observed_at": _mtime_iso(target_path),
        "value": {"path": target_path, "sha256": target.get("sha256"),
                  "arch": target.get("arch"), "bits": target.get("bits"),
                  "endian": target.get("endian"),
                  "interpreter": target.get("interpreter"),
                  "needed": target.get("needed") or []},
        "evidence_refs": [evidence_id],
        "source": {"type": "manual", "tool": TOOL, "path": target_path},
    }


def _fact_run(plan: Dict[str, Any], evidence_refs: List[str], status: str,
              counts: Dict[str, Any], rc: Optional[int],
              failure: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    value: Dict[str, Any] = {
        "status": status, "backend": "qiling",
        "events": counts.get("events", 0), "sink_hits": counts.get("sink_hits", 0),
        "observed": counts.get("observed", 0), "exit_code": rc,
    }
    if failure:
        value["failure"] = failure
    return {
        "schema": "fact/1.0",
        "fact_id": "F-QL-RUN-" + short_hash({"run": plan.get("run_id"),
                                             "plan": plan.get("plan_id"),
                                             "status": status}),
        "run_id": plan.get("run_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "type": "stage", "observed_at": utc_now(), "value": value,
        "evidence_refs": evidence_refs,
        "source": {"type": "emulation", "tool": "qiling",
                   "path": (plan.get("execution") or {}).get("target")},
    }


def _fact_event(plan: Dict[str, Any], event: Dict[str, Any],
                evidence_id: str) -> Dict[str, Any]:
    hook = str(event.get("hook") or "")
    mechanism = str(event.get("mechanism") or "other")
    if hook in NETWORK_HOOKS:
        typ = "network"
    elif mechanism == "syscall":
        typ = "syscall"
    elif mechanism in ("api", "libc"):
        typ = "api-call"
    else:
        typ = "other"
    return {
        "schema": "fact/1.0",
        "fact_id": "F-QL-EVT-" + short_hash({"run": plan.get("run_id"),
                                             "event": event.get("event_id")}),
        "run_id": plan.get("run_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "type": typ, "observed_at": utc_now(),
        "value": {"hook": hook, "mechanism": mechanism,
                  "args": event.get("args") or {}, "trigger": True,
                  "event_id": event.get("event_id")},
        "evidence_refs": [evidence_id],
        "source": {"type": "emulation", "tool": "qiling"},
    }


def _result_failure(status: str, blockers: List[Dict[str, str]],
                    runner: Dict[str, Any],
                    sandbox: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if status not in ("FAILED", "BLOCKED", "TIMED_OUT"):
        return None
    # 沙箱策略阻断优于「计划阻断」：否则 host_fallback 会被错标成 plan-blocked，
    # 看起来像计划写错，而不是隔离边界拒绝执行。
    if status == "BLOCKED":
        mode = str(sandbox.get("mode") or "")
        if mode and mode != "sandbox":
            return {"category": "policy-blocked",
                    "reason": "沙箱报告 mode=%r，拒绝把非 sandbox 结果当仿真" % mode,
                    "retryable": False}
    if blockers:
        return {"category": "plan-blocked",
                "reason": "; ".join("%s: %s" % (b.get("code"), b.get("message"))
                                    for b in blockers[:4]),
                "retryable": False}
    if status == "TIMED_OUT":
        return {"category": "timeout",
                "reason": "沙箱在预算内未结束（timed_out=%s）" % sandbox.get("timed_out"),
                "retryable": True}
    if status == "BLOCKED":
        return {"category": "sandbox-unavailable",
                "reason": "sandbox_run.py 退出 %r，未获得隔离执行环境"
                          % sandbox.get("exit_code"), "retryable": True}
    err = runner.get("error") if isinstance(runner.get("error"), dict) else {}
    return {"category": str(err.get("category") or "emulation-error"),
            "reason": str(err.get("message") or "Qiling runner 报告失败"),
            "retryable": bool(err.get("retryable", False))}


def build_import(plan: Dict[str, Any], raw_events: List[Dict[str, Any]],
                 runner: Dict[str, Any], sandbox: Dict[str, Any],
                 events_path: str, mode: str,
                 parse_errors: Optional[List[Dict[str, str]]] = None,
                 plan_path: Optional[str] = None,
                 extra_errors: Optional[List[Dict[str, str]]] = None) -> Dict[str, Any]:
    errors = list(parse_errors or []) + list(extra_errors or [])
    events, ev_errs, warnings = normalize_events(raw_events, plan, events_path)
    errors.extend(ev_errs)
    sink_events = [e for e in events if e.get("classified_as") == "sink-hit"]
    observed = [e for e in events if e.get("classified_as") == "observed"]
    failures = [e for e in events if e.get("classified_as") == "failure"]
    truncated = bool(runner.get("events_truncated"))
    rc = sandbox.get("exit_code")
    timed_out = bool(sandbox.get("timed_out")) or rc == EXIT_TIMEOUT
    blockers = verify_plan(plan)
    runner_error = runner.get("error") if isinstance(runner.get("error"), dict) else None
    hook_errors = [h for h in (runner.get("hook_errors") or []) if isinstance(h, dict)]
    sink_hooks = {str(x) for x in ((plan.get("filters") or {}).get("sink_hooks") or [])}
    missing_sink_hooks = sorted({str(h.get("hook")) for h in hook_errors
                                 if str(h.get("hook")) in sink_hooks})
    if blockers:
        status = "BLOCKED"
    elif sandbox and (sandbox.get("mode") not in (None, "sandbox", "offline")
                      or sandbox.get("host_fallback")):
        status = "BLOCKED"
        blockers = [_blocker("SANDBOX_POLICY", "沙箱报告非 sandbox 模式",
                             "拒绝在宿主机执行")]
    elif timed_out:
        status = "TIMED_OUT"
    elif rc in (EXIT_BLOCKED, EXIT_POLICY, EXIT_ADMISSION):
        status = "BLOCKED"
    elif runner_error or (runner and runner.get("ok") is False):
        status = "FAILED"
    elif rc not in (None, 0):
        status = "FAILED"
    elif errors or truncated or missing_sink_hooks:
        status = "PARTIAL"
    else:
        status = "SUCCESS"
    failure = _result_failure(status, blockers, runner, sandbox)
    counts = {"events": len(events), "sink_hits": len(sink_events),
              "observed": len(observed), "failure_events": len(failures),
              "parse_errors": len(errors)}
    evidence: List[Dict[str, Any]] = []
    facts: List[Dict[str, Any]] = []
    target_path = (plan.get("target") or {}).get("host_path")
    if isinstance(target_path, str) and os.path.isfile(target_path):
        target_ev = _evidence_target(plan, target_path)
        evidence.append(target_ev)
        facts.append(_fact_target(plan, target_ev["evidence_id"], target_path))
    run_ev = _evidence_run(plan, events_path, status, rc, len(errors), truncated)
    evidence.append(run_ev)
    run_refs = [run_ev["evidence_id"]]
    for event in sink_events:
        ev = _evidence_event(plan, event, events_path)
        evidence.append(ev)
        facts.append(_fact_event(plan, event, ev["evidence_id"]))
        run_refs.append(ev["evidence_id"])
    if failure:
        fail_ev = _evidence_failure(plan, failure, events_path)
        evidence.append(fail_ev)
        run_refs.append(fail_ev["evidence_id"])
    facts.append(_fact_run(plan, run_refs, status, counts, rc, failure))
    limitations = list(plan.get("limitations") or [])
    limitations.extend([
        "Qiling 只覆盖用户态执行；内核、驱动、硬件外设与真实网络不在范围内。",
        "SUCCESS 只表示执行完成；sink-hit 不是漏洞结论，仍需按类型判据验证。",
    ])
    if warnings:
        limitations.extend(warnings)
    if errors:
        limitations.append("有 %d 条事件无法完整解析；结果按 PARTIAL 处理。" % len(errors))
    if truncated:
        limitations.append("事件达到 max_events 上限，后续 Hook 未记录。")
    if hook_errors:
        names = ", ".join(sorted({str(h.get("hook")) for h in hook_errors}))
        limitations.append("%d 个 Hook 因目标未导入对应符号或符号不可解析而跳过：%s"
                           % (len(hook_errors), names))
    if missing_sink_hooks:
        msg = "请求的 sink hook 未能安装：%s" % ", ".join(missing_sink_hooks)
        warnings.append(msg)
        limitations.append(msg)
    if failure:
        limitations.append("本次执行以 %s 结束：%s" % (failure["category"],
                                                       failure["reason"]))
    started = runner.get("started_at") or utc_now()
    finished = runner.get("finished_at") or utc_now()
    result: Dict[str, Any] = {
        "schema": "emulation-result/1.0",
        "emulation_id": "QL-" + short_hash({
            "run": plan.get("run_id"), "plan": plan.get("plan_id"),
            "started": runner.get("started_at"), "finished": runner.get("finished_at"),
            "status": status, "events": [e.get("event_id") for e in events]}),
        "run_id": plan.get("run_id"), "intent_id": plan.get("intent_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "target_sha256": (plan.get("target") or {}).get("sha256"),
        "backend": "qiling",
        "backend_version": str(runner.get("qiling_version") or "unverified"),
        "status": status,
        "environment": {
            "mode": mode, "host_fallback": False,
            "sandbox_mode": sandbox.get("mode"), "sandbox_exit_code": rc,
            "sandbox_timed_out": timed_out,
            "sandbox_image": sandbox.get("image") or (plan.get("runtime") or {}).get("image"),
            "qiling_version": runner.get("qiling_version"),
            "qiling_plan_id": plan.get("plan_id"), "target": target_path,
            "rootfs": (plan.get("rootfs") or {}).get("host_path"),
            "network": "none",
        },
        "observations": [
            {"type": "emulation", "kind": "qiling-event",
             "seq": e.get("seq"), "mechanism": e.get("mechanism"),
             "hook": e.get("hook"), "phase": e.get("phase"),
             "args": e.get("args"), "trigger": e.get("trigger"),
             "classified_as": e.get("classified_as")} for e in events],
        "evidence_refs": [e["evidence_id"] for e in evidence
                          if e["evidence_id"].startswith("E-QL-EVT-")
                          or e["evidence_id"].startswith("E-QL-FAIL-")],
        "artifacts": [], "resource_usage": {
            "duration_s": _duration_seconds(started, finished),
            "timeout_s": (plan.get("budget") or {}).get("timeout_s"),
            "exit_code": rc, "timed_out": timed_out,
            "event_count": len(events), "sink_hits": len(sink_events),
            "observed": len(observed), "parse_errors": len(errors)},
        "started_at": started, "finished_at": finished,
        "limitations": limitations,
    }
    if failure:
        result["failure"] = failure
    artifact_paths = [plan_path, events_path, runner.get("_path"), sandbox.get("_path")]
    seen = set()
    for p in artifact_paths:
        if isinstance(p, str) and os.path.isfile(p) and p not in seen:
            seen.add(p)
            result["artifacts"].append(_artifact(p))
    if _validate_emulation_result is not None:
        errs = _validate_emulation_result(result)
        if errs:
            raise AdapterError("RESULT_INVALID",
                               _contract_summary(errs) if _contract_summary else str(errs))
    doc_status = "failed" if status in ("FAILED", "BLOCKED", "TIMED_OUT") \
        else ("partial" if (status == "PARTIAL" or errors or warnings) else "parsed")
    doc: Dict[str, Any] = {
        "schema": SCHEMA_IMPORT,
        "adapter": {"name": TOOL, "version": VERSION},
        "run_id": plan.get("run_id"), "intent_id": plan.get("intent_id"),
        "firmware_sha256": plan.get("firmware_sha256"),
        "status": doc_status, "plan_id": plan.get("plan_id"),
        "backend": {"name": "qiling",
                    "version": str(runner.get("qiling_version") or "unverified"),
                    "image": sandbox.get("image") or (plan.get("runtime") or {}).get("image")},
        "execution": {"mode": mode, "host_fallback": False,
                      "sandbox": {"mode": sandbox.get("mode"),
                                  "exit_code": rc, "timed_out": timed_out,
                                  "image": sandbox.get("image")}},
        "result": result, "events": events, "evidence": evidence,
        "facts": facts, "errors": errors,
        "limitations": list(dict.fromkeys(limitations)),
        "filters": plan.get("filters") or {},
        "counts": dict(counts, evidence=len(evidence), facts=len(facts),
                       by_mechanism={m: sum(1 for e in events
                                            if e.get("mechanism") == m)
                                     for m in sorted({str(e.get("mechanism"))
                                                      for e in events})},
                       by_classification={"sink-hit": len(sink_events),
                                          "observed": len(observed),
                                          "failure": len(failures)}),
    }
    if _validate_qiling_import is not None:
        errs = _validate_qiling_import(doc)
        if errs:
            raise AdapterError("IMPORT_INVALID",
                               _contract_summary(errs) if _contract_summary else str(errs))
    return doc


def _duration_seconds(started: Any, finished: Any) -> Optional[float]:
    try:
        a = datetime.fromisoformat(str(started).replace("Z", "+00:00"))
        b = datetime.fromisoformat(str(finished).replace("Z", "+00:00"))
        return round((b - a).total_seconds(), 3)
    except Exception:
        return None


def render_plan_md(plan: Dict[str, Any]) -> str:
    target = plan.get("target") or {}
    lines = ["# Qiling 定向仿真计划", "",
             "- 计划 ID：%s" % plan.get("plan_id"),
             "- 状态：%s" % plan.get("status"),
             "- 目标：%s" % target.get("container_path"),
             "- 架构：%s / %s-bit / %s" % (target.get("arch"), target.get("bits"),
                                          target.get("endian")),
             "- 镜像：%s" % ((plan.get("runtime") or {}).get("image")),
             "", "## 执行参数", "",
             " ".join(str(x) for x in ((plan.get("execution") or {}).get("argv") or [])),
             "", "## 过滤", "",
             "- trigger_markers：%s" % (", ".join(
                 (plan.get("filters") or {}).get("trigger_markers") or []) or "（未设置）"),
             "- sink_hooks：%s" % (", ".join(
                 (plan.get("filters") or {}).get("sink_hooks") or []) or "（空）"),
             "", "计划成 ready 不代表仿真一定成功；只有 run 产生的事件与证据才能复核。"]
    if plan.get("blockers"):
        lines.extend(["", "## 阻断项", ""])
        for b in plan["blockers"]:
            lines.append("- %s：%s（下一步：%s）" % (b.get("code"), b.get("message"),
                                                    b.get("next_action")))
    return "\n".join(lines) + "\n"


def render_result_md(doc: Dict[str, Any]) -> str:
    result = doc.get("result") or {}
    counts = doc.get("counts") or {}
    lines = ["# Qiling 定向仿真结果", "",
             "- 状态：%s" % result.get("status"),
             "- 目标：%s" % ((result.get("environment") or {}).get("target")),
             "- 事件：%s（sink-hit %s / observed %s）" % (
                 counts.get("events"), counts.get("sink_hits"),
                 counts.get("observed")),
             "- 沙箱：mode=%s，host_fallback=%s" % (
                 (result.get("environment") or {}).get("sandbox_mode"),
                 (result.get("environment") or {}).get("host_fallback")),
             "", "## 限制", ""]
    for text in result.get("limitations") or []:
        lines.append("- " + str(text))
    if result.get("failure"):
        lines.extend(["", "## 失败/阻断", "",
                      "- %s：%s" % ((result.get("failure") or {}).get("category"),
                                    (result.get("failure") or {}).get("reason"))])
    lines.extend(["", "本结果不是漏洞结论；sink-hit 仍需按候选类型判据复核。"])
    return "\n".join(lines) + "\n"


def _load_runner(path: Optional[str]) -> Dict[str, Any]:
    if not path:
        return {}
    if not os.path.isfile(path):
        return {"ok": False, "error": {"category": "runner-report-missing",
                                       "message": "runner 报告不存在：%s" % path,
                                       "retryable": True}, "_path": path}
    try:
        doc = _read_json(path)
    except (OSError, ValueError) as exc:
        return {"ok": False, "error": {"category": "runner-report-invalid",
                                       "message": str(exc), "retryable": True},
                "_path": path}
    if isinstance(doc, dict):
        doc["_path"] = path
        return doc
    return {"ok": False, "error": {"category": "runner-report-invalid",
                                   "message": "runner 报告顶层不是对象",
                                   "retryable": True}, "_path": path}


def _load_sandbox(path: Optional[str]) -> Dict[str, Any]:
    if not path or not os.path.isfile(path):
        return {}
    try:
        doc = _read_json(path)
    except (OSError, ValueError):
        return {"_path": path}
    if isinstance(doc, dict):
        doc["_path"] = path
        return doc
    return {"_path": path}


def cmd_plan(args: argparse.Namespace) -> int:
    plan = build_plan(
        args.target, args.firmware_root, args.rootfs, args.run_id,
        args.intent_id, args.firmware_sha256, args.target_sha256,
        args.arg, args.env, args.stdin, args.image, args.timeout,
        args.max_events, args.max_string, args.trigger_marker,
        args.sink_hook, args.allow_target_outside_rootfs)
    validate_plan_doc(plan)
    if args.json_out:
        _write_json(args.json_out, plan)
    if args.md:
        parent = os.path.dirname(os.path.abspath(args.md))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(args.md, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_plan_md(plan))
    if args.json_stdout:
        print(json.dumps(plan, ensure_ascii=False, indent=2))
    elif not args.quiet and not args.status_only:
        print(render_plan_md(plan), end="")
    return EXIT_OK if plan.get("status") == "ready" else EXIT_BLOCKED


def _sandbox_argv(args: argparse.Namespace, plan: Dict[str, Any],
                  out: str) -> List[str]:
    timeout_s = int(getattr(args, "timeout", 0) or
                    (plan.get("budget") or {}).get("timeout_s") or DEFAULT_TIMEOUT)
    image = getattr(args, "image", None) or (plan.get("runtime") or {}).get("image")
    cmd = "%s /out/qiling_runner.py --plan /out/qiling-plan.json --out /out" \
          % ((plan.get("runtime") or {}).get("python") or "python3")
    argv = [sys.executable, os.path.abspath(args.sandbox_script or SANDBOX_RUN),
            "--mode", "sandbox", "--firmware", plan.get("firmware_root"),
            "--out", out, "--image", str(image or DEFAULT_IMAGE),
            "--timeout", str(timeout_s), "--network", "none", "--cmd", cmd,
            "--json", os.path.join(out, "sandbox-run.json"),
            "--md", os.path.join(out, "sandbox-run.md")]
    if getattr(args, "policy", None):
        argv.extend(["--policy", args.policy])
    if getattr(args, "state_dir", None):
        argv.extend(["--state-dir", args.state_dir])
    if getattr(args, "queue_timeout", None) is not None:
        argv.extend(["--queue-timeout", str(args.queue_timeout)])
    return argv


def _run_adapter(args: argparse.Namespace) -> Dict[str, Any]:
    plan = _read_json(args.plan)
    validate_plan_doc(plan)
    out = os.path.abspath(args.out)
    os.makedirs(out, exist_ok=True)
    plan_copy = os.path.join(out, "qiling-plan.json")
    _write_json(plan_copy, plan)
    if os.path.isfile(RUNNER):
        shutil.copyfile(RUNNER, os.path.join(out, "qiling_runner.py"))
    stdin_host = (plan.get("stdin") or {}).get("host_path")
    if stdin_host and os.path.isfile(stdin_host):
        shutil.copyfile(stdin_host, os.path.join(out, "qiling-stdin.txt"))
    blockers = verify_plan(plan)
    events_path = os.path.join(out, "qiling-events.jsonl")
    runner_path = os.path.join(out, "qiling-runner.json")
    sandbox_path = os.path.join(out, "sandbox-run.json")
    if blockers:
        return build_import(plan, [], {}, {}, events_path, "sandbox",
                            plan_path=plan_copy,
                            extra_errors=[{"path": "$", "code": b["code"],
                                           "message": b["message"]}
                                          for b in blockers])
    argv = _sandbox_argv(args, plan, out)
    timeout_s = int(getattr(args, "timeout", 0) or
                    (plan.get("budget") or {}).get("timeout_s") or DEFAULT_TIMEOUT)
    timed_out = False
    rc = None
    proc_out = ""
    proc_err = ""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout_s + SANDBOX_TIMEOUT_PAD)
        rc = proc.returncode
        proc_out = proc.stdout or ""
        proc_err = proc.stderr or ""
    except subprocess.TimeoutExpired as exc:
        timed_out = True
        rc = EXIT_TIMEOUT
        proc_out = exc.stdout if isinstance(exc.stdout, str) else ""
        proc_err = exc.stderr if isinstance(exc.stderr, str) else ""
    if proc_out:
        with open(os.path.join(out, "sandbox-stdout.log"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(proc_out)
    if proc_err:
        with open(os.path.join(out, "sandbox-stderr.log"), "w",
                  encoding="utf-8", newline="\n") as fh:
            fh.write(proc_err)
    sandbox = _load_sandbox(sandbox_path)
    if timed_out:
        sandbox["timed_out"] = True
        sandbox["exit_code"] = EXIT_TIMEOUT
    elif rc is not None and "exit_code" not in sandbox:
        sandbox["exit_code"] = rc
    raw_events, parse_errors = load_events(events_path)
    runner = _load_runner(runner_path)
    extra: List[Dict[str, str]] = []
    if not os.path.isfile(sandbox_path):
        extra.append({"path": sandbox_path, "code": "SANDBOX_REPORT_MISSING",
                      "message": "sandbox_run.py 未写报告（rc=%r）" % rc})
    if not os.path.isfile(runner_path) and rc not in (EXIT_BLOCKED, EXIT_POLICY,
                                                       EXIT_ADMISSION, EXIT_TIMEOUT):
        extra.append({"path": runner_path, "code": "RUNNER_REPORT_MISSING",
                      "message": "Qiling runner 未写报告（rc=%r）" % rc})
    return build_import(plan, raw_events, runner, sandbox, events_path,
                        "sandbox", parse_errors, plan_copy, extra)


def _cmd_parse(args: argparse.Namespace) -> Dict[str, Any]:
    plan = _read_json(args.plan)
    validate_plan_doc(plan)
    raw_events, parse_errors = load_events(args.events)
    runner = _load_runner(args.runner)
    sandbox = _load_sandbox(args.sandbox)
    if not sandbox:
        sandbox = {"mode": "offline", "host_fallback": False,
                   "exit_code": runner.get("exit_code")}
    return build_import(plan, raw_events, runner, sandbox, args.events,
                        "offline", parse_errors, args.plan)


def _write_outputs(doc: Dict[str, Any], json_path: Optional[str],
                   md_path: Optional[str], as_json: bool, quiet: bool) -> None:
    if json_path:
        _write_json(json_path, doc)
    if md_path:
        parent = os.path.dirname(os.path.abspath(md_path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(md_path, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(render_result_md(doc))
    if as_json:
        print(json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2))
    elif not quiet:
        print(render_result_md(doc), end="")


def _exit_for(doc: Dict[str, Any]) -> int:
    status = (doc.get("result") or {}).get("status")
    if status == "SUCCESS":
        return EXIT_OK
    if status == "BLOCKED":
        return EXIT_BLOCKED
    if status == "TIMED_OUT":
        return EXIT_TIMEOUT
    return EXIT_FAILED


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(
        description="Qiling 定向仿真：计划、沙箱执行、事件归一化与黑板导入")
    ap.add_argument("--version", action="version", version="adapter_qiling " + VERSION)
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("plan", help="只读探测并生成 qiling-plan/1.0")
    p.add_argument("--target", required=True)
    p.add_argument("--firmware-root", required=True)
    p.add_argument("--rootfs")
    p.add_argument("--run-id")
    p.add_argument("--intent-id")
    p.add_argument("--firmware-sha256")
    p.add_argument("--target-sha256")
    p.add_argument("--arg", action="append", default=[])
    p.add_argument("--env", action="append", default=[])
    p.add_argument("--stdin")
    p.add_argument("--image", default=DEFAULT_IMAGE)
    p.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT)
    p.add_argument("--max-events", type=int, default=DEFAULT_MAX_EVENTS)
    p.add_argument("--max-string", type=int, default=DEFAULT_MAX_STRING)
    p.add_argument("--trigger-marker", action="append", default=[])
    p.add_argument("--sink-hook", action="append", default=[])
    p.add_argument("--allow-target-outside-rootfs", action="store_true")
    p.add_argument("--json", dest="json_out")
    p.add_argument("--md")
    p.add_argument("--json-stdout", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--status-only", action="store_true")

    p = sub.add_parser("run", help="经 sandbox_run.py 执行并归一化结果")
    p.add_argument("--plan", required=True)
    p.add_argument("--out", required=True)
    p.add_argument("--sandbox-script", default="")
    p.add_argument("--image")
    p.add_argument("--timeout", type=int, default=0)
    p.add_argument("--policy")
    p.add_argument("--state-dir")
    p.add_argument("--queue-timeout", type=int)
    p.add_argument("--json", dest="json_out")
    p.add_argument("--md")
    p.add_argument("--json-stdout", action="store_true")
    p.add_argument("--quiet", action="store_true")

    p = sub.add_parser("parse", help="离线解析已有事件/报告，不执行 Qiling")
    p.add_argument("--plan", required=True)
    p.add_argument("--events", required=True)
    p.add_argument("--runner")
    p.add_argument("--sandbox")
    p.add_argument("--json", dest="json_out")
    p.add_argument("--md")
    p.add_argument("--json-stdout", action="store_true")
    p.add_argument("--quiet", action="store_true")

    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return EXIT_USAGE
    try:
        if args.cmd == "plan":
            return cmd_plan(args)
        doc = _run_adapter(args) if args.cmd == "run" else _cmd_parse(args)
        _write_outputs(doc, args.json_out, args.md, args.json_stdout, args.quiet)
        return _exit_for(doc)
    except AdapterError as exc:
        print("[error] %s: %s" % (exc.code, exc.message), file=sys.stderr)
        return exc.exit_code
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("[error] IO_ERROR: %s" % exc, file=sys.stderr)
        return EXIT_USAGE


if __name__ == "__main__":
    raise SystemExit(main())
