#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""emu_run.py — 通过沙箱执行整机仿真，产出 EmulationResult

M4 的第二半：读 emu_plan.py 生成的 emulation-plan/1.0，复核计划是否仍然成立
（镜像存在、ext2、哈希未变、内核未变），再通过 sandbox_run.py 在容器里启动
QEMU，采集串口与退出码，最后写出一份 emulation-result/1.0。

边界
----
* 本工具不直接在宿主机启动 QEMU；唯一执行路径是 sandbox_run.py --mode sandbox。
* 沙箱不可用时返回 BLOCKED，不做宿主机回退。
* 串口里看到 shell/login 只证明「启动到了用户态」，不证明任何服务有漏洞；
  端口开放同样不是漏洞。observations 只记录仿真观察，不写 finding。
* 计划里的镜像不存在、哈希变了、内核被替换，都在启动前拒绝（STALE_PLAN）。
* 超时是资源事实，不等于失败：已经看到 shell 的超时记为 SUCCESS + limitation；
  没看到任何用户态信号的超时记为 TIMED_OUT。

用法
----
    python scripts/emu_plan.py --rootfs fw/rootfs --json plan.json
    python scripts/emu_run.py --plan plan.json --out out/ --run-id R-001 \
        --intent-id I-001 --firmware-sha256 <64hex> --json result.json

退出码：0 SUCCESS；1 FAILED/PARTIAL；2 用法；3 BLOCKED（计划/沙箱不可用）；
4 策略拒绝；5 资源准入拒绝；124 TIMED_OUT。纯标准库。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shlex
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0"
SCHEMA = "emulation-result/1.0"
TOOL = "emu_run.py"
PLAN_SCHEMA = "emulation-plan/1.0"
DEFAULT_IMAGE = "iot-fw/qemu:latest"
DEFAULT_SANDBOX_TIMEOUT_PAD = 90
MAX_SERIAL_BYTES = 4 * 1024 * 1024
MAX_SERIAL_LINES = 20000
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")

EXIT_OK = 0
EXIT_FAILED = 1
EXIT_USAGE = 2
EXIT_BLOCKED = 3
EXIT_POLICY = 4
EXIT_ADMISSION = 5
EXIT_TIMEOUT = 124

#: 成功信号：看到任意一条才可能判 SUCCESS。顺序即优先级。
SUCCESS_MARKERS = (
    ("console-ready", re.compile(r"Please press Enter to activate this console")),
    ("login-prompt", re.compile(r"(?m)^(?:\(none\) )?login:\s*$")),
    ("shell-prompt", re.compile(r"(?m)^(?:/ #|~ #|root@[^\s:]+:[^#\n]*#)\s*$")),
    ("init-started", re.compile(r"(?m)^starting pid \d+, tty")),
)

#: 失败信号。比成功信号优先判断：先崩了又出现旧提示符不能算成功。
FAILURE_MARKERS = (
    # 更具体的失败先判：一行里同时出现 "Kernel panic" 与 "Unable to mount root"
    # 时，rootfs-mount 才是可操作的原因。
    ("rootfs-mount", re.compile(r"VFS: Unable to mount root fs|VFS: Cannot open root device|"
                                r"No filesystem could mount root|VFS: Mounted root .* failed")),
    ("no-init", re.compile(r"No init found|Failed to execute /(?:sbin/)?init|"
                           r"request_module: runaway loop")),
    ("init-crash", re.compile(r"Attempted to kill init")),
    ("library-missing", re.compile(r"can't load library|error while loading shared libraries")),
    ("illegal-instruction", re.compile(r"Illegal instruction|SIGILL")),
    ("kernel-panic", re.compile(r"Kernel panic|Internal error: Oops|Unable to handle kernel")),
    # 不把 "console [ttyS0] enabled" 当失败：这是正常启动的必经日志。
    # 真正的 console 不匹配表现为没有输出/卡住，由 boot-no-output / timeout 归类。
)

BOOT_MARKERS = re.compile(
    r"Linux version|Booting Linux|Freeing unused kernel memory|"
    r"Run /(?:sbin/)?init as init process|Kernel command line:")


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _force_utf8_io() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


def _say(msg: str = "", stream: Any = None) -> None:
    out = stream if stream is not None else sys.stdout
    try:
        print(msg, file=out)
    except UnicodeEncodeError:
        enc = getattr(out, "encoding", None) or "utf-8"
        print(msg.encode(enc, "replace").decode(enc, "replace"), file=out)


def _write_text(path: str, text: str) -> str:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(text)
    return path


def _write_json(path: str, obj: Any) -> str:
    return _write_text(path, json.dumps(obj, ensure_ascii=False, indent=2) + "\n")


def sha256_file(path: str) -> Optional[str]:
    h = hashlib.sha256()
    try:
        with open(path, "rb") as fh:
            for blk in iter(lambda: fh.read(1 << 20), b""):
                h.update(blk)
    except OSError:
        return None
    return h.hexdigest()


def _image_fs(path: str) -> str:
    try:
        with open(path, "rb") as fh:
            fh.seek(1080)
            raw = fh.read(2)
    except OSError:
        return "unknown"
    return "ext2" if raw == b"\x53\xef" else "unknown"


def _short_id(seed: str, n: int = 12) -> str:
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:n]


def load_plan(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        doc = json.load(fh)
    if not isinstance(doc, dict):
        raise ValueError("计划必须是 JSON 对象")
    if doc.get("schema") != PLAN_SCHEMA:
        raise ValueError("计划 schema 必须是 %s，实际 %r"
                         % (PLAN_SCHEMA, doc.get("schema")))
    return doc


def validate_plan(plan: Dict[str, Any]) -> List[Dict[str, str]]:
    """优先用 contracts.py；导入失败时退回最小检查，不静默放行。"""
    try:
        sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        import contracts  # type: ignore
        return contracts.validate_emulation_plan(plan)
    except Exception:
        errors: List[Dict[str, str]] = []
        for key in ("plan_id", "status", "rootfs", "qemu"):
            if key not in plan:
                errors.append({"path": "plan." + key, "code": "MISSING",
                               "message": "必填字段缺失"})
        if plan.get("status") not in ("ready", "blocked"):
            errors.append({"path": "plan.status", "code": "BAD_VALUE",
                           "message": "status 必须是 ready/blocked"})
        return errors


def verify_plan(plan: Dict[str, Any], run_id: Optional[str],
                intent_id: Optional[str], fw_sha: Optional[str],
                timeout: Optional[int]) -> Tuple[Optional[str], Optional[str],
                                                 Optional[str], List[str]]:
    """返回 (run_id,intent_id,firmware_sha256,blockers)。blockers 非空即拒绝执行。"""
    blockers: List[str] = []
    run = run_id or plan.get("run_id")
    intent = intent_id or plan.get("intent_id")
    fw = (fw_sha or plan.get("firmware_sha256") or "").lower() or None
    if not run:
        blockers.append("RUN_ID_MISSING：计划与参数都没有 run_id")
    if not intent:
        blockers.append("INTENT_ID_MISSING：计划与参数都没有 intent_id；"
                        "EmulationResult 必须绑定一个 Intent")
    if not fw:
        blockers.append("FIRMWARE_SHA_MISSING：需要 --firmware-sha256")
    elif not re.fullmatch(r"[0-9a-f]{64}", fw):
        blockers.append("FIRMWARE_SHA_INVALID：--firmware-sha256 必须是 64 位十六进制")
    elif plan.get("firmware_sha256") and plan["firmware_sha256"] != fw:
        blockers.append("FIRMWARE_MISMATCH：参数 %s 与计划 %s 不一致"
                        % (fw, plan["firmware_sha256"]))
    if plan.get("status") != "ready":
        codes = ",".join(str(b.get("code")) for b in plan.get("blockers") or [])
        blockers.append("PLAN_BLOCKED：计划状态为 %s（%s）"
                        % (plan.get("status"), codes or "无阻断明细"))
    qemu = plan.get("qemu") or {}
    argv = qemu.get("argv")
    if not isinstance(argv, list) or not argv:
        blockers.append("PLAN_NO_QEMU_ARGV：计划没有可执行的 QEMU argv")
    image = plan.get("image") or {}
    image_path = image.get("path")
    if not image_path:
        blockers.append("PLAN_NO_IMAGE：计划没有 rootfs 镜像路径")
    elif not os.path.isfile(image_path):
        blockers.append("IMAGE_NOT_READY：镜像不存在 %s；先按 build.commands 构建"
                        % image_path)
    else:
        if _image_fs(image_path) != "ext2":
            blockers.append("IMAGE_NOT_EXT2：%s 不是 ext2/3/4 镜像" % image_path)
        digest = sha256_file(image_path)
        if not digest:
            blockers.append("IMAGE_UNREADABLE：无法读取镜像 %s" % image_path)
        elif image.get("sha256") and digest != image["sha256"]:
            blockers.append("IMAGE_HASH_MISMATCH：镜像已被替换（计划 %s，实际 %s）"
                            % (str(image["sha256"])[:12], digest[:12]))
    kernel = plan.get("kernel") or {}
    kernel_path = kernel.get("path")
    if not kernel_path:
        blockers.append("PLAN_NO_KERNEL：计划没有内核路径")
    elif not os.path.isfile(kernel_path):
        blockers.append("KERNEL_NOT_READY：内核不存在 %s" % kernel_path)
    else:
        digest = sha256_file(kernel_path)
        if kernel.get("sha256") and digest != kernel["sha256"]:
            blockers.append("KERNEL_HASH_MISMATCH：内核已被替换")
    fw_root = plan.get("firmware_root")
    if not fw_root or not os.path.isdir(fw_root):
        blockers.append("FIRMWARE_ROOT_MISSING：--firmware-root 目录不存在")
    if timeout is not None and timeout <= 0:
        blockers.append("TIMEOUT_INVALID：--timeout 必须大于 0")
    return run, intent, fw, blockers


def build_sandbox_argv(plan: Dict[str, Any], out_dir: str, image: str,
                       timeout: int, sandbox_script: str,
                       sandbox_json: str, sandbox_md: str,
                       policy: Optional[str], state_dir: Optional[str],
                       queue_timeout: Optional[float]) -> List[str]:
    qemu = plan.get("qemu") or {}
    budget = plan.get("budget") or {}
    argv = [
        sys.executable, sandbox_script,
        "--mode", "sandbox",
        "--firmware", str(plan.get("firmware_root")),
        "--out", out_dir,
        "--image", image,
        "--timeout", str(timeout),
        "--memory", str(budget.get("memory") or "512m"),
        "--cpus", str(budget.get("cpus") or "1"),
        "--network", "none",
        "--cmd", shlex.join(qemu.get("argv") or []),
        "--json", sandbox_json,
        "--md", sandbox_md,
    ]
    if policy:
        argv += ["--policy", policy]
    if state_dir:
        argv += ["--state-dir", state_dir]
    if queue_timeout is not None:
        argv += ["--queue-timeout", str(queue_timeout)]
    return argv


def _truncate_serial(text: str) -> Tuple[str, bool]:
    raw = text.encode("utf-8", "replace")
    if len(raw) > MAX_SERIAL_BYTES:
        raw = raw[:MAX_SERIAL_BYTES]
        text = raw.decode("utf-8", "replace")
        return text, True
    lines = text.splitlines()
    if len(lines) > MAX_SERIAL_LINES:
        return "\n".join(lines[:MAX_SERIAL_LINES]) + "\n", True
    return text, False


def read_serial(path: str) -> Tuple[str, bool, int]:
    try:
        with open(path, "rb") as fh:
            raw = fh.read(MAX_SERIAL_BYTES + 1)
    except OSError:
        return "", False, 0
    truncated = len(raw) > MAX_SERIAL_BYTES
    raw = raw[:MAX_SERIAL_BYTES]
    text = raw.decode("utf-8", "replace").replace("\r\n", "\n").replace("\r", "\n")
    text = ANSI_RE.sub("", text).replace("\x00", "")
    text, cut2 = _truncate_serial(text)
    return text, truncated or cut2, len(raw)


def _find_marker(text: str, patterns, limit: int = 3) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    lines = text.splitlines()
    for name, rx in patterns:
        for i, line in enumerate(lines, 1):
            if rx.search(line):
                rows.append({"signal": name, "line": i, "text": line[:400]})
                if len(rows) >= limit:
                    return rows
                break
    return rows


def classify_serial(text: str, timed_out: bool, exit_code: Optional[int],
                    stderr: str = "") -> Dict[str, Any]:
    """把串口文本归一成状态与结构化失败；不做任何漏洞推断。"""
    text = text or ""
    if not text.strip():
        if re.search(r"could not load kernel|The image is not ELF|"
                     r"Invalid ELF image|not a valid ELF",
                     stderr or "", re.IGNORECASE):
            return {"status": "FAILED", "category": "kernel-format",
                    "reason": "QEMU 拒绝加载内核镜像（格式不是 ELF 或与 machine 不匹配）：%s"
                              % (stderr or "")[:300],
                    "retryable": False, "observations": [],
                    "limitations": ["需要匹配 machine/架构的内核；不能据此判断 rootfs 不可用"]}
        if re.search(r"qemu-system[^\s:]*: (?:command )?not found|"
                     r"executable file not found|No such file or directory",
                     stderr or ""):
            return {"status": "BLOCKED", "category": "backend-unavailable",
                    "reason": "容器内没有可执行的 QEMU 或缺少动态库",
                    "retryable": True, "observations": [],
                    "limitations": []}
        if timed_out:
            return {"status": "TIMED_OUT", "category": "timeout",
                    "reason": "达到观察窗口仍没有任何串口输出",
                    "retryable": True, "observations": [],
                    "limitations": ["没有串口输出，无法判断内核是否启动"]}
        return {"status": "FAILED", "category": "boot-no-output",
                "reason": "QEMU 退出但 /out/serial.log 为空；优先检查 console 与内核",
                "retryable": True, "observations": [],
                "limitations": []}

    successes = _find_marker(text, SUCCESS_MARKERS)
    failures = _find_marker(text, FAILURE_MARKERS)
    has_boot = bool(BOOT_MARKERS.search(text))
    observations: List[Dict[str, Any]] = []
    for row in successes:
        observations.append({"type": "emulation", "kind": "console-success",
                             "signal": row["signal"], "line": row["line"],
                             "text": row["text"]})
    for row in failures:
        observations.append({"type": "emulation", "kind": "console-failure",
                             "signal": row["signal"], "line": row["line"],
                             "text": row["text"]})
    if has_boot:
        m = BOOT_MARKERS.search(text)
        line = text[:m.start()].count("\n") + 1 if m else 1
        observations.append({"type": "emulation", "kind": "kernel-boot",
                             "line": line, "text": (m.group(0) if m else "")[:200]})

    # 崩溃优先：即便之前打印过 login，也不能把后续 panic 当成功。
    if failures:
        first = failures[0]
        if successes and first["signal"] in ("kernel-panic", "rootfs-mount",
                                              "no-init", "init-crash"):
            return {"status": "PARTIAL", "category": None,
                    "reason": "启动到用户态后发生内核异常",
                    "retryable": False, "observations": observations,
                    "limitations": ["启动成功后发生 %s（第 %d 行）：%s"
                                    % (first["signal"], first["line"],
                                       first["text"][:160])]}
        return {"status": "FAILED", "category": first["signal"],
                "reason": "串口出现 %s：%s" % (first["signal"], first["text"][:240]),
                "retryable": True, "observations": observations,
                "limitations": []}
    if successes:
        limitations: List[str] = []
        if timed_out:
            limitations.append("达到观察窗口后由沙箱终止；已观察到 %s，"
                               "不表示进程/服务稳定" % successes[0]["signal"])
        if exit_code not in (0, None) and not timed_out:
            limitations.append("QEMU 退出码 %s；shell/login 已出现，但退出原因未归类"
                               % exit_code)
        return {"status": "SUCCESS", "category": None,
                "reason": "观察到 %s" % successes[0]["signal"],
                "retryable": False, "observations": observations,
                "limitations": limitations}
    if timed_out:
        return {"status": "TIMED_OUT", "category": "timeout",
                "reason": "串口有启动日志，但窗口内未出现 shell/login/init 完成信号",
                "retryable": True, "observations": observations,
                "limitations": ["内核可能卡在 init、库加载或交互等待；需提高超时或换 init"]}
    if has_boot:
        return {"status": "PARTIAL", "category": None,
                "reason": "内核有启动日志，但未观察到用户态完成信号",
                "retryable": False, "observations": observations,
                "limitations": ["只证明内核开始启动，不证明 rootfs/init 可用"]}
    return {"status": "FAILED", "category": "boot-no-output",
            "reason": "串口只有噪声/非启动输出，未匹配到内核启动或失败信号",
            "retryable": True, "observations": observations,
            "limitations": []}


def _artifact(path: str) -> Optional[Dict[str, Any]]:
    if not os.path.isfile(path):
        return None
    return {"path": os.path.abspath(path), "sha256": sha256_file(path),
            "size": os.path.getsize(path)}


def make_result(plan: Dict[str, Any], run_id: str, intent_id: str,
                firmware_sha256: str, status: str, category: Optional[str],
                reason: str, retryable: bool, observations: List[Dict[str, Any]],
                limitations: List[str], serial_text: str,
                serial_truncated: bool, sandbox: Optional[Dict[str, Any]],
                out_dir: str, started_at: str, duration_s: float,
                exit_code: Optional[int], timed_out: bool,
                extra_artifacts: Optional[List[Dict[str, Any]]] = None,
                timeout_s: Optional[int] = None) -> Dict[str, Any]:
    qemu = plan.get("qemu") or {}
    image = plan.get("image") or {}
    sandbox = sandbox or {}
    serial_path = os.path.join(out_dir, "serial.log")
    artifacts: List[Dict[str, Any]] = []
    art = _artifact(serial_path)
    if art:
        artifacts.append(art)
    for item in extra_artifacts or []:
        if item:
            artifacts.append(item)
    result: Dict[str, Any] = {
        "schema": SCHEMA,
        "emulation_id": "EMU-" + _short_id("|".join([
            run_id, intent_id, firmware_sha256, str(plan.get("plan_id")),
            str((art or {}).get("sha256") or "no-serial")])),
        "run_id": run_id,
        "intent_id": intent_id,
        "firmware_sha256": firmware_sha256,
        "target_sha256": (plan.get("rootfs") or {}).get("sha256") or None,
        "backend": "qemu-system",
        "backend_version": str(qemu.get("version") or "unverified"),
        "status": status,
        "environment": {
            "mode": "sandbox",
            "host_fallback": False,
            "sandbox_image": sandbox.get("image"),
            "sandbox_mode": sandbox.get("mode"),
            "sandbox_timed_out": bool(sandbox.get("timed_out")),
            "qemu_binary": qemu.get("binary"),
            "machine": qemu.get("machine"),
            "cpu": qemu.get("cpu"),
            "kernel": (plan.get("kernel") or {}).get("path"),
            "kernel_sha256": (plan.get("kernel") or {}).get("sha256"),
            "image": image.get("path"),
            "image_sha256": image.get("sha256"),
            "network": plan.get("network"),
            "plan_id": plan.get("plan_id"),
            "serial_log": serial_path,
        },
        "observations": observations,
        "evidence_refs": [],
        "artifacts": artifacts,
        "resource_usage": {
            "duration_s": round(duration_s, 3),
            "timeout_s": (timeout_s if timeout_s is not None
                          else (plan.get("budget") or {}).get("timeout_s")),
            "exit_code": exit_code,
            "timed_out": bool(timed_out),
            "serial_bytes": len(serial_text.encode("utf-8", "replace")),
            "serial_truncated": bool(serial_truncated),
        },
        "started_at": started_at,
        "finished_at": utc_now(),
        "limitations": list(limitations),
    }
    if status in ("FAILED", "BLOCKED", "TIMED_OUT"):
        result["failure"] = {"category": category or "unknown",
                             "reason": reason,
                             "retryable": bool(retryable)}
    elif status == "PARTIAL" and not result["limitations"]:
        result["limitations"] = [reason or "结果不完整"]
    return result


def _sandbox_block(plan: Dict[str, Any], blockers: List[str], out_dir: str,
                   started_at: str) -> Dict[str, Any]:
    return make_result(
        plan, run_id="", intent_id="", firmware_sha256="",
        status="BLOCKED", category="plan-blocked",
        reason="；".join(blockers), retryable=False,
        observations=[], limitations=["未执行 QEMU；计划未通过启动前复核"],
        serial_text="", serial_truncated=False, sandbox=None, out_dir=out_dir,
        started_at=started_at, duration_s=0.0, exit_code=None, timed_out=False)


def render_md(result: Dict[str, Any]) -> str:
    icon = {"SUCCESS": "✅", "PARTIAL": "⚠️", "FAILED": "❌",
            "BLOCKED": "⛔", "TIMED_OUT": "⏱️",
            "NOT_APPLICABLE": "➖"}.get(result.get("status"), "?")
    lines = ["# 整机仿真结果（%s）" % result.get("emulation_id"),
             "",
             "%s **%s**" % (icon, result.get("status")),
             "",
             "| 项 | 值 |",
             "|---|---|",
             "| run / intent | %s / %s |" % (result.get("run_id"), result.get("intent_id")),
             "| backend | %s %s |" % (result.get("backend"), result.get("backend_version")),
             "| plan | %s |" % ((result.get("environment") or {}).get("plan_id")),
             "| image | %s |" % ((result.get("environment") or {}).get("sandbox_image")),
             "| QEMU | %s |" % ((result.get("environment") or {}).get("qemu_binary")),
             "| 退出 / 超时 | %s / %s |" % (
                 ((result.get("resource_usage") or {}).get("exit_code")),
                 ((result.get("resource_usage") or {}).get("timed_out"))),
             ""]
    if result.get("failure"):
        f = result["failure"]
        lines += ["## 失败分类", "",
                  "- **%s**：%s（可重试：%s）"
                  % (f.get("category"), f.get("reason"), f.get("retryable")), ""]
    obs = result.get("observations") or []
    if obs:
        lines += ["## 观察（仅仿真事实）", ""]
        for row in obs[:20]:
            lines.append("- [%s] %s" % (row.get("kind") or row.get("type"),
                                        str(row.get("text") or "")[:240]))
        if len(obs) > 20:
            lines.append("- ……另有 %d 条" % (len(obs) - 20))
        lines.append("")
    if result.get("limitations"):
        lines += ["## 限制", ""] + ["- %s" % x for x in result["limitations"]] + [""]
    if result.get("artifacts"):
        lines += ["## 产物", ""]
        for art in result["artifacts"]:
            lines.append("- %s（%s 字节，sha256 %s）"
                         % (art.get("path"), art.get("size"),
                            str(art.get("sha256"))[:12]))
        lines.append("")
    lines += ["---", "",
              "启动到 shell/login 只证明用户态可运行，不是漏洞结论；"
              "端口开放也不是漏洞。需要 Candidate 级验证时另走动态触发与证据链。"]
    return "\n".join(lines) + "\n"


def _load_sandbox_json(path: str) -> Optional[Dict[str, Any]]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) else None
    except (OSError, ValueError):
        return None


def run_sandbox(argv: List[str], timeout: int) -> Tuple[int, str, str, bool]:
    """只调用 sandbox_run.py；给它足够的收尾时间，超时由它自己清理容器。"""
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              encoding="utf-8", errors="replace",
                              timeout=timeout + DEFAULT_SANDBOX_TIMEOUT_PAD,
                              check=False)
        return (proc.returncode, proc.stdout or "", proc.stderr or "", False)
    except subprocess.TimeoutExpired as exc:
        return (EXIT_TIMEOUT, (exc.stdout or "") if isinstance(exc.stdout, str) else "",
                "emu_run 等待 sandbox_run 超时", True)
    except OSError as exc:
        return (EXIT_USAGE, "", "无法启动 sandbox_run：%s" % exc, False)


def _exit_for(status: str, category: Optional[str]) -> int:
    if status == "SUCCESS":
        return EXIT_OK
    if status == "TIMED_OUT":
        return EXIT_TIMEOUT
    if status == "BLOCKED":
        if category == "sandbox-policy":
            return EXIT_POLICY
        if category == "admission-rejected":
            return EXIT_ADMISSION
        return EXIT_BLOCKED
    return EXIT_FAILED


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="经 sandbox_run 执行整机仿真并产出 EmulationResult")
    ap.add_argument("--plan", required=True, help="emu_plan.py 生成的计划 JSON")
    ap.add_argument("--out", help="输出目录（串口、沙箱报告、结果；--check 时不需要）")
    ap.add_argument("--run-id", help="覆盖计划里的 run_id")
    ap.add_argument("--intent-id", help="覆盖计划里的 intent_id")
    ap.add_argument("--firmware-sha256", help="固件 sha256（64 位十六进制）")
    ap.add_argument("--timeout", type=int,
                    help="覆盖计划预算的单次观察窗口秒数")
    ap.add_argument("--image", default=os.environ.get("IOT_QEMU_IMAGE", DEFAULT_IMAGE),
                    help="含 QEMU 的容器镜像（默认环境变量 IOT_QEMU_IMAGE 或 %s）"
                         % DEFAULT_IMAGE)
    ap.add_argument("--sandbox-script",
                    default=os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                         "sandbox_run.py"),
                    help="sandbox_run.py 路径（测试可替换；生产不要改）")
    ap.add_argument("--policy", help="资源策略 JSON（传给 sandbox_run）")
    ap.add_argument("--state-dir", help="并发槽位状态目录（传给 sandbox_run）")
    ap.add_argument("--queue-timeout", type=float,
                    help="排队超时秒数（传给 sandbox_run）")
    ap.add_argument("--json", dest="json_out", help="EmulationResult 输出路径")
    ap.add_argument("--md", dest="md_out", help="中文 Markdown 输出路径")
    ap.add_argument("--check", action="store_true",
                    help="只做计划复核，不执行 QEMU，也不写结果")
    ap.add_argument("--quiet", action="store_true", help="不打印人类可读摘要")
    return ap


def main(argv=None) -> int:
    _force_utf8_io()
    args = build_parser().parse_args(argv)
    if not args.check and not args.out:
        _say("[error] 非 --check 模式必须提供 --out", sys.stderr)
        return EXIT_USAGE
    started_at = utc_now()

    try:
        plan = load_plan(args.plan)
    except (OSError, ValueError) as exc:
        _say("[error] 读取计划失败：%s" % exc, sys.stderr)
        return EXIT_USAGE

    errors = validate_plan(plan)
    if errors:
        for e in errors[:8]:
            _say("[error] %s: %s" % (e.get("path"), e.get("message")), sys.stderr)
        return EXIT_USAGE

    timeout = args.timeout or int((plan.get("budget") or {}).get("timeout_s") or 120)
    run_id, intent_id, fw, blockers = verify_plan(
        plan, args.run_id, args.intent_id, args.firmware_sha256, timeout)

    if args.check:
        if blockers:
            _say("[blocked] " + "；".join(blockers), sys.stderr)
            return EXIT_BLOCKED
        _say("[ready] %s run=%s intent=%s timeout=%ss"
             % (plan.get("plan_id"), run_id, intent_id, timeout))
        return EXIT_OK

    os.makedirs(args.out, exist_ok=True)
    serial_path = os.path.join(args.out, "serial.log")
    sandbox_json = os.path.join(args.out, "sandbox-run.json")
    sandbox_md = os.path.join(args.out, "sandbox-run.md")

    if blockers:
        # 即使拒绝执行，也写一份可审计的 BLOCKED 结果；run_id 缺失时用占位符，
        # 但这会让契约的 run_id 仍是非空字符串，下游能看到「为什么没跑」。
        res = make_result(
            plan, run_id=run_id or "RUN-UNSET", intent_id=intent_id or "INTENT-UNSET",
            firmware_sha256=fw or ("0" * 64),
            status="BLOCKED", category="plan-blocked",
            reason="；".join(blockers), retryable=False,
            observations=[], limitations=["未执行 QEMU；计划未通过启动前复核"],
            serial_text="", serial_truncated=False, sandbox=None, out_dir=args.out,
            started_at=started_at, duration_s=0.0, exit_code=None, timed_out=False,
            timeout_s=timeout)
        _write_result(res, args)
        if not args.quiet:
            _say("[blocked] " + "；".join(blockers), sys.stderr)
        return EXIT_BLOCKED

    argv = build_sandbox_argv(plan, args.out, args.image, timeout,
                              args.sandbox_script, sandbox_json, sandbox_md,
                              args.policy, args.state_dir, args.queue_timeout)
    t0 = time.monotonic()
    rc, stdout, stderr, wait_timeout = run_sandbox(argv, timeout)
    duration = time.monotonic() - t0
    sb = _load_sandbox_json(sandbox_json)
    if sb is None:
        sb = {
            "schema": "sandbox-run/1.1", "mode": "fail-closed",
            "image": args.image, "timed_out": wait_timeout,
            "exit_code": rc, "ok": False, "stderr_head": stderr[:4000],
            "admission": {"decision": "rejected", "code": "NO_REPORT"},
        }
    timed_out = bool(sb.get("timed_out")) or rc == EXIT_TIMEOUT
    sandbox_mode = sb.get("mode")
    admission = sb.get("admission") or {}
    category: Optional[str] = None
    reason = ""
    status = "FAILED"
    retryable = True
    observations: List[Dict[str, Any]] = []
    limitations: List[str] = []
    serial_text, truncated, _n = read_serial(serial_path)

    if sandbox_mode == "fail-closed" or rc == EXIT_BLOCKED:
        status, category = "BLOCKED", "sandbox-unavailable"
        reason = "沙箱不可用，已按 fail-closed 拒绝在宿主机执行（sandbox_run rc=%s）" % rc
        retryable = True
    elif rc == EXIT_POLICY or admission.get("decision") == "rejected" \
            and admission.get("code") == "POLICY_INVALID":
        status, category = "BLOCKED", "sandbox-policy"
        reason = "资源策略拒绝执行：%s" % (admission.get("message") or stderr[:300])
        retryable = False
    elif rc == EXIT_ADMISSION or admission.get("decision") in ("queue-timeout",
                                                               "budget-exhausted"):
        status, category = "BLOCKED", "admission-rejected"
        reason = "资源准入拒绝：%s" % (admission.get("code") or stderr[:300])
        retryable = True
    else:
        if wait_timeout:
            serial_text, truncated, _n = read_serial(serial_path)
            verdict = classify_serial(serial_text, True, rc,
                                     (sb.get("stderr_head") or stderr))
            # 等 sandbox_run 本身超时，可能连 serial 都没落盘；仍按 TIMED_OUT 处理。
            status = verdict["status"]
            category = verdict.get("category") or "timeout"
            reason = "emu_run 等待 sandbox_run 超过 %ss；%s" % (
                timeout + DEFAULT_SANDBOX_TIMEOUT_PAD, verdict.get("reason"))
            observations = verdict.get("observations") or []
            limitations = verdict.get("limitations") or []
            retryable = True
        else:
            serial_text, truncated, _n = read_serial(serial_path)
            verdict = classify_serial(serial_text, timed_out, rc,
                                     (sb.get("stderr_head") or stderr))
            status = verdict["status"]
            category = verdict.get("category")
            reason = verdict.get("reason") or ""
            observations = verdict.get("observations") or []
            limitations = verdict.get("limitations") or []
            retryable = bool(verdict.get("retryable"))
            if status == "FAILED" and rc not in (0, None) and not serial_text:
                reason = "%s；sandbox rc=%s stderr=%s" % (
                    reason, rc, (stderr or "")[:200])
    if timed_out and status == "SUCCESS":
        limitations = list(dict.fromkeys(limitations + [
            "达到观察窗口后由沙箱终止；shell/login 已出现，但未验证服务稳定性"]))
    if plan.get("limitations"):
        limitations = list(dict.fromkeys(limitations + [
            str(x) for x in plan.get("limitations") or []]))

    artifacts = []
    for extra in (sandbox_json, sandbox_md, args.plan):
        art = _artifact(extra)
        if art:
            artifacts.append(art)
    res = make_result(plan, run_id or "RUN-UNSET", intent_id or "INTENT-UNSET",
                      fw or ("0" * 64), status, category, reason, retryable,
                      observations, limitations, serial_text, truncated, sb,
                      args.out, started_at, duration, rc, timed_out, artifacts,
                      timeout_s=timeout)
    _write_result(res, args)
    if not args.quiet:
        _say("[%s] %s %s" % (res["status"], res["emulation_id"],
                            res.get("failure", {}).get("category") or ""))
        if args.json_out:
            _say("[ok] JSON -> %s" % args.json_out)
        if args.md_out:
            _say("[ok] Markdown -> %s" % args.md_out)
    return _exit_for(res["status"], category)


def _write_result(res: Dict[str, Any], args: argparse.Namespace) -> None:
    if args.json_out:
        _write_json(args.json_out, res)
    if args.md_out:
        _write_text(args.md_out, render_md(res))


if __name__ == "__main__":
    raise SystemExit(main())
