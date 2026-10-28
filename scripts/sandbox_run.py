#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
sandbox_run.py — 不可信固件的一次性隔离执行边界（fail-closed）

用途：
  把「在固件里跑二进制 / 脚本 / init 流程」收进一条**可执行**的边界。默认
  --mode auto：探到真正可用的 docker / podman，就在一次性、低权限、无凭据的
  容器里执行；探不到就**失败关闭**（退出码 3），绝不静默回退宿主机。

为什么 fail-closed：
  在宿主机直接执行不可信固件 = 放弃全部隔离：固件里的二进制可以主动出网、读宿主
  机凭据、挂载真实设备、写任意路径。而「探测失败」与「沙箱可用」在报告里长得一模
  一样，静默回退是这类工具最常见的真实事故。所以本工具的默认结果是「不执行」：
  要执行必须**显式**满足条件——要么有可用运行时，要么 --mode host 且同时给出
  --i-understand-host-risk。JSON 里 host_fallback 恒为 false：本工具没有回退路径，
  host 只能是被选择的，不可能被 fallback 到。

隔离参数（sandbox 模式，全部记录在 JSON 的 policy 与 command 里）：
  --network none / --read-only / --cap-drop=ALL / --security-opt=no-new-privileges
  --user 65534:65534 / --memory 512m / --cpus 1 / --pids-limit 128
  --tmpfs /tmp:rw,noexec,nosuid,size=16m
  固件目录 :ro 挂到 /firmware，输出目录 rw 挂到 /out；命令统一经容器内
  /bin/sh -c 执行（便于占位符与管道，镜像需自带 /bin/sh）；超时由 Python 侧
  subprocess 实现（超时 kill 客户端，并尽力 docker rm -f 掉可能残留的容器）。

资源准入（M2）：
  执行前先过 resource_manager.py 的策略检查：并发槽位（跨进程文件锁，超限排队
  而不是先启动）、总预算（排队 + 探测 + 执行 + 清理都计入）、单命令超时、内存、
  CPU、PID 与镜像白名单。策略用 --policy 指定，缺省策略见
  resource_manager.py defaults --json；槽位目录默认在系统临时目录下。

退出码：
  0   命令在隔离环境内成功执行（exit 0）
  1   命令已执行但返回非零（真实退出码见 JSON 的 exit_code）
  2   输入 / 参数错误
  3   隔离环境不可用（fail-closed，绝不回退宿主机）
  4   策略拒绝（host 未显式授权、挂载重叠、固件目录不存在、超出资源上限等）
  5   资源准入失败（排队超时 / 预算耗尽；没有启动任何命令）
  124 容器命令超时

示例：
  # 只探测隔离能力（不执行任何固件内容）
  python scripts/sandbox_run.py --check

  # 默认命令 /bin/true：只验证隔离链路，不执行固件内容
  python scripts/sandbox_run.py --firmware 01-extract --json sandbox-run.json

  # 容器内只看固件目录；占位符分别指向只读挂载点与可写输出点
  python scripts/sandbox_run.py --firmware 01-extract --out sandbox-out \
      --cmd "ls -l {firmware}/bin && cp {firmware}/etc/passwd {out}/" \
      --timeout 60 --md sandbox-run.md

  # 资源准入：1 个并发槽位、60 秒总预算、排队最多 10 秒
  python scripts/sandbox_run.py --firmware 01-extract --policy sandbox-policy.json \
      --state-dir .sandbox-slots --slots 1 --budget 60 --queue-timeout 10 \
      --cmd "ls -l {firmware}/bin" --json sandbox-run.json

  # 宿主机执行：必须显式授权，且只用于可完全信任的自建 rootfs
  python scripts/sandbox_run.py --firmware ./my-rootfs --mode host \
      --i-understand-host-risk --cmd "echo hi"
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import threading
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

import resource_manager as rm

VERSION = "1.1"
SCHEMA = "sandbox-run/1.1"
TOOL = "sandbox_run.py"

# 默认值：都是「最保守且能跑起来」的选择，改任何一项都要能被 JSON 复算出来。
DEFAULT_IMAGE = "debian:bookworm-slim"
DEFAULT_CMD = "/bin/true"                     # 默认不执行任何固件内容，只验证隔离链路
DEFAULT_TIMEOUT = 120                         # 秒
DEFAULT_MEMORY = "512m"
DEFAULT_CPUS = "1"
DEFAULT_PIDS = 128
DEFAULT_TMPFS = "/tmp:rw,noexec,nosuid,size=16m"
CONTAINER_UID = "65534:65534"                 # nobody:nogroup，无家目录、无凭据
FIRMWARE_TARGET = "/firmware"                 # 容器内只读挂载点
OUT_TARGET = "/out"                           # 容器内可写挂载点

RUNTIME_PROBE_TIMEOUT = 5                     # <rt> version 探测超时（秒）
CAPTURE_LIMIT = 1 << 20                       # 每路输出最多保留 1 MiB，避免被目标刷爆内存
READ_CHUNK = 64 << 10
HEAD_LIMIT = 4000                             # stdout_head / stderr_head 截断长度（字符）

EXIT_OK = 0
EXIT_COMMAND_FAILED = 1
EXIT_USAGE = 2
EXIT_UNAVAILABLE = 3
EXIT_POLICY = 4
EXIT_ADMISSION = 5
EXIT_TIMEOUT = 124

# 失败关闭时 stderr 必须出现的原话（文档与测试都对它做断言，不要改写）。
FAIL_CLOSED_MSG = "隔离环境不可用，拒绝在宿主机执行不可信固件（fail-closed）"

# FILE_ATTRIBUTE_REPARSE_POINT：Windows 上 junction 等重解析点的属性位
FILE_ATTRIBUTE_REPARSE_POINT = 0x400

MEMORY_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?[bkmg]?$")
CPUS_RE = re.compile(r"^[0-9]+(?:\.[0-9]+)?$")


# ------------------------------------------------------------ 基础工具

def utc_now() -> str:
    """UTC ISO8601（秒级，带 Z）：报告里所有时间都必须是同一时区。"""
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _force_utf8_io() -> None:
    """把 stdout/stderr 固定为 UTF-8。

    Windows 下输出被重定向到管道/文件时，Python 用的是本地代码页（简体中文环境为
    cp936），中文与「→」会变成乱码 —— 本工具的产物必须是 UTF-8，不能取决于调用
    方怎么接管道。控制台本身走宽字符 API，不受影响。
    """
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")  # type: ignore[attr-defined]
        except (AttributeError, ValueError, OSError):
            pass


def _say(msg: str = "", stream: Any = None) -> None:
    """打印到 stdout/stderr；当前编码表示不了的字符降级替换，绝不因输出崩掉。

    Windows 控制台与重定向管道的代码页未必覆盖「→」这类符号，直接 print 会抛
    UnicodeEncodeError —— 一个纯显示问题不能变成执行失败。
    """
    out = stream if stream is not None else sys.stdout
    try:
        print(msg, file=out)
    except UnicodeEncodeError:
        enc = getattr(out, "encoding", None) or "utf-8"
        print(msg.encode(enc, "replace").decode(enc, "replace"), file=out)


def _text(raw: Optional[bytes]) -> str:
    """子进程输出按 UTF-8 解码（坏字节替换，不抛异常）。"""
    if not raw:
        return ""
    return raw.decode("utf-8", "replace")


def write_text(path: str, text: str) -> Optional[str]:
    """写 UTF-8 文本（自动建父目录）；失败返回错误串而不是抛异常。"""
    try:
        parent = os.path.dirname(os.path.abspath(path))
        if parent:
            os.makedirs(parent, exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as f:
            f.write(text)
    except OSError as exc:
        return str(exc)
    return None


def sha256_file(path: str) -> Optional[str]:
    """单文件 sha256（分块读，避免大固件把内存吃掉）；读不了返回 None。"""
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                h.update(blk)
    except OSError:
        return None
    return h.hexdigest()


def _is_link(path: str) -> bool:
    """是否是符号链接（Windows 下把 junction 等重解析点也算进来）。

    Windows 的 os.path.islink() 对 junction 返回 False，而 os.walk 会照样钻进去 ——
    一个指向 C:/ 的 junction 就能把宿主机文件系统算进固件指纹。固件可能来自任何人，
    所以在 Windows 上直接看重解析点属性，宁可多跳过一个目录，也不越过边界。
    """
    try:
        if os.path.islink(path):
            return True
        if os.name == "nt":
            st = os.stat(path, follow_symlinks=False)
            return bool(getattr(st, "st_file_attributes", 0)
                        & FILE_ATTRIBUTE_REPARSE_POINT)
    except (OSError, AttributeError):
        return False
    return False


def dir_hash(root: str, notes: Optional[List[str]] = None) -> Optional[str]:
    """固件目录的「清单哈希」：对 relpath + b"\0" + sha256(file) 逐行求 sha256。

    只有这样才能把「同一路径、内容变了」和「内容没变、只是 mtime 变了」分开；
    对整棵目录树取哈希，才能证明本次执行用的就是被审计的那份固件。

    - 跳过符号链接：跟随会把宿主机上的 /etc、/proc 之类算进固件指纹，而且固件里
      的符号链接本身就可能指向容器外的绝对路径；
    - 跳过非普通文件（设备节点 / FIFO 等），数量记进 notes；
    - 有文件读不了就返回 None：宁可不给哈希，也不给一个"看起来正常"的假指纹。
    """
    if notes is None:
        notes = []
    root = os.path.abspath(root)
    rows: List[bytes] = []
    symlinks = 0
    specials = 0
    unreadable: List[str] = []

    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        dirnames.sort()
        # 指向目录的符号链接不会跟进（followlinks=False），但要计数并说明跳过
        for d in list(dirnames):
            if _is_link(os.path.join(dirpath, d)):
                symlinks += 1
                dirnames.remove(d)
        for fn in sorted(filenames):
            full = os.path.join(dirpath, fn)
            rel = os.path.relpath(full, root).replace("\\", "/")
            if _is_link(full):
                symlinks += 1
                continue
            if not os.path.isfile(full):
                specials += 1
                continue
            digest = sha256_file(full)
            if digest is None:
                unreadable.append(rel)
                continue
            rows.append(rel.encode("utf-8") + b"\x00" + digest.encode("ascii"))

    rows.sort()                                  # 按相对路径排序，与 os.walk 的顺序无关
    h = hashlib.sha256()
    for row in rows:
        h.update(row + b"\n")

    if symlinks:
        notes.append("固件目录含符号链接 %d 个，已跳过（不跟随、不计入清单哈希）" % symlinks)
    if specials:
        notes.append("固件目录含非普通文件 %d 个，已跳过（不计入清单哈希）" % specials)
    notes.append("固件清单哈希覆盖 %d 个文件（按相对路径排序）" % len(rows))
    if unreadable:
        notes.append("固件目录有 %d 个文件读取失败，清单哈希不可信：%s"
                     % (len(unreadable), "、".join(unreadable[:5])))
        return None
    return h.hexdigest()


def _norm_path(path: str) -> str:
    """归一化到可比较的绝对真实路径（Windows 下同时统一大小写与分隔符）。"""
    return os.path.normcase(os.path.realpath(os.path.abspath(path)))


def _within(child: str, parent: str) -> bool:
    """child 是否就是 parent 或位于 parent 之下（两者都需先归一化）。"""
    if child == parent:
        return True
    prefix = parent if parent.endswith(os.sep) else parent + os.sep
    return child.startswith(prefix)


# ------------------------------------------------------------ 运行时探测

def _probe_runtime(name: str, path: Optional[str], argv_prefix: List[str],
                   requested: str) -> Dict[str, Any]:
    """探测一个候选运行时；argv_prefix 是调用它的前缀（如 python wrapper）。"""
    rec: Dict[str, Any] = {"name": name, "path": path, "version": None,
                           "available": False, "probe": "not-found",
                           "argv": list(argv_prefix)}
    if not path:
        return rec
    argv = list(argv_prefix) + ["version", "--format", "{{.Server.Version}}"]
    try:
        p = subprocess.run(argv, capture_output=True,
                           timeout=RUNTIME_PROBE_TIMEOUT)
        out = _text(p.stdout).strip()
        err = _text(p.stderr).strip()
        if p.returncode == 0 and out:
            rec["available"] = True
            rec["version"] = out.splitlines()[0].strip()
            rec["probe"] = "ok"
        elif err:
            rec["probe"] = "exit=%s: %s" % (
                p.returncode, err.splitlines()[0][:200])
        else:
            rec["probe"] = "exit=%s: 版本输出为空" % p.returncode
    except subprocess.TimeoutExpired:
        rec["probe"] = "timeout>%ss" % RUNTIME_PROBE_TIMEOUT
    except OSError as exc:
        rec["probe"] = "exec-error: %s" % exc
    return rec


def detect_runtime(prefer: str = "auto", bin_path: Optional[str] = None) -> Dict[str, Any]:
    """探测容器运行时是否**真正可用**，返回可直接写进 JSON 的记录。

    判定必须同时满足：能找到可执行文件；<rt> version --format
    "{{.Server.Version}}" 在 5 秒内以 0 退出且打印出版本号。
    只 which 到文件不算可用——客户端在、守护进程没起，照样跑不了容器，而这正是
    「以为隔离了其实没有」的典型来源。显式 --runtime docker/podman 时只测该运行时。

    --runtime-bin 可指向一个自定义运行时封装；.py 文件会用当前 Python 解释器
    启动（便于测试桩和带 DOCKER_HOST 的小包装）。封装是否真的调用容器运行时，
    工具无法从版本号证明——它和 docker 二进制一样属于可信配置，记录在 JSON 里。
    """
    if bin_path:
        path = os.path.abspath(bin_path)
        if not os.path.isfile(path):
            rec = {"name": "custom", "path": path, "version": None,
                   "available": False, "probe": "not-found", "argv": []}
            return {"name": "custom", "version": None, "available": False,
                    "path": path, "probe": "not-found", "requested": "custom",
                    "argv": [], "tried": [rec]}
        argv = ([sys.executable, path] if path.lower().endswith(".py") else [path])
        rec = _probe_runtime("custom", path, argv, "custom")
        rec["requested"] = "custom"
        return {"name": "custom", "version": rec["version"],
                "available": rec["available"], "path": path,
                "probe": rec["probe"], "requested": "custom",
                "argv": argv, "tried": [rec]}

    order = ["docker", "podman"] if prefer == "auto" else [prefer]
    tried: List[Dict[str, Any]] = []
    for name in order:
        path = shutil.which(name)
        rec = _probe_runtime(name, path, [path] if path else [], prefer)
        tried.append(rec)
        if rec["available"]:
            break

    chosen = next((r for r in tried if r["available"]), None)
    if chosen:
        return {"name": chosen["name"], "version": chosen["version"],
                "available": True, "path": chosen["path"], "probe": "ok",
                "requested": prefer, "argv": chosen["argv"], "tried": tried}

    reason = "；".join("%s=%s" % (r["name"], r["probe"]) for r in tried)
    return {"name": None if prefer == "auto" else tried[0]["name"],
            "version": None, "available": False, "path": None,
            "probe": (reason or "无候选运行时")[:500],
            "requested": prefer, "argv": [], "tried": tried}


# ------------------------------------------------------------ 命令组装

def expand_cmd(cmd: str, firmware: str, out: str) -> str:
    """替换占位符 {firmware} / {out}。

    sandbox 模式传入容器内路径（/firmware、/out）；host 模式传入宿主机真实路径。
    整条命令是作为**单个 argv 元素**交给容器内 /bin/sh -c 的，不经过宿主机 shell，
    所以宿主机侧的引号、分号、反引号都不会被解释。
    """
    return (cmd or "").replace("{firmware}", firmware).replace("{out}", out)


def build_container_argv(runtime_argv: List[str], image: str, firmware: str, out: str,
                         args: argparse.Namespace,
                         name: Optional[str] = None) -> List[str]:
    """组装一次性容器的 argv（数组顺序即审计顺序，JSON 的 command 原样记录）。

    runtime_argv 是调用运行时的前缀：标准 docker/podman 只有一项，--runtime-bin
    包装脚本可能是 [python, wrapper.py]。前缀完全由调用者提供，不经过 shell。
    """
    argv: List[str] = list(runtime_argv) + ["run", "--rm"]
    if name:
        # 给容器一个可定位的名字：超时只杀得掉客户端，容器要靠这个名字 rm -f
        argv += ["--name", name]
    argv += [
        # 网络：无论 --network none 还是 loopback，都不给容器任何外部网络接口
        "--network", "none",
        "--read-only",                          # 根文件系统只读，只有 /out 与 /tmp 可写
        "--cap-drop=ALL",
        "--security-opt=no-new-privileges",
        "--user", CONTAINER_UID,                # 无根、无家目录、无凭据
        "--memory", args.memory,
        "--cpus", args.cpus,
        "--pids-limit", str(args.pids),
        "--tmpfs", DEFAULT_TMPFS,               # /tmp 明确 noexec,nosuid
        "-v", "%s:%s:ro" % (firmware, FIRMWARE_TARGET),
        "-v", "%s:%s:rw" % (out, OUT_TARGET),
        "--workdir", OUT_TARGET,                # 相对路径写入落到可写挂载点
        image,
        "/bin/sh", "-c", expand_cmd(args.cmd, FIRMWARE_TARGET, OUT_TARGET),
    ]
    return argv


# ------------------------------------------------------------ 执行

def _pump(pipe: Any, sink: Dict[str, Any]) -> None:
    """读取一路管道：前 CAPTURE_LIMIT 字节留作头部，之后继续读但丢弃。

    必须一直读到 EOF，否则子进程会因管道写满而阻塞，超时机制也就形同虚设。
    """
    buf = bytearray()
    total = 0
    try:
        while True:
            chunk = pipe.read(READ_CHUNK)
            if not chunk:
                break
            total += len(chunk)
            room = CAPTURE_LIMIT - len(buf)
            if room > 0:
                buf.extend(chunk[:room])
    except (OSError, ValueError):
        pass
    finally:
        try:
            pipe.close()
        except OSError:
            pass
    sink["data"] = bytes(buf)
    sink["bytes"] = total


def run_proc(argv: List[str], timeout_s: float) -> Dict[str, Any]:
    """执行命令并有界捕获输出；超时 kill 客户端并标记 timed_out（不抛异常）。

    返回 {exit_code, timed_out, stdout, stderr, stdout_bytes, stderr_bytes, error}。
    超时后 exit_code 为 None —— 那是「没跑完」，不是「跑完返回空」。
    """
    res: Dict[str, Any] = {"exit_code": None, "timed_out": False, "stdout": "",
                           "stderr": "", "stdout_bytes": 0, "stderr_bytes": 0,
                           "error": None}
    out_sink: Dict[str, Any] = {}
    err_sink: Dict[str, Any] = {}
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    except OSError as exc:
        res["error"] = "无法启动进程: %s" % exc
        return res

    th_out = threading.Thread(target=_pump, args=(proc.stdout, out_sink), daemon=True)
    th_err = threading.Thread(target=_pump, args=(proc.stderr, err_sink), daemon=True)
    th_out.start()
    th_err.start()

    try:
        res["exit_code"] = proc.wait(timeout=timeout_s)
    except subprocess.TimeoutExpired:
        res["timed_out"] = True
        proc.kill()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            res["error"] = "超时后进程仍未退出（kill 无效）"
    # 两路读取线程共用一个 5 秒截止时间：超时后孙进程可能仍持有管道，
    # 逐个 join(10) 会把一次 2 秒超时拖成 20 秒。线程是 daemon，超时直接放手。
    deadline = time.monotonic() + 5
    for th in (th_out, th_err):
        th.join(timeout=max(0.0, deadline - time.monotonic()))

    res["stdout"] = _text(out_sink.get("data") or b"")
    res["stderr"] = _text(err_sink.get("data") or b"")
    res["stdout_bytes"] = int(out_sink.get("bytes") or 0)
    res["stderr_bytes"] = int(err_sink.get("bytes") or 0)
    return res


def cleanup_container(runtime_argv: List[str], name: str, notes: List[str]) -> None:
    """尽力删除超时后可能残留的容器。

    杀 docker CLI 不等于容器退出（CLI 只是 API 客户端），一个还在跑固件的容器
    必须被清掉，否则「一次性」就是空话。失败也要留痕，让人能手工收尾。
    """
    shown = " ".join(runtime_argv)
    try:
        p = subprocess.run(list(runtime_argv) + ["rm", "-f", name],
                           capture_output=True, timeout=15)
        if p.returncode == 0:
            notes.append("超时后已删除可能残留的容器：%s" % name)
        else:
            notes.append("超时后删除容器 %s 失败（exit=%s）：请手工执行 %s rm -f %s"
                         % (name, p.returncode, shown, name))
    except (OSError, subprocess.TimeoutExpired) as exc:
        notes.append("超时后清理容器 %s 异常：%s（请手工执行 %s rm -f %s）"
                     % (name, exc, shown, name))


# ------------------------------------------------------------ 策略

def sandbox_policy(args: argparse.Namespace) -> Dict[str, Any]:
    """sandbox 模式实际施加的隔离参数（与 build_container_argv 一一对应）。"""
    return {
        "network": "none",
        "network_requested": args.network,
        "read_only_rootfs": True,
        "cap_drop": "ALL",
        "no_new_privileges": True,
        "user": CONTAINER_UID,
        "memory": args.memory,
        "cpus": args.cpus,
        "pids_limit": args.pids,
        "tmpfs": DEFAULT_TMPFS,
        "timeout_s": args.timeout,
        "host_execution": "forbidden",
    }


def host_policy(args: argparse.Namespace) -> Dict[str, Any]:
    """host 模式：没有任何一项隔离生效，字段置空表示「不适用」，不许冒充沙箱。"""
    return {
        "network": None,
        "network_requested": args.network,
        "read_only_rootfs": False,
        "cap_drop": None,
        "no_new_privileges": False,
        "user": None,
        "memory": None,
        "cpus": None,
        "pids_limit": None,
        "tmpfs": None,
        "timeout_s": args.timeout,
        "host_execution": "explicit-opt-in",
        "note": "host 模式不施加任何隔离参数，以上各项一律未生效",
    }


def _null_policy() -> Dict[str, Any]:
    """还没决定用哪种策略就退出时的占位。"""
    return {"network": None, "network_requested": None, "read_only_rootfs": None,
            "cap_drop": None, "no_new_privileges": None, "user": None,
            "memory": None, "cpus": None, "pids_limit": None, "tmpfs": None,
            "timeout_s": None, "host_execution": "forbidden"}


# ------------------------------------------------------------ 渲染

def _fence(text: str, lang: str = "") -> str:
    """选一个比正文里最长连续反引号更长的围栏，避免内容把代码块截断。"""
    longest = 0
    cur = 0
    for ch in text:
        if ch == "`":
            cur += 1
            longest = max(longest, cur)
        else:
            cur = 0
    fence = "`" * max(3, longest + 1)
    return "%s%s\n%s\n%s" % (fence, lang, text, fence)


def shlex_join(argv: List[str]) -> str:
    """可读的命令行展示（只用于 Markdown，不参与执行）。"""
    try:
        import shlex
        return shlex.join(argv)
    except (ImportError, TypeError, ValueError):
        return " ".join(argv)


def render_md(doc: Dict[str, Any]) -> str:
    """渲染简短中文 Markdown：模式 / 运行时 / 隔离参数 / 命令 / 结果 / 固件哈希。"""
    rt = doc.get("runtime") or {}
    pol = doc.get("policy") or {}
    mounts = doc.get("mounts") or {}
    fw = mounts.get("firmware") or {}
    out = mounts.get("out") or {}

    def esc(val: Any) -> str:
        return "—" if val is None else str(val).replace("|", "\\|")

    if rt.get("available"):
        runtime = "`%s %s`（%s）" % (rt.get("name"), rt.get("version"),
                                           rt.get("path") or "-")
    else:
        runtime = "**不可用** —— %s" % (rt.get("probe") or "未探测")
    if doc.get("mode") == "host-opt-in":
        # host 模式虽然也探测了运行时，但容器一个都没起，别让表格读起来像跑了容器
        runtime += "（host 模式未启动容器）"

    # cap_drop 只存 "ALL"，展示时补回完整参数名，避免被读成「授予 ALL 能力」
    cap_drop = pol.get("cap_drop")
    cap_txt = "`--cap-drop=%s`" % cap_drop if cap_drop else "—"

    lines = [
        "# 沙箱执行记录",
        "",
        "> schema `%s`　·　工具 `%s %s`" % (
            doc.get("schema"), doc.get("tool"), doc.get("version")),
        "",
        "| 项 | 值 |",
        "|---|---|",
        "| 模式 | `%s`（host_fallback=%s） |" % (doc.get("mode"),
                                                  doc.get("host_fallback")),
        "| 运行时 | %s |" % runtime,
        "| 镜像 | `%s` |" % esc(doc.get("image")),
        "| 退出码 | %s |" % ("未执行" if doc.get("exit_code") is None
                             else doc.get("exit_code")),
        "| 耗时 | %s s |" % doc.get("duration_s"),
        "| 是否超时 | %s |" % ("是" if doc.get("timed_out") else "否"),
        "| 结果 | %s |" % ("成功" if doc.get("ok") else "未成功 / 已拒绝"),
        "",
        "## 隔离参数",
        "",
        "| 项 | 值 |",
        "|---|---|",
        "| 网络 | `%s`（请求 `%s`） |" % (esc(pol.get("network")),
                                                  esc(pol.get("network_requested"))),
        "| 根文件系统 | %s |" % ("只读" if pol.get("read_only_rootfs") else "未限制"),
        "| 能力（cap-drop） | %s |" % cap_txt,
        "| no-new-privileges | %s |" % ("是" if pol.get("no_new_privileges") else "否"),
        "| 运行用户 | `%s` |" % esc(pol.get("user")),
        "| 内存 | `%s` |" % esc(pol.get("memory")),
        "| CPU | `%s` |" % esc(pol.get("cpus")),
        "| PID 上限 | `%s` |" % esc(pol.get("pids_limit")),
        "| tmpfs | `%s` |" % esc(pol.get("tmpfs")),
        "| 超时 | %s s |" % esc(pol.get("timeout_s")),
        "| 宿主机执行 | `%s` |" % esc(pol.get("host_execution")),
        "",
    ]

    adm = doc.get("admission") or {}
    if adm:
        slots = adm.get("slots") or {}
        budget = adm.get("budget") or {}
        lines += [
            "## 资源准入",
            "",
            "| 项 | 值 |",
            "|---|---|",
            "| 决策 | `%s`（code=%s） |" % (esc(adm.get("decision")),
                                               esc(adm.get("code"))),
            "| 策略 | `%s…`（来源 %s） |" % (
                esc((adm.get("policy_sha256") or "")[:12]),
                esc(adm.get("policy_source"))),
            "| 槽位 | %s / %s（等待 %ss） |" % (
                esc(slots.get("slot")), esc(slots.get("limit")),
                esc(slots.get("wait_s"))),
            "| 预算 | %s s（已用 %s s，剩余 %s s） |" % (
                esc(budget.get("limit_s")), esc(budget.get("used_s")),
                esc(budget.get("remaining_s"))),
            "| 说明 | %s |" % esc(adm.get("message")),
            "",
        ]

    lines += [
        "## 挂载与指纹",
        "",
        "| 挂载点 | 宿主机路径 | 只读 | sha256 |",
        "|---|---|---|---|",
        "| `%s` | `%s` | %s | `%s` |" % (
            esc(fw.get("target") or FIRMWARE_TARGET), esc(fw.get("path")),
            "是" if fw.get("read_only") else "否", esc(fw.get("sha256") or "未计算")),
        "| `%s` | `%s` | %s | — |" % (
            esc(out.get("target") or OUT_TARGET), esc(out.get("path")),
            "是" if out.get("read_only") else "否"),
        "",
        "## 命令",
        "",
    ]
    argv = doc.get("command") or []
    if argv:
        lines.append(_fence(shlex_join([str(x) for x in argv]), "bash"))
    else:
        lines.append("（本次没有构造命令）")
    lines.append("")

    lines += [
        "## 结果",
        "",
        "- 退出码：`%s`　耗时 `%s s`　超时：%s" % (
            "未执行" if doc.get("exit_code") is None else doc.get("exit_code"),
            doc.get("duration_s"), "是" if doc.get("timed_out") else "否"),
        "- stdout %d 字节，stderr %d 字节" % (doc.get("stdout_bytes") or 0,
                                             doc.get("stderr_bytes") or 0),
        "",
    ]

    for key, title in (("stdout_head", "stdout 头部"), ("stderr_head", "stderr 头部")):
        body = (doc.get(key) or "").strip()
        if body:
            lines += ["### %s" % title, "", _fence(body[:1200], "text"), ""]

    notes = doc.get("notes") or []
    if notes:
        lines += ["## 备注", ""]
        lines += ["- %s" % str(n) for n in notes]
        lines.append("")
    return "\n".join(lines) + "\n"


def print_summary(doc: Dict[str, Any]) -> None:
    """stderr 中文摘要：不给 --json/--md 时，这就是唯一的人类可读结果。"""
    rt = doc.get("runtime") or {}
    pol = doc.get("policy") or {}
    mounts = doc.get("mounts") or {}
    fw = mounts.get("firmware") or {}
    out = mounts.get("out") or {}

    rt_txt = ("%s %s" % (rt.get("name"), rt.get("version"))
              if rt.get("available") else "不可用")
    _say("[sandbox] 模式：%s；运行时：%s；网络：%s"
         % (doc.get("mode"), rt_txt, pol.get("network") or "—"), sys.stderr)
    if fw:
        _say("[sandbox] 固件：%s → %s（%s），清单哈希：%s"
             % (fw.get("path"), fw.get("target") or FIRMWARE_TARGET,
                "只读" if fw.get("read_only") else "未限制读写",
                fw.get("sha256") or "未计算"), sys.stderr)
    if out:
        _say("[sandbox] 输出：%s → %s（可写）"
             % (out.get("path"), out.get("target") or OUT_TARGET), sys.stderr)
    _say("[sandbox] 退出码：%s；耗时：%ss；超时：%s；ok=%s"
         % ("未执行" if doc.get("exit_code") is None else doc.get("exit_code"),
            doc.get("duration_s"), "是" if doc.get("timed_out") else "否",
            doc.get("ok")), sys.stderr)
    adm = doc.get("admission") or {}
    if adm:
        slots = adm.get("slots") or {}
        budget = adm.get("budget") or {}
        _say("[sandbox] 准入：%s（code=%s）；槽位 %s/%s；等待 %ss；预算剩余 %ss"
             % (adm.get("decision"), adm.get("code") or "—",
                slots.get("slot"), slots.get("limit"), slots.get("wait_s"),
                budget.get("remaining_s")), sys.stderr)


# ------------------------------------------------------------ 参数

def _network_arg(value: str) -> str:
    """--network 归一化：none / loopback（loopback 只是接受写法，仍不接外部网络）。"""
    v = (value or "").strip().lower()
    if v == "none":
        return "none"
    if v in ("loopback", "none+loopback", "none+lo", "lo"):
        return "loopback"
    raise argparse.ArgumentTypeError(
        "--network 只接受 none / loopback（loopback 同样不接外部网络）")


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(
        description="不可信固件的一次性隔离执行边界（无运行时即 fail-closed）")
    ap.add_argument("--firmware",
                    help="固件 rootfs 目录（以 :ro 只读挂载到容器 /firmware）")
    ap.add_argument("--out",
                    help="输出目录（可写挂载到容器 /out）；默认用临时目录，结束后删除")
    ap.add_argument("--json", dest="json_out",
                    help="输出 JSON 路径（schema %s）" % SCHEMA)
    ap.add_argument("--md", dest="md_out", help="输出中文 Markdown 路径")
    ap.add_argument("--mode", choices=("auto", "sandbox", "host"), default="auto",
                    help="auto=有可用运行时则沙箱，否则失败关闭（默认）；"
                         "sandbox=必须沙箱，不可用即失败关闭；"
                         "host=仅在 --i-understand-host-risk 下于宿主机执行")
    ap.add_argument("--i-understand-host-risk", action="store_true",
                    help="--mode host 的必需授权：承认宿主机执行不可信固件的全部风险")
    ap.add_argument("--runtime", choices=("auto", "docker", "podman"), default="auto",
                    help="容器运行时；auto=依次探测 docker、podman")
    ap.add_argument("--image", default=DEFAULT_IMAGE,
                    help="容器镜像（默认 %s；离线环境请用本地已有镜像）" % DEFAULT_IMAGE)
    ap.add_argument("--network", type=_network_arg, default="none",
                    help="容器网络：none（默认，无外网）；loopback 同样不接外部网络")
    ap.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                    help="命令超时秒数（默认 %d），由 Python 侧 kill" % DEFAULT_TIMEOUT)
    ap.add_argument("--memory", default=DEFAULT_MEMORY,
                    help="内存上限（默认 %s）" % DEFAULT_MEMORY)
    ap.add_argument("--cpus", default=DEFAULT_CPUS,
                    help="CPU 上限（默认 %s）" % DEFAULT_CPUS)
    ap.add_argument("--pids", type=int, default=DEFAULT_PIDS,
                    help="进程数上限（默认 %d）" % DEFAULT_PIDS)
    ap.add_argument("--cmd", default=DEFAULT_CMD,
                    help="容器内命令（默认 %s，只验证隔离链路、不执行固件内容）；"
                         "可用占位符 {firmware} → /firmware、{out} → /out" % DEFAULT_CMD)
    ap.add_argument("--check", action="store_true",
                    help="只探测隔离能力并输出 JSON，不执行任何固件内容（退出 0/3）")
    ap.add_argument("--policy",
                    help="资源准入策略 JSON（缺省用 resource_manager 默认策略）")
    ap.add_argument("--state-dir",
                    help="跨进程并发槽位目录（缺省在系统临时目录；不放固件内容）")
    ap.add_argument("--slots", type=int, default=None,
                    help="本次允许的并发槽位；不得超过策略 max_concurrency")
    ap.add_argument("--queue-timeout", type=float, default=None,
                    help="等待槽位的最长秒数；不得超过策略 queue_timeout_s")
    ap.add_argument("--budget", type=float, default=None,
                    help="本次总预算秒数（排队+探测+执行+清理）；"
                         "不得超过策略 max_total_seconds")
    ap.add_argument("--runtime-bin",
                    help="自定义容器运行时封装（.py 用当前解释器启动）；"
                         "与 docker 二进制同属可信配置，记入 JSON")
    ap.add_argument("--verbose", action="store_true",
                    help="把探测与命令细节额外打印到 stderr")
    return ap


def validate_args(args: argparse.Namespace) -> Optional[str]:
    """数值 / 格式类校验（返回中文错误串；None 表示通过）。"""
    if not (args.cmd or "").strip():
        return "--cmd 不能为空"
    if args.timeout <= 0:
        return "--timeout 必须是正整数秒（收到 %s）" % args.timeout
    if args.pids <= 0:
        return "--pids 必须是正整数（收到 %s）" % args.pids
    if not MEMORY_RE.match((args.memory or "").strip().lower()):
        return "--memory 格式不合法（如 512m / 1g）：%s" % args.memory
    if not CPUS_RE.match((args.cpus or "").strip()):
        return "--cpus 必须是正数（如 1 / 0.5）：%s" % args.cpus
    if float(args.cpus) <= 0:
        return "--cpus 必须大于 0"
    if not (args.image or "").strip():
        return "--image 不能为空"
    return None


# ------------------------------------------------------------ 主流程

def main(argv=None) -> int:
    _force_utf8_io()
    args = build_parser().parse_args(argv)
    t0 = time.monotonic()
    started_at = utc_now()
    notes: List[str] = []

    # 资源准入状态。策略在参数校验后加载；这里的初值保证任何提前退出都有完整
    # admission 块，而不是一个解释不了的空对象。
    policy: Dict[str, Any] = rm.default_policy()
    policy_sha: str = rm.policy_sha256(policy)
    policy_source: str = "defaults"
    policy_errors: List[Dict[str, Any]] = []
    slots_limit: int = int(policy["max_concurrency"])
    queue_timeout: float = float(policy["queue_timeout_s"])
    budget_limit: float = float(policy["max_total_seconds"])
    state_dir: str = rm.default_state_dir()
    slot_pool: Optional[rm.SlotPool] = None
    slot_no: Optional[int] = None
    slot_wait: float = 0.0

    # mode 记录的是**实际生效**的模式：sandbox / host-opt-in / fail-closed。
    # 初值取 fail-closed：任何提前退出的路径都不该让 JSON 看起来像"跑过沙箱"。
    ctx: Dict[str, Any] = {
        "mode": "host-opt-in" if args.mode == "host" else "fail-closed",
        "runtime": None,
        "command": [],
        "mounts": {"firmware": None, "out": None},
        "policy": None,
        "exit_code": None,
        "timed_out": False,
        "stdout": "",
        "stderr": "",
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "ok": False,
        "out_tmp": None,
        "admission": None,
    }

    def release_slot() -> None:
        """释放并发槽位；重复调用安全。任何退出路径都必须经过这里。"""
        nonlocal slot_pool
        if slot_pool is not None:
            try:
                slot_pool.release()
            except OSError as exc:
                notes.append("释放并发槽位失败：%s" % exc)
            finally:
                slot_pool = None

    def budget_snapshot() -> Dict[str, Any]:
        used = round(time.monotonic() - t0, 3)
        return {"limit_s": round(budget_limit, 3), "used_s": used,
                "remaining_s": round(max(0.0, budget_limit - used), 3)}

    def admission_snapshot(decision: str, code: Optional[str] = None,
                           message: Optional[str] = None) -> Dict[str, Any]:
        rec: Dict[str, Any] = {
            "decision": decision,
            "code": code,
            "message": message,
            "policy": policy,
            "policy_sha256": policy_sha,
            "policy_source": policy_source,
            "request": {"mode": args.mode, "timeout": args.timeout,
                        "memory": args.memory, "cpus": args.cpus,
                        "pids": args.pids, "image": args.image},
            "slots": {"limit": slots_limit, "slot": slot_no,
                      "wait_s": round(slot_wait, 3),
                      "queued": bool(slot_wait > 0), "state_dir": state_dir},
            "budget": budget_snapshot(),
        }
        if policy_errors:
            rec["policy_errors"] = policy_errors
        return rec

    ctx["admission"] = admission_snapshot("pending")

    def finish(code: int) -> int:
        """统一收尾：释放槽位 / 补时间 / 写 JSON、Markdown → stderr 摘要。"""
        release_slot()
        if ctx["admission"] and ctx["admission"].get("decision") == "pending":
            ctx["admission"] = admission_snapshot("rejected")
        if ctx["out_tmp"]:
            tmp = ctx["out_tmp"]
            ctx["out_tmp"] = None
            try:
                shutil.rmtree(tmp)
                notes.append("未指定 --out，临时输出目录已删除：%s" % tmp)
            except OSError as exc:
                notes.append("临时输出目录删除失败（%s）：%s" % (tmp, exc))

        elapsed = round(time.monotonic() - t0, 3)
        if ctx["stdout_bytes"] > CAPTURE_LIMIT:
            notes.append("stdout 共 %d 字节，超过捕获上限 %d，仅保留前部"
                         % (ctx["stdout_bytes"], CAPTURE_LIMIT))
        if ctx["stderr_bytes"] > CAPTURE_LIMIT:
            notes.append("stderr 共 %d 字节，超过捕获上限 %d，仅保留前部"
                         % (ctx["stderr_bytes"], CAPTURE_LIMIT))

        runtime = ctx["runtime"] or {
            "name": None, "version": None, "available": False, "path": None,
            "probe": "未探测", "requested": args.runtime, "tried": []}

        doc: Dict[str, Any] = {
            "schema": SCHEMA,
            "tool": TOOL,
            "version": VERSION,
            "mode": ctx["mode"],
            # 本工具不存在宿主机回退路径：host 只能是显式选择，绝不会是 fallback
            "host_fallback": False,
            "check_only": bool(args.check),
            "image": args.image,
            "runtime": runtime,
            "command": ctx["command"],
            "mounts": ctx["mounts"],
            "policy": ctx["policy"] or _null_policy(),
            "admission": ctx["admission"] or admission_snapshot("rejected"),
            "started_at": started_at,
            "finished_at": utc_now(),
            "duration_s": elapsed,
            "exit_code": ctx["exit_code"],
            "timed_out": ctx["timed_out"],
            "stdout_bytes": ctx["stdout_bytes"],
            "stderr_bytes": ctx["stderr_bytes"],
            "stdout_head": ctx["stdout"][:HEAD_LIMIT],
            "stderr_head": ctx["stderr"][:HEAD_LIMIT],
            "ok": bool(ctx["ok"]),
            "notes": notes,
        }

        # --check 的 stdout 只放 JSON：别让日志行污染可解析输出
        log_stream = sys.stderr if args.check else sys.stdout
        json_err = None
        md_err = None
        if args.json_out:
            json_err = write_text(
                args.json_out, json.dumps(doc, ensure_ascii=False, indent=2) + "\n")
            if json_err:
                _say("[error] 写 JSON 失败（%s）：%s" % (args.json_out, json_err),
                     sys.stderr)
            else:
                _say("[ok] JSON → %s" % args.json_out, log_stream)
        if args.md_out:
            md_err = write_text(args.md_out, render_md(doc))
            if md_err:
                _say("[error] 写 Markdown 失败（%s）：%s" % (args.md_out, md_err),
                     sys.stderr)
            else:
                _say("[ok] Markdown → %s" % args.md_out, log_stream)

        if args.check:
            _say(json.dumps(doc, ensure_ascii=False, indent=2))

        print_summary(doc)

        # 该写的产物没写成 → 不能还报成功（但更重要的退出码要保留）
        if code == EXIT_OK and (json_err or md_err):
            return EXIT_USAGE
        return code

    def fail(code: int, msg: str) -> int:
        """打一行错误再收尾（成功路径不会走到这里）。"""
        _say("[error] %s" % msg, sys.stderr)
        return finish(code)

    def absorb(result: Dict[str, Any]) -> None:
        """把一次执行结果吸收进 ctx（退出码 / 超时 / 输出 / 字节数）。"""
        ctx["exit_code"] = result.get("exit_code")
        ctx["timed_out"] = bool(result.get("timed_out"))
        ctx["stdout"] = result.get("stdout") or ""
        ctx["stderr"] = result.get("stderr") or ""
        ctx["stdout_bytes"] = int(result.get("stdout_bytes") or 0)
        ctx["stderr_bytes"] = int(result.get("stderr_bytes") or 0)
        if result.get("error"):
            notes.append(str(result["error"]))

    # ---- 1. 参数合法性 ----
    problem = validate_args(args)
    if problem:
        return fail(EXIT_USAGE, problem)

    # ---- 2. 资源策略：先加载，再做任何可能消耗资源的事 ----
    policy, policy_errors, policy_sha, policy_source = rm.load_policy(args.policy)
    if policy_errors:
        detail = "；".join("%s: %s" % (e.get("path"), e.get("message"))
                          for e in policy_errors[:4])
        ctx["admission"] = admission_snapshot(
            "rejected", "POLICY_INVALID", "资源策略不合法：" + detail)
        return fail(EXIT_POLICY, "资源策略不合法（%s）：%s"
                    % (args.policy or "defaults", detail))

    slots_limit = int(policy["max_concurrency"])
    if args.slots is not None:
        if args.slots < 1:
            ctx["admission"] = admission_snapshot(
                "rejected", "SLOTS_LIMIT", "--slots 必须 >= 1")
            return fail(EXIT_POLICY, "--slots 必须 >= 1（收到 %s）" % args.slots)
        if args.slots > int(policy["max_concurrency"]):
            ctx["admission"] = admission_snapshot(
                "rejected", "SLOTS_LIMIT", "--slots 超过策略上限")
            return fail(EXIT_POLICY,
                        "--slots %s 超过策略 max_concurrency=%s；"
                        "调高并发只能改策略，不能用命令行绕过"
                        % (args.slots, policy["max_concurrency"]))
        slots_limit = args.slots

    queue_timeout = float(policy["queue_timeout_s"])
    if args.queue_timeout is not None:
        if args.queue_timeout < 0:
            ctx["admission"] = admission_snapshot(
                "rejected", "QUEUE_LIMIT", "--queue-timeout 不能为负")
            return fail(EXIT_POLICY, "--queue-timeout 不能为负（收到 %s）"
                        % args.queue_timeout)
        if args.queue_timeout > float(policy["queue_timeout_s"]):
            ctx["admission"] = admission_snapshot(
                "rejected", "QUEUE_LIMIT", "--queue-timeout 超过策略上限")
            return fail(EXIT_POLICY,
                        "--queue-timeout %ss 超过策略 queue_timeout_s=%ss"
                        % (args.queue_timeout, policy["queue_timeout_s"]))
        queue_timeout = float(args.queue_timeout)

    budget_limit = float(policy["max_total_seconds"])
    if args.budget is not None:
        if args.budget <= 0:
            ctx["admission"] = admission_snapshot(
                "rejected", "BUDGET_LIMIT", "--budget 必须大于 0")
            return fail(EXIT_POLICY, "--budget 必须大于 0（收到 %s）" % args.budget)
        if args.budget > float(policy["max_total_seconds"]):
            ctx["admission"] = admission_snapshot(
                "rejected", "BUDGET_LIMIT", "--budget 超过策略上限")
            return fail(EXIT_POLICY,
                        "--budget %ss 超过策略 max_total_seconds=%ss"
                        % (args.budget, policy["max_total_seconds"]))
        budget_limit = float(args.budget)

    state_dir = (os.path.abspath(args.state_dir) if args.state_dir
                 else rm.default_state_dir())

    request_errors = rm.check_request(
        policy, timeout=args.timeout, memory=args.memory, cpus=args.cpus,
        pids=args.pids, image=args.image, mode=args.mode)
    if request_errors:
        first = request_errors[0]
        detail = "；".join("%s: %s" % (e.get("path"), e.get("message"))
                          for e in request_errors[:4])
        ctx["admission"] = admission_snapshot(
            "rejected", first.get("code"), "资源请求超出策略：" + detail)
        return fail(EXIT_POLICY, "资源请求超出策略：%s" % detail)

    ctx["admission"] = admission_snapshot("pending")

    # ---- 3. host 模式必须先拿到显式授权 ----
    # 放在最前：连固件都不看，就能拒绝一次「忘了加授权」的宿主机执行。
    if args.mode == "host" and not args.i_understand_host_risk:
        return fail(EXIT_POLICY,
                    "--mode host 必须同时给 --i-understand-host-risk："
                    "宿主机执行不可信固件等于放弃全部隔离。"
                    "本工具没有回退路径，也不会替你默认选择 host。")

    # ---- 3. 固件目录 ----
    fw_abs: Optional[str] = None
    if args.firmware:
        fw_abs = os.path.abspath(args.firmware)
        if not os.path.exists(fw_abs):
            return fail(EXIT_POLICY, "固件目录不存在：%s（拒绝执行）" % fw_abs)
        if not os.path.isdir(fw_abs):
            return fail(EXIT_POLICY, "--firmware 必须是目录：%s" % fw_abs)
        fw_abs = os.path.realpath(fw_abs)

    if fw_abs and _within(_norm_path(state_dir), _norm_path(fw_abs)):
        ctx["admission"] = admission_snapshot(
            "rejected", "STATE_DIR_IN_FIRMWARE",
            "槽位目录不得落在固件目录内")
        return fail(EXIT_POLICY,
                    "槽位目录不得落在固件目录内：state-dir=%s firmware=%s"
                    "（锁文件和 owner 元数据不应污染固件证据）"
                    % (state_dir, fw_abs))
    if not fw_abs and not args.check:
        return fail(EXIT_USAGE, "--firmware 是必填项（只有 --check 可以省略）")

    # ---- 4. 输出目录：这里只算路径，真正要执行时才创建 ----
    # 失败关闭的路径不该留下任何副作用：一个「拒绝执行」却在磁盘上建了目录的工具，
    # 会让人以为有东西跑过了。
    out_abs: Optional[str] = None
    if args.out:
        out_abs = os.path.realpath(os.path.abspath(args.out))
        if os.path.exists(out_abs) and not os.path.isdir(out_abs):
            return fail(EXIT_USAGE, "--out 已存在但不是目录：%s" % out_abs)

    # ---- 5. 挂载重叠：可写输出若覆盖只读固件，隔离就名存实亡 ----
    if fw_abs and out_abs:
        fw_n, out_n = _norm_path(fw_abs), _norm_path(out_abs)
        if _within(fw_n, out_n) or _within(out_n, fw_n):
            return fail(EXIT_POLICY,
                        "固件目录与输出目录不得相同或互为父子：firmware=%s out=%s"
                        "（可写输出覆盖只读固件时，:ro 挂载形同虚设）"
                        % (fw_abs, out_abs))

    def prepare_out_for_container() -> None:
        """让容器内的 uid 65534 能写入 bind mount 的输出目录。

        docker/podman 的 bind mount 不做 UID 映射：宿主机上由 root 或普通用户
        创建的 0755 目录，进容器后对 65534 只有 r-x，写 /out 会 Permission denied。
        这里补 other 的 rwx 与 sticky（保留 owner/group 位）：other 写让容器能落
        产物，sticky 让其他本地用户不能删除容器创建的文件。只在 sandbox 模式调用，
        host 模式沿用用户原目录权限。非 POSIX 平台 chmod 语义有限，失败只记 notes，
        由命令自身的 exit_code 暴露问题，不静默假装可写。
        """
        if not out_abs:
            return
        try:
            st = os.stat(out_abs)
        except OSError as exc:
            notes.append("无法检查输出目录权限：%s" % exc)
            return
        mode = stat.S_IMODE(st.st_mode)
        wanted = mode | 0o1007
        if wanted == mode:
            return
        try:
            os.chmod(out_abs, wanted)
        except OSError as exc:
            notes.append("输出目录权限无法调整为容器可写（%04o）：%s" % (mode, exc))
            return
        notes.append("输出目录 %s 原模式 %04o，已补 other rwx + sticky 为 %04o"
                     "（容器以 uid %s 写入，bind mount 不做 UID 映射）"
                     % (out_abs, mode, wanted, CONTAINER_UID))

    def ensure_out() -> Optional[int]:
        """执行前准备输出目录（未给 --out 时用临时目录，结束后由 finish 删除）。

        返回 None 表示就绪；返回退出码表示已失败并已完成收尾。
        """
        nonlocal out_abs
        if out_abs:
            if not os.path.isdir(out_abs):
                try:
                    os.makedirs(out_abs, exist_ok=True)
                except OSError as exc:
                    return fail(EXIT_USAGE, "无法创建输出目录 %s：%s" % (out_abs, exc))
            if args.mode != "host":
                prepare_out_for_container()
            return None
        try:
            out_abs = os.path.realpath(tempfile.mkdtemp(prefix="sandbox-run-out-"))
        except OSError as exc:
            return fail(EXIT_USAGE, "无法创建临时输出目录：%s" % exc)
        ctx["out_tmp"] = out_abs
        notes.append("未指定 --out，已创建临时输出目录 %s（结束后删除）" % out_abs)
        if args.mode != "host":
            prepare_out_for_container()
        return None

    def acquire_slot() -> Optional[int]:
        """占用一个并发槽位；拿不到就按 admission 失败收尾（返回退出码）。

        槽位必须在 ensure_out / dir_hash / 启动命令之前拿到：先启动再发现超限，
        等于让宿主机先承受一次峰值。
        """
        nonlocal slot_pool, slot_no, slot_wait
        try:
            slot_pool = rm.SlotPool(state_dir, slots_limit)
            slot_no, slot_wait = slot_pool.acquire(
                queue_timeout, budget_deadline=t0 + budget_limit,
                owner={"pid": os.getpid(), "mode": args.mode,
                       "cmd": (args.cmd or "")[:200]})
        except rm.AdmissionError as exc:
            slot_pool = None
            decision = ("budget-exhausted" if exc.code == "BUDGET_EXHAUSTED"
                        else "queue-timeout")
            ctx["admission"] = admission_snapshot(decision, exc.code, exc.message)
            return fail(exc.exit_code, exc.message)
        except OSError as exc:
            slot_pool = None
            ctx["admission"] = admission_snapshot(
                "rejected", "STATE_DIR_ERROR",
                "槽位目录不可用：%s" % exc)
            return fail(EXIT_ADMISSION, "槽位目录不可用：%s" % exc)

        if slot_wait > 0:
            notes.append("资源准入：排队 %.2fs 后获得槽位 %s/%s"
                         % (slot_wait, slot_no, slots_limit))
        remaining = budget_limit - (time.monotonic() - t0)
        if remaining < 1.0:
            release_slot()
            ctx["admission"] = admission_snapshot(
                "budget-exhausted", "BUDGET_EXHAUSTED",
                "获取槽位后剩余预算不足 1 秒")
            return fail(EXIT_ADMISSION,
                        "获取槽位后剩余预算不足 1 秒（预算 %.1fs，已用 %.1fs）；"
                        "未启动任何命令" % (budget_limit, time.monotonic() - t0))
        ctx["admission"] = admission_snapshot("admitted")
        return None

    # ---- 6. 运行时探测 ----
    runtime = detect_runtime(args.runtime, args.runtime_bin)
    ctx["runtime"] = runtime
    if args.verbose:
        for rec in runtime.get("tried") or []:
            _say("[probe] %s: %s" % (rec.get("name"), rec.get("probe")), sys.stderr)

    # ---- 7. --check：只报能力，不碰固件内容 ----
    if args.check:
        ctx["mode"] = ("host-opt-in" if args.mode == "host"
                       else "sandbox" if runtime["available"] else "fail-closed")
        ctx["ok"] = bool(runtime["available"])
        ctx["policy"] = (host_policy(args) if args.mode == "host"
                         else sandbox_policy(args))
        if fw_abs:
            ctx["mounts"]["firmware"] = {
                "path": fw_abs, "sha256": None, "read_only": True,
                "target": FIRMWARE_TARGET}
            notes.append("--check 不读取固件内容，未计算清单哈希")
        if out_abs:
            ctx["mounts"]["out"] = {"path": out_abs, "read_only": False,
                                    "target": OUT_TARGET}
        if fw_abs and out_abs:
            rt_argv = (runtime.get("argv")
                       or [runtime.get("path") or runtime.get("name") or "docker"])
            ctx["command"] = build_container_argv(
                rt_argv, args.image, fw_abs, out_abs, args, None)
            notes.append("command 为预览：--check 不执行任何内容")
        if not runtime["available"]:
            ctx["admission"] = admission_snapshot(
                "checked", "RUNTIME_UNAVAILABLE",
                "只做能力探测；运行时不可用，未占槽位")
            _say("[check] 运行时 %s 不可用：%s"
                 % (args.runtime, runtime.get("probe") or "未知原因"), sys.stderr)
            _say("[hint] 安装并启动 docker 或 podman 后重试；"
                 "仅为可完全信任的 rootfs 保留 --mode host --i-understand-host-risk",
                 sys.stderr)
            _say("[error] " + FAIL_CLOSED_MSG, sys.stderr)
            return finish(EXIT_UNAVAILABLE)
        _say("[check] 隔离能力可用：%s %s（%s）"
             % (runtime["name"], runtime["version"], runtime["path"]), sys.stderr)
        if args.mode == "host":
            notes.append("host 模式下 --check 仍按隔离能力给出 0/3；"
                         "host 执行本身不受隔离能力限制")
        ctx["admission"] = admission_snapshot(
            "checked", None, "只做能力探测，未占槽位、未执行命令")
        return finish(EXIT_OK)

    # ---- 8. 决定这次到底在哪儿执行 ----
    if args.mode == "host":
        rc = acquire_slot()
        if rc is not None:
            return rc
        rc = ensure_out()
        if rc is not None:
            return rc
        ctx["mode"] = "host-opt-in"
        ctx["policy"] = host_policy(args)
        ctx["mounts"]["firmware"] = {
            "path": fw_abs, "sha256": dir_hash(fw_abs, notes),
            "read_only": False, "target": fw_abs, "enforced": False}
        ctx["mounts"]["out"] = {"path": out_abs, "read_only": False,
                                "target": out_abs, "enforced": False}
        notes.append("host-opt-in：命令直接在宿主机执行，隔离参数全部未生效；"
                     "固件目录没有被只读保护")
        _say("", sys.stderr)
        _say("!" * 72, sys.stderr)
        _say("[warn] host 模式：命令将直接在宿主机执行，容器隔离参数全部不生效！",
             sys.stderr)
        _say("[warn] 仅限可完全信任的自建 rootfs 或人工确认过的只读命令；"
             "本机可能被固件内容改动，甚至被植入持久化。", sys.stderr)
        _say("[warn] 这不是 fallback，是你显式授权的选择（host_fallback=false）。",
             sys.stderr)
        _say("!" * 72, sys.stderr)

        cmd_host = expand_cmd(args.cmd, fw_abs or "", out_abs or "")
        argv = (["cmd", "/c", cmd_host] if os.name == "nt"
                else ["/bin/sh", "-c", cmd_host])
        ctx["command"] = argv
        if args.verbose:
            _say("[exec] %s" % " ".join(argv), sys.stderr)
        remaining = budget_limit - (time.monotonic() - t0)
        if remaining < 0.5:
            ctx["admission"] = admission_snapshot(
                "budget-exhausted", "BUDGET_EXHAUSTED",
                "准备执行时预算已耗尽")
            return fail(EXIT_ADMISSION,
                        "准备执行时预算已耗尽（预算 %.1fs）；未启动命令"
                        % budget_limit)
        effective_timeout = min(float(args.timeout), max(0.1, remaining))
        if effective_timeout < float(args.timeout):
            notes.append("总预算只剩 %.1fs，命令超时由 %ss 截短为 %.1fs"
                         % (remaining, args.timeout, effective_timeout))
        absorb(run_proc(argv, effective_timeout))
        if ctx["timed_out"]:
            notes.append("命令超过 %.1fs 未结束，已被 kill（退出码 124）"
                         % effective_timeout)
            return finish(EXIT_TIMEOUT)
        if ctx["exit_code"] == 0:
            ctx["ok"] = True
            return finish(EXIT_OK)
        notes.append("命令已执行但返回非零（宿主机退出码 %s）；"
                     "进程退出码按约定映射为 1" % ctx["exit_code"])
        return finish(EXIT_COMMAND_FAILED)

    # sandbox 路径（mode=auto / sandbox）：没有可用运行时 → 失败关闭，绝不回退
    if not runtime["available"]:
        ctx["mode"] = "fail-closed"
        ctx["policy"] = sandbox_policy(args)
        if fw_abs:
            ctx["mounts"]["firmware"] = {
                "path": fw_abs, "sha256": None, "read_only": True,
                "target": FIRMWARE_TARGET}
        if out_abs:
            ctx["mounts"]["out"] = {"path": out_abs, "read_only": False,
                                    "target": OUT_TARGET}
        notes.append("运行时探测失败：%s"
                     % (runtime.get("probe") or "未找到 docker / podman"))
        notes.append("本次没有执行任何固件内容；本工具不存在宿主机回退路径")
        notes.append("确需在宿主机执行，请显式 --mode host --i-understand-host-risk")
        _say("[error] " + FAIL_CLOSED_MSG, sys.stderr)
        _say("[hint] 安装并启动 docker 或 podman 后重试；"
             "本工具不会为了「先跑起来」而降低隔离要求", sys.stderr)
        return finish(EXIT_UNAVAILABLE)

    # 有可用运行时：真正执行
    rc = acquire_slot()
    if rc is not None:
        return rc
    rc = ensure_out()
    if rc is not None:
        return rc
    ctx["mode"] = "sandbox"
    ctx["policy"] = sandbox_policy(args)
    ctx["mounts"]["firmware"] = {
        "path": fw_abs, "sha256": dir_hash(fw_abs, notes),
        "read_only": True, "target": FIRMWARE_TARGET}
    ctx["mounts"]["out"] = {"path": out_abs, "read_only": False,
                            "target": OUT_TARGET}
    if args.network != "none":
        notes.append("请求 --network %s：容器仍以 --network none 启动（不接任何外部网络）；"
                     "容器内 lo 的启用取决于镜像与命令，本工具不授予 CAP_NET_ADMIN"
                     % args.network)
    notes.append("容器不注入任何宿主机环境变量（无凭据）；输出目录已按 uid %s "
                 "调整 other rwx + sticky，写入失败仍会如实记录 exit_code"
                 % CONTAINER_UID)

    name = "iotfw-sandbox-" + uuid.uuid4().hex[:12]
    rt_argv = runtime.get("argv") or [runtime.get("path") or runtime["name"]]
    argv = build_container_argv(rt_argv, args.image, fw_abs, out_abs, args, name)
    ctx["command"] = argv
    if args.verbose:
        _say("[exec] %s" % " ".join(argv), sys.stderr)

    remaining = budget_limit - (time.monotonic() - t0)
    if remaining < 0.5:
        ctx["admission"] = admission_snapshot(
            "budget-exhausted", "BUDGET_EXHAUSTED", "准备执行时预算已耗尽")
        return fail(EXIT_ADMISSION,
                    "准备执行时预算已耗尽（预算 %.1fs）；未启动容器" % budget_limit)
    effective_timeout = min(float(args.timeout), max(0.1, remaining))
    if effective_timeout < float(args.timeout):
        notes.append("总预算只剩 %.1fs，命令超时由 %ss 截短为 %.1fs"
                     % (remaining, args.timeout, effective_timeout))

    absorb(run_proc(argv, effective_timeout))

    if ctx["timed_out"]:
        cleanup_container(rt_argv, name, notes)
        notes.append("命令超过 %.1fs 未结束，已被 kill（退出码 124）"
                     % effective_timeout)
        return finish(EXIT_TIMEOUT)

    if ctx["exit_code"] == 0:
        ctx["ok"] = True
        return finish(EXIT_OK)

    if ctx["exit_code"] is None:
        notes.append("命令未能正常结束（见上方备注），进程退出码按约定映射为 1")
    else:
        notes.append("命令已执行但返回非零（容器退出码 %s）；"
                     "进程退出码按约定映射为 1" % ctx["exit_code"])
    return finish(EXIT_COMMAND_FAILED)


if __name__ == "__main__":
    raise SystemExit(main())
