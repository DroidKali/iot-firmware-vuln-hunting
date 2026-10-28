#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""resource_manager.py — 沙箱资源准入：策略、并发槽位与预算（ROADMAP M2）

为什么需要它
------------
M2 之前，sandbox_run.py 已经 fail-closed，但「谁可以同时跑、能跑多久、最多
吃多少内存」只靠调用方自觉：两个审计任务同时启动两个 QEMU，宿主机先被拖垮，
再谈隔离已经没有意义。这个模块把资源准入从「文档约定」变成可执行的检查：

* 策略（sandbox-policy/1.0）给出上限：并发、排队、总预算、单命令超时、内存、
  CPU、PID、镜像白名单、是否允许 host 模式；
* 跨进程槽位（SlotPool）用操作系统文件锁实现。超限时**排队等待**，而不是先
  启动再发现资源不足；等待超过 queue_timeout 返回 QUEUE_TIMEOUT；
* 预算是从进程启动开始算的墙钟上限，排队、探测、执行、清理都计入；执行前
  把剩余预算折算成命令超时，避免「排队排了 10 分钟，命令还能再跑 120 秒」；
* 所有拒绝都返回机器可读 code，sandbox_run 把它写进 JSON 的 admission 块。

边界
----
这不是容器本身，也不替代 sandbox_run.py 的隔离参数。它只回答「现在能不能
开始」和「最多给多少」。策略文件是可信输入；槽位目录只放锁文件与 owner 元数据，
不放固件内容。

用法
----
    python scripts/resource_manager.py defaults --json
    python scripts/resource_manager.py validate --policy policy.json

退出码：0 通过；1 策略不合法；2 用法/IO 错误。纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import tempfile
import time
from typing import Any, Dict, List, Optional

VERSION = "1.0"
POLICY_SCHEMA = "sandbox-policy/1.0"
EXIT_POLICY = 1
EXIT_USAGE = 2

#: 默认策略。这些值必须不小于 sandbox_run.py 的默认请求（120s / 512m / 1 CPU /
#: 128 PID），否则「不带 --policy 的默认调用」会被自己的策略拒绝。
DEFAULT_POLICY: Dict[str, Any] = {
    "schema": POLICY_SCHEMA,
    "max_concurrency": 1,
    "queue_timeout_s": 300,
    "max_total_seconds": 1800,
    "max_timeout_s": 300,
    "max_memory_mb": 1024,
    "max_cpus": 2.0,
    "max_pids": 256,
    "allowed_images": None,          # null = 不限制镜像；数组 = 精确白名单
    "allow_host": True,              # host 仍需 --i-understand-host-risk；策略可再收紧
}

POLICY_KEYS = tuple(DEFAULT_POLICY.keys())
INT_KEYS = ("max_concurrency", "queue_timeout_s", "max_total_seconds",
            "max_timeout_s", "max_memory_mb", "max_pids")
RANGES = {
    "max_concurrency": (1, 64),
    "queue_timeout_s": (0, 86400),
    "max_total_seconds": (1, 86400),
    "max_timeout_s": (1, 86400),
    "max_memory_mb": (16, 1 << 20),
    "max_pids": (8, 1 << 20),
}
MEMORY_RE = re.compile(r"^([0-9]+(?:\.[0-9]+)?)\s*([bkmgBKMG]?)$")
MEMORY_UNIT_MB = {"": 1.0 / (1024 * 1024), "b": 1.0 / (1024 * 1024),
                  "k": 1.0 / 1024, "m": 1.0, "g": 1024.0}


class AdmissionError(Exception):
    """资源准入失败：带机器可读 code 与建议退出码。"""

    def __init__(self, code: str, message: str, exit_code: int = 5):
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code

    def as_dict(self) -> Dict[str, Any]:
        return {"code": self.code, "message": self.message,
                "exit_code": self.exit_code}


def canonical_json(obj: Any) -> str:
    """稳定 JSON：策略 hash 与事件 dedupe 都不受键顺序影响。"""
    return json.dumps(obj, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def policy_sha256(policy: Dict[str, Any]) -> str:
    return hashlib.sha256(canonical_json(policy).encode("utf-8")).hexdigest()


def default_policy() -> Dict[str, Any]:
    return json.loads(json.dumps(DEFAULT_POLICY))


def default_state_dir() -> str:
    """跨进程槽位目录：同一用户共享一个稳定位置，但不同用户不互相踩。"""
    if hasattr(os, "getuid"):
        tag = str(os.getuid())
    else:
        try:
            import getpass
            tag = hashlib.sha256(getpass.getuser().encode("utf-8")).hexdigest()[:10]
        except Exception:
            tag = "default"
    return os.path.join(tempfile.gettempdir(), "iot-firmware-sandbox-" + tag)


def memory_to_mb(value: Any) -> Optional[float]:
    """把 docker 风格的内存值换算成 MiB；无法解析返回 None。

    只接受一个数字加可选单位，不做表达式求值：策略/参数是配置，不是脚本。
    """
    if not isinstance(value, str):
        return None
    m = MEMORY_RE.match(value.strip())
    if not m:
        return None
    try:
        number = float(m.group(1))
    except ValueError:
        return None
    unit = (m.group(2) or "").lower()
    return number * MEMORY_UNIT_MB[unit]


def _err(errors: List[Dict[str, str]], path: str, code: str, message: str) -> None:
    errors.append({"path": path, "code": code, "message": message})


def validate_policy(raw: Any) -> tuple:
    """校验并补全策略；返回 (policy, errors)。

    未知字段直接拒绝：策略里一个拼错的 max_memory 如果被忽略，调用方会以为
    限制生效了，这比没有策略更危险。
    """
    errors: List[Dict[str, str]] = []
    if not isinstance(raw, dict):
        _err(errors, "policy", "BAD_TYPE", "策略必须是 JSON 对象")
        return default_policy(), errors

    for key in raw:
        if key not in POLICY_KEYS:
            _err(errors, "policy." + str(key), "UNKNOWN_FIELD",
                 "未知策略字段 %r（拼错的限制不会被静默忽略）" % key)

    policy = default_policy()
    if "schema" in raw and raw.get("schema") != POLICY_SCHEMA:
        _err(errors, "policy.schema", "UNKNOWN_VERSION",
             "策略 schema 必须是 %s（收到 %r）" % (POLICY_SCHEMA, raw.get("schema")))

    for key in INT_KEYS:
        if key not in raw:
            continue
        val = raw.get(key)
        if isinstance(val, bool) or not isinstance(val, int):
            _err(errors, "policy." + key, "BAD_TYPE", "%s 必须是整数" % key)
            continue
        lo, hi = RANGES[key]
        if val < lo or val > hi:
            _err(errors, "policy." + key, "OUT_OF_RANGE",
                 "%s 必须在 %s..%s 之间（收到 %s）" % (key, lo, hi, val))
            continue
        policy[key] = val

    if "max_cpus" in raw:
        val = raw.get("max_cpus")
        if isinstance(val, bool) or not isinstance(val, (int, float)):
            _err(errors, "policy.max_cpus", "BAD_TYPE", "max_cpus 必须是数字")
        elif float(val) < 0.1 or float(val) > 256:
            _err(errors, "policy.max_cpus", "OUT_OF_RANGE",
                 "max_cpus 必须在 0.1..256 之间（收到 %s）" % val)
        else:
            policy["max_cpus"] = float(val)

    if "allowed_images" in raw:
        val = raw.get("allowed_images")
        if val is None:
            policy["allowed_images"] = None
        elif not isinstance(val, list) or not val:
            _err(errors, "policy.allowed_images", "BAD_TYPE",
                 "allowed_images 必须是 null 或非空字符串数组")
        elif any(not isinstance(x, str) or not x.strip() for x in val):
            _err(errors, "policy.allowed_images", "BAD_TYPE",
                 "allowed_images 的每一项都必须是非空字符串")
        else:
            policy["allowed_images"] = [x.strip() for x in val]

    if "allow_host" in raw:
        val = raw.get("allow_host")
        if not isinstance(val, bool):
            _err(errors, "policy.allow_host", "BAD_TYPE", "allow_host 必须是布尔值")
        else:
            policy["allow_host"] = val

    # 单命令超时超过总预算没有意义：预算会在执行前把 timeout 截短，配置本身
    # 就是矛盾的，直接拒绝而不是悄悄截断。
    if (isinstance(policy.get("max_timeout_s"), int)
            and isinstance(policy.get("max_total_seconds"), int)
            and policy["max_timeout_s"] > policy["max_total_seconds"]):
        _err(errors, "policy.max_timeout_s", "TIMEOUT_EXCEEDS_BUDGET",
             "max_timeout_s (%s) 不得大于 max_total_seconds (%s)"
             % (policy["max_timeout_s"], policy["max_total_seconds"]))

    return policy, errors


def load_policy(path: Optional[str]) -> tuple:
    """读取策略文件；path 为空时返回默认策略。返回 (policy, errors, sha, source)。"""
    if not path:
        policy = default_policy()
        return policy, [], policy_sha256(policy), "defaults"
    try:
        with open(path, "r", encoding="utf-8") as fh:
            raw = json.load(fh)
    except OSError as exc:
        return default_policy(), [{"path": "policy", "code": "READ_ERROR",
                                   "message": "无法读取策略文件 %s：%s" % (path, exc)}], \
            policy_sha256(default_policy()), path
    except ValueError as exc:
        return default_policy(), [{"path": "policy", "code": "PARSE_ERROR",
                                   "message": "策略文件不是合法 JSON：%s" % exc}], \
            policy_sha256(default_policy()), path
    policy, errors = validate_policy(raw)
    return policy, errors, policy_sha256(policy), os.path.abspath(path)


def check_request(policy: Dict[str, Any], *, timeout: int, memory: str,
                  cpus: str, pids: int, image: str, mode: str,
                  enforce_host: bool = True) -> List[Dict[str, str]]:
    """把一次请求与策略对拍；返回结构化错误列表（空表示准入）。"""
    errors: List[Dict[str, str]] = []
    if isinstance(timeout, bool) or not isinstance(timeout, int) or timeout <= 0:
        _err(errors, "request.timeout", "BAD_TYPE", "timeout 必须是正整数秒")
    elif timeout > int(policy["max_timeout_s"]):
        _err(errors, "request.timeout", "TIMEOUT_LIMIT",
             "请求超时 %ss 超过策略上限 %ss" % (timeout, policy["max_timeout_s"]))

    mem = memory_to_mb(memory)
    if mem is None:
        _err(errors, "request.memory", "BAD_TYPE", "内存值无法解析：%r" % memory)
    elif mem > float(policy["max_memory_mb"]) + 1e-9:
        _err(errors, "request.memory", "MEMORY_LIMIT",
             "请求内存 %s（%.1f MiB）超过策略上限 %s MiB"
             % (memory, mem, policy["max_memory_mb"]))

    try:
        cval = float(cpus)
    except (TypeError, ValueError):
        cval = -1.0
    if cval <= 0:
        _err(errors, "request.cpus", "BAD_TYPE", "CPU 值无法解析：%r" % cpus)
    elif cval > float(policy["max_cpus"]) + 1e-9:
        _err(errors, "request.cpus", "CPU_LIMIT",
             "请求 CPU %s 超过策略上限 %s" % (cpus, policy["max_cpus"]))

    if isinstance(pids, bool) or not isinstance(pids, int) or pids <= 0:
        _err(errors, "request.pids", "BAD_TYPE", "pids 必须是正整数")
    elif pids > int(policy["max_pids"]):
        _err(errors, "request.pids", "PIDS_LIMIT",
             "请求 PID 上限 %s 超过策略上限 %s" % (pids, policy["max_pids"]))

    if not isinstance(image, str) or not image.strip():
        _err(errors, "request.image", "BAD_TYPE", "镜像不能为空")
    elif policy.get("allowed_images") is not None:
        if image not in policy["allowed_images"]:
            _err(errors, "request.image", "IMAGE_NOT_ALLOWED",
                 "镜像 %r 不在策略白名单内：%s"
                 % (image, ", ".join(policy["allowed_images"])))

    if enforce_host and mode == "host" and not policy.get("allow_host", False):
        _err(errors, "request.mode", "HOST_FORBIDDEN",
             "策略禁止 host 执行；--i-understand-host-risk 也不能放宽策略")
    return errors


# ------------------------------------------------------------ 槽位

def _try_lock_fd(fd: int) -> bool:
    """尝试对 fd 指向的 1 个字节加独占锁；已被占用返回 False。"""
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (OSError, ValueError):
        return False


def _unlock_fd(fd: int) -> None:
    try:
        if os.name == "nt":
            import msvcrt
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_UN)
    except (OSError, ValueError):
        pass


class SlotPool:
    """跨进程并发槽位：基于文件字节锁，进程退出/崩溃时由操作系统释放。

    槽位文件只用于加锁，内容是固定的一个字节；owner 元数据是旁路文件，丢失
    不影响正确性，只影响排障可读性。
    """

    def __init__(self, state_dir: str, limit: int):
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 1:
            raise AdmissionError("BAD_SLOTS", "并发槽位必须是正整数", 2)
        self.state_dir = os.path.abspath(state_dir)
        self.limit = limit
        try:
            os.makedirs(self.state_dir, mode=0o700, exist_ok=True)
        except OSError as exc:
            raise AdmissionError("STATE_DIR_ERROR",
                                 "无法创建槽位目录 %s：%s" % (self.state_dir, exc), 5)
        if not os.path.isdir(self.state_dir):
            raise AdmissionError("STATE_DIR_ERROR",
                                 "槽位路径不是目录：%s" % self.state_dir, 5)
        self.paths = [os.path.join(self.state_dir, "slot-%d.lock" % i)
                      for i in range(limit)]
        self.owner_paths = [os.path.join(self.state_dir, "slot-%d.owner.json" % i)
                            for i in range(limit)]
        self.fd: Optional[int] = None
        self.slot: Optional[int] = None
        self.wait_s = 0.0

    def _open_lock(self, path: str) -> Optional[int]:
        try:
            fd = os.open(path, os.O_RDWR | os.O_CREAT, 0o600)
        except OSError:
            return None
        try:
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
                os.fsync(fd)
            os.lseek(fd, 0, os.SEEK_SET)
            return fd
        except OSError:
            try:
                os.close(fd)
            except OSError:
                pass
            return None

    def _write_owner(self, slot: int, owner: Optional[Dict[str, Any]],
                     wait_s: float) -> None:
        if owner is None:
            owner = {}
        rec = dict(owner)
        rec.setdefault("pid", os.getpid())
        rec.setdefault("acquired_at", time.time())
        rec["wait_s"] = round(wait_s, 3)
        rec["limit"] = self.limit
        tmp = self.owner_paths[slot] + ".tmp.%d" % os.getpid()
        try:
            with open(tmp, "w", encoding="utf-8", newline="\n") as fh:
                json.dump(rec, fh, ensure_ascii=False, sort_keys=True)
                fh.write("\n")
            os.replace(tmp, self.owner_paths[slot])
        except OSError:
            try:
                os.unlink(tmp)
            except OSError:
                pass

    def acquire(self, timeout_s: float, budget_deadline: Optional[float] = None,
                owner: Optional[Dict[str, Any]] = None) -> tuple:
        """等待并占用一个槽位；返回 (slot, wait_s)。

        超时抛 AdmissionError：预算先到为 BUDGET_EXHAUSTED，否则 QUEUE_TIMEOUT。
        """
        start = time.monotonic()
        deadline = start + max(0.0, float(timeout_s))
        if budget_deadline is not None:
            deadline = min(deadline, budget_deadline)
        while True:
            for i, path in enumerate(self.paths):
                fd = self._open_lock(path)
                if fd is None:
                    continue
                if _try_lock_fd(fd):
                    self.fd = fd
                    self.slot = i
                    self.wait_s = round(time.monotonic() - start, 3)
                    self._write_owner(i, owner, self.wait_s)
                    return i, self.wait_s
                try:
                    os.close(fd)
                except OSError:
                    pass
            now = time.monotonic()
            if now >= deadline:
                code = ("BUDGET_EXHAUSTED"
                        if budget_deadline is not None and now >= budget_deadline
                        else "QUEUE_TIMEOUT")
                raise AdmissionError(
                    code,
                    "等待并发槽位超时（等待 %.1fs，上限 %.1fs，limit=%d）"
                    % (now - start, max(0.0, deadline - start), self.limit), 5)
            time.sleep(min(0.2, max(0.02, deadline - now)))

    def release(self) -> None:
        if self.fd is None:
            return
        slot = self.slot
        try:
            _unlock_fd(self.fd)
        finally:
            try:
                os.close(self.fd)
            except OSError:
                pass
            self.fd = None
            self.slot = None
        if slot is not None:
            try:
                os.unlink(self.owner_paths[slot])
            except OSError:
                pass


class Budget:
    """从构造时刻开始的墙钟预算。"""

    def __init__(self, limit_s: float):
        self.limit_s = float(limit_s)
        self.started = time.monotonic()

    def used_s(self) -> float:
        return round(time.monotonic() - self.started, 3)

    def remaining_s(self) -> float:
        return max(0.0, self.limit_s - (time.monotonic() - self.started))

    def deadline(self) -> float:
        return self.started + self.limit_s


# ------------------------------------------------------------ CLI

def _force_utf8_io() -> None:
    """让 Windows 控制台/管道输出 UTF-8，避免中文错误信息变成乱码。"""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def _print(obj: Any) -> None:
    text = json.dumps(obj, ensure_ascii=False, indent=2, sort_keys=True)
    try:
        print(text)
    except UnicodeEncodeError:
        enc = getattr(sys.stdout, "encoding", None) or "utf-8"
        print(text.encode(enc, "replace").decode(enc, "replace"))


def main(argv=None) -> int:
    _force_utf8_io()
    ap = argparse.ArgumentParser(
        description="沙箱资源准入策略：并发槽位、排队、预算与资源上限")
    sub = ap.add_subparsers(dest="cmd")
    p_def = sub.add_parser("defaults", help="输出默认策略")
    p_def.add_argument("--json", action="store_true", help="输出 JSON（默认行为）")
    p_val = sub.add_parser("validate", help="校验策略文件")
    p_val.add_argument("--policy", required=True, help="策略 JSON 路径")
    args = ap.parse_args(argv)

    if args.cmd == "defaults" or args.cmd is None:
        policy = default_policy()
        _print({"ok": True, "schema": POLICY_SCHEMA, "policy": policy,
                "sha256": policy_sha256(policy)})
        return 0 if args.cmd == "defaults" else 2

    policy, errors, sha, source = load_policy(args.policy)
    _print({"ok": not errors, "schema": POLICY_SCHEMA, "source": source,
            "sha256": sha, "policy": policy, "errors": errors})
    return 0 if not errors else EXIT_POLICY


if __name__ == "__main__":
    raise SystemExit(main())
