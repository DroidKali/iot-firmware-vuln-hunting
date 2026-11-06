#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""tool_index.py — Phase 0 工具索引（tool-index/1.0）

为什么需要它
------------
atomic-capabilities.md 列出了 54 项原子能力，但“能力”不等于“这台机器上
现在就能调用”。此前 Agent 往往在 Phase 1 解包或 Phase 4 仿真时才撞到
moria / ast-grep / Qiling 缺失，然后临时猜安装命令。这个脚本把“可用性”
提前到 Phase 0，并给出可复现的安装/降级路径。

设计边界
--------
* 只探测工具自身（--version / image inspect / 模块元数据），不读取固件，
  不执行固件，不把目标文件传给被测工具。
* 默认绝不安装。安装是显式动作：--install TOOL --yes；无 --yes 只打印计划。
* 工具与能力清单在 assets/tool-registry.json；新增/调整工具只改配置文件，
  脚本只负责加载、校验、探测与渲染。
* 安装配方固定在注册表里，不抓取网页后执行。网页只作为 docs 链接，避免把
  第三方页面内容当成命令。
* 探测失败不伪造版本：找不到就是 missing；找到但版本命令失败是 degraded，
  仍算 found，但 --strict 会拒绝把它当作“已验证版本”。

用法
----
    python scripts/tool_index.py --out fw-audit/<target>/00-tool-index.json
    python scripts/tool_index.py --registry assets/tool-registry.json --json
    python scripts/tool_index.py --only moria,ast-grep,qiling --json
    python scripts/tool_index.py --require moria --require ast-grep
    python scripts/tool_index.py --docs --only qiling
    python scripts/tool_index.py --install ast-grep --yes

退出码：0 索引生成/要求满足；1 安装失败；2 用法；3 必需工具缺失
（或 --strict 下版本未知）；4 安装被策略拒绝（没有自动配方）。纯标准库。
"""
from __future__ import annotations

import argparse
import glob
import hashlib
import importlib.metadata as md
import importlib.util
import json
import os
import platform
import re
import shlex
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

VERSION = "1.0"
SCHEMA = "tool-index/1.0"
ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_TIMEOUT = 5.0
EXTRA_BIN_DIRS = (
    "~/.local/bin", "~/bin", "~/.cargo/bin",
    "/usr/local/bin", "/opt/homebrew/bin", "/snap/bin",
)
VERSION_RE = re.compile(r"([0-9]+[.][0-9]+(?:[.][0-9]+)?(?:[-+~][0-9A-Za-z.+~-]+)?)")
PHASES = [
    ("P0", "度量与定界"),
    ("P1", "提取与侦察"),
    ("P2", "分层与分配"),
    ("P3", "三层审计"),
    ("P4", "动态验证"),
    ("P5", "门禁与报告"),
]
PHASE_NAMES = dict(PHASES)


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def _install(kind: str, auto: bool = False, argv: Optional[List[str]] = None,
             shell: str = "", docs: str = "", requires: Optional[List[str]] = None,
             notes: str = "") -> Dict[str, Any]:
    return {
        "kind": kind,
        "auto": bool(auto),
        "argv": list(argv or []),
        "shell": shell,
        "docs": docs,
        "requires": list(requires or []),
        "notes": notes,
    }


def _fallback(tools: List[str], impact: str) -> Dict[str, Any]:
    return {"tools": list(tools), "impact": impact}


# ── 工具注册表加载 ───────────────────────────────────────────────────────────
# 工具与能力清单放在 assets/tool-registry.json；新增/调整工具只改那一个文件。
# 本脚本只负责：加载并校验注册表 -> 探测版本 -> 渲染索引/安装计划。
DEFAULT_REGISTRY = os.path.join(ROOT, "assets", "tool-registry.json")
REGISTRY_SCHEMA = "tool-registry/1.0"
TOOL_KINDS = ("cli", "family", "python-module", "python-runtime", "container-image")
TOOL_ID_RE = re.compile(r"^[a-z0-9][a-z0-9._-]*$")
CAP_ID_RE = re.compile(r"^[A-Z][0-9]{1,2}$")
DEFAULT_FALLBACK_IMPACT = "按 atomic-capabilities.md §11 选择替代路径"
REGISTRY_TOP_KEYS = {"schema", "version", "description", "p0_tools", "capabilities", "tools"}
CAP_KEYS = {"id", "name", "phases", "primary", "tools", "manual", "fallback"}
TOOL_KEYS = {
    "id", "kind", "capabilities", "argv", "alternates", "module", "images",
    "prefix", "prefixes", "extra_paths", "required", "recommended", "docs",
    "install", "fallback", "notes", "version_must_contain", "ok_returncodes",
}
INSTALL_KEYS = {"kind", "auto", "argv", "shell", "docs", "requires", "notes"}
FALLBACK_KEYS = {"tools", "impact"}


class RegistryError(Exception):
    """注册表缺失、损坏或不合契约；调用方必须 fail-closed。"""

    def __init__(self, message: str, path: str = "") -> None:
        self.path = path
        prefix = (path + "：") if path else ""
        super().__init__(prefix + message)


def _bad(errors: List[str], path: str, message: str) -> None:
    errors.append(path + ": " + message)


def _unknown_fields(obj: Dict[str, Any], allowed: Any, path: str,
                    errors: List[str]) -> None:
    for key in obj:
        if key not in allowed:
            _bad(errors, path + "." + key, "未知字段（拼写错误或注册表版本不匹配）")


def _field_str(obj: Dict[str, Any], key: str, path: str, errors: List[str],
               *, required: bool = False, allow_empty: bool = False) -> str:
    if key not in obj:
        if required:
            _bad(errors, path + "." + key, "必填")
        return ""
    value = obj[key]
    if not isinstance(value, str):
        _bad(errors, path + "." + key, "必须是字符串")
        return ""
    if not allow_empty and not value.strip():
        _bad(errors, path + "." + key, "不能为空")
        return ""
    return value


def _field_bool(obj: Dict[str, Any], key: str, path: str, errors: List[str],
                *, default: bool = False) -> bool:
    if key not in obj:
        return default
    value = obj[key]
    if not isinstance(value, bool):
        _bad(errors, path + "." + key, "必须是 true/false")
        return default
    return value


def _field_str_list(obj: Dict[str, Any], key: str, path: str, errors: List[str],
                    *, required: bool = False, allow_empty: bool = True) -> List[str]:
    if key not in obj:
        if required:
            _bad(errors, path + "." + key, "必填")
        return []
    value = obj[key]
    if not isinstance(value, list):
        _bad(errors, path + "." + key, "必须是字符串数组")
        return []
    out: List[str] = []
    for i, item in enumerate(value):
        if not isinstance(item, str) or not item.strip():
            _bad(errors, "%s.%s[%d]" % (path, key, i), "必须是非空字符串")
            continue
        out.append(item)
    if not allow_empty and not out:
        _bad(errors, path + "." + key, "至少需要一项")
    return out


def _check_install(raw: Any, path: str, errors: List[str]) -> None:
    if not isinstance(raw, dict):
        _bad(errors, path, "install 必须是对象")
        return
    _unknown_fields(raw, INSTALL_KEYS, path, errors)
    _field_str(raw, "kind", path, errors, required=True)
    _field_bool(raw, "auto", path, errors)
    _field_str_list(raw, "argv", path, errors)
    _field_str(raw, "shell", path, errors, allow_empty=True)
    _field_str(raw, "docs", path, errors, allow_empty=True)
    _field_str_list(raw, "requires", path, errors)
    _field_str(raw, "notes", path, errors, allow_empty=True)


def _check_fallback(raw: Any, path: str, errors: List[str]) -> None:
    if not isinstance(raw, dict):
        _bad(errors, path, "fallback 必须是对象")
        return
    _unknown_fields(raw, FALLBACK_KEYS, path, errors)
    _field_str_list(raw, "tools", path, errors)
    _field_str(raw, "impact", path, errors, allow_empty=True)


def _check_tool(raw: Any, index: int, errors: List[str]) -> str:
    path = "tools[%d]" % index
    if not isinstance(raw, dict):
        _bad(errors, path, "工具必须是对象")
        return ""
    _unknown_fields(raw, TOOL_KEYS, path, errors)
    tid = _field_str(raw, "id", path, errors, required=True)
    if tid and not TOOL_ID_RE.match(tid):
        _bad(errors, path + ".id", "只允许小写字母/数字/点/下划线/连字符，且必须以字母或数字开头")
    kind = _field_str(raw, "kind", path, errors) or "cli"
    if kind not in TOOL_KINDS:
        _bad(errors, path + ".kind", "未知类型 %r；可选：%s" % (kind, ", ".join(TOOL_KINDS)))
    _field_str_list(raw, "capabilities", path, errors)
    argv = _field_str_list(raw, "argv", path, errors)
    alternates = raw.get("alternates", [])
    if not isinstance(alternates, list):
        _bad(errors, path + ".alternates", "必须是字符串数组的数组")
        alternates = []
    for i, cand in enumerate(alternates):
        _field_str_list({"argv": cand}, "argv", "%s.alternates[%d]" % (path, i), errors,
                        required=True, allow_empty=False)
    module = _field_str(raw, "module", path, errors, allow_empty=True)
    images = _field_str_list(raw, "images", path, errors)
    prefix = _field_str(raw, "prefix", path, errors, allow_empty=True)
    prefixes = _field_str_list(raw, "prefixes", path, errors)
    _field_str_list(raw, "extra_paths", path, errors)
    _field_bool(raw, "required", path, errors)
    _field_bool(raw, "recommended", path, errors)
    _field_str(raw, "docs", path, errors, allow_empty=True)
    if raw.get("install") is not None:
        _check_install(raw.get("install"), path + ".install", errors)
    if raw.get("fallback") is not None:
        _check_fallback(raw.get("fallback"), path + ".fallback", errors)
    _field_str(raw, "notes", path, errors, allow_empty=True)
    _field_str(raw, "version_must_contain", path, errors, allow_empty=True)
    codes = raw.get("ok_returncodes", [0])
    if not isinstance(codes, list) or not codes:
        _bad(errors, path + ".ok_returncodes", "必须是非空整数数组")
    else:
        for i, code in enumerate(codes):
            if isinstance(code, bool) or not isinstance(code, int):
                _bad(errors, "%s.ok_returncodes[%d]" % (path, i), "必须是整数")
    if kind == "cli" and not argv and not alternates:
        _bad(errors, path, "cli 类型至少需要 argv 或 alternates")
    if kind == "family" and not prefix and not prefixes:
        _bad(errors, path, "family 类型至少需要 prefix 或 prefixes")
    if kind == "python-module" and not module:
        _bad(errors, path + ".module", "python-module 类型必须给 module")
    if kind == "container-image" and not images:
        _bad(errors, path + ".images", "container-image 类型必须给 images")
    return tid


def _check_capability(raw: Any, index: int, errors: List[str]) -> str:
    path = "capabilities[%d]" % index
    if not isinstance(raw, dict):
        _bad(errors, path, "能力必须是对象")
        return ""
    _unknown_fields(raw, CAP_KEYS, path, errors)
    cid = _field_str(raw, "id", path, errors, required=True)
    if cid and not CAP_ID_RE.match(cid):
        _bad(errors, path + ".id", "能力 ID 形如 R1/E9/C6/F4/B8/D12/N3/H2")
    _field_str(raw, "name", path, errors, required=True)
    phases = _field_str_list(raw, "phases", path, errors, required=True, allow_empty=False)
    for i, pid in enumerate(phases):
        if pid not in ALL_PHASES:
            _bad(errors, "%s.phases[%d]" % (path, i), "未知阶段 %r" % pid)
    primary = _field_str(raw, "primary", path, errors, allow_empty=True)
    tools = _field_str_list(raw, "tools", path, errors)
    manual = _field_str(raw, "manual", path, errors, allow_empty=True)
    _field_str(raw, "fallback", path, errors, allow_empty=True)
    if primary and primary not in tools:
        _bad(errors, path + ".primary", "primary=%r 不在 tools 中" % primary)
    if not tools and not manual:
        _bad(errors, path, "没有 tools 时必须写 manual 替代路径，否则会把缺口误报成可用")
    return cid


def _validate_registry(doc: Any) -> List[str]:
    errors: List[str] = []
    if not isinstance(doc, dict):
        return ["$: 顶层必须是 JSON 对象"]
    _unknown_fields(doc, REGISTRY_TOP_KEYS, "$", errors)
    if doc.get("schema") != REGISTRY_SCHEMA:
        _bad(errors, "$.schema", "必须是 %r，实际 %r" % (REGISTRY_SCHEMA, doc.get("schema")))
    version = _field_str(doc, "version", "$", errors, required=True)
    if version and not re.match(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$", version):
        _bad(errors, "$.version", "建议使用 YYYY-MM-DD，实际 %r" % version)
    _field_str(doc, "description", "$", errors, allow_empty=True)
    p0_tools = _field_str_list(doc, "p0_tools", "$", errors, required=True, allow_empty=False)
    tools_raw = doc.get("tools")
    if not isinstance(tools_raw, list) or not tools_raw:
        _bad(errors, "$.tools", "必须是非空数组")
        tools_raw = []
    tool_ids = set()
    for i, raw in enumerate(tools_raw):
        tid = _check_tool(raw, i, errors)
        if tid:
            if tid in tool_ids:
                _bad(errors, "tools[%d].id" % i, "工具 ID 重复：%r" % tid)
            tool_ids.add(tid)
    caps_raw = doc.get("capabilities")
    if not isinstance(caps_raw, list) or not caps_raw:
        _bad(errors, "$.capabilities", "必须是非空数组")
        caps_raw = []
    cap_ids = set()
    for i, raw in enumerate(caps_raw):
        cid = _check_capability(raw, i, errors)
        if cid:
            if cid in cap_ids:
                _bad(errors, "capabilities[%d].id" % i, "能力 ID 重复：%r" % cid)
            cap_ids.add(cid)
    for i, raw in enumerate(tools_raw):
        if not isinstance(raw, dict):
            continue
        for cid in raw.get("capabilities") or []:
            if cid not in cap_ids:
                _bad(errors, "tools[%d].capabilities" % i, "未定义的能力 %r" % cid)
    for i, raw in enumerate(caps_raw):
        if not isinstance(raw, dict):
            continue
        for tid in raw.get("tools") or []:
            if tid not in tool_ids:
                _bad(errors, "capabilities[%d].tools" % i, "未注册的工具 %r" % tid)
    for i, tid in enumerate(p0_tools):
        if tid not in tool_ids:
            _bad(errors, "$.p0_tools[%d]" % i, "未注册的工具 %r" % tid)
    if "python" not in tool_ids:
        _bad(errors, "$.tools", "缺少 python；Phase 0 无法运行本 skill")
    if "python" not in p0_tools:
        _bad(errors, "$.p0_tools", "必须包含 python")
    return errors


def _norm_tool(raw: Dict[str, Any]) -> Dict[str, Any]:
    docs = raw.get("docs") or ""
    inst_raw = raw.get("install")
    if inst_raw is None:
        install = _install("manual", docs=docs, shell="按官方文档安装",
                           notes="没有固定安装配方")
    else:
        install = _install(
            inst_raw.get("kind") or "manual",
            auto=bool(inst_raw.get("auto")),
            argv=list(inst_raw.get("argv") or []),
            shell=inst_raw.get("shell") or "",
            docs=inst_raw.get("docs") or docs,
            requires=list(inst_raw.get("requires") or []),
            notes=inst_raw.get("notes") or "",
        )
    fb_raw = raw.get("fallback")
    if fb_raw is None:
        fallback = _fallback([], DEFAULT_FALLBACK_IMPACT)
    else:
        fallback = _fallback(fb_raw.get("tools") or [],
                             fb_raw.get("impact") or DEFAULT_FALLBACK_IMPACT)
    return {
        "id": raw["id"],
        "kind": raw.get("kind") or "cli",
        "capabilities": list(raw.get("capabilities") or []),
        "argv": list(raw.get("argv") or []),
        "alternates": [list(a) for a in (raw.get("alternates") or [])],
        "module": raw.get("module") or "",
        "images": list(raw.get("images") or []),
        "prefix": raw.get("prefix") or "",
        "prefixes": list(raw.get("prefixes") or []),
        "extra_paths": list(raw.get("extra_paths") or []),
        "required": bool(raw.get("required")),
        "recommended": bool(raw.get("recommended")),
        "docs": docs,
        "install": install,
        "fallback": fallback,
        "notes": raw.get("notes") or "",
        "version_must_contain": raw.get("version_must_contain") or "",
        "ok_returncodes": list(raw.get("ok_returncodes") or [0]),
    }


def _norm_cap(raw: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": raw["id"],
        "name": raw["name"],
        "phases": list(raw["phases"]),
        "primary": raw.get("primary") or "",
        "tools": list(raw.get("tools") or []),
        "manual": raw.get("manual") or "",
        "fallback": raw.get("fallback") or "",
    }


def _registry_source(path: str) -> str:
    abspath = os.path.abspath(path)
    try:
        rel = os.path.relpath(abspath, ROOT)
    except ValueError:
        rel = abspath
    if rel.startswith(".." + os.sep) or rel == "..":
        rel = abspath
    return rel.replace(os.sep, "/")


def load_registry(path: str = DEFAULT_REGISTRY) -> Dict[str, Any]:
    abspath = os.path.abspath(path)
    try:
        with open(abspath, "rb") as fh:
            raw = fh.read()
    except OSError as exc:
        raise RegistryError("无法读取：%s" % exc, abspath)
    try:
        text = raw.decode("utf-8-sig")
    except UnicodeDecodeError as exc:
        raise RegistryError("不是 UTF-8 文本：%s" % exc, abspath)
    try:
        doc = json.loads(text)
    except json.JSONDecodeError as exc:
        raise RegistryError("JSON 解析失败（第 %d 行第 %d 列）：%s" % (
            exc.lineno, exc.colno, exc.msg), abspath)
    errors = _validate_registry(doc)
    if errors:
        shown = errors[:12]
        more = "\n  ... 另有 %d 条" % (len(errors) - len(shown)) if len(errors) > len(shown) else ""
        raise RegistryError("校验失败：\n  - " + "\n  - ".join(shown) + more, abspath)
    return {
        "path": abspath,
        "source": _registry_source(abspath),
        "sha256": hashlib.sha256(raw).hexdigest(),
        "version": doc["version"],
        "p0_tools": list(doc["p0_tools"]),
        "tools": [_norm_tool(t) for t in doc["tools"]],
        "capabilities": [_norm_cap(c) for c in doc["capabilities"]],
    }


def init_registry(path: str = DEFAULT_REGISTRY) -> None:
    global TOOLS, CAPABILITIES, CAP_BY_ID, TOOL_BY_ID, P0_TOOLS, REGISTRY_META
    reg = load_registry(path)
    TOOLS = reg["tools"]
    CAPABILITIES = reg["capabilities"]
    CAP_BY_ID = {c["id"]: c for c in CAPABILITIES}
    TOOL_BY_ID = {t["id"]: t for t in TOOLS}
    P0_TOOLS = tuple(reg["p0_tools"])
    REGISTRY_META = {
        "schema": REGISTRY_SCHEMA,
        "version": reg["version"],
        "tools": len(TOOLS),
        "source": reg["source"],
        "sha256": reg["sha256"],
    }


TOOLS: List[Dict[str, Any]] = []
CAPABILITIES: List[Dict[str, Any]] = []
CAP_BY_ID: Dict[str, Dict[str, Any]] = {}
TOOL_BY_ID: Dict[str, Dict[str, Any]] = {}
P0_TOOLS: tuple = ()
REGISTRY_META: Dict[str, Any] = {}

ALL_PHASES = [p for p, _ in PHASES]


def _tool_phases(tool: Dict[str, Any]) -> List[str]:
    phases = set()
    if tool["id"] in P0_TOOLS:
        phases.add("P0")
    for cid in tool["capabilities"]:
        cap = CAP_BY_ID.get(cid)
        if cap:
            phases.update(cap["phases"])
    return [p for p in ALL_PHASES if p in phases]


def _first_line(text: str) -> str:
    text = (text or "").strip()
    if not text:
        return ""
    return text.splitlines()[0].strip()


def _parse_version(text: str) -> Optional[str]:
    m = VERSION_RE.search(text or "")
    if not m:
        return None
    return m.group(1).strip(".,;:")


def _fmt_cmd(argv: List[str]) -> str:
    if not argv:
        return ""
    if os.name == "nt":
        return subprocess.list2cmdline(argv)
    return shlex.join(argv)


def _search_dirs() -> List[str]:
    dirs: List[str] = []
    for raw in os.environ.get("PATH", "").split(os.pathsep):
        if raw and raw not in dirs:
            dirs.append(raw)
    for raw in EXTRA_BIN_DIRS:
        path = os.path.expanduser(os.path.expandvars(raw))
        if path and path not in dirs:
            dirs.append(path)
    return dirs


def _is_executable(path: str) -> bool:
    if not os.path.isfile(path):
        return False
    if os.name == "nt":
        return True
    return os.access(path, os.X_OK)


def _which(name: str) -> Optional[str]:
    found = shutil.which(name)
    if found:
        return found
    candidates = [name]
    if os.name == "nt" and not name.lower().endswith((".exe", ".cmd", ".bat")):
        candidates.extend([name + ".exe", name + ".cmd", name + ".bat"])
    for directory in _search_dirs():
        for candidate in candidates:
            path = os.path.join(directory, candidate)
            if _is_executable(path):
                return path
    return None


def _replace_placeholders(argv: List[str]) -> List[str]:
    container = ""
    for name in ("docker", "podman"):
        if _which(name):
            container = name
            break
    out = []
    for item in argv:
        item = item.replace("{root}", ROOT)
        item = item.replace("{container}", container or "docker")
        out.append(item)
    return out


def _spawn(path: str, args: List[str]) -> List[str]:
    if os.name == "nt" and path.lower().endswith((".cmd", ".bat")):
        comspec = os.environ.get("COMSPEC", "cmd.exe")
        return [comspec, "/d", "/s", "/c", subprocess.list2cmdline([path] + list(args))]
    return [path] + list(args)


def _exec(argv: List[str], timeout: float) -> Dict[str, Any]:
    started = time.monotonic()
    kwargs: Dict[str, Any] = {
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "stdin": subprocess.DEVNULL,
        "text": True,
        "encoding": "utf-8",
        "errors": "replace",
        "timeout": timeout,
    }
    if os.name == "nt":
        kwargs["creationflags"] = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        proc = subprocess.run(argv, **kwargs)
        return {
            "returncode": proc.returncode,
            "stdout": proc.stdout or "",
            "stderr": proc.stderr or "",
            "error": None,
            "duration_ms": int((time.monotonic() - started) * 1000),
        }
    except FileNotFoundError:
        return {"returncode": None, "stdout": "", "stderr": "",
                "error": "not-found", "duration_ms": int((time.monotonic() - started) * 1000)}
    except subprocess.TimeoutExpired:
        return {"returncode": None, "stdout": "", "stderr": "",
                "error": "timeout", "duration_ms": int((time.monotonic() - started) * 1000)}
    except OSError as exc:
        return {"returncode": None, "stdout": "", "stderr": "",
                "error": "os-error: " + str(exc), "duration_ms": int((time.monotonic() - started) * 1000)}


def _probe_cli(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    candidates = []
    if tool.get("argv"):
        candidates.append(list(tool["argv"]))
    candidates.extend([list(a) for a in tool.get("alternates") or []])
    if not candidates:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [], "returncode": None, "ok": False,
                          "duration_ms": 0, "error": "no-candidate"}}
    checked = []
    for cand in candidates:
        path = _which(cand[0])
        if not path:
            for raw in tool.get("extra_paths") or []:
                expanded = os.path.expandvars(os.path.expanduser(raw))
                if os.path.basename(expanded) == os.path.basename(cand[0]) and os.path.isfile(expanded):
                    path = expanded
                    break
        if not path:
            checked.append(cand)
            continue
        result = _exec(_spawn(path, cand[1:]), timeout)
        text = (result.get("stdout") or "") + ((result.get("stderr") or ""))
        must = (tool.get("version_must_contain") or "").lower()
        if must and must not in text.lower():
            checked.append(cand)
            continue
        version = _parse_version(text)
        ok = result.get("returncode") in (tool.get("ok_returncodes") or [0])
        status = "available" if ok else "degraded"
        return {
            "found": True,
            "status": status,
            "version": version,
            "path": path,
            "probe": {"argv": cand, "returncode": result.get("returncode"), "ok": ok,
                      "duration_ms": result.get("duration_ms"), "error": result.get("error")},
        }
    return {"found": False, "status": "missing", "version": None, "path": None,
            "probe": {"argv": checked[0] if checked else candidates[0], "returncode": None,
                      "ok": False, "duration_ms": 0, "error": "not-found"}}


def _probe_family(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    prefixes = tool.get("prefixes") or ([tool["prefix"]] if tool.get("prefix") else [])
    names: List[str] = []
    for directory in _search_dirs():
        for prefix in prefixes:
            for path in glob.glob(os.path.join(directory, prefix + "*")):
                if _is_executable(path):
                    names.append(path)
    names = sorted(set(names), key=lambda p: os.path.basename(p).lower())
    if not names:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [], "returncode": None, "ok": False,
                          "duration_ms": 0, "error": "not-found"}}
    versions = []
    last = None
    for path in names:
        result = _exec(_spawn(path, ["--version"]), timeout)
        last = result
        text = (result.get("stdout") or "") + (result.get("stderr") or "")
        ver = _parse_version(text)
        if ver and ver not in versions:
            versions.append(ver)
    return {
        "found": True,
        "status": "available" if versions else "degraded",
        "version": ", ".join(versions) if versions else None,
        "path": names[0],
        "probe": {"argv": [names[0], "--version"],
                  "returncode": (last or {}).get("returncode"),
                  "ok": bool(versions),
                  "duration_ms": (last or {}).get("duration_ms"),
                  "error": (last or {}).get("error")},
    }


def _probe_python_module(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    module = tool.get("module") or tool["id"]
    try:
        spec = importlib.util.find_spec(module)
    except (ImportError, ValueError, ModuleNotFoundError):
        spec = None
    if spec is None:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [sys.executable, "-c", "import " + module],
                          "returncode": None, "ok": False, "duration_ms": 0,
                          "error": "module-not-found"}}
    version = None
    try:
        version = md.version(module)
    except (md.PackageNotFoundError, ValueError):
        version = None
    return {
        "found": True,
        "status": "available" if version else "degraded",
        "version": version,
        "path": getattr(spec, "origin", None),
        "probe": {"argv": [sys.executable, "-c", "import " + module],
                  "returncode": 0, "ok": bool(version), "duration_ms": 0, "error": None},
    }


def _probe_python_runtime(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    return {
        "found": True,
        "status": "available",
        "version": platform.python_version(),
        "path": sys.executable,
        "probe": {"argv": [sys.executable, "--version"], "returncode": 0, "ok": True,
                  "duration_ms": 0, "error": None},
    }


def _probe_container_image(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    runtime = None
    for name in ("docker", "podman"):
        if _which(name):
            runtime = name
            break
    if not runtime:
        return {"found": False, "status": "missing", "version": None, "path": None,
                "probe": {"argv": [tool.get("images", ["image"])[0], "image", "inspect"],
                          "returncode": None, "ok": False, "duration_ms": 0,
                          "error": "container-runtime-not-found"}}
    last = None
    for image in tool.get("images") or []:
        result = _exec([runtime, "image", "inspect", "--format", "{{.Id}}", image], timeout)
        last = result
        if result.get("returncode") == 0:
            return {
                "found": True,
                "status": "available",
                "version": image,
                "path": runtime + " image " + image,
                "probe": {"argv": [runtime, "image", "inspect", image],
                          "returncode": 0, "ok": True,
                          "duration_ms": result.get("duration_ms"), "error": None},
            }
    image = (tool.get("images") or [tool["id"]])[0]
    return {"found": False, "status": "missing", "version": None, "path": runtime,
            "probe": {"argv": [runtime, "image", "inspect", image],
                      "returncode": (last or {}).get("returncode"),
                      "ok": False, "duration_ms": (last or {}).get("duration_ms"),
                      "error": "image-not-found"}}


def probe_tool(tool: Dict[str, Any], timeout: float) -> Dict[str, Any]:
    kind = tool.get("kind")
    if kind == "python-runtime":
        return _probe_python_runtime(tool, timeout)
    if kind == "python-module":
        return _probe_python_module(tool, timeout)
    if kind == "container-image":
        return _probe_container_image(tool, timeout)
    if kind == "family":
        return _probe_family(tool, timeout)
    return _probe_cli(tool, timeout)


def _selected_tools(only: Optional[List[str]], profile: str) -> List[Dict[str, Any]]:
    wanted = set(only or [])
    phases = set(ALL_PHASES if profile == "all" else {
        "phase0": ["P0"], "extract": ["P1"], "static": ["P3"], "dynamic": ["P4"],
    }[profile])
    out = []
    for tool in TOOLS:
        if wanted and tool["id"] not in wanted:
            continue
        if profile != "all" and not (set(_tool_phases(tool)) & phases):
            continue
        out.append(tool)
    return out


def build_index(only: Optional[List[str]] = None, profile: str = "all",
                timeout: float = DEFAULT_TIMEOUT) -> Dict[str, Any]:
    selected = _selected_tools(only, profile)
    rows = []
    for tool in selected:
        row = dict(tool)
        row.update(probe_tool(tool, timeout))
        row["phases"] = _tool_phases(tool)
        rows.append(row)
    rows_by_id = {r["id"]: r for r in rows}
    selected_ids = set(rows_by_id)
    caps = []
    for cap in CAPABILITIES:
        if profile != "all":
            phase_set = {"phase0": ["P0"], "extract": ["P1"],
                         "static": ["P3"], "dynamic": ["P4"]}[profile]
            if not (set(cap["phases"]) & set(phase_set)):
                continue
        if only and cap["tools"] and not (set(cap["tools"]) & set(only)):
            continue
        if not cap["tools"] and not cap.get("manual"):
            continue
        available_tools = [t for t in cap["tools"]
                           if t in selected_ids and rows_by_id[t].get("found")]
        missing_tools = [t for t in cap["tools"]
                         if t in selected_ids and not rows_by_id[t].get("found")]
        if not cap["tools"]:
            status = "manual"
        elif cap.get("primary") and rows_by_id.get(cap["primary"], {}).get("found"):
            status = "available"
        elif available_tools:
            status = "degraded"
        else:
            status = "missing"
        caps.append({
            "id": cap["id"],
            "name": cap["name"],
            "phases": list(cap["phases"]),
            "status": status,
            "primary": cap.get("primary") or "",
            "available_tools": available_tools,
            "missing_tools": missing_tools,
            "manual": cap.get("manual", ""),
            "fallback": cap.get("fallback", ""),
        })
    phases_out = []
    if profile == "all":
        phase_ids = ["P0", "P1", "P3", "P4"]
    else:
        phase_ids = {"phase0": ["P0"], "extract": ["P1"],
                     "static": ["P3"], "dynamic": ["P4"]}[profile]
    for pid in phase_ids:
        if pid == "P0":
            base = [rows_by_id[t] for t in P0_TOOLS if t in rows_by_id]
            p0_found = [row["id"] for row in base if row.get("found")]
            p0_missing = [row["id"] for row in base if not row.get("found")]
            py = next((row for row in base if row["id"] == "python"), None)
            file_row = next((row for row in base if row["id"] == "file"), None)
            if py is not None and not py.get("found"):
                pstatus = "blocked"
            elif py is not None and file_row is not None and file_row.get("found"):
                pstatus = "ready"
            elif py is not None:
                pstatus = "partial"
            else:
                pstatus = "n/a"
            phases_out.append({
                "id": pid,
                "name": PHASE_NAMES[pid],
                "status": pstatus,
                "available_tools": sorted(p0_found),
                "missing_tools": sorted(p0_missing),
            })
            continue
        phase_caps = [c for c in caps if pid in c["phases"]
                      and c["status"] != "manual"
                      and (not only or ((set(c["available_tools"])
                                         | set(c["missing_tools"])) & set(only)))]
        if not phase_caps:
            pstatus = "n/a"
        elif all(c["status"] == "available" for c in phase_caps):
            pstatus = "ready"
        elif any(c["status"] in ("available", "degraded") for c in phase_caps):
            pstatus = "partial"
        else:
            pstatus = "blocked"
        phases_out.append({
            "id": pid,
            "name": PHASE_NAMES[pid],
            "status": pstatus,
            "available_tools": sorted({t for c in phase_caps for t in c["available_tools"]}),
            "missing_tools": sorted({t for c in phase_caps for t in c["missing_tools"]}),
        })
    summary = {
        "total": len(rows),
        "available": sum(1 for r in rows if r["status"] == "available"),
        "degraded": sum(1 for r in rows if r["status"] == "degraded"),
        "missing": sum(1 for r in rows if r["status"] == "missing"),
    }
    return {
        "schema": SCHEMA,
        "tool_version": VERSION,
        "generated_at": utc_now(),
        "host": {
            "os": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
            "is_windows": os.name == "nt",
        },
        "registry": dict(REGISTRY_META),
        "profile": profile,
        "summary": summary,
        "tools": rows,
        "capabilities": caps,
        "phases": phases_out,
        "notes": "只做版本探测，不读取固件；安装必须显式 --install TOOL --yes。",
    }


def _install_hint(row: Dict[str, Any]) -> str:
    inst = row.get("install") or {}
    if inst.get("argv"):
        return _fmt_cmd(_replace_placeholders(inst["argv"]))
    if inst.get("shell"):
        return inst["shell"]
    return "见官方文档"


def render_text(index: Dict[str, Any]) -> str:
    s = index["summary"]
    lines = [
        "[工具索引] %d 项：可用 %d / 降级 %d / 缺失 %d" % (
            s["total"], s["available"], s["degraded"], s["missing"]),
        "主机：%s %s %s / Python %s" % (
            index["host"]["os"], index["host"]["release"],
            index["host"]["machine"], index["host"]["python"]),
        "生成：%s（profile=%s）" % (index["generated_at"], index["profile"]),
    ]
    if s["total"] < index["registry"]["tools"]:
        lines.append("注意：本次只探测 %d/%d 项；缺失与阶段结论只针对选中工具，全量请用 --profile all。" % (
            s["total"], index["registry"]["tools"]))
    lines.extend([
        "",
        "阶段就绪度：",
    ])
    for phase in index["phases"]:
        lines.append("  %s %-8s %-8s 缺：%s" % (
            phase["id"], phase["name"], phase["status"],
            ", ".join(phase["missing_tools"][:10]) or "无"))
    missing = [t for t in index["tools"] if not t.get("found")]
    if missing:
        lines.extend(["", "缺失工具（安装/降级）："])
        for row in missing:
            lines.append("  - %s：%s" % (row["id"], row.get("notes") or row["kind"]))
            lines.append("    安装：" + _install_hint(row))
            docs = (row.get("install") or {}).get("docs") or row.get("docs") or ""
            if docs:
                lines.append("    文档：" + docs)
            fb = row.get("fallback") or {}
            if fb.get("tools") or fb.get("impact"):
                lines.append("    降级：%s；%s" % (
                    ", ".join(fb.get("tools") or []) or "无等价工具",
                    fb.get("impact") or ""))
    weak = [c for c in index["capabilities"] if c["status"] in ("degraded", "missing")]
    if weak:
        lines.extend(["", "能力缺口："])
        for cap in weak:
            lines.append("  %s %-22s %-8s 缺：%s；替代：%s" % (
                cap["id"], cap["name"], cap["status"],
                ", ".join(cap["missing_tools"]) or "无",
                cap["fallback"] or cap["manual"] or "无"))
    lines.extend([
        "",
        "下一步：",
        "  python scripts/tool_index.py --out fw-audit/<target>/00-tool-index.json",
        "  python scripts/tool_index.py --require moria --require ast-grep（按目标选路后）",
        "  python scripts/tool_index.py --install <tool> --yes（显式安装；无 --yes 只打印计划）",
    ])
    return chr(10).join(lines)


def _parse_ids(value: Optional[str]) -> List[str]:
    if not value:
        return []
    return [x.strip() for x in value.split(",") if x.strip()]


def _write_json(path: str, obj: Dict[str, Any]) -> int:
    parent = os.path.dirname(os.path.abspath(path))
    if parent and not os.path.isdir(parent):
        try:
            os.makedirs(parent, exist_ok=True)
        except OSError as exc:
            print("[error] 无法创建输出目录：%s" % exc, file=sys.stderr)
            return 2
    try:
        with open(path, "w", encoding="utf-8", newline=chr(10)) as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2)
            fh.write(chr(10))
    except OSError as exc:
        print("[error] 无法写入 %s：%s" % (path, exc), file=sys.stderr)
        return 2
    return 0


def _require_tools(index: Dict[str, Any], ids: List[str], strict: bool) -> List[str]:
    by_id = {t["id"]: t for t in index["tools"]}
    problems = []
    for tid in ids:
        row = by_id.get(tid)
        if row is None:
            problems.append(tid + "（未包含在本次索引中）")
        elif not row.get("found"):
            problems.append(tid + "（缺失）")
        elif strict and row.get("status") != "available":
            problems.append(tid + "（版本未知/探测降级）")
    return problems


def _precheck_requires(install: Dict[str, Any]) -> List[str]:
    missing = []
    for req in install.get("requires") or []:
        if req == "c++":
            if not (_which("c++") or _which("g++")):
                missing.append("c++/g++")
        elif not _which(req):
            missing.append(req)
    return missing


def run_install(ids: List[str], assume_yes: bool) -> int:
    failures = []
    planned = False
    for tid in ids:
        tool = TOOL_BY_ID.get(tid)
        if tool is None:
            print("[error] 未知工具：%s" % tid, file=sys.stderr)
            return 2
        probe = probe_tool(tool, DEFAULT_TIMEOUT)
        if probe.get("found"):
            print("[skip] %s 已可用：%s" % (tid, probe.get("version") or "版本未知"))
            continue
        inst = tool.get("install") or {}
        argv = _replace_placeholders(inst.get("argv") or [])
        docs = inst.get("docs") or tool.get("docs") or ""
        if not argv:
            print("[manual] %s 没有可自动执行的固定配方，按官方文档安装：" % tid)
            if inst.get("shell"):
                print("  " + inst["shell"])
            if docs:
                print("  " + docs)
            failures.append(tid)
            continue
        if not inst.get("auto"):
            print("[manual] %s 的安装被标记为人工确认；不会自动执行：" % tid)
            print("  " + _fmt_cmd(argv))
            if docs:
                print("  " + docs)
            failures.append(tid)
            continue
        missing = _precheck_requires(inst)
        if missing:
            print("[miss] %s 需要先安装：%s" % (tid, ", ".join(missing)))
            failures.append(tid)
            continue
        print("[install] " + _fmt_cmd(argv))
        if not assume_yes:
            print("[plan] 未加 --yes，未执行。")
            planned = True
            continue
        result = _exec(argv, 600.0)
        out = ((result.get("stdout") or "") + (result.get("stderr") or "")).strip()
        if result.get("returncode") != 0:
            print("[fail] %s rc=%s %s" % (tid, result.get("returncode"), out[-1200:]))
            failures.append(tid)
        else:
            print("[ok] %s 安装命令返回 0" % tid)
    if planned:
        return 2
    return 0 if not failures else 1


def _force_utf8_io() -> None:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass


def main(argv: Optional[List[str]] = None) -> int:
    _force_utf8_io()
    ap = argparse.ArgumentParser(
        description="Phase 0 工具索引：探测 moria/ast-grep/qiling 等实现，给出安装/降级路径")
    ap.add_argument("--out", help="把 tool-index/1.0 写到这个 JSON 路径")
    ap.add_argument("--registry", default=DEFAULT_REGISTRY,
                    help="工具注册表 JSON（默认 assets/tool-registry.json）")
    ap.add_argument("--json", action="store_true", help="把索引 JSON 打到 stdout")
    ap.add_argument("--only", help="只探测这些工具（逗号分隔）")
    ap.add_argument("--require", action="append", default=[], help="必需工具；缺失退出 3（可重复）")
    ap.add_argument("--profile", default="all",
                    choices=["all", "phase0", "extract", "static", "dynamic"],
                    help="按阶段筛选：phase0/extract/static/dynamic/all")
    ap.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT,
                    help="单次版本探测超时秒数（默认 3）")
    ap.add_argument("--strict", action="store_true", help="--require 的工具必须版本已知")
    ap.add_argument("--docs", action="store_true", help="只打印官方文档链接")
    ap.add_argument("--install", action="append", default=[], help="显式安装工具（可重复）")
    ap.add_argument("--yes", action="store_true", help="与 --install 连用，确认执行安装命令")
    ap.add_argument("--quiet", action="store_true", help="不打印文本摘要")
    args = ap.parse_args(argv)
    if args.timeout < 0.5:
        args.timeout = 0.5
    if args.timeout > 30:
        args.timeout = 30
    try:
        init_registry(args.registry)
    except RegistryError as exc:
        print("[error] 工具注册表不可用：%s" % exc, file=sys.stderr)
        return 2
    only = _parse_ids(args.only)
    unknown = [x for x in only if x not in TOOL_BY_ID]
    if unknown:
        print("[error] 未知工具：%s（可用：%s）" % (", ".join(unknown), ", ".join(TOOL_BY_ID)), file=sys.stderr)
        return 2
    require_ids = []
    for raw in args.require:
        require_ids.extend(_parse_ids(raw))
    unknown = [x for x in require_ids if x not in TOOL_BY_ID]
    if unknown:
        print("[error] 未知工具：%s" % ", ".join(unknown), file=sys.stderr)
        return 2
    install_ids = []
    for raw in args.install:
        install_ids.extend(_parse_ids(raw))
    unknown = [x for x in install_ids if x not in TOOL_BY_ID]
    if unknown:
        print("[error] 未知工具：%s" % ", ".join(unknown), file=sys.stderr)
        return 2
    if args.docs:
        for tid in only or list(TOOL_BY_ID):
            tool = TOOL_BY_ID[tid]
            print("%s	%s" % (tid, tool.get("docs") or (tool.get("install") or {}).get("docs") or ""))
        return 0
    if install_ids:
        return run_install(install_ids, args.yes)
    index = build_index(only or None, args.profile, args.timeout)
    if args.out:
        rc = _write_json(args.out, index)
        if rc:
            return rc
    if args.json:
        print(json.dumps(index, ensure_ascii=False, indent=2))
    elif not args.quiet:
        print(render_text(index))
    if require_ids:
        problems = _require_tools(index, require_ids, args.strict)
        if problems:
            print("[error] 必需工具不满足：%s" % "; ".join(problems), file=sys.stderr)
            return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
