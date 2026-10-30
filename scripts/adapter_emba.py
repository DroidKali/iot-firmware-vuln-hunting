#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EMBA 离线适配器：把已有 EMBA 日志解析成黑板可消费的结构化观察（ROADMAP M3）。

设计边界
--------
* 只读解析，不启动 EMBA、Qiling、QEMU，也不执行固件里的任何字节；
* 同一份日志重复解析，输出字节稳定：没有生成时间、ID 由内容与 run_id 派生；
* 三类观察严格分型，避免把「静态看到服务」升级成「进程真的跑起来」：
    - service        静态发现（L15/S09 行），value.observation = "static-discovery"
    - runtime-process 仿真进程实际产生输出（S115），value.observation = "runtime-process"
    - port-response  系统仿真中端口有响应（L10），value.observation = "port-response"
* P99 的 ELF 落成 elf，PE32 落成 file；L10 没有开放端口时不生成 port-response；
  F50 的 user_emulation_state 按成功用户态仿真计数解释，不当作状态字符串；
* 缺字段、版本不符、坏行、固件哈希不符都返回结构化错误，不静默跳过；
* 缺少可选日志时状态为 partial；--require 指定的产物缺失则 failed，并在
  requirements.missing 中列出，绝不伪造观察。

退出码：0 parsed 或 partial；1 failed；2 用法/IO；3 --strict 且 partial。
纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import csv
import hashlib
import json
import os
import re
import sys
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Sequence, Set, Tuple

try:
    from contracts import summarize as _contract_summary
    from contracts import validate_emba_import as _validate_emba_import
except Exception:  # pragma: no cover - 单独拷走时不做自检
    _contract_summary = None
    _validate_emba_import = None

VERSION = "1.1"
SCHEMA = "emba-import/1.0"
HEX64 = re.compile(r"^[0-9a-f]{64}$")
ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[A-Za-z]")
S115_RE = re.compile(
    r"\[\+\]\s+Emulated binary\s+(.+?)\s+generated output in\s+(.+?)\s*$")
PORT_RE = re.compile(r"\b(\d{1,5})/(tcp|udp)\b", re.IGNORECASE)

F50_KEYS = {
    "firmware_vendor", "firmware_version", "device", "fw_path", "emba_command",
    "emba_version", "architecture_verified", "architecture_unverified",
    "os_verified", "files", "directories", "entropy_value", "shell_scripts",
    "shell_script_vulns", "cve_counter", "cve_critical", "cve_high",
    "cve_medium", "cve_low", "exploits", "user_emulation_state",
    "system_emulation_state",
}

ARCH_ALIASES = {
    "mips": "mips", "mips32": "mips", "mips64": "mips",
    "mipsel": "mipsel", "mipsle": "mipsel", "mips64el": "mipsel",
    "arm": "arm", "arm32": "arm", "armhf": "arm", "armel": "arm",
    "arm64": "arm64", "aarch64": "arm64",
    "x86": "x86", "i386": "x86", "i486": "x86", "i586": "x86", "i686": "x86",
    "x86_64": "x86_64", "x86-64": "x86_64", "amd64": "x86_64",
    "riscv": "riscv64", "riscv64": "riscv64",
}

P99_FIELDS = ("source_module", "path", "class", "data", "machine",
              "flags_cnt", "arch_guessed", "file_output", "md5")
# EMBA 的 S09 表头第 4 列写作 version_rule，但写入点实际放的是
# lAPP_NAME（modules/S09_firmware_base_version_check.sh:477）；这里按真实
# 语义命名为 app_name，避免把产品名误读成版本规则。
S09_FIELDS = ("module", "binary", "rule_id", "app_name",
              "version_detected", "csv_rule", "license", "mode")
# --require 允许显式要求的可选产物角色；F50 永远必需，不在其中。
ARTIFACT_ROLES = ("p99", "s09", "l15", "l10", "s115")


class AdapterError(Exception):
    """解析器无法继续；code 是机器可读原因。"""

    def __init__(self, code: str, message: str, path: str = "",
                 exit_code: int = 1) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.path = path
        self.exit_code = exit_code


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True,
                      separators=(",", ":"))


def short_hash(value: Any) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()[:12]


def file_sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def mtime_iso(path: str) -> str:
    return datetime.fromtimestamp(os.path.getmtime(path), timezone.utc) \
        .isoformat(timespec="seconds").replace("+00:00", "Z")


def rel_path(path: str, root: str) -> str:
    try:
        rel = os.path.relpath(path, root)
    except ValueError:
        return os.path.abspath(path)
    if rel.startswith(".."):
        return os.path.abspath(path).replace("\\", "/")
    return rel.replace("\\", "/")


def _norm_value(value: Any) -> str:
    if value is None:
        return ""
    text = str(value).strip()
    if len(text) >= 2 and text[0] == text[-1] == '"':
        text = text[1:-1].strip()
    if text.upper() in ("NA", "N/A", "NONE", "NULL", "-"):
        return ""
    return text


def _to_int(value: Any) -> Optional[int]:
    text = _norm_value(value).replace(",", "")
    if not text:
        return None
    if re.fullmatch(r"-?\d+", text):
        try:
            return int(text)
        except ValueError:
            return None
    return None


def state_tokens(value: Any) -> Set[str]:
    """把 F50 的 system_emulation_state 拆成 token；下划线归一成空格。"""
    text = _norm_value(value).lower()
    if not text:
        return set()
    return {t.strip().replace("_", " ")
            for t in re.split(r"[;,]+", text) if t.strip()}


def raw_state_tokens(value: Any) -> List[str]:
    """保留 F50 原始 token 的大小写与下划线，用于原样记录标志位。"""
    text = _norm_value(value)
    if not text:
        return []
    return [t.strip() for t in re.split(r"[;,]+", text) if t.strip()]


def system_booted(value: Any) -> bool:
    """只有明确的 booted 才算启动；not booted / not_booted 一律否。"""
    tokens = state_tokens(value)
    if any(t.startswith("not booted") for t in tokens):
        return False
    return "booted" in tokens


def norm_arch(value: Any) -> str:
    text = _norm_value(value).lower()
    if not text:
        return ""
    token = re.split(r"[\s,;/()]+", text)[0]
    return ARCH_ALIASES.get(token, token)


def norm_version(value: Any) -> str:
    text = _norm_value(value)
    if not text:
        return ""
    token = text.split()[0]
    return token[1:] if token.lower().startswith("v") else token


def _read_text(path: str) -> str:
    with open(path, "r", encoding="utf-8-sig", errors="strict") as fh:
        return fh.read()


def _read_csv(path: str) -> List[List[str]]:
    with open(path, "r", encoding="utf-8-sig", errors="strict", newline="") as fh:
        return [row for row in csv.reader(fh, delimiter=";")]


def _is_header(row: Sequence[str], needles: Sequence[str]) -> bool:
    joined = " ".join(_norm_value(x).lower() for x in row)
    return any(n in joined for n in needles)


def _header_map(row: Sequence[str], fields: Sequence[str]) -> Dict[str, int]:
    mapping: Dict[str, int] = {}
    lowered = [_norm_value(x).lower() for x in row]
    for field in fields:
        tokens = [t for t in field.split("_") if t]
        for i, name in enumerate(lowered):
            if all(t in name for t in tokens):
                mapping[field] = i
                break
        # S09/L15 的历史表头把 app_name 写成 version_rule。
        if field == "app_name" and "app_name" not in mapping:
            for i, name in enumerate(lowered):
                if "version_rule" in name or ("app" in name and "name" in name):
                    mapping["app_name"] = i
                    break
        # 同一表头把 static/emulation 这一列当作类型列，列名里没有 "mode"。
        if field == "mode" and "mode" not in mapping:
            for i, name in enumerate(lowered):
                if "static/emulation" in name or name in ("type", "mode"):
                    mapping["mode"] = i
                    break
    # 首列没有表头文字时按位置兜底
    if "module" in fields and "module" not in mapping:
        mapping["module"] = 0
    return mapping


class Observations:
    """一次解析的事实/证据收集器；所有 ID 由内容与 run_id 决定。"""

    def __init__(self, run_id: str, firmware_sha256: str,
                 tool_version: str, logs_root: str) -> None:
        self.run_id = run_id
        self.firmware_sha256 = firmware_sha256
        self.tool_version = tool_version or "unknown"
        self.logs_root = logs_root
        self.facts: List[Dict[str, Any]] = []
        self.evidence: List[Dict[str, Any]] = []
        self.errors: List[Dict[str, Any]] = []
        self.limitations: List[str] = []
        self.inputs: List[Dict[str, Any]] = []
        self.fatal = False
        self._fact_ids: Set[str] = set()
        self._evidence_ids: Set[str] = set()
        self._input_roles: Set[Tuple[str, str]] = set()

    # ── 错误与输入 ──────────────────────────────────────────────────────────
    def error(self, code: str, message: str, path: str = "",
              line: Optional[int] = None, fatal: bool = False) -> None:
        row: Dict[str, Any] = {"code": code, "message": message}
        if path:
            row["path"] = path
        if line is not None:
            row["line"] = int(line)
        self.errors.append(row)
        if fatal:
            self.fatal = True

    def limit(self, text: str) -> None:
        if text and text not in self.limitations:
            self.limitations.append(text)

    def add_input(self, role: str, path: str, root: Optional[str] = None) -> Dict[str, Any]:
        rel = rel_path(path, root or self.logs_root)
        key = (role, rel)
        if key in self._input_roles:
            for row in self.inputs:
                if row.get("role") == role and row.get("path") == rel:
                    return row
        row = {"role": role, "path": rel,
               "sha256": file_sha256(path), "size": os.path.getsize(path)}
        self.inputs.append(row)
        self._input_roles.add(key)
        return row

    # ── 事实与证据 ──────────────────────────────────────────────────────────
    def add_fact(self, fact_type: str, identity: Dict[str, Any],
                 value: Dict[str, Any], evidence_type: str,
                 rel_file: str, line: Optional[int],
                 source_type: str = "tool-report",
                 event: Optional[Dict[str, Any]] = None,
                 fact_source: Optional[Dict[str, Any]] = None,
                 evidence_status: str = "parsed") -> str:
        key = {"kind": fact_type, "run_id": self.run_id,
               "file": rel_file, "line": line, "identity": identity}
        fid = "F-EMBA-" + short_hash({"fact": key})
        eid = "E-EMBA-" + short_hash({"evidence": key})
        if fid in self._fact_ids:
            self.error("DUPLICATE_FACT_ID", f"同一观察被重复生成：{fid}",
                       rel_file, line)
            return fid
        if eid in self._evidence_ids:
            self.error("DUPLICATE_EVIDENCE_ID", f"同一证据被重复生成：{eid}",
                       rel_file, line)
            return fid
        artifact = None
        full = os.path.join(self.logs_root, rel_file.replace("/", os.sep))
        if os.path.isfile(full):
            artifact = {"path": rel_file, "sha256": file_sha256(full),
                        "size": os.path.getsize(full)}
            observed = mtime_iso(full)
        else:  # 理论上不会发生；不为缺失文件编造 fingerprint
            observed = "1970-01-01T00:00:00Z"
            self.error("MISSING_ARTIFACT", f"证据文件不存在：{rel_file}",
                       rel_file, line)
        src = {"type": source_type, "tool": "emba",
               "tool_version": self.tool_version, "path": rel_file}
        if line is not None:
            src["line"] = line
        ev: Dict[str, Any] = {
            "schema": "evidence/1.1", "evidence_id": eid,
            "run_id": self.run_id, "firmware_sha256": self.firmware_sha256,
            "type": evidence_type, "observed_at": observed,
            "status": evidence_status, "source": src,
        }
        if artifact:
            ev["artifact"] = artifact
        if event is not None:
            ev["event"] = event
        if evidence_status != "parsed":
            ev["limitations"] = ["该观察来自不完整的解析结果"]
        fact_src = dict(fact_source or {"type": source_type, "tool": "emba",
                                        "path": rel_file})
        fact_src.setdefault("tool", "emba")
        if line is not None:
            fact_src.setdefault("location", f"line {line}")
        fact = {
            "schema": "fact/1.0", "fact_id": fid, "run_id": self.run_id,
            "firmware_sha256": self.firmware_sha256, "type": fact_type,
            "value": value, "evidence_refs": [eid],
            "source": fact_src, "observed_at": observed,
            "scope": {"source": fact_source.get("tool", "emba") if fact_source else "emba"},
        }
        self.facts.append(fact)
        self.evidence.append(ev)
        self._fact_ids.add(fid)
        self._evidence_ids.add(eid)
        return fid


# ── 各日志解析器 ─────────────────────────────────────────────────────────────

def parse_f50(obs: Observations, path: str) -> Dict[str, str]:
    rel = rel_path(path, obs.logs_root)
    obs.add_input("f50", path)
    try:
        rows = _read_csv(path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        obs.error("F50_CORRUPT", f"无法读取 F50 CSV：{exc}", rel, fatal=True)
        return {}
    data: Dict[str, str] = {}
    for lineno, row in enumerate(rows, 1):
        if not row or all(not _norm_value(c) for c in row):
            continue
        key = _norm_value(row[0])
        if not key or key.startswith("#"):
            continue
        if len(row) == 1 and "=" in key:
            key, _, raw = key.partition("=")
            key = _norm_value(key)
            value = _norm_value(raw)
        elif len(row) >= 2:
            # EMBA 的 write_csv_log() 固定用 NA 补齐尾部列（helpers_emba_print.sh:333）。
            # 这些 NA 是列填充，不是值的一部分；但 system_emulation_state 这类
            # 值本身可能含分号（如 booted;IP_DET），所以要保留非空单元格。
            cells = [c for c in (_norm_value(x) for x in row[1:]) if c]
            value = ";".join(cells)
        else:
            obs.error("PARSE_ERROR", "F50 行列数不足（需要 key;value）", rel, lineno)
            continue
        if not key:
            obs.error("PARSE_ERROR", "F50 行缺少键名", rel, lineno)
            continue
        data[key.lower()] = value
    if not data:
        obs.error("F50_EMPTY", "F50 CSV 没有任何可解析的键值", rel, fatal=True)
        return {}
    if not (set(data) & F50_KEYS):
        obs.error("F50_CORRUPT", "F50 CSV 不含任何已知 EMBA 字段", rel, fatal=True)
        return {}
    return data


def emit_f50_facts(obs: Observations, data: Dict[str, str]) -> None:
    rel = "csv_logs/f50_base_aggregator.csv"
    vendor = data.get("firmware_vendor", "")
    product = data.get("device", "") or data.get("firmware_device", "")
    version = data.get("firmware_version", "")
    arch_verified = data.get("architecture_verified", "")
    arch_unverified = data.get("architecture_unverified", "")
    if not any((vendor, product, version, arch_verified, arch_unverified)):
        obs.error("F50_EMPTY", "F50 的固件元数据字段全为空", rel, fatal=True)
        return
    fw_value: Dict[str, Any] = {
        "observation": "static-discovery",
        "vendor": vendor, "product": product, "version": version,
        "verified_arch": norm_arch(arch_verified),
        "unverified_arch": norm_arch(arch_unverified),
        "fw_path": data.get("fw_path", ""),
        "emba_command": data.get("emba_command", ""),
        "files": _to_int(data.get("files")),
        "directories": _to_int(data.get("directories")),
        "entropy": data.get("entropy_value", ""),
        "shell_scripts": _to_int(data.get("shell_scripts")),
        "shell_script_vulns": _to_int(data.get("shell_script_vulns")),
        "cves": {k: _to_int(data.get(k)) for k in
                 ("cve_counter", "cve_critical", "cve_high", "cve_medium", "cve_low")},
        "exploits": _to_int(data.get("exploits")),
    }
    obs.add_fact("firmware", {"vendor": vendor, "product": product,
                              "version": version, "arch": fw_value["verified_arch"]},
                 fw_value, "static", rel, None,
                 fact_source={"type": "tool-report", "tool": "emba"})

    if arch_verified or arch_unverified:
        arch_value = {"observation": "static-discovery",
                      "verified": norm_arch(arch_verified),
                      "unverified": norm_arch(arch_unverified),
                      "raw_verified": arch_verified, "raw_unverified": arch_unverified,
                      "source": "f50"}
        obs.add_fact("architecture", {"verified": arch_value["verified"],
                                      "unverified": arch_value["unverified"]},
                     arch_value, "static", rel, None,
                     fact_source={"type": "tool-report", "tool": "emba"})

    # F50_base_aggregator.sh:252-256 写的是成功用户态仿真的**数量**，
    # 不是状态字符串；字段名沿用 EMBA 的历史叫法，但语义必须按计数解释。
    user_raw = data.get("user_emulation_state", "")
    system_raw = data.get("system_emulation_state", "")
    if user_raw or system_raw:
        user_count = _to_int(user_raw)
        stage_value = {"observation": "static-discovery",
                       "user_emulation_count": user_count,
                       "user_emulation_state_raw": user_raw,
                       "system_emulation_state": system_raw,
                       "system_emulation_flags": sorted(
                           t for t in raw_state_tokens(system_raw)
                           if t.lower().replace("_", " ")
                           not in ("booted", "not booted")),
                       "system_booted": system_booted(system_raw),
                       "source": "f50"}
        obs.add_fact("stage", {"user_emulation_count": user_count,
                               "system_emulation_state": system_raw},
                     stage_value, "static", rel, None,
                     fact_source={"type": "tool-report", "tool": "emba"})


def parse_p99(obs: Observations, path: str) -> None:
    rel = rel_path(path, obs.logs_root)
    obs.add_input("p99", path)
    try:
        rows = _read_csv(path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        obs.error("PARSE_ERROR", f"无法读取 P99 CSV：{exc}", rel)
        return
    header: Optional[Dict[str, int]] = None
    start = 0
    if rows and _is_header(rows[0], ("source_module", "file_output", "arch_guessed")):
        header = _header_map(rows[0], P99_FIELDS)
        start = 1
    arches: Set[str] = set()
    elf_count = 0
    file_count = 0
    for lineno, row in enumerate(rows[start:], start + 1):
        if not row or all(not _norm_value(c) for c in row):
            continue
        if header is not None:
            get = lambda key: _norm_value(row[header[key]]) if key in header and header[key] < len(row) else ""
        else:
            if len(row) < 9:
                obs.error("PARSE_ERROR", f"P99 行只有 {len(row)} 列（需要 9 列）",
                          rel, lineno)
                continue
            get = lambda key, row=row: _norm_value(row[P99_FIELDS.index(key)])
        binary = get("path")
        file_output = get("file_output")
        blob = " ".join((get("class"), get("data"), file_output)).upper()
        if "ELF" not in blob and "PE32" not in blob:
            continue
        # P99 同时记录 ELF 与 PE32。只有 ELF 能落成 elf Fact；PE32 是
        # Windows 可执行文件，落成 file Fact 并保留 format，避免把 PE
        # 冒充成 Linux ELF 后误导依赖/加载器分析。
        fmt = "ELF" if "ELF" in blob else "PE32"
        fact_type = "elf" if fmt == "ELF" else "file"
        if not binary:
            obs.error("PARSE_ERROR", f"P99 {fmt} 行缺少路径", rel, lineno)
            continue
        arch = norm_arch(get("arch_guessed")) or norm_arch(get("machine"))
        if arch:
            arches.add(arch)
        value = {"observation": "static-discovery", "path": binary,
                 "format": fmt, "class": get("class"), "endian": get("data"),
                 "machine": get("machine"), "arch": arch,
                 "flags": get("flags_cnt"), "file_type": file_output,
                 "file_md5": get("md5"), "source": "p99"}
        obs.add_fact(fact_type, {"path": binary, "arch": arch, "format": fmt},
                     value, "static", rel, lineno,
                     fact_source={"type": "tool-report", "tool": "emba"})
        if fact_type == "elf":
            elf_count += 1
        else:
            file_count += 1
    binary_count = elf_count + file_count
    if binary_count and arches:
        value = {"observation": "static-discovery", "source": "p99",
                 "guessed": sorted(arches), "binary_count": binary_count,
                 "elf_count": elf_count, "file_count": file_count}
        obs.add_fact("architecture", {"guessed": sorted(arches)}, value, "static",
                     rel, None, fact_source={"type": "tool-report", "tool": "emba"})
    if not binary_count:
        obs.limit("P99 中没有识别到 ELF/PE32 行")


def _parse_version_rows(obs: Observations, path: str, role: str,
                        fact_type: str) -> None:
    rel = rel_path(path, obs.logs_root)
    obs.add_input(role, path)
    try:
        rows = _read_csv(path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        obs.error("PARSE_ERROR", f"无法读取 {role.upper()} CSV：{exc}", rel)
        return
    header: Optional[Dict[str, int]] = None
    start = 0
    if rows and _is_header(rows[0], ("rule identifier", "binary/file", "version_detected")):
        header = _header_map(rows[0], S09_FIELDS)
        start = 1
    count = 0
    for lineno, row in enumerate(rows[start:], start + 1):
        if not row or all(not _norm_value(c) for c in row):
            continue
        if header is not None:
            get = lambda key: _norm_value(row[header[key]]) if key in header and header[key] < len(row) else ""
        else:
            if len(row) < 2:
                obs.error("PARSE_ERROR", f"{role.upper()} 行列数不足", rel, lineno)
                continue
            get = lambda key, row=row: (_norm_value(row[S09_FIELDS.index(key)])
                                        if S09_FIELDS.index(key) < len(row) else "")
        binary = get("binary")
        if not binary:
            continue
        base = {"observation": "static-discovery", "binary": binary,
                "module": get("module"), "rule_id": get("rule_id"),
                "app_name": get("app_name"),
                "version_detected": get("version_detected"),
                "csv_rule": get("csv_rule"), "license": get("license"),
                "mode": get("mode"), "source": role}
        if fact_type == "service":
            base["service"] = os.path.basename(binary)
        obs.add_fact(fact_type, {"binary": binary, "rule": get("rule_id"),
                                 "version": get("version_detected")},
                     base, "static", rel, lineno,
                     fact_source={"type": "tool-report", "tool": "emba"})
        count += 1
    if not count:
        obs.limit(f"{role.upper()} 中没有可解析的二进制行")


def _strip_label(value: str, label: str) -> str:
    """剥掉 L10 手工拼出的 "Label: value" 前缀（大小写不敏感）。"""
    text = _norm_value(value)
    if text.lower().startswith(label.lower()):
        return text[len(label):].strip()
    return text


def parse_l10(obs: Observations, path: str) -> None:
    rel = rel_path(path, obs.logs_root)
    obs.add_input("l10", path)
    try:
        rows = _read_csv(path)
    except (OSError, UnicodeDecodeError, csv.Error) as exc:
        obs.error("PARSE_ERROR", f"无法读取 L10 CSV：{exc}", rel)
        return
    header: Optional[Dict[str, int]] = None
    start = 0
    if rows and _is_header(rows[0], ("available network services", "firmware_path", "booted state")):
        header = {}
        for i, cell in enumerate(rows[0]):
            name = _norm_value(cell).lower()
            if "available network services" in name:
                header["services"] = i
            elif "online services cnt" in name:
                header["count"] = i
            elif name.startswith("ip address") or "ip address" in name:
                header["ip"] = i
            elif "booted state" in name:
                header["booted"] = i
            elif "tcp state" in name and "tcp-0" not in name:
                header["tcp"] = i
            elif "network mode" in name:
                header["mode"] = i
        start = 1
    rows_seen = 0
    port_facts = 0
    no_port_lines: List[int] = []
    for lineno, row in enumerate(rows[start:], start + 1):
        if not row or all(not _norm_value(c) for c in row):
            continue
        rows_seen += 1
        if header is not None:
            get = lambda key: _norm_value(row[header[key]]) if key in header and header[key] < len(row) else ""
        else:
            if len(row) < 9:
                obs.error("PARSE_ERROR", f"L10 行只有 {len(row)} 列（需要 9 列以上）",
                          rel, lineno)
                continue
            get = lambda key, row=row: {
                "services": _norm_value(row[7]), "count": _norm_value(row[6]),
                "ip": _norm_value(row[8]), "booted": _norm_value(row[2]),
                "tcp": _norm_value(row[5]), "mode": _norm_value(row[9])
                if len(row) > 9 else ""}[key]
        raw_services = get("services")
        ports: List[Dict[str, Any]] = []
        seen: Set[Tuple[int, str]] = set()
        for match in PORT_RE.finditer(raw_services):
            port = int(match.group(1))
            transport = match.group(2).lower()
            if 0 < port < 65536 and (port, transport) not in seen:
                seen.add((port, transport))
                ports.append({"port": port, "transport": transport, "state": "open"})
        # L10 真实写点（modules/L10_system_emulation.sh:3180）把值拼成
        # "IP address: 1.2.3.4" 与 "Network mode: default (eth0|...)"；
        # 入库前剥掉标签，避免把展示文本当成机器字段。
        raw_ip = get("ip")
        raw_mode = get("mode")
        ip = _strip_label(raw_ip, "IP address:")
        mode_text = _strip_label(raw_mode, "Network mode:")
        mode_token = mode_text.split()[0] if mode_text.split() else ""
        # L10 的 available network services 只列 nmap 判定为 open 的端口
        # （modules/L10_system_emulation.sh:3180）。空列表表示系统仿真没有
        # 观测到开放端口，不能写成 trigger=false 的 port-response 事实。
        if not ports:
            no_port_lines.append(lineno)
            continue
        value = {"observation": "port-response", "ip": ip,
                 "services": [f"{p['port']}/{p['transport']}" for p in ports],
                 "ports": ports, "count": len(ports),
                 "reported_count": _to_int(get("count")),
                 "booted_state": get("booted"), "tcp_state": get("tcp"),
                 "network_mode": mode_token, "network_mode_detail": mode_text,
                 "ip_raw": raw_ip, "source": "l10"}
        event = {"type": "port-response", "trigger": True,
                 "args": {"ip": ip, "ports": value["services"],
                          "booted_state": get("booted")}}
        obs.add_fact("port-response", {"line": lineno, "ip": ip,
                                       "services": value["services"]},
                     value, "dynamic", rel, lineno, source_type="dynamic",
                     event=event, fact_source={"type": "dynamic", "tool": "emba"})
        port_facts += 1
    if not rows_seen:
        obs.limit("L10 中没有可解析的系统仿真行")
    elif not port_facts:
        where = f"（行 {', '.join(str(n) for n in no_port_lines)}）" if no_port_lines else ""
        obs.limit(f"L10 中没有开放的端口响应，未生成 port-response 事实{where}")
    else:
        for lineno in no_port_lines:
            obs.limit(f"L10 第 {lineno} 行未解析到开放端口，"
                      "未生成 port-response 事实")


def parse_s115(obs: Observations, path: str) -> None:
    rel = rel_path(path, obs.logs_root)
    obs.add_input("s115", path)
    try:
        text = _read_text(path)
    except (OSError, UnicodeDecodeError) as exc:
        obs.error("PARSE_ERROR", f"无法读取 S115 日志：{exc}", rel)
        return
    count = 0
    for lineno, line in enumerate(text.splitlines(), 1):
        clean = ANSI_RE.sub("", line)
        match = S115_RE.search(clean)
        if not match:
            continue
        binary = match.group(1).strip().strip("'\"")
        output = match.group(2).strip().strip("'\"")
        # EMBA 的成功行以句号结尾：“... generated output in /tmp/x.txt.”
        # 句号是英文标点，不属于路径。
        if output.endswith("."):
            output = output[:-1].rstrip()
        if not binary:
            obs.error("PARSE_ERROR", "S115 成功标记缺少二进制名", rel, lineno)
            continue
        value = {"observation": "runtime-process", "binary": binary,
                 "output": output, "emulator": "qemu-user",
                 "log": "s115_usermode_emulator.txt", "source": "s115"}
        event = {"type": "process-exec", "trigger": True,
                 "args": {"binary": binary, "output": output}}
        obs.add_fact("runtime-process", {"binary": binary, "line": lineno},
                     value, "emulation", rel, lineno, source_type="emulation",
                     event=event, fact_source={"type": "emulation", "tool": "emba"})
        count += 1
    if not count:
        obs.limit("S115 中没有找到 Emulated binary ... generated output 成功标记")


def parse_error_log(obs: Observations, path: str) -> None:
    rel = rel_path(path, obs.logs_root)
    obs.add_input("emba_error", path)
    try:
        text = _read_text(path)
    except (OSError, UnicodeDecodeError) as exc:
        obs.error("PARSE_ERROR", f"无法读取 emba_error.log：{exc}", rel)
        return
    lines = [ln for ln in text.splitlines() if ln.strip()]
    if not lines:
        return
    obs.error("EMBA_ERROR_LOG", f"EMBA 记录 {len(lines)} 行错误输出", rel)
    obs.limit("emba_error.log 非空；EMBA 自身报告了失败或告警，解析结果按 partial 处理")
    value = {"observation": "static-discovery", "failure": True,
             "error_lines": len(lines),
             "error_excerpt": [ln.strip()[:500] for ln in lines[:5]],
             "source": "emba_error"}
    obs.add_fact("stage", {"error_lines": len(lines)}, value, "static",
                 rel, None, fact_source={"type": "tool-report", "tool": "emba"})


# ── 主流程 ───────────────────────────────────────────────────────────────────

def parse_logs(logs_dir: str, run_id: str, firmware_sha256: str,
               firmware_path: Optional[str] = None,
               expect_version: Optional[str] = None,
               tool_version_hint: str = "",
               required: Sequence[str] = ()) -> Dict[str, Any]:
    root = os.path.abspath(logs_dir)
    if not os.path.isdir(root):
        raise AdapterError("LOGS_NOT_FOUND", f"日志目录不存在：{root}", root, 2)

    required_roles = {str(r).strip().lower() for r in (required or ())
                      if str(r).strip()}
    obs = Observations(run_id, firmware_sha256.lower(), tool_version_hint, root)
    if firmware_path:
        if not os.path.isfile(firmware_path):
            raise AdapterError("FIRMWARE_NOT_FOUND", f"固件文件不存在：{firmware_path}",
                               firmware_path, 2)
        actual = file_sha256(firmware_path)
        obs.add_input("firmware", firmware_path, root=os.path.dirname(os.path.abspath(firmware_path)))
        if actual != firmware_sha256.lower():
            obs.error("FIRMWARE_MISMATCH",
                      f"--firmware 实际 sha256={actual} 与 --firmware-sha256 不一致",
                      rel_path(firmware_path, root), fatal=True)
    else:
        obs.limit("firmware_sha256 由操作者提供，未与固件文件独立核对")

    f50_path = os.path.join(root, "csv_logs", "f50_base_aggregator.csv")
    if not os.path.isfile(f50_path):
        obs.error("F50_MISSING", "缺少必需的 F50 汇总 CSV", "csv_logs/f50_base_aggregator.csv",
                  fatal=True)
        return finish(obs, tool_version_hint, expect_version, required_roles)

    f50 = parse_f50(obs, f50_path)
    version = norm_version(f50.get("emba_version", ""))
    if not version:
        obs.error("EMBA_VERSION_MISSING", "F50 缺少可解析的 EMBA_version",
                  rel_path(f50_path, root), fatal=True)
    elif expect_version and norm_version(expect_version) != version:
        obs.error("EMBA_VERSION_MISMATCH",
                  f"EMBA_version={version}，期望 {norm_version(expect_version)}",
                  rel_path(f50_path, root), fatal=True)
    obs.tool_version = version or (tool_version_hint or "unknown")
    if f50:
        emit_f50_facts(obs, f50)

    optional = (
        ("p99", os.path.join(root, "csv_logs", "p99_prepare_analyzer.csv"), parse_p99),
        ("s09", os.path.join(root, "csv_logs", "s09_firmware_base_version_check.csv"),
         lambda o, p: _parse_version_rows(o, p, "s09", "dependency")),
        ("l15", os.path.join(root, "csv_logs", "l15_emulated_checks_nmap.csv"),
         lambda o, p: _parse_version_rows(o, p, "l15", "service")),
        ("l10", os.path.join(root, "csv_logs", "l10_system_emulation.csv"), parse_l10),
        ("s115", os.path.join(root, "s115_usermode_emulator.txt"), parse_s115),
    )
    for role, path, parser in optional:
        if os.path.isfile(path):
            parser(obs, path)
        elif role in required_roles:
            obs.error("MISSING_REQUIRED_ARTIFACT",
                      f"缺少本次审计显式要求的 EMBA 产物：{role}",
                      os.path.relpath(path, root).replace("\\", "/"),
                      fatal=True)
        else:
            obs.error("MISSING_ARTIFACT", f"缺少可选 EMBA 产物：{role}",
                      os.path.relpath(path, root).replace("\\", "/"))

    err_path = os.path.join(root, "emba_error.log")
    if os.path.isfile(err_path):
        parse_error_log(obs, err_path)

    return finish(obs, version or tool_version_hint, expect_version,
                  required_roles)


def finish(obs: Observations, tool_version: str,
           expect_version: Optional[str] = None,
           required: Sequence[str] = ()) -> Dict[str, Any]:
    facts = sorted(obs.facts, key=lambda f: f.get("fact_id", ""))
    evidence = sorted(obs.evidence, key=lambda e: e.get("evidence_id", ""))
    errors = sorted(obs.errors, key=lambda e: (e.get("path", ""),
                                               e.get("line", 0),
                                               e.get("code", ""),
                                               e.get("message", "")))
    inputs = sorted(obs.inputs, key=lambda x: (x.get("role", ""), x.get("path", "")))
    present_roles = {str(row.get("role") or "") for row in inputs}
    required_roles = sorted({str(r).strip().lower() for r in (required or ())
                             if str(r).strip()})
    requirements = {
        "required": required_roles,
        "satisfied": sorted(set(required_roles) & present_roles),
        "missing": sorted(set(required_roles) - present_roles),
    }
    limitations = sorted(set(obs.limitations))
    observations = [{"fact_id": f["fact_id"], "type": f.get("type"),
                     "observation": (f.get("value") or {}).get("observation", "")}
                    for f in facts]
    counts: Dict[str, Any] = {"evidence": len(evidence), "facts": len(facts),
                              "errors": len(errors), "by_type": {}}
    by_type: Dict[str, int] = {}
    for fact in facts:
        typ = str(fact.get("type") or "")
        if typ:
            by_type[typ] = by_type.get(typ, 0) + 1
    counts["by_type"] = by_type
    for row in observations:
        key = str(row.get("observation") or "")
        if key:
            counts[key] = counts.get(key, 0) + 1
    return {
        "schema": SCHEMA,
        "adapter": {"name": "adapter_emba", "version": VERSION},
        "run_id": obs.run_id,
        "firmware_sha256": obs.firmware_sha256,
        "status": "failed" if obs.fatal else ("partial" if errors else "parsed"),
        "tool": {"name": "emba", "version": tool_version or "unknown"},
        "expect_version": expect_version,
        "inputs": inputs,
        "requirements": requirements,
        "counts": counts,
        "observations": observations,
        "evidence": evidence,
        "facts": facts,
        "errors": errors,
        "limitations": limitations,
    }


def write_json(path: str, doc: Dict[str, Any]) -> None:
    parent = os.path.dirname(os.path.abspath(path))
    if parent:
        os.makedirs(parent, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(doc, fh, ensure_ascii=False, sort_keys=True, indent=2)
        fh.write("\n")


def render_summary(doc: Dict[str, Any]) -> str:
    counts = doc.get("counts") or {}
    lines = [
        f"[adapter_emba] status={doc.get('status')} "
        f"facts={counts.get('facts', 0)} evidence={counts.get('evidence', 0)} "
        f"errors={counts.get('errors', 0)}",
        f"  tool={((doc.get('tool') or {}).get('name'))} "
        f"{((doc.get('tool') or {}).get('version'))} "
        f"static-discovery={counts.get('static-discovery', 0)} "
        f"runtime-process={counts.get('runtime-process', 0)} "
        f"port-response={counts.get('port-response', 0)}",
    ]
    req = doc.get("requirements") or {}
    if req.get("required"):
        missing = ",".join(req.get("missing") or []) or "-"
        lines.append(f"  required={','.join(req.get('required') or [])} "
                     f"missing={missing}")
    for err in (doc.get("errors") or [])[:5]:
        loc = err.get("path") or ""
        if err.get("line") is not None:
            loc += f":{err['line']}"
        lines.append(f"  [{err.get('code')}] {loc} {err.get('message')}"
                     if loc else f"  [{err.get('code')}] {err.get('message')}")
    if len(doc.get("errors") or []) > 5:
        lines.append(f"  ... 另有 {len(doc['errors']) - 5} 条错误")
    for lim in (doc.get("limitations") or [])[:3]:
        lines.append(f"  limitation: {lim}")
    return "\n".join(lines)


def parse_required(values: Sequence[str]) -> List[str]:
    """--require 支持重复参数与逗号分隔；未知角色直接拒绝。"""
    roles: List[str] = []
    for raw in values or ():
        for part in str(raw).split(","):
            role = part.strip().lower()
            if not role:
                continue
            if role not in ARTIFACT_ROLES:
                raise AdapterError(
                    "BAD_REQUIRE",
                    f"未知的必需产物角色 {role!r}；可选：{', '.join(ARTIFACT_ROLES)}",
                    exit_code=2)
            if role not in roles:
                roles.append(role)
    return roles


def validate_args(args: argparse.Namespace) -> None:
    if not isinstance(args.run_id, str) or not args.run_id.strip():
        raise AdapterError("BAD_RUN_ID", "--run-id 必须是非空字符串", exit_code=2)
    if not HEX64.match((args.firmware_sha256 or "").lower()):
        raise AdapterError("BAD_FIRMWARE_HASH",
                           "--firmware-sha256 必须是 64 位十六进制", exit_code=2)
    if args.strict and args.status_only:
        raise AdapterError("BAD_ARGS", "--strict 与 --status-only 不能同时使用", exit_code=2)
    args.require = parse_required(getattr(args, "require", []) or [])


def main(argv: Optional[List[str]] = None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass
    ap = argparse.ArgumentParser(
        description="离线解析 EMBA 日志为黑板事实/证据（不启动仿真）")
    ap.add_argument("--version", action="version", version=f"adapter_emba {VERSION}")
    sub = ap.add_subparsers(dest="cmd")
    p = sub.add_parser("parse", help="解析一份 EMBA 日志目录")
    p.add_argument("--logs", required=True)
    p.add_argument("--run-id", required=True)
    p.add_argument("--firmware-sha256", required=True)
    p.add_argument("--firmware")
    p.add_argument("--expect-version")
    p.add_argument("--require", action="append", default=[], metavar="ROLE",
                   help="显式要求本次审计必须提供的可选产物（可重复/逗号分隔）："
                        + ", ".join(ARTIFACT_ROLES))
    p.add_argument("--out")
    p.add_argument("--json", action="store_true", dest="json_out")
    p.add_argument("--strict", action="store_true")
    p.add_argument("--status-only", action="store_true")
    args = ap.parse_args(argv)
    if not args.cmd:
        ap.print_help()
        return 2
    try:
        validate_args(args)
        doc = parse_logs(args.logs, args.run_id, args.firmware_sha256,
                         args.firmware, args.expect_version,
                         required=args.require)
        if _validate_emba_import is not None:
            errs = _validate_emba_import(doc)
            if errs:
                raise AdapterError("SELF_CHECK_FAILED",
                                   _contract_summary(errs) if _contract_summary else str(errs),
                                   exit_code=1)
        if args.out:
            write_json(args.out, doc)
        if args.json_out:
            print(json.dumps(doc, ensure_ascii=False, sort_keys=True, indent=2))
        elif not args.status_only:
            print(render_summary(doc))
        if doc.get("status") == "failed":
            return 1
        if doc.get("status") == "partial" and args.strict:
            return 3
        return 0
    except AdapterError as exc:
        print(f"[error] {exc.code}: {exc.message}", file=sys.stderr)
        return exc.exit_code
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        print(f"[error] IO_ERROR: {exc}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
