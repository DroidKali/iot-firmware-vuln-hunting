#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""IoT 固件漏洞检测合成基准评测器（bench_eval.py）。

合成边界（必读）
================
assets/bench 下的样本是 100% 手工构造的迷你 rootfs 片段，不含任何真实固件
二进制或厂商代码。它们只用于验证本工具的校验、匹配、指标与基线门禁契约，
不能用来推断真实设备上的 precision/recall/FPR。真实固件基准目前为
real_firmware=pending，补充后必须重新标注并单独报告，不得把本报告当作
真实固件检出率。

指标定义
========
- TP：reviewed 标签被至少一个 finding 命中；同一标签最多记一次 TP。
- FP：评测范围内、没有命中任何标签（reviewed 或非 reviewed）的 finding。
  落在 safe 或 hard-negative 样本上的 FP 会进入 FPR 分子；落在漏洞样本上
  但没有标签覆盖的 finding 同样计入 FP。命中同一标签、但因“一标签一 TP”
  未选中为 TP 的重复 finding 不计 FP，单独披露。命中 needs_review/unknown
  标签的 finding 不进入主指标（既不计 TP 也不计 FP），避免未复核标签污染
  precision。
- FN：reviewed 标签没有被任何 finding 命中。
- TN：没有 FP 的 safe 或 hard-negative 样本数（样本级）。
- Precision = TP / (TP + FP)
- Recall = TP / (TP + FN)
- F1 = 2 * Precision * Recall / (Precision + Recall)
- FPR = 至少有一个 FP 的负样本数 / 负样本总数
- 漏报率 = FN / (TP + FN) = 1 - Recall

匹配规则
========
finding 与标签的文件路径必须相同，并且满足以下任一条件：
1. finding 的 line 在标签 line 的正负 3 行内；
2. finding 的 symbol 与标签 symbol 归一化后相同；
3. finding 的 pattern / evidence / match / context / snippet / text 等证据文本包含标签 symbol。
findings 先按 file + line + pattern 去重。一个 finding 最多贡献一个 TP；同一
标签只计一次 TP。file 不在 manifest 任何样本中的 finding 计入 out_of_scope，
不进入 P/R/FPR 分母；因 --split 被排除的 finding 单独计入 excluded_by_split。
review 不是 reviewed 的标签在 not_evaluable 中单列，不计入主指标 P/R 分母。
非严格模式会额外计算一个明确标注为非权威的 provisional 指标，把未复核标签
一并计入，用于敏感性分析；--strict 时不计算 provisional。

依赖与编码
==========
仅使用 Python 3.10+ 标准库；所有输入输出均为 UTF-8。
"""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import subprocess
import sys
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any, Optional


SCHEMA_MANIFEST = "bench-manifest/1.0"
SCHEMA_RESULT = "bench-result/1.0"
TOOL_NAME = "bench_eval.py"
TOOL_VERSION = "1.0.0"
ARCH_ORDER = ("mips", "arm", "x86_64", "none")
KIND_ORDER = ("vuln", "safe", "hard-negative")
REVIEW_STATES = ("reviewed", "needs_review", "unknown")
NEGATIVE_KINDS = ("safe", "hard-negative")
SPLIT_ORDER = ("dev", "holdout")
MAX_DETAILS = 200
MAX_PRINT_ISSUES = 80
HEX_RE = re.compile(r"^0[xX][0-9a-fA-F]+$")
SHA256_RE = re.compile(r"^[0-9a-fA-F]{64}$")

CATEGORY_ALIASES = {
    "cmd-exec": "command-injection",
    "cmd-execution": "command-injection",
    "command-exec": "command-injection",
    "command-execution": "command-injection",
    "command-injection": "command-injection",
    "os-command-injection": "command-injection",
    "shell-injection": "command-injection",
    "memory": "buffer-overflow",
    "memory-corruption": "buffer-overflow",
    "buffer-overflow": "buffer-overflow",
    "buffer-overflow-classic": "buffer-overflow",
    "strcpy": "buffer-overflow",
    "unsafe-string": "buffer-overflow",
    "path-traversal": "path-traversal",
    "directory-traversal": "path-traversal",
    "traversal": "path-traversal",
    "file-path-traversal": "path-traversal",
    "credential": "hardcoded-credential",
    "credentials": "hardcoded-credential",
    "hardcoded-credential": "hardcoded-credential",
    "hardcoded-password": "hardcoded-credential",
    "config-credential": "hardcoded-credential",
    "auth-credential": "hardcoded-credential",
}


class InputError(Exception):
    """参数、文件或 JSON 读取错误。"""


class FindingsError(Exception):
    """findings 结构错误。"""


@dataclass
class Label:
    id: str
    sample_id: str
    category: str
    file: str
    line: int
    symbol: str
    cwe: str
    severity: str
    evidence: str
    review: str
    raw: dict[str, Any] = field(default_factory=dict)
    matched: bool = False
    matched_finding_index: Optional[int] = None

    @property
    def reviewed(self) -> bool:
        return self.review == "reviewed"


@dataclass
class Sample:
    id: str
    path: str
    sha256: str
    size: int
    files: list[dict[str, Any]]
    arch: str
    kind: str
    source: str
    license: str
    labels: list[Label]
    notes: str
    split: str
    dir: Path


@dataclass
class Bench:
    root: Path
    manifest_path: Path
    sha256: str
    data: dict[str, Any]
    samples: list[Sample]
    by_id: dict[str, Sample]
    splits: dict[str, list[str]]
    issues: list[str]
    warnings: list[str]


@dataclass
class Finding:
    index: int
    raw: dict[str, Any]
    sample: Sample
    file: str
    line: Optional[int]
    offset: Optional[int]
    pattern: str
    text: str
    category: str
    rule_id: str
    title: str
    symbol: str = ""
    priority: str = ""
    engine: str = ""
    lines: list[int] = field(default_factory=list)
    status: str = ""
    label_id: Optional[str] = None
    reason: str = ""


@dataclass
class EvalOutcome:
    mode: str
    counted_ids: set[str]
    labels: list[Label]
    findings: list[Finding]
    tp: int
    fp: int
    fn: int
    tp_labels: list[Label]
    fn_labels: list[Label]
    fp_findings: list[Finding]
    duplicate_findings: list[Finding]
    unreviewed_findings: list[Finding]
    fp_negative_samples: set[str]
    fp_positive_samples: set[str]
    not_evaluable: list[Label]


def is_int(value: Any) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def nonempty_str(value: Any) -> Optional[str]:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return None


def norm_path(value: str) -> str:
    """把 Windows/Unix 路径归一化为 posix 相对路径；仅用于匹配。"""
    text = str(value).strip().replace("\\", "/")
    text = re.sub(r"^[A-Za-z]:", "", text)
    text = text.lstrip("/")
    parts: list[str] = []
    for part in text.split("/"):
        if part in ("", "."):
            continue
        if part == "..":
            if parts:
                parts.pop()
            continue
        parts.append(part)
    return "/".join(parts)


def is_plain_rel(value: Any) -> bool:
    if not isinstance(value, str) or not value.strip():
        return False
    text = value.strip().replace("\\", "/")
    if text.startswith("/") or re.match(r"^[A-Za-z]:", text):
        return False
    return all(part not in ("", ".", "..") for part in text.split("/"))


def within(child: Path, parent: Path) -> bool:
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def read_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def read_text_lines(path: Path) -> list[str]:
    return path.read_text(encoding="utf-8").splitlines()


def safe_div(num: float, den: float) -> Optional[float]:
    if den == 0:
        return None
    return num / den


def round6(value: Optional[float]) -> Optional[float]:
    if value is None:
        return None
    return round(float(value), 6)


def fmt_num(value: Optional[float]) -> str:
    if value is None:
        return "N/A"
    return f"{value:.4f}"


def md_cell(value: Any) -> str:
    text = "" if value is None else str(value)
    return text.replace("|", "\\|").replace("\r", " ").replace("\n", " ")


def normalize_category(value: Any) -> str:
    text = str(value).strip().lower().replace("_", "-")
    return CATEGORY_ALIASES.get(text, text or "unknown")


def norm_symbol(value: Any) -> str:
    text = str(value).strip().lower()
    text = re.sub(r"\(.*$", "", text)
    text = re.sub(r"[^a-z0-9_]+", "", text)
    return text


def category_sort_key(value: str) -> tuple[int, str]:
    preferred = [
        "command-injection",
        "buffer-overflow",
        "path-traversal",
        "hardcoded-credential",
    ]
    if value in preferred:
        return (preferred.index(value), value)
    return (len(preferred), value)


def split_sort_key(value: str) -> tuple[int, str]:
    if value in SPLIT_ORDER:
        return (SPLIT_ORDER.index(value), value)
    return (len(SPLIT_ORDER), value)


def arch_sort_key(value: str) -> tuple[int, str]:
    if value in ARCH_ORDER:
        return (ARCH_ORDER.index(value), value)
    return (len(ARCH_ORDER), value)


def scan_files(root: Path) -> list[str]:
    if not root.is_dir():
        return []
    result: list[str] = []
    for path in root.rglob("*"):
        if path.is_file():
            result.append(path.relative_to(root).as_posix())
    return sorted(result)


def validate_labels(
    raw_labels: Any,
    sample_id: str,
    sample_dir: Path,
    declared_files: set[str],
    line_cache: dict[str, list[str]],
    seen_label_ids: set[str],
    issues: list[str],
    warnings: list[str],
) -> list[Label]:
    labels: list[Label] = []
    if not isinstance(raw_labels, list):
        issues.append(f"[labels] 样本 {sample_id}.labels 必须是数组")
        return labels
    seen_keys: set[tuple[str, int, str, str]] = set()
    for idx, raw in enumerate(raw_labels):
        ctx = f"{sample_id}.labels[{idx}]"
        if not isinstance(raw, dict):
            issues.append(f"[labels] {ctx} 必须是 object")
            continue
        label_id = nonempty_str(raw.get("id"))
        if not label_id:
            issues.append(f"[labels] {ctx}.id 必须是非空字符串")
            label_id = f"UNKNOWN-{sample_id}-{idx}"
        elif label_id in seen_label_ids:
            issues.append(f"[labels] 重复标签 ID: {label_id}")
        else:
            seen_label_ids.add(label_id)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", label_id):
            warnings.append(f"[labels] 标签 ID 建议使用字母数字短横线: {label_id!r}")

        category = nonempty_str(raw.get("category"))
        if not category:
            issues.append(f"[labels] {label_id}.category 必须是非空字符串")
            category = "unknown"
        frel = nonempty_str(raw.get("file"))
        if not frel or not is_plain_rel(frel):
            issues.append(f"[labels] {label_id}.file 必须是不含 .. 的相对路径")
            frel = norm_path(frel) if frel else ""
        else:
            frel = norm_path(frel)
        line = raw.get("line")
        if not is_int(line) or line <= 0:
            issues.append(f"[labels] {label_id}.line 必须是正整数")
            line = 0
        symbol = nonempty_str(raw.get("symbol"))
        if not symbol:
            issues.append(f"[labels] {label_id}.symbol 必须是非空字符串")
            symbol = ""
        cwe = nonempty_str(raw.get("cwe"))
        if not cwe:
            issues.append(f"[labels] {label_id}.cwe 必须是非空字符串")
            cwe = ""
        elif not re.fullmatch(r"CWE-[0-9]+", cwe):
            warnings.append(f"[labels] {label_id}.cwe 格式不是 CWE-数字: {cwe!r}")
        severity = nonempty_str(raw.get("severity"))
        if not severity:
            issues.append(f"[labels] {label_id}.severity 必须是非空字符串")
            severity = ""
        evidence = nonempty_str(raw.get("evidence"))
        if not evidence:
            issues.append(f"[labels] {label_id}.evidence 必须是非空字符串")
            evidence = ""
        review = nonempty_str(raw.get("review"))
        if review not in REVIEW_STATES:
            issues.append(
                f"[labels] {label_id}.review 必须是 {'/'.join(REVIEW_STATES)} 之一，实际 {review!r}"
            )
            review = review or "unknown"

        fpath: Optional[Path] = None
        if frel:
            fpath = (sample_dir / frel).resolve()
            if not within(fpath, sample_dir.resolve()):
                issues.append(f"[labels] {label_id}.file 逃出样本目录: {frel}")
                fpath = None
            elif not fpath.is_file():
                issues.append(f"[labels] {label_id}.file 不存在: {sample_dir.name}/{frel}")
                fpath = None
            elif declared_files and frel not in declared_files:
                issues.append(f"[labels] {label_id}.file 未出现在样本 files[] 中: {frel}")

        if fpath is not None and line > 0:
            try:
                key = str(fpath)
                if key not in line_cache:
                    line_cache[key] = read_text_lines(fpath)
                file_lines = line_cache[key]
            except (OSError, UnicodeDecodeError) as exc:
                issues.append(f"[labels] {label_id} 无法以 UTF-8 读取 {frel}: {exc}")
            else:
                if line > len(file_lines):
                    issues.append(
                        f"[labels] {label_id} line={line} 超出文件行数 {len(file_lines)}: {frel}"
                    )
                else:
                    actual_line = file_lines[line - 1]
                    if evidence and evidence not in actual_line:
                        other = [
                            no + 1
                            for no, value in enumerate(file_lines)
                            if evidence in value
                        ]
                        hint = f"（evidence 实际出现于行 {other}）" if other else ""
                        issues.append(
                            f"[labels] {label_id} evidence 不在 {frel}:{line} 指定行{hint}: {evidence!r}"
                        )
                    if symbol and symbol not in actual_line:
                        warnings.append(
                            f"[labels] {label_id}.symbol={symbol!r} 不在 {frel}:{line} 的文本中"
                        )

        if frel and line > 0:
            key2 = (frel, line, category, symbol)
            if key2 in seen_keys:
                issues.append(f"[labels] {label_id} 与同一文件/行/类别/符号的标签重复")
            seen_keys.add(key2)
        labels.append(
            Label(
                id=label_id,
                sample_id=sample_id,
                category=category,
                file=frel,
                line=line,
                symbol=symbol,
                cwe=cwe,
                severity=severity,
                evidence=evidence,
                review=review,
                raw=raw,
            )
        )
    return labels


def validate_manifest(manifest_path: Path) -> Bench:
    manifest_path = manifest_path.resolve()
    root = manifest_path.parent
    if not manifest_path.is_file():
        raise InputError(f"manifest 文件不存在: {manifest_path}")
    try:
        data = read_json(manifest_path)
    except json.JSONDecodeError as exc:
        raise InputError(f"manifest JSON 解析失败: {exc}") from exc
    except OSError as exc:
        raise InputError(f"manifest 读取失败: {exc}") from exc
    manifest_sha = sha256_file(manifest_path)
    issues: list[str] = []
    warnings: list[str] = []
    splits: dict[str, list[str]] = {"dev": [], "holdout": []}
    samples: list[Sample] = []
    by_id: dict[str, Sample] = {}

    if not isinstance(data, dict):
        issues.append("[schema] manifest 顶层必须是 JSON object")
        return Bench(root, manifest_path, manifest_sha, {}, samples, by_id, splits, issues, warnings)

    if data.get("schema") != SCHEMA_MANIFEST:
        issues.append(
            f"[schema] manifest schema 必须为 {SCHEMA_MANIFEST!r}，实际 {data.get('schema')!r}"
        )
    dataset = data.get("dataset")
    if not isinstance(dataset, dict):
        issues.append("[dataset] 缺少 dataset object")
        dataset = {}
    else:
        for key in ("name", "version", "created", "kind", "license", "description", "real_firmware"):
            value = dataset.get(key)
            if not isinstance(value, str) or not value.strip():
                issues.append(f"[dataset] dataset.{key} 必须是非空字符串")
        kind_value = dataset.get("kind")
        if isinstance(kind_value, str) and kind_value not in ("synthetic", "real"):
            issues.append(f"[dataset] dataset.kind 必须是 synthetic 或 real，实际 {kind_value!r}")
        created = dataset.get("created")
        if isinstance(created, str) and created.strip():
            try:
                date.fromisoformat(created.strip())
            except ValueError:
                issues.append(f"[dataset] dataset.created 不是 ISO 日期: {created!r}")
    for key in ("rule_version", "tool_version"):
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            issues.append(f"[schema] 缺少非空字符串 {key}")

    splits_raw = data.get("splits")
    if not isinstance(splits_raw, dict):
        issues.append("[splits] 缺少 splits object")
    else:
        for name in SPLIT_ORDER:
            value = splits_raw.get(name)
            if not isinstance(value, list) or not value:
                issues.append(f"[splits] splits.{name} 必须是非空数组")
                continue
            cleaned: list[str] = []
            for item in value:
                if not isinstance(item, str) or not item.strip():
                    issues.append(f"[splits] splits.{name} 含非字符串或空 ID")
                    continue
                cleaned.append(item.strip())
            if len(set(cleaned)) != len(cleaned):
                issues.append(f"[splits] splits.{name} 含重复样本 ID")
            splits[name] = cleaned
        for extra in sorted(set(splits_raw) - set(SPLIT_ORDER)):
            warnings.append(f"[splits] 忽略未知 split {extra!r}（仅支持 dev/holdout）")

    samples_raw = data.get("samples")
    if not isinstance(samples_raw, list) or not samples_raw:
        issues.append("[samples] samples 必须是非空数组")
        samples_raw = []

    seen_ids: set[str] = set()
    seen_paths: set[str] = set()
    seen_label_ids: set[str] = set()
    line_cache: dict[str, list[str]] = {}

    for idx, raw in enumerate(samples_raw):
        ctx = f"samples[{idx}]"
        if not isinstance(raw, dict):
            issues.append(f"[samples] {ctx} 必须是 object")
            continue
        sid = nonempty_str(raw.get("id"))
        if not sid:
            issues.append(f"[samples] {ctx}.id 必须是非空字符串")
            continue
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", sid):
            issues.append(f"[samples] 样本 ID 不合法（只允许字母数字 . _ -）: {sid!r}")
            continue
        if sid in seen_ids:
            issues.append(f"[samples] 重复样本 ID: {sid}")
        seen_ids.add(sid)
        sample_dir = root / "samples" / sid

        rel = raw.get("path")
        rel_norm = ""
        # 即使 path 非法也要先定义，后续 files[] 的锚点校验会用到；否则会
        # 以 UnboundLocalError 崩溃，而不是给出可读的校验问题。
        expected_prefix = f"samples/{sid}/"
        anchor_abs: Optional[Path] = None
        if not isinstance(rel, str) or not is_plain_rel(rel):
            issues.append(f"[samples] {sid}.path 必须是不含 .. 的相对路径")
        else:
            rel_norm = norm_path(rel)
            if rel_norm in seen_paths:
                issues.append(f"[samples] 重复样本路径: {rel_norm}")
            seen_paths.add(rel_norm)
            if not rel_norm.startswith(expected_prefix):
                issues.append(
                    f"[samples] {sid}.path 必须位于 {expected_prefix} 下，实际 {rel_norm}"
                )
            anchor_abs = (root / rel_norm).resolve()
            if not within(anchor_abs, root):
                issues.append(f"[samples] {sid}.path 逃出 manifest 目录: {rel_norm}")
                anchor_abs = None
            elif not anchor_abs.is_file():
                issues.append(f"[samples] {sid}.path 文件不存在: {rel_norm}")
                anchor_abs = None

        sha = raw.get("sha256")
        sha_ok = isinstance(sha, str) and bool(SHA256_RE.fullmatch(sha.strip()))
        if not sha_ok:
            issues.append(f"[samples] {sid}.sha256 必须是 64 位十六进制字符串")
            sha_norm = ""
        else:
            sha_norm = sha.strip().lower()
        size = raw.get("size")
        size_ok = is_int(size) and size >= 0
        if not size_ok:
            issues.append(f"[samples] {sid}.size 必须是非负整数")
        if anchor_abs is not None:
            actual_sha = sha256_file(anchor_abs)
            actual_size = anchor_abs.stat().st_size
            if sha_ok and actual_sha != sha_norm:
                issues.append(
                    f"[sha256] 样本 {sid} 锚点文件哈希不符: manifest={sha_norm} actual={actual_sha} path={rel_norm}"
                )
            if size_ok and actual_size != size:
                issues.append(
                    f"[size] 样本 {sid} 锚点文件大小不符: manifest={size} actual={actual_size} path={rel_norm}"
                )

        arch = nonempty_str(raw.get("arch"))
        if arch not in ARCH_ORDER:
            issues.append(f"[samples] {sid}.arch 必须是 {'/'.join(ARCH_ORDER)} 之一，实际 {arch!r}")
            arch = arch or "unknown"
        kind = nonempty_str(raw.get("kind"))
        if kind not in KIND_ORDER:
            issues.append(f"[samples] {sid}.kind 必须是 {'/'.join(KIND_ORDER)} 之一，实际 {kind!r}")
            kind = kind or "unknown"
        source = nonempty_str(raw.get("source"))
        if not source:
            issues.append(f"[samples] {sid}.source 必须是非空字符串")
            source = "unknown"
        if dataset.get("kind") == "synthetic" and source != "synthetic":
            warnings.append(f"[samples] {sid}.source={source!r}，合成数据集的样本通常为 synthetic")
        license_value = nonempty_str(raw.get("license"))
        if not license_value:
            issues.append(f"[samples] {sid}.license 必须是非空字符串")
            license_value = ""
        notes = raw.get("notes")
        if not isinstance(notes, str):
            issues.append(f"[samples] {sid}.notes 必须是字符串")
            notes = "" if notes is None else str(notes)

        declared: dict[str, dict[str, Any]] = {}
        files_for_sample: list[dict[str, Any]] = []
        files_raw = raw.get("files")
        if files_raw is None:
            warnings.append(f"[samples] {sid} 未提供 files[]，只能校验锚点文件")
            for frel in scan_files(sample_dir):
                fpath = sample_dir / frel
                files_for_sample.append(
                    {"path": frel, "sha256": sha256_file(fpath), "size": fpath.stat().st_size}
                )
        elif not isinstance(files_raw, list) or not files_raw:
            issues.append(f"[samples] {sid}.files 必须是非空数组")
        else:
            for fi, fmeta in enumerate(files_raw):
                fctx = f"{sid}.files[{fi}]"
                if not isinstance(fmeta, dict):
                    issues.append(f"[samples] {fctx} 必须是 object")
                    continue
                frel_raw = nonempty_str(fmeta.get("path"))
                if not frel_raw or not is_plain_rel(frel_raw):
                    issues.append(f"[samples] {fctx}.path 必须是不含 .. 的相对路径")
                    continue
                frel = norm_path(frel_raw)
                if frel in declared:
                    issues.append(f"[samples] {fctx}.path 重复: {frel}")
                    continue
                fpath = (sample_dir / frel).resolve()
                if not within(fpath, sample_dir.resolve()):
                    issues.append(f"[samples] {fctx}.path 逃出样本目录: {frel}")
                    continue
                if not fpath.is_file():
                    issues.append(f"[samples] {fctx}.path 文件不存在: {frel}")
                    continue
                fsha = fmeta.get("sha256")
                fsize = fmeta.get("size")
                if not isinstance(fsha, str) or not SHA256_RE.fullmatch(fsha.strip()):
                    issues.append(f"[samples] {fctx}.sha256 必须是 64 位十六进制字符串")
                    fsha = ""
                if not is_int(fsize) or fsize < 0:
                    issues.append(f"[samples] {fctx}.size 必须是非负整数")
                    fsize = 0
                actual_sha = sha256_file(fpath)
                actual_size = fpath.stat().st_size
                if fsha and actual_sha != fsha.strip().lower():
                    issues.append(
                        f"[sha256] 样本 {sid} 文件 {frel} 哈希不符: manifest={fsha.strip().lower()} actual={actual_sha}"
                    )
                if fsize and actual_size != fsize:
                    issues.append(
                        f"[size] 样本 {sid} 文件 {frel} 大小不符: manifest={fsize} actual={actual_size}"
                    )
                declared[frel] = fmeta
                files_for_sample.append(
                    {"path": frel, "sha256": actual_sha, "size": actual_size}
                )
            actual_files = set(scan_files(sample_dir))
            missing = sorted(actual_files - set(declared))
            extra = sorted(set(declared) - actual_files)
            if missing:
                issues.append(f"[files] 样本 {sid} 的 files[] 未覆盖实际文件: {missing}")
            if extra:
                issues.append(f"[files] 样本 {sid} 的 files[] 声明了不存在的文件: {extra}")
            anchor_rel = (
                rel_norm[len(expected_prefix):]
                if rel_norm.startswith(expected_prefix)
                else rel_norm
            )
            if anchor_rel and anchor_rel not in declared:
                issues.append(
                    f"[files] 样本 {sid} 的锚点未出现在 files[]: {anchor_rel}"
                )
        files_for_sample.sort(key=lambda item: item["path"])

        labels = validate_labels(
            raw.get("labels"),
            sid,
            sample_dir,
            set(declared),
            line_cache,
            seen_label_ids,
            issues,
            warnings,
        )
        if kind == "vuln" and not any(label.reviewed for label in labels):
            warnings.append(f"[labels] 漏洞样本 {sid} 没有 reviewed 标签")
        if kind in NEGATIVE_KINDS and labels:
            warnings.append(f"[labels] 负样本 {sid} 含标签，评测时按证据匹配，需人工确认语义")

        sample = Sample(
            id=sid,
            path=rel_norm,
            sha256=sha_norm,
            size=size if size_ok else 0,
            files=files_for_sample,
            arch=arch,
            kind=kind,
            source=source,
            license=license_value,
            labels=labels,
            notes=notes,
            split="",
            dir=sample_dir,
        )
        samples.append(sample)
        by_id[sid] = sample

    split_of: dict[str, str] = {}
    for name in SPLIT_ORDER:
        for sid in splits.get(name, []):
            if sid not in seen_ids:
                issues.append(f"[splits] splits.{name} 引用了不存在的样本 ID: {sid}")
                continue
            if sid in split_of:
                issues.append(f"[splits] 样本 {sid} 同时出现在 {split_of[sid]} 和 {name}")
                continue
            split_of[sid] = name
    for sample in samples:
        sample.split = split_of.get(sample.id, "")
        if not sample.split:
            issues.append(f"[splits] 样本 {sample.id} 未出现在 dev/holdout 中")
    for name in SPLIT_ORDER:
        if not splits.get(name):
            issues.append(f"[splits] split {name} 为空")

    return Bench(
        root=root,
        manifest_path=manifest_path,
        sha256=manifest_sha,
        data=data,
        samples=samples,
        by_id=by_id,
        splits=splits,
        issues=issues,
        warnings=warnings,
    )


# ---------------------------------------------------------------------------
# findings 读取、路径解析与归一化
# ---------------------------------------------------------------------------
def build_file_index(bench: Bench) -> dict[str, list[tuple[Sample, str]]]:
    index: dict[str, list[tuple[Sample, str]]] = {}
    for sample in bench.samples:
        for meta in sample.files:
            rel = norm_path(meta.get("path", ""))
            if rel:
                index.setdefault(rel, []).append((sample, rel))
    return index


def _lookup_sample_prefix(
    bench: Bench, raw: str
) -> tuple[Optional[Sample], Optional[str]]:
    candidates: list[str] = []
    if raw.startswith("samples/"):
        candidates.append(raw[len("samples/") :])
    marker = "/samples/"
    pos = raw.rfind(marker)
    if pos >= 0:
        candidates.append(raw[pos + len(marker) :])
    for rest_all in candidates:
        sid, sep, rel = rest_all.partition("/")
        if not sep or sid not in bench.by_id:
            continue
        sample = bench.by_id[sid]
        for meta in sample.files:
            if norm_path(meta.get("path", "")) == rel:
                return sample, rel
    return None, None


def resolve_file(
    bench: Bench, index: dict[str, list[tuple[Sample, str]]], filename: str
) -> tuple[Optional[Sample], str, str]:
    raw = norm_path(filename)
    if not raw:
        return None, "", "empty"
    exact = index.get(raw, [])
    if len(exact) == 1:
        return exact[0][0], exact[0][1], "exact"
    if len(exact) > 1:
        return None, raw, "ambiguous"
    sample, rel = _lookup_sample_prefix(bench, raw)
    if sample is not None and rel is not None:
        return sample, rel, "sample-prefix"
    candidates: dict[tuple[str, str], Sample] = {}
    for key, entries in index.items():
        if raw == key or raw.endswith("/" + key):
            for sample_item, rel_item in entries:
                candidates[(sample_item.id, rel_item)] = sample_item
    if len(candidates) == 1:
        sid, rel = next(iter(candidates))
        return candidates[(sid, rel)], rel, "suffix"
    if len(candidates) > 1:
        return None, raw, "ambiguous"
    return None, raw, "out-of-scope"


def load_findings(path: Path) -> tuple[list[dict[str, Any]], str, dict[str, Any]]:
    if not path.is_file():
        raise FindingsError(f"findings 文件不存在: {path}")
    digest = sha256_file(path)
    try:
        data = read_json(path)
    except json.JSONDecodeError as exc:
        raise FindingsError(f"findings JSON 解析失败: {exc}") from exc
    except OSError as exc:
        raise FindingsError(f"findings 读取失败: {exc}") from exc
    meta: dict[str, Any] = {}
    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = data.get("findings")
        if items is None and isinstance(data.get("results"), list):
            items = data["results"]
        if not isinstance(items, list):
            raise FindingsError("findings JSON 缺少 findings 数组")
        for key in ("tool", "schema", "version", "rule_version", "rules_source", "target"):
            value = data.get(key)
            if isinstance(value, (str, int, float)) and str(value).strip():
                meta[key] = value
    else:
        raise FindingsError("findings 顶层必须是 object 或数组")
    result: list[dict[str, Any]] = []
    for idx, item in enumerate(items):
        if not isinstance(item, dict):
            raise FindingsError(f"findings[{idx}] 必须是 object")
        result.append(item)
    return result, digest, meta


def parse_location(raw: dict[str, Any]) -> tuple[Optional[int], Optional[int]]:
    line: Optional[int] = None
    offset: Optional[int] = None
    raw_line = raw.get("line")
    if is_int(raw_line) and raw_line > 0:
        line = raw_line
    elif isinstance(raw_line, str) and raw_line.strip().isdigit():
        line = int(raw_line.strip())
    loc = raw.get("location")
    if line is None:
        if is_int(loc) and loc > 0:
            line = loc
        elif isinstance(loc, str):
            text = loc.strip()
            if text.isdigit():
                line = int(text)
            elif HEX_RE.fullmatch(text):
                try:
                    offset = int(text, 16)
                except ValueError:
                    pass

    raw_offset = raw.get("offset")
    if is_int(raw_offset) and raw_offset >= 0:
        offset = raw_offset
    elif isinstance(raw_offset, str) and raw_offset.strip():
        text = raw_offset.strip()
        try:
            offset = int(text, 16) if HEX_RE.fullmatch(text) else int(text, 10)
        except ValueError:
            pass
    return line, offset


def extract_symbol(raw: dict[str, Any]) -> str:
    for key in ("symbol", "function", "sink"):
        value = nonempty_str(raw.get(key))
        if value:
            return value
    parts: list[str] = []
    # 只从真实证据文本推断 symbol；title/rule_id 是元数据，不能当成漏洞证据。
    for key in ("pattern", "match", "evidence", "context", "snippet", "text"):
        value = raw.get(key)
        if isinstance(value, str) and value.strip():
            parts.append(value.strip())
    text = "\n".join(parts)
    for name in (
        "strcpy",
        "strcat",
        "sprintf",
        "gets",
        "system",
        "popen",
        "shell_exec",
        "passthru",
        "eval",
        "exec",
        "cat",
    ):
        if re.search(r"(?<![A-Za-z0-9_])" + re.escape(name) + r"(?![A-Za-z0-9_])", text, re.I):
            return name
    return ""


def finding_line_numbers(
    finding: Finding, byte_cache: dict[tuple[str, str], Optional[bytes]]
) -> tuple[list[int], bool]:
    if finding.line is not None and finding.line > 0:
        return [finding.line], False
    if finding.offset is None or finding.offset < 0:
        return [], False
    key = (finding.sample.id, finding.file)
    if key not in byte_cache:
        path = finding.sample.dir / finding.file
        try:
            byte_cache[key] = path.read_bytes()
        except OSError:
            byte_cache[key] = None
    blob = byte_cache[key]
    if blob is None or finding.offset > len(blob):
        return [], False
    return [blob[: finding.offset].count(b"\n") + 1], True


def normalize_findings(
    raw_items: list[dict[str, Any]], bench: Bench
) -> tuple[list[Finding], list[dict[str, Any]], int]:
    index = build_file_index(bench)
    findings: list[Finding] = []
    out_of_scope: list[dict[str, Any]] = []
    seen: set[tuple[Any, ...]] = set()
    deduplicated = 0

    for idx, raw in enumerate(raw_items):
        file_value = raw.get("file") or raw.get("file_path") or raw.get("path")
        if not isinstance(file_value, str) or not file_value.strip():
            out_of_scope.append(
                {"index": idx, "file": None, "reason": "missing-file"}
            )
            continue
        sample, rel, how = resolve_file(bench, index, file_value)
        if sample is None:
            reason = "ambiguous-relpath" if how == "ambiguous" else "file-not-in-manifest"
            out_of_scope.append(
                {"index": idx, "file": str(file_value), "reason": reason}
            )
            continue
        line, offset = parse_location(raw)
        pattern = (
            nonempty_str(raw.get("pattern"))
            or nonempty_str(raw.get("rule_id"))
            or nonempty_str(raw.get("match"))
            or "(unknown)"
        )
        pattern = pattern[:300]
        rule_id = nonempty_str(raw.get("rule_id")) or nonempty_str(raw.get("rule")) or ""
        title = nonempty_str(raw.get("title")) or ""
        symbol = extract_symbol(raw)
        category = normalize_category(
            raw.get("category") if raw.get("category") is not None else raw.get("type")
        )
        priority = nonempty_str(raw.get("priority")) or ""
        engine = nonempty_str(raw.get("engine")) or ""
        # pattern/evidence 是匹配依据；context/snippet 是扫描器给出的源码证据。
        # title/rule_id/description 是元数据，不参与“文本包含 symbol”匹配。
        text_parts: list[str] = []
        for key in ("pattern", "evidence", "match", "context", "snippet", "text"):
            value = raw.get(key)
            if isinstance(value, str) and value.strip():
                text_parts.append(value.strip())
        text = "\n".join(dict.fromkeys(text_parts))
        line_key: Any = line if line is not None else offset
        dedupe_key = (sample.id, rel, line_key, pattern)
        if dedupe_key in seen:
            deduplicated += 1
            continue
        seen.add(dedupe_key)
        findings.append(
            Finding(
                index=idx,
                raw=raw,
                sample=sample,
                file=rel,
                line=line,
                offset=offset,
                pattern=pattern,
                text=text,
                category=category,
                rule_id=rule_id,
                title=title,
                symbol=symbol,
                priority=priority,
                engine=engine,
            )
        )
    return findings, out_of_scope, deduplicated


# ---------------------------------------------------------------------------
# 匹配与指标
# ---------------------------------------------------------------------------
def get_text_lines(
    bench: Bench, sample_id: str, rel: str, cache: dict[tuple[str, str], list[str]]
) -> list[str]:
    key = (sample_id, rel)
    if key not in cache:
        sample = bench.by_id.get(sample_id)
        if sample is None:
            cache[key] = []
        else:
            try:
                cache[key] = read_text_lines(sample.dir / rel)
            except (OSError, UnicodeDecodeError):
                cache[key] = []
    return cache[key]


def finding_matches_label(
    finding: Finding, label: Label, label_lines: list[str]
) -> bool:
    if finding.sample.id != label.sample_id:
        return False
    if finding.file != label.file:
        return False
    if label_lines and label.line > 0:
        if any(abs(number - label.line) <= 3 for number in finding.lines):
            return True
    fsym = norm_symbol(finding.symbol)
    lsym = norm_symbol(label.symbol)
    if fsym and lsym and fsym == lsym:
        return True
    if lsym:
        if lsym in norm_symbol(finding.pattern):
            return True
        if lsym in norm_symbol(finding.text):
            return True
    return False


def match_labels(
    bench: Bench, findings: list[Finding], labels: list[Label]
) -> dict[tuple[str, str], list[Finding]]:
    text_cache: dict[tuple[str, str], list[str]] = {}
    byte_cache: dict[tuple[str, str], Optional[bytes]] = {}
    finding_lines: dict[int, list[int]] = {}
    for finding in findings:
        lines, _derived = finding_line_numbers(finding, byte_cache)
        finding.lines = lines
        finding_lines[finding.index] = lines
    matches: dict[tuple[str, str], list[Finding]] = {}
    for label in labels:
        key = (label.sample_id, label.id)
        matches[key] = []
        lines = get_text_lines(bench, label.sample_id, label.file, text_cache)
        for finding in findings:
            if finding.sample.id != label.sample_id or finding.file != label.file:
                continue
            if finding_matches_label(finding, label, lines):
                matches[key].append(finding)
    return matches


def build_cases(
    bench: Bench,
    labels: list[Label],
    matches: dict[tuple[str, str], list[Finding]],
) -> tuple[list[dict[str, Any]], set[int]]:
    cases: list[dict[str, Any]] = []
    tp_ids: set[int] = set()
    for label in labels:
        sample = bench.by_id.get(label.sample_id)
        if sample is None:
            continue
        candidates = sorted(
            matches.get((label.sample_id, label.id), []), key=lambda item: item.index
        )
        # 一对一匹配：一个 finding 最多贡献一个 TP，避免两个相邻标签把同一个
        # finding 重复算成两个 TP（那会虚高 recall）。
        chosen = next((item for item in candidates if item.index not in tp_ids), None)
        if chosen is not None:
            tp_ids.add(chosen.index)
            label.matched = True
            label.matched_finding_index = chosen.index
            cases.append(
                {
                    "label": label,
                    "sample": sample,
                    "tp": True,
                    "candidate_count": len(candidates),
                    "finding": chosen,
                }
            )
        else:
            label.matched = False
            label.matched_finding_index = None
            cases.append(
                {
                    "label": label,
                    "sample": sample,
                    "tp": False,
                    "candidate_count": len(candidates),
                    "finding": None,
                }
            )
    return cases, tp_ids


def collect_fp_cases(
    findings: list[Finding], negatives: list[Sample], covered_ids: set[int]
) -> list[dict[str, Any]]:
    """收集评测范围内的 FP。

    covered_ids 是所有标签（含未复核）命中过的 finding；这些 finding 已经
    有标签证据，不能因为“一标签一 TP”的分配顺序而被误判为 FP。
    """
    negative_ids = {sample.id for sample in negatives}
    result: list[dict[str, Any]] = []
    for finding in findings:
        if finding.index in covered_ids:
            continue
        if finding.sample.id in negative_ids:
            reason = "负样本中未命中任何标签"
        else:
            reason = "漏洞样本中未命中任何标签"
        result.append(
            {
                "finding": finding,
                "sample": finding.sample,
                "reason": reason,
            }
        )
    return result


def compute_metrics(
    cases: list[dict[str, Any]], fp_cases: list[dict[str, Any]], negatives: list[Sample]
) -> dict[str, Any]:
    tp = sum(1 for case in cases if case["tp"])
    fn = len(cases) - tp
    fp = len(fp_cases)
    precision = safe_div(tp, tp + fp)
    recall = safe_div(tp, tp + fn)
    if precision is None or recall is None:
        f1 = None
    elif precision + recall == 0:
        f1 = 0.0
    else:
        f1 = 2 * precision * recall / (precision + recall)
    negative_ids = {sample.id for sample in negatives}
    flagged = {
        case["finding"].sample.id
        for case in fp_cases
        if case["finding"].sample.id in negative_ids
    }
    tn = max(0, len(negatives) - len(flagged))
    fpr = safe_div(len(flagged), len(negatives))
    fnr = safe_div(fn, tp + fn)
    return {
        "tp": tp,
        "fp": fp,
        "fn": fn,
        "tn": tn,
        "positive_labels": tp + fn,
        "negative_samples": len(negatives),
        "negative_samples_flagged": len(flagged),
        "precision": round6(precision),
        "recall": round6(recall),
        "f1": round6(f1),
        "fpr": round6(fpr),
        "fnr": round6(fnr),
    }


def group_metrics(
    cases: list[dict[str, Any]],
    fp_cases: list[dict[str, Any]],
    negatives: list[Sample],
    key_func: Any,
    sort_key: Any,
    fp_key_func: Optional[Any] = None,
    negative_key_func: Optional[Any] = None,
) -> list[dict[str, Any]]:
    keys: set[str] = set()
    for case in cases:
        keys.add(str(key_func(case)))
    if fp_key_func is not None:
        for case in fp_cases:
            keys.add(str(fp_key_func(case)))
    if negative_key_func is not None:
        for sample in negatives:
            keys.add(str(negative_key_func(sample)))
    rows: list[dict[str, Any]] = []
    for key in sorted(keys, key=sort_key):
        sub_cases = [case for case in cases if str(key_func(case)) == key]
        if fp_key_func is None:
            sub_fps = list(fp_cases)
        else:
            sub_fps = [case for case in fp_cases if str(fp_key_func(case)) == key]
        if negative_key_func is None:
            sub_negatives = list(negatives)
        else:
            sub_negatives = [
                sample
                for sample in negatives
                if str(negative_key_func(sample)) == key
            ]
        if not sub_cases and not sub_negatives and not sub_fps:
            continue
        metrics = compute_metrics(sub_cases, sub_fps, sub_negatives)
        rows.append({"key": key, **metrics})
    return rows


def macro_metrics(groups: list[dict[str, Any]]) -> dict[str, Any]:
    positive_groups = [group for group in groups if group["positive_labels"] > 0]
    negative_groups = [group for group in groups if group["negative_samples"] > 0]

    def mean_of(field: str, source: list[dict[str, Any]], zero_if_undefined: bool = False) -> Optional[float]:
        values = []
        for group in source:
            value = group.get(field)
            if value is None:
                if zero_if_undefined:
                    values.append(0.0)
            else:
                values.append(value)
        if not values:
            return None
        return round6(sum(values) / len(values))

    return {
        "groups_with_positive": len(positive_groups),
        "groups_with_negative": len(negative_groups),
        # 某类别没有 TP/FP 时 precision/F1 在数学上未定义；macro 按 0 计入，
        # 避免把“没有可判定的正例”误算成满分，抬高总体质量。
        "precision": mean_of("precision", positive_groups, zero_if_undefined=True),
        "recall": mean_of("recall", positive_groups),
        "f1": mean_of("f1", positive_groups, zero_if_undefined=True),
        "fpr": mean_of("fpr", negative_groups),
        "fnr": mean_of("fnr", positive_groups),
    }


def label_detail(label: Label, sample: Sample, **extra: Any) -> dict[str, Any]:
    result = {
        "label_id": label.id,
        "sample_id": label.sample_id,
        "split": sample.split,
        "arch": sample.arch,
        "kind": sample.kind,
        "category": label.category,
        "file": label.file,
        "line": label.line,
        "symbol": label.symbol,
        "cwe": label.cwe,
        "severity": label.severity,
        "evidence": label.evidence,
        "review": label.review,
    }
    result.update(extra)
    return result


def finding_detail(finding: Finding, **extra: Any) -> dict[str, Any]:
    result = {
        "index": finding.index,
        "sample_id": finding.sample.id,
        "sample_kind": finding.sample.kind,
        "arch": finding.sample.arch,
        "split": finding.sample.split,
        "file": finding.file,
        "line": finding.line,
        "offset": finding.offset,
        "pattern": finding.pattern,
        "category": finding.category,
        "rule_id": finding.rule_id,
        "priority": finding.priority,
        "engine": finding.engine,
        "symbol": finding.symbol,
    }
    result.update(extra)
    return result


def detail_block(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "count": len(items),
        "limit": MAX_DETAILS,
        "truncated": len(items) > MAX_DETAILS,
        "items": items[:MAX_DETAILS],
    }


def evaluate_slice(
    bench: Bench, all_findings: list[Finding], split_scope: str, strict: bool
) -> dict[str, Any]:
    selected_samples = [
        sample
        for sample in bench.samples
        if split_scope == "all" or sample.split == split_scope
    ]
    sample_ids = {sample.id for sample in selected_samples}
    findings = [finding for finding in all_findings if finding.sample.id in sample_ids]
    labels = [label for sample in selected_samples for label in sample.labels]
    reviewed = [label for label in labels if label.reviewed]
    pending = [label for label in labels if not label.reviewed]
    negatives = [sample for sample in selected_samples if sample.kind in NEGATIVE_KINDS]
    matches = match_labels(bench, findings, labels)

    cases, tp_ids = build_cases(bench, reviewed, matches)
    # 所有标签（含未复核）命中的 finding 都已有标签证据；重复命中不能被
    # 当成 FP，否则同一漏洞的多条规则输出会虚增误报。
    covered_ids = {
        finding.index
        for candidates in matches.values()
        for finding in candidates
    }
    fp_cases = collect_fp_cases(findings, negatives, covered_ids)
    micro = compute_metrics(cases, fp_cases, negatives)

    by_category = group_metrics(
        cases,
        fp_cases,
        negatives,
        lambda case: normalize_category(case["label"].category),
        category_sort_key,
        fp_key_func=lambda case: normalize_category(case["finding"].category),
    )
    by_arch = group_metrics(
        cases,
        fp_cases,
        negatives,
        lambda case: case["sample"].arch,
        arch_sort_key,
        fp_key_func=lambda case: case["sample"].arch,
        negative_key_func=lambda sample: sample.arch,
    )
    by_split = group_metrics(
        cases,
        fp_cases,
        negatives,
        lambda case: case["sample"].split,
        split_sort_key,
        fp_key_func=lambda case: case["sample"].split,
        negative_key_func=lambda sample: sample.split,
    )
    macro = macro_metrics(by_category)

    tp_details: list[dict[str, Any]] = []
    fn_details: list[dict[str, Any]] = []
    for case in cases:
        label: Label = case["label"]
        sample: Sample = case["sample"]
        if case["tp"]:
            chosen: Finding = case["finding"]
            tp_details.append(
                label_detail(
                    label,
                    sample,
                    finding_index=chosen.index,
                    finding_line=chosen.line,
                    finding_offset=chosen.offset,
                    pattern=chosen.pattern,
                    rule_id=chosen.rule_id,
                    candidate_count=case["candidate_count"],
                )
            )
        else:
            reason = "line±3 / symbol / pattern / evidence 均未命中"
            if case["candidate_count"]:
                reason = (
                    "存在候选 finding，但候选已被其他标签占用"
                    "（同一 finding 最多贡献一个 TP）"
                )
            fn_details.append(
                label_detail(
                    label,
                    sample,
                    candidate_count=case["candidate_count"],
                    reason=reason,
                )
            )

    fp_details = [
        finding_detail(case["finding"], reason=case["reason"])
        for case in fp_cases
    ]
    unmatched_vuln = [
        finding
        for finding in findings
        if finding.sample.kind == "vuln" and finding.index not in covered_ids
    ]
    unmatched_details = [
        finding_detail(finding, reason="漏洞样本中的 finding 未命中任何标签，已计入 FP")
        for finding in unmatched_vuln
    ]
    reviewed_match_ids = {
        finding.index
        for label in reviewed
        for finding in matches.get((label.sample_id, label.id), [])
    }
    duplicate_details = [
        finding_detail(
            finding,
            reason="命中 reviewed 标签但未计入 TP（同一标签只计一次 TP）",
        )
        for finding in findings
        if finding.index in reviewed_match_ids and finding.index not in tp_ids
    ]

    pending_details: list[dict[str, Any]] = []
    for label in pending:
        sample = bench.by_id[label.sample_id]
        candidates = matches.get((label.sample_id, label.id), [])
        pending_details.append(
            label_detail(
                label,
                sample,
                in_denominator=False,
                has_matching_finding=bool(candidates),
                matching_finding_index=candidates[0].index if candidates else None,
                reason="review 不是 reviewed，主指标不纳入 P/R 分母",
            )
        )

    provisional: Optional[dict[str, Any]] = None
    # 只有存在未复核标签时才需要敏感性分析；全部 reviewed 时它只会重复主指标。
    if not strict and pending:
        all_cases, all_tp_ids = build_cases(bench, labels, matches)
        all_fp_cases = collect_fp_cases(findings, negatives, covered_ids)
        provisional_metrics = compute_metrics(all_cases, all_fp_cases, negatives)
        provisional = {
            "authoritative": False,
            "reason": "包含 needs_review/unknown 标签，只用于敏感性分析，不得作为质量结论",
            "labels_included": len(labels),
            "metrics": provisional_metrics,
        }

    split_counts: dict[str, int] = {name: 0 for name in SPLIT_ORDER}
    for sample in selected_samples:
        split_counts[sample.split] = split_counts.get(sample.split, 0) + 1

    return {
        "scope": {
            "split": split_scope,
            "samples": len(selected_samples),
            "samples_by_split": split_counts,
            "findings_in_scope": len(findings),
            "findings_total": len(all_findings),
            "findings_excluded_by_split": len(all_findings) - len(findings),
            "labels_total": len(labels),
            "labels_reviewed": len(reviewed),
            "labels_not_evaluable": len(pending),
            "negative_samples": len(negatives),
        },
        "confusion_matrix": {
            "tp": micro["tp"],
            "fp": micro["fp"],
            "fn": micro["fn"],
            "tn": micro["tn"],
        },
        "micro": micro,
        "macro": macro,
        "by_category": by_category,
        "by_arch": by_arch,
        "by_split": by_split,
        "provisional": provisional,
        "details": {
            "true_positives": detail_block(tp_details),
            "false_negatives": detail_block(fn_details),
            "false_positives": detail_block(fp_details),
            "unmatched_vulnerable_findings": detail_block(unmatched_details),
            "duplicate_reviewed_matches": detail_block(duplicate_details),
            "not_evaluable": detail_block(pending_details),
        },
    }


# ---------------------------------------------------------------------------
# 基线、可复现性记录与结果组装
# ---------------------------------------------------------------------------
def compare_baseline(
    baseline_path: Path,
    current: dict[str, Any],
    max_recall_drop: float,
    max_fpr_rise: float,
) -> dict[str, Any]:
    path = baseline_path.resolve()
    if not path.is_file():
        raise InputError(f"基线文件不存在: {path}")
    try:
        data = read_json(path)
    except json.JSONDecodeError as exc:
        raise InputError(f"基线 JSON 解析失败: {exc}") from exc
    except OSError as exc:
        raise InputError(f"基线读取失败: {exc}") from exc
    if not isinstance(data, dict):
        raise InputError("基线顶层必须是 object")
    if data.get("schema") != SCHEMA_RESULT:
        raise InputError(
            f"基线 schema 必须是 {SCHEMA_RESULT!r}，实际 {data.get('schema')!r}"
        )
    previous = data.get("metrics", {}).get("micro") if isinstance(data.get("metrics"), dict) else None
    if not isinstance(previous, dict):
        raise InputError("基线缺少 metrics.micro")
    for field in ("recall", "fpr", "f1"):
        value = previous.get(field)
        if not isinstance(value, (int, float)) or isinstance(value, bool):
            raise InputError(f"基线 metrics.micro.{field} 必须是数值")
    current_recall = current.get("recall")
    current_fpr = current.get("fpr")
    current_f1 = current.get("f1")
    if current_recall is None or current_fpr is None:
        raise InputError("当前结果缺少 recall 或 FPR，无法与基线比较")

    recall_drop = round6(float(previous["recall"]) - float(current_recall))
    fpr_rise = round6(float(current_fpr) - float(previous["fpr"]))
    f1_change = (
        round6(float(current_f1) - float(previous["f1"]))
        if current_f1 is not None and isinstance(previous.get("f1"), (int, float))
        else None
    )
    reasons: list[str] = []
    if recall_drop is not None and recall_drop > max_recall_drop + 1e-12:
        reasons.append(
            f"recall 下降 {recall_drop:.6f} 超过阈值 {max_recall_drop:.6f}"
        )
    if fpr_rise is not None and fpr_rise > max_fpr_rise + 1e-12:
        reasons.append(f"FPR 上升 {fpr_rise:.6f} 超过阈值 {max_fpr_rise:.6f}")
    return {
        "path": str(path),
        "sha256": sha256_file(path),
        "schema": data.get("schema"),
        "previous": {
            "recall": previous["recall"],
            "fpr": previous["fpr"],
            "f1": previous.get("f1"),
        },
        "current": {
            "recall": current_recall,
            "fpr": current_fpr,
            "f1": current_f1,
        },
        "deltas": {
            "recall_drop": recall_drop,
            "fpr_rise": fpr_rise,
            "f1_change": f1_change,
        },
        "thresholds": {
            "max_recall_drop": max_recall_drop,
            "max_fpr_rise": max_fpr_rise,
        },
        "regression": bool(reasons),
        "reasons": reasons,
    }


def git_commit(root: Path) -> str:
    try:
        completed = subprocess.run(
            ["git", "-C", str(root), "rev-parse", "HEAD"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=5,
        )
    except (OSError, subprocess.SubprocessError):
        return "unknown"
    if completed.returncode != 0:
        return "unknown"
    value = completed.stdout.strip()
    return value if value else "unknown"


def collect_dataset_info(bench: Bench) -> dict[str, Any]:
    dataset = bench.data.get("dataset", {}) if isinstance(bench.data, dict) else {}
    kind_counts = {kind: 0 for kind in KIND_ORDER}
    arch_counts = {arch: 0 for arch in ARCH_ORDER}
    label_total = 0
    reviewed = 0
    pending = 0
    categories: dict[str, int] = {}
    for sample in bench.samples:
        kind_counts[sample.kind] = kind_counts.get(sample.kind, 0) + 1
        arch_counts[sample.arch] = arch_counts.get(sample.arch, 0) + 1
        for label in sample.labels:
            label_total += 1
            if label.reviewed:
                reviewed += 1
            else:
                pending += 1
            category = normalize_category(label.category)
            categories[category] = categories.get(category, 0) + 1
    return {
        "name": dataset.get("name"),
        "version": dataset.get("version"),
        "created": dataset.get("created"),
        "kind": dataset.get("kind"),
        "license": dataset.get("license"),
        "description": dataset.get("description"),
        "real_firmware": dataset.get("real_firmware"),
        "manifest_sha256": bench.sha256,
        "manifest_path": str(bench.manifest_path),
        "samples": len(bench.samples),
        "splits": {name: len(bench.splits.get(name, [])) for name in SPLIT_ORDER},
        "split_ids": {name: list(bench.splits.get(name, [])) for name in SPLIT_ORDER},
        "arch_counts": {key: arch_counts.get(key, 0) for key in ARCH_ORDER},
        "kind_counts": {key: kind_counts.get(key, 0) for key in KIND_ORDER},
        "label_counts": {
            "total": label_total,
            "reviewed": reviewed,
            "not_evaluable": pending,
        },
        "label_categories": {
            key: categories[key]
            for key in sorted(categories, key=category_sort_key)
        },
        "rule_version": bench.data.get("rule_version"),
        "tool_version": bench.data.get("tool_version"),
    }


def collect_reproducibility(
    bench: Bench,
    findings_path: Path,
    findings_sha: str,
    findings_meta: dict[str, Any],
    parameters: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    try:
        script_sha = sha256_file(Path(__file__).resolve())
    except OSError:
        script_sha = "unknown"
    return {
        "manifest_sha256": bench.sha256,
        "findings_sha256": findings_sha,
        "script_sha256": script_sha,
        "git_commit": git_commit(bench.root),
        "python_version": platform.python_version(),
        "python_implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "manifest_rule_version": bench.data.get("rule_version"),
        "manifest_tool_version": bench.data.get("tool_version"),
        "findings_tool": findings_meta.get("tool"),
        "findings_schema": findings_meta.get("schema"),
        "findings_version": findings_meta.get("version"),
        "findings_rule_version": findings_meta.get("rule_version") or findings_meta.get("version"),
        "findings_rules_source": findings_meta.get("rules_source"),
        "findings_path": str(findings_path.resolve()),
        "generated_at": generated_at,
        "arguments": parameters,
    }


def build_result(
    bench: Bench,
    findings_path: Path,
    findings_sha: str,
    findings_meta: dict[str, Any],
    raw_total: int,
    all_findings: list[Finding],
    out_of_scope: list[dict[str, Any]],
    deduplicated: int,
    slice_result: dict[str, Any],
    baseline_result: Optional[dict[str, Any]],
    parameters: dict[str, Any],
    generated_at: str,
) -> dict[str, Any]:
    regression = baseline_result["regression"] if baseline_result else None
    reasons = baseline_result["reasons"] if baseline_result else []
    not_evaluable = slice_result["details"]["not_evaluable"]
    result = {
        "schema": SCHEMA_RESULT,
        "tool": TOOL_NAME,
        "tool_version": TOOL_VERSION,
        "status": "regression" if regression else "ok",
        "synthetic": True,
        "regression": regression,
        "regression_reasons": reasons,
        "generated_at": generated_at,
        "dataset": collect_dataset_info(bench),
        "parameters": parameters,
        "validation": {
            "status": "ok",
            "strict": bool(parameters.get("strict")),
            "warnings": list(bench.warnings),
            "warning_count": len(bench.warnings),
        },
        "scope": slice_result["scope"],
        "confusion_matrix": slice_result["confusion_matrix"],
        "metrics": {
            "micro": slice_result["micro"],
            "macro": slice_result["macro"],
            "by_category": slice_result["by_category"],
            "by_arch": slice_result["by_arch"],
            "by_split": slice_result["by_split"],
        },
        "provisional": slice_result["provisional"],
        "not_evaluable": not_evaluable,
        "out_of_scope": {
            **detail_block(out_of_scope),
            "note": "file 不在 manifest 样本中或路径歧义，不进入 P/R/FPR 分母",
        },
        "excluded_by_split": slice_result["scope"]["findings_excluded_by_split"],
        "findings_source": {
            "path": str(findings_path.resolve()),
            "sha256": findings_sha,
            "meta": findings_meta,
            "input_total": raw_total,
            "normalized_total": len(all_findings),
            "deduplicated": deduplicated,
        },
        "details": slice_result["details"],
        "reproducibility": collect_reproducibility(
            bench,
            findings_path,
            findings_sha,
            findings_meta,
            parameters,
            generated_at,
        ),
        "baseline": baseline_result,
        "notes": [
            "合成集只验证评测契约与指标计算，不能推断真实固件 precision/recall/FPR。",
            "主指标只使用 review=reviewed 的标签；needs_review/unknown 单列且不进入 P/R 分母。",
            "FPR 为样本级：至少有一个 FP 的 safe/hard-negative 样本数 / 负样本总数。",
            "FP 以 finding 为单位，FN 以 reviewed 标签为单位，TN 为未误报负样本数；"
            "同一 finding 最多贡献一个 TP，同一标签只计一次 TP。",
            "findings 按 file+line+pattern 去重后再评测；out_of_scope 与 split 外 finding 不进入指标。",
            "类别行的 FPR 分母为全部负样本，FP 按 finding.category 归组；架构/划分行按样本归组。",
        ],
    }
    return result


def location_text(item: dict[str, Any]) -> str:
    file_value = str(item.get("file") or "?")
    line = item.get("line")
    if isinstance(line, int) and line > 0:
        return f"{file_value}:{line}"
    offset = item.get("offset")
    if isinstance(offset, int) and offset >= 0:
        return f"{file_value}@0x{offset:x}"
    return file_value


def render_group_table(title: str, rows: list[dict[str, Any]]) -> list[str]:
    lines = [
        f"### {title}",
        "",
        "| 分组 | TP | FP | FN | Precision | Recall | F1 | FPR | 负样本 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    if not rows:
        lines.append("| （无数据） | 0 | 0 | 0 | - | - | - | - | 0 |")
    for row in rows:
        lines.append(
            "| "
            + " | ".join(
                [
                    md_cell(row.get("key")),
                    str(row.get("tp", 0)),
                    str(row.get("fp", 0)),
                    str(row.get("fn", 0)),
                    fmt_num(row.get("precision")),
                    fmt_num(row.get("recall")),
                    fmt_num(row.get("f1")),
                    fmt_num(row.get("fpr")),
                    str(row.get("negative_samples", 0)),
                ]
            )
            + " |"
        )
    lines.append("")
    return lines


def render_report(result: dict[str, Any]) -> str:
    dataset = result["dataset"]
    scope = result["scope"]
    metrics = result["metrics"]
    micro = metrics["micro"]
    macro = metrics["macro"]
    confusion = result["confusion_matrix"]
    parameters = result["parameters"]
    details = result["details"]
    lines: list[str] = []
    lines.append("# IoT 固件漏洞检测基准报告（合成集）")
    lines.append("")
    lines.append(f"生成时间：{result['generated_at']}")
    lines.append("")
    lines.append(
        "> **边界声明**：本报告使用 100% 手工构造的合成 rootfs 片段，"
        "不是真实固件评测。它可以证明校验、匹配、指标和基线门禁可复现，"
        "但不能推断真实设备上的 precision/recall/FPR。"
    )
    lines.append("")
    lines.append("## 数据集简介")
    lines.append("")
    lines.append(f"- 名称：{md_cell(dataset.get('name'))}")
    lines.append(f"- 版本：{md_cell(dataset.get('version'))}")
    lines.append(f"- 类型：{md_cell(dataset.get('kind'))}（合成集）")
    lines.append(f"- 创建日期：{md_cell(dataset.get('created'))}")
    lines.append(f"- 许可证：{md_cell(dataset.get('license'))}")
    lines.append(f"- 真实固件：{md_cell(dataset.get('real_firmware'))}")
    lines.append(f"- 样本数：{dataset.get('samples')}")
    lines.append(
        "- 划分：dev {} 个，holdout {} 个".format(
            dataset.get("splits", {}).get("dev", 0),
            dataset.get("splits", {}).get("holdout", 0),
        )
    )
    lines.append(
        "- 架构分布："
        + "，".join(
            f"{key}={value}" for key, value in dataset.get("arch_counts", {}).items()
        )
    )
    lines.append(
        "- 样本类型："
        + "，".join(
            f"{key}={value}" for key, value in dataset.get("kind_counts", {}).items()
        )
    )
    label_counts = dataset.get("label_counts", {})
    lines.append(
        "- 标签：总数 {}，reviewed {}，不可评估 {}".format(
            label_counts.get("total", 0),
            label_counts.get("reviewed", 0),
            label_counts.get("not_evaluable", 0),
        )
    )
    lines.append(
        "- 类别覆盖："
        + "，".join(
            f"{key}={value}" for key, value in dataset.get("label_categories", {}).items()
        )
    )
    lines.append(f"- manifest SHA-256：{dataset.get('manifest_sha256')}")
    lines.append(f"- manifest 规则/工具版本：{dataset.get('rule_version')} / {dataset.get('tool_version')}")
    lines.append("")
    lines.append("## 评测范围与参数")
    lines.append("")
    lines.append(f"- 划分：{parameters.get('split')}")
    lines.append(f"- 严格模式：{'是' if parameters.get('strict') else '否'}")
    lines.append(
        f"- 范围内样本 {scope.get('samples')} 个，reviewed 标签 {scope.get('labels_reviewed')} 个，"
        f"不可评估标签 {scope.get('labels_not_evaluable')} 个，负样本 {scope.get('negative_samples')} 个"
    )
    findings_source = result.get("findings_source", {})
    lines.append(
        f"- findings：输入 {findings_source.get('input_total')} 条，manifest 内 "
        f"{findings_source.get('normalized_total')} 条，范围内 {scope.get('findings_in_scope')} 条，"
        f"因 split 排除 {scope.get('findings_excluded_by_split')} 条"
    )
    lines.append(
        f"- findings 去重 {findings_source.get('deduplicated')} 条，"
        f"out_of_scope {result['out_of_scope'].get('count')} 条"
    )
    warnings = result.get("validation", {}).get("warnings", [])
    if warnings:
        lines.append(f"- 校验警告 {len(warnings)} 条：")
        for warning in warnings[:8]:
            lines.append(f"  - {warning}")
        if len(warnings) > 8:
            lines.append(f"  - （其余 {len(warnings) - 8} 条见 JSON validation.warnings）")
    lines.append("")
    lines.append("## 混淆矩阵与主指标")
    lines.append("")
    lines.append("| 指标 | 数值 |")
    lines.append("| --- | ---: |")
    lines.append(f"| TP | {confusion.get('tp', 0)} |")
    lines.append(f"| FP | {confusion.get('fp', 0)} |")
    lines.append(f"| FN | {confusion.get('fn', 0)} |")
    lines.append(f"| TN（负样本） | {confusion.get('tn', 0)} |")
    lines.append(f"| Precision | {fmt_num(micro.get('precision'))} |")
    lines.append(f"| Recall | {fmt_num(micro.get('recall'))} |")
    lines.append(f"| F1 | {fmt_num(micro.get('f1'))} |")
    lines.append(f"| FPR（样本级） | {fmt_num(micro.get('fpr'))} |")
    lines.append(f"| 漏报率 | {fmt_num(micro.get('fnr'))} |")
    lines.append(
        f"| 被标记负样本 | {micro.get('negative_samples_flagged', 0)} / {micro.get('negative_samples', 0)} |"
    )
    lines.append("")
    lines.append(
        "主指标仅使用 reviewed 标签。Precision = TP/(TP+FP)，Recall = TP/(TP+FN)，"
        "F1 = 2PR/(P+R)，FPR = 至少一个 FP 的负样本数 / 负样本总数，漏报率 = FN/(TP+FN)。"
        "FP 以 finding 为单位，FN 以 reviewed 标签为单位，TN 为未误报负样本数；"
        "同一 finding 最多贡献一个 TP，同一标签只计一次 TP。"
    )
    lines.append("")
    lines.extend(render_group_table("按类别", metrics.get("by_category", [])))
    lines.extend(render_group_table("按架构", metrics.get("by_arch", [])))
    lines.extend(render_group_table("按划分", metrics.get("by_split", [])))
    lines.append("### 聚合")
    lines.append("")
    lines.append("| 聚合 | Precision | Recall | F1 | FPR |")
    lines.append("| --- | ---: | ---: | ---: | ---: |")
    lines.append(
        "| Micro | {} | {} | {} | {} |".format(
            fmt_num(micro.get("precision")),
            fmt_num(micro.get("recall")),
            fmt_num(micro.get("f1")),
            fmt_num(micro.get("fpr")),
        )
    )
    lines.append(
        "| Macro | {} | {} | {} | {} |".format(
            fmt_num(macro.get("precision")),
            fmt_num(macro.get("recall")),
            fmt_num(macro.get("f1")),
            fmt_num(macro.get("fpr")),
        )
    )
    lines.append("")
    lines.append(
        "Micro 为所有 reviewed 标签/负样本合并计算；Macro 为按类别分组的未加权平均，"
        "无 TP/FP 的类别其 precision/F1 未定义、按 0 计入。"
        "类别行的 FPR 分母为全部负样本，FP 按 finding.category 归组；"
        "架构和划分行的 FPR 按对应样本归组。"
    )
    lines.append("")
    if result.get("provisional"):
        provisional = result["provisional"]
        pmetrics = provisional.get("metrics", {})
        lines.append("## 敏感性分析（非权威）")
        lines.append("")
        lines.append(
            "以下指标把 needs_review/unknown 标签一并计入，仅用于观察未复核标签的影响，"
            "不得作为质量结论或基线门禁依据。"
        )
        lines.append("")
        lines.append("| 指标 | 数值 |")
        lines.append("| --- | ---: |")
        lines.append(f"| 纳入标签 | {provisional.get('labels_included', 0)} |")
        lines.append(f"| TP | {pmetrics.get('tp', 0)} |")
        lines.append(f"| FP | {pmetrics.get('fp', 0)} |")
        lines.append(f"| FN | {pmetrics.get('fn', 0)} |")
        lines.append(f"| Precision | {fmt_num(pmetrics.get('precision'))} |")
        lines.append(f"| Recall | {fmt_num(pmetrics.get('recall'))} |")
        lines.append(f"| F1 | {fmt_num(pmetrics.get('f1'))} |")
        lines.append(f"| FPR | {fmt_num(pmetrics.get('fpr'))} |")
        lines.append("")
    elif parameters.get("strict"):
        lines.append("## 敏感性分析")
        lines.append("")
        lines.append("--strict 已启用，未计算包含未复核标签的 provisional 指标。")
        lines.append("")
    lines.append("## 误报与漏报样例（各前 10 条）")
    lines.append("")
    lines.append("### 误报（FP）")
    lines.append("")
    fp_items = details.get("false_positives", {}).get("items", [])
    if not fp_items:
        lines.append("无。")
    else:
        for item in fp_items[:10]:
            lines.append(
                "- {}，样本 {}（{}），类别 {}，规则 {}；原因：{}".format(
                    location_text(item),
                    item.get("sample_id"),
                    item.get("sample_kind"),
                    item.get("category"),
                    item.get("pattern"),
                    item.get("reason"),
                )
            )
    lines.append("")
    lines.append("### 漏报（FN）")
    lines.append("")
    fn_items = details.get("false_negatives", {}).get("items", [])
    if not fn_items:
        lines.append("无。")
    else:
        for item in fn_items[:10]:
            lines.append(
                "- {}，标签 {}（{}，review={}），符号 {}；原因：{}".format(
                    location_text(item),
                    item.get("label_id"),
                    item.get("category"),
                    item.get("review"),
                    item.get("symbol"),
                    item.get("reason"),
                )
            )
    lines.append("")
    lines.append("## 无法评估的标签")
    lines.append("")
    not_evaluable = result.get("not_evaluable", {})
    ne_items = not_evaluable.get("items", [])
    if not ne_items:
        lines.append("无。")
    else:
        lines.append(
            "以下标签的 review 不是 reviewed，不计入主指标 P/R 分母"
            + ("；--strict 下全部按不可评估披露。" if parameters.get("strict") else "。")
        )
        lines.append("")
        for item in ne_items[:10]:
            matched = "有匹配 finding" if item.get("has_matching_finding") else "无匹配 finding"
            lines.append(
                "- {}，标签 {}，review={}，{}，{}".format(
                    location_text(item),
                    item.get("label_id"),
                    item.get("review"),
                    matched,
                    item.get("reason"),
                )
            )
        if not_evaluable.get("truncated"):
            lines.append(f"- 其余 {not_evaluable.get('count', 0) - 10} 条见 JSON not_evaluable.items。")
    lines.append("")
    out_scope = result.get("out_of_scope", {})
    if out_scope.get("count"):
        lines.append("## 范围外 findings")
        lines.append("")
        lines.append(
            f"共 {out_scope.get('count')} 条 finding 的 file 不在 manifest 样本中或路径歧义，"
            "未进入 P/R/FPR 分母。"
        )
        for item in out_scope.get("items", [])[:10]:
            lines.append(
                "- index {}，file {}，原因 {}".format(
                    item.get("index"), item.get("file") or "?", item.get("reason")
                )
            )
        lines.append("")
    lines.append("## 基线比较")
    lines.append("")
    baseline = result.get("baseline")
    if baseline:
        previous = baseline.get("previous", {})
        current = baseline.get("current", {})
        deltas = baseline.get("deltas", {})
        lines.append("| 指标 | 基线 | 当前 | 变化 |")
        lines.append("| --- | ---: | ---: | ---: |")
        lines.append(
            f"| Recall | {fmt_num(previous.get('recall'))} | {fmt_num(current.get('recall'))} | "
            f"下降 {fmt_num(deltas.get('recall_drop'))} |"
        )
        lines.append(
            f"| FPR | {fmt_num(previous.get('fpr'))} | {fmt_num(current.get('fpr'))} | "
            f"上升 {fmt_num(deltas.get('fpr_rise'))} |"
        )
        lines.append(
            f"| F1 | {fmt_num(previous.get('f1'))} | {fmt_num(current.get('f1'))} | "
            f"变化 {fmt_num(deltas.get('f1_change'))} |"
        )
        lines.append("")
        thresholds = baseline.get("thresholds", {})
        lines.append(
            "- 阈值：recall 最大下降 {}，FPR 最大上升 {}".format(
                thresholds.get("max_recall_drop"), thresholds.get("max_fpr_rise")
            )
        )
        lines.append(f"- 质量回归：{'是' if baseline.get('regression') else '否'}")
        lines.append(
            "- regression: {}".format("true" if baseline.get("regression") else "false")
        )
        for reason in baseline.get("reasons", []):
            lines.append(f"  - {reason}")
        lines.append("")
    else:
        lines.append("未提供 --baseline，regression = null，退出码 0。")
        lines.append("")
    lines.append("## 复现信息")
    lines.append("")
    repro = result.get("reproducibility", {})
    lines.append(f"- manifest SHA-256：{repro.get('manifest_sha256')}")
    lines.append(f"- findings SHA-256：{repro.get('findings_sha256')}")
    lines.append(f"- 评测脚本 SHA-256：{repro.get('script_sha256')}")
    lines.append(f"- git commit：{repro.get('git_commit')}")
    lines.append(
        "- Python：{} {}（{}）".format(
            repro.get("python_implementation"),
            repro.get("python_version"),
            repro.get("platform"),
        )
    )
    lines.append(
        "- manifest 规则/工具版本：{} / {}".format(
            repro.get("manifest_rule_version"), repro.get("manifest_tool_version")
        )
    )
    lines.append(
        "- findings 工具/版本/规则：{} / {} / {}".format(
            repro.get("findings_tool"),
            repro.get("findings_version"),
            repro.get("findings_rule_version"),
        )
    )
    lines.append(f"- 生成时间（UTC）：{repro.get('generated_at')}")
    lines.append("")
    lines.append("运行参数：")
    lines.append("")
    lines.append("~~~text")
    lines.append("python scripts/bench_eval.py " + " ".join(sys.argv[1:]))
    lines.append("~~~")
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append(
        "本报告由 bench_eval.py {} 生成。合成集不是真实固件评测；"
        "接入真实固件后必须重新标注、重新计算指标并单独报告。".format(TOOL_VERSION)
    )
    lines.append("")
    return "\n".join(lines)


def console_summary(result: dict[str, Any], json_path: Optional[Path], md_path: Optional[Path]) -> None:
    dataset = result["dataset"]
    scope = result["scope"]
    micro = result["metrics"]["micro"]
    print(
        "基准校验通过：{} 个样本（dev {} / holdout {}），{} 个 reviewed 标签，{} 个负样本".format(
            dataset.get("samples"),
            dataset.get("splits", {}).get("dev", 0),
            dataset.get("splits", {}).get("holdout", 0),
            scope.get("labels_reviewed"),
            scope.get("negative_samples"),
        )
    )
    findings_source = result.get("findings_source", {})
    print(
        "评测范围：split={}，findings 输入 {} 条，manifest 内 {} 条，范围内 {} 条，"
        "去重 {} 条，out_of_scope {} 条".format(
            scope.get("split"),
            findings_source.get("input_total"),
            findings_source.get("normalized_total"),
            scope.get("findings_in_scope"),
            findings_source.get("deduplicated"),
            result["out_of_scope"].get("count"),
        )
    )
    if micro.get("precision") is None:
        print("主指标：无可计算的正样本或 findings，Precision=N/A")
    else:
        print(
            "主指标：TP={} FP={} FN={} precision={} recall={} F1={} FPR={}".format(
                micro.get("tp"),
                micro.get("fp"),
                micro.get("fn"),
                fmt_num(micro.get("precision")),
                fmt_num(micro.get("recall")),
                fmt_num(micro.get("f1")),
                fmt_num(micro.get("fpr")),
            )
        )
    if result.get("provisional"):
        pmetrics = result["provisional"].get("metrics", {})
        print(
            "敏感性分析（非权威）：recall={} F1={}（纳入 {} 个未复核标签）".format(
                fmt_num(pmetrics.get("recall")),
                fmt_num(pmetrics.get("f1")),
                result["provisional"].get("labels_included"),
            )
        )
    if result.get("regression") is None:
        print("质量门禁：未提供基线，regression=null，退出码 0")
    elif result.get("regression"):
        print("质量门禁：检测到质量回归，退出码 3")
    else:
        print("质量门禁：未发现质量回归，退出码 0")
    if json_path is not None:
        print(f"JSON 结果：{json_path.resolve()}")
    if md_path is not None:
        print(f"Markdown 报告：{md_path.resolve()}")


def _add_eval_arguments(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--manifest", type=Path, required=True, help="bench manifest JSON 路径")
    parser.add_argument(
        "--findings",
        type=Path,
        required=True,
        help="sink_scan 或兼容格式的 findings JSON 路径",
    )
    parser.add_argument(
        "--split",
        choices=("dev", "holdout", "all"),
        default="all",
        help="只评测指定划分（默认 all）",
    )
    parser.add_argument(
        "--out", type=Path, help="输出目录，自动写 bench-result.json 与 bench-report.md"
    )
    parser.add_argument("--json", type=Path, help="JSON 结果路径（覆盖 --out 默认值）")
    parser.add_argument("--md", type=Path, help="Markdown 报告路径（覆盖 --out 默认值）")
    parser.add_argument(
        "--baseline", type=Path, help="之前的 bench-result JSON，用于质量门禁比较"
    )
    parser.add_argument(
        "--max-recall-drop",
        type=float,
        default=0.05,
        help="允许的 recall 最大下降（默认 0.05）",
    )
    parser.add_argument(
        "--max-fpr-rise",
        type=float,
        default=0.02,
        help="允许的 FPR 最大上升（默认 0.02）",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="严格模式：未复核标签全部按不可评估披露，不计算 provisional 指标",
    )
    parser.add_argument("--quiet", action="store_true", help="不输出常规摘要")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="bench_eval.py",
        description=(
            "IoT 固件漏洞检测合成基准评测器：校验 bench manifest、匹配 findings 与标签、"
            "计算 P/R/F1/FPR、输出可复现 JSON 与中文 Markdown 报告。"
        ),
        epilog=(
            "示例：\n"
            "  python scripts/bench_eval.py evaluate --manifest assets/bench/manifest.json "
            "--findings layer1.json --split all --out out/bench\n"
            "  python scripts/bench_eval.py validate --manifest assets/bench/manifest.json\n"
            "为兼容旧脚本，省略 evaluate 直接传 --manifest/--findings 也可运行。"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    subparsers = parser.add_subparsers(
        dest="command",
        required=True,
        metavar="{evaluate,validate}",
    )

    evaluate = subparsers.add_parser(
        "evaluate",
        help="校验基准集并评测 findings（默认命令）",
        description="校验 bench manifest，匹配 findings 与标签，计算指标并写出 JSON/Markdown。",
        epilog=(
            "示例：python scripts/bench_eval.py evaluate --manifest assets/bench/manifest.json "
            "--findings layer1.json --out out/bench"
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    _add_eval_arguments(evaluate)

    validate = subparsers.add_parser(
        "validate",
        help="只校验基准集（manifest、哈希、标签证据）",
        description="只执行基准集契约校验，不读取 findings，不计算指标。",
    )
    validate.add_argument("--manifest", type=Path, required=True, help="bench manifest JSON 路径")
    validate.add_argument("--quiet", action="store_true", help="不输出常规摘要")
    return parser


def print_validation_failure(issues: list[str]) -> None:
    print("基准集校验失败，发现 {} 个问题：".format(len(issues)), file=sys.stderr)
    for issue in issues[:MAX_PRINT_ISSUES]:
        print(f"  - {issue}", file=sys.stderr)
    if len(issues) > MAX_PRINT_ISSUES:
        print(
            f"  - 其余 {len(issues) - MAX_PRINT_ISSUES} 个问题已省略",
            file=sys.stderr,
        )


def configure_stdio() -> None:
    """Windows 管道默认可能是 GBK；统一改成 UTF-8，保证中文帮助/摘要可被测试脚本读取。"""
    for stream in (sys.stdout, sys.stderr):
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is None:
            continue
        try:
            reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError):
            pass


def run_validate(args: argparse.Namespace) -> int:
    try:
        bench = validate_manifest(args.manifest)
    except InputError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1
    if bench.issues:
        print_validation_failure(bench.issues)
        return 1
    if not args.quiet:
        dataset = bench.data.get("dataset") or {}
        print(
            "基准集校验通过：{} 个样本（dev {} / holdout {}），"
            "{} 个标签（reviewed {}），{} 个负样本".format(
                len(bench.samples),
                len(bench.splits.get("dev", [])),
                len(bench.splits.get("holdout", [])),
                sum(len(sample.labels) for sample in bench.samples),
                sum(1 for sample in bench.samples for label in sample.labels if label.reviewed),
                sum(1 for sample in bench.samples if sample.kind in NEGATIVE_KINDS),
            )
        )
        print(f"数据集：{dataset.get('name')} {dataset.get('version')}（{dataset.get('kind')}）")
        print(f"manifest：{args.manifest.resolve()}")
        if bench.warnings:
            print("校验警告：", file=sys.stderr)
            for warning in bench.warnings[:MAX_PRINT_ISSUES]:
                print(f"  - {warning}", file=sys.stderr)
            if len(bench.warnings) > MAX_PRINT_ISSUES:
                print(
                    f"  - 其余 {len(bench.warnings) - MAX_PRINT_ISSUES} 条警告已省略",
                    file=sys.stderr,
                )
    return 0


def run_evaluate(args: argparse.Namespace) -> int:
    try:
        bench = validate_manifest(args.manifest)
    except InputError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1
    if bench.issues:
        print_validation_failure(bench.issues)
        return 1
    if not args.quiet and bench.warnings:
        print("校验警告：", file=sys.stderr)
        for warning in bench.warnings[:MAX_PRINT_ISSUES]:
            print(f"  - {warning}", file=sys.stderr)
        if len(bench.warnings) > MAX_PRINT_ISSUES:
            print(
                f"  - 其余 {len(bench.warnings) - MAX_PRINT_ISSUES} 条警告已省略",
                file=sys.stderr,
            )

    try:
        raw_findings, findings_sha, findings_meta = load_findings(args.findings)
        findings, out_of_scope, deduplicated = normalize_findings(raw_findings, bench)
    except FindingsError as exc:
        print(f"[错误] {exc}", file=sys.stderr)
        return 1
    except OSError as exc:
        print(f"[错误] 读取 findings 失败: {exc}", file=sys.stderr)
        return 1

    parameters = {
        "manifest": str(args.manifest.resolve()),
        "findings": str(args.findings.resolve()),
        "split": args.split,
        "strict": bool(args.strict),
        "baseline": str(args.baseline.resolve()) if args.baseline else None,
        "max_recall_drop": args.max_recall_drop,
        "max_fpr_rise": args.max_fpr_rise,
    }
    slice_result = evaluate_slice(bench, findings, args.split, args.strict)
    baseline_result: Optional[dict[str, Any]] = None
    if args.baseline is not None:
        try:
            baseline_result = compare_baseline(
                args.baseline,
                slice_result["micro"],
                args.max_recall_drop,
                args.max_fpr_rise,
            )
        except InputError as exc:
            print(f"[错误] 基线比较失败: {exc}", file=sys.stderr)
            return 1

    generated_at = datetime.now(timezone.utc).isoformat(timespec="seconds")
    result = build_result(
        bench,
        args.findings,
        findings_sha,
        findings_meta,
        len(raw_findings),
        findings,
        out_of_scope,
        deduplicated,
        slice_result,
        baseline_result,
        parameters,
        generated_at,
    )
    exit_code = 3 if result["regression"] else 0
    result["exit_code"] = exit_code

    json_path: Optional[Path] = args.json
    md_path: Optional[Path] = args.md
    if args.out is not None:
        if json_path is None:
            json_path = args.out / "bench-result.json"
        if md_path is None:
            md_path = args.out / "bench-report.md"

    try:
        if json_path is not None:
            json_path.parent.mkdir(parents=True, exist_ok=True)
            json_path.write_text(
                json.dumps(result, ensure_ascii=False, indent=2) + "\n",
                encoding="utf-8",
                newline="\n",
            )
        if md_path is not None:
            md_path.parent.mkdir(parents=True, exist_ok=True)
            md_path.write_text(
                render_report(result) + "\n",
                encoding="utf-8",
                newline="\n",
            )
    except OSError as exc:
        print(f"[错误] 写输出失败: {exc}", file=sys.stderr)
        return 1

    if not args.quiet:
        console_summary(result, json_path, md_path)
    return exit_code


def main(argv: Optional[list[str]] = None) -> int:
    configure_stdio()
    parser = build_parser()
    raw = list(sys.argv[1:] if argv is None else argv)
    if not raw:
        parser.print_help()
        return 2
    if raw[0] in ("evaluate", "validate"):
        pass
    elif raw[0] in ("-h", "--help", "--version"):
        pass
    else:
        raw = ["evaluate"] + raw
    args = parser.parse_args(raw)
    if args.command == "validate":
        return run_validate(args)
    if not math.isfinite(args.max_recall_drop) or args.max_recall_drop < 0:
        parser.error("--max-recall-drop 必须是大于等于 0 的有限数")
    if not math.isfinite(args.max_fpr_rise) or args.max_fpr_rise < 0:
        parser.error("--max-fpr-rise 必须是大于等于 0 的有限数")
    return run_evaluate(args)


if __name__ == "__main__":
    raise SystemExit(main())
