#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
coverage_gate.py — 覆盖率门禁（Phase 5）

对抗「随机游走式审计」的硬约束：分配清单里的每个文件都必须有结论，否则不许出报告。

输入：
  --plan       03-audit-plan.md          （fw_triage.py --plan 产出，含 Tier 与文件清单）
  --verified   30-findings-verified.md   （审计结论，含 finding 与 NOT_FOUND）
  --candidates 20-findings-candidates.jsonl（可选，用于校验候选处置率）
  --tiering    02-tiering.json           （可选，用于补充 T1/T2/T3 清单与 promotions）
  --layer1     10-layer1-sinks.json      （sink_scan.py 产出；strict 必填，消费 scan_integrity）
  --stages     audit-stages.json         （可选，阶段状态 success/partial/skipped/failed）
  --scan-waiver scan-waiver.json         （可选，对扫描缺口逐文件显式豁免）

判据：
  T1 覆盖率 100%（硬门禁）
  T2 覆盖率 >= 95%
  候选处置率 100%（每条 candidate 必须落到枚举内的结构化状态，且输入解析完整）
  promotions 跟进率 100%
  扫描完整性：strict 下 partial / failed 阻断；complete 与 scoped（仅跳过规则声明的
  目录/正则排除）可通过，但必须在报告中披露
  阶段状态：必需阶段非 success 即阻断

退出码：0 通过；1 未通过（缺口写入 40-coverage.md）；2 参数/文件错误
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set, Tuple

# 同目录的契约校验器（scripts/contracts.py）。缺失时退化为内置最小校验，
# 保证 coverage_gate.py 单独拷走也能跑；此时 schema 校验会弱一些，并在
# --manifest 的检查明细里明确写出来（不允许静默降级）。
try:
    from contracts import summarize as _contract_summary
    from contracts import validate_audit_task as _validate_audit_task
    from contracts import validate_firmware_manifest as _validate_manifest
except Exception:  # pragma: no cover - 仅在缺文件/被拷走时触发
    _contract_summary = None
    _validate_audit_task = None
    _validate_manifest = None

PATH_IN_BACKTICK = re.compile(r"`([^`]+)`")
PLAN_ROW = re.compile(r"^\|\s*\[[ xX]\]\s*\|\s*`([^`]+)`\s*\|\s*([A-Z0-9]*)\s*\|")
SHARD_HEAD = re.compile(r"^###\s+(\S+?)(?:（|\(|$)")
FILE_FIELD = re.compile(r"^[\s>*\-]*\*{0,2}\s*(?:文件|位置|覆盖文件|covered)\s*\*{0,2}\s*[:：]\s*(.+)$")
NOT_FOUND_HEAD = re.compile(r"^#{1,6}\s*NOT_FOUND\s*[·:：\-]\s*(.+)$", re.I)
FINDING_HEAD = re.compile(r"^#{1,6}\s*(F-\d+|C-\d+|L1-\d+)\b")
PENDING_MARKS = ("待动态验证", "未动态验证", "unverified", "待验证")

# 审阅清单（Phase 2.5 的「我打算看哪些文件」声明）行格式：
#   - [x] `usr/sbin/httpd`      或  | [x] | `usr/sbin/httpd` | ...
CHECKBOX_ROW = re.compile(r"^\s*[-*]?\s*\[([ xX])\]\s*`([^`]+)`")
CHECK_TABLE_ROW = re.compile(r"^\|\s*\[([ xX])\]\s*\|\s*`([^`]+)`")

# ── G4：入口级覆盖 ────────────────────────────────────────────────────────────
# 对抗 "httpd 2923 函数只读了 5 个，却因『文件级 100%』而过门禁"。
# 适用对象：T1 且 text_kb 超阈值的「服务型可执行」（bin|sbin|usr/bin|usr/sbin 下的
# ELF，排除 .so 库）。每个适用文件必须提交入口枚举 entrypoints.json。
ENTRYPOINT_SCHEMA = "entrypoints/v1"
SERVICE_EXEC_DIRS = ("bin/", "sbin/", "usr/bin/", "usr/sbin/")

# ── G5：绕过矩阵完备 ─────────────────────────────────────────────────────────
# 对抗「有防护 / 已过滤 / 不可利用」被当作结论收尾。
# 触发词（前置否定词 未/无/不/非 会排除「未鉴权」「无过滤」等）：
PROTECT_CLAIM = re.compile(
    r"(?<![未无不非])(?:已鉴权|已认证|已过滤|已验签|已限长|有防护|已做校验|已校验"
    r"|存在性校验|白名单(?:校验|过滤|限制)|长度校验|字符校验|已转义|已做转义"
    r"|access\(\)\s*(?:校验|检查))"
    r"|不可利用|判定当前不可利用"
)
# 「修复建议」行是建议而非结论断言，扫描时剔除，避免误报。
RECOMMEND_LINE = re.compile(r"^\s*[-*]*\s*\*{0,2}(?:修复建议|建议|加固建议)\*{0,2}\s*[:：]")
BYPASS_ITEM = re.compile(r"\bB(?:1[0-2]|[1-9])\b")
BYPASS_MIN_ITEMS = 10          # 一张完整 B1–B12 矩阵至少应出现 10 个条目号

GATE_VERSION = "1.6"           # 门禁语义版本：判据变化时递增，便于复算历史结论

# ── 候选处置状态枚举（封闭集合）─────────────────────────────────────────────
# 「文本里提过这个 ID」不等于「这条候选被处置过」。只有落在枚举内的结构化
# status 才算实质处置；没有 status 的旧格式只能靠文本匹配，strict 下不认。
CAND_STATUS = {
    "hypothesis",                  # 仍是假设，未验证
    "confirmed",                   # 已验证成立（必须带 evidence）
    "not_reproduced",              # 验证后未复现
    "not_applicable",              # 不适用（代码不存在 / 配置不可达）
    "pending_static_analysis",     # 待静态分析
    "pending_dynamic_validation",  # 待动态验证
    "blocked_by_environment",      # 环境受限（QEMU 起不来 / 缺 NVRAM）
    # 兼容既有写法
    "validated",
    "not_found",
}

# ── G6：跨请求污点溯源（高阶漏洞，Bridge / IEEE S&P'26）───────────────────────
# 对抗「只审单请求数据流」。污点常经 NVRAM / 运行时文件 等**持久化存储**跨请求传递：
# 请求 1 写入存储，请求 2 读出并触发 sink（RAXE500 F-012/F-013 即此形态）。
# 判据：凡 finding 的 `Source:` 指向**运行时写入的持久化存储**（nvram/uci 键，或
# /tmp·/var·/dev/shm 等可写路径），就必须在同一 finding 内声明**写入面**
# （谁 / 哪个入口能写入该存储）——否则溯源链断开，「输入可控」不成立。
# 注意：静态配置（固件镜像内的 .conf/.cfg，如 F-002 的 updater.conf）不触发，避免误报。
CROSS_REQUEST_SOURCE = re.compile(
    r"nvram|acosNvramConfig|nvram_safe_get|nvram_get|\buci\b"
    r"|/tmp/|/var/|/dev/shm|/mnt/|/data/|persist",
    re.I)
WRITE_FACE = re.compile(
    r"写入面|写端|write[-_ ]?face|可写|writable|被写入|由[^。\n]{0,60}写(?:入|的)"
    r"|导入|restore|(?:nvram|uci|config|acosNvramConfig)[^。\n]{0,30}(?:set|safe_set|写入)"
    r"|_set\b|set\s*\(",
    re.I)

# ── 类型 → DKTSS Base 命中（兜底规则：报告里出现的类型必须可映射）────────────
# 报告类型是自由文本（如「硬编码凭据 / 私钥泄露」「更新流程降级 / MITM」），
# 这里用关键词把标签归一到 Base 表的规范类型；归不到且未写「映射依据」→ 告警。
BASE_SYNONYM: List[tuple] = [
    ("硬编码凭据", ("凭据", "私钥", "口令", "密码", "api key", "apikey", "token", "密钥")),
    ("敏感信息泄露", ("信息泄露", "泄露", "敏感信息", "明文")),
    ("RCE / 命令注入", ("命令注入", "命令执行", "rce", "代码执行", "反序列化")),
    ("固件升级无验签", ("无验签", "升级无校验", "固件校验")),
    ("认证绕过", ("认证", "鉴权", "登录绕过", "认证缺失", "访问控制")),
    ("路径穿越", ("路径穿越", "目录穿越", "任意文件写", "任意文件读", "文件写", "文件读")),
    ("内存破坏", ("溢出", "内存破坏", "栈", "堆", "uaf", "use-after-free")),
    ("SSRF", ("ssrf", "服务端请求伪造")),
    ("文件上传", ("文件上传", "上传")),
    ("配置篡改", ("配置篡改", "改配置", "篡改配置")),
    ("拒绝服务", ("拒绝服务", "dos", "崩溃", "重启", "断网")),
    ("供应链 / 第三方组件", ("供应链", "第三方组件", "组件漏洞", "组件过期")),
    ("云对接鉴权缺失", ("云对接", "mqtt", "tr-069", "云 api", "云平台")),
    ("越权 / 业务逻辑绕过", ("越权", "业务逻辑", "idor", "提权", "权限提升")),
    ("弱随机 / 可预测令牌", ("弱随机", "可预测", "随机数", "令牌预测")),
    ("CSRF", ("csrf", "跨站请求伪造")),
    ("调试接口 / 后门", ("后门", "调试接口", "调试端口", "telnet", "串口")),
    ("安全启动绕过 / 持久化", ("安全启动", "持久化", "信任链", "bootargs")),
    ("传输安全降级 / MITM", ("mitm", "降级", "中间人", "tls 校验", "证书校验")),
    ("不安全临时文件 / 本地提权", ("不安全临时文件", "临时文件", "临时路径", "符号链接",
                            "竞态", "toctou", "/tmp 可写")),
]


def norm(p: str) -> str:
    p = p.strip().strip("`").strip()
    p = p.replace("\\", "/")
    p = re.sub(r"^\./", "", p)
    p = re.sub(r":(0x[0-9a-fA-F]+|\d+)$", "", p)     # 去掉 :行号 / :偏移
    p = re.sub(r":(0x[0-9a-fA-F]+\(\d+\))$", "", p)
    return p.strip()


# 根目录下的文件（无 "/"，如嵌入式常见的 `.init_enable_core` / `.keep`）在
# 依赖 "/" 的过滤里会被静默丢弃。此处放行「不含空白、无扩展名歧义的根级点文件」，
# 既不放过散文/版本串（如 `iperf 3.8.1`），也能覆盖真实存在的根级文件。
_ROOT_DOTFILE = re.compile(r"^\.[A-Za-z0-9][A-Za-z0-9._+@\-]*$")


def is_pathish(tok: str) -> bool:
    """判断一个 token 是否像文件路径（供覆盖门禁做路径识别）。"""
    if "/" in tok:
        return True
    if not tok or any(c.isspace() for c in tok):
        return False
    return bool(_ROOT_DOTFILE.match(tok))


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


def _sha256_file(path: Optional[str]) -> Optional[str]:
    """输入文件指纹：让「同样的输入 + 同样的版本」可被复核是同一件事。"""
    if not path or not os.path.isfile(path):
        return None
    import hashlib
    h = hashlib.sha256()
    try:
        with open(path, "rb") as f:
            for blk in iter(lambda: f.read(1 << 20), b""):
                h.update(blk)
    except OSError:
        return None
    return h.hexdigest()


def parse_plan(path: str) -> List[Dict[str, str]]:
    rows: List[Dict[str, str]] = []
    shard = ""
    for line in read(path).splitlines():
        m = SHARD_HEAD.match(line)
        if m:
            shard = m.group(1)
            continue
        m = PLAN_ROW.match(line)
        if m:
            rows.append({"file": norm(m.group(1)), "tier": m.group(2) or "", "shard": shard})
    if not rows:
        # 容错：任何反引号包裹且像路径的内容
        for line in read(path).splitlines():
            if "|" in line and "`" in line:
                for c in PATH_IN_BACKTICK.findall(line):
                    c = norm(c)
                    if c and "/" in c and not c.startswith("http"):
                        rows.append({"file": c, "tier": "", "shard": shard})
    return rows


def parse_verified(path: str) -> Dict[str, Any]:
    text = read(path)
    covered: Set[str] = set()
    headings: List[str] = []
    not_found: Set[str] = set()
    ids: Set[str] = set()
    pending: Set[str] = set()
    cur_files: List[str] = []

    def collect(val: str) -> List[str]:
        out: List[str] = []
        for c in PATH_IN_BACKTICK.findall(val):
            out.append(norm(c))
        for part in re.split(r"[,，;；]\s*", val):
            part = norm(part)
            if part and is_pathish(part) and not part.startswith("http"):
                out.append(part)
        return [x for x in out if x]

    for line in text.splitlines():
        s = line.strip()
        if s.startswith("#"):
            hm = NOT_FOUND_HEAD.match(s)
            if hm:
                headings.append(s)
                cur_files = collect(hm.group(1))
                not_found.update(cur_files)
                covered.update(cur_files)
                continue
            fm = FINDING_HEAD.match(s)
            if fm:
                headings.append(s)
                ids.add(fm.group(1))
            else:
                headings.append(s)
            cur_files = []
            continue
        m = FILE_FIELD.match(s)
        if m:
            got = collect(m.group(1))
            covered.update(got)
            cur_files.extend(got)
            if any(p in m.group(1) for p in PENDING_MARKS):
                pending.update(got)
            continue
        if any(p in s for p in PENDING_MARKS) and cur_files:
            pending.update(cur_files)
    return {"text": text, "covered": covered, "headings": headings,
            "not_found": not_found, "ids": ids, "pending": pending}


def parse_review_list(path: str) -> Dict[str, Any]:
    """解析 Phase 2.5 的「审阅文件清单」——模型声明的本轮打算审计的文件。

    支持两种行格式：
      - [x] `usr/sbin/httpd`            （markdown 复选框列表）
      | [x] | `usr/sbin/httpd` | T1     （表格行）
    返回 {declared: {file...}, checked: {file...}, unchecked: {file...}, total}
    """
    out: Dict[str, Any] = {"declared": set(), "checked": set(), "unchecked": set(),
                           "total": 0, "exists": False}
    if not path or not os.path.isfile(path):
        return out
    out["exists"] = True
    for line in read(path).splitlines():
        m = CHECKBOX_ROW.match(line) or CHECK_TABLE_ROW.match(line)
        if not m:
            continue
        mark, raw = m.group(1), norm(m.group(2))
        if not raw or not is_pathish(raw) or raw.startswith("http"):
            continue
        out["declared"].add(raw)
        if mark.lower() == "x":
            out["checked"].add(raw)
        else:
            out["unchecked"].add(raw)
    out["total"] = len(out["declared"])
    return out


def diff_review_list(review: Dict[str, Any], plan: List[Dict[str, str]],
                     covered: Set[str], tier_of: Dict[str, str]) -> Dict[str, Any]:
    """把「声明的审阅清单」与「计划文件清单」「实际结论」三方对齐。

    对抗文章所述「模型声称 100% 但实际 70-85%」：
      - G1 声明未勾选：审阅清单里打了 [ ] 没打 [x] 的文件
      - G2 计划缺失：计划要求审的文件（T1/T2）压根没进审阅清单
      - G3 勾选无结论：清单里勾了 [x]，但 30-findings-verified.md 里没有对应结论
    """
    declared: Set[str] = review.get("declared", set())
    checked: Set[str] = review.get("checked", set())
    unchecked: Set[str] = review.get("unchecked", set())

    plan_files = {r["file"] for r in plan
                  if (r["tier"] or tier_of.get(r["file"], "")) in ("T1", "T2")}
    g1 = sorted(unchecked)
    g2 = sorted(f for f in plan_files if f not in declared)
    g3 = sorted(f for f in checked if f not in covered)
    return {"available": bool(review.get("exists")), "declared": len(declared),
            "checked": len(checked), "G1_unchecked": g1, "G2_not_declared": g2,
            "G3_no_conclusion": g3,
            "ok": not (g1 or g2 or g3)}


def load_tiering_index(path: str) -> Dict[str, Any]:
    """加载 02-tiering.json，返回分层清单 + 逐文件元数据（tier / text_kb / kind）。

    供 G4 判定「哪些文件属于需提交入口枚举的服务型大二进制」。
    """
    idx: Dict[str, Any] = {"t1": set(), "t2": set(), "t3": set(), "skip": set(),
                           "items": {}, "promotions": [], "ok": False}
    if not path or not os.path.isfile(path):
        return idx
    try:
        tj = json.load(open(path, encoding="utf-8"))
    except Exception:  # noqa
        return idx
    t = tj.get("tiering") or tj.get("rootfs_analysis", {}).get("tiering") or {}
    for k, key in (("t1", "t1_list"), ("t2", "t2_list"),
                   ("t3", "t3_list"), ("skip", "skip_list")):
        for f in (t.get(key) or []):
            idx[k].add(norm(str(f)))
    for sh in (t.get("shards") or []):
        for it in (sh.get("items") or []):
            f = norm(str(it.get("file", "")))
            if not f:
                continue
            idx["items"][f] = {
                "tier": str(it.get("tier", "")),
                "text_kb": float(it.get("text_kb") or 0),
                "ealoc": it.get("ealoc"),
                "kind": str(it.get("kind") or it.get("type") or ""),
                "reason": it.get("reason") or "",
            }
    idx["promotions"] = t.get("promotions") or []
    idx["ok"] = True
    return idx


def check_entrypoints(path: str, idx: Dict[str, Any], text_kb_threshold: float,
                      audit_min: float) -> Dict[str, Any]:
    """G4：入口级覆盖。

    规则：T1 且 text_kb > 阈值的「服务型可执行」必须提交 entrypoints.json，且
      - 每个适用文件有一条记录；
      - 记录须声明 handler_table_count（派发表条目数），且枚举条目数 ≥ 该值；
      - 每个枚举入口须有非空 conclusion（已处置：finding id / NOT_FOUND / 待动态验证）；
      - 全局入口审计率 ≥ audit_min（默认 100%）。
    豁免：文件级 `waiver{reason}`，或 `entrypoints:"none"` + `reason`（无外部可达入口的 CLI 工具）。
    """
    out: Dict[str, Any] = {
        "checked": False, "exists": False, "required": [], "missing": [],
        "enum_incomplete": [], "under_audited": [], "waived": [],
        "audited_done": 0, "audited_total": 0, "audited_ratio": None,
        "skipped": None, "threshold": text_kb_threshold, "audit_min": audit_min,
    }

    qualifying: List[str] = []
    for f, meta in (idx.get("items") or {}).items():
        if meta.get("tier") != "T1":
            continue
        if float(meta.get("text_kb") or 0) <= text_kb_threshold:
            continue
        if f.endswith(".so") or ".so." in f:               # 库不计入
            continue
        if not f.startswith(SERVICE_EXEC_DIRS):            # 只要求 bin/sbin/usr-* 下可执行
            continue
        qualifying.append(f)
    out["required"] = sorted(qualifying)

    if not path or not os.path.isfile(path):
        out["skipped"] = ("未提供 --entrypoints（入口枚举未提交）" if not path
                          else f"entrypoints.json 不存在: {path}")
        return out
    out["exists"] = True
    try:
        ep = json.load(open(path, encoding="utf-8"))
    except Exception as e:  # noqa
        out["skipped"] = f"entrypoints.json 解析失败: {e}"
        return out
    out["checked"] = True

    by_file: Dict[str, Dict[str, Any]] = {}
    for rec in (ep.get("files") or []):
        if isinstance(rec, dict):
            by_file[norm(str(rec.get("file", "")))] = rec

    done_total = 0
    seen_total = 0
    for f in qualifying:
        rec = by_file.get(f)
        if rec is None:
            out["missing"].append(f)
            continue
        if rec.get("waiver"):
            out["waived"].append(f)
            continue
        if str(rec.get("entrypoints", "")).lower() == "none":
            if rec.get("reason"):
                out["waived"].append(f)
            else:
                out["enum_incomplete"].append({"file": f, "why": "声明无入口但未写 reason"})
            continue
        table_n = rec.get("handler_table_count")
        handlers = rec.get("handlers") or []
        if not isinstance(table_n, int) or table_n < 1:
            out["enum_incomplete"].append({"file": f, "why": "未声明 handler_table_count"})
            continue
        if len(handlers) < table_n:
            out["enum_incomplete"].append(
                {"file": f, "why": f"已枚举 {len(handlers)} < 派发表 {table_n}"})
        done = sum(1 for h in handlers if isinstance(h, dict) and h.get("conclusion"))
        seen_total += len(handlers)
        done_total += done
        if handlers and done < len(handlers):
            out["under_audited"].append(
                {"file": f, "audited": done, "total": len(handlers)})

    out["audited_done"] = done_total
    out["audited_total"] = seen_total
    if seen_total:
        out["audited_ratio"] = round(done_total * 100.0 / seen_total, 2)
    out["ok"] = (not out["missing"] and not out["enum_incomplete"]
                 and (out["audited_ratio"] is None or out["audited_ratio"] >= audit_min))
    return out


def check_bypass_matrix(verified_path: str) -> Dict[str, Any]:
    """G5：绕过矩阵完备。

    扫描结论台账的每个章节；只要章节正文出现「已鉴权 / 已过滤 / 有效校验 /
    不可利用」这类**防护断言**，就必须在同一章节给出 B1–B12 绕过矩阵
    （检测 `bypass_matrix` 关键词或 ≥ BYPASS_MIN_ITEMS 个 B 条目号）。
    「修复建议」行视为建议而非断言，不触发。
    """
    out: Dict[str, Any] = {"checked": False, "claims": [], "missing_matrix": [],
                           "skipped": None}
    if not verified_path or not os.path.isfile(verified_path):
        out["skipped"] = f"文件不存在: {verified_path}"
        return out
    out["checked"] = True
    text = read(verified_path)
    lines = text.splitlines()

    secs: List[tuple] = []
    cur_title: Optional[str] = None
    cur_start = 0
    cur_body: List[str] = []
    for i, ln in enumerate(lines):
        m = re.match(r"^#{1,4}\s+(.+)$", ln.strip())
        if m:
            if cur_title is not None:
                secs.append((cur_title, cur_start, cur_body))
            cur_title, cur_start, cur_body = m.group(1), i, []
            continue
        if cur_title is not None:
            cur_body.append(ln)
    if cur_title is not None:
        secs.append((cur_title, cur_start, cur_body))

    for title, start, body in secs:
        kept = [b for b in body if not RECOMMEND_LINE.match(b)]
        blob = "\n".join(kept)
        if not PROTECT_CLAIM.search(blob):
            continue
        items = set(BYPASS_ITEM.findall(blob))
        has_matrix = ("bypass_matrix" in blob) or (len(items) >= BYPASS_MIN_ITEMS)
        out["claims"].append({"title": title[:80], "line": start + 1,
                              "items": len(items), "has_matrix": has_matrix})
        if not has_matrix:
            out["missing_matrix"].append({
                "title": title[:80], "line": start + 1, "items_found": len(items)})
    return out


HIGH_ORDER_CLAIM = re.compile(
    r"高阶|high[-_ ]?order|other_get|跨请求污点", re.I)
# 「无高阶漏洞」「非高阶」这类否定表述不是声明，先剔掉再判
HIGH_ORDER_NEG = re.compile(
    r"(?:无|非|不属于|不涉及|未发现|未见|没有)\s*高阶"
    r"|(?:无|非|不属于|不涉及|未发现|未见|没有)\s*跨请求污点", re.I)


def report_claims_high_order(report_path: str) -> bool:
    """报告是否**声称**了高阶（跨请求）漏洞。

    只认「漏洞详情」区块内的 finding 正文，不认报告其它章节提到这些词——
    否则一句「本次未发现高阶漏洞」也会被当成声明（否定表述会被 HIGH_ORDER_NEG 剔除）。"""
    if not report_path or not os.path.isfile(report_path):
        return False
    lines = read(report_path).splitlines()
    start = None
    for i, ln in enumerate(lines):
        m = re.match(r"^#{1,3}\s*(.+)$", ln.strip())
        if m and "漏洞详情" in m.group(1):
            start = i
            break
    body = "\n".join(lines[start:]) if start is not None else "\n".join(lines)
    return bool(HIGH_ORDER_CLAIM.search(HIGH_ORDER_NEG.sub("", body)))


def check_taint_graph(path: str, report_path: str = "") -> Dict[str, Any]:
    """G7：跨请求污点图（taint-graph.json）——把「声明写入面」升级为「四元组闭合」。

    G6 只要求报告**文字里**出现写入面。文字可以含糊：写成「由恢复配置导入」
    就过了，但那个键到底由哪个 action 写、读它的又是哪个 action，仍可能是错的。
    G7 要求把链写成图：

        write.action --key--> 存储 --key--> read.action --> sink

    并机械校验三条语义（与 Bridge 的高阶定义一致）：
      1. 写面与读面**必须分属不同 action**，否则是一阶漏洞（不得计入高阶）
      2. 键在两端**必须字面一致**（不一致说明常量恢复没做）
      3. 每一端都要有 **addr + evidence**，sink 要归到已知类型
    外加一条：报告声称了高阶漏洞，图里就必须真有高阶链——不能只有结论没有图。
    """
    out: Dict[str, Any] = {
        "checked": False, "chains": 0, "first_order": 0, "violations": [],
        "warnings": [], "summary": {}, "skipped": None,
        "claims_high_order": report_claims_high_order(report_path),
    }
    if not path:
        out["skipped"] = "未提供 --taint-graph"
        return out
    out["checked"] = True
    if not os.path.isfile(path):
        out["violations"].append(f"taint-graph 不存在: {path}")
        return out
    try:
        g = json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError) as exc:
        out["violations"].append(f"taint-graph 解析失败: {exc}")
        return out
    script_dir = os.path.dirname(os.path.abspath(__file__))
    if script_dir not in sys.path:
        sys.path.insert(0, script_dir)
    import taint_graph as tg  # noqa: E402

    val = tg.validate_graph(g)
    out["violations"].extend(val["violations"])
    out["warnings"].extend(val["warnings"])
    out["chains"] = len(g.get("chains") or [])
    out["first_order"] = len(g.get("first_order") or [])
    out["summary"] = g.get("summary") or {}

    if out["claims_high_order"] and out["chains"] == 0:
        out["violations"].append(
            "报告声称存在高阶漏洞，但图里 0 条高阶链——"
            "写面/读面没有配对，或写读落在同一 action（那种情况是一阶）")
    return out


def check_cross_request(report_path: str) -> Dict[str, Any]:
    """G6：跨请求污点溯源（高阶漏洞）。

    凡 `Source:` 指向**运行时写入的持久化存储**（nvram/uci 键，或 /tmp·/var·
    /dev/shm 等可写路径），该 finding 就必须声明**写入面**——即该存储的上一跳
    由谁 / 哪个入口写入。缺写入面 → 溯源未闭合，「输入可控」不成立。
    静态配置（镜像内 .conf/.cfg）由 CROSS_REQUEST_SOURCE 排除，不触发。
    """
    out: Dict[str, Any] = {"checked": False, "findings": 0, "violations": [],
                           "skipped": None}
    if not report_path or not os.path.isfile(report_path):
        out["skipped"] = f"报告不存在: {report_path}"
        return out
    out["checked"] = True
    lines = read(report_path).splitlines()

    # 定位「漏洞详情」区块范围（从该标题到下一个 ## 标题）
    start = None
    end = len(lines)
    for i, ln in enumerate(lines):
        m = re.match(r"^#{1,3}\s*(.+)$", ln.strip())
        if not m:
            continue
        if start is None and ("漏洞详情" in m.group(1)):
            start = i
            continue
        if start is not None and i > start and re.match(r"^##\s", ln):
            end = i
            break
    if start is None:
        # 没有漏洞条目就无从判断跨请求污点，标为未执行而不是「0 违规」。
        out["checked"] = False
        out["skipped"] = "未找到「漏洞详情」区块"
        return out

    # 按 ### F-xxx 切分
    blocks: List[tuple] = []
    cur: Optional[tuple] = None
    for i in range(start + 1, end):
        s = lines[i].strip()
        m = re.match(r"^#{3,4}\s*(F-\d+\s*[·:：]\s*.+)$", s)
        if m:
            if cur:
                blocks.append(cur)
            cur = (m.group(1), i, [])
            continue
        if cur is not None:
            cur[2].append(s)
    if cur:
        blocks.append(cur)

    SRC = re.compile(r"^\s*[-*]*\s*\*{0,2}Source\*{0,2}\s*[:：]\s*(.+)$")
    for title, idx, body in blocks:
        src = None
        for b in body:
            m = SRC.match(b)
            if m:
                src = m.group(1).strip()
                break
        if src is None or not CROSS_REQUEST_SOURCE.search(src):
            continue
        out["findings"] += 1
        if not WRITE_FACE.search("\n".join(body)):
            out["violations"].append(
                {"title": title[:80], "line": idx + 1, "source": src[:100]})
    return out


def parse_base_table(path: str) -> Dict[str, Any]:
    """从 references/reporting.md 的 `### Base` 表解析规范类型清单。"""
    out: Dict[str, Any] = {"ok": False, "types": set(), "rows": 0, "skipped": None}
    if not path or not os.path.isfile(path):
        out["skipped"] = f"Base 表文件不存在: {path}"
        return out
    text = read(path)
    m = re.search(r"###\s*Base[^\n]*\n(.*?)(?=\n###\s|\Z)", text, re.S)
    if not m:
        out["skipped"] = "未找到 Base 表区块（### Base）"
        return out
    for ln in m.group(1).splitlines():
        s = ln.strip()
        if not s.startswith("|"):
            continue
        cells = [c.strip() for c in s.strip("|").split("|")]
        if len(cells) < 3:
            continue
        if cells[0] in ("漏洞类型", "") or set(cells[0]) <= set("-: "):
            continue
        out["types"].add(cells[0])
        out["rows"] += 1
    out["ok"] = bool(out["types"])
    return out


def map_type_label(label: str, base_types: Set[str]) -> Optional[str]:
    """把报告的自由文本类型标签归一到 Base 表规范类型（命中不到返回 None）。"""
    lb = label.lower()
    for canonical, kws in BASE_SYNONYM:
        if canonical not in base_types:
            continue
        if any(kw in lb for kw in kws):
            return canonical
    return None


def check_type_base(report_path: str, base_path: str) -> Dict[str, Any]:
    """校验报告每个 finding 的「类型」字段能否命中 DKTSS Base 表（兜底规则）。

    命中不到时，允许在紧随的正文里写「映射依据」豁免；否则记入 unmapped。
    """
    out: Dict[str, Any] = {"checked": False, "base_rows": 0, "report_labels": 0,
                           "unmapped": [], "skipped": None}
    base = parse_base_table(base_path)
    if not base["ok"]:
        out["skipped"] = base.get("skipped") or "Base 表不可用"
        return out
    out["base_rows"] = base["rows"]
    if not report_path or not os.path.isfile(report_path):
        out["skipped"] = f"报告不存在: {report_path}"
        return out
    text = read(report_path)
    lines = text.splitlines()
    out["checked"] = True

    unmapped: Dict[str, Dict[str, Any]] = {}
    for i, ln in enumerate(lines):
        m = re.match(r"^\s*[-*]*\s*\*{0,2}类型\*{0,2}\s*[:：]\s*(.+)$", ln)
        if not m:
            continue
        raw = re.sub(r"[（(]\s*CWE[^)）]*[)）]", "", m.group(1)).strip()
        labels = [x.strip() for x in re.split(r"[/、,，]|\s+或\s+", raw) if x.strip()]
        out["report_labels"] += len(labels)
        blk = "\n".join(lines[i:i + 20])
        has_note = "映射依据" in blk
        for lb in labels:
            if map_type_label(lb, base["types"]) or lb in base["types"] or has_note:
                continue
            unmapped.setdefault(lb, {"label": lb, "line": i + 1})
    out["unmapped"] = list(unmapped.values())
    return out


CAND_SCHEMA = "candidates/1.0"
LEGACY_ID_RE = re.compile(r"\b([A-Z]{1,4}-\d{1,6})\b")


def _parse_candidate_document(raw: str, legacy_text: bool
                              ) -> Tuple[List[Dict[str, Any]], List[Dict[str, Any]],
                                         int, Optional[str], bool]:
    """把候选文件解析成 (行, 解析错误, 注释行数, schema, 是否为 envelope)。

    契约（ISSUE-01 / ISSUE-09）：
      - 空行与以 # 开头的整行注释允许，跳过并计数；
      - JSONL：逐行一个 JSON 对象；非空行解析失败必须记录「行号 + 原因 + 片段」，
        绝不静默丢弃（旧实现 except JSONDecodeError: continue 是 P0 缺陷）；
      - envelope：整个文件是一个 {"schema": "candidates/1.0", "candidates": [...]}，
        这是 strict 唯一接受的输入形态；
      - --legacy-text-candidates：非 JSON 行按旧文本格式回落（仅 standard 生效，
        strict 下即使开启也不通过）。
    """
    rows: List[Dict[str, Any]] = []
    errors: List[Dict[str, Any]] = []
    comments = 0
    schema: Optional[str] = None
    envelope = False

    stripped = raw.lstrip("\ufeff \t\r\n")
    if stripped.startswith("{"):
        try:
            doc = json.loads(stripped)
        except json.JSONDecodeError:
            doc = None
        if isinstance(doc, dict) and isinstance(doc.get("candidates"), list):
            envelope = True
            schema = str(doc.get("schema") or "") or None
            for i, c in enumerate(doc["candidates"], 1):
                if isinstance(c, dict):
                    c = dict(c)
                    c.setdefault("__line__", i)
                    rows.append(c)
                else:
                    errors.append({"line": i, "error": "候选条目不是 JSON 对象",
                                   "col": 0, "sample": str(c)[:120]})
            return rows, errors, comments, schema, envelope

    for lineno, line in enumerate(raw.splitlines(), 1):
        s = line.strip()
        if not s:
            continue
        if s.startswith("#"):
            comments += 1
            continue
        try:
            obj = json.loads(s)
        except json.JSONDecodeError as exc:
            if legacy_text:
                m = LEGACY_ID_RE.search(s)
                rows.append({"__legacy__": True, "__line__": lineno,
                             "id": m.group(1) if m else "", "raw": s[:160]})
            else:
                errors.append({"line": lineno, "error": exc.msg,
                               "col": exc.colno, "sample": s[:120]})
            continue
        if isinstance(obj, list):
            for it in obj:
                if isinstance(it, dict):
                    rows.append(dict(it))
                else:
                    errors.append({"line": lineno, "error": "候选条目不是 JSON 对象",
                                   "col": 0, "sample": str(it)[:120]})
            continue
        if not isinstance(obj, dict):
            errors.append({"line": lineno, "error": "候选记录必须是 JSON 对象",
                           "col": 0, "sample": s[:120]})
            continue
        obj = dict(obj)
        obj.setdefault("__line__", lineno)
        rows.append(obj)
    return rows, errors, comments, schema, envelope


def check_candidates(cand_path: Optional[str], text: str, strict: bool,
                     allow_empty: bool = False,
                     legacy_text: bool = False) -> Dict[str, Any]:
    """候选处置校验（结构化优先，文本匹配仅在显式兼容模式下允许）。

    修复的两个 P0（改进计划 §3 ISSUE-01 / ISSUE-02）：
      1. 非法 JSON 行不再 `continue` 静默吞掉，而是逐行记录并整体判定输入不完整；
      2. 空清单、文件缺失、读取失败、解析失败、未提供 五种状态分开判定：
         只有「文件存在 + 解析完整 + 显式 --allow-empty-candidates」才算通过，
         且 strict 下同样成立（旧实现 strict 里空清单永远过不了）。

    另外（ISSUE-09）：strict 只接受带 schema 的 envelope 输入；旧文本匹配必须
    显式 --legacy-text-candidates 才启用，且在 strict 下不作为通过路径。
    """
    out: Dict[str, Any] = {
        "checked": False, "exists": False, "total": 0, "disposed": 0,
        "unresolved": [], "duplicates": [], "bad_status": [],
        "missing_evidence": [], "weak": [], "mode": "structured",
        "skipped": None, "ok": False, "reason": None,
        "parse_errors": [], "parse_complete": True, "comments": 0,
        "schema": None, "envelope": False,
    }
    if not cand_path:
        out["skipped"] = "未提供 --candidates（候选处置未被评估）"
        out["reason"] = "not-provided"
        return out
    if not os.path.isfile(cand_path):
        out["skipped"] = f"候选文件不存在: {cand_path}"
        out["checked"] = True          # 显式给了却没落地 → 是缺口，不是「跳过」
        out["reason"] = "missing-file"
        out["ok"] = False
        out["unresolved"] = ["<候选文件缺失>"]
        return out

    out["checked"] = True
    out["exists"] = True
    try:
        with open(cand_path, encoding="utf-8-sig", errors="replace") as f:
            raw = f.read()
    except OSError as exc:
        out["skipped"] = f"候选文件读取失败: {exc}"
        out["reason"] = "read-error"
        out["ok"] = False
        return out

    rows, errors, comments, schema, envelope = _parse_candidate_document(
        raw, legacy_text)
    out["parse_errors"] = errors
    out["parse_complete"] = not errors
    out["comments"] = comments
    out["schema"] = schema
    out["envelope"] = envelope

    # 版本化输入：声明了 schema 就必须是已知版本，未知版本不猜、不降级
    if schema and schema not in (CAND_SCHEMA, "candidate/1.0"):
        out["skipped"] = f"候选输入 schema 不受支持: {schema}（期望 {CAND_SCHEMA}）"
        out["reason"] = "unsupported-schema"
        out["ok"] = False
        out["unresolved"] = ["<候选输入 schema 未知>"]
        return out

    if not rows:
        if errors:
            first = errors[0]
            out["skipped"] = (f"候选清单无有效记录：{len(errors)} 行非法 JSON"
                              f"（首条第 {first['line']} 行：{first['error']}）")
            out["reason"] = "parse-error"
            out["ok"] = False
            out["unresolved"] = ["<候选文件解析失败>"]
            return out
        out["skipped"] = "候选清单为空（0 条）"
        out["reason"] = "empty"
        # 空清单 ≠ 没有候选这回事：只有调用方显式声明「本次确实无候选」才算通过
        out["ok"] = bool(allow_empty)
        if not allow_empty:
            out["unresolved"] = ["<空候选清单：需显式 --allow-empty-candidates>"]
        return out

    out["total"] = len(rows)
    seen: Dict[str, int] = {}
    unresolved: List[str] = []
    weak: List[str] = []

    for c in rows:
        cid = str(c.get("id") or c.get("candidate_id") or "").strip()
        if not cid:
            out["duplicates"].append("<缺失 id>")
            unresolved.append("<缺失 id 的候选行>")
            continue
        seen[cid] = seen.get(cid, 0) + 1

        status = str(c.get("status") or "").strip().lower()
        if not status:
            disp = c.get("disposition")
            if isinstance(disp, dict):
                status = str(disp.get("type") or "").strip().lower()
        if not status:
            # 无结构化状态：仅在显式兼容模式下回落为文本匹配，并标记为弱证据
            out["mode"] = "legacy-text" if c.get("__legacy__") else "text"
            if _id_in_text(cid, text):
                out["disposed"] += 1
                weak.append(cid)
            else:
                unresolved.append(cid)
            continue

        if status not in CAND_STATUS:
            out["bad_status"].append({"id": cid, "status": status,
                                      "allowed": sorted(CAND_STATUS)[:8]})
            unresolved.append(cid)
            continue

        if status == "confirmed" and not _has_evidence(c):
            out["missing_evidence"].append(cid)
            unresolved.append(cid)
            continue
        out["disposed"] += 1

    out["duplicates"] = [f"{k} ×{v}" for k, v in seen.items() if v > 1]
    out["unresolved"] = unresolved
    out["weak"] = weak
    hard = bool(unresolved or out["duplicates"] or out["bad_status"]
                or out["missing_evidence"] or errors)
    if errors:
        out["reason"] = "parse-error"
        unresolved.append(f"<{len(errors)} 行候选记录解析失败>")
    if strict and not envelope:
        out["reason"] = out["reason"] or "unversioned-input"
        hard = True
        unresolved.append(f"<未声明 schema（strict 要求 {CAND_SCHEMA} envelope）>")
    if strict and out["mode"] != "structured":
        out["reason"] = out["reason"] or "non-structured-mode"
        hard = True
    out["ok"] = not hard
    out["unresolved"] = unresolved
    return out


def _id_in_text(cid: str, text: str) -> bool:
    """按 ID 边界匹配，避免 `C-001` 被 `C-0010` 这类更长 ID 误判为已提及。"""
    pat = re.compile(r"(?<![A-Za-z0-9_-])" + re.escape(cid) + r"(?![A-Za-z0-9_-])")
    return bool(pat.search(text))


def _has_evidence(c: Dict[str, Any]) -> bool:
    ev = c.get("evidence")
    if isinstance(ev, list):
        return any(str(x).strip() for x in ev)
    if isinstance(ev, str):
        return bool(ev.strip())
    return bool(c.get("evidence_ref") or c.get("evidence_path"))


def plan_auto_recover(rdiff: Dict[str, Any], round_no: int, max_rounds: int,
                      enabled: bool) -> Dict[str, Any]:
    """G1/G2/G3 的修复路径分流（自动 vs 人工）。

    自动修复的红线：**不得改变「审什么」的范围**。
      - G1 声明未勾选 → 自动重派（原 shard / 补审 Agent），不改变范围；
      - G3 勾选无结论 → 自动重总结（限 1 轮），不编造结论；
      - G2 计划未声明 → **禁止自动**，只能「补充分片重审」或「书面 waiver」。
    轮次上限 max_rounds；超限后 G1/G3 亦回硬门禁，强制人工介入。
    """
    g1 = list(rdiff.get("G1_unchecked", []))
    g2 = list(rdiff.get("G2_not_declared", []))
    g3 = list(rdiff.get("G3_no_conclusion", []))
    out: Dict[str, Any] = {
        "enabled": enabled, "round": round_no, "max_rounds": max_rounds,
        "reassign": [], "reconclude": [], "blocked": [], "notes": [],
        "budget_exhausted": False, "auto_ok": True,
    }
    if not enabled:
        return out
    out["budget_exhausted"] = round_no > max_rounds
    if out["budget_exhausted"]:
        out["blocked"] = sorted(set(g1 + g2 + g3))
        out["auto_ok"] = False
        out["notes"].append(
            f"自动修复轮次 {round_no} > 上限 {max_rounds}：G1/G3 亦回硬门禁，必须人工介入")
        return out
    out["reassign"] = [{"file": f, "action": "re-dispatch", "stage": "补审"}
                       for f in g1]
    out["reconclude"] = [{"file": f, "action": "re-summarize", "stage": "结论汇总"}
                         for f in g3]
    out["blocked"] = g2                        # G2 永不自动
    out["auto_ok"] = not g2
    if g1:
        out["notes"].append(f"G1 {len(g1)} 项 → 自动重派到原 shard（范围不变）")
    if g3:
        out["notes"].append(f"G3 {len(g3)} 项 → 自动重总结（限 1 轮，不得编造结论）")
    if g2:
        out["notes"].append(
            f"G2 {len(g2)} 项 → 禁止自动：须补充分片重审，或在 25-review-list.md "
            f"的 `## WAIVER` 段写明理由")
    return out


LAYER1_SCHEMAS = ("layer1-sinks/1.3", "layer1-sinks/1.2", "layer1-sinks/1.0")
SCAN_WAIVER_SCHEMA = "scan-waiver/1.0"
STAGE_SCHEMA = "audit-stages/1.0"
STAGE_STATUSES = ("success", "partial", "skipped", "failed")
SCAN_HARD_GAP_REASONS = ("too-large", "stat-failed", "read-error", "decode-error")
SCAN_SCOPE_REASONS = ("skip-dir", "excluded")


def _load_scan_waiver(path: Optional[str]) -> Dict[str, Any]:
    """载入 scan-waiver/1.0：对具体文件的扫描缺口做显式、可审计的豁免。"""
    out: Dict[str, Any] = {"provided": False, "files": {}, "errors": [], "schema": None}
    if not path:
        return out
    out["provided"] = True
    if not os.path.isfile(path):
        out["errors"].append(f"豁免文件不存在: {path}")
        return out
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        out["errors"].append(f"豁免文件解析失败: {exc}")
        return out
    if not isinstance(doc, dict) or str(doc.get("schema") or "") != SCAN_WAIVER_SCHEMA:
        out["errors"].append(f"豁免文件 schema 必须是 {SCAN_WAIVER_SCHEMA}")
        return out
    out["schema"] = doc.get("schema")
    for it in doc.get("files") or []:
        if not isinstance(it, dict):
            out["errors"].append(f"豁免条目必须是对象: {str(it)[:80]}")
            continue
        f = norm(str(it.get("path") or it.get("file") or ""))
        reason = str(it.get("reason") or "").strip()
        by = str(it.get("approved_by") or "").strip()
        if not f or not reason or not by:
            out["errors"].append(
                f"豁免条目缺 path/reason/approved_by: {str(it)[:80]}")
            continue
        out["files"][f] = {"reason": reason, "approved_by": by,
                           "scope": str(it.get("scope") or "file")}
    return out


def _engine_summary(es: Any) -> Dict[str, Any]:
    """把 engine_status 归一为 success / partial / skipped / failed（ISSUE-04）。"""
    out: Dict[str, Any] = {
        "verdict": "skipped", "reason": "", "engines": [],
        "fallback_reasons": {}, "structural_confirmed": 0,
        "regex_fallback": 0, "rules_with_structural": 0,
    }
    if not isinstance(es, dict):
        out["reason"] = "Layer 1 输出缺 engine_status"
        return out
    out["engines"] = sorted(k for k, v in (es.get("engines") or {}).items() if v)
    out["structural_confirmed"] = int(es.get("structural_confirmed") or 0)
    out["regex_fallback"] = int(es.get("regex_fallback") or 0)
    out["rules_with_structural"] = int(es.get("rules_with_structural") or 0)
    cnt: Dict[str, int] = {}
    for f in es.get("fallbacks") or []:
        if isinstance(f, dict):
            r = str(f.get("reason") or "unknown")
            cnt[r] = cnt.get(r, 0) + 1
    out["fallback_reasons"] = cnt
    if not es.get("structural_enabled"):
        out["verdict"] = "skipped"
        out["reason"] = "--no-structural（结构确认未启用）"
        return out
    if out["rules_with_structural"] == 0:
        out["verdict"] = "success"
        out["reason"] = "规则集无需结构确认"
        return out
    if not out["engines"]:
        out["verdict"] = "skipped"
        out["reason"] = "未找到 ast-grep / semgrep，结构确认全部降级为 regex"
        return out
    if cnt.get("engine-error"):
        out["verdict"] = "failed"
        out["reason"] = "结构引擎报错后降级"
        return out
    if out["regex_fallback"] > 0:
        out["verdict"] = "partial"
        detail = ", ".join(f"{k}×{v}" for k, v in sorted(cnt.items()))
        out["reason"] = f"部分命中缺少结构确认（{detail or '未知原因'}）"
        return out
    out["verdict"] = "success"
    out["reason"] = "结构确认全部成功"
    return out


def check_scan_integrity(path: Optional[str], waiver_path: Optional[str] = None
                         ) -> Dict[str, Any]:
    """消费 sink_scan.py 的 scan_integrity / engine_status（ISSUE-03 / ISSUE-04）。

    旧实现把完整性只写进 10-layer1-sinks.json，门禁从不读取，于是「扫描不完整」
    与「扫完没发现」在最终报告里长得一模一样。这里把缺口变成可判定的输入。

    verdict 四态：
      complete — 没有跳过、没有截断、没有解析失败；
      scoped   — 仅跳过规则声明的目录/正则排除（skip-dir / excluded），范围内完整；
      partial  — 有文件因体积/行数/分块上限被截断或静默跳过（未被豁免）；
      failed   — 有文件读取/stat/解码失败，或缺 scan_integrity（输出损坏）。
    """
    out: Dict[str, Any] = {
        "checked": False, "exists": False, "verdict": None, "ok": False,
        "complete_raw": None, "gaps": [], "blocking": [], "waived": [],
        "scope": {}, "skip_reason_counts": {}, "files_scanned": 0,
        "files_skipped": 0, "files_partial": 0, "findings": 0,
        "schema": None, "schema_ok": False, "engine": _engine_summary(None),
        "engine_verdict": None, "skipped": None, "error": None,
        "waiver_errors": [],
    }
    if not path:
        out["skipped"] = "未提供 --layer1（Layer 1 扫描完整性未纳入门禁）"
        return out
    out["checked"] = True
    if not os.path.isfile(path):
        out["error"] = f"Layer 1 输出不存在: {path}（缺文件不等于零发现）"
        out["verdict"] = "failed"
        out["blocking"].append({"code": "LAYER1_MISSING", "detail": out["error"]})
        return out
    out["exists"] = True
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        out["error"] = f"Layer 1 输出解析失败（不得当作空结果）: {exc}"
        out["verdict"] = "failed"
        out["blocking"].append({"code": "LAYER1_CORRUPT", "detail": out["error"]})
        return out
    if not isinstance(doc, dict):
        out["error"] = "Layer 1 输出顶层不是 JSON 对象"
        out["verdict"] = "failed"
        out["blocking"].append({"code": "LAYER1_CORRUPT", "detail": out["error"]})
        return out

    out["schema"] = str(doc.get("schema") or doc.get("version") or "")
    out["schema_ok"] = out["schema"] in LAYER1_SCHEMAS
    out["findings"] = len(doc.get("findings") or [])
    out["engine"] = _engine_summary(doc.get("engine_status"))
    out["engine_verdict"] = out["engine"]["verdict"]

    si = doc.get("scan_integrity")
    if not isinstance(si, dict):
        out["error"] = "Layer 1 输出缺 scan_integrity（旧版或被截断的输出）"
        out["verdict"] = "failed"
        out["blocking"].append({"code": "LAYER1_NO_INTEGRITY",
                                "detail": out["error"]})
        return out

    out["complete_raw"] = bool(si.get("complete"))
    out["files_scanned"] = int(si.get("files_scanned") or 0)
    out["files_skipped"] = int(si.get("files_skipped") or 0)
    out["files_partial"] = int(si.get("files_partial") or 0)
    out["skip_reason_counts"] = dict(si.get("skip_reason_counts") or {})
    out["scope"] = dict(si.get("scope") or {})

    waiver = _load_scan_waiver(waiver_path)
    out["waiver_errors"] = waiver["errors"]
    if waiver["errors"] and waiver_path:
        out["blocking"].append({"code": "SCAN_WAIVER_INVALID",
                                "detail": "; ".join(waiver["errors"])})

    gaps: List[Dict[str, Any]] = []
    for p in si.get("partial_files") or []:
        if not isinstance(p, dict):
            continue
        f = norm(str(p.get("file") or ""))
        gaps.append({"file": f, "reason": "partial",
                     "detail": str(p.get("truncation_reason") or "scan_complete=false"),
                     "bytes_total": p.get("bytes_total"),
                     "bytes_scanned": p.get("bytes_scanned"),
                     "lines_total": p.get("lines_total"),
                     "lines_scanned": p.get("lines_scanned")})
    for s in si.get("skipped_files") or []:
        if not isinstance(s, dict):
            continue
        reason = str(s.get("reason") or "unknown")
        if reason in SCAN_SCOPE_REASONS:
            continue
        f = norm(str(s.get("file") or ""))
        gaps.append({"file": f, "reason": reason,
                     "detail": (f"超过上限 {s.get('limit_mb')} MiB"
                                if s.get("limit_mb") is not None else reason),
                     "bytes_total": s.get("bytes_total")})

    for g in gaps:
        w = waiver["files"].get(g["file"])
        if w:
            g["waived"] = True
            g["waiver"] = w
            out["waived"].append({"file": g["file"], "reason": g["reason"],
                                  "waiver": w})
        else:
            g["waived"] = False

    unwaived = [g for g in gaps if not g["waived"]]
    hard_fail = any(g["reason"] in ("stat-failed", "read-error", "decode-error")
                    for g in unwaived)
    if not out["schema_ok"]:
        out["blocking"].append({
            "code": "LAYER1_SCHEMA",
            "detail": f"Layer 1 schema 未识别: {out['schema'] or '<缺失>'}"})
    if unwaived and hard_fail:
        out["verdict"] = "failed"
    elif unwaived:
        out["verdict"] = "partial"
    elif out["complete_raw"]:
        out["verdict"] = "complete"
    elif out["waived"]:
        # 缺口全部被显式豁免：结论是「按豁免范围可接受」，不是「扫全了」
        out["verdict"] = "scoped"
    elif (out["scope"].get("skip_dirs") or out["scope"].get("excluded")):
        out["verdict"] = "scoped"
    else:
        out["verdict"] = "partial"

    if out["verdict"] in ("partial", "failed"):
        for g in unwaived:
            out["blocking"].append({
                "code": ("LAYER1_READ_ERROR" if g["reason"] in
                         ("stat-failed", "read-error", "decode-error")
                         else "LAYER1_SCAN_GAP"),
                "detail": f"{g['file']}: {g['reason']}（{g['detail']}）"
                          f"{'，已截断' if g.get('bytes_scanned') is not None else ''}"})
    out["gaps"] = gaps
    out["ok"] = out["verdict"] in ("complete", "scoped") and not out["blocking"]
    return out


def check_stages(path: Optional[str]) -> Dict[str, Any]:
    """校验 audit-stages/1.0：必需阶段非 success 即阻断（ISSUE-04）。"""
    out: Dict[str, Any] = {
        "checked": False, "exists": False, "stages": [], "blocked": [],
        "warnings": [], "schema": None, "skipped": None, "error": None,
        "ok": False,
    }
    if not path:
        out["skipped"] = "未提供 --stages（阶段状态未登记）"
        return out
    out["checked"] = True
    if not os.path.isfile(path):
        out["error"] = f"阶段状态文件不存在: {path}"
        out["blocked"].append({"code": "STAGES_MISSING", "detail": out["error"]})
        return out
    out["exists"] = True
    try:
        with open(path, encoding="utf-8") as f:
            doc = json.load(f)
    except (OSError, json.JSONDecodeError) as exc:
        out["error"] = f"阶段状态文件解析失败（不得当作全部成功）: {exc}"
        out["blocked"].append({"code": "STAGES_CORRUPT", "detail": out["error"]})
        return out
    if not isinstance(doc, dict):
        out["error"] = "阶段状态文件顶层不是 JSON 对象"
        out["blocked"].append({"code": "STAGES_CORRUPT", "detail": out["error"]})
        return out
    out["schema"] = str(doc.get("schema") or "")
    if out["schema"] != STAGE_SCHEMA:
        out["error"] = (f"阶段状态 schema 必须是 {STAGE_SCHEMA}"
                        f"（实际 {out['schema'] or '<缺失>'}）")
        out["blocked"].append({"code": "STAGES_SCHEMA", "detail": out["error"]})
        return out

    for i, st in enumerate(doc.get("stages") or [], 1):
        if not isinstance(st, dict):
            out["blocked"].append({"code": "STAGES_CORRUPT",
                                   "detail": f"第 {i} 个 stage 不是对象"})
            continue
        sid = str(st.get("id") or st.get("stage") or st.get("name") or f"stage-{i}")
        status = str(st.get("status") or "").strip().lower()
        required = st.get("required", True) is not False
        rec = {"id": sid, "status": status, "required": required,
               "detail": str(st.get("detail") or ""),
               "fallback_reason": str(st.get("fallback_reason") or "")}
        if status not in STAGE_STATUSES:
            out["blocked"].append({
                "code": "STAGE_BAD_STATUS", "stage": sid,
                "detail": f"阶段 {sid} 状态非法: {status or '<缺失>'}"
                          f"（允许 {', '.join(STAGE_STATUSES)}）"})
            rec["status"] = "invalid"
            out["stages"].append(rec)
            continue
        out["stages"].append(rec)
        if required and status != "success":
            out["blocked"].append({
                "code": "STAGE_NOT_SUCCESS", "stage": sid,
                "detail": (f"必需阶段 {sid} 状态为 {status}"
                           + (f"（{rec['fallback_reason']}）"
                              if rec["fallback_reason"] else ""))})
        elif not required and status in ("partial", "skipped", "failed"):
            out["warnings"].append({
                "code": "STAGE_DEGRADED", "stage": sid,
                "detail": (f"非必需阶段 {sid} 状态为 {status}"
                           + (f"（{rec['fallback_reason']}）"
                              if rec["fallback_reason"] else ""))})
    out["ok"] = not out["blocked"]
    return out


def merge_stages(declared: Dict[str, Any], scan: Dict[str, Any],
                 require_structural: bool) -> Dict[str, Any]:
    """把 --stages 声明与 Layer 1 派生阶段合并，并交叉校验两者是否自相矛盾。"""
    stages = [dict(s) for s in declared.get("stages") or []]
    blocked = list(declared.get("blocked") or [])
    warnings = list(declared.get("warnings") or [])
    seen = {s["id"]: s for s in stages}

    def add(stage_id: str, status: str, required: bool, detail: str) -> None:
        if stage_id in seen:
            return
        rec = {"id": stage_id, "status": status, "required": required,
               "detail": detail, "derived": True}
        stages.append(rec)
        seen[stage_id] = rec

    if scan.get("checked"):
        mapping = {"complete": "success", "scoped": "success",
                   "partial": "partial", "failed": "failed"}
        status = mapping.get(str(scan.get("verdict")), "failed")
        add("layer1-scan", status, True,
            f"扫描完整性 verdict={scan.get('verdict')}")
        declared_scan = seen.get("layer1-scan") or seen.get("scan-integrity")
        if declared_scan and declared_scan.get("status") == "success" \
                and scan.get("verdict") in ("partial", "failed"):
            blocked.append({
                "code": "STAGE_INCONSISTENT", "stage": declared_scan["id"],
                "detail": (f"阶段 {declared_scan['id']} 声明 success，"
                           f"但 Layer 1 扫描完整性为 {scan.get('verdict')}")})

    if scan.get("checked"):
        ev = str(scan.get("engine_verdict") or "skipped")
        add("structural-engine", ev, bool(require_structural),
            str((scan.get("engine") or {}).get("reason") or ""))
        declared_engine = seen.get("structural-engine")
        if declared_engine and declared_engine.get("status") == "success" \
                and ev != "success":
            blocked.append({
                "code": "STAGE_INCONSISTENT", "stage": "structural-engine",
                "detail": (f"阶段 structural-engine 声明 success，"
                           f"但结构引擎状态为 {ev}")})

    return {"checked": declared.get("checked") or scan.get("checked"),
            "exists": declared.get("exists") or scan.get("exists"),
            "schema": declared.get("schema"), "stages": stages,
            "blocked": blocked, "warnings": warnings,
            "skipped": declared.get("skipped"), "error": declared.get("error"),
            "ok": not blocked}


def _minimal_manifest_errors(doc: Dict[str, Any]) -> List[Dict[str, str]]:
    """contracts.py 不可用时的兜底校验：只查最关键的四项。"""
    errs: List[Dict[str, str]] = []
    image = doc.get("image") if isinstance(doc.get("image"), dict) else {}
    for key, typ in (("schema", str), ("id", str), ("vendor", str),
                     ("product", str), ("version", str), ("arch", str)):
        if not isinstance(doc.get(key), typ) or not str(doc.get(key) or "").strip():
            errs.append({"path": f"manifest.{key}", "code": "MISSING",
                         "message": "必填字段缺失或类型错误（builtin 兜底校验）"})
    if not (isinstance(doc.get("sha256"), str) or isinstance(image.get("sha256"), str)):
        errs.append({"path": "manifest.image.sha256", "code": "MISSING",
                     "message": "缺少镜像哈希 image.sha256"})
    sha = doc.get("sha256") or image.get("sha256")
    if isinstance(sha, str) and not re.match(r"^[0-9a-f]{64}$", sha.lower()):
        errs.append({"path": "manifest.sha256", "code": "BAD_HASH",
                     "message": "sha256 必须是 64 位十六进制"})
    return errs


def check_manifest(path: Optional[str]) -> Dict[str, Any]:
    """FirmwareManifest 契约（ISSUE-05）：版本化输入，不接受自由文本替代。

    判定：
      * 未提供         -> SKIPPED（是否必需由 --require-manifest 决定）
      * 文件不存在     -> FAIL（MANIFEST_MISSING）
      * JSON 解析失败  -> FAIL（MANIFEST_CORRUPT）
      * 契约违规       -> FAIL（MANIFEST_INVALID，逐条列出字段路径）
      * image 哈希不符 -> FAIL（MANIFEST_HASH_MISMATCH，只警告版本号变化不算数）
    """
    out: Dict[str, Any] = {
        "checked": bool(path), "exists": False, "ok": False, "schema": None,
        "id": None, "arch": None, "sha256": None, "errors": [], "blocking": [],
        "image_verified": None, "skipped": None, "detail": "",
    }
    if not path:
        out["skipped"] = "未提供 --manifest"
        out["detail"] = out["skipped"]
        return out
    if not os.path.isfile(path):
        out["errors"].append({"path": "$", "code": "MISSING", "message": "文件不存在"})
        out["blocking"].append({"code": "MANIFEST_MISSING",
                                "detail": f"固件清单不存在：{path}"})
        out["detail"] = "文件不存在"
        return out
    out["exists"] = True
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        out["errors"].append({"path": "$", "code": "PARSE_ERROR", "message": str(exc)})
        out["blocking"].append({"code": "MANIFEST_CORRUPT",
                                "detail": f"固件清单解析失败：{exc}"})
        out["detail"] = "JSON 解析失败"
        return out
    if not isinstance(doc, dict):
        out["errors"].append({"path": "$", "code": "BAD_TYPE",
                              "message": "顶层必须是 JSON 对象"})
        out["blocking"].append({"code": "MANIFEST_INVALID",
                                "detail": "固件清单顶层必须是 JSON 对象"})
        out["detail"] = "顶层必须是对象"
        return out

    out["schema"] = doc.get("schema") if isinstance(doc.get("schema"), str) else None
    out["id"] = doc.get("id") if isinstance(doc.get("id"), str) else None
    out["arch"] = doc.get("arch") if isinstance(doc.get("arch"), str) else None
    _img0 = doc.get("image") if isinstance(doc.get("image"), dict) else {}
    _sha = doc.get("sha256")
    if not isinstance(_sha, str) and isinstance(_img0.get("sha256"), str):
        _sha = _img0["sha256"]
    out["sha256"] = _sha if isinstance(_sha, str) else None

    if _validate_manifest is not None:
        errs = _validate_manifest(doc)
    else:
        errs = _minimal_manifest_errors(doc)
        errs.append({"path": "$", "code": "DEGRADED",
                     "message": "contracts.py 不可用，已退化为内置最小校验"})
    out["errors"] = errs
    if errs:
        out["blocking"].append({"code": "MANIFEST_INVALID",
                                "detail": (f"{len(errs)} 处契约违规："
                                           + "；".join(f"{e['path']} {e['message']}"
                                                       for e in errs[:3]))})

    # 镜像哈希核对：清单声明的 image 若存在，必须与磁盘一致。
    image = doc.get("image")
    if isinstance(image, dict) and isinstance(image.get("path"), str):
        ip = image["path"]
        if not os.path.isabs(ip):
            ip = os.path.join(os.path.dirname(os.path.abspath(path)), ip)
        if os.path.isfile(ip):
            actual = _sha256_file(ip)
            declared = str(image.get("sha256") or "").lower()
            out["image_verified"] = (actual == declared)
            if actual != declared:
                out["blocking"].append({
                    "code": "MANIFEST_HASH_MISMATCH",
                    "detail": f"镜像哈希不符：清单 {declared[:12]}… 实际 {actual[:12]}…"})
        else:
            out["image_verified"] = None

    out["ok"] = not out["blocking"] and not errs
    if out["ok"]:
        out["detail"] = (f"schema={out['schema']} id={out['id']} arch={out['arch']} "
                         f"sha256={str(out['sha256'])[:12]}…")
    else:
        head = "；".join(f"{e['path']}: {e['message']}" for e in errs[:3])
        out["detail"] = (head or "；".join(str(b["detail"]) for b in out["blocking"][:2]))
        if _contract_summary is not None and errs:
            out["detail"] = _contract_summary(errs, limit=3)
    return out


def _minimal_audit_task_errors(doc: Dict[str, Any]) -> List[Dict[str, str]]:
    """contracts.py 不可用时的兜底校验：只查最关键的五项。"""
    errs: List[Dict[str, str]] = []
    for key in ("schema", "task_id", "manifest_id", "profile", "created_at"):
        if not isinstance(doc.get(key), str) or not str(doc.get(key) or "").strip():
            errs.append({"path": f"task.{key}", "code": "MISSING",
                         "message": "必填字段缺失或类型错误（builtin 兜底校验）"})
    scope = doc.get("scope")
    if not isinstance(scope, dict):
        errs.append({"path": "task.scope", "code": "MISSING",
                     "message": "缺少范围声明对象 scope"})
    return errs


def check_audit_task(path: Optional[str], manifest: Dict[str, Any]) -> Dict[str, Any]:
    """AuditTask 契约（ISSUE-05）：范围/预算声明必须能回指固件清单。

    判定：
      * 未提供          -> SKIPPED（可选输入）
      * 文件不存在      -> FAIL（AUDIT_TASK_MISSING）
      * JSON 解析失败   -> FAIL（AUDIT_TASK_CORRUPT）
      * 契约违规        -> FAIL（AUDIT_TASK_INVALID）
      * manifest_id 与 --manifest 不一致 -> FAIL（AUDIT_TASK_MISMATCH）
    """
    out: Dict[str, Any] = {
        "checked": bool(path), "ok": False, "schema": None, "task_id": None,
        "manifest_id": None, "profile": None, "errors": [], "blocking": [],
        "skipped": None, "detail": "",
    }
    if not path:
        out["skipped"] = "未提供 --audit-task"
        out["detail"] = out["skipped"]
        return out
    if not os.path.isfile(path):
        out["errors"].append({"path": "$", "code": "MISSING", "message": "文件不存在"})
        out["blocking"].append({"code": "AUDIT_TASK_MISSING",
                                "detail": f"审计任务文件不存在：{path}"})
        out["detail"] = "文件不存在"
        return out
    try:
        with open(path, "r", encoding="utf-8") as fh:
            doc = json.load(fh)
    except (OSError, json.JSONDecodeError) as exc:
        out["errors"].append({"path": "$", "code": "PARSE_ERROR", "message": str(exc)})
        out["blocking"].append({"code": "AUDIT_TASK_CORRUPT",
                                "detail": f"审计任务解析失败：{exc}"})
        out["detail"] = "JSON 解析失败"
        return out
    if not isinstance(doc, dict):
        out["errors"].append({"path": "$", "code": "BAD_TYPE",
                              "message": "顶层必须是 JSON 对象"})
        out["blocking"].append({"code": "AUDIT_TASK_INVALID",
                                "detail": "审计任务顶层必须是 JSON 对象"})
        out["detail"] = "顶层必须是对象"
        return out

    out["schema"] = doc.get("schema") if isinstance(doc.get("schema"), str) else None
    out["task_id"] = doc.get("task_id") if isinstance(doc.get("task_id"), str) else None
    out["profile"] = doc.get("profile") if isinstance(doc.get("profile"), str) else None
    out["manifest_id"] = (doc.get("manifest_id")
                          if isinstance(doc.get("manifest_id"), str) else None)
    if _validate_audit_task is not None:
        errs = _validate_audit_task(doc)
    else:
        errs = _minimal_audit_task_errors(doc)
        errs.append({"path": "$", "code": "DEGRADED",
                     "message": "contracts.py 不可用，已退化为内置最小校验"})
    out["errors"] = errs
    if errs:
        out["blocking"].append({"code": "AUDIT_TASK_INVALID",
                                "detail": (f"{len(errs)} 处契约违规："
                                           + "；".join(f"{e['path']} {e['message']}"
                                                       for e in errs[:3]))})

    # 回指核对：任务声明的固件必须就是本次门禁审的那一份。
    if manifest.get("checked") and out["manifest_id"] and manifest.get("id"):
        if out["manifest_id"] != manifest["id"]:
            out["blocking"].append({
                "code": "AUDIT_TASK_MISMATCH",
                "detail": (f"任务 manifest_id={out['manifest_id']} "
                           f"≠ 固件清单 id={manifest['id']}")})

    out["ok"] = not out["blocking"] and not errs
    if out["ok"]:
        out["detail"] = (f"schema={out['schema']} task={out['task_id']} "
                         f"profile={out['profile']} manifest={out['manifest_id']}")
    else:
        head = "；".join(f"{e['path']}: {e['message']}" for e in errs[:3])
        out["detail"] = (head or "；".join(str(b["detail"]) for b in out["blocking"][:2]))
        if _contract_summary is not None and errs:
            out["detail"] = _contract_summary(errs, limit=3)
    return out


def check_report_fields(report_path: str) -> Dict[str, Any]:
    """校验报告里每条漏洞（第 4 区块 ### F-00x）是否含 9 个必填字段。

    必填字段（任一缺失 → 该条 finding 不完整）：
      类型 / 位置 / 优先级 / 置信度 / CVSS 3.1 / Source / Sink / 完整调用链 / 证据
    另：置信度必须是 CONFIRMED / HYPOTHESIS（两态），HYPOTHESIS 必须写「缺项」。
    标题不得含评级括注（如 `(Critical)`）。
    """
    out: Dict[str, Any] = {"checked": False, "findings": 0, "incomplete": [],
                           "hypothesis_no_gap": [], "bad_title": [],
                           "skipped": None, "section_missing": False}
    if not report_path or not os.path.isfile(report_path):
        out["skipped"] = f"报告不存在: {report_path}"
        return out
    text = read(report_path)
    out["checked"] = True
    lines = text.splitlines()

    # 定位「漏洞详情」区块范围（从该标题到下一个 ## 标题）
    start = None
    end = len(lines)
    for i, ln in enumerate(lines):
        m = re.match(r"^#{1,3}\s*(.+)$", ln.strip())
        if not m:
            continue
        if start is None and ("漏洞详情" in m.group(1)):
            start = i
            continue
        if start is not None and i > start and re.match(r"^##\s", ln):
            end = i
            break
    if start is None:
        # 整块缺失是结构性缺陷：不能因为「0 条待检查」就判通过。
        out["section_missing"] = True
        out["skipped"] = "未找到「漏洞详情」区块（报告结构不完整）"
        return out

    # 按 ### F-xxx 切分
    blocks: List[tuple] = []
    cur: Optional[tuple] = None
    for i in range(start + 1, end):
        s = lines[i].strip()
        m = re.match(r"^#{3,4}\s*(F-\d+\s*[·:：]\s*.+)$", s)
        if m:
            if cur:
                blocks.append(cur)
            cur = (m.group(1), i, [])
            continue
        if cur is not None:
            cur[2].append(s)
    if cur:
        blocks.append(cur)

    REQUIRED = [
        ("类型", r"^\s*[-*]*\s*\*{0,2}类型\*{0,2}\s*[:：]"),
        ("位置", r"^\s*[-*]*\s*\*{0,2}位置\*{0,2}\s*[:：]"),
        ("优先级", r"^\s*[-*]*\s*\*{0,2}优先级\*{0,2}\s*[:：]"),
        ("置信度", r"^\s*[-*]*\s*\*{0,2}置信度\*{0,2}\s*[:：]"),
        ("CVSS 3.1", r"^\s*[-*]*\s*\*{0,2}CVSS\s*3\.1\*{0,2}\s*[:：]"),
        ("Source", r"^\s*[-*]*\s*\*{0,2}Source\*{0,2}\s*[:：]"),
        ("Sink", r"^\s*[-*]*\s*\*{0,2}Sink\*{0,2}\s*[:：]"),
        ("完整调用链", r"^\s*[-*]*\s*\*{0,2}完整调用链\*{0,2}\s*[:：]"),
        ("证据", r"^\s*[-*]*\s*\*{0,2}证据\*{0,2}\s*[:：]"),
    ]
    CONF_RE = re.compile(r"置信度\*{0,2}\s*[:：]\s*<?\s*(CONFIRMED|HYPOTHESIS)\b", re.I)
    GAP_RE = re.compile(r"缺项|缺哪一步|待验证|需验证|未验证|尚未")
    BAD_TITLE = re.compile(r"[（(]\s*(Critical|High|Medium|Low|严重|高|中|低)\s*[)）]")

    for title, idx, body in blocks:
        out["findings"] += 1
        blob = "\n".join(body)
        missing = [name for name, pat in REQUIRED
                   if not any(re.search(pat, b) for b in body)]
        if missing:
            out["incomplete"].append({"id": title.split()[0], "line": idx + 1,
                                      "missing": missing})
        # 标题评级
        if BAD_TITLE.search(title):
            out["bad_title"].append({"id": title.split()[0], "line": idx + 1,
                                     "title": title[:100]})
        # 置信度两态 + HYPOTHESIS 缺项
        cm = CONF_RE.search(blob)
        if cm and cm.group(1).upper() == "HYPOTHESIS" and not GAP_RE.search(blob):
            out["hypothesis_no_gap"].append({"id": title.split()[0], "line": idx + 1})
    return out


def check_cve_discipline(report_path: str) -> Dict[str, Any]:
    """校验报告是否把「组件版本命中 CVE」误当成「可被利用漏洞」。

    规则（对应 SKILL.md 铁律 7）：
      - V1 出现版本命中式断言（「组件/版本 存在 CVE」「受 CVE 影响」且无未验证措辞）
      - V2 CVE 出现在「漏洞统计」表里（应挪到组件风险区块）
      - V3 组件 CVE 被赋予 P0-P3 优先级或 CVSS 分会制造假优先级
      - V4 同一 CVE-ID 同时出现在 ④ 漏洞详情与 ⑥ 组件风险（Phase 4 验证通过后应「移动」，
           不是「复制」；⑥ 里只允许保留一行「→ F-0xx」指针）
    返回 violations；空表示通过。文件不存在时返回 skipped。
    """
    out: Dict[str, Any] = {"checked": False, "violations": [], "cve_total": 0,
                           "unverified_section": False, "skipped": None}
    if not report_path or not os.path.isfile(report_path):
        out["skipped"] = f"报告不存在: {report_path}"
        return out
    text = read(report_path)
    out["checked"] = True

    # 拆分区块，定位「组件风险」与「漏洞统计」区块的行区间
    lines = text.splitlines()
    sec_start: Dict[str, int] = {}
    for i, ln in enumerate(lines):
        m = re.match(r"^#{2,3}\s*(.+)$", ln.strip())
        if m:
            sec_start[m.group(1).strip()] = i
    comp_idx = [i for t, i in sec_start.items() if "组件" in t and "风险" in t]
    stat_idx = [i for t, i in sec_start.items() if "漏洞统计" in t]
    # ④ 漏洞详情：`### F-0xx · …` 形式的条目块
    det_idx = [i for t, i in sec_start.items() if re.match(r"^F-0\d", t.strip())]

    def in_ranges(idx: int, starts: List[int]) -> bool:
        if not starts:
            return False
        # 从该标题起，到下一个同级或更高级标题为止
        for s in starts:
            end = len(lines)
            for j in range(s + 1, len(lines)):
                if re.match(r"^#{2,3}\s", lines[j].strip()):
                    end = j
                    break
            if s <= idx < end:
                return True
        return False

    out["unverified_section"] = bool(comp_idx)
    cve_re = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)

    # 未验证措辞白名单：出现这些词说明已正确标注为线索
    hedge = re.compile(
        r"疑似|尚未|未验证|待验证|需验证|不可用|不确定|线索|版本命中|"
        r"cve-hit|影响区间|可能"
    )
    # 断言式措辞：直接下漏洞结论
    assert_re = re.compile(
        r"存在\s*(该|上述|对应)?\s*漏洞|设备存在|可被(攻击|利用)|"
        r"可远程(执行|攻击)|存在\s*CVE|受\s*CVE.{0,6}影响"
    )
    # 优先级 / 评分
    prio_re = re.compile(r"\bP[0-3]\b")
    cvss_re = re.compile(r"CVSS\s*[:：]?\s*\d")

    for i, ln in enumerate(lines):
        hit_cve = bool(cve_re.search(ln))
        use_assert = bool(assert_re.search(ln))
        use_hedge = bool(hedge.search(ln))
        has_prio = bool(prio_re.search(ln))
        has_cvss = bool(cvss_re.search(ln))
        line_in_comp = in_ranges(i, comp_idx)
        line_in_stat = in_ranges(i, stat_idx)

        if hit_cve:
            out["cve_total"] += cve_re.findall(ln).__len__()

        # V1：未加「未验证」措辞的版本命中式断言
        if hit_cve and use_assert and not use_hedge:
            out["violations"].append({
                "rule": "V1", "line": i + 1, "sev": "high",
                "msg": "把 CVE 命中写成漏洞断言，且未标注「未验证可达性」",
                "text": ln.strip()[:150]})

        # V2：CVE 出现在漏洞统计区块
        if hit_cve and line_in_stat and not line_in_comp:
            out["violations"].append({
                "rule": "V2", "line": i + 1, "sev": "high",
                "msg": "组件 CVE 出现在「漏洞统计」区块，应移入「组件风险（未验证）」",
                "text": ln.strip()[:150]})

        # V3：未验证的组件 CVE 被打优先级 / CVSS
        if hit_cve and not line_in_comp and (has_prio or has_cvss) and not use_hedge:
            out["violations"].append({
                "rule": "V3", "line": i + 1, "sev": "medium",
                "msg": "为未验证可达性的组件 CVE 赋予优先级或 CVSS，会制造假优先级",
                "text": ln.strip()[:150]})

    if out["cve_total"] and not out["unverified_section"]:
        out["violations"].append({
            "rule": "V0", "line": 0, "sev": "medium",
            "msg": "报告出现 CVE 但没有「组件风险（未验证）」区块，无法区分"
                   "「版本命中」与「可被利用漏洞」",
            "text": ""})

    # V4：同一 CVE-ID 不得同时作为「已升级漏洞（④）」与「未验证线索（⑥）」存在。
    #     Phase 4 验证通过后应把条目从 ⑥「移入」④；⑥ 内仅允许保留指向 ④ 的指针行，
    #     指针行特征：含「已升级/已迁移/升入/→ F-0xx」措辞，或已标 `cve-reachable`
    #     /`cve-exploitable`/`cve-nonreachable`（这些状态属于迁移台账，不再算未验证线索）。
    pointer_re = re.compile(
        r"已升|升入|已迁移|已移入|→\s*F-|->\s*F-|"
        r"cve-reachable|cve-exploitable|cve-nonreachable")

    def _cve_ids_in(starts: List[int]) -> set:
        ids: set = set()
        for s in starts:
            end = len(lines)
            for j in range(s + 1, len(lines)):
                if re.match(r"^#{2,3}\s", lines[j].strip()):
                    end = j
                    break
            for ln in lines[s:end]:
                if pointer_re.search(ln):
                    continue
                ids.update(x.upper() for x in cve_re.findall(ln))
        return ids

    dup_ids = sorted(_cve_ids_in(det_idx) & _cve_ids_in(comp_idx))
    for cid in dup_ids:
        out["violations"].append({
            "rule": "V4", "line": 0, "sev": "high",
            "msg": f"{cid} 同时出现在 ④ 漏洞详情与 ⑥ 组件风险：验证通过后应「移动」"
                   f"（从 ⑥ 删除，⑥ 只留一行「→ F-0xx」指针），不得两处并存造成重复计数",
            "text": cid})
    return out


def main() -> int:
    ap = argparse.ArgumentParser(description="覆盖率门禁校验")
    ap.add_argument("--plan", required=True)
    ap.add_argument("--verified", required=True)
    ap.add_argument("--candidates")
    ap.add_argument("--tiering")
    ap.add_argument("--report",
                    help="最终报告路径，用于校验「CVE 命中 ≠ 可利用漏洞」（铁律 7）")
    ap.add_argument("--review-list",
                    help="Phase 2.5 审阅文件清单（声明[- [x] `file`]），"
                         "用于 diff「计划 vs 声明 vs 实际结论」")
    ap.add_argument("--entrypoints",
                    help="G4：入口枚举文件 entrypoints.json（或含它的目录）。"
                         "给出即启用入口级覆盖校验（默认关闭以兼容旧流程）")
    ap.add_argument("--require-entrypoints", action="store_true",
                    help="G4 强制模式：未找到 entrypoints.json 时也判失败")
    ap.add_argument("--entrypoint-audit-min", type=float, default=100.0,
                    help="G4：入口审计率下限%%，默认 100")
    ap.add_argument("--text-kb-threshold", type=float, default=200.0,
                    help="G4：判定「服务型大二进制」的 text_kb 阈值，默认 200")
    ap.add_argument("--bypass-check", action="store_true",
                    help="G5：开启绕过矩阵完备校验（对 30-findings-verified.md）")
    ap.add_argument("--cross-request", action="store_true",
                    help="G6：开启跨请求污点溯源校验（持久化存储来源须声明写入面）")
    ap.add_argument("--taint-graph",
                    help="G7：跨请求污点图 taint-graph.json（由 taint_graph.py 生成）；"
                         "校验『写面 action ≠ 读面 action + 键一致 + 两端有证据』")
    ap.add_argument("--auto-recover", action="store_true",
                    help="G1/G3 自动修复（G2 永不自动）；默认关闭")
    ap.add_argument("--max-rounds", type=int, default=2,
                    help="--auto-recover 的轮次上限，默认 2；超限强制人工")
    ap.add_argument("--recover-round", type=int, default=1,
                    help="当前自动修复轮次，默认 1")
    ap.add_argument("--type-base", action="store_true",
                    help="校验报告「类型」字段能否命中 DKTSS Base 表（兜底规则）")
    ap.add_argument("--type-base-strict", action="store_true",
                    help="类型未命中 Base 表时判失败（默认仅告警）")
    ap.add_argument("--base-table",
                    help="Base 表来源，默认 references/reporting.md")
    ap.add_argument("--out")
    ap.add_argument("--t1-threshold", type=float, default=100.0)
    ap.add_argument("--t2-threshold", type=float, default=95.0)
    ap.add_argument("--lenient", action="store_true",
                    help="额外用子串匹配兜底（会把出现路径名当作已覆盖）")
    ap.add_argument("--profile", choices=("light", "standard", "strict"),
                    default="standard",
                    help="门禁档位：light=只查覆盖率；standard=当前默认；"
                         "strict=必需输入齐全 + 高级检查全部启用 + 未执行即失败")
    ap.add_argument("--allow-empty-candidates", action="store_true",
                    help="显式声明本次审计确实没有候选（空清单不再判失败）")
    ap.add_argument("--layer1",
                    help="sink_scan.py 的 10-layer1-sinks.json；strict 必填，"
                         "其 scan_integrity 纳入门禁判定")
    ap.add_argument("--stages",
                    help="阶段状态文件 audit-stages/1.0（success/partial/skipped/failed）")
    ap.add_argument("--scan-waiver",
                    help="扫描缺口豁免 scan-waiver/1.0（逐文件、需 reason 与 approved_by）")
    ap.add_argument("--require-structural", action="store_true",
                    help="结构引擎降级（partial/skipped/failed）即判失败")
    ap.add_argument("--legacy-text-candidates", action="store_true",
                    help="允许旧文本候选格式（非 JSON 行按 ID 正则解析；strict 下仍不通过）")
    ap.add_argument("--manifest",
                    help="firmware-manifest/1.0 固件清单（结构化契约输入，ISSUE-05）")
    ap.add_argument("--audit-task",
                    help="审计任务声明 JSON（audit-task/1.0，contracts.py 校验并核对 manifest_id）")
    ap.add_argument("--require-manifest", action="store_true",
                    help="强制要求 --manifest 通过契约校验（CI 与正式审计建议开启）")
    ap.add_argument("--gate-config",
                    help="输出 gate-config.json 的路径（记录执行了哪些检查与版本）")
    args = ap.parse_args()

    PROFILE = args.profile
    STRICT = PROFILE == "strict"

    # strict：高级检查全部默认开启，并用单一入口统一管理，
    # 避免「调用方漏写一个 flag，门禁就静默少跑一项检查」。
    if STRICT:
        args.bypass_check = True
        args.cross_request = True
        args.type_base = True
        args.type_base_strict = True
        args.require_entrypoints = True

    for p in (args.plan, args.verified):
        if not os.path.isfile(p):
            print(f"[error] 文件不存在: {p}", file=sys.stderr)
            return 2

    plan = parse_plan(args.plan)
    ver = parse_verified(args.verified)
    text = ver["text"]
    covered: Set[str] = set(ver["covered"])

    tier_of: Dict[str, str] = {r["file"]: r["tier"] for r in plan if r["tier"]}
    tindex = load_tiering_index(args.tiering) if args.tiering else {
        "skip": set(), "t2": set(), "t3": set(), "items": {}, "promotions": [], "ok": False}
    if args.tiering and not tindex["ok"]:
        print("[warn] tiering 解析失败或结构不符（G4 将无法判定适用文件）", file=sys.stderr)
    for f in tindex["skip"]:
        tier_of.setdefault(f, "SKIP")
    for f in tindex["t2"]:
        tier_of.setdefault(f, "T2")
    for f in tindex["t3"]:
        tier_of.setdefault(f, "T3")

    # 合并 tiering 里声明但 plan 里没有的文件
    known = {r["file"] for r in plan}
    for f, t in tier_of.items():
        if f not in known:
            plan.append({"file": f, "tier": t, "shard": "(tiering)"})
            known.add(f)

    if args.lenient:
        for r in plan:
            if r["file"] in text:
                covered.add(r["file"])

    missing = [r for r in plan
               if r["file"] not in covered
               and (r["tier"] or tier_of.get(r["file"], "")) != "SKIP"]
    by_tier_total: Dict[str, int] = {}
    by_tier_cov: Dict[str, int] = {}
    for r in plan:
        t = r["tier"] or tier_of.get(r["file"], "?")
        by_tier_total[t] = by_tier_total.get(t, 0) + 1
        if r["file"] in covered:
            by_tier_cov[t] = by_tier_cov.get(t, 0) + 1
        elif t == "SKIP":
            # SKIP 不要求逐文件语义结论，只要 Layer 1 关键字扫描覆盖即算通过
            by_tier_cov[t] = by_tier_cov.get(t, 0) + 1

    def pct(t: str) -> float:
        tot = by_tier_total.get(t, 0)
        return 100.0 if tot == 0 else round(by_tier_cov.get(t, 0) * 100.0 / tot, 2)

    # 候选处置率（结构化优先；文本匹配只在显式兼容模式下允许）
    cand = check_candidates(args.candidates, text, STRICT,
                            allow_empty=args.allow_empty_candidates,
                            legacy_text=args.legacy_text_candidates)
    cand_missing: List[str] = list(cand["unresolved"])

    # Layer 1 扫描完整性（ISSUE-03）与阶段状态（ISSUE-04）：
    # 两者都必须真正进入门禁，而不是只写在中间产物里。
    scan = check_scan_integrity(args.layer1, args.scan_waiver)
    declared_stages = check_stages(args.stages)
    stages = merge_stages(declared_stages, scan, args.require_structural)
    manifest = check_manifest(args.manifest)
    audit_task = check_audit_task(args.audit_task, manifest)
    blocking: List[Dict[str, Any]] = []
    blocking.extend(scan["blocking"])
    blocking.extend(stages["blocked"])
    blocking.extend(manifest["blocking"])
    blocking.extend(audit_task["blocking"])
    if cand["parse_errors"]:
        blocking.append({"code": "CAND_PARSE_ERROR",
                         "detail": f"{len(cand['parse_errors'])} 行候选记录解析失败"})
    if cand["reason"] in ("missing-file", "unsupported-schema",
                          "unversioned-input", "non-structured-mode"):
        blocking.append({"code": "CAND_INPUT_INVALID",
                         "detail": cand["skipped"] or cand["reason"]})

    # promotions 跟进
    promo_missing: List[str] = []
    for p in tindex.get("promotions", []):
        fn = norm(p.get("file", ""))
        if fn and fn not in covered:
            promo_missing.append(fn)

    # CVE 纪律检查（铁律 7）
    cve = check_cve_discipline(args.report) if args.report else {
        "checked": False, "violations": [], "cve_total": 0,
        "unverified_section": False, "skipped": "未提供 --report"}
    cve_hard = [v for v in cve["violations"] if v["sev"] == "high"]

    # 审阅清单三方对齐（对抗「声称 100% 实际 70-85%」）
    review = parse_review_list(args.review_list) if args.review_list else {
        "declared": set(), "checked": set(), "unchecked": set(),
        "total": 0, "exists": False}
    rdiff = diff_review_list(review, plan, covered, tier_of) if args.review_list else {
        "available": False, "declared": 0, "checked": 0,
        "G1_unchecked": [], "G2_not_declared": [], "G3_no_conclusion": [], "ok": True}

    # G1/G2/G3 修复路径分流（自动 vs 人工）
    recover = plan_auto_recover(rdiff, args.recover_round, args.max_rounds,
                               args.auto_recover)
    if recover["enabled"] and rdiff["available"]:
        # 硬门禁判据：G2 永不自动；G1/G3 仅在「未超轮次」时可由自动修复承接
        rdiff_hard_ok = (not rdiff["G2_not_declared"]
                         and (not recover["budget_exhausted"]
                              or not (rdiff["G1_unchecked"] or rdiff["G3_no_conclusion"])))
    else:
        rdiff_hard_ok = rdiff["ok"]

    # G4 入口级覆盖
    ep_path = args.entrypoints
    if ep_path and os.path.isdir(ep_path):
        ep_path = os.path.join(ep_path, "entrypoints.json")
    epres = check_entrypoints(ep_path, tindex, args.text_kb_threshold,
                             args.entrypoint_audit_min)
    # 显式给出 --entrypoints 却不存在，或 --require-entrypoints：都视为缺口，
    # 绝不静默跳过（否则「不交枚举」反而比「交了不全」更容易过门禁）。
    if not epres["checked"] and (args.require_entrypoints or args.entrypoints):
        epres["missing"] = [f for f in epres["required"]
                            if f not in epres.get("waived", [])]
        epres["ok"] = False
        epres["checked"] = True

    # G5 绕过矩阵完备
    byp = check_bypass_matrix(args.verified) if args.bypass_check else {
        "checked": False, "claims": [], "missing_matrix": [], "skipped": "未启用 --bypass-check"}

    # G6 跨请求污点溯源（对报告 30-findings 的 Source 字段）
    xreq = check_cross_request(args.report) if args.cross_request else {
        "checked": False, "findings": 0, "violations": [], "skipped": "未启用 --cross-request"}

    # G7 跨请求污点图（写面/读面/键/sink 四元组闭合）
    tgraph = check_taint_graph(args.taint_graph, args.report)

    # 类型 → DKTSS Base 命中
    base_path = args.base_table or os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "..", "references", "reporting.md")
    tbase = check_type_base(args.report, base_path) if (args.type_base or args.type_base_strict) else {
        "checked": False, "base_rows": 0, "report_labels": 0, "unmapped": [],
        "skipped": "未启用 --type-base"}

    checks = [
        ("T1 覆盖率 100%", pct("T1") >= args.t1_threshold,
         f"{pct('T1')}%（{by_tier_cov.get('T1',0)}/{by_tier_total.get('T1',0)}）"),
        ("T2 覆盖率 ≥ %.0f%%" % args.t2_threshold, pct("T2") >= args.t2_threshold,
         f"{pct('T2')}%（{by_tier_cov.get('T2',0)}/{by_tier_total.get('T2',0)}）"),
        ("promotions 跟进 100%", not promo_missing,
         f"缺失 {len(promo_missing)} 项"),
        ("无未审文件", not missing, f"缺失 {len(missing)} 个"),
    ]
    warn_checks: List[Tuple[str, str]] = []

    # 扫描完整性（ISSUE-03）：文件缺失/截断/解析失败都不等于「没发现」。
    if scan["checked"]:
        unwaived = [g for g in scan["gaps"] if not g.get("waived")]
        if scan["verdict"] in ("complete", "scoped"):
            detail = (f"verdict={scan['verdict']}；扫描 {scan['files_scanned']} 个文件，"
                      f"跳过 {scan['files_skipped']}、截断 {scan['files_partial']}")
            if scan["verdict"] == "scoped":
                detail += "；范围外仅为规则声明的目录/正则排除"
            if scan["waived"]:
                detail += f"；已豁免 {len(scan['waived'])} 个"
            checks.append(("扫描完整性（Layer 1）", True, detail))
        else:
            checks.append((
                "扫描完整性（Layer 1）", False,
                (scan.get("error") and f"{scan['error']}；" or "")
                + f"verdict={scan['verdict']}；缺口 {len(scan['gaps'])} 个，"
                  f"未豁免 {len(unwaived)} 个"
                + ("；存在读取/解析失败" if scan["verdict"] == "failed" else "")))

        # 结构引擎降级（ISSUE-04）：默认只警告；--require-structural 或引擎报错才阻断。
        ev = str(scan["engine_verdict"] or "skipped")
        ereason = str((scan["engine"] or {}).get("reason") or "")
        if ev == "success":
            checks.append((
                "结构引擎完整性", True,
                f"引擎 {','.join(scan['engine']['engines']) or '—'}；"
                f"结构确认 {scan['engine']['structural_confirmed']} 条"))
        elif args.require_structural or ev == "failed":
            checks.append(("结构引擎完整性", False, f"{ev}：{ereason}"))
        else:
            warn_checks.append(("结构引擎完整性",
                                f"{ev}：{ereason}（未启用 --require-structural）"))

    # 阶段状态（ISSUE-04）：必需阶段非 success 即阻断。
    if args.stages:
        if not stages["stages"]:
            checks.append(("审计阶段全部成功", False,
                           stages.get("error") or "阶段状态文件无有效阶段"))
        else:
            bad_stages = [s for s in stages["stages"]
                          if s.get("required", True)
                          and s.get("status") != "success"]
            detail = f"{len(stages['stages'])} 个阶段；非 success {len(bad_stages)} 个"
            if bad_stages:
                detail += "（" + "、".join(f"{s['id']}={s.get('status')}"
                                           for s in bad_stages[:6]) + "）"
            checks.append(("审计阶段全部成功", not bad_stages, detail))
            for w in stages["warnings"]:
                warn_checks.append(("阶段降级", str(w.get("detail") or "")))

    # 固件清单契约（ISSUE-05）：版本化输入 + 字段/类型/枚举校验 + 镜像哈希核对。
    if manifest["checked"]:
        checks.append(("固件清单契约（FirmwareManifest）", manifest["ok"],
                       manifest["detail"]))
    if audit_task["checked"]:
        checks.append(("审计任务契约（AuditTask）", audit_task["ok"],
                       audit_task["detail"]))
    # 候选处置：只有「真的评估过、且每条都有结构化状态」才算 PASS；
    # 未提供文件 / 文件不存在 / 空清单 一律进 SKIPPED 或 FAIL，不允许静默通过。
    if cand["checked"] and cand["total"] > 0:
        detail = f"{cand['disposed']}/{cand['total']} 已处置"
        if not cand["ok"]:
            detail += (f"；未处置 {len(cand['unresolved'])}、"
                       f"重复 {len(cand['duplicates'])}、"
                       f"未知状态 {len(cand['bad_status'])}、"
                       f"确认但缺证据 {len(cand['missing_evidence'])}")
        if cand["parse_errors"]:
            detail += f"；**解析失败 {len(cand['parse_errors'])} 行**"
        if cand["mode"] != "structured":
            detail += f"；**{cand['mode']} 兼容模式（无结构化保证）**"
        checks.append(("候选处置率 100%", cand["ok"], detail))
    elif cand["checked"]:
        # 文件存在但没有任何有效记录：空清单 / 解析失败 / 结构不受支持，
        # 三者都必须显式判定，绝不允许「没数据所以通过」。
        detail = cand["skipped"] or "空/无效候选清单"
        if cand["parse_errors"]:
            detail += f"；{len(cand['parse_errors'])} 行非法 JSON"
        checks.append(("候选处置率 100%", cand["ok"], detail))
    if rdiff["available"]:
        if recover["enabled"] and not rdiff["ok"]:
            note = (f"；自动修复第 {recover['round']}/{recover['max_rounds']} 轮"
                    f"：重派 {len(recover['reassign'])}、重总结 {len(recover['reconclude'])}、"
                    f"G2 阻断 {len(recover['blocked'])}")
            if recover["budget_exhausted"]:
                note += "（轮次超限，回硬门禁）"
        else:
            note = ""
        checks.append((
            "审阅清单与结论一致",
            rdiff_hard_ok,
            f"声明 {rdiff['declared']} / 勾选 {rdiff['checked']}"
            + ("" if rdiff["ok"] else
               f"；未勾 {len(rdiff['G1_unchecked'])}、未声明 {len(rdiff['G2_not_declared'])}、"
               f"勾选无结论 {len(rdiff['G3_no_conclusion'])}")
            + note))

    # 报告 9 必填字段校验
    fields = check_report_fields(args.report) if args.report else {
        "checked": False, "findings": 0, "incomplete": [],
        "hypothesis_no_gap": [], "bad_title": [], "skipped": "未提供 --report"}
    fields_bad = (len(fields["incomplete"]) + len(fields["hypothesis_no_gap"])
                  + len(fields["bad_title"]))
    if fields["checked"]:
        if fields.get("section_missing"):
            checks.append(("漏洞条目 9 字段完整", False, fields["skipped"]))
        else:
            checks.append((
                "漏洞条目 9 字段完整",
                fields_bad == 0,
                f"{fields['findings']} 条，{fields_bad} 处问题" if fields_bad
                else (f"{fields['findings']} 条全部完整" if fields["findings"]
                      else "报告未包含 finding 条目（0 条）")))
    if cve["checked"]:
        checks.append((
            "CVE 命中未被当作可利用漏洞",
            not cve_hard,
            f"{cve['cve_total']} 条 CVE，{len(cve_hard)} 处违规"
            + ("" if cve["unverified_section"] or not cve["cve_total"]
               else "，缺「组件风险」区块")))

    # G4 入口级覆盖（仅给出 --entrypoints / --require-entrypoints 时纳入门禁）
    if epres["checked"]:
        checks.append((
            "入口级覆盖（G4）",
            epres["ok"],
            f"适用 {len(epres['required'])} 个服务型大二进制；"
            f"缺记录 {len(epres['missing'])}、枚举不全 {len(epres['enum_incomplete'])}、"
            f"入口审计率 {epres['audited_ratio'] if epres['audited_ratio'] is not None else '—'}"
            f"%（门槛 {args.entrypoint_audit_min:g}%）"))

    # G5 绕过矩阵完备
    if byp["checked"]:
        checks.append((
            "绕过矩阵完备（G5）",
            not byp["missing_matrix"],
            f"{len(byp['claims'])} 处防护断言，{len(byp['missing_matrix'])} 处缺 B1–B12 矩阵"))

    # G6 跨请求污点溯源
    if xreq["checked"]:
        checks.append((
            "跨请求污点溯源（G6）",
            not xreq["violations"],
            f"持久化存储来源 {xreq['findings']} 条，缺写入面 {len(xreq['violations'])} 条"))

    # G7 跨请求污点图（高阶链必须四元组闭合）
    if tgraph["checked"]:
        checks.append((
            "跨请求污点图（G7）",
            not tgraph["violations"],
            f"高阶链 {tgraph['chains']} 条 / 一阶 {tgraph['first_order']} 条；"
            f"违规 {len(tgraph['violations'])} 条"
            + (f"；报告声称高阶={tgraph['claims_high_order']}" if tgraph["claims_high_order"] else "")))

    # 类型 → DKTSS Base 命中
    if tbase["checked"]:
        bad = len(tbase["unmapped"])
        if args.type_base_strict:
            checks.append((
                "报告类型命中 Base 表",
                bad == 0,
                f"Base {tbase['base_rows']} 行；报告 {tbase['report_labels']} 个类型标签，"
                f"未命中 {bad} 个"))
    # ── 未执行的检查：必须显式登记，不能从列表里消失 ────────────────────────
    # 「脚本具备某项检查」≠「本次审计执行了它」≠「它通过了」。
    # 旧实现只在 checked 时 append，导致没启用的高级检查在报告里完全不可见，
    # 退出码 0 被误读为「所有质量约束都过了」。
    skipped_checks: List[Tuple[str, str, bool]] = []
    if not scan["checked"]:
        # strict 下 --layer1 是必需输入：没交 Layer 1 输出就无从证明扫描完整
        skipped_checks.append(("扫描完整性（Layer 1）",
                               scan["skipped"] or "未提供 --layer1", True))
    if not manifest["checked"]:
        skipped_checks.append(("固件清单契约（FirmwareManifest）",
                               manifest["skipped"] or "未提供 --manifest",
                               bool(args.require_manifest)))
    if not audit_task["checked"]:
        skipped_checks.append(("审计任务契约（AuditTask）",
                               audit_task["skipped"] or "未提供 --audit-task",
                               False))
    if not cand["checked"]:
        skipped_checks.append(("候选处置率 100%",
                               cand["skipped"] or "未评估候选处置", True))
    if not rdiff["available"]:
        skipped_checks.append(("审阅清单与结论一致",
                               "未提供 --review-list", True))
    if not fields["checked"]:
        skipped_checks.append(("漏洞条目 9 字段完整",
                               fields.get("skipped") or "未提供 --report", True))
    if not cve["checked"]:
        skipped_checks.append(("CVE 命中未被当作可利用漏洞",
                               cve.get("skipped") or "未提供 --report", True))
    if not epres["checked"]:
        skipped_checks.append(("入口级覆盖（G4）",
                               epres.get("skipped") or "未提供 --entrypoints", True))
    if not byp["checked"]:
        skipped_checks.append(("绕过矩阵完备（G5）",
                               byp.get("skipped") or "未启用 --bypass-check", True))
    if not xreq["checked"]:
        skipped_checks.append(("跨请求污点溯源（G6）",
                               xreq.get("skipped") or "未启用 --cross-request", False))
    if not tgraph["checked"]:
        # 报告声称了高阶漏洞却没给图 → strict 下必须失败（「说自己是高阶」要有图兜底）
        skipped_checks.append(("跨请求污点图（G7）",
                               tgraph.get("skipped") or "未提供 --taint-graph",
                               bool(STRICT and tgraph["claims_high_order"])))
    if not tbase["checked"]:
        skipped_checks.append(("报告类型命中 Base 表",
                               tbase.get("skipped") or "未启用 --type-base", False))

    ROWS = [{"name": n, "status": "PASS" if ok else "FAIL", "detail": d,
             "required": True, "executed": True} for n, ok, d in checks]
    # WARN：检查执行了、也发现了降级，但不构成阻断（例如未启用 --require-structural
    # 时的结构引擎回落）。旧实现只有 PASS/FAIL/SKIPPED 三态，降级信息会丢失。
    ROWS += [{"name": n, "status": "WARN", "detail": d,
              "required": False, "executed": True} for n, d in warn_checks]
    ROWS += [{"name": n, "status": "SKIPPED", "detail": r,
              "required": req, "executed": False} for n, r, req in skipped_checks]

    failed = [r for r in ROWS if r["status"] == "FAIL"]
    if STRICT:
        # strict 下「必需检查没跑」按失败处理——这是整个 profile 的意义所在
        failed += [r for r in ROWS if r["status"] == "SKIPPED" and r["required"]]

    # 机器可读的阻断项：让编排层/CI 不必解析 Markdown 表格就能知道为什么没过。
    blocking.extend({"code": "CHECK_FAILED", "detail": f"{r['name']}：{r['detail']}"}
                    for r in ROWS if r["status"] == "FAIL")
    if STRICT:
        blocking.extend({"code": "CHECK_NOT_EXECUTED",
                         "detail": f"{r['name']}：{r['detail']}"}
                        for r in ROWS
                        if r["status"] == "SKIPPED" and r["required"])

    n_pass = sum(1 for r in ROWS if r["status"] == "PASS")
    n_skip = sum(1 for r in ROWS if r["status"] == "SKIPPED")
    n_warn = sum(1 for r in ROWS if r["status"] == "WARN")

    lines = [
        "# 覆盖率门禁报告（40-coverage.md）",
        "",
        f"> 档位 **{PROFILE}**　·　PASS {n_pass} / FAIL "
        f"{len([r for r in ROWS if r['status'] == 'FAIL'])} / WARN {n_warn} / SKIPPED {n_skip}",
        ">",
        "> `SKIPPED` 表示该检查**本次没有执行**，不等于通过。"
        + ("strict 档位下必需检查的 SKIPPED 判为失败。" if STRICT else
           "standard 档位下仅提示；正式审计请用 `--profile strict`。"),
        "",
        "## 判据",
        "",
        "| 检查项 | 结果 | 数值 / 原因 |",
        "|---|---|---|",
    ]
    for r in ROWS:
        mark = {"PASS": "PASS", "FAIL": "**FAIL**", "WARN": "**WARN**",
                "SKIPPED": "SKIPPED", "ERROR": "**ERROR**"}[r["status"]]
        lines.append("| %s | %s | %s |" % (r["name"], mark, r["detail"]))

    lines += ["", "## 分层覆盖率", "",
              "| Tier | 计划文件 | 已覆盖 | 覆盖率 | 门禁要求 |",
              "|---|---|---|---|---|",
              "| T1 | %d | %d | %s%% | 100%% |" % (by_tier_total.get("T1", 0), by_tier_cov.get("T1", 0), pct("T1")),
              "| T2 | %d | %d | %s%% | ≥95%% |" % (by_tier_total.get("T2", 0), by_tier_cov.get("T2", 0), pct("T2")),
              "| T3 | %d | %d | %s%% | — |" % (by_tier_total.get("T3", 0), by_tier_cov.get("T3", 0), pct("T3")),
              "| SKIP | %d | %d | %s%% | 关键字扫描 |" % (by_tier_total.get("SKIP", 0), by_tier_cov.get("SKIP", 0), pct("SKIP")),
              "| 合计 | %d | %d | %s%% | — |" % (len(plan), len(plan) - len(missing),
                                                 100.0 if not plan else round((len(plan) - len(missing)) * 100.0 / len(plan), 2)),
              ]

    lines += ["", "## 待补审清单", ""]
    if missing:
        lines += ["| Tier | 分片 | 文件 |", "|---|---|---|"]
        for r in missing:
            lines.append("| %s | %s | `%s` |" % (
                r["tier"] or tier_of.get(r["file"], "?"), r.get("shard", ""), r["file"]))
    else:
        lines.append("无。所有计划内文件均有审计结论。")

    # ── 扫描完整性 / 阶段状态（ISSUE-03 / ISSUE-04）──────────────────────────
    # 「扫描不完整」与「扫完没发现」必须在报告里长得完全不一样。
    if scan["checked"] or (args.stages and stages["stages"]):
        lines += ["", "## 扫描完整性与阶段状态", ""]
        if scan["checked"]:
            lines += [
                f"- Layer 1 verdict：`{scan['verdict']}`"
                f"（原始 `scan_integrity.complete={scan['complete_raw']}`；"
                f"schema=`{scan['schema'] or '—'}`）",
                f"- 已扫描 {scan['files_scanned']} 个文件；跳过 {scan['files_skipped']}、"
                f"截断 {scan['files_partial']}；findings {scan['findings']} 条",
            ]
            if scan["skip_reason_counts"]:
                lines.append("- 跳过原因：" + "，".join(
                    f"`{k}`×{v}"
                    for k, v in sorted(scan["skip_reason_counts"].items())))
            sc = (scan.get("scope") or {}) if isinstance(scan.get("scope"), dict) else {}
            bits = []
            if sc.get("skip_dirs"):
                bits.append("跳过目录 " + "、".join(
                    f"`{d}`" for d in list(sc["skip_dirs"])[:10]))
            if sc.get("excluded"):
                bits.append("排除正则 " + "、".join(
                    f"`{e}`" for e in list(sc["excluded"])[:10]))
            if bits:
                lines.append("- 声明范围外：" + "；".join(bits))
            lines.append("")
            if scan["gaps"]:
                lines += ["| 文件 | 原因 | 细节 | 处置 |", "|---|---|---|---|"]
                for g in scan["gaps"][:200]:
                    wv = g.get("waiver") or {}
                    disp = ("已豁免：" + str(wv.get("reason") or "—")
                            if g.get("waived") else "**未豁免（覆盖缺口）**")
                    lines.append("| `%s` | %s | %s | %s |" % (
                        g["file"], g["reason"],
                        str(g["detail"]).replace("|", "\\|"), disp))
                if len(scan["gaps"]) > 200:
                    lines.append(f"\n> 仅显示前 200 个缺口，共 {len(scan['gaps'])} 个。")
            else:
                lines.append("无扫描缺口（未跳过、未截断）。")
            eng = scan["engine"] or {}
            lines += [
                "",
                f"**结构引擎**：`{scan['engine_verdict']}` — {eng.get('reason') or '—'}",
                "",
                "- 引擎：" + ("、".join(f"`{e}`" for e in eng.get("engines") or [])
                            or "—")
                + f"；结构确认 {eng.get('structural_confirmed', 0)} 条、"
                  f"正则回落 {eng.get('regex_fallback', 0)} 条",
            ]
            fr = eng.get("fallback_reasons") or {}
            if fr:
                lines.append("- 回落原因：" + "，".join(
                    f"`{k}`×{v}" for k, v in sorted(fr.items())))
        for w in stages["warnings"]:
            lines.append("- ⚠ " + str(w.get("detail") or ""))
        for b in stages["blocked"]:
            lines.append(f"- ⛔ **{b.get('code')}** {b.get('detail') or ''}")
        if stages["stages"]:
            lines += ["", "| 阶段 | 状态 | 必需 | 说明 |", "|---|---|---|---|"]
            for s in stages["stages"]:
                lines.append("| `%s` | %s | %s | %s |" % (
                    s.get("id"), s.get("status"),
                    "是" if s.get("required", True) else "否",
                    str(s.get("detail") or s.get("fallback_reason") or "")
                    .replace("|", "\\|")))
        lines.append("")

    if manifest["checked"]:
        lines += ["", "## 固件清单契约（FirmwareManifest）", ""]
        if manifest["ok"]:
            lines += [
                f"- schema：`{manifest['schema']}`",
                f"- 固件：`{manifest['id']}`（arch `{manifest['arch']}`）",
                f"- 镜像 sha256：`{manifest['sha256']}`",
            ]
            if manifest["image_verified"] is True:
                lines.append("- 镜像哈希：已与磁盘文件核对一致")
        else:
            lines.append(f"- ⛔ 未通过：{manifest['detail']}")
            for e in manifest["errors"][:30]:
                lines.append(f"- `{e['path']}` [{e['code']}] {e['message']}")
        lines.append("")

    if audit_task["checked"]:
        lines += ["", "## 审计任务契约（AuditTask）", ""]
        if audit_task["ok"]:
            lines += [f"- schema：`{audit_task['schema']}`",
                      f"- 任务：`{audit_task['task_id']}`（profile `{audit_task['profile']}`）",
                      f"- 固件清单：`{audit_task['manifest_id']}`（已与 --manifest 核对）"]
        else:
            lines.append(f"- ⛔ 未通过：{audit_task['detail']}")
            for e in audit_task["errors"][:30]:
                lines.append(f"- `{e['path']}` [{e['code']}] {e['message']}")
        lines.append("")

    if cand["parse_errors"]:
        lines += ["", "## 候选文件解析失败（非法行不得被静默忽略）", "",
                  f"`{os.path.basename(args.candidates or '')}` 中有 "
                  f"{len(cand['parse_errors'])} 行不是合法 JSON 对象。"
                  "旧实现会直接跳过这些行，导致「少读了几条候选」和「候选都处置了」"
                  "在报告里无法区分。", "",
                  "| 行号 | 原因 | 片段 |", "|---|---|---|"]
        for e in cand["parse_errors"][:200]:
            lines.append("| %s | %s | `%s` |" % (
                e.get("line"), e.get("error"),
                str(e.get("sample") or "").replace("`", "'").replace("|", "\\|")[:100]))
        if len(cand["parse_errors"]) > 200:
            lines.append("")
            lines.append(f"> 仅显示前 200 条，共 {len(cand['parse_errors'])} 条。")

    if cand["checked"] and cand["mode"] != "structured":
        lines += ["", "## 候选输入为兼容模式（无结构化保证）", "",
                  f"mode=`{cand['mode']}`：部分候选只凭「报告里出现过 ID」判定处置，"
                  "没有结构化 status。该模式在 standard 下仅提示，"
                  "strict 下不构成通过路径。", ""]
        for c in cand["weak"]:
            lines.append(f"- `{c}`")

    if cand_missing:
        lines += ["", "## 未处置的候选（必须落到 status 枚举里的合法状态）", "",
                  "合法状态：" + "、".join(f"`{s}`" for s in sorted(CAND_STATUS)), ""]
        for c in cand_missing:
            lines.append(f"- `{c}`")

    if cand["duplicates"]:
        lines += ["", "## 候选 ID 重复（每条候选必须有唯一稳定 ID）", ""]
        for c in cand["duplicates"]:
            lines.append(f"- `{c}`")

    if cand["bad_status"]:
        lines += ["", "## 候选状态不在枚举内", ""]
        for b in cand["bad_status"]:
            lines.append(f"- `{b['id']}`：`{b['status']}`")

    if cand["missing_evidence"]:
        lines += ["", "## 标记为 confirmed 但缺证据", ""]
        for c in cand["missing_evidence"]:
            lines.append(f"- `{c}`")

    if promo_missing:
        lines += ["", "## 未跟进的动态提升（T2→T1 等）", ""]
        for p in promo_missing:
            lines.append(f"- `{p}`")

    if rdiff["available"]:
        lines += ["", "## 审阅清单 diff（计划 vs 声明 vs 实际结论）", ""]
        if rdiff["ok"]:
            lines.append(f"一致。声明 {rdiff['declared']} 个文件，全部勾选且均有结论。")
        else:
            lines += ["| 缺口 | 数量 | 说明 |", "|---|---|---|"]
            lines.append("| G1 声明未勾选 | %d | 清单里 `[ ]` 未打钩，等于声明了却没审 |"
                         % len(rdiff["G1_unchecked"]))
            lines.append("| G2 计划未声明 | %d | 计划要求审的 T1/T2 文件未进清单 |"
                         % len(rdiff["G2_not_declared"]))
            lines.append("| G3 勾选无结论 | %d | 打了钩但 `30-findings-verified.md` 无对应结论 |"
                         % len(rdiff["G3_no_conclusion"]))
            lines.append("")
            for label, key in (("G1 声明未勾选", "G1_unchecked"),
                               ("G2 计划未声明", "G2_not_declared"),
                               ("G3 勾选无结论", "G3_no_conclusion")):
                items = rdiff[key]
                if items:
                    lines.append(f"**{label}**（{len(items)}）")
                    lines.append("")
                    for f in items[:100]:
                        lines.append(f"- `{f}`")
                    lines.append("")

    if cve["checked"] and cve["violations"]:
        lines += ["", "## CVE 纪律检查（版本命中 ≠ 可利用漏洞）", ""]
        if not cve["unverified_section"] and cve["cve_total"]:
            lines.append("- **缺少「组件风险（未验证）」区块**：无法区分「版本命中」与「已可利用」。")
            lines.append("")
        lines += ["| 规则 | 行 | 严重度 | 说明 |", "|---|---|---|---|"]
        for v in cve["violations"]:
            lines.append("| %s | %s | %s | %s |" % (
                v["rule"], v["line"] or "-", v["sev"], v["msg"]))
            if v.get("text"):
                lines.append("")
                lines.append("  > `%s`" % v["text"].replace("|", "\\|"))
        lines.append("")
        lines.append("处置：把上述条目改为「疑似…尚未验证可达性」，移入第 6 区块，"
                     "并补做「代码是否存在 / 是否可达 / 是否已修复」三项检查后再升级。")
    elif cve["checked"]:
        lines += ["", "## CVE 纪律检查", "",
                  f"通过。报告含 {cve['cve_total']} 条 CVE 引用，"
                  + ("已单列「组件风险（未验证）」区块。"
                     if cve["unverified_section"] else "未发现违规。")]

    if fields["checked"] and fields_bad:
        lines += ["", "## 报告字段完整性（9 必填字段）", ""]
        if fields["incomplete"]:
            lines += ["| Finding | 行 | 缺失字段 |", "|---|---|---|"]
            for f in fields["incomplete"]:
                lines.append("| %s | %s | %s |" % (
                    f["id"], f["line"], "、".join(f["missing"])))
            lines.append("")
        if fields["bad_title"]:
            lines += ["**标题含评级括注**（评级应放「优先级」字段，不放标题）：", ""]
            for f in fields["bad_title"]:
                lines.append(f"- `{f['id']}`（第 {f['line']} 行）：{f['title']}")
            lines.append("")
        if fields["hypothesis_no_gap"]:
            lines += ["**HYPOTHESIS 未写明「缺项」**（必须写缺哪一步才能升级）：", ""]
            for f in fields["hypothesis_no_gap"]:
                lines.append(f"- `{f['id']}`（第 {f['line']} 行）")
            lines.append("")
    elif fields["checked"]:
        lines += ["", "## 报告字段完整性", "",
                  f"通过。{fields['findings']} 条漏洞条目均含 9 个必填字段。"]

    # G4 明细
    if epres["checked"]:
        lines += ["", "## 入口级覆盖（G4，对抗「文件级 100% 但函数级 0.2%」）", "",
                  f"- 适用对象：T1 且 `text_kb > {args.text_kb_threshold:g}` 的服务型可执行"
                  f"（`bin|sbin|usr/bin|usr/sbin` 下的 ELF，排除 `.so`）",
                  f"- 适用文件数：{len(epres['required'])}；豁免 {len(epres['waived'])}",
                  f"- 入口审计率：{epres['audited_done']}/{epres['audited_total']}"
                  f"（{epres['audited_ratio'] if epres['audited_ratio'] is not None else '—'}%）"
                  f"，门槛 {args.entrypoint_audit_min:g}%", ""]
        if epres["required"]:
            lines += ["| 文件 | 派发表 | 已枚举 | 已处置 |", "|---|---|---|---|"]
            by_file = {}
            try:
                for rec in (json.load(open(ep_path, encoding="utf-8")).get("files") or []):
                    by_file[norm(str(rec.get("file", "")))] = rec
            except Exception:  # noqa
                pass
            for f in epres["required"]:
                rec = by_file.get(f)
                if rec is None:
                    lines.append("| `%s` | — | — | **缺记录** |" % f)
                    continue
                hn = len(rec.get("handlers") or [])
                dn = sum(1 for h in (rec.get("handlers") or [])
                         if isinstance(h, dict) and h.get("conclusion"))
                lines.append("| `%s` | %s | %s | %s |" % (
                    f, rec.get("handler_table_count", "—"), hn, dn))
            lines.append("")
        if not epres["exists"]:
            lines.append(f"> 未找到 `entrypoints.json`（{epres['skipped']}）。"
                         "Phase 5 需先按 `entrypoints/v1` 生成入口枚举。")
            lines.append("")

    # G1/G2/G3 自动修复计划
    if recover["enabled"] and rdiff["available"]:
        lines += ["", "## 自动修复计划（G1/G2/G3 分流）", "",
                  f"轮次 {recover['round']}/{recover['max_rounds']}"
                  + ("　**（超限，已回硬门禁）**" if recover["budget_exhausted"] else ""), ""]
        for n in recover["notes"]:
            lines.append(f"- {n}")
        if recover["reassign"]:
            lines += ["", "**G1 自动重派**（不改变审计范围）", ""]
            for it in recover["reassign"][:200]:
                lines.append(f"- `{it['file']}` → {it['stage']}")
        if recover["reconclude"]:
            lines += ["", "**G3 自动重总结**（补产物，不编结论）", ""]
            for it in recover["reconclude"][:200]:
                lines.append(f"- `{it['file']}` → {it['stage']}")
        if recover["blocked"]:
            lines += ["", "**必须人工介入（禁止静默塞回清单）**", ""]
            for f in recover["blocked"][:200]:
                lines.append(f"- `{f}`")
        lines.append("")

    # G5 明细
    if byp["checked"] and byp["missing_matrix"]:
        lines += ["", "## 绕过矩阵完备（G5）", "",
                  "以下章节写了「防护存在 / 不可利用」类断言，却没有 B1–B12 绕过矩阵：", "",
                  "| 章节 | 行 | 已出现的 B 条目 |", "|---|---|---|"]
        for m in byp["missing_matrix"]:
            lines.append("| %s | %s | %s/12 |" % (m["title"], m["line"], m["items_found"]))
        lines += ["", "处置：「有防护」≠「防护有效」。对每个此类入口跑完 "
                  "B1–B12（见 `references/methodology.md` §3.1），每条落 "
                  "`N/A` / `已测·不可绕过` / `可绕过`，产出 `bypass_matrix` 后重跑。", ""]
    elif byp["checked"]:
        lines += ["", "## 绕过矩阵完备（G5）", "",
                  f"通过。{len(byp['claims'])} 处防护断言均有 B1–B12 矩阵。"]

    # G6 明细
    if xreq["checked"] and xreq["violations"]:
        lines += ["", "## 跨请求污点溯源（G6，高阶漏洞）", "",
                  "以下 finding 的 `Source:` 指向运行时写入的持久化存储"
                  "（nvram/uci 键，或 /tmp·/var 等可写路径），却未声明**写入面**：", "",
                  "| 条目 | 行 | Source |", "|---|---|---|"]
        for v in xreq["violations"]:
            lines.append("| %s | %s | %s |" % (v["title"], v["line"], v["source"]))
        lines += ["", "处置：污点可跨请求传递（Bridge, IEEE S&P'26）。必须在同一 finding 内"
                  "写明该存储由谁 / 哪个入口写入（写入面）——写入与读取常分属不同请求。"
                  "追踪法见 `references/methodology.md` §3.2 与 SKILL.md Phase 3 Track C。", ""]
    elif xreq["checked"]:
        lines += ["", "## 跨请求污点溯源（G6）", "",
                  f"通过。{xreq['findings']} 条持久化存储来源均已声明写入面。"]

    # G7 明细
    if tgraph["checked"] and (tgraph["violations"] or tgraph["warnings"]):
        s = tgraph["summary"] or {}
        lines += ["", "## 跨请求污点图（G7，高阶链四元组闭合）", "",
                  f"图内：键 {s.get('keys', 0)} 个 / 高阶链 {tgraph['chains']} 条 / "
                  f"一阶 {tgraph['first_order']} 条 / 控制键 {s.get('control_keys', 0)} 个 / "
                  f"ADG 边 {s.get('adg_edges', 0)} 条。", ""]
        if tgraph["violations"]:
            lines += ["以下链不成立（写面 action ≠ 读面 action 才是高阶；键必须一致；"
                      "两端都要 addr + evidence）：", ""]
            for v in tgraph["violations"]:
                lines.append(f"- {v}")
        if tgraph["warnings"]:
            lines += ["", "提示：", ""]
            for w in tgraph["warnings"]:
                lines.append(f"- {w}")
        lines += ["", "生成方式：`scripts/taint_graph.py build --facts taint-facts.json`；"
                  "常量键恢复：`scripts/taint_graph.py recover --src <反编译目录>`。"
                  "方法见 `references/high-order-taint.md`。", ""]
    elif tgraph["checked"]:
        s = tgraph["summary"] or {}
        lines += ["", "## 跨请求污点图（G7）", "",
                  f"通过。高阶链 {tgraph['chains']} 条、一阶 {tgraph['first_order']} 条，"
                  f"覆盖键 {s.get('keys', 0)} 个。"]

    # 类型 → Base 明细
    if tbase["checked"] and tbase["unmapped"]:
        lines += ["", "## 报告类型命中 DKTSS Base 表", "",
                  f"Base 表 {tbase['base_rows']} 行；以下 {len(tbase['unmapped'])} 个类型标签"
                  "未能命中，且未写「映射依据」（兜底规则）：", ""]
        for u in tbase["unmapped"]:
            lines.append(f"- `{u['label']}`（第 {u['line']} 行）")
        lines += ["", "处置：或把标签归一到 Base 表已有类型，或为该行补「映射依据」，"
                  "或在 `references/reporting.md` 的 Base 表补一行（防评分落空）。", ""]

    lines += ["", "## 结论", ""]
    if failed:
        lines += ["**门禁未通过，不得输出最终报告。** 请按上方待补审清单补齐后重跑本检查。", ""]
        for r in failed:
            tag = "未通过" if r["status"] == "FAIL" else "未执行（strict 视为失败）"
            lines.append(f"- {tag}：{r['name']}（{r['detail']}）")
    else:
        lines += [f"门禁通过（{PROFILE} 档位），可进入 Phase 5.2 规则沉淀与 5.3 报告生成。", ""]
        if n_warn:
            lines += [f"> 注意：有 {n_warn} 项**警告**（降级但不阻断，见上表 WARN）。"
                      "如需把降级也当作阻断，请加 `--require-structural`。", ""]
        if n_skip:
            lines += [f"> 注意：仍有 {n_skip} 项检查未执行（见上表 SKIPPED）。"
                      "若需「所有必需检查均已执行」的结论，请用 `--profile strict`。", ""]

    out_text = "\n".join(lines) + "\n"
    if args.out:
        d = os.path.dirname(os.path.abspath(args.out))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(out_text)
        print(f"[ok] 报告 → {args.out}")
        # 自动修复工作清单（供编排层消费）
        if args.auto_recover and rdiff["available"]:
            rec_path = os.path.splitext(args.out)[0] + ".auto-recover.json"
            payload = {
                "round": recover["round"], "max_rounds": recover["max_rounds"],
                "budget_exhausted": recover["budget_exhausted"],
                "reassign": recover["reassign"], "reconclude": recover["reconclude"],
                "blocked_manual": recover["blocked"], "notes": recover["notes"],
                "waiver_hint": "G2 需在 25-review-list.md 的 `## WAIVER` 段写明理由",
            }
            with open(rec_path, "w", encoding="utf-8", newline="\n") as f:
                json.dump(payload, f, ensure_ascii=False, indent=2)
            print(f"[ok] 自动修复计划 → {rec_path}")
    else:
        print(out_text)

    # ── gate-config.json：本次门禁到底执行了什么 ──────────────────────────────
    # 只记录「通过/失败」是不够的：同一份产物用不同档位跑会得到不同结论，
    # 所以要把档位、输入哈希、每项检查的执行状态和版本一起落盘，才能复算。
    cfg_path = args.gate_config
    if not cfg_path and STRICT and args.out:
        cfg_path = os.path.splitext(args.out)[0] + ".gate-config.json"
    if cfg_path:
        cfg = {
            "schema_version": "gate-config/1.1",
            "profile": PROFILE,
            "gate_version": GATE_VERSION,
            "strict": STRICT,
            "thresholds": {"t1": args.t1_threshold, "t2": args.t2_threshold,
                           "entrypoint_audit_min": args.entrypoint_audit_min,
                           "text_kb_threshold": args.text_kb_threshold},
            "flags": {
                "candidates": bool(args.candidates),
                "entrypoints": bool(args.entrypoints),
                "require_entrypoints": bool(args.require_entrypoints),
                "bypass_check": bool(args.bypass_check),
                "cross_request": bool(args.cross_request),
                "taint_graph": bool(args.taint_graph),
                "type_base_strict": bool(args.type_base_strict),
                "review_list": bool(args.review_list),
                "report": bool(args.report),
                "layer1": bool(args.layer1),
                "require_structural": bool(args.require_structural),
                "legacy_text_candidates": bool(args.legacy_text_candidates),
                "manifest": bool(args.manifest),
                "require_manifest": bool(args.require_manifest),
            },
            "inputs": {
                k: {"path": v, "sha256": _sha256_file(v)}
                for k, v in (("plan", args.plan), ("verified", args.verified),
                             ("candidates", args.candidates),
                             ("review_list", args.review_list),
                             ("tiering", args.tiering),
                             ("report", args.report),
                             ("taint_graph", args.taint_graph),
                             ("layer1", args.layer1),
                             ("stages", args.stages),
                             ("scan_waiver", args.scan_waiver),
                             ("manifest", args.manifest),
                             ("entrypoints", ep_path))
            },
            # 机器可读的阻断原因：编排层不必解析 Markdown 表格
            "blocked": blocking,
            "candidate_input": {
                "mode": cand["mode"],
                "schema": cand["schema"],
                "parse_complete": cand["parse_complete"],
                "parse_errors": len(cand["parse_errors"]),
                "total": cand["total"],
                "reason": cand["reason"],
            },
            "scan_integrity": ({
                "verdict": scan["verdict"],
                "complete_raw": scan["complete_raw"],
                "gaps": len(scan["gaps"]),
                "unwaived": len([g for g in scan["gaps"] if not g.get("waived")]),
                "waived": len(scan["waived"]),
                "files_scanned": scan["files_scanned"],
                "files_skipped": scan["files_skipped"],
                "files_partial": scan["files_partial"],
                "engine_verdict": scan["engine_verdict"],
            } if scan["checked"] else None),
            "stages": stages["stages"] or None,
            "manifest": ({
                "ok": manifest["ok"],
                "schema": manifest["schema"],
                "id": manifest["id"],
                "arch": manifest["arch"],
                "sha256": manifest["sha256"],
                "image_verified": manifest["image_verified"],
                "errors": len(manifest["errors"]),
            } if manifest["checked"] else None),
            "audit_task": ({
                "ok": audit_task["ok"],
                "schema": audit_task["schema"],
                "task_id": audit_task["task_id"],
                "manifest_id": audit_task["manifest_id"],
                "profile": audit_task["profile"],
                "errors": len(audit_task["errors"]),
            } if audit_task["checked"] else None),
            "checks": ROWS,
            "summary": {
                "pass": n_pass,
                "fail": sum(1 for r in ROWS if r["status"] == "FAIL"),
                "warn": n_warn,
                "skipped": n_skip,
                "error": sum(1 for r in ROWS if r["status"] == "ERROR"),
                "executed": sum(1 for r in ROWS if r["executed"]),
                "total": len(ROWS),
            },
            "result": "fail" if failed else "pass",
        }
        d = os.path.dirname(os.path.abspath(cfg_path))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(cfg_path, "w", encoding="utf-8", newline="\n") as f:
            json.dump(cfg, f, ensure_ascii=False, indent=2)
        print(f"[ok] 门禁配置 → {cfg_path}")

    for r in ROWS:
        print(f"  {r['status']:<7} {r['name']}: {r['detail']}")
    if tbase["checked"] and tbase["unmapped"]:
        tag = "FAIL" if args.type_base_strict else "WARN"
        print(f"  {tag}  报告类型命中 Base 表: {len(tbase['unmapped'])} 个未命中"
              f"（{'--type-base-strict 已判失败' if args.type_base_strict else '仅告警'}）",
              file=sys.stderr)
    if failed:
        print(f"[gate] 未通过（{len(failed)} 项，档位 {PROFILE}）", file=sys.stderr)
        return 1
    print(f"[gate] 通过（档位 {PROFILE}；PASS {n_pass} / WARN {n_warn} / "
          f"SKIPPED {n_skip}）")
    return 0


if __name__ == "__main__":
    sys.exit(main())
