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

判据：
  T1 覆盖率 100%（硬门禁）
  T2 覆盖率 >= 95%
  候选处置率 100%（每条 candidate 必须落到 validated / NOT_FOUND / 待动态验证）
  promotions 跟进率 100%

退出码：0 通过；1 未通过（缺口写入 40-coverage.md）；2 参数/文件错误
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, List, Optional, Set

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


def norm(p: str) -> str:
    p = p.strip().strip("`").strip()
    p = p.replace("\\", "/")
    p = re.sub(r"^\./", "", p)
    p = re.sub(r":(0x[0-9a-fA-F]+|\d+)$", "", p)     # 去掉 :行号 / :偏移
    p = re.sub(r":(0x[0-9a-fA-F]+\(\d+\))$", "", p)
    return p.strip()


def read(path: str) -> str:
    with open(path, encoding="utf-8", errors="replace") as f:
        return f.read()


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
            if part and "/" in part and not part.startswith("http"):
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
        if not raw or "/" not in raw or raw.startswith("http"):
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


def check_report_fields(report_path: str) -> Dict[str, Any]:
    """校验报告里每条漏洞（第 4 区块 ### F-00x）是否含 9 个必填字段。

    必填字段（任一缺失 → 该条 finding 不完整）：
      类型 / 位置 / 优先级 / 置信度 / CVSS 3.1 / Source / Sink / 完整调用链 / 证据
    另：置信度必须是 CONFIRMED / HYPOTHESIS（两态），HYPOTHESIS 必须写「缺项」。
    标题不得含评级括注（如 `(Critical)`）。
    """
    out: Dict[str, Any] = {"checked": False, "findings": 0, "incomplete": [],
                           "hypothesis_no_gap": [], "bad_title": [], "skipped": None}
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
    ap.add_argument("--out")
    ap.add_argument("--t1-threshold", type=float, default=100.0)
    ap.add_argument("--t2-threshold", type=float, default=95.0)
    ap.add_argument("--lenient", action="store_true",
                    help="额外用子串匹配兜底（会把出现路径名当作已覆盖）")
    args = ap.parse_args()

    for p in (args.plan, args.verified):
        if not os.path.isfile(p):
            print(f"[error] 文件不存在: {p}", file=sys.stderr)
            return 2

    plan = parse_plan(args.plan)
    ver = parse_verified(args.verified)
    text = ver["text"]
    covered: Set[str] = set(ver["covered"])

    tier_of: Dict[str, str] = {r["file"]: r["tier"] for r in plan if r["tier"]}
    t1_declared: Set[str] = set()
    if args.tiering and os.path.isfile(args.tiering):
        try:
            tj = json.load(open(args.tiering, encoding="utf-8"))
            t = tj.get("tiering") or tj.get("rootfs_analysis", {}).get("tiering") or {}
            for f in t.get("t1_list", []):
                t1_declared.add(norm(f))
            for f in t.get("skip_list", []):
                tier_of.setdefault(norm(f), "SKIP")
            for f in t.get("t2_list", []):
                tier_of.setdefault(norm(f), "T2")
            for f in t.get("t3_list", []):
                tier_of.setdefault(norm(f), "T3")
        except Exception as e:  # noqa
            print(f"[warn] tiering 解析失败: {e}", file=sys.stderr)

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

    # 候选处置率
    cand_total = cand_disposed = 0
    cand_missing: List[str] = []
    if args.candidates and os.path.isfile(args.candidates):
        with open(args.candidates, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    c = json.loads(line)
                except json.JSONDecodeError:
                    continue
                cand_total += 1
                cid = str(c.get("id", ""))
                if cid and cid in text:
                    cand_disposed += 1
                else:
                    cand_missing.append(cid or line[:60])

    # promotions 跟进
    promo_missing: List[str] = []
    if args.tiering and os.path.isfile(args.tiering):
        try:
            tj = json.load(open(args.tiering, encoding="utf-8"))
            t = tj.get("tiering") or tj.get("rootfs_analysis", {}).get("tiering") or {}
            for p in t.get("promotions", []):
                fn = norm(p.get("file", ""))
                if fn and fn not in covered:
                    promo_missing.append(fn)
        except Exception:  # noqa
            pass

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

    checks = [
        ("T1 覆盖率 100%", pct("T1") >= args.t1_threshold,
         f"{pct('T1')}%（{by_tier_cov.get('T1',0)}/{by_tier_total.get('T1',0)}）"),
        ("T2 覆盖率 ≥ %.0f%%" % args.t2_threshold, pct("T2") >= args.t2_threshold,
         f"{pct('T2')}%（{by_tier_cov.get('T2',0)}/{by_tier_total.get('T2',0)}）"),
        ("候选处置率 100%", (cand_total == 0 or cand_disposed == cand_total),
         f"{cand_disposed}/{cand_total}"),
        ("promotions 跟进 100%", not promo_missing,
         f"缺失 {len(promo_missing)} 项"),
        ("无未审文件", not missing, f"缺失 {len(missing)} 个"),
    ]
    if rdiff["available"]:
        checks.append((
            "审阅清单与结论一致",
            rdiff["ok"],
            f"声明 {rdiff['declared']} / 勾选 {rdiff['checked']}"
            + ("" if rdiff["ok"] else
               f"；未勾 {len(rdiff['G1_unchecked'])}、未声明 {len(rdiff['G2_not_declared'])}、"
               f"勾选无结论 {len(rdiff['G3_no_conclusion'])}")))

    # 报告 9 必填字段校验
    fields = check_report_fields(args.report) if args.report else {
        "checked": False, "findings": 0, "incomplete": [],
        "hypothesis_no_gap": [], "bad_title": [], "skipped": "未提供 --report"}
    fields_bad = (len(fields["incomplete"]) + len(fields["hypothesis_no_gap"])
                  + len(fields["bad_title"]))
    if fields["checked"]:
        checks.append((
            "漏洞条目 9 字段完整",
            fields_bad == 0,
            f"{fields['findings']} 条，{fields_bad} 处问题"
            if fields_bad else f"{fields['findings']} 条全部完整"))
    if cve["checked"]:
        checks.append((
            "CVE 命中未被当作可利用漏洞",
            not cve_hard,
            f"{cve['cve_total']} 条 CVE，{len(cve_hard)} 处违规"
            + ("" if cve["unverified_section"] or not cve["cve_total"]
               else "，缺「组件风险」区块")))
    failed = [c for c in checks if not c[1]]

    lines = [
        "# 覆盖率门禁报告（40-coverage.md）",
        "",
        "## 判据",
        "",
        "| 检查项 | 结果 | 数值 |",
        "|---|---|---|",
    ]
    for name, ok, val in checks:
        lines.append("| %s | %s | %s |" % (name, "PASS" if ok else "**FAIL**", val))

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

    if cand_missing:
        lines += ["", "## 未处置的候选（必须升为 validated / 降为 NOT_FOUND / 标注待动态验证）", ""]
        for c in cand_missing:
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

    lines += ["", "## 结论", ""]
    if failed:
        lines += ["**门禁未通过，不得输出最终报告。** 请按上方待补审清单补齐后重跑本检查。", ""]
        for name, _ok, val in failed:
            lines.append(f"- 未通过：{name}（{val}）")
    else:
        lines += ["门禁通过，可进入 Phase 5.2 规则沉淀与 5.3 报告生成。", ""]

    out_text = "\n".join(lines) + "\n"
    if args.out:
        d = os.path.dirname(os.path.abspath(args.out))
        if d:
            os.makedirs(d, exist_ok=True)
        with open(args.out, "w", encoding="utf-8", newline="\n") as f:
            f.write(out_text)
        print(f"[ok] 报告 → {args.out}")
    else:
        print(out_text)

    for name, ok, val in checks:
        print(f"  {'PASS' if ok else 'FAIL'}  {name}: {val}")
    if failed:
        print(f"[gate] 未通过（{len(failed)} 项）", file=sys.stderr)
        return 1
    print("[gate] 通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())
