#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
taint_graph.py — 跨请求（高阶）污点图：BDG/ADG 的最小可执行实现

背景（方法来源：Bridge, IEEE S&P 2026；已用其 artifact 在 DIR878 上实测复现）：
  一阶漏洞在一个请求内闭合：source → … → sink。
  高阶漏洞的链被**持久化存储**切断：
      请求 1（action A）：用户输入 → nvram_safe_set("k", v)
      请求 2（action B）：nvram_safe_get("k") → system(...)
  只审单请求时，B 里的 `k` **没有写入点**，A 里的 `v` **没有消费点**，两边都看
  不出问题。要证明这类漏洞，必须显式构造一条**五元组链**：

      write.action --key--> store --key--> read.trigger_action
                                          └─ via(控制值) → read.binary:addr → sink

  注意两个「action」不是一回事（实测校正）：
    · read.trigger_action = 前端发起、最终导致该次读取的 action（来自 ADG）
    · read.binary:addr    = 真正执行读取的进程与地址（BDG 的 get 侧，常是 rc/librcm.so）
  Bridge 的 `other_get` 只是说「读发生在另一个二进制」；**一阶/高阶的分界是
  写它的请求与触发读的请求是否同一个**。DIR878 的 `SysLogRemote_IPAddress`
  就是典型一阶：set 与 trigger 都是 SetSysLogSettings，但读点落在 rc。

本脚本把五元组变成可执行产物 `taint-graph.json`：把散在报告正文里的
「写入面 / 键 / 触发 action / 读点 / sink」抽取成图，做**机械可判**的一致性
检查，供 `coverage_gate.py --taint-graph` 消费。它回答四个问题：

  1. 这个键到底被哪些 action 写过、被哪些进程读过？（BDG）
  2. 写它的请求与触发读的请求**是不是同一个**？相同 → 一阶，必须降级标注。
  3. 键两端**是否字面一致**？不一致 → 常量恢复没做（见 `recover`），配对无效。
  4. 读点在别的进程时，**哪个控制值**把请求带过去？没有 → 只是假设（缺 ADG 边）。

三种用法：

  # 1) 从人工/半自动整理的 facts 构图并自检
  python taint_graph.py build --facts fw-audit/<t>/taint-facts.json \\
      --out fw-audit/<t>/taint-graph.json

  # 2) 从反编译伪代码里做常量恢复，生成 facts 骨架（OD-ICP 的轻量版）
  python taint_graph.py recover --src fw-audit/<t>/decomp/ \\
      --out fw-audit/<t>/taint-facts.json --target myrouter

  # 3) 看统计
  python taint_graph.py stats --graph fw-audit/<t>/taint-graph.json

只用 Python 标准库。不做反编译、不做符号执行——那是 IDA/Ghidra 与 angr 的事；
本脚本负责**把证据组织成可被门禁否决的形状**。
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

GRAPH_SCHEMA = "taint-graph/1.0"
FACTS_SCHEMA = "taint-facts/1.0"
TOOL = {"name": "taint_graph.py", "version": "1.0"}

HERE = os.path.dirname(os.path.abspath(__file__))
DEFAULT_IPC_TABLE = os.path.join(os.path.dirname(HERE), "assets", "ipc-functions.json")


# ── 公共工具 ──────────────────────────────────────────────────────────────────

def find_interval(value: int) -> int:
    """Bridge 的相对阈值：取 value 所在 2 的幂区间的下界的一半。

    find_interval(5)=2, (12)=4, (100)=32, (1000)=256。
    用途：集中性判定除了绝对阈值（10），还要排除『只有极少数键特别热』的干扰，
    因此候选键必须同时超过 top 值对应的相对阈值。
    """
    if value < 1:
        return 0
    i = 0
    while True:
        lower, upper = 2 ** i, 2 ** (i + 1)
        if lower <= value < upper:
            return 2 ** (i - 1) if i else 0
        i += 1


def load_json(path: str) -> Dict[str, Any]:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def dump_json(obj: Any, path: str) -> None:
    d = os.path.dirname(os.path.abspath(path))
    if d and not os.path.isdir(d):
        os.makedirs(d, exist_ok=True)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=False)
        fh.write("\n")


def _as_list(v: Any) -> List[Any]:
    if v is None:
        return []
    if isinstance(v, list):
        return v
    return [v]


def _norm_key(k: Any) -> str:
    """键归一：去空白、去引号。不做大小写折叠——nvram 键区分大小写。"""
    if k is None:
        return ""
    s = str(k).strip()
    if len(s) >= 2 and s[0] == s[-1] and s[0] in "\"'":
        s = s[1:-1]
    return s


# ── 词表 ──────────────────────────────────────────────────────────────────────

def load_ipc_table(path: Optional[str] = None) -> Dict[str, Any]:
    p = path or DEFAULT_IPC_TABLE
    if not os.path.isfile(p):
        raise SystemExit(f"[error] IPC 词表不存在: {p}")
    return load_json(p)


def _sink_kinds(ipc: Dict[str, Any]) -> Dict[str, str]:
    """函数名 → sink 类型（command_exec / weak_copy / …）。"""
    out: Dict[str, str] = {}
    for kind, info in (ipc.get("sinks") or {}).items():
        for fn in info.get("functions") or []:
            out.setdefault(fn, kind)
    return out


def _mech_of(func: str, ipc: Dict[str, Any], direction: str) -> Optional[str]:
    for mech, info in (ipc.get("mechanisms") or {}).items():
        for item in info.get(direction) or []:
            if item.get("name") == func:
                return mech
    return None


# ── BDG：键 → 写端/读端 ───────────────────────────────────────────────────────

def _iter_endpoints(actions: Iterable[Dict[str, Any]], field: str):
    for act in actions:
        aid = act.get("id") or act.get("action") or ""
        binary = act.get("binary") or ""
        for ep in _as_list(act.get(field)):
            if not isinstance(ep, dict):
                continue
            yield aid, binary, ep


def build_graph(facts: Dict[str, Any], ipc: Dict[str, Any]) -> Dict[str, Any]:
    """facts → taint-graph。不做任何『猜测式补齐』：缺什么就记成 defect。"""
    actions = facts.get("actions") or []
    store_type = facts.get("store_type") or ""
    sink_kinds = _sink_kinds(ipc)
    errors: List[str] = []
    defects: List[Dict[str, Any]] = []

    if facts.get("schema") and facts["schema"] != FACTS_SCHEMA:
        errors.append(f"facts.schema 应为 {FACTS_SCHEMA}，实际 {facts.get('schema')}")

    keys: Dict[str, Dict[str, Any]] = {}

    def slot(k: str) -> Dict[str, Any]:
        return keys.setdefault(k, {"writers": [], "readers": [], "reads_without_sink": []})

    for aid, binary, ep in _iter_endpoints(actions, "writes"):
        if not aid:
            defects.append({"kind": "action-unnamed", "detail": "writes 端点缺 action id"})
            continue
        mech_w = ep.get("mechanism") or _mech_of(ep.get("func") or "", ipc, "write") or ""
        if mech_w and (ipc.get("mechanisms") or {}).get(mech_w, {}).get("keyed") is False:
            defects.append({"kind": "mechanism-not-keyed", "action": aid, "binary": binary,
                            "func": ep.get("func"),
                            "detail": f"{mech_w} 的参数是控制值不是存储键，应写成 ipc_control（ADG 边）"})
            continue
        k = _norm_key(ep.get("key"))
        if not k:
            defects.append({"kind": "key-unrecovered", "action": aid, "binary": binary,
                            "func": ep.get("func"), "detail": "写端键为空/未恢复"})
            continue
        slot(k)["writers"].append({
            "action": aid, "binary": binary,
            "func": ep.get("func") or "",
            "addr": ep.get("addr") or "",
            "value_from": ep.get("value_from") or "",
            "mechanism": mech_w,
            "evidence": ep.get("evidence") or "",
        })

    for aid, binary, ep in _iter_endpoints(actions, "reads"):
        if not aid:
            defects.append({"kind": "action-unnamed", "detail": "reads 端点缺 action id"})
            continue
        k = _norm_key(ep.get("key"))
        if not k:
            defects.append({"kind": "key-unrecovered", "action": aid, "binary": binary,
                            "func": ep.get("func"), "detail": "读端键为空/未恢复"})
            continue
        rec = {
            "action": aid,
            # 读点的宿主进程可能不是触发 action 所在的二进制（rc / librcm.so 最常见），
            # 端点级 `binary` 可覆盖，BDG 的 get 侧本来就是按进程记的。
            "binary": ep.get("binary") or binary,
            "func": ep.get("func") or "",
            "addr": ep.get("addr") or "",
            "mechanism": ep.get("mechanism") or _mech_of(ep.get("func") or "", ipc, "read") or "",
            "evidence": ep.get("evidence") or "",
            # 触发这次读取的**前端 action**（来自 ADG）；缺省退回宿主 action，
            # 但跨二进制读取缺它就无法区分一阶/高阶，validate 会拦下。
            "trigger_action": ep.get("trigger_action") or "",
            "via_control": ep.get("via_control") or None,
        }
        sink = ep.get("sink")
        if isinstance(sink, dict) and (sink.get("name") or sink.get("addr")):
            rec["sink"] = {
                "name": sink.get("name") or "",
                "addr": sink.get("addr") or "",
                "kind": sink.get("kind") or sink_kinds.get(sink.get("name") or "", "unknown"),
            }
            slot(k)["readers"].append(rec)
        else:
            slot(k)["reads_without_sink"].append(rec)

    # 集中性：机制阈值（Bridge 取 10）+ 相对阈值
    top_writers = max([len(v["writers"]) for v in keys.values()] or [0])
    rel = find_interval(top_writers)
    for k, v in keys.items():
        mech = (v["writers"][0]["mechanism"] if v["writers"] else
                v["readers"][0]["mechanism"] if v["readers"] else "")
        info = (ipc.get("mechanisms") or {}).get(mech) or {}
        thr = int(info.get("concentration_threshold") or 10)
        wc = len(v["writers"])
        v["writer_count"] = wc
        v["reader_count"] = len(v["readers"])
        v["mechanism"] = mech
        v["concentration"] = {
            "threshold": thr,
            "relative_threshold": rel,
            "control_candidate": bool(wc >= thr and wc > rel) if mech != "process_call" else False,
            "note": ("写端集中于单一 action，按数据键处理" if wc < thr
                     else "多 action 共写同一键，可能是控制消息（须再验『消费-控制流』约束）"),
        }

    chains: List[Dict[str, Any]] = []
    first_order: List[Dict[str, Any]] = []
    seq = 0
    for k in sorted(keys):
        for w in keys[k]["writers"]:
            for r in keys[k]["readers"]:
                seq += 1
                # 判据 C1（实测校正）：比的是**触发该次读取的前端 action**，不是读点的
                # 宿主进程。读点常在别的进程（rc / librcm.so），拿它当 "action" 永远
                # 判成高阶——Bridge 的 other_get 指「读发生在另一个二进制」，而一阶/
                # 高阶的分界是「写它的请求」与「触发读的请求」是否同一个。
                trig = r.get("trigger_action") or r["action"]
                same_request = (w["action"] == trig)
                chain = {
                    "id": ("F-%03d" if same_request else "H-%03d") % seq,
                    "order": "first" if same_request else "high",
                    "key": k,
                    "write": {kk: w[kk] for kk in ("action", "binary", "func", "addr", "evidence")},
                    "read": {kk: r.get(kk) for kk in ("binary", "func", "addr", "evidence")},
                    "sink": dict(r["sink"]),
                    "mechanism": keys[k]["mechanism"],
                    "control_message": keys[k]["concentration"]["control_candidate"],
                }
                chain["read"]["action"] = trig
                chain["read"]["host_action"] = r["action"]
                if r.get("via_control"):
                    chain["read"]["via_control"] = dict(r["via_control"])
                missing = [f"{side}.evidence" for side in ("write", "read")
                           if not chain[side].get("evidence")]
                if not chain["write"].get("addr") or not chain["read"].get("addr"):
                    missing.append("addr")
                if chain["sink"].get("kind") == "unknown":
                    missing.append("sink.kind")
                if missing:
                    chain["defects"] = missing
                (first_order if same_request else chains).append(chain)

    # 控制流边（ADG）：action --ipc--> action
    adg: List[Dict[str, Any]] = []
    for aid, binary, link in _iter_endpoints(actions, "ipc_control"):
        src = aid
        dst = link.get("target_action") or ""
        if not src or not dst:
            defects.append({"kind": "adg-edge-unnamed", "detail": "ipc_control 缺 target_action",
                            "action": src})
            continue
        adg.append({
            "from": {"action": src, "binary": binary},
            "to": {"action": dst, "binary": link.get("target_binary") or ""},
            "via": {"mechanism": link.get("mechanism") or "", "func": link.get("func") or "",
                    "value": link.get("value") or "", "addr": link.get("addr") or ""},
            "kind": link.get("kind") or "implicit",
            "evidence": link.get("evidence") or "",
        })

    summary = {
        "keys": len(keys),
        "high_order_chains": len(chains),
        "first_order_chains": len(first_order),
        "control_keys": sum(1 for v in keys.values() if v["concentration"]["control_candidate"]),
        "adg_edges": len(adg),
        "defects": len(defects),
        "unrecovered_keys": sum(1 for d in defects if d["kind"] == "key-unrecovered"),
    }

    return {
        "schema": GRAPH_SCHEMA,
        "tool": TOOL,
        "target": facts.get("target") or "",
        "store_type": store_type,
        "ipc_table": facts.get("ipc_table") or os.path.basename(DEFAULT_IPC_TABLE),
        "keys": keys,
        "chains": chains,
        "first_order": first_order,
        "adg": adg,
        "defects": defects,
        "errors": errors,
        "summary": summary,
    }


# ── 校验（gate 复用同一函数，避免两套口径）──────────────────────────────────

def validate_graph(g: Dict[str, Any]) -> Dict[str, Any]:
    """返回 {ok, violations[], warnings[]}。violations 一律硬失败。"""
    v: List[str] = []
    w: List[str] = []
    if g.get("schema") != GRAPH_SCHEMA:
        v.append(f"graph.schema 应为 {GRAPH_SCHEMA}，实际 {g.get('schema')}")
    if g.get("errors"):
        v.extend(g["errors"])

    chains = g.get("chains") or []
    firsts = g.get("first_order") or []
    if not chains and not firsts:
        w.append("图中没有任何链（可能确实无污点，也可能是没做配对）")

    for c in chains:
        cid = c.get("id") or "<no-id>"
        if c.get("order") != "high":
            v.append(f"{cid}: 出现在 chains 里但 order != high")
        wr, rd = c.get("write") or {}, c.get("read") or {}
        # 核心语义（实测校正）：高阶 = **写它的前端 action** ≠ **触发读的前端 action**。
        # 读点本身常在另一个进程（rc / librcm.so），拿读点宿主进程当 action 会把
        # 一阶误判成高阶（DIR878 的 SysLogRemote_IPAddress 就是这样：set 与 trigger
        # 都是 SetSysLogSettings，读却发生在 rc）。
        if wr.get("action") == rd.get("action"):
            v.append(f"{cid}: 写面与读面的**触发 action** 相同（{wr.get('action')}），"
                     f"这是一阶漏洞而不是高阶——不得计入 chains")
        if not c.get("key"):
            v.append(f"{cid}: 缺 key")
        if wr.get("key") and rd.get("key") and wr["key"] != rd["key"]:
            v.append(f"{cid}: 写读键不一致（{wr['key']} != {rd['key']}）")
        # C5：读点在别的进程时，必须给出「哪个控制值把请求带过去」——
        # 否则「请求 2 能到达读点」只是假设（Bridge 用 ADG 证明这一步）。
        if rd.get("binary") and wr.get("binary") and rd["binary"] != wr["binary"]:
            via = rd.get("via_control") or {}
            if not via.get("value"):
                v.append(f"{cid}: 读点在另一个进程（{rd['binary']}）却没有 via_control"
                         f"——请求如何到达该进程未证明（缺 ADG 边）")
        for side in ("write", "read"):
            if not (c.get(side) or {}).get("evidence"):
                v.append(f"{cid}: {side} 缺 evidence（跨请求链的每一端都要有落点）")
            if not (c.get(side) or {}).get("addr"):
                v.append(f"{cid}: {side} 缺 addr")
        if not (c.get("sink") or {}).get("name"):
            v.append(f"{cid}: 缺 sink.name")
        if (c.get("sink") or {}).get("kind") in (None, "", "unknown"):
            v.append(f"{cid}: sink.kind 未知（须归入 command_exec / weak_copy 等）")

    for c in firsts:
        if c.get("order") != "first":
            v.append(f"{c.get('id')}: 出现在 first_order 里但 order != first")

    for d in g.get("defects") or []:
        if d.get("kind") == "key-unrecovered":
            v.append(f"键未恢复（{d.get('action')}/{d.get('func')}）：常量恢复没做，"
                     f"配对结果不可用")
        else:
            w.append(f"defect: {d.get('kind')} — {d.get('detail')}")

    for e in g.get("adg") or []:
        if not (e.get("to") or {}).get("action"):
            w.append("ADG 边缺目标 action")

    s = g.get("summary") or {}
    if s.get("high_order_chains") != len(chains):
        v.append("summary.high_order_chains 与 chains 数量不符（手改过图？）")

    return {"ok": not v, "violations": v, "warnings": w}


def render_markdown(g: Dict[str, Any], max_rows: int = 40) -> str:
    s = g.get("summary") or {}
    lines = [f"# 跨请求污点图 · {g.get('target') or '(未命名)'}", ""]
    lines.append(f"- 存储机制：`{g.get('store_type') or '-'}`")
    lines.append(f"- 键 {s.get('keys', 0)} 个；高阶链 {s.get('high_order_chains', 0)} 条；"
                 f"一阶链 {s.get('first_order_chains', 0)} 条；控制键 {s.get('control_keys', 0)} 个；"
                 f"ADG 边 {s.get('adg_edges', 0)} 条；缺陷 {s.get('defects', 0)} 处")
    lines += ["", "## 高阶链（写请求 ≠ 触发读的请求）", "",
              "| 链 | 键 | 写面（request 1） | 触发读的请求（request 2） | 读点 → sink | via（控制值） |",
              "|---|---|---|---|---|---|"]
    for c in (g.get("chains") or [])[:max_rows]:
        wr, rd = c.get("write") or {}, c.get("read") or {}
        via = (rd.get("via_control") or {}).get("value") or "—"
        lines.append("| {id} | `{k}` | {wa} @ {wb} `{wc}` {waddr} | {ra} | {rb} `{rc}` {raddr} → "
                     "{sink} ({kind}) | {via} |".format(
                         id=c.get("id"), k=c.get("key"),
                         wa=wr.get("action"), wb=wr.get("binary"), wc=wr.get("func"), waddr=wr.get("addr"),
                         ra=rd.get("action"), rb=rd.get("binary"), rc=rd.get("func"), raddr=rd.get("addr"),
                         sink=(c.get("sink") or {}).get("name"), kind=(c.get("sink") or {}).get("kind"),
                         via=via))
    if not g.get("chains"):
        lines.append("| — | — | — | — | — | — |")

    if g.get("first_order"):
        lines += ["", "## 一阶链（写读同一 action，不计入高阶）", ""]
        for c in g["first_order"][:max_rows]:
            lines.append(f"- `{c.get('key')}` · {c.get('write', {}).get('action')} → "
                         f"{(c.get('sink') or {}).get('name')}")
    if g.get("defects"):
        lines += ["", "## 缺陷（必须先修，否则链不成立）", ""]
        for d in g["defects"][:max_rows]:
            lines.append(f"- `{d.get('kind')}`: {d.get('detail')} "
                         f"(action={d.get('action') or '-'}, func={d.get('func') or '-'})")
    if g.get("adg"):
        lines += ["", "## ADG（action → IPC 控制值 → action）", ""]
        for e in g["adg"][:max_rows]:
            via = e.get("via") or {}
            lines.append(f"- {e['from'].get('action')} --{via.get('func')}(\"{via.get('value')}\")--> "
                         f"{e['to'].get('action')} [{e.get('kind')}]")
    return "\n".join(lines) + "\n"


# ── OD-ICP 轻量版：从反编译伪代码恢复常量键 ──────────────────────────────────
# 只做三件确定能做的事，不猜：
#   1. 参数是字符串字面量           → 直接用
#   2. 参数是局部变量，函数体内有唯一赋值 → 用该字面量
#   3. 参数是 snprintf/sprintf 拼出来的 → 若所有 %s 的实参都是常量，拼起来
# 拼不出来就记 unknown 并写 reason（Bridge 在这里用欠约束符号执行补，本脚本不假装能做到）。

_CALL_RE = re.compile(r"\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)")
_STR_LIT = r'"((?:[^"\\]|\\.)*)"'
_LOCAL_ASSIGN = r"\b{name}\s*=\s*{lit}\s*;"

# 格式化/拷贝函数的 (格式串下标, 首个实参下标)；用于把拼出来的键还原成字面量
_FMT_CALLS = {"snprintf": (2, 3), "sprintf": (1, 2), "asprintf": (1, 2),
              "vsnprintf": (2, 3), "vsprintf": (1, 2)}
# 对目标缓冲区『追加/覆盖』写入的函数：第一实参是目标缓冲区
_FILL_CALLS = {"strcpy": 1, "strncpy": 1, "strcat": 2, "strncat": 2,
               "snprintf": 1, "sprintf": 1, "memcpy": 1}


def _split_args(s: str) -> List[str]:
    out, depth, cur, in_str, i = [], 0, [], False, 0
    while i < len(s):
        ch = s[i]
        if in_str:
            cur.append(ch)
            if ch == "\\" and i + 1 < len(s):
                cur.append(s[i + 1])
                i += 2
                continue
            if ch == '"':
                in_str = False
            i += 1
            continue
        if ch == '"':
            in_str = True
            cur.append(ch)
        elif ch in "([{":
            depth += 1
            cur.append(ch)
        elif ch in ")]}":
            depth -= 1
            cur.append(ch)
        elif ch == "," and depth == 0:
            out.append("".join(cur).strip())
            cur = []
        else:
            cur.append(ch)
        i += 1
    if "".join(cur).strip():
        out.append("".join(cur).strip())
    return out


def _compose_from_call(call: str, scope: str) -> Tuple[Optional[str], str]:
    """把 snprintf/sprintf/strcpy 这类调用还原成常量串。"""
    m = re.fullmatch(r"\s*([A-Za-z_]\w*)\s*\((.*)\)\s*", call, re.S)
    if not m:
        return None, "不是函数调用"
    fn, inner_s = m.group(1), m.group(2)
    inner = _split_args(inner_s)
    if fn in _FMT_CALLS:
        fmt_i, arg_i = _FMT_CALLS[fn]
        if len(inner) <= fmt_i:
            return None, f"{fn} 参数不足"
        fmt, why = _resolve(inner[fmt_i], scope)
        if fmt is None:
            return None, f"格式串不可定值（{why}）"
        parts, idx = [], 0
        for piece in re.split(r"(%[-#0-9.]*(?:s|d|u|x|X|i))", fmt):
            if not piece:
                continue
            if piece.startswith("%"):
                if arg_i + idx >= len(inner):
                    return None, "格式串实参不足"
                val, why2 = _resolve(inner[arg_i + idx], scope)
                if val is None:
                    return None, f"格式串实参 {why2}"
                parts.append(val)
                idx += 1
            else:
                parts.append(piece)
        return "".join(parts), "format-composed"
    if fn in _FILL_CALLS:
        if len(inner) < 2:
            return None, f"{fn} 参数不足"
        return _resolve(inner[1], scope)
    return None, f"{fn} 不是常量构造函数"


def _resolve(token: str, scope: str) -> Tuple[Optional[str], str]:
    """把实参 token 解析成字符串常量。返回 (值, 依据)；解析不出返回 (None, 原因)。

    四条规则，全部是**可验证**的，不做概率猜测：
      1. 字面量                          → literal
      2. 局部变量且函数体内唯一 `x = \"…\"` → local-const
      3. 局部缓冲区被 strcpy/snprintf/strcat 按序填充 → fill-composed
      4. 直接内联的 snprintf/sprintf/strcpy → format-composed
    """
    t = token.strip()
    m = re.fullmatch(_STR_LIT, t, re.S)
    if m:
        return m.group(1), "literal"
    if re.fullmatch(r"[A-Za-z_]\w*", t):
        pat = re.compile(_LOCAL_ASSIGN.format(name=re.escape(t), lit=_STR_LIT), re.S)
        hits = pat.findall(scope)
        if len(hits) == 1:
            return hits[0], "local-const"
        if len(hits) > 1:
            return None, f"局部变量 {t} 有 {len(hits)} 处赋值（多值，需符号执行）"
        # 被填充的缓冲区：按出现顺序收集对该目标的写入
        fill_re = re.compile(r"(?<![\w.])(%s)\s*\(([^;{}]*)\)" % "|".join(_FILL_CALLS), re.S)
        pieces: List[Tuple[int, str, str, str]] = []
        for fm in fill_re.finditer(scope):
            fn, argstr = fm.group(1), fm.group(2)
            args = _split_args(argstr)
            if not args or args[0].strip() != t:
                continue
            if fn in ("strcat", "strncat") and not pieces:
                continue  # 累加前没有初值，无法定值
            pieces.append((fm.start(), fn, fm.group(0), argstr))
        if not pieces:
            return None, f"局部变量 {t} 无常量赋值，也未被常量填充"
        out: List[str] = []
        for _pos, fn, call, _a in sorted(pieces):
            val, why = _compose_from_call(call, scope)
            if val is None:
                return None, f"{t} 的填充 {fn} 不可定值（{why}）"
            out.append(val)
        return "".join(out), "fill-composed"
    if re.fullmatch(r"\(?\s*(?:const\s+)?char\s*\*?\s*\)?\s*\w+", t):
        return None, "强转指针，需人工追"
    if "(" in t:
        return _compose_from_call(t, scope)
    return None, "非常量表达式"


def recover_from_source(src_dir: str, ipc: Dict[str, Any], target: str = "") -> Dict[str, Any]:
    """扫描反编译目录（*.c/*.txt/*.dec），提取 IPC 写/读与常量键，产出 facts 骨架。"""
    write_fns, read_fns, key_arg = {}, {}, {}
    for mech, info in (ipc.get("mechanisms") or {}).items():
        for item in info.get("write") or []:
            write_fns[item["name"]] = mech
            if isinstance(item.get("key"), int):
                key_arg[(item["name"], "w")] = item["key"]
        for item in info.get("read") or []:
            read_fns[item["name"]] = mech
            if isinstance(item.get("key"), int):
                key_arg[(item["name"], "r")] = item["key"]
    sink_kinds = _sink_kinds(ipc)

    files: List[str] = []
    for root, _dirs, names in os.walk(src_dir):
        for n in sorted(names):
            if n.endswith((".c", ".txt", ".dec", ".pseudo", ".asm")) or "." not in n:
                files.append(os.path.join(root, n))

    actions: Dict[Tuple[str, str], Dict[str, Any]] = {}
    unknowns: List[Dict[str, Any]] = []
    nonkeyed = {m for m, info in (ipc.get("mechanisms") or {}).items()
                if info.get("keyed") is False}

    def fn_scopes(text: str) -> List[Tuple[int, int, str]]:
        """切出函数体：(起, 止, 函数名)。用大括号配平，容忍无返回类型的老式写法。"""
        out: List[Tuple[int, int, str]] = []
        for m in re.finditer(r"^[ \t]*[A-Za-z_][^\n;{}]*\([^;{}]*\)\s*\{", text, re.M):
            head = m.group(0)
            name_m = re.match(r"^[ \t]*([A-Za-z_]\w*)\s*\(", head)
            if not name_m:  # `int foo(...)` 形式：取 `(` 前最后一个标识符
                name_m = re.search(r"([A-Za-z_]\w*)\s*\(", head)
            name = name_m.group(1) if name_m else ""
            depth, i = 0, m.end() - 1
            while i < len(text):
                if text[i] == "{":
                    depth += 1
                elif text[i] == "}":
                    depth -= 1
                    if depth == 0:
                        break
                i += 1
            out.append((m.start(), i + 1, name))
        return out

    for path in files:
        try:
            text = open(path, encoding="utf-8", errors="replace").read()
        except OSError:
            continue
        scopes = fn_scopes(text)
        for m in _CALL_RE.finditer(text):
            fn, argstr = m.group(1), m.group(2)
            mech = write_fns.get(fn) or read_fns.get(fn)
            if mech is None:
                continue
            if mech in nonkeyed:
                continue  # process_call 等：命令串是控制值而非存储键，属 ADG
            direction = "w" if fn in write_fns else "r"
            kpos = key_arg.get((fn, direction))
            line = text[:m.start()].count("\n") + 1
            if kpos is None:
                unknowns.append({"file": os.path.basename(path), "func": fn,
                                 "pos": f"L{line}",
                                 "reason": "该原语的键位置未定义（见 assets/ipc-functions.json）"})
                continue
            args = _split_args(argstr)
            if len(args) <= kpos:
                continue
            scope, action_id = "", ""
            for start, end, name in scopes:
                if start <= m.start() < end:
                    scope, action_id = text[start:end], name
                    break
            val, why = _resolve(args[kpos], scope)
            if val is None or not _norm_key(val):
                unknowns.append({"file": os.path.basename(path), "func": fn,
                                 "pos": f"L{line}", "reason": why})
                key = ""
            else:
                key = _norm_key(val)

            # 归属 action：函数名；不在任何函数内则退化到文件名
            if not action_id:
                action_id = os.path.splitext(os.path.basename(path))[0]
            binary = os.path.basename(path)
            slot = actions.setdefault((binary, action_id),
                                      {"id": action_id, "binary": binary,
                                       "writes": [], "reads": []})
            rec = {"key": key, "func": fn, "addr": f"L{line}",
                   "evidence": f"{os.path.basename(path)}:{line} {fn}(...)"}
            if val is not None:
                rec["key_recovered_by"] = why
            rec["mechanism"] = mech
            if direction == "w":
                slot["writes"].append(rec)
            else:
                if fn in sink_kinds:
                    rec["sink"] = {"name": fn, "kind": sink_kinds[fn]}
                else:
                    # 返回值被赋给某个变量，且该变量在同一函数内流向 sink → 记为**候选** sink。
                    # 只有候选不等于证据：不参与构图，只提示审计者去哪看数据流。
                    pre = text[max(0, m.start() - 80):m.start()]
                    vm = re.search(r"([A-Za-z_]\w*)\s*=\s*[^;=]*$", pre)
                    if vm:
                        var = vm.group(1)
                        tail_start = m.end()
                        scope_tail = text[tail_start:tail_start + 4000]
                        for sm in re.finditer(r"\b([A-Za-z_]\w*)\s*\(([^;{}]*)\)", scope_tail):
                            sn = sm.group(1)
                            if sn not in sink_kinds:
                                continue
                            if re.search(r"\b%s\b" % re.escape(var), sm.group(2)):
                                rec["sink_candidates"] = [{
                                    "name": sn, "kind": sink_kinds[sn],
                                    "addr": f"L{text[:tail_start + sm.start()].count(chr(10)) + 1}",
                                    "note": f"{var} 直接作为 {sn} 实参（候选，需确认无过滤）"}]
                                break
                slot["reads"].append(rec)

    return {
        "schema": FACTS_SCHEMA,
        "target": target or os.path.basename(os.path.abspath(src_dir)),
        "store_type": "",
        "source": {"mode": "recover", "dir": src_dir, "files": len(files),
                   "note": "由 taint_graph.py recover 生成；sink 与 ipc_control 需人工/反编译逐步补齐"},
        "actions": sorted(actions.values(), key=lambda a: (a["binary"], a["id"])),
        "unrecovered": unknowns,
    }


# ── CLI ──────────────────────────────────────────────────────────────────────

def cmd_build(args) -> int:
    facts = load_json(args.facts)
    ipc = load_ipc_table(args.ipc)
    g = build_graph(facts, ipc)
    if args.out:
        dump_json(g, args.out)
    if args.md:
        d = os.path.dirname(os.path.abspath(args.md))
        if d and not os.path.isdir(d):
            os.makedirs(d, exist_ok=True)
        with open(args.md, "w", encoding="utf-8") as fh:
            fh.write(render_markdown(g))
    val = validate_graph(g)
    s = g["summary"]
    print(f"[graph] keys={s['keys']} high={s['high_order_chains']} "
          f"first={s['first_order_chains']} control_keys={s['control_keys']} "
          f"adg={s['adg_edges']} defects={s['defects']}")
    for w in val["warnings"]:
        print(f"  [warn] {w}")
    for v in val["violations"]:
        print(f"  [FAIL] {v}")
    if args.strict and not val["ok"]:
        return 1
    return 0


def cmd_recover(args) -> int:
    if not os.path.isdir(args.src):
        print(f"[error] 目录不存在: {args.src}", file=sys.stderr)
        return 2
    ipc = load_ipc_table(args.ipc)
    facts = recover_from_source(args.src, ipc, args.target)
    dump_json(facts, args.out)
    nw = sum(len(a["writes"]) for a in facts["actions"])
    nr = sum(len(a["reads"]) for a in facts["actions"])
    print(f"[recover] 扫描 {facts['source']['files']} 个文件 → {len(facts['actions'])} 个候选 action，"
          f"写 {nw} 处 / 读 {nr} 处；未恢复 {len(facts['unrecovered'])} 处")
    if facts["unrecovered"]:
        print("  未恢复样例（必须人工补，不能当 0）：")
        for u in facts["unrecovered"][:5]:
            print(f"    {u['file']}:{u['pos']} {u['func']} — {u['reason']}")
    return 0


def cmd_stats(args) -> int:
    g = load_json(args.graph)
    print(render_markdown(g))
    val = validate_graph(g)
    print(f"[validate] {'OK' if val['ok'] else 'FAIL'} "
          f"violations={len(val['violations'])} warnings={len(val['warnings'])}")
    for v in val["violations"]:
        print(f"  [FAIL] {v}")
    return 0 if val["ok"] else 1


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="跨请求（高阶）污点图：BDG/ADG 最小实现（Bridge 方法，纯标准库）")
    sub = ap.add_subparsers(dest="cmd")

    b = sub.add_parser("build", help="facts → taint-graph.json 并自检")
    b.add_argument("--facts", required=True, help="taint-facts.json（人工/半自动整理）")
    b.add_argument("--out", help="输出 taint-graph.json")
    b.add_argument("--md", help="额外输出可读 Markdown")
    b.add_argument("--ipc", help="IPC 词表，默认 assets/ipc-functions.json")
    b.add_argument("--strict", action="store_true", help="存在 violation 时返回 1")
    b.set_defaults(func=cmd_build)

    r = sub.add_parser("recover", help="从反编译伪代码恢复常量键，生成 facts 骨架")
    r.add_argument("--src", required=True, help="反编译输出目录")
    r.add_argument("--out", required=True, help="输出 taint-facts.json")
    r.add_argument("--target", default="", help="目标名")
    r.add_argument("--ipc", help="IPC 词表")
    r.set_defaults(func=cmd_recover)

    s = sub.add_parser("stats", help="打印图与校验结果")
    s.add_argument("--graph", required=True)
    s.set_defaults(func=cmd_stats)

    args = ap.parse_args(argv)
    if not getattr(args, "func", None):
        ap.print_help()
        return 2
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
