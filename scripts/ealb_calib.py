#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""EALB 预算校准（ISSUE-07）。

现状与目标
----------
EALB = Σ tier_weight × text_units，只回答「相对工作量」。它被当成排期依据，
却从未用实际数据校准过：不同架构、不同固件规模、不同阶段的真实成本可能
相差数倍。本脚本把「预测」与「实测」分开记录，并显式标注模型状态：

* status = heuristic     样本不足 / 全部为合成数据 —— 只能当相对排序用；
* status = experimental  样本量达到下限但仍有较大误差；
* status = calibrated    样本量、误差、场景覆盖都达标（需要真实数据）。

预测目标（二选一，记录里用实际字段决定）
* 人工复核工时 minutes；
* token/上下文成本 tokens。
指标：MAE、MAPE（剔除实际值为 0 的样本，并在报告里说明剔除了多少）、
RMSE；按 arch / 规模档 / 阶段分组给出，避免「总体 MAE 好看、小固件全错」。

用法
----
    python scripts/ealb_calib.py predict --ealb 1200
    python scripts/ealb_calib.py evaluate --records measures.jsonl
    python scripts/ealb_calib.py fit --records measures.jsonl --out assets/ealb-calibration.json
    python scripts/ealb_calib.py check --records measures.jsonl   # 偏差过大 -> 退出码 3

退出码：0 正常；1 输入错误；3 偏差超阈值（需要保守降级或重新校准）。
纯标准库，Python 3.10+。
"""
from __future__ import annotations

import argparse
import json
import math
import os
import sys
from typing import Any, Dict, List, Optional, Tuple

VERSION = "1.0"
SCHEMA = "ealb-calibration/1.0"
MEASURE_SCHEMA = "ealb-measure/1.0"
DEFAULT_CAL = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                           "assets", "ealb-calibration.json")
MIN_SAMPLES_EXPERIMENTAL = 20
MIN_SAMPLES_CALIBRATED = 60
MAX_MAPE_CALIBRATED = 0.30


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def load_records(path: str) -> List[Dict[str, Any]]:
    """读取实测记录：支持 JSON 数组文件或 JSONL。"""
    if not os.path.isfile(path):
        raise SystemExit(f"[error] 记录文件不存在：{path}")
    with open(path, "r", encoding="utf-8") as fh:
        raw = fh.read().strip()
    if not raw:
        return []
    if raw.startswith("["):
        rows = json.loads(raw)
    elif raw.startswith("{"):
        doc = json.loads(raw)
        rows = doc.get("records") if isinstance(doc, dict) else None
        if rows is None:
            rows = [doc]
    else:
        rows = [json.loads(line) for line in raw.splitlines()
                if line.strip() and not line.strip().startswith("#")]
    out = []
    for i, r in enumerate(rows):
        if not isinstance(r, dict):
            raise SystemExit(f"[error] 第 {i + 1} 条记录不是对象")
        if not isinstance(r.get("ealb"), (int, float)):
            raise SystemExit(f"[error] 第 {i + 1} 条记录缺少数值型 ealb")
        if not isinstance(r.get("actual_minutes"), (int, float)) and \
                not isinstance(r.get("actual_tokens"), (int, float)):
            raise SystemExit(f"[error] 第 {i + 1} 条记录缺少 actual_minutes 或 actual_tokens")
        out.append(r)
    return out


def load_calibration(path: str) -> Dict[str, Any]:
    if not os.path.isfile(path):
        raise SystemExit(f"[error] 校准文件不存在：{path}")
    doc = _load_json(path)
    if not isinstance(doc, dict) or doc.get("schema") != SCHEMA:
        raise SystemExit(f"[error] 校准文件 schema 必须是 {SCHEMA}")
    return doc


def predict_minutes(ealb: float, cal: Dict[str, Any]) -> float:
    model = cal.get("model") or {}
    k = float(model.get("minutes_per_ealb", 0.18))
    b = float(model.get("intercept_minutes", 5.0))
    return k * max(0.0, ealb) + b


def predict_tokens(ealb: float, cal: Dict[str, Any]) -> float:
    model = cal.get("model") or {}
    k = float(model.get("tokens_per_ealb", 260.0))
    return k * max(0.0, ealb)


def _target(record: Dict[str, Any]) -> Tuple[str, float]:
    if isinstance(record.get("actual_minutes"), (int, float)):
        return "minutes", float(record["actual_minutes"])
    return "tokens", float(record["actual_tokens"])


def _band(ealb: float) -> str:
    if ealb < 200:
        return "small(<200)"
    if ealb < 800:
        return "medium(200-800)"
    if ealb < 3000:
        return "large(800-3000)"
    return "xlarge(>=3000)"


def _metrics(pairs: List[Tuple[float, float]]) -> Dict[str, Any]:
    """pairs = [(predicted, actual)]；MAPE 剔除实际值为 0 的样本并记录数量。"""
    n = len(pairs)
    if not n:
        return {"n": 0, "mae": None, "mape": None, "rmse": None, "zero_actual": 0}
    errs = [p - a for p, a in pairs]
    mae = sum(abs(e) for e in errs) / n
    rmse = math.sqrt(sum(e * e for e in errs) / n)
    nonzero = [(p, a) for p, a in pairs if a != 0]
    mape = (sum(abs(p - a) / abs(a) for p, a in nonzero) / len(nonzero)) if nonzero else None
    return {"n": n, "mae": round(mae, 4),
            "mape": (round(mape, 4) if mape is not None else None),
            "rmse": round(rmse, 4), "zero_actual": n - len(nonzero)}


def evaluate(records: List[Dict[str, Any]], cal: Dict[str, Any]) -> Dict[str, Any]:
    by_target: Dict[str, List[Tuple[float, float]]] = {"minutes": [], "tokens": []}
    groups: Dict[str, Dict[str, List[Tuple[float, float]]]] = {
        "arch": {}, "size": {}, "stage": {}}
    for r in records:
        kind, actual = _target(r)
        pred = predict_minutes(r["ealb"], cal) if kind == "minutes" else \
            predict_tokens(r["ealb"], cal)
        by_target[kind].append((pred, actual))
        groups["arch"].setdefault(str(r.get("arch") or "unknown"), []).append((pred, actual))
        groups["size"].setdefault(_band(float(r["ealb"])), []).append((pred, actual))
        groups["stage"].setdefault(str(r.get("stage") or "unknown"), []).append((pred, actual))
    return {
        "schema": "ealb-eval/1.0",
        "targets": {k: _metrics(v) for k, v in by_target.items() if v},
        "groups": {g: {name: _metrics(v) for name, v in sorted(items.items())}
                   for g, items in groups.items() if items},
        "records": len(records),
        "synthetic_share": (round(sum(1 for r in records
                                      if str(r.get("source", "")).startswith("synthetic"))
                                  / len(records), 3) if records else None),
    }


def fit(records: List[Dict[str, Any]], cal: Dict[str, Any]) -> Dict[str, Any]:
    """最小二乘拟合 minutes = k * EALB + b（强制过原点用 --through-origin）。"""
    pts = [(float(r["ealb"]), float(r["actual_minutes"]))
           for r in records if isinstance(r.get("actual_minutes"), (int, float))]
    if len(pts) < 2:
        return {"fitted": False, "reason": "minutes 样本不足（<2）"}
    n = len(pts)
    sx = sum(x for x, _ in pts)
    sy = sum(y for _, y in pts)
    sxx = sum(x * x for x, _ in pts)
    sxy = sum(x * y for x, y in pts)
    denom = n * sxx - sx * sx
    if abs(denom) < 1e-9:
        return {"fitted": False, "reason": "EALB 无方差，无法拟合"}
    k = (n * sxy - sx * sy) / denom
    b = (sy - k * sx) / n
    if k <= 0:
        return {"fitted": False, "reason": f"拟合斜率为负或零（k={k:.4f}），数据可疑"}
    return {"fitted": True, "minutes_per_ealb": round(k, 6),
            "intercept_minutes": round(b, 4), "n": n}


def status_for(records: List[Dict[str, Any]], met: Dict[str, Any]) -> str:
    real = [r for r in records if not str(r.get("source", "")).startswith("synthetic")]
    if len(real) < MIN_SAMPLES_EXPERIMENTAL:
        return "heuristic"
    mape = ((met.get("targets") or {}).get("minutes") or {}).get("mape")
    if len(real) < MIN_SAMPLES_CALIBRATED or mape is None or mape > MAX_MAPE_CALIBRATED:
        return "experimental"
    return "calibrated"


def cmd_predict(args: argparse.Namespace) -> int:
    cal = load_calibration(args.calibration)
    out = {
        "schema": "ealb-prediction/1.0",
        "ealb": args.ealb,
        "status": cal.get("status"),
        "minutes": round(predict_minutes(args.ealb, cal), 2),
        "tokens": round(predict_tokens(args.ealb, cal), 1),
        "caveat": cal.get("caveat"),
    }
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(out, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    print(f"EALB {args.ealb} -> {out['minutes']} 分钟 / {out['tokens']} tokens"
          f"（模型状态：{out['status']}）")
    if out["status"] != "calibrated":
        print(f"[warn] {out['caveat'] or '样本不足，数字仅供相对排序，不得当作承诺工期'}")
    return 0


def cmd_evaluate(args: argparse.Namespace) -> int:
    cal = load_calibration(args.calibration)
    records = load_records(args.records)
    met = evaluate(records, cal)
    met["status"] = status_for(records, met)
    met["calibration_status"] = cal.get("status")
    if args.json:
        with open(args.json, "w", encoding="utf-8", newline="\n") as fh:
            json.dump(met, fh, ensure_ascii=False, indent=2)
            fh.write("\n")
    print(f"样本 {met['records']} 条；状态 {met['status']}；"
          f"合成占比 {met['synthetic_share']}")
    for kind, m in (met["targets"] or {}).items():
        print(f"  {kind}: MAE={m['mae']} MAPE={m['mape']} "
              f"RMSE={m['rmse']}（零值剔除 {m['zero_actual']}）")
    worst = None
    for g, items in (met["groups"] or {}).items():
        for name, m in items.items():
            if m.get("mape") is not None and (worst is None or m["mape"] > worst[2]):
                worst = (g, name, m["mape"])
    if worst:
        print(f"  最差分组：{worst[0]}/{worst[1]} MAPE={worst[2]}")
    limit = args.max_mape
    over = [m for m in (met["targets"] or {}).values()
            if m.get("mape") is not None and m["mape"] > limit]
    if over:
        print(f"[warn] MAPE 超过阈值 {limit}：预算偏差过大，应保守降级（增加 agent 数/缩小分片）")
        return 3 if args.strict else 0
    return 0


def cmd_fit(args: argparse.Namespace) -> int:
    cal = load_calibration(args.calibration)
    records = load_records(args.records)
    res = fit(records, cal)
    met = evaluate(records, cal)
    new = json.loads(json.dumps(cal))
    new["updated"] = args.updated
    new["samples"] = {"total": len(records),
                      "real": sum(1 for r in records
                                  if not str(r.get("source", "")).startswith("synthetic"))}
    new["metrics"] = {"minutes": (met.get("targets") or {}).get("minutes")}
    new["status"] = status_for(records, met)
    if res.get("fitted"):
        new.setdefault("model", {})
        new["model"]["minutes_per_ealb"] = res["minutes_per_ealb"]
        new["model"]["intercept_minutes"] = res["intercept_minutes"]
    new["caveat"] = ("未达校准门槛：数字仅供相对排序" if new["status"] != "calibrated"
                     else "已用真实样本校准，仍按季度复核")
    out = args.out or args.calibration
    with open(out, "w", encoding="utf-8", newline="\n") as fh:
        json.dump(new, fh, ensure_ascii=False, indent=2)
        fh.write("\n")
    print(f"[ok] 校准结果 -> {out}（status={new['status']}，"
          f"拟合={'成功' if res.get('fitted') else res.get('reason')}）")
    if new["status"] != "calibrated":
        print("[warn] 仍不是 calibrated：文档不得把它写成已验证预测")
    return 0


def cmd_check(args: argparse.Namespace) -> int:
    return cmd_evaluate(args)


def main(argv: Optional[List[str]] = None) -> int:
    ap = argparse.ArgumentParser(
        description="EALB 预算校准：预测、误差评估、拟合与偏差告警（ISSUE-07）")
    ap.add_argument("--version", action="version", version=f"ealib {VERSION}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def common(p):
        p.add_argument("--calibration", default=DEFAULT_CAL,
                       help="校准文件（默认 assets/ealb-calibration.json）")
        p.add_argument("--json", help="输出 JSON 的路径")

    p1 = sub.add_parser("predict", help="用当前模型预测单点 EALB 的成本")
    common(p1)
    p1.add_argument("--ealb", type=float, required=True)

    p2 = sub.add_parser("evaluate", help="用实测记录评估误差（MAE/MAPE/RMSE）")
    common(p2)
    p2.add_argument("--records", required=True)
    p2.add_argument("--max-mape", type=float, default=0.35)
    p2.add_argument("--strict", action="store_true", help="MAPE 超阈值时退出码 3")

    p3 = sub.add_parser("check", help="同 evaluate，供 CI 使用")
    common(p3)
    p3.add_argument("--records", required=True)
    p3.add_argument("--max-mape", type=float, default=0.35)
    p3.add_argument("--strict", action="store_true")

    p4 = sub.add_parser("fit", help="用实测记录重新拟合模型并写回校准文件")
    common(p4)
    p4.add_argument("--records", required=True)
    p4.add_argument("--out", help="写回路径（默认覆盖 --calibration）")
    p4.add_argument("--updated", default="2026-10-22")

    args = ap.parse_args(argv)
    return {"predict": cmd_predict, "evaluate": cmd_evaluate,
            "check": cmd_check, "fit": cmd_fit}[args.cmd](args)


if __name__ == "__main__":
    raise SystemExit(main())
