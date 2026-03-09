#!/usr/bin/env python3
"""Aggregate pyabduce CT report JSON files into CSV + plots.

Usage:
  python3 tools/pyabduce/scripts/ct_report_aggregate.py \
      --root /path/to/tools-paper \
      --out /path/to/output_dir
"""

from __future__ import annotations

import argparse
import csv
import json
import os
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _nested_get(data: Dict[str, Any], keys: Iterable[str], default: Any = None) -> Any:
    cur: Any = data
    for key in keys:
        if not isinstance(cur, dict) or key not in cur:
            return default
        cur = cur[key]
    return cur


def _status_norm(raw: Optional[str]) -> str:
    if raw is None:
        return "UNKNOWN"
    sval = str(raw).strip().upper()
    if sval in {"SECURE", "INSECURE", "UNKNOWN"}:
        return sval
    if sval == "TRUE":
        return "SECURE"
    if sval == "FALSE":
        return "INSECURE"
    return sval or "UNKNOWN"


def _selected_status(report: Dict[str, Any]) -> str:
    ct_val = report.get("ct_validation") or {}
    val = _nested_get(ct_val, ("selected", "status_norm"))
    if val is None:
        val = _nested_get(ct_val, ("selected", "status"))
    if val is not None:
        return _status_norm(val)
    dnf_val = report.get("ct_dnf_validation") or {}
    val = dnf_val.get("status_norm", dnf_val.get("status"))
    if val is not None:
        return _status_norm(val)
    return "UNKNOWN"


def _baseline_status(report: Dict[str, Any]) -> str:
    val = report.get("baseline_status")
    if val is not None:
        return _status_norm(val)
    ct_val = report.get("ct_validation") or {}
    val = _nested_get(ct_val, ("baseline", "status_norm"))
    if val is None:
        val = _nested_get(ct_val, ("baseline", "status"))
    return _status_norm(val)


def _policy_kind(policy_expr: Optional[str]) -> str:
    if policy_expr is None:
        return "NONE"
    txt = str(policy_expr).strip()
    if not txt:
        return "NONE"
    lower = txt.lower()
    if lower in {"{true}", "true", "(0x1 = 0x1)"}:
        return "TRUE"
    if lower in {"(0x0 = 0x1)", "false"}:
        return "UNSAT"
    if "|" in txt:
        return "DNF"
    return "CLAUSE"


def _first_q_explain(report: Dict[str, Any]) -> str:
    qexp = report.get("q_explain")
    if isinstance(qexp, list) and len(qexp) > 0:
        return str(qexp[0])
    return ""


def _estimate_runtime(stats: Dict[str, Any]) -> float:
    timers = stats.get("timers") if isinstance(stats, dict) else None
    if not isinstance(timers, dict):
        return 0.0
    values = []
    for section in timers.values():
        if not isinstance(section, dict):
            continue
        last = section.get("last")
        if isinstance(last, (int, float)):
            values.append(float(last))
    return max(values) if values else 0.0


def _collect_rows(root: Path, include_collect: bool) -> List[Dict[str, Any]]:
    rows: List[Dict[str, Any]] = []
    for path in sorted(root.rglob("*.report.json")):
        if not include_collect and path.name.endswith(".collect.report.json"):
            continue
        try:
            report = json.loads(path.read_text(encoding="utf-8"))
        except Exception:
            continue

        relpath = str(path.relative_to(root))
        stem = path.name.replace(".report.json", "")
        suite = str(path.parent.relative_to(root))
        policy = report.get("selected_policy")
        if policy is None:
            policy = report.get("ct_dnf_policy")
        stats = report.get("stats", {}) if isinstance(report.get("stats"), dict) else {}
        gen = stats.get("generation", {}) if isinstance(stats.get("generation"), dict) else {}
        oracles = stats.get("oracles", {}) if isinstance(stats.get("oracles"), dict) else {}
        binsec = oracles.get("binsec", {}) if isinstance(oracles.get("binsec"), dict) else {}
        minibinsec = oracles.get("minibinsec", {}) if isinstance(oracles.get("minibinsec"), dict) else {}
        pruned = gen.get("pruned", {}) if isinstance(gen.get("pruned"), dict) else {}
        leak_kind_counts = report.get("leak_kind_counts", {}) if isinstance(report.get("leak_kind_counts"), dict) else {}
        leak_cf = int(leak_kind_counts.get("control_flow", 0) or 0)
        leak_ma = int(leak_kind_counts.get("memory_access", 0) or 0)
        leak_other = int(leak_kind_counts.get("other", 0) or 0)
        selected_policy_raw = report.get("selected_policy_raw")
        fallback_reason = report.get("selected_policy_fallback_reason")

        row = {
            "report_path": relpath,
            "suite": suite,
            "benchmark": stem,
            "baseline_status": _baseline_status(report),
            "selected_status": _selected_status(report),
            "selected_policy": policy if policy is not None else "",
            "selected_policy_raw": selected_policy_raw if selected_policy_raw is not None else "",
            "selected_policy_fallback_reason": fallback_reason if fallback_reason is not None else "",
            "policy_kind": _policy_kind(policy),
            "ct_stop_reason": str(report.get("ct_stop_reason", "")),
            "q_explain_count": len(report.get("q_explain", [])) if isinstance(report.get("q_explain"), list) else 0,
            "q_explain_head": _first_q_explain(report),
            "leak_cf": leak_cf,
            "leak_ma": leak_ma,
            "leak_other": leak_other,
            "secure_clauses_count": len(report.get("ct_secure_clauses", [])) if isinstance(report.get("ct_secure_clauses"), list) else 0,
            "insecure_evidence_count": len(report.get("ct_insecure_evidence", [])) if isinstance(report.get("ct_insecure_evidence"), list) else 0,
            "counterexamples_count": len(report.get("ct_counterexamples", [])) if isinstance(report.get("ct_counterexamples"), list) else 0,
            "binsec_calls": int(binsec.get("calls", 0) or 0),
            "binsec_timeouts": int(binsec.get("timeouts", 0) or 0),
            "binsec_crashes": int(binsec.get("crashes", 0) or 0),
            "binsec_time_total": float(sum(binsec.get("times", []) or [])),
            "minibinsec_calls": int(minibinsec.get("calls", 0) or 0),
            "evaluated_candidates": int(gen.get("evaluated", 0) or 0),
            "considered_candidates": int(gen.get("considered", 0) or 0),
            "pruned_total": int(gen.get("pruned", 0) or 0) if not isinstance(gen.get("pruned"), dict) else int(sum(v for v in pruned.values() if isinstance(v, int))),
            "pruned_consistency": int(pruned.get("consistency", pruned.get("consistency-pruned candidates", 0)) or 0),
            "pruned_ct_counterexample": int(pruned.get("ct_counterexample", pruned.get("ct_counterexample-pruned candidates", 0)) or 0),
            "pruned_necessary": int(pruned.get("necessary", pruned.get("necessary-pruned candidates", 0)) or 0),
            "estimated_runtime_s": _estimate_runtime(stats),
        }
        rows.append(row)
    return rows


def _write_csv(rows: List[Dict[str, Any]], out_csv: Path) -> None:
    out_csv.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        out_csv.write_text("", encoding="utf-8")
        return
    columns = [
        "report_path",
        "suite",
        "benchmark",
        "baseline_status",
        "selected_status",
        "policy_kind",
        "selected_policy_fallback_reason",
        "ct_stop_reason",
        "q_explain_count",
        "leak_cf",
        "leak_ma",
        "leak_other",
        "secure_clauses_count",
        "insecure_evidence_count",
        "counterexamples_count",
        "binsec_calls",
        "binsec_timeouts",
        "binsec_crashes",
        "binsec_time_total",
        "minibinsec_calls",
        "evaluated_candidates",
        "considered_candidates",
        "pruned_total",
        "pruned_consistency",
        "pruned_ct_counterexample",
        "pruned_necessary",
        "estimated_runtime_s",
        "q_explain_head",
        "selected_policy",
        "selected_policy_raw",
    ]
    with out_csv.open("w", newline="", encoding="utf-8") as fobj:
        writer = csv.DictWriter(fobj, fieldnames=columns)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k, "") for k in columns})


def _write_markdown(rows: List[Dict[str, Any]], out_md: Path) -> None:
    out_md.parent.mkdir(parents=True, exist_ok=True)
    total = len(rows)
    secure_sel = sum(1 for r in rows if r["selected_status"] == "SECURE")
    insecure_sel = sum(1 for r in rows if r["selected_status"] == "INSECURE")
    unknown_sel = sum(1 for r in rows if r["selected_status"] == "UNKNOWN")
    avg_binsec = (sum(r["binsec_calls"] for r in rows) / total) if total else 0.0
    lines = [
        "# CT Report Summary",
        "",
        f"- reports: {total}",
        f"- selected SECURE: {secure_sel}",
        f"- selected INSECURE: {insecure_sel}",
        f"- selected UNKNOWN: {unknown_sel}",
        f"- avg binsec calls: {avg_binsec:.2f}",
        "",
        "## Top 15 by BINSEC Calls",
        "",
        "| benchmark | suite | baseline | selected | binsec_calls | stop_reason | policy_kind |",
        "|---|---|---|---|---:|---|---|",
    ]
    top = sorted(rows, key=lambda r: r["binsec_calls"], reverse=True)[:15]
    for r in top:
        lines.append(
            f"| {r['benchmark']} | {r['suite']} | {r['baseline_status']} | {r['selected_status']} | {r['binsec_calls']} | {r['ct_stop_reason'] or '-'} | {r['policy_kind']} |"
        )
    lines.append("")
    out_md.write_text("\n".join(lines), encoding="utf-8")


def _plot_rows(rows: List[Dict[str, Any]], out_dir: Path) -> List[Path]:
    created: List[Path] = []
    try:
        import matplotlib

        matplotlib.use("Agg")
        import matplotlib.pyplot as plt
    except Exception:
        return created

    out_dir.mkdir(parents=True, exist_ok=True)
    if not rows:
        return created

    # 1) BINSEC calls per benchmark (top 20)
    top = sorted(rows, key=lambda r: r["binsec_calls"], reverse=True)[:20]
    fig = plt.figure(figsize=(14, 6))
    labels = [r["benchmark"] for r in top]
    vals = [r["binsec_calls"] for r in top]
    plt.bar(range(len(vals)), vals)
    plt.xticks(range(len(vals)), labels, rotation=70, ha="right")
    plt.ylabel("binsec calls")
    plt.title("Top Benchmarks by BINSEC Calls")
    plt.tight_layout()
    p1 = out_dir / "binsec_calls_top20.png"
    fig.savefig(p1, dpi=150)
    plt.close(fig)
    created.append(p1)

    # 2) Candidate generation cost (evaluated vs pruned)
    top2 = sorted(rows, key=lambda r: r["evaluated_candidates"], reverse=True)[:20]
    fig = plt.figure(figsize=(14, 6))
    labels = [r["benchmark"] for r in top2]
    evals = [r["evaluated_candidates"] for r in top2]
    pruned = [r["pruned_total"] for r in top2]
    x = list(range(len(top2)))
    plt.bar([i - 0.2 for i in x], evals, width=0.4, label="evaluated")
    plt.bar([i + 0.2 for i in x], pruned, width=0.4, label="pruned")
    plt.xticks(x, labels, rotation=70, ha="right")
    plt.ylabel("count")
    plt.title("Candidate Cost (Top by Evaluated)")
    plt.legend()
    plt.tight_layout()
    p2 = out_dir / "candidate_cost_top20.png"
    fig.savefig(p2, dpi=150)
    plt.close(fig)
    created.append(p2)

    # 3) Outcome distribution by selected_status
    counts = {"SECURE": 0, "INSECURE": 0, "UNKNOWN": 0}
    for r in rows:
        counts[r["selected_status"]] = counts.get(r["selected_status"], 0) + 1
    fig = plt.figure(figsize=(6, 6))
    labels = list(counts.keys())
    vals = [counts[k] for k in labels]
    plt.pie(vals, labels=labels, autopct="%1.1f%%")
    plt.title("Selected Policy Validation Status")
    plt.tight_layout()
    p3 = out_dir / "selected_status_pie.png"
    fig.savefig(p3, dpi=150)
    plt.close(fig)
    created.append(p3)

    return created


def main() -> int:
    parser = argparse.ArgumentParser(description="Aggregate CT pyabduce report JSON files.")
    parser.add_argument(
        "--root",
        default=".",
        help="Project root to scan for *.report.json (default: current directory).",
    )
    parser.add_argument(
        "--out",
        default="ct-results",
        help="Output directory for summary files.",
    )
    parser.add_argument(
        "--include-collect",
        action="store_true",
        help="Also include *.collect.report.json files.",
    )
    args = parser.parse_args()

    root = Path(args.root).resolve()
    out_dir = Path(args.out).resolve()
    rows = _collect_rows(root, include_collect=args.include_collect)

    csv_path = out_dir / "summary.csv"
    md_path = out_dir / "summary.md"
    _write_csv(rows, csv_path)
    _write_markdown(rows, md_path)
    created_plots = _plot_rows(rows, out_dir)

    print(f"[ok] reports found: {len(rows)}")
    print(f"[ok] csv: {csv_path}")
    print(f"[ok] markdown: {md_path}")
    if created_plots:
        for p in created_plots:
            print(f"[ok] plot: {p}")
    else:
        print("[warn] plots not generated (matplotlib not available).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
