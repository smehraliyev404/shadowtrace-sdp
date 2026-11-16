"""Does a neighbouring cluster change our latency? (parallel-runs test)

    ./venv/bin/python experiments/parallel_runs/compare_latency.py par_a1 par_a2 par_b1
                                                 ^base  ^noise ^test

All runs use the SAME seed, so their normal traffic is the same plan. For every
run we collect, per call edge (caller service -> callee service + operation),
the durations of the callee's spans in NORMAL traces only (origin label
"normal"), leaving out the run's own attack bursts plus 30 s after each, so
only the neighbour can make a difference.

Each later run is compared with the first (the base):
  * median ratio and p95 ratio per edge (1.00 = same)
  * KS distance per edge (0 = same distribution, 1 = disjoint)
Then a summary per run: the median over edges of |log2 median ratio|,
|log2 p95 ratio| and KS. The second run (alone again) is the NOISE level:
how much two identical setups differ anyway. The test run (next to a loaded
second cluster) shows interference only if it is clearly above that noise.

Verdict rule (printed, not hidden): the test run is "no worse than noise" if each
of its three summary numbers is <= 1.5 x the noise run's number + a small floor
(0.05 for log2 ratios ~ 3.5 %, 0.03 for KS). Read the per-edge table too:
one or two slow edges matter if they are edges the model relies on.

Writes data/runs/<test run>/latency_compare.json.
"""

import argparse
import collections
import glob
import json
import math
import os
import sys

import numpy as np

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
MIN_SAMPLES = 50          # edges with fewer samples in any run are skipped
BURST_MARGIN_S = 30       # after an own burst, the system needs time to settle
FLOOR_LOG2, FLOOR_KS, FACTOR = 0.05, 0.03, 1.5


def norm(tid):
    return (tid or "").lower().lstrip("0")


def load_run(run_id, runs_dir, raw_dir):
    origin = {}
    for line in open(os.path.join(runs_dir, run_id, "origin.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        origin[norm(r["trace_id"])] = r
    bursts = []
    bpath = os.path.join(runs_dir, f"{run_id}.json")
    if os.path.exists(bpath):
        for b in json.load(open(bpath, encoding="utf-8")).get("attack_bursts", []):
            bursts.append((b["start_ts"], b["end_ts"] + BURST_MARGIN_S))

    edges = collections.defaultdict(list)       # edge -> [duration_ms]
    used = skipped_burst = 0
    for f in glob.glob(os.path.join(raw_dir, run_id, "trace_*.json")):
        t = json.load(open(f, encoding="utf-8"))
        rec = origin.get(norm(t["traceID"]))
        if not rec or rec["origin"] != "normal":
            continue
        if any(s <= rec["ts"] <= e for s, e in bursts):
            skipped_burst += 1
            continue
        used += 1
        procs = t.get("processes") or {}
        spans = {s["spanID"]: s for s in t.get("spans", [])}
        for s in spans.values():
            parents = [r["spanID"] for r in s.get("references") or [] if r.get("refType") == "CHILD_OF"]
            if not parents or parents[0] not in spans:
                continue
            p = spans[parents[0]]
            ps = (procs.get(p.get("processID")) or {}).get("serviceName", "?")
            cs = (procs.get(s.get("processID")) or {}).get("serviceName", "?")
            if ps == cs:                 # in-process span, not a call between services
                continue
            edges[f"{ps} -> {cs} {s.get('operationName', '?').lstrip('/')}"].append(
                s.get("duration", 0) / 1000.0)
    return {k: np.sort(np.array(v)) for k, v in edges.items()}, used, skipped_burst


def ks(a, b):
    """Two-sample Kolmogorov-Smirnov distance of sorted arrays."""
    grid = np.concatenate([a, b])
    return float(np.max(np.abs(np.searchsorted(a, grid, side="right") / len(a)
                               - np.searchsorted(b, grid, side="right") / len(b))))


def compare(base, other):
    rows = []
    for e in sorted(set(base) & set(other)):
        a, b = base[e], other[e]
        if len(a) < MIN_SAMPLES or len(b) < MIN_SAMPLES:
            continue
        ma, mb = float(np.median(a)), float(np.median(b))
        pa, pb = float(np.percentile(a, 95)), float(np.percentile(b, 95))
        rows.append({"edge": e, "n_base": len(a), "n": len(b),
                     "median_ms_base": round(ma, 3), "median_ms": round(mb, 3),
                     "median_ratio": round(mb / ma, 3) if ma > 0 else None,
                     "p95_ms_base": round(pa, 3), "p95_ms": round(pb, 3),
                     "p95_ratio": round(pb / pa, 3) if pa > 0 else None,
                     "ks": round(ks(a, b), 3)})
    return rows


def summary(rows):
    def med(xs):
        xs = [x for x in xs if x is not None]
        return round(float(np.median(xs)), 4) if xs else None
    return {"edges": len(rows),
            "abs_log2_median_ratio": med([abs(math.log2(r["median_ratio"])) for r in rows if r["median_ratio"]]),
            "abs_log2_p95_ratio": med([abs(math.log2(r["p95_ratio"])) for r in rows if r["p95_ratio"]]),
            "ks": med([r["ks"] for r in rows])}


def main():
    p = argparse.ArgumentParser(description="normal-traffic latency: base vs other runs")
    p.add_argument("runs", nargs="+", help="base run first, then the others (e.g. noise run, test run)")
    p.add_argument("--runs-dir", default=os.path.join(PROJECT_ROOT, "data", "runs"))
    p.add_argument("--raw-dir", default=os.path.join(PROJECT_ROOT, "data", "raw_traces"))
    a = p.parse_args()
    if len(a.runs) < 2:
        p.error("give at least two runs: base first")

    data = {}
    for r in a.runs:
        edges, used, skipped = load_run(r, a.runs_dir, a.raw_dir)
        data[r] = edges
        print(f"[latency] {r}: {used} normal traces used ({skipped} skipped near own bursts), "
              f"{len(edges)} edges")

    base = a.runs[0]
    report = {"base": base, "runs": {}}
    for r in a.runs[1:]:
        rows = compare(data[base], data[r])
        report["runs"][r] = {"summary": summary(rows), "edges": rows}

    print(f"\n  summary vs {base} (median over edges; 0 = identical)")
    print(f"  {'run':14s} {'edges':>5s} {'|log2 med|':>11s} {'|log2 p95|':>11s} {'KS':>6s}")
    for r, v in report["runs"].items():
        s = v["summary"]
        print(f"  {r:14s} {s['edges']:5d} {s['abs_log2_median_ratio']!s:>11s} "
              f"{s['abs_log2_p95_ratio']!s:>11s} {s['ks']!s:>6s}")

    if len(a.runs) >= 3:
        noise, test = report["runs"][a.runs[1]]["summary"], report["runs"][a.runs[-1]]["summary"]
        checks = {
            "median": test["abs_log2_median_ratio"] <= FACTOR * noise["abs_log2_median_ratio"] + FLOOR_LOG2,
            "p95": test["abs_log2_p95_ratio"] <= FACTOR * noise["abs_log2_p95_ratio"] + FLOOR_LOG2,
            "ks": test["ks"] <= FACTOR * noise["ks"] + FLOOR_KS,
        }
        ok = all(checks.values())
        report["verdict"] = {"noise_run": a.runs[1], "test_run": a.runs[-1],
                             "checks": checks, "no_worse_than_noise": ok}
        print(f"\n  VERDICT ({a.runs[-1]} vs noise {a.runs[1]}): "
              f"{'no worse than run-to-run noise' if ok else 'INTERFERENCE above noise'}  {checks}")

    last = a.runs[-1]
    worst = sorted(report["runs"][last]["edges"], key=lambda r: -r["ks"])[:12]
    print(f"\n  most changed edges in {last} (by KS):")
    print(f"  {'KS':>5s} {'med x':>6s} {'p95 x':>6s} {'med ms':>13s}  edge")
    for r in worst:
        print(f"  {r['ks']:5.2f} {r['median_ratio']!s:>6s} {r['p95_ratio']!s:>6s} "
              f"{r['median_ms_base']:6.2f}->{r['median_ms']:<6.2f}  {r['edge']}")

    out = os.path.join(a.runs_dir, last, "latency_compare.json")
    json.dump(report, open(out, "w"), indent=2)
    print(f"\n  report -> {out}")


if __name__ == "__main__":
    main()
