"""How much do the model inputs differ between two redaction levels?

    ./venv/bin/python scripts/compare_levels.py --queue queues/batch3.txt

Loads every run's windows at L0 and at L1 exactly as the models see them
(ml.data.load_runs, so L0 includes the copied redacted-share feature) and compares
them window by window:
  * nodes: for each node feature, the share of (run, window, service) nodes whose
    value differs between the levels, the mean absolute difference, and the
    mean value at each level
  * edges: whether the caller -> callee edges and their raw statistics are identical
  * window statistics (traces, calls, errors, latency): identical or not
Writes data/features/level_diff_<a>_<b>_<queue>.json and prints a table.
"""

import argparse
import json
import os
import sys

import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from ml.data import FEATURES_DIR, NODE_FEATURES, WINDOW_FEATURES, load_runs  # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def read_queue(path):
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            yield line.split()[0]


def main():
    ap = argparse.ArgumentParser(description="compare model inputs between two redaction levels")
    ap.add_argument("--queue", default=os.path.join(PROJECT_ROOT, "queues", "batch3.txt"))
    ap.add_argument("--runs", nargs="*", help="instead of --queue")
    ap.add_argument("--a", default="L0")
    ap.add_argument("--b", default="L1")
    ap.add_argument("--features-dir", default=FEATURES_DIR)
    args = ap.parse_args()
    runs = args.runs or list(read_queue(args.queue))

    diff = {f: 0 for f in NODE_FEATURES}
    absdiff = {f: 0.0 for f in NODE_FEATURES}
    sums = {f: [0.0, 0.0] for f in NODE_FEATURES}
    nodes = windows = edge_mismatch = window_mismatch = node_set_mismatch = 0
    for run in runs:
        wa = load_runs([run], args.a, args.features_dir).set_index("window")
        wb = load_runs([run], args.b, args.features_dir).set_index("window")
        for w in wa.index.intersection(wb.index):
            ra, rb = wa.loc[w], wb.loc[w]
            windows += 1
            if any(not np.isclose(float(ra[f]), float(rb[f])) for f in WINDOW_FEATURES):
                window_mismatch += 1
            ea = sorted((e["src"], e["dst"], e["count"]) for e in ra["edges"])
            eb = sorted((e["src"], e["dst"], e["count"]) for e in rb["edges"])
            edge_mismatch += ea != eb
            na = {n["service"]: n for n in ra["nodes"]}
            nb = {n["service"]: n for n in rb["nodes"]}
            node_set_mismatch += set(na) != set(nb)
            for s in set(na) & set(nb):
                nodes += 1
                for f in NODE_FEATURES:
                    x, y = float(na[s].get(f, 0.0)), float(nb[s].get(f, 0.0))
                    sums[f][0] += x
                    sums[f][1] += y
                    if not np.isclose(x, y):
                        diff[f] += 1
                        absdiff[f] += abs(x - y)
    out = {"levels": [args.a, args.b], "runs": len(runs), "windows": windows, "nodes": nodes,
           "windows_with_different_window_stats": window_mismatch,
           "windows_with_different_edges": edge_mismatch,
           "windows_with_different_node_sets": node_set_mismatch,
           "node_features": {f: {"nodes_differing": diff[f], "share_differing": diff[f] / nodes if nodes else None,
                                 "mean_abs_diff_where_differing": absdiff[f] / diff[f] if diff[f] else 0.0,
                                 f"mean_{args.a}": sums[f][0] / nodes if nodes else None,
                                 f"mean_{args.b}": sums[f][1] / nodes if nodes else None}
                             for f in NODE_FEATURES}}
    name = os.path.splitext(os.path.basename(args.queue))[0] if not args.runs else "runs"
    path = os.path.join(args.features_dir, f"level_diff_{args.a}_{args.b}_{name}.json")
    json.dump(out, open(path, "w"), indent=1)

    print(f"[compare_levels] {args.a} vs {args.b}: {len(runs)} runs, {windows:,} windows, {nodes:,} nodes")
    print(f"  windows with different window statistics: {window_mismatch}")
    print(f"  windows with different edges:             {edge_mismatch}")
    print(f"  windows with different sets of services:  {node_set_mismatch}")
    print(f"  {'node feature':<15} {'nodes differing':>16} {'share':>8} {'mean |diff|':>12} {args.a + ' mean':>9} {args.b + ' mean':>9}")
    for f, r in out["node_features"].items():
        print(f"  {f:<15} {r['nodes_differing']:>16,} {r['share_differing']:>8.3%} {r['mean_abs_diff_where_differing']:>12.4f} "
              f"{r['mean_' + args.a]:>9.4f} {r['mean_' + args.b]:>9.4f}")
    print(f"  -> {path}")


if __name__ == "__main__":
    main()
