"""One summary over a whole batch after build_features.py and pii_audit.py.

    ./venv/bin/python scripts/batch_report.py --queue queues/batch3.txt

Adds up, over every run of the queue file that has features:
  * build: traces kept, spans, background dropped, unmatched, partial traces,
    repaired spans, windows (complete), window labels at k = 3
  * L1 audit against the ground truth (pii_audit.json): values exposed in L0 and
    still in L1 per field, overall recall, precision (strict and without IP /
    trace-context redactions), the attribute keys behind redactions of values
    that are not in the ground truth
  * the batch-3 inspection checks: login_typo requests that succeeded (status
    200), and lateral_movement traces with fewer than 2 services (a lateral call
    whose target never appeared)
Writes data/features/batch_report_<queue>.json and prints the main numbers.
"""

import argparse
import collections
import json
import os

import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
NOT_IN_TRUTH = ("ip", "trace_context")


def read_queue(path):
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            yield line.split()[0]


def norm(tid):
    return (tid or "").lower().lstrip("0")


def main():
    p = argparse.ArgumentParser(description="batch summary of features, L1 audit and checks")
    p.add_argument("--queue", default=os.path.join(PROJECT_ROOT, "queues", "batch3.txt"))
    p.add_argument("--runs", nargs="*", help="instead of --queue")
    p.add_argument("--features-dir", default=os.path.join(PROJECT_ROOT, "data", "features"))
    p.add_argument("--runs-dir", default=os.path.join(PROJECT_ROOT, "data", "runs"))
    a = p.parse_args()
    runs = a.runs or list(read_queue(a.queue))

    build = collections.Counter()
    labels, wlabels = collections.Counter(), collections.Counter()
    exposed, still, kinds, keys = (collections.Counter() for _ in range(4))
    red = tp = 0
    typo_ok = typo_all = lat_small = lat_all = 0
    missing, no_audit = [], []
    for r in runs:
        rep = os.path.join(a.features_dir, r, "build_report.json")
        if not os.path.exists(rep):
            missing.append(r)
            continue
        b = json.load(open(rep))
        build["runs"] += 1
        for k in ("traces_kept", "spans_kept", "partial_traces", "repaired_spans", "windows", "windows_complete"):
            build[k] += b.get(k) or 0
        build["background"] += (b.get("dropped") or {}).get("background", 0)
        build["unmatched"] += (b.get("dropped") or {}).get("unmatched", 0)
        labels.update(b.get("labels") or {})
        wlabels.update((b.get("window_labels") or {}).get("k3") or {})

        au = os.path.join(a.features_dir, r, "pii_audit.json")
        if os.path.exists(au):
            x = json.load(open(au))
            exposed.update(x["exposed_in_l0"])
            still.update(x["still_in_l1"])
            kinds.update(x["no_pii_by_l1_kind"])
            keys.update(x["no_pii_top_keys"])
            red += x["redactions"]
            tp += x["true_positive"]
        else:
            no_audit.append(r)

        tr = pd.read_parquet(os.path.join(a.features_dir, r, "L2", "traces.parquet"),
                             columns=["trace_id", "label", "n_services", "root_status_code"])
        lat = tr[tr["label"] == "lateral_movement"]
        lat_all += len(lat)
        lat_small += int((lat["n_services"] < 2).sum())
        origin = os.path.join(a.runs_dir, r, "origin.jsonl")
        if os.path.exists(origin):
            typo = set()
            with open(origin, encoding="utf-8") as f:
                for line in f:
                    if '"login_typo"' in line:
                        typo.add(norm(json.loads(line)["trace_id"]))
            t = tr[tr["trace_id"].isin(typo)]
            typo_all += len(t)
            typo_ok += int((t["root_status_code"] == "200").sum())

    n_exp, n_still = sum(exposed.values()), sum(still.values())
    red_truth = red - sum(kinds[k] for k in NOT_IN_TRUTH)
    out = {
        "runs_in_queue": len(runs), "runs_with_features": build["runs"], "missing_features": missing,
        "runs_without_audit": no_audit, "build": dict(build), "trace_labels": dict(labels),
        "window_labels_k3": dict(wlabels),
        "l1_audit": {
            "exposed_in_l0": dict(exposed), "still_in_l1": {k: v for k, v in still.items() if v},
            "recall": round(1 - n_still / n_exp, 5) if n_exp else None,
            "recall_by_field": {f: round(1 - still[f] / exposed[f], 5) for f in sorted(exposed)},
            "redactions": red, "true_positive": tp,
            "precision_strict": round(tp / red, 5) if red else None,
            "precision_without_ip_and_trace_context": round(tp / red_truth, 5) if red_truth else None,
            "no_pii_by_l1_kind": dict(kinds), "no_pii_top_keys": dict(keys.most_common(15)),
        },
        "checks": {"login_typo_traces": typo_all, "login_typo_status_200": typo_ok,
                   "lateral_traces": lat_all, "lateral_traces_under_2_services": lat_small},
    }
    name = os.path.splitext(os.path.basename(a.queue))[0] if not a.runs else "runs"
    path = os.path.join(a.features_dir, f"batch_report_{name}.json")
    json.dump(out, open(path, "w"), indent=2)

    bl = out["build"]
    print(f"[batch] {bl.get('runs', 0)}/{len(runs)} runs with features"
          + (f", missing {missing}" if missing else "") + (f", no audit {no_audit}" if no_audit else ""))
    print(f"  traces {bl.get('traces_kept', 0):,}  spans {bl.get('spans_kept', 0):,}  background dropped "
          f"{bl.get('background', 0):,}  unmatched {bl.get('unmatched', 0):,}  partial {bl.get('partial_traces', 0):,}"
          f"  repaired spans {bl.get('repaired_spans', 0):,}")
    print(f"  windows {bl.get('windows', 0):,} ({bl.get('windows_complete', 0):,} complete); k=3 labels {dict(wlabels)}")
    au = out["l1_audit"]
    print(f"  L1 recall {au['recall']} over {n_exp:,} exposed values; still in L1 {au['still_in_l1']}")
    print(f"  L1 precision strict {au['precision_strict']}, without IP/trace context "
          f"{au['precision_without_ip_and_trace_context']} ({red:,} redactions)")
    print(f"  top keys of redactions not in the ground truth: {list(au['no_pii_top_keys'])[:6]}")
    c = out["checks"]
    print(f"  check: login_typo with status 200: {c['login_typo_status_200']} of {c['login_typo_traces']}")
    print(f"  check: lateral traces with < 2 services: {c['lateral_traces_under_2_services']} of {c['lateral_traces']}")
    print(f"  -> {path}")


if __name__ == "__main__":
    main()
