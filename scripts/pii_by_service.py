"""RQ1 per service: which services' spans carry which personal values, at L0 and L1.

    ./venv/bin/python scripts/pii_by_service.py --queue queues/batch3.txt --jobs 16

Same ground truth and matching as pii_audit.py (the `pii` values each request
really sent, as sent / URL-encoded / with '+' decoded; values shorter than 4
characters skipped). A value counts as exposed in a service when it appears in
the attributes of at least one span of that service in the same trace; so one
value can be exposed in several services (that is the point: baggage carries the
session id into services that never handle user data). Counted per run:

  exposed[service][field]   (trace, value) pairs present in that service at L0
  still[service][field]     ... and still present there at L1
  keys[service][attribute]  attribute keys the L0 values were found in

Writes data/features/<run>/pii_by_service.json per run and
data/features/pii_by_service_<queue>.json over the queue, and prints a table.
"""

import argparse
import collections
import json
import os
import sys
from concurrent.futures import ProcessPoolExecutor

import pandas as pd

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from check_origin_match import norm  # noqa: E402
from pii_audit import MIN_LEN, flatten, variants  # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))


def read_queue(path):
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if line:
            yield line.split()[0]


def run_one(args):
    run, features_dir, runs_dir = args
    truth = {}
    for line in open(os.path.join(runs_dir, run, "origin.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        if r.get("pii"):
            vals = [(f, v) for f, v in flatten(r["pii"]) if len(v) >= MIN_LEN]
            if vals:
                truth[norm(r["trace_id"])] = [(f, variants(v)) for f, v in vals]
    cols = ["trace_id", "span_id", "service", "attrs"]
    l0 = pd.read_parquet(os.path.join(features_dir, run, "L0", "spans.parquet"), columns=cols)
    l0 = l0[l0["trace_id"].isin(truth)]
    l1 = pd.read_parquet(os.path.join(features_dir, run, "L1", "spans.parquet"), columns=["trace_id", "span_id", "attrs"])
    l1 = l1[l1["trace_id"].isin(truth)].set_index("span_id")["attrs"]

    exposed, still = collections.defaultdict(collections.Counter), collections.defaultdict(collections.Counter)
    keys = collections.defaultdict(collections.Counter)
    for tid, g in l0.groupby("trace_id"):
        spans = [(svc, json.loads(a0), json.loads(l1.get(sid, "{}")))
                 for svc, sid, a0 in zip(g["service"], g["span_id"], g["attrs"])]
        text0 = "\n".join(str(v) for _, d0, _ in spans for v in d0.values())
        for field, vs in truth[tid]:
            if not any(x in text0 for x in vs):        # not in the trace at all: skip the per-span work
                continue
            seen0, seen1 = set(), set()
            for svc, d0, d1 in spans:
                hit = [k for k, v in d0.items() if any(x in str(v) for x in vs)]
                if hit:
                    seen0.add(svc)
                    keys[svc].update(hit)
                    if any(x in str(v) for v in d1.values() for x in vs):
                        seen1.add(svc)
            for svc in seen0:
                exposed[svc][field] += 1
            for svc in seen1:
                still[svc][field] += 1
    out = {"run_id": run, "traces_with_pii": len(truth),
           "exposed": {s: dict(c) for s, c in exposed.items()},
           "still_in_l1": {s: dict(c) for s, c in still.items() if c},
           "keys": {s: dict(c.most_common(20)) for s, c in keys.items()}}
    json.dump(out, open(os.path.join(features_dir, run, "pii_by_service.json"), "w"), indent=1)
    return out


def main():
    ap = argparse.ArgumentParser(description="RQ1: personal values per service at L0 and L1")
    ap.add_argument("--queue", default=os.path.join(PROJECT_ROOT, "queues", "batch3.txt"))
    ap.add_argument("--runs", nargs="*", help="instead of --queue")
    ap.add_argument("--features-dir", default=os.path.join(PROJECT_ROOT, "data", "features"))
    ap.add_argument("--runs-dir", default=os.path.join(PROJECT_ROOT, "data", "runs"))
    ap.add_argument("--jobs", type=int, default=1)
    a = ap.parse_args()
    runs = a.runs or list(read_queue(a.queue))
    jobs = [(r, a.features_dir, a.runs_dir) for r in runs]
    if a.jobs > 1:
        with ProcessPoolExecutor(a.jobs) as pool:
            res = list(pool.map(run_one, jobs))
    else:
        res = [run_one(j) for j in jobs]

    exposed, still, keys = (collections.defaultdict(collections.Counter) for _ in range(3))
    for r in res:
        for s, c in r["exposed"].items():
            exposed[s].update(c)
        for s, c in r["still_in_l1"].items():
            still[s].update(c)
        for s, c in r["keys"].items():
            keys[s].update(c)
    services = sorted(exposed, key=lambda s: -sum(exposed[s].values()))
    fields = sorted({f for c in exposed.values() for f in c}, key=lambda f: -sum(exposed[s][f] for s in exposed))
    summary = {"runs": len(res), "traces_with_pii": sum(r["traces_with_pii"] for r in res),
               "services": [{"service": s, "exposed_total": sum(exposed[s].values()),
                             "still_in_l1_total": sum(still[s].values()),
                             "fields": len(exposed[s]), "exposed": dict(exposed[s]),
                             "still_in_l1": dict(still[s]), "top_keys": dict(keys[s].most_common(8))}
                            for s in services]}
    name = os.path.splitext(os.path.basename(a.queue))[0] if not a.runs else "runs"
    path = os.path.join(a.features_dir, f"pii_by_service_{name}.json")
    json.dump(summary, open(path, "w"), indent=1)

    print(f"[pii_by_service] {len(res)} runs, {summary['traces_with_pii']:,} traces with ground truth")
    print(f"{'service':<24} {'exposed (L0)':>14} {'still in L1':>12} {'fields':>7}  top attribute keys")
    for r in summary["services"]:
        print(f"{r['service']:<24} {r['exposed_total']:>14,} {r['still_in_l1_total']:>12,} {r['fields']:>7}  "
              f"{list(r['top_keys'])[:4]}")
    print("\nper field (exposed at L0) in each service:")
    print(f"{'service':<24} " + " ".join(f"{f[:10]:>10}" for f in fields))
    for s in services:
        print(f"{s:<24} " + " ".join(f"{exposed[s].get(f, 0):>10,}" for f in fields))
    print(f"  -> {path}")


if __name__ == "__main__":
    main()
