"""L1 redaction recall and precision against the ground truth in origin.jsonl.

    ./venv/bin/python scripts/pii_audit.py --run-id a3_01
    ./venv/bin/python scripts/pii_audit.py --run-id a3_01 a3_02 --origin other.jsonl   # testing

Every origin line carries `pii`: the personal values that request really sent
(session id, credentials, checkout values; all synthetic). Per trace:

  exposed    a pii value (as sent, URL-encoded, or with '+' decoded to a space)
             appears in the trace's L0
             attributes, i.e. the testbed leaked it into the trace
  recall     share of exposed values that no longer appear in L1, per pii field
  precision  every attribute value that L1 changed is one redaction; it is a
             true positive if its L0 value contains a pii value of that trace.
             Redactions without a pii value are listed by the L1 replacement
             kind ([ip], H_ token, [removed], ...): IPs and trace context are
             sensitive but not in the ground truth, so precision is reported
             both strictly and without those kinds.
Values shorter than 4 characters are skipped (too many accidental matches).

Writes data/features/<run>/pii_audit.json.
"""

import argparse
import collections
import json
import os
import re
import sys
import urllib.parse

import pandas as pd

from check_origin_match import norm

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
MIN_LEN = 4
HMAC_TOKEN = re.compile(r"H_[a-p]{16}")
NOT_IN_TRUTH = {"ip", "trace_context"}      # sensitive, redacted on purpose, not in the pii ground truth


def flatten(d, prefix=""):
    for k, v in (d or {}).items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            yield from flatten(v, key + ".")
        elif isinstance(v, list):
            for x in v:
                yield key, str(x)
        elif v is not None:
            yield key, str(v)


def variants(v):
    """The forms a value can take in span attributes: as sent, URL-encoded, and with
    '+' turned into a space (Python services decode baggage that way: "a+shop@x"
    arrives as "a shop@x" in emailservice and recommendationservice spans)."""
    out = {v, urllib.parse.quote_plus(v), urllib.parse.quote(v, safe="")}
    if "+" in v:
        out.add(v.replace("+", " "))
    return out


def l1_kind(key, value):
    """What L1 put in place of a value: trace context, a token, a placeholder kind, or 'changed'."""
    if "traceparent" in key or "tracestate" in key:
        return "trace_context"
    if HMAC_TOKEN.search(value):
        return "hmac_token"
    m = re.search(r"\[(\w+)\]", value)
    return m.group(1) if m else "changed"


def audit(run_id, features_dir, origin_path):
    truth = {}
    for line in open(origin_path, encoding="utf-8"):
        r = json.loads(line)
        if r.get("pii"):
            truth[norm(r["trace_id"])] = [(f, v) for f, v in flatten(r["pii"])]
    cols = ["trace_id", "span_id", "attrs"]
    l0 = pd.read_parquet(os.path.join(features_dir, run_id, "L0", "spans.parquet"), columns=cols)
    l1 = pd.read_parquet(os.path.join(features_dir, run_id, "L1", "spans.parquet"), columns=cols)
    l0 = l0[l0["trace_id"].isin(truth)]
    l1 = l1[l1["trace_id"].isin(truth)].set_index("span_id")["attrs"]

    exposed, still = collections.Counter(), collections.Counter()
    skipped_short, values_total = 0, 0
    tp, fp_kinds, tp_kinds, fp_keys = 0, collections.Counter(), collections.Counter(), collections.Counter()
    for tid, g in l0.groupby("trace_id"):
        a0 = [json.loads(x) for x in g["attrs"]]
        a1 = [json.loads(l1.get(s, "{}")) for s in g["span_id"]]
        text0 = "\n".join(str(v) for d in a0 for v in d.values())
        text1 = "\n".join(str(v) for d in a1 for v in d.values())
        vals = []
        for field, v in truth[tid]:
            values_total += 1
            if len(v) < MIN_LEN:
                skipped_short += 1
                continue
            vs = variants(v)
            vals.append(vs)
            if any(x in text0 for x in vs):
                exposed[field] += 1
                still[field] += any(x in text1 for x in vs)
        for d0, d1 in zip(a0, a1):
            for k, v0 in d0.items():
                v0, v1 = str(v0), str(d1.get(k, ""))
                if v0 == v1 or urllib.parse.unquote_plus(v0) == v1:    # unchanged or only URL-decoded
                    continue
                kind = l1_kind(k, v1)
                if any(x in v0 for vs in vals for x in vs):
                    tp += 1
                    tp_kinds[kind] += 1
                else:
                    fp_kinds[kind] += 1
                    fp_keys[k] += 1

    n_red = tp + sum(fp_kinds.values())
    n_red_truth = n_red - sum(fp_kinds[k] for k in NOT_IN_TRUTH)
    n_exp = sum(exposed.values())
    return {
        "run_id": run_id, "traces_with_pii": len(truth), "traces_in_l0": int(l0["trace_id"].nunique()),
        "pii_values": values_total, "skipped_shorter_than_4": skipped_short,
        "exposed_in_l0": dict(exposed), "still_in_l1": dict(still),
        "recall": round(1 - sum(still.values()) / n_exp, 5) if n_exp else None,
        "recall_by_field": {f: round(1 - still[f] / exposed[f], 5) for f in exposed},
        "redactions": n_red, "true_positive": tp,
        "precision_strict": round(tp / n_red, 5) if n_red else None,
        "precision_without_ip_and_trace_context": round(tp / n_red_truth, 5) if n_red_truth else None,
        "true_positive_by_l1_kind": dict(tp_kinds),
        "no_pii_by_l1_kind": dict(fp_kinds), "no_pii_top_keys": dict(fp_keys.most_common(15)),
    }


def main():
    p = argparse.ArgumentParser(description="L1 recall/precision against the origin pii ground truth")
    p.add_argument("--run-id", nargs="+", required=True)
    p.add_argument("--features-dir", default=os.path.join(PROJECT_ROOT, "data", "features"))
    p.add_argument("--runs-dir", default=os.path.join(PROJECT_ROOT, "data", "runs"))
    p.add_argument("--origin", help="origin.jsonl to use instead of the run's own (testing)")
    a = p.parse_args()
    for run in a.run_id:
        origin = a.origin or os.path.join(a.runs_dir, run, "origin.jsonl")
        r = audit(run, a.features_dir, origin)
        if not r["traces_with_pii"]:
            sys.exit(f"[pii_audit] {run}: no origin line has `pii` (run predates batch 3?)")
        json.dump(r, open(os.path.join(a.features_dir, run, "pii_audit.json"), "w"), indent=2)
        print(f"[pii_audit] {run}: {r['traces_with_pii']} traces with pii, exposed in L0 {r['exposed_in_l0']}")
        print(f"  recall {r['recall']} {r['recall_by_field']}; still in L1 {r['still_in_l1']}")
        print(f"  precision strict {r['precision_strict']}, without IP/trace context "
              f"{r['precision_without_ip_and_trace_context']} ({r['redactions']} redactions); "
              f"no-pii kinds {r['no_pii_by_l1_kind']}")


if __name__ == "__main__":
    main()
