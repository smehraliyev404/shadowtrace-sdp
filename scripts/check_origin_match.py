"""Join a run's harvested traces to its origin log by trace ID.

    ./venv/bin/python scripts/check_origin_match.py --run-id run_01

Two directions, because they answer different questions:

  1. harvested -> origin: of the traces we harvested, how many did one of our
     clients send? The rest are traces nobody sent through the front door
     (Kubernetes health probes, the services' own exporter self-traces, ...).
     They are listed by root service + root operation so each kind is visible.
     GATE A: >= 99% of the harvested traces that are NOT known background traces
     (health checks, exporter self-tracing) must match the origin log.

  2. origin -> harvested: of the requests we logged INSIDE the harvest bracket,
     how many did Jaeger store? Missing ones = lost traces. Reported per origin
     label. GATE B: >= 99% overall AND per label (a whole attack source going
     missing must fail the run even when it is a small share of all requests).
  2b. partial traces: one of our requests
     gives exactly ONE span whose parent is not in the trace (the entry span; its
     parent is our client-side span). A trace with more roots lost spans in
     between. GATE C: partial share of our harvested traces < 2 %.
     Requests outside the bracket (k6 starts before the attacks and stops after
     them) are counted separately, not as losses.

  3. distinct trace patterns: a pattern is the
     shape of a trace = its call tree of (service, operation[, path]) with
     children sorted, so two checkouts with the same calls count once. Reported
     overall and per origin label, to show the traffic is not one pattern per run.

Writes data/runs/<run>/origin_match.json; exit 1 if the gate fails.
"""

import argparse
import collections
import glob
import hashlib
import json
import os
import re
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
GATE = 0.99
PARTIAL_GATE = 0.02

# traces that never come from a client and are dropped by the feature builder
BACKGROUND_OPS = ("grpc.health.v1.Health/Check",
                  "opentelemetry.proto.collector.trace.v1.TraceService/Export")
BACKGROUND_HTTP_PATHS = ("/healthz", "/_healthz")


def norm(tid):
    return (tid or "").lower().lstrip("0")


PATH_TAGS = ("url.path", "http.target", "http.route", "http.url", "url.full")
UA_TAGS = ("user_agent.original", "http.user_agent")


def tag_dict(span):
    return {t.get("key"): str(t.get("value")) for t in span.get("tags") or []}


def n_roots(trace):
    """Spans whose parent is not in the trace (1 for a complete trace of ours)."""
    ids = {sp["spanID"] for sp in trace.get("spans", [])}
    n = 0
    for sp in trace.get("spans", []):
        parents = [r["spanID"] for r in sp.get("references") or [] if r.get("refType") == "CHILD_OF"]
        n += not parents or parents[0] not in ids
    return n


def root_of(trace):
    """(service, operation, path, user_agent) of the span whose parent is not in
    this trace. otelhttp names server spans by method only ("GET"), so the path
    and User-Agent come from the span attributes."""
    ids = {s["spanID"] for s in trace.get("spans", [])}
    procs = trace.get("processes") or {}
    roots = []
    for s in trace.get("spans", []):
        parents = [r["spanID"] for r in s.get("references") or [] if r.get("refType") == "CHILD_OF"]
        if not parents or parents[0] not in ids:
            roots.append(s)
    if not roots:
        return ("?", "?", "", "")
    r = min(roots, key=lambda s: s.get("startTime", 0))
    svc = (procs.get(r.get("processID")) or {}).get("serviceName", "?")
    tags = tag_dict(r)
    path = next((tags[k] for k in PATH_TAGS if k in tags), "")
    ua = next((tags[k] for k in UA_TAGS if k in tags), "")
    return (svc, r.get("operationName", "?"), path.split("?")[0], ua)


def norm_path(path):
    path = path.split("?")[0]
    path = re.sub(r"^/product/[^/]+", "/product/{id}", path)
    return path


def pattern_of(trace):
    """Canonical call-tree signature of one trace (sha1, 12 hex)."""
    spans = trace.get("spans", [])
    procs = trace.get("processes") or {}
    ids = {sp["spanID"] for sp in spans}
    kids = collections.defaultdict(list)
    roots = []
    for sp in spans:
        parents = [r["spanID"] for r in sp.get("references") or [] if r.get("refType") == "CHILD_OF"]
        if parents and parents[0] in ids:
            kids[parents[0]].append(sp)
        else:
            roots.append(sp)

    def label(sp):
        svc = (procs.get(sp.get("processID")) or {}).get("serviceName", "?")
        tags = tag_dict(sp)
        path = next((tags[k] for k in PATH_TAGS if k in tags), "")
        return f"{svc}:{sp.get('operationName', '?')}" + (f" {norm_path(path)}" if path else "")

    def sig(sp):
        return label(sp) + "(" + ",".join(sorted(sig(c) for c in kids[sp["spanID"]])) + ")"

    return hashlib.sha1("|".join(sorted(sig(r) for r in roots)).encode()).hexdigest()[:12]


def is_background(root):
    _, op, path, ua = root
    # Python's gRPC instrumentation names spans "/pkg.Service/Method" (leading
    # slash), Go's "pkg.Service/Method": compare without it
    return (op.lstrip("/") in BACKGROUND_OPS or ua.startswith("kube-probe/")
            or any(x.endswith(p) for x in (op, path) for p in BACKGROUND_HTTP_PATHS))


def main():
    p = argparse.ArgumentParser(description="origin-log <-> harvest join check")
    p.add_argument("--run-id", required=True)
    p.add_argument("--runs-dir", default=os.path.join(PROJECT_ROOT, "data", "runs"))
    p.add_argument("--raw-dir", default=os.path.join(PROJECT_ROOT, "data", "raw_traces"))
    a = p.parse_args()

    harvest = json.load(open(os.path.join(a.runs_dir, f"{a.run_id}.harvest.json")))
    start, end = harvest["started_at"], harvest["ended_at"]

    origin = {}
    for line in open(os.path.join(a.runs_dir, a.run_id, "origin.jsonl"), encoding="utf-8"):
        rec = json.loads(line)
        origin[norm(rec["trace_id"])] = rec

    harvested = {}           # trace id -> (root service, op, path, user agent)
    patterns = {}            # trace id -> pattern signature
    roots = {}               # trace id -> number of root spans
    for f in glob.glob(os.path.join(a.raw_dir, a.run_id, "trace_*.json")):
        t = json.load(open(f, encoding="utf-8"))
        tid = norm(t["traceID"])
        harvested[tid] = root_of(t)
        patterns[tid] = pattern_of(t)
        roots[tid] = n_roots(t)

    # 1. harvested -> origin
    matched = {t for t in harvested if t in origin}
    unmatched = collections.Counter(harvested[t] for t in harvested if t not in origin)
    background = sum(c for root, c in unmatched.items() if is_background(root))
    other_unmatched = sum(unmatched.values()) - background
    relevant = len(harvested) - background
    match_rate = len(matched) / relevant if relevant else 0.0

    # 2. origin -> harvested (only requests sent inside the bracket)
    inside = {t: r for t, r in origin.items() if start <= r["ts"] <= end}
    outside = len(origin) - len(inside)
    by_label = collections.defaultdict(lambda: [0, 0])     # label -> [sent, found]
    for t, r in inside.items():
        by_label[r["origin"]][0] += 1
        by_label[r["origin"]][1] += t in harvested
    sent_in = len(inside)
    found_in = sum(v[1] for v in by_label.values())

    # 3. distinct patterns among our own (matched) traces, per origin label
    pat_by_label = collections.defaultdict(collections.Counter)
    for t in matched:
        pat_by_label[origin[t]["origin"]][patterns[t]] += 1
    all_pats = collections.Counter()
    for c in pat_by_label.values():
        all_pats.update(c)
    pattern_report = {
        "distinct_total": len(all_pats),
        "by_label": {k: {"traces": sum(c.values()), "distinct": len(c),
                         "top_share": round(c.most_common(1)[0][1] / sum(c.values()), 3)}
                     for k, c in sorted(pat_by_label.items())},
    }

    found_rate = found_in / sent_in if sent_in else 0.0
    low_labels = [k for k, v in by_label.items() if v[0] and v[1] / v[0] < GATE]
    gate_a = match_rate >= GATE
    gate_b = found_rate >= GATE and not low_labels
    partial = sum(1 for t in matched if roots[t] > 1)
    partial_rate = partial / len(matched) if matched else 0.0
    gate_c = partial_rate < PARTIAL_GATE
    passed = gate_a and gate_b and gate_c
    report = {
        "run_id": a.run_id, "bracket": [start, end],
        "harvested_traces": len(harvested), "origin_requests": len(origin),
        "harvested_matched": len(matched),
        "harvested_background": background,
        "harvested_unmatched_other": other_unmatched,
        "match_rate_excl_background": round(match_rate, 5),
        "unmatched_by_root": [{"service": s, "operation": o, "path": pth, "user_agent": ua,
                               "background": is_background((s, o, pth, ua)), "traces": c}
                              for (s, o, pth, ua), c in unmatched.most_common()],
        "origin_inside_bracket": sent_in, "origin_outside_bracket": outside,
        "origin_found": found_in,
        "origin_found_rate": round(found_in / sent_in, 5) if sent_in else None,
        "origin_by_label": {k: {"sent": v[0], "found": v[1]} for k, v in sorted(by_label.items())},
        "patterns": pattern_report,
        "partial_traces": partial, "partial_rate": round(partial_rate, 5),
        "gate_c_partial": gate_c,
        "gate": GATE, "gate_a_harvested_matched": gate_a,
        "gate_b_origin_found": gate_b, "labels_below_gate": low_labels, "pass": passed,
    }
    out = os.path.join(a.runs_dir, a.run_id, "origin_match.json")
    json.dump(report, open(out, "w"), indent=2)

    print(f"[match] {a.run_id}: bracket {end - start:.0f}s")
    print(f"  harvested traces       : {len(harvested)}")
    print(f"    matched to origin    : {len(matched)}")
    print(f"    background (probes, exporter self-traces): {background}")
    print(f"    other unmatched      : {other_unmatched}")
    print(f"  MATCH RATE (excl. background): {len(matched)}/{relevant} = {match_rate:.3%}  "
          f"-> {'PASS' if gate_a else 'FAIL'} (gate A, {GATE:.0%})")
    print("  unmatched traces by root (service, operation, path, user agent):")
    for root, c in unmatched.most_common(10):
        s, o, pth, ua = root
        print(f"    {c:6d}  {s:16s} {o[:40]:40s} {pth or '-':14s} {ua[:24] or '-':24s}"
              f"{'  [background]' if is_background(root) else ''}")
    print(f"  origin requests inside bracket: {sent_in} (outside: {outside})")
    print(f"    found in harvest     : {found_in} ({found_in / sent_in:.2%})" if sent_in else "")
    for k, v in sorted(by_label.items()):
        print(f"    {k:24s} sent {v[0]:6d}  found {v[1]:6d}  ({v[1] / v[0]:.2%})")
    print(f"  distinct trace patterns (our traces): {len(all_pats)}")
    for k, v in pattern_report["by_label"].items():
        print(f"    {k:24s} {v['distinct']:5d} patterns in {v['traces']:6d} traces "
              f"(most common = {v['top_share']:.0%})")
    print(f"  GATE B (our requests found, overall and per label >= {GATE:.0%}): "
          f"{'PASS' if gate_b else 'FAIL'}" + (f"  low: {low_labels}" if low_labels else ""))
    print(f"  GATE C (partial traces < {PARTIAL_GATE:.0%}): {partial} of {len(matched)} "
          f"= {partial_rate:.3%} -> {'PASS' if gate_c else 'FAIL'}")
    print(f"  RUN {'PASS' if passed else 'FAIL'}")
    print(f"  report -> {out}")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
