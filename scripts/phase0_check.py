"""Ground-truth checks of the testbed, run before collecting.

Answers three questions before we build anything on top of the traces:

1. Propagation: if a client picks its own trace ID and sends it as a W3C
   `traceparent`, does each entry service (frontend, authservice, ssrfservice)
   continue that trace, so Jaeger stores it under OUR ID with our span as parent?
   Provenance labels depend on this.
2. Inventory: which services emit their own spans, and which are only visible
   from the caller's side (a client span with no server child)?
3. Integrity: how many spans are orphans (parent missing), how many children
   start before their parent (clock skew), and which services start detached
   traces of their own (lost context)?

Writes data/phase0/<UTC stamp>/report.json and report.md. Needs only `requests`.

    python scripts/phase0_check.py
    python scripts/phase0_check.py --journeys 10 --wait 30
"""

import argparse
import json
import os
import random
import sys
import time
from collections import defaultdict
from datetime import datetime, timezone
from urllib.parse import urlparse

import requests

# Every service we expect in the Boutique + stubs. loadgenerator is scaled to 0.
EXPECTED_SERVICES = [
    "frontend", "checkoutservice", "productcatalogservice", "shippingservice",
    "currencyservice", "paymentservice", "emailservice", "recommendationservice",
    "adservice", "cartservice", "authservice", "ssrfservice",
]
# Services that legitimately start traces (clients talk to them directly).
ENTRY_SERVICES = {"frontend", "authservice", "ssrfservice", "attacker"}
JAEGER_SELF = {"jaeger-all-in-one", "jaeger-query", "jaeger-collector"}

PRODUCTS = ["OLJCESPC7Z", "66VCHSJNUP", "1YMWWN1N4O", "L9ECAV7KIM", "2ZYFJ3GM2N",
            "0PUK6V6EV0", "LS4PSXUNUM", "9SIQT8TOJO", "6E92ZMYYFZ"]
CURRENCIES = ["EUR", "USD", "JPY", "GBP", "CAD", "TRY"]


# ---------------------------------------------------------------- trace IDs

from provenance import new_ids, traceparent  # noqa: E402  (same ID rules as every client)
from check_origin_match import norm as norm_id  # noqa: E402


# ---------------------------------------------------------------- Jaeger

def jaeger_get(jaeger, path, params=None):
    try:
        r = requests.get(f"{jaeger}{path}", params=params, timeout=30)
    except requests.RequestException as e:
        print(f"[!] Jaeger unreachable at {jaeger}: {e}")
        return None
    if r.status_code != 200:
        return None
    return r.json().get("data")


def fetch_trace(jaeger, trace_id, wait):
    """Poll Jaeger for one trace until it shows up or `wait` seconds pass.

    Call this only after the settle pause in main(): exporters send spans in
    batches (about every 5 s), so a trace can appear before all its spans do.
    """
    deadline = time.time() + wait
    while True:
        data = jaeger_get(jaeger, f"/api/traces/{trace_id}")
        if data:
            return data[0]
        if time.time() >= deadline:
            return None
        time.sleep(2)


def tag(span, key):
    for t in span.get("tags", []):
        if t.get("key") == key:
            return t.get("value")
    return None


def flatten(trace):
    """Jaeger trace JSON -> list of plain span dicts."""
    procs = {pid: p.get("serviceName") for pid, p in (trace.get("processes") or {}).items()}
    spans = []
    for s in trace.get("spans", []):
        parent = None
        for ref in s.get("references") or []:
            if ref.get("refType") in ("CHILD_OF", "FOLLOWS_FROM"):
                parent = norm_id(ref.get("spanID"))
                break
        spans.append({
            "span_id": norm_id(s.get("spanID")),
            "parent": parent,
            "service": procs.get(s.get("processID"), "?"),
            "name": s.get("operationName"),
            "kind": tag(s, "span.kind") or "unset",
            "start": s.get("startTime", 0),
            "duration": s.get("duration", 0),
            "callee": callee_of(s),
        })
    return spans


def callee_of(span):
    """Best guess of which service a client span calls."""
    rpc = tag(span, "rpc.service")
    if rpc:                                    # hipstershop.CartService -> cartservice
        return rpc.split(".")[-1].lower()
    # Go otelgrpc clients carry no rpc.service tag, only the span name or
    # rpc.method in the form "hipstershop.CartService/GetCart"
    for full in (tag(span, "rpc.method"), span.get("operationName")):
        if full and "/" in full and "." in full.split("/")[0]:
            return full.split("/")[0].split(".")[-1].lower()
    for key in ("server.address", "net.peer.name", "peer.service"):
        v = tag(span, key)
        if v:
            return str(v).split(".")[0].lower()
    url = tag(span, "http.url") or tag(span, "url.full")
    if url:
        host = urlparse(url).hostname
        if host:
            return host.split(".")[0].lower()
    return None


# ---------------------------------------------------------------- traffic

def send(session, method, url, our_ids, label, **kwargs):
    """One request under a client-chosen trace ID. Redirects are not followed,
    so a 302 never re-sends the same traceparent as a second request."""
    trace_id, span_id = new_ids()
    headers = kwargs.pop("headers", {})
    headers["traceparent"] = traceparent(trace_id, span_id)
    try:
        r = session.request(method, url, headers=headers, timeout=15,
                            allow_redirects=False, **kwargs)
        status = r.status_code
    except requests.RequestException as e:
        status = f"error: {str(e)[:80]}"
    our_ids.add(span_id)
    return {"label": label, "trace_id": trace_id, "span_id": span_id, "status": status}


def journey(frontend, n, our_ids):
    """One full shop visit: home -> product -> currency -> add to cart -> cart -> checkout."""
    s = requests.Session()
    pid = random.choice(PRODUCTS)
    uid = random.randint(10000, 99999)
    sent = [
        send(s, "GET", f"{frontend}/", our_ids, "home"),
        send(s, "GET", f"{frontend}/product/{pid}", our_ids, "product"),
        send(s, "POST", f"{frontend}/setCurrency", our_ids, "set_currency",
             data={"currency_code": random.choice(CURRENCIES)}),
        send(s, "POST", f"{frontend}/cart", our_ids, "add_to_cart",
             data={"product_id": pid, "quantity": str(random.randint(1, 5))}),
        send(s, "GET", f"{frontend}/cart", our_ids, "view_cart"),
        send(s, "POST", f"{frontend}/cart/checkout", our_ids, "checkout", data={
            "email": f"phase0_{uid}@example.com",
            "street_address": f"{uid} Test Street", "zip_code": "94043",
            "city": "Mountain View", "state": "CA", "country": "United States",
            "credit_card_number": "4432801561520454",   # synthetic test card
            "credit_card_expiration_month": "1",
            "credit_card_expiration_year": "2039", "credit_card_cvv": "672",
        }),
    ]
    for r in sent:
        r["journey"] = n
    return sent


# ---------------------------------------------------------------- checks

def check_propagation(name, sent, trace):
    """Did the entry service continue our trace with our span as parent?"""
    result = {"entry": name, "status": sent["status"], "trace_id": sent["trace_id"],
              "found_under_our_id": trace is not None, "parent_is_our_span": False,
              "child_service": None, "services_in_trace": []}
    if trace is not None:
        spans = flatten(trace)
        result["services_in_trace"] = sorted({s["service"] for s in spans})
        children = [s for s in spans if s["parent"] == norm_id(sent["span_id"])]
        if children:
            result["parent_is_our_span"] = True
            result["child_service"] = children[0]["service"]
    # the entry service itself must be the one that continued our trace
    result["pass"] = (result["found_under_our_id"] and result["parent_is_our_span"]
                      and result["child_service"] == name)
    return result


def analyse(traces, our_ids):
    """Inventory + integrity over every trace we fetched."""
    our_ids = {norm_id(i) for i in our_ids}
    inv = defaultdict(lambda: defaultdict(int))
    called = defaultdict(lambda: {"calls": 0, "with_server_child": 0})
    integ = defaultdict(lambda: {"spans": 0, "orphans": 0, "no_parent": 0,
                                 "starts_before_parent": 0, "max_skew_ms": 0.0})
    for trace in traces:
        spans = flatten(trace)
        by_id = {s["span_id"]: s for s in spans}
        children = defaultdict(list)
        for s in spans:
            if s["parent"]:
                children[s["parent"]].append(s)
        for s in spans:
            svc = s["service"]
            inv[svc][s["kind"]] += 1
            integ[svc]["spans"] += 1
            if s["parent"] and s["parent"] not in by_id and s["parent"] not in our_ids:
                integ[svc]["orphans"] += 1
            # in our traces even the entry span has a parent (our span ID), so a
            # span without any parent lost its parent ID on the way to Jaeger
            if not s["parent"]:
                integ[svc]["no_parent"] += 1
            parent = by_id.get(s["parent"]) if s["parent"] else None
            if parent and s["start"] < parent["start"]:
                skew = (parent["start"] - s["start"]) / 1000.0
                integ[svc]["starts_before_parent"] += 1
                integ[svc]["max_skew_ms"] = max(integ[svc]["max_skew_ms"], round(skew, 3))
            if s["kind"] == "client" and s["callee"]:
                c = called[s["callee"]]
                c["calls"] += 1
                if any(ch["service"] != svc for ch in children[s["span_id"]]):
                    c["with_server_child"] += 1
    return ({k: dict(v) for k, v in inv.items()}, dict(called), dict(integ))


def is_health_check(name):
    name = (name or "").lower()
    return "grpc.health" in name or "healthz" in name or "/health" in name


def detached_traces(jaeger, start_us, end_us, our_trace_ids):
    """Traces in our time range that start at a non-entry service.

    A service that loses the incoming context starts a new trace of its own,
    which never shows up under our trace IDs, so we look for those separately.
    Kubernetes gRPC/HTTP probes also start such traces; they are counted apart.
    """
    ours = {norm_id(t) for t in our_trace_ids}
    out = {}
    for svc in jaeger_get(jaeger, "/api/services") or []:
        if svc in ENTRY_SERVICES or svc in JAEGER_SELF:
            continue
        data = jaeger_get(jaeger, "/api/traces",
                          {"service": svc, "start": start_us, "end": end_us, "limit": 2000}) or []
        health, other, ops = 0, 0, defaultdict(int)
        for trace in data:
            if norm_id(trace.get("traceID")) in ours:
                continue
            spans = flatten(trace)
            roots = [s for s in spans if not s["parent"]]
            if not roots or not all(r["service"] == svc for r in roots):
                continue
            if is_health_check(roots[0]["name"]):
                health += 1
            else:
                other += 1
                ops[roots[0]["name"]] += 1
        top = sorted(ops.items(), key=lambda kv: -kv[1])[:3]
        out[svc] = {"health_checks": health, "other": other, "top_other_ops": top}
    return out


def classify(svc, inv, called):
    own = inv.get(svc, {})
    c = called.get(svc, {"calls": 0, "with_server_child": 0})
    if own.get("server", 0) > 0:
        return "traced"
    if sum(own.values()) > 0:
        return "spans but no server spans"
    if c["calls"] > 0:
        return "visible only from callers"
    return "not seen"


# ---------------------------------------------------------------- report

def write_report(out_dir, report):
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "report.json"), "w", encoding="utf-8") as f:
        json.dump(report, f, indent=2)

    L = [f"# Phase 0 report ({report['stamp']})", ""]
    L += ["## 1. Propagation", "",
          "| Entry | HTTP status | Found under our ID | Parent = our span | Child service | "
          "Services in trace | Pass |",
          "|---|---|---|---|---|---|---|"]
    for p in report["propagation"]:
        L.append(f"| {p['entry']} | {p['status']} | {p['found_under_our_id']} | "
                 f"{p['parent_is_our_span']} | {p['child_service'] or '-'} | "
                 f"{', '.join(p['services_in_trace']) or '-'} | "
                 f"{'PASS' if p['pass'] else 'FAIL'} |")

    j = report["journeys"]
    L += ["", f"## 2. Inventory ({j['requests']} journey requests, "
              f"{j['traces_found']} traces found, {j['non_2xx']} non-2xx/3xx)", "",
          "| Service | Status | server | client | internal | unset | Called by others | "
          "Calls with server child |",
          "|---|---|---|---|---|---|---|---|"]
    for svc in report["inventory"]["services"]:
        own = report["inventory"]["own_spans"].get(svc, {})
        c = report["inventory"]["called"].get(svc, {"calls": 0, "with_server_child": 0})
        L.append(f"| {svc} | {report['inventory']['status'][svc]} | {own.get('server', 0)} | "
                 f"{own.get('client', 0)} | {own.get('internal', 0)} | {own.get('unset', 0)} | "
                 f"{c['calls']} | {c['with_server_child']} |")

    L += ["", "## 3. Integrity", "",
          "| Service | Spans | Orphans | No parent ID | Starts before parent | Max skew (ms) | "
          "Own traces: health checks | Own traces: other |",
          "|---|---|---|---|---|---|---|---|"]
    det = report["integrity"]["detached_traces"]
    for svc in sorted(set(report["integrity"]["per_service"]) | set(det)):
        v = report["integrity"]["per_service"].get(
            svc, {"spans": 0, "orphans": 0, "no_parent": 0, "starts_before_parent": 0,
                  "max_skew_ms": 0.0})
        d = det.get(svc)
        L.append(f"| {svc} | {v['spans']} | {v['orphans']} | {v['no_parent']} | "
                 f"{v['starts_before_parent']} | {v['max_skew_ms']} | "
                 f"{d['health_checks'] if d else '-'} | {d['other'] if d else '-'} |")
    others = {svc: d["top_other_ops"] for svc, d in det.items() if d["other"]}
    if others:
        L += ["", "Root operations of non-health-check traces that start inside a service "
                  "(possible lost context):", ""]
        for svc, ops in others.items():
            L.append(f"- {svc}: " + ", ".join(f"`{op}` ×{n}" for op, n in ops))
    L += ["",
          "**Reading this:** a service that is `visible only from callers` is not instrumented, "
          "but the edge to it still exists through the caller's client span. Orphans, or "
          "non-health-check traces that start inside a service, point to lost context. "
          "`No parent ID` means the trace ID arrived but the parent span ID was lost on export. "
          "Health-check traces come from Kubernetes probes and are expected. "
          "`Starts before parent` on a single-node cluster is timestamp ordering, not real "
          "clock skew."]
    with open(os.path.join(out_dir, "report.md"), "w", encoding="utf-8") as f:
        f.write("\n".join(L) + "\n")


# ---------------------------------------------------------------- main

def main():
    p = argparse.ArgumentParser(description="ShadowTrace Phase 0 ground-truth checks")
    p.add_argument("--frontend", default="http://localhost:8080")
    p.add_argument("--auth", default="http://localhost:8081")
    p.add_argument("--ssrf", default="http://localhost:8082")
    p.add_argument("--jaeger", default=os.getenv("JAEGER_BASE_URL", "http://localhost:16686"))
    p.add_argument("--ssrf-target", default="http://frontend:80/",
                   help="URL ssrfservice fetches (in-cluster, harmless)")
    p.add_argument("--journeys", type=int, default=5)
    p.add_argument("--wait", type=int, default=30, help="max seconds to wait for each trace")
    p.add_argument("--settle", type=int, default=15,
                   help="seconds to wait after sending, so batched spans reach Jaeger")
    p.add_argument("--out", default="data/phase0")
    args = p.parse_args()

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    start_us = int(time.time() * 1e6)
    our_ids = set()

    if jaeger_get(args.jaeger, "/api/services") is None:
        sys.exit(f"[!] Jaeger not reachable at {args.jaeger}. Is `docker compose up -d` running?")

    # send everything first, then wait once, so batched spans have arrived
    # before anything is read back
    print(f"[1/3] sending: 3 propagation probes + {args.journeys} journeys")
    s = requests.Session()
    probes = [
        ("frontend", send(s, "GET", f"{args.frontend}/", our_ids, "frontend")),
        ("authservice", send(s, "POST", f"{args.auth}/login", our_ids, "authservice",
                             data={"username": "phase0", "password": "phase0"})),
        ("ssrfservice", send(s, "GET", f"{args.ssrf}/fetch", our_ids, "ssrfservice",
                             params={"url": args.ssrf_target})),
    ]
    sent_all = []
    for n in range(args.journeys):
        sent_all += journey(args.frontend, n, our_ids)
    print(f"    waiting {args.settle}s for exporters to flush")
    time.sleep(args.settle)

    print("[2/3] propagation + inventory")
    traces, propagation = [], []
    for name, sent in probes:
        trace = fetch_trace(args.jaeger, sent["trace_id"], args.wait)
        res = check_propagation(name, sent, trace)
        propagation.append(res)
        if trace:
            traces.append(trace)
        print(f"    {name:12s} {'PASS' if res['pass'] else 'FAIL'}  (status {sent['status']}, "
              f"services: {', '.join(res['services_in_trace']) or '-'})")
    found = 0
    for sent in sent_all:
        trace = fetch_trace(args.jaeger, sent["trace_id"], args.wait)
        sent["found"] = trace is not None
        if trace:
            traces.append(trace)
            found += 1
    print(f"    {found}/{len(sent_all)} journey traces found")

    print("[3/3] integrity")
    inv, called, integ = analyse(traces, our_ids)
    our_traces = [p["trace_id"] for _, p in probes] + [r["trace_id"] for r in sent_all]
    detached = detached_traces(args.jaeger, start_us, int(time.time() * 1e6), our_traces)
    services = EXPECTED_SERVICES + sorted(set(inv) - set(EXPECTED_SERVICES) - JAEGER_SELF)

    report = {
        "stamp": stamp,
        "args": vars(args),
        "propagation": propagation,
        "journeys": {
            "requests": len(sent_all), "traces_found": found,
            "non_2xx": sum(1 for r in sent_all
                           if not (isinstance(r["status"], int) and r["status"] < 400)),
            "sent": sent_all,
        },
        "inventory": {"services": services, "own_spans": inv, "called": called,
                      "status": {svc: classify(svc, inv, called) for svc in services}},
        "integrity": {"per_service": integ, "detached_traces": detached},
    }
    out_dir = os.path.join(args.out, stamp)
    write_report(out_dir, report)

    for svc in services:
        print(f"    {svc:24s} {report['inventory']['status'][svc]}")
    print(f"[✓] report -> {out_dir}/report.md")
    sys.exit(0 if all(p["pass"] for p in propagation) else 1)


if __name__ == "__main__":
    main()
