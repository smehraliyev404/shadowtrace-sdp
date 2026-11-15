"""Leakage check and counts: which personal data
ends up in which span attribute of which service.

    ./venv/bin/python scripts/leakage_check.py --run-id run_50
    ./venv/bin/python scripts/leakage_check.py --run-id run_50 --max-traces 5000

Scans every span attribute (and span log field) of the run's harvested traces with
simple detectors for the synthetic personal data k6 and the attack scripts send:

    email        any address-like value (formats and domains vary, plus-addressing)
    card         13-19 digits that pass the Luhn check (random Visa/MasterCard)
    card_masked  first 6 + stars + last 4 (X-Card-Display header)
    jwt          eyJ... . eyJ... tokens (Authorization: Bearer)
    session      sess_<hex> tokens, shop_session-id cookies, session UUIDs
    phone        international and US formats (+994 50 ..., +1 (415) 555-...)
    address      street formats of US, DE, AZ, TR, FR, IN (k6_test/normal_traffic.js)
    ip           IPv4 addresses (pod/client network identifiers)
    username     enduser.id values on login spans
Every value is checked as stored AND URL-decoded (form bodies and query strings
encode "@" as %40, spaces as "+").

Why a gate: default OpenTelemetry instrumentation records almost no personal
data (no headers, no bodies). The leak channels come from the testbed's own
instrumentation, so every channel the measurement relies on is checked after
each testbed change, before collecting. EXPECTED lists those channels; the check fails if any is silent.

Writes data/runs/<run>/leakage.json; exit 1 if a channel is missing.
"""

import argparse
import collections
import urllib.parse
import glob
import json
import os
import re
import sys

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

DETECTORS = {
    "email":   re.compile(r"[\w.+-]+(?:@|%40)[\w-]+\.[a-z]{2,}", re.I),
    "jwt":     re.compile(r"eyJ[\w-]{5,}\.[\w-]{5,}"),
    "session": re.compile(r"sess_[0-9a-f]{4,}|shop_session-id=[\w-]+|"
                          r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I),
    "card_masked": re.compile(r"\b\d{6}\*{3,9}\d{4}\b"),
    "phone":   re.compile(r"\+\d{1,3}[\s(]{1,2}\d{1,5}\)?(?:[\s-]\d{2,7}){1,4}|\b\d{3}-555-\d{4}\b"),
    "address": re.compile(r"\b\d{1,5} (?:[A-Z][A-Za-z]+ )+(?:St|Ave|Rd|Blvd|Ln|Dr|Way|Road|Street)\b"
                          r"|\b[A-Z][a-z]+(?:strasse|weg|allee) \d{1,4}\b"
                          r"|\b[A-Z][a-z]+(?: [A-Z][a-z]+)? str\. \d{1,4}\b"
                          r"|\bCd\. No:\d{1,4}\b"
                          r"|\b\d{1,4} (?:rue|avenue|boulevard) "),
    "ip":      re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b"),
}
CARD_CANDIDATE = re.compile(r"(?<!\d)\d{13,19}(?!\d)")


def luhn_ok(digits):
    total, alt = 0, False
    for d in reversed(digits):
        n = int(d)
        if alt:
            n = n * 2 - 9 if n > 4 else n * 2
        total += n
        alt = not alt
    return total % 10 == 0


def detect(value):
    forms = {value, urllib.parse.unquote_plus(value)}
    found = [name for name, rx in DETECTORS.items() if any(rx.search(f) for f in forms)]
    if any(luhn_ok(c) for f in forms for c in CARD_CANDIDATE.findall(f)):
        found.append("card")
    return found


# (service, detector) pairs that must leak with the testbed instrumentation (leak.go,
# checkout/email/auth attributes, header capture, k6 query string, Redis keys).
EXPECTED = [
    ("frontend", "email"),          # url.query, X-User-Email header, form body
    ("frontend", "jwt"),            # Authorization header
    ("frontend", "card"),           # form body (credit_card_number)
    ("frontend", "card_masked"),    # X-Card-Display header
    ("frontend", "phone"),          # form body (phone)
    ("frontend", "session"),        # enduser.id / cookie / X-Session-Token
    ("frontend", "address"),        # form body (street_address)
    ("checkoutservice", "email"),   # user.email (+ baggage)
    ("checkoutservice", "address"), # shipping.street_address
    ("emailservice", "email"),      # email.to (+ baggage)
    ("authservice", "username"),    # enduser.id on /login
    ("cartservice", "session"),     # db.statement with the key + baggage
    # baggage (enduser.id / user.email from the frontend) copied into spans of
    # services that never handle user data themselves
    ("productcatalogservice", "session"),
    ("currencyservice", "session"),
    ("shippingservice", "session"),
    ("recommendationservice", "session"),
    ("paymentservice", "email"),
]
OPTIONAL = [
    ("paymentservice", "card"),     # only last 4 digits in error messages -> usually not Luhn
    ("adservice", "session"),       # Java agent: no baggage processor (not configured)
]


def main():
    p = argparse.ArgumentParser(description="which personal data leaks into which span attribute")
    p.add_argument("--run-id", required=True)
    p.add_argument("--raw-dir", default=os.path.join(PROJECT_ROOT, "data", "raw_traces"))
    p.add_argument("--runs-dir", default=os.path.join(PROJECT_ROOT, "data", "runs"))
    p.add_argument("--max-traces", type=int, default=0, help="0 = all")
    a = p.parse_args()

    files = sorted(glob.glob(os.path.join(a.raw_dir, a.run_id, "trace_*.json")))
    if a.max_traces:
        files = files[:a.max_traces]
    hits = collections.Counter()          # (service, attribute, detector) -> count
    examples = {}
    spans_per_service = collections.Counter()
    for f in files:
        t = json.load(open(f, encoding="utf-8"))
        procs = t.get("processes") or {}
        for sp in t.get("spans", []):
            svc = (procs.get(sp.get("processID")) or {}).get("serviceName", "?")
            spans_per_service[svc] += 1
            fields = [(tg["key"], tg.get("value")) for tg in sp.get("tags") or []]
            fields += [("log:" + fl["key"], fl.get("value"))
                       for lg in sp.get("logs") or [] for fl in lg.get("fields") or []]
            for key, val in fields:
                v = str(val)
                kinds = detect(v)
                if key == "enduser.id" and svc == "authservice" and v:
                    kinds.append("username")
                for kind in kinds:
                    hits[(svc, key, kind)] += 1
                    examples.setdefault((svc, key, kind), v[:100])

    by_service = collections.defaultdict(collections.Counter)
    for (svc, key, kind), c in hits.items():
        by_service[svc][kind] += c

    print(f"[leakage] {a.run_id}: {len(files)} traces, "
          f"{sum(spans_per_service.values())} spans scanned")
    print(f"\n  {'service':24s} {'attribute':38s} {'kind':9s} {'count':>7s}  example")
    for (svc, key, kind), c in sorted(hits.items(), key=lambda x: (x[0][0], -x[1])):
        if kind == "ip":
            continue                      # listed in the summary only (very common)
        print(f"  {svc:24s} {key[:38]:38s} {kind:9s} {c:7d}  {examples[(svc, key, kind)][:60]}")
    print("\n  per service (spans with each kind):")
    for svc in sorted(by_service):
        print(f"    {svc:24s} " + "  ".join(f"{k}={v}" for k, v in sorted(by_service[svc].items())))

    missing = [(s, k) for s, k in EXPECTED if by_service[s][k] == 0]
    opt_missing = [(s, k) for s, k in OPTIONAL if by_service[s][k] == 0]
    print("\n  expected leak channels:")
    for s, k in EXPECTED + OPTIONAL:
        state = "OK " if by_service[s][k] else ("MISSING" if (s, k) in missing else "absent (optional)")
        print(f"    {state:18s} {s:20s} {k}")
    passed = not missing
    print(f"\n  LEAKAGE CHECK {'PASS' if passed else 'FAIL'}"
          + (f" - silent channels: {missing}" if missing else ""))

    out_dir = os.path.join(a.runs_dir, a.run_id)
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, "leakage.json")
    json.dump({"run_id": a.run_id, "traces": len(files),
               "spans_per_service": spans_per_service,
               "by_service": {s: dict(c) for s, c in by_service.items()},
               "by_attribute": [{"service": s, "attribute": k, "kind": d, "count": c,
                                 "example": examples[(s, k, d)]}
                                for (s, k, d), c in hits.most_common()],
               "missing": missing, "optional_missing": opt_missing, "pass": passed},
              open(out, "w"), indent=2)
    print(f"  report -> {out}")
    sys.exit(0 if passed else 1)


if __name__ == "__main__":
    main()
