"""Provenance labels: every client picks its own trace ID and logs it.

Every request we send carries `traceparent: 00-<trace_id>-<span_id>-01` with IDs
WE chose, and before it is sent one line is appended to the run's origin log:

    {"ts": ..., "trace_id": "...", "span_id": "...", "origin": "normal" | <attack>,
     "client": "k6" | "brute_force" | ..., "run_id": ..., "seed": ..., "method": "POST",
     "path": "/login", "params": {...}}

The labeller later joins Jaeger traces to this file by trace_id. The models never
read it, and nothing about the origin travels with the request.

Rules that keep the join exact:
  * no leading zero in either ID (Jaeger may print IDs without them),
  * redirects are NOT followed automatically: a followed 302 would re-send the
    same traceparent and put two requests into one trace. `send()` follows them by
    hand, each hop with a new ID and its own log line (`follow_of` = previous ID),
  * the line is written BEFORE the request, so a timed-out request is still logged.

Where the log goes: --origin-log / $ORIGIN_LOG, default data/runs/<run_id>/origin.jsonl.
Run ID and seed come from $SHADOWTRACE_RUN_ID / $SHADOWTRACE_SEED when the
attack scripts are launched by the orchestrator.
"""

import json
import os
import random
import secrets
import threading
import time
from urllib.parse import urljoin, urlsplit

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))

# Attacks use the same User-Agent as the k6 shoppers, so the client name is
# not a shortcut at L0/L1. Must match the k6 version in the lab; override with
# $SHADOWTRACE_USER_AGENT if the lab's k6 differs.
DEFAULT_USER_AGENT = os.getenv("SHADOWTRACE_USER_AGENT", "Grafana k6/2.3.0")


def new_ids():
    """A client-chosen trace ID (32 hex) and parent span ID (16 hex), no leading 0."""
    trace_id = secrets.token_hex(16)
    while trace_id[0] == "0":
        trace_id = secrets.token_hex(16)
    span_id = secrets.token_hex(8)
    while span_id[0] == "0":
        span_id = secrets.token_hex(8)
    return trace_id, span_id


def traceparent(trace_id, span_id):
    return f"00-{trace_id}-{span_id}-01"   # 01 = sampled


def default_origin_path(run_id):
    return os.path.join(PROJECT_ROOT, "data", "runs", run_id or "adhoc", "origin.jsonl")


class OriginLog:
    """Append-only, thread-safe JSONL writer. One instance per process."""

    def __init__(self, path=None, run_id=None, seed=None, client=None):
        self.run_id = run_id or os.getenv("SHADOWTRACE_RUN_ID") or "adhoc"
        seed_env = os.getenv("SHADOWTRACE_SEED")
        self.seed = seed if seed is not None else (int(seed_env) if seed_env else None)
        self.client = client
        self.path = path or os.getenv("ORIGIN_LOG") or default_origin_path(self.run_id)
        os.makedirs(os.path.dirname(os.path.abspath(self.path)), exist_ok=True)
        self._lock = threading.Lock()
        # line-buffered append; each write is one complete line under the lock
        self._f = open(self.path, "a", encoding="utf-8", buffering=1)

    def write(self, trace_id, span_id, origin, **extra):
        rec = {"ts": round(time.time(), 6), "trace_id": trace_id, "span_id": span_id,
               "origin": origin, "client": self.client, "run_id": self.run_id,
               "seed": self.seed}
        rec.update({k: v for k, v in extra.items() if v is not None})
        line = json.dumps(rec, separators=(",", ":"))
        with self._lock:
            self._f.write(line + "\n")
        return rec

    def close(self):
        with self._lock:
            self._f.close()


class Tally(dict):
    """Request counters shared by attack worker threads; add() holds a lock, so no
    increment is lost (dict += is only safe by accident of the GIL)."""

    def __init__(self, *keys):
        super().__init__({k: 0 for k in keys})
        self._lock = threading.Lock()

    def add(self, key):
        with self._lock:
            self[key] += 1


class Pacer:
    """Seeded, jittered waits between requests (no fixed sleep, so the
    inter-request timing is not a giveaway). sleep() waits base * (1 +- jitter),
    uniform. Same rng_seed + worker index -> same sequence of waits."""

    def __init__(self, base, jitter=0.0, rng_seed=None, worker=0):
        self.base, self.jitter = base, max(0.0, min(jitter, 0.95))
        self.rng = random.Random(None if rng_seed is None else rng_seed * 1009 + worker)

    def next(self):
        return self.base * (1 + self.rng.uniform(-self.jitter, self.jitter))

    def sleep(self):
        time.sleep(self.next())


def add_origin_args(parser):
    """--origin-log / --run-id / --seed / --jitter / --rng-seed for every attack script."""
    parser.add_argument("--origin-log", default=None,
                        help="origin.jsonl path (default $ORIGIN_LOG or data/runs/<run_id>/origin.jsonl)")
    parser.add_argument("--run-id", default=None, help="default $SHADOWTRACE_RUN_ID")
    parser.add_argument("--seed", type=int, default=None, help="default $SHADOWTRACE_SEED")
    parser.add_argument("--jitter", type=float, default=0.0,
                        help="random +- share of the pause per request (0 = fixed pause)")
    parser.add_argument("--rng-seed", type=int, default=None,
                        help="seed for the jitter (from the manifest), so waits replay")


def origin_log_from_args(args, client):
    return OriginLog(path=args.origin_log, run_id=args.run_id, seed=args.seed, client=client)


def send(session, method, url, log, origin, log_params=None, max_hops=3, pii=None, **kwargs):
    """Send one request under a fresh client-chosen trace ID and log it.

    `pii` (dict): the personal data this request really sends (ground truth for
    the leakage measurement, e.g. a brute-force username and password); written
    into the origin line of the first hop only. `log_params` (dict) goes into
    the origin line only. Everything in **kwargs (data=, params=, timeout=, ...)
    goes to requests. Follows up to `max_hops` redirects by hand (GET, new ID
    per hop). Returns the final response, or raises the requests exception of
    the hop that failed (that hop is already logged).
    """
    headers = dict(kwargs.pop("headers", None) or {})
    headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    kwargs.setdefault("timeout", 10)
    follow_of = None
    for _ in range(max_hops + 1):
        trace_id, span_id = new_ids()
        headers["traceparent"] = traceparent(trace_id, span_id)
        log.write(trace_id, span_id, origin, method=method, path=urlsplit(url).path,
                  params=log_params, follow_of=follow_of, pii=pii if follow_of is None else None)
        r = session.request(method, url, headers=headers, allow_redirects=False, **kwargs)
        if not r.is_redirect:
            return r
        # the redirect target is a separate request with its own trace
        url = urljoin(url, r.headers["Location"])
        method, follow_of = "GET", trace_id
        kwargs.pop("data", None)
        kwargs.pop("json", None)
        kwargs.pop("params", None)
    return r


def merge_k6_console(console_file, origin_path):
    """Append the ORIGIN lines k6 printed (k6 cannot write files itself) to the
    run's origin.jsonl. Returns the number of lines merged. Lines that are not
    valid JSON records with a trace_id are skipped and counted."""
    if not os.path.exists(console_file):
        raise SystemExit(f"[origin] {console_file} does not exist: k6 never wrote its "
                         f"console log (did k6 start? see k6_stdout.log next to it)")
    merged = bad = 0
    with open(console_file, encoding="utf-8") as src, \
            open(origin_path, "a", encoding="utf-8") as dst:
        for line in src:
            line = line.strip()
            if not line.startswith("ORIGIN "):
                continue
            try:
                rec = json.loads(line[len("ORIGIN "):])
                assert rec.get("trace_id") and rec.get("origin")
            except (ValueError, AssertionError):
                bad += 1
                continue
            dst.write(json.dumps(rec, separators=(",", ":")) + "\n")
            merged += 1
    if bad:
        print(f"[origin] skipped {bad} malformed k6 ORIGIN lines")
    return merged


if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser(description="origin-log utilities")
    sub = p.add_subparsers(dest="cmd", required=True)
    m = sub.add_parser("merge-k6", help="append k6 console ORIGIN lines to origin.jsonl")
    m.add_argument("console_file")
    m.add_argument("origin_log")
    a = p.parse_args()
    if a.cmd == "merge-k6":
        print(f"[origin] merged {merge_k6_console(a.console_file, a.origin_log)} k6 lines "
              f"-> {a.origin_log}")
