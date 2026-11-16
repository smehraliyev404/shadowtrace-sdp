"""Feature builder: harvested traces -> labelled Parquet tables per content level.

    ./venv/bin/python scripts/build_features.py --run-id run_01
    ./venv/bin/python scripts/build_features.py --run-id run_01 run_02 --workers 8
    ./venv/bin/python scripts/build_features.py --run-id run_01 --max-traces 2000   # quick test

Per run, from data/raw_traces/<run>/ and data/runs/<run>/origin.jsonl:

  1. assemble each trace; drop background traces (health checks, exporter
     self-traces); join the rest to the origin log by trace ID (the label)
  2. repair orphan spans: a span whose parent is missing, other than the entry
     span, gets the span of another service whose interval encloses it (latest
     start wins); unrepaired ones stay roots with caller "unknown"
  3. edges: caller service -> callee service for every cross-service call; the
     entry span gets caller "client"; client spans without a traced callee get
     the database system ("redis"), the gRPC service, or "external"
  4. 60 s windows by the entry span's start; per window the edge list (raw
     statistics), node and window features and labels for k = 1, 3, 5, 10:
     for each attack type, 0 traces -> normal, >= k -> that attack,
     1..k-1 -> excluded; two attack types >= k -> excluded
  5. content levels L0 / L1 / L2 (redact.py)

Output, data/features/<run>/<level>/:

  spans.parquet    one row per span: structure, timing, status; L0 and L1 also
                   `attrs` (JSON object of the span attributes and log fields,
                   raw at L0, redacted at L1); L2 has no attributes
  traces.parquet   one row per trace: shape, timing, status, pattern, label
  windows.parquet  one row per window: `edges` and `nodes` (lists of structs),
                   window features, attack counts, labels per k

traces.parquet and the edge features use structure and timing only, so they
are the same at every level. Each window node also carries six content
features computed from that level's span attributes (CONTENT_FEATURES; all 0
at L2, which has no attributes), so the same model sees less content as
redaction gets stronger.
Edge statistics are raw (counts, latencies in microseconds, error shares);
normalisation and "seen in training" depend on the run split and are fitted
on training runs only (edge_norm.py).

Writes data/features/<run>/build_report.json (counts, labels, redaction
statistics and a residual-leak audit of L1). Raw traces are not modified.
"""

import argparse
import collections
import glob
import hashlib
import json
import math
import multiprocessing as mp
import os
import re
import sys
import time
import urllib.parse

import numpy as np
import pandas as pd
import pyarrow as pa
import pyarrow.parquet as pq

from check_origin_match import is_background, norm, root_of
from leakage_check import detect
from redact import ALLOW_HEADERS, ALLOW_KEYS, CARD_CANDIDATE, FORM, PATTERNS, PII_NAME, Redactor, fingerprint, load_key, luhn_ok

HMAC_TOKEN = re.compile(r"H_[a-p]{16}")

# ---- content features (per span, then per node and window); see PLAN.md Phase 5
CONTENT_FEATURES = ("c_inject", "c_url_param", "c_ids_log", "c_paths_log", "c_resp_log", "c_redacted")
REQUEST_KEYS = ("url.path", "http.target", "url.query", "http.url", "url.full", "http.request.body")
INJECT = re.compile(r"'|--|;|/\*|\b(union|select|drop|insert|waitfor|sleep)\b|\bor\s+'?\d|\.\./|/etc/", re.I)
URL_PARAM = re.compile(r"=\s*(https?|ftp|file|gopher)://", re.I)
ID_SEGMENTS = {"enduser", "username", "userid", "login", "session", "sessionid"}
PLACEHOLDER = re.compile(r"^\[\w+\]$")
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
WINDOW_S = 60
KS = (1, 3, 5, 10)
ATTACKS = ("http_flood", "exfiltration", "sqli_probe", "brute_force",
           "session_rotation_brute", "slow_brute", "ssrf_probe", "lateral_movement")
LEVELS = ("L0", "L1", "L2")

GRPC_CODES = {"OK": 0, "CANCELLED": 1, "UNKNOWN": 2, "INVALID_ARGUMENT": 3,
              "DEADLINE_EXCEEDED": 4, "NOT_FOUND": 5, "ALREADY_EXISTS": 6,
              "PERMISSION_DENIED": 7, "RESOURCE_EXHAUSTED": 8, "FAILED_PRECONDITION": 9,
              "ABORTED": 10, "OUT_OF_RANGE": 11, "UNIMPLEMENTED": 12, "INTERNAL": 13,
              "UNAVAILABLE": 14, "DATA_LOSS": 15, "UNAUTHENTICATED": 16}
GRPC_CLIENT = {1, 3, 5, 6, 7, 9, 11, 16}
CLASS_RANK = {"": 0, "ok": 1, "client": 2, "server": 3}

SPAN_COLS = [("trace_id", pa.string()), ("span_id", pa.string()), ("parent_id", pa.string()),
             ("service", pa.string()), ("operation", pa.string()), ("kind", pa.string()),
             ("start_us", pa.int64()), ("duration_us", pa.int64()),
             ("status_code", pa.string()), ("status_class", pa.string()),
             ("repaired", pa.bool_())]
SCHEMA_L2 = pa.schema(SPAN_COLS)
SCHEMA_ATTRS = pa.schema(SPAN_COLS + [("attrs", pa.string())])


# ---------------------------------------------------------------- span helpers


def content_of(attrs):
    """One span's content signals from its (raw or redacted) attributes:
    (injection marker, URL inside a parameter, identity value, request path,
    response bytes, share of values redacted). Request values are URL-decoded
    first; placeholders such as "[removed]" are not identities."""
    req = " ".join(urllib.parse.unquote_plus(str(attrs[k])) for k in REQUEST_KEYS if attrs.get(k))
    ident = None
    for k, v in attrs.items():
        if set(re.split(r"[._\-]+", k.lower())) & ID_SEGMENTS and v and not PLACEHOLDER.match(str(v)):
            ident = str(v)
            break
    path = attrs.get("url.path") or attrs.get("http.target") or ""
    path = urllib.parse.unquote_plus(str(path)).split("?")[0] or None
    resp = attrs.get("http.response.body.size")
    try:
        resp = float(resp) if resp not in (None, "") else None
    except (TypeError, ValueError):
        resp = None
    vals = [str(v) for v in attrs.values() if v not in (None, "")]
    red = sum(bool(PLACEHOLDER.match(v)) or bool(HMAC_TOKEN.fullmatch(v)) for v in vals)
    return (bool(INJECT.search(req)), bool(URL_PARAM.search(req)), ident, path, resp,
            red / len(vals) if vals else 0.0)

def status_of(tags):
    """(code, class) of one span; class in ok / client / server, "" if unknown."""
    found = []
    for k in ("http.response.status_code", "http.status_code"):
        if k in tags:
            try:
                n = int(tags[k])
                found.append((str(n), "server" if n >= 500 else "client" if n >= 400 else "ok"))
            except ValueError:
                pass
    for k in ("rpc.grpc.status_code", "grpc.status_code", "rpc.response.status_code"):
        if k not in tags:
            continue
        v = str(tags[k]).strip().upper()
        if v.startswith("CODE(") and v.endswith(")"):
            v = v[5:-1]
        n = int(v) if v.lstrip("-").isdigit() else GRPC_CODES.get(v)
        if n is None:
            continue
        if n >= 400:                       # application code in HTTP terms
            found.append((str(n), "server" if n >= 500 else "client"))
        else:
            found.append((f"grpc:{n}", "ok" if n == 0 else "client" if n in GRPC_CLIENT else "server"))
    if str(tags.get("otel.status_code", "")).upper() == "ERROR" and not any(c != "ok" for _, c in found):
        found.append(("ERROR", "server"))
    if not found:
        return "", ""
    return max(found, key=lambda x: CLASS_RANK[x[1]])


def leaf_target(tags, op):
    """Callee of a client span that has no traced child in another service."""
    if tags.get("db.system"):
        return str(tags["db.system"])
    rpc = str(tags.get("rpc.service") or tags.get("rpc.method") or (op if "/" in op else ""))
    rpc = rpc.lstrip("/").split("/")[0]
    if rpc.startswith("hipstershop."):
        return rpc.split(".", 1)[1].lower()
    if any(k in tags for k in ("http.method", "http.request.method", "http.url", "url.full")):
        return "external"
    return None


def pattern_sig(spans, kids, roots):
    def sig(s):
        return f"{s['svc']}:{s['op']}(" + ",".join(sorted(sig(c) for c in kids[s['id']])) + ")"
    return hashlib.sha1("|".join(sorted(sig(r) for r in roots)).encode()).hexdigest()[:12]


def known_values(items):
    """Personal values in raw attributes, for the residual-leak audit:
    detector matches plus whole values under personal-data names."""
    out = []
    for key, val in items:
        v = "" if val is None else str(val)
        if not v or key in ALLOW_KEYS:
            continue
        text = urllib.parse.unquote_plus(v)
        for kind, rx, _ in PATTERNS:
            if kind in ("ip", "traceparent"):
                continue
            out += [(m.group(), kind) for m in rx.finditer(text)]
        out += [(c, "card") for c in CARD_CANDIDATE.findall(text) if luhn_ok(c)]
        name = key.rsplit(".", 1)[-1] if key.startswith("http.request.header.") else key
        if name in ALLOW_HEADERS and name != key:
            continue
        if key in ("url.query", "http.request.body") or FORM.match(v) or name == "cookie":
            sep = "; " if name == "cookie" else "&"
            for part in v.split(sep):
                k, eq, pv = part.partition("=")
                pv = urllib.parse.unquote_plus(pv)
                if eq and PII_NAME.search(k) and pv:
                    out.append((pv, "named:" + k))
        elif PII_NAME.search(name):
            out.append((text, "named:" + name))
    return out


# ---------------------------------------------------------------- worker

_ORIGIN = {}
_RED = None
_LEVELS = LEVELS


def _init(origin, key, levels):
    global _ORIGIN, _RED, _LEVELS
    _ORIGIN, _RED, _LEVELS = origin, Redactor(key), levels


def process(path):
    t = json.load(open(path, encoding="utf-8"))
    tid = norm(t["traceID"])
    root = root_of(t)
    if is_background(root):
        return ("background", root[:2])
    o = _ORIGIN.get(tid)
    if o is None:
        return ("unmatched", root[:2])

    procs = t.get("processes") or {}
    spans = []
    for sp in t.get("spans", []):
        tags = {tg.get("key"): tg.get("value") for tg in sp.get("tags") or []}
        items = [(tg.get("key"), tg.get("value")) for tg in sp.get("tags") or []]
        items += [("log:" + fl.get("key", ""), fl.get("value"))
                  for lg in sp.get("logs") or [] for fl in lg.get("fields") or []]
        parents = [r["spanID"] for r in sp.get("references") or [] if r.get("refType") == "CHILD_OF"]
        code, cls = status_of(tags)
        spans.append({"id": sp["spanID"], "parent": parents[0] if parents else None,
                      "svc": (procs.get(sp.get("processID")) or {}).get("serviceName", "?"),
                      "op": sp.get("operationName", "?"), "kind": str(tags.get("span.kind", "")),
                      "start": int(sp.get("startTime", 0)), "dur": int(sp.get("duration", 0)),
                      "code": code, "cls": cls, "tags": tags, "items": items, "repaired": False})
    by_id = {s["id"]: s for s in spans}
    roots = [s for s in spans if s["parent"] not in by_id]
    n_roots = len(roots)
    entry = min(roots, key=lambda s: s["start"]) if roots else min(spans, key=lambda s: s["start"])

    # orphan repair: enclosing span of another service, latest start
    for s in roots:
        if s is entry:
            continue
        cands = [p for p in spans if p is not s and p["svc"] != s["svc"]
                 and p["start"] <= s["start"] and p["start"] + p["dur"] >= s["start"] + s["dur"]]
        if cands:
            best = max(cands, key=lambda p: (p["start"], p["kind"] == "client"))
            s["parent"], s["repaired"] = best["id"], True
    for s in spans:
        if s is not entry and s["parent"] not in by_id:
            s["parent"] = None
    if entry["parent"] not in by_id:
        entry["parent"] = None

    kids = collections.defaultdict(list)
    for s in spans:
        if s["parent"]:
            kids[s["parent"]].append(s)

    # edges: (src, dst, duration_us, status class)
    edges = []
    for s in spans:
        p = by_id.get(s["parent"]) if s["parent"] else None
        if s is entry:
            edges.append(("client", s["svc"], s["dur"], s["cls"]))
        elif p is None:
            edges.append(("unknown", s["svc"], s["dur"], s["cls"]))
        elif p["svc"] != s["svc"]:
            edges.append((p["svc"], s["svc"], s["dur"], s["cls"] or p["cls"]))
        if s["kind"] == "client" and not any(c["svc"] != s["svc"] for c in kids[s["id"]]):
            dst = leaf_target(s["tags"], s["op"])
            if dst:
                edges.append((s["svc"], dst, s["dur"], s["cls"]))

    def depth(s):
        d = 1
        while s["parent"] and d < 256:
            s, d = by_id[s["parent"]], d + 1
        return d

    start = min(s["start"] for s in spans)
    end = max(s["start"] + s["dur"] for s in spans)
    top = [s for s in spans if not s["parent"]]
    trace = {
        "trace_id": tid, "ts_client": o["ts"], "start_us": entry["start"],
        "duration_us": end - start, "n_spans": len(spans),
        "n_services": len({s["svc"] for s in spans}), "n_calls": len(edges),
        "depth": max(depth(s) for s in spans), "n_roots": n_roots,
        "n_repaired": sum(s["repaired"] for s in spans),
        "pattern": pattern_sig(spans, kids, top),
        "root_service": entry["svc"], "root_operation": entry["op"],
        "root_status_code": entry["code"], "root_status_class": entry["cls"],
        "n_client_err": sum(e[3] == "client" for e in edges),
        "n_server_err": sum(e[3] == "server" for e in edges),
        "label": o["origin"], "client": o.get("client", ""), "source": o.get("source") or "",
    }
    l2 = [(tid, s["id"], s["parent"] or "", s["svc"], s["op"], s["kind"], s["start"], s["dur"],
           s["code"], s["cls"], s["repaired"]) for s in spans]

    out = {"trace": trace, "edges": edges, "spans_l2": l2, "op_hits": 0}
    for s in spans:                       # operation names must carry no personal data
        _RED.stats = {}
        if _RED._detect(s["op"])[1]:
            out["op_hits"] += 1
    if "L0" in _LEVELS:
        raw = [{k: (v if isinstance(v, (int, float, bool)) or v is None else str(v)) for k, v in s["items"]}
               for s in spans]
        out["attrs_l0"] = [json.dumps(r, ensure_ascii=False) for r in raw]
        out["content_l0"] = [content_of(r) for r in raw]
    if "L1" in _LEVELS:
        _RED.stats = {}
        red = [_RED.attrs(s["items"]) for s in spans]
        out["attrs_l1"] = [json.dumps(r, ensure_ascii=False) for r in red]
        out["content_l1"] = [content_of(r) for r in red]
        out["red_stats"] = dict(_RED.stats)
        l1_text = "\n".join(v for r in red for v in r.values())
        audit_total, audit_leak, short = collections.Counter(), collections.Counter(), 0
        seen = set()
        for s in spans:
            for val, kind in known_values(s["items"]):
                kind = kind.split(":")[0]
                if (val, kind) in seen:
                    continue
                seen.add((val, kind))
                if len(val) < 4:
                    short += 1
                    continue
                audit_total[kind] += 1
                audit_leak[kind] += val in l1_text
        # HMAC tokens removed first: "shop_session-id=H_..." would match the cookie detector
        det = collections.Counter(k for r in red for v in r.values()
                                  for k in detect(HMAC_TOKEN.sub("", v)))
        out["audit"] = (dict(audit_total), dict(audit_leak), short, dict(det))
    return ("ok", out)


# ---------------------------------------------------------------- windows

def build_windows(traces, edges, spans_l2, t0):
    tw = traces.set_index("trace_id")["window"]
    n_win = int(traces["window"].max()) + 1

    e = edges.copy()
    e["window"] = e["trace_id"].map(tw)
    g = e.groupby(["window", "src", "dst"])
    est = g.agg(count=("dur_us", "size"),
                lat_p50_us=("dur_us", "median"),
                lat_p95_us=("dur_us", lambda x: float(np.percentile(x, 95))),
                client_err=("cls", lambda x: float((x == "client").mean())),
                server_err=("cls", lambda x: float((x == "server").mean()))).reset_index()
    prev = est[["window", "src", "dst", "count"]].copy()
    prev["window"] += 1
    est = est.merge(prev.rename(columns={"count": "prev_count"}), on=["window", "src", "dst"], how="left")
    est["prev_count"] = est["prev_count"].fillna(0).astype(int)
    est["d_log_count"] = np.log1p(est["count"]) - np.log1p(est["prev_count"])

    s = spans_l2.copy()
    s["window"] = s["trace_id"].map(tw)
    s["err"] = s["status_class"].isin(["client", "server"])
    s["server_dur"] = s["duration_us"].where(s["kind"] == "server")
    nst = s.groupby(["window", "service"]).agg(
        n_spans=("span_id", "size"), n_server=("kind", lambda x: int((x == "server").sum())),
        err_share=("err", "mean"), server_p50_us=("server_dur", "median")).reset_index()
    nst["server_p50_us"] = nst["server_p50_us"].fillna(0.0)

    first, last = traces["start_us"].min() / 1e6, traces["start_us"].max() / 1e6
    rows = []
    for w in range(n_win):
        tw_ = traces[traces["window"] == w]
        ew = est[est["window"] == w]
        nw = nst[nst["window"] == w]
        calls = e[e["window"] == w]
        counts = {a: int((tw_["label"] == a).sum()) for a in ATTACKS}
        row = {"window": w, "t_start": t0 + w * WINDOW_S,
               "complete": bool(t0 + w * WINDOW_S >= first and t0 + (w + 1) * WINDOW_S <= last),
               "n_traces": len(tw_), "n_spans": int(nw["n_spans"].sum()), "n_calls": len(calls),
               "n_edges": len(ew), "n_patterns": int(tw_["pattern"].nunique()),
               "client_err": float((calls["cls"] == "client").mean()) if len(calls) else 0.0,
               "server_err": float((calls["cls"] == "server").mean()) if len(calls) else 0.0,
               "trace_p50_us": float(tw_["duration_us"].median()) if len(tw_) else 0.0,
               "trace_p95_us": float(np.percentile(tw_["duration_us"], 95)) if len(tw_) else 0.0}
        row.update({f"n_{a}": c for a, c in counts.items()})
        row["n_normal"] = int((tw_["label"] == "normal").sum())
        for k in KS:
            hit = [a for a, c in counts.items() if c >= k]
            amb = [a for a, c in counts.items() if 0 < c < k]
            row[f"label_k{k}"] = ("excluded" if amb or len(hit) > 1 else hit[0] if hit else "normal")
        row["edges"] = ew.drop(columns=["window"]).to_dict("records")
        row["nodes"] = nw.drop(columns=["window"]).to_dict("records")
        rows.append(row)
    return pd.DataFrame(rows)


def add_content(win, traces, content):
    """Merge per-(window, service) content features into each window's nodes.
    content: DataFrame (trace_id, service, inject, url_param, ident, path, resp,
    redacted) for one level, or None (L2: every content feature is 0)."""
    win = win.copy()
    if content is None or content.empty:
        win["nodes"] = [[{**n, **{f: 0.0 for f in CONTENT_FEATURES}} for n in nodes] for nodes in win["nodes"]]
        return win
    c = content.copy()
    c["window"] = c["trace_id"].map(traces.set_index("trace_id")["window"])
    g = c.groupby(["window", "service"]).agg(
        c_inject=("inject", "mean"), c_url_param=("url_param", "mean"),
        ids=("ident", "nunique"), paths=("path", "nunique"),
        resp=("resp", "mean"), c_redacted=("redacted", "mean"))
    g["c_ids_log"] = np.log1p(g["ids"])
    g["c_paths_log"] = np.log1p(g["paths"])
    g["c_resp_log"] = np.log1p(g["resp"].fillna(0.0))
    feats = {k: {f: float(v[f]) for f in CONTENT_FEATURES} for k, v in g.iterrows()}
    zero = {f: 0.0 for f in CONTENT_FEATURES}
    win["nodes"] = [[{**n, **feats.get((w, n["service"]), zero)} for n in nodes]
                    for w, nodes in zip(win["window"], win["nodes"])]
    return win


# ---------------------------------------------------------------- main

def write_table(df, path):
    pq.write_table(pa.Table.from_pandas(df, preserve_index=False), path, compression="zstd")


def build_run(run_id, a, key):
    t_begin = time.time()
    raw = os.path.join(a.raw_dir, run_id)
    files = sorted(glob.glob(os.path.join(raw, "trace_*.json")))
    if a.max_traces:
        files = files[:a.max_traces]
    if not files:
        sys.exit(f"[features] {run_id}: no traces in {raw}")
    origin = {}
    for line in open(os.path.join(a.runs_dir, run_id, "origin.jsonl"), encoding="utf-8"):
        r = json.loads(line)
        origin[norm(r["trace_id"])] = {k: r.get(k) for k in ("ts", "origin", "client", "source")}
    manifest = json.load(open(os.path.join(a.runs_dir, run_id, "manifest.json")))

    out_root = os.path.join(a.out_dir, run_id)
    tmp_root = out_root + ".partial"
    for lv in a.levels:
        os.makedirs(os.path.join(tmp_root, lv), exist_ok=True)
    writers = {lv: pq.ParquetWriter(os.path.join(tmp_root, lv, "spans.parquet"),
                                    SCHEMA_L2 if lv == "L2" else SCHEMA_ATTRS, compression="zstd")
               for lv in a.levels}
    buf = {lv: [] for lv in a.levels}

    def flush(force=False):
        for lv in a.levels:
            if buf[lv] and (force or len(buf[lv]) >= 200_000):
                cols = list(zip(*buf[lv]))
                schema = writers[lv].schema
                writers[lv].write_table(pa.Table.from_arrays(
                    [pa.array(c, type=f.type) for c, f in zip(cols, schema)], schema=schema))
                buf[lv] = []

    traces, edges, spans_l2 = [], [], []
    content = {lv: [] for lv in a.levels if lv != "L2"}
    dropped = collections.Counter()
    dropped_roots = collections.defaultdict(collections.Counter)
    red_stats, a_total, a_leak = collections.Counter(), collections.Counter(), collections.Counter()
    short, op_hits = 0, 0
    det_hits = collections.Counter()

    with mp.Pool(a.workers, initializer=_init, initargs=(origin, key, tuple(a.levels))) as pool:
        for i, (status, res) in enumerate(pool.imap_unordered(process, files, chunksize=32), 1):
            if status != "ok":
                dropped[status] += 1
                dropped_roots[status][" ".join(res)] += 1
                continue
            traces.append(res["trace"])
            tid = res["trace"]["trace_id"]
            edges += [(tid,) + e for e in res["edges"]]
            spans_l2 += res["spans_l2"]
            for lv in content:
                content[lv] += [(r[0], r[3]) + c for r, c in zip(res["spans_l2"], res["content_" + lv.lower()])]
            op_hits += res["op_hits"]
            for lv in a.levels:
                if lv == "L2":
                    buf[lv] += res["spans_l2"]
                else:
                    buf[lv] += [r + (x,) for r, x in zip(res["spans_l2"], res["attrs_" + lv.lower()])]
            if "red_stats" in res:
                red_stats.update(res["red_stats"])
                at, al, sh, dh = res["audit"]
                a_total.update(at)
                a_leak.update(al)
                det_hits.update(dh)
                short += sh
            flush()
            if i % 5000 == 0:
                print(f"[features] {run_id}: {i}/{len(files)} traces", flush=True)
    flush(force=True)
    for w in writers.values():
        w.close()

    tr = pd.DataFrame(traces)
    t0 = math.floor(tr["start_us"].min() / 1e6)
    tr["window"] = ((tr["start_us"] / 1e6 - t0) // WINDOW_S).astype(int)
    tr.insert(0, "run_id", run_id)
    tr.insert(1, "run_kind", manifest.get("kind", ""))
    tr = tr.sort_values("start_us").reset_index(drop=True)
    ed = pd.DataFrame(edges, columns=["trace_id", "src", "dst", "dur_us", "cls"])
    sp = pd.DataFrame(spans_l2, columns=[c for c, _ in SPAN_COLS])
    win = build_windows(tr, ed, sp, t0)
    win.insert(0, "run_id", run_id)
    win.insert(1, "run_kind", manifest.get("kind", ""))

    ccols = ["trace_id", "service", "inject", "url_param", "ident", "path", "resp", "redacted"]
    content_check = {}
    for lv in a.levels:
        cdf = pd.DataFrame(content[lv], columns=ccols) if lv in content else None
        write_table(tr, os.path.join(tmp_root, lv, "traces.parquet"))
        write_table(add_content(win, tr, cdf), os.path.join(tmp_root, lv, "windows.parquet"))
        if cdf is not None:      # sanity: content signals per trace label
            m = cdf.merge(tr[["trace_id", "label"]], on="trace_id")
            content_check[lv] = {lab: {"spans_with_injection_marker": int(x["inject"].sum()),
                                       "spans_with_url_param": int(x["url_param"].sum()),
                                       "distinct_identities": int(x["ident"].nunique())}
                                 for lab, x in m.groupby("label")}

    labels = tr["label"].value_counts().to_dict()
    report = {
        "run_id": run_id, "run_kind": manifest.get("kind"), "seed": manifest.get("seed"),
        "test_run": manifest.get("test_run"), "levels": list(a.levels),
        "window_s": WINDOW_S, "t0": t0, "files": len(files),
        "traces_kept": len(tr), "spans_kept": len(sp),
        "dropped": dict(dropped),
        "dropped_by_root": {k: dict(v.most_common(10)) for k, v in dropped_roots.items()},
        "partial_traces": int((tr["n_roots"] > 1).sum()),
        "repaired_spans": int(tr["n_repaired"].sum()),
        "unknown_caller_calls": int((ed["src"] == "unknown").sum()),
        "labels": labels,
        "origin_lines": len(origin),
        "edges_distinct": sorted({f"{s}->{d}" for s, d in zip(ed["src"], ed["dst"])}),
        "windows": len(win), "windows_complete": int(win["complete"].sum()),
        "window_labels": {f"k{k}": win[f"label_k{k}"].value_counts().to_dict() for k in KS},
        "operation_names_with_personal_data": op_hits,
        "hmac_key_fingerprint": fingerprint(key),
        "content_by_label": content_check,
        "seconds": round(time.time() - t_begin, 1),
    }
    if "L1" in a.levels:
        report["l1_redactions"] = dict(red_stats)
        report["l1_audit"] = {
            "method": "personal values found in L0 (detectors + personal-data names), "
                      "searched in the same trace's L1 attributes",
            "values_checked": dict(a_total), "values_still_present": dict(a_leak),
            "skipped_shorter_than_4": short,
            "leakage_detector_hits_in_l1": dict(det_hits),
            "recall": round(1 - sum(a_leak.values()) / sum(a_total.values()), 5) if a_total else None,
        }
    json.dump(report, open(os.path.join(tmp_root, "build_report.json"), "w"), indent=2)
    if os.path.exists(out_root):
        import shutil
        shutil.rmtree(out_root)
    os.replace(tmp_root, out_root)
    return report


def main():
    p = argparse.ArgumentParser(description="harvested traces -> labelled Parquet per content level")
    p.add_argument("--run-id", nargs="+", required=True)
    p.add_argument("--raw-dir", default=os.path.join(PROJECT_ROOT, "data", "raw_traces"))
    p.add_argument("--runs-dir", default=os.path.join(PROJECT_ROOT, "data", "runs"))
    p.add_argument("--out-dir", default=os.path.join(PROJECT_ROOT, "data", "features"))
    p.add_argument("--levels", default="L0,L1,L2")
    p.add_argument("--workers", type=int, default=max(1, (os.cpu_count() or 2) - 1))
    p.add_argument("--max-traces", type=int, default=0, help="0 = all (testing only)")
    a = p.parse_args()
    a.levels = [lv for lv in a.levels.split(",") if lv]
    if set(a.levels) - set(LEVELS):
        sys.exit(f"unknown level in {a.levels}")
    key = load_key(os.path.join(a.out_dir, "hmac.key"))
    for run_id in a.run_id:
        r = build_run(run_id, a, key)
        print(f"[features] {run_id}: {r['traces_kept']} traces, {r['spans_kept']} spans, "
              f"{r['windows']} windows ({r['windows_complete']} complete), dropped {r['dropped']}, "
              f"{r['seconds']} s")
        print(f"  labels: {r['labels']}")
        print(f"  windows k=3: {r['window_labels']['k3']}")
        if "l1_audit" in r:
            au = r["l1_audit"]
            print(f"  L1 audit: recall {au['recall']}, still present "
                  f"{ {k: v for k, v in au['values_still_present'].items() if v} }, "
                  f"leakage detector hits {au['leakage_detector_hits_in_l1']}")
        if r["operation_names_with_personal_data"]:
            print(f"  WARNING: {r['operation_names_with_personal_data']} operation names match a detector")


if __name__ == "__main__":
    main()
