# ShadowTrace: ETL from one collected run into MongoDB.
#
# The collection pipeline (k6 + scripts/orchestrator.py + scripts/harvest_traces.py,
# tied together by collect_run.sh) organizes everything by run_id:
#   data/raw_traces/<run_id>/trace_*.json   - every trace harvested during that run
#   data/runs/<run_id>.json                 - the burst log (attack ground-truth
#                                              labels: attack_type + start/end unix
#                                              timestamps), only present for attack
#                                              runs - a pure `--normal` run has none.
#
# One run mixes normal traffic with (usually) several different attack bursts,
# so the label is decided PER TRACE here, by checking whether that trace's
# start time falls inside one of the run's burst windows - not per folder like
# the old flat data/raw_traces/*.json layout this script used to assume.
#
# Retention, same rule as before, now applied per-trace instead of per-batch:
#   - "normal": retention_class=temporary, no payload embedded (only a
#     source_ref), expires in NORMAL_RETENTION_DAYS, and the majority class is
#     downsampled to --sample-size representative traces.
#   - any attack type: retention_class=long_term_attack, expires_at=null
#     (never auto-deleted), full payload embedded, never downsampled.
#
# The four real ST-GNN detection signals (path entropy, causal-history
# distance, temporal jitter, call repetition) require windowing across many
# requests over time - they can't be computed from one trace in isolation.
# The feature_vector written here is a placeholder: basic per-trace graph
# statistics, useful for sanity checks and class-balance bookkeeping, not the
# final training features.
#
# Usage:
#   python ingest_traces.py --run-id run_04 --split train
#   python ingest_traces.py --run-id run_01 --split test      # a --normal run
#   python ingest_traces.py --run-id run_04 --delete-after    # actually delete processed normal files
# Dry-run (report only, nothing deleted) is the default. Deletion never
# touches attack-class files, and never touches files skipped by downsampling
# (they were never opened long enough to know they were excess - only files
# actually parsed and stored are eligible).

import argparse
import json
import os
import random
import sys
from collections import Counter
from datetime import datetime, timezone
from uuid import uuid4

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, PROJECT_ROOT)

from analytics.parse_traces import parse_single_trace_json  # noqa: E402
from mongo_client import get_database  # noqa: E402
from setup_database import ATTACK_TYPES, compute_retention  # noqa: E402

RAW_TRACES_DIR = os.getenv("RAW_TRACES_DIR", os.path.join(PROJECT_ROOT, "data", "raw_traces"))
RUNS_DIR = os.getenv("RUNS_DIR", os.path.join(PROJECT_ROOT, "data", "runs"))
DEFAULT_NORMAL_SAMPLE_SIZE = 5000


def load_burst_windows(run_id):
    """Returns [(attack_type, start_ts, end_ts), ...] in unix seconds, or [] if
    this run has no burst log (a pure `--normal` collect_run.sh run)."""
    path = os.path.join(RUNS_DIR, f"{run_id}.json")
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8") as f:
        run_record = json.load(f)
    return [
        (b["attack_type"], b["start_ts"], b["end_ts"])
        for b in run_record.get("attack_bursts", [])
    ]


def label_for(trace_start_unix, burst_windows):
    for attack_type, start_ts, end_ts in burst_windows:
        if start_ts <= trace_start_unix <= end_ts:
            return attack_type
    return "normal"


def peek_trace_start_unix(json_path):
    """Cheap read: just enough to get the trace's earliest span start time, so
    we can decide its label (and whether downsampling skips it) before paying
    for the full pandas/networkx parse in build_graph_doc."""
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except (json.JSONDecodeError, OSError):
        return None
    starts = [s.get("startTime", 0) for s in data.get("spans", [])]
    if not starts:
        return None
    return min(starts) / 1_000_000.0  # microseconds -> unix seconds


def build_graph_doc(json_path, trial_id, label):
    """Parses one raw trace file into a structural graphs document (no payload)."""
    df_spans, df_edges = parse_single_trace_json(json_path)
    if df_spans.empty:
        return None

    trace_id = df_spans["trace_id"].iloc[0]
    timestamp_us = df_spans["start_time"].min()
    timestamp = datetime.fromtimestamp(timestamp_us / 1_000_000.0, tz=timezone.utc)

    nodes = [
        {"node_id": name, "service_name": name}
        for name in sorted(df_spans["service_name"].unique().tolist())
    ]

    edges = []
    if not df_edges.empty:
        grouped = df_edges.groupby(["parent_service", "child_service"])["edge_latency_ms"]
        for (parent, child), latencies in grouped:
            edges.append(
                {
                    "from": parent,
                    "to": child,
                    "latency_ms": round(float(latencies.mean()), 3),
                    "latency_zscore": None,  # requires a rolling baseline - not available per-trace
                    "call_count": int(latencies.count()),
                }
            )

    feature_vector = {
        "span_count": int(len(df_spans)),
        "unique_services": int(df_spans["service_name"].nunique()),
        "edge_count": int(len(df_edges)),
        "avg_duration_ms": round(float(df_spans["duration_ms"].mean()), 3),
        "max_duration_ms": round(float(df_spans["duration_ms"].max()), 3),
        "avg_edge_latency_ms": round(float(df_edges["edge_latency_ms"].mean()), 3) if not df_edges.empty else 0.0,
    }

    return {
        "trial_id": trial_id,
        "trace_id": str(trace_id),
        "timestamp": timestamp,
        "nodes": nodes,
        "edges": edges,
        "feature_vector": feature_vector,
        "label": label,
    }


def build_raw_trace_doc(json_path, trial_id, label, captured_at):
    retention_class, expires_at = compute_retention(label, captured_at)
    trace_id = os.path.splitext(os.path.basename(json_path))[0].replace("trace_", "")

    doc = {
        "trace_id": trace_id,
        "trial_id": trial_id,
        "attack_type": label,
        "captured_at": captured_at,
        "source_ref": json_path,
        "trace_payload": None,
        "processing_status": "processed",
        "retention_class": retention_class,
        "expires_at": expires_at,
        "schema_version": 1,
    }

    if retention_class == "long_term_attack":
        with open(json_path, "r", encoding="utf-8") as f:
            doc["trace_payload"] = json.load(f)

    return doc


def captured_at_for(json_path):
    try:
        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        harvested_at = data.get("harvested_at")
        if harvested_at:
            return datetime.fromisoformat(harvested_at.replace("Z", "+00:00"))
    except Exception:
        pass
    return datetime.fromtimestamp(os.path.getmtime(json_path), tz=timezone.utc)


def run(run_id, split_assignment, sample_size, delete_after):
    raw_dir = os.path.join(RAW_TRACES_DIR, run_id)
    if not os.path.isdir(raw_dir):
        raise FileNotFoundError(
            f"No such run directory: {raw_dir}\n"
            f"(expected output of collect_run.sh / harvest_traces.py --run-id {run_id})"
        )

    burst_windows = load_burst_windows(run_id)
    json_files = [entry.path for entry in os.scandir(raw_dir) if entry.name.endswith(".json")]
    print(f"[*] Found {len(json_files)} raw trace files in {raw_dir}")
    if burst_windows:
        attack_names = sorted({b[0] for b in burst_windows})
        print(f"[*] Loaded {len(burst_windows)} attack burst(s) from data/runs/{run_id}.json: {attack_names}")
    else:
        print(f"[*] No burst log for this run - every trace is labeled 'normal'")
    if not json_files:
        return

    # Randomize processing order so the surviving 'normal' sample (once the cap
    # is hit) is representative of the whole run, not just whichever files the
    # filesystem happened to list first.
    rng = random.Random(42)
    rng.shuffle(json_files)

    trial_id = run_id  # one collect_run.sh run = one trial: same cluster state, same time bracket
    database = get_database()

    label_counts = Counter()
    normal_kept = 0
    graphs_inserted = 0
    raw_docs_inserted = 0
    skipped = 0
    to_delete = []
    captured_ats = []

    for path in json_files:
        trace_start_unix = peek_trace_start_unix(path)
        if trace_start_unix is None:
            skipped += 1
            continue

        label = label_for(trace_start_unix, burst_windows)

        # Downsampling only ever applies to 'normal' - every attack-labeled
        # trace is kept in full, regardless of how many there are.
        if label == "normal" and sample_size > 0 and normal_kept >= sample_size:
            continue

        graph_doc = build_graph_doc(path, trial_id, label)
        if graph_doc is None:
            skipped += 1
            continue

        if label == "normal":
            normal_kept += 1
        label_counts[label] += 1

        captured_at = captured_at_for(path)
        captured_ats.append(captured_at)
        raw_doc = build_raw_trace_doc(path, trial_id, label, captured_at)

        database.graphs.insert_one(graph_doc)
        graphs_inserted += 1

        try:
            database.raw_traces.insert_one(raw_doc)
            raw_docs_inserted += 1
        except Exception as e:
            # Most likely a duplicate trace_id from a previous ingestion run.
            print(f"[!] raw_traces insert skipped for {path}: {e}")

        if raw_doc["retention_class"] == "temporary":
            to_delete.append(path)

    if captured_ats:
        attack_labels_present = sorted(set(label_counts) - {"normal"})
        if not attack_labels_present:
            trial_attack_type = "normal"
        elif len(attack_labels_present) == 1:
            trial_attack_type = attack_labels_present[0]
        else:
            trial_attack_type = "mixed"

        trials_doc = {
            "trial_id": trial_id,
            "attack_type": trial_attack_type,
            "attack_types_present": attack_labels_present,
            "platform": "google-online-boutique",
            "feature_condition": "structural-only-placeholder",
            "started_at": min(captured_ats),
            "ended_at": max(captured_ats),
            "split_assignment": split_assignment,
        }
        try:
            database.trials.insert_one(trials_doc)
        except Exception as e:
            print(f"[!] trials insert skipped (already ingested this run?): {e}")

    print("\n" + "=" * 60)
    print("[+] INGESTION COMPLETE")
    print(f"    trial_id: {trial_id}")
    print(f"    graphs inserted: {graphs_inserted}  (by label: {dict(label_counts)})")
    print(f"    raw_traces tracking docs inserted: {raw_docs_inserted}")
    print(f"    skipped (unparseable / empty): {skipped}")
    print(f"    'normal' traces kept: {normal_kept}" + (f" (capped at {sample_size})" if sample_size > 0 else " (no cap)"))
    print("=" * 60)

    if to_delete:
        if delete_after:
            for path in to_delete:
                os.remove(path)
            print(f"[+] Deleted {len(to_delete)} processed 'normal' source files (--delete-after)")
        else:
            print(
                f"[*] Dry run: {len(to_delete)} 'normal' source files are safely parsed and would "
                f"be deleted. Re-run with --delete-after to actually remove them."
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShadowTrace: ingest one collected run into MongoDB")
    parser.add_argument("--run-id", required=True, help="e.g. run_04 (matches data/raw_traces/<run_id>/)")
    parser.add_argument(
        "--split",
        default="train",
        choices=["train", "test"],
        help="Trial-level train/test split assignment for this whole run. Split at the "
        "run/trial level, never per-trace - see Ma (2026)'s leakage finding.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=DEFAULT_NORMAL_SAMPLE_SIZE,
        help=f"Cap on how many 'normal' traces to keep from this run (default {DEFAULT_NORMAL_SAMPLE_SIZE}, "
        f"0 = no cap). Never applied to attack-labeled traces.",
    )
    parser.add_argument(
        "--delete-after",
        action="store_true",
        help="Actually delete source files once safely parsed (normal-labeled only). Default is dry-run.",
    )
    args = parser.parse_args()

    run(
        run_id=args.run_id,
        split_assignment=args.split,
        sample_size=args.sample_size,
        delete_after=args.delete_after,
    )
