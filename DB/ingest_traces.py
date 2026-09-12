# ShadowTrace: batch ETL from harvested raw trace JSON files into MongoDB.
#
# Why this exists: raw trace JSON is bulky (the team currently has ~400k
# files / ~30GB from repeated k6 harvest runs) and MongoDB Atlas's free
# tier is 512MB, so the raw payloads are never bulk-loaded into Mongo.
# Instead this script parses each trace file into a small structural
# "graphs" document (nodes/edges/basic stats, no payload - a few KB each)
# and writes a lightweight tracking document to "raw_traces". Only that
# tracking document's retention differs by class:
#   - "normal" traces: retention_class=temporary, TTL-expires in
#     NORMAL_RETENTION_DAYS (see setup_database.py), no payload embedded.
#   - any attack class: retention_class=long_term_attack, expires_at=null
#     (kept forever), and the raw payload IS embedded since attacks are
#     the rare, evidentiary class this whole project is measured against.
#
# The four real ST-GNN detection signals (path entropy, causal-history
# distance, temporal jitter, call repetition) require windowing across
# MANY requests over time - they cannot be computed from one trace in
# isolation. The feature_vector written here is a placeholder: basic
# per-trace graph statistics, useful for early sanity checks and
# class-balance bookkeeping, not the final training features.
#
# Usage:
#   python ingest_traces.py --input /path/to/raw_traces --attack-type normal --split train
#   python ingest_traces.py --input /path/to/sqli_traces --attack-type sqli --split train
#   python ingest_traces.py --input ./data/raw_traces --delete-after   # actually delete
# Dry-run (report only, nothing deleted) is the default; pass --delete-after
# to actually remove source files once they've been safely parsed and
# written to Mongo. Deletion is never applied to attack-class files.

import argparse
import glob
import os
import random
import sys
from datetime import datetime, timezone
from uuid import uuid4

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
sys.path.insert(0, PROJECT_ROOT)

from analytics.parse_traces import parse_single_trace_json  # noqa: E402
from mongo_client import get_database  # noqa: E402
from setup_database import ATTACK_TYPES, compute_retention  # noqa: E402

DEFAULT_NORMAL_SAMPLE_SIZE = 5000


def build_graph_doc(json_path, trial_id, attack_type):
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
        "label": attack_type,
    }


def build_raw_trace_doc(json_path, trial_id, attack_type, captured_at):
    retention_class, expires_at = compute_retention(attack_type, captured_at)
    trace_id = os.path.splitext(os.path.basename(json_path))[0].replace("trace_", "")

    doc = {
        "trace_id": trace_id,
        "trial_id": trial_id,
        "attack_type": attack_type,
        "captured_at": captured_at,
        "source_ref": json_path,
        "trace_payload": None,
        "processing_status": "processed",
        "retention_class": retention_class,
        "expires_at": expires_at,
        "schema_version": 1,
    }

    if retention_class == "long_term_attack":
        import json

        with open(json_path, "r", encoding="utf-8") as f:
            doc["trace_payload"] = json.load(f)

    return doc


def captured_at_for(json_path):
    try:
        import json

        with open(json_path, "r", encoding="utf-8") as f:
            data = json.load(f)
        harvested_at = data.get("harvested_at")
        if harvested_at:
            return datetime.fromisoformat(harvested_at.replace("Z", "+00:00"))
    except Exception:
        pass
    return datetime.fromtimestamp(os.path.getmtime(json_path), tz=timezone.utc)


def run(input_dir, attack_type, split_assignment, sample_size, delete_after, trial_id=None):
    if attack_type not in ATTACK_TYPES and attack_type != "normal":
        raise ValueError(f"Unknown attack_type '{attack_type}'")

    json_files = sorted(glob.glob(os.path.join(input_dir, "*.json")))
    print(f"[*] Found {len(json_files)} raw trace files in {input_dir}")
    if not json_files:
        return

    # Downsampling only ever applies to the majority "normal" class. Every
    # attack-class file is ingested in full - it's the rare, valuable class.
    if attack_type == "normal" and sample_size and len(json_files) > sample_size:
        rng = random.Random(42)  # fixed seed: reproducible sample across teammates/runs
        json_files = rng.sample(json_files, sample_size)
        print(f"[*] Downsampled 'normal' class to {sample_size} representative traces")

    trial_id = trial_id or f"trial_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}_{uuid4().hex[:6]}"
    database = get_database()

    graphs_inserted = 0
    raw_docs_inserted = 0
    skipped = 0
    to_delete = []
    captured_ats = []

    for path in json_files:
        graph_doc = build_graph_doc(path, trial_id, attack_type)
        if graph_doc is None:
            skipped += 1
            continue

        captured_at = captured_at_for(path)
        captured_ats.append(captured_at)
        raw_doc = build_raw_trace_doc(path, trial_id, attack_type, captured_at)

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
        trials_doc = {
            "trial_id": trial_id,
            "attack_type": attack_type,
            "platform": "google-online-boutique",
            "feature_condition": "structural-only-placeholder",
            "started_at": min(captured_ats),
            "ended_at": max(captured_ats),
            "split_assignment": split_assignment,
        }
        database.trials.insert_one(trials_doc)

    print("\n" + "=" * 60)
    print("[+] INGESTION COMPLETE")
    print(f"    trial_id: {trial_id}")
    print(f"    graphs inserted: {graphs_inserted}")
    print(f"    raw_traces tracking docs inserted: {raw_docs_inserted}")
    print(f"    skipped (unparseable): {skipped}")
    print(f"    retention_class: {'long_term_attack (kept forever)' if attack_type in ATTACK_TYPES else f'temporary (TTL expiry, {len(to_delete)} eligible)'}")
    print("=" * 60)

    if to_delete:
        if delete_after:
            for path in to_delete:
                os.remove(path)
            print(f"[+] Deleted {len(to_delete)} processed source files (--delete-after)")
        else:
            print(
                f"[*] Dry run: {len(to_delete)} source files are safely parsed and would be "
                f"deleted. Re-run with --delete-after to actually remove them."
            )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShadowTrace raw trace -> MongoDB ingestion")
    parser.add_argument("--input", required=True, help="Directory of raw trace_*.json files")
    parser.add_argument(
        "--attack-type",
        default="normal",
        choices=["normal", *sorted(ATTACK_TYPES)],
        help="Label applied to every trace in this batch (one attack_type per run)",
    )
    parser.add_argument(
        "--split",
        default="train",
        choices=["train", "test"],
        help="Trial-level train/test split assignment for this whole batch. Split at the "
        "trial level, never per-trace - see Ma (2026)'s leakage finding.",
    )
    parser.add_argument(
        "--sample-size",
        type=int,
        default=DEFAULT_NORMAL_SAMPLE_SIZE,
        help=f"Cap on how many 'normal' traces to ingest (default {DEFAULT_NORMAL_SAMPLE_SIZE}). Ignored for attack classes.",
    )
    parser.add_argument(
        "--delete-after",
        action="store_true",
        help="Actually delete source files once safely parsed (temporary/normal only). Default is dry-run.",
    )
    parser.add_argument("--trial-id", default=None, help="Reuse an existing trial_id instead of generating one")
    args = parser.parse_args()

    run(
        input_dir=args.input,
        attack_type=args.attack_type,
        split_assignment=args.split,
        sample_size=args.sample_size,
        delete_after=args.delete_after,
        trial_id=args.trial_id,
    )
