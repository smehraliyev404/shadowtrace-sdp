# So this part is Jaeger which is basically fetching all spans and as a result of a run turns them into traces which are the stored in our data folder.

import os
import json
import time
import argparse
from datetime import datetime, timezone

import requests

JAEGER_BASE_URL = os.getenv("JAEGER_BASE_URL", "http://localhost:16686")
RAW_TRACES_DIR = os.getenv("RAW_TRACES_DIR", "data/raw_traces")
RUNS_DIR = os.getenv("RUNS_DIR", "data/runs")

# Jaeger traces itself, those spans aren't part of the Boutique call graph
EXCLUDED_SERVICES = {"jaeger-all-in-one", "jaeger-query", "jaeger-collector"}

# every service that can root a trace, not just frontend - the attacker pod and
# authservice root traces that never touch frontend (a frontend-only query missed
# the lateral ones).
DEFAULT_ROOT_SERVICES = ["frontend", "attacker", "authservice", "ssrfservice"]


def ensure_directory_exists(directory_path):
    os.makedirs(directory_path, exist_ok=True)
    return directory_path


def fetch_traces(service, start_us, end_us, limit):
    url = f"{JAEGER_BASE_URL}/api/traces"
    # parameters inside the request are in microseconds to make it very very precise and avoid overlapping traces 
    params = {
        "service": service,
        "start": int(start_us),
        "end": int(end_us),
        "limit": int(limit),
    }
    try:
        response = requests.get(url, params=params, timeout=30)
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to Jaeger at {url}: {e}")
        return []

    if response.status_code != 200:
        print(f"[!] Jaeger returned {response.status_code} for service '{service}'")
        return []
    return response.json().get("data") or []


def trace_start_us(trace):
    starts = [s.get("startTime", 0) for s in trace.get("spans", [])]
    return min(starts) if starts else 0


def trace_services(trace):
    return {p.get("serviceName") for p in (trace.get("processes") or {}).values()}


def save_trace(trace, output_dir):
    trace_id = trace.get("traceID", f"unknown_{int(time.time() * 1000)}")
    payload = {
        "harvested_at": datetime.now(timezone.utc).isoformat(),
        "traceID": trace_id,
        "span_count": len(trace.get("spans", [])),
        "processes": trace.get("processes", {}),
        "spans": trace.get("spans", []),
    }
    with open(os.path.join(output_dir, f"trace_{trace_id}.json"), "w", encoding="utf-8") as f:
        json.dump(payload, f, indent=2)
    return payload["span_count"]

# Here we provide an amount of time and other parameters for Jaeger to store traces and then send them to not overload the system.
def harvest_run(run_id, start_ts, end_ts, services=None, limit=5000,
                chunk_seconds=30, raw_dir=RAW_TRACES_DIR, runs_dir=RUNS_DIR):
    services = services or DEFAULT_ROOT_SERVICES
    start_us = start_ts * 1_000_000  
    end_us = end_ts * 1_000_000

    output_dir = ensure_directory_exists(os.path.join(raw_dir, run_id))
    ensure_directory_exists(runs_dir)

    print(f"[*] Run: {run_id}")
    print(f"[*] Bracket: {datetime.fromtimestamp(start_ts)} -> {datetime.fromtimestamp(end_ts)} "
          f"({end_ts - start_ts:.0f}s)")
    print(f"[*] Querying Jaeger services={services} in {chunk_seconds}s slices")

    saved, spans_saved, seen = 0, 0, set()
    dropped_bounds, dropped_excluded = 0, 0

    slice_start = start_us
    step = int(chunk_seconds * 1_000_000)
    while slice_start < end_us:
        slice_end = min(slice_start + step, end_us)
        for service in services:
            traces = fetch_traces(service, slice_start, slice_end, limit)
            if len(traces) >= limit:
                print(f"    [!] slice {(slice_start-start_us)/1e6:.0f}-{(slice_end-start_us)/1e6:.0f}s "
                      f"service '{service}' hit the {limit} cap -- shrink --chunk-seconds")
            for trace in traces:
                trace_id = trace.get("traceID")
                if not trace_id or trace_id in seen:  
                    continue
                t_start = trace_start_us(trace)
                if not (start_us <= t_start <= end_us):
                    dropped_bounds += 1
                    continue
                if trace_services(trace) & EXCLUDED_SERVICES:
                    dropped_excluded += 1
                    continue
                seen.add(trace_id)
                spans_saved += save_trace(trace, output_dir)
                saved += 1
        slice_start = slice_end

    print(f"[*] harvested across {((end_us - start_us) / step):.0f} slices, "
          f"{len(services)} services each.")

    manifest = {
        "run_id": run_id,
        "started_at": start_ts,
        "ended_at": end_ts,
        "harvested_at": datetime.now(timezone.utc).isoformat(),
        "jaeger_services_queried": services,
        "traces_saved": saved,
        "spans_saved": spans_saved,
        "traces_dropped_out_of_bounds": dropped_bounds,
        "traces_dropped_excluded_service": dropped_excluded,
        "output_dir": os.path.abspath(output_dir),
    }
    manifest_path = os.path.join(runs_dir, f"{run_id}.harvest.json")
    with open(manifest_path, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=2)

    print("\n" + "=" * 60)
    print(f"[✓] Saved {saved} traces / {spans_saved} spans -> {output_dir}")
    print(f"    dropped {dropped_bounds} outside bracket, "
          f"{dropped_excluded} for excluded services")
    print(f"    manifest -> {manifest_path}")
    print("=" * 60)
    return manifest


def main():
    parser = argparse.ArgumentParser(description="ShadowTrace raw trace harvester")
    parser.add_argument("--run-id", required=True, help="Run identifier, e.g. run_01")
    parser.add_argument("--start", type=float,
                        help="Run start as a unix timestamp (seconds)")
    parser.add_argument("--end", type=float,
                        help="Run end as a unix timestamp (seconds)")
    parser.add_argument("--last", type=float,
                        help="Convenience: harvest the last N seconds instead of --start/--end")
    parser.add_argument("--services", nargs="+", default=None,
                        help=f"Jaeger services to query (default: {DEFAULT_ROOT_SERVICES}). "
                             "Every service that can root a trace must be listed.")
    parser.add_argument("--limit", type=int, default=5000,
                        help="Max traces per time slice (default: 5000)")
    parser.add_argument("--chunk-seconds", type=int, default=30,
                        help="Harvest in slices this many seconds wide (default: 30). "
                             "Smaller slices avoid a high-volume burst crowding out others.")
    args = parser.parse_args()

    if args.last is not None:
        end_ts = time.time()
        start_ts = end_ts - args.last
    elif args.start is not None and args.end is not None:
        start_ts, end_ts = args.start, args.end
    else:
        parser.error("provide either --last SECONDS, or both --start and --end")

    if end_ts <= start_ts:
        parser.error("--end must be after --start")

    harvest_run(args.run_id, start_ts, end_ts, services=args.services,
                limit=args.limit, chunk_seconds=args.chunk_seconds)


if __name__ == "__main__":
    main()
