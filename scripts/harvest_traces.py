import os
import json
import time
import requests
import argparse
from datetime import datetime

JAEGER_BASE_URL = os.getenv("JAEGER_BASE_URL", "http://localhost:16686")
OUTPUT_DIR = os.getenv("OUTPUT_DIR", "data/raw_traces")
DEFAULT_SERVICES = ["frontend", "checkoutservice", "paymentservice", "cartservice", "emailservice", "shadowtrace-test-service"]

def ensure_directory_exists(directory_path):
    if not os.path.exists(directory_path):
        os.makedirs(directory_path)
        print(f"[+] Created directory: {directory_path}")

def get_all_services_from_jaeger():
    """Dynamically fetches all service names currently registered in Jaeger."""
    try:
        url = f"{JAEGER_BASE_URL}/api/services"
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            services = response.json().get("data", [])
            # Filter out internal jaeger query service
            return [s for s in services if s and s != "jaeger-query"]
    except Exception as e:
        print(f"[!] Warning: Could not fetch service list from Jaeger: {e}")
    return []

def fetch_traces_from_jaeger(service_name, limit=300):
    """Queries Jaeger REST API for raw traces belonging to a specific service."""
    url = f"{JAEGER_BASE_URL}/api/traces"
    params = {
        "service": service_name,
        "limit": limit,
        "lookback": "1h"
    }
    try:
        response = requests.get(url, params=params, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return data.get("data", [])
        else:
            print(f"[!] Warning: Received status code {response.status_code} for service '{service_name}'")
            return []
    except requests.exceptions.RequestException as e:
        print(f"[!] Error connecting to Jaeger API at {url}: {e}")
        return []

def save_trace_payload(trace_data, output_dir):
    """Saves a single trace payload as a structured JSON file."""
    trace_id = trace_data.get("traceID", f"unknown_{int(time.time()*1000)}")
    file_path = os.path.join(output_dir, f"trace_{trace_id}.json")

    output_payload = {
        "harvested_at": datetime.utcnow().isoformat() + "Z",
        "traceID": trace_id,
        "span_count": len(trace_data.get("spans", [])),
        "processes": trace_data.get("processes", {}),
        "spans": trace_data.get("spans", [])
    }

    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(output_payload, f, indent=2)

    return len(trace_data.get("spans", []))

def run_harvesting_pipeline(target_count, output_dir):
    ensure_directory_exists(output_dir)

    print(f"[*] Starting Trace Harvester. Target: {target_count}+ traces.")
    print(f"[*] Target Directory: {os.path.abspath(output_dir)}")

    # 1. Try dynamic service discovery
    discovered_services = get_all_services_from_jaeger()
    if discovered_services:
        print(f"[✓] Dynamically discovered services in Jaeger: {discovered_services}")
        services_to_query = discovered_services
    else:
        print(f"[*] No dynamic services found in Jaeger yet. Using default list: {DEFAULT_SERVICES}")
        services_to_query = DEFAULT_SERVICES

    total_traces_saved = 0
    total_spans_saved = 0
    saved_trace_ids = set()

    for service in services_to_query:
        print(f"[*] Querying Jaeger for service: '{service}'...")
        traces = fetch_traces_from_jaeger(service, limit=300)

        for trace in traces:
            trace_id = trace.get("traceID")
            if trace_id and trace_id not in saved_trace_ids:
                saved_trace_ids.add(trace_id)
                spans_in_trace = save_trace_payload(trace, output_dir)

                total_traces_saved += 1
                total_spans_saved += spans_in_trace

                print(f"    [-->] Saved trace_{trace_id}.json ({spans_in_trace} spans)")

            if total_traces_saved >= target_count:
                break

        if total_traces_saved >= target_count:
            break

    print("\n" + "="*60)
    print(f"[✓] HARVESTING COMPLETE!")
    print(f"    - Total Traces Saved: {total_traces_saved}")
    print(f"    - Total Spans Captured: {total_spans_saved}")
    print(f"    - Dataset Path: {os.path.abspath(output_dir)}")
    print("="*60)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="ShadowTrace Raw Trace Harvester")
    parser.add_argument("--target", type=int, default=500, help="Target number of traces to harvest (default: 500)")
    parser.add_argument("--output", type=str, default=OUTPUT_DIR, help="Output directory for raw JSON files")
    args = parser.parse_args()

    run_harvesting_pipeline(args.target, args.output)