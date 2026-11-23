"""Lateral movement: direct gRPC calls to internal services from inside the cluster.

    --source attacker               the dedicated attacker pod
    --source recommendationservice  code running inside a compromised legitimate pod;
                                    its calls look like recommendationservice ->
                                    productcatalog (an edge that also exists in normal
                                    traffic), -> currency and -> cart (edges that never do)

lateral.py (in the testbed repository, src/attacker/) is piped into the pod on
stdin (`kubectl exec -i ... python -`), so both sources run the same code and a
change needs no image rebuild. It runs every call under a trace ID it chose and
prints one "ORIGIN {...}" line per call; this wrapper appends those lines to
the run's origin.jsonl.
"""

import os
import sys
import json
import argparse
import subprocess

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from provenance import add_origin_args, origin_log_from_args  # noqa: E402

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
LATERAL_PY = os.path.join(PROJECT_ROOT, "..", "shadowtrace-testbed", "src", "attacker", "lateral.py")
OTLP = "http://host.minikube.internal:4317"

# where the code runs, and the environment it needs there
SOURCES = {
    "attacker": {
        "target": ["attacker"],                  # bare pod, its env already has OTEL_*
        "env": ["PYTHONPATH=/app"],
        "runner": ["opentelemetry-instrument", "python", "-"],
    },
    "recommendationservice": {
        "target": ["deploy/recommendationservice", "-c", "server"],
        # the service configures tracing in its own code, so the auto-instrumented
        # side process needs the exporter settings spelled out
        "env": ["PYTHONPATH=/recommendationservice",
                "OTEL_SERVICE_NAME=recommendationservice",
                f"OTEL_EXPORTER_OTLP_ENDPOINT={OTLP}", "OTEL_EXPORTER_OTLP_PROTOCOL=grpc",
                "OTEL_TRACES_EXPORTER=otlp", "OTEL_METRICS_EXPORTER=none",
                "OTEL_LOGS_EXPORTER=none", "OTEL_PROPAGATORS=tracecontext,baggage"],
        # the image copies site-packages but not /usr/local/bin, so there is no
        # opentelemetry-instrument executable: set up tracing in code instead
        "runner": ["python", "-", "--self-instrument"],
    },
}


def main():
    p = argparse.ArgumentParser(description="ShadowTrace lateral-movement attack")
    p.add_argument("--duration", type=int, required=True, help="seconds to run")
    p.add_argument("--source", default="attacker", choices=sorted(SOURCES),
                   help="where the foothold is: the attacker pod or a compromised service pod")
    p.add_argument("--pause", type=float, default=0.3, help="seconds between call rounds")
    p.add_argument("--label", default="lateral_movement", help="origin label in origin.jsonl")
    p.add_argument("--script", default=LATERAL_PY, help="lateral.py to pipe into the pod")
    add_origin_args(p)
    args = p.parse_args()
    log = origin_log_from_args(args, client="lateral")
    src = SOURCES[args.source]

    cmd = (["kubectl", "exec", "-i", *src["target"], "--", "env", *src["env"],
            *src["runner"],
            "--duration", str(args.duration), "--label", args.label,
            "--pause", str(args.pause), "--jitter", str(args.jitter)]
           + (["--rng-seed", str(args.rng_seed)] if args.rng_seed is not None else []))
    print(f"[lateral] from {args.source} for {args.duration}s")
    logged = bad = 0
    with open(args.script, "rb") as script:
        proc = subprocess.Popen(cmd, stdin=script, stdout=subprocess.PIPE, text=True)
        try:
            for line in proc.stdout:
                if not line.startswith("ORIGIN "):
                    print(line, end="")
                    continue
                try:
                    rec = json.loads(line[len("ORIGIN "):])
                    log.write(rec.pop("trace_id"), rec.pop("span_id"), rec.pop("origin"),
                              source=args.source, **rec)
                    logged += 1
                except (ValueError, KeyError):
                    bad += 1
            proc.wait(timeout=args.duration + 60)   # +60s slack over the burst
        except subprocess.TimeoutExpired:
            proc.kill()
            print("[lateral] pod exec exceeded its timeout; killed")
        finally:
            log.close()
    print(f"[lateral] logged {logged} calls to {log.path}" + (f" ({bad} malformed lines)" if bad else ""))
    if logged == 0:
        print(f"[lateral] WARNING: no ORIGIN lines from {args.source} (exit {proc.returncode})")
        sys.exit(1)
    if proc.returncode != 0:      # crashed or killed part-way: the burst is shorter than planned
        print(f"[lateral] pod script exited {proc.returncode} after {logged} calls - burst incomplete")
        sys.exit(1)


if __name__ == "__main__":
    main()
