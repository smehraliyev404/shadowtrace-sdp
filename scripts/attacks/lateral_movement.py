"""Lateral movement (the headline threat): host-side wrapper.

Real work is in the attacker pod (src/attacker/lateral.py) - a gRPC client that
calls internal services directly, skipping the frontend. Signal: edges like
attacker->productcatalog with no precedent -> causal_history_distance spikes.
"""

import argparse
import subprocess


def main():
    p = argparse.ArgumentParser(description="ShadowTrace lateral-movement attack")
    p.add_argument("--duration", type=int, required=True, help="seconds to run")
    p.add_argument("--pod", default="attacker", help="attacker pod name")
    args = p.parse_args()

    # exec into the attacker pod and run its script *through* the OTel wrapper, so
    # the internal gRPC calls it makes get traced like any other service's calls
    cmd = ["kubectl", "exec", args.pod, "--",
           "opentelemetry-instrument", "python", "/app/lateral.py",
           "--duration", str(args.duration)]
    print(f"[lateral] driving pod '{args.pod}' for {args.duration}s")
    subprocess.run(cmd, check=False, timeout=args.duration + 60)   # +60s slack over the burst


if __name__ == "__main__":
    main()
