"""SQL injection probing: product pages requested with injection strings as the ID.

The shop has no SQL database, so no probe succeeds; the attack shows up as a
burst of failing product lookups on frontend -> productcatalog. Requests are
traced and recorded like in the other attack scripts (see provenance.py).
"""

import os
import sys
import time
import argparse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from provenance import Pacer, add_origin_args, origin_log_from_args, send  # noqa: E402

# classic injection strings we cycle through; the catalog rejects them all - we
# only care that the attempt was made, not that anything "worked"
PROBES = ["1' OR '1'='1", "'; DROP TABLE products;--", "1 UNION SELECT null",
          "%27%20OR%201=1", "../../etc/passwd", "0x27", "admin'--", "1;WAITFOR"]


def main():
    p = argparse.ArgumentParser(description="ShadowTrace SQLi probing attack")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--label", default="sqli_probe", help="origin label in origin.jsonl")
    p.add_argument("--pause", type=float, default=0.1)
    add_origin_args(p)
    args = p.parse_args()
    log = origin_log_from_args(args, client="sqli_probe")
    pacer = Pacer(args.pause, args.jitter, args.rng_seed)

    s = requests.Session()
    start, sent, errors, i = time.time(), 0, 0, 0
    print(f"[sqli] probing {args.url}/product/<payload> for {args.duration}s")
    while time.time() - start < args.duration:
        try:
            # drop a probe string into the product id, URL-encoded into the path
            r = send(s, "GET",
                     f"{args.url}/product/{requests.utils.quote(PROBES[i % len(PROBES)], safe='')}",
                     log, args.label, timeout=5)
            sent += 1
            errors += r.status_code >= 400   # 4xx/5xx expected - that's the error-rate signal
        except requests.RequestException:
            errors += 1
        i += 1
        pacer.sleep()
    log.close()
    print(f"[sqli] done: {sent} probes in {time.time()-start:.0f}s ({errors} errored)")


if __name__ == "__main__":
    main()
