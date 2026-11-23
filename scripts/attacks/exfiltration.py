"""Catalog exfiltration: repeatedly walks every product page and every currency.

A shopper looks at a handful of products; this client enumerates all of them.
setCurrency answers with a redirect, which is followed as a separate request
with its own trace ID (see provenance.send).
"""

import os
import sys
import time
import argparse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from provenance import Pacer, add_origin_args, origin_log_from_args, send  # noqa: E402

# the full catalog - a human looks at a handful, the exfiltrator walks all of them
PRODUCT_IDS = [
    "OLJCESPC7Z", "66VCHSJNUP", "1YMWWN1N4O", "L9ECAV7KIM", "2ZYFJ3GM2N",
    "0PUK6V6EV0", "LS4PSXUNUM", "9SIQT8TOJO", "6E92ZMYYFZ",
]
CURRENCIES = ["EUR", "USD", "JPY", "GBP", "TRY", "CAD"]


def sweep(session, base_url, log, label, pacer):
    """One full pass over every data-bearing endpoint."""
    n = 0
    send(session, "GET", base_url + "/", log, label, timeout=5); n += 1
    pacer.sleep()
    for pid in PRODUCT_IDS:
        send(session, "GET", f"{base_url}/product/{pid}", log, label, timeout=5); n += 1
        pacer.sleep()
    for cur in CURRENCIES:
        send(session, "POST", f"{base_url}/setCurrency", log, label,
             data={"currency_code": cur}, timeout=5); n += 1
        pacer.sleep()
    send(session, "GET", base_url + "/cart", log, label, timeout=5); n += 1
    return n


def main():
    p = argparse.ArgumentParser(description="ShadowTrace exfiltration attack")
    p.add_argument("--duration", type=int, required=True, help="seconds to run")
    p.add_argument("--url", default="http://localhost:8080", help="frontend base URL")
    p.add_argument("--label", default="exfiltration", help="origin label in origin.jsonl")
    p.add_argument("--pause", type=float, default=0.5,
                   help="seconds between requests (methodical, not a flood)")
    add_origin_args(p)
    args = p.parse_args()
    log = origin_log_from_args(args, client="exfiltration")
    pacer = Pacer(args.pause, args.jitter, args.rng_seed)

    session = requests.Session()
    start, passes, total = time.time(), 0, 0
    print(f"[exfil] enumerating {len(PRODUCT_IDS)} products + "
          f"{len(CURRENCIES)} currencies -> {args.url} for {args.duration}s")

    while time.time() - start < args.duration:
        try:
            total += sweep(session, args.url, log, args.label, pacer)
            passes += 1
        except requests.RequestException:
            pass
        pacer.sleep()
    log.close()

    elapsed = time.time() - start
    print(f"[exfil] done: {passes} full catalog sweeps, {total} requests in {elapsed:.0f}s")


if __name__ == "__main__":
    main()
