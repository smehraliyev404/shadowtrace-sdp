"""Exfiltration / bulk enumeration: walk the whole catalog over and over.

Looks like a foothold pulling everything systematically. Unlike the flood,
breadth is high: causal_history and path_entropy widen because it hits paths a
normal session never would. Slow and single-threaded on purpose - the tell is
the shape of the access, not volume.
"""

import time
import argparse

import requests

# the full catalog - a human looks at a handful, the exfiltrator walks all of them
PRODUCT_IDS = [
    "OLJCESPC7Z", "66VCHSJNUP", "1YMWWN1N4O", "L9ECAV7KIM", "2ZYFJ3GM2N",
    "0PUK6V6EV0", "LS4PSXUNUM", "9SIQT8TOJO", "6E92ZMYYFZ",
]
CURRENCIES = ["EUR", "USD", "JPY", "GBP", "TRY", "CAD"]


def sweep(session, base_url):
    """One full pass over every data-bearing endpoint."""
    n = 0
    session.get(base_url + "/", timeout=5); n += 1   # homepage first, then enumerate everything
    for pid in PRODUCT_IDS:                      # walk the whole catalog
        session.get(f"{base_url}/product/{pid}", timeout=5); n += 1
    for cur in CURRENCIES:                        # and every currency
        session.post(f"{base_url}/setCurrency",
                     data={"currency_code": cur}, timeout=5); n += 1
    session.get(base_url + "/cart", timeout=5); n += 1
    return n


def main():
    p = argparse.ArgumentParser(description="ShadowTrace exfiltration attack")
    p.add_argument("--duration", type=int, required=True, help="seconds to run")
    p.add_argument("--url", default="http://localhost:8080", help="frontend base URL")
    p.add_argument("--label", default="exfiltration", help="attack label (for logging only)")
    p.add_argument("--pause", type=float, default=0.5,
                   help="seconds between requests (methodical, not a flood)")
    args = p.parse_args()

    session = requests.Session()

    start = time.time()
    passes = 0
    total = 0
    print(f"[exfil] enumerating {len(PRODUCT_IDS)} products + "
          f"{len(CURRENCIES)} currencies -> {args.url} for {args.duration}s")

    while time.time() - start < args.duration:
        try:
            total += sweep(session, args.url)   # one exhaustive pass over everything
            passes += 1
        except requests.RequestException:
            pass                                 # failed mid-sweep, just start the next pass
        time.sleep(args.pause)                   # methodical spacing, not a flood

    elapsed = time.time() - start
    print(f"[exfil] done: {passes} full catalog sweeps, {total} requests in {elapsed:.0f}s")


if __name__ == "__main__":
    main()
