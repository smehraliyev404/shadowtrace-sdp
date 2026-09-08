"""SQLi probing: poke the product-lookup endpoint with junk identifiers.

No SQL DB and we ignore payloads, so this only fakes the shape of a scan. Signal
on frontend->productcatalog: call_repetition up, high error rate, low jitter.
Known not to separate cleanly here.
"""

import time
import argparse

import requests

# classic injection strings we cycle through; the catalog rejects them all - we
# only care that the attempt was made, not that anything "worked"
PROBES = ["1' OR '1'='1", "'; DROP TABLE products;--", "1 UNION SELECT null",
          "%27%20OR%201=1", "../../etc/passwd", "0x27", "admin'--", "1;WAITFOR"]


def main():
    p = argparse.ArgumentParser(description="ShadowTrace SQLi probing attack")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8080")
    p.add_argument("--label", default="sqli_probe")
    p.add_argument("--pause", type=float, default=0.1)
    args = p.parse_args()

    s = requests.Session()
    start, sent, errors, i = time.time(), 0, 0, 0
    print(f"[sqli] probing {args.url}/product/<payload> for {args.duration}s")
    while time.time() - start < args.duration:
        try:
            # drop a probe string into the product id, URL-encoded into the path
            r = s.get(f"{args.url}/product/{requests.utils.quote(PROBES[i % len(PROBES)])}",
                      timeout=5)
            sent += 1
            errors += r.status_code >= 400   # 4xx/5xx expected - that's the error-rate signal
        except requests.RequestException:
            errors += 1
        i += 1
        time.sleep(args.pause)
    print(f"[sqli] done: {sent} probes in {time.time()-start:.0f}s ({errors} errored)")


if __name__ == "__main__":
    main()
