# a typical brute-force login attack against Microservice-demo-shop 


import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

USERNAMES = ["admin", "root", "user", "test", "operator", "guest"]
STOP = threading.Event()


def worker(url, label, counters, pause):
    # one worker = one reused session firing login attempts back to back
    s = requests.Session()
    i = 0
    while not STOP.is_set():
        i += 1
        try:
            # cycle usernames with an always-wrong password as a result server should answer 401
            r = s.post(url, data={"username": USERNAMES[i % len(USERNAMES)],
                                  "password": f"guess{i}"}, timeout=5)
            counters["401" if r.status_code == 401 else "other"] += 1 
        except requests.RequestException:
            counters["err"] += 1   
        time.sleep(pause) 


def main():
    p = argparse.ArgumentParser(description="ShadowTrace brute-force login attack")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8081/login")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--pause", type=float, default=0.15,
                   help="seconds between attempts per worker (keeps rate ~15-25/s)")
    p.add_argument("--label", default="brute_force")
    args = p.parse_args()

    counters = {"401": 0, "other": 0, "err": 0}
    start = time.time()
    print(f"[brute] {args.concurrency} workers -> {args.url} for {args.duration}s")
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        # fan out N identical workers, all hammering the same /login endpoint
        for _ in range(args.concurrency):
            pool.submit(worker, args.url, args.label, counters, args.pause)
        try:
            time.sleep(args.duration)  
        finally:
            STOP.set()               
    total = sum(counters.values())
    print(f"[brute] done: {total} attempts in {time.time()-start:.0f}s "
          f"({counters['401']} rejected, {counters['err']} errors)")


if __name__ == "__main__":
    main()
