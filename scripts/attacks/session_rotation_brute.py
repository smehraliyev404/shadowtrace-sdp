"""Session-rotation brute force: brute_force, but a fresh session per attempt.

Rotating sessions dodges per-session rate limiting but not us - detection keys
off the auth->frontend edge, which every attempt crosses no matter the session.
"""

import time
import argparse
import threading
from concurrent.futures import ThreadPoolExecutor

import requests

USERNAMES = ["admin", "root", "user", "test", "operator", "guest"]
STOP = threading.Event()  # flipped when the run is over; every worker watches it


def worker(url, label, counters, pause):
    i = 0
    while not STOP.is_set():
        i += 1
        # fresh session each attempt - the only difference from brute_force
        s = requests.Session()
        try:
            r = s.post(url, data={"username": USERNAMES[i % len(USERNAMES)],
                                  "password": f"guess{i}"}, timeout=5)
            counters["401" if r.status_code == 401 else "other"] += 1  # tally rejects
        except requests.RequestException:
            counters["err"] += 1
        finally:
            s.close()               # drop the connection so the next attempt looks brand new
        time.sleep(pause)   # keep it a rare event under normal traffic


def main():
    p = argparse.ArgumentParser(description="ShadowTrace session-rotation brute force")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8081/login")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--pause", type=float, default=0.15,
                   help="seconds between attempts per worker (keeps rate ~15-25/s)")
    p.add_argument("--label", default="session_rotation_brute")
    args = p.parse_args()

    counters = {"401": 0, "other": 0, "err": 0}
    start = time.time()
    print(f"[sessrot] {args.concurrency} workers, fresh session per attempt -> "
          f"{args.url} for {args.duration}s")
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        # same fan-out as brute_force, but each attempt inside opens a new session
        for _ in range(args.concurrency):
            pool.submit(worker, args.url, args.label, counters, args.pause)
        try:
            time.sleep(args.duration)   # run for the whole burst
        finally:
            STOP.set()                  # time's up -> stop every worker
    total = sum(counters.values())
    print(f"[sessrot] done: {total} attempts across {total} sessions in "
          f"{time.time()-start:.0f}s ({counters['401']} rejected)")


if __name__ == "__main__":
    main()
