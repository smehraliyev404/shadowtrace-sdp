"""Brute-force login against authservice; each worker reuses one HTTP session.

Usernames come from a credential-stuffing list (synthetic_people.py) that mixes
admin names with real-looking user names; passwords are always wrong. The
credentials of every attempt are recorded in origin.jsonl as ground truth.
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
from synthetic_people import candidate_usernames, password_guess  # noqa: E402

STOP = threading.Event()


def worker(url, label, log, counters, pacer, idx):
    # one worker = one reused session firing login attempts back to back
    s = requests.Session()
    i = idx
    while not STOP.is_set():
        i += 1
        try:
            # always-wrong password, so the server answers 401
            user = USERNAMES[i % len(USERNAMES)]
            creds = {"username": user, "password": password_guess(i, user)}
            r = send(s, "POST", url, log, label,
                     data=creds,
                     pii=creds,          # ground truth: the credentials this attempt sends
                     timeout=5)
            counters["401" if r.status_code == 401 else "other"] += 1
        except requests.RequestException:
            counters["err"] += 1
        pacer.sleep()


# credential-stuffing usernames, filled in main() from --rng-seed (synthetic_people.py)
USERNAMES = []


def main():
    p = argparse.ArgumentParser(description="ShadowTrace brute-force login attack")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8081/login")
    p.add_argument("--concurrency", type=int, default=4)
    p.add_argument("--pause", type=float, default=0.15,
                   help="seconds between attempts per worker (keeps rate ~15-25/s)")
    p.add_argument("--label", default="brute_force", help="origin label in origin.jsonl")
    add_origin_args(p)
    args = p.parse_args()
    USERNAMES[:] = candidate_usernames(args.rng_seed)
    log = origin_log_from_args(args, client="brute_force")

    counters = {"401": 0, "other": 0, "err": 0}
    start = time.time()
    print(f"[brute] {args.concurrency} workers -> {args.url} for {args.duration}s")
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        # fan out N identical workers, all hammering the same /login endpoint
        for idx in range(args.concurrency):
            pool.submit(worker, args.url, args.label, log, counters, Pacer(args.pause, args.jitter, args.rng_seed, idx), idx * 1000)
        try:
            time.sleep(args.duration)
        finally:
            STOP.set()
    log.close()
    total = sum(counters.values())
    print(f"[brute] done: {total} attempts in {time.time()-start:.0f}s "
          f"({counters['401']} rejected, {counters['other']} other, {counters['err']} errors)")


if __name__ == "__main__":
    main()
