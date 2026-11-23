"""Slow brute-force login: one attempt every few seconds from a single client.

The rate stays below thresholds that look at short windows; the volume only
becomes visible when attempts are accumulated over a longer period.
"""

import os
import sys
import time
import argparse

import requests

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))
from provenance import Pacer, add_origin_args, origin_log_from_args, send  # noqa: E402
from synthetic_people import candidate_usernames, password_guess  # noqa: E402



# credential-stuffing usernames, filled in main() from --rng-seed (synthetic_people.py)
USERNAMES = []


def main():
    p = argparse.ArgumentParser(description="ShadowTrace slow brute force")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8081/login")
    p.add_argument("--interval", type=float, default=2.0,
                   help="seconds between attempts (low, to stay under fast-window thresholds)")
    p.add_argument("--label", default="slow_brute", help="origin label in origin.jsonl")
    add_origin_args(p)
    args = p.parse_args()
    USERNAMES[:] = candidate_usernames(args.rng_seed)
    log = origin_log_from_args(args, client="slow_brute")
    pacer = Pacer(args.interval, args.jitter, args.rng_seed)

    s = requests.Session()
    start, attempts, rejected = time.time(), 0, 0
    print(f"[slow] one login every {args.interval}s -> {args.url} for {args.duration}s")
    # single thread, one attempt per interval - deliberately slow so no short
    # window spikes; the volume only surfaces when summed over a long window
    while time.time() - start < args.duration:
        attempts += 1
        try:
            user = USERNAMES[attempts % len(USERNAMES)]
            creds = {"username": user, "password": password_guess(attempts, user)}
            r = send(s, "POST", args.url, log, args.label,
                     data=creds,
                     pii=creds,          # ground truth: the credentials this attempt sends
                     timeout=5)
            rejected += r.status_code == 401
        except requests.RequestException:
            pass
        pacer.sleep()
    log.close()
    elapsed = time.time() - start
    print(f"[slow] done: {attempts} attempts in {elapsed:.0f}s "
          f"(~{attempts/elapsed:.1f}/s, {rejected} rejected, low by design)")


if __name__ == "__main__":
    main()
