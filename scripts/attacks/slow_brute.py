"""Slow brute force: failed logins spaced out so no short window spikes.

Too sparse for the 60s window, but over ~300s call_repetition on the auth edge
climbs past baseline - so the wider accumulation window catches it.
"""

import time
import argparse

import requests

USERNAMES = ["admin", "root", "user", "test", "operator"]


def main():
    p = argparse.ArgumentParser(description="ShadowTrace slow brute force")
    p.add_argument("--duration", type=int, required=True)
    p.add_argument("--url", default="http://localhost:8081/login")
    p.add_argument("--interval", type=float, default=2.0,
                   help="seconds between attempts (low, to stay under fast-window thresholds)")
    p.add_argument("--label", default="slow_brute")
    args = p.parse_args()

    s = requests.Session()
    start, attempts = time.time(), 0
    print(f"[slow] one login every {args.interval}s -> {args.url} for {args.duration}s")
    # single thread, one attempt per interval - deliberately slow so no short
    # window spikes; the volume only surfaces when summed over a long window
    while time.time() - start < args.duration:
        attempts += 1
        try:
            # same failed-login pattern as brute_force, just paced way down
            s.post(args.url, data={"username": USERNAMES[attempts % len(USERNAMES)],
                                   "password": f"guess{attempts}"}, timeout=5)
        except requests.RequestException:
            pass                      # ignore errors, the pacing is what matters here
        time.sleep(args.interval)     # the gap is the whole point - keeps the rate low
    print(f"[slow] done: {attempts} attempts in {time.time()-start:.0f}s "
          f"(~{attempts/(time.time()-start):.1f}/s, low by design)")


if __name__ == "__main__":
    main()
