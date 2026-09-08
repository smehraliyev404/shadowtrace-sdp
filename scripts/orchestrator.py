"""Attack orchestrator: fire attacks in random bursts over live normal traffic.

Logs each burst's start/end to data/runs/<run_id>.json - the only label source.
Enforces two things: bursts must overlap normal traffic (--i-have-normal-traffic,
since you run k6 yourself), and each burst is >= MIN_BURST_SECONDS so a 60s label
window can sit fully inside it.
"""

import os
import sys
import json
import time
import random
import argparse
import subprocess
from datetime import datetime, timezone

PYTHON = sys.executable  # whatever python is running this (the venv)

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
PROJECT_ROOT = os.path.abspath(os.path.join(SCRIPT_DIR, ".."))
RUNS_DIR = os.path.join(PROJECT_ROOT, "data", "runs")

WINDOW_SECONDS = 60          # keep in sync with parse_traces.WINDOW_SECONDS
MIN_BURST_SECONDS = 90       # bigger than one window so a window can sit fully inside
MIN_GAP_SECONDS = 75         # bigger than one window so each gap gives a clean normal window
DEFAULT_GAP_RANGE = (75, 120)

# the 8 attacks we collect. {python}/{root}/{duration} get filled in per burst.
# lateral_movement kubectl-execs into the attacker pod, so --dry-run swaps in
# sleep to test the schedule without a live cluster.
ATTACKS = {
    "http_flood":             "{python} {root}/scripts/attacks/http_flood.py --duration {duration}",
    "exfiltration":           "{python} {root}/scripts/attacks/exfiltration.py --duration {duration}",
    "brute_force":            "{python} {root}/scripts/attacks/brute_force.py --duration {duration}",
    "sqli_probe":             "{python} {root}/scripts/attacks/sqli_probe.py --duration {duration}",
    "ssrf_probe":             "{python} {root}/scripts/attacks/ssrf_probe.py --duration {duration}",
    "lateral_movement":       "{python} {root}/scripts/attacks/lateral_movement.py --duration {duration}",
    "session_rotation_brute": "{python} {root}/scripts/attacks/session_rotation_brute.py --duration {duration}",
    "slow_brute":             "{python} {root}/scripts/attacks/slow_brute.py --duration {duration}",
}


def run_burst(attack_type, duration, dry_run):
    """Execute one attack burst; return (start_ts, end_ts) actually observed."""
    if dry_run:
        cmd = f"sleep {duration}"
    else:
        cmd = ATTACKS[attack_type].format(python=PYTHON, root=PROJECT_ROOT, duration=duration)

    # wall-clock start/end bracket the burst - this pair is what labels the windows
    start_ts = time.time()
    print(f"[burst] {attack_type:14s} start {datetime.fromtimestamp(start_ts):%H:%M:%S} "
          f"dur~{duration}s :: {cmd}")
    try:
        subprocess.run(cmd, shell=True, check=False,
                       timeout=duration + 30)   # hard stop if the attack script hangs
    except subprocess.TimeoutExpired:
        print(f"[!] burst '{attack_type}' exceeded its timeout; killed.")
    end_ts = time.time()
    print(f"[burst] {attack_type:14s} end   {datetime.fromtimestamp(end_ts):%H:%M:%S} "
          f"({end_ts - start_ts:.0f}s)")
    return start_ts, end_ts


def orchestrate(run_id, attacks, n_bursts, burst_range, gap_range, dry_run, seed):
    if seed is not None:
        random.seed(seed)

    lo, hi = burst_range
    if lo < MIN_BURST_SECONDS:
        print(f"[!] raising minimum burst length to {MIN_BURST_SECONDS}s: a burst "
              f"shorter than one {WINDOW_SECONDS}s window yields zero attack labels.")
        lo = MIN_BURST_SECONDS
        hi = max(hi, lo)

    glo, ghi = gap_range
    if glo < MIN_GAP_SECONDS:
        print(f"[!] raising minimum gap to {MIN_GAP_SECONDS}s: a gap shorter than one "
              f"{WINDOW_SECONDS}s window yields zero clean NORMAL windows inside the run.")
        glo = MIN_GAP_SECONDS
        ghi = max(ghi, glo)
    gap_range = (glo, ghi)

    os.makedirs(RUNS_DIR, exist_ok=True)
    started_at = time.time()
    print(f"\n[*] Run {run_id}: {n_bursts} bursts of {attacks}")
    print(f"[*] burst {lo}-{hi}s, gap {gap_range[0]}-{gap_range[1]}s, "
          f"{'DRY-RUN (sleep)' if dry_run else 'LIVE attacks'}\n")

    # deal from a shuffled deck, not random.choice - choice drifted badly (once
    # lateral_movement 15x vs exfiltration 4x). the deck gives every attack an
    # equal count per cycle, random order, and reshuffles when empty.
    deck = []

    def draw_attack():
        nonlocal deck
        if not deck:
            deck = list(attacks)
            random.shuffle(deck)
        return deck.pop()

    bursts = []
    for i in range(n_bursts):
        attack_type = draw_attack()          # next attack off the shuffled deck
        duration = random.randint(lo, hi)    # random burst length within range
        s, e = run_burst(attack_type, duration, dry_run)
        bursts.append({"attack_type": attack_type,
                       "start_ts": round(s, 3), "end_ts": round(e, 3)})

        if i < n_bursts - 1:
            gap = random.randint(*gap_range)
            print(f"[gap]   {gap}s of pure normal traffic\n")
            time.sleep(gap)   # quiet gap -> a clean stretch of normal-only windows

    ended_at = time.time()

    run_record = {
        "run_id": run_id,
        "started_at": round(started_at, 3),
        "ended_at": round(ended_at, 3),
        "created_at": datetime.now(timezone.utc).isoformat(),
        "dry_run": dry_run,
        "seed": seed,
        "attack_bursts": bursts,
    }
    out_path = os.path.join(RUNS_DIR, f"{run_id}.json")
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(run_record, f, indent=2)

    total_attack = sum(b["end_ts"] - b["start_ts"] for b in bursts)
    span = ended_at - started_at
    print("\n" + "=" * 60)
    print(f"[✓] Run {run_id} complete.")
    print(f"    duration     : {span:.0f}s")
    print(f"    bursts        : {len(bursts)}  ({total_attack:.0f}s attack, "
          f"{span - total_attack:.0f}s normal)")
    print(f"    burst log     : {out_path}")
    print(f"\n    NEXT: harvest this exact bracket, then parse with this log:")
    print(f"      ./venv/bin/python scripts/harvest_traces.py --run-id {run_id} "
          f"--start {started_at:.0f} --end {ended_at:.0f}")
    print(f"      ./venv/bin/python analytics/parse_traces.py --run-id {run_id} "
          f"--run-json {out_path}")
    print("=" * 60)
    return run_record


def main():
    p = argparse.ArgumentParser(description="ShadowTrace attack orchestrator")
    p.add_argument("--run-id", required=True, help="e.g. run_03")
    p.add_argument("--attacks", nargs="+", default=["http_flood"],
                   help=f"attack types to draw from; available: {sorted(ATTACKS)}")
    p.add_argument("--bursts", type=int, default=4, help="number of attack bursts")
    p.add_argument("--burst-range", type=int, nargs=2, default=[MIN_BURST_SECONDS, 150],
                   metavar=("MIN", "MAX"), help="burst length range (seconds)")
    p.add_argument("--gap-range", type=int, nargs=2, default=list(DEFAULT_GAP_RANGE),
                   metavar=("MIN", "MAX"), help="gap between bursts (seconds)")
    p.add_argument("--seed", type=int, help="RNG seed for reproducible schedules")
    p.add_argument("--dry-run", action="store_true",
                   help="substitute 'sleep' for the attack (attack scripts not built yet)")
    p.add_argument("--i-have-normal-traffic", action="store_true",
                   help="confirm normal_traffic.js is already running concurrently")
    args = p.parse_args()

    unknown = [a for a in args.attacks if a not in ATTACKS]
    if unknown:
        p.error(f"unknown attack types {unknown}; available: {sorted(ATTACKS)}")

    if not args.dry_run and not args.i_have_normal_traffic:
        p.error("refusing to run: attacks must overlap normal traffic. Start "
                "normal_traffic.js first, then pass --i-have-normal-traffic "
                "(or use --dry-run to test the scheduler).")

    orchestrate(args.run_id, args.attacks, args.bursts,
                tuple(args.burst_range), tuple(args.gap_range),
                args.dry_run, args.seed)


if __name__ == "__main__":
    main()
