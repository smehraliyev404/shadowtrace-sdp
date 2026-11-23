"""Replay the attack schedule of a run manifest over live normal traffic.

    ./venv/bin/python scripts/orchestrator.py --run-id run_01 \
        --manifest data/runs/run_01/manifest.json --t0 <k6 start time> --i-have-normal-traffic

The schedule (which attack, when, for how long, with which parameters) is drawn
by scenario_sampler.py from the run seed. Burst start times are offsets from t0,
the moment k6 started, so normal traffic and attacks follow one seeded plan.
Each burst runs scripts/attacks/<attack>.py with the manifest parameters as
command-line options; every request it sends is recorded in the run's
origin.jsonl (see provenance.py).

Writes data/runs/<run_id>.json with planned and actual burst times. Exits 1 if
any burst fails, because a run with a missing attack is not a valid run.
"""

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone

PYTHON = sys.executable
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
RUNS_DIR = os.path.join(PROJECT_ROOT, "data", "runs")


def attack_command(burst):
    """argv for one burst: the attack script plus every manifest parameter as
    --<name> <value> (underscores become hyphens)."""
    cmd = [PYTHON, os.path.join(PROJECT_ROOT, "scripts", "attacks", f"{burst['attack']}.py"),
           "--duration", str(burst["duration_s"])]
    for key, value in burst["params"].items():
        cmd += [f"--{key.replace('_', '-')}", str(value)]
    return cmd


def run_manifest(run_id, manifest_path, t0, dry_run):
    manifest = json.load(open(manifest_path, encoding="utf-8"))
    plan = manifest.get("attacks")
    if not plan:
        raise SystemExit(f"[orchestrator] {manifest_path} has no attacks (normal run?)")

    origin_log = os.path.join(RUNS_DIR, run_id, "origin.jsonl")
    os.makedirs(os.path.dirname(origin_log), exist_ok=True)
    env = dict(os.environ, SHADOWTRACE_RUN_ID=run_id, ORIGIN_LOG=origin_log,
               SHADOWTRACE_SEED=str(manifest["seed"]))
    started_at = time.time()
    print(f"\n[*] Run {run_id}: {len(plan['schedule'])} bursts from {manifest_path} "
          f"(t0 = k6 start, {started_at - t0:.0f}s ago)"
          f"{'  DRY-RUN (sleep)' if dry_run else ''}\n")

    bursts = []
    for b in plan["schedule"]:
        wait = t0 + b["start_s"] - time.time()
        if wait > 0:
            print(f"[wait]  {wait:.0f}s of normal traffic until t+{b['start_s']}s")
            time.sleep(wait)
        cmd = ["sleep", str(b["duration_s"])] if dry_run else attack_command(b)
        s_ts = time.time()
        print(f"[burst] {b['attack']:22s} t+{s_ts - t0:5.0f}s (planned t+{b['start_s']}) "
              f"dur {b['duration_s']}s  {b['params']}")
        try:
            rc = subprocess.run(cmd, env=env, check=False, timeout=b["duration_s"] + 60).returncode
        except subprocess.TimeoutExpired:
            rc = "timeout"
            print(f"[!] burst '{b['attack']}' exceeded its timeout; killed.")
        e_ts = time.time()
        print(f"[burst] {b['attack']:22s} end after {e_ts - s_ts:.0f}s (exit {rc})\n")
        bursts.append({"i": b["i"], "attack_type": b["attack"], "params": b["params"],
                       "planned_start_s": b["start_s"], "planned_duration_s": b["duration_s"],
                       "start_ts": round(s_ts, 3), "end_ts": round(e_ts, 3), "exit": rc})

    record = {"run_id": run_id, "manifest": manifest_path, "t0": round(t0, 3),
              "started_at": round(started_at, 3), "ended_at": round(time.time(), 3),
              "created_at": datetime.now(timezone.utc).isoformat(), "dry_run": dry_run,
              "seed": manifest["seed"], "origin_log": origin_log, "attack_bursts": bursts}
    out_path = os.path.join(RUNS_DIR, f"{run_id}.json")
    json.dump(record, open(out_path, "w", encoding="utf-8"), indent=2)
    late = max(b["start_ts"] - t0 - b["planned_start_s"] for b in bursts)
    failed = [b["attack_type"] for b in bursts if b["exit"] != 0]
    print(f"[✓] {len(bursts)} bursts done, max start delay {late:.1f}s -> {out_path}")
    if failed:
        print(f"[✗] bursts with a non-zero exit: {failed} - run is invalid")
        sys.exit(1)
    return record


def main():
    p = argparse.ArgumentParser(description="replay a manifest's attack schedule")
    p.add_argument("--run-id", required=True)
    p.add_argument("--manifest", required=True, help="data/runs/<run_id>/manifest.json")
    p.add_argument("--t0", type=float, help="unix time k6 started (default: now)")
    p.add_argument("--dry-run", action="store_true", help="sleep instead of attacking")
    p.add_argument("--i-have-normal-traffic", action="store_true",
                   help="confirm normal traffic (k6) is already running")
    args = p.parse_args()
    if not args.dry_run and not args.i_have_normal_traffic:
        p.error("attacks must overlap normal traffic: start k6 first and pass "
                "--i-have-normal-traffic (or use --dry-run)")
    run_manifest(args.run_id, args.manifest, args.t0 or time.time(), args.dry_run)


if __name__ == "__main__":
    main()
