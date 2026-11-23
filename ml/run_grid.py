"""Run the experiment grid (PLAN.md §11) in priority order, unattended.

    ./venv/bin/python -m ml.run_grid --dry-run                       # show the plan
    ./venv/bin/python -m ml.run_grid --stages main --jobs 4          # first full table
    ./venv/bin/python -m ml.run_grid --stages seeds,ablations,k --jobs 4

Stages (each is a list of trainings; one training = one model, level, k,
assignment and seed, run by ml.train / ml.jacob / ml.ma):

  batching   ST-GNN with --batching run vs random, assignment 0, seed 1, L2
             (the one decision PLAN.md asks for before the full runs)
  main       k = 3, seed 1, all 5 assignments: ST-GNN (GATv2, GCN, SAGE), RF,
             LightGBM, MLP, SVM and Ma at L0, L1, L2; Jacob once (its input,
             operation-pair counts, is the same at every level) -> the first table
  seeds      the same with seeds 2-5 (25 repetitions per model and level)
  ablations  ST-GNN without "seen" (L0, L1, L2) and without content features
             (L0, L1; at L2 they are 0 anyway), 5 assignments x 5 seeds
  k          k = 1, 5, 10: every model at every level, seed 1, 5 assignments
  loao       leave-one-attack-out: ST-GNN, SVM, LightGBM, RF, MLP trained without
             one attack type (every window holding any of its traces dropped from
             training and validation), L2, k = 3, seed 1, 5 assignments, 8 attacks
  rules      simple rule detectors (ml.rules), L2, k = 3, 5 assignments

A training whose result folder already exists is skipped (the model scripts
refuse to overwrite), so the same command continues after a stop. Each
training's output goes to results/logs/<name>.log; a summary to
results/grid_<time>.log. Failed trainings are listed at the end and do not stop
the rest.
"""

import argparse
import os
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
LEVELS = ("L0", "L1", "L2")
WINDOW_MODELS = ("stgnn", "stgnn_gcn", "stgnn_sage", "rf", "gbm", "mlp", "svm")
STAGES = ("batching", "main", "seeds", "ablations", "k", "loao", "rules")
LOAO_MODELS = ("stgnn", "svm", "gbm", "rf", "mlp")
ATTACKS = ("http_flood", "exfiltration", "sqli_probe", "brute_force", "session_rotation_brute",
           "slow_brute", "ssrf_probe", "lateral_movement")


def job(module, level, k, assignment, seed, extra=(), name=None):
    """name: model name plus its flags, e.g. 'stgnn_noseen' or 'stgnn_batching-random'."""
    args = ["--split", "{split}", "--assignment", str(assignment), "--seed", str(seed),
            "--level", level, "--k", str(k), *extra]
    name = name or module.split(".")[-1]
    return {"module": module, "args": args, "model": name,
            "label": f"{name} {level} k{k} a{assignment} s{seed}"}


def window(model, level, k, a, s, *flags):
    tag = "".join("_" + f.lstrip("-").replace("-", "") if f.startswith("--") else "-" + f for f in flags)
    return job("ml.train", level, k, a, s, ("--model", model, *flags), name=model + tag)


def plan(stage, assignments, seeds):
    jobs = []
    if stage == "batching":
        for b in ("run", "random"):
            jobs.append(window("stgnn", "L2", 3, assignments[0], 1, "--batching", b))
        return jobs
    if stage in ("main", "seeds", "k"):
        ks = [3] if stage != "k" else [1, 5, 10]
        ss = [1] if stage != "seeds" else [s for s in seeds if s != 1]
        for k in ks:
            for s in ss:
                for lv in LEVELS:                     # level-major: a usable table per level early
                    for a in assignments:
                        jobs += [window(m, lv, k, a, s) for m in WINDOW_MODELS]
                        jobs.append(job("ml.ma", lv, k, a, s))
                        if lv == "L2":
                            jobs.append(job("ml.jacob", lv, k, a, s))
        return jobs
    if stage == "ablations":
        for s in seeds:
            for lv in LEVELS:
                for a in assignments:
                    jobs.append(window("stgnn", lv, 3, a, s, "--no-seen"))
                    if lv != "L2":
                        jobs.append(window("stgnn", lv, 3, a, s, "--no-content"))
        return jobs
    if stage == "loao":
        for att in ATTACKS:
            for a in assignments:
                jobs += [window(m, "L2", 3, a, 1, "--leave-out", att) for m in LOAO_MODELS]
        return jobs
    if stage == "rules":
        return [job("ml.rules", "L2", 3, a, 1) for a in assignments]
    raise ValueError(stage)


def run_one(j, split, extra, log_dir, env):
    cmd = [sys.executable, "-m", j["module"], *[x.replace("{split}", split) for x in j["args"]], *extra]
    name = j["label"].replace(" ", "_")
    log = os.path.join(log_dir, name + ".log")
    t0 = time.time()
    with open(log, "w") as f:
        f.write(" ".join(cmd) + "\n\n")
        f.flush()
        rc = subprocess.run(cmd, cwd=PROJECT_ROOT, stdout=f, stderr=subprocess.STDOUT, env=env).returncode
    text = open(log).read()
    if rc != 0 and "already has results" in text:
        status = "skipped"
    else:
        status = "done" if rc == 0 else f"FAILED (exit {rc})"
    lines = text.strip().splitlines()
    last = [ln for ln in lines if ln.startswith("[")][-1:] if status == "done" else lines[-1:]
    return j["label"], status, round(time.time() - t0), (last or [""])[0], log


def main():
    ap = argparse.ArgumentParser(description="run the experiment grid in priority order")
    ap.add_argument("--stages", default="main", help=f"comma-separated, from {','.join(STAGES)}")
    ap.add_argument("--split", default=os.path.join(PROJECT_ROOT, "splits", "batch3.json"))
    ap.add_argument("--assignments", default="0,1,2,3,4")
    ap.add_argument("--seeds", default="1,2,3,4,5")
    ap.add_argument("--models", help="only these (e.g. stgnn,rf,jacob,ma); default all")
    ap.add_argument("--levels", help="only these levels (e.g. L2); default all")
    ap.add_argument("--jobs", type=int, default=2, help="trainings in parallel")
    ap.add_argument("--extra", default="", help="arguments added to every training; write it with '=': --extra='--device cpu'")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    stages = [s for s in a.stages.split(",") if s]
    bad = set(stages) - set(STAGES)
    if bad:
        ap.error(f"unknown stage(s) {sorted(bad)}")
    assignments = [int(x) for x in a.assignments.split(",")]
    seeds = [int(x) for x in a.seeds.split(",")]
    jobs = [j for s in stages for j in plan(s, assignments, seeds)]
    if a.models:
        keep = set(a.models.split(","))
        jobs = [j for j in jobs if j["model"] in keep
                or (j["module"] == "ml.train" and j["args"][j["args"].index("--model") + 1] in keep)]
    if a.levels:
        lv = set(a.levels.split(","))
        jobs = [j for j in jobs if j["args"][j["args"].index("--level") + 1] in lv]
    extra = a.extra.split()

    print(f"[grid] {len(jobs)} trainings in stage(s) {stages}, {a.jobs} at a time")
    if a.dry_run:
        for j in jobs:
            print("  " + j["label"])
        return

    log_dir = os.path.join(PROJECT_ROOT, "results", "logs")
    os.makedirs(log_dir, exist_ok=True)
    summary = os.path.join(PROJECT_ROOT, "results", f"grid_{datetime.now():%Y%m%d_%H%M%S}.log")
    env = dict(os.environ)
    threads = max(1, (os.cpu_count() or 2) // max(1, a.jobs))
    env.setdefault("OMP_NUM_THREADS", str(threads))      # parallel trainings share the CPU
    counts, failed = {}, []
    with open(summary, "w") as out, ThreadPoolExecutor(a.jobs) as pool:
        futs = [pool.submit(run_one, j, a.split, extra, log_dir, env) for j in jobs]
        for i, f in enumerate(as_completed(futs), 1):
            label, status, secs, last, log = f.result()
            key = status.split()[0]
            counts[key] = counts.get(key, 0) + 1
            line = f"[{i}/{len(jobs)}] {status:9s} {label} ({secs} s) {last}"
            print(line, flush=True)
            out.write(line + "\n")
            out.flush()
            if status.startswith("FAILED"):
                failed.append((label, log))
    print(f"[grid] {counts} -> {summary}")
    for label, log in failed:
        print(f"  failed: {label}  (see {log})")
    sys.exit(1 if failed else 0)


if __name__ == "__main__":
    main()
