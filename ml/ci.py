"""95 % confidence intervals for the main table: two-level bootstrap.

    ./venv/bin/python -m ml.ci results/*_k3_a*_s*/predictions.parquet --part heldout --jobs 16 --out results/ci_k3_heldout.json

The table value of a model at one level is the mean over its repetitions
(assignment x seed). Its uncertainty has two sources: which runs happen to be in
the test set (the assignment) and which windows of those runs we saw (windows
are autocorrelated). Each bootstrap replicate therefore
  1. draws the assignments with replacement,
  2. for each drawn assignment picks one of its seeds at random,
  3. block-resamples that training's windows (blocks of --block-len consecutive
     windows of one run, as in ml.metrics),
and averages the metric over the drawn assignments. The 2.5 / 97.5 percentiles
of the replicates are the interval. Metrics: macro-F1 (classifiers), binary-F1,
the false-positive rate at the validation threshold, and the ROC area up to
1 % FPR.
"""

import argparse
import json
import os
from concurrent.futures import ProcessPoolExecutor

import numpy as np
import pandas as pd

from ml.metrics import blocks, bounded_auc, macro_f1, val_threshold

METRICS = ("macro_f1", "binary_f1", "fpr_at_val_threshold", "pauc_1fpr")


def load(path, part):
    pred = pd.read_parquet(path)
    cfg = json.load(open(os.path.join(os.path.dirname(path), "config.json")))
    val = pred[pred["part"] == "val"]
    thr = val_threshold(val) if len(val) else None
    d = pred[pred["part"] == part].reset_index(drop=True)
    if d.empty:
        return None
    return {"group": f"{cfg['level']} k{cfg['k']}", "model": cfg["model_name"],
            "assignment": cfg.get("assignment"), "seed": cfg["seed"], "detector": bool(cfg.get("detector")),
            "y": d["y"].to_numpy(), "pred": d["pred"].to_numpy(), "score": 1 - d["p_normal"].to_numpy(),
            "thr": thr, "blocks": blocks(d, BLOCK_LEN)}


def metrics_of(y, pred, score, thr, detector):
    atk = y != 0
    out = {"macro_f1": float("nan") if detector else macro_f1(y, pred),
           "binary_f1": macro_f1(atk.astype(int), (pred != 0).astype(int)),
           "fpr_at_val_threshold": float((score[~atk] > thr).mean()) if thr is not None and (~atk).any() else float("nan"),
           "pauc_1fpr": bounded_auc(atk, score)}
    return out


def interval(job):
    (group, model), reps, n_boot, seed = job
    rng = np.random.default_rng(seed)
    by_asg = {}
    for r in reps:
        by_asg.setdefault(r["assignment"], []).append(r)
    asgs = sorted(by_asg, key=str)
    point = {m: float(np.nanmean([metrics_of(r["y"], r["pred"], r["score"], r["thr"], r["detector"])[m] for r in reps]))
             for m in METRICS}
    boot = {m: [] for m in METRICS}
    for _ in range(n_boot):
        vals = {m: [] for m in METRICS}
        for a in rng.choice(len(asgs), len(asgs), replace=True):
            cand = by_asg[asgs[a]]
            r = cand[rng.integers(len(cand))]
            idx = np.concatenate([r["blocks"][i] for i in rng.integers(len(r["blocks"]), size=len(r["blocks"]))])
            m_ = metrics_of(r["y"][idx], r["pred"][idx], r["score"][idx], r["thr"], r["detector"])
            for m in METRICS:
                vals[m].append(m_[m])
        for m in METRICS:
            boot[m].append(np.nanmean(vals[m]) if not np.all(np.isnan(vals[m])) else np.nan)
    ci = {}
    for m in METRICS:
        b = np.array(boot[m], float)
        b = b[~np.isnan(b)]
        ci[m] = [float(np.percentile(b, 2.5)), float(np.percentile(b, 97.5))] if len(b) else None
    return {"group": group, "model": model, "reps": len(reps), "assignments": len(asgs),
            "point": point, "ci95": ci}


BLOCK_LEN = 10


def main():
    global BLOCK_LEN
    ap = argparse.ArgumentParser(description="two-level (assignment, block) bootstrap CIs per model and level")
    ap.add_argument("predictions", nargs="+")
    ap.add_argument("--part", default="test", choices=["val", "test", "heldout"])
    ap.add_argument("--n-boot", type=int, default=1000)
    ap.add_argument("--block-len", type=int, default=10)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out")
    a = ap.parse_args()
    BLOCK_LEN = a.block_len
    files = [load(p, a.part) for p in a.predictions]
    groups = {}
    for f in files:
        if f:
            groups.setdefault((f["group"], f["model"]), []).append(f)
    jobs = [(k, v, a.n_boot, a.seed + i) for i, (k, v) in enumerate(sorted(groups.items()))]
    if a.jobs > 1:
        with ProcessPoolExecutor(a.jobs) as pool:
            res = list(pool.map(interval, jobs))
    else:
        res = [interval(j) for j in jobs]
    print(f"=== {a.part}: mean over repetitions [95 % CI, two-level bootstrap, {a.n_boot} replicates]")
    for r in res:
        cells = []
        for m in METRICS:
            p, c = r["point"][m], r["ci95"][m]
            if np.isnan(p):
                continue
            cells.append(f"{m} {p:.3f} [{c[0]:.3f}, {c[1]:.3f}]" if c else f"{m} {p:.3f}")
        print(f"{r['group']:<7} {r['model']:<26} n={r['reps']:<3} " + "  ".join(cells))
    if a.out:
        json.dump({"part": a.part, "n_boot": a.n_boot, "block_len": a.block_len, "results": res},
                  open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
