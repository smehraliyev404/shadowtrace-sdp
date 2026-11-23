"""Simple rule detectors as a reference point: is a learned model needed at all?

    ./venv/bin/python -m ml.rules --split splits/batch3.json --assignment 0

Each rule is one hand-picked window statistic of the kind an operator would put
on a dashboard alarm. It is standardised with the mean and SD of the NORMAL
training windows and fires above the 99th percentile of the validation normal
windows (the same 1 % target the models' thresholds use). "any" fires when any
single rule exceeds its own threshold, recalibrated on validation so that it
too targets 1 %.

  volume         log(1 + traces in the window)          floods, exfiltration
  client_errors  share of calls that end in a 4xx        brute force, probing
  server_errors  share of calls that end in a 5xx        SQLi, faults
  auth_failures  error share of authservice spans        brute-force variants
  new_edges      caller -> callee pairs never seen in    SSRF, lateral movement
                 normal training windows
  latency        log p95 trace duration                  load-heavy attacks

Every rule is written as a detector (config "detector": true, as Jacob) to
results/rules_<rule>_<level>_k<k>_a<assignment>_s<seed>/, so ml.metrics and
ml.summary score it unchanged. Structure and timing only, so L2 is the level.
"""

import argparse
import json
import os
import time

import numpy as np
import pandas as pd

from ml.data import CLASSES, load_runs
from ml.train import add_split_args, results_dir, split_runs

FLAGGED = len(CLASSES)          # a detector names no class (as ml/jacob.py)
RULES = ("volume", "client_errors", "server_errors", "auth_failures", "new_edges", "latency")


def raw(w, normal_edges):
    auth = [next((n["err_share"] for n in nodes if n["service"] == "authservice"), 0.0) for nodes in w["nodes"]]
    new = [sum((e["src"], e["dst"]) not in normal_edges for e in edges) for edges in w["edges"]]
    return pd.DataFrame({"volume": np.log1p(w["n_traces"].astype(float)),
                         "client_errors": w["client_err"].astype(float),
                         "server_errors": w["server_err"].astype(float),
                         "auth_failures": np.array(auth, float),
                         "new_edges": np.array(new, float),
                         "latency": np.log1p(w["trace_p95_us"].astype(float))})


def samples(w, k):
    lab = w[f"label_k{k}"]
    return w[(lab != "excluded") & w["complete"]].reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser(description="rule detectors on window statistics")
    add_split_args(ap)
    ap.add_argument("--features-dir")
    a = ap.parse_args()
    runs = split_runs(ap, a)
    if not runs.get("val"):
        ap.error("rules need validation runs for their thresholds")
    outs = {r: results_dir(a, f"rules_{r}") for r in RULES + ("any",)}     # refuse before any work
    t0 = time.time()
    win = {p: samples(load_runs(r, a.level, a.features_dir), a.k) for p, r in runs.items() if r}
    tr = win["train"]
    tr_normal = tr[tr[f"label_k{a.k}"] == "normal"]
    normal_edges = {(e["src"], e["dst"]) for edges in tr_normal["edges"] for e in edges}
    x_tr = raw(tr_normal, normal_edges)
    mu = x_tr.mean()
    sd = x_tr.std().where(x_tr.std() > 1e-9, 1.0)
    mu["new_edges"], sd["new_edges"] = 0.0, 1.0                    # a count: 0 is normal, every new pair counts

    z = {p: (raw(w, normal_edges) - mu) / sd for p, w in win.items()}
    vn = win["val"][f"label_k{a.k}"] == "normal"
    thr = {r: float(np.quantile(z["val"].loc[vn, r], 0.99)) for r in RULES}
    s = {p: pd.DataFrame({r: zz[r] - thr[r] for r in RULES}) for p, zz in z.items()}
    for p in s:
        s[p]["any"] = s[p][list(RULES)].max(axis=1)
    thr_any = float(np.quantile(s["val"].loc[vn, "any"], 0.99))
    for p in s:
        s[p]["any"] = s[p]["any"] - thr_any

    for rule, (name, out) in outs.items():
        rows = []
        for p in ("val", "test", "heldout"):
            if p not in win:
                continue
            w, sc = win[p], s[p][rule].to_numpy()
            d = w[["run_id", "run_kind", "window"]].copy()
            d.insert(0, "part", p)
            d["label"] = w[f"label_k{a.k}"].to_numpy()
            d["y"] = [CLASSES.index(lab) for lab in d["label"]]
            d["pred"] = np.where(sc > 0, FLAGGED, 0)
            p_normal = 1.0 / (1.0 + np.exp(np.clip(sc, -50, 50)))    # 0.5 exactly at the threshold
            d["p_normal"] = p_normal
            for c in CLASSES[1:]:
                d[f"p_{c}"] = (1 - p_normal) / (len(CLASSES) - 1)
            rows.append(d)
        pred = pd.concat(rows, ignore_index=True)
        pred.to_parquet(os.path.join(out, "predictions.parquet"), index=False)
        cfg = {k: v for k, v in vars(a).items()}
        cfg.update({"model_name": f"rules_{rule}", "rule": rule, "detector": True, "runs": runs,
                    "assignment": a.assignment if a.split else None,
                    "threshold_z": thr.get(rule, thr_any), "train_normal_mean": mu.to_dict(), "train_normal_sd": sd.to_dict(),
                    "normal_edges": len(normal_edges), "seconds": round(time.time() - t0, 1)})
        json.dump(cfg, open(os.path.join(out, "config.json"), "w"), indent=1, default=str)
        msg = "  ".join(f"{p}: flagged {int((g['pred'] != 0).sum())}/{len(g)} "
                        f"(normal {int(((g['pred'] != 0) & (g['y'] == 0)).sum())}/{int((g['y'] == 0).sum())})"
                        for p, g in pred.groupby("part"))
        print(f"[rules] {name}: {msg}")
    print(f"[rules] {len(outs)} detectors in {time.time() - t0:.1f} s")


if __name__ == "__main__":
    main()
