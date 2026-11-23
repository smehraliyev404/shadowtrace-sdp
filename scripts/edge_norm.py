"""Edge features for the window graphs, normalised with training runs only.

windows.parquet keeps raw edge statistics; this turns them into the 7 model
features once the run split is known:

    log_count     log(1 + calls on the edge in the window)
    lat_p50_z     z-score of log(1 + median latency) against the edge's NORMAL training windows
    lat_p95_z     same for the p95 latency
    client_err    share of calls with a client-side error (4xx, gRPC client codes)
    server_err    share of calls with a server-side error (5xx, gRPC server codes)
    seen          1 if the edge occurs in a NORMAL training window, else 0
    d_log_count   change of log_count against the previous window (0 calls -> 0)

The reference ("what is normal") is fitted only on training windows without
any attack trace (label_k1 == "normal"), including the normal windows of
attack runs. Attack windows would pull the mean and std towards the attack
and mark attack-only edges as seen. Attack windows are used
by the classifier, not here. Edges never seen in normal training windows get
lat z = 0 and seen = 0.

    from edge_norm import load_windows, fit, transform
    train = load_windows(["run_01", "run_02"], level="L2")
    stats = fit(train)
    feats = transform(load_windows(["run_03"]), stats)   # one row per (run, window, edge)

    ./venv/bin/python scripts/edge_norm.py --train run_01 run_02 --apply run_03
"""

import argparse
import os

import numpy as np
import pandas as pd

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
FEATURES = ["log_count", "lat_p50_z", "lat_p95_z", "client_err", "server_err", "seen", "d_log_count"]
MIN_STD = 0.05          # log-latency std floor, so a near-constant edge does not explode


def load_windows(run_ids, level="L2", features_dir=None):
    d = features_dir or os.path.join(PROJECT_ROOT, "data", "features")
    return pd.concat([pd.read_parquet(os.path.join(d, r, level, "windows.parquet")) for r in run_ids],
                     ignore_index=True)


def edges_long(windows):
    rows = []
    for run, w, edges in zip(windows["run_id"], windows["window"], windows["edges"]):
        for e in edges:
            rows.append({"run_id": run, "window": w, **e})
    return pd.DataFrame(rows)


def fit(train_windows, normal_label="normal"):
    normal = train_windows[train_windows["label_k1"] == normal_label]
    if normal.empty:
        raise ValueError("no normal windows in the training runs")
    e = edges_long(normal)
    e["l50"], e["l95"] = np.log1p(e["lat_p50_us"]), np.log1p(e["lat_p95_us"])
    g = e.groupby(["src", "dst"])
    st = g.agg(mu50=("l50", "mean"), sd50=("l50", "std"), mu95=("l95", "mean"), sd95=("l95", "std"),
               n_windows=("l50", "size")).reset_index()
    st[["sd50", "sd95"]] = st[["sd50", "sd95"]].fillna(0).clip(lower=MIN_STD)
    return {"edges": st, "train_runs": sorted(train_windows["run_id"].unique()),
            "normal_windows": len(normal), "train_windows": len(train_windows)}


def transform(windows, stats):
    e = edges_long(windows).merge(stats["edges"], on=["src", "dst"], how="left")
    seen = e["mu50"].notna()
    e["log_count"] = np.log1p(e["count"])
    e["lat_p50_z"] = np.where(seen, (np.log1p(e["lat_p50_us"]) - e["mu50"]) / e["sd50"], 0.0)
    e["lat_p95_z"] = np.where(seen, (np.log1p(e["lat_p95_us"]) - e["mu95"]) / e["sd95"], 0.0)
    e["seen"] = seen.astype(float)
    return e[["run_id", "window", "src", "dst"] + FEATURES]


def main():
    p = argparse.ArgumentParser(description="fit edge statistics on training runs, apply to others")
    p.add_argument("--train", nargs="+", required=True)
    p.add_argument("--apply", nargs="+", required=True)
    p.add_argument("--level", default="L2")
    a = p.parse_args()
    if set(a.train) & set(a.apply):
        raise SystemExit("a run cannot be both training and evaluation data")
    stats = fit(load_windows(a.train, a.level))
    out = transform(load_windows(a.apply, a.level), stats)
    print(f"[edge_norm] fitted on {stats['normal_windows']} normal of {stats['train_windows']} windows "
          f"in {stats['train_runs']}: {len(stats['edges'])} edges")
    print(out.groupby(["src", "dst"])[["seen", "lat_p50_z", "log_count"]].mean().round(2).to_string())


if __name__ == "__main__":
    main()
