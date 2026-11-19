"""Train one model on one run assignment and seed; write its predictions.

    # batch 3 (lab): assignment 0 of the fixed split, seed 1, L2, k = 3
    ./venv/bin/python -m ml.train --model stgnn --split splits/batch3.json --assignment 0 --seed 1 --level L2 --k 3

    # explicit runs (local testing only)
    ./venv/bin/python -m ml.train --model rf --train run_03 --val leak_02 --test leak_02 --allow-overlap

Models: stgnn (GATv2, main), stgnn_gcn, stgnn_sage, rf, gbm, mlp, svm (flat
baselines tuned by grid search on the validation runs, ml/models.py GRIDS).
Ablations: --no-seen (edge feature "seen" = 0), --no-content (node content features = 0).
Training (PLAN.md §10): class-weighted cross-entropy, Adam lr 0.001, early
stopping on validation macro-F1. Normalisation and vocabularies come from the
training runs only (ml/data.py Prep).

Output results/<name>/: predictions.parquet (part, run, window, label, pred,
p_<class>), config.json (arguments, runs, best epoch, times), history.csv.
"""

import argparse
import json
import os
import random
import time

import numpy as np
import pandas as pd
import torch
import torch.nn.functional as F

from ml.data import CLASSES, L0_REDACTED, NODE_FEATURES, PROJECT_ROOT, Prep, build, load_runs
from ml.metrics import macro_f1
from ml.models import DEFAULTS, GRIDS, STGNN, class_weights, make_flat, resolve_device

MODELS = {"stgnn": "gatv2", "stgnn_gcn": "gcn", "stgnn_sage": "sage", "rf": None, "gbm": None, "mlp": None,
          "svm": None}
PARTS = ("train", "val", "test", "heldout")


def set_seed(seed):
    random.seed(seed)
    np.random.seed(seed)
    torch.manual_seed(seed)


def full_proba(model, X):
    """predict_proba over all CLASSES (classes never seen in training get 0)."""
    p = np.zeros((len(X), len(CLASSES)))
    p[:, model.classes_] = model.predict_proba(X)
    return p


def predict_gnn(model, ds, batch=256):
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(ds), batch):
            out.append(F.softmax(model(ds.graphs, torch.tensor(ds.seq[i:i + batch])), dim=1).cpu().numpy())
    return np.concatenate(out) if out else np.zeros((0, len(CLASSES)))


def batches(ds, size, rng, by_run):
    """Sample index batches for one epoch. by_run: whole runs (shuffled) are packed
    into a batch until it holds >= size samples, so the 12-window sequences of a
    batch share their windows and each window is encoded about once per epoch
    (random batches encode each window ~10 times, one per sequence it is in)."""
    if not by_run:
        order = rng.permutation(len(ds))
        return [order[i:i + size] for i in range(0, len(order), size)]
    runs = [np.flatnonzero(ds.meta["run_id"].to_numpy() == r) for r in ds.meta["run_id"].unique()]
    out, cur = [], []
    for i in rng.permutation(len(runs)):
        cur.extend(runs[i])
        if len(cur) >= size:
            out.append(np.array(cur))
            cur = []
    if cur:
        out.append(np.array(cur))
    return out


def train_gnn(a, data, seed):
    tr, va = data["train"], data.get("val")
    has_val = va is not None and len(va) > 0
    dev = resolve_device(a.device)
    model = STGNN(len(NODE_FEATURES), 7, a.prep.n_services, len(CLASSES), encoder=MODELS[a.model],
                  hidden=a.hidden).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=a.lr)
    w = class_weights(tr.y, len(CLASSES)).to(dev)
    rng = np.random.default_rng(seed)
    best, best_state, best_epoch, wait, hist = -1.0, None, 0, 0, []
    for epoch in range(1, a.epochs + 1):
        model.train()
        loss_sum = 0.0
        for idx in batches(tr, a.batch, rng, a.batching == "run"):
            loss = F.cross_entropy(model(tr.graphs, torch.tensor(tr.seq[idx])), torch.tensor(tr.y[idx]).to(dev), weight=w)
            opt.zero_grad()
            loss.backward()
            opt.step()
            loss_sum += loss.item() * len(idx)
        f1 = macro_f1(va.y, predict_gnn(model, va).argmax(1)) if has_val else float("nan")
        hist.append({"epoch": epoch, "loss": loss_sum / max(len(tr), 1), "val_macro_f1": f1})
        if not has_val:                # no validation runs (laptop tests): train all epochs, keep the last
            best_state, best_epoch = None, epoch
            continue
        if f1 > best:
            best, best_epoch, wait = f1, epoch, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            wait += 1
            if wait >= a.patience:
                break
    if best_state:
        model.load_state_dict(best_state)
    return model, {"best_epoch": best_epoch, "best_val_macro_f1": best, "epochs_run": epoch}, hist


def grid(name, tune):
    from sklearn.model_selection import ParameterGrid
    return [dict(p) for p in ParameterGrid(GRIDS[name])] if tune else [dict(DEFAULTS[name])]


def gbm_in_subprocess(data, seed, tune):
    """LightGBM cannot share a process with torch on macOS (ml/__init__.py)."""
    import subprocess
    import sys
    import tempfile
    parts = [p for p in ("val", "test", "heldout") if p in data]
    has_val = "val" in data and len(data["val"])
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = os.path.join(tmp, "in.npz"), os.path.join(tmp, "out.npz")
        extra = {"y_val": data["val"].y} if has_val else {}
        np.savez(src, X_train=data["train"].flat, y_train=data["train"].y, seed=seed, n_classes=len(CLASSES),
                 grid=json.dumps(grid("gbm", tune and has_val)), **extra,
                 **{f"X_{p}": data[p].flat for p in parts})
        subprocess.run([sys.executable, "-m", "ml.gbm_fit", src, dst], check=True, cwd=PROJECT_ROOT)
        out = np.load(dst)
        info = {"best_params": json.loads(str(out["best"])), "grid_scores": json.loads(str(out["scores"]))}
        return {id(data[p]): out[f"P_{p}"] for p in parts}, info


def fit_flat(name, data, seed, tune):
    """Grid search on the validation runs (one fit per setting on the training runs,
    scored by validation macro-F1); without validation runs or with --no-tune the
    DEFAULTS are used. Returns the best model and the search record."""
    tr, va = data["train"], data.get("val")
    has_val = va is not None and len(va) > 0
    best, scores = None, []
    for params in grid(name, tune and has_val):
        m = make_flat(name, seed, **params)
        if name == "mlp":
            from sklearn.utils.class_weight import compute_sample_weight
            m.fit(tr.flat, tr.y, sample_weight=compute_sample_weight("balanced", tr.y))
        else:
            m.fit(tr.flat, tr.y)
        f1 = macro_f1(va.y, full_proba(m, va.flat).argmax(1)) if has_val else float("nan")
        scores.append({"params": {k: list(v) if isinstance(v, tuple) else v for k, v in params.items()},
                       "val_macro_f1": f1})
        if best is None or f1 > best[0]:
            best = (f1, m, scores[-1]["params"])
    return best[1], {"best_params": best[2], "grid_scores": scores}


def add_split_args(ap):
    """Arguments every model CLI shares: which runs go where, level, k, seed, paths."""
    ap.add_argument("--split", help="split file from scripts/make_split.py")
    ap.add_argument("--assignment", type=int, default=0)
    ap.add_argument("--train", nargs="+")
    ap.add_argument("--val", nargs="*")
    ap.add_argument("--test", nargs="*")
    ap.add_argument("--heldout", nargs="*")
    ap.add_argument("--allow-overlap", action="store_true", help="local testing only: same run in two parts")
    ap.add_argument("--level", default="L2", choices=["L0", "L1", "L2"])
    ap.add_argument("--k", type=int, default=3, choices=[1, 3, 5, 10])
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out-dir", default=os.path.join(PROJECT_ROOT, "results"))
    ap.add_argument("--overwrite", action="store_true", help="replace an existing results folder")
    ap.add_argument("--device", default="auto", help="auto (CUDA if available, else CPU), cpu, cuda, mps")
    ap.add_argument("--l0-redacted", action=argparse.BooleanOptionalAction, default=L0_REDACTED,
                    help="L0 only: c_redacted from the L1 windows (D19); default from ml/data.py L0_REDACTED")


# arguments that say WHICH data a result is for; every other argument is a model setting
DATA_ARGS = {"help", "split", "assignment", "train", "val", "test", "heldout", "allow_overlap", "level", "k",
             "seed", "out_dir", "overwrite", "features_dir", "name", "model", "no_seen", "no_content", "device",
             "l0_redacted"}


def variant(ap, a):
    """Model settings that differ from the defaults, as a name suffix ("hidden16_lr0.01";
    "" with defaults), so results of different settings never share a name."""
    return "_".join(f"{act.dest.replace('_', '')}{getattr(a, act.dest)}" for act in ap._actions
                    if act.dest not in DATA_ARGS and getattr(a, act.dest, act.default) != act.default)


def results_dir(a, model_name):
    """results/<model>_<level>_k<k>_a<assignment>_s<seed>; refuses to replace an existing
    result unless --overwrite (a rerun with other settings must not erase the first)."""
    name = getattr(a, "name", None) or f"{model_name}_{a.level}_k{a.k}_a{a.assignment if a.split else 'x'}_s{a.seed}"
    out = os.path.join(a.out_dir, name)
    if os.path.exists(os.path.join(out, "predictions.parquet")) and not a.overwrite:
        raise SystemExit(f"{out} already has results (use --overwrite to replace them)")
    os.makedirs(out, exist_ok=True)
    return name, out


def split_runs(ap, a):
    """Resolve the runs per part and refuse a run that is in two parts."""
    if not (a.split or a.train):
        ap.error("--split or --train is required")
    runs = resolve_runs(a)
    for i, p in enumerate(PARTS):
        for q in PARTS[i + 1:]:
            both = set(runs[p]) & set(runs[q])
            if both and not a.allow_overlap:
                raise SystemExit(f"runs in both {p} and {q}: {sorted(both)}")
    return runs


def resolve_runs(a):
    if a.split:
        s = json.load(open(a.split))
        asg = s["assignments"][a.assignment]
        return {p: asg.get(p, []) for p in PARTS}
    return {"train": a.train, "val": a.val or [], "test": a.test or [], "heldout": a.heldout or []}


def main():
    ap = argparse.ArgumentParser(description="train one model on one run assignment")
    ap.add_argument("--model", required=True, choices=list(MODELS))
    add_split_args(ap)
    ap.add_argument("--no-seen", action="store_true")
    ap.add_argument("--no-content", action="store_true")
    ap.add_argument("--no-tune", action="store_true",
                    help="flat baselines: use DEFAULTS instead of the grid search on validation runs")
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--patience", type=int, default=20)
    ap.add_argument("--batch", type=int, default=32, help="samples per batch (minimum, with --batching run)")
    ap.add_argument("--batching", choices=["run", "random"], default="run",
                    help="run: whole runs per batch, each window encoded ~once per epoch (default)")
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--hidden", type=int, default=64)
    ap.add_argument("--features-dir")
    ap.add_argument("--name", help="default: model_level_k_assignment_seed[_flags]")
    a = ap.parse_args()
    runs = split_runs(ap, a)
    v = variant(ap, a)
    model_name = a.model + ("_noseen" if a.no_seen else "") + ("_nocontent" if a.no_content else "") + (f"_{v}" if v else "")
    name, out = results_dir(a, model_name)          # before training: refuse early, not after an hour
    set_seed(a.seed)
    t0 = time.time()
    windows = {p: load_runs(r, a.level, a.features_dir, a.l0_redacted) for p, r in runs.items() if r}
    a.prep = Prep.fit(windows["train"])
    assert set(a.prep.train_runs) == set(runs["train"]), "normalisation must come from training runs only"
    data = {p: build(w, a.prep, a.k, use_seen=not a.no_seen, use_content=not a.no_content)
            for p, w in windows.items()}

    info, hist = {}, []
    if MODELS[a.model]:
        model, info, hist = train_gnn(a, data, a.seed)
        predict = lambda ds: predict_gnn(model, ds)  # noqa: E731
    elif a.model == "gbm":
        probs, info = gbm_in_subprocess(data, a.seed, not a.no_tune)
        predict = lambda ds: probs[id(ds)]  # noqa: E731
    else:
        model, info = fit_flat(a.model, data, a.seed, not a.no_tune)
        predict = lambda ds: full_proba(model, ds.flat)  # noqa: E731

    rows = []
    for p in ("val", "test", "heldout"):
        ds = data.get(p)
        if ds is None or not len(ds):
            continue
        prob = predict(ds)
        d = ds.meta.copy()
        d.insert(0, "part", p)
        d["y"], d["pred"] = ds.y, prob.argmax(1)
        for i, c in enumerate(CLASSES):
            d[f"p_{c}"] = prob[:, i]
        rows.append(d)
    pred = pd.concat(rows, ignore_index=True)

    pred.to_parquet(os.path.join(out, "predictions.parquet"), index=False)
    if hist:
        pd.DataFrame(hist).to_csv(os.path.join(out, "history.csv"), index=False)
    cfg = {k: v for k, v in vars(a).items() if k != "prep"}
    cfg.update({"model_name": model_name, "device_used": str(resolve_device(a.device)), "runs": runs, "assignment": a.assignment if a.split else None,
                "n_samples": {p: len(d) for p, d in data.items()},
                "train_labels": pd.Series(data["train"].meta["label"]).value_counts().to_dict(),
                "services": a.prep.services, "edge_vocab": len(a.prep.edge_vocab),
                "normal_windows_for_edge_stats": a.prep.edge_stats["normal_windows"],
                "seconds": round(time.time() - t0, 1), **info})
    json.dump(cfg, open(os.path.join(out, "config.json"), "w"), indent=1, default=str)
    msg = "  ".join(f"{p} macro-F1 {macro_f1(g['y'].to_numpy(), g['pred'].to_numpy()):.3f}"
                    for p, g in pred.groupby("part"))
    print(f"[train] {name}: {msg}  ({cfg['seconds']} s) -> {out}")


if __name__ == "__main__":
    main()
