"""Train one model on one run assignment and seed; write its predictions.

    # batch 3 (lab): assignment 0 of the fixed split, seed 1, L2, k = 3
    ./venv/bin/python -m ml.train --model stgnn --split splits/batch3.json --assignment 0 --seed 1 --level L2 --k 3

    # explicit runs (local testing only)
    ./venv/bin/python -m ml.train --model rf --train run_03 --val leak_02 --test leak_02 --allow-overlap

Models: stgnn (GATv2, main), stgnn_gcn, stgnn_sage, rf, gbm, mlp.
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

from ml.data import CLASSES, NODE_FEATURES, PROJECT_ROOT, Prep, build, load_runs
from ml.metrics import macro_f1
from ml.models import STGNN, class_weights, make_flat

MODELS = {"stgnn": "gatv2", "stgnn_gcn": "gcn", "stgnn_sage": "sage", "rf": None, "gbm": None, "mlp": None}
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
            out.append(F.softmax(model(ds.graphs, torch.tensor(ds.seq[i:i + batch])), dim=1).numpy())
    return np.concatenate(out) if out else np.zeros((0, len(CLASSES)))


def train_gnn(a, data, seed):
    tr, va = data["train"], data["val"]
    model = STGNN(len(NODE_FEATURES), 7, a.prep.n_services, len(CLASSES), encoder=MODELS[a.model],
                  hidden=a.hidden)
    opt = torch.optim.Adam(model.parameters(), lr=a.lr)
    w = class_weights(tr.y, len(CLASSES))
    rng = np.random.default_rng(seed)
    best, best_state, best_epoch, wait, hist = -1.0, None, 0, 0, []
    for epoch in range(1, a.epochs + 1):
        model.train()
        order, loss_sum = rng.permutation(len(tr)), 0.0
        for i in range(0, len(order), a.batch):
            idx = order[i:i + a.batch]
            loss = F.cross_entropy(model(tr.graphs, torch.tensor(tr.seq[idx])), torch.tensor(tr.y[idx]), weight=w)
            opt.zero_grad()
            loss.backward()
            opt.step()
            loss_sum += loss.item() * len(idx)
        f1 = macro_f1(va.y, predict_gnn(model, va).argmax(1)) if len(va) else float("nan")
        hist.append({"epoch": epoch, "loss": loss_sum / max(len(tr), 1), "val_macro_f1": f1})
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


def gbm_in_subprocess(data, seed):
    """LightGBM cannot share a process with torch on macOS (ml/__init__.py)."""
    import subprocess
    import sys
    import tempfile
    parts = [p for p in ("val", "test", "heldout") if p in data]
    with tempfile.TemporaryDirectory() as tmp:
        src, dst = os.path.join(tmp, "in.npz"), os.path.join(tmp, "out.npz")
        np.savez(src, X_train=data["train"].flat, y_train=data["train"].y, seed=seed, n_classes=len(CLASSES),
                 **{f"X_{p}": data[p].flat for p in parts})
        subprocess.run([sys.executable, "-m", "ml.gbm_fit", src, dst], check=True, cwd=PROJECT_ROOT)
        out = np.load(dst)
        return {id(data[p]): out[f"P_{p}"] for p in parts}


def resolve_runs(a):
    if a.split:
        s = json.load(open(a.split))
        asg = s["assignments"][a.assignment]
        return {p: asg.get(p, []) for p in PARTS}
    return {"train": a.train, "val": a.val or [], "test": a.test or [], "heldout": a.heldout or []}


def main():
    ap = argparse.ArgumentParser(description="train one model on one run assignment")
    ap.add_argument("--model", required=True, choices=list(MODELS))
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
    ap.add_argument("--no-seen", action="store_true")
    ap.add_argument("--no-content", action="store_true")
    ap.add_argument("--epochs", type=int, default=200)
    ap.add_argument("--patience", type=int, default=20)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--hidden", type=int, default=64)
    ap.add_argument("--features-dir")
    ap.add_argument("--out-dir", default=os.path.join(PROJECT_ROOT, "results"))
    ap.add_argument("--name", help="default: model_level_k_assignment_seed[_flags]")
    a = ap.parse_args()
    if not (a.split or a.train):
        ap.error("--split or --train is required")

    runs = resolve_runs(a)
    for i, p in enumerate(PARTS):
        for q in PARTS[i + 1:]:
            both = set(runs[p]) & set(runs[q])
            if both and not a.allow_overlap:
                raise SystemExit(f"runs in both {p} and {q}: {sorted(both)}")
    set_seed(a.seed)
    t0 = time.time()
    windows = {p: load_runs(r, a.level, a.features_dir) for p, r in runs.items() if r}
    a.prep = Prep.fit(windows["train"])
    assert set(a.prep.train_runs) == set(runs["train"]), "normalisation must come from training runs only"
    data = {p: build(w, a.prep, a.k, use_seen=not a.no_seen, use_content=not a.no_content)
            for p, w in windows.items()}

    model_name = a.model + ("_noseen" if a.no_seen else "") + ("_nocontent" if a.no_content else "")
    info, hist = {}, []
    if MODELS[a.model]:
        model, info, hist = train_gnn(a, data, a.seed)
        predict = lambda ds: predict_gnn(model, ds)  # noqa: E731
    elif a.model == "gbm":
        probs = gbm_in_subprocess(data, a.seed)
        predict = lambda ds: probs[id(ds)]  # noqa: E731
    else:
        model = make_flat(a.model, a.seed)
        tr = data["train"]
        if a.model == "mlp":
            from sklearn.utils.class_weight import compute_sample_weight
            model.fit(tr.flat, tr.y, sample_weight=compute_sample_weight("balanced", tr.y))
        else:
            model.fit(tr.flat, tr.y)
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

    name = a.name or f"{model_name}_{a.level}_k{a.k}_a{a.assignment if a.split else 'x'}_s{a.seed}"
    out = os.path.join(a.out_dir, name)
    os.makedirs(out, exist_ok=True)
    pred.to_parquet(os.path.join(out, "predictions.parquet"), index=False)
    if hist:
        pd.DataFrame(hist).to_csv(os.path.join(out, "history.csv"), index=False)
    cfg = {k: v for k, v in vars(a).items() if k != "prep"}
    cfg.update({"model_name": model_name, "runs": runs, "assignment": a.assignment if a.split else None,
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
