"""Shortcut probes and the L0-vs-L1 content check (robustness checks).

    ./venv/bin/python -m ml.probes --split splits/batch3.json --assignment 0 --levels L0,L1,L2

Per level, on the flat window features (the input of RF / LightGBM / MLP / SVM):

1. One-feature probes: for every feature that varies in training, a depth-3
   decision tree (class-weighted) trained on that feature alone; macro-F1 and
   binary-F1 (normal vs attack) on test and held-out runs. A single feature
   that comes close to the full models means the task has a shortcut.
2. Best single feature per attack: one-vs-rest ROC AUC of each raw feature on
   the test runs (max of AUC and 1 - AUC). Expected pairs (c_inject for SQLi,
   window request counts for floods) are fine; odd ones are worth a look.
3. Content features (L0 / L1 only; at L2 they are 0): how far each content
   column of the normal windows moves between training and held-out runs
   (Kolmogorov-Smirnov statistic), and a random forest trained with and
   without the content columns, scored on test and held-out runs (macro-F1 and
   the share of normal windows it calls attack). If L0 is worse than L1 on
   held-out only with content, the L0 content values are run-specific.

Writes results/probes/probes_<level>_a<assignment>.json.
"""

import argparse
import json
import os
import time
import warnings

import numpy as np
from scipy.stats import ks_2samp
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.tree import DecisionTreeClassifier

from ml.data import CLASSES, CONTENT_FEATURES, Prep, build, load_runs
from ml.metrics import macro_f1
from ml.train import add_split_args, split_runs

PARTS_EVAL = ("test", "heldout")
warnings.filterwarnings("ignore", message=".*sklearn.utils.parallel.delayed.*")   # harmless, floods the log


def scores(y, pred):
    return {"macro_f1": macro_f1(y, pred),
            "binary_f1": macro_f1((y != 0).astype(int), (pred != 0).astype(int)),
            "normal_called_attack": float((pred[y == 0] != 0).mean()) if (y == 0).any() else float("nan")}


def one_feature_probes(data, names, seed):
    tr = data["train"]
    var = tr.flat.std(0) > 1e-9
    rows = []
    for j in np.flatnonzero(var):
        t = DecisionTreeClassifier(max_depth=3, class_weight="balanced", random_state=seed)
        t.fit(tr.flat[:, [j]], tr.y)
        row = {"feature": names[j]}
        for p in PARTS_EVAL:
            if p in data and len(data[p]):
                s = scores(data[p].y, t.predict(data[p].flat[:, [j]]))
                row[f"{p}_macro_f1"], row[f"{p}_binary_f1"] = s["macro_f1"], s["binary_f1"]
        rows.append(row)
    return sorted(rows, key=lambda r: -r.get("test_macro_f1", 0))


def best_feature_per_attack(ds, names):
    out = {}
    for ci, c in enumerate(CLASSES[1:], 1):
        yy = ds.y == ci
        if not yy.any() or yy.all():
            continue
        y01 = yy | (ds.y == 0)                     # this attack vs normal windows only
        best = (0.5, None)
        for j in range(ds.flat.shape[1]):
            x = ds.flat[y01, j]
            if x.std() < 1e-9:
                continue
            auc = roc_auc_score(yy[y01], x)
            auc = max(auc, 1 - auc)
            if auc > best[0]:
                best = (auc, names[j])
        out[c] = {"feature": best[1], "auc": round(float(best[0]), 4)}
    return out


def content_columns(names):
    return [j for j, n in enumerate(names) if n.startswith("n_") and n.endswith(CONTENT_FEATURES)]


def content_check(data, names, seed):
    cols = content_columns(names)
    tr = data["train"]
    drift = []
    for j in cols:
        a = tr.flat[tr.y == 0, j]
        if a.std() < 1e-9:
            continue
        row = {"feature": names[j]}
        for p in PARTS_EVAL:
            if p in data and (data[p].y == 0).any():
                b = data[p].flat[data[p].y == 0, j]
                row[f"ks_{p}"] = float(ks_2samp(a, b).statistic)
                row[f"mean_train_normal"], row[f"mean_{p}_normal"] = float(a.mean()), float(b.mean())
        drift.append(row)
    drift.sort(key=lambda r: -r.get("ks_heldout", 0))

    rf = {}
    for label, zero in (("with_content", False), ("without_content", True)):
        def X(ds):
            x = ds.flat.copy()
            if zero:
                x[:, cols] = 0.0
            return x
        m = RandomForestClassifier(n_estimators=300, class_weight="balanced", n_jobs=-1, random_state=seed)
        m.fit(X(tr), tr.y)
        rf[label] = {p: scores(data[p].y, m.predict(X(data[p]))) for p in PARTS_EVAL if p in data and len(data[p])}
        imp = np.argsort(-m.feature_importances_)[:10]
        rf[label]["top_features"] = [(names[j], round(float(m.feature_importances_[j]), 4)) for j in imp]
    return {"n_content_columns": len(cols), "drift_normal_windows": drift[:15], "random_forest": rf}


def main():
    ap = argparse.ArgumentParser(description="one-feature shortcut probes and the L0/L1 content check")
    add_split_args(ap)
    ap.add_argument("--levels", default="L0,L1,L2")
    ap.add_argument("--top", type=int, default=15, help="probes to print")
    ap.add_argument("--features-dir")
    a = ap.parse_args()
    runs = split_runs(ap, a)
    out_dir = os.path.join(a.out_dir, "probes")
    os.makedirs(out_dir, exist_ok=True)
    for level in a.levels.split(","):
        t0 = time.time()
        raw = {p: load_runs(r, level, a.features_dir) for p, r in runs.items() if r}
        prep = Prep.fit(raw["train"])
        data = {p: build(w, prep, k=a.k) for p, w in raw.items()}
        names = prep.flat_names
        res = {"level": level, "k": a.k, "assignment": a.assignment if a.split else None, "seed": a.seed,
               "runs": {p: r for p, r in runs.items()}, "n_features": len(names),
               "windows": {p: int(len(d)) for p, d in data.items()}}
        res["one_feature"] = one_feature_probes(data, names, a.seed)
        if "test" in data and len(data["test"]):
            res["best_feature_per_attack_test"] = best_feature_per_attack(data["test"], names)
        if level != "L2":
            res["content"] = content_check(data, names, a.seed)
        path = os.path.join(out_dir, f"probes_{level}_k{a.k}_a{res['assignment'] if a.split else 'x'}.json")
        json.dump(res, open(path, "w"), indent=1)

        print(f"\n=== {level} k{a.k}: {len(names)} flat features, windows {res['windows']} ({time.time() - t0:.0f} s)")
        print(f"one-feature probes, top {a.top} by test macro-F1 (depth-3 tree on one feature):")
        for r in res["one_feature"][:a.top]:
            print(f"  {r['feature']:<48} test macro {r.get('test_macro_f1', float('nan')):.3f} "
                  f"binary {r.get('test_binary_f1', float('nan')):.3f} | held-out macro "
                  f"{r.get('heldout_macro_f1', float('nan')):.3f} binary {r.get('heldout_binary_f1', float('nan')):.3f}")
        if "best_feature_per_attack_test" in res:
            print("best single feature per attack (test, attack vs normal ROC AUC):")
            for c, v in res["best_feature_per_attack_test"].items():
                print(f"  {c:<26} {v['auc']:.3f}  {v['feature']}")
        if "content" in res:
            c = res["content"]
            print(f"content columns: {c['n_content_columns']}; most drifted between train and held-out normal windows (KS):")
            for r in c["drift_normal_windows"][:8]:
                print(f"  {r['feature']:<40} KS held-out {r.get('ks_heldout', float('nan')):.3f}  test "
                      f"{r.get('ks_test', float('nan')):.3f}  mean train {r['mean_train_normal']:+.2f} "
                      f"held-out {r.get('mean_heldout_normal', float('nan')):+.2f}")
            for label, v in c["random_forest"].items():
                parts = "  ".join(f"{p} macro {s['macro_f1']:.3f} normal->attack {s['normal_called_attack']:.3f}"
                                  for p, s in v.items() if p in PARTS_EVAL)
                print(f"  RF {label:<16} {parts}")
                print(f"     top features: {[n for n, _ in v['top_features'][:5]]}")
        print(f"  -> {path}")


if __name__ == "__main__":
    main()
