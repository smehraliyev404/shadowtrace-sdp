"""LightGBM in its own process (no torch here; see ml/__init__.py).

    python -m ml.gbm_fit <in.npz> <out.npz>
in.npz:  X_train, y_train, seed, n_classes, grid (JSON list of settings), optionally
         X_val + y_val (then every setting is scored on validation macro-F1 and the
         best is kept), and X_<part> for each part to predict
out.npz: P_<part> = class probabilities over all n_classes (unseen classes 0),
         best (JSON: chosen settings), scores (JSON: validation macro-F1 per setting)
"""
import json
import sys

import numpy as np
from lightgbm import LGBMClassifier
from sklearn.metrics import f1_score


def fit(d, params):
    m = LGBMClassifier(learning_rate=0.05, class_weight="balanced", random_state=int(d["seed"]), verbose=-1, **params)
    return m.fit(d["X_train"], d["y_train"])


def proba(m, X, n_classes):
    p = np.zeros((len(X), n_classes))
    if len(X):
        p[:, m.classes_] = m.predict_proba(X)
    return p


def main(src, dst):
    d = np.load(src)
    grid = json.loads(str(d["grid"]))
    scores, best, best_m = [], None, None
    for params in grid:
        m = fit(d, params)
        if "y_val" in d.files and len(d["y_val"]):
            pred = m.classes_[m.predict_proba(d["X_val"]).argmax(1)]
            f1 = float(f1_score(d["y_val"], pred, labels=sorted(set(d["y_val"].tolist())), average="macro", zero_division=0))
        else:
            f1 = float("nan")
        scores.append({"params": params, "val_macro_f1": f1})
        if best is None or f1 > best[0]:
            best, best_m = (f1, params), m
    out = {"P_" + k[2:]: proba(best_m, d[k], int(d["n_classes"]))
           for k in d.files if k.startswith("X_") and k != "X_train"}
    np.savez(dst, best=json.dumps(best[1]), scores=json.dumps(scores), **out)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
