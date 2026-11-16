"""LightGBM in its own process (no torch here; see ml/__init__.py).

    python -m ml.gbm_fit <in.npz> <out.npz>
in.npz:  X_train, y_train, seed, n_classes, and X_<part> for each part to predict
out.npz: P_<part> = class probabilities over all n_classes (unseen classes 0)
"""
import sys

import numpy as np
from lightgbm import LGBMClassifier


def main(src, dst):
    d = np.load(src)
    m = LGBMClassifier(n_estimators=300, learning_rate=0.05, num_leaves=31, class_weight="balanced",
                       random_state=int(d["seed"]), verbose=-1)
    m.fit(d["X_train"], d["y_train"])
    out = {}
    for key in d.files:
        if key.startswith("X_") and key != "X_train":
            p = np.zeros((len(d[key]), int(d["n_classes"])))
            if len(d[key]):
                p[:, m.classes_] = m.predict_proba(d[key])
            out["P_" + key[2:]] = p
    np.savez(dst, **out)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
