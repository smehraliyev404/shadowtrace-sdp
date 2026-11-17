"""Evaluation harness (PLAN.md §11).

Per prediction file (one model, one assignment, one seed; written by train.py):
    macro_f1, mcc, pr_auc (macro one-vs-rest average precision), per-attack recall,
    attack-vs-normal: score = 1 - p(normal);
      tpr_at_1fpr_curve   TPR at 1 % FPR read off the test ROC curve
      tpr_at_1fpr_val     TPR with the threshold fixed on validation normal windows
                          (99th percentile), plus the FPR it really gives on test
      precision_at_1pct   precision at 1 % attack prevalence, from that TPR and FPR
                          (Bayes: TPR*p / (TPR*p + FPR*(1-p)); reproduces Arp et al.'s
                          P8 example, 99 % TPR at 1 % FPR and 1:100 -> ~100 false per
                          99 true positives, USENIX Security 2022 §2.3)
      pauc_1fpr           ROC area up to 1 % FPR, divided by 0.01 (= mean TPR over
                          FPR 0..1 %): Arp et al. §2.3 recommend ROC curves "only up
                          to tractable false-positive rates" and bounded AUC values
    95 % CIs by block bootstrap: windows of a run are cut into blocks of
    consecutive windows and whole blocks are resampled (windows are
    autocorrelated, so resampling single windows would be too optimistic).
Two metric families: multi-class and normal-vs-attack (binary_*, detect_*,
TPR/FPR); a detector (Jacob) only has the binary family, see point_metrics.
Across repetitions (assignments x seeds): Wilcoxon signed-rank of each model
against a reference model, Holm-corrected, separately for every level and k
(results of different levels or k are never pooled; two results for the same
level, k, model and repetition are an error).

    ./venv/bin/python -m ml.metrics results/*/predictions.parquet --part test
    ./venv/bin/python -m ml.metrics results/*/predictions.parquet --part test --compare stgnn_gatv2 --metric macro_f1
"""

import argparse
import json
import os

import numpy as np
import pandas as pd
from scipy.stats import wilcoxon
from sklearn.metrics import average_precision_score, f1_score, matthews_corrcoef, roc_curve

from ml.data import CLASSES

ATTACK_CLASSES = CLASSES[1:]
FPR_TARGET = 0.01
PREVALENCE = 0.01


def macro_f1(y, p):
    labels = sorted(set(y))
    return float(f1_score(y, p, labels=labels, average="macro", zero_division=0))


def pr_auc(y, prob):
    """Macro average precision over the classes present in y (one-vs-rest)."""
    out = [average_precision_score(y == c, prob[:, c]) for c in sorted(set(y))]
    return float(np.mean(out)) if out else float("nan")


def tpr_at_fpr(is_attack, score, fpr=FPR_TARGET):
    if is_attack.all() or not is_attack.any():
        return float("nan")
    f, t, _ = roc_curve(is_attack, score)
    return float(np.interp(fpr, f, t))


def bounded_auc(is_attack, score, max_fpr=FPR_TARGET):
    """ROC area for FPR in [0, max_fpr], divided by max_fpr (1.0 = perfect, ~max_fpr/2 = random)."""
    if is_attack.all() or not is_attack.any():
        return float("nan")
    f, t, _ = roc_curve(is_attack, score)
    grid = np.linspace(0, max_fpr, 101)
    return float(np.trapezoid(np.interp(grid, f, t), grid) / max_fpr)


def precision_at(tpr, fpr, prevalence=PREVALENCE):
    d = tpr * prevalence + fpr * (1 - prevalence)
    return float(tpr * prevalence / d) if d > 0 else float("nan")


def point_metrics(df, val_threshold=None, detector=False):
    """Two families of metrics, so detectors and classifiers are never mixed:
    multi-class (macro_f1, mcc, pr_auc, recall_<attack>: is it the right attack?)
    and normal vs attack (binary_f1, binary_mcc, binary_pr_auc, detect_<attack>,
    the TPR/FPR measures: is an attack flagged at all?). A detector (Jacob) names
    no attack, so its multi-class metrics are NaN and only the binary family
    exists for it; compare() skips NaN values."""
    nan = float("nan")
    y = df["y"].to_numpy()
    p = df["pred"].to_numpy()
    prob = df[[f"p_{c}" for c in CLASSES]].to_numpy()
    is_attack = y != 0
    score = 1 - prob[:, 0]
    yb, pb = is_attack.astype(int), (p != 0).astype(int)
    m = {"n": len(df), "n_attack": int(is_attack.sum()),
         "macro_f1": nan if detector else macro_f1(y, p),
         "mcc": nan if detector or len(set(y) | set(p)) < 2 else float(matthews_corrcoef(y, p)),
         "pr_auc": nan if detector else pr_auc(y, prob),
         "binary_f1": macro_f1(yb, pb),
         "binary_mcc": float(matthews_corrcoef(yb, pb)) if len(set(yb) | set(pb)) > 1 else nan,
         "binary_pr_auc": float(average_precision_score(yb, score)) if 0 < yb.sum() < len(yb) else nan}
    m["tpr_at_1fpr_curve"] = tpr_at_fpr(is_attack, score)
    m["pauc_1fpr"] = bounded_auc(is_attack, score)
    if val_threshold is not None:
        tpr = float((score[is_attack] > val_threshold).mean()) if is_attack.any() else float("nan")
        fpr = float((score[~is_attack] > val_threshold).mean()) if (~is_attack).any() else float("nan")
        m.update({"tpr_at_1fpr_val": tpr, "fpr_at_val_threshold": fpr, "precision_at_1pct": precision_at(tpr, fpr)})
    for c in ATTACK_CLASSES:
        ci = CLASSES.index(c)
        if (y == ci).any():
            m[f"recall_{c}"] = nan if detector else float((p[y == ci] == ci).mean())
            m[f"detect_{c}"] = float((p[y == ci] != 0).mean())
    return m


def val_threshold(val_df, fpr=FPR_TARGET):
    """Attack-score threshold that flags `fpr` of the validation normal windows."""
    s = 1 - val_df.loc[val_df["y"] == 0, "p_normal"].to_numpy()
    return float(np.quantile(s, 1 - fpr)) if len(s) else None


def blocks(df, block_len):
    keys = df["run_id"].astype(str) + ":" + (df["window"] // block_len).astype(str)
    return [idx.to_numpy() for _, idx in df.groupby(keys).groups.items()]


def block_bootstrap(df, thr=None, block_len=10, n_boot=1000, seed=0, alpha=0.05, detector=False):
    rng = np.random.default_rng(seed)
    df = df.reset_index(drop=True)
    bl = blocks(df, block_len)
    reps = []
    for _ in range(n_boot):
        pick = rng.integers(0, len(bl), len(bl))
        reps.append(point_metrics(df.loc[np.concatenate([bl[i] for i in pick])], thr, detector))
    rep = pd.DataFrame(reps)
    lo, hi = rep.quantile(alpha / 2), rep.quantile(1 - alpha / 2)
    return {k: [float(lo[k]), float(hi[k])] for k in rep.columns if k not in ("n", "n_attack")}


def holm(pvals):
    """Holm-Bonferroni adjusted p-values, same order as the input."""
    order = np.argsort(pvals)
    m, adj, running = len(pvals), np.empty(len(pvals)), 0.0
    for rank, i in enumerate(order):
        running = max(running, min(1.0, (m - rank) * pvals[i]))
        adj[i] = running
    return adj.tolist()


def compare(scores, reference):
    """scores: {model: {repetition: value}} -> Wilcoxon of every model against `reference`."""
    scores = {m: {r: v for r, v in d.items() if not np.isnan(v)} for m, d in scores.items()}   # NaN = metric n/a
    others = [m for m in scores if m != reference]
    rows = []
    for m in others:
        common = sorted(set(scores[m]) & set(scores[reference]))
        a = np.array([scores[reference][r] for r in common])
        b = np.array([scores[m][r] for r in common])
        p = float(wilcoxon(a, b).pvalue) if len(common) >= 5 and np.any(a != b) else float("nan")
        rows.append({"model": m, "n_reps": len(common), "ref_median": float(np.median(a)) if len(a) else float("nan"),
                     "model_median": float(np.median(b)) if len(b) else float("nan"), "p": p})
    ps = [r["p"] for r in rows]
    valid = [i for i, p in enumerate(ps) if not np.isnan(p)]
    adj = holm([ps[i] for i in valid]) if valid else []
    for i, a in zip(valid, adj):
        rows[i]["p_holm"] = a
    return rows


def evaluate_file(path, part="test", n_boot=1000, block_len=10):
    pred = pd.read_parquet(path)
    cfg = json.load(open(os.path.join(os.path.dirname(path), "config.json")))
    thr = val_threshold(pred[pred["part"] == "val"]) if (pred["part"] == "val").any() else None
    d = pred[pred["part"] == part]
    if d.empty:
        return None
    return {"run": os.path.basename(os.path.dirname(path)), "model": cfg["model_name"],
            "group": f"{cfg['level']} k{cfg['k']}", "path": path,
            "rep": f"a{'x' if cfg.get('assignment') is None else cfg['assignment']}_s{cfg['seed']}", "part": part, "val_threshold": thr,
            "detector": bool(cfg.get("detector")),
            "metrics": point_metrics(d, thr, bool(cfg.get("detector"))),
            "ci95": block_bootstrap(d, thr, block_len, n_boot, detector=bool(cfg.get("detector"))) if n_boot else {}}


def main():
    ap = argparse.ArgumentParser(description="metrics, block-bootstrap CIs and model comparison")
    ap.add_argument("predictions", nargs="+")
    ap.add_argument("--part", default="test", choices=["val", "test", "heldout"])
    ap.add_argument("--n-boot", type=int, default=1000)
    ap.add_argument("--block-len", type=int, default=10, help="windows per bootstrap block")
    ap.add_argument("--compare", help="reference model name for Wilcoxon + Holm")
    ap.add_argument("--metric", default="macro_f1")
    ap.add_argument("--out", help="write all results as JSON")
    a = ap.parse_args()
    res = [r for r in (evaluate_file(p, a.part, a.n_boot, a.block_len) for p in a.predictions) if r]
    seen = {}
    for r in res:                      # one result per (level/k, model, repetition)
        key = (r["group"], r["model"], r["rep"])
        if key in seen:
            raise SystemExit(f"two results for {key}: {seen[key]} and {r['path']}")
        seen[key] = r["path"]
    res.sort(key=lambda r: (r["group"], r["model"], r["rep"]))
    for r in res:
        m, ci = r["metrics"], r["ci95"]
        line = "  ".join(f"{k} {m[k]:.3f}" + (f" [{ci[k][0]:.3f}, {ci[k][1]:.3f}]" if k in ci else "")
                         for k in ("macro_f1", "binary_f1", "pr_auc", "tpr_at_1fpr_val", "pauc_1fpr") if k in m)
        print(f"{r['group']:<7} {r['model']:<16} {r['rep']:<8} n={m['n']:<5} {line}")
    out = {"results": res}
    if a.compare:                      # models are compared within one level and k only
        out["comparison"] = {}
        for group in sorted({r["group"] for r in res}):
            scores = {}
            for r in res:
                if r["group"] == group:
                    scores.setdefault(r["model"], {})[r["rep"]] = r["metrics"].get(a.metric, float("nan"))
            if a.compare not in scores:
                print(f"[{group}] no {a.compare} results - skipped")
                continue
            out["comparison"][group] = compare(scores, a.compare)
            for row in out["comparison"][group]:
                if not row["n_reps"]:
                    print(f"[{group}] vs {a.compare}: {row['model']} has no {a.metric} (a detector? use a binary_* metric)")
                else:
                    print(f"[{group}] vs {a.compare}: {row}")
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
