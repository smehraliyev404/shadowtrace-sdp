"""Paper tables from the JSON written by ml.metrics --out.

    ./venv/bin/python -m ml.metrics results/*_k3_a*_s*/predictions.parquet --part test --n-boot 0 --out results/metrics_k3_test.json
    ./venv/bin/python -m ml.summary results/metrics_k3_test.json --ref stgnn

Prints, per level and k:
  1. every model: repetitions, mean ± sd and median of each metric
  2. model vs the reference model (--ref): paired Wilcoxon signed-rank over the
     shared repetitions (assignment x seed), Holm-corrected within the level,
     one block per metric; detectors only get the binary metrics
  2b. per attack: share of that attack's windows flagged as any attack
     (detect_<attack>, also for detectors) and, for classifiers, labelled as
     exactly that attack (recall_<attack>), mean over repetitions
  3. RQ3: per model, L1 vs L0 and L2 vs L0 on the same repetitions, Wilcoxon,
     Holm-corrected over all (model, level) pairs of that metric
A model with fewer than 5 shared repetitions gets no p-value (too few pairs).

Every comparison also gets a per-assignment line ("per asg"): the seeds of one
assignment share the same test runs, so they are not independent and the
25-repetition p-values are optimistic. Here the seeds are averaged per
assignment first (5 values per model), and the line gives how many assignments
the model is higher in, the mean difference and the exact Wilcoxon p on those 5
pairs (its smallest possible two-sided value is 0.0625).
"""

import argparse
import json
import re

import numpy as np
from scipy.stats import wilcoxon

from ml.metrics import ATTACK_CLASSES, compare, holm

METRICS = ("macro_f1", "binary_f1", "pr_auc", "pauc_1fpr", "tpr_at_1fpr_val", "fpr_at_val_threshold", "fpr_pred")
TESTED = ("macro_f1", "binary_f1", "pauc_1fpr")


def by_assignment(ref, other):
    """{rep: value} x 2 -> seeds averaged per assignment ('a3_s2' -> 'a3'), then
    n assignments, how many with other > ref, mean difference, Wilcoxon p."""
    def means(d):
        g = {}
        for r, v in d.items():
            if not np.isnan(v):
                g.setdefault(r.split("_")[0], []).append(v)
        return {k: float(np.mean(v)) for k, v in g.items()}
    x, y = means(ref), means(other)
    common = sorted(set(x) & set(y))
    if not common:
        return None
    xa, ya = np.array([x[c] for c in common]), np.array([y[c] for c in common])
    p = float(wilcoxon(xa, ya).pvalue) if len(common) >= 5 and np.any(xa != ya) else float("nan")
    return {"n_assignments": len(common), "higher": int((ya > xa).sum()),
            "mean_diff": float((ya - xa).mean()), "p": p}


def asg_text(b):
    return "" if not b else (f"  | per asg: higher in {b['higher']}/{b['n_assignments']}, "
                             f"mean diff {b['mean_diff']:+.3f}, p {fmt(b['p'])}")


def fmt(p):
    return "  n/a " if p is None or np.isnan(p) else f"{p:.4f}" if p >= 1e-4 else f"{p:.0e}"


def main():
    ap = argparse.ArgumentParser(description="means, model comparisons and RQ3 tests from ml.metrics JSON")
    ap.add_argument("json", nargs="+", help="written by ml.metrics --out (one part each)")
    ap.add_argument("--ref", default="stgnn", help="reference model for the comparisons")
    ap.add_argument("--metrics", default=",".join(TESTED), help="metrics to test")
    ap.add_argument("--out", help="write everything as JSON")
    a = ap.parse_args()
    tested = a.metrics.split(",")
    out = {}
    for path in a.json:
        res = json.load(open(path))["results"]
        part = res[0]["part"] if res else "?"
        table = {}                                   # (group, model) -> {rep: metrics}
        for r in res:
            table.setdefault((r["group"], r["model"]), {})[r["rep"]] = r["metrics"]
        groups = sorted({g for g, _ in table})
        rep = out.setdefault(part, {"means": [], "vs_ref": {}, "rq3": {}, "per_attack": [], "loao": []})

        print(f"\n=== {part}: means over repetitions ({path})")
        print(f"{'group':<7} {'model':<22} {'reps':>4}  " + "  ".join(f"{m:>19}" for m in METRICS))
        for (g, model), reps in sorted(table.items()):
            cells, row = [], {"group": g, "model": model, "reps": len(reps)}
            for m in METRICS:
                v = np.array([x.get(m, np.nan) for x in reps.values()], float)
                v = v[~np.isnan(v)]
                if len(v):
                    cells.append(f"{v.mean():.3f}±{v.std(ddof=1) if len(v) > 1 else 0:.3f} ({np.median(v):.3f})")
                    row[m] = {"mean": float(v.mean()), "sd": float(v.std(ddof=1)) if len(v) > 1 else 0.0,
                              "median": float(np.median(v)), "n": int(len(v))}
                else:
                    cells.append(f"{'–':>19}")
            rep["means"].append(row)
            print(f"{g:<7} {model:<22} {len(reps):>4}  " + "  ".join(f"{c:>19}" for c in cells))

        short = {c: c.replace("http_flood", "flood").replace("session_rotation_brute", "sess_rot").replace("lateral_movement", "lateral")
                 .replace("exfiltration", "exfil")[:9] for c in ATTACK_CLASSES}
        what = {"detect_thr": "flagged by the validation threshold (pair with fpr_at_val_threshold)",
                "detect": "whose predicted class is an attack (pair with fpr_pred)",
                "recall": "labelled as exactly that attack"}
        for kind in ("detect_thr", "detect", "recall"):
            print(f"\n=== {part}: per attack, {kind}: share of the attack's windows {what[kind]}, mean")
            print(f"{'group':<7} {'model':<22} " + " ".join(f"{short[c]:>9}" for c in ATTACK_CLASSES))
            for (g, model), reps in sorted(table.items()):
                vals = []
                for c in ATTACK_CLASSES:
                    v = np.array([x.get(f"{kind}_{c}", np.nan) for x in reps.values()], float)
                    vals.append(float(np.nanmean(v)) if (~np.isnan(v)).any() else float("nan"))
                if all(np.isnan(vals)):
                    continue
                rep["per_attack"].append({"group": g, "model": model, "kind": kind,
                                          **{c: v for c, v in zip(ATTACK_CLASSES, vals)}})
                print(f"{g:<7} {model:<22} " + " ".join(f"{'–':>9}" if np.isnan(v) else f"{v:>9.3f}" for v in vals))

        loao = {}
        for (g, model), reps in table.items():
            mm = re.fullmatch(r"(.+)_leaveout(.+)", model)
            if mm and mm.group(2) in ATTACK_CLASSES:
                loao[(g, mm.group(1), mm.group(2))] = reps
        if loao:
            print(f"\n=== {part}: leave one attack out: share of the LEFT-OUT attack's windows flagged as an attack "
                  "(trained without it) vs the same model trained on all attacks (same repetitions), and FPR")
            for (g, base, att), reps in sorted(loao.items()):
                full = table.get((g, base), {})
                common = sorted(set(reps) & set(full))
                def mean(dd, key, rs):
                    v = np.array([dd[r].get(key, np.nan) for r in rs], float)
                    return float(np.nanmean(v)) if (~np.isnan(v)).any() else float("nan")
                row = {"group": g, "model": base, "attack": att, "reps": len(reps),
                       "detect_thr_left_out": mean(reps, f"detect_thr_{att}", reps),
                       "detect_thr_full": mean(full, f"detect_thr_{att}", common),
                       "fpr_at_val_threshold": mean(reps, "fpr_at_val_threshold", reps),
                       "detect_left_out": mean(reps, f"detect_{att}", reps),
                       "detect_full": mean(full, f"detect_{att}", common),
                       "fpr_pred": mean(reps, "fpr_pred", reps)}
                rep["loao"].append(row)
                print(f"  {g:<7} {base:<10} {att:<24} n={len(reps):<3} threshold: detect {row['detect_thr_left_out']:.3f} "
                      f"(all attacks {row['detect_thr_full']:.3f}) FPR {row['fpr_at_val_threshold']:.3f} | predicted "
                      f"class: detect {row['detect_left_out']:.3f} (all attacks {row['detect_full']:.3f}) "
                      f"FPR {row['fpr_pred']:.3f}")

        for m in tested:
            print(f"\n=== {part}: {m}, each model vs {a.ref} (Wilcoxon, Holm within the level)")
            for g in groups:
                scores = {model: {r: x.get(m, np.nan) for r, x in reps.items()}
                          for (gg, model), reps in table.items() if gg == g}
                if a.ref not in scores:
                    continue
                rows = compare(scores, a.ref)
                rep["vs_ref"].setdefault(m, {})[g] = rows
                for row in sorted(rows, key=lambda x: x["model"]):
                    if not row["n_reps"]:
                        continue
                    d = row["model_median"] - row["ref_median"]
                    row["per_assignment"] = b = by_assignment(scores[a.ref], scores[row["model"]])
                    print(f"  {g:<7} {row['model']:<22} n={row['n_reps']:<3} median {row['model_median']:.3f} vs "
                          f"{row['ref_median']:.3f} ({d:+.3f})  p {fmt(row['p'])}  Holm {fmt(row.get('p_holm'))}"
                          + asg_text(b))

        levels = sorted({g.split()[0] for g in groups})
        ks = sorted({g.split()[1] for g in groups})
        if "L0" not in levels:
            continue
        for m in tested:
            rows = []
            for k in ks:
                for model in sorted({mo for (g, mo) in table if g == f"L0 {k}"}):
                    base = table.get((f"L0 {k}", model), {})
                    for lv in levels:
                        if lv == "L0" or (f"{lv} {k}", model) not in table:
                            continue
                        other = table[(f"{lv} {k}", model)]
                        common = sorted(set(base) & set(other))
                        x = np.array([base[r].get(m, np.nan) for r in common], float)
                        y = np.array([other[r].get(m, np.nan) for r in common], float)
                        ok = ~(np.isnan(x) | np.isnan(y))
                        x, y = x[ok], y[ok]
                        p = float("nan")
                        if len(x) >= 5 and np.any(x != y):
                            p = float(wilcoxon(x, y).pvalue)
                        if len(x):
                            rows.append({"k": k, "model": model, "level": lv, "n_reps": int(len(x)),
                                         "median_L0": float(np.median(x)), "median_level": float(np.median(y)),
                                         "median_diff": float(np.median(y - x)), "p": p,
                                         "per_assignment": by_assignment({r: v.get(m, np.nan) for r, v in base.items()},
                                                                         {r: v.get(m, np.nan) for r, v in other.items()})})
            valid = [i for i, r in enumerate(rows) if not np.isnan(r["p"])]
            for i, adj in zip(valid, holm([rows[i]["p"] for i in valid]) if valid else []):
                rows[i]["p_holm"] = adj
            rep["rq3"][m] = rows
            print(f"\n=== {part}: RQ3 {m}, level vs L0 on the same repetitions (Wilcoxon, Holm over all rows)")
            for r in rows:
                print(f"  {r['k']:<4} {r['model']:<22} {r['level']} vs L0  n={r['n_reps']:<3} median {r['median_level']:.3f} "
                      f"vs {r['median_L0']:.3f} (paired diff {r['median_diff']:+.3f})  p {fmt(r['p'])}  "
                      f"Holm {fmt(r.get('p_holm'))}" + asg_text(r["per_assignment"]))
    if a.out:
        json.dump(out, open(a.out, "w"), indent=1)


if __name__ == "__main__":
    main()
