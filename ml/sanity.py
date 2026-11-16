"""Phase 6 sanity checks (PLAN.md Phase 6). Run before trusting any result.

    ./venv/bin/python -m ml.sanity --train run_03 --eval leak_02          # laptop
    ./venv/bin/python -m ml.sanity --split splits/batch3.json --assignment 0  # lab

  1. split      no run in two parts of any assignment; every regular run tested once
  2. prep       normalisation and vocabularies come from the training runs only
  3. sequences  no sample's window sequence crosses into another run
  4. L2 content content features are all 0 at L2 (so --no-content changes nothing there)
  5. overfit    the ST-GNN reaches 100 % training accuracy on a tiny batch
                (if not, the model or the input pipeline is broken)
  6. shuffled   trained on shuffled labels, evaluation macro-F1 ~ chance
                (if not, labels leak through the inputs or the evaluation)
"""

import argparse
import json
import os
import sys

import numpy as np
import torch
import torch.nn.functional as F

from ml.data import CLASSES, CONTENT_FEATURES, NODE_FEATURES, PROJECT_ROOT, Prep, build, load_runs
from ml.metrics import macro_f1
from ml.models import STGNN, make_flat

sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))
from make_split import check as check_split  # noqa: E402

results = []


def report(name, ok, detail):
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def overfit(ds, prep, n=16, steps=300, seed=0):
    torch.manual_seed(seed)
    idx = np.random.default_rng(seed).permutation(len(ds))[:n]
    sub = ds.subset(idx)
    m = STGNN(len(NODE_FEATURES), 7, prep.n_services, len(CLASSES))
    opt = torch.optim.Adam(m.parameters(), lr=3e-3)
    seq, y = torch.tensor(sub.seq), torch.tensor(sub.y)
    for _ in range(steps):
        m.train()
        loss = F.cross_entropy(m(sub.graphs, seq), y)
        opt.zero_grad()
        loss.backward()
        opt.step()
    m.eval()
    with torch.no_grad():
        acc = float((m(sub.graphs, seq).argmax(1) == y).float().mean())
    return acc, loss.item()


def fit_eval_gnn(tr, ev, prep, labels, seed, epochs=60):
    torch.manual_seed(seed)
    m = STGNN(len(NODE_FEATURES), 7, prep.n_services, len(CLASSES))
    opt = torch.optim.Adam(m.parameters(), lr=1e-3)
    seq, y = torch.tensor(tr.seq), torch.tensor(labels)
    for _ in range(epochs):
        m.train()
        loss = F.cross_entropy(m(tr.graphs, seq), y)
        opt.zero_grad()
        loss.backward()
        opt.step()
    m.eval()
    with torch.no_grad():
        return macro_f1(ev.y, m(ev.graphs, torch.tensor(ev.seq)).argmax(1).numpy())


def main():
    ap = argparse.ArgumentParser(description="Phase 6 sanity checks")
    ap.add_argument("--split")
    ap.add_argument("--assignment", type=int, default=0)
    ap.add_argument("--train", nargs="+")
    ap.add_argument("--eval", nargs="+", help="evaluation runs (default: the assignment's validation runs)")
    ap.add_argument("--level", default="L1")
    ap.add_argument("--k", type=int, default=3)
    ap.add_argument("--seeds", type=int, default=5)
    a = ap.parse_args()

    if a.split:
        s = json.load(open(a.split))
        runs = list(s["run_kinds"].items())
        try:
            check_split(s["assignments"], runs)
            report("split", True, f"{len(s['assignments'])} assignments, disjoint, every regular run tested once")
        except AssertionError as e:
            report("split", False, str(e))
        asg = s["assignments"][a.assignment]
        train_runs, eval_runs = asg["train"], a.eval or asg["val"]
    else:
        train_runs, eval_runs = a.train, a.eval
        overlap = sorted(set(train_runs) & set(eval_runs))
        report("split", not overlap, f"explicit runs, overlap {overlap}" if overlap else "explicit runs, disjoint")

    tw, ew = load_runs(train_runs, a.level), load_runs(eval_runs, a.level)
    prep = Prep.fit(tw)
    report("prep", set(prep.train_runs) == set(train_runs) and set(prep.edge_stats["train_runs"]) == set(train_runs),
           f"fitted on {prep.train_runs}, edge reference from {prep.edge_stats['normal_windows']} normal windows")
    tr, ev = build(tw, prep, a.k), build(ew, prep, a.k)

    bad = 0
    for ds in (tr, ev):
        for row, sq in zip(ds.meta.itertuples(), ds.seq):
            bad += sum(ds.graph_keys[g][0] != row.run_id for g in sq if g >= 0)
    report("sequences", bad == 0, f"{len(tr) + len(ev)} samples, {bad} windows from another run")

    l2 = load_runs(train_runs[:1], "L2")
    cmax = max((abs(n.get(f, 0.0)) for nodes in l2["nodes"] for n in nodes for f in CONTENT_FEATURES), default=0.0)
    report("L2 content", cmax == 0.0, f"max |content feature| at L2 = {cmax}")

    acc, loss = overfit(tr, prep)
    report("overfit", acc == 1.0, f"training accuracy {acc:.3f} on 16 samples after 300 steps (loss {loss:.4f})")

    rng = np.random.default_rng(0)
    real, shuf, rf_real, rf_shuf = [], [], [], []
    for seed in range(a.seeds):
        perm = rng.permutation(tr.y)
        real.append(fit_eval_gnn(tr, ev, prep, tr.y, seed))
        shuf.append(fit_eval_gnn(tr, ev, prep, perm, seed))
        for lab, out in ((tr.y, rf_real), (perm, rf_shuf)):
            m = make_flat("rf", seed).fit(tr.flat, lab)
            out.append(macro_f1(ev.y, m.predict(ev.flat)))
    n_cls = len(set(ev.y))
    chance = 1.0 / n_cls
    ok = np.mean(shuf) < np.mean(real) and np.mean(shuf) < chance + 0.25
    report("shuffled", ok,
           f"eval macro-F1 over {a.seeds} seeds: ST-GNN real {np.mean(real):.3f}, shuffled {np.mean(shuf):.3f}; "
           f"RF real {np.mean(rf_real):.3f}, shuffled {np.mean(rf_shuf):.3f}; "
           f"uniform guess ~{chance:.2f} ({n_cls} classes in eval)")
    print(f"[sanity] {sum(results)}/{len(results)} passed")
    sys.exit(0 if all(results) else 1)


if __name__ == "__main__":
    main()
