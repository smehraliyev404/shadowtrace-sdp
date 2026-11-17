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
  7. jacob      the forecaster's training sequences contain normal windows only
                (SKIP when there are none, e.g. on night-1 runs; batch 3 normal runs have them)
  8. ma         the per-request GCN fits 64 training traces up to the best accuracy
                its input allows: traces of different classes can have identical graphs
                (same services, span counts and text; e.g. a flood request is an ordinary
                page load), so the limit is the majority-label share per distinct graph
                (node order ignored, features rounded to 0.01: on run_03 three traces differ
                only below that and the GCN does not separate them even with standardised
                inputs, 0.656 vs 0.703 at 4 decimals, tested 17 Nov); PASS within 0.02 of it
"""

import argparse
import json
import os
import sys

import numpy as np
import torch
import torch.nn.functional as F

from ml.data import CLASSES, CONTENT_FEATURES, FEATURES_DIR, NODE_FEATURES, PROJECT_ROOT, Prep, build, load_runs
from ml.metrics import macro_f1
from ml.models import STGNN, make_flat

sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))
from make_split import check as check_split  # noqa: E402

results = []


def report(name, ok, detail):
    if ok is None:
        print(f"[SKIP] {name}: {detail}")
        return
    results.append(ok)
    print(f"[{'PASS' if ok else 'FAIL'}] {name}: {detail}")


def check_jacob(tw):
    from ml.jacob import T_IN, build_graph, count_matrix, sequences
    pairs, _ = build_graph(tw)
    X = count_matrix(tw, pairs)
    _, _, rows = sequences(tw, X, T_IN, True)
    if not len(rows):
        return None, "no all-normal training sequences in these runs"
    bad = 0
    for r in rows:
        run, w = tw.loc[r, "run_id"], tw.loc[r, "window"]
        g = tw[(tw["run_id"] == run) & (tw["window"].between(w - T_IN, w))]
        bad += int((g["label_k1"] != "normal").any())
    return bad == 0, f"{len(rows)} training sequences over {len(pairs)} operation pairs, {bad} with an attack window"


def check_ma(train_runs, level, seed=0, n=64, steps=300):
    from torch_geometric.data import Batch
    from ml.ma import Featurizer, MaGCN, load_part, sample_ids
    ids = sample_ids(train_runs[:1], level, FEATURES_DIR, max(1, n // len(CLASSES)) + 1, seed)
    tr, tn, te = load_part(train_runs[:1], level, FEATURES_DIR, ids)
    feat = Featurizer().fit(tn, tn["trace_id"].map(tr.set_index("trace_id")["label"]).to_numpy())
    gs = feat.graphs(tr, tn, te)
    keep = [i for i, g in enumerate(gs) if g is not None][:n]
    b = Batch.from_data_list([gs[i] for i in keep])
    y = torch.tensor([CLASSES.index(lab) for lab in tr["label"].iloc[keep]])
    torch.manual_seed(seed)
    m = MaGCN(feat.dim, len(CLASSES))
    opt = torch.optim.Adam(m.parameters(), lr=3e-3)
    for _ in range(steps):
        m.train()
        loss = F.cross_entropy(m(b), y)
        opt.zero_grad()
        loss.backward()
        opt.step()
    m.eval()
    with torch.no_grad():
        acc = float((m(b).argmax(1) == y).float().mean())
    import collections
    sig = collections.defaultdict(collections.Counter)
    for i, lab in zip(keep, y.tolist()):
        rows = tuple(sorted(map(tuple, gs[i].x.numpy().round(2).tolist())))    # < 0.01 apart = identical
        sig[(rows, gs[i].edge_index.shape[1])][lab] += 1
    limit = sum(c.most_common(1)[0][1] for c in sig.values()) / len(keep)
    return acc >= limit - 0.02, (f"training accuracy {acc:.3f} on {len(keep)} traces ({level}) after {steps} steps; "
                                 f"best possible with these inputs {limit:.3f} ({len(sig)} distinct graphs)")


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
    ok_j, msg_j = check_jacob(tw)
    report("jacob", ok_j, msg_j)
    ok_m, msg_m = check_ma(train_runs, a.level)
    report("ma", ok_m, msg_m)

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
