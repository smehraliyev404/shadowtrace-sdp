"""Ma (2026) baseline: one graph per request, GCN classifier.

Re-implementation of Ma, "Can Graph-Based Microservice Performance Detection
Be Used for Microservice Intrusion Detection?", arXiv 2605.24283v1 (preprint;
notes: ~/academic papers/literature/claude-reading-notes.md, entry 48):

  unit       one request trace -> service-level graph: nodes = services in the
             trace, edges = caller/callee service pairs, symmetrised, no edge
             attributes (§4)
  features   per node: service identity and coarse shape (one-hot service,
             log span count, degree; no durations or status codes, as in the
             paper's trace variant) + 16 TF-IDF dimensions of text (§4: log
             TF-IDF). We have no logs or container metrics; the text is the
             node's span attributes at that level, so it is empty at L2
             (PLAN.md §10: "+ attribute text at L0/L1"). Adaptation: the 16
             terms are chosen by chi2 against the training labels (from a
             TF-IDF vocabulary without terms in > 50 % of nodes; punctuation
             runs are tokens). With plain top-16 frequency all terms were
             attribute boilerplate (span.kind, otel.scope.name, ports) and
             predictions were identical at L0, L1 and L2 (tested 17 Nov)
  model      2-layer GCN, mean pooling, MLP (§4)
  labels     the trace's own provenance label (the paper used trace-window overlap)

Training follows our protocol (PLAN.md §10: class-weighted CE, Adam 0.001,
early stopping on validation macro-F1), not the paper's 5 or 100 epochs.
Training and validation traces are subsampled per class (--max-per-class);
test and held-out runs are scored on every trace.

To compare with the window models, request predictions are turned into window
predictions: E_c = sum of p_c over the window's traces (expected number of
class-c traces), p(window) proportional to (k, E_attack1, ..., E_attack8), so a
window is called attack c when about k or more of its traces look like c
(the same rule as the window labels).

    ./venv/bin/python -m ml.ma --split splits/batch3.json --assignment 0 --seed 1 --level L1
Output: results/ma_<level>_k<k>_a<i>_s<seed>/predictions.parquet (windows,
same format as ml/train.py) and requests.parquet (one row per trace).
"""

import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import pyarrow.parquet as pq
import torch
import torch.nn as nn
import torch.nn.functional as F
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.feature_selection import SelectKBest, chi2
from torch_geometric.data import Batch, Data
from torch_geometric.nn import GCNConv, global_mean_pool

from ml.data import CLASSES, FEATURES_DIR
from ml.metrics import macro_f1
from ml.models import class_weights, resolve_device
from ml.train import add_split_args, results_dir, set_seed, split_runs, variant

N_TFIDF = 16


def read_run(run, level, features_dir, trace_ids=None):
    d = os.path.join(features_dir, run, level)
    tr = pd.read_parquet(os.path.join(d, "traces.parquet"), columns=["run_id", "run_kind", "trace_id", "label", "window"])
    if trace_ids is not None:
        tr = tr[tr["trace_id"].isin(trace_ids)]
    cols = ["trace_id", "span_id", "parent_id", "service"] + (["attrs"] if level != "L2" else [])
    filt = [("trace_id", "in", list(tr["trace_id"]))] if trace_ids is not None else None
    sp = pq.read_table(os.path.join(d, "spans.parquet"), columns=cols, filters=filt).to_pandas()
    return tr, sp


def node_tables(sp):
    """Per trace: node rows (trace_id, service, n_spans, text) and service edges."""
    par = sp[["trace_id", "span_id", "service"]].rename(columns={"span_id": "parent_id", "service": "psvc"})
    e = sp[["trace_id", "parent_id", "service"]].merge(par, on=["trace_id", "parent_id"])
    e = e[e["psvc"] != e["service"]][["trace_id", "psvc", "service"]].drop_duplicates()
    agg = {"span_id": "size"}
    if "attrs" in sp:
        sp = sp.assign(text=[" ".join(f"{k}={v}" for k, v in json.loads(a).items()) if a else "" for a in sp["attrs"]])
        agg["text"] = " ".join
    nodes = sp.groupby(["trace_id", "service"]).agg(agg).rename(columns={"span_id": "n_spans"}).reset_index()
    if "text" not in nodes:
        nodes["text"] = ""
    return nodes, e


class Featurizer:
    def fit(self, nodes, node_labels):
        """node_labels: the trace label of each node row (training data only)."""
        self.services = sorted(nodes["service"].unique())
        texts = nodes["text"]
        self.tfidf, self.keep = None, None
        if texts.str.len().gt(0).any():
            # words and punctuation runs (so "'--" or "../" survive); terms in more than half of the
            # nodes are boilerplate every span carries (span.kind, scope names) and are dropped;
            # the 16 kept terms are the most label-informative ones (chi2 on training nodes)
            self.tfidf = TfidfVectorizer(max_features=5000, token_pattern=r"(?u)\b\w\w+\b|[^\w\s=]{2,}",
                                         max_df=0.5, min_df=5, lowercase=True)
            X = self.tfidf.fit_transform(texts)
            sel = SelectKBest(chi2, k=min(N_TFIDF, X.shape[1])).fit(X, node_labels)
            self.keep = np.sort(sel.get_support(indices=True))
        return self

    @property
    def terms(self):
        return [] if self.tfidf is None else list(self.tfidf.get_feature_names_out()[self.keep])

    @property
    def dim(self):
        return len(self.services) + 1 + 2 + N_TFIDF        # one-hot (+ unseen), log spans, degree, tf-idf

    def graphs(self, tr, nodes, edges):
        pos = {s: i for i, s in enumerate(self.services)}
        tf = np.zeros((len(nodes), N_TFIDF), np.float32)
        if self.tfidf is not None:
            t = self.tfidf.transform(nodes["text"])[:, self.keep].toarray()
            tf[:, :t.shape[1]] = t
        nodes = nodes.assign(_row=np.arange(len(nodes)))
        nby = {t: g for t, g in nodes.groupby("trace_id")}
        eby = {t: g for t, g in edges.groupby("trace_id")}
        out = []
        for tid in tr["trace_id"]:
            g = nby.get(tid)
            if g is None:
                out.append(None)
                continue
            names = list(g["service"])
            ix = {s: i for i, s in enumerate(names)}
            ee = eby.get(tid)
            src = [ix[a] for a in ee["psvc"]] if ee is not None else []
            dst = [ix[b] for b in ee["service"]] if ee is not None else []
            ei = torch.tensor([src + dst, dst + src], dtype=torch.long).reshape(2, -1)   # symmetrised
            deg = np.bincount(ei[0].numpy(), minlength=len(names))
            x = np.zeros((len(names), self.dim), np.float32)
            for i, s in enumerate(names):
                x[i, pos.get(s, len(self.services))] = 1.0
            x[:, len(self.services) + 1] = np.log1p(g["n_spans"].to_numpy())
            x[:, len(self.services) + 2] = np.log1p(deg)
            x[:, len(self.services) + 3:] = tf[g["_row"].to_numpy()]
            out.append(Data(x=torch.tensor(x), edge_index=ei))
        return out


class MaGCN(nn.Module):
    def __init__(self, d_in, n_classes, hidden=32):
        super().__init__()
        self.c1, self.c2 = GCNConv(d_in, hidden), GCNConv(hidden, hidden)
        self.mlp = nn.Sequential(nn.Linear(hidden, hidden), nn.ReLU(), nn.Linear(hidden, n_classes))

    def forward(self, b):
        b = b.to(next(self.parameters()).device)
        h = F.relu(self.c1(b.x, b.edge_index))
        h = F.relu(self.c2(h, b.edge_index))
        return self.mlp(global_mean_pool(h, b.batch))


def sample_ids(runs, level, features_dir, max_per_class, seed):
    tr = pd.concat([pd.read_parquet(os.path.join(features_dir, r, level, "traces.parquet"),
                                    columns=["run_id", "trace_id", "label"]) for r in runs], ignore_index=True)
    parts = [g.sample(min(len(g), max_per_class), random_state=seed) for _, g in tr.groupby("label")]
    return pd.concat(parts)


def load_part(runs, level, features_dir, ids=None):
    trs, nodes, edges = [], [], []
    for r in runs:
        want = None if ids is None else set(ids.loc[ids["run_id"] == r, "trace_id"])
        tr, sp = read_run(r, level, features_dir, want)
        n, e = node_tables(sp)
        trs.append(tr)
        nodes.append(n)
        edges.append(e)
    return pd.concat(trs, ignore_index=True), pd.concat(nodes, ignore_index=True), pd.concat(edges, ignore_index=True)


def predict(model, graphs, batch=1024):
    model.eval()
    out = []
    with torch.no_grad():
        for i in range(0, len(graphs), batch):
            out.append(F.softmax(model(Batch.from_data_list(graphs[i:i + batch])), 1).cpu().numpy())
    return np.concatenate(out) if out else np.zeros((0, len(CLASSES)))


def to_windows(req, windows, k):
    """Request probabilities -> window rows in the train.py prediction format."""
    E = req.groupby(["run_id", "window"])[[f"p_{c}" for c in CLASSES[1:]]].sum()
    w = windows[["run_id", "run_kind", "window", f"label_k{k}", "complete"]].rename(columns={f"label_k{k}": "label"})
    w = w[(w["label"] != "excluded") & w["complete"]].drop(columns="complete")
    w = w.merge(E, left_on=["run_id", "window"], right_index=True, how="left").fillna(0.0)
    q = np.column_stack([np.full(len(w), float(k))] + [w[f"p_{c}"].to_numpy() for c in CLASSES[1:]])
    p = q / q.sum(1, keepdims=True)
    for i, c in enumerate(CLASSES):
        w[f"p_{c}"] = p[:, i]
    w["y"] = [CLASSES.index(lab) for lab in w["label"]]
    w["pred"] = p.argmax(1)
    return w.reset_index(drop=True)


def main():
    ap = argparse.ArgumentParser(description="Ma 2026 per-request GCN baseline")
    add_split_args(ap)
    ap.add_argument("--max-per-class", type=int, default=5000, help="training traces per class (all runs)")
    ap.add_argument("--max-per-class-val", type=int, default=1000)
    ap.add_argument("--epochs", type=int, default=100)
    ap.add_argument("--patience", type=int, default=15)
    ap.add_argument("--batch", type=int, default=128)
    ap.add_argument("--lr", type=float, default=1e-3)
    ap.add_argument("--hidden", type=int, default=32, help="32 as in Ma's reproduction command (p. 9)")
    ap.add_argument("--features-dir", default=FEATURES_DIR)
    a = ap.parse_args()
    runs = split_runs(ap, a)
    v = variant(ap, a)
    model_name = "ma" + (f"_{v}" if v else "")
    name, out = results_dir(a, model_name)          # before training
    set_seed(a.seed)
    t0 = time.time()

    tr_ids = sample_ids(runs["train"], a.level, a.features_dir, a.max_per_class, a.seed)
    tr, tn, te = load_part(runs["train"], a.level, a.features_dir, tr_ids)
    feat = Featurizer().fit(tn, tn["trace_id"].map(tr.set_index("trace_id")["label"]).to_numpy())
    gtr = feat.graphs(tr, tn, te)
    keep = [i for i, g in enumerate(gtr) if g is not None]
    gtr, ytr = [gtr[i] for i in keep], np.array([CLASSES.index(lab) for lab in tr["label"].iloc[keep]])
    gva, yva = [], np.array([], int)
    if runs["val"]:
        va_ids = sample_ids(runs["val"], a.level, a.features_dir, a.max_per_class_val, a.seed)
        va, vn, ve = load_part(runs["val"], a.level, a.features_dir, va_ids)
        g = feat.graphs(va, vn, ve)
        kv = [i for i, x in enumerate(g) if x is not None]
        gva, yva = [g[i] for i in kv], np.array([CLASSES.index(lab) for lab in va["label"].iloc[kv]])

    dev = resolve_device(a.device)
    model = MaGCN(feat.dim, len(CLASSES), a.hidden).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=a.lr)
    w = class_weights(ytr, len(CLASSES)).to(dev)
    rng = np.random.default_rng(a.seed)
    best, best_state, best_epoch, wait, hist = -1.0, None, 0, 0, []
    for epoch in range(1, a.epochs + 1):
        model.train()
        order, tot = rng.permutation(len(gtr)), 0.0
        for i in range(0, len(order), a.batch):
            b = order[i:i + a.batch]
            loss = F.cross_entropy(model(Batch.from_data_list([gtr[j] for j in b])), torch.tensor(ytr[b]).to(dev), weight=w)
            opt.zero_grad()
            loss.backward()
            opt.step()
            tot += loss.item() * len(b)
        f1 = macro_f1(yva, predict(model, gva).argmax(1)) if len(gva) else float("nan")
        hist.append({"epoch": epoch, "loss": tot / len(gtr), "val_macro_f1_requests": f1})
        if not len(gva) or f1 > best:
            best, best_epoch, wait = f1, epoch, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            wait += 1
            if wait >= a.patience:
                break
    model.load_state_dict(best_state)

    win_rows, req_rows = [], []
    for p in ("val", "test", "heldout"):
        for r in runs.get(p) or []:                 # every trace of every evaluation run, one run at a time
            t, n, e = load_part([r], a.level, a.features_dir)
            g = feat.graphs(t, n, e)
            ok = [i for i, x in enumerate(g) if x is not None]
            prob = predict(model, [g[i] for i in ok])
            req = t.iloc[ok].reset_index(drop=True)
            req.insert(0, "part", p)
            req["y"] = [CLASSES.index(lab) for lab in req["label"]]
            req["pred"] = prob.argmax(1)
            for i, c in enumerate(CLASSES):
                req[f"p_{c}"] = prob[:, i]
            req_rows.append(req)
            wins = pd.read_parquet(os.path.join(a.features_dir, r, a.level, "windows.parquet"),
                                   columns=["run_id", "run_kind", "window", f"label_k{a.k}", "complete"])
            wr = to_windows(req, wins, a.k)
            wr.insert(0, "part", p)
            win_rows.append(wr)

    pred, reqs = pd.concat(win_rows, ignore_index=True), pd.concat(req_rows, ignore_index=True)
    pred.to_parquet(os.path.join(out, "predictions.parquet"), index=False)
    reqs.to_parquet(os.path.join(out, "requests.parquet"), index=False)
    pd.DataFrame(hist).to_csv(os.path.join(out, "history.csv"), index=False)
    cfg = {k: v for k, v in vars(a).items()}
    cfg.update({"model_name": model_name, "device_used": str(dev), "runs": runs, "assignment": a.assignment if a.split else None,
                "train_traces": len(gtr), "train_labels": pd.Series(ytr).map(dict(enumerate(CLASSES))).value_counts().to_dict(),
                "val_traces": len(gva), "services": feat.services,
                "tfidf_terms": feat.terms,
                "best_epoch": best_epoch, "best_val_macro_f1_requests": best, "seconds": round(time.time() - t0, 1)})
    json.dump(cfg, open(os.path.join(out, "config.json"), "w"), indent=1, default=str)
    msg = "  ".join(f"{p}: requests macro-F1 {macro_f1(g['y'].to_numpy(), g['pred'].to_numpy()):.3f}"
                    for p, g in reqs.groupby("part"))
    msg += "  " + "  ".join(f"{p}: windows macro-F1 {macro_f1(g['y'].to_numpy(), g['pred'].to_numpy()):.3f}"
                            for p, g in pred.groupby("part"))
    print(f"[ma] {name}: {len(gtr)} training traces, best epoch {best_epoch}; {msg} ({cfg['seconds']} s) -> {out}")


if __name__ == "__main__":
    main()
