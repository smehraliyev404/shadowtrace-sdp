"""Jacob et al. (2022) baseline: DCRNN forecaster of operation-pair call counts.

Re-implementation of Jacob, Qiao, Ye & Lee, "Anomalous distributed traffic:
Detecting cyber security attacks amongst microservices using graph
convolutional networks", Computers & Security 118 (2022) 102728:

  nodes      source -> destination RPC pairs, each end "service + operation",
             within and across services, "-" as the source of a root (their
             §4.3, Table A1): windows.parquet `op_edges`; the set seen in
             NORMAL training windows (fixed graph, as in the paper)
  adjacency  Algorithm 1: 0.5 both ways when two pairs share a source or a
             destination (self-loops included), 1.0 for a dependency (one
             pair's destination is the other's source)
  feature    calls of that pair in the window (§4.4; here log1p and
             standardised per node, as DCRNN inputs usually are)
  model      DCRNN: diffusion convolution (dual random walk, K = 2) inside GRU
             cells, encoder-decoder, 2 layers x 150 units; Adam, lr 0.01 with
             decay ratio 0.1, MAE loss, up to 50 epochs, early stopping 15
             (§4.6-4.8, §5.4, Fig. 3); forecasts the next window (one step, §5.4)
  training   normal windows only (self-supervised, no attack labels; PLAN.md C3)
  detection  per-node forecast error outside mu_i +- 2 sigma_i (§4.9); mu and
             sigma from validation normal windows. Window score =
             max_i |e_i - mu_i| / sigma_i, flagged if > 2.

Differences from the paper (data, not method): 60 s windows and our input
length (--t-in, default 4; the paper does not give it); windows before a
run's start are filled with the first window, in training and scoring alike;
the error sigma has a floor (MIN_ERR_SD). Pairs never
seen in normal training are not graph nodes, as in the paper's fixed graph.
It is a detector: it says normal or attack, not which attack, so metrics.py
scores it binary (config "detector": true).

    ./venv/bin/python -m ml.jacob --split splits/batch3.json --assignment 0 --seed 1
"""

import argparse
import json
import os
import time

import numpy as np
import pandas as pd
import torch
import torch.nn as nn

from ml.data import CLASSES, load_runs

T_IN = 4               # input windows; the paper does not give T'
MIN_ERR_SD = 0.05      # floor for the per-node error sigma (inputs are standardised, so 0.05 = 5 % of a node's spread)
FLAGGED = len(CLASSES)  # pred of a flagged window: out of range for CLASSES on purpose (a detector names no class)
from ml.models import resolve_device
from ml.train import add_split_args, results_dir, set_seed, split_runs, variant


def pair_key(e):
    return (e["src"], e["dst"])


def build_graph(train):
    normal = train[train["label_k1"] == "normal"]
    pairs = sorted({pair_key(e) for ops in normal["op_edges"] for e in ops})
    n = len(pairs)
    A = np.zeros((n, n), np.float32)
    for i, (si, di) in enumerate(pairs):                        # Algorithm 1, in its order
        for j, (sj, dj) in enumerate(pairs):
            if si == sj or di == dj:                            # includes i == j: self-loop 0.5
                A[j, i] = A[i, j] = 0.5
            if si == dj:
                A[j, i] = 1.0                                   # dependency j -> i
            if di == sj:
                A[i, j] = 1.0                                   # dependency i -> j
    return pairs, A


def supports(A):
    """Dual random walk transition matrices (DCRNN): forward D_out^-1 A, backward D_in^-1 A^T."""
    def rw(M):
        d = M.sum(1, keepdims=True)
        return np.divide(M, d, out=np.zeros_like(M), where=d > 0)
    return [torch.tensor(rw(A)), torch.tensor(rw(A.T))]


def count_matrix(windows, pairs):
    """[n_windows, n_pairs] call counts, windows in run/window order."""
    pos = {p: i for i, p in enumerate(pairs)}
    X = np.zeros((len(windows), len(pairs)), np.float32)
    for r, ops in enumerate(windows["op_edges"]):
        for e in ops:
            i = pos.get(pair_key(e))
            if i is not None:
                X[r, i] += e["count"]
    return np.log1p(X)


def sequences(windows, X, t_in, train_mode, relaxed=False):
    """(inputs [S, t_in, N], targets [S, N], row index of the target window).

    The input is the t_in windows before the target; near a run's start there
    are fewer, and the history is padded with the run's first window. Training
    uses the same padding (every target from the second window on), so the
    forecaster has seen start-of-run sequences before it is scored on them.
    Training and validation targets are complete windows only."""
    xs, ys, rows = [], [], []
    for _, g in windows.groupby("run_id", sort=False):
        idx = g.index.to_numpy()
        normal = (g["label_k1"] == "normal").to_numpy()
        complete = g["complete"].to_numpy()
        for j in range(len(idx)):
            hist = [idx[max(j - t_in + h, 0)] for h in range(t_in)]
            if train_mode:
                # the target must be a complete window: a run's partial last window would
                # teach a fake end-of-run collapse and inflate the validation sigma
                if j < 1 or not normal[j] or not complete[j] \
                        or (not relaxed and not normal[max(0, j - t_in):j].all()):
                    continue
            xs.append(X[hist])
            ys.append(X[idx[j]])
            rows.append(idx[j])
    n = X.shape[1]
    return (np.array(xs, np.float32).reshape(-1, t_in, n), np.array(ys, np.float32).reshape(-1, n),
            np.array(rows, np.int64))


class DiffConv(nn.Module):
    def __init__(self, d_in, d_out, n_supports, k):
        super().__init__()
        self.k = k
        self.lin = nn.Linear(d_in * (1 + n_supports * k), d_out)

    def forward(self, x, sup):                      # x: [B, N, d_in]
        out = [x]
        for P in sup:
            h = x
            for _ in range(self.k):
                h = torch.einsum("nm,bmd->bnd", P, h)
                out.append(h)
        return self.lin(torch.cat(out, dim=-1))


class DCGRUCell(nn.Module):
    def __init__(self, d_in, hidden, n_supports, k):
        super().__init__()
        self.hidden = hidden
        self.gates = DiffConv(d_in + hidden, 2 * hidden, n_supports, k)
        self.cand = DiffConv(d_in + hidden, hidden, n_supports, k)

    def forward(self, x, h, sup):
        r, u = torch.sigmoid(self.gates(torch.cat([x, h], -1), sup)).chunk(2, -1)
        c = torch.tanh(self.cand(torch.cat([x, r * h], -1), sup))
        return u * h + (1 - u) * c


class DCRNN(nn.Module):
    def __init__(self, sup, hidden=150, layers=2, k=2):
        super().__init__()
        self.n_sup = len(sup)
        for i, P in enumerate(sup):               # buffers, so .to(device) moves them too
            self.register_buffer(f"sup{i}", P)
        self.enc = nn.ModuleList([DCGRUCell(1 if i == 0 else hidden, hidden, len(sup), k) for i in range(layers)])
        self.dec = nn.ModuleList([DCGRUCell(1 if i == 0 else hidden, hidden, len(sup), k) for i in range(layers)])
        self.proj = nn.Linear(hidden, 1)

    @property
    def sup(self):
        return [getattr(self, f"sup{i}") for i in range(self.n_sup)]

    def forward(self, x):                           # x: [B, T, N] -> [B, N]
        x = x.to(self.sup[0].device)
        B, T, N = x.shape
        h = [x.new_zeros(B, N, c.hidden) for c in self.enc]
        for t in range(T):
            inp = x[:, t, :, None]
            for i, cell in enumerate(self.enc):
                h[i] = cell(inp, h[i], self.sup)
                inp = h[i]
        inp = x.new_zeros(B, N, 1)                  # GO symbol, one decoder step (horizon 1)
        for i, cell in enumerate(self.dec):
            h[i] = cell(inp, h[i], self.sup)
            inp = h[i]
        return self.proj(inp).squeeze(-1)


def main():
    ap = argparse.ArgumentParser(description="Jacob et al. 2022 DCRNN forecaster baseline")
    add_split_args(ap)
    ap.add_argument("--relaxed", action="store_true",
                    help="laptop test only: train on normal targets even if earlier windows had attacks")
    ap.add_argument("--t-in", type=int, default=T_IN)
    ap.add_argument("--hidden", type=int, default=150)
    ap.add_argument("--layers", type=int, default=2)
    ap.add_argument("--diffusion-k", type=int, default=2)
    ap.add_argument("--lr", type=float, default=0.01)
    ap.add_argument("--epochs", type=int, default=50)
    ap.add_argument("--patience", type=int, default=15)
    ap.add_argument("--batch", type=int, default=32)
    ap.add_argument("--features-dir")
    a = ap.parse_args()
    runs = split_runs(ap, a)
    v = variant(ap, a)
    model_name = "jacob" + (f"_{v}" if v else "")
    name, out = results_dir(a, model_name)          # before training
    set_seed(a.seed)
    t0 = time.time()
    win = {p: load_runs(r, a.level, a.features_dir, a.l0_redacted) for p, r in runs.items() if r}
    if "op_edges" not in win["train"]:
        raise SystemExit("windows.parquet has no op_edges: rebuild the features with build_features.py")
    pairs, A = build_graph(win["train"])
    if not pairs:
        raise SystemExit("no operation pairs in normal training windows")
    Xr = {p: count_matrix(w, pairs) for p, w in win.items()}
    tr_normal = win["train"]["label_k1"].to_numpy() == "normal"
    mu, sd = Xr["train"][tr_normal].mean(0), Xr["train"][tr_normal].std(0)
    sd = np.where(sd > 1e-6, sd, 1.0)
    X = {p: (x - mu) / sd for p, x in Xr.items()}

    xtr, ytr, _ = sequences(win["train"], X["train"], a.t_in, True, a.relaxed)
    if not len(xtr):
        raise SystemExit("no all-normal training sequences (use --relaxed only for laptop tests)")
    has_val = "val" in win
    xva, yva, _ = sequences(win["val"], X["val"], a.t_in, True, a.relaxed) if has_val else (None, None, None)
    dev = resolve_device(a.device)
    model = DCRNN(supports(A), a.hidden, a.layers, a.diffusion_k).to(dev)
    opt = torch.optim.Adam(model.parameters(), lr=a.lr)
    # decay ratio 0.1 (§5.4); the paper gives no decay epochs, these are an assumption
    sched = torch.optim.lr_scheduler.MultiStepLR(opt, milestones=[20, 30, 40], gamma=0.1)
    rng = np.random.default_rng(a.seed)
    best, best_state, best_epoch, wait, hist = np.inf, None, 0, 0, []
    for epoch in range(1, a.epochs + 1):
        model.train()
        order, tot = rng.permutation(len(xtr)), 0.0
        for i in range(0, len(order), a.batch):
            b = order[i:i + a.batch]
            loss = nn.functional.l1_loss(model(torch.tensor(xtr[b])), torch.tensor(ytr[b]).to(dev))
            opt.zero_grad()
            loss.backward()
            opt.step()
            tot += loss.item() * len(b)
        model.eval()
        with torch.no_grad():
            vl = float(nn.functional.l1_loss(model(torch.tensor(xva)), torch.tensor(yva).to(dev))) \
                if has_val and len(xva) else tot / len(xtr)
        sched.step()
        hist.append({"epoch": epoch, "train_mae": tot / len(xtr), "val_mae": vl})
        if vl < best:
            best, best_epoch, wait = vl, epoch, 0
            best_state = {k: v.clone() for k, v in model.state_dict().items()}
        else:
            wait += 1
            if wait >= a.patience:
                break
    model.load_state_dict(best_state)
    model.eval()

    def errors(xs, ys):
        with torch.no_grad():
            return ys - model(torch.tensor(xs)).cpu().numpy()

    ref = errors(xva, yva) if has_val and len(xva) else errors(xtr, ytr)
    e_mu, e_sd = ref.mean(0), ref.std(0)
    e_sd = np.maximum(e_sd, MIN_ERR_SD)   # a node with near-constant error must not turn tiny changes into alarms

    rows = []
    for p in ("val", "test", "heldout"):
        if p not in win:
            continue
        w = win[p]
        xs, ys, idx = sequences(w, X[p], a.t_in, False)
        score = np.abs((errors(xs, ys) - e_mu) / e_sd).max(1)
        d = w.loc[idx, ["run_id", "run_kind", "window", f"label_k{a.k}", "complete"]].rename(
            columns={f"label_k{a.k}": "label"})
        keep = (d["label"] != "excluded") & d["complete"]
        d, score = d[keep].drop(columns="complete").reset_index(drop=True), score[keep.to_numpy()]
        d.insert(0, "part", p)
        d["y"] = [CLASSES.index(lab) for lab in d["label"]]
        p_normal = 1.0 / (1.0 + (score / 2.0) ** 4)          # 0.5 exactly at the 2-sigma threshold
        d["pred"] = np.where(score > 2.0, FLAGGED, 0)         # CLASSES[FLAGGED] raises: no class is named
        d["score"] = score
        d["p_normal"] = p_normal
        for c in CLASSES[1:]:
            d[f"p_{c}"] = (1 - p_normal) / (len(CLASSES) - 1)
        rows.append(d)
    pred = pd.concat(rows, ignore_index=True)

    pred.to_parquet(os.path.join(out, "predictions.parquet"), index=False)
    pd.DataFrame(hist).to_csv(os.path.join(out, "history.csv"), index=False)
    cfg = {k: v for k, v in vars(a).items()}
    cfg.update({"model_name": model_name, "device_used": str(dev), "detector": True, "runs": runs,
                "assignment": a.assignment if a.split else None, "n_pairs": len(pairs),
                "pairs": [list(p) for p in pairs], "train_sequences": len(xtr),
                "val_sequences": 0 if xva is None else len(xva), "best_epoch": best_epoch,
                "best_val_mae": best, "seconds": round(time.time() - t0, 1)})
    json.dump(cfg, open(os.path.join(out, "config.json"), "w"), indent=1, default=str)
    flag = [f"{part}: flagged {int((g['pred'] != 0).sum())}/{len(g)} (attack windows {int((g['y'] != 0).sum())})"
            for part, g in pred.groupby("part")]
    print(f"[jacob] {name}: {len(pairs)} pairs, {len(xtr)} training sequences, best epoch {best_epoch}; "
          + "; ".join(flag) + f" ({cfg['seconds']} s) -> {out}")


if __name__ == "__main__":
    main()
