"""windows.parquet -> model inputs (graph sequences for the ST-GNN, flat vectors
for RF / GBM / MLP).

Everything that is learned from data (edge reference statistics, service and
edge vocabularies, feature scaling) is fitted on the TRAINING runs only, by
`Prep.fit`, and then applied to validation, test and held-out runs.

    from ml.data import Prep, load_runs, build
    train = load_runs(["a3_01", ...], level="L2")
    prep = Prep.fit(train)
    ds = build(load_runs(["a3_02"], level="L2"), prep, k=3)
    ds.graphs[i]      torch_geometric Data for window i (x, service, edge_index, edge_attr)
    ds.seq            [N, T] window indices per sample (-1 = before the run started)
    ds.y              [N] class index (CLASSES)
    ds.flat           [N, F] flat features of the sample's last window

A sample is one complete, non-excluded window w together with the T - 1
windows before it in the same run (PLAN.md §8: T = 12). Sequences never cross
runs. Options: `use_seen=False` zeroes the "seen" edge feature, and
`use_content=False` zeroes the node content features (PLAN.md §11 ablations).
"""

import os
import sys

import numpy as np
import pandas as pd
import torch
from torch_geometric.data import Data

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(PROJECT_ROOT, "scripts"))

from build_features import ATTACKS, CONTENT_FEATURES  # noqa: E402
from edge_norm import FEATURES as EDGE_FEATURES, fit as fit_edges, transform as transform_edges  # noqa: E402

CLASSES = ("normal",) + ATTACKS
T = 12
NODE_STRUCT = ("n_spans", "n_server", "err_share", "server_p50_us")
NODE_FEATURES = NODE_STRUCT + CONTENT_FEATURES
LOG_NODE = {"n_spans", "n_server", "server_p50_us"}
WINDOW_FEATURES = ("n_traces", "n_spans", "n_calls", "n_edges", "n_patterns",
                   "client_err", "server_err", "trace_p50_us", "trace_p95_us")
LOG_WINDOW = {"n_traces", "n_spans", "n_calls", "n_edges", "n_patterns", "trace_p50_us", "trace_p95_us"}
OTHER = "<other>"
FEATURES_DIR = os.path.join(PROJECT_ROOT, "data", "features")
# D19: at L0 the node feature c_redacted is 0 by construction (nothing is redacted),
# so L1 had a signal L0 lacked. With this on, L0 takes each node's c_redacted from
# the L1 windows of the same run: the share of values the L1 redactor WOULD replace,
# computable from the raw L0 spans by the same rules. On since 19 Nov (every L0 result
# retrained; the earlier L0 results, without it, are in results_old_L0/ on the lab).
L0_REDACTED = True


def _read(run_ids, level, d):
    missing = [r for r in run_ids if not os.path.exists(os.path.join(d, r, level, "windows.parquet"))]
    if missing:
        raise FileNotFoundError(f"no {level} features for {missing} in {d} (run build_features.py)")
    return pd.concat([pd.read_parquet(os.path.join(d, r, level, "windows.parquet")) for r in run_ids],
                     ignore_index=True)


def with_l1_redacted(w0, w1):
    """L0 windows with every node's c_redacted replaced by the L1 value of the same
    run, window and service (0 where L1 has no such node)."""
    ref = {(r, int(win)): {n["service"]: float(n.get("c_redacted", 0.0)) for n in nodes}
           for r, win, nodes in zip(w1["run_id"], w1["window"], w1["nodes"])}
    keys = list(zip(w0["run_id"], w0["window"].astype(int)))
    missing = [k for k in keys if k not in ref]
    if missing:
        raise ValueError(f"{len(missing)} L0 windows have no L1 window, e.g. {missing[:3]}")
    w0 = w0.copy()
    w0["nodes"] = [[{**n, "c_redacted": ref[k].get(n["service"], 0.0)} for n in nodes]
                   for k, nodes in zip(keys, w0["nodes"])]
    return w0


def load_runs(run_ids, level="L2", features_dir=None, l0_redacted=None):
    """l0_redacted: None = L0_REDACTED (only matters for level L0)."""
    d = features_dir or FEATURES_DIR
    w = _read(run_ids, level, d)
    if level == "L0" and (L0_REDACTED if l0_redacted is None else l0_redacted):
        w = with_l1_redacted(w, _read(run_ids, "L1", d)[["run_id", "window", "nodes"]])
    return w.sort_values(["run_id", "window"]).reset_index(drop=True)


def _node_raw(n):
    return [np.log1p(float(n.get(f, 0.0))) if f in LOG_NODE else float(n.get(f, 0.0)) for f in NODE_FEATURES]


def _window_raw(row):
    return [np.log1p(float(row[f])) if f in LOG_WINDOW else float(row[f]) for f in WINDOW_FEATURES]


class Prep:
    """Statistics fitted on the training windows only."""

    @classmethod
    def fit(cls, train):
        p = cls()
        p.train_runs = sorted(train["run_id"].unique())
        p.edge_stats = fit_edges(train)                       # normal windows only (D14)
        services = set()
        for nodes, edges in zip(train["nodes"], train["edges"]):
            services |= {n["service"] for n in nodes}
            services |= {e["src"] for e in edges} | {e["dst"] for e in edges}
        p.services = [OTHER] + sorted(services)
        p.edge_vocab = sorted({(e["src"], e["dst"]) for edges in train["edges"] for e in edges})
        nx = np.array([_node_raw(n) for nodes in train["nodes"] for n in nodes] or [[0.0] * len(NODE_FEATURES)])
        p.node_mu, p.node_sd = nx.mean(0), np.where(nx.std(0) > 1e-9, nx.std(0), 1.0)
        wx = np.array([_window_raw(r) for _, r in train.iterrows()])
        p.win_mu, p.win_sd = wx.mean(0), np.where(wx.std(0) > 1e-9, wx.std(0), 1.0)
        return p

    def service_index(self, s):
        try:
            return self.services.index(s)
        except ValueError:
            return 0

    @property
    def n_services(self):
        return len(self.services)

    @property
    def flat_names(self):
        names = [f"w_{f}" for f in WINDOW_FEATURES]
        names += [f"e_{s}->{d}_{f}" for s, d in self.edge_vocab for f in EDGE_FEATURES]
        names += ["e_unseen_n", "e_unseen_log_count"]
        names += [f"n_{s}_{f}" for s in self.services[1:] for f in NODE_FEATURES]
        return names


class Dataset:
    def __init__(self, graphs, seq, y, flat, meta, flat_names, graph_keys=None):
        self.graphs, self.seq, self.y, self.flat, self.meta, self.flat_names = graphs, seq, y, flat, meta, flat_names
        self.graph_keys = graph_keys or []          # (run_id, window) of each graph

    def __len__(self):
        return len(self.y)

    def subset(self, idx):
        idx = np.asarray(idx)
        return Dataset(self.graphs, self.seq[idx], self.y[idx], self.flat[idx],
                       self.meta.iloc[idx].reset_index(drop=True), self.flat_names, self.graph_keys)


def build(windows, prep, k=3, use_seen=True, use_content=True, t=T, only_complete=True):
    """One Dataset from the windows of one or more runs (all of one split)."""
    label_col = f"label_k{k}"
    ef = transform_edges(windows, prep.edge_stats)
    if not use_seen:
        ef["seen"] = 0.0
    ef_by = {key: g for key, g in ef.groupby(["run_id", "window"])}
    content_idx = [NODE_FEATURES.index(f) for f in CONTENT_FEATURES]
    vocab_pos = {e: i for i, e in enumerate(prep.edge_vocab)}
    svc_pos = {s: i for i, s in enumerate(prep.services[1:])}
    n_edge_cols = len(EDGE_FEATURES)

    graphs, flat_rows, gid = [], [], {}
    for _, row in windows.iterrows():
        key = (row["run_id"], int(row["window"]))
        nodes = {n["service"]: n for n in row["nodes"]}
        e = ef_by.get(key)
        names = list(nodes)
        if e is not None:
            names += [s for s in pd.unique(pd.concat([e["src"], e["dst"]])) if s not in nodes]
        if not names:
            names = [OTHER]
        pos = {s: i for i, s in enumerate(names)}
        x = np.array([_node_raw(nodes.get(s, {})) for s in names], dtype=np.float32)
        x = ((x - prep.node_mu) / prep.node_sd).astype(np.float32)
        if not use_content:
            x[:, content_idx] = 0.0
        absent = np.array([s not in nodes for s in names])
        x[absent] = 0.0                      # client / redis / external: no node statistics
        if e is not None and len(e):
            ei = np.array([[pos[s] for s in e["src"]], [pos[d] for d in e["dst"]]], dtype=np.int64)
            ea = e[list(EDGE_FEATURES)].to_numpy(np.float32)
        else:
            ei, ea = np.zeros((2, 0), np.int64), np.zeros((0, n_edge_cols), np.float32)
        graphs.append(Data(x=torch.tensor(x), edge_index=torch.tensor(ei), edge_attr=torch.tensor(ea),
                           service=torch.tensor([prep.service_index(s) for s in names])))
        gid[key] = len(graphs) - 1

        f_edge = np.zeros(len(prep.edge_vocab) * n_edge_cols, np.float32)
        unseen_n, unseen_lc = 0, 0.0
        if e is not None:
            for r in e.itertuples(index=False):
                i = vocab_pos.get((r.src, r.dst))
                vals = [getattr(r, f) for f in EDGE_FEATURES]
                if i is None:
                    unseen_n += 1
                    unseen_lc += r.log_count
                else:
                    f_edge[i * n_edge_cols:(i + 1) * n_edge_cols] = vals
        f_node = np.zeros((len(svc_pos), len(NODE_FEATURES)), np.float32)
        for s, i_node in pos.items():
            if s in svc_pos and not absent[i_node]:
                f_node[svc_pos[s]] = x[i_node]
        f_win = (np.array(_window_raw(row)) - prep.win_mu) / prep.win_sd
        flat_rows.append(np.concatenate([f_win, f_edge, [unseen_n, unseen_lc], f_node.ravel()]))

    seq, y, meta, flat = [], [], [], []
    for _, row in windows.iterrows():
        lab = row[label_col]
        if lab == "excluded" or (only_complete and not row["complete"]):
            continue
        run, w = row["run_id"], int(row["window"])
        seq.append([gid.get((run, w - j), -1) for j in range(t - 1, -1, -1)])
        y.append(CLASSES.index(lab))
        meta.append({"run_id": run, "run_kind": row["run_kind"], "window": w, "label": lab})
        flat.append(flat_rows[gid[(run, w)]])
    return Dataset(graphs, np.array(seq, dtype=np.int64).reshape(-1, t), np.array(y, dtype=np.int64),
                   np.array(flat, dtype=np.float32).reshape(len(y), -1), pd.DataFrame(meta), prep.flat_names,
                   list(gid))
