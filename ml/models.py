"""Window classifiers.

ST-GNN: per window, a service embedding plus the node features, plus the mean
of the node's incoming and outgoing edge features (so GCN and GraphSAGE, which
cannot read edge features, see them too), then 2 graph layers, mean + max
pooling -> one vector per window; a GRU over the T windows of a sample; a
linear classifier on its last state. Encoders: "gatv2" (main model, also uses
the edge features in its attention), "gcn", "sage".

Flat baselines on the last window's flat vector: random forest, gradient
boosting (LightGBM, fitted in a child process by ml/gbm_fit.py, see
ml/__init__.py), an MLP and a linear SVM (scikit-learn), all class-weighted and
tuned by grid search on the validation runs (GRIDS).
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Batch
from torch_geometric.nn import GATv2Conv, GCNConv, SAGEConv, global_max_pool, global_mean_pool
from torch_geometric.utils import scatter

ENCODERS = ("gatv2", "gcn", "sage")
FLAT_MODELS = ("rf", "gbm", "mlp", "svm")

# Flat baselines are tuned like Osswald et al. (PDP 2025, §IV-D, Table VI: grid search,
# RF and SVM baselines), but on our VALIDATION RUNS instead of random folds of the
# training data (windows of one run are correlated, so random folds would leak).
# Their selected settings (RF 100 trees, depth 6; SVM C = 10, L2, tol 1e-4) are in the grids.
GRIDS = {
    "rf": {"n_estimators": [100, 300, 500], "max_depth": [6, 12, None]},
    "svm": {"C": [0.1, 1, 10]},
    "mlp": {"hidden_layer_sizes": [(64,), (128, 64)], "alpha": [1e-4, 1e-3]},
    "gbm": {"num_leaves": [15, 31, 63], "n_estimators": [100, 300]},
}
DEFAULTS = {"rf": {"n_estimators": 500, "max_depth": None}, "svm": {"C": 1.0},
            "mlp": {"hidden_layer_sizes": (128, 64), "alpha": 1e-4},
            "gbm": {"num_leaves": 31, "n_estimators": 300}}


class LinearSVM:
    """Linear SVM (L2 penalty, tol 1e-4, as in Osswald et al.) on standardised
    features, class-weighted; predict_proba = softmax of the decision values (a
    monotone score per class, enough for PR-AUC and the attack score)."""

    def __init__(self, C=1.0, seed=0):
        from sklearn.pipeline import make_pipeline
        from sklearn.preprocessing import StandardScaler
        from sklearn.svm import LinearSVC
        self.model = make_pipeline(StandardScaler(), LinearSVC(C=C, penalty="l2", tol=1e-4, class_weight="balanced",
                                                               max_iter=20000, random_state=seed))

    def fit(self, X, y):
        self.model.fit(X, y)
        self.classes_ = self.model.classes_
        return self

    def predict_proba(self, X):
        d = self.model.decision_function(X)
        if d.ndim == 1:                              # two classes: one decision value
            d = np.column_stack([-d, d])
        e = np.exp(d - d.max(1, keepdims=True))
        return e / e.sum(1, keepdims=True)

    def predict(self, X):
        return self.classes_[self.predict_proba(X).argmax(1)]


class STGNN(nn.Module):
    def __init__(self, node_dim, edge_dim, n_services, n_classes, encoder="gatv2",
                 hidden=64, svc_dim=8, heads=2, dropout=0.2):
        super().__init__()
        if encoder not in ENCODERS:
            raise ValueError(encoder)
        self.encoder, self.dropout, self.hidden = encoder, dropout, hidden
        self.svc = nn.Embedding(n_services, svc_dim)
        d_in = node_dim + svc_dim + 2 * edge_dim
        if encoder == "gatv2":
            self.c1 = GATv2Conv(d_in, hidden // heads, heads=heads, edge_dim=edge_dim)
            self.c2 = GATv2Conv(hidden, hidden // heads, heads=heads, edge_dim=edge_dim)
        elif encoder == "gcn":
            self.c1, self.c2 = GCNConv(d_in, hidden), GCNConv(hidden, hidden)
        else:
            self.c1, self.c2 = SAGEConv(d_in, hidden), SAGEConv(hidden, hidden)
        self.gru = nn.GRU(2 * hidden, hidden, batch_first=True)
        self.out = nn.Linear(hidden, n_classes)

    @property
    def device(self):
        return next(self.parameters()).device

    def embed_windows(self, graphs):
        """List of window graphs -> [n_windows, 2 * hidden]."""
        b = Batch.from_data_list(graphs).to(self.device)
        n = b.x.size(0)
        ea = b.edge_attr
        e_in = scatter(ea, b.edge_index[1], dim=0, dim_size=n, reduce="mean")
        e_out = scatter(ea, b.edge_index[0], dim=0, dim_size=n, reduce="mean")
        h = torch.cat([b.x, self.svc(b.service), e_in, e_out], dim=1)
        for conv in (self.c1, self.c2):
            h = conv(h, b.edge_index, ea) if self.encoder == "gatv2" else conv(h, b.edge_index)
            h = F.dropout(F.elu(h), self.dropout, self.training)
        return torch.cat([global_mean_pool(h, b.batch), global_max_pool(h, b.batch)], dim=1)

    def forward(self, graphs, seq):
        """graphs: all window graphs of the dataset; seq: LongTensor [B, T], -1 = padding."""
        seq = seq.cpu()                       # indices into the (CPU) list of graphs
        used = torch.unique(seq[seq >= 0])
        emb = self.embed_windows([graphs[i] for i in used.tolist()])
        lookup = torch.full((int(seq.max()) + 1,), -1, dtype=torch.long)
        lookup[used] = torch.arange(len(used))
        z = torch.zeros(seq.size(0), seq.size(1), emb.size(1), device=emb.device)
        mask = seq >= 0
        z[mask.to(emb.device)] = emb[lookup[seq[mask]].to(emb.device)]
        _, h = self.gru(z)
        return self.out(h[-1])


def resolve_device(name):
    """--device: "auto" = CUDA if available, else CPU; or an explicit torch device."""
    if name == "auto":
        return torch.device("cuda" if torch.cuda.is_available() else "cpu")
    return torch.device(name)


def class_weights(y, n_classes):
    """Inverse frequency, normalised to mean 1; classes absent from training get 0."""
    counts = np.bincount(y, minlength=n_classes).astype(float)
    w = np.where(counts > 0, counts.sum() / np.maximum(counts, 1) / (counts > 0).sum(), 0.0)
    return torch.tensor(w, dtype=torch.float32)


def make_flat(name, seed, **params):
    """A flat baseline with the given settings (DEFAULTS where none are given)."""
    p = {**DEFAULTS[name], **params}
    if name == "rf":
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(class_weight="balanced", n_jobs=-1, random_state=seed, **p)
    if name == "mlp":
        from sklearn.neural_network import MLPClassifier
        return MLPClassifier(early_stopping=False, max_iter=500, random_state=seed, **p)
    if name == "svm":
        return LinearSVM(C=p["C"], seed=seed)
    raise ValueError(name)       # gbm runs in its own process (ml/gbm_fit.py)
