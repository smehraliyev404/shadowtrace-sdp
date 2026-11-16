"""Window classifiers (PLAN.md §10).

ST-GNN: per window, a service embedding plus the node features, plus the mean
of the node's incoming and outgoing edge features (so GCN and GraphSAGE, which
cannot read edge features, see them too), then 2 graph layers, mean + max
pooling -> one vector per window; a GRU over the T windows of a sample; a
linear classifier on its last state. Encoders: "gatv2" (main model, also uses
the edge features in its attention), "gcn", "sage".

Flat baselines on the last window's flat vector: random forest, gradient
boosting (LightGBM, fitted in a child process by ml/gbm_fit.py, see
ml/__init__.py) and an MLP (scikit-learn), all class-weighted.
"""

import numpy as np
import torch
import torch.nn as nn
import torch.nn.functional as F
from torch_geometric.data import Batch
from torch_geometric.nn import GATv2Conv, GCNConv, SAGEConv, global_max_pool, global_mean_pool
from torch_geometric.utils import scatter

ENCODERS = ("gatv2", "gcn", "sage")
FLAT_MODELS = ("rf", "gbm", "mlp")


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

    def embed_windows(self, graphs):
        """List of window graphs -> [n_windows, 2 * hidden]."""
        b = Batch.from_data_list(graphs)
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
        used = torch.unique(seq[seq >= 0])
        emb = self.embed_windows([graphs[i] for i in used.tolist()])
        lookup = torch.full((int(seq.max()) + 1,), -1, dtype=torch.long)
        lookup[used] = torch.arange(len(used))
        z = torch.zeros(seq.size(0), seq.size(1), emb.size(1))
        mask = seq >= 0
        z[mask] = emb[lookup[seq[mask]]]
        _, h = self.gru(z)
        return self.out(h[-1])


def class_weights(y, n_classes):
    """Inverse frequency, normalised to mean 1; classes absent from training get 0."""
    counts = np.bincount(y, minlength=n_classes).astype(float)
    w = np.where(counts > 0, counts.sum() / np.maximum(counts, 1) / (counts > 0).sum(), 0.0)
    return torch.tensor(w, dtype=torch.float32)


def make_flat(name, seed):
    if name == "rf":
        from sklearn.ensemble import RandomForestClassifier
        return RandomForestClassifier(n_estimators=500, class_weight="balanced", n_jobs=-1, random_state=seed)
    if name == "mlp":
        from sklearn.neural_network import MLPClassifier
        return MLPClassifier(hidden_layer_sizes=(128, 64), early_stopping=False, max_iter=500,
                             random_state=seed)
    raise ValueError(name)
