# ShadowTrace: Spatio-Temporal GNN Model template
# PyTorch geometric model architecture for Metadata-Blind detection

import torch
import torch.nn.functional as F
from torch_geometric.nn import GCNConv, global_mean_pool

class ShadowTraceGNN(torch.nn.Module):
    # Spatio-Temporal GNN architecture for ShadowTrace
    # Performs spatial message passing over trace DAGs + global pooling
    def __init__(self, input_dim=25, hidden_dim=32, num_classes=2):
        super(ShadowTraceGNN, self).__init__()
        # Layer 1: Message passing between immediate neighbors
        self.conv1 = GCNConv(input_dim, hidden_dim)
        # Layer 2: Message passing across 2 hops
        self.conv2 = GCNConv(hidden_dim, hidden_dim)
        # Final Classifier (MLP)
        self.classifier = torch.nn.Linear(hidden_dim, num_classes)

    def forward(self, x, edge_index, batch):
        # Step 1: Spatial Message Passing
        x = self.conv1(x, edge_index)
        x = F.relu(x)
        x = self.conv2(x, edge_index)
        
        # Step 2: Global Mean Pooling (Readout Phase)
        graph_embedding = global_mean_pool(x, batch)
        
        # Step 3: MLP Anomaly Classification
        out = self.classifier(graph_embedding)
        return out

if __name__ == "__main__":
    model = ShadowTraceGNN(input_dim=25, hidden_dim=32, num_classes=2)
    print("PyTorch geometric ShadowTraceGNN Model started")
    print(model)
