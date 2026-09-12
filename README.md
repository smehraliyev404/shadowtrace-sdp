# 🛡️ ShadowTrace: Privacy-Preserving Security Anomaly Detection
### *Resolving the Privacy-Security Paradox in Microservice Telemetry via Metadata-Blind ST-GNNs*

ShadowTrace is an observability-driven security research framework designed to detect application-layer cyberattacks—specifically **lateral movement**—in cloud-native microservice architectures.

Standard observability pipelines (OpenTelemetry) create a **Privacy-Security Paradox**: auto-instrumentation exposes sensitive metadata (internal pod IPs, RPC schemas, tokens) in plain text, creating GDPR/CCPA compliance risks and an internal reconnaissance attack surface. ShadowTrace decouples threat detection from data exposure using **Spatio-Temporal Graph Neural Networks (ST-GNNs)**, achieving high threat detection fidelity on **100% redacted, metadata-blind telemetry streams**.

---

## 📂 Repository Structure

```text
shadowtrace-sdp/
├── DB/                           # Database design & MongoDB collection schemas
│   ├── Schemas/                  # Collection JSON schemas (alerts, privacy_audits, etc.)
│   ├── indexes.js                # Reference: full-system indexes (all 8 collections, eventual)
│   ├── mongo_client.py           # Shared connection helper (Atlas MONGO_URI or local docker-compose)
│   ├── setup_database.py         # Creates validators/indexes for the 4 collections used this phase
│   ├── test_connection.py        # Quick connectivity + collection list sanity check
│   └── ingest_traces.py          # Batch ETL: raw trace JSON -> graphs + raw_traces (with retention/TTL + downsampling)
├── User_Design/                  # Appendix B deliverables
│   ├── erd-schema.png            # Entity-Relationship diagram for MongoDB
│   ├── uc1-developer-redaction.png # Figma Journey: Dev configures redaction
│   ├── uc2-admin-alert.png       # Figma Journey: Admin views lateral movement alert
│   ├── uc3-system-enforcement.png # Figma Journey: System auto-enforces Istio policy
│   ├── uc4-auditor-audit.png     # Figma Journey: Auditor reviews privacy score
│   └── user-design.md            # User Design Document narrative
├── analytics/                    # Python analytics, DAG parser, & ST-GNN models
│   ├── parse_traces.py           # Extracts DAGs and time-weighted latency edges (w_ij)
│   ├── privacy_entropy_audit.py  # Calculates Shannon Entropy H(X) & plots chart
│   └── st_gnn_model.py           # PyTorch Geometric ST-GNN architecture
├── collector/                    # OpenTelemetry Collector configuration
│   ├── Dockerfile                # Custom OTel Collector container build
│   └── config.yaml               # OTel pipeline receiver, exporter, and processor config
├── data/                         # Trace datasets
│   └── raw_traces/               # Harvested JSON trace dumps (trace_*.json)
├── docs/                         # Research artifacts & figures
│   └── diagrams/
│       └── privacy_leakage_chart.png # Generated empirical baseline privacy chart
├── k6_test/                      # Traffic generation & attack simulation
│   └── normal_traffic.js         # Synthetic user shopping workload with dynamic metadata
├── scripts/                      # Data collection & automation scripts
│   └── harvest_traces.py         # Automated harvester querying Jaeger REST API
├── docker-compose.yml            # Observability stack (Jaeger + OTel Collector)
├── .gitignore                    # Git exclusion rules (venv, .DS_Store, raw JSONs, .iml)
├── README.md                     # Project documentation & execution guide
└── requirements.txt              # Python dependencies
```

---

## ⚡ Quick Start: Python Environment Setup

```bash
# 1. Create Python virtual environment
python3 -m venv venv

# 2. Activate virtual environment
# On macOS / Linux:
source venv/bin/activate
# On Windows (PowerShell as Admin):
# .\venv\Scripts\Activate.ps1

# 3. Install required Python packages
pip install -r requirements.txt
```

---

## 💻 Machine Setup (macOS & Windows)

### 🍎 macOS Setup

1. **Install Docker Desktop:**
   * Download from [docker.com](https://www.docker.com/products/docker-desktop/) and launch it.
   * In **Settings → Resources**, set **CPUs: 4+** and **Memory: 8 GB+**.
   * Verify in terminal: `docker ps`

2. **Install CLI Tools via Homebrew:**
   ```bash
   brew install kubectl minikube k6
   ```

3. **Start Minikube Cluster:**
   ```bash
   minikube start --driver=docker --cpus=4 --memory=8192
   ```

4. **Verify Cluster Health:**
   ```bash
   minikube status
   kubectl get nodes
   ```

---

### 🪟 Windows Setup (PowerShell as Administrator)

1. **Install Docker Desktop with WSL 2:**
   * If WSL 2 is not installed: `wsl --install` (then restart PC).
   * Install Docker Desktop and enable the WSL 2 backend.
   * In **Settings → Resources**, set **CPUs: 4+** and **Memory: 8 GB+**.
   * Verify: `docker ps`

2. **Install CLI Tools via Chocolatey:**
   ```powershell
   choco install kubernetes-cli minikube k6 -y
   ```
   *(Close and reopen PowerShell after installation).*

3. **Start Minikube Cluster:**
   ```powershell
   minikube start --driver=docker --cpus=4 --memory=8192
   ```

4. **Verify Cluster Health:**
   ```powershell
   minikube status
   kubectl get nodes
   ```

---

## 🚀 Lab Deployment: Google Online Boutique

### 1. Deploy the 11 Microservices
```bash
kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/main/release/kubernetes-manifests.yaml
```

### 2. Wait for Pods to Reach `Running`
```bash
kubectl get pods -w
```
*(Press `Ctrl + C` once all pods show status `Running` and `1/1 READY`).*

---

### 3. Essential Cluster Patches

#### A. Fix `cartservice` Out-Of-Memory Crashes (OOMKilled fix)
Google Online Boutique sets a low 128MB limit on `cartservice`. Increase it to 512MB:
```bash
kubectl set resources deployment cartservice --limits=memory=512Mi --requests=memory=128Mi
```

#### B. Disable Google's Built-in Load Generator
Disable Google's default background bot so **only our controlled `k6` scripts generate telemetry**:
```bash
kubectl scale deployment loadgenerator --replicas=0
```

#### C. Route Tracing to Host Jaeger & Configure Explicit Service Names (Port 4317)
Configure all microservice deployments to send OpenTelemetry traces to your local Jaeger instance and set clean, explicit service names:
```bash
kubectl set env deployment/frontend COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=frontend
kubectl set env deployment/checkoutservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=checkoutservice
kubectl set env deployment/paymentservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=paymentservice
kubectl set env deployment/cartservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=cartservice
kubectl set env deployment/productcatalogservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=productcatalogservice
kubectl set env deployment/currencyservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=currencyservice
kubectl set env deployment/shippingservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=shippingservice
kubectl set env deployment/emailservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=emailservice
kubectl set env deployment/recommendationservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=recommendationservice
kubectl set env deployment/adservice COLLECTOR_SERVICE_ADDR=host.minikube.internal:4317 ENABLE_TRACING=1 OTEL_EXPORTER_OTLP_ENDPOINT=http://host.minikube.internal:4317 OTEL_SERVICE_NAME=adservice
```

---

## 🔄 End-to-End Pipeline Execution (Run the Experiment)

Follow these 5 steps to generate traffic, harvest trace DAGs, and execute the Shannon Entropy Privacy Audit:

### Step 1: Start Observability Stack (Jaeger + OTel Collector)
```bash
docker compose up -d
```
* **Verify:** Open [http://localhost:16686](http://localhost:16686) in your browser to verify the Jaeger UI loads.

---

### Step 2: Port-Forward the Frontend Service
```bash
# Kill any broken background tunnels and start fresh port-forwarding
pkill -f "port-forward"
kubectl port-forward svc/frontend 8080:80 &
```
* **Verify:** Open [http://localhost:8080](http://localhost:8080) to confirm the Online Boutique store renders in your browser.

---

### Step 3: Generate User Traffic (k6)

#### Option A: Running with locally installed k6 (macOS / Windows)
```bash
k6 run -e BASE_URL=http://localhost:8080 k6_test/normal_traffic.js
```

#### Option B: Running k6 via Docker (No installation required)
```bash
docker run --rm -i -e BASE_URL=http://host.docker.internal:8080 grafana/k6 run - < k6_test/normal_traffic.js
```
*(Let k6 run for its 2-minute duration. You will see `homepage → 200`, `product → 200`, `checkout → 200`)*.

---

### Step 4: Harvest Trace DAGs to Disk
```bash
python3 scripts/harvest_traces.py --target 500
```
* **Verify:** Check that 500 trace JSON files were saved in `data/raw_traces/`:
  ```bash
  ls data/raw_traces
  ```

---

### Step 5: Parse Trace DAGs & Run Shannon Entropy Privacy Audit
```bash
# 1. Parse trace DAGs and compute time-weighted latency edges (w_ij)
python3 analytics/parse_traces.py

# 2. Run Shannon Entropy (H) audit and generate leakage chart
python3 analytics/privacy_entropy_audit.py
```

* **Output Artifacts (Reference Baseline Run, N=500 traces):**
  * Terminal prints summary metrics: ~4,056 spans, ~2,940 DAG edges, ~10,157 flagged sensitive attributes.
  * Generates high-resolution chart saved directly to: `docs/diagrams/privacy_leakage_chart.png`.

---

## 🗄️ Shared Team Database (MongoDB)

The team shares one live MongoDB dataset (Atlas free tier) instead of everyone
harvesting and training against separate local copies. Full setup steps,
which collections are in use this phase, and the retention/TTL policy for
raw traces are documented in **[docs/db-schema-notes.md](docs/db-schema-notes.md)**.

Quick version:
```bash
# One-time, after copying .env.example to .env and filling in MONGO_URI (Atlas) or
# MONGO_USERNAME/MONGO_PASSWORD (local docker-compose mongodb service):
python DB/setup_database.py

# Sanity check:
python DB/test_connection.py

# Ingest a directory of harvested trace_*.json files (one attack_type per run):
python DB/ingest_traces.py --input data/raw_traces --attack-type normal --split train
```

Only 4 of the 8 collections in the User Design ERD are used at this stage
(`raw_traces`, `trials`, `graphs`, `model_versions`) — see the notes doc for
why the other 4 are deferred to Semester 2, and for the reasoning behind
retaining `normal` traces for only 7 days (TTL-enforced) while any attack
class is kept indefinitely.

---

## 🧹 Clean Up & Cluster Teardown

```bash
# Clear harvested local JSON traces
rm -rf data/raw_traces/*.json

# Stop observability containers
docker compose down

# Delete Online Boutique application from Minikube
kubectl delete -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/main/release/kubernetes-manifests.yaml

# Stop or completely wipe Minikube cluster
minikube stop
# minikube delete   # (use this only if you want a complete fresh reset)
```

---

## 📑 References & Baselines
1. **Ma, Y. (May 2026)**, *Can Graph-Based Microservice Performance Detection Be Used for Microservice Intrusion Detection?* (arXiv:2605.24283).
2. **Chen, J. et al. (2023)**, *Tracegra: A trace-based anomaly detection for microservice using graph deep learning*, Computer Communications.
3. **Sigelman, B. H. et al. (2010)**, *Dapper, a Large-Scale Distributed Systems Tracing Infrastructure*, Google Technical Report.
4. **NIST SP 800-204 (2019)**, *Security Strategies for Microservices-based Application Systems*, R. Chandramouli.
5. **Regulation (EU) 2016/679 (GDPR)**, *General Data Protection Regulation*, Articles 4(1), 5(1)(c), 25, 32.
