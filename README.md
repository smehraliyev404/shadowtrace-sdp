# 🛡️ ShadowTrace: Privacy-Preserving Security Anomaly Detection
### *Resolving the Privacy-Security Paradox in Microservice Telemetry via Metadata-Blind ST-GNNs*

ShadowTrace is an observability-driven security research framework designed to detect application-layer cyberattacks—specifically **lateral movement**—in cloud-native microservice architectures.

Standard observability pipelines (OpenTelemetry) create a **Privacy-Security Paradox**: auto-instrumentation exposes sensitive metadata (internal pod IPs, RPC schemas, tokens) in plain text, creating GDPR/CCPA compliance risks and an internal reconnaissance attack surface. ShadowTrace decouples threat detection from data exposure using **Spatio-Temporal Graph Neural Networks (ST-GNNs)**, achieving high threat detection fidelity on **100% redacted, metadata-blind telemetry streams**.

### The Lab in One Paragraph

The experimental lab is **Google's Online Boutique** (11 gRPC microservices) running on minikube, extended into an instrumented attack range. That extension lives in a **companion repository, `microservices-demo-main/`** (cloned next to this one), which ships a modified `release/kubernetes-manifests.yaml` that (a) bakes OpenTelemetry tracing into every Boutique service, and (b) adds three small **stub services** that give real attacks something to hit:

| Stub service | Purpose | Attack it enables |
| --- | --- | --- |
| `authservice` | Traced `POST /login` that always returns 401 and calls the frontend on each attempt (forms the `auth → frontend` edge). | brute-force, session-rotation, slow brute |
| `ssrfservice` | Deliberately SSRF-vulnerable `GET /fetch?url=` that fetches an attacker-supplied URL server-side. | SSRF probe |
| `attacker` | An **instrumented** in-cluster gRPC client that calls internal services directly, bypassing the frontend. | lateral movement (the headline threat) |

Attacks are fired as short **bursts over live normal traffic**; each burst's start/end is logged as the ground-truth label. Because every service (stubs included) is traced, each attack surfaces as **real edges in the trace graph** — some with historical precedent, some without — which is exactly the signal the ST-GNN and privacy audit consume.

---

## ✅ Prerequisites

| Tool | Why | Install |
| --- | --- | --- |
| **Docker Desktop** | Runs minikube + the Jaeger/OTel containers | [docker.com](https://www.docker.com/products/docker-desktop/) |
| **minikube** | Local Kubernetes cluster for the lab | `brew install minikube` |
| **kubectl** | Talks to the cluster | `brew install kubectl` |
| **k6** | Generates normal user traffic | `brew install k6` |
| **Python 3.11+** | Attack scripts, harvester, analytics | system / pyenv |
| **`microservices-demo-main/`** | The instrumented Boutique + stub sources | cloned **next to** this repo |

## 🗺️ Contents

1. [Python Environment Setup](#-quick-start-python-environment-setup)
2. [Machine Setup (macOS & Windows)](#-machine-setup-macos--windows)
3. [Lab Deployment](#-lab-deployment-instrumented-online-boutique--attack-stubs) — one-time per cluster
4. [Observability & Session Setup](#-observability--session-setup-per-session) — per session
5. [Attack Suite](#-attack-suite) — the 8 attacks
6. [Running the Experiment](#-running-the-experiment) — automated vs manual
7. [Analytics & Privacy Audit](#-analytics-parse-dags--run-the-shannon-entropy-privacy-audit)
8. [Clean Up & Teardown](#-clean-up--cluster-teardown)

> **Platform note:** the commands below are written for **macOS/Linux (zsh/bash)**. On Windows use
> the PowerShell equivalents — swap `./venv/bin/python` for `.\venv\Scripts\python.exe`, drop the
> trailing `&` (run each port-forward in its own terminal), and replace `pkill -f "port-forward"`
> by closing those terminals.

---

## 📂 Repository Structure

```text
shadowtrace-sdp/                   # THIS repo — observability, attacks, analytics
├── DB/                            # Database design & MongoDB collection schemas
│   ├── Schemas/                   # Collection JSON schemas (alerts, privacy_audits, etc.)
│   ├── indexes.js                 # Reference: full-system indexes (all 8 collections, eventual)
│   ├── mongo_client.py            # Shared connection helper (Atlas MONGO_URI or local docker-compose)
│   ├── setup_database.py          # Creates validators/indexes for the 4 collections used this phase
│   ├── test_connection.py         # Quick connectivity + collection list sanity check
│   └── ingest_traces.py           # Batch ETL: raw trace JSON -> graphs + raw_traces (with retention/TTL + downsampling)
├── User_Design/                   # Appendix B deliverables
│   ├── erd-schema.png             # Entity-Relationship diagram for MongoDB
│   ├── uc1-developer-redaction.png # Figma Journey: Dev configures redaction
│   ├── uc2-admin-alert.png        # Figma Journey: Admin views lateral movement alert
│   ├── uc3-system-enforcement.png # Figma Journey: System auto-enforces Istio policy
│   ├── uc4-auditor-audit.png      # Figma Journey: Auditor reviews privacy score
│   └── user-design.md             # User Design Document narrative
├── analytics/                     # Python analytics, DAG parser, & ST-GNN models
│   ├── parse_traces.py            # Extracts DAGs and time-weighted latency edges (w_ij)
│   ├── privacy_entropy_audit.py   # Calculates Shannon Entropy H(X) & plots chart
│   └── st_gnn_model.py            # PyTorch Geometric ST-GNN architecture
├── collector/                     # OpenTelemetry Collector configuration
│   ├── Dockerfile                 # Custom OTel Collector container build
│   └── config.yaml                # OTel pipeline receiver, exporter, and processor config
├── data/                          # Trace datasets (gitignored — GBs of JSON)
│   ├── raw_traces/                # Harvested JSON trace dumps, per run: run_XX/
│   └── runs/                      # Per-run burst logs (run_XX.json) = attack labels
├── docs/                          # Research artifacts & figures
│   └── diagrams/
│       └── privacy_leakage_chart.png # Generated empirical baseline privacy chart
├── k6_test/                       # Traffic generation
│   └── normal_traffic.js          # Synthetic user shopping workload with dynamic metadata
├── scripts/                       # Data collection & automation
│   ├── orchestrator.py            # Fires attacks in random bursts, writes the label log
│   ├── harvest_traces.py          # Queries the Jaeger REST API, dumps traces to disk
│   ├── README.md                  # Condensed collection runbook (integrated below)
│   └── attacks/                   # The 8 attack scripts (see "Attack Suite")
├── collect_run.sh                 # One-command run: normal traffic → attacks → harvest
├── docker-compose.yml             # Observability stack (Jaeger + OTel Collector)
├── requirements.txt               # Python dependencies
├── .gitignore                     # Git exclusion rules (venv, .DS_Store, raw JSONs, .iml)
└── README.md                      # This file — project documentation & execution guide

../microservices-demo-main/        # COMPANION repo — the instrumented Online Boutique
├── release/kubernetes-manifests.yaml  # Boutique + 3 stubs, tracing baked in, loadgen=0
└── src/{attacker,authservice,ssrfservice}/  # Dockerfiles + source for the 3 custom images
```

> **Note:** `microservices-demo-main/` is a separate checkout

and in order to start it create all pods and test out attack scripts against that strcuture you should to this link here the corresponding file has the same zip name

https://adauniversity-my.sharepoint.com/my?id=%2Fpersonal%2Fjakbarov15227%5Fada%5Fedu%5Faz%2FDocuments%2FTraces&viewid=f46b0982%2D5654%2D4dfa%2D9fca%2D1799eca04e3e

microservices-demo-main.zap

just download it , read all instructions listed below 
and make sure to follow them carefully 


> repo (side-by-side under the same parent folder). Adjust the paths in the deployment commands
> below if you keep it elsewhere.

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

> **Heads up — `requirements.txt` is the full stack.** It pins the heavy **analytics** dependencies
> (`torch`, `torch-geometric`, `matplotlib`, `scikit-learn`, `jupyter`) alongside the light ones.
> If you only need to **deploy the lab, generate traffic, and collect traces**, the sole Python
> dependency is `requests` (plus `k6` on your PATH) — you can skip the full install and only run it
> when you reach the [Analytics](#-analytics-parse-dags--run-the-shannon-entropy-privacy-audit) stage.

---

## 💻 Machine Setup (macOS & Windows)

> **Memory matters.** minikube runs as a container *inside* Docker Desktop, and Jaeger + the
> OTel Collector run in that **same** Docker daemon. So minikube's `--memory` must be **strictly
> less** than Docker Desktop's total allocation, with headroom left over for Jaeger. On a 16 GB
> host, give Docker Desktop **10–12 GB** and minikube **6 GB**. (`minikube --memory=8192` will
> fail if Docker Desktop itself is only allocated ~8 GB.)

### 🍎 macOS Setup

1. **Install Docker Desktop:**
   * Download from [docker.com](https://www.docker.com/products/docker-desktop/) and launch it.
   * In **Settings → Resources**, set **CPUs: 4+** and **Memory: 10–12 GB**.
   * Verify in terminal: `docker ps`

2. **Install CLI Tools via Homebrew:**
   ```bash
   brew install kubectl minikube k6
   ```

3. **Start Minikube Cluster:**
   ```bash
   minikube start --driver=docker --cpus=4 --memory=6144
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
   * In **Settings → Resources**, set **CPUs: 4+** and **Memory: 10–12 GB**.
   * Verify: `docker ps`

2. **Install CLI Tools via Chocolatey:**
   ```powershell
   choco install kubernetes-cli minikube k6 -y
   ```
   *(Close and reopen PowerShell after installation).*

3. **Start Minikube Cluster:**
   ```powershell
   minikube start --driver=docker --cpus=4 --memory=6144
   ```

4. **Verify Cluster Health:**
   ```powershell
   minikube status
   kubectl get nodes
   ```

---

## 🚀 Lab Deployment: Instrumented Online Boutique + Attack Stubs

This is a **one-time setup per fresh cluster**. It builds the 3 custom stub images into minikube,
then deploys the whole traced stack (Boutique + stubs) from the **companion repo's local
manifest** — *not* the upstream Google manifest, which has no tracing and no attack targets.

### 1. Build the 3 Custom Stub Images *into* minikube

The stubs are referenced with `imagePullPolicy: Never`, so they must exist in minikube's own
Docker daemon (there is no public registry for them). Point your shell at minikube's Docker and
build:

```bash
# Docker Desktop and minikube must already be running.
eval $(minikube docker-env)

# NOTE: the shell is zsh — always brace the tag: ${s}:latest
# (a bare $s:latest silently mangles the tag via the :l modifier)
for s in authservice ssrfservice attacker; do
  ( cd ../microservices-demo-main/src/$s && docker build -t "shadowtrace/${s}:latest" . )
done

# Confirm all three are present in minikube:
docker images | grep shadowtrace
```

### 2. Deploy the Full Traced Stack (Boutique + Stubs)

```bash
kubectl apply -f ../microservices-demo-main/release/kubernetes-manifests.yaml
```

This single manifest already bakes in everything the old manual patches used to do:
* **Tracing → host Jaeger** on `host.minikube.internal:4317`, with explicit `OTEL_SERVICE_NAME`s.
* **`loadgenerator` scaled to `0`** — so only your controlled `k6` scripts generate telemetry.
* **`cartservice` / `currencyservice` at 512Mi** — the OOMKilled fix is pre-applied.

### 3. Wait for Pods to Become Ready

```bash
kubectl wait --for=condition=Ready pod --all --timeout=420s
minikube addons enable metrics-server        # enables `kubectl top pods` for health-gating
kubectl get pods                              # expect 14/14 Running, 1/1 READY, 0 restarts
```

*(First run pulls 11 public images + builds 3 stub images; on a slow link the builds are the
long pole. Images are cached afterwards, so restarts are fast. Custom images **vanish on
`minikube delete`** — rebuild them via step 1 after any delete.)*

> **Deploying the plain upstream manifest instead?** If you ever run the vanilla Google Boutique
> (`kubectl apply -f https://raw.githubusercontent.com/GoogleCloudPlatform/microservices-demo/main/release/kubernetes-manifests.yaml`),
> it has none of the above baked in and no attack stubs. The legacy manual patches for that case
> are preserved in **[Appendix A](#-appendix-a-manual-patches-upstream-manifest-only)**.

---

## 🔭 Observability & Session Setup (per session)

Start the staging Jaeger and open the port-forwards the traffic + attack scripts talk to. Do this
once per working session.

```bash
# 1. Observability stack (Jaeger UI/API on :16686, OTLP on :4317/:4318)
docker compose up -d
#    Verify: open http://localhost:16686 and confirm the Jaeger UI loads.

# 2. Port-forward the three externally-driven endpoints
pkill -f "port-forward"
kubectl port-forward svc/frontend    8080:80   >/tmp/pf1.log 2>&1 &   # store + k6 + http/exfil/sqli
kubectl port-forward svc/authservice 8081:8080 >/tmp/pf2.log 2>&1 &   # brute-force family
kubectl port-forward svc/ssrfservice 8082:8080 >/tmp/pf3.log 2>&1 &   # SSRF probe
```

* **Verify frontend:** open [http://localhost:8080](http://localhost:8080) — the Online Boutique store should render.
* **Verify authservice:** `curl -s -o /dev/null -w '%{http_code}\n' -X POST http://localhost:8081/login` → `401`.

---

## 🎯 Attack Suite

ShadowTrace ships **8 attack scripts** in `scripts/attacks/`. Each is driven over live normal
traffic and is written so its telemetry forms a specific, detectable edge/timing signature.

| Attack | Target (port-forward) | Detection signal |
| --- | --- | --- |
| `lateral_movement` | internal gRPC direct — productcatalog/currency/cart *(via the `attacker` pod)* | new `attacker → service` edges with **no precedent** → `causal_history_distance` spikes |
| `http_flood` | frontend `:8080` | `call_repetition` ↑, `temporal_jitter` → 0, `path_entropy` narrows |
| `exfiltration` | frontend `:8080` (full catalog sweep) | breadth ↑ — `causal_history` & `path_entropy` widen |
| `brute_force` | authservice `:8081/login` | `auth → frontend` edge; `call_repetition` ↑, jitter → 0 |
| `session_rotation_brute` | authservice `:8081/login` (fresh session each attempt) | same `auth → frontend` edge regardless of rotated session |
| `slow_brute` | authservice `:8081/login` (sparse, ~0.5/s) | sub-window; the wider accumulation window catches the climb |
| `sqli_probe` | frontend `:8080/product/<payload>` | on `frontend → productcatalog`: repetition ↑, high error rate, low jitter |
| `ssrf_probe` | ssrfservice `:8082/fetch` | new `ssrfservice → target` edge to an unseen destination |

---

## 🔄 Running the Experiment

There are two ways to run: the **automated labeled collection** (`collect_run.sh`, the primary
research path) and a **manual quick pass** (raw k6 + harvest). Both feed the same analytics.

### Option A — Automated Labeled Collection (`collect_run.sh`)

`collect_run.sh` runs the whole chain for one run: **normal traffic (k6) → attack bursts
(orchestrator) → harvest that exact time bracket to disk**. The per-run burst log
(`data/runs/<run_id>.json`) holds the attack start/end timestamps, which are the ground-truth
**labels**. Run them **one at a time** — two concurrent runs overload a 4-CPU cluster and their
traffic leaks between runs.

```bash
# Normal-only baselines (label 0) at different loads:
./collect_run.sh run_01 --normal --vus 10
./collect_run.sh run_02 --normal --vus 25
./collect_run.sh run_03 --normal --vus 50

# Attack runs — balanced (one burst of each attack) over normal traffic underneath:
./collect_run.sh run_04
./collect_run.sh run_05

# Single-attack run (e.g. just SSRF, 4 bursts):
./collect_run.sh run_07 --attacks "ssrf_probe" --bursts 4
```

> The default balanced set fires 7 attacks (`http_flood exfiltration brute_force sqli_probe
> lateral_movement session_rotation_brute slow_brute`); `ssrf_probe` is excluded from the default
> only because it needs the `ssrfservice` port-forward, and is run explicitly with
> `--attacks "ssrf_probe"` as shown. All 8 are available.

**Output per run:** `data/raw_traces/run_XX/` (raw Jaeger traces, structure + timing only —
payload-free by design) and `data/runs/run_XX.json` (the burst log = labels). Before each run,
[health-gate the cluster](#health-gate-every-run-learned-the-hard-way); after it, run the
[verify gate](#verify-a-run-the-gate) and discard anything that fails.

### Option B — Manual Quick Pass (normal traffic + harvest)

Use this for a simple, unlabeled normal-traffic capture without the orchestrator.

```bash
# 1. Generate user traffic (locally installed k6)
k6 run -e BASE_URL=http://localhost:8080 k6_test/normal_traffic.js
#    …or via Docker (no install):
#    docker run --rm -i -e BASE_URL=http://host.docker.internal:8080 grafana/k6 run - < k6_test/normal_traffic.js

# 2. Harvest the traces produced in the last N seconds to disk, under a run id.
#    (harvest_traces.py takes --run-id plus either --last SECONDS or --start/--end;
#    output lands in data/raw_traces/<run-id>/.)
./venv/bin/python scripts/harvest_traces.py --run-id manual_01 --last 300
find data/raw_traces/manual_01 -name '*.json' | wc -l   # verify JSON files were saved
```

> **Want to drive the attacks by hand instead of `collect_run.sh`?** You can — just remember the
> golden rule: **k6 normal traffic goes first and stays running.** Kick off the k6 command above in
> one terminal and leave it going, then in a second terminal fire the attack scripts one at a time
> (e.g. `./venv/bin/python scripts/attacks/brute_force.py --duration 60`, then the next, and so on).
> The whole point of the background k6 is that each attack lands *inside* realistic traffic, so its
> malicious edges are buried in normal shopping activity rather than sitting alone in an empty
> cluster. Run an attack with no k6 underneath and it'll still produce traces — it just won't look
> like the real world, and it won't be a clean labeled dataset. If you want labels, jot down each
> attack's start/end time and harvest that window afterwards. Honestly, though: unless you're
> debugging one specific attack, let `collect_run.sh` do the juggling — it never forgets the timing.

### Health-gate every run (learned the hard way)

* **Never collect on a sick cluster.** Before each run: `kubectl get pods` and `kubectl top pods`.
  If any pod is crash-looping or restart counts are climbing (watch `currencyservice` /
  `paymentservice` especially), **stop and let it settle**.
* **Sequential only** — two runs at once overload the cluster and cross-contaminate traffic.
* **Kills happen** under heavy load. Clean the partial and re-run:
  `rm -rf data/raw_traces/run_XX data/runs/run_XX.* && ./collect_run.sh run_XX`.
* **Traces live on disk**, not in Docker — killing Jaeger or minikube never loses a collected run.
  `collect_run.sh` wipes Jaeger's in-memory staging store before each run to keep queries fast.

### Verify a run (the gate)

```bash
find data/raw_traces/run_XX -name '*.json' | wc -l   # trace count
grep -c '→ 5' /tmp/k6_run_XX.log                     # 5xx rate in the k6 log (want ~0%)
kubectl get pods | grep -E 'currency|payment'        # restarts flat?
```

A run with a high 5xx rate or climbing restarts is **BAD** — discard and re-run.

---

## 📊 Analytics: Parse DAGs & Run the Shannon Entropy Privacy Audit

Collection (above) produces raw traces + labels; the analytics stage turns them into graphs,
features, and the privacy baseline. (Building graphs/windows/features and the ST-GNN itself is the
analytics half of the project — collection deliberately stops at raw traces + labels so the two
halves stay cleanly separable.)

> Requires the full `requirements.txt` install (torch / matplotlib / scikit-learn). Commands use
> `./venv/bin/python`; if your venv is activated, plain `python` works too.

```bash
# 1. Parse trace DAGs and compute time-weighted latency edges (w_ij)
./venv/bin/python analytics/parse_traces.py

# 2. Run Shannon Entropy (H) audit and generate the leakage chart
./venv/bin/python analytics/privacy_entropy_audit.py
```

* **Output Artifacts (illustrative reference run, N≈500 traces):**
  * Terminal prints summary metrics on the order of ~4,000 spans, ~2,900 DAG edges, and ~10,000 flagged sensitive attributes (exact counts vary with the traffic captured).
  * Generates a high-resolution chart saved to: `docs/diagrams/privacy_leakage_chart.png`.

**Payload-free is the privacy premise:** collect traces only — never request payloads or logs.

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
# Clear harvested local JSON traces (safe — every finished run is already on disk under run_XX/)
rm -rf data/raw_traces/*

# Stop observability containers
docker compose down

# Delete the lab from minikube (use the same local manifest you deployed)
kubectl delete -f ../microservices-demo-main/release/kubernetes-manifests.yaml

# Stop or completely wipe the minikube cluster
minikube stop
# minikube delete   # complete fresh reset — NOTE: the 3 custom stub images are lost and
                     # must be rebuilt (Lab Deployment step 1) before the next run.
```

---

## 📎 Appendix A: Manual Patches (upstream manifest only)

These patches are **already baked into** the companion repo's local manifest, so you only need
them if you deploy the **vanilla upstream** Google Boutique. They are preserved here for
completeness.

#### A. Fix `cartservice` Out-Of-Memory Crashes (OOMKilled fix)
```bash
kubectl set resources deployment cartservice --limits=memory=512Mi --requests=memory=128Mi
```

#### B. Disable Google's Built-in Load Generator
```bash
kubectl scale deployment loadgenerator --replicas=0
```

#### C. Route Tracing to Host Jaeger & Set Explicit Service Names (Port 4317)
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

## 📑 References & Baselines
1. **Ma, Y. (May 2026)**, *Can Graph-Based Microservice Performance Detection Be Used for Microservice Intrusion Detection?* (arXiv:2605.24283).
2. **Chen, J. et al. (2023)**, *Tracegra: A trace-based anomaly detection for microservice using graph deep learning*, Computer Communications.
3. **Sigelman, B. H. et al. (2010)**, *Dapper, a Large-Scale Distributed Systems Tracing Infrastructure*, Google Technical Report.
4. **NIST SP 800-204 (2019)**, *Security Strategies for Microservices-based Application Systems*, R. Chandramouli.
5. **Regulation (EU) 2016/679 (GDPR)**, *General Data Protection Regulation*, Articles 4(1), 5(1)(c), 25, 32.
