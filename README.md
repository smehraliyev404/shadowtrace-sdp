# ShadowTrace

Attack detection in microservices from privacy-redacted OpenTelemetry traces.

This repository holds the data-collection pipeline: normal traffic, eight attack
types, trace harvesting, per-request ground truth and the checks that gate every
run. The testbed (a modified Google Online Boutique with tracing in every service,
three extra services and realistic leak channels) is a separate repository,
expected next to this one as `../microservices-demo-main/`.

## How a run is labelled

Every client (k6 shoppers and every attack script) picks the W3C trace ID of each
request itself, sends it as `traceparent`, and writes one line per request to
`data/runs/<run_id>/origin.jsonl`:

```json
{"ts": 1794659436.12, "trace_id": "f217...", "span_id": "9df3...", "origin": "brute_force",
 "client": "brute_force", "run_id": "run_01", "seed": 42, "method": "POST", "path": "/login",
 "pii": {"username": "...", "password": "..."}}
```

The entry services continue that trace, so every harvested trace is joined to its
label by trace ID. No time windows or burst logs are needed to label a request.
`pii` (on requests that carry personal data) records the values the request
really sent; the leakage measurement uses it as ground truth.

## Testbed

| Service | Role |
| --- | --- |
| Online Boutique (11 services) | Tracing fixed or added in every service. Records request headers, query strings, form bodies, user IDs (also via baggage), Redis commands and errors in spans, as production instrumentation often does. |
| `authservice` | `POST /login` for 500 synthetic accounts; 200 on the right password, 401 otherwise. |
| `ssrfservice` | `GET /fetch?url=` fetches a URL server-side (SSRF target). |
| `attacker` | Pod for in-cluster lateral movement. |

All personal data is synthetic (`k6_test/people.json`, `scripts/synthetic_people.py`).

## Attacks

| Script (`scripts/attacks/`) | Target | What it does |
| --- | --- | --- |
| `http_flood.py` | frontend | several workers cycle the home, cart and all product pages |
| `exfiltration.py` | frontend | walks every product page and every currency |
| `sqli_probe.py` | frontend `/product/<id>` | injection strings as the product ID |
| `brute_force.py` | authservice `/login` | credential stuffing with realistic usernames |
| `session_rotation_brute.py` | authservice `/login` | same, with a fresh session per attempt |
| `slow_brute.py` | authservice `/login` | low-rate credential stuffing |
| `ssrf_probe.py` | ssrfservice `/fetch` | asks for internal and cloud-metadata URLs |
| `lateral_movement.py` | internal gRPC services | direct calls from the attacker pod or from inside `recommendationservice` |

Attacks run as bursts over live normal traffic, with seeded jitter and the same
User-Agent as k6.

## Layout

```
collect_run.sh             one run end to end
build_images.sh            build all testbed images into minikube
docker-compose.yml         Jaeger (in-memory, capped at 500,000 traces)
k6_test/normal_traffic.js  seeded shopper state machine (k6)
queues/                    run lists for scripts/run_queue.py
scripts/
  scenario_sampler.py      seed -> manifest.json (load shape, journeys, attack schedule)
  orchestrator.py          replays the manifest's attack schedule
  provenance.py            trace IDs, origin log, request helper, jitter
  harvest_traces.py        Jaeger -> data/raw_traces/<run_id>/
  check_origin_match.py    join traces to the origin log (gates A, B, C)
  leakage_check.py         which personal data reaches which span attribute
  run_queue.py             unattended series of runs with preflight and gates
  phase0_check.py          testbed ground-truth checks before collecting
  synthetic_people.py      usernames and password guesses for the attacks
  attacks/                 the eight attack scripts
  build_features.py        raw traces -> labelled Parquet per level (L0/L1/L2) in data/features/
  redact.py                L1 redaction (allow-list, detectors, HMAC tokens)
  edge_norm.py             edge features, normalised on normal training windows
  pii_audit.py             L1 recall and precision against the origin pii ground truth
  make_split.py            fixed run-level split (5 assignments) -> splits/
ml/
  data.py                  windows.parquet -> graph sequences and flat vectors
  models.py                ST-GNN (GATv2 / GCN / SAGE) and flat baselines
  train.py                 train one model on one assignment and seed -> results/
  gbm_fit.py               LightGBM in a child process (cannot share one with torch)
  jacob.py                 Jacob et al. 2022 baseline: DCRNN forecaster, normal windows only
  ma.py                    Ma 2026 baseline: one GCN graph per request, scored per window too
  metrics.py               metrics, block-bootstrap CIs, Wilcoxon + Holm
  sanity.py                checks to pass before trusting results
  run_grid.py              runs the whole experiment grid in priority order, resumable
splits/batch3.json         the fixed split of batch 3
experiments/parallel_runs/ test of whether a second cluster changes latency
DB/, collector/             planned MongoDB store and in-Collector redaction (later work; docs/mongodb.md)
docs/                      user design, MongoDB setup
docs/results/              final results of batch 3 (snapshot, 23 Nov 2026), see "Results"
```

## Setup

Requirements: Docker, minikube, kubectl, k6, Python 3.12+ (the pinned packages need it).

```bash
python3 -m venv venv
./venv/bin/python -m pip install -r requirements.txt
```

Cluster (once; images use `imagePullPolicy: Never`, so they are built into minikube):

```bash
minikube start --driver=docker
./build_images.sh
kubectl apply -f ../microservices-demo-main/release/kubernetes-manifests.yaml
kubectl wait --for=condition=Ready pod --all --timeout=600s
```

Per session:

```bash
docker compose up -d
kubectl port-forward svc/frontend    8080:80   &
kubectl port-forward svc/authservice 8081:8080 &
kubectl port-forward svc/ssrfservice 8082:8080 &
```

Jaeger UI: http://localhost:16686. After recreating Jaeger, wait a few minutes (or
restart the deployments) before collecting: services reconnect with back-off.

## Collecting

One run:

```bash
./collect_run.sh run_01 --seed 101              # attack run, one burst of each attack
./collect_run.sh run_02 --seed 102 --normal     # normal traffic only
./collect_run.sh run_03 --seed 903 --held-out   # held-out load and attack settings
./collect_run.sh test_01 --seed 1 --minutes 10 --bursts 2 --attacks "brute_force ssrf_probe"
```

The same seed gives the same run plan. Steps: sampler writes `manifest.json`; k6
runs for the manifest's duration while the orchestrator replays the attack
schedule; k6's origin lines are merged into `origin.jsonl`; traces are harvested;
the join and leakage checks run. Output goes to `data/runs/<run_id>/` and
`data/raw_traces/<run_id>/`.

A series of runs:

```bash
./venv/bin/python scripts/run_queue.py queues/batch3.txt --plan   # show the plan
./venv/bin/python scripts/run_queue.py queues/batch3.txt          # run it (e.g. in tmux)
```

The queue checks the cluster before every run, warms it up with uncollected
traffic, empties the cart store, stops on a failed gate and resumes where it
stopped. Reports go to `data/queue_reports/`.

## Features

```bash
./venv/bin/python scripts/build_features.py --run-id a3_01 a3_02     # -> data/features/<run>/{L0,L1,L2}/
./venv/bin/python scripts/pii_audit.py --run-id a3_01                # L1 recall/precision vs ground truth
```

Per run and level: `spans.parquet` (structure, timing, status; L0/L1 also the
attributes, raw or redacted), `traces.parquet` and `windows.parquet` (60 s
windows: edge and node statistics, six node content features that are 0 at
L2, labels for k = 1, 3, 5, 10), plus `build_report.json`. Edge statistics are
raw; `edge_norm.py` normalises them against normal windows of the training
runs only.

## Models

```bash
./venv/bin/python scripts/make_split.py                 # once, before any results (already done: splits/batch3.json)
./venv/bin/python -m ml.sanity --split splits/batch3.json --assignment 0
./venv/bin/python -m ml.train --model stgnn --split splits/batch3.json --assignment 0 --seed 1 --level L2 --k 3
./venv/bin/python -m ml.jacob --split splits/batch3.json --assignment 0 --seed 1 --level L2
./venv/bin/python -m ml.ma --split splits/batch3.json --assignment 0 --seed 1 --level L1
./venv/bin/python -m ml.metrics results/*/predictions.parquet --part test --compare stgnn
./venv/bin/python -m ml.metrics results/*_k3_a*_s*/predictions.parquet --part test --n-boot 0 --out results/metrics_k3_test.json
./venv/bin/python -m ml.summary results/metrics_k3_test.json --ref stgnn   # means ± sd, Wilcoxon + Holm vs stgnn, RQ3 level vs L0
./venv/bin/python -m ml.probes --split splits/batch3.json --assignment 0   # one-feature shortcut probes, L0/L1 content drift
./venv/bin/python -m ml.train --model stgnn --split splits/batch3.json --leave-out ssrf_probe   # leave-one-attack-out
./venv/bin/python -m ml.rules --split splits/batch3.json --assignment 0            # rule detectors (volume, errors, auth failures, new edges, latency, any)
./venv/bin/python -m ml.ci results/*_k3_a*_s*/predictions.parquet --part heldout --jobs 16   # two-level bootstrap 95 % CIs
./venv/bin/python scripts/pii_by_service.py --queue queues/batch3.txt --jobs 16    # RQ1: personal values per service, L0 and L1
```

The whole grid (every model, level, assignment and seed) in priority order, skipping
results that already exist, logs in `results/logs/`:

```bash
./venv/bin/python -m ml.run_grid --stages main --dry-run          # show the plan
./venv/bin/python -m ml.run_grid --stages main --jobs 4           # first table: k = 3, seed 1
./venv/bin/python -m ml.run_grid --stages seeds,ablations,k --jobs 4
```

`--device` (default `auto`: CUDA if available) selects where the ST-GNN, Jacob and
Ma run; the device used is stored in each result's `config.json`. Results from
different devices are not bit-identical, so one study uses one device.

Models: `stgnn` (GATv2, main), `stgnn_gcn`, `stgnn_sage`, and the flat baselines
`rf`, `gbm`, `mlp`, `svm`, each tuned by grid search on the validation runs
(`--no-tune` uses fixed defaults);
ablations `--no-seen` and `--no-content`. Baselines: `ml.jacob` (forecasts
operation-pair call counts, trained on normal windows only, flags a window when
the error leaves mean ± 2σ; scored as a detector) and `ml.ma` (classifies each
request, then turns request predictions into window predictions so all models
are scored on the same windows). Each result goes to `results/<model>[_<non-default settings>]_<level>_k<k>_a<assignment>_s<seed>/`;
an existing result is never replaced without `--overwrite`, and `ml.metrics`
compares models only within one level and k. Every regular run is the test run in
exactly one of the five assignments; held-out runs are only ever tested on.
Normalisation and vocabularies are fitted on the training runs of each
assignment.

## Results

`docs/results/` holds the final outputs of batch 3 (78 runs, 23 Nov 2026), so the
numbers can be read without re-running anything:

- `summary_all.json` / `summary_all.log`: written by `ml.summary` over every
  training (main grid with 5 assignments x 5 seeds, k = 1, 3, 5, 10, ablations,
  leave-one-attack-out, rule detectors): means, per-attack detection, Wilcoxon +
  Holm tests with per-assignment consistency, and the L1/L2 vs L0 comparisons
- `ci_k3_test.json`, `ci_k3_heldout.json`: 95 % intervals from `ml.ci`
- `pii_by_service_batch3.json`: personal values per service and field at L0 and
  L1, from `scripts/pii_by_service.py`

The per-window predictions behind them (about 12 GB, `results/` on the lab
machine) are not in the repository.

## Gates

A run fails, and the queue stops, if any of these fails:

| Check | Condition |
| --- | --- |
| Harvest | no Jaeger query slice full, no query error, trace count well below the Jaeger cap |
| A: harvested -> origin | >= 99 % of harvested traces (health checks and exporter self-traces excluded) are in the origin log |
| B: origin -> harvested | >= 99 % of logged requests are in Jaeger, overall and per label |
| C: partial traces | < 2 % of traces have more than one root span |
| Leakage | every expected leak channel shows its personal data |
| Pods | no pod restarted or was replaced during the run |

## References

1. Ma, Y. (2026). *Can Graph-Based Microservice Performance Detection Be Used for Microservice Intrusion Detection?* arXiv:2605.24283.
2. Chen, J. et al. (2023). *TraceGra: A trace-based anomaly detection for microservice using graph deep learning.* Computer Communications.
3. Sigelman, B. H. et al. (2010). *Dapper, a Large-Scale Distributed Systems Tracing Infrastructure.* Google Technical Report.
4. Chandramouli, R. (2019). *Security Strategies for Microservices-based Application Systems.* NIST SP 800-204.
5. Regulation (EU) 2016/679 (GDPR), Articles 4(1), 5(1)(c), 25, 32.

## License

The testbed is derived from Google's Online Boutique (Apache License 2.0).
