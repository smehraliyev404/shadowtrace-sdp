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
experiments/parallel_runs/ test of whether a second cluster changes latency
analytics/, DB/, collector/  earlier work (see docs/mongodb.md)
docs/                      user design, MongoDB setup
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
