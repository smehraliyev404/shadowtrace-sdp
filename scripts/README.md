# ShadowTrace — Trace Collection Runbook

How to run the full flow and get labelled traces. **Our job is trace collection only** —
graphs and the model are the AI teammate's half. Output per run:
`data/raw_traces/run_XX/` (raw Jaeger traces) + `data/runs/run_XX.json` (burst log = labels).

## 0. One-time setup (per fresh cluster)

```bash
# Docker Desktop must be running first.
minikube start --driver=docker

# Build the 3 custom stub images INTO minikube (no public registry, so this is required).
# NOTE: shell is zsh — always brace the tag: ${s}:latest  (bare $s:latest silently mangles it)
eval $(minikube docker-env)
for s in authservice ssrfservice attacker; do
  ( cd ../microservices-demo-main/src/$s && docker build -t "shadowtrace/${s}:latest" . )
done

# Bring up the whole traced infra from the single manifest (Boutique + our 3 stubs,
# tracing baked in, loadgenerator=0, currency/payment at 512Mi):
kubectl apply -f ../microservices-demo-main/release/kubernetes-manifests.yaml
minikube addons enable metrics-server
kubectl wait --for=condition=Ready pod --all --timeout=420s
```

## 1. Per session

```bash
docker compose up -d                                   # Jaeger (staging)
pkill -f "port-forward"
kubectl port-forward svc/frontend    8080:80   >/tmp/pf1.log 2>&1 &
kubectl port-forward svc/authservice 8081:8080 >/tmp/pf2.log 2>&1 &
kubectl port-forward svc/ssrfservice 8082:8080 >/tmp/pf3.log 2>&1 &
```

## 2. Collect — one command per run

`collect_run.sh` does the whole chain: normal traffic (k6) + attacks (orchestrator)
→ harvest every root service to disk. Run them **one at a time** (never concurrent).

```bash
# Normal-only runs (label-0 baseline) at different loads:
./collect_run.sh run_01 --normal --vus 10
./collect_run.sh run_02 --normal --vus 25
./collect_run.sh run_03 --normal --vus 50

# Attack runs — all attacks, balanced (one of each per run), normal traffic underneath:
./collect_run.sh run_04
./collect_run.sh run_05

# Single-attack run (e.g. just SSRF):
./collect_run.sh run_07 --attacks "ssrf_probe" --bursts 4
```

Attacks: `http_flood exfiltration brute_force sqli_probe ssrf_probe lateral_movement
session_rotation_brute slow_brute`.

## 3. Running tips (learned the hard way)

- **Health-gate before every run.** If any pod is crash-looping or restarts are climbing,
  STOP and let it settle — never collect on a sick cluster:
  `kubectl get pods` · `kubectl top pods`.
- **Sequential only.** Two runs at once overload the 4-CPU cluster and share traffic (leak).
- **Kills happen.** A background run sometimes gets killed under heavy load — just clean the
  partial and re-run: `rm -rf data/raw_traces/run_XX data/runs/run_XX.* && ./collect_run.sh run_XX`.
- **zsh tag gotcha.** Build images with `${s}:latest` (braces), or the `:l` modifier corrupts the tag.
- **Traces live on disk**, not in Docker — killing Jaeger/minikube never loses collected runs.
- **Custom images vanish on `minikube delete`** — rebuild them (step 0) after any delete.

## 4. Verify a run (the gate)

```bash
# trace count
find data/raw_traces/run_XX -name '*.json' | wc -l
# 5xx rate in the k6 log (want ~0%)
grep -c '→ 5' /tmp/k6_run_XX.log
# restarts flat? (currency/payment must not climb)
kubectl get pods | grep -E 'currency|payment'
```
A run with high 5xx or climbing restarts is **BAD** — discard and re-run.

## What NOT to do here

- Don't build graphs / windows / features — that's the teammate's step (`parse_traces.py` is a stub).
- Don't collect logs or request payloads — payload-free is the privacy premise; traces only.
- Don't commit `data/` — it's gitignored (219k+ trace files / GBs stay off git by design).
