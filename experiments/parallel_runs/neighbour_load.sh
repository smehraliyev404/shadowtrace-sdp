#!/usr/bin/env bash
# Parallel-runs test: a second cluster "loadgen" that only makes load
# next to our collection cluster "minikube", to measure whether it changes our
# latency (experiments/parallel_runs/compare_latency.py). It is never collected from.
#
#   experiments/parallel_runs/neighbour_load.sh setup          # once: create + build + deploy (~20-30 min)
#   experiments/parallel_runs/neighbour_load.sh load 1200      # heavy load for 1200 s (run in its own tmux window)
#   experiments/parallel_runs/neighbour_load.sh stop           # stop the cluster (keeps its images) - idle B still costs CPU
#   experiments/parallel_runs/neighbour_load.sh start          # start it again (and switch kubectl back to "minikube")
#   experiments/parallel_runs/neighbour_load.sh delete         # remove it completely
#
# Safety, because both clusters run the same services under the same names:
#   * every kubectl call here names --context loadgen explicitly, and setup switches
#     kubectl's default back to "minikube" (minikube start -p switches it away),
#     so collect_run.sh and the port-forwards keep talking to cluster A;
#   * B's services export traces to host.minikube.internal:4399, where nothing
#     listens, so they never reach our Jaeger (:4317). If they did, the join check
#     of the A run would fail on unexplained traces (gate A);
#   * B uses ports 9080/9081 and writes its origin lines to /tmp, never to data/.
#   * same caps as A: $CPUS (default 12) CPUs, 32 GiB. The host limits all Docker
#     workloads together to 28 threads / 100 GB, so two clusters
#     x 12 + Jaeger fit; 2 x 16 would not.
set -euo pipefail
cd "$(dirname "$0")/../.."      # repository root

P=loadgen
CPUS="${CPUS:-12}"
MANIFESTS=../shadowtrace-testbed/release/kubernetes-manifests.yaml
KB=(kubectl --context "$P")
PY=./venv/bin/python

case "${1:-}" in
  setup)
    minikube start -p "$P" --cpus "$CPUS" --memory 32g
    kubectl config use-context minikube >/dev/null
    echo "[neighbour] kubectl default context is back on: $(kubectl config current-context)"
    MINIKUBE_PROFILE="$P" ./build_images.sh
    # tracing to a dead port: B must never write into our Jaeger
    sed 's#host.minikube.internal:4317#host.minikube.internal:4399#g' "$MANIFESTS" | "${KB[@]}" apply -f -
    "${KB[@]}" wait --for=condition=Ready pod --all --timeout=600s
    echo "[neighbour] cluster '$P' ready; tracing endpoints:"
    "${KB[@]}" get deploy -o yaml | grep -o "host.minikube.internal:[0-9]*" | sort | uniq -c
    ;;

  load)
    SECS="${2:?usage: neighbour_load.sh load <seconds>}"
    [ "$(kubectl config current-context)" = "minikube" ] \
      || { echo "[neighbour] kubectl default context is not 'minikube' - fix with: kubectl config use-context minikube"; exit 1; }
    "${KB[@]}" port-forward svc/frontend 9080:80 >/tmp/pf_loadgen_frontend.log 2>&1 &
    PF1=$!
    "${KB[@]}" port-forward svc/authservice 9081:8080 >/tmp/pf_loadgen_auth.log 2>&1 &
    PF2=$!
    PIDS=("$PF1" "$PF2")
    trap 'kill "${PIDS[@]}" 2>/dev/null || true' EXIT
    sleep 3
    MIN=$(( (SECS + 59) / 60 ))
    $PY scripts/scenario_sampler.py --run-id loadgen --seed 99 --minutes "$MIN" --bursts 0 \
        --out /tmp/loadgen_manifest.json --force >/dev/null
    export ORIGIN_LOG=/tmp/loadgen_origin.jsonl SHADOWTRACE_RUN_ID=loadgen
    echo "[neighbour] heavy load on '$P' for ${SECS}s: shoppers + continuous http_flood + brute_force"
    k6 run -q --log-format raw --console-output /dev/null -e MANIFEST=/tmp/loadgen_manifest.json \
        -e BASE_URL=http://localhost:9080 -e AUTH_URL=http://localhost:9081 \
        k6_test/normal_traffic.js >/tmp/loadgen_k6.log 2>&1 &
    PIDS+=($!)
    # the heaviest training settings, all the time (worst-case neighbour)
    $PY scripts/attacks/http_flood.py --duration "$SECS" --url http://localhost:9080 \
        --concurrency 4 --pause 0.16 --jitter 0.4 >/tmp/loadgen_flood.log 2>&1 &
    PIDS+=($!)
    $PY scripts/attacks/brute_force.py --duration "$SECS" --url http://localhost:9081/login \
        --concurrency 6 --pause 0.18 --jitter 0.4 >/tmp/loadgen_brute.log 2>&1 &
    PIDS+=($!)
    sleep "$SECS"
    echo "[neighbour] done"; tail -n1 /tmp/loadgen_flood.log /tmp/loadgen_brute.log
    ;;

  stop)   minikube stop -p "$P" ;;
  start)
    minikube start -p "$P" --cpus "$CPUS" --memory 32g
    kubectl config use-context minikube >/dev/null
    echo "[neighbour] kubectl default context is back on: $(kubectl config current-context)"
    "${KB[@]}" wait --for=condition=Ready pod --all --timeout=600s ;;
  delete) minikube delete -p "$P" ;;
  *) echo "usage: $0 setup | start | load <seconds> | stop | delete"; exit 2 ;;
esac
