#!/usr/bin/env bash
# Collect one run end-to-end.
#   ./collect_run.sh run_03 --seed 103                  # attack run: all 8 attacks, one burst each
#   ./collect_run.sh run_01 --seed 101 --normal         # pure normal run (control / label 0)
#   ./collect_run.sh run_09 --seed 909 --held-out       # held-out run (unseen load + attack settings)
#   ./collect_run.sh run_04 --seed 104 --bursts 5       # attack run, 5 bursts
#   ./collect_run.sh test_01 --seed 3 --minutes 10 --bursts 3 --attacks "brute_force lateral_movement"
#                                                        # short TEST run (not for the dataset)
#
# Chain: seed -> manifest.json (scenario_sampler: load, journeys AND the
# attack schedule) -> k6 runs the manifest's full duration; the orchestrator replays
# the attack schedule anchored to k6's start -> merge k6's ORIGIN lines into
# origin.jsonl -> harvest k6's whole run (stops if a slice is full / Jaeger cap near)
# -> join check + distinct trace patterns (check_origin_match.py; fails the run
# below 99 %). Everything lands in data/runs/<run_id>/ (manifest.json, origin.jsonl,
# k6_console.log, origin_match.json); the burst log stays data/runs/<run_id>.json.
# Run one at a time (two overload the cluster); do the setup once per session
# first (docker compose up, kubectl apply, both port-forwards).
set -euo pipefail
cd "$(dirname "$0")"

RUN_ID="${1:?usage: collect_run.sh <run_id> --seed N [--normal] [--held-out] [--bursts N] [--attacks "a b"] [--minutes M]}"
shift || true

# Load (VUs, duration, shape) now comes from the manifest (scenario_sampler.py
# training ranges: 25-45 VUs; attack runs 55-65 min, normal runs 35-45 min), not from flags.
# Attack timing/parameters come from the manifest too; --bursts/--attacks only
# shape the plan the sampler draws (default: one burst of each of the 8 attacks).
MODE="attack"; BURSTS=""; ATTACKS=""; SEED=""; HELD_OUT=""; MINUTES=""
while [ $# -gt 0 ]; do
  case "$1" in
    --normal)     MODE="normal" ;;
    --seed)       SEED="$2"; shift ;;
    --held-out)   HELD_OUT="--held-out" ;;
    --minutes)    MINUTES="$2"; shift ;;                # test runs only: shorter k6 run
    --bursts)     BURSTS="$2"; shift ;;
    --attacks)    ATTACKS="$2"; shift ;;              # e.g. "lateral_movement brute_force"
    --gap-range|--durations)
                  echo "[collect] $1 is gone: gaps and burst lengths come from the manifest now"; exit 2 ;;
    *) echo "[collect] unknown arg: $1"; exit 2 ;;
  esac
  shift
done

[ -n "$SEED" ] || { echo "[collect] --seed N is required (same seed = same run)"; exit 2; }

PY=./venv/bin/python
# absolute: k6's open() resolves relative paths from the SCRIPT's folder (k6_test/)
RUN_DIR="$PWD/data/runs/${RUN_ID}"
MANIFEST="${RUN_DIR}/manifest.json"
ORIGIN="${RUN_DIR}/origin.jsonl"
K6_CONSOLE="${RUN_DIR}/k6_console.log"
# must match docker-compose.yml's --memory.max-traces
export JAEGER_MAX_TRACES="${JAEGER_MAX_TRACES:-500000}"
BASE=http://localhost:8080
AUTH=http://localhost:8081
SSRF=http://localhost:8082
[ "$MODE" = "normal" ] && BURSTS=0

# preflight - bail out early with a clear message instead of collecting garbage
command -v k6      >/dev/null || { echo "[collect] k6 not on PATH"; exit 1; }
curl -s -o /dev/null --max-time 5 "$BASE/" \
  || { echo "[collect] frontend :8080 unreachable — is 'kubectl port-forward svc/frontend 8080:80' up?"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST "$AUTH/login" || true)
[ "$code" = "401" ] \
  || { echo "[collect] authservice :8081 not returning 401 (got '$code') — is its port-forward up?"; exit 1; }
if [ "$MODE" = "attack" ]; then
  curl -s -o /dev/null --max-time 5 "$SSRF/healthz" \
    || { echo "[collect] ssrfservice :8082 unreachable — is 'kubectl port-forward svc/ssrfservice 8082:8080' up?"; exit 1; }
  kubectl get pod attacker >/dev/null 2>&1 \
    || { echo "[collect] no 'attacker' pod — kubectl apply the manifests first"; exit 1; }
fi

[ -e "$ORIGIN" ] && { echo "[collect] $ORIGIN already exists - pick a new run id"; exit 1; }
echo "[collect] run=$RUN_ID mode=$MODE seed=$SEED ${HELD_OUT}"

# 1. seed -> manifest (before any traffic)
# shellcheck disable=SC2086  # $ATTACKS is a space-separated list on purpose
$PY scripts/scenario_sampler.py --run-id "$RUN_ID" --seed "$SEED" $HELD_OUT \
    ${MINUTES:+--minutes "$MINUTES"} ${BURSTS:+--bursts "$BURSTS"} ${ATTACKS:+--attacks $ATTACKS}
K6_ARGS=(--log-format raw --console-output "$K6_CONSOLE"
         -e BASE_URL="$BASE" -e AUTH_URL="$AUTH" -e MANIFEST="$MANIFEST")
export SHADOWTRACE_RUN_ID="$RUN_ID" SHADOWTRACE_SEED="$SEED" ORIGIN_LOG="$ORIGIN"

# wipe Jaeger's in-memory store before each run - it's just staging and every
# finished run is on disk. keeps queries fast (piled-up traces choked it once).
# services reconnect their OTLP exporters on their own; the sleep gives them time.
if docker ps --format '{{.Names}}' | grep -q '^shadowtrace-jaeger$'; then
  echo "[collect] clearing Jaeger before run..."
  docker restart shadowtrace-jaeger >/dev/null
  for _ in $(seq 1 20); do
    curl -s -o /dev/null --max-time 3 http://localhost:16686/api/services && break
    sleep 1
  done
  sleep 5  # let Boutique services hook their exporters back up
fi

# k6 runs the manifest's full duration in the background in BOTH modes; the
# harvest bracket is k6's whole run, so no logged request falls outside it.
START=$(date +%s)
k6 run "${K6_ARGS[@]}" k6_test/normal_traffic.js >"${RUN_DIR}/k6_stdout.log" 2>&1 &
K6_PID=$!
trap 'kill $K6_PID 2>/dev/null || true' EXIT
sleep 8
# a k6 that died at start-up (bad manifest path, script error) would go unnoticed
# in the background and attacks would run with no normal traffic: check it.
if ! kill -0 $K6_PID 2>/dev/null || ! grep -q '^ORIGIN ' "$K6_CONSOLE" 2>/dev/null; then
  echo "[collect] k6 is not running or logged no requests after 8 s - aborting. k6 output:"
  tail -20 "${RUN_DIR}/k6_stdout.log"
  exit 1
fi

if [ "$MODE" = "attack" ]; then
  # replays manifest["attacks"]["schedule"]; burst times are offsets from START
  # (k6's start). Writes data/runs/<run_id>.json with planned + actual times.
  $PY scripts/orchestrator.py --run-id "$RUN_ID" --manifest "$MANIFEST" --t0 "$START" \
      --i-have-normal-traffic
fi

echo "[collect] waiting for k6 to finish its manifest duration..."
wait $K6_PID || { echo "[collect] k6 exited non-zero - see ${RUN_DIR}/k6_stdout.log"; exit 1; }
trap - EXIT
END=$(date +%s)
sleep 10  # give spans time to flush to Jaeger

# k6 cannot write files: move its ORIGIN lines into the run's origin.jsonl
$PY scripts/provenance.py merge-k6 "$K6_CONSOLE" "$ORIGIN"

# harvest this exact bracket to disk - this is what we hand off (raw trace JSON +
# origin.jsonl, which labels every trace by its trace ID).
# building the graphs is the analytics side's job. 60s slices with a big cap so
# every burst stays covered even when http_flood dominates (~18k/slice, under 30k).
# A full slice, a failed Jaeger query or a near-full Jaeger cap makes the harvester
# exit non-zero, and set -e stops the run here (status "failed" in .harvest.json).
$PY scripts/harvest_traces.py --run-id "$RUN_ID" --start "$START" --end "$END" \
    --limit 30000 --chunk-seconds 60 --jaeger-cap "$JAEGER_MAX_TRACES"

# join gate (>= 99 % of non-background traces matched) + distinct trace patterns;
# exits non-zero (and stops here) if the gate fails
$PY scripts/check_origin_match.py --run-id "$RUN_ID"

# leakage gate: the planted personal data must reach the traces
# through every expected channel (headers, query, body, enduser.id, ...); a run
# collected with a silently reverted image would otherwise look fine
# (pipefail: the "if" sees the check's exit code through the pipe to tail)
if ! $PY scripts/leakage_check.py --run-id "$RUN_ID" --max-traces 5000 | tail -14; then
  echo "[collect] leakage check FAILED - see ${RUN_DIR}/leakage.json"; exit 1
fi

# find, not ls *.json - a big run has 100k+ files and the glob blows past ARG_MAX
TRACES=$(find "data/raw_traces/${RUN_ID}" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
echo "[collect] DONE $RUN_ID"
echo "  traces : ${TRACES}  -> data/raw_traces/${RUN_ID}/"
echo "  origin : ${ORIGIN}  ($(wc -l <"$ORIGIN" | tr -d ' ') requests, ground truth)"
echo "  bursts : data/runs/${RUN_ID}.json   manifest: ${MANIFEST}"
echo "  check  : ${RUN_DIR}/origin_match.json (join gate + trace patterns)"
# print the next run id, but only if this one ends in a number (run_13 -> run_14)
if [[ "${RUN_ID##*_}" =~ ^[0-9]+$ ]]; then
  echo "[collect] next: ./collect_run.sh ${RUN_ID%_*}_$(printf '%02d' $(( 10#${RUN_ID##*_} + 1 )))  (sequentially)"
fi
