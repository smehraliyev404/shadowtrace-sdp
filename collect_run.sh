#!/usr/bin/env bash
# Collect one run end-to-end so I don't run the sub-steps by hand.
#   ./collect_run.sh run_03                 # attack run, all 7 attacks
#   ./collect_run.sh run_01 --normal        # pure normal run (control / label 0)
#   ./collect_run.sh run_09 --bursts 5      # attack run, different burst count
#
# Chain: k6 normal traffic -> attacks (orchestrator) -> harvest that bracket.
# Run one at a time (two overload the cluster); do the setup once per session
# first (docker compose up, kubectl apply, both port-forwards).
set -euo pipefail
cd "$(dirname "$0")"

RUN_ID="${1:?usage: collect_run.sh <run_id> [--normal] [--bursts N] [--normal-min M]}"
shift || true

# VUS=35 (rebalanced pass): lighter normal load lifts attack's raw *share* to ~43%
# without a dangerous absolute attack rate -- normal still stays the 57% majority.
MODE="attack"; BURSTS=7; NORMAL_MIN=12; VUS=35; ATTACKS_OVERRIDE=""   # 7 bursts = one of each attack
GAP_RANGE=""; DURATIONS=""   # forwarded to the orchestrator when set
while [ $# -gt 0 ]; do
  case "$1" in
    --normal)     MODE="normal" ;;
    --bursts)     BURSTS="$2"; shift ;;
    --normal-min) NORMAL_MIN="$2"; shift ;;
    --vus)        VUS="$2"; shift ;;
    --attacks)    ATTACKS_OVERRIDE="$2"; shift ;;   # e.g. "lateral_movement" to redo just one attack
    --gap-range)  GAP_RANGE="$2 $3"; shift 2 ;;      # e.g. --gap-range 100 130
    --durations)  DURATIONS="$2"; shift ;;           # e.g. "http_flood=120,slow_brute=260"
    *) echo "[collect] unknown arg: $1"; exit 2 ;;
  esac
  shift
done

PY=./venv/bin/python
BASE=http://localhost:8080
AUTH=http://localhost:8081
# dropped ssrf_probe from the set (Boutique has no real SSRF endpoint, no useful
# edge). lateral_movement stays now that the harvester queries every root service.
ATTACKS="http_flood exfiltration brute_force sqli_probe lateral_movement session_rotation_brute slow_brute"
ATTACKS="${ATTACKS_OVERRIDE:-$ATTACKS}"   # --attacks wins if given

# preflight - bail out early with a clear message instead of collecting garbage
command -v k6      >/dev/null || { echo "[collect] k6 not on PATH"; exit 1; }
curl -s -o /dev/null --max-time 5 "$BASE/" \
  || { echo "[collect] frontend :8080 unreachable — is 'kubectl port-forward svc/frontend 8080:80' up?"; exit 1; }
code=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 -X POST "$AUTH/login" || true)
[ "$code" = "401" ] \
  || { echo "[collect] authservice :8081 not returning 401 (got '$code') — is its port-forward up?"; exit 1; }

echo "[collect] run=$RUN_ID mode=$MODE"

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

if [ "$MODE" = "normal" ]; then
  # pure normal run: just k6, grab the bracket by hand, parse off the harvest manifest
  START=$(date +%s)
  k6 run -e BASE_URL="$BASE" -e AUTH_URL="$AUTH" -e "VUS=${VUS}" -e "DURATION=${NORMAL_MIN}m" k6_test/normal_traffic.js
  END=$(date +%s)
  sleep 10  # give spans time to flush to Jaeger
  RUN_JSON="data/runs/${RUN_ID}.harvest.json"
else
  # attack run: normal traffic in the background, orchestrator fires the bursts
  k6 run -e BASE_URL="$BASE" -e AUTH_URL="$AUTH" -e "VUS=${VUS}" -e DURATION=40m k6_test/normal_traffic.js \
      >"/tmp/k6_${RUN_ID}.log" 2>&1 &
  K6_PID=$!
  trap 'kill $K6_PID 2>/dev/null || true' EXIT
  sleep 8  # let normal traffic ramp up before the first burst

  # orchestrator blocks till it's done and writes data/runs/<run_id>.json
  # (started_at / ended_at / attack_bursts is where the labels come from)
  $PY scripts/orchestrator.py --run-id "$RUN_ID" --attacks $ATTACKS \
      --bursts "$BURSTS" --i-have-normal-traffic \
      ${GAP_RANGE:+--gap-range $GAP_RANGE} \
      ${DURATIONS:+--durations "$DURATIONS"}

  kill $K6_PID 2>/dev/null || true; trap - EXIT
  sleep 10  # flush
  RUN_JSON="data/runs/${RUN_ID}.json"
  START=$($PY -c "import json;print(int(json.load(open('$RUN_JSON'))['started_at']))")
  END=$($PY -c "import json;print(int(json.load(open('$RUN_JSON'))['ended_at']))")
fi

# harvest this exact bracket to disk - this is what we hand off (raw trace JSON +
# the burst log $RUN_JSON, which holds the attack timestamps used as labels).
# building the graphs is the analytics side's job. 60s slices with a big cap so
# every burst stays covered even when http_flood dominates (~18k/slice, under 30k).
$PY scripts/harvest_traces.py --run-id "$RUN_ID" --start "$START" --end "$END" \
    --limit 30000 --chunk-seconds 60

# find, not ls *.json - a big run has 100k+ files and the glob blows past ARG_MAX
TRACES=$(find "data/raw_traces/${RUN_ID}" -name '*.json' 2>/dev/null | wc -l | tr -d ' ')
echo "[collect] DONE $RUN_ID"
echo "  traces : ${TRACES}  -> data/raw_traces/${RUN_ID}/   (payload-free: structure + timing only)"
echo "  labels : data/runs/${RUN_ID}.json"
# print the next run id, but only if this one ends in a number (run_13 -> run_14)
if [[ "${RUN_ID##*_}" =~ ^[0-9]+$ ]]; then
  echo "[collect] next: ./collect_run.sh ${RUN_ID%_*}_$(printf '%02d' $(( 10#${RUN_ID##*_} + 1 )))  (sequentially)"
fi
