#!/usr/bin/env bash
# Build every image the manifest expects locally (imagePullPolicy: Never) into
# minikube, so a fresh cluster is one command away:
#   ./build_images.sh && kubectl apply -f ../shadowtrace-testbed/release/kubernetes-manifests.yaml
#   ./build_images.sh emailservice        # rebuild just one after a code change
#
# The 3 stubs are ours. The other 10 are upstream Boutique services with our fixes
# (see the "ShadowTrace:" comments in their source):
#   currencyservice, paymentservice  old OTLP exporter dropped parent span IDs
#   checkoutservice                  context.TODO() lost the trace on Convert calls
#   emailservice, recommendationservice  bound IPv6 only, never listened in our cluster
#   shippingservice (Go)             tracing was a TODO -> otelgrpc server spans
#   adservice (Java)                 tracing was a TODO -> OTel Java agent
#   cartservice (C#)                 no tracing at all -> OTel .NET (gRPC + Redis spans)
#   frontend (Go)                    records headers, query, form body, enduser.id (leak.go)
#   baggage                          frontend puts enduser.id / user.email into baggage; frontend,
#                                    checkout, shipping, productcatalog, currency, payment, email,
#                                    recommendation and cart copy baggage into span attributes
# authservice: login stub, 200 for the 500 synthetic accounts (derived passwords), 401 otherwise.
# attacker: lateral.py runs every call under our own trace ID (origin log).
# Uses `minikube image build`, not `eval $(minikube docker-env)`: the cluster runs
# containerd, where docker-env does not work.
set -euo pipefail
cd "$(dirname "$0")"

SRC=../shadowtrace-testbed/src
# which minikube cluster: default "minikube"; MINIKUBE_PROFILE=loadgen ./build_images.sh
# builds into the second cluster of the parallel-runs test
MK="minikube -p ${MINIKUBE_PROFILE:-minikube}"
IMAGES="authservice ssrfservice attacker frontend productcatalogservice currencyservice paymentservice checkoutservice emailservice recommendationservice shippingservice adservice cartservice"
[ $# -gt 0 ] && IMAGES="$*"

command -v minikube >/dev/null || { echo "[build] minikube not on PATH"; exit 1; }
$MK status >/dev/null 2>&1 || { echo "[build] $MK is not running - '$MK start' first"; exit 1; }

for s in $IMAGES; do
  ctx="$SRC/$s"
  [ "$s" = cartservice ] && ctx="$SRC/cartservice/src"   # its Dockerfile lives in src/
  [ -d "$ctx" ] || { echo "[build] no source folder $ctx"; exit 1; }
  echo "[build] shadowtrace/${s}:latest"
  # minikube image build can exit 0 on a failed build, and checking that
  # ":latest" exists would pass on the OLD image. So build under a one-off tag
  # that only exists if THIS build worked, then point :latest at it.
  # zsh/bash note: keep the braces, a bare $s:latest is mangled by zsh's :l modifier
  tag="build-$(date +%Y%m%d%H%M%S)-$$"
  $MK image build -t "shadowtrace/${s}:${tag}" "$ctx" >"/tmp/build_${s}.log" 2>&1 \
    || { echo "[build] FAILED $s - see /tmp/build_${s}.log"; exit 1; }
  $MK image ls | grep -q "shadowtrace/${s}:${tag}" \
    || { echo "[build] FAILED $s - this build produced no image, see /tmp/build_${s}.log"; exit 1; }
  $MK image tag "shadowtrace/${s}:${tag}" "shadowtrace/${s}:latest" >>"/tmp/build_${s}.log" 2>&1 \
    || { echo "[build] FAILED $s - could not tag it :latest"; exit 1; }
  $MK image rm "shadowtrace/${s}:${tag}" >>"/tmp/build_${s}.log" 2>&1 || true   # keep only :latest
done

echo "[build] done. Images in the cluster:"
$MK image ls | grep shadowtrace/ || true
