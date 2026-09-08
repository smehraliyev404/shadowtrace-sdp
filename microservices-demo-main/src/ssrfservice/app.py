"""ShadowTrace stub ssrfservice — a deliberately SSRF-vulnerable endpoint.

Boutique has no endpoint that fetches a user-supplied URL, so a real SSRF probe
had nothing to trigger and produced no distinctive edge. This stub fills that
gap the same way authservice filled the missing-login gap: GET /fetch?url=<url>
makes the SERVER fetch whatever URL the caller supplies — the essence of SSRF.

Because the outbound `requests.get` is auto-instrumented, the fetch propagates
trace context and appears as a NEW edge  ssrfservice -> <target>  in the trace.
A normal shopper never causes ssrfservice to call anything, so that edge has no
precedent — exactly the "new outbound edge to an unseen destination" signal the
ssrf_probe attack is meant to create (causal_history fires on it).

Traced like every other service; tracing is applied by the opentelemetry-instrument
wrapper in the container CMD.
"""

import os

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/fetch")
def fetch():
    # The vulnerable behaviour: fetch an attacker-controlled URL server-side.
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "url required"}), 400
    try:
        r = requests.get(url, timeout=4)          # instrumented -> forms the SSRF edge
        return jsonify({"fetched": url, "status": r.status_code}), 200
    except requests.RequestException as e:
        return jsonify({"fetched": url, "error": str(e)[:80]}), 502


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
