"""ShadowTrace stub authservice.

Boutique has no login endpoint, so brute-force / credential-stuffing attacks
have nothing to target. This is the smallest thing that fills the gap: a traced
HTTP service whose POST /login always fails with 401 and, on each attempt, makes
one downstream call to the frontend -- which creates the auth -> frontend EDGE
the research framework (§5.1) names as the brute-force signature.

Without that downstream hop a login is a single root span with no edge, invisible
to the per-edge feature extractor. The `requests` call is auto-instrumented, so
context propagates and the frontend span becomes a child in the same trace.

Spans export to the same host Jaeger as every Boutique service; tracing is applied
by the `opentelemetry-instrument` wrapper in the container CMD.
"""

import os

import requests
from flask import Flask, request, jsonify

app = Flask(__name__)
FRONTEND_URL = os.getenv("FRONTEND_URL", "http://frontend:80/")


@app.route("/healthz")
def healthz():
    return "ok", 200


@app.route("/login", methods=["POST"])
def login():
    username = request.form.get("username", "")
    try:
        requests.get(FRONTEND_URL, timeout=5)   # forms the auth -> frontend edge
    except requests.RequestException:
        pass
    return jsonify({"error": "invalid credentials", "user": username}), 401


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=int(os.getenv("PORT", "8080")))
