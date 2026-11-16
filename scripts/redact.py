"""Span attribute redaction for the three content levels.

    L0  attributes as harvested
    L1  known personal data removed:
          1. allow-list: technical attributes (method, status, route, RPC names,
             sizes, scope, ...) are kept as they are; their values still pass
             through the detectors below as a safety net
          2. structured values (query strings, form bodies, cookies) are split
             into name=value pairs and each pair is redacted on its own
          3. detectors (e-mail, Luhn-valid card, masked card, JWT, session id,
             UUID, payment token, phone, street address, IP, traceparent):
             high-entropy kinds are replaced by a keyed HMAC token H_... (stable, so
             the same session or token stays linkable), low-entropy kinds are
             removed and replaced by their kind, e.g. "[email]"
          4. attributes or parameters whose NAME marks personal data (email,
             user, name, street, zip, phone, card, cvv, token, session, ...)
             lose the whole value: one random-looking identifier is
             HMAC-tokenised, anything else is removed ("[removed]" or the
             detector kind), also when a detector matched only part of it
          5. any other remaining random-looking token is HMAC-tokenised
        HMAC tokens are pseudonyms, not anonymisation: low-entropy values can be
        brute-forced from their HMAC and are therefore removed instead.
    L2  no attributes at all (structure and timing only; see build_features.py)

The HMAC key comes from $SHADOWTRACE_HMAC_KEY, else from a key file created once
(data/features/hmac.key, git-ignored). Only the key's fingerprint is recorded.
"""

import hashlib
import hmac
import os
import re
import secrets
import urllib.parse

from leakage_check import CARD_CANDIDATE, DETECTORS, luhn_ok

# attribute keys kept verbatim (technical, not personal)
ALLOW_KEYS = {
    "span.kind", "otel.scope.name", "otel.scope.version", "otel.status_code", "error",
    "rpc.method", "rpc.service", "rpc.system", "rpc.system.name", "rpc.grpc.status_code",
    "rpc.response.status_code", "rpc.user_agent", "grpc.method", "grpc.status_code",
    "grpc.error_name",
    "http.method", "http.request.method", "http.status_code", "http.response.status_code",
    "http.route", "http.scheme", "http.flavor", "url.scheme", "url.path", "http.target",
    "http.request.body.size", "http.response.body.size", "http.server_name",
    "http.user_agent", "user_agent.original",
    "network.protocol.version", "network.type", "network.peer.port", "net.peer.port",
    "net.host.port", "server.port", "server.address", "http.host", "net.host.name",
    "db.system", "db.redis.database_index", "thread.id", "thread.name", "user.currency",
    "log:event", "log:message.type", "log:message.id",
}
ALLOW_HEADERS = {"accept", "accept-encoding", "accept_encoding", "connection",
                 "content-length", "content-type", "host", "user-agent", "user_agent"}

PII_SEGMENTS = {"email", "mail", "user", "username", "userid", "enduser", "name", "firstname",
                "lastname", "fullname", "address", "addr", "street", "city", "zip", "zipcode",
                "postal", "postcode", "state", "country", "phone", "mobile", "tel", "card", "cvv",
                "cvc", "expiration", "expiry", "password", "passwd", "pwd", "secret", "token",
                "session", "sessionid", "cookie", "authorization", "auth", "ssn", "birth",
                "birthdate", "dob", "account", "login", "credential"}
SEGMENT_SPLIT = re.compile(r"[._\-\s]+")


class _PiiName:
    """Attribute or parameter name that marks personal data: one of its
    segments (split on . _ -) is a personal-data word ("db.statement" is not,
    "shipping.state" and "x-user-email" are)."""
    def search(self, name):
        return any(seg in PII_SEGMENTS for seg in SEGMENT_SPLIT.split(name.lower()))


PII_NAME = _PiiName()

UUID = r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b"
PATTERNS = [   # (kind, regex, high_entropy); earlier entries win on overlap
    ("traceparent", re.compile(r"\b00-[0-9a-f]{32}-[0-9a-f]{16}-[0-9a-f]{2}\b"), True),
    ("jwt", re.compile(r"eyJ[\w-]{5,}\.[\w-]{5,}(?:\.[\w-]+)?"), True),
    ("session", re.compile(UUID + r"|\bsess_[0-9a-z_]{4,}", re.I), True),
    ("token", re.compile(r"\btok_[0-9a-z]{8,}", re.I), True),
    ("email", DETECTORS["email"], False),
    ("card_masked", DETECTORS["card_masked"], False),
    ("phone", DETECTORS["phone"], False),
    ("address", DETECTORS["address"], False),
    ("ip", DETECTORS["ip"], False),
]
LOW_KINDS = {k for k, _, high in PATTERNS if not high} | {"card"}
SCHEME = re.compile(r"^(Bearer|Basic|Token)\s+(.+)$", re.I)
HEX2LETTERS = str.maketrans("0123456789", "ghijklmnop")
FORM = re.compile(r"^[^=&\s]+=[^&]*(?:&[^=&\s]+=[^&]*)*$")
TOKEN_SPLIT = re.compile(r"([\s,;:/()\[\]\"'=&?]+)")


def load_key(path):
    env = os.getenv("SHADOWTRACE_HMAC_KEY")
    if env:
        return env.encode()
    if not os.path.exists(path):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "w") as f:
            f.write(secrets.token_hex(32))
    return open(path).read().strip().encode()


def fingerprint(key):
    return hashlib.sha256(b"fp:" + key).hexdigest()[:12]


def random_looking(s):
    """True for machine-generated identifiers (UUIDs, hex ids, mixed-class tokens),
    False for human-chosen or small-domain values (names, zips, usernames)."""
    s = s.strip()
    if (re.fullmatch(r"[0-9a-f-]{16,}", s, re.I) and sum(c.isdigit() for c in s) >= 4
            and re.search(r"[a-f]", s, re.I)):      # pure digit runs (card numbers) are low-entropy
        return True
    classes = sum(bool(re.search(p, s)) for p in (r"[a-z]", r"[A-Z]", r"[0-9]"))
    return len(s) >= 20 and classes >= 3 and not re.search(r"\s", s)


class Redactor:
    def __init__(self, key):
        self.key = key
        self.stats = {}          # kind -> count of replacements

    def _count(self, kind):
        self.stats[kind] = self.stats.get(kind, 0) + 1

    def token(self, value):
        """H_ + 16 letters: no digits, so tokens never look like card numbers or IPs."""
        return "H_" + hmac.new(self.key, value.encode(), hashlib.sha256).hexdigest()[:16].translate(HEX2LETTERS)

    def _detect(self, text):
        """Replace detector matches in free text. Returns (text, n_replaced)."""
        spans = []                                       # (start, end, kind, high)
        for kind, rx, high in PATTERNS:
            for m in rx.finditer(text):
                if not any(m.start() < e and s < m.end() for s, e, *_ in spans):
                    spans.append((m.start(), m.end(), kind, high))
        for m in CARD_CANDIDATE.finditer(text):
            if luhn_ok(m.group()) and not any(m.start() < e and s < m.end() for s, e, *_ in spans):
                spans.append((m.start(), m.end(), "card", False))
        if not spans:
            return text, 0
        out, pos = [], 0
        for s, e, kind, high in sorted(spans):
            out.append(text[pos:s])
            out.append(self.token(text[s:e]) if high else f"[{kind}]")
            self._count(kind)
            pos = e
        out.append(text[pos:])
        return "".join(out), len(spans)

    def _residual(self, text):
        """HMAC any remaining random-looking token."""
        parts = TOKEN_SPLIT.split(text)
        for i, p in enumerate(parts):
            if i % 2 == 0 and p and not p.startswith(("H_", "[")) and random_looking(p):
                parts[i] = self.token(p)
                self._count("random")
        return "".join(parts)

    def scalar(self, name, value):
        """One value under one attribute or parameter name.

        Under a personal-data name the whole value goes: a value that is one
        high-entropy identifier is tokenised, anything else is removed (a
        detector can miss part of a value, e.g. "name shop@mail.com")."""
        m = SCHEME.match(value)
        if m:                                           # keep "Bearer", redact the credential
            return m.group(1) + " " + self.scalar(name, m.group(2))
        text, n = self._detect(value)
        if not (PII_NAME.search(name) and value.strip()):
            return self._residual(text)
        if (text.startswith("H_") and len(text) == 18) or random_looking(value):
            self._count("named_token")
            return text if text.startswith("H_") and len(text) == 18 else self.token(value)
        kinds = re.findall(r"^\[(\w+)\]$", text)
        self._count("named_removed")
        return f"[{kinds[0]}]" if kinds else "[removed]"

    def _name(self, k):
        """A parameter name: detectors and the random-token rule apply to names too
        (an e-mail or a token can be sent as a name, e.g. "?alice@x.com=1")."""
        text, _ = self._detect(urllib.parse.unquote_plus(k))
        return self._residual(text)

    def _pairs(self, value, sep):
        out = []
        for part in value.split(sep):
            k, eq, v = part.partition("=")
            out.append(self._name(k) + eq + (self.scalar(k, urllib.parse.unquote_plus(v)) if eq else self.scalar("", k)))
        return sep.join(out)

    @staticmethod
    def _is_form(v):
        """name=value[&...] with real parameter names. A single token that only
        contains "=" (base64 padding: "dG9r...MTIz=") is not a form: its "name"
        would be the secret itself."""
        if not FORM.match(v):
            return False
        names = [part.partition("=")[0] for part in v.split("&")]
        return not any(random_looking(n) or len(n) > 64 for n in names)

    def value(self, key, value):
        v = "" if value is None else str(value)
        if not v:
            return v
        header = key.startswith("http.request.header.") and key.rsplit(".", 1)[-1]
        if key in ALLOW_KEYS or (header and header in ALLOW_HEADERS):
            text, _ = self._detect(urllib.parse.unquote_plus(v) if "%" in v else v)
            return text
        if header == "cookie":
            return self._pairs(v, "; ")
        if PII_NAME.search(header or key) and header != "cookie":
            return self.scalar(header or key, urllib.parse.unquote_plus(v) if "%" in v else v)
        if key in ("url.query", "http.request.body") or self._is_form(v):
            return self._pairs(v, "&")
        if "%" in v:
            v = urllib.parse.unquote_plus(v)
        return self.scalar(header or key, v)

    def attrs(self, items):
        """[(key, value), ...] -> {key: redacted value}"""
        return {k: self.value(k, v) for k, v in items}
