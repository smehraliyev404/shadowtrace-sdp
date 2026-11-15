# Appendix B — User Design

**ShadowTrace** detects attacks in microservices without storing request payloads. It watches call structure and timing only.

Two parts: **Section 1** covers who uses the system and what they do. **Section 2** covers how the data behind those journeys is stored.

---

## Section 1 — User Journey Maps

### How to read these

Four actors, one journey each. Every map uses the same seven rows across five stages, so they can be compared side by side.

The third map uses **Confidence** instead of Emotions, because its actor is software — an emotion row there would be made up, while confidence is what decides whether the system may act.

**Data sensitivity** runs through all four maps at three levels:

| Level | What it covers |
|---|---|
| Structural | Service names, timestamps, counts, entropy values |
| Metadata | Attribute keys, policy config, user IDs |
| Payload | Request bodies, headers, database queries |

Payload appears in exactly **one** place across all four journeys — the developer preview in 1.1 — and nowhere after. That absence is the point.

### Who does what

| | Redaction | Alerting | Enforcement | Audit |
|---|---|---|---|---|
| **Developer** | Owns | — | — | Supplies evidence |
| **Admin** | — | Owns | Approves | — |
| **System** | Applies | Generates | Owns | Records |
| **Auditor** | Reviews | — | — | Owns |

---

### 1.1 Developer Configures PII Redaction

![Developer configures PII redaction](images/uc1-developer-redaction.png)

Tracing captures request bodies, headers and database queries by default — which quietly turns your monitoring into a copy of your user database. GDPR Article 25 says minimization has to be built in, not cleaned up later. So this journey is a pre-merge gate: you can't ship a service that exports payload.

The developer doesn't label fields by hand. The system scores each endpoint automatically from three signals and assigns a redaction tier. The developer reviews that call and can override it.

Sensitive values are **replaced, not deleted** — swapped for one-way tokens so repeats stay linkable and the detector keeps working.

The **Preview** stage matters most. It's the only place payload is ever visible, and only on screen, so the developer can see for themselves that redaction doesn't break detection. Without it they'd assume it does and turn it off.

> **Database pain point** — policy history loads slowly at Commit because version lookups are unindexed. Fixed by an index on service + version.

---

### 1.2 Admin Views Lateral Movement Alert

![Admin views lateral movement alert](images/uc2-admin-alert.png)

Detection runs on four payload-free signals:

| Signal | What it catches |
|---|---|
| Path entropy | Unusual routes through the system |
| Causal history | Edges and nodes with no precedent |
| Temporal jitter | Irregular timing |
| Call repetition | Same call fired over and over |

The fourth exists because of a known failure. A brute-force login is a graph of two nodes and one edge — identical in shape to a real login. Any model scoring one request at a time calls it normal. Only repetition **across a window** separates them.

The hard part is **Examine Paths**. The admin is used to reading request bodies as evidence and now can't, because that data was never stored. So the interface shows its reasoning instead: which paths appeared that normally don't, and how many times.

> **Database pain point** — graph rendering is slow because trace queries are unindexed. Fixed by an index on `trace_id`.

---

### 1.3 System Auto-Enforces Istio Policy

![System auto-enforces Istio policy](images/uc3-system-enforcement.png)

No human acts in the first four stages. The system sees an anomaly holding across several windows, picks a policy template, and pushes a rate limit or edge block to Istio.

This is the riskiest journey, so it has brakes:

- **Dry-run by default**
- **Human approval** above a severity threshold
- **Expiry** on every auto-applied policy

The reason: our framework validates Istio as a *telemetry source*, not an enforcement target. Blocking automatically on a detector whose accuracy is still an open question is how a security tool causes the outage it was meant to prevent.

The best part is **Verify** — the system re-measures the same features that raised the alert and rolls back if nothing improved. It doesn't just act, it checks whether acting helped.

> **Known limit** — an attacker who knows the logic can pace their calls to stay under threshold. Results describe a non-adaptive attacker.

> **Database pain point** — verification stalls because feature windows are scanned without a compound index. Fixed by an index on `trial_id` + `window_start`.

---

### 1.4 Auditor Reviews Privacy Score

![Auditor reviews privacy score](images/uc4-auditor-audit.png)

The auditor needs proof that privacy was designed in, not bolted on. Three things make that possible, all produced by earlier journeys:

1. **Signed policy history** (from 1.1) — proves *when* controls were applied and by whom
2. **Retention settings** — proves data doesn't linger, satisfying Article 5(1)(e)
3. **Privacy measurement** — gives a number

That number comes with two rules. It's reported as a **measured value with its method named**, never a guarantee. And it's **never shown alone** — always beside the detection accuracy it cost, because that trade-off is the project's actual finding.

> **Database pain point** — the coverage query scans every policy document. Fixed by the same service + version index as 1.1.

---

## Section 2 — Database Design

**Choice: MongoDB, a non-relational document database.**

### 2.1 Why

**Our data changes shape.** The feature vector is what we're testing — 25 values in one condition, 3 in another, more variants after. In SQL each version is a migration. Here it's one field that looks different in different records.

**Our graphs are tiny and separate.** Why not Neo4j? Neo4j is for walking through one huge connected graph. We have tens of thousands of *separate* request graphs, some just two nodes and one edge, each read whole. That's a document read, not a traversal.

**Data pours in and must expire.** Feature windows arrive constantly and are almost never edited. MongoDB deletes old ones automatically — which isn't housekeeping, it's the GDPR retention rule enforced by the database itself.

**Trade-offs we accept.** MongoDB won't reject a malformed record unless we add validation. Joins across collections are clumsier than SQL. Multi-document transactions exist but aren't default. All fine here — our data is written once and rarely joined.

---

### 2.2 Schema

![Collection schema and relationships](images/erd-schema.png)

> PK/FK/UK are shown for readability. MongoDB only enforces `_id`; the rest are conventions the application maintains.

**Eight collections.** Five come from the journey maps, one records retraining, two hold research data.

| Collection | Holds | Journey |
|---|---|---|
| `redaction_policies` | Versioned config + tier assignment | 1.1 writes, 1.4 reads |
| `feature_windows` | Four features per edge per window | 1.2 |
| `alerts` | What fired, and the admin's decision | 1.2 |
| `policy_actions` | Automated responses + verification | 1.3 |
| `privacy_audits` | Privacy score + accuracy it cost | 1.4 |
| `model_versions` | Retraining runs fed by admin labels | after 1.2 |
| `trials` | One experimental run | research only |
| `graphs` | Labelled attack graphs | research only |

**Flexible fields.** Only two fields are free-form: `feature_vector` in graphs and `verification_result` in policy actions. Everything structural stays fixed and indexed. A good document schema isn't schema-less — it pins down what's stable and flexes only where the research needs it.

**Embed or link?** One rule: small things always read with their parent go **inside** it (rules in a policy, nodes in a graph). Anything shared or expiring separately gets **linked** by ID. That's why alerts hold window IDs, not copies — windows delete themselves, alerts must survive.

---

### 2.3 Document Structures

```json
// redaction_policies
{
  "_id": "ObjectId",
  "service_name": "String",
  "version": "Number",
  "rules": [{ "attribute_key": "String", "action": "drop | hash | keep" }],
  "features_enabled": ["String"],
  "sensitivity_score": "Number",
  "signals": { "E": "Number", "C": "Number", "R": "Number" },
  "tier": "maximal | coarse | minimal",
  "hmac_key_ref": "String",
  "author": "String",
  "committed_at": "ISODate",
  "is_active": "Boolean"
}
```

```json
// feature_windows
{
  "_id": "ObjectId",
  "trial_id": "String",
  "edge_key": "String",
  "window_start": "ISODate",
  "window_end": "ISODate",
  "path_entropy": "Number",
  "entropy_baseline": "Number",
  "causal_history_distance": "Number",
  "temporal_jitter_z": "Number",
  "call_repetition": "Number",
  "repetition_baseline": "Number"
}
```

```json
// alerts
{
  "_id": "ObjectId",
  "triggering_window_ids": ["ObjectId"],
  "alert_class": "lateral_movement | brute_force | probing",
  "severity": "low | medium | high",
  "edge_key": "String",
  "detected_at": "ISODate",
  "status": "open | confirmed | dismissed",
  "analyst_label": "String",
  "reviewed_by": "String",
  "reviewed_at": "ISODate"
}
```

```json
// policy_actions
{
  "_id": "ObjectId",
  "alert_id": "ObjectId",
  "istio_policy_type": "rate_limit | deny_edge",
  "mode": "dry_run | awaiting_approval | enforced",
  "applied_at": "ISODate",
  "ttl_seconds": "Number",
  "verification_result": {
    "entropy_after": "Number",
    "repetition_after": "Number",
    "anomaly_subsided": "Boolean"
  },
  "rolled_back": "Boolean",
  "approved_by": "String"
}
```

```json
// graphs
{
  "_id": "ObjectId",
  "trial_id": "String",
  "trace_id": "String",
  "timestamp": "ISODate",
  "nodes": [{ "node_id": "String", "service_name": "String" }],
  "edges": [{
    "from": "String",
    "to": "String",
    "latency_ms": "Number",
    "latency_zscore": "Number",
    "call_count": "Number"
  }],
  "feature_vector": { "<flexible>": "Number" },
  "label": "String"
}
```

```json
// trials
{
  "_id": "ObjectId",
  "trial_id": "String",
  "attack_type": "normal | http_flood | brute_force | sqli | ssrf",
  "platform": "String",
  "feature_condition": "String",
  "started_at": "ISODate",
  "ended_at": "ISODate",
  "split_assignment": "train | test"
}
```

```json
// model_versions
{
  "_id": "ObjectId",
  "version": "Number",
  "trained_at": "ISODate",
  "positive_examples": "Number",
  "negative_examples": "Number",
  "macro_f1": "Number"
}
```

```json
// privacy_audits
{
  "_id": "ObjectId",
  "feature_condition": "String",
  "run_at": "ISODate",
  "redaction_aggressiveness": "Number",
  "detection_macro_f1": "Number",
  "tier_coverage_pct": "Number",
  "redaction_coverage_pct": "Number"
}
```

---

### 2.4 Query Optimization

**Five indexes cover every screen.** Each answers a pain point from Section 1.

```javascript
db.feature_windows.createIndex({ trial_id: 1, window_start: 1 })
db.feature_windows.createIndex({ window_end: 1 }, { expireAfterSeconds: 604800 })
db.alerts.createIndex({ status: 1, severity: 1, detected_at: -1 })
db.graphs.createIndex({ trace_id: 1 })
db.redaction_policies.createIndex({ service_name: 1, version: -1 })
```

| Index | Fixes |
|---|---|
| `trial_id` + `window_start` | Stalled verification (1.3) |
| `window_end` TTL | Automatic retention — the GDPR control |
| `status` + `severity` + `detected_at` | Alert queue sorting (1.2) |
| `trace_id` | Slow graph rendering (1.2) |
| `service_name` + `version` | Slow policy history (1.1) and coverage scan (1.4) |

The expiry index is different from the others — it exists to **delete** data, not retrieve it. That's how the retention obligation is met automatically instead of relying on someone running a cleanup job.

**Aggregation pipelines.** Two do the analytical work:

1. **Baseline comparison** (1.2) — match an edge and time range, group to compute rolling mean and standard deviation, project the deviation. This lets a value be shown against what's normal *for that edge* rather than a global threshold.
2. **Quarterly report** (1.4) — group active policies by service, compute coverage per tier, join to the latest privacy audit so coverage and accuracy cost appear together.

**Caching.** Rolling baselines are cached rather than recomputed per alert. Change streams push new alerts to the interface without polling — which is what makes the five-minute triage target realistic.

---

### 2.5 The Flow

```
policy decides what's collected
        ↓
feature windows record measurements
        ↓
window drifts from baseline → alert
        ↓
sustained alert → policy action (verifies itself)
        ↓
admin decisions → labels → next model version
```

`privacy_audits` reads across everything to produce quarterly evidence.

`trials` and `graphs` sit alongside as the offline data the detector was trained and benchmarked on — no user touches them.