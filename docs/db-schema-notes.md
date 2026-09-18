# MongoDB: shared team database setup

## 1. Creating the shared Atlas cluster (one-time, do this once as a team)

Whoever sets this up should do the following in a browser, then share the
resulting connection string with the rest of the team out-of-band (not
through Git):

1. Go to <https://www.mongodb.com/cloud/atlas/register> and create a free
   account (or log in).
2. Create a new project, e.g. `shadowtrace-sdp`.
3. Build a database: choose the **M0 Free** tier (512MB storage, $0/forever
   - matches the project's $0 procurement budget).
4. Under **Database Access**, add a database user (e.g. `shadowtrace_admin`)
   with a generated password and "Read and write to any database" role.
5. Under **Network Access**, add an IP access entry. For a small student
   team, `0.0.0.0/0` (allow from anywhere) is the pragmatic choice so
   nobody's dynamic home IP breaks the connection - acceptable here because
   access is still gated by the database username/password, and the data
   involved is synthetic (Google Online Boutique traffic), not real PII.
6. Go to **Database -> Connect -> Drivers**, copy the `mongodb+srv://...`
   connection string.
7. Each teammate creates their own local `.env` (copy `.env.example`) and
   sets:
   ```
   MONGO_URI=mongodb+srv://shadowtrace_admin:<password>@<cluster>.mongodb.net/?retryWrites=true&w=majority
   MONGO_DATABASE=shadowtrace
   ```
   Never commit `.env` - it's already gitignored.
8. From any machine, run `python DB/setup_database.py` once to create the
   collections/validators/indexes. It's idempotent - safe to re-run.

If `MONGO_URI` is not set, every script (`setup_database.py`,
`test_connection.py`, `ingest_traces.py`) falls back to the local
docker-compose Mongo instead (`MONGO_USERNAME`/`MONGO_PASSWORD`), so local
dev work never depends on network access to Atlas.

## 2. Which collections are used in this phase

The User Design ERD defines 8 collections; this phase (building the
labelled dataset the ST-GNN trains on) only needs 4:

| Collection | Used now? | Why |
|---|---|---|
| `raw_traces` | Yes | Ingestion staging/tracking record per harvested trace |
| `trials` | Yes | Experiment metadata + the train/test split, at the trial level |
| `graphs` | Yes | The actual training data: parsed DAGs + feature vectors + label |
| `model_versions` | Yes | Records each training run's Macro-F1 once training exists |
| `redaction_policies` | Not yet | Semester 2 runtime redaction config (M5) |
| `feature_windows` | Not yet | Semester 2 live sliding-window features (M5) |
| `alerts` | Not yet | Semester 2 runtime alerting (M5) |
| `policy_actions` | Not yet | Semester 2 Istio enforcement (M6) |

The deferred four aren't deleted or redesigned - their schemas already
exist in `DB/Schemas/` for when the runtime pipeline work starts.

## 3. How a run's traces get their label

`collect_run.sh` / `scripts/orchestrator.py` fire attack bursts **on top of
live normal traffic**, so one run's trace folder
(`data/raw_traces/<run_id>/`) is a mix of normal and (usually) several
different attack types, not one label per folder. The ground truth lives in
`data/runs/<run_id>.json` - the burst log - as a list of
`{attack_type, start_ts, end_ts}` windows in unix seconds.

`DB/ingest_traces.py --run-id <run_id>` reads that burst log once, then for
every trace in the run checks whether its start time falls inside one of
those windows: inside -> that burst's `attack_type`; outside every window
(or no burst log at all, i.e. a `--normal`-mode run) -> `"normal"`. The
label is decided **per trace**, not per folder or per run.

Because a run can contain several distinct attack types, a `trials` document
now also carries `attack_types_present` (every type that actually fired)
alongside `attack_type`, which is `"normal"` (no bursts), the one specific
type (a single-attack run, e.g. `--attacks "ssrf_probe"`), or `"mixed"` (the
default balanced run of several attacks).

The 8 valid attack labels, matching `scripts/attacks/` and
`scripts/orchestrator.py::ATTACKS` exactly: `http_flood`, `exfiltration`,
`brute_force`, `sqli_probe`, `ssrf_probe`, `lateral_movement`,
`session_rotation_brute`, `slow_brute`.

## 4. Retention policy (GDPR Art. 5(1)(e) - storage limitation)

Even a single balanced run generates far more `normal` traces than attack
ones (normal traffic is deliberately the bulk of every run - see
`k6_test/normal_traffic.js` - so attacks stay rare and buried rather than
dominating the traffic mix). That volume can't and shouldn't live in
MongoDB wholesale - Atlas's free tier caps at 512MB, and even self-hosting
that much raw payload just to throw most of it away later defeats the
project's own minimization argument.

The rule, implemented in `DB/setup_database.py::compute_retention` and
applied by `DB/ingest_traces.py` **per trace**, not per run:

- **`normal` traces** -> `retention_class = "temporary"`, no payload
  embedded in Mongo (only a `source_ref` pointing at the original file),
  `expires_at = captured_at + 7 days`. A TTL index on `raw_traces.expires_at`
  deletes the tracking document automatically once that time passes - no
  cron job, the database enforces it. 7 days mirrors the TTL already used
  for `feature_windows` elsewhere in the schema and is long enough to
  cover reprocessing/debugging without becoming an open-ended PII store.
  Once a trace has been parsed into a `graphs` document (structural only -
  service names, latencies, counts, no payload), the raw JSON has served
  its purpose and both the source file and the Mongo tracking record are
  safe to delete.
- **Any of the 8 attack types** -> `retention_class = "long_term_attack"`,
  `expires_at = null`. The TTL index ignores documents where `expires_at`
  is null, so these are never auto-deleted. The full raw payload IS
  embedded for these, since attack traces are the rare, evidentiary class
  the whole thesis is measured against - they're the labelled benchmark
  dataset itself, not disposable intermediate data.

## 5. Downsampling within a run

A single run can still contain tens of thousands of `normal` traces (a
30-50 minute run at 50+ VUs adds up fast), which provide diminishing
training signal past the first few thousand and would overflow the free
tier if all kept. `ingest_traces.py` takes a fixed-seed random sample
(default 5,000 per run, override with `--sample-size`, `0` = no cap) of
that run's `normal` traces, while always ingesting **100%** of every
attack-labeled trace regardless of count (never downsample the minority
classes you're trying to detect). Skipped-by-sampling files are left
untouched on disk - only `--delete-after` removes files that were actually
parsed and stored.
