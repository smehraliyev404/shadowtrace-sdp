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

## 3. Retention policy (GDPR Art. 5(1)(e) - storage limitation)

The team currently has ~400k harvested trace files (~30GB), all `normal`
traffic (no attack k6 scripts exist yet). That volume can't and shouldn't
live in MongoDB - Atlas's free tier caps at 512MB, and even self-hosting
30GB of raw payload just to throw most of it away later defeats the
project's own minimization argument.

The rule, implemented in `DB/setup_database.py::compute_retention` and
applied by `DB/ingest_traces.py`:

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
- **Any attack class** (`http_flood`, `brute_force`, `sqli`, `ssrf`,
  `exfiltration`) -> `retention_class = "long_term_attack"`,
  `expires_at = null`. The TTL index ignores documents where `expires_at`
  is null, so these are never auto-deleted. The full raw payload IS
  embedded for these, since attack traces are the rare, evidentiary class
  the whole thesis is measured against - they're the labelled benchmark
  dataset itself, not disposable intermediate data.

Because only `normal` traffic exists today, this design front-loads the
harder rule (long-term retention for something rare and important) so it's
already correct the moment the five k6 attack scripts start producing
labelled data.

## 4. Downsampling the 400k-trace backlog

400k largely-identical benign shopping-flow traces provide little
additional training signal over the first several thousand - and matching
that dataset into Mongo directly would still overflow the free tier even
after stripping payloads. `ingest_traces.py` therefore takes a fixed-seed
random sample (default 5,000, override with `--sample-size`) of `normal`
traces per ingestion run, while always ingesting **100%** of any
attack-class batch (never downsample the minority class you're trying to
detect). This also produces a more usable, less imbalanced dataset for
training than hoarding every trace ever harvested.
