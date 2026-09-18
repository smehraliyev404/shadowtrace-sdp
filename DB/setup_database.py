# ShadowTrace: MongoDB collection setup - validators + indexes
#
# Covers the 4 collections needed for the current phase (building the
# labelled training dataset for the ST-GNN): raw_traces (ingestion staging),
# trials (experiment/train-test metadata), graphs (the actual training
# data), model_versions (retraining history). The other 4 collections in
# the User Design ERD - redaction_policies, feature_windows, alerts,
# policy_actions - belong to the Semester 2 runtime pipeline and aren't
# created yet; their shapes are still defined in DB/Schemas/ for when that
# work starts.

from datetime import datetime, timedelta, timezone

from pymongo import ASCENDING, DESCENDING

from mongo_client import get_database

# Retention policy (GDPR Art. 5(1)(e) - storage limitation, enforced by the
# database rather than a cleanup job someone has to remember to run):
# - "normal" traffic has no forensic or training value once it has been
#   parsed into a graphs document, so its raw_traces tracking record
#   expires automatically after NORMAL_RETENTION_DAYS.
# - Any attack class is the rare, valuable class the whole thesis is
#   measured against, so it is retained indefinitely: expires_at = None,
#   and the TTL index below simply skips documents where that field is null.
NORMAL_RETENTION_DAYS = 7
# Matches the 8 scripts in scripts/attacks/ exactly (see orchestrator.py's
# ATTACKS dict) - these are the literal strings that land in a run's burst
# log and therefore in every attack-labeled trace/graph document.
ATTACK_TYPES = {
    "http_flood",
    "exfiltration",
    "brute_force",
    "sqli_probe",
    "ssrf_probe",
    "lateral_movement",
    "session_rotation_brute",
    "slow_brute",
}


def compute_retention(attack_type: str, captured_at: datetime):
    """Returns (retention_class, expires_at) for a trace captured at captured_at."""
    if attack_type in ATTACK_TYPES:
        return "long_term_attack", None
    return "temporary", captured_at + timedelta(days=NORMAL_RETENTION_DAYS)


raw_trace_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [
            "trace_id",
            "trial_id",
            "attack_type",
            "captured_at",
            "processing_status",
            "retention_class",
            "expires_at",
            "schema_version",
        ],
        "properties": {
            "trace_id": {"bsonType": "string"},
            "trial_id": {"bsonType": "string"},
            "attack_type": {"enum": ["normal", *sorted(ATTACK_TYPES)]},
            "captured_at": {"bsonType": "date"},
            "source_ref": {
                "bsonType": ["string", "null"],
                "description": "Path/identifier of the original raw JSON file. Full "
                "payloads are not bulk-stored in Mongo at 400k-trace scale - only a "
                "reference, unless retention_class is long_term_attack.",
            },
            "trace_payload": {"bsonType": ["object", "null"]},
            "processing_status": {"enum": ["pending", "parsed", "processed", "failed"]},
            "retention_class": {"enum": ["temporary", "long_term_attack"]},
            "expires_at": {"bsonType": ["date", "null"]},
            "schema_version": {"bsonType": "int"},
        },
    }
}

trial_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["trial_id", "attack_type", "started_at", "split_assignment"],
        "properties": {
            "trial_id": {"bsonType": "string"},
            # A single collect_run.sh run mixes normal traffic with several
            # different attack bursts, so a trial's attack_type is "normal"
            # (no bursts fired), one specific type (a single-attack run, e.g.
            # --attacks "ssrf_probe"), or "mixed" (the default balanced run of
            # several attacks) - see attack_types_present for the full list.
            "attack_type": {"enum": ["normal", "mixed", *sorted(ATTACK_TYPES)]},
            "attack_types_present": {
                "bsonType": "array",
                "items": {"enum": sorted(ATTACK_TYPES)},
                "description": "Every distinct attack type that actually fired during this trial.",
            },
            "platform": {"bsonType": "string"},
            "feature_condition": {"bsonType": "string"},
            "started_at": {"bsonType": "date"},
            "ended_at": {"bsonType": ["date", "null"]},
            "split_assignment": {"enum": ["train", "test"]},
        },
    }
}

graph_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": ["trial_id", "trace_id", "timestamp", "nodes", "edges", "label"],
        "properties": {
            "trial_id": {"bsonType": "string"},
            "trace_id": {"bsonType": "string"},
            "timestamp": {"bsonType": "date"},
            "nodes": {
                "bsonType": "array",
                "items": {
                    "bsonType": "object",
                    "required": ["node_id", "service_name"],
                    "properties": {
                        "node_id": {"bsonType": "string"},
                        "service_name": {"bsonType": "string"},
                    },
                },
            },
            "edges": {
                "bsonType": "array",
                "items": {
                    "bsonType": "object",
                    "required": ["from", "to"],
                    "properties": {
                        "from": {"bsonType": "string"},
                        "to": {"bsonType": "string"},
                        "latency_ms": {"bsonType": ["double", "int"]},
                        "latency_zscore": {"bsonType": ["double", "int", "null"]},
                        "call_count": {"bsonType": "int"},
                    },
                },
            },
            "feature_vector": {"bsonType": "object"},
            "label": {"bsonType": "string"},
        },
    }
}

model_version_validator = {
    "$jsonSchema": {
        "bsonType": "object",
        "required": [
            "version",
            "trained_at",
            "positive_examples",
            "negative_examples",
            "macro_f1",
        ],
        "properties": {
            "version": {"bsonType": "int"},
            "trained_at": {"bsonType": "date"},
            "positive_examples": {"bsonType": "int"},
            "negative_examples": {"bsonType": "int"},
            "macro_f1": {"bsonType": ["double", "int"]},
        },
    }
}

COLLECTIONS = {
    "raw_traces": raw_trace_validator,
    "trials": trial_validator,
    "graphs": graph_validator,
    "model_versions": model_version_validator,
}


def ensure_collection(database, name, validator):
    if name not in database.list_collection_names():
        database.create_collection(name, validator=validator)
        print(f"Created {name} collection")
    else:
        database.command(
            {
                "collMod": name,
                "validator": validator,
                "validationLevel": "strict",
                "validationAction": "error",
            }
        )
        print(f"Updated {name} validation rules")


def main():
    database = get_database()

    for name, validator in COLLECTIONS.items():
        ensure_collection(database, name, validator)

    database.raw_traces.create_index([("trace_id", ASCENDING)], unique=True, name="unique_trace_id")
    database.raw_traces.create_index([("trial_id", ASCENDING)], name="trial_lookup")
    # TTL index: Mongo deletes a document once its expires_at has passed.
    # Documents with expires_at = null (long_term_attack traces) are never
    # touched by this index - that is what makes long-term retention work
    # without a separate code path.
    database.raw_traces.create_index(
        [("expires_at", ASCENDING)], expireAfterSeconds=0, name="raw_trace_expiry"
    )

    database.trials.create_index([("trial_id", ASCENDING)], unique=True, name="unique_trial_id")
    database.trials.create_index([("split_assignment", ASCENDING)], name="split_lookup")

    database.graphs.create_index([("trace_id", ASCENDING)], name="trace_lookup")
    database.graphs.create_index([("trial_id", ASCENDING)], name="trial_lookup")
    database.graphs.create_index([("label", ASCENDING)], name="label_lookup")

    database.model_versions.create_index(
        [("version", DESCENDING)], unique=True, name="unique_version"
    )

    print("Database setup successful")


if __name__ == "__main__":
    main()
