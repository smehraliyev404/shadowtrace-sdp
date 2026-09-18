// Reference indexes for the Semester 2 collections that setup_database.py does not
// create yet (design: User_Design/user-design.md, section 2.4). Run these in
// mongosh once those collections exist.
//
// The collections in use today (raw_traces, trials, graphs, model_versions) get
// their indexes from setup_database.py - including graphs.trace_id, which is a
// unique index there - so they are deliberately not listed here.
db.feature_windows.createIndex({ trial_id: 1, window_start: 1 })
db.feature_windows.createIndex({ window_end: 1 }, { expireAfterSeconds: 604800 })
db.alerts.createIndex({ status: 1, severity: 1, detected_at: -1 })
db.redaction_policies.createIndex({ service_name: 1, version: -1 })