"""Run-level split of a batch, fixed before any results exist.

    ./venv/bin/python scripts/make_split.py --queue queues/batch3.txt --out splits/batch3.json

Run types come from the queue flags (as run_queue.py reads them):
    attack           no flag          every run has one burst of each of the 8 attacks
    normal           --normal         no attacks
    held-out attack  --held-out       unseen load and attack settings
    held-out normal  --held-out --normal

Five run assignments (PLAN.md §11, "5 seeds x 5 run assignments"): attack and
normal runs are each shuffled once (fixed seed) and cut into 5 equal groups.
Assignment i uses group i as test, group i+1 (mod 5) as validation and the
other three as training, so every run is a test run exactly once and the
split is ~60/20/20 inside each run type. Held-out runs are never trained on
or tuned on; they are a separate test set in every assignment.
"""

import argparse
import hashlib
import json
import os
import random
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
N_FOLDS = 5


def read_queue(path):
    runs = []
    for line in open(path, encoding="utf-8"):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        run_id, _seed, *flags = line.split()
        held, normal = "--held-out" in flags, "--normal" in flags
        kind = ("heldout_normal" if held and normal else "heldout_attack" if held
                else "normal" if normal else "attack")
        runs.append((run_id, kind))
    return runs


def make_split(runs, seed):
    rng = random.Random(seed)
    groups = {}
    for kind in ("attack", "normal"):
        ids = sorted(r for r, k in runs if k == kind)
        if len(ids) % N_FOLDS:
            raise SystemExit(f"{len(ids)} {kind} runs do not split into {N_FOLDS} equal groups")
        rng.shuffle(ids)
        size = len(ids) // N_FOLDS
        groups[kind] = [sorted(ids[i * size:(i + 1) * size]) for i in range(N_FOLDS)]
    heldout = sorted(r for r, k in runs if k.startswith("heldout"))
    assignments = []
    for i in range(N_FOLDS):
        v = (i + 1) % N_FOLDS
        a = {"assignment": i, "train": [], "val": [], "test": [], "heldout": heldout}
        for kind, g in groups.items():
            a["test"] += g[i]
            a["val"] += g[v]
            a["train"] += [r for j, grp in enumerate(g) if j not in (i, v) for r in grp]
        for part in ("train", "val", "test"):
            a[part] = sorted(a[part])
        assignments.append(a)
    return groups, assignments


def check(assignments, runs):
    all_ids = {r for r, _ in runs}
    tested = []
    for a in assignments:
        parts = [set(a[p]) for p in ("train", "val", "test", "heldout")]
        for i in range(4):
            for j in range(i + 1, 4):
                assert not parts[i] & parts[j], f"assignment {a['assignment']}: overlap"
        assert set().union(*parts) == all_ids, f"assignment {a['assignment']}: runs missing"
        tested += a["test"]
    assert sorted(tested) == sorted(r for r, k in runs if k in ("attack", "normal")), "not every run tested once"


def main():
    p = argparse.ArgumentParser(description="fixed run-level split of a batch")
    p.add_argument("--queue", default=os.path.join(PROJECT_ROOT, "queues", "batch3.txt"))
    p.add_argument("--out", default=os.path.join(PROJECT_ROOT, "splits", "batch3.json"))
    p.add_argument("--seed", type=int, default=20261116, help="shuffle seed (fixed; do not change after results)")
    p.add_argument("--force", action="store_true", help="overwrite an existing split")
    a = p.parse_args()
    if os.path.exists(a.out) and not a.force:
        raise SystemExit(f"{a.out} exists: the split is fixed once made (use --force only before any results)")
    runs = read_queue(a.queue)
    groups, assignments = make_split(runs, a.seed)
    check(assignments, runs)
    out = {
        "queue": os.path.relpath(a.queue, PROJECT_ROOT),
        "queue_sha256": hashlib.sha256(open(a.queue, "rb").read()).hexdigest()[:16],
        "seed": a.seed, "created_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "run_kinds": dict(runs),
        "groups": groups,
        "assignments": assignments,
    }
    os.makedirs(os.path.dirname(a.out), exist_ok=True)
    json.dump(out, open(a.out, "w"), indent=1)
    kinds = {k: sum(1 for _, x in runs if x == k) for k in sorted({k for _, k in runs})}
    a0 = assignments[0]
    print(f"[split] {len(runs)} runs {kinds}; per assignment train {len(a0['train'])}, "
          f"val {len(a0['val'])}, test {len(a0['test'])}, held-out {len(a0['heldout'])} -> {a.out}")


if __name__ == "__main__":
    main()
