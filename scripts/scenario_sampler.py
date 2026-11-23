"""Scenario sampler: one seed -> data/runs/<run_id>/manifest.json.

Runs ONCE per run, before any traffic, and sends no traffic itself. Everything
random about the NORMAL traffic of a run is drawn here from the seed and written
to the manifest; k6 (k6_test/normal_traffic.js) only reads it. So:

    same seed  ->  same manifest  ->  same shopper behaviour (same load shape,
                                       journey mix, products, think times)

Only the trace IDs stay truly random (they must be unique, not replayable).

Two kinds of run:
  * normal runs (default): parameters drawn from the TRAINING ranges below,
  * --held-out: drawn from separate ranges (different load shape and journey mix)
    that no training run uses, for the generalisation test.

The attack part is drawn here too: which attack runs when, for how long, and
with which rate / concurrency / timing jitter (no fixed sleeps, so timing is not
a giveaway, and no single pattern per run). The orchestrator only replays manifest["attacks"]["schedule"],
anchored to the moment k6 starts. Held-out runs draw attack settings from ranges
no training run uses. --bursts 0 = a pure normal run (attacks: null).

    ./venv/bin/python scripts/scenario_sampler.py --run-id run_01 --seed 101
    ./venv/bin/python scripts/scenario_sampler.py --run-id run_02 --seed 102 --bursts 0
    ./venv/bin/python scripts/scenario_sampler.py --run-id run_09 --seed 909 --held-out
"""

import argparse
import hashlib
import json
import math
import os
import random
import sys
from datetime import datetime, timezone

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
# Version 2: longer attack runs, bursts and gaps (2-4 windows fully inside each
# burst), and a separate length for normal runs. A seed gives a different plan
# than under version 1; every run stores its own manifest.
SCHEMA_VERSION = 2

# The 9 Boutique products (src/productcatalogservice/products.json)
PRODUCTS = ["OLJCESPC7Z", "66VCHSJNUP", "1YMWWN1N4O", "L9ECAV7KIM", "2ZYFJ3GM2N",
            "0PUK6V6EV0", "LS4PSXUNUM", "9SIQT8TOJO", "6E92ZMYYFZ"]
CURRENCIES = ["EUR", "USD", "JPY", "GBP", "TRY", "CAD"]

# ---------------------------------------------------------------- parameter ranges
# (lo, hi) uniform ranges. TRAIN and HELD_OUT differ on purpose; keep them that way.
RANGES = {
    "train": {
        "load_profiles": ["steady", "ramp", "wave"],
        "base_vus": (25, 45),
        "duration_min": (55, 65),        # attack runs: 8 long bursts + long gaps must fit (50-60 squeezed 8 %)
        "duration_min_normal": (35, 45),  # --bursts 0 (pure normal runs)
        "think_time_s": ((0.8, 1.5), (2.5, 4.0)),   # (min range, max range)
        "p_login": (0.12, 0.18),        # sessions that log in with their own account
        "p_login_typo": (0.03, 0.07),   # sessions that mistype the password first
        "p_currency": (0.15, 0.35),
        "p_add_to_cart": (0.55, 0.75),
        "p_checkout": (0.45, 0.65),     # of sessions with a non-empty cart
        "p_invalid_card": (0.08, 0.12),  # of checkouts (~10%)
        "p_empty_cart": (0.03, 0.08),
        "p_logout": (0.05, 0.15),
        "p_abandon_step": (0.05, 0.12),  # chance to leave after any step
        "browse_products": (1, 4),       # product pages viewed before deciding
        "cart_items": (1, 9),            # distinct products in a cart
        "quantity": (1, 5),
        "product_skew": (0.0, 1.2),      # 0 = all products equally popular
    },
    "held_out": {
        "load_profiles": ["spiky"],      # never used in training
        "base_vus": (50, 60),            # more load than any training run
        "duration_min": (60, 70),        # (55-65 squeezed 22 % of held-out schedules)
        "duration_min_normal": (35, 45),
        "think_time_s": ((0.4, 0.7), (1.5, 2.2)),
        "p_login": (0.22, 0.28),
        "p_login_typo": (0.08, 0.10),
        "p_currency": (0.40, 0.50),
        "p_add_to_cart": (0.80, 0.90),
        "p_checkout": (0.70, 0.80),
        "p_invalid_card": (0.08, 0.12),
        "p_empty_cart": (0.10, 0.15),
        "p_logout": (0.20, 0.30),
        "p_abandon_step": (0.02, 0.04),
        "browse_products": (2, 6),
        "cart_items": (1, 9),
        "quantity": (1, 5),
        "product_skew": (1.5, 2.0),
    },
}


def u(rng, lo_hi, nd=3):
    return round(rng.uniform(*lo_hi), nd)


def derive_seed(seed, name):
    """Independent sub-seed per consumer, so adding a new consumer later does not
    shift the numbers any existing one gets."""
    h = hashlib.sha256(f"{seed}:{name}".encode()).hexdigest()
    return int(h[:8], 16)


def fit_stages(stages, total_s):
    """Cut the stage list to exactly total_s seconds: truncate whatever runs past
    the end, drop 0-second stages, and hold the last target if it is too short."""
    out, used = [], 0
    for st in stages:
        d = min(int(st["duration"][:-1]), total_s - used)
        if d > 0:
            out.append({"duration": f"{d}s", "target": st["target"]})
            used += d
    if used < total_s:
        out.append({"duration": f"{total_s - used}s", "target": out[-1]["target"]})
    return out


def load_stages(rng, profile, base_vus, duration_min):
    """k6 ramping-vus stages, exactly duration_min minutes long."""
    total_s = duration_min * 60
    return fit_stages(_raw_stages(rng, profile, base_vus, total_s), total_s)


def _raw_stages(rng, profile, base_vus, total_s):
    if profile == "steady":
        return [{"duration": "60s", "target": base_vus},
                {"duration": f"{total_s - 60}s", "target": base_vus}]
    if profile == "ramp":
        lo = max(5, int(base_vus * u(rng, (0.4, 0.6))))
        hi = int(base_vus * u(rng, (1.1, 1.3)))
        third = total_s // 3
        return [{"duration": "60s", "target": lo},
                {"duration": f"{third}s", "target": lo},
                {"duration": f"{third}s", "target": hi},
                {"duration": f"{total_s - 60 - 2 * third}s", "target": hi}]
    if profile == "wave":
        # slow up/down cycles around base_vus (a "diurnal" pattern compressed)
        n = rng.randint(2, 4)
        amp = u(rng, (0.2, 0.4))
        seg = (total_s - 60) // (2 * n)
        stages = [{"duration": "60s", "target": base_vus}]
        for _ in range(n):
            stages.append({"duration": f"{seg}s", "target": int(base_vus * (1 + amp))})
            stages.append({"duration": f"{seg}s", "target": int(base_vus * (1 - amp))})
        used = 60 + 2 * n * seg
        stages.append({"duration": f"{max(total_s - used, 1)}s", "target": base_vus})
        return stages
    if profile == "spiky":
        # short legitimate surges (held-out only)
        stages, used = [{"duration": "60s", "target": base_vus}], 60
        while used < total_s - 240:
            calm = rng.randint(180, 300)
            stages += [{"duration": f"{calm}s", "target": base_vus},
                       {"duration": "30s", "target": int(base_vus * u(rng, (1.6, 2.0)))},
                       {"duration": "30s", "target": base_vus}]
            used += calm + 60
        stages.append({"duration": f"{max(total_s - used, 1)}s", "target": base_vus})
        return stages
    raise ValueError(profile)


def product_weights(rng, skew):
    """Zipf-like popularity over a seeded random order of the 9 products."""
    order = PRODUCTS[:]
    rng.shuffle(order)
    w = [1.0 / (rank + 1) ** skew for rank in range(len(order))]
    s = sum(w)
    return {pid: round(x / s, 4) for pid, x in zip(order, w)}


# ---------------------------------------------------------------- attacks
ALL_ATTACKS = ["http_flood", "exfiltration", "brute_force", "session_rotation_brute",
               "slow_brute", "sqli_probe", "ssrf_probe", "lateral_movement"]

# Per-attack parameters, passed to the attack script as --<name> <value>.
# TRAIN ranges sit around the rates the cluster survived (orchestrator.py notes:
# http_flood capped ~15/s, brute ~28/s, sqli ~30/s). HELD_OUT ranges are disjoint
# from TRAIN but not faster, so the held-out run tests unseen settings, not a
# cluster overload. ("choice", [...]) = pick one; (lo, hi) ints = randint.
ATTACK_RANGES = {
    "train": {
        "http_flood":             {"concurrency": (3, 4), "pause": (0.16, 0.24)},
        "exfiltration":           {"pause": (0.10, 0.18)},
        "brute_force":            {"concurrency": (4, 6), "pause": (0.18, 0.30)},
        "session_rotation_brute": {"concurrency": (4, 6), "pause": (0.18, 0.30)},
        "slow_brute":             {"interval": (1.5, 3.0)},
        "sqli_probe":             {"pause": (0.02, 0.04)},
        "ssrf_probe":             {"pause": (0.08, 0.15)},
        # source: where the in-cluster foothold is: the attacker pod,
        # or code running inside a compromised legitimate pod
        "lateral_movement":       {"pause": (0.20, 0.40),
                                   "source": ("choice", ["attacker", "recommendationservice"])},
        "_jitter": (0.3, 0.5),        # +-share of the pause, per request
        "_burst_s": (150, 300),       # v2: 2-4 windows fully inside each burst (v1: 90-150)
        "_gap_s": (120, 180),         # v2: >= 1 clean normal window between bursts (v1: 75-120)
        "_lead_in_s": (90, 150),      # normal traffic before the first burst (v1: 60-120)
    },
    "held_out": {
        "http_flood":             {"concurrency": (2, 2), "pause": (0.10, 0.12)},
        "exfiltration":           {"pause": (0.25, 0.35)},
        "brute_force":            {"concurrency": (2, 3), "pause": (0.10, 0.12)},
        "session_rotation_brute": {"concurrency": (2, 3), "pause": (0.10, 0.12)},
        "slow_brute":             {"interval": (4.0, 5.0)},
        "sqli_probe":             {"pause": (0.06, 0.08)},
        "ssrf_probe":             {"pause": (0.25, 0.30)},
        "lateral_movement":       {"pause": (0.60, 0.80),
                                   "source": ("choice", ["attacker", "recommendationservice"])},
        "_jitter": (0.6, 0.7),
        "_burst_s": (200, 300),       # v2 (v1: 160-200)
        "_gap_s": (150, 200),         # v2 (v1: 130-160)
        "_lead_in_s": (150, 200),     # v2 (v1: 130-160)
    },
}
TAIL_S = 60          # normal traffic after the last burst, before k6 stops
MIN_BURST_S, MIN_GAP_S, MIN_LEAD_S = 90, 75, 60


def draw_param(rng, spec):
    if isinstance(spec, tuple) and spec and spec[0] == "choice":
        return rng.choice(spec[1])
    lo, hi = spec
    if isinstance(lo, int) and isinstance(hi, int):
        return rng.randint(lo, hi)
    return round(rng.uniform(lo, hi), 3)


def attack_schedule(seed, kind, attacks, n_bursts, total_s):
    """Seeded attack plan that fits inside the k6 run (total_s seconds)."""
    if n_bursts == 0:
        return None
    R = ATTACK_RANGES[kind]
    rng = random.Random(derive_seed(seed, "attacks"))

    # deck draw: every attack once (shuffled) before any repeats
    order, deck = [], []
    for _ in range(n_bursts):
        if not deck:
            deck = list(attacks)
            rng.shuffle(deck)
        order.append(deck.pop())

    lead = rng.randint(*R["_lead_in_s"])
    durs = [rng.randint(*R["_burst_s"]) for _ in order]
    gaps = [rng.randint(*R["_gap_s"]) for _ in order[1:]]
    params = []
    for i, a in enumerate(order):
        ps = {k: draw_param(rng, v) for k, v in R[a].items()}
        ps["jitter"] = u(rng, R["_jitter"])
        ps["rng_seed"] = derive_seed(seed, f"attack{i}")
        params.append(ps)

    # Too long for the run? Shrink gaps, then bursts, then the lead-in towards
    # their minimums (all by the same share), deterministically.
    def need():
        return lead + sum(durs) + sum(gaps) + TAIL_S
    for vals, floor in ((gaps, MIN_GAP_S), (durs, MIN_BURST_S)):
        excess = need() - total_s
        room = sum(v - floor for v in vals)
        if excess > 0 and room > 0:
            cut = min(1.0, excess / room)
            for j, v in enumerate(vals):
                vals[j] = max(floor, v - math.ceil((v - floor) * cut))
    if need() > total_s:
        lead = max(MIN_LEAD_S, lead - (need() - total_s))
    if need() > total_s:
        raise SystemExit(f"[sampler] {n_bursts} bursts need >= {need()} s but the run is "
                         f"{total_s} s: use fewer --bursts or a longer run")

    schedule, t = [], lead
    for i, a in enumerate(order):
        schedule.append({"i": i, "attack": a, "start_s": t, "duration_s": durs[i],
                         "params": params[i]})
        t += durs[i] + (gaps[i] if i < len(gaps) else 0)
    return {"kind": kind, "attacks_pool": list(attacks), "lead_in_s": lead,
            "tail_s": total_s - schedule[-1]["start_s"] - schedule[-1]["duration_s"],
            "attack_seconds": sum(durs), "schedule": schedule}


def sample(run_id, seed, held_out=False, minutes=None, attacks=None, n_bursts=None):
    kind = "held_out" if held_out else "train"
    R = RANGES[kind]
    rng = random.Random(derive_seed(seed, "normal"))

    profile = rng.choice(R["load_profiles"])
    base_vus = rng.randint(*R["base_vus"])
    duration_min = rng.randint(*R["duration_min"])
    if n_bursts == 0:
        # pure normal run: its own (shorter) length; drawn after duration_min so
        # the random stream for everything else stays the same
        duration_min = rng.randint(*R["duration_min_normal"])
    if minutes is not None:
        # test runs only: shorter run, every other parameter still from the seed
        # (the draw above still happens, so the rest of the manifest is unchanged)
        duration_min = minutes
    tmin = u(rng, R["think_time_s"][0])
    tmax = u(rng, R["think_time_s"][1])

    journey = {k: u(rng, R[k]) for k in (
        "p_login", "p_login_typo", "p_currency", "p_add_to_cart", "p_checkout",
        "p_invalid_card", "p_empty_cart", "p_logout", "p_abandon_step")}
    journey.update({
        "browse_products": {"min": R["browse_products"][0], "max": R["browse_products"][1]},
        "cart_items": {"min": R["cart_items"][0], "max": R["cart_items"][1]},
        "quantity": {"min": R["quantity"][0], "max": R["quantity"][1]},
        "currencies": CURRENCIES,
        "product_weights": product_weights(rng, u(rng, R["product_skew"])),
    })

    return {
        "schema_version": SCHEMA_VERSION,
        "run_id": run_id,
        "seed": seed,
        "kind": kind,
        "test_run": minutes is not None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "normal": {
            "k6_seed": derive_seed(seed, "k6"),
            "load": {"profile": profile, "base_vus": base_vus,
                     "duration_min": duration_min,
                     "stages": load_stages(rng, profile, base_vus, duration_min)},
            "think_time_s": {"min": tmin, "max": tmax},
            "journey": journey,
        },
        "attacks": attack_schedule(
            seed, kind, attacks or ALL_ATTACKS,
            len(attacks or ALL_ATTACKS) if n_bursts is None else n_bursts,
            duration_min * 60),
    }


def main():
    p = argparse.ArgumentParser(description="ShadowTrace scenario sampler (seed -> manifest)")
    p.add_argument("--run-id", required=True)
    p.add_argument("--seed", type=int, required=True)
    p.add_argument("--held-out", action="store_true",
                   help="draw from the held-out ranges (unseen load and journey mix)")
    p.add_argument("--out", help="default data/runs/<run_id>/manifest.json")
    p.add_argument("--force", action="store_true", help="overwrite an existing manifest")
    p.add_argument("--attacks", nargs="+", default=None, choices=ALL_ATTACKS,
                   help="attack pool (default: all 8)")
    p.add_argument("--bursts", type=int, default=None,
                   help="number of bursts (default: one per attack in the pool; 0 = normal run)")
    p.add_argument("--minutes", type=int, default=None,
                   help="TEST RUNS ONLY: override the run length (min 3). Marks the "
                        "manifest test_run=true; never use for dataset runs")
    a = p.parse_args()

    out = a.out or os.path.join(PROJECT_ROOT, "data", "runs", a.run_id, "manifest.json")
    if os.path.exists(out) and not a.force:
        sys.exit(f"[sampler] {out} exists; a run's manifest is written once (use --force)")
    if a.minutes is not None and a.minutes < 3:
        p.error("--minutes must be >= 3 (stages need a 60 s ramp plus room for the profile)")
    m = sample(a.run_id, a.seed, a.held_out, a.minutes, a.attacks, a.bursts)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(m, f, indent=2)
    L = m["normal"]["load"]
    print(f"[sampler] {a.run_id} seed={a.seed} kind={m['kind']} profile={L['profile']} "
          f"vus~{L['base_vus']} {L['duration_min']}min -> {out}")
    A = m["attacks"]
    if A is None:
        print("[sampler] no attacks (normal run)")
    else:
        for b in A["schedule"]:
            print(f"[sampler]   t+{b['start_s']:5d}s  {b['attack']:22s} {b['duration_s']:4d}s  {b['params']}")


if __name__ == "__main__":
    main()
