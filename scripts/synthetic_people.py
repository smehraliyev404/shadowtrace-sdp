"""Usernames for the credential-stuffing attacks.

Normal shoppers log in with one of 500 accounts named like "leyla.aliyeva42"
(k6_test/normal_traffic.js, names from k6_test/people.json). If brute force only
tried "admin", "root", ... the recorded login name (enduser.id) alone would tell
attack from normal at L0. Real credential stuffing uses leaked, real-looking
usernames, so the attack lists mix ~30 % typical admin names with ~70 %
"first.last[nn]" names from the same name pool (some of them are real accounts).
Passwords are always wrong: the account passwords are derived with a secret the
attacker does not have (authservice).
"""

import json
import os
import random

PEOPLE = json.load(open(os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                     "..", "k6_test", "people.json"), encoding="utf-8"))

COMMON_PASSWORDS = ["123456", "password", "qwerty", "letmein", "admin123", "welcome1",
                    "Passw0rd", "iloveyou", "dragon", "monkey", "abc123", "football",
                    "baku2024", "summer2025", "P@ssw0rd!", "111111"]


def candidate_usernames(rng_seed=None, n=80):
    rng = random.Random(rng_seed)
    out = []
    while len(out) < n:
        if rng.random() < 0.3:
            name = rng.choice(PEOPLE["admin_usernames"])
        else:
            first, last = rng.choice(PEOPLE["first_names"]), rng.choice(PEOPLE["last_names"])
            name = f"{first}.{last}" + (str(rng.randint(1, 99)) if rng.random() < 0.5 else "")
        if name not in out:
            out.append(name)
    return out


def password_guess(i, username):
    """Deterministic wrong guess number i for a username (common passwords and
    simple variations on the username)."""
    base = COMMON_PASSWORDS[i % len(COMMON_PASSWORDS)]
    variant = (i // len(COMMON_PASSWORDS)) % 4
    if variant == 1:
        return username.split(".")[0] + str(100 + i % 900)
    if variant == 2:
        return base + "!"
    if variant == 3:
        return base.capitalize() + str(i % 100)
    return base
