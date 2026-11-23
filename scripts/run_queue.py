"""Run queue: a series of collection runs, one at a time, unattended.

    tmux new -s runs
    ./venv/bin/python scripts/run_queue.py queues/batch3.txt      # then Ctrl+B, d
    ./venv/bin/python scripts/run_queue.py queues/batch3.txt --plan   # only show the plan

Queue file: one run per line, "<run_id> <seed> [collect_run.sh flags...]", e.g.
    run_01 101
    run_09 909 --held-out
    run_10 110 --normal
Blank lines and "# comments" are ignored.

What it does:
  * preflight before EVERY run: kubectl context = minikube, cluster CPU cap = 12
    (set again if minikube lost it), Jaeger answering, all pods Ready (waits up to
    5 min), port-forwards answering (restarted if dead), enough free disk, and
    redis-cart emptied (carts pile up over days; memory limit 256Mi).
  * warm-up: 10 min of uncollected normal traffic at queue start and whenever the
    minikube container was restarted (the first run after a start is slower:
    Java/Node warm-up).
  * runs ./collect_run.sh for each line; its output goes to the screen AND to
    data/runs/<run_id>.collect.log.
  * gates per run: collect_run.sh exit 0 (every burst ran, harvest ok, join gates
    A/B and partial-trace gate C in check_origin_match.py) AND no pod restarted
    or was replaced during the run.
  * a failed run is recorded and the queue moves on; an unhealthy cluster
    (pods not Ready after 5 min) stops the queue.
  * resumable: each run gets data/runs/<run_id>.queue.json; runs that already
    have one (done, failed or interrupted) are skipped, so the same command
    continues after Ctrl+C or a reboot. Rerun a failed run under a NEW run id.
  * morning report: data/queue_reports/<queue name>.md (+ .json), rewritten after
    every run, so it is readable while the queue is still going.
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime

PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
DATA_DIR = os.getenv("SHADOWTRACE_DATA", os.path.join(PROJECT_ROOT, "data"))   # override: tests only
RUNS_DIR = os.path.join(DATA_DIR, "runs")
RAW_DIR = os.path.join(DATA_DIR, "raw_traces")
REPORT_DIR = os.path.join(DATA_DIR, "queue_reports")
PY = os.path.join(PROJECT_ROOT, "venv", "bin", "python")

CPU_CAP_NANO = 12_000_000_000          # 12 CPUs
PORT_FORWARDS = [("frontend", "8080:80"), ("authservice", "8081:8080"), ("ssrfservice", "8082:8080")]
JAEGER = "http://localhost:16686/api/services"


def log(msg):
    print(f"[queue {datetime.now():%H:%M:%S}] {msg}", flush=True)


def sh(cmd, timeout=120):
    """Run a command, return (exit code, stdout+stderr)."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, (r.stdout + r.stderr).strip()
    except (subprocess.TimeoutExpired, FileNotFoundError) as e:
        return 99, str(e)


# ---------------------------------------------------------------- health checks

def http_status(url, method="GET", timeout=5):
    req = urllib.request.Request(url, method=method, data=b"" if method == "POST" else None)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status
    except urllib.error.HTTPError as e:
        return e.code
    except (urllib.error.URLError, OSError):
        return None


def port_forwards_ok():
    return (http_status("http://localhost:8080/") == 200
            and http_status("http://localhost:8081/login", "POST") == 401
            and http_status("http://localhost:8082/healthz") == 200)


def restart_port_forwards():
    log("port-forwards not answering - restarting them")
    sh(["pkill", "-f", "kubectl port-forward"])
    time.sleep(1)
    for svc, ports in PORT_FORWARDS:
        out = open(f"/tmp/pf_{svc}.log", "w")
        subprocess.Popen(["kubectl", "port-forward", f"svc/{svc}", ports],
                         stdout=out, stderr=subprocess.STDOUT, start_new_session=True)
    for _ in range(15):
        time.sleep(2)
        if port_forwards_ok():
            log("port-forwards back up")
            return True
    return False


def pods():
    """{pod name: (all containers ready, total restarts)}"""
    rc, out = sh(["kubectl", "get", "pods", "-o", "json"])
    if rc != 0:
        return None
    res = {}
    for p in json.loads(out).get("items", []):
        cs = p.get("status", {}).get("containerStatuses") or []
        res[p["metadata"]["name"]] = (bool(cs) and all(c.get("ready") for c in cs),
                                      sum(c.get("restartCount", 0) for c in cs))
    return res


def wait_pods_ready(limit_s=300):
    t0 = time.time()
    while time.time() - t0 < limit_s:
        p = pods()
        if p and all(ready for ready, _ in p.values()):
            return p
        time.sleep(10)
    return None


def cluster_started_at():
    rc, out = sh(["docker", "inspect", "minikube", "--format", "{{.State.StartedAt}}"])
    return out if rc == 0 else None


def ensure_cap():
    rc, out = sh(["docker", "inspect", "minikube", "--format", "{{.HostConfig.NanoCpus}}"])
    if rc == 0 and out.strip() == str(CPU_CAP_NANO):
        return True, "ok"
    log(f"cluster CPU cap is {out.strip()!r}, setting {CPU_CAP_NANO // 10**9}")
    sh(["docker", "update", "--cpus", str(CPU_CAP_NANO // 10**9), "minikube"])
    rc, out = sh(["docker", "inspect", "minikube", "--format", "{{.HostConfig.NanoCpus}}"])
    return (rc == 0 and out.strip() == str(CPU_CAP_NANO)), "re-applied"


def flush_carts():
    """Empty redis-cart before every run. Every k6 session is a new shopper, and
    abandoned carts stay in Redis (memory limit 256Mi); over a multi-day queue
    that could OOM-kill the pod. Starting each run with an empty cart store also
    keeps runs alike. Returns the number of keys removed (None if it failed)."""
    rc, out = sh(["kubectl", "exec", "deploy/redis-cart", "--", "redis-cli", "DBSIZE"])
    keys = int(out.split()[-1]) if rc == 0 and out.split() and out.split()[-1].isdigit() else None
    rc2, _ = sh(["kubectl", "exec", "deploy/redis-cart", "--", "redis-cli", "FLUSHALL"])
    return keys if rc2 == 0 else None


def free_gb():
    os.makedirs(DATA_DIR, exist_ok=True)
    return shutil.disk_usage(DATA_DIR).free / 2**30


def preflight(min_free_gb):
    """Everything a run needs. Returns (ok, notes, pod snapshot)."""
    notes = []
    rc, ctx = sh(["kubectl", "config", "current-context"])
    if ctx != "minikube":
        sh(["kubectl", "config", "use-context", "minikube"])
        notes.append(f"kubectl context was {ctx!r}, switched to minikube")
    ok_cap, how = ensure_cap()
    if how != "ok":
        notes.append(f"CPU cap {how}")
    if not ok_cap:
        return False, notes + ["could not set the CPU cap"], None
    if http_status(JAEGER) != 200:
        return False, notes + ["Jaeger not answering on :16686 (docker compose up -d jaeger)"], None
    snap = wait_pods_ready()
    if snap is None:
        return False, notes + ["pods not all Ready after 5 min"], None
    if not port_forwards_ok() and not restart_port_forwards():
        return False, notes + ["port-forwards could not be restarted"], None
    if free_gb() < min_free_gb:
        return False, notes + [f"only {free_gb():.0f} GB free on data/ (< {min_free_gb})"], None
    keys = flush_carts()
    if keys is None:
        notes.append("could not empty redis-cart (continuing)")
    elif keys > 0:
        log(f"emptied redis-cart ({keys} carts)")
    return True, notes, snap


# ---------------------------------------------------------------- warm-up

def warm_up(minutes):
    log(f"warm-up: {minutes} min of normal traffic, not collected")
    manifest = "/tmp/shadowtrace_warmup_manifest.json"
    rc, out = sh([PY, os.path.join(PROJECT_ROOT, "scripts", "scenario_sampler.py"),
                  "--run-id", "warmup", "--seed", "1", "--minutes", str(minutes),
                  "--bursts", "0", "--out", manifest, "--force"])
    if rc != 0:
        log(f"warm-up manifest failed: {out[-300:]}")
        return False
    rc, out = sh(["k6", "run", "-q", "--log-format", "raw", "--console-output", "/dev/null",
                  "-e", f"MANIFEST={manifest}", "-e", "BASE_URL=http://localhost:8080",
                  "-e", "AUTH_URL=http://localhost:8081",
                  os.path.join(PROJECT_ROOT, "k6_test", "normal_traffic.js")],
                 timeout=minutes * 60 + 120)
    log(f"warm-up done (k6 exit {rc})")
    return rc == 0


# ---------------------------------------------------------------- one run

def run_collect(collect_cmd, run_id, seed, flags):
    """collect_run.sh with output on screen and in data/runs/<run>.collect.log."""
    os.makedirs(RUNS_DIR, exist_ok=True)
    logpath = os.path.join(RUNS_DIR, f"{run_id}.collect.log")
    cmd = [*collect_cmd, run_id, "--seed", str(seed), *flags]
    with open(logpath, "a", encoding="utf-8") as lf:
        lf.write(f"\n=== {datetime.now().isoformat()} {' '.join(cmd)}\n")
        # own process group, so stopping the queue can stop k6, the orchestrator and
        # the attack scripts too (otherwise k6 keeps sending traffic into the next run)
        proc = subprocess.Popen(cmd, cwd=PROJECT_ROOT, stdout=subprocess.PIPE,
                                stderr=subprocess.STDOUT, text=True, bufsize=1, start_new_session=True)
        try:
            for line in proc.stdout:
                sys.stdout.write(line)
                lf.write(line)
            return proc.wait()
        except BaseException:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=30)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass
            raise


def read_json(path):
    try:
        return json.load(open(path, encoding="utf-8"))
    except (OSError, ValueError):
        return None


def dir_size_gb(path):
    total = 0
    for root, _, files in os.walk(path):
        for f in files:
            try:
                total += os.path.getsize(os.path.join(root, f))
            except OSError:
                pass
    return total / 2**30


def kind_of(flags):
    return "normal" if "--normal" in flags else "held_out" if "--held-out" in flags else "attack"


def status_path(run_id):
    return os.path.join(RUNS_DIR, f"{run_id}.queue.json")


def do_run(collect_cmd, run_id, seed, flags, before):
    rec = {"run_id": run_id, "seed": seed, "flags": flags, "kind": kind_of(flags),
           "started": datetime.now().isoformat(timespec="seconds"),
           "loadavg_before": [round(x, 2) for x in os.getloadavg()]}
    t0 = time.time()
    rc = run_collect(collect_cmd, run_id, seed, flags)
    rec["minutes"] = round((time.time() - t0) / 60, 1)
    rec["collect_exit"] = rc
    rec["loadavg_after"] = [round(x, 2) for x in os.getloadavg()]

    after = None
    for _ in range(5):                       # a kubectl hiccup must not look like replaced pods
        after = pods()
        if after is not None:
            break
        time.sleep(10)
    restarted = {n: after[n][1] - before[n][1] for n in before
                 if n in after and after[n][1] > before[n][1]} if after is not None else {}
    replaced = sorted(set(before) ^ set(after)) if after is not None else []
    rec["pod_restarts"] = restarted
    rec["pods_replaced"] = replaced

    m = read_json(os.path.join(RUNS_DIR, run_id, "origin_match.json")) or {}
    h = read_json(os.path.join(RUNS_DIR, f"{run_id}.harvest.json")) or {}
    rec.update({
        "traces": h.get("traces_saved"), "spans": h.get("spans_saved"),
        "harvest_status": h.get("status"),
        "requests": m.get("origin_requests"),
        "gate_a": m.get("gate_a_harvested_matched"), "gate_b": m.get("gate_b_origin_found"),
        "gate_c": m.get("gate_c_partial"), "partial_rate": m.get("partial_rate"),
        "match_rate": m.get("match_rate_excl_background"),
        "patterns": (m.get("patterns") or {}).get("by_label"),
        "raw_gb": round(dir_size_gb(os.path.join(RAW_DIR, run_id)), 2),
    })
    problems = []
    if rc != 0:
        problems.append(f"collect_run.sh exit {rc}")
    if restarted:
        problems.append(f"pod restarts during run: {restarted}")
    if replaced:
        problems.append(f"pods replaced during run: {replaced}")
    if after is None:
        problems.append("could not read pods after the run (kubectl failed 5 times): restarts unverified")
    rec["problems"] = problems
    rec["status"] = "done" if not problems else "failed"
    rec["ended"] = datetime.now().isoformat(timespec="seconds")
    json.dump(rec, open(status_path(run_id), "w"), indent=2)
    return rec


# ---------------------------------------------------------------- report

def write_report(queue_name, entries, queue_notes):
    os.makedirs(REPORT_DIR, exist_ok=True)
    md = os.path.join(REPORT_DIR, f"{queue_name}.md")
    lines = [f"# Run queue `{queue_name}`", "",
             f"Updated {datetime.now():%Y-%m-%d %H:%M}, free disk {free_gb():.0f} GB.", ""]
    for n in queue_notes:
        lines.append(f"- {n}")
    lines += ["", "| Run | Seed | Kind | Status | Start | Min | Traces | Requests | Match | A | B | C (partial) | Normal patterns | Restarts | Load before | Raw GB | Problems |",
              "|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|"]

    def yn(v):
        return "–" if v is None else ("✓" if v else "✗")

    for e in entries:
        normal = ((e.get("patterns") or {}).get("normal") or {})
        pr = e.get("partial_rate")
        lines.append("| " + " | ".join(str(x) for x in [
            e["run_id"], e.get("seed", ""), e.get("kind", ""), e.get("status", "pending"),
            (e.get("started") or "")[11:16], e.get("minutes", ""), e.get("traces", ""),
            e.get("requests", ""),
            f"{e['match_rate']:.2%}" if e.get("match_rate") is not None else "",
            yn(e.get("gate_a")), yn(e.get("gate_b")),
            f"{yn(e.get('gate_c'))} {pr:.2%}" if pr is not None else yn(e.get("gate_c")),
            normal.get("distinct", ""), sum((e.get("pod_restarts") or {}).values()) or 0,
            (e.get("loadavg_before") or [""])[0], e.get("raw_gb", ""),
            "; ".join(e.get("problems") or [])]) + " |")
    done = sum(e.get("status") == "done" for e in entries)
    lines += ["", f"**{done} of {len(entries)} runs done.**", ""]
    open(md, "w", encoding="utf-8").write("\n".join(lines))
    json.dump({"queue": queue_name, "notes": queue_notes, "runs": entries},
              open(os.path.join(REPORT_DIR, f"{queue_name}.json"), "w"), indent=2)
    return md


# ---------------------------------------------------------------- main

def parse_queue(path):
    runs = []
    for i, line in enumerate(open(path, encoding="utf-8"), 1):
        line = line.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        if len(parts) < 2 or not parts[1].isdigit():
            raise SystemExit(f"{path}:{i}: expected '<run_id> <seed> [flags]', got {line!r}")
        runs.append((parts[0], int(parts[1]), parts[2:]))
    ids = [r[0] for r in runs]
    if len(ids) != len(set(ids)):
        raise SystemExit(f"{path}: duplicate run ids")
    return runs


def main():
    p = argparse.ArgumentParser(description="ShadowTrace run queue")
    p.add_argument("queue_file")
    p.add_argument("--warmup-min", type=int, default=10)
    p.add_argument("--min-free-gb", type=float, default=30)
    p.add_argument("--plan", action="store_true", help="show what would run, run nothing")
    p.add_argument("--collect-cmd", default="./collect_run.sh",
                   help=argparse.SUPPRESS)          # tests only
    a = p.parse_args()

    runs = parse_queue(a.queue_file)
    name = os.path.splitext(os.path.basename(a.queue_file))[0]
    entries, todo = [], []
    for run_id, seed, flags in runs:
        st = read_json(status_path(run_id))
        if st:
            entries.append(st)
        elif os.path.exists(os.path.join(RUNS_DIR, run_id)):
            entries.append({"run_id": run_id, "seed": seed, "kind": kind_of(flags),
                            "status": "interrupted",
                            "problems": ["run folder exists without a queue record "
                                         "(stopped mid-run?) - rerun under a new id"]})
        else:
            entries.append({"run_id": run_id, "seed": seed, "kind": kind_of(flags), "status": "pending"})
            todo.append((run_id, seed, flags))

    log(f"queue {name}: {len(runs)} runs, {len(todo)} to do, "
        f"{len(runs) - len(todo)} already recorded")
    for run_id, seed, flags in todo:
        log(f"  {run_id} seed={seed} {' '.join(flags)}")
    if a.plan:
        return                        # --plan only prints; it writes nothing
    if not todo:
        write_report(name, entries, ["nothing to do"])
        return

    collect_cmd = a.collect_cmd.split()
    notes = [f"queue started {datetime.now():%Y-%m-%d %H:%M}"]
    warmed_for = None
    by_id = {e["run_id"]: e for e in entries}

    def stop(signum, frame):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, stop)

    try:
        for run_id, seed, flags in todo:
            ok, pf_notes, snap = preflight(a.min_free_gb)
            notes += [f"{run_id}: {n}" for n in pf_notes]
            if not ok:
                notes.append(f"STOPPED before {run_id}: {pf_notes[-1]}")
                log(notes[-1])
                write_report(name, entries, notes)
                sys.exit(2)
            started = cluster_started_at()
            if a.warmup_min > 0 and started != warmed_for:
                if not warm_up(a.warmup_min):
                    notes.append(f"warm-up before {run_id} failed (k6) - continuing")
                warmed_for = started
                notes.append(f"warm-up {a.warmup_min} min before {run_id}")
                snap = pods() or snap            # restarts during warm-up do not count
            log(f"=== {run_id} (seed {seed}) {' '.join(flags)}")
            by_id[run_id].update({"status": "running",
                                  "started": datetime.now().isoformat(timespec="seconds")})
            write_report(name, entries, notes)
            rec = do_run(collect_cmd, run_id, seed, flags, snap)
            by_id[run_id].clear()
            by_id[run_id].update(rec)
            log(f"=== {run_id}: {rec['status'].upper()}"
                + (f" ({'; '.join(rec['problems'])})" if rec["problems"] else ""))
            md = write_report(name, entries, notes)
            log(f"report -> {md}")
    except KeyboardInterrupt:
        for e in entries:
            if e.get("status") == "running":
                e.update({"status": "interrupted", "problems": ["queue stopped during this run"]})
                json.dump(e, open(status_path(e["run_id"]), "w"), indent=2)
        notes.append(f"queue interrupted {datetime.now():%H:%M}")
        write_report(name, entries, notes)
        log("interrupted - report written; rerun the same command to continue")
        sys.exit(130)

    notes.append(f"queue finished {datetime.now():%Y-%m-%d %H:%M}")
    md = write_report(name, entries, notes)
    log(f"ALL DONE -> {md}")


if __name__ == "__main__":
    main()
