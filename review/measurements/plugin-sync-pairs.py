"""Run counterbalanced full-CRS benchmark process pairs on one pinned CPU.

usage: pairs.py <before-exe> <after-exe> <before-rev> <after-rev> <cpu> <out-dir>
"""

import hashlib
import json
import os
import shutil
import statistics
import subprocess
import sys
from pathlib import Path

WORKLOADS = ["get", "form", "json"]
ORDERS = ["before after", "after before", "after before", "before after"]
SAMPLES = 24


def sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def main():
    before, after, before_rev, after_rev, cpu, out = sys.argv[1:7]
    out = Path(out)
    out.mkdir(parents=True)
    exe = {"before": before, "after": after}
    record = {
        "harness": {
            side: {"engine": rev, "executable": sha256(exe[side])}
            for side, rev in (("before", before_rev), ("after", after_rev))
        },
        "driver": sha256(__file__),
        "cpu": int(cpu),
        "samples_per_workload": SAMPLES,
        "crs_commit": subprocess.check_output(
            ["git", "-C", os.environ["CRS_BENCH_DIR"], "rev-parse", "HEAD"], text=True
        ).strip(),
        "toolchain": subprocess.check_output(["rustc", "-vV"], text=True).strip(),
        "runs": [],
    }
    for round_number, order in enumerate(ORDERS):
        for side in order.split():
            home = out / f"round{round_number}-{side}"
            env = dict(os.environ, CRITERION_HOME=str(home))
            done = subprocess.run(
                ["taskset", "-c", cpu, exe[side], "--bench", "full_crs",
                 "--sample-size", str(SAMPLES), "--noplot"],
                env=env, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
            )
            (home / "output.log").write_text(done.stdout)
            results = {}
            for workload in WORKLOADS:
                new = home / "full_crs" / workload / "new"
                estimate = json.loads((new / "estimates.json").read_text())
                results[workload] = {
                    "mean_us": estimate["mean"]["point_estimate"] / 1000,
                    "raw_sha256": sha256(new / "sample.json"),
                }
                shutil.rmtree(home / "full_crs" / workload / "base", ignore_errors=True)
            run = {"round": round_number, "side": side, "results": results,
                   "exit": done.returncode}
            record["runs"].append(run)
            print(json.dumps(run), flush=True)
    record["median_of_run_means_us"] = {
        side: {
            workload: statistics.median(
                run["results"][workload]["mean_us"]
                for run in record["runs"] if run["side"] == side
            )
            for workload in WORKLOADS
        }
        for side in exe
    }
    (out / "summary.json").write_text(json.dumps(record, indent=2) + "\n")
    print(json.dumps(record["median_of_run_means_us"], indent=2))


if __name__ == "__main__":
    main()
