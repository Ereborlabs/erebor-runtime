#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess

from benchmark_raw_storage import distribution


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("before", type=Path)
    parser.add_argument("after", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--scan-modes", nargs=2, choices=["pages", "stream"], default=["pages", "pages"])
    args = parser.parse_args()
    binaries = {label: getattr(args, label).resolve() for label in ["before", "after"]}
    modes = dict(zip(binaries, args.scan_modes))
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    provenance = {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "binaries": {label: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()}
                     for label, path in binaries.items()},
        "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in [
            Path("crates/araphor-data/src/analysis/native/benchmark/candidate.rs"),
            Path("crates/araphor-data/src/analysis/native/benchmark.rs"),
            Path("crates/araphor-data/examples/raw_owner_bench.rs"),
            Path("crates/araphor-data/examples/raw_storage/common.rs"),
            Path("scripts/benchmark_raw_storage.py"), Path(__file__)]},
        "engine_commits": {name: subprocess.check_output(["git", "-C", name, "rev-parse", "HEAD"], text=True).strip()
                           for name in ["fjall", "lsm-tree"]},
        "records": [16384, 262144], "batch_records": 256,
        "orders": [["before", "after"], ["after", "before"], ["before", "after"], ["after", "before"]],
        "cache": "fresh store/process per run; OS cache retained; new engine cache on reopen",
        "scan_modes": modes,
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    runs = []
    for count in provenance["records"]:
        for pair, order in enumerate(provenance["orders"], 1):
            for label in order:
                stem = f"{count}-pair{pair}-{label}"
                report = output / f"{stem}.json"
                subprocess.run(["sync", "-f", str(output)], check=True)
                with (output / f"{stem}.log").open("w") as log:
                    command = ["/usr/bin/time", "-v", "-o", str(output / f"{stem}.time"),
                               str(binaries[label]), "fjall", str(count), str(report)]
                    if modes[label] != "pages": command.append(modes[label])
                    subprocess.run(command,
                                   stdout=log, stderr=subprocess.STDOUT, check=True)
                run = json.loads(report.read_text())
                assert run["backend"] == "fjall" and run["records"] == count
                assert run.get("scan_mode", "pages") == modes[label]
                assert all(run["checks"].values())
                run.update({"variant": label, "pair": pair})
                runs.append(run)
                print(f"{stem}: reopened={count / run['reopened_scan']['elapsed_s']:,.0f} events/s", flush=True)
    summary = []
    for count in provenance["records"]:
        peers = [run for run in runs if run["records"] == count]
        assert len({run["input_bytes"] for run in peers}) == 1
        for label in binaries:
            selected = [run for run in peers if run["variant"] == label]
            row = {"records": count, "variant": label,
                   "write_events_s": statistics.median(run["write_records_s"] for run in selected),
                   "cycle": distribution([sample["total_ns"] for run in selected for sample in run["append_samples"]])}
            for phase in ["warm_scan", "after_maintenance_scan", "reopened_scan"]:
                row[phase] = {"events_s": statistics.median(count / run[phase]["elapsed_s"] for run in selected),
                              "page": distribution([sample for run in selected for sample in run[phase]["samples_ns"]])}
            summary.append(row)
    pairs = []
    for count in provenance["records"]:
        for pair in range(1, 5):
            selected = {run["variant"]: run for run in runs if run["records"] == count and run["pair"] == pair}
            pairs.append({"records": count, "pair": pair, **{
                phase: selected["before"][phase]["elapsed_s"] / selected["after"][phase]["elapsed_s"]
                for phase in ["warm_scan", "after_maintenance_scan", "reopened_scan"]}})
    (output / "summary.json").write_text(json.dumps({"summary": summary, "paired_speedups": pairs}, indent=2) + "\n")
    print(json.dumps(summary, indent=2), flush=True)


if __name__ == "__main__":
    main()
