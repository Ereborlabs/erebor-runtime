#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time

from benchmark_raw_storage import distribution


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--binary", type=Path, default=Path("target/release/examples/raw_owner_bench"))
    args = parser.parse_args()
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    backends = ["production", "table-batch", "table-record"]
    orders = [backends, list(reversed(backends)),
              ["table-batch", "table-record", "production"],
              ["production", "table-record", "table-batch"]]
    sources = [Path("crates/araphor-data/examples/raw_owner_bench.rs"),
               Path("crates/araphor-data/examples/raw_storage/common.rs"),
               Path("crates/araphor-analysis-types/src/source.rs"),
               Path("crates/araphor-data/src/analysis/raw.rs"),
               Path("crates/araphor-data/src/analysis/raw_segments.rs"),
               Path("scripts/benchmark_raw_storage.py"), Path(__file__),
               *sorted(Path("crates/araphor-data/src/analysis/native").rglob("*.rs"))]
    provenance = {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "binary": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
        "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        "engine_commits": {name: subprocess.check_output(["git", "-C", name, "rev-parse", "HEAD"], text=True).strip()
                           for name in ["fjall", "lsm-tree"]},
        "engine_status": {name: subprocess.check_output(["git", "-C", name, "status", "--short"], text=True)
                          for name in ["fjall", "lsm-tree"]},
        "compiler": subprocess.check_output(["rustc", "-Vv"], text=True),
        "host": subprocess.check_output(["uname", "-a"], text=True),
        "filesystem": subprocess.check_output(["df", "-h", str(output)], text=True),
        "dataset_records": [16384, 262144], "batch_records": 256,
        "orders": orders,
        "cache": "fresh process/store per run; OS page cache retained; same-process owner reopen",
        "scope": "isolated native-keyspace batch/record comparison; production is a separate full-owner reference",
        "limits": ["PoC history is append-only saved-cut filtering, not native retained table history",
                   "production retains its existing branch and indexes",
                   "production point reads are unmeasured",
                   "forced maintenance, not sustained natural compaction or power-loss recovery",
                   "CPU and RSS include all scans, points, replay, and integrity checks"],
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    runs = []
    for count in provenance["dataset_records"]:
        for pair, order in enumerate(orders, 1):
            for backend in order:
                stem = f"{count}-pair{pair}-{backend}"
                report = output / f"{stem}.json"
                subprocess.run(["sync", "-f", str(output)], check=True)
                started = time.perf_counter()
                with (output / f"{stem}.log").open("w") as log:
                    subprocess.run(["/usr/bin/time", "-v", "-o", str(output / f"{stem}.time"),
                                    str(binary), backend, str(count), str(report)],
                                   stdout=log, stderr=subprocess.STDOUT, check=True)
                run = json.loads(report.read_text())
                assert run["backend"] == backend and run["records"] == count
                assert all(run["checks"].values())
                assert run["batch_records"] == 256 and run["scan_mode"] == "pages"
                counts = run["statistics"]["logical_counts"]
                if backend.startswith("table-"):
                    assert counts["events"][0] == (count if backend == "table-record" else count // 256)
                    assert counts["source_receipts"][0] == counts["source_epochs"][0] == 1
                    assert all(len(run[phase]["samples_ns"]) == count // 256
                               for phase in ["warm_points", "after_maintenance_points", "reopened_points"])
                else:
                    assert counts["payload"][0] == counts["span"][0] == counts["position"][0] == count // 256
                    assert run["reopened_points"] is None
                run["pair"] = pair
                run["process_wall_s"] = time.perf_counter() - started
                run["process_usage"] = (output / f"{stem}.time").read_text()
                runs.append(run)
                print(f"{stem}: cycle={run['write_records_s']:,.0f}/s "
                      f"p95={run['append']['p95_ms']:.3f}ms "
                      f"space={run['maintained_bytes'][1] / 1048576:.2f}MiB", flush=True)
    summary = []
    for count in provenance["dataset_records"]:
        peers = [run for run in runs if run["records"] == count]
        assert len({run["input_bytes"] for run in peers}) == 1
        for backend in backends:
            selected = [run for run in peers if run["backend"] == backend]
            assert len(selected) == 4
            row = {"records": count, "backend": backend,
                   "cycle_events_s": statistics.median(run["write_records_s"] for run in selected),
                   "allocated_mib": statistics.median(run["maintained_bytes"][1] / 1048576 for run in selected),
                   "logical_file_mib": statistics.median(run["maintained_bytes"][0] / 1048576 for run in selected),
                   "journal_mib": statistics.median(run["statistics"]["journal_bytes"] / 1048576 for run in selected),
                   "process_wall_s": statistics.median(run["process_wall_s"] for run in selected)}
            for field in ["accept", "capture", "progress", "total"]:
                row[field] = distribution([sample[f"{field}_ns"] for run in selected for sample in run["append_samples"]])
            for phase in ["warm_scan", "after_maintenance_scan", "reopened_scan"]:
                row[phase] = {"events_s": statistics.median(count / run[phase]["elapsed_s"] for run in selected),
                              "page": distribution([sample for run in selected for sample in run[phase]["samples_ns"]])}
            for phase in ["warm_points", "after_maintenance_points", "reopened_points"]:
                row[phase] = None if backend == "production" else distribution(
                    [sample for run in selected for sample in run[phase]["samples_ns"]])
            for phase in ["reopen_s", "replay_s", "resume_s", "continue_s"]:
                row[phase] = statistics.median(run[phase] for run in selected)
            row["maintenance"] = {field: statistics.median(run["maintenance"][field] for run in selected)
                                  for field in selected[0]["maintenance"]}
            row["logical_groups"] = {name: [statistics.median(run["statistics"]["logical_counts"][name][index]
                                                              for run in selected) for index in range(3)]
                                     for name in selected[0]["statistics"]["logical_counts"]}
            summary.append(row)
    pairs = []
    for count in provenance["dataset_records"]:
        for pair in range(1, 5):
            selected = {run["backend"]: run for run in runs if run["records"] == count and run["pair"] == pair}
            batch, record = selected["table-batch"], selected["table-record"]
            pairs.append({"records": count, "pair": pair,
                          "record_cycle_rate_over_batch": record["write_records_s"] / batch["write_records_s"],
                          "record_space_over_batch": record["maintained_bytes"][1] / batch["maintained_bytes"][1],
                          "record_reopened_rate_over_batch": batch["reopened_scan"]["elapsed_s"] / record["reopened_scan"]["elapsed_s"],
                          "batch_point_median_over_record": batch["reopened_points"]["read"]["median_ms"] / record["reopened_points"]["read"]["median_ms"]})
    result = {"provenance": provenance, "summary": summary, "paired_ratios": pairs,
              "process_runs": len(runs), "process_wall_s": sum(run["process_wall_s"] for run in runs)}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Completed {len(runs)} process runs; results: {output / 'summary.json'}", flush=True)


if __name__ == "__main__":
    main()
