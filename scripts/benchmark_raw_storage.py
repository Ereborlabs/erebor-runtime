#!/usr/bin/env python3
import argparse
import hashlib
import json
from pathlib import Path
import statistics
import subprocess
import time


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--binary", type=Path)
    parser.add_argument("--owner", action="store_true")
    parser.add_argument("--owner-backend", choices=["production", "hybrid"], default="production")
    args = parser.parse_args()
    example = "raw_owner_bench" if args.owner else "raw_storage_bench"
    binary = (args.binary or Path("target/release/examples") / example).resolve()
    baseline = args.owner_backend if args.owner else "segments"
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    provenance = {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "binary": str(binary),
        "binary_sha256": hashlib.sha256(binary.read_bytes()).hexdigest(),
        "source_sha256": {
            str(path): hashlib.sha256(path.read_bytes()).hexdigest()
            for path in [Path("crates/araphor-data/src/analysis/raw_benchmark.rs"),
                         Path("crates/araphor-data/examples/raw_storage_bench.rs"),
                         Path("crates/araphor-data/examples/raw_storage/common.rs"),
                         *([Path("crates/araphor-data/examples/raw_owner_bench.rs"),
                            Path("crates/araphor-data/src/analysis/native/benchmark.rs"),
                            Path("crates/araphor-data/src/analysis/native/benchmark/candidate.rs"),
                            Path("crates/araphor-data/src/analysis/native/mod.rs"),
                            Path("crates/araphor-data/src/analysis/native/source/raw.rs"),
                            Path("crates/araphor-data/src/analysis/raw.rs"),
                            Path("crates/araphor-data/src/analysis/raw_segments.rs"),
                            Path("crates/araphor-data/Cargo.toml")]
                           if args.owner else []), Path(__file__)]
        },
        "engine_commits": {
            name: subprocess.check_output(["git", "-C", name, "rev-parse", "HEAD"], text=True).strip()
            for name in ["fjall", "lsm-tree"]
        },
        "cache": "OS page cache retained; fresh store and process per run; setup filesystem sync outside append timing",
        "maintenance": "explicit flush and major compaction; not a steady natural compaction test",
        "dataset_records": [16384, 262144], "batch_records": 256,
        "orders_per_dataset": [[baseline, "fjall"], ["fjall", baseline],
                               [baseline, "fjall"], ["fjall", baseline]],
        "comparison": f"{baseline} owner versus all-Fjall candidate" if args.owner else "raw segment versus Fjall pilot",
    }
    (output / "provenance.json").write_text(json.dumps(provenance, indent=2) + "\n")
    runs = []
    for count in provenance["dataset_records"]:
        for pair, order in enumerate(provenance["orders_per_dataset"], 1):
            for backend in order:
                stem = f"{count}-pair{pair}-{backend}"
                report = output / f"{stem}.json"
                subprocess.run(["sync", "-f", str(output)], check=True)
                started = time.time()
                with (output / f"{stem}.log").open("w") as log:
                    command = ["/usr/bin/time", "-v", "-o", str(output / f"{stem}.time"),
                               str(binary), backend, str(count), str(report)]
                    result = subprocess.run(command, stdout=log, stderr=subprocess.STDOUT)
                if result.returncode:
                    raise RuntimeError(f"{stem} failed ({result.returncode}); see {stem}.log")
                run = json.loads(report.read_text())
                assert run["backend"] == backend and run["records"] == count
                assert all(run["checks"].values())
                run["pair"] = pair
                run["process_wall_s"] = time.time() - started
                run["process_usage"] = (output / f"{stem}.time").read_text()
                runs.append(run)
                print(f"{stem}: write={run['write_records_s']:.1f} records/s "
                      f"append_p95={run['append']['p95_ms']:.3f} ms "
                      f"reopen={run['reopen_s'] * 1000:.3f} ms", flush=True)
    summary = []
    for count in provenance["dataset_records"]:
        peers = [run for run in runs if run["records"] == count]
        assert len({run["input_bytes"] for run in peers}) == 1
        for backend in [baseline, "fjall"]:
            selected = [run for run in peers if run["backend"] == backend]
            totals = [sample["total_ns"] for run in selected for sample in run["append_samples"]]
            commit_key = "progress_ns" if args.owner else "commit_ns"
            commits = [sample[commit_key] for run in selected for sample in run["append_samples"]]
            row = {"records": count, "backend": backend, "runs": len(selected),
                   "input_bytes": selected[0]["input_bytes"],
                   "append": distribution(totals), "commit": distribution(commits),
                   "write_records_s_median": statistics.median(run["write_records_s"] for run in selected),
                   "reopened_read_records_s_median": statistics.median(
                       count / run["reopened_scan"]["elapsed_s"] for run in selected),
                   "reopen_ms_median": statistics.median(run["reopen_s"] * 1000 for run in selected),
                   "allocated_mib_median": statistics.median(run["maintained_bytes"][1] / 1048576 for run in selected),
                   "replay_ms_median": statistics.median(run["replay_s"] * 1000 for run in selected),
                   "maintenance": [run["maintenance"] for run in selected]}
            if args.owner:
                for stage in ["accept", "capture", "progress"]:
                    row[stage] = distribution([sample[f"{stage}_ns"] for run in selected
                                               for sample in run["append_samples"]])
                row["resume_ms_median"] = statistics.median(run["resume_s"] * 1000 for run in selected)
            else:
                row["point_read"] = distribution([sample for run in selected
                                                  for sample in run["reopened_points"]["samples_ns"]])
            summary.append(row)
    ratios = []
    for count in provenance["dataset_records"]:
        for pair in range(1, 5):
            selected = {run["backend"]: run for run in runs if run["records"] == count and run["pair"] == pair}
            segment, fjall = selected[baseline], selected["fjall"]
            ratios.append({"records": count, "pair": pair,
                           f"fjall_write_rate_over_{baseline}": fjall["write_records_s"] / segment["write_records_s"],
                           f"{baseline}_append_p95_over_fjall": segment["append"]["p95_ms"] / fjall["append"]["p95_ms"],
                           f"{baseline}_reopen_over_fjall": segment["reopen_s"] / fjall["reopen_s"]})
    (output / "summary.json").write_text(json.dumps({"summary": summary, "paired_ratios": ratios}, indent=2) + "\n")
    lines = ["# Raw storage benchmark", "", "All 16 process runs passed byte, position, retained-cut, reopen, and log-resume checks.", "",
             "| Records | Backend | Write records/s | Cycle median ms | Cycle p95 ms | Cycle p99 ms | Cycle max ms | Reopened read records/s | Reopen ms | Allocated MiB |",
             "| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    for row in summary:
        latency = row["append"]
        lines.append(f"| {row['records']:,} | {row['backend']} | {row['write_records_s_median']:,.0f} | "
                     f"{latency['median_ms']:.3f} | {latency['p95_ms']:.3f} | {latency['p99_ms']:.3f} | {latency['max_ms']:.3f} | "
                     f"{row['reopened_read_records_s_median']:,.0f} | "
                     f"{row['reopen_ms_median']:.3f} | {row['allocated_mib_median']:.2f} |")
    lines.extend(["", "Cycle latency is per durable 256-record batch. Percentiles pool samples by dataset/backend; throughput is the median of four process rates.",
                  "Read throughput includes exact-byte verification.",
                  "OS page cache was not dropped. Reopen uses a new engine cache in the same process.",
                  "Maintenance is forced flush/major compaction.",
                  "This is not a complete Data owner, notification benchmark, crash test, or retention-parity qualification.", ""])
    if args.owner:
        lines.extend(["Both backends acknowledge event acceptance before the later durable result/reference/progress transaction.",
                      "Hybrid calls production NativeStore and DataWrite; the second transaction includes stage_raw anchors.",
                      "The all-Fjall candidate has no segment files, segment references, RawEntry records, or RAM range index.",
                      "Saved consumer positions and source/cursor references are read from committed result records after reopen.",
                      "Hybrid uses production history and journal collection at checkpoint. Its original event log remains in raw segments.",
                      "The candidate retains all native history and original event WAL for the probes.",
                      "Point-read latency and Arrow conversion are not measured.",
                      "The result/progress record belongs to this benchmark. Production managed-result and witness-pin semantics are not qualified.", "",
                      "| Records | Backend | Accept median ms | Accept p95 ms | Result/reference/progress median ms | Result/reference/progress p95 ms |",
                      "| ---: | --- | ---: | ---: | ---: | ---: |"])
        for row in summary:
            lines.append(f"| {row['records']:,} | {row['backend']} | {row['accept']['median_ms']:.3f} | "
                         f"{row['accept']['p95_ms']:.3f} | {row['progress']['median_ms']:.3f} | {row['progress']['p95_ms']:.3f} |")
        lines.append("")
    else:
        lines.extend(["Native history and original journals remain retained for the probes.",
                      "Segments validate all retained payloads at open; the Fjall candidate restores index metadata and validates payloads on reads.",
                      "The Fjall candidate prepares an unused segment identity header; prepare and commit samples are recorded separately.", ""])
    (output / "README.md").write_text("\n".join(lines))
    print(output / "README.md", flush=True)


def distribution(samples):
    values = sorted(samples)
    return {"count": len(values), "median_ms": values[len(values) // 2] / 1e6,
            "p95_ms": values[len(values) * 95 // 100] / 1e6,
            "p99_ms": values[len(values) * 99 // 100] / 1e6,
            "max_ms": values[-1] / 1e6}


if __name__ == "__main__":
    main()
