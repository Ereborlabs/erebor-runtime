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
    parser.add_argument("--compact", action="store_true")
    parser.add_argument("--compression", action="store_true")
    parser.add_argument("--batch-layout", action="store_true")
    parser.add_argument("--experimental-binary", type=Path)
    parser.add_argument("--build-manifest", type=Path)
    args = parser.parse_args()
    if args.batch_layout and (args.compact or args.compression):
        parser.error("--batch-layout is a separate batch-only comparison")
    if args.compression and (not args.experimental_binary or not args.build_manifest):
        parser.error("--compression requires --experimental-binary and --build-manifest")
    binary = args.binary.resolve()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    backends = ["production", "table-batch", "table-record"]
    orders = [backends, list(reversed(backends)),
              ["table-batch", "table-record", "production"],
              ["production", "table-record", "table-batch"]]
    if args.compact:
        backends = ["table-batch", "table-record", "compact-batch", "compact-record"]
        orders = [[backends[index] for index in order] for order in
                  [[0, 1, 3, 2], [1, 2, 0, 3], [2, 3, 1, 0], [3, 0, 2, 1]]]
    if args.compression:
        backends = ["compact-batch", "compact-record", "compact-lz4-batch", "compact-lz4-record"]
        orders = [[backends[index] for index in order] for order in
                  [[0, 1, 3, 2], [1, 2, 0, 3], [2, 3, 1, 0], [3, 0, 2, 1]]]
    if args.batch_layout:
        backends = ["compact-batch", "compact-meta-batch", "compact-frame-batch", "compact-lz4-frame-batch"]
        orders = [[backends[index] for index in order] for order in
                  [[0, 1, 3, 2], [1, 2, 0, 3], [2, 3, 1, 0], [3, 0, 2, 1]]]
    binaries = {name: (args.experimental_binary.resolve() if args.compression and "-lz4-" in name else binary) for name in backends}
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
        "scope": ("matched long/compact keys and batch/record payload granularity" if args.compact else
                  "isolated native-keyspace batch/record comparison; production is a separate full-owner reference"),
        "limits": ["PoC history is append-only saved-cut filtering, not native retained table history",
                   "production retains its existing branch and indexes",
                   "production point reads are unmeasured",
                   "forced maintenance, not sustained natural compaction or power-loss recovery",
                   "CPU and RSS include all scans, points, replay, and integrity checks"],
    }
    if args.compression:
        manifest = json.loads(args.build_manifest.read_text())
        assert hashlib.sha256(binary.read_bytes()).hexdigest() == manifest["default"]["binary_sha256"]
        assert hashlib.sha256(args.experimental_binary.read_bytes()).hexdigest() == manifest["experimental"]["binary_sha256"]
        provenance["build_manifest"] = manifest
        provenance["scope"] = "compact batch/record; default versus combined all-level SST/index LZ4 and WAL threshold1; post-consumption journal collection"
    if args.batch_layout:
        provenance["scope"] = "batch-only compact baseline versus packed metadata, production frame codec, and native SST/index compression; default WAL settings; same post-consumption collection"
        assert not any(provenance["engine_status"].values()), "engine forks must remain clean"
    provenance["binaries"] = {name: {"path": str(path), "sha256": hashlib.sha256(path.read_bytes()).hexdigest()} for name, path in binaries.items()}
    if args.compact or args.compression or args.batch_layout:
        provenance["limits"] = [item for item in provenance["limits"] if not item.startswith("production")]
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
                                    str(binaries[backend]), backend, str(count), str(report), *( ["pages", "gc"] if args.compression or args.batch_layout else [])],
                                   stdout=log, stderr=subprocess.STDOUT, check=True)
                run = json.loads(report.read_text())
                assert run["backend"] == backend and run["records"] == count
                assert all(run["checks"].values())
                assert run["batch_records"] == 256 and run["scan_mode"] == "pages"
                counts = run["statistics"]["logical_counts"]
                if backend != "production":
                    assert counts["events"][0] == (count if backend.endswith("-record") else count // 256)
                    width = 16 if backend.startswith("compact-") else 81
                    assert counts["events"][1] == width * counts["events"][0]
                    mappings = 1 if backend.startswith("compact-") else 0
                    assert counts["sources"][0] == counts["source_ids"][0] == mappings
                    assert counts["source_receipts"][0] == counts["source_epochs"][0] == 1
                    if args.batch_layout:
                        simplified = backend != "compact-batch"
                        assert counts["source_receipts"][1] == (8 if simplified else 73)
                        assert counts["benchmark_state"][0] == (1 if simplified else 6)
                    assert all(len(run[phase]["samples_ns"]) == count // 256
                               for phase in ["warm_points", "after_maintenance_points", "reopened_points"])
                else:
                    assert counts["payload"][0] == counts["span"][0] == counts["position"][0] == count // 256
                    assert run["reopened_points"] is None
                if args.compression or args.batch_layout:
                    gc = run["post_gc"]
                    assert all(gc["checks"].values()) and gc["records"] == count + 512
                    assert gc["journals_after"][0] < gc["journals_before"][0]
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
        if args.compact or args.compression:
            for granularity in ["batch", "record"]:
                assert len({run["statistics"]["logical_counts"]["events"][2] for run in peers
                            if run["backend"].endswith(granularity)}) == 1
        for backend in backends:
            selected = [run for run in peers if run["backend"] == backend]
            assert len(selected) == 4
            row = {"records": count, "backend": backend,
                   "intake_events_s": statistics.median(count / (sum(sample["accept_ns"] for sample in run["append_samples"]) / 1e9) for run in selected),
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
            if args.compression or args.batch_layout:
                row["post_gc"] = {
                    "records": count + 512,
                    "allocated_mib": statistics.median(run["post_gc"]["after_bytes"][1] / 1048576 for run in selected),
                    "before_allocated_mib": statistics.median(run["post_gc"]["before_bytes"][1] / 1048576 for run in selected),
                    "journal_allocated_mib": statistics.median(run["post_gc"]["journals_after"][2] / 1048576 for run in selected),
                    "before_journal_allocated_mib": statistics.median(run["post_gc"]["journals_before"][2] / 1048576 for run in selected),
                    "journal_files_removed": [run["post_gc"]["journals_before"][0] - run["post_gc"]["journals_after"][0] for run in selected],
                    "reopen_s": statistics.median(run["post_gc"]["reopen_s"] for run in selected),
                    "scan_events_s": statistics.median((count+512) / run["post_gc"]["scan"]["elapsed_s"] for run in selected),
                    "points": distribution([value for run in selected for value in run["post_gc"]["points"]["samples_ns"]]),
                }
            row["logical_groups"] = {name: [statistics.median(run["statistics"]["logical_counts"][name][index]
                                                              for run in selected) for index in range(3)]
                                     for name in selected[0]["statistics"]["logical_counts"]}
            if args.batch_layout:
                row["journal_logical_groups"] = {
                    name: [statistics.median(run["statistics"]["journal_logical_counts"][name][index]
                                             for run in selected) for index in range(3)]
                    for name in selected[0]["statistics"]["journal_logical_counts"]}
            summary.append(row)
    pairs = []
    for count in provenance["dataset_records"]:
        for pair in range(1, 5):
            selected = {run["backend"]: run for run in runs if run["records"] == count and run["pair"] == pair}
            if args.batch_layout:
                for before, after in zip(backends, backends[1:]):
                    a, b = selected[before], selected[after]
                    intake = lambda run: count / (sum(sample["accept_ns"] for sample in run["append_samples"]) / 1e9)
                    pairs.append({"records": count, "pair": pair, "before": before, "after": after,
                                  "intake_rate_ratio": intake(b) / intake(a),
                                  "cycle_rate_ratio": b["write_records_s"] / a["write_records_s"],
                                  "post_gc_space_ratio": b["post_gc"]["after_bytes"][1] / a["post_gc"]["after_bytes"][1],
                                  "reopened_read_ratio": a["reopened_scan"]["elapsed_s"] / b["reopened_scan"]["elapsed_s"]})
                continue
            batch, record = (selected["compact-batch"], selected["compact-record"]) if args.compression else (selected["table-batch"], selected["table-record"])
            pairs.append({"records": count, "pair": pair,
                          "record_cycle_rate_over_batch": record["write_records_s"] / batch["write_records_s"],
                          "record_space_over_batch": record["maintained_bytes"][1] / batch["maintained_bytes"][1],
                          "record_reopened_rate_over_batch": batch["reopened_scan"]["elapsed_s"] / record["reopened_scan"]["elapsed_s"],
                          "batch_point_median_over_record": batch["reopened_points"]["read"]["median_ms"] / record["reopened_points"]["read"]["median_ms"]})
    if args.compact and not args.compression:
        for row in pairs:
            selected = {run["backend"]: run for run in runs if run["records"] == row["records"] and run["pair"] == row["pair"]}
            compact_batch, compact_record = selected["compact-batch"], selected["compact-record"]
            row.update({
                "compact_record_cycle_rate_over_batch": compact_record["write_records_s"] / compact_batch["write_records_s"],
                "compact_record_rate_over_long_record": compact_record["write_records_s"] / selected["table-record"]["write_records_s"],
                "compact_batch_rate_over_long_batch": compact_batch["write_records_s"] / selected["table-batch"]["write_records_s"],
                "compact_record_space_over_batch": compact_record["maintained_bytes"][1] / compact_batch["maintained_bytes"][1],
                "compact_batch_point_median_over_record": compact_batch["reopened_points"]["read"]["median_ms"] / compact_record["reopened_points"]["read"]["median_ms"],
            })
    if args.compression:
        for row in pairs:
            selected = {run["backend"]: run for run in runs if run["records"] == row["records"] and run["pair"] == row["pair"]}
            cb, cr = selected["compact-lz4-batch"], selected["compact-lz4-record"]
            row.update({"compressed_record_cycle_over_batch": cr["write_records_s"] / cb["write_records_s"],
                        "compressed_record_post_gc_space_over_batch": cr["post_gc"]["after_bytes"][1] / cb["post_gc"]["after_bytes"][1]})
    result = {"provenance": provenance, "summary": summary, "paired_ratios": pairs,
              "process_runs": len(runs), "process_wall_s": sum(run["process_wall_s"] for run in runs)}
    (output / "summary.json").write_text(json.dumps(result, indent=2) + "\n")
    print(f"Completed {len(runs)} process runs; results: {output / 'summary.json'}", flush=True)


if __name__ == "__main__":
    main()
