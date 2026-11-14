#!/usr/bin/env python3
import argparse
import hashlib
import itertools
import json
from pathlib import Path
import statistics
import subprocess
import time


def distribution(values):
    values = sorted(values)
    return {"count": len(values), "min_ms": values[0]/1e6, "median_ms": statistics.median(values)/1e6,
            "p95_ms": values[len(values)*95//100]/1e6, "max_ms": values[-1]/1e6}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("output", type=Path)
    parser.add_argument("--binary", type=Path, default=Path("target/release/examples/table_storage_bench"))
    parser.add_argument("--sender", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    binary = args.binary.resolve()
    orders = list(itertools.permutations(["frames", "packed", "columns"]))
    conditions = ["frames", "packed", "columns"]
    if args.sender:
        conditions = ["production", "receiver-packed", "sender-packed", "receiver-columns", "sender-columns"]
        orders = [conditions[index:]+conditions[:index] for index in range(len(conditions))]
    sources = [Path("Cargo.lock"), Path("crates/araphor-data/Cargo.toml"),
               Path("crates/araphor-data/src/analysis/native/benchmark.rs"),
               Path("crates/araphor-data/src/analysis/raw.rs"),
               Path("crates/araphor-data/src/analysis/raw_segments.rs"),
               Path("crates/araphor-data/src/evidence.rs"),
               Path("crates/araphor-data/src/analysis/native/benchmark/columnar.rs"),
               *sorted(Path("crates/araphor-data/src/analysis/native/benchmark/columnar").glob("*.rs")),
               Path("crates/araphor-data/examples/table_storage_bench.rs"),
               Path("crates/araphor-data/examples/raw_storage/common.rs"),
               *sorted(Path("crates/araphor-data/examples/table_storage").glob("*.rs")), Path(__file__)]
    provenance = {
        "commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "binary": {"path": str(binary), "sha256": hashlib.sha256(binary.read_bytes()).hexdigest()},
        "source_sha256": {str(path): hashlib.sha256(path.read_bytes()).hexdigest() for path in sources},
        "engines": {name: {"commit": subprocess.check_output(["git", "-C", name, "rev-parse", "HEAD"], text=True).strip(),
                           "status": subprocess.check_output(["git", "-C", name, "status", "--short"], text=True)} for name in ["fjall", "lsm-tree"]},
        "compiler": subprocess.check_output(["rustc", "-Vv"], text=True),
        "host": subprocess.check_output(["uname", "-a"], text=True),
        "filesystem": subprocess.check_output(["df", "-h", str(output)], text=True),
        "orders": orders, "records": [16384, 262144], "batch_records": 256,
        "sender": args.sender,
        "cache": "fresh process and store; OS caches retained; query order full/raw/projected/cpu/residual/late_raw; owner reopen is not cold IO",
        "limits": ["benchmark-only table protocol; no production intake/Graph/packages/notification qualification",
                   "read counters are requested KV value bytes, not block/device IO",
                   "held snapshot and original WAL continuation, not durable historical table queries",
                   "forced flush/compaction, not sustained compaction or power failure",
                   "RawCommit uses fixed legacy revision field 1 only as a payload codec; all progress uses native input Cursor"],
    }
    if args.sender:
        provenance["transport"] = "same standard MessagePack envelope in all cases; native records and original frames constructed inside sender clock; Arrow sender uses native fields directly"
        provenance["cursor_change"] = "four contiguous per-source cursor streams; original global task_cookie and original frame bytes unchanged; older global cursor metadata is not reused"
        provenance["limits"] += ["authoritative sender Arrow; no independent receiver equivalence check against preserved protobuf fields",
                                 "production NativeStore admission/extraction plus benchmark SQL provider, not complete production Query/package qualification",
                                 "no sockets, network transit, authentication or kernel capture in the benchmark"]
    assert not any(engine["status"] for engine in provenance["engines"].values())
    (output/"provenance.json").write_text(json.dumps(provenance, indent=2)+"\n")
    runs = []
    for count in provenance["records"]:
        for pair, order in enumerate(orders, 1):
            for layout in order:
                stem = f"{count}-pair{pair}-{layout}"
                report = output/f"{stem}.json"
                started = time.perf_counter()
                with (output/f"{stem}.log").open("w") as log:
                    subprocess.run(["/usr/bin/time", "-v", "-o", str(output/f"{stem}.time"), str(binary), layout, str(count), str(report)], stdout=log, stderr=subprocess.STDOUT, check=True)
                run = json.loads(report.read_text())
                assert run["layout"] == layout and run["records"] == count and run["batch_records"] == 256
                assert all(run["checks"].values())
                for stage in ["warm", "after_flush", "reopened"]:
                    assert run[stage]["full"]["rows"] == count
                    assert run[stage]["projected"]["rows"] == count
                    assert run[stage]["cpu"]["rows"] == count//4
                    if layout.endswith("columns"):
                        assert run[stage]["projected"]["reads"]["ipc_columns"] == count//256*2
                        assert run[stage]["cpu"]["reads"]["ipc_columns"] == count//256//4*2
                    elif layout.endswith("packed"):
                        assert run[stage]["projected"]["reads"]["ipc_columns"] == count//256*2
                run["pair"] = pair
                run["process_wall_s"] = time.perf_counter()-started
                runs.append(run)
                print(f"{stem}: cycle={run['cycle_events_s']:,.0f}/s space={run['maintained_bytes'][1]/1048576:.3f}MiB", flush=True)
    summary = []
    for count in provenance["records"]:
        assert len({run["input_bytes"] for run in runs if run["records"] == count}) == 1
        for layout in conditions:
            selected = [run for run in runs if run["records"] == count and run["layout"] == layout]
            row = {"records": count, "layout": layout,
                   "intake_events_s": statistics.median(count/(sum(sample["accept_ns"] for sample in run["samples"])/1e9) for run in selected),
                   "cycle_events_s": statistics.median(run["cycle_events_s"] for run in selected),
                   "allocated_mib": statistics.median(run["maintained_bytes"][1]/1048576 for run in selected),
                   "logical_file_mib": statistics.median(run["maintained_bytes"][0]/1048576 for run in selected),
                   "statistics": selected[0]["statistics"]}
            if args.sender:
                row["sender_events_s"] = statistics.median(count/(sum(sample["sender_ns"] for sample in run["samples"])/1e9) for run in selected)
                row["receiver_events_s"] = statistics.median(count/(sum(sample["receiver_ns"] for sample in run["samples"])/1e9) for run in selected)
                row["wire_bytes"] = selected[0]["samples"] and sum(sample["wire_bytes"] for sample in selected[0]["samples"])
                assert len({sum(sample["wire_bytes"] for sample in run["samples"]) for run in selected}) == 1
            for field in ["accept", "read", "progress", "total", *(["sender", "receiver"] if args.sender else [])]:
                row[field] = distribution([sample[f"{field}_ns"] for run in selected for sample in run["samples"]])
            for stage in ["warm", "after_flush", "reopened"]:
                row[stage] = {}
                for name in selected[0][stage]:
                    measurements = [run[stage][name] for run in selected]
                    assert len({json.dumps(item["reads"], sort_keys=True) for item in measurements}) == 1
                    assert len({item["rows"] for item in measurements}) == 1
                    row[stage][name] = {"time": distribution([int(item["elapsed_s"]*1e9) for item in measurements]),
                                        "rows": measurements[0]["rows"], "reads": measurements[0]["reads"]}
            summary.append(row)
    (output/"summary.json").write_text(json.dumps({"provenance": provenance, "summary": summary, "runs": runs}, indent=2)+"\n")


if __name__ == "__main__":
    main()
