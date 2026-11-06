"""Summarize the storage PoC's recorded samples. Times use milliseconds."""

import json
import math
import statistics
import sys


def stats(values):
    values = sorted(values)
    return {
        "n": len(values),
        "min": values[0],
        "median": statistics.median(values),
        "p95_nearest_rank": values[math.ceil(len(values) * 0.95) - 1],
        "max": values[-1],
    }


def summarize(report):
    result = {
        "source": report["source"],
        "profile": report["profile"],
        "time_unit": "ms",
        "percentile_limit": "Descriptive samples; six rounds do not establish a tail bound.",
        "engines": {},
        "paired_round_ratios": {},
    }
    for engine in ("duckdb", "redb", "fjall"):
        runs = [r for r in report["runs"] if r["engine"] == engine]
        samples = [s for s in report["samples"] if s["engine"] == engine]
        entry = {
            name.removesuffix("_s") + "_ms": stats([r[name] * 1000 for r in runs])
            for name in (
                "write_s", "warm_read_s", "open_s", "reopen_s",
                "historical_read_s", "reopened_read_s",
            )
        }
        if "scenario_s" in runs[0]:
            entry["scenario_ms"] = stats([r["scenario_s"] * 1000 for r in runs])
            for name in ("capture_s", "index_s", "resolve_s", "detect_s", "normalize_s"):
                entry[name.removesuffix("_s") + "_ms"] = stats([
                    sum(sample[name] for sample in samples
                        if sample["round"] == run["round"]) * 1000
                    for run in runs
                ])
            for name, operation in (("traversal_ms", "neighbors"), ("presence_ms", "presence")):
                entry[name] = stats([
                    sum(call["elapsed_s"] for sample in samples
                        if sample["round"] == run["round"]
                        for call in sample["calls"] if call["operation"] == operation) * 1000
                    for run in runs
                ])
        for name in ("file_bytes", "allocated_bytes", "files"):
            entry[name] = stats([r[name] for r in runs])
        entry["per_commit_ms"] = {
            name.removesuffix("_s"): stats([s["write"][name] * 1000 for s in samples])
            for name in ("prepare_s", "work_s", "commit_s", "total_s")
        }
        if "scenario_s" in samples[0]:
            entry["by_revision_ms"] = {
                revision: {
                    **{
                        name.removesuffix("_s"): stats([
                            sample[name] * 1000 for sample in samples
                            if sample["write"]["revision"] == revision
                        ])
                        for name in ("scenario_s", "capture_s", "index_s", "resolve_s",
                                     "detect_s", "normalize_s", "verification_read_s")
                    },
                    "write": stats([
                        sample["write"]["total_s"] * 1000 for sample in samples
                        if sample["write"]["revision"] == revision
                    ]),
                    "traversal": stats([
                        sum(call["elapsed_s"] for call in sample["calls"]
                            if call["operation"] == "neighbors") * 1000
                        for sample in samples if sample["write"]["revision"] == revision
                    ]),
                }
                for revision in sorted({sample["write"]["revision"] for sample in samples})
            }
        else:
            entry["by_revision_ms"] = {
                revision: {
                    "write": stats([
                        s["write"]["total_s"] * 1000 for s in samples
                        if s["write"]["revision"] == revision
                    ]),
                    "output_capture": stats([
                        s["output_capture_s"] * 1000 for s in samples
                        if s["write"]["revision"] == revision
                    ]),
                    "output_rows": stats([
                        s["output_read_s"] * 1000 for s in samples
                        if s["write"]["revision"] == revision
                    ]),
                    "output_cdc": stats([
                        s["output_cdc_s"] * 1000 for s in samples
                        if s["write"]["revision"] == revision
                    ]),
                }
                for revision in sorted({s["write"]["revision"] for s in samples})
            }
        result["engines"][engine] = entry
    runs = {(r["round"], r["engine"]): r for r in report["runs"]}
    for faster, slower in (("redb", "duckdb"), ("fjall", "duckdb"), ("fjall", "redb")):
        result["paired_round_ratios"][slower + "_over_" + faster] = {
            name.removesuffix("_s"): stats([
                runs[round_, slower][name] / runs[round_, faster][name]
                for round_ in range(report["rounds"])
            ])
            for name in (("scenario_s", "write_s", "warm_read_s")
                         if "scenario_s" in report["runs"][0] else ("write_s", "warm_read_s"))
        }
    return result


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as source:
        print(json.dumps(summarize(json.load(source)), indent=2))
