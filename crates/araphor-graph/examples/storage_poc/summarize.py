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
        "percentile_limit": f"Descriptive samples; {report['rounds']} rounds do not establish a tail bound.",
        "engines": {},
        "paired_round_ratios": {},
    }
    engines = list(dict.fromkeys(run["engine"] for run in report["runs"]))
    for engine in engines:
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
        historical = [sample for sample in report.get("history", []) if sample["engine"] == engine]
        if historical:
            entry["history"] = {}
            for stage in sorted({sample["stage"] for sample in historical}):
                selected = [sample for sample in historical if sample["stage"] == stage]
                metrics = ("elapsed_s", "capture_s", "index_s", "resolve_s", "detect_s", "normalize_s")
                totals = {
                    name.removesuffix("_s") + "_ms": stats([
                        sum(sample[name] for sample in selected if sample["round"] == run["round"]) * 1000
                        for run in runs
                    ]) for name in metrics
                }
                totals["traversal_ms"] = stats([
                    sum(call["elapsed_s"] for sample in selected if sample["round"] == run["round"]
                        for call in sample["calls"] if call["operation"] == "neighbors") * 1000
                    for run in runs
                ])
                totals["evaluations_per_round"] = len(selected) // len(runs)
                totals["by_cut_ms"] = {
                    str(revision): {
                        direction: stats([sample["elapsed_s"] * 1000 for sample in selected
                            if sample["captured"] == revision and sample["direction"] == direction])
                        for direction in ("backward", "forward")
                    } for revision in sorted({sample["captured"] for sample in selected})
                }
                entry["history"][stage] = totals
        result["engines"][engine] = entry
    runs = {(r["round"], r["engine"]): r for r in report["runs"]}
    pairs = [("redb", "duckdb"), ("fjall", "duckdb"), ("fjall", "redb")]
    pairs = [(a, b) for a, b in pairs if a in engines and b in engines]
    if "home" in engines:
        pairs.extend(("home", engine) for engine in engines if engine != "home")
    for candidate in ("surrealkv", "surrealkv-native", "neon-layers"):
        if candidate in engines:
            pairs.extend((candidate, engine) for engine in engines if engine != candidate)
    pairs = list(dict.fromkeys(pairs))
    for faster, slower in pairs:
        result["paired_round_ratios"][slower + "_over_" + faster] = {
            name.removesuffix("_s"): stats([
                runs[round_, slower][name] / runs[round_, faster][name]
                for round_ in range(report["rounds"])
            ])
            for name in (("scenario_s", "write_s", "warm_read_s")
                         if "scenario_s" in report["runs"][0] else ("write_s", "warm_read_s"))
        }
        if report.get("history"):
            result["paired_round_ratios"][slower + "_over_" + faster]["history"] = {
                stage: stats([
                    sum(sample["elapsed_s"] for sample in report["history"]
                        if sample["round"] == round_ and sample["engine"] == slower and sample["stage"] == stage)
                    / sum(sample["elapsed_s"] for sample in report["history"]
                        if sample["round"] == round_ and sample["engine"] == faster and sample["stage"] == stage)
                    for round_ in range(report["rounds"])
                ]) for stage in sorted({sample["stage"] for sample in report["history"]})
            }
    return result


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as source:
        print(json.dumps(summarize(json.load(source)), indent=2))
