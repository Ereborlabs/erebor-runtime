#!/usr/bin/env python3
"""Compare unchanged Graph workloads before and after an adapter change."""
import json
import statistics
import sys

from summarize_stable import summarize


def compare(before, after):
    for report in [before, after]:
        assert report["profile"] == "release"
        summarize(report)

    def calls(sample):
        return [tuple(c[k] for k in ["writer", "operation", "relation", "key_count", "rows"])
                for c in sample["calls"]]

    def shape(report):
        return {(r["engine"], r["round"]): (
            [(s["write"]["revision"], s["write"]["added"], s["write"]["closed"],
              s["write"]["encoded_bytes"], s["frontier_records"], calls(s)) for s in r["samples"]],
            [(s["stage"], s["direction"], s["revision"], s["captured"],
              s["frontier_records"], calls(s)) for s in r["history"]]) for r in report["runs"]}

    assert shape(before) == shape(after)

    def totals(run):
        rows = run["samples"]
        return {
            "complete": sum(s["scenario_s"] for s in rows)*1000,
            "graph_reads": sum(c["elapsed_s"] for s in rows for c in s["calls"])*1000,
            "write_work": sum(s["write"]["work_s"] for s in rows)*1000,
            "write_commit": sum(s["write"]["commit_s"] for s in rows)*1000,
            "write_total": sum(s["write"]["total_s"] for s in rows)*1000,
        }

    def measurements(report):
        result = {}
        summary = summarize(report)
        for engine in ["fjall", "fjall-stable", "neon-layers", "neon-stable"]:
            runs = sorted((r for r in report["runs"] if r["engine"] == engine), key=lambda r: r["round"])
            values = [totals(r) for r in runs]
            result[engine] = {
                "eight_cycles_ms": {name: statistics.median(v[name] for v in values) for name in values[0]},
                "complete_rounds_ms": [v["complete"] for v in values],
                "historical_16_ms": summary["engines"][engine]["historical_16_ms"],
                "reopen_ms": statistics.median(r["reopen_s"]*1000 for r in runs),
            }
        return result

    result = {"before_source": before["source"], "after_source": after["source"],
              "before": measurements(before), "after": measurements(after), "paired_ratios": {}}
    for neon, fjall in [("neon-layers", "fjall"), ("neon-stable", "fjall-stable")]:
        result["paired_ratios"][neon] = {}
        for label in ["before", "after"]:
            ratios = [n/f for n, f in zip(result[label][neon]["complete_rounds_ms"],
                                         result[label][fjall]["complete_rounds_ms"])]
            result["paired_ratios"][neon][label] = {"rounds": ratios, "median": statistics.median(ratios)}
    return result


if __name__ == "__main__":
    with open(sys.argv[1]) as source:
        before = json.load(source)
    with open(sys.argv[2]) as source:
        after = json.load(source)
    print(json.dumps(compare(before, after), indent=2))
