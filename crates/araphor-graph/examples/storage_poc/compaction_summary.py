"""Summarize sustained Graph cycles and actual background merge overlap."""

import json
import math
import sys

from summarize import stats


def distribution(values):
    result = stats(values)
    result["p99_nearest_rank"] = sorted(values)[math.ceil(len(values) * 0.99) - 1]
    return result


def merges(events):
    pending = {}
    completed = []
    for event in sorted(events, key=lambda e: e["at_s"]):
        message = event["message"]
        thread = event["thread"]
        if message.startswith("Compaction choice:"):
            pending.pop(thread, None)
            if message.startswith("Compaction choice: Merge"):
                pending[thread] = event
        elif message == "Compaction successful":
            started = pending.pop(thread)
            completed.append({
                "started_s": started["at_s"],
                "ended_s": event["at_s"],
                "elapsed_ms": (event["at_s"] - started["at_s"]) * 1000,
                "choice": started["message"],
                "thread": thread,
            })
    return completed


def overlaps(cycle, intervals):
    return any(cycle["started_s"] < interval["ended_s"]
               and cycle["ended_s"] > interval["started_s"] for interval in intervals)


def cycles_summary(cycles):
    if not cycles:
        return None
    return {
        "cycles": len(cycles),
        "scenario_ms": distribution([c["scenario_s"] * 1000 for c in cycles]),
        "write_ms": distribution([c["write"]["total_s"] * 1000 for c in cycles]),
        "commit_work_ms": distribution([c["write"]["commit_s"] * 1000 for c in cycles]),
        "traversal_ms": distribution([
            sum(call["elapsed_s"] for call in c["calls"]
                if call["operation"] == "neighbors") * 1000 for c in cycles
        ]),
        "index_ms": distribution([c["index_s"] * 1000 for c in cycles]),
        "verification_read_ms": distribution([c["verification_read_s"] * 1000 for c in cycles]),
    }


def summarize(report):
    result = {
        "source": report["source"],
        "profile": report["profile"],
        "time_unit": "ms",
        "limit": "Observed distributions from two passes per engine; not a production tail bound. Overlap also varies with retained-history size.",
        "passes": [],
        "paired_rounds": [],
    }
    for run in report["passes"]:
        intervals = merges(run["events"])
        cycles = run["cycles"]
        overlapping = [c for c in cycles if overlaps(c, intervals)]
        final = cycles[-1]["after"]
        result["passes"].append({
            "engine": run["engine"], "round": run["round"], "epochs": run["epochs"],
            "wall_ms": (run["ended_s"] - run["started_s"]) * 1000,
            "scenario_total_ms": sum(c["scenario_s"] for c in cycles) * 1000,
            "write_total_ms": sum(c["write"]["total_s"] for c in cycles) * 1000,
            "reopen_ms": run["reopen_s"] * 1000,
            "file_bytes": run["file_bytes"], "allocated_bytes": run["allocated_bytes"],
            "added": sum(c["write"]["added"] for c in cycles),
            "closed": sum(c["write"]["closed"] for c in cycles),
            "merges": intervals,
            "maintenance_at_last_cycle": final,
            "max_sampled_l0_tables": max(c["after"]["l0_tables"] for c in cycles) if final else None,
            "max_sampled_tables": max(c["after"]["tables"] for c in cycles) if final else None,
            "errors": [e for e in run["events"] if e["level"] in ("WARN", "ERROR")],
            "all": cycles_summary(cycles),
            "merge_overlap": cycles_summary(overlapping),
            "without_merge_overlap": cycles_summary([c for c in cycles if not overlaps(c, intervals)]),
            "first_epoch": cycles_summary([c for c in cycles if c["epoch"] == 0]),
            "last_epoch": cycles_summary([c for c in cycles if c["epoch"] == run["epochs"] - 1]),
        })
    for round_ in (0, 1):
        fjall = next(p for p in report["passes"] if p["engine"] == "fjall" and p["round"] == round_)
        redb = next(p for p in report["passes"] if p["engine"] == "redb" and p["round"] == round_)
        intervals = merges(fjall["events"])
        paired = {c["write"]["revision"]: c for c in redb["cycles"]}
        selected = [c for c in fjall["cycles"] if overlaps(c, intervals)]
        result["paired_rounds"].append({
            "round": round_,
            "fjall_overlap": cycles_summary(selected),
            "redb_at_same_revisions": cycles_summary([paired[c["write"]["revision"]] for c in selected]),
            "redb_over_fjall_total": {
                "scenario": sum(c["scenario_s"] for c in redb["cycles"]) / sum(c["scenario_s"] for c in fjall["cycles"]),
                "write": sum(c["write"]["total_s"] for c in redb["cycles"]) / sum(c["write"]["total_s"] for c in fjall["cycles"]),
            },
        })
    return result


if __name__ == "__main__":
    with open(sys.argv[1], encoding="utf-8") as source:
        print(json.dumps(summarize(json.load(source)), indent=2))
