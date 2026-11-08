#!/usr/bin/env python3
"""Check the CDC report and print milliseconds for each measured interval."""
import json
import statistics
import sys


def summarize(report):
    runs = report["runs"]
    assert len(runs) == 8
    orders = [["fjall", "home"], ["home", "fjall"], ["home", "fjall"], ["fjall", "home"]]
    revisions = [26, 29, 44, 46, 62, 64, 85, 87]
    captured = [24, 27, 36, 44, 48, 62, 71, 85]
    result = {"source": report["source"], "engines": {}}
    for round_number, order in enumerate(orders):
        assert [r["engine"] for r in runs[2 * round_number:2 * round_number + 2]] == order
    for run in runs:
        assert len(run["samples"]) == 8
        assert run["historical_views"] == 16
        assert sum(w["source_wakes"] for w in run["walks"]) == 8
        assert sum(w["graph_wakes"] for w in run["walks"]) == 8
        if run["engine"] == "fjall":
            assert run["compactions"] > 0 and run["rotation"]
        else:
            assert run["compactions"] == 0 and not run["rotation"]
        for i, sample in enumerate(run["samples"]):
            assert sample["revision"] == revisions[i] and sample["captured"] == captured[i]
            assert sample["restarted"] == (i == 4)
            assert sample["findings"] == [0, 1, 1, 1, 1, 2, 2, 3][i]
            source = sample["source_cursor"]
            graph = sample["graph_cursor"]
            assert (source["journal"], source["offset"]) < (graph["journal"], graph["offset"])
            assert source["sequence"] < graph["sequence"]
    fields = ["source_commit_s", "source_wake_s", "source_ready_s", "package_s",
              "output_commit_s", "output_wake_s", "output_ready_s", "total_s"]
    for engine in ["fjall", "home"]:
        selected = [r for r in runs if r["engine"] == engine]
        assert len(selected) == 4
        assert sorted(r["round"] for r in selected) == list(range(4))
        rows = [s for r in selected for s in r["samples"] if not s["restarted"]]
        assert len(rows) == 28
        result["engines"][engine] = {
            "ordinary_samples": len(rows),
            "ordinary_ms": {field.removesuffix("_s"): {
                "median": statistics.median(s[field] for s in rows) * 1000,
                "max": max(s[field] for s in rows) * 1000,
            } for field in fields},
            "restart_including_maintenance_ms": [s["total_s"] * 1000 for r in selected
                                                 for s in r["samples"] if s["restarted"]],
            "physical_compactions": [r["compactions"] for r in selected] if engine == "fjall" else None,
            "journal_bytes": sum(w["journal_bytes"] for r in selected for w in r["walks"]),
        }
    return result


if __name__ == "__main__":
    with open(sys.argv[1]) as source:
        print(json.dumps(summarize(json.load(source)), indent=2))
