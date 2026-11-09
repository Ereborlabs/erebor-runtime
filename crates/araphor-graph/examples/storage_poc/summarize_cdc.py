#!/usr/bin/env python3
"""Check the CDC report and print milliseconds for each measured interval."""
import json
import statistics
import sys


def summarize(report):
    if report.get("mode") == "combined":
        return combined(report)
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


def combined(report):
    runs = report["runs"]
    versioned = report.get("versioned_fjall", False)
    orders = [["fjall", "fjall-stable"], ["fjall-stable", "fjall"], ["fjall-stable", "fjall"], ["fjall", "fjall-stable"]]
    revisions = [26, 29, 44, 46, 62, 64, 85, 87]
    captured = [24, 27, 36, 44, 48, 62, 71, 85]
    logical = [(50, 0), (12, 0), (1, 1), (1, 1), (1, 1), (63, 1), (2, 2), (64, 2)]
    assert len(runs) == 8
    for round_number, order in enumerate(orders):
        assert [r["engine"] for r in runs[2*round_number:2*round_number+2]] == order
    def cursor(value):
        return (value["journal"], value["offset"], value["sequence"])
    for run in runs:
        stable = run["engine"] == "fjall-stable"
        assert len(run["samples"]) == 8
        assert run["compactions"] > 0 and run["rotation"]
        assert run["historical_views"] == (6 if stable and not versioned else 16)
        assert [(v["stage"], v["revision"]) for v in run["unavailable"]] == ([("after-continue", r) for r in [26, 29, 44]] + [("after-final-reopen", r) for r in revisions[:-1]] if stable and not versioned else [])
        assert sum(w["source_wakes"] for w in run["walks"]) == 8
        assert sum(w["graph_wakes"] for w in run["walks"]) == 8
        assert sum(w["batches"] for w in run["walks"]) == 27
        assert sum(len(s["calls"]) for s in run["samples"]) == 42
        for i, sample in enumerate(run["samples"]):
            assert sample["revision"] == revisions[i] and sample["captured"] == captured[i]
            assert (sample["added"], sample["closed"]) == logical[i]
            assert sample["members"] == ([50, 12, 1, 1, 1, 63, 2, 64] if stable else [50, 12, 2, 2, 2, 64, 4, 66])[i]
            assert sample["phase"] == ("resume" if i == 4 else "continued" if i > 4 else "initial")
            assert sample["restarted"] == (i == 4)
            assert sample["result_rows"] == [50, 62, 62, 62, 62, 124, 124, 186][i]
            assert sample["findings"] == [0, 1, 1, 1, 1, 2, 2, 3][i]
            assert sample["graph_read_rows"] == sum(c["rows"] for c in sample["calls"])
            assert sample["graph_read_keys"] == sum(c["key_count"] for c in sample["calls"])
            assert abs(sample["graph_read_s"] - sum(c["elapsed_s"] for c in sample["calls"])) < 1e-12
            assert cursor(sample["source_cursor"]) < cursor(sample["graph_cursor"])
            if i:
                assert cursor(run["samples"][i-1]["graph_cursor"]) < cursor(sample["source_cursor"])
            assert sample["source_wake_s"] <= sample["source_ready_s"]
            assert sample["output_wake_s"] <= sample["output_ready_s"]
            assert sample["source_commit_s"] + sample["package_s"] + sample["output_commit_s"] + sample["result_read_s"] <= sample["total_s"] + 1e-9
        resume = run["resume"]
        assert cursor(resume["started_after"]) == min(cursor(resume["saved_source"]), cursor(resume["saved_graph"]))
        assert cursor(resume["first_decoded"]) == cursor(resume["saved_graph"])
        assert cursor(resume["started_after"]) < cursor(resume["first_decoded"]) < cursor(resume["first_match"])
        assert resume["first_match"] == resume["pending_head"] == resume["caught_up"] == run["samples"][4]["source_cursor"]
        assert resume["first_decoded_s"] <= resume["first_match_s"] <= resume["caught_up_s"]
        assert resume["batches"] == 3 and resume["journal_bytes"] > 0 and resume["items"] > 0
        for sample in run["samples"][5:]:
            assert cursor(sample["source_cursor"]) > cursor(resume["caught_up"])
    fields = ["source_commit_s", "source_cdc_read_s", "source_wake_s", "capture_s", "graph_read_s", "package_s",
              "output_stage_s", "output_sync_s", "output_commit_s", "output_cdc_read_s", "output_wake_s", "result_read_s", "total_s"]
    def timings(rows, names):
        return {field.removesuffix("_s"): {"median": statistics.median(r[field] for r in rows)*1000,
                                          "max": max(r[field] for r in rows)*1000} for field in names}
    result = {"source": report["source"], "mode": "combined", "engines": {}}
    for engine in ["fjall", "fjall-stable"]:
        selected = [r for r in runs if r["engine"] == engine]
        assert sorted(r["round"] for r in selected) == list(range(4))
        rows = [s for r in selected for s in r["samples"] if not s["restarted"]]
        continued = [s for s in rows if s["phase"] == "continued"]
        assert len(rows) == 28 and len(continued) == 12
        result["engines"][engine] = {
            "ordinary_samples": len(rows), "ordinary_ms": timings(rows, fields),
            "continued_samples": len(continued), "continued_ms": timings(continued, fields),
            "resume_ms": timings([r["resume"] for r in selected], ["feed_open_s", "first_decoded_s", "first_match_s", "caught_up_s", "read_s"]),
            "resume_backlog_bytes": [r["resume"]["journal_bytes"] for r in selected],
            "resume_backlog_items": [r["resume"]["items"] for r in selected],
            "resume_total_including_maintenance_ms": [s["total_s"]*1000 for r in selected for s in r["samples"] if s["restarted"]],
            "graph_sdk_read_ms_per_eight_cycles": statistics.median(sum(s["graph_read_s"] for s in r["samples"])*1000 for r in selected),
            "journal_read_ms_per_run": statistics.median(sum(w["read_s"] for w in r["walks"])*1000 for r in selected),
            "journal_bytes_per_run": [sum(w["journal_bytes"] for w in r["walks"]) for r in selected],
            "journal_items_per_run": [sum(w["items"] for w in r["walks"]) for r in selected],
            "journal_batches_per_run": 27, "historical_views": sum(r["historical_views"] for r in selected),
            "unavailable_views": sum(len(r["unavailable"]) for r in selected),
        }
    return result


if __name__ == "__main__":
    with open(sys.argv[1]) as source:
        print(json.dumps(summarize(json.load(source)), indent=2))
