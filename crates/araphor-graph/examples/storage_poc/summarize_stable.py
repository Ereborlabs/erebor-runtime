#!/usr/bin/env python3
"""Check the stable-key report and print round totals in milliseconds."""
import json
import statistics
import sys


def summarize(report):
    runs = report["runs"]
    versioned = report.get("versioned_fjall", False)
    engines = ["fjall", "fjall-stable", "neon-layers", "neon-stable"]
    assert len(runs) == 16
    revisions = [26, 29, 44, 46, 62, 64, 85, 87]
    captured = [24, 27, 36, 44, 48, 62, 71, 85]
    expected = [(50, 0), (12, 0), (1, 1), (1, 1), (1, 1), (63, 1), (2, 2), (64, 2)]
    result = {"source": report["source"], "engines": {}}
    for round_number in range(4):
        assert [r["engine"] for r in runs[round_number*4:round_number*4+4]] == [engines[(slot+round_number)%4] for slot in [0, 1, 3, 2]]
    for run in runs:
        stable = run["engine"].endswith("stable")
        assert len(run["samples"]) == 8
        assert run["member_keys"] == (186 if stable else 194)
        candidate = versioned and run["engine"] == "fjall-stable"
        assert run["historical_views"] == (24 if run["engine"] == "fjall" or candidate else 16)
        assert run["unsupported_after_reopen"] == (15 if run["engine"] == "fjall-stable" and not candidate else 0)
        for i, sample in enumerate(run["samples"]):
            assert sample["write"]["revision"] == revisions[i]
            assert (sample["write"]["added"], sample["write"]["closed"]) == expected[i]
        stages = ["after-writes"]
        if run["engine"].startswith("fjall"):
            assert run["compactions"] > 0
            stages.append("after-compaction")
        else:
            assert run["compactions"] == 0
        if run["engine"] != "fjall-stable" or candidate:
            stages.append("after-reopen")
        assert len(run["history"]) == 16*len(stages)
        for stage in stages:
            samples = [s for s in run["history"] if s["stage"] == stage]
            assert [s["revision"] for s in samples] == list(reversed(revisions)) + revisions
            assert [s["captured"] for s in samples] == list(reversed(captured)) + captured
            assert [s["direction"] for s in samples] == ["backward"]*8 + ["forward"]*8
    for engine in engines:
        selected = [r for r in runs if r["engine"] == engine]
        assert sorted(r["round"] for r in selected) == list(range(4))
        totals = [sum(s["scenario_s"] for s in r["samples"])*1000 for r in selected]
        stages = {s["stage"] for r in selected for s in r["history"]}
        result["engines"][engine] = {
            "eight_cycles_ms": {"rounds": totals, "median": statistics.median(totals), "max": max(totals)},
            "historical_16_ms": {stage: statistics.median(sum(s["elapsed_s"] for s in r["history"] if s["stage"] == stage)*1000 for r in selected) for stage in sorted(stages)},
            "reopen_ms": statistics.median(r["reopen_s"]*1000 for r in selected),
            "member_keys": selected[0]["member_keys"],
            "unsupported_requests_after_reopen": sum(r["unsupported_after_reopen"] for r in selected),
        }
    result["primary_cycles"] = sum(len(r["samples"]) for r in runs)
    result["historical_evaluations"] = sum(len(r["history"]) for r in runs)
    result["historical_views"] = sum(r["historical_views"] for r in runs)
    return result


if __name__ == "__main__":
    with open(sys.argv[1]) as source:
        print(json.dumps(summarize(json.load(source)), indent=2))
