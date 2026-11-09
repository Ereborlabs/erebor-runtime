# Native Graph participant qualification

Date: 2026-11-09. Result: **Done for the optional Graph participant and its
package PoC caller. Production migration and performance goals are not done.**
Read the [source review guide](../../../../../../docs/guides/araphor-graph-commit-review.md#native-fjall-participant-2026-11-09).

## Source and commands

[Source and binary identity](native-graph-source.json) records Runtime parent
`e0351b994`, Fjall `cceaa84`, the native tree `2e1b5df34ffc`, and every changed
Rust source and manifest. The before binary is the retained accepted PoC from
Fjall `a042865`; its SHA-256 is
`125ee085a8aa8c3d2deedbc530e8c3092ea7160d4f71a2e2eb48669dd749449f`.
The after binary is `output/araphor-fjall-migration-20261109/native-graph-poc`.
Use the source record for its exact hash. No binary is stored in Git.

The [comparison driver](compare.py) repeats the existing combined runner in
four alternating pairs. [Commands and exits](native-graph-pairs.json) record
all eight runs. No build runs during the comparison. Both binaries use release
settings and the [same DuckDB link override](release-override.toml).
The source writes, package inputs, call comparisons, state, evidence rows,
frontiers, timeouts, and assertions stay unchanged. The native target uses the
shared Graph owner. The revision-key control keeps its prior adapter.

## Measured comparison

The [pooled result](native-graph-pair-summary.json) contains 112 ordinary
`fjall-stable` samples per version. Each original JSON report and its checked
summary are in this directory. Both columns use the median and an inclusive
linearly interpolated p95 from `statistics.quantiles(n=100, method="inclusive")`.
Earlier engine records can use a different p95 estimator.

| Complete source-write through result-read boundary | Before | After |
| --- | ---: | ---: |
| Median | 4.445 ms | 7.669 ms |
| p95 | 7.323 ms | 13.697 ms |
| Maximum | 7.766 ms | 15.413 ms |

This is a measured slowdown. There is no performance improvement claim.
The complete boundary still ends after result inspection. Preparation is in
`output_stage_s` and in the complete interval. The new result check reconstructs
semantic changes from two retained native views. The old adapter reads a copied
change vector. The native target has no copied change log. The new committed
view also loads property chunks on demand instead of accepting an unconfirmed
precommit cache. The comparison includes these procedure changes and exact
cut stamping. It does not isolate engine sync cost or prove incident latency.
The stage medians are nested; do not add them as disjoint intervals.

## Correctness and limits

The [stable report](native-graph-stable-final.json) and
[checked summary](native-graph-stable-final-summary.json) pass 128 primary
cycles, 640 historical package evaluations, and 320 retained views. Exact rows,
package calls, partial findings, states, historical reads after compaction,
and historical reads after reopen pass. The native target keeps 186 stable
membership keys. No retained request is unsupported. Its eight-cycle median
is 41.540 ms in this run; the other engine conditions are controls.

The combined reports pass the existing original-journal wake, saved-cursor
resume, continued input, output membership-key, historical-view, and logical
result assertions. Their source and output wakes still walk original journals.
`inspect.cdc_s` measures historical change reconstruction in the native target;
it does not measure the journal reader.

[Focused gates](gates.json) record six native Graph tests, library clippy with
warnings denied, the feature-off check, and the passing changed-file format
check. The earlier package-wide format check reports pre-existing source and
mixed-edition example differences. Its failed log is retained separately.
Full workspace CI is not run, as the user requires during iteration. The CDC
manifest and lock resolve; only the Neon wrapper binary runs this combined
qualification. Both wrappers use the same Graph and CDC modules.

These cases do not qualify production Data, native DataFusion input capture,
notification processing, sustained load, large retained histories, power loss,
or the requested 100-fold and sub-100 ms incident results. Production still
uses DuckDB. The remaining migration must switch all Data transaction families
together before removing DuckDB.
