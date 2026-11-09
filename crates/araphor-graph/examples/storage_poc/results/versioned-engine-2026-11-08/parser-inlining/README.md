# Native parser compiler visibility

`lsm-tree` `aed3e47a` adds `#[inline]` to five existing block-parser methods.
The data-block methods are `parse_restart_key`, `parse_full`, and
`parse_truncated`. The index-block methods are `parse_restart_key` and
`parse_full`. Method bodies, interfaces, codecs, search rules, and stored bytes
remain. Fjall stays at `42be11f`.
The [source patch](inline-parser.patch) starts at `29549fd7`.
The [binary manifest](inline-parser-binary.json) records exact sources,
patch and executable hashes, and code sizes.

The native default and LZ4 library suites pass 241 and 244 cases. Three
read-view and three retained-history cases pass in each configuration.
Fjall passes 125 CDC cases and 84 cases without CDC. Existing ignored cases
remain. The production check without default features, library clippy, and
formatting pass. Clippy reports existing warnings. Full workspace CI was not
run during iteration. See the logs and [verification record](verification.json).

## Unchanged PoC timings

Units are milliseconds. Each value comes from the existing summary checks.
Each combined pass has 28 ordinary fixed-key cycles. Restart and maintenance
remain separate. Each stable value is the existing median of four eight-cycle
runs. All existing correctness assertions pass.

| State | Combined median 0 | Combined max 0 | Combined median 1 | Combined max 1 | Stable median 0 | Stable median 1 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Before | 4.529 | 7.329 | 4.848 | 7.340 | 26.502 | 26.839 |
| Parser annotations | 4.550 | 7.680 | 4.483 | 6.769 | 25.670 | 26.764 |

Nearest-rank p95 changes from 7.221 to 7.441 ms in pass 0, and from 7.294
to 6.754 ms in pass 1. The [percentile record](cycle-percentiles.json) retains
minimum, median, p95, and maximum. The existing acceptance calculations remain.

These wall-time results are mixed. No overall latency gain is proved.
Both current combined medians exceed the 4.370 ms target. Both maxima reach
the 8.717 ms target, and both stable medians reach the 26.985 ms target.
Complete performance qualification remains **Not done**.

[compare.py](compare.py) uses the frozen `versioned-direct-compression` binary
before and `versioned-inline-parser` after. The script retains the previous
balanced order and all existing workloads, configurations, durability,
assertions, and timing boundaries. No task build, test, or profiler ran during
these eight untraced calls. Source and binary identity for the before state
remain in the [preceding manifest](../native-index-compression/direct-compression-binary.json).

## Query instruction diagnostic

The diagnostic runs the same complete combined driver under Callgrind 3.22.0.
The [tool record](tool.json) identifies the extracted Ubuntu package and its
hash. The tool runs from `/tmp`; no system package is installed. All profiled
timing fields are excluded from acceptance.

The [commands](cycle-commands.json) collect the original control and the
preceding candidate. The [annotated-parser command](inline-command.json)
collects the new candidate. Threads and eight caller levels remain separate.
Collection toggles target native `View::query` and `View::presence`, but the
presence toggle collects no instructions in these optimized binaries. This
diagnostic measures neighbor queries only. Revision 26 has presence calls
only; its zero collected count does not mean zero SDK work.

Each package evaluation clears counters before entry and saves a profile on
return. Each report has 72 main-thread profiles: eight runs, each with eight
primary evaluations and one rollback evaluation. [analyze-cycles.py](analyze-cycles.py)
resolves interned function IDs and checks each incoming query-call count
against the report's neighbor calls. The analysis excludes rollback and
restart from the 28 ordinary fixed-key evaluations. Both candidates execute
the same 92 selected neighbor calls.

The [complete instruction comparison](current-inline-instructions.json)
records 144,417,138 instructions before and 136,189,231 after, a decrease of
5.70%. The median changes from 4,948,318.5 to 4,679,004 instructions.
Every collected revision median decreases. This result measures complete
query work; disappearance of parser symbols alone is not a decrease.
The executable code section decreases from 50,342,256 to 50,340,528 bytes.
The executable file decreases from 88,447,944 to 88,445,352 bytes.

The [original-control comparison](control-current-instructions.json) also
locates the earlier difference at revision 29: median query instruction counts are
1,501,805 for the original control and 2,739,957 for the preceding candidate.
The driver flushes between its early increments. The original adapter saves
snapshots before flush. Retained reads use the latest structure and a separate
value cut. The native source and profiles show table decoding in that path.
Cold block loading is a small part of the collected instruction work; this
evidence does not justify a new cache or a different history structure.

Instruction counts do not measure I/O wait, scheduling, result inspection,
presence calls, or whole-cycle latency. The diagnostic does not prove that
specific compiler transformations caused the decrease. Prepared Arrow and
synthetic source metadata remain the existing PoC limits. Production
notification latency is not measured.

## Reproduction and raw evidence

Restore the source and labels from the manifests and the dependency locks in
the parent directory. Use the existing release command and
[release override](../native-read-comparison/release-override.toml).
The override reuses cached DuckDB output without changing DuckDB behavior.
Copy each executable to its manifest path before the next build.

Download the exact package version in `tool.json` and extract the package under
`/tmp/araphor-callgrind/tool`. Set `VALGRIND_LIB` to that directory's
`usr/libexec/valgrind` path. Extract [the raw profile archive](callgrind-profiles.tar.gz)
under `/tmp/araphor-callgrind` to reproduce analysis without running the profiler.
The archive retains all threads, the initial aggregate diagnostics, and all
216 evaluation profiles. Its hash is in `verification.json`.

Run [run-cycles.py](run-cycles.py) from the repository root for the original
and preceding candidate. Use `inline-command.json` for the new candidate.
Run `python3 /tmp/araphor-callgrind/analyze-cycles.py current inline` from the
repository root after
placing the script, raw profiles, and cycle reports under
`/tmp/araphor-callgrind`. Every profiled driver report also passes the unchanged
`summarize_cdc.py` checks. All raw reports, summaries, logs, source patches,
and command records remain in this directory or its raw profile archive.
