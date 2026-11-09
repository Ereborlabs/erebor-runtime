# Ordinary execution compared with the original PoC

This record compares the original frozen control with the accepted versioned
engine. No source code changes in this comparison. The current engine uses
Fjall `04c304a` and `lsm-tree` `5c005a47`. The [original manifest](original-binary.json)
and [current manifest](current-binary.json) identify both executables.

The combined interval remains source write, original-journal wake, package
work, atomic output and cursor commit, output wake, and result read. Both
existing workloads, their balanced order, durability, caches, values,
assertions, and timing boundaries remain.

## Untraced elapsed results

Each combined result has 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank: sample 27 of 28. Stable values are the
existing median of four eight-cycle runs. Units are milliseconds.

| Pass | Engine | Combined median | p95 | Maximum | Stable median |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Original | 4.318 | 7.171 | 8.465 | 24.800 |
| 1 | Current | 4.590 | 7.112 | 7.269 | 25.989 |
| 2 | Original | 4.357 | 8.860 | 11.425 | 24.727 |
| 2 | Current | 4.839 | 7.214 | 7.535 | 26.386 |

All eight summaries pass. The current combined medians exceed the recorded
4.370082 ms target. Both current maxima and stable medians reach their
8.717326 and 26.985 ms targets. Complete performance remains **Not done**.
The original control also has an unexplained 11.425 ms maximum in this pair.
No build, test, profiler, large hash, or archive task runs during these calls.

The paired sample deltas locate extra elapsed work in the package stage:
median deltas are +0.185 and +0.319 ms. Capture setup medians increase by
about 3 microseconds. These observations do not establish a cause.

| Nested interval | Original / current median, pass 1 | Original / current median, pass 2 |
| --- | --- | --- |
| Source commit | 0.561 / 0.588 | 0.560 / 0.588 |
| Complete package | 1.863 / 2.014 | 1.706 / 2.088 |
| Recorded SDK reads | 0.726 / 0.824 | 0.701 / 0.905 |
| Complete output commit | 1.303 / 1.434 | 1.295 / 1.464 |
| Output commit start through wake | 1.855 / 1.778 | 1.888 / 1.907 |
| Result inspection | 0.335 / 0.441 | 0.385 / 0.443 |

Nested intervals and medians are not additive. `output_sync_s` contains the
complete transaction commit; it does not isolate `fsync` duration.
[verification.json](verification.json) retains all interval medians and
matched sample deltas.

## CPU instruction diagnostics

Each diagnostic runs the unchanged complete combined driver under Callgrind
3.22.0. All profiled timings are excluded from acceptance. Each analysis
selects 28 ordinary fixed-key samples after validating actual function entries.

| Collected owner | Original instructions | Current instructions | Change |
| --- | ---: | ---: | ---: |
| Neighbor queries, 92 calls | 143,786,515 | 138,727,222 | -3.519% |
| Result inspection, 28 calls | 139,347,483 | 128,039,843 | -8.115% |
| Complete package, 28 calls | 367,266,702 | 360,929,945 | -1.725% |

Neighbor queries are nested inside the complete package body. Do not add
these counts. Capture, commits, CDC, and waiting are outside the package
collection. The complete body includes membership checks and shared package
computation. Membership-check instructions also decrease. The current
elapsed package gap is not explained by excess instruction count.

The query diagnostic checks 72 actual package-return dumps. All 64 primary
incoming query counts match reported neighbor calls. Eight rollback counts
match separately. The result diagnostic checks 200 actual inspection dumps:
25 per run, comprising eight primary, one rollback, and 16 history calls.
The complete package diagnostic checks 72 actual entry and return pairs.
Each selected raw header, exclusive sum, and exact target incoming cost
agree. Residual and worker profiles collect zero instructions.

Selected ordinary sample fields match after only timing fields and physical
source and Graph cursors are removed. The full driver reports differ in
historical support and physical journal positions. Those differences remain
explicit in the raw reports and verification record. Current historical
queries succeed; the original control retains its unsupported requests.
Shared package, SDK, Graph, and fixture source does not change between the
original control source and this accepted source.

Instruction counts do not measure CPU cycles, cache penalties, contention,
I/O wait, or scheduling. The [hardware counter probe](perf-probe.json) is
blocked by this host's `perf_event_paranoid=4`. Host settings remain unchanged.
No production edit follows from these instruction counts alone.

## Reproduction

- [All raw profiles, reports, summaries, and logs](raw-evidence.tar.zst).
- [Verification, exact measurements, and archive identity](verification.json).
- [Original and current balanced comparison](compare.py).
- [Archive builder and reproduction checks](publish.py).
- Query: [collector](profile-query.py), [commands](ordinary-query-commands.json), [analysis](analyze-query.py), [counts](ordinary-query-instructions.json).
- Inspection: [collector](profile-inspect.py), [commands](result-inspect-commands.json), [analysis](analyze-inspect.py), [counts](ordinary-inspect-instructions.json).
- Package: [collector](profile-package.py), [commands](package-evaluate-commands.json), [analysis](analyze-package.py), [counts](ordinary-package-instructions.json).
- [Tool identity](tool.json), [host/compiler identity](environment.json), and [release override](release-override.toml).

All 778 archive members match their original files. All 14 summaries
reproduce through the unchanged summary functions. The archive uses Zstandard;
the verification record saves its command, version, size, and hash.
Extract the archive with `tar --zstd -xf raw-evidence.tar.zst`. Restore its
`callgrind/` files under `/tmp/araphor-callgrind/`, and its `output/` files
under `output/storage-engine-baseline-20261108/`. Run the analysis scripts
from the repository root. Collection requires the recorded Valgrind tool and
frozen executables. Rebuild the current executable with the source and build
script in the [point-read evidence](../point-decoder/README.md). Move existing
reports before rerunning collection or comparison scripts. Move the evidence
directory before rerunning the archive builder.

No native Rust source changes here. The preceding native correctness gates
remain the applicable source checks. Full workspace CI is not run during
iteration, as the user requires. Production notification latency is outside
this PoC.
