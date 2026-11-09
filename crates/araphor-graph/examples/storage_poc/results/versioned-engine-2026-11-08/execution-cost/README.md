# Native execution cost diagnostic

This record adds two diagnostics for the source state in the
[ordinary execution comparison](../ordinary-gap/README.md). Fjall remains at
`04c304a`; `lsm-tree` remains at `5c005a47`. No engine source changes here.
Complete performance qualification remains **Not done**.

## Ordinary package events

Callgrind runs each frozen executable through the unchanged combined driver.
Instrumentation stays active throughout the driver. Collection and counter
resets occur at the actual `storage_poc::package::evaluate` entry. Each driver
has 72 package-return dumps. The analysis selects the same 28 ordinary
fixed-key evaluations. Restart remains separate.

| Event | Original | Current | Change |
| --- | ---: | ---: | ---: |
| Instructions | 367,523,378 | 361,077,028 | -1.754% |
| Atomic operations, `Ge` | 628,714 | 396,859 | -36.878% |
| Indirect branches | 6,749,561 | 6,323,385 | -6.314% |
| Simulated indirect-branch misses | 1,050,066 | 948,855 | -9.639% |
| Simulated L1 instruction misses | 3,483,224 | 3,107,684 | -10.781% |
| Simulated L1 data-read misses | 1,874,370 | 1,876,517 | +0.115% |

All 14 event columns pass conservation checks. The raw header, exclusive
sum, and exact package incoming cost agree in each dump. Residual and worker
profiles collect zero events. Zero collection does not prove worker inactivity.
Selected ordinary work matches after only timing fields and physical cursors
are removed. Both unchanged driver summaries pass.

`Ge` counts operations, not contention or cycles. Cache and predictor misses
are simulated. The tool models a direct-mapped 16 MiB last-level cache. The
host reports a 16-way 16 MiB L3 cache. The simulated last-level read-miss
increase does not establish a hardware penalty. These events do not explain
the elapsed median gap or the earlier maximum. No source edit follows from
these counts alone.

The [host counter probe](perf-host-probe.json) also fails outside the sandbox:
`perf stat -e cycles,instructions -- true` returns 255 because
`perf_event_paranoid` is 4. No host setting changes.

## Whole-driver CPU stacks

The standard Ubuntu `libprofiler` 2.15 package runs each unchanged combined
driver at a requested 1000 Hz. Only `libprofiler` is preloaded. The allocator,
workload, durability, and assertions remain. The matching `google-pprof`
reader resolves symbols; the original Go reader supplies raw sample locations.
The analysis joins the two records by exact address. It keeps full Rust names.
Some compiled functions share one address. A reported name does not distinguish
those paths.
Both unchanged driver summaries pass.

| Sample check | Original | Current |
| --- | ---: | ---: |
| Samples, equal to profiler interrupts | 787 | 824 |
| Samples with more than one frame | 787 | 824 |
| Samples with an unresolved leaf or other frame | 15 | 15 |
| Maximum observed stack depth | 48 | 57 |

The unresolved samples contain one virtual dynamic shared object address per
driver. Legacy records have no truncation flag. No truncated-sample count is
established. Sampling uses the default process-wide CPU timer. The records
have no thread labels and do not prove unbiased worker CPU coverage.

This scope includes both layouts, verification, history, maintenance, and
reopen. The control lacks some historical support. The sample totals are not
an equal-work performance comparison. No ordinary-only timing or latency gain
is claimed. All profiled timing fields are excluded from acceptance.

The preceding GNU gprofng probes are invalid. Each experiment reports
`itimer could not be set` and produces no clock profile. Exit status zero and
successful timer syscalls do not prove valid collection. These probes remain
in the archive. No application or profiler workaround is applied.

## Evidence and reproduction

[verification.json](verification.json) records the event totals, sample
checks, cache geometry, tool and dependency hashes, and archive identity.
All 225 members of [raw-evidence.tar.zst](raw-evidence.tar.zst) match their
original files. The archive includes complete profiles, reports, summaries,
commands, invalid probes, and the two Ubuntu profiler packages.

- Cache: [collector](profile-cache.py), [commands](cache-commands.json), and [analysis](analyze-cache.py).
- CPU: [collector](profile-cpu.py), [commands](cpu-commands.json), [symbol reader](symbolize-cpu.py), [reader commands](symbolize-commands.json), and [analysis](analyze-cpu.py).
- [Archive builder and verification](publish.py).
- [Original executable identity](original-binary.json) and [current identity](current-binary.json).
- [Valgrind identity](tool.json), [host identity](environment.json), and [release override](release-override.toml).

Extract with `tar --zstd -xf raw-evidence.tar.zst`. Restore `callgrind/`
files under `/tmp/araphor-callgrind/` and `cpu/` files under
`/tmp/araphor-gperftools/`. Extract both `.deb` packages with `dpkg-deb -x`
into `/tmp/araphor-gperftools/tool/`. This operation does not install packages.
The Go reader version and dependency hashes are in the verification record.
Run the analysis scripts from the repository root. They reproduce
`cache-package-events.json` and `cpu-stacks.json` in those temporary paths.
Collection also requires the recorded frozen executables and Valgrind tree.
Move existing reports before recollection. Move the evidence directory before
rerunning the archive builder.

The preceding focused native correctness gates remain applicable because
engine source does not change. No new untraced timing run or full workspace
CI runs in this diagnostic. Production notification latency remains outside
this PoC.
