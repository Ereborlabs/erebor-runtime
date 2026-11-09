# Checked borrowed point-block handles

Result: **Done for measured native CPU work; Not done for complete performance**.
Accepted source: Fjall `04c304a` and `lsm-tree` `1918e262`.
The corrected [patch](checked-handle.patch) removes owned index end keys from
three point-read block loads. The parsed item checks its prefix and suffix
bounds before it returns the existing offset and size. The terminal-miss
comparison uses checked borrowed bytes. Search, cache, data decoding, stored
bytes, public iterators, and error propagation remain.

The first [draft](handle.patch) omitted checks previously made during key
materialization. It is superseded. Its executable, patch, gates, reports,
and profiles remain available; its CPU figures do not describe accepted source.

## Untraced elapsed results

Each combined report has 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank, sample 27 of 28. Stable values are medians
of four existing eight-cycle runs. Units are milliseconds.

| Draft | Pass | Side | Minimum | Median | p95 | Maximum | Stable median |
| --- | --- | --- | ---: | ---: | ---: | ---: | ---: |
| Corrected | 1 | Before | 3.360 | 4.381 | 6.516 | 6.904 | 26.345 |
| Corrected | 1 | After | 2.875 | 4.211 | 6.674 | 7.126 | 25.509 |
| Corrected | 2 | Before | 3.622 | 4.582 | 7.465 | 7.876 | 25.639 |
| Corrected | 2 | After | 3.779 | 4.950 | 6.800 | 9.635 | 25.764 |
| Superseded | 1 | Before | 3.149 | 4.667 | 6.727 | 7.230 | 26.441 |
| Superseded | 1 | After | 3.233 | 4.547 | 7.165 | 7.196 | 26.883 |
| Superseded | 2 | Before | 3.030 | 4.657 | 7.178 | 7.240 | 26.187 |
| Superseded | 2 | After | 3.771 | 4.795 | 6.682 | 6.991 | 26.702 |

The [recorded PoC](../../combined-2026-11-08/release.json) has a 4.370082 ms
median, 8.600200 ms p95, and 8.717326 ms maximum. The corrected first pass
reaches the median and maximum targets; the second pass exceeds both. Both
stable medians reach 26.985 ms. Comparisons remain mixed. No repeatable
elapsed gain or sustained latency bound is proved.

The corrected second pass has a 9.634602 ms ordinary sample at revision 87,
round 1. Source commit takes 2.906486 ms there; its ordinary median is
0.591739 ms. This interval includes the commit work and does not isolate
`fsync`. The cause of the longer commit is not established.

No build, test, profiler, large hash, or archive job runs during these calls.
Workloads, fixtures, engine order, values, caches, `SyncAll`, assertions,
and timing boundaries remain. All 16 untraced summaries pass.

## Corrected CPU result

The full-package collector uses the same frozen executables and unchanged
combined driver. All profiled timings are excluded. Analysis selects 28
ordinary fixed-key evaluations from 72 actual one-entry evaluation dumps per
side. Actual native caller-context counts match in every dump.

| Scope | Before instructions | Corrected instructions | Change |
| --- | ---: | ---: | ---: |
| Complete package evaluation | 360,645,844 | 359,505,675 | -0.316% |
| Nested entered `Table::get`, 14,096 calls | 64,328,617 | 62,978,242 | -2.099% |

These scopes overlap. Native counts include actual entered method bodies;
they do not claim coverage of every possible inlined native path. Raw
headers, totals, exclusive sums, and exact incoming root costs agree in all
144 dumps. Every reachable native node balances. Residual and worker dumps
collect zero instructions. Domain work and non-time reports match fully.
The reviewer independently checks these properties.

The initial method-only collector is excluded. Before part 11 has a header
and native incoming cost of 1,328,536 instructions, but its raw total and
exclusive sum are 1,328,542. The six extra instructions occur in two reachable
allocator contexts. The tool-level cause is unknown. The failed strict
analysis and both raw sides remain in the archive; no assertion is relaxed.

The superseded full-package pair conserves counters, but uses the unchecked
draft. Its figures are retained only as draft evidence. They are not combined
with the corrected result above.

## Source checks and reproduction

`borrowed_handles_keep_bounds` compares valid plain and prefix keys with
legacy materialization and checks exact offset/size fields. Six malformed
prefix or suffix ranges must panic in legacy materialization, the new
handle method, and checked comparison.

Corrected default/LZ4 libraries pass 243/246 cases, with two existing ignored
cases each. Eight selected native integrations pass 19 cases, with one
existing ignored case, per configuration. Fjall CDC/without CDC pass 127/86
cases, with one existing ignored case each. Production without default
features, library clippy, formatting, and the release build pass. Existing
clippy warnings remain. Full workspace CI is not run during iteration, as
the user requires.

- [Verification, exact measurements, source IDs, binary hashes, and archive identity](verification.json).
- Corrected [gates](checked-handle-gates.json), [binary identity](checked-handle-binary.json), [build](build.py), and [comparison](compare.py).
- Corrected package [collector](profile-package.py) and [strict analysis](analyze-package.py).
- Superseded package [collector](profile-draft-package.py) and [analysis](analyze-draft-package.py).
- Excluded method-only [collector](profile-excluded.py) and [failed strict analysis](analyze-excluded.py).
- [All raw reports, profiles, logs, commands, and patches](raw-evidence.tar.zst).
- [Archive builder and reproduction checks](publish.py), [tool identity](tool.json), [environment](environment.json), and [release override](release-override.toml).

The environment file is an inherited earlier host and tool observation from
the point-decoder record. Its timestamp remains. It does not establish host
load or build environment during these measurements. The binary manifests
and saved build commands identify each measured executable.

All 578 archive members match their original bytes. All 22 driver summaries
reproduce, including both excluded profile drivers. This confirms workload
results; it does not admit excluded counters or profiled elapsed times.
Extract with `tar --zstd -xf raw-evidence.tar.zst`. Restore `callgrind/` files
under `/tmp/araphor-callgrind/` and `reports/` files under
`output/storage-engine-baseline-20261108/`. Run the saved scripts from the
repository root. Collection needs the recorded tool and frozen executables.
Move existing reports or the evidence directory before rerunning scripts
that refuse to overwrite them.

Production DataFusion input, notification delivery, and a 100x incident-test
gain remain outside this PoC proof. Complete performance remains **Not done**.
