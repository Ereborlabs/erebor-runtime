# Borrowed native point-lookup keys

Result: **Done for measured ordinary package CPU work; Not done for complete performance**.
Accepted source: Fjall `bdb1843` and `lsm-tree` `2e1b5df3`.
The [patch](borrow-key.patch) changes only the memtable module. A private
comparison interface gives Crossbeam's existing `Borrow<Q>` lookup a stack
tuple of caller bytes and sequence number. Stored `InternalKey` ordering
remains. No new index, stored representation, public API, dependency, or
unsafe code is added.

Lookup keeps the zero-cut return before validation, the existing nonzero-cut
key-length assertion, the exclusive `cut - 1` bound, exact-key filtering,
and cloned result fields. It removes the temporary owned search key. Small
keys were already inline; the result does not claim that every lookup loses
a heap allocation or that complete lookup is allocation-free.

## Untraced elapsed results

Each combined report has 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank, sample 27 of 28. Stable values are medians
of four existing eight-cycle runs. Units are milliseconds.

| Pass | Side | Combined median | p95 | Maximum | Stable median |
| --- | --- | ---: | ---: | ---: | ---: |
| 1 | Before | 4.616 | 6.540 | 7.105 | 26.032 |
| 1 | After | 4.653 | 7.187 | 8.332 | 25.042 |
| 2 | Before | 4.517 | 7.123 | 7.338 | 26.219 |
| 2 | After | 4.568 | 7.080 | 7.223 | 25.939 |

All eight summaries pass. Full reports match after removing only the source
label and timing fields; physical CDC positions also match. Fixtures,
engine order, caches, values, `SyncAll`, assertions, and timing boundaries
remain. No build, test, profiler, large hash, or archive job runs during
these calls. Both candidate medians exceed the recorded 4.370082 ms target
and their fresh controls. Both maxima and stable medians reach their
8.717326 ms and 26.985 ms targets. These observations establish neither a
repeatable elapsed gain nor a sustained regression.

## Complete ordinary package CPU result

Both frozen executables run the unchanged combined driver. All profiled
timings are excluded. Each side has 72 actual one-entry/return evaluation
dumps: 64 primary and eight rollback calls. Analysis selects 28 ordinary
fixed-key evaluations. Headers, raw totals, exclusive sums, and exact incoming
root costs agree in all 144 dumps. Residual and worker dumps collect zero
instructions. Full non-time reports, including cursors, match. Both summaries
pass. The reviewer independently checks these properties.

| Scope | Before instructions | After instructions | Actual calls |
| --- | ---: | ---: | ---: |
| Complete ordinary package | 359,859,804 | 355,220,178 | 28 |
| Nested entered `Memtable::get` | 17,836,479 | 12,955,155 | 12,980 |

Complete ordinary package work decreases by 1.289%. The nested scope overlaps
the complete owner; do not add these counts. Entered native counts match in
every dump, and every reachable native node balances. They do not cover every
possible inlined lookup. The new tuple accessor enters 129,076 times and
uses 774,456 exclusive instructions. This added work is included in the
complete result. The revision-46 median instruction count increases slightly;
not every revision improves.

## Source checks and reproduction

`borrowed_point_queries` compares borrowed ordering and equality with the
stored-key implementation. An independent linear oracle checks all four
result fields across binary, prefix, missing, 20-byte, 21-byte, long, and
65,535-byte keys. Versions include strong and weak deletes, empty values,
zero and maximum cuts, and exact visibility boundaries. Oversized keys panic
with a nonzero cut in both the old constructor and new lookup; cut zero
returns without validation.

Native default/LZ4 libraries pass 244/247 cases, with two existing ignored
cases each. Eight selected native integrations pass 19 cases, with one
existing ignored case, per configuration. Fjall CDC/without CDC pass 128/87
cases, with one existing ignored case each. Production without default
features, library clippy, formatting, and the release build pass. Existing
warnings remain. Full workspace CI is not run during iteration, as the user
requires.

- [Verification, measurements, and archive identity](verification.json).
- [Source patch](borrow-key.patch), [binary identity and build commands](borrow-key-binary.json), and [gate commands/results](borrow-key-gates.json).
- [Build](build.py), [gates](gates.py), and [balanced comparison](compare.py).
- Complete package [collector](profile.py) and [strict analysis](analyze.py).
- [Raw reports, profiles, logs, commands, and detailed CPU counts](raw-evidence.tar.zst).
- [Archive builder](publish.py), [tool identity](tool.json), [earlier environment observation](environment.json), and [release override](release-override.toml).

The archive builder compares every member byte with its original file and
reproduces all ten summaries. The environment file keeps an earlier host and
tool observation with its original timestamp; it does not establish host load
or build environment during these measurements. Build commands and binary
hashes identify the measured executables.

Extract with `tar --zstd -xf raw-evidence.tar.zst`. Restore `callgrind/` files
under `/tmp/araphor-callgrind/` and `reports/` files under
`output/storage-engine-baseline-20261108/`. Run saved scripts from the
repository root with the recorded tool and frozen executables. Move existing
reports or the evidence directory before rerunning scripts that refuse to
overwrite them. Production input, notification delivery, and a 100x incident
test gain remain outside this PoC proof. Complete performance remains **Not done**.
