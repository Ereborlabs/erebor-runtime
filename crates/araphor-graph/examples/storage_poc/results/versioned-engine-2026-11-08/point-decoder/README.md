# Native point reads without iterator positioning

`lsm-tree` `5c005a47` removes the point-read use of `Iter` and its
`DoubleEndedPeekable`. A point read constructs the same native `Decoder`
directly. The hash free marker returns before construction. A direct hash hit
uses the same restart offset. A conflict or absent hash index uses the same
`head_key < needle` restart search. The existing key, visibility, and
materialization loop selects the result.

Public range iterators and their positioning methods remain. No parser,
codec, stored byte, cache setting, value, or benchmark adapter changes.
Fjall stays at `04c304a`. The reviewer and implementer agreed before coding.
The [source patch](source.patch) starts at `lsm-tree` `aed3e47a`.
The [binary manifest](binary.json) records both frozen executables.

## Complete native point-read CPU diagnostic

Callgrind 3.22.0 collects actual `DataBlock::point_read` calls in the
unchanged combined driver. Both executables make 105,692 calls across both
layouts and all stages. This scope includes verification, history, and
maintenance. These counts do not describe ordinary cycles alone or the
complete cycle. All profiled timings are excluded from acceptance.

| Executable | Native point-read instructions |
| --- | ---: |
| Accepted source before this edit | 341,999,812 |
| Direct native decoder | 321,338,731 |

The complete point-read body uses 20,661,081 fewer instructions, or **6.041%**.
Each raw profile header, exclusive sum, and exact incoming target cost agree.
All five worker profiles collect zero instructions in each execution. Full
reports match after only source labels and timing fields are excluded.
Materialization remains 24,004,537 inclusive and 7,581,784 exclusive
instructions. These nested costs are not added to the complete count.

The earlier iterator positioning method accounts for 286,691,167 nested
instructions, including search and decoding. Its disappearance does not
remove that complete cost. The table above includes the work in the decoder
and point-read body after this edit.

## Untraced PoC results

Each combined result has 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank: sample 27 of 28. Stable values use the
existing median of four eight-cycle runs. Units are milliseconds.

| Pass | Combined median / p95 / maximum, before | Combined median / p95 / maximum, after | Stable median, before / after |
| --- | --- | --- | --- |
| 1 | 4.667 / 7.204 / 7.655 | 4.751 / 7.066 / 7.091 | 25.329 / 26.278 |
| 2 | 4.680 / 7.040 / 7.280 | 4.709 / 7.130 / 7.805 | 25.708 / 25.630 |

All eight untraced summaries pass. Each complete report matches its paired
report after only source labels and timing fields are excluded. Cursors,
revisions, history, maintenance, and package results match. The candidate
checks 128 combined primary cycles and 256 stable primary cycles.
No build, test, profiler, large hash, or archive task runs during these calls.

Both combined medians increase in these calls. Stable results remain mixed.
No ordinary latency gain or sustained regression is established. Both
candidate combined medians exceed the 4.370082 ms target. Both maxima and
stable medians reach their recorded 8.717326 and 26.985 ms targets.
Complete performance qualification remains **Not done**.

## Verification and reproduction

Native library tests pass 242 cases by default and 245 with LZ4, with two
existing ignored cases in each configuration. Eight selected native
integration suites pass 19 cases, with one existing ignored case, in each
configuration. These suites include retained history, read views, snapshots,
and table boundaries. Fjall passes 127 CDC cases and 86 cases without CDC,
with one existing ignored case in each configuration. Production without
default features, library clippy, formatting, and the release PoC build pass.
Existing warnings remain. Full workspace CI was not run during iteration,
as the user requires.

The committed `point_read_matches_oracle` case compares all four fields
against an independent linear search. It checks exclusive cuts, missing and
binary keys, empty values, deletions, shared key prefixes, restart intervals
1 through 16 and 255, and four hash ratios. Assertions require every actual
hash outcome and both native offset widths. Every four-byte case checks a
restart offset above 65,535.

- [Verification, percentiles, exact work, and archive identity](verification.json).
- [All 64 raw reports, summaries, logs, source, and profile files](raw-evidence.tar.gz).
- [Native gate commands](gates.json), [gate runner](gates.py), and [release build](build.py).
- [Unchanged balanced comparisons](compare.py) and [result verifier](verify.py).
- [Before profile](profile-before.py), [after profile](profile-after.py), and [counter verifier](analyze-point.py).
- [Profiler identity](tool.json), [host and compiler identity](environment.json), and [release override](release-override.toml).

All archive members match their original files. All ten summaries reproduce
through the unchanged summary functions. Frozen binaries remain under
`output/storage-engine-baseline-20261108`; their manifest records exact hashes.
Run scripts from the repository root after restoring the recorded source.
Copy the release override to its recorded `/tmp` path. Restore archive members
under their recorded output and Callgrind directories before verification.
Profile scripts require the recorded Valgrind installation under
`/tmp/araphor-callgrind`. Move existing reports and frozen candidate files
before rerunning build, comparison, or profile scripts.
