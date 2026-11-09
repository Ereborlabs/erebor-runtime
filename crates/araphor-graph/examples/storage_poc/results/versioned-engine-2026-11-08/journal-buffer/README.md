# Reuse initialized journal encoding buffers

Fjall `04c304a` replaces the private encoding vector with
`std::io::Cursor<Vec<u8>>`. The vector keeps its initialized storage up to the
largest Item compression bound. The writer resets its logical position at
the former vector-clear points. Later Items reuse initialized bytes
without zero-filling the complete compression bound again.

The existing `Encode` and byteorder methods fill the 21-byte Item header on
the stack. One write copies that header into the cursor. Native LZ4 receives
the same maximum-bound slice. The actual compressed end sets the logical
position. The stored-length patch includes the initial cursor position.
`Writer::write_buffer` writes, hashes, and counts only the logical prefix.
The generic Item encoder uses a temporary cursor and keeps its `Write` API.

Only `fjall/src/journal/entry.rs` and `writer.rs` change. The 8 KiB file buffer,
codecs, thresholds, stored bytes, dirty flag, error handling, rotation, and
`SyncAll` remain. The buffer holds one Item bound, not a transaction.
`lsm-tree` stays at `aed3e47a`. The reviewer and implementer agreed on each
design change before coding and accepted only the measured apply CPU result.

The [final patch](reused-source.patch) starts at Fjall `ee3ea07`. The
[final binary manifest](reused-binary.json) identifies both executables.
The [Cursor-only patch](cursor-source.patch) and [manifest](cursor-binary.json)
retain the intermediate draft for isolation. No PoC workload, value, execution
order, assertion, timing boundary, durability, or summary calculation changes.

## Complete apply CPU diagnostic

Callgrind 3.22.0 collects only actual `Native::apply_saved` calls in the
existing combined driver. Each executable makes 72 calls across both layouts:
64 primary calls and eight rollback calls. Worker threads collect zero
instructions. Each raw profile header, exclusive sum, and incoming target cost
agree. All reported domain work matches. All profiled timings are excluded.
These counts do not describe ordinary cycles alone or the complete cycle.

| Executable | Complete apply instructions |
| --- | ---: |
| Original frozen control, context only | 449,467,444 |
| Accepted source before this edit | 450,974,505 |
| Intermediate Cursor-only draft | 448,453,981 |
| Final buffer and header rewrite | 444,525,190 |

The final rewrite removes 6,449,315 instructions, or **1.430%**, from complete
apply calls. The nested native commit count decreases from 98,231,114 to
92,616,942. Nested costs are not added to the apply total. Both LZ4 compressor
exclusive counters remain unchanged: 44,241,440 and 3,700,056. Decompression
also remains unchanged. The original control does not isolate this edit.

Before this edit, direct serializer calls account for 7,229,356 `memset`
instructions. Calls through allocation account for another 1,312,488.
The first draft removes repeated zero-filling but adds cursor work for each
primitive field. The stack header removes most of that added cursor work.
History protection replacement accounts for 75,156 nested instructions in
the prior apply profile. That result does not justify a retention rewrite.

## Untraced PoC results

Each combined result uses 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank: sample 27 of 28. Stable values use the
existing median of four eight-cycle runs. Units are milliseconds.

| Draft and pass | Combined median / p95 / maximum, before | Combined median / p95 / maximum, after | Stable median, before / after |
| --- | --- | --- | --- |
| Cursor only, 1 | 4.729 / 6.948 / 7.255 | 4.523 / 6.995 / 8.582 | 25.298 / 25.872 |
| Cursor only, 2 | 4.664 / 6.709 / 7.267 | 4.645 / 7.220 / 7.226 | 25.729 / 26.439 |
| Final, 1 | 4.766 / 7.275 / 7.471 | 4.561 / 7.094 / 7.162 | 25.935 / 25.816 |
| Final, 2 | 4.416 / 6.468 / 6.487 | 4.597 / 7.312 / 7.357 | 26.842 / 25.175 |

All 16 untraced summaries pass. Each complete report matches its paired
report after only timing fields and source labels are excluded. Cursors,
revisions, history, maintenance, and package outputs match. The final
candidate checks 128 combined primary cycles and 256 stable primary cycles.

The recorded targets remain 4.370082 ms median and 8.717326 ms maximum per
ordinary combined increment, and 26.985 ms median per stable eight-cycle run.
Both final combined medians exceed their target. Wall-time changes remain
mixed. No sustained latency gain is proved. Complete performance
qualification remains **Not done**.

## Verification and reproduction

Both drafts pass 127 CDC library cases and 86 cases without CDC, with one
existing ignored case in each run. Production without default features,
library clippy, formatting, and release builds pass. Existing warnings remain.
The extended exact-wire case checks both codecs, a nonzero prefix, empty
values, and 70,000 bytes of noise followed by small values. It checks that initialized
storage does not shrink and that only the current logical prefix is decoded.
Full workspace CI was not run during iteration, as the user requires.

- [Verification, percentiles, work equality, and archive identity](verification.json).
- [All 117 raw reports, summaries, logs, patches, and profile files](raw-evidence.tar.gz).
- Native gates: [final commands](reused-gates.json), [final runner](reused-gates.py), [intermediate commands](cursor-gates.json), [intermediate runner](cursor-gates.py).
- Release builds: [final runner](reused-build.py) and [intermediate runner](cursor-build.py).
- Unchanged comparisons: [final](reused-compare.py) and [intermediate](cursor-compare.py).
- Apply profiles: [prior and control](profile-prior.py), [intermediate](profile-cursor.py), [final](profile-reused.py), and [counter verifier](analyze-apply.py).
- [Profiler identity](tool.json), [host and compiler](environment.json), and [release override](release-override.toml).

All archive members were compared with their original files. All 20 summaries
reproduce through the unchanged summary functions. Frozen executables remain
under `output/storage-engine-baseline-20261108`; the manifests record their
hashes. Run scripts from the repository root after restoring their recorded
source. Copy the release override to its recorded `/tmp` path. Profile scripts
require the recorded Valgrind installation under `/tmp/araphor-callgrind`.
Move existing profile and frozen candidate files before rerunning their
scripts. Comparison scripts overwrite local reports; the archive preserves
the original measurements.
