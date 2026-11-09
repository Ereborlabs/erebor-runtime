# Buffered native journal checksum reads

Fjall `f72bd21` lets the private checksum reader use bytes already in its
`BufReader`. A complete buffered request copies and hashes those exact bytes,
then consumes them. Other requests use the standard `Take` read loop through
the existing checksum `read` method. Partial reads still update the checksum
before EOF or another error. `Interrupted` still retries. Empty requests do
no I/O. The decoder, stored bytes, offsets, durability, and public APIs remain.
The reader does not retain a buffer across a new durable boundary.

Only `fjall/src/journal/reader.rs` changes. `lsm-tree` remains at `aed3e47a`.
The reviewer and implementer agreed on this design before the edit and checked
the source and raw evidence before acceptance. The [source patch](source.patch)
starts at Fjall `42be11f`. The [binary manifest](binary.json) identifies the
exact build, patch, source label, and frozen executables. No PoC workload,
order, assertion, timing boundary, durability, or summary calculation changes.

## Measured native CDC work

Callgrind 3.22.0 collects only native feed calls in the complete existing
combined driver. This includes all workers and both key layouts. It is not an
ordinary-cycle or per-layout instruction measurement. All profiled timings
are excluded from acceptance.

| Recorded work | Before | After |
| --- | ---: | ---: |
| Feed instructions | 61,885,118 | 56,262,749 |
| Feed calls | 216 | 216 |
| Decoded batches | 216 | 216 |
| Decoded items | 14,264 | 14,264 |
| Journal bytes | 3,046,976 | 3,046,976 |
| Source wakes / Graph wakes | 64 / 64 | 64 / 64 |

Feed instructions decrease by **9.085%**. For each raw profile, the header,
exclusive instruction sum, and incoming native-feed cost agree. The main
thread collects zero instructions. LZ4 decompression and checksum-update
exclusive counters remain identical. The reduction includes the removal of
the repeated generic buffered-read path. Native `read_exact` inclusive cost
decreases from 21,013,408 to 15,301,260 instructions. This nested cost is not
added to the feed total.

The archive also retains the original control diagnostic: 115,669,991 feed
instructions across 207 calls, 216 batches, 14,264 items, and 3,039,092 bytes.
Its bulk `read` can return multiple batches. The current feed returns one
batch. The extra bytes include versioned metadata. That control comparison
does not isolate this source edit; per-call measurements are not comparable.

## Untraced PoC results

Each combined value uses 28 ordinary fixed-key samples. Restart remains
separate. p95 uses nearest rank. Each stable value uses the existing median
of four eight-cycle runs. Units are milliseconds.

| Pass | Combined median / p95 / maximum, before | Combined median / p95 / maximum, after | Stable median, before / after |
| --- | --- | --- | --- |
| 1 | 4.467 / 6.852 / 6.860 | 4.448 / 7.257 / 7.308 | 25.434 / 25.663 |
| 2 | 4.662 / 7.022 / 7.205 | 4.419 / 6.946 / 7.057 | 25.646 / 25.879 |

All eight existing summaries pass. Every non-timing report field matches
within each comparison, except for the source label. Candidate reports cover
128 combined primary cycles and 256 stable primary cycles. Historical replay,
compaction, reopen, rollback, and CDC continuation checks remain unchanged.

The recorded targets remain 4.370082 ms median and 8.717326 ms maximum per
ordinary combined increment, and 26.985 ms median per stable eight-cycle run.
Both candidate combined medians exceed their target. The observed wall-time
differences do not establish a sustained latency gain. Complete performance
qualification remains **Not done**.

## Verification and reproduction

Fjall passes 126 CDC library cases and 85 cases without CDC. One existing case
is ignored in each configuration. The new test checks buffered reads, refill,
large reads, successful partial reads, `Interrupted`, partial EOF, permission
errors, exact partial checksums, and empty requests before and after errors.
Production without default features, library clippy, formatting, and the
release PoC build pass. Existing warnings remain. Full workspace CI was not
run during iteration, as the user requires.

- [Verification, percentiles, work equality, and archive identity](verification.json).
- [All raw reports, summaries, logs, and feed profiles](raw-evidence.tar.gz).
- [Focused verification commands](gates.json) and [runner](gates.py).
- [Unchanged eight-call comparison sequence](compare.py).
- [Prior feed profile commands](profile-prior.py) and [candidate command](profile-candidate.py).
- [Counter and report verifier](analyze-cdc.py).
- [Profiler identity](tool.json), [host and compiler](environment.json), and [release override](release-override.toml).

The archive contains 70 members. Every member was compared with its original
file. All 11 summaries reproduce through the unchanged summary functions.
Frozen executables remain under `output/storage-engine-baseline-20261108`;
their hashes are in the binary manifest. Scripts run from the repository root.
Profile scripts require the recorded extracted Valgrind installation under
`/tmp/araphor-callgrind`. Existing profile files must be moved before rerunning
those scripts; each script checks that its outputs do not already exist.
The comparison script overwrites its local output reports. The committed
archive preserves the original measurements.

The earlier whole-cycle CPU attempt is excluded. Its reset function was
inlined in one executable, so its totals included work outside the intended
interval. None of those totals support this result or the latency target.
