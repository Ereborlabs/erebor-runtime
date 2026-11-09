# Unapplied cached-index experiments

**Result: Not done for performance. Both experiments are removed.**
Accepted source remains at Fjall `42be11f` and `lsm-tree` `aed3e47a`.
The reviewer and implementer agree that these results do not justify the
additional memory and code. The existing PoC workloads, order, durability,
assertions, timing boundaries, and summary calculations remain unchanged.

## Changes and limits

The [cache patch](cached-index.patch) retains immutable restart-key metadata
beside each native index block. The existing native decoder and binary search
use that metadata. Public raw-block interfaces remain. The existing cache key,
tag, capacity, and replacement owner remain; entry and pinned sizes include
the metadata. The iterator owns the metadata after the cache and index drop.
Cold construction must parse each restart. Extra metadata can reduce the
number of blocks that fit in the cache. Zero-capacity and small caches can
repeat construction. No cold-read gain is claimed.

The [second patch](cached-inline.patch) adds one `#[inline]` attribute to that
draft. Its [incremental patch](cached-inline-only.patch) contains only the
attribute. The [ELF comparison](cached-inline-code-comparison.json) accounts
for all 111 changed code bytes in five named PoC wrapper functions. No
standalone native or query-method code bytes change. This does not mean that
the complete binaries are identical. The redundant instruction profile was
not run.

## Untraced results

Each combined row has 28 ordinary source-write through result-read samples.
Restart remains separate. Values are milliseconds; p95 uses nearest rank.
Each stable value is the existing median of four eight-cycle runs.

| Comparison | Combined median / p95 / maximum, before | Combined median / p95 / maximum, after | Stable median, before / after |
| --- | --- | --- | --- |
| Cache, pass 1 | 4.461 / 6.663 / 7.008 | 4.521 / 7.487 / 7.715 | 26.354 / 24.567 |
| Cache, pass 2 | 4.760 / 7.149 / 7.452 | 4.375 / 7.212 / 7.296 | 26.880 / 26.237 |
| Attribute, pass 1 | 4.675 / 7.430 / 13.984 | 4.847 / 7.102 / 7.336 | 25.991 / 26.535 |
| Attribute, pass 2 | 4.979 / 7.173 / 7.315 | 4.820 / 7.026 / 7.140 | 27.390 / 26.747 |

The combined median target is 4.370082 ms. No candidate median reaches it.
The stable median target is 26.985 ms. Wall-time changes remain mixed.
All non-timing report fields match, except for the source label.

The same cache binary has maxima of 7.715 and 13.984 ms in different calls.
The 13.984 ms sample spends 6.018 ms in the output commit phase. That phase
contains the complete native commit; it does not measure `fsync` alone.
The source binary cannot explain this variation between calls. Its underlying
cause is not established. See the exact sample fields in
[verification.json](verification.json).

## Query instruction diagnostic

The existing query-only Callgrind collection validates 72 evaluations,
including 28 ordinary fixed-key evaluations and 92 neighbor calls.
Complete ordinary query instructions change from 136,189,231 to 136,195,283
(+0.00444%). The median changes from 4,679,004 to 4,667,065.5 instructions.
Early revisions decrease; later revisions increase. This does not establish
net query savings. Parser-symbol changes alone do not establish less work.
Presence collects no instructions in this diagnostic. All profiled timing
fields are excluded from acceptance.

## Evidence and reproduction

- [Cache source and binary identity](cached-index-binary.json).
- [Attribute source and binary identity](cached-inline-binary.json).
- [Verified summaries, percentiles, counters, and archive identity](verification.json).
- [Raw reports, summaries, logs, and 79 profile files](raw-evidence.tar.gz).
- [Original cache comparison command sequence](compare-cache.py).
- [Original attribute comparison command sequence](compare-inline.py).
- [ELF byte comparison](compare-code.py).

The archive contains 163 members. Each member was compared with its original
file. All 17 summaries reproduce through the unchanged summary functions.
The archive contains every report from both eight-call comparisons and the
profiled combined call. Native verification logs and both exact patches are
retained. Frozen binaries remain under `output/storage-engine-baseline-20261108`.
The manifests record their hashes. From the repository root:

```sh
python3 crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/cached-index-experiment/compare-cache.py
python3 crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/cached-index-experiment/compare-inline.py
python3 crates/araphor-graph/examples/storage_poc/results/versioned-engine-2026-11-08/cached-index-experiment/compare-code.py
```

These commands overwrite the corresponding local output reports. The
committed archive preserves the original measurements.

## Verification

Both drafts pass 243 default, 246 LZ4, and 242 metrics native library cases;
two existing cases are ignored in each run. Three read-view and three history
cases pass in each configuration. Fjall passes 125 CDC library cases and
84 cases without CDC, with one existing ignored case in each run. Production
without default features, default library clippy, formatting, and the release
PoC build pass. The added tests compare complete index end-key, sequence,
offset, and size fields. They check iterator directions, cache replacement
and accounting, and iterator lifetime after other owners drop. Existing native
suites supply value and deletion coverage.

Metrics library clippy fails on the existing eight-argument `Iter::new` at
`lsm-tree/src/table/iter.rs:122`. The same source exists in the accepted commit.
No unrelated code was changed. Full workspace CI was not run during iteration,
as the user requires. Complete performance qualification remains **Not done**.
