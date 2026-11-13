# Native kernel evidence replacement: measured results

Implementation: `1250ba8ff`. The production collector uses Data's existing Fjall
database and branch. It has no Evidence segment files. Diagnostic files and
Node retry spools retain their owners. See the [source review](../../guides/araphor-kernel-evidence-storage-review.md).

## Method

This run uses the existing owner benchmark. Each workload has four matched
pairs with alternating order. The inputs have 16,384 or 262,144 records in
256-record batches. Both variants use the same bytes, assertions, release
profile, `test-fixtures` feature, compiler, and Fjall/lsm-tree revisions.
Each process creates a fresh store. The OS page cache stays enabled. No build
runs during the pairs. The host uses NVMe and ext4. The root filesystem reports
100% used and 3.7 GiB free. Desktop processes remain active. No CPU pinning or page-cache reset is applied.

The baseline is the frozen `raw_owner_stream` release artifact from the read
investigation. Its archived driver hashes exactly match `9bd0c6704` for the
example, bridge, and candidate. The current example changes only backend names
and report text; timed loops, inputs, assertions, and untimed validation probes
are identical. This baseline was not rebuilt from `9bd0c6704`. The JSON record
contains the original build provenance, both binary hashes, source hashes,
engine revisions, host details, and the pre-existing working-tree difference
hash. Earlier artifacts and reports are unchanged.

The first comparison used an older frozen driver. That comparison is
superseded. Its reports remain in `output/araphor-kernel-evidence-20261112/paired/`
and in the compressed sample record. The tables below use only the corrected
16-run matrix in `output/araphor-kernel-evidence-20261112/matched/`.

```sh
python3 scripts/benchmark_raw_reads.py \
  output/araphor-raw-read-20261112/raw_owner_stream \
  output/araphor-kernel-evidence-20261112/raw_owner_native \
  output/araphor-kernel-evidence-20261112/matched \
  --backends hybrid production
```

All 16 process runs pass. Each run checks exact bytes and logical positions,
partial pages, historical cuts, maintenance, reopen, durable result references,
saved replay, and continued replay. The new production replay reads original
PAYLOAD journal items and binds them to HEAD and POSITION in the same commit.

## Durable writes

Acceptance measures a validated Data batch through its durable acceptance.
The cycle also captures its cut, reads its input, and commits the benchmark
result/reference/progress record. Each variant has two durable steps. The
cycle is not a package detector or notification measurement. Percentiles pool
equal-size batch samples from the four runs. Throughput is the median of the
four process throughputs.

| Records | Storage | Accept p50 / p95, ms | Cycle p50 / p95, ms | Cycle events/s |
| ---: | --- | ---: | ---: | ---: |
| 16,384 | Segment baseline | 1.172 / 1.259 | 1.826 / 2.032 | 137,319 |
| 16,384 | Native production | 0.683 / 0.750 | 1.044 / 1.371 | 223,303 |
| 262,144 | Segment baseline | 1.178 / 1.247 | 1.832 / 1.940 | 137,793 |
| 262,144 | Native production | 0.707 / 0.785 | 1.260 / 1.447 | 211,825 |

The large workload has 1.54 times the cycle throughput. The cycle median
is lower in all four large pairs. This result does not establish a 100-fold
notification improvement.

## Reads

Each page returns at most 256 records. Reads include frame validation and
exact-byte checks. Each independent page captures its own read view. Values
below are median whole-scan rates in millions of events per second.

| Records | Storage | Warm | After flush and compaction | After reopen |
| ---: | --- | ---: | ---: | ---: |
| 16,384 | Segment baseline | 5.793 | 5.905 | 5.414 |
| 16,384 | Native production | 7.333 | 7.162 | 5.814 |
| 262,144 | Segment baseline | 5.240 | 5.215 | 4.682 |
| 262,144 | Native production | 6.115 | 6.310 | 4.516 |

Warm and post-maintenance scans improve in every large pair. Small reopened
scans improve in all four pairs. Large reopened scans are 3.55% slower in the
aggregate and slower in all four pairs. This is a measured cost of this
replacement.

## Lifecycle and storage cost

The next table uses the large workload. Each value is the median of four runs.
Allocated bytes use filesystem block counts after checkpoint, flush, and major
compaction. They are not bytes written to the device. Peak RSS is the process
maximum resident set size. Reopen time includes engine open and startup checks.

| Storage | Reopen, ms | Replay, ms | Resume, ms | Continue, ms | Allocated MiB | Peak RSS MiB |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Segment baseline | 70.367 | 16.194 | 15.906 | 0.050 | 37.94 | 112.56 |
| Native production | 90.104 | 20.412 | 18.987 | 0.069 | 54.42 | 136.11 |

| Storage | Checkpoint, ms | Major compaction, ms | Process CPU user / system, s |
| --- | ---: | ---: | ---: |
| Segment baseline | 14.279 | 9.442 | 0.505 / 0.330 |
| Native production | 89.120 | 57.990 | 0.660 / 0.270 |

Background compaction counts are zero in all reports. Native production uses
more retained disk allocation and peak memory. Startup, forced maintenance,
and replay also cost more. Process CPU includes all scans and validation
probes; it is not a storage-only CPU measurement.

The old replay walks its retained raw-file/RAM index. The new replay walks
the original native journal. Those replay paths have different mechanisms;
do not describe their difference as an engine-only CDC comparison.

Native expiry is logical. Retained history or journals can keep old payload
versions, including versions retained by unrelated package or catalogue roots.
The replacement does not promise immediate physical erasure.

## Functional proof and limits

- Data: 293 focused integration tests pass.
- Native DataFusion execution: 14 integration tests pass.
- Public Control intake: two integration tests pass, including durable pending input without an early ACK.
- Owner example: the partial history test and native production smoke run pass.
- Default-feature native raw and event test targets pass `cargo check`.
- Changed Rust files pass formatting.
- Data library tests remain blocked by 80 old DuckDB and `graph_rows` compile errors.
- Control library tests remain blocked by 36 old Graph and activation compile errors.
- The shared final CI procedure stops at formatting in 123 files outside this change.

The benchmark does not measure collector transport, Arrow conversion, package
analysis, Graph detection, or notification creation/delivery. It uses forced
flush and major compaction; it does not measure long-running natural
compaction or power-loss recovery. The production integration tests cover
overlap, gaps, expiry, pins, restart, and backup separately. The synthetic
incident stays ignored. Native format 11 is refused without an automatic
converter. Table abstraction and collector registration remain outside the
approved replacement.

[Machine-readable summary](araphor-kernel-evidence-2026-11-12.json) and
[all process samples](araphor-kernel-evidence-2026-11-12.samples.json.gz) retain
the measurements. Raw process output is in
`output/araphor-kernel-evidence-20261112/matched/`.
