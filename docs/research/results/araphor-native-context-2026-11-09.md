# Native context admission qualification

Date: 2026-11-09. Source parent: `66bc190c5`. The commit that adds this record
contains the qualified source. Result: **Done for default-limit native context
admission, retained proof, and canonical fact-index staging**. Production
cutover and the incident performance targets remain **Not done**.
The [source record](araphor-native-context-2026-11-09.json) identifies the
changed source, removed physical-context path, engine commits, gate exits,
and frozen PoC binary.

Read the [source guide](../../guides/araphor-native-data-review.md#qualified-context-admission).
This extends the existing Data owner. It adds no store layer or backend trait.
Packages still receive no store or commit capability.

## Admission behavior

`NativeStore` supplies guarded context batches, checked writes, and qualified
interning. A wrapper owns one `DataWrite`, runs the guard, and commits once.
Failure discards the batch. Empty and unchanged guarded calls still run the
guard without a native commit.

The borrowed context participant stages immutable values, maximum owner heads,
canonical fact records, intern scopes, and imported-document pointers together.
An exact retry checks its canonical fact index and retained package proof,
returns the original reference, and does not repeat new-record CAS checks.
The caller must discard a borrowed transaction after a staging error. This
matches the existing Graph participant contract.

The current and native owners share the existing pure fact decoder, retained
closure reader, and package proof cache. Retained package proof does not require
current image installation. Context reads keep the current package-proof
contract; no fact-index lookup is added to every generic read.

Ordinary writes and intern calls populate the same tenant/owner/lifetime scope
index. Interning selects the first matching entity in byte order and sees
earlier inputs staged in the same batch. Bodies stay in context values. They
are not copied into keys or hashed for change detection.

Imported documents use the existing history validator and a pointer that spans
lifetimes. Notification admission uses the existing obligation and approved
route validators. Its fixed obligation lifetime allows the existing context
head to serve CAS and latest-state reads. No duplicate notification head is
added. Recovery checks context identity, fact indexes, scope/pointer sets,
retained proof, imported history, and native metadata revision bounds.

## Focused checks

The final source passes 34 integration cases: ten context cases and the 24
existing catalogue, raw, transaction, index, and schema cases. The context cases
cover guarded mixed batches, original retry references, denied callbacks,
conflict rollback, stale CAS, zero owner-revision heads, staged interning,
lexical selection, retained proof, canonical fact-index consistency, imported
history, notification CAS, raw-prefix history, compaction, and reopen.

A real `AnalysisStore` caller also installs a package, admits its provenance
context and a fact, retries, and reopens. This checks the shared helper changes
through the current production owner. Another case stages a borrowed batch,
observes a later-row error, rolls it back, and then reuses the store.

```sh
cargo test --offline -p araphor-data --features native-store,test-fixtures \
  --test native_context --test native_packages --test native_raw \
  --test native_store --test raw_index --test store_schema \
  --config /tmp/araphor-storage-release-override.toml
cargo check --offline -p araphor-data --no-default-features --lib \
  --config /tmp/araphor-storage-release-override.toml
cargo clippy --offline -p araphor-data --features native-store,test-fixtures \
  --lib --no-deps --config /tmp/araphor-storage-release-override.toml
```

The feature-off build passes. Clippy still stops on the two unchanged `expect`
calls in `analysis/managed/graph/projection/publish.rs:90` and
`analysis/managed/reader/committed/graph.rs:213`. Selected changed modules and
the new integration target pass formatting. Existing formatting in the three
mechanically updated managed callers is outside that claim. Full CI does not
run during iteration, as the user requires.

Earlier logs retain a build failure from three unconverted fact-helper callers,
a test-fixture compile failure from its missing CPU field, and nine passing
context cases with one invalid imported-document fixture. That fixture used
schema 1; the current schema constant is 3. The final cases use the actual
schema and retain all validity checks. Logs use `native-context-` under
`output/araphor-fjall-migration-20261109/`.

## Existing Graph and CDC PoCs

The unchanged combined driver passes 64 cycles and all 128 requested
historical views. The unchanged stable driver passes 128 primary cycles,
640 historical package evaluations, and 320 historical views. No requested
view is unavailable. Both existing parsers reproduce the saved summaries.
The workloads retain their traversal, assertions, rollback, history,
compaction, reopen, saved CDC resume, and continued input.

The final optimized binary is 98,122,976 bytes. Its SHA-256 is
`a44eb47a767052c93bcd3306c48fb89e7fdeb1ece29031b748a784ebfeb2bb38`.
It remains at `output/araphor-fjall-migration-20261109/native-context-poc`.
The reports retain the runner's `unrecorded` source label. The external source
hashes and frozen binary manifest supply the exact qualification identity.
These are correctness checks, not paired performance comparisons or production
notification measurements.

## Limits

This qualification does not cover configured capacity, managed attempts or
results, source-range fact reads, context pagination/providers, notification
finding/concern lookups or effects, collection, retention, backup, or production
CDC routing. It adds no raw-record or witness requirement to context admission.
The complete managed transaction and production switch remain **Not done**.

The incident test is not rerun for this optional-owner increment. Its last
[qualified result](araphor-native-raw-2026-11-09.md#unchanged-incident) still
uses DuckDB. No incident speedup, creation below 100 milliseconds, or 100-fold
improvement follows from these owner checks.
