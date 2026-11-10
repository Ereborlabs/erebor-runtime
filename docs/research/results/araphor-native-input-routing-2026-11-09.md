# Native input routing, 2026-11-09

Result: **Done for optional native input routing after a committed Data view**.
Durable consumer records, atomic acknowledgement, collection floors, production
provider binding, notification batches, cutover, and both incident targets
remain **Not done**.

Data owns one shared Fjall journal reader and one raw position reader. A
subscription waits for the existing Data publication signal. It runs blocking
log reads on the blocking pool. Each read stops at one published view's exact
native boundary and raw revision. Producers supply no change descriptions.
Native raw append now sends the availability signal after view publication.

The router reads canonical context headers, coverage references, and Graph
publications. It skips payload fragments, owner indexes, receipt mirrors,
checkpoints, and unrelated transaction keys. It reads Graph producer witnesses
only when a registered interest can match the publication. The existing rule
stays unchanged: any matching producer witness permits a wake; the empty
witness fallback applies only when all producer witness lists are empty.

Raw routing uses the original entry's identity, intake time, spans, and record
ordinals. The native reader and legacy initial-head reader use the same last
matching ordinal rule. This rule applies the requested cursor upper bound.
No raw payload is copied or decoded for routing.

`subscribe_inputs` starts after the current committed view.
`subscribe_inputs_at` replays after a supplied committed view. A new lagging
registration can rewind the shared readers. Delivered positions suppress
duplicate wakes for existing readers. A failed batch restores its previous
physical cursor. A missing saved journal or raw footer returns an error.
This API uses complete Data cuts. It does not acknowledge consumption or
replace the query's partial raw-page cursor.

The focused gate passed **81 tests** in **34.278 seconds**, including build
work. The nine integration suites have no failed, ignored, or filtered tests.
The new cases check matching and unrelated inputs, original raw-only commits,
rollback, replay, lagging registration, repeated decode failure, compaction,
reopen, missing journal history, multi-row positions, and legacy head parity.
Real Graph publications check tenant/source isolation and both witness fallback
cases. The saved call records prove the exact witness lists used by those cases.

Read the [machine record](araphor-native-input-routing-2026-11-09.json) for the
command, 15 unchanged source hashes, engine commits, and evidence hashes.
Selected-file format checks pass. The incident workload and definition hashes
are unchanged. This increment did not rerun the production incident or full CI.
It establishes no speedup. Production still uses DuckDB.
