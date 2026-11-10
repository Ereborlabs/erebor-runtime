# Native source recovery ranges

Result: **Done for optional native source recovery records, extraction, and CDC**.
Production replacement remains **Not done**. Production still uses DuckDB.

`NativeStore::record_recovery_floor` now preserves the existing Control contract.
When the node floor exceeds the accepted cursor, Data records only the new
missing suffix. A repeated or lower recorded floor makes no commit. The method
still returns the full Partial interval from accepted cursor plus one through
the node floor. A floor no greater than the accepted cursor returns Complete.

For example, accepted cursor 1 and node floor 4 produce the recovery range
2 through 4. This does not acknowledge those records. If record 5 arrives,
the accepted cursor stays at 1 and the pending input gap remains 2 through 4.
An unknown source can have a recovery record without a receipt or CPU binding.

The native record key contains the existing source identity and last cursor.
One ordered range supplies the previous maximum and exclusive-after paging;
no extra index or copied CDC log exists. The public recovery API retains the
existing 256-record page bound. Historical Data views expose the same API.
Source extraction reads all required ranges at the captured native cut, checks
cancellation for each row, and charges decoding and vector growth to the actual
read budget. It includes recovery changes in source freshness.

The original committed batch routes each new range through the existing Removal
change. Source and cursor interests decide which subscriptions wake. Repeated
records and unrelated context interests produce no wake. A managed attempt
captured before a recovery change fails with AnalysisSourceChanged; a new capture
sees the range and can proceed.

Native format 8 records this durable recovery authority and rejects earlier
formats. Reopen validates source identity, exact keys, cursor bounds, revision
order, and the existing relation-notice guard. Each gap revision must be no
greater than the recovery notice, and that notice must be no greater than the
metadata revision. Compaction preserves retained historical ranges.

## Verification

The [machine record](araphor-native-source-recovery-2026-11-10.json) freezes 126
source hashes, both unchanged incident inputs, engine identities, exact commands,
and log hashes. The focused gate passes **155 tests in nine suites**, with no
failed, ignored, or filtered cases:

- Data: 129 tests in six suites, including raw history, extraction, original-log
  routing, managed execution, notification storage, and format recovery.
- Query: nine connected native execution cases.
- Analysis: four native instance and 13 native notification cases.

Seven new cases cover recovery without acknowledgement, whole-range paging,
cursor bounds, corrupt ranges and notices, historical headers, finite read
budgets, cancellation, selective CDC replay after reopen, and stale captures.
Default and native Analysis library checks and selected-file formatting pass.

Data Clippy fails at two unchanged legacy Graph `expect` calls:
`analysis/managed/graph/projection/publish.rs:90` and
`analysis/managed/reader/committed/graph.rs:213`. It reports no diagnostic in the
new recovery owner. The checked engine commits remain Fjall `cceaa84d3711`
and lsm-tree `2e1b5df34ffc`; both engine worktrees are clean.

The incident does not run again for this storage-only increment. The prior
[DuckDB correctness result](araphor-native-notification-consumption-2026-11-10.md)
remains separate evidence. No native incident pass, matched comparison,
sub-100 ms durable creation, or 100-fold gain is claimed. Full CI does not run.

Configured capacity, raw retention and interrupted deletion recovery, complete
Source providers, indexed affected-key reads, trace storage, backup, public
Data cutover, DuckDB removal, and both incident targets remain **Not done**.
Read the [review guide](../../guides/araphor-native-data-review.md#native-source-recovery-ranges)
for the owner reading order and data flow.
