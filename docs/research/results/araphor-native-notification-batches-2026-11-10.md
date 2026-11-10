# Native notification write batches

Result: **Done for native notification delivery batches**. Production replacement
remains **Not done**. Production still uses DuckDB. No native incident speedup is
measured.

NotificationCycle saves ordered immutable context versions in memory. One native
Data transaction checks each expected owner revision. The transaction keeps
intermediate versions, including the exact subject of each pending attempt.
New write buffers, delivery results, and ready-attempt metadata use the prepared
memory budget. One ready buffer serves all delivery kinds.

The Router first routes the SQL rows and collects each obligation once. Delivery
then runs the existing kinds in order: Finding, FailureEscalation, and
AcknowledgementEscalation. Each kind prepares all ready attempts and commits
Pending before any sink effect. The next kind commits prior outcomes with its
new Pending versions. A final flush commits the remaining outcomes. Each state
keeps its existing retry, route, sensitivity, acknowledgement, and escalation
rules. Effects for different obligations can now occur in a different order.

A checked-write conflict or guard failure stops the cycle before the affected
effects. An ordinary per-state preparation or effect error skips that state's
later delivery kinds. Any Pending already committed remains available for retry.
A sink interruption can leave all Pending records committed with no saved outcomes.
Restart uses the same attempt numbers, immutable subjects, and approved routes.

Direct routing flushes its writes before return. Direct delivery uses the same
batch procedure with one obligation. The legacy DuckDB save stays synchronous;
its shared traversal uses the same delivery-kind order until removal.

## Verification

The [machine record](araphor-native-notification-batches-2026-11-10.json) freezes
the source, unchanged incident workload, engine commits, commands, and logs.
Formatting, default and native Analysis library checks, and native Analysis
Clippy pass. Clippy reports warnings; this is not a warnings-denied workspace
gate. The focused runtime gate passes **21 tests in three suites** with no
failed, ignored, or filtered cases.

The eight public notification cases include three new batch cases. They run
actual NotificationRouter SQL through native DataFusion. Three obligations
share one Pending commit and one outcome commit. Failed delivery adds the
FailureEscalation kind. A later clock adds AcknowledgementEscalation and proves
all three Pending fences plus the final outcome fence. Every sink effect reads
the actual durable Pending records. Reopen preserves the final versions and
the original immutable subjects.

The conflict case checks the complete batch rollback and zero effects. The
interruption case checks all Pending records before the first effect, reopens,
and checks the same delivered request and attempt number. The existing direct
delivery, retry, conflict, owner, route, and historical subject cases still pass.
Four native Instance cases and nine native Query cases also pass.

The unchanged production incident passes one selected case, with 694 other
cases filtered by its exact name. Its harness takes **13.98 seconds** and its
process takes **14.043 seconds**. This run uses DuckDB and the unchanged workload,
assertions, and timeouts. The build takes 344.349 seconds. The machine record
includes binary identity and build profiles. This is a shared-code correctness
regression check. No native or matched performance comparison is claimed.

## Remaining work

Notification consumption still uses finite snapshot rows. No sealed notification
input token reaches the final batch. Durable notification CDC completion,
affected-key reads, native Host notification admission, configured capacity,
retention, collection, backup, cutover, DuckDB removal, and both incident targets
remain **Not done**. Pending preparation batches do not acknowledge input.
The full CI procedure does not run for this increment.
