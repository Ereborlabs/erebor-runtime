# Grouped Graph staging

This draft changes the existing Data and Graph owners. It adds no stored table, service, cache, or codec. It remains in the temporary tree until the live SQL run ends and root releases source.

`Contributions.apply` accepts one revision and a map from native scope ID to reset flag and replacements. `Replacement` is unchanged. The temporary member table includes scope ID. The diff, current-member checks, owner checks, deltas, closes, inserts, and state queries use that scope ID. Empty replacement scopes remain in the temporary scope table. Global additive metadata refs retain their existing rules. Each scope keeps its exact current/base version and source checks. Returned inserted and closed counts agree with the actual native write counts.

`GraphRows.apply_units` is the same production owner with a batch input. It validates each call and prepares its existing members. It applies all detector scopes once, then calls `StateRows.finish` for each scope. The public Graph unchanged check stays in its original position. Metadata is applied as one scope only when the existing publish path runs. No metadata version is created before that decision.

`GraphRows.canonical_contexts` reads the full native context key, validity bounds, sensitivity, body, and commit revision once. The native key and its canonical version key must identify the same row. `decode_context_row` and the typed GraphFact decoder remain. The result keeps the full typed fact, sensitivity, commit revision, and native fact reference. Each call still checks its exact record, key, value, sensitivity, support, and metadata membership. State anchors reuse only this checked native fact reference. Full pooled-fact and anchor checks remain in the native state reader and recovery owner.

The metadata factory returns its existing native evidence and position references for all detector calls. Position lookup uses the native evidence ID. A missing current or historical evidence ID is interned with the same source and CPU checks. The metadata fact temporary table and the repeated per-call context and dependency temporary tables are removed. Work counters retain the actual record and fact candidates. They omit the repeated per-call context and position stages.

Existing native tests use the batch API with one actual scope. Rejection tests call the real canonical-read and unit-validation chain inside the same assertion. Their inputs, mutations, and assertions remain. No test or workload is added.

Only format, source, caller, and dry-apply checks have run. The first measured Graph conversion is 0.013356 seconds. Its managed transaction work is 2.925956 seconds; the commit is 0.045938 seconds. These are the existing measured boundaries. The draft has no elapsed result. No fraction of the transaction time is assigned to individual SQL statements.
