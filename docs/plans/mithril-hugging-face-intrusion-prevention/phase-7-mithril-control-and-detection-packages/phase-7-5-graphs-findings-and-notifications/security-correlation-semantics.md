# Security Correlation And Vector Operations

This is the correlation operation record for the
[Security Analytics contract inventory](security-contract-inventory.md).
All listed ports and reference checks belong to 7.5.9 and are **Not done**.
The parent inventory supplies the common input, output, state, and host rules.

## Explicit finding correlation

`security.findings.correlate` needs findings and their related event documents.
Finding tags alone cannot reproduce source query and join-field behavior.
The source entry point is
[JoinEngine.onSearchDetectorResponse](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/JoinEngine.java).

| Operation ID | Source symbol | Inputs -> outputs and exact calculation |
| --- | --- | --- |
| SA-03.rules | `JoinEngine.onAutoCorrelations`; `CorrelationRule.parse`; `CorrelationQuery.parse` | Finding detector category and pinned rules -> rules whose nested `correlate.category` matches. Each clause carries index, query, category, and optional field; each rule carries a millisecond window and optional trigger. |
| SA-03.source-filter | `JoinEngine.getValidDocuments` | Source finding's related document IDs -> valid source documents. A field clause requires that field to exist. A query clause uses the source query-string filter. Qualify missing fields and index identity. |
| SA-03.field-join | `JoinEngine.getValidDocuments` | Valid source documents and their field values -> target field-membership query, plus the optional target query. Source uses the first value fetched for each hit. Local multivalue policy needs an explicit reference case. |
| SA-03.category-window | `JoinEngine.getValidDocuments`, `searchFindingsByTimestamp` | Clauses -> category/query lists and category window. Source uses the maximum rule window per category. Candidate findings use inclusive `[finding_time-window, finding_time+window]`. |
| SA-03.documents | `JoinEngine.searchFindingsByTimestamp` | Candidate findings -> related document IDs, query strings, and target source indices for each category. |
| SA-03.target-filter | `JoinEngine.searchDocsWithFilterKeys` | Candidate related documents -> documents that match at least one target query (`minimumShouldMatch(1)`) and the document-ID restriction. Preserve query-string semantics and source index identity. |
| SA-03.finding-join | `JoinEngine.getCorrelatedFindings` | Filtered related documents -> finding IDs in the same time range. Match `correlated_doc_ids`; exclude the source finding when category matches. |
| SA-03.merge | `JoinEngine.getCorrelatedFindings`, `getTimestampFeature` | Explicit and automatic neighbor maps -> union of finding IDs per category. Keep the result kind and matched rule IDs so similarity/shared tags do not become causal proof. |
| SA-03.trigger-select | `CorrelationRuleScheduler.schedule` | Each rule with a trigger -> finding IDs from its listed categories. Source runs a task immediately; it does not delay until the end of the rule window. |
| SA-03.trigger-state | `CorrelationRuleScheduler.RuleTask.run`, `addCorrelationAlertIntoIndex`, `updateCorrelationAlert`; `CorrelationAlertService.getActiveAlerts` | Evaluation time, rule window, candidate findings, and prior active alerts -> create or update an alert candidate. Preserve start/end times and source finding identity. The host supplies prior state and time. |
| SA-03.alert-read | `CorrelationAlertService.getCorrelationAlerts`, `parseCorrelationAlerts`, `getParsedCorrelationAlert` | Rule/filter/sort/page arguments and retained alert rows -> selected typed alert rows. This is a host query/read mapping, not an independent detector. |
| SA-03.alert-status | `CorrelationAlertService.acknowledgeAlerts`, `updateCorrelationAlertsWithError` | Prior alert state and explicit acknowledgement/error input -> status transition. The existing notification owner retains authority and durable state. Package output can describe a candidate transition only. |

Correlation computation needs no independent durable store. A package can
recompute from complete current windows. An incremental implementation must
version its window contributions and prior trigger state. A removed finding
must stop contributing after its source window is replaced.

## Automatic correlation

These operations share `security.findings.correlate` and have separate fixtures.
The resource input is
[mitre_correlation.json](../../../../../security-analytics/src/main/resources/correlations/mitre_correlation.json).

| Operation ID | Source symbol | Inputs -> outputs and exact calculation |
| --- | --- | --- |
| SA-04.map | `AutoCorrelationsRepo.autoCorrelationsAsMap` | Pinned intrusion-set resource -> intrusion-set name to set of `mitreAttackId` strings. |
| SA-04.tags | `JoinEngine.generateAutoCorrelations` | Each finding's query tags -> unique tags with prefix `attack.`. Other tags do not enter automatic matching. |
| SA-04.intrusion-sets | `AutoCorrelationsRepo.validIntrusionSets` | ATT&CK tags and map -> intrusion sets that contain at least one tag. |
| SA-04.candidates | `JoinEngine.generateAutoCorrelations` | All Sigma log types and finding time -> findings in the inclusive symmetric configured window. Exclude source finding ID. |
| SA-04.tag-match | `JoinEngine.generateAutoCorrelations` | Source and candidate tag sets -> correlation when at least one tag is shared. |
| SA-04.set-match | `JoinEngine.generateAutoCorrelations` | Source and candidate intrusion-set sets -> correlation when at least one set is shared. This is an OR alternative to shared tags. |
| SA-04.group | `JoinEngine.generateAutoCorrelations`, `getCorrelatedFindings` | Positive automatic matches -> per-log-type neighbor IDs, then union with explicit matches. Preserve automatic versus explicit provenance. |

The source limits log types to 100 and findings to 10,000 per search. Those
limits are not proof of complete input. A local bounded evaluation must either
receive a complete declared input or report incomplete coverage.

## Vector construction, state, search, and ranking

Source vector calculations are under
[VectorEmbeddingsEngine](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/VectorEmbeddingsEngine.java),
[TransportCorrelateFindingAction](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/transport/TransportCorrelateFindingAction.java),
and the
[correlation query/mapper/codec modules](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/index/).
These are numerical algorithms. They require no AI service.

| Operation ID | Export and source symbols | Required calculation and state |
| --- | --- | --- |
| SA-05.epoch | `security.correlation.vectors`: `TransportCorrelateFindingAction.getTimestampFeature`; `CorrelationIndices.setupCorrelationIndex` | Maintain score epoch and root metadata. If `finding_time - fixed_historical_interval` advances the epoch, use the historical interval in seconds as the feature. Otherwise use integer millisecond difference divided by 1,000, then convert to `f32`. Preserve the exact units and rounding. |
| SA-05.root | Vectors: `VectorEmbeddingsEngine.getSearchMetadataIndexRequest`; `CorrelationIndices.setupCorrelationIndex` | Resolve log-type `correlation_id`; carry root counter, timestamp, and score timestamp as typed state. No local package writes metadata directly. |
| SA-05.finding-vector | Vectors: `insertCorrelatedFindings` | For current counter `c`, finding vector `[c, c-50, timestamp_feature]` with finding ID, counter, category/correlation ID, time, record kind, and source references. |
| SA-05.pair-vector | Vectors: `insertCorrelatedFindings` | For current and neighbor counters `c` and `n`, pair vector `[c-25, n-25, timestamp_feature]`. Source stores a cast/truncated counter derived from `c-25`. Preserve rule IDs and both findings. |
| SA-05.orphan-first | Vectors: `insertOrphanFindings`: counter zero | Set root counter 50 and root timestamp to finding time; emit finding vector `[50,0,timestamp_feature]`. |
| SA-05.orphan-expired | Vectors: `insertOrphanFindings`: time beyond configured window | Reset root counter to 50 and root timestamp to finding time; emit the first vector again. Boundary equality is a separate case. |
| SA-05.orphan-neighbor | Vectors: `insertOrphanFindings`: active root | Query vector `[c-25,c-25,timestamp_feature]`, `k=100`, filtered to finding-pair rows in the inclusive symmetric time window. Inspect the first returned neighbor and its counter. |
| SA-05.orphan-current | Vectors: `insertOrphanFindings`: no matching neighbor counter | Emit `[c,c-50,timestamp_feature]` with the current counter. |
| SA-05.orphan-next | Vectors: `insertOrphanFindings`: matching neighbor counter | Advance root counter by 50; emit `[c+50,c,timestamp_feature]`. Preserve update/emission order through one checkpoint result. |
| SA-05.vector-validate | `security.correlation.neighbors`: `CorrelationVectorFieldMapper.getFloatsFromContext`; `LuceneFieldMapper.parseCreateField`; `CorrelationQueryBuilder` | Require finite `f32`, declared dimension, consistent query/candidate dimensions, valid k, and mapped vector field. Preserve missing-vector handling. |
| SA-05.similarity | Neighbors: `CorrelationParamsContext.parse`; `LuceneFieldMapper` | Source permits Lucene similarity enum values, with EUCLIDEAN default. Enumerate resolved Lucene functions and their normalization/preconditions in reference qualification. Return metric and score semantics with the declared model. |
| SA-05.index | Neighbors: `BasePerFieldCorrelationVectorsFormat.getKnnVectorsFormatForField`, `getMaxConnections`, `getBeamWidth`; versioned format classes | Source HNSW uses configurable `m` and `ef_construction`, or format defaults. A compiled package can keep versioned opaque index bytes or use an exact bounded scan. Declare the selected implementation and its numeric/recall limits. |
| SA-05.knn | Neighbors: `CorrelationQueryFactory.create` | `KnnFloatVectorQuery` with or without a delegated filter -> top-k neighbors and scores. Pin filter-before-search behavior, ties, approximate recall, and score tolerance. |
| SA-05.search | Neighbors: `TransportSearchCorrelationAction.AsyncSearchCorrelationAction.start` | Finding timestamp, root score epoch, and counter -> query vector `[c-25,c-25,(finding_time-score_epoch)/1000]` -> filtered nearest-neighbor pairs -> findings with scores. Exclude the query finding. |
| SA-05.rank-merge | Neighbors: `AsyncSearchCorrelationAction.start` | Pair endpoints -> finding/category keys. Keep the maximum hit score for each key and union its rule IDs. Source map iteration does not establish deterministic tie order. |
| SA-05.list | Neighbors: `TransportListCorrelationAction.AsyncListCorrelationAction.start` | Inclusive start/end time filter and nonempty pair endpoints -> finding/category pairs and rule IDs. Deduplicate by the source concatenated finding-pair key. Host admission and bounded reads remain required. |
| SA-05.encoding | Vectors/neighbors: `CorrelationVectorSerializer`, `CorrelationVectorAsArraySerializer`, `VectorField`; versioned codec classes | Preserve float-array values and dimensions. Source Lucene document-value and codec formats are infrastructure, not a required package wire format. A package checkpoint declares its own compatible encoding. |

The default source vectors have three dimensions. The field/query interfaces
permit a configured dimension. The SDK must not fix every vector at three.
Counter-to-float conversion loses integer precision at large values; record
and test that operation explicitly. It does not justify losing integer
precision elsewhere in the contract.

## Intended differences and required reference cases

- Source joins use one maximum window per category across rules. Qualify two
  overlapping rules with different windows and retain each rule's identity.
  A corrected per-rule window requires an explicit tested difference record.
- Source query-string construction inserts fetched field values into text.
  Local operators must preserve values without query injection. Test spaces,
  punctuation, escapes, multi-values, and malformed query strings.
- Source result reconstruction splits a combined log-type string at `-` and
  combines finding IDs with `:`. Local typed keys must preserve separate
  identity fields. Test values that contain those delimiters.
- Several multi-search loops skip failure without advancing their request
  index. Local failures must not associate a response with another category.
- Source search and vector limits can omit candidates. Local incomplete
  inputs and resource overflow must not produce a complete negative result.
- Root/index updates precede or follow vector writes in different branches.
  Local state and result datasets commit atomically under the host contract.
- Source trigger tasks read `Instant.now()` and produce random IDs. Local
  evaluation uses host time and declared deterministic identity/seed rules.
- Byte-identical approximate neighbor ranking is not established. Before
  qualification, pin the reference implementation, metric, recall/error
  tolerance, score formula, tie ordering, and empty/filter behavior.

## Tests and later closure

Source reference tests include `correlation/CorrelationEngineRestApiIT`,
`correlation/CorrelationEngineRuleRestApiIT`,
`correlation/alerts/CorrelationAlertServiceTests`, and
`correlation/alerts/CorrelationAlertsRestApiIT` under
[`src/test/java`](../../../../../security-analytics/src/test/java/org/opensearch/securityanalytics/).
The source has no dedicated `VectorEmbeddingsEngineTests` or
`CorrelationQueryFactoryTests` file at this revision.

Required local fixtures cover explicit query and field joins; category/time
counterexamples; automatic shared tags and shared intrusion sets; missing
documents; source-ID exclusion; all orphan branches; epoch boundaries; finite
and malformed vectors; metric/filter/k variants; ranking ties and tolerance;
replaced findings; replay; empty input; and failure/limit handling. A correlation
or neighbor match cannot establish causality or permission to prevent an action.
