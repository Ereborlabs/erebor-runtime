# Security Analytics Contract Inventory

This inventory records the portable inputs, results, and state that the SDK
must carry for the pinned Security Analytics source. It supports
[7.5.2](phase-7-5-2-analysis-contract-and-sdk.md). Algorithm implementation and
reference qualification belong to [7.5.9](phase-7-5-9-security-analytics-algorithms.md).

## Source and result

The source is the tracked `security-analytics/` checkout at
`e33c62506efcb15ae795847484357704b539bcf1`. The audit date is 2026-10-10. The
checkout has 3,005 tracked files, including 414 production Java files, two
ANTLR grammars, and 2,326 rule files. Untracked `bin/` output is excluded.

**Done:** the source accounting and rule metadata reports identify every
tracked file. The operation tables identify the analysis paths, helper
operations, source variants, delegated calculations, inputs, outputs, and
state requirements. **Not done:** Rust algorithm ports, JVM reference runs,
installed-package execution, rule compatibility, and live input qualification.
This inventory does not claim those results.

Read these records together:

- [Rule and aggregate operations](security-rule-semantics.md).
- [Explicit correlation, automatic correlation, and vectors](security-correlation-semantics.md).
- [Indicators, detector composition, and monitor decisions](security-indicator-semantics.md).
- [Tracked source accounting](security-source-accounting.tsv): one row for each
  tracked file outside the rule corpus. Each row states its semantic owner or
  exclusion, declared symbols, local references, and external dependencies.
- [Rule metadata](security-rule-inventory.ndjson): one row for each tracked rule
  file. Each row records the source rule ID, category, conditions, required
  fields, modifier chains, value types, metadata, and remaining checks.

File counts prove accounting only. Java declaration and import scans do not
prove a runtime call graph. The operation tables trace the analysis entry
points and their local calculation helpers. External calls are recorded below;
their implementation and reference checks remain with 7.5.9.

## Entry points and calculation paths

| Entry point | Required local calculation path | Operation record |
| --- | --- | --- |
| `RuleIndices.getQueries`; `TransportIndexRuleAction`; `TransportValidateRulesAction` | `SigmaRule.fromYaml` -> `SigmaDetections.fromDict` -> `SigmaDetection.fromDefinition` -> `SigmaDetectionItem.fromMapping` -> modifier chain -> condition and aggregate visitors -> `QueryBackend.convertRule` -> `OSQueryBackend`. | SA-01 and SA-02 in the rule record. |
| `TransportIndexDetectorAction.createMonitorFromQueries`, `updateMonitorFromQueries` | Built-in/custom rule selection -> field applicability -> document or bucket monitor composition -> `DetectorTrigger` conditions -> optional workflow and chained finding composition. | SA-07 in the indicator record. |
| `TransportCorrelateFindingAction.doExecute` | Detector and finding lookup -> `JoinEngine.onSearchDetectorResponse` -> automatic tags or explicit source-document filters -> finding joins -> trigger decisions -> timestamp feature and vectors. | SA-03, SA-04, and SA-05 in the correlation record. |
| `TransportSearchCorrelationAction.doExecute` | Root and neighbor vectors -> filtered `CorrelationQueryBuilder` -> Lucene nearest-neighbor calculation -> score and source finding reconstruction. | SA-05 in the correlation record. |
| `TransportListCorrelationAction.doExecute` | Category, finding-pair, timestamp, and score filters -> pair result construction. | SA-05.list in the correlation record. |
| `STIX2IOCFetchService.onlyIndexIocs`, `downloadAndIndexIOCs` | Supplied STIX, custom JSONPath, or CSV data -> indicator records -> replace/delta operations in `STIX2IOCConsumer`. | SA-06 in the indicator record. |
| `TransportThreatIntelMonitorFanOutAction.doExecute` | Shard revision and document selection -> field extraction -> `IoCScanService.scanIoCs` -> per-type indicator join -> findings -> trigger filter and prior-alert decisions. | SA-06 in the indicator record. |
| `DetectorThreatIntelService.createDocLevelQueriesFromThreatIntelList` | Log-type indicator fields -> feed values -> document query construction -> document monitor execution. | SA-06.legacy and SA-07 in the indicator record. |

## Minimal package interface requirements

These are datasets and ordinary computation. They require no package callback
to OpenSearch, a live feed, a scheduler, or a notification service.

| Required export | Named inputs | Named outputs | Prior and next state |
| --- | --- | --- | --- |
| `security.rules.evaluate` | Typed event rows; pinned rules; field mappings; schema and log-type metadata. | Rule/event matches; rejected or unavailable rules; evidence and mapped-field details. | Rule/mapping revision and any event progress state. |
| `security.rules.aggregate` | Matches or events; aggregate definitions; exact evaluation window. | Groups, typed aggregate values, thresholds, matching members, and evidence. | Group state when an implementation uses incremental evaluation. |
| `security.findings.correlate` | Findings; their related documents; explicit rules; log types; optional pinned ATT&CK intrusion-set data. | Explicit and automatic correlations; source findings; rule IDs; correlation kind; trigger candidates. | Window contributions and any prior trigger state. |
| `security.correlation.vectors` | Findings/correlations; log-type correlation IDs; prior counters and historical vectors. | Finding and finding-pair vectors; counter and time metadata. | Root counters, root timestamps, score epoch, and optional index state. |
| `security.correlation.neighbors` | Query vectors; candidate vectors; category, time, and finding filters. | Ranked neighbors, scores, finding pairs, and evidence references. | Optional compiled index state. Exact scan needs no index state. |
| `security.indicators.parse` | Bounded feed bytes or rows; pinned feed schema and metadata. | Indicators, replace records, rejected rows, parse coverage, and unsupported-mode errors. | Feed revision. The pinned source rejects DELTA; it does not supply a delta algorithm. |
| `security.indicators.match` | Typed events; field/type mappings; pinned indicators. | Typed indicator matches, source/feed membership, findings, and evidence. | Any incremental join state and input progress. |
| `security.detectors.decide` | Rule/indicator matches; detector and trigger definitions; prior decision state; optional aggregate/chained findings. | Finding and alert candidates, reasons, details, and evidence references. | Decision state only. Host owners retain notification and acknowledgement state. |

Several source operations can share one export. The operation IDs in the
supporting tables remain separate verification items. These names identify the
exports that 7.5.9 must implement; they do not add an SDK API for each operation.

The contract must carry these values without implicit loss:

- Missing fields and present null fields, scalar and list values, and nested
  records. Preserve multivalue membership for rules, tags, document references,
  fields, and feed membership.
- Exact signed/unsigned integers, finite `f32` vectors, finite `f64` aggregate
  values, timestamp units, and opaque bytes. A three-element `f32` vector can
  use a fixed-size list. A general vector can use a list with declared dimension.
- Exact rule, mapping, feed, intrusion-set, source-window, and prior-state
  revisions. Include an evaluation time and seed when generated values need
  them. A package must not read the wall clock or use an undeclared random seed.
- Multiple inputs and output row counts that can differ from every input.
  Preserve evidence sets and many-to-many source membership.
- Bounded complete inputs, explicit incomplete coverage, structured errors,
  and typed versioned checkpoints. A checkpoint can contain opaque index bytes
  in a declared binary field. The package owns the byte format and version.
- Ordering, numeric precision, permitted error, and tie rules in schema or
  model metadata. Approximate search and median absolute deviation need
  explicit qualification limits. They cannot silently become exact results.

An Arrow schema can represent these requirements with existing integer, float,
timestamp, UTF-8, binary, struct, list, and fixed-size-list types. The computation
contract does not require a second rule language or a new host service.

## Delegated calculations and target constraints

| Delegate used by the pinned caller | Required local semantics | Later target and proof |
| --- | --- | --- |
| OpenSearch `queryStringQuery`, `matchQuery`, `termsQuery`, `existsQuery`, `rangeQuery`, nested Boolean queries, and the rule analyzer | Escaping, token and case behavior, typed comparisons, missing/null/multivalue behavior, timestamp boundaries, and correlation document filters. | SQL or compiled package. Pin field/analyzer assumptions and compare reference fixtures. Reject unsupported query syntax. |
| OpenSearch metric and terms aggregations; Alerting `BucketSelectorExtAggregationBuilder` | Value-count versus document-count, grouping, missing values, multivalue contributions, numeric reductions, bucket selection, threshold comparisons, and MAD approximation. | SQL or compiled package. Test all builder variants, including variants absent from the bundled corpus. |
| Lucene `KnnFloatVectorQuery`, `KnnFloatVectorField`, similarity functions, and HNSW formats | Finite fixed-dimension vectors; filtered top-k selection; similarity scores; approximate recall, ranking, ties, and index parameters. | Compiled package with portable or qualified native dependencies. A bounded exact scan is permitted with an explicit difference record and tests. No vector service. |
| ANTLR grammars, SnakeYAML, Java `Pattern`, Base64, and charset conversion | The exact registered syntax and transformations in the rule record. | Import/build library or compiled runtime operator as needed. Operators do not need a JVM. |
| Jayway JSONPath 2.9.0 and Commons CSV 1.10.0 | Supplied-byte parsing, path selection, scalar/list extraction, record splitting, default metadata, invalid rows, and parse coverage. | Compiled package or shared importer with the same descriptor. Credentials and fetching stay in the host. |
| Security Analytics Commons 1.0.0; OpenSearch Common Utils/Alerting SPI from the build | STIX conversion and codec assumptions; document monitor query evaluation; trigger query-ID/tag predicates; bucket/chained finding membership. | Explicit semantic implementation and reference checks. External implementations are not in this checkout; caller contracts are recorded in the supporting tables. |

`build.gradle` selects OpenSearch `3.8.0-SNAPSHOT` by default and permits build
overrides. It does not pin a unique snapshot artifact revision. Later reference
runs must record their resolved OpenSearch, Lucene, Common Utils, Alerting, and
Commons artifact revisions. The source revision alone cannot prove delegated
binary parity. This is a reference qualification requirement, not a missing
SDK datatype.

## Host checks and intended differences

All exports consume host-selected, authorized, pinned inputs. The host checks
tenant, source, node, sensitivity, evidence identity, source lifetimes, coverage,
resource limits, cancellation, checkpoint compatibility, and result references.
`GraphAndFindingOwner` checks findings and proof limits. `AnalysisStore` owns
atomic result and progress commits. `NotificationRouter` owns delivery.

Source code can skip failed shards, accept partial batches, truncate searches,
read the wall clock, create random IDs, or log errors after successful findings.
Packages must report incomplete input or failure and preserve the host retry
contract. They must not turn partial execution into a clean negative result.

The supporting tables record source defects and required review cases. Those
cases do not authorize silent behavioral changes. Before a port is qualified,
7.5.9 must record the tested intended difference. It must retain algorithm
coverage even when a source defect needs a local correction.

## Corpus accounting and verification

Every tracked YAML file was structurally parsed with PyYAML `safe_load`. All
2,326 parsed. There are 2,221 distinct rule IDs and 104 groups with repeated
IDs. Seven files contain a condition list. Thirty-three declare a timeframe.
Eight of the 14 registered modifier names occur in the corpus; no unregistered
modifier name occurs. No bundled condition contains the source aggregate
separator ` | `. There are 307 distinct detection field names.

The report preserves each file variant. Rule ID alone does not identify an
import when the same ID occurs under different log types. Use source revision,
tracked path, category, and rule ID. Fields in a negative branch remain input
requirements: missing proof must not make that branch pass.

No rule declares an explicit `license` field. The checkout contains Apache-2.0
`LICENSE` and `NOTICE` files. The report records those source notices and the
absence of rule-specific metadata. Package construction must retain source
notices and resolve rule attribution before release.

Structural parse is not Sigma parse, mapping, execution, or compatibility proof.
Each report row keeps those checks `Not done`. 7.5.9 must fill them from committed
positive and negative operator fixtures and the required package cases. Missing
deployment fields are a separate availability result.

The inventory check compared all report paths to `git ls-files`, checked the
pinned revision and unchanged tracked source, counted rule IDs and variants,
checked registered modifier names, and checked document links. No source was
changed and no Java runtime or performance test was run.

## End scope and example

This record is complete when every tracked source and rule file is accounted
for and each analysis operation has an input, output, state, host boundary, and
later verification owner. It stops before algorithm development and package
activation.

Example: `security.findings.correlate` consumes two authorized findings, their
related event rows, and a pinned rule with a 60-second window. Its output can
refer to both findings and the rule revision. An empty replacement input can
remove that correlation. A schema, evidence, or checkpoint error rejects the
complete evaluation. The package cannot send a notification or claim causal
proof.
