# Security Indicator And Detector Operations

This is the indicator and detector operation record for the
[Security Analytics contract inventory](security-contract-inventory.md).
All listed ports and reference checks belong to 7.5.9 and are **Not done**.
The parent inventory supplies the common inputs, outputs, state, and host checks.

## Feed and schema calculation

Feed fetching, credentials, scheduler jobs, source configuration CRUD, index
rotation, and locks remain host operations. The calculations inside their
source adapters remain in scope. Supply exact feed bytes/rows and schema
revisions to `security.indicators.parse`.

| Operation ID | Source symbols | Required calculation and result |
| --- | --- | --- |
| SA-06.stix | `STIX2IOCFetchService.constructS3Connector`; `STIX2IOCConnectorFactory`; Commons `InputCodecFactory`; `STIX2IOC` constructors, `parse`, and `validate` | Supplied codec/schema input -> STIX indicator ID, name, type, value, severity, created/modified time, description, labels, spec version, feed ID/name, and version. Preserve invalid/required field rules and field provenance. Commons conversion is an external delegate. |
| SA-06.custom-json | `JsonPathAwareInputCodec.parse`; `JsonPathIocSchemaThreatIntelHandler.parseCustomSchema`, `parseCustomSchemaInternal` | Supplied JSON and pinned JSONPath schema -> aligned type/value/metadata lists and indicator rows. Jayway options are DEFAULT_PATH_LEAF_TO_NULL, ALWAYS_RETURN_LIST, and SUPPRESS_EXCEPTIONS. Preserve path grammar and parse coverage. |
| SA-06.json-values | `handleIocValueFieldParsing`, `nullOrBlank` | String/number scalar or list -> string indicator values. Skip blank/non-string/non-number list items; expand each retained value into a row. Preserve type/value alignment. |
| SA-06.json-strings | `parseStringListFromJsonPathNotation`, `isStringAndNonEmpty`, validation predicates | Missing/null/non-string optional metadata -> null; required ID/name replacement can generate identifiers. Reject absent/all-invalid type/value data and unequal type/value list lengths. Record skipped rows. |
| SA-06.json-times | `parseInstantListFromJsonPathNotation` | Supplied metadata strings -> ISO Instant values; failed or absent time values -> null in source. Preserve units and parse status. |
| SA-06.csv-reader | `ThreatIntelFeedParser.getThreatIntelFeedReaderCSV`, `validateUrl`; Commons CSV 1.10.0 | Supplied CSV bytes -> RFC4180 records with source charset/quote/delimiter behavior. URL validation/fetch is a host boundary; packages parse bytes only. |
| SA-06.csv-legacy | `ThreatIntelFeedDataService.parseAndSaveThreatIntelFeedDataCSV`, `isValidIp` | CSV records and legacy column configuration -> feed/type/value records. Source takes the first space-delimited token and can skip invalid IPv4-like values. Preserve configured columns and rejected row details. |
| SA-06.csv-current | `STIX2IOCFetchService.parseAndSaveThreatIntelFeedDataCSV` | Configured value column and first configured IOC type -> STIX records with generated ID/name, high severity, evaluation-created times, feed identity, and value token. Source IPv4 validation is a dotted-decimal regex without octet bounds. |
| SA-06.feed-replace | `STIX2IOCConsumer.accept`, `flushIOCs`, `buildIOCToActions`, `buildReplaceActions`; `STIX2IOCFeedStore.storeIOCs`, `indexIocs` | REPLACE feed snapshot -> UPSERT operations for retained indicators. Preserve batches and duplicate-key behavior. Host input revisions replace previous feed contributions; no package writes index aliases. |
| SA-06.feed-delta | `STIX2IOCConsumer.buildDeltaActions`; Commons `UpdateType` and `UpdateAction`; `STIX2IOCFeedStore.storeIOCs` | DELTA explicitly throws UnsupportedOperationException. Preserve a structured unsupported-mode result. Store DELETE is a no-op; UPSERT calls indexIocs; other actions fail. Do not claim a supported delta algorithm or silently accept deletions. |
| SA-06.type-inputs | `SATIFSourceConfigService.getIocTypeToIndices`; `LogTypeService.getIocFieldsList`; `ThreatIntelInput`, `PerIocTypeScanInput` | Enabled feed/type/source configuration and event schema -> indicator type to feed inputs and source-field mappings. Resolve as pinned host inputs; packages cannot select unauthorized feeds. |
| SA-06.feed-metadata | `BuiltInTIFMetadataLoader`; `DefaultTifSourceConfigLoaderService`; `SourceConfigDtoValidator.validateSourceConfigDto`; `ParameterValidator.validateTIFJobName` | Pinned built-in metadata and source schema -> validated parse/refresh/type configuration. Source names and upload/download settings are data; external credentials and source lifecycle remain host-owned. |

Use
[JsonPathIocSchemaThreatIntelHandler](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/threatIntel/service/JsonPathIocSchemaThreatIntelHandler.java),
[STIX2IOCFetchService](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/services/STIX2IOCFetchService.java),
and
[STIX2IOCConsumer](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/services/STIX2IOCConsumer.java)
as the source reading route. Parsing can produce more output rows than input
rows. Required metadata defaults need supplied evaluation time and identity/seed
rules. A package must not fetch a source to fill a missing input.

## Indicator extraction, matching, findings, and triggers

The source reading route is
[TransportThreatIntelMonitorFanOutAction](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/threatIntel/model/monitor/TransportThreatIntelMonitorFanOutAction.java),
[IoCScanService](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/threatIntel/iocscan/service/IoCScanService.java),
[SaIoCScanService](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/threatIntel/iocscan/service/SaIoCScanService.java),
and
[ThreatIntelMonitorUtils](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/threatIntel/util/ThreatIntelMonitorUtils.java).

| Operation ID | Export and source symbols | Required calculation and state |
| --- | --- | --- |
| SA-06.documents | `security.indicators.match`: `TransportThreatIntelMonitorFanOutAction.onGetIocTypeToIndices`, `fetchDataFromShards`, `fetchLatestDocsFromShard`, `searchShard` | Source uses per-shard sequence progress and index/field restrictions to select documents. Host extraction supplies exact authorized rows, source-window/progress revision, and coverage. Preserve late/new document membership; do not copy shard authority into packages. |
| SA-06.extract | Match: `IoCScanService.extractIocsPerType`; `SaIoCScanService.getValuesAsStringList`, `getIndexName`, `getId` | Per-type mapped event fields -> unique values by type; value-to-document references; document-to-values. Preserve scalar/list values, empty fields, and exact source identity. |
| SA-06.join | Match: `SaIoCScanService.matchAgainstThreatIntelAndReturnMaliciousIocs`, `performScanForMaliciousIocsPerIocType`, `getSearchRequestForIocType` | Event values and feed rows -> exact terms join on value plus IOC type. Type/field/feed maps are named inputs. No fuzzy-match behavior is implemented by the source TODO. |
| SA-06.batches | Match: `getGroupSizeForIocs`, `getGroupedListenerForIocScanPerIocType`, `getGroupedListenerForIocScanFromAllIocTypes`, `buildException` | Bounded type/value batches -> collected indicator matches and structured failures. Local missing/failed batches report incomplete coverage. They cannot pass as a clean negative scan. |
| SA-06.finding | Match: `IoCScanService.createIocFindings`; `IocWithFeeds`; `IocFinding` | Matched indicators -> grouped value/type findings, related documents, unique feed memberships, monitor identity, time, and evidence. Preserve all source/feed memberships. Local result identity uses declared deterministic inputs, not hidden UUID generation. |
| SA-06.trigger-filter | `security.detectors.decide`: `ThreatIntelMonitorUtils.getTriggerMatchedFindings`; `SaIoCScanService.executeTriggers`, `executeTrigger` | Findings and trigger type/source lists -> matching findings. Empty type list means all types; empty data-source list means all sources. Nonempty source list uses any related source; combine type and source predicates with AND. |
| SA-06.prior-alerts | Decide: `getSearchSourceBuilderForExistingAlertsQuery`; `SaIoCScanService.fetchExistingAlertsForTrigger` | Prior alert rows -> ACTIVE or ACKNOWLEDGED rows for trigger and exact value/type. Host supplies prior state; it keeps acknowledgement authority. |
| SA-06.update-alert | Decide: `ThreatIntelMonitorUtils.prepareAlertsToUpdate` | Existing value/type alert and matching findings -> candidate updated finding membership. Source appends finding IDs; qualify duplicate and replacement behavior. |
| SA-06.new-alert | Decide: `ThreatIntelMonitorUtils.prepareNewAlerts`; `SaIoCScanService.saveAlertsAndExecuteActions` | Unmatched prior value/type keys -> new ACTIVE alert candidates with trigger severity, monitor/source identity, time, and finding membership. Notification and persistence remain host operations. |
| SA-06.legacy-queries | `security.indicators.match`: `DetectorThreatIntelService.createDocLevelQueriesFromThreatIntelList`, `buildQueryStringQueryWithIocList`, `constructId` | Log-type IOC field declarations and feed values -> one document-level query per declared field/type, with threat-intel, type, field, and feed tags. Preserve legacy query mode separately from exact type/value scan. |

The type is data from the pinned schema/feed, not a hard-coded SDK enum. The
source delegates additional STIX/codec type definitions to Security Analytics
Commons. Later imports must enumerate the resolved supported types and reject
unknown types with the exact source/feed/schema identity.

## Detector, monitor, finding, and alert composition

These operations use `security.detectors.decide`. Rule parsing, evaluation,
aggregate computation, and indicator matching remain the shared exports above.
Installation, monitor scheduling, durable alert state, acknowledgement, and
delivery are existing host responsibilities.

| Operation ID | Source symbols | Required calculation and boundary |
| --- | --- | --- |
| SA-07.rule-load | `RuleIndices.getRules`, `loadQueries`, `getRuleCategory`, `ingestQueries`, `getQueries`; `TransportIndexRuleAction`; `TransportIndexDetectorAction.importRules`, `importCustomRules` | Built-in files/custom rules -> selected rule IDs, category, parsed queries, tags, levels, field requirements, and source revisions. Account for every file variant; installation supplies pinned assets. |
| SA-07.partition | `createMonitorFromQueries`, `updateMonitorFromQueries`, `createDocLevelMonitorRequest`, `buildBucketLevelMonitorRequests`, `createBucketLevelMonitorRequest`; `Rule.isAggregationRule`, `getAggregationItemsFromRule` | Partition ordinary rules and aggregate rules. Document queries retain rule ID/title and category/level/rule tags; bucket rules use their first aggregate/query in the source. Multiple conditions and aggregates require explicit reference cases. |
| SA-07.threat-intel | `addThreatIntelBasedDocLevelQueries`; `DetectorThreatIntelService` | Detector enabled flag and log-type IOC fields -> optional additional threat-intel document queries. This uses pinned feed input; no automatic live feed access. |
| SA-07.trigger | `DetectorTrigger.convertToCondition` | Within each configured type/ID/severity/tag list, combine query predicates with OR; combine nonempty lists with AND. Threat-intel detection adds OR with `query[tag=threat_intel]`. Default detection type is rules. Retain empty-filter behavior as a reference case. |
| SA-07.chained-trigger | `DetectorTrigger.convertToConditionForChainedFindings` | Same predicates, but rule IDs use query tags instead of query IDs. This is a distinct source variant. |
| SA-07.aggregate-selection | `DetectorUtils.getAggRuleIdsConfiguredToTrigger`, `checkIfRuleIsAggAndTriggerable`, `getBucketLevelMonitorIds`; `shouldAddChainedFindingDocMonitor` | Select aggregate rules by configured rule IDs or matching tags; identify bucket monitor dependencies and whether a chained document monitor is needed. |
| SA-07.chained-documents | `createDocLevelMonitorMatchAllRequest`; `WorkflowService.upsertWorkflow`, `createWorkflowRequest` | Bucket finding membership -> selected match-all source documents tagged with contributing rule IDs/category/level/tags. Preserve ordering of ordinary/bucket delegates and final chained monitor. |
| SA-07.document-delegate | Alerting `DocLevelMonitorInput`, `DocumentLevelTrigger`, `AlertingPluginInterface.indexMonitor`; `ThreatIntelMonitorRunner` | Document query evaluation -> matched query IDs/tags and related source documents -> trigger predicate. Explicit local semantic implementation and reference fixtures are required; registering an upstream monitor is not a local implementation. |
| SA-07.bucket-delegate | Alerting `SearchInput`, `BucketLevelTrigger`, `ChainedMonitorFindings`, `Workflow` | Matching buckets and chained source documents -> findings and trigger candidates. Preserve dependency membership, empty results, windows, retries, and error results without adding a scheduler service. |
| SA-07.finding-read | `FindingsService.getBoolQueryBuilder`, `mapFindingWithDocsToFindingDto`; `FindingDto` | Detection type/severity/finding-ID/time filters -> selected findings with detector and source-document metadata. Existing host read APIs own authorization and references. |
| SA-07.alert-read | `AlertsService.getBoolQueryBuilder`, `mapAlertToAlertDto`; `AlertDto` | Monitor/detector/time filters -> alert rows with detector and trigger identity. Host reads and notification policy remain authoritative. |
| SA-07.template | `DetectorTrigger.getActions`; `NotificationService.compileTemplate`; correlation/IOC template context classes | Detector-to-monitor template field conversion and supplied finding/trigger data -> notification candidate fields. Rendering/delivery/credentials stay in NotificationRouter; a package cannot execute an action. |

## Source defects and required difference records

- `IoCScanService` groups document/feed/type data by value alone in several
  maps. Two IOC types with one value can collide. Local typed keys must carry
  value and type separately; test this change and record the difference.
- Source document identity uses `id + ":" + index`, then splits on `:` for
  trigger source filters. Local identities must preserve separate fields.
- `DetectorThreatIntelService` groups values by type but builds each legacy
  query from the unfiltered set of all values. Test mixed types and preserve
  the corrected behavior through an explicit difference record.
- `DetectorTrigger` appends the separator for multiple tags to the severity
  builder. Test multiple-tag triggers before translating this calculation.
- Custom JSON parsing checks equal type/value list lengths before its intended
  one-type/many-values branch. Test alignment and report exact rejected cases.
- Source skips invalid rows, failed parses, shard failures, and partial batches
  in several paths. Local coverage/errors must record those omissions.
- Source uses current time and random IDs for parsed indicators, findings, and
  alerts. Local fixture/replay results must use declared time and identity rules.
- Source scan treats notification failure after saved findings as successful
  scan progress. Preserve finding idempotence; let the notification owner retain
  and retry its delivery obligation.

## Tests and later closure

Use source reference tests under
[`src/test/java`](../../../../../security-analytics/src/test/java/org/opensearch/securityanalytics/):
`DetectorThreatIntelIT`; `model/STIX2IOCTests`, `STIX2IOCDtoTests`,
`DetailedSTIX2IOCDtoTests`, `IocFindingTests`, `threatintel/ThreatIntelAlertTests`;
`threatIntel/util/ThreatIntelFeedParserTests`; `threatIntel/model/JsonPathIocSchemaTests`,
`ThreatIntelSourceTests`, `monitor/ThreatIntelInputTests`;
`resthandler/CustomSchemaSourceConfigIocUploadIT`, `ThreatIntelAlertIT`,
`ThreatIntelMonitorRestApiIT`, `DetectorMonitorRestApiIT`, `DetectorRestApiIT`,
`OCSFDetectorRestApiIT`; and `threatIntel/integTests/ThreatIntelJobRunnerIT`.

Required local fixtures cover each parser mode and schema path; scalar/list and
missing/null fields; invalid/misaligned metadata; all resolved IOC types;
type/value collisions; feed replace/delta and removed indicators; all trigger
filter combinations; prior ACTIVE/ACKNOWLEDGED state; ordinary/bucket/chained
rule decisions; positive and negative predicates; replay; empty input;
incomplete/failing batches; notification candidate validation; and missing live
input. Tests of upstream REST storage are reference checks, not a requirement
to port that service.
