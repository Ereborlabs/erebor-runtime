# Algorithm Coverage Inventory

Track the algorithms that must run through the SDK and package system. This
inventory supports [7.5](README.md); the linked child phases own implementation.
Review date: 2026-10-09. Implementation of these migrations and ports: **Not done**.

## Source boundaries

| Source | Local revision examined | Development owner |
| --- | --- | --- |
| Current Araphor | `1b08236077223bb1e9b32ae36df78778a674c4cf` | [7.5.2 SDK migration](phase-7-5-2-analysis-contract-and-sdk.md#current-algorithm-migration); [7.5.4 installed Wasm execution](phase-7-5-4-wasm-execution.md#current-algorithm-migration) |
| Discovery Engine | `0b5b73425c5aec89b803e737b188b2a331d0e218` | [7.5.8 algorithm packages](phase-7-5-8-discovery-engine-algorithms.md) |
| OpenSearch Security Analytics | `e33c62506efcb15ae795847484357704b539bcf1` | [7.5.9 algorithm packages](phase-7-5-9-security-analytics-algorithms.md) |

The upstream algorithm scope includes all analysis behavior in these pinned
sources, including helpers and delegated computation required by their public
analysis entry points. It does not mean all future upstream features. Source
revision changes require an inventory delta. The Security Analytics checkout has
an untracked `bin/` directory; this inventory uses tracked source only.

The tables below identify source families. The contract requirements audit is
**Done** on 2026-10-10. Use the detailed records below for individual algorithms,
variants, delegated operations, inputs, outputs, state, host checks, package
exports, execution constraints, and expected differences:

- [Current Araphor records](current-contract-inventory.md) cover AR-01 through
  AR-07 and identify the operations that remain host-owned.
- [Discovery Engine records](discovery-contract-inventory.md) cover the complete
  tracked source tree and 58 computation records, including retained variants.
- [Security Analytics records](security-contract-inventory.md) cover the complete
  tracked source tree, delegated computations, and all 2,326 rule files.

These records establish interface requirements. They do not prove computation
parity or installed-package execution. Keep exact source symbols, fields,
schemas, state, dependencies, exports, targets, differences, and test results
with each later port. Check the full source tree and reachable delegated
operations when the pinned source changes.
Phases 7.5.8 and 7.5.9 verify the inventory against the pinned source, implement
the declared exports, and fill in verification results. A new contract gap must
be resolved and the affected runtimes checked before its package is qualified.

Separate algorithm implementation from live input readiness. A tested algorithm
can report Unsupported when a deployment lacks its input. That result is not a
test of the algorithm's positive path. Missing implementations or semantic
variants remain Not done; they cannot be relabeled as unsupported input to close
the phase. A scope reduction needs an explicit recorded decision.

## Current Araphor algorithms

All rows belong to 7.5.2 for SDK conversion, production adapters, and equivalence
through trusted Rust calls. That migration is **Not done**. Installed Wasm
execution and dispatch replacement belong to 7.5.4 and are also **Not done**.
For AR-04, migration means integration with the shared host selector through the
SDK input contract. Authorization and trusted selection stay in that host owner.

| ID | Behavior and source | Migration boundary |
| --- | --- | --- |
| AR-01 | [DiscoveryOwner::derive_recorded](../../../../../crates/araphor-data/src/discovery/derive.rs): exact atoms, counts, evidence samples, unresolved and excluded records, coverage and lifecycle accounting. | Reuse computation as a package model; keep source and result validation in the host. |
| AR-02 | [BehaviorSnapshotV1::merge and display_groups](../../../../../crates/araphor-data/src/discovery/derive.rs). | Preserve exact merge behavior, deterministic groups, and input references. |
| AR-03 | [BehaviorSnapshotV1::compare](../../../../../crates/araphor-data/src/discovery/derive.rs): baseline differences, forbidden groups, outcome and identity changes. | Keep baseline review authority in the host; return typed comparison datasets. |
| AR-04 | [DiscoveryOwner::select_context](../../../../../crates/araphor-data/src/discovery/context.rs): time cutoff, selection order, conflicts, omissions, and missing facts. | Reuse the host selector as the SDK context input. Packages cannot override permissions, trust, or history cutoff. |
| AR-05 | [HF-PROC-001](../../../../../crates/araphor-data/src/graph/derive.rs): native process/file analysis and context-only classifications. | Preserve qualified effects, relationships, findings, limits, and evidence. |
| AR-06 | [HF-DW-001](../../../../../crates/araphor-data/src/graph/derive.rs): credential and local-channel joins. | Preserve exact identity requirements, contextual branches, and missing proof. |
| AR-07 | [HF-XNODE-001](../../../../../crates/araphor-data/src/graph/derive.rs): implemented Kubernetes request-to-admission state. | Preserve current unqualified causality. Later Kubernetes proof remains with its existing phase. |

Shared graph validation, identity construction, proof checks, window selection,
expiration, result assembly, storage, and notification routing remain production
owner operations. The 7.5.2 migration exercises them through shared SDK code
called by existing production owners. Phase 7.5.4 repeats those checks through
installed packages. Do not copy these checks into independently trusted plugin
implementations.

## Discovery Engine algorithms

All rows belong to 7.5.8 and are **Not done**. Names describe computation; no
row grants permission to apply the inferred policy.

| ID | Required family | Source to enumerate |
| --- | --- | --- |
| DE-01 | System behavior discovery: filtering, workload grouping, process/file/protocol sets, source constraints, and candidate rules for Kubernetes and VM inputs. | [systemPolicy.go](../../../../../discovery-engine/src/systempolicy/systemPolicy.go), [system helpers](../../../../../discovery-engine/src/systempolicy/helperFunctions.go). |
| DE-02 | File and directory path trees, recursive aggregation, directory merging, and duplicate paths. | [common/pathAggregator.go](../../../../../discovery-engine/src/common/pathAggregator.go). |
| DE-03 | Network discovery: ingress/egress, L3/L4 and L7, source/destination label aggregation, namespace grouping, protocol/port merging, CIDR, FQDN, entities, DNS, and service/endpoint resolution. | [networkPolicy.go](../../../../../discovery-engine/src/networkpolicy/networkPolicy.go), [network helpers](../../../../../discovery-engine/src/networkpolicy/helperFunctions.go). |
| DE-04 | HTTP method/path trees, numeric path segments, wildcard aggregation, and equivalent child merging. | [httpAggregator.go](../../../../../discovery-engine/src/networkpolicy/httpAggregator.go). |
| DE-05 | Duplicate and overlap detection, incremental candidate merging, and stable policy identity for system and network candidates. | [system deduplicator](../../../../../discovery-engine/src/systempolicy/deduplicator.go), [network deduplicator](../../../../../discovery-engine/src/networkpolicy/deduplicator.go), network policy merge functions. |
| DE-06 | Process/file/network summaries, workload aggregation, ingress/egress summaries, and system/network insight construction. | [observability](../../../../../discovery-engine/src/observability/), [insight](../../../../../discovery-engine/src/insight/). |
| DE-07 | Template matching, hardening recommendations, admission patterns and preconditions, and service-account token automount analysis. | [recommendpolicy](../../../../../discovery-engine/src/recommendpolicy/), [admissionControllerPolicy.go](../../../../../discovery-engine/src/admissioncontrollerpolicy/admissionControllerPolicy.go). |
| DE-08 | Recorded-log policy analysis and semantic conversions between generic candidates and KubeArmor, Cilium, and Kubernetes network policy forms. | [analyzer](../../../../../discovery-engine/src/analyzer/), [plugin converters](../../../../../discovery-engine/src/plugin/). |

Use pinned template data and qualified inventory/DNS inputs. Do not make package
code call Kubernetes, resolve live DNS, download templates, or write policies.
Transport and database adapters are host infrastructure. Preserve any analysis
semantics inside those adapters in the appropriate package or shared input
adapter. Exported candidate policy text is a review artifact; it is not active
policy or a guarantee of least privilege.

## Security Analytics algorithms

All rows belong to 7.5.9 and are **Not done**. The tracked rule corpus contains
2,326 YAML files at the pinned revision. File count is not a rule execution or
compatibility result; inventory rule IDs and variants separately.

| ID | Required family | Source to enumerate |
| --- | --- | --- |
| SA-01 | Rule parsing and evaluation: Boolean conditions, selectors, typed values, field existence, nulls, wildcards, regex, CIDR, string/encoding modifiers, comparisons, and log-field mapping. | [rules](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/rules/), [mapper](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/mapper/), [logtype](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/logtype/). |
| SA-02 | Grouped and time-bounded rule aggregates, thresholds, count, average, min/max, sum, terms, and median absolute deviation. | [AggregationBuilders](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/rules/backend/AggregationBuilders.java), [OSQueryBackend](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/rules/backend/OSQueryBackend.java). |
| SA-03 | Explicit multi-source finding correlation, time windows, category/query filters, and correlation trigger conditions. | [JoinEngine](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/JoinEngine.java), [correlation alerts](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/alert/). |
| SA-04 | Automatic correlation from ATT&CK tags and intrusion-set mappings. | [JoinEngine](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/JoinEngine.java), [AutoCorrelationsRepo](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/util/AutoCorrelationsRepo.java). |
| SA-05 | Correlation feature-vector construction, orphan handling, filtered nearest-neighbor search, and associated score/ranking behavior. | [VectorEmbeddingsEngine](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/VectorEmbeddingsEngine.java), [correlation index/query](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/correlation/index/query/), correlation transport callers. |
| SA-06 | Threat-feed value/schema extraction, indicator normalization and matching by type, finding construction, and threat-intelligence trigger evaluation. | [threatIntel](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/threatIntel/), including `IoCScanService`, `SaIoCScanService`, and `JsonPathIocSchemaThreatIntelHandler`. |
| SA-07 | Built-in and custom rule loading, detector-to-rule/monitor composition, and finding/alert decision semantics delegated to the upstream alerting engine. | [rule corpus](../../../../../security-analytics/src/main/config/rules/), [DetectorMonitorConfig](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/config/monitors/DetectorMonitorConfig.java), [services](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/services/), [findings](../../../../../security-analytics/src/main/java/org/opensearch/securityanalytics/findings/). |

Enumerate all supported modifier and aggregate variants at the pinned source.
Do not claim support for every Sigma version or rule language feature. Preserve
source metadata, licence, rule ID, and required fields when importing the corpus.
Missing Windows, cloud, or other input fields must be reported; one available
Linux event stream cannot satisfy every rule's required evidence.

Correlation vectors here are algorithm data, not an AI model service. Reuse the
package contract and AnalysisStore for their state. Correlation, similarity, and
indicator matches cannot create causal or prevention proof. Alert decisions
must still pass Araphor's mandatory notification and authority checks.

## Coverage closure

Keep one checklist per source algorithm or variant under its family above. Map
upstream source and tests to package exports and committed Rust or platform
tests. Record both computation parity and live-input readiness. A missing live
adapter does not remove the algorithm from the implementation checklist.

Done requires every in-scope algorithm to have implementation, positive and
negative semantic tests, installed-package execution, replay and failure checks,
and exact source/package revisions. Record numerical tolerances and intended
security differences explicitly. Reuse one implementation when an upstream
family matches an existing algorithm; record the mapping and test it.
For current algorithms, record 7.5.2 computation equivalence separately from
7.5.4 installed execution and 7.5.7 integrated qualification. Completing the
SDK conversion alone does not close installed-package coverage.

Upstream HTTP, gRPC, OpenSearch storage, schedulers, installers, cluster clients,
and dashboards are not additional services to port. Existing Araphor owners
supply these boundaries. Algorithm calls delegated to those services still need
an explicit semantic mapping; infrastructure exclusion cannot conceal a missing
computation. Full upstream product compatibility is a separate claim.
