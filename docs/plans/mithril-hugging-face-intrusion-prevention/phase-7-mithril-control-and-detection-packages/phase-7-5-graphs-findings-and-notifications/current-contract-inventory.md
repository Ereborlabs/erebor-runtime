# Current algorithm contract inventory

This record expands the current Araphor rows in [the coverage index](algorithm-coverage.md).
The [contract and SDK](phase-7-5-2-analysis-contract-and-sdk.md) use these requirements.
The [current migration](phase-7-5-4-wasm-execution.md) implements these exports later.

## Source and result

The computation baseline is `1b08236077223bb1e9b32ae36df78778a674c4cf`.
The audit also checks the current checkout at `9948327a`. Native graph storage
and traversal changed after the baseline. The computation entry points below
retain their owners and meaning. The audit reads each entry point, its helpers,
its model validation, and its tests. It does not run a package or replace dispatch.

**Done:** identify the contract requirements and migration boundaries.
**Not done:** migrate any computation to installed package execution.
Every row below belongs to the current migration owner. The target is Rust
computation with the default Wasm binding and a qualified native binding.
The host context selector remains a host operation.

## Inputs and outputs

Use exact field names and types from the linked source models. Do not copy
their Rust types into the SDK. A host adapter supplies typed relations or a
bounded binary field with its owner, type, and encoding in schema metadata.
The host decodes and validates that field before it accepts a domain result.

| Dataset | Required information |
|---|---|
| `records` | Every `DiscoveryRecordV1` field: full stream, CPU, durable cursor, original kernel sequence, and `wire_record` bytes. Store position and received time remain host manifest or context fields. The decoded `EvidenceRecord` retains decisions, reason, effect, operation, object, task, source time, coverage interval, execution set, destination, and optional exact decision/file context. |
| `contexts` | Every `DiscoveryContextBindingV1` field: subject/image/configuration revision, process/entry/binding lifetime, role/state/entry rule, catalog revision, static operation key, and policy revision. Context identity is not a PID or path. |
| `coverage` | Every `DiscoveryCoverageV1` field: exact stream/CPU, cursor range, expected count, interval identity/revision, state, and gap reasons. Preserve Healthy, Gapped, Unknown, and Closed states. The host supplies the coarse SDK coverage state. |
| `exclusions`, `lifecycle` | Exact record references and exclusion reasons; every lifecycle case and its Missing, NotApplicable, or Recorded state with retained references. |
| `atoms`, `groups` | The complete `BehaviorAtomKeyV1` or `BehaviorDisplayKeyV1`, count, cursor bounds, evidence samples, group members, and coverage. Counts use checked unsigned 64-bit arithmetic. A display group is not a new identity. |
| `baseline` | Reviewed snapshot, reviewer, review time, and forbidden static keys. Host authority validates the review. Comparison outputs retain before/after rows. |
| `context_request`, `context_revisions` | Exact access/subject/method/window, evidence handles, owner facts, missing facts, document identity/revision, import/validity time, origin, sensitivity, trust, kind, and text. Supply the frozen selector result to packages. |
| `facts` | Every `GraphFactV1` field and each `GraphFactValueV1` variant: NativeParent, Baseline, Credential, AuthorityUse, Kubernetes, PolicyActivation, and Context. Keep fact history, proof quality, issuer/lifetime, exact record anchor, and validity. |
| `graph_manifest` | Full source and result revisions, record/coverage/context selections, window and lateness limits, package versions, witness deadlines, and exact dependency revisions. Native graph consumers also receive all selected version IDs, including empty replacement versions, and the traversal receipt. |
| `subjects`, `relationships`, `findings`, `branches` | Full existing owner keys, proof, cause, evidence, required intervals, time bounds, package identity, policy provenance, effects, reason, severity, sensitivity, action, limits, and branch state. Output row counts are independent. |
| `checkpoint` | Versioned algorithm state only. Package state, accepted/observed watermarks, replay contract, and coverage requirements remain explicit. The host retains progress, witness references, expiration, and atomic commit state. |

The source models are [discovery models](../../../../../crates/araphor-data/src/discovery/model.rs),
[context types](../../../../../crates/araphor-data/src/discovery/context.rs),
[graph models](../../../../../crates/araphor-data/src/graph/model.rs), and
[native traversal types](../../../../../crates/araphor-data/src/graph/traversal.rs).
UTC timestamps use signed nanoseconds. Boot time and source positions use
unsigned integers. Do not compare different Node boot clocks.

All package rows inherit these host checks: authorize each input version and
source; retain full tenant and lifetime keys; qualify context and proof; check
evidence membership; apply row, byte, time, cancellation, and state limits;
validate all domain outputs; commit through AnalysisStore. A correlation
cannot upgrade proof. A package result cannot grant authority.

## Computation and variant audit

`derive.rs` below means [discovery derivation](../../../../../crates/araphor-data/src/discovery/derive.rs).
`context.rs` means [context selection](../../../../../crates/araphor-data/src/discovery/context.rs).
`graph/derive.rs` means [graph derivation](../../../../../crates/araphor-data/src/graph/derive.rs).
Each export can return several named datasets. Reuse one implementation when
several exports need the same operation.

| ID / later export | Source symbols and variants | Input, output, and state | Existing tests |
|---|---|---|---|
| AR01.1 `discovery.atoms` | `DiscoveryOwner::derive_recorded`: exact deduplication; conflicting record/context/exclusion rejection; orphan joins. | Records, contexts, exclusions to deduplicated input and dispositions. State: exact seen identities for a bounded evaluation. | `discovery_derivation_replay_counts`, `discovery_derivation_conflicting_input`. |
| AR01.2 `discovery.atoms` | `unresolved_reason`: absent generation/object, operation mismatch, missing lifetime, contradictory source context, absent observed-runtime context. | Records plus context/proof kind to included or unresolved rows. ObservedRuntime, RecordedInput, Synthetic, and ConfigurationScan remain distinct. No independent durable state. | `discovery_derivation_missing_generation`, `discovery_derivation_disposition_accounting`. |
| AR01.3 `discovery.atoms` | `physical_result`: denied negative kernel result to Prevented; other results to Unknown. | Exact source decision/result to physical class. The host checks source authority. | Derivation corpus and graph effect tests. |
| AR01.4 `discovery.atoms` | Atom construction and checked `add`: complete key, counts, first/last cursors, bounded evidence samples. | Qualified records to atoms and accounting rows. State: atom-key map. Preserve all key distinctions. | `discovery_derivation_distinct_keys`, `discovery_derivation_replay_counts`. |
| AR01.5 `discovery.atoms` | Range accounting: expected count, gapped/unknown source reports, included/unresolved/excluded totals; lifecycle copy and validation. | Records/coverage/lifecycle to coverage and disposition outputs. State: range counters. | `discovery_derivation_disposition_accounting`, `discovery_derivation_lifecycle_schema`, `discovery_derivation_corpus_parity`. |
| AR02.1 `discovery.merge` | `BehaviorSnapshotV1::merge`: same-input return; exact source/proof match; non-overlapping ranges; checked count merge; sorted bounded samples. | Two snapshots to one snapshot. State: merged atoms and references. Reject conflicting overlap. | `discovery_derivation_page_merge`, corpus parity. |
| AR02.2 `discovery.merge` | `merge_coverage`: adjacent compatible ranges; state precedence and deduplicated gap reasons. Lifecycle merge: Missing replacement, Recorded union, conflicting state rejection. | Coverage/lifecycle rows to merged rows. State: last range and lifecycle cases. | Page merge, lifecycle schema, corpus parity. |
| AR02.3 `discovery.groups` | `BehaviorSnapshotV1::display_groups`, `BehaviorDisplayKeyV1::from`: complete display key, count sum, exact members, samples, overlapping coverage. | Atoms/coverage to ordered groups. State: group-key map. | `discovery_derivation_distinct_keys`, page merge, comparison tests. |
| AR03.1 `discovery.compare` | `BehaviorSnapshotV1::compare`: exact group additions/removals and changed counts. | Current/reviewed groups to added, removed, and before/after count datasets. No independent state. | `discovery_comparison_reviewed_changes`. |
| AR03.2 `discovery.compare` | `outcome_basis`, `identity_basis`: changed outcome and subject/image/configuration/policy identity. | Current/reviewed groups to independent result and identity differences. Preserve many-to-many matches. | Reviewed changes and corpus parity. |
| AR03.3 `discovery.compare` | Exact resource key comparison, forbidden static-key membership, coverage and lifecycle differences. | Atoms/baseline to new resources, forbidden groups, coverage before/after, lifecycle before/after. | Reviewed changes and corpus parity. |
| AR04.1 `context.select` | `DiscoveryOwner::select_context`: request validation; record deduplication; exact subject; received-time cutoff; handle cap. | Host request and evidence to selected handles and omission counts. The host supplies the selected input to SDK exports. | `discovery_context_cutoff_replay`, subject revision and packet quota tests. |
| AR04.2 `context.select` | Owner facts: history/key checks, subject match, recorded/validity cutoff, sensitivity, fact cap. | Frozen owner facts to selected facts and omissions. Authorization stays on the host. | Context cutoff, conflicts/omissions, subject revision. |
| AR04.3 `context.select` | Document history and latest revision at cutoff; subject/method/access/validity checks; source and handle caps. | Frozen documents to handles, source counts, and omissions. State: latest document map. | `discovery_context_approval_state`, `discovery_context_cutoff_replay`, source quota, history bounds/import tests. |
| AR04.4 `context.select` | Statement conflict groups; `omit`, `refresh_missing`; bounded packet trimming in document/evidence/fact order. | Selected records to conflicts, missing facts, and complete bounded context packet. Do not hide omissions. | `discovery_context_conflicts_omissions`, byte quota, packet quota. |
| AR05.1 `HF-PROC-001.detect` | `GraphDerivation::native`: task/process/execution-set membership and native effect object joins. | Records and exact context to subject/relationship candidates. State: evaluation subject/edge sets. Full key and proof validation remains host-owned. | `control_graph_denial_and_missing_lifetime`, `control_graph_accepted_physical_results_keep_stage_semantics`. |
| AR05.2 `HF-PROC-001.detect` | Qualified NativeParent fact join; task-cookie or process match; complete integrity/coverage; reviewed role/state baseline match. | Records plus parent/baseline/policy facts to ancestry and deviation candidates. | `control_graph_native_parent_is_exact_and_local`, `control_graph_provenance_requires_retained_exact_acknowledgement`. |
| AR05.3 `HF-PROC-001.detect` | Contradicted baseline/policy; missing identity; enforced effect; audited deviation; unproved baseline. | Candidates to Contradiction, LineageCoverageGap, UnexpectedEffect, or AuditedRoleDeviation findings with exact limits. | `control_graph_denial_and_missing_lifetime`, `control_graph_transition_history_does_not_replace_exact_generation`. |
| AR05.4 `HF-PROC-001.detect` | `context_actions`: OutsideAuthority, InMemory, PayloadUnobservable classification. | Exact context fact anchor to coverage-insufficient finding. No physical action proof. | Context classifications in the [lightweight replay fixture](../../../../../crates/mithril-e2e/src/discovery/graph_notification/replay.rs). No crate-local context-only test. |
| AR06.1 `HF-DW-001.detect` | `credentials`: object match; expected-access contradictions; duplicate completion identity with conflicting bytes; read/open/mmap variants. | Records and credential facts to qualified or contradicted credential seeds. | `control_graph_credential_versions_cannot_overwrite_conflict`, `control_graph_read_channel_and_provider_results_stay_separate`. |
| AR06.2 `HF-DW-001.detect` | Read completion: policy match, qualified successful result, positive bytes, exact task/process/object; Read/InheritedFd/IoUring accepted; Mmap/Memory remain unproved. | Credential seed and completion to bytes-proved state and limits. | `control_graph_mmap_and_other_operation_cannot_borrow_read_bytes`, `control_graph_read_channel_and_provider_results_stay_separate`. |
| AR06.3 `HF-DW-001.detect` | Local channel join: same Node/boot/label lifetime, ordered boot time, bounded window, network family, same exact task or process. | Records to credential/channel pairs. State: bounded join window. | `control_graph_read_channel_and_provider_results_stay_separate`, `control_graph_window_boundary_preserves_credential_join`. |
| AR06.4 `HF-DW-001.detect` | AuthorityUse join: exact task/process/socket/request/lease/principal/operation; qualified direct result or provider/coordinator workload context. | Credential/channel/authority facts to direct and contextual pairs. State: deduplicated authority matches. | `control_graph_shared_principal_is_contextual_only`, `control_graph_read_channel_and_provider_results_stay_separate`. |
| AR06.5 `HF-DW-001.detect` | Result contradiction by full authority/request/lease/principal/operation key; missing/direct/contextual/contradicted classification. | Pairs to findings, relationships, evidence, and limits. A contextual branch cannot create direct causal proof. | `control_graph_contradictions_require_same_operation`, `control_graph_credential_versions_cannot_overwrite_conflict`. |
| AR07.1 `HF-XNODE-001.detect` | `cross_node`: source qualification; carried request, audit, object/version, owner/pod, scheduler Node, full container/admission field checks. | Kubernetes stage facts to missing-field rows and package states. State: selected stage facts. | `control_graph_kubernetes_preserves_partial_stages`. |
| AR07.2 `HF-XNODE-001.detect` | Ordered state choice: proof missing, request, audit, object, scheduled, remote admission; optional object relationship. | Stage facts to contextual relationship and coverage-insufficient finding. Always retain `CROSS_NODE_CAUSALITY_UNQUALIFIED`. | `control_graph_kubernetes_preserves_partial_stages`. |

Graph test symbols and fixtures are under [graph tests](../../../../../crates/araphor-data/src/graph/tests.rs)
and [processing tests](../../../../../crates/araphor-data/src/graph/tests/processing.rs).
The migration must extend these test mappings and run the installed
production path. The current tests do not prove package execution.

## Shared operations that remain host-owned

| Owner operation | Source and required contract behavior |
|---|---|
| Exact identity and proof | `GraphDerivation::subject`, `task`, `proof`, `qualified_result`, `edge`; graph input/model/proof validation. Packages return computation candidates. Host validation constructs and qualifies production identities and relationships. |
| Fact and policy qualification | `facts`, `policies`, `reviewed_policy`, `policy_conflict`; fact history, issuer/replay, policy provenance, local/remote binding checks. Supply qualified facts; do not give packages an authority callback. |
| Domain result assembly | `effect`, `finding`, `finish`; deterministic finding identity, provenance/effects, severity/action, branch priority, ordering, graph revision, checkpoint metadata. The SDK maps namespaced reasons to current reasons without changing these checks. |
| Storage and retention | `graph/commit.rs`, `window.rs`, `expiry.rs`, `read.rs`, `analysis/progress.rs`, native graph row modules. Replacements, retry equality, history, quotas, witness expiry, progress, backup, and recovery stay with AnalysisStore and graph owners. |
| Live extraction and scheduling | `discovery/live.rs`, `graph/live.rs`, `graph/input.rs`, `query/graph.rs`, and analysis extraction. Authorized frozen input is a dataset, not a package database handle. Close durable readers before computation. |
| Notifications and enforcement | NotificationRouter, Control policy owners, Node, and Interceptor. Package computation changes neither mandatory routes nor human deadlines nor physical authority. |

The SDK contract also needs bounded selected graph relations. The selection
manifest retains every authorized version ID, source window, counts, limits,
and hop-boundary state. A removed finding or empty replacement cannot restore
an older current version. Global row references span ordered batches. They do
not require a complete GraphSnapshotV1 or a new SDK graph identity type.

State alone is not evidence. A stateful export receives required prior result
rows as named inputs with their exact retained revisions. The host resolves
those rows to retained evidence. Alternatively, the host supplies retained raw
input for replay. A missing retained dependency yields incomplete coverage.

## Contract coverage and later proof

The portable contract represents all listed rows with typed named datasets,
parameters, exact revisions/windows, coverage, clock/seed, evidence links,
reason detail schemas, and versioned state datasets. Trees and indexes use
declared bounded binary checkpoint fields. No additional language, store,
permission API, live lookup, or collector loader is required by this audit.

Required later semantic cases include duplicates and conflicting bytes,
same-name subjects with different lifetimes, missing generation/context,
overflow, page split/merge, reviewed baseline changes, late data, expired
witnesses, empty replacements, direct/contextual contradictions, wrong Node
boot clocks, and restart/replay. The SDK tests check the portable contract.
The migration tests must check the algorithm and the host integration.
