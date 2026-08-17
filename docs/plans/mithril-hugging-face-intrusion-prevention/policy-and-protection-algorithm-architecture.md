# Mithril Policy And Protection Algorithm Architecture — Superseded

**Status: SUPERSEDED HISTORICAL RECORD — 2026-08-08.** This earlier architecture
is retained only for design history and rejected alternatives. It is not an
implementation authority and must not be used to fill gaps in the validated
[readable architecture](./policy-and-protection-algorithm-architecture-readable.md).
When the files disagree, the readable architecture controls.

Status: Proposed architecture companion. This document does not authorize an
implementation phase. An approved phase may implement only the part assigned
to it by the
[Mithril Hugging Face Intrusion Prevention Master Plan](./README.md).

Normative acceptance:

- [Hugging Face Adversarial Acceptance](./hugging-face-adversarial-acceptance.md)
- [Live Two-Node Lifecycle Probe](./live-two-node-lifecycle-probe.md)

Research inputs:

- [Erebor Defender: Linux Enforcement, Correlation, and Response Engineering](../../research/erebor-defender-learning-from-tetragon-and-falco.md)
- [Mithril Single-Gatherer Architecture and Upstream Adoption Plan](../../research/erebor-warden-single-gatherer-architecture-plan.md)
- [Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Hugging Face Agent Intrusion: Published Live Action Stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

## Document Navigation

This document is organized as an implementation contract, not a chronological
research notebook:

| Part | Answers |
| --- | --- |
| [I — Contract, scope, claims](#part-i-contract) | What the terms mean, what Mithril can honestly claim, and which retained designs are superseded |
| [II — Code-validated basis and invariants](#part-ii-basis) | What was learned from pinned KubeArmor/Tetragon source and which release invariants follow |
| [III — Identity and runtime admission](#part-iii-identity) | How every native child, external root, kubelet action, CI/root restore, and unchanged workload receives identity |
| [IV — Policy and local enforcement](#part-iv-enforcement) | How source policy compiles and where file/network/device/privilege effects are physically decided |
| [V — Evidence, correlation, response](#part-v-evidence) | How loss-aware observations become multi-node/provider graph edges and verified containment |
| [VI — Incident, configuration, CI](#part-vi-incident) | What happens for every Hugging Face action and how an operator selects allow/alert/deny/reject/response |
| [VII — Acceptance, failure, performance](#part-vii-qualification) | Which hostile fixture and physical oracle permit each advertised capability |
| [VIII — Ownership, delivery, approval](#part-viii-delivery) | Which component/phase owns work and what remains an explicit approval choice |
| [Appendix A — Primary technical references](#appendix-a-primary-technical-references) | Which pinned local files and external contracts support the design |

### Normative dependency hierarchy

The hierarchy is a dependency graph. A lower item may consume only artifacts
produced above it; it cannot repair an omitted prerequisite after the physical
effect:

```text
Part I: words, claims, supersession
  └─ Part II: pinned-source facts and non-weakenable invariants
       └─ Part III: live task/process/entry/authority identity
            └─ Part IV: compiled generation and physical decision
                 └─ Part V: evidence, causal edge, response postcondition
                      └─ Part VI: incident package and operator configuration
                           └─ Part VII: fixture result and qualification envelope
                                └─ Part VIII: owner, phase, approval, product claim
```

For example, `HF-011` cannot begin with a detection rule named "credential
read." Part III must first identify the exact task and authority domain; Part
IV must separately decide open, read, inherited-fd, passed-fd and mapped-page
paths; Part V records only the result each hook proves; Part VI maps those
results to the incident stage; Part VII runs the physical byte oracle; and
Part VIII assigns the state and test to a named owner and phase.

### Implementer reading path

1. Read Part I and the protection invariants before choosing a hook or schema.
2. Read the relevant source-evidence IDs in Part II; they state exactly what the
   local upstream code proves and what it does not.
3. Implement identity/admission in Part III before an effect rule in Part IV;
   an effect cannot safely authorize an unidentified task.
4. Implement evidence/response contracts in Part V independently of the
   physical deny path.
5. Select the real incident/configuration case in Part VI, then make its named
   Part VII fixture pass on an exact platform manifest.
6. Do not expose a product claim until Part VIII's completion ledger says
   `PASS`; `UNSUPPORTED` and `INSUFFICIENT_COVERAGE` are first-class results.

### Question-to-contract map

| Question | Normative owner | Proof owner |
| --- | --- | --- |
| What do `exact`, `prevented`, and `contained` mean? | [Normative reading](#normative-reading-and-implementation-contract) and [claim boundary](#claim-boundary) | [Qualification](#completion-standard-for-this-architecture) |
| How is a process identified? | [Identity/execution model](#identity-and-execution-model) | [External-entry](#kubernetes-external-entry-acceptance-matrix) and moved-task fixtures |
| How is kubelet/runtime intent bound to one task? | [Runtime admission](#kubernetes-and-runtime-created-entry-architecture) and authenticated intent | Kubelet-ticket/held-task fixtures |
| How is policy compiled without mixed generations? | [Policy package/compiler](#policy-package-and-compiler) | Compiler and paused-update golden tests |
| Where is a syscall or packet denied? | [Node decision](#node-decision-architecture) and [effect algorithms](#effect-family-algorithms) | [Effect/bypass matrix](#effect-and-bypass-acceptance-matrix) |
| How are nodes and providers correlated? | [Detection graph/evidence](#deterministic-detection-and-correlation-algorithms) | HF granular and replay fixtures |
| How is containment applied? | [Response algorithms](#response-algorithms) | Response/failure postcondition fixtures |
| Can this platform advertise the capability? | [Completion standard](#completion-standard-for-this-architecture) | Platform support manifest, result bundle, ledger and signed envelope |

#### Implementation route index

This is the short route from a requirement to code. The detailed phase table
in Part VIII is authoritative when a row spans phases.

| Need | Read in order | Durable owner | First executable objection |
| --- | --- | --- | --- |
| Native child cannot shed its budget | `INV-ENTRY-001`/`INV-ROLE-002` → `TaskLabelV1` → `ProcessSecurityStateV1`/`AuthorityDomainStateV1` → task allocation/finalization algorithm | `NativeSecurityStateOwner` inside `mithril-node`; kernel map-object lifecycle through `KernelHostOwner` | child performs token open before userspace sees fork |
| Kubelet probe differs from attacker using identical argv | `SignedIntentV1` → `IntentPayloadV1(kind=RUNTIME_ENTRY)` → `RuntimeEntryBodyV1` → held-entry state machine → `CARD-ENTRY-PROBE-IMPERSONATION-001`; `RuntimeEntryIntentV1` is an abandoned name | `IntentAdmissionOwner` plus kernel claim program | three identical `/app/healthcheck` invocations must receive three correct entry results |
| Python cannot read the mounted ServiceAccount token | `FileObjectIdentityV1` → file decision algorithm → `CARD-FILE-SA-TOKEN-OPEN-001` | object classifier + policy generation owner + qualified BPF LSM file program | in-process `openat2`, read, mmap, inherited-fd and `SCM_RIGHTS` variants |
| Existing allowed socket cannot launder a later role | socket provenance/state → authority-domain state → packet/established-flow decision | socket/effect owner in `mithril-node` | fd pass and shared-TLS negative/hostile pair |
| Node-A credential use creates a privileged Pod on node B | `ProviderEdgeContractV1` → graph algorithms → `CARD-XNODE-PRIVILEGED-POD-001` | node evidence owner then control graph owner; node-B admission is local | exact audit/object/binding chain, contextual fallback, and no invented cross-node parent edge |
| Kill/fence/revoke claim is physically true | `ResponsePlanV1` → target re-resolution → actuator postcondition → healthy coverage interval | `ResponseCoordinator` and one typed node/provider actuator | stale target, shared authority-domain blast radius, replacement Pod and late branch |
| Release can state "prevented" | exact `ClaimVectorV1` → registry result → ledger → `QualificationEnvelopeV1` | release qualifier, not a detector or UI | any non-PASS fixture, missing negative control, wrong build/platform digest, or coverage gap blocks signing |

The retained route/table name `RuntimeEntryIntentV1` is abandoned as a schema
identifier; no record with that name exists. The exact route is
`SignedIntentV1` → canonical `IntentPayloadV1(kind=RUNTIME_ENTRY)` →
`RuntimeEntryBodyV1` → one-use claim slot → held task. The unversioned
`RuntimeEntryIntent` later in Part III is a logical teaching sketch only. This
correction also controls the scenario-boundary row that retained the nonexistent
name.

### Heading and statement semantics

- **Normative** text is the implementation contract.
- **Practical example** names a concrete actor, operation, compiled decision,
  evidence, negative control, and physical/provider oracle.
- **Correction** supersedes the named retained statement.
- **Abandoned design** is forbidden implementation history retained because the
  document may not erase earlier content.
- **Source-derived lesson** is a pinned code observation. It neither imports
  upstream policy nor implies the upstream project intended Mithril's product
  guarantees.

Every core algorithm should be translatable into this reviewable record:

```text
ImplementationCardV1 {
  card_id
  real_world_stimulus
  starting_task_entry_role_and_authority
  authoritative_inputs
  exact_decision_boundary
  ordered_map_and_state_reads
  compiled_policy_key
  physical_disposition
  evidence_emitted
  degraded_or_unsupported_result
  legitimate_negative_control
  hostile_fixture
  physical_or_provider_oracle
  upstream_source_evidence_ids[]
}
```

Words such as “credential operation,” “strong,” “current namespace,”
“verified,” or “known token” are not executable unless the nearby schema/card
defines their exact object, proof axes, stage, and result.

#### Resolution of retained convenience phrases

Earlier sketches use ordinary-language shortcuts. They remain visible, but an
implementer must lower them exactly as follows:

| Retained phrase | Only permitted implementation meaning |
| --- | --- |
| “map-of-maps or equivalent indirection” | Build a complete immutable inactive generation, read it back, atomically switch one binding reference, retain old referenced generations, and pass the mixed-update fixture. Any BPF map shape with those measured properties qualifies; in-place mutation does not. |
| attach `fail_closed_unknown` “when possible” | Install it at a capability-qualified returning `task_alloc` path. If the target cannot do so, the platform is a first-protected-effect tier and must deny there; it cannot claim child-creation denial. |
| external trust anchor “where available” | A separately administered measured-boot/IMA/TPM or node-attestation source with an explicit `KernelCapabilityRecordV1`, authenticated coverage interval, and expected program/map/runtime digests. Without it, successful kernel/root tamper closes local integrity coverage as `ENFORCER_TAMPERED_OR_UNKNOWN`. |
| correlate a Kubernetes principal “when possible” | Join the exact runtime entry ticket to the exact Kubernetes audit request UID and authenticated principal. If either join is missing, preserve runtime-task identity and audit-principal identity as separate/contextual subjects. |
| traditional-LSM audit “where available” | A configured SELinux/AppArmor/other adapter has a healthy source epoch/sequence interval covering the denied request and its documented join fields. Otherwise record the physical result only if another oracle proves it, plus the audit gap. |
| inode generation/version “where available” | The filesystem/kernel capability probe proves a stable generation/version for that live object. If absent, the object key must use another qualified integrity tier or report reduced identity; zero or guessed generation is forbidden. |
| `sk_free_security` “or equivalent” | A target-qualified final kernel-object destruction hook or complete safe iterator owns an idempotent final reference release. Fd close, process exit, or a userspace timeout is not equivalent. |
| descriptor/DB/endpoint evidence “where available” | The matching closed assurance-axis record names the exact hook/provider adapter, covered operations, interval, and proof vector. A missing record yields the row's degraded result; code may not opportunistically infer it. |
| “suspicious,” “unusual,” or “unexpected” action | Display prose only. The executable result must name the exact compiled rule/package, inputs, threshold/window if any, stage, proof vector, and negative control. These adjectives are never BPF keys or model-only authorization outputs. |
| “appropriate approval” | A valid `ResponsePlanV1.authorization_id` whose signer, exact action/target scope, expiry, and blast radius satisfy the installed signed response policy. Human judgment without that object cannot actuate. |
| `ALG-NET` blocks a channel “when possible” | The managed task/socket and enabled protocol path hit a qualified local destination/packet decision before bytes leave. External tasks, unqualified protocol paths, or TLS-opaque verbs are observation/provider tiers and cannot report a local block. |

This table resolves the phrase wherever it appears later. A narrower adjacent
correction or capability matrix still wins; no phrase widens a claim.

<a id="part-i-contract"></a>

## Part I — Contract, Scope, And Claims

### Purpose

The phase files say when Mithril builds each capability. This document says
what the finished policy system means and which algorithm handles each
Hugging Face incident situation.

It is deliberately more specific than a product description. An implementer
should be able to derive Rust owners, BPF maps and hooks, policy schemas,
decision order, failure behavior, and adversarial tests from it. A reviewer
should be able to object to an explicit decision rather than infer one from a
phrase such as “anomalous process.”

The target is an unchanged application deployment. Mithril may install node
security integration, BPF programs, a runtime admission transport, and audit
collectors, but the baseline cannot require one job per Pod, one job per
process, application instrumentation, a different ServiceAccount, narrower
RBAC/IAM, a sidecar, a TLS proxy, or a modified agent harness.

### Normative Reading And Implementation Contract

This section removes vocabulary ambiguity from every later pseudocode block.
The words **MUST**, **MUST NOT**, **SHOULD**, **SHOULD NOT**, and **MAY** have
their RFC 2119 meanings. A later example can narrow a rule for its named
profile; it cannot silently redefine a term in this section.

#### Security and execution terms

| Term | Normative meaning | Concrete example | Not sufficient |
| --- | --- | --- | --- |
| Protected scope | A live node, cgroup binding, execution set, or host scope to which an activated profile generation is bound | Pod UID `p1`, container ID `c1`, cgroup binding generation `19`, profile generation `42` | A namespace label, Pod name, image tag, or cgroup path observed in the past |
| Protected task | A live Linux task with a verified `TaskLabel`, or an unlabeled task currently inside a protected scope and therefore subject to fail-closed admission | Python task cookie `7001` in execution set `e1` | Any process whose `comm` happens to be `python` |
| Protected effect | An operation for which the active profile declares a decision and for which the capability matrix names a synchronous hook or an explicitly observation-only source | `file_open` of the projected token, `connect(2)` to IMDS, `bprm_check_security` for `/bin/sh` | Arithmetic inside Python, a decrypted HTTPS verb invisible to the node, or a syscall with no qualified hook |
| Decision point | The exact boundary that can still cause the requested physical result | BPF LSM returns `-EACCES` before `open(2)` returns; a runtime gate refuses an exec ticket before it creates the task | An audit event delivered after the server committed the operation |
| External execution root | A task created by a runtime, shim, host service, or administrator without a verified labeled Linux parent in the protected execution set | Container entrypoint or the process created for `kubectl exec` | Every process in a container; ordinary `fork()` descendants are not external roots |
| Native descendant | A task created by `fork`, `clone`, `clone3`, or `vfork` from a labeled task, whether or not it later execs | A Python `multiprocessing` child | A task merely sharing PID/mount/network namespaces |
| Entry admission | A one-use authorization that binds an external root to an exact protected scope, role, policy generation, lifetime, and live kernel task | Held init pidfd for container `c1` receives `ContainerStartEntry` nonce `n1` | A container-create event, matching command text, or cgroup membership alone |
| Role | A finite policy state assigned by an admitted entry or approved native transition | `conversion-worker-root`, `kubelet-exec-probe` | Executable pathname, Linux UID, Kubernetes ServiceAccount, or human-readable job name |
| Physical budget | The complete set of entry, exec, file, network, device, security, lifetime, concurrency, and response permissions compiled for a role | Probe can read `probe-health-file` for three seconds and cannot fork or connect | A severity, finding name, or list of command strings |
| Hard invariant | A product rule that no profile, exception, issuer, model, or lower-priority rule may weaken | Preserve an earlier LSM denial; deny an unlabeled protected task in strict mode | An ordinary operator deny rule that a signed, scoped exception may narrow |
| Coverage interval | A half-open interval `[start_sequence, end_sequence)` for one source instance and generation in which health and loss are known | Node source `n1/boot7`, sequence 400 through 900, zero ring loss | “Sensor was online today” |
| Authority boundary | The component that can physically decide or actuate the effect | Linux kernel for local file open; Kubernetes authorizer for API authorization; AWS for an AWS API result | Mithril Control receiving a later copy of an audit record |

#### Evidence and result terms

| Term | Required proof | Permitted statement | Example |
| --- | --- | --- | --- |
| `exact` | Stable identifiers from the authority that owns both ends of the claimed relation, or an authenticated one-use proof claimed by the exact live kernel task | “This task claimed this runtime ticket” | pidfd plus task cookie plus one-use runtime nonce |
| `conservative` | Several candidates remain, but every candidate compiles to the same or a stricter physical budget | “This task has no more authority than any matching probe candidate” | Readiness and liveness commands are identical and both have the same deny-all network budget |
| `contextual` | Time, IP, name, label, shared principal, or other supporting evidence without a unique causal join | “These observations may be related” | One Pod socket and one API audit event share a ServiceAccount and ten-second window |
| `unknown` | Required evidence is absent, contradictory, outside authority, or across an unhealthy interval | “Mithril cannot determine this relation/result” | Provider feed was unavailable during the alleged GitHub write |
| `observed` | An authoritative source recorded an attempt or state, without proof that it completed | “The kernel hook saw an open attempt” | `file_open` hook returned allow, but the syscall later failed for another reason |
| `completed` | A post-effect kernel return, runtime result, or provider result proves the operation completed at its defined boundary | “The API reported a successful Secret read” | Kubernetes audit response status is successful for the exact audit event |
| `prevented` | A synchronous decision point returned denial and an effect-specific oracle proves the protected effect did not complete | “No token byte was returned because `file_permission` denied the read” | Syscall exit is `-EACCES` and the safe fixture confirms its output buffer stayed unchanged |
| `rejected` | A higher-level request was refused before its task, lease, or semantic provider operation was admitted | “The runtime did not create the exec process” | Streaming-exec ticket reaches terminal state `REJECTED` before stream activation |
| `contained` | Every branch named in a response plan has an applied restriction; unresolved branches remain listed | “The known local lineage and two known sockets are fenced” | A remote credential branch may keep overall result `partial` |
| `verified` | Every required physical postcondition held through a healthy configured watch interval including source lateness | “Containment is verified for this response scope” | No replacement Pod appeared before Kubernetes watermark passed the watch end |

`exact` never means “high confidence.” It names a specific proof shape. A
detector can be 99.9% statistically confident and still produce only a
`contextual` edge. Conversely, an exact audit event may prove that a benign
operation happened; exactness is not maliciousness.

#### Identifier, time, and unit rules

All schemas in this document use these defaults unless the field explicitly
states otherwise:

- IDs ending in `_id` are opaque byte strings with a named issuer and scope.
  Mithril-created durable IDs are 128-bit values unique within
  `(tenant_id, node_boot_id, label_epoch)`; provider IDs retain the provider
  namespace and are never parsed for authority.
- Digests are lowercase algorithm-qualified values such as
  `sha256:<64 hexadecimal characters>`. A tag, branch, path, or mutable URL is
  not a digest.
- Node decision deadlines and TTLs use monotonic boottime nanoseconds. Wall
  clock is retained only for display and remote-token validation. A reboot
  invalidates every monotonic deadline from the prior boot.
- Remote timestamps use signed UTC instants plus the source's measured clock
  uncertainty. A time-window join expands by both sources' uncertainty and
  remains contextual unless another exact join field exists.
- Durations in source configuration require an explicit unit. Rates are
  `(count, interval, scope)` triples; `10/m` without a named per-task,
  per-entry, per-workload, or per-issuer scope is invalid.
- Intervals are half-open: `[start, end)`. Sequence numbers are unsigned
  64-bit counters scoped to a source instance and epoch; wrap, reset, and
  source restart open a new epoch rather than appearing continuous.
- Optional fields written with `?` may be absent only when the compiler names
  the resulting lower evidence tier or rejects the object. They never mean
  “silently use a convenient default.”

#### Practical reading example

Suppose task cookie `7001` in protected execution set `e1` attempts to open a
projected ServiceAccount token:

1. `file_open` is the decision point for opening the file and records an
   `observed` attempt.
2. If the hook returns `-EACCES` and the syscall returns `-EACCES`, the open is
   `prevented`; no claim about a Kubernetes API request is needed.
3. If the hook returns allow but the filesystem later returns `ENOENT`, the
   operation was observed but not completed and Mithril did not prevent it.
4. If the open succeeds, a later read must be decided or observed separately.
   “Open succeeded” is not “secret bytes were read.”
5. If a provider event later shows the ServiceAccount called Kubernetes, the
   task-to-request edge is exact only with a request/lease proof described in
   the correlation section. Shared Pod identity plus time is contextual.

Every implementation test must use this vocabulary in its expected result.
Tests fail if they report a stronger word than their physical oracle proves.

#### Normative and supersession index

The document intentionally preserves earlier sketches and incorrect ideas so
reviewers can see why they were rejected. Implementers use this index when two
passages appear to conflict:

| Topic | Normative reading | Superseded/abandoned reading |
| --- | --- | --- |
| Decision location | Kernel for qualified local pre-effects; runtime/broker/provider boundary for semantic admission; control plane for correlation | Put every decision in BPF |
| Containment | Exact attribution and actuator scope are independent proof dimensions | Exact graph automatically means exact provider response |
| Task creation | Qualified synchronous task allocation/inheritance; otherwise first-protected-effect or observe tier | Post-run observation called pre-run protection |
| Threads/process state | Threads share one `ProcessSecurityState`, role, execution, taint, and response set | Separate `thread_child_role` or authoritative per-task dynamic bits |
| Exec | Stage every `bprm` chain member; commit result role synchronously before user mode | Rust/asynchronous post-exec role assignment |
| Streaming CRI exec | Prepare ticket and later authenticated stream/task are separate state transitions | One CRI `Exec` call immediately identifies a task |
| Entry claim | Held task/carried ticket for exact; identical no-ticket claims are same-budget ambiguous at best; final role only on exec commit | Candidate key/time makes concurrent identical roots exact or provisional task gets final role |
| AWS/gcloud/gsutil | Native process/exec plus separate authority-lease evidence | CLI-specific execution-entry kinds |
| Intent failure | Local signed policy selects failure posture; explicit one-use slots and persistent replay state | Issuer selects fail-open or a reusable claim counter |
| Ambiguous budgets | identical shared budget, deny, simulated intersection, or explicitly broad degraded exception | Unequal allow-union called conservative |
| Policy conflicts | Exact-key expansion plus explicit override/exception or compilation failure | Prose “most specific wins” |
| Policy generations | New admissions use active generation; live objects use retained pinned generations | Every label must equal active generation |
| Cgroup identity | Live cgroup object/binding nonce plus interval, never bare ID/path | Numeric cgroup lookup is durable identity |
| Sensitive read | Pre-hook proves attempted/permitted access; completed bytes need exact post-read coverage | File-open allow proves secret bytes were read |
| Network | Hook/path coverage matrix; current-task and socket policies intersect; packet fence is distinct | `sendmsg4/6` covers every TCP send or old socket allow transfers authority |
| Seccomp/Landlock | Seccomp only becomes stricter; Landlock ABI covers multiple FS/network/IPC rights but needs a pre-run installation seam | Detect a task weakening seccomp; Landlock is filesystem-only and centrally dynamic |
| Evidence quality | Multi-axis proof and explicit coverage intervals | One scalar `sourceQualityAtLeast` |
| Kubernetes graph | Process-to-audit edge direct only with a carried exact request/lease proof | Audit ID/IP/user agent/time automatically identifies local task |
| Response descendants | Inherited O(1) effective response set, bounded activation proof, broader fallback on overflow | Bounded ancestor vector alone guarantees all future descendants |
| Response verification | Non-invasive production readback/postconditions; active probes only in isolated qualification fixtures | Inject fresh hostile probes into compromised production target |
| Provider response | Credential/provider-specific actuator and postcondition with disclosed blast radius | Generic exact AWS session revoke and audit silence as proof |
| CI | Advertised assurance tier; job-scoped credential remains job-scoped; semantic effects require explicit lowering | Signed callback alone proves step or BPF makes a write token read-only |
| Incident path | Connector catalog was direct worker traffic; AWS had external and worker-local branches | Connector catalog necessarily traversed mesh; every AWS call was external |

An “Abandoned design” paragraph is normative negative guidance. No
implementation, test, example, or later model may select that design merely
because the older retained prose appears first.

#### Machine-checked supersession ownership

The human-readable table is not enough for a release: this document contains
many deliberately retained sketches, so recency, heading depth, and a model's
preference must never decide which one becomes code. Phase 0 creates the
following checked-in source at
`spec/architecture/v1/supersessions.yaml`:

```text
SupersessionRegistryDraftAbandoned {
  architecture_revision_digest
  records[] {
    supersession_id
    kind: CORRECTION | ABANDONED_DESIGN | SUPERSEDED_ASSUMPTION
    retained_statement_anchor
    controlling_statement_anchor
    containing_part_and_contract_path
    forbidden_interpretation
    replacement_schema_algorithm_or_invariant_ids[]
    affected_implementation_card_ids[]
    upstream_source_evidence_ids[]
    owning_phase_and_crate
  }
}
```

Every heading beginning `Correction:`, `Corrections:`, `Corrected`,
`Abandoned design:`, `Abandoned interpretation:`, `Abandoned branch:`, or
`Abandoned fallback:` receives one adjacent marker:

```html
<!-- mithril-supersession-v1: SUP-TASK-CGROUP-FIRST-001 -->
```

The marker ID grammar is the fixture grammar with the `SUP-` prefix. The docs
lint resolves both anchors, verifies that the controlling statement is in the
same Part and contract path unless the row explicitly names a cross-Part
replacement, and fails on an unregistered correction heading, orphan record,
duplicate ID, missing replacement contract, or later positive example that
selects the forbidden interpretation. The generated
`SupersessionHeadingSetV1` and registry must have equal sorted ID sets and the
same architecture revision digest. Until that check exists and passes, no
phase may claim this architecture is mechanically complete.

Supersession precedence is exact:

1. a hard invariant cannot be weakened;
2. a registered controlling schema/algorithm replaces only the retained
   statement named in its row;
3. the local abandoned-design subsection forbids its named interpretation;
4. a retained example is explanatory only and cannot override any of the
   above; and
5. two controlling records that select different physical results for the
   same expanded key are a document error, not an implementer choice.

**Practical example.** The retained cgroup-first exec sketch would look up the
current cgroup and assign whatever workload happens to own it. Its adjacent
`Abandoned design: cgroup-first exec lookup` record instead points to
task-first `TaskLabelV1`, the live binding nonce, and fixture
`ID-MOVED-TASK-EXEC-005`. If a future example again assigns an exec role from
bare cgroup membership, docs lint identifies the forbidden phrase's contract
path and fails before any BPF map is generated. An implementer is not asked to
decide which paragraph "sounds newer."

##### Correction: markers and statement IDs are authoritative, not heading prose

The retained prefix list is incomplete: this document also uses headings such
as `Adjacent correction`, `Correct stacked-LSM`, `Walkthrough corrections`,
and `Normative durable-owner correction`. More importantly, neither a heading
prefix nor the prose `forbidden_interpretation` lets a deterministic linter
prove that a later example has selected the bad design. That automation claim
is abandoned.

The implementable registry uses explicit statement markers regardless of
heading wording:

```html
<!-- mithril-statement-v1: STMT-CGROUP-FIRST-RETAINED-001 RETAINED -->
<!-- mithril-statement-v1: STMT-CGROUP-FIRST-CONTROL-002 CONTROLLING -->
<!-- mithril-supersession-v1: SUP-TASK-CGROUP-FIRST-001 -->
```

```text
SupersessionRegistryV1 {
  architecture_revision_digest
  records[] {
    supersession_id
    retained_statement_ids[]
    controlling_statement_ids[]
    replacement_contract_ids[]
    affected_card_ids[]
    forbidden_contract_ids[]
    upstream_source_evidence_ids[]
  }
}

ImplementationCardV1 {
  ...
  governing_statement_ids[]
  supersession_dependency_ids[]
}
```

Phase 0 lint performs only syntactically decidable checks: marker grammar and
uniqueness; every ID/anchor resolves; each supersession has at least one
retained, controlling and replacement ID; each affected card declares the
dependency; no card declares a forbidden contract ID; registry/document
digests match; and all explicit correction markers are registered. A separate
human/security review decides whether new prose semantically repeats a bad
idea and then assigns it a statement/contract ID. Passing lint is not a claim
that natural-language equivalence was solved.

### Decision Summary

The proposed architecture makes these decisions:

1. A container is a **container execution set**, not necessarily one native
   tree. Its ordinary entrypoint, kubelet-created exec probes and lifecycle
   commands, administrative exec sessions, and other runtime-created tasks can
   be distinct native roots inside the same container.
2. Every root enters through an authenticated, one-use **entry admission**.
   Native descendants receive their label in kernel before they can perform a
   protected effect.
3. A task is authorized by its exact task/process identity and current role,
   not by its comm, path, PID, Pod name, namespace numbers, or cgroup alone.
4. Policy controls physical effects: executable transitions, file and code
   objects, sockets and packets, devices and ioctls, privileges, kernel
   interfaces, and control-plane operations. It does not pretend to recognize
   malicious intent inside Python.
5. Local decisions are deterministic and synchronous in kernel. Central
   correlation is asynchronous and never sits in a syscall decision loop.
6. Direct TLS is preserved. Operations inside the same allowed TLS channel are
   distinguished only by authoritative server/provider evidence; if that
   evidence arrives after completion, the result is detection and containment,
   not prevention.
7. Prevention continuity and evidence continuity are separate. A full
   ring-buffer or disconnected control plane cannot turn a loaded deny into an
   allow. Missing evidence prevents a negative conclusion.
8. The policy model is extensible. The Hugging Face package is the first set of
   roles, effects, causal predicates, and responses, not a special-purpose
   command signature engine.

These are proposed defaults. The final section lists the decisions that need
explicit approval or a replacement with equivalent proof.

#### Corrected reading of “local decisions are in kernel”

The phrase in decision 5 is too broad if read literally. The intended rule is:

```text
local Linux effect decision
    -> synchronous BPF LSM/cgroup/seccomp/runtime hook; no central round trip

runtime entry admission
    -> local authenticated userspace gate may hold/reject the runtime request

provider or control-plane semantic decision
    -> owning provider authorizer/admission/connector, or asynchronous audit
```

##### Abandoned design: putting every local decision in BPF

An earlier reading would require BPF to decide runtime-ticket authenticity,
human approval, CI workflow identity, and provider verbs. That design is
abandoned because those objects do not exist at a Linux hook and because a
CRI runtime can safely hold an entry while the local Rust owner validates its
authenticated metadata. BPF remains the final task/effect binder; it is not a
YAML parser, OIDC verifier, or Kubernetes authorizer.

**Example.** `mithril-node` verifies a signed kubelet probe proof and tells the
held runtime request whether it may proceed. When the resulting task reaches
the exec hook, BPF verifies that the exact task claims that one-use decision.
The first step is local userspace admission; the second is kernel binding.
Neither depends on Mithril Control.

### Claim Boundary

Mithril can protect a Linux or Kubernetes estate on which it is installed. It
cannot retroactively control `HF-001` through `HF-007` in OpenAI's external
evaluation environment, and it cannot claim to reject the uploaded HDF5 or the
Jinja expression itself without an application-owned content gate.

For `HF-008` through `HF-021`, the baseline claim is:

```text
hostile content may reach an existing interpreter
  -> Mithril denies the first distinguishable out-of-profile physical effect
  -> the denial is attached to an exact native execution and policy generation
  -> allowed or already-completed effects are correlated through exact
     Kubernetes/provider identities
  -> the smallest authorized local and remote scopes are contained
  -> postconditions and unresolved branches are reported
```

The following examples define the boundary:

- `os.environ` reading environment already resident in the same Python address
  space has no file syscall for Mithril to deny. Opening
  `/proc/self/environ`, a projected token, or another file does.
- Evaluating attacker-controlled Python inside an existing interpreter may
  create no exec event. `python -> sh`, `python -> curl`, an executable mapping,
  a protected file read, or a socket effect does.
- A new connection to IMDS can be denied by process role and destination. A
  forbidden Kubernetes verb inside a connection that the same role already
  needs is known from Kubernetes audit, not from encrypted packet bytes.
- Git clone and Git push can share a host, port, credential, and TLS
  connection. With no TLS interception and no attenuated provider capability,
  the node cannot honestly distinguish them. Provider audit can detect the
  server-side write and trigger a whole-channel or principal response.

#### Corrected containment claim

“The smallest authorized local and remote scopes are contained” means the
smallest **resolvable actuator scopes that the response policy authorizes**.
It is not a promise that every provider offers a per-session actuator.

##### Abandoned design: equating exact attribution with narrow actuation

That equation is wrong. AWS may identify one assumed-role session in
CloudTrail while the available emergency action revokes every older session
for the role. GitHub may identify an installation but require suspension of
the installation when the defender does not possess the individual token.
Mithril must show that wider blast radius before approval and return
`partial` or `unknown` when it cannot act. It must never relabel a broad
provider action as narrow merely because the graph edge was exact.

**Example.** The graph resolves AWS access-key ID `ASIA...1` to one malicious
session. The actuator capability says `revoke_before_time(role, timestamp)`,
which affects 17 sessions. The plan therefore displays those 17 sessions,
requires the configured broad-response approval, and records the physical
postcondition for all affected sessions. If approval is withheld, the exact
finding remains open; it does not become contained.

#### Kernel/platform eligibility is measured, not inferred from version

Every node produces a `KernelCapabilityRecordV1` before a profile can bind:

```text
KernelCapabilityRecordV1 {
  node_boot_id
  architecture
  kernel_release_and_build_id
  kernel_config_digest
  vmlinux_btf_digest
  core_relocation_probe_results[]
  active_lsm_order[]
  bpf_lsm_configured_and_active
  cgroup_v2_mount_and_config
  lockdown_and_privilege_state
  supported_program_and_attach_types[]
  supported_map_and_storage_types[]
  hook_results[] { hook, attach, ordering, return_semantics, test_id }
  helper_and_kfunc_results[] { program_type, symbol, result }
  link_and_map_ids_digests_and_pin_readback[]
  controlled_allow_deny_probe_results[]
  record_digest
}
```

Eligibility requires BPF LSM configured **and** `bpf` active in the running
LSM list, usable BTF/CO-RE for the exact build, cgroup v2 and cgroup-BPF for
claimed cgroup programs, every required hook/helper/kfunc/map type, sufficient
loader privileges under lockdown, and exact link/map readback. Kernel version
is only a hint. A distribution may backport a helper or disable BPF LSM on a
new kernel.

BPF LSM object files declare a GPL-compatible BPF program license as required
by that kernel program type and its helpers. This requirement applies to the
loaded BPF object; it does not force the independently linked Rust userspace or
the whole product to adopt the same license. Phase 0 records every copied or
derived BPF file's provenance/license separately.

**Eligibility test.** Two nodes report the same release string; one omits
`bpf` from active LSMs and another blocks a required helper under lockdown.
Both fail the relevant capability despite their version. A third passes every
attach/readback/deny probe and stores the exact build/BTF/program digests used
by the later support manifest.

<a id="part-ii-basis"></a>

## Part II — Code-Validated Design Basis And Invariants

### Source-Derived Mechanism Decisions

KubeArmor and Tetragon are implementation studies, not product chassis. Phase
0 still owns the per-file license and provenance decision. Nothing in this
document authorizes copying source.

#### Pinned source baseline and comparison vocabulary

These observations were validated against the local clones at:

- KubeArmor commit `e46f112e8bd4d3c8c8a73c23bfe438ff40eeea1a`;
- Tetragon commit `dbb59576f9ce504c044f8d9a0cd7a0f91c71ae2c`.

“Shy” is not a motive or a generic criticism. Every comparison is labeled as:

1. `UPSTREAM_EXPLICIT`: an upstream code comment/contract explicitly states
   the boundary;
2. `IMPLEMENTATION_BOUNDARY`: the checked-in mechanism does not satisfy a
   named Mithril invariant, although the project could choose to extend it; or
3. `FUNDAMENTAL_BOUNDARY`: Linux/kernel evidence cannot prove the requested
   semantic fact, so Mithril also needs provider/coordinator evidence or a
   semantic admission boundary.

##### Correction: boundary kind and evidence relationship are separate axes

The three values above classify a **gap claim**. The detailed ledger's `Kind`
column also contains “adopted behavior,” “correction,” “mixed,” and
“qualification hazard,” so treating it as the same three-value machine field
is contradictory. The visible column is retained as display shorthand. The
machine record separates what the source proves from how Mithril uses it:

```text
EvidenceBoundaryKindDraftAbandoned =
  UPSTREAM_EXPLICIT | IMPLEMENTATION_BOUNDARY | FUNDAMENTAL_BOUNDARY |
  NONE_ADOPTED

EvidenceRelationshipDraftAbandoned =
  PRIMARY_OBSERVATION | ADOPTED_BEHAVIOR | ADOPTED_ARCHITECTURE |
  ADOPTED_VOCABULARY | CORRECTION | SUPERSESSION |
  MIXED_ADOPTION_AND_EXTENSION | QUALIFICATION_HAZARD

SourceEvidenceDraftAbandoned {
  evidence_id
  upstream_repository_and_commit
  exact_file_line_ranges[]
  boundary_kind: EvidenceBoundaryKindDraftAbandoned
  relationship: EvidenceRelationshipDraftAbandoned
  claim_digest
  downstream_fixture_ids[]
}
```

That first split is still wrong: `UPSTREAM_EXPLICIT` says **how the assertion
was obtained**, not whether the limitation is an implementation choice or a
fundamental observability boundary. It cannot represent a boundary that is
both explicitly documented upstream and implementation-specific. The
canonical machine types are orthogonal and every umbrella evidence row expands
to one or more atomic claims:

```text
EvidenceBoundaryNatureV1 = NONE | IMPLEMENTATION | FUNDAMENTAL

EvidenceAssertionModeV1 = UPSTREAM_EXPLICIT | CODE_INFERRED |
  UPSTREAM_TEST_PROVED

EvidenceRelationshipV1 =
  PRIMARY_OBSERVATION | ADOPTED_BEHAVIOR | ADOPTED_ARCHITECTURE |
  ADOPTED_VOCABULARY | CORRECTION | SUPERSESSION |
  MIXED_ADOPTION_AND_EXTENSION | QUALIFICATION_HAZARD

SourceRangeV1 {
  repository_url: canonical HTTPS upstream URL
  commit: exactly 40 lowercase hexadecimal bytes
  path: normalized repository-relative UTF-8 path; no `..`
  start_line: u32 > 0
  end_line: u32 >= start_line
  blob_oid: exact Git blob object ID at `commit:path`
}

SourceEvidenceClaimV1 {
  evidence_id
  atomic_claim_id: u16 > 0
  ranges[1..16]: SourceRangeV1
  boundary_nature: EvidenceBoundaryNatureV1
  assertion_mode: EvidenceAssertionModeV1
  relationship: EvidenceRelationshipV1
  normalized_claim_utf8: bounded text with LF line endings
  claim_digest: DigestV1
  downstream_fixture_ids[]
}

claim_digest = SHA-256(
  ASCII("MITHRIL-SOURCE-CLAIM-V1") || 0x00 ||
  deterministic_cbor({evidence_id, atomic_claim_id, ranges,
                      boundary_nature, assertion_mode, relationship,
                      normalized_claim_utf8}))
```

An umbrella such as `KA-CODE-006` remains a readable citation, but its BPF-LSM
socket matching, NFLOG attribution, and Mithril extension are separate atomic
claims with separate ranges and digests. `TG-CODE-005` likewise separates
local node/boot/cache implementation gaps from the fundamental absence of a
provider request edge in a Linux-only sensor. Phase 0 rejects a source fixture
that supplies only the prose `Kind` token or one digest over several claims.

##### Abandoned design: inferring machine evidence from the display `Kind`

The legacy display values below are retained for review history, but they do
**not** lower deterministically. The ledger contains additional tokens and
several mixed rows; the canonical `SourceEvidenceClaimV1` fields above must be
written explicitly.

| Display `Kind` token | Boundary kind | Relationship |
| --- | --- | --- |
| `UPSTREAM_EXPLICIT` | `UPSTREAM_EXPLICIT` | `PRIMARY_OBSERVATION` |
| `IMPLEMENTATION_BOUNDARY`, `stacking boundary`, `DNS implementation boundary`, `path-rendering/object-identity boundary`, `observer read/loss boundary`, `runtime-hook intent/authentication boundary`, `bounded process-state capacity with preserved unknown enforcement` | `IMPLEMENTATION_BOUNDARY` | `PRIMARY_OBSERVATION` |
| `adopted behavior` | `NONE_ADOPTED` | `ADOPTED_BEHAVIOR` |
| `adopted architecture` | `NONE_ADOPTED` | `ADOPTED_ARCHITECTURE` |
| `adopted vocabulary boundary` | `IMPLEMENTATION_BOUNDARY` | `ADOPTED_VOCABULARY` |
| `correction`, `correction to ...` | the corrected row's explicit `UPSTREAM_EXPLICIT` or `IMPLEMENTATION_BOUNDARY` value in `fixtures.yaml`; never inferred from the word | `CORRECTION` |
| `retained/superseded reading` | `IMPLEMENTATION_BOUNDARY` | `SUPERSESSION` |
| `mixed` | `IMPLEMENTATION_BOUNDARY` | `MIXED_ADOPTION_AND_EXTENSION` |
| `qualification hazard`, `audited concurrency hazard` | `IMPLEMENTATION_BOUNDARY` | `QUALIFICATION_HAZARD` |

The retained draft required an explicit boundary kind for corrections and used
`NONE_ADOPTED` for pure adoption. Canonical Phase 0 instead requires explicit
`boundary_nature`, `assertion_mode`, and `relationship` on every atomic claim;
an omitted axis is rejected. The fundamental TLS/provider boundary remains the
separate `SOURCE-BOUNDARY-001` record.

The stable evidence IDs below are referenced by downstream algorithms and
fixtures. They describe the pinned snapshots, not every version or the entire
upstream product.

##### Canonical evidence index by mechanism

The detailed ledger is retained in append order so earlier claims and their
later corrections remain visible. Implementers should navigate it through
this grouped index; a range is an index, not permission to cite every ID in it
without reading the exact row.

| Upstream | Mechanism family | Evidence IDs | Mandatory companion reading |
| --- | --- | --- | --- |
| KubeArmor | BPF-LSM physical decision, telemetry independence, attachment and stacking | `KA-CODE-001`, `KA-CODE-002`, `KA-CODE-003`, `KA-CODE-011`, `KA-CODE-020`, `KA-CODE-021`, `KA-CODE-022`, `KA-CODE-023`, `KA-CODE-028` | `KA-CODE-001` does not describe every hook; use `KA-CODE-011`/`020`/`021`/`022` for the exact program, and `KA-CODE-002`/`003`/`028` for the exact loss path |
| KubeArmor | Runtime timing, process context and observer identity | `KA-CODE-004`, `KA-CODE-005`, `KA-CODE-008`, `KA-CODE-010`, `KA-CODE-017`, `KA-CODE-023`, `KA-CODE-026` | `KA-CODE-005` requires width correction `KA-CODE-010`; shutdown claim `KA-CODE-004` requires `KA-CODE-017`; exec context `KA-CODE-008`/`KA-CODE-026` is not per-task role authority |
| KubeArmor | Network, NFLOG and DNS parser | `KA-CODE-006`, `KA-CODE-012`, `KA-CODE-013`, `KA-CODE-015`, `KA-CODE-025` | attribution wording in `KA-CODE-006` requires `KA-CODE-013`; DNS summary `KA-CODE-012` requires framing/parser corrections `KA-CODE-015`/`KA-CODE-025` |
| KubeArmor | Policy lowering, action vocabulary, map transaction and capacity | `KA-CODE-007`, `KA-CODE-009`, `KA-CODE-014`, `KA-CODE-019`, `KA-CODE-027` | action reading `KA-CODE-009` requires `KA-CODE-014`; map-shape lesson `KA-CODE-007` requires failure/capacity rows `KA-CODE-019`/`KA-CODE-027` |
| KubeArmor | File/path/preset classifier scope and identity bounds | `KA-CODE-016`, `KA-CODE-018`, `KA-CODE-024` | none of these bounded classifiers independently qualifies the broader Mithril object/effect family |
| Tetragon | Fork/exec/process identity, edge tests and bounded state | `TG-CODE-001`, `TG-CODE-002`, `TG-CODE-005`, `TG-CODE-006`, `TG-CODE-014`, `TG-CODE-017`, `TG-CODE-018`, `TG-CODE-020`, `TG-CODE-024` | `TG-CODE-002` prevents a false non-leader-exec criticism; `TG-CODE-020` separates source program from fixture; `TG-CODE-024` preserves upstream unknown enforcement while rejecting unknown Mithril role authority |
| Tetragon | Cgroup/runtime metadata and initial-container gate | `TG-CODE-003`, `TG-CODE-004`, `TG-CODE-009`, `TG-CODE-021`, `TG-CODE-023` | `TG-CODE-004` requires fail-mode correction `TG-CODE-021`; transport/admission claims require authentication/field-join boundary `TG-CODE-023` |
| Tetragon | Generic LSM and separate enforcer action/stacking | `TG-CODE-007`, `TG-CODE-010`, `TG-CODE-011`, `TG-CODE-013`, `TG-CODE-015`, `TG-CODE-019` | `TG-CODE-007` requires mechanism split `TG-CODE-019`; socket example correction is `TG-CODE-015`; prior-return/miss behavior is hook-specific under `TG-CODE-010`/`TG-CODE-011` |
| Tetragon | Observer loss and one-process chassis | `TG-CODE-008`, `TG-CODE-012` | chassis consolidation does not imply ordered loss/WAL coverage truth |
| Tetragon | Policy-filter publication and live mutation | `TG-CODE-016`, `TG-CODE-022` | only fresh forward-inner-map publication is adopted; `TG-CODE-022` forbids an atomic bidirectional-transaction claim |

##### Detailed pinned-code evidence ledger

| Evidence ID | Kind | Validated source behavior and precise Mithril gap |
| --- | --- | --- |
| `KA-CODE-001` | `IMPLEMENTATION_BOUNDARY` | `KubeArmor/BPF/enforcer.bpf.c:10-68` returns literal allow on several missing container/scratch/path lookups. Mithril invariant `INV-EFFECT-001` instead fails a required protected lookup closed. |
| `KA-CODE-002` | adopted behavior | Main exec enforcement in `enforcer.bpf.c:346-412` retains the computed decision when ring reservation fails. Mithril adopts deny-before-evidence ordering. |
| `KA-CODE-003` | `IMPLEMENTATION_BOUNDARY` | `protectenv.bpf.c:78-81`, `filelessexec.bpf.c:91-95`, `anonmapexec.bpf.c:97-100`, `protectproc.bpf.c:86-89`, and `exec.bpf.c:117-120` return allow when event allocation fails. Mithril does not inherit this for a claimed deny. |
| `KA-CODE-004` | `UPSTREAM_EXPLICIT` | `core/nriHandler.go:120-240` documents/implements post-start binding and stop-time removal. That callback shape cannot satisfy Mithril first-exec and protected-shutdown invariants by itself. `KA-CODE-017` controls the precise shutdown reading: the file proves a post-removal window for existing tasks, not PreStop ordering. |
| `KA-CODE-005` | retained/superseded reading | `BPF/system_monitor.c:1362-1376` attempts to propagate parent `exec_id` at `sched_process_fork`; `KA-CODE-010` is mandatory when consuming this ID because the pinned types do not prove correct full-width copying. `monitor/processTree.go:133-428` remains PID-keyed/procfs-assisted. This is an early correlation mechanism, not a synchronous per-task role installed before first effect. |
| `KA-CODE-010` | correction to `KA-CODE-005` | The pinned fork map is declared with a `u64` value at `system_monitor.c:319-328`, but the fork program reads/writes it through `u32 *exists`/`u32 val` at `:1368-1373`; consumers read `u64` at `shared.h:564-570` and `exec.bpf.c:50-53`. The snapshot proves an early propagation mechanism is attempted, not that a full 64-bit execution ID is correctly copied. Mithril must behavior-test it and must not copy this width mismatch. |
| `KA-CODE-006` | `IMPLEMENTATION_BOUNDARY` | BPF-LSM network logic in `enforcer.bpf.c:415-648` primarily matches socket type/protocol; separate nftables/NFLOG code in `networkPolicyEnforcer.go:733-824` and `types/types.go:722-767` collects CIDRs and protocol/ports, while `networkPolicyEnforcer.go:267-303` shows Pod-IP/container-first attribution. Neither joins destination to Mithril's exact process role/entry. The retained phrase “shows ... attribution” is superseded by `KA-CODE-013`: that range is userspace NFLOG enrichment and uses the first endpoint container, not an enforcement key. |
| `KA-CODE-007` | correction | `BPF/shared.h:250-259`, `mapHelpers.go:47-73`, and `rulesHandling.go:414-638` use one per-container inner rule map mutated entry-by-entry. This is not immutable generations plus one atomic active pointer. `KA-CODE-019` additionally proves userspace/BPF divergence is possible on logged map errors. |
| `KA-CODE-008` | `IMPLEMENTATION_BOUNDARY` | `BPF/exec.bpf.c:22-53` uses namespace/TTY/inherited exec context and permits the non-TTY branch. TTY is neither an authenticated probe ticket nor a reliable admin/attacker discriminator. “Inherited exec context” is retained shorthand only: the file directly proves namespace tuple, TTY, and exec-ID-map membership; `KA-CODE-010` controls the attempted fork-propagation qualification. |
| `KA-CODE-009` | adopted vocabulary boundary | `core/kubeUpdate.go:1405-1414` normalizes/defaults policy actions to Allow/Audit/Block; `types/types.go:640-656` merely declares the unconstrained `Action string` schema field. The vocabulary is useful, but this is not a complete entry-admission plus notification plus response transaction. The retained “normalizes/defaults” wording is superseded by `KA-CODE-014`: only lowercase known values and empty are handled; other strings pass the switch unchanged. |
| `KA-CODE-011` | stacking boundary | Exec early misses at `enforcer.bpf.c:10-68` are not the whole stacking story: socket/file programs omit the trailing BPF-LSM `ret` at `:650-690`; `capable` receives `ret` but initializes its own result to zero and returns zero on miss/allow paths at `:692-727,781-808`. Mithril therefore qualifies preserve-prior-return behavior per hook and never generalizes one exec path to all KubeArmor programs. |
| `KA-CODE-012` | DNS implementation boundary | The BPF-LSM DNS path parses `socket_sendmsg` only for destination port 53 and returns allow when state/iovec/data is unavailable or packet size exceeds 512 bytes (`enforcer.bpf.c:1025-1075`); rule-lookup misses also allow at `:889-1002`. Literal-IP traffic, non-53 DNS, DoT/DoH, malformed/oversized messages, and missing state are not semantically covered by that path. This is a checked-in implementation boundary, not proof that BPF can never enforce a broader destination policy. `KA-CODE-015` adds the code-visible `msg_name`, first-iovec, and DNS-over-TCP framing gaps omitted by this retained summary. |
| `TG-CODE-001` | `IMPLEMENTATION_BOUNDARY` | `bpf/process/bpf_fork.c:24-104` skips child state when parent state is absent. That is useful observation behavior but fails Mithril's strict protected-child identity invariant. `TG-CODE-018` controls the additional TGID/one-event-per-thread-group boundary; this is not synchronous per-task role state. |
| `TG-CODE-002` | mixed | `bpf_execve_event.c:284-293,377-399`, `process.h:423-445`, `pkg/sensors/exec/exit_test.go:101-139`, and registration at `exec_test.go:95-100` handle non-leader exec/de-threading observationally; `pkg/process/process.go:268-283` intentionally does not cache per-thread identities. Mithril extends this to per-task authorization, not “Tetragon misses non-leader exec.” |
| `TG-CODE-003` | adopted boundary | `policy_filter.h:27-95` resolves through a cgroup tracker/current cgroup ID and returns non-match when required policy/cgroup state is absent. This is useful numeric membership filtering, but lacks Mithril's authenticated admission lifetime/binding nonce. `pkg/policyfilter/state.go:126-153` warns and retains both memberships when one container ID appears with a different cgroup ID because it cannot decide which is correct; strict Mithril admission rejects/quarantines that conflict. |
| `TG-CODE-004` | `IMPLEMENTATION_BOUNDARY` | OCI hook `contrib/tetragon-rthooks/cmd/oci-hook/main.go:443-459` can fail create before user exec, but `pkg/policyfilter/rthooks/rthooks.go:30-110` and `pkg/policyfilter/state.go:549-589,614-634` can log-and-continue policy/cgroup map failures. Mithril strict admission requires held-task map/readback success before ack. `TG-CODE-021` controls the exact hook reading: `createRuntime` supplies a conditionally fail-capable opportunity, `createContainer` is a no-op, and configured `checkFail` may still allow the container. |
| `TG-CODE-005` | mixed | Tetragon's `exec_id` is cluster-oriented (`tetragon.proto:195-198`, `process_id_linux.go:13-15`); node identity is environment/hostname-derived (`pkg/reader/node/node.go:31-45,67-89`); and the process cache explicitly handles LRU/out-of-order/GC behavior (`pkg/process/cache.go:24-29,50-115,146-214`). It does not provide attested node-boot authority, provider request edges, or complete ordered coverage intervals required by Mithril multi-node causality. |
| `TG-CODE-006` | adopted behavior | `pkg/sensors/exec/fork_test.go:25-66` defines the fork-without-exec fixture and `pkg/sensors/exec/exec_test.go:81-103` registers/runs it. Mithril adds first-effect denial and label-order oracles. |
| `TG-CODE-007` | correction | Generic LSM supports Override/signals (`genericlsm.go:196-220,415-499`, `generic_calls.h:1007-1029`), with enforcer/miss mechanics in `bpf_enforcer.h:30-108`, `bpf_enforcer.c:6-55`, and metrics at `pkg/metrics/enforcermetrics/enforcermetrics.go:50-92`; Tetragon is not observation-only. `TG-CODE-015` separately corrects the socket example's attachment type. Mithril's durable typed causal/response transaction is an extension, not an upstream defect. The phrase joining Generic LSM “with” `bpf_enforcer` is superseded by `TG-CODE-019`: these are separate enforcement mechanisms with separate qualification. |
| `TG-CODE-008` | `IMPLEMENTATION_BOUNDARY` | Observer loss is counted (`observer_linux.go:64-180`, `metrics.go:28-63`), while the event schema at `api/v1/tetragon/events.proto:197-236` lacks Mithril's source epoch/sequence/gap interval. Mithril adds WAL and coverage truth. |
| `TG-CODE-009` | `IMPLEMENTATION_BOUNDARY` | Runtime-hook API exposes initial `CreateContainer` (`tetragon.proto:748-800`, `rthooks/runner.go:23-40`), not one-use probe/lifecycle/streaming-exec tickets. |
| `TG-CODE-010` | qualification hazard | Generic LSM rejects `MatchReturnArgs` and argument indexes above 4 (`pkg/sensors/tracing/genericlsm.go:196-201,223-230`), while `bpf/process/generic_calls.h:795-804` copies only raw arguments 0 through 4. A five-semantic-argument hook such as `path_rename` places the chained BPF-LSM return outside that window. `bpf_generic_lsm_output.c:24-31` returns literal zero when its output heap lookup misses, and only the final `try_override` path returns staged enforcement state. These paths do not establish Mithril's preserve-prior-BPF-return contract on every miss; hook-signature-specific stacked-denial tests are mandatory. |
| `TG-CODE-011` | audited concurrency hazard | Generic LSM override staging uses an `override_tasks` map whose checked-in default is one entry; insert failure is ignored and absent state allows (`generic_maps.h:16-21`, `genericlsm.go:620-623`, `generic_calls.h:853-871`, `basic.h:2719-2733`). This is a required saturation test, not an asserted public vulnerability. |
| `TG-CODE-012` | adopted architecture | One Tetragon binary owns many sensors/streams (`cmd/tetragon/main.go:466-602`). One KubeArmor daemon also owns monitor readers (`monitor/systemMonitor.go:649-654,761-785`), BPF-LSM ring handling (`enforcer/bpflsm/enforcer.go:274-282,317-353`), and preset readers such as `presets/filelessexec/preset.go:100-165`. This validates one gatherer as one durable owner, not one BPF object. |
| `TG-CODE-013` | adopted vocabulary boundary | `generic_calls.h:1090-1103` separates monitor/enforce mode and action cases at `:967-1029` include Post/NoPost/Signal/Override. Mithril preserves that separation and adds typed entry rejection and post-effect/provider response. |
| `TG-CODE-014` | correction to exec lesson | `bpf/process/bpf_execve_map_update.c:28-82` clears match-binary bitsets; it is not the cross-hook exec collection mechanism. That mechanism is supported by `bpf_execve_bprm_commit_creds.c:47-161`, `process.h:423-445,533-571`, and `bpf_execve_event.c:234-249,296,324,350-458`. |
| `TG-CODE-015` | correction to socket example | `examples/tracingpolicy/security-socket-connect-block-others.yaml:6-57` is a `kprobes` policy on `security_socket_connect`, not a `lsmHooks` example. Generic-LSM action support is independently present in `genericlsm.go:196-220` and `generic_calls.h:1007-1029`; the example cannot prove generic-LSM socket-hook coverage. |
| `TG-CODE-016` | policy-map publication nuance | `pkg/policyfilter/map.go:221-252` fills a fresh inner map before publishing its outer entry, while later membership updates mutate the published map entry-by-entry at `map.go:459-528` and `state.go:549-589,751-797`. Mithril may learn initial publish ordering, but immutable full generations and atomic live replacement remain its own requirement. `TG-CODE-022` further limits the adoption: only the fresh forward inner-map fill precedes its publish; reverse-map updates are later and not atomically rolled back. |
| `TG-CODE-017` | contextual init-tree evidence | `bpf/process/bpf_fork.c:61-77` propagates init-tree-related observation state and `api/v1/tetragon/tetragon.proto:301-305` exposes the corresponding process flag. This is useful context, not authenticated kubelet probe/admin intent. |
| `KA-CODE-013` | correction to `KA-CODE-006` attribution wording | `networkPolicyEnforcer.go:209-303` is NFLOG userspace log construction, not the nftables enforcement key. It resolves an endpoint from Pod IP and, when present, records `ep.Containers[0]`; it proves neither exact per-container nor per-process enforcement attribution. CIDR/protocol/port rule generation remains at `:733-824`. |
| `KA-CODE-014` | correction to `KA-CODE-009` normalization wording | `core/kubeUpdate.go:1405-1414` canonicalizes lowercase `allow`/`audit`/`block` and changes only an empty action to `Block`; there is no default branch rejecting or canonicalizing another string. Combined with unconstrained `Action string` at `types/types.go:640-656`, the pin does not prove a closed validated action enum. |
| `KA-CODE-015` | extension of `KA-CODE-012` DNS boundary | `enforcer.bpf.c:1025-1075` reads `skc_dport`, not the per-message `msg_name`, and reads only the first iovec. `shared.h:1221-1263` assumes QNAME starts at byte 12. Therefore unconnected-UDP per-message destinations, a QNAME split across iovecs, and DNS-over-TCP's two-byte length prefix are additional unqualified shapes in this parser. These are pinned implementation boundaries, not fundamental BPF limits. |
| `KA-CODE-016` | correction to practical file-hook wording | At `enforcer.bpf.c:672-690`, pinned KubeArmor enforces read/open policy at `file_open`; `file_permission` returns immediately unless the mask contains write or append. The pin therefore does not prove inherited/passed-fd read-use enforcement. Mithril's separate read-use hook matrix is an owned design and qualification obligation. |
| `KA-CODE-017` | correction to shutdown/PreStop wording | `core/nriHandler.go:181-214` documents `StopContainer` before the runtime sends the termination signal and removes enforcement in that callback. It proves a possible policy-free interval for already-running tasks during signal-driven shutdown; it does not prove Kubernetes orders a `PreStop` handler after that removal. Mithril qualifies PreStop admission and shutdown-retention as separate paths. |
| `TG-CODE-018` | per-task authorization boundary | `bpf/process/bpf_fork.c:33-52` keys clone state by TGID and emits it once per thread group; `bpf/lib/process.h:342-353` documents TGID-tracked exec state; `pkg/process/process.go:268-283` deliberately omits TIDs from the userspace cache. This is useful process-lineage observation, not an authoritative synchronous label for every task/thread. |
| `TG-CODE-019` | correction to `TG-CODE-007` mechanism conflation | Generic-LSM signal/Override actions are implemented through `genericlsm.go:196-220` and `generic_calls.h:967-1029` plus override-task state. `bpf_enforcer.h:30-108`, `bpf_enforcer.c:6-55`, and enforcer metrics describe a separate staged kprobe/fmod_ret enforcer. Both demonstrate enforcement capability, but they are not one mechanism and must be qualified independently. |
| `TG-CODE-020` | correction to fork source-table wording | `bpf/process/bpf_fork.c` implements the observation path; it does not itself test fork-without-exec. The executable fixture is `pkg/sensors/exec/fork_test.go:25-66`, registered at `exec_test.go:100`. Mithril cites the program for placement and the test for the testing lesson. |
| `KA-CODE-018` | preset scope correction | The fileless preset checks only `memfd:`, `/run/shm/`, and `/dev/shm/` shapes (`filelessexec.bpf.c:15-34,77-82`); the anonymous-exec preset checks `PROT_EXEC && MAP_ANONYMOUS` at `lsm/mmap_file` (`anonmapexec.bpf.c:78-100`), not later `mprotect`/`pkey_mprotect`; and `protectproc.bpf.c:17-89` is procfs-path open logic, not general ptrace/process-vm/perf coverage. These classifiers seed Mithril fixtures but do not qualify the larger effect families. |
| `KA-CODE-019` | policy-state failure divergence | `mapHelpers.go:59-73` records a new inner map in userspace before the outer-map `Put` and logs publish failure; `rulesHandling.go:466-488` mutates userspace rule state before a BPF `Put` and logs failures; `rulesHandling.go:590-626` removes userspace entries even when BPF deletion fails. The pin therefore does not prove transactional userspace/kernel policy equality under map errors. Mithril builds, reads back, activates, or rejects; it never treats log-and-continue as activation. |
| `TG-CODE-021` | runtime-hook fail-mode nuance | In `contrib/tetragon-rthooks/cmd/oci-hook/main.go`, the `createContainer` command case is a no-op and `createRuntime` sends the request (`:443-459`); request failure exits nonzero only when `checkFail` selects failure, while `checkFail` explicitly permits a configured allow despite the error (`:352-367`). This is a pre-user-exec failure opportunity conditionally selected by CEL, not strict fail-closed admission by default. |
| `TG-CODE-022` | correction to `TG-CODE-016` transaction wording | `pkg/policyfilter/map.go:221-252` fills a fresh forward inner map before outer publication, then mutates reverse cgroup-to-policy mappings one by one after publication and can return without rolling the published forward entry back. Live adds are likewise forward-then-reverse in `state.go:549-589`. Mithril adopts only the fresh-forward-map publication technique, not atomic bidirectional state or a complete policy transaction. |
| `KA-CODE-020` | partial-attachment boundary | Core exec/file/socket/capability/DNS attachment failures return errors in `enforcer/bpflsm/enforcer.go:133-193`, while path-object load and mknod/link/unlink/symlink/mkdir/chmod/truncate/rename/rmdir attachment failures only warn and continue at `:196-272`. Mithril may expose a measured reduced tier, but full file-mutation activation requires every declared link/program read back; warn-and-continue cannot satisfy it. |
| `KA-CODE-021` | path-hook stacking boundary | Path-mutation programs in `BPF/enforcer_path.bpf.c:7-73` omit the trailing BPF-LSM `ret`; link and rename each use separate source/old and destination/new programs (`:23-57`), and `path_chown` is commented out (`:65-68`). Mithril must qualify prior-denial preservation and complete hook attachment per individual path program, including ordering between the paired link/rename programs. |
| `KA-CODE-022` | DNS/preset stacking boundary | The pinned DNS program (`enforcer.bpf.c:1025-1075`) and preset LSM signatures in `protectenv.bpf.c`, `filelessexec.bpf.c`, `anonmapexec.bpf.c`, `protectproc.bpf.c`, and `exec.bpf.c` omit the trailing BPF-LSM `ret`. A normal nonmatch returning zero can therefore fail to preserve an earlier BPF denial independently of the presets' ring-reservation fail-open paths. Every enabled main, DNS, path, and preset program needs its own stacking fixture. |
| `KA-CODE-023` | observer attachment/coverage boundary | `monitor/systemMonitor.go:587-642` attaches syscall, fork, security and network probes independently; failures warn and delete that probe, perf-reader failure warns at `:651-654`, and initialization can still return nil at `:663`. One-daemon ownership is useful; daemon liveness does not prove complete lineage/evidence coverage. Mithril makes every required attach/reader/readback part of a closed capability record and emits `UNSUPPORTED` or a gap when one is absent. |
| `KA-CODE-024` | path-rendering/object-identity boundary | `BPF/shared.h:315-395` walks at most 20 dentries; the scratch path is 4096 bytes but `MAX_STRING_SIZE` rule keys store 200 bytes (`shared.h:20,73-74,418`), and directory/from-source prefix scans examine only the first 64 positions (`shared.h:809-859,888-922`). A path with more components/bytes, or a relevant directory boundary after byte 63, is not proved equivalent to the full VFS object and can reach truncated/suffix/miss behavior. Mithril uses resolved filesystem/mount/inode generation identity for authority, bounds paths as display evidence, and qualifies deep/long/bind aliases with a physical byte oracle. |
| `KA-CODE-025` | DNS parser boundary | `BPF/shared.h:1221-1263` asks `bpf_probe_read_user` for 256 bytes without checking its return, assumes the first QNAME length at byte 12, and emits at most 63 name characters. `enforcer.bpf.c:1069-1075` rejects only sizes above 512 and ignores `extract_dns_name`'s return. The pin therefore does not prove safe/complete behavior for payloads shorter than 13 bytes, failed/partial user reads, compressed or malformed names, question-boundary/multi-question variants, or legitimate names beyond the emitted bound. Mithril treats this parser as a fixture source; unknown DNS falls back to the IP/destination floor or deny, never a semantic allow. |
| `KA-CODE-026` | evictable exec-context boundary | `BPF/system_monitor.c:261-272,319-328` declares the pinned `kubearmor_exec_pids` as a 10,240-entry LRU map. The exec preset's `BPF/exec.bpf.c:35-53` returns allow for a non-TTY task or a missing exec-ID entry. Under churn, eviction or a missing propagation record is therefore an allow in that preset path. Mithril may use an LRU for observation hints, but authoritative task/process/role state is non-evictable; capacity failure denies protected admission/effects. |
| `KA-CODE-027` | compiled-map capacity/publication boundary | `enforcer/bpflsm/enforcer.go:81-98` fixes the outer container map and each inner rule map at 256 entries. The `(pidns=0,mntns=0)` host entry in `mapHelpers.go:128-148` consumes one outer slot **only when** `cfg.GlobalCfg.HostPolicy` makes `enforcer.go:283-285` call `AddHostToMap()`. Userspace can retain/log a failed outer publication, while BPF required-lookup misses reach allow paths described by `KA-CODE-001`/`KA-CODE-019`. Capacity must therefore be measured in compiled map entries—not YAML rule count—and strict Mithril activation remains non-`ACTIVE` until every map/link/value readback matches. `SOURCE-KA-CAPACITY-005` tests 256 container publications with `HostPolicy=false`, then host plus 255 and host plus 256 with `HostPolicy=true`; the over-capacity generation never activates. |
| `KA-CODE-028` | observer read/loss boundary | `monitor/systemMonitor.go:761-789` logs ordinary perf-read errors and continues, logs and discards `LostSamples`, exits on a closed reader, and exits immediately for a nil reader. These are observation-source gaps, distinct from the main BPF-LSM decision path: `KA-CODE-002` shows main exec denial survives event reserve failure, while `KA-CODE-003` shows several presets return allow on their own reserve failure. Mithril records source-specific coverage and physical result instead of using one generic “KubeArmor loss” claim. |
| `TG-CODE-023` | runtime-hook intent/authentication boundary | The OCI hook opens gRPC with `insecure.NewCredentials` (`contrib/tetragon-rthooks/cmd/oci-hook/main.go:83-99`); the node server creates a Unix socket with mode `0660` when configured for Unix transport (`cmd/tetragon/main.go:859-873`) and forwards `RuntimeHookRequest` to hook handlers (`pkg/server/server.go:554-562`). The protobuf `CreateContainer` carries metadata but no signer/key ID, nonce, expiry, one-use claim slot, or held-task handle (`api/v1/tetragon/tetragon.proto:748-800`). `pkg/rthooks/args.go:47-67,81-85,98-103,133-142` accepts a supplied Pod UID/container ID while resolving cgroup ID from the separately supplied cgroup path. This is useful trusted-socket metadata plumbing, not a vulnerability claim and not cryptographic Mithril intent. Mithril signs the canonical body, enforces replay/expiry/one-use, and proves Pod/container/cgroup/task belong to one live transaction. |
| `TG-CODE-024` | bounded process-state capacity with preserved unknown enforcement | `bpf/lib/process.h:380-385,490-515` defines a bounded hash `execve_map` and returns no entry after failed insertion; `pkg/sensors/base/base.go:27,108-153` sets a configurable default of 32,768. The fork path can consequently skip detailed inherited state. Importantly, `pkg/sensors/tracing/kprobe_sigkill_test.go:119-187` deliberately shrinks the map to one and proves a policy action still enforces with the process flagged `unknown`. Mithril adopts that hostile capacity test, while extending the result: `unknown` observation is not sufficient role authority, so a protected task gets preallocated fail-closed state or its effect/admission denies. |

Fundamental boundary `SOURCE-BOUNDARY-001` applies to both studies and Mithril:
generic LSM/socket/packet evidence on encrypted same-destination TLS does not
reveal Git clone versus push or a specific Kubernetes/cloud verb, and Linux
hooks cannot revoke a remote IAM session. Target/version-specific uprobes or
application instrumentation may sometimes observe pre-encryption plaintext,
but that is a separately qualified, mutable observation surface and is not
authenticated provider-semantic proof. The production choices are a typed
coordinator/provider audit or gate, scoped capability, explicitly qualified
plaintext instrumentation, or an honest whole-channel decision—not an
unqualified “more eBPF” claim. Remote session revocation still requires the
provider's authority/API.

#### Scenario boundary index: why the pinned mechanisms are insufficient alone

This is the precise meaning of “KubeArmor/Tetragon are shy of the Mithril
contract.” It does not claim either project is incapable of future work. It
names the concrete proof missing from the pinned code and the exact mechanism
Mithril must add.

| Real operation | What the pinned code actually provides | Missing Mithril proof | Boundary nature | Local code evidence | Mithril addition and rejection test |
| --- | --- | --- | --- | --- | --- |
| Python opens a mounted ServiceAccount token while a required map/scratch/path lookup is absent or its alias exceeds a path key | KubeArmor has semantic BPF LSM file hooks, but several early protected-state lookup paths return allow and its pinned rendered path/key is component/byte bounded | a protected lookup/classification failure or alias cannot widen authority | `IMPLEMENTATION` | `KA-CODE-001`, `KA-CODE-003`, `KA-CODE-011`, `KA-CODE-016`, `KA-CODE-020`, `KA-CODE-021`, `KA-CODE-024` | task-first protected-scope lookup plus resolved object identity and typed fail-closed miss; delete/exhaust each required map and use 21-component/>200-byte bind aliases while the token byte oracle still returns `EACCES`; qualify open and already-open read-use separately |
| Child forks and reads the token before a userspace event arrives | KubeArmor attempts fork-time `exec_id` propagation through a bounded LRU but the pinned value widths conflict and its exec preset allows a missing entry; Tetragon records bounded process/TGID-oriented state, skips detailed fork state when the parent is absent, yet correctly preserves selector-independent signal enforcement in its capacity test | correct full-width, synchronous non-evictable child task/process/domain restriction before first effect | `IMPLEMENTATION` | `KA-CODE-005`, `KA-CODE-010`, `KA-CODE-026`, `TG-CODE-001`, `TG-CODE-006`, `TG-CODE-018`, `TG-CODE-020`, `TG-CODE-024` | owned task-allocation/inheritance path plus fork-without-exec byte oracle and N+1 capacity case; preserve a separately qualified deny but never authorize a role from missing/unknown state |
| Initial container must be protected before its first user instruction | KubeArmor's pinned NRI callback records post-start timing; Tetragon's OCI `createRuntime` path can conditionally fail before user exec, but its failure policy/map updates can continue and its local request is metadata plumbing without signed one-use task authority | held exact task, signed/replay-safe request, Pod/container/cgroup consistency, successful map/readback transaction, and no user exec on partial install | `IMPLEMENTATION`; coordinator intent itself is `FUNDAMENTAL` to kernel-only evidence | `KA-CODE-004`, `KA-CODE-017`, `TG-CODE-004`, `TG-CODE-021`, `TG-CODE-023` | target-qualified held-entry gate; mix Pod-A identity with Pod-B cgroup, replay it, and inject failure after every write; no marker binary runs except the one exact valid claim |
| Kubelet probe, native attacker child, and `kubectl exec` run identical `/app/healthcheck` bytes | KubeArmor has TTY/non-TTY/inherited execution context; Tetragon exposes initial create-container metadata and init-tree context | authenticated one-use reason and exact live-task binding for each later root | split claims: pinned later-entry transport is `IMPLEMENTATION`; deriving intent from identical kernel effects is `FUNDAMENTAL` | `KA-CODE-008`, `TG-CODE-009`, `TG-CODE-017` | `SignedIntentV1` → `IntentPayloadV1(kind=RUNTIME_ENTRY)` → `RuntimeEntryBodyV1` plus `ENTRY-PROBE-IMPERSONATION-003`; `RuntimeEntryIntentV1` is an abandoned name, and command/cgroup/namespace/timing/TTY are hostile controls, never authority |
| Two processes in one Pod need different destination budgets | KubeArmor's LSM network path uses socket type/protocol while its CIDR/port enforcement is separate; NFLOG enriches by Pod IP and first endpoint container rather than enforcing per process | one exact task/entry/authority-domain decision carried into socket provenance and packet policy | `IMPLEMENTATION` | `KA-CODE-006`, `KA-CODE-012`, `KA-CODE-013`, `KA-CODE-015` | role-aware socket storage plus current-actor/domain intersection; two Python roots at one Pod IP must receive different physical results |
| DNS leaves through literal IP, short/malformed packet, long QNAME, unconnected UDP `msg_name`, split iovec, large UDP, TCP, non-53, DoT or DoH | KubeArmor's checked BPF DNS parser is limited to port 53, first-iovec/bounded packet/state shapes, assumes byte-12 QNAME framing, ignores one user-read/parser result, emits at most 63 characters, and contains allow-on-miss paths | explicit coverage for every advertised resolver/packet form, an independent destination floor, and honest TLS opacity | parser/coverage is `IMPLEMENTATION`; encrypted application meaning is `FUNDAMENTAL` | `KA-CODE-012`, `KA-CODE-015`, `KA-CODE-025`, `SOURCE-BOUNDARY-001` | destination/packet controls and protocol-specific fixtures at every length/framing boundary; malformed/unknown follows destination deny, and unsupported encrypted semantic names cannot become “DNS prevented” |
| Policy changes two coupled permissions while workers keep running or reaches N+1 compiled entries | KubeArmor mutates one bounded per-container inner rule map entry by entry and can diverge userspace/BPF state on logged publication errors; Tetragon fills a fresh forward inner map but later reverse/live membership changes are not one transaction | complete immutable generation, preflight compiled cardinality, one atomic binding switch, retained old references and readback equality | `IMPLEMENTATION` | `KA-CODE-007`, `KA-CODE-019`, `KA-CODE-027`, `TG-CODE-016`, `TG-CODE-022` | pause/fail between every old/new/forward/reverse write and test N/N+1 expanded entries; a decision sees all generation N or all N+1, never a mixture, and an over-capacity generation never becomes active |
| A previous LSM has denied an operation | KubeArmor and Tetragon behavior differs by program/hook; neither checked source proves Mithril's preserve-prior-return invariant everywhere, including paired path link/rename programs | per-hook preservation of an earlier denial through every allow/miss/error branch | `IMPLEMENTATION` | `KA-CODE-011`, `KA-CODE-020`, `KA-CODE-021`, `KA-CODE-022`, `TG-CODE-010`, `TG-CODE-019` | attach a deterministic earlier-deny probe and run every required program, paired ordering, lookup-miss, saturation and telemetry-loss branch |
| A probe/reader fails or an event ring loses records while an operator asks “did no attack occur?” | KubeArmor can remain initialized while an individual attach/reader fails and logs/discards perf loss; its main denial and preset reserve-failure paths have different physical results. Tetragon counts observer loss but its event schema does not supply Mithril source epoch/ordered coverage-gap intervals | per-source closed interval proving which negative conclusions and physical-denial claims remain eligible | `IMPLEMENTATION` | `KA-CODE-002`, `KA-CODE-003`, `KA-CODE-023`, `KA-CODE-028`, `TG-CODE-008` | node WAL plus `CoverageIntervalV1` per link/reader/decision path; observation loss keeps a separately proven deny but forces `INSUFFICIENT_COVERAGE` for absence, while a preset fail-open can never be reported denied |
| Same process and existing TLS channel can legitimately clone and maliciously push | Linux LSM/socket/packet evidence sees the channel and bytes, not the authenticated GitHub verb | server-owned operation/result identity or a pre-issued operation-specific capability | `FUNDAMENTAL` for kernel-only evidence | `SOURCE-BOUNDARY-001` | direct TLS stays direct; use GitHub/provider audit or typed semantic gate for detection/rejection, or deny the whole channel and disclose that blast radius |

Each row has both a legitimate negative control and a hostile proof later in
the effect/entry matrices. A developer cannot replace the named code evidence
with “KubeArmor/Tetragon do not support X,” and cannot replace the missing proof
with another event collected after the effect.

#### What to learn from KubeArmor

| Source mechanism | Useful lesson | Mithril adaptation | What Mithril must not inherit |
| --- | --- | --- | --- |
| [`enforcer.bpf.c`](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c) defines `SEC("lsm/...")` programs at exec, file, socket, and capability decision points; [`enforcer.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/enforcer.go) loads/attaches them | Select semantic pre-effect LSM hooks and return a denial before completion | Organize owned CO-RE programs by effect family and preserve the earlier LSM return value | A missing protected-container map, scratch map, or path must not silently return allow |
| [`rulesHandling.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go) compiles higher-level process/file/network/capability rules into bounded map keys and bit masks; source-path lowering appears at `rulesHandling.go:124-165,384-405` and runtime current/parent executable lookups at `enforcer.bpf.c:78-123,452-539,733-779` | Keep policy parsing and conflict resolution in userspace; keep the kernel tuple compact | The Rust compiler produces reviewed immutable generations and finite role/effect keys | Paths and “from source path” are not durable process roles or executable identity |
| [`shared.h`](../../../KubeArmor/KubeArmor/BPF/shared.h) and [`mapHelpers.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go) use a map-of-maps for per-container generations | Map indirection is a practical atomic policy-generation technique | Bind a stable workload/profile generation to a cgroup identity, then switch one active-generation pointer | PID and mount namespace numbers are reusable context, not the workload key |
| The main exec enforcer retains its decision when ring-buffer reservation fails | Enforcement and alert transport must be independent | Compute and commit the return value before best-effort evidence emission; increment loss counters on failure | Some presets, including [`protectenv.bpf.c`](../../../KubeArmor/KubeArmor/BPF/protectenv.bpf.c), [`filelessexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/filelessexec.bpf.c), and [`anonmapexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/anonmapexec.bpf.c), return allow when event reservation fails; that ordering is forbidden |
| Fileless exec, anonymous executable mapping, `/proc/*/environ`, and process inspection presets choose concrete kernel hooks | These are useful object classifiers and acceptance cases | Make them ordinary role-aware effect classes with explicit policy and coverage | A global preset keyed by the PID+mount namespace `outer_key` tuple (`BPF/shared.h:523-535`) still cannot decide which process role legitimately needs the effect |
| [`nriHandler.go`](../../../KubeArmor/KubeArmor/core/nriHandler.go) explicitly records that `StartContainer` occurs after start, namespace IDs can be reused, and enforcement is removed before shutdown | Runtime callback timing and teardown order are security properties | Full protection requires a pre-exec gate, exact lifetime identity, and policy retained through `preStop` and termination | Post-start binding cannot be advertised as enforce-from-first-exec; stop notification cannot remove policy before the last task exits |
| [`processTree.go`](../../../KubeArmor/KubeArmor/monitor/processTree.go) enriches a userspace PID tree and falls back to procfs | Procfs recovery is useful for explicit bootstrap and display | Reconstruct existing tasks as `bootstrapped` and retain the gap | A userspace PID cache is not race-free lineage or actuator identity |
| [`enforcer.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/enforcer.go) treats core and path attachment failures differently; several path failures warn and continue | Link-by-link activation state matters more than daemon liveness | Compile a closed required-link manifest, read back every ID/digest, and run hook-specific physical probes before strict release | A healthy daemon or one attached file program cannot stand for complete file-mutation enforcement (`KA-CODE-020`) |
| [`systemMonitor.go`](../../../KubeArmor/KubeArmor/monitor/systemMonitor.go) can continue after individual attach failure and logs/discards read/lost-sample failures | One gatherer needs source-specific health, not one process-ready bit | Maintain per-source epochs, sequence/gap intervals, and negative-claim eligibility while keeping already-proven kernel decisions separate | Reader loss must not be hidden, and it must not be conflated with the main enforcer or preset physical result (`KA-CODE-023`, `KA-CODE-028`) |
| [`shared.h`](../../../KubeArmor/KubeArmor/BPF/shared.h) bounds dentry/path/directory/DNS parsing and [`exec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/exec.bpf.c) consumes an evictable exec-context map | Bounded extraction is necessary for BPF but needs explicit unknown semantics | Use live object identity and destination floors for authority; use bounded text as quality-labeled evidence; keep security identity non-evictable | A truncation/parser/map miss cannot mean “not protected” (`KA-CODE-024`, `KA-CODE-025`, `KA-CODE-026`) |
| [`enforcer.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/enforcer.go) fixes outer and inner maps at 256 entries and [`mapHelpers.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go) logs publication failures | Capacity and kernel/userspace equality are activation inputs | Count expanded entries, reject N+1 before publication, read back exact values, and keep prior generation active | Human/YAML rule count or userspace state cannot prove a kernel generation is installed (`KA-CODE-019`, `KA-CODE-027`) |

##### Abandoned interpretation: KubeArmor map-of-maps is policy generations

The retained third row is factually wrong if “per-container generations” means
immutable generation N/N+1 with one atomic active switch. `KA-CODE-007` shows
one inner rule map per container/namespace identity and live entry-by-entry
updates/deletes. Map indirection is still useful, but Mithril's immutable
generation build, readback, switch, reference retirement, and mixed-state test
are an independent design.

**Concrete update test.** Generation 12 denies token read and allows dataset
read; generation 13 changes both. Pause a test updater after removing one old
key and before inserting its replacement while workers perform both opens.
An in-place map update can expose a mixture. Mithril must build all of 13 in an
inactive map, read it back, switch one binding, and prove every decision used
all of 12 or all of 13.

##### Correction: KubeArmor lineage and network are richer than the short table

`KA-CODE-005` originally appeared to prove the system monitor copies a parent
`exec_id` to the child PID at fork; KubeArmor is not purely a post-hoc procfs
tree. `KA-CODE-010` corrects that reading: the pinned source has a `u64` map
value but `u32` fork lookup/write variables, so it proves an early propagation
attempt, not correct full-width copying. Mithril learns the placement of the
early signal, does not inherit the width mismatch, and requires a
fork-before-first-effect behavior oracle rather than source inspection alone.

`KA-CODE-006` also prevents the false statement “KubeArmor has no CIDR/port
network policy.” Its separate nftables/NFLOG enforcer does. The practical gap
is role/entry attribution across separate enforcement paths: two Python roots
at one Pod IP can receive different Mithril roles, while endpoint-IP policy
cannot by itself distinguish their intent. That is a checked-in architecture
boundary, not a fundamental nftables/BPF limitation.

##### Practical KubeArmor lesson examples

The table above is intentionally compact. The following examples make each
lesson concrete and state why Mithril adopts one part of the mechanism without
inheriting the weaker identity or failure behavior around it.

###### 1. Put the decision at the semantic LSM effect hook

**Example.** A dataset-conversion Python process tries to open the projected
service-account token at
`/var/run/secrets/kubernetes.io/serviceaccount/token`. An exec-only sensor sees
no new command because Python calls `open(2)` in-process. A BPF LSM
`file_open`/`file_permission` decision—the two hooks used by the pinned
KubeArmor enforcer at `BPF/enforcer.bpf.c:672-690`—can reject that operation with
`EACCES` before any token byte reaches Python. The same principle applies when
the process calls `connect(2)` or requests a capability: decide at the hook
that mediates the real effect, not by guessing from a preceding command.

**Mithril adoption.** Implement owned, small CO-RE BPF LSM programs for file,
exec, socket, and capability effect families. Resolve the already-attached
task role and immutable policy generation, calculate the decision, preserve a
prior denial, and only then attempt to emit evidence.

**What not to inherit.** A lookup failure must not mean “unprotected” merely
because a task-to-container map, scratch map, path buffer, or classifier entry
is missing. For a task already proven to be in a protected cgroup, such a miss
is an identity or coverage failure and follows the profile's fail-closed rule.

**Why.** Otherwise an attacker does not need to evade the policy. It only
needs to create map pressure, hit an unhandled path shape, or race startup so
that the enforcement program returns allow.

###### Correction: pinned `file_permission` does not cover token-read use

The retained example's phrase “`file_open`/`file_permission` ... can reject
that operation” is too broad. `KA-CODE-016` proves that this KubeArmor pin
checks the token's read/open policy at `file_open`; its `file_permission`
program immediately returns allow unless the mask includes write or append.
It therefore does not prove that an fd opened before restriction, inherited
across fork, received through `SCM_RIGHTS`, or otherwise already present will
be stopped on a later read.

The correct Mithril implementation keeps the useful `file_open` lesson and
adds an independently qualified read-use matrix. For each advertised kernel it
must name the exact hook/path that covers `read`, `pread`, vectored I/O,
`io_uring`, splice/copy paths, page fault/mmap, and descriptor transfer, or mark
the shape `UNSUPPORTED`. In `FILE-SA-TOKEN-OPEN-001`, open denial proves no fd
was returned. In the pre-opened-fd variant, the separate sentinel-byte oracle
must prove that zero protected bytes reached the caller; seeing the original
`file_open` is irrelevant to that variant.

###### 2. Compile rich policy in userspace and keep kernel decisions finite

**Example.** A policy author writes: “the `conversion-worker` role may read
the checked-out dataset and write `/work/output`, but it may not read projected
credentials.” The Rust compiler can resolve mount-aware object identities,
conflicts, and defaults once, then lower the result to bounded keys such as
`(profile_generation, role_id, effect_class, object_class) -> decision`.
The BPF program does not need to parse YAML, traverse an arbitrary rule list,
or resolve precedence on every `open(2)`.

**Mithril adoption.** Use the KubeArmor pattern of userspace compilation and
compact kernel maps, but make the Rust compiler produce a validated,
immutable, signed generation with deterministic conflict resolution and a
reviewable compiled manifest.

**What not to inherit.** Do not make `/usr/bin/curl`, `python`, a process name,
or “started from this path” the durable role. An approved updater and a
compromised dataset worker may both execute the same `/usr/bin/curl`; the
attacker can also copy or rename a binary.

**Why.** A path identifies an object in a particular mount view. It does not
prove why the process exists, which admitted entry created it, or which
authority it should have.

###### 3. Use map indirection for atomic generations, not namespace identity

**Example.** Profile generation 12 is active while a reviewed generation 13
is loaded. Mithril populates generation 13 completely, verifies it, and then
atomically changes one binding pointer. A new decision sees either all of 12
or all of 13; it never sees a half-populated mixture. Generation 12 remains
resident while an existing task or socket still references it.

**Mithril adoption.** Use a map-of-maps or equivalent BPF map indirection to
bind a live cgroup interval and execution set to one immutable policy
generation, with explicit reference retirement.

**What not to inherit.** Do not key durable workload authority by PID
namespace, mount namespace, or an unqualified cgroup number. Container A can
exit and container B can later receive a reused numeric namespace or cgroup
identifier.

**Why.** Without a live interval, full container identity, and generation,
container B could inherit container A's permissions or containment state even
though the number happens to match.

###### 4. A full evidence channel must not cancel a denial

**Example.** Compromised code generates 100,000 forbidden exec attempts and
fills the ring buffer. The 100,001st attempt still returns `-EACCES`. Mithril
increments a per-CPU loss counter and later reports that evidence was dropped,
but the attempted shell does not start.

**Mithril adoption.** Follow the main KubeArmor exec enforcer's useful
ordering: calculate and commit the enforcement return value before reserving
or constructing an event.

**What not to inherit.** Do not copy preset paths that return allow when a
ring-buffer reservation fails.

**Why.** Alert transport is attacker-influenceable load. If event allocation
controls authorization, flooding telemetry becomes a deterministic policy
bypass.

###### 5. Treat presets as effect classifiers, not universal container rules

**Example.** Reading another process's `/proc/<pid>/environ` is expected for a
narrow diagnostic role but suspicious for a dataset converter. Anonymous
executable memory may be expected for an approved JIT runtime but forbidden
for an image-conversion worker. The kernel hook and object classification are
useful in both cases; the correct answer depends on the task's admitted role.

**Mithril adoption.** Reuse the underlying ideas—fileless execution,
executable anonymous mappings, environment inspection, and process
inspection—as explicit effect classes in the normal role/effect policy model.

**What not to inherit.** Do not turn them into global “container on/off”
presets keyed only by namespace or workload membership.

**Why.** A Pod can contain application, sidecar, probe, lifecycle, and
administrative execution roots with deliberately different budgets. A single
container-wide answer either blocks legitimate operation or gives the
compromised role excessive authority.

###### Correction: pinned presets are classifier seeds, not full effect families

The retained names “fileless execution,” “anonymous executable mappings,” and
“process inspection” sound broader than the checked programs. `KA-CODE-018`
narrows them to specific memfd/shm executable-name shapes, anonymous
`PROT_EXEC` at `mmap_file`, `/proc/*/environ`, and procfs cross-process open
logic. They do not prove later `mprotect`/`pkey_mprotect`, every memfd alias,
ptrace, `process_vm_*`, or perf coverage.

Mithril uses each checked hook as one fixture seed. The larger `CODE_LOAD` or
`PROCESS_INSPECTION` class may be advertised only after the effect/bypass
matrix enumerates and passes every constituent operation. A process denied on
`/proc/123/environ` but allowed to read the same memory through
`process_vm_readv` has passed one classifier fixture and failed the claimed
family.

###### 6. Runtime timing must protect the first instruction through the last

**Example.** If enforcement is installed only after `StartContainer`, the
entrypoint can read a token and send it before the callback arrives. At the
other end, if policy is removed when `StopContainer` begins, a malicious
`PreStop` command can exfiltrate during the termination grace period.

**Mithril adoption.** Require a pre-exec admission handshake for strict
profiles, bind the exact root before its user image runs, and keep the binding
and referenced policy generations until the last protected task and socket
have exited or been explicitly invalidated.

**What not to inherit.** Do not advertise post-start discovery as protection
from first exec, and do not use a stop notification as proof that no protected
task remains.

**Why.** Startup and shutdown are attacker-usable execution windows, not
administrative bookkeeping outside the security boundary.

###### Correction: the pinned NRI order does not prove PreStop-after-removal

The retained phrase “a malicious `PreStop` command can exfiltrate” may be a
valid workload threat, but the cited KubeArmor code does not prove that
ordering. `KA-CODE-017` shows only that its `StopContainer` callback removes
enforcement before the runtime sends the termination signal. The source-backed
counterexample is an **already-running task** that performs a file/socket
effect in the interval after removal and before signal-driven shutdown.

Mithril treats Kubernetes lifecycle admission as a separate qualified path:

1. an `exec` PreStop handler is a later runtime-created root and needs its own
   held `LifecycleHookEntry` ticket before execution;
2. an HTTP PreStop handler is a kubelet-originated request whose server-side
   effect remains in the existing application task/domain;
3. a sleep handler creates no workload process but still delays the lifetime
   during which existing tasks remain protected; and
4. policy and object references retire only after every task/socket lifetime
   and the runtime/container terminal transition are reconciled.

The platform fixture pauses each handler and the stop callback in both
observable orders. A full-support result must show no interval in which an
already-running task or newly admitted exec handler can use an unprotected
effect. The implementation cannot infer Kubernetes PreStop ordering from this
NRI file.

###### 7. Procfs recovery is evidence of a gap, not reconstructed certainty

**Example.** `mithril-node` restarts and discovers PID 4242 in a protected
cgroup through procfs. It can record executable, cgroup, namespace, and current
parent coordinates, but it cannot prove that no missed fork, exec, or
reparenting transition occurred while the sensor was unavailable. Later, PID
4242 can exit and the kernel can reuse the number.

**Mithril adoption.** Create an explicit `bootstrapped` observation with its
known coordinates, unknown interval, source quality, and conservative role so
operators can see and contain the affected execution set.

**What not to inherit.** Do not promote the reconstructed userspace PID tree
to exact birth lineage, use its cached PID as a later kill handle, or silently
close the missing interval.

**Why.** Procfs is a current snapshot. It cannot retrospectively prove event
order, and a PID is reusable. Exact response requires live re-resolution such
as pidfd plus start-time and cgroup validation.

###### 8. “Daemon ready” is not “every enforcing link attached”

**Example.** An operator installs a rule intended to block moving a projected
credential into `/work`. The main file-open program attaches, but the
`path_rename` link fails. In the pinned KubeArmor loader, several path-object
attachment failures warn and continue (`KA-CODE-020`), so the daemon may still
look healthy while the exact mutation path is absent.

**Mithril adoption.** Compile a closed required-program list for the selected
profile and kernel. Activation remains `PREPARING` until the loader reads back
every expected program/link ID and digest and runs an allow/deny probe for each
hook. The UI says `path_rename: ATTACH_FAILED`; strict workload release is
rejected or the operator selects a disclosed reduced profile.

**What not to inherit.** Do not derive security readiness from process
liveness, the presence of one BPF link, or a warning-only loader result.

**Why.** Enforcement is the conjunction of the paths the claim names. Nine
attached file programs do not physically cover the tenth missing operation.
`SOURCE-KA-PARTIAL-ATTACH-001` injects failure independently for every path
link and proves no full-file-mutation capability becomes `ACTIVE`.

###### 9. Preserve a prior BPF denial in every individual LSM program

**Example.** Earlier BPF program A returns `-EPERM` for a rename. A later path,
DNS, or preset program that has no trailing chained-return argument and returns
literal zero on nonmatch can invalidate the expected stacked result. The
pinned KubeArmor main exec path cannot be generalized to its separate path,
DNS, capability, or preset signatures (`KA-CODE-011`, `KA-CODE-021`,
`KA-CODE-022`).

**Mithril adoption.** Generate and qualify each hook prototype separately.
Where the kernel ABI exposes the prior BPF return, check it before every map,
scratch, parser, or evidence operation and return the exact nonzero value. If a
chosen program shape cannot receive/preserve it, do not advertise stacked
enforcement for that path.

**What not to inherit.** Do not test one exec hook and stamp “LSM stacking
supported” on all objects. Do not treat an event from the earlier program as a
substitute for the physical return value.

**Why.** Attachment order and signature shape decide whether two controls
compose. `SOURCE-KA-STACK-PER-HOOK-002` places an earlier deny before every
Mithril hook, forces every later miss/event-allocation failure, and asserts the
syscall still receives the original errno.

###### 10. Observer initialization is not coverage truth

**Example.** The fork probe fails to attach, or the perf reader becomes nil or
closed, while file enforcement remains active. The pinned system monitor can
warn, delete/skip the failed probe, log lost samples, and continue or return
from that reader without making the daemon itself unavailable (`KA-CODE-023`,
`KA-CODE-028`). A dashboard based only on Pod readiness would still show green
while native lineage has a gap.

**Mithril adoption.** Give each source its own epoch, attachment identity,
reader state, last sequence, lost-count interval, and negative-claim
eligibility. A failed fork source makes lineage `GAPPED`; it does not change an
already computed BPF-LSM deny. Admission that requires exact lineage remains
closed until repair/readback.

**What not to inherit.** Do not merge “event loss” into one boolean or infer
that enforcement failed because observation lost samples. Conversely, do not
infer complete lineage because another enforcer still denies files.

**Why.** The physical result differs by code path: main exec denial survives a
ring reserve failure (`KA-CODE-002`), several presets allow on their reserve
failure (`KA-CODE-003`), and system perf loss discards observations only.
`SOURCE-KA-READER-LOSS-003` exercises all three and verifies three different
coverage/result records.

###### 11. Bounded strings and parsers are evidence, not object authority

**Example.** A protected directory boundary appears after byte 63 in a
200-plus-byte path, a file has 21 parent components, or a DNS datagram is 12
bytes long, malformed/compressed, split, or contains a legitimate name longer
than the parser's 63-character output. The pinned path and DNS code has those
exact bounds and unchecked shapes (`KA-CODE-024`, `KA-CODE-025`). A textual
miss does not prove that the VFS object or destination was outside policy.

**Mithril adoption.** Resolve filesystem authority from mount/filesystem/object
identity and apply an IP/destination network floor independently of DNS.
Bounded paths/names remain explanations and optional selectors with explicit
`EXACT|TRUNCATED|MALFORMED|UNKNOWN` quality. Required unknown classification
denies.

**What not to inherit.** Do not make a truncated path suffix, first 64
positions, or partially decoded QNAME the final allow key. Do not silently
skip a short/long/malformed DNS packet while claiming DNS egress prevention.

**Why.** Attackers choose names and packet framing. `SOURCE-KA-BOUNDS-004`
places the relevant directory boundary at bytes 63/64/65, varies 20/21
dentries and 199/200/201-byte keys, and sends DNS payloads below 13 bytes,
exact/over 63 output characters, failed user reads, compression/malformed and
multiple questions. Every unknown strict branch follows the object/destination
floor; a valid ordinary path and FQDN are positive controls.

###### 12. Preflight compiled cardinality and never evict authority

**Example.** A cluster has 256 container entries including host policy, or one
human rule expands into more than 256 path/source/action keys. Separately,
10,241 live exec contexts churn a 10,240-entry LRU. The pinned map sizes and
miss behavior are concrete implementation choices (`KA-CODE-026`,
`KA-CODE-027`); YAML rule count and apparent userspace configuration do not
prove that the kernel contains the authority state.

**Mithril adoption.** The compiler reports exact expanded entries per map,
reserves failure headroom, rejects an over-capacity generation before
publication, and reads every active entry/digest back. Task/process/domain and
decision authority use non-evictable maps; exhaustion denies the affected
protected admission/effect and opens a health defect.

**What not to inherit.** Do not log a failed outer-map `Put` and keep a
userspace “configured” state. Do not use an LRU whose missing entry means allow
for a security identity.

**Why.** Capacity is adversary-influenceable state. `SOURCE-KA-CAPACITY-005`
tests N and N+1 compiled rule/container entries, counts the host slot, forces
outer publication failure, and churns beyond the exec LRU capacity. A strict
workload never becomes `ACTIVE` on an unreadable/missing kernel entry.

One additional stacking rule is mandatory. BPF LSM programs receive the return
value from an earlier LSM/BPF program. Mithril never turns an earlier denial
back into success:

```text
if prior_ret != 0:
    record prior denial if possible
    return prior_ret
```

Mithril's policy can make a result stricter. It cannot weaken SELinux,
AppArmor, Landlock, another BPF LSM program, or an earlier Mithril program.

##### Practical LSM-stacking example

SELinux denies a write to `/etc/shadow` and passes a nonzero `prior_ret` into
Mithril's BPF LSM program. Even if Mithril's own profile would otherwise allow
the role to write the classified object—or Mithril cannot find its policy
map—the only correct return is that original nonzero value. Returning `0`
would not mean “Mithril has no opinion”; it would erase another active
security module's denial. This is why every Mithril LSM path checks and
preserves `prior_ret` before considering its own allow result.

##### Abandoned design: treating a static LSM denial as BPF `prior_ret`

The two retained paragraphs immediately above are wrong if read as saying
that SELinux, AppArmor, or another static LSM passes its result through the
`ret` argument of a Mithril BPF LSM program. That implementation is abandoned.
The BPF LSM `ret` argument carries the result of a previously executed **BPF
LSM program attached to the same hook**. Depending on the target kernel's LSM
dispatch and ordering, a static LSM denial can instead stop later hook
implementations from running at all. Mithril therefore cannot promise to emit
its own record for every SELinux/AppArmor denial.

The implementable stacking contract is:

1. BPF link order and every BPF LSM program digest are read back at activation.
2. If an earlier BPF LSM program passes nonzero `ret`, Mithril preserves that
   exact value and may emit only best-effort evidence; it never returns zero.
3. Static-LSM denials are consumed from that LSM's authoritative audit stream,
   normalized as `DENIED_BY_OTHER_LSM`, and never represented as a Mithril
   hook denial.
4. A profile that requires a Mithril-specific decision point is supported only
   when a controlled probe proves that Mithril's hook runs for that path under
   the target's complete LSM order. Otherwise the result is
   `UNSUPPORTED` or `DENIED_BY_OTHER_LSM`, not a fabricated Mithril decision.

**Practical examples.** BPF program A returns `-EPERM` from `file_open`; the
later Mithril BPF program receives nonzero `ret` and returns the same value.
That is the valid `prior_ret` example. Separately, SELinux denies a write to
`/etc/shadow` and its AVC record identifies the denial. If Mithril's BPF
program is not invoked, the syscall is still denied, but Mithril correlates
the AVC record and reports `enforcer=SELINUX`; it does not claim that its BPF
program observed or caused the denial. The qualification suite exercises both
orders and fails any build that turns either denial into allow.

`KA-CODE-001` and `TG-CODE-010` are the source-backed reason this is a
qualification requirement: checked-in early-miss/generic paths do not
establish preservation for every hook shape. Mithril generates typed
hook-specific prototypes with the final prior-BPF-return argument where the
kernel ABI supplies it, short-circuits nonzero, and runs the earlier-deny probe
on every advertised hook/kernel/LSM order.

#### What to learn from Tetragon

| Source mechanism | Useful lesson | Mithril adaptation | What Mithril must not inherit |
| --- | --- | --- | --- |
| [`bpf_fork.c`](../../../tetragon/bpf/process/bpf_fork.c) observes `wake_up_new_task`, inherits parent execution state, and tests fork-without-exec. The retained words “and tests” are superseded by `TG-CODE-020`: the program implements observation; [`fork_test.go`](../../../tetragon/pkg/sensors/exec/fork_test.go) owns the test. | Fork, clone, thread creation, exec, de-threading, and exit need separate state transitions | Allocate exact task and process identities before a child can perform a protected effect; test every Linux creation variant | Tetragon skips the child when no parent exists in `execve_map`; a protected unknown child must instead fail closed and open a coverage defect |
| [`process.h`](../../../tetragon/bpf/lib/process.h) stores `(pid, ktime)`, parent keys, an event/clone marker, namespace/capability state, and explicit miss/error flags | Native coordinates need time bounds and source quality flags | Retain host TID/TGID/start time and proven event markers as coordinates while using non-reused task/process cookies as durable identity | The snapshot does not capture the full syscall `CLONE_*` flag set, and TGID-keyed execution state is not enough for per-thread identity, non-leader exec, PID reuse, or response authority. The retained non-leader phrase means “not sole authorization state,” not “Tetragon misses the event”; `TG-CODE-002` and `TG-CODE-018` control that reading. |
| [`bpf_execve_event.c`](../../../tetragon/bpf/process/bpf_execve_event.c), [`bpf_execve_bprm_commit_creds.c`](../../../tetragon/bpf/process/bpf_execve_bprm_commit_creds.c), and [`process.h`](../../../tetragon/bpf/lib/process.h) stage exec collection across hooks and tail calls | Complex argument/object collection should be staged and verifier-bounded | Use a small pre-effect decision record and richer post-decision observation record | Rich event construction cannot be allowed to delay or determine the physical deny; `bpf_execve_map_update.c` only clears match-binary state and is not evidence for this lesson |
| [`policy_filter.h`](../../../tetragon/bpf/process/policy_filter.h) and [`policyfilter/state.go`](../../../tetragon/pkg/policyfilter/state.go) compile Kubernetes selection into policy-ID/cgroup maps | Filter and select in kernel using a node-resolved cgroup binding | Resolve exact Pod UID/container/image/profile in userspace, then install a generation-bound cgroup key | Labels, image tags, and a cgroup ID without its live interval are not durable identity |
| The [`OCI hook`](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go) transport exposes Pod/image-reference plus rootDir/mount context (`main.go:234-245,249-314`; `api/v1/tetragon/tetragon.proto:757-800`), while built-in [`rthooks.go`](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go) policy binding consumes cgroup/Pod/container/name/image-reference fields and does not consume RootDir/Mounts (`rthooks.go:30-110`) | Runtime metadata closes attribution gaps that the kernel cannot infer, but transport availability and policy consumption are different claims | Use authenticated runtime handoff, own rootfs/mount classification, separately resolve/verify immutable image digest, and re-resolve the live cgroup/task | An annotation-derived image reference, unconsumed mount payload, or create-container notification alone is not an image digest/mount proof and does not admit later `ExecSync`/streaming exec roots |
| [`cache.go`](../../../tetragon/pkg/process/cache.go) handles out-of-order events and garbage collection | The central graph must accept replay, duplicates, and late events | Immutable observations build versioned views; local WAL sequence exposes gaps | A userspace LRU record cannot authorize a syscall or irreversible response |
| [`fork_test.go`](../../../tetragon/pkg/sensors/exec/fork_test.go) exercises fork-without-exec | Kernel edge cases deserve real executable fixtures | Carry these cases into Phase 2 and the standing incident suite | A happy-path `fork -> exec -> exit` test is not sufficient identity proof |
| The OCI hook, node Unix gRPC server, protobuf, and [`args.go`](../../../tetragon/pkg/rthooks/args.go) transport runtime metadata locally | Runtime metadata is a valuable attribution/admission input, but socket access and field presence are not signed task intent | Add canonical signature, replay/expiry/one-use claim, held-task proof, and Pod/container/cgroup consistency checks | Independently supplied Pod/container fields and cgroup path cannot be concatenated into authority without proving their relation (`TG-CODE-023`) |
| [`process.h`](../../../tetragon/bpf/lib/process.h), [`base.go`](../../../tetragon/pkg/sensors/base/base.go), and [`kprobe_sigkill_test.go`](../../../tetragon/pkg/sensors/tracing/kprobe_sigkill_test.go) expose bounded exec state and preserve an action with an `unknown` process under map pressure | Capacity misses should be hostile tests, and selector-independent enforcement can remain valid | Preserve valid generic denies while preallocating non-evictable fail-closed Mithril role/task/domain state | `unknown` observation cannot grant an admitted role, but it is also wrong to claim every upstream miss disables enforcement (`TG-CODE-024`) |
| Generic LSM validates only five argument indexes and its output program has literal-zero miss paths | Hook signature and miss branch must be part of stacking qualification | Generate exact typed hook programs, preserve the chained BPF return at its real position, and keep physical result independent of output heap | A generic five-slot decoder or final Override support cannot qualify five-argument `path_rename` stacking (`TG-CODE-010`) |

##### Corrections: what Tetragon already does and where Mithril extends it

The retained `process.h` row must not imply that Tetragon simply misses
non-leader exec. `TG-CODE-002` shows explicit de-thread/non-leader observation
and tests. The implementable Mithril difference is authorization: every TID has
a task label, while shared process/domain state is read synchronously before an
effect; an evictable TGID-oriented userspace cache is not used as a pre-effect
role or kill handle.

Tetragon is also not observation-only. `TG-CODE-007` validates generic-LSM
Override/signal enforcement. The retained phrase “and a socket-connect
blocking example” incorrectly treated the checked-in kprobe policy as a
generic-LSM example and is abandoned by `TG-CODE-015`. Mithril does not claim
novelty for returning a denial. It adds transactional runtime intent,
task/domain roles, hook-specific physical oracles, coverage truth, and
target-revalidated multi-object/provider response.

`TG-CODE-019` also corrects the retained sentence that joined Generic LSM
Override with `bpf_enforcer` mechanics. Generic LSM action/override state and
the staged kprobe/fmod_ret enforcer are two code paths. Mithril may learn from
both, but an allow/deny/saturation result from one cannot qualify the other.
Every adopted hook records which path, map and physical oracle it actually
uses.

The retained source-table phrases “clone flags” and
“`bpf_execve_map_update.c` stages exec collection” are also abandoned.
`TG-CODE-014` identifies the actual cross-hook exec files. The pinned
`process.h` exposes event/miss flags and an `EVENT_COMMON_FLAG_CLONE` marker;
`bpf_fork.c` does not capture the syscall's full `CLONE_*` flags. Mithril must
collect or derive any clone-sharing facts it authorizes from its own qualified
creation path rather than attributing them to that structure.

The initial OCI hook is stronger than a post-start callback: it can run before
user exec and fail create. But `TG-CODE-004` shows the policy-filter path may
log and continue map-update failures before hook success. Mithril's strict
variant holds the task and treats any link/map/install/readback/probe failure as
admission failure. This is an upstream implementation choice that can be
extended, not a fundamental OCI limitation.

That retained summary is still too broad without `TG-CODE-021`: the pinned
hook sends from `createRuntime`, treats `createContainer` as a no-op, and its
CEL-backed `checkFail` can explicitly allow a container after request failure.
Mithril therefore adopts a pre-user-exec integration opportunity, not a claim
that the upstream default is a strict admission transaction. Separately,
`TG-CODE-022` limits the policy-map lesson to filling a fresh forward inner map
before outer publication; reverse membership changes are not one atomic
transaction.

Finally, `TG-CODE-005` corrects “local PID only”: Tetragon creates a
cluster-oriented exec ID using export-node name, kernel ktime, and PID. Mithril still needs
attested node boot/label epochs and typed remote authority edges. In the
node-A-token-use -> API request -> node-B-Pod-start test, cluster/node metadata
helps group events, but request UID, token/lease identity, Pod admission UID,
and runtime binding prove causality; timestamp/IP proximity remains contextual.

`TG-CODE-011` is handled as an audited concurrency hazard, not a public
vulnerability claim. `LSM-DENY-SATURATION-001` runs more simultaneous denied
operations than every staging/scratch map capacity, across CPUs, while forcing
insert and event-reservation failure. Mithril returns the physical LSM errno
directly from the deciding hook wherever possible. If a target-specific bridge
must stage an override, failed staging itself follows a qualified fail-closed
path; no missing side-map entry may convert the deny to allow.

##### Practical Tetragon lesson examples

###### 1. Label a child before fork-without-exec can perform an effect

**Example.** A Python conversion worker uses `multiprocessing` with `fork`.
The child does not call exec; its first action is to open the projected
service-account token. An exec-only process model never sees a new executable,
but the child is still a new task that needs inherited, restrictive authority
before it can run that `open(2)`.

**Mithril adoption.** Learn from Tetragon's early fork observation and parent
state inheritance. Allocate the child task identity and attach its inherited
role at a target-kernel-proven creation point before a protected effect can be
accepted.

**What not to inherit.** If the expected parent state is absent, do not skip
the child and continue. Attach `fail_closed_unknown` when possible, deny its
first protected effect, and open a coverage defect for the execution set.

**Why.** A missing parent can mean attach-after-start, event loss, unsupported
kernel behavior, or tampering. Treating every such child as invisible turns a
sensor gap into an attack path.

###### 2. Separate durable identity from PID and thread coordinates

**Example.** Thread TID 8102 in process TGID 8100 performs exec. Linux
de-threading can make the surviving task take different visible TID/TGID
coordinates. Later, an unrelated process may reuse PID 8102. An event or
response addressed only to `8102` can therefore attach to or kill the wrong
process.

**Mithril adoption.** Retain TID, TGID, start boottime, proven clone/event
markers, and parent keys as valuable coordinates and evidence, while assigning non-reused
`task_cookie`, `process_lineage_id`, and `execution_id` values for the node
boot and label epoch.

**What not to inherit.** Do not make a TGID-keyed map the sole owner of
per-thread role, non-leader exec state, or actuator authority.

**Why.** Linux exposes several identities whose relationships change across
clone and exec. Durable authorization needs a Mithril identity whose
continuity is explicit while native coordinates are revalidated at use time.

###### 3. Stage rich exec evidence without putting it on the deny path

**Example.** A worker attempts `/bin/sh -c 'curl ...'`. The pre-effect hook
needs only the exact task label, candidate executable object, interpreter
chain, and compiled edge to deny `/bin/sh` immediately. Full argv, cwd,
namespaces, hashes, and display strings are useful evidence, but collecting or
emitting them can fail or exceed verifier/tail-call budgets.

**Mithril adoption.** Use a small verifier-bounded pre-decision record and
stage richer post-decision observation across suitable hooks, as Tetragon
demonstrates for exec collection.

**What not to inherit.** Do not make successful tail calls, path rendering,
argument copying, or event reservation a prerequisite for the physical deny.

**Why.** Detailed telemetry improves investigation. It must not increase the
number of dependencies that an attacker can fail to obtain execution.

###### 4. Resolve Kubernetes selection to an exact live cgroup binding

**Example.** A policy selects Pods labeled `job=dataset-conversion`. Pod A
matches, exits, and is replaced by Pod B with the same name and labels. A
numeric cgroup identifier can also be reused after deletion. Pod B must receive
a new binding containing its exact Pod UID, full container ID, image digest,
cgroup live interval, and approved profile generation.

**Mithril adoption.** Learn from Tetragon's userspace selection and kernel
cgroup filtering, then install the resolved, exact binding in one atomic
generation.

**What not to inherit.** Do not let a label selector, image tag, Pod name, or
bare cgroup ID act as durable runtime authority.

**Why.** Selectors answer which current workloads should be considered.
They do not prove that a later task belongs to the same admitted workload or
policy lifetime.

###### 5. Runtime metadata admits an entry; it does not replace later entries

**Example.** An OCI hook supplies Pod UID, an annotation-derived image
reference, mounts, and cgroup for the initial container process. Mithril must
resolve and verify the immutable image digest separately. Ten minutes later kubelet starts an exec probe,
or an administrator uses `kubectl exec`. Those are new runtime-created roots;
the original create-container hook does not run again and cannot explain why
either new process exists.

**Mithril adoption.** Use an authenticated runtime handoff to create the
initial execution set and `ContainerStartEntry`, then use separate one-use
`RuntimeEntryIntent` admissions for each later runtime exec.

**What not to inherit.** Do not treat membership in the original cgroup or
knowledge of the container-create event as authority for every later root.

**Why.** The same container can legitimately host roots with very different
purposes and budgets: application, probe, lifecycle, and administrator.

###### 6. Let the central graph repair evidence, never retroactively authorize

**Example.** Node events are delivered out of order: a socket connect
observation reaches the graph before the exec observation that explains the
new execution image. The graph may later recompute its versioned causal view
and attach the evidence correctly. The connect's local allow/deny decision,
however, was already made from kernel-resident task state and cannot depend on
that later cache repair.

**Mithril adoption.** Accept replay, duplicates, late events, loss markers,
and versioned recomputation in the userspace graph, following the operational
lesson in Tetragon's cache.

**What not to inherit.** Do not use an evictable userspace cache entry as a
syscall authorization record or issue `kill(pid)` from a stale graph node.

**Why.** Distributed evidence is eventually ordered; kernel effects are not.
Irreversible response must re-resolve and prove the current target.

###### 7. Turn fork edge cases into permanent executable acceptance tests

**Example.** A fixture forks a child that never execs, synchronizes so the
child attempts a protected token read immediately, and asserts that the child
already carries the expected restrictive role and receives `EACCES`. Related
fixtures cover `CLONE_THREAD`, `vfork`, non-leader exec, rapid exit, and PID
reuse.

**Mithril adoption.** Carry the fork-without-exec testing lesson into Phase 2
and keep the hostile identity matrix in every release gate.

**What not to inherit.** Do not accept only `fork -> exec -> exit` tests or
tests that verify an event appeared after the protected effect completed.

**Why.** The security claim is about identity being installed before the
child can act. A plausible event stream after the fact does not prove that
ordering.

###### 8. Treat the runtime hook as metadata transport, not signed intent

**Example.** A request contains Pod A's supplied UID and container ID but Pod
B's cgroup path. The pinned Tetragon hook transports the fields over gRPC and,
when configured with the Unix listener, the node server creates that socket
with mode `0660`; its argument helper accepts the
explicit Pod/container values while resolving cgroup identity from the
separate path (`TG-CODE-023`). The code provides useful local plumbing; the
message itself has no signer, nonce, expiry, one-use task claim, or proof that
those fields describe one object.

**Mithril adoption.** Keep the low-latency local runtime boundary, then verify
peer credentials/socket ownership, validate a canonical signed intent, CAS a
one-use claim slot, resolve the cgroup from an opened live fd, fetch the Pod by
UID, prove full container ID and runtime task belong to it, and install/read
back authority before release.

**What not to inherit.** Do not concatenate individually plausible runtime
fields into an identity. Do not call Unix-file permissions replay protection
or a held-task binding.

**Why.** A trusted local producer may still be buggy, compromised, stale, or
send mismatched metadata. `SOURCE-TG-RUNTIME-JOIN-006` submits Pod-A/Pod-B
field mixtures, replay, expiry, wrong peer credentials, reused cgroup path,
and a valid exact request. Only the final request claims the held task once.

###### 9. Preserve enforcement on process-map miss, but do not invent a role

**Example.** Tetragon's default `execve_map` has 32,768 entries and insertion
can fail. Its own hostile test shrinks the map to one and still delivers the
configured signal action with the process marked `unknown` (`TG-CODE-024`).
That is an important positive upstream behavior; it would be false to say the
map miss universally disables Tetragon enforcement.

**Mithril adoption.** Reuse the saturation-test discipline and preserve any
effect rule whose selector is valid without process identity. For a Mithril
rule that requires an admitted role/task/domain, however, preallocate
non-evictable fail-closed state before wakeup; a missing role lookup denies
instead of interpreting `unknown` as converter, probe, or administrator.

**What not to inherit.** Do not equate an `unknown` observation record with an
authenticated role, and do not overstate the upstream miss as “all policy
allows.”

**Why.** Generic enforcement and exact role authorization are different
claims. `SOURCE-TG-EXEC-MAP-007` tests map sizes 1/N/N+1, fork-without-exec,
unknown enforcement, and a role-only allow. The pinned test proves that its
selector-independent `SIGKILL` action still applies when process state is
`unknown`; it does not prove an LSM errno denial. Mithril's separately
qualified deny must remain physical, and its role-only allow fails closed
until exact identity exists.

###### 10. Qualify stacked return position from the exact hook signature

**Example.** Tetragon Generic LSM accepts only argument indexes 0 through 4 and
rejects return-argument selectors. A five-argument hook such as `path_rename`
uses all five positions for semantic inputs, leaving the chained BPF-LSM return
outside the copied window; an output-heap miss can return literal zero
(`TG-CODE-010`). A generic “LSM supports Override” statement does not settle
that path's composition with an earlier denial.

**Mithril adoption.** Generate the exact typed prototype per selected hook,
place and preserve the prior return where that ABI supplies it, and make a
heap/scratch miss return the already fixed physical result. Compile-time and
load-time checks record the semantic argument count and return position.

**What not to inherit.** Do not use one generic five-slot decoder for
authorization on every LSM hook, and do not infer prior-return preservation
from the final override path alone.

**Why.** The difference is visible only on a concrete stacked call.
`SOURCE-TG-PATH-RENAME-008` attaches an earlier program returning `-EPERM`,
forces output-heap miss and nonmatch for five-argument `path_rename`, and
asserts the rename remains physically denied. Four-argument and ordinary allow
controls prove the fixture itself is not simply blocking all renames.

The intended synthesis is narrow: KubeArmor demonstrates useful BPF LSM
decision points and policy lowering; Tetragon demonstrates useful kernel
lineage, cgroup filtering, lifecycle metadata, miss flags, and test patterns.
Mithril replaces their container/path/PID authority with its own exact task,
entry, role, coverage, and response contracts.

#### Combined KubeArmor And Tetragon Lessons: One Mithril Pipeline

The mechanisms become useful together when they are arranged around one
Mithril-owned decision path rather than exposed as two independent policy
systems:

| Pipeline step | Mechanism learned from | Mithril's combined behavior | Concrete proof |
| --- | --- | --- | --- |
| Admit a workload root | Tetragon runtime metadata and cgroup binding | An authenticated runtime intent binds exact Pod, container, image, cgroup live interval, entry kind, role, and policy generation before execution | An unacknowledged initial root cannot execute under a strict profile |
| Preserve native lineage | Tetragon fork/exec state and miss flags | Kernel task state assigns a non-reused identity and restrictive role before each child can act; an exec transitions the existing lineage | A fork-without-exec child is denied the token read on its first operation |
| Decide the real effect | KubeArmor's semantic BPF LSM hook selection | File, exec, socket, and capability programs evaluate exact task role plus classified object before the effect | In-process Python `open(2)` is denied without needing a shell or exec event |
| Lower and update policy | KubeArmor's compact rule maps and map indirection | Rust compiles one reviewed immutable generation and atomically switches the exact workload binding | Concurrent decisions see all of generation 12 or all of 13, never a mixture |
| Preserve enforcement under telemetry failure | KubeArmor's useful deny-before-event ordering plus Tetragon's explicit miss evidence | Local denial survives ring/WAL/control-plane failure while loss counters narrow later claims | Filling the ring buffer loses evidence but never starts the forbidden command |
| Build explainable history | Tetragon's rich observations and out-of-order cache handling | Versioned local and multi-node graphs repair late evidence without becoming the syscall or response authority | A late exec event can repair causality but cannot retroactively justify an allowed connect |

##### Source-evidence-to-implementation traceability

| Mithril owner/algorithm | Source evidence used | Exact adoption or extension | Named fixture IDs and additional proof variants (explanatory) |
| --- | --- | --- | --- |
| Native task inheritance | `TG-CODE-001`, `TG-CODE-002`, `TG-CODE-006`, `TG-CODE-018`, `TG-CODE-020`, `TG-CODE-024`, `KA-CODE-005`, `KA-CODE-010`, `KA-CODE-023`, `KA-CODE-026` | Adopt early fork/de-thread placement, explicit unknown handling, and executable capacity fixtures; reject full-width-copy, evictable context, and one-event-per-thread-group as per-task authorization; add synchronous non-evictable fail-closed task/domain state before first effect and make a missing required link explicit | `ID-MOVED-PARENT-FORK-004`, `SOURCE-TG-EXEC-MAP-007`, fork-without-exec token open, per-thread/non-leader exec, width-mismatch, eviction and attach-failure probes |
| Runtime/container admission | `KA-CODE-004`, `KA-CODE-017`, `TG-CODE-004`, `TG-CODE-009`, `TG-CODE-021`, `TG-CODE-023` | Preserve the target-qualified pre-user OCI opportunity and local metadata plumbing; add signed/replay-safe intent, held exact task, Pod/container/cgroup cross-check, all-map readback, failure transaction, shutdown retention and distinct later exec tickets | `ENTRY-START-001`, `ENTRY-KUBELET-TICKET-001`, `SOURCE-TG-RUNTIME-JOIN-006`, mixed Pod/cgroup identity, injected map-update/conditional-fail failure and shutdown-window probes |
| File/exec/capability deny | `KA-CODE-001`, `KA-CODE-002`, `KA-CODE-003`, `KA-CODE-011`, `KA-CODE-016`, `KA-CODE-018`, `KA-CODE-020`, `KA-CODE-021`, `KA-CODE-022`, `KA-CODE-024`, `TG-CODE-007`, `TG-CODE-010`, `TG-CODE-011`, `TG-CODE-014`, `TG-CODE-019` | Adopt semantic LSM decisions and actual exec staging sources; distinguish open from already-open read-use; use resolved object identity rather than bounded path authority; fail required misses/attaches closed; qualify every program's prior-return and physical result before evidence | token-open/read-use and deep/long/bind-alias byte oracles, preset bypasses, stacked earlier-deny and attach-failure probes, concurrent ring/override saturation |
| Policy generation | `KA-CODE-007`, `KA-CODE-019`, `KA-CODE-027`, `TG-CODE-003`, `TG-CODE-016`, `TG-CODE-022` | Adopt compact maps/cgroup selection and only the fresh-forward-inner-map publish technique; independently preflight expanded cardinality, build immutable full generations, atomically switch the live binding, read back equality, and strictly reject capacity/binding conflicts | `SOURCE-KA-CAPACITY-005`, paused/faulted mixed-update and forward/reverse divergence tests, duplicate-container/different-cgroup conflict, and cgroup reuse test |
| Role-aware network | `KA-CODE-006`, `KA-CODE-012`, `KA-CODE-013`, `KA-CODE-015`, `KA-CODE-025`, `TG-CODE-007`, `TG-CODE-015`, `SOURCE-BOUNDARY-001` | Combine exact current task/socket role with destination/packet policy; do not confuse NFLOG enrichment or a kprobe YAML with the physical enforcement key; qualify short/long/malformed and multi-iovec DNS shapes, retain an IP/destination floor, and use provider audit for encrypted verbs | `SOURCE-KA-BOUNDS-004`, same-Pod two-role connect, DNS short/name-bound/msg_name/iovec/TCP/port/size/DoH/DoT exfil, same-TLS clone/push |
| Bootstrap/evidence graph | `KA-CODE-005`, `KA-CODE-010`, `KA-CODE-023`, `KA-CODE-028`, `TG-CODE-005`, `TG-CODE-008`, `TG-CODE-012` | Adopt reconciliation and one node owner while treating the fork value, daemon liveness and reader liveness as unqualified; add explicit per-source attach/readback capabilities, gap intervals, WAL order, attested boot identity, and typed remote edges | `SOURCE-KA-READER-LOSS-003`, restart/PID reuse, fork-width behavior, individual link/reader loss, ring loss, node-A API node-B start |
| Probe/admin exec identity | `KA-CODE-008`, `TG-CODE-009`, `TG-CODE-017` | Use TTY/init-tree only as context; require carried one-use kubelet/runtime ticket for exact purpose | identical non-TTY probe, admin exec, and native child race |

Every implementation card and acceptance result stores
`upstream_source_evidence_ids[]`. This field records design provenance only; it
does not import an upstream policy decision or waive Mithril's own capability
probe.

The final column deliberately mixes stable fixture IDs with human-readable
variant descriptions and is therefore not a machine registry. The normative
many-to-many edge is `SourceEvidenceClaimV1.downstream_fixture_ids[]`; every member
must resolve to an exact `FixtureCaseV1`/fixture-family entry in Part VII. A
Phase 0 linter rejects an evidence record whose claimed downstream ID is
absent, and rejects an acceptance case that cites an unknown `KA-CODE-*`,
`TG-CODE-*`, or `SOURCE-BOUNDARY-*` ID. This keeps the table readable while
making the checked artifact exact.

##### Combined example A: compromised conversion code acts without a new command

1. The runtime admits the container root as entry `E1`, assigns the
   `conversion-worker` role, and binds policy generation 42 to its exact cgroup
   live interval.
2. A malicious dataset template executes inside the existing Python process.
   There is no new Linux process event, so lineage monitoring alone has
   nothing new to report.
3. Python opens the projected service-account token. The file LSM hook reads
   Python's exact task label inherited from `E1`, classifies the credential
   object, and generation 42 returns deny before bytes are read.
4. Python forks a child without exec. The Tetragon-derived lineage mechanism
   attaches a restrictive child role before the child runs. Its immediate
   token open is denied by the same KubeArmor-derived semantic hook.
5. The child tries to exec `/bin/sh`. The exec LSM hook denies the role
   transition. If the evidence ring is full, the deny still stands and a loss
   counter records reduced observability.

The retained first sentence in step 4 is wrong if read as an upstream
capability. `TG-CODE-001`, `TG-CODE-018`, and `TG-CODE-020` show an early
Tetragon observation/process-lineage mechanism and its fixture, not Mithril
role installation. The correct mechanism is **Mithril's synchronous task and
process/domain state transition**, placed using the upstream hook/testing
lesson. Only the Mithril child-before-first-effect oracle can prove the role
was attached in time.

This is why an effect-only design and a lineage-only design are each
incomplete. Container-wide effect rules cannot distinguish the compromised
worker from a legitimate diagnostic root, while perfect lineage telemetry
without a semantic pre-effect enforcer only explains the intrusion after the
token or connection was already obtained.

##### Combined example B: a probe and an attacker run the same executable

Assume the PodSpec declares an exec readiness probe `/app/healthcheck`.

1. Before kubelet's probe reaches the runtime execution point, a one-use
   intent tied to the reviewed PodSpec digest admits its root as
   `KubeletExecProbeEntry` and assigns `kubelet-exec-probe`.
2. If the application forks and execs that exact same `/app/healthcheck`, the
   new execution remains a native descendant of `application-root`. Matching
   the filename does not let it claim probe authority.
3. If an attacker with `pods/exec` permission requests the same command, the
   streaming exec is admitted, if policy permits it at all, as
   `AdministrativeExecEntry`; it does not receive the probe role.
4. File and network LSM decisions can therefore give the real probe only its
   small health-check budget while denying the application descendant and the
   administrative root from reading credentials or opening unrelated
   connections.

Tetragon's runtime/cgroup and native-lineage lessons supply primitives for the
initial container and native descendants; the pinned runtime hook does **not**
establish probe versus administrative versus attacker intent for later roots.
Mithril's authenticated one-use later-entry ticket establishes which of those
executions this is. KubeArmor's LSM/policy-lowering lessons then help decide
whether that exact Mithril execution may perform an effect. Mithril needs all
three answers in the same task/state/generation path; two disconnected agents
or after-the-fact reconciliation would reintroduce races and disagreement.

#### Release-gating implementation cards

These cards demonstrate the required level of specificity. A later phase may
change a hook only by recording the replacement capability probe and physical
oracle; it may not replace the card with “monitor credential access” or
“detect an unusual process.”

##### Card `CARD-FILE-SA-TOKEN-OPEN-001`: in-process Python token read

```text
real_world_stimulus:
  host TID 31749 in the existing python3 conversion process calls
  openat2(AT_FDCWD,
          "/var/run/secrets/kubernetes.io/serviceaccount/token",
          O_RDONLY|O_CLOEXEC, ...)

starting_task_entry_role_and_authority:
  task_cookie = tc-9b7f
  process_lineage_id = pl-converter-17
  entry = ContainerStartEntry/pod-uid-8/container-id-a
  role = conversion-worker
  authority_domain = ad-converter-17
  profile_generation = 42

authoritative_inputs_and_ordered_reads:
  1. preserve nonzero prior BPF-LSM result
  2. task storage tc-9b7f -> process/domain IDs and placement expectation
  3. ProcessSecurityState and AuthorityDomainState at matching versions
  4. protected-root CGRP_STORAGE -> binding nonce bn-22 and retained gen 42
  5. effective response set
  6. resolved file->f_path -> FileObjectIdentityV1 classified
     PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN for pod-uid-8
  7. effect_tables[42][conversion-worker, FILE, OPEN_READ,
                       PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN,
                       current_state] -> DENY/EACCES

exact_decision_boundary:
  target-qualified BPF LSM file_open after VFS resolution and before fd return;
  file_permission/read-family coverage separately handles inherited or passed fd

physical_disposition_and_oracle:
  openat2 returns -1/EACCES; no fd is installed; a sentinel token byte cannot be
  read; the projected token file itself remains unchanged

evidence_emitted:
  FILE_EFFECT_DENIED with task/process/entry/role, file object and mount view,
  generation 42, rule ID, hook capability ID, prior-ret value, sequence and
  coverage epoch; ring failure increments loss but leaves EACCES unchanged

degraded_or_unsupported_result:
  a missing required task/state/binding/object/rule lookup is EACCES plus a
  typed health defect in protect mode; an unqualified hook/kernel cannot
  advertise this card as PASS

legitimate_negative_control:
  the same Python process opens /work/input/dataset.parquet and reads a fixed
  sentinel successfully under the exact DATASET_INPUT object rule

hostile_fixture:
  repeat in-process, after plain fork without exec, through symlink/bind-mount
  aliases, a pre-opened fd, SCM_RIGHTS, mmap, io_uring, and ring saturation
hostile_fixture_id: FILE-SA-TOKEN-OPEN-001

upstream_source_evidence_ids:
  [KA-CODE-001, KA-CODE-002, KA-CODE-003, KA-CODE-011, KA-CODE-016,
   KA-CODE-020, KA-CODE-021, KA-CODE-022, KA-CODE-024,
   KA-CODE-026, TG-CODE-001, TG-CODE-007,
   TG-CODE-010, TG-CODE-011, TG-CODE-018, TG-CODE-019, TG-CODE-024]
```

The retained card list formerly included `TG-CODE-015`. That provenance is
abandoned for this file card: `TG-CODE-015` proves only that one socket YAML is
a kprobe policy rather than Generic LSM, so it belongs to the role-aware
network lesson and cannot qualify file/open/read enforcement.

This card is intentionally not “detect `cat token`.” No shell or new exec is
required. The control follows the actual Python task to the resolved file
effect, which is the exact gap the combined source lessons identify.

##### Card `CARD-ENTRY-PROBE-IMPERSONATION-001`: identical health-check bytes

```text
real_world_stimulus:
  A. kubelet requests the declared exec readiness probe /app/healthcheck
  B. compromised application forks and execs the same immutable file/argv
  C. an operator requests kubectl exec -- /app/healthcheck

starting_task_entry_role_and_authority:
  A has a one-use KubeletExecProbe ticket bound to Pod UID, container ID,
    PodSpec digest, probe index, command digest and runtime operation
  B has native parent task_cookie tc-app and role application-root
  C has a one-use AdministrativeExec ticket and authenticated requester/audit ID

authoritative_inputs_and_ordered_reads:
  1. authenticated runtime stream/request plus node-boot and lifecycle generation
  2. exact held child pidfd/task coordinates and target cgroup binding nonce
  3. one-use claim slot CAS and `KernelClaimTombstoneV1` readback
  4. task label, ProcessSecurityState, retained policy generation and exact
     candidate ExecutableObject at bprm_check_security
  5. transition/entry table keyed by physical source identity, never filename alone

exact_decision_boundary:
  A and C are bound while the runtime-created task is held before user exec;
  B is classified synchronously as native inheritance plus exec transition

compiled_policy_key_and_result:
  A: (KUBELET_PROBE_ENTRY, reviewed_probe_3, healthcheck_object) ->
     role kubelet-exec-probe/ALLOW
  B: (application-root, EXEC, healthcheck_object) ->
     application-healthcheck-child or DENY, never kubelet-exec-probe
  C: (ADMINISTRATIVE_EXEC_ENTRY, requester/session) ->
     administrative-exec or REJECT according to approval policy

physical_or_provider_oracle:
  only A obtains the narrow probe role and can contact the declared loopback
  health port; B cannot read credentials or use unrelated egress; C receives
  its administrative result and never the probe budget. Three task/entry IDs
  remain distinct even though executable bytes and argv digest are identical.

degraded_or_unsupported_result:
  no carried exact ticket means AMBIGUOUS_EXTERNAL_ROOT or fail-closed admission;
  command/time/cgroup similarity cannot upgrade it

legitimate_negative_control:
  repeated legitimate probes consume separate signed slots and continue within
  the signed probe-frequency and deadline budget

hostile_fixture:
  race A/B/C with identical non-TTY argv, replay a consumed slot, delay the
  stream, restart kubelet/runtime/mithril-node, and move B across cgroups
hostile_fixture_id: ENTRY-PROBE-IMPERSONATION-003

upstream_source_evidence_ids:
  [KA-CODE-004, KA-CODE-005, KA-CODE-010, KA-CODE-008, TG-CODE-001,
   TG-CODE-004, TG-CODE-006, TG-CODE-009, TG-CODE-021, TG-CODE-023]
```

##### Card `CARD-XNODE-PRIVILEGED-POD-001`: token use creates a remote root

```text
real_world_stimulus:
  compromised conversion process on node A submits a Pod with hostPID,
  privileged=true and hostPath "/"; scheduler binds it to node B

starting_task_entry_role_and_authority:
  node-A process is pl-converter-17/conversion-worker; the ServiceAccount lease,
  if its exact jti/request binding is available, is lease-sa-4; node B has the
  signed NODE_FLOOR generation 7 installed before runtime admission opens

authoritative_inputs:
  node-A token-object and socket observations; Kubernetes API audit request UID,
  authenticated principal, object UID and authoritative result; scheduler and
  binding object UIDs; node-B CRI request, Pod UID, full container/image IDs and
  exact node-floor generation. Shared identity plus time is contextual unless
  lease/request proof joins the local process to the API request.

exact_decision_boundaries:
  node A may deny token open or undeclared API egress at LOCAL_PRE_EFFECT;
  Kubernetes semantic admission may REJECT the object at REMOTE_PRE_ADMISSION;
  regardless of both, node B rejects prohibited privileged/host-root fields at
  ENTRY_ADMISSION before mounts or the user image are created

graph_and_result:
  never create a Linux parent edge across nodes. Create typed process-to-lease,
  lease-to-request, request-to-object, object-to-binding and binding-to-runtime
  edges at their individual ProofQualityV1 values. If node B rejects, CRI
  returns the typed floor error, no host mount exists and no marker executes.

legitimate_negative_control:
  a separately signed, digest-pinned CSI DaemonSet exception admits only its
  declared image, ServiceAccount, host paths, devices, capabilities and expiry

degraded_or_unsupported_result:
  missing node-A request proof keeps source attribution contextual; missing
  node-B pre-mount admission makes privileged-root prevention UNSUPPORTED and
  cannot be rewritten as later detection

hostile_fixture_id: XNODE-PRIVILEGED-POD-001

upstream_source_evidence_ids:
  [KA-CODE-004, KA-CODE-005, KA-CODE-010, TG-CODE-003, TG-CODE-004,
   TG-CODE-005, TG-CODE-008, TG-CODE-009, TG-CODE-021, TG-CODE-023,
   SOURCE-BOUNDARY-001]
```

### Protection Invariants

These invariants apply across all phases once the owning capability is enabled:

| ID | Invariant |
| --- | --- |
| `INV-ENTRY-001` | Every task performing a protected effect has either a verified native-parent label or a verified external-entry admission. |
| `INV-ENTRY-002` | An unlabeled task in a protected cgroup is denied at its first protected hook unless it atomically claims a matching one-use entry intent. |
| `INV-ENTRY-003` | Reparenting, PID reuse, namespace reuse, cgroup reuse, runtime restart, or kubelet restart cannot change a task's birth lineage. |
| `INV-ROLE-001` | A role is assigned by an admitted entry or approved transition; executable path and process name alone never assign authority. |
| `INV-ROLE-002` | Fork without exec receives a restrictive inherited child role and remains enforceable. Exec without fork retains process identity and creates a new execution identity. |
| `INV-EFFECT-001` | The most specific deny wins. Missing protected identity, generation, object classification required by policy, or response state fails closed. |
| `INV-EFFECT-002` | Event construction, rate limiting, ring-buffer pressure, WAL pressure, or control-plane availability cannot change a computed local denial into allow. |
| `INV-POLICY-001` | Only a signed, validated, locally compiled generation can enter enforcement maps. Observation never self-authorizes. |
| `INV-POLICY-002` | A policy update is atomic for new decisions; old generations remain until no live task or socket refers to them. |
| `INV-K8S-001` | Container start, runtime exec, exec probe, lifecycle exec, interactive exec, init container, sidecar, and ephemeral container are distinct entry classes even when they use the same binary. |
| `INV-K8S-002` | `preStop` and shutdown tasks remain protected. Termination is not an implicit policy bypass. |
| `INV-GRAPH-001` | Native parent edges never cross a node. Remote expansion uses typed causal edges with named proof. |
| `INV-RESPONSE-001` | A response re-resolves the live kernel/provider target and verifies a physical postcondition; a stale graph identifier is never an actuator handle. |
| `INV-COVERAGE-001` | A missing hook, sequence gap, bootstrap edge, ambiguous entry, or unavailable provider feed narrows the claim instead of being interpreted as benign. |

#### Abandoned design: `INV-EFFECT-001` uses prose specificity

The retained first sentence of `INV-EFFECT-001`—“the most specific deny
wins”—is not executable and contradicts the compiler contract later in this
document. It is abandoned. The normative invariant with the same stable ID is:

```text
INV-EFFECT-001:
  immutable hard invariants and active response restrictions apply first;
  selectors are expanded into the generation's finite exact decision keys;
  identical decisions for one exact key may merge compatible evidence;
  different physical decisions require a signed explicit override/exception
  edge naming the exact key delta, approver, scope and expiry;
  otherwise profile compilation fails;
  after successful compilation, a missing protected identity, retained
  generation, required object classification, rule table or response state
  fails closed at the qualified decision point.
```

**Practical example.** One rule is role-exact/object-wildcard allow and another
is role-wildcard/token-exact deny. Neither is inherently “more specific.” The
compiler expands both onto `(conversion-worker, OPEN_READ, token-object)` and
fails unless the deny carries the signed override edge. It never silently
chooses whichever rule happened to look narrower or more restrictive.

#### Practical Protection-Invariant Examples

Each invariant is a release property, not an aspirational alert rule. These
examples state an action that a hostile acceptance fixture can perform and the
result an implementation must prove.

| Invariant | Practical example | Required result and why |
| --- | --- | --- |
| `INV-ENTRY-001` | The labeled conversion worker forks a child, while `kubectl exec` separately creates a root in the same container. | The forked child has a kernel-proven parent label before it runs. The administrative root has a one-use, audited external-entry admission. Neither is accepted merely because both are in the container cgroup. |
| `INV-ENTRY-002` | A host process uses `nsenter`, or a runtime task is moved directly into the protected cgroup, with no pending runtime intent. Its first action is to read the service-account token. | The file hook denies the read and records `unknown-external-entry`. Cgroup membership proves where the task is now, not why it was created or what authority it has. |
| `INV-ENTRY-003` | Container A exits; container B later receives the same PID, namespace number, or numeric cgroup ID. | Container B cannot resolve A's label, policy generation, or containment state because every lookup also verifies the live interval, full container identity, boot/label epoch, and non-reused task identity. |
| `INV-ROLE-001` | An approved update root and a compromised conversion worker both execute `/usr/bin/curl`. | The updater receives only the role admitted for its signed entry and transition. The worker remains a worker or receives a denied exec transition. Identical executable paths do not create identical authority. |
| `INV-ROLE-002` | Python forks a child that immediately reads a credential without exec; another thread later execs a new image. | The forked child already has the restrictive inherited child role. Exec retains the process lineage but creates a new execution identity and applies the reviewed role transition, including during non-leader de-threading. |
| `INV-EFFECT-001` | A permitted output path is changed into a symlink to the projected token, or the mount-aware object classifier cannot determine the target inode. | The credential read or unresolved classification is denied. A textual path match cannot override a more specific deny, and a required classifier miss cannot become allow. |
| `INV-EFFECT-002` | The attacker floods exec and file attempts until the ring buffer is full while the central service and local WAL are under pressure. | Every already-computed denial remains a denial. Mithril exposes loss and pressure counters, but telemetry backpressure never opens the protected effect. |
| `INV-POLICY-001` | Learning mode observes a compromised worker successfully calling the Kubernetes API with its mounted token. | The observation becomes a review candidate and evidence; it never writes an allow entry. Only a signed policy, validated and compiled by the Rust owner, can authorize that role/effect tuple. |
| `INV-POLICY-002` | Generation 42 allows an established approved socket while generation 43 denies new sockets to that destination. The update occurs while tasks and the old socket are live. | One atomic pointer activates generation 43 for new decisions. References that require generation 42 keep it resident until their explicit lifetime policy completes; no decision reads a half-loaded mixture or a freed map. |
| `INV-K8S-001` | The declared readiness probe, an application child, and `kubectl exec` each run the identical `/app/healthcheck` bytes. | They receive `kubelet-exec-probe`, application-descendant, and `administrative-exec` entry/role identities respectively. The executable object is evidence for command matching, not proof of Kubernetes intent. |
| `INV-K8S-002` | During termination, a malicious or compromised `PreStop` command tries to read a Secret and send it externally. | The policy remains installed and the narrow `kubelet-prestop` budget still applies until all tasks and relevant sockets are gone. “Terminating” never means unrestricted. |
| `INV-GRAPH-001` | A process on node A uses the Kubernetes API to create a Pod whose root later starts on node B. | Node A's task is not recorded as the Linux parent of node B's root. The graph adds a typed causal chain—API request, audit object, controller/scheduler decision, Pod UID, runtime admission—with the strength and gaps of each proof. |
| `INV-RESPONSE-001` | The graph says PID 7312 was malicious, but it exited and the kernel reused 7312 before containment arrives. | The actuator rejects the stale target after pidfd/start-time/cgroup/task-cookie re-resolution. It acts only on the current verified process, cgroup, credential, or provider object and then verifies the requested postcondition. |
| `INV-COVERAGE-001` | The node sensor missed sequence 900–915, attached after the worker started, or lost the provider audit feed that distinguishes a GitHub read from a write. | The affected task, interval, and claim are marked incomplete. Mithril may conservatively deny or contain according to policy, but it cannot report “no malicious action occurred” from absent evidence. |

##### Correction: the path example does not reintroduce prose specificity

The retained `INV-EFFECT-001` example says a textual path cannot override a
“more specific deny.” That phrase is abandoned here as well. The exact result
is: the symlink/bind alias resolves to one qualified file-object key; the
compiler expands all matching selectors onto that key; conflicting physical
results require the signed explicit override/exception edge or compilation
fails; and a required unresolved object fails closed. No runtime or compiler
step ranks path prose by apparent specificity.

For example, passing `INV-K8S-001` is not proven by an event that prints
`/app/healthcheck`. The test must create all three roots above, demonstrate
three different admitted identities, and show that each receives its own
file, network, exec, and response budget before it can perform those effects.

#### How an invariant becomes executable

Every invariant is compiled into an `InvariantQualification` record. A phase
cannot mark the invariant passed from prose or from an event screenshot:

```text
InvariantQualification {
  invariant_id: fixed enum
  capability_record_digest: Digest
  upstream_source_evidence_ids[]
  profile_generation: GenerationId
  protected_scope: ScopeId
  preconditions: [MachinePredicate]
  stimulus_fixture_id: FixtureId
  expected_decision_point: HookOrAdmissionId
  expected_physical_result: PhysicalOracle
  required_coverage: [CoverageRequirement]
  observed_result_artifacts: [ArtifactDigest]
  status: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
}
```

The four non-pass results are distinct:

- `FAIL` means the capability was advertised and the physical oracle did not
  match.
- `UNSUPPORTED` means the measured kernel/runtime lacks a required mechanism;
  the profile must not advertise the invariant on that target.
- `INSUFFICIENT_COVERAGE` means the mechanism may have worked, but required
  evidence was missing or unhealthy.
- `PASS` requires both the physical result and healthy required coverage.

**Example.** `INV-ENTRY-002` uses a fixture that moves an unlabeled task into
the exact protected cgroup and attempts a token open. The expected decision
point is `lsm/file_open`, the physical oracle is syscall return `-EACCES` and
zero bytes in the fixture result buffer, and the required coverage includes a
healthy task-label lookup and cgroup binding. An alert with no syscall result
is `INSUFFICIENT_COVERAGE`, not `PASS`.

“First protected hook” never means “the first instruction or syscall of any
kind.” A forked task may perform CPU-only computation before it reaches a
qualified protected hook. If a profile must prevent process creation or CPU
consumption itself, it needs a qualified `task_alloc` denial, seccomp clone
floor, cgroup `pids.max`, CPU controller, or runtime admission control. A file
hook cannot make that stronger claim.

<a id="part-iii-identity"></a>

## Part III — Execution Identity And Runtime Admission

### Identity And Execution Model

#### Why a container can have several roots

The container's configured entrypoint is created by the runtime and has no
native parent inside the workload. Later, kubelet or an administrator can ask
the runtime to execute another command in the same container. That new task
can be created by a host runtime/shim and placed into the container's cgroup
and namespaces; it need not be a descendant of container PID 1.

Therefore this graph is wrong:

```text
container PID 1
  -> every legitimate task in the container
```

The required graph is:

```text
ContainerExecutionSet
  +-- ContainerStartEntry -----------------> native tree A
  +-- KubeletPostStartEntry ---------------> native tree B
  +-- KubeletExecProbeEntry #1 ------------> native tree C
  +-- KubeletExecProbeEntry #2 ------------> native tree D
  +-- KubeletPreStopEntry -----------------> native tree E
  +-- AdministrativeExecEntry -------------> native tree F
  +-- other admitted runtime entries ------> native tree ...
```

The edge from an entry to its root process is `entry_started_execution`, not a
fabricated Linux parent edge. Ordinary fork/clone/exec edges below each root
remain native.

#### Does the attacker also go through kubelet exec?

Sometimes, but not necessarily. More importantly, **“created through kubelet”
is provenance, not trust**. Kubelet may be carrying out a legitimate probe, a
legitimate administrator request, an attacker-controlled `pods/exec` request,
or a maliciously changed PodSpec. Those executions must not receive the same
role merely because kubelet initiated the runtime call.

The earlier entry diagram must not be read as assuming a kubelet-created task
is safe. That assumption would be wrong. The correct rule is:

```text
runtime and kubelet provenance select a candidate entry class
+ authenticated intent and reviewed workload state prove its purpose
+ compiled policy assigns or denies its role
```

Four practical paths must be distinguished.

##### Path 1: compromise inside the existing worker does not use kubelet exec

In the published Hugging Face chain, the data-derived Jinja expression caused
Python execution inside the existing conversion worker. That action did not
need `kubectl exec`, kubelet `ExecSync`, or a new process. If the compromised
Python process reads a token or opens a socket itself, its existing
`conversion-worker` task label reaches the file or socket hook. If it forks or
execs a shell, native inheritance and exec-transition policy continue from
that same admitted root.

```text
admitted ContainerStartEntry
  -> existing Python worker
       -> in-process Jinja/Python payload      # no kubelet and no new task
       -> forked child                         # native child, not external root
       -> exec /bin/sh                         # native exec transition
```

The protection must therefore work even when no kubelet or exec audit event
exists. This is precisely why task roles plus semantic file/socket/capability
hooks are required.

##### Path 2: an attacker using `pods/exec` normally does go through kubelet

If an attacker has Kubernetes `pods/exec` authority, a normal `kubectl exec`
path goes through the API/streaming control path to kubelet, which asks the
container runtime to create an exec process. Mithril classifies that process as
`AdministrativeExecEntry`, correlates the Kubernetes audit principal and
request when available, and applies default-deny or an explicitly approved
break-glass role.

For example, an attacker cannot obtain probe authority by running the probe's
exact command:

```text
declared readiness probe -> /app/healthcheck -> kubelet-exec-probe role
kubectl exec by attacker  -> /app/healthcheck -> administrative-exec role
```

The binary, argv, cgroup, and namespaces can all match. The request transport,
authenticated intent, API audit principal, one-use nonce, and entry kind do
not. If the audit proof or admission is missing, the protected root is
ambiguous or unknown, not a probe.

##### Path 3: an attacker can make kubelet execute a malicious declared hook

An attacker able to change a controller's Pod template, submit a replacement
Pod, or influence the manifest before admission could change a readiness probe
or `PreStop` command to `/bin/sh -c ...`. Most fields of an already-running
Pod are not freely mutable; in the common controller case the change creates a
replacement Pod. Kubelet later issuing the command does not cleanse that
attacker-controlled intent. Mithril binds approved entry rules to the reviewed
Pod UID, resource version, PodSpec digest, command digest, lifecycle state,
and policy generation. The replacement Pod or changed reviewed specification
creates a new deployment/profile generation; it cannot reuse an entry rule
compiled for the previous digest.

The deployment-preserving default is to report and deny or hold the unmatched
hook according to the protected profile, not to rewrite the manifest and not
to learn the new command as legitimate. If an installation initially chooses
observation-only compatibility, Mithril must say that this entry is unapproved
and that prevention coverage is absent; it must not label the command trusted.

##### Path 4: node or runtime access can bypass kubelet

An attacker with node access can call the CRI/runtime directly, use a tool such
as `crictl exec`, or manipulate a shim. That root may never pass through the
Kubernetes API or kubelet request path. Mithril requires a separately
authenticated `HostAdministrativeExecEntry` with runtime peer evidence and
denies it by default for protected workloads. Merely appearing in the target
cgroup is insufficient and triggers `INV-ENTRY-002`.

If the attacker controls kernel/root authority strongly enough to unload or
replace BPF programs, rewrite protected maps, forge the runtime trust channel,
or subvert kubelet and the runtime together, the node enforcement trust
boundary is lost. Mithril must detect and report attachment/map/measurement
failure from an external trust anchor where available; it cannot claim that a
compromised kernel enforces policy against itself.

##### What stock CRI can and cannot tell Mithril

Streaming `Exec` and synchronous `ExecSync` are separate CRI operations, so
the transport can help distinguish an interactive or administrative exec from
the synchronous mechanism kubelet commonly uses for exec probes and exec
lifecycle handlers. That still does not fully solve intent classification.
Stock `ExecSyncRequest` carries the container ID, command, and timeout, but not
“readiness probe,” “liveness probe,” `PostStart`, or `PreStop` as an
authenticated reason.

Therefore:

- a streaming exec cannot claim a probe/lifecycle role merely because its
  command matches the PodSpec;
- an `ExecSync` command is matched against the exact reviewed PodSpec and
  current lifecycle state, never against command text alone;
- when probe and lifecycle declarations are indistinguishable at the runtime
  boundary, Mithril uses a conservative shared budget or denies the ambiguous
  entry; and
- exact distinct roles require an authenticated kubelet-side reason/nonce or
  another pre-exec proof. Observation after the process starts cannot
  retroactively authorize it.

This answers the apparent contradiction: yes, one attacker path can traverse
kubelet exec, but kubelet transport does not make an execution legitimate.
Mithril protects both attacker paths—the in-process/native-descendant path and
the external runtime-root path—using different identity proofs that converge
on the same role/effect enforcement model.

#### Durable identity objects

```text
ContainerExecutionSet {
  execution_set_id
  tenant_id
  cluster_uid
  node_boot_id
  pod_uid
  pod_resource_version
  sandbox_id
  full_container_id
  container_kind: init | sidecar | application | ephemeral
  image_digest
  cgroup_binding_id
  cgroup_live_interval
  profile_id
  active_profile_generation_ref_id
  lifecycle_generation
}

EntryInstance {
  entry_instance_id
  execution_set_id
  entry_nonce
  entry_kind
  request_transport
  request_provenance
  classification: exact | conservative | ambiguous | unknown
  pod_spec_digest
  command_digest
  candidate_binary_identity
  requested_at
  claim_deadline
  claimed_task_cookie?
  target_role_id
  state: pending | claimed | expired | denied | completed
}

TaskLabel {
  node_boot_id
  label_epoch
  task_cookie
  process_lineage_id
  process_instance_id
  entry_root_process_state_id
  entry_instance_id
  execution_set_id
  profile_generation
  role_id
  execution_id
  lineage_depth
  ancestor_process_lineage_ids[MAX_DEPTH]
  dynamic_state_bits
  response_state
}
```

##### Adjacent correction: dynamic and response authority is not task-local

The retained `TaskLabel.dynamic_state_bits`, `TaskLabel.response_state`, and
authoritative `role_id` fields are abandoned as mutable authorization state.
They appear here only because the original sketch must remain visible. A
sibling thread could otherwise keep stale broader authority after another
thread reads a secret, changes role, or receives containment.

The executable identity record stores immutable coordinates and references:

```text
EntryClassificationV1 =
  EXACT_TARGET
  | SAME_BUDGET_AMBIGUOUS
  | AMBIGUOUS
  | UNKNOWN

TaskLabelV1Abandoned {
  node_boot_id, label_epoch, task_cookie
  process_lineage_id, process_instance_id, entry_instance_id
  execution_set_id, profile_generation, execution_id
  lineage_depth, ancestor_process_lineage_ids[MAX_DEPTH]
  process_state_id
  authority_domain_id
  task_placement_expectation
  cached_decision_set_id?
  cached_transition_version?
}
```

###### Abandoned design: active authority lives in an immutable task label

The retained `TaskLabelV1Abandoned` still contains `profile_generation`,
`execution_id`, `authority_domain_id`, and mutable cache fields. That conflicts
with exec commit, explicit generation migration, cross-entry domain join, and
the promise that the label is immutable. It is abandoned as the authoritative
V1 layout. The canonical split is:

```text
TaskLabelV1 {                          // immutable after successful install
  node_boot_id
  label_epoch
  task_cookie
  process_lineage_id
  process_instance_id                  // opaque ID allocated while ALLOCATING
  process_state_id
  entry_instance_id
  execution_set_id
  birth_profile_generation_ref_id
  birth_execution_id
  birth_authority_domain_id
  lineage_depth
  ancestor_process_lineage_ids[MAX_DEPTH]
  task_placement_expectation
}

ProcessSecurityStateV1 {               // sole active process authority
  process_state_id
  node_boot_id
  label_epoch
  process_lock: bpf_spin_lock
  process_lineage_id
  process_instance_id
  entry_instance_id
  entry_root_process_state_id
  active_execution_id
  active_role_id
  active_profile_generation_ref_id
  authority_domain_id
  process_state_vector_id
  effective_response_set_ref_id
  exec_guard_state:
    NONE | EXEC_PREPARING | EXEC_COMMIT_PENDING | EXEC_OUTCOME_UNKNOWN
  pending_exec_id?
  pending_target_execution_id?
  pending_target_role_id?
  pending_exec_response_set_ref_id?
  transition_version
  live_thread_refs
  state: ALLOCATING | ACTIVE | EXITING | RECLAIMABLE |
         FAIL_CLOSED_OVERFLOW | CORRUPT
}

`process_lock` protects `active_execution_id`, `active_role_id`,
`active_profile_generation_ref_id`, `authority_domain_id`,
`process_state_vector_id`, `effective_response_set_ref_id`, every exec-guard/
pending field, `transition_version`, reference counters, and lifecycle state in
this one fixed-layout value. BPF resolves transition/set descriptors before
taking the lock, rechecks the complete expected tuple/version while held,
performs no helper or map lookup under the lock, writes the complete next
tuple, and increments the version before unlock. `STATE-THREAD-RACE-001`
includes role/state/exec transitions against effects on another CPU; the ABI
fixture also verifies C/Rust offsets, spin-lock placement and load/readback on
every advertised kernel.

ProcessStateVectorV1 {
  process_state_vector_id: u32         // nonzero; non-reused in label epoch
  node_boot_id: Id128
  label_epoch: u64
  state_bits: u64                      // closed Phase 0 bit registry
  profile_generation_ref_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

EntrySecurityStateV1 {                // entry_state_map[entry_instance_id]
  entry_instance_id: Id128
  node_boot_id: Id128
  label_epoch: u64
  entry_lock: bpf_spin_lock
  execution_set_id: Id128
  entry_kind: EntryKindV1
  claim_slot_id: Id128
  root_task_cookie: u64
  root_process_state_id: Id128
  committed_execution_id: Id128
  live_task_refs: u64
  admission_state: PREPARING | CLAIM_BOUND_PROVISIONAL | COMMITTED |
                   TERMINAL_FAILED
  lifetime_state: OPEN | DRAINING | COMPLETE
  transition_version: u64
}

TaskDecisionCacheDraftAbandoned {      // retained post-V1 idea; absent in V1
  task_cookie
  process_state_id
  observed_process_transition_version
  observed_authority_domain_id
  observed_domain_transition_version
  cached_decision_set_id
}
```

Role, active execution, active profile-generation reference and current authority domain
change only in `ProcessSecurityStateV1` through a target-qualified atomic
transition. A cross-entry join updates `process.authority_domain_id`; exec
updates `process.active_execution_id` and `active_role_id`; an explicit policy
migration would update `process.active_profile_generation_ref_id`, but live
migration is not a Version 1 capability. `TaskLabelV1`
never changes. A cache hit is valid only when both recorded versions exactly
match the current process and domain in the retained post-Version-1 sketch;
Version 1 has no cache hit and always reads the authoritative states.

The retained cache record is not instantiated in Version 1. The canonical
lookup always reads process, domain, object/socket and binding state; the
decision-ABI section defines the exact disabled-cache invariant. A future
cache proposal must receive a new capability and wire contract rather than
quietly implementing `TaskDecisionCacheDraftAbandoned`.

`pending_exec_response_set_ref_id` is absent exactly when
`exec_guard_state=NONE`. In every other guard state it references an active
immutable `RESPONSE` set whose rows are the source/target/loader intersection
for the exact exec attempt. The generic lookup always intersects it as the
`pending_exec_floor`; a missing, zero, non-retained/unusable, or wrong-attempt reference
denies. The abandoned phrase “pending target decision set” cannot select an
effect table or grant a prospective role.

`EntrySecurityStateV1.COMMITTED` is the every-effect entry authority. The
separate `KernelClaimTombstoneV1` proves winner selection, restart/replay, and
the provisional-to-exec transaction; it is cross-checked when committing the
entry but is not read on every later effect. Its retention deadline is at
least the later of replay-policy expiry and `lifetime_state=COMPLETE`, so a
long-lived lineage never loses its claim evidence merely because a nonce
window elapsed.

Every retained pseudocode occurrence lowers mechanically as follows:

| Retained field/read | Canonical V1 read |
| --- | --- |
| `label.role` or `label.role_id` | `process_state_map[label.process_state_id].active_role_id` |
| `label.execution_id` | `process.active_execution_id` |
| `label.profile_generation` | `process.active_profile_generation_ref_id`, then `profile_generation_refs[ref_id]` |
| `label.authority_domain_id` | `process.authority_domain_id` |
| `label.dynamic_state` | `process_state_vectors[process.process_state_vector_id].state_bits` for process-role state, intersected with domain sensitive/restriction state |
| mutable fields in `TaskLabel` | in-place atomic `ProcessSecurityStateV1` transition; no task decision cache exists in Version 1 |

The authoritative read order is always label → process state → current
authority domain → live binding/retained generation → response/object/
policy state. A direct label-to-domain lookup is forbidden. Missing, corrupt,
wrong-version, or non-active state denies the protected effect and records the
exact health result.

The retained lowercase `classification: exact | conservative | ambiguous |
unknown` field is superseded by `EntryClassificationV1`. `EXACT_TARGET`
requires the one-use live-task proof; `SAME_BUDGET_AMBIGUOUS` means all
remaining candidates compile to an identical or stricter budget but does not
identify which intent caused the task; `AMBIGUOUS` has unequal candidates and
cannot receive their allow union; `UNKNOWN` has no sufficient candidate set.

Every protected effect resolves `ProcessSecurityState` and
`AuthorityDomainState`; Version 1 does not use a decision cache. The later
process-shared section owns reclamation, atomic state transitions, fork
sharing, and response references. This adjacent note
prevents an implementer from treating the older sketch as a temporary simpler
ABI.

`task_cookie` and `process_lineage_id` are allocated by Mithril for the node
boot/label epoch. TID, TGID, namespace IDs, cgroup ID, start boottime, and pidfd
are live coordinates and revalidation material. They are not durable identity
alone.

##### Concrete identity field contract

The earlier object sketches are logical, not permission to choose convenient
types independently in Rust and C. Phase 0 must encode these meanings in the
versioned C/Rust ABI:

| Field family | Required representation and invariant |
| --- | --- |
| Mithril durable ID | 128-bit opaque value; equality only; never reused within its stated tenant/node-boot/label-epoch scope |
| Kernel coordinate | Unsigned 64-bit normalized value plus its namespace/boot/live-interval scope; never used alone as durable identity |
| Generation | Unsigned 64-bit nonzero value, monotonically allocated by its owner; zero means invalid/uninitialized |
| Counter/sequence | Unsigned 64-bit value with explicit source epoch; overflow creates a new epoch and a coverage break |
| Digest | Algorithm enum plus fixed-length bytes; no free-form digest string in kernel maps |
| Timestamp/deadline | Unsigned 64-bit monotonic boottime nanoseconds for node objects; signed UTC plus uncertainty for remote observations |
| Optional ID | Presence byte plus value in the wire schema; all-zero bytes do not mean absent |
| Enum | Fixed-width integer with `UNKNOWN=0`; decoders retain unknown numeric values and reject them at enforcement boundaries |

A profile generation has one portable signed identity and one node-local hot-
path handle; a bare generation integer is never enough to select policy:

```text
PortableProfileGenerationV1 {
  profile_id: Id128
  owner_generation: u64 > 0
  compiled_artifact_digest: DigestV1
}

ExactObjectKindV1 = REGULAR_FILE | DIRECTORY | PIPE | UNIX_SOCKET |
                    INET_SOCKET | MEMFD | SHARED_MEMORY | DEVICE |
                    KERNEL_SECURITY_OBJECT | OTHER_QUALIFIED

ExactObjectGenerationV1 {
  object_kind: ExactObjectKindV1
  authority_scope_id: Id128          // node boot or persistent-volume authority
  live_object_id: Id128              // never a raw pointer or PID
  object_generation: u64 > 0
  backing_identity_digest: DigestV1  // mount/fs/inode, socket, pipe, device, etc.
  opened_boottime_ns: u64
  tombstoned_boottime_ns?: u64
}
```

Signed deployment, restore, and control objects carry
`PortableProfileGenerationV1`. During node binding, Rust verifies that exact
artifact and allocates the non-reused node-local `ProfileGenerationRefV1`
handle defined in Part IV. Kernel maps carry only that handle. For example,
profile `hf-converter` generation `42` and profile `ci-runner` generation `42`
have different portable identities and necessarily different node-local
reference IDs; neither can select the other's tables.

`task_cookie` is allocated with an atomic per-node-epoch counter combined with
the random 64-bit `label_epoch`. Counter exhaustion, rollback, or loss of the
pinned epoch while labeled tasks remain is a fatal identity-health transition;
Mithril does not restart the counter at one and hope PIDs differ.

##### Identity state machines

###### Abandoned teaching shorthand: a direct `PENDING -> CLAIMED` entry transition

The first `EntryInstance` diagram below is retained as the original teaching
sketch, but its direct `PENDING -> CLAIMED` edge is not an implementation
state machine. It collapses the winner-selection CAS, provisional authority,
exec commit, and crash recovery into one word. The corrected transaction
immediately following the example is normative. The task and execution rows
remain lifecycle illustrations; they do not override the closed V1 records.

```text
EntryInstance
  PENDING -> CLAIMED -> RUNNING -> COMPLETED
      |         |          |          |
      |         |          |          +-> terminal
      |         |          +-> DENIED_BY_EFFECT (task existed; effect denied)
      |         +-> CLAIM_FAILED
      +-> REJECTED | EXPIRED | CANCELLED

TaskIdentity
  ALLOCATING -> LABELED -> RUNNABLE -> EXITED -> REAPED
       |           |
       +-> FAILED  +-> FAIL_CLOSED_UNKNOWN

ExecutionInstance
  ACTIVE -> EXEC_PREPARING -> ACTIVE_NEW_IMAGE
               |                  |
               +-> EXEC_FAILED ---+  (old image remains active)
```

Only an external runtime root consumes an `EntryInstance`. A native fork
creates `TaskIdentity` and, for a new process, a new process instance, but it
keeps the originating entry ID. Exec creates a new `ExecutionInstance`; it
does not create a new process lineage or entry.

**Example.** Python task `T1/P1/X1/E1` forks. The child is
`T2/P2/X1/E1`: new task and process, same active execution image provenance
and same entry. The child execs `/bin/sh`; if allowed it becomes
`T2/P2/X2/E1`. Calling that exec a new entry would lose the real native parent
edge and is forbidden.

##### Corrected entry lifetime and per-process execution identity

The earlier `EntryInstance.state` sketch and diagram combine admission,
lineage lifetime, and an effect denial. That is wrong if implemented as one
enum: a denied file open does not end the process, and a root exit does not
complete an entry while descendants still live. Version 1 separates them:

```text
EntryAdmissionState:
  PENDING -> CLAIMING -> COMMITTED
  PENDING|CLAIMING -> REJECTED | EXPIRED | CANCELLED | CLAIM_FAILED

EntryLineageLifetime:
  INACTIVE -> ACTIVE -> DRAINING -> COMPLETE

entry_live_refcount = every live task/process retaining entry_instance_id
COMPLETE requires entry_live_refcount == 0 after iterator reconciliation
```

`EntryAdmissionState` is a product-level projection, not the kernel claim-slot
state machine. Its `CLAIMING` includes the later exact
`CLAIMING -> CLAIM_BOUND_PROVISIONAL` transaction, and its `COMMITTED` is
reached only when that slot becomes `EXEC_COMMITTED`. It never means that the
first CAS alone admitted the user image. Claim failure before exec commit maps
to `CLAIM_FAILED`; the slot is terminal and cannot be reused. This correction
is controlled by `PreparedExternalRootStateV1` and the claim transaction in
the external-entry algorithm.

`DENIED_BY_EFFECT` is an immutable effect observation attached to the entry;
it is never an entry state transition. Repeated denials can occur while the
entry remains active.

##### Corrected entry reference accounting

The retained phrase “every live task/process” is double-countable and is
abandoned as an implementation rule. Version 1 counts **task references
only**—one reference for every live Linux task, including every thread, whose
`TaskLabel.entry_instance_id` equals the entry:

```text
TaskLifetimeOwnershipV1 {             // mutable BPF task storage beside label
  task_cookie: u64
  birth_transaction_id: Id128
  birth_transition_version: u64
  entry_instance_id: Id128
  process_state_id: Id128
  profile_generation_ref_id: u64
  authority_domain_id: Id128
  owns_entry_task_ref: bool
  owns_process_thread_ref: bool
  owns_profile_generation_task_ref: bool
  owns_authority_domain_task_ref_draft_abandoned: exactly false
  state: PREPARING | OWNED | RELEASED | RECONCILIATION_REQUIRED
}

ProcessLifetimeOwnershipV1 {          // one owner per process instance
  process_state_id: Id128
  authority_domain_id: Id128
  authority_domain_ref_owned: bool
  acquisition_transition_version: u64
  release_transition_version?: u64
  state: OWNED | DOMAIN_JOIN_PREPARING | RELEASED |
         RECONCILIATION_REQUIRED
}

TaskReferenceTombstoneV1 {            // pinned map[task_cookie]
  task_cookie: u64
  birth_transaction_id: Id128
  birth_transition_version: u64
  entry_instance_id: Id128
  process_state_id: Id128
  profile_generation_ref_id: u64
  authority_domain_id_at_birth: Id128
  acquired_bits: u64
  released_bits: u64
  task_free_observed: bool
  wal_acknowledged: bool
  transition_version: u64
  state: PREPARING | OWNED | RELEASED | RECLAIMABLE
}

on successful task-label installation at task birth:
    install ownership PREPARING with all owned bits false
    insert matching pinned tombstone with BPF_NOEXIST and read it back
    acquire each typed counter/ref, then set its owned bit true
    mirror each acquired bit into the tombstone
    read back label + ownership + tombstone + counters; CAS both to OWNED
    only then allow the new task to become runnable

on task_free for ownership state OWNED:
    CAS each tombstone bit to released, then each task-storage bit false,
    and decrement its exact counter once
    after every bit is false, CAS OWNED -> RELEASED
    duplicate cleanup observes false/RELEASED and never decrements

COMPLETE iff:
    entry admission is COMMITTED
    entry_state_map[entry_instance_id].live_task_refs == 0
    a BPF task iterator finds no live label for the entry
```

The former final predicate—“no retained socket/object lifetime contract still
keeps the entry open”—is abandoned for Version 1 because it named no counter
or owner. A passed socket/file/shared object carries self-contained immutable
acquisition provenance, its own generation/SetRef ownership, and the source
entry ID for evidence. It can outlive the source entry without keeping
`EntrySecurityStateV1` authoritative. Every later use is decided from the
current actor plus that object provenance. Entry state may therefore become
`COMPLETE` after the task predicate above; object retirement is independent.

`TaskLabelV1` itself remains immutable. The phrase “mark that label reference
released” in the retained draft is replaced by
`TaskLifetimeOwnershipV1`. Reconciliation joins the complete BPF task iterator
to pinned tombstones: a live label without `OWNED`, a dead task with owned
bits, or a counter mismatch holds the entry fail-closed and records
`TASK_REFERENCE_RECONCILIATION_REQUIRED`.

The task-storage draft originally gave every thread an
`owns_authority_domain_task_ref`. That is abandoned because the domain counts
live **processes**, not threads: it double-counts `CLONE_THREAD`, while
releasing on leader exit is too early. `ProcessLifetimeOwnershipV1` acquires
one domain ref at process creation, transfers it atomically during a domain
join, and releases it only when `ProcessSecurityStateV1.live_thread_refs`
reaches zero. Leader-exits-first and multithreaded-domain-join fixtures verify
both cases. The pinned tombstone remains until all bits are released, WAL is
acknowledged, and grace passes; loss/capacity at birth denies, while an exit-
path update failure leaks fail-closed for reconciliation rather than guessing.

The process leader exiting does not close the entry while sibling threads or
descendants remain. A non-thread fork adds one task reference; `CLONE_THREAD`
also adds one; exec changes execution identity but not the entry reference.
`task_free` may execute in non-sleepable/interrupt context, so its BPF cleanup
does only bounded lookups, an idempotent atomic decrement/tombstone, and a
best-effort fixed-size record. Rust performs rich graph/WAL cleanup later.

**Reference tests.** Create three threads, let the leader exit first, fork a
child, exec one survivor, and exit tasks in every order. The counter reaches
zero exactly once only after the final task. A failed fork and a normal exit
each exercise the `task_free` cleanup path; map exhaustion and duplicate
cleanup cannot underflow or prematurely complete the entry. A task iterator
must repair a deliberately lost userspace exit record without inventing an
extra kernel reference.

The compact `T2/P2/X1/E1` fork example is also ambiguous if `X1` is a mutable
execution instance: closing it in one process would close the sibling's view.
Version 1 separates immutable image provenance from per-process execution:

```text
ImageProvenance {
  image_provenance_id
  executable_object
  script_or_binfmt_chain[]
  elf_loader_objects[]
  source_exec_event_id
}

ProcessExecutionInstance {
  process_execution_instance_id
  process_lineage_id
  image_provenance_id
  started_by: PROCESS_BIRTH | EXEC_COMMIT
  start_boottime_ns
  end_boottime_ns?
}
```

Correct example: parent `T1/P1/X1/I1/E1` forks a process, creating
`T2/P2/X2/I1/E1`: new task, process, and per-process execution instance; same
immutable image provenance and originating entry. That child execs a shell and
becomes `T2/P2/X3/I2/E1`. A thread clone shares P1/X1/I1.

`process_lineage_id` is the durable graph identity created at non-thread
process birth and surviving exec/reparent/coordinate changes.
`process_instance_id` is the exact live kernel process interval with birth,
TGID/PID-namespace coordinates, pidfd/start-time proof, and death. Version 1
normally creates both together, but they are not interchangeable: graph edges
use lineage ID; live actuation re-resolves process instance ID.

**Lifetime test.** Root R forks child C and exits. Entry lifetime remains
`ACTIVE` with refcount one; C's token denial is an observation and does not
complete the entry. Only C's exit plus iterator reconciliation moves the entry
through `DRAINING -> COMPLETE`.

#### Native inheritance algorithm

The authority parent is the task that invoked task creation, not whatever
Linux later exposes as the wait/signal parent. Mithril records two different
relations:

```text
CreatedByEdgeV1 {                      // immutable authority/causal edge
  child_task_cookie
  creator_task_cookie
  child_process_lineage_id
  creator_process_lineage_id
  clone_attempt_id
  clone_flags_digest
  task_alloc_hook_id
}

KernelRealParentIntervalV1 {           // mutable topology/evidence only
  child_task_cookie
  real_parent_task_cookie_or_coordinates
  interval_start_boottime_ns
  interval_end_boottime_ns?
  change_reason: BIRTH | CLONE_PARENT | PARENT_EXIT | SUBREAPER |
                 NAMESPACE_INIT_REPARENT | PTRACE_REPARENT | UNKNOWN
  proof_quality
}
```

`CREATED_BY` supplies inheritance and never changes. `CLONE_PARENT` may make
the child's kernel `real_parent` the creator's parent; double-fork,
daemonization, subreaper adoption and namespace-init reparenting may change it
again. Those changes close/open `KERNEL_REAL_PARENT` intervals but never
replace authority lineage or entry/domain refs. `ID-CREATOR-PARENT-007` covers
`CLONE_PARENT`, double-fork, subreaper, creator exit and PID reuse; every child
keeps the creator-derived restriction even when `/proc/<pid>/status` reports a
different PPid.

At the earliest target-kernel-proven task allocation hook:

```text
on_task_create(parent, child, clone_flags):
    parent_label = task_storage[parent]

    if parent is outside every protected binding:
        do not invent a protected label
        return

    if parent_label is missing:
        mark protected binding identity_incomplete
        install fail_closed_unknown label on child if the hook permits
        return

    child.task_cookie = allocate_monotonic_cookie()
    child.entry_instance_id = parent.entry_instance_id
    child.execution_set_id = parent.execution_set_id
    child.profile_generation = parent.profile_generation

    if clone_flags contains CLONE_THREAD:
        child.process_lineage_id = parent.process_lineage_id
        child.process_instance_id = parent.process_instance_id
        child.role_id = parent.thread_child_role or parent.role_id
    else:
        child.process_lineage_id = allocate_monotonic_process_id()
        child.process_instance_id = derive_process_instance_id(...)
        child.ancestors = parent.ancestors + parent.process_lineage_id
        child.role_id = transition(parent.role_id, FORK_WITHOUT_EXEC)

    if ancestor bound would overflow:
        apply profile overflow action: deny creation or cgroup-scope response

    atomically attach label before child can perform a protected effect
```

##### Abandoned branch: assigning `parent.thread_child_role`

The retained `CLONE_THREAD` branch is not implementable policy and is
abandoned. Threads share the process address space and normally share files,
so giving the child a distinct role lets one thread acquire authority/data and
another use the broader sibling role. The normative branch is:

```text
if clone_flags contains CLONE_THREAD:
    child.process_lineage_id = parent.process_lineage_id
    child.process_instance_id = parent.process_instance_id
    child.process_state_id = parent.process_state_id
    child.authority_domain_id = parent.authority_domain_id
    increment the shared process/domain references atomically
    do not assign or cache a distinct thread role
else:
    create a new process identity and state reference
    keep the child in the parent's monotonic AuthorityDomainState in V1
    apply the single compiled FORK_WITHOUT_EXEC transition to process state
```

The `STATE-THREAD-RACE-001` and `STATE-FORK-IPC-002` fixtures in Part IV are
mandatory for this branch. A target that cannot attach these references before
the child's first protected effect cannot advertise synchronous native
identity for that creation variant.

###### Correction: a thread is not a new authority-domain process reference

The retained line “increment the shared process/domain references” is
double-counting. `AuthorityDomainStateV1.live_process_refs` counts process
instances, while `ProcessSecurityStateV1.live_thread_refs` counts Linux tasks
sharing that process. The exact transaction is:

```text
CLONE_THREAD success:
  increment entry_task_refcount
  increment existing ProcessSecurityStateV1.live_thread_refs
  install child TaskLabelV1 referencing that process_state_id
  do not increment AuthorityDomainStateV1.live_process_refs

new-process fork success:
  increment entry_task_refcount
  create ALLOCATING ProcessSecurityStateV1 with live_thread_refs = 1
  increment AuthorityDomainStateV1.live_process_refs exactly once
  install child TaskLabelV1 referencing the new process state

task_free:
  decrement entry_task_refcount once for this task
  decrement process.live_thread_refs once
  when and only when the final thread closes the process instance,
    decrement domain.live_process_refs once
```

All increments have rollback-owned bits in the preallocated child state; a
failed clone or duplicate `task_free` cannot decrement twice. The thread race
fixture asserts entry refs increase by N tasks, process refs remain one, and
domain process refs remain one until the final thread exits.

The observation hook then emits the exact parent/child coordinates. If event
delivery fails, the label still exists. If the selected kernel cannot prove
pre-run inheritance, that kernel tier is observation-only until an equivalent
fallback passes the hostile identity matrix.

##### Abandoned design: classify the parent by current cgroup before its label

The retained pseudocode's `if parent is outside every protected binding`
before acting on `parent_label` recreates the move-to-host escape. A labeled
worker moved to a host cgroup could fork an unlabeled child there. That order is
abandoned. The normative creation algorithm is:

```text
parent_label = task_storage[parent]

if parent_label exists:
    parent_state = process_security_state[parent_label.process_state_id]
    expected = binding_by_execution_set[parent_label.execution_set_id]
    require expected live and generation retained
    if current parent placement mismatches expected:
        deny creation when task_alloc can return;
        otherwise install fail_closed_unknown child label
    else:
        inherit exact entry/execution-set/process-or-thread/domain state
    # Never classify this branch as host.
else:
    placement = resolve current protected root/ancestor completely
    if placement is protected:
        mark identity incomplete and deny or install fail_closed_unknown
    else if placement resolution is complete:
        apply explicit host task-creation policy
    else:
        apply coverage posture; do not infer host
```

`ID-MOVED-PARENT-FORK-004` moves a labeled worker to a host cgroup, then runs
ordinary fork, clone, thread clone, and vfork. Every child either fails birth
or carries the worker's fail-closed identity/domain before attempting file,
socket, and exec effects. None may reach the unlabeled host branch.

##### Concrete task-creation hook selection

The primary candidate is BPF LSM `task_alloc`, because it is synchronous,
receives the child task and clone flags, and can return an error. The capability
probe must prove that the target kernel allows Mithril's task-storage helper
use and that the label is readable from the child's first hostile effect.

If `task_alloc` cannot create/read the required storage on a target kernel,
Mithril may use a target-kernel-proven synchronous fentry/kprobe such as the
new-task wake path only when the fixture proves the program runs before the
child becomes runnable. A sched tracepoint that merely reports the child after
it ran is observation-only.

| Task-creation outcome | Required behavior |
| --- | --- |
| Parent labeled, map capacity available | Install child label; permit creation |
| Parent protected but missing label | Install `fail_closed_unknown`; deny creation if the qualified hook can return an error, otherwise deny the child's first protected effect |
| Ancestor/role depth limit exceeded | Deny at `task_alloc` when qualified; otherwise install overflow restriction and deny all protected effects while opening a coverage/availability finding |
| Task-storage allocation fails | Return the configured `task_alloc` errno when possible; never create an unlabeled child and call it protected |
| Parent outside protected scope | Do not create a protected label; host policy remains a separate profile |

This makes “deny creation or effect” precise. A target may claim creation
prevention only when its capability record proves a returning task-creation
hook. Otherwise the claim is first-protected-effect prevention.

`task_alloc` occurs before all later fork/clone setup is guaranteed to
succeed. Every allocated label/process-state/generation/response reference has
an `ALLOCATING` owner and is rolled back from a qualified `task_free`/failed
creation path if the child never becomes runnable. Rollback is idempotent and
cannot emit a parent/child graph edge that claims a running child.

**Rollback test.** Force task-storage allocation to succeed, then make later
`copy_files`, namespace/cgroup validation, or another fork stage fail. The
child never appears `RUNNABLE`; all generation, process-state, entry, and
response references return to their previous values, and repeated cleanup
does not underflow them.

###### Correction: `task_alloc` allocates identity but cannot finalize PID coordinates

The retained creation pseudocode calls
`derive_process_instance_id(...)` at `task_alloc`. That is wrong if it means
deriving identity from PID/TGID/start boottime or a pidfd: Linux reaches
`task_alloc` before `alloc_pid` and the final live coordinates are available.
The opaque `process_instance_id` may be allocated there, but its coordinate
record remains `ALLOCATING`:

```text
ProcessInstanceV1 {
  process_instance_id                 // opaque, non-reused; allocated early
  process_lineage_id
  process_state_id
  state: ALLOCATING | COORDINATES_FINALIZED | RUNNABLE |
         EXITED | FAILED | FAIL_CLOSED_UNKNOWN
  host_tgid?
  host_leader_tid?
  pid_namespace_inode_and_generation?
  namespace_pid_chain[]
  start_boottime_ns?
  pidfd_identity?                     // userspace revalidation after visibility
  coordinate_finalization_hook_id?
  owned_reference_bits
}
```

`ProcessInstanceV1` is not the per-thread record. Every Linux task also owns:

```text
TaskInstanceV1 {
  task_cookie
  process_instance_id
  process_state_id
  state: ALLOCATING | COORDINATES_FINALIZED | RUNNABLE |
         EXITED | FAILED | FAIL_CLOSED_UNKNOWN
  host_tid?
  pid_namespace_inode_and_generation?
  namespace_tid_chain[]
  task_start_boottime_ns?
  live_interval { finalized_boottime_ns?, exited_boottime_ns? }
  thread_pidfd_identity?                // only when PIDFD_THREAD is qualified
  coordinate_finalization_hook_id?
  owned_reference_bits
  coordinate_history_head_id
}

TaskCoordinateHistoryV1 {
  history_id
  task_cookie
  transition: BIRTH_FINALIZED | NONLEADER_EXEC_DETHREAD |
              LEADER_EXITED | PID_NAMESPACE_CHANGE_OBSERVED | EXIT
  prior_and_new_host_tid_tgid_coordinates
  process_instance_id
  source_hook_id
  boottime_ns
}
```

A `CLONE_THREAD` child gets its own task cookie/`TaskInstanceV1` and TID
coordinates but shares `ProcessInstanceV1` and `ProcessSecurityStateV1`. A
non-thread clone gets both new records. Non-leader exec/de-threading keeps the
surviving task cookie and process instance ID, appends coordinate-history
changes for the task and process leader view, and never rewrites durable IDs.
Thread pidfd is optional and cannot be assumed on a kernel that lacks the
qualified `PIDFD_THREAD` path; task-cookie/start/TID/live-interval revalidation
remains mandatory and such a target cannot advertise thread-pidfd actuation.

The two-stage transaction is:

1. At qualified returning `task_alloc`, allocate the opaque task/process IDs,
   preallocated security state and rollback bits; install an immutable
   `TaskLabelV1` whose process state is `ALLOCATING`. No PID/start/
   pidfd claim is made.
2. At a target-proven pre-wake point after PID assignment, such as a qualified
   fentry at the entry to `wake_up_new_task`, populate the already allocated
   coordinate slots and transition them once to `COORDINATES_FINALIZED`.
   This non-returning program performs no allocation and grants no authority.
3. The first runnable/effect path requires finalized coordinates when its
   claim needs them. A finalization miss leaves the immutable label pointing to
   `FAIL_CLOSED_UNKNOWN`; every protected effect denies until reconciliation.
4. After the task is visible, Rust may open a pidfd and append that revalidation
   handle. A pidfd is never fabricated inside BPF or required to authorize the
   child's first kernel effect.

Because the pre-wake point cannot return an error, failure there is
first-protected-effect prevention, not child-creation denial. A platform may
advertise creation denial only for failures already decidable at the returning
`task_alloc` hook. `ID-TASK-COORD-FINALIZE-006` pauses before/after PID
assignment, forces finalization-state/map failure, and proves: no PID-derived
field exists early; no child is reported `RUNNABLE` from an incomplete
record; and an incomplete child cannot read one sentinel byte or send one
packet. It also covers leader-exits-first, thread/TID reuse, unavailable
`PIDFD_THREAD`, and non-leader exec/de-threading coordinate changes.

The `task_free` rollback program is deliberately tiny because the kernel may
invoke the LSM task-free path in non-sleepable/interrupt context. It performs
only verifier-approved bounded task-storage/map lookups, an idempotent
compare-and-swap from `REFERENCE_OWNED` to `REFERENCE_RELEASED`, atomic
reference decrements, and a best-effort fixed record. It never allocates,
walks a graph, waits, or writes a WAL. A Rust reconciliation owner performs
those rich operations after consuming the tombstone/counters. Phase 0
load-verifies every helper in this program and runs failed-fork plus normal-exit
fixtures that prove cleanup occurs exactly once.

##### Abandoned fallback: wake-path labeling without cross-cgroup failure proof

A non-returning wake-path observer is not a protect-mode fallback merely
because it usually runs before ordinary child work. A protected parent can use
`clone3(CLONE_INTO_CGROUP)` to create the child directly in an unprotected
cgroup. If label allocation then fails, both a task-label lookup and current
protected-cgroup lookup can be absent, recreating host allow. That fallback is
abandoned unless the platform proves all of the following:

- every child of a protected parent receives its inherited/fail-closed label
  before it can run, independent of the child's destination cgroup;
- task-storage/map exhaustion produces an independently enforced deny or a
  readable fail-closed label;
- `CLONE_INTO_CGROUP` and later migration are denied by a separately qualified
  floor whenever that guarantee is unavailable; and
- the task-first decision order never sends a partially labeled child through
  host policy.

#### Exec transition algorithm

At `bprm_check_security`:

```text
on_exec(current_task, candidate_file, argv):
    preserve any earlier LSM denial
    binding = resolve_live_protected_cgroup(current_task)
    label = task_storage[current_task]

    if binding is protected and label is missing:
        label = claim_external_entry_or_deny(binding, candidate_file, argv)

    process = authoritative_process_state(label.process_state_id)
    source_role = process.active_role_id
    binary_key = classify_executable_object(candidate_file, binding.mount_view)
    interpreter_chain = classify_script_or_interpreter(candidate_file)
    edge = lookup_exec_edge(profile_generation, source_role,
                            binary_key, interpreter_chain)

    if response policy, hard invariant, or edge says deny:
        return -EACCES

    stage PendingExecCommit(task_cookie, edge.result_role,
                            binary_key, policy_generation)
    return prior_ret
```

##### Abandoned design: cgroup-first exec lookup

The retained exec pseudocode resolves current cgroup before task storage and
later assumes `binding.mount_view` exists. That is wrong for a labeled worker
moved to a host cgroup and is abandoned. Exec uses the same task-first invariant
as every effect:

```text
label = task_storage[current]
if label exists:
    state = authoritative ProcessSecurityState(label.process_state_id)
    binding = binding_by_execution_set[label.execution_set_id]
    validate live binding, expected nonce, retained generation, and placement
    if placement mismatches: deny exec
else:
    placement = resolve current protected root/ancestor
    if protected: atomically claim exact external entry or deny
    if completely outside: apply explicit host exec policy
    if resolution unknown: apply fail-closed/unsupported coverage posture

classify candidate in binding's exact live mount view only after binding exists
```

`ID-MOVED-TASK-EXEC-005` moves a labeled worker to a host cgroup and calls
`execve`/`execveat` for an otherwise host-allowed binary. The exec must be
denied as placement mismatch; no null/default mount view and no host rule may
be used.

At the post-exec observation point, Mithril verifies that the staged candidate
became the execution image, closes the prior `ExecutionInstance`, assigns the
resulting role, and emits the new instance. A failed or mismatched commit is a
coverage defect and leaves the task in a restrictive fail-closed role.

Non-leader thread exec and Linux de-threading must retain the task cookie and
process-lineage ID while updating native TID/TGID coordinates.

##### Abandoned design: userspace or asynchronous post-exec role assignment

If “post-exec observation point” means that Rust receives an event and then
writes the result role, the design is wrong. The new image could execute user
instructions and protected effects before Rust runs. That interpretation is
abandoned.

The corrected design commits the role in a synchronous kernel program before
return to user mode. Rich event emission and Rust graph updates happen later.
The target kernel may use a qualified exec-commit fentry/kprobe or the
`sched_process_exec` tracepoint only after Phase 0 proves its ordering. The
LSM documentation also warns that `bprm_check_security` can run multiple times
for one exec, so a script and its interpreter are one exec attempt, not two
independent role commits.

```text
on first bprm_check_security for exec attempt A:
    require current TaskLabel
    create PendingExec(A, source_role, source_execution_id)

on every bprm_check_security for the same linux_binprm/attempt:
    append and validate candidate executable/interpreter object
    compute target role and exact loader/interpreter allowances
    if any chain member is denied: return -EACCES and mark A denied
    set task.exec_state = EXEC_PREPARING(A), but keep active_role unchanged

while the kernel loads A:
    file/mmap hooks evaluate the explicit exec-loader allowance and the
    intersection of source and target restrictions; they never get a union

at synchronous successful exec-commit hook before user mode:
    require PendingExec(A) and final validated chain
    atomically replace active_role and execution_id in existing task storage
    clear PendingExec; preserve task_cookie/process_lineage_id

on exec syscall failure before commit:
    clear PendingExec(A)
    retain the old image, role, and execution_id

after commit:
    emit the rich execution observation best-effort
```

##### Abandoned design: every failed exec returns to the old image

The retained `on exec syscall failure before commit` branch is correct only
before Linux crosses exec's point of no return. It is wrong as a universal
failure rule and is abandoned in that form. `begin_new_exec()` commits state
from which a later binary-loader failure can no longer restore the old image;
the kernel terminates the task, commonly with a fatal signal. The
`bprm_committed_creds` LSM hook occurs around that commit boundary and is
therefore **not** proof that all executable/interpreter segments loaded
successfully.

The executable state machine is:

```text
EXEC_PREPARING(A)
  -> PRE_PONR_FAILURE
       clear PendingExec(A); old image/role/execution remains active
  -> POST_PONR_FATAL
       mark PendingExec(A)=EXEC_FATAL; never restore old image authority;
       task_free closes task/entry/generation references
  -> SUCCESS_COMMIT
       qualified sched_process_exec-equivalent point runs synchronously
       before user mode; atomically installs target role/execution and clears A
```

A target profile names both owners: a qualified synchronous successful-exec
hook (normally `sched_process_exec` or a target-proven equivalent) and a
qualified return/fexit boundary for `bprm_execve`/the exact exec implementation
that classifies negative results as pre- or post-point-of-no-return. If the
platform cannot distinguish them, it keeps the task in restrictive
`EXEC_OUTCOME_UNKNOWN` until exit/reconciliation and cannot claim exact exec
lifecycle coverage.

###### Correction: the successful-exec observer cannot deny or allocate state

The retained phrase “atomically replace ... at `sched_process_exec`” is
incomplete. That tracepoint/equivalent successful-exec observer cannot return
an errno; a failed map allocation there could otherwise let the new image run
with the old broader role. The corrected transaction preallocates all state and
narrows authority before the point of no return:

```text
at final validated bprm stage, before PONR:
  require existing ProcessSecurityStateV1 and preallocated PendingExecV1
  store target execution/role/decision-set IDs in existing process state
  set exec_guard_state = EXEC_COMMIT_PENDING
  effective decision while pending =
    source authority INTERSECT target authority INTERSECT exec-loader budget
  publish transition_version atomically before returning allow

at qualified successful-exec observer before return to user mode:
  perform only an in-place, non-allocating locked/CAS transition
  require pending attempt and candidate digest match
  on match:
    active_execution_id = pending_target_execution_id
    active_role_id = pending_target_role_id
    exec_guard_state = NONE
    clear pending IDs; increment transition_version
  on mismatch/CAS/state failure:
    set exec_guard_state = EXEC_OUTCOME_UNKNOWN using the preallocated value
    keep the restrictive pending decision set; emit health best-effort

on proven pre-PONR failure:
  restore source active fields and clear the pending guard in-place

on post-PONR fatal path:
  never restore source authority; retain restrictive guard until task_free
```

No commit hook inserts a map element, allocates task storage, calls Rust, or
returns a denial. If the target cannot prove the non-allocating transition
runs before user mode, the new image's **exec completion** is unsupported; the
preinstalled guard must still deny its first protected effect. Fixture
`EXEC-COMMIT-STATE-001` exhausts every unrelated map and corrupts/mismatches
the commit attempt after PONR. The new image must never observe the source
role's file/network authority, even when the commit event is lost.

###### Correction: every bprm pass is guarded and Version 1 serializes exec

“At final validated bprm stage” is not an addressable Linux hook. A script,
interpreter or `binfmt_misc` chain can invoke `bprm_check_security` more than
once, and sibling threads can start competing exec attempts. Version 1 uses:

```text
PendingExecV1 {                       // pending_exec_map[pending_exec_id]
  pending_exec_id: Id128
  task_cookie
  process_state_id
  exec_attempt_sequence
  syscall_entry_coordinate
  state: PREPARING | COMMIT_PENDING | PRE_PONR_FAILED |
         POST_PONR_FATAL | SUCCESS | OUTCOME_UNKNOWN
  ordered_candidate_object_digests[MAX_BPRM_CHAIN]
  source_execution_id
  source_role_id
  source_profile_generation_ref_id
  pending_exec_response_set_ref_id
  final_chain_digest?
}
```

At a qualified `bprm_execve` entry—or the first bprm check only when a target
proves equivalent creation/cleanup—the task increments its per-task attempt
sequence and CASes `ProcessSecurityStateV1.exec_guard_state` from `NONE` to
`EXEC_PREPARING`. The loser of a concurrent sibling exec receives a denial
before staging. Raw `linux_binprm *` may be an ephemeral same-attempt lookup
input but is never persisted, emitted or used after hook lifetime.

Every `bprm_check_security` pass requires the same task/attempt, appends one
bounded candidate, and atomically replaces the pending effective decision set
with an equal-or-stricter intersection of source, all candidates, prospective
target and exact loader budget. An unexpected chain length, different attempt,
map/state miss or non-monotonic result denies. The qualified exec return/fexit
path clears only proven pre-PONR failures. The success observer matches the
final staged chain and performs the in-place active-role/execution switch.

If the successful observer's match/update/CAS cannot complete, it may
best-effort mark `EXEC_OUTCOME_UNKNOWN`, but safety does not depend on that
write: the already installed `EXEC_COMMIT_PENDING` restriction remains
authoritative. Under `EXEC_PREPARING`, `EXEC_COMMIT_PENDING` or
`EXEC_OUTCOME_UNKNOWN`, every non-loader protected effect denies. The task-
creation hook also denies fork/clone/vfork/thread creation, so a broad source
role cannot leave a surviving child while narrowing itself. The loader budget
contains no `TASK_CREATE`, ordinary file, network, device, IPC or privilege
allow.

`EXEC-CONCURRENT-002` races two threads executing different target roles and
races exec against fork/vfork/thread clone. Exactly one attempt may stage; no
child is born while guarded; and forced success-observer state failure leaves
the winner unable to use either source or target non-loader authority. A
separate script/interpreter/`binfmt_misc` vector proves every chain pass belongs
to one attempt and stale attempt state cannot be reused.

`execveat(..., AT_EXECVE_CHECK)` is also a distinct check-only operation on
kernels that implement it. It validates execution permission/credentials but
does not install an image. It must not consume an entry intent, create a
`PendingExec`, or transition a role. Mithril optionally observes it at a
qualified syscall/fentry boundary; unknown `execveat` flags are denied under a
full exec profile or make that variant unsupported.

**Exec outcome tests.** Run a denied pre-PONR script/interpreter case and prove
the old process continues under its old role. Then use a malformed/deliberately
failing ELF load after `begin_new_exec`; prove no old-role restoration occurs,
the task exits, and `EXEC_FATAL` references close once. A successful dynamic
ELF commits once. An `AT_EXECVE_CHECK` fixture returns its check result without
an entry claim or execution transition. Repeating every case through
`execve`, `execveat`, a non-leader thread, shebang, and enabled `binfmt_misc`
prevents a success-only implementation from passing.

**Practical script example.** The worker calls
`execve("./tool.py", ...)`; the kernel checks the script and then
`/usr/bin/python3`. The edge must authorize both immutable objects and their
ordered interpreter relation. One pending attempt is committed to one new
execution ID before Python receives control. If the interpreter object is
replaced or the second check fails, the old worker role remains and no new
image is reported as active.

##### ELF loader is not another `bprm_check_security` interpreter pass

Repeated `bprm_check_security` passes cover scripts and binary-format handlers
such as shebang/binfmt cases. An ELF `PT_INTERP` dynamic loader is loaded as an
exec-loader file/mapping, not assumed to generate another bprm pass. The
pending exec records it through the exact loader `file_open`/`mmap_file`
allowance and immutable object key. Substituting the ELF interpreter is denied
even when the main executable object is approved.

The exec suite separately covers a shebang script, `binfmt_misc`, static ELF,
dynamic ELF with approved `PT_INTERP`, substituted/denied loader, and exec
failure. Only script/binfmt candidates appear in the bprm chain; loader objects
appear in the loader list.

### Kubernetes And Runtime-Created Entry Architecture

#### Current Kubernetes facts the classifier must respect

Current Kubernetes behavior creates several materially different cases:

- `PostStart` begins concurrently with the container entrypoint; it is not
  ordered strictly before or after the main process.
- An exec lifecycle handler runs inside the container's cgroups and
  namespaces. HTTP and sleep handlers run from kubelet; they do not create a
  new task in the container.
- Exec probes create commands inside the container. HTTP, TCP, and gRPC probes
  are node-originated network operations and create no probe command in the
  container.
- Lifecycle hooks are at-least-once and can be repeated after kubelet failure.
- `PreStop` finishes before the normal termination signal, but its time is
  charged to the termination grace period.
- Init, sidecar, application, and ephemeral containers are separate container
  roots even when they share Pod namespaces or volumes.

The stock CRI `ExecSyncRequest` carries `container_id`, `cmd`, and `timeout`.
It does **not** state whether kubelet is running startup/readiness/liveness,
`PostStart`, or `PreStop`. This is an information limitation in the interface,
not a KubeArmor/Tetragon limitation. Exact semantic classification requires an
authenticated kubelet-side reason or a conservative policy when declarations
are indistinguishable.

Primary references are the Kubernetes
[lifecycle-hook documentation](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/),
[probe documentation](https://kubernetes.io/docs/concepts/workloads/pods/probes/),
[`handlerRunner`](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/lifecycle/handlers.go),
[`prober`](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/prober/prober.go),
and the [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto).

#### Entry-class matrix

| Kubernetes/runtime situation | Native shape | Required entry treatment | Default role and decision |
| --- | --- | --- | --- |
| Initial application entrypoint | Runtime-created root in new container cgroup | Pre-start `ContainerStartEntry` bound to full container/image/Pod/profile generation | Exact `application-root`; deny start if strict admission cannot complete |
| Regular fork/thread from labeled workload | Native descendant | Kernel inheritance; no runtime admission | Profile transition or restrictive inherited role |
| Exec `PostStart` | Possible secondary root, concurrent with entrypoint | One-use `KubeletPostStartEntry`, matched against exact PodSpec generation | Narrow `kubelet-poststart`; no inheritance of all application authority |
| Exec `PreStop` | Possible secondary root during termination | One-use `KubeletPreStopEntry`; policy stays installed through exit | Narrow `kubelet-prestop`; no universal containment bypass |
| Exec startup/liveness/readiness probe | Repeated secondary roots | Bounded, repeatable `KubeletExecProbeEntry` matched to effective PodSpec command | `kubelet-exec-probe`; strict file/socket/exec budget |
| HTTP lifecycle handler | Kubelet-originated connection to Pod endpoint | No workload entry; retain node-flow and declared-hook context | Do not invent a workload process or parent edge |
| HTTP/TCP/gRPC probe | Kubelet-originated connection | No workload entry; optional inbound-probe observation | Do not treat application receiver thread as a probe-created root |
| Sleep lifecycle handler | Sleep in kubelet | No workload task or entry | No workload decision |
| `kubectl exec` / streaming exec | Runtime-created secondary root plus Kubernetes `pods/exec` audit | `AdministrativeExecEntry`, correlated to audit principal when possible | Default deny or explicit approval; limited break-glass role |
| `kubectl cp` | Usually a streaming exec that runs archive tooling | Same as administrative exec; never infer benignity from `tar` | Default deny or explicit scoped file-transfer role |
| Direct `crictl exec` or runtime API exec | Runtime-created secondary root without Kubernetes user audit | `HostAdministrativeExecEntry` with runtime peer evidence | Deny on protected workloads unless host break-glass policy allows |
| Checkpoint/restore or migration | Restores one or many tasks, mappings, fds, sockets, namespaces, and device state, possibly without user `bprm` | `CheckpointRestoreEntry`; default reject, or hold the entire restored set and reconcile every object before atomic resume | Restore-specific role/current policy; never inherit old-node labels or skip entry because no exec occurred |
| `kubectl attach` / CRI `Attach` | Authenticated streams attach to an existing process; normally no new workload task | Stream-authority object correlated to `pods/attach`/runtime evidence; retain existing task role | No invented entry/root; allow/reject/record the stream according to actor and target policy |
| `kubectl port-forward` / CRI `PortForward` | Kubelet/API streaming path forwards traffic to Pod network; normally no new workload process | Typed port-forward stream/flow authority and audit edge | No invented process lineage; restrict actor, Pod UID, ports, direction, bytes/time, and destination flow |
| Ephemeral container | Separate container creation, optionally targeting another PID namespace | Normal container-root admission with `container_kind=ephemeral` and API audit | Default deny for protected workloads or isolated diagnostic profile |
| Init container | Separate ordered container root | Its own execution set and image/profile | Init-specific role; never app-role inheritance |
| Native sidecar | Separate independently restarted container root | Its own execution set and image/profile | Sidecar-specific role; shared Pod network does not merge lineage |
| OCI runtime hook process | Infrastructure process, often outside workload cgroup | Infrastructure observation only | Never assign workload authority from shared namespaces alone |
| `nsenter` or task moved into protected cgroup | Unlabeled external task | No pending authenticated entry means deny first protected effect | `unknown-external-entry` finding; fail closed |
| Container restart in same Pod | New full container ID, cgroup live interval, root and lifecycle generation | New execution set and root admission | Never reuse the prior root label or response target implicitly |

#### Checkpoint creation, restore, attach, and port-forward

##### Checkpoint restore admission and atomic resume

Checkpoint restore bypasses a final-exec-only design: CRIU/OCI restore can
resume multiple tasks with executable mappings, open files/devices/sockets,
namespaces, and shared state without a normal user-image `bprm` transition.
Version 1 therefore defaults `CheckpointRestoreEntry` to reject. Full restore
support requires:

```text
CheckpointRestoreIntentDraftAbandoned {
  signed_source_and_checkpoint_digest
  source_node_boot/execution_set/profile_generation
  target_node_and_current_profile_generation
  expected_process_task_topology
  expected_mapping/file/socket/device/namespace manifests
  approval, deadline, one_use_nonce
}
```

The retained slash/plus-separated fields are prose, not a serializable
record. The exact admission object is:

```text
CheckpointRestoreIntentV1 {
  restore_intent_id: Id128
  signed_intent_proof_id: Id128
  claim_slot_id: Id128
  checkpoint_digest: DigestV1
  checkpoint_manifest_digest: DigestV1
  source_node_boot_id: Id128
  source_execution_set_id: Id128
  source_profile_generation: PortableProfileGenerationV1
  target_node_boot_id: Id128
  target_execution_set_id: Id128
  target_profile_generation: PortableProfileGenerationV1
  runtime_name_version_config_digest: DigestV1
  restore_engine_binary_and_config_digest: DigestV1
  task_topology_manifest_digest: DigestV1
  expected_process_count: u32
  expected_task_count: u32
  expected_mm_class_count: u32
  file_descriptor_manifest_digest: DigestV1
  socket_manifest_digest: DigestV1
  vma_manifest_digest: DigestV1
  device_manifest_digest: DigestV1
  namespace_manifest_digest: DigestV1
  authority_domain_manifest_digest: DigestV1
  approval_id: Id128
  issued_at_utc_ns: i64
  expires_at_utc_ns: i64
  target_boottime_deadline_ns: u64
  state: PENDING | SETUP_RUNNING | RESTORED_SET_HELD | RECONCILING |
         COMMITTING | COMMITTED | REJECTED | FAILED | EXPIRED
}
```

Every manifest is deterministic CBOR containing exact object identities,
counts and relationships; a digest without the matching bounded manifest is
`RESTORE_MANIFEST_MISSING`. Source labels are evidence only. Target roles,
profile generation and restrictions are compiled from current target policy.

###### Abandoned design: freeze the entire restore cgroup before CRIU can restore

The retained sentence “the runtime creates the entire restored cgroup frozen”
is not generally executable: CRIU/runtime coordinator and restorer tasks must
run to reconstruct the target. The corrected protocol separates setup
authority from restored-user release:

```text
measured restore coordinator/helper
  -> runs under narrow RESTORE_SETUP in a setup cgroup
  -> may create namespaces, pages, fds and target tasks only according to the
     exact engine/version manifest
  -> brings every target task to an authenticated final stopped/held barrier
     (`--leave-stopped` or a target-qualified runtime equivalent)

restored target set
  -> never receives RESTORE_SETUP authority
  -> is moved/bound into the exact final cgroup while every task remains held
  -> receives task/process/domain/generation/entry labels and object state
  -> is enumerated against every expected manifest and count
  -> reads back all labels/maps/refs plus held-state evidence
  -> commits one restore generation
  -> releases each target exactly once
```

“Atomic resume” means **no restored user task can execute before the global
commit**; it does not claim the scheduler runs all tasks simultaneously. The
setup helper has no public/control-plane egress, checkpoint-content export,
arbitrary exec, host-root/device or credential-read authority beyond the exact
restore budget. Any missing/extra task/object, early wake, engine mismatch,
helper escape or partial commit reaps/fences the target set and terminalizes
the slot. `ENTRY-RESTORE-001` must include helper-needs-to-run positive
control, early target wake, helper moved into final cgroup, `--leave-stopped`
absence, and failure after each label/object/ref write.

The restored targets are kernel children of setup/restorer helpers, so ordinary
native inheritance would incorrectly give them the helper's entry/process/
domain. Replacing that immutable label later is forbidden. The restore path
therefore stages one exact birth slot per manifest task before the engine
creates it:

```text
RestoreTargetBirthSlotV1 {
  restore_intent_id
  manifest_task_index
  one_use_slot_id
  measured_coordinator_process_lineage_id
  expected_creator_task_cookie
  expected_clone_flags_and_relation: PROCESS | THREAD_OF(index) | VFORK
  preallocated_task_cookie/process_instance_id/process_state_id
  restored_entry_instance_id
  restored_execution_set_id
  restore_target_preparing_domain_id
  birth_profile_generation
  expected_namespace_and_coordinate_constraints
  expected_restorer_step_budget_id
  immutable_slot_digest
  state: RESERVED | CLAIMING | TARGET_PREPARING | HELD_RECONCILED |
         COMMITTED | FAILED
}
```

At `task_alloc`, only a task labeled `RESTORE_SETUP` from the exact measured
coordinator may CAS the next manifest-indexed slot. The hook installs the
target's immutable `TaskLabelV1` and distinct
`RESTORE_TARGET_PREPARING` process/domain state **at birth**, instead of normal
helper inheritance. The target can execute only exact bounded restorer steps
and must reach the final held barrier; it never joins the helper authority
domain. An un-ticketed/reordered/extra helper child follows the helper's
restrictive native transition or is denied and cannot masquerade as a target.

While every target is held, Mithril installs final active execution/role/
profile fields in each `ProcessSecurityStateV1` sequentially, but their common
target domain remains `PREPARING`, so no partial promotion can act. After
complete task/object/ref/manifest readback, one domain activation plus the
authenticated release barrier makes the committed states usable. Failure
leaves the domain non-active and all targets held/reaped. The restore fixture
adds extra/reordered clone, helper-child impersonation, attempted task-label
replacement, missing thread slot and failure after each final-role write.

The runtime creates the entire restored cgroup frozen/held. Mithril labels every
task/thread/process/authority domain, reconciles every VMA, fd, socket,
derived-device capability and namespace under **current** policy, installs
generation/response state, reads the complete task/object set back, and then
atomically unfreezes. Missing/extra tasks, unknown restored objects, early
resume, changed checkpoint bytes, wrong node/generation, or unqualified CRIU
version rejects and reaps the restore.

###### Abandoned restatement: the complete restore cgroup is frozen while the helper runs

The retained paragraph immediately above repeats the earlier abandoned model.
It is preserved as historical wording but superseded by the measured
`RESTORE_SETUP` protocol: the coordinator/helper must run in its separate,
narrow setup cgroup, while only the restored **target tasks** and their final
target cgroup are held. Commit means no target user instruction executes before
global domain/profile/object activation and exact `BarrierEvidenceV1`
readback. The barrier may be authenticated stopped tasks, a private bootstrap
gate, or a qualified final-target cgroup freeze; it is not necessarily one
“atomic unfreeze” operation. Every fixture and implementation card must use
this corrected physical oracle.

##### Checkpoint creation as a memory-export effect

Checkpoint **creation** is a separate semantic effect. Kubernetes' kubelet
Checkpoint API/CRI operation can archive process memory that contains secrets
without the worker executing a file read. Protected workloads default-reject
`ContainerCheckpointRequest`. A forensic exception names exact actor/approval,
live container and response state, destination object, encryption key, byte and
retention limits, archive path, and postcondition. Runtime/CRIU archive writes
are infrastructure actions linked to the request; they are not fabricated as
worker-process file writes.

```text
CheckpointCreationRequestV1 {
  checkpoint_request_id: Id128
  authenticated_request_proof_id: Id128
  actor_principal_id: Id128
  approval_id: Id128
  target_node_boot_id: Id128
  target_execution_set_id: Id128
  full_container_id: bstr(32..128)
  cgroup_binding_id_and_nonce: (Id128, Id128)
  target_response_state_digest: DigestV1
  destination_store_id: Id128
  destination_object_key: bstr(1..1024)
  destination_precondition_revision?: bstr(1..512)
  encryption_key_public_id: bstr(1..512)
  maximum_archive_bytes: u64
  retention_deadline_utc_ns: i64
  include_memory/include_fds/include_sockets: bool
  request_digest: DigestV1
  issued_at_utc_ns: i64
  target_boottime_deadline_ns: u64
  state: PENDING | AUTHORIZED | CAPTURING | STORED | REJECTED |
         FAILED | QUARANTINED | EXPIRED
}
```

The `CheckpointAuthorityOwner` rejects before invoking the runtime unless the
typed request, current target and destination precondition match. `STORED`
requires the provider/store revision, exact encrypted archive digest and byte
count, encryption-key ID, retention policy readback and runtime result. A
runtime log that capture started is only `CAPTURING`; it cannot prove an
archive exists or that plaintext was not written elsewhere.

`ENTRY-RESTORE-001` restores a multi-process checkpoint with a secret marker in
memory, preopened token/device/socket, and executable mapping; it varies target
node/generation, omits one child, adds an fd, and resumes early. Only the exact
fully reconciled manifest may unfreeze. `CHECKPOINT-CREATE-001` holds a marker
only in memory and requests a checkpoint while normal and while contained;
unapproved creation yields no archive, while approved forensics produces the
exact encrypted destination and retention record. Path traversal/overwrite and
lost semantic audit are rejection/coverage failures.

##### Attach and port-forward stream authority

Attach and port-forward do not create workload roots. The streaming owner binds
actor, Kubernetes request UID, Pod/container UID, ports/TTY/direction, TTL, and
stream ID; it meters/fences the stream and records its relation to the existing
task/flow. `ENTRY-STREAM-001` runs `pods/attach` and `pods/portforward` beside
an identical `pods/exec`: only exec creates an entry. Removing audit/ticket
identity makes stream authorization contextual/default-reject, never a fake
child process.

The “streaming owner” is the node/control `StreamAuthorityOwner`, not an
unnamed connector. It owns this closed object and no process identity:

```text
StreamAuthorityV1 {
  stream_authority_id: Id128
  kind: ATTACH | PORT_FORWARD
  tenant_id/cluster_uid/node_boot_id/pod_uid: Id128
  full_container_id?: bstr(32..128)       // required for ATTACH
  target_process_lineage_id?: Id128       // exact only when runtime proves it
  kubernetes_request_uid?: bstr(1..128)
  authenticated_actor_principal: bstr(1..512)
  runtime_stream_ticket_id: Id128
  stream_transport_digest: DigestV1
  tty_stdin_stdout_stderr_bits: u8         // ATTACH only
  allowed_ports[]: u16                    // PORT_FORWARD only, 1..128
  direction: CLIENT_TO_TARGET | TARGET_TO_CLIENT | BIDIRECTIONAL
  maximum_bytes_each_direction: u64
  maximum_concurrent_channels: u32
  issued_boottime_ns/deadline_boottime_ns: u64
  required_audit_proof: ProofQualityPredicateV1
  state: PREPARED | AUTHENTICATED | ACTIVE | FENCED | COMPLETED |
         REJECTED | EXPIRED | DISCONNECTED | UNKNOWN_RESULT
}
```

`PREPARED -> AUTHENTICATED` consumes the one-use runtime ticket and actor
proof. `AUTHENTICATED -> ACTIVE` occurs only after the exact target/ports and
transport read back. The owner meters bytes/channels/time in both directions;
overflow or expiry closes/fences the stream according to signed policy. Attach
never grants a new role; port-forward never creates a process parent edge.
`ENTRY-STREAM-001` includes stolen URL, audit UID mismatch, wrong Pod/container,
extra port, reverse direction, byte/concurrency/TTL overflow, disconnect/replay,
and an identical `pods/exec` negative comparison.

#### Node-wide default admission floor for attacker-created workloads

Protecting only Pods selected before an incident leaves the Hugging Face
privileged-Pod step open: a stolen `system:masters` identity can create a new
Pod UID that has no Mithril profile, mount the host root, and become node root.
“No profile means host policy” is therefore abandoned on an enrolled protect
node.

Every `RunPodSandbox`, `CreateContainer`, container start, and runtime exec
request passes the single local admission owner before the runtime performs
the requested security-sensitive setup. It selects an explicit signed workload
profile from the authenticated CRI/Pod snapshot; if none matches, the signed
node policy chooses exactly one posture:

```text
UnmatchedWorkloadPosture =
  REJECT_UNMATCHED
  | BASELINE_HARD_FLOOR(NodeHardFloorProfileId)
  | OBSERVE_ONLY_WITH_START_GAP
```

The floor does not inspect an open-ended Pod object in BPF. The local
`WorkloadBindingOwner` receives the authenticated runtime request before
security-sensitive setup, canonicalizes it into this bounded record, and
applies a signed, closed table:

```text
NodeAdmissionRequestV1 {
  request_id: Id128
  node_boot_id: Id128
  authenticated_runtime_peer_id: Id128
  runtime_name_version_config_digest: DigestV1
  operation: RUN_POD_SANDBOX | CREATE_CONTAINER | START_CONTAINER |
             EXEC_SYNC | STREAMING_EXEC | RESTORE
  cluster_uid/pod_uid: Id128?
  namespace_uid/service_account_uid/controller_uid: Id128?
  full_container_id?: bstr(32..128)
  image_digest: DigestV1
  effective_oci_and_cri_request_digest: DigestV1
  requested_field_entries[]: NodeAdmissionFieldV1  // unique/sorted, <=512
  selected_profile_id?: Id128
  selected_profile_generation?: u64
  signed_exception_id?: Id128
  one_use_exception_slot_id?: Id128
  cgroup_binding_id_and_nonce?: (Id128, Id128)
  deadline_boottime_ns: u64
}

NodeAdmissionFieldV1 {
  field_key: NodeAdmissionFieldKeyV1
  canonical_value: bool | i64 | u64 | bstr(0..1024) | DigestV1 |
                   sorted array of those bounded primitives
  source_path_id: u32                 // closed CRI/OCI field-path registry
}

NodeHardFloorDecisionV1 {
  request_id
  matched_floor_generation
  matched_exact_field_keys[]
  result: ALLOW_MATCHED_PROFILE | ALLOW_BASELINE |
          ALLOW_SIGNED_EXCEPTION | REJECT_REQUEST | OBSERVE_START_GAP
  rejection_reason_code?
  normalized_request_digest
  required_runtime_postcondition
}
```

`NodeAdmissionFieldKeyV1` contains at least:

```text
PRIVILEGED, ALLOW_PRIVILEGE_ESCALATION,
HOST_PID, HOST_IPC, HOST_NETWORK,
ADDED_CAPABILITY, DROPPED_CAPABILITY,
SECCOMP_PROFILE_KIND_AND_DIGEST,
APPARMOR_PROFILE_KIND_AND_DIGEST,
SELINUX_OPTIONS,
HOST_PATH_SOURCE_AND_FLAGS, HOST_DEVICE_SOURCE_AND_PERMISSIONS,
PROC_MOUNT_MASKS, PROC_MOUNT_TYPE,
RUNTIME_CLASS, USER_NAMESPACE_MODE,
PID_IPC_NETWORK_NAMESPACE_TARGET,
SYSCTL_NAME_AND_VALUE, MOUNT_PROPAGATION,
ROOTFS_READ_ONLY, RUN_AS_UID_GID_GROUPS,
NO_NEW_PRIVILEGES, MASKED_PATH, READONLY_PATH
```

Each repeating field produces one canonical entry; for example, every
hostPath includes source, destination, recursive/read-only/propagation flags
and mount-object intent, while every added capability is a separate numeric
capability ID. Unknown runtime fields or values are not silently omitted: a
profile that requires full floor coverage rejects them as
`NODE_FLOOR_FIELD_UNKNOWN`.

The physical boundary is the held runtime request. `REJECT_REQUEST` must be
returned before sandbox namespace creation, host-path/device mount, requested
credential/capability installation, or user task creation. The per-runtime
qualification instrumentally checks those postconditions; if the integration
is reached only after one of them, that field's pre-setup prevention is
`UNSUPPORTED`, even if a later LSM hook denies the user image.

`REJECT_UNMATCHED` is the strongest production default. `BASELINE_HARD_FLOOR`
admits ordinary containers but rejects or restricts exact request fields before
setup: privileged mode, `allowPrivilegeEscalation`, host PID/IPC/network,
dangerous added capabilities, unconfined seccomp/AppArmor/SELinux requests,
host-root/hostPath mounts, host devices, unsafe proc masks, runtime classes,
and namespace sharing. Each field is an explicit typed key; “suspicious Pod”
is not an implementation rule. `OBSERVE_ONLY_WITH_START_GAP` carries no
prevention claim.

Legitimate CSI, CNI, storage, node-observer, and other privileged controllers
use signed, exact exceptions naming ServiceAccount UID, controller UID,
namespace, image digest, runtime class, requested field delta, maximum nodes,
approver, and expiry. A label that the requesting principal can freely add is
not sufficient. Existing Pod manifests need not be changed; the exception can
be compiled centrally from reviewed current deployment state.

##### Abandoned design: Kubernetes metadata alone authenticates a privileged exception

A `system:masters` attacker can copy labels, ServiceAccount, owner references,
image digest, and much of a legitimate CSI/CNI PodSpec. Those fields remain
matching inputs but cannot be the exception's trust root. Every privileged
exception is authorized by an independently signed
the deployment-admission intent from the Mithril policy trust domain:

```text
DeploymentAdmissionIntentDraftAbandoned {
  canonical_effective_podspec_and_cri_security_digest
  exact image/argv/working-dir/env-reference/config/secret/mount/device digests
  controller UID + immutable revision digest
  permitted namespaces/nodes/replica or one-use slot count
  permitted runtime-generated normalization rules
  admission-issued Pod UID nonce when exact instance binding is required
  policy generation, approver, issued/expiry, replay sequence
}
```

The plus/slash prose fields above are not the wire schema. They are superseded
by:

```text
DeploymentAdmissionIntentV1 {
  deployment_intent_id: Id128
  trust_domain_id/issuer_id/approver_principal_id: Id128
  sequence_epoch/sequence: u64
  effective_podspec_and_cri_security_digest: DigestV1
  image_digest: DigestV1
  canonical_argv_digest: DigestV1
  working_directory_bytes: bstr(0..4096)
  environment_reference_manifest_digest: DigestV1
  config_reference_manifest_digest: DigestV1
  secret_reference_manifest_digest: DigestV1
  mount_manifest_digest: DigestV1
  device_manifest_digest: DigestV1
  security_field_manifest_digest: DigestV1
  controller_uid: Id128
  immutable_controller_revision_digest: DigestV1
  permitted_namespace_uids[]: Id128[1..256]
  permitted_node_uids[]: Id128[1..4096]
  maximum_instance_count: u32
  claim_slot_ids[]: Id128[1..4096]
  runtime_normalization_rule_ids[]: u32[0..128]
  require_instance_binding: bool
  admission_issued_pod_uid_nonce?: Id128
  target_profile_generation: PortableProfileGenerationV1
  issued_at_utc_ns/expires_at_utc_ns: i64
}
```

`maximum_instance_count` must equal the number of unique slots and cannot
exceed local policy. Every referenced manifest is present, bounded and signed;
an empty digest is not “no restriction.” Runtime normalization IDs point to a
closed, version-specific transform such as injecting a known sandbox path;
they cannot ignore an unknown field. The independently signed deployment
intent is encoded as `IntentKindV1=6 DEPLOYMENT_ADMISSION`; any Version 1
decoder that supports this node-floor capability must add that exact tag/body
and its golden vector, otherwise it reports the capability unsupported.

The node reconstructs the effective request, normalizes only declared
kubelet/runtime-added fields, and requires an exact digest plus unused slot.
Any command, env/config reference, hostPath, device, capability, security
context, owner, node, or multiplicity delta rejects. Kubernetes administrators
cannot mint this independent signature.

`NODE-FLOOR-EXCEPTION-002` copies exact CSI metadata/image but changes each
field above in separate runs and creates one extra byte-identical replica past
the signed multiplicity. Every clone rejects; the exact reviewed replicas on
allowed nodes remain the positive control.

The decision uses the request snapshot delivered at the runtime boundary and
live Pod UID/resource version when available; it does not wait for later audit.
If required Kubernetes metadata has not arrived, the node floor still applies.
Direct runtime requests receive the same floor plus host-peer classification.
A compromised API identity cannot select `OBSERVE_ONLY` or invent an exception;
those values come only from the separately signed node policy.

**Real incident fixture.** An attacker with `system:masters` creates a brand-new
Pod with `privileged: true`, `hostPID: true`, a `/` hostPath mounted at
`/host`, `CAP_SYS_ADMIN`, and a command that reads `/host/etc/shadow`. The test
races CRI creation ahead of audit/control-plane delivery. Under
`REJECT_UNMATCHED`, `CreateContainer` is rejected. Under the baseline floor,
the first forbidden request field is rejected before any setup task mounts the
host. A reviewed CSI DaemonSet with an exact non-expired exception remains a
positive control. No result may claim a later file denial if the dangerous
mount was already allowed.

#### One-gatherer runtime integration

The only Mithril event and policy owner remains the one `mithril-node` process.
Runtime integration is an admission transport, not another gatherer:

```text
kubelet / CRI caller
    -> runtime execution path
       -> lightweight hook, in-runtime adapter, or CRI admission proxy
          -> authenticated local RuntimeEntryIntent to mithril-node
             -> task/entry label installed and verified
          <- one-use acknowledgement
       -> runtime permits candidate executable transition
```

##### Cold-boot ordering and the DaemonSet circular dependency

A DaemonSet-only node cannot provide fail-closed admission before its own Pod
starts, and kubelet may start other Pods before that DaemonSet/NRI callback
registers after reboot. Advertising enforce-from-boot from that packaging is
abandoned.

The preferred full tier installs the same single `mithril-node` binary as a
host service ordered after the container runtime's control socket is available
but before kubelet is allowed to schedule/start workloads. It loads/verifies
links/maps/node floor, opens the local runtime admission endpoint, records a new
boot coverage interval, and only then releases kubelet. There is still one
gatherer, one event stream, and one WAL per node; Kubernetes may manage its
configuration, but the enforcement owner is not bootstrapped by an unprotected
workload container.

An alternative Kubernetes-packaged full tier needs a tiny persistent
runtime/shim admission gate. That gate is not a gatherer: it owns no policy
compiler, telemetry stream, graph, or WAL. At boot it holds/rejects all starts
except one exact signed Mithril bootstrap image/request under a fixed
no-network/no-host-mutation budget. After the DaemonSet node process attests
required links/maps and opens admission, the gate disables the bootstrap
exception. A forged image/tag/Pod label cannot claim it; image digest, runtime
request peer, node boot nonce, binary measurement, and one-use bootstrap slot
all match.

Packaging tiers are explicit:

| Tier | Boot guarantee |
| --- | --- |
| Host service before kubelet | Full start admission after local boot attestation |
| DaemonSet plus persistent non-gathering runtime gate | Full after exact bootstrap transaction |
| DaemonSet/NRI alone | `START_GAP`; reconcile/restart workloads before upgrading coverage, never first-exec prevention |

`BOOT-ADMISSION-001` exercises cold boot with runtime then kubelet then node
agent, reversed service timing, agent Pod reschedule, daemon crash, upgrade,
and a forged bootstrap Pod. No non-bootstrap user marker may run before healthy
admission; the real bootstrap cannot receive workload/network/host authority.
In DaemonSet-only mode the same race must report `START_GAP`, not pass.

Preferred mechanisms, in descending order of guarantee:

1. A runtime/shim integration holds the exact new task before user executable
   installation, passes a pidfd plus full runtime identity, and resumes only
   after Mithril installs and reads back the task label.
2. The `mithril-node` process provides a local CRI admission proxy and writes a
   one-use pending intent before forwarding `ExecSync`/`Exec`; an unlabeled
   task may claim that intent only at `bprm_check_security` in the exact bound
   cgroup and for the exact candidate executable class.
3. An OCI pre-start hook, delivered as a short-lived mode of the same product
   binary, provides initial-container admission. This does not solve later
   runtime exec by itself.
4. Observe-only runtime callbacks may enrich a task after start, but they must
   report a start gap and cannot claim enforce-from-first-exec.

##### Abandoned design: a generic OCI pre-start hook is strict admission

Item 3 is useful transport context but is not a universal strict-admission
mechanism. OCI hook names/order have changed, hook context varies by runtime,
and an OCI init task may perform namespace, mount, pivot-root, credential, and
capability setup while already placed in the future workload cgroup and before
the user image. A blanket unlabeled-task deny would break the runtime; a broad
“runtime may do anything” exception would be an escape gap. Treating any
generic pre-start hook as sufficient is abandoned.

Initial-container support uses this binding state machine:

```text
UNBOUND
  -> PREPARING(exact runtime request and container identity)
  -> ADMITTING(exact held runtime-init task, runtime-setup role)
  -> USER_EXEC_PREPARING(entry-provisional role)
  -> BOUND_USER(final application/init/sidecar role)
  -> TERMINATING
  -> TOMBSTONED

any pre-user state -> REJECTED | SETUP_FAILED
```

The runtime/shim supplies the held init task/pidfd before it enters
`ADMITTING`. `runtime-setup` is a fixed, runtime-version-specific physical
budget permitting only the proven namespace/mount/rootfs/credential/loader
operations for that init path. It denies workload data/credential reads,
public/control-plane network, arbitrary child exec, devices, and unrelated
privilege effects. The exact final user `bprm` chain switches first to
`entry-provisional` and then atomically to the target role at successful exec
commit.

No ordinary workload task may claim `runtime-setup`. Peer identity, runtime
request, full container ID, cgroup binding nonce, held pidfd, runtime binary
measurement, and one-use setup nonce all match. Failure or timeout reaps the
held init and tombstones the binding; it does not leave a setup-authorized task
runnable.

Qualification is per `(runtime, runtime version/config, OCI implementation,
kernel, hook phase)`. Phase 0 records the exact setup effects observed from
known-good container start, converts them into a reviewed fixed budget, and
runs hostile tests that make the runtime init attempt a credential read,
network connect, extra exec, or device access. Legitimate start must pass and
every injected extra effect must deny. An OCI hook that cannot bind the held
task provides evidence only.

##### Implementable runtime-setup budget and hold protocol

The retained phrase “namespace/mount/rootfs/credential/loader operations” is
too broad to implement safely. In particular, “credential operations” could
be misread as permission to read a mounted credential. That broad reading is
abandoned. Each supported runtime build ships a reviewed, signed
`RuntimeSetupBudgetV1`:

```text
RuntimeSetupBudgetV1 {
  budget_id
  runtime_binary_measurement
  runtime_name_version_config_digest
  kernel_capability_manifest_digest
  ordered_variants[] {
    variant_id
    steps[] {
      step_id
      permitted_predecessor_step_mask
      decision_point: exact LSM/fentry/seccomp hook ID
      syscall_or_kernel_operation_variant
      object_selector_or_namespace_type
      argument_mask_and_required_values
      minimum_count
      maximum_count
      result_requirement
    }
  }
  final_uid_gid_groups_capabilities_securebits
  final_namespace_and_rootfs_identity
  final_seccomp_proof_requirement?
}
```

A runtime start matches exactly one ordered variant. A step outside its
operation/object/flag/count/order bounds is `RUNTIME_SETUP_BUDGET_VIOLATION`
and fails the start. Allowed credential work means only the exact kernel
credential transitions needed to reach the declared final UID/GID/groups,
capability drops, securebits, and `no_new_privs`, plus mounting declared
projected credential volumes as opaque mount objects. It never means opening,
reading, mapping, copying, or sending their contents. A setup task may mount
`kube-api-access-abc` at the PodSpec-declared target; `openat()` of its `token`
file is still denied.

`pidfd` is a stable task handle, **not a suspension primitive**. The first
production hold protocol is a runtime/shim integration using this sequence:

```text
1. runtime supervisor creates the init child with clone3(CLONE_PIDFD);
2. the measured child bootstrap reaches its mandatory stop barrier before
   namespace/rootfs/setup work; supervisor verifies WSTOPPED with waitid(P_PIDFD);
3. supervisor sends pidfd + sealed one-use setup ticket over the root-only
   Mithril socket; SO_PEERCRED and runtime measurement must match;
4. mithril-node re-resolves pidfd, task start time, cgroup root/binding nonce,
   runtime request, and ticket;
5. mithril-node creates BPF_MAP_TYPE_TASK_STORAGE through its userspace
   pidfd-keyed map operation, then reads it back through the same pidfd and a
   BPF task iterator; both copies must match the staged budget/generation;
6. only after readback does the supervisor release the stop barrier;
7. every setup effect consumes the exact budget; final exec atomically commits
   the application/init/sidecar role before user mode.
```

The bootstrap barrier may be a shim-owned stopped-child protocol or a
separately qualified ptrace stop used only during admission; steady-state
ptrace is not required. For a brand-new empty cgroup, an alternative
`cgroup.freeze` protocol is legal only when readback proves `frozen=1`, the
exact task set contains only the candidate setup tasks, and unfreeze happens
after all labels are verified. Merely possessing a pidfd, sending `SIGSTOP`
without observing the stop, or attaching an OCI hook after setup is not a
hold.

A plain signal/group stop remains insufficient even after `WSTOPPED`: another
permitted task can send `SIGCONT`. The supported task barrier is either (a) a
ptrace-stop exclusively owned by the measured supervisor, released only by its
authenticated `PTRACE_CONT`, or (b) a trusted static bootstrap blocked in a
private `CLOEXEC` pipe/eventfd/futex protocol that loops across signals and
accepts one MAC-bound acknowledgement for its task/ticket/readback digest.
The task-kill/ptrace floor protects both bootstrap and supervisor. A leaked
release fd, ordinary SIGSTOP-only protocol, or supervisor whose descendants can
invoke the release operation is reduced/unsupported.

###### Correction: only a stopped barrier has `WSTOPPED` evidence

Step 2's `WSTOPPED` claim applies only to the ptrace/stopped-child variant. A
private pipe/eventfd/futex bootstrap is running but blocked and must never
fabricate a stopped-task result. Every hold acknowledgement includes one closed
variant:

```text
BarrierEvidenceV1 =
  PTRACE_STOPPED {
    held_pidfd_identity, task_cookie, start_boottime_ns,
    waitid_p_pidfd_result_digest, wstopped_observed: true,
    exclusive_tracer_process_identity, ptrace_relationship_digest,
    stop_boottime_ns
  }
  | PRIVATE_BOOTSTRAP_BLOCKED {
      held_pidfd_identity, task_cookie, start_boottime_ns,
      measured_bootstrap_digest, ready_transcript_digest,
      private_release_handle_identity, release_nonce,
      ack_mac_key_id, expected_ack_payload_digest,
      wstopped_observed: false
    }
  | CGROUP_FROZEN {
      cgroup_fd_identity, cgroup_binding_nonce,
      cgroup_events_frozen_value: 1,
      exact_member_task_set_digest, member_count,
      freeze_generation, readback_boottime_ns
    }
```

The release acknowledgement signs/MACs
`(barrier_variant, exact held target/set, setup ticket, all label/object
readback digests, release_nonce)`. A verifier rejects fields from another
variant, a claimed `WSTOPPED` without `waitid(P_PIDFD)`, any changed cgroup
member, reused handle/nonce, leaked release handle or unmatched supervisor.
`ENTRY-HOLD-ATTACK-002` runs all three variants independently and never treats
one variant's oracle as proof for another.

`ENTRY-HOLD-ATTACK-002` sends hostile `SIGCONT`, `SIGKILL`, ptrace attach, and
spurious signals; kills the parent; induces `EINTR`/spurious wake; leaks a
candidate pipe fd; and sends a resume token before readback. Neither setup nor
user marker may run. Only the measured supervisor with the matching one-use ack
can advance the positive control.

**Runtime setup tests.** For every advertised runtime/shim/config version,
pause before label installation and prove the child cannot advance; inject an
early resume and require admission failure; substitute wrong task/pidfd,
runtime binary, cgroup, ticket, and config digests; add one unknown effect and
one extra repetition at every sequence position; force setup and final-exec
failure; try to read the mounted service-account token from the setup task;
and exhaust task storage. The physical oracle is that the user image executes
only after matching task-storage readback, while every malicious variant is
reaped and the binding becomes `SETUP_FAILED` without a runnable
`runtime-setup` task.

##### Required post-setup, pre-user-exec object-binding barrier

The initial stop proves the setup task is labeled before setup; it does not yet
provide the mount/rootfs/projected-volume objects needed for final file/exec
classification. Releasing that barrier and running directly to user exec would
race asynchronous topology/object binding. That one-barrier design is
abandoned.

The runtime integration has a second measured synchronization point:

```text
SETUP_LABELED
  -> SETUP_RUNNING_UNDER_BUDGET
  -> ROOTFS_READY_HELD
  -> TOPOLOGY_RECONCILED
  -> OBJECT_TABLES_INSTALLED_AND_READ_BACK
  -> ONE_USE_FINAL_EXEC_ARMED
  -> USER_EXEC_COMMIT
```

Immediately before the runtime would install the configured user image, its
trusted init path stops on the runtime synchronization pipe and sends
`RootfsReadyV1`: held pidfd/task cookie, mount-namespace fd/identity, cgroup
binding, overlay/rootfs identity, OCI config digest, image digest, declared
mounts/devices/projected volumes, and final argv/environment metadata digest.
`mithril-node` holds the namespace fd, reconciles `MountNamespaceStateV1` to
`CLEAN`, resolves executable/loader/file/projected-volume object keys, compiles
and installs them in the inactive/entry tables, reads every required key and
task expectation back, and stages one final-exec claim. Only then does it send
the resume acknowledgement.

Any mount/topology change after readback atomically marks the namespace DIRTY;
the final `bprm` or file hook denies until another full reconciliation. Token
rotation does not require binding secret bytes or one transient inode: the
projected-volume identity plus bounded relative semantic item is the
synchronous classifier described in the file section.

`ENTRY-ROOTFS-BARRIER-001` delays the object binder, performs overlay copy-up,
rotates a projected token, attempts an extra mount after acknowledgement, and
injects resume before object-table readback. The user executable marker must
not run in any failing/dirty case. The positive control reaches user mode only
after the exact executable, loader, rootfs, and projected-volume classifiers
are readable from the active generation.

An NRI `StartContainer` callback alone is insufficient for full protection;
the local KubeArmor implementation documents precisely that post-start gap.
No permanently resident second collector is introduced. A short-lived hook or
code executing inside the runtime is not allowed to own policy maps, lineage,
WAL, or an independent event stream.

##### Abandoned design: treating streaming `Exec` as one synchronous request

The compact diagram above can be misread as “receive CRI `Exec`, forward it,
and immediately bind a process.” That interpretation is wrong and is
abandoned. In CRI, streaming `Exec` prepares an endpoint and returns a URL;
the exec process is normally created only after the client connects to the
runtime's streaming server. A proxy that observes only the prepare RPC has no
task to bind and cannot prove which later stream consumed the request.

The normative streaming state machine is:

```text
PREPARE_RECEIVED
  -> TICKET_ISSUED
  -> STREAM_AUTHENTICATED
  -> TASK_HELD_OR_PENDING_CLAIM
  -> TASK_BOUND
  -> RUNNING
  -> EXITED

from PREPARE_RECEIVED or TICKET_ISSUED:
  -> REJECTED | EXPIRED | CANCELLED

from STREAM_AUTHENTICATED or TASK_HELD_OR_PENDING_CLAIM:
  -> BIND_FAILED (client receives failure; user command does not run)
```

`mithril-node` implements this contract in one of two ways:

1. The admission endpoint owns both the prepare RPC and the returned stream
   URL. It returns a Mithril URL containing an opaque ticket, authenticates
   the later stream, consumes the ticket once, and then opens the upstream
   runtime stream. The ticket is not a bearer authorization by itself: the
   later peer, target container, stream flags, request digest, deadline, and
   runtime connection must all match.
2. The runtime/shim is modified or extended at its process-creation seam. It
   receives a prevalidated ticket ID, creates the child held before user mode,
   passes a pidfd and immutable runtime identity to `mithril-node`, and resumes
   only after label readback succeeds.

A proxy that forwards the runtime's original URL directly to the client does
not own the second stage and therefore cannot claim strict streaming-exec
admission. It may still record prepare-time context, but the resulting tier is
observation-only unless the pending-claim fallback is separately qualified.

The durable ticket is:

```text
RuntimeStreamTicket {
  ticket_id: 128 random bits
  request_sequence: u64 within authenticated caller epoch
  request_digest: Digest(canonical ExecRequest)
  caller_peer_id: LocalPeerId
  execution_set_id: ExecutionSetId
  full_container_id: bytes
  entry_instance_id: EntryInstanceId
  issued_boottime_ns: u64
  deadline_boottime_ns: u64
  expected_tty_stdin_stdout_stderr: bitset
  state: ISSUED | CLAIMING | CONSUMED | EXPIRED | CANCELLED | FAILED
}
```

Transitions use compare-and-swap. `ISSUED -> CLAIMING` happens only after
stream authentication. `CLAIMING -> CONSUMED` happens only after the exact
task label is installed and read back. A disconnect before `CONSUMED` moves
the ticket to `CANCELLED`; reconnecting does not revive it. A second stream
using the same ticket receives a typed replay error.

**Practical test.** Client A requests `kubectl exec`, receives ticket `Q`, and
disconnects. Client B steals the URL and connects after the deadline. No task
may start, `Q` ends `EXPIRED` or `CANCELLED`, and an admission finding records
both authenticated peers. A second fixture opens two concurrent connections
with `Q`; exactly one can transition `ISSUED -> CLAIMING`, and the loser gets
`ENTRY_TICKET_ALREADY_CLAIMED`.

`ExecSync` is different: it is one synchronous CRI operation from the caller's
perspective, but the runtime still creates and runs the process internally.
Strict `ExecSync` support therefore requires the runtime/shim hold-and-bind
seam or the qualified pre-exec pending claim. Waiting for the `ExecSync`
response is post-execution evidence and cannot authorize the command.

#### `RuntimeEntryIntent`

```text
RuntimeEntryIntent {
  nonce: 128-bit random
  caller_transport: oci_hook | cri_execsync | cri_exec | runtime_shim
  caller_peer: authenticated local identity
  request_sequence
  cluster_uid
  node_boot_id
  pod_uid
  pod_resource_version
  full_container_id
  cgroup_binding_id
  runtime_lifecycle_generation
  operation: container_start | exec_sync | streaming_exec | ephemeral_start
  command: redacted argv plus canonical digest
  candidate_binary_hint
  tty, stdin, stdout, stderr
  requested_at
  deadline
}
```

The userspace classifier joins the request to the effective PodSpec and emits
an `EntryInstance`. It never trusts container annotations alone; it re-resolves
the full container, cgroup live interval, Pod UID, image digest, and policy
generation.

#### Authenticated intent proof: common protocol

`RuntimeEntryIntent` proves the runtime operation and caller transport. It does
not, by itself, prove the human or coordinator purpose behind the operation.
The same distinction applies outside Kubernetes. Seeing `aws sso login`,
`gcloud auth login`, `gsutil cp`, `kubectl`, or `/app/healthcheck` in argv does
not prove that a human, CI job, kubelet probe, or approved deployment intended
that action. An attacker can execute the same binary and arguments.

**The AWS and Google CLI examples are analogies for proving intent through a
separate authenticated channel; they are not entry kinds.** Mithril does not
create `AwsLoginEntry`, `GcloudLoginEntry`, or `GsutilEntry`. Those processes
keep their real native parent/exec lineage. Only the separately obtained
provider authority is represented as an `AuthorityLeaseIntent` and, after
issuance is proven, a `CredentialLease`. The reason to study those login flows
is to reuse their signed issuer, audience, nonce, expiry, approval, and session
binding ideas for kubelet and CI intent proof.

The correct extension is a general **intent-proof channel**: a trusted
coordinator sends a signed, replay-resistant assertion before the relevant
entry, transition, or authority acquisition. This is another input to the one
`mithril-node` gatherer, not a second gatherer. The producer does not load BPF,
collect kernel events, own policy, or maintain a competing process graph.

```text
trusted coordinator or identity provider
    -> signed one-use IntentProofEnvelope
       -> authenticated local socket or central signed stream
          -> mithril-node validates issuer, nonce, time, target, and policy
             -> pending entry / transition / authority-lease proof
                -> exact task claims proof at the matching pre-effect point
```

##### Intent proof envelope

```text
IntentProofEnvelope {
  proof_id
  issuer_id
  issuer_kind: kubelet | ci_coordinator | human_approval | identity_provider |
               deployment_controller | connector
  issuer_key_id
  signature
  issued_at
  not_before
  expires_at
  nonce
  sequence

  subject_scope {
    cluster_uid?
    node_id?
    pod_uid?
    full_container_id?
    cgroup_binding_id?
    execution_set_id?
    process_lineage_id?
    ci_run_id?
    ci_job_id?
    ci_step_id?
    human_session_id?
  }

  declared_intent {
    kind: runtime_entry | native_transition | authority_lease |
          artifact_handoff | provider_operation
    operation
    command_digest?
    executable_object?
    image_digest?
    provider?
    account_or_project?
    requested_role_or_permission_set?
    credential_audience?
    artifact_digests[]
    lifecycle_state?
  }

  trigger {
    actor_id?
    event_type?
    workflow_or_manifest_ref?
    immutable_definition_digest?
    approval_id?
    parent_proof_id?
  }

  allowed_claim_count
  disposition_on_mismatch
  disposition_on_expiry
}
```

##### Normative intent wire, trust, and replay contract

The object above lists logical fields. It is not permission for each adapter
to invent its own JSON signing rules. Version 1 uses one canonical security
object:

```text
SignedIntentV1 {
  wire_version: 1
  key_id: non-empty byte string, maximum 128 bytes
  algorithm: value allowed for key_id by the installed TrustBundle
  canonical_payload: deterministic CBOR IntentPayloadV1
  signature: bytes
}

signature_input =
  ASCII("MITHRIL-INTENT-V1") || 0x00 || SHA-256(canonical_payload)
```

###### Correction: `IntentPayloadV1` is a closed discriminated wire record

The retained signature envelope names but does not define `IntentPayloadV1`;
the earlier logical envelope also omits tenant/trust domain, signed sequence
epoch and explicit slot IDs while retaining abandoned failure/count fields.
Independent issuers cannot safely implement that sketch. The following is the
normative Version 1 wire contract.

All maps use unsigned integer keys written below; unknown or duplicate keys
are rejected. `Id128` is a 16-byte CBOR byte string; `DigestV1` is map
`{0: 1, 1: <32-byte SHA-256>}`; UTC values are signed 64-bit Unix-epoch
nanoseconds; durations and sequences are unsigned 64-bit integers. Text is not
used for security IDs.

```text
SignedIntentV1 = {
  0: 1,                         // wire_version
  1: bstr(1..128),              // key_id
  2: 1,                         // algorithm = ED25519
  3: bstr(1..32768),            // exact canonical IntentPayloadV1 bytes
  4: bstr(64)                   // Ed25519 signature over signature_input
}

IntentPayloadV1 = {
  0: 1,                         // payload_version
  1: IntentKindV1,
  2: Id128,                     // proof_id
  3: Id128,                     // tenant_id
  4: Id128,                     // trust_domain_id
  5: Id128,                     // issuer_id
  6: u64_nonzero,               // sequence_epoch
  7: u64_nonzero,               // sequence
  8: i64,                       // issued_at_utc_ns
  9: i64,                       // not_before_utc_ns
  10: i64,                      // expires_at_utc_ns; > not_before
  11: [Id128; 1..64],           // unique, sorted claim_slot_ids
  12: IntentBodyV1,             // type selected exactly by key 1
  13?: Id128,                   // parent_proof_id
  14?: [Id128; 1..16]           // trigger_proof_ids, unique/sorted
}

IntentKindV1 =
  1 RUNTIME_ENTRY | 2 NATIVE_TRANSITION | 3 AUTHORITY_LEASE |
  4 ARTIFACT_HANDOFF | 5 PROVIDER_OPERATION | 6 DEPLOYMENT_ADMISSION |
  7 CI_STEP
```

The body is one of these integer-keyed maps; a field from another variant is
an unknown-field error, not an extension:

```text
RuntimeEntryBodyV1 = {
  0: Id128 cluster_uid,
  1: Id128 node_boot_id,
  2: bstr(1..64) pod_uid,
  3: bstr(32..128) full_container_id,
  4: Id128 execution_set_id,
  5: Id128 cgroup_binding_id,
  6: Id128 cgroup_binding_nonce,
  7: u64_nonzero lifecycle_generation,
  8: RuntimeOperationV1,
  9: EntryKindV1,
  10: DigestV1 immutable_definition_or_podspec_digest,
  11?: DigestV1 canonical_command_digest,
  12: Id128 target_role_id,
  13: DigestV1 runtime_request_digest,
  14?: DigestV1 held_task_or_stream_binding_digest
}

NativeTransitionBodyV1 = {
  0: Id128 node_boot_id,
  1: Id128 execution_set_id,
  2: Id128 process_lineage_id,
  3: Id128 source_execution_id,
  4: NativeOperationV1,
  5: DigestV1 candidate_executable_or_action_digest,
  6: Id128 source_role_id,
  7: Id128 target_role_id
}

AuthorityLeaseBodyV1 = {
  0: LocalAuthoritySubjectV1,   // exact execution set/process or exact CI job/step
  1: ProviderV1,
  2: bstr(1..256) provider_account_or_project,
  3: bstr(1..512) audience,
  4: [u32; 1..128] requested_permission_ids,
  5: [ResourceSelectorV1; 1..128] requested_resources,
  6: u64 maximum_ttl_ns,
  7: bstr(1..256) issuer_subject,
  8: Id128 provider_request_nonce
}

ArtifactHandoffBodyV1 = {
  0: CausalSubjectV1 producer,
  1: CausalSubjectV1 consumer,
  2: ArtifactKindV1,
  3: DigestV1 immutable_artifact_digest,
  4: ProducerTrustClassV1,
  5: ArtifactOperationV1,
  6: [DigestV1; 0..32] required_attestation_digests
}

ProviderOperationBodyV1 = {
  0: ProviderV1,
  1: bstr(1..256) provider_account_or_tenant,
  2: ProviderPrincipalV1,
  3: u32 canonical_operation_id,
  4: [ResourceSelectorV1; 1..128] resources,
  5: Id128 request_nonce,
  6: ProviderResultBoundaryV1,
  7: u64 maximum_ttl_ns
}

DeploymentAdmissionBodyV1 = {
  0: Id128 approver_principal_id,
  1: DigestV1 effective_podspec_and_cri_security_digest,
  2: DigestV1 image_digest,
  3: DigestV1 canonical_argv_digest,
  4: bstr(0..4096) working_directory_bytes,
  5: DigestV1 environment_reference_manifest_digest,
  6: DigestV1 config_reference_manifest_digest,
  7: DigestV1 secret_reference_manifest_digest,
  8: DigestV1 mount_manifest_digest,
  9: DigestV1 device_manifest_digest,
  10: DigestV1 security_field_manifest_digest,
  11: Id128 controller_uid,
  12: DigestV1 immutable_controller_revision_digest,
  13: [Id128; 1..256] permitted_namespace_uids,
  14: [Id128; 1..4096] permitted_node_uids,
  15: u32 maximum_instance_count,
  16: [u32; 0..128] runtime_normalization_rule_ids,
  17: bool require_instance_binding,
  18?: Id128 admission_issued_pod_uid_nonce,
  19: u64 target_profile_generation
}

CiStepIntentBodyDraftAbandoned = {
  0: CiCoordinatorV1 coordinator,
  1: bstr(1..256) tenant_id,
  2: bstr(1..256) repository_or_project_id,
  3: bstr(1..256) pipeline_run_id,
  4: bstr(1..256) pipeline_job_id,
  5: bstr(1..256) pipeline_step_id,
  6: u32_nonzero run_attempt,
  7: DigestV1 immutable_pipeline_definition_digest,
  8: DigestV1 step_definition_identity_digest,
  9: DigestV1 materialized_step_invocation_digest,
  10: CiTriggerTrustClassV1,
  11: CiExecutionShapeV1,
  12: bstr(1..256) exact_runner_assignment_id,
  13: Id128 node_boot_id,
  14: Id128 execution_set_id,
  15: Id128 cgroup_binding_id,
  16: Id128 cgroup_binding_nonce,
  17: Id128 requested_role_id,
  18: [DigestV1; 0..128] input_artifact_digests,
  19: [Id128; 0..32] requested_authority_lease_proof_ids,
  20?: Id128 parent_step_proof_id,
  21: DigestV1 coordinator_assignment_proof_digest,
  22?: DigestV1 held_task_or_runtime_request_binding_digest
}

CiExecutionBindingV1 =
  {0: 1,                              // LOCAL_NATIVE
   1: Id128 node_boot_id,
   2: Id128 execution_set_id,
   3: Id128 cgroup_binding_id,
   4: Id128 cgroup_binding_nonce,
   5: DigestV1 held_pidfd_task_binding_digest}
  | {0: 2,                            // LOCAL_RUNTIME_ROOT
     1: Id128 node_boot_id,
     2: Id128 execution_set_id,
     3: Id128 cgroup_binding_id,
     4: Id128 cgroup_binding_nonce,
     5: DigestV1 held_runtime_request_binding_digest}
  | {0: 3,                            // COORDINATOR_ONLY
     1: Id128 provider_operation_request_id}

CiStepIntentBodyV1 = {
  0: CiCoordinatorV1 coordinator,
  1: bstr(1..256) tenant_id,
  2: bstr(1..256) repository_or_project_id,
  3: bstr(1..256) pipeline_run_id,
  4: bstr(1..256) pipeline_job_id,
  5: bstr(1..256) pipeline_step_id,
  6: u32_nonzero run_attempt,
  7: DigestV1 immutable_pipeline_definition_digest,
  8: DigestV1 step_definition_identity_digest,
  9: DigestV1 materialized_step_invocation_digest,
  10: CiTriggerTrustClassV1,
  11: CiExecutionShapeV1,
  12: bstr(1..256) exact_runner_assignment_id,
  13: CiExecutionBindingV1 execution_binding,
  14: Id128 requested_role_id,
  15: [DigestV1; 0..128] input_artifact_digests,
  16: [Id128; 0..32] requested_authority_lease_proof_ids,
  17?: Id128 parent_step_proof_id,
  18: DigestV1 provider_job_assignment_evidence_digest,
  19?: DigestV1 trusted_runner_step_launch_attestation_digest
}
```

The draft body required local node/cgroup fields even for
`COORDINATOR_BUILTIN_NO_LOCAL_TASK`; that shape was impossible. The tagged
binding forbids—not zero-fills—local fields for `COORDINATOR_ONLY`. Shapes 1–4
require the corresponding local binding and held-target digest. Variant-extra,
variant-missing, wrong-shape and dummy-zero fields are parser rejection
vectors.

`RuntimeOperationV1` is `1 CONTAINER_START`, `2 EXEC_SYNC`,
`3 STREAMING_EXEC`, `4 LIFECYCLE_EXEC`, `5 EPHEMERAL_CONTAINER`, or
`6 CHECKPOINT_RESTORE`. `NativeOperationV1` is `1 FORK`, `2 EXEC`, or
`3 PRIVILEGE_TRANSITION`. `ArtifactOperationV1` is `1 READ_AS_DATA`,
`2 VERIFY`, `3 LOAD`, `4 EXECUTE`, or `5 DEPLOY`. The referenced provider,
subject, resource, entry-kind, artifact-kind, trust-class and result-boundary
types are closed tagged unions in the Phase 0 schema registry; every union has
an explicit numeric discriminant and variant-specific integer-keyed map. A
variant is not implementable until its complete tag/field/bound registry and
golden vector is checked in.

`CiCoordinatorV1` is `1 GITHUB_ACTIONS`, `2 GITLAB_CI`, `3 JENKINS`, or
`4 TEKTON`. `CiTriggerTrustClassV1` is `1 TRUSTED_REF`,
`2 UNTRUSTED_CHANGE`, `3 SCHEDULED`, `4 MANUAL_APPROVED`, or
`5 POLICY_GENERATED`. `CiExecutionShapeV1` is `1 NATIVE_TRANSITION`,
`2 RUNTIME_JOB_CONTAINER_ROOT`, `3 RUNTIME_ACTION_CONTAINER_ROOT`,
`4 SERVICE_ROOT`, or `5 COORDINATOR_BUILTIN_NO_LOCAL_TASK`. Shape 5 cannot
claim a local task slot; it produces coordinator evidence only.

The baseline tag registry needed by this plan is already fixed here:

```text
ProviderV1 = 1 KUBERNETES | 2 AWS | 3 GCP | 4 GITHUB |
             5 INTERNAL_CONNECTOR | 6 OCI_REGISTRY

EntryKindV1 = 1 CONTAINER_START | 2 EXEC_PROBE | 3 LIFECYCLE_POSTSTART |
              4 LIFECYCLE_PRESTOP | 5 ADMINISTRATIVE_EXEC |
              6 EPHEMERAL_CONTAINER | 7 CI_CONTAINER_ACTION |
              8 CHECKPOINT_RESTORE | 9 UNKNOWN_EXTERNAL

ArtifactKindV1 = 1 FILE | 2 DIRECTORY_TREE | 3 OCI_IMAGE |
                 4 CI_ARTIFACT | 5 CACHE_ENTRY | 6 QUEUE_MESSAGE |
                 7 DEPLOYMENT_MANIFEST

ProducerTrustClassV1 = 1 UNTRUSTED_INPUT | 2 PROTECTED_BUILD |
                       3 APPROVED_RELEASE | 4 EXTERNAL_UNVERIFIED

ProviderResultBoundaryV1 = 1 SYNCHRONOUS_GATE_RESULT |
                           2 AUTHORITATIVE_API_RESULT

LocalAuthoritySubjectV1 =
  {0: 1, 1: Id128 node_boot_id, 2: Id128 execution_set_id,
   3: Id128 process_lineage_id}
  | {0: 2, 1: ProviderV1 coordinator, 2: bstr(1..256) run_id,
     3: bstr(1..256) job_id, 4?: bstr(1..256) step_id}

CausalSubjectV1 =
  {0: 1, 1: Id128 node_boot_id, 2: Id128 process_lineage_id,
   3?: Id128 execution_id}
  | {0: 2, 1: ProviderV1 coordinator, 2: bstr(1..256) run_id,
     3: bstr(1..256) job_id}
  | {0: 3, 1: ProviderV1, 2: bstr(1..512) stable_subject_id}

ResourceSelectorV1 = {
  0: u16 resource_kind_id,
  1: bstr(1..1024) provider_canonical_resource_bytes,
  2?: DigestV1 immutable_revision_digest
}

ProviderPrincipalV1 = {
  0: u16 principal_kind_id,
  1: bstr(1..512) provider_stable_principal_id,
  2?: bstr(1..512) public_session_or_lease_id
}
```

For provider-specific `resource_kind_id`, `principal_kind_id`, permission and
operation IDs, the signed provider adapter capability owns a checked-in numeric
registry at `spec/intent/v1/providers/<provider>.yaml`. A release cannot emit
or accept an unregistered number; adding one changes the registry digest in
the platform manifest and requires provider golden/negative vectors. Display
names are generated from that registry and never signed in place of the ID.

The signed payload never contains `allowed_claim_count`,
`disposition_on_mismatch`, or `disposition_on_expiry`. Their retained logical
fields are rejected as unknown. The local signed policy owns failure posture;
the array in key 11 owns exact multiplicity.

Bounds are checked before signature verification allocation: maximum nesting
depth 8; encoded payload 32 KiB; aggregate byte-string data 24 KiB; aggregate
array members 512; one body only; 64 slots; 16 trigger IDs. IDs and arrays
must be bytewise sorted where stated and contain no duplicates. Issued/not-
before/expiry and trust-bundle validity are checked with the uncertainty rule
below; expiry may be at most 24 hours after issue and each intent-kind/local
policy can compile a smaller limit.

The normative parser/signature golden vector uses the exact runtime-entry body
above, omits optional command/parent/trigger fields, and fills fixed IDs with
the repeated byte shown by each field in the Phase 0 fixture. The private seed
is public **test material** and must be rejected by production trust-bundle
lint:

```text
key_id_utf8 = test-ed25519-1
test_private_seed =
  000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
ed25519_public_key =
  03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8

canonical_payload_hex =
  ad00010101025002020202020202020202020202020202035003030303030303030303030303030303045004040404040404040404040404040404055005050505050505050505050505050505060107182a080009000a1a3b9aca000b8150111111111111111111111111111111110cae0050202020202020202020202020202020200150212121212121212121212121212121210249706f642d7569642d3103582022222222222222222222222222222222222222222222222222222222222222220450232323232323232323232323232323230550242424242424242424242424242424240650252525252525252525252525252525250707080109010aa2000101582026262626262626262626262626262626262626262626262626262626262626260c50272727272727272727272727272727270da2000101582028282828282828282828282828282828282828282828282828282828282828280ea200010158202929292929292929292929292929292929292929292929292929292929292929
payload_sha256 =
  64bf8002f28e948c1cd7a4cc990b5640b3d2916ebc282056aea6574b0ff14535
signature_input_hex =
  4d49544852494c2d494e54454e542d56310064bf8002f28e948c1cd7a4cc990b5640b3d2916ebc282056aea6574b0ff14535
ed25519_signature =
  d74c4459149c9b4a1703cc161c619f1a0068b0133ca3c7dfafb184d3ae5355ee90f1a013b1536799e9ee8e592af035c7485493c6ff559be4d9587cacd5d22e01
canonical_signed_envelope_hex =
  a50001014e746573742d656432353531392d31020103590186ad00010101025002020202020202020202020202020202035003030303030303030303030303030303045004040404040404040404040404040404055005050505050505050505050505050505060107182a080009000a1a3b9aca000b8150111111111111111111111111111111110cae0050202020202020202020202020202020200150212121212121212121212121212121210249706f642d7569642d3103582022222222222222222222222222222222222222222222222222222222222222220450232323232323232323232323232323230550242424242424242424242424242424240650252525252525252525252525252525250707080109010aa2000101582026262626262626262626262626262626262626262626262626262626262626260c50272727272727272727272727272727270da2000101582028282828282828282828282828282828282828282828282828282828282828280ea200010158202929292929292929292929292929292929292929292929292929292929292929045840d74c4459149c9b4a1703cc161c619f1a0068b0133ca3c7dfafb184d3ae5355ee90f1a013b1536799e9ee8e592af035c7485493c6ff559be4d9587cacd5d22e01
envelope_sha256 =
  9343ba9751e4e03e757a43d0aa8cad668b94b84ceba8f5d9a6f3485a9ffa1d30
```

Phase 0 stores these exact bytes under `spec/intent/v1/golden/` and runs Rust
encode, decode, reject-noncanonical and signature verification against them.
Changing any integer tag, field omission rule, ordering, domain separator or
bound is a wire-version change, not a refactor.

`canonical_payload` uses RFC 8949 deterministic CBOR: definite lengths,
shortest integer encodings, and deterministically ordered map keys. A decoder
rejects duplicate keys, indefinite-length values, non-canonical encodings,
unknown security-relevant fields, overlong strings/arrays, and a decoded
object whose re-encoding differs byte-for-byte. JSON/YAML may be used for
human input, but it is normalized and validated before signing; raw JSON or
YAML bytes are never the signature payload.

`TrustBundle` is owned by the control trust owner and contains:

```text
TrustBundle {
  trust_domain_id
  bundle_generation: u64
  issuers[] {
    issuer_id
    issuer_kind
    key_id
    public_key
    allowed_algorithm
    sequence_epoch
    valid_from_utc
    valid_until_utc
    revoked_at_utc?
    allowed_intent_kinds[]
    allowed_subject_scopes[]
  }
  maximum_clock_skew: duration = 30s
  replay_window_size: u32 = 4096
}
```

`maximum_clock_skew` is configurable from `0s` through `5m`; values above
`5m` fail profile validation rather than silently weakening expiry. A proof is
accepted only when the local trusted-clock interval—including measured clock
uncertainty—intersects its validity interval. On receipt, Mithril derives a
boottime deadline. Later claim checks use that monotonic deadline, so an NTP
step cannot revive an expired proof.

Replay state is keyed by
`(trust_domain_id, issuer_id, key_id, sequence_epoch)`. It stores the highest
sequence, a 4096-bit seen window, and tombstones for accepted `proof_id` and
claim-slot IDs through their expiry plus skew. Acceptance is one transaction:

1. validate the signature, trust scope, canonical payload, time, and target;
2. verify the sequence is new within the bounded out-of-order window and all
   IDs are unseen;
3. durably append the replay acceptance to the local WAL;
4. only after the append is durable, expose claim slots to the kernel/runtime;
5. durably record every exact
   `PENDING -> CLAIMING -> CLAIM_BOUND_PROVISIONAL -> EXEC_COMMITTED`
   transition, or the exact terminal `EXPIRED|CANCELLED|EXEC_FAILED|TASK_EXITED`
   transition that occurred.

A restart replays this WAL before the admission socket opens. A proof already
accepted before the crash cannot be accepted again. A sequence older than the
window is rejected as `INTENT_SEQUENCE_TOO_OLD`, even if its ID is absent.
Key rotation creates a new signed `sequence_epoch` linked to the previous
epoch and authorized by the trust-bundle generation; changing a key ID alone
does not reset replay protection.

Item 5 does not make a BPF hook wait for disk. Proof acceptance/staging is
durable before exposure as stated. The later kernel claim uses a pinned claim
journal whose entry is the authoritative crash bridge:

```text
KernelClaimTombstoneAbandoned {
  node_boot_id
  claim_slot_id
  proof_id
  task_cookie
  exec_attempt_id
  claimed_boottime_ns
  state: CLAIMING | COMMITTED | EXEC_FAILED | TASK_EXITED
  wal_acknowledged: bool
}
```

The retained item 5 and tombstone enum use the obsolete shorthand `CLAIMED`/
`COMMITTED`. The exact durable records use
`PENDING -> CLAIMING -> CLAIM_BOUND_PROVISIONAL -> EXEC_COMMITTED`, with
terminal `EXEC_FAILED|EXPIRED|CANCELLED|TASK_EXITED` as applicable. A WAL
record names the exact transition; `CLAIM_BOUND_PROVISIONAL` is durable but
does not authorize ordinary user effects, and only `EXEC_COMMITTED` projects
to product-level admission `COMMITTED`. No decoder accepts the obsolete enum
as an alias because that would make crash recovery unable to distinguish a
provisional claim from a committed image.

The canonical pinned record is:

```text
KernelClaimTombstoneV1 {
  node_boot_id: Id128
  label_epoch: u64
  claim_slot_id: Id128
  proof_id: Id128
  task_cookie: u64
  process_state_id: Id128
  entry_instance_id: Id128
  exec_attempt_id: Id128
  claimed_boottime_ns: u64
  transition_sequence: u64
  state: CLAIMING | CLAIM_BOUND_PROVISIONAL | EXEC_COMMITTED |
         EXEC_FAILED | EXPIRED | CANCELLED | TASK_EXITED
  owned_ref_bits: u64
  wal_acknowledged_through_sequence: u64
}
```

`owned_ref_bits` is the idempotent-release oracle for the entry, generation,
process, and authority-domain references named by the prepared transaction.
Recovery releases only a bit observed as owned and clears that bit in the same
owner-specific transition. It never infers ownership from a missing event.

The BPF claim CAS must insert/update this preallocated pinned record before it
installs authority. Map-capacity failure denies the claim. Event emission is
best effort and cannot remove the tombstone. Rust reads the map, appends the
transition to WAL, marks `wal_acknowledged`, and deletes only after the replay
tombstone retention deadline **and** the corresponding
`EntrySecurityStateV1.lifetime_state=COMPLETE`, whichever occurs later. The
hot path uses the committed entry state rather than this tombstone, but the
tombstone remains the claim/replay recovery oracle for the full entry lineage.
On daemon restart, admission stays closed while
map entries are reconciled into WAL. A node reboot changes `node_boot_id`, so
old node-targeted proofs cannot be claimed even if central delivery retries.

##### Abandoned design: synchronous disk I/O from a BPF claim hook

Reading “durably record every transition” as blocking `bprm_check_security` on
Rust/disk contradicts the local-decision and performance contract and is
abandoned. Durability is the two-stage WAL-plus-pinned-map protocol above.

**Crash tests.** Kill `mithril-node` after the BPF CAS but before ring emission;
restart must recover the claim from the pinned map and no second task may claim
the slot. Repeat after the task exits but before WAL acknowledgement; the
tombstone remains sufficient to reject replay until reconciled.

The required target fields depend on intent kind:

| Intent kind | Required subject and declared-intent fields | Claim point |
| --- | --- | --- |
| `runtime_entry` | tenant/trust domain, cluster UID, node boot ID, Pod UID, full container ID, cgroup binding ID, runtime lifecycle generation, operation, immutable definition/PodSpec digest, command digest when a command exists, target role | Runtime-held task or exact external-root pre-exec claim |
| `native_transition` | node boot ID, execution-set ID, process-lineage ID, source execution ID, operation, immutable executable/action digest, source and target role | Fork/exec transition of that already-labeled lineage |
| `authority_lease` | execution-set or CI job ID plus process-lineage/step binding when claimed as step-exact, provider, account/project, audience, requested permission set, maximum TTL, issuer subject, unique lease-request nonce | Before the broker/identity exchange; provider result completes the lease |
| `artifact_handoff` | producer run/execution, consumer run/execution, immutable artifact digest, artifact type, producer trust class, permitted consumption operation | Restore/open/execute transition for that exact digest |
| `provider_operation` | provider, account/tenant, principal or lease, canonical operation, resource selector, request nonce, result boundary, maximum TTL | Synchronous semantic gate only; audit cannot consume a pre-effect claim |

An adapter cannot omit a required field because its vendor API lacks it. It
must report that proof class as unsupported and emit a weaker contextual
observation. Optional fields in the earlier logical sketch mean “optional for
some intent kinds,” not “optional when required by this matrix.”

##### Abandoned design: issuer-selected failure posture and reusable claims

The earlier `disposition_on_mismatch`, `disposition_on_expiry`, and
`allowed_claim_count` fields are unsafe if read literally. A compromised or
over-permissive issuer could ask Mithril to fail open, or one intercepted proof
could be raced repeatedly. That interpretation is abandoned.

- Version 1 requires `disposition_on_mismatch` and
  `disposition_on_expiry` to be absent. The locally installed signed workload
  policy alone chooses `allow`, `alert`, `deny`, or `reject` for invalid proof.
- Version 1 requires one proof to contain explicit `claim_slot_ids[]`. Each
  slot is independently one-use, target-identical, and rate-limited by local
  policy. The envelope's legacy `allowed_claim_count` is accepted only when it
  equals the number of explicit slots and is capped by the locally compiled
  maximum; otherwise validation fails.
- An issuer that needs three legitimate identical probes sends three slot IDs.
  Three concurrent claimants race separate slots; a fourth has no slot and is
  rejected. No counter is decremented optimistically in userspace.

**Practical replay test.** Proof sequence 12 contains slots `A`, `B`, and `C`.
Three exact probe roots claim them concurrently. A fourth root is rejected.
After node-process restart, replaying sequence 12 or any slot is rejected from
the restored WAL. Sequence 11 arriving afterward is accepted only if it is
inside the configured window and its proof/slots were never seen; sequence
`12 - 4096` is always too old.

Secrets, OAuth authorization codes, bearer tokens, and cloud secret keys are
not stored in this envelope. It contains stable public identifiers, digests,
lease IDs, audiences, and provider request/session identifiers when available.

##### Four ways an intent proof is consumed

| Intended action | Linux/runtime shape | Mithril object created | Practical example |
| --- | --- | --- | --- |
| Runtime creates a process with no labeled native parent | External root | `EntryInstance` | kubelet exec probe, `kubectl exec`, Docker container action, Tekton step container |
| A labeled runner or worker forks/execs a child | Native child or exec transition | `TransitionIntent`, consumed by the already-labeled lineage | GitHub Actions `run:` shell step, Jenkins `sh`, approved worker helper |
| A process obtains or activates credentials | Usually no new root beyond the CLI process | `AuthorityLeaseIntent` bound to a task/process lineage and provider identity | AWS SSO login, STS web-identity exchange, Google Workload Identity Federation, GitHub job token |
| One job publishes data consumed by another job or node | No Linux parent relation | `ArtifactHandoffIntent` plus typed causal edge | CI artifact, cache entry, image digest, deployment manifest, queue message |

This corrects a tempting but wrong model: **not every coordinator action is an
entry**. If a GitHub runner forks a shell for a step, the shell is a native
descendant and must retain that physical parent edge. The signed step intent
authorizes a role transition. If the runner asks Docker to start a container
action, that container root needs an entry admission. If a later job downloads
the first job's artifact, the relationship is an artifact edge, never a native
parent.

##### Concrete consumed-intent objects and state machines

The four names in the table are normative Version 1 records, not conceptual
placeholders:

```text
TransitionIntentV1 {
  transition_intent_id
  proof_id
  claim_slot_id
  node_boot_id
  execution_set_id
  source_process_lineage_id
  source_execution_id
  operation: FORK | EXEC | PRIVILEGE_TRANSITION
  candidate_executable_object?
  canonical_argv_digest?
  requested_target_role
  deadline_boottime_ns
  state: PENDING | CLAIMING | COMMITTED | DENIED | EXPIRED | CANCELLED
}

AuthorityLeaseIntentV1 {
  authority_intent_id
  proof_id
  claim_slot_id
  local_owner: exact process lineage or exact CI job/step subject
  provider
  provider_account_or_project
  issuer_subject
  audience
  requested_permission_set
  requested_resource_scope
  maximum_ttl
  provider_request_nonce
  state: PENDING | REQUESTING | ISSUED | DENIED | FAILED | EXPIRED | CANCELLED
}

CredentialLeaseV1 {
  credential_lease_id
  authority_intent_id
  provider
  provider_credential_type
  public_session_or_access_key_identifier
  exact_provider_principal
  exact_resource_and_permission_scope_when_proven
  issued_at
  expires_at
  local_owner_binding_quality
  provider_request_and_result_evidence_ids[]
  secret_material: NEVER_STORED
  state: ACTIVE | EXPIRED | REVOKE_REQUESTED | REVOKED | UNKNOWN
}

ArtifactHandoffIntentV1 {
  handoff_intent_id
  proof_id
  producer_subject_id
  consumer_subject_id
  artifact_kind
  immutable_digest
  producer_trust_class
  permitted_consumer_operation: READ_AS_DATA | VERIFY | LOAD | EXECUTE |
                                DEPLOY
  required_attestation_ids[]
  deadline
  state: PENDING | PUBLISHED | CLAIMED | VERIFIED | REJECTED | EXPIRED
}
```

Every state transition is durable and idempotent. A provider response moves
an authority intent to `ISSUED` and creates a lease only when response identity,
scope, audience, nonce, and TTL are compatible; otherwise it is `FAILED` and
the unmatched response is separate evidence. An artifact `READ_AS_DATA` claim
does not authorize `EXECUTE`: execution consumes a separately permitted
operation or is denied.

**Practical examples.** An approved `aws` process claims an authority intent,
but STS returns a different role ARN; no `CredentialLease` is created and the
response is a provider mismatch finding. A build job restores digest D with
`READ_AS_DATA`, then `dlopen`s D; the file/mmap transition requests `LOAD` and
is rejected because the handoff never authorized it.

##### Credential material versus a protected actuator handle

`secret_material: NEVER_STORED` means never stored in observations, findings,
graphs, WAL, logs, or central analytics. It does not magically make a
provider's possessed-token revocation endpoint usable. When an approved broker
must later revoke the exact bearer token, it may retain a short-lived
`ProtectedCredentialHandleV1` in a separate node/vault boundary:

```text
ProtectedCredentialHandleV1 {
  handle_id
  credential_lease_id
  encrypted_or_nonexportable_provider_secret_reference
  permitted_operations: [REVOKE_SELF]
  expires_at
  never_serialized_to_evidence: true
}
```

Only the broker and typed actuator can dereference it; evidence contains the
opaque handle ID. If no such handle is retained, Mithril must use a broader
provider response or wait for expiry. A public token fingerprint/hash is a
correlation key, not secret material and not automatically a revocation
credential.

`ArtifactHandoffIntentV1`'s singular consumer fields are a logical shorthand.
Fan-out uses an immutable artifact instance plus independent one-use consumer
slots:

```text
ArtifactInstanceV1 {
  artifact_instance_id
  provider_artifact_id_and_version
  producer_subject_id
  producer_trust_class
  immutable_digest
  byte_length
  media_type
  source_material_ids[]
  storage_observation_ids[]
  attestation_verification_ids[]
  state: PUBLISHED | QUARANTINED | EXPIRED
}

ArtifactConsumerSlotV1 {
  slot_id
  artifact_instance_id
  exact_consumer_subject_id
  permitted_operation
  deadline
  state: PENDING | CLAIMED | COMPLETED | REJECTED | EXPIRED
}

AttestationVerificationV1 {
  attestation_digest
  predicate_type_and_version
  signer_identity_and_trust_root
  builder_identity
  subject_digests[]
  material_digests[]
  source_repository_and_revision?
  verifier_policy_digest
  result: VALID_AND_POLICY_MATCHED | VALID_BUT_POLICY_MISMATCH |
          INVALID | UNKNOWN
}
```

A valid signature proves the signer made the statement, not that the producer
was trusted or the bytes are safe. Each fan-out consumer claims its own slot.
Artifact names/cache keys are display/index fields and never replace provider
version plus digest.

From verification to `LOAD|EXECUTE|DEPLOY`, the consumed file must remain the
same object/bytes: use fs-verity/IMA/sealed immutable storage where qualified,
or hold the exact fd/object and revalidate digest/version before the protected
transition. A mutable workspace copy without this continuity loses verified
status.

**Artifact tests.** Poison a cache under the expected key, publish the same
name with a different digest, fan one digest to three jobs, mutate bytes after
verification, and present a valid attestation from a trusted signer whose
declared producer is untrusted. Every consumer remains independent; only exact
bytes with a policy-matched attestation can reach the requested privileged
operation.

##### Proof-strength and use matrix

| Proof | Strength when verified | What it may authorize | What it cannot prove alone |
| --- | --- | --- | --- |
| Signed pre-exec coordinator assertion with one-use nonce, immutable definition digest, exact target, and short TTL | Exact for the asserted coordinator intent | Entry admission, native transition, or credential-lease request | That the resulting provider operation later succeeded |
| Provider-signed OIDC token with issuer, audience, subject, token ID, run/job/ref claims, and expiry | Exact for the claims the provider actually signed | A job-level authority exchange whose trust policy matches those claims | A particular shell command or step when the token has no step claim |
| Provider issuance record with exact request/session/access-key/lease identity | Exact for credential issuance | Bind the authority lease and later provider audit operations | Which local task requested it unless joined through a broker, nonce, or exact coordinator proof |
| Kubernetes, cloud, source-control, mesh, or connector audit after completion | Exact for fields and result supplied by that authority | Finding, causal edge, response eligibility | Retroactive local prevention of an operation that already succeeded |
| Measured runner/kubelet event without a carried nonce | Strong or conservative depending uniqueness and source measurement | Same-budget classification when every remaining candidate is equally restrictive | Exact selection among concurrent identical requests with unequal authority |
| Command, process name, timestamp, cadence, label, or destination alone | Contextual | Candidate matching and operator explanation | Intent, caller authority, or an allow decision |

##### Correction: `Strong` is not a proof class

The retained capitalized `Strong` and later prose “strong mapping/evidence” are
non-normative adjectives and are abandoned as decision inputs. The measured
event row compiles to explicit `ProofQualityV1` axes—normally
`AUTHENTICATED_MEASUREMENT` source authority plus its actually proven local
binding—and intent classification `SAME_BUDGET_AMBIGUOUS` when no carried nonce
exists. Rules match those axes, never the word `strong`.

`mithril-node` verifies an intent proof as follows:

```text
verify_and_stage_intent(envelope, live_context):
    verify issuer key, signature, key validity, and revocation state
    verify node boot/cluster/tenant and profile trust domain
    reject expired, future, replayed, or non-monotonic proof
    resolve immutable workflow/manifest/image/command digests
    resolve exact live Pod/container/cgroup or labeled process lineage
    verify actor, trigger trust class, approval, and requested authority
    ensure requested role/effects are a subset of signed policy
    ensure claim count, concurrency, rate, and lifetime budgets remain

    if any required field is missing or conflicts:
        apply configured mismatch disposition; never silently widen

    stage one of EntryIntent, TransitionIntent, AuthorityLeaseIntent,
    or ArtifactHandoffIntent with a one-use claim key
```

The kernel remains the final task binder. A valid proof for job 55 cannot be
claimed by job 56, a different cgroup, a native child with an existing label,
or the same task after expiry. The userspace assertion supplies purpose; live
kernel identity supplies the process that will exercise it.

#### Kubernetes kubelet-to-task proof

##### Practical kubelet-probe proof

The stock CRI gap remains real: `ExecSyncRequest` does not carry “readiness,”
“liveness,” `PostStart`, or `PreStop`. Mithril can close it with an optional
authenticated kubelet-side channel:

1. Immediately before invoking the runtime, measured kubelet integration
   emits a signed proof containing Pod UID/resource version, full container
   ID, lifecycle generation, exact probe or hook field, canonical command
   digest, monotonic sequence, deadline, and one-use nonce.
2. The local CRI admission path observes the corresponding `ExecSync` and
   supplies its authenticated peer, container, command, and request order.
3. `mithril-node` requires the two records to agree and stages the exact
   `KubeletExecProbeEntry`, `KubeletPostStartEntry`, or
   `KubeletPreStopEntry`.
4. The runtime-held pidfd root or exact `bprm_check_security` claimant consumes
   the proof before the executable image begins.
5. A duplicate, expired, wrong-command, wrong-container, wrong-lifecycle, or
   already-claimed proof follows the configured rejection action.

For exact classification under concurrent identical `ExecSync` requests, the
nonce must travel through a measured kubelet/runtime extension or the
integration must hold and bind the exact task. Merely correlating two identical
commands by time is not exact. If no nonce can be carried, same-budget
conservative classification remains valid; unequal budgets remain ambiguous
and default to rejection in protect mode.

##### Selected production kubelet-to-task implementation

“Optional authenticated kubelet-side channel” is not a build instruction by
itself. Version 1 selects a maintained kubelet **and** runtime integration for
exact probe/lifecycle classification; stock CRI remains an explicitly reduced
tier.

At kubelet's exec-probe and exec-lifecycle call sites, immediately before the
existing `RunInContainer` operation, the maintained patch sends
`KubeletExecutionRequestV1` to `mithril-node` over a root-owned Unix socket:

```text
KubeletExecutionRequestV1 {
  kubelet_instance_id
  kubelet_build_and_config_digest
  pod_uid
  pod_resource_version
  full_container_id
  container_spec_digest
  lifecycle_generation
  reason: STARTUP_PROBE | READINESS_PROBE | LIVENESS_PROBE |
          POST_START_EXEC | PRE_STOP_EXEC
  podspec_field_path
  canonical_argv_digest
  timeout_ns
  kubelet_monotonic_sequence
}
```

`mithril-node` authenticates the peer, resolves the live Pod/container/spec,
and returns a signed one-use `KubeletExecutionTicket`. The patched kubelet
uses a local `RunInContainerWithMithrilTicket` runtime extension instead of
dropping the ticket into a timing side channel. The runtime/shim passes the
ticket to the exact child-creation path, creates that child behind the
held-task barrier defined above, and returns its pidfd plus ticket nonce to
`mithril-node`. Mithril resolves and labels the stopped task, reads the label
back, consumes the ticket, and acknowledges resume. Only then may the runtime
execute the command. Result/timeout flows back with the same ticket ID.

This integration changes node control-plane components, not the PodSpec,
container image, application process model, or number of workload jobs. It is
therefore compatible with the unchanged-workload requirement. The patch is a
small maintained call-site/transport change; the one existing `mithril-node`
binary still owns policy, maps, events, and WAL.

| Kubelet/runtime combination | Honest capability |
| --- | --- |
| Stock kubelet + stock CRI/runtime | No exact reason transport; identical operations may use one compiled same-budget class or reject |
| Patched kubelet + stock CRI/runtime | Authenticated reason exists but cannot be bound to one of concurrent identical runtime children; contextual/same-budget only |
| Stock kubelet + patched runtime | Exact task can be held, but probe versus lifecycle purpose is absent; same-budget or reject |
| Patched kubelet + ticket-aware runtime/shim | `EXACT_INTENT_AND_TASK` after held-task label readback |
| Direct `crictl ExecSync` | No kubelet ticket; `HostAdministrativeExecEntry` or reject, never a probe/hook role |
| Version/build/config mismatch on either patch | Capability becomes unavailable before request; strict distinct-budget request rejects rather than silently using time correlation |

Every supported tuple `(kubelet build/config, CRI API, runtime, shim, Mithril
adapter, kernel)` is named in `PlatformSupportManifestV1`. Rolling upgrade
allows exact mode only where both endpoints advertise a compatible ticket
protocol; mixed-version nodes use the configured reduced tier.

**Exactness test.** In `ENTRY-KUBELET-TICKET-001`, readiness, liveness,
`PostStart`, `PreStop`, and direct `crictl ExecSync` all request identical argv
concurrently. The fixture reverses runtime child-creation order. Each carried
ticket must bind to its own held pidfd and role; the `crictl` process must not
claim any ticket. Duplicate, dropped, swapped, expired, and post-restart
tickets reject. Running the same fixture against stock CRI may pass only the
identical-budget expectation; it must never produce exact reason attribution.

##### Abandoned design: signed side-channel timing proves exact kubelet intent

A signed event establishes what kubelet intended to request, but request
ordering, argv, cgroup, and timestamp do not select one of two concurrent
identical children. That earlier interpretation is abandoned. Exactness needs
the carried ticket plus held-task binding above; without it, policy compiles to
same-budget ambiguity or rejection.

#### Cloud authority-lease proof

##### Practical AWS CLI login and session mapping

Observing `aws sso login` proves only that a process executed that CLI command.
It does not prove that the login was approved or which later AWS session belongs
to the process. A strong mapping is:

```text
approved human or CI intent
  -> AuthorityLeaseIntent(provider=aws, account, role/permission-set,
                          target lineage, TTL, approval/run identity)
  -> exact labeled `aws` process performs browser/device/OIDC exchange
  -> provider issuance/audit supplies session/access-key identifier
  -> CredentialLease(lease_id, provider_session_id, source_identity,
                     owning process lineage, expires_at)
  -> CloudTrail operations join by exact session/access-key/source identity
```

The policy separately controls:

- exec of the measured AWS CLI object;
- access to `~/.aws/config`, `~/.aws/sso/cache`, `~/.aws/login/cache`, or an
  approved `credential_process` endpoint;
- network access to the expected identity and AWS API destinations;
- requested account, role, audience, source identity, session tags, and TTL;
- which descendant roles may use the resulting lease; and
- provider operations allowed for that session.

AWS CLI SSO caches an authentication token under `~/.aws/sso/cache`; newer
interactive AWS login also uses a local cache. A shared cache read is therefore
not a unique provider-session proof. Exact task-to-session binding requires a
credential broker/process provider that can carry the Mithril lease nonce, or
provider issuance fields such as source identity/session name/tags that are
cryptographically tied to the approved coordinator identity. Without that,
Mithril records a strong local login lineage and provider session evidence but
marks their join conservative or contextual rather than inventing certainty.

No TLS interception is required. AWS STS/IAM and CloudTrail provide semantic
session and operation evidence; the local kernel provides the task and socket
identity.

##### Practical `gcloud`/`gsutil` and Google workload-identity mapping

`gcloud auth login` can store user credentials in the Cloud CLI configuration,
and `gcloud auth login --cred-file` supports external-account configurations.
`gsutil` can use the same authenticated Cloud CLI or workload identity. The
binary name still does not prove purpose.

For CI, the preferred exact path is:

1. GitHub Actions, GitLab, or another coordinator issues a signed OIDC token
   containing its run/job/repository/ref claims and unique token ID.
2. A signed `AuthorityLeaseIntent` binds the expected issuer, audience, job,
   immutable workflow definition, target Google project/service account,
   scope, and lifetime to the exact CI task lineage.
3. Google Security Token Service validates the OIDC token and returns a
   federated credential, optionally followed by service-account
   impersonation.
4. Google audit identifies the federated principal or impersonated service
   account and operation. Mithril joins it to the job proof through the signed
   subject/audience/token ID and provider request/lease evidence available.
5. A `gsutil cp`, `gcloud storage cp`, client library, or raw HTTPS client all
   receive the same authority decision because policy follows the lease and
   provider operation, not the CLI filename.

##### Abandoned design: assuming Google audit carries the source OIDC `jti`

Step 4 is exact only for fields the configured Google service actually logs.
Google WIF audit commonly identifies the mapped federated
`principalSubject`; it does not make the source GitHub/GitLab token ID a
universal downstream audit join. Service-account impersonation and downstream
services can also differ in whether delegation identity is preserved. Treating
the source `jti` as always present is abandoned.

For job-exact GitHub WIF, the deployment maps an immutable job identifier such
as `check_run_id` (plus tenant/repository constraints) into `google.subject`,
enforces the corresponding attribute condition, enables the required STS/IAM
and downstream Data Access audit, and qualifies each service's principal and
delegation fields. `AuthorityLeaseIntent` records the exact mapping and broker
request. If downstream audit exposes only a shared service account, the
operation is authoritative for that account but the local-job join is
contextual.

**WIF test.** Two GitHub jobs in one `run_id` have distinct check-run IDs and
request the same service account. With subject mapping and complete service
audit, operations remain separate. Remove the mapped subject/delegation field
from the downstream service fixture: both operations downgrade to shared-SA
contextual binding and exact-job automatic response becomes ineligible.

For a human browser login with persistent cached credentials, use a human
approval proof scoped to the administrative session and classify every cache
read. If the provider flow exposes no bindable nonce/session identifier, the
join to later provider operations is weaker and automatic narrow response is
ineligible until the exact principal/session is resolved.

##### Non-negotiable limitation

An intent channel can prove what a trusted issuer asked for. It cannot make a
compromised issuer truthful. If kubelet, the CI coordinator, its signing key,
or the cloud identity provider is controlled by the attacker, the assertion is
inside the compromised authority boundary. Mithril still applies product hard
invariants and role/effect limits, records issuer identity, and requires an
independent provider/kernel postcondition where configured, but it cannot
cryptographically recover honest intent from a dishonest trust root.

#### ExecSync classification algorithm

```text
classify_exec_sync(intent, pod_spec, container_state):
    candidates = []

    for each declared exec startup/liveness/readiness probe:
        if canonical_command matches intent.command:
            add candidate(kind=probe type,
                          allowed_state=running and probe schedule eligible)

    for postStart exec:
        if command matches and lifecycle generation is starting:
            add candidate(kind=postStart)

    for preStop exec:
        if command matches and lifecycle generation is terminating:
            add candidate(kind=preStop)

    discard candidates with wrong Pod resource version, container ID,
    lifecycle generation, command, deadline, or multiplicity budget

    if authenticated kubelet reason exists and exactly matches a candidate:
        classification = exact
    else if all remaining candidates compile to the same target role and
            identical effect budget:
        classification = conservative
    else if no candidate remains:
        deny as undeclared runtime exec
    else:
        classification = ambiguous
        apply profile's ambiguity action, default deny in protect mode
```

Timing is supporting evidence, never the sole proof. A command that happens to
run every ten seconds does not become a liveness probe. Matching a declared
command does not authorize a different caller. Kubelet restarts and the
at-least-once hook contract are handled with idempotency keys and bounded
multiplicity, not a single expected timestamp.

When unmodified CRI cannot distinguish two declarations and their effect
budgets differ, only three honest choices exist:

- deny the ambiguous entry;
- compile the explicitly approved union of both budgets and mark the entry
  `conservative`; or
- install an authenticated kubelet/runtime reason extension.

Mithril must not pop an arbitrary pending intent and label the task with a more
powerful role.

##### Abandoned design: calling an unequal-budget union conservative

The phrase “compile the explicitly approved union ... and mark the entry
`conservative`” above is mathematically and operationally wrong. A union is
more permissive than either candidate, not conservative. The text is retained
to make the rejected option visible, but that classification is abandoned.

The normative ambiguity outcomes are:

| Candidate budgets | Automatic result | Classification |
| --- | --- | --- |
| Byte-for-byte identical compiled budget and lifetime | Admit the shared role/budget | `same_budget_ambiguous`; safe for effects, not exact lifecycle provenance |
| Unequal budgets, strict protect mode | Reject the entry | `ambiguous_rejected` |
| Unequal budgets, operator explicitly chooses the intersection | Admit only after simulation shows the legitimate action still works | `intersection_degraded`; may reduce availability |
| Unequal budgets, operator explicitly chooses the union | Admit only as an exception naming both roles, approver, TTL, and authority delta | `merged_broad_budget`; excluded from full-support/exact claims |

**Practical example.** `/app/check` is both a readiness probe that may read
`/run/healthy` and a `PreStop` hook that may send to `/drain`. Their union would
let every readiness invocation contact the drain endpoint and every shutdown
invocation obtain the health-file right. Mithril defaults to rejection. If the
operator chooses the intersection, neither special effect is granted and the
simulation will likely show both actions failing. The real fix is a carried
reason nonce or distinct reviewed commands—not calling the union safe.

#### Pending-intent claim algorithm

The pidfd handshake is preferred. The fallback for a runtime that cannot
provide the task before exec is an atomic claim at `bprm_check_security`:

```text
claim_external_entry_or_deny(binding, candidate_file, argv):
    assert current task has no label
    assert binding is protected and live

    candidate_key = bounded_exec_classifier(candidate_file, argv)
    pending_key = (binding.id, binding.lifecycle_generation, candidate_key)
    intents = pending_entry_map[pending_key]

    choose only an unexpired intent whose role/effect budget is unique
    atomically change PENDING -> CLAIMING with current task cookie and
             exec_attempt_id; do not grant the target role yet
    reject stale generation, duplicate claim, exhausted multiplicity,
           wrong binary object, or ambiguous target role

    install external-root TaskLabel before continuing exec evaluation
    emit entry_started_execution separately
```

An attacker-created native child cannot claim an external intent because it
already carries its inherited task label. An unlabeled task manually moved
into the cgroup cannot claim without a live authenticated intent. A host-root
attacker who can modify the runtime, BPF maps, or Mithril process is outside
this node trust boundary and must be handled by host integrity controls.

The prototype must prove that the selected BPF hooks can safely parse the
bounded executable/argv material and create task storage. If not, the fallback
is not promoted; full support requires the runtime-held pidfd path.

##### Provisional external-root role and final promotion

The phrase “install external-root `TaskLabel`” must not mean assigning the
final application/probe/administrative role during the first
`bprm_check_security`. Exec can fail, and a script can cause more interpreter
checks. The root first receives `ENTRY_PROVISIONAL`, which permits only the
exact loader/interpreter objects needed for this staged exec and denies normal
file, network, device, privilege, and child-creation effects.

###### Abandoned design: a three-state claim promotion

The next diagram is retained because it explains why a provisional role is
needed, but `COMMITTED` and `COMPLETED` are obsolete collapsed names. It is not
the kernel ABI; `KernelClaimTombstoneV1` and
`PreparedExternalRootStateV1` below are authoritative.

```text
pending slot PENDING
  -> CLAIMING(task_cookie, exec_attempt_id, provisional_role)
  -> COMMITTED(final_execution_id, target_role)   # synchronous exec commit
  -> COMPLETED                                    # task later exits

CLAIMING -> EXEC_FAILED | DENIED | CANCELLED      # terminal; slot not reusable
```

###### Correction: one claim transaction installs every authoritative state

The retained claim algorithm says “CAS the slot” and “install `TaskLabel`” but
omits `ProcessSecurityStateV1`, `AuthorityDomainStateV1`, entry/generation/
domain references, the kernel tombstone, and partial-failure ordering. That is
not implementable as strict admission. Version 1 uses one preallocated claim
transaction:

```text
PreparedExternalRootStateV1 {          // built/read back before slot exposure
  claim_slot_id
  immutable_task_label_template
  process_state_id                     // PREPARING, provisional deny set
  authority_domain_id                  // ACTIVE; existing or prebuilt new
  entry_instance_id
  active_profile_generation_ref_id
  generation_ref_slot
  entry_task_ref_slot
  domain_pending_ref_slot
  kernel_claim_tombstone_slot
  expected_binding/candidate/attempt digests
  prepared_immutable_fields_digest
  expected_claim_bound_state_digest
  state: PREPARING | EXPOSED | CLAIMING | CLAIM_BOUND_PROVISIONAL |
         EXEC_COMMITTED | TERMINAL_FAILED | RECONCILING
}
```

Userspace completely creates the inactive/preallocated records. If the entry
needs a new authority domain, userspace builds it under a pending/binding
reference, reads it back, and transitions it `PREPARING -> ACTIVE` **before**
exposing any claimant; a process may never become active while pointing to a
`PREPARING` domain. It then durably accepts the signed proof and publishes the
claim slot as `PENDING`. The `bprm` claim program performs bounded operations
in this order:

1. validate current boot/epoch, live binding/nonce, candidate object/attempt,
   prepared immutable digest, sole-thread claimant shape, exact `EXPOSED`
   state, and an `ACTIVE` domain held by its pending/binding reference;
2. allocate the current task's non-reused `task_cookie`, then CAS slot
   `PENDING -> CLAIMING(task_cookie, exec_attempt_id)`; only the CAS winner may
   reference this slot's preallocated process/domain state;
3. install `TaskLabelV1` pointing to the winner's unique process state,
   whose effective budget is fail-closed `ENTRY_PROVISIONAL`; if installation
   fails, the task remains unlabeled inside a protected binding and this same
   synchronous hook returns denial;
4. write/read the preallocated `KernelClaimTombstoneV1` before any target
   authority is active;
5. idempotently acquire the entry-task and retained-generation refs, convert
   the domain's pending ref to one live-process ref when this is a new process,
   and record each owned bit in prepared state;
6. transition the existing process-state value from `PREPARING` to `ACTIVE`
   with provisional role/profile/domain IDs and incremented version;
7. re-read label, process, domain, binding, generation refs and tombstone;
   revalidate `prepared_immutable_fields_digest`, compare the current bounded
   state to `expected_claim_bound_state_digest`, then set slot/prepared state
   `CLAIM_BOUND_PROVISIONAL`;
8. only now return allow for the exact loader/interpreter budget. The exec
   transaction later commits the final role through `ProcessSecurityStateV1`.

No step allocates an unbounded map or waits for disk. CAS happens before label
installation so two contenders can never point at the same preallocated
process state. A failure after CAS returns the hook-specific denial and
terminalizes the slot. Before label installation, ordinary protected-unlabeled
policy denies every effect; after installation, `ENTRY_PROVISIONAL` does. The
runtime reaps the stub and idempotent `task_free`/Rust reconciliation releases
only owned ref bits. A failure before CAS grants nothing and may leave the slot
pending only when the program proves no claim mutation occurred.

`CLAIM_BOUND_PROVISIONAL` means claim identity/state is durable but no user
image has executed. Only the qualified successful-exec observer changes it to
`EXEC_COMMITTED(final_execution_id,target_role)`; a pre-PONR failure becomes
terminal `EXEC_FAILED`, and no `entry_started_execution` event exists. This
distinction is required for restart recovery.

Version 1 fallback admits only a sole-task runtime stub at claim time. If the
thread group already has siblings, or a runtime creates bootstrap/nsexec tasks
whose shared state is not covered by the one slot, the fallback rejects and
requires the held-task integration to label the full setup set.

`ENTRY-CLAIM-TRANSACTION-004` injects failure after every numbered operation,
including ref overflow, tombstone/map loss, readback mismatch, duplicate task,
two contenders paused before/after CAS, daemon crash and task exit. In every
run at most one task owns or references the slot state; the loser remains
unlabeled/fail-closed and never observes the winner's committed role; no
user marker or protected effect runs; refs return to their exact starting
counts; and restart reconciliation rejects replay. This fixture is required
for the fallback and held-task paths because both must produce the same
authoritative hot-path state.

The bprm fallback is platform-qualified only when a per-runtime trace proves
the exact claimant reaches the bound cgroup before its first bprm and performs
no protected effect after placement but before claim. Fixtures cover runtime
setup clones, `CLONE_INTO_CGROUP`/move timing, `setns`, credential/capability
changes, `chdir`, seccomp installation and final bprm for every supported
runtime version. If setup needs an effect in that interval, Mithril must use
the earlier held-task path with a narrow runtime-exec-setup role; a bprm-only
fallback is `UNSUPPORTED`, not silently availability-breaking.

The successful kernel exec-commit atomically replaces the provisional role
with the target role. If any executable/interpreter check fails, the task
retains the fail-closed provisional role and the slot becomes terminal; the
runtime is expected to return the exec error and reap the stub. A failed exec
must never leave a runtime helper holding application authority.

##### Abandoned design: exact attribution from an identical pending-candidate key

Keying only by binding, lifecycle, executable, and argv cannot distinguish two
concurrent identical `pods/exec` requests. Either process could claim either
actor's slot. That is safe only when all candidate roles/effect budgets are
identical, and even then actor/request attribution is not exact.

Exact claim requires one of:

- a runtime-held pidfd/task associated with the authenticated request;
- an opaque stream/entry ticket carried through the runtime creation seam; or
- another target-kernel-proven per-request value inaccessible to competing
  workload tasks.

Without one, the classifier may return `SAME_BUDGET_AMBIGUOUS`; it stores all
candidate actor/request IDs and creates no exact actor-to-task edge. Unequal
budgets reject. A pending-map compare-and-swap alone prevents double use but
does not prove that the right identical process won.

**Concurrency test.** Two administrators issue the same command to the same
container at once, one read-only and one break-glass. With no carried ticket,
both roots are rejected because budgets differ. With runtime-held pidfds,
each root receives the correct role and audit actor even when task creation
order is reversed.

#### Shutdown and containment interaction

Policy is retained until the runtime confirms exit and a BPF task/cgroup
reconciliation proves no live member remains. `StopContainer` and Pod deletion
change lifecycle state; they do not delete enforcement maps.

When a lineage is contained:

- new ordinary external entries are denied;
- declared `preStop` is not automatically allowed;
- a profile may authorize a narrow shutdown role with exact file/socket
  effects and a deadline;
- if that cleanup role could re-open the attack path, containment wins and the
  hook fails;
- cgroup freeze or kill is a separate typed response with its own approval;
- kubelet/controller replacement is watched and constrained separately.

<a id="part-iv-enforcement"></a>

## Part IV — Policy Compilation And Local Enforcement

### Policy Package And Compiler

#### Source policy object

```text
WorkloadProtectionProfile {
  profile_id
  version
  schema_version
  issuer
  signature
  valid_from, valid_until?
  selectors
  required_capabilities
  default_postures
  entry_rules[]
  roles[]
  transition_rules[]
  effect_rules[]
  dynamic_state_rules[]
  authority_behavior_rules[]
  correlation_packages[]
  response_rules[]
  coverage_requirements[]
  rollout
}
```

Selectors find candidate workloads in userspace. They do not become kernel
authority. The binder resolves a selector to an exact Pod UID, full container
ID, immutable image digest, cgroup live interval, and profile generation.

##### Normative signed-profile format and anti-rollback state

The source object above is a logical model. The signed object is
`SignedWorkloadProtectionProfileV1`, using the same deterministic-CBOR and
trust-bundle rules as `SignedIntentV1`, but with domain separator
`MITHRIL-PROFILE-V1`. The signature covers every selector, default, rule,
capability requirement, rollout field, exception, issuer sequence, and
validity bound. Unsigned YAML comments and key ordering carry no semantics.

```text
ProfileSignatureHeaderV1 {
  schema_version: 1
  issuer_id
  issuer_key_id
  issuer_sequence: u64
  trust_domain_id
  profile_id
  profile_version: u64
  valid_from_utc
  valid_until_utc?
  rollback_authorization_id?
}
```

###### Correction: signed profile and rollback envelopes are closed wire types

The retained text names `SignedWorkloadProtectionProfileV1` and
`RollbackAuthorizationV1` without defining their bytes. The normative forms
reuse the integer-keyed deterministic-CBOR primitives and Ed25519 algorithm
from `SignedIntentV1`:

```text
ProfileSignatureHeaderV1 = {
  0: 1,                         // header schema
  1: Id128 issuer_id,
  2: u64_nonzero sequence_epoch,
  3: u64_nonzero issuer_sequence,
  4: Id128 trust_domain_id,
  5: Id128 profile_id,
  6: u64_nonzero profile_version,
  7: i64 valid_from_utc_ns,
  8?: i64 valid_until_utc_ns,
  9?: Id128 rollback_authorization_id,
  10: DigestV1 policy_document_digest,
  11: DigestV1 provider_numeric_registry_bundle_digest,
  12: DigestV1 required_capability_schema_digest,
  13: DigestV1 source_selector_registry_digest,
  14: DigestV1 object_classifier_registry_digest,
  15: DigestV1 reason_code_registry_digest,
  16: DigestV1 correlation_package_registry_digest,
  17: DigestV1 provider_vocabulary_registry_digest
}

SignedWorkloadProtectionProfileV1 = {
  0: 1,                         // wire version
  1: bstr(1..128) key_id,
  2: 1,                         // ED25519
  3: bstr(1..4096) canonical ProfileSignatureHeaderV1,
  4: bstr(1..1048576) canonical PolicyDocumentV1,
  5: bstr(64) signature
}

profile_signature_input =
  ASCII("MITHRIL-PROFILE-V1") || 0x00 ||
  SHA-256(canonical_header) || SHA-256(canonical_policy_document)

RollbackAuthorizationPayloadV1 = {
  0: 1,
  1: Id128 rollback_authorization_id,
  2: Id128 trust_domain_id,
  3: Id128 issuer_id,
  4: Id128 approver_principal_id,
  5: u64_nonzero sequence_epoch,
  6: u64_nonzero issuer_sequence,
  7: Id128 profile_id,
  8: DigestV1 currently_active_profile_digest,
  9: u64_nonzero currently_active_profile_version,
  10: DigestV1 exact_older_target_profile_digest,
  11: u64_nonzero exact_older_target_profile_version,
  12: u32 closed_reason_code,
  13?: DigestV1 human_reason_artifact_digest,
  14: DigestV1 exact_platform_scope_digest,
  15: i64 issued_at_utc_ns,
  16: i64 expires_at_utc_ns
}

SignedRollbackAuthorizationV1 = {
  0: 1,
  1: bstr(1..128) key_id,
  2: 1,                         // ED25519
  3: bstr(1..16384) canonical RollbackAuthorizationPayloadV1,
  4: bstr(64) signature
}

rollback_signature_input =
  ASCII("MITHRIL-ROLLBACK-V1") || 0x00 ||
  SHA-256(canonical_rollback_payload)
```

The profile decoder re-encodes both embedded objects and requires key 10 of
the header to equal the policy bytes' SHA-256 before verifying the signature.
Unknown keys/tags, a header/payload ID or version mismatch, validity longer
than the locally compiled maximum, an unregistered provider ID, or a rollback
authorization whose exact current/target digest, version, platform, approver
scope or expiry differs is rejected. Rollback authorization is consumed once
and tombstoned under the same replay-WAL rules as intent proof.

`CFG-V1-GOLDEN-002` owns the future canonical policy bytes/header/signature vector;
`CFG-ROLLBACK-GOLDEN-002` owns current-8 → exact-7 success plus wrong-current,
wrong-target, wrong-platform, expired, replayed and valid-signature-without-
authorization failures. Phase 0 checks the literal `.cbor`, `.hex`, public-key,
digest and signature files under `spec/policy/v1/golden/`; until those files
exist and cross-language Rust/reference decoding agrees, signed-profile and
rollback status remains `SCHEMA_ONLY`, not implementation-complete.

Activation persists the greatest accepted `(issuer_sequence,
profile_version)` for each `(trust_domain_id, issuer_id, profile_id)` before
switching the active generation. A lower value is rejected even when its
signature and time are valid. Intentional rollback requires a separately
signed `RollbackAuthorizationV1` that names the currently active digest, the
exact older target digest, reason, approver, and expiry. “Re-sign version 7” is
not a rollback authorization.

The schema validator rejects duplicate keys, unknown enforcement fields,
unknown enum values, zero/negative durations, values outside declared bounds,
integer overflow, an unsupported signature algorithm, an expired/revoked key,
and a decoded object that is not canonical.

##### Abandoned design: Version 1 metadata extensions

The retained sentence “extension fields are allowed only inside a signed
`metadata.extensions` map” is abandoned. Closed `PolicyDocumentV1` has no
extension field; Version 1 rejects it as `CFG_UNKNOWN_FIELD`. A future
extension container requires a new schema version, explicit size/type bounds,
and a proof that no compiler or runtime consumer interprets its contents as
authority.

**Practical tests.** Reordering YAML keys produces the same canonical payload
and digest. Writing `default_postures` twice is rejected before signature
verification. Activating version 8 and replaying valid version 7 is rejected;
the old profile becomes activatable only with the exact, unexpired rollback
authorization naming both digests.

#### Entry rules

```text
EntryRule {
  entry_kind
  container_kind
  command_match: exact digest | executable object | none
  pod_spec_field_proof
  permitted_lifecycle_states
  caller_proof
  concurrency_limit
  rate_budget
  claim_ttl
  target_role_id
  ambiguity_action
  default_action
}
```

The normative field details are:

| Field | Type, unit, and default |
| --- | --- |
| `entry_kind` | Closed enum from the entry-class matrix; unknown is a compile error |
| `container_kind` | Closed enum `init|sidecar|application|ephemeral|any`; default `any` only when explicitly encoded |
| `command_match` | `none`, executable-object ID, or SHA-256 of `CanonicalArgvV1`; no shell-string normalization |
| `permitted_lifecycle_states` | Non-empty set from `CREATED|STARTING|RUNNING|TERMINATING`; empty is invalid |
| `caller_proof` | Required proof-quality axes and required issuer IDs, never a free-form string |
| `concurrency_limit` | `{count:u32, scope:execution_set|entry_rule|issuer, on_exhaustion:reject|alert}`; omitted means compiler-selected hard maximum, not infinity |
| `rate_budget` | `{count:u32, per:Duration, burst:u32, scope, on_exhaustion}`; `per` is `1ms..24h` |
| `claim_ttl` | Monotonic duration `1ms..5m`; default `5s`; cannot exceed enclosing proof expiry |
| `ambiguity_action` | `reject|same_budget_only|intersection_degraded|merged_broad_budget_exception`; default `reject` |
| `default_action` | `admit|alert_admit|reject`; default `reject` in protect mode and `alert_admit` in explicit observation mode |

`CanonicalArgvV1` is a length-delimited byte vector:

```text
u32_be(argc) || for each argument: u32_be(byte_length) || raw_bytes
```

It uses the actual kernel argument bytes, not shell re-tokenization, Unicode
normalization, whitespace folding, or redacted display strings. For
`/bin/sh -c 'x'`, the script is the exact bytes of the third argument. The BPF
fallback may compare only a compiler-declared bounded prefix plus executable
object; if truncation could merge unequal roles, the platform cannot claim an
exact command match and must reject or use the held-task runtime path.

Arguments may help classify a declared kubelet action, but arguments are not a
substitute for physical effect policy. Shell quoting, interpreter flags, file
descriptors, environment, and in-process code make an argv allowlist
insufficient.

#### Roles and transitions

```text
Role {
  role_id
  description
  entry_origins[]
  thread_creation
  fork_without_exec_target_role
  max_native_depth
  allowed_exec_edges[]
  effect_policy_id
  dynamic_state_machine_id
}

TransitionRule {
  source_role_id
  operation: fork | clone_thread | exec | privilege_transition
  candidate_object_key?
  interpreter_chain?
  required_state_bits
  resulting_role_id
  decision: allow | audit | deny
}
```

`TransitionRule` is the sole normative authority for fork, thread, exec, and
privilege-transition results. The similarly named fields inside `Role` are
source shorthand. The compiler expands them into transition rows and rejects
the profile if a shorthand row and explicit rule disagree.

##### Abandoned design: two independent transition authorities

Allowing `Role.fork_without_exec_target_role` or `allowed_exec_edges` to win in
some code paths while `TransitionRule` wins in others would make the result
depend on which hook was reached. That design is abandoned. Kernel maps contain
one compiled transition table and every simulation/probe reads that same
table.

**Practical test.** A role says fork target `child-a`, while an explicit rule
says `child-b`. Compilation fails with both source locations; it does not pick
one by file order. After correction, `task_alloc`, simulator, and explain API
all return the same target-role ID.

Recommended initial roles for the incident fixture are:

| Role | Purpose | Default dangerous effects |
| --- | --- | --- |
| `conversion-worker-root` | Existing unchanged interpreter/worker | deny undeclared exec, credential objects, API/IMDS, device/privilege escape |
| `conversion-worker-child` | Forked child that has not execed | narrower than root; cannot claim runtime entry |
| `declared-tool` | Exact approved worker child executable | only tool-specific files and destinations |
| `kubelet-exec-probe` | Declared startup/readiness/liveness command | no child exec, credential read, public egress, API/IMDS, device, or privilege effects by default |
| `kubelet-poststart` | Declared setup command | only reviewed setup objects/effects; bounded lifetime |
| `kubelet-prestop` | Declared cleanup command | reviewed cleanup effects and deadline; no containment bypass |
| `administrative-exec` | Approved interactive session | explicit break-glass policy, actor, TTL, recording/coverage requirements |
| `ephemeral-diagnostic` | Approved ephemeral container | separate container profile and restricted cross-container process/file access |
| `unknown-protected-task` | Identity or entry failure | deny every protected effect and emit high-severity coverage finding |
| `restricted-lineage` | Active response state | deny new exec/file/socket/device/privilege effects according to response policy |

#### Effect rules

```text
EffectRule {
  role_id
  effect_family
  operation
  object_class
  object_key_match
  required_dynamic_state
  lifecycle_states
  decision: allow | audit | deny
  errno
  set_state_bits[]
  clear_state_bits[]
  evidence_level
}
```

`errno` is a positive symbolic source value compiled to a negative Linux hook
return. The compiler accepts only the per-family set it has physically tested:

| Decision family | Allowed source errno values | Kernel return |
| --- | --- | --- |
| file/exec | `EACCES|EPERM` | `-EACCES|-EPERM` |
| socket connect/send | `EACCES|EPERM` when supported by that hook | corresponding negative errno |
| capability/device/security | `EPERM` by default; additional values only in the capability record | corresponding negative errno |

Zero, an already-negative YAML integer, unknown errno, or an errno not proven
for the selected hook is a compile error. `allow` and `audit` must omit
`errno`.

An object class is a policy concept such as `dataset-input`,
`projected-service-account-token`, `worker-environment-procfile`,
`kubernetes-api`, `cloud-imds`, `mesh-control`, `tun-device`, or
`anonymous-executable-memory`. The kernel uses compact compiled keys; the
evidence record retains the resolved semantic class and provenance.

#### Authority behavior rules

Linux can decide that a process may connect to the Kubernetes API. It cannot
parse an already-encrypted request and decide that `list pods` is expected but
`create rolebinding` is not. That second decision belongs to an asynchronous
authority behavior policy:

```text
AuthorityBehaviorRule {
  principal_selector
  source_workload_selector
  authority: kubernetes | aws | github | mesh | connector | artifact_repo
  allowed_operations[]
  allowed_resource_selectors[]
  allowed_credential_lease_types[]
  time/rate/concurrency budgets
  required_request_proof
  finding_on_deviation
  response_playbook
}
```

The normative authority rule also contains:

```text
evaluation_stage: REMOTE_PRE_ADMISSION | POST_EFFECT
operation_vocabulary_id: provider + API/version
resource_selector: typed provider-specific AST
result_filter: SUCCEEDED | DENIED_BY_PROVIDER | FAILED | ANY
rate_budget: { count, per, burst, scope }
required_audit_level_or_connector_capability
```

Free-form strings such as `create secret-ish object` are invalid operations.
For Kubernetes, a compiled key names audit stage, verb, API group/resource,
namespace/object selector, subresource, principal, and result. For AWS it
names event source, event name, account/region/resource selectors, session
identity fields, and result class. An adapter must version and test its
normalizer against the provider schema.

At `POST_EFFECT`, `allow` means “record without a deviation finding,” not “let
the already-finished operation proceed.” Only a synchronous connector,
admission service, or broker may compile `REMOTE_PRE_ADMISSION -> reject`.

This rule consumes Kubernetes/provider audit. It never claims that the kernel
prevented a server operation that had already succeeded.

#### Compilation pipeline

```text
signed source profile
  -> schema and signature validation
  -> selector resolution and immutable workload snapshot
  -> conflict and reachability analysis
  -> entry/role state-machine compilation
  -> object classifier compilation
  -> compact effect decision tables
  -> response and coverage requirement compilation
  -> userspace simulation against observed workload baseline
  -> human approval
  -> inactive BPF map generation
  -> read-back + controlled allow/deny probes
  -> atomic active-generation switch
```

Compiler rejection conditions include:

- an entry maps ambiguously to roles with unequal budgets without an explicit
  ambiguity action;
- a role is unreachable or can escalate through a transition cycle;
- a deny depends on an unsupported hook or object key;
- a path-only executable is marked immutable;
- a rule claims a TLS/server verb from network-only evidence;
- a response target lacks a revalidation key and physical postcondition;
- an allow would override a hard invariant or active response state;
- a required object classifier can return unknown with fail-open behavior; or
- the generation exceeds verified BPF map, stack, instruction, depth, or
  latency bounds.

Observation generates a **candidate** role/effect profile. It never writes an
allow directly into the active generation. Candidate promotion requires
review, simulation, signature, controlled probes, and rollout health.

#### Policy precedence

Every protected hook evaluates in this order:

1. Preserve a nonzero prior LSM result.
2. Resolve the live protected cgroup/profile binding.
3. Resolve or admit the exact current task label.
4. Apply response-root and emergency hard-deny state.
5. Apply immutable product invariants.
6. Apply exact entry/role transition or effect rule.
7. Apply role and profile default posture.
8. Commit dynamic state changes associated with an allowed/audited effect.
9. Emit decision evidence independently.

No later step can change an earlier deny into allow.

##### Abandoned design: cgroup lookup precedes an existing task label

Steps 2 and 3 in the retained list are ordered incorrectly. If a labeled
protected task is moved to a host cgroup, “resolve cgroup first” can reach host
allow before discovering its label. That ordering is abandoned and superseded
everywhere—including the performance fast path—by one invariant:

```text
1. preserve a nonzero prior BPF-LSM result;
2. read current TaskLabel first;
3. if a valid label exists, resolve its execution-set/root binding and verify
   current placement against that binding; it can never enter host allow;
4. only for an unlabeled task, resolve current cgroup/root/ancestor placement;
5. if protected, claim an exact eligible external entry or deny;
6. only after a complete qualified traversal proves both label and protected
   placement absent may explicit host policy return allow;
7. apply response, invariants, exact rule/default, atomic state, and evidence.
```

**Practical example.** Worker task T is labeled for execution set E, then a
privileged helper moves T from E's cgroup to `/system.slice`. T attempts a
network send. The task-storage lookup still resolves E; placement validation
returns `PROTECTED_TASK_PLACEMENT_MISMATCH`. The host profile is never
consulted. Conversely, a genuinely unlabeled host process in `/system.slice`
reaches host policy only after bounded ancestor resolution completes without a
protected binding or coverage error.

##### Abandoned design: prose specificity as the conflict algorithm

“Most specific deny wins” and “exact matches outrank broader matches” are not
complete algorithms. A role-exact/object-wildcard rule and a
role-wildcard/object-exact rule are incomparable. Letting different compiler
implementations choose is abandoned.

The normative compiler resolves rules as follows:

1. Partition by physical stage: `ENTRY_ADMISSION`, `NATIVE_TRANSITION`,
   `LOCAL_PRE_EFFECT`, `REMOTE_PRE_ADMISSION`, or `POST_EFFECT`. Rules from
   different stages never compete.
2. Resolve selectors and expand every rule into finite exact decision keys for
   the bound generation. A key includes every relevant dimension; wildcard is
   expanded against the generation's closed role/object/operation universe.
3. Apply immutable hard invariants and active response restrictions. Source
   policy cannot override them.
4. For each exact key, identical physical decisions may merge evidence,
   notification, and compatible response requirements.
5. Different physical decisions are legal only when one rule has an explicit
   signed `overrides: [rule_id...]` or `Exception` naming the other rule, exact
   affected subject/key delta, approver, and expiry. The compiler records that
   edge in its explanation.
6. Without that explicit edge, compilation fails. File order, map iteration,
   lexical rule ID, and “looks more specific” never decide.

The existing `priority` field is normative only for notification-routing order
and deterministic display (`i32`, larger first, rule ID as the stable tie
sort). It does not resolve conflicting physical effects. If a future schema
wants priority-based authorization, it requires a new schema version and an
explicit security review.

**Practical example.** Rule A allows every `converter` role to read any
runtime object. Rule B denies every role reading object `secret-17`. The tuple
`(converter, read, secret-17)` has two decisions. Compilation fails unless B
explicitly overrides A for that exact object family (or A carries a narrower
signed exception). Reordering YAML changes neither the result nor the compiler
diagnostic.

### Node Decision Architecture

#### Compiled map model

The exact layout is Phase 0 ABI work, but the architecture requires the
following logical maps:

```text
protected_cgroup_bindings:
  live cgroup key -> execution set, active generation, retained generations,
                     lifecycle, mode

task_labels:
  BPF task storage -> TaskLabel

pending_entries:
  binding + lifecycle generation + candidate class -> one-use entry slots

active_profile_generations:
  profile ID -> active generation pointer

role_transition_tables[generation]:
  source role + transition + object key -> decision + target role

effect_tables[generation]:
  role + effect + operation + object class/key + state -> decision

response_roots:
  node boot + label epoch + process lineage -> restrictions + TTL

socket_labels:
  socket storage -> immutable creation/admission provenance, socket namespace,
                    generation/lifetime contract, destination/flow identity,
                    response state

coverage_counters:
  per CPU/hook/generation sequence, drop, classifier miss, map failure
```

##### Decision-set ABI and lookup semantics

The retained map names are logical families, but the four `*_set_id` fields
used later are authorization inputs. They cannot remain unspecified aliases
for “whatever Rust compiled.” Version 1 gives each field exactly one meaning:

| Field | Exact referent | May it grant an actor permission? |
| --- | --- | --- |
| `TaskDecisionCacheDraftAbandoned.cached_decision_set_id` | Retained future idea for a precomputed intersection; no such map or field exists in Version 1 | No. Version 1 always reads authoritative state. |
| `AuthorityDomainStateV1.effective_restriction_set_ref_id` | A monotonic set of domain-wide negative constraints compiled from potential/observed sensitive state, cross-entry joins, and topology posture | No. An entry can be `NO_ADDITIONAL_RESTRICTION` or make the actor's base result stricter; it cannot turn a base deny into allow. |
| `AuthorityDomainStateV1.effective_response_set_ref_id` | A monotonic set of active response restrictions with response-plan identities and deadlines | No. It can deny, freeze, meter, or require an explicitly compiled cleanup operation; it cannot add a positive role grant. |
| `AuthorityDomainStateV1.retained_generation_set_ref_id` | Bounded membership index for generations whose immutable maps are still pinned and reference-valid for this domain | No. Membership says the tables still exist; it does not select a rule or authorize migration. |

###### Abandoned design: owner-local generations, digest-only defaults, and a cached final allow

The first ABI draft below is retained because it names the decision families,
but it is not implementable as written. A bare `profile_generation: u64`
collides when profile A and profile B both own generation 42; a default digest
does not tell BPF which physical decision to return; one response lookup loses
either process-local or domain-wide response state; `CLEANUP_ONLY` is not a
physical total-order result; and a cached final allow can outlive a mutable
object or socket floor. The whole first draft through its original
`DECISION-SET-GOLDEN-001` paragraph is therefore abandoned as a wire ABI. The
canonical replacement follows it and preserves every useful concept with
closed records.

The retained draft kernel ABI is:

```text
EffectDecisionKeyV1 {
  profile_generation: u64
  active_role_id: u32
  entry_kind: u16
  effect_family: u16
  operation: u16
  object_class: u16
  object_key_id: u64
  process_state_vector_id: u32
  binding_lifecycle_state: u8
}

PhysicalDecisionV1 {
  decision: ALLOW | AUDIT_ALLOW | DENY
  errno: i16                    // zero unless DENY
  evidence_class_id: u32
  transition_id: u32            // zero means no state transition
}

RestrictionDecisionKeyV1 {
  restriction_set_id: u64
  profile_generation: u64
  effect_family: u16
  operation: u16
  object_class: u16
  decision_object_key_id: u64   // nonzero exact key or nonzero class sentinel
}

RestrictionDecisionV1 {
  result: NO_ADDITIONAL_RESTRICTION | DENY
  errno: i16
  restriction_reason_bits: u64
}

ResponseDecisionKeyV1 {
  response_set_id: u64
  profile_generation: u64
  effect_family: u16
  operation: u16
  object_class: u16
  decision_object_key_id: u64
}

ResponseDecisionV1 {
  result: NO_ADDITIONAL_RESTRICTION | DENY | CLEANUP_ONLY
  errno: i16
  response_plan_set_digest_id: u64
}

GenerationMembershipKeyV1 {
  retained_generation_set_id: u64
  profile_generation: u64
}

RestrictionSetDescriptorV1 {
  restriction_set_id: u64
  set_epoch: u64
  covered_generation_set_id: u64
  row_count: u32
  table_digest_id: u64
  declared_default_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

ResponseSetDescriptorV1 {
  response_set_id: u64
  set_epoch: u64
  covered_generation_set_id: u64
  response_plan_set_digest_id: u64
  row_count: u32
  table_digest_id: u64
  declared_default_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

GenerationSetDescriptorV1 {
  retained_generation_set_id: u64
  membership_count: u32
  membership_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

DecisionSetDescriptorV1 {
  cached_decision_set_id: u64
  process_state_id: u128
  process_transition_version: u64
  authority_domain_id: u128
  domain_transition_version: u64
  profile_generation: u64
  active_role_id: u32
  entry_kind: u16
  process_state_vector_id: u32
  compiled_artifact_digest_id: u64
}

CachedDecisionKeyV1 {
  cached_decision_set_id: u64
  effect_family: u16
  operation: u16
  object_class: u16
  decision_object_key_id: u64
}
```

All wildcards are expanded by Rust against the closed generation universe;
there is no “best match” walk in BPF. The object classifier returns one
nonzero `decision_object_key_id`: an exact immutable/live object key when
quality is sufficient, or a compiler-assigned nonzero class-default sentinel
when that rule explicitly permits class-level authority. Zero, unknown class,
or an exact-required classification miss denies before table lookup. Rust
materializes restriction and response rows for every allowed exact key and
class sentinel in every covered retained generation, so BPF never performs an
exact-then-class fallback.

Descriptors and table digests are populated and read back while `PREPARING`;
the activation owner marks them `ACTIVE` only after cardinality, membership,
defaults and row digests match the signed artifact. The BPF hot path checks
descriptor ID/epoch/state and exact membership; it does not recompute a digest.
The physical result is:

```text
object_key = classify_to_exact_or_declared_class_sentinel()
base = effect_decisions[EffectDecisionKeyV1(object_key)] or exact profile_default
restriction = restriction_decisions[
  RestrictionDecisionKeyV1(process.generation, object_key)]
response = response_decisions[
  ResponseDecisionKeyV1(process.generation, object_key)]
require generation_membership[(domain.retained_generation_set_id,
                               process.active_profile_generation)] == PRESENT
result = base intersect restriction intersect response intersect object/socket floor
```

`intersect` uses the order `DENY > CLEANUP_ONLY > AUDIT_ALLOW > ALLOW`; it
never treats an absent negative row as an allow until the set descriptor and
its declared default have been found and validated. An unknown set ID,
descriptor/map miss, unknown enum, wrong digest, generation-membership miss,
or Version 1 cardinality overflow returns the profile's fail-closed errno and
increments the named health counter. A BPF LRU map is forbidden for any of
these authoritative tables. The sole exception is the optional cache: a
missing/stale `DecisionSetDescriptorV1` or `CachedDecisionKeyV1` entry discards
the cache and runs the authoritative lookups above; it never returns cache
allow and never converts cache absence itself into a denial.

Mixed generations are explicit. If a domain contains generation-42 and
generation-43 processes, one `effective_restriction_set_id` has separately
compiled rows keyed by 42 and 43, and its descriptor's covered generation set
contains both. Each process uses its own pinned generation. The compiler proves
the semantic restriction (for example `NO_PUBLIC_EGRESS_AFTER_SENSITIVE`) is
no weaker in either universe; inability to lower it for one generation rejects
the join/profile rather than dropping that member's restriction.

State changes use a second precompiled map:

```text
MonotonicSetTransitionKeyV1 {
  current_restriction_set_id
  current_response_set_id
  current_state_vector_id
  transition_id
}

MonotonicSetTransitionValueV1 {
  next_restriction_set_id
  next_response_set_id
  next_state_vector_id
  restriction_delta_digest
}
```

Rust proves at compilation that each transition preserves or narrows every
decision in every covered generation's closed effect universe. BPF resolves
the transition row **before** taking a value spin lock. Inside the lock it
rechecks the current IDs and version; if they still match, it installs the
pre-resolved packed state/set IDs and increments `transition_version`. On a
mismatch it releases the lock, retries the authoritative read/lookup once, and
then denies on continuing contention. It performs no helper/map lookup while
holding the lock. A missing transition is a denial; BPF never synthesizes a set
by enumerating rules.

`DECISION-SET-GOLDEN-001` compiles a concrete converter role: generation 42
allows `NET_CONNECT` to the result endpoint, restriction set 700 denies public
network after `SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED`, and response set 901 permits only
evidence upload/cleanup. The fixture checks the exact binary keys and values,
then exercises clean allow, state-transition deny, response cleanup-only,
unknown set ID, deleted membership row, stale cache descriptor, and a forced
map-capacity failure. A second generation-43 vector uses different object-key
IDs/defaults but the same semantic restriction, and joins in both process
orders. Rust and BPF must produce the same result and errno for every vector;
cache deletion must equal the authoritative result, not cause a new allow or
deny.

###### Canonical Version 1 decision ABI

Version 1 uses node-epoch-global, non-reused handles. A handle is a nonzero
`u64` allocated monotonically within `(node_boot_id, label_epoch)`. Exhaustion
or loss of the allocator epoch while protected state survives is a fatal
health transition; the node does not wrap or reuse a number.

Every descriptor repeats and is checked against that `node_boot_id` and
`label_epoch`; map ownership alone is not treated as an implicit epoch proof.
`owner_set_epoch` is the immutable semantic revision assigned by the set's
compiler/owner and is compared to the signed activation manifest. It is not a
node label epoch and cannot substitute for either explicit epoch field.

```text
ProfileGenerationRefV1 {
  profile_generation_ref_id: u64       // node-epoch-global handle
  node_boot_id: Id128
  label_epoch: u64
  profile_id: Id128
  owner_generation: u64                // the profile owner's generation
  compiled_artifact_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

SetKindV1 = RESTRICTION | RESPONSE | RETAINED_GENERATION

SetRefDescriptorDraftAbandoned {
  set_ref_id: u64                      // node-epoch-global; never reused
  node_boot_id: Id128
  label_epoch: u64
  set_kind: SetKindV1
  owner_set_epoch: u64                 // semantic set revision, not label epoch
  artifact_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

SetRefV1 {                            // set_ref_map[set_ref_id]
  set_lock: bpf_spin_lock
  set_ref_id: u64                     // node-epoch-global; never reused
  node_boot_id: Id128
  label_epoch: u64
  set_kind: SetKindV1
  owner_set_epoch: u64
  artifact_digest_id: u64
  refs_by_class[SetReferenceClassV1]: u64
  state: PREPARING | ACTIVE | RETIRING
  transition_version: u64
}
```

All earlier authoritative fields named `active_profile_generation`,
`effective_restriction_set_id`, `effective_response_set_id`, and
`retained_generation_set_id` are retained display shorthands. Their canonical
types and names are respectively `active_profile_generation_ref_id`,
`effective_restriction_set_ref_id`, `effective_response_set_ref_id`, and
`retained_generation_set_ref_id`. Both `ProcessSecurityStateV1` and
`AuthorityDomainStateV1` carry their own
`effective_response_set_ref_id`; neither shadows the other. The immutable
neutral response set has a real nonzero, non-reused `SetRefV1` handle and
complete default rows. Zero always means invalid/missing and denies.

The descriptor selected by a handle contains the full owner generation and
artifact identity. A new-reference path requires the descriptor to be
`ACTIVE`; an existing qualified holder may use `ACTIVE` or `RETIRING` as
specified below. The hot path
does not claim to recompute or compare a digest that is absent from the
authoritative state. Stale-ID safety comes from never reusing the handle in the
node label epoch. Rust verifies descriptor digest and exact map contents during
activation readback. Restart with surviving protected state must recover the
same allocator/WAL epoch or hold the workload fail-closed.

The preceding “requires `ACTIVE`” applies when creating a new holder. Once
retirement begins, an existing process/socket/object whose retained-generation
membership is still present may continue to resolve a `RETIRING` descriptor;
new holders cannot acquire it. Removing its table rows or membership before
the final qualified reference reaches zero is forbidden.

The same lifecycle rule is uniform across
`ProfileGenerationRefV1`, `SetRefV1`, `ProcessStateVectorV1`, and
`TransitionDescriptorV1`:

| Descriptor state | Existing retained holder | New reference/admission | Deletion |
| --- | --- | --- | --- |
| `PREPARING` | deny | deny | rollback only after proving no published holder |
| `ACTIVE` | use after exact type/epoch/digest activation checks | may acquire, then read back owned reference | forbidden while any reference exists |
| `RETIRING` | may use only while its exact retained-membership/reference proof remains valid | deny | only after zero references, iterator reconciliation and grace period |
| missing/unknown | deny | deny | not applicable; report corruption/gap |

A transition descriptor in `RETIRING` may serve an already retained process
only when every next state/set reference named by its value is itself retained
and usable. It may not create a reference to another retiring object.

One object may have several independent security properties. The classifier
therefore returns a bounded composite atom, not one lossy “best class”:

```text
ClassifierAxisValueV1 { axis_id: u16, value_id: u32 }

CompositeDecisionAtomV1 {
  atom_id: u64
  effect_family: u16
  sorted_unique_axis_values[1..MAX_CLASSIFIER_AXES]: ClassifierAxisValueV1
  canonical_axis_digest_id: u64
}
```

The compiler enumerates the closed, effect-family-specific cross product and
assigns an `atom_id`. It rejects an unbounded combination before activation.
At runtime, a missing required axis, duplicate axis, unknown value, or absent
composite atom denies. For example, the projected Kubernetes token inode is
simultaneously `{credential=service_account_token,
backing=projected_volume, mutability=provider_rotated,
persistence=pod_lifetime}`; selecting only “ordinary file” or only “token” is
illegal. A connection to the Kubernetes API is simultaneously
`{destination_scope=cluster_control_plane, address_scope=private,
protocol=tls}`; “private IP” cannot erase the API deny.

The executable maps are:

```text
BindingLifecycleStateV1 = PREPARING | ACTIVE | DRAINING | TERMINATING |
  TOMBSTONED

ExecutionSetBindingStateV1 {          // binding_by_execution_set[execution_set_id]
  binding_lock: bpf_spin_lock
  binding_id: Id128
  binding_nonce: Id128
  node_boot_id: Id128
  label_epoch: u64
  execution_set_id: Id128
  protected_scope_id: Id128
  profile_id: Id128
  active_profile_generation_ref_id: u64
  root_cgroup_id: u64
  root_cgroup_live_interval_id: Id128
  mount_view_generation_id: Id128
  network_namespace_generation_id: Id128
  lifecycle_state: BindingLifecycleStateV1
  lifecycle_generation: u64
  mode: OBSERVE | PROTECT
  transition_version: u64
}

BindingRetainedGenerationKeyV1 {      // separate bounded membership map
  binding_id: Id128
  profile_generation_ref_id: u64
}

BindingRetainedGenerationValueV1 {
  binding_nonce: Id128
  lifecycle_generation: u64
  membership_state: ACTIVE | RETIRING
}

RestrictionFloorV1 {
  result: NO_ADDITIONAL_RESTRICTION | DENY
  errno: i16                           // zero unless DENY
  reason_bits: u64
}

ExactObjectFloorKeyV1 {
  exact_object_key_id: u64
  exact_object_generation: u64
  effect_family: u16
  operation: u16
}

ExactSocketOrChannelFloorKeyV1 {
  exact_socket_or_channel_key_id: u64
  exact_socket_or_channel_generation: u64
  current_actor_authority_domain_id: Id128
  effect_family: u16
  operation: u16
}

ResolvedSocketOrChannelGenerationV1 {
  exact_socket_or_channel_key_id: u64
  exact_socket_or_channel_generation: u64
  backing_identity: ExactObjectGenerationV1
}

BindingLifetimeFloorKeyV1 {
  binding_id: Id128
  binding_nonce: Id128
  lifecycle_state: BindingLifecycleStateV1
  effect_family: u16
  operation: u16
}

FloorRequirementKeyV1 {
  profile_generation_ref_id: u64
  active_role_id: u32
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  lifetime_kind: OBJECT | SOCKET_OR_CHANNEL
}

FloorRequirementValueV1 =
  EXPLICIT_NEUTRAL
  | DYNAMIC_REQUIRED {
      template_id:u64,
      required_provenance_bits:u64,
      required_reference_classes:u64
    }

DynamicFloorTemplateV1 {
  template_id: u64
  profile_generation_ref_id: u64
  artifact_digest_id: u64
  floor: RestrictionFloorV1
  state: PREPARING | ACTIVE | RETIRING
}

DynamicFloorStateV1 {
  exact_lifetime_identity_digest: DigestV1
  source_template_id: u64
  source_profile_generation_ref_id: u64
  restriction_set_ref_id?: u64
  generation_reference_owned: bool
  set_reference_owned: bool
  floor: RestrictionFloorV1
  state: PREPARING | ACTIVE | TOMBSTONED | RECONCILIATION_REQUIRED
  transition_version: u64
}

EffectDecisionKeyV1 {
  profile_generation_ref_id: u64
  active_role_id: u32
  entry_kind: u16
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  exact_object_key_id: u64             // nonzero
  process_state_vector_id: u32
  binding_lifecycle_state: u8
}

EffectDefaultKeyV1 {
  profile_generation_ref_id: u64
  active_role_id: u32
  entry_kind: u16
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  process_state_vector_id: u32
  binding_lifecycle_state: u8
}

PhysicalDecisionV1 {
  decision: ALLOW | AUDIT_ALLOW | DENY
  errno: i16                            // zero unless DENY
  evidence_class_id: u32
  transition_id: u32                    // zero means no transition
}

RestrictionDecisionKeyV1 {
  restriction_set_ref_id: u64
  profile_generation_ref_id: u64
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  exact_object_key_id: u64
}

RestrictionDefaultKeyV1 {
  restriction_set_ref_id: u64
  profile_generation_ref_id: u64
  effect_family: u16
  operation: u16
  composite_atom_id: u64
}

RestrictionDecisionV1 {
  result: NO_ADDITIONAL_RESTRICTION | DENY
  errno: i16
  restriction_reason_bits: u64
}

ResponseDecisionKeyV1 {
  response_set_ref_id: u64
  profile_generation_ref_id: u64
  effect_family: u16
  operation: u16
  composite_atom_id: u64
  exact_object_key_id: u64
}

ResponseDefaultKeyV1 {
  response_set_ref_id: u64
  profile_generation_ref_id: u64
  effect_family: u16
  operation: u16
  composite_atom_id: u64
}

ResponseDecisionV1 {
  result: NO_ADDITIONAL_RESTRICTION | AUDIT_ALLOW | DENY
  errno: i16
  response_plan_set_digest_id: u64
}

TransitionKindV1 = NONE | PROCESS_ONLY | DOMAIN_SENSITIVE_ONLY

TransitionDescriptorV1 {
  transition_id: u32
  node_boot_id: Id128
  label_epoch: u64
  transition_kind: TransitionKindV1
  profile_generation_ref_id: u64
  transition_artifact_digest_id: u64
  state: PREPARING | ACTIVE | RETIRING
}

ProcessTransitionKeyV1 {
  profile_generation_ref_id: u64
  transition_id: u32
  current_role_id: u32
  current_process_state_vector_id: u32
  current_process_response_set_ref_id: u64
}

ProcessTransitionValueV1 {
  next_role_id: u32
  next_process_state_vector_id: u32
  next_process_response_set_ref_id: u64
}

DomainSensitiveTransitionKeyV1 {
  profile_generation_ref_id: u64
  transition_id: u32
  current_potential_sensitive_bits: u64
  current_observed_sensitive_bits: u64
  current_restriction_set_ref_id: u64
  current_domain_response_set_ref_id: u64
}

DomainSensitiveTransitionValueV1 {
  next_potential_sensitive_bits: u64
  next_observed_sensitive_bits: u64
  next_restriction_set_ref_id: u64
  next_domain_response_set_ref_id: u64
}

GenerationMembershipKeyV1 {
  retained_generation_set_ref_id: u64
  profile_generation_ref_id: u64
}

GenerationMembershipValueV1 {
  result: PRESENT
}
```

`ExecutionSetBindingStateV1` is a fixed-size value. The hot path never scans a
retained-generation array: it copies the binding tuple under `binding_lock`,
then performs the exact `BindingRetainedGenerationKeyV1` lookup. Rotation
publishes the new generation and its membership row before switching
`active_profile_generation_ref_id` under the binding lock. The old membership
changes to `RETIRING`; it is deleted only after the typed generation counters,
owned-reference tombstones, complete iterator reconciliation, and BPF grace
period all agree that no holder remains. A lifecycle change increments both
`lifecycle_generation` and `transition_version`. Consequently an allow cannot
race a torn `ACTIVE -> TERMINATING` binding value.

`ProcessStateVectorV1` and `TransitionDescriptorV1` are immutable children of
one `ProfileGenerationRefV1` in Version 1. Their displayed
`PREPARING | ACTIVE | RETIRING` state mirrors their owning generation; they do
not retire or reclaim independently. Activation writes every child in
`PREPARING`, reads back its full bytes and digest, changes the complete
generation artifact to `ACTIVE`, and only then publishes binding membership.
Retirement keeps every child until the owning generation's last typed holder
is released and the whole artifact passes iterator reconciliation plus grace.

`SetRefV1` is deliberately different: it is node-label-epoch-owned and may
contain rows for several retained profile generations. Emergency response
sets must survive a profile switch, and a retained-generation membership set
is inherently multi-generation. Its independent ownership ABI is:

```text
SetReferenceClassV1 = PROCESS_RESPONSE | DOMAIN_RESTRICTION |
  DOMAIN_RESPONSE | DOMAIN_GENERATION_MEMBERSHIP | PENDING_EXEC_RESPONSE |
  TRANSITION_TARGET | RESPONSE_PLAN | OBJECT_OR_PUBLICATION

SetReferenceCountersDraftAbandoned {  // superseded by inline SetRefV1 fields
  set_ref_id: u64
  node_boot_id: Id128
  label_epoch: u64
  refs_by_class[SetReferenceClassV1]: u64
  state: PREPARING | ACTIVE | RETIRING
  transition_version: u64
}

SetReferenceTombstoneV1 {
  reference_owner_id: Id128
  reference_owner_generation: u64
  set_ref_id: u64
  reference_class: SetReferenceClassV1
  owned: bool
  acquisition_transition_version: u64
  release_transition_version?: u64
}
```

Before publishing any process/domain/pending/plan pointer, the owner creates
and reads the tombstone, resolves the `SetRefV1` pointer, locks `set_lock`,
requires the expected state/version, increments the matching inline counter,
unlocks, CASes the tombstone to `owned=true`, and reads both back. No map/helper
lookup occurs while the lock is held. Moving the pointer acquires the new
ref first, atomically swaps the owning tuple, then releases the old tombstone
exactly once. A SetRef becomes `RETIRING` only after no new publisher can point
to it. Deletion requires every counter zero, no owned tombstone in the complete
iterator/WAL reconciliation, and a BPF grace period. Missing ownership denies;
response and restriction sets are never reclaimed merely because one profile
generation retired.

`SetRefDescriptorDraftAbandoned` and
`SetReferenceCountersDraftAbandoned` are retained to show the two-value draft;
they are not loaded. Canonical `SetRefV1` is the sole lifecycle and counter
authority, so `ACTIVE -> RETIRING` is one locked transition rather than two
records that can disagree.

`binding_lifetime_floors` stores `RestrictionFloorV1`;
`exact_object_floors` and `exact_socket_or_channel_floors` store
`DynamicFloorStateV1`.
Static compilation cannot enumerate future accepted sockets, pipes, files, or
SCM_RIGHTS transfers. It instead emits, per
`(profile_generation_ref, role, effect, operation, composite_atom)`, either
`DYNAMIC_REQUIRED` plus a `DynamicFloorTemplateV1` or `EXPLICIT_NEUTRAL` in
`floor_requirements[FloorRequirementKeyV1]`. The object/socket acquisition hook copies the
template to an exact-generation dynamic row, acquires its SetRef/generation
references, reads the bytes back, and only then publishes the usable object or
socket handle. A first use before `ACTIVE`, a missing required row, capacity
N+1, object reuse, or an unclassified received fd denies. `accept`,
`socketpair`, pipe creation, fork/inheritance and fd passing each have a
specific creation/transfer path and hostile fixture; none relies on a later
userspace binder. For an operation whose static rule says
`EXPLICIT_NEUTRAL`, the lookup initializes the corresponding floor to
`NO_ADDITIONAL_RESTRICTION` and performs no dynamic lookup. A file operation
with required exact classification but no resolved object denies
`CLASSIFIER_UNKNOWN`; zero is never used as an object key.

Each key family has its own preallocated non-LRU map. `effect_defaults`,
`restriction_defaults`, and `response_defaults` store the exact value types
shown above; `declared_default_digest_id` in the retained draft is not an
executable default. Activation requires exactly one default row for every
reachable non-exact key. A missing exact row falls back only to its fully
initialized default key. A missing default, descriptor, composite atom, or
membership row denies and increments a typed health counter.

`PhysicalDecisionV1.transition_id=0` means no state change. For a nonzero ID,
BPF resolves and validates the descriptor and exact transition row by
`(profile_generation_ref_id, transition_id)` before
taking the owning map value's spin lock, then rechecks every current field and
version under that lock, writes the complete next tuple, and increments the
owner's transition version. `PROCESS_ONLY` changes one
`ProcessSecurityStateV1`; `DOMAIN_SENSITIVE_ONLY` changes one
`AuthorityDomainStateV1`. Version 1 rejects a rule that asks one syscall to
atomically change both map values. In particular, an access that must prevent
sibling publication uses the domain transition as its authority; a process
state bit may be emitted later as evidence but cannot independently relax or
tighten that publication decision.

`transition_id` is unique only inside its immutable profile-generation
artifact. A bare transition ID is never a map key, evidence identity, or
recovery coordinate; every such use includes the node-epoch-global
`profile_generation_ref_id`.

`CLEANUP_ONLY` in the retained draft is abandoned. Source policy may name a
reviewed cleanup operation class, but compilation expands that class into an
ordinary row for every exact operation/object atom: allowed cleanup becomes
`ALLOW` or `AUDIT_ALLOW`; every unmatched operation becomes `DENY`. The BPF
result remains a physical three-value decision and never asks whether an
arbitrary syscall “looks like cleanup.”

For Version 1, decision caching is disabled:

```text
decision_cache_capability = DISABLED
cached_decision_map is absent
no task/process/domain ABI contains a cache-authority field
```

This is deliberate. Object, socket, binding-lifetime, process-response and
domain-response floors may change independently of a task cache. A later cache
capability needs a separately approved value ABI and must still read and
intersect every mutable floor. Until then, a nonzero cache ID or a loaded cache
map is `DECISION_CACHE_UNQUALIFIED` and prevents strict activation.

The complete lookup initializes every field; constructor shorthand is
forbidden in golden vectors:

```text
if effect_context.prior_lsm_result != 0:
  best_effort_emit(STACKED_BPF_LSM_DENIAL, exact prior result)
  return effect_context.prior_lsm_result

label = task_storage[current]
if label is missing:
  placement = resolve_current_task_against_protected_root_index()
  if placement == EXACTLY_OUTSIDE_EVERY_PROTECTED_ROOT:
    return evaluate_explicit_host_policy(effect_context)
  if placement == INSIDE_PROTECTED_ROOT or placement == UNKNOWN_OR_STALE:
    return deny(PROTECTED_TASK_IDENTITY_MISSING)

placement = resolve_current_task_against_protected_root_index()
require placement == INSIDE_EXPECTED_PROTECTED_ROOT
root_storage = cgrp_storage[placement.opened_live_root_cgroup]
require root_storage.binding_id ==
        label.task_placement_expectation.protected_root_binding_id
require root_storage.binding_nonce ==
        label.task_placement_expectation.protected_root_binding_nonce
require placement.descendant_relation satisfies
        label.task_placement_expectation.allowed_descendant_policy_id
require placement.full_cgroup_id and live_interval still match root storage

process = locked_copy_process_authority_tuple(label.process_state_id)
domain = locked_copy_domain_authority_tuple(process.authority_domain_id)
entry = locked_copy_entry_tuple(label.entry_instance_id)
binding = locked_copy_binding_tuple(label.execution_set_id)
relock process_state_map[label.process_state_id]
require process transition_version, authority_domain_id and every copied
        authority field still equal; otherwise unlock and retry whole snapshot once
unlock process
relock entry_state_map[label.entry_instance_id]
require entry transition_version, admission_state, lifetime_state,
        execution_set_id and root_process_state_id still equal; otherwise
        unlock and retry whole snapshot once
unlock entry
relock binding_by_execution_set[label.execution_set_id]
  require binding transition_version, binding_nonce, lifecycle_generation,
        lifecycle_state and active generation still equal;
        otherwise unlock and retry whole snapshot once
unlock binding
generation = profile_generation_refs[process.active_profile_generation_ref_id]
process_vector = process_state_vectors[process.process_state_vector_id]

require label/process/domain/binding/entry identities, epochs, states and versions
require entry.admission_state == COMMITTED and entry.lifetime_state != COMPLETE
require entry.execution_set_id == label.execution_set_id
require entry.entry_instance_id == label.entry_instance_id
require process.entry_instance_id == label.entry_instance_id
require entry.root_process_state_id == process.entry_root_process_state_id
require process_vector.profile_generation_ref_id ==
        process.active_profile_generation_ref_id
require process_vector.state in [ACTIVE, RETIRING] for this retained holder
require generation.state in [ACTIVE, RETIRING] for an existing process holder
require generation.state == ACTIVE when acquiring a new admission reference
require generation.profile_id == binding.profile_id
require binding_retained_generations[
  BindingRetainedGenerationKeyV1 {
    binding_id: binding.binding_id,
    profile_generation_ref_id: process.active_profile_generation_ref_id
  }
] == BindingRetainedGenerationValueV1 {
  binding_nonce: binding.binding_nonce,
  lifecycle_generation: binding.lifecycle_generation,
  membership_state: ACTIVE | RETIRING for this existing holder
}
require generation_membership[
  GenerationMembershipKeyV1 {
    retained_generation_set_ref_id:
      domain.retained_generation_set_ref_id,
    profile_generation_ref_id:
      process.active_profile_generation_ref_id
  }
] == GenerationMembershipValueV1 { result: PRESENT }

atom = classify_all_required_axes_or_deny(effect_context)
object_key = classify_exact_object_or_zero(effect_context)

base = MISSING
if object_key != 0:
  effect_key = EffectDecisionKeyV1 {
    profile_generation_ref_id: process.active_profile_generation_ref_id,
    active_role_id: process.active_role_id,
    entry_kind: entry.entry_kind,
    effect_family: effect.family,
    operation: effect.operation,
    composite_atom_id: atom.atom_id,
    exact_object_key_id: object_key,
    process_state_vector_id: process.process_state_vector_id,
    binding_lifecycle_state: binding.lifecycle_state
  }
  base = effect_decisions[effect_key]
if base is missing:
  base = effect_defaults[EffectDefaultKeyV1 {
    profile_generation_ref_id: process.active_profile_generation_ref_id,
    active_role_id: process.active_role_id,
    entry_kind: entry.entry_kind,
    effect_family: effect.family,
    operation: effect.operation,
    composite_atom_id: atom.atom_id,
    process_state_vector_id: process.process_state_vector_id,
    binding_lifecycle_state: binding.lifecycle_state
  }] or deny(EFFECT_DEFAULT_MISSING)

domain_restriction = exact_if_object_key_nonzero_else_default_restriction(
  restriction_set_ref_id: domain.effective_restriction_set_ref_id,
  profile_generation_ref_id: process.active_profile_generation_ref_id,
  effect_family: effect.family, operation: effect.operation,
  composite_atom_id: atom.atom_id, exact_object_key_id: object_key)
process_response = exact_if_object_key_nonzero_else_default_response(
  response_set_ref_id: process.effective_response_set_ref_id,
  profile_generation_ref_id: process.active_profile_generation_ref_id,
  effect_family: effect.family, operation: effect.operation,
  composite_atom_id: atom.atom_id, exact_object_key_id: object_key)
domain_response = exact_if_object_key_nonzero_else_default_response(
  response_set_ref_id: domain.effective_response_set_ref_id,
  profile_generation_ref_id: process.active_profile_generation_ref_id,
  effect_family: effect.family, operation: effect.operation,
  composite_atom_id: atom.atom_id, exact_object_key_id: object_key)

exact_object_floor = initialized_neutral_floor
if effect_requires_exact_object(effect.family, effect.operation):
  require object_key != 0
  object_identity = resolve_exact_object_generation_or_deny(effect_context)
  object_floor_state = exact_object_floors[ExactObjectFloorKeyV1 {
    exact_object_key_id: object_key,
    exact_object_generation: object_identity.object_generation,
    effect_family: effect.family,
    operation: effect.operation
  }] or deny(EXACT_OBJECT_FLOOR_MISSING)
  require object_floor_state.state == ACTIVE
  require object_floor_state exact lifetime/template/generation/ref ownership
          matches object_identity and current retained generation
  exact_object_floor = object_floor_state.floor

exact_socket_or_channel_floor = initialized_neutral_floor
if effect_requires_socket_or_channel(effect.family, effect.operation):
  channel = resolve_exact_socket_or_channel_generation_or_deny(effect_context)
  channel_floor_state = exact_socket_or_channel_floors[
    ExactSocketOrChannelFloorKeyV1 {
      exact_socket_or_channel_key_id: channel.exact_socket_or_channel_key_id,
      exact_socket_or_channel_generation:
        channel.exact_socket_or_channel_generation,
      current_actor_authority_domain_id: process.authority_domain_id,
      effect_family: effect.family,
      operation: effect.operation
    }
  ] or deny(EXACT_SOCKET_OR_CHANNEL_FLOOR_MISSING)
  require channel_floor_state.state == ACTIVE
  require channel_floor_state exact lifetime/template/generation/ref ownership
          matches channel and current actor
  exact_socket_or_channel_floor = channel_floor_state.floor

binding_lifetime_floor = binding_lifetime_floors[BindingLifetimeFloorKeyV1 {
  binding_id: binding.binding_id,
  binding_nonce: binding.binding_nonce,
  lifecycle_state: binding.lifecycle_state,
  effect_family: effect.family,
  operation: effect.operation
}] or deny(BINDING_LIFETIME_FLOOR_MISSING)

pending_exec_response = neutral_response
if process.exec_guard_state != NONE:
  require process.pending_exec_id is present
  pending_exec = pending_exec_map[process.pending_exec_id]
  require pending_exec.pending_exec_id == process.pending_exec_id
  require pending_exec.task_cookie == label.task_cookie
  require pending_exec.process_state_id == process.process_state_id
  require pending_exec.source_profile_generation_ref_id ==
          process.active_profile_generation_ref_id
  require pending_exec.pending_exec_response_set_ref_id ==
          process.pending_exec_response_set_ref_id
  require pending_exec.exec_attempt_sequence == current task attempt sequence
  require pending_exec state is legal for the exact process guard according to
          the guard/state table below
  require process.pending_exec_response_set_ref_id is nonzero
  pending_exec_response = exact_if_object_key_nonzero_else_default_response(
    response_set_ref_id: process.pending_exec_response_set_ref_id,
    profile_generation_ref_id: process.active_profile_generation_ref_id,
    effect_family: effect.family, operation: effect.operation,
    composite_atom_id: atom.atom_id, exact_object_key_id: object_key)

require every referenced SetRefV1 is the expected kind, belongs to the current
        node label epoch, and is ACTIVE or RETIRING for this retained holder

result = intersect_physical(
  base, domain_restriction,
  process_response, domain_response,
  exact_object_floor, exact_socket_or_channel_floor,
  pending_exec_response, binding_lifetime_floor)
```

The exec guard/state join is closed rather than a string-name comparison:

| `ProcessSecurityStateV1.exec_guard_state` | Permitted `PendingExecV1.state` | Effect result while guard exists |
| --- | --- | --- |
| `NONE` | no `pending_exec_id`; `PRE_PONR_FAILED` and `SUCCESS` records may exist only as released evidence | ordinary lookup without pending floor |
| `EXEC_PREPARING` | exactly `PREPARING` | loader-budget effects only; all other protected effects deny |
| `EXEC_COMMIT_PENDING` | exactly `COMMIT_PENDING` | loader-budget effects only; all other protected effects deny |
| `EXEC_OUTCOME_UNKNOWN` | `COMMIT_PENDING`, `POST_PONR_FATAL`, or `OUTCOME_UNKNOWN` | fail-closed pending response floor; no source-role authority |

Every other pair is `EXEC_GUARD_PENDING_STATE_MISMATCH` and denies. In
particular, `PRE_PONR_FAILED` and `SUCCESS` cannot authorize a non-`NONE`
guard. `POST_PONR_FATAL` is a pending-record state, not a process-guard enum;
the process remains `EXEC_OUTCOME_UNKNOWN` until qualified cleanup.

The last physical lowering is explicit about rollout mode. A prior stacked-LSM
denial, missing protected identity, corrupt/missing authority state, a hard
binding lifetime floor, or an installed emergency response floor is a
`HARD_SAFETY_DENY` in both modes. In `PROTECT`, a policy-derived denial is
returned as its errno. In `OBSERVE`, and only for a decision row marked
`SIMULATABLE_POLICY_DENY`, the hook returns allow, records the exact
`WOULD_DENY` cell and leaves transitions/responses unapplied. An observe policy
cannot simulate away `TERMINATING`, stale nonce, missing label, set corruption,
or an already installed response. The mode-lowering acceptance case runs the same projected-
token open under both modes: observe opens and emits `WOULD_DENY`; protect
returns `EACCES`. Its stale-binding control returns `EACCES` in both.

`locked_copy_*` copies the fixed authority fields and version while holding
that one value's spin lock; it never copies the lock itself and never nests a
process, domain, entry, binding, object, or socket lock. The process recheck
closes a concurrent domain-pointer/role/state change. Continuing contention
after one full retry denies. A domain transition after the copied domain
snapshot linearizes after this ordinary decision; publication and sensitive-
access operations additionally use the same domain lock in their reservation/
transition commit. `STATE-THREAD-RACE-001` pauses writers after each tuple
field in process/domain/entry state and proves readers see only complete old or
complete new tuples—never a new role with an old state/set reference.

`intersect_physical` returns `DENY` if any input denies; otherwise it returns
`AUDIT_ALLOW` if any input requires audit and all inputs permit; otherwise it
returns `ALLOW`. Negative sets can never grant. Object/socket floors are read
on every operation, after exact target resolution, so a previously computed
base allow cannot bypass a later taint or containment state.

`DECISION-SET-GOLDEN-001` is corrected accordingly: its generation-42 and
generation-43 rows use distinct global reference IDs even when two profile
owners both call their generation “42”; it includes executable default rows,
both process and domain response refs, and a multi-axis token/persistent-file
atom. Its former cache-deletion and `CLEANUP_ONLY` branches are retained test
ideas but are replaced by (a) rejection of any nonzero V1 cache ID and (b)
exact cleanup-operation allow plus adjacent non-cleanup deny. N/N+1 map
capacity, missing default, unknown atom, stale/non-active descriptor, wrong
profile binding, and deleted generation membership all deny.

##### Abandoned design: mutable generation and “current socket owner” shorthand

The original logical-map sketch contained these exact lines:

```text
protected_cgroup_bindings:
  live cgroup key -> execution set, profile generation, lifecycle, mode

socket_labels:
  socket storage -> creator/current process, role, generation, destination,
                    flow identity, response state
```

They are retained here but abandoned as an implementation contract. A binding
must distinguish the active generation for new admissions from retained pinned
generations for live tasks/sockets. A socket has immutable acquisition and
lifetime provenance but no single mutable “current process”: duplicated,
inherited, or passed descriptors can be used concurrently by several actors,
and every operation evaluates its actual current task/domain state. The
normative map entries immediately above and the pinning/socket algorithms below
replace the shorthand without erasing it.

#### Policy-generation pinning and retirement

`binding.active_profile_generation_ref_id` applies to **new** entries and policy objects. An
existing task, pending exec, socket, or response plan evaluates against its
own pinned generation as long as that generation is in the binding's retained
set. Activating generation 43 must not invalidate a live generation-42 task.

```text
BindingGenerationStateV1 {
  active_profile_generation_ref_id
  retained[] {
    profile_generation_ref_id
    task_refs
    socket_refs
    file_and_shared_object_refs
    authority_domain_refs
    derived_kernel_capability_refs
    vma_and_publication_refs
    checkpoint_restore_refs
    pending_entry_and_exec_refs
    response_plan_refs
    state: ACTIVE | RETIRING
  }
}

GenerationReferenceClassV1 = TASK | SOCKET | FILE_OR_SHARED_OBJECT |
  AUTHORITY_DOMAIN | DERIVED_KERNEL_CAPABILITY | VMA_OR_PUBLICATION |
  CHECKPOINT_RESTORE | PENDING_ENTRY_OR_EXEC | RESPONSE_PLAN

GenerationReferenceTombstoneV1 {
  reference_owner_id: Id128
  reference_owner_generation: u64
  profile_generation_ref_id: u64
  reference_class: GenerationReferenceClassV1
  owned: bool
  acquisition_transition_version: u64
  release_transition_version?: u64
}
```

Every live owner that can still interpret or enforce generation-specific
meaning owns exactly one typed tombstone and increments exactly one matching
counter before publication/use. Final destruction or complete held iterator
reconciliation CASes `owned=true -> false` and decrements once. Retirement
requires every counter above to be zero, no owned tombstone in the complete
iterator/WAL reconciliation, and the BPF grace period. A generic “object ref”
that cannot identify its class or final-lifetime proof is not sufficient.

New roots pin the active generation at admission. Fork/exec retains the
process's pinned generation unless an explicit, synchronously committed
generation-transition rule admits migration. A socket pins the generation
selected by its declared lifetime policy; merely switching the workload
generation never rewrites an established socket's meaning.

##### Abandoned design: live process generation migration in Version 1

The retained migration exception has no safe transaction for new/old
generation refs, process/domain state, thread readback and concurrent
retirement. Updating the process first can reference a generation whose ref was
not acquired; updating the ref first can leak or race failure. Version 1
therefore **does not migrate a live process**. Every existing process, its
native forks and its execs remain pinned to
`ProcessSecurityStateV1.active_profile_generation_ref_id`; only a newly admitted
external root selects `binding.active_profile_generation_ref_id`. Sockets/objects follow their
declared birth lifetime as already specified.

A future migration protocol is a new approved capability: freeze/quiesce the
complete process/domain; acquire all new task/socket/domain generation refs;
hold all old refs with a migration lease; install `MIGRATION_PENDING` whose
authority is old-intersect-new; update every process and any separately
approved future cache (none exists in Version 1); read back
threads/domains/objects; activate; and release old refs only at their original
lifetime/reconciled zero. Fault injection is required after every ref/state
write. Until that protocol exists, any source rule requesting live migration is
`CFG_LIVE_GENERATION_MIGRATION_UNSUPPORTED`.

Retirement is:

1. atomically switch the active pointer after inactive maps and probes pass;
2. mark the old generation `RETIRING` and reject new references to it;
3. decrement reference counters at verified task/socket/pending/response end;
4. reconcile counters with BPF iterators and userspace durable state;
5. after all counters are zero, wait the required BPF RCU/grace period;
6. remove maps and record a retirement artifact.

Emergency response restrictions are generation-independent and therefore
continue to apply while a workload generation changes.

##### Abandoned design: label generation must equal active generation

The later compact algorithm says to deny when a label's generation disagrees
with the binding. Read as strict equality to `active_generation`, that is
wrong and contradicts `INV-POLICY-002`. The check is superseded by:

```text
require label.execution_set_id == binding.execution_set_id
require label.node_boot_id == current_node_boot_id
require label.label_epoch == current_label_epoch
process = process_state_map[label.process_state_id]
require process is ACTIVE and identity/epoch match label
require binding_retained_generations[
          {binding.binding_id, process.active_profile_generation_ref_id}]
        == {binding.binding_nonce, binding.lifecycle_generation,
            ACTIVE | RETIRING for this holder}
lookup every task decision in
       tables_by_profile_generation_ref[process.active_profile_generation_ref_id]
require binding_retained_generations[
          {binding.binding_id, socket.profile_generation_ref_id}]
        == {binding.binding_nonce, binding.lifecycle_generation,
            ACTIVE | RETIRING for this holder}
```

**Practical test.** Task T and socket S start on 42. Activate 43. T continues
to use tables 42, S follows its declared generation-42 lifetime, and a new root
N uses 43. After T exits and S closes, reconciliation reaches zero, the grace
period completes, and only then may maps 42 disappear.

The socket schema deliberately has no mutable “current process owner.” A
socket or duplicated fd may be used concurrently by several processes. Every
connect/send/receive/ioctl operation reads the current actor's `TaskLabel` and
`ProcessSecurityState` independently and intersects that authority with the
socket's immutable provenance/lifetime restrictions. `SCM_RIGHTS`, `dup`,
fork, and a successful use never transfer ownership. The socket suite passes
one socket to two roles that concurrently send/receive/close/duplicate it and
proves each operation is decided for its actual actor without racing a
last-user field.

#### Cgroup binding identity, reuse, and task placement

The cgroup key must survive ancestor placement and cgroup v2 layout variation.
The node binder records the kernel cgroup ID, a generation/live interval, a
tracker for descendants where needed, the full cgroup path for evidence, and
the container/Pod binding. A bare cgroup ID recovered after deletion is not
enough to revive a binding.

`exact_current_cgroup_key()` means the following concrete object, not merely
the numeric value returned by `bpf_get_current_cgroup_id()`:

```text
CgroupBindingIdentity {
  node_boot_id
  kernel_cgroup_id
  binding_nonce: 128 random bits
  cgroupfs_mount_identity
  cgroup_inode_and_generation_when_available
  opened_cgroup_fd_identity
  live_interval { opened_boottime_ns, tombstoned_boottime_ns? }
}
```

The preferred target uses cgroup-local BPF storage tied to the live kernel
cgroup object and populated/reconciled through the opened cgroup fd. Its value
contains `binding_nonce` and execution-set ID. A task label stores the same
nonce, so numeric cgroup-ID reuse produces a mismatch instead of reviving an
old binding. A fallback map keyed by numeric ID is eligible only if Phase 0
proves synchronous cgroup release/tombstone ordering against reuse; otherwise
it is observation-only. Paths are explanatory and never the hot-path identity.

**Reuse test.** Delete protected cgroup C, force allocator churn until its
numeric ID is reused, then start an unrelated task. The new live cgroup object
has no old local storage/binding nonce. Neither the old task label nor the
old response key can match it, even if the displayed path and numeric ID are
identical.

##### Correction: practical cgroup reuse qualification

The test above is not a practical black-box requirement for the full exported
64-bit BPF cgroup ID. Linux's kernfs ID includes a cyclic low component and a
generation component, so forcing a complete-value collision during an ordinary
test is unrealistic. The baseline identity is `(node_boot_id, full u64 BPF
cgroup ID, live interval)`; cgroup-local storage plus `binding_nonce` is the
stronger live-object tier when the exact kernel/map/helper path is qualified.

The executable test deletes C, creates C2 at the same path, verifies a distinct
full ID/live object and no inherited binding/storage, then injects a stale-map
entry or nonce mismatch through the test harness to exercise the theoretical
collision path. “Allocator churn eventually reproduces the same full ID” is
abandoned as a release gate.

##### Exact cgroup-storage type and task placement expectation

“Cgroup-local BPF storage” above means `BPF_MAP_TYPE_CGRP_STORAGE`: its key is
an opened cgroup fd in userspace and its value is attached to the live cgroup
object. It does **not** mean legacy `BPF_MAP_TYPE_CGROUP_STORAGE`, whose
lifetime/key semantics are associated with cgroup-program attachments and
which is not the Mithril identity mechanism. Phase 0 probes the exact map type,
userspace create/update/read behavior, and helper availability from every
program type that consumes it. The qualified fallback is explicitly
`(node_boot_id, full_u64_cgroup_id, live_interval)` plus synchronous
tombstones; a bare number remains invalid.

The canonical label/state schemas include an expected placement:

```text
TaskPlacementExpectationV1 {
  protected_root_binding_id
  protected_root_binding_nonce
  allowed_descendant_policy_id
}

TaskLabel/ProcessSecurityState {
  ...
  task_placement_expectation
}

SocketProvenanceV1 {
  ...
  creator_placement_expectation
}
```

A current leaf cgroup need not have asynchronously prepopulated storage. The
bounded descendant index or ancestor walk resolves the live protected **root**,
then the hook reads that root's `BPF_MAP_TYPE_CGRP_STORAGE` and requires its
binding ID/nonce to equal the label expectation. A stale descendant index,
same-path recreation, injected old nonce, moved task, or socket surviving a
tombstoned binding cannot satisfy that equality. Each is a mandatory hostile
fixture; a socket may retain evidence after tombstone but receives the
configured restrictive lifetime/response result, not the old allow.

Policy maps are bounded and preallocated where the selected hook cannot safely
allocate. Map exhaustion is a health transition. In protect mode, exhaustion
that prevents identity or a required lookup fails closed for the affected
protected binding; it does not silently evict a live label or rule.

#### Generic pre-effect algorithm

##### Abandoned design: cgroup-first shorthand and ad-hoc state/default lookup

The following compact body is retained as the original control-flow sketch,
but it is not executable Version 1 pseudocode. It resolves cgroup before an
existing task label, compares an immutable label generation to a binding,
reads nonexistent `domain.dynamic_state_bits`, performs an unspecified
`exact_effect_lookup`, and synthesizes `profile.default_for(effect)`. The
canonical implementation is the fully initialized Version 1 decision lookup
under “Canonical Version 1 decision ABI,” preceded by the task-first placement
algorithm under “Abandoned design: resolving cgroup before an existing task
label.” Only the retained ordering rule—fix the physical decision before
best-effort evidence emission—survives this sketch.

```text
decide(effect_context):
    if effect_context.prior_lsm_result != 0:
        best_effort_emit(STACKED_DENIAL)
        return prior_lsm_result

    binding = protected_cgroup_bindings.lookup_current_ancestor()
    if binding is absent:
        return evaluate_explicit_host_policy_or_allow()

    if binding is expired, tombstoned, or outside its live interval:
        return deny(IDENTITY_STALE)

    label = task_storage.current()
    if label is absent:
        if effect is executable transition:
            label = atomically_claim_pending_entry()
        if label is still absent:
            return deny(PROTECTED_TASK_UNLABELED)

    if label.execution_set_id, generation, epoch, or node boot disagrees
       with binding:
        return deny(IDENTITY_BINDING_MISMATCH)

    if response_roots matches label.process or any bounded ancestor:
        return evaluate_response_restriction(effect)

    object = classify_effect_object(effect_context)
    if object is unknown and profile requires exact classification:
        return deny(REQUIRED_OBJECT_UNKNOWN)

    process = process_state_map[label.process_state_id]
    domain = authority_domain_map[process.authority_domain_id]
    rule = exact_effect_lookup(process.active_role_id, effect, object,
                               process.dynamic_state_bits,
                               domain.dynamic_state_bits,
                               binding.lifecycle)
    decision = rule or profile.default_for(effect)

    if decision allows/audits:
        apply atomic dynamic-state transition

    best_effort_emit(decision, exact identity, object, generation,
                     classifier quality, coverage counters)
    return decision.errno_or_prior_result
```

`best_effort_emit` reserves a ring record only after the decision is fixed.
Failure increments a per-CPU loss counter visible to the collector. The
decision path never waits for Rust, the central service, DNS, Kubernetes, an
LLM, or provider audit.

##### Correct stacked-LSM result and evidence semantics

The `ret` argument seen by a BPF LSM program must be preserved when nonzero;
it represents a preceding BPF LSM program in that hook chain. It does not prove
Mithril will observe every SELinux, AppArmor, Smack, or other static-LSM denial.
Kernel integer-hook dispatch can stop on an earlier denial before a later
program runs, depending on hook/LSM ordering.

Therefore `best_effort_emit(STACKED_DENIAL)` is exact only when Mithril actually
executes with a nonzero prior BPF return. Traditional-LSM denials come from
their authoritative audit/evidence adapters when enabled and join by the proof
available there. If neither Mithril's hook nor the other LSM's audit is covered,
the syscall may still be physically denied, but Mithril reports an evidence
gap rather than inventing an event.

**Stacking test.** On every advertised LSM ordering, configure SELinux/AppArmor
and an earlier BPF program to deny separate fixture objects. Record whether the
Mithril hook executes, verify it never changes a prior denial, ingest the
traditional audit record where available, and publish the exact evidence
coverage in the platform manifest.

##### Abandoned design: resolving cgroup before an existing task label

The compact algorithm's early “binding absent -> host allow” is unsafe when a
labeled protected task is moved out of its cgroup. A process must not escape by
moving itself, being moved, or using `clone3(CLONE_INTO_CGROUP)` and then
reaching a cgroup lookup that says “not protected.” That ordering is
abandoned.

The normative lookup order is:

```text
decide(effect_context):
    label = task_storage.current()
    current_cgroup = exact_current_cgroup_key()

    if label exists:
        require label boot/epoch are current
        binding = binding_by_execution_set[label.execution_set_id]
        require binding exists and is live
        process = process_state_map[label.process_state_id]
        require process is ACTIVE and identity/epoch match label
        require binding_retained_generations[
                  {binding.binding_id,
                   process.active_profile_generation_ref_id}]
                == {binding.binding_nonce, binding.lifecycle_generation,
                    ACTIVE | RETIRING for this holder}
        domain = authority_domain_map[process.authority_domain_id]
        require domain is ACTIVE and identity/epoch match process

        placement = protected_cgroup_index[current_cgroup]
        if placement does not name label.execution_set_id and an allowed
           descendant interval:
            deny(PROTECTED_TASK_PLACEMENT_MISMATCH)

        # Never return host allow for an already protected label.
        evaluate response, object, and
                 tables_by_profile_generation_ref[
                   process.active_profile_generation_ref_id]
        return physical result

    placement = protected_cgroup_index[current_cgroup]
    if placement absent:
        placement = bounded_verified_ancestor_fallback(current_cgroup)
    if placement absent and traversal was complete:
        return evaluate_explicit_host_policy_or_allow()
    if placement unknown because traversal/index coverage failed:
        apply host/profile coverage posture; never claim protected coverage

    binding = resolve live binding from placement
    if current hook is qualified external-root exec:
        attempt exact one-use entry claim
    if label remains absent:
        deny(PROTECTED_TASK_UNLABELED)
```

`protected_cgroup_index` is maintained from cgroup lifecycle evidence and maps
every live protected root and known descendant cgroup to the exact binding and
live interval. The fallback is capped by the capability manifest's
`MAX_CGROUP_ANCESTORS`; reaching the cap is `CGROUP_ANCESTOR_OVERFLOW`, not a
negative lookup. Strict admission rejects a workload whose measured hierarchy
can exceed the qualified limit unless the exact index covers it.

**Practical tests.** In `ID-CGROUP-ESCAPE-001`, a labeled worker is moved to a
host cgroup and opens its token: the label is found first and the open is
denied as a placement mismatch. In `ID-CLONE-CGROUP-002`, an outside task uses
`clone3(CLONE_INTO_CGROUP)` to place a child directly into the protected
cgroup. The child either receives an explicitly admitted external-root label
before its first protected effect or the first token/exec/socket effect is
denied. Neither case may return through the host-allow branch.

### Effect-Family Algorithms

#### Normative mount and network-namespace identity

The later names `mount_view_generation` and
`network_namespace_generation` are logical placeholders, not kernel fields.
Version 1 defines them as:

```text
MountViewIdentityV1 {
  node_boot_id
  mount_namespace_inum
  mount_namespace_binding_nonce
  mount_namespace_live_interval
  topology_epoch
}

LiveMountObjectV1 {
  mount_view_identity
  unique_mount_id_when_qualified
  legacy_mount_id?
  superblock_and_filesystem_identity
  mount_live_interval
}

NetworkNamespaceIdentityV1 {
  node_boot_id
  netns_cookie
  netns_live_interval
  capture_mechanism
}
```

`LiveMountObjectV1` also contains security semantics, not only identity:

```text
MountSecurityViewV1 {
  mount_root_object_and_subtree
  idmapped_mount_user_namespace_identity?
  readonly
  noexec
  nosuid
  nodev
  atime_and_other_policy-relevant_flags
  propagation: PRIVATE | SHARED(peer_group) | SLAVE(master) | UNBINDABLE
  overlay_options_and_upper/lower/work identities?
}
```

The same inode through an idmapped mount can have different ownership and
file-capability behavior. `mount_setattr`, remount, propagation change, and
overlay option/topology changes advance the topology epoch even when
superblock/inode numbers do not change. A file rule evaluates the exact mount
security view; a `noexec/nosuid/nodev/ro` kernel floor can make the result
stricter but is never assumed from another alias.

`MOUNT-ATTR-001` accesses the same inode through ordinary and idmapped bind
mounts, exercises setuid/file capabilities, toggles ro/noexec/nosuid/nodev with
recursive `mount_setattr`, changes propagation, and varies overlay metacopy/
redirect options. Every change dirties/rebinds topology and no authority
follows the inode into a differently attributed mount.

Userspace holds an namespace fd while binding and assigns the random binding
nonce. The strongest mount tier uses `STATX_MNT_ID_UNIQUE` in userspace and
the corresponding target-kernel unique mount identity where accessible;
legacy mount IDs are reusable and cannot stand alone. `topology_epoch`
increments on every covered mount, unmount, move, pivot, or namespace topology
change. Loss of a required topology event makes exact path/object
classification unknown until reconciliation.

The netns cookie is captured at a qualified program type/helper location and
copied into socket storage; helper availability in one cgroup socket program
does not imply availability in every LSM hook. An alternative CO-RE read must
be separately qualified. A bare namespace inode/display number or userspace
path is contextual.

**Namespace tests.** Unmount/remount an allowed path with a different object,
move a mount, pivot root, setns into another view, delete/recreate a mount or
network namespace, and reuse displayed namespace/mount numbers. Every live
decision either resolves the new nonce/unique ID/topology epoch or fails the
required classifier closed. No old file/socket allow follows the reused name.

##### Synchronous mount-topology invalidation

A userspace watcher that increments `topology_epoch` after a successful mount
leaves a race in which another task can authorize a file against stale
topology. That interpretation is abandoned. Every topology-changing operation
claimed as covered has a qualified pre-effect hook/floor and a post-result
reconciliation owner:

```text
MountNamespaceStateV1 {
  mount_view_identity_without_epoch
  topology_epoch
  pending_topology_changes
  state: CLEAN | DIRTY | RECONCILING | COVERAGE_UNKNOWN
  last_reconciled_snapshot_digest
}

before allowing mount/umount/move_mount/open_tree mutation/pivot_root/
fsconfig or another covered topology change:
    resolve the target/current mount namespace
    atomically increment topology_epoch and pending_topology_changes
    set state = DIRTY

on any strict object decision in that namespace:
    if state != CLEAN: deny(MOUNT_TOPOLOGY_DIRTY)
    classify against the current epoch and live mount-object identity

after the topology syscall result:
    reconcile through held namespace fd + mount snapshot/exact kernel evidence
    decrement pending count
    set CLEAN only when count == 0 and snapshot/identities agree
```

The pre-effect transition applies regardless of actor label: a host task that
uses `setns` and mutates a protected namespace dirties that namespace too. A
failed mount may conservatively churn the epoch; correctness does not depend on
rolling it back. If an enabled mount-API variant has no qualified pre-effect
invalidation, strict mount-aware classification is unsupported or that variant
is denied by a seccomp/capability floor.

**Topology race tests.** A host task joins the workload mount namespace and
mounts over an allowed path; a worker continuously opens it. Repeat with
`move_mount`, `pivot_root`, new mount API calls, a failed mount, and two
concurrent changes. If the open linearizes before DIRTY it sees the old exact
object; after DIRTY it fails closed until reconciliation. No open during a
DIRTY interval may be allowed from a cached path/object rule, and the final
epoch must remain advanced even after the failed-mount fixture.

##### Linearizable topology reconciliation commit

The retained pseudocode's generic “after syscall result, decrement” cannot
depend on a ring event or an unversioned Rust write. The kernel pre-hook
allocates a bounded `mutation_id`, increments `(epoch,pending)`, and records the
attempt before allow. A qualified return/fexit path marks that exact mutation
complete in the kernel map regardless of whether rich evidence is emitted. A
missing completion keeps the namespace DIRTY.

Rust reconciles only after reading `(epoch=E,pending=0,state=DIRTY)`. It holds
the namespace fd, snapshots topology, resolves/installs object tables, reads
them back, then performs one compare-and-swap:

```text
CAS MountNamespaceState
    expected = (epoch=E, pending=0, DIRTY, snapshot_base)
    desired  = (epoch=E, pending=0, CLEAN, new_snapshot_digest)
```

A new mutation increments epoch before its effect and makes the CAS fail. Lost
completion, daemon death, or mutation-map exhaustion stays DIRTY until a
separately authorized freeze/quiescent full rescan proves all tasks stopped and
commits a new epoch; no timeout guesses success.

`MOUNT-CAS-002` drops the result evidence, kills Rust mid-snapshot, runs two
concurrent mounts, inserts a mount between snapshot and CAS, fails a mount, and
exhausts mutation slots. Every stale CAS fails and strict opens remain denied.
Only the exact no-pending snapshot becomes CLEAN.

The snapshot mechanism is a platform capability, not the phrase “exact kernel
evidence.” Preferred targets qualify `listmount(2)`/`statmount(2)` together with
`STATX_MNT_ID_UNIQUE` while holding mount-namespace and root fds. The fallback
parses the complete `/proc/<pid>/mountinfo` only while the namespace/task set is
held or quiescent, then verifies every resolved mount/root with
`openat2`/`statx`; it records lower identity quality. Truncation, escaped mount
names, or disappearing namespace fails reconciliation.

The async Rust runtime never calls `setns` on a shared executor thread. Where a
namespace-local read is unavoidable, it launches a short-lived measured helper
mode of the same Mithril binary, passes only held fds over a private socket,
produces a sealed canonical snapshot, and exits. It owns no maps, events, WAL,
or policy state and is not another gatherer.

`MOUNT-SNAPSHOT-004` covers escaped names, stacked/hidden mounts,
lazy-detached mounts, mountinfo larger than a page, namespace/task exit during
snapshot, and a kernel without `statmount`. The strong tier uses stable unique
IDs; fallback either proves its declared lower tier under quiescence or remains
DIRTY.

##### Propagation, automount, and referral topology changes

A caller-namespace mount syscall record does not cover a mount replicated by
shared/slave propagation into other namespaces, nor an autofs/NFS referral
instantiated during pathname lookup. Assuming all topology changes originate
as a direct syscall in the protected namespace is abandoned.

The Version 1 full tier validates at `ROOTFS_READY_HELD` that protected mount
trees are private and contain no unqualified automount/referral points. It
rejects bidirectional/host-to-container propagation for that tier unless a
signed exception selects a separately qualified mechanism. Such a mechanism
must mark **every affected protected namespace DIRTY before visibility**, with
bounded fan-out; overflow sets a global affected-set fail-closed bit. An
automount/referral needs an equivalent synchronous kernel topology point or is
denied/unsupported.

`MOUNT-PROPAGATION-003` propagates a host mount into rslave/bidirectional Pod
mounts, exercises recursive shared peers, triggers autofs during open and an
NFS referral, and overflows the fan-out bound while workers race file opens.
The private baseline rejects the topology at admission. The extended tier
dirties every affected namespace before any new object is authorized; overflow
keeps all affected opens denied.

#### Executable images and commands

Mithril governs executable transitions, not command strings alone.

The executable object key should contain the strongest target-kernel evidence
available:

```text
ExecutableObjectKey {
  mount_view_generation
  mount_id
  superblock/device identity
  inode number
  inode generation/version where available
  file type and executable mode
  immutable image-layer/file-manifest identity if pre-resolved
  IMA/fs-verity/content digest if available without a decision-path race
  overlay origin/copy-up state
  deleted_or_unlinked
  memfd/anonymous class
}
```

Userspace resolves immutable image files into object keys when binding the
profile. The BPF decision compares the live candidate file object to the
compiled key. It does not synchronously hash an arbitrary executable in every
exec hook. Mutable executable objects require an explicit mutable-code rule or
an integrity mechanism such as fs-verity/IMA; matching a pathname is not
equivalent.

##### Abandoned design: undefined mount generation and reusable inode key

`mount_view_generation`, bare `mount_id`, and “inode generation/version where
available” in the retained key are placeholders, not a portable authorization
identity. They are superseded by one file-object schema used by exec, file,
artifact, and device classifiers:

```text
FileObjectIdentityV1 {
  node_boot_id
  mount_view: MountViewIdentityV1
  live_mount: LiveMountObjectV1
  filesystem_identity {
    fs_type
    filesystem_uuid_or_target_proven_superblock_identity
    superblock_live_interval
  }
  inode_number
  incarnation {
    mechanism: FS_GENERATION | I_VERSION | IMMUTABLE_LAYER_OBJECT |
               FS_VERITY_DIGEST | IMA_MEASUREMENT | NONE
    value?
  }
  overlay {
    layer: LOWER | UPPER | MERGED | NOT_OVERLAY
    origin_object?
    current_upper_object?
    copy_up_epoch?
  }
  file_type_mode
  deleted_or_unlinked
  live_object_interval
  quality: IMMUTABLE_VERIFIED | LIVE_EXACT | REUSABLE_CONTEXTUAL | UNKNOWN
}
```

The exact incarnation mechanisms are filesystem- and kernel-qualified. An
inode number with `NONE` is reusable context and cannot authorize mutable
code. Approved executable authority then requires a signed immutable image
layer object, fs-verity/IMA identity, a held exact object/fd with a qualified
live interval, or an explicit mutable-code rule with tighter revalidation. An
overlay copy-up creates a new current object and invalidates a lower-only key.

Holding an fd proves object lifetime, not immutable contents: another fd can
truncate, write, mmap-write, reflink/replace backing state, or use direct I/O
while the first remains open. The retained “held exact object/fd” option is
therefore abandoned if used alone for immutable code. Immutable-code authority
requires a verified immutable image layer with current overlay state,
fs-verity/IMA appraisal, a correctly sealed memfd (including write/future-write
seal semantics), or an exclusive integrity lease whose write/truncate/mmap/
direct-I/O paths synchronously advance an epoch and deny mutation. Everything
else is explicit `MUTABLE_CODE` with narrower authority and invalidation.

`FILE-CONTENT-RACE-002` holds the binder's fd while a second fd writes,
truncates, mmap-writes, and attempts direct I/O between parse and `bprm`.
Unsealed memfd and interpreter substitution are included. Every mutation must
invalidate/deny exec; the sealed/verified object remains the positive control.

`FILE-IDENTITY-001` authorizes executable A, unlinks it, forces inode reuse for
different bytes, bind-mounts/renames it, and races overlay copy-up. The changed
object never inherits A's exec rule. Positive controls prove the same immutable
layer object remains authorized through a rename/bind mount because the exact
mount/object provenance—not pathname text—matches.

Required cases:

- `execve`, `execveat`, `fexecve`, scripts and shebang interpreters;
- dynamic linker and interpreter transitions;
- memfd, deleted file, `/dev/shm`, `/run/shm`, and unlinked executable images;
- overlay copy-up and mount replacement;
- a renamed or bind-mounted approved binary;
- an approved pathname whose inode/content changed;
- non-leader thread exec and de-threading; and
- forked code that performs effects without exec.

`python -> sh` and `python -> curl` are denied at the executable edge when the
role lacks those target object keys. Python importing a module or evaluating a
template in-process creates no executable transition; file/code mapping and
later effects remain the control points.

#### File and credential objects

File policy is role, operation, and object based:

```text
FileEffectKey = (
  role_id,
  operation: open_read | open_write | permission | mmap_exec |
             truncate | create | rename | link | unlink | ioctl,
  object_class,
  live_file_object_key,
  lifecycle_state,
  dynamic_state
)
```

##### Correct keys for filesystem namespace mutation

One `live_file_object_key` cannot represent operations whose target does not
yet exist or which have two endpoints. Version 1 compiles separate physical
keys:

```text
CreateKeyV1  = (actor, mount_view, parent_dir_object,
                bounded_name{length,bytes,digest}, object_type, mode,
                open/create/resolve flags)
LinkKeyV1    = (actor, source_object, destination_parent,
                destination_name, flags)
RenameKeyV1  = (actor, source_parent, source_object,
                destination_parent, destination_existing_object?,
                destination_name, RENAME_NOREPLACE|EXCHANGE|WHITEOUT|other)
UnlinkKeyV1  = (actor, parent_dir, victim_object, FILE|DIRECTORY)
SetattrKeyV1 = (actor, object, TRUNCATE|MODE|UID|GID|XATTR|FILE_CAPABILITY,
                bounded_new_value_class)
```

Authorization uses resolved live parent/mount/object identities. Path strings
are bounded evidence and selector input, never the only authority. Names beyond
the qualified bound, hash collisions, unresolved parents, or unknown flags
follow the classifier-unknown posture. The compiler maps each key to exact
target-qualified `inode_create/mkdir/mknod/symlink/link/rename/unlink/rmdir`,
`inode_setattr/setxattr`, path/file, and open hooks; missing variants are denied
or `UNSUPPORTED`.

`FILE-NAMESPACE-001` covers `openat/openat2(O_CREAT)` from changed dirfds,
symlink and hardlink, `O_TMPFILE` then `linkat`, every rename flag including
exchange/whiteout/noreplace, cross-mount attempts, overlay copy-up,
unlink-while-open, chmod/chown/truncate, xattrs/file capabilities, and a name
beyond the extraction bound. Each forbidden namespace/result object remains
absent/unchanged. Creating an ordinary declared scratch file is the positive
control.

Primary hooks include BPF LSM `file_open`, `file_permission`, `mmap_file`, and
selected inode/path hooks required to cover creation, rename, link, unlink,
and mount-view changes. The compiler must state which operation is actually
prevented by which hook; a later close/write tracepoint is evidence only.

##### Correct mapped-file operations and preexisting mappings

The retained `mmap_exec` operation omits credential reads through
`mmap(PROT_READ)` and shared-file mutation through
`mmap(PROT_WRITE|MAP_SHARED)`. Version 1 compiles `MMAP_READ`, `MMAP_WRITE`, and
`MMAP_EXEC` independently at `mmap_file`, then covers permission additions at
`file_mprotect` and qualified `pkey_mprotect`/architecture variants. A
transition adding write or execute—including `RX -> RWX`—is re-evaluated;
W^X policy may deny mappings that are writable and executable simultaneously.

Mappings created before attachment or before a new response cannot be
retroactively denied as though their bytes were never accessible. Iterator/VMA
reconciliation records them as `PREEXISTING_MAPPING`. Policy may freeze/kill or
restart the exact lineage, deny later `mprotect`/network/file effects, and
report the acquisition interval `UNKNOWN`; it cannot claim a prevented mmap.

“Iterator/VMA reconciliation” is not permission to read `/proc/<pid>/maps`
once and declare the address space complete. The full-support tier performs a
target-qualified BPF task-VMA iterator (`SEC("iter/task_vma")` with
`bpf_iter__task_vma` context), or a target-kernel mechanism proven to provide
the same snapshot properties, over a pidfd-revalidated task set that has been
frozen or otherwise made quiescent. For each VMA it emits:

```text
VmaSnapshotV1 {
  node_boot_id
  process_lineage_id
  shared_mm_identity
  target_start_boottime_ns
  range_start, range_end
  vm_flags
  effective_protection
  backing_file_object_identity?
  anonymous_or_special_class?
  deleted_or_memfd_state?
  snapshot_epoch
}
```

`shared_mm_identity` is snapshot-scoped evidence, never a durable authorization
key:

```text
MmSnapshotIdentityDraftAbandoned {
  node_boot_id
  snapshot_epoch: 128-bit random
  opaque_mm_cookie: nonzero u64 unique within snapshot_epoch
  quality: KERNEL_MM_EQUALITY | UNKNOWN
}
```

While the complete target set is frozen, a target-qualified CO-RE iterator
uses kernel-side `mm_struct` pointer equality only as an internal lookup key and
maps equal pointers to the same opaque epoch cookie. Raw kernel pointers never
leave the program and cannot be stored as graph/authority IDs. `CLONE_VM` and
`vfork` members share the cookie; a normal non-sharing fork has a distinct
`mm_struct`; successful exec replaces the mm and therefore the cookie; final mm
release tombstones its internal snapshot entry. Because the cookie dies with
the epoch, later pointer reuse cannot revive identity.

The task iterator performs a before/after sharer pass over every live task and
emits `(task_cookie, process_lineage_id, pidfd/start-time coordinates,
opaque_mm_cookie)`. The VMA iterator emits the same cookie from each
`vma->vm_mm`. A target where the BPF verifier/program type cannot implement
this internal equality-to-cookie map reports `VMA_MM_IDENTITY_UNSUPPORTED`; it
must not substitute TGID, PID, start time, current cgroup, or a raw pointer.

###### Correction: an `mm_struct *` map key is not private merely because Rust sees a cookie

The retained statement “raw kernel pointers never leave the program” is false
if a BPF map is keyed by the raw `mm_struct *`: any holder of the map fd may
enumerate the key, and verifier acceptance of storing a kernel pointer depends
on the exact program type, privilege state, kernel, and load path. Calling the
key internal does not remove its KASLR-disclosure surface. The universal
pointer-map tier is abandoned.

The preferred full-support tier performs equality in userspace with the Linux
`kcmp` syscall while the target set is held:

1. Enumerate candidate live tasks from the complete task iterator and keep
   pidfds plus start-boottime/task-cookie coordinates. Freeze every currently
   discovered process/domain allowed by the response/admission authority.
2. From the host PID namespace, compare candidates with
   `kcmp(pid1, pid2, KCMP_VM, 0, 0)`. Return `0` means the tasks share the exact
   address space; no ordering value becomes identity. Linux implements this as
   comparison of `task1->mm` and `task2->mm` and subjects both tasks to
   `PTRACE_MODE_READ_REALCREDS` access checks.
3. Assign one random snapshot-epoch cookie to each equality class, run the VMA
   iterator once per class, then repeat task enumeration, pidfd/start checks,
   freeze verification, and every relevant equality comparison before commit.
   Any changed class, new sharer, exit/exec, `EPERM`, `ESRCH`, or syscall error
   makes the negative snapshot incomplete.

The capability probe requires `CONFIG_KCMP` on Linux 5.12 and later; older
supported kernels require the historical `CONFIG_CHECKPOINT_RESTORE` path that
made `kcmp` available. The syscall exists since Linux 3.5, but version alone
does not establish that it was built or that ptrace/Yama/LSM access permits the
comparison. The node probe executes a real same-mm and distinct-mm comparison
under Mithril's production credentials before advertising the tier. The
primary references are the [Linux `kcmp` implementation](https://github.com/torvalds/linux/blob/master/kernel/kcmp.c#L126-L204),
[current `CONFIG_KCMP` definition](https://github.com/torvalds/linux/blob/master/init/Kconfig#L1811-L1819),
and [`kcmp(2)` ABI/history](https://man7.org/linux/man-pages/man2/kcmp.2.html).

A second, explicitly reduced privileged tier may use a raw-pointer equality
map only when the exact object load proves verifier acceptance and all of these
conditions hold: the map is created per snapshot, unpinned, inaccessible
outside the single root-owned loader fd, never exported/enumerated into
evidence, and destroyed before the epoch ends; the platform threat model
records the remaining kernel-pointer/KASLR risk. Rust still receives only the
assigned cookie. Failure of any condition, verifier rejection, or inability to
confine the map returns `VMA_MM_IDENTITY_UNSUPPORTED`; it does not silently
fall back to PID/TGID.

Completeness uses the iterator fd, not the lossy observation ring:

```text
VmaIteratorSessionV1 {
  iterator_session_id: Id128
  snapshot_epoch: Id128
  target_set_digest: DigestV1
  representative_task_cookie: u64
  representative_process_state_id: Id128
  representative_pidfd_and_start_coordinates
  userspace_assigned_mm_class_cookie: Id128
  expected_sharer_task_cookies[]
  state: PREPARED | ITERATING | EOF_VALIDATED | REVALIDATED | COMMITTED |
         INCOMPLETE
}

VmaIteratorSessionIdentityV1 {
  iterator_session_id: Id128
  representative_task_cookie: u64
  representative_start_boottime_ns: u64
}

MmSnapshotIdentityV1 {
  node_boot_id: Id128
  snapshot_epoch: Id128
  userspace_assigned_mm_class_cookie: Id128
  iterator_session_id: Id128
  representative_task_cookie: u64
  representative_start_boottime_ns: u64
  target_set_digest: DigestV1
  quality: KCMP_VM_HELD_AND_REVALIDATED |
           CONFINED_RAW_POINTER_EQUALITY_REDUCED | UNKNOWN
}
```

Rust creates one session and one serialized task-VMA iterator fd for one held
representative task in each `kcmp(KCMP_VM)` equality class. The BPF program is
parameterized by the read-only session/representative identity and emits that
identity on every frame. It does **not** emit or look up a userspace mm cookie,
and it does not store `mm_struct *` in any map. After EOF, Rust repeats pidfd,
start-time, task-set and all relevant `kcmp` comparisons. Only then does Rust
attach `userspace_assigned_mm_class_cookie` to the accepted records and commit
one `MmSnapshotIdentityV1`. A frame for another task/session, concurrent second
reader, failed before/after comparison, or representative exec/exit makes the
session `INCOMPLETE`.

```text
VmaIteratorFrameV1 =
  BEGIN {
    wire_version, VmaIteratorSessionIdentityV1, snapshot_epoch,
    target_set_digest,
    expected_sharer_count, first_sequence=1
  }
  | RECORD {
      sequence, VmaIteratorSessionIdentityV1, task/process IDs,
      range_start, range_end, vm_flags, effective_protection,
      backing_identity_quality:
        EXACT_LIVE_FILE_OBJECT | ANONYMOUS_CLASSIFIED |
        REDUCED_INODE_ONLY | UNKNOWN,
      special_class:
        FILE | MEMFD | ANON_PRIVATE | ANON_SHARED | STACK | HEAP |
        VDSO | VVAR | VSYSCALL | HUGETLB | PFNMAP_OR_IO | OTHER | UNKNOWN,
      backing_file_object_identity?
    }
  | END {
      final_sequence, record_count, sharer_count,
      stream_digest, status: COMPLETE | ITERATOR_ERROR
    }
```

The BPF iterator writes fixed, versioned binary frames with `bpf_seq_write`.
Rust reads until EOF and rejects a partial frame, read error, missing/multiple
BEGIN or END, sequence discontinuity, count/digest mismatch, unknown required
class, target/sharer mismatch, or non-`COMPLETE` end. It then repeats the task
sharer pass while targets remain frozen and commits only if the target-set and
mm-cookie relation are identical. Text `seq_printf` output and the ring buffer
may be diagnostic copies; neither is a completeness oracle.

The retained `END.stream_digest` field is abandoned as BPF output: this
architecture does not define or require a verifier-safe cryptographic digest
implementation in the iterator. The wire `END` carries sequence, counts and
status only. After EOF and framing/count validation, Rust computes
`sha256("MITHRIL-VMA-SNAPSHOT-V1" || accepted canonical frame bytes)` and stores
that digest in the committed snapshot artifact. Restart before commit discards
the epoch. In the preferred `kcmp` tier, session configuration and uncommitted
frames are destroyed with the epoch; there is no mm-cookie BPF map. Only the
explicitly reduced raw-pointer-equality tier destroys its confined per-snapshot
map. The earlier “final mm release tombstones its internal snapshot entry” is
optional cleanup in that reduced tier, not a required final-mm lifetime hook or
durable identity guarantee.

Rust reconciles one shared `mm` exactly once and joins the snapshot to every
live process/domain that references it. The iterator result is accepted only
when the pidfd/start-time target still matches, freeze/quiescence remained in
force, every iterator record and terminal marker arrived without loss or
truncation, and the target set did not change before commit. Failure of any
condition yields `VMA_SNAPSHOT_INCOMPLETE`; it never proves that a forbidden
mapping is absent.

The target set includes every live task that shares the `mm`, even when one
task moved to another cgroup. Rust enumerates sharers before freezing, freezes
every sharer inside its response authority, verifies each relevant cgroup/task
reached the requested quiescent state, enumerates again, and accepts only an
identical sharer set. A sharer outside response authority, an uninterruptible
task that never reaches quiescence, or a newly discovered sharer makes the
negative snapshot incomplete; Mithril may still report each positive VMA it
observed.

`/proc/<pid>/maps` and `map_files` are a reduced observation tier. That tier
checks pidfd/start-time and the relevant `mm` identity before and after the
walk, records a bounded interval, and may prove that an observed mapping
existed. It cannot prove a concurrent negative snapshot. `FILE-VMA-SNAPSHOT-001`
races `mmap`, `munmap`, and `mremap` against reconciliation; covers a shared
`mm`, deleted and memfd-backed mappings, target exit/PID reuse, iterator loss
and truncation, and failed cgroup freeze. The full tier either commits one
complete epoch or returns `VMA_SNAPSHOT_INCOMPLETE`; the procfs tier never
upgrades the negative result.

`FILE-MMAP-001` reads a projected credential through `mmap(PROT_READ)`, writes
an output/host file through `MAP_SHARED`, inherits a mapping across plain
fork, maps before attachment, and tries `RX -> RWX` with `mprotect` and
`pkey_mprotect`. It also covers `sendfile`, `splice`, `copy_file_range`, and
io_uring file paths. The physical oracle distinguishes no bytes delivered/no
file mutation from a preexisting-mapping containment result; an ordinary
read-only dataset mmap remains the positive control.

That list is incomplete for writable-to-executable transitions. A file or
anonymous mapping can be created writable and later changed executable without
a new `mmap_file` decision. Every profile claiming executable-memory control
must also qualify BPF LSM `file_mprotect` and decide transitions whose requested
or resulting protection adds `PROT_EXEC`, including `RW -> RX`, `R -> RX`,
memfd-backed, deleted-file, and anonymous mappings. If `file_mprotect` is
unavailable, the platform manifest must say that post-map executable
transitions are unsupported; `mmap_file` alone is not equivalent.

**Practical test.** The fixture creates an anonymous `RW` page, writes machine
code, calls `mprotect(..., RX)`, and jumps to it. A no-JIT role receives
`EACCES` at the mprotect transition and never executes the marker. The same is
repeated for memfd and deleted-file mappings. An approved JIT role succeeds
only inside its exact memory/lifetime budget.

##### Executable stack and personality coverage

`mmap_file` plus `file_mprotect` still misses executable memory established by
the ELF loader itself. An ELF `PT_GNU_STACK` request and architecture/personality
behavior such as `READ_IMPLIES_EXEC` can produce an executable stack/effective
execute permission without a later userspace `mprotect`. Treating the previous
two hooks as universally complete is abandoned.

The executable classifier parses immutable, bounded ELF metadata before the
exec point of no return and stores it in `ExecutableObject`/
`ImageProvenance`: `PT_GNU_STACK` flags, static/dynamic form, interpreter
identity, architecture, and qualified personality implications. A no-JIT role
rejects an executable-stack image at the exec transition. Unknown format or
unqualified architecture/personality behavior is `UNSUPPORTED`/denied for a
full executable-memory profile, not assumed non-executable.

This parsing is performed by the Rust binder at the held
`ROOTFS_READY_HELD` barrier, not by arbitrary byte parsing inside
`bprm_check_security` (which normally runs before the ELF loader has interpreted
`PT_GNU_STACK`). The binder opens the exact candidate and loader by fd in the
held mount view, validates bounded ELF metadata, and binds the result only to
an immutable `FileObjectIdentityV1`/integrity lease. The BPF exec hook performs
a bounded identity/table lookup. In-hook parsing of mutable ELF content is
abandoned; an unregistered or mutable executable-stack ELF denies under full
exec-memory control.

The race suite mutates/replaces the file after parse but before exec, swaps the
interpreter, and compares sealed with unsealed memfd. Any identity/integrity
epoch mismatch makes the bprm lookup deny.

`MEM-EXEC-001` covers static and dynamic ELFs with executable and
non-executable `PT_GNU_STACK`, anonymous `mmap(PROT_EXEC)`, `mprotect` and
`pkey_mprotect` adding execute, memfd/deleted files, and
personality-mediated effective execute. Each forbidden fixture attempts to
write and run a marker; the marker must remain absent. The allowed compiler/JIT
negative control succeeds only with its exact signed image and memory budget.

Kernel-created executable mappings are a separate allow class. vDSO/vvar,
legacy vsyscall, and architecture signal trampoline/gate mappings may not
traverse ordinary user `mmap` hooks and must not be mislabeled as attacker JIT.
`KernelExecutableMappingClassV1` binds exact architecture, kernel build/BTF,
personality/vsyscall mode, mapping flags/range class, and measured provenance.
Initial VMA reconciliation, exec qualification, and checkpoint restore permit
only the manifest's fixed classes. An unknown kernel-generated executable
mapping is a coverage failure; “allow all anonymous RX” is forbidden.

`MEM-KERNEL-MAP-002` inventories each advertised architecture's vDSO/vvar/
vsyscall/signal-gate behavior across exec, personality modes, and checkpoint
restore. Normal startup succeeds with exact classes, while an extra anonymous
RX mapping with similar shape is denied/unknown rather than inheriting the
kernel exception.

Initial Hugging Face object classes include:

| Object class | Representative resolver | Default conversion-worker rule |
| --- | --- | --- |
| `dataset-input` | admitted job mount/root plus immutable revision when known | read; no execute; write only to declared output |
| `worker-runtime` | immutable image/runtime libraries | read/map according to executable profile |
| `worker-scratch` | exact scratch mount and lifetime | bounded read/write/create; no execute by default |
| `worker-environment-procfile` | `/proc/<pid>/environ` resolved to target task | deny cross-task; self-read requires explicit rule |
| `projected-service-account-token` | Kubernetes projected volume provenance plus Pod/container binding and rotating file identity | deny for conversion role; allow only controller role that demonstrably needs it |
| `cloud-credential-file` | mounted credential volume/provider path provenance | deny unless exact role requires it |
| `other-proc-task` | target task cookie/process plus proc inode/path class | deny inspection absent declared diagnostics |
| `host-filesystem` | mount provenance outside admitted container view | deny |
| `socket-or-device-file` | inode type plus device identity | dispatch to socket/device policy |
| `anonymous-executable-memory` | executable anonymous mapping | deny unless reviewed JIT role |

Projected tokens rotate, so policy cannot pin only one inode forever. The
binder classifies the mounted projected volume and its path/object lifetime;
rotation updates the exact live object set without broadening the directory to
arbitrary files.

##### Correction: rotation cannot wait for an asynchronous inode-set update

If “rotation updates” means userspace notices Kubernetes AtomicWriter's
symlink swap and later replaces an inode allow/deny set, there is a race. That
design is abandoned for strict token protection. The pre-effect classifier
uses exact projected-volume mount provenance plus a bounded relative semantic
path (`token`, `namespace`, `ca.crt`, or configured projected item) in the live
mount view. Inode identities enrich/cache the object but are not the sole
authority.

If the target hook cannot safely prove the relative target within the projected
volume, a role that should not read credentials denies the whole projected
volume class. A role needing one item requires a stronger qualified resolver or
accepts an explicitly broader budget; it does not race a background inode
refresh.

`/proc/<pid>/environ` likewise needs an exact procfs resolver that proves the
target PID namespace/task and joins it to the live task cookie. A textual proc
path is insufficient. If that target resolution is unavailable, the compiler
can conservatively deny the whole proc-environ class but cannot claim a
self-versus-cross-task distinction.

**Rotation test.** Continuously open the token path while AtomicWriter performs
every symlink/data-directory swap, deliberately delay the Rust binder, and
assert every worker attempt denies. Separately recreate a PID in another PID
namespace and prove proc-environ classification never follows the displayed
number.

Opening `/proc/self/environ` is enforceable. Reading the process's already
resident environment with a language API is not. If the role legitimately
holds secrets in memory, file policy alone cannot prevent in-process access;
Mithril must stop the next exfiltration or authority effect and report that
the memory read itself was unobservable.

Already-open descriptors, inherited descriptors, descriptor passing,
`mmap`, `sendfile`, `splice`, shared memory, and `io_uring` are separate
coverage cases. A file-open denial claim cannot be generalized to data already
present in process memory or a descriptor obtained before policy attachment.

##### Actor identity versus an opened file's mount/provenance

Like sockets, a file descriptor retains its own object/mount context. A host
task can open a file through mount namespace A or a lazy-detached mount and
pass it to a container task in mount namespace B. Classifying later read/write/
mmap only against B's current mount view is abandoned.

```text
FileInstanceProvenanceV1 {
  file_instance_id
  exact_file_pointer_cookie_and_live_interval
  file_path_object: FileObjectIdentityV1 from file->f_path
  acquisition_mount_view
  acquiring_actor_role_generation_authority_domain
  open_flags_and_mode
  descriptor_transfer_edges[]
  retained_generation
  response_state
}
```

Every use reads the **current actor** task/process/domain state and intersects
it with the exact `file->f_path` object and immutable acquisition/lifetime
restrictions. Where per-open provenance is required, a target-qualified bounded
file-instance map is installed at file allocation/open/receive and released
idempotently at `file_free_security` or a proved equivalent. Inode storage
alone cannot distinguish the same inode opened through two mount views.
Missing instance provenance fails closed for a rule that requires it; fd number
or current path cannot reconstruct it.

`FILE-FD-PASS-001` opens a host credential in the host mount namespace, then
passes/acquires it through plain fork, `SCM_RIGHTS`, and `pidfd_getfd` into the
container. It repeats through a lazy-unmounted mount, bind aliases, and two
views of the same inode, then forces file-pointer/fd reuse and final free. The
container's current role is the actor, but classification stays on the opened
host object/view and denies read/write/mmap. Its own dataset fd remains the
positive control.

##### Delegated filesystem and local-proxy egress

A workload can publish bytes by writing an NFS/9p/CIFS/FUSE/CSI/object-store
mount or a local Unix/proxy socket. The external packet may be emitted by a
kernel filesystem client, FUSE daemon, CSI sidecar, or proxy, so recording it as
the worker's own network connect/send is false.

```text
DelegatedIoEdgeV1 {
  initiating_file_or_local_socket_effect_id
  exact_worker_task_and_object
  delegate_kind: KERNEL_FS | FUSE_DAEMON | CSI_SIDECAR | LOCAL_PROXY | OTHER
  backing_mount_or_service_identity
  delegate_process/socket/request_identity?
  backing_remote_flow_or_provider_operation?
  proof_quality
}
```

A strict no-egress profile either denies worker writes to writable remote/relay
objects, governs the delegate's own role/flow and joins an exact request ID, or
declares a semantic/contextual gap and consumes authoritative service audit.
`ALG-NET` never invents a direct worker packet edge when the delegate emitted
it.

`FILE-DELEGATED-EGRESS-001` writes a marker to NFS, FUSE/CSI/object-store
mounts and a local Unix proxy. Packet capture proves the source is the kernel or
delegate. Deny mode returns a file/socket errno before the marker reaches the
delegate. Allowed mode creates the typed edge at its actual proof quality; an
unjoinable multiplexed proxy remains contextual. An approved result upload is
the negative control.

#### Process-shared security state and sensitive-read semantics

##### Abandoned design: process-local sensitive-read state controls publication

Mithril may maintain a deterministic process state bit after an observable
sensitive read:

```text
on allowed/audited read of credential or protected secret object:
    process.dynamic_state |= OBSERVED_SENSITIVE_READ

on later socket/write/exec effect:
    use the stricter effect table for OBSERVED_SENSITIVE_READ
```

This is coarse information-flow control, not byte-level taint. It is useful for
roles that may read one sensitive file but must not subsequently contact public
destinations or create artifacts. It cannot prove that bytes sent came from
that file, and it cannot see secrets read from existing memory. Profiles must
opt in after baseline simulation because the state can intentionally tighten
all later effects of the process.

The sketch is abandoned as an exfiltration authority. A sibling process in the
same shared-memory/file/socket authority domain could publish while only this
process value changes, and BPF cannot atomically update separate process and
domain map values. The canonical sensitive-access transition locks the one
`AuthorityDomainStateV1` value, changes its sensitive bits and
`effective_restriction_set_ref_id`, increments `transition_version`, and only
then allows the read/access attempt. A later process-state observation is
explanation only.

**Real-world race.** PID 4100 is the converter and PID 4200 is an upload
sidecar sharing `/work`. PID 4100 opens the projected ServiceAccount token
while PID 4200 is blocked in a send. Before the token operation returns allow,
the domain transition installs `NO_PUBLIC_EGRESS_AFTER_SENSITIVE`. PID 4200's
publication reservation takes the same domain lock: it either linearizes
first, in which case the token access denies while publication is in flight,
or it linearizes second and the send denies. Updating only PID 4100 would fail
this test.

##### Retained process-shared sketch (abandoned as the Version 1 ABI)

The earlier `TaskLabel.dynamic_state_bits` field and the native-inheritance
branch that permits a `thread_child_role` are incomplete if implemented
literally. Linux threads share address space and commonly share file tables,
so one thread cannot safely receive a less restricted taint/role while another
thread keeps the powerful state. The authoritative mutable state is
process-shared:

```text
ProcessSecurityState {
  state_id
  node_boot_id
  label_epoch
  process_lineage_id
  active_execution_id
  active_role_id
  dynamic_state_bits
  effective_response_set_id
  transition_version
  live_thread_refs
}

TaskLabel {
  ...immutable task/entry/process identity...
  process_state_id
  cached_role_and_generation_for_bounded_lookup
}
```

The retained unversioned shapes are explanatory only. The canonical records
are `TaskLabelV1`, `ProcessSecurityStateV1`, `ProcessStateVectorV1`, and
`AuthorityDomainStateV1`; Version 1 has no task decision cache. In particular,
active profile-generation reference and current authority-domain ID are
mandatory fields of process state, while sensitive publication authority is
domain-owned and a mutable role/generation cache is not part of immutable task
identity.

##### Abandoned design: authorize from a stale task-label role cache

The retained cache name and earlier algorithms that read `label.role_id` or
`label.role` are unsafe if interpreted as authority. A sibling can set a
sensitive bit, enter a narrower role, or receive a response restriction while
another task still has a more permissive cached value. Asynchronous cache
refresh is abandoned.

Every decision resolves authoritative `ProcessSecurityState` and
`AuthorityDomainState`. An optional cache is usable only with an exact version
match:

```text
TaskLabel {
  ...immutable identity...
  process_state_id
  authority_domain_id
  cached_decision_set_id
  cached_transition_version
}

decision:
  state = process_state_map[label.process_state_id]
  domain = authority_domain_map[label.authority_domain_id]
  if either missing: deny(SECURITY_STATE_MISSING)
  if label.cached_transition_version == state.transition_version and
     cache decision-set IDs equal authoritative IDs:
      cache may avoid decoding, but domain restrictions still intersect
  else:
      use authoritative state/domain now; never allow from stale cache
```

###### Abandoned design: load the authority domain from the task label

The retained `authority_domain_map[label.authority_domain_id]` line is
abandoned. A quiescent cross-entry join changes the process's domain without
rewriting immutable task labels. The exact hot-path sequence is:

```text
process = process_state_map[label.process_state_id]
require process identity/epoch/state/transition_version valid
domain = authority_domain_map[process.authority_domain_id]
require domain identity/epoch/state/transition_version valid
binding = binding_by_execution_set[label.execution_set_id]
require process.active_profile_generation in binding.retained_generations
evaluate process.active_role_id and process.active_execution_id
intersect domain, response, object/socket and pending-exec restrictions
```

The retained post-Version-1 cache proposal would have to record both process
and domain versions. Any domain join, sensitive-state transition, exec,
generation migration, response change, overflow or recovery would increment
the relevant version before the restriction became observable. Version 1
installs no such record or map and cannot authorize from a cache at all.

An allowed state-changing hook publishes the new compact role/state/response
set IDs plus incremented version atomically before returning allow. The
qualified implementation uses a target-proven atomic packed transition or BPF
spin-locked map value; no reader may observe a new version with old authority.
A future approved cache may be refreshed opportunistically only after the
current decision has used authoritative state.

`STATE-THREAD-RACE-001` places two threads on a barrier. Thread A performs an
allowed sensitive access, role transition, and response insertion in separate
runs while thread B races file and network effects after reading a stale pre-
lock authoritative snapshot. Before B commits an allow, its hook must recheck
the process/domain transition versions at the owning lock/linearization point;
if A won, B retries once against the new tuple and denies. Map loss, version
wrap, exhaustion, or continuing contention fails closed; Rust scheduling is
irrelevant to the physical result. A separate activation branch loads a cache
map or presents a nonzero legacy cache field and must fail strict activation as
`DECISION_CACHE_UNQUALIFIED`.

Every `CLONE_THREAD` child references the exact same process state and retains
the same role and execution ID. Actual per-thread credentials remain input to
capability/security decisions, but they cannot grant a more powerful Mithril
role. A non-thread fork creates a new process state, copies the parent's active
execution identity and only state bits whose schema says `inherit_on_fork`,
then applies the single compiled fork transition. Exec atomically changes the
process state's execution/role before user mode. Process state is reclaimed
only after all thread references and reconciliation reach zero.

##### Abandoned design: assigning a separate thread-child role

The `thread_child_role or parent.role_id` branch in the compact inheritance
algorithm is abandoned. A hostile thread could read shared secret memory or a
shared descriptor under one role and arrange for a sibling with another role
to send it. Thread creation is still independently allow/deny/rate-limited,
but an allowed thread joins the process's existing role and state.

`CLONE_THREAD` is not the only sharing case. `vfork` and non-thread clones may
share address space (`CLONE_VM`), file-descriptor table (`CLONE_FILES`), or
filesystem context (`CLONE_FS`). Until those resources are proven unshared,
the related processes belong to one `SharedAuthorityDomain`:

```text
SharedAuthorityDomain {
  domain_id
  member_process_lineage_ids[]
  shared_mm_id?
  shared_files_id?
  shared_fs_id?
  effective_role_restrictions
  union_dynamic_sensitive_bits
  union_response_restrictions
  generation_set
}
```

Authority combines conservatively: restrictions intersect allowed effects,
sensitive/response bits union, and an old generation cannot override a newer
member's deny. A child sharing any listed resource cannot receive broader
authority than its domain. It gets an independent process state only after a
qualified exec/unshare transition proves the relevant sharing ended; copied or
inherited descriptors remain governed by their object/socket labels.

**Sharing tests.** A `vfork` child opens a sensitive object before exec and the
parent sends after it resumes; the parent's domain sees the sensitive bit. A
`CLONE_FILES` child inserts a credential descriptor into the shared table; the
parent cannot use it under an untainted/broader role. A `CLONE_VM` child writes
a secret marker to shared memory; both members retain the same response and
egress restriction until the domain splits at a proven transition.

##### Abandoned design: an unbounded member list and eager domain split

The retained `member_process_lineage_ids[]` cannot be stored or walked on a
BPF hot path, and “split at a proven exec/unshare transition” is unsafe as a
baseline. `unshare(CLONE_FILES)` copies the descriptor table; exec can retain
non-`CLOEXEC` descriptors; copied memory may already contain a secret; and
there is no assumed generic pre-effect LSM commit hook that proves every
unshare result. A split could therefore relax authority while the risky state
survives. That representation and eager relaxation are abandoned.

The kernel stores a fixed-size, O(1) domain reference:

```text
AuthorityDomainState {
  authority_domain_id
  node_boot_id
  label_epoch
  live_process_refs
  shared_resource_kinds: MM | FILES | FS | VFORK
  effective_restriction_set_id
  union_dynamic_sensitive_bits
  effective_response_set_id
  retained_generation_set_id
  transition_version
  state: ACTIVE | DRAINING | RECLAIMABLE | FAIL_CLOSED_OVERFLOW
}

ProcessSecurityState {
  ...
  authority_domain_id
}
```

At a sharing clone, the child increments the same domain reference before it
runs. A restriction, sensitive bit, response root, or newer-generation deny is
merged with an atomic monotonic operation; it can only reduce authority. BPF
never enumerates members. Rust keeps the explanatory member edges in the
graph, but the graph is not an authorization lookup.

Version 1 does not relax or split a domain while any member lives. Exec,
successful `unshare`, closing an fd, or one member's exit may remove current
sharing, but does not prove that copied data or descriptors are gone. A future
quiescent re-admission protocol may split only if it freezes all members,
enumerates and closes/relabels relevant resources, proves memory/credential
postconditions, installs a new domain on every survivor, reads all labels back,
and resumes atomically. Until that protocol is implemented and qualified, the
old restrictions last until the final member exits.

**Domain tests.** Cover `vfork`, every combination of `CLONE_VM`,
`CLONE_FILES`, and `CLONE_FS`, failed exec/unshare, a copied credential fd,
secret bytes in copied/shared memory, every member-exit order, rapid domain-ID
reuse attempt, and domain-map exhaustion. A child that unshares or execs cannot
regain egress after another member touched a secret. Exhaustion denies the
sharing clone when a returning hook/floor exists; otherwise every affected
member enters `FAIL_CLOSED_OVERFLOW` before its next protected effect.

##### Abandoned design: only explicit `CLONE_VM/FILES/FS` sharing joins a domain

An ordinary fork copies an fd table whose entries still point to the same open
file descriptions and sockets; it can inherit pipes, socketpairs, memfd, and
`MAP_SHARED` mappings. A child can read a secret and write it through one of
those channels for a supposedly untainted parent to exfiltrate. Limiting the
authority domain to explicit clone sharing flags therefore does not close the
document's coarse cross-process information-flow claim and is abandoned.

Version 1's safe coarse baseline keeps **every non-thread fork descendant** in
the same monotonic `AuthorityDomainState` as its parent, adding
`FORK_RELATION|INHERITED_FDS|INHERITED_MAPPINGS|IPC_CHANNELS` to the resource
kind bits as applicable. Each process still has its own process/execution
identity and role, but its effective authority is intersected with the common
domain until the last member exits. This can over-restrict independent work;
profiles that cannot tolerate it must say coarse information-flow control is
disabled rather than claim equivalent isolation.

A future finer design may split through exact object-level labels and taint
transfer for every pipe, Unix socket, shared mapping, memfd, passed fd, and IPC
variant plus the quiescent transaction above. It is not Version 1.

`STATE-FORK-IPC-002` uses plain `fork()` with no sharing flags. The child reads
a credential, then writes a marker through an inherited pipe, socketpair,
shared memfd mapping, and inherited connected socket in separate runs. The
parent's later public send is denied by the shared domain in every case. Exec
and either process exiting first do not relax the remaining member.

##### Cross-entry communication and shared-resource authority

The monotonic fork domain closes laundering among native descendants, but it
does not cover independent entry roots. A Pod's application, sidecar,
`PostStart`, probe, and administrative exec can have no native parent relation
while sharing an `emptyDir`, `/dev/shm`, a Unix socket, a pipe passed by a
runtime helper, SysV/POSIX IPC, or a shared PID/IPC namespace. Treating each
root as an isolated information-flow universe is therefore abandoned.

The Rust compiler builds the communication authority domain from the exact
runtime and live-kernel topology without changing the Pod:

```text
CommunicationAuthorityDomainDraftAbandoned {
  communication_domain_id
  execution_set_id
  participant_entry_and_role_ids[]
  shared_channel_bindings[] {
    channel_id
    kind: WRITABLE_MOUNT | FILE_OBJECT | PIPE | UNIX_SOCKET | POSIX_SHM |
          SYSV_SHM | SHARED_MM | PASSED_FD | LOCAL_INET_STREAM |
          LOCAL_INET_DGRAM | PROCESS_MEMORY | PROCESS_CONTROL | OTHER
    live_object_identity
    participant_set
    transfer_mode: DENY | CONSERVATIVE_DOMAIN_MERGE | OBJECT_TAINT
    required_hook_and_iterator_coverage[]
  }
  effective_restriction_set_id
  state: ACTIVE | INCOMPLETE_TOPOLOGY | FAIL_CLOSED_OVERFLOW | RETIRED
}

SharedResourceStateV1 {
  channel_id
  live_object_generation
  writer_sensitive_bits
  reader_sensitive_bits
  effective_response_set_id
  transition_version
}
```

`AuthorityDomainStateV1` is the sole kernel value for domain-sensitive
publication authority. `domain_lock` protects only fields in that one fixed-
layout value, including the inline publication slots; BPF resolves every map
key/transition row before taking it, rechecks the expected version under the
lock, performs no helper or map lookup while held, and increments
`transition_version` in the same critical section. `potential_sensitive_bits`,
`observed_sensitive_bits`, and `effective_restriction_set_ref_id` therefore
cannot be observed in a mixed transition. Process-local state and
`SharedResourceStateV1` may explain provenance but never override this floor.

###### Correction: a communication topology spans execution sets and zero-process gaps

The retained singular `execution_set_id` is wrong for Pod-scoped resources.
Init, app and sidecar containers are distinct execution sets; a restarted
sidecar gets a new full container/execution-set ID, while the same `emptyDir`,
Pod sandbox network/IPC namespace or persistent local channel can survive an
interval with no live process. The userspace topology plan is:

```text
CommunicationAuthorityDomainV1 {
  communication_domain_id
  durable_scope {
    cluster_uid, pod_uid
    sandbox_binding_id_and_live_interval
    volume_mount_and_backing_object_bindings[]
    network_ipc_namespace_live_bindings[]
  }
  participant_execution_set_ids[]
  expected_future_entry_kinds_and_slots[]
  shared_channel_bindings[]
  authority_domain_id
  topology_plan_digest
  state: PREPARING | ACTIVE | DRAINING | RETIRED |
         INCOMPLETE_TOPOLOGY | FAIL_CLOSED_OVERFLOW
}
```

The durable sandbox/volume/namespace binding, not one container lifetime, owns
`execution_set_binding_refs` and persistent shared-resource refs in
`AuthorityDomainStateV1`. A later exact execution set joins the already active
domain before release; it does not create a clean domain merely because
`live_process_refs` temporarily reached zero. `STATE-CROSS-EXECSET-PERSIST-006`
runs init-write/exit → app-start and sidecar-sensitive-state/exit → sidecar-
restart with a new container ID. The app/restarted sidecar retains the compiled
restriction and object state until the sandbox/volume/namespace live interval
is tombstoned and complete object/task iterators pass.

The compiler selects exactly one safe transfer mode per channel:

1. `DENY` blocks the undeclared channel at its creation/open/connect/attach or
   first covered operation. This is the default when participants or hook
   coverage are unknown and the profile requires information-flow protection.
2. `CONSERVATIVE_DOMAIN_MERGE` makes every participant use the intersection of
   all participant permissions and the union of sensitive/response bits. It is
   required for writable shared mappings and SysV/POSIX shared memory whose
   bytes can change without a per-byte LSM hook. The merge happens before the
   mapping/attach is allowed; observing a later page write would be too late.
3. `OBJECT_TAINT` is available only when the platform qualifies every enabled
   writer and reader path for that object class. Before an allowed sensitive
   role writes/sends, the hook atomically taints the exact live file, pipe, or
   Unix-socket object. Before another root reads/receives, its process and
   communication domain atomically inherit the taint. Missing object state,
   generation mismatch, map exhaustion, or an unqualified I/O path follows the
   profile's deny/merge result, never allow.

###### Abandoned design: object pre-hook taint alone prevents concurrent transfer

The third mode and the later `emptyDir` example are unsafe if read as a
prevention claim. A clean receiver can pass its `read`/`recv` pre-hook and
block. A sensitive writer can then taint the object and write bytes; the
already-admitted receive may return those bytes without another security hook.
The receiver can race an egress from another thread before any post-return
observation propagates taint. This is a fundamental pre-hook time-of-check gap,
not something fixed by a faster BPF map update.

Version 1 therefore separates prevention from observation:

```text
CrossEntryTransferControlV1 {
  prevention_mode:
    DENY
    | PRE_USE_CONSERVATIVE_DOMAIN_MERGE
    | SERIALIZED_TRANSFER_GATE
  observation_mode:
    NONE | OBJECT_TAINT_BEST_EFFORT | COMPLETE_POST_TRANSFER_TAINT
}
```

###### Local IPv4/IPv6 is a cross-entry channel, not ordinary external egress

The retained examples name Unix sockets but omit a common unchanged-Pod path:
the compromised converter sends a credential to a clean uploader on
`127.0.0.1`, `::1`, or the Pod IP, and the uploader sends it externally under
its own role. A network namespace does not isolate containers that share the
Pod sandbox network; it deliberately gives them the same loopback and Pod-IP
stack. Classifying only the uploader's later public connection would leave the
laundering step unexplained.

```text
LocalInetChannelIdentityV1 {
  network_namespace_identity: NetworkNamespaceIdentityV1
  family: AF_INET | AF_INET6
  transport: TCP | UDP
  local_address_and_port
  peer_address_and_port
  socket_cookie_and_birth_generation
  listener_socket_cookie_and_generation?
  accepted_child_socket_cookie_and_generation?
  endpoint_selection:
    EXACT_ONE | EXACT_REUSEPORT_SET | WILDCARD_LISTENER_SET | UNKNOWN
  participant_authority_domain_ids[]
  topology_version
}
```

An address is local when route/socket resolution in the exact live network
namespace can deliver it to a local socket, not merely when its text starts
with `127.`. This includes IPv4/IPv6 loopback, the Pod IP, wildcard listeners,
local transparent/BPF redirection, and qualified service-address hairpin
paths. Destination text, DNS, and the source process's belief are not proof of
the receiver.

###### Abandoned as the Version 1 baseline: pre-resolve listeners before application code runs

The listener-aware rules below describe a useful future qualified tier, but
rule 1 is impossible as a general pre-release baseline: ordinary application
listeners do not exist until their roots run. Observing `bind`/`listen` later
also cannot retroactively merge a connection whose bytes were already queued.
The rules are retained as requirements for that future tier, not as the
unchanged-Pod Version 1 mechanism:

1. For declared same-Pod listeners, Rust resolves every listener/reuseport
   participant and places all possible sender/receiver execution sets in the
   same authority domain before either user root is released.
2. For a dynamic TCP connect, the connect path may proceed only when the exact
   listener set and both domain versions already name the same active domain.
   Otherwise the first connect is denied; the optional crash-safe quiescent
   join can commit out of band, and a later new connect retries. An accepted
   child receives listener/channel provenance before `accept` can make it
   usable by the receiving task.
3. For connected or unconnected UDP, each `sendmsg`/io_uring send resolves the
   actual per-message destination and **all** possible local recipients before
   enqueue. `SO_REUSEPORT`, wildcard binds, multicast/broadcast, a missing
   `msg_name`, NAT, or BPF redirect that prevents an exact bounded recipient
   set makes strict prevention deny or report the path unsupported. It never
   chooses whichever receiver was observed afterward.
4. A local socket inherited across fork or passed with `SCM_RIGHTS` retains its
   channel/domain identity. Passing the fd does not reset it. io_uring and
   SQPOLL use the submitter/registered-resource authority contract; an
   unattributable worker is denied for a full-support profile.
5. Traffic arriving from outside the protected topology is ingress, not a
   fictional merge with a remote process. The receiving role and socket policy
   still decide it, and any later local forwarding follows the rules above.

The canonical Version 1 baseline premerges **all admitted and expected future
execution sets that share the Pod network namespace** before the first user
root is released. The shared domain carries only common negative restrictions,
sensitive-state joins, and response floors; the converter, uploader, probe,
sidecar, and lifecycle roots retain their own positive role grants. A later
root for the same exact Pod sandbox increments the already-live domain at its
held admission barrier. Zero currently running processes does not retire that
domain while the sandbox/network-namespace binding remains live.

**Real-world result.** The converter may call its approved result service and
the uploader may call its approved upload service while both are clean. If the
converter then receives permission to open the projected token, the shared
domain atomically acquires `NO_PUBLICATION_AFTER_SENSITIVE_ACCESS`. The
uploader's next public send denies even if the token arrived through
`127.0.0.1`, `::1`, Pod IP, UDP, or a socket fd it inherited. The merge did not
give the converter the uploader's destination allow; it only made the
restriction common.

A local endpoint between domains that were not premerged denies the **current**
connect/send/delivery. Mithril may then run the crash-safe quiescent join out of
band and let the application retry; it never blocks inside BPF waiting for
Rust. If the application cannot retry, the operator must choose the broader
premerge or accept denial/unsupported status.

The exact live-recipient tier remains a future capability and may advertise
less conservative domains only after one transaction covers bind, listen,
accept/release, close, port reuse, `SO_REUSEPORT` membership/selection,
wildcard listeners, UDP per-datagram routing, multicast/broadcast, NAT,
service hairpin, cgroup/socket BPF redirects, io_uring/SQPOLL, and recipient
resolution before enqueue. Unknown or changing recipient sets deny the
current operation. Post-delivery observation is evidence, not prevention.

`STATE-LOCAL-INET-LAUNDER-008` starts a converter and uploader in different
containers of one ordinary Pod. It sends a marker over TCP and UDP through
IPv4 loopback, IPv6 loopback, Pod IP, wildcard bind, connected and unconnected
UDP, an accepted socket, `SO_REUSEPORT`, passed/inherited fd, and io_uring. Each
strict branch either has a pre-use common domain that blocks the uploader's
later public send or returns a local-channel errno before delivery. Unknown
redirect/recipient branches are `UNSUPPORTED`/denied, never `prevented` after
the marker reached the uploader. An approved local health request is the
positive control and succeeds because actor-local positive grants still
differ inside the premerged negative-restriction domain. A separate
future-tier branch is dormant until the complete live-recipient capability is
allocated and qualified.

###### Process memory, descriptor extraction, and signals are authority channels

File and socket channels are not exhaustive. Linux exposes direct
cross-process data and control operations that can move bytes, descriptors, or
execution influence without creating a child or ordinary IPC connection:

| Operation | Version 1 pre-effect result across different authority domains |
| --- | --- |
| `process_vm_readv`, ptrace peek/read, `/proc/<pid>/mem` read | Deny, or finish a pre-use domain merge and propagate the target's potential/observed-sensitive restrictions to the reader **before** bytes can return. |
| `process_vm_writev`, ptrace poke/register/write/control, `/proc/<pid>/mem` write | Deny, or complete a pre-use conservative domain merge before target memory/registers can change. |
| `pidfd_getfd` | Treat as `PASSED_FD`: deny or merge before the duplicate descriptor is installed; attach the exact source object/socket authority state to the result. |
| `kill`, `tgkill`, `rt_sigqueueinfo`, `pidfd_send_signal`, ptrace resume/signal injection | Treat as a control edge. Cross-domain default is deny unless an exact declared controller-target relation, signal set, purpose, multiplicity, and lifetime authorizes it. A signal name alone does not grant the target's role. |

Every target is resolved as `(node_boot_id, label_epoch, task_cookie,
process_state_id, live task coordinates/pidfd, target transition_version)`.
PID or namespace PID alone is invalid.

###### Abandoned design: a returning hook can undo process-memory effects

The retained phrase “a target change between lookup and the returning hook
denies” is abandoned as prevention. By a return hook, `process_vm_readv` may
already have copied bytes and `process_vm_writev`/ptrace may already have
changed memory or registers. A later denial cannot undo that effect.

The canonical pre-effect path pins the exact kernel target task/object and
revalidates its immutable cookie, process-state ID, transition version, and
allowed relation at the last qualified pre-effect decision point. The same
pinned target must remain the kernel effect target; if the program/hook cannot
carry that exact target through the effect, strict policy denies the current
operation. A needed authority-domain join is out of band: deny this attempt,
hold and quiesce both domains, commit the join, then require a new syscall.
Return-hook revalidation is evidence and completion accounting only.

If the target kernel cannot provide a qualified pre-effect hook for the
operation, the strict profile reports that operation `UNSUPPORTED` and blocks
it with seccomp/LSM where a safe floor exists; a tracepoint after completion is
observation only.

A defender may need read-only inspection without merging the defended task's
restrictions into the defender service. That is not an implicit exception. It
is a signed `DEFENDER_READ_DECLASSIFICATION` naming the exact target cookie,
case/finding ID, allowed read operations and byte bound, output evidence sink,
approver, and monotonic expiry. It forbids memory/register writes, signal
injection, fd extraction, and target resume/control. The read result becomes
sensitive defender evidence and may leave only through the named evidence
sink. No exception or a stale/reused target returns `EPERM`.

###### Abandoned design: seccomp authorizes `/proc/<target>/mem` by pathname

The retained proposal that seccomp “permits only the `O_RDONLY
/proc/<target>/mem` path” is physically impossible: seccomp filters syscall
numbers and scalar arguments; it cannot safely dereference and authenticate a
pathname pointer. Version 1 instead uses an owner-opened-fd protocol.

1. The trusted `NativeSecurityStateOwner` resolves the exact target cookie and
   opens the target memory object while the target is held. The BPF-LSM check
   binds that open to the signed case, target cookie, byte bound, expiry, and
   expected helper identity.
2. The owner passes the already-classified read-only target fd and one fixed
   evidence-sink fd to the short-lived measured `mithril-inspector`; all other
   inherited fds are closed before release.
3. The installed/read-back seccomp filter denies `open`, `openat`, `openat2`,
   `socket`, `connect`, `dup*`, descriptor-producing `fcntl`, `pidfd_getfd`,
   `ptrace`, `process_vm_writev`, signal/control syscalls, BPF, perf, and every
   write destination except the fixed evidence-sink fd. It permits only the
   qualified `read`/`pread` on the target fd or the separately qualified
   bounded `process_vm_readv` path, plus minimal exit/runtime syscalls.
4. The BPF-LSM target-aware record independently verifies helper task, case,
   target cookie, exact fd object, byte budget, deadline, and evidence sink on
   every permitted access. Seccomp supplies syscall/flag/fd confinement; BPF
   LSM supplies exact target/object authority.

Ptrace peek remains excluded because attach/seize would also expose control
operations. A platform lacking either the syscall-filter readback, exact
target-open path, fd confinement proof, or target-aware BPF-LSM check supports
no declassification helper.

`STATE-PROCESS-CHANNEL-009` covers same- and cross-PID-namespace targets, PID
reuse, target exec/exit races, every read/write operation above, ptrace
attach/seize/peek/poke/resume, proc-mem, `pidfd_getfd`, queued signals, and a
read-only defender exception. A cross-domain marker never reaches an
unrestricted reader/target; a stale PID never selects its replacement; the
defender positive control reads only its named target and cannot mutate or
signal it.

- `PRE_USE_CONSERVATIVE_DOMAIN_MERGE` is the unchanged-deployment baseline.
  For a writable shared mount or shared-memory namespace, all admitted
  participant roles merge before any participant user task is released. For a
  dynamically created pipe/Unix socket/passed fd, both endpoints/domains merge
  before connect, accept, attach, or transfer makes the channel usable. Unknown
  or late participants are denied until the merge commits and every live task
  label reads back the merged restriction.
- `SERIALIZED_TRANSFER_GATE` qualifies only when one kernel/runtime/provider
  boundary owns every enqueue/dequeue, proves there is no already-admitted
  blocking receiver, commits the receiver's restriction before delivering
  bytes, and passes cancellation, partial-read, splice, io_uring, duplicated-fd
  and multi-reader races. It is an optional semantic channel capability, not a
  claim made for ordinary Linux files, pipes, sockets, or shared memory.
- `OBJECT_TAINT_BEST_EFFORT` may enrich observation and trigger later
  restriction. Even complete post-transfer taint proves completed transfer
  only for its qualified operations; neither mode is a first-transfer
  prevention claim by itself.

The corrected unchanged-Pod result is intentionally conservative. If the
converter and upload sidecar share writable `/work`, their communication
domains merge before both roots run. Once the converter obtains sensitive
authority, the sidecar's public-send budget is already intersected and denies;
there is no clean blocked-reader interval. If the operator refuses that blast
radius, policy must deny the shared channel or declare cross-entry laundering
prevention unsupported—it cannot select the attractive but racy object-taint
claim.

`STATE-CROSS-ENTRY-RACE-004` starts a clean blocking `read`/`recv` before the
sensitive writer, then releases writer and receiver on separate CPUs and races
an immediate sibling egress. It covers a regular file, pipe, Unix stream and
datagram socket, shared-memory signal plus data, splice, io_uring, duplicated
fd, and multiple readers. `PRE_USE_CONSERVATIVE_DOMAIN_MERGE` or `DENY` must
close every branch. Observation-only object taint must report its exact timing
and is forbidden from returning `prevented`.

###### Intermediate correction (abandoned): cross-entry state uses the existing bounded authority domain

The retained `CommunicationAuthorityDomainDraftAbandoned` arrays are a userspace topology
plan, not a BPF hot-path object, and `communication_domain_id` is not a second
unread authority pointer. Treating those unbounded arrays as kernel state is
abandoned. This intermediate draft correctly folds every prevention-relevant
join into one bounded authority domain, but its reference accounting and bare
set IDs are superseded by the canonical record immediately below:

```text
AuthorityDomainStateDraftAbandoned {
  authority_domain_id
  node_boot_id, label_epoch, domain_epoch
  live_process_refs
  shared_resource_kind_bits
  potential_sensitive_bits
  observed_sensitive_bits
  effective_restriction_set_id
  effective_response_set_id
  retained_generation_set_id
  transition_version
  state: PREPARING | ACTIVE | DRAINING | RECLAIMABLE |
         FAIL_CLOSED_OVERFLOW | CORRUPT
}

decision(actor, effect, object):
  label = task_storage.current()
  process = process_state_map[label.process_state_id]
  domain = authority_domain_map[process.authority_domain_id]
  require label/process/domain versions, epochs, refs and placement are valid
  actor_allow = role_effect_table[process.active_role_id, effect, object, state]
  return actor_allow intersect domain.effective_restriction_set and
         domain.effective_response_set and object/socket lifetime restrictions
```

###### Abandoned design: reclaim a domain after only its last process exits

The retained `AuthorityDomainStateDraftAbandoned` has only
`live_process_refs`. That can
reclaim restrictions while a persistent shared file/socket/IPC object, a
pending later entry, a response plan, or restart reconciliation can still
reintroduce a participant. Its reference model is abandoned. The canonical
record with the same V1 type name is:

```text
AuthorityDomainStateV1 {
  authority_domain_id
  node_boot_id, label_epoch, domain_epoch
  domain_lock: bpf_spin_lock
  execution_set_binding_refs
  live_process_refs
  live_channel_and_shared_object_refs
  pending_entry_and_join_refs
  response_plan_refs
  reconciliation_hold_refs
  publication_reservation_and_capability_refs
  shared_resource_kind_bits
  potential_sensitive_bits
  observed_sensitive_bits
  effective_restriction_set_ref_id
  effective_response_set_ref_id
  retained_generation_set_ref_id
  publication: AuthorityDomainPublicationStateV1
  transition_version
  state: PREPARING | ACTIVE | DRAINING | RECLAIMABLE |
         FAIL_CLOSED_OVERFLOW | CORRUPT
}

SharedResourceStateV1 {
  shared_resource_state_id
  exact_live_object_identity_and_generation: ExactObjectGenerationV1
  authority_domain_id
  reference_owned: bool
  participant_topology_plan_digest: DigestV1
  potential_sensitive_bits
  observed_sensitive_bits
  effective_response_set_ref_id
  transition_version
  state: PREPARING | ACTIVE | DRAINING | TOMBSTONED | CORRUPT
}
```

A static shared-mount/IPC topology keeps one
`execution_set_binding_refs` reference even when no process is currently
running. Every live pipe/socket/memfd/shared mapping/file object whose label
can carry the domain owns one idempotent
`live_channel_and_shared_object_refs` reference. A pending runtime root or
quiescent join owns `pending_entry_and_join_refs`; an immutable response plan
owns `response_plan_refs`; restart/iterator repair owns
`reconciliation_hold_refs`. Object/channel destruction releases its reference
only from a qualified final-object hook or complete iterator reconciliation,
never from fd close or process exit alone.

Each non-free inline publication slot and each persistent publication
capability owns one `publication_reservation_and_capability_refs` reference.
Release is idempotent and occurs only through the canonical completion or held
reconciliation transaction. `RECLAIMABLE` additionally requires
`publication.inflight_publications == 0` and
`publication.persistent_publication_present == false`; a counter alone cannot
hide a corrupt live slot or persistent bit.

That last sentence is still too weak for a linked regular file. Destruction of
the final `struct file` or eviction of an inode from cache does not destroy the
bytes: another process can reopen the directory entry later, and a persistent
volume can be detached from one Pod and mounted by another. Treating kernel
object death as authority-state death is abandoned for persistent storage.

```text
PersistentFileSecurityStateV1 {
  persistent_state_id
  backing_volume_live_identity
  filesystem_instance_identity
  stable_filesystem_object_identity_and_generation
  known_namespace_alias_digest
  link_count_observation
  open_file_refs
  vma_refs
  async_io_and_writeback_refs
  authority_domain_id
  potential_sensitive_bits
  observed_sensitive_bits
  transition_version
  state: PREPARING | ACTIVE | UNLINKED_REFERENCED | RETIRING |
         TOMBSTONED | CORRUPT
}
```

The backing-volume/filesystem object owns the security state, not an fd or
inode-cache address. Rename preserves the state. Hard-link creation attaches
the alias before it becomes usable. Overlay copy-up creates a new object and
must inherit or conservatively join the source state before the new upper
object becomes visible; otherwise the mutation denies. Unlink can enter
`UNLINKED_REFERENCED`, but release requires verified link count zero, no open
file/VMA/async-I/O/writeback refs, and a qualified filesystem/volume lifetime
transition. Inode-number reuse is a new generation and cannot inherit the old
key accidentally. A persistent-volume state may outlive a Pod UID, sandbox,
and every process, and the next admitted execution set joins it before open or
mount release.

If a filesystem/CSI backend cannot provide a stable non-reused object identity
and qualified link/copy-up/remount lifecycle, Mithril cannot offer per-file
state for that backend. The strict alternatives are a backing-volume-wide
authority domain/restriction or denial of the writable shared surface; a path
plus inode number observed in one mount interval is not promoted to durable
identity.

`STATE-PERSISTENT-FILE-LIFETIME-007` writes sensitive marker bytes, closes all
fds, exits every process, restarts the sidecar, and reopens the file. Separate
branches rename it, add a hard link, unlink it while mapped/open, force inode
cache pressure and number reuse, trigger overlay copy-up, and detach/remount a
persistent volume in a new Pod. The restriction survives every same-object
branch, a reused object number does not inherit stale state, and state becomes
reclaimable only after the exact backing object and all refs are proven gone.

###### Correction: durable volume authority precedes every mount, writer, and clone

The retained per-file record is insufficient for detach/remount, node reboot,
or a new Pod on another node. A pinned node map cannot carry authority to that
node, and asynchronous replication after a sensitive write loses the race if
the writer node crashes. For RWX storage, another node may publish concurrently
before any reactive taint arrives. The safe unchanged-deployment Version 1
baseline is therefore volume-wide and precomputed:

```text
PersistentVolumeAuthorityV1 {
  persistent_volume_authority_id: Id128
  cluster_uid: Id128
  csi_driver_canonical_name
  provider_or_csi_volume_handle_digest: DigestV1
  provisioned_volume_uid: Id128
  provisioned_storage_generation: u64
  access_mode: RWO | ROX | RWX | RWOP | UNKNOWN
  potential_sensitive_bits: u64
  semantic_restriction_artifact_digest: DigestV1
  permitted_execution_set_ids[]
  record_generation: u64
  control_commit_index: u64
  policy_artifact_digest: DigestV1
  state: PREPARING | ACTIVE | RETIRING | REVOKED | CORRUPT
  signer_key_id
  signature
}

VolumeMountBarrierV1 {
  barrier_id: Id128
  node_boot_id: Id128
  execution_set_id: Id128
  persistent_volume_authority_id: Id128
  exact_live_mount_identity
  observed_record_generation: u64
  observed_control_commit_index: u64
  installed_local_restriction_set_ref_id: u64
  installed_semantic_restriction_artifact_digest: DigestV1
  installed_domain_and_restriction_digest: DigestV1
  state: HELD | READ_BACK | RELEASED | DENIED
}
```

The central signed control WAL owns `PersistentVolumeAuthorityV1`; it carries
the portable semantic restriction artifact, never a node-local `SetRefV1`
handle. Every node
mount/start barrier remains `HELD` until it fetches the latest non-rollback
record, compiles that exact artifact into a fresh local non-reused restriction
set reference, joins the execution set to its restriction domain, installs the
node state, and reads back both the local ref and artifact digest. Control unavailability, stale commit
index, unknown volume generation, or signature failure keeps the mount/root
held. Before **any** permitted writer or reader root is released, the compiler
marks a writable volume `POTENTIAL_SENSITIVE` whenever one participant could
obtain protected material. This conservative mark, not a later per-file event,
is what survives a writer-node crash.

For an RWO/RWOP volume, sequential detach/remount is safe only through this
barrier. For RWX, every concurrent node installs the same precomputed common
restriction before release. A profile that refuses this common domain must
deny the shared writable mount or report cross-node publication prevention
`UNSUPPORTED`. Reactive per-file bits can still improve evidence and response,
but cannot support the cross-node prevention claim unless the storage/provider
offers a separately qualified synchronous metadata transaction.

Every operation that creates a new persistent object has an explicit
propagation rule:

| Operation | Pre-visibility Version 1 result |
| --- | --- |
| `FICLONE`/`FICLONERANGE`, `copy_file_range`, file-to-file `sendfile`/`splice`, ordinary copy | Attach/join the source volume/domain state to the destination before destination bytes become readable, or deny. A post-copy event is detection only. |
| overlay copy-up | Reserve the upper object under the source restriction before publishing the dentry; failure denies copy-up. |
| hard link/rename | Preserve the same object state; never create a clean generation merely because the path changed. |
| backup/restore or CSI snapshot/clone | Hold destination admission until authenticated provider/CSI evidence binds source volume generation and propagated authority. Audit after restore cannot claim prevention. |
| unknown backend copy/offload | Deny the offload or use volume-wide potential-sensitive restriction; never infer clean bytes. |

**Real-world example.** A converter on node A writes a token-derived marker to
an RWX PVC and the node loses power before its event uploads. An uploader Pod
on node B is already mounted. Because both roots received the signed volume-
wide potential-sensitive restriction before either ran, node B's public send
is denied even though it never saw node A's file event. Without that premark,
Mithril may later correlate the intrusion, but it cannot say it prevented the
send.

`STATE-PERSISTENT-FILE-LIFETIME-007` is extended with node-A crash before WAL
upload, node-B sequential remount, simultaneous RWX mounts, stale/signed-
rollback mount records, control outage, `FICLONE`/`FICLONERANGE`, each kernel
copy path, overlay copy-up, backup/restore, and CSI snapshot/clone. The strict
oracle is mount/root held or destination restriction installed before first
read/publication; “a taint event arrived later” never passes.

The domain state has closed admission/effect semantics:

| State | New task/entry/channel | Existing protected effect | Response/recovery | Transition out |
| --- | --- | --- | --- | --- |
| `PREPARING` | stage refs only; release of a user task and channel use are denied | deny `DOMAIN_NOT_ACTIVE`; loader-only budget is allowed only for the exact held admission transaction | readback/rollback only | `ACTIVE` after every process/object/ref and task label reads back, otherwise tombstone/fail closed |
| `ACTIVE` | permit only compiled exact admission/transfer and increment refs before use | role allow intersect domain/response/object/pending-exec restrictions | typed response may monotonically narrow | `DRAINING` after binding retirement or final-admission closure begins |
| `DRAINING` | no new entries, joins, channels, or broadening transitions | existing members remain under the last restrictions; only declared cleanup effects may pass | containment, evidence and reconciliation remain available | `RECLAIMABLE` only after all seven ref classes are zero, publication counters/bits are clear, and iterators find no live holder |
| `RECLAIMABLE` | deny | deny stale domain | tombstone/readback only | remove after grace period; ID is never reused in the epoch |
| `FAIL_CLOSED_OVERFLOW` | deny | deny every protected effect except separately authorized containment/evidence | bounded containment and repair | only a quiescent signed recovery transaction may produce a new domain |
| `CORRUPT` | deny | deny every protected effect | evidence capture and independently authorized containment only | never repair in place; quiesce, replace, read back and tombstone |

`PREPARING` therefore never releases a task. `DRAINING` never relaxes a rule.
`DOMAIN-REF-LIFETIME-001` exits all processes while retaining, in separate
runs, a shared Unix socket, memfd mapping, writable shared file, pending probe,
response plan and forced restart hold. The domain cannot become reclaimable
until the final corresponding object/ticket/plan/reconciliation reference and
iterator proof are gone; each duplicate destructor is idempotent.

There is no unbounded participant or channel walk in BPF. Rust keeps those
edges for explanation and enforces signed per-execution-set maxima. The kernel
uses fixed-size state/set IDs and O(1) lookups. Missing/corrupt state, reference
overflow, version mismatch, or a topology plan beyond its signed bound makes
the affected protected effect fail closed and the axis unhealthy.

Static shared mounts, shared IPC namespaces, sidecars, init/lifecycle roots,
and expected later probe/admin roots are compiled before release. All relevant
entries reference the same authority domain from their held admission; a later
entry increments that existing domain only after exact topology revalidation.
For an undeclared dynamic channel between two active domains, Version 1 denies
the create/connect/accept/attach/fd-transfer operation. It does not attempt an
impossible multi-map atomic union inside one BPF hook. An optional quiescent
join must deny the triggering operation, freeze and enumerate both complete
domains, create one `PREPARING` combined state, update every
`ProcessSecurityState.authority_domain_id`, read every task/state back, activate
the new root, tombstone the old roots, and only then allow a later retry. Any
failure leaves the channel denied and both old domains restrictive; no split
or rollback can restore broader authority while a member lives.

###### Intermediate correction (abandoned): narrow old roots before redirecting members

The retained order is not crash-safe if “create the combined state, update
processes, then tombstone old roots” leaves an old root `ACTIVE` while only
some processes point at the new root. A daemon or node failure in that interval
could resume one half under its former broader authority. That transaction
order is abandoned.

The retained intermediate join attempted an idempotent journaled transaction,
but its root-level state still overclaims atomicity. It is retained only to
show the failure that the canonical per-root/per-reference transaction below
must close:

```text
AuthorityDomainJoinTransactionDraftAbandoned {
  join_transaction_id
  triggering_channel_identity_and_generation
  old_domain_ids[2..MAX_JOIN_DOMAINS]
  old_domain_versions[]
  combined_domain_id
  combined_restriction_set_id
  combined_response_set_id
  combined_retained_generation_set_id
  complete_target_process_set_digest
  complete_target_object_set_digest
  state:
    PREPARED | OLD_ROOTS_RESTRICTED | TARGETS_QUIESCENT |
    MEMBER_POINTERS_INSTALLED | COMBINED_ACTIVE |
    OLD_ROOTS_RECLAIMING | COMMITTED | FAILED_CLOSED
}
```

1. Deny the triggering create/connect/accept/attach/transfer and return a
   retryable policy result only after the control transaction later commits.
2. Allocate the combined domain as `PREPARING`, with all refs and the union of
   negative restrictions, response restrictions, sensitive bits, and retained
   generations. Read it back while no process can use it.
3. CAS every old domain from its exact `ACTIVE/version` to `DRAINING` and
   install that same combined-or-stricter restriction floor in each old root.
   New channels, entries, and positive transitions now deny from either root.
4. Freeze or otherwise prove quiescence for every process, thread, async I/O
   context, shared object, and future-entry slot named by both topology plans.
   Re-enumerate; any missing/extra target changes the transaction to
   `FAILED_CLOSED` while the old roots remain restricted.
5. Change every `ProcessSecurityStateV1.authority_domain_id` and object/channel
   reference to the `PREPARING` combined domain. A crash halfway leaves some
   members on `DRAINING` old roots and others on a non-active new root; both
   sides deny protected effects.
6. Read back the complete target set and reference counters. Only then CAS the
   combined root to `ACTIVE`, resume members, and leave old roots `DRAINING`
   until their refs reconcile to zero and the grace period completes.
7. A later retry re-resolves both endpoints and may use the channel only if
   both now resolve to that exact active combined domain and topology version.

Restart reconciliation reads the transaction journal before admission opens
and resumes the first incomplete step by state/version. It never restores an
old `ACTIVE` state. `DOMAIN-JOIN-CRASH-002` injects failure before and after
every state/ref/pointer write, including half of the member pointers. On every
restart the original channel remains physically unusable and no process
regains a permission absent from the combined restriction; the positive
control succeeds only on a new retry after `COMMITTED`.

###### Correction: per-root and per-reference crash progress is authoritative

The coarse transaction above is retained but its statement that a partial
step leaves “both old domains restrictive” is not generally true. Two domain
map values and many process/object pointers cannot change atomically. A crash
after the first old-root CAS leaves the other old root unchanged. Safety comes
from keeping the triggering channel and admission gate denied throughout and
from recording progress for every root and transferred reference—not from
pretending the writes were one transaction.

```text
AuthorityDomainJoinTransactionV1 {
  join_transaction_id: Id128
  triggering_channel_identity_and_generation
  join_gate_key
  join_gate_state: DENYING | RETRY_ALLOWED | TOMBSTONED
  combined_domain_id: Id128
  combined_domain_prepared_digest: DigestV1
  old_roots[]: DomainJoinRootProgressV1
  targets[]: DomainJoinTargetProgressV1
  quiescence: DomainJoinQuiescenceV1
  state: PREPARED | INSTALLING_OLD_FLOORS | QUIESCING |
         TRANSFERRING_REFS | ACTIVATING | COMMITTED | FAILED_CLOSED
}

DomainJoinRootProgressV1 {
  old_domain_id: Id128
  expected_before_version: u64
  expected_before_state: ACTIVE
  combined_floor_digest: DigestV1
  observed_after_version?: u64
  state: UNTOUCHED | FLOOR_INSTALLING | FLOOR_INSTALLED | CONFLICT |
         RECLAIMING
}

DomainJoinTargetProgressV1 {
  target_kind: PROCESS | SHARED_OBJECT | SOCKET | PENDING_ENTRY |
               EXECUTION_SET_BINDING | RESPONSE_PLAN | RECONCILIATION_HOLD |
               PERSISTENT_FILE_STATE | PERSISTENT_VOLUME_MOUNT |
               PUBLICATION_SLOT | PERSISTENT_PUBLICATION_CAPABILITY |
               DERIVED_KERNEL_CAPABILITY
  target_id: Id128
  target_generation: u64
  source_domain_ref_class: EXECUTION_SET_BINDING | LIVE_PROCESS |
                           LIVE_CHANNEL_OR_SHARED_OBJECT |
                           PENDING_ENTRY_OR_JOIN | RESPONSE_PLAN |
                           RECONCILIATION_HOLD |
                           PUBLICATION_RESERVATION_OR_CAPABILITY
  expected_source_domain_id: Id128
  expected_target_transition_version: u64
  destination_ref_owned: bool
  pointer_state: SOURCE | CAS_IN_PROGRESS | DESTINATION
  source_ref_released: bool
  observed_after_version?: u64
}

DomainJoinQuiescenceV1 {
  new_channel_and_entry_gate: CLOSED
  new_async_submission_gate: CLOSED
  io_uring_instances[]: CANCELLED | DRAINED | UNRESOLVED
  sqpoll_workers[]: STOPPED_AND_DRAINED | UNRESOLVED
  registered_file_and_buffer_sets[]: SNAPSHOTTED | UNRESOLVED
  aio_and_kernel_worker_requests[]: CANCELLED | DRAINED | UNRESOLVED
  inflight_publications: 0
  persistent_publication_present: false
  frozen_process_set_digest: DigestV1
  task_object_socket_iterator_digests[]
  state: NOT_STARTED | GATED | DRAINED | FROZEN | VERIFIED | INCOMPLETE
}
```

`targets[]` is complete across every pointer/ref owner in the canonical domain
record. Execution-set bindings move so later admitted roots resolve the
combined domain; response plans and reconciliation holds move without losing
their floors; persistent file/volume, derived-capability and publication
owners move with the exact ref class they hold. An implementation may leave an
owner on an old `DRAINING` root only by marking the transaction
`FAILED_CLOSED`; it cannot commit while relying on an unreachable old root.

The transaction order is exact:

1. Install/read back `join_gate_state=DENYING` for the triggering channel key
   and close admission of new cross-domain channels. Return denial to the
   original syscall.
2. Build/read back the combined domain as `PREPARING`, owning one transaction
   reference. It contains the union of negative restrictions and sensitive/
   response state, but grants nothing while non-active.
3. For each old root independently, CAS its exact version to the combined
   restriction floor and record `FLOOR_INSTALLED`. If a crash occurs, an
   `UNTOUCHED` root retains its original authority, an installed root is
   narrower, and the still-denied join gate prevents any new transfer between
   them. Recovery resumes; it never reports all roots restricted until every
   row says so.
4. Close new io_uring/AIO/publication submissions; cancel or drain every
   request, including SQPOLL and kernel workers; snapshot registered buffers
   and files; require the canonical domain publication counters/cap bit to be
   zero; freeze all tasks; and run complete before/after task, object, socket,
   fd, and VMA iterator readbacks. Any `UNRESOLVED` item keeps the gate denied
   and transaction `FAILED_CLOSED`. “Otherwise prove quiescence” is not an
   accepted implementation branch.
5. For each target row, acquire exactly one destination-domain reference and
   set `destination_ref_owned=true`; CAS the target pointer from the exact
   source domain/version to the destination with `join_transaction_id`; only
   after observing `pointer_state=DESTINATION` release the source reference and
   set `source_ref_released=true`. A crash can leak the destination ref or keep
   both refs, which is safe. It can never release the source ref before the
   pointer moved. Recovery repeats only the first incomplete owned-bit step.
6. After every root floor, quiescence proof, target pointer, and ref bit reads
   back, CAS the combined root `PREPARING -> ACTIVE`, resume members, and set
   `join_gate_state=RETRY_ALLOWED`. The application must issue a new operation,
   which re-resolves both endpoints to the exact active combined domain.

`DOMAIN-JOIN-CRASH-002` now pauses after each individual root CAS, destination-
ref acquire, pointer CAS, source-ref release, async-cancel result, iterator
frame, activation CAS, and gate transition. Its oracle explicitly allows an
untouched root to remain at its old authority during recovery; it requires the
channel/admission gate to remain denied and every moved/non-active member to
remain fail-closed. This is the testable safety property.

###### Abandoned design: merge intersects unrelated positive role grants

The retained phrase “intersection of all participant permissions” is too broad
if it intersects positive role tables. A converter normally lacks the upload
permission that a sidecar needs, so literal intersection would disable every
clean upload and contradict the positive control. Domain merge never grants
one role another role's allow and never removes a clean actor-specific allow
merely because a peer lacks it. The exact formula above preserves each actor's
base role table and shares only monotonic **restrictions**, sensitive-state
bits, response restrictions, and generation constraints.

In the clean `/work` control, the converter may write declared non-sensitive
output and the uploader's own role may send it. After the converter's sensitive
access commits a common restriction bit, the uploader's unchanged base allow
is intersected with that restriction and its later send denies. This is an
authority-state control, not byte provenance.

###### Credential already in memory or inherited before an observable read

Reactive sensitive-access state cannot protect a secret that starts in an
environment block, checkpointed memory, inherited/pre-opened fd, or
preexisting mapping. Before releasing any participant in a shared authority
domain, the runtime/object binder classifies declared Secret/credential env
delivery, mounted/projected and inherited descriptors, checkpoint state, and
preexisting mappings. It sets `POTENTIAL_SENSITIVE_IN_MEMORY` or a more exact
credential-class bit on the common domain whenever possession is known or
cannot be disproved for a prevention profile.

If that pre-set bit would remove a required upload channel, the honest choices
are: deny the credential/shared channel, accept the disclosed domain-wide
restriction, use a separately qualified semantic transfer gate, or advertise
`PAYLOAD_UNOBSERVABLE`/unsupported for that endpoint. Mithril does not claim an
unchanged environment secret will first pass through a file hook.

`STATE-CROSS-ENTRY-PREPOSSESSED-005` injects the marker separately through an
environment variable, restored anonymous memory, inherited fd, preexisting
mapping, and runtime-passed memfd. The uploader starts with a blocked read and
an allowed result endpoint. Each prevention-capable run has the common
potential-sensitive bit before either user task runs and emits no marker;
removing the delivery evidence yields the configured unsupported/whole-channel
result, never a fabricated prevented read.

Mount sharing is classified from exact mount-view/backing-object identities,
not the display path `/work`. IPC/shm IDs carry node boot, namespace live
identity, kernel object identity, and creation generation so reuse cannot
revive old taint. `SCM_RIGHTS` also transfers the existing file/socket
provenance described earlier; it does not manufacture a clean object in the
receiver.

**Real Pod example.** An unchanged Pod has a converter container and an upload
sidecar sharing `emptyDir /work`. The converter is compromised, reads the
ServiceAccount token, and writes `/work/result.json`; the unrelated sidecar
then uploads every file in `/work`. Native lineage alone sees two legitimate
roots. With `OBJECT_TAINT`, the converter's covered write taints the exact file
before bytes are committed, the sidecar's open/read inherits the sensitive
bit, and its public send is denied. If the converter and sidecar instead share
an `mmap(MAP_SHARED)` ring buffer, the compiler selects
`CONSERVATIVE_DOMAIN_MERGE` before mapping because no hook can attribute every
memory store. A normal converter output written without sensitive state is the
positive control and the upload succeeds.

###### Abandoned design: `OBJECT_TAINT` prevents the `emptyDir` attack

The retained Real Pod paragraph is a useful description of the desired
observation but is wrong as a prevention mechanism. The sidecar can enter a
blocking read while the file is still clean; the converter can then taint and
write it; that already-admitted read can return bytes and race a send before
post-transfer propagation. `OBJECT_TAINT` may report the file/reader relation
at its qualified timing. It cannot return `prevented` for the first transfer.

The normative unchanged-Pod example uses one of two configurations:

- `PRE_USE_CONSERVATIVE_DOMAIN_MERGE`: before either user root is released,
  the exact `/work` backing mount joins converter and uploader to one
  authority domain. Their positive role grants remain distinct. When the
  converter's sensitive acquisition transition commits, the common domain
  gains `NO_PUBLICATION_AFTER_SENSITIVE_ACCESS`; the uploader's otherwise
  valid public-send rule is intersected with that restriction and returns
  `EACCES`.
- `DENY`: if the operator will not accept that common restriction, the
  converter cannot open/write the shared mount or the uploader cannot read it,
  according to the selected reviewed boundary. There is no prevention claim
  for the blocked-reader shape when neither option is selected.

The clean positive control still works under the first configuration: a
converter that has not obtained sensitive authority writes an ordinary result,
and the uploader's own public-send allow remains valid. The difference is the
shared monotonic authority transition, not a claim that Mithril proved which
bytes were secret.

`STATE-CROSS-ENTRY-003` repeats that attack through `emptyDir`, `/dev/shm`, a
pipe, Unix stream/datagram sockets, SysV shm, POSIX shm, shared memfd mapping,
and `SCM_RIGHTS`; it includes init, sidecar, lifecycle, probe, and
administrative roots. It races object creation/reuse and transfer with taint,
forces topology and map loss, and proves the configured deny/merge/taint
result. A profile that enables none of these modes must state that coarse
taint is process/domain-local and cannot claim prevention of cross-root
laundering.

For this fixture, a `taint`-only result is an observation oracle and never the
prevention oracle. Only `DENY` or `PRE_USE_CONSERVATIVE_DOMAIN_MERGE` may pass
the `no marker delivered` prevention branch; this sentence supersedes the
retained phrase “proves the configured ... taint result” wherever that phrase
could be read as physical prevention.

##### Attempted/permitted access versus completed byte read

An LSM `file_open` or `file_permission` allow proves that access was permitted,
not that positive bytes were returned to userspace. Therefore the earlier name
`OBSERVED_SENSITIVE_READ` is superseded for the baseline path by
`SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED`. Mithril sets that conservative bit
atomically **before** returning an allow/audit result from the sensitive
pre-effect hook. A racing network effect then sees either the old state when it
linearized first or the stricter state when the sensitive access linearized
first; there is no userspace update window.

`SENSITIVE_BYTES_CONFIRMED` is legal only on a platform profile that proves an
exact post-syscall join for every enabled read path it claims—`read`, `pread`,
vectored reads, `sendfile`/`splice`, mmap faults where distinguishable,
`io_uring`, descriptor passing, and inherited descriptors—and observes a
positive result. Missing one enabled path prevents the general “bytes read”
claim. The safe exfiltration policy should normally key on the conservative
pre-effect bit.

Domain-sensitive transitions obey these rules:

```text
on allowed/audited pre-effect with nonzero transition_id:
    descriptor = transition_descriptors[
      (process.active_profile_generation_ref_id, transition_id)]
    require descriptor.kind == DOMAIN_SENSITIVE_ONLY and usable for holder
    key = DomainSensitiveTransitionKeyV1 {
      profile_generation_ref_id: process.active_profile_generation_ref_id,
      transition_id,
      current_potential_sensitive_bits: copied_domain.potential_sensitive_bits,
      current_observed_sensitive_bits: copied_domain.observed_sensitive_bits,
      current_restriction_set_ref_id:
        copied_domain.effective_restriction_set_ref_id,
      current_domain_response_set_ref_id:
        copied_domain.effective_response_set_ref_id
    }
    next = domain_sensitive_transitions[key] or deny(TRANSITION_ROW_MISSING)
    require (next.next_potential_sensitive_bits &
             copied_domain.potential_sensitive_bits) ==
            copied_domain.potential_sensitive_bits
    require (next.next_observed_sensitive_bits &
             copied_domain.observed_sensitive_bits) ==
            copied_domain.observed_sensitive_bits
    require next restriction/response SetRefs are nonzero, expected kind,
            ACTIVE for new acquisition, and already owned by prepared
            SetReferenceTombstoneV1 records
    lock domain.domain_lock
    require the complete current key tuple and transition_version still match
    write all four next fields, transfer SetRef ownership, increment version
    unlock before hook returns

on denied effect:
    do not mutate state unless a separate explicit on_deny transition exists
```

The earlier `set_bits`/`clear_bits` rule shape is abandoned in Version 1.
There is no `clear_bits` field: both sensitive bitsets are monotonic for the
authority-domain lifetime. A compiler that receives a next value missing any
current bit returns `CFG_NON_MONOTONIC_DOMAIN_TRANSITION`. The real-world race
is a converter thread opening its projected ServiceAccount token while its
uploader sibling calls `sendmsg`: whichever acquires `domain_lock` first is
the recorded linearization; no reader can observe new sensitive bits with the
old restriction SetRef.

Sensitive-access bits are monotonic for the complete authority-domain lifetime,
not merely until the reading process exits. Other reversible process-role
state uses the separate process transition table; it cannot loosen the domain
floor. A target without the required one-value atomic primitive supports only
the precomputed conservative domain or denies the sensitive access.

**Race test.** Thread A attempts a permitted credential open while thread B
connects to public egress. A barrier fixture runs both possible linearization
orders 100,000 times. If A's atomic state commit wins first, B must use the
strict table. If B's decision wins first, the connect follows the old table
and the evidence records that order; the implementation must not claim the
later sensitive access preceded it. Both threads must report one
`authority_domain_id`; same-process and separate-process members are both
tested.

##### Abandoned design: publication admission completes byte publication

The retained race result is correct only as an **admission-order** statement.
It is not a byte-exfiltration prevention contract. After a clean thread passes
`sendmsg`/`write` authorization, it can block before the kernel copies its
mutable userspace buffer. A sibling could then obtain a secret and replace the
buffer, or an io_uring/SQPOLL request queued while clean could execute after a
later sensitive transition. Saying “the connect/send won first” does not prove
which bytes were delivered.

###### Abandoned design: publication authority split across two map values

The first lease draft below is retained, but it is not the Version 1
transaction. `PublicationLeaseStateV1` is a different map value from
`AuthorityDomainStateV1`, so BPF cannot atomically inspect sensitive bits and
set IDs while incrementing its counter. It also allocates an instance and a
counter in one sentence without a crash order, reserves a writable mapping
after success rather than before release, and has no exact source lifetime for
zero-copy operations. Those claims are abandoned. The canonical single-value
reservation follows the retained draft.

The retained draft proposed an authority-domain publication lease:

```text
PublicationLeaseStateV1 {
  authority_domain_id
  transition_version
  sensitive_state_vector_id
  inflight_publications: u32
  persistent_publication_caps: u32
  publication_epoch: u64
  state: ACTIVE | FAIL_CLOSED_OVERFLOW | RECONCILIATION_REQUIRED
}

PublicationInstanceV1 {
  publication_instance_id
  authority_domain_id
  actor_process_state_id_and_version
  operation: WRITE | SEND | SENDMSG | SENDFILE | SPLICE |
             COPY_FILE_RANGE | IO_URING | MMAP_SHARED_WRITEBACK | OTHER
  exact_sink_object_or_flow
  async_request_or_syscall_identity
  begin_version
  state: INFLIGHT | COMPLETED | CANCELLED | STUCK_FAIL_CLOSED
}
```

The two transitions serialize on the same domain state, without holding a BPF
spin lock across a syscall:

```text
publication_begin:
  atomically require no publication-denying sensitive/response bit
  allocate exact instance and increment inflight_publications
  only then return allow from the pre-effect hook

sensitive_acquisition_begin:
  atomically require inflight_publications == 0 and
                     persistent_publication_caps == 0
  set SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED and stricter set IDs
  otherwise deny this acquisition with the configured EACCES/EAGAIN result

publication_end_or_cancel:
  exact returning/completion/cancellation program resolves the same instance
  decrement once; duplicate end is idempotent; unknown end never decrements
```

The counter is not an event count. Begin/end programs mutate authoritative
maps directly, while ring/WAL records remain best effort. Phase 0 must qualify
the exact paired path for blocking and partial `write*`/`send*`, `sendfile`,
`splice`, `copy_file_range`, io_uring submission/completion/cancellation,
registered files/buffers, SQPOLL, process exit, signal interruption, and fd
close. If any enabled begin can execute without an exact end/cancel owner, the
profile either denies that operation or leaves a conservative
`STUCK_FAIL_CLOSED` lease until frozen iterator reconciliation. It advertises
only syscall-admission ordering when it cannot pair every path.

A writable `MAP_SHARED` mapping to an output file, host-visible mount,
`emptyDir`, persistent volume, NFS, FUSE/CSI, or relay-backed object is a
**persistent publication capability**, not a sequence of visible write
syscalls. Successful mapping increments `persistent_publication_caps`; a later
sensitive acquisition denies while it exists. A process that already has a
sensitive/potential-sensitive bit cannot create the mapping. The cap is
released only after exact full-range `munmap`/mm teardown, async fault and
writeback drainage, and frozen VMA/object reconciliation. `msync`, ordinary
exit, delayed kernel writeback, fork, and exec do not manufacture a clean
interval. If the target cannot prove these postconditions, strict policy denies
the mapping or pre-merges the sink's authority domain.

`STATE-PUBLICATION-LEASE-010` blocks a TCP send and a regular-file write after
their pre-hooks, mutates the userspace buffers from a sibling, and attempts a
token read before kernel copy. The read must deny until the exact publication
ends. Separate branches submit io_uring before the secret attempt and complete
after it, cancel requests, use SQPOLL/registered buffers, and exercise
sendfile/splice/copy-file-range. `STATE-MMAP-PUBLICATION-011` maps output,
NFS/FUSE, `emptyDir`, and a host-visible file writable/shared, then attempts a
secret read and stores a marker followed by `msync`, `munmap`, exit, and delayed
writeback. No strict branch delivers the marker; missing completion or VMA
proof becomes fail-closed/unsupported, not a prevention PASS. A clean
non-sensitive streaming upload remains the positive control.

###### Canonical Version 1 publication reservation

Publication authorization linearizes in the same locked
`AuthorityDomainStateV1` value that owns sensitive state, restriction refs,
and response refs. `PublicationLeaseStateV1` above is only an abandoned view;
there is no second authoritative counter map.

```text
AuthorityDomainPublicationStateV1 {   // inline in AuthorityDomainStateV1
  publication_epoch: u64
  inflight_publications: u32
  persistent_publication_present: bool
  state: ACTIVE | CAPACITY_FAIL_CLOSED | STUCK_FAIL_CLOSED |
         RECONCILIATION_REQUIRED
  slots[MAX_DOMAIN_PUBLICATIONS]: PublicationSlotV1
}

PublicationSlotV1 {
  publication_instance_id: Id128      // zero only when FREE
  descriptor_id: u64                  // nonzero immutable descriptor
  release_epoch: u64                  // zero until domain-side release
  state: FREE | INFLIGHT | COMPLETING | RELEASED_PENDING_ACK
}

PublicationSourceDraftAbandoned =
  USER_MM_BUFFER {
    origin_task_cookie: u64, process_state_id: Id128,
    authority_domain_id: Id128, address: u64, length: u64,
    syscall_entry_sequence: u64, effect_attempt_sequence: u64
  }
  | FILE_OBJECT { object: ExactObjectGenerationV1 }
  | PIPE_BUFFER { pipe: ExactObjectGenerationV1, pipe_generation: u64 }
  | SOCKET_RECEIVE_QUEUE {
      socket: ExactObjectGenerationV1, receive_generation: u64
    }

UserBufferSegmentV1 {
  address: u64
  length: u64 > 0
}

PublicationPayloadSourceV1 =
  USER_BUFFER { segment: UserBufferSegmentV1 }
  | FILE_RANGE {
      object: ExactObjectGenerationV1, offset:u64, length:u64 > 0
    }
  | PIPE_BUFFER {
      pipe: ExactObjectGenerationV1, pipe_generation:u64, length:u64 > 0
    }
  | SOCKET_RECEIVE_QUEUE {
      socket: ExactObjectGenerationV1, receive_generation:u64,
      length:u64 > 0
    }

IpcCapabilityTransferV1 {
  transfer_id: Id128
  kind: SCM_RIGHTS | SCM_CREDENTIALS
  exact_transferred_object?: ExactObjectGenerationV1
  sender_task_cookie: u64
  sender_authority_domain_id: Id128
  receiver_channel: ExactObjectGenerationV1
  required_result: DENY | PRE_USE_DOMAIN_JOIN | DECLARED_SAME_DOMAIN
}

PublicationTransferPlanV1 =
  SINGLE {
    source: PublicationPayloadSourceV1,
    sink: ExactPublicationSinkV1
  }
  | USER_IOVEC {
      segments[1..MAX_IOV]: UserBufferSegmentV1,
      sink: ExactPublicationSinkV1
    }
  | MESSAGE_BATCH {
      messages[1..MAX_MMSG] {
        message_index:u32,
        segments[0..MAX_IOV]: UserBufferSegmentV1,
        sink: ExactPublicationSinkV1,
        capability_transfer_ids[0..MAX_SCM_TRANSFERS]: Id128
      }
    }

SourceMutabilityProofV1 {
  proof_id: Id128
  proof_generation: u64 > 0
  covered_source_identity_digest: DigestV1
  proof: SAME_AUTHORITY_DOMAIN { authority_domain_id:Id128 }
       | PREMERGED_AUTHORITY_DOMAIN { join_transaction_id:Id128 }
       | SEALED_MEMFD {
           object:ExactObjectGenerationV1,
           required_seals:F_SEAL_WRITE|F_SEAL_SEAL,
           no_preexisting_writable_mapping_proof_id:Id128
         }
       | IMMUTABLE_CAS_OR_IMAGE_OBJECT {
           object:ExactObjectGenerationV1,
           content_digest:DigestV1,
           read_only_backing_proof_id:Id128
         }
       | HELD_WRITER_RECONCILIATION {
           object:ExactObjectGenerationV1,
           reconciliation_id:Id128,
           writer_and_vma_snapshot_id:Id128
         }
  valid_from_transition_version: u64
  state: ACTIVE | INVALIDATED | CONSUMED
}

ExactPublicationSinkV1 =
  FILE_OBJECT { object: ExactObjectGenerationV1, offset: u64, length: u64 }
  | NETWORK_FLOW {
      socket: ExactObjectGenerationV1, flow_generation: u64,
      final_destination_identity_digest: DigestV1
    }
  | PIPE_OR_IPC {
      object: ExactObjectGenerationV1, queue_generation: u64
    }

ExactRequestIdentityV1 =
  SYNC_SYSCALL {
    task_cookie: u64, process_state_id: Id128,
    syscall_entry_sequence: u64, effect_attempt_sequence: u64,
    effect_family: u16, operation: u16
  }
  | AIO_REQUEST {
      aio_context_id: Id128, request_id: Id128, submission_sequence: u64
    }
  | IO_URING_REQUEST {
      ring_id: Id128, ring_generation: u64, submission_sequence: u64,
      sqe_index: u32, user_data: u64, opcode: u16
    }
  | MMAP_ATTEMPT {
      task_cookie: u64, process_state_id: Id128,
      authority_domain_id: Id128, attempt_sequence: u64
    }

ExactCompletionIdentityV1 =
  SYNC_RETURN {
    task_cookie: u64, syscall_entry_sequence: u64,
    effect_attempt_sequence: u64
  }
  | AIO_COMPLETION { aio_context_id: Id128, request_id: Id128 }
  | IO_URING_CQE {
      ring_id: Id128, ring_generation: u64, submission_sequence: u64,
      user_data: u64
    }
  | ZEROCOPY_NOTIFICATION {
      socket: ExactObjectGenerationV1, notification_generation: u64,
      first_id: u32, last_id: u32
    }
  | HELD_WRITEBACK_RECONCILIATION { reconciliation_id: Id128 }

TaskEffectAttemptStateV1 {            // BPF task storage
  task_cookie: u64
  syscall_entry_sequence: u64
  next_effect_attempt_sequence: u64
  frames[MAX_NESTED_EFFECT_ATTEMPTS] {
    effect_attempt_sequence: u64
    effect_family: u16
    operation: u16
    hook_discriminator: u16
    repeated_lsm_pass_count: u16
    publication_instance_id?: Id128
    state: ACTIVE | RETURNED | CANCELLED
  }
  depth: u16
  state: ACTIVE | OVERFLOW_FAIL_CLOSED | TASK_EXITED
}

PublicationDescriptorV1 {             // preallocated; immutable while owned
  descriptor_id: u64
  publication_instance_id: Id128
  authority_domain_id: Id128
  actor_process_state_id: Id128
  actor_transition_version: u64
  operation: WRITE | WRITEV | SEND | SENDMSG | SENDMMSG | SENDFILE |
             SPLICE | VMSPLICE | TEE | COPY_FILE_RANGE | AIO |
             IO_URING | MMAP_SHARED_WRITEBACK
  transfer_plan: PublicationTransferPlanV1
  source_mutability_proof_ids[1..MAX_PUBLICATION_SOURCES]: Id128
  async_request_or_syscall_identity: ExactRequestIdentityV1
  required_completion_kind: SYNC_RETURN | AIO_COMPLETION | IO_URING_CQE |
                            ZEROCOPY_NOTIFICATION |
                            HELD_WRITEBACK_RECONCILIATION
  descriptor_creation_sequence: u64
}

PublicationDescriptorLifetimeV1 {
  descriptor_id: u64
  publication_instance_id: Id128
  authority_domain_id: Id128
  slot_reference_owned: bool
  prepared_boottime_ns: u64
  completion_identity_digest?: DigestV1
  completion_boottime_ns?: u64
  domain_release_epoch?: u64
  transition_version: u64
  state: PREPARED | OWNED | COMPLETING | COMPLETED | CANCELLED |
         RECLAIMABLE | CORRUPT
}

PersistentPublicationCapabilityV1 {   // durable evidence/reconcile record
  capability_id: Id128
  authority_domain_id: Id128
  origin_task_cookie: u64
  origin_process_state_id: Id128
  mapping_attempt_identity: ExactRequestIdentityV1::MMAP_ATTEMPT
  reconciled_mm_snapshot_id?: Id128
  exact_sink_object_id_and_generation: ExactObjectGenerationV1
  requested_mapping: {
    file_offset: u64, length: u64,
    prot_bits: READ | WRITE | EXEC,
    map_flags: SHARED | SHARED_VALIDATE,
    unknown_flag_bits: exactly 0
  }
  reservation_epoch: u64
  domain_reference_owned: bool
  transition_version: u64
  state: RESERVED | MAPPING_OBSERVED | RECONCILIATION_REQUIRED | RELEASED |
         RECLAIMABLE
}
```

The abandoned duplicate `process_state_id` field implied one current owner.
The capability records only immutable `origin_process_state_id`; fork,
`mremap`, VMA split and origin exit can leave several or only a child holder.
Live holders come exclusively from held VMA/mm snapshot and reconciliation
records. `STATE-MMAP-PUBLICATION-011` includes fork-before-origin-exit and a
child-only surviving mapping; neither case clears the domain capability early.

Operation/source/completion compatibility is closed:

| Operation | Required source variant | Required completion |
| --- | --- | --- |
| `WRITE`, `SEND` | `SINGLE(USER_BUFFER, sink)` | `SYNC_RETURN`, or `ZEROCOPY_NOTIFICATION` when the socket/request retains pages |
| `WRITEV` | `USER_IOVEC(1..MAX_IOV, one sink)` | `SYNC_RETURN`, or page-lifetime completion when the request retains pages |
| `SENDMSG` | `MESSAGE_BATCH` with exactly one message; that message owns its iovecs, sink, and linked capability transfers | `SYNC_RETURN` or `ZEROCOPY_NOTIFICATION` |
| `SENDMMSG` | `MESSAGE_BATCH(1..MAX_MMSG)`; each message has its own iovecs and sink | `SYNC_RETURN` or exact per-message/zero-copy completion |
| `SENDFILE`, `COPY_FILE_RANGE` | `SINGLE(FILE_RANGE, sink)` | `SYNC_RETURN` or exact async completion |
| `SPLICE` | `SINGLE(FILE_RANGE|PIPE_BUFFER|SOCKET_RECEIVE_QUEUE, sink)` matching the qualified direction | `SYNC_RETURN` or exact async completion |
| `VMSPLICE` | `USER_IOVEC` | page-lifetime completion; syscall return alone is insufficient when pages remain referenced |
| `TEE` | `PIPE_BUFFER` | `SYNC_RETURN` plus qualified pipe-buffer lifetime when transfer remains deferred |
| `AIO`, `IO_URING` | plan required by the concrete opcode; fixed-file/file-copy opcodes require `FILE_RANGE`, scalar buffers require `SINGLE`, and vectored/message opcodes require their closed plan | matching `AIO_COMPLETION`, `IO_URING_CQE`, or zero-copy notification |
| `MMAP_SHARED_WRITEBACK` | the mapped file object plus `MMAP_ATTEMPT`; represented by `PersistentPublicationCapabilityV1` rather than an ordinary slot after mapping commit | held VMA/writeback reconciliation |

The decoder/compiler rejects a missing source, an operation/source mismatch,
a zero-length or wrapping range, an unqualified mutable source, and a
completion kind that cannot prove the kernel stopped retaining the source.
Thus `sendfile`, `splice`, copy, fixed-file and zero-copy paths can never fall
through an optional-source branch.

`PublicationSourceDraftAbandoned` is insufficient for `writev`, `vmsplice`,
`sendmsg`, and `sendmmsg`: it collapses many iovecs and per-message
destinations into one buffer/sink. `PublicationTransferPlanV1` replaces it.
The decoder walks the userspace iovec/message headers once into the bounded
plan, rejects `IOV_MAX`/`MAX_IOV`/`MAX_MMSG` overflow, pointer+length wrap,
partial header reads, and an N+1 element, and rechecks the request identity at
the deciding hook. `SCM_RIGHTS` and `SCM_CREDENTIALS` are authority transfers,
not payload bytes; they require separate linked `IpcCapabilityTransferV1`
transactions and deny if an undeclared transfer cannot be joined before use.

User-buffer segments are request-scoped coordinates, not durable byte identity.
Ordinary write/send hooks cannot use the forensic
`MmSnapshotIdentityV1.userspace_assigned_mm_class_cookie`, which exists only
after a held `kcmp`/iterator snapshot. Mutation safety comes from the
linearized authority-domain publication reservation: while that request owns a
slot, sensitive acquisition anywhere in the domain denies. Address reuse after
completion cannot revive the request because `(task_cookie, process_state_id,
authority_domain_id, syscall_entry_sequence, effect_attempt_sequence)` is
non-reused for that live request.

`SourceMutabilityProofV1` replaces the unproved scalar `IMMUTABLE` claim. An
ordinary regular file is mutable by default. A sealed memfd is eligible only
with `F_SEAL_WRITE|F_SEAL_SEAL` and proof that no writable mapping predated the
seal; `F_SEAL_FUTURE_WRITE` alone is insufficient. A writer fd, pre-seal
`MAP_SHARED`, overlay copy-up, proof-generation reuse, changed object
generation, or invalidated held snapshot makes the proof unusable. Every proof
is read and validated both before reservation and at completion. Otherwise the
source must be in the same authority domain, premerged before use, or the
publication denies.

A target-qualified syscall-entry program increments
`syscall_entry_sequence`; the first deciding hook for one logical effect pushes
one frame and increments `next_effect_attempt_sequence`. Repeated LSM passes
for the same `(syscall, effect, hook discriminator)` reuse that frame and only
increment `repeated_lsm_pass_count`; a nested kernel effect pushes another
bounded frame. The qualified return/completion observer must match task,
syscall, effect attempt and publication instance before it may complete a
slot. `task_free` marks every still-active frame cancelled/stuck for held
reconciliation and cannot infer success. Sequence wrap, depth overflow,
missing entry/return coverage or a mismatched frame denies the protected
effect and marks `OVERFLOW_FAIL_CLOSED`.

`MAX_DOMAIN_PUBLICATIONS` is a platform-manifest constant with an N/N+1
fixture. Slots live inline so the domain spin lock can atomically validate the
authority state, reserve an instance, increment the counter, and advance the
epoch without a map lookup under the lock. The immutable descriptor is built
and read back before that lock is taken. Descriptor loss while a slot is live
sets `STUCK_FAIL_CLOSED`; it never guesses that publication ended.

The exact begin/end algorithms are:

```text
PublicationIdAllocatorV1 {            // pinned one-element ARRAY map
  allocator_lock: bpf_spin_lock
  node_boot_id: Id128
  label_epoch: u64                    // immutable random 64-bit epoch
  next_instance_counter: u64          // starts at 1
  next_descriptor_counter: u64        // starts at 1
  state: ACTIVE | EXHAUSTED | LOST_EPOCH_FAIL_CLOSED
}

publication_instance_id = Id128 {
  high_u64: label_epoch,
  low_u64: allocated_instance_counter
}
descriptor_id = allocated_descriptor_counter
```

The deciding BPF program—not Rust—allocates both counters under
`allocator_lock`, performs no helper call while locked, then inserts descriptor
and lifetime with `BPF_NOEXIST`. Counter zero/wrap, epoch mismatch, map-full,
or an unexpected existing key sets the allocator/domain fail-closed; IDs are
never returned to a free list. The pinned allocator survives a node-agent
restart. Losing it while any labeled task/domain/descriptor survives prevents
reattachment rather than restarting at one. Failure before slot ownership
leaves a `PREPARED` lifetime for bounded Rust reconciliation; failure after
slot ownership leaves the domain reservation live.

The removed `prepared_digest_id` was also an impossible synchronous authority:
Rust cannot hash a descriptor before a syscall-local BPF hook creates its
dynamic buffer/sink fields. BPF instead inserts the complete fixed-layout
descriptor once and reads every field back before domain reservation. Rust
later computes
`SHA-256("MITHRIL-PUBLICATION-DESCRIPTOR-V1" || canonical_map_value_bytes)`
for WAL/evidence and verifies those bytes still match; that digest never grants
the syscall. Mutation of an owned descriptor is corruption and holds the
domain fail-closed.

```text
publication_begin(descriptor):
  1. allocate epoch+counter IDs, insert descriptor and lifetime=PREPARED with
     BPF_NOEXIST, using the allocator protocol above
  2. validate and read back every immutable/lifetime field
  3. resolve label -> process -> current domain and exact source/sink objects
  4. validate every source mutability proof and require each mutable source is
     in this domain, already joined, or backed by an active exact proof
  5. before the effect returns allow, lock the one domain value
  6. revalidate actor version, no sensitive/publication-denying response bit,
     state ACTIVE, counter bounds, and a FREE inline slot
  7. in that same locked value write slot INFLIGHT, increment counter,
     publication_reservation_and_capability_refs, and epoch
  8. unlock; CAS lifetime PREPARED -> OWNED with slot_reference_owned=true;
     re-read exact slot + descriptor + lifetime; mismatch returns denial and
     leaves the reservation conservatively live for reconciliation
  9. only the successful readback returns allow

publication_end(exact_instance, exact_completion):
  1. resolve the same domain, inline slot, descriptor, lifetime and completion
  2. lock the domain value and revalidate all five plus slot state INFLIGHT
  3. set the inline slot to COMPLETING and advance publication_epoch; unlock
  4. CAS lifetime OWNED -> COMPLETING -> COMPLETED or CANCELLED, recording the
     exact completion digest; an unknown completion leaves both fail-closed
  5. lock again, require slot COMPLETING and matching terminal lifetime; then
     decrement counter and the one owned publication ref exactly once, advance
     publication_epoch, and retain `{instance, descriptor, release_epoch}` in
     slot state RELEASED_PENDING_ACK; unlock without making the slot reusable
  6. CAS the external lifetime with that exact release epoch to
     slot_reference_owned=false and record domain_release_epoch
  7. lock again, require the exact RELEASED_PENDING_ACK tuple and acknowledged
     lifetime, then zero IDs/epoch and change the slot to FREE
  8. duplicate/late completion finds no matching live owned slot and never decrements
  9. an unknown or mismatched completion marks the domain STUCK_FAIL_CLOSED
     and waits for held reconciliation
```

A crash after step 7 but before userspace observes allow leaks a reservation,
which blocks sensitive acquisition but leaks no authority. Recovery scans the
inline live slots and immutable descriptors. It may complete an exact kernel-
proven request or keep the domain held; it never decrement-infers from a ring
event or daemon absence. A crash at `INFLIGHT+PREPARED` lets recovery claim the
lifetime as `OWNED`; a crash at `COMPLETING` requires the exact completion or
held reconciliation. A crash at `RELEASED_PENDING_ACK` never decrements again:
recovery copies the retained release epoch into the lifetime and only then
frees the slot. This single-value slot protocol replaces the
cross-map `PREPARED -> counter -> INFLIGHT` draft and gives duplicate completion
an idempotent physical oracle.

After the terminal lifetime and slot/ref release are read back, Rust appends
the completion to WAL, waits the required BPF grace period, CASes the lifetime
to `RECLAIMABLE`, and deletes descriptor/lifetime map entries. Descriptor and
instance IDs are never reused in the node label epoch even though storage is
reclaimed. `STATE-PUBLICATION-LEASE-010` therefore includes two capacity
oracles: N/N+1 simultaneous reservations must fail closed at N+1, while at
least 100× map capacity sequential successful begin/end/reclaim cycles must
remain available with bounded map cardinality. A system that passes only the
concurrent test but leaks every completed descriptor fails qualification.
Crash injection covers before and after `COMPLETING`, domain-side release,
lifetime acknowledgement, and final `FREE`; no run may underflow a counter or
reuse a slot before acknowledgement.

For a writable `MAP_SHARED` publication, the `mmap_file` decision reserves the
domain's monotonic `persistent_publication_present` bit **before** returning
allow, precreates the capability from the origin task and exact mapping
attempt, and acquires its domain reference first. No VMA snapshot is claimed
at this point; `reconciled_mm_snapshot_id` is populated only by the later held
complete reconciliation. Parser/runtime validation rejects any
`MMAP_ATTEMPT` carrying a forensic mm-class cookie or snapshot ID before that
commit. A failed/partial mmap may clear
the bit only through a qualified return observer that proves no VMA acquired
the capability; otherwise it safely leaks into `RECONCILIATION_REQUIRED`.
`munmap`, VMA split/merge, `mremap`, fork, exec, partial unmap, `msync`, and
ordinary exit never clear it individually. Clearance requires a held full-
domain reconciliation: gate new mappings/publications, freeze every member,
drain faults/writeback, run complete before/after-validated VMA snapshots for
every shared-mm class, prove no matching sink VMA/capability remains, then
clear the bit and release the hold in one domain transition. Platforms that
cannot prove this deny the mapping or premerge the sink domain.

After that transition, each matching capability moves to `RELEASED`, releases
its one domain reference exactly once, waits for WAL acknowledgement and the
BPF grace period, then becomes `RECLAIMABLE`. A missing capability record while
the monotonic bit is set keeps the domain in `RECONCILIATION_REQUIRED`; it does
not make the bit disappear.

For `sendfile`, `splice`, `tee`, `vmsplice`, `copy_file_range`, AIO, fixed-file
io_uring and similar paths, the descriptor names the exact source object and
generation. The source must be immutable or already in the actor's common
authority domain; an independent writer cannot replace it between decision
and transfer. Otherwise the operation denies or first performs an out-of-band
domain join and is retried. `SO_ZEROCOPY`, `MSG_ZEROCOPY`, registered buffers,
SQPOLL and any operation whose kernel retains user pages remain reserved until
their exact completion notification—not syscall return. Setup flags/opcodes
are denied on a platform without that paired lifetime.

**Real-world race.** A Python upload thread enters `sendmsg()` with a buffer
containing `result.json` and is stopped immediately after Mithril's pre-effect
hook. A sibling then opens the mounted ServiceAccount token and overwrites the
same buffer. The inline publication slot already exists, so the token open
returns the configured `EAGAIN`/`EACCES`; it cannot commit sensitive authority
while bytes are in flight. In the source-object branch, an independent process
rewrites a file after an `io_uring` send is submitted. Strict mode allows that
send only when the source is immutable or both writers were premerged; the
unqualified fixed-file/zero-copy branch is denied.

`STATE-PUBLICATION-LEASE-010` additionally covers `writev`, `sendmmsg`,
`vmsplice`, `tee`, AIO, `SO_ZEROCOPY`/`MSG_ZEROCOPY`, independent source-file
replacement, missing/duplicate completion, N/N+1 inline slots, and crash after
each numbered begin/end step. `STATE-MMAP-PUBLICATION-011` covers VMA
split/merge, `mremap`, fork, exec, partial unmap, failed mmap, daemon restart,
and full held reconciliation. A PASS requires zero marker delivery and exact
counter/slot/bit state; a conservative leaked reservation is safe but is a
degraded availability result, not a successful cleanup result.

#### Network, sockets, and packets

Network policy has two distinct jobs:

1. pre-effect authorization for socket creation, connection, bind/listen,
   send, and packet transmission; and
2. response fencing for existing and future flows.

The socket label is created in socket storage and carries the creating
task/process/role/profile generation. On inheritance or descriptor passing,
the effect is evaluated against the **current sender** and the socket label;
the receiver does not automatically acquire the creator's network authority.

When task and socket generations differ, the decision is the restrictive
intersection, never “the socket was once allowed, so the new sender is
grandfathered”:

```text
sender_decision = tables[current_process.profile_generation]
                  [current_role, operation, live destination, state]
socket_lifetime_decision = tables[socket.profile_generation]
                           [socket creator/lifetime rule]

deny if either decision denies or either generation is no longer retained
allow only if both allow/audit under their declared lifetime contracts
```

A grandfather exception must name the exact socket/flow and permitted process
lineage; passing it via `SCM_RIGHTS` to another lineage or a new generation
does not transfer the exception.

**Generation test.** Socket S is created under generation 42, then passed with
`SCM_RIGHTS` to a generation-43 task whose role denies that destination. Its
first send is denied by 43 even while S and tables 42 remain retained. Closing
S releases the 42 socket reference.

```text
NetworkEffectKey = (
  current_role,
  socket_creator_role,
  operation,
  family/type/protocol,
  network_namespace_generation,
  destination_class,
  address/prefix,
  port,
  DNS/provenance quality,
  dynamic_state,
  response_state
)
```

##### Correct actor and socket network-namespace identity

The retained single `network_namespace_generation` is ambiguous and is
abandoned as the physical key. A process in network namespace B can use a
socket created in namespace A after fork, fd inheritance, `pidfd_getfd`, or
`SCM_RIGHTS`; changing the actor's namespace does not move the socket. Version
1 evaluates both identities:

```text
NetworkEffectKeyV1 = (
  current_actor_role,
  current_actor_process_and_authority_domain,
  current_actor_netns_identity,
  socket_creator_role_and_generation,
  socket_netns_cookie_and_live_interval,
  socket_creation_or_acceptance_provenance,
  operation,
  family/type/protocol,
  actual_destination_after_qualified_rewrite_point,
  destination_class_and_quality,
  dynamic_and_response_state
)
```

Role and taint come from the current actor. Routing context, socket lifetime,
and destination policy use the socket's network namespace (`sk_net`/qualified
cookie), while actor netns remains evidence and may add a stricter rule. In
`NET-NS-PASS-001`, task A creates a socket in netns A, passes it to task B in
netns B, and B connects/sends. The decision must report actor B and socket
netns A, use A's route/destination class, and deny if either B's role or the
socket lifetime contract denies. A pre-opened socket used after `setns` is the
same test shape.

Required mechanisms include:

- BPF LSM `socket_create`, `socket_connect`, and `socket_sendmsg` where
  available and target-kernel-proven;
- cgroup `connect4/6` and `sendmsg4/6` for address decisions;
- socket storage for process/role attribution;
- cgroup/TC packet policy for established-flow and packet-level fences; and
- explicit coverage for UDP, IPv6, raw/packet sockets, TUN/TAP, AF_XDP,
  `io_uring`, BPF redirects, inherited descriptors, `SCM_RIGHTS`,
  `sendfile`, and `splice`.

The mechanisms are not interchangeable. In particular, cgroup
`sendmsg4/6` address hooks cover UDP send paths; they are not a general
established-TCP send hook. An LSM connect denial controls a new connection but
does not close a socket that was already connected. TC or cgroup-skb egress
can fence packets, but packet context may not contain a meaningful current
task, so it must consume socket/cgroup state installed earlier.

The platform capability manifest contains one row per required path:

| Path | Pre-effect decision | Required identity | Claim when qualified |
| --- | --- | --- | --- |
| New TCP connect IPv4/IPv6 | LSM `socket_connect` and/or cgroup `connect4/6` | current process plus destination | connection attempt prevented |
| UDP connected/unconnected send | LSM `socket_sendmsg` plus cgroup `sendmsg4/6` where supported | current sender, socket label, actual peer | datagram send prevented |
| Send on established TCP | LSM `socket_sendmsg` where its object decision is sufficient; packet fence at TC/cgroup-skb for response | current sender at LSM; pinned socket/cgroup at packet hook | send attempt denied or packets dropped, stated separately |
| Pre-existing/inherited/SCM_RIGHTS socket | sender-time LSM decision plus socket storage | current sender and original socket provenance | current unauthorized use prevented |
| Existing flow after containment | TC/cgroup-skb/socket-destroy actuator as qualified | response set plus socket/cgroup label | subsequent packets fenced; not “connection never existed” |
| Raw/packet/AF_XDP/TUN path | protocol/device/capability hooks plus packet control | task role and interface/device identity | only the specifically tested path |

Every row is independently `SUPPORTED|UNSUPPORTED|OBSERVATION_ONLY`. A profile
requiring “no public egress” cannot be full support while any enabled escape
path is unknown.

##### Socket lifecycle and protocol coverage

LSM `socket_create` can pre-authorize family/type/protocol, but it does not
receive the completed socket object to label. Socket storage is first installed
at a qualified post-create/cgroup socket hook or the first guaranteed
socket-bearing hook before bind/connect/send. If installation fails, strict
profiles deny the first operation and emit `SOCKET_IDENTITY_MISSING`; they do
not use an unlabeled socket.

The platform matrix separately qualifies:

| Operation | Candidate enforcement/label point | Required fixture |
| --- | --- | --- |
| create | `socket_create` decision; qualified post-create/cgroup sock hook for storage | every enabled family/type/protocol and storage failure |
| bind/listen | `socket_bind`, `socket_listen`, cgroup bind hooks where applicable | wildcard, loopback, IPv4/6, reused port, Unix/vsock/netlink |
| accept | `socket_accept` plus accepted-socket storage before use | allowed listener receiving a connection that an unauthorized task inherits/passes |
| socketpair | `socket_socketpair` plus both endpoints labeled | Unix stream/datagram pair passed across roles |
| connect/send/receive | LSM/cgroup hooks named in the path matrix | TCP/UDP plus Unix, netlink, vsock, raw, packet, inherited/passed fd |
| close/release | release observation and storage/reference reconciliation | rapid close/reuse and lost close event |

The `accept` row does not mean that pre-return `security_socket_accept` alone
can label the completed accepted socket. Each enabled protocol needs a
qualified post-clone/graft point before the child socket's first use: candidate
points include `sk_clone_security`/TCP clone plus `sock_graft`, the `newsk`
path of `unix_stream_connect`, and target-specific SCTP clone/MPTCP subflow
hooks. The platform records the exact function/hook and ordering it proved. If
the accepted child has no storage at its first protected use, strict policy
denies `SOCKET_IDENTITY_MISSING`.

`NET-ACCEPT-PASS-001` accepts a connection and immediately passes the accepted
fd to another role before either process performs I/O. That receiver's first
read/send must see accepted-socket provenance plus the receiver's task label.
Rapid accept/close/fd-number reuse cannot inherit old storage. SCTP and MPTCP
fixtures repeat the case for every advertised clone/subflow path.

For a full “no undeclared egress” claim, the compiler takes one of two concrete
positions per family/protocol: deny its creation at `socket_create`, or qualify
all of its secondary paths. The latter includes SCTP bind/connect and
multihoming, MPTCP new subflows, netlink sends, vsock, InfiniBand/RDMA,
AF_XDP, packet/raw sockets, and every enabled tunnel/redirect mechanism. It is
not enough to test one TCP `connect` and one UDP `sendmsg`.

Socket control is a separate operation family:

```text
SocketControlEffectKeyV1 = (
  current_actor_role,
  socket_provenance,
  SETSOCKOPT | IOCTL | NETLINK_CONTROL,
  level,
  option_or_command,
  qualified_value_class,
  socket_netns,
  response_state
)
```

Options such as `SO_MARK`, `SO_BINDTODEVICE`, `IP_TRANSPARENT`, `IP_FREEBIND`,
`SO_ATTACH_BPF`, reuseport selection, packet fanout, MPTCP/TCP ULP, and routing
controls can change the enforcement path or delegate network authority. The
generic LSM `socket_setsockopt` decision may expose level/option but not a safe
semantic copy of every option value. Fixed value classes require a
target-qualified post-copy kernel hook; pointer/large/unknown values are denied
by option or use a specialized hook, never dereferenced from mutable userspace
for authorization. Socket ioctl/compat and bounded netlink-control messages
have their own qualified paths.

`NET-SOCKCTL-001` tries route/mark/interface changes, transparent/freebind,
attaching/replacing BPF filters, reuseport listener selection, packet fanout,
TCP ULP/MPTCP changes, native/compat ioctls, and an unknown option. The final
packet fence and socket readback must remain consistent; an approved harmless
option is the negative control.

##### Exact socket-generation reference lifetime

An fd `close` event is not socket death: duplicated/passed descriptors,
in-flight `SCM_RIGHTS`, protocol references, accepted children, and MPTCP/SCTP
subobjects may keep the kernel socket alive. Userspace close observation must
not decrement `BindingGenerationState.socket_refs`.

On each qualified protocol, installing socket storage atomically increments
one generation reference for that kernel socket/subobject. A target-proven
`sk_free_security` or equivalent final destruction hook performs an
idempotent, non-sleeping `REFERENCE_OWNED -> REFERENCE_RELEASED` transition,
decrements once, and writes only a fixed tombstone/counter. Rust consumes the
evidence but never decides physical lifetime from fd numbers. If a protocol
has no qualified destruction hook or safe iterator, its generation is retained
conservatively until profile/node teardown.

`NET-SOCKET-LIFE-001` duplicates a socket, closes one fd, passes another in
flight, exits the creator, accepts TCP children, creates enabled MPTCP/SCTP
subobjects, drops the rich death event, and finally destroys every reference.
No early close decrements; each kernel object decrements exactly once at final
death despite event loss/map pressure. Reconciliation may repair evidence but
cannot free a generation whose object lifetime is unproved.

##### Shared-socket containment blast radius

Current-actor LSM checks can deny a contained process's future send/receive
calls, but queued bytes, retransmissions, and stack-generated packets have no
reliable per-sender `current` at TC/cgroup-skb. When two lineages share one TCP
socket, Mithril cannot selectively remove only one lineage's already queued
bytes.

Response compilation therefore either atomically unions a restrictive
socket/flow-fence bit into the socket lifetime state and fences/destroys the
**whole socket/flow** before reporting `APPLIED`, or reports narrow packet
containment `UNSUPPORTED/PARTIAL`. The response record enumerates every known
sharing lineage and the resulting blast radius. It never attributes a packet
to a contained actor merely from the current task at a packet hook.

`NET-SHARED-RESPONSE-002` has two roles concurrently use one established TLS
socket, queues data from both, contains one role, then triggers retransmission
and new sends from both. Whole-flow mode yields no later packet from that
socket and reports impact to both roles. Narrow mode may deny the contained
role's new syscall but remains partial for queued packets; it cannot claim
per-lineage packet fencing.

**Real workload example.** The Hugging Face-style conversion worker is
configured for TCP/443 to the exact dataset/result service and UDP/TCP DNS to
the cluster resolver. `socket_create` rejects AF_PACKET, AF_XDP, AF_VSOCK,
SCTP, MPTCP, and RDMA because that worker has no declared need. If an operator
enables MPTCP for the result service, the profile cannot claim full egress
coverage until an extra-subflow fixture attempts a denied address and the
actual packet is absent. A legitimate node-network agent uses a separate node
role; its needs do not broaden the conversion worker.

##### Receive-path semantics and queued data

The lifecycle table names receive, but connect/send coverage does not prove
receive prevention. A qualified `socket_recvmsg` decision reads the current
actor plus socket provenance and can deny before bytes are copied to that
caller. The honest oracle is `recv*` returns the configured errno and the user
buffer remains unchanged; an ingress packet may already have arrived or remain
queued, so Mithril does not report “packet never reached the node.”

For unconnected datagrams, the exact remote source may not be available at a
generic pre-copy LSM boundary. Source-selective policy therefore needs a
qualified ingress packet/socket association or denies receive for the whole
socket class. Existing queued data, `recv`, `recvfrom`, `recvmsg`, `recvmmsg`,
io_uring receive, SQPOLL, and enabled AF_UNIX/vsock/netlink/protocol paths are
separate capability rows. Unsupported families are denied at create for a full
bidirectional-isolation claim.

`NET-RECV-001` queues a marker before containment, then races ordinary recv,
`recvmmsg`, and io_uring recv from two roles sharing the socket. Each denied
caller receives zero marker bytes even though the queue/packet counter may show
arrival. A permitted dataset-service receive is the negative control. If an
SQPOLL worker cannot recover the submitting authority, its setup is denied or
receive coverage is `UNSUPPORTED`.

`sendfile`, `splice`, every supported `io_uring` opcode, SQPOLL worker context,
and BPF redirect each need a tested decision point carrying or recovering the
exact process/socket/file state. If a kernel worker makes `current` unusable,
Mithril must bind the operation at submission/setup or mark that path
unsupported/deny its setup. Listing the path is not coverage.

Initial destination classes include `kubernetes-api`, `cloud-imds`,
`cloud-api`, `public-internet`, `approved-dataset-service`, `artifact-store`,
`mesh-control`, `mesh-peer`, `connector`, and `unknown`.

DNS is evidence, not destination identity by itself. The node records query,
answer, TTL, network namespace, and socket timing, then enforces the actual
address/prefix/service identity. Hard-coded IPs, stale DNS, CNAMEs, IPv6,
private endpoints, and alternate interfaces must not bypass the class.

A conversion role that never needs the Kubernetes API or IMDS is denied at
connect/send. A controller role that needs the Kubernetes API may connect; its
verbs and resources are evaluated later from Kubernetes audit. Direct TLS
remains opaque.

##### Destination rewriting and final-address proof

A cgroup `sock_addr` program may rewrite the address supplied to `connect` or
`sendmsg`, and CNI/mesh/other BPF programs can share the attach chain. A check
of the original sockaddr is therefore not proof of the final destination.
Mithril records and reads back every relevant cgroup/TC/XDP link, program
digest, attach mode, and execution order. It makes a broad destination claim
only when one of these is qualified:

1. Mithril exclusively owns the relevant chain and decides after all permitted
   rewrites;
2. a target-proven post-rewrite hook exposes the actual address and still has
   authority to deny; or
3. a final TC/cgroup-skb packet fence enforces the actual packet destination,
   with the result described as packet prevention rather than connect denial.

Unknown/reordered links or a chain update close network coverage before new
strict admission. `NET-REWRITE-001` supplies an originally allowed address and
has another program rewrite it to IMDS or a denied public address, once before
and once after Mithril's cgroup program. NAT and BPF redirect variants are
separate. The final physical packet must be absent; if only the original
sockaddr was checked, the test fails the broad egress claim.

##### DNS is an egress channel, not automatically safe infrastructure

Allowing UDP/TCP 53 to the cluster resolver lets a compromised worker encode a
secret in attacker-controlled query names. Destination-only DNS permission
does not prevent that channel. Every role selects one mode:

```text
DnsPolicyMode =
  NO_RUNTIME_DNS_SIGNED_SERVICE_ADDRESSES
  | SEMANTIC_RESOLVER_GATE
  | DESTINATION_ONLY_WITH_PAYLOAD_GAP
```

- `NO_RUNTIME_DNS_SIGNED_SERVICE_ADDRESSES` pre-resolves signed service/IP
  policy and denies all runtime DNS for the role.
- `SEMANTIC_RESOLVER_GATE` uses an owned node/CNI/resolver request boundary—not
  TLS interception—to enforce tenant, qname suffix/exact name, query type,
  response/CNAME chain, length/rate/cardinality, and request ID. Direct packets
  to other resolvers are denied.
- `DESTINATION_ONLY_WITH_PAYLOAD_GAP` allows the approved resolver address but
  records `DNS_PAYLOAD_SEMANTICS_UNENFORCED`; resolver logs may detect unusual
  queries after the fact. It cannot claim secret-exfil prevention.

DoH, DoT, and HTTP CONNECT to an otherwise allowed TLS endpoint remain the
same encrypted-channel semantic limitation unless their endpoint is denied or
the service itself supplies typed audit/admission. `NET-DNS-EXFIL-001` encodes
a marker in UDP and TCP qnames, CNAME chains, truncation/retry, fragments,
alternate resolver addresses, DoH, and DoT. The selected mode's physical
oracle must match exactly. One declared service lookup succeeds under the
semantic gate; a destination-only result is explicitly degraded rather than
reported prevented.

`NET-DNS-EXFIL-001.upstream_source_evidence_ids` includes `KA-CODE-006`,
`KA-CODE-012`, `TG-CODE-007`, `TG-CODE-015`, and
`SOURCE-BOUNDARY-001`. In particular, it must exercise port 53 payloads above
512 bytes, missing iovec/classifier state, non-53 DNS, literal IP, DoH, and DoT
so Mithril never inherits the pinned KubeArmor parser's checked-in allow gaps
while citing only its useful hook placement.

#### Devices and ioctl APIs

Device admission uses cgroup v2 device BPF for major/minor/access plus file and
ioctl policy for the API exposed by the device:

```text
DeviceEffectKey = (
  role_id,
  device_type,
  major,
  minor or range,
  access: read | write | mknod,
  ioctl_command_class,
  lifecycle_state
)
```

That compact tuple spans three different boundaries and must be compiled into
separate keys:

```text
CgroupDeviceFloorKey = (device_type, major, minor_or_range,
                        MKNOD | READ | WRITE)
DeviceFileEffectKey  = (current_role, exact_device_object,
                        OPEN_READ | OPEN_WRITE)
DeviceIoctlEffectKey = (current_role, exact_device_object,
                        native_or_compat_abi, ioctl_command)
```

Cgroup-device BPF supplies the major/minor/access floor. File LSM hooks apply
the current-role object policy, including to a descriptor passed from another
role where the operation rechecks. `file_ioctl` and qualified compat ioctl
coverage decide command numbers. An ioctl argument that is a userspace pointer
is not dereferenced for an authorization decision because the memory can change
and creates a TOCTOU race; a command such as `TUNSETIFF` is allow/deny by
device/command unless a separate kernel semantic hook is qualified. Dedicated
TUN create/attach/open hooks are used where supported.

##### Correct device-fd lifetime operations

The retained `DeviceFileEffectKey` covers only acquisition and is insufficient
for a pre-opened, inherited, duplicated, `pidfd_getfd`, or `SCM_RIGHTS`-passed
GPU/KVM/FUSE/TUN/device fd. It is superseded by:

```text
DeviceFileEffectKeyV1 = (
  current_actor_role_and_authority_domain,
  exact_live_device_object,
  operation: OPEN_READ | OPEN_WRITE | READ | WRITE |
             MMAP_DATA | MMAP_EXEC | POLL | ASYNC_SUBMIT,
  descriptor_acquisition_provenance,
  native_or_compat_abi,
  dynamic_and_response_state
)
```

| Operation | Required decision point or honest fallback |
| --- | --- |
| `OPEN_*` | cgroup-device floor plus `file_open` and exact live device object |
| `READ`/`WRITE` | qualified current-actor `file_permission`/device path for every enabled syscall, splice, and io_uring variant; otherwise deny descriptor transfer/acquisition or mark use coverage unsupported |
| `MMAP_DATA`/`MMAP_EXEC` | `mmap_file`, `file_mprotect`, executable-stack/image policy, and pkey/personality variants where enabled |
| `POLL` | target/device-specific returning hook when qualified; there is no assumed universal rich LSM poll authorization, so strict roles deny receiving/acquiring the fd or deny the syscall class with a launcher floor |
| `ASYNC_SUBMIT` | bind the exact registered fd/opcode/current authority at qualified io_uring submission/setup; SQPOLL without recoverable authority is denied at setup |
| descriptor receive/duplication | `file_receive` and exact pidfd/dup/SCM_RIGHTS coverage where available; receiving a device fd is a new authority decision, not ownership transfer |

Cgroup-device BPF does not re-authorize later I/O on an already open fd. A
profile may advertise only the rows it physically proved; denying `/dev/kvm`
open does not establish protection after a host helper passes a KVM fd.

##### Derived kernel capability objects

Some allowed device or subsystem commands mint a new anonymous capability fd
that is no longer the original character-device object. For example,
`KVM_CREATE_VM` on `/dev/kvm` returns an anon-inode VM fd, which can create
vCPU/device fds; DRM/GPU, perf, and io_uring APIs have analogous delegation.
Applying only the original major/minor rule to those fds is abandoned.

```text
DerivedKernelCapabilityObjectV1 {
  capability_object_id
  parent_device_or_capability_object
  creating_actor_process_role_generation
  creating_command_and_result
  returned_fd_kernel_object_identity
  capability_class
  live_interval
  retained_policy_generation
  response_state
}
```

The object is labeled at a target-qualified post-return/driver creation point
before another task can use the returned fd. Subsequent ioctl/read/write/mmap/
async decisions combine the current actor with this immutable creation chain.
If no such label point exists, policy may allow or deny the minting command as
a whole but cannot advertise granular post-mint authority.

`DEVICE-DERIVED-001` allows `/dev/kvm` open, creates a VM and vCPU fd, then
duplicates/passes/acquires it through `SCM_RIGHTS` and `pidfd_getfd` after the
creator exits. Another role attempts ioctl and mmap; fd-number reuse is forced.
Every operation resolves the live derived object and its creation generation,
and the generation reference decrements only at actual object death.

**Real device example.** A legitimate GPU sidecar opens `/dev/nvidia0` and
passes the fd to the conversion worker over a Unix socket. If policy permits
only inference ioctls, the receiver admission records the exact device and
current worker role, harmless qualified commands pass, and a VM-management or
unclassified ioctl is denied. In the negative test, the same fd is inherited
before Mithril attaches and used via `mmap`, `read`, `poll`, and io_uring. Each
advertised row must deny at its own physical point; an uncovered poll path
returns `UNSUPPORTED` rather than inheriting success from `file_open`.

**Device tests.** Exercise native and compat tasks, pre-opened and
`SCM_RIGHTS`-passed device fds, TUN/TAP create/attach variants, alias nodes with
the same major/minor, and an allowed harmless versus denied dangerous ioctl.
If the only required decision happened before Mithril attached, the result is
coverage unknown rather than a successful open denial.

`/dev/net/tun` is a key Hugging Face control. Denying the file or cgroup-device
access prevents an unapproved process from creating a TUN interface even if a
mesh client binary is present. Raw block devices, GPUs, accelerators, FUSE,
KVM, and terminal devices require separate policy classes; “device allowed”
does not mean every ioctl is allowed.

#### Privilege and kernel escape effects

The security effect family covers:

- capability checks and credential transitions;
- setuid/setgid/file-capability executable transitions;
- ptrace and cross-process access;
- namespace create/join and `setns`;
- mount, pivot-root, filesystem context, and propagation changes;
- BPF program/map operations;
- perf events and kernel tracing interfaces;
- kernel module loading;
- keyring operations;
- dangerous sysctls and `/proc` control files; and
- seccomp changes that weaken an existing floor.

The list compiles through this operation matrix; a family name alone is not a
prevention claim:

| Operation | Syscall/API variants | Candidate pre-effect hook/floor | Required fallback and test |
| --- | --- | --- | --- |
| capability/credential change | capability use, `capset`, setuid/setgid, file capabilities at exec | `capable`, task credential/fix-setuid hooks, bprm credential hooks | seccomp/capability floor plus tests for ambient, inheritable, bounding and user-namespace cases |
| ptrace/process inspection | attach, seize, `PTRACE_TRACEME`, process-vm and proc-memory paths | `ptrace_access_check`, `ptrace_traceme`, file/proc hooks | deny all uncovered cross-process APIs; same/cross PID namespace tests |
| clone namespace creation | clone/clone3 namespace flags | qualified `task_alloc` flags plus namespace/capability policy | seccomp floor for whole syscall classes; one test per namespace flag |
| `unshare`/`setns` | all flags/fd namespace types | there is no assumed generic `task_setns` LSM hook; use preinstalled seccomp/capability floor and downstream object hooks | if no pre-run floor can deny the requested syscall, that direct claim is unsupported; test every enabled namespace |
| mount/root changes | legacy mount/umount, new mount API, move_mount, open_tree, pivot_root | `sb_mount`, move-mount/pivot-root and `fs_context` family hooks as target-qualified | seccomp/capability floor for uncovered variant; mount topology must update atomically or classifier fails closed |
| BPF | map/prog/link/token create/use and command variants | target `bpf`, `bpf_map`, `bpf_prog`, `bpf_token` LSM hooks plus capability/lockdown | deny `bpf(2)` by seccomp when rich use is unnecessary; fixture per advertised command |
| perf/tracing | perf event open/read/write/attach and trace interfaces | target perf-event LSM hooks plus file/capability policy | deny syscall/interface family when hook coverage incomplete |
| kernel/module/firmware load | init/finit/delete module and kernel file/data loads | `kernel_read_file`, `kernel_load_data`, lockdown/module policy hooks | seccomp/capability floor; test fd-based and memory/data variants |
| keyrings | add/request/update/link/read/invalidate/revoke | `key_permission` and qualified key lifecycle hooks | deny syscall family or mark uncovered operation unsupported |
| io_uring privileged delegation | ring setup/register, SQPOLL, credential override, uring command | qualified `uring_allowed`, SQPOLL/override-credential/command hooks plus operation hooks | deny setup/register modes that lose current-task attribution; test SQPOLL and registered fds |
| seccomp supervisors | installing user-notification listener, trace supervisor relationships | seccomp floor plus ptrace/file/socket/fd-transfer controls | deny unapproved listener/tracer creation or handoff; filters themselves cannot be weakened |

The retained “legacy/new mount API” shorthand expands into separate keys and
fixtures for `chroot`, `pivot_root`, legacy mount/remount/bind/propagation,
`umount2`, `fsopen`, every `fsconfig` command, `fsmount`, `fspick`, `open_tree`,
`move_mount`, and `mount_setattr` including recursive/idmap/flag changes.
Unknown commands/flags are `UNSUPPORTED`/denied. A host task that first joins a
protected mount namespace is included; testing only workload-originated mounts
does not qualify the family.

##### Exact credential and proc/sysctl operation coverage

The compact `setuid/setgid` row is not a syscall inventory. Each platform
matrix separately maps and tests `setuid`, `setreuid`, `setresuid`, `setfsuid`
and their GID variants, `setgroups`, `capset`, file-capability exec,
`prctl(PR_CAP_AMBIENT_RAISE|LOWER|CLEAR_ALL)`, bounding-set drops,
securebits, and `PR_SET_NO_NEW_PRIVS`. Architecture compatibility entry points
are included where enabled. Dropping privilege may be permitted by the exact
runtime-setup budget; regaining or changing identity is a different key.
`no_new_privs` itself is monotonic and cannot be “cleared,” so policy verifies
its installation rather than inventing a weakening operation.

The listed dangerous sysctl/proc family compiles to real objects and calls:

| Object/action | Identity and decision point | Full-support requirement |
| --- | --- | --- |
| `/proc/sys/**` read/write | procfs mount identity, relative sysctl key, owning user/net namespace, current actor; `file_open`/`file_permission`/inode hooks | exact write denial and namespace identity, or deny whole writable proc-sys class |
| `/proc/sysrq-trigger`, `/proc/kcore`, `/proc/kallsyms`, `/proc/keys` | exact proc object plus file hooks and capability floor | deny undeclared access; never rely on displayed path alone |
| `/proc/<pid>/{mem,maps,map_files,fd,fdinfo,ns,environ,attr}` | target task cookie/PID namespace/live interval plus file, ptrace, and proc-specific hooks | distinguish self/cross-task only when exact target resolver is qualified |
| `/proc/<pid>/{uid_map,gid_map,setgroups}` | target user namespace/task identity plus file hooks and namespace/capability floor | test mapping order and helper process in parent namespace |
| debugfs/tracefs/securityfs and `/sys/kernel/**` controls | exact superblock/mount/object class plus file/capability/lockdown hooks | deny uncovered control objects or mark family unsupported |
| legacy architecture sysctl syscall, if present | explicit syscall variant plus seccomp/capability floor | deny or separately qualify; procfs coverage does not imply syscall coverage |

**Real privilege example.** A conversion worker writes
`/proc/sys/net/ipv4/ip_forward`, then tries `setfsuid(0)`, ambient capability
raise, `setgroups`, opens another task's `/proc/<pid>/mem`, and invokes a
compat credential syscall. Every attempt names its actual hook/object and
returns the configured errno. A runtime setup task may execute the one
predeclared UID/GID/capability-drop sequence; swapping one UID, adding a group,
or reordering beyond its signed budget fails container start. This negative
control prevents “deny every credential syscall” from breaking legitimate
runtime setup while still proving worker isolation.

Additional host-control operations are explicit capability rows:

| Operation family | Concrete variants | Decision/fallback and physical oracle |
| --- | --- | --- |
| process signal/release | `kill`, `tkill`, `tgkill`, `pidfd_send_signal`, queued signals, `process_mrelease` and enabled process-lifecycle APIs | qualified `task_kill`, ptrace/process hooks, and syscall floor; protected daemon/runtime target returns errno and remains alive |
| cgroup control | writes to `cgroup.procs`, `cgroup.threads`, `cgroup.freeze`, `cgroup.kill`, controller/subtree files; cgroup attach/move | exact cgroupfs live object plus file/cgroup hooks; target tasks remain in expected binding and are neither frozen nor killed |
| bpffs/BPF object control | pin/unpin/rename, `BPF_*_GET_FD_BY_ID`, map update/delete/freeze, link/prog detach/update, token/delegation commands | bpffs file-object policy plus target BPF LSM/capability/lockdown hooks; required link/map/program IDs and digests remain readable and unchanged |
| daemon/runtime replacement | write/rename/unlink/mount-over executable, libraries, unit files, sockets, config, or bpffs roots | immutable object policy, mount floor, service/cgroup isolation, and measurement; next readback matches approved bytes/config |
| reboot/kexec/kernel lifecycle | `reboot`, kexec file/memory variants, crash paths | lockdown/kernel-load hooks plus seccomp/capability floor; call fails and node boot ID remains live |
| identity/time host state | `sethostname`, `setdomainname`, `clock_settime`, `settimeofday`, `adjtimex`, time namespace operations | seccomp/capability floor or target-specific hook; exact UTS/time state is unchanged |
| dump/core controls | `PR_SET_DUMPABLE`, `PR_SET_PTRACER`, core-pattern/proc sysctls, coredump target files/pipes | prctl/seccomp plus proc/file/ptrace policy; no unauthorized core artifact or pipe helper starts |
| kernel event/delegation APIs | `fanotify_init/mark`, `userfaultfd`, perf/BPF/io_uring delegated fds | deny syscall/setup or qualify exact object/mark/command hooks; no observer/delegated fd is created |

`SELF-PROTECT-001` starts a hostile privileged/hostPID task and attempts every
signal variant against `mithril-node`, kubelet, runtime, and shim; writes every
listed cgroup control; unpins/replaces BPF objects; obtains map/program/link fds
by ID and mutates them; mounts over/replaces runtime bytes; and invokes
reboot/kexec. Each supported hard floor has an independent errno and readback
oracle. If root changes a required mechanism, that family's coverage closes
before any later prevention claim. If only `mithril-node` dies, pinned kernel
decisions continue within their proven limits and userspace-dependent
admission fails closed as specified; those two failures are not conflated.

Hook spelling and availability are taken from target BTF/build capability
records, not inferred from kernel version. A new syscall variant or command not
mapped to a qualified pre-effect boundary makes that operation
`UNSUPPORTED`/denied under a full family profile; it never inherits a claim
from a similar older syscall.

The selected LSM/cgroup/seccomp hooks vary by kernel. Phase 0 produces a
capability matrix and controlled deny probe per claimed operation. A missing
hook is a reduced protection tier, not a best-effort equivalent.

Seccomp is complementary: it cheaply removes syscall classes a role never
needs, but ordinary seccomp cannot decide rich file objects, cgroup-bound
roles, Kubernetes identities, or provider operations. Landlock and mount
namespaces can provide optional process-local/filesystem floors, but Mithril's
node BPF LSM remains necessary for exact cross-process roles, runtime-created
entries, dynamic response, network/device/security effects, and evidence.

##### Abandoned design: detecting a task weakening its installed seccomp floor

The earlier bullet “seccomp changes that weaken an existing floor” is
factually wrong for ordinary seccomp filters. Once installed, filters are
inherited across allowed fork/clone/exec and additional filters can only layer
more restrictions; a task cannot detach an existing filter or add a more
permissive override. That bullet is retained as a rejected concern.

The real Mithril seccomp responsibilities are:

- verify that an optional runtime/launcher-installed floor exists before the
  protected task runs and matches the expected digest/mode;
- deny or alert attempts to create dangerous **new** seccomp user-notification
  or ptrace relationships when the role lacks them;
- model `SECCOMP_RET_USER_NOTIF` and especially `SECCOMP_RET_TRACE` supervisor
  authority, because a permitted tracer/supervisor can affect syscall
  execution; and
- report a start/coverage gap when the unchanged deployment offered no seam to
  install the floor. Mithril cannot inject seccomp retroactively into an
  arbitrary already-running task and call it equivalent.

##### Seccomp floor proof levels

The phrase “matches the expected digest/mode” also needs a proof source.
`/proc/<pid>/status` can expose seccomp mode and filter count, but does not let
Mithril read back arbitrary installed classic-BPF bytecode and hash it. Version
1 records one of:

```text
SeccompFloorProofV1 {
  level: INSTALLER_ATTESTED | KERNEL_OBSERVED | PRESENCE_ONLY | ABSENT
  expected_filter_digest?
  installer_measurement_and_setup_ticket?
  observed_mode
  observed_filter_count
  tsync_scope_and_result?
  listener_or_trace_actions_present
  target_task_set
}
```

- `INSTALLER_ATTESTED`: the trusted held-task launcher hashes canonical filter
  bytes, installs those exact bytes, records the syscall/result, and Mithril
  verifies mode/filter count on every target thread before resume.
- `KERNEL_OBSERVED`: a target-qualified kernel attach path records sufficient
  installed filter identity/content to prove the expected digest and scope.
- `PRESENCE_ONLY`: only mode/count are visible. It may prove “some filter is
  installed,” never that the expected deny rules exist.
- `ABSENT`: no floor is claimed.

Without the owned pre-run install seam or separately qualified kernel proof,
the platform cannot advertise an exact seccomp digest. `SECCOMP-QUAL-001`
installs correct and wrong bytecode with the same mode/count, forces install
failure, triggers partial `TSYNC` failure across threads, and exercises
`NEW_LISTENER`, `USER_NOTIF`, and `TRACE`. Only the correct full-task-set
installation reaches `INSTALLER_ATTESTED`; presence-only evidence cannot
authorize the workload as if its syscall floor were known.

##### Correct Landlock scope and limitation

Calling Landlock only a filesystem floor is outdated. Its ABI is
capability-detected: filesystem rights include execute/read/write/refer,
truncate, device ioctl, and pathname Unix-socket resolution as their ABI
versions permit; network rules include TCP bind/connect and, on newer ABI,
UDP bind/connect-send; scopes can restrict signals and abstract Unix sockets.

Landlock is still optional in Mithril's unchanged-deployment baseline because
it is installed by a process on itself (and inherited by descendants), is
monotonic, and cannot be centrally rewritten for a new dynamic response. On
older ABI, applying a rule in only one thread also does not necessarily cover
existing sibling threads. An OCI/runtime launcher can install a Landlock floor
before exec when the deployment supports that integration; `mithril-node`
records the exact ABI/handled rights and never assumes unsupported rights were
enforced.

**Practical combination.** A runtime-created worker receives a mount namespace
that hides the host, a Landlock rule that permits only dataset/scratch paths
and selected TCP ports, and a seccomp floor that removes module-loading and
other unused syscall classes. BPF LSM/cgroup policy still distinguishes the
worker from a kubelet probe in the same container, follows multiple external
roots and native descendants, changes response restrictions dynamically,
classifies exact file/device/socket objects, and emits correlated evidence.
If Landlock ABI lacks UDP or the launcher seam is absent, those layers are
reported absent; BPF coverage is evaluated independently.

<a id="part-v-evidence"></a>

## Part V — Evidence, Correlation, And Response

### Deterministic Detection And Correlation Algorithms

Local prevention is not enough when an effect was allowed, happened before
attachment, used an existing encrypted channel, or originated outside the
node. Mithril Control runs versioned packages over immutable observations.

#### Evidence prerequisites

Every package declares:

```text
PackagePrerequisite {
  required_sources[]
  required_coverage_intervals[]
  maximum_lateness_by_source
  exact_join_fields[]
  permitted_contextual_fields[]
  suppression_requirements[]
}
```

An unavailable audit feed produces `insufficient_coverage`, not “no malicious
operation.” Events can arrive in any order. Package state is keyed by exact
subjects and recomputed when late evidence arrives; duplicates are idempotent.

#### Normative observation and coverage records

Every source normalizer emits one versioned envelope. A package cannot consume
an unwrapped ad hoc event:

```text
ObservationEnvelopeV1 {
  tenant_id
  observation_id
  source_id
  source_epoch
  source_sequence
  source_event_id?
  node_boot_id?
  cpu_id?
  hook_or_adapter_id
  abi_or_adapter_version
  policy_generation?
  event_boottime_ns?
  projected_utc
  projected_utc_uncertainty_ns
  ingestion_utc
  payload_kind
  payload_schema_version
  payload
  proof_quality
  coverage_interval_id
  integrity { transport, key_id?, batch_digest? }
}
```

`observation_id` is a deterministic digest of tenant, source epoch/sequence,
payload schema, and canonical payload. Provider duplicates use the provider's
stable event ID when present; receiving the same provider record twice creates
one observation. Payload schemas use the same canonical type rules as signed
policy and have explicit maximum lengths.

Kernel sources maintain per-CPU, per-hook counters:

```text
attempted       increment before deciding whether evidence is requested
requested       increment before ring-buffer reservation
emitted         increment after successful reservation/submit
lost            increment when a requested record cannot be reserved/submitted
suppressed      increment when policy intentionally requests no rich record
classifier_miss increment when a required classifier returns unknown
```

Intentional suppression is not transport loss. A periodic authenticated
counter snapshot makes the accounting invariant testable:

```text
attempted == suppressed + requested
requested == emitted + lost
```

A violation itself creates a coverage gap. Enforcement can continue while
evidence is gapped, but packages that require a missing event cannot conclude
it did not occur.

```text
CoverageIntervalV1 {
  interval_id
  source_id
  source_epoch
  exact_scope
  required_payload_kinds[]
  start_source_sequence
  end_source_sequence?
  start_time
  end_time?
  capture_mode: DECISION_ONLY | REQUIRED_EVENTS | FORENSIC
  state: OPEN | HEALTHY | GAPPED | CLOSED | UNKNOWN
  gap_reason?
  first_lost_sequence?
  last_lost_sequence?
  last_counter_snapshot
}
```

On the first loss, detach, counter inconsistency, clock reset, or source-epoch
change, the owner closes the preceding healthy interval and opens a `GAPPED`
interval. Recovery opens a **new** healthy interval after link/map readback and
the configured isolated qualification probe; it never rewrites the gap as
healthy.

The local WAL acknowledges a contiguous range per source epoch. The uploader
may truncate only records and coverage snapshots below a durably acknowledged
contiguous boundary. Restart restores the last sequence and interval state; if
that cannot be proved, it starts a new source epoch with an explicit gap.

**Loss test.** Force record sequence 901 to fail reservation while 900 and 902
are requested. The loss counter closes coverage around 901, the file denial
still returns its errno, and a package needing that interval returns
`coverage_insufficient`. Restart preserves the gap. A later healthy snapshot
opens a new interval but cannot justify “no credential access” across 901.

#### Proof quality is a vector, not a scalar

The earlier labels `exact`, `conservative`, `contextual`, and any
`source_quality_at_least` matcher are useful shorthand but cannot form one
global ordering. A provider audit can be authoritative about an API result and
still have no exact local-task binding. The normative value is:

```text
ProofQualityV1 {
  source_authority:
    KERNEL_DECISION | SIGNED_COORDINATOR | AUTHORITATIVE_PROVIDER |
    AUTHENTICATED_MEASUREMENT | UNAUTHENTICATED
  local_subject_binding:
    EXACT_TASK | EXACT_PROCESS | EXACT_EXECUTION_SET | CONTEXTUAL | NONE
  remote_subject_binding:
    EXACT_REQUEST | EXACT_SESSION | EXACT_OBJECT | PRINCIPAL_ONLY |
    CONTEXTUAL | NONE
  operation_result_authority:
    PRE_EFFECT_DECISION | AUTHORITATIVE_SUCCEEDED |
    AUTHORITATIVE_DENIED | OBSERVED_ATTEMPT | CONTEXTUAL | UNKNOWN
  temporal_coverage: COMPLETE | GAPPED | UNKNOWN
  integrity: SIGNED | AUTHENTICATED_CHANNEL | LOCAL_ATTESTED | UNVERIFIED
}
```

Matchers name required values on each axis. They never compare unrelated axes
with `>=`. Intent classification remains a separate enum:
`EXACT_TARGET|SAME_BUDGET_AMBIGUOUS|AMBIGUOUS|UNKNOWN`.

**Practical example.** CloudTrail can authoritatively report a successful AWS
operation for an assumed-role session, while two local processes share that
session. The observation is `AUTHORITATIVE_PROVIDER`,
`EXACT_SESSION`, and `AUTHORITATIVE_SUCCEEDED`, but local binding is
`CONTEXTUAL`. It may drive session-scoped response but cannot automatically
restrict one supposedly exact Linux process.

##### Abandoned design: scalar `sourceQualityAtLeast`

Any configuration fragment using `sourceQualityAtLeast` is retained as an
illustration of intent but is not a valid Version 1 match. The compiler emits
`SCALAR_PROOF_QUALITY_UNSUPPORTED` and names the explicit axes the rule must
provide.

#### Package windows, watermarks, and finding lifecycle

Each package version declares, per source, `maximum_lateness`, `retention_ttl`,
clock-uncertainty limit, required coverage mode, and late-event action.
Durations are nanosecond-backed values with explicit units. A source watermark
is the greatest projected event time whose uncertainty interval is older than
`latest_seen_lower_bound - maximum_lateness`. Cross-node time alone never
creates an exact edge.

```text
FindingV1 {
  finding_id = Digest(package_id, package_version, subject_key, window)
  revision: u64
  state: PROVISIONAL | CONFIRMED | SUPERSEDED | RETRACTED |
         COVERAGE_INSUFFICIENT
  window
  graph_version
  evidence_ids[]
  required_coverage_interval_ids[]
  supersedes_revision?
  reason_code
}
```

Late evidence appends a new revision; it does not mutate the old evidence.
Duplicates are idempotent by observation ID. “Outside reviewed baseline” means
outside a named signed baseline/profile digest, never merely rare in learned
history. Replaying a fixed observation set in any delivery order must produce
byte-identical terminal finding revisions.

**Ordering test.** Deliver facts C, A, duplicate C, then B after the initial
watermark. The package first emits a provisional or insufficient result as
specified, then a deterministic superseding revision. Removing required
provider coverage produces `COVERAGE_INSUFFICIENT`, not a confirmed absence.

#### `HF-PROC-001`: unexpected native effect

This package explains a local deny or audited deviation:

```text
input: exact TaskLabel + EntryInstance + role + EffectObservation

if task/entry identity incomplete:
    emit LineageCoverageGap, not a proven malicious edge
else if effect decision is deny:
    emit UnexpectedEffect with prevention point and physical errno
else if effect is allowed but outside reviewed role baseline:
    emit AuditedRoleDeviation

attach:
  native ancestors, entry class, binary object identity, cgroup/Pod/container,
  policy generation, dynamic state, hook, decision, loss counters
```

The finding does not rely on a process name such as `curl`. The same binary can
be allowed from a declared tool role and denied from an exec-probe or worker
role.

#### `HF-DW-001`: credential-to-authority pivot

This package correlates an observable credential access or credential-bearing
channel with later authority use:

```text
state key = exact credential object/lease when available,
            otherwise exact process/socket/workload scope with weaker proof

facts:
  A = protected credential object read or credential lease obtained
  B = socket/channel to authority or credential used in provider audit
  C = server-side operation outside AuthorityBehaviorRule

if A and B share exact task/process/socket/lease proof and C is authoritative:
    emit direct credential_pivot path
else if only workload + principal + bounded time match:
    emit contextual hypothesis; do not authorize credential-specific response
```

Expected controller token reads and expected API verbs are negative controls.
Two Pods sharing a ServiceAccount name never receive an exact credential edge
from that name alone.

#### `HF-XNODE-001`: distributed Kubernetes expansion

```text
LinuxExecution A on node 1
  -> process_issued_api_request (exact socket/request or credential proof)
  -> Kubernetes AuditEvent auditID
  -> api_request_created_or_mutated_resource object UID/resourceVersion
  -> owner-reference/controller reconcile chain
  -> Pod UID
  -> scheduler binding/spec.nodeName
  -> container full ID/cgroup on node 2
  -> ContainerStartEntry
  -> LinuxExecution B on node 2
```

Each arrow is a typed immutable edge with evidence IDs, proof strength,
coverage references, and missing fields. Time adjacency, an IP address, a
label selector, a ServiceAccount name, or the same process name cannot create
the direct path alone. Fan-out creates one branch per exact object/Pod/root.

##### Abandoned design: unconditional process-to-Kubernetes-audit edge

The first arrow in the compact chain can be misread as saying stock Kubernetes
audit `auditID` identifies the Linux process. It does not. The API server owns
the audit ID. Standard audit records can authoritatively identify the API
principal, verb, URI/object, stages, and result at the configured audit level,
but source IP, user agent, shared ServiceAccount credential, and time do not
uniquely identify one task. That unconditional interpretation is abandoned.

The exactness of each segment is:

| Segment | Direct edge requirement | Weaker evidence result |
| --- | --- | --- |
| Task -> socket | Kernel task/socket storage and healthy hook interval | workload/cgroup-contextual flow |
| Audit ID -> API operation/result/object | Authoritative audit at a level containing request/response fields needed by the package | operation/result unknown or coverage insufficient |
| Task/socket -> audit ID | A request nonce carried through a synchronous semantic gate into authenticated server evidence; an exact client/server request ID observed at both ends; or a credential lease unique to that task/request scope | principal/IP/time/user-agent join is contextual only |
| API object -> controller/replacement Pod | Exact object UID/resourceVersion and owner/controller evidence | label/name/time hypothesis |
| Pod UID -> remote runtime root | scheduler/binding state plus exact node admission using the same Pod UID/full container ID | remote branch remains open/unknown |

**Practical concurrency test.** Two processes in one Pod use the same mounted
ServiceAccount token concurrently. T1 creates Pod A and T2 creates Pod B.
Kernel evidence has two task/socket branches and audit has two exact API
operations, but no carried nonce or unique lease. Mithril creates contextual
candidate edges and refuses to arbitrarily attach either audit ID to T1. It
may contain the whole credential/workload scope if policy authorizes that
blast radius; it may not claim exact-task response eligibility.

#### Canonical multi-node graph contract

```text
GraphSubjectV1 {
  tenant_id
  subject_id
  kind: TASK | PROCESS | EXECUTION_SET | SOCKET | REQUEST | CREDENTIAL_LEASE |
        KUBERNETES_OBJECT | PROVIDER_OBJECT | ARTIFACT | CI_RUN | CI_JOB | ...
  authority_id
  immutable_identity
  live_or_valid_interval?
}

GraphEdgeV1 {
  edge_id
  edge_type
  from_subject_id
  to_subject_id
  package_id
  package_version
  evidence_ids_sorted[]
  proof_quality
  required_coverage_interval_ids[]
  state: DIRECT | CONTEXTUAL | CONTRADICTED | SUPERSEDED
  supersedes_edge_id?
  created_at_utc
}

GraphVersionV1 {
  tenant_id
  graph_version: u64
  parent_graph_version?
  added_subject_ids[]
  added_edge_ids[]
  closed_branch_ids[]
  creation_observation_watermarks[]
}
```

`subject_id` is a deterministic digest of tenant, kind, authority, and the
kind's canonical immutable identity. `edge_id` is a deterministic digest of
tenant, edge type, exact endpoints, package/version, sorted evidence IDs, and
proof state. Redelivery creates no duplicate. A stronger proof appends a new
direct edge that supersedes—not mutates—the contextual one. Contradictory
authoritative evidence appends a `CONTRADICTED` edge/revision and re-evaluates
dependent findings.

The graph is not assumed acyclic: retries, controller ownership, bidirectional
sessions, and artifact reuse can form cycles. Traversal is bounded by edge
types, tenant partition, package depth, time/validity intervals, and visited
subject IDs. Native Linux parent edges are valid only within one node boot;
cross-node relationships always use another named causal edge.

Each incident branch records:

```text
BranchState {
  branch_id
  seed_subject_id
  terminal_subject_ids[]
  required_edge_types[]
  required_coverage[]
  state: OPEN | TERMINAL_VERIFIED | CONTEXTUAL_ONLY |
         OUTSIDE_AUTHORITY | COVERAGE_UNKNOWN
}
```

**Multi-node retry test.** One controller retry creates three Pod UIDs across
two nodes. Duplicate audit delivery adds no edge. Every Pod has an independent
runtime-root branch; the offline node stays `COVERAGE_UNKNOWN`. No task on node
A becomes a native parent of a task on node B, even when names/images match.

#### Provider and connector expansion

AWS, mesh, connector, GitHub, artifact, and message systems use the same rule:

- exact request IDs, credential lease/access-key IDs, installation IDs,
  connector invocation IDs, message IDs/offsets, and immutable artifact
  digests can create direct edges;
- principal name, repository name, IP, mutable tag, and time can create only
  contextual evidence;
- a network flow proves communication, not a remote command or API verb; and
- late provider evidence creates a new finding/lineage version without
  rewriting the earlier view.

##### Abandoned design: an identifier alone creates an arbitrary direct edge

The first bullet is too broad if “direct” does not name both endpoint types and
the identifier's uniqueness scope. An AWS access-key ID can directly join a
credential/session subject to an AWS event that authoritatively carries that
same key; it cannot directly join an arbitrary Linux process to the event when
two processes possessed the key. The identifier-only interpretation is
abandoned.

Every provider edge type is registered as:

```text
ProviderEdgeContractV1 {
  edge_type
  from_subject_kind
  to_subject_kind
  authoritative_source_kind
  required_equal_fields[]
  identifier_uniqueness_scope
  required_request_fields[]
  required_result_fields[]
  required_coverage[]
  minimum_proof_vector: ProofQualityV1
  missing_field_result: CONTEXTUAL_EDGE | NO_EDGE | COVERAGE_UNKNOWN
  legitimate_shared_identity_negative_test_id
}
```

Version 1 registers these concrete shapes:

| Edge | Exact endpoints and equal fields | Uniqueness/result/coverage rule | What it never proves alone |
| --- | --- | --- | --- |
| `AWS_LEASE_PERFORMED_OPERATION` | `CredentialLeaseV1 -> AwsProviderOperation`; provider account/partition, access-key or assumed-role session ID, and provider event/request ID | CloudTrail/service source owns the identifiers and exact result; coverage spans the event watermark | Which Linux task used a shared key unless that task claimed the exact broker nonce/lease |
| `K8S_REQUEST_AFFECTED_OBJECT` | `KubernetesApiRequest -> KubernetesObjectVersion`; cluster UID, audit ID/request UID, verb/resource/namespace/name or UID, response object UID/resourceVersion | Kubernetes audit/request source proves authenticated principal and response status under complete audit coverage | A local process caused the request without carried token/lease/request proof |
| `LOCAL_LEASE_CAUSED_K8S_REQUEST` | `CredentialLeaseV1 -> KubernetesApiRequest`; unique token `jti`/same-provider fingerprint or broker-forwarded request nonce plus cluster UID | Consumer/authenticator and audit fields must expose the same unique value; shared ServiceAccount alone is insufficient | Linux parenthood across nodes or the later Pod root |
| `GITHUB_TOKEN_PERFORMED_OPERATION` | `CredentialLeaseV1 -> GithubOperation`; installation/App/repository scope plus documented token-attribution field and operation/delivery ID | GitHub/connector source must document the field and exact result; no standard mint event is invented | Possession of a token revocation secret, or which local task requested a shared token |
| `CONNECTOR_FORWARDED_REQUEST` | `ConnectorInvocation -> ProviderRequest`; connector deployment/epoch, source invocation ID, forwarded destination request ID | Connector owns both IDs and downstream provider confirms the destination ID/result | A time-adjacent shared connector principal is not the source invocation |
| `ARTIFACT_CONSUMED` | `ArtifactInstanceV1 -> ArtifactConsumerSlotV1`; provider artifact version, immutable digest, exact consumer slot | Provider/object coverage proves publication and exact digest verification/claim | Artifact name, cache key, tag, or URL alone does not join bytes |
| `MESSAGE_CONSUMED` | `MessagePublication -> MessageConsumption`; provider/cluster, topic or queue, partition/shard, immutable message ID/offset and content digest when supplied | Broker owns the coordinates and confirms publish/consume results under retention coverage | A shared producer credential identifies one local producer task |

Every edge contract has a fixture with two concurrent clients sharing the same
principal/credential while only one carries the unique request/lease/message
join. Only that client's edge becomes direct; the other remains contextual or
unjoined exactly as the contract says. Provider adapters cannot emit a generic
`DIRECT` edge outside this registry.

The fixture IDs are `EDGE-AWS-SHARED-001`, `EDGE-K8S-SHARED-002`,
`EDGE-GITHUB-SHARED-003`, `EDGE-CONNECTOR-FORWARD-004`,
`EDGE-ARTIFACT-CONSUMER-005`, and `EDGE-MESSAGE-CONSUMER-006`. The Kubernetes
fixture covers both Kubernetes edge rows in separate subcases.

### Response Algorithms

#### Local lineage restriction and exact target re-resolution

An authorized local response inserts this key:

```text
ResponseRootKey = (node_boot_id, label_epoch, process_lineage_id)

ResponseRestriction {
  request_id
  target_process_instance_id
  permitted_emergency_effects
  deny_effect_families
  socket_fence
  expires_at
  policy_generation
}
```

Every protected hook checks the current process-lineage ID and bounded ancestor
vector. Existing and future descendants therefore match without waiting for a
userspace tree walk. A task iterator/pidfd reconciliation verifies that the
enumerated subtree agrees and reports missing/overflow branches.

##### Abandoned design: bounded ancestors as the only future-descendant control

The sentence above is too strong if the ancestor vector is the only lookup. A
future child deeper than `MAX_DEPTH` can lose the response root from its vector.
That design is abandoned. Ancestors remain graph/reconciliation evidence; the
enforcement state inherited on every fork is O(1):

```text
EffectiveResponseSet {
  set_id
  response_restriction_ids[MAX_RESPONSE_REFS]
  combined_deny_effect_families
  combined_socket_fence
  earliest_expiry_boottime_ns
}
```

`ProcessSecurityState.effective_response_set_id` points to this immutable
combined set. A child atomically inherits it at `task_alloc` before it can run.
If a response targets an existing root, the response-root lookup immediately
covers current descendants whose verified ancestor vectors include the root,
then a task iterator upgrades every descendant to the effective set. Exact
lineage response is unavailable if an existing branch exceeds the qualified
ancestor bound; the coordinator must propose a separately authorized cgroup
freeze/fence or report `unknown`.

If `MAX_RESPONSE_REFS` is exhausted, fork and newly protected effects fail
closed with `RESPONSE_SET_OVERFLOW` until an approved broader fence or set
compaction succeeds. The implementation must never drop the oldest response.

**Depth test.** Construct a branch at `MAX_DEPTH - 1`, restrict its root, and
fork two further generations while reconciliation is delayed. The deepest
child inherits the effective response set from its parent and its first exec
and connect are denied. A fixture that starts with a pre-existing unprovable
overflow branch must refuse an exact-subtree containment claim.

#### Response application and physical verification

The algorithm is:

1. Re-resolve node boot, label epoch, task/process cookie, native coordinates,
   cgroup, Pod UID, and container live interval.
2. Reject stale, ambiguous, bootstrapped-incomplete, or depth-overflow targets
   for exact-subtree response.
3. Insert the response root with TTL and read it back.
4. Run a fresh denied file, exec, socket, and device probe from the target
   scope where safe.
5. Fence existing sockets/packets if requested; an LSM connect deny alone does
   not stop an established connection.
6. Optionally freeze or signal only through separately authorized operations.
7. Watch for future descendants until the response closes.
8. Record `verified`, `partial`, `failed`, or `unknown` from physical
   postconditions.

##### Abandoned design: active probes inside the compromised production target

Step 4 cannot safely mean injecting file, exec, socket, or device operations
into an arbitrary production process. Such probes modify the workload, may
cause damage, and are often technically impossible. That production
interpretation is abandoned.

Controlled hostile probes run only in an isolated qualification fixture with
the same kernel, hook set, profile shape, and BPF object digest. Production
installation verification uses non-invasive actuator evidence:

| Action | Required production postcondition | Additional evidence when a real attempt occurs |
| --- | --- | --- |
| lineage restriction | Response key and effective-set map readback; exact target task state references set; every in-scope existing descendant reconciled or a named broader fence is verified; hooks/maps healthy | denial event plus syscall errno for the attempted family |
| packet/socket fence | Exact socket/cgroup keys present in TC/cgroup maps, programs attached, generation read back, pre-existing sockets enumerated according to capability | packet drop/socket-destroy counters tied to the fence |
| cgroup freeze | Kernel cgroup state reads `frozen=1` for exact live cgroup and task reconciliation shows membership | no active execution claim is inferred merely from silence |
| process signal/kill | pidfd target revalidated; wait/pidfd exit state confirms exact process exited | replacement/container branches remain separately open |
| provider action | Provider-specific authoritative readback or a deliberately executed benign canary request using the affected credential/session | audit silence is only quiet-window evidence |

The old YAML phrase `verify: no-new-protected-effect-from-lineage` is therefore
not a sufficient physical postcondition. It must compile to the exact
installation/readback checks above plus a named healthy watch requirement.
“No event arrived” never proves installation.

#### Durable response state machine and result vocabulary

```text
ResponsePlanV1 {
  plan_id
  revision
  frozen_graph_version
  frozen_branch_ids[]
  requested_actions[]
  authorization_id
  authorization_expires_utc
  node_deadline_boottime_ns?
  idempotency_key_per_action[]
  state
  action_results[]
  required_watch_interval
  required_coverage[]
}

PROPOSED -> AUTHORIZED -> REVALIDATING -> APPLYING -> VERIFYING -> WATCHING
  -> VERIFIED | PARTIAL | FAILED | UNKNOWN | EXPIRED | CANCELLED
```

Every transition is a durable compare-and-swap that records actor, previous
revision, UTC, node boottime where applicable, and reason. Retries reuse the
same idempotency key. Cancellation cannot erase an already applied action; it
records whether rollback is supported and separately authorized.

Result terms are exact:

- `VERIFIED`: every requested action in this exact plan revision passed its
  physical postcondition and all required coverage stayed healthy throughout
  the watch interval.
- `PARTIAL`: at least one action verified and at least one action failed,
  expired, remained outside authority, or could not verify.
- `FAILED`: authoritative postconditions prove none of the requested actions
  achieved their intended state.
- `UNKNOWN`: evidence/authority/coverage cannot establish whether any required
  action achieved its state.
- `EXPIRED`: authorization or monotonic application deadline elapsed before
  the next irreversible transition. Applied actions remain recorded.
- `CANCELLED`: an authorized actor cancelled future transitions; it says
  nothing about already applied effects.

A plan freezes a graph version and branch set. If a replacement Pod or late
remote branch becomes direct while the plan watches, Mithril creates a new
plan revision including it. The old revision may remain verified for its old
scope, but the incident cannot report globally contained until the new revision
finishes.

`ResponseRestriction.policy_generation` in the earlier compact object records
the generation that authorized creation; it is not a lookup lifetime. Active
response restrictions are generation-independent and do not disappear when a
new workload policy activates.

**Late-branch test.** A controller creates a replacement Pod one second before
the 5-minute watch ends. The original plan revision records its already
verified actions, the incident opens a new revision/branch, and the global
result returns to `WATCHING` or `PARTIAL`; it never remains `VERIFIED` by
ignoring the late branch.

#### Cgroup and workload response

If exact lineage is incomplete, the product may propose a broader cgroup
egress fence or freeze. Before authorization it must show every known task and
container affected. In a shared interpreter, it explicitly states that all
in-process jobs may be interrupted and that no kernel evidence identifies one
logical job.

Kubelet can restart a container and a controller can replace a Pod. Therefore
process kill alone is not distributed containment. The coordinator separately
tracks:

- current local process/socket branches;
- container restart under the same Pod;
- replacement Pod UIDs created by the owning controller;
- remote node branches;
- credential/provider sessions; and
- artifact, mesh, connector, or source-control branches.

#### Shared authority-domain response blast radius

A response bit stored in a common `AuthorityDomainStateV1` is deliberately
monotonic and affects every participant. Therefore a request to “contain the
converter process” cannot be described as process-only when the converter,
uploader sidecar, lifecycle root, or later administrative root share that
domain.

Before authorization, the response planner:

1. resolves the exact authority-domain root and transition version from the
   target process;
2. enumerates every live process/entry/workload participant plus each shared
   mount, mapping, IPC object, passed descriptor and socket edge from the
   frozen graph and a fresh kernel/runtime reconciliation;
3. shows which participants lose which file/network/device/exec effects and
   which shared/preexisting flows require an additional packet/socket fence;
4. obtains authorization for that expanded target set and blast radius;
5. atomically installs one monotonic response-set reference on the common
   domain, reads the root and every participant state back, and applies any
   separately authorized existing-flow fence; and
6. keeps the plan open while participants exit, restart, or a newly admitted
   root joins. A late root inherits the response before release and creates a
   new plan revision if it was absent from the authorized set.

The result is named `SHARED_AUTHORITY_DOMAIN_RESTRICTION`, never
`PROCESS_ONLY_RESTRICTION`. If the operator does not authorize the expanded
blast radius, Mithril may apply a narrower independently proven socket/object
fence or report partial; it cannot silently write the common-domain bit.

`HF-RESP-SHARED-DOMAIN-003` contains a converter and uploader with one common
domain, an independent nonparticipant sidecar, a preexisting upload socket,
and a late administrative entry. It tests every participant exit order,
container restart, late-root admission, map/readback failure and daemon
restart. The converter/uploader/late root all retain the common restriction;
the independent sidecar does not; the preexisting socket is stopped only when
its separately authorized fence verifies.

#### Distributed response

```text
plan(distributed_lineage_version):
    fence proven seed process/socket immediately when locally authorized
    enumerate exact open branches and their authority owners
    produce one typed action per node/controller/provider target
    require target-specific approval and revalidation
    execute idempotently
    keep a watch open for replacement or late branches
    verify each physical postcondition

result = verified only if every required branch verifies under healthy
         required coverage through the watch interval
```

An offline node, an outside-authority environment, a contextual-only branch,
or unavailable provider verification forces `partial` or `unknown`.

<a id="part-vi-incident"></a>

## Part VI — Incident Controls, Configuration, And CI

### Per-Incident Protection Design

This section answers “what should Mithril do?” for every published stage. The
event IDs refer to the normalized
[live action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md).

#### `HF-001` through `HF-007`: external evaluation foothold and staging

**Situation.** The recovered root shell, environment discovery, public exfil,
remote staging, packing, and reconnaissance occurred in an external evaluation
environment outside the protected Hugging Face estate.

**Mithril action.** A Hugging Face deployment records these as outside-authority
subjects if provider or shared-artifact evidence later refers to them. It does
not claim local prevention. If Mithril is independently installed in an
evaluation estate, the ordinary policies apply: unexpected exec edges,
protected environment/credential access, public C2 destinations, anonymous
executable mappings, and remote loaders are denied by that estate's profile.

**Correlation.** Later exact artifact digests, credential IDs, connector
request IDs, or mesh enrollment IDs may connect the outside subject to a
protected branch. Similar commands or close timestamps do not.

**Acceptance.** The report must say `outside_authority` for the external
actions and must not turn them into fictitious ancestors of a Hugging Face
process.

#### `HF-008`: hostile HDF5 external-file reference reaches conversion

**Situation.** An admitted dataset causes the unchanged conversion worker to
ask HDF5 to open a filesystem object selected by hostile metadata.

**Local policy.** The `conversion-worker-root` role may read only
`dataset-input`, reviewed runtime/library objects, and declared scratch/output
objects. An HDF5 external-file target resolved to
`worker-environment-procfile`, a projected credential, another Pod/process,
host filesystem, device, or an object outside the admitted dataset view is
denied at `file_open` before bytes are returned.

**Algorithm.** The file classifier uses the live mount namespace, mount ID,
inode/superblock identity, resolved proc target where applicable, and admitted
dataset mount provenance. It does not permit `../`, symlink, bind-mount, or
`/proc/<pid>/fd/<n>` aliases merely because the original string resembles the
dataset directory. The decision is attached to the exact interpreter task and
entry instance even though no child process exists.

**Central evidence.** The dataset/revision is connected to the worker only if
the platform supplies an exact immutable revision or dispatch identifier. If
the application supplies no job/revision event, Mithril reports the exact
process and file object but does not guess which concurrent logical job caused
it.

**Response.** Restrict the exact process lineage or, if the interpreter is
shared and continued execution is unsafe, propose a cgroup fence/freeze with
the explicit multi-job blast radius. Quarantine of one dataset revision is
eligible only with exact platform evidence.

**Required test.** A non-weaponized HDF5 fixture attempts an external read of
an allowed dataset sidecar file and of each protected object alias. The allowed
case completes; every protected case returns `EACCES`; no protected bytes enter
the converted output; `HF-LOCAL-001` contains the exact task, object key,
policy generation, and denial hook.

**Limit.** Mithril does not claim to reject the HDF5 structure at upload. That
would be an optional artifact scanner/admission control. The baseline prevents
the worker-side prohibited file effect.

#### `HF-009`: worker environment and secrets are disclosed

**Situation.** Hostile processing obtains worker context or secrets and
publishes them through a dataset/result or network channel.

**Local policy, observable file path.** Opening `/proc/self/environ`, another
task's environ, a projected secret, token, cloud credential file, or host
configuration is evaluated by object class. If the conversion role has no
declared need, the read is denied before completion. An allowed but sensitive
access attempt can set `SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED`, causing stricter later artifact and
egress decisions.

**Local policy, in-memory path.** If Python reads its own already resident
environment, the read has no distinguishable kernel file effect. Mithril
therefore evaluates the next action:

- a new/public socket or unapproved destination is denied;
- an output file/repository object outside the role is denied;
- an unexpected helper exec is denied; and
- an operation inside the same required encrypted publication channel is
  detected from service/provider audit when available.

**Correlation.** `HF-DW-001` joins an observable protected-object read to the
later socket/artifact/provider operation by exact task/process/socket or
credential lease. If only the same Pod and time are known, the edge remains
contextual.

**Response.** Restrict the exact lineage and fence its sockets. If authoritative
audit proves a result/dataset revision was written, mark that immutable
revision for review or quarantine through a separately authorized repository
action. Rotate/revoke a credential only when its exact identity and blast
radius are known.

**Required test.** The fixture has four branches: `/proc/self/environ`,
projected-token file, `os.environ` with public egress, and `os.environ` with an
already allowed TLS destination. The first two prove file denial, the third
proves network denial, and the fourth proves an honest
`semantic_effect_completed`/provider-audit result rather than a kernel
prevention claim.

##### Abandoned design: publication success proves secret exfiltration

The final phrase above is too broad. If normal conversion and hostile output
use the same allowed TLS endpoint and result schema, provider audit proves a
publication, not what the encrypted payload meant. Version 1 uses:

| Result | Required proof |
| --- | --- |
| `PUBLICATION_OBSERVED` | Authoritative result/artifact operation and outcome |
| `SUSPECTED_SENSITIVE_PUBLICATION` | Publication plus exact observable sensitive-access state on the same writer/lineage in causal order; byte equality is unproved |
| `CONFIRMED_EXFIL` | A trusted content/provenance oracle links protected bytes to published bytes, for example a secret-owner keyed fingerprint matched in an authorized scanning boundary; raw secret is not stored in evidence |
| `PAYLOAD_UNOBSERVABLE` | Channel/result is known but no content oracle or observable acquisition distinguishes payload |

An in-memory `os.environ` access followed by normal result publication is
`PAYLOAD_UNOBSERVABLE` unless another source proves content. The conservative
sensitive-state bit can restrict the channel but cannot turn its payload into
confirmed exfiltration.

**Negative-control test.** Publish a normal result and a same-size secret value
through the same API/TLS/object schema. Without a content oracle, the two
provider events have the same semantic result and neither is
`CONFIRMED_EXFIL`. Add an exact observable protected-file read to only one
branch: it becomes `SUSPECTED_SENSITIVE_PUBLICATION`. Enable the authorized
fingerprint oracle: only the matching branch becomes confirmed.

#### `HF-010`: template-based Python execution in the worker

**Situation.** Hostile template evaluation runs inside the already approved
Python interpreter.

**Local policy.** Mithril does not attempt to classify Python bytecode or
template intent. It denies the first prohibited physical effect:

- `python -> sh/curl/tailscale` at `bprm_check_security`;
- a module/plugin file outside the allowed code objects at file open/map;
- memfd or anonymous executable memory for a non-JIT role at exec/mmap;
- projected token, proc, host, or device access at file/device hooks;
- API/IMDS/C2 at socket hooks; or
- ptrace, namespace, mount, BPF, perf, capability, or module effects at the
  corresponding security hook.

**Algorithm.** This is an effect-state machine on the existing task label.
There is no prerequisite child process and no command-line signature.

**Response.** The exact interpreter process is the smallest native target. If
it hosts several logical jobs, Mithril states that containing it affects all
of them. It does not invent a job-specific response.

**Required test.** The malicious behavior driver performs prohibited file and
socket actions directly from Python without `subprocess`, then repeats them
through a helper child. Both in-process and exec-edge paths must be denied at
their respective pre-effect hooks. A pure arithmetic/template operation with
no effect must remain intentionally unclassified.

#### `HF-011`: projected Kubernetes ServiceAccount token read

**Situation.** The compromised worker opens its projected ServiceAccount
token, or obtains equivalent credentials already loaded by legitimate code.

**Local policy.** The binder classifies the projected volume and rotating token
objects for the exact Pod/container. `conversion-worker-root` denies reads if
the worker does not need them. A controller role that legitimately reads the
same mounted token receives a reviewed token-read rule and a narrower
authority behavior rule; the entire Pod is not globally allowed.

**Algorithm.** A successful audited token read records the exact task,
process, file object, projected-volume provenance, ServiceAccount/Pod binding,
and profile generation, then optionally sets the sensitive-read state. Token
contents are never stored in evidence.

##### Correction: token access, descriptor open, byte read, and provider use

The retained phrase “successful audited token read” collapses four different
boundaries and is abandoned. Version 1 records only the strongest result whose
named oracle passed:

| Result | Exact required source/oracle | What it does not prove |
| --- | --- | --- |
| `FILE_ACCESS_ATTEMPT_ALLOWED` | Qualified `file_open`/`file_permission` pre-effect observation for the exact task, open file/object and operation returned allow | That VFS installed an fd or returned any byte |
| `FILE_DESCRIPTOR_OPENED` | Exact open-attempt ID joined to the same task's syscall/io_uring completion with a nonnegative new fd, then fd-to-file identity readback | That a later read returned data |
| `SENSITIVE_BYTES_READ` | Target-qualified post-read completion covers the actual path, joins exact task/open-file identity and attempt, and reports a positive byte count; mmap requires its separately qualified fault/content path | That the bytes were used in a provider request or came from an already-memory-resident copy |
| `PROVIDER_CREDENTIAL_USED` | Kubernetes/authenticator/provider authority records the exact credential lease/fingerprint/request and operation result under complete coverage | Which earlier local read supplied it unless an exact lease/request join exists |

The conservative pre-effect bit remains
`SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED`; it may restrict later effects but is
not renamed `SENSITIVE_BYTES_READ`. `HF-011-READ-RESULT-001` covers zero-byte
read, EOF, `EIO`, partial positive read, mmap, inherited/pre-opened fd,
io_uring, token already in environment/memory, and a later authoritative API
use. Every branch emits its exact result; only the positive qualified
completion emits `SENSITIVE_BYTES_READ`.

**Already-held credential.** If the token was read before attachment or is
already in memory, file denial is no longer prevention. Socket and Kubernetes
audit decisions remain active. Coverage reports the pre-attachment gap.

**Response.** Restrict the process/socket first. Deleting the Pod or revoking
broad ServiceAccount authority is not automatic. A projected token naturally
rotating does not prove every external bearer copy is invalid; provider-side
recovery follows Kubernetes' actual token type and issuer semantics.

**Required test.** Token rotation replaces the inode while the same projected
object class remains protected. A legitimate controller in the same Pod or on
the same node continues its declared read/API behavior; the conversion role
gets `EACCES`. Secret/token bytes never appear in WAL or findings.

#### `HF-012`: Kubernetes API and cloud metadata probing

**Situation.** The foothold probes Kubernetes control-plane addresses and
cloud IMDS to enumerate or obtain authority.

**Local policy.** The node maintains destination classes for every discovered
API and metadata address: service IP, endpoint IPs, public/private API names,
IPv4/IPv6 link-local metadata, secondary interfaces, and provider-specific
paths. A conversion role with no need is denied on in-process connect/send;
no helper exec is required.

For a role that legitimately needs an API destination, network access remains
allowed. Kubernetes/provider audit then evaluates the exact principal, verb,
resource, namespace/account, result, and request ID against its
`AuthorityBehaviorRule`.

**Algorithm.** DNS observation updates provenance but the actual address and
network namespace drive the kernel decision. Existing socket storage retains
creator/current role. An established allowed connection is not reclassified
by TLS bytes; response uses the packet fence.

The retained “creator/current role” phrase is abandoned. Socket storage keeps
immutable creation/admission provenance and lifetime/generation restrictions;
every operation reads the actual current actor's task/process/authority-domain
state. Passed or duplicated sockets never acquire a mutable last-user owner.
An established TLS flow still hides the verb, and a packet fence remains a
separate physical response.

**Response.** Denied probes require no broad network change. A completed
forbidden API operation triggers exact process/socket restriction and a typed
Kubernetes/provider response against the resulting object or credential, with
resource UID/version preconditions.

**Required test.** `HF-NET-001` tries hard-coded IP, DNS, IPv6, alternate API
endpoint, and IMDS paths directly from Python. Negative controls exercise a
legitimate controller's expected API operation. A forbidden verb over its
allowed connection is detected from audit and is not mislabeled as a connect
denial.

#### `HF-013`: dataset repository used as a dead-drop

**Situation.** A leaked write-capable token is used to publish an artifact or
dataset revision that becomes staging, C2, or a handoff point.

**Local prevention.** If the acting role does not need the repository
destination, connect/send is denied. If it has read-only network use but a
different endpoint or credential identity exists for writes, the profile can
deny the write channel. If read and write share the same process, endpoint,
credential, and TLS connection, the kernel cannot distinguish them.

##### Abandoned design: a bearer-token identity inside TLS selects a kernel rule

The retained “different credential identity” sentence is valid only when that
identity changes a kernel-visible or synchronous authority boundary: a
separately labeled helper/process, a distinct endpoint, a broker-delivered
lease object available only to the approved role, a read-only provider token,
or a semantic repository gate. A bearer-token string chosen inside one
encrypted connection is not visible to BPF LSM/socket policy. Without one of
those mechanisms, Mithril can deny the whole repository channel or detect the
provider-confirmed write; it cannot locally deny write while allowing clone.

**Authority behavior.** Repository audit must identify repository, actor/token
or principal, operation, immutable revision/commit/artifact ID, request ID,
and result. An unexpected create/update is a server-side deviation even when
the local channel was allowed.

**Correlation.** The exact written artifact digest/revision connects the
writer to later consumers. Repository name, filename, mutable branch/tag, or
time alone is contextual.

**Response.** Fence the source process/channel; revoke the exact token or
session when supported; quarantine or remove the exact immutable malicious
revision; enumerate downstream loads. Deleting an entire repository is not
the default.

**Required test.** A fixture permits a legitimate read and attempts a write on
the same TLS destination. The node reports network ambiguity; provider audit
produces the write finding. A separately identifiable write endpoint/token is
denied pre-effect. No test claims packet inspection recognized a repository
verb.

#### `HF-014`: compromised node reaches mesh control

**Situation.** Code on the protected estate invokes or contacts mesh tooling
and its control service.

**Earliest prevention chain.** Any one of these independent policy gates can
stop the branch when absent from the conversion role:

1. deny `python -> tailscale` or another unapproved mesh executable object;
2. deny `/dev/net/tun` and its ioctls;
3. deny network/namespace/capability effects needed to establish the mesh;
4. deny the mesh-control destination; or
5. detect a forbidden mesh enrollment/control operation from provider audit.

The finding records which gate actually prevented the physical effect. It
does not claim all later gates fired after an earlier denial.

##### Abandoned design: provider audit is a prevention gate

Item 5 is not part of the “earliest prevention chain” when it is ordinary
provider audit. Items 1–4 can physically deny a local prerequisite. A healthy
synchronous mesh/provider admission API can reject before enrollment. Audit
arriving after the provider result can only detect and trigger response; its
finding says `DETECTED_AFTER_EFFECT`, never `PREVENTED`. This correction is
also the required implementation split for `HF-014/C`.

**Response.** Restrict the local lineage, fence existing mesh sockets, and use
a typed mesh action for the exact device/node/auth key. Revoking an enrollment
key and deleting an already enrolled device are different postconditions.

**Required test.** The fixture independently attempts unexpected mesh exec,
TUN open/ioctl, raw socket/capability, control connection, and use of an
already established mesh flow. Each advertised gate and the packet fence have
their own physical assertion.

##### HF-014 trust-boundary split after node-root access

The retained prevention chain is valid before node root, and may remain valid
after a root shell only while Mithril's enforcement boundary is independently
proved intact. The public sequence obtained node root before enrolling that
node into the mesh. “Same-node BPF will still contain an attacker who controls
that BPF/runtime boundary” is therefore abandoned as an unconditional claim.

Mithril records one of these branches:

```text
HF_014_A_ENFORCER_INTACT:
  root-capable task exists, but protected links/maps/runtime binary,
  admission socket, policy signer, and required packet hooks pass tamper probes
  -> local exec/device/network gates remain eligible

HF_014_B_ENFORCER_TAMPERED_OR_UNKNOWN:
  attacker detaches/replaces a required link/map/runtime, kills the only
  userspace owner, controls the kernel, or integrity evidence is missing
  -> affected local prevention coverage is UNKNOWN;
     rely only on independently controlled mesh admission, upstream network
     fence, credential/device response, and evidence sources
```

Root UID alone does not automatically choose B: lockdown, signed BPF policy,
capability removal, read-only bpffs, runtime integrity, or another hard floor
may deny tampering. The measured tamper result chooses the branch.

`HF-GRAN-MESH-ROOT-001` starts from the privileged-hostPath root fixture and
tries to kill `mithril-node`, alter/pin/replace maps, detach links, load BPF,
replace the runtime/shim, change the CNI chain, and then establish mesh access.
Every denied tamper has its own errno/postcondition. If any required tamper
succeeds, the affected coverage interval closes before the subsequent mesh
attempt and no local-prevention claim is permitted; provider-side rejection or
response remains independently testable.

#### `HF-015`: attacker environment enrolls into the mesh

**Situation.** An external environment joins the organization's mesh. The
joining process may be outside every Mithril node.

**Mithril action.** Mesh audit creates an external subject keyed by exact
device/node/enrollment/auth-key identifiers. Credential acquisition/use and
the enrollment result form typed provider edges. A local node is connected to
that branch only with exact shared credential, request, or connector evidence.

**Prevention boundary.** Without a mesh admission integration, the enrollment
may complete before audit arrives. Mithril calls this detection/containment.
An optional provider-side pre-admission policy can deny unknown device posture
or unapproved enrollment, but it is not kernel prevention.

**Response.** Expire/revoke the exact enrollment credential to stop new joins,
delete or disable the enrolled device to stop the existing member, and verify
both separately. Search for other devices enrolled with the same credential.

**Required test.** The response test proves that key revocation alone does not
remove an existing device, then verifies the distinct device-removal action.
An outside-authority origin keeps the distributed result `partial` until the
provider branch is contained.

#### `HF-016`: mesh access reaches an internal connector catalog

**Situation.** An enrolled mesh client reaches a connector or catalog that can
expose cluster/cloud/source-control context.

**Local policy.** On managed connector hosts, Mithril applies a connector
service role: declared listeners and upstreams are allowed, but unexpected
child exec, credential objects, destinations, devices, and privilege effects
are denied. A network flow from a mesh peer proves communication only.

**Authority behavior.** Connector-native audit should carry authenticated
source device/principal, connector ID, catalog/resource, source request ID,
destination request ID when forwarded, operation, and result. These fields
support `connector_forwarded_request`; a shared connector principal plus time
does not.

**Response.** Fence the compromised mesh device/channel, restrict the exact
connector process if it deviated, disable only affected connector grants or
sessions, and preserve service for unaffected principals where the provider
supports that scope.

**Required test.** A legitimate catalog request and an unexpected request use
the same connector service. Provider/request IDs distinguish them. Removing
those IDs downgrades the edge to contextual and makes connector-specific
automatic response ineligible.

##### Abandoned design: the internal connector catalog was reached through mesh

The section title and retained situation can imply that the connector-catalog
request traversed the newly enrolled mesh client. The detailed Hugging Face
timeline explicitly corrects that assumption: the worker foothold reached the
internal connector hostname directly inside the cluster, separately from and
not through the mesh. Treating the mesh device as this request's parent would
create a false causal edge and is abandoned.

The normative incident graph has independent branches:

```text
Branch A — direct connector compromise path
conversion-worker process
  -> exact task/socket to internal RFC1918 connector destination
  -> connector catalog request/result when connector evidence exists
  -> shared connector credential
  -> cluster A system:masters authority
  -> cluster B system:masters authority

Branch B — mesh paths
rooted managed node or external sandbox
  -> mesh enrollment/device/session
  -> mesh routes, exit nodes, internal CI subnets, source-control connector
  -> only those remote requests proven by mesh/connector request evidence
```

Branch A's earliest local prevention is a worker-role connect/send denial to
the exact connector service address set. If that channel is legitimate, the
connector semantic policy rejects or alerts an unexpected catalog operation.
The single shared connector credential then creates two explicit cluster
authority branches and a broad response blast radius; “one connector” is not
one cluster.

**Corrected test.** The worker reaches the connector while no mesh device or
SOCKS process exists. `ALG-NET` must still deny or attribute the flow. When the
fixture supplies a catalog result containing two exact cluster connection
identities, `ALG-AUTHORITY` creates two branches. Adding a concurrent unrelated
mesh session must not make it an ancestor of the direct request.

##### Abandoned design: shared credential means exact end-to-end cluster cause

The catalog can prove that it exposed two cluster records, and each cluster can
authoritatively prove use of a shared `system:masters` credential. Neither fact
alone proves which concurrent local requester caused a particular cluster
operation. Calling both branches exact end-to-end causality is abandoned.

The graph uses four different edges:

```text
CATALOG_EXPOSED_CLUSTER
  connector request/result -> immutable cluster identity
  exact only for fields in authenticated connector output

CREDENTIAL_VALID_FOR_CLUSTER
  credential ID -> cluster identity
  exact configuration/authority relation, not observed use

CREDENTIAL_USED_IN_CLUSTER
  credential ID -> Kubernetes audit request/result
  exact authority operation in that cluster

LOCAL_REQUEST_CAUSED_CLUSTER_OPERATION
  local/connector request -> cluster audit request
  exact only with forwarded request IDs, a unique per-request lease, or a
  carried nonce; otherwise CONTEXTUAL_SHARED_AUTHORITY
```

**Concurrency test.** Two clients use the same connector credential at once,
one against each cluster. Connector catalog output and both Kubernetes audit
records remain authoritative. Without forwarded IDs, the two local-to-cluster
edges stay contextual. Supplying distinct end-to-end request IDs upgrades only
the correctly matched edges. This prevents response against client A merely
because client B used the same credential nearby in time.

#### `HF-017`: harvested AWS credentials are used externally

**Situation.** A credential obtained from the protected estate is used from an
external origin to call AWS.

**Earlier prevention.** Deny the credential file/IMDS effect or the local
exfiltration channel when distinguishable. If the credential has escaped,
node enforcement cannot stop an external AWS request.

**Correlation.** Cloud audit resolves access-key ID, assumed-role session,
principal ARN, account, request/event ID, source, API operation, resource, and
result. An exact access-key/session ID connects an AWS operation to that
credential/session. It connects a particular Linux acquisition to later use
only when protected credential inventory, a broker lease, or a qualified
fingerprint observation binds the local object/use to the same ID. Otherwise
the acquisition and provider use remain separate exact facts with a contextual
edge. The same IAM role name used concurrently by several workloads is not an
exact edge.

##### Abandoned design: access-key ID alone proves the Linux reader

The retained sentence “an exact access-key/session ID can connect credential
acquisition to use” was too broad. CloudTrail does not observe which local
process read a shared file or environment value. `HF-017/C` requires the
inventory/broker/fingerprint join above; without it, response may target the
credential/session but cannot claim the chosen Linux process acquired it.

**Authority behavior.** Expected role operations remain quiet. A new source,
operation, resource, region, or session behavior outside the signed rule emits
a versioned finding. Behavioral novelty supports detection but does not replace
the exact provider identity.

**Response.** Revoke/disable the exact access key or role session where
possible, apply a narrowly scoped deny/quarantine, enumerate resources changed
by that session, and verify provider state. Broad role-session revocation has
an explicit blast radius and approval.

**Required test.** Two workloads concurrently use the same role name with
different sessions. Only the exact compromised session is joined and targeted.
A shared-name-only case remains contextual. Resource postconditions are
verified after revocation.

##### Abandoned design: all AWS use occurred from an external origin

The retained situation is true for one Day 3 branch: node-role credentials
were replayed from external hosting addresses. It is incomplete as the only
model. The detailed timeline also reports Day 4 cloud-key use from the same
worker foothold against internal services, plus a local STS identity call whose
result was exfiltrated over a raw socket. Describing every AWS action as
external would erase preventable local effects and is abandoned.

Mithril models both branches:

```text
External replay branch:
  earlier credential acquisition/exfil evidence
    -> exact AWS access-key/session where proven
      -> external-source CloudTrail operations
        -> provider detection/response; no local syscall prevention claim

Worker-local branch:
  conversion-worker task
    -> optional package-install/code/file effects
    -> internal MongoDB-AWS destination attempt
    -> AWS STS destination/request
    -> public raw-socket exfiltration
      -> local exec/file/network denial where each effect is distinguishable
      -> provider/database result records success, timeout, or denial
```

The failed MongoDB server-selection attempt remains a failed provider/service
result, not Mithril prevention, unless a local hook actually denied its socket.
The STS call and later raw exfil are independently enforceable destinations.

**Corrected test.** Run the same access key from an unprotected external client
and from the labeled worker. The external call can only be detected/responded
to through provider evidence. The worker's undeclared STS/database/exfil
connections return the configured errno. The graph keeps the two source
subjects distinct even when CloudTrail shows the same access-key ID.

#### `HF-018`: source-control installation token is minted

**Situation.** A connector or compromised authority asks GitHub to mint a
GitHub App installation token and may then modify source or CI state.

**Local policy.** If the connector process/destination is unexpected, node
policy denies it. If the connector legitimately talks to GitHub over direct
TLS, the kernel cannot determine whether the HTTPS request is token creation,
clone, push, email-like notification, or another API operation.

**Authority behavior.** Connector audit and GitHub audit/API state identify the
App, installation, actor, token request where exposed, repositories,
permissions, operation, request/delivery IDs, and result. The signed behavior
rule permits expected installation operations and flags token minting or
write-capable repository effects outside them.

**Optional prevention.** A GitHub/connector-side policy integration at the
semantic API boundary may reject token minting before the provider call. This
does not require TLS interception because the connector itself supplies typed
operation metadata. Without that integration, detection follows authoritative
audit.

**Response.** Revoke a known token where supported, suspend the exact
installation if necessary, rotate App credentials with appropriate approval,
and enumerate commits, branches, workflows, releases, packages, and image
digests changed during the exposure. Token revocation and installation
suspension are distinct actions.

**Required test.** Read and write operations share a GitHub TLS destination.
The node does not claim verb visibility. Provider/connector evidence detects
the token/write effect, and the response verifies repository and installation
state rather than merely receiving HTTP success.

##### Abandoned design: GitHub audit token identity is a revocation handle

The retained “revoke a known token” is implementable only when the component
calling GitHub still possesses that installation token (or a protected handle
to it). GitHub's revoke-installation-token endpoint revokes the token used to
authenticate the revoke request. A `hashed_token`, token fingerprint, audit
actor, installation ID, or guessed token ID cannot revoke an arbitrary bearer
token. Treating audit identity as a revocation credential is abandoned.

The GitHub adapter exposes distinct capabilities:

```text
ConnectorTokenMintObservation {
  broker_request_id, app_id, installation_id, repositories, permissions,
  result, credential_lease_id, protected_token_handle?
}

GithubDocumentedAuditObservation {
  documented downstream repository/organization/workflow operation fields
}

GithubRevokePossessedInstallationToken {
  credential_lease_id, protected_token_handle
}

GithubSuspendInstallation { installation_id }
GithubRemoveRepositoryAccess { installation_id, repository_id }
WaitForExpiryAndWatch { token_fingerprint, expires_at }
```

Standard GitHub audit-only mode marks installation-token **mint detection**
`UNSUPPORTED` unless the configured GitHub schema/version documents that event.
It may still detect documented downstream repository, workflow, organization,
or access-token-attributed operations. A connector/broker that made the mint
request supplies exact request/result evidence. If its protected raw handle is
available, exact self-revocation is eligible; with only a hash, choose scoped
repository removal, broader installation suspension, or expiry/watch and
report the blast radius.

`HF-GRAN-GITHUB-REVOKE-001` mints token T through the test broker and token U
outside it. Revocation by T's protected handle makes T fail a provider probe
while U remains usable. Replaying only T's audit hash makes exact revoke
ineligible. Suspending the installation makes both fail and must report that
broader scope. In standard audit-only mode, the mint result is
`UNSUPPORTED_SOURCE`; a later documented repository write can still alert.

#### `HF-019`: public remote loader re-arms fresh sandboxes

**Situation.** New external sandboxes retrieve and execute a public loader,
allowing persistence across ephemeral environments.

**Managed-node prevention.** On any protected node, deny the unapproved loader
destination, artifact write/code mapping, executable edge, memfd/deleted image,
or anonymous executable memory according to role. Those generic denials do not
require payload identity. An artifact digest joins download to execution only
when a trusted download/CAS/content-hash source, IMA measurement, fs-verity
proof, or held sealed-object reconciliation measures both ends.

##### Abandoned design: every memfd/anonymous execution retains a trusted digest

The old unqualified digest sentence is abandoned. Filename equality, reading
bytes in userspace, and later anonymous executable memory do not automatically
preserve content identity. `HF-019/B` tests generic memfd/deleted/anonymous-map
denial. `HF-019/C` is a separate correlation case and may claim the same digest
only with one of the named content oracles; otherwise it reports
`CONTENT_PROVENANCE_UNAVAILABLE`.

**Outside authority.** If the sandboxes are not managed by Mithril, record them
as external subjects and act on shared provider/artifact/C2 infrastructure
within authority. Do not claim a Hugging Face node stopped their execution.

**Response.** Remove/quarantine the exact artifact or endpoint where
authorized, revoke the credential or dispatch mechanism that causes reload,
and enumerate every consumer by immutable digest/request ID. URL or filename
alone is insufficient for exact consumer lineage.

**Required test.** Execute the same bytes by ordinary file, renamed file,
memfd, deleted file, and anonymous mapping on a protected fixture. Each claimed
execution path is denied. An unprotected external fixture remains explicitly
outside authority.

#### `HF-020`: staged binary and host state inspection

**Situation.** The foothold examines staged code and host/process state late in
the campaign.

**Local policy.** The current role is evaluated for procfs/sysfs/debugfs reads,
other-process memory/fds/maps, ptrace, perf, BPF, device access, mount/namespace
operations, host filesystem objects, and executable staging. Normal worker
diagnostics can be declared as exact read-only object classes without granting
general host inspection.

**Correlation.** A series of audited reconnaissance effects from the same
execution can raise finding priority, but every event remains independently
attributed and covered. A process name such as `readelf` is neither necessary
nor sufficient.

**Response.** Restrict the exact lineage and preserve relevant files,
descriptors, memory metadata, and WAL evidence before irreversible kill when
authorized. Evidence preservation cannot silently delay an already authorized
socket fence.

**Required test.** The profile allows one declared diagnostic file and denies
cross-task proc, ptrace, perf, BPF, debugfs, host mount, and staged executable
cases. Ring-buffer loss during a denial does not permit the operation.

##### Abandoned design: HF-020 definitely belongs to one protected lineage

The published activity does not identify one exclusive execution location for
every staged-binary and host-inspection action. The retained phrases “current
role” and “exact lineage” are conditional, not established incident facts.
Assigning them unconditionally to a protected Hugging Face task is abandoned.

The package emits one of:

```text
HF_020_A_MANAGED_EXACT:
  exact node boot/task/execution evidence exists
  -> local file/device/privilege decision and lineage response are eligible

HF_020_B_EXTERNAL_EXACT:
  exact provider/sandbox evidence proves an unmanaged execution location
  -> outside_authority; correlate artifact/provider behavior only

HF_020_C_LOCATION_UNRESOLVED:
  action/tool/artifact evidence exists without an exact location join
  -> evidence-only external-or-unknown subject; no local denial or exact kill
```

`HF-GRAN-HOST-LOC-001` replays identical `readelf`, hostname, proc inspection,
and staged-file evidence from (a) a labeled protected task, (b) an explicitly
unmanaged sandbox source, and (c) a source with location fields removed. Only
(a) may return a local errno and bind a lineage response. Case (b) is
`outside_authority`; case (c) is `LOCATION_UNRESOLVED`. Process/tool names and
matching timestamps cannot upgrade either case.

#### `HF-021`: access cut and end of recovered activity

**Situation.** Defenders sever access and activity ends. The architectural
question is how Mithril proves containment rather than infers it from silence.

**Response plan.** Mithril:

1. fences the proven local seed process and established flows;
2. follows the exact versioned distributed lineage across current nodes,
   controllers, mesh, connectors, cloud, repositories, and credentials;
3. re-resolves and authorizes one typed action per target;
4. watches kubelet/container restarts and controller-created replacement Pods;
5. watches provider feeds for credential reuse, late artifacts, and new
   branches;
6. verifies every physical postcondition; and
7. reports unresolved, outside-authority, or coverage-deficient branches.

**No-silence rule.** “No more alerts” is not a postcondition. Required source
coverage must remain healthy for the declared watch interval. An offline node
or provider-feed gap prevents `verified` containment.

**Required test.** `HF-RESP-002` contains a two-node branch, lets the controller
attempt replacement, delivers one provider event late, and makes one optional
source unavailable. The expected result is deterministic: every required
branch must verify for `verified`; otherwise the result is `partial` or
`unknown` with exact reasons.

### Situation-To-Control Summary

| Stage | Earliest local prevention when available | Required semantic/correlation control | Narrow response |
| --- | --- | --- | --- |
| `HF-008` | role/object file-open denial | exact dataset dispatch/revision if available | process/cgroup plus exact revision only when proven |
| `HF-009` | environ/credential file, artifact, or egress denial | sensitive-read and provider publication evidence | process/socket; exact leaked object/credential |
| `HF-010` | first exec/file/socket/device/security effect | same-process limitation retained | exact interpreter lineage, honest multi-job blast radius |
| `HF-011` | projected-token object denial | exact credential object/lease to authority use | process/socket; token/session-specific recovery |
| `HF-012` | API/IMDS destination denial | Kubernetes/cloud verb and resource audit | exact process/socket and mutated resource/session |
| `HF-013` | repository channel if distinguishable | repository operation and immutable revision | token/session plus exact artifact/revision |
| `HF-014` | mesh exec, TUN, capability, or control destination | mesh operation/device audit | local lineage/socket plus exact mesh device/key |
| `HF-015` | provider admission only; external node may be outside authority | exact enrollment/device/key | revoke new-enrollment key and remove existing device separately |
| `HF-016` | managed connector role/effect policy | exact connector source/destination request IDs | device/channel and affected connector grant/session |
| `HF-017` | earlier credential/IMDS/exfil gate | exact AWS key/session and API audit | exact session/key, then changed resources |
| `HF-018` | unexpected connector/GitHub channel; semantic connector gate if installed | GitHub App/installation/token/repository audit | token or installation plus repository integrity review |
| `HF-019` | destination/artifact/exec/memfd/mmap denial on managed nodes | immutable artifact consumer graph | artifact/dispatch/C2 within authority |
| `HF-020` | proc/ptrace/perf/BPF/device/host-object denial | exact reconnaissance sequence | lineage restriction and evidence preservation |
| `HF-021` | response-root and packet fences | versioned distributed branch watch | independently verified node/controller/provider actions |

### Worked Policy Example

This pseudo-configuration is illustrative, not an approved serialization
format. It shows how an unchanged worker and a kubelet-created probe receive
different authority in the same container.

```yaml
profile: hf-conversion-worker
version: 7
selector:
  namespace: datasets
  labels:
    app: conversion-worker

defaults:
  exec: deny
  file: deny
  network: deny
  device: deny
  security: deny

entries:
  - kind: container-start
    container: application
    imageDigest: sha256:approved-worker-image
    role: conversion-worker-root
    onMissingAdmission: deny-start

  - kind: kubelet-exec-probe
    declaredField: readinessProbe.exec
    commandDigest: sha256:canonical-health-command
    role: kubelet-exec-probe
    maxConcurrent: 2
    ambiguity: deny

  - kind: kubelet-prestop
    declaredField: lifecycle.preStop.exec
    commandDigest: sha256:canonical-cleanup-command
    role: kubelet-prestop
    claimTtl: 2s
    ambiguity: deny

roles:
  conversion-worker-root:
    forkWithoutExec: conversion-worker-child
    maxDepth: 8
    exec:
      - targetObject: approved-converter-helper
        resultRole: declared-converter-helper
    files:
      - allow: [read]
        class: dataset-input
      - allow: [read, mmap]
        class: worker-runtime
      - allow: [read, write, create]
        class: worker-scratch
      - deny: [read]
        class: projected-service-account-token
        setFinding: HF-PROC-001
      - deny: [read]
        class: worker-environment-procfile
    network:
      - allow: [connect, send]
        destination: approved-dataset-service
      - deny: [connect, send]
        destination: [kubernetes-api, cloud-imds, mesh-control, public-internet]
    devices: []
    security: []

  kubelet-exec-probe:
    lifetime: 3s
    childProcesses: deny
    files:
      - allow: [read]
        class: probe-health-file
    network: []
    devices: []
    security: []

  kubelet-prestop:
    lifetime: 20s
    childProcesses: deny
    files:
      - allow: [write]
        class: declared-cleanup-state
    network:
      - allow: [send]
        destination: declared-drain-endpoint
    onActiveContainment: deny

authorityBehavior:
  - principal: conversion-worker-service-account
    sourceRole: conversion-worker-root
    kubernetes:
      allowedOperations: []
    onDeviation: HF-DW-001
```

Consequences:

- the readiness process is legitimate even though the host runtime, not PID 1,
  created it;
- it cannot read the mounted token merely because it shares the container;
- an attacker running the health binary as a native worker child keeps the
  worker-child transition, not the kubelet-probe role;
- a direct unadmitted runtime exec cannot borrow the probe role;
- the worker can process multiple logical jobs without Mithril naming or
  changing them; and
- `preStop` remains subject to active containment policy.

### Configuration And Detection Disposition Model

The earlier `EffectRule.decision: allow | audit | deny` is correct for a small
kernel decision table, but it is incomplete as the operator-facing model.
`audit` does not say whether to notify anyone, `deny` does not distinguish a
syscall denial from rejecting a runtime request, and provider audit may arrive
after the effect can no longer be denied. The complete configuration separates
**physical disposition**, **finding delivery**, and **optional response**.

This is an additive clarification, not a replacement of the earlier rule.
The compiler still lowers effect rules to compact allow/audit/deny values. It
now compiles the full source rule into the correct entry, kernel, finding, and
response plans.

#### Exact meaning of the four requested dispositions

| Configured disposition | Physical meaning | Evidence and notification | Valid decision point |
| --- | --- | --- | --- |
| `allow` | Let the entry or effect proceed | Emit only required coverage/evidence or configured sampling; no finding by default | Entry, transition, local effect, or provider behavior rule |
| `alert` | Let the action proceed | Persist a finding and route the configured notifications; no claim of prevention | Any observable point, including provider audit after completion |
| `deny` | Return the hook-specific failure before the protected local effect completes, such as `EACCES` for file/exec or `EPERM` for a security operation | Always persist a denial finding when evidence transport is available; notification routing remains configurable | Synchronous local pre-effect hook only |
| `reject` | Refuse the higher-level request before its process/lease/provider operation is admitted | Persist a rejection finding and return a typed reason to the runtime, CI coordinator, admission service, or semantic connector | Entry admission or another synchronous semantic request boundary |

`alert` is therefore “allow plus finding,” not a weaker spelling of deny.
`reject` is not a different errno for `open(2)`: a file hook can deny the open,
but it cannot reject a CI job that already started. Conversely, a provider
audit record that says a GitHub token was minted can alert and trigger response,
but cannot deny the already-completed mint. If a typed GitHub/connector
pre-admission integration exists, that integration can reject the request.

This separation is source-grounded: `KA-CODE-009` shows an effective compact
Allow/Audit/Block policy vocabulary, while `TG-CODE-013` separates mode and
Post/Signal/Override actions. Mithril does not flatten those lessons into one
ambiguous enum. A projected-token `file_open` can be `deny + alert`; an
unproven runtime root is `reject`ed before admission; and a completed unusual
provider read is `alert + optional response` because neither a kernel deny nor
entry rejection remains physically possible.

The final sentence is conditional on such a token-mint record actually
existing in the configured source. GitHub's documented audit schema does not
currently establish a standard installation-access-token creation event.
Therefore a GitHub audit-only adapter must mark that specific source
`UNSUPPORTED`; a connector/broker that makes the token request may emit its own
authenticated request/result observation. “Maybe GitHub audit contains it” is
not coverage.

#### Evaluation-stage lowering table

Every source rule names one stage. `allow` at a post-effect stage means “record
without finding,” because there is no longer an action to let proceed.

| Stage | Legal physical dispositions | Compiled physical result | Semantic result |
| --- | --- | --- | --- |
| `ENTRY_ADMISSION` | `allow|alert|reject` | admit, audit-admit, or reject request | optional finding |
| `NATIVE_TRANSITION` | `allow|alert|deny` | allow, audit-allow, or negative errno | optional finding |
| `LOCAL_PRE_EFFECT` | `allow|alert|deny` | allow, audit-allow, or negative errno | optional finding |
| `REMOTE_PRE_ADMISSION` | `allow|alert|reject` | semantic gate forwards, forwards+finds, or rejects | authoritative gate result |
| `POST_EFFECT` | `allow|alert` only | not applicable | record only, or finding/response proposal |

Post-effect observations also carry
`observed_effect_result=SUCCEEDED|DENIED_BY_AUTHORITY|FAILED|UNKNOWN`. A
provider's own denial is not Mithril prevention. `deny` or `reject` at
`POST_EFFECT` is a compile error.

#### Source configuration objects

```text
DetectionDispositionRule {
  rule_id
  enabled
  priority
  match {
    finding_id?
    entry_kind?
    role_id?
    effect_family?
    operation?
    object_class?
    authority?
    provider_operation?
    lifecycle_state?
    intent_issuer?
    intent_strength_at_least?
    source_quality_at_least?
    trigger_trust_class?
    namespaces_or_workloads?
  }

  disposition: allow | alert | deny | reject
  errno?
  severity
  evidence_level: minimal | standard | forensic
  notify[]
  response_playbook?

  fallbacks {
    missing_intent
    ambiguous_intent
    source_unavailable
    classifier_unknown
    control_plane_unavailable
    response_authority_unavailable
  }

  budgets {
    max_per_interval?
    max_concurrent?
    max_lifetime?
    notification_dedupe_window?
    automatic_response_limit?
  }

  exceptions[]
  valid_from?
  valid_until?
  approval_id?
}
```

Version 1 tightens the source sketch with these required types:

| Concept | Normative type/default |
| --- | --- |
| `evaluation_stage` | Required closed enum from the table above |
| `enabled` | Boolean, required; no truthy strings |
| `priority` | `i32`, default 0; display/notification ordering only, never physical conflict resolution |
| `severity` | `info|low|medium|high|critical`, required when a finding can emit |
| `evidence_level` | `minimal|standard|forensic`; default `standard` |
| duration | String `<unsigned integer>ns|us|ms|s|m|h`; no fractional or unitless value; schema-specific range applies |
| rate | `{count:u32, per:duration, burst:u32, scope, onExhaustion}`; every field required |
| limit | `{count, scope, onExhaustion}`; omission never means silently unbounded where a hard product limit exists |
| fallback | Closed condition-specific disposition set; invalid physical combinations fail compilation |
| exception | `ExceptionV1` below; free-form text is metadata only |

```text
ExceptionV1 {
  exception_id
  narrows_rule_id
  exact_subject_selector: ExactExceptionSubjectSelectorV1
  permitted_authority_delta: PermittedAuthorityDeltaV1
  approver_id
  approval_proof_id
  valid_from_utc
  valid_until_utc
  maximum_uses?
  reason
}

ExactExceptionSubjectSelectorV1 {
  profile_id
  workload_selector_ids[1..32]
  protected_scope_ids[1..32]
  execution_set_ids[0..64]
  entry_kind_ids[1..16]
  role_ids[1..32]
  immutable_definition_digests[0..32]
}

PermittedAuthorityDeltaV1 {
  delta_kind: NARROWING_ONLY | BOUNDED_BROADENING
  exact_compiled_key_digests[1..256]
  added_physical_results[]: ALLOW_EFFECT | AUDIT_ALLOW_EFFECT | ADMIT |
                            AUDIT_ADMIT
  removed_restriction_reason_bits[]
  maximum_uses: u32
  maximum_lifetime: duration
  required_capability_ids[]
}
```

An exception cannot target `*`, last forever, or override a hard invariant.
Expiration is evaluated from trusted UTC at activation and converted to node
monotonic deadlines.

`source_unavailable` is not a fallback evaluated on a missing event—there is
no event to match. The source-health owner emits a synthetic
`SOURCE_COVERAGE_UNAVAILABLE` observation naming source, scope, start time,
required packages, and current gap. A separate health rule alerts, rejects new
admissions, or invokes an independently supported fence.

Notification and response are explicit collaborators:

```text
NotificationRoute {
  route_id
  sink: pager | chat | email | siem | webhook | ticket
  minimum_severity
  grouping_key
  dedupe_window
  rate_limit
  include_evidence_fields[]
  redact_fields[]
  delivery_failure_action
}

ResponseBinding {
  playbook_id
  action: restrict_lineage | fence_sockets | freeze_cgroup |
          reject_replacement | revoke_credential | disable_mesh_device |
          quarantine_artifact | suspend_installation | provider_specific
  required_proof
  approval: automatic | preapproved | human
  max_blast_radius
  target_revalidation
  physical_postcondition
  watch_interval
}
```

No rule sends secret bytes, token values, full environments, or unrestricted
argv into a notification. Evidence fields are allowlisted and redacted before
leaving the node.

Redaction is driven by sensitivity labels assigned when an evidence field is
created, not by names such as `argvSecrets`. A token can appear in any argv,
path, URL, header, or provider field. Every `NotificationRoute` is default
deny and names its allowed schema fields plus maximum sensitivity:

```text
PUBLIC < INTERNAL < SENSITIVE_IDENTIFIER < SECRET
```

`SECRET` is never routable. `minimal` evidence contains subject IDs, decision,
hook/gate, object class, generation, time, result, and coverage references.
`standard` additionally contains normalized object/request identifiers and
lineage edge IDs. `forensic` additionally retains locally encrypted bounded
raw fields explicitly permitted by the schema; it does not weaken notification
redaction. Unknown fields are excluded.

#### Compiler output and impossible configurations

One source rule compiles to a capability-specific plan:

```text
CompiledActionPlan {
  local_pre_effect_result: allow | audit_allow | errno_deny | not_applicable
  entry_admission_result: admit | reject | not_applicable
  emit_finding: yes | no
  severity
  notification_route_ids[]
  response_binding_id?
  required_proof
  fallback_plan
}
```

The normative compiled record is the additive Version 1 form:

```text
CompiledActionPlanV1 {
  evaluation_stage
  physical_result:
    ADMIT | AUDIT_ADMIT | REJECT_REQUEST |
    ALLOW_EFFECT | AUDIT_ALLOW_EFFECT | DENY_ERRNO | NOT_APPLICABLE
  post_effect_actions: sorted unique nonempty set of
                       RECORD | FINDING | RESPONSE_PROPOSAL
  expected_observed_result:
    ADMISSION_NOT_ATTEMPTED | ADMITTED | REJECTED_BY_MITHRIL |
    EFFECT_NOT_ATTEMPTED | ALLOWED_BY_MITHRIL | DENIED_BY_MITHRIL |
    PROVIDER_SUCCEEDED | PROVIDER_DENIED_BY_AUTHORITY |
    PROVIDER_FAILED | PROVIDER_RESULT_UNKNOWN
  emit_finding
  severity?
  evidence_field_allowlist
  notification_route_ids[]
  response_binding_ids[]
  required_proof_axes
  fallback_plan_by_failure_condition
  source_rule_ids[]
  source_explanation_digest
}
```

The compiler rejects configurations that promise an impossible physical
outcome:

- `reject` on a plain file/socket hook, because only `deny` is physically
  available there;
- `deny` on a GitHub, AWS, mesh, database, or Kubernetes audit event that
  arrives after the operation completed;
- `reject` on a provider operation without a configured synchronous provider,
  admission, broker, or connector boundary;
- `allow` that would erase a prior SELinux/AppArmor/Landlock/BPF LSM denial;
- `allow` for a hard product invariant such as a stale protected identity in a
  strict profile;
- an automatic response whose required identity or postcondition is absent;
- `alert` with a notification route that can leak a protected credential; or
- a fail-open fallback for a required classifier in a profile that claims
  prevention.

Configuration controls Mithril's behavior where Mithril has authority. It
cannot configure history. An already-completed external AWS call cannot become
“denied” by choosing that word in YAML.

#### Precedence between configuration rules

For rules that match the same action:

1. A nonzero prior security-module denial remains final.
2. Active response restrictions and immutable product invariants apply.
3. Exact workload, role, entry, object, provider principal, and operation
   matches outrank broader matches.
4. A more restrictive physical disposition wins: `reject` at an admission
   point or `deny` at an effect point outranks `alert`, which outranks `allow`.
5. Notifications and response bindings are unioned only within configured
   budget and blast-radius limits.
6. An explicit exception must name the rule it narrows, its exact subject,
   approver, expiry, and maximum authority. A broad exception cannot erase a
   hard invariant.

The compiler emits a conflict report that names both source rules, the exact
tuple, the selected result, and why. It never depends on source-file ordering.

##### Abandoned design: configuration specificity and restrictive-action wins

Items 3 and 4 above, and the phrase “the selected result,” reintroduce the
same ambiguous precedence algorithm already rejected by Policy Package And
Compiler. They are retained history and abandoned. A deny is not allowed to
hide an accidental conflict merely because it is more restrictive; the
operator may have intended the allow for availability, or the two rules may
belong to different physical stages where they cannot compete at all.

The only normative configuration conflict algorithm is:

1. lower every source rule to exactly one physical evaluation stage;
2. expand selectors into finite exact keys in the closed generation universe;
3. apply hard invariants and response restrictions, which source rules cannot
   override;
4. merge identical physical results and compatible notification/response
   metadata for the same key;
5. when physical results differ, require a signed `overrides`/`Exception` edge
   naming the other rule, exact subject/key delta, approver, expiry and maximum
   authority; and
6. fail compilation when that edge is absent or invalid.

The conflict report therefore records `COMPILATION_FAILED` or the explicit
edge that selected the result. Exact match, wildcard count, YAML order,
severity, display priority, and the ordering `reject > deny > alert > allow`
are not authorization tie-breakers.

**Real configuration example.** The baseline allows a controller role to call
the Kubernetes API, while a workload-specific rule denies Pod creation. On
the exact key `(controller-A, K8S_CREATE_POD, namespace-prod)`, the compiler
does not silently choose deny. The deny rule must explicitly override the
baseline for that controller/namespace and carry the reviewed expiry, or the
profile is rejected before any generation is loaded.

#### Practical configuration example

This remains prospective YAML, but it is concrete enough to define parser,
compiler, simulator, and acceptance-test behavior:

```yaml
profile: hf-conversion-worker
version: 8
mode: protect

failurePosture:
  missingTaskIdentity: deny
  requiredClassifierUnknown: deny
  intentChannelUnavailable: reject
  providerFeedUnavailable: alert
  notificationUnavailable: keep-enforcement-and-buffer

notificationRoutes:
  security-pager:
    sink: pager
    minimumSeverity: critical
    groupingKey: [executionSetId, processLineageId, findingId]
    dedupeWindow: 2m
    redact: [argvSecrets, environmentValues, tokenBytes]

  defender-stream:
    sink: siem
    minimumSeverity: medium
    groupingKey: [findingId, providerPrincipalId, objectId]
    dedupeWindow: 15s
    redact: [tokenBytes]

responses:
  restrict-compromised-worker:
    action: restrict_lineage
    approval: preapproved
    requiredProof: exact-task-lineage
    maxBlastRadius:
      processes: 32
      executionSets: 1
    verify: no-new-protected-effect-from-lineage

  revoke-exact-aws-session:
    action: revoke_credential
    approval: human
    requiredProof: exact-provider-session
    verify: session-rejected-and-no-later-cloud-events

dispositions:
  - id: admit-exact-readiness-probe
    match:
      entryKind: kubelet-exec-probe
      intentStrengthAtLeast: exact
      lifecycleState: running
    disposition: allow
    evidenceLevel: standard
    fallbacks:
      missingIntent: reject
      ambiguousIntent: reject

  - id: observe-same-budget-probe-ambiguity
    match:
      entryKind: kubelet-exec-probe
      intentStrengthAtLeast: conservative
    disposition: alert
    severity: medium
    notify: [defender-stream]
    budgets:
      maxConcurrent: 2
      maxLifetime: 3s

  - id: reject-unapproved-runtime-root
    match:
      findingId: UNAPPROVED_RUNTIME_ENTRY
    disposition: reject
    severity: high
    notify: [defender-stream]

  - id: deny-conversion-worker-token-read
    match:
      roleId: conversion-worker-root
      effectFamily: file
      operation: read
      objectClass: projected-service-account-token
    disposition: deny
    errno: EACCES
    severity: critical
    notify: [security-pager, defender-stream]
    responsePlaybook: restrict-compromised-worker

  - id: deny-worker-control-plane-connect
    match:
      roleId: conversion-worker-root
      effectFamily: network
      operation: connect
      objectClass: [kubernetes-api, cloud-imds, mesh-control]
    disposition: deny
    errno: EACCES
    severity: critical
    notify: [security-pager, defender-stream]

  - id: alert-completed-aws-deviation
    match:
      findingId: HF-DW-001
      authority: aws
      sourceQualityAtLeast: exact-provider-session
    disposition: alert
    severity: critical
    notify: [security-pager, defender-stream]
    responsePlaybook: revoke-exact-aws-session

  - id: reject-github-token-mint-at-typed-connector
    match:
      authority: github
      providerOperation: create-installation-token
      intentStrengthAtLeast: exact
    disposition: reject
    severity: critical
    notify: [security-pager, defender-stream]
    # Valid only when the configured connector is a synchronous semantic gate.

  - id: alert-github-token-mint-from-audit
    match:
      authority: github
      providerOperation: create-installation-token
      sourceQualityAtLeast: authoritative-audit
    disposition: alert
    severity: critical
    notify: [security-pager, defender-stream]
    # Audit-only deployments cannot claim that token minting was rejected.
```

#### Abandoned design: circular admission, reversed GitHub intent, and generic AWS revocation

Three retained fragments in the illustrative YAML are invalid Version 1
configuration:

1. `reject-unapproved-runtime-root` matches a finding that is normally emitted
   **after** the admission decision. Using that finding to decide the same
   admission is circular.
2. `reject-github-token-mint-at-typed-connector` matches
   `intentStrengthAtLeast: exact`, which is positive proof, and then rejects it
   without testing whether the requested installation/repositories/permissions
   exceed policy. That reverses the intended gate.
3. `revoke-exact-aws-session` assumes every AWS credential type has a narrow
   immediate revoke API and treats later audit silence as verification. AWS
   role-session revocation can invalidate all sessions issued before a cutoff;
   a policy deny targeting one assumed-role session is a different actuator,
   and propagation is not instantaneous.

The corrected admission and connector rules are:

```yaml
dispositions:
  - id: reject-missing-or-invalid-protected-entry-intent
    evaluationStage: entry-admission
    match:
      protectedScope: true
      externalRoot: true
      intentStatus: [missing, invalid, expired, replayed, ambiguous]
    disposition: reject
    emitFinding: UNAPPROVED_RUNTIME_ENTRY
    severity: high

  - id: reject-github-installation-token-by-default
    evaluationStage: remote-pre-admission
    match:
      connectorId: github-prod-gate
      providerOperation: create-installation-access-token
    disposition: reject
    emitFinding: GITHUB_TOKEN_REQUEST_REJECTED

  - id: allow-exact-approved-github-installation-token
    evaluationStage: remote-pre-admission
    overrides: [reject-github-installation-token-by-default]
    match:
      connectorId: github-prod-gate
      providerOperation: create-installation-access-token
      intentClassification: exact-target
      authorizationResult: approved
      installationId: 12345
      repositories: [org/read-only-fixtures]
      permissions:
        contents: read
      maximumTtl: 5m
    disposition: allow
```

The connector emits authenticated request and provider-result observations.
Missing, replayed, permission-expanded, repository-expanded, or expired intent
matches only the default reject. If there is no synchronous gate, these rules
do not compile. A standard GitHub audit-only deployment cannot configure an
undocumented installation-token-mint source; it watches documented repository,
installation, organization, and workflow events and reports the exact coverage
limit.

AWS response configuration selects an actuator capability, not a generic verb:

```text
AwsDenyAssumedRoleSession {
  principal_id
  role_session_name
  policy_change_target
}

AwsRevokeRoleSessionsBefore {
  role_arn
  cutoff_utc
}

AwsIdentityCenterRevokeUserSession {
  user_id
  permission_set_or_application
}
```

For each capability the adapter records required IAM authority, targeted
credential type, estimated affected sessions, expected propagation interval,
reversibility, and verification procedure. A role-cutoff action affecting S1
and S2 cannot be displayed as “revoke exact S1.” An exact-session test must
make a benign S1 request fail while S2 still succeeds; when only cutoff
revocation exists, both sessions appear in blast-radius approval. Provider
policy readback plus an authorized benign canary request verifies the action;
“no later CloudTrail events” is merely quiet-window evidence.

`maxLifetime` also needs an object-specific expiry action. For a pending entry
it expires and rejects the unused claim. For a running probe role it must name
`onExpiry: restrict|signal|terminate|alert`; expiry does not silently kill a
process. For an authority lease it stops new broker use where supported and
opens a provider watch. Version 1 rejects a bare `maxLifetime` without the
matching `onExpiry` semantics.

#### Normative Version 1 configuration and parser contract

The earlier Worked Policy Example and Practical configuration example are
retained, non-compilable design sketches. Their unversioned keys, camel-case
aliases, scalar proof quality, circular finding match, shorthand verification,
and provider assumptions are useful review history but are not an accepted
file format. This section is the one Version 1 implementation contract.

The source file is UTF-8 YAML 1.2 restricted to the JSON data model. The parser
rejects duplicate keys, aliases, anchors, merge keys, custom tags, non-string
map keys, implicit timestamps, NaN/infinity, integers outside the declared
type, unknown fields, unknown enums, and more than the signed size/depth/count
limits. Enum values are uppercase ASCII. Durations match
`^[0-9]+(ns|us|ms|s|m|h)$`; zero is legal only where the field explicitly says
so. YAML is decoded into the closed types below, encoded as deterministic CBOR,
and signed as `SignedWorkloadProtectionProfileV1`; comments and YAML order have
no security meaning.

```text
PolicyDocumentV1 {
  api_version: exactly "mithril.erebor.dev/v1"
  kind: exactly "ProtectionPolicy"
  metadata: {
    profile_id: Id128
    profile_version: u64 > 0
    trust_domain_id: Id128
    valid_from_utc: RFC3339 UTC string normalized to i64 nanoseconds
    valid_until_utc?: RFC3339 UTC string normalized to i64 nanoseconds
  }
  required_capability_ids[]
  protected_universe: {
    workload_selector_ids[]
    protected_scope_ids[]
    execution_set_ids[]
    role_ids[]
    entry_kind_ids[]
    object_class_ids[]
    provider_account_ids[]
  }
  workload_selectors[]: WorkloadSelectorV1
  classifier_bindings[]: ObjectClassifierBindingV1
  roles[]: RoleDefinitionV1
  entry_role_assignments[]: EntryRoleAssignmentV1
  native_transition_rules[]: NativeRoleTransitionRuleV1
  process_state_definitions[]: ProcessStateDefinitionV1
  domain_sensitive_state_rules[]: DomainSensitiveStateRuleV1
  effect_family_defaults[]: EffectFamilyDefaultV1
  authority_behavior_rules[]: AuthorityBehaviorRuleV1
  correlation_package_bindings[]: CorrelationPackageBindingV1
  default_postures: DefaultPosturesV1
  notification_routes[]: NotificationRouteV1
  response_bindings[]: ResponseBindingV1
  exceptions[]: ExceptionV1
  rules[]: DetectionDispositionRuleV1
  source_coverage_health_rules[]: SourceCoverageHealthRuleV1
  rollout: RolloutV1
}

PolicyLocalIdV1 = UTF-8 matching `^[a-z][a-z0-9.-]{0,127}$`
RegistrySymbolV1 = ASCII matching `^[A-Z][A-Z0-9_]{0,127}$`
ReasonCodeIdV1 = RegistrySymbolV1
ObjectClassIdV1 = RegistrySymbolV1
ResultCodeIdV1 = RegistrySymbolV1
PackageIdV1 = ASCII matching `^[A-Z][A-Z0-9-]{0,126}[0-9]$`

LabelRequirementV1 {
  key: UTF-8 Kubernetes qualified-name, 1..253 bytes
  operator: IN | NOT_IN | EXISTS | DOES_NOT_EXIST
  values[]: UTF-8 Kubernetes label values, sorted unique, 0..64
}

WorkloadSelectorV1 {
  workload_selector_id: PolicyLocalIdV1
  cluster_uids[1..16]: Id128
  namespace_uids[1..64]: Id128
  controller_uids[0..256]: Id128
  service_account_uids[0..64]: Id128
  pod_label_requirements[0..64]: LabelRequirementV1
  container_names[0..64]: UTF-8 1..253 bytes
  container_kinds[1..4]: INIT | SIDECAR | APPLICATION | EPHEMERAL
  image_digests[0..256]: DigestV1
}

ObjectClassifierSelectorV1 =
  PROJECTED_SERVICE_ACCOUNT_TOKEN {
    workload_selector_ids[1..32], service_account_uids[1..64],
    required_projected_source: KUBERNETES_SERVICEACCOUNT_TOKEN,
    required_mount_read_only: bool
  }
  | FILESYSTEM_OBJECT {
      workload_selector_ids[1..32], mount_source_class,
      relative_component_bytes[], filesystem_type_ids[],
      required_object_type: FILE | DIRECTORY
    }
  | IMMUTABLE_ARTIFACT { artifact_digests[1..256] }
  | DESTINATION { destination_policy_ids[1..256] }
  | DEVICE { device_class_ids[1..256] }
  | KERNEL_SECURITY_OBJECT { security_object_ids[1..256] }

DestinationPolicyRecordV1 {
  destination_policy_id: PolicyLocalIdV1
  protocols[1..3]: TCP | UDP | SCTP
  ipv4_prefixes[0..256]: canonical CIDR
  ipv6_prefixes[0..256]: canonical CIDR
  port_ranges[1..64] { first:u16, last:u16 >= first }
  required_network_namespace_ids[0..64]: Id128
  service_identities[0..64] {
    provider: KUBERNETES | AWS | GITHUB | MESH | CONNECTOR | OTHER
    stable_service_id: PolicyLocalIdV1
    endpoint_registry_generation: u64 > 0
  }
  final_address_required: bool
}

DeviceClassRecordV1 {
  device_class_id: PolicyLocalIdV1
  device_type: CHAR | BLOCK
  major_ranges[1..64] { first:u32, last:u32 >= first }
  minor_ranges[1..64] { first:u32, last:u32 >= first }
  driver_name_digests[0..64]: DigestV1
  allowed_ioctl_command_ids[0..256]: u32
}

SecurityObjectRecordV1 {
  security_object_id: PolicyLocalIdV1
  family: PTRACE | PROCESS_VM | PIDFD | BPF | PERF | KEYRING |
          CAPABILITY | NAMESPACE | MOUNT | MODULE | IO_URING_CONTROL
  operation_ids[1..256]: RegistrySymbolV1
  target_selector_ids[0..64]: PolicyLocalIdV1
}

MountSourceClassRecordV1 {
  mount_source_class_id: PolicyLocalIdV1
  source_kind: ROOTFS | BIND | TMPFS | PROJECTED | SECRET |
               CONFIGMAP | EMPTYDIR | HOSTPATH | CSI | NFS | FUSE | OTHER
  filesystem_type_ids[1..64]: PolicyLocalIdV1
  backing_object_or_volume_ids[0..64]: Id128
  required_mount_flags[0..32]: READ_ONLY | NOSUID | NODEV | NOEXEC
}

ObjectClassifierRegistryV1 {
  registry_version: u64 > 0
  destination_policies[]: DestinationPolicyRecordV1
  device_classes[]: DeviceClassRecordV1
  security_objects[]: SecurityObjectRecordV1
  mount_source_classes[]: MountSourceClassRecordV1
  filesystem_types[] { filesystem_type_id:PolicyLocalIdV1,
                       numeric_magic:u64, name:bounded UTF-8 }
  canonical_payload_digest: DigestV1
}

ObjectClassifierBindingV1 {
  classifier_binding_id: PolicyLocalIdV1
  object_class_id: ObjectClassIdV1
  selector: ObjectClassifierSelectorV1
  required_capability_ids[1..64]
  unknown_result: DENY | ALERT
}

RoleDefinitionV1 {
  role_id: PolicyLocalIdV1
  maximum_native_depth: u16
  default_process_state_id: PolicyLocalIdV1
  permitted_entry_kinds[1..16]: EntryKindV1
  description_artifact_digest?: DigestV1
}

EntryRoleAssignmentV1 {
  assignment_id: PolicyLocalIdV1
  workload_selector_ids[1..32]
  entry_kinds[1..16]: EntryKindV1
  container_kinds[1..4]: INIT | SIDECAR | APPLICATION | EPHEMERAL
  immutable_definition_digests[0..64]: DigestV1
  accepted_classifications[1..2]: EXACT_TARGET | SAME_BUDGET_AMBIGUOUS
  resulting_role_id: PolicyLocalIdV1
  claim_ttl: duration
  on_missing_or_unequal_ambiguity: REJECT |
    ADMIT_UNKNOWN_RESTRICTED_AND_ALERT
  unknown_restricted_role_id?: PolicyLocalIdV1
}

NativeRoleTransitionRuleV1 {
  transition_rule_id: PolicyLocalIdV1
  source_role_ids[1..32]
  operation: FORK | THREAD_CREATE | EXEC | PRIVILEGE_TRANSITION
  executable_object_ids[0..256]: PolicyLocalIdV1
  required_process_state_ids[1..64]: PolicyLocalIdV1
  resulting_role_id: PolicyLocalIdV1
  resulting_process_state_id: PolicyLocalIdV1
  requested_disposition: ALLOW | ALERT | DENY
  errno?: EACCES | EPERM | EAGAIN
}

ProcessStateDefinitionV1 {
  process_state_id: PolicyLocalIdV1
  state_bits: sorted unique closed ProcessStateBitV1[0..64]
}

DomainSensitiveStateRuleV1 {
  state_rule_id: PolicyLocalIdV1
  triggering_object_class_ids[1..256]: ObjectClassIdV1
  triggering_operations[1..64]
  set_sensitive_bits[1..64]: closed DomainSensitiveBitV1
  resulting_restriction_semantic_ids[1..64]: PolicyLocalIdV1
  monotonic: exactly true
}

EffectFamilyDefaultV1 {
  role_ids[1..32]: PolicyLocalIdV1
  effect_family: EXEC | FILE | NETWORK | DEVICE | PRIVILEGE | IPC | MOUNT
  operations[1..256]
  requested_disposition: ALLOW | ALERT | DENY
  errno?: EACCES | EPERM | EAGAIN | ECONNREFUSED
  finding?: FindingSpecV1
}

AuthorityBehaviorRuleDraftAbandoned {
  authority_rule_id: PolicyLocalIdV1
  evaluation_stage: REMOTE_PRE_ADMISSION | POST_EFFECT
  gate_capability_id?: PolicyLocalIdV1
  provider: ProviderV1
  provider_account_ids[1..64]: PolicyLocalIdV1
  principal_or_lease_selector_ids[1..64]: PolicyLocalIdV1
  canonical_operations[1..256]
  resource_selector_ids[1..256]: PolicyLocalIdV1
  expected_results[1..4]: SUCCEEDED | DENIED_BY_AUTHORITY | FAILED | UNKNOWN
  required_proof: ProofQualityPredicateV1
  requested_disposition: ALLOW | ALERT | REJECT
  finding?: FindingSpecV1
  response_binding_ids[0..16]: PolicyLocalIdV1
  budgets: BudgetSetV1
}

AuthorityBehaviorRuleV1 =
  REMOTE_ADMISSION {
    authority_rule_id: PolicyLocalIdV1,
    gate_capability_id: PolicyLocalIdV1,
    provider: ProviderV1,
    provider_account_ids[1..64]: PolicyLocalIdV1,
    principal_or_lease_selector_ids[1..64]: PolicyLocalIdV1,
    canonical_operations[1..256],
    resource_selector_ids[1..256]: PolicyLocalIdV1,
    required_proof: ProofQualityPredicateV1,
    requested_disposition: ALLOW | ALERT | REJECT,
    finding?: FindingSpecV1,
    response_binding_ids[0..16]: PolicyLocalIdV1,
    budgets: BudgetSetV1
  }
  | POST_EFFECT_RESULT {
      authority_rule_id: PolicyLocalIdV1,
      provider: ProviderV1,
      provider_account_ids[1..64]: PolicyLocalIdV1,
      principal_or_lease_selector_ids[1..64]: PolicyLocalIdV1,
      canonical_operations[1..256],
      resource_selector_ids[1..256]: PolicyLocalIdV1,
      authoritative_results[1..4]:
        SUCCEEDED | DENIED_BY_AUTHORITY | FAILED | UNKNOWN,
      required_proof: ProofQualityPredicateV1,
      requested_disposition: ALLOW | ALERT,
      finding?: FindingSpecV1,
      response_binding_ids[0..16]: PolicyLocalIdV1,
      budgets: BudgetSetV1
    }

// `AuthorityBehaviorRuleDraftAbandoned` mixed a result known only after the
// provider call with a pre-call REJECT. The tagged union above is canonical:
// REMOTE_ADMISSION requires a healthy synchronous gate and has no result
// predicate; POST_EFFECT_RESULT may alert/propose response but cannot reject
// an operation that already happened.

CorrelationPackageBindingV1 {
  binding_id: PolicyLocalIdV1
  package_id: PackageIdV1              // must exist in signed package registry
  package_version: u32 > 0
  required_source_ids[1..64]: PolicyLocalIdV1
  parameter_digest: DigestV1
  finding: FindingSpecV1
}

FindingSpecV1 {
  reason_code: ReasonCodeIdV1         // member of signed reason-code registry
  severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
  route_ids[0..32]: PolicyLocalIdV1
  evidence_level: MINIMAL | STANDARD | FORENSIC
  title_template_id?: PolicyLocalIdV1 // signed display template; no authority
}

SignedCorrelationPackageRegistryV1 {
  registry_version: u64 > 0
  packages[] {
    package_id: PackageIdV1
    package_version: u32 > 0
    implementation_digest: DigestV1
    parameter_schema_digest: DigestV1
    required_source_schema_ids[1..64]: PolicyLocalIdV1
  }
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}

ResolvedObjectClassBindingV1 {
  classifier_binding_id: PolicyLocalIdV1
  object_class_id: PolicyLocalIdV1
  exact_object: ExactObjectGenerationV1
  classifier_axis_id: u16
  classifier_axis_value_id: u32
  source_object_revision_digest: DigestV1
}

SignedWorkloadBindingGenerationDraftAbandoned {
  binding_generation_id: Id128
  policy_document_digest: DigestV1
  selector_registry_digest: DigestV1
  classifier_registry_digest: DigestV1
  cluster_uid: Id128
  node_boot_id: Id128
  workload_selector_id: PolicyLocalIdV1
  pod_uid: Id128
  pod_resource_version_digest: DigestV1
  full_container_id_digest: DigestV1
  image_digest: DigestV1
  execution_set_id: Id128
  protected_scope_id: Id128
  cgroup_binding_identity_digest: DigestV1
  resolved_object_class_bindings[]: sorted unique ResolvedObjectClassBindingV1
  binding_generation: u64 > 0
  valid_from_boottime_ns: u64
  state: PREPARING | ACTIVE | RETIRING | TOMBSTONED
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}

WorkloadBindingArtifactV1 {           // immutable signed payload
  binding_generation_id: Id128
  policy_document_digest: DigestV1
  selector_registry_digest: DigestV1
  classifier_registry_digest: DigestV1
  cluster_uid: Id128
  node_boot_id: Id128
  workload_selector_id: PolicyLocalIdV1
  pod_uid: Id128
  pod_resource_version_digest: DigestV1
  full_container_id_digest: DigestV1
  image_digest: DigestV1
  execution_set_id: Id128
  protected_scope_id: Id128
  cgroup_binding_identity_digest: DigestV1
  resolved_object_class_bindings[]: sorted unique ResolvedObjectClassBindingV1
  binding_generation: u64 > 0
  valid_from_boottime_ns: u64
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}

WorkloadBindingActivationStateV1 {    // node-local mutable state; not signed
  binding_generation_id: Id128
  artifact_digest: DigestV1
  state: PREPARING | ACTIVE | RETIRING | TOMBSTONED
  transition_version: u64
  last_complete_readback_digest: DigestV1
}

DetectionDispositionRuleV1 {
  schema_version: exactly 1
  rule_id
  enabled: bool
  priority: i32 = 0                 // display/notification order only
  evaluation_stage: ENTRY_ADMISSION | NATIVE_TRANSITION |
                    LOCAL_PRE_EFFECT | REMOTE_PRE_ADMISSION | POST_EFFECT
  match: EntryAdmissionMatchV1 | NativeTransitionMatchV1 |
         LocalEffectMatchV1 | RemoteAdmissionMatchV1 | PostEffectMatchV1
  requested_disposition: ALLOW | ALERT | DENY | REJECT
  errno?: EACCES | EPERM | EAGAIN | ECONNREFUSED
  finding?: FindingSpecV1
  response_binding_ids[]
  fallback_by_condition[]: FallbackV1
  budgets: BudgetSetV1
  overrides_rule_ids[]
  exception_ids[]
  valid_from_utc?
  valid_until_utc?
}

CommonSubjectMatchV1 {
  workload_selector_ids[]?
  protected_scope_ids[]?
  execution_set_ids[]?
  entry_kind_ids[]?
  role_ids[]?
  process_state_required_bits[]
  process_state_forbidden_bits[]
}

EntryAdmissionMatchV1 {
  kind: exactly ENTRY_ADMISSION
  subject: CommonSubjectMatchV1
  runtime_operation: CONTAINER_START | EXEC_SYNC | STREAMING_EXEC |
                     LIFECYCLE_EXEC | EPHEMERAL_CONTAINER |
                     CHECKPOINT_RESTORE
  intent_classification[]: EXACT_TARGET | SAME_BUDGET_AMBIGUOUS |
                           AMBIGUOUS | UNKNOWN
  intent_status[]: VALID | MISSING | INVALID | EXPIRED | REPLAYED
  immutable_definition_digests[]
}

NativeTransitionMatchV1 {
  kind: exactly NATIVE_TRANSITION
  subject: CommonSubjectMatchV1
  operation: FORK | THREAD_CREATE | EXEC | PRIVILEGE_TRANSITION
  executable_object_ids[]
  source_role_ids[]
  target_role_ids[]
}

LocalEffectMatchV1 {
  kind: exactly LOCAL_EFFECT
  subject: CommonSubjectMatchV1
  effect_family: EXEC | FILE | NETWORK | DEVICE | PRIVILEGE | IPC | MOUNT
  operations[]
  object_selector: LocalObjectSelectorV1
  binding_lifecycle_states[1..4]: PREPARING | ACTIVE | DRAINING | TERMINATING
  required_proof: ProofQualityPredicateV1
}

LocalObjectSelectorV1 =
  EXACT_OBJECTS { exact_object_ids[1..256]: Id128 }
  | OBJECT_CLASSES { object_class_ids[1..256]: ObjectClassIdV1 }
  | DESTINATION_CLASSES { destination_class_ids[1..256]: PolicyLocalIdV1 }
  | DEVICE_CLASSES { device_class_ids[1..256]: PolicyLocalIdV1 }
  | SECURITY_OBJECT_CLASSES {
      security_object_class_ids[1..256]: PolicyLocalIdV1
    }

RemoteAdmissionMatchV1 {
  kind: exactly REMOTE_ADMISSION
  subject: CommonSubjectMatchV1
  gate_capability_id
  provider
  provider_account_id
  canonical_operations[]
  resource_selector_ids[]
  authority_lease_permission_sets[]
  required_proof: ProofQualityPredicateV1
}

PostEffectMatchV1 =
  LOCAL_COMPLETION {
    package_ids[0..256]: PackageIdV1,
    finding_reason_codes[0..256]: ReasonCodeIdV1,
    subject: CommonSubjectMatchV1,
    effect_family: EXEC | FILE | NETWORK | DEVICE | PRIVILEGE | IPC | MOUNT,
    operations[1..256],
    object_selector: LocalObjectSelectorV1,
    result_source_ids[1..64]: PolicyLocalIdV1,
    local_result_ids[1..256]: ResultCodeIdV1,
    coverage_source_ids[1..64]: PolicyLocalIdV1,
    required_proof: ProofQualityPredicateV1
  }
  | PROVIDER_RESULT {
      package_ids[0..256]: PackageIdV1,
      finding_reason_codes[0..256]: ReasonCodeIdV1,
      provider: ProviderV1,
      provider_account_ids[1..64]: PolicyLocalIdV1,
      canonical_operations[1..256],
      authoritative_results[1..4]:
        SUCCEEDED | DENIED_BY_AUTHORITY | FAILED | UNKNOWN,
      required_proof: ProofQualityPredicateV1
    }
  | PACKAGE_OR_FINDING {
      package_ids[0..256]: PackageIdV1,
      finding_reason_codes[0..256]: ReasonCodeIdV1,
      required_proof: ProofQualityPredicateV1
    }

ProofQualityPredicateV1 {
  source_authority[]: values from ProofQualityV1.source_authority
  local_subject_binding[]: values from ProofQualityV1.local_subject_binding
  remote_subject_binding[]: values from ProofQualityV1.remote_subject_binding
  operation_result_authority[]: values from ProofQualityV1.operation_result_authority
  temporal_coverage[]: COMPLETE | GAPPED | UNKNOWN
  integrity[]: SIGNED | AUTHENTICATED_CHANNEL | LOCAL_ATTESTED | UNVERIFIED
}

FallbackV1 {
  condition: MISSING_TASK_IDENTITY | MISSING_INTENT | AMBIGUOUS_INTENT |
             CLASSIFIER_UNKNOWN |
             CONTROL_PLANE_UNAVAILABLE | RESPONSE_AUTHORITY_UNAVAILABLE |
             MAP_OR_STATE_EXHAUSTED
  requested_disposition: ALLOW | ALERT | DENY | REJECT
  reason_code
  finding?: FindingSpecV1
  response_binding_ids[0..16]: PolicyLocalIdV1
}

BudgetSetDraftUnallocated {
  rate_limits[] { count:u32, per:duration, burst:u32,
                  scope:TASK|ENTRY|EXECUTION_SET|ISSUER|PROVIDER_ACCOUNT,
                  on_exhaustion: ALERT|DENY|REJECT }
  concurrency_limits[] { count:u32, scope, on_exhaustion }
  maximum_lifetime? { duration, on_expiry: ALERT|RESTRICT|SIGNAL|TERMINATE|REJECT_NEW_USE }
  automatic_response_limit? { count:u32, per:duration, scope }
}

BudgetSetV1 {                        // closed Phase 0/Version 1 subset
  rate_limits: exactly []
  concurrency_limits: exactly []
  maximum_lifetime: absent
  automatic_response_limit: absent
}

// The draft token-bucket, concurrency, lifetime, and automatic-response
// shapes are retained requirements, but no atomic counter key, clock/restart
// rule, release tombstone, or object-specific expiry action is allocated in
// the approved phases. A nonempty draft budget therefore returns
// CFG_BUDGET_EXECUTION_UNALLOCATED; it never compiles to an approximate limit.

DefaultPosturesV1 {
  missing_task_identity: DefaultPostureActionV1
  required_classifier_unknown: DefaultPostureActionV1
  missing_entry_intent: DefaultPostureActionV1
}

DefaultPostureActionV1 {
  requested_disposition: ALERT | DENY | REJECT
  finding: FindingSpecV1
  unknown_restricted_role_id?: PolicyLocalIdV1
}

NotificationRouteV1 {
  route_id: PolicyLocalIdV1
  sink: PAGER | CHAT | EMAIL | SIEM | WEBHOOK | TICKET
  sink_binding_id: PolicyLocalIdV1
  minimum_severity: INFO | LOW | MEDIUM | HIGH | CRITICAL
  grouping_fields[1..16]: FindingGroupingFieldV1
  dedupe_window: duration
  allowed_evidence_fields[1..64]: EvidenceFieldV1
  maximum_sensitivity: PUBLIC | INTERNAL | SENSITIVE_IDENTIFIER
  delivery_failure_action: RECORD_ROUTE_FAILURE | ALERT_LOCAL_ONLY
}

FindingGroupingFieldV1 = FINDING_ID | REASON_CODE | PROCESS_LINEAGE_ID |
  AUTHORITY_DOMAIN_ID | EXECUTION_SET_ID | EXACT_OBJECT_ID |
  PROVIDER_PRINCIPAL_ID | PROVIDER_RESOURCE_ID

EvidenceFieldV1 = FINDING_ID | REASON_CODE | DECISION | ERRNO |
  TASK_COOKIE | PROCESS_LINEAGE_ID | AUTHORITY_DOMAIN_ID |
  EXECUTION_SET_ID | EXACT_OBJECT_ID | OBJECT_CLASS_ID |
  DESTINATION_ID | PROVIDER_REQUEST_ID | PROVIDER_RESULT |
  COVERAGE_INTERVAL_IDS | POLICY_RULE_IDS | RESPONSE_RESULT

ProvisionedNotificationSinkBindingV1 { // independent control configuration
  sink_binding_id: PolicyLocalIdV1
  sink_kind: PAGER | CHAT | EMAIL | SIEM | WEBHOOK | TICKET
  endpoint_or_tenant_digest: DigestV1
  protected_credential_handle_id: Id128
  delivery_capability_id: PolicyLocalIdV1
  allowed_maximum_sensitivity: PUBLIC | INTERNAL | SENSITIVE_IDENTIFIER
  health_record_id: Id128
  config_generation: u64
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}

ResponseBindingV1 {
  binding_id: PolicyLocalIdV1
  action_spec: ResponseActionSpecV1
  approval: AUTOMATIC | PREAPPROVED | HUMAN
  required_proof: ProofQualityPredicateV1
  maximum_blast_radius: BlastRadiusLimitV1
  target_revalidation
  physical_postcondition
  watch_interval: duration
}

ResponseActionSpecV1 =
  LOCAL { action: RESTRICT_LINEAGE | FENCE_SOCKETS | FREEZE_CGROUP }
  | KUBERNETES { action: REJECT_REPLACEMENT, admission_capability_id }
  | CREDENTIAL {
      action: REVOKE_CREDENTIAL, provider: ProviderV1,
      credential_kind, actuator_capability_id,
      typed_request_schema_digest: DigestV1
    }
  | MESH {
      action: DISABLE_MESH_DEVICE, provider: ProviderV1,
      actuator_capability_id, typed_request_schema_digest: DigestV1
    }
  | ARTIFACT {
      action: QUARANTINE_ARTIFACT, store_capability_id,
      typed_request_schema_digest: DigestV1
    }
  | SOURCE_CONTROL {
      action: SUSPEND_INSTALLATION, provider: ProviderV1,
      actuator_capability_id, typed_request_schema_digest: DigestV1
    }
  | PROVIDER_SPECIFIC {
      provider: ProviderV1, canonical_action_id: PolicyLocalIdV1,
      actuator_capability_id: PolicyLocalIdV1,
      typed_request_schema_digest: DigestV1
    }

BlastRadiusLimitV1 =
  LOCAL {
    permitted_target_selector_ids[1..64], process_count: u32,
    execution_set_count: u32, socket_count: u32, node_count: u32
  }
  | KUBERNETES {
      permitted_namespace_uids[1..64]: Id128,
      object_count: u32, controller_count: u32, node_count: u32
    }
  | CREDENTIAL {
      permitted_provider_account_ids[1..64], session_count: u32,
      principal_count: u32, role_count: u32, account_count: u32
    }
  | MESH {
      permitted_tailnet_or_tenant_ids[1..64], device_count: u32,
      route_count: u32, auth_key_count: u32
    }
  | SOURCE_CONTROL {
      permitted_organization_ids[1..64], installation_count: u32,
      repository_count: u32, ref_or_pr_count: u32
    }
  | ARTIFACT {
      permitted_store_ids[1..64], artifact_count: u32,
      consumer_count: u32
    }
  | PROVIDER_RESOURCES {
      permitted_provider_account_ids[1..64],
      permitted_resource_selector_ids[1..64], resource_count: u32,
      principal_count: u32
    }

TargetRevalidationV1 =
  PROCESS_PIDFD_TASK_COOKIE_STARTTIME_CGROUP_BINDING
  | LINEAGE_ROOT_AND_COMPLETE_EFFECTIVE_RESPONSE_SET
  | SOCKET_COOKIE_PROVENANCE_AND_LIVE_BINDING
  | CGROUP_FD_NONCE_AND_MEMBER_SET
  | KUBERNETES_UID_RESOURCE_VERSION
  | PROVIDER_STABLE_ID_REVISION_AND_AUTHORITY
  | ARTIFACT_IMMUTABLE_DIGEST_AND_STORE_REVISION

PhysicalPostconditionV1 =
  RESPONSE_SET_INSTALLED_AND_DESCENDANTS_RECONCILED
  | PROCESS_STOPPED_VIA_PIDFD
  | SOCKET_SET_FENCED_AND_EXISTING_FLOW_ORACLE_PASSED
  | CGROUP_FROZEN_AND_PACKET_FENCE_ACTIVE
  | REPLACEMENT_REJECTED_THROUGH_WATCH_WATERMARK
  | PROVIDER_CREDENTIAL_ACTION_READ_BACK
  | MESH_DEVICE_DISABLED_AND_HANDSHAKE_REJECTED
  | ARTIFACT_QUARANTINED_AND_CONSUMER_LOAD_REJECTED
  | PROVIDER_OPERATION_SPECIFIC_POSTCONDITION

RolloutV1 {
  rollout_generation: u64 > 0
  desired_profile_mode: OBSERVE | PROTECT
  cohort_selection: ALL_BOUND_EXECUTION_SETS | EXPLICIT_EXECUTION_SETS |
                    HASHED_EXECUTION_SET_BINDING
  explicit_execution_set_ids[]
  selector_hash_modulus: u32 > 0
  selected_bucket_ids[]: sorted unique u32 values < selector_hash_modulus
}
```

`SignedWorkloadBindingGenerationDraftAbandoned` mixed mutable activation state
into a signed payload; changing `PREPARING -> ACTIVE` would invalidate its
digest. The immutable artifact plus local activation record above replaces it.
The binding-signature mutation case changes only the old state byte while retaining the
signature and must fail verification; the canonical transition changes only
`WorkloadBindingActivationStateV1` after full map readback.

Classifier resolution happens before activation, never lazily in a deciding
hook. For example, the selector
`PROJECTED_SERVICE_ACCOUNT_TOKEN{hf-conversion-workers, sa_uid_7}` resolves the
Pod's projected-volume mount, follows every AtomicWriter revision to exact
inode/mount generations, and emits one `ResolvedObjectClassBindingV1` with
class `PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN`. The destination record
`kubernetes-api-prod` resolves both IPv4 and IPv6 endpoints plus ports and the
network-namespace generation. A missing axis, overlapping records that assign
different classes, an endpoint-registry rotation not yet bound, or a selector
registry digest different from profile-header key 13 keeps the binding
`PREPARING`; it never chooses the first match.

All five registry digests in profile-header keys 13–17 are SHA-256 over
`ASCII("MITHRIL-<REGISTRY-NAME>-V1") || 0x00 || deterministic_cbor(closed
registry payload without its digest/signature fields)`. Exact domain strings
are respectively `SOURCE-SELECTOR`, `OBJECT-CLASSIFIER`, `REASON-CODE`,
`CORRELATION-PACKAGE`, and `PROVIDER-VOCABULARY`. Swapping a reason, package,
destination, or provider numeric vocabulary while reusing a signed policy
therefore fails header verification instead of silently changing its meaning.

##### Abandoned configuration fields and their exact replacements

- `FallbackV1.condition=SOURCE_UNAVAILABLE` is abandoned. A rule cannot match
  an event that did not arrive. `SourceCoverageHealthRuleV1` below owns a
  synthetic coverage observation and its independent fence/admission result.
- The earlier `RolloutV1.mode` and scalar `selected_buckets` are abandoned.
  They did not distinguish desired enforcement mode from cohort selection or
  say which buckets were selected. The closed record above replaces both.
- An optional `finding` is legal only for a pure `ALLOW` with no notification
  or response. `ALERT`, `DENY`, and `REJECT`, or any nonempty route/response
  list, require `finding`; a denial always persists its reason even if route
  delivery fails.
- A source `CompiledActionPlanV1.post_effect_action` or singular
  `response_binding_id` is abandoned. The corrected nonempty action set and
  sorted unique `response_binding_ids[]` allow the common
  `FINDING + RESPONSE_PROPOSAL` result without inventing order.

Default/entry compatibility is closed:

| Condition | Legal action | Additional requirement |
| --- | --- | --- |
| missing protected task identity | `ALERT` only if the task is admitted into a named unknown-restricted role; otherwise `DENY` | finding always required; never `REJECT` after the task already runs |
| required classifier unknown | `ALERT` only when the matched effect family has an explicit safe unknown floor; otherwise `DENY` | finding always required |
| missing entry intent before a held runtime root starts | `REJECT`, or `ALERT` plus `ADMIT_UNKNOWN_RESTRICTED_AND_ALERT` | alert path requires `unknown_restricted_role_id` and successful label readback before resume |
| `EntryRoleAssignmentV1.on_missing_or_unequal_ambiguity=REJECT` | reject at held entry | `unknown_restricted_role_id` forbidden |
| `...=ADMIT_UNKNOWN_RESTRICTED_AND_ALERT` | admit only the named restricted role | `unknown_restricted_role_id` required and must have no authority-increasing transition |

Any mismatch is `CFG_DEFAULT_STAGE_MISMATCH`; an `ALERT` with no physical
unknown-role/default floor is not a rollout mode but an unsafe allow.

```text
SourceCoverageHealthRuleV1 {
  health_rule_id
  required_source_id
  protected_scope_ids[1..64]
  maximum_gap: duration
  on_gap: ALERT | REJECT_NEW_ADMISSION | INSTALL_INDEPENDENT_FENCE
  finding: required FindingSpecV1
  independent_admission_gate_binding_id?: PolicyLocalIdV1
  independent_admission_capability_id?: PolicyLocalIdV1
  independent_response_binding_ids[]
}
```

`INSTALL_INDEPENDENT_FENCE` compiles only when the response boundary does not
depend on the missing source. For example, loss of Kubernetes audit may alert
and make new privileged-Pod admission reject through a separately healthy
runtime gate; it cannot claim to reconstruct the missing audit event.

`REJECT_NEW_ADMISSION` requires both independent admission fields, verifies
that the gate-health source is distinct from `required_source_id`, and reads
back the installed rejection before reporting success. The fields are
forbidden for `ALERT`. `INSTALL_INDEPENDENT_FENCE` requires a nonempty response
list whose actuator and postcondition sources do not depend on the failed
source. Otherwise compilation returns
`CFG_COVERAGE_RESPONSE_NOT_INDEPENDENT`.

Field cardinality is not inferred from `[]` syntax:

| Field class | Omitted | Present empty | Present nonempty |
| --- | --- | --- | --- |
| `CommonSubjectMatchV1` optional selector | Expand the corresponding finite `protected_universe` dimension | `CFG_EMPTY_SELECTOR` | Unique known IDs; compiler expands exact Cartesian keys |
| Rule `operations`, `object_values`, entry intent/status, remote operation/resource lists | Not optional unless the specific schema marks it optional | `CFG_EMPTY_REQUIRED_MATCH` | `1..256`, unique and sorted after canonicalization |
| `process_state_required_bits` / `process_state_forbidden_bits` | Equivalent to empty | Legal empty set | Unique closed bit IDs; overlap is `CFG_STATE_BIT_CONTRADICTION` |
| `protected_universe` provider-account dimension | Legal only when no enabled rule/response/provider object consumes that dimension | Legal and signed as “this profile has no provider account universe” | Finite IDs; an enabled provider rule must bind at least one |
| `exceptions`, `response_binding_ids`, notification routes, budget lists, attestation digests | Use the field's documented empty default | Legal empty set/list | Bounded by the signed schema |
| Every `ProofQualityPredicateV1` axis | Forbidden | Forbidden | At least one closed value for all six axes; `NONE`/`UNKNOWN` must be encoded when that is the required quality |

Each source `operations[]` member expands to a **separate exact compiled key**.
The compiler may use a bitset as an internal storage optimization only when
the compiled manifest still enumerates each operation/capability/result cell
and the physical hook can produce the same result. `OPEN_READ` and `READ` are
never one logical operation.

Response pairs are compiled from a closed compatibility table. At minimum:

| Action | Permitted revalidation | Required postcondition family |
| --- | --- | --- |
| `RESTRICT_LINEAGE` | process or lineage-root variant | response set installed plus descendant reconciliation |
| `FENCE_SOCKETS` | socket-cookie variant; lineage variant only when every socket is enumerated | socket fence plus existing-flow oracle |
| `FREEZE_CGROUP` | cgroup-fd variant | frozen member-set and packet-fence readback |
| `REJECT_REPLACEMENT` | Kubernetes UID/resourceVersion | watch through authoritative watermark |
| credential/mesh/provider-specific | provider stable ID/revision/authority | action-specific provider readback/canary; absence is a compile error |
| `QUARANTINE_ARTIFACT` | immutable artifact/store revision | quarantine readback and consumer load rejection |

An arbitrary string in either response field is `CFG_UNKNOWN_ENUM_VALUE`; an
incompatible pair is `CFG_RESPONSE_POSTCONDITION_MISMATCH`.

All source rule families lower through one ordered pipeline; none silently
wins because it appears later in YAML:

1. bind the signed selector/classifier registries to exact workload/object
   generations;
2. validate the complete role/process-state graph and reject unreachable or
   cyclic authority-increasing transitions;
3. lower entry assignments, native transitions, effect-family defaults, and
   authority rules into `NormalizedDecisionCellV1` values with stable cell IDs;
4. overlay `DetectionDispositionRuleV1` only through an exact key and an
   explicit `overrides_rule_ids` edge to the source cell/rule it replaces;
5. compare the **whole** cell, then emit the immutable generation.

```text
NormalizedDecisionCellV1 {
  cell_id: PolicyLocalIdV1
  exact_compiled_key
  physical_result
  transition_descriptor?
  finding_specs[]
  response_binding_ids[]
  budget_semantics
  source_rule_ids[]
}
```

Two rules with the same exact key are mergeable only when physical result,
errno, complete transition tuple, findings, responses, and budget semantics
are byte-identical. A separately specified monotonic domain-union compiler may
produce one new reviewed transition; ordinary merging may not. Otherwise the
compiler returns `CFG_EXACT_CELL_CONFLICT`, even when both rows say `ALLOW`.
`priority` controls display/notification order only and never resolves an
authority conflict. Goldens include same-allow/different-target-role,
same-deny/different-on-deny-transition, default-versus-rule, and native-rule-
versus-generic-transition conflicts.

Empty selector lists are rejected as `CFG_EMPTY_SELECTOR`; they never mean
wildcard. Omitting an optional selector means the whole finite set from
`protected_universe`, which the compiler expands and records. The compiler
rejects a rule with no reachable exact key, an operation absent from its effect
family vocabulary, a proof predicate with an empty required axis, a fallback
whose disposition is illegal at the rule's stage, or any conflict without the
explicit signed override/exception contract.

The retained first sentence applies only to an optional **selector/match
dimension** that is present. It does not apply to empty state-bit sets, budget
lists, exceptions, response bindings, attestation lists, or an unused
provider-account universe. The cardinality table above controls every field;
there is no blanket “all empty arrays invalid” rule.

Universe expansion has two explicit stages:

```text
StaticExpandedProfileV1 {
  profile_id
  profile_version
  source_policy_digest
  statically_expanded_workload_selector_ids[]
  statically_expanded_protected_scope_ids[]
  statically_expanded_role_ids[]
  statically_expanded_entry_kind_ids[]
  statically_expanded_object_class_ids[]
  statically_expanded_provider_account_ids[]
  unresolved_binding_selectors[]       // protected/execution-set dimensions only
  compiled_rule_cell_digests[]
  rollout: RolloutV1
}

NodeBoundProfileGenerationV1 {
  static_profile_digest
  signed_workload_binding_generation
  node_boot_id
  label_epoch
  exact_protected_scope_ids[]
  exact_execution_set_ids[]
  exact_rollout_membership[]
  exact_compiled_kernel_cell_digests[]
  node_binding_digest
  state: PREPARING | READ_BACK | ACTIVE | REJECTED
}
```

The static compiler expands workload, role, entry, object, provider, operation,
and proof dimensions only against the signed finite `protected_universe`.
`protected_scope_ids` and `execution_set_ids` may additionally contain
bind-time selectors because their exact live IDs do not exist at authoring
time. The node binder resolves those selectors only against one signed
`signed_workload_binding_generation`; it emits an immutable
`NodeBoundProfileGenerationV1`, installs every exact row, reads it back, and
only then activates. A later Pod or execution set creates a new node-bound
generation; it never mutates the active key set in place.

Hashed rollout membership is:

```text
bucket = first_u64_be(
  sha256("MITHRIL-ROLLOUT-V1" ||
         canonical(profile_id) ||
         u64be(profile_version) ||
         u64be(rollout.rollout_generation) ||
         execution_set_id.bytes ||
         signed_workload_binding_generation.digest.bytes))
  mod rollout.selector_hash_modulus
selected = bucket in rollout.selected_bucket_ids
```

`ALL_BOUND_EXECUTION_SETS` requires empty explicit IDs and selects every bound
set. `EXPLICIT_EXECUTION_SETS` requires a nonempty exact subset and ignores the
hash fields. `HASHED_EXECUTION_SET_BINDING` requires empty explicit IDs, a
nonempty bucket set, and the formula above. Invalid combinations fail with
`CFG_ROLLOUT_FIELD_CONFLICT`; an undefined `rollout_generation` is impossible.

This is a complete valid source document using only Version 1 fields:

```yaml
api_version: mithril.erebor.dev/v1
kind: ProtectionPolicy
metadata:
  profile_id: hf-conversion-worker
  profile_version: 9
  trust_domain_id: hf-production
  valid_from_utc: "2026-08-01T00:00:00Z"
required_capability_ids:
  - cap.bpf_lsm.file_open.v1
  - cap.runtime.held_entry.v1
protected_universe:
  workload_selector_ids: [hf-conversion-workers]
  role_ids: [conversion-worker-root]
  entry_kind_ids: [CONTAINER_START]
  object_class_ids: [PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN]
  provider_account_ids: []
default_postures:
  missing_task_identity: DENY
  required_classifier_unknown: DENY
  missing_entry_intent: REJECT
notification_routes:
  - route_id: defender-stream
    sink: SIEM
    minimum_severity: HIGH
    grouping_fields: [finding_id, process_lineage_id, object_id]
    dedupe_window: 15s
    allowed_evidence_fields:
      - finding_id
      - process_lineage_id
      - object_id
      - decision
      - coverage_interval_ids
    maximum_sensitivity: SENSITIVE_IDENTIFIER
    delivery_failure_action: RECORD_ROUTE_FAILURE
response_bindings:
  - binding_id: restrict-worker
    action: RESTRICT_LINEAGE
    approval: PREAPPROVED
    required_proof:
      local_subject_binding: [EXACT_PROCESS]
      temporal_coverage: [COMPLETE]
    maximum_blast_radius:
      process_count: 32
      execution_set_count: 1
    target_revalidation: PIDFD_TASK_COOKIE_AND_CGROUP_BINDING
    physical_postcondition: RESPONSE_SET_INSTALLED_AND_DESCENDANTS_RECONCILED
    watch_interval: 5m
exceptions: []
rules:
  - schema_version: 1
    rule_id: deny-worker-projected-token-open
    enabled: true
    evaluation_stage: LOCAL_PRE_EFFECT
    match:
      kind: LOCAL_EFFECT
      subject:
        workload_selector_ids: [hf-conversion-workers]
        entry_kind_ids: [CONTAINER_START]
        role_ids: [conversion-worker-root]
        process_state_required_bits: []
        process_state_forbidden_bits: []
      effect_family: FILE
      operations: [OPEN_READ, READ]
      object_selector: OBJECT_CLASSES
      object_values: [PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN]
      required_proof:
        source_authority: [KERNEL_DECISION]
        local_subject_binding: [EXACT_TASK]
        remote_subject_binding: [NONE]
        operation_result_authority: [PRE_EFFECT_DECISION]
        temporal_coverage: [COMPLETE]
        integrity: [LOCAL_ATTESTED]
    requested_disposition: DENY
    errno: EACCES
    finding:
      reason_code: WORKER_PROJECTED_TOKEN_OPEN_DENIED
      severity: CRITICAL
      route_ids: [defender-stream]
      evidence_level: STANDARD
    response_binding_ids: [restrict-worker]
    fallback_by_condition:
      - condition: MISSING_TASK_IDENTITY
        requested_disposition: DENY
        reason_code: PROTECTED_TASK_IDENTITY_MISSING
      - condition: CLASSIFIER_UNKNOWN
        requested_disposition: DENY
        reason_code: REQUIRED_FILE_CLASSIFIER_UNKNOWN
      - condition: MAP_OR_STATE_EXHAUSTED
        requested_disposition: DENY
        reason_code: REQUIRED_STATE_UNAVAILABLE
    budgets:
      rate_limits: []
      concurrency_limits: []
    overrides_rule_ids: []
    exception_ids: []
rollout:
  mode: PROTECT
  selector_hash_modulus: 10000
  selected_buckets: 10000
```

At compile time the profile binder resolves `hf-conversion-workers` to exact
live protected scopes and expands the omitted execution-set dimension inside
that bound universe. A parser implementation rejects an empty selector array
rather than interpreting it as `*`; the compiler's normalized explanation
names every dimension that came from the bound universe.

The golden compiler result for the rule is one key per bound token object and
operation:

```text
stage = LOCAL_PRE_EFFECT
key = (profile_generation_9, conversion-worker-root, CONTAINER_START,
       FILE, OPEN_READ|READ,
       PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN, state_set)
physical_result = DENY_ERRNO(EACCES)
post_effect_action = FINDING + RESPONSE_PROPOSAL(restrict-worker)
required_capability_ids = [cap.bpf_lsm.file_open.v1 plus the READ-path capability]
source_rule_ids = [deny-worker-projected-token-open]
```

##### Abandoned design: the retained “complete valid” source and combined key

Calling the retained YAML complete/valid is wrong. Its response proof omits
four required axes; `target_revalidation` and `physical_postcondition` were
undefined at that point; it requests both `OPEN_READ` and `READ` while
declaring only `cap.bpf_lsm.file_open.v1`; and its golden output combines two
logical operations into `OPEN_READ|READ`. That interpretation and output are
abandoned.

###### Abandoned design: construct a golden input by applying prose substitutions

The next fragment is retained as review history, but calling a document built
by substitutions a golden fixture is abandoned. A test cannot hash “the
earlier document with these edits,” and later schema corrections can make the
base silently invalid. Its final sentence—“the standalone source after this
fragment is canonical”—is now also abandoned for the reason recorded at that
fragment.

The draft correction used these substitutions:

```yaml
# required_capability_ids remains open-only for this example:
required_capability_ids:
  - cap.bpf_lsm.file_open.v1
  - cap.runtime.held_entry.v1

response_bindings:
  - binding_id: restrict-worker
    action: RESTRICT_LINEAGE
    approval: PREAPPROVED
    required_proof:
      source_authority: [KERNEL_DECISION]
      local_subject_binding: [EXACT_PROCESS]
      remote_subject_binding: [NONE]
      operation_result_authority: [PRE_EFFECT_DECISION]
      temporal_coverage: [COMPLETE]
      integrity: [LOCAL_ATTESTED]
    maximum_blast_radius:
      process_count: 32
      execution_set_count: 1
    target_revalidation: PROCESS_PIDFD_TASK_COOKIE_STARTTIME_CGROUP_BINDING
    physical_postcondition: RESPONSE_SET_INSTALLED_AND_DESCENDANTS_RECONCILED
    watch_interval: 5m

# inside deny-worker-projected-token-open:
match:
  kind: LOCAL_EFFECT
  subject:
    workload_selector_ids: [hf-conversion-workers]
    entry_kind_ids: [CONTAINER_START]
    role_ids: [conversion-worker-root]
    process_state_required_bits: []
    process_state_forbidden_bits: []
  effect_family: FILE
  operations: [OPEN_READ]
  object_selector: OBJECT_CLASSES
  object_values: [PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN]
  required_proof:
    source_authority: [KERNEL_DECISION]
    local_subject_binding: [EXACT_TASK]
    remote_subject_binding: [NONE]
    operation_result_authority: [PRE_EFFECT_DECISION]
    temporal_coverage: [COMPLETE]
    integrity: [LOCAL_ATTESTED]
```

All omitted YAML fields are exactly the retained values. Its normative
compiler output is one open key:

```text
key = (profile_generation_9, conversion-worker-root, CONTAINER_START,
       FILE, OPEN_READ,
       PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN, state_set)
physical_result = DENY_ERRNO(EACCES)
required_capability_ids = [cap.bpf_lsm.file_open.v1]
```

This proves descriptor-acquisition prevention only. A profile that also
advertises already-open/passed/inherited-fd `READ` adds a separate rule,
separate `READ` key, and an exact target-qualified read-use capability ID from
the file bypass matrix. If that capability is absent, `READ` compilation fails
with `CFG_REQUIRED_CAPABILITY_MISSING`; it is never inferred from
`file_open`.

###### Abandoned design: stale standalone `CFG-V1-GOLDEN-001` source and vector

This retained source and every byte/digest/signature below predate mandatory
workload selectors, classifier bindings, roles, entry assignments, process
states, effect defaults, authority/correlation/coverage lists, structured
default postures, tagged object selectors, the renamed rollout selector, and
profile-header registry digests 13–17. It also uses the obsolete
`object_selector + object_values` shape. It therefore does **not** parse as the
closed `PolicyDocumentV1`, and its length, CBOR, hashes, signature, and envelope
must never be used as a conformance oracle.

Phase 0 replaces it atomically with `CFG-V1-GOLDEN-002`: one checked-in complete
YAML file, canonical CBOR, all registry payloads/digests, signed header,
signature, and envelope generated by the same repository tool invocation. The
generator first parses the source against the final Rust closed types, then
re-parses canonical CBOR, verifies every reference and registry digest,
compiles the exact `OPEN_READ` cell, and only then writes the golden. A missing
newly mandatory field must fail as `CFG_REQUIRED_FIELD_MISSING`. Until those
artifacts exist, configuration-schema implementation may proceed, but the
Phase 0 configuration-golden exit criterion is `NOT DONE`.

The old text claimed this exact UTF-8 source—starting with `api_version` and ending with the final
newline after `selected_bucket_ids: []`—is the fixture input. It uses no
response binding so the golden stays focused on parsing, exact expansion, and
a physical file-open denial. In the real workload this means: the protected
conversion execution set cannot open its projected Kubernetes ServiceAccount
token, and the denial persists a local finding. Ordinary dataset files are
governed by separate rules.

```yaml
api_version: mithril.erebor.dev/v1
kind: ProtectionPolicy
metadata:
  profile_id: 33333333-3333-3333-3333-333333333333
  profile_version: 9
  trust_domain_id: 22222222-2222-2222-2222-222222222222
  valid_from_utc: "2026-08-01T00:00:00Z"
required_capability_ids:
  - cap.bpf_lsm.file_open.v1
  - cap.runtime.held_entry.v1
protected_universe:
  workload_selector_ids: [hf-conversion-workers]
  protected_scope_ids: [hf-production-converters]
  execution_set_ids: [hf-converter-execution-set-1]
  role_ids: [conversion-worker-root]
  entry_kind_ids: [CONTAINER_START]
  object_class_ids: [PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN]
  provider_account_ids: []
default_postures:
  missing_task_identity: DENY
  required_classifier_unknown: DENY
  missing_entry_intent: REJECT
notification_routes: []
response_bindings: []
exceptions: []
rules:
  - schema_version: 1
    rule_id: deny-worker-projected-token-open
    enabled: true
    evaluation_stage: LOCAL_PRE_EFFECT
    match:
      kind: LOCAL_EFFECT
      subject:
        workload_selector_ids: [hf-conversion-workers]
        protected_scope_ids: [hf-production-converters]
        execution_set_ids: [hf-converter-execution-set-1]
        entry_kind_ids: [CONTAINER_START]
        role_ids: [conversion-worker-root]
        process_state_required_bits: []
        process_state_forbidden_bits: []
      effect_family: FILE
      operations: [OPEN_READ]
      object_selector: OBJECT_CLASSES
      object_values: [PROJECTED_KUBERNETES_SERVICEACCOUNT_TOKEN]
      required_proof:
        source_authority: [KERNEL_DECISION]
        local_subject_binding: [EXACT_TASK]
        remote_subject_binding: [NONE]
        operation_result_authority: [PRE_EFFECT_DECISION]
        temporal_coverage: [COMPLETE]
        integrity: [LOCAL_ATTESTED]
    requested_disposition: DENY
    errno: EACCES
    finding:
      reason_code: WORKER_PROJECTED_TOKEN_OPEN_DENIED
      severity: CRITICAL
      route_ids: []
      evidence_level: STANDARD
    response_binding_ids: []
    fallback_by_condition:
      - condition: MISSING_TASK_IDENTITY
        requested_disposition: DENY
        reason_code: PROTECTED_TASK_IDENTITY_MISSING
      - condition: CLASSIFIER_UNKNOWN
        requested_disposition: DENY
        reason_code: REQUIRED_FILE_CLASSIFIER_UNKNOWN
      - condition: MAP_OR_STATE_EXHAUSTED
        requested_disposition: DENY
        reason_code: REQUIRED_STATE_UNAVAILABLE
    budgets:
      rate_limits: []
      concurrency_limits: []
    overrides_rule_ids: []
    exception_ids: []
rollout:
  rollout_generation: 1
  desired_profile_mode: PROTECT
  cohort_selection: ALL_BOUND_EXECUTION_SETS
  explicit_execution_set_ids: []
  selector_hash_modulus: 1
  selected_bucket_ids: []
```

The parser normalizes UUID strings to 16-byte `Id128` values only in typed ID
fields; symbolic selector IDs remain bounded UTF-8 bytes. `PolicyDocumentV1`
uses deterministic CBOR with UTF-8 field names as keys, definite lengths,
shortest integers, and RFC 8949 deterministic map ordering. Phase 0 checks in
the source, canonical policy bytes, header bytes, signature, and envelope under
`spec/policy/v1/golden/CFG-V1-GOLDEN-001/`. The exact digest and signature
vector below makes that future file independently reproducible.

For this vector, `DigestV1={0:1,1:bstr(32)}` where algorithm `1` is SHA-256.
The provider-registry digest preimage is the exact ASCII string
`MITHRIL-EMPTY-PROVIDER-REGISTRY-V1`. The capability-schema digest preimage is
the exact UTF-8 text
`MITHRIL-CAPABILITY-SCHEMA-V1:cap.bpf_lsm.file_open.v1\ncap.runtime.held_entry.v1\n`.
The test issuer ID is byte `0x11` repeated 16 times, sequence epoch/sequence
are both 1, and the Ed25519 seed/key ID are the public test values already
defined by the intent golden. In the multiline hex value, concatenate lines
without whitespace:

```text
source_utf8_length = 2727
source_sha256 = d061d3ac9b1e56665ac78be334b2b4bd1ab846a39d008e469f3c8dcf68779d26
canonical_policy_cbor_length = 2233
canonical_policy_cbor_hex =
ab646b696e647050726f74656374696f6e506f6c6963796572756c657381ad656572726e6f66454143434553656d6174
6368a7646b696e646c4c4f43414c5f454646454354677375626a656374a768726f6c655f6964738176636f6e76657273
696f6e2d776f726b65722d726f6f746e656e7472795f6b696e645f696473816f434f4e5441494e45525f535441525471
657865637574696f6e5f7365745f69647381781c68662d636f6e7665727465722d657865637574696f6e2d7365742d31
7370726f7465637465645f73636f70655f69647381781868662d70726f64756374696f6e2d636f6e7665727465727375
776f726b6c6f61645f73656c6563746f725f696473817568662d636f6e76657273696f6e2d776f726b657273781b7072
6f636573735f73746174655f72657175697265645f6269747380781c70726f636573735f73746174655f666f72626964
64656e5f62697473806a6f7065726174696f6e7381694f50454e5f524541446d6566666563745f66616d696c79644649
4c456d6f626a6563745f76616c75657381782950524f4a45435445445f4b554245524e455445535f5345525649434541
43434f554e545f544f4b454e6e72657175697265645f70726f6f66a669696e74656772697479816e4c4f43414c5f4154
54455354454470736f757263655f617574686f72697479816f4b45524e454c5f4445434953494f4e7174656d706f7261
6c5f636f7665726167658168434f4d504c455445756c6f63616c5f7375626a6563745f62696e64696e67816a45584143
545f5441534b7672656d6f74655f7375626a6563745f62696e64696e6781644e4f4e45781a6f7065726174696f6e5f72
6573756c745f617574686f7269747981735052455f4546464543545f4445434953494f4e6f6f626a6563745f73656c65
63746f726e4f424a4543545f434c41535345536762756467657473a26b726174655f6c696d6974738072636f6e637572
72656e63795f6c696d6974738067656e61626c6564f56766696e64696e67a46873657665726974796843524954494341
4c69726f7574655f696473806b726561736f6e5f636f64657822574f524b45525f50524f4a45435445445f544f4b454e
5f4f50454e5f44454e4945446e65766964656e63655f6c6576656c685354414e444152446772756c655f696478206465
6e792d776f726b65722d70726f6a65637465642d746f6b656e2d6f70656e6d657863657074696f6e5f696473806e7363
68656d615f76657273696f6e01706576616c756174696f6e5f7374616765704c4f43414c5f5052455f45464645435472
6f76657272696465735f72756c655f6964738074726573706f6e73655f62696e64696e675f696473807566616c6c6261
636b5f62795f636f6e646974696f6e83a369636f6e646974696f6e754d495353494e475f5441534b5f4944454e544954
596b726561736f6e5f636f6465781f50524f5445435445445f5441534b5f4944454e544954595f4d495353494e477572
65717565737465645f646973706f736974696f6e6444454e59a369636f6e646974696f6e72434c41535349464945525f
554e4b4e4f574e6b726561736f6e5f636f6465782052455155495245445f46494c455f434c41535349464945525f554e
4b4e4f574e757265717565737465645f646973706f736974696f6e6444454e59a369636f6e646974696f6e764d41505f
4f525f53544154455f4558484155535445446b726561736f6e5f636f6465781a52455155495245445f53544154455f55
4e415641494c41424c45757265717565737465645f646973706f736974696f6e6444454e59757265717565737465645f
646973706f736974696f6e6444454e5967726f6c6c6f7574a66b636f686f72745f6d6f64657818414c4c5f424f554e44
5f455845435554494f4e5f5345545372726f6c6c6f75745f67656e65726174696f6e017373656c65637465645f627563
6b65745f6964738074646573697265645f70726f66696c655f6d6f64656750524f544543547573656c6563746f725f68
6173685f6d6f64756c757301781a6578706c696369745f657865637574696f6e5f7365745f69647380686d6574616461
7461a46a70726f66696c655f696450333333333333333333333333333333336e76616c69645f66726f6d5f7574637432
3032362d30382d30315430303a30303a30305a6f70726f66696c655f76657273696f6e096f74727573745f646f6d6169
6e5f696450222222222222222222222222222222226a657863657074696f6e73806b6170695f76657273696f6e756d69
746872696c2e657265626f722e6465762f76317064656661756c745f706f737475726573a3746d697373696e675f656e
7472795f696e74656e746652454a454354756d697373696e675f7461736b5f6964656e746974796444454e59781b7265
7175697265645f636c61737369666965725f756e6b6e6f776e6444454e5971726573706f6e73655f62696e64696e6773
807270726f7465637465645f756e697665727365a768726f6c655f6964738176636f6e76657273696f6e2d776f726b65
722d726f6f746e656e7472795f6b696e645f696473816f434f4e5441494e45525f5354415254706f626a6563745f636c
6173735f69647381782950524f4a45435445445f4b554245524e455445535f534552564943454143434f554e545f544f
4b454e71657865637574696f6e5f7365745f69647381781c68662d636f6e7665727465722d657865637574696f6e2d73
65742d317370726f7465637465645f73636f70655f69647381781868662d70726f64756374696f6e2d636f6e76657274
6572737470726f76696465725f6163636f756e745f6964738075776f726b6c6f61645f73656c6563746f725f69647381
7568662d636f6e76657273696f6e2d776f726b657273736e6f74696669636174696f6e5f726f75746573807772657175
697265645f6361706162696c6974795f6964738278186361702e6270665f6c736d2e66696c655f6f70656e2e76317819
6361702e72756e74696d652e68656c645f656e7472792e7631

policy_sha256 = 95ab9918887ff65f18fb8de93580862764762dc7a9ee124c7df3d96b60e41ecd
provider_registry_sha256 = 424d5f9a14067d84ce1d177c28975bfc9b7690a68a2f7afaba71ecb88e11d372
capability_schema_sha256 = 758695f4c4f07d301625337f6c5eaa82e44fa51cd58fa495ed897d1dc9573041
canonical_header_cbor_length = 190
canonical_header_cbor_hex =
ab0001015011111111111111111111111111111111020103010450222222222222222222222222222222220550333333333333333333333333333333330609071b18c7855a436600000aa2000101582095ab9918887ff65f18fb8de93580862764762dc7a9ee124c7df3d96b60e41ecd0ba20001015820424d5f9a14067d84ce1d177c28975bfc9b7690a68a2f7afaba71ecb88e11d3720ca20001015820758695f4c4f07d301625337f6c5eaa82e44fa51cd58fa495ed897d1dc9573041
header_sha256 = d680d29964d34c25e09a0259244b92fb7dbe6a70a6911d62155a93c9781d1599
signature_input_hex =
4d49544852494c2d50524f46494c452d563100d680d29964d34c25e09a0259244b92fb7dbe6a70a6911d62155a93c9781d159995ab9918887ff65f18fb8de93580862764762dc7a9ee124c7df3d96b60e41ecd
ed25519_signature =
2dbc600322bccfd75cbbecb2607cd47a649b6e300326023ec65e677ce6efe243199c56abd651038d9bced8821928311699c6a9613c12449ffb3c8ed0a7dfdc0f
signed_envelope_length = 2518
signed_envelope_sha256 = 184b1875a4b07f4184c2ec6fe464bb80bdee394b72f0615675acbd3b5d1f41b8
```

The exact envelope bytes are mechanically unique from the already closed
`SignedWorkloadProtectionProfileV1` constructor and the policy/header/signature
bytes above; implementations must emit length 2518 and the stated digest.
Changing source bytes alone does not change policy semantics after parse, but
this source-file golden intentionally checks both the raw source digest and the
typed canonical payload.

Parser/compiler golden failures are stable API:

| Retained/hostile fragment | Exact diagnostic |
| --- | --- |
| duplicate `default_postures` or duplicate rule key | `CFG_DUPLICATE_KEY` with canonical path and both source locations |
| `sourceQualityAtLeast` or `intentStrengthAtLeast` | `CFG_UNKNOWN_FIELD`; if accepted only by the legacy-sketch importer, it emits `SCALAR_PROOF_QUALITY_UNSUPPORTED` and no profile |
| `attestation: verified` | `CFG_UNKNOWN_FIELD`; use the complete attestation predicate fields |
| `evaluation_stage: POST_EFFECT` plus `DENY`/`REJECT` | `CFG_DISPOSITION_STAGE_MISMATCH` |
| `LOCAL_PRE_EFFECT` plus `REJECT` | `CFG_DISPOSITION_STAGE_MISMATCH` |
| finding `UNAPPROVED_RUNTIME_ENTRY` used to decide the same entry | `CFG_CIRCULAR_DECISION_DEPENDENCY` |
| GitHub audit-only token-mint match without a source capability | `CFG_REQUIRED_SOURCE_UNSUPPORTED` |
| two different physical results on one expanded key without a signed edge | `CFG_EXACT_KEY_CONFLICT` naming both rule IDs and key |
| exception wildcard, missing expiry/approver, or hard-invariant target | `CFG_INVALID_EXCEPTION_SCOPE` |
| bare `maxLifetime` | `CFG_EXPIRY_ACTION_REQUIRED` |
| notification field with `SECRET` sensitivity or unknown field | `CFG_NOTIFICATION_FIELD_FORBIDDEN` |
| unknown enum casing such as `local-pre-effect` | `CFG_UNKNOWN_ENUM_VALUE` |
| anchor, alias, merge key, custom tag, implicit timestamp, or noncanonical scalar | `CFG_YAML_FEATURE_FORBIDDEN` |

`CFG-V1-GOLDEN-001`, the valid-document golden test, parses, canonicalizes,
signs, compiles, and
round-trips to the byte-identical deterministic-CBOR payload. Every invalid
row asserts no generation, inactive map, admission slot, or response binding
becomes visible.

#### One detection evaluated in four configurations

Assume the exact `conversion-worker-root` task opens the projected token:

| Configuration | Kernel result | Finding result | What the operator sees |
| --- | --- | --- | --- |
| `allow` | `open(2)` succeeds | No finding unless evidence sampling is enabled | Normal workload evidence only |
| `alert` | `open(2)` succeeds | `HF-PROC-001` is persisted and routed | Alert explicitly says `semantic_effect_completed` |
| `deny` | `open(2)` returns `EACCES` before bytes are read | Denial finding is persisted and optionally paged | Alert says `prevented`, with hook and errno proof |
| `reject` | Compiler error for this match | No generation is activated | Compiler explains that file effects support `deny`, not entry rejection |

##### Correct result wording for the file example

The retained `alert` cell's phrase `semantic_effect_completed` is too strong.
An LSM allow proves permission; an exact syscall-exit observation can prove an
`open(2)` returned a descriptor; neither proves positive secret bytes were
read. Version 1 reports one of:

- `FILE_ACCESS_ATTEMPT_ALLOWED` from the pre-effect decision;
- `FILE_DESCRIPTOR_OPENED` only from an exact positive open result;
- `SENSITIVE_BYTES_READ` only from the fully qualified post-read coverage
  described earlier; or
- `FILE_OPEN_PREVENTED` from a pre-effect denial plus negative syscall result.

The denial prevents this attempted descriptor acquisition, not access through
an already-open/inherited descriptor or secret bytes already in memory. The
finding states those coverage limits explicitly.

Now assume an unapproved `kubectl exec` request:

| Configuration | Admission result | Meaning |
| --- | --- | --- |
| `allow` | Runtime root is admitted with the explicitly configured administrative role | The process still receives that role's effect limits |
| `alert` | Root is admitted and a finding is routed | Useful during rollout, but not prevention |
| `deny` | Compiler error at this semantic entry boundary | Configure `reject`; a syscall deny may still happen later but is a weaker lifecycle result |
| `reject` | Runtime/CRI admission returns a typed rejection before the user command starts | Correct physical prevention for an entry request |

#### Rollout and exceptions

Every rule can be simulated and rolled out without silently changing its
meaning:

```yaml
rollout:
  phase: observe            # simulate deny/reject, physically allow, alert
  selectedNodes: 5%
  minimumHealthyCoverage: 99.99%
  promoteAfter: 24h
  abortOn:
    - required-hook-detached
    - identity-classifier-miss-rate-above: 0.001%
    - legitimate-entry-rejection-above: 0
```

In `observe`, the result is named `would_deny` or `would_reject`; it is never
reported as physical prevention. Promotion creates a new signed policy
generation. A temporary exception names exact Pod/container/image/role/object
or provider identity, has an owner and expiry, is simulated, and is visible in
every affected finding.

#### Abandoned rollout selector and retained metric-denominator rules

The retained `mode: protect` plus `rollout.phase: observe` is ambiguous unless
separated. Version 1 has:

The following retained pair and node-oriented hash are abandoned because they
reuse “cohort mode” for the already separate enforcement mode and conflict
with canonical `RolloutV1`:

```text
desired_profile_mode: PROTECT
cohort_mode: OBSERVE | PROTECT
```

The old draft said that the selected rollout cohort runs `cohort_mode`; nodes
outside it remain on the previous signed generation/mode, and that “5%” means
buckets 0 through 499 of:

```text
u64_be(first 8 bytes of SHA-256(
  canonical(cluster_uid, node_uid, profile_id, rollout_generation))) % 10000
```

A node restart would retain its node UID and bucket and a replacement node
would be independently assigned. This node formula is abandoned. Canonical
Version 1 uses `RolloutV1.cohort_selection` and the
`MITHRIL-ROLLOUT-V1` execution-set-binding formula above; the selected binding
runs `desired_profile_mode`. The metric-denominator rules below remain
normative.

Coverage is calculated over explicit `(binding, required_source, nanosecond)`
tuples:

```text
denominator = sum required duration for every named binding/source
numerator   = sum duration overlapped by HEALTHY intervals in required mode
coverage_ratio = numerator / denominator
```

One detached required hook makes that hook's affected seconds uncovered; a
healthy unrelated source cannot compensate. Every abort metric declares
window, denominator, and minimum sample count. For example,
`identity-classifier-miss-rate-above: 0.001%` means classifier misses divided
by protected effect attempts over a rolling 60-minute window with at least
100,000 attempts; below the minimum it is `insufficient_samples`, not zero.
“Legitimate-entry rejection” is measured only by signed acceptance fixtures or
operator-confirmed labeled events, never inferred because a rejected process
retried.

`promoteAfter: 24h` means every required metric remained within bounds and
coverage healthy continuously for 24 hours after the minimum sample counts
were reached. Promotion is a newly approved and signed rollout generation; a
node never flips itself from observe to protect merely because a timer expired.

### CI/CD Execution And Intent Mapping

CI/CD is not one process tree. A workflow can fan out to jobs on different
nodes, run native shell/JavaScript children, create job and service containers,
start privileged build daemons, pass caches/artifacts to later jobs, obtain
short-lived cloud credentials, wait for human approval, deploy, and run cleanup
after failure. Mithril must preserve each physical shape instead of calling the
whole workflow one container or one process.

#### Current execution practices the model must cover

- GitHub Actions workflows contain jobs, and jobs contain ordered steps. Jobs
  can run directly on a runner or in a job container. Docker container actions
  can run as sibling containers on the same network and shared workspace. See
  GitHub's [Actions execution overview](https://docs.github.com/en/actions/get-started/understand-github-actions),
  [job-container documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container),
  and [custom container hooks](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/customize-containers).
- GitHub creates a job-scoped `GITHUB_TOKEN`, and a job with `id-token: write`
  can request an OIDC token containing claims such as repository, ref,
  workflow, workflow SHA, run ID/attempt, actor, environment, and runner type.
  These are job/workflow claims, not a proof of one shell step. See the
  [`GITHUB_TOKEN` contract](https://docs.github.com/en/actions/concepts/security/github_token)
  and [OIDC claim reference](https://docs.github.com/en/actions/reference/security/oidc).
- GitLab's Docker executor has prepare, pre-job, job, and post-job phases, with
  helper and service containers. Its Kubernetes executor creates a Pod for
  each job with build, helper, and service containers. See the
  [Docker executor](https://docs.gitlab.com/runner/executors/docker/) and
  [Kubernetes executor](https://docs.gitlab.com/runner/executors/kubernetes/).
- GitLab CI ID tokens contain exact pipeline/job/runner/project/ref/config
  claims and a unique token ID. They prove the signed claims for the job, not
  arbitrary step intent. See [GitLab ID token authentication](https://docs.gitlab.com/ci/secrets/id_token_authentication/).
- Tekton runs a Task as a Kubernetes Pod. Steps are ordered containers;
  sidecars overlap the steps and workspaces/results cross step boundaries. See
  [Tekton Tasks](https://tekton.dev/docs/pipelines/tasks/).
- Jenkins can allocate a different agent for a pipeline or stage, run shell or
  container steps, execute parallel/matrix branches, and run `post`/`cleanup`
  steps after success, failure, or abort. See the
  [Jenkins Pipeline syntax](https://www.jenkins.io/doc/book/pipeline/syntax/).

These are examples of stable execution shapes, not mandatory vendor
integrations. The core model is coordinator-neutral.

#### CI assurance tiers: process identity is not credential isolation

CI support is advertised per tier; the word “step” alone grants nothing:

| Tier | What Mithril proves | What it can physically enforce | What it cannot claim |
| --- | --- | --- | --- |
| `CI0_JOB` | Exact coordinator job and job execution roots | Job-wide file/exec/network/device policy; reject whole untrusted job/root | Exact step, or separation of a job-scoped token among steps |
| `CI1_STEP_PROCESS` | Exact step process/root through a held pidfd/runtime task and authenticated coordinator proof | Step-specific local effects and endpoints distinguishable below TLS | Semantic read versus write over the same endpoint; removal of credentials already shared with the job |
| `CI2_STEP_AUTHORITY` | CI1 plus a credential/lease uniquely scoped and delivered to that step | Provider permissions and TTL of the scoped lease; deny other steps' access to lease object/broker | Operations the provider's scope itself does not distinguish |
| `CI3_PROVIDER_ADMISSION` | CI2 or an exact request to a provider-native admission/permission boundary | Provider rejects disallowed API/repository verbs before completion | Operations for which the provider exposes no synchronous policy boundary |

GitHub's `GITHUB_TOKEN` is job-scoped and available through the job context.
OIDC `id-token: write` is configured at workflow/job scope, and runner
environment variables can be used to request the token. Those facts do not
prove one shell step. If an unchanged job makes a write-capable token available
to untrusted code, BPF cannot turn it into a read token and cannot distinguish
`git clone` from `git push` when both use the same credential, host, port, and
TLS channel.

Therefore Mithril's deployment-preserving choices are honest and explicit:

- deny/fence the whole channel for the untrusted **job** when legitimate work
  does not need it;
- enforce any distinguishable local object or destination and alert the
  provider-confirmed semantic write;
- use a provider-issued/brokered scoped lease or semantic gate for preventive
  read-versus-write control; or
- report `SEMANTIC_AUTHORITY_ISOLATION_UNAVAILABLE` and recommend job/token
  separation. A recommendation is not silently counted as protection.

Mithril cannot generally derive a less-privileged GitHub token from an existing
more-privileged token. GitHub App installation tokens are minted using App
authority and requested permissions/repository scope, not attenuated from an
arbitrary installed bearer token. No TLS interception is introduced.

**Git example.** `actions/checkout` and hostile code both connect to
`github.com:443` using the job token. CI1 can prove which process initiated
each connection, but encrypted smart-HTTP does not reveal clone versus push.
If policy blocks that endpoint for the hostile step, it blocks both. CI2 solves
it with a read-only lease available only to checkout; CI3 uses a provider-
native admission/permission boundary such as effective read-only App
permissions or protected-ref rules where those semantics are sufficient. If
neither exists, prevention is job-wide endpoint denial only.

##### Declined design: Erebor Git/TLS termination

The earlier proposal for an “explicit Git-aware gate that terminates the
Git/TLS application connection” is retained only as a declined alternative.
It violates the product decision that Mithril does not act as a TLS
man-in-the-middle. Mithril may consume provider audit, request a provider-
issued scoped capability, or call a provider-native admission API; it does not
decrypt and proxy the agent's GitHub connection. Post-effect provider audit is
detection/response, not prevention.

#### GitHub container-hook and host-runner limitation

GitHub container customization hooks are public preview, are triggered for
container-based jobs, and execute in the runner service account. Their
`run_script_step` input describes how to invoke the script in the job
container, but the documented input is not a provider-signed, unforgeable step
identity. They do not provide the equivalent exact hook for an ordinary native
host job.

Consequently a callback is assertion input, not proof. Full CI1 requires a
Mithril-supported runner integration that:

1. receives provider-authenticated **job assignment** evidence over an
   authenticated coordinator channel, then creates a trusted-runner
   step-launch attestation for the locally materialized step;
2. asks `mithril-node` for a one-use transition/entry slot from a task already
   labeled `ci-runner-control`;
3. creates the step child or container held, supplies a pidfd/runtime task, and
   resumes only after label readback; and
4. closes the step tree explicitly while background descendants retain that
   step role until exit.

The signing key remains inside `mithril-node` or a separate privileged
coordinator boundary unavailable to job cgroups. Unix UID or possession of the
callback socket is insufficient; peer credentials are joined to the live
`ci-runner-control` task label. A job descendant asking for a deploy proof is
rejected even if it runs as the same service account.

Without the held-child seam, command/digest/time correlation is
`SAME_BUDGET_AMBIGUOUS` at best. Two concurrent identical execs can steal each
other's pending claim just like identical runtime roots.

**Host-runner test.** Untrusted job code copies all runner environment fields,
connects to the assertion socket, and requests a deploy step. The peer task is
`ci-job`, not `ci-runner-control`; no proof or lease is minted. A second fixture
races two identical child execs while the integration reverses creation order;
pidfds, not timing, bind the exact step IDs.

##### Concrete coordinator support matrix and first GitHub implementation

| Coordinator shape | Unmodified support | Exact process/root support path | Maximum local tier before credential broker |
| --- | --- | --- | --- |
| GitHub self-hosted host job | Exact job assignment/root when runner is isolated; step callback unavailable | Mithril-maintained patch/fork of `actions/runner` at child creation plus root-owned held-child launcher | `CI1_STEP_PROCESS` |
| GitHub self-hosted container job with preview hooks | CI0 job/root; hook event is contextual/same-budget step evidence only | Patched runner supplies internal step execution ID; Mithril container hook/launcher holds exact script/container task | `CI1_STEP_PROCESS` |
| GitHub-hosted runner | Outside node authority | Provider evidence only unless GitHub supplies a future supported enforcement integration | no local tier |
| GitLab standard executor | Job/container entry according to deployment visibility | Maintained Runner custom executor/patch at child/container creation | `CI1_STEP_PROCESS` |
| Tekton per-step containers | TaskRun/Pod/container identity can identify a step root when admission is exact | Mithril admission adapter binds TaskRun UID, step name/image and held runtime root | `CI1_STEP_PROCESS` |
| Jenkins agent | Agent/job tree; stage/step may be contextual | Maintained plugin plus durable-task/launcher integration returning held pidfd/root | `CI1_STEP_PROCESS` |

The first GitHub production implementation is not the preview hook alone. It
is a maintained `actions/runner` patch/fork that consumes the authenticated
service job message, derives an immutable local `step_execution_id` from the
current job check-run ID, run attempt, internal step ID/ordinal, definition
digest, and invocation digest, and calls a root-owned launcher before child
resume. The launcher is a short-lived mode/library of the Mithril product, not
another gatherer and owns no maps, WAL, or graph.

GitHub OIDC can identify a job with `check_run_id`; it has no documented step
claim. Thus `check_run_id` is required for job-exact GitHub proof, and the
patched runner's trusted launch record—not OIDC—binds the local step. Two jobs
in one `run_id` must have different check-run IDs and independent job epochs.

Unpatched host runners and unpatched preview-container hooks advertise CI0,
never CI1. The hostile suite swaps two identical bash scripts, reverses child
creation, forges the hook JSON from job code, and runs two jobs in one workflow
run; no command/time/`run_id` correlation may cross-bind them.

#### CI identity objects

```text
PipelineRun {
  pipeline_run_id
  coordinator_id
  tenant_id
  repository_or_project_id
  trigger_event
  trigger_actor
  trigger_trust_class: trusted_ref | untrusted_change | scheduled |
                       manual_approved | policy_generated
  source_ref
  source_sha
  pipeline_definition_ref
  pipeline_definition_digest
  run_number
  run_attempt
  parent_pipeline_run_id?
}

PipelineJob {
  pipeline_job_id
  pipeline_run_id
  job_definition_id
  matrix_coordinates?
  environment?
  runner_id
  runner_group
  node_id?
  executor_kind: host | vm | container | kubernetes | remote
  job_image_digest?
  credential_audiences[]
  state
}

PipelineStepIntent {
  step_intent_id
  pipeline_job_id
  step_definition_path
  step_definition_digest
  action_or_script_digest
  action_source_ref_and_sha?
  expected_shape: native_transition | runtime_container_root |
                  service_root | coordinator_builtin
  input_artifact_digests[]
  requested_role_id
  requested_authority_leases[]
  parent_step_intent_id?
  one_use_nonce
  not_before
  deadline
}
```

##### Correction: CI intent is the closed `IntentKindV1=7` body

`PipelineStepIntent` above is retained as a product-domain view; it is not a
second wire format. Every security field lowers to `CiStepIntentBodyV1` inside
the signed envelope defined in Part III. The envelope supplies proof ID,
issuer/trust domain, sequence epoch/sequence, validity, exact one-use claim
slots, parent proof, and trigger proofs. The coordinator assertion consumed by
the admission owner is independently closed:

```text
CiCoordinatorAssignmentProofDraftAbandoned {
  proof_version: 1
  coordinator: CiCoordinatorV1
  coordinator_tenant_id
  immutable_run_id
  immutable_job_id
  immutable_step_id
  run_attempt: u32
  repository_or_project_stable_id
  immutable_source_revision
  immutable_pipeline_definition_digest: DigestV1
  exact_runner_assignment_id
  runner_group_or_pool_id
  expected_execution_shape: CiExecutionShapeV1
  trigger_actor_stable_id
  trigger_trust_class: CiTriggerTrustClassV1
  issued_at_utc_ns
  expires_at_utc_ns
  coordinator_nonce: Id128
  issuer_key_id
  canonical_payload_digest: DigestV1
  signature
}

CiProviderJobAssignmentEvidenceV1 {
  proof_version: 1
  coordinator: CiCoordinatorV1
  coordinator_tenant_id
  immutable_run_id
  immutable_job_id
  run_attempt: u32
  repository_or_project_stable_id
  immutable_source_revision
  immutable_pipeline_definition_digest: DigestV1
  provider_job_or_check_run_id?
  provider_runner_assignment_fields[]
  trigger_actor_stable_id
  trigger_trust_class: CiTriggerTrustClassV1
  issued_at_utc_ns
  expires_at_utc_ns
  coordinator_nonce: Id128
  issuer_key_id
  canonical_payload_digest: DigestV1
  authenticated_proof
}

CiTrustedRunnerStepLaunchAttestationV1 {
  attestation_version: 1
  provider_job_assignment_evidence_digest: DigestV1
  locally_derived_step_execution_id: Id128
  step_definition_identity_digest: DigestV1
  materialized_step_invocation_digest: DigestV1
  public_environment_contract_digest: DigestV1
  node_boot_id: Id128
  execution_set_id: Id128
  cgroup_binding_id: Id128
  cgroup_binding_nonce: Id128
  held_target_binding_digest: DigestV1
  attesting_runner_control_task_cookie: u64
  issued_boottime_ns: u64
  one_use_nonce: Id128
  node_key_id
  signature
}

CiStepAdmissionJoinV1 {
  join_id: Id128
  provider_job_assignment_evidence_digest: DigestV1
  trusted_runner_step_launch_attestation_digest: DigestV1
  ci_step_intent_digest: DigestV1
  held_target_binding_digest: DigestV1
  state: PREPARING | COMMITTED | REJECTED | TOMBSTONED
}
```

`CiCoordinatorAssignmentProofDraftAbandoned` incorrectly treated provider job
identity, locally derived step identity, and runner launch as one provider-
signed object. For GitHub, `check_run_id` is job-level; the documented
container-hook invocation is not an unforgeable step claim. The three records
above are canonical: provider-authenticated job evidence, a node-signed launch
attestation created by the trusted runner-control task, and an atomic join to
the held child/root before resume. Wrong job/attempt/runner, forged callback,
two identical concurrent steps, stale nonce, or changed materialized bytes
rejects the join. Until a named adapter and signed CI policy are allocated,
these records remain dormant architecture contracts and cannot advertise CI1.

The runner/coordinator adapter authenticates and normalizes this proof but
cannot mint `SignedIntentV1`. `IntentAdmissionOwner` verifies coordinator
issuer, exact live assignment, attempt, immutable workflow/action/materialized
digests, node and binding, then stages the bounded slots. For a native step the
slot claims a held child/exec transition; for a container/service shape it
claims the exact held runtime root. A coordinator builtin has no local claim.
Replay, wrong runner, changed script bytes, shape mismatch, parent mismatch,
expired assignment, or a second claimant rejects before authority-bearing
effects.

**Concrete example.** GitHub run `901`, check-run/job `777`, attempt `2`, step
`publish-image` is assigned to runner `r-12`. The workflow asks `/usr/bin/bash`
to execute a generated file. The launcher seals the exact script bytes and the
body binds their `MaterializedStepInvocationV1` digest. A malicious job that
copies the same argv and replays run `901` from runner `r-19`, attempt `1`, or a
different memfd cannot consume the slot. Command text and `run_id` are hostile
controls; the coordinator assignment plus held object/task is authority.

`step_definition_digest` and `action_or_script_digest` have distinct meanings:

```text
StepDefinitionIdentityV1 {
  pipeline_definition_blob_digest
  canonical_definition_path_or_internal_step_id
  resolved_reusable_workflow_digest?
  resolved_action_repository_and_full_commit_sha?
  resolved_action_package_digest?
}

MaterializedStepInvocationV1 {
  step_execution_id
  exact_interpreter_or_entrypoint_object
  canonical_argv_digest
  working_directory_mount_object
  materialized_script_digest?
  held_script_fd_or_sealed_memfd_identity?
  container_image_digest?
  public_environment_contract_digest
  input_artifact_digests[]
}
```

The definition says what the coordinator planned; the materialized invocation
says what the held child will actually consume. For a generated shell script,
the root-owned launcher reads the runner-created file, rejects symlinks or
unexpected ownership/mount provenance, copies exact bytes into a sealed memfd
or equivalently holds and integrity-locks the exact file, hashes them, and
starts the interpreter against that immutable object. A mutable pathname or
workflow digest alone is not executed-byte proof. Secrets are not included in
the public environment digest; their delivery scope is recorded separately.

Composite actions create a nested step-intent graph. A JavaScript or local
action binds the resolved full commit SHA and local package digest; a container
action binds the image digest, not a tag. Every nested invocation gets its own
materialized record and held task.

##### Abandoned design: workflow digest proves executed script bytes

That inference is vulnerable to runner temp-file swap, symlink replacement,
mutable local action content, and action-tag movement, so it is abandoned.

**TOCTOU tests.** Swap the temp script after the definition callback, replace
it with a symlink, mutate a local action package, move an action tag, and launch
two identical `bash` commands from different steps. Strict support either runs
the sealed/held bytes bound to the correct step or rejects; it never hashes one
file and executes another.

Display names such as `Build`, `Test`, or `Deploy` are contextual labels. The
authority key uses immutable coordinator IDs, workflow/config digests, job and
step definition identities, run attempt, and signed trigger trust.

#### CI physical-shape matrix

| CI practice | Physical execution | Mithril representation | Default security treatment |
| --- | --- | --- | --- |
| Host/shell executor job | Long-lived runner forks job shell and tools | Runner task keeps `ci-runner-control`; signed job proof authorizes native transition to `ci-job`; every fork/exec stays native | Reject job if exact runner assignment/proof cannot bind before an authority-bearing effect |
| Job container | Runtime creates a root with no native parent in runner tree | `CiJobContainerEntry` plus `coordinator_started_job` causal edge from runner job | Bind exact image, job, workspace, credential audiences, and policy before exec |
| Script, JavaScript, or composite action | Usually native child/exec under the job | `PipelineStepIntent` authorizes a transition; composite substeps retain nested intent IDs | Same executable under another step keeps the other step's role |
| Container action | Runtime creates a sibling/secondary container root | `CiContainerActionEntry` tied to exact action ref/digest and step nonce | No automatic inheritance from job container; only declared shared workspace/network effects |
| Service container | Separate long-lived root overlapping job steps | `CiServiceEntry` with declared listener/client set and job lifetime | Service cannot read job credentials/workspace unless explicitly mounted and allowed |
| GitLab helper, checkout, cache restore, artifact upload | Helper image or runner process outside user build root | Dedicated `ci-helper-*` entries/roles and typed artifact operations | User build cannot claim helper role; helper cannot execute workspace content unless declared |
| Tekton step | New container root for each ordered step | One `CiStepContainerEntry` per TaskRun UID/step name/image digest | Sequential order does not fabricate native parentage; workspace handoff is an artifact edge |
| Tekton/Jenkins/GitHub side service | Concurrent root or background native tree | Independent service entry/tree associated with job | Cleanup deadline does not grant unrestricted authority |
| Matrix or parallel jobs | Separate jobs, often on different nodes | Sibling `PipelineJob` objects under one run with typed dependency edges | No cross-node native parents; each fan-out branch has independent coverage and response |
| Reusable workflow/downstream pipeline | New jobs defined by another immutable workflow/config | `pipeline_called_pipeline` edge carrying caller/callee digests and effective permissions | Called workflow cannot gain authority absent explicit caller policy and provider proof |
| Cache or artifact restore | Bytes cross time, jobs, and possibly trust levels | `ArtifactInstance` plus `published`, `restored`, `verified`, and `executed` edges | Restore may be allowed as data; execution or privileged consumption requires digest/provenance policy |
| OIDC/cloud login step | Native CLI/library call obtains remote authority | `AuthorityLeaseIntent` and resulting `CredentialLease` bound to job/step lineage | Job-level token alone cannot authorize every step; exact requested audience/role/project is checked |
| Deploy step (`kubectl`, Helm, Terraform, cloud CLI) | Native process plus encrypted provider operations; may create remote roots | Local step role plus provider audit and cross-node resource/controller/runtime edges | Allow only declared operations; reject through semantic gate when available, otherwise alert/respond to audit deviation |
| Post/finally/cleanup step | Runs after success, failure, cancellation, or abort | Separate `ci-post-cleanup` intent and role under terminal job lifecycle | Cleanup has only exact cleanup effects and remains restricted during containment |
| Interactive debug/web terminal | External administrator request creates shell/root | `CiAdministrativeEntry` with actor, approval, TTL, recording/coverage proof | Default reject on protected runners; never reuse build/test role |
| Docker socket or Docker-in-Docker | Job can ask another runtime/daemon to create descendants | Device/socket effect plus subordinate runtime entry graph | Untrusted role denies daemon socket; allowed builders must bind every created root or lose full coverage claim |

#### Coordinator-to-task binding algorithm

```text
on_ci_job_assigned(signed_job_proof):
    verify coordinator issuer and immutable pipeline definition
    verify repository/project, ref/SHA, trigger actor/trust, run attempt
    verify exact runner/node assignment and requested executor shape
    create PipelineRun/PipelineJob if absent; stage one-use job intent

on_ci_step_started(signed_step_proof):
    verify job is live and proof belongs to current run attempt
    resolve immutable action/script/image and input artifact digests
    compute requested role and authority leases from signed policy

    if expected shape is native_transition:
        stage TransitionIntent for exact labeled runner/job lineage
    else:
        stage EntryIntent for exact runtime container/service root

    reject proof reuse, wrong parent job, mutable action tag without resolved
           digest, wrong artifact, wrong image, wrong node, or expired deadline

on_task_or_root_claim(intent, live_task):
    re-resolve task/cgroup/container/image and existing native label
    require claim type to match physical shape
    install role before first protected effect
    emit exact coordinator-to-entry/transition edge
```

A runner-side producer can use a local authenticated socket to send these
small assertions. On GitHub self-hosted Linux runners, container customization
hooks expose prepare/job/container-step/script-step/cleanup lifecycle points,
but that interface is preview and does not by itself provide a cryptographic
step identity. A production adapter therefore signs records with a runner
identity, includes the service-issued job identity, and resolves immutable
workflow/action digests. For other coordinators, Mithril uses their supported
runner plugin, task admission, webhook, or controller API. None becomes a
second node gatherer.

##### Abandoned design: runner callback signature as sufficient proof

The phrase “adapter therefore signs records with a runner identity” is
incomplete and is abandoned if the signing key is readable or invocable by job
code. The callback normalizes coordinator input; it never holds Mithril's
signing key. Only the intent-admission owner, after authenticating the
runner-control task and coordinator assignment, signs/stages the canonical
proof. Compromise of the trusted runner-control process remains a declared
coordinator trust-boundary failure; ordinary job descendants are outside that
boundary.

#### Practical untrusted-PR and artifact example

A trusted `pull_request_target` workflow can accidentally download or check out
untrusted pull-request code and then execute it with a write-capable token.
GitHub documents this class and also warns that artifacts from an untrusted
workflow must be treated as untrusted. Mithril models trust as data provenance,
not as the workflow file's display name:

1. The coordinator proof says the workflow definition comes from the trusted
   base branch, but the trigger is an untrusted fork pull request.
2. Checkout or artifact download creates an `ArtifactInstance` labeled with
   source repository, source SHA/run, producer trust, digest, and verifier
   result.
3. The checkout helper may write those bytes to the workspace. That does not
   authorize execution.
4. `make test`, `npm install`, `cargo test`, Python import, shell sourcing, or
   loading a plugin from that tree causes an exec/file/mmap transition whose
   input provenance is `untrusted_change`.
5. Policy assigns `ci-untrusted-build`, which denies repository writes,
   workflow mutation, cloud OIDC audiences, runner-control sockets, host
   credentials, deployment APIs, and protected environment secrets.
6. A later publish/deploy job can consume only an exact artifact digest with
   the configured producer run, review/attestation proof, and promotion edge.
   A mutable filename or “successful build” string is insufficient.

This catches indirect execution too. The process does not need to run
`./malware`; a package install script, `build.rs`, test discovery, compiler
plugin, Makefile, or container build can execute attacker-controlled code.
Mithril follows the file/artifact provenance into the resulting role and
physical effects.

#### Cross-step state and runner-reuse contract

CI coordinators intentionally pass state outside native process parentage.
GitHub environment files (`GITHUB_ENV`, `GITHUB_PATH`, `GITHUB_OUTPUT`, and
action `GITHUB_STATE`), workspaces, caches, artifacts, service sockets, and
background processes are security-relevant handoffs:

```text
JobExecutionEpochV1 {
  job_epoch_id
  coordinator_job_id
  check_run_id?
  run_attempt
  runner_id
  node_boot_id
  exact_job_cgroup_binding
  workspace_mount_object
  temp_and_command_file_mount_objects[]
  start_boottime_ns
  state: PREPARING | ACTIVE | CLEANING | VERIFIED_EMPTY | FAILED_CLEANUP
}

CiStateArtifactV1 {
  state_artifact_id
  kind: ENV_FILE | PATH_FILE | OUTPUT_FILE | ACTION_STATE_FILE |
        WORKSPACE_FILE | CACHE | ARTIFACT | SERVICE_ENDPOINT
  producer_job_epoch_id
  producer_step_execution_id
  immutable_content_digest_or_endpoint_identity
  sensitivity
  consumer_slots[]
}
```

Writing `GITHUB_PATH` is not merely a file write: the next step's command
resolution consumes a typed artifact from the producer. `PYTHONPATH`,
`NODE_OPTIONS`, compiler/plugin configuration, shell startup files, and
workspace executables follow the same provenance into file/mmap/exec decisions.
A trusted publish step does not cleanse a path entry produced by an untrusted
test step.

Every job gets a fresh cgroup binding nonce and epoch. Before admitting the
next job on a reused runner, the cleanup owner fences/kills remaining job
descendants as authorized, verifies the job cgroup has no tasks or labeled
sockets, closes services, validates workspace/temp cleanup policy, tombstones
the epoch, and only then creates the next one. A daemonized child remains in
the old job role and cannot become a runner-control/new-job process by surviving
its parent.

**Tests.** `CI-STATE-001` has an untrusted step prepend a malicious directory
to `GITHUB_PATH`/`PYTHONPATH`; the later publish step's tool load retains the
untrusted producer edge and denies privileged authority. `CI-RUNNER-REUSE-001`
daemonizes a child and socket, ends the job, and assigns another job: admission
waits for verified cleanup or rejects the runner; neither object crosses the
epoch. `CI-OUTPUT-001` injects a command-like value through a step output and
proves later materialization is attributed to the producing step.

#### Practical CI policy

##### Abandoned design: this YAML is not a Version 1 policy document

The entire `coordinators`/`ciRules` example below is retained as operator-facing
design input, but it is non-compilable. Those top-level keys are not members of
`PolicyDocumentV1`; only the later `attestation: verified` correction would
leave the rest falsely looking valid. No `CiPolicyV1` or named coordinator
adapter is allocated by the approved phase plan yet.

When that surface is approved, it must either extend `PolicyDocumentV1` with a
closed, versioned CI union or compile a separately signed CI document into the
same exact `DetectionDispositionRuleV1`, authority-lease, artifact, response,
and `CiStepIntentBodyV1` contracts. Until then, the Version 1 parser returns
`CFG_UNKNOWN_FIELD` for `coordinators`, `ciRules`, and
`attestationPolicies`; the examples cannot activate a generation or satisfy a
CI fixture. The physical-shape matrix and tests remain requirements for the
future adapter, not hidden implementation authorization.

```yaml
coordinators:
  github-actions-prod:
    issuer: https://token.actions.githubusercontent.com
    requiredAudience: mithril-ci-intent
    trustedRunnerGroup: prod-runners
    requireClaims:
      - repository_id
      - workflow_ref
      - workflow_sha
      - run_id
      - run_attempt
      - check_run_id
      - actor_id
      - runner_environment
    runnerStepChannel: required

ciRules:
  - id: untrusted-pr-build
    match:
      coordinator: github-actions-prod
      triggerTrustClass: untrusted_change
    role: ci-untrusted-build
    dispositionOnMissingIntent: reject
    authorityLeases: []
    effects:
      repositoryWrite: deny
      cloudIdentityEndpoints: deny
      kubernetesApi: deny
      runnerControlSocket: deny
      serviceContainers: declared-only
      publicDependencyFetch: alert

  - id: reviewed-main-publish
    match:
      coordinator: github-actions-prod
      workflowRef: org/repo/.github/workflows/release.yml@refs/heads/main
      workflowDigest: sha256:reviewed-workflow
      triggerTrustClass: trusted_ref
      stepId: publish-image
    role: ci-publish
    requireArtifacts:
      - digestFromStep: build
        producerRole: ci-trusted-build
        attestation: verified
    authorityLeases:
      - provider: registry
        audience: prod-registry
        operations: [push-image, write-attestation]
        ttl: 10m
    dispositions:
      undeclaredArtifact: reject
      credentialAudienceMismatch: reject
      unexpectedProviderOperation: alert

  - id: production-deploy
    match:
      environment: production
      stepId: deploy
    requireApproval:
      source: coordinator-environment-protection
      preventSelfApproval: true
    role: ci-deploy
    authorityLeases:
      - provider: kubernetes
        cluster: production
        operations: [get, patch-deployment]
        resourceSelectors: [namespace=serving, deployment=model-api]
        ttl: 5m
    dispositions:
      missingApproval: reject
      unknownArtifactDigest: reject
      providerDeviation: alert

  - id: cleanup
    match:
      lifecycle: [failed, cancelled, post, cleanup]
    role: ci-post-cleanup
    effects:
      artifactUpload: declared-only
      deleteOwnTemporaryResources: allow
      newCloudLease: deny
      repositoryWrite: deny
```

##### Abandoned design: boolean `attestation: verified`

The retained YAML field does not identify what was verified and is abandoned
as an authorization predicate. A valid signature from an allowed key can still
name the wrong subject digest, source revision, materials, builder, or expired
trust state. The source schema replaces that shorthand with a policy reference:

```yaml
attestationPolicies:
  prod-image-provenance-v1:
    resultRequired: VALID_AND_POLICY_MATCHED
    predicateType: https://slsa.dev/provenance/v1
    trustedSignerSet: release-builders-v3
    allowedBuilderIds: [prod-builder]
    requireSubjectDigestMatch: true
    requireSourceRevisionMatch: true
    requireMaterialDigests: true
    maximumVerificationAge: 10m
    transparencyRequirement: required
    recheckSignerRevocationAtConsumption: true

ciRules:
  - id: reviewed-main-publish-corrected
    requireArtifacts:
      - digestFromStep: build
        producerRole: ci-trusted-build
        attestationPolicyRef: prod-image-provenance-v1
```

`VALID_AND_POLICY_MATCHED` means signature, trust chain, signer revocation,
predicate type, builder identity, exact artifact subject digest, source
revision, required material digests, transparency proof, freshness, and
producer trust all passed at the protected consumption point. Verification
results include the policy/version and evidence digests; they are not a naked
boolean.

`CI-ATTEST-001` presents: a correct attestation; a valid signature for the
wrong subject digest; wrong source revision; missing material; untrusted
builder; revoked signer; stale verification; and absent transparency proof.
Only the first may enter the publish/deploy role. A trusted signer attesting an
artifact produced by `ci-untrusted-build` remains rejected unless the policy
explicitly permits that producer trust class.

#### Required lowering for CI semantic effects

Fields such as `repositoryWrite: deny` are not kernel operations. They compile
only when the selected platform has one of the following physical plans; the
explain output names it:

| Source intent | Valid lowering | Invalid shortcut |
| --- | --- | --- |
| `repositoryWrite: deny` | Provider token whose effective permissions are read-only; synchronous Git-aware/provider gate rejecting write verbs; whole repository endpoint/channel deny; or post-effect provider alert explicitly marked non-preventive | Claiming BPF distinguished clone from push inside the same TLS connection |
| `cloudIdentityEndpoints: deny` | Deny the exact OIDC/STS/metadata destination and all alternate IP/IPv6/private endpoints before credential issuance | Claiming the request-token environment value was removed from process memory |
| `kubernetesApi: deny` | Connect/send denial to every resolved cluster API endpoint; optionally semantic admission for allowed controller jobs | Claiming packet inspection identified Kubernetes verbs under TLS |
| `runnerControlSocket: deny` | Unix-socket/file/peer decision on the exact socket object plus task role | Path string or service-account UID alone |
| `newCloudLease: deny` | Reject at the identity broker/gate, or deny every identity endpoint; otherwise alert provider issuance | Audit-only `deny` after issuance |
| `artifactUpload: declared-only` | Exact connector/store operation and digest intent, or destination deny if undeclared uploads need no shared endpoint | Filename/time correlation as exact artifact identity |
| `deleteOwnTemporaryResources: allow` | Provider gate or audit rule with exact lease, owner tag/UID, resource selector, and delete operation | A broad cloud delete permission inferred from cleanup role name |

The compiler produces one `EffectLoweringRecord` for every semantic field:

```text
EffectLoweringRecord {
  source_rule_id
  semantic_effect
  assurance_tier
  decision_stage
  physical_mechanism
  required_capability_ids[]
  required_proof_axes
  prevention_claim: PREVENTED | WHOLE_CHANNEL_PREVENTED |
                    DETECTED_AFTER_EFFECT | UNSUPPORTED
  blast_radius
  acceptance_test_ids[]
}
```

If no valid lowering exists, protect-mode compilation fails or the operator
must explicitly choose an alert-only degraded rule. A semantic comment in YAML
cannot become a product claim by itself.

Job secrets require the same honesty. `GITHUB_TOKEN`, Jenkins-injected
environment secrets, and similar values may already be present in a job
process's memory or context before a step begins. Mithril cannot retroactively
deny that memory read or reliably scrub every copy. It can prevent earlier
delivery only through a runner/coordinator credential seam; otherwise it
governs distinguishable file, broker, network, and provider effects and marks
the secret as job-scoped exposure.

GitHub environment protection can provide a required-reviewer or custom
deployment-rule proof, but the effective cloud/Kubernetes operation still
uses the authority behavior rule. The coordinator approval proves “this
deployment job may start”; it does not prove every command the job executes is
safe.

#### CI acceptance cases

| Test | Adversarial setup | Required result |
| --- | --- | --- |
| `CI-NATIVE-001` | Two steps execute identical `/usr/bin/curl`; only one has a signed publish intent | Each native exec retains its step role; the unapproved step cannot borrow publish authority |
| `CI-CONTAINER-001` | Job container, service container, and container action share network/workspace | Three independent entries and effect budgets; no fabricated parent or role inheritance |
| `CI-PR-001` | Trusted workflow downloads untrusted PR artifact and runs a build script | Resulting execution is `ci-untrusted-build`. An unopened projected credential denies at file access; a new OIDC/broker lease rejects at issuance; a distinct credential endpoint denies locally; an environment/pre-opened token already in memory cannot be unread, and a write over the same required TLS endpoint needs a semantic gate/read-only provider token or becomes provider detection/whole-channel denial. Every branch records its delivery class and physical result. |
| `CI-CACHE-001` | Untrusted job poisons a cache key consumed by trusted job | Exact producer/digest/provenance edge is visible; privileged consumption rejects or remains untrusted according to policy |
| `CI-OIDC-001` | Unapproved step reuses the job-level OIDC request variables | Job OIDC claims alone do not grant step authority; missing step/lease intent denies identity endpoint or rejects exchange |
| `CI-DIND-001` | Build talks to Docker socket and creates nested containers | Every root is bound to the job/step; if subordinate runtime visibility is absent, strict build denies the daemon effect |
| `CI-POST-001` | Job is cancelled during containment and cleanup attempts new egress | Cleanup gets its narrow post role; containment and response-root restrictions still win |
| `CI-FANOUT-001` | Matrix jobs run on three nodes and one publishes an artifact | Typed coordinator/artifact edges connect node-local trees; no cross-node Linux parent edge is invented |
| `CI-RETRY-001` | Run attempt 2 reuses attempt 1 nonce, artifact, or credential lease | Replay is rejected; new attempt identity and explicitly reusable artifacts are required |
| `CI-DEBUG-001` | Administrator opens a web terminal using the same shell command as a build step | Separate administrative entry with actor/approval/TTL; never build-step authority |

These expected results are capability-gated. `CI-NATIVE-001` requires
`CI1_STEP_PROCESS`; at `CI0_JOB`, both curls receive the job role and the
manifest must not report step separation. `CI-OIDC-001` has two valid
preventive implementations: CI1 denies the exact identity-provider endpoint
for the unapproved task, or CI2/CI3 rejects the lease/exchange. If the endpoint
is shared with required traffic and there is no broker, the result is alert or
job-wide deny—not a fictional step rejection. A separate
`CI-GITHUB-TOKEN-001` fixture proves that a write-capable job token already
available to both steps cannot be made read-only by Mithril without scoped
credential issuance or a semantic gate.

### Hugging Face Incident: Configured Algorithm Walkthrough

The earlier per-incident section explains each control in depth. This section
adds the missing operator view: which configuration rule fires, which
algorithm evaluates it, whether the action is allowed, alerted, denied, or
rejected, and what Mithril can physically prove.

It is grounded in the
[detailed implementation analysis](../../research/hugging-face-agent-intrusion-analysis.md)
and the
[source-faithful live action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md).
The public live stream has 21 representative entries; it is not the complete
17,613-action record. The more granular lateral actions published in the
technical timeline are mapped separately below.

#### Algorithm names used in the walkthrough

| Name | Owning mechanism | Decides or proves |
| --- | --- | --- |
| `ALG-INTENT` | General intent-proof verification and one-use claim | Whether a trusted coordinator authorized an entry, transition, authority lease, or artifact handoff |
| `ALG-ENTRY` | Runtime-entry classifier plus pending-intent claim | Whether a runtime-created root starts and which role it receives |
| `ALG-LINEAGE` | Native task inheritance and exec transition | Exact task/process/exec identity and role before a child effect |
| `ALG-FILE` | Generic pre-effect algorithm plus mount-aware file/object classifier | Open/read/write/map of dataset, proc, token, secret, host, code, and credential objects |
| `ALG-NET` | Socket creation provenance plus current actor/process/authority-domain state, destination classifier, connect/send/packet hooks | Local destination/channel effects without claiming encrypted API verbs |
| `ALG-DEVICE` | Device major/minor, ioctl, capability, namespace, mount, BPF, perf, and ptrace policies | Kernel/host escape and special-device effects |
| `ALG-AUTHORITY` | `AuthorityBehaviorRule` over Kubernetes/cloud/mesh/connector/source-control/database audit | Principal, operation, resource, result, and provider-side deviation |
| `ALG-ARTIFACT` | Immutable artifact identity and publication/consumption edges | Who produced, published, restored, loaded, or executed exact bytes/revisions |
| `ALG-XNODE` | Typed multi-node causal graph | API/controller/binding/runtime/provider paths between independent native trees |
| `ALG-RESPONSE` | Exact target re-resolution, authorized actuator, postcondition, and watch | Whether containment physically happened and remained effective |

The sample disposition below is a recommended strict profile, not a hidden
constant. An operator can configure a different valid disposition. The result
column states what that change would mean physically.

#### Every representative live-stream action

| Event | Concrete action and observation point | Strict sample configuration | Algorithm and practical result |
| --- | --- | --- | --- |
| `HF-001` | Root shell in an external evaluation sandbox | Hugging Face estate: no local disposition is possible; record `outside_authority` and optionally `alert` when external evidence arrives. If that sandbox is separately protected: reject unapproved job/root or deny the shell exec. | `ALG-ENTRY`/`ALG-LINEAGE` can prevent only where Mithril is installed. The Hugging Face deployment records an external subject and never claims it blocked another operator's sandbox. |
| `HF-002` | `id`, environment, mount, cgroup, filesystem, and process reconnaissance | Protected sandbox role: `deny` unapproved diagnostic exec and protected proc/host file reads; otherwise `alert` the sequence. | `ALG-LINEAGE` denies helper exec; `ALG-FILE` denies `/proc/*`, mount, host, or credential objects. Reading an already inherited environment in-process has no new file effect, so later write/send is the enforceable point. |
| `HF-003` | Use bundled debug `curl`, `nc`, `ip`, or fallback tooling | `deny` executable objects absent from the role's transition graph; `alert` allowed diagnostic tooling with restricted effects. | `ALG-LINEAGE` uses immutable executable identity, not `$PATH`. Copying or renaming the binary does not grant its role; `ALG-NET` still constrains its sockets. |
| `HF-004` | Send environment/secrets to a public capture endpoint | `deny` connect/send to unapproved public destinations and page; if the channel must be allowed, `alert` sensitive-state egress. | `ALG-NET` returns an errno before connection/send when distinguishable. `ALG-FILE` can set sensitive-read state first. Allowed shared TLS yields `semantic_effect_completed`, not a false prevention claim. |
| `HF-005` | Execute staged Python disguised as a source file | When prior artifact/download/write provenance bound the exact inode/content generation as staged code, deny that classified input read/map; otherwise do not infer Python interpretation from a kernel read—deny only an independently forbidden file access or the next distinguishable write/exec/network/provider effect. | `ALG-ARTIFACT` must pre-bind the exact object/content provenance before `ALG-FILE` may use the composite `UNTRUSTED_CODE_INPUT` atom. A `.c` name is never proof. `ALG-LINEAGE` still denies a new helper image; in-process Python execution has no exec hook. |
| `HF-006` | gzip/base64/chunk payloads in memory | Pure computation: `allow` because there is no distinguishable protected effect; `deny` the first prohibited code load, file write, exec, or send. | No algorithm invents a “packing” syscall. `ALG-FILE`, `ALG-LINEAGE`, `ALG-NET`, or `ALG-ARTIFACT` acts when packed bytes cross a real boundary. An alert-only heuristic may raise priority but cannot claim prevention. |
| `HF-007` | Search public code/platform APIs for infrastructure names | External estate: contextual `alert` from provider/API evidence; managed task with undeclared destination: `deny` connect. | `ALG-NET` can block the destination, while `ALG-AUTHORITY` can flag semantic searches when the service exposes authoritative audit. Similar query text alone does not establish causal identity. |
| `HF-008` | Malicious HDF5 external storage makes the worker open a local object | Baseline: `deny` worker reads outside `dataset-input`; optional upload scanner: `reject` the dataset before scheduling. | `ALG-FILE` resolves the actual mount/inode/proc target and returns `EACCES` before bytes enter HDF5. `reject` is valid only with the optional artifact admission boundary. |
| `HF-009` | Retrieve worker environment, secrets, source, and context through the dataset result/API | `deny` observable proc/secret/source reads; `deny` undeclared result publication or egress; `alert` an indistinguishable allowed publication. | `ALG-FILE` prevents `/proc/self/environ`, token, and non-dataset objects when opened. Already resident `os.environ` is not re-read from the kernel; `ALG-NET`/`ALG-ARTIFACT` governs the next publication. |
| `HF-010` | Jinja expression executes Python inside the existing conversion interpreter | Do not configure “deny Jinja execution” at the kernel. Configure `deny` for every unneeded exec/file/network/device/security effect of `conversion-worker-root`. | `ALG-LINEAGE` sees no new task for the initial Python execution. The existing task label reaches `ALG-FILE`, `ALG-NET`, and `ALG-DEVICE`; the first prohibited physical effect is denied. Pure arithmetic remains intentionally unclassified. |
| `HF-011` | Open projected ServiceAccount token and namespace files | Worker does not need token: `deny` and page. Legitimate controller role: `allow` or `alert` the read and set sensitive state. | `ALG-FILE` binds rotating projected-volume inodes to the semantic token object and exact task role. Token bytes never enter evidence. A credential already in memory shifts enforcement to network/provider behavior. |
| `HF-012` | Probe in-cluster/public Kubernetes API, DNS, EKS endpoints, and cloud IMDS, including hard-coded IPs | Worker role: `deny` connect/send to every API/IMDS destination class. Legitimate controller: `allow` channel and `alert`/respond on forbidden audit verb. | `ALG-NET` uses actual address/network namespace, so DNS monkey-patching does not bypass it. `ALG-AUTHORITY` evaluates Kubernetes/AWS operations over allowed TLS. |
| `HF-013` | Clone a dataset with a leaked write token and publish gzipped blobs as a dead-drop | Distinct write endpoint/lease: `deny` or semantic `reject`. Same endpoint, credential, and TLS channel as required reads: `alert` provider-confirmed write and quarantine exact revision. | `ALG-NET` cannot distinguish clone from push over identical TLS. `ALG-AUTHORITY` proves repository operation/result; `ALG-ARTIFACT` connects immutable revision/digest to consumers. |
| `HF-014` | Reach mesh control and establish mesh capability from a compromised node | `deny` unapproved mesh exec, control destination, TUN/device/ioctl, or required capability; alert provider operation if locally allowed. | `ALG-LINEAGE`, `ALG-NET`, and `ALG-DEVICE` are independent gates. Userspace-networking mesh mode may avoid TUN, but it still needs code execution and control/data sockets. |
| `HF-015` | Enroll external sandbox devices into the corporate mesh with a stolen key | With mesh pre-admission: `reject` unapproved enrollment. Audit-only: `alert`, revoke enrollment key, remove each existing device, and verify both. | `ALG-AUTHORITY` creates exact external device/key subjects. `ALG-RESPONSE` distinguishes preventing future joins from removing 181 already enrolled devices. Local BPF cannot stop an external host. |
| `HF-016` | Use mesh/cluster reachability to retrieve connector catalog and cluster connection context | Managed client with no need: `deny` destination. Typed connector gate: `reject` catalog request. Audit-only: `alert` exact request and restrict source session/device. | `ALG-NET` blocks the channel when possible. `ALG-AUTHORITY` requires connector source/destination request IDs; `ALG-XNODE` connects only proven forwarded requests. |
| `HF-017` | Replay harvested AWS credentials externally, enumerate cloud resources, validate identity, and exfiltrate result | Earlier local acquisition/exfil: `deny`. External use: `alert` exact AWS session/access key deviation and invoke approved session/key response. | `ALG-AUTHORITY` joins CloudTrail access-key/session/source-identity evidence; `ALG-RESPONSE` targets only a resolvable session/key. Same IAM role name is insufficient. |
| `HF-018` | Through connector/GitHub, mint write-capable App installation tokens, enumerate repos, and attempt a CI-triggering pull request | Typed connector/provider gate: `reject` token mint or disallowed PR/workflow operation. Audit-only: `alert`, revoke known token or suspend installation with approval, and verify repo/CI state. | `ALG-AUTHORITY` sees the semantic GitHub operation without TLS interception. `ALG-ARTIFACT` tracks commits/workflow/image digests. CI rules keep untrusted code in `ci-untrusted-build` even if a PR is accepted. |
| `HF-019` | Fresh external sandboxes re-fetch and execute a remote loader | Managed sandbox: `deny` loader destination, code-object load, exec, memfd/deleted image, or anonymous executable map. Outside estate: `alert` shared artifact/provider evidence only. | `ALG-NET`, `ALG-FILE`, and `ALG-LINEAGE` provide independent managed-node gates; `ALG-ARTIFACT` joins renamed copies by digest. |
| `HF-020` | Inspect staged binary, hostname, process, filesystem, and host state | `deny` undeclared proc/sys/debugfs/host reads, ptrace/perf/BPF/device/mount/namespace actions, and unapproved staged code; alert allowed diagnostic sequence. | `ALG-FILE` and `ALG-DEVICE` decide each effect on the exact lineage. Process names such as `readelf` are explanation, not authority. |
| `HF-021` | Access is cut and recovered activity stops | Apply configured `ALG-RESPONSE` actions; do not map silence to `allow` or “contained.” Alert unresolved branches and coverage gaps. | Exact local/provider actuators are re-resolved, replacement controllers are watched, and every postcondition must hold for the watch interval before result `verified`. |

##### Normative representative-action cards

The 21-row table above is retained as an operator overview. It is not an
implementation instruction: phrases such as “deny or alert” combine different
observation points and physical outcomes. The cards below are normative. Each
alternative is a separate case with one observation boundary, one decision
stage, and one oracle.

```text
HfRepresentativeActionCaseV1 {
  event_id: HF-001 .. HF-021
  case_id: bounded ID unique inside the fixture
  published_fact_ref: exact live-stream or technical-timeline fact anchor
  fixture_id: member of NormativeFixtureSetV1
  authority_scope: MANAGED_EXACT | EXTERNAL_EXACT |
                   OUTSIDE_AUTHORITY | LOCATION_UNRESOLVED
  required_capability_ids[]
  required_observations[] {
    source_id
    payload_schema_id
    exact_required_fields[]
    coverage_interval_id
    minimum_proof: ProofQualityV1
  }
  ordered_lookup_plan[]: LookupStepV1
  compiled_control {
    profile_generation_ref_id
    evaluation_stage
    exact_key_type
    exact_key_fields
    expected_disposition
    expected_errno?
    expected_finding_reason?
    response_binding_ids[]
  }
  expected_result {
    physical_result
    oracle
    expected_proof: ProofQualityV1
  }
  degraded_cases[] { missing_capability_or_proof, result, prohibited_claim }
  legitimate_control_case
  upstream_source_evidence_ids[]
}
```

For `LOCAL_PRE_EFFECT`, `ordered_lookup_plan` is always the canonical sequence:
preserve a prior stacked-LSM denial; load task label; copy process, domain,
entry, and binding state under their individual locks; validate placement and
retained generations; classify the complete atom and exact lifetime object;
load base/default plus restriction, response, pending-exec, object/socket, and
binding floors; intersect; commit the one declared transition/reservation; and
return the physical result before best-effort evidence. A card may name the
sequence `LOCAL_EFFECT_V1` rather than repeat it, but it must fill every key
field used by that route.

For `REMOTE_PRE_ADMISSION`, an authenticated synchronous gate may return
`REJECT`. For `POST_EFFECT`, provider audit may produce `ALERT` and an
authorized response, but never retrospective `REJECT` or local `DENY`.
`OUTSIDE_AUTHORITY` performs no fictional task/map lookup: it creates an
external subject and records only the evidence the source actually supplied.

| Event and case | Exact observation and required fields | Ordered route and compiled key | Physical result and oracle | Degraded result | Legitimate real-world control | Existing fixtures and source lessons |
| --- | --- | --- | --- | --- | --- | --- |
| `HF-001/A external-root` | Published sandbox root-shell fact; all Mithril node, task, cgroup, and binding fields must be absent | `OUTSIDE_AUTHORITY`; no local key | `outside_authority`; graph contains an external subject and no `prevented` result | Missing external feed is `coverage_unknown`, not benign | A managed conversion Pod starting its declared root normally | `HF-GRAN-OUTSIDE-001`; managed replay uses `ENTRY-START-001`; `KA-CODE-004`, `TG-CODE-004`, `TG-CODE-021` |
| `HF-002/A external-recon`; `B managed-helper`; `C in-memory-env` | A: published commands only. B: exact helper executable object and protected proc/host target. C: language runtime reads already resident environment | A: outside route. B: `NATIVE_TRANSITION` then `LOCAL_EFFECT_V1(FILE, OPEN_READ/READ)`. C: no file key; evaluate its next effect | A contextual only. B forbidden helper/read returns `EACCES`. C produces no invented read finding | Unresolved target object is classifier-unknown and follows signed fail posture | Declared health probe reads its allowed `/proc/self/status`; application reads its own already delivered environment | `HF-GRAN-OUTSIDE-001`, `HF-GRAN-HOST-LOC-001`, `FILE-IDENTITY-001`; `KA-CODE-001`, `TG-CODE-001` |
| `HF-003/A external-tools`; `B managed-copy` | A: external evidence. B: current task, immutable executable object, source role, copied/renamed inode generation | `NATIVE_TRANSITION` key includes source role, object identity, process state, and binding lifecycle; subsequent sockets use `LOCAL_EFFECT_V1` | Undeclared exec returns `EACCES`; renaming/copying never grants a tool role | Missing executable provenance denies when required; it does not fall back to basename | Declared diagnostic role runs the reviewed curl digest but remains destination-restricted | `HF-GRAN-OUTSIDE-001`, `FILE-IDENTITY-001`, `EXEC-COMMIT-STATE-001`; `KA-CODE-005`, `TG-CODE-002` |
| `HF-004/A external-publication`; `B managed-connect`; `C allowed-send`; `D provider-confirmed` | A external endpoint fact. B exact task/socket/final destination. C syscall return plus packet coverage. D authoritative service request/result | A outside. B `LOCAL_EFFECT_V1(NETWORK, CONNECT/SEND)`. C `LOCAL_COMPLETION`. D `POST_EFFECT` provider result | B errno and zero packet are prevention. C distinguishes allowed, local failure, and packet emitted. D proves only the provider result it reports | TLS payload without content oracle is `PAYLOAD_UNOBSERVABLE`; never “secret exfiltrated” | Approved telemetry sends non-sensitive bytes to its declared endpoint | `HF-004-RESULT-001`, `HF-GRAN-CAPTURE-001`, `STATE-PUBLICATION-LEASE-010`; `KA-CODE-006`, `TG-CODE-015` |
| `HF-005/A external-stage`; `B managed-classified-object`; `C ordinary-source` | Exact object generation plus trusted download/CAS/IMA/fs-verity/content oracle for B; no filename inference | B `LOCAL_EFFECT_V1(FILE, READ/MMAP/EXEC)` with `UNTRUSTED_CODE_INPUT` composite atom. C ordinary declared object atom | B read/map/exec returns `EACCES`; C succeeds. In-process Python interpretation without an oracle is not asserted | No trusted provenance yields ordinary/unknown object posture, not guessed malicious code | Converter imports its reviewed installed package or reads declared source metadata | `FILE-CONTENT-RACE-002`, `FILE-IDENTITY-001`, `MEM-EXEC-001`; `KA-CODE-002`, `TG-CODE-010` |
| `HF-006/A pure-pack`; `B boundary-crossing` | A CPU computation has no protected-effect observation. B exact file/object/socket/provider event | A no decision key. B corresponding file/network/artifact route | A allowed with no fake “packing prevented.” B has the boundary's exact errno/result oracle | Heuristic-only packing signal is contextual and cannot satisfy prevention | Normal model converter gzip-compresses an allowed result, then writes it to its declared result object | `HF-GRAN-OUTSIDE-001`, `HF-004-RESULT-001` |
| `HF-007/A external-search`; `B managed-destination`; `C service-semantic` | B exact final destination. C documented authoritative search/query audit fields | B `LOCAL_EFFECT_V1(NETWORK, CONNECT)`. C `POST_EFFECT` authority package | B connection returns errno/no packet. C alerts only the exact semantic operation exposed by the provider | Provider with no documented query event is `UNSUPPORTED_SOURCE` | Dependency resolver queries its declared public package service | `HF-GRAN-OUTSIDE-001`, `HF-NET-001`; `KA-CODE-015`, `TG-CODE-019` |
| `HF-008/A worker-local-open`; `B optional-upload-gate` | A worker task/process/domain plus actual mount/inode/proc object outside dataset view. B signed artifact upload request and held admission | A `LOCAL_EFFECT_V1(FILE, OPEN_READ)` exact object/class key. B `REMOTE_PRE_ADMISSION` artifact rule | A `EACCES`, no fd, no bytes. B rejects before scheduling only when the gate capability is present | No upload gate means B is unsupported; it does not weaken A | Worker opens `/dataset/input/chunk.h5` inside the admitted read-only view | `HF-LOCAL-001`, `FILE-NAMESPACE-001`; `KA-CODE-001`, `TG-CODE-011` |
| `HF-009/A protected-read`; `B resident-env`; `C result-publication`; `D same-TLS` | A exact object/open/read result. B no new read event. C publication reservation plus sink. D provider/content oracle if any | A `LOCAL_EFFECT_V1(FILE)`. B evaluate next effect. C `LOCAL_EFFECT_V1` plus domain publication transaction. D post-effect only | Forbidden A denies. C undeclared sink denies/no marker. D without content oracle is payload-unobservable | An allowed source read is not malicious; same TLS with no semantic/content proof cannot confirm exfiltration | Converter reads its own package metadata and uploads a declared result without acquiring sensitive authority | `HF-LOCAL-001`, `HF-GRAN-DEAD-DROP-001`, `STATE-PUBLICATION-LEASE-010`, `FILE-DELEGATED-EGRESS-001`; `KA-CODE-006`, `TG-CODE-005` |
| `HF-010/A in-process-expression`; `B helper-or-effect` | A same task/execution, arithmetic only. B exact exec/file/network/device effect | A no kernel semantic key. B native transition or `LOCAL_EFFECT_V1` | A intentionally unclassified. B forbidden effect returns exact errno | Template/Jinja text alone is not an enforcement fact | Legitimate template computes a derived column but touches no extra authority | `HF-LOCAL-001`, `HF-NET-001`, `MEM-EXEC-001`; `TG-CODE-001`, `TG-CODE-007` |
| `HF-011/A open`; `B positive-read`; `C inherited-fd`; `D resident-memory` | A exact projected-token object. B exact read request and positive return with qualified coverage. C acquisition/transfer provenance. D no new object read | A `LOCAL_EFFECT_V1(FILE, OPEN_READ)`. B completion package. C current actor + immutable file provenance. D next-effect route | A `EACCES`/no fd. B alone may say `SENSITIVE_BYTES_READ`. C use denies by current actor/object floor. D cannot be unread | Missing completion downgrades to `SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED` | Controller role opens/reads its declared token and receives stricter publication floor | `FILE-SA-TOKEN-OPEN-001`, `HF-011-READ-RESULT-001`, `FILE-FD-PASS-001`, `FILE-MMAP-001`; `KA-CODE-018`, `TG-CODE-011` |
| `HF-012/A fresh-connect`; `B rewrite`; `C existing-socket`; `D allowed-controller-verb` | Exact destination registry generation, final IPv4/IPv6 address, netns, socket lifetime; D Kubernetes/AWS authoritative operation/result | A-C `LOCAL_EFFECT_V1(NETWORK)` using exact socket/channel floors. D `POST_EFFECT` authority rule | Forbidden new or existing path returns errno/no packet. D alerts/responds to forbidden semantic verb | Missing final-address/rewrite or packet coverage makes that path unsupported; DNS text is insufficient | Approved controller reaches exact API endpoint and performs allowed `get` | `HF-NET-001`, `NET-REWRITE-001`, `NET-SOCKET-LIFE-001`, `NET-NS-PASS-001`; `KA-CODE-012`, `KA-CODE-025`, `TG-CODE-019` |
| `HF-013/A distinct-channel`; `B broker/read-only`; `C same-TLS-write` | A exact endpoint. B broker lease/token permissions or synchronous semantic request. C provider-confirmed repo operation and revision | A local network deny. B `REMOTE_PRE_ADMISSION`. C `POST_EFFECT` plus artifact edge | A errno/no packet. B reject/no write-capability issued. C alert and quarantine exact revision; no local “push denied” claim | Bearer token and Git verb inside TLS are invisible locally; same channel can only be wholly denied | Read-only token clones the allowed repository; approved release token pushes through the semantic gate | `HF-GRAN-DEAD-DROP-001`, `EDGE-ARTIFACT-CONSUMER-005`; `SOURCE-BOUNDARY-001` |
| `HF-014/A intact-local`; `B tampered-or-unknown`; `C mesh-provider` | A exact exec/device/ioctl/capability/socket events and healthy enforcement. B failed link/map/runtime integrity probe. C authoritative mesh request/result | A native/device/network keys. B hard response state. C pre-admission gate or post-effect audit | A forbidden effect errno/no packet. B local prevention claim becomes ineligible and independent fence/alert runs. C only synchronous admission rejects | TUN denial does not cover userspace networking; audit cannot retrospectively stop enrollment | Approved mesh daemon with declared binary, device/ioctl set and destination | `HF-GRAN-MESH-ROOT-001`, `SELF-PROTECT-001`, `NET-SOCKCTL-001`; `KA-CODE-020`, `TG-CODE-007` |
| `HF-015/A mesh-admission`; `B audit-only-existing-devices` | A authenticated key/device enrollment request before commit. B exact key/device IDs, provider result and inventory revision | A `REMOTE_PRE_ADMISSION`. B `POST_EFFECT` plus response coordinator | A reject means no new device. B revoke key and remove every exact device, then read back both postconditions | External host with no mesh source is outside authority; silence is not removal proof | Approved employee device enrolls with an approved key and remains present after readback | `HF-GRAN-MESH-SOCKS-001`, `HF-GRAN-MESH-ENUM-001`; `SOURCE-BOUNDARY-001` |
| `HF-016/A direct-worker-connector`; `B catalog-to-cluster`; `C shared-credential` | A exact worker destination/request. B forwarded request ID or unique lease plus cluster audit. C only shared credential/time | A local network or connector admission. B typed multi-node provider edge. C contextual edge | A deny/reject at its boundary. B exact cause only with forwarded ID. C never upgrades to exact | Missing forwarded ID is `CONTEXTUAL_SHARED_AUTHORITY`, not a Tetragon/KubeArmor defect | Approved connector request carries its request ID into an allowed cluster read | `HF-GRAN-CONNECTOR-DIRECT-001`, `HF-GRAN-CLUSTER-SHARED-001`, `EDGE-CONNECTOR-FORWARD-004`; `TG-CODE-005` |
| `HF-017/A external-AWS`; `B same-worker`; `C acquisition-to-use` | A CloudTrail session/access-key operation. B exact worker STS/private endpoint/socket. C protected inventory, broker lease, or credential fingerprint join | A post-effect authority. B local network plus provider result. C typed credential edge only with join proof | A alerts/responds to exact session. B forbidden socket errno/no packet. C attributes local acquisition only when proof exists | An access-key ID binds AWS use to a credential, not automatically to one Linux reader | Approved deployment role obtains its brokered session and performs declared AWS read/dry-run | `HF-GRAN-AWS-SPLIT-001`, `EDGE-AWS-SHARED-001`, `HF-GRAN-AWS-DRYRUN-001`; `TG-CODE-005` |
| `HF-018/A broker-mint`; `B standard-audit`; `C repo/PR`; `D response` | A connector/broker mint request/result and possessed handle. B documented GitHub audit fields only. C exact repo/commit/tree/PR/workflow IDs. D exact revocable handle or installation ID | A remote admission. B post-effect with capability check. C provider/artifact/CI routes. D authorized response | A rejects/no token. B reports mint `UNSUPPORTED_SOURCE` if absent. C alerts/rejects where gate exists. D revokes possessed token or suspends installation and reads back | Token hash/fingerprint is correlation, not a revocation handle | Approved read-scoped installation token enumerates its declared repo; approved bot PR keeps untrusted CI role | `HF-GRAN-GITHUB-MINT-001`, `HF-GRAN-GITHUB-REVOKE-001`, `HF-GRAN-GITHUB-TREE-PR-001`, `CI-PR-001`; `SOURCE-BOUNDARY-001` |
| `HF-019/A external-loader`; `B managed-generic-exec`; `C trusted-digest-correlation` | A no local identity. B exact memfd/deleted executable/anonymous executable map or destination. C trusted CAS/download/IMA/fs-verity digest joined to consumer | A outside. B native/file/network key. C artifact edge | B generic forbidden exec/map returns errno independent of digest. C may quarantine/deny exact known artifact | No content oracle means no “same payload digest” claim; `mprotect` paths require their own capability | Approved JIT uses its declared anonymous-exec profile; approved signed image digest executes | `HF-GRAN-GITHUB-REARM-001`, `MEM-EXEC-001`, `EDGE-ARTIFACT-CONSUMER-005`; `KA-CODE-002`, `TG-CODE-010` |
| `HF-020/A managed`; `B external`; `C unresolved-location` | A exact node/task/object/device evidence. B exact external provider evidence without local IDs. C hostname/command text only | A local effect/response route. B outside route. C unresolved graph subject | Only A may return errno or restrict lineage. B is outside authority. C is `LOCATION_UNRESOLVED` | Command names and hostname text cannot create a local task identity | Declared local diagnostic role reads only approved proc/host objects | `HF-GRAN-HOST-LOC-001`; `KA-CODE-003`, `TG-CODE-001` |
| `HF-021/A verified-response`; `B silence-only` | A exact response target/revision, actuator authority, request/result, readback and healthy watch interval. B merely no new events | A `ALG-RESPONSE`; B no containment transition | A becomes `verified` only after postcondition and replacement watch. B remains unresolved | Missing source/actuator/readback yields `partial` or `failed`, never contained | A deliberately stopped test branch stays stopped while an unrelated healthy branch continues emitting | `HF-RESP-002`, `HF-RESP-SHARED-DOMAIN-003`; `KA-CODE-023`, `TG-CODE-008` |

This table is deliberately concrete about what **does not** happen. For
example, `HF-013/C` does not ask BPF to parse a Git push inside TLS;
`HF-017/C` does not equate an AWS access-key ID with a particular Linux
reader; and `HF-021/B` does not turn quiet telemetry into containment. Those
are fundamental evidence boundaries, not missing code in KubeArmor or
Tetragon.

##### Walkthrough corrections and incident-boundary clarifications

The earlier heading “Walkthrough corrections for `HF-016` and `HF-017`” is
retained as historical scope; the section also corrects `HF-004`, `HF-009`,
`HF-014`, and `HF-018` and is therefore organized by the following exact
incident boundaries.

###### HF-016: direct connector path

The retained `HF-016` row's phrase “mesh/cluster reachability” is abandoned for
the catalog request itself. The actual direct worker-to-connector path uses
`ALG-NET` even with no mesh, then `ALG-AUTHORITY` fans the shared connector
credential into the two exact cluster branches. Mesh remains a separate source
control/internal-network branch.

###### HF-017: external and same-worker AWS branches

The retained `HF-017` row's external-replay result applies to the documented
external-address branch. For the separate same-worker branch, the strict
configuration denies undeclared STS, database-private-link, and raw exfil
destinations locally; provider/service evidence records whether a request
succeeded or timed out. The implementation must run and assert both fixtures.

###### HF-016: shared credential is not exact local cause

The retained phrase “two exact cluster branches” is exact only for catalog
exposure/configuration and each cluster's own authoritative audit operation.
The local-request-to-cluster-operation cause stays
`CONTEXTUAL_SHARED_AUTHORITY` unless a forwarded request ID, unique lease, or
carried nonce joins it, as defined in the HF-016 correction.

###### HF-018: mint evidence and token revocation handle

The retained `HF-018` walkthrough and granular rows are superseded where they
say GitHub audit-only mode detects token **minting** or that a “known token” is
automatically revocable. Standard audit-only capability marks the mint source
`UNSUPPORTED` unless its documented schema version supplies that event. Exact
mint evidence comes from the connector/broker. Exact token revoke requires the
broker's protected possessed-token handle; an audit hash supports correlation
and expiry watching only. Downstream documented repository-tree, PR, workflow,
or write operations remain independently detectable.

###### HF-014: local enforcement integrity boundary

The retained `HF-014` walkthrough row is also conditional on local enforcement
integrity. Before root/tamper—or after a root shell whose tamper probes fail—the
listed exec/device/network gates are valid. Once a required map/link/runtime or
kernel boundary is modified or unknown, local prevention becomes
`ENFORCER_TAMPERED_OR_UNKNOWN`; only independently controlled mesh admission,
network, credential, and provider responses remain eligible.

###### HF-009: legitimate source reads and opaque publication

The `HF-009` source-read example is role- and object-specific. A conversion
worker may legitimately need its own application source or package metadata;
that object must remain allowed and cannot be called malicious merely because
the compromised interpreter read it. The preventable distinctions are reads
of undeclared proc/credential/host/source objects, writes into the declared
dataset result that violate the result-object contract, and publication over
an undeclared channel. If the exact same allowed source bytes and result API
are necessary for normal conversion, Mithril alerts the behavioral sequence
and governs the later distinguishable effect rather than breaking the worker
or pretending it denied the in-process disclosure.

###### HF-005: a file read does not reveal Python's future interpretation

The retained claim that `ALG-FILE` can classify
`/tmp/submitted_code.c` as executable-code input from that read alone is
abandoned. At the kernel boundary it is an inode/file read; Python may parse,
display, hash, copy, or execute the same bytes without a new `execve`.
`UNTRUSTED_CODE_INPUT` is legal only when `ALG-ARTIFACT` previously bound the
exact live object/content generation to a download, staged payload, untrusted
workspace producer, or reviewed code-input manifest, and that binding is read
in the pre-effect decision. Without it, Mithril may deny the generic file read
by policy or govern later publication/exec/network effects, but must not claim
it prevented Python interpretation.

`HF-005` therefore has three cases: preclassified staged object (read/map
denies), ordinary declared application source (read succeeds positive
control), and unknown mutable file (classifier-unknown posture applies; no
code-semantics claim). The oracle checks exact inode/content generation and
artifact binding, not extension or `/tmp` pathname.

###### HF-004: allowed send is not completed secret publication

The retained HF-004 result `semantic_effect_completed` is abandoned. It did
not name which effect or source proved completion. The executable results are:

| Result | Required proof |
| --- | --- |
| `SEND_ATTEMPT_ALLOWED` | Exact task/socket pre-effect decision returned allow; no packet or publication is implied |
| `PACKET_EMITTED` | Qualified packet-path observation/counter for the exact socket/flow after the allow |
| `PUBLICATION_OBSERVED` | Authoritative capture/result/provider request and successful result joined under its edge contract |
| `PAYLOAD_UNOBSERVABLE` | Channel/publication is known but TLS or missing content provenance prevents a claim about secret bytes |

`HF-004-RESULT-001` runs four branches with the same destination: send hook
allow followed by local failure, packet emission without provider result,
provider-confirmed normal publication, and a TLS-opaque suspected secret
publication. Each must emit only its row's result; none may use the old generic
string.

#### Granular lateral actions published outside the 21-entry stream

The technical timeline describes important actions that the representative
stream groups into broader entries. An implementation and test suite must not
lose them.

| Published action | Practical configuration | Algorithm, proof, and outcome |
| --- | --- | --- |
| Read EC2 node-role credentials from IMDS | `conversion-worker-root -> cloud-imds connect: deny`; legitimate node agent uses a separate role and `allow` plus lease evidence | `ALG-NET` prevents the worker's metadata call. If credentials were already obtained, `ALG-AUTHORITY` identifies their later access-key/role session and cannot claim the earlier read was stopped. |
| Build a presigned STS caller-identity URL and use it as `k8s-aws-v1` node authentication | Worker STS/Kubernetes destinations: `deny`; node-principal Kubernetes behavior outside expected source/operation: `alert` | `ALG-NET` can stop local calls. Kubernetes audit plus AWS session/source evidence lets `ALG-AUTHORITY` join the forged node-auth request; token bytes are never required in evidence. |
| Call TokenRequest for CSI service accounts | If a synchronous Kubernetes authorization integration exists: `reject`; audit-only baseline: `alert` successful `create serviceaccounts/token`, restrict source, and enumerate minted leases | `ALG-AUTHORITY` matches exact caller, namespace, ServiceAccount UID, audience, expiry, request UID, and result. It cannot deny a completed TokenRequest from audit alone. |
| Run `SelfSubjectRulesReview` and enumerate RBAC | Unexpected authority operation: `alert`; optionally reject through a semantic API gate | `ALG-AUTHORITY` records principal and review scope. The result is reconnaissance evidence; it is not a native process transition and does not become permission by observation. |
| Create privileged hostPath Pod | Kubernetes admission integration: `reject` exact Pod request; audit-only: `alert`, add object UID/owner edge, restrict source, and delete/fence only under response approval | `ALG-AUTHORITY` proves request/result. `ALG-XNODE` follows Pod UID to scheduler/binding/node/runtime root. If creation succeeded, “deny” is no longer honest; response is a separate action. |
| Create self-respawning Pods across eleven nodes | `alert` controller/workload creation; `reject` replacements at admission when configured; contain current Pods and owning controller | `ALG-XNODE` represents every node-local tree plus owner/controller edges. `ALG-RESPONSE` watches reconciliation, so deleting current Pods cannot produce a false containment result. |
| Reach node root through a privileged Pod and host mount | Cluster hard-floor profile: deny mount/namespace/device/host-object effects where the protected node can mediate; alert any root with incomplete binding | `ALG-ENTRY` must bind the new Pod root rapidly or pre-exec. `ALG-DEVICE`/`ALG-FILE` deny host effects. A node whose kernel/runtime is already controlled is a lost enforcement trust boundary, not a normal denied effect. |
| Authenticate to internal MongoDB with static environment password | Deny initial environment/credential read and undeclared database destination; if DB access is legitimate, alert database-audit operation deviation | `ALG-FILE` and `ALG-NET` provide earlier gates. `ALG-AUTHORITY` uses database principal/session/query audit where available. Encrypted MongoDB operations are not inferred from packets. |
| Issue 84 credential-store/cluster-key operations that the store denied | `alert` high-rate forbidden operations even though provider result is denied | `ALG-AUTHORITY` records exact provider-side denial and raises sequence priority. It must not say Mithril's kernel denied operations the store itself rejected. |
| Read a Kubernetes Secret containing 136 keys | Semantic API gate: `reject get secret`; audit-only: `alert`, immediately restrict source and enumerate every exposed credential object | `ALG-AUTHORITY` matches principal, verb, Secret UID/resource version, response result, and request UID. One successful Secret read expands the graph to many candidate credential branches; each later use needs exact identity proof. |
| Use a mesh key tagged for CI automation and enroll 181 devices | Provider admission: reject wrong workload/device posture; otherwise alert exact key/tag/device use, revoke key, remove devices | `ALG-AUTHORITY` does not treat the tag name as proof of CI. Signed CI intent plus exact lease is required. `ALG-RESPONSE` separately verifies key revocation and device removal. |
| Run mesh in userspace networking with SOCKS5 and in-memory state | Deny unapproved mesh executable/code, control/data destinations, and local proxy listener even when no TUN device exists | `ALG-DEVICE` alone would miss this path. `ALG-LINEAGE` and `ALG-NET` keep the policy complete; `--state=mem:` only removes a disk artifact. |
| Retrieve a connector catalog through a shared multi-cluster credential | Reject through typed connector policy if available; otherwise alert, disable only proven session/grant where possible, and disclose shared blast radius | `ALG-AUTHORITY` needs source device/principal, connector ID, catalog resource, forwarded request IDs, and result. A shared credential can force broader response but never stronger attribution. |
| Use harvested AWS keys for MongoDB IAM auth and `GetCallerIdentity` | Deny local credential-object read or destination; external calls alert exact AWS session behavior; approved response revokes resolvable lease/session | `ALG-AUTHORITY` uses access-key/session/CloudTrail identity. Network timeout to MongoDB is recorded as failed service access, not prevention by Mithril. |
| Obtain registry token and enumerate VPC/EKS/transit/secrets with cloud role | Alert operations/resources outside authority rule; semantic cloud broker may reject; response scopes to session and changed resources | `ALG-AUTHORITY` distinguishes read, dry-run, denied, and successful calls from provider result. Enumeration is not mislabeled as mutation. |
| Read EdDSA signing key and forge valid identity tokens | Deny signing-key file/Secret object read. Token construction in memory has no kernel semantic hook; alert later token issuance/use deviation and rotate exact key under approval | `ALG-FILE` prevents observable acquisition. `ALG-AUTHORITY` detects a valid but behaviorally unexpected token principal/operation. Cryptographic validity does not equal authorized provenance. |
| Mint GitHub App tokens with write permissions | Typed connector request: reject; GitHub audit only: alert and revoke known token or suspend installation | `ALG-AUTHORITY` matches App, installation, repository set, permissions, actor/request, and result. Direct TLS network policy cannot tell mint from clone. |
| Open a pull request intended to compromise CI and read CI credentials | Source-control rule alerts/rejects unexpected PR/workflow write when semantic gate exists; CI coordinator marks artifact/ref `untrusted_change`; CI runtime denies credential/OIDC/deploy effects | `ALG-ARTIFACT` carries commit/ref provenance into `ci-untrusted-build`; `ALG-INTENT` denies a privileged lease to the unapproved step. Even if CI executes a malicious `build.rs`, its physical credential read/API effects remain denied. |
| Rewrite `/etc/resolv.conf`, append `/etc/hosts`, and pin CDN/API IPs | Deny worker writes to resolver/hosts objects; destination policy still classifies actual IP and service class | `ALG-FILE` stops configuration mutation. `ALG-NET` does not rely on DNS names, so hard-coded IP or monkey-patched resolution does not bypass destination policy. |
| Route a binary through a public CORS proxy or platform Space | Deny unapproved proxy/destination or untrusted code-object load; alert allowed relay use and track downloaded digest | `ALG-NET` sees relay channel; `ALG-ARTIFACT` identifies bytes independently of URL; `ALG-FILE`/`ALG-LINEAGE` prevents execution on managed nodes. |
| Stage an RSA private key and keep dumping process environments | Deny private-key writes outside approved key-management role and cross-process/proc environment reads; restrict lineage and preserve non-secret metadata | `ALG-FILE` records object class, inode/mount identity, and denial without key contents. Already resident environment values remain governed at publication/use. |

##### Adjacent correction: an audit token hash is not a revocation handle

The retained granular GitHub row's phrase “revoke known token” is abandoned
unless the connector/broker actually possesses a protected provider token/lease
handle that the provider accepts for that exact revocation operation. A GitHub
audit hash or token fingerprint is a correlation identifier, not secret token
material and not automatically an actuator key.

The response compiler selects only capabilities it can prove:

- revoke/expire the exact broker-issued installation-token lease when the
  broker owns that handle and readback confirms it can no longer be used;
- otherwise suspend/revoke the installation or installation authorization,
  after displaying the wider repository/user blast radius and obtaining its
  configured approval;
- rotate the underlying App credential only when that exact broader action is
  authorized; and
- in every case inspect/revert/quarantine the proven PR, ref, workflow, or
  artifact separately, because credential response does not undo completed
  source-control effects.

`HF-GRAN-GITHUB-REVOKE-001` has two negative branches—only an audit hash, and
an installation without a per-token revoke API—and one positive broker-handle
branch. The first two must not report exact token revocation; they propose the
disclosed broader action or remain open. Only the last may verify the exact
lease invalidation.

##### Abandoned design: behavior alone reliably detects a valid forged token

The retained EdDSA row is conditional in two ways. First, key acquisition may
be a local file/projected-object read, a successful Kubernetes Secret API
response over TLS, a secret already in memory, or an unknown external path.
Only the first is necessarily an `ALG-FILE` decision. A semantic Kubernetes
gate may reject the second; audit can only report it afterward. The last two
have no acquisition-prevention claim.

Second, the incident's forged valid token was used for attacker-owned private
datasets, behavior that can look ordinary. “Behaviorally unexpected” is a
heuristic, not proof of forgery. Reliable provenance detection requires an
issuer ledger and consumer-visible token identity:

```text
TokenIssuanceLedgerV1 {
  issuer_instance_id
  issuer_key_id: kid
  token_identity: jti | provider_token_fingerprint
  subject
  audiences[]
  scopes_or_claim_digest
  issued_at
  expires_at
  approved_intent_id
  issuance_request_id
  issuance_result
  coverage_interval_id
}

TokenConsumptionObservationV1 {
  consumer_service_id
  cryptographic_validation_result
  kid
  jti_or_same_provider_fingerprint
  subject/audience/scope digest
  provider_request_id
  result
}
```

After the issuance source's maximum lateness watermark, a cryptographically
valid consumption with the same `(issuer, kid, jti/fingerprint)` absent from a
**complete** issuance ledger produces
`VALID_TOKEN_ABSENT_FROM_ISSUANCE_LEDGER`. If legitimate issuance coverage has
a gap, or the consumer omits the joinable token identity, the result is
`FORGERY_UNOBSERVABLE`/contextual behavioral deviation. Rotation of the key is
a typed response with consumer verification, not proof that every forged token
was found.

`HF-GRAN-TOKEN-FORGE-001` issues legitimate token L and independently signs
forged token F with identical subject, audience, scope, and time window but
different `jti`. The consumer validates and uses both. With complete issuance
coverage and consumer `kid+jti`, only F is absent from the ledger. Remove
consumer `jti`, delay an issuance record past the watermark, and inject a
ledger gap in separate runs; each must become `FORGERY_UNOBSERVABLE`, never an
exact forgery finding.

#### Normative granular incident acceptance specification

The preceding published-action table is a human overview, not by itself a
release test. Each executable fixture is represented by:

```text
HfGranularAcceptanceV1 {
  test_id
  published_fact
  upstream_source_evidence_ids[]
  fixture_topology_and_starting_authority
  input_observation_ids_and_exact_fields
  required_coverage_intervals
  minimum_proof_vector: ProofQualityV1
  algorithm_and_policy_generation
  compiled_decision_key_or_package_key
  expected_decision_stage
  expected_disposition
  physical_or_provider_oracle
  legitimate_negative_control
  degraded_or_unsupported_result
  expected_finding_reason_and_proof_vector
}
```

The executable registry populates `upstream_source_evidence_ids[]`; it does not
leave the field to the test author's memory. The table uses these defaults,
augmented by a row-specific ID when the fixture exercises another mechanism:

| Granular fixture family | Required source-evidence cross-reference | Why this source lesson is relevant—and where it is intentionally insufficient |
| --- | --- | --- |
| `HF-GRAN-DEAD-DROP-*`, `HF-GRAN-CI-BUILDRS-*` | `KA-CODE-001`, `KA-CODE-002`, `KA-CODE-003`, `TG-CODE-007`, `TG-CODE-010`, `TG-CODE-011`, `SOURCE-BOUNDARY-001` | KubeArmor validates semantic file hooks and deny/event ordering; Tetragon validates an enforceable LSM path and the staging hazards Mithril must saturate-test. Neither can distinguish a TLS-encrypted publication verb, so the provider boundary remains explicit. |
| `HF-GRAN-HOSTPATH-*`, `HF-GRAN-RESPAWN-*` | `KA-CODE-004`, `TG-CODE-003`, `TG-CODE-004`, `TG-CODE-009` | Runtime/cgroup metadata is useful, but the pinned callbacks do not provide Mithril's held exact root plus all-entry ticket and node-floor transaction. |
| `HF-GRAN-CONNECTOR-*`, `HF-GRAN-AWS-*`, `HF-GRAN-CAPTURE-*` | `KA-CODE-006`, `TG-CODE-007`, `SOURCE-BOUNDARY-001` | Existing network enforcement proves useful socket/destination mechanisms. Exact task role, accepted/existing socket lifetime, encrypted API verb and provider actuation require Mithril's additional contracts. |
| `HF-GRAN-CLUSTER-SHARED-*`, `HF-GRAN-RESPAWN-*` | `TG-CODE-005`, `TG-CODE-008`, `TG-CODE-012`, `KA-CODE-005`, `KA-CODE-010` | Upstream lineage/loss/cache mechanisms inform collection; KubeArmor's attempted fork propagation remains width-unqualified, and none proves a request-to-object-to-node causal edge or complete gap interval without Mithril's request/lease and coverage records. |
| `HF-GRAN-MESH-ROOT-*`, `HF-GRAN-HOST-LOC-*` | `KA-CODE-001`, `KA-CODE-004`, `TG-CODE-004`, `TG-CODE-007`, `TG-CODE-008` | Local hooks can gate pre-tamper effects, but root/kernel compromise ends the local enforcement trust claim; source IDs are not evidence that a compromised node contains itself. |
| `HF-GRAN-GITHUB-*`, `HF-GRAN-TOKEN-FORGE-*`, `HF-GRAN-MESH-SOCKS-*`, `HF-GRAN-OUTSIDE-*` | `SOURCE-BOUNDARY-001`, plus `TG-CODE-005` and `TG-CODE-008` when managed evidence participates | These are primarily provider/external facts. Kernel source lessons constrain honest correlation and gaps; they do not create local task identity or semantic prevention outside authority. |

This is also what “learn from” means operationally: a source ID justifies a
specific adopted mechanism or exposes a tested implementation boundary. It is
never a claim that KubeArmor/Tetragon failed to solve a scenario they did not
promise, and never substitutes for Mithril's physical oracle.

In this table, `kernel-exact` expands to
`KERNEL_DECISION + EXACT_TASK/PROCESS + PRE_EFFECT_DECISION + COMPLETE +
LOCAL_ATTESTED`. `provider-exact` expands to
`AUTHORITATIVE_PROVIDER + the named EXACT_REQUEST/SESSION/OBJECT +
AUTHORITATIVE_SUCCEEDED or AUTHORITATIVE_DENIED + COMPLETE +
AUTHENTICATED_CHANNEL`. Those are exact field values, not “high confidence.”
Any missing axis produces the row's stated degraded result.

| Test ID and real action | Fixture inputs and minimum proof | Compiled control and decision stage | Required oracle and legitimate negative control |
| --- | --- | --- | --- |
| `HF-GRAN-DEAD-DROP-001`: each Pod command returns output through the normal Hugging Face result/dataset API | Labeled worker task, exact sensitive-access bit, actual result socket, repository result/revision when the provider exposes it; kernel-exact for local deny, provider-exact `EXACT_OBJECT` for completed publish | `conversion-worker-root + SENSITIVE_ACCESS_PERMITTED_OR_ATTEMPTED -> result-service send: deny` at `LOCAL_PRE_EFFECT`; if the same channel must remain allowed and payload is TLS-opaque, `ALG-ARTIFACT` emits `PAYLOAD_UNOBSERVABLE` at `POST_EFFECT` | Deny case: send returns configured errno and server receives no fixture marker. Same-required-channel case: no fake deny; authoritative unexpected revision alerts. Ordinary conversion output with no sensitive state succeeds. |
| `HF-GRAN-HOSTPATH-001`: privileged hostPath Pod reaches node root | New never-seen Pod UID, exact CRI request snapshot with privileged/hostPID/host-root mount/capabilities, node admission coverage; signed node-floor policy | `REJECT_UNMATCHED` or exact baseline hard-floor field rejection at runtime `ENTRY_ADMISSION`, before mount/setup | CRI returns typed rejection, no host mount appears, no user marker executes. Exact reviewed CSI DaemonSet exception starts and mounts only its declared paths. Missing admission coverage is `UNSUPPORTED`, never a later file-deny claim. |
| `HF-GRAN-RESPAWN-001`: attacker creates self-respawning Pods across eleven nodes | Two mandatory cases: (A) Kubernetes semantic-admission request/object UID before persistence; (B) already-persisted Pod UID plus scheduler/binding/CRI request, node gate, and eleven node coverage intervals | (A) semantic admission rejects the API request; (B) node/runtime admission rejects or holds every container root/setup while `ALG-XNODE` records the persisted object and `ALG-RESPONSE` restricts existing roots/controller | (A) API object never persists. (B) Pod may remain `Pending`/`Failed`, but no user root, host mount, or marker executes; already-running Pods receive exact cgroup postconditions. No replacement runs during the healthy watch. A normal Deployment rolling update remains allowed. |
| `HF-GRAN-CONNECTOR-DIRECT-001`: conversion worker reaches internal connector without mesh | Exact worker task/socket, destination service identity; authenticated connector request/result ID if semantic evidence exists | `conversion-worker-root -> connector destination: deny` at `LOCAL_PRE_EFFECT`, or typed connector catalog rule at `REMOTE_PRE_ADMISSION`; audit-only is `POST_EFFECT alert` | Connect/send errno and no request at connector, or connector rejects exact request. If allowed TLS plus no connector audit, result is `SEMANTIC_OPERATION_UNOBSERVABLE`. Legitimate connector-service role request succeeds. |
| `HF-GRAN-CLUSTER-SHARED-001`: one catalog exposes a shared `system:masters` credential valid for two clusters | Connector result identifies cluster A/B and credential ID; each Kubernetes audit identifies principal/request/result; forwarded IDs intentionally absent then present | Create `CATALOG_EXPOSED_CLUSTER`, `CREDENTIAL_VALID_FOR_CLUSTER`, and `CREDENTIAL_USED_IN_CLUSTER`; create exact `LOCAL_REQUEST_CAUSED_CLUSTER_OPERATION` only with forwarded ID/unique lease | Both cluster operations are authoritative, but local cause remains `CONTEXTUAL_SHARED_AUTHORITY` without IDs. Adding IDs upgrades only matching edges. Two concurrent legitimate clients are the negative attribution control. |
| `HF-GRAN-MESH-ROOT-001`: rooted managed node runs an HTTPS mesh proxy | Exact managed node/task until tamper, BPF/runtime/link/map integrity intervals, mesh device/session provider result | While integrity remains healthy, deny executable/control socket/device capability. After successful tamper, close local coverage and use provider admission/response only | Denied pre-tamper marker sends no packet. Successful link/runtime tamper forces `ENFORCER_TAMPERED_OR_UNKNOWN`; no local containment claim. Approved node mesh agent under intact enforcement succeeds. |
| `HF-GRAN-MESH-SOCKS-001`: external sandbox runs userspace SOCKS5 mesh with in-memory state and no TUN | Mesh provider device/key/session/request evidence; external subject; no fabricated local task | `ALG-AUTHORITY` post-effect finding/typed provider response; local `ALG-DEVICE` is explicitly inapplicable. If a managed task launches the same mode, exec/listen/control sockets are local gates | Provider shows exact enrollment/device removal/revocation. External process execution remains `outside_authority`. Approved external corporate device is the negative control; absence of TUN must not suppress the finding. |
| `HF-GRAN-MESH-ENUM-001`: 181 devices enroll, then 22 nodes/routes/exit nodes/DNS/CI subnets are enumerated | Exact mesh auth-key/device IDs, operation/result IDs, catalog snapshots and coverage watermark | Rate/cardinality package alerts after configured first/threshold events; response separately revokes enrollment key and removes exact devices | Provider count/state proves 181 devices removed and key cannot enroll a new fixture; route/node inventory is restored/verified. A signed CI automation run within its exact count/window is allowed. |
| `HF-GRAN-AWS-SPLIT-001`: harvested key is used externally and by the same worker for STS, MongoDB, and raw exfil | External CloudTrail session/access-key/source evidence versus kernel-exact worker sockets to STS/private-link/raw endpoint; service result/timeout | External branch is `POST_EFFECT alert/response`; worker branch denies undeclared destinations locally before send; shared key does not merge subjects | External API result remains provider-confirmed only. Worker socket calls return errno/no packet. Mongo timeout is `FAILED_BY_SERVICE`, not Mithril prevention. Approved controller STS call succeeds. |
| `HF-GRAN-AWS-DRYRUN-001`: cloud mutation is attempted with `DryRun=True` | Exact CloudTrail event name, `dryRun` request field, principal/session/resource, error/result such as provider-authorized dry-run response | Versioned AWS vocabulary classifies `ATTEMPTED_AUTHORIZATION_CHECK`, not completed mutation; semantic broker may reject at `REMOTE_PRE_ADMISSION`, audit-only alerts | Provider resource state remains unchanged and finding records the exact dry-run result. A denied call and a successful real mutation are different expected result classes. Approved deployment planner dry-run is the negative control. |
| `HF-GRAN-GITHUB-MINT-001`: connector mints write-capable installation token | Broker request/result with App/installation/repos/permissions and protected handle, or standard GitHub audit-only capability with no mint event | Broker rule rejects mint or records exact lease; audit-only returns `UNSUPPORTED_SOURCE` for mint. Downstream documented operations remain separate package keys | Rejected broker call yields no token. Possessed handle revokes its token; audit hash alone is ineligible. Approved read-scoped token mint succeeds. |
| `HF-GRAN-GITHUB-TREE-PR-001`: enumerate repository trees and open a CI-triggering PR | Documented GitHub operation/request/result, repository/commit/tree/PR IDs, workflow/ref trust and CI coordinator proof | `POST_EFFECT alert` from supported GitHub audit/API state or semantic gate rejection; `ALG-ARTIFACT` marks commit/ref `untrusted_change`; CI assigns `ci-untrusted-build` | PR/commit/workflow state is enumerated exactly; protected CI leases are absent/rejected. Normal bot tree read and approved dependency PR are negative controls. No audit event means coverage insufficient, not benign. |
| `HF-GRAN-GITHUB-REARM-001`: repeated fresh installation tokens retrieve payloads into fresh sandboxes | One broker lease/fingerprint/expiry per token, immutable payload digest/revision, each consumer subject and provider request; external consumers may remain outside authority | Cardinality/window package creates separate token/payload/consumer branches; revoke possessed leases, quarantine exact revision/digest, deny execution only on managed nodes | Every known token expires/revokes and every managed execution marker is absent; unknown external consumers keep containment partial. Normal token rotation without malicious digest is the negative control. |
| `HF-GRAN-TOKEN-FORGE-001`: valid EdDSA token absent from issuer ledger | Complete issuance coverage past watermark plus consumer `kid+jti`/same fingerprint and validation result | `VALID_TOKEN_ABSENT_FROM_ISSUANCE_LEDGER` at `POST_EFFECT`; missing join or gap gives `FORGERY_UNOBSERVABLE` | Legitimate token L exists in ledger; forged F with identical claims does not. Removing `jti` or coverage forces unknown. This is never inferred from behavior alone. |
| `HF-GRAN-CAPTURE-001`: 100+ single-use endpoints/raw sockets collect command output | Exact managed task/socket per endpoint where available, destination/packet coverage, external endpoint/provider records, response-set membership | Local unapproved creates/connects/sends deny; package counts immutable endpoint IDs and fans response; external endpoints remain provider/network response subjects | Managed sends return errno/no packet; authorized actuator disables each exact endpoint and watch sees no reuse. One approved telemetry endpoint remains functional. Source-IP/time-only joins remain contextual. |
| `HF-GRAN-CI-BUILDRS-001`: malicious `build.rs` uses its own CI credential | CI1 exact step process when supported, delivery class `ENV_MEMORY|PROJECTED_FILE|BROKER_LEASE`, provider operation result, artifact/source digest | Environment token already in memory has no file-read deny; deny broker lease/file open/endpoint where distinguishable, otherwise provider write alerts. `ci-untrusted-build` cannot receive new privileged lease | Projected-file and broker cases deny/reject physically. Environment-token same-TLS clone/push case is `SEMANTIC_AUTHORITY_ISOLATION_UNAVAILABLE` unless provider/gate distinguishes write. Trusted build positive control uses exact read-only lease. |
| `HF-GRAN-OUTSIDE-001`: reconnaissance/payload preparation `HF-001`–`HF-007` occurs outside managed estate | Source-faithful external/provider observations with all local node/task fields absent | Create external subjects and contextual/provider findings only; no kernel algorithm or local response target is invented | Expected result is `outside_authority` with named available provider response. Replaying the first locally distinguishable effect on a managed fixture exercises its real hook. |
| `HF-GRAN-HOST-LOC-001`: `HF-020` location is managed, external, or unresolved | Three variants defined in the HF-020 correction with exact local evidence, exact external evidence, or location fields absent | Local file/device/privilege deny only for managed exact variant; other variants are `outside_authority` or `LOCATION_UNRESOLVED` | Only managed syscall returns errno. Same `readelf`/hostname text never upgrades the other two variants. A declared local diagnostic read succeeds. |

Every row is expanded into a machine fixture with canonical input artifacts;
the table is not satisfied by an alert screenshot. CI stores syscall return,
unchanged/changed output buffers or files, packet capture/drop counter,
provider request/result and final resource state, coverage intervals, policy
generation, and graph/finding digest. A row whose required provider adapter or
kernel hook is absent must produce its named degraded result and make the
corresponding product claim unavailable.

##### Abandoned design: every malicious CI credential read is locally denyable

The `build.rs` row's final sentence and the end-to-end phrase “mounted
credentials ... deny” are too broad when read as universal guarantees. The
delivery mechanism decides what is observable:

| Credential delivery | Earliest honest control |
| --- | --- |
| Job environment/context already copied into process memory | No file-read denial; govern OIDC/token endpoint, provider operation, egress, and alert payload-unobservable exposure |
| Projected/mounted file not already open | Exact file-object open/read policy can deny when hook coverage is qualified |
| Inherited/pre-opened/passed descriptor | Sender/read permission and later effects only where covered; open denial alone is insufficient |
| Brokered per-step lease | Reject issuance/use at broker and deny lease object to other roles |
| Read-only provider token | Provider prevents write even over the same TLS endpoint; verify effective permissions |
| Write-capable job token plus same required TLS endpoint | No read/write semantic prevention without gate; provider audit detects write, or whole channel is denied |

Thus a malicious `build.rs` using an already resident write token may read it
without a new kernel effect. `ALG-INTENT` can deny a **new** privileged lease,
but cannot revoke memory. The old unconditional sentence is abandoned.

**CI credential tests.** Run identical malicious build code with an environment
token, unopened projected file, inherited fd, broker lease, and read-only
token. Assert the exact result above. For the environment/write-token case,
clone and push use the same TLS endpoint; only provider write evidence or a
semantic gate distinguishes them.

#### End-to-end configured resolution of the production branch

The following walk-through shows how several valid configurations change the
same incident path without changing the underlying attribution facts.

1. The runtime admits the reviewed conversion image as
   `conversion-worker-root`. `ALG-ENTRY` and `ALG-LINEAGE` install exact task
   identity before the interpreter runs.
2. HDF5 resolves an external raw-data path to `/proc/self/environ`.
   - With `disposition: deny`, `ALG-FILE` returns `EACCES`; the incident branch
     stops before `HF-009` and the finding says `prevented`.
   - With `disposition: alert`, the read succeeds, a sensitive-state bit is
     set, and the finding says `semantic_effect_completed`; later publication
     still receives a separate decision.
3. Jinja executes inside Python. No new entry, fork, or exec is invented. When
   Python opens the projected token, `ALG-FILE` evaluates the same exact task.
   A strict token rule denies it. If a deployment has configured that worker
   to read the token, the read is allowed or alerted and creates a credential
   acquisition edge; this does not authorize arbitrary Kubernetes behavior.
4. Python connects to Kubernetes/IMDS.
   - A worker with no declared need is denied locally by `ALG-NET`.
   - A controller role with legitimate channel access proceeds; provider audit
     reaches `ALG-AUTHORITY`, which can alert an unexpected TokenRequest,
     Secret read, or privileged-Pod creation.
5. If a Kubernetes semantic admission integration is configured, the
   privileged-Pod request is `reject`ed before persistence. If only audit is
   configured and the API reports success, Mithril alerts, restricts the
   source, builds the object/controller/binding/runtime graph, and contains
   the created branch. It never rewrites that result as a deny.
6. Every new Pod root on another node is separately bound by `ALG-ENTRY`.
   `ALG-XNODE` connects it through request UID, Pod UID, owner, scheduling,
   binding, and runtime evidence, never through a cross-node parent PID.
7. Mesh, AWS, connector, and GitHub uses that occur externally are evaluated
   from exact provider identities by `ALG-AUTHORITY`. A configured provider
   pre-admission path can reject a future operation; audit-only paths alert and
   invoke authorized `ALG-RESPONSE` actions after completion.
8. A malicious source-control change entering CI retains its commit/artifact
   trust. The CI coordinator and node enforce `ci-untrusted-build`; the build
   may compile and test, while mounted credentials, OIDC audiences, runner
   control, deployment API, and repository write effects deny or reject as
   configured.
9. Containment remains `partial` until local lineages, controllers,
   credentials, mesh devices, connector sessions, repositories/artifacts, and
   provider watch coverage each satisfy their physical postcondition.

Step 8 is interpreted through the credential-delivery matrix above. “Deny or
reject as configured” is a capability-conditional result, not a promise that
environment-resident secrets or same-TLS semantic writes always have a local
pre-effect hook.

Step 2's retained `semantic_effect_completed` phrase means only the exact
file/read/publication result proven by its hooks. It is superseded by the
`PUBLICATION_OBSERVED|SUSPECTED_SENSITIVE_PUBLICATION|CONFIRMED_EXFIL|
PAYLOAD_UNOBSERVABLE` vocabulary above and cannot imply payload semantics.

##### Abandoned correction: a file read is not a publication result

The retained correction immediately above is itself wrong because it maps one
file operation directly to publication vocabulary. For the
`/proc/self/environ` branch, Version 1 emits only the strongest independently
proven file result:

- `FILE_ACCESS_ATTEMPT_ALLOWED` when the LSM pre-effect decision allowed;
- `FILE_DESCRIPTOR_OPENED` when an exact open-result join proves fd creation;
- `SENSITIVE_BYTES_READ` only when the qualified post-read matrix proves a
  positive byte count for the exact descriptor/object; or
- `FILE_OPEN_PREVENTED` when the pre-effect deny and syscall result agree.

A later `write`/`send` is a new publication decision and receives
`SEND_ATTEMPT_ALLOWED`, `PACKET_EMITTED`, `PUBLICATION_OBSERVED`,
`SUSPECTED_SENSITIVE_PUBLICATION`, `CONFIRMED_EXFIL`, or
`PAYLOAD_UNOBSERVABLE` according to its own physical/provider proof. The graph
may relate the two events through exact process/domain state, but it never
renames the file read as publication. `HF-011-READ-RESULT-001` executes open
allow/fail, zero-byte read, positive read, later failed send, emitted packet,
and provider-confirmed publication and asserts each result appears only at its
own boundary.

This is the central configuration rule: the operator may choose to observe,
alert, prevent, or reject where the mechanism supports it, but configuration
cannot change task identity, evidence quality, authority boundary, or whether
the effect had already happened.

<a id="part-vii-qualification"></a>

## Part VII — Acceptance, Failure, And Performance Qualification

### Kubernetes External-Entry Acceptance Matrix

The following tests are mandatory before a runtime/kernel combination can
claim full protected-entry support.

| Test | Setup and adversarial variation | Expected proof |
| --- | --- | --- |
| `ENTRY-START-001` | Hold a new container in runtime-created state; delay/wrong-profile/drop admission ack | Configured executable never begins without exact ack in strict mode; observe mode records the gap and continues |
| `ENTRY-POSTSTART-001` | PostStart races entrypoint in both observed orders | Two independent admitted roots, no fabricated parent, correct roles regardless of ordering |
| `ENTRY-POSTSTART-002` | Kubelet restart causes duplicate PostStart delivery | Separate idempotent/repeated entry instances within policy budget; no stale nonce reuse |
| `ENTRY-PRESTOP-001` | Trigger deletion while policy and an active response root exist | Enforcement remains installed; configured containment-vs-cleanup rule wins; termination alone grants nothing |
| `ENTRY-PROBE-001` | Run startup, readiness, and liveness exec probes concurrently with identical and different commands | Exact reason when extension exists; otherwise only same-budget conservative classification; unequal ambiguity denies |
| `ENTRY-PROBE-002` | Application child executes the exact probe binary/argv at the expected cadence | It retains native child lineage/role and cannot claim external probe intent |
| `ENTRY-NETPROBE-001` | HTTP, TCP, and gRPC probes hit the Pod | No synthetic in-container probe task; host flow and application receive remain correctly scoped |
| `ENTRY-SLEEP-001` | PostStart/PreStop sleep action | No in-container task appears; kubelet lifecycle evidence only |
| `ENTRY-EXEC-001` | `kubectl exec`, TTY/non-TTY, and `kubectl cp` | Administrative entry role and `pods/exec` audit correlation; default deny/approval honored |
| `ENTRY-EXEC-002` | Direct `crictl exec` with the same command as a probe | Host-admin/unknown runtime entry, never exact kubelet-probe role |
| `ENTRY-EPHEMERAL-001` | Add ephemeral container targeting app PID namespace | New container execution set, API actor evidence, separate profile; shared PID namespace does not merge native trees |
| `ENTRY-CONTAINERS-001` | Init, native sidecar, and app containers share Pod network and volume | Independent roots/profiles and correct shared-resource evidence |
| `ENTRY-MIGRATE-001` | Move an unlabeled task into protected cgroup or use `nsenter` | First protected effect denied without valid pending intent |
| `ENTRY-REUSE-001` | Reuse PID, namespace number, cgroup ID/path, container name, and Pod name over time | Live interval/full IDs prevent the old profile/response from attaching to the new subject |
| `ENTRY-RESTART-001` | Restart kubelet, runtime, and `mithril-node` at every admission state | Pending intents reconcile or expire; no task executes with a stale/duplicate role; exact coverage transition recorded |
| `ENTRY-LOSS-001` | Drop runtime-intent message or BPF entry event independently | Strict task denied or container held; event loss cannot relax enforcement; loss counter closes coverage |

For every case the test captures:

- runtime/containerd or CRI-O version;
- kernel, BTF, LSM ordering, helper, and hook capability record;
- Pod UID/resourceVersion, full container ID, cgroup live interval, image digest;
- entry nonce/classification/role/claim result;
- task/process/exec cookies and native coordinate history;
- physical syscall/runtime result; and
- coverage and loss state.

### Effect And Bypass Acceptance Matrix

| Family | Required bypass cases | Required physical assertion |
| --- | --- | --- |
| Exec | execveat, fexecve, memfd, deleted file, scripts, dynamic linker, renamed/bind-mounted binary, overlay copy-up, non-leader exec | prohibited image never begins; allowed immutable image receives exact result role |
| File | symlink, hardlink, rename, bind mount, proc-fd alias, projected token rotation, inherited/passed fd, mmap, `io_uring` | claimed operation returns denial before data/effect; uncovered pre-opened-memory cases named |
| Network | DNS/hard-coded IP, IPv4/IPv6, UDP, raw/packet, inherited/passed socket, established TLS, sendfile/splice, TUN/AF_XDP/BPF redirect | prohibited connect/send/packet is physically absent; established-flow fence separately proven |
| Device | mknod, open, major/minor aliases, TUN, GPU/FUSE/KVM, approved vs unapproved ioctl | cgroup device/file/ioctl result matches exact role rule |
| Security | setuid/file caps, credential change, ptrace, setns/unshare, mount, BPF, perf, module, keyring, seccomp weakening | selected pre-effect hook returns deny; unsupported operation downgrades tier |
| Identity | fork without exec, clone thread, vfork, non-leader exec, reparent, parent exit, PID/cgroup reuse, bootstrap | exact stable cookie/role or explicit gap; no userspace labeling window |
| Evidence | ring full, CPU sequence gap, WAL full, node/control outage, generation switch, BPF-link loss | enforcement result unchanged; negative conclusions prohibited across gap |

These are code-backed fixtures. A shell transcript or alert text is supporting
evidence, not the pass condition.

The retained matrix is extended by two corrections. Exec/file qualification
must include `file_mprotect` transitions from writable/anonymous/memfd mappings
to executable. The “seccomp weakening” security case is replaced, as defined
earlier, by proof that the required floor existed before user mode, cannot be
silently omitted, and that unapproved ptrace or seccomp-user-notification
supervisors are denied. The old phrase remains a documented abandoned test,
not an implementation requirement.

The Evidence row's combined “BPF-link loss -> enforcement unchanged” reading
is also abandoned. The acceptance suite splits these faults:

| Fault | Physical expectation |
| --- | --- |
| Ring reservation/event transport pressure | Previously computed local result is unchanged; coverage gaps |
| Rust daemon/control connection loss | Pinned programs/maps continue existing decisions; userspace-dependent new admissions reject |
| bpffs pin pathname loss while live program/map references remain | Existing kernel object may continue; restart/recovery guarantee is unhealthy and must be repaired/tested |
| Enforcement link detach | That hook no longer enforces; affected family becomes `PROTECTION_UNKNOWN`; only an independently installed guard may fence/freeze |
| Required map entry missing while link/program remain | Program follows its qualified missing-entry fail-closed result; affected identity/classifier coverage records the miss |
| Whole required map replaced/lost | Link/map integrity fails, affected family is unknown, and new strict admission rejects |

Each fault is injected independently. Tests may claim “enforcement result
unchanged” only for the first two and for a specifically qualified
missing-entry fail-closed path—not for link detach.

#### Pinned-source boundaries carried into qualification

These are not generic comparisons. The exact code observations in Part II
force exact downstream tests:

| Pinned evidence | Required fixture/result in Parts VI–VIII | Why the upstream mechanism alone is short of this claim |
| --- | --- | --- |
| `KA-CODE-025` | `NET-DNS-EXFIL-001` sends short, malformed, compressed, multi-question, long-name, split-iovec, TCP, non-53, DoT/DoH and literal-IP cases; unknown parsing still hits an IP/destination deny floor | the pinned parser assumes specific first-buffer/QNAME framing, ignores one read/parser result, and emits a bounded name; it is a useful parser fixture, not a complete destination authority oracle |
| `KA-CODE-026`, `KA-CODE-027`, `TG-CODE-024` | `SOURCE-KA-CAPACITY-005`, `SOURCE-TG-EXEC-MAP-007`, `DECISION-SET-GOLDEN-001`, and task/process N/N+1 cases exhaust every authoritative map and try missing/evicted state | KubeArmor's checked exec context is LRU and its policy maps are bounded; Tetragon deliberately preserves a selector-independent action with unknown process state. Mithril adopts the hostile tests but never grants a role from missing state and never activates a partial generation |
| `KA-CODE-028` | `SOURCE-KA-READER-LOSS-003`, sole-gatherer reader death, closed/nil reader, `LostSamples`, and WAL gap cases | the pinned reader logs/continues, drops lost samples, or exits depending on the path; one daemon-ready bit cannot prove a healthy negative interval |
| `TG-CODE-023` | `SOURCE-TG-RUNTIME-JOIN-006`, `ENTRY-CLAIM-TRANSACTION-004`, and `ENTRY-PROBE-IMPERSONATION-003` mix Pod/container/cgroup identities, replay metadata, and race identical roots | the pinned runtime path provides useful local metadata transport but no signed nonce/expiry/one-use held-task proof, and accepts identity fields from separately supplied inputs. Mithril authenticates and joins them before release |

A failing row changes the exact claim vector to `UNSUPPORTED` or
`INSUFFICIENT_COVERAGE`; it cannot be waived because another upstream project
has a similarly named feature.

### Failure-State Architecture

| Failure | Observe mode | Protect mode | Claim effect |
| --- | --- | --- | --- |
| No BPF LSM or required helper/hook | Record unsupported capability and continue observation available from weaker hooks | Do not bind profile requiring the missing prevention; optionally deny workload start if operator selected strict tier | Cannot advertise equivalent prevention |
| Runtime start gate unavailable | Bind after start as `bootstrapped` with gap | Reject strict admission or use a separately proved fallback | No enforce-from-first-exec claim |
| Unlabeled task in protected cgroup | Record orphan/identity defect | Deny first protected effect | No exact lineage conclusion until recovered |
| Missing parent label at fork | Mark child lineage incomplete | Install restrictive unknown label or deny creation/effect | Never skip silently as benign |
| Pending entry ambiguous | Record all candidates and classification gap | Deny unless all candidates have explicitly identical approved budget | No exact lifecycle/probe claim |
| Ring-buffer reservation fails | Increment loss counter and close evidence interval | Same, while returning already computed deny/allow | Enforcement may remain healthy; evidence is incomplete |
| Rust process/control connection lost | Continue from pinned policy, spool health/evidence if possible | Continue in-kernel policy; reject new admissions that require userspace | Central response/new policy unavailable; existing deny not relaxed |
| BPF link/map lost or verifier probe fails | Mark affected hook unavailable | Deny new strict admissions and apply approved safe state to existing bindings | Required prevention coverage unhealthy |
| Policy generation compile/probe fails | Keep prior generation | Keep prior generation; reject update | No partial generation activation |
| Local WAL full | Apply retention/backpressure policy and expose gap before destructive overwrite | Local enforcement continues; strict evidence-dependent claims stop | No “safe”/“contained” conclusion across lost interval |
| Kubernetes/provider audit unavailable | Local effects continue | Same | Same-channel semantic deviations and distributed edges become unknown/contextual |
| Runtime/kubelet restart | Reconcile live containers/tasks and pending entries with explicit gaps | Preserve pinned bindings; expire/revalidate intents before new exec | No stale entry nonce or lifecycle classification |
| Node reboot | New node boot and label epoch; prior subjects close | New admission required | Old response keys cannot target new tasks |
| `ProcessSecurityState` or `AuthorityDomainState` missing, corrupt, version-mismatched, or capacity-exhausted | Mark the exact task/domain and effect interval incomplete; never authorize from cache | Deny affected protected effects; reject new strict admission into that domain; an independently authorized freeze may hold existing members | No role, taint, shared-resource, or process-scoped response claim from missing state |
| Cross-entry topology/merge incomplete or interrupted | Retain separate subjects and report the unproved shared channel | Keep user tasks held when pre-release, deny a dynamic cross-domain channel, and preserve every already-committed restriction; never roll back half a merge to broader authority | No cross-root laundering-prevention or process-only blast-radius claim |
| VMA snapshot BEGIN/RECORD/END stream partial, mm cookie/sharer set changed, or freeze failed | Keep positive observed VMAs and mark the negative snapshot incomplete | Do not use the snapshot to relax policy; retain existing restrictions or reject the requested exact response/admission | `VMA_SNAPSHOT_INCOMPLETE`; absence of a mapping is unproved |

#### Abandoned design: a lost enforcement mechanism applies its own safe state

The BPF-loss row's phrase “apply approved safe state” is wrong if it means the
detached program or missing map can enforce that state. The lost family cannot
prove its own replacement behavior. That interpretation is abandoned.

Health is tracked independently for `entry`, `task_identity`, `process_state`,
`authority_domain`, `cross_entry_topology`, `vma_snapshot`, `exec`, `file`,
`network_lsm`, `packet_fence`, `device`, `privilege`, and `evidence` families,
including exact required link/map/program/durable-state digests. On loss:

1. an independently healthy runtime admission gate rejects new strict entries;
2. existing bindings become `PROTECTION_UNKNOWN` for the lost family;
3. a separately qualified actuator may freeze the cgroup or apply a still-live
   packet fence, with its own blast radius and readback;
4. no finding claims denial by the absent family;
5. recovery reattaches the exact program/maps, reads them back, runs isolated
   qualification probes, reconciles live tasks/sockets, and opens a new healthy
   coverage interval before admission resumes.

**Practical test.** Detach only the file-LSM link while TC remains healthy.
Mithril can verify an egress fence if authorized, but file protection is
`UNKNOWN`; a token-open attempt cannot be reported prevented. After reattach,
the controlled file-deny fixture and live-task reconciliation must pass before
file coverage becomes healthy.

#### Correction: evidence behavior while the sole Rust gatherer is down

The failure row's “spool health/evidence if possible” cannot mean disk spooling:
with the only userspace gatherer dead, no component drains the ring buffer or
writes the WAL. Pinned links/maps keep already compiled decisions. Detailed
records survive only up to bounded ring capacity; thereafter requested records
drop and pinned counters/claim tombstones preserve the gap/replay facts.

Runtime clients whose admission needs userspace fail closed when the local
socket disappears. On restart, `mithril-node` verifies exact live link,
program, map, and pin identities; reconciles kernel claim tombstones/tasks and
counter gaps into WAL; drains what remains; and only then reopens admission.
Loss of a bpffs pathname is distinguished from actual link detach because
objects may remain alive through other kernel/file-descriptor references.

### Performance And Boundedness

#### Fast-path correctness and cost model

The architecture is intended to replace ptrace-heavy steady-state mediation.
That does not make every BPF design cheap. Each hot hook must have bounded map
lookups and no central round trip.

The expected fast path is:

```text
current cgroup binding lookup
  + task-storage lookup
  + response-root lookup
  + one compact role/effect decision lookup
  + optional socket/object lookup
  + best-effort fixed-size ring record only when policy requests evidence
```

##### Abandoned design: cgroup-first fast path

The retained fast-path list is an accounting sketch, not executable order; its
first two lookups are reversed and that order is abandoned. The measured
implementation starts with `task-storage lookup`. If a protected label exists,
it resolves the label's expected root binding and validates current placement,
then performs response/rule/object lookups. Only an unlabeled task starts with
cgroup root/ancestor admission. Performance tests measure these two branches
separately and include a labeled task moved to a host cgroup; optimizing that
case into host allow is a correctness failure, regardless of latency.

The normative labeled-task hot path, in exact authority order, is:

```text
1. preserve a nonzero prior BPF-LSM return
2. task-storage lookup -> immutable TaskLabelV1
3. process_state_map[label.process_state_id] -> authoritative role/execution
4. authority_domain_map[process.authority_domain_id] -> shared restrictions,
   sensitive state, response-set ID and retained generations
5. resolve/validate expected protected-root CGRP_STORAGE binding nonce and
   current placement; a moved labeled task never reaches host allow
6. resolve effective response set/root and required object/socket/device state
7. lookup the exact role/effect/object/state decision in the task's retained
   profile generation
8. intersect actor result with domain, response, object/socket lifetime and
   prior security results
9. atomically commit any monotonic process/domain/object state transition
   before returning allow; fail the effect if a required CAS/state allocation
   fails
10. emit a fixed bounded record only after the physical result is fixed
```

The unlabeled branch performs the bounded protected-root/ancestor lookup, then
claims one exact staged external entry or fails closed. It never skips the
process/domain lookup after a label is installed. Performance qualification
records lookup count and latency for both branches and for state-changing
versus read-only decisions.

The compiler resolves path trees, selectors, PodSpec interpretation, image
metadata, DNS/service inventory, provider rules, and conflicts outside the hot
path. BPF path/object extraction is performed only for hooks whose rule table
requires it. In-kernel filtering suppresses unneeded allowed events while
coverage counters remain observable.

#### Qualification methodology and release artifact

Phase 0 sets numerical budgets for:

- median and tail overhead on exec, open, connect/send, and fork;
- maximum policy map memory per node/container/profile generation;
- task/socket storage capacity and exhaustion behavior;
- process-state, authority-domain, response-set, cross-entry topology, VMA
  snapshot, and mm-cookie map capacity, lookup count, reference churn, CAS/spin
  contention, and fail-closed exhaustion behavior;
- maximum role depth, ancestor vector, argv/path extraction, and tail calls;
- ring/WAL throughput and intentional stress loss;
- runtime admission latency for container start and repeated exec probes; and
- baseline application success, probe timing, Pod startup, and shutdown.

The intent and CI extensions add budgets for:

- signature verification, replay lookup, and staging latency for runtime,
  lifecycle, CI-step, approval, and authority-lease proofs;
- maximum pending-proof count per node, issuer, workload, CI run, and policy
  generation, including deterministic expiry and overload behavior;
- maximum concurrently claimable identical operations without ambiguous
  cross-claiming;
- CI matrix/fan-out graph, artifact/cache handoff, and provider-audit event
  throughput; and
- coordinator or identity-provider outage behavior without silently converting
  a missing proof into an allow.

Every qualified platform publishes this required artifact:

```text
PerformanceQualificationV1 {
  qualification_id
  platform_support_manifest_digest
  cpu_model_microcode_and_count
  memory_and_numa_layout
  kernel_build_btf_and_boot_args
  lsm_order_and_bpf_object_digests
  runtime_and_kubernetes_versions
  workload_fixture_digest
  policy_fixture_digest
  evidence_mode
  operation_and_concurrency
  warmup_iterations
  measured_iterations
  baseline_distribution { p50, p95, p99, max }
  protected_distribution { p50, p95, p99, max }
  added_latency_distribution
  node_cpu_budget_and_observed
  node_memory_budget_and_observed
  map_capacity_and_peak
  event_requested_emitted_lost
  admission_latency_distribution?
  signed_thresholds
  result: PASS | FAIL | INSUFFICIENT_SAMPLES
}
```

##### Abandoned design: untyped composite qualification fields

The retained record cannot be serialized consistently: fields such as
`operation_and_concurrency`, `map_capacity_and_peak`, and `signed_thresholds`
have no closed shape, and the later ledger refers to undefined capability and
performance bundles. It is retained as a requirements list, but the release
wire types are:

```text
CapabilityRecordV1 {
  capability_id
  capability_schema_version: u32
  platform_support_manifest_digest: DigestV1
  product_build_digest: DigestV1
  node_or_fixture_platform_id
  probe_input_digest: DigestV1
  observed_kernel_runtime_result_digest: DigestV1
  state: SUPPORTED | UNSUPPORTED | DEGRADED | UNHEALTHY
  reason_code
  measured_at_utc_ns: i64
}

CapabilityBundleV1 {
  bundle_version: 1
  architecture_revision_digest: DigestV1
  product_build_digest: DigestV1
  platform_support_manifest_digest: DigestV1
  capability_records[]: sorted unique CapabilityRecordV1 by capability_id
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}

LatencyDistributionV1 {
  unit: NANOSECONDS
  sample_count: u64
  p50: u64
  p95: u64
  p99: u64
  maximum: u64
  histogram_artifact_digest: DigestV1
}

OperationPerformanceRecordV1 {
  operation_id: FORK | EXEC | OPEN | CONNECT | UDP_SEND |
                ESTABLISHED_TCP_SEND | PACKET_FENCE | ENTRY_ADMISSION |
                INTENT_VERIFY | OTHER_REGISTERED
  operation_registry_id?: u32
  concurrency: u32_nonzero
  evidence_mode_id
  state_transition_mode: READ_ONLY | MONOTONIC_TRANSITION | CONTENDED_CAS
  warmup_iterations: u64
  measured_iterations: u64
  baseline: LatencyDistributionV1
  protected: LatencyDistributionV1
  added: LatencyDistributionV1
  cpu_time_ns: u64
  peak_resident_bytes: u64
  requested_events: u64
  emitted_events: u64
  lost_events: u64
  threshold_record_id
  result: PASS | FAIL | INSUFFICIENT_SAMPLES
}

CapacityPerformanceRecordV1 {
  resource_kind: BPF_MAP | RING | WAL | PENDING_INTENT |
                 AUTHORITY_DOMAIN | PUBLICATION_SLOT | OTHER_REGISTERED
  resource_registry_id?: u32
  configured_capacity: u64
  largest_successful_cardinality: u64
  first_failed_cardinality: u64
  peak_bytes: u64
  expected_exhaustion_result
  observed_exhaustion_result
  health_transition_result
  result: PASS | FAIL | INSUFFICIENT_SAMPLES
}

PerformanceQualificationRecordV1 {
  qualification_record_id
  platform_support_manifest_digest: DigestV1
  product_build_digest: DigestV1
  cpu_microcode_memory_numa_digest: DigestV1
  kernel_btf_boot_lsm_digest: DigestV1
  runtime_kubernetes_digest: DigestV1
  bpf_object_set_digest: DigestV1
  workload_fixture_digest: DigestV1
  policy_fixture_digest: DigestV1
  signed_threshold_set_digest: DigestV1
  raw_sample_bundle_digest: DigestV1
  operation_records[]: sorted unique by
    (operation_id, operation_registry_id, concurrency,
     evidence_mode_id, state_transition_mode)
  capacity_records[]: sorted unique by
    (resource_kind, resource_registry_id)
  aggregate_result: PASS | FAIL | INSUFFICIENT_SAMPLES
}

PerformanceQualificationBundleV1 {
  bundle_version: 1
  architecture_revision_digest: DigestV1
  product_build_digest: DigestV1
  platform_support_manifest_digest: DigestV1
  records[]: sorted unique PerformanceQualificationRecordV1
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

Both bundles use deterministic CBOR and Ed25519. Their signature input is
`ASCII("MITHRIL-CAPABILITY-BUNDLE-V1") || 0x00 ||
SHA-256(canonical_unsigned_bundle)` or
`ASCII("MITHRIL-PERFORMANCE-BUNDLE-V1") || 0x00 ||
SHA-256(canonical_unsigned_bundle)`, respectively. The unsigned view omits
`canonical_payload_digest`, `signer_key_id`, and `signature`; the signed record
stores the recomputed digest. Unknown operation/resource IDs require a checked-
in registry entry and change its digest. `aggregate_result=PASS` iff every
required operation and capacity record is `PASS`, all threshold IDs belong to
the exact platform manifest, and the bundle/build/platform digests agree.

**Concrete record.** The open benchmark has two
`OperationPerformanceRecordV1` rows for concurrency 1 and 32, each with
1,000,000 measured iterations after 100,000 warmups. The `BPF_MAP` capacity row
records success at N, the exact N+1 errno/health transition, and peak bytes.
An average latency or a capacity number without the N+1 result cannot satisfy
the bundle.

The benchmark pins the workload, pre-faults maps, records warm-up separately,
and alternates baseline/protected trials to reduce drift. It reports raw
sample artifacts or a reproducible histogram, not only an average. Every
operation (`fork`, exec, open, connect, UDP send, established TCP send/packet,
and each admission path) has explicit p50/p95/p99/max, CPU, memory, and loss
thresholds in the platform manifest. “No threshold yet” means the platform
cannot advertise full support.

Map-capacity and ring/WAL stress are correctness tests as well as performance
tests: exhaust each map under concurrent fork/socket churn and assert the
documented errno/health transition; overload requested evidence and assert
denials remain denials while coverage becomes gapped.

**Reproducible example.** Run one million paired protected/unprotected opens
after 100,000 warm-up operations on the named CPU/kernel, with one and N
concurrent workers. The manifest records added distributions and fails when
any signed threshold is exceeded. A faster run that lost requested events is a
correctness failure, not a performance win.

No phase can solve a performance failure by removing a required identity,
effect, evidence, or postcondition guarantee. It must optimize the mechanism,
reduce advertised scope, or propose a reviewed design change.

<a id="part-viii-delivery"></a>

## Part VIII — Ownership, Delivery, And Approval

### Implementation Ownership

The final module names are Phase 0 decisions, but responsibilities must remain
cohesive:

| Owner | Responsibility | Must not own |
| --- | --- | --- |
| Rust runtime-entry owner in `mithril-node` | authenticate intents, resolve Pod/runtime identity, classify entry, issue one-use admission | BPF raw event parsing or central graph conclusions |
| Native identity owner | task/process/exec cookies, inheritance, bootstrap, coordinate history | Kubernetes/provider causal edges |
| Object classifier owner | executable/file/socket/device/security object resolution and quality | policy approval or response authorization |
| Policy compiler/activation owner | validate, simulate, compile, probe, atomically activate generations | model-generated direct allows |
| Kernel host owner | one loader, link/map lifecycle, ABI, capability probes, raw sequence | business detection packages |
| Local evidence owner | normalize raw events, coverage intervals, WAL, authenticated upload | mutation of kernel decisions after the fact |
| Control graph owner | immutable observations, typed causal edges, versioned lineage | native parent fabrication or live PID actuation |
| Detection-package owner | deterministic package state, lateness, findings | arbitrary response commands |
| Response coordinator | authorization, target re-resolution, typed execution, postconditions | raw shell or stale graph target |
| Intent-proof/coordinator adapter owner | authenticate issuer assertions, normalize kubelet/CI/deployment intent, stage bounded one-use proofs | load BPF, infer a task from argv/timing, label tasks directly, or maintain another process graph |
| Authority-lease owner | bind an approved credential request and provider-issued lease to the exact task/job proof and later audit identity | store secret material, treat an `aws`/`gcloud`/`gsutil` executable as intent, or invent provider success |
| Disposition compiler owner | validate `allow`/`alert`/`deny`/`reject` against the available decision point and compile notification/response bindings | promise synchronous prevention from audit-only evidence or bypass hard enforcement invariants |

#### Normative durable-owner correction

The table names responsibilities but can be misread as giving two components
authority over intent admission or policy compilation. There is exactly one
durable owner for each state transition:

| Durable owner | Process placement | Exclusive mutation authority |
| --- | --- | --- |
| `TrustBundleOwner` | control plane; verified cache in `mithril-node` | trust generations, issuer keys, rotation/revocation, anti-rollback floor |
| `IntentAdmissionOwner` | module inside the single `mithril-node` process | canonical proof validation, replay WAL, target validation and pending claim state; its owned BPF claim program performs the synchronous `PENDING -> CLAIMING -> CLAIM_BOUND_PROVISIONAL` mutation under this owner's ABI |
| `WorkloadBindingOwner` | module inside `mithril-node` | `ContainerExecutionSet`, cgroup binding object/nonce/storage, initial-container `PREPARING -> BOUND -> TERMINATING -> TOMBSTONED`, execution-set lookup, node-floor request binding and teardown |
| `NativeSecurityStateOwner` | module inside `mithril-node`; synchronous transitions run only in its owned BPF programs | schemas, semantic lifetime refs, and transition invariants for `TaskLabelV1`, `ProcessSecurityStateV1`, `AuthorityDomainStateV1`, mm/publication state, inherited restrictions, object/channel joins, and node application/removal of response-plan refs |
| `PolicyCompiler` | control plane | source/disposition validation/lowering and immutable signed compiled artifact/digest; it never mutates node active pointers or live generation refs |
| `PolicyActivationOwner` | module inside `mithril-node` | inactive generation staging/readback/probes, active-pointer CAS, and only the `BindingGenerationState` generation-retention counters held by task/socket/domain/pending/response objects, plus generation retirement/rollback; it does not own `AuthorityDomainStateV1` membership/semantic refs |
| `KernelHostOwner` | module inside `mithril-node` | the one loader, links, map-object lifecycle, capability state, and kernel ABI; it cannot invent semantic task/process/domain transitions owned by `NativeSecurityStateOwner` |
| `CoverageHealthOwner` | node source state in `mithril-node`; merged view in control | source epochs, counters, intervals, gaps, watermarks, negative-claim eligibility |
| `LocalEvidenceOwner` | module inside `mithril-node` | canonical node observations and WAL/upload acknowledgement |
| `GraphAndFindingOwner` | Mithril control | immutable graph/finding revisions and deterministic package replay |
| `NotificationRouter` | Mithril control | sensitivity-checked route delivery, dedupe, retries, delivery health |
| `ResponseCoordinator` | Mithril control | plan authorization/state/revision and target-specific dispatch |
| `ObjectAndSocketStateOwner` | modules inside `mithril-node` under the effect/network families | exact object/socket identity, lifetime, and classification; they request a versioned join/restriction transition but cannot mutate process/domain membership refs directly |
| `ProviderResponseActuator[provider, capability]` | control adapter | one typed provider operation and its authoritative postcondition |
| `CheckpointAuthorityOwner` | proposed module inside `mithril-node` plus typed store/runtime adapter | checkpoint-create authorization/result and restore setup/held-set transaction; no authority until the unallocated capability receives an approved phase |
| `StreamAuthorityOwner` | proposed node/control module at the authenticated stream gate | attach/port-forward ticket, actor/target/port binding, metering/fence and stream result; it never creates process lineage |
| `QualificationOwner` | offline/release module fed by immutable artifacts | fixture-registry validation, canonical oracle comparison, completion ledger, qualification envelope and release-claim signature; it cannot rewrite detector results or mark degraded coverage PASS |

Issuer adapters authenticate their transport and normalize vendor data into a
candidate canonical payload. They cannot stage a claim. The
`IntentAdmissionOwner` revalidates canonical semantics and is the only
component that owns `PENDING -> CLAIMING -> CLAIM_BOUND_PROVISIONAL` and the
later exec result `-> EXEC_COMMITTED | EXEC_FAILED`. A pending slot reference
belongs to that owner; the `NativeSecurityStateOwner` installs the corresponding
task/process/domain state through the claim ABI; the `PolicyActivationOwner`
only increments/decrements the generation-retention counter named by that
state. Similarly, `ResponseCoordinator` owns a response plan's lifecycle and
authorization, while `NativeSecurityStateOwner` applies/removes the node-local
`response_plan_refs` transition. Notification/provider adapters do not mutate
findings, response plans, claim slots, or authority-domain refs.

This split also corrects the phrase “live task/socket/domain/pending/response
refs” in the retained owner model. When used for `PolicyActivationOwner`, it
means **references those objects hold to one immutable policy generation** in
`BindingGenerationState`; it never means process membership, channel lifetime,
pending intent ownership, or response-plan semantic authority.

##### Abandoned design: adapter and admission owner both authenticate and stage

Any reading of the earlier table that lets the runtime-entry owner and the
intent adapter independently stage proofs is abandoned. A validly signed but
target-mismatched adapter payload is normalized, then rejected by the single
admission owner; no competing pending entry can exist.

The same node gatherer can expose a cgroup-scoped read-only observation stream
to Erebor Runtime. Runtime cannot install overlapping BPF links/maps, assign
Mithril roles, or invoke Mithril response through that subscription.

### Phase Allocation

| Architecture slice | Owning master-plan phases |
| --- | --- |
| ABI, license/provenance, capability/performance contracts, fixture vocabulary | Phase 0 |
| One Rust node process, one loader, base cgroup/runtime inventory | Phase 1 |
| task/process/exec identity, native inheritance, bootstrap, entry-independent tree | Phase 2 |
| effect observation, object classifiers, candidate profile simulation | Phase 3 |
| signed exec/file/device/security policy and generic decision precedence | Phase 4 |
| role-aware socket storage, destination policy, packet/established-flow fence | Phase 5 |
| sequence/WAL/coverage/generation restart and recovery truth | Phase 6 |
| `HF-PROC-001`, `HF-DW-001`, authority behavior and deterministic replay | Phase 7 |
| Kubernetes audit/object/runtime joins and multi-node causal graph | Phase 8 |
| response roots, cgroup/socket actions, controller replacement watch | Phase 9 |
| mesh/AWS/connector/artifact/GitHub packages and typed recovery | Phase 10 |
| runtime-specific full entry admission, packaging, scale, upgrades, complete conformance | Phase 11, with earlier prototypes in Phases 0-4 |
| optional upstream/EDR evidence adapters | Phase 12; this does not allocate named CI coordinator adapters |

The new configuration and intent objects are allocated across those phases,
not assigned to a parallel product track:

| Added architecture object | Phase allocation and exit condition |
| --- | --- |
| `IntentProofEnvelope`, issuer trust, nonce/replay ABI, and physical-disposition vocabulary | Phase 0 specifies and adversarially tests the contract; no provider-specific CLI or entry kind is introduced |
| Runtime-entry and native-transition proof claim | Phases 1-2 establish authenticated transport and exact kernel task binding; Phase 4 makes missing or mismatched proof enforceable |
| `DetectionDispositionRule` and `CompiledActionPlan` | Phase 0 fixes semantics; Phase 4 proves local `deny`/entry `reject`; Phase 7 proves alert routing and deterministic finding behavior; Phase 9 proves response bindings and postconditions |
| `EffectDecisionKeyV1`, restriction/response/generation set ABI and monotonic transition tables | Phase 0 fixes byte layout, closed enums, compiler proof and golden vectors; Phase 4 may use them physically only after exact map/readback/miss/capacity tests pass |
| `AuthorityDomainPublicationStateV1`, publication descriptors/capabilities, persistent-file state and direct process-control channel model | Phase 0 fixes state/ref/oracle schemas; Phase 3 inventories every operation and target hook; Phase 4 may advertise prevention only for completely paired begin/end, persistent-cap and target-resolution paths |
| `LocalInetChannelIdentityV1` and same-Pod TCP/UDP authority joins | Phase 0 fixes topology/identity semantics; Phase 3 observes and inventories redirect/reuseport/io_uring paths; Phase 5 denies or pre-use merges every advertised local channel before calling it laundering prevention |
| `AuthorityLeaseIntent` and `CredentialLease` | Phase 7 establishes authority behavior and exact/local evidence quality; Phase 10 qualifies each provider issuance/audit join |
| Authenticated kubelet reason proof | Prototyped in Phases 0-4, completed and runtime-version-qualified in Phase 11; without a carried nonce or held task, unequal-budget exact probe classification remains unsupported |
| Generic CI run/job/step intent and artifact handoff schema | Phase 0 fixes `IntentKindV1=7`, physical shapes, failure results, and dormant fixtures; no named coordinator adapter or CI policy surface is implementation-authorized until the master plan is amended |

#### Contract-to-phase-and-code route

The filenames below are proposed module families inside the already planned
crates; Phase 0 may rename a family, but it must preserve the one durable owner
and all listed state, transition, and proof obligations. A rename is not a
reason to split the state between daemons.

| Contract/state | First phase that defines it | First phase that mutates/uses it physically | Proposed cohesive owner/path | Required phase exit example |
| --- | ---: | ---: | --- | --- |
| Restricted policy/config YAML, capability records, source-evidence IDs, fixture/family registry, supersession registry, canonical CBOR and digest rules | 0 | 0 | `erebor-linux-sensor-abi` for shared ABI; `mithril-control::policy_schema` and `mithril-e2e::qualification_schema` for product schemas | `CFG-V1-GOLDEN-002` supplies one complete valid vector and separate duplicate-key/unknown-field rejection cases; `FIXTURE-REGISTRY-COMPLETE-001` rejects a prose-only fixture; supersession lint rejects one unregistered abandoned heading |
| Raw BPF/user ABI, map/link inventory, source epoch/sequence, capability probes | 0 | 1 | `erebor-linux-sensor-host::KernelHostOwner` inside the one `mithril-node` process | a second loader cannot acquire the pin-root lease; a failed required attach produces `UNSUPPORTED`, not a smaller silent event stream |
| `TaskLabelV1`, `EntryClassificationV1`, task/process/exec cookies and native inheritance | 0 schema | 2 | `mithril-node::identity::NativeSecurityStateOwner` plus its `lifecycle.bpf.c`/`exec.bpf.c` transition programs | fork-without-exec child is labeled before its first token open; moved-task and non-leader-exec matrices preserve the same process identity |
| `ProcessSecurityStateV1`, `AuthorityDomainStateV1`, exact decision-set ABI, mm cookie/snapshot identity and cache-disabled V1 snapshot/version protocol | 0 schema | 2 creates and transitions; 3 observes/reconciles; 4 enforces | the same `NativeSecurityStateOwner`; kernel maps are semantic state, while `KernelHostOwner` owns only their lifecycle | two threads racing taint/exec cannot recover authority; `DECISION-SET-GOLDEN-001` agrees in Rust/BPF; shared-mm iterator snapshot is complete or typed partial; map exhaustion follows the declared fail posture |
| Runtime entry ticket, held-task claim, replay tombstone and container binding | 0 schema/prototype | 1 transport, 2 identity, 4 first fail-closed use, 11 platform qualification | `mithril-node::admission::IntentAdmissionOwner`; runtime adapter only authenticates transport and holds the exact task | probe/application/admin execute identical bytes concurrently; only the carried one-use ticket receives the probe role |
| File/descriptor/mm/shared-memory/IPC object identity and cross-entry transfer/domain rule | 0 schema | 3 complete observation and bypass inventory; 4 local pre-effect denial | `mithril-node::effect` classifier with state transition delegated to `NativeSecurityStateOwner`; owned file/security BPF programs | fd/`SCM_RIGHTS`/shared-mm cases either deny before use, conservatively merge domains before use, or report `UNSUPPORTED`; post-use object taint cannot claim prevention |
| `AuthorityDomainPublicationStateV1`, `PublicationDescriptorV1`, `PersistentPublicationCapabilityV1`, persistent file/volume security state, and cross-process memory/control/fd authority | 0 schema | 3 complete begin/end/lifetime/hook inventory; 4 local pre-effect denial | `mithril-node::effect` owns object/operation classification; `NativeSecurityStateOwner` owns domain publication counters, persistent refs and joins | blocked mutable-buffer/io_uring and writable-`MAP_SHARED` tests deliver no marker; rename/remount/reopen preserves state; ptrace/process-vm/pidfd/signal cannot cross a domain without exact declared relation or pre-use merge |
| Socket identity, immutable creator provenance, current actor/domain intersection and packet fence | 0 schema | 3 observes, 5 denies/fences | `mithril-node::effect::network`; socket-local state follows the same semantic-state ownership contract | a socket created by a broad role then passed to a narrow role cannot retain the broad role's egress; existing-flow and shared-socket oracles state blast radius |
| Local IPv4/IPv6 channel identity and same-Pod authority-domain topology | 0 schema | 3 topology observation; 5 local connect/accept/send pre-use enforcement | `mithril-node::effect::network` resolves listener/recipient/socket identity and asks `NativeSecurityStateOwner` for the pre-use domain result | converter-to-uploader TCP/UDP through loopback/Pod IP/reuseport/io_uring either shares the restriction before delivery or is physically denied/unsupported |
| Coverage intervals, WAL, restart reconstruction and graph input envelope | 0 schema | 6 | `mithril-node::evidence` for node truth; `mithril-control::intake` for immutable receipt | ring/WAL loss preserves a loaded deny but blocks a no-event conclusion; restart produces a new source epoch and reconciles live objects with an explicit gap |
| Multi-node/provider `ProviderEdgeContractV1`, deterministic graph and finding revisions | 0 schema | 7 local packages, 8 Kubernetes edges, 10 provider edges | `mithril-control::graph` and `mithril-control::detections` | node-A process and node-B runtime root are connected only by typed audit/object/binding edges; shared ServiceAccount plus time remains contextual |
| Effective response set, shared-authority-domain blast radius, typed node/provider target and verified postcondition | 0 schema; Phase 4 internal response-root probe | 9 local/Kubernetes response; 10 provider actuator | `mithril-control::response::ResponseCoordinator` plus one authenticated actuator per target class | containment of one task sharing an authority domain either covers every affected task/socket or widens/returns partial; stale pidfd or object UID cannot actuate |
| Exact claim vectors, platform manifest, result bundle, completion ledger, performance bundle, qualification envelope and release claim | 0 schema and canonicalization tests | 11 executes complete conformance and signs | `mithril-e2e::qualification::QualificationOwner` or approved release-only equivalent | changing one build/platform/registry digest, omitting one negative control, or setting a degraded fixture to PASS makes signature generation fail |

No row means “implement the entire final mechanism in its first schema phase.”
It means the schema, owner, failure result, and standing fixture become binding
there. Later phases may activate a physical path only after all earlier
prerequisites are `Done` and the user approves that phase.

An adapter's milestone is not complete when it merely receives an event. It
must prove issuer authentication, replay resistance, exact target binding,
failure behavior, and the physical effect of every advertised disposition.

#### Unallocated architecture surfaces and master-plan amendment gate

This architecture has grown beyond the literal scope in the existing
`phase-*.md` files. Architecture prose does not authorize implementation. The
following status is therefore explicit rather than silently assigning work to
a convenient phase:

| Surface | Current allocation | Product consequence | Required plan action before implementation |
| --- | --- | --- | --- |
| Checkpoint creation and restore (`CheckpointCreationRequestV1`, `CheckpointRestoreIntentV1`) | `UNALLOCATED_OPTIONAL` | release manifest reports checkpoint create/restore prevention/admission `UNSUPPORTED`; these fixtures are dormant requirements, not phase acceptance | amend master plan and exact phase file with `CheckpointAuthorityOwner`, restore-engine/runtime matrix, held-target protocol, storage actuator and `CHECKPOINT-CREATE-001`/`ENTRY-RESTORE-001` |
| Attach and port-forward `StreamAuthorityV1` | `UNALLOCATED_OPTIONAL` | Mithril makes no attach/port-forward authorization/metering claim; ordinary process/network evidence may still be contextual | amend exact phase with stream gate placement, `StreamAuthorityOwner`, audit/runtime adapters, budgets/fence and `ENTRY-STREAM-001` |
| Named GitHub Actions, GitLab, Jenkins, and Tekton coordinator adapters plus a compilable CI policy surface | `UNALLOCATED_OPTIONAL` | `CiStepIntentBodyV1` and CI fixture semantics are architectural contracts only; no adapter may claim CI1/CI2/CI3, and every `CI-*` fixture is dormant outside an explicitly advertised CI claim vector | amend master plan and exact phase with coordinator trust roots, runner-control placement, held task/root transport, closed CI policy schema, adapter conformance matrix, and exact CI fixture subset |
| Unmatched-workload node hard floor and signed privileged exceptions | `UNALLOCATED_REQUIRED_FOR_FULL_HF_CLAIM` | full prevention of the incident's attacker-created privileged Pod and Phase 11 full `HF-008..021` claim are blocked; later node detection is not equivalent | amend Phase 0 schema/fixture scope, the chosen runtime-admission implementation phase, and Phase 11 conformance with `WorkloadBindingOwner`, per-runtime pre-setup oracle, `XNODE-PRIVILEGED-POD-001` and `NODE-FLOOR-EXCEPTION-002` |

A proposed amendment may place the node-floor schema/hostile baseline in Phase
0, transport/binding primitives in Phases 1–4, and final runtime/platform
qualification in Phase 11, but that proposal is not approved merely by
appearing here. Until the master/phase files mirror it and the user approves
the owning phase, implementers stop at `UNALLOCATED`.

Runtime-created entry handling crosses phases and cannot be postponed as a
late integration detail:

- Phase 0 must select the target runtime gate and prove its ordering;
- Phase 1 must carry authenticated runtime metadata;
- Phase 2 must model multiple roots and pending/claimed entries;
- Phase 4 must fail closed for missing protected labels; and
- Phase 11 must qualify each advertised containerd/CRI-O/Kubernetes version.

#### Phase output is not automatically a product claim

Every capability advances through these states:

```text
SCHEMA_ONLY
  -> FIXTURE_PROTOTYPE
  -> PLATFORM_QUALIFIED
  -> PRODUCT_CLAIM
```

- `SCHEMA_ONLY`: types/compiler behavior exist; no physical mechanism claim.
- `FIXTURE_PROTOTYPE`: named hostile fixture passes on a development target;
  supported-platform UI remains disabled.
- `PLATFORM_QUALIFIED`: capability, failure, recovery, performance, and
  coverage suites pass for an exact platform manifest.
- `PRODUCT_CLAIM`: a signed release manifest exposes the qualified platform,
  assurance tier, limitations, and required configuration.

Phase 4 may prove a fixture runtime gate and local policy semantics, but it
cannot advertise production “reject before first exec” for containerd/CRI-O
versions not qualified in Phase 11. Phase 7 may emit provider-neutral authority
findings, but exact AWS/GitHub joins and actuators remain unavailable until the
Phase 10 provider capability matrix passes. The product/API reads the manifest,
not the phase number.

**Practical example.** File denial passes on kernel K in Phase 4, while
container-start ordering for containerd R is still a fixture prototype. The
release manifest advertises file protection for already bound tasks and marks
strict container-entry prevention unsupported; the UI cannot combine those
into “fully protected runtime entry.”

### Approval Decisions And Honest Alternatives

| Decision | Proposed default | Honest alternative and required proof |
| --- | --- | --- |
| Container model | Multiple admitted entry roots per container | A single-root model must prove kubelet/runtime exec tasks are always native descendants on every supported runtime; current Kubernetes behavior makes that unlikely |
| Strict initial start | Runtime-held pre-exec admission | Post-start observation is allowed only as a reduced tier with an explicit start gap |
| Strict runtime exec | pidfd/runtime-shim gate; pending-intent BPF claim only after target-kernel proof | Without either, unknown external roots must be denied or the tier is observe-only |
| ExecSync reason | authenticated reason extension when budgets differ; otherwise same-budget conservative class or deny | Timing/command-only exact classification is rejected |
| Administrative exec | default deny/approval on protected workloads | Always allow requires a separately bounded administrative role and accepts that compromised admin authority can introduce a root |
| PreStop under containment | containment wins unless an exact safe cleanup role is approved | Universal preStop bypass is rejected; disabling all preStop is possible with availability cost |
| Missing protected identity | fail closed at first protected effect | Fail open is an observation tier and cannot carry prevention claims |
| Executable identity | immutable object/image identity | Path-only policy is a reduced integrity tier |
| Same TLS destination | provider audit or semantic connector integration; no MITM | Whole-channel deny can prevent both allowed and forbidden operations with explicit blast radius |
| Multi-job process | exact native process scope; logical job remains unknown absent platform proof | Application instrumentation may add optional job identity but cannot become baseline |
| Policy learning | observation creates review-only candidates | Auto-authorizing observed behavior is rejected because compromise can train the allowlist |
| Upstream code | study/adapt mechanisms after Phase 0 license gate; own architecture and Rust userspace | Forking a daemon would add another chassis/owner and must replace, not duplicate, the single-gatherer design |
| Intent transport | one authenticated envelope format consumed by the existing gatherer, with issuer-specific adapters | A coordinator callback may remain audit context, but it cannot authorize an entry or transition unless it is authenticated, replay-resistant, target-bound, and claimed by the live task |
| Cloud CLI interpretation | `aws`, `gcloud`, and `gsutil` retain native process lineage; provider login is a separate authority-lease proof | Creating CLI-specific entry kinds would confuse an executable name with intent and is rejected |
| Disposition vocabulary | separate physical `allow`/`deny`/`reject` from `alert`, notification, and response | A single generic action enum is acceptable only if compilation still rejects impossible boundaries and preserves these exact semantics |
| CI identity | model multiple physical roots, native children, job/step transitions, and artifact/cache/deployment edges | Treating a workflow or Pod as one process tree loses container actions, service containers, remote jobs, and cross-node artifact causality |

### Completion Standard For This Architecture

#### Retained abandoned sketch: completion from only two artifacts

The retained assertion was: **“Completion is decided from two machine-readable
artifacts.”** It is abandoned. The draft below omitted the fixture registry,
case-level result bundle, capability/performance bundles, digest binding, and
qualification envelope. It remains visible as design history; the canonical
artifact set begins with `PlatformSupportManifestV1` after the closed assurance
axes and ends with `QualificationEnvelopeV1` under “Abandoned design: two
unbound qualification artifacts.”

```text
PlatformSupportManifestDraftAbandoned {
  manifest_id
  product_build_digest
  architecture
  kernel_release_build_id_and_btf_digest
  boot_config_and_lsm_order
  landlock_abi_and_handled_rights?
  seccomp_floor_capabilities?
  container_runtime_name_version_config
  kubernetes_version_and_streaming_shape?
  bpf_program_link_map_digests[]
  capability_records[]
  assurance_tiers { runtime_entry, file, network, device, ci, providers... }
  unsupported_paths[]
  performance_qualification_ids[]
  acceptance_result_ids[]
  signed_release_claims[]
}

CompletionLedgerDraftAbandoned {
  architecture_revision_digest
  criteria[] {
    criterion_number
    prerequisite_capability_ids[]
    acceptance_test_ids[]
    expected_result: PASS
    permitted_degraded_result?
    observed_artifact_ids[]
    status: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
  }
}
```

#### Closed assurance axes and normative fixture registry

The ellipsis in the retained `assurance_tiers` sketch is not an extensibility
mechanism. An implementation that reports only the axes it passed would make a
missing security family invisible. That open-ended interpretation is
abandoned. `PlatformSupportManifestV1.assurance_tiers` has this closed type:

```text
AssuranceAxesV1 {
  boot_and_admission_availability: AssuranceAxisRecord
  initial_runtime_entry: AssuranceAxisRecord
  later_runtime_entry_and_streaming: AssuranceAxisRecord
  checkpoint_restore_and_attach: AssuranceAxisRecord
  native_task_process_exec_identity: AssuranceAxisRecord
  policy_generation_and_cgroup_binding: AssuranceAxisRecord
  mount_topology_and_namespace: AssuranceAxisRecord
  file_object_namespace_and_io: AssuranceAxisRecord
  vma_and_executable_memory: AssuranceAxisRecord
  process_and_authority_domain_state: AssuranceAxisRecord
  cross_entry_shared_resource_flow: AssuranceAxisRecord
  socket_network_and_dns: AssuranceAxisRecord
  device_and_derived_kernel_objects: AssuranceAxisRecord
  privilege_kernel_escape_and_self_protection: AssuranceAxisRecord
  seccomp_floor: AssuranceAxisRecord
  landlock_floor: AssuranceAxisRecord
  local_evidence_and_coverage_truth: AssuranceAxisRecord
  multi_node_and_provider_graph: AssuranceAxisRecord
  kubernetes_and_provider_semantic_authority: AssuranceAxisRecord
  artifact_provenance_and_trust: AssuranceAxisRecord
  local_and_distributed_response: AssuranceAxisRecord
  ci_execution_and_artifact_identity: AssuranceAxisRecord
  performance_and_capacity: AssuranceAxisRecord
}

AssuranceAxisRecord {
  capability_record_ids[]
  supported_stages: subset of
    [ENTRY_ADMISSION, NATIVE_TRANSITION, LOCAL_PRE_EFFECT,
     REMOTE_PRE_ADMISSION, POST_EFFECT, RESPONSE]
  proof_vectors[]
  supported_object_and_operation_matrix_digest
  required_fixture_ids[]
  passed_result_ids[]
  unsupported_or_degraded_paths[]
  claim_level: UNSUPPORTED | CONTEXTUAL_OBSERVATION | EXACT_OBSERVATION |
               PRE_EFFECT_DENIAL | SEMANTIC_REJECTION | VERIFIED_RESPONSE |
               COMPOSITE
}
```

`claim_level` is not an ordering. `VERIFIED_RESPONSE` does not imply
`PRE_EFFECT_DENIAL`, and `EXACT_OBSERVATION` does not imply either. A
`COMPOSITE` record enumerates multiple supported stages and proof vectors.
Every field exists in every manifest; an unsupported family is explicit.

The canonical manifest is a signed, closed record. It contains no in-place
release claim and cannot be combined with a result from another build or
platform:

```text
PlatformSupportManifestV1 {
  schema_version: exactly 1
  manifest_id: Id128
  architecture_revision_digest: DigestV1
  product_build_digest: DigestV1
  architecture: X86_64 | AARCH64
  kernel_release_build_id_and_btf_digest: DigestV1
  boot_config_and_lsm_order_digest: DigestV1
  landlock_capability_record_id?: Id128
  seccomp_capability_record_id?: Id128
  container_runtime_name_version_config_digest: DigestV1
  kubernetes_version_and_streaming_shape_digest?: DigestV1
  bpf_program_link_map_manifest_digest: DigestV1
  capability_bundle_digest: DigestV1
  assurance_axes: AssuranceAxesV1
  unsupported_paths[]: sorted unique UnsupportedPathV1
  claim_vector_ids[]: sorted unique Id128
  performance_qualification_record_ids[]: sorted unique Id128
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

##### Abandoned design: an axis-level aggregate is an authority-bearing claim

The retained `AssuranceAxisRecord.proof_vectors`, operation-matrix digest,
degraded-path list, and `COMPOSITE` claim are underspecified if a product claim
can point at that aggregate. That interpretation is abandoned. Every
authority-bearing release claim points to one exact cell:

```text
ClaimVectorV1 {
  claim_vector_id
  assurance_axis: closed field from AssuranceAxesV1
  object_family
  operation
  evaluation_stage
  authority_boundary
  physical_or_semantic_result:
    CONTEXTUAL_OBSERVATION | EXACT_OBSERVATION | PRE_EFFECT_DENIAL |
    SEMANTIC_REJECTION | VERIFIED_RESPONSE | UNSUPPORTED
  proof_quality: ProofQualityV1
  capability_record_ids[]
  required_fixture_ids[]
  passed_fixture_result_ids[]
  required_coverage_predicates[]
  unsupported_path?: UnsupportedPathV1
  performance_qualification_id?
}

UnsupportedPathV1 {
  object_family, operation, stage
  missing_capability_or_evidence
  degraded_result
  prohibited_product_statements[]
}
```

An `AssuranceAxisRecord` is only a derived index over its exact claim vectors.
Its `COMPOSITE` label means “open these cells”; it grants nothing and is not a
predicate in policy, UI, release signing, or sales claims. For example,
`socket_network_and_dns` can contain `PRE_EFFECT_DENIAL` for IPv4 TCP connect,
`EXACT_OBSERVATION` for a qualified packet path, and `UNSUPPORTED` for a
TLS-opaque provider verb at the same time without averaging them into “full
network protection.” `ALG-AUTHORITY` cells live in the explicit
`kubernetes_and_provider_semantic_authority` axis; non-CI artifact publication,
verification, load and quarantine cells live in
`artifact_provenance_and_trust`.

Every normative fixture also has a machine-owned row:

```text
NormativeFixtureRegistryDraftAbandoned {
  architecture_revision_digest
  fixtures[] {
    fixture_id
    id_kind: FIXTURE | META_TEST
    source_section_id
    owning_phase_and_crate
    criterion_numbers[]
    assurance_axes[]
    prerequisite_capability_ids[]
    upstream_source_evidence_ids[]
    required_coverage_predicates[]
    topology_digest
    stimulus_binary_or_request_digest
    expected_decision_stage
    expected_disposition
    physical_or_provider_oracle_schema
    oracle_validator_id
    legitimate_negative_control_ids[]
    fault_variant_ids[]
    degraded_result
  }
}
```

##### Abandoned design: one expected result per multi-branch fixture

The retained registry's singular stimulus, disposition, oracle, and negative
control cannot represent `HF-004-RESULT-001`, `HF-011-READ-RESULT-001`, the two
admission boundaries in `HF-GRAN-RESPAWN-001`, or credential-delivery branches
in `CI-PR-001`. It is retained as the original index shape but abandoned as the
wire schema. The corrected row owns explicit cases:

```text
FixtureAllocationConditionV1 =
  ALWAYS
  | WHEN_CLAIM_VECTOR_REFERENCES
  | WHEN_SURFACE_ALLOCATED_AND_ADVERTISED

FixtureCaseV1 {
  case_id                         // unique within fixture; stable kebab ASCII
  allocation_condition: FixtureAllocationConditionV1
  topology_digest: DigestV1
  starting_state_digest: DigestV1
  stimulus_digest: DigestV1
  expected_stage: ENTRY_ADMISSION | NATIVE_TRANSITION | LOCAL_PRE_EFFECT |
                  REMOTE_PRE_ADMISSION | POST_EFFECT | RESPONSE
  expected_disposition: ADMIT | AUDIT_ADMIT | REJECT_REQUEST |
                        ALLOW_EFFECT | AUDIT_ALLOW_EFFECT | DENY_ERRNO |
                        RECORD_ONLY | FINDING | RESPONSE_PROPOSAL |
                        VERIFIED_RESPONSE | UNSUPPORTED
  expected_result: closed result enum or registered result ID
  required_coverage_predicates[]
  oracle_schema
  oracle_validator_id
  oracle_artifact_expectation_digest: DigestV1
  negative_control_case_ids[]     // exact cases, not prose
  degraded_result: UNSUPPORTED | INSUFFICIENT_COVERAGE |
                   OBSERVATION_ONLY | NOT_APPLICABLE
}

NormativeFixtureRegistryV1 {
  architecture_revision_digest: DigestV1
  fixtures[] {
    fixture_id
    id_kind: FIXTURE | META_TEST
    source_section_id
    owning_phase_and_crate
    criterion_numbers[]
    assurance_axes[]
    prerequisite_capability_ids[]
    upstream_source_evidence_ids[]
    cases[1..256]: FixtureCaseV1
  }
}

FixtureCaseResultV1 {
  fixture_id
  case_id
  starting_state_digest: DigestV1
  stimulus_digest: DigestV1
  observed_stage
  observed_disposition
  observed_result
  observed_coverage_interval_ids[]
  oracle_artifact_ids[]
  canonical_oracle_digest: DigestV1
  negative_control_case_result_ids[]
  result: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
}
```

A fixture aggregate is `PASS` only when every case whose allocation condition
is active is `PASS`, every named negative control is present and `PASS`, and no
required coverage predicate is gapped. An inactive optional case is recorded
`UNSUPPORTED`/dormant and cannot satisfy a claim vector, but it does not block
an unrelated core claim. Cases cannot inherit an oracle or expected result
from prose.

**Concrete branches.** `HF-004-RESULT-001` has separate `send-allowed`,
`packet-emitted`, `provider-publication-confirmed`, and `tls-payload-opaque`
cases. `HF-011-READ-RESULT-001` has open-denied, descriptor-opened, zero-byte
read, positive-byte read, and later-publication cases. `CI-PR-001` has
projected-file, broker-lease, environment-memory, pre-opened-fd, read-only-
provider-token, and same-TLS-write-token cases. Each branch names its own stage
and physical oracle, so a successful file-open denial cannot make the opaque
TLS branch pass.

The checked-in source of truth is
`spec/qualification/v1/fixtures.yaml` at the future Erebor monorepo root;
`spec/qualification/v1/families.yaml` contains only explicit family membership.
Both files use the same restricted YAML parser as policy input and are hashed
as deterministic CBOR. Generated result bundles are canonical CBOR and never
edit either source file.

A normative fixture paragraph carries an exact adjacent marker:

```html
<!-- mithril-fixture-v1: FILE-MMAP-001 -->
```

The grammar is the literal prefix, one uppercase ID matching
`^[A-Z][A-Z0-9]*(?:-[A-Z0-9]+)+-[0-9]{3}$`, one space on each side of the ID,
and the literal suffix. Cards use `mithril-card-v1`, source observations use
`mithril-source-evidence-v1`, invariants use `mithril-invariant-v1`, and none
is accepted as a fixture marker. Phase 0 adds the markers mechanically to each
paragraph and fails docs lint on duplicate, missing, orphan, wrong-kind, or
malformed IDs.

`FixtureFamilyV1` is also closed:

```text
FixtureFamilyV1 {
  family_id
  member_fixture_ids[]  // explicit, nonempty, unique, sorted
}
```

Wildcards such as `ENTRY-*`, “every matrix row,” or an unnamed “positive
control” in the retained summary tables are non-normative reading aids. A
ledger, claim vector, family file, result bundle, or release envelope containing
a wildcard or card/source/invariant ID where a fixture ID is required fails
with `QUAL_WILDCARD_OR_WRONG_ID_KIND`. `CARD-ENTRY-PROBE-IMPERSONATION-001`
therefore maps to the distinct fixture `ENTRY-PROBE-IMPERSONATION-003`.

The exact fixture-ID set declared by this revision is:

```text
NormativeFixtureSetV1 {
  BOOT-ADMISSION-001
  CFG-ROLLBACK-GOLDEN-002
  CFG-V1-GOLDEN-002
  CHECKPOINT-CREATE-001
  CI-ATTEST-001
  CI-CACHE-001
  CI-CONTAINER-001
  CI-DEBUG-001
  CI-DIND-001
  CI-FANOUT-001
  CI-GITHUB-TOKEN-001
  CI-NATIVE-001
  CI-OIDC-001
  CI-OUTPUT-001
  CI-POST-001
  CI-PR-001
  CI-RETRY-001
  CI-RUNNER-REUSE-001
  CI-STATE-001
  DECISION-SET-GOLDEN-001
  DEVICE-DERIVED-001
  DOMAIN-JOIN-CRASH-002
  DOMAIN-REF-LIFETIME-001
  EDGE-ARTIFACT-CONSUMER-005
  EDGE-AWS-SHARED-001
  EDGE-CONNECTOR-FORWARD-004
  EDGE-GITHUB-SHARED-003
  EDGE-K8S-SHARED-002
  EDGE-MESSAGE-CONSUMER-006
  ENTRY-CLAIM-TRANSACTION-004
  ENTRY-CONTAINERS-001
  ENTRY-EPHEMERAL-001
  ENTRY-EXEC-001
  ENTRY-EXEC-002
  ENTRY-HOLD-ATTACK-002
  ENTRY-KUBELET-TICKET-001
  ENTRY-LOSS-001
  ENTRY-MIGRATE-001
  ENTRY-NETPROBE-001
  ENTRY-POSTSTART-001
  ENTRY-POSTSTART-002
  ENTRY-PRESTOP-001
  ENTRY-PROBE-001
  ENTRY-PROBE-002
  ENTRY-PROBE-IMPERSONATION-003
  ENTRY-RESTART-001
  ENTRY-RESTORE-001
  ENTRY-REUSE-001
  ENTRY-ROOTFS-BARRIER-001
  ENTRY-SLEEP-001
  ENTRY-START-001
  ENTRY-STREAM-001
  EXEC-COMMIT-STATE-001
  EXEC-CONCURRENT-002
  FILE-CONTENT-RACE-002
  FILE-DELEGATED-EGRESS-001
  FILE-FD-PASS-001
  FILE-IDENTITY-001
  FILE-MMAP-001
  FILE-NAMESPACE-001
  FILE-SA-TOKEN-OPEN-001
  FILE-VMA-SNAPSHOT-001
  FIXTURE-REGISTRY-COMPLETE-001
  HF-004-RESULT-001
  HF-011-READ-RESULT-001
  HF-GRAN-AWS-DRYRUN-001
  HF-GRAN-AWS-SPLIT-001
  HF-GRAN-CAPTURE-001
  HF-GRAN-CI-BUILDRS-001
  HF-GRAN-CLUSTER-SHARED-001
  HF-GRAN-CONNECTOR-DIRECT-001
  HF-GRAN-DEAD-DROP-001
  HF-GRAN-GITHUB-MINT-001
  HF-GRAN-GITHUB-REARM-001
  HF-GRAN-GITHUB-REVOKE-001
  HF-GRAN-GITHUB-TREE-PR-001
  HF-GRAN-HOST-LOC-001
  HF-GRAN-HOSTPATH-001
  HF-GRAN-MESH-ENUM-001
  HF-GRAN-MESH-ROOT-001
  HF-GRAN-MESH-SOCKS-001
  HF-GRAN-OUTSIDE-001
  HF-GRAN-RESPAWN-001
  HF-GRAN-TOKEN-FORGE-001
  HF-LOCAL-001
  HF-NET-001
  HF-RESP-002
  HF-RESP-SHARED-DOMAIN-003
  ID-CGROUP-ESCAPE-001
  ID-CLONE-CGROUP-002
  ID-CREATOR-PARENT-007
  ID-MOVED-PARENT-FORK-004
  ID-MOVED-TASK-EXEC-005
  ID-TASK-COORD-FINALIZE-006
  LSM-DENY-SATURATION-001
  MEM-EXEC-001
  MEM-KERNEL-MAP-002
  MOUNT-ATTR-001
  MOUNT-CAS-002
  MOUNT-PROPAGATION-003
  MOUNT-SNAPSHOT-004
  NET-ACCEPT-PASS-001
  NET-DNS-EXFIL-001
  NET-NS-PASS-001
  NET-RECV-001
  NET-REWRITE-001
  NET-SHARED-RESPONSE-002
  NET-SOCKCTL-001
  NET-SOCKET-LIFE-001
  NODE-FLOOR-EXCEPTION-002
  SECCOMP-QUAL-001
  SELF-PROTECT-001
  SOURCE-KA-BOUNDS-004
  SOURCE-KA-CAPACITY-005
  SOURCE-KA-PARTIAL-ATTACH-001
  SOURCE-KA-READER-LOSS-003
  SOURCE-KA-STACK-PER-HOOK-002
  SOURCE-TG-EXEC-MAP-007
  SOURCE-TG-PATH-RENAME-008
  SOURCE-TG-RUNTIME-JOIN-006
  STATE-CROSS-ENTRY-003
  STATE-CROSS-ENTRY-PREPOSSESSED-005
  STATE-CROSS-ENTRY-RACE-004
  STATE-CROSS-EXECSET-PERSIST-006
  STATE-FORK-IPC-002
  STATE-LOCAL-INET-LAUNDER-008
  STATE-MMAP-PUBLICATION-011
  STATE-PERSISTENT-FILE-LIFETIME-007
  STATE-PROCESS-CHANNEL-009
  STATE-PUBLICATION-LEASE-010
  STATE-THREAD-RACE-001
  XNODE-PRIVILEGED-POD-001
}
```

This block is the migration declaration until every adjacent marker and YAML
row exists; the three sets—block, markers, registry—must then match exactly.
Adding a normative fixture requires changing all three in one review.

`FIXTURE-REGISTRY-COMPLETE-001` is a release meta-test. The documentation build
exports the normative fixture IDs declared by this architecture; the test
compares that set byte-for-byte with the registry, every completion criterion,
every assurance axis, and the result bundle. An ID missing from the registry,
a registry row with no executable test, an executed test absent from its
criterion, or a PASS without its negative control and oracle fails release
generation. This prevents a newly added `FILE-*` or `NET-*` requirement from
remaining impressive prose that no phase actually runs.

##### Abandoned design: two unbound qualification artifacts

The retained sentence “Completion is decided from two machine-readable
artifacts” became false when the fixture registry/result bundle was added, and
the original ledger could mix results from different builds or platforms. The
unbound interpretation and the manifest's in-place `signed_release_claims[]`
field are abandoned. The corrected artifacts are digest-bound as follows:

```text
FixtureResultBundleDraftAbandoned {
  result_bundle_id
  product_build_digest
  platform_support_manifest_digest
  fixture_registry_digest
  results[] {
    fixture_id
    topology_and_stimulus_digests
    capability_record_ids[]
    observed_coverage_interval_ids[]
    negative_control_result_id
    oracle_artifact_ids[]
    canonical_oracle_digest
    result: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
  }
}

CompletionLedgerV1 {
  ledger_id
  architecture_revision_digest
  product_build_digest
  platform_support_manifest_digest
  capability_bundle_digest
  fixture_registry_digest
  fixture_result_bundle_digest
  performance_qualification_bundle_digest
  criteria[] {
    criterion_number
    claim_vector_ids[]
    prerequisite_capability_ids[]
    acceptance_fixture_ids[]  // exact IDs only
    accepted_result: PASS
    result_artifact_ids[]
    status: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
  }
}

QualificationEnvelopeV1 {
  qualification_id
  architecture_revision_digest
  product_build_digest
  platform_support_manifest_digest
  capability_bundle_digest
  fixture_registry_digest
  fixture_result_bundle_digest
  completion_ledger_digest
  performance_qualification_bundle_digest
  generated_at_utc
  release_qualifier_identity
  signature_key_id
  canonical_payload_digest
  signature
}

ReleaseClaimV1 {
  claim_id
  qualification_envelope_digest
  claim_vector_ids[]
  human_statement
  valid_for_exact_platform_manifest_digest
  signature
}
```

##### Correction: result bundles contain case results, not one fixture result

The singular `FixtureResultBundleDraftAbandoned.results[]` entry above is abandoned for the
same reason as the singular registry row. `fixture_result_bundle_digest` in the
ledger/envelope refers to this corrected payload:

```text
FixtureAggregateResultV1 {
  fixture_id
  active_case_ids[]
  dormant_case_ids[]
  case_results[]: FixtureCaseResultV1
  aggregate_result: PASS | FAIL | UNSUPPORTED | INSUFFICIENT_COVERAGE
}

FixtureResultBundleV1 {
  result_bundle_id
  product_build_digest: DigestV1
  platform_support_manifest_digest: DigestV1
  fixture_registry_digest: DigestV1
  fixture_results[]: sorted unique FixtureAggregateResultV1 by fixture_id
  canonical_payload_digest: DigestV1
  signer_key_id
  signature
}
```

The aggregate algorithm selects cases from their allocation conditions and
the exact claim vector set. It rejects an unknown/duplicate/missing case,
unregistered negative control, case digest mismatch, or fixture-level `PASS`
when one active case is not `PASS`. This is how a fixture with both allow and
deny branches is executable without collapsing them into one disposition.

The release qualifier verifies every digest and signature, exact fixture-set
equality, platform/build equality, coverage predicate, negative control and
oracle before signing the envelope. Any required fixture result other than
`PASS` makes its criterion non-PASS and makes every dependent claim vector
ineligible. A `permitted_degraded_result` may describe an unsupported product
tier but can never satisfy a PASS criterion. Results, performance data, or
capabilities from another node/kernel/build cannot be spliced into the
envelope.

“Pass” means the fixture's physical oracle and required coverage both match.
“Survive restart/reuse/fan-out” means every named fault fixture produces the
canonically equivalent expected identity/graph/finding state, not merely that
the daemon remains alive. A “healthy watch interval” is a configured duration plus
the exact `CoverageIntervalV1` set required by the response; it is never an
unqualified pause.

The earlier phrase “byte-identical expected state” is abandoned for raw output:
boot IDs, generated cookies, absolute timestamps and delivery order are
intentionally nondeterministic. `CanonicalOracleComparatorV1` performs a
defined comparison:

```text
CanonicalOracleComparatorV1 {
  schema_version: 1
  fixture_alias_bindings: actual opaque IDs -> fixture logical slots
  time_normalization: absolute times -> signed offsets/intervals from stimulus
  sequence_normalization: preserve per-source order and explicit gaps
  collection_rules: ordered_list | key_sorted_set | counted_multiset
  ignored_display_fields[]: closed registry, never security/proof/result fields
  exact_fields[]
  interval_predicates[]
  expected_canonical_digest
}
```

Aliases bind from authoritative fixture creation records, never by sorting
random IDs after the fact. Parent/child and causal edge order, result enums,
proof axes, coverage gaps, object bytes/digests, decisions and postconditions
remain exact. UTC/boottime values compare against declared offset/uncertainty
predicates. Sets sort by their canonical logical key; multisets retain counts;
ordered event/source sequences remain ordered. Rust emits the canonical CBOR
view and SHA-256 digest, and replay permutations must match that digest.

The minimum ledger mapping is:

| Criterion | Required test families |
| --- | --- |
| 1–3 | `ENTRY-*`, unchanged-workload positive controls, native fork/exec/thread and identical-command impersonation fixtures |
| 4 | One `HF-*` physical-effect fixture per claimed `HF-008` through `HF-020` gate, including bypass matrix variants |
| 5 | in-process secret, pre-opened descriptor, shared TLS clone/push, and audit-only semantic fixtures |
| 6 | identity reuse/restart, evidence loss, graph fan-out, late/duplicate/contradictory event replay |
| 7 | `HF-RESP-*`, stale-target, existing-flow, replacement-Pod, provider-actuator, and late-branch fixtures |
| 8 | every Failure-State Architecture row, independently faulted by family |
| 9 | stage-lowering/compiler golden tests, invalid physical disposition tests, and observe-mode result wording |
| 10 | intent canonicalization, signature/key rotation, restart replay, expiry, mismatch, concurrent claim, and CLI-as-non-entry fixtures |
| 11 | CI tier-specific native/container/service/artifact/OIDC/credential/cleanup/retry/runner-reuse fixtures |

##### Abandoned design: wildcard criterion expansion

The broad rows above and the next table are retained as a reading summary, but
the claim that the next table is a “normative expansion” is abandoned. It uses
wildcards, unnamed controls/matrix rows, and one card ID. Those values cannot
be joined to registry rows, and optional checkpoint/stream/CI surfaces would
incorrectly block the core Hugging Face claim.

| Criterion | Mandatory registered fixture IDs/families | What a PASS proves |
| --- | --- | --- |
| 1 | `BOOT-ADMISSION-001`, `NODE-FLOOR-*`, `ENTRY-START-*`, unchanged init/application/sidecar positive controls | The node can boot and protect ordinary workloads while every new workload receives the default floor before user or mount effects. |
| 2 | `ENTRY-ROOTFS-*`, `ENTRY-HOLD-*`, `ENTRY-RESTORE-*`, `ENTRY-STREAM-*`, `ENTRY-KUBELET-TICKET-*`, `CHECKPOINT-*`, and every Kubernetes external-entry matrix row | Initial, later, restored, lifecycle, probe, and administrative roots bind through their exact supported admission state machine. |
| 3 | `ID-MOVED-*`, `ID-CLONE-CGROUP-*`, native fork/vfork/thread/non-leader-exec/PID-reuse fixtures, `STATE-THREAD-*`, `STATE-FORK-IPC-*`, `STATE-CROSS-ENTRY-*` | Native identity survives placement and lifecycle races, and sensitive authority cannot be laundered through qualified process or cross-entry channels. |
| 4 | `MOUNT-ATTR-*`, `MOUNT-CAS-*`, `MOUNT-SNAPSHOT-*`, `MOUNT-PROPAGATION-*`, `FILE-IDENTITY-*`, `FILE-CONTENT-RACE-*`, `FILE-NAMESPACE-*`, `FILE-MMAP-*`, `FILE-VMA-SNAPSHOT-*`, `MEM-EXEC-*`, `MEM-KERNEL-MAP-*`, `NET-NS-*`, `NET-ACCEPT-*`, `NET-SOCKET-LIFE-*`, `NET-RECV-*`, `NET-REWRITE-*`, `NET-DNS-EXFIL-*`, `NET-SOCKCTL-*`, `DEVICE-DERIVED-*`, `SECCOMP-QUAL-*`, and one physical `HF-*` fixture per advertised incident gate | Each claimed local prevention surface has a qualified hook/admission point, bypass matrix, hostile oracle, and legitimate control. |
| 5 | In-process secret, `FILE-FD-PASS-*`, `FILE-DELEGATED-EGRESS-*`, shared-TLS clone/push, shared-socket/`NET-SHARED-RESPONSE-*`, credential-delivery, and payload-unobservable fixtures | The product distinguishes prevented bytes/effects from allowed, delegated, already-memory-resident, shared-channel, and TLS-opaque behavior. |
| 6 | Every identity/map/object reuse and restart test, mount/VMA snapshot race, evidence loss/coverage interval, graph fan-out, late/duplicate/contradictory replay, and all `HF-GRAN-*` proof-degradation variants | Evidence and graph claims remain deterministic and never become stronger under gaps, reuse, concurrency, or late data. |
| 7 | `HF-RESP-*`, stale pidfd/task/cgroup/socket/provider targets, existing-flow, shared-socket blast radius, replacement-Pod, late-branch and provider-actuator fixtures | Each authorized action re-resolves the physical target and verifies its exact postcondition through named healthy coverage. |
| 8 | Every Failure-State Architecture row plus `SELF-PROTECT-*`, link/map/pin replacement, sole-gatherer death, WAL/ring/map exhaustion, admission-socket loss and control-plane partition | Failure narrows the advertised capability or fails the protected effect closed; it never silently converts to healthy allow. |
| 9 | Stage-lowering, exact-key conflict, invalid-disposition, exception/expiry/rollback, observe-wording and generation anti-rollback golden tests | Configuration cannot request an impossible physical outcome or overstate observe/audit evidence. |
| 10 | Intent canonicalization/signature/key rotation/replay/expiry/mismatch/claim, `CARD-ENTRY-PROBE-IMPERSONATION-001`, cloud-CLI-as-non-entry, authority issuance and protected-handle fixtures | Authenticated one-use intent binds to the exact supported task/lease/object and cannot be forged from argv, timing, cgroup or shared identity. |
| 11 | Every named `CI-*` native/container/service/fan-out/artifact/cache/OIDC/credential/post/cancel/retry/debug/runner-reuse fixture | Each advertised CI tier identifies its real physical roots and honestly reports credential and semantic-effect limits. |

The machine contract has no wildcard or prose member:

```text
CriterionFixtureRequirementV1 {
  criterion_number: u8 in 1..11
  requirement_condition:
    ALWAYS | WHEN_CLAIM_VECTOR_REFERENCES |
    WHEN_SURFACE_ALLOCATED_AND_ADVERTISED
  exact_fixture_ids[]              // sorted unique registered fixture IDs
}
```

This revision's exact mapping is below. A fixture may appear in more than one
criterion when it proves independent claims. Optional rows are dormant unless
their stated claim/surface is active; dormant `UNSUPPORTED` does not block an
unrelated core release and cannot satisfy the optional claim.

```text
criterion 1, ALWAYS:
  BOOT-ADMISSION-001

criterion 1, WHEN_CLAIM_VECTOR_REFERENCES:
  NODE-FLOOR-EXCEPTION-002
  XNODE-PRIVILEGED-POD-001

criterion 2, ALWAYS:
  ENTRY-CLAIM-TRANSACTION-004
  ENTRY-CONTAINERS-001
  ENTRY-EPHEMERAL-001
  ENTRY-EXEC-001
  ENTRY-EXEC-002
  ENTRY-HOLD-ATTACK-002
  ENTRY-KUBELET-TICKET-001
  ENTRY-LOSS-001
  ENTRY-MIGRATE-001
  ENTRY-NETPROBE-001
  ENTRY-POSTSTART-001
  ENTRY-POSTSTART-002
  ENTRY-PRESTOP-001
  ENTRY-PROBE-001
  ENTRY-PROBE-002
  ENTRY-PROBE-IMPERSONATION-003
  ENTRY-RESTART-001
  ENTRY-REUSE-001
  ENTRY-ROOTFS-BARRIER-001
  ENTRY-SLEEP-001
  ENTRY-START-001

criterion 2, WHEN_SURFACE_ALLOCATED_AND_ADVERTISED:
  CHECKPOINT-CREATE-001
  ENTRY-RESTORE-001
  ENTRY-STREAM-001

criterion 3, ALWAYS:
  DOMAIN-JOIN-CRASH-002
  DOMAIN-REF-LIFETIME-001
  EXEC-COMMIT-STATE-001
  ID-CGROUP-ESCAPE-001
  ID-CLONE-CGROUP-002
  ID-CREATOR-PARENT-007
  ID-MOVED-PARENT-FORK-004
  ID-MOVED-TASK-EXEC-005
  ID-TASK-COORD-FINALIZE-006
  STATE-CROSS-ENTRY-003
  STATE-CROSS-ENTRY-PREPOSSESSED-005
  STATE-CROSS-ENTRY-RACE-004
  STATE-CROSS-EXECSET-PERSIST-006

criterion 4, ALWAYS:
  DEVICE-DERIVED-001
  EXEC-CONCURRENT-002
  FILE-CONTENT-RACE-002
  FILE-IDENTITY-001
  FILE-MMAP-001
  FILE-NAMESPACE-001
  FILE-SA-TOKEN-OPEN-001
  FILE-VMA-SNAPSHOT-001
  HF-LOCAL-001
  HF-NET-001
  MEM-EXEC-001
  MEM-KERNEL-MAP-002
  MOUNT-ATTR-001
  MOUNT-CAS-002
  MOUNT-PROPAGATION-003
  MOUNT-SNAPSHOT-004
  NET-ACCEPT-PASS-001
  NET-DNS-EXFIL-001
  NET-NS-PASS-001
  NET-RECV-001
  NET-REWRITE-001
  NET-SOCKCTL-001
  NET-SOCKET-LIFE-001
  SECCOMP-QUAL-001
  STATE-LOCAL-INET-LAUNDER-008
  STATE-MMAP-PUBLICATION-011
  STATE-FORK-IPC-002
  STATE-PERSISTENT-FILE-LIFETIME-007
  STATE-PROCESS-CHANNEL-009
  STATE-PUBLICATION-LEASE-010
  STATE-THREAD-RACE-001

criterion 4, WHEN_CLAIM_VECTOR_REFERENCES:
  HF-GRAN-CONNECTOR-DIRECT-001
  HF-GRAN-DEAD-DROP-001
  HF-GRAN-HOSTPATH-001
  HF-GRAN-MESH-ROOT-001

criterion 5, ALWAYS:
  FILE-DELEGATED-EGRESS-001
  FILE-FD-PASS-001
  HF-004-RESULT-001
  HF-011-READ-RESULT-001
  NET-SHARED-RESPONSE-002

criterion 5, WHEN_CLAIM_VECTOR_REFERENCES:
  HF-GRAN-CI-BUILDRS-001
  HF-GRAN-HOST-LOC-001
  HF-GRAN-OUTSIDE-001

criterion 6, ALWAYS:
  EDGE-ARTIFACT-CONSUMER-005
  EDGE-AWS-SHARED-001
  EDGE-CONNECTOR-FORWARD-004
  EDGE-GITHUB-SHARED-003
  EDGE-K8S-SHARED-002
  EDGE-MESSAGE-CONSUMER-006

criterion 6, WHEN_CLAIM_VECTOR_REFERENCES:
  HF-GRAN-AWS-SPLIT-001
  HF-GRAN-CLUSTER-SHARED-001
  HF-GRAN-GITHUB-TREE-PR-001
  HF-GRAN-MESH-SOCKS-001

criterion 7, ALWAYS:
  HF-RESP-002
  HF-RESP-SHARED-DOMAIN-003

criterion 7, WHEN_CLAIM_VECTOR_REFERENCES:
  HF-GRAN-CAPTURE-001
  HF-GRAN-GITHUB-REARM-001
  HF-GRAN-GITHUB-REVOKE-001
  HF-GRAN-MESH-ENUM-001
  HF-GRAN-RESPAWN-001

criterion 8, ALWAYS:
  LSM-DENY-SATURATION-001
  SELF-PROTECT-001
  SOURCE-KA-BOUNDS-004
  SOURCE-KA-CAPACITY-005
  SOURCE-KA-PARTIAL-ATTACH-001
  SOURCE-KA-READER-LOSS-003
  SOURCE-KA-STACK-PER-HOOK-002
  SOURCE-TG-EXEC-MAP-007
  SOURCE-TG-PATH-RENAME-008
  SOURCE-TG-RUNTIME-JOIN-006

criterion 9, ALWAYS:
  CFG-ROLLBACK-GOLDEN-002
  CFG-V1-GOLDEN-002
  DECISION-SET-GOLDEN-001
  FIXTURE-REGISTRY-COMPLETE-001

criterion 10, ALWAYS:
  ENTRY-CLAIM-TRANSACTION-004
  ENTRY-KUBELET-TICKET-001
  ENTRY-PROBE-IMPERSONATION-003

criterion 10, WHEN_CLAIM_VECTOR_REFERENCES:
  HF-GRAN-AWS-DRYRUN-001
  HF-GRAN-GITHUB-MINT-001
  HF-GRAN-TOKEN-FORGE-001

criterion 11, WHEN_SURFACE_ALLOCATED_AND_ADVERTISED:
  CI-ATTEST-001
  CI-CACHE-001
  CI-CONTAINER-001
  CI-DEBUG-001
  CI-DIND-001
  CI-FANOUT-001
  CI-GITHUB-TOKEN-001
  CI-NATIVE-001
  CI-OIDC-001
  CI-OUTPUT-001
  CI-POST-001
  CI-PR-001
  CI-RETRY-001
  CI-RUNNER-REUSE-001
  CI-STATE-001
```

`FIXTURE-REGISTRY-COMPLETE-001` compares this exact union to
`NormativeFixtureSetV1`. It also verifies that
`CARD-ENTRY-PROBE-IMPERSONATION-001` appears nowhere in a fixture list; the
registered fixture is `ENTRY-PROBE-IMPERSONATION-003`. Any new fixture without
an exact criterion row—or any wildcard/family/card ID in this machine
contract—fails qualification generation.

`HF-021` is a response/recovery outcome evaluated by criterion 7. It is not an
additional pre-effect family, which is why criterion 4 ends at `HF-020`.

This document is implemented only when all of the following are true on every
advertised full-support kernel/runtime combination:

1. The unchanged concurrent worker, declared lifecycle handlers, exec probes,
   init/sidecars, and legitimate controller behavior pass.
2. Every container/runtime-created root has exact or explicitly conservative
   entry evidence before its first protected effect.
3. A native child cannot impersonate a kubelet/runtime entry by matching its
   command, binary, timing, cgroup, or namespace.
4. The first distinguishable prohibited `HF-008`-through-`HF-020` effect is
   physically denied where the matrix claims prevention.
5. Same-process and same-TLS cases produce the documented semantic detection
   result, never a fabricated kernel claim.
6. Native and distributed lineage survive concurrency, restart, reuse, fan-out,
   loss, late evidence, and contradictory evidence.
7. Local and provider responses re-resolve their target and verify physical
   postconditions through a healthy watch interval.
8. A missing hook, admission, map, event, WAL interval, audit source, or
   provider proof narrows the result mechanically.
9. Every source disposition compiles only to a boundary capable of producing
   that physical result, and observe-mode evidence says `would_deny` or
   `would_reject` without claiming the effect occurred.
10. Every supported intent issuer proves authentication, nonce/sequence replay
    resistance, immutable target binding, expiry, mismatch behavior, and exact
    live-task claim; cloud CLI names never substitute for that proof.
11. Every advertised CI integration passes native-step, container-action,
    service/helper, matrix/fan-out, artifact/cache handoff, OIDC/authority,
    deployment approval, cleanup, cancellation, retry, and runner-reuse cases.

Until then, the phase result must state which invariant, event stage, runtime
entry class, effect family, or response postcondition remains unproved.

<a id="appendix-a-primary-technical-references"></a>

## Appendix A — Primary Technical References

### Local source snapshots

- [KubeArmor BPF LSM enforcer](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c)
- [KubeArmor policy lowering](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go)
- [KubeArmor container-map identity](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go)
- [KubeArmor NRI timing and teardown](../../../KubeArmor/KubeArmor/core/nriHandler.go)
- [Tetragon fork tracking](../../../tetragon/bpf/process/bpf_fork.c)
- [Tetragon process state](../../../tetragon/bpf/lib/process.h)
- [Tetragon cgroup policy filter](../../../tetragon/bpf/process/policy_filter.h)
- [Tetragon runtime-hook policy binding](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go)
- [Tetragon OCI hook](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go)

The short list above is retained for orientation. This expanded crosswalk is
the review index for every code-derived claim in Part II; line numbers in the
`KA-CODE-*`/`TG-CODE-*` table are relative to the pinned commits, while these
links provide the canonical local file:

| Source family | Canonical pinned files | Evidence exercised |
| --- | --- | --- |
| KubeArmor BPF LSM decisions, path programs, DNS, stacking, rendering and miss behavior | [`enforcer.bpf.c`](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c), [`enforcer_path.bpf.c`](../../../KubeArmor/KubeArmor/BPF/enforcer_path.bpf.c), [`shared.h`](../../../KubeArmor/KubeArmor/BPF/shared.h) | `KA-CODE-001`, `KA-CODE-002`, `KA-CODE-006`, `KA-CODE-011`, `KA-CODE-012`, `KA-CODE-015`, `KA-CODE-016`, `KA-CODE-020`, `KA-CODE-021`, `KA-CODE-022`, `KA-CODE-024`, `KA-CODE-025` |
| KubeArmor policy lowering, map publication/mutation, load/attach, capacity and action vocabulary | [`rulesHandling.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go), [`mapHelpers.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go), [`enforcer.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/enforcer.go), [`kubeUpdate.go`](../../../KubeArmor/KubeArmor/core/kubeUpdate.go), [`types.go`](../../../KubeArmor/KubeArmor/types/types.go) | `KA-CODE-002`, `KA-CODE-006`, `KA-CODE-007`, `KA-CODE-009`, `KA-CODE-011`, `KA-CODE-014`, `KA-CODE-019`, `KA-CODE-020`, `KA-CODE-027` |
| KubeArmor early system-monitor identity, bounded/LRU exec state, attach/reader behavior and userspace reconciliation | [`system_monitor.c`](../../../KubeArmor/KubeArmor/BPF/system_monitor.c), [`exec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/exec.bpf.c), [`systemMonitor.go`](../../../KubeArmor/KubeArmor/monitor/systemMonitor.go), [`processTree.go`](../../../KubeArmor/KubeArmor/monitor/processTree.go) | `KA-CODE-005`, `KA-CODE-008`, `KA-CODE-010`, `KA-CODE-023`, `KA-CODE-026`, `KA-CODE-028`, and KubeArmor's half of `TG-CODE-012` |
| KubeArmor runtime timing/lifetime | [`nriHandler.go`](../../../KubeArmor/KubeArmor/core/nriHandler.go) | `KA-CODE-004`, `KA-CODE-017` |
| KubeArmor network rule generation, DNS framing and NFLOG enrichment split | [`networkPolicyEnforcer.go`](../../../KubeArmor/KubeArmor/networkPolicyEnforcer/networkPolicyEnforcer.go), [`network types`](../../../KubeArmor/KubeArmor/types/types.go), [`DNS LSM/parser`](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c), [`DNS decoder`](../../../KubeArmor/KubeArmor/BPF/shared.h) | `KA-CODE-006`, `KA-CODE-012`, `KA-CODE-013`, `KA-CODE-015`, `KA-CODE-025` |
| KubeArmor concrete preset decisions, scope, evictable exec context and event/stacking behavior | [`protectenv.bpf.c`](../../../KubeArmor/KubeArmor/BPF/protectenv.bpf.c), [`filelessexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/filelessexec.bpf.c), [`anonmapexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/anonmapexec.bpf.c), [`protectproc.bpf.c`](../../../KubeArmor/KubeArmor/BPF/protectproc.bpf.c), [`exec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/exec.bpf.c), [`fileless preset reader`](../../../KubeArmor/KubeArmor/presets/filelessexec/preset.go) | `KA-CODE-003`, `KA-CODE-008`, `KA-CODE-018`, `KA-CODE-022`, `KA-CODE-026`, and KubeArmor's preset-reader half of `TG-CODE-012` |
| Tetragon fork/exec/non-leader/per-task boundaries, capacity and tests | [`bpf_fork.c`](../../../tetragon/bpf/process/bpf_fork.c), [`process.h`](../../../tetragon/bpf/lib/process.h), [`base.go`](../../../tetragon/pkg/sensors/base/base.go), [`bpf_execve_bprm_commit_creds.c`](../../../tetragon/bpf/process/bpf_execve_bprm_commit_creds.c), [`bpf_execve_event.c`](../../../tetragon/bpf/process/bpf_execve_event.c), [`bpf_execve_map_update.c`](../../../tetragon/bpf/process/bpf_execve_map_update.c), [`fork_test.go`](../../../tetragon/pkg/sensors/exec/fork_test.go), [`exec_test.go`](../../../tetragon/pkg/sensors/exec/exec_test.go), [`exit_test.go`](../../../tetragon/pkg/sensors/exec/exit_test.go), [`threads_test.go`](../../../tetragon/pkg/sensors/exec/threads_test.go), [`kprobe_sigkill_test.go`](../../../tetragon/pkg/sensors/tracing/kprobe_sigkill_test.go) | `TG-CODE-001`, `TG-CODE-002`, `TG-CODE-006`, `TG-CODE-014`, `TG-CODE-017`, `TG-CODE-018`, `TG-CODE-020`, `TG-CODE-024` |
| Tetragon Generic LSM action/output and separate staged enforcer | [`genericlsm.go`](../../../tetragon/pkg/sensors/tracing/genericlsm.go), [`generic_calls.h`](../../../tetragon/bpf/process/generic_calls.h), [`bpf_generic_lsm_core.c`](../../../tetragon/bpf/process/bpf_generic_lsm_core.c), [`bpf_generic_lsm_output.c`](../../../tetragon/bpf/process/bpf_generic_lsm_output.c), [`generic_maps.h`](../../../tetragon/bpf/process/generic_maps.h), [`basic.h`](../../../tetragon/bpf/process/types/basic.h), [`bpf_enforcer.h`](../../../tetragon/bpf/process/bpf_enforcer.h), [`bpf_enforcer.c`](../../../tetragon/bpf/process/bpf_enforcer.c), [`enforcer metrics`](../../../tetragon/pkg/metrics/enforcermetrics/enforcermetrics.go), [`socket kprobe example`](../../../tetragon/examples/tracingpolicy/security-socket-connect-block-others.yaml) | `TG-CODE-007`, `TG-CODE-010`, `TG-CODE-011`, `TG-CODE-013`, `TG-CODE-015`, `TG-CODE-019` |
| Tetragon cgroup filter, userspace selection, runtime metadata transport and non-atomic map mutation | [`policy_filter.h`](../../../tetragon/bpf/process/policy_filter.h), [`map.go`](../../../tetragon/pkg/policyfilter/map.go), [`state.go`](../../../tetragon/pkg/policyfilter/state.go), [`runtime hooks`](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go), [`runtime args`](../../../tetragon/pkg/rthooks/args.go), [`runtime server`](../../../tetragon/pkg/server/server.go), [`node main`](../../../tetragon/cmd/tetragon/main.go), [`runtime protobuf`](../../../tetragon/api/v1/tetragon/tetragon.proto), [`OCI hook`](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go) | `TG-CODE-003`, `TG-CODE-004`, `TG-CODE-009`, `TG-CODE-016`, `TG-CODE-021`, `TG-CODE-022`, `TG-CODE-023` |
| Tetragon node/process identity, cache and event/loss truth | [`node.go`](../../../tetragon/pkg/reader/node/node.go), [`process_id_linux.go`](../../../tetragon/pkg/process/process_id_linux.go), [`process.go`](../../../tetragon/pkg/process/process.go), [`cache.go`](../../../tetragon/pkg/process/cache.go), [`events.proto`](../../../tetragon/api/v1/tetragon/events.proto), [`observer_linux.go`](../../../tetragon/pkg/observer/observer_linux.go), [`observer metrics`](../../../tetragon/pkg/observer/metrics.go) | `TG-CODE-002`, `TG-CODE-005`, `TG-CODE-008`, `TG-CODE-018` |
| Tetragon one-process chassis and initial runtime handoff | [`main.go`](../../../tetragon/cmd/tetragon/main.go), [`runner.go`](../../../tetragon/pkg/rthooks/runner.go), [`args.go`](../../../tetragon/pkg/rthooks/args.go), [`server.go`](../../../tetragon/pkg/server/server.go), [`tetragon.proto`](../../../tetragon/api/v1/tetragon/tetragon.proto), [`OCI hook`](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go) | `TG-CODE-005`, `TG-CODE-009`, `TG-CODE-012`, `TG-CODE-017`, `TG-CODE-021`, `TG-CODE-023` |

Phase 0 verifies every link and recorded line range against the two pinned
commit IDs before accepting a provenance row. If a local clone moves or the
pin changes, the corresponding evidence ID is stale until a human reviews the
new code and updates both the claim and its hostile test; matching filenames
are not sufficient.

### Kernel and platform contracts

- [Linux BPF LSM programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux BPF iterators](https://docs.kernel.org/bpf/bpf_iterators.html)
- [Linux LSM hook reference](https://docs.kernel.org/security/lsm-development.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Linux cgroup-local BPF storage (`BPF_MAP_TYPE_CGRP_STORAGE`)](https://docs.kernel.org/6.17/bpf/map_cgrp_storage.html)
- [Linux deprecated cgroup storage semantics (`BPF_MAP_TYPE_CGROUP_STORAGE`)](https://docs.kernel.org/bpf/map_cgroup_storage.html)
- [Linux task-local BPF storage implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_task_storage.c)
- [Linux `kcmp` implementation and `KCMP_VM`](https://github.com/torvalds/linux/blob/master/kernel/kcmp.c)
- [Linux `CONFIG_KCMP` and checkpoint/restore selection](https://github.com/torvalds/linux/blob/master/init/Kconfig)
- [Linux `kcmp(2)` ABI, ptrace checks, and configuration history](https://man7.org/linux/man-pages/man2/kcmp.2.html)
- [Linux seccomp filter userspace contract](https://docs.kernel.org/userspace-api/seccomp_filter.html)
- [Linux Landlock userspace ABI](https://docs.kernel.org/userspace-api/landlock.html)
- [OCI runtime lifecycle](https://specs.opencontainers.org/runtime-spec/runtime/)
- [OCI hook ordering](https://specs.opencontainers.org/runtime-spec/config/)
- [Kubernetes lifecycle hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/)
- [Kubernetes probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/)
- [Kubernetes init containers](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)
- [Kubernetes sidecar containers](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
- [Kubernetes ephemeral containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [Kubernetes kubelet Checkpoint API](https://kubernetes.io/docs/reference/node/kubelet-checkpoint-api/)
- [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto)

### CI/CD coordinator and workload-identity contracts

- [GitHub Actions workflow, job, and step model](https://docs.github.com/en/actions/get-started/understand-github-actions)
- [GitHub Actions job and sibling-container behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container)
- [GitHub Actions OpenID Connect claims](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub Actions job-scoped `GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token)
- [GitHub Actions secure use of `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub Actions deployment environments and protection rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub Actions artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
- [GitHub App installation-token revocation](https://docs.github.com/en/rest/apps/installations#revoke-an-installation-access-token)
- [GitHub audit attribution by token identity](https://docs.github.com/en/enterprise-cloud@latest/organizations/keeping-your-organization-secure/managing-security-settings-for-your-organization/identifying-audit-log-events-performed-by-an-access-token)
- [GitLab Docker executor workflow](https://docs.gitlab.com/runner/executors/docker/)
- [GitLab Kubernetes executor Pod layout](https://docs.gitlab.com/runner/executors/kubernetes/)
- [GitLab CI/CD OIDC ID-token claims](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
- [Tekton Task, step-container, sidecar, workspace, and result model](https://tekton.dev/docs/pipelines/tasks/)
- [Jenkins Pipeline agent, stage, matrix, parallel, and post semantics](https://www.jenkins.io/doc/book/pipeline/syntax/)
- [Google Workload Identity Federation for deployment pipelines](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
- [AWS IAM source identity and session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)

### Incident sources used by the executable control map

- [Hugging Face technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [Local detailed incident analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Local normalized live-action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

<!-- Extend this architecture additively; preserve the decisions and examples above. -->
