# Node Component Redesign And Simplification

Simplify each Node component from its required behavior. Replace unnecessary
state, intermediate representations, and operation sequences. Also split the
large policy module. Duplicate-code removal is supporting work, not the main
design method.

Implementation status: **Not done**. A has implemented simplifications.
The 300-line increment is complete. The repository gate has one failing
E2E case. The direct-runc check also fails. Full qualification is not complete.
B-E remain proposed work. Approval to write the plan does not approve those
architecture changes or code.
Keep this work in one plan. Update its results after each approved deliverable.

The user approved A as the first implementation on 2026-10-07. A uses the
current target and lifetime APIs. This approval does not include B-E.
The user also approved test access changes for the new representation.
Keep all test scenarios, assertions, and behavior. Do not count test changes
as production reduction.

Parent: [Mithril master plan](./README.md).
Contracts: [signed enforcement](./phase-4-signed-local-pre-effect-enforcement.md),
[policy and runtime convergence](./phase-6-2-control-policy-and-evidence-convergence.md),
and [evidence and recovery](./phase-6-durable-evidence-coverage-and-recovery.md).
Use checked-out source to resolve historical implementation statements.
Source file lists below refer to `crates/mithril-node/src/`.

## Intended end state

- Keep all supported Node behavior and security guarantees. Keep one Node
  process, one Interceptor loader, existing gRPC services, and the frozen BPF
  ABI. Add no service, database, policy engine, or general workflow framework.
- Keep `NodeConfig` as startup input. Do not use a mutable copy as the current
  signed target and runtime-lifetime registry.
- Use the existing delivery journal as the current signed target and admitted
  lifetime record. Binding owners retain physical handles and kernel facts.
  Policy owners consume verified candidates and explicit target projections.
- Use one prepared policy model and one native generation row plan. Initial
  installation and binding refresh use that plan. A binding refresh does not
  rebuild immutable policy tables or compile another path graph.
- Keep one durable policy operation record with explicit intent, physical
  result, and ACK progress. Startup and live reconciliation use the same
  recovery decisions. Do not merge policy and exception authority.
- Keep Node segments as the authoritative delivery payload. Do not retain
  another complete payload collection solely to select upload batches.
- Make the policy module root thin. Split code by responsibility, not by line
  count. A module move has zero reduction credit.
- Target a net reduction of 5,000 production code lines. The target is not yet
  demonstrated. Preserve necessary comments and normal blank lines in all
  replacement code. Do not meet the target through formatting or feature loss.

## Required runtime flow

```text
Node starts
  -> TrustCache verifies the current durable trust generation
  -> NodePolicyDeliveryOwner opens the current delivery journal
  -> delivery verifies referenced signed material before it supplies authority
  -> WorkloadBindingOwner matches retained lifetimes to live CRI and kernel facts
  -> NodePolicyGenerationOwner reconciles intent with exact kernel readback
  -> each owner publishes readiness only for its verified state

Recovery finds a wrong epoch, stale lifetime, ambiguous pointer, or corrupt record
  -> the affected owner refuses authority
  -> Node closes the affected admission and evidence claims
  -> retry requires valid current material and exact physical readback
  -> recovery does not reconstruct authority from a PID or default identity

Control supplies a policy candidate
  -> delivery verifies its signature, target, sequence, time, and capabilities
  -> policy prepares one operation-owned candidate and generation row plan
  -> delivery persists activation intent before kernel publication
  -> policy stages rows under the existing generation lifecycle rules
  -> policy checks readback and runs the required activation probes
  -> policy checks the expected predecessor pointer
  -> policy publishes the approved active pointers
  -> binding adopts and verifies the qualified native binding state
  -> policy publishes entry authority last
  -> delivery commits the exact physical result
  -> Control accepts the result before delivery records ACK completion

Policy publication fails or the process stops
  -> delivery retains unresolved intent
  -> exact precommit absence permits cleanup of unreferenced candidate work
  -> proven candidate publication permits completion through the recovery path
  -> a mixed or unknown pointer result fences authority without guessed rollback
  -> recovery uses the same intent and physical-readback decision path
  -> delivery does not infer success from a file or a sent RPC

The first createRuntime hook requests Stage
  -> binding verifies and retains immutable first-hook runtime facts
  -> Stage grants no binding or exact-path authority
  -> failed reply delivery discards only those staged facts

The second createRuntime hook requests Prepare
  -> binding matches one signed target from the delivery journal
  -> binding verifies CRI Created state and held task, cgroup, and namespace facts
  -> preparation records only this lifetime transition and its prior record
  -> binding publishes and verifies the exact held root
  -> PreparedContainer has no process-view exact-path authority
  -> delivery commits the verified lifetime
  -> admission rechecks cancellation before it returns allow
  -> preparation waits for the caller's delivered receipt before completion

Prepare fails, is cancelled, or cannot confirm reply delivery
  -> preparation attempts both kernel cleanup and durable rollback
  -> durable cleanup still runs if kernel cleanup fails
  -> rollback does not resurrect a retired kernel binding
  -> incomplete cleanup closes readiness and does not return allow

The createContainer hook requests Entries
  -> binding matches the prepared lifetime and exact OCI bundle
  -> policy acquires the explicit OCI root through authenticated held descriptors
  -> policy measures routes and selectors for that retained view
  -> policy publishes binding rows for the existing signed generation
  -> policy publishes entry authority last
  -> binding verifies entry staging before admission returns the result

Entries fails or cannot confirm reply delivery
  -> admission does not claim a completed allow
  -> existing entry-stage cleanup and bounded authority remain in force
  -> Entries does not use Prepare's whole-lifetime rollback transaction

Periodic reconciliation sees PreparedContainer or a Running container
  -> PreparedContainer waits for its matching OCI Entries view
  -> Running recovery uses its separately qualified current process view
  -> reconciliation cannot replace admitted OCI routes with a new process view

An agent requests approved administrative execution
  -> authorization validates signed bytes and records durable replay acceptance
  -> the execution owner matches current binding, task, argv, and executable facts
  -> authorization derives the native slot from accepted proof and live match
  -> authorization returns an armed-slot receipt after intent and readback
  -> BPF consumes only the exact armed slot
  -> the execution owner records the checked physical result

A protected effect has a fixed kernel decision
  -> the bounded sole-reader queue supplies bytes to the evidence worker
  -> the worker decodes and attributes each accepted event
  -> coverage records source order and every applicable gap
  -> WAL writes bounded CRC32C frames and synchronizes the upload prefix
  -> delivery reads one bounded group from the retained segments
  -> Control persists the group before it returns an ACK
  -> WAL validates the ACK against the exact in-flight source and boundary
  -> WAL persists the ACK before it removes eligible segments

Evidence delivery fails, storage fills, or a source loses records
  -> the owner retains unacknowledged evidence
  -> coverage closes the affected claim with the exact reason
  -> retry reads the same unacknowledged prefix
  -> no userspace failure changes the already fixed kernel decision
```

## Component redesign proposals

These proposals require architecture approval before implementation. Review
them by the state and algorithms they remove, not by the number of functions.

### A. One prepared policy and native row plan

Baseline owners: `NodePolicyGenerationOwner`, `PreparedPolicy`,
`PreparedGeneration`, `LoweredGeneration`, `PathTables`, and
`LoweredNetworkPolicy` in `src/policy.rs` and `src/policy/`.

The policy component must turn verified signed material and measured binding
facts into qualified kernel authority. It does not need separate collections
that describe the same generation for each later operation.

Current approved deliverable: replace the row representation, share one
operation-owned verified candidate, group binding measurements, prepare entry
authority once, and split the policy module. The user deferred retained
preparation caching on 2026-10-07. The cache and its binding-only refresh path
are a separate step. Do not retain signed artifacts after this operation or
claim that this deliverable removes file loading and graph preparation from
later binding refresh. Set aggregate cache bounds before that separate step.
An oversized supported policy must not lose enforcement because of a cache
limit.

Replace the parallel table fields in `LoweredGeneration` with one private,
ordered row plan. Typed lowering adds rows through a conflict-checked insertion
boundary. Each table has one fixed specification for native layout, probe
kind, digest order, generation coordinates, and publication rules. Callers
cannot select weaker rules with flags. Keep special exception state and UTC
deadlines typed; do not reduce them to ordinary map updates.

The same plan supplies capacity checks, installation, readback, probes, digest
input, dynamic-row retention, and retirement. Remove the superseded table maps,
table-copy steps, per-binding merge plumbing, and parallel operation lists.
Do not retain those fields behind a new wrapper.

Prepare entry authority once. Keep one verified candidate snapshot for the
operation. Retain measurement records by binding, including the resolved case
with zero exact objects. Keep namespace views by their real held lifetime.
Before the separate cache step, specify which installed and pending generations
retain inputs, their aggregate count and byte bounds, and restart reconstruction. Existing
per-profile graph and compiled-cell limits are not an aggregate memory budget.
Preserve currently supported workloads and old live holders under those bounds.

After the separate cache step, a new container for policy generation 42 adds
its measured routes and entry rows. It does not reopen every policy file, rebuild the path graph, or
publish the immutable decision tables again. If the signed candidate changes,
use the full generation activation path.

Split the policy root into these cohesive responsibilities:

- preparation and binding measurements;
- typed lowering and the native row plan;
- publication, activation proof, and retirement;
- retained semantics and administrative policy lookup.

Reuse the existing policy module family. Keep public re-exports stable. Keep
effect-family lowering together where its native semantics differ. Do not add
a trait only to hide this module split. The split itself earns no line saving.

Proof must preserve exact digest domains and order, unequal-row rejection,
per-binding rejection when lowering emits zero actual decision rows,
insert-only mount guards, exception recovery,
entry-last publication, and tombstone-before-deletion. Activation-time validity
and signed role checks remain mandatory. A private byte-row plan is not a
public unchecked map-writing API.

Keep native `Preparing`, `ReadBack`, `Active`, `Retiring`, and `Tombstoned`
states. Retirement after restart uses durable descriptors and native maps; it
does not require the lost in-memory row plan. Check task, async, socket, domain,
pending-exec, and approval references before removal.

### B. One signed target and runtime-lifetime registry

Current paths: `config.rs`, `policy_delivery.rs`, `identity/binding.rs`,
`identity/runtime.rs`, `runtime_admission.rs`, and `node/admission.rs`.

The delivery journal retains signed desired state and admitted lifetimes.
`WorkloadBindingOwner` owns physical preparation, live handles, and native
binding state. `NodeConfig` supplies static host settings and startup inputs.
These are different responsibilities; do not keep complete mutable copies of
the signed target in all three owners.

Use a typed signed target with an optional admitted runtime lifetime. Keep
static-host targets explicit. The lifetime carries its actual binding identity,
container generation, runtime identity, and admission provenance. A published
physical binding refers to that record and retains its own cgroup descriptor,
held task facts, and kernel state. Remove `PublishedBinding.spec` only after
all its current consumers use the authoritative record or physical projection.

Replace `RuntimePreparation`'s full `NodeConfig` clone and whole-state rollback
copy with one lifetime transition under the existing delivery owner. Project
the exact policy inputs for this operation. Remove fabricated `scheduled:`
runtime IDs, repeated field resets, and index-based configuration replacement.

Example: a signed Pod target has no container yet. Its lifetime is absent.
Admission adds lifetime 7 after exact verification. Retirement removes that
lifetime without manufacturing another container ID. A restarted container
requires a new verified lifetime; it cannot reuse lifetime 7.

Proof must preserve signed target matching, distinct binding identities,
generation advance, Created admission versus Running recovery, retained-policy
behavior during a Control outage, cancellation, and kernel plus durable
rollback. A journal record cannot substitute for fresh physical verification.

### C. One durable policy operation, not configuration reconstruction

Current paths: `policy_delivery.rs`, `node/startup.rs`, `node/sync.rs`,
`node.rs`, and `policy/installation.rs`.

Delivery must remember accepted material, unresolved intent, checked physical
result, and Control ACK progress. Use one common candidate record and explicit
operation progress. Keep active authority and a pending replacement distinct.
Keep issuer and distribution high-water values distinct.

Supply a verified delivered candidate and target projection directly to policy.
Remove Control-delivered material's internal route through generated paths,
rebuilt mutable `NodeConfig`, and repeated file reload. Keep standalone local
artifact/key inputs and optional rollback-authorization/key inputs as another
route into the same native preparation model. Retain signed bytes and required
references on disk for restart verification. Do not replace cryptographic
verification with a serialized `verified` boolean.

Startup and live work call the same delivery reconciliation operation against
intent and exact kernel observations. Derive inspection summaries from those
records. Keep pending publication, physical proof, and ACK facts explicit;
one enum must not erase a necessary crash boundary. Preserve the existing
one-at-a-time operation limits, native anti-rollback history, generation
allocation history, and observable last-activation status.

Preserve the recorded staging time used to verify retained delivery material.
Recovery must not reject installed restrictions only because the delivery
window has expired. Fresh activation and live authorization still use their
required current-time checks. Exception deadlines remain independently enforced.

Example: the process stops after pointer publication but before the active
record commits. Restart reads the pending operation and checks that exact
generation. It commits the proven result or fences ambiguity. It does not
create another candidate or clear the pending record by guess.

Use a strict current durable schema. Remove old-format aliases and identity
hydration only where they serve compatibility, not current recovery. Keep
genuine optional state explicit. Do not add legacy readers or automatically
delete an existing state directory. Unsupported formats leave files and replay
floors intact and block admission. Agree on an internal format change before
implementation. Policy and exception records retain their separate lifetimes,
signature domains, use counters, and retained base references.

### D. Accepted proof and one retained measurement operation

Current paths: `identity/authorization/`, `administrative_exec.rs`,
`exact_object.rs`, and policy measurement consumers.

Keep signed proof acceptance under `AuthorizationProofOwner`. After fresh live
matching, produce one operation-owned execution value. The arm operation
derives its native key, slot, and receipt coordinates from that value. Do not
accept independently mutable copies of those coordinates and then reconcile
them across callers. Keep durable replay acceptance and kernel consumption
separate because they survive different failures. Accepted proof, armed-slot
receipt, kernel consumption, and execution evidence are different facts.

Keep `ExactFileObjectView` as the owner of held process, namespace, mountinfo,
and root descriptors. One measurement operation supplies route and selector
results for the same verified view. Pass the retained view into publication;
do not reacquire authority from its numeric PID. Preserve the topology and
root rechecks at the actual race boundaries.

Example: an executable is resolved in a held container view. Arming still
matches the current executable and task to the accepted signed proof. It does
not trust a stale measurement merely because the proof type is private.

This proposal must remove caller-maintained authority representations and
independent snapshot construction. New wrappers alone do not qualify.

### E. A disk-backed evidence spool with bounded delivery state

Current paths: `observation.rs`, `observation/wal.rs`, `node/run.rs`, and
`control.rs`.

Keep the Node delivery WAL separate from Control's retained analysis store.
Do not put `AnalysisStore` or DuckDB in Node. Reuse the existing shared
`EvidenceRecord` framing codec without changing the Node segment contract.

Replace `EvidenceWal.records` with ordered segment metadata and a bounded
reader position. Validate recovery one segment at a time. Use segment cursor
bounds and byte sizes for prefix selection and quota accounting. Do not build
an SQL catalogue or a complete in-memory record directory.

Retain one bounded in-flight group with its source, bytes, and exact ACK
boundaries. Remove the complete backlog payload cache and repeated group
clones. A failed connection can retain this bounded group or reread the same
frozen prefix. Keep source fairness and the existing commit-group limits.

Example: 200 MiB of unacknowledged evidence remains in segments. Delivery
holds only its bounded group and reader state, not all 200 MiB plus cloned
batches. An ACK outside the selected in-flight prefix or not at an uploaded
batch boundary still fails. Keep source association under the existing stream
contract; this proposal does not add fields to the ACK protocol.

Keep cached segment sizes and retained counts. Keep ACK persistence before
segment removal. Keep incomplete active-tail recovery different from sealed
corruption. Keep source and epoch boundaries, coverage gaps, partial-append
failure handling, and crash-safe removal. Read errors must reach the owner as
errors, not appear as an empty spool. If this reader needs more state or code
than it removes, revise the proposal before implementation.

## Findings to retain from the first review

These smaller findings support the component redesigns. Their savings overlap
with the larger proposals. Do not add overlapping estimates.

| ID | Change to preserve in this plan | Component |
| --- | --- | --- |
| 1 | Prepare signed entry authority, candidate verification, and binding measurements once. Also split the large policy module by responsibility. | A |
| 2 | Replace scheduled runtime placeholders with explicit target and lifetime state. | B |
| 3 | Remove unused `try_resolve_declared_entry`; whole-tree search found no caller. Recheck callers before deletion. | D |
| 4 | Use one concrete generation-table inventory. The sole row plan must replace parallel maps, not wrap them. | A |
| 5 | Complete coverage from its unary RPC result; remove its synthetic ACK queue and slot. Merge passive administrative inputs with existing stream combinators. Remove the redundant exception-reconciliation wrapper. | C, E |
| 6 | Collapse the WAL-capacity boolean and optional error into one recoverable state. Share real observation initialization and counter classification. Keep permanent failures and both recovery modes distinct. | E |
| 7 | Use existing `EvidenceRecord` conversions and prefix decoding instead of the Node frame codec. | E |
| 8 | Reuse `receive_notification` for asynchronous noninitial seccomp receive. Keep initial synchronous handover and response retries separate. | B |
| 9 | Construct `ObservationGrpc` once in `RuntimeObservationServer`; retain its listener and socket owner directly. Preserve peer and cgroup authorization. | E |

## Order and approval boundaries

Current approved order: implement A first against the current owner APIs.
Do not start B-E from this approval. The longer order below remains the
proposed order for the other component changes.

1. **Select the component designs.** For A-E, name the current authoritative
   input, required physical result, failure and restart behavior, replacement
   representation, and exact fields or algorithms to remove. Estimate both
   removed and added production code. Identify overlaps. Present a credible
   route toward 5,000 net lines, or state the unresolved shortfall. Obtain
   approval before code changes. Do not convert this step into repeated gap
   reports; update this document.
2. **Replace target and lifetime state together.** Implement B and the target
   portion of C before removing mutable configuration. Verify admission,
   retirement, restart, and rollback through the production owners. Commit
   each approved deliverable.
3. **Replace the policy representation and split its module.** Implement A
   against the new projections. Use the same row plan for full activation and
   binding-only publication. Do not add a second lowerer. Verify activation,
   conflicts, immutable-row preservation, and retirement before proceeding.
4. **Finish delivery and proof ownership.** Complete C and D. Remove obsolete
   reconstruction and coordinate copies only after their callers use the new
   owner paths. Verify crash boundaries, old-session handling, exception
   consumption, replay, fresh matching, and physical readback.
5. **Replace spool selection and simplify transport.** Implement E and the
   remaining small findings. Verify bounded reads, exact ACKs, quota behavior,
   reconnect, active-tail recovery, and sealed corruption. Do not change the
   Control raw-store design or trace backend.
6. **Review the complete Node result.** Run the quality and product gates,
   measure net code, and inspect the new owners for duplicate state or hidden
   replacement machinery. Report completed and remaining work. Do not claim
   the reduction target from an estimate.

Each step has a stop point: correct owner behavior must pass before the next
approved step starts. A passed test is not permission for another architecture
choice. Module moves can accompany a replacement but cannot replace it.

## Verification and constraints

- Reuse current crate tests. Add a small regression only for a missing
  transition. Test refactoring belongs to the separate workstream and has no
  reduction credit.
- Run focused `mithril-node` tests for each changed owner. Run the paired
  production-owner cases in `mithril-e2e` before physical qualification.
- Cover policy activation, binding refresh, direct-runc admission, retained
  runtime recovery, cancellation rollback, administrative proof replay,
  exception restart and consumption, evidence replay, corruption, capacity,
  and loss-aware coverage. Preserve legitimate allow and prohibited deny.
- Add the missing coverage case where a revision changes during a multi-source
  upload. Cover one administrative input closing while the other continues.
- Before changing Control connection ownership, check cancellation after newer
  trust is persisted but before handshake completion. Durable trust high-water
  must not roll back to an older in-memory candidate. Track a discovered
  failure separately; do not silently fold a security fix into this refactor.
- Run `bash .github/scripts/verify-rust-ci.sh` after the last Rust, Cargo, test,
  CI, or verification-script edit. Record the exact source state and results.
- Use existing physical Node qualification for changed enforcement, runtime,
  and recovery paths. Do not claim a VM or Kubernetes pass from unit tests.
- New or changed performance tests require explicit user approval of workload,
  duration, and limits. This plan does not supply that approval. Record
  performance as unqualified until approved measurements run.
- Put behavior on its state owner. Use `From` or `TryFrom` for complete
  single-input conversions. Free functions are limited to private stateless
  helpers. Add traits only at a real external or test-double boundary.
- New variables have at most three words; new function names have at most
  four. Keep stable external and required trait names unchanged.
- Preserve signatures, authority digests, anti-replay high-water values, held
  descriptors, source attribution, clocks, and physical readback. Do not
  merge states solely because their fields look similar.

## Reduction measurement and result

Baseline source: `6f326f63`. The first review counted 33,415 production code
lines and 35,110 production physical lines across 46 Node Rust files. Code
lines exclude tests, test-support items, blank lines, and comment-only lines.
Physical lines include normal comments and spacing outside excluded items.

Count every production addition needed by a replacement, including additions
in another crate, generated output, adapters, and retained old paths. Report
Node net and whole-workspace net separately. Moving code outside Node cannot
meet the target. Deleting comments, blank lines, diagnostics, supported fields,
or security checks cannot meet it either.

For each deliverable, record the old and new owners, removed representations
and passes, replacement additions, both net line counts, and exact proof.
Keep normal formatting and necessary comments. A function can exceed 400
lines when its remaining behavior is cohesive and necessary.

Current result: **Not done**. The implementation meets the requested
300-line increment. Full qualification is not complete.
The user requested a commit of the existing code and at least 300 fewer
production code lines in the next implementation. The existing code is
committed as `b197ac6e`. The next implementation uses this commit as its
reduction baseline. Keep retained caching outside this deliverable.
Do not start B-E.

The current implementation removes these representations and passes:

- `PreparedGeneration`, `PreparedPolicy`, and the final registry join.
  `LoweredGeneration::compile` makes one row plan for all profile bindings.
  `ProfileOperation` keeps the validated candidate, activation, and rows
  together until publication ends.
- Separate initial and replacement binding-install operations and caller
  branches. `install_bindings` accepts optional retained generation semantics.
- Copied mount-prefix lists, a second route-state directory, and a temporary
  terminal directory. The sole plan collects graph state IDs and native rows.
- `StoredIdV1` and the seven-field exception runtime copy.
  `ExceptionAuthorityOwner` retains normalized native runtime with its key,
  boot identity, and UTC deadline. The durable JSON format stays the same.
- The network handle registry, copied typed-effect coordinates, and repeated
  static witness updates. Signed destination order supplies stable handles.
  Each binding still needs an actual emitted decision witness.
- Duplicate OCI and process selector-resolution calls. The selected view
  supplies both route measurements and signed selector resolution.
- Hand-written ID conversion paths. Existing native conversion traits retain
  the same digest identities and byte order.

Task, async, and socket reference operations use one fixed list. Retirement
still checks each live holder with its typed native state. Native lifecycle,
anti-rollback, signed role checks, readback, exception recovery, entry-last
publication, and insert-only mount guards remain mandatory.

From `b197ac6e`, Node production code decreases from 33,440 to 33,118 lines.
Node production physical lines decrease from 35,166 to 34,833. The changed
E2E call sites add three lines. Count these additions against the saving.
The conservative whole-workspace reduction is 319 code lines and 330
physical lines. Tests, test-support items, comments, blank lines, and module
moves receive no code-reduction credit. The 300-line increment is met.
From the original `6f326f63` baseline, Node removes 297 code lines. The
earlier Control change adds three lines. The complete 5,000-line target is
not met. Binding refresh still prepares the full configured policy operation.

The focused policy command passes 62 tests:

```sh
cargo test -p mithril-node --all-features --lib policy:: -- --test-threads=1
```

The changed tests retain all scenarios and assertions. Three small regressions
cover native ID bytes, exception lock and reserved bytes, and durable decoding
diagnostics. No performance test was added or run.
The final command is:

```sh
CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 bash .github/scripts/verify-rust-ci.sh
```

Formatting, workspace checking, and strict Clippy pass. The workspace tests
stop in `mithril-e2e`: 166 pass, one fails, and 525 are ignored. The failing
case is `discovery::isolation::tests::discovery_owner_service_isolation`.
The case returns `RetainedRangeExpired { first_cursor: 1, last_cursor: 1 }`
from `araphor-data/src/analysis/raw.rs:350` through trace output. The case
reads retained trace output after it removes raw evidence. The same case
failed before this increment. No storage, query, or trace source changes in
this increment. The cause is not established. Do not change this test or
extend A to repair the storage path.

The workspace run passes all 295 active `araphor-data` tests and all 24 active
`araphor-observability` tests. The separate full Node command passes all 276
tests:

```sh
CARGO_INCREMENTAL=0 cargo test -p mithril-node --all-features --lib -- --test-threads=1
```

The direct-runc VM command is:

```sh
CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1 \
MITHRIL_VM_WORK_ROOT=/tmp/node-policy-proof.WmuhRa/vm-work \
bash crates/mithril-e2e/harness/vm/run.sh --entry-role-runtime-only \
  --output-directory /tmp/node-policy-proof.WmuhRa/vm-retry
```

The fresh VM installs the policy generation. The case then fails:
`canonical_mount_cache_states`: no BPF-ready mount snapshot at cache
generation 23. The same physical error occurred before this increment.
The cause is not established. The harness removes its disposable VM and
disk. Existing VMs remain unchanged. The log is
`/tmp/node-policy-proof.WmuhRa/vm-retry.log`. The first attempt did not start
a guest because libvirt lacked search permission on the temporary parent.
The retry changes only that task-owned directory permission.

No Kubernetes result covers this source state. Do not claim complete physical
qualification from the initial installation. The 319-line implementation
increment is **Done**. Full A qualification is **Not done**. Performance
remains unqualified.
