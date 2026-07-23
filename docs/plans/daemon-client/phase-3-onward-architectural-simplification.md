# Phase 3+ Architectural Simplification Candidates

Status: Proposal. No item is approved or implemented.

This is a separate decision record. It does not amend the master plan or any
phase plan. An item belongs here only when it removes a durable owner,
listener, protocol, or runtime model while preserving the intended product
contract. It does not contain hardening work, code movement, or new product
scope.

## Candidate Map

| Candidate | Owning phase if approved | Architectural removal |
| --- | --- | --- |
| F1 | Phase 3 | Runtime layered-policy composition across every enforcing surface |
| F2 | Phases 3 and 4 | Agent-owned session lifecycle extension points |
| F3 | Phase 4 | One Codex hook listener and accept loop per session |
| F4 | Phase 5 | A bespoke Hub HTTP catalog protocol and client |
| F5 | Phase 6 | The foreground standalone surface runtime and supervisor |

## F1: Compile One Effective Policy Revision Before Session Creation

### Current shape

Phase 3 proposes separate root, package, and selected-user policy layers. At
effect time, a new layered evaluator would combine their decisions with a
`NoMatch`/`NotApplicable` seam. That evaluator would be required in every
enforcing surface.

The current code already shows the beginning of this split:

- [`PolicySet`](../../../crates/erebor-runtime-policy/src/policy.rs#L26) is an
  ordered collection whose evaluation stops at the first matched local policy;
- [`read_policy_set`](../../../crates/erebor-runtime-session/src/policies.rs#L24)
  creates that runtime collection from multiple files; and
- the filesystem enforcer evaluates that collection for each physical effect in
  [`FilesystemFileOperationHandler::decide`](../../../crates/erebor-runtime-session/src/surfaces/filesystem.rs#L50).

If Phase 3 adds a second, cross-layer evaluator above this one, process,
filesystem, browser, and future surface owners must all correctly reproduce
two policy-composition models.

### Simplified target

When `erebor policy set create` selects immutable source revisions, the daemon
compiles them once into an immutable **effective policy revision**. The
revision contains:

- the source-policy digests and their roles (root minimum, package minimum,
  selected user policy);
- the compiler/version and the complete precedence result;
- rule-origin information for audit and `inspect`; and
- one canonical decision program consumed by every runtime guard and surface.

The compiler enforces the existing product semantics while creating the
revision: any applicable deny wins; mediation constraints become stricter or
reject as incompatible; approval cannot weaken either; and an allow is emitted
only when all mandatory inputs permit it. Source packages remain separately
inspectable and distributable. `SessionSpec` records the effective-revision
digest and the complete source-digest inventory.

The effective revision is immutable. A root or user policy change creates a
new revision for later sessions; it does not silently rewrite a running
session's admitted policy.

### What this removes

- A long-lived runtime layered evaluator and its `NoMatch`/`NotApplicable`
  protocol between policy layers.
- Per-surface composition code and the risk that one surface implements a
  different cross-layer precedence rule.
- The need for a guard request to carry and resolve several policy layers.

It does **not** remove policy packages, policy-set aliases, source-level audit,
or the ability to explain which source rule produced a decision.

### Required proof if approved

- Compilation preserves every mandated deny, mediation, approval, and
  first-match result with an origin trace.
- Every enforcing surface evaluates the same effective-revision fixture and
  returns the same decision.
- Conflicting mandatory sources reject policy-set creation before a session can
  be created.
- Inspection of the effective revision reconstructs its complete immutable
  source inventory.

## F2: Keep One Session Lifecycle Owner; Make Adapters Declarative

### Current shape

Phase 3 currently assigns adapter validation, installation verification,
preparation, entrypoint resolution, and lifecycle observation to one generic
adapter trait. Phase 4 then adds an adapter-owned Codex hook broker as a
per-session resource.

The daemon path already has a clear lifecycle owner:

- [`SessionManager`](../../../crates/erebor-runtime-session/src/session_manager.rs#L73)
  creates, starts, recovers, finalizes, and persists sessions;
- [`RunnerDriver`](../../../crates/erebor-runtime-session/src/runners.rs#L226)
  admits, prepares, starts, recovers, and removes runner execution; and
- the current Phase 4 plan explicitly says an adapter cannot write final
  session state or choose a runner.

Leaving lifecycle observation as a broad adapter responsibility would invite
adapter-specific start/recover/stop ownership beside `SessionManager` and
`RunnerDriver`.

### Simplified target

An adapter may only do agent-specific work in two narrow forms:

1. **Admission compilation:** validate its immutable package and installation,
   then return a declarative agent execution contribution: command shape,
   read-only artifacts, endpoint registrations, required capabilities, and
   schema-pinned event definitions.
2. **Event translation:** after a daemon-owned ingress service authenticates a
   message, interpret that agent's declared message schema into attribution or
   context. This cannot transition a session or authorize a physical effect.

`SessionManager` remains the only owner of lifecycle state, retry, recovery,
terminal finalization, and cleanup. `RunnerDriver` remains the only owner of
how an admitted workload is started, recovered, signalled, or removed. An
agent-specific resource can register with the daemon while a session is live,
but it is not an adapter-managed session engine.

### What this removes

- Adapter lifecycle callbacks and per-adapter recovery/state-machine APIs.
- A future parallel session supervisor for Codex, Claude, or another agent.
- Ambiguity over whether an adapter or the daemon records terminal state after
  an agent-side service fails.

It preserves agent-specific projections, hook schemas, authenticated
attribution, App Server transport, and any agent-specific private endpoint.

### Required proof if approved

- The generic adapter contract has no lifecycle transition, runner selection,
  or durable-session mutation method.
- A failed adapter service is reported to `SessionManager`, which performs the
  one recorded lifecycle transition and cleanup.
- A Codex fixture proves that its hook and App Server behavior remains intact
  while the session lifecycle is still owned only by the daemon and runner.

## F3: Use One Shared Codex Hook Service, Not One Server Per Session

### Current shape

The current direct Codex implementation creates a new Unix listener, socket
directory, accept-loop thread, and additional worker threads for every managed
session:

- [`CodexHookBroker`](../../../crates/erebor-runtime-session/src/agents/codex/broker.rs#L45)
  is explicitly a single-session endpoint;
- its [`start`](../../../crates/erebor-runtime-session/src/agents/codex/broker.rs#L52)
  method allocates a private directory and binds a socket;
- it starts an accept loop and a thread per accepted connection at
  [lines 67–82](../../../crates/erebor-runtime-session/src/agents/codex/broker.rs#L67); and
- it projects that private directory into the session at
  [`session_projection`](../../../crates/erebor-runtime-session/src/agents/codex/broker.rs#L125).

Phase 4 carries this forward by calling the hook broker a per-session resource.
That would create a server lifecycle for every Codex session rather than a
single daemon-owned hook ingress service with per-session registrations.

### Simplified target

Run one root-owned **Codex hook service** inside `erebord`, with one listener
and a daemon-owned registration table. Starting a Codex session registers its
session id, exact single-use ticket authority, expected peer facts,
reconciliation owner, and invocation-lease owner. Ending or recovering the
session removes or replaces that registration.

The managed session still sees only its fixed private hook path. It connects to
the shared listener through that projection, then presents an exact
session-bound ticket in its hello. The service authenticates the peer before
selecting the registration and rejects a wrong-session, replayed, expired, or
wrong-peer ticket before an event reaches Codex attribution code.

This remains a third, distinct `erebord` ingress service:

- daemon-control traffic remains on the daemon control service;
- Linux/macOS guard traffic remains on the runtime guard service; and
- Codex hook traffic remains on the Codex hook service.

It does not merge their message families, authorization state, or routing.

### What this removes

- One Unix listener, host directory, accept loop, and server lifetime per
  Codex session.
- A per-session socket projection whose only purpose is selecting a broker
  instance.
- A second source of per-session service shutdown/recovery semantics outside
  the daemon lifecycle owner.

### Required proof if approved

- Many active Codex sessions register through one listener while receiving
  only their own authenticated events.
- A valid ticket from session A cannot route to session B, including when the
  two sessions use the same owner UID.
- Registration removal, daemon restart, and session recovery make the old
  ticket fail closed.
- The hook protocol cannot be sent to the daemon-control or runtime-guard
  service, and their messages cannot be accepted by the hook service.

## F4: Make the Hub a Signed OCI Catalog Artifact

### Current shape

Phase 5 already makes OCI Distribution the transport for packages, signatures,
attestations, and pull/push. It additionally proposes a different, versioned
Hub catalog HTTP API, daemon client, credentials path, fixture server, and
network-safety branch for `erebor search`.

There is no OCI or Hub implementation in the daemon yet:
[`erebor-runtime-daemon/Cargo.toml`](../../../crates/erebor-runtime-daemon/Cargo.toml)
has no registry dependency and
[`erebor-runtime-daemon/src/lib.rs`](../../../crates/erebor-runtime-daemon/src/lib.rs)
has no registry or Hub owner. This decision can therefore remove a protocol
before it becomes deployed architecture.

### Simplified target

Represent each configured public or organization Hub as a signed OCI
**catalog artifact** in an allowed registry namespace. The catalog contains
the discovery fields Phase 5 needs: package references and digests, publisher
identity, platform/adapter/runner facts, and narrow certification labels.

`erebor search` refreshes and searches the verified local catalog snapshot.
`erebor pull` still resolves the selected registry reference independently,
fetches its full OCI graph, and applies signature, attestation, revocation,
package, policy, and runner checks. A catalog entry is discovery metadata only;
it never installs or authorizes content.

The same OCI registry client, credential boundary, origin rules, cache, and
fixture registry serve package transfer and catalog refresh. Root configuration
may select one or more catalog artifact references, or none.

### What this removes

- A bespoke Hub HTTP schema, daemon client, server fixture, token type, and
  separate redirect/DNS/SSRF implementation.
- A second remote trust and cache model beside OCI manifests and referrers.
- The possibility that the Hub and registry clients diverge on origin,
  credential, retry, or cancellation behavior.

### Deliberate trade-off

The first product would offer deterministic search over a refreshed signed
catalog snapshot, not server-side fuzzy ranking or personalized search. If
those capabilities later justify a hosted query API, they require a separate
approved phase; they are not silently reintroduced behind the OCI client.

### Required proof if approved

- Public, organization, and disabled-Hub configurations work solely through
  OCI references.
- A catalog entry that disagrees with the registry cannot affect the digest
  finally verified and installed.
- Catalog refresh reuses the registry credential and network controls without
  exposing a separate Hub credential.
- Offline search clearly reports the snapshot generation and trust age.

## F5: Retire the Foreground Surface Supervisor Before Ambient Surfaces

### Current shape

The current direct runtime has its own surface-lifecycle stack:

- [`SessionSurfaceLauncher`](../../../crates/erebor-runtime-core/src/runtime.rs#L32)
  owns a vector of services and creates a private Tokio runtime;
- [`SessionSurfaceSupervisor`](../../../crates/erebor-runtime-core/src/runtime.rs#L101)
  owns their blocking wait loop; and
- [`SurfaceServiceRunner`](../../../crates/erebor-runtime-session/src/surface_services.rs#L13)
  starts that stack from the foreground path.

Phase 6 correctly requires daemon-owned ambient surfaces, but merely evolving
these owners risks retaining the foreground supervisor beside a new durable
surface supervisor.

### Simplified target

Replace the foreground surface stack with one daemon-owned ambient-surface
supervisor. It runs in `erebord`'s long-lived runtime and owns the durable
surface record, health, restart classification, logs, evidence, and shutdown.
The only listener exposed by a surface is the surface's actual governed
endpoint; there is no standalone foreground surface control runtime.

This does **not** model an ambient surface as a session. A surface remains its
own typed, UID-scoped resource because it may outlive and be bound by several
sessions. It only removes the duplicate process/supervisor implementation.

### What this removes

- `SessionSurfaceLauncher`, `SessionSurfaceSupervisor`, and
  `SurfaceServiceRunner` as a second foreground lifecycle system.
- A private per-invocation Tokio runtime and blocking wait loop for governed
  surface lifetime.
- The risk that a surface keeps running only because a CLI-owned process is
  still alive.

### Required proof if approved

- An ambient surface continues correctly after the creating client exits and
  is recovered or stopped only by its recorded daemon policy.
- The old foreground `start` and `dev proxy-cdp` execution paths have no
  production callers.
- Surface lifecycle events, logs, and recovery are emitted by the daemon
  owner, not a CLI process.
- Binding a session to a surface checks the immutable surface id and policy
  identity without turning the surface into a session or exposing the daemon
  control socket.

## Phase Boundaries

- F1 is a Phase 3 policy-model choice and must be decided before a layered
  runtime evaluator is introduced.
- F2 defines the generic adapter boundary in Phase 3 and constrains the Codex
  implementation in Phase 4.
- F3 is Phase 4 work after F2; it is specific to the proven Codex hook
  protocol, not a generic agent-plugin system.
- F4 is a Phase 5 protocol choice. It preserves Hub discovery while avoiding a
  second remote service contract.
- F5 is Phase 6 work. It preserves the separate ambient-surface object and
  does not merge it with either the daemon-control or runtime-guard service.
- Phases 7 and 8 intentionally remain discovery-led for Claude Code; no
  Claude-specific simplification is proposed before Phase 7 supplies evidence.
- Phase 9 is certification and hardening. It should verify these decisions,
  not introduce a competing lifecycle, policy, ingress, or Hub architecture.

## Decision Rule

Approve items independently. Before implementation, copy only an approved
candidate into the owning phase plan with exact affected files, migration
order, and code-backed tests. Do not implement an unapproved candidate from
this record.
