# Phase 5: Agent, Policy, And Surface Resource Model

Status: Proposed design master. This document defines the vocabulary and
decision order for a possible Phase 5 expansion. It authorizes no code or CLI
change.

Parent plan: [Phase 5: Daemon-Owned Ambient Surfaces](../phase-5-daemon-owned-ambient-surfaces.md)

## Goal

Make agent build artifacts, policy, surfaces, and sessions understandable as
separate Erebor resources. An `Agentfile` is a future build recipe for an
immutable `Agent`; an `Agent` is not a session configuration object. Policy
remains surface-owned, and no source file becomes a second runtime authority.

The existing Docker-inspired CLI remains the working product direction:

```text
erebor surface create|start|ls|inspect|logs|events|stop|rm
```

This design does not introduce `erebor apply`, remove or rename an existing
command, require an `Ereborfile`, or change the current daemon/client
ownership model. Any such proposal needs its own approved subphase after the
resource contracts below are complete.

## Why This Is A Separate Master

The current parent Phase 5 correctly owns daemon-owned ambient surfaces,
filesystem ownership, agent-state projection, and removal of `erebor start`.
It deliberately defers declarative reconciliation until it can state identity,
create, update, delete, ownership, recovery, and evidence semantics.

The desired product model adds a broader question before that work: what
exactly is an agent, a reusable policy package, a surface, and a concrete
session; and which resource is allowed to govern execution? That question
must have an answer independent of a file format or a CLI spelling.

## Reuse-First Implementation Rule

Phase 5 is an ownership and contract migration, not permission to rewrite
working Erebor subsystems. Each implementation starts by identifying the
existing owner and reuses as much of its storage layout, behavior, recovery,
evidence, and test coverage as remains compatible with the Phase 5 contract.
New daemon/resource code should wrap, call, or move an existing owner before
creating a new abstraction. It must not recreate behavior that can be reused.

| Existing owner/mechanism | Reuse as far as compatible | Change only as necessary |
| --- | --- | --- |
| Verified local-agent enrollment, descriptor-broker resolution, staging, and executable verification | The existing `erebor agent load … --from …` path and its daemon-owned verification evidence | Bind the supplied Agent name and explicit built-in adapter to its existing verified result. |
| PolicyPackage lifecycle, `RuntimeEvent` matching, ordered policy evaluation, decisions, and evidence | Rule evaluation remains owned by the existing policy/runtime path | Validate the v1 resource envelope and replace only untyped mediation metadata with the existing built-in handler's typed contract. |
| `RuntimeGuardService`, `RuntimeInterceptionBrokerServer`, `SessionInterceptionSetup`, ptrace guards, and Phase 4 controller PTY | One shared interception listener and the existing per-Session routing, guard, PTY, input, resize, detach, and reattach behavior | Bind those existing per-Session results into Session admission/evidence; do not create a second terminal broker or PTY system. |
| `FilesystemSessionStorage`, `SystemOstreeRepository`, volume-overlay planning, and existing filesystem transaction/retention domain behavior | `prepare`, `open_existing`, the per-Session `filesystem/repo` and `filesystem/work` layout, and one OSTree repository per Session | Put daemon lifecycle and policy enforcement around that storage owner; no repository migration, replacement planner, or second filesystem store. |
| `erebor-runtime-cdp` browser/process/endpoint owners and endpoint authorization | Browser process identity, endpoint ownership, security checks, and evidence | Re-home only the incompatible foreground lifecycle wrappers under daemon supervision; do not reimplement CDP transport or browser ownership. |
| Docker-inspired daemon/client command direction | Existing command families and typed client/daemon boundaries | Only the explicitly approved command/interface cutovers in their owning subphase; no `apply`, manifest reconciler, or broad CLI redesign. |

Replacement is appropriate only when reuse cannot satisfy daemon-owned
governance. The plan must identify the exact owner or behavior that changes,
why it must change, what is still reused, and the test/evidence that proves no
enforcement, recovery, attribution, or physical-effect guarantee was lost.
Every subphase below is bound by this rule.

## Proposed Resource Model

```text
Agentfile -- build --> Agent --+
                             Session --> intrinsic Surface bindings
PolicyPackage -- compose --> PolicySet -+          ^
                                                    |
                                  named Surface configuration ---+
```

## Surface Model

A **Surface** is a registered governance domain. Every governing Rule maps to
one Surface: `terminal`, `filesystem`, or `browser_cdp`. A Surface is either
intrinsic or named; these are lifecycle/configuration forms of one concept, not
separate user-visible resource categories.

```text
Surface           = governance domain: terminal, filesystem, browser_cdp
Intrinsic Surface = daemon-provided Surface with no public configuration record
Named Surface     = independently configured Surface with a public record
SurfaceRuntime    = compiled-in, daemon-controlled realization of one Surface
SurfaceBinding    = session-specific authority and context from that runtime
Runner             = consumes a binding; it never owns governance
```

The registry is extensible by Erebor source code, but it is not user-extensible
at runtime. A runtime implementation is compiled into `erebord` and registered
by the daemon. A policy, Agent, or Surface document cannot load a plugin,
library, executable, or driver.

The initial Surface definitions are deliberately asymmetric. The first column
names the governing Surface; the runtime column names only the daemon
implementation that realizes it.

| Governance Surface | Form | Daemon implementation | Session result |
| --- | --- | --- | --- |
| `terminal` | Intrinsic Surface | `TerminalSurfaceRuntime` | One shared interception listener routes every session through a session router and token. PTYs and guard injection are session bindings. |
| `filesystem` | Intrinsic Surface | `LinuxOstreeOverlayFilesystemRuntime` | One runtime serves the daemon and reuses `FilesystemSessionStorage`. Each Session receives its own existing storage layout and OSTree repository, lower/upper/projection state, checkpoints, and session attribution. |
| `browser_cdp` | Named Surface when independently configured | Browser CDP runtime | A named Surface configuration supplies one authorized endpoint/lease binding for an admitted Session. |

### How intrinsic Surfaces are realized

`terminal` and `filesystem` are the intrinsic Surfaces. `TerminalSurfaceRuntime`
and `LinuxOstreeOverlayFilesystemRuntime` are not additional Surfaces or public
resource types: they are the daemon-owned implementations that realize those
two Surfaces. The following is the Phase 5 ownership model, not a sketch for a
future plugin system.

```text
intrinsic `terminal` Surface
  └── realized by one TerminalSurfaceRuntime
        └── per-session TerminalBinding
              ├── routing/token
              ├── PTY
              └── guard injection / environment

intrinsic `filesystem` Surface
  └── realized by one LinuxOstreeOverlayFilesystemRuntime
        └── per-session FilesystemBinding/View
              ├── one OSTree repository under that Session's storage root
              ├── lower/snapshot selection
              ├── upper/work/projection state
              ├── checkpoints
              └── session-scoped filesystem audit handler
```

The intrinsic `terminal` and `filesystem` Surfaces need no user-created Surface
document. Their implementations are daemon-long-lived; neither is created by a
Session or Runner. A Session creates only its binding. In particular, **each
Session has one OSTree repository**; the filesystem runtime owns
implementation and storage policy, while the filesystem binding owns that
repository's temporary view, checkpoints, and attribution. `LinuxHostRunner`
and future `DockerRunner` consume bindings. They do not create interception,
repositories, filesystem enforcement, or browser processes.

`LinuxHostRunner` and a future `DockerRunner` consume the filesystem and
terminal bindings that these runtimes provide. They do not create interception,
filesystem governance, browser processes, or a replacement runtime. A future
Docker-compatible filesystem implementation is another compiled-in
`FilesystemSurfaceRuntime`, not a runner and not a user-loadable plugin.

The current source tree already supports the terminal distinction:
`RuntimeGuardService` owns a shared `RuntimeInterceptionBrokerServer`, while
`SessionInterceptionSetup` registers the per-session route/token and the Linux
interception backend prepares per-session guard resources. The current
`FilesystemSessionStorage::prepare` instead initializes an OSTree repository
beneath each session directory through `SystemOstreeRepository`. Phase 5
preserves and reuses `FilesystemSessionStorage`—including its `prepare` and
`open_existing` lifecycle, per-session layout, and repository initialization—
as the storage owner inside each filesystem binding. The long-lived daemon
runtime orchestrates that existing owner; it does not replace it, migrate its
layout, or create a second storage model.

## Resource Envelope

Every declared Phase 5 resource uses the same versioned envelope:

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Agent | PolicyPackage | PolicySet | Surface | Session",
  "metadata": { "name": "user-chosen-immutable-name" },
  "spec": {}
}
```

`apiVersion`, `kind`, and `metadata.name` are required and validated together.
The daemon rejects an unknown version, kind, or missing name; it never guesses
a schema, adapter, or resource identity. `Session` is created at runtime, but
its persisted inspection record uses the same envelope.

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the resource schema and compatibility rules. Phase 5 accepts only `erebor.dev/v1`; an unknown value is rejected before resource-specific validation. | API contract |
| `kind` | Selects the resource validator and store owner. It is one of `Agent`, `PolicyPackage`, `PolicySet`, `Surface`, or `Session`; it is never inferred from a filename or command. | API contract |
| `metadata` | Carries resource identity metadata. Phase 5 defines only `metadata.name`; no labels, generated aliases, or mutable tags exist. | Resource owner |
| `metadata.name` | Stable, owner-scoped handle used by people and commands. The creator supplies it for Agent, PolicyPackage, PolicySet, and Surface; the daemon assigns it for a runtime-created Session. It never retargets. | Resource owner |
| `spec` | Contains only the resource's declared behavior. Its exact fields are fixed by the subphase that introduces the resource. `PolicySet.spec.packages` is the sole static composition reference; `Session.spec` is the sole execution association. | Resource owner |
| `status` | Optional daemon-written inspection output, never create input. It reports observed lifecycle and physical effects without becoming another configuration authority. | Daemon |

### PolicyPackage

A `PolicyPackage` is a reusable, immutable package of governing rules. It is
the unit supplied through the existing policy-package lifecycle and carries
its own daemon-verified immutable revision.

Its required `metadata.name` is the user-facing package reference. The daemon
resolves that name to its immutable revision internally; it does not expose a
second alias or raw integrity identifier.

Each Rule's existing `match.surface` declares the physical event surface it
governs, such as `filesystem` or `browser_cdp`. A package does not reference a
named Surface, and Phase 5 does not add a second package-level surface list:
that
would make a reusable package both dependent on an execution instance and
internally inconsistent.

It is not an agent package, a process extension, or a way to load code into
the daemon.

### PolicySet

A `PolicySet` is a reusable, ordered, immutable composition of
`PolicyPackage` names. Its package order and resolved revisions are
evidence-bearing facts. Its eligible Surfaces are derived from the
`match.surface` coverage of every mandatory package. `spec.packages` is the
one deliberate static resource reference: the package owns rules, the set owns
membership/order. A PolicySet does not select a named Surface or attach to an
Agent.

Every user-addressable `PolicySet` has a declared `metadata.name`; it is not a
separate mutable alias. References use that name and the daemon records the
resolved immutable revision in admission and evidence.

### Agentfile

An `Agentfile` is a future Dockerfile-like **agent build recipe**. It creates
one immutable `Agent` artifact; it does not create a session or choose a
surface. A derived Agentfile names one exact base agent with `FROM`. The base
agent includes its built-in adapter, so the derived result inherits that
adapter.

A root Agentfile may select one allowed built-in adapter with `ADAPTER`; a
derived Agentfile inherits the adapter from `FROM`. The final grammar must
reject an ambiguous recipe that changes the adapter after `FROM`.

Agentfile instructions may assemble declared agent configuration and support
artifacts into the output. They must not attach policy packages, select a
surface, name a caller host path, include live credentials or private state,
or load code into `erebord`.

### Agent

An `Agent` is the immutable build result of an Agentfile, analogous to a
Docker image. It records its exact base Agent when one exists, its adapter
identity, and every admitted build input as daemon-owned provenance. It has one
user-chosen `metadata.name` in its schema. That name is not a separately
generated alias: it is bound once to one immutable agent revision in an owner
namespace. A session may be requested by Agent name, and admission records the
resolved revision internally. A changed agent artifact requires a new Agent
name; a name never retargets silently.

The adapter is an Erebor-compiled integration contract, not a user-loaded
plugin, script, or executable path. A base agent supplies one adapter; an
agent derived from it cannot silently replace that adapter.

An Agent contains only portable, non-secret agent material. In Phase 5.1 its
only declared behavior is the adapter identity. It has no policy, state-path,
mount, host-path, or private-state field. The compiled adapter contract—not an
Agent resource field—defines that Codex uses a fixed private `CODEX_HOME`
target. The daemon-owned runtime realizing the intrinsic filesystem Surface
owns the projection and the Session records the physical result; neither the
Agent nor its adapter chooses the source.

The existing `erebor agent load … --from …` verification path remains the
Phase 5 producer for a locally enrolled Agent, but Phase 5 requires its Agent
name and built-in adapter as explicit input. It must bind that declared name
and adapter to the verified staged revision rather than generate a separate
alias or infer an adapter from a path, executable, package name, or environment.
How that verified local record becomes a base-agent build input—or whether an
Agentfile build instead stages its own portable executable artifact—is an open
Phase 6 build-provenance decision. It is not a reason to invent an
`installationRef` field or change the `Agent` resource/session-admission model
fixed in Phase 5.1.

### Surface

A named `Surface` is an optional, independently configured execution-boundary
record. Its required `metadata.name` is the user-facing reference, not a
mutable alias. It is independent: it does not select a PolicySet, list Agents,
or know Sessions. It owns only the daemon-enforced configuration and lifecycle
needed by its registered kind, such as a Browser CDP endpoint, evidence, and
recovery.

Every registered Surface exists in the governance/runtime registry whether or
not it has a named `Surface` document. Filesystem is an intrinsic Surface in
Phase 5: it is governed as `filesystem`, but no user creates an
`engineering-workspace` Surface merely to name it. Browser CDP has independent
endpoint configuration/lifecycle, so it may have a named `Surface` document.

`Session` is the only runtime association point. It selects an Agent and
PolicySet and may name the independent Surface records needed by its binding
plan. The daemon derives intrinsic bindings from the compiled adapter and the
PolicySet's surface rules, validates every named binding against the same plan,
and records the resolved identities. Neither a Surface nor an Agent can merge,
weaken, or select policy by itself.

### Session

A `Session` is one concrete daemon-owned runtime instance of an immutable
Agent, analogous to a container created from an image. It is the only resource
that references the Agent, PolicySet, and any named Surface records. It records
the resulting intrinsic and named Surface bindings after compatibility
validation. It is normally created at runtime by the existing run/session flow
rather than declared as standing configuration.

### Mediation Is Directed By Policy

`mediate` is not an allow decision with a more descriptive receipt. It means
the original physical effect must not happen; the owning execution surface must
replace it with the explicitly policy-required governed surface. A policy
package supplies the rule and requested outcome. It never runs a handler,
launches a process, chooses a named replacement Surface, or executes arbitrary
JSON.

The existing policy evaluator accepts and preserves this concrete Rule today:

```json
{
  "id": "mediate-managed-browser-launch",
  "match": {
    "surface": "terminal",
    "action": "process_exec",
    "command_contains": "--remote-debugging-port"
  },
  "decision": "mediate",
  "reason": "replace a raw browser launch with an Erebor-owned CDP endpoint",
  "mediation": {
    "kind": "managed_browser_cdp",
    "replacement_surface": "browser_cdp",
    "return_endpoint": "requested_port"
  }
}
```

| Field | Meaning in this example |
| --- | --- |
| `match.surface: terminal` | The attempted raw browser launch is a terminal process-exec event. It is not a Browser CDP event because no browser endpoint may yet exist. |
| `decision: mediate` | The terminal owner must not execute the original raw launch. It must either perform a supported replacement or fail closed. |
| `mediation.kind: managed_browser_cdp` | Names the daemon-compiled mediation handler. It is not a user plugin or executable. |
| `mediation.replacement_surface: browser_cdp` | Explicitly requires the `browser_cdp` Surface. The policy authorizes no other replacement, and it does not name a machine-specific Surface record. |
| `mediation.return_endpoint: requested_port` | Requests the response form expected by the intercepted command. It does not authorize the requested port, select a listener, or name a Surface. |

The intended physical flow is:

```text
agent command
  -> terminal RuntimeEvent
  -> PolicySet evaluates the matching PolicyPackage Rule
  -> Mediate(kind=managed_browser_cdp, replacement_surface=browser_cdp)
  -> terminal surface handler rejects the raw exec
  -> Session's already admitted browser_cdp binding provides its governed endpoint
  -> handler returns only the mediated endpoint and records the replacement
```

The existing implementation is useful precedent but not a completed Phase 5
resource design: `crates/erebor-runtime-policy/src/policy.rs` currently stores
`mediation` as unconstrained JSON, while the runtime mediation result carries a
typed replacement surface, endpoint, lease, printable response, and keepalive
contract. Preserving JSON proves that metadata survives policy evaluation; it
does not prove that a Surface can safely execute the request.

Phase 5 replaces that untyped handoff with a registry-validated mediation
request. PolicyPackage admission validates the built-in request shape. The
Session explicitly supplies one named Surface record when the required target
Surface needs independent configuration; later runtime admission activates that
exact record as the `browser_cdp` binding. The terminal handler performs no
runtime discovery and never creates an arbitrary browser. It uses only the
activated binding; if it cannot be activated, the mediated action fails closed.

The target belongs on the matching Rule, not in a duplicate
`PolicySet.mediatedSurfaces` list. PolicySet composition already carries the
Rule in immutable order; a second list would create two sources of truth. The
PolicyPackage names a Surface rather than a named Surface record so the same
package can govern different owners' independently configured browsers.

`replacement_surface` authorizes the replacement itself; it is not an
unconditional allow for later actions on that target. Once the returned Browser
CDP lease is used, Browser CDP events still evaluate the PolicySet's ordinary
Rules with `match.surface: browser_cdp`. This keeps issuing a governed endpoint
and governing actions through it as separate physical-effect decisions.

## Examples: The Intended Shape, Not A Schema Proposal

These examples are deliberately incomplete. They show the intended build and
runtime boundaries, and expose the questions an eventual Agentfile grammar and
builder must answer. They do not add an `Ereborfile`, an `apply` command, or a
replacement CLI.

### 1. A derived Agentfile builds a new agent

This is illustrative syntax only:

```dockerfile
FROM codex-base

COPY ./review-profile.toml /erebor/agent/profile.toml
CONFIG profile=review
```

The builder resolves `FROM` by the declared immutable Agent name, inherits its
`codex-v1` adapter, reads the declared profile through the descriptor broker,
and produces a new immutable agent revision. The output is an agent artifact,
not a running Codex process or a session. The builder's integrity identity is
daemon-internal and never becomes a user authoring input.

The inherited adapter prevents this invalid recipe:

```dockerfile
FROM codex-base
ADAPTER claude-code-v1
```

It must fail rather than create an artifact with two incompatible adapter
contracts.

### 2. A root Agentfile declares its adapter

```dockerfile
ADAPTER codex-v1

COPY ./default-config.toml /erebor/agent/config.toml
ENTRYPOINT ["codex"]
```

This demonstrates the first unresolved question: where do the `codex` bytes
come from? A Docker-like Agentfile is only sound if every executable and
support artifact is an admitted, immutable build input. `ENTRYPOINT ["codex"]`
must not mean a later lookup through the caller's `PATH`.

### 3. Compose surface-targeted policy, then associate it in a session

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicyPackage",
  "metadata": { "name": "filesystem-guardrail" },
  "spec": {
    "rules": [
      {
        "id": "deny-governed-marker-write",
        "match": {
          "surface": "filesystem",
          "action": "file_write",
          "target_contains": ".erebor-denied"
        },
        "decision": "deny",
        "reason": "the governed denied marker must never be written"
      },
      {
        "id": "allow-filesystem-write",
        "match": {
          "surface": "filesystem",
          "action": "file_write"
        },
        "decision": "allow"
      }
    ]
  }
}
```

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicySet",
  "metadata": { "name": "filesystem-guardrail-set" },
  "spec": { "packages": ["filesystem-guardrail"] }
}
```

The fields in these example resources have one fixed meaning:

| Resource field | Use and validation |
| --- | --- |
| `Agent.spec.adapter` | The exact compiled Erebor adapter chosen during enrollment. It selects the adapter contract and is verified against the staged executable; it is not a path, plugin, policy, or state configuration. |
| `PolicyPackage.spec.rules` | Ordered canonical rules. Each Rule's `match.surface`, not a duplicate surface field, determines the governed surface; Phase 5.1 defines every matcher field and outcome. |
| `PolicySet.spec.packages` | Immutable, non-empty ordered PolicyPackage membership. This is the one static composition reference: Rules remain exclusively on packages. |
| `PolicySet.spec.packages[]` | One immutable PolicyPackage name. Every package is mandatory for evaluation and must cover each Surface required by the admitted Session. |
| `Surface.spec.type` | Selects the registered Surface implemented by this named, independently configured boundary, initially `browser_cdp`. It is not an agent selector, runner flag, or a way to declare the intrinsic filesystem Surface. |
| `Session.spec.agent` | The only Agent resource reference. Admission resolves the named Agent once and verifies its adapter contract. |
| `Session.spec.surfaces` | Optional names of independently configured Surface records with set semantics: no duplicate name or kind and no ordering meaning. Intrinsic `terminal` and `filesystem` bindings are not listed. |
| `Session.spec.policySet` | The only PolicySet resource reference. Admission verifies it governs every required Surface before any workload starts. |

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Surface",
  "metadata": { "name": "engineering-browser" },
  "spec": {
    "type": "browser_cdp"
  }
}
```

The PolicySet is reusable policy for filesystem events; the filesystem binding
is intrinsic to the admitted Session and has no named Surface document. A
later Session names `review-codex`, `filesystem-guardrail-set`, and only the
independent browser Surface that it needs. The daemon validates the declared
resources and later records the activated binding identities internally.

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Session",
  "metadata": { "name": "review-1" },
  "spec": {
    "agent": "review-codex",
    "policySet": "filesystem-guardrail-set",
    "surfaces": ["engineering-browser"]
  }
}
```

### 4. Current executable enrollment does not change yet

The current CLI remains the path for verifying a local vendor executable:

```text
erebor agent load codex-v1 --from /opt/codex/bin/codex \
  --adapter codex-v1 --name local-codex
  -> name=local-codex
```

The resulting Agent inspection record uses the same versioned envelope:

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Agent",
  "metadata": { "name": "local-codex" },
  "spec": { "adapter": "codex-v1" }
}
```

The unresolved bridge is intentional: the design must specify whether the
Agent named `local-codex` can be promoted to a base agent, whether it contributes a staged
artifact layer, or whether Agentfile builds operate only on separately
imported agent artifacts. None of those choices is a reason to put the raw
`/opt/codex/bin/codex` path into an Agentfile.

### 5. File layout is an authoring choice, not an owner

If Agentfile builds are later approved, a source layout could be:

```text
agents/review-codex/Agentfile
agents/review-codex/review-profile.toml
policies/company-workspace.json
surfaces/engineering-browser.json
```

`Agentfile` is the build recipe for the `review-codex` image. The surrounding
policy and surface documents remain independent. This layout does not decide
what a future import or reconciliation command does to a running surface.

## Challenges The Docker Analogy Must Survive

The analogy is useful, but it cannot be copied mechanically.

1. **Image identity.** Docker images include their executable filesystem. The
   current local-agent path verifies a vendor executable already installed on
   the host. Phase 6 must decide how an Agentfile-produced portable artifact
   materializes the already-fixed `Agent` model alongside that enrolled source,
   with clearly different recovery guarantees where necessary. A mutable local
   executable cannot be a valid `FROM` input merely because it has a declared
   Agent name.
2. **Build execution.** Dockerfile `RUN` has broad authority. Agentfile v1
   should contain only declarative assembly instructions such as exact `FROM`,
   `COPY`, and adapter-validated configuration. If a future `RUN` exists, it
   must execute in a daemon-owned governed builder, have no daemon-control or
   caller-state access, and produce recorded immutable output.
3. **Configuration versus private state.** Agentfile may contain default
   non-secret configuration, but it cannot bake in authentication material or
   a caller's live agent state. State source selection, lower snapshot,
   writable upper, and retention remain surface-owned.
4. **Adapter boundary.** `ADAPTER codex-v1` selects a compiled contract. It
   cannot point at a library, script, hook, or arbitrary plugin supplied by an
   Agentfile.
5. **Base correctness.** `FROM` must resolve one immutable Agent name, not a
   moving tag. The derived agent must retain the complete base/input inventory
   and adapter identity in daemon-owned provenance so a later inspection can
   reconstruct what was built without exposing raw content hashes.
6. **Runtime lifecycle.** Building a new agent never mutates an existing agent
   image or session. Starting a Session remains a daemon-owned admission
   operation that binds the resolved Agent revision to the required intrinsic
   runtimes and any explicitly named Surface records.

## Ownership Rules

| Concern | Owner |
| --- | --- |
| Agent-specific protocol and configuration | Agent, through its built-in adapter |
| Reusable governing rules | PolicyPackage |
| Ordered policy composition with derived surface coverage | PolicySet |
| Independently configured execution boundary | Named Surface |
| Intrinsic/Named Surface realization and session binding | Daemon-owned SurfaceRuntime |
| Agent/PolicySet/named-Surface association and concrete admitted work | Session |
| Process, endpoint, evidence, recovery, and retention lifecycle | Daemon-owned runtime/session owners |

These rules deliberately preserve the parent plan's non-negotiable boundary:
the daemon, not a document, client, or agent, owns lifecycle and enforcement.

## Agentfile Is A Future Build Input; Other Files Remain Optional

`Agentfile` is the candidate future source format for building an agent. It is
not an `Ereborfile`, a session manifest, or a surface lifecycle owner.

Policy-package and surface documents may later use versioned resource
documents. They remain independent of Agentfile. An optional bundle format is
not needed to design, build, or run an agent.

Before any `apply` or reconciliation command is designed, it must answer all
of the following:

- the exact Agentfile instruction grammar, build context, and canonical
  output;
- how `FROM` and root `ADAPTER` produce a complete immutable agent identity;
- how the current verified-local-agent inventory relates to a build input;
- whether any governed build execution beyond declarative assembly is needed;
- how a surface specification creates, replaces, stops, or removes a named
  surface; and
- how local policy-package sources are read through the descriptor broker
  without treating arbitrary host paths as trusted runtime inputs.

Until those answers are approved, the Docker-inspired typed CLI remains the
only lifecycle surface.

## Phase 5 Deliverable Subphases

Phase 5 first removes raw integrity identifiers from the user-facing model,
then fixes reusable and execution resources, and finally makes those resources
real on the daemon-owned Linux path. It ends only with a real governed Codex
TUI session.

0. **[5.0 Named Resource Interface And Hidden Integrity](phase-5-0-named-resource-interface-and-hidden-integrity.md) — Done.**
   Make declared `metadata.name` the only user-facing reference for Agent,
   PolicyPackage, PolicySet, and Surface. Remove raw content hashes from CLI
   inputs/outputs, schemas, examples, normal receipts, and tests; keep daemon
   integrity identity internal.
1. **[5.1 Agent And Policy Resource Model](phase-5-1-agent-and-policy-resource-model.md).**
   Define the immutable, reusable `Agent`, `PolicyPackage`, and `PolicySet`
   resources. Require a declared Agent name on the existing verified-local
   `erebor agent load` flow with explicit `--adapter` and `--name`, and make
   package ordering and `PolicySet` resolution evidence-bearing.
2. **[5.2 Surface Model — Intrinsic And Named Surfaces](phase-5-2-surface-and-session-admission-model.md).**
   Fix the static v1 model: registered Surfaces, intrinsic versus named Surface
   records, typed mediation targets, and a Session that names an Agent,
   PolicySet, and a unique set of named Surfaces when it needs them. This phase
   starts no runtime, endpoint, filesystem view, or mediation.
3. **[5.3 Intrinsic Terminal And Filesystem Surfaces](phase-5-3-intrinsic-terminal-and-filesystem-surfaces.md).**
   Realize the intrinsic terminal Surface through its already shared
   interception runtime, and the intrinsic filesystem Surface through
   `LinuxOstreeOverlayFilesystemRuntime`. Each Session receives one OSTree
   repository and filesystem view; runners consume those bindings.
4. **[5.4 Named Browser CDP Surface And Directed Mediation](phase-5-4-daemon-owned-browser-cdp-lifecycle-and-directed-mediation.md).**
   Make Browser CDP the first listener-bearing named Surface, then implement
   terminal-to-Browser-CDP mediation through the explicit policy target and
   admitted Session binding. Remove the foreground `erebor start` path.
5. **[5.5 Real Codex TUI Governed Acceptance](phase-5-5-real-codex-tui-governed-acceptance.md).**
   Run a real explicitly enrolled Codex TUI through the fixed resource model,
   private state projection, daemon-owned surface, and controller PTY, with
   evidence of policy enforcement and physical-effect ownership.

Agentfile and its builder belong exclusively to Phase 6. Phase 6 must preserve
the named-resource boundary from 5.0 and produce the `Agent` resource fixed in
5.1; it must not introduce a second agent/session model or move policy
attachment away from surfaces. `Ereborfile`, declarative resource imports,
`erebor apply`, reconciliation, external distribution, OCI, and Docker runner
parity remain later, separately approved work.

## Acceptance For This Design Master

- Every listed resource has one purpose and one owner.
- Phase 5.1 fixes the v1 `Agent`, `PolicyPackage`, and `PolicySet` identities;
  Phase 5.2 completes the `Surface`/`Session` admission relationship. Later
  producers of agents must use that fixed model.
- A PolicyPackage derives source-surface coverage from its Rules'
  `match.surface` and names a mediation replacement through the Rule's typed
  `replacement_surface`. A PolicySet derives those requirements from every
  referenced package. Only a Session associates a PolicySet with concrete
  Surface bindings.
- An agent has no policy selection capability.
- The existing verified-local enrollment path can supply a named Phase 5 Agent
  revision without leaking a mutable host path or raw integrity identifier into
  the resource model.
- Agentfile is a Phase 6 builder for an immutable agent artifact; its resulting
  agent, not the source file, is the input to session admission.
- A derived Agentfile uses an immutable named `FROM` and cannot replace the
  inherited adapter; a root Agentfile uses one allowed built-in `ADAPTER`.
- The unresolved relationship between a verified local installation and an
  Agentfile-produced image is named explicitly rather than hidden behind an
  undefined field or raw hash reference.
- The current Docker-inspired CLI and the parent Phase 5 lifecycle scope stay
  unchanged unless a later subphase is explicitly approved.
- Phase 5 ends only when a real Codex TUI run has exercised this model through
  daemon-owned governed surfaces.

## Stop Point

Stop after the five Phase 5 deliverables and their real-Codex acceptance. Do
not add an Agentfile builder, configuration files, an `apply` command,
reconciliation, OCI distribution, or Docker runner work merely because the
vocabulary exists; Agentfile is Phase 6.
