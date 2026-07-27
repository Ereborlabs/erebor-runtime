# Phase 5.2: Surface Model — Intrinsic And Named Surfaces

Status: Done (2026-07-27).

Parent plan: [Phase 5: Agent, Policy, And Surface Resource Model](README.md)

## Purpose

Fix the static model for intrinsic Surfaces, named Surfaces, and runtime-created
Sessions. A Session is the only object that associates an Agent, a PolicySet,
and any named Surface records it needs. Surfaces never list Agents or
PolicySets, just as a volume does not list the pods that may mount it.

## Fixed Surface Model (Schema Only In This Phase)

This phase fixes the ownership vocabulary that later phases implement. It does
not start these runtimes.

```text
Surface           = registered governance domain
Intrinsic Surface = daemon-provided Surface with no public configuration record
Named Surface     = independently configured Surface with a public record
SurfaceRuntime    = compiled-in, daemon-owned realization of one Surface
SurfaceBinding    = Session-specific authority/context from that runtime
Runner            = consumes a SurfaceBinding; never owns governance
```

`SurfaceRuntime` and `SurfaceBinding` describe how a Surface is realized and
used; neither is another Surface or a public configuration category. In
particular, terminal and filesystem are the intrinsic Surfaces. Their runtime
implementations arrive in Phase 5.3.

The initial Surfaces are `terminal`, `filesystem`, and `browser_cdp`.
`terminal` and `filesystem` are **intrinsic Surfaces**: the Session will receive
their bindings without naming public Surface documents. `browser_cdp` becomes a
**named Surface** when its endpoint/lifecycle is independently configured. The
one public association is therefore:

```text
Session -> Agent + PolicySet + optional unique set of named Surfaces
```

The PolicySet says which Surfaces govern events through Rule
`match.surface`, and a mediated Rule says its exact replacement through
`mediation.replacement_surface`. It does not name a concrete Browser CDP
Surface. The Session names that concrete Surface when one is required.

## Scope

- This is a static schema/admission phase: it changes no physical runtime
  owner, storage layout, broker, filesystem store, browser owner, runner, or
  listener. Later phases apply the reuse-first rule to the owners they touch.
- Define the v1 compiled Surface registry: `terminal`, `filesystem`, and
  `browser_cdp`. Every policy `match.surface` and mediation
  `replacement_surface` must resolve to one registered Surface. Phase 5.2 fixes
  the registry and schema validation only; later phases provide the runtime
  implementations. No document, Agent, policy package, or user can add a
  Surface or load a runtime plugin.
- Make a named `Surface` an owner-isolated immutable specification only for a
  Surface with independent configuration/lifecycle. It has required
  `apiVersion`, `kind: Surface`, `metadata.name`, kind-specific configuration,
  evidence/audit roots, resource limits, listener policy, and daemon-loss
  contract. A Surface contains no agent, session, policy-package, or PolicySet
  reference. Phase 5 filesystem is intrinsic and therefore has no named
  Surface record. `terminal` and `filesystem` are intrinsic Surfaces, not
  incomplete named Surface records.
- Make `Session` a daemon-created runtime record, never standing
  configuration. Its persisted inspection record has the same required
  `apiVersion`, `kind: Session`, and `metadata.name` envelope. Its request is
  the only execution association: one Agent name, one PolicySet name, and an
  optional unique set of named Surface names. `PolicySet.spec.packages` is the
  separate static composition reference defined in Phase 5.1. The stored
  Session retains resolved immutable references after validation.
- Validate only static association before any physical resource exists: caller
  ownership must match; every policy source and mediation target Surface must be
  registered; named Surface records must implement the declared registered
  Surface; and the
  Agent's declared adapter must be known. An Agent and a Surface never select
  one another.
- Implement typed daemon/client `erebor surface create|ls|inspect` operations
  for independent surfaces. Creation persists only surface-owned configuration;
  no client-side policy/agent flags or generated aliases can be smuggled into
  the Surface record.
- Define `session create`/`session run` admission requests that take the
  declared Agent, PolicySet, and optional named Surface names. This subphase
  records a validated static Session association but does not start a listener,
  browser, terminal binding, filesystem overlay, or real Codex process.
- Preserve the typed mediation instruction introduced in Phase 5.1. Its
  `replacement_surface` is a policy requirement, not a runtime lookup. This
  phase validates the target Surface and requires a named Browser CDP Surface
  reference when a Session intends to use `browser_cdp`; Phase 5.4 creates the
  actual endpoint/lease binding.

## Delivered Resource Schemas

Phase 5.2 delivers the generic named Surface and static Session association.
Intrinsic terminal/filesystem bindings arrive in Phase 5.3; Browser CDP
physical status and mediation arrive in Phase 5.4. Filesystem is never a
Surface document. Fields not shown below are rejected in this phase.

### Surface

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Surface",
  "metadata": { "name": "engineering-browser" },
  "spec": { "type": "browser_cdp" }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the v1 Surface schema. Must equal `erebor.dev/v1`. | API contract |
| `kind` | Selects the Surface validator. Must equal `Surface`. | API contract |
| `metadata.name` | Immutable, owner-scoped handle supplied when creating an independently configured boundary. | Surface owner |
| `spec.type` | Selects the registered Surface implemented by this named record, initially `browser_cdp`. It determines the compatibility and lifecycle owner; it cannot select an Agent, PolicySet, runner option, raw host path, or the intrinsic filesystem binding. | Surface owner / SurfaceRuntime registry |

### Session

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Session",
  "metadata": { "name": "engineering-review-1" },
  "spec": {
    "agent": "local-codex",
    "policySet": "company-workspace",
    "surfaces": ["engineering-browser"]
  }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the v1 Session schema. Must equal `erebor.dev/v1`. | API contract |
| `kind` | Selects the Session validator. Must equal `Session`. | API contract |
| `metadata.name` | Daemon-assigned immutable runtime handle. It identifies one concrete run and cannot be supplied as an alias for another Session. | Daemon |
| `spec.agent` | Name of the Agent used for this run. The daemon resolves it once and validates its adapter contract. | Session admission |
| `spec.policySet` | Name of the PolicySet governing this run. The daemon reads its source and mediation target Surfaces and validates that each is registered. | Session admission |
| `spec.surfaces` | Optional JSON array with set semantics: each named, independently configured Surface may appear once and order has no meaning. It is absent when all required Surfaces are intrinsic. | Session admission |
| `spec.surfaces[]` | One named Surface record, such as `engineering-browser`. Static admission resolves its owner and registered Surface identity only. A later physical phase creates its runtime binding. | Session admission |

## Examples

### Independent Browser configuration and intrinsic Session bindings

Browser CDP has independent configuration/lifecycle and is therefore named:

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Surface",
  "metadata": { "name": "engineering-browser" },
  "spec": { "type": "browser_cdp" }
}
```

The reusable PolicySet contains frozen membership of packages whose Rules
govern terminal/filesystem events and direct Browser CDP mediation, but it does
not reference the named browser:

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicySet",
  "metadata": { "name": "codex-browser-mediated" },
  "spec": { "packages": ["codex-baseline", "browser-mediation"] }
}
```

`PolicySet.spec.packages` uses the exact Phase 5.1 membership schema. The
referenced packages own the real Rules, including the Rule with
`replacement_surface: browser_cdp`; Phase 5.2 adds no PolicySet fields.

Only the Session joins them with the Agent. Its terminal and filesystem
bindings are intrinsic registry bindings, so they are not invented as named
Surface resources. The Browser CDP binding is named because its endpoint has
independent configuration/lifecycle:

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Session",
  "metadata": { "name": "engineering-review-1" },
  "spec": {
    "agent": "local-codex",
    "policySet": "codex-browser-mediated",
    "surfaces": ["engineering-browser"]
  }
}
```

### Reverse references are invalid

This Surface schema is rejected before it is persisted:

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Surface",
  "metadata": { "name": "engineering-browser" },
  "spec": {
    "type": "browser_cdp",
    "policySet": "codex-browser-mediated",
    "admittedAgents": ["local-codex"]
  }
}
```

The error is `Surface is independent; select Agent, PolicySet, and named
Surfaces on Session`.

Likewise, this Session fails because `filesystem-only` has no Browser CDP
source Rule or `replacement_surface: browser_cdp` requirement:

```text
erebor session create \
  --agent local-codex \
  --surface engineering-browser \
  --policy filesystem-only
  -> error: Session names `engineering-browser`, but PolicySet has no browser_cdp requirement
```

## Non-Goals

- Do not start Browser CDP, create an ambient listener, remove `erebor start`,
  establish terminal interception bindings, or migrate filesystem operations;
  those are Phases 5.3 and 5.4.
- Do not attach a PolicySet or Agent list to Surface, let an Agent select a
  Surface, allow PolicyPackage to reference a named Surface, or make an
  intrinsic Surface into a fake named resource.
- Do not add Agentfile, declarative resource documents, `Ereborfile`, `apply`,
  reconciliation, OCI, or Docker.

## Checkpoint

Add crate-local and daemon/client tests for:

- immutable independent Surface and Session identities, `metadata.name`
  uniqueness/no-retarget behavior, and two-UID isolation;
- required `apiVersion`/`kind`/`metadata.name` envelopes and unknown-version or
  wrong-kind rejection before resource-specific validation;
- rejection of Surface policy/agent/session fields and PolicyPackage named-
  Surface fields;
- static Session association with a compatible Agent, PolicySet, and required
  named Surface set, retaining policy-package order and resolved internal
  revisions in evidence;
- rejection of wrong owner, unknown source/mediation Surface, duplicate
  named Surface, incompatible named Surface kind, unknown Agent adapter, and
  cross-UID resource name; and
- proof that no listener, endpoint, overlay, or workload exists after a
  successful Phase 5.2 admission record.

## Acceptance

- The Phase 5 static data model is fixed: `PolicySet -> PolicyPackage` for
  ordered composition, and `Session -> Agent + PolicySet + optional named
  Surface set` for one concrete execution.
- `Surface` is independent and has no reverse reference to Agents, Sessions,
  PolicyPackages, or PolicySets.
- A `PolicySet` governs source surfaces through mandatory Rule `match.surface`
  coverage and directs mediation through typed Rule `replacement_surface`,
  never through a named Surface instance.
- Session is one concrete attributable run association; it is the only runtime
  resource allowed to reference the Agent, PolicySet, and named Surface records
  together.
- Later physical phases receive only the validated Session association and
  independent resource records, not raw caller paths or unrecorded settings.
- A mediated Rule has one explicit target Surface. This phase does not
  create or resolve an endpoint for it; Phase 5.4 must use that exact target
  and may not discover or substitute an available Surface.

## Stop Point

Record the Surface registry, independent Surface schema, static Session
association API, validation, evidence fields, tests, and verification results.
Do not implement a listener, runner, terminal binding, filesystem view, or
Browser CDP lease in this phase. Phase 5.3 makes intrinsic terminal/filesystem
bindings physical; Phase 5.4 makes Browser CDP and directed mediation physical.

## Result

State: Done.

Implemented the static Surface and Session admission boundary without creating
a SurfaceRuntime, listener, endpoint, filesystem view, terminal binding,
runner admission, or workload:

- The daemon now has a compiled, daemon-controlled registry for the initial
  `terminal`, `filesystem`, and `browser_cdp` governance Surfaces. Policy
  package admission rejects any Rule `match.surface` or mediation
  `replacement_surface` outside that registry. No policy, Agent, or document
  can extend it.
- `erebor surface create|ls|inspect` now manages immutable, owner-isolated
  named Surface records. The delivered v1 schema accepts only
  `spec.type: browser_cdp`; `terminal` and `filesystem` are explicitly
  rejected as intrinsic Surfaces rather than stored as incomplete documents.
  Surface records reject reverse Agent, PolicySet, Session, and policy fields.
- `erebor session create` and `erebor session run` accept the static
  `--agent`, `--policy`, and repeatable `--surface` association form. The
  daemon assigns the Session name, stores the v1 `Session` envelope, resolves
  and retains the Agent, PolicySet, ordered PolicyPackage revisions, and named
  Surface revisions internally, then returns state `admitted`. In this phase,
  `session run` records that association only; it does not start it.
- Static admission rejects mixed legacy runner/workspace/workload fields,
  cross-owner names, unknown compiled Agent adapters, duplicate Surface names
  or kinds, a named Surface with no `browser_cdp` source/mediation requirement,
  or a PolicySet that requires Browser CDP without exactly one named Browser
  CDP Surface. It also requires every mandatory package to cover every source
  Surface used by that PolicySet. Intrinsic bindings remain absent from
  `Session.spec.surfaces`.
- The existing immutable named-resource store, Agent-installation evidence,
  PolicyPackage evaluator, PolicySet revision/order, and physical session
  manager remain in place. The static record is stored separately from the
  physical session manager, so successful admission creates no session output
  directory, runtime directory, listener, endpoint, overlay, or process.
- Daemon-control protocol negotiation is now version 3. A Phase 5.1 control
  peer fails negotiation rather than decoding the new Session association
  fields with the prior contract.

Verification:

- `cargo test -p erebor-runtime-daemon local_store::tests --lib` (13 passed)
- `cargo test -p erebor-runtime-ipc --test contract` (15 passed)
- `cargo test -p erebor-runtime-cli --lib` (40 passed)
- `cargo check --workspace` (passed)
- `bash .github/scripts/verify-rust-ci.sh` (passed outside the workspace
  sandbox because its local WebSocket/Unix-socket tests require host socket
  binding)

Phase 5.2 stops here. Phase 5.3 remains responsible for realizing the
intrinsic terminal/filesystem bindings, and Phase 5.4 remains responsible for
the named Browser CDP endpoint and directed mediation.

Follow-up correction (2026-07-27): CLI request-shape validation now rejects an
incomplete Session request, a partial static association, or a mixed
legacy/static request before it reaches daemon admission. A static association
also rejects explicit runner, workspace, command, failure, environment, secret,
TTY, or detach inputs instead of silently discarding them. The default legacy
failure contract remains `terminate` with a two-second loss grace only for a
complete legacy generic request.

The daemon now has a typed client/control test that creates, lists, and
inspects the named Browser CDP Surface; creates, lists, and inspects the static
Session; proves `session start` fails with the Phase 5.2 static-admission-only
error; and proves that no physical session state or runtime directory exists.

Follow-up verification:

- `cargo test -p erebor-runtime-cli --lib` (40 passed)
- `cargo test -p erebor-runtime-daemon --lib` (49 passed, 5 ignored)
- focused typed-client daemon-control test (passed outside the workspace
  sandbox because the daemon-owned hook service uses Unix-domain sockets)
- `bash .github/scripts/verify-rust-ci.sh` (passed outside the workspace
  sandbox because its daemon/browser tests require local socket binding)
