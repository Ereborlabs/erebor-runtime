# Phase 5.4: Named Browser CDP Surface And Directed Mediation

Status: Not started.

Parent plan: [Phase 5: Agent, Policy, And Surface Resource Model](README.md)

## Purpose

Make the daemon the sole lifecycle owner of persisted named Surfaces and prove
that model with the named `browser_cdp` Surface, the first listener-bearing
Surface. Then connect a typed terminal mediation Rule to the exact Browser CDP
binding named by the Session. This removes the legacy foreground ownership path
rather than translating it into a hidden compatibility layer.

## Directed Mediation Contract

The policy names the target Surface; the Session names the concrete Surface
record. Neither side may guess the other.

```json
{
  "id": "mediate-managed-browser-launch",
  "match": {
    "surface": "terminal",
    "action": "process_exec",
    "command_contains": "--remote-debugging-port"
  },
  "decision": "mediate",
  "mediation": {
    "kind": "managed_browser_cdp",
    "replacement_surface": "browser_cdp",
    "return_endpoint": "requested_port"
  }
}
```

| Field | Fixed meaning |
| --- | --- |
| `match.surface: terminal` | The original physical effect is a terminal process-exec event. |
| `decision: mediate` | Terminal interception must suppress that raw process; it is not an allow. |
| `mediation.kind` | Selects the compiled `managed_browser_cdp` handler; it cannot select a user plugin. |
| `mediation.replacement_surface: browser_cdp` | The only allowed replacement governance domain. It does not name a browser or authorize a substitute. |
| `mediation.return_endpoint` | Requests the intercepted caller's response format; it does not choose a port or listener. |

There is no `PolicySet.mediatedSurfaces` field. The immutable PolicySet carries
this instruction through the PolicyPackage Rule; a second target list would be
a duplicate source of truth.

The Session separately supplies the independently configured browser:

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

At Session start, this phase activates only that named `browser_cdp` Surface
for the Session. The shared terminal runtime then uses only that resulting
binding:

```text
terminal RuntimeEvent
  -> matching PolicyPackage Rule requires browser_cdp
  -> raw browser process is suppressed
  -> Session's engineering-browser binding supplies its authorized lease
  -> endpoint/lease is returned with evidence

missing, unhealthy, or unauthorized engineering-browser binding
  -> fail closed; do not discover another browser
```

## Scope

- Reuse the `erebor-runtime-cdp` browser/process/endpoint owners and their
  endpoint authorization, observed process identity, and evidence behavior as
  far as they meet daemon ownership. Replace the foreground lifecycle wrappers
  only where they cannot survive client exit; do not create a second CDP
  transport, browser launcher, or endpoint security model.
- Implement typed daemon-owned `erebor surface start|logs|events|stop|rm`
  operations against the immutable records from Phase 5.2. A start/stop/remove
  request acts on the persisted revision; it must not recreate a surface from
  client input.
- Replace the foreground `SessionSurfaceLauncher`, `SessionSurfaceSupervisor`,
  and `SurfaceServiceRunner` stack with a daemon-owned ambient-surface
  supervisor. It owns process handles, health, restart classification, logs,
  evidence, stop, shutdown, and recovery after client exit.
- Materialize Browser CDP with the existing `erebor-runtime-cdp` owners. Bind
  each endpoint to one observed browser process identity, one Surface revision,
  and one owner UID. A Session that uses the browser carries its Agent,
  PolicySet, and named Browser CDP Surface binding; the independent endpoint
  never selects a policy or lists Agents. Browser admission must be resolved
  before any browser-facing runtime handle is issued.
- Use owner-mode Unix sockets by default. Enforce root policy and
  per-connection authentication for any loopback TCP/WebSocket listener, and
  keep daemon-control and runtime-guard endpoints out of agent namespaces.
- Remove the top-level `erebor start --config … --listen …` parser, help,
  protocol, examples, and foreground path. It cannot remain as a client-side
  daemon launcher or a translation to implicit surface creation.
- Complete the directed `managed_browser_cdp` path. Its PolicyPackage Rule
  explicitly requires `replacement_surface: browser_cdp`; the static Session
  association already names its Browser CDP Surface. At Session start, this
  phase creates the binding between that exact named Surface and the Session.
  The shared terminal runtime from Phase 5.3 must return only that binding's
  endpoint/lease, record both the suppressed terminal action and replacement,
  and fail closed when the approved binding is unavailable. It must never
  discover a random browser, start an unnamed replacement Surface, or
  substitute another endpoint.

## Delivered Resource Schema

Phase 5.4 adds observed lifecycle status to the independent Browser CDP
Surface. It does not add Agent, PolicySet, or Session references to Surface.

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Surface",
  "metadata": { "name": "engineering-browser" },
  "spec": { "type": "browser_cdp" },
  "status": {
    "lifecycle": "healthy",
    "endpoint": {
      "transport": "unix",
      "address": "/run/erebor/surfaces/1000/browser.sock"
    }
  }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the v1 Surface inspection schema. Must equal `erebor.dev/v1`. | API contract |
| `kind` | Selects the Surface validator. Must equal `Surface`. | API contract |
| `metadata.name` | Immutable owner-scoped handle used by lifecycle commands. It is not an endpoint alias. | Surface owner |
| `spec.type` | Must equal `browser_cdp`; it selects the Browser CDP surface implementation and lifecycle owner. | Surface owner |
| `status` | Daemon-written observation of the persisted Surface. It is absent from create requests and cannot be used to change lifecycle configuration. | Daemon |
| `status.lifecycle` | Current daemon-observed lifecycle state: `created`, `starting`, `healthy`, `stopping`, `stopped`, `failed`, or `removed`. It tells a controller whether a usable endpoint exists. | Daemon supervisor |
| `status.endpoint` | Endpoint information only when the Surface is healthy. It describes the daemon-created CDP capability; it does not select policy or admit an Agent. | Daemon supervisor |
| `status.endpoint.transport` | Transport chosen by the daemon. Phase 5.4's default is `unix`; unsafe public transports are rejected. | Daemon supervisor |
| `status.endpoint.address` | Daemon-allocated endpoint address for the selected transport. It is output, never a caller supplied socket/path, and is usable only through Session admission and endpoint authorization. | Daemon supervisor |

The Session schema remains exactly the Phase 5.2 `agent`, `policySet`, and
optional `surfaces` association. Browser lifecycle does not introduce an
endpoint, policy, or Agent field on either resource.

## Examples

### A durable Browser CDP surface outlives its client

After Phase 5.2 has persisted the surface specification, its lifecycle is
always directed at that stored object:

```text
erebor surface create engineering-browser ...
  -> name=engineering-browser
erebor surface start engineering-browser
  -> status=healthy endpoint=unix:///run/erebor/surfaces/1000/browser.sock
erebor surface logs engineering-browser
erebor surface stop engineering-browser
```

The exact argument spelling is defined by this phase; the important property
is that `start` receives a persisted surface name, resolves its recorded
immutable revision, and never receives browser settings or an agent
configuration. The daemon continues supervising `engineering-browser`
after the creating client exits.

### The foreground shortcut is not translated

```text
erebor start --config browser.toml --listen 127.0.0.1:9222
  -> error: `erebor start` was removed; create and start a daemon-owned surface
```

The daemon must not silently create a surface from `browser.toml`, because that
would make an unrecorded document a lifecycle and policy authority.

### A mediated browser launch uses its admitted binding

The existing policy Rule can return
`mediate(kind=managed_browser_cdp, replacement_surface=browser_cdp)` for a
terminal browser-launch attempt. The terminal runtime must suppress that raw
launch and use only the Browser CDP binding admitted for this Session. The
returned endpoint and lease have evidence of both the attempted terminal action
and the replacement endpoint.

It must not be implemented as either of these shortcuts:

```text
terminal Session -> create unnamed Browser CDP surface
  -> rejected: a mediated action cannot create an unadmitted replacement

PolicyPackage mediation.targetSurface=engineering-browser
  -> rejected: reusable policy cannot select a named execution boundary
```

The policy instead names `replacement_surface=browser_cdp`; the Session names
`engineering-browser` in its `surfaces` list. This preserves reusable policy
while making the concrete endpoint selection explicit and evidence-bearing.

## Non-Goals

- Do not redesign filesystem transactions, retention, state snapshots, or Codex
  configuration projection; Phase 5.3 already owns those intrinsic bindings.
- Do not turn the filesystem surface into a listener or treat a browser session
  as the owner of a persistent endpoint.
- Do not add Agentfile, Docker/OCI execution, remote listeners, session
  adoption, or a compatibility wrapper for `erebor start`.

## Checkpoint

Add daemon/client e2e coverage for:

- create/start/health/logs/events/stop/remove, client exit, and restart/recovery
  for every advertised daemon-loss mode;
- Browser CDP allowed and denied actions with durable policy/evidence records;
- endpoint identity, owner-mode authorization, daemon-socket absence, two-UID
  isolation, unsafe listener rejection, and stale-upstream rejection;
- terminal-to-Browser-CDP mediation where the raw process is not executed, the
  exact policy-required Browser CDP binding supplies the returned lease, and a
  missing/failed binding fails closed without fallback; and
- rejection of every legacy `erebor start` path without creating a listener,
  process, persisted surface, or daemon request.

## Acceptance

- `erebor surface` is the sole public lifecycle for named Surface records, and
  `erebor` is a typed daemon client for it. Intrinsic terminal/filesystem
  runtimes have no fake `surface create` path.
- Browser CDP is a durable surface-owned endpoint, not a foreground client
  runtime or an agent-owned resource.
- Client exit cannot replace or stop the surface; every physical endpoint is
  attributable to its surface, the Sessions that use it, and its owner. Each
  Session retains its own validated PolicySet and explicit binding association.
- `erebor start` is absent from public and hidden runtime paths.

## Stop Point

Record the removed foreground owners, daemon supervisor owner, endpoint and
directed-mediation contracts, lifecycle e2e results, and verification evidence.
Stop before the real Codex TUI acceptance in Phase 5.5.

## Result

State: Not started.
