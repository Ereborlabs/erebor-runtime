# Phase 5.5: Real Codex TUI Governed Acceptance

Status: Not started.

Parent plan: [Phase 5: Agent, Policy, And Surface Resource Model](README.md)

## Purpose

Prove the Phase 5 product outcome: a real local Codex TUI runs through Erebor
as one daemon-created Session of an admitted immutable Agent with the intrinsic
`terminal` and `filesystem` Surface bindings. This is a real-host acceptance
result, not a deterministic fixture or an Agentfile/Docker demonstration.

## Scope

- Reuse the verified local-agent enrollment, intrinsic terminal/filesystem
  bindings, and Phase 4 controller PTY from the preceding phases. This is an
  end-to-end proof of the preserved path under the new Session association, not
  a second Codex launcher, filesystem implementation, or TUI controller.
- Use an explicitly selected local Codex candidate with the existing
  `erebor agent load … --from …` flow. The daemon must follow it through the
  descriptor broker, verify the resolved final regular executable's version,
  stage it, and run the staged installation without later `PATH`, home,
  launcher, or symlink rediscovery.
- Select the exact Phase 5.1 PolicySet with the Agent. Admission must bind the
  daemon implementations of the intrinsic terminal and filesystem Surfaces;
  record the resolved Agent, package order, PolicySet name, terminal/filesystem
  bindings, state snapshot, projection, and Session identities in the result
  chain. A named Surface is supplied only if the selected policy requires a
  Surface with independent configuration, such as Browser CDP.
- Run the actual Codex TUI through the daemon-owned Phase 4 controller PTY.
  Preserve initial geometry, controller-only input/resize, read-only
  observation, and detach/reattach of the same session.
- Prove the Phase 5.3 private-state boundary in the live workload: fixed
  private `CODEX_HOME`, managed hook/configuration works, caller state is not
  mutated, source host paths and daemon-control sockets are absent, and secrets
  are absent from logs, output, receipts, and evidence.
- Prove real filesystem policy enforcement, not just policy admission: the
  `codex-runtime-guardrail` package must deny a Codex-attempted write or
  mutation of `.erebor-denied` before any physical effect, while its explicit
  `file_open`, `file_read`, `file_write`, and `file_mutation` rules cover the
  ordinary governed filesystem operations used by the walkthrough.
- Complete the removal audit for foreground surface lifecycle and direct
  filesystem storage callers while proving the daemon reuses
  `FilesystemSessionStorage` for this Session. If Linux-host prerequisites are
  unavailable, report the exact unavailable capability and command/error; do
  not fall back to an ungoverned local Codex launch.
- Do not treat Browser CDP mediation as browser discovery. Phase 5.4 proves
  that a terminal `mediate` rule may use only its explicit
  `replacement_surface` binding. This walkthrough need not issue a browser
  launch, but any policy that includes one must name a compatible Browser CDP
  Surface in `Session.spec.surfaces` before the TUI starts.

## Accepted Resource Schemas

Phase 5.5 adds no fields. It accepts only the complete resource contract from
Phases 5.1–5.4 below; a real Codex result is invalid if any document contains
an extra field or a substituted reference.

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Agent",
  "metadata": { "name": "local-codex" },
  "spec": { "adapter": "codex-v1" }
}
```

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicyPackage",
  "metadata": { "name": "codex-runtime-guardrail" },
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
            "id": "deny-governed-marker-mutation",
            "match": {
              "surface": "filesystem",
              "action": "file_mutation",
              "target_contains": ".erebor-denied"
            },
            "decision": "deny",
            "reason": "the governed denied marker must never be created, renamed, or removed"
          },
          {
            "id": "allow-filesystem-open",
            "match": {
              "surface": "filesystem",
              "action": "file_open"
            },
            "decision": "allow"
          },
          {
            "id": "allow-filesystem-read",
            "match": {
              "surface": "filesystem",
              "action": "file_read"
            },
            "decision": "allow"
          },
          {
            "id": "allow-filesystem-write",
            "match": {
              "surface": "filesystem",
              "action": "file_write"
            },
            "decision": "allow"
          },
          {
            "id": "allow-filesystem-mutation",
            "match": {
              "surface": "filesystem",
              "action": "file_mutation"
            },
            "decision": "allow"
          },
          {
            "id": "allow-codex-terminal-processes",
            "match": {
              "surface": "terminal",
              "action": "process_exec"
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
  "metadata": { "name": "codex-runtime-guardrail-set" },
  "spec": { "packages": ["codex-runtime-guardrail"] }
}
```

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Session",
  "metadata": { "name": "codex-review-1" },
  "spec": {
    "agent": "local-codex",
    "policySet": "codex-runtime-guardrail-set"
  },
  "status": {
    "stateProjection": {
      "target": "/run/erebor/state/codex",
      "lowerSnapshot": "codex-review-1-state",
      "writableUpper": "upper-codex-review-1",
      "refresh": "explicit",
      "retention": "discard-on-session-removal"
    }
  }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| Every `apiVersion` | Must be `erebor.dev/v1`, selecting the only Phase 5 resource schema. | API contract |
| Every `kind` | Selects the matching resource validator; it must match its document (`Agent`, `PolicyPackage`, `PolicySet`, or `Session`). | API contract |
| Every `metadata.name` | Immutable owner-scoped handle. The user supplies Agent, PolicyPackage, and PolicySet names; the daemon assigns the Session name. | Resource owner / daemon for Session |
| `Agent.spec.adapter` | Explicit compiled integration contract for the staged Codex executable. It is not inferred and cannot contain state, policy, path, or credential configuration. | Agent owner / adapter registry |
| `PolicyPackage.spec.rules` | Ordered canonical Rules. The package governs a surface through each Rule's `match.surface`, not through a duplicate surface field. | PolicyPackage owner |
| `…rules[].id` | Unique evidence identifier for the rule. | PolicyPackage owner |
| `…rules[].match` | Non-empty existing event matcher. Every Phase 5 Rule must include `surface`. | PolicyPackage owner |
| `…rules[].match.surface` | Existing execution-surface value. This package covers both intrinsic `filesystem` and `terminal` events required by the Codex Session. | PolicyPackage owner |
| `…rules[].match.action` | Existing action kind. The example governs actual filesystem operations and terminal process execution. | PolicyPackage owner |
| `…rules[].match.target_contains` | Optional positive target label/URI substring. The example selects the governed denied marker without revealing or mounting a caller path. | PolicyPackage owner |
| `…rules[].match.payload_contains`, `command_contains`, `risk_at_least` | Optional existing positive match criteria for payload, command/argv summary, and risk level. They remain available even though this example does not use them. | PolicyPackage owner |
| `…rules[].decision` | Existing rule outcome: `allow`, `deny`, `require_approval`, or `mediate`. The first rule denies the marker before the general write allow can match. | PolicyPackage owner |
| `…rules[].reason` | Optional human explanation recorded with the decision. | PolicyPackage owner |
| `…rules[].mediation` | Optional structured instruction for `mediate` decisions only; it is interpreted by the owning surface, never executed as arbitrary code. | PolicyPackage owner |
| `PolicySet.spec.packages` | Immutable non-empty ordered PolicyPackage membership. It is the PolicySet's sole static composition edge and keeps Rules defined once, on PolicyPackage. | PolicySet owner |
| `PolicySet.spec.packages[]` | One immutable PolicyPackage name. Every named package is mandatory for evaluation and must cover the intrinsic Surfaces required by this Session. | PolicySet owner |
| `Session.spec.agent` | The Agent reference for this concrete run; it must resolve to `local-codex`. | Session admission |
| `Session.spec.policySet` | The governing PolicySet reference for this concrete run; admission proves it governs terminal and filesystem. | Session admission |
| `Session.spec.surfaces` | Optional named Surface records for independently configured kinds. It is absent from this terminal/filesystem-only Session. | Session admission |
| `Session.status` | Daemon-written observed result, never a Session create input. | Daemon |
| `Session.status.stateProjection` | Daemon-created private view of agent state, proving real Codex did not receive the caller's home. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.target` | Fixed in-workload target required by `codex-v1`, assigned to `CODEX_HOME`; it is not Agent config or caller input. | Adapter contract / Filesystem SurfaceRuntime |
| `Session.status.stateProjection.lowerSnapshot` | Opaque daemon identity for the read-only state snapshot. It ties evidence to the exact source without exposing a source path or contents. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.writableUpper` | Opaque daemon identity for this Session's isolated writable overlay. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.refresh` | `explicit` requires a typed, revalidated refresh; no live state source is followed during the run. | Filesystem SurfaceRuntime |
| `Session.status.stateProjection.retention` | `discard-on-session-removal` cleans this run's mutable state when removed. | Filesystem SurfaceRuntime |

## Examples

### The intended Phase 5 Codex path

The final walkthrough uses the existing enrollment and policy commands, then
the Phase 5 Session lifecycle. Terminal and filesystem bindings come from the
compiled registry; no filesystem Surface command or document participates. The
exact Session argument spelling is fixed by Phase 5.2; no Agentfile
participates.

```text
erebor agent load codex-v1 --from /opt/codex/bin/codex \
  --adapter codex-v1 --name local-codex
  -> name=local-codex

erebor policy package apply "$EREBOR_CODEX_RUNTIME_POLICY" \
  --name codex-runtime-guardrail
  -> name=codex-runtime-guardrail

erebor policyset create --name codex-runtime-guardrail-set \
  --package codex-runtime-guardrail \
  --idempotency-key codex-policy-1
  -> name=codex-runtime-guardrail-set

erebor session run \
  --agent local-codex \
  --policy codex-runtime-guardrail-set
  -> session=session-a31... controller-pty=attached
```

The resulting session inspection must include the complete admitted chain:

```text
agent_name=local-codex
policySet=codex-runtime-guardrail-set
terminal_binding=shared-runtime-interception
filesystem_binding=linux-ostree-overlay
filesystem_repo=session-a31-filesystem-repo
state_lower=session-a31-state
session=session-a31...
```

### What does not qualify as Phase 5 acceptance

```text
codex
  -> rejected as evidence: bypasses daemon admission and private state

erebor start --config codex.toml
  -> rejected: foreground start was removed

Agentfile -> Agent -> Session
  -> not tested here: Agentfile belongs to Phase 6
```

## Non-Goals

- Do not validate Agentfile, `FROM`, `COPY`, `ADAPTER`, `RUN`, `Ereborfile`,
  OCI, Docker, Kubernetes, registry, or distribution behavior. Agentfile is
  exclusively Phase 6.
- Do not accept a fixture TTY, `PATH` launch, caller-home bind, mutable
  launcher, agent-selected policy, or client-owned lifecycle as equivalent to
  the real governed path.

## Checkpoint

Add committed daemon/client and privileged Linux-host coverage for:

- explicitly enrolled real Codex final-file/version verification and staged
  execution;
- exact PolicyPackage order, PolicySet name, Agent admission, terminal and
  filesystem binding identities, and durable evidence/receipts for the real
  Session;
- private `CODEX_HOME`, managed hook behavior, source-path/daemon-socket
  absence, caller-state non-mutation, and secret redaction;
- emitted filesystem events and a real denied `.erebor-denied` write/mutation
  with no workspace or state effect; and
- controller geometry, input, observer, detach, and reattach behavior in the
  real TUI;
- two-UID isolation, policy denials, daemon-loss behavior, and physical-effect
  attribution for the advertised Linux-host mode; and
- the complete Phase 5 lifecycle probe and repository Rust CI procedure.

## Acceptance

- A real Codex TUI can run only as a daemon-owned Session whose Agent and
  PolicySet pass compatibility validation and whose intrinsic `terminal` and
  `filesystem` Surface bindings have been admitted.
- The resource model is visible in the real result:
  `PolicySet -> PolicyPackage` for static ordered composition, and
  `Session -> Agent + PolicySet + Surface bindings` for this concrete execution.
- The daemon remains the lifecycle, enforcement, state, PTY, evidence, and
  physical-effect owner; the client, agent, and source files are not alternate
  authorities.
- Phase 5 is done only when this real-host result is recorded. A missing host
  prerequisite leaves Phase 5 not done, with precise diagnostic evidence.
- A mediated terminal action may use only the typed replacement Surface
  required by its matching Rule and the named Surface activated for that
  Session; it cannot discover or substitute another surface.

## Stop Point

Record the final result in this file and update the Phase 5 master/parent
status. Stop before any Agentfile or runner work; those begin in Phase 6.

## Result

State: Not started.
