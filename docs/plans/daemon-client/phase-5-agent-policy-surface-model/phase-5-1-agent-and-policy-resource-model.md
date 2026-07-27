# Phase 5.1: Agent And Policy Resource Model

Status: Done (2026-07-27).

Parent plan: [Phase 5: Agent, Policy, And Surface Resource Model](README.md)

## Purpose

Implement the reusable, immutable resources that exist before execution:
`Agent`, `PolicyPackage`, and `PolicySet`. This subphase makes the current
verified-local Codex enrollment usable as an `Agent` revision without adding
Agentfile, a new authoring format, or an alternative policy owner.

## Scope

- Reuse the existing verified-local enrollment/staging flow and policy-package
  lifecycle wherever they satisfy the v1 resource contract. Phase 5.1 adapts
  their admission boundary rather than recreating executable verification, the
  staging store, policy evaluation, or the Rule language.
- Make `Agent` a daemon-owned immutable revision with one
  Erebor-compiled adapter identity, admitted non-secret configuration, and
  inspection/evidence identity. Its required
  `apiVersion`, `kind: Agent`, and `metadata.name` envelope is validated before
  any agent-specific fields; the user-chosen name is bound once to that revision
  and never acts as a retargetable alias.
- Adapt the existing `erebor agent load … --from …` lifecycle so that its
  verified, staged executable supplies the Phase 5 `Agent` revision under an
  explicit `--name` and `--adapter`. The adapter is selected by the user from
  the registered built-in adapter names; the daemon validates that exact choice
  against the admitted package and verified executable. It never infers an
  adapter from a package name, executable name, file path, `PATH`, version, or
  environment. The verified final-file/version provenance remains daemon-owned
  evidence; the runtime resource does not expose a generic host-path,
  installation, or base reference as configuration.
- Keep an adapter a compiled Erebor integration contract. Reject an agent that
  attempts to provide a user-loaded adapter, plugin, script, library, raw
  executable path, policy reference, live credential, private-state source, or
  surface selector.
- Preserve the existing policy-package lifecycle as the producer of immutable,
  daemon-verified `PolicyPackage` revisions. A package is governing rules;
  it is not executable agent content or daemon-loaded extension code. Its
  rule documents use the existing `match.surface` field as their declared
  target, never a named Surface. Every Phase 5 rule must include that field;
  no separate surface-list field is added as a duplicate source of truth. Its
  `apiVersion`,
  `kind: PolicyPackage`, and `metadata.name` are required.
- Make `mediate` a typed, built-in mediation request rather than retained
  arbitrary JSON. A mediated Rule must name its compiled handler kind and the
  required replacement Surface. Phase 5.1 records and validates that
  request; Phase 5.2 records the static Session association and Phase 5.4 wires
  the Browser CDP physical capability. A package never names a particular
  Surface record or discovers a replacement at execution time.
- Make `PolicySet` a reusable immutable record of one ordered list of exact
  PolicyPackage names. Its eligible Surface kinds are derived from the Rules
  in every referenced package, never supplied in a second field. Its
  required `apiVersion`, `kind: PolicySet`, and `metadata.name` replace a
  separate PolicySet alias. This is the one static composition reference in
  the model: `spec.packages` is ordered, non-empty, immutable membership; a
  Package never points back to a PolicySet. Use the typed PolicySet
  create/list/inspect/verify lifecycle rather than adding a manifest import or
  generic `apply` path.
- Replace the legacy host-lab policy flow in
  `examples/codex-app-server/run-host-lab.sh`: it must create one named
  `fixture-baseline` PolicyPackage and one named `fixture` PolicySet through
  `erebor policyset`, without a special root-policy input, digest parsing, or
  an alias. Update the host-lab shell and README to use that named target and
  the explicit `codex-v1` adapter.
- Keep agent and policy stores owner-isolated. Inspection and evidence must be
  able to reconstruct the exact agent revision and ordered policy packages
  without resolving a mutable name/alias or client path at execution time.

## Delivered Resource Schemas

Phase 5.1 delivers these three persisted resources. Every field below is part
of the v1 contract; fields not shown are rejected.

### Agent

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Agent",
  "metadata": { "name": "local-codex" },
  "spec": { "adapter": "codex-v1" }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the v1 Agent schema. Must equal `erebor.dev/v1`. | API contract |
| `kind` | Selects the Agent validator. Must equal `Agent`. | API contract |
| `metadata.name` | Immutable, owner-scoped Agent handle supplied with `erebor agent load --name`. A different revision needs a different name. | Agent owner |
| `spec.adapter` | Exact compiled adapter supplied with `--adapter`. It selects the Codex integration contract and must validate against the staged executable. It is never inferred, and it is not a host path, plugin, policy, mount, or private-state setting. | Agent owner / compiled adapter registry |

There is intentionally no `privateStateTarget`, `requirements`, `policy`,
`baseRef`, `installationRef`, executable path, credential, or host-path field.
The compiled `codex-v1` adapter has a fixed `CODEX_HOME` target; after Session
admission, the daemon-owned runtime realizing the intrinsic filesystem Surface
projects state there.

### PolicyPackage

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicyPackage",
  "metadata": { "name": "fixture-baseline" },
  "spec": {
    "rules": [
      {
        "id": "mediate-managed-browser-launch",
        "match": {
          "surface": "terminal",
          "action": "process_exec",
          "command_contains": "--remote-debugging-port"
        },
        "decision": "mediate",
        "reason": "replace raw browser debug launches with an Erebor-owned endpoint",
        "mediation": {
          "kind": "managed_browser_cdp",
          "replacement_surface": "browser_cdp",
          "return_endpoint": "requested_port"
        }
      },
      {
        "id": "deny-destructive-fixture-command",
        "match": {
          "surface": "terminal",
          "action": "process_exec",
          "command_contains": "rm -rf"
        },
        "decision": "deny",
        "reason": "destructive recursive removal is denied in the fixture session"
      },
      {
        "id": "allow-fixture-processes",
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

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the v1 PolicyPackage schema. Must equal `erebor.dev/v1`. | API contract |
| `kind` | Selects the PolicyPackage validator. Must equal `PolicyPackage`. | API contract |
| `metadata.name` | Immutable, owner-scoped package handle supplied on package creation. | PolicyPackage owner |
| `spec.rules` | Ordered canonical Rule array. A PolicyPackage has no Surface reference: each Rule declares its governed event surface through `match.surface`. | PolicyPackage owner |
| `…rules[].id` | Non-empty, unique rule identifier within the policy document. It appears in decisions and evidence. | PolicyPackage owner |
| `…rules[].match` | Non-empty event matcher. Every Phase 5 rule requires `match.surface`, ensuring packages are governed by surface type rather than an unrelated label. | PolicyPackage owner |
| `…rules[].match.surface` | Existing `ExecutionSurface` value such as `terminal`, `filesystem`, or `browser_cdp`. It declares which physical event surface the rule governs. | PolicyPackage owner |
| `…rules[].match.action` | Optional existing `ActionKind` such as `process_exec`, `file_read`, `file_write`, or `file_mutation`. It narrows a rule to a concrete governed action. | PolicyPackage owner |
| `…rules[].match.target_contains` | Optional positive substring match against an event target label or URI. | PolicyPackage owner |
| `…rules[].match.payload_contains` | Optional positive substring match against the event payload. | PolicyPackage owner |
| `…rules[].match.command_contains` | Optional positive substring match against command or argv-summary payload fields. | PolicyPackage owner |
| `…rules[].match.risk_at_least` | Optional existing risk threshold (`low`, `medium`, or `high`). | PolicyPackage owner |
| `…rules[].decision` | Required outcome: `allow`, `deny`, `require_approval`, or `mediate`. It is evaluated by the existing policy engine; Phase 5 accepts canonical `require_approval`, not the legacy alias. | PolicyPackage owner |
| `…rules[].reason` | Optional human-readable denial/approval/mediation explanation recorded with a non-allow decision. | PolicyPackage owner |
| `…rules[].mediation` | Required typed mediation instruction when `decision` is `mediate`; rejected otherwise. Only a built-in Surface handler may accept its fixed shape. It is never generic executable JSON. | PolicyPackage owner / Surface handler |
| `…rules[].mediation.kind` | Built-in handler kind. `managed_browser_cdp` means a daemon-compiled terminal handler may replace a raw browser-debug launch with a governed Browser CDP capability. It cannot identify a user plugin or a named Surface. | Built-in mediation-handler registry |
| `…rules[].mediation.replacement_surface` | Required registered Surface for the physical replacement. `browser_cdp` requires the Session to name a Browser CDP Surface and later activates only that target; no other available surface may be substituted. | PolicyPackage owner / Surface-runtime registry |
| `…rules[].mediation.return_endpoint` | Example response-format request. `requested_port` tells that handler what the intercepted caller expects back; it does not authorize a port, choose a listener, or bypass Browser CDP endpoint policy. | Built-in mediation handler |

The current package-directory importer may retain its files and provenance as
daemon evidence, but it normalizes them into this ordered `spec.rules` array.
Filenames and source-layout details are not part of the PolicyPackage resource
schema or user reference model.

The `managed_browser_cdp` Rule is intentionally not an authorization to add a
generic mediator in Phase 5.1. It proves that the PolicyPackage can carry an
explicit, validated source-to-target request without becoming the executor.
Phase 5.2 records the required named Surface; Phase 5.4 provides the
daemon-owned Browser CDP capability. No terminal handler may discover an
arbitrary browser or choose a different replacement surface.

### PolicySet

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "PolicySet",
  "metadata": { "name": "fixture" },
  "spec": { "packages": ["fixture-baseline"] }
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the v1 PolicySet schema. Must equal `erebor.dev/v1`. | API contract |
| `kind` | Selects the PolicySet validator. Must equal `PolicySet`. | API contract |
| `metadata.name` | Immutable, owner-scoped PolicySet handle supplied to `erebor policyset create --name`. It replaces the legacy alias. | PolicySet owner |
| `spec.packages` | Non-empty ordered list of immutable PolicyPackage `metadata.name` values. This is the PolicySet's sole static composition edge: it declares package membership and evaluation order, while the referenced packages retain the Rules. | PolicySet owner |
| `spec.packages[]` | One PolicyPackage name. The daemon validates owner scope and existence at creation; a package cannot point back to sets. Order is immutable because package evaluation order affects enforcement. | PolicySet owner |

A Session may use a PolicySet for a Surface type only when every mandatory
package named by `spec.packages` has Rule coverage for that `match.surface`.
This follows the existing `LayeredPolicySet` behavior: a package with no
matching rule is not silently ignored. A `deny` in any package wins; `allow`
does not short-circuit later mandatory packages. Admission/evidence stores the
resolved immutable package revisions internally; users continue to use names.

## Examples

### Current enrollment materializes an Agent revision

The current command remains the user input for a local Codex executable:

```text
erebor agent load codex-v1 --from /opt/codex/bin/codex \
  --adapter codex-v1 --name local-codex
  -> name=local-codex
```

After this phase, `local-codex` resolves to the immutable Agent schema above,
not to `/opt/codex/bin/codex` at session-start time. It deliberately contains
no mutable source path or private-state field.

This must fail: the adapter was provided explicitly, but it is not compatible
with the admitted package/executable.

```text
erebor agent load codex-v1 --from /opt/codex/bin/codex \
  --adapter claude-code-v1 --name wrong-adapter
  -> error: adapter `claude-code-v1` is not admitted for `codex-v1`
```

### A named PolicySet selects a named PolicyPackage

The Phase 5.1 host lab supplies one simple fixture policy package. A user can
inspect each stage by name:

```text
erebor policy package apply "$EREBOR_FIXTURE_POLICY" \
  --name fixture-baseline
  -> name=fixture-baseline

erebor policyset create \
  --name fixture \
  --package fixture-baseline \
  --idempotency-key fixture-policyset-1
  -> name=fixture

erebor policy package inspect fixture-baseline
erebor policyset inspect fixture
```

`fixture` is the named ordered composition used by the current `erebor run`
example. The package is rules only; it is not agent content or executable code.

### PolicyPackages compose a PolicySet, not an Agent

```text
erebor policyset create \
  --name company-workspace \
  --package company-baseline \
  --package workspace-write \
  --idempotency-key policyset-1
  -> name=company-workspace
```

The package order is part of the immutable PolicySet revision. Reversing the
two `--package` inputs creates a different named PolicySet resource.

This later Session request must fail because the example PolicySet has only
terminal rule coverage and therefore cannot govern Browser CDP:

```text
erebor session create --agent local-codex \
  --surface engineering-browser \
  --policy fixture
  -> error: PolicySet `fixture` has no mandatory-package coverage for `browser_cdp`
```

## Non-Goals

- Do not define `Surface` or `Session`; their relationship is Phase 5.2.
- Do not add Agentfile, `FROM`, `ADAPTER`, `COPY`, `RUN`, a builder, OCI,
  Docker, an `Ereborfile`, or an image-distribution path. Those are Phase 6 or
  later.
- Do not attach policy to an agent or let policy-package commands start a
  workload.

## Checkpoint

Add crate-local and daemon/client tests for:

- immutable agent revisions, `metadata.name` uniqueness/no-retarget behavior,
  owner isolation, and retained final-file/version verification evidence from the
  existing enrollment path;
- required `apiVersion`/`kind`/`metadata.name` envelopes for Agent,
  PolicyPackage, and PolicySet plus unknown-version/kind rejection;
- explicit adapter selection, successful validation of `codex-v1`, and rejection
  of an unknown or incompatible adapter without fallback or inference;
- rejection of mutable host paths, user-loaded adapters, policy fields, state
  sources, and secret-bearing agent configuration;
- PolicyPackage verification and an ordered PolicySet whose immutable
  revision changes when package membership or order changes; and
- list, inspect, and verify results that retain exact revision identities across
  a daemon restart.

## Acceptance

- `Agent`, `PolicyPackage`, and `PolicySet` are separate reusable resources
  with one immutable identity and one owner each.
- Every user-facing Agent and PolicySet reference is its declared
  `metadata.name`, not a generated or mutable alias; admission/evidence retain
  the resolved immutable revision internally.
- An `Agent` contains no policy-selection capability; a `PolicySet` contains no
  agent or session configuration.
- The existing verified-local agent path yields an admissible immutable Agent
  revision without making a mutable caller executable a runtime authority. Its
  adapter is explicitly selected and validated, never guessed.
- The only policy composition is an immutable ordered `PolicySet` of named
  PolicyPackages. Its eligibility for a surface is derived from the Rules owned
  by every named package. A later Session, not a Surface, selects it for a
  concrete run.

## Stop Point

Record schemas, daemon store/protocol owners, tests, and verification results.
Stop before creating a surface or session. Phase 5.2 consumes these revisions;
Phase 6 later adds Agentfile as another producer of the same `Agent` model.

The Phase 5.1 result must also update and run the Codex App Server host-lab
example with its named fixture PolicySet and explicit `codex-v1` adapter. Its
successful scripted path is:

```text
erebor policy package apply "$EREBOR_FIXTURE_POLICY" --name fixture-baseline
erebor policyset create --name fixture --package fixture-baseline
erebor agent load codex-v1 --from "$EREBOR_CODEX_FIXTURE" \
  --adapter codex-v1 --name fixture-codex
erebor run --policy fixture --workspace "$PWD" fixture-codex
```

## Result

State: Done.

Implemented the Phase 5.1 resource boundary without adding an authoring
format, a runner, a Surface/Session model, or an alternative policy owner:

- `Agent` records now persist the exact validated compiled adapter in
  `spec.adapter`; the existing verified-local Codex enrollment and immutable
  installation evidence remain the authority for the executable.
- `PolicyPackage` apply now requires an explicit `--name`. The descriptor-held
  package directory must declare the same name in `policy.toml`; the daemon
  records the versioned `PolicyPackage` envelope and a normalized ordered
  `spec.rules` view. Every rule requires `match.surface`, and the only accepted
  Phase 5 mediation shape is terminal `process_exec` to `browser_cdp` through
  `managed_browser_cdp` with `requested_port` return behavior.
- `PolicySetRevision` is now an ordered, non-empty list of ordinary package
  revisions. It has no root package, root digest, local override, or alias.
  The persisted `PolicySet.spec.packages` holds the corresponding ordered
  package names; duplicate membership and name retargeting fail.
- The Codex App Server fixture now supplies a `fixture-baseline` package
  directory. The host-lab script applies it as `fixture-baseline`, then creates
  `fixture` from that name. The shell and README use the explicit `codex-v1`
  adapter and the `fixture-codex` Agent name.
- Repository instructions now explicitly limit implementation to the active
  phase and user request: no unrequested architecture, compatibility behavior,
  protocol/data-model work, or adjacent cleanup.

Verification passed for the final Rust source state:

- `cargo test -p erebor-runtime-daemon local_store --lib` (9 tests)
- `cargo test -p erebor-runtime-daemon path_broker --lib` (4 tests)
- `cargo test -p erebor-runtime-cli cli::tests::policy_package_apply_requires_an_explicit_resource_name`
- `cargo test -p erebor-runtime-ipc --test contract public_named_resource_requests_round_trip_without_integrity_reference_fields`
- `cargo test -p erebor-runtime-e2e --test codex_v1_fixture fixture_builds_a_pinned_package_contract_without_vendor_state -- --nocapture`
- `cargo check --workspace`
- `bash .github/scripts/verify-rust-ci.sh`

The root-owned host-lab acceptance passed in the repository's disposable
privileged Docker environment, using its existing systemd test image. The
checkout was bind-mounted read-only;
the container created its own `erebor-lab` user and ran the documented host-lab
script as root with `SUDO_USER=erebor-lab`. Its interactive command stream
successfully:

```text
erebor agent load "$EREBOR_CODEX_PACKAGE_NAME" --from "$EREBOR_CODEX_FIXTURE" \
  --adapter codex-v1 --name fixture-codex
erebor run --policy fixture --workspace "$PWD" -d fixture-codex
erebor session ps
```

The daemon applied `fixture-baseline`, created `fixture`, enrolled
`fixture-codex`, and reported the resulting Linux-host session as `running`.
The disposable container was removed after the acceptance run.
