# Phase 5.0: Named Resource Interface And Hidden Integrity

Status: Done (2026-07-26).

Parent plan: [Phase 5: Agent, Policy, And Surface Resource Model](README.md)

## Purpose

Remove raw content hashes from the Erebor user model before new Phase 5
resources are added. Users name resources in their schemas and commands; the
daemon alone verifies, stores, and uses the internal integrity identity needed
to detect replacement and recover safely.

## Current Public Model To Replace

The current CLI's `PolicyArgs::Set` command family in
`crates/erebor-runtime-cli/src/cli/policy.rs` exposes a split PolicySet command
name, a special root-policy digest input, digest-addressed inspect/verify
operations, and a mutable alias operation. The current client/IPC/daemon
requests carry those public digest fields, and
`examples/codex-app-server/run-host-lab.sh` parses a PolicySet digest before
creating its `fixture` alias.

This is legacy Phase 4 behavior, not an acceptable Phase 5 interface. Phase
5.0 removes this public shape. A `PolicySet` has no special `root` package and
no mutable alias: it is a named immutable ordered composition of ordinary
PolicyPackages. Daemon-internal integrity evidence remains internal.

## Scope

- Reuse the existing daemon-side verifier, content/version records,
  replacement detection, and recovery evidence wherever they remain compatible
  with the name-based interface. Phase 5.0 changes public reference syntax to
  names and may adapt its boundary, but it must not add a parallel integrity
  store or weaken those checks.
- Define `metadata.name` as the required, owner-scoped, immutable
  user-facing identity for `Agent`, `PolicyPackage`, `PolicySet`, and `Surface`.
  Names are explicit input, never derived from a file path, executable,
  package hash, or generated alias, and never silently retarget.
- Define `apiVersion: erebor.dev/v1` and `kind` as required fields beside
  `metadata.name` on every Phase 5 resource document and persisted inspection
  record, including runtime-created `Session`. Reject an unknown version, kind,
  or incomplete envelope rather than guessing a schema.
- Replace raw-hash CLI arguments and output with resource names. In particular,
  local agent enrollment requires `--name` and explicit `--adapter`; PolicySet
  creation/references use declared package and PolicySet names; and references
  to independently configured Surface records use their declared names.
  Intrinsic Surfaces such as Phase 5 filesystem are registry-selected by
  admission and have no user-created name.
- Replace the legacy split PolicySet command family with `erebor policyset`.
  Its `create`, `ls`, `inspect`, and `verify` operations accept or return
  declared names, never a root package, a digest, or a mutable alias. Do not
  retain the split command or any alias subcommand as compatibility syntax:
  both preserve the retired public model.
- Remove raw content hashes from user-visible resource schemas, command help,
  normal CLI output, examples, regular receipts, and acceptance assertions.
  A user can understand, create, inspect, and run every Phase 5 resource by
  name alone.
- Keep file/version/content verification inside daemon owners. Internal
  integrity records may detect a replaced local executable, package, snapshot,
  or artifact, but they are not reference syntax, an authoring concern, or
  normal user output.
- Migrate existing daemon aliases deliberately: an existing record becomes a
  named resource only when its owner confirms a unique `metadata.name`. Never
  infer a new name from a mutable path or reuse an alias that conflicts with an
  existing name.
- Change fixtures and e2e requests to assert names, admission decisions, and
  physical effects. Low-level verifier tests may exercise internal replacement
  detection without making raw hashes part of the public contract.

## Delivered Resource Envelope Schema

Phase 5.0 delivers the common envelope only. Resource-specific `spec` fields
are deliberately not accepted until the owning subphase defines them.

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Agent | PolicyPackage | PolicySet | Surface | Session",
  "metadata": { "name": "immutable-resource-name" },
  "spec": {}
}
```

| Field | Use and validation | Owner |
| --- | --- | --- |
| `apiVersion` | Selects the schema. This phase accepts only `erebor.dev/v1`; an unknown version fails before any resource action. | API contract |
| `kind` | Selects the resource validator/store. It must be one Phase 5 resource kind and is never inferred from a command, path, package, or executable. | API contract |
| `metadata` | Container for resource identity. Phase 5.0 defines no optional labels, alias, or tag fields. | Resource owner |
| `metadata.name` | Stable owner-scoped name. A creator supplies it for Agent, PolicyPackage, PolicySet, and Surface; the daemon assigns it for Session. It is the only public reference and never retargets. | Resource owner / daemon for Session |
| `spec` | Reserved container for behavior that a later Phase 5 subphase defines. It cannot hold integrity strings, aliases, generic paths, or undeclared fields. | Owning subphase |

## Examples

### User-facing references are names

```text
erebor agent load codex-v1 --from /opt/codex/bin/codex \
  --adapter codex-v1 --name local-codex
erebor policyset create --name company-workspace \
  --package company-baseline --package workspace-write
erebor surface create engineering-browser --type browser_cdp
erebor session run \
  --agent local-codex \
  --surface engineering-browser \
  --policy company-workspace
```

The user receives names and lifecycle status, not verifier implementation
details:

```text
agent=local-codex
policySet=company-workspace
surface=engineering-browser
```

The corresponding inspection record always begins with the versioned envelope:

```json
{
  "apiVersion": "erebor.dev/v1",
  "kind": "Agent",
  "metadata": { "name": "local-codex" },
  "spec": { "adapter": "codex-v1" }
}
```

### A name is not a moving tag

This is rejected because the existing Agent name already identifies a different
immutable Agent revision:

```text
erebor agent load codex-v1 --from /opt/codex-next/bin/codex \
  --adapter codex-v1 --name local-codex
  -> error: Agent name already exists; choose a new name
```

The daemon may retain internal evidence explaining why the two executables
differ, but the user fixes the conflict by choosing a new Agent name, not by
copying an integrity string into a command.

## Non-Goals

- Do not remove daemon-side verification, replacement detection, or recovery
  evidence. This phase hides those mechanisms from the public model; it does
  not weaken them.
- Do not create Agentfile, an `Ereborfile`, a manifest import path, `apply`,
  OCI/Docker behavior, or a new runner.
- Do not implement Agent/PolicySet/Surface/Session semantics beyond the naming
  boundary. Phases 5.1 and 5.2 own those resource models.

## Checkpoint

Add crate-local and daemon/client coverage for:

- name validation, owner isolation, uniqueness, no-retarget behavior, and
  deliberate migration of existing aliases;
- required `apiVersion`/`kind`/`metadata.name` validation and rejection of an
  unknown API version or resource kind;
- rejection of raw content-hash command arguments and schema fields;
- absence of raw content hashes from normal CLI/help/receipt output and Phase 5
  e2e fixtures; and
- daemon-only replacement detection for a verified executable or policy source
  after user-facing commands have resolved names.

## Acceptance

- The versioned `apiVersion`/`kind`/`metadata.name` envelope is required for
  every Phase 5 resource, and names are the only user-facing identifiers.
- No Phase 5 user workflow, schema, example, normal receipt, or acceptance test
  requires understanding or copying a raw content hash.
- A mutable source cannot replace a named resource silently; the daemon fails
  closed using its internal integrity record.
- Later phases must preserve this boundary: Agentfile may name a base Agent,
  but it does not expose or require a raw integrity identifier.

## Stop Point

Record the public naming contract, CLI/protocol migration, compatibility result,
tests, and verification evidence. Stop before implementing the Agent and policy
resource bodies in Phase 5.1.

## Result

State: Done.

Implemented the Phase 5.0 public naming boundary without replacing the
existing daemon verifier, content store, replacement checks, session leases,
or policy evaluator:

- `erebor agent load` now accepts a root-curated package name plus mandatory
  `--adapter` and `--name`, returns `agent=<name>`, and persists an immutable
  owner-scoped `Agent` envelope. Its private integrity record remains bound to
  the verified installation; a second revision cannot retarget the same name.
- `erebor policyset create|ls|inspect|verify` replaces the retired
  `erebor policy set` family. It accepts a declared PolicySet name and ordered
  PolicyPackage names, returns names only, and resolves the existing internal
  root-curated package boundary from package provenance rather than exposing a
  special root digest. The alias command and direct-digest reference path are
  removed.
- The daemon client, IPC messages, control service, and Codex run request now
  carry Agent, PolicySet, and package names only. `erebor run` selects a named
  Agent; `--app-server` selects its certified app-server entrypoint rather than
  treating an entrypoint alias as an Agent identity.
- The existing immutable package, installation, PolicySet revision, and
  re-verification owners remain the source of integrity evidence. The new
  private named-resource records require `apiVersion: erebor.dev/v1`, `kind`,
  `metadata.name`, and an empty reserved `spec` (or the explicit Agent adapter
  field). Unknown versions/kinds and unsafe names fail closed.
- The deterministic Codex fixture, host lab, and active user-facing Codex
  guides now use names only. Existing aliases are deliberately not migrated:
  their owner must enroll a new named Agent or create a named PolicySet.

Verification:

- `cargo test -p erebor-runtime-ipc public_named_resource_requests_round_trip_without_integrity_reference_fields -- --nocapture`
- `cargo test -p erebor-runtime-daemon local_store::tests -- --nocapture`
- `cargo test -p erebor-runtime-cli -p erebor-runtime-daemon -p erebor-runtime-client -p erebor-runtime-ipc -- --nocapture`
- `bash .github/scripts/verify-rust-ci.sh` (passed after rerunning outside the
  sandbox so its local websocket/Unix-socket end-to-end tests could bind).

Phase 5.0 stops here. It does not add Agentfile, Ereborfile, resource import,
Surface configuration, or the Phase 5.1 Agent/PolicyPackage/PolicySet bodies.
