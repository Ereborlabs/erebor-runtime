# Phase 10: Provider Connectors And Recovery

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Correlate and recover the post-Kubernetes incident expansion through provider,
mesh, connector, queue/artifact, cloud, and source-control authorities using
their real operation and revocation semantics.

## Depends On

Phase 9 must be `Done`. Each adapter is a separately approved sub-checkpoint.
Approval to read provider audit is not approval to mutate provider state.

## Phase Scope

### Connector Framework

Create provider modules under:

```text
crates/mithril-control/src/connectors/
  mod.rs
  health.rs
  cursor.rs
  aws.rs
  mesh.rs
  internal_connector.rs
  source_control.rs
  artifact.rs
  queue.rs
```

Each adapter defines:

- authenticated tenant/account/authority binding;
- raw source schema, cursor, delay, retry, dedupe, and coverage;
- immutable provider request/event/resource IDs;
- secret/body redaction;
- normalized observation/action/result vocabulary;
- direct and contextual join keys;
- read credential separate from response credential;
- narrow typed response classes;
- approval/blast-radius policy;
- idempotency and expiry;
- physical postconditions; and
- sandbox/live conformance tests.

Connectors run in Mithril Control's operational boundary or consume an existing
audit feed. They are not additional privileged Linux node gatherers.

### Cross-Boundary Edge Types

Add only provider-backed edges:

```text
credential_obtained_by
credential_used_for_request
connector_forwarded_request
remote_command_started_execution
message_published
message_consumed
artifact_produced
artifact_loaded
network_communication
```

Direct edges require exact lease/access-key, source/destination request,
message/offset, immutable artifact, and receiver execution identifiers as
applicable. Principal names, repository names, tags, filenames, IPs, and time
remain contextual.

### AWS

Ingest CloudTrail-compatible:

- account/region/event ID/time;
- access-key ID, principal ARN, role session;
- source address;
- event source/name/resources/result; and
- delivery/cursor coverage.

Implement only approved actions. If the available recovery is
role-session revocation before a cutoff, show every expected impacted principal
and require high-blast-radius approval. Do not call it exact token revocation.
Isolate the workload first so it cannot immediately obtain new credentials.

### Mesh

Retain tailnet/tenant, auth-key identity when available, device ID, node key,
tags, source, and created time.

Separate:

- auth-key deletion, which prevents new enrollment; and
- exact device deletion, which removes an already enrolled device.

Verification must prove both where both are requested.

### Internal Connector

A direct forwarding edge requires authenticated source and destination request
IDs. A shared principal plus timing remains contextual.

If the deployed connector has one broad `system:masters`-like credential, the
only physical action may be disabling/rotating the shared broker. Simulate and
disclose its full blast radius; do not describe it as narrow.

### Queue And Artifact

- Queue joins require a broker message ID or stable partition/offset plus
  authenticated producer and consumer evidence.
- Artifact joins require an immutable digest/revision at production and load.
- Queue name, repository name, package name, mutable tag, or filename is not a
  direct causal identity.
- Remote execution requires receiver-side request/execution evidence in
  addition to network communication.

### GitHub/Source Control

Retain enterprise/org, App ID, installation ID, token fingerprint when safely
available, actor, repository ID, audit event ID, operation, resource, and
result.

Provider audit, not direct TLS, distinguishes clone, push, token mint,
workflow, release, package, or repository mutation.

Implement separate response classes:

- revoke a known installation token through its provider-supported exact
  mechanism when the secret is safely available; and
- suspend/uninstall the wider App installation with explicit approval.

Verification searches for later unauthorized commits, branches, workflows,
releases, packages, and image digests.

## Hugging Face Test Increment

Implement `HF-PROV-001` and map:

- `HF-013` repository dead-drop;
- `HF-014`–`HF-016` mesh and connector discovery/use;
- `HF-017` AWS credential validation/use;
- `HF-018` installation-token mint and source-control/CI attempt;
- `HF-019` request/message/artifact remote-loader propagation; and
- `HF-020`–`HF-021` late provider branches during the response watch.

Use dedicated sandbox tenants/accounts/repositories or schema-valid simulators.
No production provider authority is permitted.

## Code-Backed Tests

For every adapter:

- source authentication, schema, redaction, cursor, gap, replay, dedupe, delay,
  and clock-skew tests;
- tenant/account/resource binding and forged payload rejection;
- direct/contextual/contradicted join tests;
- two concurrent principals/resources with equal display names;
- missing exact key degrades response eligibility;
- read credential cannot invoke response;
- response credential is limited to allowlisted action/resource;
- simulation, approval, idempotency, expiry, provider error, postcondition, and
  rollback where possible;
- flow-only evidence cannot identify provider operation;
- late/contradictory event creates a new graph/finding version;
- connector removal leaves local Mithril guarantees intact; and
- `HF-PROV-001` live/sandbox tests.

Provider-specific tests additionally prove:

- AWS exact identity versus role-wide cutoff;
- mesh auth key versus enrolled device;
- connector end-to-end request IDs versus shared-principal timing;
- queue message and artifact digest joins;
- GitHub known-token revocation versus installation suspension; and
- later source-control effects are enumerated after response.

## Live Probe

Run Probe F separately for every approved adapter, then run the combined
provider branches of Probe E with one delayed and one unavailable provider.

## Checkpoint

For each adapter, run the common repository gates, source/cursor/join/security
suite, provider-specific action/postcondition suite, isolated live Probe F, and
combined delayed/unavailable-provider response. Approve adapters separately;
one passing adapter cannot mask another.

## Acceptance

- every provider fact retains authoritative IDs, raw provenance, and source
  coverage;
- display names/time/flow alone never create direct provider causality;
- direct TLS never supplies operation semantics;
- each connector uses separate read and response authority;
- each response class matches the provider's real granularity;
- shared credentials/connectors disclose broad blast radius;
- provider response results require physical postconditions;
- delayed/unavailable/outside-authority branches force versioning,
  `partial`, or `unknown`;
- the `HF-013`–`HF-019` fixture branches correlate and recover at their
  declared strength; and
- removing a provider adapter does not weaken local node prevention.

## Explicit Stop Point

Stop after each individually approved provider adapter passes. Phase 11 is the
only phase allowed to make the complete production conformance claim.

## Phase Result

State: Not started.

Record each adapter's source/action credentials, schemas, provider semantics,
test tenants, join/postcondition results, unavailable branches, performance,
and final state.
