# How To Manually Accept Phase 10

Status: Proposed runbook; no Phase 10 implementation or test has been run.

Phase: [Provider Connectors And Recovery](../phase-10-provider-connectors-and-recovery.md)  
Setup: [`PROVIDER-SANDBOX`](./environment-setup.md)

## Outcome

Prove each advertised AWS, Google, GitHub, mesh, connector, message, and
artifact source has an authenticated, coverage-aware evidence contract and
that each advertised response is one typed capability with exact
re-resolution, idempotency, authoritative provider readback, and no generic
provider authority.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 10 connector contract, source
coverage/replay, provider graph, typed actuator, outage/recovery, HF provider,
and legitimate provider-control suites against run-scoped sandboxes.
```

## Procedure

1. Complete the provider-sandbox setup with synthetic principals, repositories,
   resources, mesh identities, connectors, queues, and artifacts.
2. For each source, record its real authentication mechanism, schema/version,
   cursor/checkpoint, coverage epoch, source-native IDs, and proof-quality
   limit.
3. Produce one legitimate event, one adversarial fixture event, a duplicate, a
   late event, a cursor gap, an authentication failure, and an outage/recovery.
4. Inspect the graph edge. Shared principals and direct TLS facts must remain
   shared/contextual unless the provider supplies a stronger exact join.
5. Simulate and authorize each advertised typed actuator. Change or revoke its
   provider handle before dispatch in a separate run.
6. Inspect provider-native result and readback. Confirm secrets and payload
   bodies are absent from retained evidence.

## First-Owned Edge Fixture Matrix

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `EDGE-ARTIFACT-CONSUMER-005` | publish immutable synthetic artifact and consume it from two candidate processes | artifact digest/attestation edge is exact; consumer process identity remains separate; allowed consumer succeeds |
| `EDGE-AWS-SHARED-001` | use one sandbox principal/access path from two isolated actors | account/principal fact stays shared unless session/request proof distinguishes it; exact allowed request succeeds |
| `EDGE-CONNECTOR-FORWARD-004` | forward one authenticated event through a connector and replay/alter it | registered delegation edge retains both source and connector identity; replay dedupes and alteration/auth failure is rejected |
| `EDGE-GITHUB-SHARED-003` | use one installation/token authority from two workflows/processes | repository/installation facts do not invent a unique local actor; supported exact provider result remains exact |
| `EDGE-MESSAGE-CONSUMER-006` | deliver one message to competing/retrying consumers | message/delivery/ack IDs preserve alternate branches until authoritative consumption proof; legitimate retry succeeds |

## First-Owned Hugging Face Fixture Matrix

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `HF-GRAN-AWS-DRYRUN-001` | request an AWS dry-run/simulation and then an authorized real action | dry-run causes no effect and is not reported applied; real typed action has provider readback |
| `HF-GRAN-AWS-SPLIT-001` | split issuance/session/use across isolated actors | exact joins use provider-supported IDs; shared identity remains shared; legitimate session continues |
| `HF-GRAN-CONNECTOR-DIRECT-001` | attempt to turn connector evidence into direct process authority | connector edge never becomes process parentage or execution permission; registered legitimate delegation remains usable |
| `HF-GRAN-DEAD-DROP-001` | hand off through an immutable dead-drop artifact/message | artifact/message branch remains explicit; no invented live parent edge; allowed consumer succeeds |
| `HF-GRAN-GITHUB-MINT-001` | mint a run-scoped GitHub credential through supported authority | issuance identity, scope, expiry, and result are exact; secret bytes never enter evidence |
| `HF-GRAN-GITHUB-REARM-001` | reissue/rearm after prior containment or expiry | new authority is a new branch/generation and cannot inherit a stale verified result |
| `HF-GRAN-GITHUB-REVOKE-001` | revoke an exact supported credential/installation grant | provider readback proves the exact handle no longer authorizes; unrelated grant continues |
| `HF-GRAN-GITHUB-TREE-PR-001` | create equivalent tree through PR and non-PR paths | object/tree identity does not invent action semantics; provider-native PR/result facts remain distinct |
| `HF-GRAN-HOST-LOC-001` | use provider evidence that names a host/location but not a task | location remains contextual; no native ancestry or exact local actor is invented |
| `HF-GRAN-MESH-ENUM-001` | enumerate synthetic mesh services through an authorized identity | exact network-device/mesh result is retained; process purpose is not inferred; normal lookup succeeds |
| `HF-GRAN-MESH-ROOT-001` | use a shared/root mesh identity from isolated actors | shared root remains shared and cannot authorize one inferred process; narrower control identity works |
| `HF-GRAN-MESH-SOCKS-001` | traverse a run-scoped SOCKS/mesh intermediary | every supported hop is explicit; direct source-to-destination/process causality is not invented |
| `HF-GRAN-OUTSIDE-001` | continue the scenario through an uninstrumented external actor | graph exposes an outside/open branch and narrows confidence; no false prevention claim |
| `HF-GRAN-TOKEN-FORGE-001` | submit malformed/forged token identity material without a real secret | source authentication rejects it; no edge, authority, or verified response is created |

## Provider Module And Failure Checks

Run the source and actuator contract separately for every advertised module,
including Google even when no exact Appendix C fixture is first-owned here.
Record the provider-supported identifiers and the precise weaker result when
an API cannot distinguish a local actor, semantic verb, or revocation handle.

For every module, repeat cursor loss, duplicate/late delivery, schema mismatch,
rate limit, expired authority, provider timeout, contradictory readback, and
restart from checkpoint. Outage or ambiguity must not widen local authority or
produce `verified`. Direct TLS must not claim clone/push/verb discrimination
unless enforcement occurs at a qualified provider capability.

## Required Artifacts And Pass Rule

Retain source-authentication and coverage records, schema/cursor/dedupe history,
redacted native envelopes, graph revisions, typed requests/authorizations,
simulation, idempotency keys, provider results/readback, outage/recovery
history, legitimate controls, and a sealed case bundle. Every listed fixture
and every advertised module must pass without a generic provider-call surface
or secret material in evidence.

## Troubleshooting

- An HTTP success or audit event is not authoritative readback of revocation.
- A token hash is evidence identity, not necessarily a provider revocation
  handle.
- If the sandbox omits a required source-native ID, qualify the weaker contract
  or mark that capability unsupported; do not fabricate an exact join.

