# How To Manually Accept Phase 7

Status: Proposed runbook; no Phase 7 implementation or test has been run.

Phase: [Mithril Control And Detection Packages](../phase-7-mithril-control-and-detection-packages.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md), with durable Control storage and
an isolated notification sink

## Outcome

Prove Control authenticates and preserves node evidence, deterministically
builds local graph/finding revisions, distributes policy, delivers notifications,
and records authority without gaining local physical authority.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 7 authenticated intake,
idempotency/coverage, graph/finding determinism, HF package replay,
notification, trust/policy distribution, and authority-record suites.
```

## Procedure

1. Upload one complete Phase 6 local evidence window and record its digest.
2. Replay the same envelopes in every relevant order with duplicates, delays,
   contradictions, gaps, wrong tenant/node, and invalid digests.
3. Inspect `HF-PROC-001`, `HF-DW-001`, and the schema/state/replay contract of
   `HF-XNODE-001`.
4. Deliver finding revisions to the isolated sink under retry/outage/secret
   filtering variants.
5. Rotate/revoke trust and distribute valid/invalid/replayed policy generations.
6. Create provider-neutral approval/request/lease records without credentials
   and prove they cannot mutate node policy/roles/response.

## Fixture And Package Matrix

| Test | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` rerun | replay/expire/retarget/reboot signed proof at Control and node boundaries | invalid proof never creates lease/policy/role/action; fresh exact proof succeeds once |
| `HF-LOCAL-001` rerun | replay complete/gapped local file/exec/device/network event windows | stable local finding and exact prevented/allowed/unknown stage; clean worker remains unflagged |
| `HF-004-RESULT-001` rerun | vary send admission, packet, provider-write, and content-oracle facts | finding uses exact result word and never upgrades opaque TLS to confirmed exfiltration |
| `HF-011-READ-RESULT-001` rerun | vary open/fd/read/mmap/memory/send/provider facts | graph and finding retain every separate stage; no inferred bytes |
| `HF-PROC-001` | replay exact and incomplete task/entry/effect evidence | exact local lineage only with complete identity; otherwise named lineage gap |
| `HF-DW-001` | replay same-task, descendant, socket, shared credential, and provider-result variants | exact edge only with complete proof; shared names/time remain contextual |
| `HF-XNODE-001` contract | replay schema-valid partial cross-node chain without Phase 8 sources | deterministic open branches; never fake remote parent or complete package |
| graph delivery order | permute equal bound inputs and add late stronger evidence | byte-identical terminal revisions; late evidence appends immutable revision |
| contradiction | present two authoritative incompatible facts | parallel contradiction branches; no destructive overwrite |
| notification secret filter | include secret-bearing/oversized/malformed payload and sink retries | sensitive payload rejects/redacts by contract; retry/dedupe never duplicates finding/action |
| notification outage | stop the sink and restore it | enforcement/finding unchanged; route health and retry state are explicit |
| trust/policy rotation | deliver valid, rollback, revoked, replayed, and partial generations | node activates only valid complete generation; Control never writes node maps directly |
| provider-neutral lease | create CLI/path-named and signed target-bound request variants | CLI/path grants nothing; exact record remains non-secret and non-actuating |

## Incident Card Review

Replay `HF-001` through `HF-012`. The operator must verify each branch says one
of prevented, allowed, payload-unobservable, contextual, outside-authority, or
coverage-gap using the precise supporting source. Phase 7 must not report
provider or cross-node completion.

## Required Artifacts And Pass Rule

Retain authenticated intake receipts, source/coverage merge, graph/finding
revisions, package inputs/state/results, replay permutations, notification
deliveries/health, trust/policy inventory, and authority records. Pass requires
byte-identical deterministic replay and zero Control-to-node authority bypass.

## Troubleshooting

- A duplicate envelope is not new evidence; a late stronger envelope is a new
  immutable revision.
- Notification success/failure cannot change the finding or local policy.
- Shared ServiceAccount/principal plus time is not an exact task edge.
