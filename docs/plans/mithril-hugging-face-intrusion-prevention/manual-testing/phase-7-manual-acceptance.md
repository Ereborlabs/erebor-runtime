# How To Manually Accept Phase 7

Use this runbook during Phase 7.10 after required subphases 7.1–7.8 pass their
automated gates. Include 7.9 when remote placement is advertised.

Phase: [Mithril Control And Detection Packages](../phase-7-mithril-control-and-detection-packages/README.md)

Setup: [`SINGLE-NODE`](./environment-setup.md), with durable Control storage and
an isolated notification sink

## Outcome

Prove Control consumes immutable Phase 6.2 evidence, deterministically builds
local graph/finding revisions, preserves policy provenance, delivers
notifications, records authority, and derives discovery context and checked
assessments. Keep analysis separate from approved publication and local
physical authority.

## Automated Companion

After the planned case entry points exist, run:

```sh
cargo run -p mithril-e2e --bin mithril_discovery_test -- --case all --output-directory /tmp/araphor-acceptance
```

Use the frozen capability manifest. A missing required case fails the result.
Manual checks do not replace these owner-API cases.

## Procedure

1. Select one complete Phase 6 evidence window that Phase 6.2 durably accepted.
   Record its intake cursor, digest, coverage intervals, source policy revision,
   signed candidate, target snapshot, and node activation acknowledgement.
2. Restore a validated data backup and replay the same accepted records in every
   relevant order with duplicates, delays, contradictions, and gaps. Attempt
   references to wrong-tenant and unaccepted records.
3. Inspect `HF-PROC-001`, `HF-DW-001`, and the schema/state/replay contract of
   `HF-XNODE-001`.
4. Deliver finding revisions to the isolated sink under retry/outage/secret
   filtering variants.
5. Replay evidence from complete, partial, stale, and mixed policy rollouts.
   Verify each finding states only the policy provenance that the records prove.
6. Restart and compact the graph store within the declared retention rules.
   Verify replay produces the same retained graph and finding revisions.
7. Create provider-neutral approval/request/lease records without credentials
   and prove they cannot mutate node policy/roles/response.
8. Disable discovery analysis. Verify trace admission, upload, restart and
   query through shared data facilities. Stop the isolated query worker;
   durable upload must continue. Separately make the test data store
   unavailable: require no ACK, bounded Node spool and local trace expiry.
   Do not delete the authoritative database or its native WAL.
9. Stall required graph processing and optional discovery separately. Optional
   progress must not block expiry or intake. Resume after expiry with a recorded
   gap. Required graph input and exact review witnesses prevent reclamation.
   Raise health immediately; pause affected intake only at the protected age/byte
   or physical capacity bound. Resume required processing and expire eligible
   references. Check actual disk reuse after checkpoint, not only SQL deletion.
10. Run Phase 7.3 query and Phase 7.6 recipe, suggestion, and preview cases through owner APIs.
    Run Phase 7.7 assessment/disclosure cases with recorded inputs. No model or
    public client is required for these owner checks. A benign model label cannot
    silence escalation.
11. Run the Phase 7.10 recorded external-client and console case through production APIs.
    Compare subject, assessment, approval, and activation references. Verify
    independent approval, stale-source rejection, and uncertain-write recovery.
    Preserve legitimate workload behavior and check forbidden physical effects.
12. Run model refusal, disclosure revocation, source-gap, and client-restart
    cases. The second client must recover the same committed investigation.
    Backend-only proof is insufficient. Recorded-client tests can complete the
    core contract, but cannot prove model quality or local inference. Run actual
    external-agent measurements only for separately advertised compatibility.

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
| graph delivery order | permute equal accepted inputs and add late stronger evidence | byte-identical terminal revisions; late evidence appends immutable revision |
| contradiction | present two authoritative incompatible facts | parallel contradiction branches; no destructive overwrite |
| policy provenance | replay complete, partial, stale, and mixed rollout records | finding names only proved source/candidate/target/active generation; missing state limits the claim |
| unaccepted evidence | point a package at an absent, rejected, or wrong-tenant intake record | no graph input; explicit source or tenancy error |
| graph restart and retention | restart, restore a backup, and expire one eligible range | retained graph/finding bytes stay identical; referenced evidence is not removed |
| notification secret filter | include secret-bearing/oversized/malformed payload and sink retries | sensitive payload rejects/redacts by contract; retry/dedupe never duplicates finding/action |
| notification outage | stop the sink and restore it | enforcement/finding unchanged; route health and retry state are explicit |
| provider-neutral lease | create CLI/path-named and signed target-bound request variants | CLI/path grants nothing; exact record remains non-secret and non-actuating |

## Incident Card Review

Replay `HF-001` through `HF-012`. The operator must verify each branch says one
of prevented, allowed, payload-unobservable, contextual, outside-authority, or
coverage-gap using the precise supporting source. Phase 7 must not report
provider or cross-node completion.

## Required Artifacts And Pass Rule

Retain authenticated intake receipts, source/coverage merge, graph/finding
revisions, package inputs/state/results, replay permutations, notification
deliveries/health, policy provenance, graph lifecycle records, and authority
records. Pass requires byte-identical deterministic replay, exact tenant
isolation, independent diagnostic recovery, safe consumer retention, and zero
graph-to-policy or Control-to-node authority bypass. Retain query receipts,
assessment validation, and exact proposal/preview digests with the same proof.

## Troubleshooting

- A duplicate envelope is not new evidence; a late stronger envelope is a new
  immutable revision.
- Notification success/failure cannot change the finding or local policy.
- Shared ServiceAccount/principal plus time is not an exact task edge.
- A CRD status or rollout summary is not evidence that a node activated a
  generation. Use the exact Phase 6.2 acknowledgement and node readback.
