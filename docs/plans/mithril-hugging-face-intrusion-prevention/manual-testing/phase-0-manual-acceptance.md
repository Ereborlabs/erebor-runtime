# How To Manually Accept Phase 0

Status: Proposed runbook; no Phase 0 implementation or test has been run.

Phase: [Substrate, License, ABI, And Incident Baseline](../phase-0-substrate-license-abi-and-incident-baseline.md)  
Setup: [`KERNEL-LAB`](./environment-setup.md)

## Outcome

Produce one reviewable feasibility/closure bundle that proves each selected
stock mechanism before its ABI freezes, or marks the surface unsupported.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 0 schema/golden/fixture-registry,
source-regression, hook-feasibility, verifier, capacity, and benchmark suites.
```

The manual run reviews the exact automated artifacts and independently repeats
representative physical probes. It does not replace verifier, concurrency, or
N/N+1 automation.

## Procedure

1. Create one `KERNEL-LAB` manifest per candidate platform.
2. Pin the Meta deck and every adopted source snapshot by digest, commit, file,
   lines, and license.
3. Run every proposed hook/helper/map/task-storage/path prototype before
   accepting generated Rust/C or wire bytes.
4. Repeat one allow, deny, missing-state, saturation, and prior-LSM-denial
   physical probe per effect family.
5. Review Rust/C layouts, deterministic bytes, fixture equality, and rejected
   identifier reports.
6. Compare baseline/protected distributions and exact N/N+1 failure results.

## Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `CFG-ROLLBACK-GOLDEN-002` | inspect valid, rollback, replay, and corrupted profile artifacts | canonical bytes agree; forbidden rollback/replay rejects; prior generation remains readable |
| `CFG-V1-GOLDEN-002` | compile the readable policy golden twice and inspect unknown/duplicate variants | byte-identical output; invalid fields reject; valid minimal policy succeeds |
| `DECISION-SET-GOLDEN-001` | compare generated Rust/C offsets, enum values, keys, and lookup traces | exact byte equality and fail-closed missing-state result; allowed control key agrees |
| `FIXTURE-REGISTRY-COMPLETE-001` | compare architecture markers, registry, executable cases, criteria, and phase allocation | exactly 134 active IDs; no missing, extra, duplicate, or rejected active ID |
| `SOURCE-KA-BOUNDS-004` | run every adopted bounded parser/path case at limit and limit+1 | at-limit result matches; overflow never truncates to allow |
| `SOURCE-KA-CAPACITY-005` | fill each adopted authoritative map to N and attempt N+1 | documented failure/health transition occurs; existing allowed control remains correct |
| `SOURCE-KA-PARTIAL-ATTACH-001` | fail one required attach after earlier attaches succeed | readiness stays false and rollback leaves a complete old set or no advertised set |
| `SOURCE-KA-READER-LOSS-003` | stop/close/saturate the source reader | physical deny remains where attached; coverage interval becomes gapped/degraded |
| `SOURCE-KA-STACK-PER-HOOK-002` | load every qualified hook at worst-case stack/instruction bounds | verifier acceptance and measured bounds are retained per hook; ordinary allow probe succeeds |
| `SOURCE-TG-EXEC-MAP-007` | exhaust/omit exec staging under concurrent exec | missing authoritative state denies or yields qualified fatal/unknown result; normal exec commits once |
| `SOURCE-TG-PATH-RENAME-008` | exercise prior LSM result and rename arguments at all enabled signatures | earlier denial is preserved; source/destination objects are not swapped; allowed rename control works |
| `SOURCE-TG-RUNTIME-JOIN-006` | send authenticated, unauthenticated, incomplete, replayed, and mismatched runtime facts | only documented fields bind; missing purpose stays unknown; valid initial-root fact succeeds |

## Non-Registry Manual Gates

- Inspect the canonical bind-alias walk and confirm it resolves the older
  tracked `/var/run/secrets/service/config.json`, never the later alias.
- Confirm an untrusted mount mutation is denied before testing canonicalization.
- Review task-allocation traces: opaque state exists before first effect; PID
  coordinates are finalized later without granting permission.
- Confirm every copied/derived/reimplemented upstream unit has a local owner,
  semantic-difference note, license decision, and hostile test.
- Confirm ordinary internal helper types and child records covered by a signed
  parent were not given needless standalone digests.

## Required Artifacts And Pass Rule

Retain source/provenance dossier, verifier logs, capability manifests, ABI
goldens, fixture equality report, raw benchmark distributions, capacity
records, protected-workload baseline digest, and the closure ledger. Phase 0
passes only when every allocated surface has a physical prototype and exact
bound or is removed from the supported claim.

## Troubleshooting

- A verifier or hook failure returns the surface to unsupported; do not change
  the ABI to pretend the original mechanism exists.
- A source test that passes only with an upstream daemon does not qualify the
  local owner.
- A faster benchmark with lost evidence is a failed correctness run.
