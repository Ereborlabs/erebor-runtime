# How To Manually Accept Phase 6

Status: Proposed runbook; no Phase 6 implementation or test has been run.

Phase: [Durable Evidence, Coverage, And Recovery](../phase-6-durable-evidence-coverage-and-recovery.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md), with disposable WAL storage

## Outcome

Prove evidence is ordered, durable, replayable, and loss-aware while physical
local decisions remain independent from userspace delivery. Restart must retain
restrictions and refuse reconstructed authority.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 6 observation canonicalization,
WAL integrity/retention/replay, coverage interval, source epoch, saturation,
corruption, owner health, generation/object recovery, and restart suites.
```

## Procedure

1. Begin with healthy local decisions, source epochs, WAL, upload cursor, and
   Control acknowledgement.
2. Run one allowed and one denied local effect and retain their physical
   results before injecting faults.
3. Inject ring, reader, queue, WAL, upload, map/link/pin, daemon, runtime, and
   node failures one at a time and in selected combinations.
4. Restart the node owner and reconcile tasks, generations, exceptions,
   objects, sockets, topology, response floors, and coverage before admission.
5. Replay to Control with duplicates, delay, reorder, corruption, and cursor
   rollback attempts.

## Fixture Matrix

| Fixture | Operator stimulus | Required oracle and control |
| --- | --- | --- |
| `IPC-ENDPOINT-RESTART-006` | restart either/both channel endpoints and reuse names/coordinates | old relationship never attaches to new endpoint generation; newly declared peers reconnect |
| `IPC-RELATIONSHIP-LOSS-002` | drop peer/relationship evidence while communication is attempted | configured unmatched/hard-safe physical result and gapped relationship proof; healthy relationship control works |
| `LSM-DENY-SATURATION-001` rerun | saturate ring/queue/WAL during repeated forbidden effects | every local effect remains denied; loss counters/interval close exactly; allowed control remains correct |
| `SOURCE-KA-READER-LOSS-003` rerun | kill/close/stall sole reader | no healthy negative interval after loss; pinned decisions continue only while their mechanism remains intact |
| `SOURCE-KA-CAPACITY-005` rerun | fill authoritative maps, ring, WAL, and pending state to N/N+1 | exact failure and health transition; no overwrite-to-allow or false clean coverage |
| `SOURCE-KA-PARTIAL-ATTACH-001` rerun | lose/detach/replace one required live link/map | affected capability closes; recovery verifies exact object/digest and opens a new epoch only after probe |

## Additional Fault Matrix

| Fault | Manual verification |
| --- | --- |
| ring reservation failure | fixed decision unchanged; pinned loss count rises; gap begins at exact sequence |
| WAL full/corrupt segment | retention/backpressure/gap follows policy; no guessed repair or duplicate observation |
| mTLS upload outage | local WAL continues within bound; reconnect resumes from acknowledged cursor |
| node process death | no hidden second writer; pinned enforcement truth and later evidence gap remain distinct |
| runtime/kubelet restart | live roots reconcile without stale purpose; missing interval stays open |
| node reboot | old boot subjects close; new epoch and re-admission; old response keys cannot target new tasks |
| generation retirement/restart | every typed holder/receipt is retained or exact cleanup tombstone exists |
| stale pin/path with live object | recoverability is degraded even if live link still enforces |

## Required Artifacts And Pass Rule

Retain raw source sequences, epochs, gap/suppression counters, WAL segments and
digests, ack cursors, corruption/replay results, link/map/pin manifests,
reconciliation reports, pre/post physical effects, and local finding windows.
Pass requires that no gap supports a negative conclusion and no recovery uses
PID/name/cache guesses.

## Troubleshooting

- Do not call enforcement failed merely because upload failed; verify the
  actual program/link/map state and report evidence separately.
- Do not call enforcement healthy when a required link or map cannot be read
  back, even if prior events looked normal.
- A lost restrictive reference leaks restriction until reconciled; it never
  authorizes early cleanup.
