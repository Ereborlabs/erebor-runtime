# How To Manually Accept Phase 4

Status: Proposed runbook; no Phase 4 implementation or test has been run.

Phase: [Signed Local Pre-Effect Enforcement](../phase-4-signed-local-pre-effect-enforcement.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md)

## Outcome

Prove every qualified non-network local deny occurs before the named physical
effect, exceptions cannot exceed their authority, and unchanged legitimate
work continues.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 4 policy activation, exact lookup,
exec/file/mm/mount/IPC/device/privilege/self-protection, exception, admin-exec,
saturation, bypass, and physical-oracle suites.
```

## Procedure

1. Install a signed candidate generation only after complete readback and
   isolated allow/deny probes; record the one active-pointer CAS.
2. Run each fixture first in observe mode, then protect mode without changing
   the protected workload digest.
3. For each deny, inspect syscall errno and the named object/image/mapping/
   topology/kernel postcondition independently from the event stream.
4. Repeat with event saturation, missing dynamic state, earlier LSM denial,
   aliasing, object reuse, and concurrency.
5. Run the legitimate worker, controller, probe, lifecycle, and approved admin
   controls after every policy/fault variant.

## Fixture Matrix

| Fixture | Operator stimulus | Required protect-mode oracle and control |
| --- | --- | --- |
| `ADMIN-EXEC-APPROVAL-001` | approve one exact Kubernetes exec, then race matching/nonmatching/replay attempts | authenticated Control/admission/node chain; one atomic slot winner; exact exec commits; all reuse/expiry/mismatch attempts deny; ordinary approved admin action succeeds once |
| `DEVICE-DERIVED-001` | open/use/pass device and derived authority objects | forbidden device/ioctl/derived use changes no device/kernel state; approved device operation succeeds |
| `FILE-CONTENT-RACE-002` | mutate content/object between classification and use | stale trusted identity never authorizes; immutable approved object succeeds |
| `FILE-FD-PASS-001` | inherit/pass/reuse a protected file fd | current forbidden actor receives denial/no bytes or mutation; approved recipient works |
| `FILE-IDENTITY-001` | use symlink/hardlink/bind/proc-fd/overlay aliases | every forbidden alias returns denial and no fd/effect; declared object path works |
| `FILE-MMAP-001` | map forbidden file for read/write/execute | forbidden mapping absent; allowed mapping exists with exact state |
| `FILE-MMAP-SHARED-011` | share writable mapping across roots | forbidden acquisition/attachment denies or exact supported floor applies; no byte-taint claim |
| `FILE-NAMESPACE-001` | access same spelling/object across mount views | actor-specific exact-object decision; allowed view succeeds and denied view has no effect |
| `FILE-SA-TOKEN-OPEN-001` | worker and controller access rotating token | worker gets `EACCES` and no fd/positive bytes; controller succeeds; rotation cannot create a gap |
| `FILE-VMA-SNAPSHOT-001` | race response/policy decision with VMA changes | incomplete snapshot never relaxes; complete approved snapshot permits its control |
| `HF-LOCAL-001` | run safe in-process protected-file/effect sequence | first distinguishable forbidden effect is prevented; no later prohibited stage; clean conversion succeeds |
| `IPC-ASYNC-UNSUPPORTED-010` | use unqualified async/SQPOLL path | deny or advertised unsupported result; normal qualified synchronous control works |
| `IPC-PEER-RACE-004` | race peer exit/restart/reuse | stale peer never matches allow; exact live approved peer communicates |
| `IPC-PROCESS-CHANNEL-009` | attempt directional process control/channel use | forbidden direction/operation denies physically; explicitly allowed direction works |
| `IPC-RELATIONSHIP-ALLOW-003` | declared independent roots communicate | configured channel operation succeeds without merging identities |
| `IPC-RELATIONSHIP-UNMATCHED-005` | unknown/wildcard/reused peer communicates | configured unmatched deny/restriction occurs; declared peer control still works |
| `LSM-DENY-SATURATION-001` | fill event path during repeated forbidden effect | every syscall remains denied while loss rises; allowed control remains correct |
| `MEM-EXEC-001` | execute memfd/deleted/file/anonymous mapping or mprotect transition | forbidden executable memory/image never begins; approved immutable image/mapping succeeds |
| `MEM-KERNEL-MAP-002` | exhaust/corrupt/race mm/VMA state | missing required state denies; full valid state allows control |
| `MOUNT-ATTR-001` | attempt old/new mount, bind, propagation, idmap, recursive attrs | undeclared mutation absent; approved fixture mutation enters/clears DIRTY exactly |
| `MOUNT-CAS-002` | race concurrent topology transitions | only one consistent generation commits; conflict cannot open file/exec authority |
| `MOUNT-PROPAGATION-003` | propagate mount while protected opens loop | no post-DIRTY strict open until every affected view reconciles |
| `MOUNT-SNAPSHOT-004` | provide complete and incomplete snapshot variants | incomplete stays dirty/denied; complete approved topology resumes |
| `SELF-PROTECT-001` | mutate/detach/replace Mithril links/maps/pins/config/binary | intact floor denies where qualified; successful tamper closes capability/coverage and never claims self-containment |
| `STATE-PERSISTENT-FILE-LIFETIME-007` | reuse persistent volume/file identity after close/restart | old restriction follows exact live object only; new object cannot inherit clean authority by name |

## Mandatory Incident And Exception Checks

- `HF-008`: the hostile HDF5 reference receives no forbidden fd or bytes;
  the normal dataset/runtime/scratch/output object succeeds.
- `HF-002`-`HF-012`: every managed non-network branch uses its first real
  physical effect; pure computation and already-in-memory data are not called
  prevented.
- Bounded exceptions: run every `maximum_uses` value at N and N+1, concurrent
  consumers, unrelated rules/programs, expiry, restart, and consumed-denial
  variants. Only the decisive matching entry may consume.

## Required Artifacts And Pass Rule

Retain signed generation/readback/activation records, syscall results, object
and topology readback, exception receipts, admin approval/admission/slot traces,
loss counters, incident branch results, and legitimate controls. Pass requires
the physical negative oracle for every advertised deny.

## Troubleshooting

- An event saying `deny` without errno and physical absence does not pass.
- A failed physical operation still consumes a bounded exception when safe
  refund cannot be proved.
- `NODE-FLOOR-EXCEPTION-002` belongs to Phase 8, not this runbook.
