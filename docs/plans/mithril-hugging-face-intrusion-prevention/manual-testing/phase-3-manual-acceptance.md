# How To Manually Accept Phase 3

Status: Proposed runbook; no Phase 3 implementation or test has been run.

Phase: [Effect Observation And Profile Simulation](../phase-3-effect-observation-and-profile-simulation.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md)

## Outcome

Prove the compiler and shared Interceptor can attribute and simulate every
future Phase 4/5 decision with exact actor, object, operation, stage, and
physical completion result while policy denial remains disabled.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 3 parser/compiler/signature,
inactive-generation, Rust/BPF lookup, canonical-path, observe-effect, hostile
alias, bound, and upstream-regression suites.
```

## Procedure

1. Install one inactive candidate profile and inspect its canonical bytes,
   signature, generation identity, bounds, defaults, and complete map readback.
2. Run the unchanged worker and every legitimate control in observe mode.
3. Initiate every fixture below and inspect the actual syscall/object/packet
   result independently from `WOULD_DENY`/`WOULD_REJECT` telemetry.
4. Exercise the Meta canonical mount walk, wildcard graph, hard-link aliases,
   rename/link/mount DIRTY windows, and every declared bound.
5. Corrupt or remove identity, generation, topology, dynamic floor, and prior
   LSM state. Confirm observe mode retains the hard safety result.
6. Prove no active policy pointer or product prevention claim changed.

## Compiler And Path Cases

| Test | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `CFG-V1-GOLDEN-002` | compile valid policy twice and invalid unknown/duplicate/conflict variants | deterministic valid bytes; invalid variants reject; no active pointer changes |
| `CFG-ROLLBACK-GOLDEN-002` | present old, replayed, mismatched, and corrupted generations | candidate rejects and installed generation remains unchanged |
| `DECISION-SET-GOLDEN-001` | compare simulation and BPF lookup traces | identical key/default/transition result; missing authority never simulates allow |
| canonical bind alias | open through later `/work/input/job-42` bind alias | reconstructed candidate is original `/var/run/secrets/service/config.json`; allowed ordinary path control resolves normally |
| pre-existing hard-link alias | access one allowed and one denied spelling of the same object in both orders | no candidate cache transfers a path match; Version-1 cache remains disabled unless equivalence is proved |
| DIRTY topology | change mount/move/rename/link topology during repeated opens | all strict decisions after DIRTY are unresolved/hard-safe until clean snapshot commits |
| graph and component bounds | test exact/wildcard patterns at every limit and limit+1 | at-limit match is deterministic; overflow/truncation never becomes allow |

## Observed Effect Fixture Matrix

Every row is `operator + harness` where the kernel race or object generation
cannot be created reliably by hand.

| Fixture | Operator stimulus | Required observe-mode oracle |
| --- | --- | --- |
| `ADMIN-EXEC-APPROVAL-001` | simulate valid/invalid one-use admin exec candidates | exact approval/slot/exec candidate; no role activation or consumed production approval |
| `DEVICE-DERIVED-001` | open/use device and derived fd/object | exact device tuple, operation, actor, derived generation, and real completion result |
| `FILE-CONTENT-RACE-002` | mutate content/object around classification and use | exact before/after object/version; no stale trusted candidate |
| `FILE-FD-PASS-001` | inherit/pass/reuse fd across actors | current actor plus retained file provenance; no descriptor-number authority |
| `FILE-IDENTITY-001` | use symlink/hardlink/bind/proc-fd/overlay aliases | all aliases resolve to exact live object and honest path candidate |
| `FILE-MMAP-001` | map/read/write/execute files | mapping operation and completion are separate from open |
| `FILE-MMAP-SHARED-011` | share writable mapping across independent roots | exact object/mm relationship; no byte-provenance or actor merge claim |
| `FILE-NAMESPACE-001` | access through differing mount namespaces/views | actor view and topology generation select the candidate; no host-path shortcut |
| `FILE-SA-TOKEN-OPEN-001` | worker/controller access rotating projected token | distinct open/fd/read results; token bytes absent from evidence |
| `FILE-VMA-SNAPSHOT-001` | race VMA snapshot with map/unmap/share changes | positive mappings retained; negative snapshot becomes incomplete, never clean |
| `HF-LOCAL-001` | safe in-process driver attempts protected local effects | stable would-deny stage; unchanged legitimate conversion/controller succeeds |
| `IPC-ASYNC-UNSUPPORTED-010` | use unqualified io_uring/SQPOLL/async IPC path | explicit unsupported or hard-safe result, never silent observed allow |
| `IPC-PEER-RACE-004` | race peer exit/reuse/rebind during relationship use | exact live peer or unmatched result; no reused endpoint identity |
| `IPC-PROCESS-CHANNEL-009` | run directional control and channel operations | exact controller/peer/operation direction; reverse authority not inferred |
| `IPC-RELATIONSHIP-ALLOW-003` | declared peers communicate | exact allowed relationship and physical completion |
| `IPC-RELATIONSHIP-UNMATCHED-005` | unknown/reused/wildcard peer communicates | configured unmatched result and honest peer limit |
| `LSM-DENY-SATURATION-001` | saturate event delivery while an earlier/required denial occurs | physical denial remains hard; observe transport gap is separate |
| `MEM-EXEC-001` | create executable memfd/anonymous/file-backed memory | exact mmap/mprotect/pkey transition and completion state |
| `MEM-KERNEL-MAP-002` | race/overflow mm/VMA authority state | missing/partial state remains hard-safe; ordinary mapping control is observed |
| `MOUNT-ATTR-001` | use old/new mount APIs, propagation, idmap, recursive attrs | exact mutation candidate and DIRTY ordering |
| `MOUNT-CAS-002` | race topology generation CAS/reconciliation | one valid transition; conflict becomes unresolved |
| `MOUNT-PROPAGATION-003` | propagate a mount into another view | every affected view/snapshot is represented before clean decisions resume |
| `MOUNT-SNAPSHOT-004` | reconcile complete and partial mount snapshots | complete snapshot commits; partial/ambiguous snapshot stays dirty |
| `SELF-PROTECT-001` | attempt Mithril link/map/pin/config/binary mutation | exact attempted target/result and capability-health change; no self-containment overclaim |
| `STATE-PERSISTENT-FILE-LIFETIME-007` | close/reopen/reuse persistent shared object | object state survives only its exact qualified lifetime and references |
| `FILE-DELEGATED-EGRESS-001` | use remote file/local proxy/delegated I/O | acquisition is classified as delegated egress; file event does not invent remote result |
| `HF-004-RESULT-001` | exercise failed/allowed send, emitted packet, and provider write variants | each stage has its own result word; encrypted payload remains unobservable |
| `HF-011-READ-RESULT-001` | exercise zero/EOF/error/partial read, mmap, inherited fd, memory, send, provider write | no stage borrows another stage's result |
| `HF-NET-001` | attempt API/IMDS traffic from existing interpreter | exact actor/socket/destination/final-result observation; legitimate traffic succeeds |
| `IPC-LOCAL-INET-008` | communicate through loopback/Pod-IP/local IPv4/IPv6 | exact resolvable peer relationship or configured unmatched result |
| `NET-ACCEPT-PASS-001` | accept/pass/use socket across actors | creator, accepter, current actor, and peer state remain distinct |
| `NET-DNS-EXFIL-001` | run bounded UDP/TCP DNS framing and alternate resolver cases | parser result plus independent IP/destination floor; no qname guess on failure |
| `NET-NS-PASS-001` | pass socket across network namespaces | retained socket namespace/provenance; current namespace does not rewrite ownership |
| `NET-RECV-001` | receive through qualified and unsupported paths | exact receive-stage result or explicit unsupported status |
| `NET-REWRITE-001` | route through NAT/CNI/mesh/redirect variants | actor-stage candidate and final rewritten destination remain separate |
| `NET-SHARED-RESPONSE-002` | share established socket across lineages | disclosed socket/flow/cgroup scope; no per-lineage queued-byte claim |
| `NET-SOCKCTL-001` | bind/listen/accept/shutdown/setsockopt controls | exact socket generation and operation result |
| `NET-SOCKET-LIFE-001` | create/inherit/pass/reuse/destroy sockets | exact socket live interval/generation; fd or cookie reuse does not inherit state |

## Required Artifacts And Pass Rule

Retain source and compiled policy, signature/readback/simulation reports,
canonical-path traces, topology snapshots, verifier/bound measurements, exact
effect observations, legitimate-control results, and proof that active denial
was unchanged. Pass requires exact attribution or exact unsupported/unresolved
results for every row.

## Troubleshooting

- `WOULD_DENY` without a proven simulatable policy row is invalid.
- An unresolved mount/object/path must remain unresolved; do not fall back to
  the caller-provided pathname.
- If implementation discovers a missing hook or object identity, return that
  surface to Phase 0 before changing its ABI.
