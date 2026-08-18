# Phase 3 Closure Matrix

Phase: [Effect Observation And Profile Simulation](./phase-3-effect-observation-and-profile-simulation.md)  
Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)  
Manual acceptance: [Phase 3 runbook](./manual-testing/phase-3-manual-acceptance.md)

## Closure Decision

Phase 3 is `Done`. This result closes observation, classification, and
simulation only. It does not activate a signed policy denial or claim local or
network prevention.

The checked-in [simulation matrix](../../../crates/mithril-control/tests/fixtures/profile-simulation.json)
contains 51 cases. It contains all 39 fixture IDs that the phase plan assigns
from Phases 4 and 5. The
[matrix test](../../../crates/mithril-control/tests/profile_simulation.rs)
requires each assigned ID, rejects duplicates, compiles the exact actor,
object, family, and operation, and compares the expected decision with the
simulator result.

A `Done` row below means that Phase 3 has one exact result. It can be a
simulated `ALLOW` or `WOULD_DENY`, or an explicit hard result for unsupported,
ambiguous, or prior-LSM state. It does not mean that the later positive model
or active denial is implemented.

## Deliverable Closure

| Deliverable | Phase 3 proof | Result | Later work that is not part of this result |
| --- | --- | --- | --- |
| `D3.1` | The closed parser, deterministic lowering, conflict checks, canonical CBOR, Ed25519 signatures, and rollback envelope are owned by [`mithril-control::policy`](../../../crates/mithril-control/src/policy). Compiler and golden tests reject unknown, duplicate, conflicting, replayed, and malformed input. | Done | Phase 4 owns activation of a signed local denial generation. |
| `D3.2` | [`NodePolicyGenerationOwner`](../../../crates/mithril-node/src/policy.rs) verifies, installs, reads back, recovers, and simulates immutable candidate generations without partial activation. | Done | Phase 4 owns the active generation pointer and local denial lifecycle. |
| `D3.3` | The production Interceptor object and node reconciliation owner implement the bounded component walk, oldest unique mount selection, namespace-wide `DIRTY` state, proposal CAS, and exact-object revalidation. The Rust probe and Docker alias and mount cases provide physical checks. | Done | Phase 4 owns active local denial after the same checks. Propagation beyond the represented local mount model stays explicit until its owning fixture is qualified. |
| `D3.4` | The shared Interceptor emits typed local effect records. Every required future fixture has an exact Phase 3 result. Unqualified families retain an explicit hard result. | Done | Phase 4 owns local enforcement. Phase 5 owns destination-aware network enforcement. |
| `D3.5` | Exact file and mount-view generations and the narrow represented Unix-stream, device-ioctl, and process-target types are present. Other object and relationship models are explicit `UNSUPPORTED` or `AMBIGUOUS`; they are not inferred from partial identity. | Done for the Phase 3 classification contract | Phase 4 owns remaining positive local relationship, VMA, persistent-state, derived-authority, and self-protection models. Phase 5 owns socket, destination, flow, and network-namespace models. |
| `D3.6` | The BPF decision is fixed before ring reservation. `OBSERVE` converts only a simulatable policy denial to `WOULD_DENY`. Missing identity, unsupported objects, ambiguous topology, prior LSM denial, and telemetry loss keep their hard result. | Done | Phase 6 owns durable evidence, WAL, replay, and coverage recovery. |
| `D3.7` | The 51-case matrix classifies the managed, in-memory, external-authority, local, and network branches for `HF-002` through `HF-012`. The privileged Rust probe records its physical HF branch classifications and limits. | Done | Phases 4 and 5 own active local and network results. Provider-semantic conclusions remain in their later owning phases. |

## Phase 4 Fixture Inputs

| Fixture | Exact Phase 3 result | Proof and limit | Later owner | Phase 3 |
| --- | --- | --- | --- | --- |
| `ADMIN-EXEC-APPROVAL-001` | `EXEC/EXECUTE/ADMIN_EXEC_SLOT` → `HARD_DENY_UNSUPPORTED` | Exact simulation. No production approval is consumed. | Phase 4 approval and activation | Done |
| `DEVICE-DERIVED-001` | `DEVICE/IOCTL/DERIVED_DEVICE_CAPABILITY` → `HARD_DENY_UNSUPPORTED` | Exact simulation. The narrow exact-device ioctl model does not prove derived capability lineage. | Phase 4 derived authority | Done |
| `FILE-CONTENT-RACE-002` | `FILE/READ/VERSIONED_FILE` → `HARD_DENY_UNSUPPORTED` | Exact simulation. No byte-provenance claim is made. | Phase 4 versioned content authority | Done |
| `FILE-FD-PASS-001` | `FILE/READ/PASSED_FILE_INSTANCE` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Passed-descriptor positive provenance is not qualified. | Phase 4 delegated local file authority | Done |
| `FILE-IDENTITY-001` | `FILE/OPEN_READ/EXACT_FILE_OBJECT` → `WOULD_DENY` | The Rust probe records `exact_open_observed=true` and `exact_open_denied_before_effect=false`. The Docker direct-file case records the same observe-only result. | Phase 4 active exact-file denial | Done |
| `FILE-MMAP-001` | `FILE/MMAP_READ/EXACT_FILE_OBJECT` → `WOULD_DENY` | Exact simulation. The phase result does not claim physical mmap denial. | Phase 4 active mmap policy | Done |
| `FILE-MMAP-SHARED-011` | `FILE/MMAP_WRITE/SHARED_VMA` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Shared writable VMA provenance is not qualified. | Phase 4 VMA authority | Done |
| `FILE-NAMESPACE-001` | `FILE/OPEN_READ/AMBIGUOUS_MOUNT_VIEW` → `HARD_DENY_AMBIGUOUS_TOPOLOGY` | The mount-race and external-replacement probes stay hard closed until exact reconciliation. | Phase 4 active namespace-aware file policy | Done |
| `FILE-SA-TOKEN-OPEN-001` | `FILE/OPEN_READ/PROJECTED_TOKEN` → `WOULD_DENY` | Exact simulation. It does not prove rotating projected-token identity. | Phase 4 projected-token model | Done |
| `FILE-VMA-SNAPSHOT-001` | `FILE/MMAP_READ/VMA_SNAPSHOT` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Complete VMA snapshot identity is not qualified. | Phase 4 VMA snapshot model | Done |
| `HF-LOCAL-001` | `FILE/OPEN_READ/PROJECTED_TOKEN` → `WOULD_DENY` | Exact simulation for the managed local branch. Resident bytes remain outside a new file effect. | Phase 4 active local HF control | Done |
| `IPC-ASYNC-UNSUPPORTED-010` | `IPC/IPC_ACCESS/ASYNC_CHANNEL` → `HARD_DENY_UNSUPPORTED` | Exact simulation. No asynchronous channel relationship is inferred. | Phase 4 asynchronous IPC model | Done |
| `IPC-PEER-RACE-004` | `IPC/IPC_ACCESS/RACING_PEER` → `HARD_DENY_UNSUPPORTED` | Exact simulation. A changing peer cannot use a stale positive relationship. | Phase 4 peer lifetime and race model | Done |
| `IPC-PROCESS-CHANNEL-009` | `IPC/IPC_ACCESS/PROCESS_CHANNEL` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Process-channel positive authority is absent. | Phase 4 process-channel model | Done |
| `IPC-RELATIONSHIP-ALLOW-003` | `IPC/IPC_ACCESS/DECLARED_PEER` → `ALLOW` | Deterministic simulation only. The compiler does not install a positive exact Unix-stream relationship in the production object. | Phase 4 positive relationship model | Done |
| `IPC-RELATIONSHIP-UNMATCHED-005` | `IPC/IPC_ACCESS/UNMATCHED_PEER` → `HARD_DENY_UNSUPPORTED` | Exact simulation and unmatched-policy handling. | Phase 4 relationship enforcement | Done |
| `STATE-FORK-IPC-002` | `IPC/IPC_ACCESS/INHERITED_IPC_CHANNEL` → `WOULD_DENY` | The required matrix membership and expected result are test-enforced. This closure added the missing case. | Phase 4 inherited-channel lifecycle | Done |
| `LSM-DENY-SATURATION-001` | `FILE/OPEN_READ/EXACT_FILE_OBJECT` → `HARD_DENY_PRIOR_LSM` | Exact simulation. The 50,000-open physical runs prove explicit ring loss cannot change an unrelated hard network result. They do not prove active signed-denial saturation. | Phase 4 active-denial saturation; Phase 6 durable loss recovery | Done |
| `MEM-EXEC-001` | `FILE/MMAP_EXEC/EXECUTABLE_MEMORY` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Anonymous executable mappings retain their separate physical hard close. | Phase 4 executable-memory model | Done |
| `MEM-KERNEL-MAP-002` | `FILE/MPROTECT/UNKNOWN_VMA` → `HARD_DENY_UNSUPPORTED` | Exact simulation. No kernel-map or VMA provenance is invented. | Phase 4 kernel-map and VMA model | Done |
| `MOUNT-ATTR-001` | `MOUNT/MOUNT/MOUNT_TOPOLOGY` → `HARD_DENY_UNSUPPORTED` | Exact simulation. The Rust probe records global invalidation and exact reconciliation for its represented mount-attribute case. | Phase 4 signed mount policy | Done |
| `MOUNT-CAS-002` | `MOUNT/MOUNT/DIRTY_MOUNT_VIEW` → `HARD_DENY_AMBIGUOUS_TOPOLOGY` | The Rust probe rejects stale proposals and restores only the exact object. | Phase 4 active policy after clean CAS | Done |
| `MOUNT-PROPAGATION-003` | `MOUNT/MOUNT/PROPAGATED_MOUNT_VIEW` → `HARD_DENY_AMBIGUOUS_TOPOLOGY` | The Rust probe records propagation to the represented peer, hard closure of represented views, and reconciliation. It does not claim arbitrary cross-namespace fan-out. | Phase 4 expanded propagation model | Done |
| `MOUNT-SNAPSHOT-004` | `MOUNT/MOUNT/PARTIAL_MOUNT_SNAPSHOT` → `HARD_DENY_AMBIGUOUS_TOPOLOGY` | Bind-alias, protected mount race, external replacement, and exact restoration are physical. Partial snapshots never become allow. | Phase 4 active mount-view policy | Done |
| `SELF-PROTECT-001` | `PRIVILEGE/BPF/MITHRIL_STATE` → `HARD_DENY_UNSUPPORTED` | Exact simulation. The physical probe hard-closes its represented BPF and managed-pin mutations. Full self-protection is not claimed. | Phase 4 complete local self-protection | Done |
| `STATE-PERSISTENT-FILE-LIFETIME-007` | `FILE/READ/PERSISTENT_FILE_STATE` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Persistent provenance across reuse and restart is absent. | Phase 4 persistent file state | Done |

## Phase 5 Fixture Inputs

| Fixture | Exact Phase 3 result | Proof and limit | Later owner | Phase 3 |
| --- | --- | --- | --- | --- |
| `FILE-DELEGATED-EGRESS-001` | `FILE/READ/DELEGATED_FILE_IO` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Local file identity is not treated as egress authority. | Phase 5 delegated egress | Done |
| `HF-004-RESULT-001` | `NETWORK/SEND/NETWORK_RESULT` → `HARD_DENY_UNSUPPORTED` | Exact simulation. No provider or remote-result authority is installed. | Phase 5 network result | Done |
| `HF-011-READ-RESULT-001` | `FILE/READ/FILE_RESULT` → `HARD_DENY_UNSUPPORTED` | Exact simulation. The result does not claim rotating token or remote publication semantics. | Phase 5 result-aware flow | Done |
| `HF-NET-001` | `NETWORK/CONNECT/DESTINATION` → `HARD_DENY_UNSUPPORTED` | Exact simulation. The Docker and Rust saturation cases prove unsupported network identity remains physically denied. | Phase 5 destination-aware connect | Done |
| `IPC-LOCAL-INET-008` | `IPC/IPC_ACCESS/LOCAL_INET_PEER` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Loopback does not become a trusted local IPC relationship. | Phase 5 local-INET peer model | Done |
| `NET-ACCEPT-PASS-001` | `NETWORK/CONNECT/PASSED_SOCKET` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Passed-socket provenance is not qualified. | Phase 5 accepted and passed socket state | Done |
| `NET-DNS-EXFIL-001` | `NETWORK/SEND/DNS_DESTINATION` → `HARD_DENY_UNSUPPORTED` | Exact simulation. DNS intent is not inferred from a socket. | Phase 5 DNS-aware enforcement | Done |
| `NET-NS-PASS-001` | `NETWORK/SEND/CROSS_NAMESPACE_SOCKET` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Cross-namespace socket identity is absent. | Phase 5 network-namespace transfer | Done |
| `NET-RECV-001` | `NETWORK/READ/RECEIVE_SOCKET` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Receive-side remote identity is absent. | Phase 5 receive path | Done |
| `NET-REWRITE-001` | `NETWORK/CONNECT/REWRITTEN_DESTINATION` → `HARD_DENY_UNSUPPORTED` | Exact simulation. A pre-rewrite destination cannot authorize the final flow. | Phase 5 rewrite and final-flow identity | Done |
| `NET-SHARED-RESPONSE-002` | `NETWORK/READ/SHARED_SOCKET` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Shared-socket response attribution is absent. | Phase 5 shared response attribution | Done |
| `NET-SOCKCTL-001` | `NETWORK/CONNECT/SOCKET_CONTROL` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Socket control state is not a positive destination claim. | Phase 5 socket-control model | Done |
| `NET-SOCKET-LIFE-001` | `NETWORK/CONNECT/SOCKET_LIFETIME` → `HARD_DENY_UNSUPPORTED` | Exact simulation. Socket lifetime, reuse, and final-flow identity remain unqualified. | Phase 5 socket lifecycle | Done |

## Physical Closure Record

The final source-backed physical record used commit
`30f3b2ee9a8870d01d8b14f32eb817fcf2a38a71` for the runtime and operator
sources. Documentation-only commits follow this source state.

The disposable VM ran x86_64 Linux `6.8.0-137-generic`, BPF LSM, cgroup v2,
runtime BTF, Docker `29.1.3`, and the pinned image
`docker.io/library/python:3.13-slim-bookworm@sha256:00faa2debb87529f9f0764e9491d8ba400a3678976616c3bd7cb193745ac20d1`.
The `mithril-node` SHA-256 was
`b7b5ba057380885ec7bf628dd171ba09cf8d9896e35c177f535b2b49257ab085`.
The `mithril-effect-test` SHA-256 was
`896f8255c8e81ea1cba268a02401a6dc86d5b0c43b50191d957f22aec3755ee3`.

The self-cleaning Rust probe result SHA-256 is
`71c09e60a614ed96ae9b4050804c2607996cda2e3785152372642ea6bc06215a`.
It records:

- `protect_mode=false`, `exact_open_observed=true`, and
  `exact_open_denied_before_effect=false`;
- hard-link non-transfer, bind-alias canonicalization, protected mount-race
  denial, external-replacement fail closure, and exact reconciliation;
- 10,000 measured opens with averages of 8,638 ns baseline and 12,755 ns in
  observe mode;
- 50,000 saturation opens with the network hard denial and benign allow
  unchanged; and
- removal of its pin root, lease, cgroup, and fixture root.

The final Docker operator records have these SHA-256 values:

| Case | SHA-256 | Result |
| --- | --- | --- |
| deterministic compiler | `b176859a4f6c505ae99bc939a65f5d5af801baa725d2c9551e2f1f92f65c8749` | 19 exact cells; deterministic signed candidate; policy denial simulated |
| exact file observe | `16c689e208dd94334efc4271bad482c7c58bfc12b4a079bdd1b8f60b3e16ff68` | read completed; exact `WOULD_DENY` observed |
| later bind alias | `1247b02fc5e1f0103e31bbd958fc3a7f6873b06193f1027c383f200958f0f8f6` | original tracked mount selected |
| pre-existing hard link | `b47d55644dc935d11c895119088a4a4f7e7cfdf4f855e718abff3a505e1958e1` | original simulated denial; alias unresolved |
| protected mount attack | `06f0de4ddc476428b4c6cfbd27c4332d184309592ee307307b47626e39fdab58` | concurrent mounts denied; exact reconciliation restored observe result |
| unsupported network | `1dd1ce054e6ee2cf6a1a460c5f3f7b71ed93c398318bc29f7a4497e86dc9df47` | hard denial retained in observe mode |
| saturation | `7024ad4f3eb485900aa250998fc4234f143ae92cfe1419b2f286f888b3f9ab9b` | explicit loss; unsupported network remained denied |
| latency | `17acf24f57ec09951973e9fcb1dd736769c0bba3f2ac5a3473b5a44515c4c6db` | 10,000 opens; zero loss; 10,839.40 ns baseline and 35,649.58 ns observed per open |

Each operator case removed its task, node, BPF pins, state, lease, socket, and
run-scoped files. Final inspection found no Mithril BPF program. The exact
test container, fixture, VM domain, and two VM work directories were removed
after the nonsecret evidence was copied and hashed.

## Work Assigned To Later Phases

This closure does not pull later work into Phase 3:

- Phase 4 owns active signed local denial, positive IPC and process-control
  relationships, complete executable-memory and VMA identity, persistent
  object state, derived authority, expanded propagation, and complete local
  self-protection.
- Phase 5 owns destination, socket, DNS, rewrite, packet, receive, flow,
  network-namespace, and delegated-egress enforcement.
- Phase 6 owns durable evidence, WAL, replay, reader recovery, and coverage
  claims during loss.
- Phase 11 owns final platform, performance, and capacity qualification.
- Any mechanism without a later qualified owner remains explicit
  `UNSUPPORTED`; this phase does not assign it an allow result.

There is no remaining Phase 3 implementation or test item. Work in later
phases is not authorized by this closure.
