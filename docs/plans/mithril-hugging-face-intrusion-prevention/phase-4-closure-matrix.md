# Phase 4 Closure Matrix

- Phase: [Signed Local Pre-Effect Enforcement](./phase-4-signed-local-pre-effect-enforcement.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Manual acceptance: [Phase 4 runbook](./manual-testing/phase-4-manual-acceptance.md)

## Closure Decision

Phase 4 is **Not done** for the signed path-tree denial claim. The earlier
limited x86_64 record remains evidence for the narrower operations that it
exercised. A current source review found that the live path resolver does not
preserve source ancestry after a successful first bind of a child directory.
The open finding is in
[`code-review-suggestions.md`](./code-review-suggestions.md).

This is capability closure. It does not say that an absent authority model was
implemented. Appendix A.13.7 requires a physical oracle for each advertised
operation and an exact `UNSUPPORTED` result for an unqualified operation.
Chapter 35 requires a surface with a missing hook, field, or identity model to
return to the prototype and type-closure gate. It must remain unsupported
until that gate passes.

The retained physical result contains one typed result for all 28 allocated
Appendix C fixtures and the additional plan-owned path-tree fixture. Its
recorded results are historical evidence, with this correction:

- 14 Appendix C fixtures are `PASS`.
- 14 Appendix C fixtures are `UNSUPPORTED`.
- `FILE-PATH-TREE-DENY-001` is **Not done**. The artifact recorded `PASS`, but
  its mount-attack case denied the mount syscall and did not test access after
  a successful child-directory bind.
- No fixture is `FAIL` or `DEGRADED` in the protected result.

The status terms in this matrix have these meanings:

- `PASS`: the advertised operation has current source, a physical negative
  oracle, a legitimate control, and a current protected result.
- `UNSUPPORTED`: the operation is not advertised. The record gives the exact
  missing qualification. A broader default denial can still hard-close an
  attempt, but that denial does not create positive support.

Source-aware child-bind traversal and its physical controls are open. Adding
one of the unsupported capabilities still requires a new authorized
qualification outcome.

## Deliverable Closure

| Deliverable | Closed result | Exact boundary |
| --- | --- | --- |
| `D4.1` | Signed generation verification, capacity preflight, staged readback, activation probes, one generation publication, retained holders, asynchronous references, recovery, and retirement are implemented. The protected probe records atomic publication, retained old holders, and deletion after the last holder. | The claim covers the represented generation owners. A new authority type must pass its own capacity, recovery, and retirement proof before it can join activation. |
| `D4.2` | Exact file-backed exec denials and represented executable mapping denials are physical. Unrepresented anonymous, memfd, deleted, and pkey paths hard-close. | Immutable executable source proof, complete script/interpreter/loader provenance, complete VMA state, and the protected concurrent-exec fixture are `UNSUPPORTED`. The exact file-backed executable control is not an immutable-image claim. |
| `D4.3` | Exact file, descriptor acquisition and use, represented mappings, namespace-aware identity, mount CAS, and exact snapshot recovery are physical for their recorded cases. The path-tree record proves direct paths, repeated-root aliases, future namespaces, and denied mount mutations. | Recursive path-tree denial after a successful first child-directory bind is **Not done**. Overlay copy-up provenance, projected-token rotation, complete VMA state, complete mount-attribute coverage, full propagation fan-out, and persistent file-instance lifetime are `UNSUPPORTED`. |
| `D4.4` | Exact Unix-stream relationships, stale and unmatched peer denial, inherited endpoint denial, exact ptrace denial, unmatched signal denial, and signal-zero control are physical. | The claim does not include arbitrary pipes, datagrams, shared memory, zero-copy channels, or unqualified asynchronous operations. |
| `D4.5` | Exact device ioctl policy and pre-install denial of a descriptor-producing PTMX operation are physical. Represented namespace, BPF, and managed-pin operations hard-close. | Granular authority after a derived object is minted and complete privilege or self-protection authority are not advertised. |
| `D4.6` | Exact signed exceptions, atomic N/N+1 consumption, expiry, receipts, and restart-safe exception WAL behavior are physical. | Administrative exec is not advertised. The stock-runc bootstrap path needs a validated authority decision before implementation. |
| `D4.7` | The node reports `LANDLOCK_TARGET_CONTEXT_FLOOR=UNSUPPORTED` with `NO_QUALIFIED_TARGET_CONTEXT_INSTALL`. | Landlock is absent. Local BPF enforcement does not depend on it. |
| `D4.8` | The safe in-process driver has physical exact-file denials and honest no-effect, outside-authority, deferred-network, and unsupported branch classifications. | The full `HF-LOCAL-001` fixture is `UNSUPPORTED` because projected-token rotation and its signed controller control are not qualified. The normative contract does not require a weaponized HDF5 payload. |

## Appendix C Fixture Closure

| Fixture | Result | Source, physical proof, and limit |
| --- | --- | --- |
| `ADMIN-EXEC-APPROVAL-001` | `UNSUPPORTED` | Control, admission, authorization, and one-use slot owners exist, but no administrative-exec claim is advertised. Stock runc needs a narrow bootstrap authority that the validated architecture does not define. Reason: `ADMIN_EXEC_CLAIM_NOT_ADVERTISED`. |
| `DEVICE-DERIVED-001` | `PASS` | Exact PTMX `TIOCGPTN` succeeds. Exact `/dev/zero` use denies. PTMX `TIOCGPTPEER` denies before a slave descriptor is installed. The tier does not advertise post-mint derived-object authority. |
| `EXEC-CONCURRENT-002` | `UNSUPPORTED` | The source has exec guards and normal concurrent-exec identity tests, but no protected source-role and target-role race with a forbidden-effect oracle. Reason: `PROTECTED_CONCURRENT_EXEC_NOT_PHYSICALLY_QUALIFIED`. |
| `FILE-CONTENT-RACE-002` | `UNSUPPORTED` | Exact inode, inode-generation, mount-view, and path identity do not prove immutable bytes. `SourceMutabilityProofV1` is absent from active source. Reason: `IMMUTABLE_SOURCE_MUTABILITY_PROOF_NOT_QUALIFIED`. |
| `FILE-FD-PASS-001` | `PASS` | The protected recipient installs no secret descriptor and receives no secret bytes. The benign descriptor installs once and remains readable. Later use is checked against the current recipient. |
| `FILE-IDENTITY-001` | `UNSUPPORTED` | Hard-link, symbolic-link, bind, proc-fd, replacement, and path-tree cases are physical. Overlay copy-up provenance is not qualified, so the full fixture is not advertised. Reason: `OVERLAY_COPY_UP_PROVENANCE_NOT_QUALIFIED`. |
| `FILE-MMAP-001` | `PASS` | Forbidden read, shared-write, executable mmap, and executable mprotect acquisition deny. Benign read and mapping controls succeed. |
| `FILE-MMAP-SHARED-011` | `PASS` | An independent root cannot acquire the protected shared writable mapping. Its exact benign mapping succeeds. The record proves distinct task, lineage, and process identities. No per-load, per-store, or byte-taint claim is made after an admitted mapping. |
| `FILE-NAMESPACE-001` | `PASS` | Bind canonicalization, protected and external mount replacement, global dirty closure, and exact reconciliation are physical. |
| `FILE-SA-TOKEN-OPEN-001` | `UNSUPPORTED` | The K3s lane discovers projected tokens, but it does not bind rotating token instances to signed worker and controller profiles. Reason: `PROJECTED_TOKEN_ROTATION_BINDING_NOT_QUALIFIED`. |
| `FILE-VMA-SNAPSHOT-001` | `UNSUPPORTED` | `MmSnapshotIdentityV1`, `VmaIteratorSessionV1`, and `VmaSnapshotV1` are absent from active source. Missing state hard-closes, but no complete positive snapshot exists. Reason: `COMPLETE_VMA_SNAPSHOT_NOT_QUALIFIED`. |
| `HF-LOCAL-001` | `UNSUPPORTED` | The safe driver physically denies represented protected-file branches and keeps the benign conversion-file control. The projected-token worker denial, signed controller allow, and rotation proof are absent. Reason: `PROJECTED_TOKEN_AND_CONTROLLER_CONTROL_NOT_QUALIFIED`. |
| `IPC-ASYNC-UNSUPPORTED-010` | `PASS` | Restricted io_uring read, benign read, worker attribution, completion, reference release, and SQPOLL denial before ring creation are physical. Unowned or unrepresented operations remain unsupported. |
| `IPC-PEER-RACE-004` | `PASS` | A declared Unix-stream peer communicates. Stale and unmatched peer generations deny. |
| `IPC-PROCESS-CHANNEL-009` | `PASS` | Exact Unix-stream communication, exact ptrace denial, unmatched signal denial, and signal-zero permission control are physical. |
| `IPC-RELATIONSHIP-ALLOW-003` | `PASS` | Declared independent roots communicate over the exact Unix-stream relationship without merging native identity. |
| `IPC-RELATIONSHIP-UNMATCHED-005` | `PASS` | Stale and unmatched peers deny. The declared peer control still succeeds. |
| `LSM-DENY-SATURATION-001` | `PASS` | Fifty thousand opens lose 39,081 observation records while the protected denial and benign allow remain correct. Policy does not depend on ring delivery. |
| `MEM-EXEC-001` | `UNSUPPORTED` | File-backed negative paths and an exact file-backed control exist. The control does not prove immutable executable bytes. Complete immutable source and VMA provenance are absent. Reason: `IMMUTABLE_EXECUTABLE_SOURCE_PROOF_NOT_QUALIFIED`. |
| `MEM-KERNEL-MAP-002` | `UNSUPPORTED` | Complete mm and VMA state, mutation generations, bounded capacity proof, and a valid-state positive control are absent. Reason: `MM_AND_VMA_STATE_NOT_QUALIFIED`. |
| `MOUNT-ATTR-001` | `UNSUPPORTED` | Global invalidation and one `mount_setattr` reconciliation are physical. Old and new API variants, recursive attributes, idmapped mounts, automount, referral, copy-up, and overflow are not all qualified. Reason: `COMPLETE_MOUNT_ATTRIBUTE_VARIANTS_NOT_QUALIFIED`. |
| `MOUNT-CAS-002` | `PASS` | A stale proposal cannot commit. Strict opens remain closed while dirty. Only an exact reconciled object restores authority. |
| `MOUNT-PROPAGATION-003` | `UNSUPPORTED` | One propagation peer enters fail closure and reconciles. Complete affected-view fan-out and overflow behavior are not qualified. Reason: `COMPLETE_PROPAGATION_FANOUT_AND_OVERFLOW_NOT_QUALIFIED`. |
| `MOUNT-SNAPSHOT-004` | `PASS` | Incomplete or replaced views stay closed. A complete represented snapshot restores only the exact object. |
| `SELF-PROTECT-001` | `UNSUPPORTED` | One managed link-pin unlink and represented BPF operations hard-close. Program, link, map, pin-root, configuration, binary, process, update, reboot, and kexec protection do not all have physical postconditions. Reason: `COMPLETE_LOCAL_SELF_PROTECTION_NOT_QUALIFIED`. |
| `STATE-FORK-IPC-002` | `PASS` | A child inherits a connected Unix-stream endpoint but not the parent's exact relationship authority. The child send denies, and the parent control succeeds. |
| `STATE-PERSISTENT-FILE-LIFETIME-007` | `UNSUPPORTED` | Exact live identity prevents pathname reuse from inheriting an object row. Persistent state across close, node restart, storage remount, reuse, and retirement is absent. Reason: `PERSISTENT_FILE_INSTANCE_LIFETIME_NOT_QUALIFIED`. |
| `STATE-THREAD-RACE-001` | `UNSUPPORTED` | Generation publication is atomic and old holders retain their generation. A real role transition raced with a protected effect is not physically qualified. Reason: `PROTECTED_EFFECT_ROLE_TRANSITION_RACE_NOT_QUALIFIED`. |

## Additional Plan-Owned Qualification

`FILE-PATH-TREE-DENY-001` is **Not done**. It is not an Appendix C fixture and
must not be added to
[`fixtures.yaml`](../../../spec/qualification/v1/fixtures.yaml). The signed
source accepts recursive `DENY` floors only. The retained result proves
pre-existing, later, replacement, maximum-depth, and future-namespace
children, an outside-tree control, denied mount mutations, and cleanup. It
does not prove source-path reconstruction after a successful child bind.

Closure requires a successful child bind before activation and a successful
bind by a separate qualified mount owner after activation. The protected
source-tree access must deny through each alias. An allowed bound subtree and
an allowed file outside the protected tree must remain readable.

## Current-Source Physical Record

The retained isolated VM ran the explicitly rebuilt standalone probe at source
commit `e0438d920d5071295ab733db0d7df0eb03a95b8c`.

- Probe binary SHA-256:
  `eee25b63425be5ec7ba8d7b9f8510cabea8c1b1af6aa832c90e1181373245fd0`.
- Result:
  `/tmp/mithril-phase4-e0438d9-final/local-enforcement-physical-probe.json`.
- Result SHA-256:
  `8fc1f4ad4536d00afd29754255410fed4b1290c3a138687f51c70edac079c793`.
- Platform: x86_64, Linux `6.8.0-137-generic`, cgroup v2, and BPF LSM.
- Active LSM order:
  `lockdown,capability,landlock,yama,apparmor,bpf`.
- Runtime BTF SHA-256:
  `6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c`.
- Protected deployment digest:
  `741a9fd0857e360a8b3096924f52dd59695d9f6440aa6610370e4e092b23b1dc`.

The JSON records 15 `PASS` results and 14 `UNSUPPORTED` results. The current
review does not accept its path-tree entry as closure, so the document does
not advertise 15 current passes. The JSON has no stale fs-verity experiment
fields. The probe records 10,000 measured opens,
50,000 saturation opens, 39,081 lost observations, preserved denial and
benign results, and all four cleanup fields as `true`. Independent remote
postflight also found no probe pin root, cgroup, or owner lease.

The repository command
`bash .github/scripts/verify-rust-ci.sh` passed on the same source commit.
One earlier run exposed a pre-existing parallel temporary-file collision in
`start_preserves_absolute_policy_paths`. The exact test passed alone, and
the unchanged repository gate passed on rerun. This matrix does not treat the
transient first result as a Mithril pass.

## Future And Unallocated Work

The following work does not widen the narrower recorded results:

| Owner or gate | Work outside the closed claim |
| --- | --- |
| New prototype and type-closure outcome | Immutable source proof, complete VMA/mm state, projected-token rotation, overlay copy-up provenance, complete mount variants and propagation, persistent file-instance state, protected exec and role races, and complete local self-protection. These items have no approved implementation owner after this closure. |
| Architecture decision | A stock-runc administrative bootstrap authority. The current plan text proposes a lease, but the validated architecture does not define it. A broad runc, pipe, or socket exception is forbidden. |
| Phase 5 | Destination-aware network, socket, DNS, rewrite, packet, receive, flow, network-namespace, and delegated-egress enforcement. |
| Phase 6 | General evidence WAL, coverage recovery, source health, reader-loss recovery, and durable link/map/pin health. The local exception-use WAL is already part of this closure. |
| Phase 7 | Detection packages and graph findings. A later finding cannot replace a pre-effect decision. |
| Phase 8 | Distributed Kubernetes causality, cross-node persistent-volume conclusions, and `NODE-FLOOR-EXCEPTION-002`. |
| Phase 9 | Response coordination and verified response postconditions. |
| Phase 10 | Provider connectors, provider authority, and provider recovery. |
| Phase 11 | Final platform, installation, performance, capacity, and full conformance reruns for each advertised release tier. |
| Phase 12 | Optional Seccomp compatibility. Landlock remains explicitly absent for the current platform. |

No later-phase allocation converts an `UNSUPPORTED` or **Not done** row into a
Phase 4 `PASS`. A later owner must produce its own qualified result before a
product claim changes.
