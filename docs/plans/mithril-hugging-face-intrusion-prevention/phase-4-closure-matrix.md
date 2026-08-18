# Phase 4 Closure Matrix

Phase: [Signed Local Pre-Effect Enforcement](./phase-4-signed-local-pre-effect-enforcement.md)  
Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)  
Manual acceptance: [Phase 4 runbook](./manual-testing/phase-4-manual-acceptance.md)

## Closure Decision

Phase 4 is `Not done` at implementation commit
`b6e5dea27aba3c7d430610bdae4c326297838e18`. The reviewed architecture
SHA-256 is
`22678b9c0379ff915fe595059f3da2789c3e32cdf54d61656c7257175263d14a`.

The source implements signed generation activation, exact local policy rows,
several positive controls, conservative hard-close paths, and a disposable
physical runner. These parts do not close the phase-wide claim. The required
matrix still has local authority and lifetime models that are absent, and the
implemented rows need one current-source physical result.

The status terms in this matrix have these meanings:

- `Done`: the source owner, exact negative oracle, legitimate control, and
  current acceptance record are complete.
- `Proof open`: the production path and physical fixture exist, but no final
  current-source physical result closes the row.
- `Implementation open`: one or more required authority, lifecycle, race, or
  control paths do not exist.

Current count: 14 `Done`, zero `Proof open`, and 14 `Implementation open`
for the 28 Appendix C fixtures. The additional plan-owned path-tree test is
`Done`.

## Deliverable Closure

| Deliverable | Current source | Result | Work needed for closure |
| --- | --- | --- | --- |
| `D4.1` | [`NodePolicyGenerationOwner`](../../../crates/mithril-node/src/policy.rs) verifies signed artifacts and rollback state, preflights capacity, stages and reads back rows, probes staged decisions, publishes one profile-generation pointer, recovers ambiguous commits, retains old holders, and deletes retired rows after represented references clear. | Partial | Prove crash and concurrent-holder retirement, pending exec and administrative state, and the required post-reference grace boundary in one current physical lifecycle matrix. |
| `D4.2` | The BPF exec and memory hooks enforce exact file-backed exec variants and represented executable mappings. Unsupported anonymous, memfd, and pkey paths fail closed. | Partial | Add complete immutable image, content-race, script, interpreter, `binfmt_misc`, loader, pkey, and VMA provenance. Run the protected concurrent-exec race. |
| `D4.3` | Exact file rows, represented aliases, passed-descriptor acquisition and use, independent-root shared-mapping denial, recursive path-tree denial, global mount invalidation, propagation-peer invalidation, and exact reconciliation exist. | Partial | Add projected-token rotation, overlay copy-up, persistent file and VMA state, positive create parent-and-name authority, and the remaining local acquisition provenance. Qualify the complete mount race matrix. |
| `D4.4` | Exact Unix-stream relationships and exact process-control target rows exist. The runner has positive, inherited-endpoint, stale-peer, unmatched-peer, and denial controls. | Partial | Add listener transfer, socket activation, datagram, pipe, shared-memory, zero-copy, and remaining asynchronous lifetime models. |
| `D4.5` | Exact device ioctl and process-control rows exist. A descriptor-producing PTMX operation fails closed before it installs the derived descriptor. Represented namespace, BPF, and managed-pin operations also fail closed. | Partial | Add capability, credential, namespace, process-vm, pidfd, perf, module, keyring, and complete local self-protection authority. Do not advertise granular post-mint derived-object authority without a qualified label hook. |
| `D4.6` | Signed bounded exceptions use exact matching entries, atomic consumption, receipts, and a restart-safe WAL. The administrative path reaches Control, admission, and slot arm. | Partial | Model stock-runc bootstrap without a broad exception. Then prove one exact winner plus replay, expiry, mismatch, disconnect, and contention denials. |
| `D4.7` | The node reports `LANDLOCK_TARGET_CONTEXT_FLOOR=ABSENT` with reason `NO_QUALIFIED_TARGET_CONTEXT_INSTALL`. | Done as `ABSENT` | No Landlock work is a release gate for this platform result. |
| `D4.8` | [`EffectTestRunner`](../../../crates/mithril-e2e/src/effect.rs) records a static branch classification and represented local denials. | Partial | Add one physical first-effect negative oracle and one legitimate control for every branch that claims local prevention. Do not convert in-memory, remote, or unsupported branches into prevention claims. |

## Appendix C Fixture Closure

| Fixture | Current source and proof | Exact remaining work | Status |
| --- | --- | --- | --- |
| `ADMIN-EXEC-APPROVAL-001` | The Control, admission, signed node authorization, and exact one-use slot owners exist. The current VM lane reaches slot arm. | Stock runc fails closed in its unmodeled sealed self-clone and bootstrap channels before the target exec. Add a narrow typed bootstrap protocol and run the winner, non-winner, replay, expiry, mismatch, disconnect, and contention matrix. | Implementation open |
| `DEVICE-DERIVED-001` | The runner allows exact PTMX `TIOCGPTN`, denies exact `/dev/zero` use, and hard-closes PTMX `TIOCGPTPEER` before the descriptor-producing ioctl installs a slave descriptor. The observation retains the exact PTMX object and command. | The qualified tier denies derived-object minting as a whole. It does not advertise granular post-mint derived-object authority. The current physical record has both derived-peer fields true and retains the harmless PTMX control. | Done |
| `EXEC-CONCURRENT-002` | The identity runner proves normal Linux two-thread exec behavior only. | Race real source-role and target-role transitions against a protected exec. Prove one complete state and no forbidden effect from a loser or child. | Implementation open |
| `FILE-CONTENT-RACE-002` | Exact inode, inode-generation, mount-view, and path restrictions exist. | Add immutable approved-content provenance. Race mutation or replacement between classification and use, reject stale authority, and retain one immutable positive control. | Implementation open |
| `FILE-FD-PASS-001` | The effect runner checks protected and benign descriptor receipt, acquisition, and later read. | The current-source physical record has `passed_fd_read_denied=true`, `passed_fd_acquisition_denied=true`, `passed_fd_acquisition_installed_nothing=true`, and all three benign acquisition and read controls true. | Done |
| `FILE-IDENTITY-001` | Exact object decisions and hard-link, symbolic-link, bind, proc-fd, and recursive path-tree cases exist. | Add the required overlay copy-up identity case, then run the final alias matrix. | Implementation open |
| `FILE-MMAP-001` | The effect runner checks forbidden read, writable shared, and executable file mappings plus benign mapping controls. | The current-source physical record has all four represented file and executable mapping denials true and both benign mapping controls true. | Done |
| `FILE-MMAP-SHARED-011` | A target created before protected-cgroup attachment receives a distinct root task, process lineage, and process instance. Its inherited protected fd cannot create a writable shared mapping. The same root can create the exact benign mapping. | The current physical record has the denial, benign control, and distinct-identity fields true. The strict tier denies mapping acquisition and makes no per-load, per-store, or byte-taint claim after an admitted mapping. | Done |
| `FILE-NAMESPACE-001` | Live mount-view lookup, bind-alias selection, dirty closure, and exact reconciliation exist. | The current-source physical record has bind canonicalization, protected and external mount-race fail closure, exact restoration, and the outside-tree control true. | Done |
| `FILE-SA-TOKEN-OPEN-001` | The K3s lane discovers a projected token, but the effect bundle marks the branch `Unsupported`. | Bind worker and controller to distinct signed profiles. Deny the worker before fd or bytes, allow the controller, rotate the token, and prove no visibility gap. | Implementation open |
| `FILE-VMA-SNAPSHOT-001` | Missing or unsupported VMA state fails closed. | Add a complete typed VMA snapshot and its mutation generation. Race map, unmap, share, and policy or response changes. Prove an incomplete snapshot never allows and a complete snapshot has a positive control. | Implementation open |
| `HF-LOCAL-001` | Static classifications and represented exact file and exec denials exist. | Add branch-specific physical fixtures for each local prevention claim, including the complete hostile HDF5 no-fd/no-bytes oracle and its legitimate conversion control. | Implementation open |
| `IPC-ASYNC-UNSUPPORTED-010` | Restricted io_uring read and write ownership, executor attribution, completion, reference release, and SQPOLL fail closure exist. | The current-source physical record has denied exact read, allowed benign read, worker attribution, denied SQPOLL before ring creation, and released lifecycle state. Unsupported opcodes and unowned SQPOLL remain explicit. | Done |
| `IPC-PEER-RACE-004` | Exact Unix-stream peer generations, a stale-peer denial, and an exact allowed peer exist. | The current-source physical record has exact relationship allow plus stale and unmatched peer denials. The stale case uses a changed peer generation. | Done |
| `IPC-PROCESS-CHANNEL-009` | Exact directional Unix-stream and process-control rows exist with represented positive and negative controls. | The current-source physical record has an allowed exact Unix-stream relationship, exact ptrace denial, unmatched signal denial, and allowed signal-zero permission control. | Done |
| `IPC-RELATIONSHIP-ALLOW-003` | A declared exact Unix-stream peer can communicate without merging task identity. | The current-source physical record has `unix_stream_relationship_allowed=true`; the fixture keeps distinct actor and peer identities. | Done |
| `IPC-RELATIONSHIP-UNMATCHED-005` | Stale and unmatched Unix-stream peers deny, and the declared peer control succeeds. | The current-source physical record has stale and unmatched denials plus the declared-peer positive control. | Done |
| `LSM-DENY-SATURATION-001` | The runner performs 50,000 opens while it checks a policy denial and benign allow independently from event delivery. | The current-source physical record lost 39,081 observation records under saturation while the policy denial and benign allow remained true. | Done |
| `MEM-EXEC-001` | Exact executable file and represented mapping transitions have deny and allow controls. Anonymous, memfd, pkey, and incomplete paths fail closed. | Complete immutable image and VMA provenance for the advertised script, interpreter, loader, `binfmt_misc`, memfd, deleted-file, anonymous, mprotect, and pkey paths. | Implementation open |
| `MEM-KERNEL-MAP-002` | Missing represented state fails closed. | Add complete mm and VMA state, bounded capacity, mutation generations, cleanup, and a positive valid-state control. Prove races, overflow, and corruption cannot relax authority. | Implementation open |
| `MOUNT-ATTR-001` | A global dirty epoch covers represented mount operations, one propagation peer, and `mount_setattr` reconciliation. | Add and qualify old and new mount APIs, recursive attributes, idmapped mounts, automount, referral, overlay copy-up, and overflow behavior. | Implementation open |
| `MOUNT-CAS-002` | The runner rejects a stale proposal, blocks protected opens while dirty, and restores only an exact reconciled object. | The current-source physical record has the stale-proposal denial, protected mount-race denial, external replacement fail closure, and exact restoration true. | Done |
| `MOUNT-PROPAGATION-003` | One propagation peer enters fail closure and later reconciles. | Add the complete affected-view and overflow model, then run the full propagation race matrix. | Implementation open |
| `MOUNT-SNAPSHOT-004` | Complete represented snapshots restore exact authority; partial or replaced views remain dirty and denied. | The current-source physical record has global invalidation, propagation-view fail closure, reconciliation, external replacement fail closure, and exact restoration true. | Done |
| `SELF-PROTECT-001` | The runner denies one managed link-pin unlink and detects some pin identity changes. | Protect or explicitly close capability for program, link, map, pin-root, configuration, binary, process, and update-path replacement. Add a physical postcondition for each claimed operation. | Implementation open |
| `STATE-FORK-IPC-002` | The protected effect runner forks after it creates an exact Unix-stream relationship. The child inherits the connected endpoint but has a distinct task and process identity. | The current-source physical record has `inherited_unix_stream_send_denied=true` and `unix_stream_relationship_allowed=true`. The inherited child receives no relationship authority from the parent. | Done |
| `STATE-PERSISTENT-FILE-LIFETIME-007` | Exact live file identity prevents a different inode from inheriting an old row by name. | Add persistent object state across close, node restart, storage remount or reuse, and exact retirement. Prove a new object cannot inherit clean authority. | Implementation open |
| `STATE-THREAD-RACE-001` | Generation publication is atomic for new roots, and existing tasks retain their pinned generation. | Race a real task role or generation transition with a protected local effect. Prove every effect sees one complete state and no stale authority completes. | Implementation open |

## Additional Plan-Owned Qualification

`FILE-PATH-TREE-DENY-001` is `Done`. It is not one of the 133 Appendix C
fixture IDs, so it must not be added to
[`spec/qualification/v1/fixtures.yaml`](../../../spec/qualification/v1/fixtures.yaml).
The master plan permits a phase-owned test outside Appendix C. The signed
source rejects positive path rules and installs generation-scoped recursive
deny floors. The privileged VM result at implementation commit `d38248f`
proves pre-existing, later, replacement, maximum-depth, and future-namespace
children, an outside-tree positive control, mount-attack fail closure, and
cleanup. The
[path-tree review guide](./path-tree-denial-implementation-review.md) records
the exact lookup order and limits.

## Current-Source Physical Record

The repository VM harness passed at implementation commit `5dd695e`. The guest
ran x86-64 Ubuntu Linux
`6.8.0-137-generic` with BPF LSM, cgroup v2, runtime BTF, and unique mount
IDs. The production BPF object SHA-256 is
`ca4dace998d14c6755d759bc7c20d0c21a34c40c18c75c317f4ea2a84b95cd64`.

The local-enforcement JSON is
`/tmp/mithril-phase4-full-after-fixes/local-enforcement-physical-probe.json`.
Its SHA-256 is
`04b1fdb9f5b86c884612a880d79fe272d45e79eaade69a1fc238808376eab465`.
The harness validated the kernel, identity, observation, protection, and
cleanup records before it returned success. The record has 10,000 measured
opens and 50,000 saturation opens. It also has `pin_root_removed=true`,
`lease_removed=true`, `cgroup_removed=true`, and
`fixture_root_removed=true`.

The derived-device slice passed in the retained guest at implementation
commit `e6da7a2`. Its JSON is `/tmp/mithril-phase4-device-derived.json`, and its
SHA-256 is
`1d10974f2bc42c62e645b6d3fa07605912f5f72165b448dff955edffb053a7a3`.
It has `ptmx_ioctl_exact_allowed=true`,
`ptmx_derived_peer_hard_closed=true`,
`ptmx_derived_peer_installed_nothing=true`, and all four cleanup fields true.

The independent-root shared-mapping slice passed at implementation commit
`b6e5dea`. Its JSON is `/tmp/mithril-phase4-independent-mmap.json`, and its
SHA-256 is
`d41f0f133ffeb38b37431d5a77bf8515bfc5485f711120f94788ae375bf75b8f`.
It has `independent_root_shared_mmap_denied=true`,
`independent_root_benign_mmap_allowed=true`,
`independent_root_shared_mmap_distinct_identity=true`, and all four cleanup
fields true.

The identity source now serializes external-root label publication against a
concurrent exit. The physical fixture also uses explicit process barriers for
PID-namespace and `CLONE_INTO_CGROUP` transitions. Six consecutive identity
probes passed in one retained guest. The fresh full harness then passed the
identity probe and reported `profile_task_refs_after_exit=0`. Its identity JSON
SHA-256 is
`fff4e3f494751c01b8e75c83e1515bbb16ce143ea4c93ac7e2e79c7c4dc66c99`.

## Work Assigned To Later Phases

The following work is not a Phase 4 closure gate:

- Phase 5 owns destination-aware network enforcement, socket and flow
  authority, and `FILE-DELEGATED-EGRESS-001`. Phase 4 still owns local
  descriptor and delegated-I/O acquisition before a remote effect.
- Phase 6 owns durable evidence, coverage recovery, reader loss, and general
  evidence WAL behavior. Phase 4 still owns the exception-use WAL that is part
  of the local authorization decision.
- Phase 7 owns graph findings and detection packages. A later finding cannot
  replace a Phase 4 pre-effect decision.
- Phase 8 owns distributed Kubernetes causality and
  `NODE-FLOOR-EXCEPTION-002`. Its rerun of administrative exec does not replace
  the Phase 4 single-node approval transaction.
- Phase 9 owns response coordination. Phase 10 owns provider connectors and
  recovery. Neither phase replaces a local authority model.
- Phase 11 owns final platform, performance, capacity, installation, and full
  conformance reruns. Phase 4 must still produce its current-source physical
  result before that rerun.
- Phase 12 owns optional Seccomp compatibility. Landlock is already closed as
  an explicit `ABSENT` result for the current platform.

No later-phase allocation removes any of the 28 Appendix C rows from this
matrix.
