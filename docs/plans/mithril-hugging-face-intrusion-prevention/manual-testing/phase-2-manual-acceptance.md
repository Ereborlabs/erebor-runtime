# How To Manually Accept Phase 2

Status: The current source passed the automated privileged VM identity probe.
The optional k3s lane passed its substrate checks. It did not configure a
Mithril CRI binding. The full operator matrix is not recorded.

Phase: [Exact Native Identity](../phase-2-exact-native-identity.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md)
Implementation: [native-identity case shells and readable catalog](../../../../examples/mithril-identity-manual/README.md)

## Outcome

Prove exact task/process/execution/native-family and runtime-root identity exists
before a protected effect and cannot be recovered through command equality,
restart, reparenting, movement, or identifier reuse.

## Automated Companion

```bash
cargo test -p erebor-interceptor-abi -p erebor-interceptor \
  -p mithril-node -p mithril-e2e --all-targets --all-features
cargo run -p mithril-e2e --bin mithril-identity-test -- \
  --repo-root . --output-directory /tmp/mithril-identity-final verify
cargo build -p mithril-e2e --bin mithril-identity-test
sudo target/debug/mithril-identity-test --repo-root . \
  --output-directory /tmp/mithril-identity-physical \
  physical-probe \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-identity-test \
  --pin-root /sys/fs/bpf/erebor-mithril-identity-test \
  --lease-path /tmp/mithril-identity-physical/owner.lock
```

The physical runner refuses a pre-existing pin root or occupied cgroup, has a
30-second bound on every asynchronous observation, and owns every process it
creates. It moves one labeled, stopped external root to the parent cgroup and
requires a `fail_closed_unknown` coordinate plus a placement-mismatch counter
increase. It also proves external-root classification on valid cgroup movement,
native creator identity, pre-wake coordinates, exec commit, typed reference
release, and exact pinned-map reuse after restart. Descendant placement is
resolved by a bounded walk of the live kernel cgroup ancestry; there is no
userspace-scanned descendant index to synchronize. The runner creates and
removes its dedicated cgroup and pin tree; the broader matrix below still
supplies the required concurrency, failure-injection, Docker/CRI, and
Kubernetes cases before the phase may be marked Done.

Qualified VM record, 2026-08-15: the physical runner passed on Linux
`6.8.0-137-generic` with BPF object SHA-256
`94abdfa381e9f65330f21532f0d5113efe0c15814c68bdc6bd73a46e8cae4e7d`.
It moved a stopped `external_runtime_root` from its bound cgroup to the parent
cgroup. The task stayed tracked, became `fail_closed_unknown`, and increased
the placement-mismatch counter. The runner then removed its pin root, lease,
and cgroup. This is qualified evidence for `ID-CGROUP-ESCAPE-001` only. The
full matrix remains not done.

Creator-exit VM record, 2026-08-15: the physical runner passed on Linux
`6.8.0-137-generic` with BPF object SHA-256
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.
The retained result JSON has SHA-256
`1297453be1edb7339bd3d28ab43ac75604f62d2401ce7cc85e1d4da65cb5aaa3`.
The stopped child kept task cookie `44` and creator task cookie `41` after the
creator exited. Its real parent changed from `41` to `0`, and its real-parent
interval sequence changed from `1` to `2` when it executed `sleep`. The child
remained a restricted native task. The runner removed its pin root, lease, and
cgroup. This is qualified evidence for the creator-exit branch of
`ID-CREATOR-PARENT-007` only. The full matrix remains blocked.

## Procedure

1. Start the unchanged worker, legitimate controller, and all configured
   Docker, CRI, or Kubernetes initial/init/sidecar roots that apply to the run.
2. Create native children, threads, vfork children, external runtime roots,
   probes, lifecycle actions, and administrative-exec candidates with identical
   executable/argv variants.
3. Inspect task labels, process state, execution IDs, native-family state,
   entry classification, cgroup binding, and coordinate-finalization history.
4. Inject fork/exec allocation failures, concurrent exec, movement, metadata
   loss, restarts, and identifier reuse.
5. Attempt a harmless protected read from every incomplete/ambiguous task and
   inspect the fail-closed physical result.

For CRI-backed cases, omit `root_cgroup_path` from the temporary binding and
verify that the running node discovers and retires the exact container lifetime
without restart. Observing an already-running container proves conservative
external-root coverage, not pre-start initial-root admission; test the latter
only from a Created container with an empty cgroup or a separately qualified
start hook.

## Entry Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `ENTRY-BINDING-GAP-001` | delay/drop binding before first protected effect | unresolved effect denies and gap is recorded; qualified initial binding succeeds |
| `ENTRY-CONTAINERS-001` | run init, native sidecar, app, and shared-volume/network cases | independent execution sets remain distinct; declared sharing works through explicit relationships |
| `ENTRY-EPHEMERAL-001` | add an ephemeral container sharing PID namespace | new independent root/profile; shared namespace does not merge lineage |
| `ENTRY-EXEC-001` | run TTY/non-TTY `kubectl exec` and copy shape | restricted external root unless approved path completes; normal app child remains native |
| `ENTRY-EXEC-002` | run direct `docker exec` or `crictl exec` with probe-identical argv | restricted external root, never fabricated probe purpose |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | create indistinguishable external purposes concurrently | same permission intersection/restricted class; no timing/argv split |
| `ENTRY-LOSS-001` | drop runtime, audit, and entry evidence independently | protected unknown remains restricted and coverage reflects each loss |
| `ENTRY-MIGRATE-001` | use namespace-only `nsenter`, then move unlabeled/labeled tasks across protected cgroups/namespaces | namespace entry grants no workload identity; movement never grants or clears task-first authority; valid placement control remains allowed |
| `ENTRY-NETPROBE-001` | run HTTP/TCP/gRPC probes | no fake in-container process root; application receive and host flow remain distinct |
| `ENTRY-POSTSTART-001` | race `PostStart` and entrypoint in both orders | initial and external roots remain distinct |
| `ENTRY-POSTSTART-002` | restart kubelet and repeat `PostStart` | fresh task/lifetime identity with same restricted budget; no stale reuse |
| `ENTRY-PRESTOP-001` | terminate during active restriction | cleanup cannot regain authority; approved safe cleanup control follows policy |
| `ENTRY-PROBE-001` | run concurrent startup/readiness/liveness exec probes | stock purpose remains unknown/restricted; qualified evidence only if interface supplies it |
| `ENTRY-PROBE-002` | app child runs identical probe bytes/cadence | native child keeps application lineage and cannot impersonate external root |
| `ENTRY-PROBE-IMPERSONATION-003` | race native child, probe, admin, and direct runtime roots with identical argv/TTY | only native creation or complete approval changes authority; ordinary identical roots stay restricted |
| `ENTRY-RESTART-001` | restart runtime, kubelet, and node during binding | live reconciliation opens exact gaps and reuses no stale role |
| `ENTRY-REUSE-001` | reuse PID, namespace, cgroup path/ID, Pod/container name | new cookies/nonces/live intervals prevent old authority/response attachment |
| `ENTRY-SLEEP-001` | execute lifecycle sleep action | lifecycle fact only; no invented process entry when no task exists |
| `ENTRY-START-001` | delay/drop configured start-hook metadata | first unresolved protected effect denies; measured start gap remains explicit |
| `ENTRY-STOCK-HOOK-FAILURE-002` | fail/timeout/mismatch the configured stock hook | exact documented failure result; no held-task or purpose claim |

## Recorded Direct CRI Result — 2026-08-15

The K3s VM lane ran a direct `crictl exec` in the exact configured container.
The task record had no creator task cookie, `external_runtime_root` as its root
class, and `runtime_external_restricted` as its installed role. The lane also
completed its OBSERVE and PROTECT checks and removed its owned namespace,
fixture, pin root, and lane state.

Use [`examples/mithril-identity-manual/cri-exec.sh`](../../../../examples/mithril-identity-manual/cri-exec.sh)
for the readable operator procedure. This result covers one direct CRI exec.
It does not complete the full entry or failure-injection matrix.

## Native Identity Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | replay, retarget, expire, reboot, and mismatch signed authorization | every invalid envelope rejects; fresh exact envelope consumes according to contract |
| `EXEC-COMMIT-STATE-001` | run success, pre-PONR failure, and post-PONR fatal/unknown exec | success commits once; early failure keeps exact prior state; later failure never restores broad authority |
| `EXEC-CONCURRENT-002` | race execs across threads/non-leader de-threading | one serialized valid transition; no mixed image/role state |
| `ID-CGROUP-ESCAPE-001` | move a labeled task to host/unprotected placement | task storage still resolves and denies mismatch; unmoved allowed control works |
| `ID-CLONE-CGROUP-002` | clone into expected and changed placement | child state exists before effect and placement is verified |
| `ID-CLONE-CGROUP-FAIL-003` | force child allocation/finalization/placement failure | no unlabeled runnable child gains authority; normal clone succeeds |
| `ID-CREATOR-PARENT-007` | reparent/orphan child after native creation. Use [`native-child.sh --orphan`](../../../../examples/mithril-identity-manual/native-child.sh) for the creator-exit branch. | immutable creator edge stays exact while real-parent interval changes. The creator-exit branch does not cover double forks, subreapers, namespace-init reparenting, ptrace reparenting, or PID reuse. |
| `ID-MOVED-PARENT-FORK-004` | move parent, then fork | child inherits actual task authority and placement floor, not cgroup-derived role |
| `ID-MOVED-TASK-EXEC-005` | move labeled task, then exec | task-first old identity and placement mismatch constrain transition |
| `ID-TASK-COORD-FINALIZE-006` | inspect task at allocation, pre-wake finalization, visibility, and exit | opaque state precedes effect; PID/TGID/start coordinates finalize later without granting permission |
| `NATIVE-STATE-REF-LIFETIME-001` | exit tasks/processes while sockets/objects/generations remain referenced | exact references/tombstones retain restrictions until final qualified release |
| `STATE-FORK-IPC-002` | fork with inherited IPC/file/socket state | native state inheritance is exact; communication does not merge independent roots |
| `STATE-THREAD-RACE-001` | race threads changing/using process and native restrictions | atomic monotonic result; no thread recovers earlier authority |

## Administrative Identity Partial Gate

Run the identity half of `ADMIN-EXEC-APPROVAL-001`: target node/container,
entry class, optional claim-slot identity, expiry, and replay state must bind.
Do not mark the fixture complete until Phase 4 proves Control approval,
admission, atomic consumption, exec commit, and physical effect behavior.

## Required Artifacts And Pass Rule

Retain per-task state traces, coordinate histories, entry/runtime facts,
authorization verification, cgroup/runtime manifests, failure injection logs,
and first-effect syscall results. Pass requires exact or conservative state
before every protected effect and zero command/timing/TTY-based role grants.
Each shell implementation removes every task, pin, lease, state, config, and
log it creates. An operator who needs retained qualification evidence must copy
or pipe selected output to an explicitly owned location outside the test paths.

## Troubleshooting

- Missing PID fields at `task_alloc` are expected; missing preallocated
  fail-closed state is not.
- A task visible before coordinate finalization remains restricted; do not
  repair authority from userspace PID lookup.
- If stock CRI omits purpose, preserve `UNKNOWN` rather than adding heuristics.
