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

Double-fork VM record, 2026-08-15: the isolated physical probe ran at source
commit `2f3dad0081377651a8d2b52ca9479439ac7176b0`. The identity, BPF, and
inspector paths were unchanged from
`6190ca75641cb73d585712e2900afb520576db26`, which added this fixture. On
Linux `6.8.0-137-generic`, it used BPF object SHA-256
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`. The
result JSON has SHA-256
`e69b94754c479ceeddaf55d847b4d89d870793cf30d5a0139eead12fc28c4f64`.
The outer root had task cookie `57`, the intermediate native child had task
cookie `60`, and the stopped grandchild had task cookie `66`. Before the
intermediate exited, the grandchild creator and real parent were `60` and its
real-parent interval was `1`. After the intermediate exited and the grandchild
executed `sleep`, the grandchild kept task cookie `66` and creator `60`, while
its real parent became `0` and its interval became `2`. The probe removed its
pin root, lease, and cgroup, and `profile_task_refs_after_exit` was `0`. This
is qualified evidence for the double-fork branch of
`ID-CREATOR-PARENT-007` only. It does not cover subreapers, namespace-init or
ptrace reparenting, or PID reuse. The phase remains **Blocked**.

Moved-parent fork VM record, 2026-08-15: the isolated physical probe passed
at source commit `bd48b5a474273510c92611fa90285632883d13cb`. The copied
`mithril-identity-test` binary SHA-256 was
`5bf7300dc74ff6792727210a3d4907dfb50cf1fe32ca855ab40f2db815c288d1`. The
result JSON is
`/tmp/mithril-phase2-moved-parent-bd48b5a47427/identity-physical-probe.json`.
Its SHA-256 is
`82a525950ccf1a78d8be29307f2cf479eb28901a016d48e9404bdece982f3216`.

The repaired normal native child had task cookie `28`. Its active execution
changed from `0000000000000001000000000000001d` to
`00000000000000010000000000000023`. Its image provenance changed from
`0000000000000001000000000000001b` to
`00000000000000010000000000000024`. Both snapshots were active and the final
exec guard was none.

The runner moved its labeled parent into the parent cgroup, observed the
fail-closed state, and resumed it. The ordinary `fork` exited with `EACCES`.
The fixture rejected a visible child. The runner also required a second
placement-mismatch increment. The JSON records
`moved_parent_fork_denied=true` and
`cgroup_escape_placement_mismatch_detected=true`.

The JSON records `map_ids_stable_across_restart=true`,
`profile_task_refs_after_exit=0`, and
`live_manifest_mismatch_detected=true`. Its pin-root, lease, and cgroup cleanup
fields are true. Postflight found those dedicated paths absent.

This qualifies `ID-MOVED-PARENT-FORK-004` only. A readable manual script was
not added. It cannot reproduce the fixture-controlled cgroup move without
creating a separate runtime. The phase remains **Blocked**.

Moved-native-task exec VM record, 2026-08-15: the isolated physical probe
passed at source commit `0c25e8c84a94d4a632e1f44efd50befbbe37f420`. The copied
`mithril-identity-test` binary SHA-256 was
`ab212876b1cca4a38255a64a09b0c56c0831bef513b11ce6dc12a19b83c56404`. The
preserved result JSON is
`/tmp/mithril-phase2-moved-task-0c25e8c84a94-39721.identity-physical-probe.json`.
Its SHA-256 is
`dc116ae01389e131232f8d3c0d850b23f716cfed9309c338edaea5077cb0a854`.

The JSON has schema version `4` and `moved_task_exec_denied=true`. The normal
native child kept its task cookie across exec, changed its active execution
and image provenance IDs, and ended Runnable with no exec guard. The runner
moved only the stopped labeled child to the parent cgroup and required
`FailClosedUnknown` before release. It then required a second
placement-mismatch increase and a nonzero outer-shell exit before five
seconds. A child that executes `sleep` cannot pass that oracle.

The JSON records `pin_root_removed=true`, `lease_removed=true`, and
`cgroup_removed=true`. Postflight found the primary, alternate, and retired
pin roots, the cgroup, lease, and lane root absent. Only the unrelated tracing
BPF link remained. This is qualified physical evidence for
`ID-MOVED-TASK-EXEC-005` only. Use
[`native-child.sh --moved-exec`](../../../../examples/mithril-identity-manual/native-child.sh)
for the readable operator procedure. The full matrix remains unqualified, and
the phase remains **Blocked**.

`ENTRY-MIGRATE-001` host-task cgroup-entry VM subcase, 2026-08-15: the
moved-native-task JSON above also records one physical identity result. The
probe ran at source commit `0c25e8c84a94d4a632e1f44efd50befbbe37f420`, which
contains `5d5518e95350b364bc6bb5da58d3e0c13ea561d5`. It starts a host shell
outside the configured cgroup, then moves that PID into the configured cgroup.
The result requires `creator_task_cookie=null`, `external_runtime_root`,
`runtime_external_restricted`, the configured external role, and `Runnable`.

[`nsenter-move.sh`](../../../../examples/mithril-identity-manual/nsenter-move.sh)
requires the operator to enter the `nsenter` helper PID and its only direct
`sleep 300` child PID. The script verifies the child command, target mount,
UTS, IPC, network, and PID namespaces, and the exact no-identity inspector
result before it moves the child. It then checks the same external role and
`Runnable` state after cgroup movement. The script did not run in this VM
record. This record does not test namespace entry, restore, or a protected
effect. It is not complete `ENTRY-MIGRATE-001` qualification. The phase
remains **Blocked**.

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

## Recorded Non-TTY Kubernetes Exec Identity Subcase — 2026-08-15

The same retained K3s CRI lane ran at source
`e38a117b1d2a3bb2f3e1947483c1f4f61f7fd43e`. Its staged guest script SHA-256
was `380fd7c73d33aefc320ff7919160db38c29be7d06b59f6dc51dd5b715fcf4018`.
It ran `kubectl exec ... -- sh -c ...` without `-i`, `-t`, or `--tty`. The
staged script required `creator_task_cookie=null`, `external_runtime_root`,
and `runtime_external_restricted` before it accepted the task.

The `OBSERVE` artifact
`/tmp/mithril-phase3-direct-cri-evidence.eWjKKw/observe-clean.txt` has SHA-256
`c6cdd686dde59b84fa362b1c3e4e3d8e839bac44339081b8611cfc985057b994` and
records task cookie `80`. The `PROTECT` artifact
`/tmp/mithril-phase3-direct-cri-evidence.eWjKKw/protect-clean.txt` has SHA-256
`a3a5a16e8abc67e0d919b4650c62e0a1ce75c0df206c96028d93c8790351f8ab` and
also records task cookie `80`. Phase 3 recorded clean lane postflight. This
record reuses that evidence; it does not run another VM case.

Use [`kubernetes-exec.sh`](../../../../examples/mithril-identity-manual/kubernetes-exec.sh)
for the readable non-TTY operator procedure. It was not run in this retained
lane. This result covers one non-TTY `kubectl exec` identity subcase of
`ENTRY-EXEC-001`. It excludes TTY execution, copy-shaped execution, and a
native application child with the identical command. The phase remains
**Blocked**.

## Recorded Pre-PONR Failed Native-Exec VM Subcase — 2026-08-15

The isolated identity probe passed at source commit
`af685cd6a8dd73f22bd44234b3346298dd04dcd1`. The copied
`mithril-identity-test` binary SHA-256 was
`b23d8be165d9b88532dcd15db1905233134a86a2be8f7f40042e508a302c49a0`.
The schema-5 result JSON is
`/tmp/mithril-phase2-preponr-af685cd.9897yN/identity-physical-probe.json`.
Its SHA-256 is
`8a57d0a43b7fe505da68f0644237720e8419145a942ae9173ab643b1c8c6cf45`.

The runner stopped a native Bash child before it read the baseline. It required
no `pending_execs` entry, then caused an ELF loader failure after exec
preparation and before the point of no return. The JSON records
`pre_ponr_failed_exec_restored=true`. The before and post-failure snapshots
both had task cookie `44`, creator and real-parent cookie `41`, process state
`00000000000000010000000000000030`, active execution
`00000000000000010000000000000033`, image provenance
`00000000000000010000000000000034`, and active role `11`. Both process
execution and process-state vector states were active, and both exec guards
were none.

The later normal exec kept task cookie `44`, creator and real-parent cookie
`41`, process state `00000000000000010000000000000030`, and active role
`11`. It changed active execution to
`00000000000000010000000000000039` and image provenance to
`0000000000000001000000000000003a`. Its process execution and process-state
vector were active, and its exec guard was none. The JSON also records
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`profile_task_refs_after_exit=0`. Postflight found the run staging root absent.
Only the unrelated tracing BPF link remained.

Use [`native-child.sh --failed-exec`](../../../../examples/mithril-identity-manual/native-child.sh)
for the readable companion procedure. It requires `/bin/bash`, `python3`, and
a dynamically linked `/bin/true` in the selected workload.

This is one pre-PONR recovery subcase of `EXEC-COMMIT-STATE-001`. It does not
test post-PONR fatal or unknown handling, concurrent or non-leader exec, or the
complete fixture. The phase remains **Blocked**.

## Manual VM update — 2026-08-17

The retained manual VM ran
[`native-child.sh --thread-exec`](../../../../examples/mithril-identity-manual/native-child.sh).
The script created and removed its own Python Pod, live CRI binding, and
fixture. It printed `PASS`. The non-leader thread exec kept its process and
role identity. It changed execution and image identity. This is one serial
non-leader de-threading case. It does not prove concurrent exec races. The
phase remains **Blocked**.

## Entry-Migration Manual VM Result — 2026-08-17

At source commit `e6352f8`, the retained x86_64 Ubuntu 24.04 VM ran this exact
root-shell command:

```sh
examples/mithril-identity-manual/nsenter-move.sh
```

The shell SHA-256 was
`871f3dc975a31cf423a97296462581a16a224d16650270ca59f962ffdbb5adec`.
The shell used `identity_prepare_k3s_case`. It created its own Pod and exact
CRI binding. It started a namespace-only `sleep 300` child and confirmed that
the child had no Mithril task identity before cgroup movement. After movement,
the child had no creator task cookie, `external_runtime_root`,
`runtime_external_restricted`, active role `2`, and coordinate state `3`
(`Runnable`). The shell printed `PASS`.

The same VM ran `mithril-identity-test physical-probe` with unique paths. Its
JSON file was
`/tmp/mithril-phase2-entry-auto.KoZvGP/identity-physical-probe.json`, SHA-256
`91990138176e69b729f043b3f9e349fffa259f6bf36e9edbfdfd53405722ac2b`.
The runner used `CloneIntoCgroupFixture`. It recorded restricted external
roots for its host-entry control and its direct `CLONE_INTO_CGROUP` root. It
recorded `pin_root_removed=true`, `lease_removed=true`,
`cgroup_removed=true`, and `profile_task_refs_after_exit=0`.

Postflight found no case namespace, fixture directory, Mithril pin, node
process, lease, or cgroup. This result qualifies the namespace-entry and
cgroup-move subcase only. It does not prove a protected effect, an already
labeled task that crosses a namespace boundary, restore, or complete
`ENTRY-MIGRATE-001`. The phase remains **Blocked**.

## Native Identity Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | replay, retarget, expire, reboot, and mismatch signed authorization | every invalid envelope rejects; fresh exact envelope consumes according to contract |
| `EXEC-COMMIT-STATE-001` | run success, pre-PONR failure, and post-PONR fatal/unknown exec | success commits once; early failure keeps exact prior state; later failure never restores broad authority |
| `EXEC-CONCURRENT-002` | race execs across threads/non-leader de-threading | one serial non-leader de-threading case passed. Concurrent races remain required. |
| `ID-CGROUP-ESCAPE-001` | move a labeled task to host/unprotected placement | task storage still resolves and denies mismatch; unmoved allowed control works |
| `ID-CLONE-CGROUP-002` | clone into expected and changed placement | child state exists before effect and placement is verified |
| `ID-CLONE-CGROUP-FAIL-003` | force child allocation/finalization/placement failure | no unlabeled runnable child gains authority; normal clone succeeds |
| `ID-CREATOR-PARENT-007` | reparent or orphan a child after native creation. Use [`native-child.sh --orphan`](../../../../examples/mithril-identity-manual/native-child.sh) for creator exit and [`native-child.sh --double-fork`](../../../../examples/mithril-identity-manual/native-child.sh) for double fork. | immutable creator edge stays exact while the real-parent interval changes. The qualified branches do not cover subreapers, namespace-init reparenting, ptrace reparenting, or PID reuse. |
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
