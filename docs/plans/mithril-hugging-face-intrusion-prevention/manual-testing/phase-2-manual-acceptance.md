# How To Manually Accept Phase 2

Status: The current source passed the automated privileged VM identity probe
and its Kubernetes entry extension. Direct CRI exec, non-TTY and TTY
`kubectl exec`, `kubectl cp`, the identical native-child control, lifecycle
sleep, and HTTP, TCP, and gRPC readiness probes passed as self-contained
operator cases. Init, native-sidecar, and application container identity also
passed. A targeted ephemeral container kept a separate identity tree while it
shared the application PID namespace. The VM used the K3s distribution. The
full fixture matrix is not recorded.

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

## Recorded Live-Binding-Gap Qualification — 2026-08-17

The retained Ubuntu 24.04 VM ran this root-shell command after
`manual.sh start` and `manual.sh ssh`:

```sh
examples/mithril-identity-manual/binding-gap.sh
```

The shell used `identity_prepare_k3s_case` to create the Pod and live CRI
binding input. Before `identity_start_node`, it moved one waiting host process
into the target cgroup. The inspected process had no creator task cookie,
`restored_or_unknown_root`, `fail_closed_unknown`, external role `2`, and
`Runnable` coordinate state `3`. A later waiting host process in the same
cgroup had `external_runtime_root` and `runtime_external_restricted`.

The shell printed `PASS`. Its owned cleanup verified that the exact Pod cgroup
was absent. Postflight also found no case namespace, fixture directory,
Mithril pin, node process, lease work directory, or manual work directory.
This qualifies `ENTRY-BINDING-GAP-001` only. It does not qualify the remaining
entry fixtures. The phase remains **Blocked**.

## Recorded External-Root-Ambiguity Qualification — 2026-08-17

The retained Ubuntu 24.04 VM ran this root-shell command after
`manual.sh start` and `manual.sh ssh`:

```sh
examples/mithril-identity-manual/external-ambiguity.sh
```

The shell used `identity_prepare_k3s_case`, started Mithril, and then moved
two waiting host processes with the same command into the live Pod cgroup.
Each inspected task had no creator, `external_runtime_root`,
`runtime_external_restricted`, and coordinate state `3`. Their task cookies
and process-state IDs differed. Their active role IDs were equal to the
configured external role.

The shell printed `PASS`. Its owned cleanup verified that the exact Pod cgroup
was absent. Postflight found no case namespace, fixture directory, Mithril
pin, node process, lease work directory, or manual work directory. This
qualifies `ENTRY-EXTERNAL-AMBIGUITY-001` only. It does not qualify the
remaining entry fixtures. The phase remains **Blocked**.

## Recorded Cgroup-Escape Qualification — 2026-08-17

The retained Ubuntu 24.04 VM ran this root-shell command after `manual.sh
start` and `manual.sh ssh`:

```sh
examples/mithril-identity-manual/cgroup-escape.sh
```

The shell used `identity_prepare_k3s_case` and a live Python process that had
already installed its `SIGUSR1` open handler. It moved the process into the
live Pod cgroup and required no creator, `external_runtime_root`,
`runtime_external_restricted`, the configured external role, and coordinate
state `3`. The control received `SIGUSR1` and opened the sentinel.

The shell started a second prepared root, saved its task cookie and process
state, stopped it, and moved it to `/sys/fs/cgroup/cgroup.procs`. It required
the same task cookie, process state, configured external role, root class,
restricted role class, and coordinate state `6`. It queued `SIGUSR1`, resumed
the root, and required exit status `13` (`EACCES`). The shell printed `PASS`.

The matching schema-12 physical JSON has SHA-256
`c0605bf353ec6c67c906ae3f34fc872254c509e08ab16daebe6cfeceac50c460`.
It records task cookie `214`, role `11`, and runnable coordinate `3` for the
unmoved control. It records task cookie `221`, role `11`, and fail-closed
coordinate `6` for the moved root. It records an allowed unmoved first effect,
a placement mismatch, and a denied moved first effect. The runner removed its
pin, lease, and cgroup. The shell cleanup and postflight found no case
namespace, fixture directory, Mithril pin, node process, lease work directory,
manual work directory, or case cgroup.

This qualifies `ID-CGROUP-ESCAPE-001` only. The remaining required rows are
open. The phase remains **Blocked**.

## Recorded Clone-Into-Cgroup Native-Child First Effect — 2026-08-17

The retained Ubuntu 24.04 VM ran `manual.sh start`, then `manual.sh ssh`. As
root, it ran the schema-13 `mithril-identity-test physical-probe` with unique
output, pin, lease, and cgroup paths ending in
`mithril-phase2-clone-first-effect-20260817-1706`. The copied JSON is
`/tmp/mithril-phase2-clone-first-effect-20260817-1706.json`. Its SHA-256 is
`d690be264034dad636dd64e97e4830ae24b0a11f0ed5077dc525da303069fd44`.

The stopped `CLONE_INTO_CGROUP` root had task cookie `228`, process state
`000000000000000100000000000000e2`, no creator, restricted external-root
classes, role `11`, and coordinate `3`. The stopped native child had task
cookie `231`, process state `000000000000000100000000000000eb`, creator and
real-parent cookie `228`, role `11`, no root or installed-role class,
coordinate `3`, and active process records. The fixture released that child
through its pidfd. `clone_into_cgroup_native_child_first_effect_allowed=true`
records the direct sentinel open.

No manual shell ran for this row. A shell cannot own the exact
`CLONE_INTO_CGROUP` file descriptor, stopped root and child, pidfd release,
and status pipe without adding another fixture runner. The runner removed its
pin, lease, and cgroup. Postflight found no case namespace, fixture, Mithril
pin, node process, lease, or cgroup. This qualifies
`ID-CLONE-CGROUP-002` only. The remaining required rows are open. The phase
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
| `ENTRY-BINDING-GAP-001` | delay/drop binding before root reconciliation | unresolved root stays fail closed; later qualified binding creates a restricted external root |
| `ENTRY-CONTAINERS-001` | run init, native sidecar, and app containers | independent roots and execution sets remain distinct; later phases own shared-resource relationships |
| `ENTRY-EPHEMERAL-001` | add an ephemeral container sharing PID namespace | new independent root/profile; shared namespace does not merge lineage |
| `ENTRY-EXEC-001` | run TTY/non-TTY `kubectl exec`, `kubectl cp`, and an identical native child | ordinary exec/copy roots stay restricted external; the app child stays native; Phase 4 owns approved administrative exec |
| `ENTRY-EXEC-002` | run direct `docker exec` or `crictl exec` with probe-identical argv | restricted external root, never fabricated probe purpose |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | create indistinguishable external purposes concurrently | same permission intersection/restricted class; no timing/argv split |
| `ENTRY-LOSS-001` | drop runtime, audit, and entry evidence independently | protected unknown remains restricted and coverage reflects each loss; later phases own effect results |
| `ENTRY-NETPROBE-001` | run HTTP/TCP/gRPC probes | no fake in-container process root; later network fixtures own flow policy |
| `ENTRY-POSTSTART-001` | race `PostStart` and entrypoint in both orders | initial and external roots remain distinct |
| `ENTRY-POSTSTART-002` | keep one real hook in flight across kubelet restart, then repeat the live Pod's exact hook command through CRI | fresh task/lifetime identity with the same restricted budget; no stale reuse; do not require or claim automatic kubelet resend |
| `ENTRY-PRESTOP-001` | terminate while a restricted root is active | termination does not change identity or release required native references; Phase 4 owns containment policy |
| `ENTRY-PROBE-001` | run concurrent startup/readiness/liveness exec probes | stock purpose remains unknown/restricted; qualified evidence only if interface supplies it |
| `ENTRY-PROBE-002` | app child runs identical probe bytes/cadence | native child keeps application lineage and cannot impersonate external root |
| `ENTRY-PROBE-IMPERSONATION-003` | race native child, stock probe, ordinary `kubectl exec`, and direct CRI exec with identical argv/TTY | the child stays native and every independent stock/runtime root stays restricted; Phase 4 owns approved-role transition |
| `ENTRY-RESTART-001` | restart the Kubernetes service and node during discovery and binding | the runtime gap is unhealthy, node observation is unavailable while the node is down, and the live task keeps its exact identity after both recoveries |
| `ENTRY-REUSE-001` | reuse PID, namespace, cgroup path/ID, Pod/container name | new cookies/nonces/live intervals prevent old authority/response attachment |
| `ENTRY-SLEEP-001` | execute lifecycle sleep action | lifecycle fact only; no invented process entry when no task exists |
| `ENTRY-START-001` | delay/drop configured start metadata | root identity stays conservative and the measured start gap remains explicit; Phase 4 owns effect denial |
| `ENTRY-STOCK-HOOK-FAILURE-002` | fail/timeout/mismatch the configured stock hook | exact documented failure result; no held-task or purpose claim |

## Recorded Kubernetes Entry Results — 2026-08-17

Source commit `da01f77d2deb83482788f16081307b01a6dc6556` ran in one
disposable x86_64 Ubuntu 24.04 VM on kernel `6.8.0-137-generic`. Kubernetes
`v1.35.5` ran through the K3s `v1.35.5+k3s1` distribution. The automated
runner used
[`kubernetes-entry-workload-v1.yaml`](../../../../crates/mithril-e2e/fixtures/identity/kubernetes-entry-workload-v1.yaml),
whose SHA-256 is
`3a8d0108982c07a5a3ecd7bd6a66e187d0539fa80a63399c53a4f6c606747d54`.
It created the Namespace and Pod, read exact live CRI and cgroup identity,
published the binding, and used the existing `IdentityTestRunner` owner.

The schema-14 JSON is
`/tmp/mithril-kubernetes-entry-20260817-021/identity-physical-probe.json`.
Its SHA-256 is
`aa70c2c398c6d07d138b81293103f3cbfc4be91d2c8999387b893ff7cac92910`.
The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The pre-existing Pod root had no creator, `restored_or_unknown_root`, and
`fail_closed_unknown`. Direct CRI exec and non-TTY `kubectl exec` each had no
creator, `external_runtime_root`, `runtime_external_restricted`, and active
role `11`. Their task cookies were distinct.

The retained manual VM then ran these root-shell commands consecutively:

```sh
examples/mithril-identity-manual/cri-exec.sh
examples/mithril-identity-manual/kubernetes-exec.sh
```

The direct CRI shell SHA-256 is
`b5ed7eaa6f6512b2e6e20df34bc0e2a50d3a654b57c9a8c4c5098a8de9c866d7`.
The non-TTY Kubernetes exec shell SHA-256 is
`f03e4bd2d79751193fb024c599084d405f5c10e79b63f362cc23809bd3641faa`.
Each shell created its own Namespace, Pod, CRI binding, node, pin, lease, and
fixture, then printed `PASS`. After both cases, no case Namespace, fixture,
Mithril process, pin, lease, cgroup, or loaded Erebor Interceptor program
remained. `manual.sh destroy` removed the VM, and `virsh list --all --name`
was empty.

This completes `ENTRY-EXEC-002`. It completes only the non-TTY subcase of
`ENTRY-EXEC-001`. TTY exec, `kubectl cp`, and an application-native child with
the same command remain open. Phase 4 owns the stronger approved
administrative role. Phase 2 remains **Blocked**.

## Recorded Kubernetes Exec Closure — 2026-08-18

Source commit `53fbd287aad8b6012eb4f80dcd4fe83e34ed5470` extends the
existing `IdentityTestRunner` and physical JSON bundle. It adds no BPF map,
role, runner, or durable type. The retained x86_64 Ubuntu 24.04 VM ran kernel
`6.8.0-137-generic`. Kubernetes `v1.35.5` ran through the K3s
`v1.35.5+k3s1` distribution and the live containerd CRI endpoint.

The root shell ran the automated Kubernetes extension with unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-kubernetes-entry-exec-20260818-025 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-kubernetes-entry-exec-025 \
  --lease-path /var/tmp/mithril-kubernetes-entry-exec-20260818-025/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-kubernetes-entry-exec-025 \
  --with-kubernetes \
  --previous-bundle /var/tmp/identity-native-schema15-023.json
```

The schema-15 JSON is
`/tmp/mithril-phase2-kubernetes-entry-exec-20260818-025/identity-physical-probe.json`.
Its SHA-256 is
`ef749b5a6d2521c6bd865317ce3843bf685610d009500f6d37569c9bd26a57cc`.
The input native bundle SHA-256 is
`8ac4bf32a0851360223b8c038bf86a7fdaca13e2314908eaa956927715af0688`.
The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The automated workload manifest SHA-256 is
`6acba20b7b171c35a7140491aa87cf9e36530fc85c3a6abaee3aff4eda73cc95`.

The non-TTY, TTY, and copy tasks had task cookies `71`, `123`, and `175`.
Each had no creator, `external_runtime_root`,
`runtime_external_restricted`, and active role `11`. The copy fixture also
required the exact source bytes at the destination. The native parent had
task cookie `230`, no creator, the same external classes, and role `11`. Its
child had task cookie `271`, creator and real-parent cookie `230`, no root or
installed-role class, and role `11`. The JSON records
`kubernetes_fixture_removed=true`.

The retained VM then ran these commands consecutively as root:

```sh
examples/mithril-identity-manual/kubernetes-exec-tty.sh
examples/mithril-identity-manual/kubernetes-copy.sh
examples/mithril-identity-manual/kubernetes-native-child.sh
```

The shell SHA-256 values, in command order, are
`d5e97f6f0335bfe3e8515045ed9ae1d4e9c2125642080d390f983ab3a4c64415`,
`d4eecdaacdf918d5637632c7b6e2330109653668a90b4caed5080a8c713473ad`,
and
`89d10a01b104c4f5d2bffaee572ccf30d4469ea05ba13af04c7460d4fe469a14`.
All three shells printed `PASS`. Postflight found no case Namespace, fixture,
Mithril pin, node process, lease, cgroup, or loaded Erebor Interceptor program.
`manual.sh destroy` removed the VM. `virsh list --all --name` was empty.

Three rejected disposable runs are not acceptance evidence. Run `022` timed
out at the unchanged native reference-release check. Run `023` passed the
native probe, then exposed a stale marker between non-TTY and TTY exec. The
runner now deletes that marker and its release file before it starts TTY exec.
Run `024` timed out at the unchanged PID-namespace intermediate identity
check before it started Kubernetes. The passing Kubernetes-only run used the
schema-15 native bundle from run `023`; no failed Kubernetes output was used.

`cargo test -p mithril-e2e
production_object_and_identity_fixture_allocation_are_exact` passed.
`cargo clippy -p mithril-e2e --all-targets -- -D warnings` passed.
The final `bash .github/scripts/verify-rust-ci.sh` passed with exit status `0`.

This completes `ENTRY-EXEC-001`. The exact limit is ordinary runtime entry
identity only. Phase 4 owns approved administrative exec and its permission
transition. Other open matrix rows keep Phase 2 **Blocked**.

The same automated and manual runs also complete `ENTRY-START-001`. The Pod
and its startup barrier existed before Mithril started. After live CRI
discovery and binding, PID 1 had task cookie `5`, no creator,
`restored_or_unknown_root`, `fail_closed_unknown`, and active role `11`.
Each recorded manual shell called `identity_wait_for_initial_binding` before
it started a later entry. The exact limit is a measured late-discovery gap and
conservative identity. This result does not claim that Mithril observed the
first user instruction. Phase 4 owns the effect result during that gap.

## Recorded Kubernetes Lifecycle Sleep Result — 2026-08-18

Source commit `828fdec76c5753790c526d87e6757fde6134002e` contains the
exact runner, manifest, runtime helper, and manual shell used for this result.
It extends the existing `IdentityTestRunner` and physical JSON bundle. It adds
no BPF map, role, runner, or durable type. The retained x86_64 Ubuntu 24.04 VM
ran kernel `6.8.0-137-generic`. Kubernetes `v1.35.5` ran through the K3s
`v1.35.5+k3s1` distribution and the live containerd CRI endpoint.

The root shell ran the automated Kubernetes extension with unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-kubernetes-sleep-20260818-029 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-kubernetes-sleep-029 \
  --lease-path /var/tmp/mithril-kubernetes-sleep-20260818-029/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-kubernetes-sleep-029 \
  --with-kubernetes \
  --previous-bundle /var/tmp/identity-kubernetes-schema15-025.json
```

The schema-16 JSON is
`/tmp/mithril-phase2-kubernetes-sleep-20260818-029/identity-physical-probe.json`.
Its SHA-256 is
`a62e82352a3153c65895d69265e4e0265d78ec6a76679e50a7d1f0bbcc2804fb`.
It records `kubernetes_lifecycle_sleep_no_task=true` and
`kubernetes_fixture_removed=true`. The BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The lifecycle workload manifest SHA-256 is
`16e149155ff79321724087d5fd73bce8e7cca60934218f49370745118631d18b`.

The fixture created a real Pod with a 30-second native Kubernetes lifecycle
`sleep` action. While the Pod was not Ready, the runner resolved the exact
live container through CRI. The container cgroup contained only its init PID.
The runner then required the Pod to become Ready and removed its Namespace and
fixture directory.

The retained VM then ran this command as root from the committed source:

```sh
examples/mithril-identity-manual/kubernetes-lifecycle-sleep.sh
```

The shell SHA-256 is
`f07fb345559b7af8177e16d14acf455dd11796c8232f3953f7ca3fa5edc01afc`.
The shared runtime helper SHA-256 is
`f60b907f5bd31ef54a884e909e3c1087b72afa352f6e0751ab3274d41d9b584e`.
The shell printed container init PID `3410` and only task `3410` in the live
container cgroup. It then printed `PASS`. Postflight found no case Namespace,
fixture, pin, lease, cgroup, node process, or loaded Erebor Interceptor
program. `manual.sh destroy` removed the VM, and `virsh list --all` was empty.

Runs `026` and `027` are rejected results. Run `026` exposed an invalid
termination-grace setting. Run `027` exposed an incorrect CRI name filter.
The leaked run-`026` Namespace was removed before the accepted run. Run `028`
passed before the final cleanup-ownership change and is not the acceptance
artifact. Run `029` is the accepted automated result.

`cargo test -p mithril-e2e
production_object_and_identity_fixture_allocation_are_exact` passed.
`cargo clippy -p mithril-e2e --all-targets -- -D warnings` passed.
`bash crates/mithril-e2e/harness/vm/test.sh` passed. The final
`bash .github/scripts/verify-rust-ci.sh` passed with exit status `0` when the
local socket tests ran with host permission.

This completes `ENTRY-SLEEP-001`. The exact limit is the native Kubernetes
lifecycle `sleep` action: it created no extra in-container task. This result
does not qualify exec probes, network probes, purpose, role, or policy. Other
open matrix rows keep Phase 2 **Blocked**.

## Recorded Kubernetes Network-Probe Result — 2026-08-18

Source commit `f9b7c8bc2be84f2a39f3db7b43dae3ab1914c0d0` contains the
exact runner, manifest, runtime helper, and manual shell used for this result.
It extends the existing `IdentityTestRunner` and physical JSON bundle. It adds
no BPF map, role, runner, or durable type. The retained x86_64 Ubuntu 24.04 VM
ran kernel `6.8.0-137-generic`. Kubernetes `v1.35.5` ran through the K3s
`v1.35.5+k3s1` distribution and the live containerd CRI endpoint.

The root shell ran the automated Kubernetes extension with unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-kubernetes-network-20260818-033 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-kubernetes-network-033 \
  --lease-path /var/tmp/mithril-kubernetes-network-20260818-033/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-kubernetes-network-033 \
  --with-kubernetes \
  --previous-bundle /var/tmp/identity-kubernetes-schema16-029.json
```

The schema-17 JSON is
`/tmp/mithril-phase2-kubernetes-network-20260818-033/identity-physical-probe.json`.
Its SHA-256 is
`cbc024f56ce366a84aa2b0ffdbb7efaab58599b282d1f24295f30c08702fac07`.
It records `kubernetes_http_probe_no_task=true`,
`kubernetes_tcp_probe_no_task=true`,
`kubernetes_grpc_probe_no_task=true`, and
`kubernetes_fixture_removed=true`. The test binary SHA-256 is
`2268462584fb2f4b844c236aa7d46edce0019beb75e6960d56934af7b1df9132`.
The unchanged BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The network-probe workload manifest SHA-256 is
`1c3ed281dad293132deaf38e63a1a1304281d79d6b11252816c3c0a78bcd159f`.

The fixture created one real Pod with HTTP, TCP, and gRPC readiness probes.
All three containers became Ready without a restart. The runner then resolved
each exact live container through CRI and sampled its cgroup every 10 ms for
four seconds. Each sample contained only the CRI-reported container init PID.
The runner removed its Namespace and fixture directory.

The retained VM then ran this command as root from the committed source:

```sh
examples/mithril-identity-manual/kubernetes-network-probes.sh
```

The shell SHA-256 is
`51276805c3de845ab794a2616d6b539bc092c077a4592d1841b7b2d15ca6f7ec`.
The shared runtime helper SHA-256 is
`590fb65f4eca9b6576216334b1aec1179f5a0a10de7a3da63a828dc33cd2772b`.
The shell sampled each cgroup 400 times. It printed init PID and only task
`5490` for HTTP, `5523` for TCP, and `5553` for gRPC, then printed `PASS`.
Postflight found no case Namespace, fixture, pin, lease, cgroup, node process,
or loaded Erebor Interceptor program. `manual.sh destroy` removed the VM, and
`virsh list --all` was empty.

Run `030` is rejected because it used a stale test binary and stopped before
the Kubernetes case. Run `031` is rejected because the HTTP probe used
`/healthz`, which returns HTTP 412 when the fixture disables UDP. Debug case
`032` identified that manifest error and was removed. Run `033`, with HTTP
path `/`, is the accepted automated result.

`cargo test -p mithril-e2e
production_object_and_identity_fixture_allocation_are_exact` passed.
`cargo clippy -p mithril-e2e --all-targets -- -D warnings` passed.
`bash crates/mithril-e2e/harness/vm/test.sh` passed. The final
`bash .github/scripts/verify-rust-ci.sh` passed with exit status `0` when the
local socket tests ran with host permission.

This completes `ENTRY-NETPROBE-001`. The exact limit is HTTP, TCP, and gRPC
readiness probing: these probes created no extra in-container task. This
result does not qualify network flow, application receipt, purpose, role, or
policy. Other open matrix rows keep Phase 2 **Blocked**.

## Recorded Kubernetes Container-Identity Result — 2026-08-18

Source commit `6e23a23e327f70b3462faf932b0845f7e52ec67f` contains the
exact runner, manifest, inspector field, runtime helper, and manual shell used
for this result. It extends the existing `IdentityTestRunner` and physical JSON
bundle. It adds no BPF map, role, runner, or durable type. The retained x86_64
Ubuntu 24.04 VM ran kernel `6.8.0-137-generic`. Kubernetes `v1.35.5` ran
through the K3s `v1.35.5+k3s1` distribution and the live containerd CRI
endpoint.

The root shell ran the automated Kubernetes extension with unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-kubernetes-containers-20260818-034 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-kubernetes-containers-034 \
  --lease-path /var/tmp/mithril-kubernetes-containers-20260818-034/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-kubernetes-containers-034 \
  --with-kubernetes \
  --previous-bundle /var/tmp/identity-kubernetes-schema17-033.json
```

The schema-18 JSON is
`/tmp/mithril-phase2-kubernetes-containers-20260818-034/identity-physical-probe.json`.
Its SHA-256 is
`dfb7b407b8a945c474a210fb769abbc09b03599ecb271f4c27cb9d195da92ada`.
It records `kubernetes_containers_distinct_execution_sets=true` and
`kubernetes_fixture_removed=true`. The init, native-sidecar, and application
task cookies are `12`, `5`, and `19`. Their execution-set IDs end in `01`,
`02`, and `03`. Each root has `restored_or_unknown_root` and
`fail_closed_unknown`, because Mithril discovered the live container after it
started. The test binary SHA-256 is
`5deff30a4e3ae111bf8fda4c82c7264d77ffad6991106b9a4609723668723a76`.
The unchanged BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The workload manifest SHA-256 is
`ad54f35479d911221ae01653c0409d60e1f37c544381223efb859de52d04bf03`.

The fixture created one Pod. A restartable init container supplied the native
sidecar. A regular init container wrote the shared-volume marker and waited.
The runner bound and inspected both live roots, released the regular init, and
then bound and inspected the live application. All three containers used the
same Pod sandbox and mounted the same host-backed volume. Each used a separate
container cgroup, task root, process state, and configured execution set.

The retained VM then ran this command as root from the committed source:

```sh
examples/mithril-identity-manual/kubernetes-containers.sh
```

The shell SHA-256 is
`a3ae981f06fd2cb9b65f5265fbef21c3820f4dee4520526a4bc73ca7f7fd131c`.
The shared runtime helper SHA-256 is
`0c15474f35e053136ef0fb3df5e7bf0bdb5d24127d34b68e503bd46bc819c474`.
It printed task cookies `12`, `5`, and `19`, the three distinct execution-set
IDs, and `PASS`. The first manual attempt is rejected because its shell read
the init PID before runtime reconciliation completed. The accepted shell uses
a bounded identity wait and keeps the same oracle.

Postflight found only the four baseline Kubernetes Namespaces. It found no case
fixture, manual work directory, pin, lease, cgroup, node process, or loaded
Erebor Interceptor program. `manual.sh destroy` removed the VM, and
`virsh list --all` was empty.

`cargo test -p mithril-e2e
production_object_and_identity_fixture_allocation_are_exact` passed.
The focused namespace-init test passed after one unrelated timing timeout in
the first full-CI attempt. `cargo clippy -p mithril-e2e -p mithril-node
--all-targets -- -D warnings` passed. The VM shell checks passed. The final
`bash .github/scripts/verify-rust-ci.sh` passed with exit status `0` when the
local socket tests ran with host permission.

This completes `ENTRY-CONTAINERS-001`. The exact limit is identity separation:
the regular init, native sidecar, and application kept separate roots and
execution sets while sharing the Pod sandbox and volume. This result does not
qualify shared-network or shared-volume relationships or policy. Other open
matrix rows keep Phase 2 **Blocked**.

## Recorded Kubernetes Ephemeral-Identity Result — 2026-08-18

Source commit `76d0145c2ecd7991ab7160773faf452c383df6a9` freezes the
exact runner, manifest, runtime helper, and manual shell bytes used for this
result. It extends the existing `IdentityTestRunner` and physical JSON bundle.
It adds no BPF map, role, runner, or durable type. The retained x86_64 Ubuntu
24.04 VM ran kernel `6.8.0-137-generic`. Kubernetes `v1.35.5` ran through the
K3s `v1.35.5+k3s1` distribution and the live containerd CRI endpoint.

The root shell ran the automated Kubernetes extension with unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-kubernetes-ephemeral-20260818-035 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-kubernetes-ephemeral-035 \
  --lease-path /var/tmp/mithril-kubernetes-ephemeral-20260818-035/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-kubernetes-ephemeral-035 \
  --with-kubernetes \
  --previous-bundle /var/tmp/identity-kubernetes-schema18-034.json
```

The schema-19 JSON is
`/tmp/mithril-phase2-kubernetes-ephemeral-20260818-035/identity-physical-probe.json`.
Its SHA-256 is
`ee12bc57c8431ac801ae6e06e2e55dbf75ec50692b3a594785fc0d27fabf0efc`.
It records `kubernetes_ephemeral_shared_pid_namespace=true`,
`kubernetes_ephemeral_distinct_execution_set_and_profile=true`, and
`kubernetes_fixture_removed=true`. The application task has cookie `5`, an
execution-set ID ending in `01`, and profile generation reference `7`. The
ephemeral task has cookie `12`, an execution-set ID ending in `02`, and profile
generation reference `8`. Each task has a separate process state. Both tasks
have `restored_or_unknown_root` and `fail_closed_unknown` because Mithril
discovered the live containers after start.

The unchanged BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The workload manifest SHA-256 is
`44f419ca73b06353c372930000ab7a0acac7fec7dc83bba60ab2747e4e493141`.
The fixture created one Pod with `shareProcessNamespace: true`. It patched the
real `ephemeralcontainers` subresource with
`targetContainerName: application`, then verified that Kubernetes retained
that exact target. The application and debugger used the same Pod sandbox and
PID namespace but separate container cgroups.

The retained VM then ran this command as root from the same source bytes:

```sh
examples/mithril-identity-manual/kubernetes-ephemeral.sh
```

The shell SHA-256 is
`a692a39929d13654f5ea54c0ff353c01eac3ce6eadae9f138a3ed63366f3c896`.
The shared runtime helper SHA-256 is
`ef098b3a367c672a6677997155263cfda43bee293301dc6d8d9b99513abb72ce`.
It printed application task cookie `5`, ephemeral task cookie `12`, both
execution-set and profile identities, shared PID-namespace inode `4026532733`,
and `PASS`.

Postflight found only the four baseline Kubernetes Namespaces. It found no
case fixture, manual work directory, pin, lease, cgroup, node process, or
loaded Erebor Interceptor program. `manual.sh destroy` removed the VM, and
`virsh list --all` was empty. There was no rejected physical run for this
fixture.

The focused fixture-allocation test passed. `cargo clippy -p mithril-e2e
-p mithril-node --all-targets -- -D warnings` passed. The VM shell checks
passed. The final `bash .github/scripts/verify-rust-ci.sh` passed with exit
status `0` when the local socket tests ran with host permission.

This completes `ENTRY-EPHEMERAL-001`. The exact limit is identity separation:
the targeted ephemeral container kept a separate task root, process state,
execution set, and profile while it shared the application PID namespace and
Pod sandbox. This result does not qualify shared-namespace relationships or
policy. Other open matrix rows keep Phase 2 **Blocked**.

## Recorded Kubernetes Exec-Probe Identity Result — 2026-08-18

Source commit `4ca2d26bd90ad6a9cd85b7fe5e9e615a6ea4fa14` freezes the
runner, workload manifest, shared runtime helper, and operator shell used for
this result. It extends the existing `IdentityTestRunner` and physical bundle.
It adds no BPF map, role, runner, or durable type. The retained x86_64 Ubuntu
24.04 VM ran kernel `6.8.0-137-generic`. Kubernetes `v1.35.5` ran through the
K3s `v1.35.5+k3s1` distribution and the live containerd CRI endpoint.

The root shell ran the automated extension with unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-kubernetes-probes-20260818-042 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-kubernetes-probes-042 \
  --lease-path /var/tmp/mithril-kubernetes-probes-20260818-042/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-kubernetes-probes-042 \
  --with-kubernetes \
  --previous-bundle /var/tmp/identity-kubernetes-schema19-035.json
```

The schema-20 JSON is
`/tmp/mithril-phase2-kubernetes-probes-20260818-042/identity-physical-probe.json`.
Its SHA-256 is
`abead9ce84882d9ecc69853a417ef39ccd629f0df7de97e4ac0e5eebfd9190a6`.
It records `kubernetes_probe_identities_distinct=true` and
`kubernetes_fixture_removed=true`. Startup, readiness, and liveness probe task
cookies were `293`, `245`, and `187`. Their execution-set IDs end in `01`,
`02`, and `03`. The application parent and native child task cookies were `26`
and `29`; both used the application execution set ending in `04`. The
`kubectl exec` and direct CRI exec task cookies were `58` and `119`; both used
that application execution set. All seven process-state IDs were distinct.

Each stock probe, `kubectl exec`, and direct CRI exec had no creator,
`external_runtime_root`, `runtime_external_restricted`, and active role `11`.
The native child had creator and real-parent task cookie `26`, no root class,
no installed-role class, and inherited role `11`. The fixture required the
same `/bin/sh -c` command bytes for the native child, all three stock probes,
`kubectl exec`, and direct CRI exec. The six tasks remained live together
until every identity snapshot passed. Separate probe containers were required
because Kubernetes does not start readiness or liveness probes in a container
until its startup probe succeeds.

The unchanged BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The test binary SHA-256 is
`d8bb13e2b567eb1850cbcce5826bdafa5af04c734ea2b6cb7553adbcd62bc496`.
The workload manifest SHA-256 is
`7105b89a7023c2a73cd2b6863dfa9640bbc5f5db64dce926d41999f7730a25db`.
The operator shell SHA-256 is
`5f3dd3de608422cb857f5685bc03ccc4f3903f5a8be7d46577942be03584c958`.
The shared runtime helper SHA-256 is
`7ac409f970194a939b35585bb1f1240c3fe63bd51c3d1e8d3dca16e399cf9fa4`.

The retained VM then ran this command as root from the same source bytes:

```sh
examples/mithril-identity-manual/kubernetes-probe-impersonation.sh
```

It printed `PASS: identical bytes kept native lineage and every independent
entry restricted.` The shell removed its Mithril process, tasks, pins, state,
lease, configuration, logs, Namespace, and fixture. Independent postflight
found only the four baseline Kubernetes Namespaces and no case cgroup or
loaded Erebor Interceptor program. `manual.sh destroy` removed the VM, and
`virsh list --all --name` was empty.

Runs `036` through `041` were rejected. They exposed, in order, a profile and
generation mismatch in the fixture, shell PID escaping errors, a probe wait
that was shorter than the configured period, and stock probes that executed
before binding. The last case correctly produced conservative unknown roots,
not a false restricted-external pass. Run `042` delayed the probe attempts
until after binding and is the only accepted result.

The focused fixture-allocation and VM-harness tests passed. `cargo clippy -p
mithril-e2e -p mithril-node --all-targets -- -D warnings`, shell syntax checks,
and `cargo fmt --all -- --check` passed. The final
`bash .github/scripts/verify-rust-ci.sh` passed with exit status `0` when its
local socket tests ran with host permission.

This completes `ENTRY-PROBE-001`, `ENTRY-PROBE-002`, and
`ENTRY-PROBE-IMPERSONATION-003`. The exact limit is one held native invocation,
one held invocation of each stock probe type, one ordinary `kubectl exec`, and
one direct CRI exec in one concurrent interval. Stock Kubernetes supplied no
purpose, so every independent entry used the restricted external class. The
native child kept application lineage. Phase 4 owns approved-role transition.
Other open matrix rows keep Phase 2 **Blocked**.

## Recorded Kubernetes PreStop Identity Result — 2026-08-18

Source commit `098f167c88755f88acabf7f387da5095d568869d` freezes the
runner, workload manifest, shared runtime helper, and operator shell used for
this result. It extends the existing `IdentityTestRunner` and physical bundle.
It adds no BPF map, role, runner, or durable type. The retained x86_64 Ubuntu
24.04 VM ran kernel `6.8.0-137-generic`. Kubernetes `v1.35.5` ran through the
K3s `v1.35.5+k3s1` distribution and the live containerd CRI endpoint.

The root shell ran the automated extension with unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-kubernetes-prestop-20260818-044 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-kubernetes-prestop-044 \
  --lease-path /var/tmp/mithril-kubernetes-prestop-20260818-044/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-kubernetes-prestop-044 \
  --with-kubernetes \
  --previous-bundle /var/tmp/identity-kubernetes-schema20-042.json
```

The schema-21 JSON is
`/tmp/mithril-phase2-kubernetes-prestop-20260818-044/identity-physical-probe.json`.
Its SHA-256 is
`4d14142beb3671342c7c6d2c8ed8e5c9d85da730f60ef556f7783f7cd231fcee`.
The application snapshot was identical before and during termination. It had
task cookie `5`, process-state ID ending in `03`, execution-set ID ending in
`01`, `restored_or_unknown_root`, `fail_closed_unknown`, and role `11`. The
PreStop exec had task cookie `19`, a distinct process-state ID,
`external_runtime_root`, `runtime_external_restricted`, and role `11`. The
profile-generation task-reference count was exactly `2` while both tasks were
live and `0` after Pod deletion.

The unchanged BPF object SHA-256 is
`3269516fcd2714ab7fbe29df26386c40f0c912b6284007b641d8bbf68842b876`.
The test binary SHA-256 is
`7eaef40ea57c00366fffa24c0002ece3c3eca31989943a26b77b2628cde18236`.
The workload manifest SHA-256 is
`fff9364ac752dd26f08aa89afa62f90c4adec52ca488b5cc9ff9e59926c8f457`.
The operator shell SHA-256 is
`a3edd992ddfbca62f135cc2b0e0ec63052191a7bf1bc87344d88977d3f3d1917`.
The shared runtime helper SHA-256 is
`3bf7d3e51950c3143bde728aea200033c9f51588d3aaa699f3fc6cc038d4efca`.

The retained VM then ran this command as root from the same source bytes:

```sh
examples/mithril-identity-manual/kubernetes-prestop.sh
```

It printed application task `5`, PreStop task `19`, and `PASS`. The shell
removed its Mithril process, tasks, pins, state, lease, configuration, logs,
Namespace, and fixture. Independent postflight found only the four baseline
Kubernetes Namespaces and no case cgroup or loaded Erebor Interceptor program.
`manual.sh destroy` removed the VM, and `virsh list --all --name` was empty.

Run `043` is rejected because the VM command used a stale schema-20 binary and
returned its input unchanged. The executable was rebuilt and checked for the
PreStop fixture path before accepted run `044`.

The focused fixture-allocation and VM-harness tests passed. `cargo clippy -p
mithril-e2e -p mithril-node --all-targets -- -D warnings`, shell syntax checks,
and `cargo fmt --all -- --check` passed. The final
`bash .github/scripts/verify-rust-ci.sh` passed with exit status `0` when its
local socket tests ran with host permission.

This completes `ENTRY-PRESTOP-001`. The exact limit is identity and reference
retention during a real exec PreStop hook: termination did not alter the live
application identity or release its profile reference, and the hook received
a fresh restricted external identity. Phase 4 owns containment and effect
policy. Other open matrix rows keep Phase 2 **Blocked**.

## Recorded Kubernetes Prestart And PostStart Result — 2026-08-18

Source commit `a056f00fd7d110cc0582b6e8a476de1d1e233a59` freezes the
runner, OCI prestart hook, workload manifest, node admission path, runtime
helper, and operator shell used for this result. The implementation reuses
`IdentityTestRunner`, `WorkloadBindingOwner`, `NativeSecurityStateOwner`, and
the existing physical bundle. It adds no map, role, generic runner, or durable
type.

The retained x86_64 Ubuntu 24.04 VM ran kernel `6.8.0-137-generic`.
Kubernetes `v1.35.5` ran through K3s `v1.35.5+k3s1`, containerd
`v2.2.3-k3s1`, and the configured `io.containerd.runc.v2` handler. The root
shell first ran a fresh native base and then ran the Kubernetes extension with
unique paths:

```sh
target/debug/mithril-identity-test \
  --repo-root /mnt/mithril-source \
  --output-directory /var/tmp/mithril-poststart-native-base-20260818-5 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-poststart-native-base-20260818-5 \
  --lease-path /var/tmp/mithril-poststart-native-base-20260818-5/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-poststart-native-base-20260818-5

target/debug/mithril-identity-test \
  --repo-root /mnt/mithril-source \
  --output-directory /var/tmp/mithril-poststart-auto-20260818-5 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-poststart-auto-20260818-5 \
  --lease-path /var/tmp/mithril-poststart-auto-20260818-5/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-poststart-auto-20260818-5 \
  --with-kubernetes \
  --previous-bundle \
    /var/tmp/mithril-poststart-native-base-20260818-5/identity-physical-probe.json
```

The schema-22 JSON is
`/tmp/mithril-phase2-kubernetes-poststart-20260818-049/identity-physical-probe.json`.
Its SHA-256 is
`f7b1c44d26ad5c3b36b401d5f80e87156594dd790daf965fc65c58760e4e0dcb`.
The BPF object SHA-256 is
`02408c371aafaeeb044cbf11195a25dca35013bcdea44e37aa0756ebd2f2f3e6`.
The test binary SHA-256 is
`adcb264ac75ca077c06ea6fd7bfc6d5f0624e2f3d8f0e6042c600de12101fe74`.

The entrypoint-first application and hook had task cookies `5` and `150`.
The hook-first application and hook had task cookies `59` and `218`. The
applications had `initial_container_root`, `initial_role`, and role `10`.
The hooks had `external_runtime_root`, `runtime_external_restricted`, and role
`11`. All four task cookies and process-state IDs differed.

The restart application kept task cookie `108` and an identical snapshot
before and after K3s restart. The first real PostStart hook had task cookie
`269`. The repeated CRI delivery had task cookie `381`. Their process-state
IDs differed, and both kept the restricted external role.

The retained VM also ran this command from the same source bytes:

```sh
sudo examples/mithril-identity-manual/kubernetes-poststart.sh
```

It printed both observed orders, different repeated-hook task cookies, and
`PASS`. Automated and manual postflight found no case Namespace, RuntimeClass,
fixture, prestart request, pin, lease, cgroup, Mithril process, or loaded
Erebor Interceptor program. The retained VM remains available for the next
operator case.

The focused held-prestart unit test, shell syntax, formatting, diff check, and
final `bash .github/scripts/verify-rust-ci.sh` passed. The first CI invocation
was sandbox-blocked from local socket creation. One host-permitted retry hit an
unrelated transient CDP `WouldBlock`. The final host-permitted full run passed.

This completes `ENTRY-POSTSTART-001`. It also completes the Mithril identity
oracle in `ENTRY-POSTSTART-002`. The exact repeat limit is important: K3s did
not automatically resend the in-flight PostStart hook. Kubernetes permits
duplicate hook delivery but does not guarantee deterministic resend after this
restart. The fixture reads the live Pod's exact hook command and supplies the
second CRI `ExecSync` delivery. It does not claim automatic kubelet replay.
Hook timeout, mismatch, and missing-field rejection remain in
`ENTRY-STOCK-HOOK-FAILURE-002`.

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

## Labeled Native Mount-Namespace Entry Result — 2026-08-17

The retained x86_64 Ubuntu 24.04 VM, kernel `6.8.0-137-generic`, passed the
production probe at source commit `da4e1996c8e3ec4450d5b9e0ca5da7d6bacd6f89`.
It used unique output, pin, lease, and cgroup paths with suffix
`phase2-labelled-ns-20260817-1450`. The schema-8 JSON was
`/tmp/mithril-phase2-labelled-ns-20260817-1450/identity-physical-probe.json`.
Its SHA-256 was
`a079d291aa17bf7a19d8ef281b37ce773f325e2a014014072e75d6761d34c161`.
The BPF object SHA-256 was
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.

`CloneIntoCgroupFixture` created a restricted external root and stopped its
native child. The runner required a different target mount namespace before it
released the child. After `nsenter`, the child kept task cookie `15`, creator
and real-parent cookie `12`, process state
`00000000000000010000000000000013`, and active role `11`. Its execution ID
changed from `00000000000000010000000000000010` to
`00000000000000010000000000000019`. Its image provenance changed from
`0000000000000001000000000000000e` to
`0000000000000001000000000000001a`. The final record was `Runnable`, both
process records were active, and the exec guard was none. The JSON records
pin-root, lease, and cgroup removal.

The same retained VM ran this command as root at source commit
`af1e1c3eae202354b413beda085032930776fee3`:

```sh
examples/mithril-identity-manual/nsenter-move.sh --labeled-task
```

The shell SHA-256 was
`6cda64a4e3c62e61ee24f05f301e6ff627e722d9f4525d601434ea4c0f12cbcd`.
The shell created a restricted external Bash root, then one stopped native
child. The child entered only the Pod mount namespace and executed `sleep`.
The before and after records kept the task, creator, real-parent, process, and
restricted-role identities. The execution and image identities changed. The
shell required `Runnable`, active process records, and no exec guard. It
printed `PASS`. The shared runtime owner removed its Pod, CRI binding, fixture
directory, node, pin, lease, state, and cgroup. Postflight found no case
namespace, fixture directory, Mithril pin, node process, lease, or cgroup.

This historical result qualified the labeled native mount-namespace subcase of
`ENTRY-MIGRATE-001`. The current recheck below completes the Phase 2 identity
scope. Phase 4 owns protected effects. Phase 12 owns checkpoint restore through
`ENTRY-RESTORE-001`.

## Current Entry-Migration Manual Recheck — 2026-08-17

At source commit `ff129206ca610689c68b1de475b982f6e86ea97e`, a retained
x86_64 Ubuntu 24.04 VM, kernel `6.8.0-137-generic`, ran as root:

```sh
examples/mithril-identity-manual/nsenter-move.sh
examples/mithril-identity-manual/nsenter-move.sh --labeled-task
```

The shell SHA-256 was
`6cda64a4e3c62e61ee24f05f301e6ff627e722d9f4525d601434ea4c0f12cbcd`.
The first command printed `PASS`. The namespace-only child had no task identity
before movement. After movement, it had task cookie `12`, no creator,
`external_runtime_root`, `runtime_external_restricted`, active role `2`, and
coordinate state `3` (`Runnable`).

The labeled command printed `PASS`. The child kept task cookie `18`, creator
and real-parent task cookie `12`, process state
`00000000000000010000000000000016`, and active role `2`. Its execution ID
changed from `00000000000000010000000000000013` to
`0000000000000001000000000000001c`; its image ID changed from
`00000000000000010000000000000011` to
`0000000000000001000000000000001d`. It stayed runnable with active process
records and no exec guard.

Postflight found no case namespace, fixture directory, Mithril pin, node
process, lease or work directory, or identifiable manual cgroup. The harness
then removed the VM and `virsh list --all` was empty. This completes the Phase
2 identity scope of `ENTRY-MIGRATE-001`. Phase 4 owns protected effects. Phase
12 owns checkpoint restore through `ENTRY-RESTORE-001`. Neither later result
is a Phase 2 closure gate.

## Current Moved-Native VM Result — 2026-08-17

The retained x86_64 Ubuntu 24.04 VM ran the current
`IdentityTestRunner::physical_probe` at source commit
`c1b15be02553ae6cd18210d23f9e2bb2447a9511`. The command used the unique root
paths `/tmp/mithril-phase2-native-current.WXbFLa`,
`/sys/fs/bpf/erebor-mithril-native-current-WXbFLa`, and
`/sys/fs/cgroup/erebor-mithril-native-current-WXbFLa`. The
`mithril-identity-test` binary SHA-256 was
`ad9365eb1e89236b50f70284cdaa0688b2895e15259fd25293f5596e873a0566`.
The result JSON SHA-256 was
`25fde400976256d45d6b5a30f2c6854355af88dd910e99d97ef6c91c2de544da`.

The result has `moved_parent_fork_denied=true`. The
`CloneIntoCgroupFixture` saw the parent become fail-closed, then rejected its
ordinary fork with `EACCES`. No operator shell is valid because reproducing
that controlled move needs another fixture owner.

The result has `moved_task_exec_denied=true`. The runner moved the stopped
labeled child, required a fail-closed state, and required the child exec to
fail. Operators can run the readable
[`native-child.sh --moved-exec`](../../../../examples/mithril-identity-manual/native-child.sh)
case in an existing VM.

The JSON records removal of the pin root, lease, and cgroup. Postflight found
no node or fixture process. This result qualifies
`ID-MOVED-PARENT-FORK-004` and `ID-MOVED-TASK-EXEC-005` only. The phase remains
**Blocked**.

## Subreaper Reparenting VM Result — 2026-08-17

The qualifying source commit is `7f742772b5f6bf51a9eee9e48cc63197c08480a1`.
The retained x86_64 Ubuntu 24.04 VM ran kernel `6.8.0-137-generic`.
It ran the production probe with unique paths under
`/tmp/mithril-phase2-subreaper-20260817-1642`,
`/sys/fs/bpf/erebor-mithril-phase2-subreaper-20260817-1642`, and
`/sys/fs/cgroup/erebor-mithril-phase2-subreaper-20260817-1642`.

The schema-9 result is
`/tmp/mithril-phase2-subreaper-20260817-1642/identity-physical-probe.json`.
Its SHA-256 is
`a448889bbed4a157af9146ef7f504cac25fefc0682b2f030fc120a6e2fe6882e`.
The BPF object SHA-256 is
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.

The source fixture makes the restricted external root a Linux child
subreaper. It creates an intermediate native child and a stopped grandchild.
The intermediate exit reparents the grandchild to the root. The grandchild
then executes `sleep`. The exact final limits are task cookie `133`, creator
cookie `127`, real-parent cookie `0`, real-parent TID and TGID `6997`,
real-parent interval `2`, active role `11`, runnable coordinate, active process
execution and state vector, and no exec guard. The task cookie, creator cookie,
process state, and role remain unchanged. The execution and image IDs change.

The same VM then ran this command as root:

```sh
examples/mithril-identity-manual/native-child.sh --subreaper
```

The manual shell printed `PASS`. It used `identity_prepare_k3s_case` to own
its Pod, CRI binding, fixture directory, node, pin, lease, state, and cleanup.
It checked the same creator, parent-coordinate, execution, image, role, and
active-state limits. Postflight found no case namespace, fixture directory,
Mithril pin, node process, lease, or cgroup. The result JSON records
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`profile_task_refs_after_exit=0`.

This is physical and manual evidence for the subreaper subcase of
`ID-CREATOR-PARENT-007`. Namespace-init reparenting, ptrace reparenting, and
PID reuse remain unqualified. The phase remains **Blocked**.

## PID-Namespace-Init Reparenting VM Result — 2026-08-17

Source commit `6b1cf72` qualified this subcase on the retained x86_64 Ubuntu
24.04 VM, kernel `6.8.0-137-generic`. The production probe used unique paths
under `/tmp/mithril-phase2-namespace-init-20260817-1630`,
`/sys/fs/bpf/erebor-mithril-phase2-namespace-init-20260817-1630`, and
`/sys/fs/cgroup/erebor-mithril-phase2-namespace-init-20260817-1630`.

The schema-9 JSON is
`/tmp/mithril-phase2-namespace-init-20260817-1630/identity-physical-probe.json`.
Its SHA-256 is
`c4fac47027dd4d2e46b50ecb8fcd8fd2716d798db1347cc73b6317ef1b06a624`.
The BPF object SHA-256 is
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.

The fixture stopped an unlabelled user and PID namespace, then moved its PID-1
init into the bound cgroup. The init had task cookie `146`, host TID and TGID
`3488`, namespace PID `1`, `external_runtime_root`,
`runtime_external_restricted`, and role `11`. Its intermediate had task cookie
`149` and creator and real-parent cookie `146`. The stopped child had task
cookie `155`, creator and real-parent cookie `149`, parent TID and TGID `3489`,
and parent interval `1`.

After the intermediate exit and child `sleep` exec, the child retained task
cookie `155`, creator cookie `149`, process state
`0000000000000001000000000000009f`, and role `11`. It recorded real-parent
cookie `0`, real-parent TID and TGID `3488`, and parent interval `2`. Its
execution changed from `0000000000000001000000000000009c` to
`000000000000000100000000000000a2`. Its image changed from
`00000000000000010000000000000094` to
`000000000000000100000000000000a3`. Its coordinate was `Runnable`; process
execution and process state-vector records were active; and its exec guard was
none. The JSON records `pin_root_removed=true`, `lease_removed=true`,
`cgroup_removed=true`, and `profile_task_refs_after_exit=0`.

The same VM ran this command as root:

```sh
examples/mithril-identity-manual/native-child.sh --namespace-init
```

The shell printed `PASS`. `identity_prepare_k3s_case` owned the Pod, CRI
binding, node, pin, lease, and cleanup. The shell created the namespace before
the cgroup move. It then verified the same creator, parent-coordinate,
execution, image, role, and active-state limits. Postflight found no case
namespace, fixture directory, Mithril pin, node process, lease, cgroup, or
manual work directory.

This is physical and manual evidence for the PID-namespace-init subcase of
`ID-CREATOR-PARENT-007`. Ptrace reparenting and PID reuse remain unqualified.
The phase remains **Blocked**.

## Native Terminal-State Qualification — 2026-08-18

Source commit `e63488e` extends the existing `IdentityTestRunner` and
`NativeProcessFixture`. It adds no runner, map, role, or durable type. The
retained x86_64 Ubuntu 24.04 VM ran Linux `6.8.0-137-generic` and this command
with unique paths:

```sh
"$MITHRIL_BIN_DIRECTORY/mithril-identity-test" \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /var/tmp/mithril-native-final-20260818-8 \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-native-final-20260818-8 \
  --lease-path /run/mithril-native-final-20260818-8.lock \
  --cgroup-path /sys/fs/cgroup/mithril-native-final-20260818-8
```

The accepted schema-23 JSON is
`/tmp/mithril-phase2-native-terminal-20260818-8/identity-physical-probe.json`.
Its SHA-256 is
`f659a8983f7002f8558d88862b2f3500b2e138563c083f308f56ac309f1be8cb`.
The BPF object SHA-256 is
`02408c371aafaeeb044cbf11195a25dca35013bcdea44e37aa0756ebd2f2f3e6`.

For `EXEC-COMMIT-STATE-001`, the runner copied `/bin/true` and changed one
ELF load segment so `p_memsz` was smaller than `p_filesz`. Linux crossed the
exec point of no return and then terminated the task. Mithril recorded pending
state `4` (`PostPonrFatal`), exec guard `3` (`OutcomeUnknown`), and coordinate
state `4` (`Exited`). The source execution completed. The target execution
remained outcome-unknown and did not become active. The source role remained
restricted. The process cannot be held for an operator inspection after this
failure, so the existing runner owns this exact map oracle. The readable
[`native-child.sh --failed-exec`](../../../../examples/mithril-identity-manual/native-child.sh)
case remains the manual pre-PONR control.

For `ID-CREATOR-PARENT-007`, the runner reused namespace PID `2`. The first
task had host PID `96008`, task cookie `228`, and process state
`000000000000000100000000000000e8`. The second task had host PID `96009`, task
cookie `234`, and process state `000000000000000100000000000000ee`.
Their execution IDs were also different. Both creator edges remained task
cookie `225`.

For `ID-TASK-COORD-FINALIZE-006`, ordinary `pidfd_open` could not open the
non-leader worker. The existing task-coordinate map still identified the
worker before leader exit. The runner then reused namespace TID `3`. Host TIDs
`96010` and `96011` received task cookies `240` and `242`. No old coordinate
or task identity was reused.

For `NATIVE-STATE-REF-LIFETIME-001`, process, entry, and profile task
references were each `1` after the leader exited and the worker remained live.
They were each `0` after the worker exited. The root tombstone released after
leader exit. The worker tombstone stayed owned until final exit and then
released. The process became reclaimable and the entry became draining.

The same VM ran this readable root-shell command:

```sh
examples/mithril-identity-manual/native-pid-reuse.sh
```

The shell printed `PASS`. It used `identity_prepare_k3s_case`, reused
namespace PID `2`, and required fresh task, process, and execution identities
with the same exact creator. Automated cleanup removed the dedicated pin,
lease, cgroup, and fixture. Manual cleanup removed its Namespace, Pod, node
process, pin, lease, state, cgroup, fixture, and manual work directory.
Cleanup correction commit `6b9537e` adds exact fixture-command validation and
terminates the PID-namespace init on an error path. The retained VM reran the
shell after that correction. Postflight found no fixture process or owned
path.

This result closes only the four native rows named above. It does not qualify
node or runtime restart, cgroup/namespace/Pod/container lifetime reuse, or
stock OCI hook rejection. The phase remains **Blocked**.

## Authorization-Replay Qualification — 2026-08-18

Source commit `8c4adcb` ran in the retained x86_64 Ubuntu 24.04 VM on Linux
`6.8.0-137-generic`. The automated identity runner used unique paths under
`/var/tmp/mithril-auth-replay-20260818-11`,
`/sys/fs/bpf/mithril-auth-replay-20260818-11`,
`/run/mithril-auth-replay-20260818-11.lock`, and
`/sys/fs/cgroup/mithril-auth-replay-20260818-11`.

The accepted schema-24 JSON is
`/tmp/mithril-phase2-authorization-replay-20260818-11/identity-physical-probe.json`.
Its SHA-256 is
`9a0aca62b808421552029518dc4212ed5f1317d483afcc4d6a32b78554228951`.
The BPF object SHA-256 is
`02408c371aafaeeb044cbf11195a25dca35013bcdea44e37aa0756ebd2f2f3e6`.

The runner used the production administrative-envelope encoder and the
production `AuthorizationProofOwner`. It required these results:

- A changed exact target rejected before replay-state mutation.
- An expired envelope rejected.
- A changed signature rejected.
- A repeated proof and slot rejected in the same owner.
- A fresh proof and slot with the repeated sequence rejected after owner
  restart.
- The original proof rejected after the owner loaded a distinct boot identity.
- One fresh exact envelope passed before the boot-identity change.
- One fresh exact envelope with the next sequence passed after the change.

The replay WAL had exactly five newline-terminated records. Its SHA-256 is
`2ca8c993cab4371f8d76c35fecc9eedc8044fc3502aa8144c62be6b1b39c399a`.
The runner removed the WAL directory, pin root, lease, cgroup, and fixture
directory.

No separate manual shell is valid for this case. A shell would duplicate the
runner-owned signing key, signed body, trusted clock, proof and slot IDs, boot
identity, and WAL lifecycle. The exact reboot limit is that the fixture loads
the production owner with a distinct boot identity. It does not reboot the
VM. Phase 4 owns the complete approved-exec transaction and physical effect.

This closes `AUTHORIZATION-REPLAY-004`. Restart reconciliation, full
Kubernetes lifetime reuse, and stock-hook failures remain open. Phase 2
remains **Blocked**.

## Entry-Source Loss Qualification — 2026-08-18

Source commit `dd236af` ran in the retained x86_64 Ubuntu 24.04 VM on Linux
`6.8.0-137-generic`. The VM used Kubernetes `v1.35.5`, K3s
`v1.35.5+k3s1`, and containerd `v2.2.3-k3s1`.

The automated command used these unique paths:

```sh
"$MITHRIL_BIN_DIRECTORY/mithril-identity-test" \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /tmp/mithril-phase2-entry-loss-20260818-14/result \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-phase2-entry-loss-20260818-14 \
  --lease-path /tmp/mithril-phase2-entry-loss-20260818-14/result/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-phase2-entry-loss-20260818-14 \
  --with-kubernetes \
  --previous-bundle \
    /tmp/mithril-phase2-entry-loss-20260818-14/input/identity-physical-probe.json
```

The prior schema-24 input SHA-256 was
`9a0aca62b808421552029518dc4212ed5f1317d483afcc4d6a32b78554228951`.
The accepted schema-25 JSON is
`/tmp/mithril-phase2-entry-loss-20260818-14/identity-physical-probe.json`.
Its SHA-256 is
`d3817779c7835ef7b766d6bcbc84dc67007b8e1192665e39b8d3f00173b689fd`.

The direct CRI control had no Kubernetes API audit metadata. Its restricted
external task cookie was `19`. The stopped task had no label after independent
BPF task-storage deletion. Its next file open created fresh restricted
external task cookie `64` and a fresh process state. Both identities used the
configured external role `11`.

Stopping K3s changed exact-native-identity capability state to `UNHEALTHY`
with reason `LIVE_IDENTITY_RECONCILIATION_FAILED`. It did not change the full
task `64` snapshot. The runner restarted K3s and removed its Namespace,
fixture, pin, lease, node process, and work directory.

The same VM then ran:

```sh
examples/mithril-identity-manual/kubernetes-entry-loss.sh
```

The shell printed `PASS`. Postflight found no case Namespace, fixture, pin,
node process, lease, cgroup, or manual work directory. K3s was active.

The exact limit is identity only. The checked node config supplies a
predeclared assignment, and live CRI discovery binds it to the actual
container. This does not prove CRD delivery or a protected effect result. This
closes `ENTRY-LOSS-001`. The later restart qualification below reduces the
open set to two rows. Phase 2 remains **Blocked**.

## Kubernetes Service And Node Restart Qualification — 2026-08-18

Source commit `838fc8f` ran in the retained x86_64 Ubuntu 24.04 VM on Linux
`6.8.0-137-generic`. The VM used Kubernetes `v1.35.5`, K3s
`v1.35.5+k3s1`, and containerd `v2.2.3-k3s1`.

The automated command used these unique paths:

```sh
"$MITHRIL_BIN_DIRECTORY/mithril-identity-test" \
  --repo-root "$MITHRIL_MANUAL_SOURCE" \
  --output-directory /tmp/mithril-phase2-entry-restart-20260818-18/result \
  physical-probe \
  --pin-root /sys/fs/bpf/mithril-phase2-entry-restart-20260818-18 \
  --lease-path /tmp/mithril-phase2-entry-restart-20260818-18/result/owner.lock \
  --cgroup-path /sys/fs/cgroup/mithril-phase2-entry-restart-20260818-18 \
  --with-kubernetes \
  --previous-bundle \
    /tmp/mithril-phase2-entry-restart-20260818-18/input/identity-physical-probe.json
```

The prior schema-25 input SHA-256 was
`d3817779c7835ef7b766d6bcbc84dc67007b8e1192665e39b8d3f00173b689fd`.
The accepted schema-26 JSON is
`/tmp/mithril-phase2-entry-restart-20260818-18/identity-physical-probe.json`.
Its SHA-256 is
`d9be44d4315cd6097f9cb9eddc3514f6b1ef84aa5ddd326ad1709bc10f85eb02`.

The Pod existed before the node started. The discovered application root had
task cookie `5`, no creator, `restored_or_unknown_root`, and
`fail_closed_unknown`. A stopped direct CRI task then had task cookie `64`,
process state `0000000000000001000000000000003e`,
`external_runtime_root`, `runtime_external_restricted`, and role `11`.

Stopping K3s changed exact-native-identity capability state to `UNHEALTHY`
with reason `LIVE_IDENTITY_RECONCILIATION_FAILED`. The runner restarted K3s
and required `SUPPORTED` state. It then stopped the node. Node observation was
unavailable during that gap. Direct pinned-map inspection remained available.
The full task `64` snapshot was equal before the Kubernetes service restart,
after that restart, during the node gap, and after node recovery.

The same VM then ran:

```sh
examples/mithril-identity-manual/restart.sh
```

The shell printed `PASS`. Independent postflight checks found no case
Namespace, fixture, pin, node process, lease, cgroup, or manual work directory.
K3s was active. The full Rust CI script passed.

The exact service limit is specific to the qualified K3s distribution. Its one
service owns the kubelet and containerd. The result does not qualify separate
service units on another Kubernetes distribution. The node config is the
predeclared assignment. Live CRI discovery binds that assignment to the actual
container. This result does not qualify Custom Resource Definition delivery or
a protected effect decision.

Two earlier physical runs are not acceptance evidence. The first run found
that healthy reconciliation did not restore closed capability claims. The
second run found that a retryable CRI outage terminated active bindings. Both
runs removed their Namespace, fixture, pin, lease, cgroup, node process, and
work directory.

This closes `ENTRY-RESTART-001`. At this result point, `ENTRY-REUSE-001` and
`ENTRY-STOCK-HOOK-FAILURE-002` remained open. The next record closes the reuse
row.

## Recorded Identity Lifetime Reuse VM Results — 2026-08-18

The retained VM ran these operator cases as root from the same source that
produced the automated artifacts:

```sh
examples/mithril-identity-manual/native-pid-reuse.sh
examples/mithril-identity-manual/native-cgroup-reuse.sh
examples/mithril-identity-manual/kubernetes-reuse.sh
```

Each shell printed `PASS`. The native schema-27 JSON is
`/tmp/mithril-phase2-entry-reuse-native-20260818-28.json`; its SHA-256 is
`a456f1f1640ea4c64d9ad09d48c8fcceec539060dfd5b3d72ef2d86778377a`.
The Kubernetes schema-27 JSON is
`/tmp/mithril-phase2-entry-reuse-kubernetes-20260818-29.json`; its SHA-256 is
`ec2e87cede2e019132abe34c412015a251c6d72b85e2af51885c471936e6209c`.

The native result reused namespace PID `2` and namespace TID `3` with fresh
task, process, and execution identities. It removed and recreated
`/sys/fs/cgroup/mithril-phase2-entry-reuse-native-20260818-28`. The kernel
cgroup ID changed from `46662` to `46741`. The binding nonce changed from
`605d522715b446c2b1154468e0241847` to
`1cd70d410d72469090b72294c3fe3f37`. The live interval changed from
`09239bc1faf650aea03023057c19119e` to
`07288220adcd94dae6dfc11af410968a`.

The Kubernetes result reused the same Namespace, Pod, and container names.
The Pod UID changed from `30b8929e-c2c1-411a-a126-f501cbd9f768` to
`86d7f7a6-3047-4655-8e22-df8b5a28ca7f`. The full container ID changed from
`d2edd389154edc35b636b0728e7cd88021bc79c0bfe118289f484d0095094fbc` to
`8a7aba93c7f58c39f7d45c760130d8ea8df3209cc92151d42716acc1ac303fca`.
The kernel cgroup ID changed from `50040` to `50277`. The binding nonce, live
interval, sandbox ID, cgroup path, task identity, process identity, and
execution identity also changed.

The exact limit is that the cgroup allocator returned a new kernel ID. The
production recovery check rejects a repeated kernel cgroup ID with a changed
live interval, but an operator cannot safely force Linux to make that
collision. This record does not claim a policy-effect or response result.

Automated and manual cleanup removed every case Namespace, fixture, Mithril
pin, node process, lease, cgroup, and work directory. The Kubernetes service
was active after cleanup. This closes `ENTRY-REUSE-001`.
The next record closes `ENTRY-STOCK-HOOK-FAILURE-002`.

## Recorded OCI Prestart Failure VM Result — 2026-08-18

The automated runner used the configured Kubernetes RuntimeClass and OCI
prestart hook. The accepted schema-28 JSON is
`/tmp/mithril-phase2-stock-hook-failure-20260818-32/result/identity-physical-probe.json`.
Its SHA-256 is
`daa232982846a3dd0981b7771d16368497a4cebdec6f4a09bd13765c89937551`.

The runner recorded these exact container lifetimes:

- Container
  `c69d894cf9c27f49d5882c74a1059ab44a4220fb9f0517a5d147aaff5e97833e`
  had valid identity. Mithril did not release it. The hook timed out after
  exactly 30 seconds, and the runtime reported a prestart-hook failure.
- Container
  `544d5f45afef218c851279daeb005c0e1bfa022eb052312f017df6a1ab598021`
  had a changed OCI state container ID. The live-CRI binding validator
  rejected it, and the runtime reported a prestart-hook failure.
- Container
  `220dfabb9d5028dce492c04652d6fe56252fbef5659271fa95254937cbfd645d`
  had no Pod UID in its request. The validator rejected it, and the runtime
  reported a prestart-hook failure.

Each Pod payload would create a distinct host marker before it slept. None of
the three markers existed. The retained VM also ran:

```sh
sudo examples/mithril-identity-manual/kubernetes-stock-hook-failure.sh
```

The shell printed the three exact runtime failures and `PASS`. Automated and
manual postflight checks found no case Namespace, fixture, prestart request,
Mithril pin, node process, lease, cgroup, or work directory. The Kubernetes
service was active.

The exact limit is the qualified Kubernetes `v1.35.5` environment through the
K3s `v1.35.5+k3s1` distribution, containerd `v2.2.3-k3s1`, and the configured
`io.containerd.runc.v2` handler. Pod status and Events did not retain the full
hook error during the fixture window. The runner therefore joined the exact
full container ID to the local K3s journal. This result does not qualify CRD
delivery, a held-task inspection, purpose, a policy effect, or response.

This closes `ENTRY-STOCK-HOOK-FAILURE-002`. All 29 Phase 2 rows are `Done`.
Phase 2 is **Done**.

## Native Identity Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | replay, retarget, expire, reboot, and mismatch signed authorization | every invalid envelope rejects; fresh exact envelope consumes according to contract |
| `EXEC-COMMIT-STATE-001` | run success, pre-PONR failure, and post-PONR fatal/unknown exec | success commits once; early failure keeps exact prior state; later failure never restores broad authority |
| `ID-CGROUP-ESCAPE-001` | move a labeled task to host/unprotected placement | task storage still resolves and denies mismatch; unmoved allowed control works |
| `ID-CLONE-CGROUP-002` | fixture-owned physical probe; no manual shell is valid | stopped clone child has exact inherited identity before one direct first effect |
| `ID-CREATOR-PARENT-007` | reparent or orphan a child after native creation. Use [`native-child.sh --orphan`](../../../../examples/mithril-identity-manual/native-child.sh) for creator exit, [`native-child.sh --double-fork`](../../../../examples/mithril-identity-manual/native-child.sh) for double fork, [`native-child.sh --subreaper`](../../../../examples/mithril-identity-manual/native-child.sh) for subreaper reparenting, [`native-child.sh --namespace-init`](../../../../examples/mithril-identity-manual/native-child.sh) for PID-namespace-init reparenting, and [`native-pid-reuse.sh`](../../../../examples/mithril-identity-manual/native-pid-reuse.sh) for namespace PID reuse. | The immutable creator edge stays exact while the real-parent interval changes. Reused namespace PID gets fresh task, process, and execution identity. A permitted ptrace topology belongs to Phase 4. |
| `ID-MOVED-PARENT-FORK-004` | move parent, then fork | child inherits actual task authority and placement floor, not cgroup-derived role |
| `ID-MOVED-TASK-EXEC-005` | move labeled task, then exec | task-first old identity and placement mismatch constrain transition |
| `ID-TASK-COORD-FINALIZE-006` | inspect task at allocation, pre-wake finalization, visibility, and exit | opaque state precedes effect; PID/TGID/start coordinates finalize later without granting permission |
| `NATIVE-STATE-REF-LIFETIME-001` | exit tasks/processes while task generations, entry state, or native tombstones remain referenced | exact native references and tombstones retain restrictions until final qualified release; socket and protected-object lifetimes belong to later phases |

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
