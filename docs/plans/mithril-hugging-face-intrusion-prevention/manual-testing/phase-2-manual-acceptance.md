# How To Manually Accept Phase 2

Status: The current source passed the automated privileged VM identity probe
and its Kubernetes entry extension. Direct CRI exec, non-TTY and TTY
`kubectl exec`, `kubectl cp`, and the identical native-child control passed as
self-contained operator cases. The VM used the K3s distribution. The full
fixture matrix is not recorded.

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
| `ENTRY-POSTSTART-002` | restart kubelet and repeat `PostStart` | fresh task/lifetime identity with same restricted budget; no stale reuse |
| `ENTRY-PRESTOP-001` | terminate while a restricted root is active | termination does not change identity or release required native references; Phase 4 owns containment policy |
| `ENTRY-PROBE-001` | run concurrent startup/readiness/liveness exec probes | stock purpose remains unknown/restricted; qualified evidence only if interface supplies it |
| `ENTRY-PROBE-002` | app child runs identical probe bytes/cadence | native child keeps application lineage and cannot impersonate external root |
| `ENTRY-PROBE-IMPERSONATION-003` | race native child, stock probe, ordinary `kubectl exec`, and direct CRI exec with identical argv/TTY | the child stays native and every independent stock/runtime root stays restricted; Phase 4 owns approved-role transition |
| `ENTRY-RESTART-001` | restart runtime, kubelet, and node during binding | live reconciliation opens exact gaps and reuses no stale role |
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

## Native Identity Fixture Matrix

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | replay, retarget, expire, reboot, and mismatch signed authorization | every invalid envelope rejects; fresh exact envelope consumes according to contract |
| `EXEC-COMMIT-STATE-001` | run success, pre-PONR failure, and post-PONR fatal/unknown exec | success commits once; early failure keeps exact prior state; later failure never restores broad authority |
| `ID-CGROUP-ESCAPE-001` | move a labeled task to host/unprotected placement | task storage still resolves and denies mismatch; unmoved allowed control works |
| `ID-CLONE-CGROUP-002` | fixture-owned physical probe; no manual shell is valid | stopped clone child has exact inherited identity before one direct first effect |
| `ID-CREATOR-PARENT-007` | reparent or orphan a child after native creation. Use [`native-child.sh --orphan`](../../../../examples/mithril-identity-manual/native-child.sh) for creator exit, [`native-child.sh --double-fork`](../../../../examples/mithril-identity-manual/native-child.sh) for double fork, [`native-child.sh --subreaper`](../../../../examples/mithril-identity-manual/native-child.sh) for subreaper reparenting, and [`native-child.sh --namespace-init`](../../../../examples/mithril-identity-manual/native-child.sh) for PID-namespace-init reparenting. | The immutable creator edge stays exact while the real-parent interval changes. PID reuse remains unqualified. A permitted ptrace topology belongs to Phase 4. |
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
