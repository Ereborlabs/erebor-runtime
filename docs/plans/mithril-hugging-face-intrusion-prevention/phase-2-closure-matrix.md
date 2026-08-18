# Phase 2 Closure Matrix

Status: Blocked.

This table is the exact 29-fixture Phase 2 allocation in
`IdentityTestRunner`. A row is complete only when it has a source-backed Rust
fixture, a physical VM result, a readable shell when an operator can run the
case, and an acceptance record that states the exact limit.

Phase 3 and Phase 4 relationship, permission, raced-policy, and physical-effect
results are not Phase 2 gates. This table records only task, process, execution,
entry, runtime-binding, coordinate, authorization-identity, and native-reference
results.

| Fixture ID | Rust fixture | Manual shell | Physical result or exact missing limit | Status |
| --- | --- | --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | Missing from `IdentityTestRunner`; node unit cases exist. | Not operator-runnable. | Missing one runner-owned VM result for replay, retarget, expiry, reboot, mismatch, and one fresh exact envelope. | Open |
| `ENTRY-BINDING-GAP-001` | `NativeProcessFixture` in `physical_probe`. | `binding-gap.sh` | Pass: pre-binding root is `restored_or_unknown_root` and `fail_closed_unknown`; later root is restricted external. | Done |
| `ENTRY-CONTAINERS-001` | `physical_kubernetes_containers_probe` in `IdentityTestRunner` runs one regular init, native sidecar, and application in one Pod. | `kubernetes-containers.sh` | Pass: the three containers have distinct root task/process identities and distinct execution-set IDs while they share the Pod sandbox and volume. Schema-18 VM JSON SHA-256 `dfb7b407b8a945c474a210fb769abbc09b03599ecb271f4c27cb9d195da92ada`. Exact limit: late discovery gives each root conservative identity; shared-resource policy belongs to later phases. | Done |
| `ENTRY-EPHEMERAL-001` | `physical_kubernetes_ephemeral_probe` in `IdentityTestRunner` creates a targeted ephemeral container. | `kubernetes-ephemeral.sh` | Pass: the target and ephemeral container share one Pod sandbox and PID namespace but keep distinct cgroups, task/process roots, execution sets, and profiles. Schema-19 VM JSON SHA-256 `ee12bc57c8431ac801ae6e06e2e55dbf75ec50692b3a594785fc0d27fabf0efc`. Exact limit: late discovery gives both roots conservative identity; shared-namespace policy belongs to later phases. | Done |
| `ENTRY-EXEC-001` | `physical_kubernetes_probe` covers non-TTY and TTY `kubectl exec`, `kubectl cp`, and an identical native-child control. | `kubernetes-exec.sh`, `kubernetes-exec-tty.sh`, `kubernetes-copy.sh`, and `kubernetes-native-child.sh` | Pass: the three independent exec/copy roots are restricted external roots; the child keeps native parent lineage and the same restricted role. Schema-15 VM JSON SHA-256 `ef749b5a6d2521c6bd865317ce3843bf685610d009500f6d37569c9bd26a57cc`. Approved administrative exec belongs to Phase 4. | Done |
| `ENTRY-EXEC-002` | `physical_kubernetes_probe`. | `cri-exec.sh` | Pass: direct CRI exec is a separate restricted external root. VM JSON SHA-256 `aa70c2c398c6d07d138b81293103f3cbfc4be91d2c8999387b893ff7cac92910`. | Done |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | Two `NativeProcessFixture` roots in `physical_probe`. | `external-ambiguity.sh` | Pass: distinct task/process identities keep the same restricted external class. | Done |
| `ENTRY-LOSS-001` | Missing. | Missing. | Missing independent runtime-binding, entry-evidence, and audit-fact loss. Effect decisions belong to later phases. | Open |
| `ENTRY-MIGRATE-001` | `CloneIntoCgroupFixture` in `physical_probe`. | `nsenter-move.sh` | Pass: namespace entry grants no identity; cgroup entry creates a restricted external root. Phase 4 owns protected effects. Phase 12 owns checkpoint restore through `ENTRY-RESTORE-001`. | Done |
| `ENTRY-NETPROBE-001` | `physical_kubernetes_network_probe` in `IdentityTestRunner` runs real HTTP, TCP, and gRPC readiness probes and samples each live CRI cgroup. | `kubernetes-network-probes.sh` | Pass: each cgroup contained only its container init PID across repeated samples after all three probes made the Pod Ready. Schema-17 VM JSON SHA-256 `cbc024f56ce366a84aa2b0ffdbb7efaab58599b282d1f24295f30c08702fac07`. Exact limit: this proves that these native network probes create no in-container task; network flow and policy belong to later phases. | Done |
| `ENTRY-POSTSTART-001` | Missing. | Missing. | Missing both real `PostStart` and entrypoint orders. | Open |
| `ENTRY-POSTSTART-002` | Missing. | Missing. | Missing repeated `PostStart` after kubelet restart with fresh task/lifetime identity. | Open |
| `ENTRY-PRESTOP-001` | Missing. | Missing. | Missing termination-time identity and reference retention. Containment policy belongs to Phase 4. | Open |
| `ENTRY-PROBE-001` | Missing. | Missing. | Missing concurrent stock startup, readiness, and liveness exec probes as restricted external roots. | Open |
| `ENTRY-PROBE-002` | Missing. | Missing. | Missing an application child with probe-identical bytes and cadence that keeps native lineage. | Open |
| `ENTRY-PROBE-IMPERSONATION-003` | Missing. | Missing. | Missing one concurrent native child, stock probe, ordinary `kubectl exec`, and direct CRI exec with identical bytes. Approved-role transition belongs to Phase 4. | Open |
| `ENTRY-RESTART-001` | Missing. | `restart.sh` is readable but not self-contained in the manual VM. | Missing runtime, kubelet, and node restart reconciliation with exact coverage gaps. | Open |
| `ENTRY-REUSE-001` | Missing. | Missing. | Missing PID/TID, namespace, cgroup, Pod, and container lifetime reuse without stale identity. | Open |
| `ENTRY-SLEEP-001` | `physical_kubernetes_lifecycle_sleep_probe` in `IdentityTestRunner` reads the live CRI cgroup while the real lifecycle `sleep` action is pending. | `kubernetes-lifecycle-sleep.sh` | Pass: `cgroup.procs` contained only the container init PID while the Pod was not Ready. The lifecycle action created no in-container task. Schema-16 VM JSON SHA-256 `a62e82352a3153c65895d69265e4e0265d78ec6a76679e50a7d1f0bbcc2804fb`. Exact limit: this proves only the native Kubernetes lifecycle `sleep` action; it does not qualify exec probes or network probes. | Done |
| `ENTRY-START-001` | `physical_kubernetes_probe` starts the Pod before Mithril and records its initial root after live CRI discovery. | Every self-contained Kubernetes shell calls `identity_wait_for_initial_binding`; `kubernetes-exec-tty.sh` is the current recorded run. | Pass: the pre-existing PID 1 has no creator, `restored_or_unknown_root`, and `fail_closed_unknown`. Schema-15 VM JSON SHA-256 `ef749b5a6d2521c6bd865317ce3843bf685610d009500f6d37569c9bd26a57cc`. Exact limit: no first-instruction claim; Phase 4 owns effect denial. | Done |
| `ENTRY-STOCK-HOOK-FAILURE-002` | Missing. | Missing. | Missing stock hook timeout, mismatch, and missing-field identity results. | Open |
| `EXEC-COMMIT-STATE-001` | `NativeProcessFixture` covers success and pre-PONR failure. | `native-child.sh --failed-exec` | Pass for success and pre-PONR restore. Missing post-PONR fatal and unknown-state identity oracles. | Partial |
| `ID-CGROUP-ESCAPE-001` | `CloneIntoCgroupFixture` in `physical_probe`. | `cgroup-escape.sh` | Pass: moved root keeps identity, becomes fail closed, and cannot use host fallback. | Done |
| `ID-CLONE-CGROUP-002` | `CloneIntoCgroupFixture` in `physical_probe`. | Not operator-runnable; the runner owns the stopped clone and pidfd synchronization. | Pass: child identity exists before its first direct effect. | Done |
| `ID-CREATOR-PARENT-007` | `NativeProcessFixture` covers creator exit, double fork, subreaper, and PID-namespace init. | `native-child.sh --orphan`, `--double-fork`, `--subreaper`, and `--namespace-init` | Those four branches pass. Missing deterministic PID-reuse proof. Permitted ptrace policy belongs to Phase 4. | Partial |
| `ID-MOVED-PARENT-FORK-004` | `CloneIntoCgroupFixture` in `physical_probe`. | Not operator-runnable; the runner owns the stopped parent and fork result. | Pass: moved labeled parent cannot fork through host fallback. | Done |
| `ID-MOVED-TASK-EXEC-005` | `NativeProcessFixture` in `physical_probe`. | `native-child.sh --moved-exec` | Pass: moved labeled task keeps identity and cannot exec through host fallback. | Done |
| `ID-TASK-COORD-FINALIZE-006` | `NativeProcessFixture` supplies allocation and runnable snapshots. | Not operator-runnable. | Missing the no-`PIDFD_THREAD`, leader-first-exit, and TID-reuse oracles. Map-saturation failure belongs to the Phase 4 `LSM-DENY-SATURATION-001` fixture. | Partial |
| `NATIVE-STATE-REF-LIFETIME-001` | `physical_probe` records final task-generation reference count. | Not operator-runnable. | Pass for final task references reaching zero. Missing process, entry, tombstone, and retained task-generation lifetime transitions. Socket/object effect lifetimes belong to later phases. | Partial |

Phase 2 closes only when every row is `Done`. The Phase 4 administrative-exec
and raced-policy fixtures do not block this result.
