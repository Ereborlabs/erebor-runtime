# Phase 2 Closure Matrix

Status: Blocked.

This matrix records the checked source and evidence state at commit `e6352f8`.
It does not convert a registry allocation, a unit test, or a partial VM probe
into fixture qualification.

The required fixture list is the Phase 2 list in
[`phase-2-exact-native-identity.md`](./phase-2-exact-native-identity.md) and
the checked registry in [`spec/qualification/v1/fixtures.yaml`](../../../spec/qualification/v1/fixtures.yaml).
`IdentityTestRunner` owns an automated row only when its source executes the
case and emits the row evidence. A manual shell is required only when an
operator can run the case in an existing VM without a second runner.

`AUTHORIZATION-REPLAY-004` remains in this matrix because Phase 2 owns its
identity binding. Phase 4 owns the complete approved-exec physical result.
That Phase 4 result is not a Phase 2 closure gate.

| Fixture ID | Rust fixture | Manual shell | Physical VM result | Status and exact limit |
| --- | --- | --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | Identity binding has code-backed coverage in the administrative owner. | None. | Phase 4 owns the complete approved-exec physical result. | Implemented outside Phase 2: retain this trace row, but do not require Phase 4 permission or physical exec proof to close Phase 2. |
| `ENTRY-BINDING-GAP-001` | None. | None. | None. | Blocked: no source fixture, shell, or VM result. |
| `ENTRY-CONTAINERS-001` | None. | None. | None. | Blocked: init, sidecar, and shared-resource cases are absent. |
| `ENTRY-EPHEMERAL-001` | None. | None. | None. | Blocked: no ephemeral-container fixture or VM result. |
| `ENTRY-EXEC-001` | None. | `kubernetes-exec.sh`. | One non-TTY `kubectl exec` subcase only. | Blocked: TTY, copy shape, and native identical-command control are absent. |
| `ENTRY-EXEC-002` | None. | `cri-exec.sh` and `docker-exec.sh`. | One direct CRI exec subcase. | Blocked: the runner does not own a source fixture or JSON row. |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | None. | None. | None. | Blocked: no concurrent indistinguishable-root fixture. |
| `ENTRY-LOSS-001` | None. | None. | None. | Blocked: independent runtime, audit, and entry loss cases are absent. |
| `ENTRY-MIGRATE-001` | `IdentityTestRunner::physical_probe` with `CloneIntoCgroupFixture`. | Self-contained `nsenter-move.sh` in the retained manual VM. | Runner JSON `91990138176e69b729f043b3f9e349fffa259f6bf36e9edbfdfd53405722ac2b`; manual VM case passed. | Partial: no protected effect, labeled-task namespace move, or restore result exists. |
| `ENTRY-NETPROBE-001` | None. | None. | None. | Blocked: HTTP, TCP, and gRPC cases are absent. |
| `ENTRY-POSTSTART-001` | None. | None. | None. | Blocked: both start orders are absent. |
| `ENTRY-POSTSTART-002` | None. | None. | None. | Blocked: kubelet-restart lifecycle case is absent. |
| `ENTRY-PRESTOP-001` | None. | None. | None. | Blocked: termination-under-restriction case is absent. |
| `ENTRY-PROBE-001` | None. | None. | None. | Blocked: concurrent stock probe case is absent. |
| `ENTRY-PROBE-002` | None. | None. | None. | Blocked: identical native-child control is absent. |
| `ENTRY-PROBE-IMPERSONATION-003` | None. | None. | None. | Blocked: the required four-root race is absent. |
| `ENTRY-RESTART-001` | None. | `restart.sh`. | None. | Blocked: runtime, kubelet, and node restart have no runner-owned VM result. |
| `ENTRY-REUSE-001` | None. | None. | None. | Blocked: PID, namespace, cgroup, and runtime-object reuse cases are absent. |
| `ENTRY-SLEEP-001` | None. | None. | None. | Blocked: lifecycle sleep case is absent. |
| `ENTRY-START-001` | None. | None. | None. | Blocked: configured start-hook gap case is absent. |
| `ENTRY-STOCK-HOOK-FAILURE-002` | None. | None. | None. | Blocked: stock-hook failure cases are absent. |
| `EXEC-COMMIT-STATE-001` | `IdentityTestRunner::physical_probe` with `NativeProcessFixture`. | `native-child.sh --failed-exec`. | Success and pre-PONR recovery subcases. | Blocked: post-PONR fatal and unknown outcomes are absent. |
| `EXEC-CONCURRENT-002` | `NativeProcessFixture` has a serial non-leader exec only. | `native-child.sh --thread-exec` has the same serial case. | Serial non-leader result only. | Blocked: Phase 2 still needs real concurrent exec and fork/vfork/thread-creation races for the inherited restricted role. The approved one-use target-role race is Phase 4 work. |
| `ID-CGROUP-ESCAPE-001` | `IdentityTestRunner::physical_probe` with `CloneIntoCgroupFixture`. | None; the controlled fixture cannot be reproduced without another runner. | Qualified moved-root result. | Partial: the result records the root escape only. |
| `ID-CLONE-CGROUP-002` | `IdentityTestRunner::physical_probe` with `CloneIntoCgroupFixture`. | None; the controlled `clone3` fixture has no operator shell. | Direct `CLONE_INTO_CGROUP` root and native-child result. | Partial: no checked row record names this fixture alone. |
| `ID-CLONE-CGROUP-FAIL-003` | None. | None. | None. | Blocked: allocation, finalization, and placement fault injection are absent. |
| `ID-CREATOR-PARENT-007` | `IdentityTestRunner::physical_probe` with `NativeProcessFixture`. | `native-child.sh --orphan` and `--double-fork`. | Creator-exit and double-fork branches. | Partial: subreaper, namespace-init, ptrace, and PID-reuse branches remain absent. |
| `ID-MOVED-PARENT-FORK-004` | `IdentityTestRunner::physical_probe` with `CloneIntoCgroupFixture`. | None; the controlled placement move needs the fixture owner. | Current VM JSON SHA-256 `25fde400976256d45d6b5a30f2c6854355af88dd910e99d97ef6c91c2de544da`. | Done: the runner observed the fail-closed parent, rejected its ordinary `fork` with `EACCES`, and removed its resources. A shell would need a second controlled fixture, so no operator shell is valid. |
| `ID-MOVED-TASK-EXEC-005` | `IdentityTestRunner::physical_probe` with `NativeProcessFixture`. | `native-child.sh --moved-exec`. | Current VM JSON SHA-256 `25fde400976256d45d6b5a30f2c6854355af88dd910e99d97ef6c91c2de544da`. | Done: the runner requires a fail-closed moved child and a denied exec; the readable shell provides the same operator case. |
| `ID-TASK-COORD-FINALIZE-006` | `IdentityTestRunner::physical_probe` snapshots allocation and runnable state. | None. | No fixture-specific VM record. | Blocked: coordinate-history evidence is not retained as this row. |
| `NATIVE-STATE-REF-LIFETIME-001` | `IdentityTestRunner::physical_probe` checks final task-reference count. | None. | Shared probe records `profile_task_refs_after_exit=0`. | Partial: socket, object, and generation reference cases are absent. |
| `STATE-FORK-IPC-002` | `NativeProcessFixture` covers fork, not inherited IPC state. | None. | None. | Blocked: IPC inheritance case is absent. |
| `STATE-THREAD-RACE-001` | `NativeProcessFixture` has a serial non-leader exec. | `native-child.sh --thread-exec`. | Serial non-leader result only. | Blocked: no concurrent restriction-transition race exists. |

`EXEC-CONCURRENT-002` remains a Phase 2 fixture. It must race concurrent normal
exec transactions with the inherited restricted role and race exec against
fork, vfork, and thread creation. The current serial non-leader case is not
that race. The one-use approved-administrative target-role race belongs to
Phase 4.
The phase remains `Blocked` until every row has the required source fixture,
physical result, manual shell when applicable, and acceptance record with its
exact limit.
