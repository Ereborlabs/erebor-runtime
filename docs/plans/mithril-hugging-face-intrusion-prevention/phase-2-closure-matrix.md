# Phase 2 Closure Gates

Status: Blocked.

This matrix contains only open Phase 2 closure gates. Each row needs a
source-backed `IdentityTestRunner` fixture, a physical VM result, and a manual
shell when an operator can run the case. It excludes completed rows and the
approved administrative-exec physical path, which Phase 4 owns.

`Blocked: no current fixture contract` means that the current owner cannot
create the exact target and oracle. It is not a request for a similar test.

Completed-row evidence remains in the phase result and acceptance record:
`ENTRY-BINDING-GAP-001`, `ENTRY-EXTERNAL-AMBIGUITY-001`,
`ID-CGROUP-ESCAPE-001`, `ID-CLONE-CGROUP-002`,
`ID-MOVED-PARENT-FORK-004`, and
`ID-MOVED-TASK-EXEC-005`.

| Fixture ID | Current proof | Missing closure proof |
| --- | --- | --- |
| `ENTRY-CONTAINERS-001` | Blocked: no current fixture contract. | Init, sidecar, and shared-resource cases. |
| `ENTRY-EPHEMERAL-001` | Blocked: no current fixture contract. | Ephemeral-container case. |
| `ENTRY-EXEC-001` | Blocked: one operator subcase has no automated fixture contract. | Runner fixture, TTY, copy-shaped, and identical native-child controls. |
| `ENTRY-EXEC-002` | Blocked: one operator subcase has no automated fixture contract. | Runner fixture and row JSON. |
| `ENTRY-LOSS-001` | Blocked: no current fixture contract. | Independent runtime, audit, and entry-loss cases. |
| `ENTRY-MIGRATE-001` | Blocked. Namespace-only entry, cgroup movement, and labeled native mount-namespace entry passed. The Phase 2 identity owner has no effect permission table, so an unlabeled moved root is restricted but has no first-effect denial oracle. No owned restore operation exists. | Add a Phase-2-compatible first-effect and restore mechanism before adding the remaining fixture, VM result, and manual shell. |
| `ENTRY-NETPROBE-001` | Blocked: no current fixture contract. | HTTP, TCP, and gRPC cases. |
| `ENTRY-POSTSTART-001` | Blocked: no current fixture contract. | Both start orders. |
| `ENTRY-POSTSTART-002` | Blocked: no current fixture contract. | Kubelet-restart lifecycle case. |
| `ENTRY-PRESTOP-001` | Blocked: no current fixture contract. | Restricted termination case. |
| `ENTRY-PROBE-001` | Blocked: no current fixture contract. | Concurrent stock-probe case. |
| `ENTRY-PROBE-002` | Blocked: no current fixture contract. | Identical native-child control. |
| `ENTRY-PROBE-IMPERSONATION-003` | Blocked: no current fixture contract. | Required four-root race. |
| `ENTRY-RESTART-001` | Blocked: readable shell has no automated fixture contract. | Runtime, kubelet, and node restart fixture and VM result. |
| `ENTRY-REUSE-001` | Blocked: no current fixture contract. | PID, namespace, cgroup, and runtime-object reuse cases. |
| `ENTRY-SLEEP-001` | Blocked: no current fixture contract. | Lifecycle sleep case. |
| `ENTRY-START-001` | Blocked: no current fixture contract. | Configured start-hook gap case. |
| `ENTRY-STOCK-HOOK-FAILURE-002` | Blocked: no current fixture contract. | Stock-hook failure cases. |
| `EXEC-COMMIT-STATE-001` | Blocked: success and pre-PONR recovery passed; no post-PONR fault contract. | Post-PONR fatal and unknown outcomes. |
| `EXEC-CONCURRENT-002` | Serial and two-worker normal exec passed in the VM. | Blocked: the current fixture has no control that holds real exec staging. A shared barrier loses the creator sibling to Linux `de_thread` before it reaches fork, vfork, or thread creation. |
| `ID-CREATOR-PARENT-007` | Creator exit, double fork, subreaper, and PID-namespace-init reparenting passed. | Blocked: current owners have a `PTRACE_ATTACH` denial fixture, not a permitted ptrace transition. A ptrace topology needs an approved permitted transition. The existing fixture has no bounded way to require a real host-PID collision; a PID-reuse case needs an approved deterministic collision design. |
| `ID-TASK-COORD-FINALIZE-006` | Blocked. Allocation and runnable snapshots exist. The current fixture has no allocation or finalization fault-injection protocol, missing-`PIDFD_THREAD` control, or leader-first-exit/TID-reuse oracle. | Add the required coordinate-failure controls before adding retained allocation, finalization, visibility, and exit evidence. |
| `NATIVE-STATE-REF-LIFETIME-001` | Blocked: task-reference count is the only current observable. | Socket, object, and generation-reference cases. |
| `STATE-FORK-IPC-002` | Blocked: no resource-inheritance snapshot contract. | Inherited IPC state case. |
| `STATE-THREAD-RACE-001` | Blocked: no restriction-transition fixture contract. | Concurrent restriction-transition race. |

Phase 2 closes only after every row in this matrix passes. The Phase 4
administrative-exec exception does not block this Phase 2 result.
