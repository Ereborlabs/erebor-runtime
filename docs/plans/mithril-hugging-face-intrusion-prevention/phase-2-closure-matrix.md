# Phase 2 Closure Gates

Status: Blocked.

This matrix contains only open Phase 2 closure gates. Each row needs a
source-backed `IdentityTestRunner` fixture, a physical VM result, and a manual
shell when an operator can run the case. It excludes completed rows and the
approved administrative-exec physical path, which Phase 4 owns.

Completed-row evidence remains in the phase result and acceptance record:
`ID-MOVED-PARENT-FORK-004` and `ID-MOVED-TASK-EXEC-005`.

| Fixture ID | Current proof | Missing closure proof |
| --- | --- | --- |
| `ENTRY-BINDING-GAP-001` | No fixture. | Binding-gap source fixture and VM result. |
| `ENTRY-CONTAINERS-001` | No fixture. | Init, sidecar, and shared-resource cases. |
| `ENTRY-EPHEMERAL-001` | No fixture. | Ephemeral-container case. |
| `ENTRY-EXEC-001` | One non-TTY `kubectl exec` subcase. | Runner fixture, TTY, copy-shaped, and identical native-child controls. |
| `ENTRY-EXEC-002` | One direct CRI exec subcase. | Runner fixture and row JSON. |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | No fixture. | Concurrent indistinguishable-root case. |
| `ENTRY-LOSS-001` | No fixture. | Independent runtime, audit, and entry-loss cases. |
| `ENTRY-MIGRATE-001` | Namespace-only host entry and cgroup move passed. | Labeled-task namespace move. |
| `ENTRY-NETPROBE-001` | No fixture. | HTTP, TCP, and gRPC cases. |
| `ENTRY-POSTSTART-001` | No fixture. | Both start orders. |
| `ENTRY-POSTSTART-002` | No fixture. | Kubelet-restart lifecycle case. |
| `ENTRY-PRESTOP-001` | No fixture. | Restricted termination case. |
| `ENTRY-PROBE-001` | No fixture. | Concurrent stock-probe case. |
| `ENTRY-PROBE-002` | No fixture. | Identical native-child control. |
| `ENTRY-PROBE-IMPERSONATION-003` | No fixture. | Required four-root race. |
| `ENTRY-RESTART-001` | Readable shell exists. | Runtime, kubelet, and node restart fixture and VM result. |
| `ENTRY-REUSE-001` | No fixture. | PID, namespace, cgroup, and runtime-object reuse cases. |
| `ENTRY-SLEEP-001` | No fixture. | Lifecycle sleep case. |
| `ENTRY-START-001` | No fixture. | Configured start-hook gap case. |
| `ENTRY-STOCK-HOOK-FAILURE-002` | No fixture. | Stock-hook failure cases. |
| `EXEC-COMMIT-STATE-001` | Success and pre-PONR recovery passed. | Post-PONR fatal and unknown outcomes. |
| `EXEC-CONCURRENT-002` | Serial and two-worker normal exec passed in the VM. | Exec versus fork, vfork, and thread creation. |
| `ID-CGROUP-ESCAPE-001` | Moved root becomes fail closed. | Unmoved control and first-effect denial proof. |
| `ID-CLONE-CGROUP-002` | Direct `CLONE_INTO_CGROUP` root and child passed. | First-effect proof and fixture-specific record. |
| `ID-CLONE-CGROUP-FAIL-003` | No fixture. | Allocation, finalization, and placement fault injection. |
| `ID-CREATOR-PARENT-007` | Creator exit and double fork passed. | Subreaper, namespace-init, ptrace, and PID-reuse cases. |
| `ID-TASK-COORD-FINALIZE-006` | Allocation and runnable snapshots exist. | Retained coordinate history for allocation, finalization, visibility, and exit. |
| `NATIVE-STATE-REF-LIFETIME-001` | Final task-reference count is zero. | Socket, object, and generation-reference cases. |
| `STATE-FORK-IPC-002` | Native fork passed. | Inherited IPC state case. |
| `STATE-THREAD-RACE-001` | Serial non-leader exec passed. | Concurrent restriction-transition race. |

Phase 2 closes only after every row in this matrix passes. The Phase 4
administrative-exec exception does not block this Phase 2 result.
