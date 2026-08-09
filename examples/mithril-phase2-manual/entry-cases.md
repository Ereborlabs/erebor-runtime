# Phase 2 Entry And Container-Runtime Cases

Direct-runtime rows can be exercised without Kubernetes. Kubernetes rows and
their runnable shell remain in the catalog because Phase 2 must qualify those
entry surfaces too.

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `ENTRY-BINDING-GAP-001` | Delay or drop the binding before the first protected effect. | The unresolved effect denies and the gap is recorded; a qualified initial binding succeeds. |
| `ENTRY-CONTAINERS-001` | Run init, native sidecar, application, and shared-volume/network cases. | Independent execution sets remain distinct; declared sharing works only through explicit relationships. |
| `ENTRY-EPHEMERAL-001` | Add an ephemeral container that shares the PID namespace. | It receives a new independent root/profile; the shared namespace does not merge lineage. |
| `ENTRY-EXEC-001` | Run TTY and non-TTY `kubectl exec` and a copy-shaped command. Start with [`kubernetes-exec.sh`](./kubernetes-exec.sh). | It is a restricted external root unless the approved path completes; a normal app child remains native. |
| `ENTRY-EXEC-002` | Run direct `crictl exec` or `docker exec` with probe-identical argv using [`cri-exec.sh`](./cri-exec.sh) or [`docker-exec.sh`](./docker-exec.sh). | It is a restricted external root, never fabricated probe purpose. |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | Create indistinguishable external purposes concurrently. | They receive the same permission intersection/restricted class; timing and argv do not split them. |
| `ENTRY-LOSS-001` | Drop runtime, audit, and entry evidence independently. | Protected unknown state remains restricted and coverage records each loss. |
| `ENTRY-MIGRATE-001` | Use namespace-only `nsenter`, then move the task into the protected cgroup with [`nsenter-move.sh`](./nsenter-move.sh). | Namespace entry grants no workload identity; movement creates a restricted external root and never application authority. |
| `ENTRY-NETPROBE-001` | Run HTTP, TCP, and gRPC probes. | No fake in-container process root appears; application receive and host flow remain distinct. |
| `ENTRY-POSTSTART-001` | Race `PostStart` and the entrypoint in both orders. | Initial and external roots remain distinct. |
| `ENTRY-POSTSTART-002` | Restart kubelet and repeat `PostStart`. | A fresh task/lifetime identity gets the same restricted budget; stale identity is not reused. |
| `ENTRY-PRESTOP-001` | Terminate during an active restriction. | Cleanup cannot regain authority; approved safe cleanup follows policy. |
| `ENTRY-PROBE-001` | Run concurrent startup, readiness, and liveness exec probes. | Stock purpose remains unknown/restricted unless a qualified interface proves it. |
| `ENTRY-PROBE-002` | Have an app child run identical probe bytes and cadence. [`native-child.sh`](./native-child.sh) supplies the native-child control. | The native child keeps application lineage and cannot impersonate an external root. |
| `ENTRY-PROBE-IMPERSONATION-003` | Race a native child, probe, admin, and direct-runtime root with identical argv/TTY. | Only native creation or complete approval changes authority; ordinary identical roots stay restricted. |
| `ENTRY-RESTART-001` | Restart the runtime, kubelet when present, and node during binding. [`restart.sh`](./restart.sh) covers the node-only branch. | Live reconciliation opens exact gaps and does not reuse a stale role. |
| `ENTRY-REUSE-001` | Reuse PID, namespace, cgroup path/ID, Pod/container name. | New cookies, nonces, and live intervals prevent old authority or response attachment. |
| `ENTRY-SLEEP-001` | Execute a lifecycle sleep action. | It is only a lifecycle fact; no process entry is invented when no task exists. |
| `ENTRY-START-001` | Delay or drop configured start-hook metadata. | The first unresolved protected effect denies and the start gap remains explicit. |
| `ENTRY-STOCK-HOOK-FAILURE-002` | Fail, time out, or mismatch the configured stock hook. | The documented failure result occurs; there is no held-task or purpose claim. |

Phase 2 establishes identity. Phase 4 owns permission tables and physical
file/network/exec denial, so these cases must not claim a Phase 4 denial yet.
