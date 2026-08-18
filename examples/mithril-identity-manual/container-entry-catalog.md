# Container Entry And Identity Cases

Direct-runtime rows can be exercised without Kubernetes. Kubernetes rows and
their runnable shell remain in the catalog because native identity must qualify those
entry surfaces too.

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `ENTRY-BINDING-GAP-001` | Delay or drop the binding before root reconciliation. | The unresolved root stays fail closed; a qualified later root is restricted external. |
| `ENTRY-CONTAINERS-001` | Run init, native sidecar, and application containers. | Independent roots and execution sets remain distinct. Later phases own shared-resource policy. |
| `ENTRY-EPHEMERAL-001` | Add an ephemeral container that shares the PID namespace. | It receives a new independent root/profile; the shared namespace does not merge lineage. |
| `ENTRY-EXEC-001` | Run TTY and non-TTY `kubectl exec`, `kubectl cp`, and an identical native child. Start with [`kubernetes-exec.sh`](./kubernetes-exec.sh) for non-TTY exec. | Ordinary exec and copy roots stay restricted external; the app child stays native. Phase 4 owns approved administrative exec. |
| `ENTRY-EXEC-002` | Run direct `crictl exec` or `docker exec` with probe-identical argv using [`cri-exec.sh`](./cri-exec.sh) or [`docker-exec.sh`](./docker-exec.sh). | It is a restricted external root, never fabricated probe purpose. |
| `ENTRY-EXTERNAL-AMBIGUITY-001` | Create two identical external roots with [`external-ambiguity.sh`](./external-ambiguity.sh). | They have separate task/process identity and the same restricted external role; timing and argv do not split them. |
| `ENTRY-LOSS-001` | Drop runtime, audit, and entry evidence independently. | Unknown identity remains restricted and coverage records each loss. Later phases own effect decisions. |
| `ENTRY-MIGRATE-001` | Run the verified namespace-only `sleep 300` child from [`nsenter-move.sh`](./nsenter-move.sh), then move that child into the protected cgroup. | Namespace entry grants no workload identity. The cgroup move creates a restricted external root and never application authority. |
| `ENTRY-NETPROBE-001` | Run HTTP, TCP, and gRPC probes. | No synthetic in-container process root appears. Later network fixtures own flow policy. |
| `ENTRY-POSTSTART-001` | Race `PostStart` and the entrypoint in both orders. | Initial and external roots remain distinct. |
| `ENTRY-POSTSTART-002` | Restart kubelet and repeat `PostStart`. | A fresh task/lifetime identity gets the same restricted budget; stale identity is not reused. |
| `ENTRY-PRESTOP-001` | Terminate while a restricted root is active. | Termination does not change identity or release required native references. Phase 4 owns containment policy. |
| `ENTRY-PROBE-001` | Run concurrent startup, readiness, and liveness exec probes. | Stock purpose remains unknown/restricted unless a qualified interface proves it. |
| `ENTRY-PROBE-002` | Have an app child run identical probe bytes and cadence. [`native-child.sh`](./native-child.sh) supplies the native-child control. | The native child keeps application lineage and cannot impersonate an external root. |
| `ENTRY-PROBE-IMPERSONATION-003` | Race a native child, stock probe, ordinary `kubectl exec`, and direct-runtime root with identical argv/TTY. | The child stays native and the independent runtime roots stay restricted. Phase 4 owns approved-role transition. |
| `ENTRY-RESTART-001` | Restart the Kubernetes service and node during discovery and binding. [`restart.sh`](./restart.sh) creates the case in an existing VM. | Live reconciliation opens exact gaps and retains the exact live task identity. In the qualified K3s distribution, one service restart covers its embedded kubelet and container runtime. |
| `ENTRY-REUSE-001` | Reuse PID and namespace number with [`native-pid-reuse.sh`](./native-pid-reuse.sh), recreate one cgroup path with [`native-cgroup-reuse.sh`](./native-cgroup-reuse.sh), and recreate one Kubernetes Pod and container name with [`kubernetes-reuse.sh`](./kubernetes-reuse.sh). | New full runtime IDs, cgroup IDs, cookies, nonces, and live intervals prevent old authority or response attachment. Source recovery rejects a reused cgroup ID when its live interval differs. |
| `ENTRY-SLEEP-001` | Execute a lifecycle sleep action. | It is only a lifecycle fact; no process entry is invented when no task exists. |
| `ENTRY-START-001` | Delay or drop configured start metadata. | The root stays conservative and the start gap remains explicit. Phase 4 owns effect denial. |
| `ENTRY-STOCK-HOOK-FAILURE-002` | Use [`kubernetes-stock-hook-failure.sh`](./kubernetes-stock-hook-failure.sh) to time out a valid prestart request, mismatch its container ID, and remove its Pod UID. | Each configured OCI hook failure stops container creation before the payload marker. There is no held-task, purpose, policy-effect, or CRD-delivery claim. |

This work establishes identity. Local enforcement owns permission tables and
physical file, network, and exec denial, so these cases do not claim a policy
denial.
