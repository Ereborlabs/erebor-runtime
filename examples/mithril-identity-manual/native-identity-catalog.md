# Native Identity And Authorization Cases

[`native-child.sh`](./native-child.sh) supplies the required ordinary
native-child control. The fault, reparenting, and race rows stay in the catalog
until their exact qualification environment is run.

| Fixture | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `AUTHORIZATION-REPLAY-004` | Replay, retarget, expire, reboot, and mismatch a signed authorization. | Every invalid envelope rejects; a fresh exact envelope consumes according to contract. |
| `EXEC-COMMIT-STATE-001` | Run successful exec, pre-PONR failure, and post-PONR fatal/unknown exec. Run the pre-PONR branch with [`native-child.sh --failed-exec`](./native-child.sh). | Success commits once; early failure keeps exact prior state; later failure never restores broader authority. The procedure does not cover the post-PONR branch. |
| `EXEC-CONCURRENT-002` | Race execs across threads and non-leader de-threading. | One serialized valid transition occurs; image and role state never mix. |
| `ID-CGROUP-ESCAPE-001` | Move a labeled task to host/unprotected placement. | Task storage still resolves and constrains the mismatch; an unmoved control works. |
| `ID-CLONE-CGROUP-002` | Clone into expected and changed placement. | Child state exists before its first effect and placement is verified. |
| `ID-CLONE-CGROUP-FAIL-003` | Force child allocation, finalization, or placement failure. | No unlabeled runnable child gains authority; a normal clone succeeds. |
| `ID-CREATOR-PARENT-007` | Reparent or orphan a child after native creation. Run the creator-exit branch with [`native-child.sh --orphan`](./native-child.sh) and the double-fork branch with [`native-child.sh --double-fork`](./native-child.sh). | The immutable creator edge stays exact while the real-parent interval changes. The procedures do not cover subreapers, namespace-init reparenting, ptrace reparenting, or PID reuse. |
| `ID-MOVED-PARENT-FORK-004` | Move a parent, then fork. | The child inherits actual task authority and the placement floor, not a cgroup-derived role. |
| `ID-MOVED-TASK-EXEC-005` | Move a stopped labeled child, then exec. Run [`native-child.sh --moved-exec`](./native-child.sh). | The task and creator cookies stay exact. The moved child becomes fail closed and cannot exec `sleep` through host policy. |
| `ID-TASK-COORD-FINALIZE-006` | Inspect allocation, pre-wake finalization, visibility, and exit. | Opaque state precedes effects; coordinates finalize later without granting permission. |
| `NATIVE-STATE-REF-LIFETIME-001` | Exit tasks/processes while sockets, objects, or generations remain referenced. | Exact references and tombstones retain restrictions until final qualified release. |
| `STATE-FORK-IPC-002` | Fork with inherited IPC, file, and socket state. | Native state inheritance is exact; communication does not merge independent roots. |
| `STATE-THREAD-RACE-001` | Race threads changing and using process/native restrictions. | The result is atomic and monotonic; no thread recovers earlier authority. |

The identity half of `ADMIN-EXEC-APPROVAL-001` must bind target node/container,
entry class, optional slot identity, expiry, and replay state. Local enforcement must
still prove approval, atomic consumption, exec commit, and physical effects.
