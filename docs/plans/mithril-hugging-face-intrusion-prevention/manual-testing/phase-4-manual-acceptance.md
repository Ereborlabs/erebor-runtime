# How To Manually Accept Phase 4

Status: **Not done** for the complete phase. The signed path-tree denial claim
is **Done** for the tested mount forms. The remaining unsupported capabilities
and the stock-runc administrative bootstrap keep the phase open.

- Phase: [Signed Local Pre-Effect Enforcement](../phase-4-signed-local-pre-effect-enforcement.md)
- Setup: [`SINGLE-NODE`](./environment-setup.md)
- Closure: [local fixture matrix](../phase-4-closure-matrix.md)
- Review: [implementation review guide](../phase-4-implementation-review.md)

## Outcome

Prove every qualified non-network local deny occurs before the named physical
effect, exceptions cannot exceed their authority, and unchanged legitimate
work continues.

## Automated Companion

```sh
rtk cargo build --locked -p mithril-node --bins \
  -p mithril-control --bin mithril-policy \
  -p mithril-e2e --bin mithril-effect-test

sudo target/debug/mithril-effect-test --repo-root . physical-probe \
  --protect \
  --output-directory /tmp/mithril-local-enforcement-final \
  --pin-root /sys/fs/bpf/erebor-mithril-local-enforcement-final \
  --lease-path /tmp/mithril-local-enforcement-final/owner.lock \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-local-enforcement-final
```

The probe is assertion-bearing and self-cleaning. It uses the production
libbpf-rs loader and BPF object, not a second test implementation. It retains
only its JSON result under the requested output directory. Its current exact
slice covers exact file open/read/mmap/mprotect allow and deny, exact
file-backed exec controls and denials across the represented entry variants,
exact character-device ioctl allow and deny, unmatched signal and exact ptrace
denial, configured AF_UNIX `SOCK_STREAM` relationships, concurrent N/N+1
exception consumption, hard-link/bind aliases, denied protected mounts,
successful protected and allowed bind aliases, recursive binds, `open_tree`
plus `move_mount`, external mount replacement, reconciliation, ring
saturation, latency, and cleanup. A denied mount mutation remains a separate
mount-policy result.
Unqualified anonymous and memfd execution, file mutation, SysV IPC, namespace
creation, BPF map creation, and pinned-link removal remain hard closed. An
exact file-backed exec control does not prove immutable executable authority.

The probe records the BPF mount-cache keys before the first protected file
effect. The effect must apply the exact policy and publish a new `READY` cache
state with a nonzero mount count. After each successful mount change, the next
protected effect must use a new stable namespace event and mount-tree snapshot.
Node does not rebuild a running task's mount topology.

The real `mithril-node` Docker and raw-namespace cases live in
[`examples/mithril-local-enforcement-manual`](../../../../examples/mithril-local-enforcement-manual/README.md).
Run the individual shell for the behavior under review; each installs an EXIT
trap before starting the node and removes Mithril-owned pins, leases, processes,
mounts, sockets, FIFOs, and temporary state. It leaves the supplied container
and cgroup intact. The prepared task waits on a FIFO; the host does not signal
it after policy activation. The checked policy
includes exact benign, executable, and device allow and deny controls; exact
process-control denials; exact AF_UNIX relationship allow and unmatched-policy
deny controls; and a two-use exact write-open exception. Raw BPF map creation
remains in the automated probe because it uses the vendored libbpf API instead
of copied architecture-specific syscall numbers.

## K3s CRI Paired Control

The disposable K3s lane uses one real `kubectl exec` task and two exact
read-only hostPath files. It verifies the secret denial and the benign allow
control in the same task. Run the lane with:

```sh
rtk proxy bash crates/mithril-e2e/harness/vm/run.sh \
  --with-k3s \
  --skip-administrative-exec \
  --output-directory /tmp/mithril-k3s-cri-control
```

Inspect `k3s-cri-observe.txt` and `k3s-cri-effect.txt` before using later
probe output as an overall result. The CRI files are complete evidence when
they show these facts for one task cookie:

- Observe: secret selector `manual-secret` (handle
  `943398411243188049`) is `WOULD_DENY`; benign selector
  `manual-benign` (handle `442755278878333200`) is
  `EXACT_POLICY_ALLOW`. Both have `UNKNOWN_AFTER_PRE_EFFECT`.
- Protect: secret selector `manual-secret` is `EXACT_POLICY_DENY` with
  `DENIED_BEFORE_EFFECT` and `kernel_result=-13`. Benign selector
  `manual-benign` is `EXACT_POLICY_ALLOW` with `kernel_result=0`.

For an operator-driven benign-only CRI case, use
[`cri-benign-allow.sh`](../../../../examples/mithril-local-enforcement-manual/cri-benign-allow.sh).
It does not prove the secret-deny half, projected-token rotation, or the
administrative-exec path.

## Dated Qualification Records

Each record below applies only to its named source state and date. Its old
status sentence does not override the final closure record.

### Signed Exact selectors from containerd Running inventory — 2026-08-21

State: **Done** for signed selector authority and Exact binding after an
authenticated CRI `Running` transition. Exact binding before process start is
**Not done** on the qualified stock containerd interface.

The retained x86_64 K3s VM `mithril-runtime-qualification-344630` ran the final
node binary with SHA-256
`904088e728a6e8eead6b25c2d1976082a4a54c52f369bfe9fbf2a57b7ea63f34`.
The VM, K3s installation, image cache, and empty controller cgroups remain
available for compatible later tests.

The OBSERVE output is
`/tmp/mithril-session-exact-20260821/k3s-cri-observe-final.txt`, SHA-256
`6af613db8e881be8f3cfc498ee5646821bb2bf2a19826c26271a5e99c85a5c1b`.
Direct CRI and `kubectl exec` roots were
`runtime_external_restricted`. Both secret reads used signed selector handle
`943398411243188049` and reported `WOULD_DENY` with kernel result 0. The
benign read used signed selector handle `442755278878333200` and reported
`EXACT_POLICY_ALLOW` with kernel result 0.

The PROTECT output is
`/tmp/mithril-session-exact-20260821/k3s-cri-protect-final.txt`, SHA-256
`29ef205dc4d09a89392fa1fcc31a5d3a249810b3c3508de24617da284afbf0ed`.
Direct CRI and `kubectl exec` secret reads reported `EXACT_POLICY_DENY`,
`DENIED_BEFORE_EFFECT`, and kernel result -13. The benign Exact read remained
allowed. Both lanes exited 0 after they removed their Pod, namespace, pins,
node process, and lane state. The dedicated controller cgroup was empty and
reusable after each node exit.

Each output records
`exact_binding_stage=containerd-running-inventory` and
`initial_binding_start_gap=recorded:container-running-before-node-binding`.
The OCI prestart identity hook does not resolve Exact selectors because the
qualified runc task does not yet expose its final mount topology.

The administrative-exec diagnostic reached signed Exact executable binding
without a node-config object. It then failed before the approved process exec:
the policy-active runc bootstrap used unlabelled read-mode process inspection
and an anonymous bootstrap pipe, and the process-control and unsupported-file
floors denied those operations. Its diagnostic output SHA-256 is
`72708b25d1f098410d0ee27869af7f9b0ec2ad07eea2b0e2a4dcee360b0e552e`.
This is **Not done** for policy-active administrative runc bootstrap. It does
not change the passing CRI Exact result. A future fix needs explicit runtime
bootstrap authority; it must not add a broad runtime bypass.

### Retained VM alias and mount evidence — 2026-08-15

At source `5b1abfa984d0`, a retained x86_64 VM ran the existing
`mithril-effect-test physical-probe --protect` owner with unique state paths.
The JSON artifact SHA-256 is
`9cfda0507593f4b2b2ca040d58f2bb03d922bbf2cc0f93d182ec746859157dca`.
The binary SHA-256 is
`8426f68d285187e74e39bfadadeb57c3595a944a200001df639a685116bbfd1b`.
The embedded BPF object SHA-256 is
`69ee79417f875f7c7a7065d18e08918e9d9bc32359711b57013eba77879fbcbe`.

The record has `bind_alias_canonicalized=true`,
`mount_stale_proposal_failed_closed=true`,
`protected_mount_race_denied=true`,
`external_mount_replacement_failed_closed=true`, and
`exact_object_restored_after_reconciliation=true`. It also has
`mount_propagation_reached_peer=true`,
`mount_propagation_all_views_failed_closed=true`,
`mount_propagation_reconciled=true`,
`mount_setattr_global_invalidation=true`, and
`mount_setattr_reconciled=true`. The cleanup fields
`pin_root_removed=true`, `lease_removed=true`, `cgroup_removed=true`, and
`fixture_root_removed=true`. This is automated evidence for the implemented
alias and mount-CAS slice. It does not replace the manual matrix in this
document. The phase remains **Not done**. The administrative runc bootstrap
sequence remains unsupported.

### CRI Bind Alias And Mount Attack — 2026-08-16

A fresh manual K3s VM ran two readable CRI cases with one bound Python 3.12
container. The working tree was based at `78f12f568b2e8fb8de89d2fbc667aef3824eddfb`.
The bind-alias script SHA-256 was
`8ffca2db77acd95d87b669374a5cf1246829e2e5221f401bac468c891b83b74d`.
The mount-attack script SHA-256 was
`51a14ad266eb02c3d8c2af22cabab1bc3ffecc7470b50dec0814b665bca336df`.

`nsenter-bind-alias-deny.sh` created two file bind aliases before activation.
Its Python probe opened both aliases after release. The script required two
key-7 `EXACT_POLICY_DENY` events and a `DENIED_BEFORE_EFFECT` result. It exited
0.
Its output SHA-256 was
`09e3b76ee1a37afd563eb0c4b6171dbcfa86a25510f4c14b1d9854665eae35e7`.

`mount-attack-deny.sh` started eight Python `mount(2)` attempts after
activation. The script required `EACCES` or `EPERM` from every call, at least
eight `UNSUPPORTED_OBJECT` events, and a later exact protected-file denial.
It exited 0. Its output SHA-256 was
`3f2e2a62c5281b2a1750f4c6d12f19649e8a8f1e9a3a0797886e2c3c9655c73c`.

Each case removed its node, pins, lease, state, sockets, and mounts. The
outer runner removed its Pod, namespace, and fixture. Final inspection found
no Mithril pin or process. Only unrelated BPF link 1 remained.

This is one CRI bind-alias case and one CRI mount-attack case. It does not
qualify propagation, idmapped mounts, token rotation, or administrative exec.
The phase remains **Not done**.

### Automated successful-mount proof — 2026-08-21

State: **Done** for the tested path-tree mount forms.

The retained x86_64 qualification VM ran the protected physical probe from the
current working tree. The test used the production BPF object. It required
successful mounts and completed reconciliation before it accepted a
path-tree denial.

The result records these fields as true:

- `path_tree_preexisting_bind_alias_denied`
- `path_tree_postactivation_bind_alias_denied`
- `allowed_bind_alias_allowed`
- `path_tree_recursive_bind_alias_denied`
- `allowed_recursive_bind_alias_allowed`
- `path_tree_move_mount_alias_denied`
- `allowed_move_mount_alias_allowed`
- `path_tree_outside_control_allowed`
- `pin_root_removed`
- `lease_removed`
- `cgroup_removed`
- `fixture_root_removed`

Each protected alias emitted `PATH_TREE_POLICY_DENY`. Each matching allowed
alias emitted `EXACT_POLICY_ALLOW`. The recursive-bind source had no nested
submount. The new mount API case used `open_tree` plus `move_mount`.

### Self-contained manual VM cases — 2026-08-17

On the retained manual VM, the operator ran `nsenter-bind-alias-deny.sh` and
`mount-attack-deny.sh` with no arguments. Each script created its own Python
Pod, live CRI binding, and fixture. Each script printed `PASS` and removed its
Mithril state, Pod, and fixture.

The bind-alias case denied both pre-existing aliases as exact object key `7`.
The mount-attack case denied all protected mount attempts and the later
protected open. These are one-container manual cases. They do not qualify
path access after a successful child-directory bind, propagation, idmapped
mounts, token rotation, or administrative exec. The phase remains **Not
done**.

### Signed path-tree denial — 2026-08-17

State: Superseded. This record proves a narrower path-tree and mount-denial
slice. This historical record left `FILE-PATH-TREE-DENY-001` **Not done**.

The disposable x86_64 VM harness ran exact implementation commit `d38248f`.
The kernel was `6.8.0-137-generic`, and the active LSM order included `bpf`.
The local-enforcement artifact is
`/tmp/mithril-path-tree-d38248f/local-enforcement-physical-probe.json`. Its
SHA-256 is
`fa91e8f1a3ee179285ec0d6ad7f592cc5a612d1d030d3f70ffefd9cec6898a3b`.
The production BPF object SHA-256 is
`edf9d9941e8bd3bbc8ec0a04f32e5fec1adc1571b8b1b508b8c4ab8a994d6943`.

The artifact records these true fields:

- `path_tree_preexisting_child_denied`
- `path_tree_meta_depth_denied`
- `path_tree_future_namespace_denied`
- `path_tree_later_child_denied`
- `path_tree_replacement_child_denied`
- `path_tree_outside_control_allowed`
- `path_tree_mount_attack_failed_closed`

The last field means that the attempted mount operations failed. It does not
mean that a child-directory bind succeeded and a later alias access denied.

The same run denied a managed `CREATE` before it created the file. It installed
the graph before it created one test mount namespace, then moved that task to
the managed cgroup and required `PATH_TREE_POLICY_DENY`. An external bind
replacement also failed closed. The artifact records successful propagation
invalidation, `mount_setattr` reconciliation, `cgroup_removed=true`, and
`fixture_root_removed=true`.

An isolated retained harness VM then ran this documented command from the
root guest shell:

```sh
examples/mithril-local-enforcement-manual/mount-attack-deny.sh
```

It printed:

```text
PASS: every mount over the signed path tree was denied and no file retry widened authority.
Mithril, tasks, pins, state, lease, config, and logs removed.
```

The implementation accepts at most 255 canonical path components. Each
component accepts at most 255 bytes. The mount enumeration accepts 4,096
mounts. The red-black-tree scan stack accepts 255 entries, and the combined
mount and dentry walk accepts 4,351 callbacks. These are checked verifier
bounds. The proof does not qualify idmapped mounts, full propagation coverage,
token rotation, or administrative exec.

The corrected acceptance case must create the child bind before policy
activation, then read both a protected file and an allowed file through bound
subtrees. The protected file must deny with `PATH_TREE_POLICY_DENY`. The
allowed bound file and a file outside the protected tree must succeed. A
second case must let a separate qualified mount owner complete the bind after
activation, reconcile the namespace, and produce the same three results.

### Earlier local enforcement record — 2026-08-18

The repository VM harness passed at implementation commit `5dd695e`. The guest
ran x86-64 Ubuntu Linux
`6.8.0-137-generic` with BPF LSM, cgroup v2, runtime BTF, and unique mount
IDs.

The local-enforcement record is
`/tmp/mithril-phase4-full-after-fixes/local-enforcement-physical-probe.json`.
Its SHA-256 is
`04b1fdb9f5b86c884612a880d79fe272d45e79eaade69a1fc238808376eab465`.
The production BPF object SHA-256 is
`ca4dace998d14c6755d759bc7c20d0c21a34c40c18c75c317f4ea2a84b95cd64`.
The protected deployment digest is
`741a9fd0857e360a8b3096924f52dd59695d9f6440aa6610370e4e092b23b1dc`.

The record closes the represented physical rows for passed file descriptors,
file mappings, exact mount views, restricted io_uring, inherited and exact
Unix-stream relationships, process-control relationships, event saturation,
mount CAS, and mount
snapshots. The [closure matrix](../phase-4-closure-matrix.md) names the exact
14 Appendix C rows and their limits. The record also has:

- `new_roots_generation_published_atomically=true`,
  `existing_tasks_retained_old_generation=true`, and
  `old_generation_deleted_after_last_holder=true`;
- 10,000 measured opens and 50,000 saturation opens;
- 39,081 lost observation records during saturation while the policy denial
  and benign allow remained true; and
- `inherited_unix_stream_send_denied=true` with
  `unix_stream_relationship_allowed=true`; and
- `pin_root_removed=true`, `lease_removed=true`,
  `cgroup_removed=true`, and `fixture_root_removed=true`.

The identity source serializes external-root label publication against a
concurrent exit. The physical fixture uses explicit process barriers for
PID-namespace and `CLONE_INTO_CGROUP` transitions. Six consecutive identity
probes passed in one retained guest. The fresh full harness then passed the
identity probe with `profile_task_refs_after_exit=0`. The identity JSON
SHA-256 is
`fff4e3f494751c01b8e75c83e1515bbb16ce143ea4c93ac7e2e79c7c4dc66c99`.

The retained guest ran the derived-device slice at implementation commit
`e6da7a2`. The result is `/tmp/mithril-phase4-device-derived.json`, with
SHA-256
`1d10974f2bc42c62e645b6d3fa07605912f5f72165b448dff955edffb053a7a3`.
It records the exact allowed PTMX control, the hard-closed descriptor-producing
operation, no installed descriptor, and complete cleanup. This tier does not
advertise granular authority after a derived object is minted.

The retained guest ran the independent-root shared-mapping slice at
implementation commit `b6e5dea`. The result is
`/tmp/mithril-phase4-independent-mmap.json`, with SHA-256
`d41f0f133ffeb38b37431d5a77bf8515bfc5485f711120f94788ae375bf75b8f`.
The protected mapping denies, the benign mapping succeeds, and the decision
records prove distinct task, process-lineage, and process-instance identities.
This tier makes no per-load, per-store, or byte-taint claim after an admitted
mapping.

This result did not qualify the 14 rows that now have exact `UNSUPPORTED`
results. It did not qualify projected-token rotation, immutable content and
VMA provenance, complete self-protection, or administrative exec.

### Closure record — 2026-08-18

The retained isolated x86_64 VM ran the explicitly rebuilt standalone probe at
implementation commit
`e0438d920d5071295ab733db0d7df0eb03a95b8c`. The probe binary SHA-256 is
`eee25b63425be5ec7ba8d7b9f8510cabea8c1b1af6aa832c90e1181373245fd0`.

The result is
`/tmp/mithril-phase4-e0438d9-final/local-enforcement-physical-probe.json`.
Its SHA-256 is
`8fc1f4ad4536d00afd29754255410fed4b1290c3a138687f51c70edac079c793`.
It records 15 `PASS`, 14 `UNSUPPORTED`, zero `FAIL`, and zero `DEGRADED`
fixture results. The exact statuses and reason codes are in the
[closure matrix](../phase-4-closure-matrix.md).

The guest ran Linux `6.8.0-137-generic` with cgroup v2 and BPF LSM. The active
LSM order was `lockdown,capability,landlock,yama,apparmor,bpf`. The runtime BTF
SHA-256 was
`6da9f6b4ebcae9b07e6a717b517884abf7f6b524e46340e40fb164eed4a49a7c`.
The protected deployment digest was
`741a9fd0857e360a8b3096924f52dd59695d9f6440aa6610370e4e092b23b1dc`.

The result has 10,000 measured opens and 50,000 saturation opens. It lost
39,081 observation records during saturation. The protected denial and benign
allow remained correct. `pin_root_removed`, `lease_removed`,
`cgroup_removed`, and `fixture_root_removed` are true. Independent postflight
found no probe pin root, cgroup, or owner lease.

The repository command `bash .github/scripts/verify-rust-ci.sh` passed at the
same implementation commit. One earlier run exposed an unrelated parallel
temporary-file collision in `start_preserves_absolute_policy_paths`. The exact
test passed alone, and the unchanged repository gate passed on rerun. Do not
use the transient first run as Mithril evidence.

## Procedure

1. Install a signed candidate generation only after complete readback and
   isolated allow/deny probes; record the one active-pointer CAS.
2. Run each fixture first in observe mode, then protect mode without changing
   the protected workload digest.
3. For each deny, inspect syscall errno and the named object/image/mapping/
   topology/kernel postcondition independently from the event stream.
4. Repeat with event saturation, missing dynamic state, earlier LSM denial,
   aliasing, object reuse, and concurrency.
5. Run each advertised legitimate control after every policy or fault
   variant.

## Fixture Matrix

| Fixture | Operator stimulus | Required protect-mode oracle and control |
| --- | --- | --- |
| `ADMIN-EXEC-APPROVAL-001` | approve one exact Kubernetes exec, then race matching/nonmatching/replay attempts | authenticated Control/admission/node chain; one atomic slot winner; exact exec commits; all reuse/expiry/mismatch attempts deny; ordinary approved admin action succeeds once |
| `DEVICE-DERIVED-001` | open/use/pass device and derived authority objects | forbidden device/ioctl/derived use changes no device/kernel state; approved device operation succeeds |
| `FILE-CONTENT-RACE-002` | mutate content/object between classification and use | stale trusted identity never authorizes; immutable approved object succeeds |
| `FILE-FD-PASS-001` | inherit/pass/reuse a protected file fd | current forbidden actor receives denial/no bytes or mutation; approved recipient works |
| `FILE-IDENTITY-001` | use symlink/hardlink/bind/proc-fd/overlay aliases | every forbidden alias returns denial and no fd/effect; declared object path works |
| `FILE-MMAP-001` | map forbidden file for read/write/execute | forbidden mapping absent; allowed mapping exists with exact state |
| `FILE-MMAP-SHARED-011` | share writable mapping across roots | forbidden acquisition/attachment denies or exact supported floor applies; no byte-taint claim |
| `FILE-NAMESPACE-001` | access same spelling/object across mount views | actor-specific exact-object decision; allowed view succeeds and denied view has no effect |
| `FILE-PATH-TREE-DENY-001` | install before one namespace exists; complete a child-directory bind before activation; let a separate qualified mount owner complete one after activation; reconcile; read protected and allowed bound subtrees; read old, new, and replaced children; create a child | every protected effect denies through the successful aliases before an fd, byte, or filesystem mutation; the allowed bound subtree and outside-tree control succeed; a live mount replacement or topology race fails closed |
| `FILE-SA-TOKEN-OPEN-001` | worker and controller access rotating token | worker gets `EACCES` and no fd/positive bytes; controller succeeds; rotation cannot create a gap |
| `FILE-VMA-SNAPSHOT-001` | race response/policy decision with VMA changes | incomplete snapshot never relaxes; complete approved snapshot permits its control |
| `HF-LOCAL-001` | run safe in-process protected-file/effect sequence | first distinguishable forbidden effect is prevented; no later prohibited stage; clean conversion succeeds |
| `IPC-ASYNC-UNSUPPORTED-010` | use unqualified async/SQPOLL path | deny or advertised unsupported result; normal qualified synchronous control works |
| `IPC-PEER-RACE-004` | race peer exit/restart/reuse | stale peer never matches allow; exact live approved peer communicates |
| `IPC-PROCESS-CHANNEL-009` | attempt directional process control/channel use | forbidden direction/operation denies physically; explicitly allowed direction works |
| `IPC-RELATIONSHIP-ALLOW-003` | declared independent roots communicate | configured channel operation succeeds without merging identities |
| `IPC-RELATIONSHIP-UNMATCHED-005` | unknown/wildcard/reused peer communicates | configured unmatched deny/restriction occurs; declared peer control still works |
| `STATE-FORK-IPC-002` | fork while pipe/socket state is inherited | inherited family restriction remains active; the later public send receives the configured result |
| `EXEC-CONCURRENT-002` | race exec attempts with real source and target policy roles | one staged decision; no losing thread or child completes the forbidden effect |
| `STATE-THREAD-RACE-001` | race a policy role transition with a protected effect | each effect sees one complete policy state; no stale authority completes |
| `LSM-DENY-SATURATION-001` | fill event path during repeated forbidden effect | every syscall remains denied while loss rises; allowed control remains correct |
| `MEM-EXEC-001` | execute memfd/deleted/file/anonymous mapping or mprotect transition | forbidden executable memory/image never begins; approved immutable image/mapping succeeds |
| `MEM-KERNEL-MAP-002` | exhaust/corrupt/race mm/VMA state | missing required state denies; full valid state allows control |
| `MOUNT-ATTR-001` | attempt old/new mount, bind, propagation, idmap, recursive attrs | undeclared mutation absent; approved fixture mutation enters/clears DIRTY exactly |
| `MOUNT-CAS-002` | race concurrent topology transitions | only one consistent generation commits; conflict cannot open file/exec authority |
| `MOUNT-PROPAGATION-003` | propagate mount while protected opens loop | no post-DIRTY strict open until every affected view reconciles |
| `MOUNT-SNAPSHOT-004` | provide complete and incomplete snapshot variants | incomplete stays dirty/denied; complete approved topology resumes |
| `SELF-PROTECT-001` | mutate/detach/replace Mithril links/maps/pins/config/binary | intact floor denies where qualified; successful tamper closes capability/coverage and never claims self-containment |
| `STATE-PERSISTENT-FILE-LIFETIME-007` | reuse persistent volume/file identity after close/restart | old restriction follows exact live object only; new object cannot inherit clean authority by name |

## Concurrent Exec Control Result — 2026-08-17

The x86_64 Ubuntu 24.04 VM, kernel `6.8.0-137-generic`, ran
[`native-child.sh --concurrent-thread-exec`](../../../../examples/mithril-identity-manual/native-child.sh)
as root. Two sibling Python threads waited on one barrier and both called
`exec`. Linux retained one `sleep` process. The survivor kept the root creator,
process state, and restricted role, changed execution and image IDs, and had
no exec guard. The shell printed `PASS` and removed its Kubernetes Namespace,
Pod fixture, node, pin, lease, and cgroup.

The paired source control required four identity-ID allocations and two
distinct live task coordinates. Its JSON SHA-256 is
`6438be6817109b6592fb60bd39fd50e061528fcc8615f5403037c4bcc5a0ee08`.
This proves normal Linux two-thread exec behavior only. It does not qualify
`EXEC-CONCURRENT-002`, which still needs real source-role and target-role
transitions plus a raced protected-effect oracle.

## Mandatory Incident And Exception Checks

- `HF-008`: the safe in-process driver receives no forbidden fd or bytes from
  the protected object; the normal conversion object succeeds. The baseline
  does not need a weaponized HDF5 or Jinja payload.
- `HF-002`-`HF-012`: every managed non-network branch uses its first real
  physical effect; pure computation and already-in-memory data are not called
  prevented.
- Bounded exceptions: run every `maximum_uses` value at N and N+1, concurrent
  consumers, unrelated rules/programs, expiry, restart, and consumed-denial
  variants. Only the decisive matching entry may consume.

## Required Artifacts And Pass Rule

Retain signed generation/readback/activation records, syscall results, object
and topology readback, exception receipts, admin approval/admission/slot traces,
loss counters, incident branch results, and legitimate controls. Pass requires
the physical negative oracle for every advertised deny.

## Troubleshooting

- If `kubectl-mithril` exits before it prints an activation URL, keep its
  terminal output. It prints the Control HTTP response body after a rejected
  draft. Use that result to correct the exact binding, policy, or mount-view
  state. Do not retry through raw `kubectl exec`.
- When you inspect retained effect observations, use each printed
  `observed_boottime_ns` value to order the denied operations. Do not infer the
  first denial from log order alone.
- The VM administrative fixture runs static BusyBox at
  `/var/lib/mithril/busybox`. Invoke it as
  `/var/lib/mithril/busybox sleep 20`. Do not rename this file to
  `admin-exec`; BusyBox would not find that applet.
- An event saying `deny` without errno and physical absence does not pass.
- A failed physical operation still consumes a bounded exception when safe
  refund cannot be proved.
- `NODE-FLOOR-EXCEPTION-002` belongs to Phase 8, not this runbook.
