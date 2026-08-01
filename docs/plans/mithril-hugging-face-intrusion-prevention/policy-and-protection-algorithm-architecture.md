# Mithril Policy And Protection Algorithm Architecture

Status: Proposed architecture companion. This document does not authorize an
implementation phase. An approved phase may implement only the part assigned
to it by the
[Mithril Hugging Face Intrusion Prevention Master Plan](./README.md).

Normative acceptance:

- [Hugging Face Adversarial Acceptance](./hugging-face-adversarial-acceptance.md)
- [Live Two-Node Lifecycle Probe](./live-two-node-lifecycle-probe.md)

Research inputs:

- [Erebor Defender: Linux Enforcement, Correlation, and Response Engineering](../../research/erebor-defender-learning-from-tetragon-and-falco.md)
- [Mithril Single-Gatherer Architecture and Upstream Adoption Plan](../../research/erebor-warden-single-gatherer-architecture-plan.md)
- [Hugging Face Agent Intrusion: Erebor Defender Implementation Analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Hugging Face Agent Intrusion: Published Live Action Stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

## Purpose

The phase files say when Mithril builds each capability. This document says
what the finished policy system means and which algorithm handles each
Hugging Face incident situation.

It is deliberately more specific than a product description. An implementer
should be able to derive Rust owners, BPF maps and hooks, policy schemas,
decision order, failure behavior, and adversarial tests from it. A reviewer
should be able to object to an explicit decision rather than infer one from a
phrase such as “anomalous process.”

The target is an unchanged application deployment. Mithril may install node
security integration, BPF programs, a runtime admission transport, and audit
collectors, but the baseline cannot require one job per Pod, one job per
process, application instrumentation, a different ServiceAccount, narrower
RBAC/IAM, a sidecar, a TLS proxy, or a modified agent harness.

## Decision Summary

The proposed architecture makes these decisions:

1. A container is a **container execution set**, not necessarily one native
   tree. Its ordinary entrypoint, kubelet-created exec probes and lifecycle
   commands, administrative exec sessions, and other runtime-created tasks can
   be distinct native roots inside the same container.
2. Every root enters through an authenticated, one-use **entry admission**.
   Native descendants receive their label in kernel before they can perform a
   protected effect.
3. A task is authorized by its exact task/process identity and current role,
   not by its comm, path, PID, Pod name, namespace numbers, or cgroup alone.
4. Policy controls physical effects: executable transitions, file and code
   objects, sockets and packets, devices and ioctls, privileges, kernel
   interfaces, and control-plane operations. It does not pretend to recognize
   malicious intent inside Python.
5. Local decisions are deterministic and synchronous in kernel. Central
   correlation is asynchronous and never sits in a syscall decision loop.
6. Direct TLS is preserved. Operations inside the same allowed TLS channel are
   distinguished only by authoritative server/provider evidence; if that
   evidence arrives after completion, the result is detection and containment,
   not prevention.
7. Prevention continuity and evidence continuity are separate. A full
   ring-buffer or disconnected control plane cannot turn a loaded deny into an
   allow. Missing evidence prevents a negative conclusion.
8. The policy model is extensible. The Hugging Face package is the first set of
   roles, effects, causal predicates, and responses, not a special-purpose
   command signature engine.

These are proposed defaults. The final section lists the decisions that need
explicit approval or a replacement with equivalent proof.

## Claim Boundary

Mithril can protect a Linux or Kubernetes estate on which it is installed. It
cannot retroactively control `HF-001` through `HF-007` in OpenAI's external
evaluation environment, and it cannot claim to reject the uploaded HDF5 or the
Jinja expression itself without an application-owned content gate.

For `HF-008` through `HF-021`, the baseline claim is:

```text
hostile content may reach an existing interpreter
  -> Mithril denies the first distinguishable out-of-profile physical effect
  -> the denial is attached to an exact native execution and policy generation
  -> allowed or already-completed effects are correlated through exact
     Kubernetes/provider identities
  -> the smallest authorized local and remote scopes are contained
  -> postconditions and unresolved branches are reported
```

The following examples define the boundary:

- `os.environ` reading environment already resident in the same Python address
  space has no file syscall for Mithril to deny. Opening
  `/proc/self/environ`, a projected token, or another file does.
- Evaluating attacker-controlled Python inside an existing interpreter may
  create no exec event. `python -> sh`, `python -> curl`, an executable mapping,
  a protected file read, or a socket effect does.
- A new connection to IMDS can be denied by process role and destination. A
  forbidden Kubernetes verb inside a connection that the same role already
  needs is known from Kubernetes audit, not from encrypted packet bytes.
- Git clone and Git push can share a host, port, credential, and TLS
  connection. With no TLS interception and no attenuated provider capability,
  the node cannot honestly distinguish them. Provider audit can detect the
  server-side write and trigger a whole-channel or principal response.

## Source-Derived Mechanism Decisions

KubeArmor and Tetragon are implementation studies, not product chassis. Phase
0 still owns the per-file license and provenance decision. Nothing in this
document authorizes copying source.

### What to learn from KubeArmor

| Source mechanism | Useful lesson | Mithril adaptation | What Mithril must not inherit |
| --- | --- | --- | --- |
| [`enforcer.bpf.c`](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c) attaches BPF LSM programs at exec, file, socket, and capability decision points | Select semantic pre-effect LSM hooks and return a denial before completion | Organize owned CO-RE programs by effect family and preserve the earlier LSM return value | A missing protected-container map, scratch map, or path must not silently return allow |
| [`rulesHandling.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go) compiles higher-level process/file/network/capability rules into bounded map keys and bit masks | Keep policy parsing and conflict resolution in userspace; keep the kernel tuple compact | The Rust compiler produces reviewed immutable generations and finite role/effect keys | Paths and “from source path” are not durable process roles or executable identity |
| [`shared.h`](../../../KubeArmor/KubeArmor/BPF/shared.h) and [`mapHelpers.go`](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go) use a map-of-maps for per-container generations | Map indirection is a practical atomic policy-generation technique | Bind a stable workload/profile generation to a cgroup identity, then switch one active-generation pointer | PID and mount namespace numbers are reusable context, not the workload key |
| The main exec enforcer retains its decision when ring-buffer reservation fails | Enforcement and alert transport must be independent | Compute and commit the return value before best-effort evidence emission; increment loss counters on failure | Some presets, including [`protectenv.bpf.c`](../../../KubeArmor/KubeArmor/BPF/protectenv.bpf.c), [`filelessexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/filelessexec.bpf.c), and [`anonmapexec.bpf.c`](../../../KubeArmor/KubeArmor/BPF/anonmapexec.bpf.c), return allow when event reservation fails; that ordering is forbidden |
| Fileless exec, anonymous executable mapping, `/proc/*/environ`, and process inspection presets choose concrete kernel hooks | These are useful object classifiers and acceptance cases | Make them ordinary role-aware effect classes with explicit policy and coverage | A global preset keyed only by container namespace cannot decide which process role legitimately needs the effect |
| [`nriHandler.go`](../../../KubeArmor/KubeArmor/core/nriHandler.go) explicitly records that `StartContainer` occurs after start, namespace IDs can be reused, and enforcement is removed before shutdown | Runtime callback timing and teardown order are security properties | Full protection requires a pre-exec gate, exact lifetime identity, and policy retained through `preStop` and termination | Post-start binding cannot be advertised as enforce-from-first-exec; stop notification cannot remove policy before the last task exits |
| [`processTree.go`](../../../KubeArmor/KubeArmor/monitor/processTree.go) enriches a userspace PID tree and falls back to procfs | Procfs recovery is useful for explicit bootstrap and display | Reconstruct existing tasks as `bootstrapped` and retain the gap | A userspace PID cache is not race-free lineage or actuator identity |

#### Practical KubeArmor lesson examples

The table above is intentionally compact. The following examples make each
lesson concrete and state why Mithril adopts one part of the mechanism without
inheriting the weaker identity or failure behavior around it.

##### 1. Put the decision at the semantic LSM effect hook

**Example.** A dataset-conversion Python process tries to open the projected
service-account token at
`/var/run/secrets/kubernetes.io/serviceaccount/token`. An exec-only sensor sees
no new command because Python calls `open(2)` in-process. A BPF LSM
`file_open`/`inode_permission` decision can reject that operation with
`EACCES` before any token byte reaches Python. The same principle applies when
the process calls `connect(2)` or requests a capability: decide at the hook
that mediates the real effect, not by guessing from a preceding command.

**Mithril adoption.** Implement owned, small CO-RE BPF LSM programs for file,
exec, socket, and capability effect families. Resolve the already-attached
task role and immutable policy generation, calculate the decision, preserve a
prior denial, and only then attempt to emit evidence.

**What not to inherit.** A lookup failure must not mean “unprotected” merely
because a task-to-container map, scratch map, path buffer, or classifier entry
is missing. For a task already proven to be in a protected cgroup, such a miss
is an identity or coverage failure and follows the profile's fail-closed rule.

**Why.** Otherwise an attacker does not need to evade the policy. It only
needs to create map pressure, hit an unhandled path shape, or race startup so
that the enforcement program returns allow.

##### 2. Compile rich policy in userspace and keep kernel decisions finite

**Example.** A policy author writes: “the `conversion-worker` role may read
the checked-out dataset and write `/work/output`, but it may not read projected
credentials.” The Rust compiler can resolve mount-aware object identities,
conflicts, and defaults once, then lower the result to bounded keys such as
`(profile_generation, role_id, effect_class, object_class) -> decision`.
The BPF program does not need to parse YAML, traverse an arbitrary rule list,
or resolve precedence on every `open(2)`.

**Mithril adoption.** Use the KubeArmor pattern of userspace compilation and
compact kernel maps, but make the Rust compiler produce a validated,
immutable, signed generation with deterministic conflict resolution and a
reviewable compiled manifest.

**What not to inherit.** Do not make `/usr/bin/curl`, `python`, a process name,
or “started from this path” the durable role. An approved updater and a
compromised dataset worker may both execute the same `/usr/bin/curl`; the
attacker can also copy or rename a binary.

**Why.** A path identifies an object in a particular mount view. It does not
prove why the process exists, which admitted entry created it, or which
authority it should have.

##### 3. Use map indirection for atomic generations, not namespace identity

**Example.** Profile generation 12 is active while a reviewed generation 13
is loaded. Mithril populates generation 13 completely, verifies it, and then
atomically changes one binding pointer. A new decision sees either all of 12
or all of 13; it never sees a half-populated mixture. Generation 12 remains
resident while an existing task or socket still references it.

**Mithril adoption.** Use a map-of-maps or equivalent BPF map indirection to
bind a live cgroup interval and execution set to one immutable policy
generation, with explicit reference retirement.

**What not to inherit.** Do not key durable workload authority by PID
namespace, mount namespace, or an unqualified cgroup number. Container A can
exit and container B can later receive a reused numeric namespace or cgroup
identifier.

**Why.** Without a live interval, full container identity, and generation,
container B could inherit container A's permissions or containment state even
though the number happens to match.

##### 4. A full evidence channel must not cancel a denial

**Example.** Compromised code generates 100,000 forbidden exec attempts and
fills the ring buffer. The 100,001st attempt still returns `-EACCES`. Mithril
increments a per-CPU loss counter and later reports that evidence was dropped,
but the attempted shell does not start.

**Mithril adoption.** Follow the main KubeArmor exec enforcer's useful
ordering: calculate and commit the enforcement return value before reserving
or constructing an event.

**What not to inherit.** Do not copy preset paths that return allow when a
ring-buffer reservation fails.

**Why.** Alert transport is attacker-influenceable load. If event allocation
controls authorization, flooding telemetry becomes a deterministic policy
bypass.

##### 5. Treat presets as effect classifiers, not universal container rules

**Example.** Reading another process's `/proc/<pid>/environ` is expected for a
narrow diagnostic role but suspicious for a dataset converter. Anonymous
executable memory may be expected for an approved JIT runtime but forbidden
for an image-conversion worker. The kernel hook and object classification are
useful in both cases; the correct answer depends on the task's admitted role.

**Mithril adoption.** Reuse the underlying ideas—fileless execution,
executable anonymous mappings, environment inspection, and process
inspection—as explicit effect classes in the normal role/effect policy model.

**What not to inherit.** Do not turn them into global “container on/off”
presets keyed only by namespace or workload membership.

**Why.** A Pod can contain application, sidecar, probe, lifecycle, and
administrative execution roots with deliberately different budgets. A single
container-wide answer either blocks legitimate operation or gives the
compromised role excessive authority.

##### 6. Runtime timing must protect the first instruction through the last

**Example.** If enforcement is installed only after `StartContainer`, the
entrypoint can read a token and send it before the callback arrives. At the
other end, if policy is removed when `StopContainer` begins, a malicious
`PreStop` command can exfiltrate during the termination grace period.

**Mithril adoption.** Require a pre-exec admission handshake for strict
profiles, bind the exact root before its user image runs, and keep the binding
and referenced policy generations until the last protected task and socket
have exited or been explicitly invalidated.

**What not to inherit.** Do not advertise post-start discovery as protection
from first exec, and do not use a stop notification as proof that no protected
task remains.

**Why.** Startup and shutdown are attacker-usable execution windows, not
administrative bookkeeping outside the security boundary.

##### 7. Procfs recovery is evidence of a gap, not reconstructed certainty

**Example.** `mithril-node` restarts and discovers PID 4242 in a protected
cgroup through procfs. It can record executable, cgroup, namespace, and current
parent coordinates, but it cannot prove that no missed fork, exec, or
reparenting transition occurred while the sensor was unavailable. Later, PID
4242 can exit and the kernel can reuse the number.

**Mithril adoption.** Create an explicit `bootstrapped` observation with its
known coordinates, unknown interval, source quality, and conservative role so
operators can see and contain the affected execution set.

**What not to inherit.** Do not promote the reconstructed userspace PID tree
to exact birth lineage, use its cached PID as a later kill handle, or silently
close the missing interval.

**Why.** Procfs is a current snapshot. It cannot retrospectively prove event
order, and a PID is reusable. Exact response requires live re-resolution such
as pidfd plus start-time and cgroup validation.

One additional stacking rule is mandatory. BPF LSM programs receive the return
value from an earlier LSM/BPF program. Mithril never turns an earlier denial
back into success:

```text
if prior_ret != 0:
    record prior denial if possible
    return prior_ret
```

Mithril's policy can make a result stricter. It cannot weaken SELinux,
AppArmor, Landlock, another BPF LSM program, or an earlier Mithril program.

#### Practical LSM-stacking example

SELinux denies a write to `/etc/shadow` and passes a nonzero `prior_ret` into
Mithril's BPF LSM program. Even if Mithril's own profile would otherwise allow
the role to write the classified object—or Mithril cannot find its policy
map—the only correct return is that original nonzero value. Returning `0`
would not mean “Mithril has no opinion”; it would erase another active
security module's denial. This is why every Mithril LSM path checks and
preserves `prior_ret` before considering its own allow result.

### What to learn from Tetragon

| Source mechanism | Useful lesson | Mithril adaptation | What Mithril must not inherit |
| --- | --- | --- | --- |
| [`bpf_fork.c`](../../../tetragon/bpf/process/bpf_fork.c) observes `wake_up_new_task`, inherits parent execution state, and tests fork-without-exec | Fork, clone, thread creation, exec, de-threading, and exit need separate state transitions | Allocate exact task and process identities before a child can perform a protected effect; test every Linux creation variant | Tetragon skips the child when no parent exists in `execve_map`; a protected unknown child must instead fail closed and open a coverage defect |
| [`process.h`](../../../tetragon/bpf/lib/process.h) stores `(pid, ktime)`, parent keys, clone flags, namespace/capability state, and explicit miss/error flags | Native coordinates need time bounds and source quality flags | Retain host TID/TGID/start time as coordinates while using non-reused task/process cookies as durable identity | TGID-keyed execution state is not enough for per-thread identity, non-leader exec, PID reuse, or response authority |
| [`bpf_execve_event.c`](../../../tetragon/bpf/process/bpf_execve_event.c) and [`bpf_execve_map_update.c`](../../../tetragon/bpf/process/bpf_execve_map_update.c) stage exec collection across hooks and tail calls | Complex argument/object collection should be staged and verifier-bounded | Use a small pre-effect decision record and richer post-decision observation record | Rich event construction cannot be allowed to delay or determine the physical deny |
| [`policy_filter.h`](../../../tetragon/bpf/process/policy_filter.h) and [`policyfilter/state.go`](../../../tetragon/pkg/policyfilter/state.go) compile Kubernetes selection into policy-ID/cgroup maps | Filter and select in kernel using a node-resolved cgroup binding | Resolve exact Pod UID/container/image/profile in userspace, then install a generation-bound cgroup key | Labels, image tags, and a cgroup ID without its live interval are not durable identity |
| [`rthooks.go`](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go) and the [`OCI hook`](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go) obtain Pod, image, mount, and cgroup context before normal execution | Runtime metadata closes attribution gaps that the kernel cannot infer | Use authenticated runtime handoff plus live cgroup/task re-resolution | A create-container notification alone does not admit later `ExecSync`/streaming exec roots |
| [`cache.go`](../../../tetragon/pkg/process/cache.go) handles out-of-order events and garbage collection | The central graph must accept replay, duplicates, and late events | Immutable observations build versioned views; local WAL sequence exposes gaps | A userspace LRU record cannot authorize a syscall or irreversible response |
| [`fork_test.go`](../../../tetragon/pkg/sensors/exec/fork_test.go) exercises fork-without-exec | Kernel edge cases deserve real executable fixtures | Carry these cases into Phase 2 and the standing incident suite | A happy-path `fork -> exec -> exit` test is not sufficient identity proof |

#### Practical Tetragon lesson examples

##### 1. Label a child before fork-without-exec can perform an effect

**Example.** A Python conversion worker uses `multiprocessing` with `fork`.
The child does not call exec; its first action is to open the projected
service-account token. An exec-only process model never sees a new executable,
but the child is still a new task that needs inherited, restrictive authority
before it can run that `open(2)`.

**Mithril adoption.** Learn from Tetragon's early fork observation and parent
state inheritance. Allocate the child task identity and attach its inherited
role at a target-kernel-proven creation point before a protected effect can be
accepted.

**What not to inherit.** If the expected parent state is absent, do not skip
the child and continue. Attach `fail_closed_unknown` when possible, deny its
first protected effect, and open a coverage defect for the execution set.

**Why.** A missing parent can mean attach-after-start, event loss, unsupported
kernel behavior, or tampering. Treating every such child as invisible turns a
sensor gap into an attack path.

##### 2. Separate durable identity from PID and thread coordinates

**Example.** Thread TID 8102 in process TGID 8100 performs exec. Linux
de-threading can make the surviving task take different visible TID/TGID
coordinates. Later, an unrelated process may reuse PID 8102. An event or
response addressed only to `8102` can therefore attach to or kill the wrong
process.

**Mithril adoption.** Retain TID, TGID, start boottime, clone flags, and parent
keys as valuable coordinates and evidence, while assigning non-reused
`task_cookie`, `process_lineage_id`, and `execution_id` values for the node
boot and label epoch.

**What not to inherit.** Do not make a TGID-keyed map the sole owner of
per-thread role, non-leader exec state, or actuator authority.

**Why.** Linux exposes several identities whose relationships change across
clone and exec. Durable authorization needs a Mithril identity whose
continuity is explicit while native coordinates are revalidated at use time.

##### 3. Stage rich exec evidence without putting it on the deny path

**Example.** A worker attempts `/bin/sh -c 'curl ...'`. The pre-effect hook
needs only the exact task label, candidate executable object, interpreter
chain, and compiled edge to deny `/bin/sh` immediately. Full argv, cwd,
namespaces, hashes, and display strings are useful evidence, but collecting or
emitting them can fail or exceed verifier/tail-call budgets.

**Mithril adoption.** Use a small verifier-bounded pre-decision record and
stage richer post-decision observation across suitable hooks, as Tetragon
demonstrates for exec collection.

**What not to inherit.** Do not make successful tail calls, path rendering,
argument copying, or event reservation a prerequisite for the physical deny.

**Why.** Detailed telemetry improves investigation. It must not increase the
number of dependencies that an attacker can fail to obtain execution.

##### 4. Resolve Kubernetes selection to an exact live cgroup binding

**Example.** A policy selects Pods labeled `job=dataset-conversion`. Pod A
matches, exits, and is replaced by Pod B with the same name and labels. A
numeric cgroup identifier can also be reused after deletion. Pod B must receive
a new binding containing its exact Pod UID, full container ID, image digest,
cgroup live interval, and approved profile generation.

**Mithril adoption.** Learn from Tetragon's userspace selection and kernel
cgroup filtering, then install the resolved, exact binding in one atomic
generation.

**What not to inherit.** Do not let a label selector, image tag, Pod name, or
bare cgroup ID act as durable runtime authority.

**Why.** Selectors answer which current workloads should be considered.
They do not prove that a later task belongs to the same admitted workload or
policy lifetime.

##### 5. Runtime metadata admits an entry; it does not replace later entries

**Example.** An OCI hook supplies Pod UID, image digest, mounts, and cgroup for
the initial container process. Ten minutes later kubelet starts an exec probe,
or an administrator uses `kubectl exec`. Those are new runtime-created roots;
the original create-container hook does not run again and cannot explain why
either new process exists.

**Mithril adoption.** Use an authenticated runtime handoff to create the
initial execution set and `ContainerStartEntry`, then use separate one-use
`RuntimeEntryIntent` admissions for each later runtime exec.

**What not to inherit.** Do not treat membership in the original cgroup or
knowledge of the container-create event as authority for every later root.

**Why.** The same container can legitimately host roots with very different
purposes and budgets: application, probe, lifecycle, and administrator.

##### 6. Let the central graph repair evidence, never retroactively authorize

**Example.** Node events are delivered out of order: a socket connect
observation reaches the graph before the exec observation that explains the
new execution image. The graph may later recompute its versioned causal view
and attach the evidence correctly. The connect's local allow/deny decision,
however, was already made from kernel-resident task state and cannot depend on
that later cache repair.

**Mithril adoption.** Accept replay, duplicates, late events, loss markers,
and versioned recomputation in the userspace graph, following the operational
lesson in Tetragon's cache.

**What not to inherit.** Do not use an evictable userspace cache entry as a
syscall authorization record or issue `kill(pid)` from a stale graph node.

**Why.** Distributed evidence is eventually ordered; kernel effects are not.
Irreversible response must re-resolve and prove the current target.

##### 7. Turn fork edge cases into permanent executable acceptance tests

**Example.** A fixture forks a child that never execs, synchronizes so the
child attempts a protected token read immediately, and asserts that the child
already carries the expected restrictive role and receives `EACCES`. Related
fixtures cover `CLONE_THREAD`, `vfork`, non-leader exec, rapid exit, and PID
reuse.

**Mithril adoption.** Carry the fork-without-exec testing lesson into Phase 2
and keep the hostile identity matrix in every release gate.

**What not to inherit.** Do not accept only `fork -> exec -> exit` tests or
tests that verify an event appeared after the protected effect completed.

**Why.** The security claim is about identity being installed before the
child can act. A plausible event stream after the fact does not prove that
ordering.

The intended synthesis is narrow: KubeArmor demonstrates useful BPF LSM
decision points and policy lowering; Tetragon demonstrates useful kernel
lineage, cgroup filtering, lifecycle metadata, miss flags, and test patterns.
Mithril replaces their container/path/PID authority with its own exact task,
entry, role, coverage, and response contracts.

### Combined KubeArmor And Tetragon Lessons: One Mithril Pipeline

The mechanisms become useful together when they are arranged around one
Mithril-owned decision path rather than exposed as two independent policy
systems:

| Pipeline step | Mechanism learned from | Mithril's combined behavior | Concrete proof |
| --- | --- | --- | --- |
| Admit a workload root | Tetragon runtime metadata and cgroup binding | An authenticated runtime intent binds exact Pod, container, image, cgroup live interval, entry kind, role, and policy generation before execution | An unacknowledged initial root cannot execute under a strict profile |
| Preserve native lineage | Tetragon fork/exec state and miss flags | Kernel task state assigns a non-reused identity and restrictive role before each child can act; an exec transitions the existing lineage | A fork-without-exec child is denied the token read on its first operation |
| Decide the real effect | KubeArmor's semantic BPF LSM hook selection | File, exec, socket, and capability programs evaluate exact task role plus classified object before the effect | In-process Python `open(2)` is denied without needing a shell or exec event |
| Lower and update policy | KubeArmor's compact rule maps and map indirection | Rust compiles one reviewed immutable generation and atomically switches the exact workload binding | Concurrent decisions see all of generation 12 or all of 13, never a mixture |
| Preserve enforcement under telemetry failure | KubeArmor's useful deny-before-event ordering plus Tetragon's explicit miss evidence | Local denial survives ring/WAL/control-plane failure while loss counters narrow later claims | Filling the ring buffer loses evidence but never starts the forbidden command |
| Build explainable history | Tetragon's rich observations and out-of-order cache handling | Versioned local and multi-node graphs repair late evidence without becoming the syscall or response authority | A late exec event can repair causality but cannot retroactively justify an allowed connect |

#### Combined example A: compromised conversion code acts without a new command

1. The runtime admits the container root as entry `E1`, assigns the
   `conversion-worker` role, and binds policy generation 42 to its exact cgroup
   live interval.
2. A malicious dataset template executes inside the existing Python process.
   There is no new Linux process event, so lineage monitoring alone has
   nothing new to report.
3. Python opens the projected service-account token. The file LSM hook reads
   Python's exact task label inherited from `E1`, classifies the credential
   object, and generation 42 returns deny before bytes are read.
4. Python forks a child without exec. The Tetragon-derived lineage mechanism
   attaches a restrictive child role before the child runs. Its immediate
   token open is denied by the same KubeArmor-derived semantic hook.
5. The child tries to exec `/bin/sh`. The exec LSM hook denies the role
   transition. If the evidence ring is full, the deny still stands and a loss
   counter records reduced observability.

This is why an effect-only design and a lineage-only design are each
incomplete. Container-wide effect rules cannot distinguish the compromised
worker from a legitimate diagnostic root, while perfect lineage telemetry
without a semantic pre-effect enforcer only explains the intrusion after the
token or connection was already obtained.

#### Combined example B: a probe and an attacker run the same executable

Assume the PodSpec declares an exec readiness probe `/app/healthcheck`.

1. Before kubelet's probe reaches the runtime execution point, a one-use
   intent tied to the reviewed PodSpec digest admits its root as
   `KubeletExecProbeEntry` and assigns `kubelet-exec-probe`.
2. If the application forks and execs that exact same `/app/healthcheck`, the
   new execution remains a native descendant of `application-root`. Matching
   the filename does not let it claim probe authority.
3. If an attacker with `pods/exec` permission requests the same command, the
   streaming exec is admitted, if policy permits it at all, as
   `AdministrativeExecEntry`; it does not receive the probe role.
4. File and network LSM decisions can therefore give the real probe only its
   small health-check budget while denying the application descendant and the
   administrative root from reading credentials or opening unrelated
   connections.

Tetragon's runtime/cgroup/lineage lessons establish *which execution this is*.
KubeArmor's LSM/policy-lowering lessons establish *whether this execution may
perform this effect*. Mithril needs both answers in the same task label and
generation; running two disconnected agents or reconciling two policy engines
afterward would reintroduce races and disagreement.

## Protection Invariants

These invariants apply across all phases once the owning capability is enabled:

| ID | Invariant |
| --- | --- |
| `INV-ENTRY-001` | Every task performing a protected effect has either a verified native-parent label or a verified external-entry admission. |
| `INV-ENTRY-002` | An unlabeled task in a protected cgroup is denied at its first protected hook unless it atomically claims a matching one-use entry intent. |
| `INV-ENTRY-003` | Reparenting, PID reuse, namespace reuse, cgroup reuse, runtime restart, or kubelet restart cannot change a task's birth lineage. |
| `INV-ROLE-001` | A role is assigned by an admitted entry or approved transition; executable path and process name alone never assign authority. |
| `INV-ROLE-002` | Fork without exec receives a restrictive inherited child role and remains enforceable. Exec without fork retains process identity and creates a new execution identity. |
| `INV-EFFECT-001` | The most specific deny wins. Missing protected identity, generation, object classification required by policy, or response state fails closed. |
| `INV-EFFECT-002` | Event construction, rate limiting, ring-buffer pressure, WAL pressure, or control-plane availability cannot change a computed local denial into allow. |
| `INV-POLICY-001` | Only a signed, validated, locally compiled generation can enter enforcement maps. Observation never self-authorizes. |
| `INV-POLICY-002` | A policy update is atomic for new decisions; old generations remain until no live task or socket refers to them. |
| `INV-K8S-001` | Container start, runtime exec, exec probe, lifecycle exec, interactive exec, init container, sidecar, and ephemeral container are distinct entry classes even when they use the same binary. |
| `INV-K8S-002` | `preStop` and shutdown tasks remain protected. Termination is not an implicit policy bypass. |
| `INV-GRAPH-001` | Native parent edges never cross a node. Remote expansion uses typed causal edges with named proof. |
| `INV-RESPONSE-001` | A response re-resolves the live kernel/provider target and verifies a physical postcondition; a stale graph identifier is never an actuator handle. |
| `INV-COVERAGE-001` | A missing hook, sequence gap, bootstrap edge, ambiguous entry, or unavailable provider feed narrows the claim instead of being interpreted as benign. |

### Practical Protection-Invariant Examples

Each invariant is a release property, not an aspirational alert rule. These
examples state an action that a hostile acceptance fixture can perform and the
result an implementation must prove.

| Invariant | Practical example | Required result and why |
| --- | --- | --- |
| `INV-ENTRY-001` | The labeled conversion worker forks a child, while `kubectl exec` separately creates a root in the same container. | The forked child has a kernel-proven parent label before it runs. The administrative root has a one-use, audited external-entry admission. Neither is accepted merely because both are in the container cgroup. |
| `INV-ENTRY-002` | A host process uses `nsenter`, or a runtime task is moved directly into the protected cgroup, with no pending runtime intent. Its first action is to read the service-account token. | The file hook denies the read and records `unknown-external-entry`. Cgroup membership proves where the task is now, not why it was created or what authority it has. |
| `INV-ENTRY-003` | Container A exits; container B later receives the same PID, namespace number, or numeric cgroup ID. | Container B cannot resolve A's label, policy generation, or containment state because every lookup also verifies the live interval, full container identity, boot/label epoch, and non-reused task identity. |
| `INV-ROLE-001` | An approved update root and a compromised conversion worker both execute `/usr/bin/curl`. | The updater receives only the role admitted for its signed entry and transition. The worker remains a worker or receives a denied exec transition. Identical executable paths do not create identical authority. |
| `INV-ROLE-002` | Python forks a child that immediately reads a credential without exec; another thread later execs a new image. | The forked child already has the restrictive inherited child role. Exec retains the process lineage but creates a new execution identity and applies the reviewed role transition, including during non-leader de-threading. |
| `INV-EFFECT-001` | A permitted output path is changed into a symlink to the projected token, or the mount-aware object classifier cannot determine the target inode. | The credential read or unresolved classification is denied. A textual path match cannot override a more specific deny, and a required classifier miss cannot become allow. |
| `INV-EFFECT-002` | The attacker floods exec and file attempts until the ring buffer is full while the central service and local WAL are under pressure. | Every already-computed denial remains a denial. Mithril exposes loss and pressure counters, but telemetry backpressure never opens the protected effect. |
| `INV-POLICY-001` | Learning mode observes a compromised worker successfully calling the Kubernetes API with its mounted token. | The observation becomes a review candidate and evidence; it never writes an allow entry. Only a signed policy, validated and compiled by the Rust owner, can authorize that role/effect tuple. |
| `INV-POLICY-002` | Generation 42 allows an established approved socket while generation 43 denies new sockets to that destination. The update occurs while tasks and the old socket are live. | One atomic pointer activates generation 43 for new decisions. References that require generation 42 keep it resident until their explicit lifetime policy completes; no decision reads a half-loaded mixture or a freed map. |
| `INV-K8S-001` | The declared readiness probe, an application child, and `kubectl exec` each run the identical `/app/healthcheck` bytes. | They receive `kubelet-exec-probe`, application-descendant, and `administrative-exec` entry/role identities respectively. The executable object is evidence for command matching, not proof of Kubernetes intent. |
| `INV-K8S-002` | During termination, a malicious or compromised `PreStop` command tries to read a Secret and send it externally. | The policy remains installed and the narrow `kubelet-prestop` budget still applies until all tasks and relevant sockets are gone. “Terminating” never means unrestricted. |
| `INV-GRAPH-001` | A process on node A uses the Kubernetes API to create a Pod whose root later starts on node B. | Node A's task is not recorded as the Linux parent of node B's root. The graph adds a typed causal chain—API request, audit object, controller/scheduler decision, Pod UID, runtime admission—with the strength and gaps of each proof. |
| `INV-RESPONSE-001` | The graph says PID 7312 was malicious, but it exited and the kernel reused 7312 before containment arrives. | The actuator rejects the stale target after pidfd/start-time/cgroup/task-cookie re-resolution. It acts only on the current verified process, cgroup, credential, or provider object and then verifies the requested postcondition. |
| `INV-COVERAGE-001` | The node sensor missed sequence 900–915, attached after the worker started, or lost the provider audit feed that distinguishes a GitHub read from a write. | The affected task, interval, and claim are marked incomplete. Mithril may conservatively deny or contain according to policy, but it cannot report “no malicious action occurred” from absent evidence. |

For example, passing `INV-K8S-001` is not proven by an event that prints
`/app/healthcheck`. The test must create all three roots above, demonstrate
three different admitted identities, and show that each receives its own
file, network, exec, and response budget before it can perform those effects.

## Identity And Execution Model

### Why a container can have several roots

The container's configured entrypoint is created by the runtime and has no
native parent inside the workload. Later, kubelet or an administrator can ask
the runtime to execute another command in the same container. That new task
can be created by a host runtime/shim and placed into the container's cgroup
and namespaces; it need not be a descendant of container PID 1.

Therefore this graph is wrong:

```text
container PID 1
  -> every legitimate task in the container
```

The required graph is:

```text
ContainerExecutionSet
  +-- ContainerStartEntry -----------------> native tree A
  +-- KubeletPostStartEntry ---------------> native tree B
  +-- KubeletExecProbeEntry #1 ------------> native tree C
  +-- KubeletExecProbeEntry #2 ------------> native tree D
  +-- KubeletPreStopEntry -----------------> native tree E
  +-- AdministrativeExecEntry -------------> native tree F
  +-- other admitted runtime entries ------> native tree ...
```

The edge from an entry to its root process is `entry_started_execution`, not a
fabricated Linux parent edge. Ordinary fork/clone/exec edges below each root
remain native.

### Does the attacker also go through kubelet exec?

Sometimes, but not necessarily. More importantly, **“created through kubelet”
is provenance, not trust**. Kubelet may be carrying out a legitimate probe, a
legitimate administrator request, an attacker-controlled `pods/exec` request,
or a maliciously changed PodSpec. Those executions must not receive the same
role merely because kubelet initiated the runtime call.

The earlier entry diagram must not be read as assuming a kubelet-created task
is safe. That assumption would be wrong. The correct rule is:

```text
runtime and kubelet provenance select a candidate entry class
+ authenticated intent and reviewed workload state prove its purpose
+ compiled policy assigns or denies its role
```

Four practical paths must be distinguished.

#### Path 1: compromise inside the existing worker does not use kubelet exec

In the published Hugging Face chain, the data-derived Jinja expression caused
Python execution inside the existing conversion worker. That action did not
need `kubectl exec`, kubelet `ExecSync`, or a new process. If the compromised
Python process reads a token or opens a socket itself, its existing
`conversion-worker` task label reaches the file or socket hook. If it forks or
execs a shell, native inheritance and exec-transition policy continue from
that same admitted root.

```text
admitted ContainerStartEntry
  -> existing Python worker
       -> in-process Jinja/Python payload      # no kubelet and no new task
       -> forked child                         # native child, not external root
       -> exec /bin/sh                         # native exec transition
```

The protection must therefore work even when no kubelet or exec audit event
exists. This is precisely why task roles plus semantic file/socket/capability
hooks are required.

#### Path 2: an attacker using `pods/exec` normally does go through kubelet

If an attacker has Kubernetes `pods/exec` authority, a normal `kubectl exec`
path goes through the API/streaming control path to kubelet, which asks the
container runtime to create an exec process. Mithril classifies that process as
`AdministrativeExecEntry`, correlates the Kubernetes audit principal and
request when available, and applies default-deny or an explicitly approved
break-glass role.

For example, an attacker cannot obtain probe authority by running the probe's
exact command:

```text
declared readiness probe -> /app/healthcheck -> kubelet-exec-probe role
kubectl exec by attacker  -> /app/healthcheck -> administrative-exec role
```

The binary, argv, cgroup, and namespaces can all match. The request transport,
authenticated intent, API audit principal, one-use nonce, and entry kind do
not. If the audit proof or admission is missing, the protected root is
ambiguous or unknown, not a probe.

#### Path 3: an attacker can make kubelet execute a malicious declared hook

An attacker able to change a controller's Pod template, submit a replacement
Pod, or influence the manifest before admission could change a readiness probe
or `PreStop` command to `/bin/sh -c ...`. Most fields of an already-running
Pod are not freely mutable; in the common controller case the change creates a
replacement Pod. Kubelet later issuing the command does not cleanse that
attacker-controlled intent. Mithril binds approved entry rules to the reviewed
Pod UID, resource version, PodSpec digest, command digest, lifecycle state,
and policy generation. The replacement Pod or changed reviewed specification
creates a new deployment/profile generation; it cannot reuse an entry rule
compiled for the previous digest.

The deployment-preserving default is to report and deny or hold the unmatched
hook according to the protected profile, not to rewrite the manifest and not
to learn the new command as legitimate. If an installation initially chooses
observation-only compatibility, Mithril must say that this entry is unapproved
and that prevention coverage is absent; it must not label the command trusted.

#### Path 4: node or runtime access can bypass kubelet

An attacker with node access can call the CRI/runtime directly, use a tool such
as `crictl exec`, or manipulate a shim. That root may never pass through the
Kubernetes API or kubelet request path. Mithril requires a separately
authenticated `HostAdministrativeExecEntry` with runtime peer evidence and
denies it by default for protected workloads. Merely appearing in the target
cgroup is insufficient and triggers `INV-ENTRY-002`.

If the attacker controls kernel/root authority strongly enough to unload or
replace BPF programs, rewrite protected maps, forge the runtime trust channel,
or subvert kubelet and the runtime together, the node enforcement trust
boundary is lost. Mithril must detect and report attachment/map/measurement
failure from an external trust anchor where available; it cannot claim that a
compromised kernel enforces policy against itself.

#### What stock CRI can and cannot tell Mithril

Streaming `Exec` and synchronous `ExecSync` are separate CRI operations, so
the transport can help distinguish an interactive or administrative exec from
the synchronous mechanism kubelet commonly uses for exec probes and exec
lifecycle handlers. That still does not fully solve intent classification.
Stock `ExecSyncRequest` carries the container ID, command, and timeout, but not
“readiness probe,” “liveness probe,” `PostStart`, or `PreStop` as an
authenticated reason.

Therefore:

- a streaming exec cannot claim a probe/lifecycle role merely because its
  command matches the PodSpec;
- an `ExecSync` command is matched against the exact reviewed PodSpec and
  current lifecycle state, never against command text alone;
- when probe and lifecycle declarations are indistinguishable at the runtime
  boundary, Mithril uses a conservative shared budget or denies the ambiguous
  entry; and
- exact distinct roles require an authenticated kubelet-side reason/nonce or
  another pre-exec proof. Observation after the process starts cannot
  retroactively authorize it.

This answers the apparent contradiction: yes, one attacker path can traverse
kubelet exec, but kubelet transport does not make an execution legitimate.
Mithril protects both attacker paths—the in-process/native-descendant path and
the external runtime-root path—using different identity proofs that converge
on the same role/effect enforcement model.

### Durable identity objects

```text
ContainerExecutionSet {
  execution_set_id
  tenant_id
  cluster_uid
  node_boot_id
  pod_uid
  pod_resource_version
  sandbox_id
  full_container_id
  container_kind: init | sidecar | application | ephemeral
  image_digest
  cgroup_binding_id
  cgroup_live_interval
  profile_id
  active_profile_generation
  lifecycle_generation
}

EntryInstance {
  entry_instance_id
  execution_set_id
  entry_nonce
  entry_kind
  request_transport
  request_provenance
  classification: exact | conservative | ambiguous | unknown
  pod_spec_digest
  command_digest
  candidate_binary_identity
  requested_at
  claim_deadline
  claimed_task_cookie?
  target_role_id
  state: pending | claimed | expired | denied | completed
}

TaskLabel {
  node_boot_id
  label_epoch
  task_cookie
  process_lineage_id
  process_instance_id
  entry_instance_id
  execution_set_id
  profile_generation
  role_id
  execution_id
  lineage_depth
  ancestor_process_lineage_ids[MAX_DEPTH]
  dynamic_state_bits
  response_state
}
```

`task_cookie` and `process_lineage_id` are allocated by Mithril for the node
boot/label epoch. TID, TGID, namespace IDs, cgroup ID, start boottime, and pidfd
are live coordinates and revalidation material. They are not durable identity
alone.

### Native inheritance algorithm

At the earliest target-kernel-proven task allocation hook:

```text
on_task_create(parent, child, clone_flags):
    parent_label = task_storage[parent]

    if parent is outside every protected binding:
        do not invent a protected label
        return

    if parent_label is missing:
        mark protected binding identity_incomplete
        install fail_closed_unknown label on child if the hook permits
        return

    child.task_cookie = allocate_monotonic_cookie()
    child.entry_instance_id = parent.entry_instance_id
    child.execution_set_id = parent.execution_set_id
    child.profile_generation = parent.profile_generation

    if clone_flags contains CLONE_THREAD:
        child.process_lineage_id = parent.process_lineage_id
        child.process_instance_id = parent.process_instance_id
        child.role_id = parent.thread_child_role or parent.role_id
    else:
        child.process_lineage_id = allocate_monotonic_process_id()
        child.process_instance_id = derive_process_instance_id(...)
        child.ancestors = parent.ancestors + parent.process_lineage_id
        child.role_id = transition(parent.role_id, FORK_WITHOUT_EXEC)

    if ancestor bound would overflow:
        apply profile overflow action: deny creation or cgroup-scope response

    atomically attach label before child can perform a protected effect
```

The observation hook then emits the exact parent/child coordinates. If event
delivery fails, the label still exists. If the selected kernel cannot prove
pre-run inheritance, that kernel tier is observation-only until an equivalent
fallback passes the hostile identity matrix.

### Exec transition algorithm

At `bprm_check_security`:

```text
on_exec(current_task, candidate_file, argv):
    preserve any earlier LSM denial
    binding = resolve_live_protected_cgroup(current_task)
    label = task_storage[current_task]

    if binding is protected and label is missing:
        label = claim_external_entry_or_deny(binding, candidate_file, argv)

    source_role = label.role_id
    binary_key = classify_executable_object(candidate_file, binding.mount_view)
    interpreter_chain = classify_script_or_interpreter(candidate_file)
    edge = lookup_exec_edge(profile_generation, source_role,
                            binary_key, interpreter_chain)

    if response policy, hard invariant, or edge says deny:
        return -EACCES

    stage PendingExecCommit(task_cookie, edge.result_role,
                            binary_key, policy_generation)
    return prior_ret
```

At the post-exec observation point, Mithril verifies that the staged candidate
became the execution image, closes the prior `ExecutionInstance`, assigns the
resulting role, and emits the new instance. A failed or mismatched commit is a
coverage defect and leaves the task in a restrictive fail-closed role.

Non-leader thread exec and Linux de-threading must retain the task cookie and
process-lineage ID while updating native TID/TGID coordinates.

## Kubernetes And Runtime-Created Entry Architecture

### Current Kubernetes facts the classifier must respect

Current Kubernetes behavior creates several materially different cases:

- `PostStart` begins concurrently with the container entrypoint; it is not
  ordered strictly before or after the main process.
- An exec lifecycle handler runs inside the container's cgroups and
  namespaces. HTTP and sleep handlers run from kubelet; they do not create a
  new task in the container.
- Exec probes create commands inside the container. HTTP, TCP, and gRPC probes
  are node-originated network operations and create no probe command in the
  container.
- Lifecycle hooks are at-least-once and can be repeated after kubelet failure.
- `PreStop` finishes before the normal termination signal, but its time is
  charged to the termination grace period.
- Init, sidecar, application, and ephemeral containers are separate container
  roots even when they share Pod namespaces or volumes.

The stock CRI `ExecSyncRequest` carries `container_id`, `cmd`, and `timeout`.
It does **not** state whether kubelet is running startup/readiness/liveness,
`PostStart`, or `PreStop`. This is an information limitation in the interface,
not a KubeArmor/Tetragon limitation. Exact semantic classification requires an
authenticated kubelet-side reason or a conservative policy when declarations
are indistinguishable.

Primary references are the Kubernetes
[lifecycle-hook documentation](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/),
[probe documentation](https://kubernetes.io/docs/concepts/workloads/pods/probes/),
[`handlerRunner`](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/lifecycle/handlers.go),
[`prober`](https://github.com/kubernetes/kubernetes/blob/master/pkg/kubelet/prober/prober.go),
and the [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto).

### Entry-class matrix

| Kubernetes/runtime situation | Native shape | Required entry treatment | Default role and decision |
| --- | --- | --- | --- |
| Initial application entrypoint | Runtime-created root in new container cgroup | Pre-start `ContainerStartEntry` bound to full container/image/Pod/profile generation | Exact `application-root`; deny start if strict admission cannot complete |
| Regular fork/thread from labeled workload | Native descendant | Kernel inheritance; no runtime admission | Profile transition or restrictive inherited role |
| Exec `PostStart` | Possible secondary root, concurrent with entrypoint | One-use `KubeletPostStartEntry`, matched against exact PodSpec generation | Narrow `kubelet-poststart`; no inheritance of all application authority |
| Exec `PreStop` | Possible secondary root during termination | One-use `KubeletPreStopEntry`; policy stays installed through exit | Narrow `kubelet-prestop`; no universal containment bypass |
| Exec startup/liveness/readiness probe | Repeated secondary roots | Bounded, repeatable `KubeletExecProbeEntry` matched to effective PodSpec command | `kubelet-exec-probe`; strict file/socket/exec budget |
| HTTP lifecycle handler | Kubelet-originated connection to Pod endpoint | No workload entry; retain node-flow and declared-hook context | Do not invent a workload process or parent edge |
| HTTP/TCP/gRPC probe | Kubelet-originated connection | No workload entry; optional inbound-probe observation | Do not treat application receiver thread as a probe-created root |
| Sleep lifecycle handler | Sleep in kubelet | No workload task or entry | No workload decision |
| `kubectl exec` / streaming exec | Runtime-created secondary root plus Kubernetes `pods/exec` audit | `AdministrativeExecEntry`, correlated to audit principal when possible | Default deny or explicit approval; limited break-glass role |
| `kubectl cp` | Usually a streaming exec that runs archive tooling | Same as administrative exec; never infer benignity from `tar` | Default deny or explicit scoped file-transfer role |
| Direct `crictl exec` or runtime API exec | Runtime-created secondary root without Kubernetes user audit | `HostAdministrativeExecEntry` with runtime peer evidence | Deny on protected workloads unless host break-glass policy allows |
| Ephemeral container | Separate container creation, optionally targeting another PID namespace | Normal container-root admission with `container_kind=ephemeral` and API audit | Default deny for protected workloads or isolated diagnostic profile |
| Init container | Separate ordered container root | Its own execution set and image/profile | Init-specific role; never app-role inheritance |
| Native sidecar | Separate independently restarted container root | Its own execution set and image/profile | Sidecar-specific role; shared Pod network does not merge lineage |
| OCI runtime hook process | Infrastructure process, often outside workload cgroup | Infrastructure observation only | Never assign workload authority from shared namespaces alone |
| `nsenter` or task moved into protected cgroup | Unlabeled external task | No pending authenticated entry means deny first protected effect | `unknown-external-entry` finding; fail closed |
| Container restart in same Pod | New full container ID, cgroup live interval, root and lifecycle generation | New execution set and root admission | Never reuse the prior root label or response target implicitly |

### One-gatherer runtime integration

The only Mithril event and policy owner remains the one `mithril-node` process.
Runtime integration is an admission transport, not another gatherer:

```text
kubelet / CRI caller
    -> runtime execution path
       -> lightweight hook, in-runtime adapter, or CRI admission proxy
          -> authenticated local RuntimeEntryIntent to mithril-node
             -> task/entry label installed and verified
          <- one-use acknowledgement
       -> runtime permits candidate executable transition
```

Preferred mechanisms, in descending order of guarantee:

1. A runtime/shim integration holds the exact new task before user executable
   installation, passes a pidfd plus full runtime identity, and resumes only
   after Mithril installs and reads back the task label.
2. The `mithril-node` process provides a local CRI admission proxy and writes a
   one-use pending intent before forwarding `ExecSync`/`Exec`; an unlabeled
   task may claim that intent only at `bprm_check_security` in the exact bound
   cgroup and for the exact candidate executable class.
3. An OCI pre-start hook, delivered as a short-lived mode of the same product
   binary, provides initial-container admission. This does not solve later
   runtime exec by itself.
4. Observe-only runtime callbacks may enrich a task after start, but they must
   report a start gap and cannot claim enforce-from-first-exec.

An NRI `StartContainer` callback alone is insufficient for full protection;
the local KubeArmor implementation documents precisely that post-start gap.
No permanently resident second collector is introduced. A short-lived hook or
code executing inside the runtime is not allowed to own policy maps, lineage,
WAL, or an independent event stream.

### `RuntimeEntryIntent`

```text
RuntimeEntryIntent {
  nonce: 128-bit random
  caller_transport: oci_hook | cri_execsync | cri_exec | runtime_shim
  caller_peer: authenticated local identity
  request_sequence
  cluster_uid
  node_boot_id
  pod_uid
  pod_resource_version
  full_container_id
  cgroup_binding_id
  runtime_lifecycle_generation
  operation: container_start | exec_sync | streaming_exec | ephemeral_start
  command: redacted argv plus canonical digest
  candidate_binary_hint
  tty, stdin, stdout, stderr
  requested_at
  deadline
}
```

The userspace classifier joins the request to the effective PodSpec and emits
an `EntryInstance`. It never trusts container annotations alone; it re-resolves
the full container, cgroup live interval, Pod UID, image digest, and policy
generation.

### General authenticated intent-proof channels

`RuntimeEntryIntent` proves the runtime operation and caller transport. It does
not, by itself, prove the human or coordinator purpose behind the operation.
The same distinction applies outside Kubernetes. Seeing `aws sso login`,
`gcloud auth login`, `gsutil cp`, `kubectl`, or `/app/healthcheck` in argv does
not prove that a human, CI job, kubelet probe, or approved deployment intended
that action. An attacker can execute the same binary and arguments.

**The AWS and Google CLI examples are analogies for proving intent through a
separate authenticated channel; they are not entry kinds.** Mithril does not
create `AwsLoginEntry`, `GcloudLoginEntry`, or `GsutilEntry`. Those processes
keep their real native parent/exec lineage. Only the separately obtained
provider authority is represented as an `AuthorityLeaseIntent` and, after
issuance is proven, a `CredentialLease`. The reason to study those login flows
is to reuse their signed issuer, audience, nonce, expiry, approval, and session
binding ideas for kubelet and CI intent proof.

The correct extension is a general **intent-proof channel**: a trusted
coordinator sends a signed, replay-resistant assertion before the relevant
entry, transition, or authority acquisition. This is another input to the one
`mithril-node` gatherer, not a second gatherer. The producer does not load BPF,
collect kernel events, own policy, or maintain a competing process graph.

```text
trusted coordinator or identity provider
    -> signed one-use IntentProofEnvelope
       -> authenticated local socket or central signed stream
          -> mithril-node validates issuer, nonce, time, target, and policy
             -> pending entry / transition / authority-lease proof
                -> exact task claims proof at the matching pre-effect point
```

#### Intent proof envelope

```text
IntentProofEnvelope {
  proof_id
  issuer_id
  issuer_kind: kubelet | ci_coordinator | human_approval | identity_provider |
               deployment_controller | connector
  issuer_key_id
  signature
  issued_at
  not_before
  expires_at
  nonce
  sequence

  subject_scope {
    cluster_uid?
    node_id?
    pod_uid?
    full_container_id?
    cgroup_binding_id?
    execution_set_id?
    process_lineage_id?
    ci_run_id?
    ci_job_id?
    ci_step_id?
    human_session_id?
  }

  declared_intent {
    kind: runtime_entry | native_transition | authority_lease |
          artifact_handoff | provider_operation
    operation
    command_digest?
    executable_object?
    image_digest?
    provider?
    account_or_project?
    requested_role_or_permission_set?
    credential_audience?
    artifact_digests[]
    lifecycle_state?
  }

  trigger {
    actor_id?
    event_type?
    workflow_or_manifest_ref?
    immutable_definition_digest?
    approval_id?
    parent_proof_id?
  }

  allowed_claim_count
  disposition_on_mismatch
  disposition_on_expiry
}
```

Secrets, OAuth authorization codes, bearer tokens, and cloud secret keys are
not stored in this envelope. It contains stable public identifiers, digests,
lease IDs, audiences, and provider request/session identifiers when available.

#### Four ways an intent proof is consumed

| Intended action | Linux/runtime shape | Mithril object created | Practical example |
| --- | --- | --- | --- |
| Runtime creates a process with no labeled native parent | External root | `EntryInstance` | kubelet exec probe, `kubectl exec`, Docker container action, Tekton step container |
| A labeled runner or worker forks/execs a child | Native child or exec transition | `TransitionIntent`, consumed by the already-labeled lineage | GitHub Actions `run:` shell step, Jenkins `sh`, approved worker helper |
| A process obtains or activates credentials | Usually no new root beyond the CLI process | `AuthorityLeaseIntent` bound to a task/process lineage and provider identity | AWS SSO login, STS web-identity exchange, Google Workload Identity Federation, GitHub job token |
| One job publishes data consumed by another job or node | No Linux parent relation | `ArtifactHandoffIntent` plus typed causal edge | CI artifact, cache entry, image digest, deployment manifest, queue message |

This corrects a tempting but wrong model: **not every coordinator action is an
entry**. If a GitHub runner forks a shell for a step, the shell is a native
descendant and must retain that physical parent edge. The signed step intent
authorizes a role transition. If the runner asks Docker to start a container
action, that container root needs an entry admission. If a later job downloads
the first job's artifact, the relationship is an artifact edge, never a native
parent.

#### Proof-strength and use matrix

| Proof | Strength when verified | What it may authorize | What it cannot prove alone |
| --- | --- | --- | --- |
| Signed pre-exec coordinator assertion with one-use nonce, immutable definition digest, exact target, and short TTL | Exact for the asserted coordinator intent | Entry admission, native transition, or credential-lease request | That the resulting provider operation later succeeded |
| Provider-signed OIDC token with issuer, audience, subject, token ID, run/job/ref claims, and expiry | Exact for the claims the provider actually signed | A job-level authority exchange whose trust policy matches those claims | A particular shell command or step when the token has no step claim |
| Provider issuance record with exact request/session/access-key/lease identity | Exact for credential issuance | Bind the authority lease and later provider audit operations | Which local task requested it unless joined through a broker, nonce, or exact coordinator proof |
| Kubernetes, cloud, source-control, mesh, or connector audit after completion | Exact for fields and result supplied by that authority | Finding, causal edge, response eligibility | Retroactive local prevention of an operation that already succeeded |
| Measured runner/kubelet event without a carried nonce | Strong or conservative depending uniqueness and source measurement | Same-budget classification when every remaining candidate is equally restrictive | Exact selection among concurrent identical requests with unequal authority |
| Command, process name, timestamp, cadence, label, or destination alone | Contextual | Candidate matching and operator explanation | Intent, caller authority, or an allow decision |

`mithril-node` verifies an intent proof as follows:

```text
verify_and_stage_intent(envelope, live_context):
    verify issuer key, signature, key validity, and revocation state
    verify node boot/cluster/tenant and profile trust domain
    reject expired, future, replayed, or non-monotonic proof
    resolve immutable workflow/manifest/image/command digests
    resolve exact live Pod/container/cgroup or labeled process lineage
    verify actor, trigger trust class, approval, and requested authority
    ensure requested role/effects are a subset of signed policy
    ensure claim count, concurrency, rate, and lifetime budgets remain

    if any required field is missing or conflicts:
        apply configured mismatch disposition; never silently widen

    stage one of EntryIntent, TransitionIntent, AuthorityLeaseIntent,
    or ArtifactHandoffIntent with a one-use claim key
```

The kernel remains the final task binder. A valid proof for job 55 cannot be
claimed by job 56, a different cgroup, a native child with an existing label,
or the same task after expiry. The userspace assertion supplies purpose; live
kernel identity supplies the process that will exercise it.

#### Practical kubelet-probe proof

The stock CRI gap remains real: `ExecSyncRequest` does not carry “readiness,”
“liveness,” `PostStart`, or `PreStop`. Mithril can close it with an optional
authenticated kubelet-side channel:

1. Immediately before invoking the runtime, measured kubelet integration
   emits a signed proof containing Pod UID/resource version, full container
   ID, lifecycle generation, exact probe or hook field, canonical command
   digest, monotonic sequence, deadline, and one-use nonce.
2. The local CRI admission path observes the corresponding `ExecSync` and
   supplies its authenticated peer, container, command, and request order.
3. `mithril-node` requires the two records to agree and stages the exact
   `KubeletExecProbeEntry`, `KubeletPostStartEntry`, or
   `KubeletPreStopEntry`.
4. The runtime-held pidfd root or exact `bprm_check_security` claimant consumes
   the proof before the executable image begins.
5. A duplicate, expired, wrong-command, wrong-container, wrong-lifecycle, or
   already-claimed proof follows the configured rejection action.

For exact classification under concurrent identical `ExecSync` requests, the
nonce must travel through a measured kubelet/runtime extension or the
integration must hold and bind the exact task. Merely correlating two identical
commands by time is not exact. If no nonce can be carried, same-budget
conservative classification remains valid; unequal budgets remain ambiguous
and default to rejection in protect mode.

#### Practical AWS CLI login and session mapping

Observing `aws sso login` proves only that a process executed that CLI command.
It does not prove that the login was approved or which later AWS session belongs
to the process. A strong mapping is:

```text
approved human or CI intent
  -> AuthorityLeaseIntent(provider=aws, account, role/permission-set,
                          target lineage, TTL, approval/run identity)
  -> exact labeled `aws` process performs browser/device/OIDC exchange
  -> provider issuance/audit supplies session/access-key identifier
  -> CredentialLease(lease_id, provider_session_id, source_identity,
                     owning process lineage, expires_at)
  -> CloudTrail operations join by exact session/access-key/source identity
```

The policy separately controls:

- exec of the measured AWS CLI object;
- access to `~/.aws/config`, `~/.aws/sso/cache`, `~/.aws/login/cache`, or an
  approved `credential_process` endpoint;
- network access to the expected identity and AWS API destinations;
- requested account, role, audience, source identity, session tags, and TTL;
- which descendant roles may use the resulting lease; and
- provider operations allowed for that session.

AWS CLI SSO caches an authentication token under `~/.aws/sso/cache`; newer
interactive AWS login also uses a local cache. A shared cache read is therefore
not a unique provider-session proof. Exact task-to-session binding requires a
credential broker/process provider that can carry the Mithril lease nonce, or
provider issuance fields such as source identity/session name/tags that are
cryptographically tied to the approved coordinator identity. Without that,
Mithril records a strong local login lineage and provider session evidence but
marks their join conservative or contextual rather than inventing certainty.

No TLS interception is required. AWS STS/IAM and CloudTrail provide semantic
session and operation evidence; the local kernel provides the task and socket
identity.

#### Practical `gcloud`/`gsutil` and Google workload-identity mapping

`gcloud auth login` can store user credentials in the Cloud CLI configuration,
and `gcloud auth login --cred-file` supports external-account configurations.
`gsutil` can use the same authenticated Cloud CLI or workload identity. The
binary name still does not prove purpose.

For CI, the preferred exact path is:

1. GitHub Actions, GitLab, or another coordinator issues a signed OIDC token
   containing its run/job/repository/ref claims and unique token ID.
2. A signed `AuthorityLeaseIntent` binds the expected issuer, audience, job,
   immutable workflow definition, target Google project/service account,
   scope, and lifetime to the exact CI task lineage.
3. Google Security Token Service validates the OIDC token and returns a
   federated credential, optionally followed by service-account
   impersonation.
4. Google audit identifies the federated principal or impersonated service
   account and operation. Mithril joins it to the job proof through the signed
   subject/audience/token ID and provider request/lease evidence available.
5. A `gsutil cp`, `gcloud storage cp`, client library, or raw HTTPS client all
   receive the same authority decision because policy follows the lease and
   provider operation, not the CLI filename.

For a human browser login with persistent cached credentials, use a human
approval proof scoped to the administrative session and classify every cache
read. If the provider flow exposes no bindable nonce/session identifier, the
join to later provider operations is weaker and automatic narrow response is
ineligible until the exact principal/session is resolved.

#### Non-negotiable limitation

An intent channel can prove what a trusted issuer asked for. It cannot make a
compromised issuer truthful. If kubelet, the CI coordinator, its signing key,
or the cloud identity provider is controlled by the attacker, the assertion is
inside the compromised authority boundary. Mithril still applies product hard
invariants and role/effect limits, records issuer identity, and requires an
independent provider/kernel postcondition where configured, but it cannot
cryptographically recover honest intent from a dishonest trust root.

### ExecSync classification algorithm

```text
classify_exec_sync(intent, pod_spec, container_state):
    candidates = []

    for each declared exec startup/liveness/readiness probe:
        if canonical_command matches intent.command:
            add candidate(kind=probe type,
                          allowed_state=running and probe schedule eligible)

    for postStart exec:
        if command matches and lifecycle generation is starting:
            add candidate(kind=postStart)

    for preStop exec:
        if command matches and lifecycle generation is terminating:
            add candidate(kind=preStop)

    discard candidates with wrong Pod resource version, container ID,
    lifecycle generation, command, deadline, or multiplicity budget

    if authenticated kubelet reason exists and exactly matches a candidate:
        classification = exact
    else if all remaining candidates compile to the same target role and
            identical effect budget:
        classification = conservative
    else if no candidate remains:
        deny as undeclared runtime exec
    else:
        classification = ambiguous
        apply profile's ambiguity action, default deny in protect mode
```

Timing is supporting evidence, never the sole proof. A command that happens to
run every ten seconds does not become a liveness probe. Matching a declared
command does not authorize a different caller. Kubelet restarts and the
at-least-once hook contract are handled with idempotency keys and bounded
multiplicity, not a single expected timestamp.

When unmodified CRI cannot distinguish two declarations and their effect
budgets differ, only three honest choices exist:

- deny the ambiguous entry;
- compile the explicitly approved union of both budgets and mark the entry
  `conservative`; or
- install an authenticated kubelet/runtime reason extension.

Mithril must not pop an arbitrary pending intent and label the task with a more
powerful role.

### Pending-intent claim algorithm

The pidfd handshake is preferred. The fallback for a runtime that cannot
provide the task before exec is an atomic claim at `bprm_check_security`:

```text
claim_external_entry_or_deny(binding, candidate_file, argv):
    assert current task has no label
    assert binding is protected and live

    candidate_key = bounded_exec_classifier(candidate_file, argv)
    pending_key = (binding.id, binding.lifecycle_generation, candidate_key)
    intents = pending_entry_map[pending_key]

    choose only an unexpired intent whose role/effect budget is unique
    atomically change PENDING -> CLAIMED with current task cookie
    reject stale generation, duplicate claim, exhausted multiplicity,
           wrong binary object, or ambiguous target role

    install external-root TaskLabel before continuing exec evaluation
    emit entry_started_execution separately
```

An attacker-created native child cannot claim an external intent because it
already carries its inherited task label. An unlabeled task manually moved
into the cgroup cannot claim without a live authenticated intent. A host-root
attacker who can modify the runtime, BPF maps, or Mithril process is outside
this node trust boundary and must be handled by host integrity controls.

The prototype must prove that the selected BPF hooks can safely parse the
bounded executable/argv material and create task storage. If not, the fallback
is not promoted; full support requires the runtime-held pidfd path.

### Shutdown and containment interaction

Policy is retained until the runtime confirms exit and a BPF task/cgroup
reconciliation proves no live member remains. `StopContainer` and Pod deletion
change lifecycle state; they do not delete enforcement maps.

When a lineage is contained:

- new ordinary external entries are denied;
- declared `preStop` is not automatically allowed;
- a profile may authorize a narrow shutdown role with exact file/socket
  effects and a deadline;
- if that cleanup role could re-open the attack path, containment wins and the
  hook fails;
- cgroup freeze or kill is a separate typed response with its own approval;
- kubelet/controller replacement is watched and constrained separately.

## Policy Package And Compiler

### Source policy object

```text
WorkloadProtectionProfile {
  profile_id
  version
  schema_version
  issuer
  signature
  valid_from, valid_until?
  selectors
  required_capabilities
  default_postures
  entry_rules[]
  roles[]
  transition_rules[]
  effect_rules[]
  dynamic_state_rules[]
  authority_behavior_rules[]
  correlation_packages[]
  response_rules[]
  coverage_requirements[]
  rollout
}
```

Selectors find candidate workloads in userspace. They do not become kernel
authority. The binder resolves a selector to an exact Pod UID, full container
ID, immutable image digest, cgroup live interval, and profile generation.

### Entry rules

```text
EntryRule {
  entry_kind
  container_kind
  command_match: exact digest | executable object | none
  pod_spec_field_proof
  permitted_lifecycle_states
  caller_proof
  concurrency_limit
  rate_budget
  claim_ttl
  target_role_id
  ambiguity_action
  default_action
}
```

Arguments may help classify a declared kubelet action, but arguments are not a
substitute for physical effect policy. Shell quoting, interpreter flags, file
descriptors, environment, and in-process code make an argv allowlist
insufficient.

### Roles and transitions

```text
Role {
  role_id
  description
  entry_origins[]
  thread_creation
  fork_without_exec_target_role
  max_native_depth
  allowed_exec_edges[]
  effect_policy_id
  dynamic_state_machine_id
}

TransitionRule {
  source_role_id
  operation: fork | clone_thread | exec | privilege_transition
  candidate_object_key?
  interpreter_chain?
  required_state_bits
  resulting_role_id
  decision: allow | audit | deny
}
```

Recommended initial roles for the incident fixture are:

| Role | Purpose | Default dangerous effects |
| --- | --- | --- |
| `conversion-worker-root` | Existing unchanged interpreter/worker | deny undeclared exec, credential objects, API/IMDS, device/privilege escape |
| `conversion-worker-child` | Forked child that has not execed | narrower than root; cannot claim runtime entry |
| `declared-tool` | Exact approved worker child executable | only tool-specific files and destinations |
| `kubelet-exec-probe` | Declared startup/readiness/liveness command | no child exec, credential read, public egress, API/IMDS, device, or privilege effects by default |
| `kubelet-poststart` | Declared setup command | only reviewed setup objects/effects; bounded lifetime |
| `kubelet-prestop` | Declared cleanup command | reviewed cleanup effects and deadline; no containment bypass |
| `administrative-exec` | Approved interactive session | explicit break-glass policy, actor, TTL, recording/coverage requirements |
| `ephemeral-diagnostic` | Approved ephemeral container | separate container profile and restricted cross-container process/file access |
| `unknown-protected-task` | Identity or entry failure | deny every protected effect and emit high-severity coverage finding |
| `restricted-lineage` | Active response state | deny new exec/file/socket/device/privilege effects according to response policy |

### Effect rules

```text
EffectRule {
  role_id
  effect_family
  operation
  object_class
  object_key_match
  required_dynamic_state
  lifecycle_states
  decision: allow | audit | deny
  errno
  set_state_bits[]
  clear_state_bits[]
  evidence_level
}
```

An object class is a policy concept such as `dataset-input`,
`projected-service-account-token`, `worker-environment-procfile`,
`kubernetes-api`, `cloud-imds`, `mesh-control`, `tun-device`, or
`anonymous-executable-memory`. The kernel uses compact compiled keys; the
evidence record retains the resolved semantic class and provenance.

### Authority behavior rules

Linux can decide that a process may connect to the Kubernetes API. It cannot
parse an already-encrypted request and decide that `list pods` is expected but
`create rolebinding` is not. That second decision belongs to an asynchronous
authority behavior policy:

```text
AuthorityBehaviorRule {
  principal_selector
  source_workload_selector
  authority: kubernetes | aws | github | mesh | connector | artifact_repo
  allowed_operations[]
  allowed_resource_selectors[]
  allowed_credential_lease_types[]
  time/rate/concurrency budgets
  required_request_proof
  finding_on_deviation
  response_playbook
}
```

This rule consumes Kubernetes/provider audit. It never claims that the kernel
prevented a server operation that had already succeeded.

### Compilation pipeline

```text
signed source profile
  -> schema and signature validation
  -> selector resolution and immutable workload snapshot
  -> conflict and reachability analysis
  -> entry/role state-machine compilation
  -> object classifier compilation
  -> compact effect decision tables
  -> response and coverage requirement compilation
  -> userspace simulation against observed workload baseline
  -> human approval
  -> inactive BPF map generation
  -> read-back + controlled allow/deny probes
  -> atomic active-generation switch
```

Compiler rejection conditions include:

- an entry maps ambiguously to roles with unequal budgets without an explicit
  ambiguity action;
- a role is unreachable or can escalate through a transition cycle;
- a deny depends on an unsupported hook or object key;
- a path-only executable is marked immutable;
- a rule claims a TLS/server verb from network-only evidence;
- a response target lacks a revalidation key and physical postcondition;
- an allow would override a hard invariant or active response state;
- a required object classifier can return unknown with fail-open behavior; or
- the generation exceeds verified BPF map, stack, instruction, depth, or
  latency bounds.

Observation generates a **candidate** role/effect profile. It never writes an
allow directly into the active generation. Candidate promotion requires
review, simulation, signature, controlled probes, and rollout health.

### Policy precedence

Every protected hook evaluates in this order:

1. Preserve a nonzero prior LSM result.
2. Resolve the live protected cgroup/profile binding.
3. Resolve or admit the exact current task label.
4. Apply response-root and emergency hard-deny state.
5. Apply immutable product invariants.
6. Apply exact entry/role transition or effect rule.
7. Apply role and profile default posture.
8. Commit dynamic state changes associated with an allowed/audited effect.
9. Emit decision evidence independently.

No later step can change an earlier deny into allow.

## Node Decision Architecture

### Compiled map model

The exact layout is Phase 0 ABI work, but the architecture requires the
following logical maps:

```text
protected_cgroup_bindings:
  live cgroup key -> execution set, profile generation, lifecycle, mode

task_labels:
  BPF task storage -> TaskLabel

pending_entries:
  binding + lifecycle generation + candidate class -> one-use entry slots

active_profile_generations:
  profile ID -> active generation pointer

role_transition_tables[generation]:
  source role + transition + object key -> decision + target role

effect_tables[generation]:
  role + effect + operation + object class/key + state -> decision

response_roots:
  node boot + label epoch + process lineage -> restrictions + TTL

socket_labels:
  socket storage -> creator/current process, role, generation, destination,
                    flow identity, response state

coverage_counters:
  per CPU/hook/generation sequence, drop, classifier miss, map failure
```

The cgroup key must survive ancestor placement and cgroup v2 layout variation.
The node binder records the kernel cgroup ID, a generation/live interval, a
tracker for descendants where needed, the full cgroup path for evidence, and
the container/Pod binding. A bare cgroup ID recovered after deletion is not
enough to revive a binding.

Policy maps are bounded and preallocated where the selected hook cannot safely
allocate. Map exhaustion is a health transition. In protect mode, exhaustion
that prevents identity or a required lookup fails closed for the affected
protected binding; it does not silently evict a live label or rule.

### Generic pre-effect algorithm

```text
decide(effect_context):
    if effect_context.prior_lsm_result != 0:
        best_effort_emit(STACKED_DENIAL)
        return prior_lsm_result

    binding = protected_cgroup_bindings.lookup_current_ancestor()
    if binding is absent:
        return evaluate_explicit_host_policy_or_allow()

    if binding is expired, tombstoned, or outside its live interval:
        return deny(IDENTITY_STALE)

    label = task_storage.current()
    if label is absent:
        if effect is executable transition:
            label = atomically_claim_pending_entry()
        if label is still absent:
            return deny(PROTECTED_TASK_UNLABELED)

    if label.execution_set_id, generation, epoch, or node boot disagrees
       with binding:
        return deny(IDENTITY_BINDING_MISMATCH)

    if response_roots matches label.process or any bounded ancestor:
        return evaluate_response_restriction(effect)

    object = classify_effect_object(effect_context)
    if object is unknown and profile requires exact classification:
        return deny(REQUIRED_OBJECT_UNKNOWN)

    rule = exact_effect_lookup(label.role, effect, object,
                               label.dynamic_state, binding.lifecycle)
    decision = rule or profile.default_for(effect)

    if decision allows/audits:
        apply atomic dynamic-state transition

    best_effort_emit(decision, exact identity, object, generation,
                     classifier quality, coverage counters)
    return decision.errno_or_prior_result
```

`best_effort_emit` reserves a ring record only after the decision is fixed.
Failure increments a per-CPU loss counter visible to the collector. The
decision path never waits for Rust, the central service, DNS, Kubernetes, an
LLM, or provider audit.

## Effect-Family Algorithms

### Executable images and commands

Mithril governs executable transitions, not command strings alone.

The executable object key should contain the strongest target-kernel evidence
available:

```text
ExecutableObjectKey {
  mount_view_generation
  mount_id
  superblock/device identity
  inode number
  inode generation/version where available
  file type and executable mode
  immutable image-layer/file-manifest identity if pre-resolved
  IMA/fs-verity/content digest if available without a decision-path race
  overlay origin/copy-up state
  deleted_or_unlinked
  memfd/anonymous class
}
```

Userspace resolves immutable image files into object keys when binding the
profile. The BPF decision compares the live candidate file object to the
compiled key. It does not synchronously hash an arbitrary executable in every
exec hook. Mutable executable objects require an explicit mutable-code rule or
an integrity mechanism such as fs-verity/IMA; matching a pathname is not
equivalent.

Required cases:

- `execve`, `execveat`, `fexecve`, scripts and shebang interpreters;
- dynamic linker and interpreter transitions;
- memfd, deleted file, `/dev/shm`, `/run/shm`, and unlinked executable images;
- overlay copy-up and mount replacement;
- a renamed or bind-mounted approved binary;
- an approved pathname whose inode/content changed;
- non-leader thread exec and de-threading; and
- forked code that performs effects without exec.

`python -> sh` and `python -> curl` are denied at the executable edge when the
role lacks those target object keys. Python importing a module or evaluating a
template in-process creates no executable transition; file/code mapping and
later effects remain the control points.

### File and credential objects

File policy is role, operation, and object based:

```text
FileEffectKey = (
  role_id,
  operation: open_read | open_write | permission | mmap_exec |
             truncate | create | rename | link | unlink | ioctl,
  object_class,
  live_file_object_key,
  lifecycle_state,
  dynamic_state
)
```

Primary hooks include BPF LSM `file_open`, `file_permission`, `mmap_file`, and
selected inode/path hooks required to cover creation, rename, link, unlink,
and mount-view changes. The compiler must state which operation is actually
prevented by which hook; a later close/write tracepoint is evidence only.

Initial Hugging Face object classes include:

| Object class | Representative resolver | Default conversion-worker rule |
| --- | --- | --- |
| `dataset-input` | admitted job mount/root plus immutable revision when known | read; no execute; write only to declared output |
| `worker-runtime` | immutable image/runtime libraries | read/map according to executable profile |
| `worker-scratch` | exact scratch mount and lifetime | bounded read/write/create; no execute by default |
| `worker-environment-procfile` | `/proc/<pid>/environ` resolved to target task | deny cross-task; self-read requires explicit rule |
| `projected-service-account-token` | Kubernetes projected volume provenance plus Pod/container binding and rotating file identity | deny for conversion role; allow only controller role that demonstrably needs it |
| `cloud-credential-file` | mounted credential volume/provider path provenance | deny unless exact role requires it |
| `other-proc-task` | target task cookie/process plus proc inode/path class | deny inspection absent declared diagnostics |
| `host-filesystem` | mount provenance outside admitted container view | deny |
| `socket-or-device-file` | inode type plus device identity | dispatch to socket/device policy |
| `anonymous-executable-memory` | executable anonymous mapping | deny unless reviewed JIT role |

Projected tokens rotate, so policy cannot pin only one inode forever. The
binder classifies the mounted projected volume and its path/object lifetime;
rotation updates the exact live object set without broadening the directory to
arbitrary files.

Opening `/proc/self/environ` is enforceable. Reading the process's already
resident environment with a language API is not. If the role legitimately
holds secrets in memory, file policy alone cannot prevent in-process access;
Mithril must stop the next exfiltration or authority effect and report that
the memory read itself was unobservable.

Already-open descriptors, inherited descriptors, descriptor passing,
`mmap`, `sendfile`, `splice`, shared memory, and `io_uring` are separate
coverage cases. A file-open denial claim cannot be generalized to data already
present in process memory or a descriptor obtained before policy attachment.

### Coarse sensitive-read state

Mithril may maintain a deterministic process state bit after an observable
sensitive read:

```text
on allowed/audited read of credential or protected secret object:
    process.dynamic_state |= OBSERVED_SENSITIVE_READ

on later socket/write/exec effect:
    use the stricter effect table for OBSERVED_SENSITIVE_READ
```

This is coarse information-flow control, not byte-level taint. It is useful for
roles that may read one sensitive file but must not subsequently contact public
destinations or create artifacts. It cannot prove that bytes sent came from
that file, and it cannot see secrets read from existing memory. Profiles must
opt in after baseline simulation because the state can intentionally tighten
all later effects of the process.

### Network, sockets, and packets

Network policy has two distinct jobs:

1. pre-effect authorization for socket creation, connection, bind/listen,
   send, and packet transmission; and
2. response fencing for existing and future flows.

The socket label is created in socket storage and carries the creating
task/process/role/profile generation. On inheritance or descriptor passing,
the effect is evaluated against the **current sender** and the socket label;
the receiver does not automatically acquire the creator's network authority.

```text
NetworkEffectKey = (
  current_role,
  socket_creator_role,
  operation,
  family/type/protocol,
  network_namespace_generation,
  destination_class,
  address/prefix,
  port,
  DNS/provenance quality,
  dynamic_state,
  response_state
)
```

Required mechanisms include:

- BPF LSM `socket_create`, `socket_connect`, and `socket_sendmsg` where
  available and target-kernel-proven;
- cgroup `connect4/6` and `sendmsg4/6` for address decisions;
- socket storage for process/role attribution;
- cgroup/TC packet policy for established-flow and packet-level fences; and
- explicit coverage for UDP, IPv6, raw/packet sockets, TUN/TAP, AF_XDP,
  `io_uring`, BPF redirects, inherited descriptors, `SCM_RIGHTS`,
  `sendfile`, and `splice`.

Initial destination classes include `kubernetes-api`, `cloud-imds`,
`cloud-api`, `public-internet`, `approved-dataset-service`, `artifact-store`,
`mesh-control`, `mesh-peer`, `connector`, and `unknown`.

DNS is evidence, not destination identity by itself. The node records query,
answer, TTL, network namespace, and socket timing, then enforces the actual
address/prefix/service identity. Hard-coded IPs, stale DNS, CNAMEs, IPv6,
private endpoints, and alternate interfaces must not bypass the class.

A conversion role that never needs the Kubernetes API or IMDS is denied at
connect/send. A controller role that needs the Kubernetes API may connect; its
verbs and resources are evaluated later from Kubernetes audit. Direct TLS
remains opaque.

### Devices and ioctl APIs

Device admission uses cgroup v2 device BPF for major/minor/access plus file and
ioctl policy for the API exposed by the device:

```text
DeviceEffectKey = (
  role_id,
  device_type,
  major,
  minor or range,
  access: read | write | mknod,
  ioctl_command_class,
  lifecycle_state
)
```

`/dev/net/tun` is a key Hugging Face control. Denying the file or cgroup-device
access prevents an unapproved process from creating a TUN interface even if a
mesh client binary is present. Raw block devices, GPUs, accelerators, FUSE,
KVM, and terminal devices require separate policy classes; “device allowed”
does not mean every ioctl is allowed.

### Privilege and kernel escape effects

The security effect family covers:

- capability checks and credential transitions;
- setuid/setgid/file-capability executable transitions;
- ptrace and cross-process access;
- namespace create/join and `setns`;
- mount, pivot-root, filesystem context, and propagation changes;
- BPF program/map operations;
- perf events and kernel tracing interfaces;
- kernel module loading;
- keyring operations;
- dangerous sysctls and `/proc` control files; and
- seccomp changes that weaken an existing floor.

The selected LSM/cgroup/seccomp hooks vary by kernel. Phase 0 produces a
capability matrix and controlled deny probe per claimed operation. A missing
hook is a reduced protection tier, not a best-effort equivalent.

Seccomp is complementary: it cheaply removes syscall classes a role never
needs, but ordinary seccomp cannot decide rich file objects, cgroup-bound
roles, Kubernetes identities, or provider operations. Landlock and mount
namespaces can provide optional process-local/filesystem floors, but Mithril's
node BPF LSM remains necessary for exact cross-process roles, runtime-created
entries, dynamic response, network/device/security effects, and evidence.

## Deterministic Detection And Correlation Algorithms

Local prevention is not enough when an effect was allowed, happened before
attachment, used an existing encrypted channel, or originated outside the
node. Mithril Control runs versioned packages over immutable observations.

### Evidence prerequisites

Every package declares:

```text
PackagePrerequisite {
  required_sources[]
  required_coverage_intervals[]
  maximum_lateness_by_source
  exact_join_fields[]
  permitted_contextual_fields[]
  suppression_requirements[]
}
```

An unavailable audit feed produces `insufficient_coverage`, not “no malicious
operation.” Events can arrive in any order. Package state is keyed by exact
subjects and recomputed when late evidence arrives; duplicates are idempotent.

### `HF-PROC-001`: unexpected native effect

This package explains a local deny or audited deviation:

```text
input: exact TaskLabel + EntryInstance + role + EffectObservation

if task/entry identity incomplete:
    emit LineageCoverageGap, not a proven malicious edge
else if effect decision is deny:
    emit UnexpectedEffect with prevention point and physical errno
else if effect is allowed but outside reviewed role baseline:
    emit AuditedRoleDeviation

attach:
  native ancestors, entry class, binary object identity, cgroup/Pod/container,
  policy generation, dynamic state, hook, decision, loss counters
```

The finding does not rely on a process name such as `curl`. The same binary can
be allowed from a declared tool role and denied from an exec-probe or worker
role.

### `HF-DW-001`: credential-to-authority pivot

This package correlates an observable credential access or credential-bearing
channel with later authority use:

```text
state key = exact credential object/lease when available,
            otherwise exact process/socket/workload scope with weaker proof

facts:
  A = protected credential object read or credential lease obtained
  B = socket/channel to authority or credential used in provider audit
  C = server-side operation outside AuthorityBehaviorRule

if A and B share exact task/process/socket/lease proof and C is authoritative:
    emit direct credential_pivot path
else if only workload + principal + bounded time match:
    emit contextual hypothesis; do not authorize credential-specific response
```

Expected controller token reads and expected API verbs are negative controls.
Two Pods sharing a ServiceAccount name never receive an exact credential edge
from that name alone.

### `HF-XNODE-001`: distributed Kubernetes expansion

```text
LinuxExecution A on node 1
  -> process_issued_api_request (exact socket/request or credential proof)
  -> Kubernetes AuditEvent auditID
  -> api_request_created_or_mutated_resource object UID/resourceVersion
  -> owner-reference/controller reconcile chain
  -> Pod UID
  -> scheduler binding/spec.nodeName
  -> container full ID/cgroup on node 2
  -> ContainerStartEntry
  -> LinuxExecution B on node 2
```

Each arrow is a typed immutable edge with evidence IDs, proof strength,
coverage references, and missing fields. Time adjacency, an IP address, a
label selector, a ServiceAccount name, or the same process name cannot create
the direct path alone. Fan-out creates one branch per exact object/Pod/root.

### Provider and connector expansion

AWS, mesh, connector, GitHub, artifact, and message systems use the same rule:

- exact request IDs, credential lease/access-key IDs, installation IDs,
  connector invocation IDs, message IDs/offsets, and immutable artifact
  digests can create direct edges;
- principal name, repository name, IP, mutable tag, and time can create only
  contextual evidence;
- a network flow proves communication, not a remote command or API verb; and
- late provider evidence creates a new finding/lineage version without
  rewriting the earlier view.

## Response Algorithms

### Exact local restriction

An authorized local response inserts this key:

```text
ResponseRootKey = (node_boot_id, label_epoch, process_lineage_id)

ResponseRestriction {
  request_id
  target_process_instance_id
  permitted_emergency_effects
  deny_effect_families
  socket_fence
  expires_at
  policy_generation
}
```

Every protected hook checks the current process-lineage ID and bounded ancestor
vector. Existing and future descendants therefore match without waiting for a
userspace tree walk. A task iterator/pidfd reconciliation verifies that the
enumerated subtree agrees and reports missing/overflow branches.

The algorithm is:

1. Re-resolve node boot, label epoch, task/process cookie, native coordinates,
   cgroup, Pod UID, and container live interval.
2. Reject stale, ambiguous, bootstrapped-incomplete, or depth-overflow targets
   for exact-subtree response.
3. Insert the response root with TTL and read it back.
4. Run a fresh denied file, exec, socket, and device probe from the target
   scope where safe.
5. Fence existing sockets/packets if requested; an LSM connect deny alone does
   not stop an established connection.
6. Optionally freeze or signal only through separately authorized operations.
7. Watch for future descendants until the response closes.
8. Record `verified`, `partial`, `failed`, or `unknown` from physical
   postconditions.

### Cgroup and workload response

If exact lineage is incomplete, the product may propose a broader cgroup
egress fence or freeze. Before authorization it must show every known task and
container affected. In a shared interpreter, it explicitly states that all
in-process jobs may be interrupted and that no kernel evidence identifies one
logical job.

Kubelet can restart a container and a controller can replace a Pod. Therefore
process kill alone is not distributed containment. The coordinator separately
tracks:

- current local process/socket branches;
- container restart under the same Pod;
- replacement Pod UIDs created by the owning controller;
- remote node branches;
- credential/provider sessions; and
- artifact, mesh, connector, or source-control branches.

### Distributed response

```text
plan(distributed_lineage_version):
    fence proven seed process/socket immediately when locally authorized
    enumerate exact open branches and their authority owners
    produce one typed action per node/controller/provider target
    require target-specific approval and revalidation
    execute idempotently
    keep a watch open for replacement or late branches
    verify each physical postcondition

result = verified only if every required branch verifies under healthy
         required coverage through the watch interval
```

An offline node, an outside-authority environment, a contextual-only branch,
or unavailable provider verification forces `partial` or `unknown`.

## Per-Incident Protection Design

This section answers “what should Mithril do?” for every published stage. The
event IDs refer to the normalized
[live action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md).

### `HF-001` through `HF-007`: external evaluation foothold and staging

**Situation.** The recovered root shell, environment discovery, public exfil,
remote staging, packing, and reconnaissance occurred in an external evaluation
environment outside the protected Hugging Face estate.

**Mithril action.** A Hugging Face deployment records these as outside-authority
subjects if provider or shared-artifact evidence later refers to them. It does
not claim local prevention. If Mithril is independently installed in an
evaluation estate, the ordinary policies apply: unexpected exec edges,
protected environment/credential access, public C2 destinations, anonymous
executable mappings, and remote loaders are denied by that estate's profile.

**Correlation.** Later exact artifact digests, credential IDs, connector
request IDs, or mesh enrollment IDs may connect the outside subject to a
protected branch. Similar commands or close timestamps do not.

**Acceptance.** The report must say `outside_authority` for the external
actions and must not turn them into fictitious ancestors of a Hugging Face
process.

### `HF-008`: hostile HDF5 external-file reference reaches conversion

**Situation.** An admitted dataset causes the unchanged conversion worker to
ask HDF5 to open a filesystem object selected by hostile metadata.

**Local policy.** The `conversion-worker-root` role may read only
`dataset-input`, reviewed runtime/library objects, and declared scratch/output
objects. An HDF5 external-file target resolved to
`worker-environment-procfile`, a projected credential, another Pod/process,
host filesystem, device, or an object outside the admitted dataset view is
denied at `file_open` before bytes are returned.

**Algorithm.** The file classifier uses the live mount namespace, mount ID,
inode/superblock identity, resolved proc target where applicable, and admitted
dataset mount provenance. It does not permit `../`, symlink, bind-mount, or
`/proc/<pid>/fd/<n>` aliases merely because the original string resembles the
dataset directory. The decision is attached to the exact interpreter task and
entry instance even though no child process exists.

**Central evidence.** The dataset/revision is connected to the worker only if
the platform supplies an exact immutable revision or dispatch identifier. If
the application supplies no job/revision event, Mithril reports the exact
process and file object but does not guess which concurrent logical job caused
it.

**Response.** Restrict the exact process lineage or, if the interpreter is
shared and continued execution is unsafe, propose a cgroup fence/freeze with
the explicit multi-job blast radius. Quarantine of one dataset revision is
eligible only with exact platform evidence.

**Required test.** A non-weaponized HDF5 fixture attempts an external read of
an allowed dataset sidecar file and of each protected object alias. The allowed
case completes; every protected case returns `EACCES`; no protected bytes enter
the converted output; `HF-LOCAL-001` contains the exact task, object key,
policy generation, and denial hook.

**Limit.** Mithril does not claim to reject the HDF5 structure at upload. That
would be an optional artifact scanner/admission control. The baseline prevents
the worker-side prohibited file effect.

### `HF-009`: worker environment and secrets are disclosed

**Situation.** Hostile processing obtains worker context or secrets and
publishes them through a dataset/result or network channel.

**Local policy, observable file path.** Opening `/proc/self/environ`, another
task's environ, a projected secret, token, cloud credential file, or host
configuration is evaluated by object class. If the conversion role has no
declared need, the read is denied before completion. An allowed but sensitive
read can set `OBSERVED_SENSITIVE_READ`, causing stricter later artifact and
egress decisions.

**Local policy, in-memory path.** If Python reads its own already resident
environment, the read has no distinguishable kernel file effect. Mithril
therefore evaluates the next action:

- a new/public socket or unapproved destination is denied;
- an output file/repository object outside the role is denied;
- an unexpected helper exec is denied; and
- an operation inside the same required encrypted publication channel is
  detected from service/provider audit when available.

**Correlation.** `HF-DW-001` joins an observable protected-object read to the
later socket/artifact/provider operation by exact task/process/socket or
credential lease. If only the same Pod and time are known, the edge remains
contextual.

**Response.** Restrict the exact lineage and fence its sockets. If authoritative
audit proves a result/dataset revision was written, mark that immutable
revision for review or quarantine through a separately authorized repository
action. Rotate/revoke a credential only when its exact identity and blast
radius are known.

**Required test.** The fixture has four branches: `/proc/self/environ`,
projected-token file, `os.environ` with public egress, and `os.environ` with an
already allowed TLS destination. The first two prove file denial, the third
proves network denial, and the fourth proves an honest
`semantic_effect_completed`/provider-audit result rather than a kernel
prevention claim.

### `HF-010`: template-based Python execution in the worker

**Situation.** Hostile template evaluation runs inside the already approved
Python interpreter.

**Local policy.** Mithril does not attempt to classify Python bytecode or
template intent. It denies the first prohibited physical effect:

- `python -> sh/curl/tailscale` at `bprm_check_security`;
- a module/plugin file outside the allowed code objects at file open/map;
- memfd or anonymous executable memory for a non-JIT role at exec/mmap;
- projected token, proc, host, or device access at file/device hooks;
- API/IMDS/C2 at socket hooks; or
- ptrace, namespace, mount, BPF, perf, capability, or module effects at the
  corresponding security hook.

**Algorithm.** This is an effect-state machine on the existing task label.
There is no prerequisite child process and no command-line signature.

**Response.** The exact interpreter process is the smallest native target. If
it hosts several logical jobs, Mithril states that containing it affects all
of them. It does not invent a job-specific response.

**Required test.** The malicious behavior driver performs prohibited file and
socket actions directly from Python without `subprocess`, then repeats them
through a helper child. Both in-process and exec-edge paths must be denied at
their respective pre-effect hooks. A pure arithmetic/template operation with
no effect must remain intentionally unclassified.

### `HF-011`: projected Kubernetes ServiceAccount token read

**Situation.** The compromised worker opens its projected ServiceAccount
token, or obtains equivalent credentials already loaded by legitimate code.

**Local policy.** The binder classifies the projected volume and rotating token
objects for the exact Pod/container. `conversion-worker-root` denies reads if
the worker does not need them. A controller role that legitimately reads the
same mounted token receives a reviewed token-read rule and a narrower
authority behavior rule; the entire Pod is not globally allowed.

**Algorithm.** A successful audited token read records the exact task,
process, file object, projected-volume provenance, ServiceAccount/Pod binding,
and profile generation, then optionally sets the sensitive-read state. Token
contents are never stored in evidence.

**Already-held credential.** If the token was read before attachment or is
already in memory, file denial is no longer prevention. Socket and Kubernetes
audit decisions remain active. Coverage reports the pre-attachment gap.

**Response.** Restrict the process/socket first. Deleting the Pod or revoking
broad ServiceAccount authority is not automatic. A projected token naturally
rotating does not prove every external bearer copy is invalid; provider-side
recovery follows Kubernetes' actual token type and issuer semantics.

**Required test.** Token rotation replaces the inode while the same projected
object class remains protected. A legitimate controller in the same Pod or on
the same node continues its declared read/API behavior; the conversion role
gets `EACCES`. Secret/token bytes never appear in WAL or findings.

### `HF-012`: Kubernetes API and cloud metadata probing

**Situation.** The foothold probes Kubernetes control-plane addresses and
cloud IMDS to enumerate or obtain authority.

**Local policy.** The node maintains destination classes for every discovered
API and metadata address: service IP, endpoint IPs, public/private API names,
IPv4/IPv6 link-local metadata, secondary interfaces, and provider-specific
paths. A conversion role with no need is denied on in-process connect/send;
no helper exec is required.

For a role that legitimately needs an API destination, network access remains
allowed. Kubernetes/provider audit then evaluates the exact principal, verb,
resource, namespace/account, result, and request ID against its
`AuthorityBehaviorRule`.

**Algorithm.** DNS observation updates provenance but the actual address and
network namespace drive the kernel decision. Existing socket storage retains
creator/current role. An established allowed connection is not reclassified
by TLS bytes; response uses the packet fence.

**Response.** Denied probes require no broad network change. A completed
forbidden API operation triggers exact process/socket restriction and a typed
Kubernetes/provider response against the resulting object or credential, with
resource UID/version preconditions.

**Required test.** `HF-NET-001` tries hard-coded IP, DNS, IPv6, alternate API
endpoint, and IMDS paths directly from Python. Negative controls exercise a
legitimate controller's expected API operation. A forbidden verb over its
allowed connection is detected from audit and is not mislabeled as a connect
denial.

### `HF-013`: dataset repository used as a dead-drop

**Situation.** A leaked write-capable token is used to publish an artifact or
dataset revision that becomes staging, C2, or a handoff point.

**Local prevention.** If the acting role does not need the repository
destination, connect/send is denied. If it has read-only network use but a
different endpoint or credential identity exists for writes, the profile can
deny the write channel. If read and write share the same process, endpoint,
credential, and TLS connection, the kernel cannot distinguish them.

**Authority behavior.** Repository audit must identify repository, actor/token
or principal, operation, immutable revision/commit/artifact ID, request ID,
and result. An unexpected create/update is a server-side deviation even when
the local channel was allowed.

**Correlation.** The exact written artifact digest/revision connects the
writer to later consumers. Repository name, filename, mutable branch/tag, or
time alone is contextual.

**Response.** Fence the source process/channel; revoke the exact token or
session when supported; quarantine or remove the exact immutable malicious
revision; enumerate downstream loads. Deleting an entire repository is not
the default.

**Required test.** A fixture permits a legitimate read and attempts a write on
the same TLS destination. The node reports network ambiguity; provider audit
produces the write finding. A separately identifiable write endpoint/token is
denied pre-effect. No test claims packet inspection recognized a repository
verb.

### `HF-014`: compromised node reaches mesh control

**Situation.** Code on the protected estate invokes or contacts mesh tooling
and its control service.

**Earliest prevention chain.** Any one of these independent policy gates can
stop the branch when absent from the conversion role:

1. deny `python -> tailscale` or another unapproved mesh executable object;
2. deny `/dev/net/tun` and its ioctls;
3. deny network/namespace/capability effects needed to establish the mesh;
4. deny the mesh-control destination; or
5. detect a forbidden mesh enrollment/control operation from provider audit.

The finding records which gate actually prevented the physical effect. It
does not claim all later gates fired after an earlier denial.

**Response.** Restrict the local lineage, fence existing mesh sockets, and use
a typed mesh action for the exact device/node/auth key. Revoking an enrollment
key and deleting an already enrolled device are different postconditions.

**Required test.** The fixture independently attempts unexpected mesh exec,
TUN open/ioctl, raw socket/capability, control connection, and use of an
already established mesh flow. Each advertised gate and the packet fence have
their own physical assertion.

### `HF-015`: attacker environment enrolls into the mesh

**Situation.** An external environment joins the organization's mesh. The
joining process may be outside every Mithril node.

**Mithril action.** Mesh audit creates an external subject keyed by exact
device/node/enrollment/auth-key identifiers. Credential acquisition/use and
the enrollment result form typed provider edges. A local node is connected to
that branch only with exact shared credential, request, or connector evidence.

**Prevention boundary.** Without a mesh admission integration, the enrollment
may complete before audit arrives. Mithril calls this detection/containment.
An optional provider-side pre-admission policy can deny unknown device posture
or unapproved enrollment, but it is not kernel prevention.

**Response.** Expire/revoke the exact enrollment credential to stop new joins,
delete or disable the enrolled device to stop the existing member, and verify
both separately. Search for other devices enrolled with the same credential.

**Required test.** The response test proves that key revocation alone does not
remove an existing device, then verifies the distinct device-removal action.
An outside-authority origin keeps the distributed result `partial` until the
provider branch is contained.

### `HF-016`: mesh access reaches an internal connector catalog

**Situation.** An enrolled mesh client reaches a connector or catalog that can
expose cluster/cloud/source-control context.

**Local policy.** On managed connector hosts, Mithril applies a connector
service role: declared listeners and upstreams are allowed, but unexpected
child exec, credential objects, destinations, devices, and privilege effects
are denied. A network flow from a mesh peer proves communication only.

**Authority behavior.** Connector-native audit should carry authenticated
source device/principal, connector ID, catalog/resource, source request ID,
destination request ID when forwarded, operation, and result. These fields
support `connector_forwarded_request`; a shared connector principal plus time
does not.

**Response.** Fence the compromised mesh device/channel, restrict the exact
connector process if it deviated, disable only affected connector grants or
sessions, and preserve service for unaffected principals where the provider
supports that scope.

**Required test.** A legitimate catalog request and an unexpected request use
the same connector service. Provider/request IDs distinguish them. Removing
those IDs downgrades the edge to contextual and makes connector-specific
automatic response ineligible.

### `HF-017`: harvested AWS credentials are used externally

**Situation.** A credential obtained from the protected estate is used from an
external origin to call AWS.

**Earlier prevention.** Deny the credential file/IMDS effect or the local
exfiltration channel when distinguishable. If the credential has escaped,
node enforcement cannot stop an external AWS request.

**Correlation.** Cloud audit resolves access-key ID, assumed-role session,
principal ARN, account, request/event ID, source, API operation, resource, and
result. An exact access-key/session ID can connect credential acquisition to
use. The same IAM role name used concurrently by several workloads is not an
exact edge.

**Authority behavior.** Expected role operations remain quiet. A new source,
operation, resource, region, or session behavior outside the signed rule emits
a versioned finding. Behavioral novelty supports detection but does not replace
the exact provider identity.

**Response.** Revoke/disable the exact access key or role session where
possible, apply a narrowly scoped deny/quarantine, enumerate resources changed
by that session, and verify provider state. Broad role-session revocation has
an explicit blast radius and approval.

**Required test.** Two workloads concurrently use the same role name with
different sessions. Only the exact compromised session is joined and targeted.
A shared-name-only case remains contextual. Resource postconditions are
verified after revocation.

### `HF-018`: source-control installation token is minted

**Situation.** A connector or compromised authority asks GitHub to mint a
GitHub App installation token and may then modify source or CI state.

**Local policy.** If the connector process/destination is unexpected, node
policy denies it. If the connector legitimately talks to GitHub over direct
TLS, the kernel cannot determine whether the HTTPS request is token creation,
clone, push, email-like notification, or another API operation.

**Authority behavior.** Connector audit and GitHub audit/API state identify the
App, installation, actor, token request where exposed, repositories,
permissions, operation, request/delivery IDs, and result. The signed behavior
rule permits expected installation operations and flags token minting or
write-capable repository effects outside them.

**Optional prevention.** A GitHub/connector-side policy integration at the
semantic API boundary may reject token minting before the provider call. This
does not require TLS interception because the connector itself supplies typed
operation metadata. Without that integration, detection follows authoritative
audit.

**Response.** Revoke a known token where supported, suspend the exact
installation if necessary, rotate App credentials with appropriate approval,
and enumerate commits, branches, workflows, releases, packages, and image
digests changed during the exposure. Token revocation and installation
suspension are distinct actions.

**Required test.** Read and write operations share a GitHub TLS destination.
The node does not claim verb visibility. Provider/connector evidence detects
the token/write effect, and the response verifies repository and installation
state rather than merely receiving HTTP success.

### `HF-019`: public remote loader re-arms fresh sandboxes

**Situation.** New external sandboxes retrieve and execute a public loader,
allowing persistence across ephemeral environments.

**Managed-node prevention.** On any protected node, deny the unapproved loader
destination, artifact write/code mapping, executable edge, memfd/deleted image,
or anonymous executable memory according to role. Artifact digest joins the
download to execution even if its filename changes.

**Outside authority.** If the sandboxes are not managed by Mithril, record them
as external subjects and act on shared provider/artifact/C2 infrastructure
within authority. Do not claim a Hugging Face node stopped their execution.

**Response.** Remove/quarantine the exact artifact or endpoint where
authorized, revoke the credential or dispatch mechanism that causes reload,
and enumerate every consumer by immutable digest/request ID. URL or filename
alone is insufficient for exact consumer lineage.

**Required test.** Execute the same bytes by ordinary file, renamed file,
memfd, deleted file, and anonymous mapping on a protected fixture. Each claimed
execution path is denied. An unprotected external fixture remains explicitly
outside authority.

### `HF-020`: staged binary and host state inspection

**Situation.** The foothold examines staged code and host/process state late in
the campaign.

**Local policy.** The current role is evaluated for procfs/sysfs/debugfs reads,
other-process memory/fds/maps, ptrace, perf, BPF, device access, mount/namespace
operations, host filesystem objects, and executable staging. Normal worker
diagnostics can be declared as exact read-only object classes without granting
general host inspection.

**Correlation.** A series of audited reconnaissance effects from the same
execution can raise finding priority, but every event remains independently
attributed and covered. A process name such as `readelf` is neither necessary
nor sufficient.

**Response.** Restrict the exact lineage and preserve relevant files,
descriptors, memory metadata, and WAL evidence before irreversible kill when
authorized. Evidence preservation cannot silently delay an already authorized
socket fence.

**Required test.** The profile allows one declared diagnostic file and denies
cross-task proc, ptrace, perf, BPF, debugfs, host mount, and staged executable
cases. Ring-buffer loss during a denial does not permit the operation.

### `HF-021`: access cut and end of recovered activity

**Situation.** Defenders sever access and activity ends. The architectural
question is how Mithril proves containment rather than infers it from silence.

**Response plan.** Mithril:

1. fences the proven local seed process and established flows;
2. follows the exact versioned distributed lineage across current nodes,
   controllers, mesh, connectors, cloud, repositories, and credentials;
3. re-resolves and authorizes one typed action per target;
4. watches kubelet/container restarts and controller-created replacement Pods;
5. watches provider feeds for credential reuse, late artifacts, and new
   branches;
6. verifies every physical postcondition; and
7. reports unresolved, outside-authority, or coverage-deficient branches.

**No-silence rule.** “No more alerts” is not a postcondition. Required source
coverage must remain healthy for the declared watch interval. An offline node
or provider-feed gap prevents `verified` containment.

**Required test.** `HF-RESP-002` contains a two-node branch, lets the controller
attempt replacement, delivers one provider event late, and makes one optional
source unavailable. The expected result is deterministic: every required
branch must verify for `verified`; otherwise the result is `partial` or
`unknown` with exact reasons.

## Situation-To-Control Summary

| Stage | Earliest local prevention when available | Required semantic/correlation control | Narrow response |
| --- | --- | --- | --- |
| `HF-008` | role/object file-open denial | exact dataset dispatch/revision if available | process/cgroup plus exact revision only when proven |
| `HF-009` | environ/credential file, artifact, or egress denial | sensitive-read and provider publication evidence | process/socket; exact leaked object/credential |
| `HF-010` | first exec/file/socket/device/security effect | same-process limitation retained | exact interpreter lineage, honest multi-job blast radius |
| `HF-011` | projected-token object denial | exact credential object/lease to authority use | process/socket; token/session-specific recovery |
| `HF-012` | API/IMDS destination denial | Kubernetes/cloud verb and resource audit | exact process/socket and mutated resource/session |
| `HF-013` | repository channel if distinguishable | repository operation and immutable revision | token/session plus exact artifact/revision |
| `HF-014` | mesh exec, TUN, capability, or control destination | mesh operation/device audit | local lineage/socket plus exact mesh device/key |
| `HF-015` | provider admission only; external node may be outside authority | exact enrollment/device/key | revoke new-enrollment key and remove existing device separately |
| `HF-016` | managed connector role/effect policy | exact connector source/destination request IDs | device/channel and affected connector grant/session |
| `HF-017` | earlier credential/IMDS/exfil gate | exact AWS key/session and API audit | exact session/key, then changed resources |
| `HF-018` | unexpected connector/GitHub channel; semantic connector gate if installed | GitHub App/installation/token/repository audit | token or installation plus repository integrity review |
| `HF-019` | destination/artifact/exec/memfd/mmap denial on managed nodes | immutable artifact consumer graph | artifact/dispatch/C2 within authority |
| `HF-020` | proc/ptrace/perf/BPF/device/host-object denial | exact reconnaissance sequence | lineage restriction and evidence preservation |
| `HF-021` | response-root and packet fences | versioned distributed branch watch | independently verified node/controller/provider actions |

## Worked Policy Example

This pseudo-configuration is illustrative, not an approved serialization
format. It shows how an unchanged worker and a kubelet-created probe receive
different authority in the same container.

```yaml
profile: hf-conversion-worker
version: 7
selector:
  namespace: datasets
  labels:
    app: conversion-worker

defaults:
  exec: deny
  file: deny
  network: deny
  device: deny
  security: deny

entries:
  - kind: container-start
    container: application
    imageDigest: sha256:approved-worker-image
    role: conversion-worker-root
    onMissingAdmission: deny-start

  - kind: kubelet-exec-probe
    declaredField: readinessProbe.exec
    commandDigest: sha256:canonical-health-command
    role: kubelet-exec-probe
    maxConcurrent: 2
    ambiguity: deny

  - kind: kubelet-prestop
    declaredField: lifecycle.preStop.exec
    commandDigest: sha256:canonical-cleanup-command
    role: kubelet-prestop
    claimTtl: 2s
    ambiguity: deny

roles:
  conversion-worker-root:
    forkWithoutExec: conversion-worker-child
    maxDepth: 8
    exec:
      - targetObject: approved-converter-helper
        resultRole: declared-converter-helper
    files:
      - allow: [read]
        class: dataset-input
      - allow: [read, mmap]
        class: worker-runtime
      - allow: [read, write, create]
        class: worker-scratch
      - deny: [read]
        class: projected-service-account-token
        setFinding: HF-PROC-001
      - deny: [read]
        class: worker-environment-procfile
    network:
      - allow: [connect, send]
        destination: approved-dataset-service
      - deny: [connect, send]
        destination: [kubernetes-api, cloud-imds, mesh-control, public-internet]
    devices: []
    security: []

  kubelet-exec-probe:
    lifetime: 3s
    childProcesses: deny
    files:
      - allow: [read]
        class: probe-health-file
    network: []
    devices: []
    security: []

  kubelet-prestop:
    lifetime: 20s
    childProcesses: deny
    files:
      - allow: [write]
        class: declared-cleanup-state
    network:
      - allow: [send]
        destination: declared-drain-endpoint
    onActiveContainment: deny

authorityBehavior:
  - principal: conversion-worker-service-account
    sourceRole: conversion-worker-root
    kubernetes:
      allowedOperations: []
    onDeviation: HF-DW-001
```

Consequences:

- the readiness process is legitimate even though the host runtime, not PID 1,
  created it;
- it cannot read the mounted token merely because it shares the container;
- an attacker running the health binary as a native worker child keeps the
  worker-child transition, not the kubelet-probe role;
- a direct unadmitted runtime exec cannot borrow the probe role;
- the worker can process multiple logical jobs without Mithril naming or
  changing them; and
- `preStop` remains subject to active containment policy.

## Configuration And Detection Disposition Model

The earlier `EffectRule.decision: allow | audit | deny` is correct for a small
kernel decision table, but it is incomplete as the operator-facing model.
`audit` does not say whether to notify anyone, `deny` does not distinguish a
syscall denial from rejecting a runtime request, and provider audit may arrive
after the effect can no longer be denied. The complete configuration separates
**physical disposition**, **finding delivery**, and **optional response**.

This is an additive clarification, not a replacement of the earlier rule.
The compiler still lowers effect rules to compact allow/audit/deny values. It
now compiles the full source rule into the correct entry, kernel, finding, and
response plans.

### Exact meaning of the four requested dispositions

| Configured disposition | Physical meaning | Evidence and notification | Valid decision point |
| --- | --- | --- | --- |
| `allow` | Let the entry or effect proceed | Emit only required coverage/evidence or configured sampling; no finding by default | Entry, transition, local effect, or provider behavior rule |
| `alert` | Let the action proceed | Persist a finding and route the configured notifications; no claim of prevention | Any observable point, including provider audit after completion |
| `deny` | Return the hook-specific failure before the protected local effect completes, such as `EACCES` for file/exec or `EPERM` for a security operation | Always persist a denial finding when evidence transport is available; notification routing remains configurable | Synchronous local pre-effect hook only |
| `reject` | Refuse the higher-level request before its process/lease/provider operation is admitted | Persist a rejection finding and return a typed reason to the runtime, CI coordinator, admission service, or semantic connector | Entry admission or another synchronous semantic request boundary |

`alert` is therefore “allow plus finding,” not a weaker spelling of deny.
`reject` is not a different errno for `open(2)`: a file hook can deny the open,
but it cannot reject a CI job that already started. Conversely, a provider
audit record that says a GitHub token was minted can alert and trigger response,
but cannot deny the already-completed mint. If a typed GitHub/connector
pre-admission integration exists, that integration can reject the request.

### Source configuration objects

```text
DetectionDispositionRule {
  rule_id
  enabled
  priority
  match {
    finding_id?
    entry_kind?
    role_id?
    effect_family?
    operation?
    object_class?
    authority?
    provider_operation?
    lifecycle_state?
    intent_issuer?
    intent_strength_at_least?
    source_quality_at_least?
    trigger_trust_class?
    namespaces_or_workloads?
  }

  disposition: allow | alert | deny | reject
  errno?
  severity
  evidence_level: minimal | standard | forensic
  notify[]
  response_playbook?

  fallbacks {
    missing_intent
    ambiguous_intent
    source_unavailable
    classifier_unknown
    control_plane_unavailable
    response_authority_unavailable
  }

  budgets {
    max_per_interval?
    max_concurrent?
    max_lifetime?
    notification_dedupe_window?
    automatic_response_limit?
  }

  exceptions[]
  valid_from?
  valid_until?
  approval_id?
}
```

Notification and response are explicit collaborators:

```text
NotificationRoute {
  route_id
  sink: pager | chat | email | siem | webhook | ticket
  minimum_severity
  grouping_key
  dedupe_window
  rate_limit
  include_evidence_fields[]
  redact_fields[]
  delivery_failure_action
}

ResponseBinding {
  playbook_id
  action: restrict_lineage | fence_sockets | freeze_cgroup |
          reject_replacement | revoke_credential | disable_mesh_device |
          quarantine_artifact | suspend_installation | provider_specific
  required_proof
  approval: automatic | preapproved | human
  max_blast_radius
  target_revalidation
  physical_postcondition
  watch_interval
}
```

No rule sends secret bytes, token values, full environments, or unrestricted
argv into a notification. Evidence fields are allowlisted and redacted before
leaving the node.

### Compiler output and impossible configurations

One source rule compiles to a capability-specific plan:

```text
CompiledActionPlan {
  local_pre_effect_result: allow | audit_allow | errno_deny | not_applicable
  entry_admission_result: admit | reject | not_applicable
  emit_finding: yes | no
  severity
  notification_route_ids[]
  response_binding_id?
  required_proof
  fallback_plan
}
```

The compiler rejects configurations that promise an impossible physical
outcome:

- `reject` on a plain file/socket hook, because only `deny` is physically
  available there;
- `deny` on a GitHub, AWS, mesh, database, or Kubernetes audit event that
  arrives after the operation completed;
- `reject` on a provider operation without a configured synchronous provider,
  admission, broker, or connector boundary;
- `allow` that would erase a prior SELinux/AppArmor/Landlock/BPF LSM denial;
- `allow` for a hard product invariant such as a stale protected identity in a
  strict profile;
- an automatic response whose required identity or postcondition is absent;
- `alert` with a notification route that can leak a protected credential; or
- a fail-open fallback for a required classifier in a profile that claims
  prevention.

Configuration controls Mithril's behavior where Mithril has authority. It
cannot configure history. An already-completed external AWS call cannot become
“denied” by choosing that word in YAML.

### Precedence between configuration rules

For rules that match the same action:

1. A nonzero prior security-module denial remains final.
2. Active response restrictions and immutable product invariants apply.
3. Exact workload, role, entry, object, provider principal, and operation
   matches outrank broader matches.
4. A more restrictive physical disposition wins: `reject` at an admission
   point or `deny` at an effect point outranks `alert`, which outranks `allow`.
5. Notifications and response bindings are unioned only within configured
   budget and blast-radius limits.
6. An explicit exception must name the rule it narrows, its exact subject,
   approver, expiry, and maximum authority. A broad exception cannot erase a
   hard invariant.

The compiler emits a conflict report that names both source rules, the exact
tuple, the selected result, and why. It never depends on source-file ordering.

### Practical configuration example

This remains prospective YAML, but it is concrete enough to define parser,
compiler, simulator, and acceptance-test behavior:

```yaml
profile: hf-conversion-worker
version: 8
mode: protect

failurePosture:
  missingTaskIdentity: deny
  requiredClassifierUnknown: deny
  intentChannelUnavailable: reject
  providerFeedUnavailable: alert
  notificationUnavailable: keep-enforcement-and-buffer

notificationRoutes:
  security-pager:
    sink: pager
    minimumSeverity: critical
    groupingKey: [executionSetId, processLineageId, findingId]
    dedupeWindow: 2m
    redact: [argvSecrets, environmentValues, tokenBytes]

  defender-stream:
    sink: siem
    minimumSeverity: medium
    groupingKey: [findingId, providerPrincipalId, objectId]
    dedupeWindow: 15s
    redact: [tokenBytes]

responses:
  restrict-compromised-worker:
    action: restrict_lineage
    approval: preapproved
    requiredProof: exact-task-lineage
    maxBlastRadius:
      processes: 32
      executionSets: 1
    verify: no-new-protected-effect-from-lineage

  revoke-exact-aws-session:
    action: revoke_credential
    approval: human
    requiredProof: exact-provider-session
    verify: session-rejected-and-no-later-cloud-events

dispositions:
  - id: admit-exact-readiness-probe
    match:
      entryKind: kubelet-exec-probe
      intentStrengthAtLeast: exact
      lifecycleState: running
    disposition: allow
    evidenceLevel: standard
    fallbacks:
      missingIntent: reject
      ambiguousIntent: reject

  - id: observe-same-budget-probe-ambiguity
    match:
      entryKind: kubelet-exec-probe
      intentStrengthAtLeast: conservative
    disposition: alert
    severity: medium
    notify: [defender-stream]
    budgets:
      maxConcurrent: 2
      maxLifetime: 3s

  - id: reject-unapproved-runtime-root
    match:
      findingId: UNAPPROVED_RUNTIME_ENTRY
    disposition: reject
    severity: high
    notify: [defender-stream]

  - id: deny-conversion-worker-token-read
    match:
      roleId: conversion-worker-root
      effectFamily: file
      operation: read
      objectClass: projected-service-account-token
    disposition: deny
    errno: EACCES
    severity: critical
    notify: [security-pager, defender-stream]
    responsePlaybook: restrict-compromised-worker

  - id: deny-worker-control-plane-connect
    match:
      roleId: conversion-worker-root
      effectFamily: network
      operation: connect
      objectClass: [kubernetes-api, cloud-imds, mesh-control]
    disposition: deny
    errno: EACCES
    severity: critical
    notify: [security-pager, defender-stream]

  - id: alert-completed-aws-deviation
    match:
      findingId: HF-DW-001
      authority: aws
      sourceQualityAtLeast: exact-provider-session
    disposition: alert
    severity: critical
    notify: [security-pager, defender-stream]
    responsePlaybook: revoke-exact-aws-session

  - id: reject-github-token-mint-at-typed-connector
    match:
      authority: github
      providerOperation: create-installation-token
      intentStrengthAtLeast: exact
    disposition: reject
    severity: critical
    notify: [security-pager, defender-stream]
    # Valid only when the configured connector is a synchronous semantic gate.

  - id: alert-github-token-mint-from-audit
    match:
      authority: github
      providerOperation: create-installation-token
      sourceQualityAtLeast: authoritative-audit
    disposition: alert
    severity: critical
    notify: [security-pager, defender-stream]
    # Audit-only deployments cannot claim that token minting was rejected.
```

### One detection evaluated in four configurations

Assume the exact `conversion-worker-root` task opens the projected token:

| Configuration | Kernel result | Finding result | What the operator sees |
| --- | --- | --- | --- |
| `allow` | `open(2)` succeeds | No finding unless evidence sampling is enabled | Normal workload evidence only |
| `alert` | `open(2)` succeeds | `HF-PROC-001` is persisted and routed | Alert explicitly says `semantic_effect_completed` |
| `deny` | `open(2)` returns `EACCES` before bytes are read | Denial finding is persisted and optionally paged | Alert says `prevented`, with hook and errno proof |
| `reject` | Compiler error for this match | No generation is activated | Compiler explains that file effects support `deny`, not entry rejection |

Now assume an unapproved `kubectl exec` request:

| Configuration | Admission result | Meaning |
| --- | --- | --- |
| `allow` | Runtime root is admitted with the explicitly configured administrative role | The process still receives that role's effect limits |
| `alert` | Root is admitted and a finding is routed | Useful during rollout, but not prevention |
| `deny` | Compiler error at this semantic entry boundary | Configure `reject`; a syscall deny may still happen later but is a weaker lifecycle result |
| `reject` | Runtime/CRI admission returns a typed rejection before the user command starts | Correct physical prevention for an entry request |

### Rollout and exceptions

Every rule can be simulated and rolled out without silently changing its
meaning:

```yaml
rollout:
  phase: observe            # simulate deny/reject, physically allow, alert
  selectedNodes: 5%
  minimumHealthyCoverage: 99.99%
  promoteAfter: 24h
  abortOn:
    - required-hook-detached
    - identity-classifier-miss-rate-above: 0.001%
    - legitimate-entry-rejection-above: 0
```

In `observe`, the result is named `would_deny` or `would_reject`; it is never
reported as physical prevention. Promotion creates a new signed policy
generation. A temporary exception names exact Pod/container/image/role/object
or provider identity, has an owner and expiry, is simulated, and is visible in
every affected finding.

## CI/CD Execution And Intent Mapping

CI/CD is not one process tree. A workflow can fan out to jobs on different
nodes, run native shell/JavaScript children, create job and service containers,
start privileged build daemons, pass caches/artifacts to later jobs, obtain
short-lived cloud credentials, wait for human approval, deploy, and run cleanup
after failure. Mithril must preserve each physical shape instead of calling the
whole workflow one container or one process.

### Current execution practices the model must cover

- GitHub Actions workflows contain jobs, and jobs contain ordered steps. Jobs
  can run directly on a runner or in a job container. Docker container actions
  can run as sibling containers on the same network and shared workspace. See
  GitHub's [Actions execution overview](https://docs.github.com/en/actions/get-started/understand-github-actions),
  [job-container documentation](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container),
  and [custom container hooks](https://docs.github.com/en/actions/how-tos/manage-runners/self-hosted-runners/customize-containers).
- GitHub creates a job-scoped `GITHUB_TOKEN`, and a job with `id-token: write`
  can request an OIDC token containing claims such as repository, ref,
  workflow, workflow SHA, run ID/attempt, actor, environment, and runner type.
  These are job/workflow claims, not a proof of one shell step. See the
  [`GITHUB_TOKEN` contract](https://docs.github.com/en/actions/concepts/security/github_token)
  and [OIDC claim reference](https://docs.github.com/en/actions/reference/security/oidc).
- GitLab's Docker executor has prepare, pre-job, job, and post-job phases, with
  helper and service containers. Its Kubernetes executor creates a Pod for
  each job with build, helper, and service containers. See the
  [Docker executor](https://docs.gitlab.com/runner/executors/docker/) and
  [Kubernetes executor](https://docs.gitlab.com/runner/executors/kubernetes/).
- GitLab CI ID tokens contain exact pipeline/job/runner/project/ref/config
  claims and a unique token ID. They prove the signed claims for the job, not
  arbitrary step intent. See [GitLab ID token authentication](https://docs.gitlab.com/ci/secrets/id_token_authentication/).
- Tekton runs a Task as a Kubernetes Pod. Steps are ordered containers;
  sidecars overlap the steps and workspaces/results cross step boundaries. See
  [Tekton Tasks](https://tekton.dev/docs/pipelines/tasks/).
- Jenkins can allocate a different agent for a pipeline or stage, run shell or
  container steps, execute parallel/matrix branches, and run `post`/`cleanup`
  steps after success, failure, or abort. See the
  [Jenkins Pipeline syntax](https://www.jenkins.io/doc/book/pipeline/syntax/).

These are examples of stable execution shapes, not mandatory vendor
integrations. The core model is coordinator-neutral.

### CI identity objects

```text
PipelineRun {
  pipeline_run_id
  coordinator_id
  tenant_id
  repository_or_project_id
  trigger_event
  trigger_actor
  trigger_trust_class: trusted_ref | untrusted_change | scheduled |
                       manual_approved | policy_generated
  source_ref
  source_sha
  pipeline_definition_ref
  pipeline_definition_digest
  run_number
  run_attempt
  parent_pipeline_run_id?
}

PipelineJob {
  pipeline_job_id
  pipeline_run_id
  job_definition_id
  matrix_coordinates?
  environment?
  runner_id
  runner_group
  node_id?
  executor_kind: host | vm | container | kubernetes | remote
  job_image_digest?
  credential_audiences[]
  state
}

PipelineStepIntent {
  step_intent_id
  pipeline_job_id
  step_definition_path
  step_definition_digest
  action_or_script_digest
  action_source_ref_and_sha?
  expected_shape: native_transition | runtime_container_root |
                  service_root | coordinator_builtin
  input_artifact_digests[]
  requested_role_id
  requested_authority_leases[]
  parent_step_intent_id?
  one_use_nonce
  not_before
  deadline
}
```

Display names such as `Build`, `Test`, or `Deploy` are contextual labels. The
authority key uses immutable coordinator IDs, workflow/config digests, job and
step definition identities, run attempt, and signed trigger trust.

### CI physical-shape matrix

| CI practice | Physical execution | Mithril representation | Default security treatment |
| --- | --- | --- | --- |
| Host/shell executor job | Long-lived runner forks job shell and tools | Runner task keeps `ci-runner-control`; signed job proof authorizes native transition to `ci-job`; every fork/exec stays native | Reject job if exact runner assignment/proof cannot bind before an authority-bearing effect |
| Job container | Runtime creates a root with no native parent in runner tree | `CiJobContainerEntry` plus `coordinator_started_job` causal edge from runner job | Bind exact image, job, workspace, credential audiences, and policy before exec |
| Script, JavaScript, or composite action | Usually native child/exec under the job | `PipelineStepIntent` authorizes a transition; composite substeps retain nested intent IDs | Same executable under another step keeps the other step's role |
| Container action | Runtime creates a sibling/secondary container root | `CiContainerActionEntry` tied to exact action ref/digest and step nonce | No automatic inheritance from job container; only declared shared workspace/network effects |
| Service container | Separate long-lived root overlapping job steps | `CiServiceEntry` with declared listener/client set and job lifetime | Service cannot read job credentials/workspace unless explicitly mounted and allowed |
| GitLab helper, checkout, cache restore, artifact upload | Helper image or runner process outside user build root | Dedicated `ci-helper-*` entries/roles and typed artifact operations | User build cannot claim helper role; helper cannot execute workspace content unless declared |
| Tekton step | New container root for each ordered step | One `CiStepContainerEntry` per TaskRun UID/step name/image digest | Sequential order does not fabricate native parentage; workspace handoff is an artifact edge |
| Tekton/Jenkins/GitHub side service | Concurrent root or background native tree | Independent service entry/tree associated with job | Cleanup deadline does not grant unrestricted authority |
| Matrix or parallel jobs | Separate jobs, often on different nodes | Sibling `PipelineJob` objects under one run with typed dependency edges | No cross-node native parents; each fan-out branch has independent coverage and response |
| Reusable workflow/downstream pipeline | New jobs defined by another immutable workflow/config | `pipeline_called_pipeline` edge carrying caller/callee digests and effective permissions | Called workflow cannot gain authority absent explicit caller policy and provider proof |
| Cache or artifact restore | Bytes cross time, jobs, and possibly trust levels | `ArtifactInstance` plus `published`, `restored`, `verified`, and `executed` edges | Restore may be allowed as data; execution or privileged consumption requires digest/provenance policy |
| OIDC/cloud login step | Native CLI/library call obtains remote authority | `AuthorityLeaseIntent` and resulting `CredentialLease` bound to job/step lineage | Job-level token alone cannot authorize every step; exact requested audience/role/project is checked |
| Deploy step (`kubectl`, Helm, Terraform, cloud CLI) | Native process plus encrypted provider operations; may create remote roots | Local step role plus provider audit and cross-node resource/controller/runtime edges | Allow only declared operations; reject through semantic gate when available, otherwise alert/respond to audit deviation |
| Post/finally/cleanup step | Runs after success, failure, cancellation, or abort | Separate `ci-post-cleanup` intent and role under terminal job lifecycle | Cleanup has only exact cleanup effects and remains restricted during containment |
| Interactive debug/web terminal | External administrator request creates shell/root | `CiAdministrativeEntry` with actor, approval, TTL, recording/coverage proof | Default reject on protected runners; never reuse build/test role |
| Docker socket or Docker-in-Docker | Job can ask another runtime/daemon to create descendants | Device/socket effect plus subordinate runtime entry graph | Untrusted role denies daemon socket; allowed builders must bind every created root or lose full coverage claim |

### Coordinator-to-task binding algorithm

```text
on_ci_job_assigned(signed_job_proof):
    verify coordinator issuer and immutable pipeline definition
    verify repository/project, ref/SHA, trigger actor/trust, run attempt
    verify exact runner/node assignment and requested executor shape
    create PipelineRun/PipelineJob if absent; stage one-use job intent

on_ci_step_started(signed_step_proof):
    verify job is live and proof belongs to current run attempt
    resolve immutable action/script/image and input artifact digests
    compute requested role and authority leases from signed policy

    if expected shape is native_transition:
        stage TransitionIntent for exact labeled runner/job lineage
    else:
        stage EntryIntent for exact runtime container/service root

    reject proof reuse, wrong parent job, mutable action tag without resolved
           digest, wrong artifact, wrong image, wrong node, or expired deadline

on_task_or_root_claim(intent, live_task):
    re-resolve task/cgroup/container/image and existing native label
    require claim type to match physical shape
    install role before first protected effect
    emit exact coordinator-to-entry/transition edge
```

A runner-side producer can use a local authenticated socket to send these
small assertions. On GitHub self-hosted Linux runners, container customization
hooks expose prepare/job/container-step/script-step/cleanup lifecycle points,
but that interface is preview and does not by itself provide a cryptographic
step identity. A production adapter therefore signs records with a runner
identity, includes the service-issued job identity, and resolves immutable
workflow/action digests. For other coordinators, Mithril uses their supported
runner plugin, task admission, webhook, or controller API. None becomes a
second node gatherer.

### Practical untrusted-PR and artifact example

A trusted `pull_request_target` workflow can accidentally download or check out
untrusted pull-request code and then execute it with a write-capable token.
GitHub documents this class and also warns that artifacts from an untrusted
workflow must be treated as untrusted. Mithril models trust as data provenance,
not as the workflow file's display name:

1. The coordinator proof says the workflow definition comes from the trusted
   base branch, but the trigger is an untrusted fork pull request.
2. Checkout or artifact download creates an `ArtifactInstance` labeled with
   source repository, source SHA/run, producer trust, digest, and verifier
   result.
3. The checkout helper may write those bytes to the workspace. That does not
   authorize execution.
4. `make test`, `npm install`, `cargo test`, Python import, shell sourcing, or
   loading a plugin from that tree causes an exec/file/mmap transition whose
   input provenance is `untrusted_change`.
5. Policy assigns `ci-untrusted-build`, which denies repository writes,
   workflow mutation, cloud OIDC audiences, runner-control sockets, host
   credentials, deployment APIs, and protected environment secrets.
6. A later publish/deploy job can consume only an exact artifact digest with
   the configured producer run, review/attestation proof, and promotion edge.
   A mutable filename or “successful build” string is insufficient.

This catches indirect execution too. The process does not need to run
`./malware`; a package install script, `build.rs`, test discovery, compiler
plugin, Makefile, or container build can execute attacker-controlled code.
Mithril follows the file/artifact provenance into the resulting role and
physical effects.

### Practical CI policy

```yaml
coordinators:
  github-actions-prod:
    issuer: https://token.actions.githubusercontent.com
    requiredAudience: mithril-ci-intent
    trustedRunnerGroup: prod-runners
    requireClaims:
      - repository_id
      - workflow_ref
      - workflow_sha
      - run_id
      - run_attempt
      - actor_id
      - runner_environment
    runnerStepChannel: required

ciRules:
  - id: untrusted-pr-build
    match:
      coordinator: github-actions-prod
      triggerTrustClass: untrusted_change
    role: ci-untrusted-build
    dispositionOnMissingIntent: reject
    authorityLeases: []
    effects:
      repositoryWrite: deny
      cloudIdentityEndpoints: deny
      kubernetesApi: deny
      runnerControlSocket: deny
      serviceContainers: declared-only
      publicDependencyFetch: alert

  - id: reviewed-main-publish
    match:
      coordinator: github-actions-prod
      workflowRef: org/repo/.github/workflows/release.yml@refs/heads/main
      workflowDigest: sha256:reviewed-workflow
      triggerTrustClass: trusted_ref
      stepId: publish-image
    role: ci-publish
    requireArtifacts:
      - digestFromStep: build
        producerRole: ci-trusted-build
        attestation: verified
    authorityLeases:
      - provider: registry
        audience: prod-registry
        operations: [push-image, write-attestation]
        ttl: 10m
    dispositions:
      undeclaredArtifact: reject
      credentialAudienceMismatch: reject
      unexpectedProviderOperation: alert

  - id: production-deploy
    match:
      environment: production
      stepId: deploy
    requireApproval:
      source: coordinator-environment-protection
      preventSelfApproval: true
    role: ci-deploy
    authorityLeases:
      - provider: kubernetes
        cluster: production
        operations: [get, patch-deployment]
        resourceSelectors: [namespace=serving, deployment=model-api]
        ttl: 5m
    dispositions:
      missingApproval: reject
      unknownArtifactDigest: reject
      providerDeviation: alert

  - id: cleanup
    match:
      lifecycle: [failed, cancelled, post, cleanup]
    role: ci-post-cleanup
    effects:
      artifactUpload: declared-only
      deleteOwnTemporaryResources: allow
      newCloudLease: deny
      repositoryWrite: deny
```

GitHub environment protection can provide a required-reviewer or custom
deployment-rule proof, but the effective cloud/Kubernetes operation still
uses the authority behavior rule. The coordinator approval proves “this
deployment job may start”; it does not prove every command the job executes is
safe.

### CI acceptance cases

| Test | Adversarial setup | Required result |
| --- | --- | --- |
| `CI-NATIVE-001` | Two steps execute identical `/usr/bin/curl`; only one has a signed publish intent | Each native exec retains its step role; the unapproved step cannot borrow publish authority |
| `CI-CONTAINER-001` | Job container, service container, and container action share network/workspace | Three independent entries and effect budgets; no fabricated parent or role inheritance |
| `CI-PR-001` | Trusted workflow downloads untrusted PR artifact and runs a build script | Resulting execution is `ci-untrusted-build`; credential/API effects deny even though workflow definition is trusted |
| `CI-CACHE-001` | Untrusted job poisons a cache key consumed by trusted job | Exact producer/digest/provenance edge is visible; privileged consumption rejects or remains untrusted according to policy |
| `CI-OIDC-001` | Unapproved step reuses the job-level OIDC request variables | Job OIDC claims alone do not grant step authority; missing step/lease intent denies identity endpoint or rejects exchange |
| `CI-DIND-001` | Build talks to Docker socket and creates nested containers | Every root is bound to the job/step; if subordinate runtime visibility is absent, strict build denies the daemon effect |
| `CI-POST-001` | Job is cancelled during containment and cleanup attempts new egress | Cleanup gets its narrow post role; containment and response-root restrictions still win |
| `CI-FANOUT-001` | Matrix jobs run on three nodes and one publishes an artifact | Typed coordinator/artifact edges connect node-local trees; no cross-node Linux parent edge is invented |
| `CI-RETRY-001` | Run attempt 2 reuses attempt 1 nonce, artifact, or credential lease | Replay is rejected; new attempt identity and explicitly reusable artifacts are required |
| `CI-DEBUG-001` | Administrator opens a web terminal using the same shell command as a build step | Separate administrative entry with actor/approval/TTL; never build-step authority |

## Hugging Face Incident: Configured Algorithm Walkthrough

The earlier per-incident section explains each control in depth. This section
adds the missing operator view: which configuration rule fires, which
algorithm evaluates it, whether the action is allowed, alerted, denied, or
rejected, and what Mithril can physically prove.

It is grounded in the
[detailed implementation analysis](../../research/hugging-face-agent-intrusion-analysis.md)
and the
[source-faithful live action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md).
The public live stream has 21 representative entries; it is not the complete
17,613-action record. The more granular lateral actions published in the
technical timeline are mapped separately below.

### Algorithm names used in the walkthrough

| Name | Owning mechanism | Decides or proves |
| --- | --- | --- |
| `ALG-INTENT` | General intent-proof verification and one-use claim | Whether a trusted coordinator authorized an entry, transition, authority lease, or artifact handoff |
| `ALG-ENTRY` | Runtime-entry classifier plus pending-intent claim | Whether a runtime-created root starts and which role it receives |
| `ALG-LINEAGE` | Native task inheritance and exec transition | Exact task/process/exec identity and role before a child effect |
| `ALG-FILE` | Generic pre-effect algorithm plus mount-aware file/object classifier | Open/read/write/map of dataset, proc, token, secret, host, code, and credential objects |
| `ALG-NET` | Socket creator/current-role state, destination classifier, connect/send/packet hooks | Local destination/channel effects without claiming encrypted API verbs |
| `ALG-DEVICE` | Device major/minor, ioctl, capability, namespace, mount, BPF, perf, and ptrace policies | Kernel/host escape and special-device effects |
| `ALG-AUTHORITY` | `AuthorityBehaviorRule` over Kubernetes/cloud/mesh/connector/source-control/database audit | Principal, operation, resource, result, and provider-side deviation |
| `ALG-ARTIFACT` | Immutable artifact identity and publication/consumption edges | Who produced, published, restored, loaded, or executed exact bytes/revisions |
| `ALG-XNODE` | Typed multi-node causal graph | API/controller/binding/runtime/provider paths between independent native trees |
| `ALG-RESPONSE` | Exact target re-resolution, authorized actuator, postcondition, and watch | Whether containment physically happened and remained effective |

The sample disposition below is a recommended strict profile, not a hidden
constant. An operator can configure a different valid disposition. The result
column states what that change would mean physically.

### Every representative live-stream action

| Event | Concrete action and observation point | Strict sample configuration | Algorithm and practical result |
| --- | --- | --- | --- |
| `HF-001` | Root shell in an external evaluation sandbox | Hugging Face estate: no local disposition is possible; record `outside_authority` and optionally `alert` when external evidence arrives. If that sandbox is separately protected: reject unapproved job/root or deny the shell exec. | `ALG-ENTRY`/`ALG-LINEAGE` can prevent only where Mithril is installed. The Hugging Face deployment records an external subject and never claims it blocked another operator's sandbox. |
| `HF-002` | `id`, environment, mount, cgroup, filesystem, and process reconnaissance | Protected sandbox role: `deny` unapproved diagnostic exec and protected proc/host file reads; otherwise `alert` the sequence. | `ALG-LINEAGE` denies helper exec; `ALG-FILE` denies `/proc/*`, mount, host, or credential objects. Reading an already inherited environment in-process has no new file effect, so later write/send is the enforceable point. |
| `HF-003` | Use bundled debug `curl`, `nc`, `ip`, or fallback tooling | `deny` executable objects absent from the role's transition graph; `alert` allowed diagnostic tooling with restricted effects. | `ALG-LINEAGE` uses immutable executable identity, not `$PATH`. Copying or renaming the binary does not grant its role; `ALG-NET` still constrains its sockets. |
| `HF-004` | Send environment/secrets to a public capture endpoint | `deny` connect/send to unapproved public destinations and page; if the channel must be allowed, `alert` sensitive-state egress. | `ALG-NET` returns an errno before connection/send when distinguishable. `ALG-FILE` can set sensitive-read state first. Allowed shared TLS yields `semantic_effect_completed`, not a false prevention claim. |
| `HF-005` | Execute staged Python disguised as a source file | `deny` unapproved code-object read/map and unexpected interpreter/code transition. | `ALG-FILE` classifies `/tmp/submitted_code.c` as an untrusted executable-code input even though Python is the executable; `ALG-LINEAGE` denies a new helper image. Filename extension is irrelevant. |
| `HF-006` | gzip/base64/chunk payloads in memory | Pure computation: `allow` because there is no distinguishable protected effect; `deny` the first prohibited code load, file write, exec, or send. | No algorithm invents a “packing” syscall. `ALG-FILE`, `ALG-LINEAGE`, `ALG-NET`, or `ALG-ARTIFACT` acts when packed bytes cross a real boundary. An alert-only heuristic may raise priority but cannot claim prevention. |
| `HF-007` | Search public code/platform APIs for infrastructure names | External estate: contextual `alert` from provider/API evidence; managed task with undeclared destination: `deny` connect. | `ALG-NET` can block the destination, while `ALG-AUTHORITY` can flag semantic searches when the service exposes authoritative audit. Similar query text alone does not establish causal identity. |
| `HF-008` | Malicious HDF5 external storage makes the worker open a local object | Baseline: `deny` worker reads outside `dataset-input`; optional upload scanner: `reject` the dataset before scheduling. | `ALG-FILE` resolves the actual mount/inode/proc target and returns `EACCES` before bytes enter HDF5. `reject` is valid only with the optional artifact admission boundary. |
| `HF-009` | Retrieve worker environment, secrets, source, and context through the dataset result/API | `deny` observable proc/secret/source reads; `deny` undeclared result publication or egress; `alert` an indistinguishable allowed publication. | `ALG-FILE` prevents `/proc/self/environ`, token, and non-dataset objects when opened. Already resident `os.environ` is not re-read from the kernel; `ALG-NET`/`ALG-ARTIFACT` governs the next publication. |
| `HF-010` | Jinja expression executes Python inside the existing conversion interpreter | Do not configure “deny Jinja execution” at the kernel. Configure `deny` for every unneeded exec/file/network/device/security effect of `conversion-worker-root`. | `ALG-LINEAGE` sees no new task for the initial Python execution. The existing task label reaches `ALG-FILE`, `ALG-NET`, and `ALG-DEVICE`; the first prohibited physical effect is denied. Pure arithmetic remains intentionally unclassified. |
| `HF-011` | Open projected ServiceAccount token and namespace files | Worker does not need token: `deny` and page. Legitimate controller role: `allow` or `alert` the read and set sensitive state. | `ALG-FILE` binds rotating projected-volume inodes to the semantic token object and exact task role. Token bytes never enter evidence. A credential already in memory shifts enforcement to network/provider behavior. |
| `HF-012` | Probe in-cluster/public Kubernetes API, DNS, EKS endpoints, and cloud IMDS, including hard-coded IPs | Worker role: `deny` connect/send to every API/IMDS destination class. Legitimate controller: `allow` channel and `alert`/respond on forbidden audit verb. | `ALG-NET` uses actual address/network namespace, so DNS monkey-patching does not bypass it. `ALG-AUTHORITY` evaluates Kubernetes/AWS operations over allowed TLS. |
| `HF-013` | Clone a dataset with a leaked write token and publish gzipped blobs as a dead-drop | Distinct write endpoint/lease: `deny` or semantic `reject`. Same endpoint, credential, and TLS channel as required reads: `alert` provider-confirmed write and quarantine exact revision. | `ALG-NET` cannot distinguish clone from push over identical TLS. `ALG-AUTHORITY` proves repository operation/result; `ALG-ARTIFACT` connects immutable revision/digest to consumers. |
| `HF-014` | Reach mesh control and establish mesh capability from a compromised node | `deny` unapproved mesh exec, control destination, TUN/device/ioctl, or required capability; alert provider operation if locally allowed. | `ALG-LINEAGE`, `ALG-NET`, and `ALG-DEVICE` are independent gates. Userspace-networking mesh mode may avoid TUN, but it still needs code execution and control/data sockets. |
| `HF-015` | Enroll external sandbox devices into the corporate mesh with a stolen key | With mesh pre-admission: `reject` unapproved enrollment. Audit-only: `alert`, revoke enrollment key, remove each existing device, and verify both. | `ALG-AUTHORITY` creates exact external device/key subjects. `ALG-RESPONSE` distinguishes preventing future joins from removing 181 already enrolled devices. Local BPF cannot stop an external host. |
| `HF-016` | Use mesh/cluster reachability to retrieve connector catalog and cluster connection context | Managed client with no need: `deny` destination. Typed connector gate: `reject` catalog request. Audit-only: `alert` exact request and restrict source session/device. | `ALG-NET` blocks the channel when possible. `ALG-AUTHORITY` requires connector source/destination request IDs; `ALG-XNODE` connects only proven forwarded requests. |
| `HF-017` | Replay harvested AWS credentials externally, enumerate cloud resources, validate identity, and exfiltrate result | Earlier local acquisition/exfil: `deny`. External use: `alert` exact AWS session/access key deviation and invoke approved session/key response. | `ALG-AUTHORITY` joins CloudTrail access-key/session/source-identity evidence; `ALG-RESPONSE` targets only a resolvable session/key. Same IAM role name is insufficient. |
| `HF-018` | Through connector/GitHub, mint write-capable App installation tokens, enumerate repos, and attempt a CI-triggering pull request | Typed connector/provider gate: `reject` token mint or disallowed PR/workflow operation. Audit-only: `alert`, revoke known token or suspend installation with approval, and verify repo/CI state. | `ALG-AUTHORITY` sees the semantic GitHub operation without TLS interception. `ALG-ARTIFACT` tracks commits/workflow/image digests. CI rules keep untrusted code in `ci-untrusted-build` even if a PR is accepted. |
| `HF-019` | Fresh external sandboxes re-fetch and execute a remote loader | Managed sandbox: `deny` loader destination, code-object load, exec, memfd/deleted image, or anonymous executable map. Outside estate: `alert` shared artifact/provider evidence only. | `ALG-NET`, `ALG-FILE`, and `ALG-LINEAGE` provide independent managed-node gates; `ALG-ARTIFACT` joins renamed copies by digest. |
| `HF-020` | Inspect staged binary, hostname, process, filesystem, and host state | `deny` undeclared proc/sys/debugfs/host reads, ptrace/perf/BPF/device/mount/namespace actions, and unapproved staged code; alert allowed diagnostic sequence. | `ALG-FILE` and `ALG-DEVICE` decide each effect on the exact lineage. Process names such as `readelf` are explanation, not authority. |
| `HF-021` | Access is cut and recovered activity stops | Apply configured `ALG-RESPONSE` actions; do not map silence to `allow` or “contained.” Alert unresolved branches and coverage gaps. | Exact local/provider actuators are re-resolved, replacement controllers are watched, and every postcondition must hold for the watch interval before result `verified`. |

The `HF-009` source-read example is role- and object-specific. A conversion
worker may legitimately need its own application source or package metadata;
that object must remain allowed and cannot be called malicious merely because
the compromised interpreter read it. The preventable distinctions are reads
of undeclared proc/credential/host/source objects, writes into the declared
dataset result that violate the result-object contract, and publication over
an undeclared channel. If the exact same allowed source bytes and result API
are necessary for normal conversion, Mithril alerts the behavioral sequence
and governs the later distinguishable effect rather than breaking the worker
or pretending it denied the in-process disclosure.

### Granular lateral actions published outside the 21-entry stream

The technical timeline describes important actions that the representative
stream groups into broader entries. An implementation and test suite must not
lose them.

| Published action | Practical configuration | Algorithm, proof, and outcome |
| --- | --- | --- |
| Read EC2 node-role credentials from IMDS | `conversion-worker-root -> cloud-imds connect: deny`; legitimate node agent uses a separate role and `allow` plus lease evidence | `ALG-NET` prevents the worker's metadata call. If credentials were already obtained, `ALG-AUTHORITY` identifies their later access-key/role session and cannot claim the earlier read was stopped. |
| Build a presigned STS caller-identity URL and use it as `k8s-aws-v1` node authentication | Worker STS/Kubernetes destinations: `deny`; node-principal Kubernetes behavior outside expected source/operation: `alert` | `ALG-NET` can stop local calls. Kubernetes audit plus AWS session/source evidence lets `ALG-AUTHORITY` join the forged node-auth request; token bytes are never required in evidence. |
| Call TokenRequest for CSI service accounts | If a synchronous Kubernetes authorization integration exists: `reject`; audit-only baseline: `alert` successful `create serviceaccounts/token`, restrict source, and enumerate minted leases | `ALG-AUTHORITY` matches exact caller, namespace, ServiceAccount UID, audience, expiry, request UID, and result. It cannot deny a completed TokenRequest from audit alone. |
| Run `SelfSubjectRulesReview` and enumerate RBAC | Unexpected authority operation: `alert`; optionally reject through a semantic API gate | `ALG-AUTHORITY` records principal and review scope. The result is reconnaissance evidence; it is not a native process transition and does not become permission by observation. |
| Create privileged hostPath Pod | Kubernetes admission integration: `reject` exact Pod request; audit-only: `alert`, add object UID/owner edge, restrict source, and delete/fence only under response approval | `ALG-AUTHORITY` proves request/result. `ALG-XNODE` follows Pod UID to scheduler/binding/node/runtime root. If creation succeeded, “deny” is no longer honest; response is a separate action. |
| Create self-respawning Pods across eleven nodes | `alert` controller/workload creation; `reject` replacements at admission when configured; contain current Pods and owning controller | `ALG-XNODE` represents every node-local tree plus owner/controller edges. `ALG-RESPONSE` watches reconciliation, so deleting current Pods cannot produce a false containment result. |
| Reach node root through a privileged Pod and host mount | Cluster hard-floor profile: deny mount/namespace/device/host-object effects where the protected node can mediate; alert any root with incomplete binding | `ALG-ENTRY` must bind the new Pod root rapidly or pre-exec. `ALG-DEVICE`/`ALG-FILE` deny host effects. A node whose kernel/runtime is already controlled is a lost enforcement trust boundary, not a normal denied effect. |
| Authenticate to internal MongoDB with static environment password | Deny initial environment/credential read and undeclared database destination; if DB access is legitimate, alert database-audit operation deviation | `ALG-FILE` and `ALG-NET` provide earlier gates. `ALG-AUTHORITY` uses database principal/session/query audit where available. Encrypted MongoDB operations are not inferred from packets. |
| Issue 84 credential-store/cluster-key operations that the store denied | `alert` high-rate forbidden operations even though provider result is denied | `ALG-AUTHORITY` records exact provider-side denial and raises sequence priority. It must not say Mithril's kernel denied operations the store itself rejected. |
| Read a Kubernetes Secret containing 136 keys | Semantic API gate: `reject get secret`; audit-only: `alert`, immediately restrict source and enumerate every exposed credential object | `ALG-AUTHORITY` matches principal, verb, Secret UID/resource version, response result, and request UID. One successful Secret read expands the graph to many candidate credential branches; each later use needs exact identity proof. |
| Use a mesh key tagged for CI automation and enroll 181 devices | Provider admission: reject wrong workload/device posture; otherwise alert exact key/tag/device use, revoke key, remove devices | `ALG-AUTHORITY` does not treat the tag name as proof of CI. Signed CI intent plus exact lease is required. `ALG-RESPONSE` separately verifies key revocation and device removal. |
| Run mesh in userspace networking with SOCKS5 and in-memory state | Deny unapproved mesh executable/code, control/data destinations, and local proxy listener even when no TUN device exists | `ALG-DEVICE` alone would miss this path. `ALG-LINEAGE` and `ALG-NET` keep the policy complete; `--state=mem:` only removes a disk artifact. |
| Retrieve a connector catalog through a shared multi-cluster credential | Reject through typed connector policy if available; otherwise alert, disable only proven session/grant where possible, and disclose shared blast radius | `ALG-AUTHORITY` needs source device/principal, connector ID, catalog resource, forwarded request IDs, and result. A shared credential can force broader response but never stronger attribution. |
| Use harvested AWS keys for MongoDB IAM auth and `GetCallerIdentity` | Deny local credential-object read or destination; external calls alert exact AWS session behavior; approved response revokes resolvable lease/session | `ALG-AUTHORITY` uses access-key/session/CloudTrail identity. Network timeout to MongoDB is recorded as failed service access, not prevention by Mithril. |
| Obtain registry token and enumerate VPC/EKS/transit/secrets with cloud role | Alert operations/resources outside authority rule; semantic cloud broker may reject; response scopes to session and changed resources | `ALG-AUTHORITY` distinguishes read, dry-run, denied, and successful calls from provider result. Enumeration is not mislabeled as mutation. |
| Read EdDSA signing key and forge valid identity tokens | Deny signing-key file/Secret object read. Token construction in memory has no kernel semantic hook; alert later token issuance/use deviation and rotate exact key under approval | `ALG-FILE` prevents observable acquisition. `ALG-AUTHORITY` detects a valid but behaviorally unexpected token principal/operation. Cryptographic validity does not equal authorized provenance. |
| Mint GitHub App tokens with write permissions | Typed connector request: reject; GitHub audit only: alert and revoke known token or suspend installation | `ALG-AUTHORITY` matches App, installation, repository set, permissions, actor/request, and result. Direct TLS network policy cannot tell mint from clone. |
| Open a pull request intended to compromise CI and read CI credentials | Source-control rule alerts/rejects unexpected PR/workflow write when semantic gate exists; CI coordinator marks artifact/ref `untrusted_change`; CI runtime denies credential/OIDC/deploy effects | `ALG-ARTIFACT` carries commit/ref provenance into `ci-untrusted-build`; `ALG-INTENT` denies a privileged lease to the unapproved step. Even if CI executes a malicious `build.rs`, its physical credential read/API effects remain denied. |
| Rewrite `/etc/resolv.conf`, append `/etc/hosts`, and pin CDN/API IPs | Deny worker writes to resolver/hosts objects; destination policy still classifies actual IP and service class | `ALG-FILE` stops configuration mutation. `ALG-NET` does not rely on DNS names, so hard-coded IP or monkey-patched resolution does not bypass destination policy. |
| Route a binary through a public CORS proxy or platform Space | Deny unapproved proxy/destination or untrusted code-object load; alert allowed relay use and track downloaded digest | `ALG-NET` sees relay channel; `ALG-ARTIFACT` identifies bytes independently of URL; `ALG-FILE`/`ALG-LINEAGE` prevents execution on managed nodes. |
| Stage an RSA private key and keep dumping process environments | Deny private-key writes outside approved key-management role and cross-process/proc environment reads; restrict lineage and preserve non-secret metadata | `ALG-FILE` records object class, inode/mount identity, and denial without key contents. Already resident environment values remain governed at publication/use. |

### End-to-end configured resolution of the production branch

The following walk-through shows how several valid configurations change the
same incident path without changing the underlying attribution facts.

1. The runtime admits the reviewed conversion image as
   `conversion-worker-root`. `ALG-ENTRY` and `ALG-LINEAGE` install exact task
   identity before the interpreter runs.
2. HDF5 resolves an external raw-data path to `/proc/self/environ`.
   - With `disposition: deny`, `ALG-FILE` returns `EACCES`; the incident branch
     stops before `HF-009` and the finding says `prevented`.
   - With `disposition: alert`, the read succeeds, a sensitive-state bit is
     set, and the finding says `semantic_effect_completed`; later publication
     still receives a separate decision.
3. Jinja executes inside Python. No new entry, fork, or exec is invented. When
   Python opens the projected token, `ALG-FILE` evaluates the same exact task.
   A strict token rule denies it. If a deployment has configured that worker
   to read the token, the read is allowed or alerted and creates a credential
   acquisition edge; this does not authorize arbitrary Kubernetes behavior.
4. Python connects to Kubernetes/IMDS.
   - A worker with no declared need is denied locally by `ALG-NET`.
   - A controller role with legitimate channel access proceeds; provider audit
     reaches `ALG-AUTHORITY`, which can alert an unexpected TokenRequest,
     Secret read, or privileged-Pod creation.
5. If a Kubernetes semantic admission integration is configured, the
   privileged-Pod request is `reject`ed before persistence. If only audit is
   configured and the API reports success, Mithril alerts, restricts the
   source, builds the object/controller/binding/runtime graph, and contains
   the created branch. It never rewrites that result as a deny.
6. Every new Pod root on another node is separately bound by `ALG-ENTRY`.
   `ALG-XNODE` connects it through request UID, Pod UID, owner, scheduling,
   binding, and runtime evidence, never through a cross-node parent PID.
7. Mesh, AWS, connector, and GitHub uses that occur externally are evaluated
   from exact provider identities by `ALG-AUTHORITY`. A configured provider
   pre-admission path can reject a future operation; audit-only paths alert and
   invoke authorized `ALG-RESPONSE` actions after completion.
8. A malicious source-control change entering CI retains its commit/artifact
   trust. The CI coordinator and node enforce `ci-untrusted-build`; the build
   may compile and test, while mounted credentials, OIDC audiences, runner
   control, deployment API, and repository write effects deny or reject as
   configured.
9. Containment remains `partial` until local lineages, controllers,
   credentials, mesh devices, connector sessions, repositories/artifacts, and
   provider watch coverage each satisfy their physical postcondition.

This is the central configuration rule: the operator may choose to observe,
alert, prevent, or reject where the mechanism supports it, but configuration
cannot change task identity, evidence quality, authority boundary, or whether
the effect had already happened.

## Kubernetes External-Entry Acceptance Matrix

The following tests are mandatory before a runtime/kernel combination can
claim full protected-entry support.

| Test | Setup and adversarial variation | Expected proof |
| --- | --- | --- |
| `ENTRY-START-001` | Hold a new container in runtime-created state; delay/wrong-profile/drop admission ack | Configured executable never begins without exact ack in strict mode; observe mode records the gap and continues |
| `ENTRY-POSTSTART-001` | PostStart races entrypoint in both observed orders | Two independent admitted roots, no fabricated parent, correct roles regardless of ordering |
| `ENTRY-POSTSTART-002` | Kubelet restart causes duplicate PostStart delivery | Separate idempotent/repeated entry instances within policy budget; no stale nonce reuse |
| `ENTRY-PRESTOP-001` | Trigger deletion while policy and an active response root exist | Enforcement remains installed; configured containment-vs-cleanup rule wins; termination alone grants nothing |
| `ENTRY-PROBE-001` | Run startup, readiness, and liveness exec probes concurrently with identical and different commands | Exact reason when extension exists; otherwise only same-budget conservative classification; unequal ambiguity denies |
| `ENTRY-PROBE-002` | Application child executes the exact probe binary/argv at the expected cadence | It retains native child lineage/role and cannot claim external probe intent |
| `ENTRY-NETPROBE-001` | HTTP, TCP, and gRPC probes hit the Pod | No synthetic in-container probe task; host flow and application receive remain correctly scoped |
| `ENTRY-SLEEP-001` | PostStart/PreStop sleep action | No in-container task appears; kubelet lifecycle evidence only |
| `ENTRY-EXEC-001` | `kubectl exec`, TTY/non-TTY, and `kubectl cp` | Administrative entry role and `pods/exec` audit correlation; default deny/approval honored |
| `ENTRY-EXEC-002` | Direct `crictl exec` with the same command as a probe | Host-admin/unknown runtime entry, never exact kubelet-probe role |
| `ENTRY-EPHEMERAL-001` | Add ephemeral container targeting app PID namespace | New container execution set, API actor evidence, separate profile; shared PID namespace does not merge native trees |
| `ENTRY-CONTAINERS-001` | Init, native sidecar, and app containers share Pod network and volume | Independent roots/profiles and correct shared-resource evidence |
| `ENTRY-MIGRATE-001` | Move an unlabeled task into protected cgroup or use `nsenter` | First protected effect denied without valid pending intent |
| `ENTRY-REUSE-001` | Reuse PID, namespace number, cgroup ID/path, container name, and Pod name over time | Live interval/full IDs prevent the old profile/response from attaching to the new subject |
| `ENTRY-RESTART-001` | Restart kubelet, runtime, and `mithril-node` at every admission state | Pending intents reconcile or expire; no task executes with a stale/duplicate role; exact coverage transition recorded |
| `ENTRY-LOSS-001` | Drop runtime-intent message or BPF entry event independently | Strict task denied or container held; event loss cannot relax enforcement; loss counter closes coverage |

For every case the test captures:

- runtime/containerd or CRI-O version;
- kernel, BTF, LSM ordering, helper, and hook capability record;
- Pod UID/resourceVersion, full container ID, cgroup live interval, image digest;
- entry nonce/classification/role/claim result;
- task/process/exec cookies and native coordinate history;
- physical syscall/runtime result; and
- coverage and loss state.

## Effect And Bypass Acceptance Matrix

| Family | Required bypass cases | Required physical assertion |
| --- | --- | --- |
| Exec | execveat, fexecve, memfd, deleted file, scripts, dynamic linker, renamed/bind-mounted binary, overlay copy-up, non-leader exec | prohibited image never begins; allowed immutable image receives exact result role |
| File | symlink, hardlink, rename, bind mount, proc-fd alias, projected token rotation, inherited/passed fd, mmap, `io_uring` | claimed operation returns denial before data/effect; uncovered pre-opened-memory cases named |
| Network | DNS/hard-coded IP, IPv4/IPv6, UDP, raw/packet, inherited/passed socket, established TLS, sendfile/splice, TUN/AF_XDP/BPF redirect | prohibited connect/send/packet is physically absent; established-flow fence separately proven |
| Device | mknod, open, major/minor aliases, TUN, GPU/FUSE/KVM, approved vs unapproved ioctl | cgroup device/file/ioctl result matches exact role rule |
| Security | setuid/file caps, credential change, ptrace, setns/unshare, mount, BPF, perf, module, keyring, seccomp weakening | selected pre-effect hook returns deny; unsupported operation downgrades tier |
| Identity | fork without exec, clone thread, vfork, non-leader exec, reparent, parent exit, PID/cgroup reuse, bootstrap | exact stable cookie/role or explicit gap; no userspace labeling window |
| Evidence | ring full, CPU sequence gap, WAL full, node/control outage, generation switch, BPF-link loss | enforcement result unchanged; negative conclusions prohibited across gap |

These are code-backed fixtures. A shell transcript or alert text is supporting
evidence, not the pass condition.

## Failure-State Architecture

| Failure | Observe mode | Protect mode | Claim effect |
| --- | --- | --- | --- |
| No BPF LSM or required helper/hook | Record unsupported capability and continue observation available from weaker hooks | Do not bind profile requiring the missing prevention; optionally deny workload start if operator selected strict tier | Cannot advertise equivalent prevention |
| Runtime start gate unavailable | Bind after start as `bootstrapped` with gap | Reject strict admission or use a separately proved fallback | No enforce-from-first-exec claim |
| Unlabeled task in protected cgroup | Record orphan/identity defect | Deny first protected effect | No exact lineage conclusion until recovered |
| Missing parent label at fork | Mark child lineage incomplete | Install restrictive unknown label or deny creation/effect | Never skip silently as benign |
| Pending entry ambiguous | Record all candidates and classification gap | Deny unless all candidates have explicitly identical approved budget | No exact lifecycle/probe claim |
| Ring-buffer reservation fails | Increment loss counter and close evidence interval | Same, while returning already computed deny/allow | Enforcement may remain healthy; evidence is incomplete |
| Rust process/control connection lost | Continue from pinned policy, spool health/evidence if possible | Continue in-kernel policy; reject new admissions that require userspace | Central response/new policy unavailable; existing deny not relaxed |
| BPF link/map lost or verifier probe fails | Mark affected hook unavailable | Deny new strict admissions and apply approved safe state to existing bindings | Required prevention coverage unhealthy |
| Policy generation compile/probe fails | Keep prior generation | Keep prior generation; reject update | No partial generation activation |
| Local WAL full | Apply retention/backpressure policy and expose gap before destructive overwrite | Local enforcement continues; strict evidence-dependent claims stop | No “safe”/“contained” conclusion across lost interval |
| Kubernetes/provider audit unavailable | Local effects continue | Same | Same-channel semantic deviations and distributed edges become unknown/contextual |
| Runtime/kubelet restart | Reconcile live containers/tasks and pending entries with explicit gaps | Preserve pinned bindings; expire/revalidate intents before new exec | No stale entry nonce or lifecycle classification |
| Node reboot | New node boot and label epoch; prior subjects close | New admission required | Old response keys cannot target new tasks |

## Performance And Boundedness

The architecture is intended to replace ptrace-heavy steady-state mediation.
That does not make every BPF design cheap. Each hot hook must have bounded map
lookups and no central round trip.

The expected fast path is:

```text
current cgroup binding lookup
  + task-storage lookup
  + response-root lookup
  + one compact role/effect decision lookup
  + optional socket/object lookup
  + best-effort fixed-size ring record only when policy requests evidence
```

The compiler resolves path trees, selectors, PodSpec interpretation, image
metadata, DNS/service inventory, provider rules, and conflicts outside the hot
path. BPF path/object extraction is performed only for hooks whose rule table
requires it. In-kernel filtering suppresses unneeded allowed events while
coverage counters remain observable.

Phase 0 sets numerical budgets for:

- median and tail overhead on exec, open, connect/send, and fork;
- maximum policy map memory per node/container/profile generation;
- task/socket storage capacity and exhaustion behavior;
- maximum role depth, ancestor vector, argv/path extraction, and tail calls;
- ring/WAL throughput and intentional stress loss;
- runtime admission latency for container start and repeated exec probes; and
- baseline application success, probe timing, Pod startup, and shutdown.

The intent and CI extensions add budgets for:

- signature verification, replay lookup, and staging latency for runtime,
  lifecycle, CI-step, approval, and authority-lease proofs;
- maximum pending-proof count per node, issuer, workload, CI run, and policy
  generation, including deterministic expiry and overload behavior;
- maximum concurrently claimable identical operations without ambiguous
  cross-claiming;
- CI matrix/fan-out graph, artifact/cache handoff, and provider-audit event
  throughput; and
- coordinator or identity-provider outage behavior without silently converting
  a missing proof into an allow.

No phase can solve a performance failure by removing a required identity,
effect, evidence, or postcondition guarantee. It must optimize the mechanism,
reduce advertised scope, or propose a reviewed design change.

## Implementation Ownership

The final module names are Phase 0 decisions, but responsibilities must remain
cohesive:

| Owner | Responsibility | Must not own |
| --- | --- | --- |
| Rust runtime-entry owner in `mithril-node` | authenticate intents, resolve Pod/runtime identity, classify entry, issue one-use admission | BPF raw event parsing or central graph conclusions |
| Native identity owner | task/process/exec cookies, inheritance, bootstrap, coordinate history | Kubernetes/provider causal edges |
| Object classifier owner | executable/file/socket/device/security object resolution and quality | policy approval or response authorization |
| Policy compiler/activation owner | validate, simulate, compile, probe, atomically activate generations | model-generated direct allows |
| Kernel host owner | one loader, link/map lifecycle, ABI, capability probes, raw sequence | business detection packages |
| Local evidence owner | normalize raw events, coverage intervals, WAL, authenticated upload | mutation of kernel decisions after the fact |
| Control graph owner | immutable observations, typed causal edges, versioned lineage | native parent fabrication or live PID actuation |
| Detection-package owner | deterministic package state, lateness, findings | arbitrary response commands |
| Response coordinator | authorization, target re-resolution, typed execution, postconditions | raw shell or stale graph target |
| Intent-proof/coordinator adapter owner | authenticate issuer assertions, normalize kubelet/CI/deployment intent, stage bounded one-use proofs | load BPF, infer a task from argv/timing, label tasks directly, or maintain another process graph |
| Authority-lease owner | bind an approved credential request and provider-issued lease to the exact task/job proof and later audit identity | store secret material, treat an `aws`/`gcloud`/`gsutil` executable as intent, or invent provider success |
| Disposition compiler owner | validate `allow`/`alert`/`deny`/`reject` against the available decision point and compile notification/response bindings | promise synchronous prevention from audit-only evidence or bypass hard enforcement invariants |

The same node gatherer can expose a cgroup-scoped read-only observation stream
to Erebor Runtime. Runtime cannot install overlapping BPF links/maps, assign
Mithril roles, or invoke Mithril response through that subscription.

## Phase Allocation

| Architecture slice | Owning master-plan phases |
| --- | --- |
| ABI, license/provenance, capability/performance contracts, fixture vocabulary | Phase 0 |
| One Rust node process, one loader, base cgroup/runtime inventory | Phase 1 |
| task/process/exec identity, native inheritance, bootstrap, entry-independent tree | Phase 2 |
| effect observation, object classifiers, candidate profile simulation | Phase 3 |
| signed exec/file/device/security policy and generic decision precedence | Phase 4 |
| role-aware socket storage, destination policy, packet/established-flow fence | Phase 5 |
| sequence/WAL/coverage/generation restart and recovery truth | Phase 6 |
| `HF-PROC-001`, `HF-DW-001`, authority behavior and deterministic replay | Phase 7 |
| Kubernetes audit/object/runtime joins and multi-node causal graph | Phase 8 |
| response roots, cgroup/socket actions, controller replacement watch | Phase 9 |
| mesh/AWS/connector/artifact/GitHub packages and typed recovery | Phase 10 |
| runtime-specific full entry admission, packaging, scale, upgrades, complete conformance | Phase 11, with earlier prototypes in Phases 0-4 |
| optional upstream/EDR evidence adapters | Phase 12 |

The new configuration and intent objects are allocated across those phases,
not assigned to a parallel product track:

| Added architecture object | Phase allocation and exit condition |
| --- | --- |
| `IntentProofEnvelope`, issuer trust, nonce/replay ABI, and physical-disposition vocabulary | Phase 0 specifies and adversarially tests the contract; no provider-specific CLI or entry kind is introduced |
| Runtime-entry and native-transition proof claim | Phases 1-2 establish authenticated transport and exact kernel task binding; Phase 4 makes missing or mismatched proof enforceable |
| `DetectionDispositionRule` and `CompiledActionPlan` | Phase 0 fixes semantics; Phase 4 proves local `deny`/entry `reject`; Phase 7 proves alert routing and deterministic finding behavior; Phase 9 proves response bindings and postconditions |
| `AuthorityLeaseIntent` and `CredentialLease` | Phase 7 establishes authority behavior and exact/local evidence quality; Phase 10 qualifies each provider issuance/audit join |
| Authenticated kubelet reason proof | Prototyped in Phases 0-4, completed and runtime-version-qualified in Phase 11; without a carried nonce or held task, unequal-budget exact probe classification remains unsupported |
| CI run/job/step intent and artifact handoff | Reuses Phases 2-6 for node enforcement and coverage; the generic model is fixed here, while named coordinator adapters and their conformance suites are Phase 12 unless a separate approved master-plan change promotes them |

An adapter's milestone is not complete when it merely receives an event. It
must prove issuer authentication, replay resistance, exact target binding,
failure behavior, and the physical effect of every advertised disposition.

Runtime-created entry handling crosses phases and cannot be postponed as a
late integration detail:

- Phase 0 must select the target runtime gate and prove its ordering;
- Phase 1 must carry authenticated runtime metadata;
- Phase 2 must model multiple roots and pending/claimed entries;
- Phase 4 must fail closed for missing protected labels; and
- Phase 11 must qualify each advertised containerd/CRI-O/Kubernetes version.

## Approval Decisions And Honest Alternatives

| Decision | Proposed default | Honest alternative and required proof |
| --- | --- | --- |
| Container model | Multiple admitted entry roots per container | A single-root model must prove kubelet/runtime exec tasks are always native descendants on every supported runtime; current Kubernetes behavior makes that unlikely |
| Strict initial start | Runtime-held pre-exec admission | Post-start observation is allowed only as a reduced tier with an explicit start gap |
| Strict runtime exec | pidfd/runtime-shim gate; pending-intent BPF claim only after target-kernel proof | Without either, unknown external roots must be denied or the tier is observe-only |
| ExecSync reason | authenticated reason extension when budgets differ; otherwise same-budget conservative class or deny | Timing/command-only exact classification is rejected |
| Administrative exec | default deny/approval on protected workloads | Always allow requires a separately bounded administrative role and accepts that compromised admin authority can introduce a root |
| PreStop under containment | containment wins unless an exact safe cleanup role is approved | Universal preStop bypass is rejected; disabling all preStop is possible with availability cost |
| Missing protected identity | fail closed at first protected effect | Fail open is an observation tier and cannot carry prevention claims |
| Executable identity | immutable object/image identity | Path-only policy is a reduced integrity tier |
| Same TLS destination | provider audit or semantic connector integration; no MITM | Whole-channel deny can prevent both allowed and forbidden operations with explicit blast radius |
| Multi-job process | exact native process scope; logical job remains unknown absent platform proof | Application instrumentation may add optional job identity but cannot become baseline |
| Policy learning | observation creates review-only candidates | Auto-authorizing observed behavior is rejected because compromise can train the allowlist |
| Upstream code | study/adapt mechanisms after Phase 0 license gate; own architecture and Rust userspace | Forking a daemon would add another chassis/owner and must replace, not duplicate, the single-gatherer design |
| Intent transport | one authenticated envelope format consumed by the existing gatherer, with issuer-specific adapters | A coordinator callback may remain audit context, but it cannot authorize an entry or transition unless it is authenticated, replay-resistant, target-bound, and claimed by the live task |
| Cloud CLI interpretation | `aws`, `gcloud`, and `gsutil` retain native process lineage; provider login is a separate authority-lease proof | Creating CLI-specific entry kinds would confuse an executable name with intent and is rejected |
| Disposition vocabulary | separate physical `allow`/`deny`/`reject` from `alert`, notification, and response | A single generic action enum is acceptable only if compilation still rejects impossible boundaries and preserves these exact semantics |
| CI identity | model multiple physical roots, native children, job/step transitions, and artifact/cache/deployment edges | Treating a workflow or Pod as one process tree loses container actions, service containers, remote jobs, and cross-node artifact causality |

## Completion Standard For This Architecture

This document is implemented only when all of the following are true on every
advertised full-support kernel/runtime combination:

1. The unchanged concurrent worker, declared lifecycle handlers, exec probes,
   init/sidecars, and legitimate controller behavior pass.
2. Every container/runtime-created root has exact or explicitly conservative
   entry evidence before its first protected effect.
3. A native child cannot impersonate a kubelet/runtime entry by matching its
   command, binary, timing, cgroup, or namespace.
4. The first distinguishable prohibited `HF-008`-through-`HF-020` effect is
   physically denied where the matrix claims prevention.
5. Same-process and same-TLS cases produce the documented semantic detection
   result, never a fabricated kernel claim.
6. Native and distributed lineage survive concurrency, restart, reuse, fan-out,
   loss, late evidence, and contradictory evidence.
7. Local and provider responses re-resolve their target and verify physical
   postconditions through a healthy watch interval.
8. A missing hook, admission, map, event, WAL interval, audit source, or
   provider proof narrows the result mechanically.
9. Every source disposition compiles only to a boundary capable of producing
   that physical result, and observe-mode evidence says `would_deny` or
   `would_reject` without claiming the effect occurred.
10. Every supported intent issuer proves authentication, nonce/sequence replay
    resistance, immutable target binding, expiry, mismatch behavior, and exact
    live-task claim; cloud CLI names never substitute for that proof.
11. Every advertised CI integration passes native-step, container-action,
    service/helper, matrix/fan-out, artifact/cache handoff, OIDC/authority,
    deployment approval, cleanup, cancellation, retry, and runner-reuse cases.

Until then, the phase result must state which invariant, event stage, runtime
entry class, effect family, or response postcondition remains unproved.

## Primary Technical References

Local studies:

- [KubeArmor BPF LSM enforcer](../../../KubeArmor/KubeArmor/BPF/enforcer.bpf.c)
- [KubeArmor policy lowering](../../../KubeArmor/KubeArmor/enforcer/bpflsm/rulesHandling.go)
- [KubeArmor container-map identity](../../../KubeArmor/KubeArmor/enforcer/bpflsm/mapHelpers.go)
- [KubeArmor NRI timing and teardown](../../../KubeArmor/KubeArmor/core/nriHandler.go)
- [Tetragon fork tracking](../../../tetragon/bpf/process/bpf_fork.c)
- [Tetragon process state](../../../tetragon/bpf/lib/process.h)
- [Tetragon cgroup policy filter](../../../tetragon/bpf/process/policy_filter.h)
- [Tetragon runtime-hook policy binding](../../../tetragon/pkg/policyfilter/rthooks/rthooks.go)
- [Tetragon OCI hook](../../../tetragon/contrib/tetragon-rthooks/cmd/oci-hook/main.go)

Kernel and platform contracts:

- [Linux BPF LSM programs](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux LSM hook reference](https://docs.kernel.org/security/lsm-development.html)
- [Linux cgroup v2](https://docs.kernel.org/admin-guide/cgroup-v2.html)
- [Linux task-local BPF storage implementation](https://github.com/torvalds/linux/blob/master/kernel/bpf/bpf_task_storage.c)
- [OCI runtime lifecycle](https://specs.opencontainers.org/runtime-spec/runtime/)
- [OCI hook ordering](https://specs.opencontainers.org/runtime-spec/config/)
- [Kubernetes lifecycle hooks](https://kubernetes.io/docs/concepts/containers/container-lifecycle-hooks/)
- [Kubernetes probes](https://kubernetes.io/docs/concepts/workloads/pods/probes/)
- [Kubernetes init containers](https://kubernetes.io/docs/concepts/workloads/pods/init-containers/)
- [Kubernetes sidecar containers](https://kubernetes.io/docs/concepts/workloads/pods/sidecar-containers/)
- [Kubernetes ephemeral containers](https://kubernetes.io/docs/concepts/workloads/pods/ephemeral-containers/)
- [Kubernetes auditing](https://kubernetes.io/docs/tasks/debug/debug-cluster/audit/)
- [CRI runtime API](https://github.com/kubernetes/cri-api/blob/master/pkg/apis/runtime/v1/api.proto)

CI/CD coordinator and workload-identity contracts:

- [GitHub Actions workflow, job, and step model](https://docs.github.com/en/actions/get-started/understand-github-actions)
- [GitHub Actions job and sibling-container behavior](https://docs.github.com/en/actions/how-tos/write-workflows/choose-where-workflows-run/run-jobs-in-a-container)
- [GitHub Actions OpenID Connect claims](https://docs.github.com/en/actions/reference/security/oidc)
- [GitHub Actions job-scoped `GITHUB_TOKEN`](https://docs.github.com/en/actions/concepts/security/github_token)
- [GitHub Actions secure use of `pull_request_target`](https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target)
- [GitHub Actions deployment environments and protection rules](https://docs.github.com/en/actions/reference/workflows-and-actions/deployments-and-environments)
- [GitHub Actions artifact attestations](https://docs.github.com/en/actions/how-tos/secure-your-work/use-artifact-attestations)
- [GitLab Docker executor workflow](https://docs.gitlab.com/runner/executors/docker/)
- [GitLab Kubernetes executor Pod layout](https://docs.gitlab.com/runner/executors/kubernetes/)
- [GitLab CI/CD OIDC ID-token claims](https://docs.gitlab.com/ci/secrets/id_token_authentication/)
- [Tekton Task, step-container, sidecar, workspace, and result model](https://tekton.dev/docs/pipelines/tasks/)
- [Jenkins Pipeline agent, stage, matrix, parallel, and post semantics](https://www.jenkins.io/doc/book/pipeline/syntax/)
- [Google Workload Identity Federation for deployment pipelines](https://cloud.google.com/iam/docs/workload-identity-federation-with-deployment-pipelines)
- [AWS IAM source identity and session tags](https://docs.aws.amazon.com/IAM/latest/UserGuide/id_session-tags.html)

Incident sources used by the executable control map:

- [Hugging Face technical timeline](https://huggingface.co/blog/agent-intrusion-technical-timeline)
- [Local detailed incident analysis](../../research/hugging-face-agent-intrusion-analysis.md)
- [Local normalized live-action stream](../../research/hugging-face-agent-intrusion-live-action-stream.md)

<!-- Extend this architecture additively; preserve the decisions and examples above. -->
