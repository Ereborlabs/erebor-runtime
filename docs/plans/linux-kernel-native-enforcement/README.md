# Linux Kernel-Native Effect Enforcement Master Plan

Status: Proposed. This master plan authorizes no implementation until the user
approves a named phase.

## Goal

Define and prove the production Linux enforcement foundation for
Erebor-governed effects. Filesystem is the first Surface; future network,
process, device, and mediated external-system Surfaces must extend the same
admission, attribution, evidence, and recovery contract without inheriting a
filesystem-specific implementation. The production path must make ordinary
allow/deny decisions at the appropriate effect boundary, not by stopping every
workload syscall in a userspace tracer. It must preserve Session attribution,
immutable PolicySet selection, before-effect denial, lifecycle recovery, and
evidence integrity.

The proposed filesystem target is a daemon-owned BPF LSM runtime with
per-Session cgroup binding:

```text
immutable PolicySet + declared filesystem view
                 │ Session admission compiles a typed kernel policy image
                 ▼
BPF LSM hooks + Session-cgroup binding/maps + policy-image digest
                 │
                 ▼
VFS/LSM effect hooks ── allow or deny before the kernel applies the effect
                 │
                 ├── bounded ordered evidence channel -> durable Erebor ledger
                 └── channel or collector unhealthy -> fail closed / fence
```

This is a cross-cutting production master. It is not a Phase 5.5 subphase, a
Codex optimization, or an authorization to change the current Linux ptrace
pilot. The current pilot remains honestly described as `linux_ptrace` until an
approved phase proves the stronger backend.

## Scope And Boundary

The first implementation scope is the intrinsic `filesystem` Surface on Linux.
It covers an admitted Session's workload process tree and all filesystem effect
families that the approved policy contract claims to govern. The exact hook and
operation matrix is a Phase 0 deliverable; it must include more than the
current `open`, `openat`, and `openat2` syscall approximation.

The master establishes the reusable effect-enforcement contract that future
process, network, device, and other Linux Surface runtimes may consume. It does
not authorize those future Surface implementations. Their expansion gate is
[Future Surface Expansion](./future-surface-expansion.md). In particular:

- Browser CDP endpoint ownership remains owned by `erebor-runtime-cdp`.
- The controller PTY remains terminal presentation/control, not filesystem
  enforcement.
- Raw terminal policies requiring interactive approval or semantic command
  argument review are not silently moved into BPF. They require a separately
  approved mediated capability design.
- This plan does not add a public resource type, plugin interface, `apply`
  command, or a second daemon.
- This plan does not use AgentSight or Codex source, binaries, probes, SDKs,
  libraries, or runtime components. Erebor owns its implementation. Upstream
  kernel facilities and mature BPF build/loading dependencies may be evaluated
  in Phase 0 under Erebor's normal dependency rules.

## Expansion Model

`filesystem` is the first independent Surface adapter, not the model that every
future effect must force through. Session admission owns one immutable PolicySet
selection and asks every requested Surface to lower only its own
kernel-checkable or mediated facts:

```text
immutable PolicySet + declared Session capabilities
                    │
                    ▼
       per-Surface representability and host preflight
                    │
       ┌────────────┼──────────────┐
       ▼            ▼              ▼
filesystem     network         future Surface
BPF LSM        cgroup BPF      appropriate owned
VFS hooks      socket hooks    enforcement path
       └────────────┴──────────────┘
                    │
                    ▼
      one Session identity, evidence contract, and recovery result
```

Every Surface must declare: its effect taxonomy; subject binding; stable object
identity; exact pre-effect hook or owned mediation boundary; policy-image
lowering; evidence ordering and fence behavior; recovery; host capabilities;
and bypass tests. If one of those cannot be proved, admission rejects that
Surface. A Surface may use a kernel mechanism, an Erebor-owned mediation path,
or both; the reusable contract does not require BPF where BPF is the wrong
boundary.

No future work may turn this into one universal BPF program or a second generic
policy engine. The existing policy owner remains authoritative. Each Surface
gets a narrow lowerer and enforcement owner only after its own approved
capability phase.

### Network Is A Planned Independent Surface

A future network Surface should bind to the Session cgroup and evaluate
transport-level facts at cgroup BPF socket hooks: for example IPv4/IPv6
`connect`, `bind`, UDP `sendmsg`, and, where the approved policy requires it,
egress packet hooks. It must prove the exact IPv4, IPv6, TCP, UDP, Unix-socket,
proxy, and descendant-process matrix it claims.

That is not equivalent to governing hostnames, HTTP methods, SaaS resources, or
arbitrary encrypted application payloads. At socket hooks the kernel normally
sees addresses, ports, protocol, and socket state, not a trustworthy DNS name
or HTTP/API intent. Domain- or API-semantic policy therefore requires an
Erebor-owned DNS/proxy/gateway or another approved mediated capability; it must
not be falsely represented as a BPF-only network allow-list. Network namespace
and routing isolation may provide containment, but do not replace the
per-effect policy and evidence contract.

## BPF LSM: Strengths And Boundaries

BPF LSM is the preferred *filesystem* candidate because it runs at Linux
security-object hooks and can deny the physical effect before VFS completes it.
That is a better fit than a syscall tracer for a policy about filesystem
objects: it avoids entry-and-exit ptrace stops, removes the tracee-memory path
inspection and userspace decision round trip from ordinary allows, and does not
make a syscall spelling the enforcement boundary. The kernel verifier validates
program memory/control-flow access before load, while the policy maps remain
daemon-owned.

It is not universally better:

- **Attachment scope is a capability decision:** Linux exposes both regular LSM
  attachment and a cgroup-LSM attachment type. The actual hook coverage,
  hierarchy semantics, and per-cgroup program limits must be proven on the
  supported kernel profile. The preferred filesystem profile attaches to the
  Session cgroup. If a required hook can only use a regular global LSM
  attachment, the program must cheaply identify an Erebor Session cgroup and
  return without affecting other processes; the resulting host-wide hook cost
  and hostile-neighbor behavior become explicit acceptance tests, not hidden
  assumptions.
- **Static, bounded decision logic:** BPF programs have verifier, helper,
  stack, map, and execution-context constraints. They are suitable for a
  compiled allow/deny image, not arbitrary policy evaluation, unbounded path
  traversal, large mutable state, or runtime dependency resolution. Unsupported
  policy semantics fail Session admission rather than falling back to a daemon
  decision for an allowed effect.
- **No synchronous human or daemon consultation:** a BPF LSM hook cannot safely
  pause a filesystem effect while Erebor asks for approval. Ring-buffer output
  is asynchronous transport, not a decision RPC and not durable storage.
- **Hook and object limits vary by kernel:** an LSM hook must expose the object
  facts and helpers needed for the claimed operation. Kernel configuration,
  active LSM order, BTF, verifier behavior, and supported helpers/kfuncs are
  production-host capabilities, not merely build details.
- **Host trust boundary:** a process with host-level BPF/LSM, cgroup, mount, or
  equivalent administrative authority is outside this Session boundary. The
  daemon and its pinned objects need host protection; a hostile root-equivalent
  cannot be contained by a workload-level BPF program.
- **Evidence is not persistence:** BPF maps/ring buffers are bounded kernel
  state. The collector/fence/recovery design remains required even though the
  allow/deny result is in kernel.

Accordingly, BPF LSM is a first-class filesystem enforcement mechanism, not a
replacement for seccomp, namespaces, mount isolation, cgroup network hooks, or
Erebor-mediated connectors. Those mechanisms may be layered where their own
boundaries are stronger.

## Why The Existing Pilot Is Not The Production Shape

The current backend enum has only `LinuxPtrace` in
`crates/erebor-runtime-core/src/config/session/interception.rs`. Its guard
continues every traced process with `PTRACE_SYSCALL` in
`crates/erebor-runtime-session/src/os/linux/process_guard/sys.rs`, producing
entry and exit stops for every syscall in the workload tree. A relevant
filesystem operation also performs userspace path inspection and synchronous
broker routing before the tracee continues.

The current filesystem policy handler additionally writes one durable JSONL
record for every routed decision. `StoredPolicyFileOperationHandler` calls
`append_durable_audit_record`, whose JSONL sink opens, writes, flushes, and
calls `sync_data()` before returning. That preserves the present pilot's
evidence behavior, but it makes a high-rate workload depend on one userspace
round trip and one local durability barrier per observed operation.

Changing that path only to reduce ptrace stops would preserve the wrong
production ownership model. A production backend must make the normal kernel
allow/deny decision without a daemon RPC and make evidence loss an explicit
fail-closed condition rather than a silent gap.

## Production Invariants

- **One policy authority:** immutable packages and ordered PolicySet evaluation
  remain owned by the existing policy owner. A kernel policy image is an
  admission-time compiled artifact, not a second rules engine and not an
  untrusted workload input.
- **Admission, then enforcement:** a Session starts only after the daemon has
  resolved its filesystem view, compiled the selected policy into a typed
  kernel image, installed that image, and bound it to the Session cgroup.
- **Kernel before effect:** the relevant LSM hook returns allow or an error
  before the physical VFS effect. Syscall spelling must not create a bypass.
- **No capability escape:** workload processes receive no BPF-loading,
  cgroup-management, mount-management, or daemon-control authority. Inherited
  and received file descriptors are part of the effect model, not an exception.
- **No silent evidence loss:** an allowed effect may proceed only while its
  evidence event is accepted into the bounded kernel-to-daemon channel. Channel
  exhaustion, a failed collector, policy-image mismatch, or an unknown Session
  cgroup fences the effect and makes the Session unhealthy.
- **Recovery is explicit:** pinned program/map lifecycle, cgroup emptiness,
  collector restart, daemon restart, and abnormal workload death have one
  owner and a sealed or recoverable Session result. Filesystem COW/OSTree state
  remains the existing storage/recovery owner.
- **No automatic downgrade:** a Session that requires the kernel-enforced
  capability fails admission on an unsupported host. `linux_ptrace` may remain
  a separately declared development/compatibility capability, but never
  satisfies a kernel-enforced production request by fallback.
- **Evidence does not redefine effect semantics:** the audit collector may
  batch durable writes only under a documented bounded-channel, fencing, and
  recovery contract. It must not replace a failed write with an unrecorded
  allow, nor claim that a ring-buffer observation alone is durable evidence.

## Target Ownership

The exact crate split is an explicit Phase 0 decision. The target responsibility
boundaries are fixed now so a later implementation cannot reproduce the
ptrace-era duplicate ownership:

| Responsibility | Proposed owner | Must not own |
| --- | --- | --- |
| Portable Session capability requirement, Surface identity, and admitted enforcement tier | `erebor-runtime-core` | Linux BPF loading or policy evaluation |
| Immutable package ordering plus typed per-Surface policy-image lowering | existing daemon policy owner, extracted only as needed | BPF program lifecycle or workload-side decisions |
| Linux feature/privilege preflight, pinned maps/programs, cgroup attachment, and kernel error mapping | new Linux-only enforcement crate, subject to Phase 0 approval | CLI rendering, resource storage, or a second policy engine |
| Session admission/teardown orchestration | `erebor-runtime-daemon` and existing session manager | raw BPF instructions or filesystem repository replacement |
| Filesystem view, COW layers, checkpoints, retention, and reconciliation | existing `FilesystemSessionStorage` and filesystem runtime | kernel policy ownership |
| Kernel or mediated event drain, ordered ledger append, health/fence state | Surface enforcement owner with the existing audit domain | policy reevaluation |
| CLI | `erebor-runtime-cli` | kernel decisions, evidence persistence, or feature implementation |

## Surface Policy Lowering Contract

The current string-oriented matching forms are not automatically a
kernel-enforceable policy contract. Each Surface lowerer must produce an
immutable, digest-bearing image containing only facts its selected effect
boundary can check. Phase 1 defines the filesystem instance, for example:

- Session/cgroup identity and policy-image revision;
- resolved filesystem root and object identities in the admitted namespace;
- parent-object plus entry-name rules for creates and topology changes;
- action masks for file open/read/write/truncate, creation, removal, rename,
  link, metadata mutation, execution, and any other action the supported
  kernel-hook matrix claims;
- explicit handling for symbolic links, hard links, mount/namespace attempts,
  `/proc/self/fd`, descriptor inheritance/passing, and asynchronous I/O.

An admitted policy is either fully representable by this contract or rejected
with a structured `not kernel representable` admission result. A partial
translation must not route remaining cases through a userspace allow path.
Dynamic approval or mediation rules require an independently governed,
low-rate capability surface; they are not representable as a raw filesystem
permission check in this master. A future network lowerer, for example, must
distinguish address/port policy from hostname or application-intent policy and
reject claims its hook cannot prove.

## Evidence And Recovery Contract

BPF ring buffers provide ordered, efficient transport but are not a durable
ledger and do not block when full. The production contract is therefore:

1. The kernel enforcer allocates/commits an ordered evidence event before it
   returns allow. If it cannot allocate the event, it returns a fail-closed
   error instead.
2. A daemon-owned collector validates the Session/policy-image identity and
   appends events to an Erebor-owned durable ledger in order.
3. The collector publishes a durable cursor/health state. Session teardown
   seals the ledger only after the cgroup is empty and all committed events are
   reconciled.
4. On collector or daemon failure, the pinned kernel state fences new effects
   once its bounded capacity is exhausted. Recovery either resumes from the
   last durable cursor or marks the Session as evidence-incomplete; it never
   reports an unproven clean result.

The detailed durability boundary, batching maximums, event sizes, and failure
responses are Phase 3 deliverables. They require explicit review because they
replace the current per-operation `sync_data()` behavior.

## Host Capability Facts Observed On 2026-07-28

This repository's current host is a useful negative preflight result, not the
production target:

| Check | Observed value | Meaning |
| --- | --- | --- |
| Running kernel | `6.8.0-136-generic` | Kernel age is not the blocker for basic BPF LSM work. |
| Kernel configuration | `CONFIG_BPF_LSM=y`, `CONFIG_BPF_SYSCALL=y`, `CONFIG_CGROUP_BPF=y`, `CONFIG_DEBUG_INFO_BTF=y` | The kernel image includes BPF LSM support, BPF syscall support, cgroup BPF, and BTF. |
| Configured default LSM order | `CONFIG_LSM="landlock,lockdown,yama,integrity,apparmor"` | The built kernel's default boot LSM list omits `bpf`. |
| Active LSM order | `lockdown,capability,landlock,yama,apparmor` | BPF LSM is not active, so an LSM BPF program cannot attach on this boot. |
| Kernel command line | no `lsm=` override | Nothing corrected the default omission at boot. |
| Kernel lockdown | `none` | Lockdown is not the present blocker. |
| `unprivileged_bpf_disabled` | `2` | Unprivileged workloads cannot load BPF; that is desirable. The daemon still needs the host-approved BPF authority. |

Therefore the immediate limitation is **boot-time LSM activation**, not a
missing loadable module and not an insufficient kernel version. BPF LSM is
compiled into this kernel, but it was not enabled in the boot LSM order. A host
administrator would need a boot configuration that includes `bpf` in the LSM
order and then reboot. A production preflight must also verify that the daemon
has the required BPF/LSM authority while the workload does not. Phase 0 owns
the exact feature and privilege probe; this document does not authorize a host
boot configuration change.

## Phase Baseline Summary

- `SessionInterceptionBackendKind` currently exposes only `LinuxPtrace`.
- `LinuxPtraceInterceptionBackendBundle` prepares the current guard and its
  environment for Linux-host and Docker runners.
- `RuntimeGuardService` and `RuntimeInterceptionBrokerServer` own the current
  userspace broker/session-routing lifecycle.
- `StoredPolicyFileOperationHandler` owns current filesystem policy routing and
  per-decision durable JSONL evidence.
- `FilesystemSessionStorage` owns the existing per-Session OSTree repository,
  overlay, checkpoints, and retention layout.
- No BPF LSM source, program loader, policy compiler, cgroup-bound kernel map,
  kernel evidence collector, or kernel-enforcement capability report exists.

## Phase Index

- [Kernel Lifecycle Probe](./lifecycle-probe.md)
- [Phase 0: Contract And Linux Capability Spike](./phase-0-contract-and-capability-spike.md)
- [Phase 1: Kernel-Representable Policy And Admission Contract](./phase-1-policy-and-admission-contract.md)
- [Phase 2: BPF LSM Filesystem Enforcer](./phase-2-bpf-lsm-filesystem-enforcer.md)
- [Phase 3: Evidence Ledger, Fencing, And Recovery](./phase-3-evidence-ledger-and-recovery.md)
- [Phase 4: Session Lifecycle Integration And Production Cutover](./phase-4-session-lifecycle-and-cutover.md)
- [Future Surface Expansion Gate](./future-surface-expansion.md)

## Approval Workflow And Stop Points

This master plan is proposed design only. The user approves one phase at a
time. After each approved phase, stop, report the exact capability/verification
result, and wait for the next approval.

- **Stop after Phase 0:** approve the exact Linux kernel feature profile,
  privilege model, BPF build/loader dependency choice, object-identity/hook
  feasibility result, Surface-extension contract, and the production-host
  support policy before a resource or protocol change.
- **Stop after Phase 1:** approve the policy-language representability rules,
  admission failure behavior, and whether any existing policy documents need a
  migration. Do not silently reinterpret `target_contains` or approvals.
- **Stop after Phase 2:** approve the verified enforcement matrix and the
  evidence backpressure behavior before changing durable audit semantics.
- **Stop after Phase 3:** approve recovery/sealing semantics before production
  backend selection or retirement decisions.
- **Stop after Phase 4:** leave `linux_ptrace` available only at its explicitly
  documented compatibility tier; do not remove it or claim replacement without
  separate user approval.

## Verification Bar

Each implementation phase must add code-backed tests at the owning crate and
privileged Linux e2e coverage. The complete program must prove, at minimum:

- before-effect denial with no forbidden physical mutation;
- allow behavior through ordinary syscall variants and asynchronous paths;
- no bypass through descendant processes, `openat2`, rename/link/symlink,
  inherited or passed descriptors, `/proc`, or workload-controlled cgroups;
- deterministic behavior when the evidence channel fills, collector stops,
  daemon restarts, the workload crashes, or the Session is reattached;
- policy-image digest and Session attribution on every durable record;
- unsupported-host admission failure with a precise capability report;
- the real Linux workload lifecycle probe in `lifecycle-probe.md`.

Every future Surface must add equivalent pre-effect, bypass, evidence,
recovery, unsupported-host, and cross-Surface isolation coverage before it can
be offered at an admitted enforcement tier.

For Rust changes, each approved implementation phase must finish with:

```sh
bash .github/scripts/verify-rust-ci.sh
```

The privileged BPF LSM e2e suite must run in an isolated Linux test host with
the Phase 0 feature profile. A host that lacks BPF LSM is an expected
unsupported-capability result; it does not make the phase pass or justify a
ptrace fallback.
