# Implemented Phase Review

This guide explains the current implementation. It uses source links so that a
reviewer can follow each owner, state transition, and BPF decision. It does not
replace an acceptance record.

Source reviewed: commit `0c7f3bb8139d878d0214a3a81339c96e218ae4d5` plus the
Mithril working-tree changes on 2026-08-12. This review includes BPF object
SHA-256 `49d2f74b6c1312303e7eb1017d28c6a730f907ff7b3e662c73ba77f9d92805de`.
The validated architecture digest in the phase records is
`4a445b4015c4868a87af4893398068c5f362452c316d0cb8d06c038d41ffc0d8`.

The source contains one production BPF object, native task identity, signed
local policy rows, exact file decisions, typed device and process decisions,
exact Unix-stream relationships, and restart-safe bounded exceptions. The
current source has new programs, maps, policy gates, and evidence predicates.
Earlier VM records remain historical evidence. A current-source VM and k3s
qualification run is required before this guide makes a new physical claim.

The latest phase results remain:

- Phase 0: **Done** for its narrow x86-64 BPF Linux Security Module (LSM)
  capability and performance claim.
- Phase 1: **Done**.
- Phase 2: **Blocked** on the remaining failure-injection and entry-case
  matrix. An earlier identity VM probe passed for an older object.
- Phase 3: **Blocked** on a qualified Mithril CRI effect run and the remaining
  manual matrix. An earlier standalone observation VM probe passed for an
  older object.
- Phase 4: **Not done**. The source implements more narrow policy and
  hard-close slices. The complete activation, retirement, exec provenance,
  file lifetime, mount propagation, derived-device, privilege,
  self-protection, administrative-ingress, and Hugging Face contracts remain
  incomplete.

The optional Landlock deliverable is complete as `ABSENT`. The node reports
`LANDLOCK_TARGET_CONTEXT_FLOOR=ABSENT` with reason
`NO_QUALIFIED_TARGET_CONTEXT_INSTALL`. Local BPF enforcement does not depend on
Landlock.

Treat a source-backed hard denial as a safety floor. Do not treat it as a
positive policy-support result. Treat a unit or source-contract test as code
evidence. Do not treat it as a privileged physical result.

This guide is explanatory only. The authoritative scope and acceptance records
remain the phase documents and the readable architecture:

- [Master plan](./README.md)
- [Readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- [Phase 0 result](./phase-0-substrate-license-abi-and-incident-baseline.md)
- [Phase 1 result](./phase-1-one-binary-node-chassis.md)
- [Phase 2 result](./phase-2-exact-native-identity.md)
- [Phase 3 result](./phase-3-effect-observation-and-profile-simulation.md)
- [Phase 4 result](./phase-4-signed-local-pre-effect-enforcement.md)

## What to review, in order

Start at an owner boundary, not in a BPF helper. The following path gives the
smallest complete explanation of who does what.

| Order | Open this code first | What to establish before continuing |
| --- | --- | --- |
| 1 | [`mithril-node` main](../../../crates/mithril-node/src/main.rs#L22) | The CLI loads `NodeConfig` and starts one `NodeChassis`. It does not load a second object or decide effects. |
| 2 | [`NodeChassis::start`](../../../crates/mithril-node/src/node.rs#L49) | Startup order is: load or recover one object, publish bindings, install an optional signed generation, activate identity, and start observation and control. |
| 3 | [`KernelHostOwner::start`](../../../crates/erebor-interceptor/src/host.rs#L322) | `KernelHostOwner` is the only production load, attach, pin, manifest, and lease owner. It loads one object for one node. It does not load one object for each container. |
| 4 | [`WorkloadBindingOwner::publish_configured`](../../../crates/mithril-node/src/identity/binding.rs#L94) | The binding owner turns a validated live cgroup into one `execution_set_bindings` row. It owns container placement in userspace. |
| 5 | [`ContainerRuntimeInventory::snapshot`](../../../crates/mithril-node/src/identity/runtime.rs#L88) | The optional Container Runtime Interface (CRI) owner verifies configured container identity and resolves its local cgroup. It publishes no BPF program. |
| 6 | [`NodePolicyGenerationOwner::load_and_install`](../../../crates/mithril-node/src/policy.rs#L48) | A verified candidate becomes node-local map rows. The node reads each required row back before it sets the descriptor to `ACTIVE`. |
| 7 | [`NativeSecurityStateOwner::activate_with_effect_policy`](../../../crates/mithril-node/src/identity/native.rs#L40) | The identity owner writes or recovers one runtime configuration record. It then runs the task iterator. It does not load another BPF object. |
| 8 | [`identity.bpf.c`](../../../bpf/erebor-interceptor/programs/identity.bpf.c#L3) | One C translation unit includes the maps and all hook families in one ELF object. Read this file before an individual BPF header. |
| 9 | [`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L54) | This file declares BPF state and common helpers. It separates durable map state from per-CPU scratch state. |
| 10 | [`erebor_task_alloc`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L35) | Read the complete explanation in [Task allocation](#task-allocation-line-by-line). |
| 11 | [`resolved_identity_effect_gate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L271) | The common gate validates actor identity, binding, generation, object state, and the selected decision. Typed wrappers add device, process, IPC, file, and mount data. |
| 12 | [`LoweredGeneration::install`](../../../crates/mithril-node/src/policy.rs#L902) | This function fills the policy maps. It also prevents a partial generation from becoming active. |
| 13 | [`ExceptionAuthorityOwner`](../../../crates/mithril-node/src/policy/exception_authority.rs#L85) | This owner reconciles the kernel exception counters and receipts with the append-only local WAL. |
| 14 | [`IdentityTestRunner`](../../../crates/mithril-e2e/src/identity.rs#L150), [`EffectTestRunner::physical_probe`](../../../crates/mithril-e2e/src/effect.rs#L509), and [the VM harness](../../../crates/mithril-e2e/harness/vm/README.md) | Automated tests use the production object. Their cleanup owners remove pins, cgroups, leases, processes, mounts, and temporary files. |
| 15 | [Identity manual cases](../../../examples/mithril-identity-manual/README.md), [effect-observation manual cases](../../../examples/mithril-effect-observation-manual/README.md), and [local-enforcement manual cases](../../../examples/mithril-local-enforcement-manual/README.md) | These shells start the real node and perform operator actions. The examples link to the automated harness but do not own it. |

The most useful first pass is this short chain:

```text
NodeChassis::start
  -> KernelHostOwner::start
  -> WorkloadBindingOwner::publish_configured
  -> NodePolicyGenerationOwner::load_and_install (when configured)
  -> NativeSecurityStateOwner::activate_with_effect_policy
  -> identity.bpf.c
  -> identity_maps.h
  -> identity_lifecycle.bpf.h: erebor_task_alloc
```

## Current implementation, without phase-document ambiguity

| Area | Implemented owner | Current, honest claim |
| --- | --- | --- |
| Build and ABI | `erebor-interceptor-abi`, `erebor-interceptor` build script | Rust `repr(C)` ABI types use `zerocopy` for checked byte conversion. cbindgen renders one checked snake_case C header. `libbpf-cargo` compiles one C BPF object at Cargo build time. |
| Runtime loading | `KernelHostOwner` in `erebor-interceptor` | `libbpf-rs` opens the embedded object, applies the host BTF, loads, attaches, pins, reads back, and recovers it. |
| Binding and task identity | `WorkloadBindingOwner`, `NativeSecurityStateOwner`, BPF lifecycle hooks | Cgroup binding is userspace-published; task/process/entry/execution state is BPF-native and fail closed when it cannot be proven. |
| Signed policy generation | `PolicyArtifactOwner`/compiler in `mithril-control`, then `NodePolicyGenerationOwner` | Control-side policy stays portable and signed. The node verifies it, applies anti-rollback, derives local numeric handles, and publishes BPF map rows. |
| Local policy decisions | BPF effect/path/device/process/IPC headers, `NodePolicyGenerationOwner` | Exact file decisions use the current actor, a clean mount view, the canonical component graph, and an exact kernel object tuple. Device ioctl uses an exact command for allow or alert. Process control uses an exact target role and operation argument. Unix-stream relationships use both live endpoints. Missing or unsupported protected state fails closed. |
| Bounded exceptions | BPF receipt and counter maps, `ExceptionAuthorityOwner` | A synchronous `file_open` read or write attempt gets one stable receipt identity. BPF consumes under a spin lock. Userspace persists consumed receipts and monotonic runtime state in a local WAL. `file_receive` cannot consume an exception. Generic asynchronous request identity is not implemented. Production Control does not yet deliver an administrative request to this owner. |
| Other attached hooks | Explicit typed BPF wrappers | An attached hook can still be partial or unsupported. A protected request reaches an explicit hard-safe result when the code cannot prove the required object or state. |
| Observation | one `EffectObservationReader` plus `EffectObservationStore` | One `libbpf-rs` ring reader copies best-effort records into a bounded in-process history. It does not authorize and is not durable evidence. |
| Landlock target-context floor | Capability registration | The optional floor is complete as `ABSENT`, with reason `NO_QUALIFIED_TARGET_CONTEXT_INSTALL`. No BPF decision depends on this floor. |
| Physical qualification | `mithril-e2e` VM harness | The current object requires 50 production programs and 46 maps. It has 49 persistent program links and one temporary task iterator. Current-source VM evidence is pending. The k3s lane is limited to the declared CRI effect probe. It does not prove distributed policy, admission, or administrative approval. |

## One object, one loader, one node

The production binary embeds an already-built BPF ELF. It never compiles BPF
at node startup and it does not instantiate a BPF program for each container.

```mermaid
sequenceDiagram
    participant Cargo as Cargo build
    participant ABI as erebor-interceptor-abi
    participant Build as erebor-interceptor build.rs
    participant LC as libbpf-cargo and clang
    participant Node as mithril-node
    participant LR as libbpf-rs / KernelHost
    participant K as Linux BPF LSM and bpffs

    Cargo->>ABI: generate checked C ABI from Rust repr(C) types
    ABI-->>Build: erebor_interceptor_abi.h matches checked source
    Cargo->>Build: compile identity.bpf.c once
    Build->>LC: source + vmlinux wrapper + BPF headers
    LC-->>Build: BPF ELF in OUT_DIR
    Build-->>Node: include_bytes! embeds that ELF
    Node->>LR: start one KernelHost
    LR->>K: open embedded ELF with host runtime BTF
    LR->>K: load maps and attach required persistent programs
    LR->>K: pin and read back maps and links under one pin root
    K-->>LR: IDs and links recorded in manifest
```

Read the concrete build path in [`erebor-interceptor/build.rs`](../../../crates/erebor-interceptor/build.rs#L15).
It names the four checked BTF headers and invokes
[`libbpf_cargo::SkeletonBuilder`](../../../crates/erebor-interceptor/build.rs#L6).
The embedded bytes are in
[`bundled.rs`](../../../crates/erebor-interceptor/src/bundled.rs#L1), and
the runtime `libbpf-rs` open/load/attach path is in
[`KernelHostOwner::start`](../../../crates/erebor-interceptor/src/host.rs#L322).

`vmlinux.h` is present. It is the small architecture selector at
[`bpf/erebor-interceptor/include/vmlinux.h`](../../../bpf/erebor-interceptor/include/vmlinux.h#L1-L22),
which chooses checked generated x86, arm64, arm, or riscv definitions through
the standard `__TARGET_ARCH_*` Clang target macro. CO-RE reads make the program
adapt to the runtime BTF layout within the supported kernel field variants.

The ABI header is also intentionally generated, not hand duplicated:

```mermaid
flowchart LR
    R["Rust ABI types: repr(C)"] --> G["cbindgen"]
    G --> C["checked erebor_interceptor_abi.h: snake_case C names"]
    C --> B["identity.bpf.c"]
    R --> A["Rust map readers and writers"]
    A -. "same bytes and offsets" .-> C
    B -. "static assertions for size and offsets" .-> C
```

[`erebor-interceptor-abi/build.rs`](../../../crates/erebor-interceptor-abi/build.rs#L13)
rejects a build when cbindgen produces a header different from the
checked-in one. The BPF translation unit adds size and offset assertions at
[`identity.bpf.c`](../../../bpf/erebor-interceptor/programs/identity.bpf.c#L12).
The small BPF-only `exception_runtime_state_bpf_v1` wrapper is not a second
ABI: its first field must be the literal C `struct bpf_spin_lock` so the kernel
BTF recognizes it as a spin lock. The following assertions prove that it has
the same bytes and field offsets as the generated Rust ABI value.

### ABI read and write boundary

The Rust types are the source of the shared Application Binary Interface
(ABI). They use `#[repr(C)]`. The BPF program and the node run on the same host.
Map keys and values therefore use the host C layout and native byte order.
Userspace uses `to_ne_bytes()` for kernel map keys. The current generation
descriptor lookup uses `to_le_bytes()`. That representation equals native byte
order on the qualified x86-64 host and the checked little-endian targets. This
guide makes no big-endian claim. Deterministic digests and signed formats use
their separately defined byte order. The C translation unit uses
`_Static_assert` for decision-critical sizes and offsets.

The Rust code uses the existing `zerocopy` crate. It does not use manual byte
offsets or a new parser framework.

| ABI case | Conversion | Validation result | Example |
| --- | --- | --- | --- |
| All bit patterns are valid | `FromBytes::read_from_bytes` | Rejects a wrong input size | [`IdentityRuntimeConfigV1` recovery](../../../crates/mithril-node/src/identity/native.rs#L68) and [`IdentityHealthV1` aggregation](../../../crates/mithril-node/src/identity/native.rs#L117) |
| An enum or closed field can contain an invalid bit pattern | `TryFromBytes::try_read_from_bytes` | Rejects a wrong input size and an invalid field value | [`ExecutionSetBindingStateV1` recovery](../../../crates/mithril-node/src/identity/binding.rs#L759) and [generic policy ABI reads](../../../crates/mithril-node/src/policy.rs#L1278) |
| Rust value to map bytes | `IntoBytes::as_bytes` | Preserves the `repr(C)` value layout | [`execution_set_bindings` publication](../../../crates/mithril-node/src/identity/binding.rs#L180) |

Each conversion maps an invalid value to a crate-owned SNAFU error. The
binding owner compares the recovered typed value with the newly prepared live
binding. This typed comparison replaces the earlier field-by-field byte-offset
reader. Per-CPU health aggregation parses each exact-size `IdentityHealthV1`
chunk and then adds its counters.

The ABI does not make every value 64 bits. Linux identifiers and counters keep
the width required by their kernel source and range. Closed enum and flag
fields use smaller fixed widths where the layout permits it. `Id128V1` is for
stable opaque identities that need 128 bits. Explicit reserved bytes make C
alignment visible. A reviewer must compare a proposed width with the Linux
field, capacity, atomic operation, and cbindgen layout before narrowing or
widening it.

### Loader startup and recovery

```mermaid
sequenceDiagram
    participant N as NodeChassis
    participant H as KernelHostOwner
    participant L as PinRootLease
    participant K as Kernel / bpffs
    participant B as WorkloadBindingOwner
    participant P as NodePolicyGenerationOwner
    participant I as NativeSecurityStateOwner

    N->>H: start(identity config, host BTF, pin root)
    H->>H: validate config, preflight, calculate ELF digest
    H->>L: nonblocking exclusive flock on lease file
    alt fresh pin root
        H->>K: load one ELF and attach persistent programs
        H->>K: pin every map and link, then read its ID back
    else populated identity pin root
        H->>K: reuse each pinned map
        H->>K: open each pinned link and verify program tag
    end
    H-->>N: one ready KernelHost and manifest
    N->>B: publish cgroup bindings PREPARING then ACTIVE
    opt candidate configured
        N->>P: verify/lower/install/activate policy rows
    end
    N->>I: write or recover identity_config, then run task iterator
```

[`PinRootLease`](../../../crates/erebor-interceptor/src/lease.rs#L10)
is a nonblocking exclusive `flock` held as the `_lease` field of the live
`KernelHost`. Its role is narrow: prevent a second loader from owning the same
pin root. Dropping it unlocks the lease file. It does not unlink the lease file,
maps, links, or pin directories. It is not a policy lock. BPF map atomics and
spin locks still protect event-time state. The single live `KernelHost` owner
also gives userspace one map writer for active-generation publication.

The recovery branch starts at
[`KernelHostOwner::recover`](../../../crates/erebor-interceptor/src/host.rs#L534).
It reuses existing map pins and verifies the complete expected link set. It
does not attach another persistent hook set. The task iterator is the one
exception: [`KernelHost::reconcile_tasks`](../../../crates/erebor-interceptor/src/host.rs#L956)
attaches the iterator only while it is read to completion during activation.

On normal node shutdown the production identity pins intentionally remain, so
a later process can validate and recover them. The disposable qualification
object removes its pins. See
[`KernelHost::shutdown`](../../../crates/erebor-interceptor/src/host.rs#L983).

Two loader details answer common review questions:

- A vector capacity is not a membership rule. The fresh loader starts
  `link_records` empty, attaches only programs selected by
  [`KernelObjectKind::attaches`](../../../crates/erebor-interceptor/src/host.rs#L199),
  and then compares the attached names with the exact required set in
  [`validate_attached_set`](../../../crates/erebor-interceptor/src/host.rs#L822).
  Recovery uses `Vec::with_capacity(expected_links.len())` only to reserve
  memory. Before that loop, it derives `expected_links` from the required list
  and compares the complete pin-directory names with that set. It validates
  the resulting records again. The final validation compares sorted vectors,
  not mathematical sets. An extra duplicate therefore also fails. Capacity
  does not accept an extra, duplicate, or missing program.
- [`KernelHost::map`](../../../crates/erebor-interceptor/src/host.rs#L854)
  finds a map by name in the `libbpf-rs` object. `lookup_map` then handles a
  normal or per-CPU lookup. A Rust `HashMap<String, Map<'_>>` inside
  `KernelHost` would borrow the `Object` stored in the same structure. That is
  a self-reference. A table of duplicated `MapHandle` values would add handle
  and close ownership. The object has 46 maps, and no measured lookup
  bottleneck requires that extra state. The direct object lookup keeps one
  owner and is the simpler design.

## Ownership and publication boundaries

| State or capability | Durable owner | First implementation location | Not owned here |
| --- | --- | --- | --- |
| BPF ELF, map/link lifecycle, pins and manifest | `KernelHostOwner` / `KernelHost` | [`host.rs`](../../../crates/erebor-interceptor/src/host.rs#L289) | Workload semantics or policy compilation |
| One node process and shutdown/reconnect loop | `NodeChassis` | [`node.rs`](../../../crates/mithril-node/src/node.rs#L35) | A second privileged daemon |
| Cgroup workload binding | `WorkloadBindingOwner` | [`binding.rs`](../../../crates/mithril-node/src/identity/binding.rs#L51) | Task labels, process state, policy decision rows |
| Identity configuration and reconciliation health | `NativeSecurityStateOwner` | [`native.rs`](../../../crates/mithril-node/src/identity/native.rs#L22) | Object loading or container discovery |
| Portable policy/signature/simulation | `mithril-control` policy owners | [`mithril-control/src/policy`](../../../crates/mithril-control/src/policy) | BPF map handles or node startup |
| Node-local policy rows, active handles, and mount reconstruction | `NodePolicyGenerationOwner` | [`policy.rs`](../../../crates/mithril-node/src/policy.rs#L41) | Signature creation or cgroup binding lifecycle |
| Durable bounded-exception state and receipts | `ExceptionAuthorityOwner` | [`exception_authority.rs`](../../../crates/mithril-node/src/policy/exception_authority.rs#L85) | Policy selection or online approval delivery |
| Administrative proof and slot state | `AuthorizationProofOwner` | [`authorization/mod.rs`](../../../crates/mithril-node/src/identity/authorization/mod.rs#L110) | Production Control ingress; `NodeChassis` does not invoke this owner yet |
| Task/process/exec state | BPF lifecycle, exec, and exit programs | [`identity_lifecycle.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h), [`identity_exec.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h), [`identity_exit.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_exit.bpf.h) | Userspace task enrollment after the fact |
| Per-effect result | BPF common and typed gates | [`identity_effects.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L271), [`identity_device_process.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_device_process.bpf.h#L32), [`identity_ipc.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L223) | Control round trips or ring-buffer delivery |
| Ring consumption and recent records | `EffectObservationReader` / `EffectObservationStore` | [`host.rs`](../../../crates/erebor-interceptor/src/host.rs#L929), [`observation.rs`](../../../crates/mithril-node/src/observation.rs) | Policy decisions or durable audit |

### Node startup order

```mermaid
sequenceDiagram
    participant Config as NodeConfig
    participant Node as NodeChassis
    participant Host as KernelHost
    participant Binding as WorkloadBindingOwner
    participant Policy as NodePolicyGenerationOwner
    participant Native as NativeSecurityStateOwner
    participant Ring as EffectObservationReader
    participant Control as mithril-control

    Config->>Node: validated configuration
    Node->>Host: start or recover one identity object
    Node->>Binding: publish configured or CRI-resolved cgroups
    opt policy candidates exist
        Node->>Policy: verify and install local generation
    end
    Node->>Native: enable identity and effect policy when a candidate exists
    Native->>Host: run task reconciliation iterator and aggregate health
    opt candidate exists
        Node->>Ring: create the only ring-buffer reader
    end
    Node->>Control: register capabilities and begin reconnect loop
```

This is the exact ordering in
[`NodeChassis::start`](../../../crates/mithril-node/src/node.rs#L49).
It matters that bindings and an optional generation exist *before* identity is
enabled and live tasks are reconciled. Policy candidates and workload binding
specifications are startup configuration in this implementation. The Control
stream does not deliver or activate a new candidate generation.

### Control connection and readiness

```mermaid
sequenceDiagram
    participant Node as NodeChassis run loop
    participant Connector as NodeControlConnector
    participant Control as mithril-control
    participant Ready as readiness watch

    Node->>Connector: connect with registration and local health
    Connector->>Control: mTLS stream and Registration, sequence 1
    Control-->>Connector: RegistrationAccepted, sequence 1
    Control-->>Connector: TrustGeneration, sequence 2
    Connector->>Connector: persist trust cache
    Connector->>Control: TrustAck, node sequence 2
    Connector->>Control: ReadinessReport, node sequence 3
    Node->>Ready: control_ready=true and admission_ready=identity_healthy
    alt stream closes or sends an unexpected later message
        Node->>Ready: control_ready=false and admission_ready=false
        Node->>Node: reconnect with bounded backoff
    end
```

Read the handshake at
[`NodeControlConnector::connect`](../../../crates/mithril-node/src/control.rs#L52)
and the reconnect loop at
[`NodeChassis::run`](../../../crates/mithril-node/src/node.rs#L211). The current
post-registration handler accepts no policy, binding, exception, or
administrative-exec delivery message. An unexpected message closes the
connection. This is a clear implementation limit, not an implicit dynamic
control plane.

### CRI binding refresh

```mermaid
sequenceDiagram
    participant Node as NodeChassis
    participant Binding as WorkloadBindingOwner
    participant CRI as CRI RuntimeService
    participant Proc as procfs Process
    participant Host as KernelHost
    participant Map as execution_set_bindings

    Node->>Binding: publish_configured or periodic reconcile
    Binding->>CRI: ListContainers
    loop configured container IDs only
        Binding->>CRI: ContainerStatus(verbose=true)
        CRI-->>Binding: exact ID, labels, image, time, runtime info
        alt OCI cgroupsPath is present
            Binding->>Binding: validate and resolve cgroupsPath
        else CRI-dockerd gives a live PID
            Binding->>Proc: open Process and read unified cgroup
            Proc-->>Binding: kernel cgroup path
        end
        Binding->>Binding: verify exact configured container lifetime
        Binding->>Host: PREPARING row, readback, ACTIVE row, readback
        Host->>Map: update one cgroup binding
    end
```

Read this flow at
[`ContainerRuntimeInventory::snapshot`](../../../crates/mithril-node/src/identity/runtime.rs#L88)
and
[`WorkloadBindingOwner::reconcile_runtime_inner`](../../../crates/mithril-node/src/identity/binding.rs#L424).
The node uses the `k8s-cri` generated client. It uses `procfs::Process` for the
CRI-dockerd PID fallback. It does not start a Docker listener, parse a CRI
command, or load a per-container BPF object.

### Shutdown and recovery

```mermaid
sequenceDiagram
    participant Node as mithril-node
    participant Host as KernelHost
    participant Lease as PinRootLease
    participant Pins as bpffs pins
    participant Test as e2e cleanup owner

    alt production node stops
        Node->>Host: shutdown
        Host->>Lease: close file and release flock
        Host-->>Pins: keep identity map and link pins
    else node restarts
        Node->>Host: start with same pin root
        Host->>Pins: reuse maps and verify every pinned link/program tag
    else disposable probe stops
        Test->>Host: shutdown qualification owner
        Host->>Pins: remove probe-owned pins
        Test->>Test: remove cgroup, lease, files, mounts, and tasks
    end
```

A bpffs pin keeps a map or link alive after the loader process exits. Process
exit does not delete a pinned object. Production identity shutdown keeps the
pins for recovery. The test owners explicitly remove disposable pins and then
assert that the paths no longer exist. The production shutdown implementation
starts at [`KernelHost::shutdown`](../../../crates/erebor-interceptor/src/host.rs#L983).

## The BPF object: source relationship and hook families

`identity.bpf.c` is intentionally a single translation unit. The include order
is the source-level dependency graph:

```text
vmlinux.h + generated ABI + libbpf headers
        |
        v
identity_maps.h             -- 46 maps, shared validation, attempts, exceptions
identity_task_helpers.h     -- native child construction and rollback
identity_root_helpers.h     -- root construction and coordinate finalization
identity_path.bpf.h         -- bounded path graph and mount-view state
        |
        +--> identity_lifecycle.bpf.h      -- task/cgroup/wakeup/iterator
        +--> identity_exec.bpf.h           -- exec and admin-argv transaction
        +--> identity_effects.bpf.h        -- common effect gate
                 +--> identity_device_process.bpf.h
                 +--> identity_ipc.bpf.h
                 +--> explicit file/path/mount/privilege LSM wrappers
        +--> identity_exit.bpf.h           -- exact reference release
```

The loader requires 50 named programs from this one ELF. The exact list is
[`REQUIRED_IDENTITY_PROGRAMS`](../../../crates/erebor-interceptor/src/host.rs#L78).
It permanently attaches 49 programs. The task iterator is loaded but attached
only while userspace reads it. The following catalog accounts for every
required program.

| Program | ELF section and program kind | Invocation and relationship |
| --- | --- | --- |
| [`erebor_task_alloc`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L35) | `lsm/task_alloc`, BPF LSM | Runs during child allocation. It preserves a prior LSM result. It publishes complete native child state or denies a protected allocation. |
| [`erebor_cgroup_attach_task`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L107) | `tp_btf/cgroup_attach_task`, BTF tracepoint | Runs when Linux attaches a task to a cgroup. It labels an unlabelled task that enters a protected binding. It marks a labelled placement mismatch fail closed. |
| [`erebor_cgroup_release`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L156) | `raw_tracepoint/cgroup_release` | Tombstones the released cgroup binding. It does not grant or recover authority. |
| [`erebor_wake_up_new_task`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L174) | `fentry/wake_up_new_task` | Labels a pre-wake protected root or finalizes the child coordinate before the task runs. |
| [`erebor_reconcile_tasks`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L210) | `iter/task`, BPF iterator | Userspace attaches and drains this program during activation. It checks live labelled tasks. It retains restrictions and raises reconciliation health on uncertainty. |
| [`erebor_sys_enter_execve`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L339) | `tracepoint/syscalls/sys_enter_execve` | Tries to prepare one bounded administrative argument match. The BPRM hook starts the general exec transition. |
| [`erebor_sys_enter_execveat`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L346) | `tracepoint/syscalls/sys_enter_execveat` | Records an `AT_EXECVE_CHECK` marker or tries the same bounded administrative argument match. The BPRM hook handles the executable candidate. |
| [`erebor_bprm_check_security`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L625) | `lsm/bprm_check_security`, BPF LSM | Adds ordered executable candidates, checks the exec decision, and validates an exact administrative match when one exists. It preserves prior denial. |
| [`erebor_bprm_committing_creds`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L673) | `fentry/security_bprm_committing_creds` | Marks the transaction past the point where a failed exec can safely restore the old state. |
| [`erebor_sys_exit_execve`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L779) | `tracepoint/syscalls/sys_exit_execve` | Closes an `execve` failure before or after the point of no return. |
| [`erebor_sys_exit_execveat`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L785) | `tracepoint/syscalls/sys_exit_execveat` | Closes an `execveat` failure with the same conservative rule. |
| [`erebor_sched_process_exec`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L804) | `tracepoint/sched/sched_process_exec` | Commits the process, image, execution, role, and administrative-slot outcome after Linux reports exec success. |
| [`erebor_exception_sys_enter`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L6) | `raw_tracepoint/sys_enter` | Advances the task-local syscall-attempt sequence. This sequence forms part of the stable exception receipt identity. |
| [`erebor_exception_sys_exit`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L26) | `raw_tracepoint/sys_exit` | Marks the task-local exception attempt inactive when the syscall ends. |
| [`erebor_mount_mutation_sys_exit`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h#L333) | `tracepoint/raw_syscalls/sys_exit` | Completes a task-local mount attempt and leaves the namespace view dirty for userspace reconciliation. It uses atomics because tracing programs cannot use the mount-view BPF spin lock. |
| [`erebor_identity_file_open`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L574) | `lsm/file_open`, BPF LSM | Applies exact file-open or default policy before Linux returns the file descriptor. |
| [`erebor_identity_file_permission`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L580) | `lsm/file_permission`, BPF LSM | Converts the Linux read, write, and execute mask into separate typed operations and applies each decision. |
| [`erebor_identity_file_ioctl`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L600) | `lsm/file_ioctl`, BPF LSM | Runs the common actor and object proof, then uses the exact device and ioctl key in [`identity_device_ioctl_gate`](../../../bpf/erebor-interceptor/programs/identity_device_process.bpf.h#L143). |
| [`erebor_identity_mmap_file`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L607) | `lsm/mmap_file`, BPF LSM | Applies read, write, and executable file-mapping decisions for the requested protection bits. |
| [`erebor_identity_file_mprotect`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L631) | `lsm/file_mprotect`, BPF LSM | Uses the mapped file when present and applies write or execute transitions. Anonymous executable memory stays a hard-close path, not a complete VMA model. |
| [`erebor_identity_socket_post_create`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L434) | `lsm/socket_post_create`, BPF LSM | Stores creator endpoint identity in socket-local storage for a protected Unix stream. Other socket kinds do not receive positive Unix-stream authority. |
| [`erebor_identity_unix_stream_connect`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L448) | `lsm/unix_stream_connect`, BPF LSM | Validates the current client, stored listener, and accepted child. It creates one channel identity and applies an exact relationship decision. Only denial relationships are compiled. |
| [`erebor_identity_socket_connect`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L457) | `lsm/socket_connect`, BPF LSM | Defers AF_UNIX stream authority to `unix_stream_connect`. Other protected network connection requests use the unsupported network path. |
| [`erebor_identity_socket_sendmsg`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L474) | `lsm/socket_sendmsg`, BPF LSM | Revalidates both stored endpoints for a connected Unix stream. Other protected socket messages do not inherit that authority. |
| [`erebor_identity_socket_recvmsg`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L492) | `lsm/socket_recvmsg`, BPF LSM | Applies the receive direction of the same connected-stream proof. |
| [`erebor_identity_socket_socketpair`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L509) | `lsm/socket_socketpair`, BPF LSM | Takes the explicit unsupported IPC path. Socket-pair positive authority is not implemented. |
| [`erebor_identity_unix_may_send`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L516) | `lsm/unix_may_send`, BPF LSM | Takes the explicit unsupported Unix datagram path. |
| [`erebor_identity_ipc_permission`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L523) | `lsm/ipc_permission`, BPF LSM | Takes the explicit unsupported SysV IPC path for a protected actor. |
| [`erebor_identity_shm_shmat`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L530) | `lsm/shm_shmat`, BPF LSM | Takes the explicit unsupported shared-memory attach path. |
| [`erebor_identity_ptrace_access_check`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L662) | `lsm/ptrace_access_check`, BPF LSM | Calls the exact controller-target snapshot and process-rule gate. Positive rows require exact target roles and exact operation arguments. |
| [`erebor_identity_task_kill`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L670) | `lsm/task_kill`, BPF LSM | Applies the same exact controller-target proof to signal delivery and records the signal as the operation argument. |
| [`erebor_identity_path_unlink`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L679) | `lsm/path_unlink`, BPF LSM | Applies path/object policy to an existing unlink target. |
| [`erebor_identity_path_mknod`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L687) | `lsm/path_mknod`, BPF LSM | Checks the destination path. A negative or unresolved destination cannot gain exact-object authority. |
| [`erebor_identity_path_mkdir`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L696) | `lsm/path_mkdir`, BPF LSM | Checks directory creation with the same conservative destination rule. |
| [`erebor_identity_path_symlink`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L704) | `lsm/path_symlink`, BPF LSM | Checks symlink creation. It does not infer authority from the target text. |
| [`erebor_identity_path_rmdir`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L712) | `lsm/path_rmdir`, BPF LSM | Applies path/object policy to the existing directory. |
| [`erebor_identity_path_chmod`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L720) | `lsm/path_chmod`, BPF LSM | Applies metadata policy to the exact existing path object. |
| [`erebor_identity_path_chown`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L728) | `lsm/path_chown`, BPF LSM | Applies ownership-change policy to the exact existing path object. |
| [`erebor_identity_path_truncate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L736) | `lsm/path_truncate`, BPF LSM | Applies truncate policy to an exact path object. |
| [`erebor_identity_file_truncate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L743) | `lsm/file_truncate`, BPF LSM | Applies truncate policy through an existing file object. |
| [`erebor_identity_path_link`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L750) | `lsm/path_link`, BPF LSM | Checks the existing source and then the destination. It does not transfer a signed path class to an unrepresented hard-link alias. |
| [`erebor_identity_path_rename`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L763) | `lsm/path_rename`, BPF LSM | Checks both source and destination before the rename. |
| [`erebor_identity_sb_mount`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L785) | `lsm/sb_mount`, BPF LSM | Applies the mount policy. If Linux may continue, it dirties the namespace view before mutation. |
| [`erebor_identity_sb_umount`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L793) | `lsm/sb_umount`, BPF LSM | Applies unmount policy and starts the same dirty-view transaction when allowed. |
| [`erebor_identity_sb_pivotroot`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L800) | `lsm/sb_pivotroot`, BPF LSM | Applies pivot-root policy and invalidates the represented topology before an allowed change. |
| [`erebor_identity_move_mount`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L807) | `lsm/move_mount`, BPF LSM | Applies move-mount policy and invalidates the represented topology before an allowed change. |
| [`erebor_identity_capable`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L814) | `lsm/capable`, BPF LSM | Uses the typed privilege operation and a finite default cell. Missing protected authority hard-denies. It is not a complete credential-transition model. |
| [`erebor_identity_bpf`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L822) | `lsm/bpf`, BPF LSM | Applies the BPF privilege operation before the command. It is not complete protection of every Mithril map, link, and binary operation. |
| [`erebor_sched_process_exit`](../../../bpf/erebor-interceptor/programs/identity_exit.bpf.h#L16) | `tracepoint/sched/sched_process_exit` | Uses the task tombstone to release task, process, entry, domain, image, execution, and generation references once. Failed decrements retain restriction and raise reconciliation health. |

Use the following family matrix with the program catalog. The program catalog
identifies the exact hook. The family matrix identifies its state, helper
constraints, physical result, userspace setup, and proof path.

| Program family | Map reads and writes | Important BPF helpers | Return and physical effect | Userspace setup and proof |
| --- | --- | --- | --- | --- |
| `task_alloc`, `cgroup_attach_task`, `wake_up_new_task` | Read runtime config, live cgroup binding, creator state, and generation refs. Create task storage, coordinates, creator edges, process, vector, entry, domain, image, execution, and tombstone rows. Rollback removes only acquired state. | CO-RE cgroup and task reads, `bpf_get_current_task_btf`, task storage, map lookup/update/delete, and BPF atomics. | `task_alloc` can return the prior LSM denial or a negative errno. Trace and fentry programs return zero after state work; they do not override a syscall result. Missing protected identity retains a restrictive result or health state. | `WorkloadBindingOwner` publishes the cgroup row first. `NativeSecurityStateOwner` enables identity. The identity e2e runner proves root, native-child, exec, restart, reference, and cleanup paths. Source-contract tests in [`bundled.rs`](../../../crates/erebor-interceptor/src/bundled.rs) check verifier-sensitive task-storage and counter rules. |
| `cgroup_release`, `sched_process_exit` | Tombstone the binding or task. Release exact task, process, vector, entry, domain, image, execution, and generation references. | Raw or scheduler trace context reads, map lookup/update/delete, and nonzero compare-and-swap decrement. | These trace programs return zero. They cannot deny exit. A failed decrement keeps the restrictive row and increments reconciliation health. | Recovery reads retained refs. `lifecycle_counters_use_the_nonzero_cas_decrement` checks the source contract. The identity probe checks final reference counts. |
| `reconcile_tasks` | Read every live task label and related state. Update health or retain restriction on mismatch. | BPF iterator context, task storage, CO-RE reads, and bounded map lookups. | Returns zero for each iterator element. It changes reconciliation state, not the task syscall result. | `KernelHost::reconcile_tasks` attaches, drains, and drops this program for each reconciliation run. It is the only required program without a persistent link. |
| Exec entry, BPRM, commit, exit, and success programs | Read task, process, entry, image, exact object, policy, approved slot, approved argument, and exception state. Write pending exec, pending administrative match, candidate image, image provenance, execution, process role, and reference rows. | `bpf_probe_read_user`, bounded loop callbacks, BPRM CO-RE reads, map operations, task storage, spin-locked exception consumption, and atomics. | `bprm_check_security` returns the prior denial, policy denial, or zero before exec. Trace and fentry programs return zero after transaction maintenance. A post-commit uncertainty never restores wider authority. | `AuthorizationProofOwner` installs exact ordered-argument keys and one slot when called. `NodePolicyGenerationOwner` installs exec decisions. The effect probe checks exec variants, an approved exact control, and failed-close memory cases. `bundled.rs` checks argument-loop, candidate-index, and BPRM-loop bounds. |
| Exception syscall entry and exit | Write task-local syscall state and a bounded `file_open` frame stack in `task_effect_attempt_states`. Read no policy row. | Current task storage and raw syscall context. | Return zero. These programs identify an attempt. They do not allow or deny that attempt. A malformed, unfinished, or overflowed frame fails closed. | `NodePolicyGenerationOwner` installs exception bindings. `ExceptionAuthorityOwner` restores receipts and reconciles the WAL. Current-source physical proof is pending. |
| File open, permission, mmap, and mprotect | Read actor identity, binding, generation, exact object, mount view, canonical graph, effect decision/default, exception, and observation state. Write late root state, exception receipts/counters, mount proposal state, observation health, and ring records. | Trusted current task, task storage, CO-RE inode/dentry/mount reads, bounded loop callbacks, map operations, spin locks where valid, atomics, ring reserve/submit, and monotonic time. | Preserve a prior LSM denial. Return zero for allow or observe-only `WOULD_DENY`. Return a verified negative errno in protect mode or for an integrity failure. Ring loss cannot change the return. | `NodePolicyGenerationOwner` installs all signed rows and exact mount state. Earlier VM records cover file, alias, descriptor, mapping, saturation, and benign controls for an older object. |
| Device ioctl | Run the common actor and exact-object proof. Then read `device_effect_decisions` with exact type, major, minor, command, role, and state. Write only common exception and observation state. | File/inode CO-RE reads, Linux device-number helpers, map lookup, and the common observation helpers. | Preserve prior denial. Return an exact command result. A command wildcard is denial-only. Missing typed authority hard-denies. | The node lowerer rejects an unsigned device class and a positive command wildcard. The fixture uses `/dev/pts/ptmx` and `TIOCGPTN`; `/dev/zero` is the exact deny control. |
| Ptrace and signal | Read controller identity and target task storage, binding, coordinate, process/vector, generation, and `process_control_rules`. Recheck target and transition versions after lookup. Write common observation state. | Trusted target task pointer, task storage, CO-RE target reads, map lookup, and common observation helpers. | Preserve prior denial. Return an exact directional result or hard-deny missing proof. Generic rows are denial-only. | `lower_process` owns the exact target and argument restriction. Current physical evidence covers exact denial and signal-zero permission only. |
| Unix-stream socket programs | Read and write `ipc_socket_states`. Read actor, peer, binding, generation, and `ipc_relationship_decisions`. Write common observation state. | Socket-local storage, trusted socket member pointers, task storage, CO-RE socket/process reads, and map lookup. | Connected stream hooks apply an exact relationship result or the signed unmatched result. Socketpair, datagram, SysV IPC, and shared-memory hooks take the explicit unsupported path. | `lower_ipc_relationships` installs exact two-direction rows for allow, alert, or deny, plus signed unmatched rows. Current-source physical proof is pending. |
| Path mutation programs | Read actor, source/destination dentry and inode state, exact object, mount graph, and signed effect rows. Write common observation and exception state. | CO-RE path reads, bounded canonical path loop, map lookup, and the common gate. | Preserve a prior denial. Return source denial before destination evaluation. An unresolved negative destination cannot gain object authority. | The policy owner installs represented roots and exact objects. Earlier VM records cover create, metadata, truncate, unlink, link, and rename hard-close paths for an older object. `link_and_rename_check_source_before_destination` checks source order. |
| Mount mutation programs and syscall exit | Read actor policy and namespace view. The LSM hooks lock and mark an allowed mutation `DIRTY` before Linux changes topology. The exit tracepoint advances version and pending state with atomics. | Mount/dentry CO-RE reads, map lookup, BPF spin lock in LSM programs, task storage, and atomics in the tracepoint. | LSM hooks deny an unsupported protected mutation or return zero after invalidation. The exit tracepoint returns zero and cannot authorize the mutation. | The policy owner installs and reconciles mount rows from retained namespace capabilities. Earlier VM records cover protected and external replacement races and exact restoration for an older object. Source-contract tests prohibit spin locks in the tracepoint. |
| `capable` and `bpf` | Read current actor, generation, finite privilege defaults, and observation state. Write common exception and observation state. | Common actor helpers, map lookup, and ring helpers. | Preserve prior denial. Return the signed finite result or hard-deny missing protected authority. | The protection probe checks namespace privilege, BPF, and link-removal safety floors. These programs do not prove the full privilege or self-protection matrix. |

The required-program list is a load-time completeness check. It is not a
capability claim. Review each program with its map inputs, policy compiler
support, and physical oracle. The common relationship is:

```mermaid
flowchart LR
    L[Lifecycle hooks] --> I[Task and process identity]
    I --> X[Exec transaction]
    X --> I
    I --> G[Common effect gate]
    P[Signed generation maps] --> G
    M[Mount and path state] --> G
    G --> D[Device and process gate]
    G --> U[Unix-stream IPC gate]
    G --> F[File, path, mount, privilege wrappers]
    D --> O[Fixed physical result]
    U --> O
    F --> O
    O --> R[Best-effort observation]
    E[Exit hook] --> I
```

## Maps: what they store, who fills them, and who reads them

The authoritative declarations are all in
[`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L93).
The important simplification is that each map has one domain publisher on the
userspace side, while BPF owns event-time identity transitions. The kernel
loader has the file descriptor; it does not invent map contents.

### 1. Bootstrap and temporary state

| Map | Filled by | Read by | Plain meaning |
| --- | --- | --- | --- |
| `identity_config` (array, one record) | `NativeSecurityStateOwner`; `allocate_id` advances `next_id` atomically | Every identity/effect hook | Node boot ID, label epoch, enabled flags, configured deny errno, and opaque-ID allocator. |
| `identity_health` (per-CPU array) | BPF hook families increment counters | `NativeSecurityStateOwner` aggregates all CPU values | Diagnostic counters; missing health storage never authorizes anything. |
| `identity_scratch` (per-CPU array) | The currently running BPF invocation | That same invocation only | Reusable temporary construction area, not durable task identity. One invocation completes on one CPU. A later invocation uses the slot for its current CPU. Durable data is published to task storage or hash maps before return. |
| `effect_observation_health` (per-CPU array) | Effect gate | Runtime observation | Attempted/emitted/lost/unresolved observation counters. |
| `effect_observations` (4 MiB ring buffer) | Effect gate after selecting the result | One `libbpf-rs` ring reader | Best-effort evidence. Ring pressure can lose evidence but cannot change allow/deny. |

### 2. Binding and identity state

| Map(s) | Filled by | Read by | Plain meaning |
| --- | --- | --- | --- |
| `execution_set_bindings` | `WorkloadBindingOwner`: `PREPARING` → exact readback → `ACTIVE`; BPF consumes the single initial-root marker and tombstones a released cgroup | Lifecycle and effect gate | The live cgroup-to-workload authority record, including nonce, profile generation and roles. BPF never creates or activates a binding. |
| `profile_generation_task_refs` | Binding owner creates the zero value; BPF birth increments and exit decrements | BPF lifecycle and node recovery | Keeps a generation retained while labelled tasks exist. |
| `active_profile_generations` | `NodePolicyGenerationOwner` publishes binding ID → generation after the generation is `ACTIVE`; `WorkloadBindingOwner` reads it before it updates the live binding | New-root admission helpers and binding activation | This is the switch for future roots. Existing processes keep the generation stored in their process state. It is not a per-effect global pointer. |
| `task_labels` (task storage) | BPF `publish_task`; BPF rollback deletes partial publication | Every hot BPF path | Immutable birth identity attached directly to the kernel task. There is no delayed PID enrollment. |
| `task_coordinates`, `kernel_real_parent_intervals`, `created_by_edges` | BPF birth/wakeup/exec/exit/reconcile | Identity and effect paths; inspection | Reusable Linux coordinates, current kernel-parent observation, and immutable creator proof. |
| `process_states`, `process_state_vectors`, `entry_states`, `authority_domains` | BPF root/native birth; BPF exec and exit transitions | Lifecycle, exec and effect paths | Current mutable authority state for a process, its finite state vector, entry lifetime, and native-family domain. |
| `external_root_classifications`, `pending_execs`, `image_provenance`, `process_execution_instances`, `task_reference_tombstones` | BPF lifecycle/exec/exit | Lifecycle, exec, effect and reconciliation paths | Root kind, in-flight exec state, exact executable provenance, execution instances, and exactly-once release bookkeeping. |

### 3. Authorization-proof state

| Map(s) | Filled by | Read or changed by | Plain meaning |
| --- | --- | --- | --- |
| `approved_exec_slots`, `approved_exec_arguments` | `AuthorizationProofOwner` when an in-process caller invokes it | Exec path consumes one matching slot; exec path reads bounded argument bytes | Identity-side foundation for an exact administrative exec proof. `NodeChassis` has no production Control request path that invokes this owner. It is not a command-string allow list. |
| `pending_administrative_matches` | Exec entry path | BPRM/exec completion path | Short-lived bridge from verified syscall argv to the BPRM transaction. |

### 4. Signed policy, exact file, and mount state

| Map(s) | Filled by | Read or changed by | Plain meaning |
| --- | --- | --- | --- |
| `profile_generation_descriptors` | `NodePolicyGenerationOwner` writes `PREPARING`, `READ_BACK`, then `ACTIVE` | Effect gate | The generation is usable only when its boot/epoch/profile descriptor is `ACTIVE`. Its mode says `OBSERVE` or `PROTECT`. |
| `effect_decisions`, `effect_defaults` | `NodePolicyGenerationOwner` | Effect gate | Exact-object row first, then finite default fallback. A decision contains the physical disposition and errno/exception handle. |
| `device_effect_decisions` | `NodePolicyGenerationOwner` | Exact device ioctl gate | Exact file tuple, device major/minor/type, ioctl command, actor state, and generation. An explicit command wildcard can deny only. |
| `process_control_rules` | `NodePolicyGenerationOwner` | Ptrace and signal gates | Exact controller and target roles/state vectors plus operation argument. Generic rows can deny only. |
| `ipc_relationship_decisions` | `NodePolicyGenerationOwner` | Connected Unix-stream gate | Endpoint role and operation rows for allow, alert, or deny. The lowerer installs both directions for one local-channel relationship. The unmatched row can allow, alert, or deny. |
| `ipc_socket_states` | BPF socket creation and connect paths | BPF Unix-stream connect/send/receive paths | Socket-local endpoint and channel identity. The value follows the socket lifetime. |
| `exception_handle_bindings`, `exception_runtime_states`, `exception_use_receipts` | Policy and exception owners install bindings/state and restore durable consumed receipts | BPF claims one receipt, locks one runtime value, checks deadline/count, and consumes one use | Stable exception instance and use identity. The WAL owns restart reconciliation. |
| `task_effect_attempt_states` | Raw syscall entry/exit and `file_open` BPF code | Exception consumption | Task-local syscall state and bounded `file_open` frames. Each current synchronous file-open decision gets a new effect-attempt sequence. |
| `exact_file_objects` | `NodePolicyGenerationOwner` writes configured tuple rows | Effect and device gates read only | Exact object key: generation, mount namespace, unique mount identity, device, inode, and inode generation. BPF does not create a new authority row from a pathname. |
| `mount_security_views`, `mount_mutation_epochs`, `mount_security_view_locks`, `mount_reconciliation_proposals` | Policy owner initializes/reconciles; BPF mount hooks dirty/advance state; BPF file gate commits an exact proposal | BPF path and policy reconciliation | Namespace-global topology safety state. A dirty or racing view cannot produce a strict file decision. |
| `canonical_mount_roots`, `path_graph_exact_transitions`, `path_graph_wildcard_transitions`, `path_graph_terminals` | Policy owner after resolving the represented mount view | BPF canonical path candidate | The bounded Meta component graph and trusted root prefix used to turn live dentry components into a signed class candidate. |
| `mount_mutation_attempts` (task storage) | BPF mount and exit paths | BPF mount completion | A small task-local pairing record only. Namespace topology authority stays in namespace-keyed maps. |

### Complete map lifecycle matrix

All maps in this table belong to the one production object. The loader pins
all of them below `PIN_ROOT/maps`. “Pin-root lifetime” means that the bpffs pin
keeps the map alive after process exit. A later node can reuse the map. Only an
explicit cleanup owner removes the pin. Task-storage values also end when their
kernel task ends. Per-CPU scratch content is reusable temporary content even
though the map object stays pinned.

The object uses flat typed maps instead of a map-of-maps. Generation and
binding IDs are part of decision keys. The active handle selects a generation,
and an `ACTIVE` descriptor validates it. A map-of-maps would add inner-map
creation, template, file-descriptor, pin, recovery, replacement, and retirement
ownership. It is useful when a design needs whole inner-table replacement or
strong per-tenant map isolation. The current source does not need that extra
owner for its single-node, single-writer publication model. Do not add a
map-of-maps only because another project uses one. Reconsider it if a later
multiwriter or whole-generation atomic-replacement requirement cannot be met by
the active handle and immutable generation keys.

| Map | Key and value ABI | Userspace writer | BPF writer | Readers | Lifetime |
| --- | --- | --- | --- | --- | --- |
| `identity_config` | `u32` → `IdentityRuntimeConfigV1` | `NativeSecurityStateOwner` | `allocate_id` changes `next_id` atomically | All identity and effect families | Pin-root lifetime; one row for one boot and label epoch |
| `identity_health` | per-CPU `u32` → `IdentityHealthV1` | None | Lifecycle, exec, and exit families | Native health aggregation | Pin-root lifetime; counters are per CPU |
| `identity_scratch` | per-CPU `u32` → BPF-only `identity_scratch_v1` | None | Current BPF invocation | Current BPF invocation | Pin-root lifetime; content is temporary and can change on the next invocation on that CPU |
| `task_labels` | task-storage kernel key → `TaskLabelV1` | None | Root and native publication; rollback deletes | Lifecycle, exec, effect, exit, iterator, inspector | Map has pin-root lifetime; each value has task lifetime |
| `task_coordinates` | `u64 task_cookie` → `TaskCoordinateV1` | None | Root, native, wake, exec, exit, iterator | Lifecycle, exec, effect, inspector | Pin-root lifetime; explicit exit and rollback cleanup |
| `kernel_real_parent_intervals` | `KernelRealParentIntervalKeyV1` → `KernelRealParentIntervalV1` | None | Birth, refresh, exec, exit, iterator | Identity, effect, inspector | Pin-root lifetime; interval and exit cleanup |
| `created_by_edges` | `u64 task_cookie` → `CreatedByEdgeV1` | None | Root and native birth | Identity and inspector | Pin-root lifetime; immutable creator proof until cleanup |
| `process_states` | `Id128V1` → `ProcessSecurityStateV1` | None | Root, native, exec, exit | Lifecycle, exec, effect, inspector | Pin-root lifetime; reference-owned process lifetime |
| `process_state_vectors` | `Id128V1` → `ProcessStateVectorV1` | None | Root, native, exec, exit | Lifecycle, exec, effect, inspector | Pin-root lifetime; process-state lifetime |
| `profile_generation_task_refs` | `u64 generation_ref` → `u64 count` | Binding owner creates zero row | Birth and exit change count atomically | Lifecycle, effect, binding recovery | Pin-root lifetime; retained while bindings or tasks refer to the generation |
| `entry_states` | `Id128V1` → `EntrySecurityStateV1` | None | Root, native, exec, exit | Lifecycle, exec, effect, inspector | Pin-root lifetime; entry reference lifetime |
| `authority_domains` | `Id128V1` → `AuthorityDomainStateV1` | None | Root, native, exec, exit | Lifecycle, exec, effect, inspector | Pin-root lifetime; native-family reference lifetime |
| `execution_set_bindings` | `u64 cgroup_id` → `ExecutionSetBindingStateV1` | `WorkloadBindingOwner` | Initial-root consume; cgroup release tombstones | Lifecycle, exec, effect, binding recovery | Pin-root lifetime; userspace terminates or BPF tombstones a dead cgroup |
| `external_root_classifications` | `u64 task_cookie` → `ExternalRootClassificationV1` | None | Root publication and rollback | Exec, exit, inspector | Pin-root lifetime; root task lifetime |
| `pending_execs` | `u64 task_cookie` → `PendingExecV1` | None | Exec syscall and BPRM transaction | Exec and effect families | Pin-root lifetime; one in-flight exec transaction |
| `image_provenance` | `Id128V1` → `ImageProvenanceV1` | None | Root and exec commit/rollback | Exec, effect, exit, inspector | Pin-root lifetime; execution reference lifetime |
| `process_execution_instances` | `Id128V1` → `ProcessExecutionInstanceV1` | None | Root and exec commit/rollback | Exec, effect, exit, inspector | Pin-root lifetime; execution reference lifetime |
| `approved_exec_slots` | `ApprovedExecSlotKeyV1` → `ApprovedExecSlotV1` | `AuthorizationProofOwner` | Exec path changes or consumes a matching slot | Authorization owner and exec path | Pin-root lifetime; one approved slot lifetime |
| `approved_exec_arguments` | `ApprovedExecArgumentKeyV1` → `u8` | `AuthorizationProofOwner` | None | Authorization owner and exec argument matcher | Pin-root lifetime; removed with its slot |
| `pending_administrative_matches` | `u64 task_cookie` → `PendingAdministrativeMatchV1` | None | Exec entry, BPRM, completion, and exit | Exec path | Pin-root lifetime; one in-flight administrative match |
| `task_reference_tombstones` | `u64 task_cookie` → `TaskReferenceTombstoneV1` | None | Birth, rollback, and exit | Exit and reconciliation | Pin-root lifetime; used once for exact reference release |
| `profile_generation_descriptors` | `u64 generation_ref` → `ProfileGenerationDescriptorV1` | `NodePolicyGenerationOwner` | None | Effect gate and recovery | Pin-root lifetime; immutable active generation until policy cleanup |
| `active_profile_generations` | `Id128V1 profile_id` → `u64 generation_ref` | `NodePolicyGenerationOwner` | None | Binding activation and new-root generation admission | Pin-root lifetime; one future-root handle for one profile |
| `binding_activation_targets` | `BindingActivationTargetKeyV1` → `ExecutionSetBindingStateV1` | `NodePolicyGenerationOwner` | None | New-root generation admission | Pin-root lifetime; immutable target row for a binding and generation |
| `effect_decisions` | `EffectDecisionKeyV1` → `PhysicalDecisionV1` | `NodePolicyGenerationOwner` | None | Effect gate | Pin-root lifetime; generation lifetime |
| `effect_defaults` | `EffectDefaultKeyV1` → `PhysicalDecisionV1` | `NodePolicyGenerationOwner` | None | Effect gate | Pin-root lifetime; generation lifetime |
| `ipc_relationship_decisions` | `IpcRelationshipDecisionKeyV1` → `PhysicalDecisionV1` | `NodePolicyGenerationOwner` | None | Unix-stream connect/send/receive gates | Pin-root lifetime; generation lifetime; exact relationship rows plus one unmatched row per role and operation |
| `ipc_socket_states` | socket-storage kernel key → `IpcSocketStateV1` | None | Socket creation and Unix-stream connection paths | Unix-stream connect/send/receive gates | Map has pin-root lifetime; each value has socket lifetime |
| `device_effect_decisions` | `DeviceEffectKeyV1` → `PhysicalDecisionV1` | `NodePolicyGenerationOwner` | None | Device ioctl gate | Pin-root lifetime; generation and exact device-object lifetime |
| `process_control_rules` | `ProcessControlRuleKeyV1` → `PhysicalDecisionV1` | `NodePolicyGenerationOwner` | None | Ptrace and signal gates | Pin-root lifetime; generation lifetime; exact target role and operation argument; generic rows are denial-only |
| `exception_handle_bindings` | `ExceptionHandleBindingKeyV1` → `ExceptionHandleBindingV1` | `NodePolicyGenerationOwner` | None | Common effect gate, exec administrative match, authorization owner | Pin-root lifetime; generation handle to stable exception instance |
| `exception_runtime_states` | `ExceptionRuntimeStateKeyV1` → `ExceptionRuntimeStateV1` compatible BPF lock wrapper | `NodePolicyGenerationOwner` with `ExceptionAuthorityOwner` | Effect or administrative exec consumes, expires, and exhausts under spin lock | Exception reconciliation and BPF consumption | Pin-root lifetime plus WAL recovery; mutable stable exception instance |
| `exception_use_receipts` | `ExceptionUseReceiptKeyV1` → `ExceptionUseReceiptV1` | `ExceptionAuthorityOwner` restores durable consumed receipts | BPF inserts `CLAIMING`, changes it to `CONSUMED`, or removes a denied claim | Exception reconciliation and BPF retry | Pin-root lifetime; successful receipts also have WAL lifetime |
| `task_effect_attempt_states` | task-storage kernel key → `TaskEffectAttemptStateV1` | None | Raw syscall entry starts state; `file_open` creates and returns one frame; raw syscall exit and task exit close frames | BPF exception consumption | Map has pin-root lifetime; each value has task lifetime |
| `exact_file_objects` | `ExactFileObjectKeyV1` → `ExactObjectBindingV1` | `NodePolicyGenerationOwner` | None | Common effect and device gates | Pin-root lifetime; generation and mount-view validity limit use |
| `mount_security_views` | `u32 mount_namespace_inode` → `MountSecurityViewStateV1` | `NodePolicyGenerationOwner` | Mount hooks dirty and advance the view; file gate can commit reconciliation | Policy owner, mount hooks, path gate | Pin-root lifetime; namespace view lifetime |
| `mount_security_view_locks` | `u32 mount_namespace_inode` → BPF spin lock | `NodePolicyGenerationOwner` creates row | LSM mount and path programs lock the row | LSM mount and path programs | Pin-root lifetime; namespace view lifetime |
| `mount_reconciliation_proposals` | `u32 mount_namespace_inode` → `MountReconciliationProposalV1` | `NodePolicyGenerationOwner` | File gate consumes a matching proposal | Policy owner and file gate | Pin-root lifetime; one exact epoch/version proposal |
| `mount_mutation_epochs` | `u32 mount_namespace_inode` → `u64` | `NodePolicyGenerationOwner` initializes row | Mount paths advance epoch atomically | Policy owner, mount path, file path | Pin-root lifetime; namespace view lifetime |
| `canonical_mount_roots` | `CanonicalMountRootKeyV1` → `CanonicalMountRootV1` | `NodePolicyGenerationOwner` | None | Canonical path engine | Pin-root lifetime; active generation and represented view lifetime |
| `path_graph_exact_transitions` | `PathGraphTransitionKeyV1` → `PathGraphTransitionV1` | `NodePolicyGenerationOwner` | None | Canonical path engine | Pin-root lifetime; active generation lifetime |
| `path_graph_wildcard_transitions` | `PathGraphStateKeyV1` → `PathGraphTransitionV1` | `NodePolicyGenerationOwner` | None | Canonical path engine | Pin-root lifetime; active generation lifetime |
| `path_graph_terminals` | `PathGraphStateKeyV1` → `PathGraphTerminalV1` | `NodePolicyGenerationOwner` | None | Canonical path engine | Pin-root lifetime; active generation lifetime |
| `mount_mutation_attempts` | task-storage kernel key → `MountMutationAttemptV1` | None | Mount LSM entry and syscall-exit completion | Mount completion | Map has pin-root lifetime; each value has task or syscall-attempt lifetime |
| `effect_observations` | no key → `EffectObservationV1` ring records | None | Effect gate after it fixes the physical result | One `EffectObservationReader` | Pin-root lifetime; a full ring rejects a new reservation and increments the loss counter |
| `effect_observation_health` | per-CPU `u32` → `EffectObservationHealthV1` | None | Effect emission path | Runtime observation health | Pin-root lifetime; counters are per CPU |

`identity_scratch` is not a per-task cache. Linux keeps one BPF invocation on
one CPU, so another CPU does not write that invocation's per-CPU slot. The
program copies every durable result into task storage or another map before it
returns. The next hook on that CPU can overwrite the complete scratch value.
Reviewers must reject any change that keeps a scratch pointer or assumes that
scratch content belongs to the same task across two hooks. A helper path that
can re-enter the same scratch-using program would also need a separate proof;
the per-CPU map alone is not a re-entry lock.

The rest of this section gives the map-fill order for review.

### Binding publication

```mermaid
sequenceDiagram
    participant W as WorkloadBindingOwner
    participant H as KernelHost map API
    participant M as execution_set_bindings
    participant B as BPF lifecycle/effect hook

    W->>W: canonicalize cgroup path and keep opened handle
    W->>W: verify cgroup dev/inode lifetime and non-overlap
    W->>H: write binding lifecycle PREPARING
    H->>M: update key = root cgroup ID
    W->>H: exact readback
    W->>H: ensure profile_generation_task_refs[generation] = 0
    W->>H: write binding lifecycle ACTIVE, version + 1
    W->>H: exact readback
    B->>M: bounded live cgroup ancestry lookup, maximum 64 steps
```

The concrete writes are in
[`WorkloadBindingOwner::publish_all`](../../../crates/mithril-node/src/identity/binding.rs#L106-L265).
[`prepare`](../../../crates/mithril-node/src/identity/binding.rs#L521) opens and
validates the live cgroup once before publication. `publish_all` does not repeat
that immediate validation. The later check in
[`activate_configured_profiles`](../../../crates/mithril-node/src/identity/binding.rs#L256)
is a time-of-use check after policy publication. Periodic reconciliation also
checks that the opened cgroup identity is still live. Those later checks cover
state changes across transactions; they are not duplicate parsing inside one
preparation call.
For a configured runtime socket, the same owner reconciles a CRI inventory;
it still publishes exactly the same binding record rather than loading another
BPF program.

### Signed generation publication

```mermaid
sequenceDiagram
    participant A as signed artifact
    participant N as NodePolicyGenerationOwner
    participant R as anti-rollback store
    participant H as KernelHost map API
    participant M as policy maps
    participant G as BPF effect gate

    A->>N: candidate path and public key from node config
    N->>N: verify signature, validity, source/compiled binding
    N->>R: validate candidate and record monotonic high-water state
    N->>H: descriptor = PREPARING
    loop every decision/default/device/process/IPC/object/graph row
        N->>H: write row
        N->>H: read exact row back
    end
    N->>H: restore receipts and write/read exception state and bindings
    N->>H: write/read mutable mount rows
    N->>H: set descriptor to READ_BACK, then read it back
    N->>H: set descriptor to ACTIVE, then read it back
    N->>H: stage immutable binding-and-generation target rows
    N->>R: persist a pending activation after target readback
    N->>H: publish profile ID -> active generation, then read it back
    N->>R: finalize pending activation and consume a rollback proof, if used
    G->>M: use rows only after matching ACTIVE descriptor
```

[`LoweredGeneration::install`](../../../crates/mithril-node/src/policy.rs#L1052)
contains the row sequence. [`reconcile_pending_activations`](../../../crates/mithril-node/src/policy.rs#L1204)
compares a durable pending activation with the active profile pointer and the
descriptor digest after restart. A failed pre-commit stage leaves the prior
pointer active. A successful pointer update is the commit point. A readback
failure after that update closes readiness and retains the committed state for
recovery. The code does not roll the pointer back after the commit point.

The active-generation switch starts at
[`activate_profile`](../../../crates/mithril-node/src/policy.rs#L1326).
It stages immutable target rows in `binding_activation_targets`, checks the
old pointer again, and updates one profile-keyed pointer. It is a serialized
userspace transaction under the exclusive pin-root owner. It is not a
multiwriter kernel compare-and-swap transaction.

`active_profile_generations` selects the generation for future roots.
`binding_activation_targets` supplies the staged binding state for that
generation. Existing tasks keep the generation already stored in
`ProcessSecurityStateV1`. This avoids a mid-execution global policy change.
Generation retirement and removal after all typed references reach zero are
not implemented. A durable monotonic node generation-handle allocator and
ahead-of-write map-capacity proof are also not implemented.

### Bounded exception consumption and WAL recovery

```mermaid
sequenceDiagram
    participant P as NodePolicyGenerationOwner
    participant W as ExceptionAuthorityOwner and WAL
    participant M as exception maps
    participant B as BPF effect or admin exec

    P->>W: load exception-authority-v1.jsonl
    W->>W: reject a torn record or invalid transition
    W->>M: restore each durable CONSUMED receipt with BPF_NOEXIST
    P->>W: prepare stable node/exception instance state
    W->>M: install handle binding and runtime state
    B->>M: derive claim-slot or file-open attempt receipt key
    B->>M: insert CLAIMING receipt with BPF_NOEXIST
    B->>M: lock runtime state
    B->>M: validate binding, deadline, state, and maximum uses
    alt one use remains
        B->>M: increment consumed uses and mark receipt CONSUMED
        B-->>B: allow this matched exception use
    else expired, exhausted, or corrupt
        B->>M: retain restrictive state and delete denied receipt
        B-->>B: deny
    end
    P->>W: periodic reconciliation reads locked runtime and receipt maps
    W->>W: append JSON record, newline, fsync file, fsync new parent
```

Read the kernel algorithm at
[`consume_bounded_exception`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L584)
and the durable owner at
[`ExceptionAuthorityOwner::load`](../../../crates/mithril-node/src/policy/exception_authority.rs#L95),
[`restore_receipts`](../../../crates/mithril-node/src/policy/exception_authority.rs#L226),
and [`reconcile`](../../../crates/mithril-node/src/policy/exception_authority.rs#L272).
The WAL append starts at
[`append`](../../../crates/mithril-node/src/policy/exception_authority.rs#L434).
An append failure poisons the owner. A restart on the same boot trusts a live
pinned counter after it checks the durable predecessor. A missing live counter
or a boot change conservatively exhausts any remaining uses. The total reserved
maximum uses cannot exceed the 65,536 receipt-map capacity.

The kernel-effect identity is currently limited to synchronous `lsm/file_open`
read and write decisions. The raw syscall hook starts the task state. The
file-open gate allocates a fresh frame. The gate closes that frame after its
decision. A nested or malformed stack fails closed. `file_receive` passes no
exception handle. General VFS retry correlation and asynchronous or offloaded
io_uring identity are not implemented.

This is a local restart-safe exception owner. It is not complete online
administrative approval. `AuthorizationProofOwner` can verify and arm an exact
slot when called, and the BPF exec path can consume that slot. `NodeChassis`
does not connect this owner to a production Control request. The WAL is also
reconciled on startup and the periodic node reconciliation interval, not
synchronously after every permitted effect.

### Identity birth and use

```mermaid
sequenceDiagram
    participant T as creator task
    participant A as lsm/task_alloc
    participant C as cgroup_attach_task
    participant W as wake_up_new_task
    participant E as later effect hook
    participant M as identity maps

    T->>A: clone/fork/thread allocation request
    A->>M: read creator label and creator cgroup binding
    alt labelled valid creator
        A->>M: construct/publish child task/process state
    else unlabelled creator already in protected binding
        A->>M: publish an external root for the creator
        A->>M: construct/publish child task/process state
    else unlabelled creator outside binding
        A-->>T: do not label here
    end
    C->>M: classify an unlabelled task after Linux supplies a protected target cgroup
    W->>M: classify an unlabelled pre-wake root or finalize a labelled coordinate
    E->>M: classify a remaining unlabelled bound root before its first allowed effect
    E->>M: require label, current binding, and current process state
```

`task_alloc` never guesses the new child's future cgroup. It reads the current
creator's live cgroup. If that unlabelled creator is already in a protected
binding, the hook publishes an external root for the creator and then publishes
the child as a native descendant. The cgroup-attach hook remains the primary
path when Linux supplies a target protected cgroup. The wake hook and the
first-effect front are conservative fallbacks for runtime creation orders that
do not expose a usable attach event before the task enters the protected
cgroup.

### Exec and administrative-match transaction

```mermaid
sequenceDiagram
    participant U as execve or execveat caller
    participant S as syscall-entry tracepoint
    participant B as bprm_check_security
    participant C as committing-creds fentry
    participant X as syscall-exit or sched-exec tracepoint
    participant M as exec and identity maps

    U->>S: executable, ordered argv, and execveat flags
    alt AT_EXECVE_CHECK
        S->>M: mark a check-only request
    else exact administrative candidate
        S->>M: match the preinstalled argument keys in order
        S->>M: publish a pending administrative match
    end
    U->>B: Linux presents the first executable candidate
    B->>M: create pending exec state and add the candidate
    B->>M: validate and consume an administrative slot, if one matched
    U->>B: Linux presents an interpreter or auxiliary candidate
    B->>M: append the candidate, up to the fixed limit
    U->>C: Linux reaches the credential-commit boundary
    C->>M: create preparing image and execution records
    alt exec fails before the commit boundary
        X->>M: restore the old active state and delete pending state
    else failure after the commit boundary
        X->>M: retain restrictions and mark the outcome unknown
    else Linux reports exec success
        X->>M: activate the new image, execution, role, and entry state
    end
```

The administrative argument matcher starts at
[`administrative_argv_matches`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L207).
It accepts at most 256 arguments and 4,096 argument bytes in total. It does not
sort, normalize, or hash the arguments. It checks the exact argument count,
argument order, length, bytes, and final null pointer. Userspace first installs
one map key for each argument in
[`arm_administrative_slot`](../../../crates/mithril-node/src/identity/authorization/mod.rs#L205).
The syscall-entry program then checks those keys without copying a variable
argument vector into one BPF map value. This design keeps the comparison exact
and gives the verifier fixed bounds.

The general transition starts in
[`identity_bprm_transition`](../../../bpf/erebor-interceptor/programs/identity_exec.bpf.h#L424),
not at syscall entry. Linux can call the BPRM hook more than once for one exec,
for example for an interpreter. The pending record therefore stores up to
eight ordered executable candidates. The commit and exit hooks separate a
safe pre-commit rollback from an uncertain post-commit failure. They do not
convert an uncertain result into authority.

### Exact-file decision and observation

```mermaid
sequenceDiagram
    participant L as typed LSM wrapper
    participant G as identity_effect_gate
    participant I as identity/binding maps
    participant P as mount view and path graph
    participant D as decision/exception maps
    participant R as ring buffer
    participant U as one libbpf-rs reader

    L->>G: file/object arguments, operation, prior LSM result
    G->>I: validate current task label, cgroup binding, process/entry/domain
    alt prior LSM denied or identity is broken
        G->>G: keep prior result or hard-deny
    else policy disabled
        G-->>L: return prior success
    else qualified file object
        G->>P: require a CLEAN view, build bounded components, and revalidate the snapshot
        G->>D: exact object then exact/default policy key
        alt OBSERVE deny
            G->>G: result = 0, reason = WOULD_DENY
        else PROTECT deny
            G->>G: result = signed negative errno
        else exception-backed allow
            G->>D: lock/check/increment bounded counter once
        end
    else unsupported protected object
        G->>G: result = hard deny, reason = UNSUPPORTED_OBJECT
    end
    G->>R: best-effort copy after result is fixed
    G-->>L: return fixed result
    U->>R: poll and decode
```

Start at
[`identity_effect_gate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L509).
Then read
[`prepare_effect_identity`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L206)
and
[`resolved_identity_effect_gate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L271).
The wrappers below it deliberately retain visible Linux hook prototypes; they
do not hide unrelated operations behind a macro. Device, process-control, and
IPC wrappers ask the common gate to validate the actor but defer the final
decision to their typed key. A wrapper without a supported typed model uses the
explicit hard-safe result.

### Typed device and process-control decisions

```mermaid
sequenceDiagram
    participant L as ioctl, ptrace, or signal LSM hook
    participant G as common identity gate
    participant T as typed device/process gate
    participant M as exact state and decision maps

    L->>G: prior result and typed operation, defer final decision
    G->>M: validate current actor, binding, process, entry, and generation
    alt device ioctl
        T->>M: require exact file tuple and configured object binding
        T->>M: derive device type, major, minor, and command
        T->>M: lookup exact command, then denial-only command wildcard
    else ptrace or signal
        T->>M: snapshot exact live target label, binding, process, and coordinate
        T->>M: lookup controller role/state -> target role/state -> operation
        T->>M: recheck live target label and both transition versions
    end
    T-->>L: apply signed result or hard-deny missing proof
```

The device gate starts at
[`identity_device_ioctl_gate`](../../../bpf/erebor-interceptor/programs/identity_device_process.bpf.h#L143).
The process gate starts at
[`identity_process_control_gate`](../../../bpf/erebor-interceptor/programs/identity_device_process.bpf.h#L390).
Both wrappers call
[`identity_effect_actor_gate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L525)
first. That call returns before the wrapper calls its typed operation frame.
This sequence keeps the largest BPF call chain below the kernel 512-byte stack
limit. It does not skip actor validation or soften a missing typed decision.
The device model supports an exact configured character or block device and an
exact ioctl command. An explicit wildcard command can deny only. It does not model device acquisition,
derived file descriptors, driver-private subobjects, or later authority
transfer.

The process model supports exact directional `PTRACE_ACCESS_<mode>` and
`SIGNAL_<number>` rows. An allow or alert row requires an exact target role and
exact argument. A generic row can deny only. It does not support
`process_vm_*`,
`/proc/PID/mem`, `pidfd`, `perf`, or another process operation.

### Unix-stream IPC decisions

```mermaid
sequenceDiagram
    participant C as protected socket creator
    participant S as socket-local storage
    participant X as unix_stream_connect
    participant P as peer task/process state
    participant R as relationship decisions

    C->>S: socket_post_create stores endpoint A identity
    X->>S: read client, listener, and accepted-child socket state
    X->>P: validate current client and live listener creator identity
    X->>R: lookup actor role -> peer role -> CONNECT
    alt exact relationship decision
        X-->>C: allow, audit-allow, simulated deny, or deny
    else unmatched policy decision
        X-->>C: allow, audit-allow, simulated deny, or deny
        X->>S: store the connected channel after a successful decision
    end
    C->>S: connected send or receive reads both endpoint identities
    C->>P: revalidate current actor and live peer process/binding/generation
    C->>R: lookup SEND or RECEIVE relationship decision
```

Read socket storage and the connect hook at
[`identity_ipc.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_ipc.bpf.h#L434).
The BPF model is limited to connected AF_UNIX `SOCK_STREAM` connect, send, and
receive. The compiler and node lowerer accept exact relationship allow, alert,
and deny rows; see [`lower_ipc_relationships`](../../../crates/mithril-node/src/policy/ipc.rs#L21).
The lowerer installs both directions for one local-channel relationship and
one unmatched row for each role and operation. Unix datagrams, socket pairs,
SysV IPC, shared memory, and exact pipes are unsupported.
An actor outside the protected scope can use an untracked host socket. It
cannot connect to a listener that has protected socket state or use a connected
socket that has protected channel state. Those cross-boundary cases deny. This
containment rule does not implement listener transfer or grant host authority.
Listener transfer, socket activation, and socket transfer through `SCM_RIGHTS`
are not qualified. The code does not claim that a transferred listener gains
the current holder's positive authority.

### Mount invalidation and reconciliation

```mermaid
sequenceDiagram
    participant A as task in represented mount namespace
    participant L as mount LSM hook
    participant V as namespace view maps
    participant X as syscall exit hook
    participant N as NodePolicyGenerationOwner
    participant F as later exact-file hook

    A->>L: mount, unmount, pivot_root, or move_mount
    alt protected unsupported mutation
        L-->>A: deny before mutation and leave the view unchanged
    else allowed external entrant
        L->>V: increment epoch and pending count, then mark the view DIRTY
        L-->>A: allow Linux mutation
        A->>X: syscall completion
        X->>V: increment version, decrement pending last, and retain the DIRTY state
    end
    N->>V: read epoch/version/pending
    N->>N: prove configured exact object and snapshot still match
    N->>V: write/read root rows and exact reconciliation proposal
    F->>V: under LSM spin lock, CAS matching proposal to CLEAN
    F->>V: only then walk path graph for strict file decision
```

The view key is the mount-namespace inode, not the task cgroup. That prevents a
host task that enters the represented mount namespace from bypassing topology
invalidation merely because it is outside the workload cgroup. The LSM-side
map lock is used only in LSM programs; the tracing exit program uses atomics as
required by the verifier.

## BPF vocabulary needed for review

| Item | Meaning here |
| --- | --- |
| `SEC("...")` | Puts a function in an ELF section. libbpf uses the section to select program type/attach behavior. `SEC("lsm/task_alloc")` is a BPF LSM hook for the kernel `task_alloc` security hook. |
| `BPF_PROG(name, ...)` | libbpf tracing macro that gives C a typed function view of the BPF context while preserving the ABI Linux expects. It is not Rust and does not itself attach a program. |
| `BPF_CORE_READ_INTO` | CO-RE field read: Clang records field relocation information so libbpf can adapt a supported kernel field layout using runtime BTF. |
| `bpf_get_current_task_btf()` | Returns a verifier-trusted pointer to the task that is currently executing the hook. In `task_alloc`, that is the creator, not the half-created `task` argument. |
| `bpf_task_storage_get` | Looks up a BPF task-storage value. Passing flags `0, 0` means lookup only; it does not create a label. |
| `bpf_map_lookup_elem` | Returns a temporary pointer to a map value for this BPF invocation or `NULL`. The verifier prevents retaining it after return. |
| `BPF_NOEXIST` | Map-update mode that fails rather than replacing a key that already exists. Birth code uses it to avoid silently overwriting identity state. |
| `__sync_*` | Clang lowers these operations to BPF atomics. They implement bounded counters/CAS without a userspace lock in the hot path. |
| BPF spin lock | A special lock field recognized from BTF in a map value. It is used only where Linux permits it; it is not interchangeable with an ordinary `u32`. |
| Return `0` from an LSM BPF program | Adds no denial. It does not override another LSM's prior nonzero decision. A negative errno denies the operation. |

## Task allocation: contract before reading the source

The exact function under review is:

```c
SEC("lsm/task_alloc")
int BPF_PROG(erebor_task_alloc, struct task_struct *task,
             unsigned long clone_flags, int ret)
```

It is at
[`identity_lifecycle.bpf.h` line 35](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L35).

Its contract is deliberately narrow:

1. Preserve a denial from an earlier LSM program.
2. Do nothing while Mithril identity is disabled.
3. Read the *creator's* label and the creator's live cgroup binding.
4. If that creator has a valid Mithril label, create a fail-closed native child
   before Linux can run it.
5. If it is unlabelled but is inside a protected binding, publish an external
   root for the creator. Then create the new task as its native child.
6. If it is unlabelled and outside every configured binding, make no identity
   claim. A later cgroup-attach, wake, or first-effect path creates an external
   or initial root after the task has a protected cgroup.

`clone_flags` is the standard Linux UAPI word. The child helper uses standard
`CLONE_THREAD` and `CLONE_PARENT` from
[`linux_uapi.h`](../../../bpf/erebor-interceptor/include/linux_uapi.h), rather
than an invented Mithril clone-flag copy. Threads retain the process-level
identity; a process child receives distinct process/execution identifiers.

### Task allocation line by line

Every physical source line in this function is described below. This includes
the blank separator and braces. A blank line emits no BPF instruction.

| Source line | Exact effect |
| --- | --- |
| [35](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L35) | `SEC("lsm/task_alloc")` puts the next function in the BPF LSM task-allocation section. libbpf uses this section to load and attach the program to the Linux `task_alloc` security hook. |
| [36](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L36) | `BPF_PROG` gives C a typed view of the BPF tracing context. `erebor_task_alloc` is the program name that the loader requires. `task` is the new kernel task. |
| [37](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L37) | `clone_flags` is the Linux clone flag word. `ret` is the result from an earlier LSM program. |
| [38](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L38) | The opening brace starts the program body. No pointer from this body can escape the BPF invocation. |
| [39](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L39) | Declares a pointer to the one runtime configuration value. The program assigns the pointer at line 51. |
| [40](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L40) | Declares a pointer to the current CPU's health counters. Health data reports faults. Health data never grants authority. |
| [41](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L41) | Declares a pointer to the current CPU's scratch value. The program uses this value to construct state before publication. |
| [42](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L42) | Declares a verifier-trusted pointer to the current creator task. |
| [43](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L43) | Declares the creator cgroup pointer and initializes it to `NULL`. This initialization prevents use of an undefined pointer after a failed read. |
| [44](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L44) | Declares the optional creator label from BPF task storage. |
| [45](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L45) | Declares the optional binding found from the creator's live cgroup ancestry. |
| [46](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L46) | Declares the ancestry lookup status. A separate status distinguishes “no binding” from “could not prove the lookup.” |
| [47](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L47) | Declares the child-construction result. Zero means success. A negative errno denies the allocation. |
| [48](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L48) | This blank line separates declarations from executable statements. It emits no BPF instruction. |
| [49](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L49) | Tests the earlier LSM result before Mithril reads or changes state. |
| [50](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L50) | Returns the earlier result unchanged. Mithril cannot mask an earlier denial. |
| [51](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L51) | Looks up array key zero in `identity_config`. The helper returns a temporary map-value pointer or `NULL`. |
| [52](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L52) | Tests for an absent configuration or a disabled identity engine. |
| [53](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L53) | Returns zero while identity is disabled. Zero adds no Mithril denial. Other LSM decisions remain in force. |
| [54](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L54) | Gets this CPU's health record. A failed lookup produces `NULL`. |
| [55](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L55) | Gets this CPU's scratch record. A per-CPU value avoids cross-CPU writers for one invocation. |
| [56](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L56) | Tests the required scratch pointer. |
| [57](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L57) | Denies when scratch is unavailable. `identity_deny` returns the configured negative errno or standard `-EACCES`. |
| [58](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L58) | Calls `bpf_get_current_task_btf()`. The helper returns a BTF-typed, verifier-trusted pointer to the creator that is running this hook. |
| [59](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L59) | Calls `bpf_task_storage_get` for the creator. The zero flags request lookup only. The helper does not create a label. |
| [60](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L60) | Calls `task_cgroup` to read the creator's current default cgroup. The test is for a read failure. |
| [61](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L61) | Tests whether the optional health record exists. |
| [62](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L62) | Counts the cgroup read failure as a placement mismatch. |
| [63](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L63) | Denies because the program cannot prove whether the creator is in a protected cgroup. |
| [64](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L64) | Closes the cgroup-read failure branch. |
| [65](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L65) | Starts the bounded binding lookup from the creator cgroup. |
| [66](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L66) | Passes a status output to the lookup. The returned pointer can be `NULL` after a complete walk outside all configured bindings. |
| [67](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L67) | Tests for an incomplete or invalid ancestry walk. |
| [68](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L68) | Tests whether health counters are available. |
| [69](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L69) | Counts the failed ancestry proof as a placement mismatch. |
| [70](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L70) | Denies rather than treating an incomplete walk as unprotected. |
| [71](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L71) | Closes the failed-binding-lookup branch. |
| [72](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L72) | Selects the established native-child path when the creator already has a label. |
| [73](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L73) | Checks that the creator label has the current node boot ID and label epoch. |
| [74](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L74) | Checks that the live binding has the label's binding ID and nonce and has the `ACTIVE` state. |
| [75](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L75) | Tests whether health counters are available after either identity check fails. |
| [76](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L76) | Counts the stale or misplaced creator identity. |
| [77](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L77) | Denies before the program publishes child state. |
| [78](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L78) | Closes the invalid-established-identity branch. |
| [79](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L79) | Calls the native-child constructor with the new task, trusted creator, Linux clone flags, runtime configuration, creator label, binding, and scratch record. |
| [80](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L80) | Completes the call and stores its result. The helper publishes all required state or rolls back its partial state. |
| [81](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L81) | Starts the path for a creator that has no task-storage label. |
| [82](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L82) | Tests whether the unlabelled creator is already inside a configured protected binding. |
| [83](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L83) | Calls `label_external_root` for the creator. This helper constructs the complete root state, publishes task storage, and finalizes the Linux coordinate. |
| [84](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L84) | Tests whether health counters are available after root publication fails. |
| [85](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L85) | Counts a denied protected creator that still has no usable identity. |
| [86](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L86) | Denies the child allocation. The failed root helper retains no usable partial authority. |
| [87](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L87) | Closes the failed-external-root branch. |
| [88](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L88) | Starts a new lookup of the creator label after root publication. |
| [89](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L89) | Calls `bpf_task_storage_get` again. The returned pointer proves that publication created the task label. |
| [90](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L90) | Tests for an absent label after the root helper reported success. |
| [91](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L91) | Tests whether health counters are available. |
| [92](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L92) | Counts the inconsistent publication as missing identity. |
| [93](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L93) | Denies. The program does not create a child from an unproven creator label. |
| [94](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L94) | Closes the missing-label-after-publication branch. |
| [95](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L95) | Calls the same native-child constructor after external-root publication. |
| [96](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L96) | Passes the new creator label and the existing protected binding. |
| [97](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L97) | Completes the call and stores the result. |
| [98](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L98) | Starts the case for an unlabelled creator outside all configured bindings. |
| [99](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L99) | Returns zero. This hook makes no claim about an unprotected task. |
| [100](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L100) | Closes the no-binding branch. |
| [101](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L101) | Closes the unlabelled-creator branch. |
| [102](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L102) | Tests for a failed native-child constructor and an available health record. |
| [103](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L103) | Counts the child allocation failure. The counter does not change the result. |
| [104](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L104) | Returns zero after complete publication. It returns the constructor's negative errno after a failure. |
| [105](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L105) | Ends the program. The BPF verifier proves that no temporary pointer escapes. |

### The helpers `task_alloc` depends on

The line-by-line table above is the complete hook. These helper groups are the
minimum transitive reading set needed to understand its nontrivial lines.

| Helper | Start | What to verify |
| --- | --- | --- |
| `identity_runtime_config`, `identity_health_record`, `identity_scratch_record` | [`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L407) | All use fixed key zero. Config is authority; health is diagnostic; scratch is temporary. |
| `task_cgroup`, `cgroup_id`, `cgroup_parent`, `binding_for_cgroup` | [`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L476) | CO-RE reads the current default cgroup and walks at most 64 ancestors. It distinguishes a complete no-binding result from an error. |
| `identity_deny` | [`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L566) | `identity_errno` sign-extends the ABI value, bounds it to a legal negative errno for the verifier, and falls back to `-EACCES`. The inline text is BPF instruction assembly. It is not host x86 or Arm assembly. |
| `label_matches_runtime`, `binding_matches_label` | [`identity_maps.h`](../../../bpf/erebor-interceptor/programs/identity_maps.h#L730) | Label boot and epoch checks plus binding ID, nonce, and state checks prevent stale state and cgroup reuse from becoming authority. |
| `label_external_root` | [`identity_lifecycle.bpf.h`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L6) | Uses the shared root constructor and coordinate finalizer. It records allocation or coordinate failure. It returns `-EACCES` when it cannot publish a usable root. |
| `create_native_child` | [`identity_task_helpers.h`](../../../bpf/erebor-interceptor/programs/identity_task_helpers.h#L414) | Validates parent authority, allocates IDs, constructs records in scratch, writes no-replace rows, publishes task storage, and reverses acquired state after a failure. |

### Native child publication order

```mermaid
sequenceDiagram
    participant A as task_alloc
    participant H as create_native_child
    participant M as identity maps
    participant T as task_labels storage

    A->>H: validated creator label, binding, clone flags
    H->>M: validate parent process/vector/entry/domain/execution
    H->>M: allocate opaque task and, for process, process/execution IDs
    H->>M: create execution/vector/process rows with BPF_NOEXIST
    H->>M: increment entry/profile and process/domain references
    H->>M: create creator edge
    H->>T: publish label, coordinate, parent interval and tombstone
    alt all readbacks/promotion succeed
        H->>M: mark process and vector ACTIVE
        H-->>A: 0
    else any step fails
        H->>M: delete only rows/refs acquired on this path
        H-->>A: configured negative errno
    end
```

The helper uses `CLONE_THREAD` only to distinguish a new thread from a new
process. A thread retains the parent process state and increments its thread
reference; a process child receives new process/execution identities and adds a
domain process reference. `CLONE_PARENT` is handled using the kernel's
`real_parent` observation, but does not rewrite the immutable
`CreatedByEdgeV1` proof of the actual creator.

### Root-classification paths

The implementation has four entry points to one root constructor. Each entry
point calls `label_external_root`. That helper calls
[`create_external_root`](../../../bpf/erebor-interceptor/programs/identity_root_helpers.h#L264)
and then calls
[`finalize_task_coordinate`](../../../bpf/erebor-interceptor/programs/identity_root_helpers.h#L289).

| Entry point | When it runs | Reason for the entry point |
| --- | --- | --- |
| [`erebor_cgroup_attach_task`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L107) | Linux attaches an unlabelled task to a configured cgroup. | This is the primary path because the hook supplies the target cgroup. |
| [`erebor_wake_up_new_task`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L174) | Linux is about to wake a new task. | This handles `CLONE_INTO_CGROUP` orders where the new task is already in the configured cgroup before wake. |
| [`erebor_task_alloc`](../../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h#L35) | An unlabelled creator already in a configured binding creates a child. | This makes the creator an external root before the program derives a native child from it. |
| [`prepare_effect_identity`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L206) | An unlabelled task in a configured cgroup reaches its first allowed LSM effect. | This is the last pre-effect safety path for runtime creation orders that do not produce a usable earlier event. |

`consume_initial_root` uses an atomic compare-and-swap. One root can consume an
armed initial-root marker. Later independent roots receive the external,
restricted class. The first-effect front is separate from the resolved effect
gate because the kernel limits the combined BPF call stack to 512 bytes.

## Effect gate and implementation boundary

Read the common gate in this order:

| Source | What happens |
| --- | --- |
| [`begin_effect_observation`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L63) and [`emit_effect_observation`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L73) | Initialize the event and copy it to the ring only after the caller fixes the physical result. A failed reservation cannot change allow or deny. |
| [`effect_base_decision`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L153) | Builds the exact decision key. If no exact object row matches, it builds the finite default key. |
| [`prepare_effect_identity`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L206) | Publishes a missing external-root identity before the first allowed protected effect. |
| [`apply_effect_decision`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L226) | Applies observe or protect mode and consumes only the exception handle on the selected allow row. |
| [`resolved_identity_effect_gate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L271) | Validates current task identity, cgroup binding, coordinate, process, entry, domain, execution, image, process vector, and retained generation reference. |
| [Prior-result and policy checks](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L398) | Preserve an earlier LSM denial. Return after identity checks when effect policy is disabled. Validate an in-flight exec transaction when policy is enabled. |
| [Generation and object selection](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L441) | Require the process's `ACTIVE` generation. Use a no-path default or a live exact file tuple, clean mount view, path graph, and userspace-installed exact object binding. |
| [`identity_effect_gate`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L509) | Clears the typed-defer flag, prepares late identity, and calls the resolved gate. Typed wrappers set the defer flag before their own final key lookup. |

The result rules are:

| Case | Mithril result |
| --- | --- |
| Identity disabled | Return the earlier LSM result. |
| Labelled task with broken binding, coordinate, process, entry, generation, or object proof | Return the earlier denial if one exists. Otherwise return the configured negative errno. |
| Unlabelled task outside all configured bindings | Make no Mithril claim and return the earlier result. |
| Unlabelled task inside a configured binding after late preparation fails | Deny. |
| Effect policy disabled after identity validation | Return the earlier result. |
| Active `OBSERVE` generation and selected deny | Return `0` from Mithril and emit `WOULD_DENY`. |
| Active `PROTECT` generation and selected deny | Return the verified negative errno before the effect. |
| Selected allow without exception | Return `0`. |
| Selected allow with exception | Return `0` only if the exact receipt/counter transaction succeeds. |
| Missing typed rule, dirty view, unresolved object, unsupported object, or corrupt generation | Deny. Observe mode does not soften these integrity failures. |

## Implemented, partial, and unsupported matrix

“Implemented” means that the current source has the required owner and
decision path for the stated narrow surface. “Partial” means that a smaller
safe subset exists. “Unsupported” means that the source rejects, hard-closes,
or has no product path. A physical qualification claim still needs a matching
record for this exact source state.

| Surface | State | Exact current claim | Important limit |
| --- | --- | --- | --- |
| One object, loader, pin recovery, and manifest | Implemented | One `libbpf-cargo` object is embedded and one `libbpf-rs` owner loads, attaches, pins, or recovers it. | Production pins survive process exit by design. The lease does not remove them. |
| Rust/C ABI boundary | Implemented | Rust `repr(C)` is the source. cbindgen checks the snake-case C header. `zerocopy` performs exact-size typed reads and writes. | It is a same-host native-endian ABI, not a network format. |
| Static and CRI-resolved cgroup binding | Partial | One binding row is published after live cgroup and configured container identity checks. CRI snapshots refresh configured container IDs. | A snapshot does not prove every pre-start ordering. The full runtime entry matrix is not qualified. |
| Native task/process identity | Partial | Lifecycle hooks publish task-first identity before protected work and retain restriction on cleanup failure. | The phase failure-injection, reuse, non-leader, ephemeral-container, and non-x86 physical matrix is incomplete. |
| Exec identity transaction | Partial | `execve`, `execveat`, BPRM, commit, failure, success, candidates, and exact ordered argv state exist. | Full immutable image, loader, `binfmt_misc`, content race, VMA, and administrative ingress coverage is incomplete. Arguments are not sorted or normalized. Exact order, count, lengths, and bytes must match. |
| Signed generation installation | Partial | Verified candidates install immutable rows through `PREPARING`, `READ_BACK`, and `ACTIVE`. They stage all live bindings of one profile and commit one profile pointer. Durable pending state recovers an interrupted commit. | Controlled activation probes, generation retirement, a node-local monotonic generation-handle allocator, and ahead-of-write capacity proof are not implemented. Candidates arrive through startup configuration, not the Control stream. |
| Exact file open, permission, receive, and file-backed map | Partial | Uses exact actor state, clean namespace view, bounded component graph, exact kernel object tuple, and exact/default decision. `file_receive` makes a current-recipient access decision before installing an FD. | Current-source physical proof is pending. Rotation, full content race, delegated I/O, overlay copy-up, persistent-file lifetime coverage, and general async acquisition remain incomplete. |
| File mutation | Partial | Existing exact objects can use typed unlink, rmdir, chmod, chown, truncate, link, and rename hooks. Source and destination checks are separate where Linux supplies both. | A new negative dentry has no exact inode object. Create-like operations can hard-close as unresolved. Complete positive create/rename lifecycle policy is not implemented. |
| Exec and executable memory permission | Partial | BPRM, file-backed executable map, file-backed `mprotect`, anonymous executable mapping, and pkey-mprotect use typed or hard-close paths. Positive executable-memory authority requires an exact object. | This is not the complete executable-image, loader, `binfmt_misc`, immutable-content, or VMA-lifetime model. |
| Mount mutation and path reconciliation | Partial | Allowed represented mutations make the namespace view dirty before effect. A matching epoch/version/digest proposal can make it clean. | Propagation, fan-out, automount/referral, idmapped mount, and all namespace races are not qualified. There is no separate `mount_setattr` LSM program in the required set. |
| Exact device ioctl | Partial | Exact configured device tuple, type, major/minor, actor state, and exact command select a decision. Command wildcard rows can deny only. | Device acquisition, derived descriptors, driver subobjects, and authority transfer are not modeled. |
| Ptrace and signal | Partial | The BPF path snapshots exact controller and target state, then revalidates live target and transition versions. Source policy accepts an exact target role and exact signal or ptrace-access argument. | Current physical proof is limited. `process_vm_*`, `/proc/PID/mem`, `pidfd`, perf, and other process-control operations are unsupported. |
| Connected Unix stream | Partial | Socket storage tracks endpoint identity. Connect/send/receive validate current actor, live peer, binding, generation, role, and direction. Exact relationships can allow, alert, or deny. | Current-source physical proof is pending. Datagram, socketpair, SysV IPC, shared memory, pipe pairing, listener transfer, socket activation, and listener/socket transfer through `SCM_RIGHTS` are unsupported or unqualified. |
| Bounded exception counter and receipt | Partial | BPF uses a stable instance key, no-replace receipt claim, spin-locked count, expiry, and one-use identity for synchronous file-open decisions. Userspace persists monotonic state and consumed receipts in a local WAL. | General VFS retry correlation and asynchronous or offloaded request identity are not implemented. Reconciliation is periodic. Online administrative delivery is not wired. |
| Administrative exec identity | Partial library and BPF path | The owner verifies a signed exact target, durable replay state, exact executable tuple, exact ordered argv, deadline, slot, and exception binding. The BPF path can consume a matching slot. | `NodeChassis` does not call this owner from a Control request. There is no complete production approval-to-task ingress. |
| Hugging Face local incident classification | Partial source classification | The bundle records a checked deployment digest and static classifications for HF-002 through HF-012. The declared classification is not per-branch physical proof. | A case result must come from that branch and its paired control before it can claim prevention. Network, provider, Kubernetes semantics, resident memory, and trusted content provenance remain outside the current claim. |
| Capability and BPF hooks | Partial safety floor | Protected requests use a typed default or hard-safe result before the operation. Generic CAPABILITY, BPF, NETWORK, MOUNT, and unqualified executable-memory positive defaults are rejected at compilation. | This is not complete credential, namespace, keyring, module, perf, io_uring, or self-protection policy. |
| Self-protection | Partial detection and safety floor | The loader verifies live map, link, and program IDs. A managed task that unlinks one pinned-link pathname hard-closes. | This is not host-root tamper prevention. It does not protect all maps, links, config, binary, process, or update paths. |
| Local network policy | Unsupported | Non-Unix-stream protected socket activity does not gain positive local authority. | Destination-aware network policy belongs to later work. |
| Landlock target-context floor | Implemented as absent | Capability registration reports `LANDLOCK_TARGET_CONTEXT_FLOOR=ABSENT` with reason `NO_QUALIFIED_TARGET_CONTEXT_INSTALL`. | This is the complete D4.7 result for this platform path. It provides no Landlock enforcement and does not weaken the BPF decision. |
| Dynamic Control policy/binding/admin delivery | Unsupported | The stream registers, receives trust, reports readiness, and reconnects. | A later Control message is currently an error. Startup configuration and local CRI reconciliation own current state. |

## Review checklist

Use this checklist against a change to the current implementation.

1. Is there still one `KernelHost`, one exclusive pin-root lease, and one
   production object for a node pin root?
2. Does the opened object contain the exact 50-program set? Does the attached
   manifest contain the exact 49 persistent programs, with only the iterator
   excluded?
3. Is BPF still built by `libbpf-cargo` at build time and loaded by
   `libbpf-rs` at runtime, with no per-container compiler or program load?
4. Does each userspace map update have one domain owner and a readback at a
   decision-critical publication boundary?
5. Does task identity remain BPF-native and unavailable for protected work
   when birth, coordinate, or reference publication is incomplete?
6. Does a cgroup binding still prove the opened live cgroup identity, nonce,
   lifecycle, container generation, and configured profile?
7. Does `task_alloc` preserve prior LSM denial, validate the creator, and use
   the creator's live protected binding before it derives a native child?
8. Does rollback release only state acquired by that transaction? Does a
   failed decrement retain restriction and raise reconciliation health?
9. Are all immutable generation rows read back before the descriptor becomes
   `ACTIVE`? Does activation stage every profile binding target before it
   publishes one profile-keyed pointer? Does durable pending state recover the
   pointer outcome?
10. Do existing tasks keep their stored generation while only future roots use
    a new active handle?
11. Does an exact file decision include mount namespace, unique mount ID,
    device, inode, inode generation, represented path graph, and active
    generation?
12. Does an allowed mount mutation make the namespace view dirty before Linux
    mutates it? Can only an exact epoch/version proposal make it clean?
13. Does a device decision include the exact file tuple, device identity, actor
    state, and ioctl command? Can a wildcard command only deny?
14. Does a process-control decision snapshot and recheck the exact live target?
    Do positive rows require an exact target role and operation argument?
15. Does a Unix-stream decision validate both endpoint lifetimes and direction?
    Do exact relationship rows stay generation-scoped? Do unmatched rows remain
    distinct from an exact peer relationship?
16. Does each synchronous `file_open` exception use get a new stable receipt
    identity? Does successful consumption become durable without refund after
    restart or boot change? Does `file_receive` remain exception-disabled?
17. Is the physical result fixed before ring reservation, so observation loss
    cannot alter allow or deny?
18. Does a capability claim distinguish typed positive policy, exact denial,
    hard-close safety, and unsupported behavior?

### Hugging Face local branch classification

The result bundle contains one explicit static local branch table at
[`hf_static_effect_classification`](../../../crates/mithril-e2e/src/effect.rs#L198).
The table does not turn an incident name into physical proof. Each row records
the declared boundary or why no local claim is valid.

| Result | Meaning in the bundle | Current examples |
| --- | --- | --- |
| `LOCAL_PREVENTION_PROBE` | The current generic physical fixture has a related local boundary. The branch table does not assert that this branch ran. | HF-002 helper, HF-003 copied executable, HF-006 later file boundary, HF-008 forbidden object, HF-009 protected read, and HF-010 later helper. |
| `HARD_CLOSE_PROBE` | The current generic physical fixture has a related hard-close boundary. The branch table does not assert that this branch ran. | HF-002 managed `/proc` object. |
| `NO_COVERED_EFFECT` | The action did not cross a new modeled kernel boundary. Mithril makes no prevention claim. | Resident environment or token bytes, pure memory packing, and a pure in-process expression. |
| `OUTSIDE_AUTHORITY` | The actor was not a managed Linux task on the node. | External reconnaissance, staging, search, and send branches. |
| `DEFERRED_NETWORK` | The branch needs destination-aware network or provider authority. | Capture, public service, publication, opaque TLS, API, and instance-metadata branches. |
| `UNSUPPORTED` | The required local semantic owner does not exist. | Trusted staged-content provenance, upload gate, rotating projected token with controller-role control, and Kubernetes or cloud semantic operations. |

The runner reads the checked deployment fixture digest before it starts the
production object. It performs generic exact-file, exec, benign-control, and
hard-close oracles. It writes the digest and static classifications into
[`EffectPhysicalProbeBundleV1`](../../../crates/mithril-e2e/src/effect.rs#L117).
The source test checks coverage and prevents a static no-effect, external,
deferred, or unsupported branch from becoming a physical prevention claim.
This source test does not replace a branch-specific privileged run.

## Automated VM and k3s qualification lane

The repository-owned harness starts at
[`harness/vm/run.sh`](../../../crates/mithril-e2e/harness/vm/run.sh#L1).
It keeps configuration next to the runner:
[`cloud-init-v1.yaml`](../../../crates/mithril-e2e/harness/vm/cloud-init-v1.yaml),
[`k3s-config-v1.yaml`](../../../crates/mithril-e2e/harness/vm/k3s-config-v1.yaml),
and [`k3s-workload-v1.yaml`](../../../crates/mithril-e2e/harness/vm/k3s-workload-v1.yaml).
The default provider is
[`providers/libvirt.sh`](../../../crates/mithril-e2e/harness/vm/providers/libvirt.sh#L1).

```mermaid
sequenceDiagram
    participant H as host run.sh
    participant P as provider adapter
    participant V as disposable VM
    participant K as optional k3s lane
    participant E as evidence directory

    H->>H: build locked identity, effect, qualifier, and inspector binaries
    H->>H: build one qualification BPF object
    H->>P: create and wait for guest
    P->>V: checked cloud-init and verified Ubuntu image
    H->>V: copy binaries, object, fixtures, and guest script
    V->>V: require BTF, cgroup v2, bpffs, BPF LSM, unique mount ID, inode generation
    opt --with-k3s
        H->>K: install fixed k3s version with checked config
        K->>K: ready node, CRI, Pod, kubectl exec, exact ID/digest, overlay, token
        K->>K: run the declared CRI-bound local effect probe
        K->>K: remove test namespace
    end
    V->>V: run kernel, identity, observe, and protect probes as root
    V-->>E: copy JSON evidence and optional k3s record
    H->>V: assert pin, cgroup, and lease cleanup
    opt k3s installed
        H->>K: run official uninstall owner and verify removal
    end
    H->>P: destroy guest on success or failure
```

The provider contract has six operations: `create`, `wait`, `put`, `get`,
`run`, and `destroy`. A cloud adapter can implement those operations without a
change to the probe flow. Provider credentials, network ownership, and cleanup
must stay in the provider.

The optional k3s lane is a narrow CRI effect probe. The guest helper at
[`guest.sh`](../../../crates/mithril-e2e/harness/vm/guest.sh) installs a fixed
k3s version. It proves a ready node, working CRI, `kubectl exec`, an exact
container ID and image digest, an overlay root, and a projected token. It also
uses the discovered Pod task and a checked host-path fixture to configure a
real local Mithril binding. The inspected `kubectl exec` shell performs a
baseline read and then a protected read. The protected read must return
`EACCES` and emit the matching exact-file decision for the same task.

This lane does not prove Kubernetes admission, an API-server authorization
webhook, administrative approval, multi-node propagation, release packaging,
or a cloud platform. The host-path fixture is an exact-file qualification
input. It does not prove projected-token rotation semantics.

The current provider and checked qualification record lane are x86-64. The BPF
translation unit also compiles against checked x86, arm64, arm, and RISC-V
headers. A cross-architecture compile is not a non-x86 physical result.

## Evidence and remaining limits

The prior VM records use an older BPF object. They remain historical evidence.
They do not qualify the current 50-program, 46-map object. The current source
has passed focused ABI, interceptor, node, effect, compiler, formatting, and
checked-header BPF compilation tests. A Linux 6.8 VM also loaded the current
object past `erebor_bprm_check_security` after the stack fix. The current VM
and k3s result records are pending at the time of this review.

| Evidence class | Current status |
| --- | --- |
| BPF program and map inventory | Source tests require 50 production programs, 36 qualification programs, and 46 maps. The task iterator is the one non-persistent production program. |
| BPF verifier | A live Ubuntu 24.04 Linux 6.8 guest loaded the current object after the receipt-key scratch change reduced the critical call chain from 544 bytes to 448 bytes. The full probe result is pending. |
| Cross-architecture source compatibility | Production and qualification objects compile against the checked x86, arm64, arm, and RISC-V `vmlinux` headers. This is not non-x86 physical evidence. |
| Exception attempt identity | ABI, interceptor, node-authority, and compiler tests cover the bounded file-open frame protocol. A current physical max-use record is still required. |
| Exact file receive | E2E source tests cover denied and allowed receipt of a file descriptor over a qualified Unix stream. A current physical VM record is still required. |
| Exact Unix-stream relationship | Compiler, lowering, BPF-source, and E2E fixture tests cover exact allow, alert, deny, stale-peer, and unmatched cases. A current physical VM record is still required. |
| CRI effect | The harness owns a declared k3s CRI effect lane. A current result is pending. The lane does not prove Kubernetes admission or a distributed decision. |
| Hugging Face table | The bundle serializes static source classification. It is not branch-specific physical prevention evidence. |

The historical feasibility and effect distributions remain attached to their
older records. They do not cover this source state. A new record must contain
the platform, object digest, raw samples, latency distribution, capacity,
cleanup result, and the exact current probe outcomes.

### Remaining implementation work

- Add controlled activation probes before a future-root generation pointer
  changes. The present transaction stages and commits atomically for one
  profile, but it has no isolated allow and deny probe.
- Add typed-reference retention, a grace protocol, and a deletion owner before
  any generation retirement. The task reference counter alone is not enough.
- Add a durable monotonic node generation-handle allocator and capacity
  preflight. The current write path fails closed when a map is full.
- Add immutable executable-content, loader, interpreter, `binfmt_misc`, and
  full virtual-memory-area provenance before making a complete exec claim.
- Add projected-token semantic rotation, overlay copy-up, persistent file and
  VMA lifetimes, delegated I/O, and complete file-acquisition provenance.
- Add the `mount_setattr` invalidation path, propagation affected-set handling,
  automount/referral treatment, and idmapped/overlay topology proof before
  making a complete mount claim.
- Add listener transfer, socket activation, socketpair, datagram, pipe,
  shared-memory, asynchronous, and zero-copy IPC models before making a
  complete IPC claim.
- Add derived-device, capability-number, credential, namespace, process-vm,
  pidfd, perf, module, keyring, and io_uring authority models. The present
  compiler gates only prevent broad positive wildcard authority.
- Add host-root-resistant protection for pins, maps, links, config, binaries,
  processes, and update paths. Current map and link identity checks detect
  some tampering after reconciliation. They do not prevent it.
- Add a branch-specific Hugging Face fixture and a paired legitimate control
  for every branch that claims physical prevention.

### Architecture and product decisions required

The following work cannot be completed safely by choosing defaults in code.
The product must make these decisions first.

| Decision | Why the decision is required | Minimum approved outcome |
| --- | --- | --- |
| Administrative approval authority | The current node library can verify and arm a slot. It has no authenticated requester, approver, issuer, or Control-to-node transaction. | Select the human identity provider flow, requester and approver policy, signer and audience, one-use credential format, expiry, and audit owner. |
| Kubernetes administrative-exec boundary | A plugin or a node slot alone cannot prove that the Kubernetes request, Pod, container, stream flags, and target task are one request. | Select the AdmissionReview and authentication-webhook design, TokenReview or equivalent validation, SubjectAccessReview policy, `PodExecOptions` checks, TLS/RBAC deployment, and exact consume point. |
| Control transport and operator delivery | The current stream accepts registration, trust, and readiness only. It cannot route a resolve, arm, or cancel request. | Define typed Control messages, correlated replies, node addressing, retry and cancellation rules, and the `kubectl-mithril` owner and package. |
| Generation retirement | Deleting a generation needs proof that no task, socket, file, VMA, receipt, WAL record, or future-root target can still reference it. | Define the complete reference set, retention interval, grace proof, restart rule, and one deletion owner. |
| General request identity | A receipt must identify a logical effect when work retries, fans out, or moves to another task. The current frame model covers only synchronous file-open decisions. | Define request, object, hook, and executor identity for VFS retry, io_uring, AIO, and other asynchronous work. Keep unsupported paths denied until then. |
| Mount and topology semantics | Linux has no current mount-specific pre-effect hook for every requested operation. Propagation can change more than one namespace. | Select an accepted invalidation source, affected-namespace model, overflow rule, and reconciliation proof before making a complete mount claim. |
| Immutable content and VMA provenance | A pathname and an inode tuple do not prove immutable image bytes, loader state, or mapping lifetime. | Define the trusted content source, loader/interpreter scope, writable history, VMA lifetime owner, and positive-control policy. |
| Root-tamper threat boundary | A same-root host actor can still replace pins or stop processes before periodic detection. | Select the trusted boot, measurement, lifecycle authority, and recovery model before claiming prevention instead of detection. |

Phase 2 remains **Blocked**. Phase 3 remains **Blocked**. Phase 4 remains
**Not done**. Landlock remains complete as the explicit `ABSENT` result. A
hard-close result proves a safety floor for its exact probe. It does not prove
a positive policy model for a larger surface.

This guide covers commit `0c7f3bb8139d878d0214a3a81339c96e218ae4d5` plus the
Mithril working tree on 2026-08-12. It covers the current BPF object SHA-256
stated at the start of this guide. A later source or BPF-object change needs
new source checks and a new privileged record.
