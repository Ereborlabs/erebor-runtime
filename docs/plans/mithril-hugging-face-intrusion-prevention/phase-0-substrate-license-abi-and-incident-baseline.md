# Phase 0: Substrate, License, ABI, And Incident Baseline

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Freeze the buildable kernel/userspace substrate, current-repository module
tree, upstream adoption boundary, supported-platform tiers, incident fixture,
and quantitative budgets before production Mithril code is created.

This phase answers whether Rust plus upstream libbpf can own the complete loader
and whether the selected Linux hooks can prove Mithril's claims. It does not
select a third-party daemon because it is already available in the workspace.

## Current Baseline

- The workspace has no Mithril or shared Linux-sensor crates.
- The repository has no owned BPF source tree.
- Runtime's current Linux process guard uses ptrace and is a separate product
  path.
- The architecture research proposes Rust/libbpf userspace, owned C CO-RE BPF,
  one node gatherer, BPF LSM/cgroup enforcement, exact native identity, and
  Mithril Control.
- Local Tetragon, KubeArmor, Falco, Linux-tooling, and other checkouts are
  research inputs only.
- The incident analysis defines 68 acceptance requirements and three core
  detection packages, but no executable Mithril fixture exists.

## Phase Scope

### Freeze The Proposed Tree And Dependencies

Approve or replace the exact proposed paths in the master README:

```text
bpf/erebor-linux-sensor/
crates/erebor-linux-sensor-abi/
crates/erebor-linux-sensor-host/
crates/mithril-node/
crates/mithril-control/
crates/mithril-e2e/
packaging/mithril/
```

Record the dependency direction:

```text
erebor-linux-sensor-abi
          ▲
          │
erebor-linux-sensor-host
          ▲
          │
      mithril-node ─────────────► mithril-control wire contracts

mithril-e2e may depend on product crates; no production crate depends on e2e.
Runtime may consume ABI/host observation APIs but no Mithril node/control crate.
```

The phase must explicitly resolve the architecture research's open question
about exact crate/module names. Later phase plans are updated if different names
are approved.

### Select And Pin The Toolchain

Record exact versions and reproducible installation/build inputs for:

- `libbpf-rs`;
- `libbpf-cargo`;
- upstream libbpf and the selected license option;
- Clang/LLVM;
- bpftool, if retained;
- Rust toolchain and supported targets;
- BTF generation/source policy;
- C compiler flags and BPF target architectures; and
- generated-skeleton/object provenance.

Build an owned vertical spike through the proposed Rust host crate. It must
compile, load, attach, receive one ring-buffer lifecycle event, run one LSM
allow/deny probe, run one cgroup socket probe, detach, restart, and reconcile
pinned state without an upstream Go or C daemon.

### Freeze The Raw ABI

Create a versioned ABI design before proliferating events:

```text
AbiHeader {
  magic
  abi_major
  abi_minor
  record_kind
  record_size
  source_cpu
  node_boot_hash_or_runtime_binding
  label_epoch
  source_sequence
  monotonic_time_ns
  program_generation
  policy_generation
  flags
}
```

Define:

- fixed-width C/Rust layout and endianness;
- alignment, size and compile-time assertions;
- additive compatibility and major-version rejection;
- redaction rules;
- bounded variable payload rules;
- sequence/loss accounting;
- unknown-record handling;
- skeleton/object-to-ABI digest binding; and
- fuzz inputs for malformed and future records.

No public Mithril product API exposes raw BPF structs.

### Complete The License And Provenance Gate

Inventory every candidate implementation reference from the exact local
revisions already recorded in the architecture research. For each candidate
mechanism classify:

```text
study behavior | reimplement | adapt selected source | reject
```

For every adapted file record:

- repository and immutable revision;
- path, copyright and SPDX;
- complete transitive include closure;
- modification record;
- selected license option;
- notices/source-distribution obligations;
- generated-object provenance; and
- upstream security-update owner.

The default is owned reimplementation. In particular,
`tetragon/bpf/lib` is not treated as libbpf, and repository-level license labels
are not accepted as a per-file result.

### Build The Kernel And Platform Matrix

Probe, do not infer from kernel version:

- active `bpf` LSM and `CONFIG_BPF_LSM`;
- BTF/CO-RE viability;
- selected LSM hooks and denial return behavior;
- task and socket local storage;
- iterators and required helpers/kfuncs;
- ring buffer and per-CPU loss accounting;
- cgroup v2 connect/send/packet/device attachments;
- TC fallback where proposed;
- pidfd and cgroup freezer behavior;
- bpffs/link/map pinning and lockdown;
- containerd and CRI-O create/start integration points; and
- coexistence with baseline Cilium, Calico, and another supported CNI.

Assign `full`, `enforce-reduced`, `observe`, or `unsupported` from measured
capabilities. A nominal Linux version is not a support result.

### Establish Performance And Recovery Budgets

Set absolute Phase 0 budgets for:

- allowed and denied fork/exec;
- allowed and denied file open/read/write/mmap;
- TCP/UDP connect/send;
- ring-buffer saturation and loss;
- node CPU/memory;
- local spool;
- profile swap;
- root-admission latency;
- restart/reconcile time;
- control disconnection; and
- `runtime-observe`, `mithril-observe`, and `mithril-protect`.

Use Runtime's current ptrace behavior only as a comparison. “Faster than
ptrace” is not an acceptance budget.

### Create The Standing Incident Fixture

Create the safe skeleton specified in
[Hugging Face Adversarial Acceptance](./hugging-face-adversarial-acceptance.md):

```text
crates/mithril-e2e/
├── fixtures/hugging-face/
│   ├── manifests/
│   ├── worker/
│   ├── controller/
│   ├── provider-simulators/
│   └── source-records/
├── src/fixture/
│   ├── manifest.rs
│   ├── coverage.rs
│   └── result.rs
└── tests/
    ├── hugging_face_baseline.rs
    └── substrate_capabilities.rs
```

The worker supports concurrent logical jobs in one interpreter and a safe
in-process effect driver. It contains no original exploit payload, production
credential, or external exfiltration destination.

## Code-Backed Tests

- C/Rust ABI layout equivalence on every target architecture.
- Rust decoder property/fuzz tests for length, version, kind, alignment, and
  unknown fields.
- Object digest and source/toolchain provenance reproducibility.
- One-owner pin-root lease: first owner succeeds, overlapping second owner
  refuses and creates coverage evidence.
- Mode authority tests: `runtime-observe` cannot load denial/response programs
  or obtain writable map handles.
- Capability probes fail with named classifications for every intentionally
  removed feature.
- Vertical allow/deny probes prove return behavior rather than event receipt.
- `HF-BASE-001` fixture starts and completes concurrent legitimate work without
  requiring a job event.
- Performance harness produces machine-readable baseline output.

## Checkpoint

Run the repository documentation/Rust gates plus Phase 0's recorded BPF build,
ABI, capability, fixture, and benchmark commands. Preserve the exact kernel,
toolchain, object digests, and output artifacts.

## Acceptance

- exact crate/module/path names and dependency direction are approved;
- the Rust/libbpf spike owns load/attach/maps/links/events/recovery;
- no upstream daemon is required;
- every adapted source file has an approved provenance disposition;
- every required guarantee maps to a tested hook or a named missing capability;
- full/reduced/observe/unsupported tiers are produced from probes;
- the raw ABI is versioned and cross-language layout-tested;
- the safe incident fixture runs the unchanged multi-job control;
- one active owner and the Runtime watch-only boundary are physically tested;
- absolute performance/recovery budgets are recorded; and
- no production capability is credited to an unverified upstream assumption.

## Explicit Stop Point

Stop after presenting the substrate, license, ABI, capability, fixture, and
performance results. The user must approve Phase 1 and the final Phase 0 path
decisions before the production node chassis is created.

## Phase Result

State: Not started.

When complete, record exact files, selected versions, copied/adapted source
dispositions, testbed kernels/runtimes, commands, results, budgets, gaps, and
`Done`, `Not done`, or `Blocked`.
