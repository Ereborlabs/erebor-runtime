# Native Execution Decision Proposal

This record supplies the decisions required by
[the native execution phase](phase-7-5-5-native-execution.md).
D1 through D5 are **Not approved**. D6 native resource options and their disabled
defaults are **Approved** by the user. Do not implement a dependent change until
the user approves its unresolved decision. Source baseline: `2b9384ec`.

## Intended end state

An author builds Wasm and native artifacts from the same SDK computation.
An operator installs the built folder and selects native execution through
AnalysisPackageOwner. The worker returns the same output and checkpoint meaning.
The host retains authorization, evidence checks, storage, and atomic commits.
A worker failure commits no partial result and causes no target fallback.

## Current source and approval boundary

The approved parent direction supplies one SDK, one package owner, Wasm as the
default, and qualified native workers. The user also requires Arrow C interfaces
inside the worker, bounded IPC between processes, locked source builds, and no
compiler or installation hook at admission. These decisions need no new approval.

The current source has no executable native adapter or native execution owner.
No concrete native platform, export inventory, compatibility metadata, isolation
mechanism, or deployment requirement is approved in the inspected phase records.
The user approved optional native resource settings with disabled defaults after
the original proposal. D6 records that correction.

| Current owner | Source-backed fact |
| --- | --- |
| [Native header](../../../../../crates/araphor-analysis-sdk/src/bindings/analysis.h) | Defines the v1 function table and typed request, output, release, error, and cancellation fields. No table accessor symbol is declared. |
| [SDK guest](../../../../../crates/araphor-analysis-sdk/src/guest.rs) | Supplies the shared `Guest` computation interface and Wasm export adapter. |
| [SDK wire](../../../../../crates/araphor-analysis-sdk/src/wire/mod.rs) | Supplies typed Arrow IPC, bounded buffers, and independent exchange validation. |
| [Package artifact](../../../../../crates/araphor-data/src/package/bundle.rs) | Native contains only one export and artifact bytes. Selection chooses Wasm, then SQL. |
| [Package execution](../../../../../crates/araphor-data/src/package/execution.rs) | Executes SQL or Wasm. Native returns Unsupported. |
| [Package owner](../../../../../crates/araphor-data/src/package/owner.rs) | Owns four operation permits, authority checks, grant expiry, and cancellation. |
| [Package commit](../../../../../crates/araphor-data/src/package/installed/commit.rs) | Rejects stale activation generations, package revisions, and metadata. |
| [Builder](../../../../../crates/araphor-component-build/src/workspace.rs) | Builds the current components from source with locked dependencies. Its manifest contains Wasm artifacts. |
| [Header test](../../../../../crates/araphor-analysis-sdk/src/bindings/tests.rs) | Checks C syntax. It does not execute the example or prove release behavior. |

## D1: Supported platform

Proposal: qualify `x86_64-unknown-linux-gnu`, little-endian ELF64, with the
baseline x86-64 CPU instruction set. Do not use `target-cpu=native` in author
builds. Record the compiler target, required CPU features, native contract
version, isolation profile, and required system-library symbols.

Check the host CPU and required library symbols before native activation.
The library requirements come from the built artifact; do not guess a minimum
glibc version. The qualification host has glibc 2.39. That observation does not
qualify every glibc 2.39 host or an older glibc host.

Other operating systems, architectures, musl targets, GPU runtimes, and native
dependencies that require threads or child processes remain unsupported by this
profile. Their declarations must produce typed Unsupported results.

## D2: Native export inventory

Proposal: qualify all seven current portable exports and the existing SDK
detector example. Reuse their existing computation source and fixtures.

| Package | Native exports | Required parity |
| --- | --- | --- |
| Discovery | `atoms`, `merge`, `groups`, `compare` | Dataset values, ordering, numeric results, evidence, coverage, and replay. |
| HF-PROC-001 | `detect` | Exact identities, relationships, findings, evidence, reasons, and coverage. |
| HF-DW-001 | `detect` | Credential findings, exact references, reasons, coverage, and replay. |
| HF-XNODE-001 | `detect` | Kubernetes joins, exact references, reasons, coverage, and replay. |
| SDK detector example | Existing BurstDetector export | Findings, evidence, checkpoint meaning, restart, retry, and explicit switching. |

AR-04 context selection remains with the trusted host context owner. It is not
a native package export. This proposal does not repeat algorithm migration or
port additional upstream algorithms.

## D3: ABI, build, and dependency changes

Proposal: keep the current v1 C table layout. Declare one exported accessor:
`const araphor_analysis_api_v1 *araphor_analysis_get_api_v1(void)`.
Check the table version, size, and function pointers in the worker.
Use the existing `Guest` trait behind a native SDK export adapter.
The accessor returns a non-null table with static lifetime until library unload.
Check the version and `struct_size` before reading function pointers. Require
the exact v1 table size for this profile; reject an incompatible table.

Enable `arrow-array/ffi` on the existing pinned Arrow 58.4.0 dependency. That
feature also enables `arrow-data/ffi` and `arrow-schema/ffi`.
Use Arrow C Data and C Stream only inside the worker. Reuse the SDK wire types,
framing, and validation for process transport. Catch Rust unwind panics at every
SDK callback. Foreign-language adapters must catch exceptions before an ABI
return or supply a verified no-throw interface. An exception cannot unwind
through a C or Rust frame. An abort is a worker failure. The adapter must release
owned output on success and failure. Repeated release must have no effect.

Use these libraries rather than implement new ELF parsers or syscall wrappers:

| Proposed dependency | Purpose | Existing lock state |
| --- | --- | --- |
| `landlock = "=0.4.7"` | Filesystem access rules with required enforcement. | New dependency. |
| `seccompiler = "=0.5.0"`, without JSON support | Compile the Rust syscall allowlist and apply it. | New dependency. |
| `libloading = "=0.9.0"` | Load a verified library only inside the isolated worker. | New dependency. |
| `libc = "=0.2.186"` | Linux syscall numbers and narrow process controls. | Version is already locked; direct use requires approval. |
| `object = "=0.40.0"`, ELF read features only | Inspect ELF imports, versions, and dependency requirements without loading code. | Version is already locked; direct use requires approval. |

Extend the existing builder for `--locked --release` native source builds.
The built folder contains the native artifact and all non-system runtime
dependencies, each with a digest. The standard loader, libc, libm, and libgcc
requirements are explicit platform requirements. Admission validates the full
closure and the host-provided system libraries. It runs no package code,
compiler, downloader, or installation hook.
Resolve every imported library and required symbol version throughout the
closure. Clear inherited loader search configuration. Reject undeclared or
ambiguous dependencies and uncontrolled RPATH/RUNPATH entries. Account for the
trusted worker's already loaded system libraries. Bind admission checks,
isolation rules, and loading to the same immutable retained file identities;
a path or digest checked before a later file replacement is insufficient.

Keep generated native and Wasm binaries out of commits. Preserve the current
32 MiB serialized package bound. If a complete dual-target closure exceeds that
bound, report the measured size and obtain approval before changing the bound.

## D4: Artifact metadata and target selection

Proposal: extend only the native implementation declaration with an export list,
optional input bindings, artifact identity, compatibility requirements, and
locked dependency files. Each dependency has a validated relative name,
content digest, and declared library identity. Reject path traversal, duplicate
identities, changed content, and an incomplete closure.

Native compatibility contains the target triple, endianness, CPU requirements,
system-library requirements, contract version, and `single_thread_v1` isolation
profile. Check declared requirements against the ELF artifact as well as the
host. Record the artifact and closure digests in admitted metadata.

Keep the SDK computation contract at version 1. Preserve the canonical encoding
of existing SQL and Wasm packages. Native declarations without qualification
metadata remain readable inspection inputs but cannot execute. Preserve the
legacy `{export, artifact}` native form and its encoding. Add an optional native
qualification object that supplies the export list and other new fields. An
absent qualification object retains the legacy digest and means Unsupported
for execution. Qualified declarations use the same artifact bytes plus the
new object; reject conflicting export declarations.

Add explicit per-export target selection to the existing package requests and
CLI. Persist selection in activation metadata. An omitted selection retains the
current Wasm-then-SQL behavior. Add optional provenance fields to results and
receipts for the actual target, artifact digest, closure digest, and platform.
Historical records retain their original target and have absent new provenance.
The existing JSON transport needs no new Control protobuf message. The proposed
Run request adds an optional target and an explicit `rebuild` flag whose default
is false. Install and update requests accept per-export target selections.

Bind native evaluation identity and retry checks to the selected artifact and
closure. A selection change uses the existing activation generation and authority
commit checks. Reuse of an operation ID with a different target or closure returns
Conflict. A selection change must cause evaluation even when input revisions
are unchanged. For the qualified dual-target inventory, identical output and
checkpoint contracts plus parity fixtures permit a switch. Reject an incompatible
checkpoint before evaluation unless the caller requests `rebuild`. That request
uses the existing owner rebuild computation, clears the input checkpoint,
replays authorized retained inputs, and commits the selected implementation,
new output, and new checkpoint together. Missing retained input produces
incomplete coverage. The current public request has no rebuild field; this
proposal requires that addition. Add no automatic state converter.
Never switch targets after a crash, timeout, partial output, or malformed result.

## D5: Worker isolation and deployment

Proposal: run one fresh, trusted, single-thread worker per evaluation under
AnalysisPackageOwner. This requires no worker cache, second service, scheduler,
or durable store. No scope or package revision shares transient worker state.
The deployment supplies the worker executable with Araphor. Operators need no
Python, author toolchain, namespace privilege, or delegated cgroup for this profile.
Before native activation, verify that the trusted worker executable is available
and that it can install the required isolation profile. An ABI capability query
alone cannot establish native readiness.

Before loading package code or initializing any package dependency, the worker
must complete all of these controls:

- Clear environment values and inherited descriptors. Retain only owned
  transport pipes and verified read-only code handles.
- Drop inherited capabilities. Set `no_new_privs`, disable dumpability, and
  set the core-dump limit to zero.
- Install a Landlock ruleset with required filesystem enforcement, including
  truncate denial. Permit reads of exact verified code and system-library files.
  Permit no Control database, credential, home directory, or broad library tree.
- Install an architecture-checked, default-deny seccomp allowlist. Reject x32
  and other incompatible syscall numbers. Allow only the qualified loader,
  allocator, computation, and owned pipe operations.
- Deny network sockets, process and thread creation, exec, tracing, process-memory
  access, external signals, namespace changes, shared-memory IPC, `io_uring`,
  kernel administration, and filesystem mutation. Deny calls that can reverse
  privilege controls or resource limits.
- Restrict arguments for multipurpose syscalls such as `fcntl`, `prctl`, and
  `mmap`. Deny filesystem metadata mutation that Landlock does not mediate.
- Apply enabled native resource limits. Confirm successful isolation
  before opening the evaluation path.

Require Landlock filesystem rights through ABI 3 and installed seccomp filters.
Do not use best-effort enforcement. A missing control returns typed Unsupported
before package loading. A later worker fault returns the existing typed package
failure and commits no partial state.

The owner controls an owned process group and always terminates and reaps it on
failure, cancellation, expiry, or revocation. The filter prevents package children
and background threads from existing. Prove that constructor-time attempts are
denied. Retain process-group termination as cleanup protection.

The local capability query reports Linux `6.8.0-142-generic`, Landlock ABI 4,
and seccomp `KILL_PROCESS` support. This query does not install a filter, test
forbidden access, or qualify a worker. The required controls follow the
[kernel Landlock contract](https://docs.kernel.org/userspace-api/landlock.html)
and [kernel seccomp contract](https://www.kernel.org/doc/html/latest/userspace-api/seccomp_filter.html).

The proposed bindings are documented by
[landlock 0.4.7](https://docs.rs/landlock/0.4.7/landlock/),
[seccompiler 0.5.0](https://docs.rs/seccompiler/0.5.0/seccompiler/), and
[libloading 0.9.0](https://docs.rs/libloading/0.9.0/libloading/).

## D6: Mandatory controls and configurable limits

Approved resource policy: native memory and CPU limits are optional configuration
settings and are disabled by default. Retain the existing SDK data limits, host
input/output accounting, operation permits, cancellation, grant expiry, and
effective owner deadline.
Native does not inherit any optional Wasm quota or Wasm compiler-process limit.
The worker isolation profile remains the D5 proposal.

| Control | Proposed requirement and default |
| --- | --- |
| Filesystem, credentials, and network | Mandatory deny rules; no configurable bypass. |
| Worker processes and threads | One process and one thread per evaluation; no package children. Fixed by the qualified profile. |
| Package operations | Existing owner default: four simultaneous operations. Existing QueryOwner permits also apply. |
| SDK output and checkpoint | Existing declared SDK limits and host accounting always apply. SDK defaults are 1,024 batches, 1,000,000 rows, 64 MiB data, and 16 MiB checkpoint data. |
| Host buffers | Existing query defaults: 64 MiB input bytes, 128 MiB input capacity, and 16 MiB output capacity. Effective limits can be lower than the SDK declaration. |
| Time | Mandatory effective AnalysisReadControl deadline, QueryLimits evaluation timeout, and grant expiry. The query evaluation timeout defaults to one second; automatic package reconciliation supplies a 30-second outer control. Preserve caller settings and use the earliest applicable deadline. |
| Native address space | Optional `memory_bytes`, in bytes. Default `None` disables this limit. When configured, apply a checked OS address-space limit before package loading. |
| Native CPU | Optional `cpu_seconds`, in seconds. Default `None` disables this limit. When configured, apply a checked OS CPU-time limit before package loading. |
| Wasm quotas and compiled code | Preserve the six optional quotas as disabled by default and the 80 MiB, 16-entry accounting for all live compiled Wasm code. |

Define these options in the existing query configuration under `native`:

```json
{
  "native": {
    "memory_bytes": null,
    "cpu_seconds": null
  }
}
```

Each option is an optional unsigned 64-bit integer. An omitted option or `null`
disables that limit. A configured value must be positive and valid for the
qualified OS limit. Reject an invalid configured value with a typed error before
package loading. Do not reject native admission, execution, or qualification
because a cap is absent. No numeric cap value is required from the user.
Existing owner deadlines, grant expiry, transport bounds, and isolation checks
still apply. Configured resource-failure tests remain required.

## Ordered implementation and proof

The phase owns the correction TODOs and independent deliverable commits.
Run focused owner tests before each implementation commit. After the last covered
source edit, run one authoritative final Rust CI process to a terminal result.

Qualification must cover ABI errors, malformed buffers, first and repeated
release, panic containment, malformed outputs, incompatible hosts, unavailable isolation,
constructor-time forbidden access, worker crashes, stalled work, cancellation,
expiry, revocation, stale completion, resource failures, restart, retries,
upgrades, rollback, removal, and compatible switches in both directions between
Wasm and native. Check checkpoint meaning and retry identity after each switch.
Every crash and failed evaluation must preserve the prior committed output and
checkpoint, release owned resources, and produce no Wasm fallback.

Each approved dual-target export must pass identical fixtures for datasets,
ordering, numbers, identities, evidence, namespaced reasons, coverage,
checkpoints, and replay. Include large selected graph inputs across IPC.
Keep authorized native DuckDB extraction and traversal in their existing owners,
and close durable readers before worker computation.
If a selected dependency is native-only, require its declared platform and
resource requirements and semantic fixtures. Do not claim Wasm compatibility.

Extend `analysis-packages` with the source-built SDK detector and a migrated
algorithm with Python unavailable. Run affected production cases through their
supported owners. Preserve complete graph workloads, evidence assertions,
notification deadlines, and original scenario limits. Shared fixtures can own
resources and data but cannot hide scenario actions or reproduce owner internals.

Record source, artifact, platform, configuration, command, and terminal result.
Earlier Wasm and host-owner evidence applies only where its behavior is unchanged.
No native result or speed gain is proven by this proposal.

## Decision status

D1 through D5 are **Not approved**. The user approved D6 native memory and CPU
configuration options with disabled defaults. Native implementation and
qualification remain **Not done**. Await only the unresolved user decisions
before dependent implementation.
