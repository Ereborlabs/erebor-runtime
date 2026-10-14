# Native Execution Decision Proposal

This record supplies the decisions required by
[the native execution phase](phase-7-5-5-native-execution.md).
D1 is **Resolved** by the user's platform requirement. D2 and D5 are
**Approved**: qualify all current portable exports and use native calls in
Araphor's process. Rust artifacts are approved for D3. The SDK supplies its
existing binary interface. D4 is **Approved**: execution follows the installed
plugin type. D6 native
resource options and disabled defaults are **Approved**. The user explicitly
approved both Rust libraries and native-only Unsupported for an enabled hard
native cap. SQL and Wasm remain usable. Source baseline: `2b9384ec`.

## Intended end state

An author builds Wasm and native artifacts from the same SDK computation.
An operator installs a native plugin through AnalysisPackageOwner. The package
owner runs its declared native implementation. The Rust native adapter returns the same output and
checkpoint meaning in Araphor's process.
The host retains authorization, evidence checks, storage, and atomic commits.
A returned native error commits no partial result and causes no target fallback.

## Current source and approval boundary

The approved direction supplies one SDK, one package owner, execution by plugin
type, and native execution in Araphor's process. The user removed the earlier worker
and isolation requirements. Reuse Arrow C interfaces at the native library
boundary, locked source builds, and admission without a compiler or installation
hook. Native execution requires no process transport.

At baseline `2b9384ec`, the source has no executable native adapter or native
execution owner. The table below records that baseline. Read the
[implementation review](native-execution-review.md) for the implemented owners
and qualification results.
The user approved the complete current portable export inventory and native
execution like the existing builtins. The SDK supplies binary compatibility
metadata and the existing v1 adapter interface. Use the plugin's declared
implementation and the existing state lifecycle.
The user requires native execution on every platform where Araphor can compile.
The user approved optional native resource settings with disabled defaults after
the original proposal. D6 records that correction.

| Baseline owner | Source-backed fact |
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

## Existing computation and missing native package execution

The [package lifecycle result](phase-7-5-3-package-lifecycle.md#qualified-boundary)
records installed SQL execution. At that source, the current discovery and
graph algorithms execute through shared trusted Rust calls from 7.5.2. Those
algorithms are compiled into Araphor. Their computation is already implemented.

At that baseline, production adapters use InstalledAnalysis. PackageArtifactV1 selects
Wasm or SQL, and AnalysisPackageOwner evaluates those targets. Native artifact
bytes can be declared, but the owner cannot select or load them. Native returns
Unsupported. Installed Wasm execution from 7.5.4 does not supply a native loader.

This phase adds the SDK native ABI adapter, built native artifact and dependency
closure, native library loading, execution by plugin type, and native parity
and recovery proof. It reuses the algorithms and package lifecycle. An operator
must be able to install the separately built native package without rebuilding
Araphor. Do not repeat algorithm migration or copy computation implementations.

## D1: Supported platform

Resolved requirement: native execution must work on every platform where Araphor
can compile. Do not add a separate Linux x86-64 product restriction. Derive the
applicable package-owner target set from current source and build records.
Compilation and runtime qualification are separate evidence.

For each platform, build its native artifact with the shared Rust SDK.
Record the target triple, required CPU features, native contract version,
native library interface, and required system-library symbols. Check these requirements
against the host before activation. Artifact compatibility metadata describes
the built artifact; it does not define a narrower product platform list.

The current qualification host is Linux x86-64 with glibc 2.39. This observation
does not qualify other targets or other host-library versions. The loader and
native artifact compatibility checks must serve each applicable compilation
platform. Do not require a native worker or an OS isolation backend.

## D2: Native export inventory

Approved inventory: qualify all seven current portable exports and the existing SDK
detector example. Reuse their existing computation source and fixtures.
This is the qualification inventory, not an execution allowlist. The SDK must
also let authors build and operators install new native package exports through
the same contract and owner.

| Package | Native exports | Required parity |
| --- | --- | --- |
| Discovery | `atoms`, `merge`, `groups`, `compare` | Dataset values, ordering, numeric results, evidence, coverage, and replay. |
| HF-PROC-001 | `detect` | Exact identities, relationships, findings, evidence, reasons, and coverage. |
| HF-DW-001 | `detect` | Credential findings, exact references, reasons, coverage, and replay. |
| HF-XNODE-001 | `detect` | Kubernetes joins, exact references, reasons, coverage, and replay. |
| SDK detector example | Existing BurstDetector export | Findings, evidence, checkpoint meaning, restart, retry, and package updates. |

AR-04 context selection remains with the trusted host context owner. It is not
a native package export. This proposal does not repeat algorithm migration or
port additional upstream algorithms.

## D3: ABI, build, and dependency changes

Approved language: authors implement the shared computation and SDK interface in
Rust. The native adapter, builder, and execution owner also use Rust. Authors
must not write C adapter code.

Binary boundary: keep the current v1 C table layout behind a Rust SDK
export macro. This is a calling convention, not the authoring language. Declare
one exported accessor:
`const araphor_analysis_api_v1 *araphor_analysis_get_api_v1(void)`.
Check the table version, size, and function pointers in the native execution owner.
Use the existing `Guest` trait behind a native SDK export adapter.
The accessor returns a non-null table with static lifetime until library unload.
Check the version and `struct_size` before reading function pointers. Require
the exact v1 table size for this profile; reject an incompatible table.

Enable `arrow-array/ffi` on the existing pinned Arrow 58.4.0 dependency. That
feature also enables `arrow-data/ffi` and `arrow-schema/ffi`.
Use Arrow C Data and C Stream inside Araphor's process. Reuse SDK input and output
validation. Add no native process transport. Catch Rust unwind panics at every
SDK callback. Foreign-language adapters must catch exceptions before an ABI
return or supply a verified no-throw interface. An exception cannot unwind
through a C or Rust frame. An abort can terminate Araphor. The adapter must release
owned output on success and failure. Repeated release must have no effect.

Use these libraries rather than implement new artifact parsers or syscall wrappers:

| Rust dependency | Purpose | Existing lock state |
| --- | --- | --- |
| `libloading = "=0.9.0"` | Load the verified Rust native library in Araphor's process. | New dependency. |
| `object = "=0.40.0"`, required native-format read features only | Inspect imports, versions, and dependency requirements without loading code. | Version is already locked. |

Landlock, seccompiler, and a new direct libc dependency for worker controls are
removed from this proposal. Use platform support in the selected Rust loader and
artifact reader without removing an existing Araphor compilation target.

Keep Rust trait objects, Vec, String, and Rust-layout structures inside their
own library. The Rust calling convention has no stable binary contract between
independent builds. The SDK hides the versioned binary boundary from authors.
See the [Rust ABI reference](https://doc.rust-lang.org/reference/items/external-blocks.html#abi).

Extend the existing builder for `--locked --release` native source builds.
The built folder contains the native artifact and all non-system runtime
dependencies, each with a digest. For Linux, the standard loader, libc, libm,
and libgcc requirements are explicit platform requirements. Other targets must
declare their required system libraries. Admission validates the full
closure and the host-provided system libraries. It runs no package code,
compiler, downloader, or installation hook.
Resolve every imported library and required symbol version throughout the
closure. Use scoped platform loading and validated dependency identities;
do not change Araphor's environment to configure one library. Reject undeclared or
ambiguous dependencies and uncontrolled loader search paths. The Linux ELF
checks include RPATH/RUNPATH entries. Account for the
host's already loaded system libraries. Bind admission checks and loading
to the same immutable retained file identities;
a path or digest checked before a later file replacement is insufficient.

Keep generated native and Wasm binaries out of commits. Preserve the current
32 MiB serialized package bound. If a complete dual-target closure exceeds that
bound, report the measured size and obtain approval before changing the bound.

## D4: Execution by plugin type

Approved rule: a native plugin runs native; a Wasm plugin runs Wasm.
Explicit approval: the user wrote `D4 approved.`.
The installed plugin declaration determines the execution type. Add no global
Wasm or native preference and no operator target option. The user's rule
replaces the earlier default and runtime target-switch proposal.

Both artifacts can be built from the same Rust computation. Shared-source
builds and parity fixtures do not require an operator choice at runtime.

Proposal: extend only the native implementation declaration with an export list,
optional input bindings, artifact identity, compatibility requirements, and
locked dependency files. Each dependency has a validated relative name,
content digest, and declared library identity. Reject path traversal, duplicate
identities, changed content, and an incomplete closure.

Native compatibility contains the target triple, endianness, CPU requirements,
system-library requirements and native contract version. Check declared requirements against
the platform's native artifact format, including ELF on Linux, as well as the
host. Record the artifact and closure digests in admitted metadata.

Keep the SDK computation contract at version 1. Preserve the canonical encoding
of existing SQL and Wasm packages. Native declarations without qualification
metadata remain readable inspection inputs but cannot execute. Preserve the
legacy `{export, artifact}` native form and its encoding. Add an optional native
qualification object that supplies the export list and other new fields. An
absent qualification object retains the legacy digest and means Unsupported
for execution. Qualified declarations use the same artifact bytes plus the
new object; reject conflicting export declarations.

Execute the implementation declared by the installed plugin. Keep the existing
package requests and CLI. Add optional provenance fields to results and receipts
for the actual execution type, artifact digest, closure digest, and platform.
Historical records retain their original target and have absent new provenance.
The existing JSON transport needs no new Control protobuf message or Run target
field. Installation retains its current request format.

Bind native evaluation identity and retry checks to the declared artifact and
closure. Use the existing activation generation and authority commit checks.
Commit output and checkpoint together after success. Failure retains the
previous active revision and committed state. Reuse of an operation ID with a
different artifact or closure returns Conflict. Use the existing package update
and rollback behavior when an installed plugin changes. Check its output and
state contracts. Add no public rebuild option or automatic state converter.
Missing retained input produces incomplete coverage through the existing owner.
Never change execution type after a crash, timeout, partial output, or malformed
result.

### D4 example: run the installed plugin

An author builds detector A from one Rust source library. The author can produce
a native plugin and a Wasm plugin. Both builds use the same named export and
data contract.

```text
The operator installs the native plugin
  -> AnalysisPackageOwner validates and retains the declared native artifact
  -> the package owner checks native compatibility with the host
  -> a compatible saved state is supplied to the native adapter
  -> Araphor calls the adapter in its own process
  -> the existing host owners validate the complete result
  -> AnalysisStore commits the result and checkpoint together

The operator installs the Wasm plugin
  -> AnalysisPackageOwner validates and retains the declared Wasm artifact
  -> Araphor runs that artifact through the existing Wasm owner

The operator retries an operation
  -> the same operation and artifact return the original receipt
  -> a changed artifact under the same operation ID returns Conflict
```

A result identifies its package revision, actual Wasm or native artifact, input
revisions, and its saved-state version. A native error does not select Wasm.
The existing package update and rollback paths handle a changed package state
contract. They cannot reconstruct input that has expired.

## D5: In-process native execution

Approved direction: execute native Rust package code in Araphor's process,
like the current builtins. Add no native worker, process transport, sandbox,
second service, scheduler, or store. Native code has the same process privileges
and failure domain as Araphor. The earlier single-thread restriction is removed.

AnalysisPackageOwner retains authorization, immutable revision selection,
concurrency permits, host validation, stale-result checks, and atomic commits.
Use the existing supported owner APIs for extraction and domain validation.
Native loading occurs only after package admission and artifact compatibility
checks. Those checks do not isolate library initialization or native computation.

The library handle must outlive its function table, output streams, arrays,
release callbacks, and any package-created threads or tasks. Background activity
must finish before unload, or the owner must retain the library pin while that
activity can execute its code. Do not assume that unload resets global state.
Host-retained output must own its storage independently
before library unload. No evaluation can retain borrowed request pointers or
host cancellation callbacks after it returns. AnalysisStore owns durable state;
library global state cannot replace the committed checkpoint.

Check cancellation and authorization before computation and before commit.
Reject a result returned after cancellation, expiry, revocation, or an activation
change. Cooperative SDK polling can support early return, but an arbitrary native
call cannot be safely killed in Araphor's process. A call that ignores cancellation
retains its library and operation permit until it returns.

Catch unwind-mode Rust panics at the SDK boundary. An abort, invalid native
pointer, segmentation fault, or memory corruption can terminate or damage
Araphor. On restart, restore the previous complete durable commit. Do not claim
that native faults are recoverable inside the same process or that raw-pointer
validation establishes native memory safety. See the
[Rust panic contract](https://doc.rust-lang.org/std/panic/fn.catch_unwind.html).

## D6: Mandatory controls and configurable limits

Approved resource policy: native memory and CPU limits are optional configuration
settings and are disabled by default. Retain the existing SDK data limits, host
input/output accounting, operation permits, cancellation, grant expiry, and
effective owner deadline.
Native does not inherit any optional Wasm quota or Wasm compiler-process limit.
The approved D5 direction uses no process isolation.

| Control | Proposed requirement and default |
| --- | --- |
| Filesystem, credentials, and network | Native code shares Araphor's process privileges. The execution path adds no deny rules. Host API authorization checks still apply. |
| Processes and threads | Native executes in Araphor's process. No native worker or imposed single-thread restriction. |
| Package operations | Existing owner default: four simultaneous operations. Existing QueryOwner permits also apply. |
| SDK output and checkpoint | Existing declared SDK limits and host accounting always apply. SDK defaults are 1,024 batches, 1,000,000 rows, 64 MiB data, and 16 MiB checkpoint data. |
| Host buffers | Existing query defaults: 64 MiB input bytes, 128 MiB input capacity, and 16 MiB output capacity. Effective limits can be lower than the SDK declaration. |
| Time | Mandatory effective AnalysisReadControl deadline, QueryLimits evaluation timeout, and grant expiry. The query evaluation timeout defaults to one second; automatic package reconciliation supplies a 30-second outer control. Preserve caller settings and use the earliest applicable deadline. |
| Native address space | Optional `memory_bytes`, in bytes. Default `None` disables this option. An enabled hard per-library cap returns Unsupported because the shared process cannot enforce it. |
| Native CPU | Optional `cpu_seconds`, in seconds. Default `None` disables this option. An enabled hard per-library cap returns Unsupported because the shared process cannot enforce it. |
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
selected enforcement mechanism. Reject an invalid configured value with a typed error before
package loading. Do not reject native admission, execution, or qualification
because a cap is absent. No numeric cap value is required from the user.
Existing owner deadlines, grant expiry, SDK data bounds, and host output accounting
still apply. They reject late or oversized results; they cannot stop arbitrary
native CPU use or establish a per-library heap limit. Do not set a process-wide
OS limit and describe it as a native evaluation limit. Reject an enabled hard
per-library cap with Unsupported before loading native code. No cap values are
needed for the approved disabled defaults.

## Ordered implementation and proof

The phase owns the correction TODOs and independent deliverable commits.
Run focused owner tests before each implementation commit. After the last covered
source edit, run one authoritative final Rust CI process to a terminal result.

Qualification must cover ABI errors, malformed buffers, first and repeated
release, unwind-panic handling, malformed outputs, incompatible hosts,
constructor failures, shared-host crash and restart, late completion, cancellation,
expiry, revocation, stale completion, resource failures, restart, retries,
upgrades, rollback, removal, and package changes between Wasm and native builds.
Check checkpoint meaning and retry identity after each package change.
Every returned error must preserve the prior committed output and checkpoint,
release owned resources, and produce no Wasm fallback. Fatal native faults require
host restart proof against the last durable commit; they have no worker recovery.

Each approved dual-target export must pass identical fixtures for datasets,
ordering, numbers, identities, evidence, namespaced reasons, coverage,
checkpoints, and replay. Include large selected graph inputs through the native
Arrow C boundary.
Keep authorized native DuckDB extraction and traversal in their existing owners,
and close durable readers before native computation.
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

D1 is **Resolved**: native execution must work wherever Araphor can compile.
D2 is **Approved** for all current portable exports and the SDK detector example.
D5 is **Approved** for execution in Araphor's process with no isolation.
Rust artifacts are approved for D3. The SDK supplies its existing versioned
binary interface. D4 is **Approved**: execution follows the installed plugin
type. Add no global target preference, operator target option, or separate
rebuild command.
D6 options retain disabled defaults. An enabled hard per-library cap returns
Unsupported in the shared process. Native implementation and qualification
remain **Not done**. The user explicitly approved both Rust libraries and
native-only Unsupported for an enabled hard cap. Development has resumed.
The SDK, builder, loader, and production qualification must supply their own
current proof before completion.
