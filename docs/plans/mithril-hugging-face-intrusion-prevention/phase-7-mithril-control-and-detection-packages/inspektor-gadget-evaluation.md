# Inspektor Gadget Evaluation Against Existing bpftrace

Evaluate collection reuse against Araphor's existing trace path. Determine
whether Inspektor Gadget removes required work or adds a second collector.

This evaluation covers collection. The primary package requirement is to install
new algorithms and detectors over available evidence. This collection comparison
does not select or qualify an analysis extension interface.

Result: **Done for source-based design evaluation. Runtime qualification:
Not done.** Recommendation: retain bpftrace as the default diagnostic backend.
Do not add Inspektor Gadget or build an equivalent gadget loader for the current
package proposal. Reconsider an optional adapter for a named native gadget
whose capability or maintenance benefit justifies the integration.

Parent: [Extensible security packages](extensible-security-packages-design.md).
This result recommends an implementation direction. It does not authorize a
backend replacement or a new production integration.

## Intended end state

New algorithms and detectors use existing evidence through the proposed analysis
interface and the existing SQL path. Collection remains under the current trace
owners. A package needs a collection change only when required inputs are absent.
Interceptor retains prevention authority.

## Proposed flow

The following flow applies only to an optional package that adds a trace recipe.
It is not required to install an algorithm over existing inputs.

```text
Operator installs a package with a bpftrace recipe
  -> package admission checks exact source, contract, trust, and requirements
  -> TraceOwner authorizes a finite capture for exact target lifetimes
  -> Node rechecks the grant and target before execution
  -> Interceptor supervises the pinned bpftrace executable
  -> Node sends retained output through existing authenticated intake
  -> AnalysisStore commits output before acknowledgement

Recipe, target, or required backend capability is unsupported
  -> admission reports the exact unsupported requirement
  -> no alternate collector starts implicitly
```

Recipe installation is proposed work. Current source accepts a fixed recipe
set. A source file or cgroup predicate alone does not establish safe tracing.

## Evaluation basis

Research date: 2026-10-09. Upstream release: `v0.56.0`, commit
`e5a2855f270ca6557f4bd7e4fabaddf6760d8f50`. Read 26 selected source files,
211,088 bytes, and verified their Git blob identities against that commit's
tree. No clone or worktree was created. The temporary source receipt is
`/tmp/araphor-ig-evaluation/source-receipt.json`.

The host has bpftrace `v0.20.2`; `ig` is not installed. Read the current Rust
owners and the latest retained qualification record. No probes, cluster
changes, dependency builds, or performance experiments ran for this evaluation.
The conclusions below concern architecture and source behavior, not measured
speed or physical correctness of an Inspektor Gadget integration.

## The existing baseline

Araphor already implements source admission, target resolution, signed dispatch,
exact target-lifetime checks, bounded execution, cancellation, local spooling,
durable upload, and cleanup status. The bpftrace backend checks the executable
it opens and executes that inode. Collection is finite, with a maximum of
300 seconds. See [capture](../../../../crates/araphor-observability/src/capture.rs),
[target binding](../../../../crates/araphor-observability/src/target.rs), and
[backend supervision](../../../../crates/erebor-interceptor/src/diagnostic.rs).

The current [recipe implementation](../../../../crates/araphor-data/src/trace/recipe.rs)
recognizes `SyscallErrors` and `FailedOpens`; it does not accept arbitrary new
recipes from a folder. This is a local admission restriction, not a limit of
bpftrace or the requested algorithm extension. If a package needs a new trace,
keep source, output schema, attribution, sensitivity, limits, and decoding
semantics as one reviewed contract.

Existing qualification records include restart, cancellation/fault, storage,
and same-name Pod replacement cases. They retain incomplete output and unknown
trace kernel loss where applicable. Performance remains unqualified in the
[capture completion record](../../araphor-observability/phase-2-owned-capture.md#implementation-completion-record).
This is prior evidence, not a new verification run. Retaining bpftrace does
not justify broader completeness or performance claims.

## Is bpftrace more extensible?

bpftrace supports probes, predicates, actions, maps, and aggregation in scripts.
An author can add a trace or a local stateful check in a `.bt` file. It is not
limited to raw event output. See the [language](https://bpftrace.org/docs/release_026/language)
and [standard library](https://bpftrace.org/docs/release_026/stdlib).
These links describe release 0.26; they do not qualify its newer features on the
installed 0.20.2 binary.

For direct trace authoring, a script requires fewer build and package steps than
a native gadget. This is an authoring advantage, not proof of greater general
expressiveness. Inspektor Gadget supports native eBPF programs and optional
[Wasm processing](https://inspektor-gadget.io/docs/latest/gadget-devel/gadget-intro/).
Neither collection model by itself defines Araphor's retained, cross-node
algorithm inputs, result validation, state recovery, or correction semantics.

## What Inspektor Gadget adds

| Capability | Verified source behavior | Value beyond current recipes |
| --- | --- | --- |
| Native gadget distribution | The eBPF operator loads a compiled object and creates a collection. | Ships native eBPF programs without compiling each `.bt` source on the target. This can help a larger catalogue of specialized sensors. |
| Typed event data | Gadget metadata and BTF-derived layouts expose typed fields and data sources. | Rich event schemas exceed our two current counter projections. |
| Kubernetes integration | Namespace authorization and container selection are implemented. Multi-tenancy is experimental and opt-in. | Useful for an independent collector, but our exact target grants still need integration. |
| Processing extensions | Wazero runs gadget-specific Wasm callbacks with bounded linear memory. | Reuses gadget processing code; does not replace the proposed analysis interface. |

Sources: [eBPF loader](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/operators/ebpf/ebpf.go),
[data protocol](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/gadget-service/api/api.proto),
[namespace authorization](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/docs/devel/multitenancy.md),
and [Wasm host](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/operators/wasm/wasm.go).

These are useful capabilities. They do not require replacement of bpftrace
unless a selected workload benefits from them. No relative performance result
was measured.

## Concrete integration gaps

**1. File-open observations are not our authoritative effect record.** The
shipped `trace_open` gadget hooks `open` and `openat`; its source does not hook
`openat2`. It emits the supplied filename and optionally resolves the full path
after a successful open. It cannot obtain that successful-open path for a
denied open. Its process structure includes PID, TID, mount namespace, and
parent fields, but no process birth identifier. An adapter must bind these
observations to our authoritative lifetimes or retain uncertain attribution.
Sources: [file-open program](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/gadgets/trace_open/program.bpf.c)
and [process type](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/include/gadget/types.h).

The current bpftrace counter recipes also do not prove individual file effects.
Interceptor evidence supplies the authoritative policy decision. Neither
collector may convert an observed error code into proof of our policy denial.

**2. Loss reporting needs more work for durable evidence.** The tracer reads
perf loss and, where present, a ring-buffer loss map. It logs reported loss and
calls `ReportLostData`. In this pinned release, the data-source implementation
of `ReportLostData` is empty. Do not treat that call as a persisted coverage
record. Source reading also found no complete accounting for every missed
entry in the selected file-open gadget. Sources: [tracer reader](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/operators/ebpf/tracer.go)
and [loss method](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/datasource/data.go).

**3. The direct gRPC stream is not durable intake.** The service increments an
event sequence and drops the event if its bounded output channel is full.
Later sequence gaps can expose some loss, but the inspected protocol provides
no Araphor commit receipt or durable replay acknowledgement. Stop requests
cancel the gadget context; this is not our independent cleanup proof. We need
an adapter that records loss and terminal uncertainty and uses existing Node
spooling and intake. Source: [stream implementation](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/gadget-service/service-oci.go).

**4. Its Wasm host is a different executable contract.** The host uses Wazero,
WASI Preview 1, an `ig` import module, gadget API version 1, and lifecycle/data
callbacks. It sets a 16 MiB linear-memory limit and exposes BPF map operations.
The proposed analysis path uses Wasmtime components, authorized snapshots,
and explicit result/state commits. These interfaces are not binary compatible.
OCI transport does not change this. Reuse needs a source port or adapter;
collector map authority must not enter the analysis host. Sources:
[Wasm host](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/operators/wasm/wasm.go)
and [map operations](https://github.com/inspektor-gadget/inspektor-gadget/blob/e5a2855f270ca6557f4bd7e4fabaddf6760d8f50/pkg/operators/wasm/maps.go).

**5. It adds a deployment and maintenance boundary.** A Rust integration can
use the published gRPC protocol and a managed collector process. Direct Go
embedding requires a language boundary or a Go helper. Both paths need exact
grant binding, shutdown, resource accounting, package trust integration, and
new qualification. The controller is Apache-2.0; the inspected file-open BPF
source is GPL-2.0. Preserve each component's licence obligations.

## Recommendation and its limits

| Option | Result |
| --- | --- |
| Keep existing bpftrace collection | Recommended as the input baseline. Algorithm and detector extension over available evidence does not require a collector change. |
| Replace bpftrace with Inspektor Gadget | Not recommended. The current requirement does not need replacement, and the source review identifies integration gaps. |
| Install both by default | Not recommended. No selected package currently establishes enough additional collection value to justify another runtime. |
| Add an optional adapter for a named gadget | Conditional. Reconsider when a concrete native sensor removes substantial implementation or maintenance work. Qualify its exact event and lifecycle contract then. |

For example, packaging the existing syscall-error script needs a package
catalogue, admitted recipe metadata, and current TraceOwner execution. It does
not need an OCI-to-eBPF loader. A future package that needs a specialized native
gadget can justify that loader through an optional Inspektor Gadget adapter.
This is a sensor extension example. The primary acceptance case instead installs
a new algorithm and a detector that uses it over existing inputs, with no new
probe and no change to Araphor source.

Do not create a generic collection framework in advance of that requirement.
The evaluation supports this collection choice; it does not certify either
backend for every platform or establish full Hugging Face prevention.

## Verification

- Pinned source identities: 26 files matched the release Git tree.
- Local executable check: `bpftrace --version` returned `bpftrace v0.20.2`.
- Inspektor Gadget execution, adapter tests, probe lifecycle tests, and
  performance comparisons: **Not done**. No integration is claimed.
