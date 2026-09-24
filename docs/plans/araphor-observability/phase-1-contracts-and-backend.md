# Phase 1: Contracts And Backend Qualification

Prove that a pinned upstream bpftrace build can run under the existing node
owner with bounded output and verified cleanup. Resolve the loader exception
before dependent implementation. Read the [parent contract](README.md).

## Intended end state

Engineers have one request/result contract and a runnable lifecycle proof.
Unsupported platform or cleanup behavior blocks that backend. No production
endpoint or agent-facing arbitrary-script capability is enabled.

## Implementation flow

```text
Engineer selects the supported bpftrace build and platform
  -> qualification records executable, libraries, kernel, architecture, and BTF
  -> Interceptor proof starts one reviewed fixture on a disposable test host
  -> proof records attachment readiness, output, limits, and process identity
  -> proof requests cancellation and verifies probe/resource removal

Parent or child exits during preparation or collection
  -> cleanup closes only resources owned by that execution
  -> proof verifies that enforcement links and maps did not change
  -> missing cleanup or an unbounded child blocks backend qualification

Caller submits source for a read-only check
  -> compiler-only checks run without attach authority
  -> diagnostics identify unsupported probes or unresolved runtime requirements
  -> check does not invoke bpftrace --dry-run or claim an attachment proof
```

Status: **Not done** for release qualification. Reuse the existing diagnostic
owner and cases; rerun their proof on the implementing revision.

## Scope, owners, and changes

1. Record the explicit decision for delegated diagnostic loading in the parent
   and affected architecture record. Do not weaken the single enforcement
   loader or alter instructions by implication. Until approved, result is
   **Not done**, and only isolated qualification is permitted when authorized.
2. Add bounded request, target, output-frame, and terminal-result types under
   `crates/mithril-control/src/observability/` as needed. Mark all fields that
   are new. Reuse tenant, evidence-reference, digest and error conventions.
   Pin exact source and parameter digests; do not treat a recipe name as trust.
3. Inventory `WorkloadTargetFactV1` in `policy/reconciliation.rs` and the Node
   binding/CRI facts that prove each supported target. Record unsupported
   unbound targets instead of inventing a policy or accepting a PID alone.
4. Put process supervision in `crates/erebor-interceptor/src/diagnostic.rs`
   only after the ownership decision. Use the upstream executable interface.
   No Rust bpftrace parser, general backend trait, or second daemon is needed.
   Pin the binary/dependency image digest. Check packaging license notices.
5. Add qualification cases to `crates/mithril-e2e/src/observability.rs` and
   physical inputs under `harness/observability/` and `fixtures/observability/`.
   The lightweight case calls production owner methods with external-process
   doubles. The physical case runs the same transitions with bpftrace.

## Limits and proof

Initial limits to prove, not measured guarantees: 64 KiB source; 10-second
preparation; 30-second default and 300-second maximum collection; 5-second
graceful output drain; 1 MiB maximum frame; 16 MiB retained output per execution;
4,096 map keys where the selected backend supports an enforceable ceiling;
16 attached probes per approved recipe. Reject wildcard expansion above the
qualified limit. Admission caps are not a general arbitrary-script sandbox.
Record userspace RSS, BPF map memory, probe count, and kernel execution overhead
separately. Userspace cgroup limits do not bound all kernel work.

Pass `OBS-BACKEND`: parse error, unsupported hook, missing BTF, partial attach,
quiet script, histogram-only output, malformed/oversize output, graceful exit,
forced kill, parent death, compile timeout, and deadline. Prove no active
diagnostic attachment after cleanup. Verify against an enforcement baseline
before and after every failure. No test may remove another owner's resources.
Record why a selected hook is valid; do not assume kprobes are portable.

Add `observability_backend_` tests. Proposed commands after implementation:

```sh
cargo test -p erebor-interceptor observability_backend_ -- --nocapture
cargo test -p mithril-e2e observability_backend_ -- --nocapture
bash .github/scripts/verify-rust-ci.sh
```

Require a nonzero test count and physical artifacts with exact program/link
identities. Readiness cannot be inferred from process spawn or a stdout banner
without a qualified backend contract. If complete readiness cannot be proved,
state Unknown and do not claim coverage from the requested start time.

### End-to-end deliverable

Extend `ObservabilityQualification` in `crates/mithril-e2e/src/observability.rs`.
The existing `mithril_observability_test` binary accepts the qualified executable,
its SHA-256 and an output directory. Keep that entry point. Add explicit
lightweight case selection for recorded external-process behavior; do not
require a real privileged child for the lightweight suite.

Required pair: `backend-lifecycle` uses production Interceptor supervision with
an external-process double, then the existing `harness/observability/` runner
uses real bpftrace. Both emit preparation, attachment, collection, stopping
and cleanup states with the same result schema. Physical output additionally
contains program/link identities. A stub cannot pass the physical gate.

## Stop point

Require qualified attachment readiness, bounded output, lease expiry,
parent-death cleanup, and unchanged enforcement resources before owned capture.
A successful compiler run or process spawn does not prove attachment coverage.
