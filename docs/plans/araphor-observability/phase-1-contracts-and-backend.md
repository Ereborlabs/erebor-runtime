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

Status: **Done** for backend qualification at source `8e752bdb`.
The corrected partial-attach and unsupported-hook checks have direct physical
proof, and the full workspace procedure passed after the final code edit.
Read [Corrected backend proof](#corrected-backend-proof).
Production enablement also requires the later lifecycle, interference, and
shared-recovery gates.

### Current implementation work

The current work closes this phase only. Reuse `DiagnosticBackend`,
`ObservabilityQualification`, and the existing physical harness. Add the
unprivileged `backend-lifecycle` selection with an external-process double.
Use the same production supervisor and result schema. A double does not prove
kernel attachment or resource cleanup.

Add capture-mode readiness and deadline checks. Require the physical verifier
to reject unsuccessful capture and unsupported-hook cases with the wrong
outcome. Record diagnostic link identities beside program and map identities.
Pass the selected executable to the parent-death child; do not replace it with
a fixed system path. Run lightweight proof before the paired physical proof.
Do not add or run performance experiments without separate user approval.
Keep required unapproved measurements open. Do not change trace storage or
start client delivery in this phase.

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
Partial attachment requires proof that a requested probe attached before a
later attachment failed. Loaded program IDs do not supply this proof.
Missing-hook proof must reject permission and read-only-filesystem failures
even when the output also contains a generic attachment error.

Add `observability_backend_` tests. Proposed commands after implementation:

```sh
cargo test -p erebor-interceptor observability_backend_ -- --nocapture
cargo test -p mithril-e2e observability_backend_ -- --nocapture
cargo run -p mithril-e2e --bin mithril-observability-test -- --case backend-lifecycle --output-directory /tmp/araphor-backend-lifecycle
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

## Implementation result

Review of source `74c81c39` reopened this result. The commands below
exited successfully, but two physical pass conditions were insufficient.
The partial-attach check counted loaded programs without proving attachment.
The unsupported-hook receipt also contains a read-only-filesystem error.
These receipts prove resource cleanup, not the two required failure cases.
The corrected proof follows the earlier record below.

- `0706cffb` adds the feature-gated process-double entry and capture-mode
  component proof. Real execution retains digest checks, checked-inode exec,
  fixed arguments, namespaces, capability removal in compile mode, and the
  existing supervisor. Sixteen focused component tests passed; one subprocess
  helper stays ignored as a top-level test and runs through its parent test.
- `bbba9023` adds the lightweight selection, twelve lifecycle cases and
  parent-death proof. It also requires exact readiness and failure outcomes
  in the physical verifier. Parent-death execution uses the selected binary.
- `97d66dee` records live hash-map capacities and rejects missing or excessive
  recipe capacity. Nine focused end-to-end/verifier tests and two Control
  contract tests passed. The CLI argument check passed separately.
- `0bf8b2d3` rejects compiler-owned program/map IDs even when global polling
  misses those IDs. Its focused regression passed. Duplicate verifier checks
  were removed after Ponytail review.
- `74c81c39` retains dependency versions, notices, common-license texts and
  hashed provenance. Both physical runners exited 0. Review later rejected
  their partial-attach and unsupported-hook pass conditions. The receipts
  retain valid cleanup and compiler-only evidence.

The initial lightweight histogram fixture emitted invalid JSON because of
shell quoting. The fixture now uses a raw Rust string. One build attempt ran
before a verifier edit finished and failed compilation. The CLI test first
expected a default-mode requirement to fail during parsing; it now checks
the actual rejection before execution. These failures are not backend passes.
The first full workspace run was stopped after review required the final
compiler-only check. Its partial results do not replace the final run.

All retained logs use `/tmp/araphor-backend-proof.lhnEPItv/`. The focused logs
are `component-2.log`, `bounds.log`, `cli-test-2.log`, and `compile-proof.log`.
The first physical receipts are under `physical/`.

The final `bash .github/scripts/verify-rust-ci.sh` run exited 0 after the last
code and harness commit, `74c81c39`. Its log is `workspace-final.log`.
Formatting, workspace check, Clippy with warnings denied, and workspace tests
passed. The related library test counts are:

| Crate | Passed | Failed | Ignored |
| --- | ---: | ---: | ---: |
| `erebor-interceptor` | 39 | 0 | 1 |
| `araphor-data` | 141 | 0 | 5 |
| `mithril-control` | 176 | 0 | 2 |
| `mithril-e2e` | 131 | 0 | 407 |
| `mithril-node` | 266 | 0 | 1 |

Ignored tests are not passes. The backend subprocess helpers run through their
parent tests. The separate physical command below supplies backend kernel
proof; the workspace procedure alone does not supply that proof.

### Earlier backend receipts

The final binary passed `backend-lifecycle` before the physical run. Its receipt
is `lightweight-final/result.json`: twelve scenarios and a separate parent-death
check. The receipt states `physical: false`. It uses the production supervisor
but cannot prove BPF attachment or kernel cleanup.

The paired physical runner exited 0, including missing-BTF host preflight
and parent-death cleanup. This exit does not close the two rejected pass
conditions. Its receipts are under `physical-final/`; the command
log is `physical-final.log`. The owned guest is
`mithril-runtime-qualification-202610012201`, UUID
`140989e4-293d-41c7-9f69-8e68bdfef868`. The qualified platform is Ubuntu x86_64,
kernel `6.8.0-142-generic`, and bpftrace package `0.20.2-1ubuntu4.3`.

Exact SHA-256 identities:

| Artifact | SHA-256 |
| --- | --- |
| Qualification binary | `e4636413498d101c248ef9ce143d7755e8854474da7148f56e0c9bf6f3b8aa3a` |
| bpftrace executable | `d2846f3400bb129b1a569aae64adf548de99ff41f247823ff8caf1fbde40ff1e` |
| Runtime BTF | `3802b509af01c3d187fa1bef9469e311612b184efa439d7366201fd5e9753cba` |
| Dependency provenance manifest | `c0b8bb4a4036bdb1739a499d90d333da24010b6d0cef95e4316f26a726b8f4ba` |

All sixteen cases restored the BPF resource inventory and preserved the
enforcement manifest. Compile-only execution recorded no program or map IDs
in either inventory. Histogram and both reviewed recipe maps had a hash-map
capacity of 4,096 entries. Parent death removed diagnostic program 9880 and
maps 8303/8304.
The observed link sets are empty for this build's perf-event attachments.
An unsampled map-memory value stays null; no zero-memory claim follows.

The command sequence used these six build settings:

```sh
export CARGO_TARGET_DIR=/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target
export CXXFLAGS='-O2 -g0'
export CARGO_BUILD_JOBS=2 CARGO_INCREMENTAL=0 CARGO_NET_OFFLINE=true RUST_TEST_THREADS=1
cargo build --locked -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --bin mithril-observability-test
/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/mithril-observability-test --case backend-lifecycle --output-directory /tmp/araphor-backend-proof.lhnEPItv/lightweight-final
bash .github/scripts/verify-rust-ci.sh
```

The physical command ran through SSH in the owned guest after lightweight
qualification passed:

```sh
sudo -n bash /mnt/mithril-source/worktrees/mithril-ui/crates/mithril-e2e/harness/observability/guest.sh /mnt/mithril-source/target/debug/mithril-observability-test /tmp/araphor-observability-lhnEPItv-final
```

The copied provenance files passed `sha256sum --check provenance.sha256`.
Existing target contracts require authenticated inventory and exact live
binding, Node boot, CRI container identity and cgroup lifetime. Missing or
unbound target identity remains Unsupported. No PID-only target or fabricated
policy was added.

The earlier receipts do not close the two rejected pass conditions.
It does not qualify diagnostic/enforcement interference, acceptable production
overhead, Pod replacement, shared trace storage, public APIs, or a script
sandbox. RSS, map memory and kernel runtime counters are recorded observations,
not a performance guarantee. No new performance experiment ran. Diagnostics
remain disabled by default; production enablement retains the later lifecycle,
interference and shared-recovery gates.

### Corrected backend proof

Source `8e752bdb` corrects both pass conditions. The partial-attach verifier
requires a child-owned `BPF_PROG_TYPE_PERF_EVENT` program named `10` with a
positive execution count. The pinned bpftrace fixture attaches this interval
before it attempts the failing kprobe. Loaded IDs alone do not pass.
The execution count proves that the interval ran before cleanup; attachment
order proves that its attachment preceded the later failure.

The unsupported-hook fixture uses a missing raw tracepoint. Its verifier
requires the exact `Probe does not exist` error. Permission and read-only
filesystem errors fail this check. The partial-attach case can use a read-only
failure for its second attachment; that case does not claim missing-hook proof.

`observability_backend_partial_proof` and
`observability_backend_hook_rejection` rejected the old false-positive
outcomes. Both tests failed before the fix. After the fix, the focused suite
passed ten end-to-end/verifier tests and two Control tests. One subprocess
helper remains ignored as a top-level test.

Logs and receipts use `/tmp/araphor-capture-qualification.E0VU3eEo/`:

- `regression-red.log` records the two expected regression failures.
- `regression-green-2.log` records the focused pass.
- `lightweight/result.json` records twelve lifecycle cases and parent death.
  This run passed before the physical run and states `physical: false`.
- `physical/cases/` records sixteen physical cases, missing-BTF preflight and
  parent death. All sixteen cases verified cleanup and unchanged enforcement
  resources. In `partial-attach.json`, child-owned program 133 has type 7,
  name `10`, and 17 executions. `unsupported-hook.json` contains the exact
  missing-raw-tracepoint error without a permission or filesystem error.
- `workspace.log` records the full workspace procedure, which exited 0 after
  the final code edit. Formatting, workspace check, Clippy with warnings denied,
  and workspace tests passed. Related library counts are: data 141 passed and
  5 ignored; Interceptor 39 passed and 1 ignored; Control 176 passed and
  2 ignored; end-to-end 132 passed and 407 ignored; Node 266 passed and
  1 ignored. No test failed. Ignored tests are not passes.

The new owned guest is `mithril-runtime-qualification-20261002163710`, UUID
`fb6a3ee1-b6b0-4f57-82e6-834bf8629d1c`. It uses Ubuntu 24.04.5 x86_64, kernel
`6.8.0-142-generic`, and bpftrace package `0.20.2-1ubuntu4.3`.
The earlier guest was in use by another task and was not changed.

The qualification binary SHA-256 is
`a7ff912a194d364cd887502b7c9c7a260288af62929d639c61e2c6ad2ff0f470`.
The bpftrace and BTF hashes match the table above. The new provenance manifest
SHA-256 is `b2c3fd68915b358b55e196ba7219807315c653c87284877151491bf7ee09999c`.
`sha256sum --check provenance.sha256` passed for every copied input.

Use the same six build settings listed above. The corrected commands were:

```sh
cargo test --locked -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --lib observability_backend_ -- --nocapture
cargo build --locked -p araphor-data -p mithril-control -p mithril-node -p mithril-e2e --all-features --bin mithril-observability-test
/home/navid/go/src/github.com/Ereborlabs/erebor-runtime/target/debug/mithril-observability-test --case backend-lifecycle --output-directory /tmp/araphor-capture-qualification.E0VU3eEo/lightweight
bash .github/scripts/verify-rust-ci.sh
```

The physical command ran through SSH in the new owned guest:

```sh
sudo -n bash /mnt/mithril-source/worktrees/mithril-ui/crates/mithril-e2e/harness/observability/guest.sh /mnt/mithril-source/target/debug/mithril-observability-test /tmp/araphor-observability-gate-20261002
```

No supervisor isolation or enforcement resource rule changed. Missing
readiness and unsampled resource values remain Unknown. These results do not
qualify shared trace storage, physical target replacement, interference or
production enablement. No performance experiment ran.
