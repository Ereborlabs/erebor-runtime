# Phase 6.3: Shared Telemetry And Operational Logging

Status: In progress. The stderr format and this phase are approved.

Rename `erebor-runtime-telemetry` to the product-neutral `erebor-telemetry`.
Use it to add useful operational logs to Mithril Control, Mithril Node, and the
Mithril OCI hook. Keep logs separate from policy, evidence, audit, readiness,
recovery, and enforcement state.

## Intended end state

- Erebor and Mithril use `erebor-telemetry` for operational logs.
- Service stderr keeps Erebor's human-readable `tracing-subscriber` format.
- Each component has useful `ERROR`, `WARN`, `INFO`, `DEBUG`, and `TRACE`
  allocation.
- `RUST_LOG` controls global and target-specific verbosity.
- Errors are logged once at the boundary that selects exit, retry, rejection,
  quarantine, or reduced readiness.
- CLI stdout and command diagnostics keep their current contracts.
- The existing durable Erebor telemetry records remain compatible.
- Automated physical proof and an independent manual example pass.

## Current facts

`erebor-runtime-telemetry` owns the logging macros, tracing re-exports, stderr
initializer, test initializer, and durable Erebor telemetry sink. Its stderr
initializer uses:

```rust
tracing_subscriber::fmt()
    .with_env_filter(filter)
    .with_target(true)
    .with_writer(std::io::stderr)
    .try_init();
```

The current formatter produced:

```text
2026-08-24T21:30:53.969611Z DEBUG erebor_runtime_telemetry::logging::tests: test logging initialized twice
```

Mithril services use direct `eprintln!` calls. These calls do not provide
consistent levels or target filters. Mithril command binaries also use stdout
and stderr for operator output. That command output is not a service log.

## Implementation flow

Engineer starts the shared-owner change
  -> rename the directory, package, and import to `erebor-telemetry`
  -> update workspace members, dependencies, imports, active documents, and commands
  -> preserve the existing macros, stderr formatter, filters, and durable record reader
  -> do not add an old-name compatibility crate or import alias
  -> verify the rename before product instrumentation starts

Owned service starts
  -> the binary initializes shared stderr logging before the first owned operation
  -> the initializer selects `INFO` by default
  -> `RUST_LOG` can set a global level or a Rust-target override
  -> invalid initialization fails before the service reports readiness
  -> repeated test initialization remains safe

Owned operation changes state or makes a decision
  -> the state owner selects one static ASD-STE100 message
  -> the owner selects the level from this phase
  -> the owner adds bounded, safe `key=value` fields
  -> `tracing-subscriber` writes timestamp, level, Rust target, message, and fields
  -> the log does not become an authority or durable product record

Operation fails
  -> lower layers return a structured error without logging it repeatedly
  -> the owner logs once when it selects exit, retry, rejection, quarantine, or reduced readiness
  -> expected policy denial uses `INFO`, not `ERROR`
  -> repeated retry detail uses `DEBUG` or `TRACE`
  -> recovery produces one transition log

Operator runs a command binary
  -> command results remain on stdout in the command-defined format
  -> command diagnostics remain on stderr
  -> service initialization does not add a prefix to command stdout

Operator changes log verbosity
  -> Helm renders separate Control and Node `RUST_LOG` values
  -> Kubernetes restarts the affected Pod through the normal upgrade path
  -> only the selected target emits the additional detail
  -> enforcement, readiness, evidence, and policy results remain unchanged

Physical or manual test completes or fails
  -> the test captures real service stderr through runtime interfaces
  -> the test verifies format, levels, filters, fields, and sensitive-data absence
  -> the test removes its workloads, temporary logs, and markers
  -> the automated fixture keeps healthy reusable VMs and Kubernetes state
  -> cleanup reports its real result without replacing an earlier failure

## Approved stderr contract

Keep the current formatter. Do not add a custom renderer.

```text
<UTC timestamp> <LEVEL> <Rust target>: <static message> [key=value ...]
```

Example:

```text
2026-08-24T21:35:01.000000Z WARN mithril_node::node: Control rejected the evidence batch grpc_code=permission_denied retry=after_registration node_id=node-a label_epoch=1 source_id=cpu-0
```

The Rust target identifies the product and component. Do not add duplicate
`service` or `component` fields. Field order and terminal color are formatter
behavior, not a repository protocol.

Use the existing macro syntax. Put changing values in tracing fields. Use the
same field name for the same fact. Common names include `error`, `error_code`,
`status_code`, `grpc_code`, `retry`, `duration_ms`, `attempt`, `count`,
`node_id`, `kubernetes_node`, `kubernetes_node_uid`, `node_boot_id`,
`label_epoch`, `namespace`, `pod_uid`, `container_name`, `container_id`,
`profile_id`, `candidate_id`, `source_id`, and `commit_index`.

Do not log policy documents, exception documents, evidence or audit payloads,
file contents, command arguments, environment values, credentials, request or
response bodies, or complete Kubernetes annotation or label maps.

## Levels and targets

| Level | Use |
| --- | --- |
| `ERROR` | The process cannot continue safely, durable state is invalid, or fail-closed rollback fails. |
| `WARN` | A recoverable degradation needs operator attention. |
| `INFO` | A low-frequency lifecycle transition or expected security decision occurs. |
| `DEBUG` | One request, RPC, reconciliation step, retry, or bounded batch completes. |
| `TRACE` | One chunk, kernel counter, candidate match, or high-frequency diagnostic occurs. |

| Target | Required allocation |
| --- | --- |
| `mithril_control::service` | Node session, readiness, admission, evidence health, RPC, and batch results. |
| `mithril_control::store` | Store open, replay, commit, and integrity results. |
| `mithril_control::policy::reconciliation` | Desired-state, rollout, retry, and candidate-match results. |
| `mithril_control::policy::kubernetes_workloads` | Workload-watch loss, recovery, and inventory results. |
| `mithril_control::policy::kubernetes_exceptions` | Exception activation, revocation, terminal, and retry results. |
| `mithril_node::node` | Process, Control session, readiness, evidence health, and connection results. |
| `mithril_node::policy_delivery` | Stage, transfer, activation, rejection, retirement, and cleanup results. |
| `mithril_node::runtime_admission` | Final admission at `INFO`; verification at `DEBUG`; matching at `TRACE`. |
| `mithril_node::observation` | Evidence gap, recovery, batch, acknowledgement, cursor, and source results. |

Do not log unchanged reconciliation at `INFO`. Do not log each BPF effect.
The OCI hook logs only its own bounded process failure. The Node owns the
admission decision.

Example filter:

```text
RUST_LOG=info,mithril_node::runtime_admission=debug,mithril_control::store=trace
```

## Owners and changes

| Owner | Change |
| --- | --- |
| `erebor-telemetry` | Rename the crate; preserve macros, format, filtering, test initialization, and durable Erebor compatibility. |
| `.agents/engineering.md` | Add the approved format, levels, log-once rule, sensitive-data rule, and CLI exception after phase approval. |
| `mithril-control` | Initialize shared logging and replace service `eprintln!` calls with owner-level events. |
| `mithril-node` | Initialize shared logging and add Node and OCI-hook events. Keep `mithril-inspect` output unchanged. |
| Mithril Helm chart | Add validated Control and Node `RUST_LOG` values. |
| VM harness | Prove live format, level filtering, failure, recovery, and cleanup. |
| Manual example | Give an independent operator proof without VM ownership. |

## Ordered deliverables

1. Rename the crate and verify all existing consumers.
2. Converge shared initialization without a custom formatter.
3. Update `.agents/engineering.md` with the approved rules.
4. Instrument Mithril Control.
5. Instrument Mithril Node and the OCI hook.
6. Add Helm filter configuration.
7. Add automated behavior tests, the physical fixture case, and the
   independent manual example.

The user requested one commit for each deliverable. An authorized committer
must create those commits after each deliverable passes its focused checks.

## Required proof

- Shared telemetry tests capture real output and prove format preservation,
  level filtering, target override, idempotent initialization, and durable
  Erebor record compatibility.
- Control tests prove start, ready, invalid-store exit, authentication
  rejection, rollout transition, evidence rejection, no repeated transition,
  and recovery logs.
- Node tests prove Control connection, readiness loss, policy activation and
  retirement, runtime allow and deny, evidence authentication failure,
  target-specific detail, one-owner logging, and recovery.
- Command tests prove clean stdout and stderr separation.
- Tests execute the logger or product. They do not parse repository source to
  claim behavior.
- The automated two-node fixture captures `kubectl logs`, triggers the normal
  and failure flows, checks sensitive-data absence, changes one target filter,
  proves behavior is unchanged, cleans Mithril-owned state, and keeps healthy
  VMs.
- The independent manual example performs the same operator-visible checks in
  an existing cluster. It does not create, select, retain, or destroy VMs.

Run the focused crate tests after each deliverable. Run these final checks:

```sh
bash .github/scripts/verify-rust-ci.sh
bash packaging/mithril/helm/tests/verify.sh
bash crates/mithril-e2e/harness/vm/test.sh
bash examples/mithril-kubernetes-convergence-manual/test.sh
git diff --check
```

Record a pass only after the current-source automated physical run and manual
case pass.

## Acceptance

- No old telemetry crate, package, import, or compatibility alias remains.
- Erebor stderr and durable telemetry behavior remain compatible.
- Owned Mithril services use the shared logging owner and approved format.
- Levels and target filters follow this phase.
- Logs contain no prohibited payload or secret.
- CLI output remains compatible.
- Logging does not change product decisions or state.
- Automated, physical, and manual behavior proofs pass and clean their state.

## Excluded

- A custom service-log renderer.
- OTLP, collectors, metrics, profiling, remote export, log storage, and
  dynamic filter reload.
- Changes to policy, exception, evidence, audit, WAL, Control commit, gRPC, or
  BPF schemas.
- Reformatting output from containerd, kubelet, the stock NRI hook injector,
  or another external component.
- A general Erebor instrumentation pass beyond the crate rename.

## Stop point and phase result

Complete only this phase. Stop before Phase 7.

```text
State: Not done.
Completed deliverables: 1.
Changed owners: the shared telemetry crate, its workspace consumers, this plan, and the master phase index.
Verification: `cargo test -p erebor-telemetry --all-targets --all-features` and `cargo check --workspace` passed.
Physical and manual results: not run.
Remaining work: implement Deliverables 2 through 7 and run all required proof.
Next phase authorized: no.
```
