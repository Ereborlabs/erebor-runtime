# Lightweight Scenario Maintainability Todo

This work makes the Rust qualification scenarios short to add and safe to
operate. It does not change Mithril production architecture or complete the
active product phase.

## Intended end state

A new scenario supplies fixture inputs, calls a public production owner,
performs the physical action, and checks the result. Shared fixtures own only
temporary resources, process lifetime, readiness, cleanup, and failure
diagnostics. They do not reproduce a production operation sequence.

Small tests and small files are strongly encouraged when each one shows one
behavior clearly. A file split, wrapper, or moved function is not a migration
if it hides the same orchestration or makes production operations harder to
trace.

No Rust source file in `crates/mithril-e2e` can exceed 2,000 lines at
delivery. Each extracted module must own one clear scenario or fixture
responsibility. This limit does not make a mechanical split sufficient.

The suite keeps its current result schemas, security assertions, public owner
calls, stock `runc` and containerd paths, and paired Kubernetes operations.

## Scenario model

Every scenario has the same three components:

- Control, through the real `mithril-control` owner.
- Node, through the real `mithril-node` owner.
- One Python actor process in a host, `runc`, or Kubernetes environment.

The environment owner holds paths, component handles, readiness state, and
cleanup state. It exposes direct start and stop operations for Control, Node,
and the actor. It does not deliver policy, reconcile a binding, publish an
identity, acknowledge evidence, or perform another production sequence for
the scenario.

The actor file performs one physical action. Use the same actor file for the
host, `runc`, and Kubernetes forms of that case. Environment code changes
placement and component availability only. It does not change the action or
the production operation under test.

Do not add an environment trait, scenario registry, command language, or
backend matrix. Use small concrete owners in Rust and Python. Give each owner
one `start` path, direct component stop operations, and one idempotent `stop`
path.

The rejected shape hides the test behind a stateful free function:

```rust
let result = scenario::run(self, &host, &node, &binding, &path, &ready)?;
```

The required shape keeps the case visible:

```rust
let mut env = TestEnv::host(root, "read_secret.py")?;
env.control.stop().await?;
env.actor.release()?;
let result = node.public_operation(env.actor.pid())?;
ensure!(result == expected, InvalidInputSnafu { path, reason });
env.stop().await?;
```

The example is a shape, not a new test API. Each scenario must call the real
public production operation in place of `public_operation`.

## Measured suite

The inspection covers all 27 Rust source files in `crates/mithril-e2e/src`.
The files contain 41,790 lines. `cargo test -p mithril-e2e --lib -- --list`
reports 90 library tests. The two binary tests and the local VM harness check
are also in scope.

| Source | Lines | Tests | Scenario responsibility |
| --- | ---: | ---: | --- |
| `benchmark.rs` | 250 | 3 | Benchmark execution and validation |
| `capability.rs` | 320 | 4 | BPF compilation and platform checks |
| `capability_matrix.rs` | 103 | 1 | Capability closure |
| `closure.rs` | 149 | 0 | Fixture registry closure |
| `control_tls.rs` | 2,928 | 19 | Control, node, TLS, outage, replay, and decommission scenarios |
| `digest.rs` | 44 | 1 | Stable digest format |
| `effect.rs` | 5,118 | 4 | Replacement exception and physical effect scenarios |
| `effect/child.rs` | 4,422 | 14 | Physical syscall action fixture and focused checks |
| `effect/fixture_syscalls.rs` | 893 | 0 | Physical syscall actions |
| `effect/mailbox.rs` | 163 | 1 | Child control transport |
| `effect/network.rs` | 2,329 | 4 | Single-node and two-node network scenarios |
| `effect/runc.rs` | 8,476 | 2 | Runtime gate, recovery, entry-role, and upgrade scenarios |
| `effect/support.rs` | 1,128 | 5 | Effect assertions and observation readiness |
| `error.rs` | 96 | 0 | Qualification errors |
| `fixture.rs` | 227 | 1 | Safe incident fixture verification |
| `golden.rs` | 216 | 3 | Policy and ABI goldens |
| `identity.rs` | 10,577 | 13 | Native and Kubernetes identity scenarios |
| `identity/clone3.rs` | 654 | 1 | Clone-into-cgroup fixture |
| `lib.rs` | 47 | 0 | Public qualification surface |
| `loader.rs` | 337 | 2 | BPF inspection and attachment |
| `physical.rs` | 132 | 0 | Resource cleanup support |
| `prototype.rs` | 592 | 11 | Bounded model checks |
| `provenance.rs` | 289 | 1 | Source and license dossier |
| `runner.rs` | 749 | 0 | Kernel and host lifecycle scenarios |
| `bin/mithril_effect_test.rs` | 1,044 | 1 | Effect and runtime command entry points |
| `bin/mithril_identity_test.rs` | 99 | 0 | Identity command entry points |
| `bin/mithril_kernel_qualification.rs` | 178 | 1 | Kernel qualification command entry points |

The main orchestration debt is not file size alone. The largest scenario
owners are:

| Scenario owner | Approximate lines | Paired physical owner |
| --- | ---: | --- |
| `EffectTestRunner::runc_entry_role_runtime_probe` | 3,992 | `two-node-convergence.sh` protected start, concurrent exec, replacement, administrative entry, and upgrade checks |
| `EffectTestRunner::physical_probe` | 3,466 | `run.sh` observe and protect effect lanes |
| `IdentityTestRunner::physical_probe` | 2,294 | `run.sh` native identity lane |
| `NetworkTestRunner::physical_probe` | 1,237 | `two-node-network.sh` in both node directions |
| `EffectTestRunner::recovered_container_entry_probe` | 1,028 | `two-node-convergence.sh` recovered-container entry lane |
| `IdentityTestRunner::physical_kubernetes_probe` and its private cases | 4,900 combined | `run.sh --with-k3s` identity lane |

## Acceptance reset

The previous migration checkmarks are not accepted. The changes moved test
code, but they did not make scenario setup, actions, and assertions simple.
They also left stateful scenario code in loose functions and left separate
native and direct-runtime process wrappers. Reassess every migration against
the rules below before it receives a checkmark.

The baseline reliability records remain as failure evidence. They do not
count as maintainability migrations.

## Shape rules

- Prefer one small test per security behavior.
- Prefer a small file when it has one fixture or scenario responsibility.
- Keep each Rust source file below 2,000 lines.
- Keep a larger file only when a split would separate an action from its
  assertion or hide the production call order.
- Keep fixture setup, action, and assertion visible in the test.
- Put resource allocation, readiness, diagnostic capture, and cleanup in
  simple fixture owners.
- Use `ProcessFixture` as the one process lifecycle owner for identity,
  direct `runc`, and containerd tests. Do not add a native-process lifecycle
  wrapper or a second kill-and-wait implementation.
- Make one start call return a ready process. Make one fallible stop call
  complete normal cleanup. Keep `Drop` as an idempotent fallback.
- Put reusable process programs in small files under `fixtures/process`.
  Use actual Python files for identity and direct-runtime process behavior.
  Do not put process programs in Rust strings or shell `-c` arguments. Do not
  add embedded or copied variants.
- Put stateful scenario behavior on its runner or a specific scenario owner.
  Do not move it to a loose `run` function with a list of borrowed owners.
- Keep changed private function names to five or fewer underscore-separated
  components. Keep changed variable names to three or fewer components. Do
  not rename a public production API or a result-schema field for this rule.
- A migrated scenario must be easier to read at its call site. It must show
  the fixture setup, public production operations, physical action, security
  assertions, and stop operation without unrelated orchestration.
- Do not put policy delivery, binding reconciliation, admission, recovery,
  evidence acknowledgement, or another production sequence in a test helper.
- Do not add a fixture trait, builder, macro, scenario registry, or custom
  assertion language.
- Preserve every fail-closed, attribution, lifecycle, replay, and cleanup
  assertion.

## Common tooling deliverable

- [ ] Add one small environment owner for Control, Node, and one actor. Reuse
  existing Control, node, path, cgroup, and process owners inside it.
- [ ] Make Control, Node, and actor start or stop independently so outage and
  restart order stays explicit in each scenario.
- [ ] Keep host and direct-`runc` placement in Rust. Keep Kubernetes placement
  in a small Python harness. Use the same actor file in all three placements.
- [x] Keep one synchronous readiness function with an exact timeout, resource
  path, operation name, and caller-supplied last-state diagnostic.
- [x] Make `ProcessFixture` own spawn readiness, stdin actions, bounded exit
  diagnostics, explicit stop, and idempotent drop cleanup.
- [ ] Remove `NativeProcessFixture`. Move only generic Linux process mechanics
  to `ProcessFixture`; keep identity assertions and production calls in the
  identity scenario.
- [x] Make `RuncContainer` and `ContainerdServer` delegate process lifecycle
  to `ProcessFixture`. Keep runtime protocol and resource cleanup on their
  existing owners.
- [ ] Move the remaining direct-runtime exec children to the shared process
  owner as each entry-role behavior moves to its scenario owner.
- [ ] Replace every embedded native process script with an actual Python file
  in `fixtures/process`.
- [x] Execute the same Python process files from focused identity and direct
  `runc` tests.
- [x] Copy all shared Python process programs into each fresh single-node VM.
- [x] Add fresh-directory construction to the existing `ProbeDirectory`
  owner.
- [x] Keep `ProbeDirectory`, `ProbeFile`, and `ProbeCgroup` cleanup
  idempotent.
- [x] Add small focused tests for successful start and stop, early exit,
  timeout diagnostics, and repeated cleanup.
- [x] Verify with the focused support tests and Mithril e2e clippy before the
  common-tooling commit.

## Baseline reliability failures

The first normal parallel package run outside the sandbox found these existing
fixture failures. Fix and commit each test separately before another complete
physical run:

- [x] `mtls_storage_failure_withholds_ack_until_replay_is_durable`: release the
  first `ControlStore` lease before the scenario reopens the same directory.
- [x] `kubernetes_outage_mtls_session_converges_policy_while_replaying_retained_evidence`:
  make server and connection readiness deterministic and include the server
  result in a connection failure diagnostic.
- [x] `shared_mmap_target_reports_both_unrestricted_controls`: make the child
  readiness and request exchange deterministic without weakening the mmap
  allow assertions.
- [x] `native_process_fixture_reparents_double_fork_child_before_exec`: wait
  for the reparented child to reach stopped state and report its last `/proc`
  status when readiness fails.
- [x] `native_process_fixture_reparents_a_stopped_child_before_exec`: wait for
  the child to reach stopped state before the test reads its parent identity.
- [x] `mtls_evidence_gap_survives_control_restart_and_closes_with_one_ack`:
  wait for the stopped Control server to release its store lease before the
  restart.
- [x] `signed_node_decommission_uses_the_same_durable_mtls_sequence_as_kubernetes`:
  wait for the accepted node session to leave the ready set and report the
  last ready sessions on timeout.
- [x] `control_evidence_queue_reclaims_only_durably_consumed_segments`: wait
  for the last compact owner to release the store lease before reopening it.
- [x] `node_decommission_https_accepts_the_same_signed_artifact_as_control`:
  wait for the HTTPS listener before the first request.
- [x] `mtls_evidence_backlog_exceeds_the_previous_baseline`: the first
  release-mode run measured 103.6 MiB/s against the existing 107.1 MiB/s
  floor. A clean release-mode rerun passed the existing floor.
- [x] `IdentityTestRunner::physical_probe`: wait for the `CLONE_INTO_CGROUP`
  child to enter the target mount namespace and reach the final executable
  before the identity assertion.
- [x] `IdentityTestRunner::physical_probe`: wait for cgroup attachment to
  publish the complete non-leader-thread root identity before asserting it.
- [x] `IdentityTestRunner::physical_probe`: the VM reproduced an unexpected
  moved-task native fork denial. Wait for the fixture input barrier before
  cgroup attachment so the initial exec guard is complete before the fixture
  releases the fork barrier.
- [x] `EffectTestRunner::runc_entry_role_runtime_probe`: two fresh VM runs
  timed out before the direct `runc` `createContainer` request appeared.
  Report runtime process exit and bounded task and containerd output.
- [x] Rerun the direct-runtime lane in a fresh VM with the new diagnostic.
  The `createContainer` request appeared, and the complete schema 38 lane
  passed. No implementation change was required.

## In-process scenario migration ledger

All items in this ledger are reset. Each checkmark requires one verified
scenario commit that reduces orchestration and keeps behavior explicit. A
file move or copied function does not satisfy an item.

### Control and TLS

The shared fixture can own certificates, a ready server address, graceful
shutdown, and shutdown diagnostics. Each test must continue to call
`NodeControlConnector`, `ControlPlane`, policy transfer, evidence upload,
acknowledgement, or decommission operations directly.

- [ ] `mtls_registration_acknowledges_trust_and_reconnects_with_a_fresh_nonce`
- [ ] `mtls_connection_renews_the_ready_session_while_its_owner_is_idle`
- [ ] `mtls_connection_reports_local_readiness_transitions_without_reconnect`
- [ ] `signed_node_decommission_uses_the_same_durable_mtls_sequence_as_kubernetes`
- [ ] `mtls_rejects_wrong_node_binding_and_expired_client_identity`
- [ ] `mtls_evidence_stream_replays_after_disconnect_and_reuses_one_registered_session`
- [ ] `mtls_evidence_gap_survives_control_restart_and_closes_with_one_ack`
- [ ] `mtls_storage_failure_withholds_ack_until_replay_is_durable`
- [ ] `kubernetes_outage_mtls_session_converges_policy_while_replaying_retained_evidence`
- [ ] `kubernetes_outage_partitioned_node_reconnects_to_running_control_and_replaces_predecessor`
- [ ] `kubernetes_outage_retained_evidence_allows_protected_pod_admission`
- [ ] `node_decommission_https_accepts_the_same_signed_artifact_as_control`
- [ ] `mtls_evidence_stream_retains_every_record_across_node_restart_beyond_the_soft_bound`
- [ ] `mtls_evidence_backlog_exceeds_the_previous_baseline`
- [ ] `mtls_coverage_upload_preserves_gap_truth_at_control`
- [ ] `mtls_administrative_services_route_matching_results_and_cancel_waiters`

The following Control tests are already small owner-local checks. Keep them as
regressions and verify them with every Control migration:

- `kubernetes_outage_pending_policy_transfer_preempts_evidence_ack_backlog`
- `kubernetes_outage_retained_control_store_starts_from_latest_state`
- `control_evidence_queue_reclaims_only_durably_consumed_segments`

### Effect child and observation support

- [ ] Replace the repeated child mailbox readiness loop with the shared wait.
- [ ] Replace repeated process and descriptor readiness loops with the shared
  wait. Preserve PID, descriptor, and kernel-result diagnostics.
- [ ] Replace the observation deadline loop with the shared wait. Preserve the
  complete recent-observation summary on failure.

Keep and rerun all 24 focused regressions in `effect/child.rs`,
`effect/mailbox.rs`, `effect/support.rs`, and the four tests at the end of
`effect.rs`. These tests already express one action and one result. Do not
move them into a generic scenario table.

Keep and rerun the two focused `effect/runc.rs` tests and the four focused
`effect/network.rs` tests. These checks validate the fixture boundary without
starting the complete privileged scenarios.

### Native identity fixture checks

- [ ] Replace duplicated native child exit and exec readiness loops with the
  shared wait. Preserve child status and snapshot diagnostics.
- [ ] Delete `NativeProcessFixture` after its generic lifecycle and readiness
  behavior moves to `ProcessFixture`.
- [ ] Replace native child, failed-exec, post-PONR, subreaper, namespace-init,
  orphan, double-fork, leader-first, non-leader, and concurrent-thread shell
  commands with shared Python process files.
- [ ] Keep process transitions in small focused tests. Use `ProcessFixture`
  directly and keep the action and assertion visible.
- [ ] Keep production object allocation and authorization replay tests beside
  their actual runner owner. Do not use orphaned scenario functions.
- [ ] Rerun every focused identity test and the `clone3.rs` test after each
  identity fixture change.

### Compact owner-local checks

No orchestration implementation is required for the 27 compact tests in
`benchmark.rs`, `capability.rs`, `capability_matrix.rs`, `digest.rs`,
`fixture.rs`, `golden.rs`, `loader.rs`, `prototype.rs`, and
`provenance.rs`. They remain required regression coverage. The two small
binary CLI tests also remain required.

## Privileged lightweight scenario migration ledger

Each item keeps the production calls in the scenario and moves only reusable
fixture mechanics. Each item gets its own commit after its focused lightweight
command passes.

### Native identity

- [ ] Probe resources and production owners: own the pin root, lease, cgroup,
  fixture files, and cleanup. Keep `KernelHostOwner`, binding publication,
  native identity activation, recovery, and shutdown visible in the scenario.
- [ ] Binding-gap recovery: keep the terminal binding mutation and both public
  recovery calls explicit. Preserve the fail-closed root assertions.
- [ ] Concurrent external roots: keep both process starts and both complete
  restricted-root identity assertions visible.
- [ ] Cgroup escape and moved-parent fork: keep the physical cgroup move,
  production health reads, fork action, and mismatch assertions visible.
- [ ] `CLONE_INTO_CGROUP`: keep the clone action, namespace transition, exec,
  first-effect action, and exact identity assertions visible.
- [x] Native child exec: keep the fork and exec actions, production identity
  snapshots, and allocation diagnostics visible.
- [x] Non-leader thread exec: remove the loose
  `identity/scenarios/non_leader_exec.rs::run` function. Put scenario state on
  its owner, use `ProcessFixture` and the shared Python file directly, and
  keep exact TID allocation and post-exec assertions visible.
- [x] Pre-PONR failure: use fixture-owned process readiness and keep the
  pending-exec, rollback, and recovery assertions visible.
- [x] Post-PONR failure: use fixture-owned process readiness and keep the
  fatal-state assertions visible.
- [x] Moved-task exec: keep the physical cgroup move, denied exec, production
  health checks, and placement-mismatch assertions visible.
- [x] Orphan transition: use `native_orphan.py` through `ProcessFixture` in
  the focused test and the physical scenario. Preserve the parent, role, and
  execution assertions.
- [x] Subreaper transition: use `native_subreaper.py` through
  `ProcessFixture` in the focused test and physical scenario. Preserve the
  intermediate-parent, adopted-child, role, and execution assertions.
- [x] Namespace-init transition: use `native_namespace_init.py` through
  `ProcessFixture` in the focused test and physical scenario. Preserve the
  namespace PID, parent, role, execution, and tombstone assertions.
- [x] Double-fork transition: replace the embedded shell with one Python
  process file through `ProcessFixture`. Preserve the parent, role, execution,
  and tombstone assertions.
- [ ] Leader-first thread exit and reference lifetime: keep the process and
  entry reference counts, tombstones, release action, and reclamation checks.
- [ ] PID and TID reuse: keep namespace reuse actions and fresh identity checks
  in separate small scenario files.
- [ ] Cgroup lifetime reuse and retained-host restart: keep host shutdown,
  retained map validation, production recovery, recreated cgroup, and fresh
  binding identity assertions visible.

### Kernel and host lifecycle

- [ ] `KernelQualificationRunner::physical_file_open_probe`: own the lease
  and output paths with existing cleanup owners. Keep
  `BpfQualificationLoader` attachment and shutdown explicit.
- [ ] `HostLifecycleRunner::host_lifecycle`: own the pin root and lease, use
  readiness diagnostics, and keep both `KernelHostOwner` starts and the
  concurrent-owner rejection explicit.

### Effect enforcement

- [ ] `EffectTestRunner::replacement_generation_exception_probe`: own
  fixture paths and child lifetime. Keep policy installation, exact exception
  use, exhaustion denial, evidence checks, and shutdown explicit.
- [ ] `EffectTestRunner::physical_probe` setup and teardown: own its three
  cgroups, child processes, pin root, lease, and diagnostic output.
- [ ] `EffectTestRunner::physical_probe` observe scenario: keep the public
  node policy, binding, reader, action, and evidence operations explicit.
- [ ] `EffectTestRunner::physical_probe` protect scenario: keep every hard
  denial, allow control, loss counter, and evidence assertion.
- [ ] `EffectTestRunner::physical_probe` mount mutation cases: keep each
  production reconciliation call and mount syscall action visible.
- [ ] `EffectTestRunner::physical_probe` process, descriptor, network, and
  `io_uring` cases: retain exact task and object attribution assertions.

### Network

- [ ] `run_network_peer_server`: own ready-file publication, bounded wait,
  socket lifetime, and result cleanup.
- [ ] `NetworkTestRunner::physical_probe` setup and teardown: own fixture,
  transport, cgroup, nftables, pin, lease, and peer-process cleanup.
- [ ] `NetworkTestRunner::physical_probe` local socket scenarios: keep signed
  policy compilation, node binding, socket actions, and exact denials visible.
- [ ] `NetworkTestRunner::physical_probe` two-node peer scenario: keep the
  same TCP, UDP, and denied-port operations as `two-node-network.sh`.

### Direct runtime

- [ ] `EffectTestRunner::runc_retained_runtime_gate_probe`: own the bundle
  and marker cleanup. Keep the production OCI hook invocation for hostile,
  CRI, installer, recovery, and host-stock shapes explicit.
- [ ] `EffectTestRunner::recovered_container_entry_probe` setup and
  teardown: own containerd, `runc`, trace, pin, lease, cgroup, and fixture
  resources.
- [ ] Recovered-container publication: keep
  `NodeBindingReconciliation::reconcile` and the public recovered-root
  publication operation visible.
- [ ] Recovered-container cutover and task-change retry: keep the same
  production recovery operation and oracles as the Kubernetes lane.
- [ ] Recovered-container application, external, and declared-probe entries:
  keep each stock runtime action and exact role, rule, and denial assertion.

### Direct runtime entry roles

The current result schema stays unchanged. Migrate one behavior group per
commit so the approximately 4,000-line scenario does not move as one block.
Small scenario files are preferred when one file can contain its fixture
setup, production actions, assertions, and focused test.

- [ ] Fixture construction: create the rootfs, runtime paths, bind mounts,
  output files, containerd owner, `runc` owner, pin root, lease, and cleanup
  in a fixture. Do not install policy or reconcile bindings in this fixture.
- [ ] Unprotected control and prepared-container start: keep the stock runtime
  calls and `PREPARED` assertions in the scenario.
- [ ] Held OCI route publication: keep policy installation, background binding
  reconciliation, `createContainer`, route publication, and activation calls
  in their real order through public production APIs.
- [ ] Initial application activation: keep the entry action and `ACTIVE`,
  role, rule, default-effect, and large-argv assertions explicit.
- [ ] Kubernetes subpath, bind alias, and wildcard paths: keep the same mount
  order and protected reads as the Kubernetes workload.
- [ ] Concurrent exec and reader-queue saturation: keep the same containerd
  exec operation, topology snapshots, bounded queue, and fail-closed results
  as `two-node-convergence.sh`.
- [ ] Stale cache repair and unreachable-row retirement: keep the production
  node reconciliation calls and exact map absence checks visible.
- [ ] Independent additional entries and reusable PostStart entry: keep each
  declaration, stock exec, role, rule, process state, and isolation assertion.
- [ ] Declared probe mismatch and runtime infrastructure effects: keep exact
  argv, role-zero, and denial evidence checks.
- [ ] Live policy replacement: keep delivery, acknowledgement, guarded process
  migration, later exec, and old-generation holder checks explicit.
- [ ] Administrative exec: keep Control authorization, node slot arm, stock
  runtime exec, one-use consumption, replay denial, trace, and reconciliation
  operations explicit.
- [ ] Node restart and PreStop retention: keep the public restart, inventory,
  binding, and lifecycle operations explicit.
- [ ] Kernel object upgrade: keep the second production object, manifest, map
  ID, link pin, program tag, and running-identity checks explicit.
- [ ] Post-point-of-no-return evidence and generation retirement: keep the
  terminal exec, evidence retention, holder release, and absence proof.
- [ ] External entry and external cgroup entrant: keep both physical execs and
  rule-zero fail-closed evidence assertions.
- [ ] Final container and resource cleanup: require container success and
  absence of the pin root, lease, cgroup, and fixture root.

### Native and Kubernetes identity

- [ ] `IdentityTestRunner::physical_probe` setup and teardown: own native
  child processes, files, cgroups, pin roots, leases, and diagnostic artifacts.
- [ ] Migrate native binding-gap, external ambiguity, cgroup escape, fork,
  exec, reparent, PID reuse, owner restart, object upgrade, and authorization
  replay groups one commit at a time. Keep their `KernelHostOwner`,
  `WorkloadBindingOwner`, and `NativeSecurityStateOwner` calls explicit.
- [ ] `physical_kubernetes_exec_probe`
- [ ] `physical_kubernetes_lifecycle_sleep_probe`
- [ ] `physical_kubernetes_containers_probe`
- [ ] `physical_kubernetes_ephemeral_probe`
- [ ] `physical_kubernetes_probe_impersonation`
- [ ] `physical_kubernetes_prestop_probe`
- [ ] `physical_kubernetes_poststart_probe`
- [ ] `physical_kubernetes_stock_hook_failure_probe`
- [ ] `physical_kubernetes_resilience_probe`
- [ ] `physical_kubernetes_network_probe`

Each Kubernetes identity case must keep the `k3s`, CRI, OCI hook, node
process, and public production-owner operations that its physical harness
uses.

## Required pre-TODO test baseline

Commit `95775f48f2ed9864ecbc40219c3ecf79a51a0ee7` is the source baseline
immediately before this work. It contains 90 library tests and two binary
tests. All 92 test names remain present. Preserve the behavior behind every
entry when a test receives a shorter name or moves beside its real owner.

- `benchmark.rs::benchmark_records_every_open_sample_at_requested_concurrency`
- `benchmark.rs::benchmark_validation_accepts_json_rate_and_rejects_changed_rate`
- `benchmark.rs::benchmark_validation_rejects_changed_raw_samples`
- `bin/mithril_effect_test.rs::outer_process_id_is_available`
- `bin/mithril_kernel_qualification.rs::physical_record_command_requires_all_evidence_paths`
- `capability.rs::every_checked_in_vmlinux_header_compiles_the_feasibility_object`
- `capability.rs::every_checked_in_vmlinux_header_compiles_the_production_identity_object`
- `capability.rs::platform_probe_reports_bpf_lsm_as_a_measured_prerequisite`
- `capability.rs::qualification_object_compiles_against_the_checked_in_vmlinux_header`
- `capability_matrix.rs::every_allocated_surface_is_supported_or_explicitly_unsupported`
- `control_tls.rs::control_evidence_queue_reclaims_only_durably_consumed_segments`
- `control_tls.rs::kubernetes_outage_mtls_session_converges_policy_while_replaying_retained_evidence`
- `control_tls.rs::kubernetes_outage_partitioned_node_reconnects_to_running_control_and_replaces_predecessor`
- `control_tls.rs::kubernetes_outage_pending_policy_transfer_preempts_evidence_ack_backlog`
- `control_tls.rs::kubernetes_outage_retained_control_store_starts_from_latest_state`
- `control_tls.rs::kubernetes_outage_retained_evidence_allows_protected_pod_admission`
- `control_tls.rs::mtls_administrative_services_route_matching_results_and_cancel_waiters`
- `control_tls.rs::mtls_connection_renews_the_ready_session_while_its_owner_is_idle`
- `control_tls.rs::mtls_connection_reports_local_readiness_transitions_without_reconnect`
- `control_tls.rs::mtls_coverage_upload_preserves_gap_truth_at_control`
- `control_tls.rs::mtls_evidence_backlog_exceeds_the_previous_baseline`
- `control_tls.rs::mtls_evidence_gap_survives_control_restart_and_closes_with_one_ack`
- `control_tls.rs::mtls_evidence_stream_replays_after_disconnect_and_reuses_one_registered_session`
- `control_tls.rs::mtls_evidence_stream_retains_every_record_across_node_restart_beyond_the_soft_bound`
- `control_tls.rs::mtls_registration_acknowledges_trust_and_reconnects_with_a_fresh_nonce`
- `control_tls.rs::mtls_rejects_wrong_node_binding_and_expired_client_identity`
- `control_tls.rs::mtls_storage_failure_withholds_ack_until_replay_is_durable`
- `control_tls.rs::node_decommission_https_accepts_the_same_signed_artifact_as_control`
- `control_tls.rs::signed_node_decommission_uses_the_same_durable_mtls_sequence_as_kubernetes`
- `digest.rs::sha256_digest_uses_fixed_lowercase_hex`
- `effect.rs::kubernetes_mount_attack_matches_the_lightweight_security_boundary`
- `effect.rs::local_enforcement_results_close_every_owned_fixture_exactly_once`
- `effect.rs::runtime_entry_process_control_is_durable_with_exact_target`
- `effect.rs::static_effect_classification_covers_every_branch_without_physical_claims`
- `effect/child.rs::abstract_unix_stream_control_does_not_create_a_file`
- `effect/child.rs::anonymous_mapping_controls_work_without_policy`
- `effect/child.rs::batch_average_uses_every_attempt`
- `effect/child.rs::deleted_executable_fixture_retains_its_descriptor_and_mapping`
- `effect/child.rs::hard_denial_accepts_only_permission_errors`
- `effect/child.rs::native_exec_and_descriptor_transfer_controls_work_without_policy`
- `effect/child.rs::network_chain_keeps_file_read_results_separate`
- `effect/child.rs::prepared_file_fixture_can_read_and_map_before_policy_activation`
- `effect/child.rs::prepared_write_race_releases_every_preallocated_worker`
- `effect/child.rs::process_control_target_is_live_until_its_owner_releases_it`
- `effect/child.rs::ptmx_ioctl_requires_success_and_kernel_output`
- `effect/child.rs::queued_descriptor_controls_arrive_in_declared_order`
- `effect/child.rs::raw_bpf_map_create_attributes_match_the_linux_uapi_prefix`
- `effect/child.rs::shared_mmap_target_reports_both_unrestricted_controls`
- `effect/mailbox.rs::shared_mappings_round_trip_without_stream_io`
- `effect/network.rs::network_fixture_matrix_requires_physical_proof`
- `effect/network.rs::network_peer_server_requires_controls_and_denied_absence`
- `effect/network.rs::signed_network_fixture_compiles_before_physical_use`
- `effect/network.rs::signed_network_fixture_compiles_two_node_peer`
- `effect/runc.rs::normal_path_tree_denial_requires_the_application_read_identity`
- `effect/runc.rs::runc_seccomp_fixture_binds_inside_its_runtime`
- `effect/support.rs::enforcement_fixture_is_a_verified_protect_artifact`
- `effect/support.rs::exact_observation_match_rejects_the_same_reason_from_another_hook`
- `effect/support.rs::health_delta_preserves_ring_accounting`
- `effect/support.rs::io_uring_match_requires_exact_worker_request_identity`
- `effect/support.rs::object_match_requires_the_selected_exact_or_unsupported_identity`
- `fixture.rs::safe_fixture_has_exact_stages_replay_nodes_and_unchanged_digest`
- `golden.rs::cfg_rollback_golden_rejects_replay_and_corruption`
- `golden.rs::cfg_v1_golden_is_closed_deterministic_and_chassis_only`
- `golden.rs::decision_set_golden_matches_closed_rust_and_c_layout`
- `identity.rs::authorization_replay_fixture_persists_exact_rejections_and_fresh_control`
- `identity.rs::leader_first_fixture_keeps_the_worker_until_release`
- `identity.rs::native_process_fixture_executes_after_namespace_init_reparenting`
- `identity.rs::native_process_fixture_executes_after_subreaper_reparenting`
- `identity.rs::native_process_fixture_executes_non_leader_thread`
- `identity.rs::native_process_fixture_races_two_thread_execs`
- `identity.rs::native_process_fixture_recovers_from_bash_execfail`
- `identity.rs::native_process_fixture_reparents_a_stopped_child_before_exec`
- `identity.rs::native_process_fixture_reparents_double_fork_child_before_exec`
- `identity.rs::native_process_fixture_reports_failed_exec`
- `identity.rs::native_process_fixture_waits_for_stopped_child_before_exec`
- `identity.rs::post_ponr_fixture_terminates_the_exec_process`
- `identity.rs::production_object_and_identity_fixture_allocation_are_exact`
- `identity/clone3.rs::clone_into_cgroup_fixture_recognizes_childless_eacces_exit`
- `loader.rs::changed_digest_and_stale_pin_root_fail_before_privileged_load`
- `loader.rs::direct_libbpf_inspection_validates_the_owned_feasibility_object`
- `prototype.rs::bounded_component_graph_never_truncates_or_chooses_conflicting_authority`
- `prototype.rs::jailer_task_alloc_copies_parent_before_first_child_effect`
- `prototype.rs::meta_bind_alias_resolves_through_the_oldest_mount`
- `prototype.rs::meta_mutation_guard_requires_one_stable_live_snapshot`
- `prototype.rs::source_ka_capacity_n_plus_one_denies_without_corrupting_existing_rows`
- `prototype.rs::source_ka_dns_bounds_never_truncate_to_a_name`
- `prototype.rs::source_ka_partial_publication_keeps_the_complete_old_generation`
- `prototype.rs::source_ka_reader_loss_never_changes_an_installed_deny`
- `prototype.rs::source_tg_exec_map_requires_one_exact_stage_even_for_non_leader_exec`
- `prototype.rs::source_tg_path_rename_preserves_prior_denial_and_argument_order`
- `prototype.rs::source_tg_runtime_join_accepts_only_authenticated_complete_fresh_roots`
- `provenance.rs::dossier_closes_sources_licenses_owners_and_hostile_fixtures`

The current tree also has eighteen reliability and common-owner tests added
after the baseline. Preserve them while the structural changes are replaced:

- `effect/runc/process.rs::exit_reports_output`
- `effect/runc/process.rs::runc_uses_python_actor`
- `identity/native_process/tests.rs::startup_reports_exit`
- `identity/scenarios/exec/tests.rs::thread_execs_process`
- `identity/scenarios/exec/tests.rs::child_execs`
- `identity/scenarios/exec/tests.rs::exec_failure_stops`
- `identity/scenarios/exec/tests.rs::exec_recovers`
- `identity/scenarios/exec/tests.rs::fatal_exec_kills_actor`
- `identity/scenarios/exec/tests.rs::child_execs_after_orphan`
- `identity/scenarios/exec/tests.rs::threads_race_exec`
- `identity/scenarios/reparent/tests.rs::child_execs_after_subreaper`
- `identity/scenarios/reparent/tests.rs::child_execs_after_namespace_init`
- `identity/scenarios/reparent/tests.rs::child_execs_after_double_fork`
- `physical.rs::async_readiness_yields_until_the_fixture_is_ready`
- `physical.rs::readiness_reports_diagnostics_and_directory_cleanup_is_idempotent`
- `process/tests.rs::exit_reports_stderr`
- `process/tests.rs::python_start_stop`
- `process/tests.rs::stop_kills_actor`

## Documentation deliverable

- [ ] Add a short scenario recipe to `crates/mithril-e2e/README.md`.
- [ ] Show one small in-process test and one small running-container scenario.
- [ ] State which code belongs in a fixture and which production calls must
  stay in the scenario.
- [ ] Document focused unit, local harness, lightweight VM, paired Kubernetes,
  and full repository commands.

## Verification order

Run the smallest applicable command after each scenario migration. Run later
commands only after the earlier layer passes.

```text
cargo test -p mithril-e2e <exact-test-name> -- --exact
  -> cargo test -p mithril-e2e
  -> bash crates/mithril-e2e/harness/vm/test.sh
  -> bash crates/mithril-e2e/harness/vm/run.sh --entry-role-runtime-only ...
  -> bash crates/mithril-e2e/harness/vm/two-node-convergence.sh --protected-start-only ...
  -> bash crates/mithril-e2e/harness/vm/two-node-network.sh ...
  -> bash .github/scripts/verify-rust-ci.sh
```

The lightweight case must pass before its paired Kubernetes case. If
Kubernetes finds a condition that the lightweight case did not detect, stop.
Add the exact condition and expected result to lightweight qualification. Make
that case pass before an implementation change or Kubernetes retry.

## Commit rule

Commit the common tooling after its focused checks pass. Then commit each
small scenario or behavior group separately after its focused lightweight
check passes. Do not combine all scenario migrations into one commit.
