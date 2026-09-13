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

## Binding acceptance rules

These rules control every checkmark and commit in this file.

### Scenario shape

- Write each behavior as one small Rust function in its scenario module. A
  scenario module can contain as many real test functions as it needs.
- Mark a cross-environment function with
  `#[platform_test(host, runc, kubernetes)]`. List only the platforms that the
  behavior supports. The attribute must generate one standard `#[test]` case
  for each listed platform from the same function body.
- Give the function one generic `Platform` type parameter. Implement `Host`,
  `Runc`, and `Kubernetes` once in common fixture tooling. A scenario module
  must not contain a platform implementation or branch. Do not read an
  environment variable to dispatch inside the test. Do not copy the test body
  into platform modules.
- Treat every `impl Platform` block as custom platform code. Keep it out of
  scenario modules. It can contain reusable physical setup and lifecycle
  mechanics only. It must not contain a scenario or a production operation
  sequence.
- Keep a source file that contains one test below 100 lines. Put no platform
  runner functions in that file.
- Give each scenario Control, Node, and one Python actor process.
- Place the actor explicitly on the host, in `runc`, or in Kubernetes.
- Make `start_actor` create the environment and start the actor as PID 1 in
  its PID namespace or container. It must not enter an already-running
  environment.
- Use `add_actor` only when the behavior requires a process to enter an
  already-running namespace or container. Host, direct-`runc`, and Kubernetes
  implementations must use their real process-entry mechanism. Keep this
  behavior in a separate test from initial actor startup.
- Ask the actor to perform one action. Assert the expected production result.
- Keep component start, stop, outage, and restart order visible in the test.
- Test each supported component order in a separate function. Do not make a
  Node-first admission test pass by starting its actor before Node. Do not
  replace a workload-first recovery test with a Node-first test.
- Make setup, action, assertion, and teardown easy to identify.
- Prefer one security behavior per test and one responsibility per file. A
  focused file can contain several related real tests.
- Use only the `platform_test` attribute for cross-environment test
  registration. It can validate the function shape and generate named test
  cases. It must not contain scenario logic.
- Put reusable physical setup, async execution, result output, and cleanup in
  the common platform implementations. Do not put scenario actions or
  production operation sequences in those implementations. Keep actor
  behavior and result assertions shared.
- Do not build or drive an async runtime in a test function. The selected
  physical fixture owns the runtime when its production APIs require async
  work.
- Dismantle `IdentityTestRunner::physical_probe` and the other monolithic
  probes one verified scenario at a time. Moving their bodies is not enough.

The required test shape keeps the behavior visible. This example shows the
attribute and generic platform shape:

```rust
#[platform_test(host, runc, kubernetes)]
fn secret_read_is_denied<P: Platform>() -> TestResult<()> {
    let result = P::read_secret()?;
    result.assert_denied();
    result.save()
}
```

The platform implementation uses the public production operation. It owns
physical setup, readiness, the async runtime, and cleanup. It must not
reimplement a production owner operation.

### Rust test execution

- Use the standard Rust test harness. `cargo test --no-run` must compile the
  scenario functions into a test executable.
- Keep the attributed function in the behavior module. The launcher invokes
  its exact generated case, such as `secret_read_is_denied::kubernetes`.
- Mark tests that need root, BPF LSM, `runc`, containerd, or Kubernetes with a
  precise `#[ignore = "..."]` reason when the normal host cannot run them.
- Make the VM harness copy the compiled test executable and run each
  privileged test by its exact test name.
- Keep ordinary lightweight scenarios as non-ignored `#[test]` functions.
- Do not add a custom test registry, test language, or replacement harness.
- Do not add scenario-specific tests that only prove Python actor behavior.
  The production-backed scenario must prove the actor transition and the
  Mithril result together.
- Keep only generic `ProcessFixture` tests for start readiness, diagnostics,
  process control, stop, and idempotent cleanup.
- A compatibility artifact writer can serialize scenario results. It must not
  execute a hidden scenario or own setup, action, assertion, or teardown.

### Cross-environment test shape

- Keep each migrated behavior as one small attributed Rust function. The
  attribute generates its standard Rust `#[test]` cases.
- Use one Python actor file for the same behavior on the host, in direct
  `runc`, and in Kubernetes.
- Use one Rust result type and one Rust assertion function for the meaningful
  result fields in all applicable environments.
- Let the platform parameter select host, direct-`runc`, or Kubernetes
  resource placement and lifecycle setup. Environment setup can change paths,
  process placement, and component availability only.
- In the Kubernetes form, send external runtime input to the deployed Node.
  Do not instantiate `WorkloadBindingOwner` or `NativeSecurityStateOwner`
  in the test process as a substitute for that Node. The deployed Node must
  perform binding publication, prepared activation, recovery, and policy
  reconciliation through its production CRI, OCI, and Control paths.
- Use the existing Helm chart for the Control Deployment, Node DaemonSet,
  Service, RBAC, webhooks, CRDs, and runtime-hook installation. Do not build
  these resources as JSON in a test.
- Keep VM, K3s, OCI-hook, Helm, and image preparation in infrastructure
  setup. The Kubernetes Rust platform must not install, restart, or remove
  K3s. It must not build, import, tag, or repair an image. It can verify that
  the prepared cluster and required images are ready before a test starts.
- Retain K3s, its OCI hook, and its prepared image cache between focused Rust
  test runs. Recreate them only when the operator requests a clean environment
  or readiness proves that the retained environment is unusable.
- Keep the Node config, Control config, policy, PVC, and actor Pod as checked
  fixture documents. Bind only run-specific paths, names, images,
  certificates, and trust data in the platform fixture. The chart consumes
  the Node config by host path and the Control config by Secret; it does not
  generate either config from Helm values.
- Lightweight and direct-`runc` forms can call public production owners
  directly. Keep those calls visible in the test and require the same
  meaningful state transitions as the Kubernetes form.
- Do not make a host-only `TestEnv` the scenario API. A shared scenario must
  be able to use the result from each applicable physical environment.
- Keep the VM and Kubernetes launchers thin. They can copy inputs, create the
  environment, pass paths, and invoke the exact standard Rust test. They must
  not duplicate scenario assertions or Mithril production sequencing.
- Use one platform fixture trait and one `platform_test` attribute. The
  attribute arguments are the only platform selection point. Do not add a
  runtime dispatcher, backend registry, factory, option layer, or scenario
  language.

### Production behavior

- Call public `mithril-control`, `mithril-node`, and Interceptor owner APIs.
- Exercise real processes, syscalls, runtimes, identities, policies, evidence,
  and decisions when the scenario covers them.
- Do not reproduce policy delivery, binding reconciliation, identity
  publication, recovery, admission, or evidence acknowledgement in a helper.
- Use the same production operations and meaningful state transitions in the
  lightweight, direct-`runc`, and Kubernetes forms of one behavior.
- Allow environment identities and timestamps to differ. Require decisions
  and meaningful result fields to match.
- Keep production architecture and public result schemas unchanged.

### Shared fixtures

- Use `ProcessFixture` as the only process lifecycle owner for host, `runc`,
  and containerd scenarios.
- Use the same Python actor file in every applicable host, `runc`, and
  Kubernetes scenario.
- Put actor programs in `fixtures/process`. Do not embed shell or Python
  source in Rust.
- Do not keep separate native and `runc` process wrappers.
- Make one start call return a ready actor.
- Make one fallible stop call perform normal cleanup. Use `Drop` only as an
  idempotent fallback.
- Bound every readiness wait. Report the operation, resource path, last state,
  process exit status, and captured stderr when applicable.
- Keep setup, stop, restart, and teardown simple in every scenario.

### Structure and readability

- Do not accept a file move or split when orchestration stays difficult to
  read or extend.
- Put stateful behavior on one concrete fixture or scenario owner. Do not add
  orphaned stateful free functions.
- Do not split one owner's implementation across unrelated files.
- Do not add traits, builders, registries, macros, factories, backend
  matrices, or a custom scenario language beyond the required platform trait
  and `platform_test` attribute.
- Reuse existing owners, the Rust standard library, and standard Linux
  mechanisms before adding code.
- Keep security and lifecycle assertions explicit in the test.
- Prefer deletion and direct code over speculative abstractions.

### Size and naming

- Keep every Rust source file under `crates/mithril-e2e` below 2,000 lines at
  delivery.
- Prefer small test files and small responsibility-focused scenario files.
- Keep changed private function names to four or five underscore-separated
  components at most.
- Keep changed variable names to three underscore-separated components at
  most.
- Do not rename a public production API or public result field only to meet a
  naming limit.

### Coverage and reliability

- Preserve meaningful fail-closed, attribution, identity, lifecycle, replay,
  cleanup, and security assertions.
- Preserve the reliability fixes found before this acceptance reset.
- Compare coverage with pre-TODO commit
  `95775f48f2ed9864ecbc40219c3ecf79a51a0ee7`.
- A baseline test name can disappear only after its behavior and assertions
  move into a production-backed scenario. Record the replacement in this
  file. Do not keep a duplicate actor-only test.
- Replace every rejected move-only structural refactor from the earlier work.
- A generic fixture test supplements production coverage. It does not replace
  a production-backed scenario.

### Incremental workflow

- Keep this TODO inventory complete and current.
- Implement and verify shared tooling before a dependent scenario.
- Migrate one behavior at a time. Do not move all scenarios in one commit.
- Run the smallest exact test first. Then run related tests, harness checks,
  formatting, clippy, and the complete lightweight suite.
- Commit each verified behavior separately.
- Do not stage `.agents/planning.md` or unrelated files.

### Kubernetes gate

- Pass the lightweight scenario before its paired Kubernetes scenario.
- If Kubernetes exposes a missing condition, reproduce that exact condition
  in lightweight first.
- Fix implementation only after the lightweight reproduction exists.
- Rerun lightweight before Kubernetes.
- Pass the complete lightweight and Kubernetes suites before delivery.

### Final delivery

- Document how to add and run a scenario.
- Include a short plan and one concrete before-and-after scenario example.
- Document exact focused, local harness, VM, Kubernetes, and full-suite
  commands.
- Use direct ASD-STE100 text in documents and changed comments.
- Do not complete the excluded product phase.
- Do not claim completion until every Rust source file is below 2,000 lines
  and all required lightweight and Kubernetes checks pass.

## Baseline measured suite

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

## Current compliance audit

The current tree does not meet the size or naming gates. Do not mark the work
complete while these entries remain.

These Rust files exceed 2,000 lines:

| Source | Current lines |
| --- | ---: |
| `effect/runc.rs` | 8,343 |
| `identity.rs` | 7,688 |
| `effect.rs` | 5,118 |
| `effect/child.rs` | 4,472 |
| `control_tls.rs` | 2,734 |
| `effect/network.rs` | 2,329 |

The diff from `95775f48` adds or relocates these private test functions with
more than five name components:

- `authorization_replay_fixture_persists_exact_rejections_and_fresh_control`
- `production_object_and_identity_fixture_allocation_are_exact`
- `kubernetes_network_probe_container_no_task`

The same diff adds or relocates these local variables with more than three
name components:

- `clone_child_mount_namespace_path`
- `clone_child_mount_namespace`
- `clone_child_comm_path`
- `clone_native_child_after_namespace_move`
- `clone_child_mount_namespace_after`
- `cgroup_escape_unmoved_control`
- `cgroup_escape_unmoved_root`
- `health_before_cgroup_escape`
- `health_after_cgroup_escape`
- `health_after_cgroup_escape_effect`
- `clone_first_effect_fixture`
- `clone_into_cgroup_first_effect_root`
- `clone_into_cgroup_first_effect_child_pid`
- `clone_into_cgroup_first_effect_child`
- `profile_task_refs_after_exit`
- `cgroup_reuse_first_root_id`
- `cgroup_reuse_first_binding`
- `retired_pin_root_owner_rejected`
- `live_manifest_mismatch_detected`
- `map_ids_stable_across_restart`
- `cgroup_reuse_second_root`
- `cgroup_reuse_second_root_id`
- `cgroup_reuse_second_binding`
- `cgroup_reuse_fresh_identity`
- `allowed_before_target_install`
- `denied_after_target_install`
- `allowed_after_target_clear`

Public production fields and public result-schema fields are excluded from
this audit. Shorten or delete every listed private identifier as its owning
behavior is replaced. Do not add a new violation in an intermediate commit.

## Physical harness migration audit

The audited VM and Kubernetes shell harness contains 10,533 lines in 14 files.
These files provision environments, execute scenarios, parse production
results, and assert security behavior. The mixed ownership must be removed one
scenario at a time.

| Source | Lines | Current responsibility | Required end state |
| --- | ---: | --- | --- |
| `harness/vm/run.sh` | 732 | Builds one VM, runs native, direct-`runc`, and Kubernetes probes, checks JSON, and checks cleanup | Provision the VM, copy inputs, invoke exact Rust tests, collect diagnostics, and remove resources only |
| `harness/vm/test.sh` | 791 | Tests shell text, fake Kubernetes oracles, cleanup, and provider wiring | Test only launcher argument, provider, and cleanup behavior that must remain in shell |
| `harness/vm/guest.sh` | 1,764 | Installs K3s and its hook, then owns K3s qualification, CRI effect, and administrative-exec scenarios | Install or remove K3s and the runtime hook, then invoke exact Rust tests |
| `harness/vm/two-node-convergence.sh` | 4,371 | Provisions two nodes and owns policy, runtime, effect, exception, restart, upgrade, and cleanup assertions | Provision or reuse two nodes, deploy Mithril, invoke exact Rust tests, collect diagnostics, and clean up only |
| `harness/vm/two-node-outage-recovery.sh` | 1,115 | Owns Control, storage, network, API, watch, WAL, replay, and recovery scenarios | Apply the requested outage, invoke its exact Rust test, restore the environment, and collect diagnostics only |
| `harness/vm/two-node-network.sh` | 342 | Provisions two nodes and owns both network directions and result assertions | Provision the nodes and invoke one exact Rust test for each direction |
| `harness/kubernetes-oracles.sh` | 497 | Parses Kubernetes and Mithril state and owns scenario assertions | Delete each oracle after its assertion moves to the responsible Rust result owner |
| `harness/vm/concurrent-exec-overlap.sh` | 76 | Starts concurrent containerd exec actions and asserts their results | Replace it with the shared actor and a Rust Kubernetes physical setup owner |
| `harness/vm/convergence-cleanup.sh` | 89 | Collects diagnostics and removes the Helm release | Keep only bounded diagnostics and idempotent launcher cleanup |
| `harness/vm/clock.sh` | 20 | Checks guest clock readiness | Keep as environment readiness while the VM launcher owns clock correction |
| `harness/vm/runtime-hook-oracle.sh` | 172 | Checks installed, retained, and removed runtime-hook resources | Keep installation readiness only; move runtime decisions to Rust tests |
| `harness/vm/providers/libvirt.sh` | 264 | Owns VM lifecycle and file transport | Keep as the environment provider |
| `harness/vm/oidc-fixture.py` | 159 | Supplies the external OIDC test service | Keep as an external input; move approval assertions to Rust |
| `harness/vm/manual.sh` | 141 | Opens a retained operator environment | Keep separate from automated qualification |

### Tetragon patterns to use

The local Tetragon tree at commit `dbb59576f` uses its standard Go test
binary as the test authority in Kubernetes and kernel VMs. Its outer runners
provision an environment, install the product, invoke selected tests, retain
diagnostics on failure, and report test-harness results. The tests use the
Kubernetes client and production agent endpoints for actions and assertions.

Use these patterns:

- [ ] Run the same standard Rust test executable on the local host, in a kernel
  VM, and against a Kubernetes cluster.
- [ ] Use `platform_test` to generate each environment case from the same
  function. Keep the scenario name, actor action, result type, and result
  assertions unchanged.
- [ ] Let the launcher select exact test names and pass environment inputs.
  Do not let it parse Mithril domain results.
- [ ] Let each Kubernetes Rust test use the existing `kube` client dependency
  for Pod, policy, outage, and lifecycle actions.
- [ ] Connect result checks to the deployed Control and Node endpoints. Do not
  replace a deployed owner with an in-process test owner.
- [ ] Start bounded result observation before the actor action when ordering
  matters.
- [ ] Create one namespace or resource set per test. Delete it with a bounded
  wait.
- [ ] Retain bounded logs, owner state, Kubernetes events, and last observed
  values on failure. Remove successful-test artifacts unless retention is
  requested.
- [ ] Keep actor programs separate from test orchestration and reuse the same
  actor across applicable environments.
- [ ] Let a launcher attach to an existing cluster or provision a temporary
  cluster without changing the test body.

Do not copy Tetragon's feature builders, global runner, event-checker language,
or option layers. Mithril uses direct `#[test]` functions and small concrete
fixtures.

### Required Kubernetes Rust scenarios

Replace each group below with small standard Rust `#[test]` functions. One
focused module can contain several related tests. Each test uses the same
actor and shared result assertions as its lightweight pair.

Single-node and guest cases:

- [ ] K3s and CRI readiness: use a real Pod, containerd ID, image digest,
  workload root, projected token, and overlay snapshotter.
  - [x] Keep archive import out of Rust. Use the small infrastructure image
    helper to install the Control, Node, and actor archives in the persistent
    K3s image store. The Rust platform only verifies each required image
    before use. Both actor-first and Node-first order pass.
  - [ ] Make the thin retained-VM launcher call the image helper once before
    its first exact Rust test when an image is absent. Keep K3s, its OCI hook,
    and its prepared images between test runs. Do not uninstall K3s or import
    unchanged archives between exact tests.
  - [x] Require lightweight and Kubernetes cleanup to prove that Node removed
    both runtime sockets. The Kubernetes `preStop` hook must close admission
    and seccomp endpoints before the termination deadline.
  - [x] Remove the Node selector and runtime integration before Helm removes
    the Control volume. Wait for the retained K3s API, and require no test
    namespace, volume, helper Pod, or runtime hook after teardown.
- [ ] CRI effect recovery: start the Pod before Node, require conservative
  initial identity, recover the running binding, and check direct-CRI and
  Kubernetes exec identities and effects.
- [ ] Administrative exec: use real Control, Node, OIDC, TokenReview,
  admission, approval, one-use slot consumption, replay denial, and restricted
  direct-runtime fallback.
- [ ] Replace native, direct-`runc`, kernel, local-effect, and local-network CLI
  probes in `run.sh` with exact standard Rust test invocations as their
  scenario owners migrate.

Two-node convergence cases:

- [ ] Node projection, scheduler selection, exact policy delivery, and exact
  runtime target.
- [ ] Node-first create admission, held runtime release, prepared activation,
  and first application effect.
- [ ] Workload-first running-container recovery and task-change retry.
- [ ] Application, external, lifecycle, probe, PostStart, PreStop, and
  administrative entry roles.
- [ ] Incomplete declared-probe argv and unmatched entry denials.
- [ ] Concurrent containerd exec, reader saturation, fail-closed effects, and
  unchanged mount topology.
- [ ] Stale mount-cache repair and unreachable-row retirement.
- [ ] Runtime hook installer, forged installer, retained recovery, and binary
  upgrade decisions.
- [ ] Live policy replacement, running task migration, predecessor retention,
  and acknowledgement.
- [ ] One-use, overlap, expiry, revocation, maximum-bound, recreation, and
  target-retirement exception behavior.
- [ ] Unavailable runtime-admission endpoint denial and later release.
- [ ] Container restart with fresh runtime binding, prepared entry, and task
  identity.
- [ ] Node process restart with active policy and runtime binding recovery.
- [ ] Node UID replacement, unready-node quarantine, and DaemonSet selector
  derivation.
- [ ] Host reboot with a new boot identity, label epoch, Pod UID, and root
  policy chain.
- [ ] Control restart, desired-inventory cleanup, stale-close non-replay, and
  fresh root activation.

Two-node outage cases:

- [ ] Control outage keeps local denial active and blocks new protected Pods.
- [ ] Node WAL retains unacknowledged evidence across a Node restart and
  truncates only after the Control acknowledgement.
- [ ] Control storage failure withholds acknowledgement and replays the exact
  retained evidence after storage recovery.
- [ ] Node-to-Control network partition keeps the predecessor policy, then
  converges the replacement after reconnect.
- [ ] Kubernetes API outage keeps worker denial active and converges after the
  API returns.
- [ ] Compacted and interrupted Kubernetes watches relist without restarting
  Control and do not replay a deleted policy UID.

Two-node network cases:

- [ ] Node A to Node B uses the shared network actor and Rust result
  assertions.
- [ ] Node B to Node A uses the same actor and assertions in a separate test.

### Harness completion gates

- [ ] Build and copy the standard Rust test executable to every physical VM.
- [ ] Invoke every privileged scenario by its exact Rust test name.
- [ ] Keep Bash and Python launchers limited to environment provisioning,
  physical fault injection, test invocation, diagnostics, and cleanup.
- [ ] Remove all `jq`, `grep`, and shell-condition scenario assertions after
  their Rust replacement passes.
- [ ] Remove each obsolete CLI scenario command after its exact Rust test
  replaces it.
- [ ] Keep each physical fault visible in its Rust test inputs and test name.
- [ ] Run the lightweight test before its paired Kubernetes test.
- [ ] Confirm that no automated shell or Python file owns a Mithril result
  assertion or reproduces a Control or Node production sequence.

## Acceptance reset

The previous migration checkmarks are not accepted. The changes moved test
code, but they did not make scenario setup, actions, and assertions simple.
They also left stateful scenario code in loose functions and left separate
native and direct-runtime process wrappers. Reassess every migration against
the rules below before it receives a checkmark.

The baseline reliability records remain as failure evidence. They do not
count as maintainability migrations.

## Common tooling deliverable

- [ ] Add small concrete physical setup owners for Control, Node, and one
  actor. Reuse existing Control, node, path, cgroup, and process owners. Keep
  environment-specific setup separate from shared result assertions.
- [ ] Make Control, Node, and actor start or stop independently so outage and
  restart order stays explicit in each scenario.
- [ ] Keep host, direct-`runc`, and Kubernetes placement in focused Rust
  physical setup owners. Keep VM and Kubernetes shell or Python launchers
  limited to provisioning and exact test invocation. Use the same actor file
  in all three placements.
- [x] Put the existing Control TLS lifecycle owner in one small shared module.
  Reuse it for production Control and Node connections.
- [x] Keep one synchronous readiness function with an exact timeout, resource
  path, operation name, and caller-supplied last-state diagnostic.
- [x] Make `ProcessFixture` own spawn readiness, stdin actions, bounded exit
  diagnostics, explicit stop, and idempotent drop cleanup.
- [x] Remove `NativeProcessFixture`. Move only generic Linux process mechanics
  to `ProcessFixture`; keep identity assertions and production calls in the
  identity scenario.
- [x] Make `RuncContainer` and `ContainerdServer` delegate process lifecycle
  to `ProcessFixture`. Keep runtime protocol and resource cleanup on their
  existing owners.
- [ ] Move the remaining direct-runtime exec children to the shared process
  owner through `Platform::add_actor` as each entry-role behavior moves to its
  scenario owner. Keep `Platform::start_actor` for the container PID 1.
- [ ] Replace every embedded native process script with an actual Python file
  in `fixtures/process`.
- [ ] Execute the same Python process file from production-backed host,
  direct-`runc`, and Kubernetes tests when the behavior applies. Do not count
  an actor-only test as coverage.
- [x] Build the standard Rust libtest executable and copy it into each fresh
  single-node VM. Scenario migrations must invoke each privileged test by its
  exact test name.
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
- [x] Generated direct-`runc` actor cleanup: allow an already-removed actor
  cgroup, then kill tracked descendants through their existing pidfds. The
  exact cleanup regression and all generated Host and direct-`runc` cases pass.

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
- [x] Delete `NativeProcessFixture` after its generic lifecycle and readiness
  behavior moves to `ProcessFixture`.
- [ ] Replace native child, failed-exec, post-PONR, subreaper, namespace-init,
  orphan, double-fork, leader-first, non-leader, and concurrent-thread shell
  commands with shared Python process files.
- [ ] Keep process transitions in small production-backed `#[test]`
  functions. Use `ProcessFixture` directly and keep the production action and
  assertion visible. Do not keep a second actor-only scenario test.
- [ ] Keep production object allocation and authorization replay tests beside
  their actual runner owner. Do not use orphaned scenario functions.
- [ ] Rerun every exact production-backed identity test and the `clone3.rs`
  owner test after each identity fixture change.

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

The 2026-09-12 fidelity audit compares each generated test with commit
`95775f48` and the matching physical shell assertions. A passing generated
test does not close a row when its physical condition or an assertion changed.

| Generated test | Audit result | Required correction |
| --- | --- | --- |
| PID reuse | Accepted | The namespace PID, host PID, task cookie, process state, execution, creator, namespace inode, and start-time checks remain. |
| TID reuse | Accepted | The namespace TID, host TID, task cookie, process owner, creator edge, namespace inode, start-time, exit, and tombstone checks remain. |
| Native child exec | Reopened | Use the non-PID1 `add_actor` path for the original external-root condition. Restore the post-exec image-candidate check. |
| Non-leader exec | Reopened | Use the non-PID1 `add_actor` path. The current initial-container root does not replace the original external-root transition. |
| Pre-PONR failure | Reopened | Use `add_actor`. Restore the child root-class and installed-role absence checks before failure and after success. |
| Post-PONR failure | Reopened | Use `add_actor` and restore the original root classification check. Keep all terminal pending-exec, process, execution, coordinate, and tombstone checks. |
| Moved-task exec | Reopened | Use `add_actor` and restore the original root classification and installed-role checks. |
| Leader-first lifetime | Reopened | Use `add_actor`. Restore the runnable worker-coordinate and child-edge checks. |
| Workload-first recovery | Accepted | The Control, actor, policy, Node order and nonzero recovery-attempt check remain. Keep the larger recovered-entry cases. |
| Namespace init | Accepted | PID 1 is the correct cross-platform actor. Intermediate and child host-parent fields, root and role absence, runnable state, and post-exec identity changes remain. |

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
- [ ] Native child exec: keep the fork and exec actions, production identity
  snapshots, and allocation diagnostics visible.
  - [x] Add the small shared actor, result assertions, and generated test.
  - [x] Pass the Host generated case in the retained privileged VM.
  - [x] Pass the direct-`runc` generated case with the same actor and checks.
  - [x] Pass the Kubernetes generated case with the same actor and checks.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [ ] Restore the baseline fidelity gaps recorded above and rerun all three
    generated cases.
- [ ] Non-leader thread exec: replace `ExecCase::non_leader` with one small
  generated test. Use `ProcessFixture` and the shared Python file directly.
  Keep exact TID allocation and post-exec assertions visible.
  - [x] Add the small generated test and use the shared actor and assertions.
  - [x] Pass the Host generated case in the retained privileged VM.
  - [x] Pass the direct-`runc` generated case with the same actor and checks.
  - [x] Pass the Kubernetes generated case with the same actor and checks.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [ ] Restore the baseline physical condition recorded above and rerun all
    three generated cases.
- [ ] Pre-PONR failure: use fixture-owned process readiness and keep the
  pending-exec, rollback, and recovery assertions visible.
  - [x] Add the small generated test with the shared Python actor and result
    assertions.
  - [x] Pass the Host generated case in the retained privileged VM.
  - [x] Pass the direct-`runc` generated case with the same actor and checks.
  - [x] Pass the Kubernetes generated case with the same actor and checks.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [ ] Restore the baseline fidelity gaps recorded above and rerun all three
    generated cases.
- [ ] Post-PONR failure: use fixture-owned process readiness and keep the
  fatal-state assertions visible.
  - [x] Put the architecture-aware malformed executable in `ProcessFixture`
    and preserve its focused termination check.
  - [x] Add the small generated test with the shared Python actor and result
    assertions.
  - [x] Pass the Host generated case in the retained privileged VM.
  - [x] Pass the direct-`runc` generated case with the same actor and checks.
  - [x] Pass the Kubernetes generated case with the same actor and checks.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [ ] Restore the baseline physical condition recorded above and rerun all
    three generated cases.
- [ ] Moved-task exec: keep the physical cgroup move, denied exec, production
  health checks, and placement-mismatch assertions visible.
  - [x] The small generated test uses one shared Python actor and the public
    runtime admission and identity inspection APIs.
  - [x] The Host generated case passes in the retained privileged VM.
  - [x] Pass the direct-`runc` generated case with the same actor and checks.
  - [x] Pass the Kubernetes generated case with the same actor and checks.
  - [x] Remove the matching old monolithic case and compatibility field.
  - [ ] Restore the baseline fidelity gaps recorded above and rerun all three
    generated cases.
- [x] Orphan transition: use `native_orphan.py` through `ProcessFixture` in
  one production-backed `#[test]`. Preserve the parent, role, and execution
  assertions. Remove the actor-only test.
  - [x] Add `Host::add_actor`. It performs the real read-only runtime access,
    then starts the actor with its declared executable and complete argv.
  - [x] Add the direct-`runc` `add_actor` implementation. It uses stock
    `runc exec` with the declared interpreter and complete actor argv.
  - [x] Add the Kubernetes `add_actor` implementation. It mounts and runs the
    same actor through real `kubectl exec` with the declared interpreter and
    complete argv.
  - [x] Add the small generated test with the shared actor and explicit result
    assertions.
  - [x] Reproduce the Host failure before the added actor starts. Confirm that
    the signed request and the restricted external-root identity are ready.
  - [x] Trace the failure to the missing runtime-entry bootstrap operation in
    the Host physical setup. Do not change the production security gate.
  - [x] Reject the proposed `lineage_depth == 0` exception. It does not model a
    runtime entry and it weakens descendant checks.
  - [x] Keep the direct interpreter as the declared executable and pass the
    Python file in argv. A shebang changes the committed argv and must fail
    closed.
  - [x] Run the pre-change direct-`runc` entry-role probe. Require incomplete
    declared-entry argv to fail with empty output and exact
    `UNSUPPORTED_OBJECT` execute evidence.
  - [x] Rerun that direct-`runc` security probe after the fixture correction.
    Require the external-entry denial to remain unchanged.
  - [x] Pass the Host generated case in the retained privileged VM.
  - [x] Pass the direct-`runc` generated case with the same actor and checks.
    Stop container PID 1 before the added actor. PID-namespace teardown then
    removes the orphan without bypassing Mithril's signal policy. An external
    `SIGKILL` remains denied.
  - [x] Replace the invalid host-parent lookup exposed by Kubernetes. A CRI
    exec process is not a host child of container PID 1. `ProcessFixture`
    finds the one added task in the real container cgroup and reports all
    observed cgroup PIDs on timeout.
  - [x] Pass the Kubernetes generated case with the same actor and checks.
  - [x] Remove the matching old monolithic case and compatibility fields.
- [x] Subreaper transition: use `subreaper.py` through
  `ProcessFixture` in one production-backed `#[test]`. Preserve the
  intermediate-parent, adopted-child, role, and execution assertions. Remove
  the actor-only test.
  - [x] Replace external `SIGTERM` and `SIGCONT` control with visible actor
    start, middle-exit, and child-exec barriers in the shared work directory.
  - [x] Keep the generated test below 100 lines. Use `add_actor` so the same
    non-PID1 entry condition runs on Host, direct `runc`, and Kubernetes.
  - [x] Preserve the creator, real-parent cookie, host parent, interval,
    execution, role, root, coordinate, and process-state assertions.
  - [x] Pass the Host generated case.
  - [x] Pass the direct-`runc` generated case.
  - [x] Pass the Kubernetes generated case.
  - [x] Remove the matching `ReparentCase::subreaper` block and compatibility
    fields only after all three generated cases pass.
- [x] Namespace-init transition: use `native_namespace_init.py` through
  `ProcessFixture` in one production-backed `#[test]`. Preserve the namespace
  PID, parent, role, execution, and tombstone assertions. Remove the actor-only
  test.
  - [x] Make PID 1 own descendant continuation and reparenting in the shared
    actor. The external test process does not bypass production signal policy.
  - [x] Add the under-100-line generated test and pass its Host case in the
    retained privileged VM.
  - [x] Pass the direct-`runc` generated case with namespace PIDs mapped to
    host PIDs through the real parent-child process tree.
  - [x] Pass the Kubernetes generated case with the deployed Control, Node,
    OCI hook, and the same actor and checks.
  - [x] Remove the matching legacy probe method, result fields, and call site.
  - [x] Restore the baseline identity assertions recorded above and rerun all
    three generated cases.
- [ ] Double-fork transition: use `double_fork.py` through `ProcessFixture` in
  one production-backed `#[test]`. The baseline has no double-fork tombstone
  assertion. Do not invent one.
  - [x] Use `start_actor` for the environment PID 1 and `add_actor` for the
    double-fork process on Host, direct `runc`, and Kubernetes.
  - [x] Replace external `SIGTERM` and `SIGCONT` control with visible fork,
    middle-exit, and child-exec barriers in the shared work directory.
  - [x] Keep the generated test below 100 lines.
  - [x] Before adoption, assert the root class and role, both creator and real
    parent cookies, both host parent IDs, inherited role, and active state.
  - [x] After adoption and exec, assert the stable task and creator cookies,
    changed real parent, increased parent interval, changed execution ID,
    inherited role, absent child root classes, and active state.
  - [x] Pass the Host generated case.
  - [x] Pass the direct-`runc` generated case.
  - [ ] Pass the Kubernetes generated case.
  - [ ] Remove the matching `ReparentCase::double_fork` block, result fields,
    and old actor only after all three generated cases pass.
- [ ] Leader-first thread exit and reference lifetime: keep the process and
  entry reference counts, tombstones, release action, and reclamation checks.
  - [x] The small Host generated case uses the shared actor and production
    runtime admission path.
  - [x] Pass the direct-`runc` generated case with the same actor and checks.
  - [x] Pass the Kubernetes generated case with the same actor and checks.
  - [x] Remove the matching old probe code and compatibility bundle fields.
  - [ ] Restore the baseline fidelity gaps recorded above and rerun all three
    generated cases.
- [x] Node-first PID reuse: keep one small parameterized Rust test in
  `pid_reuse.rs`, one shared Python actor, one shared result assertion, and
  thin VM and Kubernetes launchers. Use
  `#[platform_test(host, runc, kubernetes)]` on that one function. Each
  generated case selects its custom physical platform implementation. Start
  Control and Node, install the signed policy, and require readiness. Then use
  `start_actor` to create the environment with the held Python actor as PID 1.
  Place it, stage its runtime facts, and admit its initial process through the
  public production boundary before release. The Host setup can
  supply CRI inventory as external test input. Direct `runc` must use its OCI
  hooks. Kubernetes must use its real CRI and OCI input. Keep stage and
  admission calls, both namespace-PID actions, and fresh process identity
  checks visible. Keep workload-first Node recovery in a separate test. The
  fixture owns async runtime setup; the test function does not call `block_on`.
  Keep the one-test `pid_reuse.rs` file below 100 lines. Put no host,
  direct-`runc`, or Kubernetes runner function in that file.
  - [x] The Host generated case passes in the retained privileged VM.
  - [x] The direct-`runc` generated case passes through the production OCI
    hooks in the retained VM. The hook stages runtime facts, prepares the
    container, and prepares its declared entry before the Python PID 1 runs.
  - [x] The Kubernetes generated case passes with the production Helm chart,
    policy CRD, Control, Node, OCI hook, and actor Pod.
  - [x] Use the shared work-directory release file so the actor cannot start
    its PID-reuse action before the test releases it on any platform.
  - [x] Replace the old PID-reuse shell and CLI path with a thin exact-test
    launcher before this behavior is complete.
- [x] TID reuse: use one Python actor through `ProcessFixture`. Keep the two
  namespace-TID actions, exact thread coordinates, and tombstone checks
  visible in a separate small scenario file.
  - [x] The Host generated case passes in the retained privileged VM.
  - [x] Remove the TID behavior and compatibility result bridge from
    `IdentityTestRunner::physical_probe`.
  - [x] The direct-`runc` generated case passes with the same Python actor and
    the production OCI hooks.
  - [x] Reproduce the Kubernetes `SIGTERM` cleanup condition in a lightweight
    Node entry-point test. Before the fix, the exact test exited with signal
    15. It now proves that `SIGTERM` starts normal Node shutdown.
  - [x] Verify that normal Kubernetes shutdown removes both runtime admission
    socket paths before accepting the Kubernetes result.
  - [x] The Kubernetes generated case passes with the same Python actor.
- [ ] Workload-first recovery: keep one small parameterized Rust test in
  `identity/scenarios/workload_recovery.rs`. Start Control. Start one ready
  Python actor while its policy and Node are absent. Install the signed policy
  while the actor is running. Start Node and let Control and the real or
  supplied CRI inventory report the running actor. The new Node must invoke
  `NodeBindingReconciliation` and native identity recovery through its
  production runtime loop. Keep the
  `active_recovered` binding, recovered application root, initial role,
  admitted entry rule, complete recovery counts, and first denied executable
  assertion visible. Use the same Python actor in every environment. Keep the
  one-test file below 100 lines.
  - [x] Record the Kubernetes admission condition. The actor Pod starts before
    its policy exists, so admission must not add Mithril annotations or a
    ready-Node selector. Kubernetes schedules the Pod normally. After the
    policy exists, Control must match the running Pod through its production
    inventory before Node recovers it. Do not use a server dry-run, set
    `spec.nodeName`, or remove admission webhooks.
  - [x] Require Node's real task map before accepting its readiness projection.
    Treat bounded map absence as recovery wait state. Include the map path and
    the last inspection error in diagnostics.
  - [x] Complete the shared physical support for a workload that exists before
    Node. The platform supplies runtime placement and the external CRI input;
    it does not call or reproduce the recovery owner sequence.
  - [x] Pass the Host generated case in the retained privileged VM with the
    Control, actor, policy, and Node order.
  - [x] Pass the direct-`runc` generated case with the actor as container PID
    1. The preexisting container must not use a test-only OCI hook.
  - [x] Pass the Kubernetes generated case with one normally scheduled actor
    Pod running before its policy and the Helm Node DaemonSet. The platform
    keeps actor input across the required K3s runtime restart. The recovered
    actor then receives the shared action and exits with the denied result.
  - [ ] Remove only the matching workload-first assertions from the old
    monolithic probes after all three generated cases pass. Preserve their
    other recovered-entry and concurrency assertions for later migrations.
  - [ ] Do not remove the legacy multi-task case until small tests preserve
    its two application and two external tasks, iterator retry, ptrace
    bootstrap, internal exec, declared-probe isolation, unmatched denial,
    post-cutover activation, and cleanup assertions. The focused one-task
    recovery test does not replace these behaviors.
  - [x] Restore the nonzero recovery-attempt assertion and rerun all three
    generated cases before the old workload-first assertions are removed.
- [ ] Retained-host restart: keep host shutdown, retained map validation,
  production recovery, stable map IDs, and ownership rejection visible.
- [ ] Cgroup lifetime reuse: recreate the cgroup path after recovery. Keep the
  new cgroup ID, binding nonce, live interval, process identity, and role
  assertions visible.

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
- [ ] `physical_kubernetes_resilience_probe`: keep the Pod and its cgroup
  running before Node starts. Require public production recovery, exact
  identity retention across the Kubernetes service and Node outages, and
  fresh identity after same-name Pod and container recreation.
- [ ] `physical_kubernetes_network_probe`

Each Kubernetes identity case must keep the `k3s`, CRI, OCI hook, node
process, and public production-owner operations that its physical harness
uses.

## Required pre-TODO test baseline

Commit `95775f48f2ed9864ecbc40219c3ecf79a51a0ee7` is the source baseline
immediately before this work. It contains 90 library tests and two binary
tests. Account for the behavior and assertions behind all 92 entries. A test
name can disappear after a real production-backed test replaces it. Do not
keep an actor-only duplicate only to preserve the old name.

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

The current tree also has nineteen tests added after the baseline. Keep these
five generic owner tests:

- `physical.rs::async_wait_yields`
- `physical.rs::readiness_reports_cleanup`
- `process/tests.rs::exit_reports_stderr`
- `process/tests.rs::python_start_stop`
- `process/tests.rs::stop_kills_actor`

Remove these scenario-specific actor or wrapper tests as their production
scenarios become standard Rust tests. They do not count as Mithril behavior
coverage:

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
- `identity/scenarios/lifetime/tests.rs::worker_lives_after_leader`

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
  -> cargo test -p mithril-e2e <privileged-test-name> -- --exact --ignored
  -> cargo test -p mithril-e2e
  -> bash crates/mithril-e2e/harness/vm/test.sh
  -> bash crates/mithril-e2e/harness/vm/run.sh --entry-role-runtime-only ...
  -> bash crates/mithril-e2e/harness/vm/two-node-convergence.sh --protected-start-only ...
  -> bash crates/mithril-e2e/harness/vm/two-node-network.sh ...
  -> bash .github/scripts/verify-rust-ci.sh
```

Apply the Kubernetes gate in the binding acceptance rules before each paired
physical command.
