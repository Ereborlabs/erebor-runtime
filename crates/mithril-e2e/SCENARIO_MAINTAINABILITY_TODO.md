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
- Keep the public test operation name `add_actor`. Do not rename it to
  `exec_actor`. A runtime can use exec as its physical process-entry mechanism.
- Give `add_actor` the command and complete argv that a production runtime
  receives, for example `python` or `cat`. Do not give it a policy rule name
  or an absolute executable path. It must not inspect the installed policy or
  reject an undeclared command before production enforcement runs. The scenario
  installs or omits the applicable rule and asserts the production result. Do
  not add role-specific process methods.
- Treat role names as policy labels. Names such as `external` and `restricted`
  have no special BPF meaning.
- Keep entry admission separate from role execution authorization. An
  execution `Allow` rule does not admit a runtime-created process. Declare each
  allowed runtime entry in `additionalEntries`. Keep an undeclared entry
  denied. Do not change BPF behavior to bypass this boundary.
- Ask the actor to perform one action. Assert the expected production result.
- Keep scenario policies, Python actors, and other process inputs together in
  `fixtures/process`. Store each distinct input once. Reuse one policy when its
  complete production specification is the same for several tests. Do not copy
  actors or policies for a test or platform. Pass the policy filename to
  `install_policy`. A platform must not select a default policy or add
  scenario-specific policy rules.
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
- Review the common platform implementations before each migrated behavior
  commit. Remove scenario-specific branches and duplicate physical operations
  when the next test proves that a smaller boundary is sufficient.
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
  its exact generated case, such as
  `secret_read_is_denied::identity_kubernetes`.
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

### Platform test lifecycle

- Put `#[lifecycle = identity]` directly below `#[platform_test(...)]`.
  `platform_test` consumes the lifecycle attribute and keeps each generated
  platform case as a standard Rust `#[test]`.
- Run one lifecycle and one platform in each test process. Production uses one
  global Interceptor lease per host, so two lifecycle Nodes must not overlap.
- Do not rename tests, add `z` prefixes, move modules, or depend on libtest
  discovery order to make lifecycle users contiguous.
- Put the lifecycle and platform in each generated leaf test name, such as
  `identity_host`. A launcher selects this suffix to run one lifecycle and one
  platform in a process. Parent module names do not control lifecycle order.
- Give an omitted lifecycle a unique name for that scenario. Give recovery,
  outage, restart, replacement, runtime integration, retained-state, owner
  cleanup, and cumulative-health tests a dedicated lifecycle.
- Do not infer a lifecycle from a scenario name, environment variable, module
  position, or runtime branch. Do not select a lifecycle in a scenario body.
- Do not define platform-specific lifecycle globals. The attribute supplies
  the name. The generated wrapper supplies the concrete platform type to the
  common lifecycle owner.
- Give each Host lifecycle process one Control and one Node. Give each direct
  `runc` lifecycle process one Control and one Node. Give each Kubernetes
  lifecycle process one Control Deployment, one Node DaemonSet, and one
  runtime integration installation.
- Keep actors, workload cgroups or namespaces, policy instances, results, and
  assertions test-scoped. The scenario keeps `Platform::setup` and final
  per-test cleanup visible. The lifecycle retains only Control, Node, and the
  platform integration between tests.
- Keep `start_control`, `start_node`, readiness, actor start, component stop,
  action, and assertion calls visible in the scenario. Keep their production
  order. Do not hide recovery or outage order in the lifecycle owner.
- Make the first ordered `start_control` or `start_node` call start the shared
  owner when it is absent. A later call in the same process must verify that
  the same owner is ready. It must not replace or restart that owner.
- Tear down each retained owner once. Process-exit teardown must be bounded.
  A failure must fail the test command and keep component logs, readiness
  state, owned paths, and actor diagnostics.
- Keep exact single-test invocation valid. It must initialize its lifecycle,
  run one scenario, perform per-test cleanup, and tear down retained resources.
- [x] Reject concurrent lifecycle Nodes on one host. A physical interleave
  probe started lifecycle A and then lifecycle B. Production rejected B
  because `/run/erebor-interceptor/owner.lock` was owned. This is the required
  `KernelHostLease` behavior. Do not weaken it for tests.
- [x] Generate a lifecycle-platform leaf name for each test. Test discovery
  found 69 physical cases with suffixes such as `identity_host`,
  `identity_runc`, and `identity_kubernetes` on 2026-09-15.
- [x] Prove one filtered Host lifecycle. The `identity_host` process passed
  22 tests in 235.08 seconds and initialized Node once on 2026-09-16.
  A control that used a new process for each exact test passed the first test
  in 37.17 seconds. Its second Node start timed out after 31.17 seconds. The
  grouped run removes this repeated and unreliable Node startup.
- [x] Prove the filtered direct-`runc` lifecycle. The `identity_runc` process
  passed 17 tests in 222.98 seconds on 2026-09-16.
- [x] Prove the filtered Kubernetes lifecycle. The `identity_kubernetes`
  process passed 19 tests in 541.91 seconds on 2026-09-16. It retained one
  Control Deployment and one Node DaemonSet. Actor setup waits for the
  container ID, attaches standard input, and then records the live host PID.
- [x] Prove serial same-lifecycle reuse with a focused physical test. Start
  real Control and Node, stop one test fixture, enter the lifecycle again, and
  require the same Node pin owner.
- [x] Reject a second lifecycle for the same platform in one process. The
  focused owner test passed. It requires the launcher to start a separate test
  process instead of restarting Node.
- [x] Recover a lifecycle after a scenario assertion panics. The focused
  mutex-poison regression passed. A failing Host runtime-entry assertion then
  removed its output directory, pin, lease, actor cgroup, and Node cgroup.
- Do not add a test registry, custom test language, replacement harness,
  builder, factory, or scenario-specific lifecycle implementation.
- Verify serial lifecycle tests first. Enable bounded parallel tests only
  after Host, direct `runc`, and Kubernetes prove unique identity, complete
  cleanup, policy and evidence isolation, and no BPF or runtime-hook race.

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
- Put actor programs in `fixtures/process`. Do not embed shell or Python source
  in Rust.
- Do not keep separate native and `runc` process wrappers.
- Make one start call return a ready actor.
- Make one fallible stop call perform normal cleanup. Use `Drop` only as an
  idempotent fallback.
- Bound every readiness wait. Report the operation, resource path, last state,
  process exit status, and captured stderr when applicable.
- Treat `ENOENT` and `ESRCH` as process absence only in a wait for process
  removal. Keep all other `/proc` errors visible.
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
- Run the smallest exact test first. Pass its Host, direct-`runc`, and
  Kubernetes cases before the next behavior when all three platforms apply.
- Run related tests, harness checks, formatting, and clippy for each migrated
  behavior.
- Run the complete Host, direct-`runc`, and Kubernetes suites after every
  third fully migrated behavior. Do not run all complete suites after each
  behavior.
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
| `NetworkTestRunner::physical_probe` | 1,237 | `two-node-network.sh` in both node directions |
| `EffectTestRunner::recovered_container_entry_probe` | 1,028 | `two-node-convergence.sh` recovered-container entry lane |
| `IdentityTestRunner::physical_kubernetes_probe` and its private cases | 4,900 combined | `run.sh --with-k3s` identity lane |

## Current compliance audit

The current tree does not meet the size or naming gates. Do not mark the work
complete while these entries remain.

These Rust files exceed 2,000 lines:

| Source | Current lines |
| --- | ---: |
| `effect/runc.rs` | 7,518 |
| `identity.rs` | 6,394 |
| `effect.rs` | 5,118 |
| `effect/child.rs` | 4,472 |
| `control_tls.rs` | 2,734 |
| `effect/network.rs` | 2,329 |

The diff from `95775f48` adds or relocates these private test functions with
more than five name components:

- `production_object_and_identity_fixture_allocation_are_exact`
- `kubernetes_network_probe_container_no_task`

The same diff adds or relocates these local variables with more than three
name components:

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
| `harness/vm/run.sh` | 758 | Builds one VM, runs native, direct-`runc`, and Kubernetes probes, checks JSON, and checks cleanup | Provision the VM, copy inputs, invoke exact Rust tests, collect diagnostics, and remove resources only |
| `harness/vm/test.sh` | 797 | Tests shell text, fake Kubernetes oracles, cleanup, and provider wiring | Test only launcher argument, provider, and cleanup behavior that must remain in shell |
| `harness/vm/guest.sh` | 1,138 | Installs K3s and its hook, then owns K3s qualification and CRI effect scenarios | Install or remove K3s and the runtime hook, then invoke exact Rust tests |
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
  - [x] Make the thin retained-VM launcher call the image helper once before
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
- [x] Administrative exec: use real Control, Node, OIDC, TokenReview,
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

- [x] Add one common named platform lifecycle owner below `platform_test`.
  The generated wrapper enters the lifecycle and still registers a standard
  Rust `#[test]`.
- [x] Make `#[lifecycle = name]` the only shared lifecycle selection. The
  `platform_test` macro consumes it. An omitted attribute gives the test a
  unique lifecycle.
  - The generated wrapper enters the lifecycle before it calls the scenario.
    `Host`, `Runc`, and `Kubernetes` use the selected lifecycle.
  - The generated leaf name contains the lifecycle and platform. This lets a
    launcher select one lifecycle process without a scenario registry.
  - `cargo test -p mithril-e2e --lib --no-run` and test discovery passed on
    2026-09-15.
- [ ] Change each platform launcher to invoke one lifecycle-platform suffix
  per process with `--test-threads=1`. Do not list scenarios in the launcher.
  - [x] The Host VM launcher invokes `identity_host` once. It does not list PID
    reuse and TID reuse as separate processes.
  - [ ] Apply the same suffix invocation to the direct-`runc` and Kubernetes
    launchers after their current platform gates pass.
- [x] Share one Control and one Node across each named Host lifecycle.
  Keep each actor, cgroup, policy instance, runtime identity, output path, and
  assertion test-scoped. Pass every existing Host scenario before commit.
  - The complete Host lane passed 25 tests in 720.23 seconds on 2026-09-14.
  - The filtered `identity_host` lifecycle passed 21 tests in 218.09 seconds
    with one Node initialization on 2026-09-16.
  - The current filtered lifecycle passed 22 tests in 235.08 seconds on
    2026-09-16.
  - The lifecycle passed 24 tests in 230.74 seconds on 2026-09-17. The
    `CLONE_INTO_CGROUP` child fixture now uses the direct Linux `fork`
    syscall, so it does not inherit glibc thread locks from the shared Node.
- [x] Share one Control and one Node across each named direct-`runc` lifecycle.
  Reuse the common Mithril lifecycle owner. Do not call Host process or actor
  operations from direct `runc`. Keep each container and actor test-scoped.
  Pass every existing direct-`runc` scenario before commit.
  - The filtered `identity_runc` lifecycle passed 16 tests in 343.52 seconds
    on 2026-09-16.
  - The current filtered lifecycle passed 17 tests in 222.98 seconds on
    2026-09-16.
- [x] Share one Helm Control Deployment, one Node DaemonSet, and one runtime
  integration installation across the serial Kubernetes platform lane. Keep
  each workload namespace, policy instance, actor Pod, runtime identity,
  output path, and assertion test-scoped. Pass every existing Kubernetes
  scenario before commit.
  - An earlier source state passed 18 tests in 1,028.03 seconds with two
    workers on 2026-09-14. The current source passed 7 of 17 tests in 469.71
    seconds on 2026-09-15. The ten `add_actor` allow-path failures return
    `EACCES`; this earlier result does not qualify the current source.
  - The focused same-lifecycle Kubernetes reuse test passed in 86.91 seconds
    on 2026-09-16. This result qualifies lifecycle reuse only. It does not
    close the complete Kubernetes gate.
  - The current filtered lifecycle passed all 18 tests in 455.40 seconds on
    2026-09-16. Cleanup waits for production policy delivery retirement. Each
    scenario uses a distinct workload namespace.
- [ ] Run order, recovery, outage, restart, and retained-state lifecycles in
  separate filtered processes. Prove that each requested owner is ready before
  use.
  - Host, direct-`runc`, and Kubernetes recovery lifecycles passed in their
    complete platform lanes on 2026-09-14.
  - Four compatible Host physical tests now use `identity_physical`. They own
    and stop their temporary physical host and can share the outer platform
    lifecycle. The group passed four tests in 137.49 seconds on 2026-09-16.
  - Keep `workload_recovery`, `recovery_tasks`, and `external_roots` separate.
    Each starts its actor before Node and must not inherit an already-running
    identity Node.
- [x] Make exact single-test cleanup and complete-lane cleanup bounded and
  diagnostic on all three platforms. Do not depend on process exit, VM
  deletion, or K3s deletion for normal cleanup.
  - The same `child_exec_keeps_identity` test passed by exact name on Host,
    direct `runc`, and Kubernetes before the complete Kubernetes lane passed.
- [ ] Record elapsed setup, Control, Node, actor, scenario, and teardown time
  without adding timing calls to scenario bodies. Compare with the current
  serial baselines: 25 Host cases in 889.98 seconds, 16 direct-`runc` cases in
  585.01 seconds, and 18 Kubernetes cases in 2,423.25 seconds.
- [ ] After all three serial shared lanes pass, prove bounded parallel shared
  execution at two workers. Keep different lifecycles serial. Increase the worker
  count only after repeated runs show no identity, policy, evidence, BPF,
  runtime-hook, or cleanup overlap.

- [ ] Add small concrete physical setup owners for Control, Node, and one
  actor. Reuse existing Control, node, path, cgroup, and process owners. Keep
  environment-specific setup separate from shared result assertions.
- [ ] Make Control, Node, and actor start or stop independently so outage and
  restart order stays explicit in each scenario.
- [ ] Keep host, direct-`runc`, and Kubernetes placement in focused Rust
  physical setup owners. Keep VM and Kubernetes shell or Python launchers
  limited to provisioning and exact test invocation. Use the same actor file
  in all three placements.
- [x] Remove the PID-reuse name from shared Kubernetes actor readiness. Use a
  scenario-neutral operation name in the common platform owner.
- [x] Put the existing Control TLS lifecycle owner in one small shared module.
  Reuse it for production Control and Node connections.
- [x] Keep one synchronous readiness function with an exact timeout, resource
  path, operation name, and caller-supplied last-state diagnostic.
- [x] Make `ProcessFixture` own spawn readiness, stdin actions, bounded exit
  diagnostics, explicit stop, and idempotent drop cleanup.
- [x] Keep actor selection outside `ProcessFixture`. The scenario gives
  `start_actor` one checked Python file name or gives `add_actor` one command
  name and complete argv. The platform mounts the shared actor directory and
  passes each command name unchanged. `ProcessFixture` owns the child process.
  It does not search a source root or environment `PATH`.
  - `ProcessFixture::script` is removed.
  - The nine generic process lifecycle tests pass.
  - The same PID-reuse Rust test passes on Host, direct `runc`, and the
    retained Kubernetes cluster.
  - The local suite passes with 91 tests and 59 ignored physical tests.
  - Strict crate Clippy passes.
  - The complete repository Rust CI script passes.
- [x] Keep post-exec actor cleanup in-band. Reuse the signed `/usr/bin/sleep`
  image with a bounded duration. Do not add an execution rule only for test
  cleanup. Do not depend on an external signal that Mithril can deny.
- [x] Remove `NativeProcessFixture`. Move only generic Linux process mechanics
  to `ProcessFixture`; keep identity assertions and production calls in the
  identity scenario.
- [x] Make `RuncContainer` and `ContainerdServer` delegate process lifecycle
  to `ProcessFixture`. Keep runtime protocol and resource cleanup on their
  existing owners.
- [ ] Move the remaining direct-runtime exec children to the shared process
  owner through `Platform::add_actor` as each entry-role behavior moves to its
  scenario owner. Keep `Platform::start_actor` for the container PID 1.
- [x] Make Host `add_actor` call `clone3(CLONE_INTO_CGROUP)` before exec. All
  23 Host platform tests pass with this process-birth path.
- [x] Remove policy-entry lookup and preflight checks from `add_actor`. Pass
  the same command name and complete argv to Host, direct `runc`, and
  Kubernetes. The production `execvp`, `runc exec`, or `kubectl exec` path
  resolves the command inside the actor environment. The platform owner and
  `ProcessFixture` do not resolve commands.
  - [x] Pass the complete Host platform set: 23 tests.
  - [x] Pass the complete direct-`runc` platform set: 16 tests.
  - [x] Reproduce the unmatched Kubernetes init-container condition in the
    lightweight Control test before the physical rerun.
  - [x] Pass the complete Kubernetes platform set: 17 tests.
- [ ] Replace every embedded native process script with an actual Python file
  in `fixtures/process`.
- [ ] Execute the same Python process file from production-backed host,
  direct-`runc`, and Kubernetes tests when the behavior applies. Do not count
  an actor-only test as coverage.
- [x] Expose the owned actor cgroup path for the Host clone scenario. Do not
  add a scenario-specific actor start method or hide the clone action in a
  platform implementation.
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
| Native child exec | Accepted | The non-PID1 `add_actor` path restores the external-root condition. The post-exec image-candidate check remains. |
| Non-leader exec | Accepted | The non-PID1 `add_actor` path restores the external-runtime root. Exact TID allocation, exec promotion, lineage, role, image, active-state, and in-band exit checks remain. |
| Pre-PONR failure | Accepted | The non-PID1 `add_actor` path restores the external root. Child root and role absence, pending-exec rollback, stable failed-exec identity, changed successful execution and image, and active-state checks remain. |
| Post-PONR failure | Accepted | The non-PID1 `add_actor` path restores the external root and installed role. Fatal status, pending exec, process, execution, coordinate, tombstone, lineage, and active-role checks remain. |
| Moved-task exec | Accepted | The non-PID1 `add_actor` path restores the external root and installed role. The physical move, lineage, fail-closed coordinate, declassification, health increments, and denied-exec errno checks remain. |
| Leader-first lifetime | Accepted | The `add_actor` path, runnable worker coordinate, child edge, reference counts, and reclamation checks remain. |
| Workload-first recovery | Accepted | The Control, actor, policy, Node order and nonzero recovery-attempt check remain. Keep the larger recovered-entry cases. |
| Namespace init | Accepted | PID 1 is the correct cross-platform actor. Intermediate and child host-parent fields, root and role absence, runnable state, and post-exec identity changes remain. |

- [ ] Probe resources and production owners: own the pin root, lease, cgroup,
  fixture files, and cleanup. Keep `KernelHostOwner`, binding publication,
  native identity activation, recovery, and shutdown visible in the scenario.
- [x] Binding-gap recovery: keep the terminal binding mutation and both public
  recovery calls explicit. Preserve the fail-closed root assertions.
  - The 98-line Host test starts the actor before it publishes the binding.
  - The test checks the fail-closed root, role, coordinate, and recovery report.
  - The test changes the binding to `Terminating` and back to `Active`. It calls
    `NativeSecurityStateOwner::recover_tasks` after each change.
  - The test waits for the profile task reference count to reach zero after the
    actor stops.
  - The focused test passed before and after removal from
    `IdentityTestRunner::physical_probe`. The final run passed in 21.27 seconds.
  - The complete 25-test Host platform set passed in 901.22 seconds.
  - The remaining native physical probe passed with only authorization replay.
  - The complete repository Rust CI script passed.
- [x] Authorization replay: use two direct production-owner tests in
  `identity/authorization_tests.rs`.
  - `invalid_auth_is_rejected` checks retargeting, expiry, signature failure,
    and the unchanged two-record owner and boot WAL.
  - `replay_is_durable` checks the exact accepted proof, same-owner replay,
    owner restart, boot change, fresh authorization, and the five-record WAL.
  - Each test calls `AuthorizationProofOwner::verify_and_accept` directly.
    `AuthCase` owns only input data, the state directory, and cleanup.
  - Both focused tests passed before and after deletion of the 301-line hidden
    helper from `identity.rs`.
  - The simplified Kubernetes base-bundle command passed in the retained VM.
  - The local suite passed with 91 tests and 59 ignored physical tests.
  - Strict crate Clippy passed.
  - The complete 25-test Host platform set passed in 889.98 seconds.
  - The complete repository Rust CI script passed.
- [ ] Concurrent external roots: keep one small parameterized Rust test in
  `identity/scenarios/external_roots.rs`. Start Control and one
  `external_roots.py` environment actor. Let that actor copy its interpreter
  and resolved shared-library dependencies to the shared work directory.
  Verify that the copied interpreter starts before the actor reports ready.
  Install policy, start Node, and recover the actor. Start two more instances
  through `add_actor` with the signed external entry and keep both alive while
  their production identities are read.
  - [x] Use the same Python actor on all platforms. Host must execute its
    signed external entry in the owned cgroup. Direct `runc` and Kubernetes
    must use stock runtime exec. Do not inject a task through namespaces or a
    test-only identity operation.
  - [x] Keep the normal post-start entry and the external post-start entry as
    distinct production operations. Share their process-start mechanics inside
    each platform implementation. Do not select behavior from the scenario
    name.
  - [x] Declare the copied interpreter as a signed additional entry that
    targets the external role. Keep it separate from the application entry and
    the normal post-start entry. Require a nonzero admitted rule ID and the
    qualified registered role class.
  - [x] Assert that both actors are creator-free external runtime roots with
    the same non-application role and runnable coordinates.
  - [x] Assert distinct task cookies and process-state IDs. Assert the same
    nonzero external role and a role different from the admitted actor.
  - [x] Pass the Host generated case and the complete Host platform set.
  - [x] Pass the direct-`runc` generated case and the complete direct-`runc`
    platform set through stock `runc exec`.
  - [x] Pass the Kubernetes generated case through real `kubectl exec`.
  - [x] Pass the complete Kubernetes platform set after the copied
    interpreter dependency correction.
  - [x] Pass the signed external entry by command name. Do not resolve the
    command in a test helper or platform owner. Host must resolve it with
    `execvp`. Direct `runc` and Kubernetes must resolve it through their
    production exec paths.
    - [x] Host passes the exact Rust scenario. The actor calls
      `execvp("python-external", ...)`. The resulting syscall is
      `execve("/work/bin/python-external", ["python-external", ...])`.
      The complete 25-test Host platform set passed in 904.39 seconds.
      The complete repository Rust CI script passed.
    - [x] Direct `runc` passes the exact Rust scenario in 35.82 seconds.
      The complete 16-test direct-`runc` platform set passed in 585.01
      seconds. The local suite, strict crate Clippy, and the complete
      repository Rust CI script passed.
    - [x] Kubernetes passes the exact Rust scenario in 120.35 seconds.
      The complete 17-test Kubernetes platform set passed in 2064.50 seconds.
      The local suite, formatting check, strict crate Clippy, and the complete
      repository Rust CI script passed.
    - The signed policy path and exact executable object remain installed.
      BPF now selects the signed declared entry from the `execve` or `execveat`
      filename. It captures and verifies the complete argv separately.
    - The old physical Kubernetes commands use absolute executable paths.
      They do not qualify command-name resolution.
    - Do not restore test-side resolution.
  - [x] Make `Platform::place` perform and verify the real cgroup attach on
    Host, direct `runc`, and Kubernetes. Expose only the checked fixture source
    path so the scenario can start one ordinary `ProcessFixture` outside the
    protected cgroup. The existing PID-reuse case passes on all three
    platforms after this tooling change.
  - [x] Add the 60-line restricted-root scenario and pass its Host case.
  - [x] Pass the direct-`runc` restricted-root case.
  - [x] Pass the Kubernetes restricted-root case.
  - [x] Keep the old restricted-placement block until a separate small test
    reproduces its creator-free `runtime_external_restricted` roots through a
    supported production cgroup-attach operation. The declared runtime-exec
    case does not replace that security assertion.
  - [x] Remove only the matching old concurrency and role assertions after the
    declared runtime-exec case passes on all three platforms. Remove the
    restricted-placement fields only after its separate replacement passes.
- [x] Cgroup escape and moved-parent fork: keep the physical cgroup move,
  production health reads, fork action, and mismatch assertions visible.
  - [x] Preserve the node-first `CLONE_INTO_CGROUP` root. A process that
    executes before a later cgroup attach is a different fail-closed case and
    cannot replace this test.
  - [x] Pass the small Host moved-parent fork test. Use the existing native
    clone fixture so `clone3(CLONE_INTO_CGROUP)` completes before the root's
    first effect.
  - [x] Remove only the matching moved-parent block and compatibility field
    from `IdentityTestRunner::physical_probe`.
  - [x] Pass the small Host unmoved first-open control with the same native
    clone fixture and restricted external identity assertions.
  - [x] Keep an unmoved first-effect control. Require it to succeed before the
    moved-root denial can qualify the replacement.
  - [x] Restore a live moved root to its owned cgroup before cleanup. Pass a
    focused Host test and keep the reap bounded with PID and state diagnostics.
  - [x] Pass the small Host moved-root first-open denial. Keep the identity,
    fail-closed coordinate, `EACCES`, and both mismatch increases explicit.
  - [x] Remove only the matching cgroup-escape block and compatibility fields
    from `IdentityTestRunner::physical_probe` after the replacement passes.
- [x] `CLONE_INTO_CGROUP`: keep the clone action, namespace transition, exec,
  first-effect action, and exact identity assertions visible.
  - [x] Pass the small Host native-child first-open test. Keep root and child
    identity, lineage, active state, and the physical allowed open explicit.
  - [x] Remove only the matching native-child first-effect block and fields
    from `IdentityTestRunner::physical_probe` after the replacement passes.
  - [x] Pass the small Host native-child mount-namespace exec test. Keep the
    physical namespace and executable transition and all identity changes.
    Use a signed identity profile and the held-root production APIs so the
    binding is active before the external clone starts.
  - [x] Remove only the matching native-child namespace/exec block and fields
    from `IdentityTestRunner::physical_probe` after the replacement passes.
- [x] Native child exec: start the admitted environment with `ready.py`, then
  use `add_actor` for the child-exec program. Keep the fork and exec actions,
  production identity snapshots, and allocation diagnostics visible. Assert
  the external-runtime root and installed role before the fork. Require an
  image candidate before and after exec.
  - [x] Add the small shared actor, result assertions, and generated test.
  - [x] Pass the corrected Host case in the retained privileged VM.
  - [x] Pass the corrected direct-`runc` case with the same actor and checks.
  - [x] Pass the corrected Kubernetes case with the same actor and checks.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [x] Restore the baseline fidelity gaps recorded above and rerun all three
    generated cases.
- [x] Non-leader thread exec: start the admitted environment with `ready.py`,
  then use `add_actor` for the thread program. Assert its external-runtime
  root and nonzero installed role. Keep exact TID allocation, thread identity,
  exec promotion, lineage, role, image, and active-state assertions visible.
  - [x] Add the small generated test and use the shared actor and assertions.
  - [x] Pass the corrected Host case in the retained privileged VM.
  - [x] Pass the corrected direct-`runc` case with the same actor and checks.
  - [x] Pass the corrected Kubernetes case with the same actor and checks.
  - [x] Remove the added `/usr/bin/cat` rule. The first Kubernetes run with
    six worker execution rules admitted the container, but its Python PID 1
    exited with status 1 before readiness. Reuse the existing signed sleep
    rule, then rerun Host and direct `runc` before Kubernetes.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [x] Restore the baseline physical condition recorded above and rerun all
    three generated cases.
- [x] Pre-PONR failure: use fixture-owned process readiness and keep the
  pending-exec, rollback, and recovery assertions visible.
  - [x] Add the small generated test with the shared Python actor and result
    assertions.
  - [x] Pass the initial Host generated case in the retained privileged VM.
  - [x] Pass the initial direct-`runc` generated case.
  - [x] Pass the initial Kubernetes generated case.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [x] Start `ready.py` as PID 1 and use `add_actor` for the failed-exec
    actor. Restore the external root and child root and role absence checks.
    Let the signed sleep action exit in-band.
  - [x] Pass the corrected Host case and the complete Host platform set.
  - [x] Pass the corrected direct-`runc` case and platform set.
  - [x] Pass the corrected Kubernetes case.
  - [x] Restore the baseline fidelity gaps recorded above and rerun all three
    generated cases.
- [x] Post-PONR failure: use fixture-owned process readiness and keep the
  fatal-state assertions visible.
  - [x] Put the architecture-aware malformed executable in `ProcessFixture`
    and preserve its focused termination check.
  - [x] Add the small generated test with the shared Python actor and result
    assertions.
  - [x] Pass the initial Host generated case in the retained privileged VM.
  - [x] Pass the initial direct-`runc` generated case.
  - [x] Pass the initial Kubernetes generated case.
  - [x] Remove the matching old monolithic case and compatibility fields.
  - [x] Start `ready.py` as PID 1 and use `add_actor` for the fatal actor.
    Restore the external root and installed role checks before fatal exec.
  - [x] Accept a fatal actor signal as a non-success exit status. Do not
    require a numeric exit code after the actor mirrors the child signal.
  - [x] Pass the corrected Host case and the complete Host platform set.
  - [x] Pass the corrected direct-`runc` case and platform set.
  - [x] Pass the corrected Kubernetes case.
  - [x] Restore the baseline physical condition recorded above and rerun all
    three generated cases.
- [x] Moved-task exec: keep the physical cgroup move, denied exec, production
  health checks, and placement-mismatch assertions visible.
  - [x] The small generated test uses one shared Python actor and the public
    runtime admission and identity inspection APIs.
  - [x] The initial Host generated case passes in the retained privileged VM.
  - [x] Pass the initial direct-`runc` generated case.
  - [x] Pass the initial Kubernetes generated case.
  - [x] Remove the matching old monolithic case and compatibility field.
  - [x] Start `ready.py` as PID 1 and use `add_actor` for the moved-task
    actor. Restore its external root and installed role checks, then rerun all
    three platforms.
  - [x] Pass the corrected Host case and the complete Host platform set.
  - [x] Pass the corrected direct-`runc` case and platform set.
  - [x] Pass the corrected Kubernetes case.
  - [x] Remove the Kubernetes `MITHRIL_TEST_CGROUP` dependency. The corrected
    physical case reached `move_task` and failed because the launcher did not
    supply a Host-only path. Derive a unique move cgroup from the test token,
    own it with `ProbeCgroup`, and keep its cleanup in the platform.
  - [x] Use `ProcessFixture` exit status for a Kubernetes `add_actor` process.
    The cgroup correction reached the denied exec, but `actor_code` waited for
    PID 1 to exit. `ProcessFixture` now owns external PID 1 termination
    observation. Remove `actor_code` from `Platform` and keep exit assertions
    in each scenario.
  - [x] Restore the baseline fidelity gaps recorded above and rerun all three
    generated cases.
- [x] Orphan transition: use `native_orphan.py` through `ProcessFixture` in
  one production-backed `#[test]`. Preserve the parent, role, and execution
  assertions. Remove the actor-only test.
  - [x] Add `Host::add_actor`. It performs the real read-only runtime access,
    then starts the actor with its declared executable and complete argv.
  - [x] Add the direct-`runc` `add_actor` implementation. It uses stock
    `runc exec` with the declared interpreter and complete actor argv.
  - [x] Add the Kubernetes `add_actor` implementation. It runs the same actor
    through real `kubectl exec` with the declared interpreter and complete
    argv.
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
  - [x] Reproduce the Kubernetes `/proc/<pid>/status` `ESRCH` exit race in a
    lightweight `ProcessFixture` test. Accept it as process absence in
    `wait_gone`; keep unrelated errors fatal. Rerun Host, direct-`runc`, and
    Kubernetes subreaper cases.
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
- [x] Double-fork transition: use `double_fork.py` through `ProcessFixture` in
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
  - [x] Pass the Kubernetes generated case.
  - [x] Remove the matching `ReparentCase::double_fork` block, result fields,
    and old actor only after all three generated cases pass.
- [x] Leader-first thread exit and reference lifetime: keep the process and
  entry reference counts, tombstones, release action, and reclamation checks.
  - [x] Use `ready.py` as the environment PID 1 and use `add_actor` for
    `native_leader_first.py` on all three platforms.
  - [x] Assert the added actor's external root class and installed role.
  - [x] Restore the runnable worker-coordinate assertion and the exact
    creator-edge child-cookie assertion from `95775f48`.
  - [x] Keep an exited group leader `Exited` when task iteration sees its
    kernel zombie. Do not accept a live task with an exited coordinate.
  - [x] Use the exact profile reference baseline owned by the environment PID
    1 and the added actor. Preserve one reference after the worker exits.
  - [x] Bound the actor's release wait so failed assertions cannot block
    teardown indefinitely.
  - [x] Pass the Host generated case.
  - [x] Pass the direct-`runc` generated case.
  - [x] Pass the Kubernetes generated case.
  - [x] Remove the matching old probe code and compatibility bundle fields.
- [x] Node-first PID reuse: keep one small parameterized Rust test in
  `pid_reuse.rs`, one shared Python actor, one explicit assertion block, and
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
  - [x] Remove the `ReuseResult` bridge. Keep all result assertions in the
    87-line scenario. The exact Host, direct-`runc`, and Kubernetes cases
    passed on 2026-09-17.
- [x] TID reuse: use one Python actor through `ProcessFixture`. Keep the two
  namespace-TID actions, exact thread coordinates, and tombstone checks
  visible in a separate small scenario file.
  - [x] The Host generated case passes in the retained privileged VM.
  - [x] Remove the TID behavior and compatibility result bridge from
    `IdentityTestRunner::physical_probe`.
  - [x] The direct-`runc` generated case passes with the same Python actor and
    the production OCI hooks.
  - [x] Remove the `ReuseResult` bridge. Keep all result assertions in the
    94-line scenario. The exact Host, direct-`runc`, and Kubernetes cases
    passed on 2026-09-17.
  - [x] Reproduce the Kubernetes `SIGTERM` cleanup condition in a lightweight
    Node entry-point test. Before the fix, the exact test exited with signal
    15. It now proves that `SIGTERM` starts normal Node shutdown.
  - [x] Verify that normal Kubernetes shutdown removes both runtime admission
    socket paths before accepting the Kubernetes result.
  - [x] The Kubernetes generated case passes with the same Python actor.
- [x] Workload-first recovery: keep one small parameterized Rust test in
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
  - [x] Remove only the matching workload-first assertions from the old
    monolithic probes after all three generated cases pass. Preserve their
    other recovered-entry and concurrency assertions for later migrations.
  - [x] Keep the legacy multi-task case until small tests preserve
    its two application and two external tasks, iterator retry, ptrace
    bootstrap, internal exec, declared-probe isolation, unmatched denial,
    post-cutover activation, and cleanup assertions. The focused one-task
    recovery test does not replace these behaviors.
  - [x] Restore the nonzero recovery-attempt assertion and rerun all three
    generated cases before the old workload-first assertions are removed.
  - [x] After the old assertion removal, rerun the unchanged Host,
    direct-`runc`, and Kubernetes cases. They passed in 32.21, 41.25, and
    110.87 seconds.
  - [x] Restore actor-first behavior after administrative-exec work. Direct
    `runc` now reserves the next policy container ID and does not publish a
    Running observation before policy exists. Kubernetes accepts zero active
    targets before Node starts and keeps the actor stdin across the K3s
    runtime restart. The unchanged direct-`runc` case passed. The unchanged
    Kubernetes case passed in 70.05 seconds on 2026-09-17.
  - [x] Rerun the old direct-runtime probe. Its remaining iterator retry,
    ptrace bootstrap, internal exec, probe isolation, denial, post-cutover,
    and cleanup checks passed.
- [x] Four-task workload-first recovery: add one small parameterized Rust
  test. Start one application root and its child. Add one external root and
  its child before policy and Node start. Recover the same four tasks on Host,
  direct `runc`, and Kubernetes.
  - [x] Use one shared Python actor for both two-task trees. Keep the test file
    below 100 lines.
  - [x] Preserve the complete recovery phase, nonzero attempt ID, one
    application entry instance, two application tasks, two external tasks,
    four expected tasks, and zero invalid tasks.
  - [x] Preserve the recovered application root and initial role. Preserve the
    distinct restored external root, zero admitted entry rule, external role,
    and distinct entry instance.
  - [x] Pass the Host case and the complete Host platform set.
  - [x] Pass the direct-`runc` case and the complete direct-`runc` platform set.
    The first exact run reached Node start and failed because the long-lived
    `runc exec` client remained in the effect-controller cgroup. Move that
    client out as the existing container-start path does. The corrected exact
    case passes. The first complete run had two transient setns start failures.
    Both exact reruns and the second complete 14-test run pass.
  - [x] Pass the Kubernetes case.
    The first exact run reached the first child wait and failed because the
    externally owned Pod PID 1 has no local child exit status. Reproduce the
    same failure in a lightweight `ProcessFixture` wait test. Poll exit status
    only for a fixture-owned child or waitable PID, then rerun lightweight
    before Kubernetes.
    The second run completed all recovery assertions, then a custom actor stop
    command failed because runtime restart had closed the exec input stream.
    Reproduce that input loss in the lightweight fixture test. Keep both
    actor trees alive without input after the fork. Use `ProcessFixture::stop`
    as the only teardown action.
    The next Host run confirmed that out-of-band kill remains denied. Release
    both trees through one shared work-directory file, wait for normal exit,
    and then reap them with `ProcessFixture::stop`.
    The first in-band Host run reached normal exit, but `wait_gone` treated its
    unreaped zombie as an actor failure. The next Kubernetes run recovered and
    released all tasks, but its disconnected `kubectl exec` client exited with
    code 1. Make `wait_gone` reap an owned wrapper and continue until the
    tracked host PID disappears. Do not use transport status as actor status.
    The corrected case passes on Host in 23.40 seconds, direct `runc` in 24.15
    seconds, and the retained Kubernetes cluster in 104.47 seconds.
  - [x] Remove only the matching four-task count and root assertions from the
    old Rust and shell probes after all three cases pass. Keep task-change
    retry, ptrace bootstrap, internal exec, probe isolation, denial evidence,
    post-cutover activation, and cleanup for separate migrations.
- [x] Retained-host restart: keep host shutdown, retained map validation,
  production recovery, stable map IDs, and ownership rejection visible.
  - [x] Add one small Host test and one concrete owner. Keep concurrent lease
    rejection, retained-link rejection, displaced-map rejection, restart, map
    identity, and live-manifest failure as explicit actions and assertions.
  - [x] Pass the Host case in the retained privileged VM.
  - [x] Remove only the matching restart assertions and result fields from
    `IdentityTestRunner::physical_probe`. Keep the restart required by the
    cgroup-lifetime case until that separate replacement passes.
- [x] Cgroup lifetime reuse: recreate the cgroup path after recovery. Keep the
  new cgroup ID, binding nonce, live interval, process identity, and role
  assertions visible.
  - [x] Reuse `RetainedHost` for kernel-host shutdown and restart. Keep both
    binding publications and all three identity activations in the test.
  - [x] Keep the standard Host test at 99 lines. Use `ProcessFixture` for both
    actor lifetimes and use the platform only for physical cgroup placement.
  - [x] Compare the cgroup ID, binding nonce, live interval, task cookie,
    process-state ID, execution ID, root class, and role with commit
    `95775f48`.
  - [x] Pass the exact Host test in the retained privileged VM. Remove only
    the matching cgroup-lifetime block and result fields from
    `IdentityTestRunner::physical_probe`.
  - [x] Pass the local crate suite, strict crate Clippy, all 24 Host platform
    cases, the remaining native identity probe, and the repository Rust CI
    gate after the deletion.

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
  - [ ] Replace the pre-policy `mount_global_mutation_epoch` read. The
    production policy owner creates this hash-map row during policy
    installation. The old probe reads it before policy installation. The full
    VM run passed 26 Host tests and the direct-`runc` entry-role probe, then
    stopped at this stale assertion on 2026-09-17. Do not initialize the row
    in a test helper or change BPF behavior.
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
  production recovery operation and oracles as the Kubernetes lane. Remove
  the old process-wide iterator pause. A direct `sudo` monitor mirrors its
  `SIGSTOP` and cannot report completion without an external continue.
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
- [ ] Independent additional entries: keep each declaration, stock exec,
  role, rule, process state, and isolation assertion.
- [x] Readiness entry policy isolation: use stock `grep`. Require the
  readiness role to read the application-denied file, then deny its own exact
  file read with matching role, admission-rule, and kernel evidence.
  - [x] Keep the 73-line standard test below 100 lines. Reuse the shared actor,
    entry-isolation policy family, FIFO readiness owner, and result fields.
  - [x] The exact Host case passed in 29.41 seconds. The existing startup case
    passed in 28.71 seconds with the expanded shared policy.
  - [x] The exact direct-`runc` case passed in 37.38 seconds. The existing
    startup case passed in 36.80 seconds with the expanded shared policy.
  - [x] The exact Kubernetes case passed in 72.08 seconds. The existing
    startup case passed in 71.84 seconds with the expanded shared policy.
  - [x] Remove only the matching readiness loop action and compatibility gate
    after all three platform cases pass.
- [x] Liveness entry policy isolation: use stock `wc`. Require the liveness
  role to read the application-denied file, then deny its own exact file read
  with matching role, admission-rule, and kernel evidence.
  - [x] Keep the 72-line standard test below 100 lines. Reuse the shared actor,
    entry-isolation policy family, FIFO readiness owner, and result fields.
  - [x] The exact Host case passed in 30.79 seconds.
  - [x] The exact direct-`runc` case passed in 38.46 seconds.
  - [x] The exact Kubernetes case passed in 74.60 seconds.
  - [x] Remove only the matching liveness loop action and compatibility gate
    after all three platform cases pass.
- [x] Startup entry policy isolation: use stock `cat`. Require the startup
  role to read a path tree denied to the application role, then deny its own
  exact file read with matching role, admission-rule, and kernel evidence.
  - [x] Put the bounded FIFO-reader wait in `ProcessFixture`. Report an early
    actor exit, its status, the FIFO path, the last reader state, and stderr.
    The unchanged Host, direct-`runc`, and Kubernetes cases passed in 30.88,
    37.42, and 73.70 seconds after this change.
  - [x] The exact Host case passed twice in 29.58 and 29.08 seconds.
  - [x] The exact direct-`runc` case passed in 36.44 seconds.
  - [x] The exact Kubernetes case passed in 69.11 seconds.
  - [x] Removed only the matching startup loop action, result field, and shell
    gate after all three platform cases passed.
- [x] Reusable PostStart entry: use the existing
  `external_roots::concurrent_roots_stay_distinct` standard test. Start the
  same signed PostStart entry twice. Require different host PIDs, task
  cookies, process-state IDs, and execution IDs. Require the same active role,
  policy generation, and admitted entry rule.
  - [x] The exact Host case passed in 41.80 seconds. The complete privileged
    Host lane passed 28 tests in 826.25 seconds on 2026-09-15.
  - [x] Pass the exact direct-`runc` case and its complete privileged lane.
    The exact case passed in 38.72 seconds. The complete privileged lane
    passed 19 tests in 578.56 seconds on 2026-09-15. The lane also verified
    that command readiness precedes pidfd ownership, so a denied runtime exec
    reports the `runc` `EACCES` result instead of an intermediate `ESRCH`.
  - [x] Pass the exact Kubernetes case and its complete privileged lane. The
    exact case passed in 75.65 seconds. The complete privileged lane passed 21
    tests in 1,451.24 seconds on 2026-09-15 against the retained K3s cluster.
  - [x] Remove the matching legacy invocation, compatibility result, and shell
    gate. Keep the existing standard test as the only replacement.
- [x] Declared probe mismatch and runtime infrastructure effects: keep exact
  argv, role-zero, and denial evidence checks.
  - [x] Add one 94-line standard platform test. Use the production observation
    snapshot. Do not add a test effect result or invoke `mithril-inspect`.
  - [x] Pass Host and its complete lifecycle. The exact Host case passed in
    32.49 seconds. The complete Host lifecycle passed 22 tests in 231.30
    seconds on 2026-09-16.
  - [x] Pass direct `runc` and its complete lifecycle. The exact `runc` case
    passed in 39.12 seconds. The complete `runc` lifecycle passed 17 tests in
    220.99 seconds on 2026-09-16.
  - [x] Pass Kubernetes and its complete lifecycle. The exact case passed in
    73.74 seconds. The complete lifecycle passed 18 tests in 455.40 seconds on
    2026-09-16.
  - [x] Remove the matching direct-`runc` block and its two compatibility
    fields after all three platform cases pass. Keep the separate two-node
    Kubernetes case until its complete scenario has a verified replacement.
- [x] Live policy replacement: keep delivery, acknowledgement, guarded process
  migration, later exec, and old-generation holder checks explicit.
  - [x] Add one 97-line standard platform test. Use one shared actor and the
    existing `install_policy` operation for the update.
  - [x] Read `/fixtures/policy_replace.py` before actor readiness under the
    first policy. Deny the same read in the second policy. Require `EACCES`,
    the replacement generation, the retained task identity, and a descendant
    exec in the replacement generation.
  - [x] Reproduce the Kubernetes no-op update in lightweight. An identical
    policy specification must not create a new policy generation. Use the
    existing actor and actor-sleep policies as a real specification update.
  - [x] Pass Host and its complete lifecycle. The exact Host case passed in
    43.77 seconds. The complete Host lifecycle passed 23 tests in 275.40
    seconds on 2026-09-16.
  - [x] Pass direct `runc` and its complete lifecycle with the corrected
    policy update. The exact case passed in 50.32 seconds. The complete
    lifecycle passed 18 tests in 246.86 seconds on 2026-09-16.
  - [x] Pass Kubernetes and its complete lifecycle. The exact case passed in
    79.26 seconds. The complete 19-test lifecycle passed in 541.91 seconds on
    2026-09-16.
  - [x] Remove the matching legacy actor protocol, assertions, and three
    compatibility fields after all three platform cases pass. Keep the policy
    update that later restart and entry cases still consume. Schema 40 and the
    remaining privileged direct-`runc` probe passed. This reduced
    `effect/runc.rs` by 235 lines.
- [x] Administrative exec: keep Control authorization, node slot arm, stock
  runtime exec, one-use consumption, replay denial, trace, and reconciliation
  operations explicit.
  - [x] Pass Host and its complete lifecycle. The test requires unapproved and
    mismatched exec denial, the armed and consumed slot states, the mismatch
    trace, administrative role 3, one-use consumption, slot reconciliation,
    and replay denial. The complete 24-test lifecycle passed in 230.74 seconds
    on 2026-09-17.
  - [x] Pass the exact direct-`runc` case. The runc platform now publishes the
    CRI Running observation after PID 1 starts. The exact case passed in 42.49
    seconds on 2026-09-17.
  - [x] Recheck the shared success and mismatch-trace cases on Host and direct
    `runc`. All four exact cases passed on 2026-09-17.
  - [x] Pass the exact Kubernetes case. Keep the Helm permission narrow: the
    `kube` WebSocket client requires `get` and `create` on `pods/exec`; it does
    not require `get` on Pods. Rebuilt Node and Control images from the current
    source before the final run. The exact case passed in 67.98 seconds on
    2026-09-17.
  - [x] Preserve the legacy process-success, policy-generation, expected-argv,
    mount-object trace, denied-role, errno, and pending-exec cleanup checks in
    the small tests. The success case is 88 lines, or 90 lines with its two
    attributes. The trace case is 98 lines, or 100 lines with its attributes.
  - [x] Keep ordinary Kubernetes `pods/exec` tasks in the restricted external
    role. Invoke the Control admission webhook only for the trusted Mithril
    approval group. A matching armed slot can then select the approved role.
  - [x] Remove the matching direct-`runc` approval sequence, result fields,
    shell result checks, and dead waits. Keep the separate recovered-container
    binding assertion for its own migration. This removes 478 net lines from
    `effect/runc.rs` and nine lines from `run.sh`. The remaining direct-`runc`
    probe passed. Its result omits the migrated fields and retains recovery,
    restart, upgrade, terminal-evidence, external-entry, and cleanup results.
  - [x] Recheck the complete platform lifecycles after the assertion and
    cleanup changes. Host passed 25 tests in 239.49 seconds. Direct `runc`
    passed 20 tests in 222.46 seconds. Kubernetes passed 20 tests in 517.59
    seconds after approval rechecked stable Node readiness at its operation
    boundary. The unchanged Kubernetes moved-exec test also passed.
  - [x] Replace the Kubernetes post-consumption assertion with the separate
    `consumed_exec_is_restricted` Rust test. It uses `Platform::add_actor` on
    Host, direct `runc`, and stock Kubernetes `pods/exec`. It explicitly
    requires role 2, rule 0, `UNSUPPORTED_OBJECT`, and `EACCES` after the
    approved slot is consumed. The test is 65 lines, or 67 lines with its
    attributes. Host passed in 34.92 seconds, direct `runc` passed in 37.99
    seconds, and Kubernetes passed in 86.01 seconds on 2026-09-17.
  - [x] Remove the matching legacy Rust and shell assertions after all three
    platform cases pass. The Rust replacements passed on Host, direct `runc`,
    and Kubernetes. The launcher now invokes the standard Rust lifecycle and
    recovery tests. This removes the 628-line guest scenario, its 301 lines of
    private inputs, and the obsolete skip option.
- [ ] Node restart and PreStop retention: keep the public stop, start, inventory,
  binding, and lifecycle operations explicit.
  - [x] Remove the scenario-specific `restart_node` operation. Add the generic
    `stop_node` operation and keep `stop_node`, `start_node`, and `node_ready`
    visible in the 23-line scenario. Remove the `actor_code` and redundant
    `pending` platform operations without removing their assertions.
  - [x] Add `node_restart_keeps_actor` for Host. The platform test starts
    Control, Node, policy, and one actor. It stops and starts the real Node and
    requires the complete task snapshot and coordinate to stay unchanged. The
    corrected exact test passed in 60.27 seconds on 2026-09-17.
  - [x] Pass the same test on direct `runc`. The exact privileged test passed
    in 63.08 seconds on 2026-09-17.
  - [x] Pass the same test on Kubernetes. The exact physical test passed in
    107.89 seconds on 2026-09-17.
  - [x] Remove the matching legacy restart snapshot, result field, and shell
    assertion after all three platform cases pass.
  - [ ] Remove the reconstructed binding, policy, and identity owners after
    their remaining PreStop, administrative recovery, mount retention, and
    generation retirement consumers move to small tests.
- [ ] Kernel object upgrade: keep the second production object, manifest, map
  ID, link pin, program tag, and running-identity checks explicit.
- [ ] Post-point-of-no-return evidence and generation retirement: keep the
  terminal exec, evidence retention, holder release, and absence proof.
- [ ] External entry and external cgroup entrant: keep both physical execs and
  rule-zero fail-closed evidence assertions.
- [ ] Final container and resource cleanup: require container success and
  absence of the pin root, lease, cgroup, and fixture root.

### Native and Kubernetes identity

- [x] Replace the `IdentityTestRunner::physical_probe` authorization replay
  with small standard tests. Remove its result flags and hidden stateful helper.
- [ ] Remove the now-empty native base-bundle command and its obsolete pin,
  lease, and cgroup arguments after the Kubernetes launcher no longer uses it.
- [ ] Migrate native binding-gap, external ambiguity, cgroup escape, fork,
  exec, reparent, PID reuse, owner restart, object upgrade, and authorization
  replay groups one commit at a time. Keep their `KernelHostOwner`,
  `WorkloadBindingOwner`, and `NativeSecurityStateOwner` calls explicit.
- [x] Dismantle `physical_kubernetes_exec_probe` one behavior at a time. Do
  not add a Kubernetes-only scenario framework or a special Node startup
  path. Use the same small Rust-test and `Platform` structure as the other
  migrated identity scenarios.
  - [x] Audit the original sequence and all result fields. The Pod starts
    before identity activation. The old probe then starts an identity-only
    `KernelHostOwner`, publishes one binding, and activates identity without
    an effect policy. It does not start Control or Node.
  - [x] Confirm that an execution `Allow` and an entry declaration are
    independent. A real Node must deny an unlisted runtime entry with `EACCES`
    in Observe and Protect modes. This result is not a contradiction and does
    not require a BPF change.
  - [x] Add `runtime_exec::unlisted_exec_is_denied` as separate fail-closed
    coverage. Use `add_actor` with one installed but unsigned actor entry.
    Require the same `EACCES` result on Host, direct `runc`, and Kubernetes.
    This test does not replace the successful restricted-entry checks below.
    - [x] Pass Host and commit it. The exact test passed in the retained
      lightweight VM on 2026-09-15 in 34.49 seconds.
    - [x] Pass direct `runc` and commit it. The exact test passed in 38.73
      seconds. The complete direct-`runc` lane passed 17 tests in 673.41
      seconds on 2026-09-15.
    - [x] Pass Kubernetes and commit it. The exact test passed in 105.99
      seconds on 2026-09-15.
      The first run found that the Kubernetes work mount does not contain a
      `bin` directory. The same actor failure was reproduced with an empty
      lightweight work directory before the shared actor setup was corrected.
  - [x] Replace the pre-existing Pod-root case with `four_tasks_recover`. Start
    the actor and its tasks before policy and Node. Let the real Node recover
    the running workload through its production loop. Require the
    `active_recovered` application root and the distinct rule-zero
    `restored_or_unknown_root`. Do not preserve the old `fail_closed_unknown`
    application result. It came from direct identity-host activation without
    Control, Node, an effect policy, or production recovery.
  - [x] Replace the successful runtime-entry classifications with
    `runtime_entries::runtime_entries_stay_distinct` on Host, direct `runc`,
    and Kubernetes. Use only `add_actor` for process entry.
    - [x] Install one policy that declares Python, Bash, cat, wc, and cp as
      additional entries with five target roles. Keep the fallback role empty.
    - [x] Require each added process to be a creator-free
      `external_runtime_root` with `qualified_registered_role`, its configured
      numeric role, and a nonzero admission rule.
    - [x] Require distinct task cookies, process-state IDs, execution IDs,
      roles, and admission rules. Require cp to copy the exact fixture bytes.
    - [x] Pass Host, direct `runc`, and Kubernetes in that order. The exact
      Host case passed in 34.11 seconds, the direct-`runc` case passed in 33.99
      seconds, and the Kubernetes case passed in 67.15 seconds on 2026-09-15.
      The first Kubernetes run found a transient `runc` helper in the actor
      cgroup. `group_wait_skips_runtime_helper` reproduced the condition in the
      lightweight fixture test before the shared readiness wait was corrected.
    - [x] Remove the matching direct-CRI, ordinary exec, TTY exec, and copy
      classification blocks and their obsolete compatibility fields.
    - [x] Remove the legacy distinct-role calculation, compatibility field,
      and shell gate. The shared test asserts all six role and admission-rule
      identities directly.
  - [x] Replace the native-child case with `child_exec_keeps_identity`. The real
    Node admits its declared Python entry with the configured role. Preserve the
    creator-free external-runtime parent, the child's creator and real-parent
    cookies, inherited role, and absent child root and installed-role classes.
    The existing exact Host, direct-`runc`, and Kubernetes runs passed. The
    matching legacy block and compatibility fields are removed.
  - [x] Keep bounded actor release, process exit, namespace deletion, pin and
    lease deletion, and work-directory cleanup in each replacement.
  - [x] Do not count `restricted_roots` as runtime-exec coverage. It preserves
    the rule-zero restricted identity after cgroup placement, not after a
    runtime exec.
  - [x] Do not count `external_roots` as restricted-entry coverage. It uses a
    signed additional entry, a nonzero admission rule, and a qualified role.
  - [x] Reuse `child_exec` for native-child coverage. Its declared entry is
    required by the real Node admission path. The legacy identity-only host did
    not exercise this production boundary.
  - [x] Remove each matching block and compatibility field only after its
    small replacement passes the required Host, direct-`runc`, and Kubernetes
    gates. Remove the legacy function after all seven behaviors are replaced.
- [x] Replace `physical_kubernetes_lifecycle_sleep_probe` with one generated
  Kubernetes Rust test. This is a Kubernetes-native lifecycle fact, not a
  Host or direct-`runc` behavior.
  - [x] Use the shared `ready.py` actor as container PID 1. Start real Control
    and Node, install the signed policy, and create the real actor Pod. Use its
    mounted ready file because Kubernetes logs wait for the handler to finish.
  - [x] Configure the Pod with the native `postStart.sleep` handler through
    reusable Kubernetes physical setup. Do not run a sleep process or emulate
    the handler in a test helper.
  - [x] While the native handler is pending, assert that `cgroup.procs`
    contains only the actor PID and that the Pod is not Ready.
  - [x] Wait for the Pod to become Ready, then stop the actor and remove all
    scenario resources with bounded diagnostics.
  - [x] Remove only the matching hidden probe call and method from
    `identity.rs` after the generated test passes. Keep the compatibility
    result field optional until the legacy bundle schema is removed.
  - [x] Remove the obsolete lifecycle-sleep fixture copy from `run.sh`. Keep
    the historical fixture file while implementation records link to it.
  - Proof: the complete serial lightweight suite passed 89 tests. Strict
    Clippy passed. The generated Kubernetes test passed in 132.46 seconds.
    The 18-test Kubernetes run passed 17 tests and exposed a platform lookup
    regression in namespace-init. After the lookup was isolated to this
    pre-readiness case, namespace-init passed in 112.56 seconds. The complete
    Kubernetes rerun is pending the test-runtime review.
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
- `identity/authorization_tests.rs::invalid_auth_is_rejected`
- `identity/authorization_tests.rs::replay_is_durable`
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
