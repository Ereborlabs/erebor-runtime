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
- Before a single-VM platform lane, stop old qualification VMs from the same
  source checkout. Keep a retained VM disk and K3s state when more work is
  expected. An intentional harness-owned two-node pair can run only for its
  two-node lane.
- Do not rename tests, add `z` prefixes, move modules, or depend on libtest
  discovery order to make lifecycle users contiguous.
- Put the lifecycle and platform in each generated leaf test name, such as
  `identity_host`. A launcher selects this suffix to run one lifecycle and one
  platform in a process. Parent module names do not control lifecycle order.
- Share a named lifecycle between all tests that can use the same retained
  Control, Node, and runtime integration. A lifecycle is a resource boundary,
  not a scenario label. An omitted lifecycle is temporary until the test is
  classified.
- Use a dedicated lifecycle only when a test requires an incompatible owner
  start, stop, outage, restart, or retained-state order. Compare the test with
  the pre-TODO baseline before adding that boundary.
- Give each scenario that starts an actor before the first Node admission a
  separate lifecycle. After the runtime gate is installed, a stopped Node
  must make a new container fail closed. Do not weaken that production gate
  so two pristine-start recovery scenarios can share one lifecycle.
- Do not change a Node-first baseline check into a recovery check only to make
  its actor executable. Declare the required actor entry in that test policy,
  keep the original production order, and reuse the compatible lifecycle.
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
- [x] Audit the current lifecycle names. The suite has 22 platform lifecycle
  groups. `identity`, `identity_physical`, `mount_late`, `mount_alias`, and
  `exception` already share compatible tests. The other 17 groups contain one
  test each and require baseline review.
- [x] Keep separate pristine-start lifecycles for unknown create, chmod, and
  truncate recovery checks. The pre-TODO probe started the actor before it
  replaced the kernel host and activated policy. A Node-first create trial
  changed the expected `EACCES` result to success and was reverted.
- [x] Audit all 17 singleton groups against commit `95775f48`. Fourteen groups
  start the actor before the first Node admission: `bpf_recovery`,
  `external_roots`, `file_create`, `file_chmod`, `file_truncate`, `mount_race`,
  `namespace_recovery`, `proc_recovery`, `ptrace_recovery`, `ptrace_unmatched`,
  `recovery_tasks`, `signal_recovery`, `signal_unmatched`, and
  `workload_recovery`. They need a pristine runtime gate. `node_restart`
  replaces the retained Node. `terminal_entry` and `terminal_retirement`
  retain terminal evidence that must not become another test's initial state.
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
- [x] Extend the reuse test with a denied unlisted entry, namespace cleanup,
  the next policy, and a fresh actor identity. The same test passed on Host,
  direct `runc`, and Kubernetes in 35.26, 48.61, and 87.55 seconds.
- [x] Reject a second lifecycle for the same platform in one process. The
  focused owner test passed. It requires the launcher to start a separate test
  process instead of restarting Node.
- [x] Recover a lifecycle after a scenario assertion panics. The focused
  mutex-poison regression passed. A failing Host runtime-entry assertion then
  removed its output directory, pin, lease, actor cgroup, and Node cgroup.
- [x] Qualify the direct-`runc` startup failure found by the full gate. The
  first lifecycle passed 23 tests, but `runtime_entries_stay_distinct` had one
  runc helper exit before PID publication. Cleanup removed its runc state and
  actor cgroup. The exact test then passed in a fresh process, and the complete
  24-test lifecycle passed in 245.11 seconds. The runc readiness error now
  names the entry and reports the last production effect decisions. No test,
  policy, timeout, or production behavior changed.
- [x] Restore the original readiness boundary for the leader-exit actor. The
  migrated test now waits for `native-fixture-ready` before its first identity
  lookup. This matches the pre-TODO `ProcessFixture::start` behavior. The
  focused Host, direct-`runc`, and Kubernetes tests passed in 28.64, 35.14,
  and 73.41 seconds. The
  complete direct-`runc` lifecycle then passed all 25 tests in 556.32 seconds.
  The runtime-entry case also passed in the shared lifecycle. Its PID startup
  error now reports identity health counters and recent production decisions.
  No policy, timeout, or production behavior changed.
- [x] Reproduce and fix the Kubernetes non-leader thread interleaving in
  lightweight. The actor now creates and reaps a decoy thread before the
  target. The test finds the target by its observed host TID and keeps the
  creator, process, execution, role, and counter assertions. The exact test
  passed on Host, direct `runc`, and Kubernetes in 33.59, 33.80, and 71.40
  seconds. The strict TID-reuse caller also passed on Host and direct `runc`
  in 30.27 and 31.93 seconds.
- [x] Qualify the Kubernetes actor-admission failures found by the next full
  identity lifecycle. The lifecycle passed 20 tests. Four unrelated tests
  failed before actor readiness while Node reported policy convergence and
  then allowed runtime preparation. The exact non-leader test already passed.
  Use the existing lifecycle owner to run eight protected actors. Each actor
  creates and reaps 512 threads. The lifecycle creates 4,096 threads in total.
  Alternate signed policies, retain the same
  Control and Node, require a valid actor identity after each start, require
  zero hard identity failures. The Host case reproduces the physical failure.
  A task-reconciliation scan ran while `task_alloc` held the process transition
  guard. The scan marked the original actor coordinate fail-closed. The actor
  and denied file writes had the same task cookie. BPF then denied the actor
  writes with `CORRUPT_IDENTITY_OR_GENERATION` and `EACCES`. The approved fix
  keeps the fallback CRI inventory check. An unchanged inventory returns before
  policy or task recovery. A real recovery scan defers a process while its
  transition guard is active. A later scan verifies it. The focused Host test
  passed in a privileged VM in 78.61 seconds. It retained one Control and Node,
  replaced the policy for each actor, and completed all 4,096 thread creations
  with zero hard identity failures. The same direct-`runc` test passed in
  127.92 seconds. One real container-change recovery raised the soft
  `reconciliation_required` retry counter, and Node then restored readiness.
  No allocation, coordinate, placement, missing-identity, or exec-guard failure
  occurred. The Kubernetes test passed in 224.78 seconds. It used one retained
  K3s cluster and one real Helm-deployed Control and Node for all eight actor
  Pods. The first complete Host lifecycle exposed seven cumulative placement
  mismatches from earlier intentional move tests. The churn test now records
  its health baseline after policy readiness and requires no counter increase.
  The complete Host lifecycle then passed all 30 tests in 321.34 seconds. Do
  not change Kubernetes readiness to hide a result. Add direct `runc` only
  after Host passes. Add Kubernetes only after direct `runc` passes.
- [x] Do not start fallback CRI reconciliation while the containerd event
  stream is connected and quiet. A runtime event or stream failure starts the
  recovery check. An unavailable event API keeps the bounded inventory scan.
  Keep the unchanged-inventory early return and repeated-recovery idempotency.
  The seven CRI runtime tests passed. The unchanged churn scenario passed on
  Host in 83.58 seconds, direct `runc` in 135.47 seconds, and Kubernetes in
  213.48 seconds on 2026-09-21.
- [x] Recover Node readiness projection when the Kubernetes API restarts during
  the first Node patch. The Helm runtime installer restarts K3s after it starts
  the Control and Node Pods. An unbounded patch could keep the readiness owner
  blocked after K3s recovered. The lightweight owner test stalls the first
  patch and requires a second patch after the five-second deadline. All 10
  Node-readiness owner tests passed. The three Kubernetes exception tests then
  passed in 146.09 seconds on 2026-09-22.
- [x] Defer an inconsistent CRI inventory snapshot during container start.
  `ListContainers` and `ContainerStatus` can report different states while
  `StartContainer` is in progress. Do not combine those records into one
  runtime identity. Keep the existing binding and retry after the next runtime
  event. The lightweight regression failed before the fix and passed after it.
  All 257 Mithril Node tests passed. The three Kubernetes exception tests then
  passed in 145.50 seconds on 2026-09-22.
- [x] Accept CRI task-PID discovery while the same container remains in the
  `Created` state. The physical failure kept every stable identity field but
  changed `init_pid` from zero to the assigned task PID before CRI reported
  `Running`. The lightweight regression failed before the fix and passed after
  it. All 257 Mithril Node tests and strict Clippy passed. The exact Kubernetes
  entry-role scenario passed in 65.41 seconds on 2026-09-22. No stable identity
  field was relaxed. Refresh the complete retained K3s preload archive through
  the existing image helper; a direct one-image import is replaced when the
  runtime-hook setup restarts K3s. The live Node then used manifest
  `b4953ffd`. Policy replacement passed in 72.16 seconds, churn passed in
  201.66 seconds, and all 25 shared Kubernetes identity tests passed in 783.56
  seconds.
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
- Keep `maximumUses` and `requestedUses` as the bounded-use contract. Do not
  restrict an exception to one use in this refactor.
- Treat the signed use-start deadline as the time limit on unused authority.
  The deadline does not limit a process that an exception already started.
- Treat consumed and expired exceptions as terminal. Do not send a later
  revoke for either state.
- Do not expose an external revoke operation. Exception-object or container
  deletion is a cleanup trigger, not a separate user action.
- Control and Node can use their existing private signed restrictive
  transition to clean up active authority. Keep that protocol internal. Do
  not add a public revoke API or another Node cleanup path.
- Apply private exception cleanup before the active base-policy owner is
  retired. Then use normal exact binding and generation cleanup for the
  deleted container.
- Keep durable exception counters and receipts as audit records. They do not
  authorize an action without a live exact binding.

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
- Treat this limit as a size check, not as proof that a legacy test runner is
  retired. Replace each old runner scenario with a verified platform test.
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
- Run the complete Host, direct-`runc`, and Kubernetes suites only when a
  shared infrastructure, Platform, Node, Control, or BPF change can affect
  unrelated scenarios, when focused results show cross-scenario regression
  risk, or before delivery.
- For a scenario-only migration, run only its exact Host, direct-`runc`, and
  Kubernetes cases.
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
  and all required lightweight and Kubernetes checks pass. Also require every
  old scenario runner and shell-owned scenario assertion to be retired.

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
| `NetworkTestRunner::physical_probe` | 753 | `two-node-network.sh` in both node directions |
| `EffectTestRunner::recovered_container_entry_probe` | 1,028 | `two-node-convergence.sh` recovered-container entry lane |
| `IdentityTestRunner::physical_kubernetes_probe` and its private cases | 4,900 combined | `run.sh --with-k3s` identity lane |

## Current compliance audit

The current tree does not meet the size, naming, or runner-retirement gates.
Do not mark the work complete while these entries remain. File size does not
decide whether a runner still needs replacement.

This table lists the files above 2,000 lines and the below-limit network
runner that still needs replacement:

| Source | Current lines | Open work |
| --- | ---: | --- |
| `effect/runc.rs` | 6,864 | Size and runner retirement |
| `identity.rs` | 5,425 | Size and runner retirement |
| `effect.rs` | 3,267 | Size and runner retirement |
| `effect/child.rs` | 2,991 | Size and runner retirement |
| `control_tls.rs` | 2,416 | Size and runner retirement |
| `effect/network.rs` | 1,505 | Runner retirement; size limit met |

The behavior sections below are the runner-retirement inventory. This size
table does not close any runner or shell action.

Runner retirement is a separate, open check. In particular:

- [ ] Retire `NetworkTestRunner::physical_probe` in `effect/network.rs` (1,505
  lines). Replace each remaining local and two-node behavior with the same
  small Rust platform test on each applicable platform. Then remove the old
  `mithril-network-test` probe command and the scenario actions and assertions
  in `run.sh` and `two-node-network.sh`. Keep this item open even though the
  source file is below 2,000 lines. The detailed behavior list is in
  [Network](#network).

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
  - [x] Use canonical local Node and Control image names. If a Docker archive
    omits the name of the pinned multi-architecture actor image, pull only that
    exact digest after archive import. The fresh retained K3s store contains
    the exact actor digest, and the VM harness behavior checks pass.
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
- [x] Accept an unchanged Control workload inventory during an explicit
  repeated policy sync. Control returns `false` when the valid inventory did
  not change. The shared platform must still reconcile the policy. The
  two-test mount lifecycle passed Host in 36.26 seconds, direct `runc` in 49.79
  seconds, and Kubernetes in 98.18 seconds.
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
  - Keep `workload_recovery`, `recovery_tasks`, `external_roots`,
    `ptrace_recovery`, and `signal_recovery` separate. Each starts its actor
    before Node and must not inherit an already-running identity Node.
  - The current source at `bc0af1fa` passed all generated platform tests on
    2026-09-18: 39 Host cases, 30 direct-`runc` cases, and 30 Kubernetes
    cases. The run used one process for each lifecycle and platform. The final
    Kubernetes workload-recovery case passed in 66.85 seconds with the actor
    image digest that `run.sh` specifies. This result does not close the
    remaining outage migrations.
  - The current source at `309359c` passed all generated platform tests on
    2026-09-18: 41 Host cases, 32 direct-`runc` cases, and 32 Kubernetes
    cases. Reported test time was 608.97 seconds for Host, 470.69 seconds for
    direct `runc`, and 1,165.07 seconds for Kubernetes. The
    first Kubernetes identity run passed 22 of 23 cases. One actor Pod exited
    with code 1 and empty logs. The same three-test transition passed on Host,
    direct `runc`, and Kubernetes. The unchanged Kubernetes identity rerun
    passed all 23 cases. The VM had no resource pressure. No code changed for
    this transient failure.
  - The current source at `e605585` passed all generated platform tests on
    2026-09-18: 44 Host cases, 35 direct-`runc` cases, and 35 Kubernetes
    cases. The run used one process for each lifecycle and platform. Reported
    test time was 671.81 seconds for Host, 528.98 seconds for direct `runc`,
    and 1,225.54 seconds for Kubernetes. All 22 processes passed without a
    rerun or source change. The Kubernetes run retained the existing K3s
    cluster.
  - The current source at `50910f48` passed all generated platform tests on
    2026-09-19: 50 Host cases, 41 direct-`runc` cases, and 41 Kubernetes
    cases. The run used one process for each lifecycle and platform. Reported
    test time was 813.06 seconds for Host, 679.19 seconds for direct `runc`,
    and 1,554.23 seconds for Kubernetes. Every current lifecycle process
    passed without a rerun or source change. The Kubernetes run retained the
    existing K3s cluster.
  - On 2026-09-20, a same-checkout qualification VM had run for about 43
    hours. With that VM active, full Node startup exceeded 30 seconds. After
    an orderly VM shutdown, the unchanged Node-first and actor-first tests
    initialized Node in 24.96 and 24.15 seconds and passed. Full Node startup
    now has a 60-second bound. Ordinary readiness, action, and shutdown waits
    keep their 30-second bounds. With the new bound, the unchanged Node-first
    and actor-first exact tests passed in 40.96 and 34.38 seconds.
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
  - [x] Use that owner for the storage-failure test's certificates, Control,
    connector, and Node WAL. The test is now 98 lines. Its focused production
    Control and Node test passed. Keep the capacity failure, replay, and
    durable acknowledgement assertions in the test.
  - [x] Use the same fixture for the cursor-gap test. The 99-line test keeps
    the Control restart, cumulative acknowledgement, exact retry, and durable
    record assertions visible. Its focused production Control and Node test
    passed.
  - [x] Use the same fixture for the disconnect-replay test. Its 96-line body
    keeps first-batch receipt, disconnect, exact replay, two acknowledgements,
    and both durable-source checks visible. The focused production Control
    and Node test passed.
  - [x] Use the same WAL fixture before and after the retained-evidence reopen.
    The 91-line test still checks all 303 records, one commit group, the
    cumulative acknowledgement, durable Control receipt, and the empty Node
    backlog. Its focused test passed.
  - [x] Use the same WAL fixture for the protected-Pod admission test. The
    99-line test keeps the retained evidence intake, admission request,
    allowed response, and nonempty scheduler patch checks visible. Its focused
    test passed.
  - [x] Use the same certificate and Control fixture for the signed Node
    decommission HTTPS test. Its 99-line body keeps the signed artifact,
    submission, accepted status, and exact status readback visible. Its
    focused test passed.
- [x] Keep one synchronous readiness function with an exact timeout, resource
  path, operation name, and caller-supplied last-state diagnostic.
- [x] Put the repeated effect-attribution comparison on the existing `Task`
  owner. Compare the task cookie, active role, admitted entry rule, reason,
  effect family, operation, and kernel result. Do not hide snapshot reads,
  readiness waits, event counts, or scenario assertions in this method.
  Replace the duplicate comparison in `mount_alias`, `mount_late`,
  `mount_recursive`, `mount_move`, and `path_wildcards`. Pass the affected
  Host, direct-`runc`, and Kubernetes mount lifecycles before commit.
  The mount-alias lifecycle passed one Host case in 33.24 seconds and one
  direct-`runc` case in 34.94 seconds. The mount-late lifecycle passed four
  Host cases in 75.08 seconds, four direct-`runc` cases in 75.96 seconds, and
  four Kubernetes cases in 165.15 seconds. The Kubernetes mount-alias case
  also passed. The 92 non-privileged library tests and strict crate Clippy
  pass.
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
- [x] Fail Kubernetes actor PID readiness when the worker has terminated.
  Report its exit code, reason, message, and Pod logs. The lightweight
  early-exit test, exact Kubernetes namespace-init case, and complete 22-case
  Kubernetes lifecycle passed.
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
- [x] `signed_node_decommission_uses_the_same_durable_mtls_sequence_as_kubernetes`: use `MtlsFixture` for certificate, Control, server, and connector setup. Keep the signed artifact, Node acceptance, quarantine, completion, and ready-session checks in the test. The test is 96 lines. Its focused run and the full Rust CI procedure passed.
- [x] Replace `mtls_rejects_wrong_node_binding_and_expired_client_identity`
  with `mtls_rejects_wrong_node`, `mtls_rejects_expired_cert`, and
  `mtls_rejects_wrong_ca` in `control_tls/rejection.rs`. Each short test calls
  the production connector, requires rejection, and requires no registered
  Control nonce. The wrong-Node test also requires the exact identity-mismatch
  reason. All three focused tests and the unchanged positive registration
  test passed.
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

The evidence-queue test keeps its four segment-count checks and durable
watermark checks. It now uses one segment path and is 99 lines. Its exact
regression passed.

### Effect child and observation support

- [x] Replace the repeated child mailbox readiness loop with the shared wait.
- [x] Replace repeated process and descriptor readiness loops with the shared
  wait. Preserve PID, descriptor, and kernel-result diagnostics.
- [x] Replace the observation deadline loop with the shared wait. Preserve the
  complete recent-observation summary on failure.

The current shared-wait implementations passed all 29 non-privileged
`effect` regressions in 0.92 seconds on 2026-09-21. The check included the
child, mailbox, observation, direct-`runc`, and network fixture tests.

Keep and rerun all 23 focused regressions in `effect/child.rs`,
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

- [x] Replace `EffectTestRunner::replacement_generation_exception_probe` with
  two small shared tests. Remove the old runner, artifact builder, result
  type, and CLI command. The shared fixture owns fallible actor and resource
  cleanup. Keep policy installation, denial, one-use allowance, exhaustion,
  and attributed evidence explicit.
  - [x] Add one small shared test for a live actor across a policy replacement
    and one-use exception. Start with `actor_policy.json`, then install
    `exception_policy.json`. Require the same task cookie, a newer effect
    generation, denial before the grant, one allowed open, one exhausted
    denial, and exact File/OpenWrite evidence. Reuse `exception.py` and add
    only one CRD for the one-use grant. Add no Platform API.
    - [x] Pass Host and commit it. The 94-line test passed in 35.11 seconds.
      All four Host exception tests passed together in 88.17 seconds. The
      production File/OpenWrite events used the new generation and one
      composite atom for the denied, allowed, and exhausted secret opens.
    - [x] Pass direct `runc` and commit it. The exact case passed in 42.10
      seconds. All four direct-`runc` exception tests passed together in
      113.45 seconds with the production OCI hook.
    - [x] Pass Kubernetes and commit it. The exact case passed in 76.40
      seconds. All four Kubernetes exception tests passed together in 167.97
      seconds on the retained K3s VM.
  - [x] Preserve the old pre-replacement inactive-grant denial before removing
    the legacy probe. Start `exception.py` under `exception_policy.json`
    without an exception CRD. Require `EACCES` and an attributed
    `EXCEPTION_UNAVAILABLE` File/OpenWrite event on the initial generation.
    Reuse the existing actor and policy; add no Platform API.
    - [x] Pass Host and commit it. The 41-line test passed in 28.93 seconds.
      All five Host exception tests passed together in 95.21 seconds.
    - [x] Pass direct `runc` and commit it. The exact case passed in 29.68
      seconds. All five direct-`runc` exception tests passed together in
      97.69 seconds with the production OCI hook.
    - [x] Pass Kubernetes and commit it. The exact case passed in 64.85
      seconds. All five Kubernetes exception tests passed together in 192.26
      seconds on the retained K3s VM.
- [ ] `EffectTestRunner::physical_probe` setup and teardown: own its three
  cgroups, child processes, pin root, lease, and diagnostic output.
- [ ] `EffectTestRunner::physical_probe` observe scenario: keep the public
  node policy, binding, reader, action, and evidence operations explicit.
  - [ ] Replace the exact secret `OpenRead` in Observe mode with one small
    shared test. Give the actor the normal admitted worker role before the
    exact Observe policy replaces the initial policy. The old probe checked
    file classification, not Node recovery. Require the actor's open to
    succeed and require attributed
    `WOULD_DENY` File/OpenRead evidence with a nonzero exact-object key and
    composite atom. Reuse the existing Python open actor. Use one distinct
    signed Observe policy and add no Platform API. The old control open also
    supplies authority for the alias checks below. Do not remove it yet.
    - [x] Pass Host and commit it. The exact Host test passed in 34.19
      seconds. It used the admitted initial actor, a signed Observe policy,
      and a file created in the actor's `/tmp`. The open succeeded. The
      attributed `WOULD_DENY` event had nonzero exact-object and composite
      IDs. The test matches the actor's stable task cookie and entry ID
      because policy replacement changes its role ID on the next BPF call.
    - [x] Pass direct `runc` and commit it. The exact test passed in 35.60
      seconds with the same actor, signed policy, and assertions as Host.
    - [x] Pass Kubernetes and commit it. The exact test passed in 73.15
      seconds in the retained K3s cluster with the same actor, signed policy,
      and result assertions as Host and direct `runc`.
  - [ ] Replace the exact-secret symlink and hard-link alias checks. Keep the
    symlink's exact decision and the hard link's unresolved-object denial.
    - [x] Qualify the symlink on Host with a 65-line standard platform test.
      The same Python actor reads the original file and its symlink. The
      physical read succeeds, and production `WOULD_DENY` evidence keeps the
      original exact-object key, composite atom, and task cookie. The exact
      Host case passed in 34.28 seconds. Keep the old symlink action until its
      Protect counterpart also passes.
    - [x] Pass the unchanged symlink test under direct `runc` and commit it.
      The exact case passed in 40.37 seconds with the production OCI hook.
    - [x] Pass the unchanged symlink test on Kubernetes and commit it. The
      exact case passed in 73.41 seconds in retained K3s. The API was
      temporarily unavailable during K3s startup, then the same test process
      completed without a scenario or production change.
    - [x] Qualify the Protect-mode symlink denial on all three platforms with
      the same actor and explicit exact-object evidence.
      - [x] Pass Host and commit it. The 75-line test passed in 34.61 seconds.
        The original and symlink reads both returned `EACCES`. Their
        attributed `EXACT_POLICY_DENY` results share the exact-object key,
        composite atom, and task cookie. The policy is a distinct Protect
        input and needs no result-file allowance.
      - [x] Pass the unchanged Protect case under direct `runc` and commit it.
        The exact case passed in 40.26 seconds with the production OCI hook.
      - [x] Pass the unchanged Protect case on Kubernetes and commit it. The
        exact case passed in 73.59 seconds in retained K3s. The API was
        temporarily unavailable during K3s startup. The same test process
        completed without a scenario or production change.
    - [x] Remove only the matching old symlink action after both Observe and
      Protect cases pass. Keep the original control open for bind aliases.
      The old action, result field, and symlink fixture path are removed.
      The hard-link and bind-alias checks remain.
    - A focused Host attempt on 2026-09-24 used the public Observe policy and
      the shared Python actor. The symlink read succeeded and kept the exact
      object and composite authority. The hard-link read also succeeded, but
      the old probe requires `EACCES`. Putting the secret in a separate
      `source` directory did not change that result. The attempted test was
      removed. Do not retire the old assertion or accept the allowed read.
      Check the public policy boundary before another replacement attempt.
  - [ ] Replace both exact-secret bind-alias checks. Keep each live mount ID,
    device, inode, inode generation, and the shared composite authority.
    - [ ] Start with Protect mode. Let the shared actor create two directory bind
      mounts before Node starts. Let production Node recover the running actor
      under the signed mount policy, then install the signed exact policy.
      Require `EACCES` for the original and both aliases, three distinct
      mount IDs, and equal device, inode, inode generation, exact-object key,
      composite atom, and actor task cookie. Pass Host, direct `runc`, and
      Kubernetes in order before deleting any legacy action.
      - [x] Host passed in 34.75 seconds. The 72-line standard test used the
        old self-bind plus two directory binds. The original and both aliases
        returned `EACCES`; all three attributed exact results kept the same
        file and composite authority. The three-test Host mount-alias
        lifecycle passed together in 47.89 seconds.
      - [x] Direct `runc` passed in 61.39 seconds with the same actor, policy,
        and assertions through stock `runc` and the production OCI hook. All
        three direct-`runc` mount-alias lifecycle tests passed in 58.99
        seconds together.
      - [x] Kubernetes passed in 77.79 seconds with the same actor, policy,
        and assertions. All three Kubernetes mount-alias lifecycle tests
        passed together in 121.25 seconds. The first exact attempt stopped
        at the image preflight; the retained K3s actor image was restored
        from its verified archive before rerunning the unchanged test.
    - [ ] Repeat the alias check in Observe mode. Require successful opens
      and attributed `WOULD_DENY` evidence before deleting the old block.
      - [x] Host passed in 35.86 seconds. The standard test uses the same
        Python actor and two live directory binds as Protect mode. The
        original and both aliases opened. Three attributed `WOULD_DENY`
        results kept distinct mount IDs and equal file and composite
        authority. All four Host mount-alias lifecycle tests passed together
        in 77.94 seconds.
      - [x] Direct `runc` passed in 59.84 seconds with the same actor,
        policy, and assertions through stock `runc` and the production OCI
        hook. All four direct-`runc` mount-alias lifecycle tests passed
        together in 139.70 seconds.
      - [x] Kubernetes passed in 95.43 seconds with the unchanged Observe
        scenario body in its own recovery lifecycle. Host and direct `runc`
        requalified in 41.63 and 50.55 seconds. The three remaining
        Kubernetes mount-alias tests passed together in 124.52 seconds.
        A prior four-test shared-lifecycle run passed Protect, then denied
        three new actor Pods after Observe stopped an activated Node. The
        production OCI hook returned `DENY_NODE_UNAVAILABLE`. This is a new
        start during a Node outage, not recovery of a running actor. The
        existing direct-`runc` retained-gate probe covers the same
        fail-closed decision and absent process. The pinned Python image
        was restored from its verified archive after K3s removed it.
    - [x] Remove the duplicate old per-alias opens and their test-only result
      field after both new tests pass on all three platforms. The current
      source passed 91 local tests, formatting, strict Clippy, and the Host
      Protect and Observe cases in 40.01 and 37.53 seconds. The old probe
      denies all 6,000 baseline opens before these actions, both before and
      after this deletion. The old runner remains unqualified.
    - [ ] Replace the old resolver topology check before removing its alias
      fixture paths. It also checks the selected mount, canonical component,
      and mount namespace, which the new effect events do not expose.
    - [x] Match each new alias effect to the live public resolver result for
      that actor path. The removed old action made this match. Distinct mount
      IDs alone do not prove that each alias used its expected mount. Keep
      this check in both Protect and Observe cases on all three platforms.
      Both 99-line tests pass on Host, direct `runc`, and Kubernetes. The
      checks also compare the selected mount, canonical component, and mount
      namespace. The first Kubernetes Protect attempt stopped at a missing
      pinned Python image; the unchanged case passed after the existing
      archive restored that image. Other resolver topology cases remain in
      the old runner.
  - [ ] Replace the exact-secret mount-change checks. Keep the first decision
    after mutation, dirty view, replaced-path denial, and restored decision.
  - [ ] Remove the old exact control open only after these alias and mount
    checks and their Protect-mode counterparts pass as platform tests.
- [ ] `EffectTestRunner::physical_probe` protect scenario: keep every hard
  denial, allow control, loss counter, and evidence assertion.
  - [x] Replace the four consecutive `HF-006`, `HF-008`, `HF-009`, and
    `HF-010` exact-secret opens. They use the same path and operation with no
    state change between them. Extend the existing proc-fd platform test and
    shared Python actor. Require a separate `EACCES` and attributed
    `EXACT_POLICY_DENY` File/OpenRead result for each branch. Keep the same
    exact-object key, composite atom, and task cookie. Keep the test below
    100 lines and add no Platform API or policy fixture.
    - [x] Pass Host and commit it. The 90-line exact case passed in 33.63
      seconds. Both affected Host symlink cases also passed. A broad symlink
      filter selected unconfigured `runc` and Kubernetes cases; those failed
      during setup, not in the Host behavior.
    - [x] Pass direct `runc` and commit it. The four-branch case passed in
      39.82 seconds. Both affected direct-`runc` symlink cases passed in
      40.18 and 40.05 seconds.
    - [x] Pass Kubernetes and commit it. The exact case passed in 74.41
      seconds. The affected Observe and Protect symlink cases passed in
      71.22 and 101.93 seconds in the retained K3s cluster.
    - [x] Remove only the four matching legacy opens after all three pass.
      Keep the separate incident classification table, original exact open,
      detached-mount denial, and descriptor-transfer checks. The replacement
      Host case passed again after deletion in 34.03 seconds. The 93
      non-privileged library tests, formatting, strict crate Clippy, and
      whitespace check passed.
  - [x] Replace the `/proc/self/fd/<fd>` exact-file alias denial. Open and
    hold the secret descriptor before the Protect policy is installed. Reopen
    it through `/proc/self/fd` after activation. Use one small standard test,
    the shared Python actor, and the existing Protect policy; add no policy
    or Platform API.
    Require `EACCES` and attributed `EXACT_POLICY_DENY` File/OpenRead evidence
    with the original exact-object key, composite atom, and task cookie.
    Keep the test below 100 lines.
    - [x] Pass Host and commit it. The 75-line exact case passed in 34.94
      seconds. The two existing Host symlink cases passed together in 47.12
      seconds after the shared actor change.
    - [x] Pass direct `runc` and commit it. The exact case passed in 40.04
      seconds with the production OCI hook. The two existing direct-`runc`
      symlink cases passed together in 60.27 seconds.
    - [x] Pass Kubernetes and commit it. The exact case passed in 73.07
      seconds in retained K3s. The two existing Kubernetes symlink cases
      passed together in 99.20 seconds after the shared actor change.
    - [x] Remove only the matching old action, result field, and prepared
      operation after all three platform cases pass. The detached-mount and
      descriptor-transfer checks remain.
  - [ ] Replace the detached-mount exact-file denial. The shared Python actor
    must clone and hold a mount descriptor before the Protect policy is
    installed. It must use `openat` through that descriptor after activation
    and read one byte if the open succeeds. Require `EACCES` and attributed
    `EXACT_POLICY_DENY` File/OpenRead evidence with the original exact-object
    key, composite atom, and task cookie. Use the existing actor and policy
    inputs. Add no Platform API. Keep the test below 100 lines.
    - [ ] Pass Host and commit it.
    - [ ] Pass direct `runc` and commit it.
    - [ ] Pass Kubernetes and commit it.
    - [ ] Remove only the matching old action, result field, and prepared
      operation after all three platform cases pass. Keep descriptor-transfer
      and mount-change checks.
    - A focused Host attempt on 2026-09-24 held `open_tree` before policy
      activation and used `openat` after activation. Direct opens returned
      `EACCES`, but the detached open returned success. Cloning the secret's
      own non-mountpoint parent gave the same result. The attempted actor and
      test were removed. Keep the legacy assertion. Check exact-object mount
      authority before another replacement attempt; do not accept the read.
- [ ] `EffectTestRunner::physical_probe` mount mutation cases: keep each
  production reconciliation call and mount syscall action visible.
  - [x] Replace the pre-existing bind-alias block with one actor-driven
    platform test. The actor must create the protected and allowed bind mounts
    before Node starts. Require recovered identity, `PATH_TREE_POLICY_DENY`
    with `EACCES`, and `EXACT_POLICY_ALLOW` for the allowed control.
    - [x] Pass Host and commit it. The exact test passed in 28.92 seconds.
    - [x] Pass direct `runc` and commit it. The exact test passed in 35.96
      seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 73.88
      seconds.
    - [x] Remove the matching legacy actions and result fields after all three
      platforms pass. No shell check consumed these fields.
  - [x] Replace the post-activation bind-alias block with one actor-driven
    platform test. Start Control and the actor, then install the policy and
    start Node. After Node recovers the actor, the actor must create the
    protected bind mount. Require `EACCES` and `PATH_TREE_POLICY_DENY` for the
    protected alias. Require the allowed alias read and its
    `EXACT_POLICY_ALLOW` evidence as the control.
    - [x] Pass Host and commit it. The exact test passed in 28.82 seconds.
    - [x] Pass direct `runc` and commit it. The exact test passed in 36.36
      seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 70.37
      seconds.
    - [x] Remove only the matching legacy actions and result fields after all
      three platforms pass. The later recursive-bind and move-mount cases stay.
  - [x] Replace the recursive-bind block with one actor-driven platform test.
    After Node recovers the actor, the actor must create protected and allowed
    recursive bind mounts. Require both mounts to succeed. Require `EACCES` and
    `PATH_TREE_POLICY_DENY` for the protected alias. Require the allowed read
    and its `EXACT_POLICY_ALLOW` evidence as the control. Do not add a Platform
    API.
    - [x] Pass Host and commit it. The exact test passed in 29.30 seconds.
    - [x] Pass direct `runc` and commit it. The exact test passed in 36.10
      seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 74.17
      seconds.
    - [x] Remove only the matching legacy recursive-bind actions and result
      fields after all three platforms pass. The move-mount case stays.
  - [x] Replace the detached-tree attachment block with one actor-driven
    platform test. After Node recovers the actor, the actor must clone the
    protected and allowed trees with `open_tree` and attach them with
    `move_mount`. Use the existing `SysAdmin` policy permission. Require both
    attachments to succeed, the mutation epoch and activity sequence to
    increase, and the global security view to become dirty before production
    rebuilds it. Require `EACCES` and `PATH_TREE_POLICY_DENY` for the protected
    attachment. Require the allowed read and its `EXACT_POLICY_ALLOW` evidence
    as the control. Do not add a Platform API. This specific test can contain
    at most 150 lines. The implementation has 143 lines. The limit preserves
    the two-stage actor protocol, dirty-state proof, Node recovery, bounded
    readiness diagnostics, and explicit effect assertions.
    - [x] Pass Host and commit it. The exact test passed in 50.04 seconds. The
      preexisting-bind, late-bind, and recursive-bind Host regression tests
      passed in 28.41, 28.37, and 28.17 seconds.
    - [x] Pass direct `runc` and commit it. The exact test passed in 63.05
      seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 96.96
      seconds.
    - [x] Remove only the matching legacy move-mount actions, helper, and
      result fields after all three platforms pass. The prepared `MoveMount`
      fail-closed case and detached `open_tree` activity assertion remain.
      All Mithril E2E targets compile. The 92 non-privileged library tests,
      package clippy, formatting, and whitespace checks pass.
  - [x] Replace the pre-policy `mount_global_mutation_epoch` read. The
    production policy owner creates this hash-map row during policy
    installation. The old probe reads it before policy installation. The full
    VM run passed 26 Host tests and the direct-`runc` entry-role probe, then
    stopped at this stale assertion on 2026-09-17. Do not initialize the row
    in a test helper or change BPF behavior.
    - [x] Make the shared actor pause after it clones both trees with
      `open_tree`. Require the activity sequence to increase and the mutation
      epoch to stay unchanged before `move_mount` attaches either tree.
    - [x] Keep the existing attachment, dirty-view, rebuild, protected denial,
      allowed control, and exact evidence assertions in the same platform
      test. The test file has 143 lines, which is below its approved 150-line
      limit.
    - [x] Pass Host and commit it. The exact test passed in 51.74 seconds. The
      preexisting-bind, late-bind, and recursive-bind Host regressions passed
      in 28.66, 27.90, and 28.24 seconds.
    - [x] Pass direct `runc` and commit it. The exact test passed in 52.42
      seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 95.08
      seconds.
    - [x] Remove the stale pre-policy counter read and its legacy result field
      after all three platform cases pass. Keep the prepared `MoveMount`
      fail-closed case. The 92 non-privileged library tests, package clippy,
      formatting, and whitespace checks pass.
  - [x] Replace the initial single-component and recursive wildcard reads with
    one actor-driven platform test. Start Control and the actor before policy
    and Node so production recovery owns the running actor. Use
    `/work/wildcard/home/*/secrets` and `/work/wildcard/srv/**/secrets` in the
    signed policy. Require `EACCES` for both matching reads, an allowed sibling
    read as the control, and task-attributed `PATH_TREE_POLICY_DENY` and
    `EXACT_POLICY_ALLOW` evidence. Do not add a Platform API. Keep the later
    concurrent recursive-read and stale-cache cases separate.
    - [x] Pass Host and commit it. The exact test passed in 34.27 seconds. The
      Rust test has 85 lines.
    - [x] Pass direct `runc` and commit it. The exact test passed in 33.19
      seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 74.20
      seconds.
    - [x] Remove only the matching legacy initial wildcard actions and result
      fields after all three platform cases pass. Keep the concurrent recursive
      read and stable-after-exec checks. The 92 non-privileged library tests,
      package clippy, formatting, shell syntax, and whitespace checks pass.
  - [x] Replace the child-created-after-activation block with one actor-driven
    platform test. Reuse the wildcard actor and signed policy. Create the
    parent tree before policy activation. After Node recovers the actor, make
    the actor create one child under `/work/wildcard/srv/**/secrets`, then open
    that child. Require successful creation, `EACCES`, and task-attributed
    `PATH_TREE_POLICY_DENY` evidence. Require the existing allowed file read
    and its `EXACT_POLICY_ALLOW` evidence as the control. Do not add a Platform
    API.
    - [x] Pass Host and commit it. The exact case passed in 33.29 seconds.
      The unchanged wildcard case passed in 29.17 seconds.
    - [x] Pass direct `runc` and commit it. The exact case passed in 40.02
      seconds. The unchanged wildcard case passed in 30.74 seconds.
    - [x] Pass Kubernetes and commit it. The exact case passed in 80.82
      seconds. The unchanged wildcard case passed in 73.65 seconds.
    - [x] Remove only the matching legacy action and result field after all
      three platform cases pass. Keep the pre-existing, maximum-depth, future
      namespace, denied-create, replacement-child, and allowed-control cases.
      The 92 non-privileged library tests and strict crate Clippy pass.
  - [x] Replace the replacement-child block with one actor-driven platform
    test. Reuse the wildcard actor and signed policy. Create the first child
    before policy activation. After Node recovers the actor, require its first
    open to return `EACCES`, then make it unlink and recreate the same path.
    Require successful unlink and recreation, a second `EACCES`, and two
    task-attributed `PATH_TREE_POLICY_DENY` events. Require the existing
    allowed file read and its `EXACT_POLICY_ALLOW` evidence as the control. Do
    not add a Platform API.
    - [x] Pass Host and commit it. The exact case passed in 35.67 seconds.
      The unchanged later-child and wildcard cases passed in 30.44 and 30.55
      seconds.
    - [x] Pass direct `runc` and commit it. The exact case passed in 46.79
      seconds. The unchanged later-child and wildcard cases passed in 30.36
      and 31.92 seconds.
    - [x] Pass Kubernetes and commit it. The exact case passed in 79.10
      seconds. The unchanged later-child and wildcard cases passed in 75.69
      and 133.37 seconds.
    - [x] Remove only the matching legacy initial-child and replacement-child
      actions and result field after all three platform cases pass. Keep the
      pre-existing, maximum-depth, future-namespace, denied-create, and
      allowed-control cases. The 92 non-privileged library tests and strict
      crate Clippy pass.
  - [x] Replace the denied-create block with one actor-driven platform test.
    Reuse the wildcard actor and signed policy. Create the protected parent
    before policy activation. After Node recovers the actor, make it create
    one child in that protected tree. Require `EACCES`, require that the child
    does not exist, and require task-attributed `PATH_TREE_POLICY_DENY`
    evidence for `Create`. Require the existing allowed file read and its
    `EXACT_POLICY_ALLOW` evidence as the control. Do not add a Platform API.
    - [x] Pass Host and commit it. The exact case passed in 34.05 seconds.
      The unchanged later-child, replacement-child, and wildcard cases passed
      in 29.38, 33.65, and 28.56 seconds.
    - [x] Pass direct `runc` and commit it. The exact case passed in 34.63
      seconds. The unchanged later-child, replacement-child, and wildcard
      cases passed in 29.29, 34.95, and 29.19 seconds.
    - [x] Pass Kubernetes and commit it. The exact case passed in 77.61
      seconds.
    - [x] Remove only the matching legacy denied-create action after all
      three platform cases pass. Keep the pre-existing, maximum-depth,
      future-namespace, and allowed-control cases. The 92 non-privileged
      library tests and strict crate Clippy pass.
  - [x] Replace the maximum-depth pre-existing child block with one
    actor-driven platform test. Reuse the wildcard actor and signed policy.
    Make the signed path-tree floor contain 254 normal components. Create its
    child before policy activation and require the actor path to contain the
    ABI maximum of 255 normal components. After Node recovers the actor,
    require `EACCES` and task-attributed `PATH_TREE_POLICY_DENY` evidence for
    `OpenRead`. Require the existing allowed file read and its
    `EXACT_POLICY_ALLOW` evidence as the control. Do not add a Platform API.
    - [x] Pass Host and commit it. The exact case passed in 33.57 seconds.
      The complete eight-case `mount_late_host` lifecycle passed in 99.91
      seconds.
    - [x] Pass direct `runc` and commit it. The exact case passed in 37.59
      seconds. The complete eight-case `mount_late_runc` lifecycle passed in
      105.69 seconds.
    - [x] Pass Kubernetes and commit it. The exact case passed in 83.44
      seconds. The complete eight-case `mount_late_kubernetes` lifecycle
      passed in 248.38 seconds.
    - [x] Remove only the matching legacy open and the pre-existing and
      maximum-depth result fields after all three platform cases pass. Keep
      the deep fixture because the future-mount-namespace, external-alias,
      and mount-race cases still use it. The 92 non-privileged library tests
      and strict crate Clippy pass.
  - [x] Replace the future-mount-namespace block with one actor-driven
    platform test. Reuse the mount-alias actor and signed policy. Start Control
    and the actor before the policy so the real Kubernetes policy has a target.
    Install the policy, start Node, and recover the actor. The protected actor
    must then create a mount namespace. Require its first private-propagation
    mutation to fail closed because the namespace was absent at activation.
    Require its namespace inode to differ from the test process namespace.
    Require `EACCES` and task-attributed `PATH_TREE_POLICY_DENY` evidence.
    Require the allowed read and its `EXACT_POLICY_ALLOW` evidence as the
    control. Do not add a Platform API.
    - [x] Pass Host and commit it. The corrected recovery-order case passed in
      31.03 seconds. The unchanged pre-existing bind case passed in 28.81
      seconds.
    - [x] Pass direct `runc` and commit it. The corrected recovery-order case
      passed in 35.82 seconds. The unchanged pre-existing bind case passed in
      30.41 seconds.
    - [x] Pass Kubernetes and commit it. The exact case passed in 87.71
      seconds. The unchanged pre-existing bind case passed in 77.40 seconds.
    - [x] Remove only the matching legacy future fixture, action, and result
      field after all three platform cases pass. Keep the shared deep path,
      external-alias, and mount-race setup. The 92 non-privileged library tests
      and strict crate Clippy pass.
  - [x] Replace the protected mount-race block with one actor-driven platform
    test. Reuse the mount-alias actor. Before readiness, make it start eight
    workers that wait at one barrier. Start Control and the actor before policy
    and Node, then recover the workers through production startup. Release all
    workers to bind mount the allowed source over the protected target. Require
    zero successful mounts, eight `EACCES` or `EPERM` results, zero other
    errors, and `UNSUPPORTED_OBJECT` mount evidence. After the race, require an
    exact protected-file denial and an exact allowed-file control from the main
    actor. Do not add a Platform API. Keep the test below 100 lines.
    - [x] Pass Host and commit it. The exact case passed in 28.40 seconds. It
      passed again in its final lifecycle in 28.71 seconds.
    - [x] Pass direct `runc` and commit it. The exact case passed in 34.95
      seconds. It passed again in its final lifecycle in 35.40 seconds with the
      production OCI hook.
    - [x] Pass Kubernetes and commit it. The exact case passed in 72.13 seconds.
      Mount race has its own lifecycle because its actor must start before Node
      installs the retained OCI hook. A reused installed hook correctly denies
      a new Pod while Node is stopped. The two compatible `mount_alias`
      Kubernetes cases passed together in 92.53 seconds. Failed and successful
      lifecycle teardown both removed the runtime integration. Kubernetes keeps
      its exec stream while Node is active and uses direct actor input only
      before Node installs the hook. The 23-test `identity_kubernetes`
      lifecycle passed in 581.31 seconds, and mount race passed again in 73.22
      seconds.
    - [x] Remove only the matching legacy mount-race setup, action, result
      field, mailbox requests, and worker owner after all three platform cases
      pass. This removed 205 lines. The 92 non-privileged library tests and
      strict crate Clippy pass.
    - [x] Run the complete Host, direct-`runc`, and Kubernetes matrix because
      this is the third completed migration since the last full matrix. On
      2026-09-19, Host passed 47 tests in nine lifecycle processes, direct
      `runc` passed 38 tests in eight processes, and Kubernetes passed 38 tests
      in eight processes. Cleanup left no Mithril runtime files, namespaces,
      or BPF pin roots.
  - [x] Replace the bounded and expired exception block with small standard
    platform tests. Use one shared Python actor and scenario policy. Do not add
    a Platform API or change Interceptor behavior.
    - [x] Release eight actor threads to open the protected write target at the
      same time. Require exactly two allowed opens, six `EACCES` results, and
      no other result.
    - [x] Attribute every result to its worker task and the exact protected
      object. Require exactly two `EXACT_POLICY_ALLOW` observations and six
      `EXCEPTION_UNAVAILABLE` observations.
    - [x] Require two consumed uses, the `Exhausted` runtime state, and only
      consumed receipt ordinals `[1, 2]`.
    - [x] Restart Node through the existing Platform lifecycle. Require the
      exhausted state to remain unchanged and require another write to fail
      with `EXCEPTION_UNAVAILABLE`.
    - [x] Require the separate one-use expired exception to start `Active`
      with zero uses, deny its write, and enter `Expired` with zero uses.
    - [x] Keep each test below 100 lines. Split independent behavior into
      separate tests instead of hiding scenario assertions in a helper.
    - [x] Pass Host and commit it. The three focused tests passed together in
      79.88 seconds. Public file rules used one nonzero signed path atom and no
      exact-object key. The test matched all eight worker cookies to that atom.
    - [x] Pass direct `runc` and commit it. The three focused tests passed
      together in 112.97 seconds with the production OCI hook.
    - [x] Reproduce the Kubernetes startup-termination condition in
      lightweight qualification before the Node fix. The real Node reached
      the pinned identity map and received `SIGTERM` while the CRI version
      request was held. Before the fix, it exited with signal 15. After the
      fix, it exited successfully, retained complete identity pins, and a
      second real Node recovered those pins and reached admission readiness.
      The focused test passed in 37.52 seconds. No readiness limit changed.
    - [x] Diagnose the Kubernetes cleanup failure. The former Control path
      created a signed revoke after the exact workload and its base-policy
      owner were gone. The revoke could not run and kept teardown pending.
      This is not the accepted exception lifecycle.
    - [x] Record the accepted lifecycle. Keep `maximumUses` unchanged. Expose
      no external revoke operation. Keep the existing private signed
      restrictive transition as a Control-to-Node cleanup detail. Keep
      consumed and expired states terminal. Keep counters and receipts as
      non-authorizing records.
    - [x] Apply an active exception's existing private cleanup before Node
      retires its active base-policy owner. Do not create a second cleanup
      path. Do not send a later cleanup for an already consumed or expired
      exception. Commit `5544c9c4` defers base-owner retirement until the
      existing cleanup becomes terminal. The focused Node test and all 33
      Control policy reconciliation tests passed.
    - [x] Verify that private cleanup preserves the use count and deadline.
      Then verify that normal container cleanup removes the exact binding and
      permits base-policy retirement. The existing exact-target regression
      kept the use bound, deadline, target, and predecessor. Host, direct-runc,
      and Kubernetes lifecycle teardown then completed.
    - [x] Pass Kubernetes and commit it. All three Kubernetes exception tests
      passed together in 185.27 seconds. Commit `7e99420c` adds Kubernetes to
      the same Rust scenarios.
    - [x] Reproduce the later cleanup race without Kubernetes. The exception
      is terminal, Control has acknowledged that result, and Node retires the
      base-policy owner before an already-created private cleanup arrives.
      Before the correction, the owner returned new kernel work. The focused
      test failed at that assertion.
    - [x] Complete a private cleanup without kernel work when its predecessor
      is already terminal. Preserve the consumed-use count and acknowledge the
      restrictive result. Keep activation without a policy owner invalid. The
      focused regression, 16 related Node tests, six related Control tests,
      formatting, and targeted strict Clippy pass.
    - [x] Reproduce the remaining physical ordering without Kubernetes. The
      private cleanup can arrive while its exact base policy is retiring or
      after Node has removed that policy owner. A restrictive transition in
      either state needs no separate kernel work. Activation without a policy
      owner remains invalid. The focused checks, all 244 Node library tests,
      and targeted strict Clippy pass.
    - [x] Refresh a retained K3s image cache when its supplied archive changes.
      The former helper skipped the archive when all image names existed. A
      K3s restart then restored an old Node tag. The helper now compares the
      supplied and retained archives before it skips import.
    - [x] Rebuild the Node image and rerun the three-case Kubernetes exception
      lifecycle. The live Pod used manifest `767ce3a2`, the replacement Node
      had zero restarts, and all three tests passed in 170.00 seconds. Final
      teardown removed the namespace and runtime sockets. The process exited
      with status 0 without recreating the VM or K3s cluster.
    - [x] Remove only the matching legacy actions, result fields, mailbox
      operations, worker owner, and embedded policy rules after all three
      platform cases pass. The actor-only write-race test was also removed.
      The final source passes the exact replacement test on Host in 28.74
      seconds, direct `runc` in 31.38 seconds, and Kubernetes in 69.55 seconds.
      The exact committed legacy probe fails at the same unrelated pre-policy
      baseline as the edited source, so this deletion did not cause that
      failure. The failure reports all 6,000 opens as `EACCES` after the old
      probe moves an unlabeled actor into an active binding.
  - [x] Replace the pre-activation descriptor read and mapping block with one
    small standard platform test. Use one shared Python actor and scenario
    policy. Do not add a Platform API.
    - [x] Resolve the public-policy selector gap before implementation.
      `WorkloadProtectionPolicy` currently lowers every file rule to a live
      `PATH` selector. The baseline case uses an `EXACT` selector and requires
      a nonzero exact-object key. Do not replace that assertion with a path
      rule's composite atom. An explicit `exact: true` file rule now lowers to
      the existing production `EXACT` selector. It cannot be recursive. The
      false default is omitted from canonical serialization. The focused
      public API test, all 201 Mithril Control tests, the generated Helm CRD,
      and strict Clippy pass on 2026-09-22.
    - [x] Start the actor under the initial policy. Make it retain protected
      and allowed file descriptors before policy replacement. Keep Node live
      so the replacement migrates the same admitted actor, as in the baseline
      policy-lifecycle block.
    - [x] Require `EACCES` for `Read` and `MmapRead` through the retained
      protected descriptor. Require both operations to succeed through the
      retained allowed descriptor.
    - [x] Attribute all four decisions to the admitted actor task and their
      exact protected or allowed object. Keep setup, action, assertions, and
      teardown in a test of fewer than 100 lines.
    - [x] Pass Host and commit it. The 83-line test passed in 34.54 seconds on
      2026-09-22. It found that the known-mount path did not snapshot the
      canonical mount-cache generation before exact-object enforcement. The
      approved correction records and verifies that generation. The unchanged
      Host mount-alias, late-mount, path, and mount-race lifecycles then passed
      all 11 tests.
    - [x] Pass direct `runc` and commit it. The unchanged scenario passed
      through stock `runc` and the production OCI hook in 38.26 seconds on
      2026-09-22.
    - [x] Pass Kubernetes and commit it. The unchanged scenario passed against
      the retained real K3s cluster in 68.95 seconds on 2026-09-22. The first
      physical run found a stale live CRD that did not contain the committed
      `exact` field, so Kubernetes pruned it. Refreshing that CRD from the
      checked-in Helm manifest preserved the exact selectors.
    - [x] Remove only the matching legacy prepared-descriptor setup and
      assertions after all three platforms pass. Keep the independent-process
      mapping cases. Keep the shared prepare, read, and mmap mailbox operations
      because the network scenario still uses them. The 29 non-privileged
      effect regressions pass after the deletion.
  - [x] Replace the independent-root shared mapping block. Reuse the retained
    descriptor actor and its exact-file policy. Keep a live primary actor and
    start one declared additional actor as a separate process root. Require
    shared writable mapping denial, benign mapping success, exact File effect
    evidence, and distinct task, lineage, and process identities. Keep the
    standard test below 100 lines. Do not add a Platform API.
    - [x] Host passed in 35.29 seconds. The 93-line test kept the independent
      process identity, exact shared mapping denial, and benign control. The
      existing descriptor Host case passed in 34.54 seconds with the shared
      actor and policy change. Commit the Host leaf separately.
    - [x] Direct `runc` passed in 35.86 seconds with the same actor, policy,
      and assertions. The existing descriptor case passed in 35.49 seconds
      with the shared policy change.
    - [x] Kubernetes passed in 72.59 seconds in retained K3s with the same
      actor, policy, and assertions. The existing descriptor case passed in
      76.45 seconds with the shared policy change.
    - [x] Remove the matching legacy independent-mapping actions, result
      fields, and private forked target after all three platform cases pass.
      The retained main-root mapping and benign-read assertions stay in the
      old probe. The new Host case passed again after deletion. The crate's
      91 non-privileged tests, formatting, and strict Clippy passed.
  - [x] Remove the remaining main-root benign `MmapRead` control and result.
    The shared retained-descriptor test already requires an admitted actor,
    an exact signed allow rule, a successful benign mapping, and attributed
    `EXACT_POLICY_ALLOW` File/MmapRead evidence on Host, direct `runc`, and
    Kubernetes. Keep the shared prepared-file mmap helper because the network
    probe still uses it. The exact shared Host case passed again in 35.53
    seconds after deletion. The 91 non-privileged tests, formatting, and
    strict Clippy passed.
  - [ ] Replace the SCM_RIGHTS file-acquisition pair with one small standard
    platform test. Reuse a shared Python actor and public signed policy. Open
    both files before protection. Transfer each descriptor from a peer in a
    separate protected cgroup and binding, then receive after activation.
    Require payload receipt, no installed secret descriptor, one installed
    and readable benign descriptor, exact File/OpenRead denial and allow
    evidence, unchanged descriptor state after the denied transfer, and
    cleanup. Keep the test below 100 lines and do not add a Platform API.
    The old probe places its Unix-stream sender in a separate peer binding.
    A fork of the main actor or `add_actor` inside its container does not
    preserve that condition. Keep the legacy transfer assertions until the
    common physical setup can create that peer on all three platforms.
    - [ ] Pass Host and commit it.
    - [ ] Pass direct `runc` and commit it.
    - [ ] Pass Kubernetes and commit it.
    - [ ] Remove only the matching legacy transfer actions and private child
      machinery after all three platforms pass. Keep unrelated Unix-stream
      and exact-file checks.
  - [ ] Replace the SysV shared-memory permission check with one small
    standard platform test. The shared Python actor must create and attach a
    private segment outside the protected cgroup. It must mark the segment
    for deletion before readiness, then move into the active binding and call
    `shmctl(IPC_STAT)`. Require `EACCES`, the restricted external role, attributed
    `UNSUPPORTED_OBJECT` IPC/Access evidence, and no exact policy object.
    Reuse the signed Python policies and existing Platform operations. Keep
    the Rust test below 100 lines and add no Platform API.
    - [ ] Pass Protect on Host and commit it.
    - [ ] Pass Protect on direct `runc` and commit it.
    - [ ] Pass Protect on Kubernetes and commit it.
    - [ ] Preserve the same legacy check under Observe mode on all three
      platforms before deleting the old action, result, and prepared segment.
    - Host draft failed: after placement in the active cgroup,
      `shmctl(IPC_STAT)` returned success. The only IPC effect was
      `RUNTIME_ENTRY_INFRASTRUCTURE`; there was no `UNSUPPORTED_OBJECT` denial.
      The recovery setup assigned `fail_closed_unknown`, not the required
      restricted role. Keep the legacy check until a physical setup preserves
      both the role and denial. Do not change BPF for this test.
    - The old probe prepares the segment before cgroup placement. It then
      stops and starts `KernelHostOwner`, republishes the binding, installs the
      policy, and activates security state before `IPC_STAT`. It does not
      assert an actor role. Do not treat the late-placement draft as an exact
      reproduction of that sequence.
  - [x] Replace anonymous executable-memory denials and their non-executable
    controls with one small standard platform test. Use one shared Python
    actor as a recovered external process and the public signed Python policy.
    Make real `mmap`, `mprotect`, and `pkey_mprotect` calls. Check the exact
    attributed production effects. Require
    `EACCES` for executable mappings and protections, success for read-only
    controls, and no policy object for unsupported anonymous execution.
    Keep the test below 100 lines. Do not add a Platform API.
    An admitted PID 1 returned success for executable `mprotect` on Host.
    That result follows the production application default and does not match
    the old late-moved actor. Keep the recovered external-root condition.
    - [x] Host passed in 28.90 seconds. The shared actor returned two
      executable-protection denials, one executable-mmap denial, and two
      successful read-only controls. The production effect records matched.
    - [x] Direct `runc` passed in 29.34 seconds with the same actor,
      test body, policy, and effect assertions.
    - [x] Kubernetes passed in 70.40 seconds with the same actor,
      test body, policy, and effect assertions.
    - [x] Preserve the old pre-protection mapping condition. The actor now
      allocates its first writable anonymous map before it reports ready.
      Host passed again in 28.56 seconds, direct `runc` in 29.52 seconds,
      and Kubernetes in 77.02 seconds.
    - [x] Preserve the old Observe-mode case before deletion. The legacy
      probe runs these five actions for both values of `protect`. The shared
      test now uses only the Protect-mode Python policy. Require the same
      anonymous-memory denials and read-only controls under Observe mode on
      Host, direct `runc`, and Kubernetes. Keep the legacy block until then.
      Use one Observe-mode CRD with only the required application and
      restricted external roles. Reuse `executable_memory.py`, the existing
      `Platform` operations, and the exact effect assertions. Do not add a
      Platform method or copy unused Protect-policy roles and rules.
      - [x] Host passed in 28.25 seconds with real Observe-mode Control,
        Node, and BPF. Its first run reached active policy delivery but timed
        out because the fixture expected Protect-mode prevention claims.
        `node_ready` now requires the claim value that matches the installed
        policy mode. The unchanged Protect case passed in 28.85 seconds.
      - [x] Direct `runc` passed in 29.91 seconds with the same actor,
        Observe policy, and effects. The unchanged Protect case passed in
        28.90 seconds.
      - [x] Kubernetes passed in 69.54 seconds with the same actor, Observe
        policy, and effects. The unchanged Protect case passed in 73.94
        seconds in the retained K3s cluster.
    - [x] Remove only the matching legacy actions, fields, and prepared
      resources after all three platforms pass. The current binary passed
      Protect and Observe on Host (28.40 and 28.98 seconds), direct `runc`
      (28.82 and 29.96 seconds), and Kubernetes (70.34 and 71.87 seconds).
      Keep the independent no-policy anonymous-mapping control test. Compile
      its two syscall helpers only for tests. The unprivileged suite passed
      with 91 tests; strict Clippy and formatting passed.
  - [x] Replace the protected `PTRACE_ATTACH` block with one small standard
    platform test. Use one shared Python actor and scenario policy. Do not add
    a Platform API.
    - [x] Start the protected actor, then make it fork one live target after
      activation. Resolve the target through `ProcessFixture::wait_child` and
      require a separate inherited task identity.
    - [x] Attempt request 16 (`PTRACE_ATTACH`) from the actor. Require `EACCES`
      and `EXACT_POLICY_DENY` for kernel access mode 18
      (`PTRACE_MODE_ATTACH_REALCREDS`).
    - [x] Attribute the decision to the exact controller and target task
      cookies, profile generations, roles, and distinct process-state IDs.
      Keep the test below 100 lines.
    - [x] Pass Host and commit it.
    - [x] Pass direct `runc` and commit it.
    - [x] Pass Kubernetes and commit it.
    - [x] Preserve the unmatched `PTRACE_ATTACH` case in a second small
      platform test. Use the same Python actor and a policy with no matching
      process-control rule. Require `EACCES`, `UNSUPPORTED_OBJECT`, operation
      argument 18, and the exact controller and target task identities.
    - [x] Pass the unmatched case on Host and commit it.
    - [x] Pass the unmatched case on direct `runc` and commit it.
    - [x] Pass the unmatched case on Kubernetes and commit it. The corrected
      shared fixture passed Host in 30.44 seconds, direct `runc` in 30.01
      seconds, and Kubernetes in 71.73 seconds on 2026-09-19.
    - [x] Remove only the matching legacy ptrace action, result field, and
      fixture operation after all three platforms pass. Keep both signal
      cases and the shared process target until their replacements pass.
  - [x] Replace the process-signal block with three small standard platform
    tests. Reuse the process-control actor and its one live child. Do not add
    a Platform API.
    - [x] With the protected policy, send signal zero. Require success and
      `EXACT_POLICY_ALLOW` evidence for the exact controller and target tasks.
    - [x] With the protected policy, send `SIGCONT`. Require `EACCES` and
      `EXACT_POLICY_DENY` evidence for the exact controller and target tasks.
    - [x] With no matching process-control rule, send signal zero. Require
      `EACCES` and `UNSUPPORTED_OBJECT` evidence for the exact controller and
      target tasks.
    - [x] Keep each test below 100 lines. Keep actor result checks and security
      assertions in each test.
    - [x] Pass the signal-zero allow case on Host and commit it. The exact case
      passed in 28.59 seconds. Both renamed Host ptrace cases passed together
      in 49.29 seconds.
    - [x] Pass the signal-zero allow case on direct `runc` and commit it. The
      exact case passed in 28.65 seconds. Both renamed direct-`runc` ptrace
      cases passed together in 50.59 seconds.
    - [x] Pass the signal-zero allow case on Kubernetes and commit it. The
      exact case passed in 69.69 seconds.
    - [x] Keep each pristine-start BPF, managed-proc, namespace, and unmatched
      ptrace case in its own lifecycle. Their former shared lifecycle passed
      its first Kubernetes case, then the retained gate correctly rejected
      the next three new Pods while Node was down. The separated cases passed
      on Host in 28.30, 28.20, 28.45, and 28.64 seconds; on direct `runc` in
      34.25, 35.42, 34.53, and 35.50 seconds; and on Kubernetes in 74.62,
      71.97, 69.29, and 70.31 seconds. Scenario bodies and security assertions
      did not change.
    - [x] Keep protected ptrace and signal-zero recovery in separate
      `ptrace_recovery` and `signal_recovery` lifecycles. A combined Kubernetes
      identity run passed 23 tests but correctly rejected both new actor Pods
      after a prior Node activation. The direct-`runc` retained-gate probe
      reproduced the condition and required `DENY_NODE_UNAVAILABLE` while the
      denied process remained absent. Protected ptrace passed Host, direct
      `runc`, and Kubernetes in 28.07, 29.18, and 67.52 seconds. Signal zero
      passed the same platforms in 28.12, 28.37, and 68.33 seconds on
      2026-09-19.
    - [x] Pass the `SIGCONT` denial case on Host and commit it. The feature
      prevents unauthorized control of another governed process. `SIGCONT` is
      a safe example for the running fixture target; it is not a separate
      product feature.
      The first Host run on 2026-09-19 returned success instead of `EACCES`.
      Its signal event used `RUNTIME_ENTRY_INFRASTRUCTURE` with argument 18
      and no controller identity. `runtime_entry_may_control_initial_target`
      matched the actor child because the child inherits the admitted entry
      identity. The runtime exemption ran before the signed process-control
      rule lookup. Keep the failing scenario unchanged until the production
      exemption is limited to the exact entry-root process.
      The unchanged recovered-container entry probe passed before the fix. It
      observed the required runtime bootstrap against the recovered initial
      task, preserved runtime-internal execution, denied the declared probe,
      denied unmatched execution, and removed all owned resources. Rerun this
      probe after the correction to prove that the valid runtime exemption is
      unchanged.
      The production predicate now also requires the target process state to
      equal its entry-root process state. The corrected Host case passed in
      28.76 seconds on 2026-09-20. The unchanged recovered-container entry
      probe then passed with both recovered task classes, the runtime bootstrap
      marker, runtime-internal rule-zero execution, both policy denials, and
      all cleanup fields.
    - [x] Pass the `SIGCONT` denial case on direct `runc` and commit it. The
      unchanged scenario passed in 36.26 seconds on 2026-09-20.
    - [x] Pass the `SIGCONT` denial case on Kubernetes and commit it. The
      unchanged security checks passed, but the first run exposed a fixture
      error: `kubectl attach` returned zero instead of the actor Pod's exit
      code. `ProcessFixture` now uses the existing Pod exit probe when the
      attach transport closes. The exact case passed in 75.36 seconds on
      2026-09-20.
    - [x] Pass the unmatched signal-zero case on Host and commit it. The first
      setup used an admitted application entry, whose missing process-control
      row correctly used application default allow. The final 96-line test
      preserves the original external-root condition: Node recovers the
      runtime-added actor with entry rule zero before it attempts signal zero.
      The exact case passed in 30.04 seconds on 2026-09-20.
    - [x] Pass the unmatched signal-zero case on direct `runc` and commit it.
      The unchanged case passed in 38.65 seconds on 2026-09-20.
    - [x] Pass the unmatched signal-zero case on Kubernetes and commit it. The
      unchanged case passed in 75.29 seconds on 2026-09-20.
    - [x] Remove only the matching legacy signal actions, result fields, and
      fixture operations after all three tests pass on all three platforms.
      Remove the shared process target only when no legacy operation uses it.
      The cleanup removed 242 lines, including the unused combined target
      request, process target owner, and its actor-only unit test. It kept the
      independent Unix-stream target. The 13 focused child-fixture tests, the
      complete non-privileged library suite, formatting, and strict crate
      Clippy pass.
    - [x] Run the complete platform matrix after the three signal behaviors.
      Each of the 52 current Host cases passed across 13 lifecycle processes.
      One Node start timed out after the physical lifecycle. Cleanup was
      complete, and the unchanged two-test lifecycle passed on its immediate
      focused rerun. All 43 direct-`runc` cases and all 43 Kubernetes cases
      passed across 12 lifecycle processes without a rerun. Cleanup left no
      Mithril process, namespace, BPF root, cgroup, or owner lease on
      2026-09-20.
- [ ] `EffectTestRunner::physical_probe` process, descriptor, network, and
  `io_uring` cases: retain exact task and object attribution assertions.
  - [x] Replace the exact Unix-stream allow relationship. Reuse the approved
    socket-pass actor and signed worker-to-worker policy. Require a completed
    descriptor transfer and payload, distinct admitted worker tasks, and
    attributed `EXACT_POLICY_ALLOW` IPC/Access evidence for Connect, Send,
    and Receive. Extend the existing approved socket-pass test and keep it
    below 100 lines. Add no actor, policy, Platform API, or production
    operation.
    - [x] Pass Host and commit it. The extended 98-line test passed in 27.37
      seconds. It retained the role, descriptor, and payload assertions and
      observed exactly the three allowed IPC operation classes. Formatting,
      strict crate Clippy, and whitespace checks passed.
    - [x] Pass direct `runc` and commit it. The unchanged test passed in
      33.64 seconds with stock `runc` and the production OCI hook.
    - [x] Pass Kubernetes and commit it. The unchanged test passed in
      65.53 seconds in the retained real K3s cluster.
    - [x] Remove only the matching legacy relationship assertions after all
      three pass. Keep its roundtrip setup while inherited, stale, and
      unmatched Unix-stream checks depend on the same endpoint. The shared
      Host case passed again after deletion in 27.52 seconds. The 93
      non-privileged library tests, formatting, and strict crate Clippy pass.
  - [x] Replace the stale Unix-stream peer denial. Reuse `socket_pass.py` and
    the signed worker-to-worker policy. Keep one connected stream open after
    its admitted receiver exits. Require the received control payload, an
    `EACCES` send, and attributed `CORRUPT_IDENTITY_OR_GENERATION` IPC/Access
    evidence. Keep the same test below 100 lines on Host, direct `runc`, and
    Kubernetes. Remove only the matching old action after all three pass.
    The shared Host case passed in 27.58 seconds, direct `runc` passed in
    33.92 seconds, and Kubernetes passed in 66.09 seconds. The matching old
    runner action, result field, and now-unused helper are removed. The Host
    case passed again after deletion in 28.03 seconds. The 91 nonprivileged
    library tests, formatting, and strict crate Clippy pass.
  - [x] Replace the inherited Unix-stream send denial. Reuse the admitted
    parent/receiver policy and shared actor. Fork after the parent receives an
    allowed payload. Hold the child until its exact task is observed, then
    require `EACCES` and attributed `CORRUPT_IDENTITY_OR_GENERATION` IPC/Access
    Send evidence. Pass the same Rust test below 100 lines on Host, direct
    `runc`, and Kubernetes before removing the matching old action.
    The 84-line Host case passed in 28.17 seconds. Direct `runc` passed in
    33.83 seconds with the production OCI hook. Kubernetes passed in 64.78
    seconds in retained K3s. The matching old action, result field, and
    now-unused fork-write wrapper are removed. The Host case passed again
    after deletion in 28.13 seconds. The 91 nonprivileged library tests,
    formatting, and strict crate Clippy pass.
  - [x] Replace the unmatched Unix-stream peer denial. After the allowed
    descriptor transfers finish, start a new peer and require `EACCES` plus
    attributed `EXACT_POLICY_DENY` IPC/Access evidence. Keep the old action
    until the same platform test passes on Host, direct `runc`, and Kubernetes.
    The legacy fixture now closes its completed stream before peer restart.
    Its focused restart test and the 91 nonprivileged library tests pass.
    - [x] Pass Host and commit it. The 98-line standard test uses one shared
      Python actor and one signed policy. It completes an approved descriptor
      transfer, starts a second peer with a different role on the same Unix
      endpoint, and requires `EACCES` with attributed `EXACT_POLICY_DENY`
      IPC/Access Connect evidence. The exact Host case passed in 29.48
      seconds. The approved, stale, and inherited Host socket cases also pass
      with the shared actor change.
    - [x] Pass direct `runc` and commit it. The same 92-line test passed with
      the production OCI hook. The short-lived approved peer exited before
      the runner could sample its process name, so the test now checks the
      completed payload, peer exit, role, and production IPC Allow evidence.
      The revised Host case passed again in 27.77 seconds.
    - [x] Pass Kubernetes and commit it. The exact shared Rust test passed in
      65.42 seconds in the retained K3s cluster. Its test namespace was
      removed; the K3s cluster remains ready for the next case.
    - [x] Remove only the matching legacy restart action and result field.
      Keep the descriptor-transfer actions until their separate platform
      tests pass. The obsolete restart method and saved socket address are
      gone. The focused fixture test now checks stream closure after transfer.
      The revised physical Host case passed in 28.11 seconds. The 91
      nonprivileged library tests, formatting, and strict crate Clippy pass.
  - [x] Replace the unmatched file-create block with one small standard
    platform test. Use one shared Python actor and the existing Python policy.
    Start the actor before Node to preserve the original recovered-root
    condition.
    Require actor `EACCES`, target absence, `UNRESOLVED_OBJECT`, File/Create,
    the exact actor task, and no exact or composite policy object.
    - [x] Pass Host and commit it. The corrected test requires the runtime-added
      actor to have `restored_or_unknown_root` and entry rule zero. It passed
      with chmod in the shared Host lifecycle in 52.95 seconds on 2026-09-22.
    - [x] Pass direct `runc` and commit it. The corrected external actor passed
      through the production OCI hook in 37.98 seconds on 2026-09-22.
    - [x] Pass Kubernetes and commit it. The corrected external actor passed
      against the retained real K3s cluster in 92.11 seconds on 2026-09-22.
    - [x] Remove only the matching legacy action and result field after all
      three platforms pass. The cleanup removed the old request, child match
      arm, target, assertion block, and result field. It kept every other file
      mutation case. The 12 focused child-fixture tests and strict crate
      Clippy pass.
  - [x] Replace the remaining unmatched file mutations with separate small
    standard platform tests. Use one shared Python actor and the existing
    Python policy. Start each actor before Node to preserve the recovered-root
    condition. Require the exact actor task, `UNRESOLVED_OBJECT`, the original
    file operation, `EACCES`, and zero exact and composite policy object IDs.
    - [x] Add one bounded `ProcessFixture` task-name wait and one `EffectCheck`
      evidence cursor. The actor waits for release with `poll(2)` and does not
      make a second governed file read after its action.
    - [x] Keep actor-before-Node recovery behaviors in separate lifecycles. A
      paired Kubernetes run passed chmod, then the retained OCI gate correctly
      denied the second new Pod while Node was unavailable. Do not weaken the
      recovery order to share Node state.
    - [x] Replace chmod. Require File/Setattr and mode `0600` after denial.
      - [x] Pass Host and commit it. An admitted PID1 correctly allowed chmod,
        so that setup was rejected. The 58-line external-actor test passed in
        30.96 seconds and passed with create in 52.95 seconds on 2026-09-22.
      - [x] Pass direct `runc` and commit it. Chmod and corrected create passed
        together through the production OCI hook in 72.69 seconds on
        2026-09-22.
      - [x] Pass Kubernetes and commit it. The isolated recovery scenario
        passed against the retained real K3s cluster in 78.32 seconds on
        2026-09-22.
      - [x] Remove only the legacy setattr request, dispatch arm, assertion,
        target, and result field after all three platforms pass. The focused
        child-fixture tests and strict crate Clippy pass on 2026-09-22.
    - [x] Replace truncate. Require File/Setattr and unchanged file length.
      - [x] Pass Host and commit it. The 58-line test retained a writable file
        descriptor before Node recovery. Its `ftruncate` denial passed in
        28.68 seconds on 2026-09-22.
      - [x] Pass direct `runc` and commit it. The same retained-descriptor test
        passed through stock `runc` and the production OCI hook in 34.86
        seconds on 2026-09-22.
      - [x] Pass Kubernetes and commit it. The same retained-descriptor test
        passed against the retained real K3s cluster in 70.53 seconds on
        2026-09-22.
      - [x] Remove only the legacy truncate request, dispatch arm, assertion,
        retained descriptor, target, and result field after all platforms
        pass. The 12 focused child-fixture tests and strict crate Clippy pass
        on 2026-09-22.
    - [x] Complete exact mount-policy installation in the same real recovery
      operation. A recovering binding is not an exact-object target until BPF
      commits it as active recovered. The Node now installs its exact rows
      after that commit. A quiet CRI event stream still does no work. The
      unchanged eight-test mount-late lifecycle passed on Host in 97.44
      seconds, direct `runc` in 154.01 seconds, and Kubernetes in 258.75
      seconds on 2026-09-22.
    - [x] Retire an inactive policy generation after its last task exits. A
      policy activation records pending retirement. The existing policy
      control tick retries lifecycle cleanup only while retirement is pending.
      A quiet Node does not scan CRI inventory or BPF maps. The unchanged
      terminal-evidence test passed on Host in 43.53 seconds, direct `runc` in
      48.71 seconds, and Kubernetes in 96.15 seconds on 2026-09-22.
    - [x] Run the complete Host, direct-`runc`, and Kubernetes matrices after
      the create, chmod, and truncate migrations and the recovery corrections.
      - [x] The complete Host matrix passed all 22 lifecycle groups.
      - [x] The complete direct-`runc` matrix passed all 21 lifecycle groups.
        The local build artifacts disappeared during its first identity run.
        After the existing hook and test binary were rebuilt, the complete
        25-case identity lifecycle passed in 551.56 seconds. All later groups
        passed without another artifact loss.
      - [x] The complete Kubernetes matrix passed all 22 lifecycle groups on
        2026-09-22. The 25-test identity lifecycle passed in 771.73 seconds.
        The remaining groups passed without a source change. The final
        `workload_recovery` group passed in 69.97 seconds.
    - [x] Replace unlink. Require File/Unlink and the target to remain.
      - [x] Pass Host and commit it. The 62-line test passed in 28.24 seconds
        on 2026-09-22. It preserved the recovered external actor, exact task
        attribution, `EACCES`, retained target, and zero policy object IDs.
      - [x] Pass direct `runc` and commit it. The unchanged test passed in
        29.49 seconds through stock `runc` and the production OCI hook on
        2026-09-22.
      - [x] Pass Kubernetes and commit it. The unchanged test passed in 70.23
        seconds against the retained real K3s cluster on 2026-09-22.
      - [x] Remove only the legacy unlink request, dispatch branch, assertion,
        target, and result field after all three platforms pass. The shared
        self-protection unlink branch remains.
    - [x] Replace hard-link creation. Require File/Link, the source to remain,
      and the target to stay absent.
      - [x] Pass Host and commit it. The 60-line test passed in 27.97 seconds
        on 2026-09-22. It preserved the recovered external actor, exact task
        attribution, source, absent target, and zero policy object IDs.
      - [x] Pass direct `runc` and commit it. The unchanged test passed in
        29.09 seconds through stock `runc` and the production OCI hook on
        2026-09-22.
      - [x] Pass Kubernetes and commit it. The unchanged test passed in 72.00
        seconds against the retained real K3s cluster on 2026-09-22.
      - [x] Remove only the legacy link request, dispatch arm, assertion,
        target, and result field after all three platforms pass.
    - [x] Replace rename. Require File/Rename, the source to remain, and the
      target to stay absent.
      - [x] Pass Host and commit it. The 68-line test passed in 28.31 seconds
        on 2026-09-22. It preserved the recovered external actor, exact task
        attribution, source, absent target, and zero policy object IDs.
      - [x] Pass direct `runc` and commit it. The unchanged test passed in
        29.34 seconds through stock `runc` and the production OCI hook on
        2026-09-22.
      - [x] Pass Kubernetes and commit it. The unchanged test passed in 73.12
        seconds against the retained real K3s cluster on 2026-09-22.
      - [x] Remove only the legacy rename request, dispatch arm, assertion,
        targets, and result field after all three platforms pass.
  - [x] Replace the managed `/proc/self/environ` read with one standard
    platform test. Use one shared Python actor and the existing Python policy.
    Start the runtime-added actor before Node so it retains the original
    external-root classification. Require `EACCES`, `UNRESOLVED_OBJECT`, the
    exact actor task, and no exact or path policy object.
  - [x] Pass the managed proc test on Host and commit it. The 89-line scenario
    file passed in 29.43 seconds on 2026-09-20.
  - [x] Pass the managed proc test on direct `runc` and commit it. The exact
    case passed in 35.10 seconds on 2026-09-20 through the production OCI
    hook.
  - [x] Pass the managed proc test on Kubernetes and commit it. The exact case
    passed in 73.64 seconds on 2026-09-20 against the retained K3s cluster.
  - [x] Remove only the matching legacy action and result field after all
    three platform cases pass. The cleanup removed 21 lines from the oversized
    legacy scenario and kept its shared actor read operation. The 92
    non-privileged library tests and strict crate Clippy pass.
  - [x] Replace the UTS namespace privilege block with one standard platform
    test. Use one shared Python actor and the existing Python policy. Start the
    runtime-added actor before Node to preserve the original external-root
    classification. Require user-space `EPERM`, BPF `EACCES`,
    `UNSUPPORTED_OBJECT`, `CAP_SYS_ADMIN`, the exact actor task, and no policy
    object.
  - [x] Pass the namespace privilege test on Host and commit it. The 79-line
    scenario passed in 29.46 seconds on 2026-09-20.
  - [x] Pass the namespace privilege test on direct `runc` and commit it. The
    exact case passed in 34.63 seconds on 2026-09-20 through the production OCI
    hook.
  - [x] Retain an execution transport status until its remote actor exits. The
    focused fixture test passed in 0.02 seconds. The namespace case then passed
    again on Host in 28.89 seconds and on direct `runc` in 37.18 seconds.
  - [x] Pass the namespace privilege test on Kubernetes and commit it. The
    exact case passed in 75.24 seconds on 2026-09-20 against the retained K3s
    cluster.
  - [x] Remove only the matching legacy action, result field, enum case, and
    dispatch arm after all three platform cases pass. The cleanup removed 16
    lines from the oversized legacy files. The 93 non-privileged library tests
    and strict all-target Clippy pass.
  - [x] Replace the BPF map-create privilege block with one standard platform
    test. Use one shared Python actor and the existing Python policy. Start the
    runtime-added actor before Node to preserve the original external-root
    classification. Require user-space and BPF `EACCES`,
    `UNSUPPORTED_OBJECT`, the exact actor task, and no policy object.
  - [x] Pass the BPF map-create test on Host and commit it. The 76-line
    scenario passed in 28.53 seconds on 2026-09-20.
  - [x] Pass the BPF map-create test on direct `runc` and commit it. The exact
    case passed in 37.05 seconds on 2026-09-20 through the production OCI hook.
  - [x] Reproduce the Kubernetes execution transport status in the lightweight
    fixture test. The actor exits successfully, the transport exits with code
    1, and `ProcessFixture` preserves the distinct transport result.
  - [x] Report the BPF syscall result independently of the execution transport.
    The shared actor publishes its errno in its task name and waits for normal
    release. The 89-line scenario passed again on Host in 29.90 seconds and on
    direct `runc` in 36.48 seconds on 2026-09-20.
  - [x] Pass the BPF map-create test on Kubernetes and commit it. The exact
    case passed in 76.19 seconds on 2026-09-20 against the retained K3s
    cluster.
  - [x] Remove only the matching legacy action, result field, enum case, and
    dispatch arm after all three platform cases pass. Keep the raw map-create
    helper because the independent network BPF-setup case still uses it. The
    cleanup removed 22 net lines from the oversized legacy files. The 13
    focused child-fixture tests, 93 non-privileged library tests, formatting,
    and strict all-target Clippy pass.
  - [x] Add Node logs to an actor early-exit diagnostic. The actor logs were
    empty in two Kubernetes exits with code 1 and one exit with code 139.
  - [x] Add the last 16 production effects to the same early-exit diagnostic.
    Reuse the Kubernetes fixture runtime. Do not create another async runtime.
    Retained kernel and container-runtime logs contain no crash, OOM, or exit
    record for the intermittent actor exits.
  - [x] Finish the third-migration platform matrix. The 58 Host cases and 49
    direct-`runc` cases passed. After the lifecycle-only correction, all four
    renamed recovery cases and the strengthened lifecycle-reuse test passed
    again on both lightweight platforms. Kubernetes passed all 49 cases. Its
    24-case identity lifecycle passed in 655.12 seconds. One earlier identity
    run lost the initial task identity for the subreaper Pod after 21 passed
    cases. The isolated subreaper case, the new lightweight transition, its
    Kubernetes form, and the unchanged full lifecycle all passed on the next
    runs. No speculative production change was made. The remaining Kubernetes
    lifecycle processes passed without changing their scenarios.

### Network

- [x] Replace `run_network_peer_server` with `NetworkPeerServer`. The owner
  binds and retains all three sockets, publishes and removes readiness, uses a
  bounded wait with the last receipt state, and removes a partial result file.
  Its focused test passed on 2026-09-23.
- [ ] `NetworkTestRunner::physical_probe` setup and teardown: own fixture,
  transport, cgroup, nftables, pin, lease, and peer-process cleanup.
  - [x] Add `NetworkProbeFixture::start` and `stop` for the fixture tree,
    transport tree, actor cgroups, root cgroup, pin root, and lease. A failed
    privileged run removed these resources on 2026-09-23.
  - [x] Keep nftables state in `NetworkRewriteOwner` with explicit cleanup and
    a `Drop` fallback.
  - [ ] Remove the remaining local server threads and launcher-owned peer
    process when their scenarios move to shared platform tests.
  - [ ] Do not repair the legacy child by adding another process launcher. The
    committed `32f4b0b` binary and the refactored binary both reject the first
    late-moved actor with `EACCES`. Kernel evidence reports
    `CORRUPT_IDENTITY_OR_GENERATION`. Shared platform actors start held in the
    governed cgroup and do not use this obsolete setup.
- [ ] `NetworkTestRunner::physical_probe` local socket scenarios: keep signed
  policy compilation, node binding, socket actions, and exact denials visible.
  - [x] Replace the allowed TCP Connect result by strengthening the existing
    TCP network-role test. Keep the exact address, port, protocol, destination
    handle, and production Allow evidence. Do not add an actor, policy, test,
    or Platform API.
    - [x] Pass Host and commit it. The exact Host case passed in 30.65 seconds
      with the production Allow decision and exact IPv4, TCP, port, address,
      destination-handle, and object-key assertions.
    - [x] Pass direct `runc` and commit it. The exact direct-runc case passed
      in 28.74 seconds with the same actor, policy, and assertions.
    - [x] Pass Kubernetes and commit it. The exact Kubernetes case passed in
      65.79 seconds in the retained K3s cluster with the same actor, policy,
      and assertions.
    - [x] Remove the matching legacy connect result field and standalone
      boolean assertion after all three platform cases pass. Keep the connect
      operation as setup because the remaining send, receive, clone, fork,
      socket-fence, and restart checks use its socket and production event.
      Keep those checks and sendmsg, sendfile, splice, receive-authority, and
      peer behavior for later migrations.
  - [x] Replace the connected TCP send and receive results by extending the
    existing TCP actor, policy, and test file. Bind one fixed loopback port.
    Require successful payload exchange and exact production Connect, Send,
    and Receive evidence. Do not add an actor, policy, helper, or Platform API.
    - [x] Pass Host and commit it. The exact Host test passed in 28.94 seconds.
      It completed the payload exchange, observed all three Allow results, and
      retired cleanly. The test found that file-descriptor release tombstoned
      each socket before TCP emitted its closing packet. The approved fix moves
      cleanup to the kernel socket destruction boundary.
    - [x] Pass direct `runc` and commit it. The exact direct-runc test passed
      in 29.50 seconds with the same actor, policy, assertions, and clean
      retirement.
    - [x] Pass Kubernetes and commit it. The exact Kubernetes test passed in
      67.87 seconds with the same actor, policy, assertions, and clean
      retirement. Actor failures use the container exit status so Kubernetes
      transport warnings do not change the shared result.
    - [x] Remove only the matching legacy result fields and standalone boolean
      assertions. Keep the socket operations as setup while sendmsg, sendfile,
      splice, clone, fork, socket-fence, and restart checks still use it. The
      focused legacy network result tests passed: 3 passed and 302 filtered
      out.
    - [x] Run the complete platform matrix after the shared BPF socket cleanup
      change. Host passed 25 of 25 lifecycle groups. Direct `runc` passed 24
      of 24 lifecycle groups. Kubernetes passed 24 of 24 lifecycle groups in
      the retained K3s cluster. The first Host identity run had one missing
      consumed-slot result. Its exact case, ordered three-case group, and clean
      39-case identity rerun passed without a source change. The first direct-
      `runc` identity run had one placement-readiness failure. Its exact case
      and clean 34-case identity rerun passed without a source change.
  - [x] Replace connected `sendmsg`, `sendfile`, and `splice` behaviors. Keep
    each syscall, payload receipt, file-backed input, role, and exact network
    result visible. Use the shared actor and one small test where this remains
    clear.
    - [x] Add one Host test with the existing actor, policy, and Platform API.
      Use one connected socket. Require exact peer payloads for `sendmsg`,
      file-backed `sendfile`, and file-backed `splice`, plus three matching
      production Send results. The test has 39 lines.
    - [x] Pass Host and commit it. The exact Host case passed in 27.93
      seconds.
    - [x] Pass direct `runc` and commit it. The exact direct-runc case passed
      in 28.87 seconds with the same actor, policy, and assertions.
    - [x] Pass Kubernetes and commit it. The exact physical case passed in the
      retained K3s cluster with the same actor, policy, and assertions.
    - [x] Remove only the matching legacy result fields and allow assertions.
      Keep the later post-fence calls and their denial assertions.
  - [x] Replace clone-send and fork-send socket inheritance. Keep distinct
    child execution, payload receipt, creator identity, and allowed result
    assertions. Keep socket-generation non-reuse as a separate lifecycle test.
    - [x] Add one Host test with the existing actor, policy, and Platform API.
      Duplicate one connected socket and fork one child with the same socket.
      Require both peer payloads, distinct child identity, root creator
      identity, two production Send results, and one shared socket generation.
      The test has 73 lines.
    - [x] Pass Host and commit it. The exact Host case passed in 28.46
      seconds.
    - [x] Pass direct `runc` and commit it. The exact direct-runc case passed
      in 28.99 seconds with the same actor, policy, and assertions.
    - [x] Pass Kubernetes and commit it. The corrected physical case passed in
      64.73 seconds in the retained K3s cluster.
      - The first physical run found an evidence-readiness gap. The actor and
        child identities were ready, but the immediate snapshot did not yet
        contain the root Send result. The shared actor now separates prepare
        and action. The Host and direct-`runc` cases pass with bounded evidence
        readiness for both tasks. No production or Platform code changed.
    - [x] Remove only the matching legacy clone-send and fork-send success
      actions and assertions. Keep the post-fence cloned-socket denial and the
      separate socket-generation non-reuse behavior.
  - [x] Replace socket-generation non-reuse with one small standard platform
    test. Reuse the TCP actor and signed policy. Close one connected socket,
    then connect and send on a new socket. Require both payloads, two allowed
    Connect and Send results for the admitted actor, and distinct socket
    generations. Do not add a Platform API.
    - [x] Pass Host and commit it. The 63-line test passed in 28.52 seconds.
      All five existing Host TCP cases passed together in 55.92 seconds with
      the shared actor and evidence-wait change.
    - [x] Pass direct `runc` and commit it. The unchanged case passed in
      29.19 seconds. All five existing direct-`runc` TCP cases passed in
      58.99 seconds with the shared actor and evidence-wait change.
    - [x] Pass Kubernetes and commit it. The unchanged case passed in
      65.24 seconds. The first attempt stopped before actor creation because
      K3s lacked the pinned Python image. Pulling that exact image restored
      the fixture; no test or production code changed. All five existing
      Kubernetes TCP cases passed in 142.86 seconds.
    - [x] Remove only the matching legacy lifecycle action and result after
      all three platforms pass. The deletion removed the extra listener,
      server thread, lifecycle action, and result field. It kept the fence,
      restart, and socket-reference checks. The new Host case passed again;
      91 non-privileged tests, formatting, and strict Clippy passed.
  - [ ] Replace the whole-socket fence and Node restart group. Preserve the
    installed response floor, retained task, socket, mount, and active-policy
    state, denied send and shutdown, absent bytes and bypass packets, released
    socket reference, and idempotent restart recovery.
    - The only Rust callers of the production
      `NodePolicyGenerationOwner::fence_network_socket` operation are in the
      legacy network probe. The deployed Node has no caller for that action.
      `FenceSockets` exists in Control's policy source and validation, but it
      does not invoke the Node operation. Keep the legacy checks until an
      approved production response path can run in Kubernetes. Do not add a
      test-only Node endpoint or complete the excluded product work.
  - [x] Replace IPv6 TCP behavior. Keep address family, protocol, destination,
    payload receipt, and policy result explicit.
    - [x] Add one Host test with the existing actor, policy, and Platform API.
      Require the `::1` payload plus exact IPv6 TCP Connect and Send results.
      The test has 54 lines.
    - [x] Pass Host and commit it. The exact Host case passed in 28.64
      seconds.
    - [x] Pass direct `runc` and commit it. The exact direct-runc case passed
      in 29.61 seconds with the same actor, policy, and assertions.
    - [x] Pass Kubernetes and commit it. The exact physical case passed in
      67.51 seconds in the retained K3s cluster with the same actor, policy,
      and assertions.
    - [x] Remove only the matching legacy IPv6 TCP action, result field, and
      assertion.
  - [x] Replace connected and unconnected UDP behavior. Keep IPv4 and IPv6
    address family, protocol, destination, payload receipt, and policy result
    explicit in each small test.
    - [x] Add one standard test with four explicit UDP cases. Reuse the
      network actor and signed policy. Check each received payload and exact
      Send result. Check the Connect result for connected sends. The test has
      fewer than 100 lines.
    - [x] Pass Host and commit it. The exact case passed in 27.94 seconds.
    - [x] Pass direct `runc` and commit it. The exact case passed in 29.10
      seconds with the production OCI hook.
    - [x] Pass Kubernetes and commit it. The exact physical case passed in
      65.51 seconds in the retained K3s cluster.
    - [x] Remove only the matching legacy UDP actions, result fields, and
      local listeners after all three platforms pass. The two-node UDP peer
      case remains.
  - [ ] Replace unsupported network family, `io_uring` SQPOLL, TUN/TAP, and BPF
    setup denials. Keep each syscall and fail-closed result explicit.
    - [ ] Qualify protected BPF map setup with the existing Python actor and
      policy. The current platform BPF test covers a recovered actor. Preserve
      the protected-actor condition from the legacy network probe.
      - A focused Host attempt on 2026-09-24 admitted the actor and returned
        `bpf-map-0`: Linux created the map. The public role has no BPF
        operation rule or Privilege default action. A capability rule would
        test a different operation. Keep the legacy check until the public
        policy can express and qualify this denial. The failed test was not
        committed.
    - [x] Qualify `io_uring` SQPOLL setup and its Privilege evidence.
      - [x] Add one 57-line test and one Python actor that calls
        `io_uring_setup` with the original disabled, single-issuer, and SQPOLL
        flags. Require actor `EACCES`, the recovered role, and attributed
        `UNSUPPORTED_OBJECT` Privilege/IoUringSqpoll evidence.
      - [x] Pass Host and commit it. The exact case passed in 28.19 seconds.
      - [x] Pass direct `runc` and commit it. The exact case passed in 28.87
        seconds with the production OCI hook.
      - [x] Pass Kubernetes and commit it. The exact physical case passed in
        70.61 seconds in the retained K3s cluster.
      - [x] Remove only the matching legacy SQPOLL mailbox action and result
        field. Keep the independent `io_uring` syscall fixture and other
        setup denials.
    - [x] Qualify TUN/TAP setup and its physical denial.
      - [x] Add a 56-line platform test and one Python actor. Check that
        `/dev/net/tun` is character device 10:200 before Node starts. The
        actor then opens it after recovery. Require `EACCES` and attributed
        `UNRESOLVED_OBJECT` File/OpenRead evidence. The legacy probe accepted
        either an open or ioctl denial; the new check names the observed
        open denial and does not claim that `TUNSETIFF` ran.
      - [x] Pass Host with `/dev/net` in the actor root and commit it. The
        exact case passed in 28.33 seconds in the retained VM.
      - [x] Pass direct `runc` with the same actor and policy, then commit it.
        The exact case passed in 29.14 seconds with the production OCI hook.
      - [x] Pass Kubernetes with the same actor and policy, then commit it.
        The exact physical case passed in 70.39 seconds in retained K3s.
      - [x] Remove only the matching legacy TUN action and result field after
        all supported platforms pass. Keep the protected-BPF probe. The three
        network unit tests and strict clippy passed after this deletion.
    - [x] Qualify every unsupported socket family and protocol in the legacy
      list. Require Mithril denial evidence where the hook supports it.
      - [x] Add one 99-line standard test. Start the extra actor before Node
        and recover it with entry rule zero. Send all seven original socket
        requests in one actor action. Require seven attributed
        `UNSUPPORTED_OBJECT` SocketCreate results with `EACCES` and no
        destination or exact-object policy handle.
      - [x] Pass Host and commit it. The exact case passed in 28.22 seconds.
      - [x] Pass direct `runc` and commit it. The exact case passed in 29.70
        seconds with the production OCI hook.
      - [x] Pass Kubernetes and commit it. The exact physical case passed in
        70.08 seconds in the retained K3s cluster.
      - [x] Remove only the matching seven legacy socket calls and their
        result field after all three platforms pass. Keep the initial
        classification socket and unrelated setup denials.
    - [ ] Remove each matching legacy action only after its platform cases
      pass. Keep unrelated network setup tests.
  - [ ] Replace accepted-socket transfer authority. Keep the narrow actor
    denial, approved actor success, descriptor transfer, role, and received
    payload assertions.
    - [x] Qualify the restricted receiver as one small shared test. Start the
      listener and receiver before Node. Create the Unix endpoint after Node
      recovers them, then pass one accepted TCP descriptor with `SCM_RIGHTS`.
      Require distinct application and external roles, one passed descriptor,
      denied Send and Receive, matching attributed socket evidence, and no
      forbidden bytes at the client. Use only ports 19097 and 19098.
      - [x] Host passed. The 87-line test passed in 34.65 seconds with the
        real Control, Node, and BPF path.
      - [x] Direct `runc` passed in 42.21 seconds with the same test body,
        Python actor, policy, and production OCI hook.
      - [x] Kubernetes passed in 83.67 seconds in retained K3s with the same
        physical transfer and result assertions.
    - [x] Qualify approved-receiver payload delivery and role attribution in
      a separate small test before removing any accepted-socket legacy block.
      - [x] Host passed in 37.10 seconds. One approved entry received the
        accepted descriptor and sent `ok`. The test checks its role and
        production Send result. The restricted Host case also passed with
        one inclusive port range in 36.25 seconds.
      - [x] Direct `runc` passed in 45.77 seconds with the same test body,
        Python actor, policy, and production OCI hook. The restricted case
        passed with the one-range policy in 37.37 seconds.
      - [x] Kubernetes passed in 83.07 seconds in retained K3s with the
        same actor, policy, and result assertions. The restricted case passed
        with the one-range policy in 79.26 seconds.
    - [ ] Retire the matching legacy actions without removing the shared
      socket fence or namespace transfer.
      - [x] Remove the narrow receiver actor, transfer, denial actions, and
        duplicate fixture result. Keep the signed connected Receive result
        explicit. The new shared test owns the narrow denial. Its focused Host
        case passed in 29.16 seconds. Three network fixture tests, formatting,
        and strict all-target Mithril E2E Clippy passed.
      - [ ] Keep the approved legacy transfer until the shared-fence and
        namespace checks have independent platform replacements. The old
        physical probe fails before these actions at its documented
        late-moved-actor classification step; do not repair that setup.
  - [ ] Replace cross-network-namespace socket transfer. Keep narrow denial,
    approved success, descriptor transfer, payload receipt, and distinct
    creator and current namespace evidence.
    - [ ] Qualify the restricted receiver on Host, direct `runc`, and
      Kubernetes. Reuse the socket-pass actor, signed policy, and effect
      checks. Require an accepted TCP descriptor transferred after policy
      activation, denied Send and Receive, no forbidden payload, and distinct
      socket creator and current network namespaces.
      - The rejected Host-only draft used `pidfd_getfd`. Host passed through
        `RUNTIME_ENTRY_INFRASTRUCTURE`. Direct `runc` returned `EPERM` and
        recorded `UNSUPPORTED_OBJECT` Privilege/Ptrace with `-EACCES`.
        The old lower-level probe allows `PTRACE_ACCESS_18`, but the public
        policy rejects a matching `Ptrace` `Allow` rule with
        `CFG_KUBERNETES_PROCESS_CONTROL`. The draft test and actor modes were
        removed. No platform is qualified by that draft. Keep the legacy
        after-policy transfer check until a shared test preserves it.
      - [ ] Use the existing Unix control socket and `SCM_RIGHTS` instead of
        `pidfd_getfd`. Move the receiver to a new network namespace before
        Node starts. Create a filesystem Unix control listener after recovery,
        then transfer the accepted TCP descriptor.
        Require the denied Send and Receive effects, no forbidden payload,
        and distinct creator and current network namespace evidence. Pass
        Host, direct `runc`, and Kubernetes before removing the old action.
        The first Host draft bound an abstract listener before Node recovered
        its creator. The later Unix connect returned `EACCES` before descriptor
        transfer. The draft now creates the listener after recovery. No old
        assertion was removed. The second Host draft reached the filesystem
        socket bind. Production denied File/Create with `UNRESOLVED_OBJECT`
        and `-EACCES`. A separate signed policy now permits only that control
        socket creation for the restricted role. Its Network Send and Receive
        permissions remain unchanged.
      - [x] Host passed with the final 99-line test in 32.94 seconds. It used
        one accepted TCP descriptor and `SCM_RIGHTS`. It required denied Send
        and Receive,
        no forbidden payload, distinct live network namespaces, and matching
        creator and current namespace in both production effect results. The
        existing same-namespace restricted case passed in 33.75 seconds.
        Formatting, strict Clippy, 91 non-privileged tests, and JSON syntax
        passed.
      - [ ] Pass the unchanged case under direct `runc`, then commit it.
      - [ ] Pass the unchanged case on Kubernetes, then commit it.
    - [ ] Qualify the approved receiver with the same physical transfer and
      distinct namespace evidence. Require the allowed Send, payload receipt,
      and exact production role and effect result on all three platforms.
      Remove the matching legacy transfer only after both tests pass.
  - [ ] Replace shared-socket-holder fencing. Keep both holders denied after
    the response floor, no received bytes, and the shared reference alive
    until the last close.
  - [ ] Replace rewritten-destination enforcement. Keep the forbidden final
    address packet absent and the allowed final destination payload received.
    - A Host platform draft reached the denied TCP flow. The final-flow BPF
      hook emitted a packet-drop observation without a task cookie. Node
      rejected that observation and marked evidence coverage as gapped. The
      actor's blocking connect timed out, so the draft did not prove an
      `EACCES` syscall result. Keep the legacy action until a replacement
      proves the packet absence, allowed payload, and valid Node evidence on
      Host, direct `runc`, and Kubernetes. No draft code or BPF change remains.
    - The final packet hook has no current-task identity by design. Its socket
      state has flow IDs, but `KernelEffectEvidenceV1` has no socket or flow ID.
      Do not copy a task cookie into packet evidence or accept an unattributed
      exact-policy result to make this test pass. The durable evidence model
      needs a separate approved attribution decision before this action can
      replace the legacy raw-event check.
  - [x] Replace delegated egress. Keep the request ID, requested and final
    destinations, forbidden request absence, and allowed request receipt.
    - [x] Keep distinct governed requester and delegate tasks, both request
      IDs, the delegate's denied and allowed Connect results, its allowed Send
      result, the allowed TCP payload, and no forbidden connection. Use one
      shared actor and one Rust test below 100 lines on all three platforms.
      A draft with a two-destination policy did not activate on Host: Node
      staged the candidate, then remained `activation_pending` for 30 seconds.
      An explicit destination deny had the same result. A known-good two-entry
      Unix/network policy passed on the same VM in 27.57 seconds. No draft
      action or assertion replaced the legacy runner.
      - A later Host probe found that two destination records with the same
        IPv4 prefix and protocol produce one Node class key. That key does
        not include the port. A policy with distinct prefixes and a Network
        Connect default activated. The delegate's forbidden Connect returned
        `EACCES` with `UNRESOLVED_OBJECT` evidence.
      - The allowed Connect to a governed requester's TCP listener remained
        `SYN-SENT` while the listener was bound. The result was the same when
        the requester and delegate exchanged primary and added-entry roles.
        The legacy probe uses an ungoverned TCP listener. Do not retire it
        until a shared physical peer preserves the allowed payload receipt
        on Host, direct `runc`, and Kubernetes. The cause of the stalled TCP
        handshake is not yet proven. No failed draft is in the source tree.
      - [x] Pass Host with an ungoverned TCP peer bound in the actor's network
        namespace. The 98-line Rust test kept two governed tasks, both request
        IDs, the denied Connect, no forbidden peer connection, the allowed
        Connect and Send, and the received payload. The focused case passed
        again in 30.47 seconds after the actor stopped copying the Python
        entry that the shared fixture already supplies. No Platform or
        production API changed.
      - [x] Pass the same Rust test, actor, and policy on direct `runc`.
        The focused case passed in 37.15 seconds through the production OCI
        hook. It used the same ungoverned peer in the actor's network
        namespace and kept all Host assertions.
      - [x] Pass the same Rust test, actor, and policy on Kubernetes.
        The focused case passed in 69.36 seconds with deployed Control and
        Node. The test process exited with status 0. No test namespace
        remained in the retained K3s cluster after teardown.
      - [x] Remove the matching legacy actions after all three passed. The
        runner no longer starts two proxy actors or listener threads. Its
        child mailbox no longer has proxy commands or a proxy result. The
        test bundle no longer claims the duplicate delegated fixture result.
        The two-node shell now expects eight remaining fixture results.
        Three network runner tests, nine child tests, the VM harness checks,
        formatting, and strict Clippy passed. Other network actions remain.
  - [ ] Replace separate read-result and provider-write behavior. Keep the
    governed file read classes, provider receipt, and network result evidence.
    - [x] Check zero-byte, EOF, partial, inherited-descriptor, mapped, and
      `EIO` reads in one shared actor before policy replacement. Keep its token
      descriptor open. After replacement, require allowed Read and MmapRead
      on that descriptor with exact production File results. Pass the same
      Rust test on Host, direct `runc`, and Kubernetes before removing the
      legacy read-result action.
      - [x] Pass Host and commit it. The 64-line Rust test passed in 34.11
        seconds with all six return classes, a retained token descriptor,
        and exact Read and MmapRead Allow results. Node logged one transient
        exact-selector reconciliation warning; policy activation, evidence,
        and teardown completed.
      - [x] Pass direct `runc` and commit it. The same test body, actor, and
        policy passed in 40.08 seconds through the production OCI hook. Node
        logged the same transient warning and completed teardown.
      - [x] Pass Kubernetes and commit it. The same test body, actor, and
        policy passed in 71.73 seconds against the deployed Node and Control
        in the retained K3s cluster. The test process exited with status 0.
      - [x] Remove the matching legacy read actions, result field, fixture
        row, child protocol, and two actor-only tests. Keep the token file and
        exact object setup for the remaining sendfile, splice, and fence
        checks. The old shell expected 12 fixture rows while the Rust probe
        emitted 10 before this deletion; it now expects the 9 rows that the
        remaining Rust probe emits. The post-deletion Host test, 91
        non-privileged crate tests, VM harness checks, formatting, and strict
        Clippy passed. The legacy network runner remains open.
    - [ ] Keep the provider-write action until a shared platform test sends
      its payload after the separate socket is fenced. The existing TCP
      round-trip proves ordinary payload delivery, but it does not prove that
      an independent allowed provider flow survives the fence. Require the
      provider receipt and exact Network results on all three platforms.
  - [x] Replace the unclassified IPv4 connect denial with one standard
    platform test. Use one shared Python actor and one scenario policy. Do not
    add a Platform API.
    - [x] Implement the approved public role default before the platform test.
      `defaultActions` is a role-level list. Its first qualified form is
      `family: Network`, `operations: [Connect]`, and `action: Deny`. Control
      lowers it to the existing `EffectFamilyDefaultV1`. An exact destination
      rule wins. A missing exact destination uses the explicit default. A
      destination allow rule alone must not create an implicit default.
      - The exact admitted Host actor reached Linux on 2026-09-22 and returned
        `ECONNREFUSED` for port 9. This proves that the default is absent.
      - The approved BPF fallback compiles. It cannot deny until Control
        installs the existing `DENY CONNECT` family default.
      - [x] Prove public parsing, lowering, compilation, explicit `EACCES`, and
        absence of an implicit default in focused Control tests.
      - [x] Regenerate the Helm CRD from the Control schema owner.
    - [x] Connect to `127.0.0.1:9`. Require actor `EACCES` and one
      `UNRESOLVED_OBJECT` network-connect observation for the exact actor task,
      IPv4 address, TCP protocol, and port. Require no policy object handle.
    - [x] Keep the test below 100 lines. The test has 60 lines.
    - [x] Pass Host and commit it. The Host case passed on 2026-09-22 with
      the production Control, Node, policy compiler, BPF program, and evidence
      path.
    - [x] Pass direct `runc` and commit it. The direct-runc case passed on
      2026-09-22 with the same test body, actor, policy, and assertions as the
      Host case.
    - [x] Pass Kubernetes and commit it. The Kubernetes case passed on
      2026-09-22 with the same test body, actor, policy, and assertions after
      the retained cluster refreshed its CRD and production image tags.
    - [x] Remove only the matching legacy action and result field after all
      three platforms pass. Network physical-probe result schema 2 removes
      this field. Its other actions, fixture rows, and assertions remain.
    - [x] Run the complete shared lifecycles after the replacement. Host passed
      32 identity cases. Direct runc passed 27 identity cases. Kubernetes
      passed 27 identity cases. Ptrace, signal, and workload recovery passed
      separately on all three platforms.
  - [x] Replace the TCP part of the DNS-exfil denial block with one standard
    platform test. Use one shared Python actor and one scenario policy. Do not
    add a Platform API.
    - [x] Deny TCP connects to `127.0.0.1:53`, `127.0.0.53:853`, and
      `127.0.0.53:443`.
    - [x] Use the approved Network `Connect` role default. Do not add
      socket-option permissions, expand role defaults, or add a test-only
      production path.
    - [x] Keep the Rust test below 100 lines. The test has 25 lines. The exact
      Host case passed in 27.99 seconds on 2026-09-23.
    - [x] Pass direct `runc` and commit it. The exact case passed in 28.86
      seconds on 2026-09-23 with the same actor, policy, and assertions.
    - [x] Pass Kubernetes and commit it. The exact physical case passed in
      66.08 seconds on 2026-09-23 with the same actor, policy, and assertions.
    - [x] Remove only the three matching legacy TCP actions after all three
      platform cases pass. Keep the combined result, fixture proof, and shell
      assertion until the UDP replacement passes.
  - [x] Replace the UDP part of the DNS-exfil denial block without expanding
    the public role defaults. Keep unconnected sends to `127.0.0.1:53` and
    `127.0.0.53:5353`, and a connected request to `8.8.8.8:53`. Preserve the
    legacy checks until this separate scenario passes all platforms.
    - [x] Use exact role destination denies for the two unconnected UDP sends.
      Keep the existing Network `Connect` default for the connected request.
      Control now accepts a DNS-port destination that only a `Deny` rule uses.
      It still rejects an `Allow` or `Alert` rule for that destination.
    - [x] Keep the Rust test below 100 lines. The test has 21 lines.
    - [x] Pass Host and commit it. The exact case passed in 28.15 seconds on
      2026-09-23. No BPF, Node, or platform change was required.
    - [x] Pass direct `runc` and commit it. The exact case passed in 29.44
      seconds on 2026-09-23 with the same test body, actor, policy, and
      assertions as Host.
    - [x] Pass Kubernetes and commit it. The exact physical case passed in
      67.17 seconds on 2026-09-23 with the same test body, actor, policy, and
      assertions as Host and direct `runc`.
    - [x] Remove only the matching legacy UDP actions and result field after
      all three platform cases pass. The shared platform test now owns the
      three UDP denials.
    - [x] Run the complete platform matrix after the Control validation
      change. Host passed 75 cases. Direct `runc` passed 66 cases. Kubernetes
      passed 66 cases. One earlier `runc` identity run had an isolated
      `setnsProcess` setup failure in the subreaper case. The exact case and a
      clean 33-case identity rerun passed without a source change.
  - [x] Retire `NET-SOCKCTL-001`. Role network policy uses the Cilium
    boundary. It governs destinations, protocols, ports, and traffic. It does
    not govern socket options.
    - [x] Remove `socketControls` from the public role policy and its compiler.
    - [x] Use one shared Python actor that sets `TCP_NODELAY` and requests a
      connection to an allowed destination. Assert the production `Connect`
      decision. A Linux refusal because no service listens is not a policy
      denial. Do not assert a separate `SETSOCKOPT` decision.
    - [x] Do not claim that Mithril denies `SO_MARK`. Linux capability checks
      govern that option.
    - [x] Do not change `network_unsupported()` for this migration.
    - [x] Keep the test below 100 lines. The test has 36 lines.
    - [x] Pass Host and commit it. The privileged Host case passed on
      2026-09-23 with the shared actor and the exact production `Connect`
      decision.
    - [x] Pass direct `runc` and commit it. The direct-runc case passed on
      2026-09-23 with the same test body, actor, policy, and assertions as the
      Host case.
    - [x] Pass Kubernetes and commit it. The physical Kubernetes case passed
      on 2026-09-23 with the same test body, actor, policy, and assertions.
    - [x] Remove only the matching legacy actions, fields, and fixture row
      after all three platforms pass. The other 12 network fixture rows remain.
- [ ] `NetworkTestRunner::physical_probe` two-node peer scenario: keep the
  same TCP, UDP, and denied-port operations as `two-node-network.sh`.
- [ ] Remove `NetworkTestRunner::physical_probe`, its old CLI path, and its
  remaining fixture code only after every local and two-node behavior above
  passes as a shared platform test. Keep the network file on this list even
  while it stays below 2,000 lines.

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
  - [x] Replace the 1,200-argument `cat` action with one standard platform
    test. Reuse `runtime_exec.py`, `runtime_entries_policy.json`, and
    `add_actor`. Do not add a Platform API or another actor program.
  - [x] Keep the declared cat role and nonzero admission rule explicit. Require
    successful exit and at least 1,024 recent effects attributed to that actor.
  - [x] Keep the test below 100 lines. The implementation has 47 lines.
    - [x] Host passed in 30.11 seconds. The existing Host entry-role test
      passed in 28.12 seconds with the shared policy change.
    - [x] Direct `runc` passed in 30.49 seconds. The existing direct-`runc`
      entry-role test passed in 28.21 seconds with the shared policy change.
    - [x] Kubernetes passed in 66.92 seconds. The existing Kubernetes
      entry-role test passed in 69.81 seconds with the shared policy change.
  - [x] Remove only the matching legacy action, result field, recent-window
    churn assertion, and shell assertion after all three platform cases pass.
  - [x] Retire the duplicate application-descendant default-exec assertion.
    Reuse `running_task_uses_new_policy`, `policy_replace.py`, and their policy.
    Keep `APPLICATION_DEFAULT_ALLOW`, Exec/Execute, child task attribution,
    inherited role and admission rule, and zero composite and exact keys
    explicit. Do not add another test, actor, policy, or Platform API.
    - [x] Host passed in 35.99 seconds. The strengthened test has 99 lines.
    - [x] Direct `runc` passed in 36.10 seconds.
    - [x] Kubernetes passed in 71.86 seconds. Remove only the matching legacy
      assertion, result field, and shell assertion.
    - [x] Run the required third-scenario gate. Host passed 35 tests in 366.79
      seconds. Direct `runc` passed 30 tests in 359.28 seconds. Kubernetes
      passed 30 tests in 880.29 seconds.
  - [x] Retire the duplicate application-entry allow result. Reuse
    `runtime_entries_stay_distinct` and its existing actor and policy. Keep the
    application execution state, runtime-binding lifecycle, declared role, and
    nonzero admission rule explicit. Do not add a test, actor, policy, or
    Platform API.
    - [x] Pass Host in a separate verified commit. The strengthened test has
      98 lines and passed in 28.13 seconds.
    - [x] Pass direct `runc` in a separate verified commit. The exact case
      passed in 29.44 seconds.
    - [x] Pass Kubernetes in a separate verified commit. The exact physical
      case passed in 64.55 seconds. Remove only the matching legacy result
      field and shell assertion.
  - [x] Replace the incidental application-default file-read result with one
    explicit platform test. Reuse `runtime_exec.py`, its policy, and its input
    fixture. Command the application actor to read the file after the evidence
    marker. Require `APPLICATION_DEFAULT_ALLOW`, File/Read, actor attribution,
    and zero composite and exact object IDs. Do not add a policy or Platform
    API.
    - [x] Pass Host in a separate verified commit. The 43-line test passed in
      28.47 seconds.
    - [x] Pass direct `runc` in a separate verified commit. The exact case
      passed in 28.48 seconds.
    - [x] Pass Kubernetes in a separate verified commit. The exact physical
      case passed in 64.39 seconds. Remove only the matching legacy result,
      helper, and shell assertion.
  - [x] Replace the direct-runc-only unprotected initial-exec block with one
    standard platform test. Start Control and Node without a policy. Require
    the shared actor to start, receive its stop command, and exit successfully.
    Do not add a fixture, policy, or Platform API.
    - [x] Pass Host in a separate verified commit. The 20-line test passed in
      21.54 seconds.
    - [x] Pass direct `runc` in a separate verified commit. The exact case
      passed in 22.03 seconds.
    - [x] Pass Kubernetes in a separate verified commit. The exact physical
      case passed in 56.68 seconds. Remove the exact legacy action and result
      field.
    - [x] Run the required third-behavior matrix. Host passed 25 lifecycle
      groups and 74 tests. Direct `runc` passed 24 lifecycle groups and 65
      tests. Kubernetes passed 24 lifecycle groups and 65 tests against the
      retained K3s cluster. The shared identity groups passed 37 Host tests in
      380.42 seconds, 32 direct-`runc` tests in 364.12 seconds, and 32
      Kubernetes tests in 951.49 seconds.
- [ ] Kubernetes subpath, bind alias, and wildcard paths: keep the same mount
  order and protected reads as the Kubernetes workload.
- [ ] Concurrent exec and reader-queue saturation: keep the same containerd
  exec operation, topology snapshots, bounded queue, and fail-closed results
  as `two-node-convergence.sh`.
- [ ] Stale cache repair and unreachable-row retirement: keep the production
  node reconciliation calls and exact map absence checks visible.
- [ ] Independent additional entries: keep each declaration, stock exec,
  role, rule, process state, and isolation assertion.
- [x] Use one entry-isolation platform test for stock `cat`, `grep`, and `wc`.
  Use one Control, Node, main actor, policy, and FIFO. Keep each command name,
  arguments, live identity, denial, and kernel evidence assertion explicit.
  This specific test can contain at most 150 lines. The implementation has 88
  lines. It passed Host in 30.26 seconds, direct `runc` in 37.06 seconds, and
  Kubernetes in 78.44 seconds. The complete shared lifecycle passed 27 Host
  cases in 253.39 seconds, 22 direct-`runc` cases in 386.50 seconds, and 22
  Kubernetes cases in 563.27 seconds.
- [x] Readiness entry policy isolation: use stock `grep`. Require the
  readiness role to read the application-denied file, then deny its own exact
  file read with matching role, admission-rule, and kernel evidence.
  - [x] Use the shared entry-isolation test, actor, policy, FIFO readiness
    owner, and result assertions.
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
  - [x] Use the shared entry-isolation test, actor, policy, FIFO readiness
    owner, and result assertions.
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
  - [x] Read the terminal approval slot before task inspection. Node can
    reconcile the consumed slot while the test reads the task. The explicit
    `Consumed` assertion passed on Host, direct `runc`, and Kubernetes. The
    shared direct-`runc` order also passed the three administrative cases.
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
  - [x] Replace the post-restart PostStart `cp` role and file-policy checks.
    - [x] Add one 88-line direct test. Start the application, restart Node,
      and hold one declared `cp` entry at a FIFO. Require its PostStart role,
      its read of an application-denied file, and its own attributed `EACCES`
      denial. The exact Host test passed in 51.23 seconds. Both Host tests in
      the `node_restart` lifecycle passed together in 80.62 seconds. The
      existing `runtime_entries_stay_distinct` Host test passed in 28.48
      seconds with the extended policy. The repository Rust CI check passed.
    - [x] Pass the same test on direct `runc` and commit that platform. The
      exact test passed in 57.90 seconds. Both `node_restart` runc tests
      passed together in 92.83 seconds. The existing
      `runtime_entries_stay_distinct` runc test passed in 34.94 seconds.
    - [x] Pass the same test on Kubernetes and commit that platform. The first
      preflight found that the retained K3s store lacked the pinned Python
      image. The existing image helper imported the retained archive and
      made that exact digest available. No test or production code changed
      for this condition.
      The exact test then passed in 85.30 seconds. Both `node_restart`
      Kubernetes tests passed together in 134.18 seconds. The existing
      `runtime_entries_stay_distinct` Kubernetes test passed in 65.73 seconds.
    - [x] Prove that the PostStart admission rule uses the literal path map.
      The separate 47-line test starts one real `cp` entry after Node restart.
      It reads the installed admission map and requires the observed rule ID,
      role ID, zero exact-object key, and default executable object. It then
      copies stdin and checks the physical output file.
      - [x] Pass Host. The exact test passed in 50.72 seconds. All three Host
        `node_restart` tests passed together in 109.74 seconds.
      - [x] Pass direct `runc` and commit that platform. The exact test passed
        in 57.69 seconds. All three runc `node_restart` tests passed together
        in 129.70 seconds.
      - [x] Pass Kubernetes and commit that platform. The exact test passed
        in 91.77 seconds. All three Kubernetes `node_restart` tests passed
        together in 178.07 seconds. The retained K3s image store again lacked
        the pinned Python image before this run. The existing preload helper
        restored the exact digest before the unchanged test started.
    - [x] Remove only the matching legacy PostStart action, result, and shell
      check. Keep the PreStop inventory-omission case until its own replacement
      passes. The old direct-`runc` fixture had changed its OCI spec only in
      memory. It now writes the spec before containerd reads it. The unchanged
      default spec had `terminal: true` and no test hooks. The repaired
      privileged probe passed in the retained VM. Its complete launcher
      result predicate passed with one PreStop entry and all remaining
      security and cleanup fields. The VM harness checks and repository Rust
      CI check passed after the change.
  - [x] Retain a declared PreStop entry across the same real Node restart.
    Require the recovered policy generation, external runtime root,
    qualified role, exact PreStop role, and nonzero admission rule.
    - [x] Pass Host and commit it. The 40-line test passed in 52.60 seconds on
      2026-09-21.
    - [x] Pass direct `runc` and commit it. The exact test passed in 69.23
      seconds on 2026-09-21.
    - [x] Pass Kubernetes and commit it. The exact test passed in 106.45
      seconds on 2026-09-21.
    - [ ] Replace the separate runtime-inventory omission case before its
      legacy result is removed. The new restart test uses the normal CRI
      inventory. It does not prove that a populated cgroup retains its binding
      when one CRI scan omits it. Keep the result field, shell gate, test-only
      probe, `/bin/dd` role assertion, and exact file-denial assertion until a
      small replacement proves all of them. The old probe calls
      `runtime_inventory_absence_proves_retirement_for_test` directly. It does
      not omit a CRI row or run deployed Node reconciliation. The replacement
      must make Node observe a missing row while the actor cgroup is populated.
      The lightweight CRI fixture can return an empty list. The current
      Kubernetes fixture uses stock containerd and has no matching input.
      Do not count another Node restart or a test-only guard call as proof.
    - [x] Replace the application and PreStop literal-admission checks. The
      new 41-line standard test reads both installed rules after Node restart.
      It requires the observed role and rule IDs, zero exact-object keys, and
      default executable objects. The shared task lookup also keeps the
      existing PostStart rule check short.
      - [x] Pass Host. The exact test passed in 51.31 seconds. All four Host
        restart tests passed together in 138.15 seconds. The unchanged
        PostStart literal-path case passed on direct `runc` in 51.15 seconds
        and Kubernetes in 91.22 seconds with the shared lookup. Repository
        Rust CI passed after the source change.
      - [x] Pass direct `runc` and commit that platform. The exact case passed
        in 51.59 seconds. All four direct-`runc` restart tests passed together
        in 140.54 seconds.
      - [x] Pass Kubernetes and commit that platform. The exact case passed
        in 91.94 seconds. All four Kubernetes restart tests passed together
        in 220.50 seconds on 2026-09-24.
      - [x] Remove the matching old literal-path result fields and shell
        gates. Keep the separate PreStop role, file-denial, and
        inventory-omission checks. The direct-`runc` probe passed in the VM.
        The complete launcher JSON predicate returned true. The probe
        removed its BPF pin root and lease lock.
  - [ ] Remove the reconstructed binding, policy, and identity owners after
    their remaining PreStop, administrative recovery, mount retention, and
    generation retirement consumers move to small tests.
- [ ] Kernel object upgrade: keep the second production object, manifest, map
  ID, link pin, program tag, and running-identity checks explicit.
- [ ] Post-point-of-no-return evidence and generation retirement: keep the
  terminal exec, evidence retention, holder release, and absence proof.
  - [x] Preserve the declared terminal-entry role. The existing shared fatal
    exec test keeps one worker role and does not replace the direct-`runc`
    assertion that the fatal exec selected the one termination-role admission
    rule.
  - [x] Add one small standard platform test for the declared terminal entry.
    Use `ProcessFixture::fatal_exec` and `Platform::add_actor`. Do not add a
    Platform API.
    - [x] Declare one live `PreStop` sleep entry and the fatal `PreStop` entry
      in the same termination role. Use the live entry only to identify the
      role through production admission.
    - [x] Require the fatal runtime entry to fail, retain `PostPonrFatal`, use
      the termination role, and use its own nonzero admission rule.
    - [x] Keep the test below 100 lines. The complete test file is 99 lines.
    - [x] Pass Host and commit it. The exact Host test passed in 29.15 seconds
      on 2026-09-21. The existing fatal-exec Host test passed with the extended
      policy in 28.11 seconds.
    - [x] Pass direct `runc` and commit it. The exact direct-`runc` test passed
      in 29.48 seconds on 2026-09-21.
    - [x] Pass Kubernetes and commit it. The exact Kubernetes test passed in
      69.69 seconds on 2026-09-21.
    - [x] Remove only the matching legacy terminal-status assertion and result
      field after all three platforms pass. Keep the action and pending row
      until the evidence-retention and generation-retirement test replaces
      them. The affected direct-`runc` probe passed. Its retained-evidence and
      inactive-generation assertions remained true.
  - [x] Add one small platform test for terminal evidence during generation
    retirement. Do not add a Platform API or call a test-only Node owner.
    - [x] Start PID 1 under the initial policy. Install the fatal-exec policy
      as a replacement, start one declared holder in that generation, then
      retain one `PostPonrFatal` row from its terminal entry.
    - [x] Install the next replacement policy through Control while PID 1
      and the declared entry remain live. Require a new active generation and
      the fatal-exec descriptor to enter `Retiring`.
    - [x] Stop the declared holder. Wait for the deployed Node to remove the
      old descriptor, binding activation targets, and execution-set bindings.
      Require the terminal pending-exec row to remain byte-for-byte equal.
    - [x] Put map parsing in one small generation-state assertion owner. The
      owner can read state and wait for readiness. It must not install policy,
      stop actors, or reproduce Node retirement.
    - [x] Keep the test below 100 lines. The complete test file is 59 lines.
    - [x] Pass Host and commit it. The corrected Host test passed in 41.18
      seconds on 2026-09-21.
    - [x] Pass direct `runc` and commit it. The corrected direct-`runc` test
      passed in 41.80 seconds on 2026-09-21.
    - [x] Pass Kubernetes and commit it. The corrected Kubernetes test passed
      in 87.86 seconds on 2026-09-21.
    - [x] Remove only the matching legacy terminal-retention and inactive-
      generation fields, actions, and shell assertions after all platforms
      pass. Keep unrelated mount, upgrade, and cleanup behavior. The affected
      direct-`runc` probe passed with the remaining recovery, mount, entry-role,
      upgrade, and cleanup assertions.
- [x] External entry and external cgroup entrant: keep both physical execs and
  rule-zero fail-closed evidence assertions.
  - [x] Extend the existing unlisted runtime-exec test with its exact
    `UNSUPPORTED_OBJECT`, exec-family, execute-operation, external-role,
    rule-zero, and `EACCES` evidence checks. The 75-line test passed Host in
    29.77 seconds, direct `runc` in 37.23 seconds, and Kubernetes in 76.22
    seconds.
  - [x] Add one small platform test for a host process placed in the protected
    actor cgroup. Require its restricted external identity, denied exec, and
    matching task-cookie, role, rule-zero, and `EACCES` evidence.
    - [x] Pass Host. The 75-line test passed in 31.34 seconds.
    - [x] Pass direct `runc` with the same actor and assertions. The exact test
      passed in 36.53 seconds.
    - [x] Pass Kubernetes with the same actor and assertions. The exact test
      passed in 74.90 seconds.
  - [x] Remove the matching direct-`runc` actions, result fields, and `run.sh`
    checks after all three platforms pass. The deletion removed 171 lines. The
    retained direct-`runc` probe passed. Keep the separate two-node Kubernetes
    effect-accounting check until its shared replacement passes.
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
    - [x] Reap the non-init actor before PID 1 during cleanup. Linux keeps PID
      1 in `zap_pid_ns_processes` while an unreaped sibling remains. The exact
      Host, direct-`runc`, and Kubernetes cases passed in 28.20, 28.66, and
      66.25 seconds on 2026-09-19.
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

- [x] Add a short shared-scenario recipe to `crates/mithril-e2e/README.md`.
  It names the actor, policy, Rust test, platform attribute, lifecycle, action,
  assertion, and stop owners. It corrects the old claim that shell owns all
  scenario assertions. Test discovery and the local VM harness check passed.
- [x] Show one small in-process test and one small running-container scenario.
  The exact ring-accounting test passed. The PreStop scenario passed on Host,
  direct `runc`, and Kubernetes.
- [x] State which code belongs in a fixture and which production calls must
  stay in the scenario.
- [ ] Document focused unit, local harness, lightweight VM, paired Kubernetes,
  and full repository commands.
  The README has exact Host, direct-`runc`, and Kubernetes commands, local
  harness and disposable VM commands, and repository CI. The exact direct-
  `runc` command passed with the mounted OCI hook in 57.30 seconds. Add a
  complete generated platform-matrix command when the thin launcher can run
  all lifecycle groups, not only its current selected set.

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
