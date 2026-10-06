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

### Simultaneous policy qualification

- [x] Keep two independent workloads on one Control and one Node. Use one
  platform setup. `install_policy` returns labels from the policy selector.
  `start_actor` receives those labels. Do not add a workload-selection API.
  Read recovery labels from the policy fixture without installing it early.
  Preserve existing actor, policy, and component order when updating calls.
- Remove the internal workload wrappers and context-switching methods. Do not
  retain the rejected API as a deprecated alias or private selector.
- The user permits the narrow 102–105-line recovery-file exception required
  to read policy labels before actor startup. Do not move assertions to helpers
  or change recovery order to meet the previous limit.
- [x] Install a different policy for each workload. Keep both policies, runtime
  observations, and workload targets present at the same time.
- [x] Use the same Python actor on both workloads. Ask both actors to read the
  same file. Assert denial under one policy and success under the other policy.
  Repeat the reads while both actors remain alive. Check distinct policy
  generations and bindings on the same Node.
- [x] Run the shared Rust test on Host, then runc, then real Kubernetes. Add each
  platform to the test attribute only after its focused test passes.
- [x] Verify shared fixture regressions and record the commands and results.
- Do not change production policy installation in this task. Independent
  per-policy installation is separate work after this proof passes.
- The one-actor rule permits multiple actors when the requested behavior is
  simultaneous workload isolation. Each actor has its own physical workload.

Current verification:

- The workload wrappers and selection methods are removed. The shared scenario
  is 93 lines. Existing scenario assertion counts are unchanged in 79 files.
- Host passed the simultaneous-policy proof and lifecycle-reuse check together:
  2 passed in 48.25 seconds in the replacement VM.
- runc passed the same pair: 2 passed in 139.13 seconds.
- Real Kubernetes passed the same pair: 2 passed in 125.01 seconds. The
  launcher-prepared pinned image had no conflicting manifest alias. No Node,
  Control, BPF, test assertion, or readiness deadline change was required.
- The CRI image-digest rejection was reproduced in lightweight before the
  Kubernetes rerun. Node rejected the mismatch without a runtime binding and
  accepted the restored digest: 1 passed in 41.00 seconds.
- The final Rust CI gate passed. The full physical platform matrix is not yet
  qualified for this change. See [MULTI_POLICY_REVIEW.md](MULTI_POLICY_REVIEW.md)
  for the failed attempts, retained VM, and verification limits.
- On 2026-09-26, `cargo test -p mithril-e2e --lib process::tests` passed 12
  tests. `cargo test -p mithril-e2e --lib platform::lifecycle::tests` passed two
  tests. In the retained VM, run
  `/mnt/mithril-source/target/debug/deps/mithril_e2e-2682e87779fe4fd2`
  as root with one exact test name and
  `--exact --ignored --test-threads=1`. The names are
  `platform::lifecycle_tests::lifecycle_reuses_node::identity_host`,
  `platform::lifecycle_tests::lifecycle_reuses_node::identity_runc`, and
  `platform::lifecycle_tests::lifecycle_reuses_node::identity_kubernetes`.
  Host passed in 47.70 seconds, direct `runc` in 59.09 seconds, and real
  Kubernetes in 93.67 seconds. The Kubernetes cleanup left no Mithril
  namespace or Pod. The first direct-`runc` command ran without root and
  failed to create its test cgroup; the root rerun passed without a code
  change.

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

This table lists files above 2,000 lines and below-limit runners that still
need replacement:

| Source | Current lines | Open work |
| --- | ---: | --- |
| `identity.rs` | 4,845 | Size and runner retirement |
| `effect/runc.rs` | 4,600 | Size and runner retirement |
| `platform/kubernetes.rs` | 3,253 | Size and fixture responsibility |
| `observability.rs` | 3,146 | Size and scenario simplification |
| `platform/host.rs` | 2,911 | Size and fixture responsibility |
| `discovery/data_store.rs` | 2,715 | Size and scenario simplification |
| `effect.rs` | 2,530 | Size and runner retirement |
| `effect/child.rs` | 2,435 | Size and fixture retirement |
| `platform/shared.rs` | 2,323 | Size and fixture responsibility |
| `control_tls.rs` | 976 | Runner retirement; size limit met |
| `effect/network.rs` | 1,411 | Runner retirement; size limit met |

This measurement covers `cec19dd0` in the refactoring worktree. Earlier
verification records apply only to their recorded source state.

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
- [ ] Diagnose the intermittent direct-`runc` entry startup denial. On
  2026-09-25, the first `identity_runc` run passed 49 of 50 tests. In
  `entry_roles_are_isolated`, `runc exec grep` exited before it wrote its PID.
  Its stderr said `read init: permission denied`; Node recorded one
  `MISSING_IDENTITY` Unix-stream IPC denial. The exact test then passed five
  isolated runs, and the full 50-test lifecycle passed on a repeat run.
  Keep the entry identity and denial assertions. Do not add an automatic
  retry. Identify why an exec child can reach IPC without an identity before
  this gate is called stable.
- [x] Qualify the approval readiness check on Kubernetes. A later 50-test
  direct-`runc` identity run passed the entry-role case but failed
  `approved_exec_consumes_once`: Control rejected `approve` because Node
  admission was not ready. A focused run logged transient evidence recovery
  checks after the denied exec. The test now waits for Node readiness after
  that denial and before it asks Control for approval. The denied exec,
  consumed approval, and replay checks remain. The three approval tests
  passed together on Host and direct `runc`. The approval test also passed in
  the complete 50-test Kubernetes identity lifecycle.
- [x] Reproduce a live but unresponsive Node admission endpoint in lightweight
  qualification. On 2026-09-25, `identity_kubernetes` passed 49 of 50 tests.
  `tcp_send_variants_are_allowed` failed before its actor started: the OCI
  hook returned `DENY_NODE_UNAVAILABLE` after its five-second admission
  timeout. The last captured Node logs showed `POLICY_CONVERGENCE_PENDING` for
  the prior container. K3s recorded the hook failure, and the kernel log
  showed no OOM kill in that interval. A direct-`runc` test proved the
  missing-socket fail-closed case. A separate 32-cycle direct-`runc` policy
  and actor churn check passed in 265.57 seconds, so it did not reproduce the
  live-endpoint timeout. `live_node_stall_is_closed` now delays an external CRI
  inventory response while the real Node remains live. The production
  `StageRuntimeFacts` request times out at the client. The same request
  succeeds after the delay clears. The exact privileged Host test passed
  twice in 35.76 and 35.98 seconds. The paired
  `tcp_send_variants_are_allowed::identity_kubernetes` test passed in 65.31
  seconds with unchanged assertions. The complete identity lifecycles passed
  on Host (55 tests, 572.53 seconds), direct `runc` (50 tests, 563.35 seconds),
  and Kubernetes (50 tests, 1320.75 seconds). This proves the missing timeout
  case. It does not identify the cause of the earlier Kubernetes stall.
  On 2026-10-05, the existing test passed in 38.87 seconds with the live Node,
  eight-second CRI stall, and four-second client deadline unchanged. The SDK
  sets both a gRPC deadline and an outer deadline. Accept only the two exact
  timeout results and require completion between four and five seconds.
  Keep rejection of every response during the stall, the live socket check,
  and successful admission after the stall. All five owned paths were absent.
  See `/tmp/mithril-platform-live-stall-final-20261005.log`. Production did
  not change. This result does not explain the earlier Kubernetes stall.
- [ ] Identify the intermittent live-Node admission stall. The complete
  Kubernetes identity lifecycle passed on the next run, including the earlier
  failed TCP case. Do not claim that the intermittent stall is fixed without
  evidence of its cause and a check for that cause. On 2026-09-28, a 56-case
  Kubernetes identity run passed 55 cases. `tcp_nodelay_uses_network_role`
  failed before its actor started. Node returned `POLICY_CONVERGENCE_PENDING`
  until the OCI hook deadline, then activated the target. The new lightweight
  `pending_policy_stage_is_closed` check sent an unmatched Pod through the
  live Node admission client. It proved fail-closed timeout and a later
  matched admission in 30.64 seconds. The exact Kubernetes TCP case passed
  on a 65.77-second rerun. Keep this item open: the cause of delayed target
  activation under the full lifecycle is not known.

The four private naming violations recorded in the diff from `95775f48` are
removed. The verification test is `object_allocations_are_exact`. The legacy
kernel probe uses `allowed_before`, `denied_after`, and `allowed_after`.
Public result fields retain their original names. No assertion, operation,
or result schema changes. These name changes do not retire either runner.
The focused verification test, formatting, and strict crate Clippy pass.

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
  - [x] The Host VM launcher reads lifecycle suffixes from the standard Rust
    test binary and runs each suffix in one process. The current binary has
    33 Host lifecycle names. The 32 groups outside `identity_host` passed in
    the retained VM; `identity_host` passed earlier with the same Rust source.
    Shell syntax and the VM harness self-test pass. A complete `run.sh` run
    with the new loop is still open.
  - [x] The Kubernetes VM launcher reads lifecycle suffixes from the standard
    Rust test binary and runs each suffix in one process. The current binary
    reports 32 Kubernetes lifecycle names. Shell syntax and the VM harness
    self-test pass. The complete 32-lifecycle physical run is still open.
  - [x] The direct-`runc` VM launcher uses the same suffix selection. The
    current binary has 33 direct-`runc` lifecycle names. All 33 groups passed
    with stock `runc` in the retained VM, including all 50 identity tests.
    Every group removed its pin root, cgroup, and lease. Shell syntax and the
    VM harness self-test passed. A complete `run.sh` run is still open.
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

- [x] Replace `mtls_registration_acknowledges_trust_and_reconnects_with_a_fresh_nonce`
  with `registration_renews_nonce` in `control_tls/registration.rs`. The
  38-line file uses the existing `MtlsFixture`. Both connector calls and all
  four baseline assertions remain explicit. The connector awaits registration
  and durable trust acknowledgement before returning, so the extra poll and
  its `Cell` are removed. The replacement passed in 0.04 seconds before the
  old function was removed. The Control/TLS family passed 19 tests in 25.44
  seconds; two existing release-budget tests remain ignored. The final Rust
  CI procedure passed after the last source edit. `control_tls.rs` decreases
  from 2,416 to 2,366 lines. No fixture, Platform, or production code changed.
  No physical platform matrix was rerun for this protocol-only change.
- [x] `mtls_connection_renews_the_ready_session_while_its_owner_is_idle`
  - Merge the remaining idle-renewal action into `readiness_keeps_session`.
    Reuse its ready server, Control, connector, bound Node session, and trust
    cache. Do not add a fixture or a second scenario setup.
  - Keep the initial readiness assertion, the 2.3-second idle interval, and
    the 1.5-second readiness freshness limit. Make no readiness report during
    the idle interval. Require the same complete bound session afterward.
    Require one registered nonce and an unchanged trust nonce.
  - Keep the existing explicit Ready, NotReady, and restored Ready reports
    and all their assertions unchanged. Keep normal connection and server
    shutdown. Keep the complete readiness file below 100 lines.
  - Compare with `95775f48`. Pass the strengthened exact test before removing
    the old function. Commit qualification and retirement separately. Pass
    the Control/TLS family, harness checks, and final Rust CI. This is real
    mTLS protocol coverage, not physical kernel or Kubernetes qualification.
    Do not change production or Platform code or rerun a physical matrix.
  - The 50-line readiness file passed its strengthened exact test in 2.34
    seconds before retirement. The related Control/TLS family passed 19
    tests in 11.36 seconds; two release-budget checks remain ignored.
    Formatting, strict E2E Clippy, and local VM harness checks passed.
    Qualification commit `5a718396` precedes removal of the old idle function.
    The duplicate setup and test are removed. The parent file decreases from
    1,458 to 1,433 lines; the small readiness file has 50 lines. The combined
    change removes 18 Rust lines net and one extra Control/client startup.
    Final repository Rust CI passes after the last Rust edit. Its 90
    in-process E2E tests pass. Both baseline behaviors remain in one real
    production-backed test; the lower test count is not lost coverage.
    No production, Platform, or fixture source changed. The rejected packet
    draft is absent. The packet-flow attribution decision remains open.
- [x] `mtls_connection_reports_local_readiness_transitions_without_reconnect`
  - Replace the repeated readiness assertions with `readiness_keeps_session`
    in `control_tls/readiness.rs`. Use one standard test below 100 lines.
    Reuse `MtlsFixture`, the production connector, and the trust cache. Keep
    Ready, NotReady, and restored Ready in the test. Require the bound Node
    name and one registered nonce at each stage. Also require the same
    connection nonce. Do not reconnect between readiness reports.
  - Compare with `95775f48`. Pass the exact replacement before removing the
    old function. Run related Control/TLS tests, local harness checks, and
    final Rust CI. Commit the verified replacement before the old function
    is removed. Add no fixture, Platform, or production API.
  - This case uses real mTLS gRPC and production readiness owners. It has
    no syscall, OCI runtime, or Pod action. Direct `runc` and Kubernetes
    platform cases are not applicable. Do not rerun the physical matrix.
  - The 43-line replacement passed in 0.04 seconds before legacy removal.
    The related family passed 20 tests in 25.35 seconds; two existing
    release-budget checks remain ignored. Formatting, strict E2E Clippy,
    and local VM harness checks passed. The test checks complete restored
    session equality and nonce equality in addition to every baseline
    condition. No fixture, Platform, or production source changed.
    Replacement commit `9bae626` precedes legacy removal. The old function
    and its repeated assertions are removed. Final repository Rust CI passes
    after the last Rust edit, including all 91 non-privileged E2E tests.
    The parent file decreases from 1,497 to 1,458 lines. The standalone
    replacement has 43 lines and adds explicit session and nonce checks.
    The remaining outage, throughput, and custom runner inventory stays open.
- [x] Replace `control_evidence_queue_reclaims_only_durably_consumed_segments`
  with `consumption_reclaims_segments` in `control_tls/retention.rs`.
  - Use one standard Rust test below 100 lines. Reuse the existing WAL fixture
    and production batch conversion. Remove manual protobuf length and CRC
    framing. Keep production intake and consumption calls in the test.
  - Keep the two-record Block limit and one retained segment. Reject cursor 3
    before consumption and after consumption at cursor 1. Keep the segment
    until cursor 2 is consumed. Then require reclamation, acceptance of cursor
    3, one retained record, and one new segment.
  - Keep the bounded store-lease readiness fix. Reopen the same store and
    require durable consumption at 2, intake at 3, and exactly one retained
    record. Add complete retained-record equality before and after reopen.
  - Compare with `95775f48`. Pass the replacement before removing the old
    function. Run the related Control/TLS tests, harness checks, and final
    Rust CI. Commit the verified replacement and retirement separately.
    This case tests public WAL, intake, retention, and store APIs. It does not
    claim physical syscall, mTLS authentication, or Kubernetes qualification.
  - The 98-line replacement passed in 0.17 seconds while the old test remained.
    The Control/TLS family passed 20 tests in 25.20 seconds; two existing
    release-budget tests remain ignored. Harness checks, formatting, and
    strict E2E Clippy passed. Commit `281200d2` adds the replacement before
    retirement. The old function and unused imports are removed after that
    qualification. `control_tls.rs` decreases from 1,598 to 1,497 lines.
    The final Rust CI procedure exited 0 after the last Rust edit. It passed
    91 in-process E2E tests and ignored 438 tests; those ignored tests are not
    physical qualification evidence. The final log is
    `/tmp/mithril-retention-final-ci-20261001.log`. No production or Platform
    source changed. No physical platform matrix was rerun.
- [x] `signed_node_decommission_uses_the_same_durable_mtls_sequence_as_kubernetes`
  - Reuse one signed input and complete Node configuration from the existing
    fixture in both HTTPS and mTLS tests. Then replace the long mTLS function
    with `decommission_keeps_durable_order`, below 100 lines. Keep prepare,
    acceptance, removal from ready sessions, quarantine, completion, and both
    durable Control states explicit. Check the complete artifact at both
    delivery stages. Commit verified inputs before the test replacement.
    The earlier TLS setup produced a 96-line function with a separate state
    wait helper. This step removes repeated stage handling and that helper.
    Keep the old test until the replacement passes. These are production
    protocol tests, not Pod tests.
  - Shared inputs pass both existing tests. The fixture signs the same
    authorization and returns its complete Node configuration. No admission,
    delivery, quarantine, or acknowledgement occurs in the fixture. Remove
    eight Rust lines net. Harness checks and final Rust CI pass. See
    `/tmp/mithril-decommission-input-{check,ci}-20261001.log`.
  - The 94-line replacement passes in 0.08 seconds before legacy removal.
    It adds exact artifact equality for execution, bounded command waits,
    last-status diagnostics, and durable Node completion. All 19 related
    Control/TLS tests, harness checks, and final Rust CI pass after removal.
    The parent file decreases from 1,052 to 954 lines. The old function and
    state wait helper are removed. No Platform or production source changes.
    Run `cargo test -p mithril-e2e --lib decommission_keeps_durable_order`.
    See `/tmp/mithril-decommission-order-{check,family,final-ci}-20261001.log`.
- [x] Replace `mtls_rejects_wrong_node_binding_and_expired_client_identity`
  with `mtls_rejects_wrong_node`, `mtls_rejects_expired_cert`, and
  `mtls_rejects_wrong_ca` in `control_tls/rejection.rs`. Each short test calls
  the production connector, requires rejection, and requires no registered
  Control nonce. The wrong-Node test also requires the exact identity-mismatch
  reason. All three focused tests and the unchanged positive registration
  test passed.
- [x] `mtls_evidence_stream_replays_after_disconnect_and_reuses_one_registered_session`
  - [x] Replace the old function with `evidence_replays_once` in
    `control_tls/replay.rs`, one standard Rust test below 100 lines. Reuse
    `MtlsFixture`, the production WAL, and the existing bounded wait. Remove
    the mutable cursor cell and manual error reconstruction. Do not add a
    fixture, Platform API, or actor-only test.
  - [x] Keep three records on two CPU sources. Send the first batch and wait
    for its durable Control cursor. Disconnect without reading or applying
    its acknowledgement. Reconnect, require the exact same WAL batch, and
    apply the production acknowledgement. Send and acknowledge the second
    source through that same connection.
  - [x] Keep distinct source IDs, two registered nonces, an empty final WAL,
    exact durable cursors, and exactly-once accepted record counts for both
    sources. Bound acknowledgement waits. Keep connection drops and normal
    server shutdown visible.
  - [x] Compare with commit `95775f48`. Pass the exact replacement before
    deleting the old function. Then pass the Control/TLS family, harness
    checks, and final Rust CI. Commit this verified protocol-only behavior
    separately. No physical platform matrix is needed because this case
    tests public WAL and mTLS APIs, not a kernel, OCI, or Pod operation.
  - The replacement file has 96 lines. The exact test passed in 0.22 seconds
    before the old function was removed. The Control/TLS family passed 19
    tests in 11.39 seconds; two existing release-budget tests remain ignored.
    The VM harness checks and the final repository Rust CI procedure passed.
    The final gate includes 91 passing in-process E2E tests; 429 tests remain
    ignored in that gate and are not new physical qualification evidence.
    The replacement also requires complete accepted-record equality.
    `control_tls.rs` decreases from 2,366 to 2,271 lines. No fixture, Platform,
    or production source changed. The old test is removed after qualification.
- [x] `mtls_evidence_gap_survives_control_restart_and_closes_with_one_ack`
  - [x] Replace the old function with `evidence_gap_survives_restart` in
    `control_tls/gap.rs`, one standard Rust test below 100 lines. Reuse
    `MtlsFixture` and the existing Control-store lease readiness check.
    Keep the real Control stop, store reopen, and server start in the test.
  - [x] Keep three one-record batches at cursors 1, 2, and 3. Send cursor 3
    first. Require no acknowledgement, Control cursor 0, one durable pending
    record, and three retained Node records. Bound the response wait.
  - [x] After Control restarts, require cursor 0 and the same pending record.
    Send cursors 1 and 2 as one production group. Require a cumulative
    acknowledgement at 3, Control cursor 3, and no pending Control records.
    Replay all three batches and require the same acknowledgement. Apply the
    received acknowledgement to the WAL. Require three accepted records and
    no retained Node records. Keep normal connection and server shutdown.
  - [x] Compare with `95775f48`. Pass the exact replacement before deleting
    the old function. Pass the Control/TLS family, harness checks, and final
    Rust CI. Commit this protocol-only replacement separately. Do not change
    production code or rerun an unrelated physical platform matrix.
  - The replacement file has 99 lines. Its final exact run passed in 0.20
    seconds before the old function was removed. The Control/TLS family
    passed 19 tests in 25.47 seconds; two existing release-budget tests remain
    ignored. The VM harness checks and final repository Rust CI passed.
    The final gate passed 91 in-process E2E tests and ignored 429 tests; the
    ignored tests are not new physical qualification evidence.
    `control_tls.rs` decreases from 2,271 to 2,172 lines. The test replaces
    parallel initial/reopened handles with one local ownership block and
    repeated group-response code with one explicit two-group loop. Both
    server lifetimes, the durable gap, and the received acknowledgements
    remain visible. No fixture, Platform, or production source changed.
- [x] `mtls_storage_failure_withholds_ack_until_replay_is_durable`
  - [x] Replace the old function with `storage_failure_keeps_evidence` in
    `control_tls/storage.rs`, one standard Rust test below 100 lines. Reuse
    `MtlsFixture` and the existing bounded Control-store lease wait. Use
    complete capacity values instead of a local limit factory. Keep all
    filesystem changes and both Control server lifetimes visible.
  - [x] Keep two actual WAL records. Replace the Control store directory
    with a file. Require the public store open to fail and both Node records
    to remain. Restore the same directory before starting Control.
  - [x] Start Control with a one-record Block limit. Upload both records
    through the production client. Require no acknowledgement, no Control
    cursor, and both retained Node records. Bound the response wait. Require
    the WAL batch to remain unchanged after both failures.
  - [x] Stop Control and reopen its durable store with the original ten-record
    limit. Replay the same group. Require the received acknowledgement at
    cursor 2, exactly two accepted records, one Control evidence cursor, and
    an empty Node WAL after applying the production acknowledgement.
  - [x] Compare with `95775f48`. Pass the exact replacement before deleting
    the old function. Pass the Control/TLS family, harness checks, and final
    repository Rust CI. Commit this protocol-only replacement separately.
    Do not change production or Platform code or rerun a physical matrix.
  - The replacement file has 95 lines. Its final exact run passed in 0.22
    seconds before the old function was removed. The Control/TLS family
    passed 19 tests in 25.46 seconds; two existing release-budget tests remain
    ignored. The VM harness checks and final repository Rust CI passed.
    The final gate passed 91 in-process E2E tests and ignored 429 tests; the
    ignored tests are not new physical qualification evidence.
    `control_tls.rs` decreases from 2,172 to 2,075 lines. The explicit
    capacity loop removes repeated server and connection setup. Both fault
    conditions, response checks, and server shutdown calls remain visible.
    Exact WAL-batch equality and complete accepted-record equality are added.
    No fixture, Platform, or production source changed.
- [x] `kubernetes_outage_mtls_session_converges_policy_while_replaying_retained_evidence`
  - [x] Preserve the connection-failure diagnostic in the existing
    `ControlServerFixture::connect` operation. Use the production
    `NodeControlConnector`. Return the server and ready connection on success.
    On failure, stop the server and report its address, connection error, and
    server result. The existing wrong-node test keeps the certificate identity
    denial and zero registered nonces. It also requires successful cleanup in
    the returned diagnostic. All 20 Control/TLS tests pass in 26.12 seconds;
    three release-budget tests remain ignored. Commit this fixture first.
  - [x] Replace the duplicated Control lifetimes with an explicit restart
    loop in a small standard Rust test. Reuse `MtlsFixture` and
    `OutagePolicyFixture`. Keep the first ACTIVE acknowledgement, retained
    Node WAL, second candidate, complete chunk transfer, rollout counts,
    both evidence and coverage acknowledgements, exact accepted records,
    and normal shutdown. Add no production or Platform API. Run the focused
    protocol test, the complete Control/TLS family, harness checks, strict
    Clippy, and the final Rust CI gate before retiring the old function.
    `restart_converges_with_replay` has 99 lines, including its imports.
    Before: the old 241-line function repeats server, connector, policy, and
    acknowledgement setup. After: one two-start loop keeps both Control
    lifetimes, ACTIVE acknowledgements, and the outage visible. It also
    reopens the retained Node WAL. No assertion moves into a helper. The
    complete delivered bundle, chunk indices, rollout counts, exact stored
    records, coverage acknowledgement, and final WAL drain remain explicit.
    The comparison with `95775f48` keeps all meaningful assertions. The new
    test also checks both bundle transfers and the evidence cursor.
    The final Rust CI gate passes after the last source edit. The VM harness
    checks pass. No production or Platform source changes. This is mTLS
    protocol qualification, not physical Kubernetes qualification. The
    physical matrix was not rerun for this protocol-only change.
    Run the focused test with `cargo test -p mithril-e2e --lib
    control_tls::restart::restart_converges_with_replay -- --exact --nocapture`.
    Source review route:
    [restart test](src/control_tls/restart.rs) starts each Control lifetime.
    -> [ControlServerFixture](src/control_fixture.rs) owns the server and
    reports connection failure with normal server cleanup.
    -> [NodeControlConnector](../mithril-node/src/control.rs) registers the
    Node client, transfers policy chunks, and sends evidence and coverage.
    -> [ControlStore](../mithril-control/src/store.rs) retains policy status
    and exact accepted evidence across the server restart. The test owns the
    store, trust cache, and Node WAL. It closes each connection before server
    shutdown. The old function and its sole-use imports are removed.
    Gate log: `/tmp/mithril-control-restart-ci-final-20261002.log`.
  - Earlier setup evidence, before the complete replacement:
  - Reuse `MtlsFixture` for both Control instances, connectors, trust input,
    and the durable Node WAL. Remove duplicate setup. Keep both policy
    generations, retained evidence, coverage, and all assertions in the test.
    The unchanged behavior passes its focused check in 0.35 seconds. This
    setup step does not complete the remaining scenario migration.
    All 19 related Control/TLS tests, strict E2E Clippy, and harness checks
    pass. No fixture or production operation changes. Remove 31 Rust lines net.
- [x] `kubernetes_outage_partitioned_node_reconnects_to_running_control_and_replaces_predecessor`
  - [x] Replace its two protocol behaviors with small standard tests in
    `control_tls/partition.rs`. Keep policy replacement and durable evidence
    replay in one test. Keep the final-priority-release race in a separate
    real mTLS test. Both tests must block Node-to-Control traffic, require the
    first session to close, and reconnect to the same running Control.
    Reuse `MtlsFixture`, `OutagePolicyFixture`, and `TcpBlackholeOwner`.
    Add no scenario or platform API. Keep each test body below 100 lines.
    Preserve the 500 ms race limit, exact acknowledgements, rescue diagnostic,
    and normal shutdown. Keep the old function until both replacements pass.
    The bodies have 88 and 97 lines. Both focused tests pass in 25.24 seconds;
    all 21 related Control/TLS tests pass in 25.38 seconds. Strict crate Clippy,
    formatting, and VM harness checks pass. No fixture, platform, or production
    source changes. These are mTLS protocol cases, not container scenarios.
    Run `cargo test -p mithril-e2e --lib control_tls::partition::`.
  - [x] Commit the replacements before removing the old function. The final
    focused run passes in 25.71 seconds. Retirement removes 199 Rust lines net
    from `control_tls.rs`; unrelated scenarios remain. All 92 local E2E tests
    and the final repository Rust CI gate pass after removal. An unchanged
    Control logging test failed once, then passed alone and with all 116
    Control tests. No production change or full physical matrix was required.
  - Previous one-test design: replace the 196-line legacy function with one
    standard protocol test.
    Reuse the TLS, policy, TCP blackhole, WAL, and trust owners. Keep the
    first Active policy, Node-to-Control packet loss, replacement policy,
    forced disconnect, reconnect, retained evidence acknowledgement, and
    current coverage interval explicit.
  - Preserve the real store-priority wait. Release the last priority
    operation and require coverage completion within the existing 500 ms.
    Keep the diagnostic rescue operation and require that rescue was not
    needed. Keep exact coverage acknowledgement, replacement candidate,
    and normal proxy and Control shutdown checks.
  - The previous temporary source prototype has 138 lines after formatting.
    It reuses
    the WAL fixture and keeps all production calls and security assertions
    in the test. No scenario helper hides the sequence. The prototype has
    not been compiled or executed. It is not in the crate. A one-time size
    exception is required before implementation. Do not delete the old test
    or mark this row complete. This is a real mTLS protocol test; physical
    container and Kubernetes platform cases are not applicable.
- [x] `kubernetes_outage_retained_evidence_allows_protected_pod_admission`
  - [x] Replace the old function with `admission_keeps_retained_evidence` in
    `control_tls/admission.rs`, one standard Rust test below 100 lines. Reuse
    the verified TLS, WAL, policy, and ready HTTPS fixtures. Do not add an owner
    or put admission actions and assertions in a helper.
  - [x] Keep the original event, historical Node identity, retained evidence,
    no allowed Node identities, complete empty workload inventory, policy
    source, Pod request, TLS, and request bounds. Do not add a live Node.
  - [x] Keep successful HTTP status, matching response UID, Allow, and the
    non-empty patch. Require one durable evidence cursor and an unchanged,
    still-pending Node WAL batch after admission. Keep normal shutdown visible.
  - [x] Compare with `95775f48`. Pass the exact replacement before removing
    the old function. Pass related Control/TLS cases, harness checks, and final
    Rust CI. Commit separately. This is real HTTPS with an external Kubernetes
    API fixture, not physical scheduling, runtime admission, or kernel proof.
    Do not change production or Platform code or rerun an unrelated matrix.
    The complete replacement file has 98 lines. Its exact test passed in
    0.65 seconds before legacy removal. The related Control/TLS run passed
    19 tests in 25.94 seconds, with two existing ignored release budgets.
    That run reported two parent imports made unused by the removal. Both
    imports were removed before the final Rust CI gate. Harness checks passed.
    Final Rust CI exited with status 0 after the last Rust edit. Its E2E run
    passed 91 tests in 28.81 seconds, with 429 existing ignored tests. These
    ignored tests are not physical qualification evidence.
    `control_tls.rs` decreases from 1,679 to 1,598 lines. The test reuses the
    previously verified ready HTTPS constructor. Temporary batch conversion,
    intake, address, and CA variables are removed. All baseline conditions
    and assertions remain visible. The receipt cursor and retained-batch
    assertions are added. No production, Platform, or shared fixture changed.
- [x] `node_decommission_https_accepts_the_same_signed_artifact_as_control`
  - [x] Add one ready HTTPS constructor on the existing
    `ControlServerFixture`. Accept the complete Kubernetes client, Control,
    policy, and Node-readiness owners. Keep the current TLS files, request
    limits, production `serve_with_client` call, bounded readiness, and
    fallible shutdown. Do not put requests, policy delivery, or assertions
    in this constructor. Replace both repeated HTTPS startup blocks, verify
    their existing exact tests and related checks, and commit tooling first.
    Both original exact tests passed: HTTPS decommission in 0.05 seconds and
    retained-evidence admission in 0.20 seconds. Harness checks passed.
    The final Rust CI gate exited with status 0. Its E2E run passed 91 tests
    in 28.76 seconds, including all 19 active Control/TLS tests, with 429
    existing ignored tests. These results are not physical Kubernetes proof.
    The shared fixture has 375 lines. `control_tls.rs` decreases from 1,798
    to 1,757 lines. Scenario actions, assertions, and shutdown order did not
    change. Tooling was committed separately as `e40bcd1e` before the scenario.
  - [x] Replace the old function with `https_decommission_keeps_status` in
    `control_tls/decommission.rs`, one standard Rust test below 100 lines.
    Keep the live authenticated Node connection, boot ID, signer, nonce,
    signed artifact, HTTP content type, and original component order.
    Reuse one endpoint instead of repeating URL construction.
  - [x] Keep HTTP 202 and Submitted state for the signed POST, HTTP 200 for
    status GET, and complete status equality. Require the returned digest
    to match the submitted artifact. Keep HTTPS shutdown, connection close,
    and gRPC shutdown visible in that order. Do not claim kernel retirement.
  - [x] Compare with `95775f48`. Pass the exact replacement before deleting
    the old function. Pass the Control/TLS family, harness checks, and final
    Rust CI. Commit the scenario separately from tooling. This case uses
    real production HTTPS and gRPC services with an external Kubernetes API
    fixture. Do not count it as physical Kubernetes qualification or change
    production or Platform code.
    The complete replacement file has 88 lines. Its exact test passed in
    0.06 seconds before the old function was removed. The related Control/TLS
    run passed 19 tests in 21.46 seconds, with two existing ignored budgets.
    Harness checks passed. Final Rust CI exited with status 0 after the last
    Rust edit; its E2E run passed 91 tests in 29.18 seconds, with 429 existing
    ignored tests. `control_tls.rs` decreases from 1,757 to 1,679 lines.
    One endpoint serves both requests. The signed artifact and all original
    assertions stay in the test; exact artifact-digest equality is added.
    This case does not prove Node command execution or kernel retirement.
    Other legacy cases remain open. No production or Platform code changed.
- [x] `mtls_evidence_stream_retains_every_record_across_node_restart_beyond_the_soft_bound`
  - [x] Replace the old function with `retained_wal_survives_restart` in
    `control_tls/retained.rs`, one standard Rust test below 100 lines. Reuse
    `MtlsFixture` and public WAL, client, and intake operations. Remove the
    mutable source tracker and unbounded acknowledgement loop. Keep the real
    WAL drop and reopen visible. Do not claim a Node daemon restart.
  - [x] Keep the Retain policy, three-record soft limit, and 4,096-record batch
    limit. Write two records before restart. Require two pending records after
    reopening the same durable path. Then write records 3 through 303 and
    require all 303 to remain pending. Require the final batch's first two
    decoded records to equal the retained records from before restart.
  - [x] Require one complete 303-record group and the same source identity.
    Upload that group through the production client. Bound the response wait.
    Require the received cumulative acknowledgement at 303, an empty WAL
    after applying that acknowledgement, one registered nonce, Control cursor
    303, and exactly 303 accepted records. Keep normal shutdown visible.
  - [x] Compare with `95775f48`. Pass the exact replacement before deleting
    the old function. Pass the Control/TLS family, harness checks, and final
    Rust CI. Commit this protocol-only replacement separately. Do not change
    production or Platform code or rerun an unrelated physical matrix.
    Qualification: the 93-line replacement passed its exact check in 0.80
    seconds before the old function was removed. The Control/TLS family
    passed 19 tests in 25.43 seconds, with two existing ignored budgets.
    Harness checks passed. The final Rust CI gate exited with status 0;
    its E2E run passed 91 tests in 28.83 seconds, with 429 existing ignored
    tests. These ignored tests are not new physical qualification evidence.
    The first draft prepared a two-record in-flight batch immediately after
    reopening the WAL. That extra call changed the baseline order. It was
    removed; the final batch is prepared only after all 303 records exist.
    Complete-record equality and the retained-prefix check are added.
    `control_tls.rs` decreases from 2,075 to 1,986 lines. Its other legacy
    scenarios remain open. No fixture, Platform, or production source changed.
- [x] `mtls_evidence_backlog_exceeds_the_previous_baseline`
  - [x] Let `MtlsFixture` own a supplied temporary directory. Reuse its
    existing certificate, Control, WAL, and connector operations in the
    unchanged budget. Keep the original target filesystem and all workload,
    timing, cursor, acknowledgement, and throughput assertions. Verify the
    release budget and related TLS cases before committing this tooling.
    This step removes repeated setup. It does not complete the scenario
    migration or permit a test above the 100-line limit.
  - [x] Reuse `MtlsFixture` for TLS, Control, connector, and WAL setup. Keep
    the fixture on the original target filesystem. Keep 4,096 records per
    batch, more than 512 MiB of acknowledged protobuf payload, the production
    batch and group limits, and the 107.1 MiB/s release threshold.
    Qualification: the unchanged release budget passed on 2026-10-01 in
    14.66 seconds. It durably acknowledged 536,989,928 bytes through five
    cumulative receipts at 143.4 MiB/s. The related Control/TLS run passed
    19 tests in 29.75 seconds, with two existing ignored budgets. Harness
    checks and the final repository Rust CI procedure exited with status 0.
    The setup change removes 24 Rust lines net. `control_tls.rs` now has
    1,265 lines. The original budget still exceeds 100 lines; its scenario
    migration remains open. No Platform or production source changed.
  - [x] Give the existing raw gRPC transfer fixture one lifecycle owner.
    Bind the listener before server startup. Replace the fixed readiness
    sleep with the bound listener. Keep complete transfer, durable sync,
    captured errors, bounded operations, and explicit shutdown.
    `GrpcTransfer` now owns that operation in `control_tls/transfer.rs`.
    The legacy budget uses the owner without changing its workload or
    assertions. Its 32-line focused fixture check passed in 0.27 seconds.
    The Control/TLS family passed 19 tests in 29.42 seconds, with the two
    existing performance budgets ignored. Local VM harness checks passed.
    The final repository Rust CI procedure exited with status 0 on
    2026-10-01. These checks do not qualify the release throughput budget.
    No production, Platform, Cargo, or protobuf schema changed.
    The unchanged release backlog case then passed on 2026-10-01 in
    14.96 seconds. It durably acknowledged 536,989,928 protobuf bytes
    through five cumulative group receipts at 134.9 MiB/s. The original
    107.1 MiB/s assertion passed. Raw transfer measured 571.0 MiB/s;
    synchronized raw-file transfer measured 418.5 MiB/s; direct intake
    measured 169.6 MiB/s. See
    `/tmp/mithril-backlog-baseline-release-20261001.log`. The first release
    build took 5 minutes 31 seconds; the retained build supports the next
    focused check. This proves the existing budget with the new transfer
    owner. It does not complete the pending scenario simplification.
  - [x] Keep raw, durable raw, direct intake, preparation, enqueue, and
    acknowledgement measurements. Keep the direct-source cursor, exactly
    one cumulative acknowledgement per group, complete source identity,
    zero pending records, and normal Control shutdown explicit.
    - [x] Reuse `MtlsFixture::effect_batch` for the original 4,096-record
      input. Keep all upload, group, acknowledgement, and timing operations
      in the test. The unchanged release case passes in 15.19 seconds at
      127.0 MiB/s, above 107.1 MiB/s. It acknowledges 536,989,928 bytes
      through five receipts. See
      `/tmp/mithril-backlog-input-release-20261001.log`. This shared input
      step does not complete the scenario migration. Local harness checks
      and the final repository Rust CI gate pass.
    - [x] Replace the direct-intake block with `direct_intake_commits_group`
      in `control_tls/intake_budget.rs`, a 65-line standard Rust test. Keep
      the original maximum commit group, 4,096 records per batch, source
      `[9; 16]`, authenticated Node identity, timing, and cumulative cursor.
      Also require the durable cursor, no pending records, and every complete
      accepted record. The release case passes in 10.39 seconds; measured
      intake is 165.8 MiB/s. Remove only the matching old block after this
      pass. See `/tmp/mithril-intake-budget-release-20261001.log`.
      The remaining release upload budget passes in 14.44 seconds at
      122.7 MiB/s with the original volume, receipts, and threshold. Local
      harness checks and the final repository Rust CI gate pass. No Platform
      or production source changes. No new physical matrix run is needed.
      Run `cargo test -p mithril-e2e --lib --release
      control_tls::intake_budget::direct_intake_commits_group -- --exact --ignored --nocapture`.
  - [x] Keep the standard test below 100 lines. Do not move upload or
    acknowledgement sequencing into a helper. Compare with `95775f48` and
    run the exact ignored test with release optimization before retirement.
    Retain the original case until that replacement passes.
    `backlog_beats_previous_budget` in `control_tls/backlog.rs` has 94 lines.
    Reuse the existing TLS and transfer owners. Replace manual cursor state
    and acknowledgement loops with contiguous groups and one complete
    cumulative receipt per group. Keep upload, readback, measurements, and
    shutdown in the test. Bound upload and acknowledgement waits. Require
    the complete source's durable cursor and zero pending records.
    The release case passes in 14.06 seconds at 126.4 MiB/s. It transfers and
    acknowledges 536,989,928 bytes through five group receipts. The original
    107.1 MiB/s assertion remains. Raw transfer is 510.0 MiB/s; synchronized
    raw transfer is 390.1 MiB/s. See
    `/tmp/mithril-backlog-migration-release-20261001.log`. Remove only the
    matched old function and unused imports after this pass. `control_tls.rs`
    decreases from 1,265 to 1,107 lines across these two behavior replacements.
    The separate direct-intake test retains its original measurement and
    adds complete-record readback. No Platform or production source changes.
    Run `cargo test -p mithril-e2e --lib --release
    control_tls::backlog::backlog_beats_previous_budget -- --exact --ignored --nocapture`.
  - [x] Commit verified shared tooling before the scenario. Then pass related
    Control/TLS tests, harness checks, and final Rust CI. This is protocol
    qualification, not physical Host, runc, or Kubernetes qualification.
    Local harness checks and the final repository Rust CI gate pass after
    retirement. The old exact command in README is not current; use the
    two replacement commands above. Keep progress updates in this TODO.
- [x] `mtls_coverage_upload_preserves_gap_truth_at_control`
  - [x] Replace the old function with `coverage_upload_keeps_truth` in
    `control_tls/coverage.rs`, one standard Rust test below 100 lines. Reuse
    `MtlsFixture::wal` and public coverage upload and intake operations.
    Remove duplicate ABI event literals, manual canonicalizer setup, and the
    parallel acknowledgement vector. Keep upload, acknowledgement, durable
    readback, and normal server shutdown visible in one source loop.
  - [x] Keep CPU 0 at sequence 2 with task cookie 7 and CPU 1 at sequence 3
    with task cookie 8. Keep two current source intervals and two matching
    acknowledgements. These initial sources have Unknown coverage because
    no kernel health sample establishes complete coverage. Do not invent a
    sequence-gap reason or promote either source to Healthy.
  - [x] Require distinct source identities and no negative-claim eligibility.
    Compare each complete persisted report: source, CPU, epoch, revision,
    interval identity, state, sequence bounds, opening counters, absent
    closing counters, and empty gap reasons. Keep the original one-current-
    interval and not-Healthy assertions. Bound both response waits and report
    the operation, CPU, and resource path on timeout.
  - [x] Compare with `95775f48`. Pass the exact replacement before deleting
    the old function. Pass the Control/TLS family, harness checks, and final
    Rust CI. Commit this protocol-only replacement separately. No physical
    platform matrix is needed; the case does not depend on kernel hooks,
    OCI runtime behavior, or Kubernetes. Do not change production or fixtures.
    Qualification: the 99-line replacement passed its final exact check in
    0.19 seconds before the old function was removed. The Control/TLS family
    passed 19 tests in 25.46 seconds, with two existing ignored budgets.
    VM harness checks passed. The final Rust CI gate exited with status 0;
    its E2E run passed 91 tests in 28.52 seconds, with 429 existing ignored
    tests. The ignored tests are not physical qualification evidence.
    The replacement removes the manual canonicalizer, duplicate event
    literals, and parallel acknowledgement vector. One explicit source loop
    performs upload, confirmation, and complete durable readback. All original
    current-interval and not-Healthy checks remain. Exact Unknown state,
    complete report equality, distinct sources, and negative-claim checks
    are added. `control_tls.rs` decreases from 1,986 to 1,899 lines. Its
    remaining legacy scenarios stay open. No fixture, Platform, or production
    source changed.
- [x] `mtls_administrative_services_route_matching_results_and_cancel_waiters`
  - [x] Replace the old function with `admin_services_keep_requests` in
    `control_tls/administrative.rs`, one standard Rust test below 100 lines.
    Reuse `MtlsFixture`. Use the existing async join primitive for the normal
    Control request and Node-client response. Remove detached normal tasks
    and their extra Control handles. Do not add a helper or Platform API.
  - [x] Keep one ready authenticated connection and the order: resolve ID 1,
    arm ID 2, then cancel resolve ID 3. Require the correct service, exact
    request ID, and complete matching result for each normal operation.
  - [x] Receive the final resolve request, then cancel its requester.
    Drop the pending request future before sending the late response. Require
    the typed production gRPC Cancelled error from the closed waiter. Do not
    accept an unrelated stream or infrastructure failure as proof.
  - [x] Bound each request/response and cancellation wait. Include its
    operation and resource path on timeout. Keep connection close and normal
    server shutdown visible. Compare all assertions with `95775f48`.
  - [x] Pass the exact replacement before deleting the old function. Then
    pass the Control/TLS family, harness checks, and final Rust CI. Commit this
    protocol-only replacement separately. The case tests real authenticated
    service routing, not kernel, OCI, or Kubernetes operations. Do not change
    production or fixtures or run an unrelated physical platform matrix.
    Qualification: the 99-line replacement passed its final exact check in
    0.03 seconds before the old function was removed. The Control/TLS family
    passed 19 tests in 25.45 seconds, with two existing ignored budgets.
    VM harness checks passed. The final Rust CI gate exited with status 0;
    its E2E run passed 91 tests in 28.57 seconds, with 429 existing ignored
    tests. These ignored tests are not new physical qualification evidence.
    Two normal joins and one explicit cancellation select replace all three
    detached requester tasks. The resolve request and confirmed response are
    reused with the last request ID. All original service and complete-result
    checks remain. Exact request IDs, bounded complete exchanges, and the
    typed cancellation status and reason are added. No assertion helper,
    fixture, Platform, or production source is added or changed.
    `control_tls.rs` decreases from 1,899 to 1,798 lines. Its remaining
    legacy scenarios stay open.

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
  `CloneIntoCgroupFixture::wait_root` now uses the shared bounded wait. Its
  owner check and all six production-backed clone scenarios passed in the
  retained VM. Other native waits remain.
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
  - [x] Replace the remaining Rust-fixture first-open control with a shared
    Python actor and `ProcessFixture`. Start Control, Node, and the signed
    external-read policy first. Create the root with `CLONE_INTO_CGROUP`, not
    a later cgroup attach. Hold the root before its first file open. Keep
    creator-free restricted identity, nonzero role, runnable coordinate,
    successful open, and normal cleanup. Require fresh attributed Node Allow
    evidence. Keep the test below 100 lines. Pass Host before adding another
    applicable platform. Add no Platform API or production change. Remove
    only the matching old case and fixture method after qualification.
    - [x] Pass `clone_open::root_first_open_allowed` on Host, direct `runc`,
      and real Kubernetes in 28.65, 28.68, and 77.80 seconds. The shared test
      is 78 lines. It uses `ProcessFixture::group_path` on all three platforms.
      No Platform API, implementation, policy fixture, or production change.
    - [x] Preserve the baseline `95775f48:2220–2250` placement control. Keep
      its restricted creator-free identity, runnable coordinate, first-open
      success, and cleanup. Restore exact equality with the binding's external
      role. Add rule-zero, fresh Node result, role, and generation checks.
      This control does not test exact-object rule selection. The first trial
      wrongly required `EXACT_POLICY_ALLOW`; the runtime bootstrap path returns
      `RUNTIME_ENTRY_INFRASTRUCTURE`. Check the attributed result, not an
      invented policy-reason requirement. Production stays unchanged.
    - [x] Remove only `cgroup_fork::unmoved_first_open_allowed` and
      `CloneIntoCgroupFixture::root_first_effect_allowed`. Keep the other five
      legacy clone cases and their used fixture methods. The unchanged Host
      moved-root first-open denial passed in 29.02 seconds. The shared process
      checks passed: 14 passed, one privileged cgroup case ignored. Strict
      clippy and local VM harness checks passed.
    - Source review: [clone_open](src/identity/scenarios/clone_open.rs) starts
      Control, Node, the signed policy, and the initial actor in that order.
      -> [ProcessFixture](src/process.rs) starts and owns the Python launcher.
      -> [clone_cgroup.py](fixtures/process/clone_cgroup.py) creates the held
      root in the target cgroup before its first open, then opens and closes
      the requested file. The launcher reaps the root and reports its status.
      -> [EffectCheck](src/effect/check.rs) excludes earlier observations. The
      test checks the root's fresh File OpenRead result, role, and generation.
      -> [ProcessFixture::stop](src/process.rs) checks normal root removal
      before the initial actor and the environment stop. Drop is a fallback.
    - [x] Pass final repository Rust CI after the matched legacy deletions.
      Run `env CARGO_INCREMENTAL=0 CARGO_BUILD_JOBS=2 RUST_TEST_THREADS=2
      bash .github/scripts/verify-rust-ci.sh`. The command exited with status
      zero. The log is `/tmp/mithril-clone-first-bounded-ci-20261006.log`.
      The lightweight crate passed 159 tests; 542 physical tests were ignored.
      The three physical clone tests passed separately as recorded above.
      The first CI run exhausted disk space. Remove only generated cache and
      failed link files. An earlier retry hit an unrelated data-read deadline;
      the unchanged exact test then passed. Use two test workers for the final
      complete CI run. Do not change its assertions or deadline.
  - [ ] Replace the moved-root first-open denial with the existing shared
    `clone_cgroup.py` actor and `ProcessFixture`. Keep the root's exact binding
    role, creator-free restricted identity, and runnable state before movement.
    Move the root with the existing `move_task` API. Keep identity stable,
    require `FailClosedUnknown`, and check both placement-mismatch increases.
    Require the actual first open to return `EACCES`. Check normal process
    removal. Keep one test file below 100 lines. Qualify Host, direct `runc`,
    and Kubernetes before removing the old case, its first-open methods, and
    its unused root-open branch. Keep the other clone cases. Add no Platform
    API, actor change, policy change, or production change.
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
  - [x] Retire the separate legacy administrative-recovery block. Add only
    the three missing public binding assertions to `workload_recovers`: the
    recovered exec cookie is zero, the initial host TGID is the actor PID,
    and the bootstrap state is zero. Pass the unchanged recovery operation on
    Host, direct `runc`, and Kubernetes. Then remove the legacy block, result
    field, and shell gate. Keep the later restart behavior intact.
    - [x] Host passed in 28.66 seconds on 2026-09-29.
    - [x] Direct `runc` passed in 29.70 seconds on 2026-09-29.
    - [x] Kubernetes passed in 62.67 seconds on 2026-09-29.
    - [x] Remove the legacy block, result field, and shell gate. This removed
      314 lines. The reduced direct-`runc` probe and its complete result
      predicate passed on 2026-09-29.
    - [x] Retire the coupled retained-mount-view flag. The old flag performed
      no production action after source exit. It only inspected the internal
      policy owner after the administrative block populated a handle. Keep the
      exact owner lifetime test and the existing platform alias and cache
      enforcement tests. Remove the test-only result. The exact owner test and
      the reduced direct-`runc` probe passed on 2026-09-29.
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

- [x] Replace the rejected file-gate draft with a shared Platform test below
  100 lines. Start real Control and Node. Control signs each policy, and Node
  installs it through its production policy path. Use the existing Python
  actor to prove allow, deny, clear, and deny on one running process. Check
  physical results, attributed evidence, active signed generations, and normal
  cleanup. Do not load BPF or change policy maps in the test. Qualify Host,
  then runc, then Kubernetes. The loader draft is preserved in stash
  `ff88972e1f4d98c08ec7ed60ff9b489633c43c57`; it is not a deliverable.
  The loader migration proposal and results below are historical. They do
  not authorize the new scenario to bypass Node or claim benchmark coverage.
  `signed_file_gate_changes` is 99 lines. Host passed in 59.52 seconds, runc
  passed in 76.45 seconds, and Kubernetes passed in 116.66 seconds. All three
  commands completed normal cleanup. See
  `/tmp/mithril-file-gate-node-final-host-20261004.log`,
  `/tmp/mithril-file-gate-node-final-runc-20261004.log`, and
  `/tmp/mithril-file-gate-node-kube-20261004.log`.
  The task birth generation stays unchanged. Fresh evidence must match the
  process active generation. Four distinct generation handles and increasing
  signed owner versions remain required. The final repository Rust CI passed:
  95 E2E library tests passed, 507 physical cases were ignored, and all 255
  Node library tests passed. See
  `/tmp/mithril-file-gate-node-final-ci-20261004.log`. VM harness checks passed.
  Review the production path in this order:
  [test](src/identity/scenarios/file_gate.rs)
    -> [Platform policy installation](src/platform/shared.rs)
    -> [Node policy installation](../mithril-node/src/policy.rs)
    -> [actor read](fixtures/process/read_path.py)
    -> [fresh evidence](src/effect/check.rs) and
       [generation readback](src/identity/scenarios/generation_state.rs).
  Run this test through the existing physical launcher. Select the exact
  `identity::scenarios::file_gate::signed_file_gate_changes::identity_host`,
  `identity_runc`, or `identity_kubernetes` case with
  `--exact --ignored --nocapture --test-threads=1`.
- [ ] `KernelQualificationRunner::physical_file_open_probe`: own the lease
  and output paths with existing cleanup owners. Keep
  `BpfQualificationLoader` attachment and shutdown explicit.
  - [ ] Replace the custom physical probe with one standard Host test below
    100 lines. Reuse the loader, prebuilt object record, capability matrix,
    output schema, and temporary resource owners. Keep the exact same object
    as the protected benchmark. Infrastructure supplies its path.
  - [ ] Preserve the real allow, inode-target deny with `EACCES`, target
    clear, and restored allow. Keep exact map readback, live map/link
    readback, decommission, absent pins, a readable target after decommission,
    and target/lease cleanup. Require a live denial again before decommission
    so the final allow proves removal of an active decision.
  - [ ] Keep the evidence digest, standard-test executable digest, object
    layout, link IDs, capability records, and public JSON schema. Write the
    existing report only after normal cleanup. Keep result serialization
    separate from actor actions and assertions.
  - [ ] Pass the exact privileged Host case, report recorder, related loader
    and capability checks, harness checks, and final repository Rust CI.
  - [ ] Commit the verified test before removing the old probe, private
    cleanup wrapper, and `physical-probe` CLI branch. Replace the one VM
    launcher call with the existing Host lifecycle invocation. Supply the
    prepared object path to that invocation. Collect the report from the
    lifecycle output and identify the standard-test executable as its
    producer. Keep benchmarks and the strict report recorder. Do not add a
    second shell-owned scenario.
  - Current result, 2026-10-01: the standard Host draft compiles and keeps the
    security checks explicit. The real allow, deny, clear, restored allow,
    and second active deny pass. Production `KernelHost::decommission`
    returns `ManifestMismatch` during its immediate global map-ID check.
    Three focused runs reach the same failure. In the diagnostic run, owned
    map IDs `4572`, `4573`, and `4574` remain visible after that return. They
    disappear within 250 milliseconds while the same test process is alive.
    Linux releases program map references through deferred work after a
    grace period. See the
    [Linux program cleanup](https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/core.c#L2552-L2641)
    and
    [Linux program reference cleanup](https://github.com/torvalds/linux/blob/v6.8/kernel/bpf/syscall.c#L2021-L2080).
    The diagnostic still returns the original error; it does not turn the
    failed test into a pass. Temporary diagnostic output and the diagnostic
    sleep are removed from the draft. No production code changed.
    Pin, lease, and cgroup paths are absent after the failed runs. The old
    probe also places pins below its output directory; the ordinary
    `/var/tmp` output is not bpffs and fails before the security actions.
    Keep the old runner until the replacement and recorder pass. A narrow
    production-owner correction requires user approval. Do not add retries,
    sleeps, or a second cleanup sequence to the scenario.
    The unchanged Host draft failed at the same decommission readback on
    2026-10-04 in 12.38 seconds. See
    `/tmp/mithril-file-gate-audit-host-20261004.log`. Keep this draft
    unqualified. No production code or assertion changed.
    A fresh run passed in 71.79 seconds. The final artifact-bound run then
    failed the same exact map-absence check in 12.97 seconds. See
    `/tmp/mithril-file-gate-final-host-20261004.log`. This is an intermittent
    owner cleanup failure, not a qualified deliverable. Keep the scenario
    unchanged. A separate owner correction needs approval.
    On 2026-10-04, the user required production to stay unchanged. Source
    review found no retained BPF descriptor in the test. The loader, object
    layout, link records, map reader, and cleanup wrappers retain paths or
    metadata only. The exact decommission contract exists in baseline
    `95775f48`. Keep the test unqualified. Do not conceal the owner failure
    with a scenario delay, retry, or accepted error.
- [x] `HostLifecycleRunner::host_lifecycle`: own the pin root and lease, use
  readiness diagnostics, and keep both `KernelHostOwner` starts and the
  concurrent-owner rejection explicit.
  - [x] Replace the runner with `clean_host_restarts`, one standard Host test
    below 100 lines. Reuse the compiler, worker fixture, platform paths, and
    cleanup owners. Keep the qualification object and public kernel owner.
    Require an initially absent pin root, ready manifests, every pinned map
    and link, exact `LeaseOwned` rejection, pin absence after each shutdown,
    successful restart, and the unchanged worker digest. Do not substitute
    retained identity-map recovery for clean qualification-object restart.
    Qualification startup checks a populated pin root before the lease.
    Require `StalePinRoot` for the same live root. Use an unpinned contender
    with the same lease for the independent exact `LeaseOwned` assertion.
    Verify the first live manifest after both rejected starts.
  - [x] Pass the exact privileged Host test and final repository Rust CI.
    The 71-line test passed in 26.50 seconds on 2026-10-01. All original
    ready, pin, clean shutdown, restart, lease, and worker digest assertions
    remain explicit. The same-root attempt returns `StalePinRoot` before
    lease acquisition. The independent unpinned attempt returns `LeaseOwned`.
    Both rejected starts preserve the first live manifest. Pin, lease, and
    cgroup cleanup and the final repository Rust CI pass. No production or
    Platform code changed. This kernel-only test applies to Host; do not add
    container platform cases that do not test a container operation.
    The unchanged retained-map recovery test passed in 49.56 seconds with
    its own pin, lease, and cgroup cleanup.
  - [x] Keep clean kernel startup in the `kernel_start` lifecycle. The other
    physical identity cases retain Node pins, so they cannot supply its
    required empty root. Keep the body and every assertion unchanged. The
    corrected exact Host case passes in 26.47 seconds with pin, lease, and
    cgroup cleanup. The final repository Rust CI gate passes. See
    `/tmp/mithril-kernel-start-host-20261001.log`.
  - [x] Remove only the verified legacy lifecycle runner, result bundle,
    binary, and Cargo registration. Replace its manual command with the exact
    standard Rust test. Keep the other kernel qualification operations.
    The replacement is committed as `3f71d642`. Retirement removes 187 Rust
    lines net and four Cargo lines. The old bundle, runner, CLI, boot-ID
    helper, and unused error wrapper are removed. The two remaining wrapper
    callers use existing Snafu context. The other kernel qualification
    operations are unchanged. VM harness behavior checks and final repository
    Rust CI pass after the last Rust edit. The scenario body is unchanged
    from its verified commit. No full physical matrix rerun is required for
    this matched deletion. `runner.rs` now has 711 lines. The other large
    legacy runners remain incomplete.

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
- [x] Replace the excessive-use request block in
  `harness/vm/two-node-convergence.sh` with `excess_uses_are_rejected`.
  Baseline `95775f48` requests two uses against a one-use grant and requires
  the exception CRD state `Failed`. Keep that rejection. Use the existing
  `exception` lifecycle, actor, policy, and installation API. Keep the shared
  test below 100 lines. Do not add a Platform API or change production code.
  - [x] Make Kubernetes exception readiness report a current-generation
    terminal `Failed` status with its actual conditions. Preserve API errors
    and the bounded timeout. A timeout is not a rejected request.
    The existing five Kubernetes exception cases passed together in 208.84
    seconds. Generic process checks passed 14 tests with one privileged case
    ignored. The fixture-path test, VM harness checks, formatting, workspace
    build, and strict all-feature Clippy passed. The new negative request
    passed on all three platforms. No production or Platform API changed.
  - [x] Derive an owned typed request from `one_use_exception.json`. Request
    two uses of `expired-write`, whose policy limit is one. Use a distinct
    name and UID. Require the exact Control rejection or the observed
    Kubernetes `Failed` and `ReconcileRejected` status. Require no new kernel
    authority or receipt row from the rejected request.
  - [x] Use `exception.py` in single mode. Require the ungranted write to
    return `EACCES`. Submit a valid one-use request as a control. Require one
    success and then `EACCES`. Match fresh File/OpenWrite evidence to the
    same task, role, entry, generation, and protected path atom.
  - [x] Pass Host and commit it. The first 89-line shared test passed in
    39.51 seconds. Output, pin, lease, and cgroup cleanup passed. The
    all-feature workspace build and formatting passed. Strict Clippy rejected
    `expect_err`; the fallible-match correction then passed strict Clippy
    and the exact Host case in 30.30 seconds. The current shared file is 90
    lines. Cleanup passed again. No policy, actor, production implementation,
    or readiness deadline changed.
  - [x] Pass direct runc and commit its registration. The same 90-line body
    passed in 58.39 seconds. Output, pin, lease, and cgroup cleanup passed.
    The all-feature workspace build and strict Clippy passed. No assertion,
    policy, actor, production implementation, or timeout changed.
  - [x] Pass real Kubernetes and commit its registration. The same 90-line
    body passed in 74.18 seconds. The actor directory, scenario namespace,
    Node pins, sockets, and lease were absent after cleanup. The first launcher
    check incorrectly required removal of the empty output parent. Source
    review confirmed that infrastructure owns that parent. The exact owned
    cleanup check then passed without a test or implementation change.
  - [x] Remove only the matched shell request and
    `exception_excess_bound_rejected` result field after all three cases pass.
    Keep the exception wait helper and all other exception and RBAC checks.
  - [x] Pass the final repository Rust CI procedure after the last source
    edit. The shared CI run below covers this migration and the overlap check.
    The affected existing Kubernetes cases already passed together.
  Review route:
  [shared test](src/effect/exception_limit.rs) submits the owned request through
  the existing policy installation API.
    -> [Shared](src/platform/shared.rs) calls Control's production exception
    reconciler on Host and runc.
    -> [Kubernetes](src/platform/kubernetes.rs) creates the real CRD and reads
    its current-generation status. An API error or timeout is not rejection.
    -> [Python actor](fixtures/process/exception.py) makes the three writes.
    -> [EffectCheck](src/effect/check.rs) reads fresh attributed evidence for
    the protected path atom. The test checks physical results and typed-map
    keys through the existing reader. Normal actor and platform stop calls
    remove the owned resources.
  Run `effect::exception_limit::excess_uses_are_rejected::exception_host`
  in the mounted standard Rust test executable with
  `--exact --ignored --nocapture --test-threads=1`. The Host log is
  `/var/tmp/mithril-exception-limit-host-20261006.log` in the retained
  qualification VM. The corrected Host run uses
  `/var/tmp/mithril-exception-limit-host-match-20261006.log`. Direct runc uses
  the `exception_runc` suffix and
  `/var/tmp/mithril-exception-limit-runc-20261006.log`.
  Kubernetes uses the `exception_kubernetes` suffix and
  `/var/tmp/mithril-exception-limit-kube-20261006.log` in the retained K3s VM.
  Source review matches baseline `95775f48`. All three cases passed. The
  matched 11-line shell request and its result flag are removed. The exception
  wait helper and all other exception and RBAC checks remain. Shell syntax,
  VM harness behavior checks, formatting, and diff checks passed.
- [x] Replace the overlapping-grant request block in
  `harness/vm/two-node-convergence.sh` with
  `overlapping_grants_are_rejected`. Baseline `95775f48:3811–3825` submits a
  second valid exception for the same live grant and target. The first grant
  is Active. The second CRD must become Failed. This condition is distinct
  from several threads consuming one bounded exception.
  - [x] Reuse the `exception` lifecycle, `exception.py`,
    `exception_policy.json`, and `one_use_exception.json`. Keep one shared
    test below 100 lines. Add no Platform API, policy copy, or production change.
  - [x] Use a fresh name and UID for each request. Keep both requests within
    the one-use policy limit. Read the first kernel authority and require
    Active, maximum uses one, and consumed uses zero before the second request.
  - [x] Require the exact Control `overlapping live grant` rejection or the
    real Kubernetes Failed and ReconcileRejected status. Require no new
    authority or receipt key. Require the first authority to remain unchanged.
  - [x] Keep the ungranted denial, first allowed write, and exhausted denial
    explicit. Match fresh File/OpenWrite evidence to the same protected path
    atom, task, role, entry, and generation. Use normal actor and platform stop.
  - [x] Pass Host and commit it. The 99-line test passed in 42.96 seconds.
    Output, pin, lease, and cgroup cleanup passed. The all-feature workspace
    build, formatting, diff checks, and strict Clippy passed.
  - [x] Pass direct runc and commit its registration. The same test passed
    in 34.42 seconds. Output, pin, lease, and cgroup cleanup passed. After
    local build caches were removed, the cold rebuild took 12 minutes. The
    first run used large debug artifacts from the shared source mount and
    failed before actor startup when Node missed the existing 60-second limit.
    Local VM copies without debug sections have identical loadable contents
    and test registrations. With those copies, Node initialized in 26 seconds.
    No scenario, production code, assertion, or readiness limit changed.
  - [x] Pass real Kubernetes and commit its registration. The same 99-line
    scenario passed in 85.53 seconds after the lightweight interruption check
    passed. Actor files, owned namespaces, pins, sockets, and lease cleanup
    passed. The current Node image, assertions, and startup limits are unchanged.
    The log is `/var/tmp/mithril-exception-overlap-kube-light-20261006.log`.
    The first exact case failed in 203.15 seconds before actor startup. Node rejected
    `/sys/fs/bpf/mithril-pid-1546442-414106001` because it contained stale state.
    At that point, the cause of that state was not proved. The log is
    `/var/tmp/mithril-exception-overlap-kube-20261006.log` in the retained K3s VM.
    Reproduce the same startup condition with a real production Node in
    lightweight before an implementation change or another Kubernetes run.
    Keep the old overlap check until Kubernetes passes. Production is unchanged.
  - [x] Reproduce interrupted Node startup in lightweight. The retained
    containerd log records the first Node start at 03:47:01 UTC, SIGTERM at
    03:48:01, and SIGKILL at 03:48:11. The next Node exited with status one.
    The chart uses 30 startup probes at two-second intervals and a ten-second
    termination grace period. The reason for slow initial startup is not yet
    proved. Reuse `Shared` for Control and configuration and `ProcessFixture`
    for the real Node executable. Kill that Node after it creates its pin
    directories and before admission readiness. Require the next public Node
    startup to reject the incomplete root. Use normal fixture cleanup. Add no
    Platform API, fake pin, or direct BPF loader. Keep this focused fixture
    check below 100 lines; it supplements the shared exception scenario.
    The 61-line standard Rust fixture check passed in 1.02 seconds. Real Node
    created empty map and link directories, then SIGKILL stopped its startup.
    The next public Node startup rejected the incomplete root as stale and
    created no admission endpoint. Pin, lease, cgroup, and output cleanup passed.
    The first attempt kept the parent outside Node's dedicated cgroup and
    failed the earlier controller check. The existing cgroup owner's `move_in`
    call restores the required placement before the second startup. The full
    all-feature build, formatting, diff checks, and strict Clippy passed.
    The log is `/var/tmp/mithril-overlap-startup-fixed-20261006.log` in the
    retained Host VM. This check does not explain the first Kubernetes startup
    duration. No production code, Platform API, or readiness limit changed.
  - [x] Remove only the matched overlap request and
    `exception_overlap_rejected` result field after all three cases pass.
    Keep adjacent consumption, expiry, deletion, and RBAC checks.
  - [x] Pass formatting, strict Clippy, harness checks, and the final repository
    Rust CI procedure after the last source edit. On 2026-10-06,
    `CARGO_TARGET_DIR="$PWD/target" CARGO_INCREMENTAL=0 RUST_TEST_THREADS=1
    bash .github/scripts/verify-rust-ci.sh` completed formatting, workspace
    check, strict all-feature Clippy, and all workspace test targets.
    Mithril e2e passed 160 ordinary tests; 538 physical or subprocess cases
    were ignored. Its physical overlap cases passed separately on all three
    platforms. The CI source is `a777bc1a` with the 17-line shell deletion
    below. The tested shell blob is
    `6d12bf7735529864f6020c9759dc238a97c2b1b9`. The log is
    `/tmp/mithril-overlap-final-ci-20261006.log`. VM harness behavior checks
    and shell syntax passed. This result is not a full physical matrix pass.
  Review route:
  [shared test](src/effect/exception_overlap.rs) submits two valid requests
  with different names and UIDs.
    -> [Shared](src/platform/shared.rs) calls the production exception
    reconciler. [ControlStore](../mithril-control/src/store.rs) rejects the
    second request while the first grant is live.
    -> [Kubernetes](src/platform/kubernetes.rs) creates the real CRD and
    requires its current-generation Failed and ReconcileRejected status.
    -> [Python actor](fixtures/process/exception.py) makes the denied write,
    one allowed write, and the exhausted write.
    -> [EffectCheck](src/effect/check.rs) reads fresh attributed results for
    the same protected path atom. The existing typed-map reader checks the
    first authority and receipt keys. Normal stop calls remove owned resources.
  Run `effect::exception_overlap::overlapping_grants_are_rejected::exception_host`
  in the mounted standard Rust test executable with
  `--exact --ignored --nocapture --test-threads=1`. The log is
  `/var/tmp/mithril-exception-overlap-host-20261006.log` in the retained VM.
  Direct runc uses the `exception_runc` suffix and
  `/var/tmp/mithril-exception-overlap-runc-local-20261006.log`. Use the retained
  VM-local test executable and hook under
  `/var/tmp/mithril-refactor-runtime-tools-20261006`. Infrastructure copies
  these artifacts with the existing provider. Keep the originals and verify
  identical loadable contents before removing debug sections from a copy.
  Host, direct runc, and Kubernetes qualification are done. The matched
  15-line shell request and its result flag are removed. Adjacent consumption,
  expiry, deletion, recreation, node-local counters, and RBAC checks remain.
  The final repository Rust CI check passed. This replacement is done.
  Startup review route:
  [fixture check](src/platform/shared/startup.rs) starts real Control through
  [Shared](src/platform/shared.rs) and owns the real Node child through
  [ProcessFixture](src/process.rs).
    -> [Node executable](../mithril-node/src/main.rs) calls public Node startup.
    -> [KernelHostOwner](../erebor-interceptor/src/host.rs) creates the real pin
    directories. SIGKILL stops that process before admission readiness.
    -> Public Node startup rejects the retained incomplete root.
    -> Normal fixture stop removes only the owned process and test resources.
- [ ] `EffectTestRunner::physical_probe` setup and teardown: own its three
  cgroups, child processes, pin root, lease, and diagnostic output.
  - [ ] Repair the old Observe probe's baseline setup. The current VM run
    denied all 6,000 secret opens before the effect policy was enabled. The
    probe stopped before its exact-file alias checks. Setting the worker
    binding's `arm_initial_root` flag did not change the result; that test
    change was reverted. Keep the baseline allow assertion and find why the
    actor is denied before changing the setup.
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
    - [ ] Qualify `hard_link_stays_unresolved` with the old restricted root,
      not the admitted application root from the rejected draft. Start Node
      without a matching policy, start the initial actor and one extra actor,
      then install the shared bootstrap policy before exact policy replacement.
      Create both links before policy. Check Observe and Protect in one test.
      Require the same device and inode, exact original-file evidence, and
      hard-link `EACCES` with attributed `UNRESOLVED_OBJECT`. Reuse
      `exception.py`, existing Platform operations, and `EffectCheck`.
      Keep the test below 100 lines. Pass Host, runc, then Kubernetes before
      removing either old mode's hard-link assertion.
      Host passes both modes in 46.58 seconds. The 92-line test requires
      rule zero and `restored_or_unknown_root` before exact policy replacement.
      The original read has the exact policy result. Both hard-link reads
      return `EACCES` with fresh actor-attributed `UNRESOLVED_OBJECT` evidence.
      Pin, lease, cgroup, and output cleanup checks pass. Keep the old action
      until runc and Kubernetes pass. No production or Platform code changes.
      The unchanged runc case passes both modes in 77.42 seconds, including
      the production OCI hook and resource cleanup. Kubernetes remains open.
      Its first Observe action returns `EACCES` for both paths. The original
      path must succeed with `WOULD_DENY`; do not accept this result. Keep the
      old actions. Check the image-overlay condition on lightweight Host
      before a correction or Kubernetes rerun.
      The unchanged assertion fails on overlay-backed Host files in 39.11
      seconds. Evidence records `WOULD_DENY`, then `UNRESOLVED_OBJECT` for
      the same actor. Its original-path open returns `EACCES`. The reproduction
      removes its pin, lease, cgroup, and output, and detaches the overlay mount.
      See `/tmp/mithril-hard-overlay-light-20261002.log`. The diagnostic-only
      change keeps the test at 94 lines. The final repository Rust CI gate
      passes. No BPF correction is authorized. Keep Kubernetes unregistered.
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
    - [ ] Replace the remaining allowed-bind and propagation resolver checks
      before removing their fixture paths. Keep their selected mount,
      canonical component, and mount namespace assertions.
      - [x] Qualify the benign bind alias with `file_bind_allowed.rs`. Reuse
        `exception.py` and `retained_descriptor_policy.json`. Require a real
        bind mount, two allowed opens, two attributed exact Allow results,
        distinct mount IDs, and equal selected mount, canonical component,
        mount namespace, device, inode, and inode generation. Keep the test
        below 100 lines and add no Platform API.
        - [x] Pass Host and commit it. The `mount_late_host` case passed in
          `mithril-runtime-qualification-762734`; 92 runnable library tests,
          format, and strict Clippy passed. The test file has 90 lines.
        - [x] Pass direct `runc` and commit it. The `mount_late_runc` case
          passed in `mithril-runtime-qualification-762734` with the same
          actor, policy, and assertions as Host.
        - [x] Pass Kubernetes and commit it. The `mount_late_kubernetes` case
          passed in the retained K3s VM with the same scenario body.
        - [x] Remove only the matching old allowed-bind comparison and its
          unused alias mount after all three platforms pass. Keep the source
          resolver for policy publication and the propagation checks. The
          old runner still fails its pre-policy baseline before this block.
        - [x] Remove the unused `allowed-bind-source` file, its signed
          `manual-benign-bind` selector, and its exact-object setup. No
          remaining legacy action reads that file. The propagation actions
          and their peer setup were retired separately below. Keep the
          original secret, benign, device, and mount-change objects. Pass
          `allowed_bind_keeps_exact_allow` on Host, runc, and Kubernetes,
          related effect checks, harness checks, and final Rust CI before
          committing this deletion. Do not change the shared test or repair
          the old pre-policy baseline failure.
          On 2026-10-06, the unchanged 90-line shared test passed Host in
          41.65 seconds, runc in 45.69 seconds, and Kubernetes in 88.40
          seconds. Owned output, pins, sockets, and leases were removed.
          The logs are `/var/tmp/mithril-bind-source-retire-{host,runc}-20261006.log`
          in the lightweight VM and
          `/var/tmp/mithril-bind-source-retire-kube-20261006.log` in the
          retained K3s VM. The 12 related effect/child checks and VM harness
          checks passed. Final format, workspace check, strict Clippy, and
          all-target/all-feature workspace tests passed; the log is
          `/tmp/mithril-bind-source-retire-final-ci-20261006.log`.
          Review [the remaining runner](src/effect.rs),
          [the shared test](src/effect/file_bind_allowed.rs),
          [the actor](fixtures/process/exception.py), and
          [the snapshot checks](src/effect/check.rs). The actor makes a real
          bind mount and opens both paths. The test requires attributed
          Allow results and equal exact identity with distinct mount IDs.
          The runner has 26 fewer lines. No assertion, Platform, actor,
          policy fixture, or production source changed.
    - [x] Remove only the duplicate protected-alias resolver comparison from
      the old effect probe. The shared Protect and Observe tests resolve the
      original file and both aliases. They require distinct mount IDs and
      equal selected mount, canonical component, mount namespace, device,
      inode, and inode generation. Both tests passed on Host, direct `runc`,
      and real Kubernetes after the deletion. Keep the original resolver
      value for policy publication and later dirty-view checks.
    - [x] Match each new alias effect to the live public resolver result for
      that actor path. The removed old action made this match. Distinct mount
      IDs alone do not prove that each alias used its expected mount. Keep
      this check in both Protect and Observe cases on all three platforms.
      Both 96-line tests pass on Host, direct `runc`, and Kubernetes. The
      checks also compare the selected mount, canonical component, and mount
      namespace. The first Kubernetes Protect attempt stopped at a missing
      pinned Python image; the unchanged case passed after the existing
      archive restored that image. Other resolver topology cases remain in
      the old runner.
    - [x] Keep both single-test files below 100 lines without moving their
      assertions. Each file has 96 lines. Protect and Observe passed again on
      Host, direct `runc`, and Kubernetes with the same actor and policies.
  - [ ] Replace the exact-secret mount-change checks. Keep the first decision
    after mutation, dirty view, replaced-path denial, and restored decision.
    A focused Host draft on 2026-09-28 used the shared Python actor to bind
    a new alias after policy activation. Node did not establish that actor's
    recovered identity, so the draft stopped before the mount. The existing
    `bind_alias_keeps_exact_deny` Host control passed with the actor's original
    bind mode. The draft also reached an exact-file denial in that original
    mode, but that mode did not make the required late mount. The draft was
    removed. Keep the old mount-change checks until a physical replacement
    passes.
    - [x] Add the 95-line `first_bind_read_keeps_deny` test. Reuse the
      qualified `bind` actor setup, then command that actor to mount one more
      alias after the exact policy is active. Require mount success, an
      advanced mutation epoch, physical `EACCES`, and fresh attributed
      `EXACT_POLICY_DENY` evidence with the original object, composite, and
      task cookie. The two existing aliases still deny before the new mount.
    - [x] Pass Host and commit it. The new case passed in 35.92 seconds. The
      unchanged `bind_alias_keeps_exact_deny` Host case passed in 36.00
      seconds with the extended shared actor.
    - [x] Pass direct `runc` and commit it. The same test body passed in
      42.97 seconds through stock `runc` and the production OCI hook. The
      unchanged bind-alias case passed in 42.47 seconds.
    - [ ] Revisit Kubernetes for this test. Do not add it now. Keep the old
      physical check until this platform case is approved and passes.
    - [ ] Remove only the matching old first-read decision and effect after
      the deferred Kubernetes case passes. Keep dirty-view, replaced-path,
      restoration, and cache snapshot checks until their own replacements pass.
    - [ ] Replace the late-bind READY-cache snapshot check with
      `bind_rebuilds_ready_cache`. Keep one shared test below 100 lines. Reuse
      `exception.py`, `file_mount_change_policy.json`, `EffectCheck`, and
      `MountCache`. Start the actor before Node; keep recovery visible.
      Test Protect and Observe with the same actor. Require successful bind,
      the first alias read's expected result, fresh attributed exact evidence,
      an advanced epoch, and a new READY key. Keep namespace identity, changed
      mountinfo, distinct mount IDs, and equal object, composite, task cookie,
      and effect generation explicit.
      - [x] Improve the shared bind action first. Capture mount errno before
        the read. Add a cache action that does not write a result file before
        or after the first protected read. Use process-name readiness. Keep
        the existing mount action and result file. Reuse the owned alias
        directory when the same actor changes policy mode.
      - [x] Pass the existing affected Host and direct-runc cases and the
        Kubernetes bind-alias case; commit shared tooling first.
        Host first-bind passed in 38.87 seconds. Direct runc passed in 65.80
        seconds. The existing Kubernetes bind-alias case passed in 80.05
        seconds. Generic process checks passed 14 tests with one privileged
        case ignored. VM harness checks and format passed. The cache action's
        production qualification follows in the shared scenario below.
      - [x] Pass Host and commit the scenario. The 87-line test passed both
        modes on one actor in 45.36 seconds. Output, pin, lease, and cgroup
        cleanup passed. Focused lightweight effect checks passed 28 tests.
        The all-feature workspace build passed. No production or Platform
        implementation changed.
      - [x] Pass direct runc and commit its registration. The same 87-line
        body passed both modes on one actor in 79.15 seconds. Output, pin,
        lease, and cgroup cleanup passed. The all-feature workspace build
        passed. No assertion, policy, timeout, or production change was needed.
      - [x] Run final Rust CI after the final registration edit. The
        repository CI procedure passed at `e6d685d4` on 2026-10-06. Formatting,
        workspace check, strict all-target all-feature Clippy, and the full
        workspace tests passed. Mithril e2e passed 160 tests with 531 physical
        cases ignored. The log is
        `/tmp/mithril-bind-snapshot-final-ci-20261006.log`.
        Do not repeat the physical matrix for this scenario-only change.
      - [ ] Revisit Kubernetes only after approval. Keep the old late-bind
        decision, snapshot assertions, result fields, and helpers until the
        paired physical replacement passes. Do not count Host or runc as
        Kubernetes proof.
      Review route:
      [shared scenario](src/effect/file_mount_snapshot.rs) installs the signed
      policy through Control and Node, then commands the actor.
        -> [Python actor](fixtures/process/exception.py) binds the alias and
        makes the first read before process-name readiness.
        -> [EffectCheck](src/effect/check.rs) reads fresh production evidence
        for the exact actor, role, entry, operation, and physical result.
        -> [MountCache](src/physical/mount_cache.rs) reads typed READY rows,
        epoch, namespace, and mountinfo. The scenario compares both snapshots.
      Run `effect::file_mount_snapshot::bind_rebuilds_ready_cache::mount_alias_host`
      in the mounted standard Rust test executable with
      `--exact --ignored --nocapture --test-threads=1`.
      Use the `mount_alias_runc` suffix for direct runc. The focused logs are
      `/var/tmp/mithril-bind-snapshot-host-20261006.log` and
      `/var/tmp/mithril-bind-snapshot-runc-20261006.log` in the retained
      qualification VM. Source review matches `95775f48`. Kubernetes remains
      unqualified; the original snapshot block is unchanged.
    - [x] Replace the Protect-mode overmount and restoration pair with
      `mount_replacement_stays_closed`. Keep one small shared Rust test below
      100 lines. Reuse `exception.py`, the qualified bind/recovery setup,
      `file_mount_change_policy.json`, `EffectCheck`, and existing map readers.
      Do not add a Platform API or a scenario fixture.
      - [x] Add actor commands for benign-file overmount, source read, and
        unmount. Use real Linux mount calls. Report mount completion through
        the existing process-name readiness boundary, not file I/O that could
        rebuild the dirty view before the test checks it.
      - [x] Keep original exact denial and actor attribution. Require
        successful overmount, the original namespace's Dirty state, physical
        `EACCES`, and fresh attributed `UNRESOLVED_OBJECT` File/OpenRead.
        Remove the overmount; require physical `EACCES` and fresh
        `EXACT_POLICY_DENY` with the original exact key, composite, and task.
      - [x] Pass Host and related shared-actor cases. Commit Host first.
        The 91-line case passed in 35.70 seconds. The existing first-bind and
        bind-alias Host cases passed in 34.72 and 40.82 seconds. Output, pin,
        lease, and cgroup cleanup passed. The VM harness checks passed.
        The final repository Rust CI procedure passed. The local library
        suite passed 91 tests; 430 physical cases remain ignored locally.
      - [x] Pass direct `runc` and commit its registration. The same 91-line
        test passed in 42.73 seconds. The existing first-bind and bind-alias
        cases passed in 43.55 and 43.65 seconds. Output, pin, lease, and cgroup
        cleanup passed. The final repository Rust CI procedure passed after
        the registration edit.
      - [x] Pass Kubernetes and commit its registration. Keep the retained
        VM, K3s, and images. Do not weaken any assertion or change production.
        The same 91-line test passed in 79.16 seconds. The existing bind-alias
        case passed in 79.17 seconds. Namespace, output, pin, lease, and socket
        cleanup passed. The final repository Rust CI procedure passed after
        the registration edit.
      - [x] Remove only the matching overmount and restoration block after
        the Observe replacement also passes on all three platforms. Keep the
        separate first-read and mount-snapshot block until its own replacement
        passes. Do not count this Protect case as Observe or cache proof.
      - [x] Compare with `95775f48`; run harness checks and final Rust CI
        after each deliverable's final Rust edit. Document focused commands.
    - [x] Replace the Observe-mode overmount and restoration pair with
      `observe_replacement_stays_closed`. Keep one shared test below 100 lines.
      Reuse `exception.py`, `file_observe.json`, `EffectCheck`, and existing map
      readers. Do not copy a policy or add a Platform API or scenario fixture.
      - [x] Start the actor before Node. Keep production recovery and policy
        installation visible. Require initial read success and fresh
        actor-attributed `WOULD_DENY` with nonzero object key and composite.
      - [x] Require successful benign-file overmount, the original namespace's
        Dirty view, physical `EACCES`, and fresh `UNRESOLVED_OBJECT` evidence.
      - [x] Remove the overmount. Require read success and fresh `WOULD_DENY`
        with the original exact key, composite, and task cookie.
      - [x] Pass and commit Host, direct `runc`, then Kubernetes separately.
        Run harness checks and final Rust CI after each final Rust edit.
        - [x] Host: the 90-line exact case passed in 35.91 seconds with the
          unchanged actor and policy. Output, pin, lease, and cgroup cleanup
          passed. VM harness checks and final repository Rust CI passed.
        - [x] Direct `runc`: the same 90-line test passed in 43.01 seconds.
          Output, pin, lease, and cgroup cleanup passed. The final repository
          Rust CI gate passed after the registration edit.
        - [x] Kubernetes: the same 90-line test passed in 79.70 seconds.
          Namespace, output, pin, lease, and socket cleanup passed. The final
          repository Rust CI gate passed after the registration edit.
      - [x] Remove only the shared legacy overmount/restoration pair after
        both policy modes pass on all three platforms. Keep cache snapshots,
        first-read decisions, and propagation actions and assertions intact.
        Compare with `95775f48` and document the exact replacement commands.
        The retirement deletes 55 Rust lines. Eight related child regressions,
        VM harness checks, and the final repository Rust CI gate passed after
        the deletion. The remaining legacy mount cases are not qualified by
        this result.
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
    - On 2026-09-28, a Host draft also self-bound the source directory before
      `open_tree`, as the old probe does. The original and repeat path opens
      returned `EACCES`, but `openat` through the detached mount succeeded.
      Node reported that exact selector `path-0` had no proven object in the
      container. The unverified actor mode and test were removed. Do not
      retire the old denial or infer that the detached mount is protected.
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
    at most 150 lines. The implementation has 131 lines. The limit preserves
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
  - [x] Replace the prepared `MoveMount` fail-closed check. Extend the shared
    mount actor to clone and hold a detached tree before policy activation.
    Recover that actor under the signed mount-race policy, which does not
    permit `SysAdmin`. Make it call `move_mount` after activation. Require a
    physical `EACCES` or `EPERM` result and a fresh, task-attributed
    `UNSUPPORTED_OBJECT` Privilege/Capability result with kernel `-EACCES`.
    Keep the standard test below 100 lines and add no Platform API or policy.
    - [x] Pass Host and commit it. The 76-line exact test passed in 37.41
      seconds. The actor cloned the tree before Node started. The protected
      `move_mount` was denied, and production reported the actor's exact
      Privilege/Capability `-EACCES` effect.
    - [x] Pass direct `runc` and commit it. The same exact test passed in
      40.94 seconds through stock `runc` and the production OCI hook. The
      existing positive mount-move runc test passed in 66.33 seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 101.80
      seconds. The existing allowed mount-move Kubernetes test passed in
      298.58 seconds on the retained cluster.
    - [x] Remove only the matching old prepared operation after all three
      cases pass. Keep `MountSetattr` and propagation hard-close checks. The
      removed branch and its unused target and syscall helper total 43
      deleted lines. The 92 non-privileged Mithril library tests pass. The
      legacy physical probe stops before these mount checks: its baseline
      open returns `EACCES` after it publishes the cgroup binding and before
      it installs policy. A syscall trace confirms this order. Retire the
      remaining legacy checks through platform scenarios; do not treat that
      baseline failure as a prepared-move result.
  - [x] Replace the prepared `MountSetattr` hard-close check. Let the shared
    mount actor prepare its mount before Node starts. After Node recovers the
    actor under the signed policy without `SysAdmin`, call `mount_setattr` to
    request a read-only mount. Require physical denial and fresh, attributed
    `UNSUPPORTED_OBJECT` Privilege/Capability `-EACCES` evidence. Add no
    Platform API or policy. Keep the standard test below 100 lines.
    - [x] Pass Host and commit it. The 71-line exact test passed in 44.85
      seconds. The existing prepared-move Host test passed in 30.71 seconds
      after the shared actor change.
    - [x] Pass direct `runc` and commit it. The exact test passed in 79.49
      seconds through stock `runc` and the production OCI hook. The existing
      prepared-move direct-`runc` test passed in 37.97 seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 78.49
      seconds with the deployed Control and Node in retained K3s.
    - [x] Remove only the matching old action after all three platforms pass.
      Keep the shared syscall helper, mount propagation, and detached-tree
      checks. The 92 non-privileged Mithril library tests pass after removal.
  - [x] Replace the prepared mount-propagation hard-close check. Let the
    shared mount actor create its bind mount before Node starts. After Node
    recovers the actor under the signed policy without `SysAdmin`, make the
    actor call `mount` with `MS_SHARED | MS_REC` on that mount. Require a
    physical `EACCES` or `EPERM` result and fresh, task-attributed
    `UNSUPPORTED_OBJECT` Mount/Mount evidence with kernel `-EACCES`. Use the
    existing actor and policy. Add no Platform API. Keep the test below 100
    lines.
    - [x] Pass Host and commit it. The 74-line exact test passed in 37.84
      seconds. The existing mount-setattr Host test passed in 29.92 seconds
      after the shared actor change.
    - [x] Pass direct `runc` and commit it. The exact test passed in 97.55
      seconds through stock `runc` and the production OCI hook. The existing
      mount-setattr direct-`runc` test passed in 61.80 seconds.
    - [x] Pass Kubernetes and commit it. The exact test passed in 92.67
      seconds with the deployed Control and Node in retained K3s.
    - [x] Remove the matching old action, its unused stored mount path,
      and its syscall helper after all three cases pass. Keep the detached
      `open_tree` check and its mount source. The 92 non-privileged Mithril
      library tests pass after removal.
  - [x] Replace filesystem reconfiguration with `reconfigure_dirties_mounts`.
    - [x] Reuse `mount_alias.py`. Mount tmpfs, call `fspick`, set `size` to
      `4194304`, and call `FSCONFIG_CMD_RECONFIGURE`. Do not substitute a
      remount or a read-only attribute change.
    - [x] Keep Protect and Observe qualification. Install the signed policy
      through Control and Node. Keep the actor action and assertions shared.
    - [x] Require the global mutation epoch and activity sequence to advance.
      Require mutation epoch to differ from clean epoch or pending mutations
      to be nonzero before the actor performs another file operation.
    - [x] Require the explicit benign-file read to succeed after reconfiguration
      with task-attributed allow evidence. Check the resulting tmpfs size.
    - [x] Keep the scenario below 100 lines. Add no Platform API. Use the
      existing process readiness, typed state reader, and effect checker.
    - [x] Pass Host and commit it. The 95-line test passed both modes in
      40.59 seconds. Normal output, pin, lease, and cgroup cleanup passed.
      The first draft omitted required policy `recursive` fields. The next
      draft checked the immutable birth generation instead of the current
      process generation. Both fixture errors are corrected. No production
      code or assertion is removed.
    - [x] Pass and commit direct `runc`. The unchanged shared test passed both
      modes in 47.57 seconds. Output, pin, lease, and cgroup cleanup passed.
    - [x] Pass and commit real Kubernetes. The unchanged shared test passed
      both modes in 81.13 seconds. Namespace, output, pin, lease, and socket
      cleanup passed. Host and direct-`runc` qualification ran first.
    - [x] Remove the matching legacy action, result field, child command, and
      unused syscall helper only after all three platform cases pass. Compare
      with baseline `95775f48`. Keep propagation, cache, and attribute checks.
      The retirement removes 141 net Rust lines. Eight child regressions and
      the VM launcher checks pass. The shared scenario remains 95 lines.
      The shared actor's preexisting-bind and mount-setattr Host regressions
      pass in 27.94 and 33.57 seconds. No Platform, production API, Node,
      Control, BPF, or public production result schema changes.
      The final repository Rust CI procedure passes after the last Rust edit.
      This focused three-platform proof does not close the full physical
      matrix delivery gate.
  - [x] Replace the successful external `mount_setattr` block with a shared
    platform test. Keep one workload with a live child in a second mount
    namespace. Use the existing signed mount policies, `ProcessFixture`, and
    `MountCache`. Keep both benign reads and the global guard checks.
    - [x] Acquire the external helper's namespace and root before protection.
      Use the shared Python file. Do not add a Rust helper or Platform API.
    - [x] Set the target mount read-only, then restore write access. Require
      syscall success and read back each actual mount attribute.
    - [x] In Protect and Observe, require the global mutation epoch to advance,
      both benign reads to succeed, and new READY cache rows after each change.
      Keep task-attributed allow evidence and normal process cleanup.
    - [x] Pass Host. The 87-line shared test passed both modes in 39.61 seconds
      on 2026-10-02. Output, pin, lease, and cgroup cleanup passed. Strict
      package clippy passed. Shared actor tooling is committed first.
    - [x] Pass direct `runc`. The unchanged 87-line scenario passed both modes
      in 47.39 seconds through stock `runc` and the production OCI hook.
      Host passed the final recursive operation in 40.47 seconds. Both runs
      removed output, pin, lease, actor cgroup, and Node cgroup. The shared
      syscall keeps the baseline `AT_RECURSIVE` flag.
    - [x] Pass and commit real Kubernetes. The corrected 93-line shared test
      passed Protect and Observe in 84.52 seconds. Namespace, output, pin,
      lease, actor cgroup, and Node cgroup cleanup passed. The first run
      stopped with raw `EACCES` before the mount action in 74.03 seconds.
      The old block stayed until the correction passed all three platforms.
      The lightweight reproduction checks the unowned observer's exact
      namespace and mountinfo reads. Cache I/O errors now include paths.
      Kubernetes ran only after the missing condition had a local proof.
      The 80-line Host reproduction passed in 27.52 seconds. The initial
      runtime target's namespace stat succeeds. The unowned observer gets
      `EACCES` for the child's namespace link; the child's mountinfo stays
      readable. Each actor reports its own namespace stat. Both physical
      reads, distinct namespace IDs, the global epoch, and two new READY
      cache rows stay in the shared test. BPF access remains unchanged.
      The corrected 93-line test passed Protect and Observe on Host in
      40.79 seconds and direct `runc` in 46.66 seconds. Both runs passed
      normal output, pin, lease, actor cgroup, and Node cgroup cleanup.
    - [x] Remove the old block, unused helper, CLI path, and result fields only
      after the matching coverage passes. Keep propagation coverage separate.
      The shared test replaces the baseline `95775f48` read-only and restore
      checks. It requires both namespaces to read after both changes, at least
      two new READY rows per change, and task-attributed allow evidence in
      both modes. The old block requires two reads after the first change,
      one after restore, and at least one new READY row. The separate exact
      file-object and successful propagation checks stay in the old runner.
      Retirement removes 166 net Rust lines. All 92 non-privileged library
      tests and the VM launcher checks pass. The final repository Rust CI
      procedure passes after the last Rust edit. No Platform API, Node,
      Control, BPF, or public production result schema changes. This focused
      three-platform proof does not close the full physical matrix gate.
    - The draft added an exact-object ID assertion absent from this baseline
      block. Its exact-file replacement stayed pending with one and two
      workload targets. The unused policy drafts are removed. Keep the
      separate legacy exact-object checks. This case must prove the signed
      file rule, mount guard, two namespace rebuilds, and physical reads.
    - Review [the shared test](src/effect/mount_setattr.rs), then
      [the Python actor](fixtures/process/mount_alias.py) and
      [the cache reader](src/physical/mount_cache.rs). The actor owns its child
      pipes and normal child exit. `ProcessFixture` owns bounded readiness and
      fallback cleanup. The test keeps policy delivery and assertions visible.
  - [x] Replace successful mount propagation with
    `propagation_rebuilds_namespaces`. Compare with baseline `95775f48`.
    - [x] Extend the shared mount actor's existing child and pipe protocol.
      Mark the bind mount `MS_SHARED`, then fork and unshare the child's mount
      namespace. Use the existing signed policies and process fixture.
    - [x] Acquire the external helper's namespace and root before protection.
      Bind the marker source beneath the shared mount, then unmount it.
    - [x] In Protect and Observe, require two distinct live namespaces, the
      marker in both after bind, and `ENOENT` in both after unmount. Require
      both benign reads to succeed and keep their task-attributed evidence.
    - [x] Require the global mutation epoch to advance and at least two new
      READY cache rows after each action. The old unmount check requires one
      peer read and one new row; keep the stronger shared check.
    - [x] Keep the standard Rust test below 100 lines. Add no Platform API,
      separate process wrapper, production sequencing, or BPF change.
    - [x] Pass and commit Host. The 95-line shared test and the existing
      mount-attribute regression passed together in 59.83 seconds. Both
      modes passed with one Control and Node. Output, pin, lease, and both
      cgroups were removed. Strict package clippy passed. The first draft
      used a task name longer than Linux permits. Short completion names
      now precede the unchanged explicit errno and result assertions.
    - [x] Pass and commit direct `runc`. The unchanged shared case and the
      existing mount-attribute regression passed together in 74.38 seconds.
      Both modes passed through stock `runc` and the production OCI hook.
      The shared owner started once. Output, pin, lease, and cgroups were
      removed.
    - [x] Pass and commit real Kubernetes after the lightweight proof. The
      shared case and the existing mount-attribute regression passed together
      in 120.19 seconds. Both modes used one real Control, Node, and runtime
      integration in retained K3s. Namespace, output, pin, lease, and cgroup
      cleanup passed. No platform, timeout, or production change was needed.
    - [x] Remove the old action, result fields, mailbox peer, and unused
      dedicated cgroup, binding, and object setup only after all three pass.
      Keep the separate mount-change exact-object checks.
      Retirement removes 416 net Rust lines. The old fixture installed peer
      secret and device objects during setup, but the peer performed no secret or ioctl
      action. Main and Unix-peer exact objects and assertions stay. All 92
      non-privileged library tests and the VM launcher checks pass.
      The final repository Rust CI procedure passes after the last Rust edit.
      This focused three-platform proof does not close the full physical
      matrix gate. No Node, Control, BPF, or public production schema changed.
    - Review [the shared test](src/effect/mount_propagation.rs).
      -> [The actor](fixtures/process/mount_alias.py) marks the mount shared,
      forks the namespace peer, and performs the external bind and unmount.
      -> [The cache reader](src/physical/mount_cache.rs) checks the kernel
      epoch and READY rows. [EffectCheck](src/effect/check.rs) checks fresh
      production evidence for each reader.
      -> [ProcessFixture](src/process.rs) stops both tracked tasks and the
      helper. The actor checks normal child exit. The shared lifecycle retains
      Control and Node between cases and removes their pins at command exit.
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
      test. The test file has 131 lines, which is below its approved 150-line
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
    - [x] Reuse the existing effect checker in the late-bind, recursive-bind,
      and move-mount tests. Keep each denial and allow expectation in its test.
      The tests have 80, 81, and 131 lines. All ten Host mount-late cases and
      all ten direct-`runc` mount-late cases passed. The three changed
      Kubernetes cases passed.
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
    - [x] Bring the shared mount-race test below 100 lines. It is 80 lines.
      The existing effect checker observes the exact denied and allowed reads.
      The test keeps all eight mount results and the worker Mount denial.
      The 92 library tests and the exact Host, direct-`runc`, and Kubernetes
      cases passed on 2026-09-27. The Kubernetes test waits for the actor's
      result file because a failed attach transport does not prove actor exit.
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
    A Host draft started both protected group members, opened the two files,
    and then replaced the signed policy. The replacement stayed pending with
    two targets on the old revision. The draft was removed. The shared fixture
    now publishes every existing member before it waits for the replacement.
    `container_roles_are_distinct` proves that both running members swap file
    decisions under one signed replacement. After the final fixture edit, it
    passed on Host in 43.89 seconds, direct `runc` in 59.28 seconds, and
    Kubernetes in 85.99 seconds. The repository Rust CI gate passed. The
    Kubernetes fixture now waits for one rollout bundle that contains both
    members; it does not mistake two containers for two rollout bundles.
    Next, rerun the descriptor transfer with the qualified replacement setup.
    The new Host draft still fails before transfer. Both actors open the
    descriptors, and policy delivery reaches readiness. The receiver remains
    on profile generation 2 while the sender reaches generation 4. The
    production Unix hook denies their connect with `EACCES`. Node also reports
    that exact selector `path-1` has no proven object in one container. Waiting
    for the listener and making a receiver file open did not change the result.
    Sorting the shared Control target facts did not converge the generations:
    the existing group-role case still observed generation 1 and 2 after a
    replacement read. The diagnostic sorting and assertion were removed.
    Do not remove the old transfer checks or commit the draft. Confirm the
    correct pre-protection startup order before changing this scenario.
    The Kubernetes setup must use one Pod with two application containers.
    They need separate CRI cgroups and Node bindings, one network namespace
    for an abstract Unix stream, and one shared file object for each transfer.
    Keep Python code in `/fixtures`, but do not put the protected files in that
    hostPath mount. Its canonical object path is not the signed `/fixtures`
    path. A focused Host run reached two distinct bindings, one network
    namespace, and matching file device and inode. Its exact-policy replacement
    then failed with `signed path selector path-0 resolved to a different
    canonical path`. The transfer did not run.
    Kubernetes setup design: keep the retained K3s cluster, Control Deployment,
    and Node DaemonSet. Install the open bootstrap policy through its CRD.
    Call the existing `start_actor_group` once. It creates one Pod with sender
    and receiver application containers. Each has its own CRI cgroup and Node
    binding. Both use the Pod network namespace and one memory-backed
    `emptyDir` mounted at `/tmp`. Mount Python fixtures read-only at
    `/fixtures`; do not store protected files there. The receiver creates the
    secret and benign files in `/tmp`. Both actors open them and report ready
    before policy replacement. Replace the same policy CRD with the signed
    exact-file policy, wait for rollout readiness, then release the receiver
    and sender through their normal actor input. Require distinct bindings,
    cgroups, and roles; the same network namespace and file device/inode;
    direct-open denial; denied secret transfer without an installed descriptor;
    allowed benign transfer with one readable descriptor; and exact File
    evidence. Stop both actors and use normal platform cleanup to delete the
    scenario namespace. Do not add a Platform API or a shell Pod runner.
    Host and direct `runc` need equivalent shared-file and Pod-network setup
    inside their existing `start_actor_group` implementations.
    The shared group-role test now checks that two group members use one
    network namespace. Direct `runc` keeps the first member's namespace open
    and joins each later member to it. The exact Host, direct `runc`, and
    Kubernetes cases passed. The Host identity lifecycle passed 62 tests. The
    direct-`runc` identity lifecycle passed 57 tests. Both lifecycles removed
    their pin root, lease, and cgroup. The repository Rust CI gate passed.
    This does not qualify descriptor transfer.
    A Host draft started two members with one shared
    `/tmp` directory. Both actors see the same file device and inode. A
    policy without `exact: true` denies the direct secret open through a
    composite atom, so it does not preserve the old exact-selector check.
    With exact selectors, the replacement remains pending for two targets
    and the 30-second readiness check fails. The draft was removed. Do not
    remove the old actions.
    This is a design, not a passing replacement. A Host draft with one shared
    `/tmp` mount proved matching file device/inode and reached exact-policy
    readiness, but the sender's Unix connect returned `EACCES` before transfer.
    A Node-after-actor Host draft failed initial exact-policy activation:
    Node reported that selector `path-0` had no proven object in the container.
    Confirm the cause in lightweight and pass Host, then direct `runc`, before
    running the same Kubernetes test. Keep the old transfer checks until all
    three cases pass with the same assertions.
    A later focused Host run used the Node-first bootstrap order and one
    shared `/tmp` mount. Both actors opened the files, and the signed exact
    replacement reached readiness. Node then reported that exact selector
    `path-0` had no proven object in the container. The sender's Unix connect
    returned `EACCES` before transfer. Deferring the fixture's first member
    publication until both targets were ready did not change this result.
    The draft actor, Pod, policies, test, and fixture changes were removed.
    Keep the old transfer actions. Do not run Kubernetes for this case until
    the same physical sequence passes on Host and direct `runc`.
    An earlier Host draft used the public Node and Control APIs, one bootstrap
    policy, and a signed exact-file replacement. A two-container Pod did not
    give both actors one proven file object. A single-container test gave the
    sender and receiver distinct declared roles, but it did not reproduce the
    old test's separate bindings. The receiver's direct secret open denied
    with exact-policy evidence. The sender's Unix-stream connect then returned
    `EACCES` with `CORRUPT_IDENTITY_OR_GENERATION`, before either descriptor
    transfer. Node also reported that exact selector `path-1` had no proven
    object during reconciliation. Moving each actor to the new policy with a
    file open did not clear the connect denial. The draft was removed; the old
    transfer assertions remain. Do not change production code or BPF for this
    migration without a separate approved defect and a lightweight repro.
    - [ ] Requalify the full identity lifecycles. Host passed 61 of 61 before
      the final private fixture edit. Direct `runc` passed 54 of 56; stock
      entry-isolation exec and the first TID cookie-gap check failed. Both
      passed unchanged when run alone. Kubernetes passed 54 of 56; the
      non-leader cookie-gap check and subreaper case failed. Both passed
      unchanged when run alone. The two full lanes are not green. Find the
      shared-lifecycle cause before delivery. Do not relax the assertions.
    - [ ] Pass Host and commit it.
    - [ ] Pass direct `runc` and commit it.
    - [ ] Pass Kubernetes and commit it.
    - [ ] Remove only the matching legacy transfer actions and private child
      machinery after all three platforms pass. Keep unrelated Unix-stream
      and exact-file checks.
  - [x] Replace the SysV shared-memory permission check with one small
    standard platform test. The shared Python actor must create and attach a
    private segment before protection starts. It must mark the segment
    for deletion before readiness, then wait for production recovery and call
    `shmctl(IPC_STAT)`. Require `EACCES`, the restricted external role, attributed
    `UNSUPPORTED_OBJECT` IPC/Access evidence, and no exact policy object.
    Reuse the signed Python policies and existing Platform operations. Keep
    the Rust test below 100 lines and add no Platform API.
    - [x] Use the existing actor-before-Node recovery flow, not late placement
      into an already-active binding. Start one namespace init and one Python
      actor before Node. The actor creates and attaches the private segment
      and marks it for deletion before readiness. Install the existing signed
      Python policy, start Node, and wait for production recovery before the
      action. Check the actor's rule-zero identity and restricted role before
      `IPC_STAT`. Require physical `EACCES`, fresh attributed IPC/Access denial,
      and zero exact-object and composite IDs. Add only the shared actor and
      small test; do not change Platform, Node, Control, or BPF. Qualify Host,
      direct `runc`, and Kubernetes in that order. Keep both old mode checks
      until Protect and Observe replacements pass.
    - [x] Protect Host passed in 28.02 seconds. The 65-line
      `identity/scenarios/ipc_stat.rs` uses `ipc_stat.py`, the existing signed
      Python policy, and production recovery. It checks rule zero, restricted
      role 2, physical `EACCES`, fresh attributed IPC/Access denial, and zero
      object IDs. The segment is marked for deletion before readiness. Actor
      cleanup returns success. A first draft passed the denial checks but its
      second stdin cleanup command failed with a broken pipe. The final actor
      uses the existing release-file cleanup pattern. No production or
      Platform code changed.
    - [x] Protect direct `runc` passed in 28.50 seconds with the same actor,
      test body, and assertions. The repository Rust CI gate passed. No
      runtime fixture or production code changed.
    - [x] Protect Kubernetes passed in 69.70 seconds. The same 70-line test
      and shared actor check the role, physical denial, attributed evidence,
      successful segment detach, and actor exit through real Control, Node,
      CRD, and Kubernetes exec operations. The repository Rust CI gate passed.
      The first Kubernetes draft passed the role, syscall, and attributed
      denial checks. It failed its cleanup status assertion. An actor that
      starts before Node can survive a runtime restart while its exec
      transport exits with a failure status. The existing lightweight
      `process::tests::transport_waits_for_actor` reproduced actor status 0
      and transport status 1 in 0.03 seconds. The replacement now requires
      the actor to detach the segment and report `ipc-clean`, then exit and
      disappear. The final 70-line test passed Host in 28.01 seconds and
      direct `runc` in 35.04 seconds. Their pin, lease, and cgroup cleanup
      checks passed. The repository Rust CI gate passed before the paired
      Kubernetes run. No security assertion or production code changed.
    - [x] Preserve the same legacy check under Observe mode on all three
      platforms before deleting the old action, result, and prepared segment.
      Reuse `ipc_stat.py`, the existing `memory_observe.json` policy, and the
      actor-before-Node recovery order. Keep physical `EACCES`, fresh IPC/Access
      evidence, rule zero, the restricted role, zero policy-object IDs, segment
      detach, and actor exit explicit in the small standard test.
      The recovered actor uses the policy's external role ID. Its installed
      class is `fail_closed_unknown`, not `runtime_external_restricted`:
      `create_external_root` and `label_restored_root` preserve the missing
      entry-history claim. Check both values; do not treat the class as a
      policy role name. The first Host draft rejected the wrong class
      expectation before the IPC action. No production change is required.
      - [x] Observe Host passed in 28.09 seconds. The 75-line
        `ipc_stat_observe.rs` retains the existing actor, policy, production
        recovery, physical denial, attribution, and normal cleanup checks.
        It checks external role ID 1 and recovered class `fail_closed_unknown`.
        The repository Rust CI gate passed.
      - [x] Observe direct `runc` passed in 32.32 seconds with the same
        75-line test, shared actor, policy, and assertions. The repository
        Rust CI gate passed. No Platform or production code changed.
      - [x] Observe Kubernetes passed in 78.84 seconds and its final Rust gate
        passed. Namespace, pin, and lease cleanup checks passed.
        The focused physical case passed in 78.84 seconds with the same actor,
        policy, role, class, denial, attribution, and cleanup assertions. The
        first final CI command failed in the unchanged Control test
        `node_session_transitions_emit_owned_logs`: its log record was absent.
        Do not claim the final gate passed or change production logging for
        this migration. The unchanged focused Control test passed in 0.01
        seconds. The full Rust CI procedure then passed without a source
        change. The cause of the missing log is not established. No legacy
        SysV code has been removed yet.
      - [x] Remove only the matching SysV legacy operation, segment resources,
        result flag, and shell gate after both modes pass on all platforms.
        The retirement deletes 14 lines from `effect.rs` and 55 lines from
        `effect/child.rs`. It removes the enum variant, segment fields, setup,
        detach, permission action, result field, and result initializer. No
        SysV shell gate remains to remove. All nine child regressions passed.
        The adjacent Unix-stream IPC action and assertions remain unchanged.
        The final repository Rust CI procedure passed after the last source
        edit.
        - The remaining legacy physical probe is not qualified. Its baseline
          opens fail before the SysV action: 0 allowed and 6,000 denied. The
          pre-deletion binary fails at the same step under Observe and Protect.
          Both post-deletion modes also fail at that step. Do not
          weaken its baseline or change production code for this retirement.
          Keep the remaining runner work open.
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
  - [x] Replace ordinary generation retirement with a small standard platform
    test. Reuse `ready.py`, both actor policies, and `GenerationState`. Keep
    Protect and Observe modes. Start both holders before the first policy,
    as the old probe does. Let Node recover their runtime identity. Replace
    one live workload's signed policy.
    Require a newer active generation and a retained `Retiring` predecessor.
    Stop an added holder first and require the predecessor to stay present.
    Stop the last holder and require no predecessor descriptor, activation
    targets, or active bindings. Let production Node perform retirement.
    Add no Platform or production API. Keep the file below 100 lines.
    Pass and commit Host, runc, then Kubernetes before removing the
    pre-saturation active-pointer and `Retiring` checks and
    `active_generation_published` field. Keep the exact-file migration effect,
    terminal-evidence checks, and post-saturation last-holder retirement check.
    The new test does not reproduce ring loss or WAL-capacity saturation.
    - [x] Host: both modes passed in 78.71 seconds. The file has 97 lines.
      Initial trials started holders after policy installation. Protect passed;
      Observe admission timed out. The final setup starts both holders before
      protection, as the baseline does. No production code or deadline changed.
    - [x] Direct runc: both modes passed in 183.38 seconds on 2026-10-06.
      The body, fixture inputs, production code, and deadlines are unchanged.
      Log: `/var/tmp/mithril-generation-runc-20261006.log` in the retained VM.
    - [x] Kubernetes: both modes passed in 129.73 seconds on 2026-10-06.
      The first Node became ready in 38 seconds with zero restarts. The test
      body, policy inputs, production source, and startup deadline are unchanged.
      Log: `/var/tmp/mithril-generation-kube-isolated-20261006.log`.
      The first run failed before actor startup in 215.82 seconds on
      2026-10-06. The first Node container was stopped after 60 seconds and
      killed after its ten-second grace period. Later starts rejected stale
      pins. The interval matches Helm's startup probe; its event and first
      Node log were removed by container cleanup. Do not claim probe expiry
      or CPU contention as a proven first cause. Log:
      `/var/tmp/mithril-generation-kube-20261006.log` in the retained VM.
      Lightweight reproduced startup interruption before the next physical
      run. With the Host VM temporarily CPU-limited, the real Node owner had
      no admission socket at 60 seconds. Killing that owner left empty pin
      directories. A fresh Node rejected those directories with the same
      stale-state error in 1.66 seconds. The original CPU setting is restored.
      Logs: `/var/tmp/mithril-startup-deadline-host-20261006.log` and
      `/var/tmp/mithril-startup-retained-host-20261006.log` in the Host VM.
      The passing focused rerun had no concurrent workspace CI. This result
      does not prove which operation delayed the first run's Node.
    - [x] Retire only the matched pre-saturation legacy checks. The deletion
      removes 54 lines from `effect.rs`. The exact-file migration effect,
      ring-loss and WAL-capacity assertions, and post-pressure last-holder
      retirement remain unchanged. Comparison with `95775f48` confirms the
      shared test retains both removed assertions in Protect and Observe.
      The 28 focused effect tests and local VM harness checks passed.
      The final repository Rust CI gate passed with `RUST_TEST_THREADS=1`.
      Formatting, workspace check, strict Clippy, and workspace tests passed.
      No physical matrix was repeated for this matched legacy deletion.
      Log: `/tmp/mithril-refactor-generation-retire-ci-20261006.log`.
    - [ ] Replace last-holder retirement after ring loss and WAL saturation.
      Keep `old_generation_deleted_after_last_holder` until this condition passes.

    Source review for the new test:

    [generation_retires_after_exit](src/identity/scenarios/generation_retirement.rs)
    starts two real holders before protection
      -> [install_policy](src/platform/shared.rs) sends the signed policy through Control
      -> [recovered](src/platform/shared.rs) waits for production Node recovery
      -> [GenerationState](src/identity/scenarios/generation_state.rs) reads the active and retiring kernel generations
      -> [ready.py](fixtures/process/ready.py) exits one holder, then the last holder
      -> [GenerationState](src/identity/scenarios/generation_state.rs) verifies removal by production Node.

    Final-source formatting, workspace check, and strict Clippy passed.
    The Rust CI gate stopped at the unchanged Araphor
    `analysis::raw::tests::observability_raw_recovery` deadline: 168 passed,
    one failed, five ignored. Log:
    `/tmp/mithril-refactor-generation-recovery-ci-20261005.log`.
    The runc registration passed the same compile and lint checks. Its CI gate
    stopped at the same Araphor deadline: 168 passed, one failed, five ignored.
    Log: `/tmp/mithril-refactor-generation-runc-ci-20261006.log`.
    Kubernetes registration passed formatting, workspace check, and strict
    Clippy. The CI gate stopped in five unchanged Araphor tests: 164 passed,
    five failed, five ignored. Log:
    `/tmp/mithril-refactor-generation-kube-ci-20261006.log`.
  - [ ] Replace the exact benign-file read control with a small platform test.
    The baseline installs an external-role exact Allow and leaves the initial
    root unarmed. Its read assertion does not check a root-class name. Keep
    entry rule zero and the external role in the replacement. Use an explicit
    recovered unknown root, not an admitted application root. Publish the same
    policy without file rules first. Wait for runtime recovery before installing
    its exact rule. Reuse `retained_descriptor.py`
    for two fresh opens and one-byte reads. Require the correct byte, successful
    exit, and two fresh, task-attributed File/Read `EXACT_POLICY_ALLOW` events
    in Protect and Observe modes. Check the signed selector and active policy
    generation. Use existing platform recovery and policy operations only.
    Pass and commit Host, runc, then Kubernetes before removing the matching
    old action and `benign_read_allowed` field. Keep the first protected open,
    outside-tree control, deep-tree inputs, asynchronous reads, generation
    checks, and saturation controls until their own replacements pass.
    - [x] Let the existing `install_policy` accept an explicit policy file.
      Keep named fixture lookup and actor path rules unchanged. Use one typed
      policy fixture for Protect and Observe; do not copy its full document.
      Add the two-fresh-read control mode to the shared descriptor actor. Pass
      the input-path check and physical production checks before committing
      this common tooling and then the scenario.
      The input-path check passed on 2026-10-05. The first Host trial failed
      before its reads. Node rejected the exact selector because no runtime
      file object was proven. The existing readiness wait now joins a stopped
      Node and returns its error. The diagnostic reproduction reported the
      exact selector error in 29.19 seconds instead of a readiness timeout.
      Production source and readiness deadlines remain unchanged.
      The Host scenario passed in 51.17 seconds. The VM harness checks passed.
      Formatting, workspace check, and strict Clippy passed. Rust CI stopped
      at the unchanged Araphor `observability_raw_recovery` test with
      `AnalysisReadDeadline`: 168 passed, one failed, and five ignored.
      The complete lightweight library passed: 160 tests, zero failures, and
      525 ignored physical or helper cases. The existing retained, passed, and
      independent descriptor cases each passed on Host, runc, and Kubernetes.
      The Host scenario uses the existing Node-first `identity` lifecycle.
      It passed with the retained and independent descriptor cases in one
      process: three passed in 69.79 seconds. The first batch command selected
      zero tests; that command is not qualification evidence.
      Review the implemented input and result flow:
      [policy_path](src/platform.rs) accepts a named fixture or an existing file.
      -> [Shared::install_policy](src/platform/shared.rs) uses signed production policy delivery.
      -> [retained_descriptor.py](fixtures/process/retained_descriptor.py) opens and reads the real file.
      -> [EffectCheck::wait_many](src/effect/check.rs) selects fresh attributed effects.
      [ProcessFixture::stop](src/process.rs) owns normal process cleanup.
      The scenario reads `ExecutionSetBindingStateV1` with a native-endian
      root-cgroup key. It checks the external role against the real binding.
    - [x] Qualify Host with the shared `identity` lifecycle. The 99-line
      [exact_read_is_allowed](src/effect/benign_read.rs) test keeps both modes
      and all explicit role, selector, generation, and evidence assertions.
    - [x] Qualify direct runc. The same `identity_runc` case passed in
      55.62 seconds. The test body and assertions did not change.
    - [ ] Qualify and commit Kubernetes.
      Not done. The first attempt stopped before actor startup because K3s
      removed the unused Python image under guest disk pressure. Remove old
      test-binary copies and use the existing infrastructure image helper.
      Do not import images in the Rust platform.
      The next attempt reached the actor but both fresh opens returned
      `EACCES`. Reproduce the container's OverlayFS storage in lightweight
      before another Kubernetes run. Mount OverlayFS in the owned VM and put
      the unchanged Host case's `MITHRIL_TEST_OUTPUT` under that mount.
      The Host reproduction reports one File/OpenRead `EXACT_POLICY_ALLOW`
      followed by one File/OpenRead `UNRESOLVED_OBJECT` for each attempt.
      It fails before either read. The task, external role, and generation
      stay the same across each pair. The reproduction took 70.61 seconds.
      Keep task-specific failure records in the existing `EffectCheck` wait.
      Unrelated IPC events must not erase the last actor records. Matching
      rules, security assertions, and wait limits stay unchanged. The three
      capture checks passed. Ordinary Host and runc passed in 38.80 and
      62.48 seconds. The diagnostic OverlayFS reproduction took 61.99 seconds.
      Kubernetes then reported the same paired OpenRead decisions and failed
      in 111.89 seconds. No production source changed.
      The final diagnostic source passed 28 related Mithril effect checks.
      Rust CI passed formatting, workspace check, and strict Clippy. Its test
      step stopped at the unchanged Araphor `observability_raw_recovery`
      `AnalysisReadDeadline`: 168 passed, one failed, and five ignored.
      Linux opens an internal backing file on a private mount for OverlayFS.
      [The Linux backing-file owner](https://raw.githubusercontent.com/torvalds/linux/v6.8/fs/backing-file.c)
      also stores the user-visible path. Mithril reads the raw `file.f_path`.
      A proposed BPF correction needs user approval. Use the stored visible
      path only for kernel-marked backing files, then retain the exact-object,
      namespace, and fail-closed checks. Ordinary unattached files must stay
      denied. Do not move the protected file to hostPath or change the Allow
      assertion to a denial. Keep Kubernetes out of the committed attribute
      until this exact case passes. Keep the legacy action and result field.
    - [ ] Remove only the matching legacy read action and result field.
  - [x] Complete BPF-link pin removal without the old mount fixture.
    [link_pin_removal_is_denied](src/effect/link_pin.rs) uses the common
    `ProcessFixture` and [link_pin.py](fixtures/process/link_pin.py) for mount
    setup. The 99-line Rust test keeps both policy modes, exact task evidence,
    recovered unknown roots, zero admission rule IDs, and the real pin.
    The test holds the actor root before protection. Linux `statat` checks
    the mounted pin's device and inode before and after each denied unlink.
    `ProcessFixture::stop` closes Python input. Python unmounts the directory
    before it exits.
    The test checks the cleanup exit status and reports captured stderr.
    No Platform API, production operation, policy, or timeout changed.
    After all three replacement cases passed, the change removed the namespace
    handles, helper thread, actor-mount methods, and namespace-only check from
    [physical.rs](src/physical.rs). This deletion removes 135 net Rust lines.
    Keep the host-local mount owner for the old subPath case until its shared
    replacement passes. Do not extend that owner. The final exact cases passed
    on Host in 47.33 seconds, runc in 65.38 seconds, and Kubernetes in 124.66
    seconds on 2026-10-02. Each case removed its owned resources. The remaining
    host-local mount cleanup regression passed in 0.03 seconds. Local VM
    harness checks and the related local physical checks passed. Formatting,
    workspace check, and strict Clippy passed. The default Rust CI test step
    stopped at the unchanged CLI `start_builds_surface_launch_plan` test with
    a JSON trailing-characters error. That exact test passed alone without a
    code change. The CLI helper's timestamp-and-PID filename can collide, but
    the cause of this run is not proved. No CLI change is part of this work.
    The full gate with `RUST_TEST_THREADS=1` passed with its normal ignored-test
    exclusions. The three physical cases passed through the separate exact
    `--ignored` commands above. No additional test filter was used.
    The four related CLI tests also passed with distinct paths under tracing.
    This result does not prove or fix the earlier default-CI failure.
    The prior implementation and verification record follows.
    The interim implementation reused the bind-mount owner from the old runc
    runner, the file-mutation actor, and existing policy fixtures. Mount the
    real links directory in the actor namespace. Check its device and inode
    before the action.
    Require `EACCES`, attributed `UNRESOLVED_OBJECT` File/Unlink evidence,
    and the retained real pin in both Protect and Observe modes. Keep the
    standard test below 100 lines. Add no Platform or production API.
    Commit the shared mount owner first. Pass and commit Host, runc, then
    Kubernetes before removing the old self-protection action.
    The shared owner now holds the actor root and mount namespace. Normal
    cleanup keeps a failed target for later cleanup; Drop is a detach fallback.
    Its privileged VM check passes for both mount paths, including failed,
    repeated, and fallback cleanup. Local physical checks and strict Clippy
    pass. The old runc runner uses this owner and loses 34 lines.
    The actor mount path uses Linux `open_tree` and `move_mount`. A short
    helper thread enters the held namespace; the test thread does not change
    namespace. This replaces the failed cross-namespace bind command.
    Privileged cleanup checks, local physical checks, and strict Clippy pass.
    Host passes both modes in 48.95 seconds with the same 86-line test.
    Keep the old unknown-entry actor condition: start the extra actor before
    Node and require `restored_or_unknown_root` with no admitted entry rule.
    The admitted application draft did not preserve that condition and was
    rejected. Both modes require the denial and retained real pin. Resource
    cleanup, 25 related checks, formatting, and strict Clippy pass.
    Direct runc passes both modes in 49.52 seconds with the same actor,
    policies, and 86-line test. Pin, output, lease, and cgroup cleanup pass.
    Strict Clippy passes after platform registration.
    Kubernetes exposed late namespace and root access from outside Node's
    controller cgroup. Lightweight outside-Node observers reproduce both
    `EACCES` results. Hold both handles before Node starts and use the held
    root for inode checks. The unchanged security assertions pass on Host in
    49.07 seconds and runc in 55.81 seconds. The test has 89 lines. Privileged
    mount cleanup and strict Clippy pass. Kubernetes remains open.
    Kubernetes passed the Protect pin check, then denied the second cold
    actor start with `DENY_NODE_UNAVAILABLE`. The existing lightweight runc
    outage test reproduces that retained-gate condition and passes. Create
    both one-action actors before policy protection. Keep one container and
    Node for both modes. Replace only the policy between real unlink attempts.
    Reuse the unchanged Python actor and hold the mount handles. Keep all
    denial, attribution, inode, recovery, and cleanup assertions. Do not add
    a repeat protocol or another setup owner for this retirement.
    The final 93-line test passes Protect and Observe on Host in 42.45 seconds
    and direct runc in 50.51 seconds. The Python actor is unchanged. Hold both
    actors before policy protection; publish the running-container observation
    once. Kubernetes passes both modes in 90.61 seconds. Host checks pre-exec identity
    only for a protected actor, not merely because Node is running. Keep the
    existing protected-actor check; its focused entry-role case passes in
    32.54 seconds. Output, pins, leases, and cgroups are removed on all three
    platforms. All 91 local library tests, harness checks, formatting, and
    strict Clippy pass. Commit Kubernetes before removing the legacy action.
    Retire the old physical runner's unlink block, child operation, and result
    flag after these commits. The shared test retains both modes, the real pin,
    and exact task attribution. This retirement removes 34 Rust lines.
    After removal, all 25 related tests, formatting, and strict Clippy pass.
  - [x] Replace the two pre-protection passed-descriptor reads with
    `passed_files_keep_authority`. Reuse `retained_descriptor.py` and its
    exact-file policy. A child passes each descriptor through `SCM_RIGHTS`
    before Node starts. After recovery, require secret Read `EACCES`, benign
    byte receipt, fresh exact-policy Deny and Allow evidence, distinct object
    selectors, and normal cleanup. Keep the test below 100 lines. Pass and
    commit Host, runc, then Kubernetes before deleting the matching old
    actions. This does not replace the later descriptor-acquisition pair.
    Host passes in 34.40 seconds with the 75-line test. The existing retained
    descriptor case passes in 34.44 seconds. Initial recovery uses the open
    bootstrap policy; the exact policy then replaces it before either read.
    Related effect tests, harness checks, formatting, and strict Clippy pass.
    The final 90-line test compares each event with its production-lowered
    exact selector. Host passes in 34.69 seconds and runc in 40.02 seconds.
    The unchanged existing Kubernetes descriptor case passes in 72.12 seconds.
    The same passed-file test passes on Kubernetes in 76.04 seconds with
    deployed Control, Node, and CRD policy. Cleanup passes on all three
    platforms. Each platform result was committed before legacy removal.
    The retirement removes 69 Rust lines. Two test-only guards keep the
    separate descriptor-transfer exec check. The later acquisition pair stays.
    After removal, all 25 related checks, all 91 local library tests, strict
    Clippy, formatting, and harness checks pass. The unchanged retained-file
    runc case passes in 34.84 seconds.
  - [ ] Replace both exact-file `io_uring` reads with a small shared test.
    Reuse the descriptor policy, Python process owner, and effect observer.
    Keep the retained descriptors, disabled restricted ring, asynchronous
    one-byte read, denied secret, successful control, and Observe result.
    Check every old request field and empty ring, request, and generation
    references after completion. Keep the old actions until all platforms
    pass. Add no Platform or production API.
    The shared Python actor passes the production-backed Host draft in
    35.35 seconds. It closes each ring and mapping with `ExitStack`. The
    draft has 97 lines. All 91 local E2E tests, 25 related effect checks,
    strict Clippy, and formatting pass. Keep Observe and other platforms open.
    The unchanged direct-runc case passes in 34.98 seconds with the real
    OCI hook and complete resource cleanup. Register and commit this platform.
    Both modes now use one explicit test loop, still in 97 lines. Protect
    requires `EACCES`; Observe requires the byte and `WOULD_DENY`. Both keep
    the successful control, all request fields, and cleanup checks. Host
    passes in 42.39 seconds and direct runc in 47.12 seconds. Related effect
    checks, strict Clippy, and formatting pass. Kubernetes remains pending.
    Kubernetes fails before Observe: both reads return `EACCES`, including
    the Allow control. Keep the old block. Its actor files are on the image
    overlay filesystem; Host and runc use plain files. Reproduce that physical
    condition on lightweight Host before a correction or Kubernetes rerun.
    Add failure-only snapshot diagnostics; the test stays below 100 lines.
    The unchanged Host assertion fails on overlay-backed files in 39.82
    seconds. Its Allow event is followed by `CORRUPT_IDENTITY_OR_GENERATION`
    for the same async request. All owned resources are removed and the
    temporary overlay mount is detached. See `/tmp/mithril-io-overlay-light-20261002.log`.
    The old files were in the VM fixture directory, not an image layer.
    Use the existing owned `/work` mount for both files on all platforms.
    Keep the exact selectors, all assertions, and both policy modes. This
    setup change does not fix or qualify overlay-backed async reads. Keep
    that production condition open; no BPF change is authorized here.
    The `/work` draft does not activate its exact policy on Host. Its
    predecessor stays active and activation remains pending. Discard that
    draft and restore the qualified actor and policy inputs. Keep Kubernetes
    unregistered and the legacy block intact. The new failure diagnostic
    preserves the 99-line limit. A BPF correction needs approval; do not
    weaken the Allow control or hide the overlay condition in setup.
  - [ ] Replace the abstract Unix-stream round trip with
    `unix_stream_is_allowed`. Use the existing actor-group setup for two
    distinct bindings under one policy and one shared network namespace.
    Give the client and server distinct policy roles. Keep the real abstract
    stream connect, request byte `1`, response byte `2`, complete readback,
    and absence of a file-create event. Require fresh attributed IPC policy
    Allow evidence for Connect, Send, and Receive. Keep the standard test
    below 100 lines.
    - [x] Use one Python actor file for both roles and all platforms. Create
      the listener after actor startup. Use bounded socket operations and
      the existing process readiness and cleanup. Do not add a Platform API
      or reproduce Node admission or binding publication.
    - [x] Pass and commit Host, then direct runc, then Kubernetes. Keep both
      binding identities, distinct cgroups and roles, and equal installed
      profile generation explicit. The policy must express the original
      client-to-peer relationship through public production inputs.
      - [x] Host passed in 35.36 seconds on 2026-10-01. The 98-line test uses
        one shared Python actor and the public signed Unix-stream policy.
        It checks distinct task cookies, roles, bindings, and cgroups, the
        same network namespace, equal live process generations, both
        exchanged bytes, fresh client-attributed IPC Allow evidence, and
        no file-create event. Output, pin, lease, and both actor cgroups
        were removed. The old round-trip and descriptor checks remain.
        Two earlier drafts compared birth generations and failed before
        connect. `NativeTaskSnapshotV1::profile_generation_ref_id` reads
        the task label's birth generation. The corrected test uses the
        existing `Platform::process` readback for the live generation.
        No Platform, Node, Control, or BPF code changed.
        All 25 non-privileged effect tests and local harness checks passed.
        The final repository Rust CI procedure passed after the last Rust
        edit, including all 91 in-process E2E tests. See
        `/tmp/mithril-unix-host-current-ci-20261001.log`.
      - [x] Direct runc passed in 35.42 seconds on 2026-10-01. The 98-line
        body, actor, policy, and assertions are unchanged. Both roots use
        real runc containers in one network namespace. Output, containers,
        pin, lease, and actor cgroups were removed. No Platform or production
        code changed. See `/tmp/mithril-unix-runc-20261001.log`.
        The final repository Rust CI procedure passed after the platform
        attribute edit. See `/tmp/mithril-unix-runc-final-ci-20261001.log`.
      - [x] Kubernetes passed the 98-line body in 72.76 seconds. The baseline
        audit then added the exact Connect, Send, and Receive Allow set to
        this two-binding round trip. The final 99-line body passed on Host
        in 29.12 seconds, direct runc in 29.89 seconds, and real Kubernetes
        in 64.72 seconds. Every event must match the client task, role, entry
        rule, and live generation with kernel result zero. Both exchanged
        bytes and the no-file-create assertion remain. All resource cleanup
        checks, 25 non-privileged effect tests, and local harness checks
        passed. The final repository Rust CI procedure passed after the
        last Rust edit. See `/tmp/mithril-unix-ops-current-ci-20261001.log`.
        No Platform or production code changed. The earlier socket-pass
        replacement also keeps its three-operation coverage; it does not
        replace this distinct-role, two-binding round trip.
    - [x] Retire the unused legacy `unix_stream_relationship_allowed`
      result field after replacement commit `f97e62f1`. It has no remaining
      shell or Rust consumer. Keep the real connection and its success
      check for descriptor-transfer setup. Keep the no-file-create check
      across those transfers and all Observe checks. The unchanged 99-line
      Host test passed again in 29.08 seconds. Cleanup, all 25 related
      non-privileged effect tests, and local harness checks passed. The final
      repository Rust CI procedure passed after the two-line retirement
      edit. See `/tmp/mithril-unix-retirement-final-ci-20261001.log`.
    - [ ] Keep the Observe round trip and its `WOULD_DENY` result open until
      its own verified replacement exists. Keep SCM_RIGHTS transfers and
      their retained descriptors. Their old round-trip setup establishes
      the connection for descriptor transfer. Keep that setup until the
      descriptor-transfer replacement passes. Retire only independent
      Protect verdict assertions after all three platforms pass.
      - [x] Replace the Observe result with `unix_stream_is_observed`.
        Reuse `unix_stream.py`, actor-group setup, and `EffectCheck`. Keep
        two distinct bindings and roles in one network namespace. Use a
        signed Observe policy with no Unix relationship allowance, as in
        `95775f48`. Require the request byte `1`, response byte `2`, fresh
        attributed `WOULD_DENY` Connect, Send, and Receive results, kernel
        result zero, configured `EACCES`, and no File/Create event. Keep
        the standard test below 100 lines. Add no Platform or production
        API. Pass and commit Host, direct runc, then Kubernetes before
        removing the legacy Observe action and result wait. Keep the Protect
        stream action, descriptor setup, and combined no-file-create assertion.
        The rejected 2026-10-01 Host draft used two admitted initial roots.
        Two Observe-first starts timed out during admission before the socket
        action. A Protect-start draft activated Observe before socket creation,
        but Connect returned `EACCES`. The later evidence wait found no three
        matching `WOULD_DENY` results; its last server results were
        `APPLICATION_DEFAULT_ALLOW`. The cause of the Connect denial is not
        proven. See `/tmp/mithril-unix-observe-evidence-20261001.log`.
        The source comparison also found a setup mismatch. The old client
        binding does not arm an initial root and has no runtime admission.
        The existing admitted-entry IPC path can select application defaults
        before the unmatched relationship. Preserve the unadmitted client
        condition, not only Observe mode. The draft and policy are removed
        from the crate; copies remain under `/tmp/mithril-unix-observe-rejected*`.
        No Platform, Node, Control, or BPF change remains. No Kubernetes run
        occurred. The old byte exchange, Observe evidence, and no-file-create
        assertions remain. Do not claim qualification or extend a deadline.
        All four failed Host runs removed their pin root, lease, cgroup,
        and actor directory. The final repository Rust CI procedure exited
        with status 0 after removal of the draft. The passing in-process
        checks do not qualify this physical Observe case.
        - [ ] Qualify actor-first group setup before the next Observe draft.
          Keep one runtime fact and signed target for each group member,
          including its actual initial PID. Use the existing group, policy,
          and start operations. Do not add a Platform API or reproduce Node
          recovery. The lightweight fixture must supply every member to the
          production owners, as real CRI does. Keep Node-first setup unchanged.
          - [x] Add `group_roles_recover` in `identity/scenarios/group_recovery.rs`.
            Reuse `read_path.py` and `group_roles_policy.json`. Start Control,
            start both application containers in one actor group, install the
            policy, then start Node. Require two `active_recovered` bindings,
            distinct roles, task cookies, bindings, and cgroups. Require the
            same read to succeed for worker and return `EACCES` for helper.
            Keep each actual initial PID and rule attribution explicit. Use
            existing operations and a pristine `group_recovery` lifecycle.
            Keep the file below 100 lines. Run Host before changing tooling.
          - [x] Make the existing lightweight runtime-input owner retain all
            ready group members. Supply each member once after its signed
            target is ready. Do not change runtime identity on policy updates.
            Keep Node-first admission and existing single-actor recovery tests.
            Commit verified tooling before the dependent Observe migration.
          - [ ] Qualify Host, direct runc, and Kubernetes in that order. Add
            each platform to the test attribute only after its focused pass.
            Check Node-first groups, policy replacement, single-actor recovery,
            readiness diagnostics, cleanup, and the complete physical matrix
            after a shared Platform change. Record exact logs and commands.
          The unchanged 98-line body passes on Host in 28.17 seconds, direct
          runc in 29.05 seconds, and real Kubernetes in 74.58 seconds. Before
          the fixture correction, Host activates one target and times out at
          worker recovery with no identity in 58.82 seconds. See
          `/tmp/mithril-group-recovery-before-20261001.log` and the paired
          `/tmp/mithril-group-recovery-{host,runc,kube}-20261001.log` files.
          All four runs remove owned actor resources. Kubernetes leaves only
          the three K3s system Pods. The CRI unit check, strict E2E Clippy,
          VM harness checks, and final repository Rust CI pass. Commit the
          shared tooling after all lightweight cases pass. Keep all three
          qualified recovery platforms enabled. The complete Kubernetes
          matrix remains an open delivery gate.
          The matrix passes all 66 Host identity cases. The next case passes
          its assertions but fails Node shutdown. A focused repeat confirms
          the failure. Restore the previous snapshot request runtime: the
          same case passes in 34.98 seconds and removes its resources. Keep
          the 30-second shutdown limit. The shared runtime left a gRPC
          transport task pending during shutdown. See
          `/tmp/mithril-snapshot-{before,after}-20261001.log`. Continue the
          matrix from its completed cases; do not repeat the passing group.
          The next lifecycle passes four cases but `clean_host_restarts`
          finds the retained Node pin root. This kernel-owner test requires
          an empty root and does not start Node. Give it `kernel_start`;
          keep the other four tests on their shared lifecycle. Its unchanged
          body passes in 26.47 seconds with pin, lease, and cgroup cleanup.
          See `/tmp/mithril-kernel-start-host-20261001.log`.
          All 152 registered Host cases now pass across the continued run
          and the two focused corrections. All 143 direct-runc cases pass.
          Kubernetes stops after one prepared-mount case passes and two fail
          during actor creation. The retained runtime gate correctly denies
          a new actor while Node is stopped. These three cases require mount
          preparation before the first Node start. Give propagation and
          setattr separate cold-start lifecycles; keep their bodies, actor,
          policy, and assertions unchanged. All three cases pass on Host and
          runc. Kubernetes passes in 72.82, 71.54, and 66.95 seconds. Resource
          cleanup, VM harness checks, and final Rust CI pass. See
          `/tmp/mithril-mount-cold-{light,kube,kube-remaining,ci}-20261001.log`.
          Continue only the 32 unfinished Kubernetes cases in 24 groups.
          The continuation passes nine groups, then three recovered-entry
          cases fail at actor creation with the same retained-gate denial.
          Give readiness order, bootstrap exec, and scoped ptrace separate
          cold-start lifecycles. The socket-transfer Allow and Deny pair has
          the same actor-first requirement; separate those lifecycles too.
          Keep all bodies and assertions unchanged. Verify affected Host and
          runc cases before Kubernetes, then resume the unfinished groups.
          All seven applicable Host and runc checks pass. All four affected
          Kubernetes checks pass, with resource cleanup. Harness checks and
          final Rust CI pass. See `/tmp/mithril-cold-recovery-{light,kube,ci}-20261001.log`.
          The continuation now has 129 passing Kubernetes cases of 143.
          Run only the remaining 14 cases. Do not restart passed groups.
          All 14 remaining cases pass with cleanup. The registered matrix
          now passes all 152 Host, 143 runc, and 143 Kubernetes cases across
          the continuation logs. See `/tmp/mithril-matrix-kube-last-20261002.log`.
          New leaf scenarios require their focused checks, not another matrix.
          The continuation logs are
          `/tmp/mithril-group-recovery-matrix-{final,remaining}-20261001.log`.
          It contains 152 Host, 143 runc, and 143 Kubernetes cases. Only the
          unrelated uncommitted `file_gate` draft is excluded. No committed
          scenario is excluded. See
          `/tmp/mithril-group-recovery-matrix-20261001.log`. No Node, Control,
          BPF, public Platform API, actor, or policy source changes are made.
          The 97-line Observe replacement passes on Host, runc, and Kubernetes.
          It reuses `bpf_recovery`: start Control and Node, start unprotected
          actors, then install policy. Socket creation still occurs after
          policy activation. Linux read and write deadlines remain five seconds.
          Kubernetes exec now waits in the actual `worker` cgroup, not the
          first group member's cgroup. The namespace check runs before policy
          installation. The 53-line `unowned_read_is_denied` test reproduces
          the outside-observer denial on all three platforms. No observer
          permission, production source, or Platform API changes are made.
          Read [the scenario](src/effect/unix_observe.rs),
          [the actor](fixtures/process/unix_stream.py), and
          [the observer check](src/effect/proc_observer.rs).
          All four lifecycle tests pass in 60.30 seconds on Host, 66.89 seconds
          on runc, and 157.80 seconds on Kubernetes. Pin, lease, output, and
          cgroup cleanup checks pass. All 91 local tests and strict release
          Clippy pass. See `/tmp/mithril-unix-shared-{light,kube}-20261002.log`.
          The Allow companion passes on Host and runc. Its Kubernetes first
          `ctypes._endian` import fails before the modified socket action.
          Keep this issue open; see `/tmp/mithril-unix-allow-kube-20261002.log`.
          Keep SCM_RIGHTS and the Protect-mode stream setup unchanged.
          The old Observe action and evidence wait are removed. The combined
          Protect no-file-create assertion remains. All 25 related effect
          tests, VM harness checks, and final repository Rust CI pass after
          the Rust edit. See `/tmp/mithril-unix-observe-retirement-ci-20261002.log`.
  - [x] Replace the remaining Observe-mode descriptor exec with
    `forked_fd_exec_is_observed`. Reuse `exec_on_release.py`, the process
    owner, and `EffectCheck`. Use a distinct signed Observe policy for the
    same external-role executable Deny as the Protect case.
    - Keep the descriptor open before Node starts. Recover the rule-zero
      external actor, fork its child, and inspect both identities before
      releasing descriptor exec. Keep the child creator, inherited role,
      distinct cookie, and zero admission rule explicit.
    - Require fresh child-attributed `WOULD_DENY` Exec/Execute evidence with
      kernel result zero, configured `EACCES`, nonzero composite atom, and
      zero exact-object and inode fields. The old test does not require the
      later dynamic loader or executable to succeed. Do not replace this
      signed decision with a runtime-entry Allow or Protect-mode denial.
    - Use one shared test below 100 lines and a pristine
      `exec_observe_recovery` lifecycle. Add no Platform or production API.
      Pass Host, direct `runc`, and Kubernetes in separate commits. Keep the
      legacy block until all three pass. Then remove only its Observe branch;
      keep descriptor transfer, positive controls, and executable mappings.
    - Compare with `95775f48`. Run focused actor regressions, local harness
      checks, and final Rust CI. Do not rerun an unrelated physical matrix.
    - [x] Host passed in 29.00 seconds. The 76-line test preserves the
      rule-zero recovered actor, fork, real descriptor exec, and all four
      baseline path-object fields. It adds child attribution, creator and
      role assertions, kernel result zero, and configured `EACCES`.
      The unchanged Protect companion passed in 28.12 seconds. Pin, lease,
      cgroup, and output cleanup passed. Strict E2E Clippy, formatting, and
      VM harness checks passed. No actor, Platform, or production source
      changed. The old Observe branch remains until all platforms pass.
    - [x] Direct `runc` passed in 28.98 seconds with the unchanged 76-line
      body. Pin, lease, cgroup, and output cleanup passed. Formatting passed.
      No actor, Platform, or production source changed.
    - [x] Kubernetes passed in 68.23 seconds after Host and direct `runc`.
      The same body used real Control, Node, recovery, and pod exec.
      The actor namespace and scenario output path were removed. Formatting
      passed. No actor, Platform, or production source changed.
    - [x] Remove the matched legacy branch and both unused path observation
      helpers after all three platforms pass. This removes 64 Rust lines
      net. Descriptor transfer, positive controls, and executable mappings
      remain. The repository Rust CI gate and local VM harness checks pass.
      Rust CI includes all 91 non-privileged E2E tests; its 441 ignored
      physical tests are not a physical qualification result. The new case
      passed separately on all three platforms. No unrelated physical matrix
      rerun is needed for the matched deletion. `effect.rs` has 2,812 lines
      and `effect/support.rs` has 936 lines. The large runners remain open.
  - [x] Replace `MemfdMprotectExec` with `memfd_mprotect_is_denied`.
    Reuse the exec actor, executable memfd preparation, signed exec policy,
    process owner, and evidence owner. Use the same Linux `MFD_EXEC` flag
    as the old fixture. Copy the full ELF image and map it read-only with
    `MAP_PRIVATE` before Node starts. Retain the descriptor and mapping.
    Check the memfd link, ELF header, executable mode, and actual `r--p`
    mapping. Retain the read-only proc maps descriptor before recovery.
    After production recovery, call real `mprotect(PROT_READ | PROT_EXEC)`.
    Require actor `EACCES`, fresh attributed `UNSUPPORTED_OBJECT`
    Exec/Mprotect evidence, and every legacy zero-object field. Check
    unmapping, descriptor close, actor exit, and normal cleanup. Keep the
    single-test file below 100 lines. Add no Platform or production API.
    Use a pristine `memfd_map_recovery` lifecycle.
    - [x] Add the memory mode to the shared exec actor and verify its callers.
      Reuse memfd creation, byte copy, mapping, mprotect, unmapping, descriptor
      close, errno report, and release wait. Host passed the new case in
      28.28 seconds. The unchanged deleted mapping and memfd exec cases
      passed in 34.26 and 34.48 seconds. All cleanup checks and the final
      repository Rust CI passed. No Platform or production code changed.
    - [x] Host passed in 28.28 seconds with the retained executable memfd,
      actual read-only mapping, real mprotect denial, fresh evidence,
      every legacy zero-object field, unmapping, descriptor close, actor
      exit, and cleanup. The final repository Rust CI passed. The single-test
      file has 93 lines. No Platform or production code changed.
    - [x] Direct `runc` passed in 29.35 seconds with the same retained memfd,
      read-only mapping, real mprotect denial, fresh evidence, and mapping
      and descriptor cleanup. Pin, lease, and cgroup cleanup passed.
      The final repository Rust CI passed. No Platform or production code
      changed.
    - [x] Kubernetes passed in 72.54 seconds with the same retained memfd,
      read-only mapping, real mprotect denial, fresh evidence, and mapping
      and descriptor cleanup. Namespace, pin, and lease cleanup passed.
      The final repository Rust CI passed. No Platform or production code
      changed. The test has 93 lines.
    - [x] Remove only the matched legacy action, memfd mapping resources,
      and unused memfd copy helper after all three platforms pass. Keep
      exact-file mappings and their positive controls.
      Remove the unsupported-object observation helper only after its last
      caller is replaced. Remove only its assertions from the combined
      matcher unit test. Keep the exact-object and operation-argument checks.
      The retirement removes 103 Rust lines net. The action, retained memfd,
      mapping, copy helper, and unused observation helper are removed. All
      25 non-privileged effect regressions, the focused exact matcher, and
      the final repository Rust CI pass. Unsupported-object fields stay
      explicit in the new physical tests. Exact-object and io_uring checks
      remain in the old support owner. No physical matrix rerun is required
      for this matched deletion. `effect.rs` has 2,907 lines,
      `effect/child.rs` has 2,715 lines, and `effect/fixture_syscalls.rs` has
      740 lines. The large runners remain incomplete.
  - [x] Replace `DeletedMprotectExec` with `deleted_mprotect_is_denied`.
    Reuse the exec actor, deleted-image preparation, signed exec policy,
    process owner, and evidence owner. Map the complete executable read-only
    with `MAP_PRIVATE` before Node starts. Keep the mapping and descriptor
    live after the path is unlinked. Check the ELF bytes, absent path, and
    actual read-only deleted mapping through Linux proc files. After production
    recovery, call real `mprotect(PROT_READ | PROT_EXEC)`. Require actor
    `EACCES`, fresh attributed `UNSUPPORTED_OBJECT` Exec/Mprotect evidence,
    and all legacy zero-object fields. Check unmapping, actor exit, and
    normal cleanup. Keep the single-test file below 100 lines. Add no Platform
    or production API. Use a pristine `deleted_map_recovery` lifecycle.
    - [x] Add the one memory operation to the shared exec actor. Reuse its
      copied image, descriptor, release wait, errno report, and cleanup.
      Keep mapping before unlink and before readiness. The real Host case
      passed in 28.44 seconds. The unchanged descriptor-exec mode passed in
      33.73 seconds. Pin, lease, and cgroup cleanup passed. The final
      repository Rust CI passed. No production or Platform code changed.
    - [x] Host passed in 28.44 seconds with the retained ELF descriptor,
      absent path, actual read-only deleted mapping, `EACCES`, fresh
      Exec/Mprotect evidence, every legacy zero-object field, unmapping,
      descriptor close, actor exit, and cleanup. The final repository Rust
      CI passed. The single-test file has 89 lines.
    - [x] Direct `runc` passed in 28.11 seconds with the same retained image,
      read-only deleted mapping, real mprotect denial, fresh evidence, and
      mapping and descriptor cleanup. Pin, lease, and cgroup cleanup passed.
      The final repository Rust CI passed. No Platform or production code
      changed.
    - [x] Kubernetes passed in 71.37 seconds with the same retained image,
      read-only deleted mapping, real mprotect denial, fresh evidence, and
      mapping and descriptor cleanup. Namespace, pin, and lease cleanup
      passed. The final repository Rust CI passed. No Platform or production
      code changed. The test has 93 lines.
      The first case returned `EACCES` without an operation or path. Keep
      the old case. Check an outside-controller proc reader in lightweight
      after the denied syscall completes, before a fix or Kubernetes rerun.
      The Host reproduction passed in 28.82 seconds. After the actor reported
      `EACCES` and the fresh effect arrived, an outside-controller reader
      could not open its proc maps. The trusted reader could. Open the
      read-only maps descriptor before recovery and reuse it for the cleanup
      check. Do not change production permissions or skip the assertion.
      The revised 93-line case passed on Host in 28.21 seconds and direct
      `runc` in 27.71 seconds. Both cleanup checks passed. Descriptor absence
      now uses fallible `try_exists`; permission errors are not absence.
      The final repository Rust CI passed. No Platform or production code
      changed. The unchanged Kubernetes rerun then passed.
      The user accepted this lightweight reproduction on 2026-10-01.
    - [x] Remove only the matched legacy action and deleted mapping resources
      after all three platforms pass. Keep memfd and exact-file mappings.
      Remove the deleted-image actor-only fixture test after the replacement
      proves a retained ELF descriptor, read-only mapping, and absent path.
      Keep all unrelated child regressions.
      The retirement removes 102 Rust lines net. The copied deleted image,
      request field, retained descriptor, mapping, enum arm, and actor-only
      fixture test are removed. All eight remaining child regressions and
      the final repository Rust CI pass. No physical matrix rerun is required
      for this matched deletion. `effect.rs` has 2,927 lines and
      `effect/child.rs` has 2,744 lines. The large runners remain incomplete.
  - [ ] Preserve the remaining exact-file executable mmap and read/write
    mprotect cases until public policy inputs can express their exact object
    selector. `ExecutionRuleV1` has no `exact` field, and Kubernetes lowering
    calls `path_selector_id` with `exact=false` for execution rules. A path
    composite is not the baseline `manual-secret` exact-object result. Do not
    weaken the assertion, add a test-only policy path, or change production
    policy types in this migration.
  - [x] Replace `NonLeaderExec` with `thread_exec_is_denied`. Keep the
    baseline fork-then-pthread condition and real descriptor exec. Reuse
    the signed exec policy, exec actor, process owner, and evidence owner.
    Hold the executable before Node starts. After production recovery, fork
    the child and create one worker thread. Use the existing child, namespace
    TID, host TID, and thread-coordinate waits. Check both creator edges,
    distinct task cookies, the worker's TGID, and its shared process state.
    Require worker-thread `EACCES` and fresh worker-attributed
    `EXACT_POLICY_DENY` Exec/Execute evidence with the inherited role,
    generation, zero entry rule, and every legacy path-object field.
    Keep the single-test file below 100 lines and use a fresh
    `thread_deny_recovery` lifecycle. Add no Platform or production API.
    - [x] Extend the existing `ProcessFixture::wait_thread` to accept an
      absent namespace TID. Select the first non-leader task from Linux
      `/proc/<pid>/task`, then read its namespace TID from Linux status.
      Keep all known-TID callers unchanged. Do not require a restricted
      worker to create or write a report file. Host traces show `EACCES` for
      both report operations. Check the known-TID wait with `tid_reuse`.
      The new worker discovery passed the real Host exec case. The unchanged
      known-TID reuse case passed in 34.12 seconds. Pin, lease, and cgroup
      cleanup passed. The final repository Rust CI passed.
    - [x] Host passed in 27.85 seconds with both creator edges, distinct
      cookies, shared process state, actual worker `EACCES`, and fresh
      worker-attributed denial fields. Pin, lease, and cgroup cleanup passed.
      The existing leader descriptor-exec case passed in 27.10 seconds.
      The script positive control and denial passed in 29.13 seconds.
      The final repository Rust CI passed. The single-test file has 95 lines.
    - [x] Direct `runc` passed in 28.87 seconds with the same fork, thread,
      creator, process-state, syscall, and fresh evidence assertions.
      Pin, lease, and cgroup cleanup passed. The final repository Rust CI
      passed. No Platform or production code changed.
    - [x] Kubernetes passed in 70.30 seconds with the same fork, thread,
      creator, process-state, syscall, and fresh evidence assertions.
      Namespace, pin, and lease cleanup passed. The final repository Rust
      CI passed. No Platform or production code changed.
    - [x] Remove only the matched legacy action, result, and unused pthread
      helper after all three platforms pass. Keep ordinary descriptor exec
      and all unrelated identity and memory assertions.
      The retirement removes 72 Rust lines net. Ordinary `Exec` keeps the
      same fork and real descriptor syscall for Observe mode and descriptor
      transfer. All nine child regressions and the final repository Rust CI
      pass. No physical matrix rerun is required for this matched deletion.
      `effect.rs` has 2,938 lines, `effect/child.rs` has 2,833 lines, and
      `effect/fixture_syscalls.rs` has 754 lines. The large runners remain
      incomplete.
  - [x] Replace `MemfdExec` with `memfd_exec_is_denied`. Reuse the shared
    exec actor, signed exec policy, process owner, and evidence owner. Before
    Node starts, create a memfd with Linux `MFD_EXEC`, copy the executable
    bytes, and hold its descriptor. Check the memfd link, ELF header, and
    executable mode in the Rust test. After production recovery, check the
    forked child's cookie, creator, inherited role, and zero entry rule.
    Require descriptor-exec `EACCES`, fresh child-attributed
    `UNSUPPORTED_OBJECT` Exec/Execute evidence, both legacy zero-object
    fields, and zero inode fields. Keep the file below 100 lines and use a
    fresh `memfd_recovery` lifecycle. Add no Platform API or duplicate policy.
    - [x] Host passed in 29.18 seconds. The actual executable memfd, ELF
      bytes, mode, child identity, `EACCES`, and fresh zero-object evidence
      passed. Pin, lease, and cgroup cleanup passed. The final repository
      Rust CI passed. The single-test file has 91 lines.
    - [x] Direct `runc` passed in 28.81 seconds with the same memfd, ELF,
      mode, child identity, syscall, and evidence checks. Pin, lease, and
      cgroup cleanup passed. The final repository Rust CI passed.
    - [x] Kubernetes passed in 71.16 seconds with the same memfd, ELF,
      executable mode, child identity, syscall, and evidence checks.
      Namespace, pin, and lease cleanup passed. The final repository Rust
      CI passed. No Platform or production code changed.
    - [x] Remove the matched legacy exec action and result only after all
      three platforms pass. Keep the memfd mapping, descriptor, preparation
      helper, and mprotect assertions for their separate memory migration.
      The retirement removes 23 Rust lines net. The descriptor remains owned
      by `_memfd_file` for the unchanged mapping controls. All nine child
      regressions, the local VM launcher verifier, and the final repository
      Rust CI pass. No physical matrix rerun is required for this deletion.
      `effect.rs` has 2,955 lines and `effect/child.rs` has 2,839 lines.
      Both legacy runners remain incomplete.
  - [x] Replace `DeletedExec` with `deleted_exec_is_denied`. Reuse
    `exec_on_release.py`, `exec_deny_policy.json`, and the common process and
    evidence owners. Before Node starts, copy the runtime's ELF executable,
    open it, and unlink its path. Check the retained deleted descriptor,
    executable mode, ELF header, and absent pathname in the shared Rust test.
    After production recovery, fork a child and check its distinct cookie,
    parent creator, inherited role, and zero entry rule before release.
    Require real descriptor-exec `EACCES` and fresh child-attributed
    `UNSUPPORTED_OBJECT` Exec/Execute evidence. Keep both legacy zero-object
    fields and require zero inode fields. Keep the single-test file below
    100 lines. Use a fresh `deleted_recovery` lifecycle.
    - [x] Host passed in 28.78 seconds with the deleted executable descriptor,
      ELF and mode checks, actual `EACCES`, child attribution, and fresh
      zero-object evidence. Pin, lease, and cgroup cleanup passed. The final
      repository Rust CI passed. The test file has 95 lines.
    - [x] Direct `runc` passed in 28.58 seconds with the same actor, policy,
      descriptor checks, and denial assertions. Pin, lease, and cgroup cleanup
      passed. The final repository Rust CI passed. No Platform API changed.
    - [x] Kubernetes passed in 68.54 seconds with the same actor, policy,
      descriptor checks, and denial assertions. Namespace, pin, and lease
      cleanup passed. The final repository Rust CI passed. No Platform or
      production code changed. The retained cluster remains available.
    - [x] Remove only the matched legacy exec action and result after all
      three platforms pass. Retain the deleted mapping, pathname setup, and
      shared descriptor resources until their separate memory tests pass.
      The retirement removes 22 Rust lines net. The descriptor remains owned
      by `_deleted_file` for the unchanged mapping controls. All nine child
      regressions and the final repository Rust CI pass. No Platform or
      production code changed. `effect.rs` has 2,971 lines and
      `effect/child.rs` has 2,844 lines. Both legacy runners remain incomplete.
  - [x] Replace the denied `ScriptExec` action with `forked_script_is_denied`.
    Reuse `exec_on_release.py` with its existing path and forked-path modes.
    Add one executable Python shebang target and one distinct signed policy
    that denies that script path. Copy the target into the shared `/work`
    mount. Before Node starts, execute the script and require success plus
    its output marker. Remove the marker. After production recovery, require
    a distinct child cookie, correct creator, inherited role, and zero entry
    rule before release. Require actual `EACCES`, fresh child-attributed
    `EXACT_POLICY_DENY` Exec/Execute evidence, every legacy path-object field,
    and no script output marker. Keep the single-test file below 100 lines.
    - [x] Host passed in 27.86 seconds. The valid-script control, denied
      syscall, fresh child evidence, legacy object fields, and absent marker
      passed. Pin, lease, and cgroup cleanup passed. The final repository
      Rust CI passed. The test file has 99 lines. No Platform API changed.
    - [x] Direct `runc` passed in 28.88 seconds with the same actor, policy,
      and assertions. Pin, lease, and cgroup cleanup passed. The final
      repository Rust CI passed. No runtime fixture changed.
    - [x] Kubernetes passed in 69.74 seconds with the same test, actor,
      policy, and assertions. Namespace, pin, and lease cleanup passed.
      The final repository Rust CI passed. No Platform or production code
      changed. The retained VM, K3s cluster, and image cache remain available.
    - [x] Remove the matching legacy script action, enum arm, result field,
      embedded shell source, stored path, and unused path-exec helper only
      after all three platforms pass. Keep descriptor exec, executable mmap,
      mprotect, and non-leader exec resources and their assertions.
      The retirement removes 65 Rust lines net. It removes the embedded shell
      target and its signed selector. The new physical positive control
      replaces the obsolete path-helper control. The original descriptor
      transfer and exec checks remain. All nine child regressions pass.
      The first retirement CI found a one-element non-leader loop after the
      script action was removed. The remaining denial and path-object checks
      now use direct calls. The final repository Rust CI passes after this
      correction. No physical matrix rerun is required for this deletion.
      `effect.rs` has 2,987 lines and `effect/child.rs` has 2,848 lines.
      Both legacy runners remain incomplete.
    - Use a fresh `script_recovery` lifecycle for actor-before-Node setup.
      Keep the target and policy shared across all three environments.
  - [x] Replace the denied `Execveat` action with `forked_at_exec_is_denied`.
    Reuse `exec_on_release.py`, `exec_deny_policy.json`, `ProcessFixture`, and
    `EffectCheck`. Add a real libc `execveat` mode with `AT_FDCWD`, an absolute
    executable path, and flags zero. Keep the baseline fork-before-exec order.
    Start the actor before Node, then use production recovery. Require a
    distinct child cookie, correct creator, inherited role, and zero entry
    rule. Require actual `EACCES`, fresh child-attributed `EXACT_POLICY_DENY`
    Exec/Execute evidence, a nonzero composite atom, and zero exact-object
    key, inode, and inode generation. Keep the Rust file below 100 lines.
    - [x] Host passed in 27.41 seconds with actual `execveat` errno, fresh
      child-attributed denial, creator and role checks, and every legacy
      path-object field assertion. Pin, lease, and cgroup cleanup passed.
      The final repository Rust CI passed.
    - [x] Direct `runc` passed in 28.54 seconds with the same actor, policy,
      child attribution, syscall errno, and object-field assertions. Pin,
      lease, and cgroup cleanup passed. The final repository Rust CI passed.
    - [x] Kubernetes passed in 69.33 seconds with the same actor, policy, and
      assertions. Namespace, pin, and lease cleanup passed. The final
      repository Rust CI passed. No Platform or production API changed.
    - [x] Remove only the legacy `Execveat` action, enum arm, and result field
      after all three platforms pass. Keep script exec and its shared path
      fixture. Remove the syscall helper's unused `execveat` branch only after
      the replacement passes; retain real path exec for script exec.
      The retirement removes 16 Rust lines net. It deletes the unused stored
      executable path, not the constructor input needed for descriptors and
      mappings. The first retirement CI failed on that unused field; the
      corrected source passes all nine child regressions and the final Rust
      CI. The existing native control now checks path exec as well as its
      original descriptor transfer and exec. Its shorter name is
      `exec_and_transfer_work`.
      `effect.rs` remains at 3,004 lines and `effect/child.rs` at 2,875 lines.
      Neither remaining legacy runner is done.
    - Use a fresh `exec_at_recovery` lifecycle. An actor-before-Node case
      cannot inherit the installed runtime gate from another scenario.
  - [x] Replace the denied `Execve` action with `forked_path_exec_is_denied`.
    Reuse `exec_on_release.py`, `exec_deny_policy.json`, and the existing
    process and evidence owners. Add a forked path mode to the actor. Start
    the actor before Node, then use production recovery. Observe the child
    cookie, creator, role, and zero entry rule before releasing path exec.
    Require actual `EACCES`, fresh child-attributed `EXACT_POLICY_DENY`
    Exec/Execute evidence, a nonzero composite atom, and zero exact-object
    key, inode, and inode generation. Keep the Rust file below 100 lines.
    - [x] Host passed in 28.23 seconds with the actual child syscall errno,
      creator and role assertions, fresh denial, and every legacy path-object
      field assertion. Pin, lease, and cgroup cleanup passed.
      The existing forked descriptor case passed in 27.33 seconds after the
      actor's two opt-in branch changes. The final repository Rust CI passed.
    - [x] Direct `runc` passed in 28.63 seconds with the same actor, policy,
      child attribution, errno, and object-field assertions. Pin, lease, and
      cgroup cleanup passed. The final repository Rust CI passed.
    - [x] Kubernetes passed in 71.88 seconds with the same actor, policy, and
      assertions. Namespace, pin, and lease cleanup passed. The final
      repository Rust CI passed. No Platform API or production source changed.
    - [x] Remove only the legacy `Execve` enum arm, action, and result field
      after all three platforms pass. Keep `Execveat`, script exec, and their
      shared path fixture and syscall helper.
      The retirement deletes seven Rust lines. Nine child regressions and the
      final repository Rust CI passed after the last Rust edit. `effect.rs`
      had 3,005 lines at this retirement; `effect/child.rs` had 2,874 lines. Neither
      remaining legacy runner is done.
    - Use a fresh `exec_path_recovery` lifecycle. Actor-before-Node cases
      cannot inherit a previous installed admission policy while Node is down.
      Keep the ordinary Node-first cases in their existing shared lifecycles.
  - [x] Replace the denied `Fexecve` action with `forked_fd_exec_is_denied`.
    Use `exec_on_release.py` with a forked descriptor mode and one signed
    execution-Deny policy. Hold the descriptor before Node starts. After
    recovery, fork the child and observe its inherited role and creator before
    releasing its real descriptor exec. Require actor `EACCES`, fresh
    child-attributed `EXACT_POLICY_DENY` Exec/Execute evidence, a nonzero
    composite atom, and zero exact-object key, inode, and inode generation.
    Keep the Rust file below 100 lines. Add no Platform or production API.
    - [x] Host passed in 28.07 seconds. The 80-line test requires actual
      `EACCES`, the child's fresh exact-deny evidence, and every legacy object
      field assertion. Pin, lease, and cgroup cleanup passed.
      The existing descriptor-Allow and path-exec Host cases passed in 27.37
      and 34.04 seconds. The final repository Rust CI procedure passed.
    - [x] Direct `runc` passed in 28.48 seconds with the same actor, signed
      policy, and assertions. Pin, lease, and cgroup cleanup passed.
      The existing descriptor-Allow and path-exec runc cases passed in 34.29
      and 33.48 seconds. The final repository Rust CI procedure passed.
    - [x] Kubernetes passed in 71.21 seconds with the same actor, signed policy,
      and assertions. Namespace, pin, and lease cleanup passed. Keep the other
      exec modes in the old runner until their replacements pass.
      The existing descriptor-Allow and path-exec Kubernetes cases passed in
      69.13 and 114.77 seconds. Their namespace, pin, and lease cleanup passed.
      The final repository Rust CI procedure passed.
    - [x] Remove only the legacy `Fexecve` action, enum arm, and result field
      after all three platforms pass. Keep `Exec`, `Execveat`, and non-leader
      descriptor exec and their shared descriptor and libc helper.
      The retirement deletes seven Rust lines. Nine child regressions and the
      final repository Rust CI procedure passed after the last Rust edit.
      At this retirement, `effect.rs` had 3,006 lines and `effect/child.rs`
      had 2,878 lines.
      Their remaining actions still require migration; neither runner is done.
    - The retained domain `mithril-runtime-qualification-955601` is shut off.
      Its configured `/tmp/mithril-recovered-vm.RSYqtR/root.qcow2` is absent.
      The existing `--manual` launcher created the retained test-only domain
      `mithril-runtime-qualification-13979`. Its source mount, current images,
      and K3s state remain available for later iterations. Do not try to
      restart the domain with the missing disk.
    - The first draft made the governed child read stdin before exec. That
      added read returned `EACCES`; it is not an exec defect. The actor now
      uses the existing release-file pattern. Its parent reaps the child before
      exit, so cleanup must observe parent exit before child disappearance.
      No assertion, production owner, or process fixture was changed.
  - [x] Replace the protected action-level executable Allow that cannot admit
    an undeclared runtime entry. Reuse `ready.py`. Give the distinct signed
    policy an external-role Allow for `/usr/bin/sleep` but no `sleep` entry
    declaration. Start Control and Node,
    install the signed policy, start the actor, and try `add_actor("sleep")`.
    Require physical `EACCES`, fresh attributed Exec/Execute
    `EXACT_POLICY_ALLOW` path evidence, and a matching
    `UNSUPPORTED_OBJECT` denial. Keep the test below 100 lines and add no
    Platform or production API.
    - [x] Pass Host and commit the test. The exact privileged case passed in
      44.37 seconds in the retained VM. After same-task event pairing, Host
      passed again in 33.11 seconds.
    - [x] Pass direct `runc` and commit its platform registration. The exact
      case passed in 54.60 seconds through stock `runc` and the OCI hook.
    - [x] Pass Kubernetes and commit its platform registration. The exact
      case passed in 81.36 seconds in retained K3s; the launcher exited 0.
    - [x] Preserve the old `fexecve` variant before retirement. The new
      `add_actor` case proves runtime entry, but the legacy action calls
      `fexecve` from a recovered external actor. Reuse the Python exec actor
      with a file-descriptor mode and require the same two decisions on all
      three platforms. The separate denied-`fexecve` case uses
      `forked_fd_exec_is_denied`; its matched legacy action is removed.
      - [x] Pass Host and commit. The actor opened the executable before Node
        policy activation, then tried file-descriptor exec after recovery.
        The exact case passed in 40.68 seconds with physical `EACCES` and
        attributed Allow-then-deny Exec evidence.
      - [x] Pass direct `runc` and commit its registration. The exact case
        passed in 43.09 seconds through stock `runc` and the OCI hook.
      - [x] Pass Kubernetes and commit its registration. The first exact run
        stopped at the actor exit check: `kubectl exec` returned status 1,
        not 13. A transport-only `kubectl exec` diagnostic preserved status
        13. Direct containerd used the same Python image and completed
        file-descriptor exec without Mithril. The cause of the protected
        Kubernetes result is not yet proven. Do not weaken this assertion or
        rerun the case before reproducing the condition in lightweight.
      - [x] Reproduce the actor/transport distinction in lightweight before
        the next Kubernetes run. `process::tests::transport_waits_for_actor`
        passed in 0.03 seconds. A transport exits with status 1 while its
        actor remains alive and later exits with status 0. The transport
        status is not the actor status. The Kubernetes added-actor path
        records the actor PID but has no actor exit-status probe.
      - [x] Report the real exec errno before actor exit. Reuse the existing
        actor name wait and release file. Close the executable descriptor
        before reporting the result. Keep immediate exit for the other
        `exec_on_release.py` caller. Keep physical `EACCES`, the attributed
        Allow and denial, and all object and entry assertions. Verify Host
        and direct `runc` before Kubernetes. Add no Platform or production
        API. This check does not yet explain the previous Kubernetes result.
        Host passed in 28.38 seconds and direct `runc` passed in 31.51
        seconds. Both require the actual syscall errno 13 and the same-task
        Allow and denial. Cleanup passed. The other exec-actor caller kept
        its immediate-exit behavior and passed on Host in 43.29 seconds and
        direct `runc` in 62.08 seconds. The shared Rust file has 82 lines.
        The other caller also passed on Kubernetes in 82.37 seconds, and its
        namespace, pin root, and lease were removed. The repository Rust CI
        gate passed after the final Rust edit.
        The corrected fd-exec case passed Kubernetes in 75.62 seconds with
        actual errno 13, both attributed decisions, and entry rule zero.
        Namespace, pin root, and lease cleanup passed. The repository Rust
        CI gate passed after registration. No production or Platform API
        changed. The old transport-status failure does not qualify as a
        production admission failure.
    - [x] Remove only the matching legacy action, result field, and unused
      fixture state after the `fexecve` case passes on all three platforms.
      Compared with baseline `95775f48`, the replacement retains physical
      `EACCES`, the action Allow, and the independent entry denial. It also
      requires same-task attribution and entry rule zero. The retirement
      deletes 57 Rust lines: the action, result flag, enum variant, request
      argument, path field, and prepared descriptor. Nine child regressions
      passed in 0.01 seconds. Keep the separate denied-`fexecve` actions.
      Keep the legacy executable path fixture: the signed policy still uses
      it, and independent unit checks require its mmap/mprotect Allow cells.
      The repository Rust CI procedure passed after the retirement edit.
      This includes formatting, workspace checking, strict Clippy, and
      workspace tests. No physical matrix rerun was needed for this deletion.
  - [x] Replace the old SQPOLL check for a restricted rule-zero actor in
    Protect and Observe modes. The old binding sets `arm_initial_root=false`.
    The existing Protect platform test covers the same recovered rule-zero
    condition. Reuse `sqpoll.py` and signed policies. Require a physical
    `io_uring_setup` denial and attributed `UNSUPPORTED_OBJECT`
    Privilege/IoUringSqpoll evidence. Add no Platform or production API.
    - [x] Protect passed on Host, direct `runc`, and Kubernetes in separate
      verified commits before this row was added.
    - An admitted-actor Host draft created the ring. The BPF gate permits an
      exact admitted application. That draft tested a different condition
      and was removed before commit.
    - [x] Pass Observe on Host. The 61-line test passed in 40.10 seconds in
      the retained VM with the real syscall and attributed denial. Reuse the
      existing `memory_observe.json` policy; `file_observe.json` needs an
      unrelated exact file and stayed activation-pending in the first draft.
      Before lifecycle separation, both passed together on Host in 64.89
      seconds.
    - [x] Pass the same Observe test on direct `runc` and commit it. The exact
      case passed in 48.70 seconds through stock `runc` and the production
      OCI hook. Before lifecycle separation, both passed together on direct
      `runc` in 86.63 seconds.
    - [x] Pass the same Observe test on Kubernetes and commit it. The final
      exact case passed in 125.44 seconds and the VM command exited with 0.
      The final separate-lifecycle case also passed on Host in 31.05 seconds
      and direct `runc` in 38.79 seconds.
      The exact Kubernetes case passed in 81.12 seconds. A two-test lifecycle
      run then passed Protect and denied the next Pod while Node was stopped.
      The OCI hook reported `DENY_NODE_UNAVAILABLE`. The existing direct-`runc`
      `runtime_gate_fails_closed` test reproduced that decision in 38.33
      seconds. Observe now has its own lifecycle. Its actor-first recovery
      order and SQPOLL assertions are unchanged.
    - [x] Remove only the matching old action, result field, and private
      syscall helper after both modes pass on all three platforms. This
      deletes 44 lines. The 92 runnable library tests pass after removal.
  - [x] Retire the old writable shared-map check. The existing
    `independent_mapping_is_denied` test calls the real mapping operation,
    checks its exact-policy denial, and checks a separate allowed mapping.
    After removal, Host passed in 47.59 seconds, direct `runc` passed in
    50.86 seconds, and Kubernetes passed in 150.77 seconds. The Kubernetes
    launcher exited 0. Remove the old action, result field, and fixture arm;
    keep the other executable-mapping checks.
  - [x] Replace the old file `MmapRead` result with an exact effect check in
    the same 100-line shared mapping test. The actor already reports physical
    `EACCES`; the test now also requires attributed `EXACT_POLICY_DENY`
    File/MmapRead evidence. Remove the hard-coded old result field. An
    unchanged Host retry passed in 76.84 seconds after one Node readiness
    timeout. Direct `runc` passed in 79.52 seconds. Kubernetes passed in
    92.99 seconds and its launcher exited 0.
  - [x] Retire the hard-coded inherited-descriptor read result. The existing
    `retained_descriptor_is_enforced` test opens the file before policy
    replacement, then checks physical read denial, exact object attribution,
    and allowed controls. The unchanged case passed on Host in 61.32
    seconds, direct `runc` in 62.54 seconds, and Kubernetes in 102.24
    seconds. The Kubernetes launcher exited 0.
  - [x] Replace the old SysV `IPC_STAT` check. Protect and Observe now pass
    on Host, direct `runc`, and Kubernetes. The detailed SysV row above records
    the role, syscall, evidence, cleanup, and retirement proof. The matching
    old operation and segment resources are removed. Keep the unrelated
    legacy checks open.
  - [x] Replace the Observe-mode unclassified PTMX ioctl denial. Use one
    shared Python actor and the existing `memory_observe.json` policy. Open
    `/dev/pts/ptmx` before Node starts. Confirm that Linux returns a PTY number
    before readiness. After Node recovers the actor, call the same `TIOCGPTN`
    ioctl. Require actor `EACCES`, attributed `UNRESOLVED_OBJECT` Device/Ioctl
    evidence, rule zero, and zero policy object IDs. Require
    descriptor cleanup and actor exit. Keep the standard Rust test below
    100 lines. Add no Platform API or production change.
    The Host root lacked `/dev/pts`. Add that standard directory to its
    existing mount owner and verify the complete Host matrix. The first
    physical draft then reached the ioctl and proved the expected actor errno,
    reason, family, operation, and identity. Its added command-field assertion
    failed: the generic actor gate returns before typed ioctl processing
    records the command. The old Observe assertion did not check that field.
    Keep the original `TIOCGPTN` action and check the observed zero field.
    Do not change BPF to satisfy the added draft assertion.
    - [x] Pass Host and commit it. The 74-line focused physical test passed
      in 29.15 seconds. Its descriptor-close, actor-exit, pin, lease, and cgroup
      checks passed. The final repository Rust CI procedure passed. The
      complete Host matrix passed all 135 tests in 41 lifecycle groups because
      its root setup changed. Every group removed its pin, lease, and cgroup.
      The 65-case identity group passed in 695.66 seconds. No assertion or
      production change was required during the matrix.
    - [x] Pass direct `runc` and commit it. The unchanged 74-line physical
      case passed in 39.00 seconds through stock `runc` and the production OCI
      hook. Pin, lease, and cgroup cleanup passed. The final Rust CI gate
      passed. No runc fixture or production source changed.
    - [x] Pass Kubernetes and commit it. The same 74-line test passed in
      92.49 seconds against real Control, Node, the signed CRD policy, and
      Kubernetes exec in retained K3s. Namespace, pin, and lease cleanup
      passed. The final repository Rust CI procedure passed. No Kubernetes
      fixture, launcher, or production source changed.
    - [x] Remove only the Observe ioctl action after all three pass. Keep
      Protect-mode PTMX Allow, derived-peer denial, zero-device denial, and
      their shared descriptor resources until their replacements pass.
      The matching Observe branch is removed: 10 Rust lines deleted. All
      nine child regressions passed. The first final Rust CI command failed in the
      unchanged Control unit test `node_session_transitions_emit_owned_logs`:
      its log record was absent. The same failure occurred during the earlier
      SysV migration. No production logging code changed. The cause of that
      unit-test failure is not established.
      The unchanged focused Control test passed in 0.01 seconds. The exact
      executable from the failed CI also passed that test in isolation. The
      unchanged repository Rust CI procedure then passed after the last Rust
      edit. Do not claim that the logging failure is fixed. No physical matrix
      or scenario rerun was required for that unrelated unit failure.
  - [ ] Replace the Protect-mode exact PTMX Allow. Require `TIOCGPTN` success
    with a kernel-written PTY number, attributed `EXACT_POLICY_ALLOW`
    Device/Ioctl evidence, the command, and the PTMX exact-object selector.
  - [ ] Replace PTMX derived-peer denial. Require `TIOCGPTPEER` to fail,
    attributed `UNSUPPORTED_OBJECT` Device/Ioctl evidence with the command
    and PTMX selector, and an unchanged descriptor set.
  - [ ] Replace the exact zero-device ioctl denial. Require `TIOCGPTN`
    `EACCES` on the retained `/dev/zero` descriptor and attributed
    `EXACT_POLICY_DENY` Device/Ioctl evidence with the command and zero-device
    selector. Keep all three Protect actions in the old runner. Its signed
    low-level source uses device classifiers and device command rules. The
    current public `KubernetesRolePolicyV1` has no device rule field, and its
    file operations exclude Ioctl. Do not substitute an unresolved-file or
    capability denial. Do not add a test-only policy path or change the CRD
    without approval.
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
  - [x] Hold the target network namespace in `NetworkRewriteOwner`. Keep the
    complete owner in one small file. Capture command exit status and stderr.
    Report cleanup errors and keep `Drop` as an idempotent fallback.
    The fixture test passed in the retained VM in 0.05 seconds and in a private
    network namespace in 0.04 seconds. The three existing network checks,
    strict Clippy, and final Rust CI passed. This tooling is committed as
    `72416c67`. It does not qualify rewritten-flow evidence. Keep the scenario
    and its pending attribution decision in the local-socket inventory below.
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
      - [x] Use the existing Unix control socket and `SCM_RIGHTS` instead of
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
      - [x] Direct `runc` passed in 36.74 seconds with the same actor, policy,
        and assertions through stock `runc` and the production OCI hook. The
        existing same-namespace restricted case passed in 34.36 seconds.
      - [x] Kubernetes passed in 78.31 seconds with the unchanged test body,
        actor, policy, and assertions against deployed Control and Node. The
        existing same-namespace restricted case passed in 71.90 seconds. The
        pinned Python image was restored from the retained archive before
        the new test started; no scenario or production code changed.
      - [ ] Keep the original `pidfd_getfd` and Ptrace permission check open.
        `SCM_RIGHTS` proves cross-namespace socket authority but does not
        execute that separate descriptor-acquisition operation. Do not delete
        the legacy pidfd action or count its permission assertion as replaced.
    - [ ] Qualify the approved receiver with the same physical transfer and
      distinct namespace evidence. Require the allowed Send, payload receipt,
      and exact production role and effect result on all three platforms.
      Remove the matching legacy transfer only after both tests pass.
      - [x] Start Control, the main actor, and a namespace holder before Node.
        Let the holder create a second network namespace. Place both processes,
        install the signed policy, and let Node recover the main actor. Add one
        declared worker entry through the runtime. That entry joins the held
        namespace with `setns` and receives one accepted TCP descriptor over
        the filesystem Unix control socket. The signed policy permits the
        exact control-socket Create and namespace-setup capability. Require
        the worker role and admission rule, received `ok` payload, attributed
        Network/Send Allow result, and distinct creator and current namespace
        in that result. The Rust test has 93 lines. A Node-first draft and a
        PID1-before-Node draft both got `ENOMEM` from `unshare(CLONE_NEWNET)`.
        The Node-first attempt recorded an exact SysAdmin Allow decision, then
        Linux failed before the socket action. No production code changed.
      - [x] Pass Host and commit it. The exact test passed in 37.12 seconds.
        The existing same-namespace approved case passed in 31.43 seconds.
        The cross-namespace denied case passed in 31.52 seconds. Formatting,
        strict Mithril E2E Clippy, JSON syntax, and whitespace checks passed.
      - [x] Pass direct `runc` and commit it. The unchanged test passed in
        31.29 seconds with stock `runc` and the production OCI hook. Move this
        recovery case into the existing socket-recovery lifecycle. The exact
        Host and direct-`runc` cases passed again in 29.93 and 30.12 seconds.
        Both socket-recovery tests then passed together on Host in 53.10
        seconds and direct `runc` in 54.88 seconds. This lifecycle does not
        stop the Node shared by unrelated identity tests.
      - [x] Pass Kubernetes and commit it.
        The first physical run failed with an unlocated OS `EACCES` after K3s
        created the actor Pod and Mithril Node Pod. The test did not reach a
        verified socket result. K3s restarted during runtime-hook installation
        and returned to Ready. The stage-labeled Host and direct-`runc` cases
        passed in 37.75 and 34.39 seconds. Locate the denied resource, then
        reproduce any missing condition in lightweight before an implementation
        fix or another Kubernetes qualification run. The later diagnostics
        located `EACCES` at the test runner's read of the approved receiver's
        `/proc/<pid>/ns/net` entry. The shared actor now checks its own network
        namespace after `setns`. The Rust test uses the holder's measured
        namespace inode and still compares distinct namespaces and the exact
        production effect fields. The final test has 93 lines. Host passed in
        32.65 and 32.13 seconds, direct `runc` passed in 31.43 and 33.68
        seconds, and Kubernetes passed in 87.29 and 79.87 seconds. The second
        direct-`runc` and Kubernetes runs used the exact final test source.
        A separate Host diagnostic run
        returned `EACCES` when the actor opened the holder's namespace handle;
        the same code passed on the next run. Keep that intermittent setup
        failure open. It does not qualify the old `pidfd_getfd` permission check.
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
    - The 2026-10-01 Host draft repeated this known condition. Both real DNAT
      rules were installed. The failed connection and absent listener
      connection passed. Node rejected the taskless packet record with
      `WAL_FAILURE`; a task-attributed wait cannot match that record. The
      draft, its policy, and its actor commands were removed. No production
      change is approved or implemented. The proposed task-cookie BPF fix
      is withdrawn. Table, pin, lease, and cgroup cleanup passed. Keep the
      baseline Connect allowance, packet denial, and allowed payload checks.
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

- [x] `EffectTestRunner::runc_retained_runtime_gate_probe`: own the bundle
  and marker cleanup. Keep the production OCI hook invocation for hostile,
  CRI, installer, recovery, and host-stock shapes explicit.
  - [x] Share native recovery-manifest path binding on `OciBundle` before
    the exact recovery-command migration. Reuse the OCI input binder. Keep
    manifest validation and the recovery decision in the production hook.
    Qualify the three existing gate cases without changing their assertions.
    The three cases passed in 2.25 seconds in the retained root VM. All ten
    remaining legacy cases and cleanup checks passed. VM harness checks and
    final Rust CI passed. See `/tmp/mithril-oci-manifest-ci-20261002.log`.
    Evidence: `target/mithril-oci-manifest-20261002T233813Z-2211321`.
    No Platform API or production code changed.
  - [x] Replace the exact Node recovery-command case with one small standard
    direct-runc test. Use a checked Python actor and native manifest. Keep
    the 35 extra arguments, host PID namespace, `CAP_SYS_ADMIN`, and all three
    required writable mounts. Require a successful physical marker write and
    the public hook's `ALLOW_EXACT_RECOVERY` log. Check runtime, process,
    cgroup, and temporary-file cleanup. Commit the replacement before removing
    its old action and result fields. Keep changed-command and changed-version
    cases until their own replacements pass.
    The 86-line [exact_recovery_can_start](src/identity/scenarios/runtime_recovery.rs)
    passed in 13.48 seconds in the retained lightweight VM. It checks the full
    38-argument round trip and exact marker text. All eight production gate
    tests passed. The four standard gate cases then passed in 6.30 seconds
    through the retained launcher; all ten legacy cases and cleanup passed.
    The generated `target` directory was removed before CI could launch its
    next test executable. Its physical evidence directory was also removed.
    Source files did not change. The restored final Rust CI run passed. See
    `/tmp/mithril-runtime-recovery-restored-ci-20261003.log`. Normal ignored
    physical cases remain excluded; no new skip was added. No production or
    Platform code changed. Commit `02da02fc` contains the replacement.
    Review route: [OciBundle](src/physical/oci_bundle.rs) binds the native inputs
      -> [OciBaseSpecOwner](../mithril-node/src/runtime_integration.rs) installs
      the production hooks
      -> stock runc invokes [mithril-oci-hook](../mithril-node/src/bin/mithril_oci_hook.rs)
      and the checked Python actor
      -> [ProcessFixture](src/process.rs) reports bounded exit and output;
      the shared platform removes the test paths and cgroup.
  - [x] Remove only the old exact recovery action, decision-log wrapper, three
    result fields, and duplicate assertions after the replacement commit.
    The fixture kept `exact_recovery_config` and `recovery_args` for the
    version-change case. The Node version retirement below removes these
    unused inputs. Qualify the four standard cases and complete reduced probe.
    The deletion removes 23 Rust lines and adds two lines. The four standard
    cases passed in 3.47 seconds through the retained launcher. All nine
    remaining legacy cases and cleanup passed. All result booleans are true.
    Evidence: `target/mithril-recovery-retirement-20261003T015137Z-2395438`.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-recovery-retirement-ci-20261003.log`. The legacy file remains
    on the retirement list at 5,604 lines. No production code changed.
  - [x] Replace the changed recovery-command denial with the same checked
    actor, manifest, and OCI input. Keep the changed command and the absent
    `/host-hook-bin` and `/host-containerd` mounts. Require failed start,
    `DENY_NODE_UNAVAILABLE`, no marker or output, empty runtime state, and
    cgroup cleanup. Add no Platform method. Commit before removing this old
    action and its three result fields.
    The 69-line [changed_recovery_never_starts](src/identity/scenarios/runtime_changed.rs)
    passed in the retained lightweight VM in 11.53 seconds. All eight
    production gate tests and VM harness checks passed. The test preserves
    both baseline rejection conditions. It does not isolate argument and
    mount rejection. The final Rust CI gate passed. See
    `/tmp/mithril-runtime-changed-ci-20261003.log`. Commit `00f150a9` contains
    the replacement. No production or Platform code changed.
    The review route uses the same native input binder, production spec
    owner, public hook, and process owner as the exact recovery test above.
  - [x] Remove only `run_changed_recovery`, its probe call, three result fields,
    and duplicate assertions after the replacement commit. Keep the exact
    recovery config, long argument list, version-change checks, and manifest.
    Qualify the five standard cases and complete reduced legacy probe.
    The deletion removes 22 Rust lines and adds one line. All five standard
    cases passed in 2.98 seconds through the retained launcher. All eight
    remaining legacy cases and cleanup passed. All result booleans are true.
    Evidence: `target/mithril-changed-retirement-20261003T021148Z-2417848`.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-changed-retirement-ci-20261003.log`. The legacy file remains
    on the retirement list at 5,583 lines. No production code changed.
  - [x] Replace exact Control recovery with one small standard direct-runc
    test. Reuse `runtime_owner.py` and `OciBundle`. Declare the exact Control
    command and its mounts in the native recovery manifest. Keep UID, GID,
    and supplementary GID 65532, no new privileges, empty capabilities,
    read-only root, private PID namespace, writable result mount, and absent
    Node endpoint. Require physical marker write, exact argv output,
    `ALLOW_EXACT_RECOVERY`, and cleanup. Keep the old action until the
    replacement passes and is committed. Add no Platform method.
    The 86-line [control_recovery_can_start](src/identity/scenarios/runtime_control.rs)
    passed in the retained lightweight VM in 7.76 seconds. All six standard
    gate cases passed through the retained launcher in 4.84 seconds. All eight
    legacy cases and cleanup passed. Evidence:
    `target/mithril-control-recovery-20261003T022058Z-2428320`. All eight
    production gate tests, VM harness checks, and final Rust CI passed. See
    `/tmp/mithril-runtime-control-ci-20261003.log`.
    Commit `5a24548b` contains the replacement.
    The checked input preserves the non-root user, empty capabilities, private
    PID namespace, and read-only root. The marker directory keeps the baseline
    mode 0777. No production or Platform code changed.
    Review route: [control_recovery_can_start](src/identity/scenarios/runtime_control.rs)
      -> [OciBundle](src/physical/oci_bundle.rs) binds the native Control entry
      and installs hooks through the production spec owner
      -> [RuntimeControlRecoveryEntryV1](../mithril-node/src/runtime_gate.rs)
      checks the exact command, user, capabilities, root, namespace, and mounts
      -> stock runc runs [runtime_owner.py](fixtures/process/runtime_owner.py)
      -> [ProcessFixture](src/process.rs) reports exit and output; the platform
      removes runtime state, temporary paths, and the actor cgroup.
  - [x] Remove only the old exact Control recovery action, decision-log wrapper,
    probe calls, three result fields, and duplicate assertions after the
    replacement commit. Keep the Control config, argument list, manifest,
    changed-capability check, and version-change check. Qualify all six standard
    cases and the complete reduced legacy probe before committing the deletion.
    The deletion removes 30 Rust lines and adds two lines. All six standard
    cases passed through the retained launcher in 7.86 seconds. All seven
    remaining legacy cases and cleanup passed. Evidence:
    `target/mithril-control-retirement-20261003T022742Z-2442569`. VM harness
    checks and final Rust CI passed. See
    `/tmp/mithril-control-retirement-ci-20261003.log`. The legacy file remains
    on the retirement list at 5,555 lines. No production or Platform code changed.
  - [x] Replace changed Control recovery with the same actor and native inputs.
    Change only the effective capability set to `CAP_SYS_ADMIN`. Keep all other
    capability sets empty, as in the baseline. Require `DENY_NODE_UNAVAILABLE`
    from the physical hook, unsuccessful exit, no marker or output, no allow
    decision, and complete cleanup. Exit failure alone is not sufficient.
    Commit the replacement before removing the matched old action and fields.
    The 57-line [changed_control_never_starts](src/identity/scenarios/runtime_control.rs)
    passed in the retained lightweight VM in 11.53 seconds. All seven standard
    gate cases passed through the retained launcher in 4.71 seconds. All seven
    legacy cases and cleanup passed. Evidence:
    `target/mithril-control-capability-20261003T023746Z-2453292`. All eight
    production gate tests, VM harness checks, and final Rust CI passed. See
    `/tmp/mithril-control-capability-ci-20261003.log`.
    Commit `e5a1e00b` contains the replacement.
    The physical denial log is mandatory. The shared actor, OCI input, manifest,
    and positive test remain unchanged. No production or Platform code changed.
    Review route: the new function changes one capability set, then uses the
    existing `OciBundle`, production hook, process owner, and platform cleanup.
  - [x] Remove only the old changed Control action, probe call, marker local,
    three result fields, and duplicate assertions after the replacement commit.
    Keep the version-change action, Control config, arguments, and manifest.
    Qualify all seven standard cases and the complete reduced legacy probe.
    The deletion removes 26 Rust lines and adds two lines. All seven standard
    cases passed through the retained launcher in 7.89 seconds. All six
    remaining legacy cases and cleanup passed. Evidence:
    `target/mithril-control-caps-retirement-20261003T024508Z-2463603`.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-control-caps-retirement-ci-20261003.log`. The legacy file remains
    on the retirement list at 5,531 lines. No production or Platform code changed.
  - [x] Replace version-changed Control recovery with the same Python actor
    copied into the test directory. Append one newline byte to that copy.
    Require different bytes, exact command and security shape, successful
    physical start, exact argv and marker output, and complete cleanup. Change
    only the actor bind source to the temporary copy. Keep its destination and
    read-only options. Do not modify repository inputs or embed program source.
    Add no Platform method. Commit before removing its old action and fields.
    The 68-line [control_version_can_start](src/identity/scenarios/runtime_control.rs)
    passed in the retained lightweight VM in 8.50 seconds. All eight standard
    gate cases passed through the retained launcher in 4.90 seconds. All six
    legacy cases and cleanup passed. Evidence:
    `target/mithril-control-version-20261003T025512Z-2473733`. All eight
    production gate tests, VM harness checks, and final Rust CI passed. See
    `/tmp/mithril-control-version-ci-20261003.log`.
    The test changes the copied actor, not the repository input. The existing
    native-input owner, production hook, process owner, and platform cleanup
    preserve exact argv, security settings, physical output, and cleanup.
    No production or Platform code changed.
  - [x] Remove the old Control version action and its two result fields after
    the replacement commit. Remove the unused legacy Control config, arguments,
    and manifest entry. Keep Node version, installer, and stock-spec checks.
    Qualify all eight standard cases and the complete reduced legacy probe.
    Commit `6b6b605f` contains the replacement. The deletion removes 84 Rust
    lines and adds two lines. All eight standard cases passed in 6.12 seconds.
    All five remaining legacy cases and cleanup passed. All result booleans
    are true. Evidence:
    `target/mithril-control-version-retirement-20261003T030402Z-2487250`.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-control-version-retirement-ci-20261003.log`. The legacy file
    remains on the retirement list at 5,449 lines. No production code changed.
  - [x] Replace version-changed Node recovery with the shared Python actor.
    Copy the actor into the test directory. Bind that copy in both the OCI
    config and native manifest before changing its bytes. Keep all 38 arguments,
    root user, administrative capability, host PID namespace, writable root,
    three writable mounts, and absent Node endpoint. Require different bytes,
    successful physical start, exact argv and marker output, and complete cleanup.
    Add no Platform method. Commit before removing the old action, result fields,
    and unused legacy Node recovery inputs.
    The 76-line [node_version_can_start](src/identity/scenarios/runtime_recovery.rs)
    passed in the retained lightweight VM in 8.01 seconds. All nine standard
    cases passed through the retained launcher in 5.26 seconds. All five
    legacy cases and cleanup passed. Evidence:
    `target/mithril-node-version-20261003T031114Z-2497625`. All eight production
    gate tests, VM harness checks, and final Rust CI passed. See
    `/tmp/mithril-node-version-ci-20261003.log`.
    The existing input owner binds the copied actor before the byte change.
    The public hook checks exact argv, source, destination, and mount mode.
    The process owner reports the physical result. The platform removes the
    copied actor, OCI input, state, markers, and cgroup. No production code changed.
  - [x] Remove only the old Node version action and its two result fields after
    the replacement commit. Remove its unused recovery config, argument list,
    and generated manifest entry. Keep the installer cases and their shell
    interpreter, stock-spec case, diagnostics, and cleanup. Qualify all nine
    standard gate cases and the complete reduced legacy probe before committing.
    Commit `b071843e` contains the replacement. The deletion removes 77 Rust
    lines and adds one line. All nine standard cases passed in 6.36 seconds.
    All four remaining legacy cases and cleanup passed. All result booleans
    are true. Evidence:
    `target/mithril-node-version-retirement-20261003T031835Z-2507754`.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-node-version-retirement-ci-20261003.log`. The legacy file
    remains on the retirement list at 5,373 lines. No production code changed.
  - [x] Replace exact installer startup with one small standard direct-runc test.
    Keep the installed executable path, `install` command, all 12 arguments,
    root user, administrative capability, host PID namespace, writable root,
    writable result and host directories, and read-only actual K3s executable.
    Use the shared Python actor and native inputs. Require successful physical
    start, exact argv, installer marker, and complete cleanup. Add no Platform
    method or legacy fixture code. Commit before removing its old action.
    The 81-line [exact_installer_can_start](src/identity/scenarios/runtime_installer.rs)
    passed in 0.93 seconds. Its file has 88 lines. All ten standard gate cases
    passed in 5.93 seconds. All four legacy cases and cleanup passed. Evidence:
    `target/mithril-installer-group-20261003T033250Z-2517493`. All eight
    production gate tests, VM harness checks, and final Rust CI passed. See
    `/tmp/mithril-installer-exact-ci-20261003.log`.
    The retained K3s VM supplies stock runc and the real K3s executable. The
    standard Rust test does not create a Pod or call Kubernetes APIs. The other
    lightweight VM lacks K3s. No substitute executable was used.
    Review route: the test binds [runtime_owner.py](fixtures/process/runtime_owner.py)
      -> [OciBundle](src/physical/oci_bundle.rs) installs the public production hooks
      -> [RetainedRuntimeGate](../mithril-node/src/runtime_gate.rs) checks installer authority
      -> stock runc executes the actor; [ProcessFixture](src/process.rs) reports
      the physical result; the platform removes paths and the actor cgroup.
    No production or Platform code changed. No launcher source changed.
  - [x] Remove the old exact installer action and its two result fields after
    the replacement commit. Remove the unused exact-config branch and fixture
    argument field. Keep canonical arguments in the manifest input. Keep the
    changed and forged installer cases, their config and logs, stock-spec case,
    and cleanup. Qualify all ten standard cases and the complete reduced probe.
    Commit `08d49949` contains the replacement. The deletion removes 27 net
    Rust lines. The remaining config keeps the same 26 arguments and mounts.
    All ten standard cases passed in 7.18 seconds. All three legacy cases and
    cleanup passed. All result booleans are true. Evidence:
    `target/mithril-installer-retirement-20261003T034302Z-2528731`.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-installer-retirement-ci-20261003.log`. The legacy file remains
    on the retirement list at 5,346 lines. No production or Platform code changed.
  - [x] Replace changed installer startup with the same shared actor and
    canonical manifest. Change the copied executable bytes, use all 26 upgraded
    arguments, and mount actual K3s read-only at `/host-runtime-cli`. Keep the
    retained `/host-k3s` declaration unchanged. Require physical success, exact
    argv and marker, `ALLOW_MITHRIL_INSTALLER` from the public hook, and cleanup.
    Add no Platform method or legacy fixture code. Commit before removal.
    The 99-line function passed in 0.78 seconds. All eleven standard gate cases
    passed in 6.48 seconds. All three legacy cases and cleanup passed. Evidence:
    `target/mithril-installer-changed-group-20261003T040515Z-2550294`.
    Formatting, all eight production gate tests, VM harness checks, and final
    Rust CI passed. See `/tmp/mithril-installer-changed-ci-20261003.log`.
    Review route: [changed_installer_can_start](src/identity/scenarios/runtime_installer.rs)
      -> [OciBundle](src/physical/oci_bundle.rs) calls the public spec owner
      -> stock runc runs [runtime_owner.py](fixtures/process/runtime_owner.py)
      -> the public hook reports installer approval; the test checks argv,
      marker, runtime inventory, and cleanup through `ProcessFixture` and Platform.
    No production, Platform, or launcher source changed. This is direct-runc
    qualification in the retained K3s VM, not Kubernetes Pod qualification.
  - [x] Remove the old changed installer action and its three result fields
    after the replacement commit. Remove its two unused log methods and Write
    import. Keep forged denial, canonical manifest, upgraded argv, stock spec,
    diagnostics, and cleanup. Qualify all eleven standard cases and the two
    remaining legacy cases before the separate retirement commit.
    Commit `c12d053b` contains the replacement. The deletion removes 99 net
    Rust lines. All eleven standard cases passed in 7.21 seconds. Both legacy
    cases and cleanup passed. Every remaining result boolean is true. Evidence:
    `target/mithril-installer-changed-retirement-20261003T041315Z-2559660`.
    The CLI executable was rebuilt before transfer to the VM. VM harness checks
    and final Rust CI passed. See
    `/tmp/mithril-installer-changed-retirement-ci-20261003.log`.
    The legacy file remains on the retirement list at 5,247 lines.
  - [x] Replace forged installer denial with the shared actor, checked upgraded
    argv, and canonical manifest. Change only the owner argument to
    `attacker/other`. Require failed physical start, `DENY_NODE_UNAVAILABLE`,
    no installer approval, no actor output or marker, empty runtime inventory,
    and cleanup. Keep the function below 100 lines. Add no Platform method or
    legacy fixture code. Commit the replacement before removing the old action.
    The 74-line function passed in 0.73 seconds. All twelve standard gate cases
    passed in 8.07 seconds. Both legacy cases and cleanup passed. Evidence:
    `target/mithril-installer-forged-group-20261003T042253Z-2568035`.
    Formatting, VM harness checks, and final Rust CI passed. See
    `/tmp/mithril-installer-forged-ci-20261003.log`.
    Review route: [forged_installer_never_starts](src/identity/scenarios/runtime_installer.rs)
      -> [OciBundle](src/physical/oci_bundle.rs) calls the public spec owner
      -> [RetainedRuntimeGate](../mithril-node/src/runtime_gate.rs) rejects the
      forged owner; stock runc does not start the shared actor.
    No production, Platform, launcher, or fixture input changed. This is
    direct-runc qualification. Keep the separate CRI installer probes.
  - [x] Remove the old forged installer action and its three result fields
    after the replacement commit. Delete installer-only manifest creation,
    fake actor, shell copy, hook fields and construction, config, and marker
    check. Keep stock-spec security, nsenter dependencies, writable result
    mount, diagnostics, and cleanup. Qualify all twelve standard cases and the
    sole remaining legacy case before the separate retirement commit.
    Commit `b25887d8` contains the replacement. The deletion removes 168 net
    Rust lines. All twelve standard cases passed in 8.61 seconds. The remaining
    stock-spec case and cleanup passed. Evidence:
    `target/mithril-installer-forged-retirement-20261003T043232Z-2581705`.
    The CLI executable was rebuilt before transfer. VM harness checks and final
    Rust CI passed. See `/tmp/mithril-installer-forged-retirement-ci-20261003.log`.
    The legacy file remains on the retirement list at 5,079 lines. The separate
    CRI shell cases and public hook input validation remain unchanged.
  - [x] Replace the final host stock-spec case with a small standard Rust test.
    Keep nsenter as the native entry, host PID and mount-namespace transition,
    real K3s `ctr oci spec`, stock mounts, limits, masked and read-only paths,
    all three capability sets, writable result mount, JSON output, and cleanup.
    Use existing `OciBundle` paths and `ProcessFixture` execution. Keep hooks
    absent. Do not replace generation with runtime integration installation.
    Add no Platform API. Verify and commit before removing the old probe.
    The 99-line [host_stock_spec_can_run](src/identity/scenarios/runtime_installer.rs)
    passed in 0.68 seconds. All thirteen standard gate cases passed in
    7.96 seconds. The remaining legacy stock-spec case and cleanup passed.
    Evidence: `target/mithril-host-stock-group-20261003T045248Z-2599715`.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-host-stock-ci-20261003.log`.
    Review route: the test asks stock runc to generate its OCI specification
      -> the test binds [runtime_host_stock.json](fixtures/process/runtime_host_stock.json)
      without replacing stock security fields
      -> [ProcessFixture](src/process.rs) runs native nsenter and captures
      real K3s JSON output; the platform removes the bundle, state, and cgroup.
    No production, Platform, or launcher source changed. This is direct-runc
    qualification in the retained K3s VM, not Kubernetes Pod qualification.
  - [x] Remove the final legacy retained-gate fixture, result types, probe,
    exports, CLI command, and lightweight launcher invocation after the
    stock-spec replacement commit. Keep the shared library dependency parser
    and the separate CRI and Kubernetes cases. Make the thin launcher run only
    the thirteen standard Rust cases and verify their normal cleanup. Run VM
    harness checks and final Rust CI before the separate retirement commit.
    Commit `23643235` contains the stock-spec replacement. The deletion
    removes 336 lines from `effect/runc.rs` and 387 net lines across the
    fixture, exports, CLI, and launcher. No live retired command or result
    consumer remains. The shared dependency parser retains its other caller.
    All thirteen standard cases passed through the reduced launcher in
    8.81 seconds. Resource absence checks passed. Evidence:
    `target/mithril-runtime-gate-retirement-20261003T050701Z-2611940`.
    The rebuilt CLI no longer lists the old command. Shell syntax, VM harness
    checks, and final Rust CI passed. See
    `/tmp/mithril-runtime-gate-retirement-ci-20261003.log`.
    The old file remains on the retirement list at 4,743 lines. Keep its
    independent recovered-entry, runtime-entry, and CRI operations until
    their replacements pass. This result does not qualify the full two-node
    Kubernetes procedure.
  - [x] Share checked OCI bundle preparation before the next runtime-gate
    migration. Keep production hook installation on `OciBaseSpecOwner` and
    process start, exit, diagnostics, and stop on `ProcessFixture`. The
    bundle input owner must not own a process or reproduce admission.
    Qualify the unchanged hostile assertions before committing the tooling.
    Add no Platform method and no legacy fixture code.
    The hostile case passed in 19.54 seconds in the retained lightweight VM.
    Its 57-line body keeps every denial, output, marker, runtime-state, and
    cgroup assertion. The 110-line
    [OciBundle](src/physical/oci_bundle.rs) binds checked OCI input paths and
    calls the public production spec owner. It returns `ProcessFixture` and
    owns no process or admission state. The existing environment removes its
    temporary files. VM harness checks and final Rust CI passed. See
    `/tmp/mithril-oci-bundle-ci-20261002.log`.
  - [x] Replace the inert CRI sandbox case with a small direct-runc test.
    Keep `/pause`, the read-only root and binds, `noNewPrivileges`, the
    non-administrative capabilities, sandbox annotations, the unavailable
    Node endpoint, actor output, and `ALLOW_CRI_SANDBOX` log assertion.
    Use a checked Python actor. Keep the old case until the replacement passes.
    The 70-line [inert_sandbox_can_start](src/identity/scenarios/runtime_sandbox.rs)
    passed in 7.77 seconds. Stock runc executed the actor and returned its
    exact output. A separate public-hook call with the same OCI config keeps
    the original `ALLOW_CRI_SANDBOX` log proof. Runtime state and cgroup
    cleanup passed. All eight retained-gate owner tests, VM harness checks,
    and final Rust CI passed. See `/tmp/mithril-runtime-sandbox-ci-20261002.log`.
  - [x] Replace the forged sandbox command in a separate small direct-runc
    test. Keep the sandbox annotations but run a different actor command with
    its writable result mount. Require failed start, `DENY_NODE_UNAVAILABLE`,
    no actor marker, empty runtime state, and cgroup cleanup. Retire only
    these two old cases after their focused verification and commits.
    The 63-line [forged_sandbox_never_starts](src/identity/scenarios/runtime_forged.rs)
    passed in 7.21 seconds. It reuses the same Python actor and OCI input as
    the inert case. The test changes only the process command and writable
    result mount. No actor marker, runtime state, or cgroup remained. VM
    harness checks and final Rust CI passed. See
    `/tmp/mithril-runtime-forged-ci-20261002.log`.
  - [x] Make the retained-upgrade launcher run the three standard runtime-gate
    cases in one compatible lifecycle. Include the shared pause actor in its
    inputs. Then remove the two old sandbox actions, their result fields,
    fake pause script, config helper, and log helper. Keep the ten other
    runtime-gate cases. Qualify the group and complete reduced probe first.
    The three standard cases passed together in 2.46 seconds in the retained
    K3s VM with stock runc 1.4.2. All ten remaining legacy cases passed. The
    result has 28 fields and reports fixture cleanup. No platform output,
    pin, actor cgroup, Node cgroup, or temporary launcher directory remained.
    The deletion removes 85 Rust lines. The launcher now copies only the two
    required Python actors and the recovery manifest. VM harness checks and
    final Rust CI passed. See `/tmp/mithril-sandbox-retirement-ci-20261002.log`.
    Evidence: `target/mithril-sandbox-retirement-20261002T230932Z-2190976`.
    This result does not qualify the full two-node Kubernetes procedure.
  - [x] Replace the hostile-container case with one standard direct-runc test
    below 100 lines. Use the shared process owner and checked OCI and Python
    inputs. Keep the host PID namespace, root user, `CAP_SYS_ADMIN`, writable
    host-root mount, and unavailable Node endpoint. Run stock runc and the
    production OCI hook. Require failed start, `DENY_HOSTILE`, no actor marker,
    empty runtime state, and cgroup cleanup. Add no Platform operation and no
    legacy fixture code. This case qualifies the retained OCI gate, not a
    Host process or a Kubernetes Pod. Keep the separate physical Pod case.
  - [x] Pass the exact direct-runc case, related checks, harness checks, and
    final Rust CI. The 98-line `hostile_runtime_never_starts` test passed in
    6.89 seconds in the retained root VM. The production hook returned
    `DENY_HOSTILE`. Neither actor marker existed. No container record, cgroup,
    pin, lease, or output directory remained. All 25 related effect checks and
    local VM harness checks passed. Final Rust CI passed after the last Rust
    edit. See `/tmp/mithril-runtime-hostile-ci-20261002.log`. The workspace
    gate uses normal ignored-test exclusions and no added skips.
    The first two runs stopped at test input checks: the existing cgroup
    getter supports Host only, and stock runc emits `null` for an empty list.
    The test uses the launcher cgroup input and serde's optional list. It also
    rejects runtime stderr and a retained container state directory.
  - [x] Commit the verified replacement before removing its old action.
    Commit `f3821368` contains the standard test and its checked inputs.
  - [x] Remove the old hostile action and its duplicate result fields.
    Keep the other twelve retained-gate cases and their security assertions.
  - [x] Make both retained-upgrade launcher paths invoke the exact standard
    Rust hostile test. Copy the test binary and required fixture inputs.
    Keep the remaining runtime-gate assertions in their Rust owner. Remove
    their duplicate shell predicates. Keep the result-schema and fixture
    cleanup checks. Verify the complete remaining probe and launcher cleanup
    in the retained root VM before the retirement commit.
    The launcher function passed with K3s stock runc 1.4.2. The exact standard
    test passed in 1.93 seconds. All twelve remaining cases passed. The result
    contains 34 fields and reports fixture cleanup. No platform output, pin,
    actor cgroup, or Node cgroup remained. The launcher removed its temporary
    input and binary directory. This change removes 24 Rust lines and one
    shell line. The full two-node Kubernetes procedure was not run.
    Evidence: `target/mithril-hostile-retirement-20261002T221222Z-2136229`.
    [run_lightweight_upgrade_probe](harness/vm/two-node-convergence.sh) copies
    the standard test binary and required fixture inputs, then invokes one
    compatible runtime-gate lifecycle. The old runner asserts the ten cases
    that do not yet have a standard replacement.
    Shell checks cover the result schema and resource cleanup only.
  - [x] Pass final Rust CI after the deletion and commit the retirement.
    All 25 related effect checks passed. Local VM harness checks and final
    Rust CI passed. The workspace gate uses normal ignored-test exclusions.
    See `/tmp/mithril-runtime-hostile-retirement-ci-20261002.log`.
    Review route: [hostile_runtime_never_starts](src/identity/scenarios/runtime_hostile.rs)
    binds the checked OCI input and keeps the Node endpoint absent.
      -> [OciBaseSpecOwner](../mithril-node/src/runtime_integration.rs) installs
      the production hooks in that spec.
      -> [mithril-oci-hook](../mithril-node/src/bin/mithril_oci_hook.rs) reads
      actual runc state; the retained gate rejects the hostile host mount.
      -> [ProcessFixture](src/process.rs) captures exit status and bounded
      output, then checks process cleanup. The common platform removes resources.
    Run the exact case in a prepared root VM with the normal platform inputs:
    `identity::scenarios::runtime_hostile::hostile_runtime_never_starts::runtime_gate_runc
    --exact --ignored --nocapture --test-threads=1`. This result does not qualify
    the separate Kubernetes hostile-Pod case or the full physical matrix.
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
  - [x] Replace post-cutover external-tree exit with one small standard
    platform test. Reuse `recovery_tree.py` and `actor_policy.json`. Fork the
    application and external trees before Node starts. Require complete
    recovery of four tasks: two application tasks, two external tasks, and
    no invalid task. Release only the external tree. Require the surviving
    binding to stay `active_recovered` with the same prepared application
    anchor, application entry ID, and admitted rule. Then release the
    application. Use existing Platform operations and process cleanup only.
    Give this actor-before-Node case its own pristine lifecycle. Pass and
    commit Host, then runc, then Kubernetes before removing their matched
    legacy readback, result field, and shell assertions. Keep task-change
    retry and the old observer until their own replacements pass.
    - [x] Host passed in 39.48 seconds in the retained root VM. The complete
      source file has 89 lines. Output, pin, lease, actor cgroup, and Node
      cgroup cleanup passed. VM harness checks and final Rust CI passed. See
      `/tmp/mithril-post-cutover-host-ci-20261003.log`.
    - [x] Direct runc passed the unchanged 89-line source in 41.87 seconds.
      Stock runc and the production OCI hook ran the two process trees.
      Output, pin, lease, actor cgroup, and Node cgroup cleanup passed.
      Only the platform attribute changed after Host commit `995ee7eb`.
      Final Rust CI passed. See
      `/tmp/mithril-post-cutover-runc-ci-20261003.log`.
    - [x] Kubernetes passed the unchanged 89-line source in 73.30 seconds.
      Real Control, Node, policy CRDs, and runtime exec performed recovery.
      Normal lifecycle cleanup passed. See
      `/tmp/mithril-post-cutover-kube-20261003.log`. Final Rust CI passed. See
      `/tmp/mithril-post-cutover-kube-final-ci-20261003.log`.
      The first diagnostic launcher required removal of the infrastructure
      output parent. Kubernetes owns only its scenario child. The existing
      lightweight directory test now requires child removal and parent
      retention; it passed before the launcher correction and Kubernetes
      rerun. No scenario body, production operation, or readiness limit changed.
    - [x] Remove only the matched old post-exit binding readback, result
      field, and Kubernetes shell snapshot assertion after the replacement
      commit. Keep external release and wait as cleanup. Keep task-change
      retry, iterator cutover, other results, and their observer. The rebuilt
      reduced probe passed in the retained root VM. Its remaining launcher
      predicate and pin, lease, cgroup, and fixture cleanup checks passed.
      This change removes 26 Rust lines and nine shell lines. The known
      stopped sudo monitor required a continue after the probe exited.
      Shell syntax, VM harness checks, and final Rust CI passed. See
      `/tmp/mithril-post-cutover-retirement-probe-20261003.log` and
      `/tmp/mithril-post-cutover-retirement-ci-20261003.log`. The full
      two-node Kubernetes launcher was not run for this matched deletion.
    Review route: [external_exit_preserves_recovery](src/identity/scenarios/post_cutover_exit.rs)
      starts both [recovery_tree.py](fixtures/process/recovery_tree.py) trees
      -> the production Node recovers four live tasks
      -> [ProcessFixture](src/process.rs) stops the external tree
      -> the test reads a fresh application snapshot and checks the binding.
    The application stops only after this readback. No actor, policy,
    Platform, or production source changed. The exact Host case is
    `identity::scenarios::post_cutover_exit::external_exit_preserves_recovery::recovery_exit_host`.
    Run it in the prepared root VM with the normal Platform inputs and
    `--exact --ignored --nocapture --test-threads=1`.
- [ ] Recovered-container application, external, and declared-probe entries:
  keep each stock runtime action and exact role, rule, and denial assertion.
  - [x] Replace the recovered-container unmatched `mkdir` exec. Keep the
    existing node-first unlisted-exec test. In a second small standard test,
    start the actor before Node, install the signed policy, recover the live
    actor, and call `add_actor("mkdir", ...)`. Require physical `EACCES` and
    fresh `UNSUPPORTED_OBJECT` Exec/Execute evidence with external role and
    rule zero. Share the result assertion with the node-first test.
    - [x] Pass Host and commit its test registration. The recovered case
      passed in 37.23 seconds. The unchanged node-first case passed in
      33.87 seconds with the shared result assertion.
    - [x] Pass direct `runc` and commit its registration. The recovered case
      passed in 89.92 seconds through stock `runc` and the OCI hook. The
      unchanged node-first case passed in 62.58 seconds.
    - [x] Pass Kubernetes and commit its registration. The recovered case
      passed in 97.69 seconds; the unchanged node-first case passed in
      79.18 seconds. Both launcher commands exited 0.
    - [x] Remove the matching old action, result field, and `run.sh` gate.
      Keep the separate two-node convergence check. The reduced direct-`runc`
      probe passed. Its remaining launcher JSON predicate returned `true`.
      The first probe run lacked the public `mithril-inspect` test binary;
      build it before this focused probe. The runner's parent needed
      `SIGCONT` after its probe child exited. Do not treat that launcher
      behavior as a test assertion.
  - [x] Replace the recovered startup entry's missing-file and signed-denial
    contrast. Reuse the shared entry-isolation policy and `ready.py` actor.
    Start the actor before Node and recover it. Then start a declared `cat`
    entry. Remove its protected file while the entry waits at a FIFO. Require
    `ENOENT`, a nonzero entry
    rule, and no fresh signed-policy denial for that entry. Restore the file,
    start the declared entry again, and require the same role and rule, a
    failed read, and attributed `EXACT_POLICY_DENY` File/OpenRead evidence.
    Keep the separate readiness-before-startup check until a shared test
    proves it.
    - [x] Host passed in 39.52 seconds. The standard test has 71 lines.
    - [x] Direct `runc` passed in 41.89 seconds through the production hook.
    - [x] Kubernetes passed in 79.15 seconds. The launcher exited 0.
    - [x] Remove only the matching old rename, missing-file action, and
      assertion. The protected file remains for its signed-denial action.
      The reduced recovered-container probe passed with its remaining checks.
      Its stopped legacy sudo monitor needed `SIGCONT` after the probe exited.
    - [x] Strengthen the same test with the restored-file signed denial. The
      98-line test passed on Host in 30.40 seconds, direct `runc` in 38.66
      seconds, and Kubernetes in 70.73 seconds. The Kubernetes launcher
      exited 0.
    - [x] Remove the duplicate result field and `run.sh` predicate. Keep the
      old signed-denial action because its event feeds the public
      `mithril-inspect` capture in this probe. The reduced probe passed with
      that capture and its earlier startup and bootstrap assertions.
    - [x] Qualify the same public `mithril-inspect` denial capture on Host and
      direct `runc` before removing the old action and capture. The current
      shared test checks the production observation API, but does not call the
      CLI. The deployed two-node Kubernetes lane checks the CLI separately.
      - [x] Add `inspection_keeps_signed_deny`, one standard platform test
        below 100 lines. Reuse `ready.py`, the entry-isolation policy, the
        existing process owner, and the real Node observation endpoint.
        Start the actor before Node. Recover it, run the declared startup
        entry, and require physical `EACCES` and fresh signed denial evidence.
        Run the public CLI with one sample. Require the same source ID, task,
        role, entry rule, family, operation, and kernel result in its output.
        Add no Platform method or temporary observation server.
      - [x] Host passed in 49.69 seconds. The 97-line test checks a recovered
        application, declared startup entry, physical denial, fresh production
        evidence, and the exact CLI fields. Output, pin, lease, actor cgroup,
        and Node cgroup cleanup passed. Strict Mithril E2E Clippy passed.
        No Platform, production, actor, policy, or legacy fixture changed.
        All 25 related effect checks and the local VM harness checks passed.
        The final repository Rust CI passed with normal ignored-test
        exclusions and no extra skips. See
        `/tmp/mithril-inspection-host-ci-20261002.log`.
      - [x] Direct runc passed the unchanged 97-line body in 52.33 seconds.
        Stock runc and the production OCI hook created the declared entry.
        The exact physical denial, Node evidence, CLI fields, and normal
        output, container, pin, lease, and cgroup cleanup passed. Only the
        platform attribute changed after Host commit `a8b8c6b7`.
        The final repository Rust CI passed for that attribute edit. See
        `/tmp/mithril-inspection-runc-ci-20261002.log`.
      - [x] Remove only the matched legacy denial action and temporary
        observation server after both pass. The deletion removes 82 Rust
        lines. The complete reduced recovered-container probe passed with
        its unchanged launcher predicate and cleanup checks. All 25 related
        effect checks and the local VM harness checks passed. Keep the real
        Kubernetes CLI lane, task-change retry, role, cutover, and cleanup
        assertions. The result schema stays at version 1.
        The final repository Rust CI passed after this deletion, with normal
        ignored-test exclusions and no extra skips. See
        `/tmp/mithril-inspection-retirement-ci-20261002.log`.
      Review route:
      [inspection_keeps_signed_deny](src/identity/scenarios/inspection_capture.rs)
      recovers the actor and releases the declared startup entry.
        -> [EffectCheck](src/effect/check.rs) checks the fresh Node denial.
        -> [mithril-inspect](../mithril-node/src/bin/mithril_inspect.rs) reads
        the real Node endpoint and prints that result.
        -> [ProcessFixture](src/process.rs) reaps the actor, entry, and CLI;
        the platform
        removes scenario resources and retains only its lifecycle services.
      The test writes no BPF map and starts no observation server.
      Run the exact case in the prepared root VM with the existing platform
      environment inputs and `--exact --ignored --nocapture --test-threads=1`.
      The prefix is
      `identity::scenarios::inspection_capture::inspection_keeps_signed_deny`.
      Select `inspection_recovery_host` or `inspection_recovery_runc` below
      that prefix. Infrastructure supplies `MITHRIL_BIN_DIRECTORY`; that
      directory must contain the production `mithril-inspect` executable.
  - [x] Replace the recovered readiness-before-startup identity order. Reuse
    `ready.py` and the entry-isolation policy. Start the actor before Node,
    recover it, run a declared `grep` readiness entry, then run a declared
    `cat` startup entry. Require both to succeed with distinct task cookies,
    distinct roles, nonzero entry rules, and one policy generation. Keep the
    old startup output and runtime-internal bootstrap checks until they have
    separate shared coverage.
    - [x] Host passed in 43.97 seconds. The formatted test has 85 lines.
    - [x] Direct `runc` passed in 47.82 seconds with the production OCI hook.
    - [x] Kubernetes passed in 88.11 seconds. The launcher exited 0.
    - [x] Remove only the matching old competing-readiness action and
      identity comparison. Keep the startup action. The reduced recovered-
      container probe passed with its output, bootstrap, and inspector checks.
  - [x] Replace the recovered runtime-internal Exec result. Reuse `ready.py`
    and the entry-isolation policy. Start the actor before Node, recover it,
    and start a declared `cat` entry. Require fresh
    `RUNTIME_ENTRY_INFRASTRUCTURE` Exec/Execute evidence with entry rule zero.
    Keep the separate ptrace, startup output, and public inspector checks.
    - [x] Host passed in 35.04 seconds.
    - [x] Direct `runc` passed in 44.09 seconds with the production OCI hook.
    - [x] Kubernetes passed in 78.49 seconds. The launcher exited 0.
    - [x] Remove only the matching old event scan, serialized result, and
      `run.sh` predicate after all three pass. The reduced old probe passed
      its remaining ptrace, role, and cleanup checks.
  - [x] Replace the recovered runtime ptrace marker. This is a runtime exec
    check, so run one shared test on direct `runc` and Kubernetes. Start the
    actor before Node, recover it, then hold a declared `cat` entry. Require
    a fresh `RUNTIME_ENTRY_INFRASTRUCTURE` Privilege event whose target task
    cookie is the recovered initial actor and whose entry rule is zero.
    Keep the old marker, result, and shell gate until both cases pass.
    - [x] Direct `runc` passed in 44.29 seconds through the production OCI
      hook. The standard test has 73 lines.
    - [x] Kubernetes passed in 73.34 seconds with the same test body. The
      launcher exited 0 and removed the test resources.
    - [x] Remove only the matching old marker, result, and shell gate. The
      reduced old probe passed its startup, role, inspector, and cleanup
      checks. Its remaining launcher predicate returned `true`.
  - [x] Replace the recovered startup entry output check. Extend the existing
    shared recovery-order test, not its platform implementations. After the
    declared `cat` entry exits, require the exact `READY\nrelease\n` bytes.
    Add bounded stdout reading to `ProcessFixture`. Keep the old startup
    action for the separate public inspector capture until that check has
    shared coverage.
    - [x] Host passed in 33.61 seconds with exact output. A first run found
      that the fixture reread a reaped child status; the corrected method
      uses the status from `wait_exit`.
    - [x] Direct `runc` passed in 43.22 seconds with the same test body and
      stock runtime exec.
    - [x] Kubernetes passed in 82.91 seconds with the same test body. The
      launcher exited 0 and removed the test resources.
    - [x] Remove only the matching old output assertion after all three pass.
      The reduced old probe passed its inspector, role, and cleanup checks.
      Its remaining launcher predicate returned `true`.

### Direct runtime entry roles

The current result schema stays unchanged. Migrate one behavior group per
commit so the approximately 4,000-line scenario does not move as one block.
Small scenario files are preferred when one file can contain its fixture
setup, production actions, assertions, and focused test.

- [ ] Fixture construction: create the rootfs, runtime paths, bind mounts,
  output files, containerd owner, `runc` owner, pin root, lease, and cleanup
  in a fixture. Do not install policy or reconcile bindings in this fixture.
- [x] Signed admission-map publication: replace the initial seven-rule
  readback with `signed_entries_are_complete`, a standard platform test below
  100 lines. Reuse `ready.py` and the existing fatal-executable fixture.
  Add one checked policy with the original six ordinary entries and one
  terminal entry. Keep the already qualified runtime policy unchanged.
  Read only the running actor's installed generation. Require seven rules,
  seven distinct nonzero admission IDs, nonzero target roles and process
  vectors, zero reserved and exact-object fields, and default executable
  objects. Require six ordinary rows and one terminal-role row.
  - [x] Host passed in 28.50 seconds in the retained root VM. The complete
    source has 69 lines. Output, pin, lease, actor cgroup, and Node cgroup
    cleanup passed. The first inputs lacked required schema fields and used
    duplicate execution-rule names; only the new fixture was corrected.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-entry-map-host-ci-20261003.log`.
  - [x] Direct runc passed the unchanged 69-line test in 37.17 seconds.
    Stock runc and the production OCI hook started the actor. Output, pin,
    lease, actor cgroup, and Node cgroup cleanup passed. Final Rust CI passed.
    See `/tmp/mithril-entry-map-runc-ci-20261003.log`.
  - [x] Kubernetes passed the unchanged 69-line test in 81.57 seconds.
    Real Control, Node, policy CRDs, and actor admission installed seven
    rules. Normal teardown and owned-directory cleanup passed. Final Rust
    CI passed. See `/tmp/mithril-entry-map-kube-20261003.log` and
    `/tmp/mithril-entry-map-kube-ci-20261003.log`.
  - [x] Remove only the matching initial map readback after qualification.
    All seven rule-count and ABI assertions remain in the qualified shared
    test. This deletes 56 Rust lines. Keep the policy-replacement readback
    until its own replacement passes. Harness checks and final Rust CI passed.
    See `/tmp/mithril-entry-map-retirement-ci-20261003.log`.
    The reduced old probe failed at a mount-cache snapshot before this map
    readback. It produced all 32 exec diagnostic pairs, then reported no READY
    row at cache generation 23. Its fixture, pin, and lease cleanup completed.
    The unchanged mount checks remain. This run does not qualify the whole
    old probe. See `/tmp/mithril-entry-map-retirement-probe-20261003.log`.
  Review route: [signed_entries_are_complete](src/identity/scenarios/entry_map.rs)
    supplies [entry_map_policy.json](fixtures/process/entry_map_policy.json)
    -> the production Control and Node install its signed generation
    -> the shared actor starts through production admission
    -> the test checks the actor's installed admission rules and stops it.
  Run the exact generated `identity_host`, `identity_runc`, or
  `identity_kubernetes` case with the prepared Platform inputs and
  `--exact --ignored --nocapture --test-threads=1`. An attribute lists a
  platform only after that platform passes.
- [x] Replace the signed admission-map readback after generation replacement
  with `entry_replace::replacement_keeps_signed_entries`. Reuse both existing
  seven-entry policies and the fatal-executable input. Keep one actor live.
  Install the entry-map policy, install the runtime-entries policy, then
  restore the entry-map policy. The public installer makes an identical
  specification a no-op; these real updates replace the old fixture's direct
  re-signing of the same document. Require a newer active generation, retained
  actor identity, seven distinct nonzero signed admission IDs, and exactly one
  terminal-role rule in the final generation. Pass and commit Host, direct
  runc, and Kubernetes before removing the matching legacy readback. Keep the
  old replacement action while the following restart checks consume it.
  - [x] Host passed the 98-line test in 49.66 seconds. Both replacement
    generations increased. The running actor retained its task, process,
    execution, entry, creator, and role identities. Normal teardown and owned
    directory cleanup passed. See
    `/tmp/mithril-entry-replace-host-final-20261003.log`.
    Final Rust CI and VM harness checks passed. See
    `/tmp/mithril-entry-replace-host-final-ci-20261003.log`.
  - [x] Direct runc passed the unchanged test in 60.54 seconds. Both
    replacement generations, final signed entries, actor identity, normal
    teardown, and owned directory cleanup passed. Formatting, compilation,
    and strict package clippy passed. See
    `/tmp/mithril-entry-replace-runc-20261003.log`.
  - [x] Kubernetes passed the unchanged test in 113.15 seconds. Real Control,
    Node, policy CRDs, and actor admission installed both replacement
    generations and seven final signed entries. Normal teardown and owned
    directory cleanup passed. The retained cluster resumed with short
    connection and HTTP 503 errors before it became ready. No timeout or
    assertion changed. See `/tmp/mithril-entry-replace-kube-20261003.log`.
  - [x] Remove only the matching old replacement readback, its unused role
    variable, and its unused key import. This deletes 61 net Rust lines.
    Keep generation installation, the running actor identity check, and all
    later mount, cache, and restart checks. The shared test retains key and
    value ABI checks, seven distinct signed IDs, and the terminal-role check.
    It also requires nonzero IDs and stable actor identity across both updates.
    VM harness checks and final Rust CI passed. See
    `/tmp/mithril-entry-replace-retirement-ci-20261003.log`.
  Review route: [replacement_keeps_signed_entries](src/identity/scenarios/entry_replace.rs)
    -> [entry_map_policy.json](fixtures/process/entry_map_policy.json)
    -> [runtime_entries_policy.json](fixtures/process/runtime_entries_policy.json)
    -> the production Control and Node publish each changed policy
    -> the test checks both active generations and final signed entries
    -> the same actor stops through the shared fixture.
  Run the exact generated `identity_host`, `identity_runc`, or
  `identity_kubernetes` case with the prepared Platform inputs and
  `--exact --ignored --nocapture --test-threads=1`. Add a platform to the
  attribute only when its focused case passes.
- [x] Unprotected control and prepared-container start: keep the stock runtime
  calls and `PREPARED` assertions in the scenario.
  `unprotected_actor_runs` owns stock startup without policy on Host, direct
  `runc`, and Kubernetes. `prepared_start_emits_effect` requires the fresh
  `PREPARED_RUNTIME_INFRASTRUCTURE` transition and resulting active binding on
  Host and direct `runc`. The old spec-only seccomp boolean, duplicate
  lifecycle strings, and literal `container_exit_success` result are removed.
  The shared test waits for the real actor exit and requires a successful
  status on all three platforms.
- [ ] Held OCI route publication: keep policy installation, background binding
  reconciliation, `createContainer`, route publication, and activation calls
  in their real order through public production APIs.
  - [x] Remove the legacy `held_runtime_admission_reconciled` result. The old
    runner assigned literal `true`, so the field did not test reconciliation.
    `prepared_start_emits_effect` already uses the production held admission
    route and requires its active binding and prepared-runtime effect on Host
    and direct `runc`. Do not change or rerun that completed platform test.
    Remove only the constant result and its shell gate, then run the reduced
    old probe. The reduced probe passed, and its complete updated result
    predicate returned `true`.
- [x] Replace the prepared-runtime effect result. Start Control and Node,
  install the signed runtime-entries policy, then start the shared application
  actor. Require a fresh production `PREPARED_RUNTIME_INFRASTRUCTURE` effect
  from the prepared-to-active runtime transition. Use the same Rust test on
  each platform where that physical transition occurs. The Host and direct
  `runc` pair now owns this assertion.
  - [x] Host passed in 63.25 seconds. The standard test has fewer than 100
    lines and checks the active runtime binding and fresh effect. The stronger
    policy-generation check passed in 41.24 seconds.
  - [x] Direct `runc` passed in 83.40 seconds with the same test body and
    production OCI hook. The stronger check passed in 45.52 seconds.
  - [ ] Revisit Kubernetes. The user excluded this platform from this test
    until its physical setup can exercise the same pre-active effect. Two
    focused Kubernetes runs found no prepared effect. A live
    `mithril-inspect effects` sample began before policy activation and saw no
    prepared effect through teardown. A temporary Host test proved that 1,100
    reads can evict an earlier effect from the Node's 1,024-record window, but
    eviction does not explain the live Kubernetes sample. The old direct-runc
    case holds the actor through OCI hook stages. The current Kubernetes Pod
    fixture does not cause the same pre-active action. Do not weaken the effect
    assertion or count Kubernetes as qualified for this behavior. The user
    confirmed this deferral on 2026-09-28. Continue other migrations.
  - [x] Remove only the matching old wait, result, and shell gate after the
    focused Host and direct-`runc` cases pass.
  - [x] `bash -n` passed for the changed launcher. The final Rust CI procedure
    passed. Its first run had one unrelated CLI test failure; that exact test
    and the complete rerun passed without a source change.
- [ ] Initial application activation: keep the entry action and `ACTIVE`,
  role, rule, default-effect, and large-argv assertions explicit.
  - [x] Replace the dynamic-loader policy exception with one standard
    platform test. Ask the shared Python actor to report its live dynamic
    loader mapping. Start one declared `bash` entry under
    `runtime_entries_policy.json`. Lower the public policy and require every
    mapped loader path to be absent from its signed path selectors. Require
    the Bash entry to keep its declared role and nonzero admission rule.
    Reuse the existing actor, policy, and Platform operations. Add no fixture
    or Platform API. Keep the test below 100 lines.
    - [x] Pass Host and commit it. The 68-line test passed in 31.41 seconds. It
      observed the declared shell role and entry rule. The Python actor
      reported the loader's absence from the lowered signed policy.
    - [x] Pass direct `runc` and commit it. The test passed in 31.44 seconds.
    - [x] Pass Kubernetes and commit it. The same test passed against the
      retained K3s cluster in 71.02 seconds.
    - [x] Remove only `dynamic_loader_paths`,
      `dynamic_loader_paths_absent_from_policy`, their old builder check,
      and the matching shell gate after all three platforms pass. The
      focused direct-`runc` entry-role probe and its complete remaining JSON
      gate passed after removal.
  - [x] Retire the duplicate application role and admission-rule check in the
    old direct-`runc` result. The shared `runtime_entries_stay_distinct` test
    already checks both fields and the active binding on Host, direct `runc`,
    and Kubernetes. Keep the old mount checks. The
    retained direct-`runc` probe passed after deletion. Its result no longer
    has the duplicate field. Shell syntax and repository Rust CI passed.
  - [x] Retire the synthetic application exec-transition check. The old runner
    froze the cgroup, wrote `CommitPending` directly to `process_states`, and
    called the identity verifier. `child_exec_keeps_identity` instead performs
    a real child exec through Node on Host, direct `runc`, and Kubernetes. It
    requires the task cookie and parent links to remain stable, a new execution
    and image provenance, and an active runnable state with no exec guard.
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
  - [x] Replace both legacy Kubernetes `subPath` alias results with one
    Kubernetes platform test. Use a Pod fixture with two real `subPath`
    mounts of the protected source. Command the shared mount actor to read the
    source and both aliases. Require `EACCES` for all three reads and fresh,
    task-attributed `PATH_TREE_POLICY_DENY` evidence. Add no Platform API.
    Remove only the two old results and their shell gates after this test
    passes against the retained K3s cluster.
    The 46-line test passed against the retained K3s cluster in 61.85
    seconds. It used two real Pod `subPath` mounts. The source and both
    aliases returned `EACCES`, and fresh attributed denial evidence was
    present. The two serialized legacy results and shell gates are removed.
    The reduced direct-`runc` probe passed, and its complete updated result
    predicate returned `true`.
  - [x] Reuse `EffectCheck` in `mount_protected.rs` for the protected bind
    denial. Keep the actor's successful mount, protected `EACCES`, allowed
    read, and task-attributed production evidence explicit. Pass Host,
    direct `runc`, and Kubernetes before committing.
    The 45-line test passed on Host in 50.63 seconds, direct `runc` in 61.34
    seconds, and real Kubernetes in 118.63 seconds. The replaced wait was
    local test plumbing; no old runner assertion was removed.
  - [ ] Replace the old protected-start in-container bind alias. Reuse
    `mount_alias.py` and `mount_alias_policy.json`. Start Node and install
    policy before the actor. Require the bind mount to succeed, the aliased
    secret read to fail with `EACCES`, the allowed read to succeed, and the
    exact attributed path-tree denial. Keep the old bind mount and read until
    the old mount-cache and five-denial capture checks have their own tests.
    - [x] Add the 68-line Rust test and the actor's `runtime` mode. The
      runtime already gives the actor a mount namespace. A second
      `MS_PRIVATE` call returned `EACCES` after Mithril reported
      `EXACT_POLICY_ALLOW`, so the new mode uses the runtime namespace. It
      still makes the protected bind and checks the denied read.
    - [x] Pass Host. All nine `mount_late_host` cases passed in 112.60
      seconds. Formatting and strict Mithril E2E Clippy passed.
    - [x] Pass direct `runc`. The exact case passed in 30.07 seconds. All
      nine `mount_late_runc` cases passed in 112.70 seconds with the current
      production OCI hook. The pin root, cgroup, and lease were removed.
    - [x] Pass real Kubernetes. The exact case passed in 67.52 seconds.
      All nine `mount_late_kubernetes` cases passed in 264.52 seconds. The
      test namespaces were removed.
    - [x] Remove the duplicate result field and shell gate. Keep the old
      action because it still drives mount-cache invalidation and the
      five-denial capture check. The complete old direct-runc probe passed
      after removal. Its mount-policy, capture, pin, lease, cgroup, and
      fixture-root gates passed, and the duplicate field is absent. The VM
      launcher passed `bash -n`. The repository Rust CI script passed after
      the final Rust edit.
    - [x] Replace the bind-mount cache check. The shared actor must stop after
      its successful bind mount. Read the production mutation, clean, and
      pending counters before the actor reads. Require a new mutation and a
      dirty view. Then require the protected read to fail and the control read
      to succeed. Keep the old mount-event receipt check until a shared test
      proves that receipt on all platforms.
      - [x] Pass Host. The 88-line `bind_refreshes_cache` test passed in the
        privileged VM. All ten related Host lifecycle tests passed in
        111.49 seconds. No old assertion was removed.
      - [x] Pass direct `runc` in a separate commit. The exact case passed in
        29.57 seconds with the production OCI hook. All ten related direct
        `runc` lifecycle tests passed in 117.34 seconds.
      - [x] Pass real Kubernetes. The exact case passed in 68.55 seconds.
        All ten related Kubernetes lifecycle tests passed in 297.38 seconds.
        The first attempt stopped before the actor: the retained VM was 97%
        full and K3s could not schedule Control. The recovery removed seven
        superseded test binaries, restarted only K3s, and restored the pinned
        actor image. The unchanged test then passed. Keep the VM disk below
        pressure limits.
      - [x] Remove only the old duplicate dirty-view assertion. The rebuilt
        complete direct-`runc` probe passed. At that point, its mount-event
        receipt, control read, five-denial capture, stale-cache repair, reader
        burst, and cleanup checks remained. Its schema is still version 40.
        The repository Rust CI script passed. Keep the old mount action until
        those distinct checks have shared coverage.
    - [x] Replace the old successful bind-mount event receipt.
      - [x] Use the shared `mount_alias.py` actor and signed policy. Record the
        public production observation cursor before the actor mounts. Require
        a successful bind mount and a new Mount/Mount effect from that actor.
        The 93-line standard test passed on Host in 45.91 seconds, direct
        `runc` in 65.77 seconds, and Kubernetes in 101.30 seconds. The related
        12-case lifecycle passed on Host in 151.24 seconds, direct `runc` in
        265.08 seconds, and Kubernetes in 356.06 seconds.
      - [x] Retire the old event wait. Its actor now writes the existing
        mount-result file before it waits on the FIFO. The old runner waits
        for that result before it releases the FIFO. The full direct-`runc`
        probe passed with the unchanged later mount, path-tree, reader-queue,
        and cleanup assertions. Its schema remains version 40. The new shared
        test owns the production Mount/Mount event assertion.
      - [x] Use the existing `EffectCheck` for the signed mount allow. The
        test now has 58 lines and requires a fresh, task-attributed
        `EXACT_POLICY_ALLOW` Mount/Mount result. The focused Host, direct
        `runc`, and Kubernetes cases passed again without a platform change.
    - [x] Retire the duplicate path-tree control allow result. The existing
      `preexisting_bind_keeps_policy` test requires the control read content
      and its fresh, task-attributed `EXACT_POLICY_ALLOW` after the bind
      change on Host, direct `runc`, and Kubernetes. Remove only
      `path_tree_control_allowed` and its shell gate. Keep the old action for
      the remaining mount sequence. The focused old direct-`runc` probe and
      its complete remaining JSON gate passed after removal.
  - [x] Retire the duplicate in-container bind-mount result and shell gate.
    `late_bind_keeps_policy` requires the mount to succeed after production
    policy activation on Host, direct `runc`, and Kubernetes. Keep the legacy
    mount action and its local failure check while the separate subPath and
    bind-alias reads still use that mount. On 2026-09-26, the exact Host,
    direct-`runc`, and Kubernetes tests passed with the removed result field.
    The VM harness checks passed. Each run removed its test resources.
- [ ] Concurrent exec and reader-queue saturation: keep the same containerd
  exec operation, topology snapshots, bounded queue, and fail-closed results
  as `two-node-convergence.sh`.
  - [x] Replace the five-denial capture check with `capture_keeps_path_denials`.
    Use the existing `read_path.py`, signed mount policy, `EffectCheck`, and
    `mount_late` lifecycle. Capture five real `OpenRead` denials through the
    production Node snapshot API. Require `EACCES`, the actor task cookie,
    signed role and entry rule, current generation, and a zero exact-object
    key. Make more denied reads. Require the first five source IDs to leave
    Node's recent window but stay in the captured results. Require unchanged
    queue-drop, lost-event, decoder-error, evidence-error, and WAL-block counts.
    Keep the test below 100 lines. Add no actor, Platform API, or legacy helper.
    - [x] Pass Host. The 98-line test passed in 52.33 seconds. All 2,053
      physical reads returned `EACCES`. The five captured source IDs left
      Node's recent window. Queue-drop, lost-event, decoder-error,
      evidence-error, and WAL-block counts did not change. Normal pin, lease,
      cgroup, and output cleanup passed. No fixture or Platform API changed.
      Strict crate Clippy passed. The repository Rust gate passed formatting,
      workspace check, and strict Clippy, then stopped at the unchanged
      `retained_wal_survives_restart` acknowledgement deadline. Its unchanged
      focused check passed in 3.63 seconds. The timeout cause is not proved.
      Run the final Rust gate again after registration and legacy retirement.
    - [x] Pass direct runc. The unchanged body passed in 63.67 seconds
      through stock runc and the production OCI hook. All 2,053 reads,
      captured fields, window changes, health counters, and normal cleanup
      checks passed. Only platform registration changed.
    - [x] Pass Kubernetes. The same 98-line capture body and the existing
      actual subPath test passed together: two tests in 120.90 seconds.
      The Pod fixture now keeps the original older-alias, source, newer-alias
      mount order. Both denials and normal namespace cleanup passed. Control,
      Node, BPF, Platform code, and readiness limits did not change for these
      two cases. The existing local VM harness checks passed.
    - [x] Remove only the old five-denial count and its string matchers after
      all three pass. The deletion removes 62 Rust lines.
      Keep the separate full-interval overlap capture and obsolete-row
      collection checks. This test does not replace those checks. The final
      repository Rust gate passed for this deletion-only source state. It
      used normal ignored-test exclusions and no extra skips. See
      `/tmp/mithril-reader-capture-count-final-ci-20261002.log`.
      The remaining legacy probe failed before the deleted count: no READY
      snapshot existed at cache generation 23. Its original physical setup,
      alias traffic, assertions, and cleanup sequence are unchanged. The
      failure cause is not proved. See
      `/tmp/mithril-reader-capture-count-retirement-20261002.log`.
    - [ ] Retire the duplicate Rust subPath actions and physical setup after
      the existing Kubernetes subPath test passes again. Keep the original
      older-alias, source, newer-alias mount order in its Pod fixture. Remove
      `FixtureBindMounts` and its fixture-only test when its last legacy
      consumer is gone. Keep the bind-alias read that supplies the current
      cache to the separate overlap and obsolete-row checks. Verify the
      complete reduced legacy probe before committing the deletion.
      Both fixture-deletion drafts are withdrawn. Removing the alias traffic
      or replacing the host-side nested binds with native OCI sources failed
      the same READY-cache precondition. The original setup also failed before
      the retired count. These results do not prove that either draft caused
      the failure. `FixtureBindMounts` and its cleanup test are restored without
      changes. Add no warm-up helper or new step to the old runner. Complete
      the dependent shared cache qualification before deleting this fixture.
  - [x] Make [CacheView](src/physical/mount_cache.rs) comparable with `Eq`
    and `PartialEq`. Read `MountCache::snapshot` in the same file for the
    cache map layout and row selection. The snapshot does not write a map.
    Keep the actor namespace, mutation epoch, generation, READY keys, and
    mountinfo digest. A READY row must have a positive mount count, as in the
    original runtime probe. Existing rebuild, mount-attribute, and propagation
    callers passed on Host, runc, and Kubernetes in the physical matrix.
    The final repository Rust CI gate passed on 2026-10-02. This tooling does
    not prove concurrent exec, Node collection, or scenario retirement.
  - [x] Reproduce the cold host-namespace cache with
    [cold_runtime_builds_cache](src/identity/scenarios/runtime_cold_view.rs).
    Reuse [mount_alias.py](fixtures/process/mount_alias.py), the signed
    wildcard policy, and [proc_read.py](fixtures/process/proc_read.py).
    The host-namespace probe enters the workload cgroup and reads its real
    process environment. Require exactly one added READY row. Keep the actor
    namespace, mountinfo, epoch, generation, and existing rows unchanged.
    The exact direct-runc case passed in 38.42 seconds on 2026-10-02 and
    44.29 seconds on 2026-10-04. Normal cleanup and owned path removal passed
    in the current-source run. See
    `/tmp/mithril-cold-audit-runc-current-20261004.log`.
    Read `ProcessFixture` for process ownership and `MountCache::snapshot`
    for read-only map selection. This reproduction does not qualify the
    separate concurrent-exec or startup-probe conditions. No old check is
    removed by this commit.
  - [ ] Make the existing `add_actor` receiver shared. Keep normal return,
    denial, readiness, and cleanup behavior. Use a standard mutex only for
    Kubernetes approval state. Give each direct-runc exec a temporary PID-file
    directory. Do not add a batch method, clone the Platform, serialize the
    exec requests, or change production. Qualify the common tooling before
    its dependent migration. Run the full physical matrix for this change.
    - Fresh related checks passed on 2026-10-04: Host entry-role isolation
      in 32.55 seconds, direct-runc signed-entry replacement in 54.42 seconds,
      and Kubernetes entry-role isolation in 76.30 seconds. Normal cleanup
      passed. These focused results do not close the full-matrix gate.
    - [x] Handle removal during an actor-cgroup cleanup read. The final
      Kubernetes matrix stopped at `exec_path_recovery_kubernetes` after its
      security assertions. Containerd removed the empty cgroup between open
      and read. Linux returned `ENODEV`. Before the fix, a real-cgroup test
      reproduced this result in 0.12 seconds. It first required `EBUSY` for
      removal of the live, populated group. Read `ProcessFixture::stop` and
      `group_removed` in [process.rs](src/process.rs). Accept `ENODEV` only
      for that cleanup read. Keep permission and other I/O errors as failures.
      The fixed native regression passed in 0.10 seconds. Twelve process
      fixture unit tests passed. The unchanged paired Host scenario passed
      in 32.56 seconds before Kubernetes passed in 81.71 seconds. All owned
      resources were removed. The final repository Rust CI gate passed:
      97 E2E tests, 508 ignored physical cases, and 255 Node tests. See
      `/tmp/mithril-cgroup-removed-repro-20261004.log` and
      `/tmp/mithril-cgroup-fixed-final-ci-20261004.log`. No production or
      scenario assertion changed. Resume only the unrun matrix groups.
    - [x] Check tracked-process disappearance before actor-wrapper status in
      `ProcessFixture::wait_gone`. The denied FD-exec scenario reached its
      assertions, but cleanup reported the wrapper's late exit after the
      tracked child was already absent. The fixture still rejects a live child
      after wrapper exit. Its existing regression failed before the fix and
      passed after it. The unchanged FD-exec scenario passed on Host in
      28.05 seconds, direct runc in 36.14 seconds, and Kubernetes in
      75.14 seconds. All owned resources were removed. The final repository
      Rust CI gate passed with 98 E2E tests and 255 Node tests. See
      `/tmp/mithril-process-order-repro-20261004.log`,
      `/tmp/mithril-process-order-fixed-20261004.log`,
      `/tmp/mithril-process-order-final-ci-20261004.log`, and
      `/tmp/mithril-fd-exec-final-kube-20261005-standard.log`.
      No production code or security assertion changed.
    - [x] Commit the tested shared-receiver tooling for the bounded cleanup.
      Read `start_entry` in [Host](src/platform/host.rs),
      [Runc](src/platform/runc.rs), and [Kubernetes](src/platform/kubernetes.rs).
      Runc owns one temporary PID directory per exec. Kubernetes locks only
      its approval state. [Observation](src/platform/observation.rs) bounds
      the existing SDK snapshot call. [Shared](src/platform/shared.rs) uses
      the production Node runtime type. Related entry checks passed on all
      three platforms. The final workspace CI gate passed on 2026-10-05.
      Full-suite qualification remains open; these checks do not qualify
      the unchanged startup-SIGTERM or intermittent counter failures.
  - [ ] Replace the old 32-request overlap with one shared Rust test below
    100 lines. Use the shared mount actor and existing policy. Release all
    32 `add_actor("sleep", ...)` calls at one thread barrier while the main
    actor reads the protected path. Require every exec to fail with `EACCES`,
    positive read count, no allowed or other read, fresh task-attributed
    `PATH_TREE_POLICY_DENY`, no unresolved evidence, unchanged namespace,
    mountinfo, security epoch, cache generation and READY keys, and increased
    mount activity. Keep the old Rust and shell assertions until this passes.
    - [x] Restore the exact `mount_security_views` key check after the
      requests. The baseline checks this map before and after the overlap.
      `CacheView` equality does not check this map. Use the existing map reader;
      add no Platform API. Keep the probe and collection dependencies open.
      Check the keys before the actor stops. Node can retire the namespace
      after actor exit. The review route is
      [runtime_mount_view.rs](src/identity/scenarios/runtime_mount_view.rs),
      [MountCache::snapshot](src/physical/mount_cache.rs), and
      [KernelStateReader::keys](../erebor-interceptor/src/host.rs). The test
      reads the map. Node retains loader and cleanup ownership. The final
      96-line test passed on runc in 169.24 seconds and real Kubernetes in
      97.74 seconds on 2026-10-05. The runc state, cgroup, and BPF pins were
      removed. Kubernetes left only system Pods, no scenario files, and no
      owned runtime socket or BPF root. The output parent directory is empty.
      The first Kubernetes command lost its result when the host output
      capture failed with `ENOSPC`. The verified command kept its full log in
      the VM and returned exit zero. The test and timeout did not change.
      VM harness checks passed. The non-privileged library suite passed:
      159 passed, 0 failed, 524 ignored. The final Rust CI formatting,
      workspace check, and strict Clippy passed. Workspace tests stopped at
      the unchanged ArData `observability_raw_recovery` test with
      `AnalysisReadDeadline`. That test shares one one-second control across
      four reads, intervening writes, and a store reopen. Production code is
      unchanged. Full workspace and platform qualification remain open.
    - [x] Keep the recursive wildcard from the original `/srv/**/secrets`
      policy. The shared policy uses `/work/mount/**/secret`. The overlap
      actor opens the bind alias of `/work/mount/team/blue/secret/blocked`.
      Existing actors still test the zero-segment wildcard case.
    - [x] Bound actor work without ending the protected read loop before the
      exec requests complete. The first draft made 491,161 denied reads and
      exceeded the normal policy-retirement readiness limit. The old actor
      made at most 16,384 attempts. The actor now waits on its stop event
      between reads and fails if 16,384 reads complete without a stop command.
      Keep the separate reader-queue burst test.
    - [x] Pass the 95-line overlap test on direct runc and real Kubernetes.
      On 2026-10-02, direct runc passed in 38.43 seconds and Kubernetes passed
      in 91.04 seconds. The runtime receives one earlier undeclared entry
      before the baseline snapshot, as the old probes did. All entries must
      return `EACCES`. Exact cache-key equality remains required.
    - [ ] Retire the matched Rust overlap after the common tooling commit.
      Remove its embedded actor loop, FIFO, result field, predicate, and
      matcher. Keep the later stale-cache repair and row-collection checks.
      Read their baseline cache immediately before the stale-cache action.
      The 182-line deletion draft compiled but failed the remaining collector
      precondition: no READY row existed in the current cache generation.
      The removed actor loop also warmed that cache. The deletion is withdrawn;
      the old runner and launcher now match HEAD. A proposed warm-up rewrite
      in the old runner was rejected because it added legacy orchestration.
      - [x] Remove the duplicate overlap result, cache comparison, denial
        matcher, and launcher predicate. The shared runc and Kubernetes cases
        and native startup-probe case are qualified. Keep the existing 32-exec
        warm-up, actor loop, FIFO, and collector baseline unchanged. Their
        removal still needs the independent collector replacement. Add no
        orchestration or Platform API to the old runner.
        On 2026-10-06, retirement removed 125 net Rust lines and one launcher
        predicate. The remaining runc source has 4,475 lines. The unused
        private observation store, matcher test, and snapshot fields are gone.
        The shared tests retain every baseline overlap comparison and require
        exact READY-key equality, task attribution, and complete capture.
        Read [runtime_exec_keeps_mount_view](src/identity/scenarios/runtime_mount_view.rs)
          -> [probe_keeps_mount_view](src/identity/scenarios/probe_mount_view.rs)
          -> [MountCache](src/physical/mount_cache.rs) for read-only cache state
          -> [EffectCheck](src/effect/check.rs) for production observation capture.
        The actor loop and collector remain in [the old runner](src/effect/runc.rs).
        Capture checks passed all three tests. VM harness checks, shell syntax,
        and final repository Rust CI passed. E2E passed 159 ordinary tests,
        with 540 physical tests ignored; Node passed 265 tests. See
        `/tmp/mithril-overlap-retire-verified-ci-20261006.log`.
        No production, Platform, actor, or shared assertion changed. The prior
        focused physical results apply to those unchanged shared tests. No
        full physical matrix was run for this deletion.
      Add no replacement warm-up helper there. Preserve the old coverage until
      the shared collector replacement can remove this dependency. The final
      Rust CI gate remains required for the shared fixture changes.
    - [ ] Capture the full request interval through Node snapshots. A final
      snapshot contains only recent events and can omit an earlier unresolved
      result. The existing `EffectCheck` now collects fresh observations
      during the action and rejects a per-CPU sequence gap. Keep the denial
      and no-unresolved assertions in the 95-line test. Qualify the revised
      test on direct runc before Kubernetes. Both physical matrix processes
      ended before the revised executable was built. The revised direct-runc
      test passed in 44.93 seconds. Kubernetes passed the scenario assertions,
      then failed normal retirement after 180 seconds. Node still reported
      one active runtime binding. The case is not qualified. Reproduce the
      missing cleanup condition in lightweight before a fix or Kubernetes
      rerun. The final Rust CI gate passed on 2026-10-02.
      A fresh direct-runc run on 2026-10-04 found a capture sequence gap.
      Protected reads started before the capture pump was ready. The pump
      now confirms its first snapshot before the action starts. The actor
      starts its protected loop inside that action. The unchanged sequence
      check then passed on direct runc in 50.40 seconds and Kubernetes in
      112.87 seconds. Both runs completed normal cleanup. The capture review
      still requires an exact end watermark: a last recent-window snapshot
      alone can miss an event that Node has not delivered yet. Keep this
      capture gate open until that condition is fixed and verified.
      The exact-watermark draft failed on 2026-10-04. The final diagnostic
      run found a permanent CPU-0 sequence gap from 1173 to 2536 with zero
      kernel loss. Sixteen captured hard results were `UNSUPPORTED_OBJECT`
      exec denials with `EACCES`. No captured result was `UNRESOLVED_OBJECT`,
      but the missing interval prevents that negative claim. Removing extra
      per-denial snapshot requests and the capture poll delay did not fix
      the gap. The public snapshot keeps 1,024 recent records and provides
      no cursor, page, or stream. Do not reopen an active WAL or Control store,
      add a competing ring reader, or accept incomplete capture. See
      `/tmp/mithril-overlap-fixture-opt-runc-20261004.log`. No Kubernetes
      rerun followed this lightweight failure. Keep the old coverage.
      The revised collector uses the opening and closing kernel sequence
      watermarks. It rejects missing records, new reader faults, and kernel
      loss. It counts captured `UNSUPPORTED_OBJECT` and `UNRESOLVED_OBJECT`
      hard results separately from the test's explicit no-unresolved check.
      Three collector unit tests passed. The Node fixture used a single-thread
      runtime, but the production Node binary uses a multi-thread runtime.
      Admission performs synchronous kernel and durable-state operations.
      Change only the fixture Node runtime to the production runtime type.
      Keep all 32 simultaneous exec requests and all read assertions unchanged.
      With this configuration, direct runc passed in 45.96 seconds and
      Kubernetes passed in 93.68 seconds. Both commands completed normal
      cleanup. See `/tmp/mithril-overlap-production-runtime-runc-20261004.log`
      and `/tmp/mithril-overlap-production-runtime-kube-20261004.log`.
      No production code changed. No client cache or new Platform API was
      added. These focused results qualify the draft, not the full fixture
      matrix. Keep full-suite qualification and the old Kubernetes
      startup-probe overlap open after the bounded cleanup commits.
      [The 95-line scenario](src/identity/scenarios/runtime_mount_view.rs)
      starts the protected read loop inside
      [EffectCheck::capture](src/effect/check.rs). The collector reads the
      opening and closing kernel counters and gathers public Node snapshots.
      The scenario checks all 32 exec denials, denied reads, exact cache
      equality, and absence of unresolved results. The same Kubernetes body
      passed in the later 11-case group; that group had one unrelated TID
      counter failure. No legacy coverage is removed by this cleanup commit.
    - [ ] Preserve the real Kubernetes probe overlap before shell retirement.
      The old startup probe retries `cat` while its last input file is absent.
      The launcher creates that file after the 32 exec requests. The file is
      not a FIFO, and the probe does not hold a process open. The current
      replacement Pod has no startup probe. The separate probe-entry test
      proves classification, not this mount-cache overlap. Keep the old
      Kubernetes actor and shell assertions until this condition passes in
      the shared Rust test. Use existing physical setup and `add_actor`.
      Do not add a Platform API or a second runner.
      - [x] Qualify `probe_keeps_mount_view` as one Kubernetes Rust test below
        100 lines. Reuse `mount_alias.py` in `overlap` mode. Use a Pod fixture
        with a real StartupProbe `cat` command and a distinct signed policy.
        The probe reads the ready input, the secret, and an absent final file.
        Keep the worker's recursive secret denial and the probe's secret Allow.
        Require an unready Pod, 32 simultaneous undeclared exec denials,
        positive denied reads, zero allowed reads, unchanged mount namespace,
        mountinfo, epoch, generation, READY keys, and one security-view key.
        Create the final file after the requests. Require Pod readiness before
        stopping the actor. Retain attributed denial and loss-aware evidence
        checks. The paired direct-runc overlap is already qualified.
        The first native run kept namespace, mountinfo, epoch, and generation,
        but READY keys increased from one to two. Declared `cat` exec alone
        did not reproduce this on Host or runc, including runc after exit.
        The unchanged `cold_runtime_builds_cache` case passed on runc in
        30.30 seconds. A cold runtime lookup added exactly one READY row while
        the protected actor's namespace, mountinfo, epoch, and generation
        stayed unchanged. Require the native probe's attributed secret read
        before the overlap baseline. Keep exact equality after the requests.
        The failed diagnostic draft was removed; it added no baseline coverage.
        The 99-line native case passed in 77.09 seconds on 2026-10-06.
        All 32 exec requests were denied. The worker had positive denied reads,
        zero allowed reads, and zero other errors. The final file made the Pod
        Ready before the worker stopped. Exact cache equality, one security
        view, increased mount activity, complete delivery, no unresolved result,
        and normal cleanup passed. No production or Platform API changed.
        Logs: `/var/tmp/mithril-native-cold-proof-runc-20261006.log` in the
        lightweight VM; `/var/tmp/mithril-probe-ready-kube-20261006.log` in K3s.
        Review [the shared test](src/identity/scenarios/probe_mount_view.rs):
        [the Pod fixture](fixtures/kubernetes/probe-mount-view-pod-v1.yaml)
        runs the native probe under
        [the signed policy](fixtures/process/mount_probe_policy.json).
        -> [EffectCheck](src/effect/check.rs) confirms the attributed probe read.
        -> [MountCache](src/physical/mount_cache.rs) reads the existing map ABI.
        -> [the actor](fixtures/process/mount_alias.py) runs protected reads
        during 32 real exec requests. The test opens the gate and stops normally.
        The replacement is qualified. Full-suite qualification remains open.
        The three capture checks, VM harness checks, and shell syntax passed.
        Final format, workspace check, strict Clippy, and workspace tests passed.
        See `/tmp/mithril-native-probe-final-ci-20261006.log`. This gate covers
        the final 99-line test and matching shell assertion removal.
      - [ ] Remove only the matching shell overlap checks after this native
        probe passes. Keep the mount-cache collector setup and assertions
        until their independent platform replacement passes.
        The duplicate six-field cache comparison is removed. The snapshots,
        exec helper, read loop, and gate still prepare the collector and its
        failure diagnostics. Keep those inputs until the collector qualifies.
    - [ ] Revisit concurrent Host entry setup. The Host trial timed out at
      actor exit and was removed from the attribute. Do not claim Host support
      or change production to make this trial pass. The old overlap check
      used containerd, not Host entry setup.
    - [ ] Complete common-fixture qualification before its commit. The
      Host, runc, and Kubernetes lifecycle matrix was run. The
      pre-existing uncommitted `file_gate` draft is not a qualified baseline
      case and is excluded. Crate tests passed: 92 library tests and two binary
      tests. Workspace formatting, check, and strict clippy passed. Workspace
      tests stopped at the unchanged CLI test
      `cli::start::tests::start_builds_surface_launch_plan`: actual surfaces
      are BrowserCdp and Terminal; the assertion expects BrowserCdp only.
      The physical matrix found a missing VM prerequisite: `clean_host_restarts`
      could not start `clang`. Install `clang` and `libbpf-dev` in the retained
      test VM. Rerun this exact case after the current VM lane ends. Do not
      replace its fresh compilation with a prebuilt object or change assertions.
      A second failure occurred in `poststart_uses_literal_path` on direct
      runc. After Node restart, `runc exec cp` exited before PID publication.
      The diagnostics report one placement mismatch and a
      `CORRUPT_IDENTITY_OR_GENERATION` denial. The cause is not yet proved.
      Run the exact case, then its five-case `node_restart_runc` lifecycle.
      Keep the test order, policy, assertions, and readiness limits unchanged.
      The lightweight matrix completed 124 lifecycle groups: 312 passed and
      these two cases failed. Fresh compilation passed in 26.65 seconds after
      the prerequisite installation. The unchanged PostStart case passed in
      79.73 seconds. Its five-case lifecycle then passed in 287.59 seconds.
      Normal resource cleanup passed for all three focused commands. The
      initial PostStart failure is not a proved or fixed production defect.
      Kubernetes failed `unmatched_signal_is_denied` before its signal action.
      Policy readiness timed out with Accepted and Compiled true, but zero
      desired and active targets. The recovery scenario had an actor before
      Node. Trace the missing target and reproduce a missing external condition
      in lightweight before an implementation change or Kubernetes retry.
      Do not lower the expected target count or increase the readiness limit.
      The retained log is
      `/tmp/mithril-runtime-tools-kube-matrix-20261002.log`. It has no matching
      Pod inventory, image digest, Node identity, or target rejection reason.
      Accepted and Compiled with zero targets does not prove the cause.
      The final repository Rust CI gate passed for the current test and
      receiver edits on 2026-10-04. See
      `/tmp/mithril-pending-final-ci-after-fixture-20261004.log`. This result
      does not qualify a later owner or capture change.
      The final Rust CI gate passed after the last Rust edit on 2026-10-04.
      The E2E library run passed 94 tests and ignored 505 physical cases.
      The Node library passed all 255 tests. See
      `/tmp/mithril-approved-owner-final-ci-20261004.log`. This result does
      not close the physical matrix gate.
      The parallel process fixture group exposed `ETXTBSY` in
      `fatal_exec_dies`. Another test's child can inherit the writable ELF
      descriptor before exec closes it. The test now runs its unchanged ELF
      write, real exec, and fatal-signal assertion in an isolated child test
      process. No retry, sleep, accepted error, or production change was added.
      The exact test and all 12 process fixture tests passed. See
      `/tmp/mithril-fatal-exec-isolated-group-20261004.log`.
      On 2026-10-05, the final workspace Rust CI gate passed: 98 E2E tests,
      508 ignored physical cases, and 255 Node tests. See
      `/tmp/mithril-final-pending-ci-20261005.log`. The physical lightweight
      matrix completed with 339 passes and eight failures. Focused checks
      then passed the FD-exec cleanup case, the live-Node stall case, all four
      installer cases, and the unchanged socket-relation case. This gives
      346 passed cases across runs, not a single green 347-case matrix.
      The installer cases used the real K3s binary from the retained cluster;
      no installer or second cluster was started. See
      `/tmp/mithril-platform-runtime-installer-final-20261005.log`.
      Keep `startup_sigterm_is_recoverable` open. The current Node binary was
      killed by SIGTERM on the matrix run and the diagnostic run. The test
      still requires graceful exit, retained pins, and successful recovery.
      Production remains unchanged. This cleanup does not add a Node fix. See
      `/tmp/mithril-platform-startup-signal-diagnostic-20261005.log`.
      The approved stock-probe diagnostic passed in 81.34 seconds. Its earlier
      admission timeout remains unexplained. The 11 formerly blocked Kubernetes
      bodies then ran: ten passed, including the mount test; `tid_reuse_is_fresh`
      failed its first global allocator check (7811 instead of 7810). Later TID
      assertions did not run. The unchanged Host and runc cases passed with the
      same diagnostic sampler in 30.41 and 39.93 seconds. This did not reproduce
      the extra ID. Keep both exact allocator assertions and the cause open.
      See `/tmp/mithril-identity-blocked-final-kube-20261005.log` and
      `/tmp/mithril-tid-sampler-host-20261005.log`.
      The remaining Kubernetes qualification completed all 41 previously
      unrun lifecycle groups: 60 passed and one failed across 61 cases.
      Groups 32 through 62 passed all 35 cases. No failed case was retried.
      `effect::file_bind_allowed::allowed_bind_keeps_exact_allow::mount_late_kubernetes`
      failed during Python startup. Python could not read
      `/usr/local/lib/python3.13/encodings/aliases.py`. The read failed with
      `EACCES`; Python exited with status 1. The actor script and mount action
      did not run. The result assertions did not run.
      The retained evidence does not identify the BPF denial reason.
      Keep the cause open; no policy, assertion, timeout, or production code
      changed. Every completed group removed its owned pins, lease, sockets,
      output, namespaces, CRI records, and Rust process. See
      `/tmp/mithril-platform-final-remaining-kube-20261005.log` and
      `/tmp/mithril-kube-unrun-progress-20261005-22942.log`.
      The pending test and fixture changes are committed. Final qualification
      is not green: the startup-SIGTERM, Kubernetes allocator, and Python
      startup failures remain open. This cleanup does not resume migration.
  - [ ] Replace the detached-exec overlap with
    `runtime_exec_keeps_mount_view`.
    - [ ] Use the shared mount actor and the existing `Platform::add_actor`
      operation. Do not add a platform API.
    - [ ] Keep protected reads active while 32 undeclared `sleep` entries fail
      with `EACCES`.
    - [ ] Require at least one protected read, no allowed or unresolved read,
      and an attributed `PATH_TREE_POLICY_DENY` result.
    - [ ] Require the actor mount namespace, mountinfo, security-view state,
      canonical cache generation, and canonical cache keys to stay unchanged.
      Require mount activity to advance without advancing the mutation epoch.
    - [ ] Pass and commit Kubernetes. Both old launchers execute this case
      through containerd: the Kubernetes launcher uses K3s `crictl exec`, and
      the VM launcher always supplies `--containerd-path`. Host and stock
      `runc` do not execute detached containerd mount preparation.
    - [ ] Remove the matching legacy Rust, actor, shell, result, and launcher
      assertions only after the Kubernetes replacement passes.
    - A rejected draft kept the protected read active but called
      `Platform::add_actor` 32 times in sequence. This weakens the old
      simultaneous 32-request condition. At that time, the operation borrowed
      the platform mutably until each request finished. The draft was removed.
      The new shared-receiver tooling permits one barrier to release all
      requests. Do not add a batch operation or expose Kubernetes or
      containerd setup to the scenario. Keep the remaining probe condition
      and legacy removal checks open.
  - [x] Replace the 70,000-read queue burst with `reader_burst_keeps_events`.
    Use the deployed Node observation path. Require the public attempted count,
    a later application child exec, a drained evidence backlog, and unchanged
    queue-drop, lost-event, decoder-error, evidence-error, and WAL-block counts.
    - [x] Pass Host and commit it. The exact ignored Host test passed in the
      retained VM in 35.64 seconds with 70,000 denied reads.
    - [x] Pass direct `runc` and commit it. The exact ignored direct-`runc`
      test passed in the retained VM in 41.76 seconds.
    - [x] Pass Kubernetes and commit it. The exact ignored Kubernetes test
      passed in the retained K3s VM in 84.44 seconds and completed teardown.
    - [x] Remove the matching legacy actor commands, private observation store,
      result field, and shell predicate after all three platforms pass. The
      focused build and shell syntax checks passed. This removes 145 net lines
      from `effect/runc.rs` and one shell predicate. The old probe reached its
      separate concurrent mount-topology check after all 32 undeclared execs
      were denied; that behavior remains for its own migration.
- [ ] Stale cache repair and unreachable-row retirement: keep the production
  node reconciliation calls and exact map absence checks visible.
  - [ ] Replace old-row collection with `obsolete_cache_is_collected`.
    Reuse the signed mount policy, read actor, `MountCache`, and `mount_late`
    lifecycle. Keep both denied reads and fresh attributed evidence. Require
    real obsolete object and state rows after the stale-count rebuild. Let
    the running production Node collect them. Require zero obsolete rows,
    retained current rows, and unchanged READY keys, generation, epoch,
    namespace, and mountinfo. Do not call an internal collector or force a
    policy change. Keep the test below 100 lines.
    - [x] Extend the existing map fixture with checked typed keys and row
      counts. Verify the tooling through the existing rebuild test on Host,
      direct `runc`, and Kubernetes before the dependent migration.
      The 89-line rebuild case passed on Host in 30.28 seconds, direct `runc`
      in 31.89 seconds, and Kubernetes in 72.03 seconds. Both real maps contain
      obsolete and current rows after rebuild. All cleanup checks passed.
      The repository Rust CI gate and local VM harness checks passed. The map
      owner stays in one 173-line file. No Platform or production code changed.
      This result proves row observation, not Node collection.
    - [ ] Pass and commit Host, then direct `runc`, then Kubernetes. A missing
      Node collection trigger is a production approval boundary, not grounds
      to weaken the test or add an unrelated runtime event.
      The 95-line Host draft reached the collection wait and failed in 58.78
      seconds on 2026-10-01. Both physical reads returned `EACCES` with fresh
      attributed `PATH_TREE_POLICY_DENY` evidence. BPF rebuilt the cache.
      After 30 seconds, 18 object rows and 2 state rows remained; 9 object
      rows and 1 state row were obsolete. Cleanup passed. See
      `/tmp/mithril-cache-collection-host-20261001.log`.
      `NodeBindingReconciliation::reconcile` returns when CRI is unchanged.
      The obsolete-row collector runs only through exact-binding
      reconciliation. The policy timer runs generation retirement only
      when retirement is pending. A BPF cache generation change does not
      reach either cleanup path. The old direct-runc probe calls the
      collector path explicitly; this masks the missing Node trigger.
      No production fix is authorized. Keep the unchanged-CRI early return.
      The user accepted this lightweight reproduction on 2026-10-01.
      This acceptance does not authorize a production change.
      A proposed fix checks the mount epoch and cache generation in the
      existing reconciliation path and collects only when that pair changes.
      Do not re-install policy or re-run exact-binding reconciliation for
      cache cleanup. Keep errors visible and retry cleanup after an error.
      The draft is retained at
      `/tmp/mithril-cache-collection-repro-20261001.rs`, outside the crate.
      No runc or Kubernetes collector run was attempted. Keep the old checks.
      After the draft was removed from the crate, the final repository Rust
      CI procedure passed. No production source or Platform API changed.
    - [ ] Remove only the matched old Rust collector check, result field,
      shell row counters, and launcher predicates after all three pass.
  - [x] Replace only stale-cache rebuild with a small standard platform test.
    Reuse `read_path.py` and `mount_alias_policy.json`. Start Control and Node,
    install the signed policy, and admit the actor normally. Require a denied
    recursive-tree control read and a READY cache. Decrease the ready row's
    mount count, as the old test does. Repeat the read. Require `EACCES`, fresh
    attributed `PATH_TREE_POLICY_DENY`, no unresolved result, a newer cache
    generation and new READY keys, and the same mutation epoch, mount namespace,
    and mountinfo. Use installed Linux and libbpf bindings. Use checked typed
    cache layouts, not literal byte offsets. Add no Platform or production API.
    - [x] Verify shared map tooling, then pass and commit Host. The 86-line
      standard test passed in 28.17 seconds. It uses the existing Python
      actor, signed policy, and `mount_late` lifecycle. The map fixture owns
      a libbpf handle, checks the loaded map sizes, and uses typed native-endian
      layouts from the named C structures. The test retained both actual
      `EACCES` results, fresh attributed denial, no unresolved event, new READY
      keys and generation, and unchanged namespace, mountinfo, and epoch.
      Pin, lease, and cgroup cleanup passed. No production or Platform API
      changed. See [CACHE_REBUILD_REVIEW.md](CACHE_REBUILD_REVIEW.md).
      The repository Rust CI procedure passed after the final Rust edit.
    - [x] Pass and commit the same test on direct `runc`. The unchanged
      86-line body passed in 28.79 seconds through stock `runc` and the
      production OCI hook. Pin, lease, and cgroup cleanup passed. The final
      repository Rust CI procedure passed after registration. No fixture or
      production source changed.
    - [x] Pass and commit the same test on Kubernetes after lightweight. The
      unchanged 86-line body passed in 68.10 seconds with deployed Control,
      Node, policy CRDs, and the actor Pod. Namespace, pin, and lease cleanup
      passed. The final repository Rust CI procedure passed. No Kubernetes
      fixture, launcher, or production source changed.
    - [x] Remove only the old rebuild assertion, result flag, and launcher
      gates after all three pass. Keep the old corruption/read setup and both
      obsolete-row checks until production collection has a verified shared
      replacement. Do not replace collection with another rebuild assertion.
      The replacement matches all five topology comparisons in baseline
      `95775f48` and requires actual denial and fresh attributed evidence.
      Retirement deletes 21 Rust lines and one `run.sh` predicate. Both
      focused runc regressions and the VM harness behavior checks passed.
      The real Kubernetes shell keeps its rebuild wait because the wait is
      also the readiness boundary for its still-unmigrated collector check.
      The repository Rust CI procedure passed after the retirement edit.
      No production, Platform, or physical fixture change was required.
- [x] Independent additional entries: keep each declaration, stock exec,
  role, rule, process state, and isolation assertion.
  - [x] Retire only the old overlapping PostStart and StartupProbe role
    comparison. `runtime_entries_stay_distinct` holds both stock entries at
    the same time and checks their signed roles, admission rules, task
    cookies, process states, and execution IDs on all three platforms. Keep
    the old actors and their identity-readiness waits for the later mount
    mutation checks.
    The exact shared test passed on Host in 29.33 seconds, direct `runc` in
    36.95 seconds, and Kubernetes in 66.94 seconds. The old direct-`runc`
    probe passed after the duplicate comparison was removed. Its later
    mount, entry, and cleanup checks remain.
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
  - [x] Replace the transient slot read with the durable approved-task
    classification. Node can retire a consumed slot before the test reads it.
    Kubernetes issues a credential at approval time and arms Node only after
    an exact CONNECT admission. A mismatched CONNECT must leave no slot to
    consume. Keep the approved role, nonzero proof and claim IDs, argv-chunk
    cleanup, and replay denial. The Control owner mismatch test, the exact
    Host and stock-`runc` cases, all 50 direct-`runc` identity tests, and the
    exact Kubernetes case pass. The complete Host identity lifecycle passed
    55 tests in 574.34 seconds. The complete direct-`runc` identity lifecycle
    passed 50 tests in 568.39 seconds. The complete Kubernetes identity
    lifecycle passed 50 tests in 1,333.84 seconds. K3s remained Ready and
    removed its test namespace and pin root.
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
    - [x] Replace the stock `dd` file-role check with
      `prestop_dd::prestop_keeps_file_role`. After Node restart, require the
      PreStop entry to read the application's denied FIFO, copy its bytes,
      and fail on its own denied file. Require its declared role, admission
      rule, and fresh attributed File/OpenRead `EACCES` evidence. Keep the
      old result until the missing-inventory condition below has separate
      proof.
      - [x] Host passed in 71.53 seconds on 2026-09-28. After the new
        role moved behind the existing role IDs, all five Host restart
        tests and all 62 Host identity tests passed without test changes.
      - [x] Direct `runc` passed in 75.92 seconds with the production OCI
        hook on 2026-09-28.
      - [x] Kubernetes passed in 106.05 seconds on the retained K3s
        cluster on 2026-09-28. The test body is unchanged.
      - [x] Remove the duplicate serialized PreStop role result and its shell
        predicate. Keep the old action and internal checks only for the
        separate missing-inventory condition below.
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
  - The 2026-09-29 source audit confirms that `retained_maps_recover` does
    not replace this case. That test restarts the same object. The old
    direct-runc action loads a second object and requires changed program
    tags and IDs with retained map IDs and link pins. Keep the old action
    and the running-identity checks until a matching small test passes.
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
    - [x] Let shared member setup reuse a pre-created actor `bin` directory.
      The terminal fixture creates its executable before platform setup. The
      unchanged test passed on Host, direct `runc`, and Kubernetes after this
      correction.
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
- [x] Remove the now-empty native base-bundle command and its obsolete pin,
  lease, and cgroup arguments after the Kubernetes launcher no longer uses it.
  The Kubernetes command now creates its result bundle and runs the remaining
  physical probes directly. The affected Rust targets compile, the VM launcher
  passes its shell syntax check, and the retained K3s run completed the
  container and ephemeral groups without the old bundle handoff. That run then
  failed in the open probe-impersonation group; it does not prove the complete
  legacy Kubernetes probe.
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
  - [x] Put the native `postStart.sleep` handler in
    `fixtures/kubernetes/lifecycle-sleep-pod-v1.yaml`. Remove the one-use
    `post_start_sleep` platform operation. Select the mounted ready file from
    the Pod's hook declaration, not a scenario switch. The unchanged test
    checks that only PID 1 runs while the Pod is not Ready, then waits for
    readiness. The 92 unprivileged library tests, the exact Kubernetes hook
    test, a normal Kubernetes actor-start test, and the full Rust CI procedure
    passed. Both Kubernetes launchers exited 0 without a K3s rebuild.
  - Proof: the complete serial lightweight suite passed 89 tests. Strict
    Clippy passed. The generated Kubernetes test passed in 132.46 seconds.
    The 18-test Kubernetes run passed 17 tests and exposed a platform lookup
    regression in namespace-init. After the lookup was isolated to this
    pre-readiness case, namespace-init passed in 112.56 seconds. The complete
    Kubernetes rerun is pending the test-runtime review.
- [ ] `physical_kubernetes_containers_probe`
  - [x] Add an 88-line shared Rust test for one three-container group. The
    test uses one group call and one policy. It observes a running sidecar and
    init before it releases init, then observes the application. It requires
    three task cookies, process states, execution sets, roles, and cgroups.
    It requires the sidecar snapshot to stay unchanged after application
    startup. The sidecar read succeeds, and the application read is denied.
    The exact Host, direct-`runc`, and real Kubernetes cases passed in 35.05,
    44.20, and 75.79 seconds. Strict Clippy passed.
  - [x] Use the Pod manifest to classify Init, restartable Sidecar, and
    Application in Host and direct `runc`. After the held init exits, the
    lightweight CRI fixture reports `ContainerExited`. Without that event,
    Node tried to read the dead init PID mount namespace during application
    admission and denied the next entry. Real Kubernetes supplies this event.
  - [ ] Keep the old probe's fail-closed unknown-root assertion. The new
    protected-policy test has `initial_container_root`, not
    `restored_or_unknown_root`. Do not remove the old probe until a small
    production-backed test proves the conservative-root case. A Host probe
    started the sidecar and init before Node, with no policy. After Node
    started, the sidecar had no published identity for 30 seconds. Node did
    not publish the old probe's conservative binding in this order. The
    experimental test was removed; the old probe remains. No platform or
    production behavior changed.
  - [x] Run the affected identity lanes after the shared platform change.
    Host passed 59 of 59 tests in 655.68 seconds. Direct `runc` passed 54 of
    54 tests in 1200.06 seconds. Real Kubernetes passed 55 of 55 tests in
    1469.39 seconds. The standalone Kubernetes case passed again in 70.86
    seconds. The earlier intermittent direct-`runc` exec failure did not
    recur; it is not proven fixed. The repository Rust CI script passed after
    Kubernetes registration. The complete platform suites remain open.
  - [x] Call `start_actor_group` once with all three actor commands. One call
    must create one workload: one Pod on Kubernetes. The Pod must declare the
    sidecar, init, and application at creation. Kubernetes starts the declared
    containers in its native order. A second group call must not add a
    container or create another Pod for this scenario.
    The two-call Host/direct-`runc` test from `99c4e467` and `37e988f3`
    passed focused tests but did not model one Pod. It was removed. The old
    Kubernetes probe remains the coverage owner.
  - [x] Remove the Pod YAML argument from `start_actor_group`. The shared test
    supplies actor commands and each member's container kind. Host and direct
    `runc` use that kind without parsing Kubernetes YAML. Kubernetes owns its
    Pod fixture: use the scenario Pod fixture when present and the existing
    standard actor Pod otherwise. Keep native probe and init/sidecar settings
    in their Kubernetes physical fixtures. One group call creates one Pod;
    the separate two-call boundary test creates two Pods by design.
    The roles, container-kind, and two-Pod boundary cases passed on Host,
    direct `runc`, and Kubernetes. The native HTTP/TCP/gRPC probe case passed
    on Kubernetes. The same scenario bodies and result assertions remain.
    The complete affected identity lifecycle passed 59 Host tests in 640.68
    seconds, 54 direct-`runc` tests in 1491.05 seconds, and 55 real Kubernetes
    tests in 1462.52 seconds. The retained VM and K3s cluster stayed running.
    The repository Rust CI verifier passed.
  - [x] Keep one Pod identity for members of one group call. A later group
    call must use a new Pod UID and new container IDs, even with the same
    policy labels and member names. The 60-line `group_boundary` test starts
    two groups under one signed policy and checks separate production
    bindings, cgroups, execution sets, and allowed reads. Its Host case passed
    in 47.26 seconds with a distinct CRI sandbox ID for each Pod. The unchanged
    two-policy Host case passed in 37.22 seconds. The complete Host identity
    lane passed 58 tests in 691.00 seconds with the original exact runtime
    entry role checks. The focused direct-`runc` case passed in 48.81 seconds.
    The full direct-`runc` lane passed 52 of 53 tests. A later `runc exec cat`
    failed before it wrote a PID file. That test passed alone in 51.08 seconds,
    and all 22 direct-`runc` identity scenarios passed in 435.84 seconds. The
    full 52-test direct-`runc` lane passed in 1157.38 seconds when only the
    new case was skipped. An unchanged repeat of all 53 direct-`runc` tests
    passed in 1200.52 seconds. The focused Kubernetes case passed in 83.53
    seconds, and the complete Kubernetes identity lane passed 54 tests in
    1451.29 seconds. The old Kubernetes probe remains in place.
  - [ ] Diagnose the intermittent direct-`runc` exec failure. One full run
    reported that `runc exec cat` exited before writing its PID file. The
    same test passed alone, in the 22-test identity subset, and in the full
    53-test repeat. No Node or BPF defect has been established. Do not weaken
    the runtime-entry assertions or claim that this failure is fixed.
  - [x] Keep the Host lane reliable after the extra workload. The TCP
    send-variants case now uses the existing bounded evidence wait and still
    requires exactly three allowed sends. The focused TCP case passed in
    43.31 seconds. The complete Host lane then passed 58 tests.
  - [x] Wait for the large-argument actor's admitted entry before checking
    its original exact role and nonzero rule. A full Host run saw role 5 while
    the first task snapshot still had rule 0. The bounded wait passed in the
    complete 58-test Host lane. It retains the exact role and rule checks.
  - [ ] Keep the original probe until its replacement passes. It starts a
    restartable sidecar and a held init container before the application. It
    checks separate cgroups, task cookies, process states, execution sets, and
    conservative roots. It checks that the sidecar root stays unchanged when
    the application starts.
  - [x] Give the shared actor group one Pod policy with a separate entry role
    for each container. Use the real `Sidecar`, `Init`, and `Application` kinds.
    Return the running init and sidecar before the Pod is Ready. Observe the
    later application through the group returned by the one start call.
  - [x] Resolve the paired lightweight setup before a Kubernetes run. In a
    focused Host run, the first target activated. With the second target, Node
    reported two runtime bindings but left a later policy activation pending.
    The fixture then timed out before it could check either root. An
    Application-only policy and an input-driven actor had the same result.
    The existing worker/helper group passed. This does not prove a Node defect.
    No replacement or production change was kept from these failed runs.
    A reversed worker/helper group timed out before its first actor activated.
    Removing the fixture's name-based first-member IDs did not fix it.
    Installing a policy without a target left Node prevention claims disabled,
    as the readiness check requires. These diagnostic changes were reverted.
  - [ ] Pass Host and direct `runc` with the original assertions. Then pass
    Kubernetes with its real init, sidecar, and application containers before
    removing the old probe.
- [ ] `physical_kubernetes_ephemeral_probe`
  - [x] Add one small Kubernetes platform test. Start Control and Node, install
    one signed Pod policy, and start one Application actor and one Ephemeral
    actor with one `start_actor_group` call.
  - [x] Extend the existing Kubernetes actor-group implementation for
    `ContainerKindV1::Ephemeral`. Use the kube client's native
    `ephemeralcontainers` subresource. Do not add a Platform operation, Pod
    fixture, shell action, or embedded actor program.
  - [x] Keep the standard actor Pod PID namespace private. Target the
    Application container from the Ephemeral container. Require both actors
    to share that PID namespace and to use different cgroups.
  - [x] Require distinct task cookies, process states, execution sets, active
    roles, and policy profiles. Require both roots to be active initial
    container roots with no creator task.
    Require `initial_role` for both container entrypoints. The user approved
    this correction on 2026-09-29. `qualified_registered_role` describes a
    later runtime entry, not a new container entrypoint.
    The 93-line test passed all assertions in 79.39 seconds in the retained
    Kubernetes VM. Pod cleanup completed. Node, Control, and BPF did not change.
  - [x] Pass the exact Kubernetes test and the existing actor-group cases.
    The shared container-kind policy passed on Host in 37.73 seconds and
    direct `runc` in 56.51 seconds. Its Kubernetes actor-group case and the
    new Ephemeral case passed in the complete identity lifecycle run.
  - [x] Pass the complete Kubernetes identity lifecycle before the platform
    commit. The 2026-09-29 run passed 59 tests and failed
    `stock_probes_are_entries` in 1788.51 seconds. See its evidence-readiness
    condition below. Do not accept a container restart or increase a timeout.
    The repository Rust CI gate passed with `RUST_TEST_THREADS=1`. Earlier
    parallel runs failed in separate CLI temporary-JSON and Control log tests.
    Both exact tests passed. Their parallel-run causes remain unproven.
    The final 2026-09-30 Kubernetes identity lifecycle passed all 60 tests in
    1562.85 seconds. It included the Ephemeral case, stock probes, socket-stale
    case, lifecycle churn, and retained-Node checks. Cleanup left no Mithril
    namespace, Pod, pin root, lease, socket, or per-test output. The VM and K3s
    cluster remain available. The final repository Rust CI gate passed after
    restoring the unmatched legacy probe comparisons. Formatting, workspace
    check, strict Clippy, workspace tests, and all 255 Node library tests passed.
    This result qualifies the affected identity lifecycle, not every generated
    lifecycle or the late-discovery conservative-root case.
  - [ ] Remove only the matching old method, result fields, manifest, and
    launcher copy after the replacement passes. Keep unrelated Kubernetes
    identity cases.
    Keep the old conservative-root oracle until a small test reproduces its
    late-discovery condition. The new signed-admission test does not prove
    `restored_or_unknown_root` with `fail_closed_unknown` for both containers.
    The temporary old-probe deletion was restored after the baseline audit.
- [ ] `physical_kubernetes_probe_impersonation`
  - [x] Replace the three stock exec-probe identities with
    `stock_probes_are_entries`. This is a Kubernetes-only physical condition.
    Use one Pod with readiness, liveness, and startup probes that run the same
    shared Python command. Start real Control and Node, install the signed
    policy, and use the existing actor-group operation.
  - [x] While all three probe processes are live, require each container PID 1
    to keep its initial root and each probe to have a creator-free external
    root, its declared role and rule, and distinct task, process, and execution
    identities. Release each probe and require ordinary Pod readiness and
    cleanup.
  - [x] Pass the small Kubernetes test. The focused test passed in 79.56
    seconds. The existing Kubernetes container-kind test passed in 72.48
    seconds with the shared policy.
  - [x] Reproduce the evidence-readiness gap from the 2026-09-29 complete
    identity lifecycle run in lightweight before a production change or
    another Kubernetes run. Supply a live containerd event stream that stays
    quiet after the container event. Keep the four-second admission deadline.
    The current lightweight CRI fixture has no containerd Subscribe service
    and uses a 10-millisecond inventory fallback. It does not prove this case.
    Require evidence recovery to restore admission without another container
    event. Keep the existing role, identity, readiness, and zero-restart checks.
    The physical run admitted the readiness container at 21:36:06 UTC. Node
    closed evidence readiness at 21:36:06.443 UTC. It staged the first liveness
    container facts at 21:36:06.555 UTC but did not complete preparation before
    the OCI client's deadline. The hook failed at 21:36:10.562 UTC. Node
    recovered evidence readiness at 21:36:11.273 UTC. Kubernetes then started
    a new container ID. The fixture still waited on the failed first ID and
    reached its 180-second identity limit. The run passed 59 tests and failed
    this test. Node samples evidence recovery during binding reconciliation;
    a live, quiet runtime event stream does not wake that path. This is the
    missing recovery trigger. This run preceded the approved Node change
    below. Control, BPF, assertions, and timeouts did not change.
  - [x] Add `evidence_gap_recovers` as a small Host test. Use the existing
    oversized-argument `cat` denial to produce a real unresolved-effect gap.
    Admit a second actor with the same Control, Node, and signed policy.
    Supply runtime updates through a private native containerd endpoint.
    Require source recovery without a later runtime event. Keep the existing
    incomplete-probe test and all its security assertions.
    The unchanged Host container-kind test passed in 40.89 seconds with this
    endpoint. It did not produce the evidence gap. A narrow Node recovery
    change was proposed on 2026-09-29. The user approved evidence-progress
    continuation after the reproduction below. Do not increase the
    Kubernetes admission deadline.
    The 69-line test reproduced the failure in 37.01 seconds before a Node
    change. One runtime update closed evidence readiness at 22:23:53.026 UTC.
    No other runtime event arrived during the five-second CRI observation
    wait. The wait failed. Cleanup then supplied a delete event, and Node
    recovered at 22:23:58.052 UTC. The test requires recovery within four
    seconds before it starts the second actor. No BPF map was changed.
    The initial timer proposal was not applied. The user rejected periodic
    reconciliation and approved evidence-progress continuation on 2026-09-29.
    The evidence owner now retains progress notifications after local log
    writes and durable gap changes. Node confirms each recovery checkpoint
    with fresh kernel counters. A pending checkpoint keeps admission closed.
    A progress notification resumes the check. Healthy batches do not scan
    bindings. Only interrupted runtime work resumes after recovery. Evidence
    recovery cannot restore unverified identity claims. BPF, Control, policy,
    and admission deadlines do not change. The deterministic unit test covers
    completion before and after waiting. All 255 Node unit tests and strict
    Clippy passed. The unchanged focused Host test passed in 49.51 seconds.
    Final identity lifecycle and paired Kubernetes verification are pending.
    The final repository Rust CI procedure passed with
    `RUST_TEST_THREADS=1` after the native event fixture and regression edits.
    Formatting, workspace check, strict Clippy, and workspace tests passed.
    The completion-order unit test and focused quiet-stream Host test passed
    after the approved Node change. The final repository Rust CI gate passed
    after the last Node edit. This result does not replace physical lifecycle
    qualification.
    A complete Host run with the diagnostic endpoint passed two tests and
    failed 63 tests. Approval cleanup timed out because this endpoint forwards
    container updates but not actor task-exit events. A later exact-selector
    retirement failure left the actor directory in place and caused the
    remaining failures. Do not use this diagnostic endpoint for a complete
    lifecycle. The original Host configuration passed all 65 tests in
    787.03 seconds. This run preceded the final combined-health guard. The
    final quiet-stream Host test passed in 42.51 seconds after that guard.
    The final repository Rust CI gate passed with all 255 Node tests.
  - [ ] Pass the final direct-`runc` and Kubernetes identity lifecycles.
    The first final direct-`runc` run stopped when libvirt paused its VM:
    `vda: no space`. The host disk was full. After disk space became available,
    the repository `target` directory was absent. Libvirt retained the open
    disk through a native block copy to a new temporary path. K3s was retained.
    The interrupted run passed 13 tests. Its remaining 46 tests failed because
    the deleted OCI hook was missing. These failures do not qualify the code.
    The production hook was restored from the verified Node image. Run with
    new output paths. No assertion or timeout changed.
    The final direct-`runc` identity lifecycle then passed all 59 tests in
    670.16 seconds. The final Host identity lifecycle passed all 65 tests in
    705.64 seconds. Both lifecycle cleanup operations completed. The paired
    Kubernetes `stock_probes_are_entries` test passed in 84.28 seconds. Its
    original readiness, role, identity, and zero-restart checks remain. The
    complete Kubernetes identity lifecycle passed 59 tests and failed
    `effect::socket_stale::exited_peer_loses_authority::identity_kubernetes`
    in 1593.46 seconds. `stock_probes_are_entries` passed again in that run.
    The approved recovery fix and its 69-line regression test were committed
    as `1d9d3792`. Do not mark the complete Kubernetes gate as passed.
  - [x] Reproduce the separate signed-target convergence condition in
    lightweight before another production change or Kubernetes run.
    - The user approved this reproduction on 2026-09-30. Add
      `signed_target_delay_is_closed` beside the shared admission fixture.
      Use the socket-stale policy and valid facts for its first worker Pod.
      Keep Control's workload inventory empty until the four-second Stage
      deadline expires. Require Node to reject an invalid Stage request while
      the valid request waits. The gRPC Health method alone does not prove
      that the Node event loop answers requests.
      Then supply the matching target through the existing fixture and
      require the unchanged request to succeed. Do not change production
      code or the socket-stale scenario. This test proves the missing-target
      condition, not the cause of the delayed Kubernetes inventory.
      The final 99-line test passed in 43.33 seconds in the retained VM.
      Its readiness check uses the existing diagnostic wait helper. The
      preceding 98-line version passed in 47.94 seconds.
      Node returned pending responses during the four-second request and
      rejected the invalid request halfway through that interval. The
      production client failed closed. The unchanged valid request succeeded
      after signed target delivery. Before delivery, no scheduled or runtime
      binding existed. After Stage succeeded, one scheduled binding existed
      and no runtime binding existed. Stage did not start an actor. The
      original socket-stale scenario remains unchanged.
      The final repository Rust CI procedure passed after the last Rust edit.
      Formatting, workspace check, strict Clippy, and workspace tests passed.
      All 255 Node library tests passed. Debug symbols were disabled for this
      build to limit disk use after the earlier Cargo cache loss. No complete
      physical platform lifecycle or Kubernetes test was rerun for this
      test-only change.
      The first run reproduced the same condition in 31.05 seconds but failed
      its timeout-text assertion. Tonic returned `Cancelled: Timeout expired`
      before the outer client timer. The final assertion accepts both timeout
      forms. The four-second deadline did not change.
    - The socket-stale test installed its policy, confirmed Node readiness,
      and created its first worker Pod. It did not reach the peer-exit action.
    - From 00:50:03.616 to 00:50:07.606 UTC on 2026-09-30, Node answered
      staging requests about every 26 milliseconds. Each response was
      `POLICY_CONVERGENCE_PENDING`: the Pod did not resolve to one signed
      scheduled target. Node was not blocked in evidence recovery.
    - At 00:50:07.617 UTC, the production OCI hook reached its four-second
      deadline and failed closed. The worker container exited with
      `StartError`, code 128, before the Python actor started.
    - Control reported zero desired targets for this policy at 00:49:56.178
      and 00:50:17.486 UTC. The Node log contains no candidate activation for
      this worker during its staging window. The cause of the missing target
      is not yet known. Control has no configured CPU or memory limit in this
      retained test deployment.
    - This is signed policy delivery for a new Pod, not BPF binding publication.
      Keep the four-second deadline and the test's security assertions.
      Do not accept a container restart or replace the socket-stale action.
      Keep the pending Ephemeral platform changes uncommitted until the
      complete Kubernetes identity gate passes.
  - [ ] Find why Control did not publish the matching scheduled target for
    the failed Kubernetes Pod. The lightweight test proves the absence
    condition, not its cause. No further production change is approved.
    The unchanged exact Kubernetes socket-stale test passed in 75.51 seconds
    on 2026-09-30 after reproduction commit `b50fc61d`. It used the retained
    VM, cluster, images, four-second admission deadline, and original security
    assertions. This result does not prove the earlier cause or close this
    item. The complete affected Kubernetes identity gate then passed all 60
    tests in 1562.85 seconds. Its output is retained in
    `/var/tmp/mithril-kube-target-gate.log` in the VM and
    `/tmp/mithril-kube-target-gate.log` on the host.
    The uncommitted legacy probe deletion was restored after comparison with
    `95775f48`. The new stock-probe test does not replace the simultaneous
    identical-command comparison with native, kubectl, and direct CRI entries.
  - [ ] Remove only the matching startup, readiness, and liveness actions,
    result fields, and old fixture containers. Keep the native-child,
    kubectl-exec, and direct-CRI assertions until their exact replacements
    pass.
    The 2026-09-29 source audit confirms that `child_exec_keeps_identity`
    does not replace the retained identical-command check. That test starts
    a declared Python entry and a native sleep child. The old probe overlaps
    a native child, kubectl exec, and direct CRI exec with identical command
    bytes. It also requires a conservative application root and restricted
    external roots. Keep that action and its result fields.
- [ ] `physical_kubernetes_prestop_probe`
  - [ ] Keep the real Pod `preStop.exec` hook. Deleting the Pod starts a new
    task in the application cgroup. The hook writes its namespace PID and
    waits on a FIFO. An ordinary `add_actor` call does not replace this event.
  - [ ] Before deletion, require one application identity and one profile
    task reference. While the hook waits, require the application snapshot
    to remain unchanged. Require a distinct PreStop task, an external runtime
    root, the restricted external role, and two profile task references.
  - [ ] Release the FIFO. Require Pod deletion, zero profile task references,
    and removal of the namespace, pin root, lease, and fixture directory.
  - [ ] Preserve the old `restored_or_unknown_root` and `fail_closed_unknown`
    application checks until a production-backed replacement proves the same
    condition. The old probe publishes an identity-only binding after Pod
    start; the current shared Node-restart test does not reproduce that setup.
  - [ ] Keep the replacement in a small standard Rust test. Use the existing
    Kubernetes fixture for the hook. Add no generic Platform operation only
    to delete this Pod. Qualify the matching lightweight condition before the
    Kubernetes case, then remove only the matching old probe and result fields.
- [ ] `physical_kubernetes_poststart_probe`
  - [x] Reproduce the undeclared hook-exec condition on Host. The small
    `undeclared_hook_is_denied` test uses the shared Python actor and a signed
    policy. It confirms `EACCES`, no hook marker, and a live initial root.
    The exact Host case passed in 31.81 seconds. This denial test does not
    replace the old native Kubernetes hook-order probe.
  - [x] Pass the same denial test on direct `runc`. The exact test passed in
    45.17 seconds with the production OCI hook. A draft native Kubernetes Pod
    did not write its hook marker. Keep the old probe until its hook identity
    and order assertions pass under the deployed Node.
  - [ ] Recheck the native hook setup before another Kubernetes run. The
    unregistered Pod draft used a Protect policy and did not reach its hook
    marker. An Observe-policy Host draft timed out in runtime admission before
    it reached identity checks. Both unverified drafts were removed. Do not
    infer a Kubernetes policy decision from the missing marker. Keep the old
    identity-only probe until a deployed-Node test proves its assertions.
  - [ ] Split the old three-Pod probe by behavior. Use small standard Rust
    tests and native Pod `postStart.exec` fixtures. Put actor actions in
    mounted Python files. Do not move the 713-line probe into another file.
  - [ ] Prove both real hook orders. In one Pod, the entrypoint must record
    its start before the hook. In another Pod, the hook must record its start
    before the entrypoint. While both tasks wait, require distinct task
    cookies and process states. Require each application to keep its initial
    root and role, and each hook to have the restricted external root and
    role. Keep the old order and identity assertions until this test passes.
  - [ ] Prove the held initial-root boundary. Before release, no held task
    may have identity. After production activation, each root must have a
    prepared binding with the expected entry instance and initial host PID.
    The deployed Node must supply this result; do not reconstruct its owner
    sequence in the test.
  - [ ] Prove a repeated hook after the Kubernetes service restarts. Keep the
    first hook live. Start a second hook with the native runtime operation.
    Require the first hook to survive, the application snapshot to stay
    unchanged, and the second hook to have a fresh cookie, process state,
    restricted root, and role. Release both hooks and require Pod readiness.
  - [ ] Qualify the paired lightweight role and activation conditions before
    the Kubernetes hook cases. Then remove only the matching old actions,
    compatibility fields, shell gates, and fixture code. Require namespace,
    pin, lease, request directory, and work directory cleanup.
- [ ] `physical_kubernetes_stock_hook_failure_probe`
  - [ ] Keep the timeout, OCI-state mismatch, missing Pod UID, no-payload,
    CRI-removal, and cleanup checks until their exact platform tests pass.
  - A direct-`runc` Node-outage test passed in 35.81 seconds. A trial
    Kubernetes registration did not reach the OCI hook: `stop_node()` removed
    the Node selector, and the new Pod stayed Pending with no containerd ID.
    The 180-second identity wait failed with `Unschedulable`. The trial
    registration was removed. Do not count this as hook-timeout coverage.
    Reproduce the scheduling condition in lightweight before a change or
    another Kubernetes qualification run.
- [ ] `physical_kubernetes_resilience_probe`: keep the Pod and its cgroup
  running before Node starts. Require public production recovery, exact
  identity retention across the Kubernetes service and Node outages, and
  fresh identity after same-name Pod and container recreation.
  - [ ] Replace the external-task label-loss and Node-restart checks with
    `external_restart::recovered_root_survives_restart`. Reuse the Platform
    lifecycle, checked policy, and process owner. Hold the external actor,
    delete its pidfd-keyed task label, and require an absent label. A real
    hostname read must allocate a fresh restricted task and process identity.
    Require the full recovered snapshot and coordinate to remain equal during
    the Node gap and after restart. Require public observation to fail during
    the gap and report supported identity after restart. Pass Host, direct
    `runc`, and Kubernetes before removing the matching old checks. Keep the
    direct CRI, Kubernetes-service-outage, and same-name recreation checks.
    - [ ] Finish the remaining platform qualification with the unchanged
      96-line shared body. Run the exact Host case on current artifacts,
      then direct runc, then Kubernetes. Use the existing external Python
      process placement, mapped control file, pidfd-keyed label deletion,
      read, snapshot, Node stop, Node start, and normal cleanup operations.
      Add no Platform API, actor copy, policy copy, or production change.
    - [x] Commit direct runc registration after its exact case and normal
      cleanup pass. The case suffix is `node_restart_runc`.
      On 2026-10-06, the unchanged 96-line body passed the fresh Host case
      in 69.28 seconds and direct runc in 57.23 seconds. Both runs removed
      their output, pin, lease, actor cgroup, and Node cgroup. The only Rust
      change adds runc to the attribute. Formatting and strict workspace
      Clippy passed. The focused process checks passed 14 tests, with one
      privileged test ignored. Both lifecycle checks and the VM harness
      check passed. See `/var/tmp/mithril-external-restart-host-20261006.log`
      and `/var/tmp/mithril-external-restart-runc-20261006.log` in the
      retained lightweight VM. Kubernetes and final Rust CI remain open.
    - [ ] Commit Kubernetes registration after its exact case and normal
      cleanup pass. The case suffix is `node_restart_kubernetes`. Reproduce
      any new Kubernetes condition in lightweight before a fix or rerun.
      The first case failed in 79.92 seconds on 2026-10-06. The external
      actor exited with status 120 before `label-read-ok`. The Node restart
      was not reached. See `/var/tmp/mithril-external-restart-kube-20261006.log`
      in the retained Kubernetes VM. The trial registration is removed.
      The actor uses the host mount namespace. Live containerd specifications
      show a separate hostname bind mount for each Pod. The direct-runc
      fixture has no such mount. First reproduce this physical difference
      with a separate hostname bind mount in direct runc. Report a failed
      read errno in the shared actor process name. Do not change a security
      assertion, readiness limit, Platform API, or production implementation.
      The hostname-only runc case passed in 53.47 seconds. That mount alone
      does not reproduce the failure. Live containerd roots use OverlayFS.
      The owned OverlayFS case reached all read and restart assertions.
      It failed cleanup because the diagnostic mount kept its root busy.
      The mount was removed. The 49 MiB of owned diagnostic data was
      removed after mount and open-file checks. Its log remains. Neither
      physical input reproduces the Kubernetes read failure. The temporary
      hostname mount was removed from the runc fixture. The test is 97
      lines after it adds the public observation to a failed read wait.
      All identity and lifecycle assertions remain unchanged. Kubernetes
      has not been rerun. Next compare the installed file rules and the
      mount namespace of the Node and external actor.
      The legacy case starts its external actor with direct CRI exec in
      the container. The shared case moves a Host actor into that cgroup
      but does not enter its mount namespace. Compare this physical setup
      before a policy or production change. It is not a proven cause yet.
      The private-launcher case passed all unchanged runc assertions in
      52.02 seconds. The external actor entered the Host mount namespace
      before placement. Normal cleanup passed. The launcher namespace
      inode was `4026532678`; the Host inode was `4026531841`. This split
      alone did not reproduce the failure. The temporary actor diagnostic
      flag is removed. Three lightweight inputs did not reproduce the
      Kubernetes read failure. Await direction before a new hypothesis.
      Keep the read-errno and failed-read observation diagnostics. Verify
      them with the Host case, the related orphan-reference case, focused
      checks, and final Rust CI before their separate commit.
      The Host external-restart case passed in 60.91 seconds with normal
      cleanup. The related Host orphan-reference case failed its same
      actor read in 52.47 seconds. It captured `label-read-13` (`EACCES`).
      See `/var/tmp/mithril-diagnostics-orphan-reference-host-20261006.log`
      in the retained lightweight VM. This is a lightweight denied-read
      result, not proof of the Kubernetes cause. No assertion is relaxed.
      Final Rust CI stopped in the unrelated Araphor raw-recovery check
      with `AnalysisReadDeadline`: 168 passed, one failed, five ignored.
      Its exact check then passed in 1.22 seconds. No Araphor source or
      deadline is changed. Rerun the same CI procedure with four ordinary
      Rust test workers. Do not skip a check or change a timeout.
      The four-worker CI procedure passed formatting, workspace check,
      strict Clippy, and all ordinary workspace checks. Mithril e2e passed
      160 checks, with 539 privileged checks ignored. Node passed 265.
      See `/tmp/mithril-read-diagnostics-final-ci-20261006.log` in the
      refactor worktree host. This does not qualify ignored physical cases.
      The failed Host orphan-reference case removed its output, pin, lease,
      actor cgroup, Node cgroup, and actor process. Its read denial remains
      open. Keep both diagnostic source edits uncommitted while this related
      physical check is red. No old identity check is removed.
      The legacy CRI shell command at `src/identity.rs:3343` reads the
      hostname, then stops without a read-status check. It asserts fresh
      restricted identity and restart stability. The shared Python case
      adds a successful-read requirement. Do not remove that requirement
      without approval. Ask whether to retain the extra allow check or
      use an explicit denied-read policy for the original identity behavior.
    - [ ] Compare the four legacy Node-specific fields and restart block
      with baseline `95775f48`, then remove only their matched checks.
      Keep label-loss setup and its recovered snapshot while the separate
      Kubernetes-service-outage assertions use them. Run related checks,
      harness checks, and final Rust CI after the last covered edit.
    - On 2026-10-03, the 98-line shared test passed its Host fault, read,
      fresh-identity, Node-gap, and restart assertions. Normal retirement
      failed after 30 seconds. A second focused run confirmed the failure.
      Do not add runc or Kubernetes, commit the test as qualified, or remove
      the old checks while this result is red.
    - The live map read showed one retained task reference in generation 1,
      zero socket and async references, and no active profile pointer. The
      raw task-label deletion leaves the original task ownership record.
      Recovery adds a fresh identity. The exit hook releases the current
      label's references, not the deleted label's references. The generation
      retirement guard therefore retains the old generation. The old
      identity-only probe did not require signed-policy retirement.
    - Read [the shared test](src/identity/scenarios/external_restart.rs),
      [the actor](fixtures/process/label_loss.py),
      [the exit hook](../../bpf/erebor-interceptor/programs/identity_exit.bpf.h),
      and [the retirement guard](../mithril-node/src/policy.rs).
      The actor blocks on stdin instead of SIGSTOP. An unmanaged controller
      cannot send SIGCONT to the label-less governed task under the signed
      policy. The bounded pipe wait and process-name result use existing
      process fixture APIs. No production or Platform API changed.
    - The final Rust CI gate and VM harness checks passed. The focused debug
      log is `/tmp/mithril-external-restart-host-debug-20261003.log`. The CI
      log is `/tmp/mithril-external-restart-host-ci-20261003.log`. These
      checks do not qualify the failed physical cleanup.
    - The unchanged Host case failed the same retirement check on 2026-10-04
      in 80.54 seconds. See `/tmp/mithril-external-audit-host-20261004.log`.
      The scenario assertions passed. Keep the cleanup result red and the
      test unqualified. No production code or assertion changed.
    - A fresh stdin-controlled run failed before the read result. The signed
      policy does not permit pipe reads. The actor now maps a one-byte control
      file before protected placement. The test changes that byte to request
      the real hostname read. No pipe-read permission was added. The 89-line
      Host test passed its fault, fresh identity, Node-gap, restart, and normal
      actor-exit assertions, then failed signed-policy retirement in 95.49
      seconds. See `/tmp/mithril-external-mailbox-host-20261004.log`.
      The user approved a narrow ownership correction. Keep all assertions
      and readiness limits. Release retained task references only after exact
      kernel lifetime proof; never clear counters to force retirement.
    - [x] Pass the corrected Host scenario and the exact-owner regression.
      The 96-line scenario passed in 50.71 seconds. Its original reference
      stays Owned while the exact task lifetime is live. The 90-line
      `orphan_release_requires_exact_owner` test passed in 95.67 seconds.
      An invalid process-instance join retains both references. After the
      join is restored, reconciliation releases the dead reference once.
      A second reconciliation keeps the tombstone and count unchanged.
      Both tests complete normal signed-policy retirement and path cleanup.
      See `/tmp/mithril-external-final-owner-host-20261004.log` and
      `/tmp/mithril-orphan-owner-proof-host-20261004.log`.
    - Review the approved ownership correction in this order:

      [Node retirement](../mithril-node/src/node.rs) finds pending inventory cleanup
        -> [KernelHost](../erebor-interceptor/src/host.rs) runs the existing task iterator
        -> [task iterator](../../bpf/erebor-interceptor/programs/identity_lifecycle.bpf.h) offers orphan maintenance
        -> [exit owner](../../bpf/erebor-interceptor/programs/identity_exit.bpf.h) checks exact coordinate and reference joins
        -> [kernel task lookup](../../bpf/erebor-interceptor/programs/identity_exit.bpf.h) proves the old physical lifetime is absent
        -> [reference release](../../bpf/erebor-interceptor/programs/identity_exit.bpf.h) uses the normal atomic release bits

      Live tasks, failed reads, invalid joins, pending transitions, and partial
      releases retain ownership. Normal exit does not scan a map. The change
      adds no map, ABI, public API, or Platform operation. Qualification covers
      external or restored process-root leaders with trusted kernel coordinates
      on the retained Linux 6.8 VM. It does not prove arbitrary map corruption,
      nonleader orphan cleanup, or full-capacity scan performance. Final Rust
      CI passed. The common physical matrix gate remains open.
    - The existing Node-restart and signed-entry condition also passed
      on direct runc in 60.16 seconds with the corrected owner. Full task
      snapshots and coordinates remained equal across the Node gap. The
      later declared entry kept its exact role and normal cleanup passed.
      See `/tmp/mithril-owner-restart-runc-20261004.log`. This result does
      not qualify the Host label-loss fault injection on runc.
      The same unchanged Node-restart test passed on Kubernetes in 113.23
      seconds. The deployed Node used the corrected ownership code. Full
      snapshots, coordinates, the declared-entry role, and normal namespace
      cleanup passed. See `/tmp/mithril-owner-restart-kube-20261003.log`.
      This result does not qualify label-loss fault injection on Kubernetes.
    - Keep the old label-loss actions while the Kubernetes-service-outage
      checks use their recovered snapshot. Remove only the matching Node
      restart block and four Node-specific result fields after qualification.
  - [x] Extend the existing `node_restart_keeps_actor` platform test with the
    live application's full task snapshot during the Node gap. It already
    compares the before and after snapshots. The separate PostStart test
    requires a fresh exact-file denial after restart. These checks do not
    replace the old external-task, Kubernetes-service-outage, BPF-label-loss,
    or same-name recreation checks.
    - [x] Pass Host and commit. The exact test passed in 51.62 seconds with
      equal full snapshots and task coordinates before shutdown, during the
      Node gap, and after restart.
    - [x] Pass direct `runc` and commit. The unchanged exact test passed in
      57.89 seconds through stock `runc` and the production OCI hook.
    - [x] Pass Kubernetes and commit. The unchanged exact test passed in
      86.96 seconds in retained K3s. Its namespace was removed.
- [x] `physical_kubernetes_network_probe`
  - [x] Add one `Platform::start_actor_group` operation. Kubernetes starts the
    group in one Pod from a checked YAML fixture. Host and direct `runc` start
    separate PID-1 actors in separate cgroups. Do not implement the group as
    repeated exec entries or reuse one container binding for several roots.
  - [x] Prove that one policy assigns different entry roles to two containers
    in the same Pod. Run the same read action in both containers. Require one
    allow result and one deny result on Host, direct `runc`, and Kubernetes.
  - [x] Keep native HTTP, TCP, and gRPC readiness probes. Require each
    container to become Ready with zero restarts. Sample each exact CRI
    container cgroup for four seconds and require only its init PID.
  - [x] Keep the test below 100 lines and remove the legacy probe only after
    the replacement passes. Verify group setup and cleanup on Host and direct
    `runc`, then run the Kubernetes case.
  - Proof on 2026-09-26: the full `identity` lifecycle passed 57 Host tests in
    640.42 seconds, 52 direct-`runc` tests in 1137.98 seconds, and 53
    Kubernetes tests in 1422.25 seconds. This is not the full generated
    platform matrix.

- [ ] Make the thin launcher run each generated lifecycle in its own test
  process. A broad platform suffix selects different lifecycles together and
  fails the lifecycle ownership check. Keep the VM and K3s between processes.

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
  is retired with its test-only matcher. Shared overlap tests require the
  production denial, task cookie, role, and entry ID through `EffectCheck`.
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
