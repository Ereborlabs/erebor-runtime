# Mithril End-To-End Qualification

Mithril end-to-end qualification runs shared Rust scenarios on Host, direct
`runc`, and Kubernetes. Run Host and direct `runc` before Kubernetes. Some
legacy physical probes still run during the migration.

## Lightweight Qualification

Rust code in `src/` owns the scenarios. Host and direct `runc` run production
owners without a Kubernetes cluster. Direct `runc` uses the stock runtime and
the production OCI hook. Kubernetes runs the same Rust test body against real
Control, Node, CRDs, and actor Pods.

The direct-`runc` lane also qualifies a kernel-host binary upgrade. It starts
with a different build of the production identity object, activates policy for
a running container, and restarts with the bundled production object. The
result must preserve the pinned map IDs, canonical link paths, running
application identity, and path-tree decision. It must replace each program
whose tag changed. The corresponding Kubernetes check is a retained
DaemonSet rollout on two nodes.

The lightweight case must reproduce the state transitions, failure condition,
and observable verdicts that the physical case will use. Owner-local unit and
integration tests can support this case, but they do not replace it.

## Physical Kubernetes Qualification

Scripts in `harness/` prepare VMs, K3s, images, and test binaries. New shared
Rust tests own the actor actions and result assertions. Legacy shell probes
still own some scenarios until a verified Rust replacement exists. Kubernetes
manifests and other inputs are in `fixtures/`.

The harness owns VM and cluster cleanup. A shared test owns its scenario
resources and checks its production evidence. Automated tests must not read
or execute files from `examples/`. Manual operator examples remain separate.

## Add And Run A Shared Scenario

Add one actor program under `fixtures/process/`. Reuse an existing signed
policy there when it states the required authority. Put one small Rust test
under the relevant `src/` scenario module and register the module. Use
`#[platform_test(host, runc, kubernetes)]` for the platforms that pass. Put
`#[lifecycle = name]` below it when tests share Control and Node resources.
The test must show the Control, Node, policy, and actor start order. Keep the
action, production result, security assertions, and stop calls in the test.
Use `ProcessFixture` for the actor and the existing `Platform` methods for
physical setup. Do not add a second process wrapper or reproduce Node work
inside a helper. A fixture owns placement, readiness, and cleanup. The test
owns component order, policy installation, actor actions, and assertions.

`install_policy("fixture.json")` returns that policy's `matchLabels` map.
Pass it to `start_actor("actor.py", &[], &labels)`. For simultaneous policies,
use fixtures with distinct selectors and retain both returned actors. Control
and Node remain shared. There is no workload-selection method in the test.
For recovery, read the labels from the policy fixture before starting the
actor. Install the policy at the required later step. Do not write labels by
hand or install policy early to obtain labels. Automatic label extraction
requires `matchLabels` only; it rejects `matchExpressions`.
See [the simultaneous policy test](src/identity/scenarios/multi_policy.rs)
and [its ownership review](MULTI_POLICY_REVIEW.md). Host tests also need the
production `mithril-oci-hook` binary. Set `MITHRIL_TEST_OCI_HOOK` when the binary
is not at `target/debug/mithril-oci-hook` under `MITHRIL_TEST_ROOT`.

For two containers under one policy, give each container match its own
`applicationEntry` role. Set each `GroupActor.kind` to the required production
container kind. Pass both actors to
`start_actor_group(&actors, &labels, |_, _| Ok(()))`. One call starts one Pod
with two container PID-1 processes on Kubernetes. Host and direct `runc` start
two separate PID-1 roots in one workload. See [the group-role test](src/identity/scenarios/group_roles.rs).
The test does not pass a Pod YAML name. For a special Kubernetes Pod, place
`<setup-name>-pod-v1.yaml` in `fixtures/kubernetes/`. Kubernetes uses that
fixture; otherwise it uses the standard actor Pod. Host and direct `runc` use
the actor kinds, not Kubernetes YAML. The
[native network-probe test](src/identity/scenarios/network_probes.rs) keeps its
HTTP, TCP, and gRPC probe definitions in its Kubernetes Pod fixture.

For a Kubernetes Ephemeral container, include an Application actor and an
Ephemeral actor in the same group call. The Application name must match the
policy selector. Kubernetes creates one Pod, then adds the Ephemeral container
through the `ephemeralcontainers` subresource. The Ephemeral container targets
the first Application container's PID namespace. Each container keeps its own
cgroup, entry role, and process identity.

Read the implemented path in this order:

[ephemeral_actor_is_isolated](src/identity/scenarios/ephemeral_container.rs) starts Control, Node, and the signed policy.
  -> [Kubernetes::start_group](src/platform/kubernetes/actor.rs) creates the Application Pod and patches the Ephemeral subresource.
  -> [KubernetesAdmissionOwner](../mithril-control/src/policy/kubernetes_workloads.rs) validates the Pod against its admitted policy revision.
  -> [Kubernetes::task](src/platform/kubernetes.rs) reads both identities through the production inspector.
  -> [ephemeral_actor_is_isolated](src/identity/scenarios/ephemeral_container.rs) checks distinct roles, rules, identities, profiles, and cgroups in one PID namespace.
  -> [ProcessFixture::stop](src/process.rs) stops both actors before per-test cleanup.

Run the generated `ephemeral_actor_is_isolated::identity_kubernetes` case by
its full name in the retained VM. This test proves signed container admission.
The old identity-only Ephemeral probe remains until a small test also proves
its late-discovery conservative-root condition.

The SysV shared-memory test passes on Host, direct `runc`, and Kubernetes. Run
`identity::scenarios::ipc_stat::ipc_stat_is_closed::ipc_recovery_host` with the
Host environment and exact-test flags below. Its intended result is a physical
permission denial for a recovered restricted actor in Protect and Observe
modes on all three platforms. Both modes are qualified at this source state.
Use `ipc_recovery_runc` or `ipc_recovery_kubernetes` for the other platforms.

[ipc_stat_is_closed](src/identity/scenarios/ipc_stat.rs) starts Control and holds both actors before Node.
  -> [Segment](fixtures/process/ipc_stat.py) creates, attaches, and marks a private segment for deletion before readiness.
  -> [Platform recovery](src/platform/shared.rs) waits for the production recovered binding and actor identity.
  -> [Segment::stat](fixtures/process/ipc_stat.py) calls libc `shmctl(IPC_STAT)`.
  -> [EffectCheck](src/effect/check.rs) requires fresh attributed `UNSUPPORTED_OBJECT` IPC/Access evidence with `EACCES` and no policy object.
  -> [ipc_stat_is_closed](src/identity/scenarios/ipc_stat.rs) requires successful segment detach, then releases the actor and checks its exit before cleanup.

The actor uses the Linux 64-bit libc SysV structures on x86-64 and AArch64.
The actor detaches the segment on normal exit. Linux removes a segment marked
for deletion when its last attachment closes, including process exit. The
matching legacy SysV action and result flag are removed after both policy modes
passed on every platform. The adjacent Unix-stream IPC checks remain.
The 70-line test passed Host in 28.01 seconds, direct `runc` in 35.04 seconds,
and Kubernetes in 69.70 seconds. The final Rust CI procedure passed. The
existing lightweight `transport_waits_for_actor` test proves that a failed
exec transport can return status 1 after its actor exits with status 0. The
SysV actor reports successful detach through its task name before exit. The
test does not use a transport status as an actor status.
The [Observe test](src/identity/scenarios/ipc_stat_observe.rs) uses the same
actor and recovery flow with `memory_observe.json`. Host passed in 28.09
seconds and direct `runc` passed in 32.32 seconds. Run
`observe_ipc_is_closed::ipc_observe_host` or its `ipc_observe_runc` counterpart
by the full generated name. The test checks external role ID 1 and recovered class
`fail_closed_unknown`. A policy role ID does not imply a witnessed runtime
entry. The recovered class keeps that identity limit. Observe Kubernetes
passed in 78.84 seconds. Use the `ipc_observe_kubernetes` generated suffix.
The final Rust CI gate passed. Its first command failed because an unchanged
Control log test did not find its record. That test passed in isolation, then
the unchanged full gate passed. The cause of that log-test failure is not
established.
Before this migration, `PreparedOperations` allocated the segment inside the
large legacy actor, dispatched a private operation, and set a result flag.
The replacement has two standard tests of 70 and 75 lines. Both use one Python
actor, existing signed policies, production recovery, and the same explicit
physical-denial and evidence assertions on all three platforms.

The retirement removes 69 lines from the two legacy Rust files. Nine focused
child regressions passed. The remaining legacy physical probe fails its
baseline file-open assertion before the IPC action. An exact pre-deletion
comparison fails the same way in Observe and Protect. That runner remains
open for migration; this SysV result does not qualify its other actions.
The final repository Rust CI procedure passed after the retirement edit.

The Observe device test replaces the legacy unclassified PTMX ioctl action.
Its intended result is physical `EACCES` and attributed `UNRESOLVED_OBJECT`
Device/Ioctl evidence on Host, direct `runc`, and Kubernetes. Read this flow:

[observe_ioctl_is_closed](src/identity/scenarios/ioctl_observe.rs) starts Control and both actors before Node.
  -> [Device::number](fixtures/process/device_ioctl.py) verifies `TIOCGPTN` output before actor readiness and retains the PTMX descriptor.
  -> [Platform recovery](src/platform/shared.rs) waits for the recovered actor with rule zero and its signed Observe policy.
  -> [Device::number](fixtures/process/device_ioctl.py) issues `TIOCGPTN` after recovery and reports its errno.
  -> [EffectCheck](src/effect/check.rs) requires the actor's fresh Device/Ioctl denial with no policy object.
  -> [Device::close](fixtures/process/device_ioctl.py) closes the descriptor and reports cleanup before actor exit.
  -> [ProcessFixture::stop](src/process.rs) completes normal process cleanup before platform teardown.

The request uses the Linux ioctl encoding on x86-64 and AArch64. The
[production ioctl gate](../../bpf/erebor-interceptor/programs/identity_device_process.bpf.h)
requires an exact device object for a recovered actor. Observe mode does not
permit this unresolved object. The generic actor gate rejects the unresolved
path before the typed ioctl stage records the command. The evidence command
field is zero; the Python actor still calls the original `TIOCGPTN` request.
The old Observe check requires the same physical denial and reason.
The Host root now includes `/dev/pts` through
its existing mount owner. The owner removes that mount during teardown.
Stock `runc` and Kubernetes already provide devpts. No production or Platform
API changes are required. Run the full generated name
`identity::scenarios::ioctl_observe::observe_ioctl_is_closed::ioctl_observe_host`
with the exact-test flags below. Platform qualification is recorded in the TODO.
The matching legacy Observe action is removed after all three platforms pass.
The Protect-mode exact PTMX Allow, derived-peer denial, zero-device denial,
and shared descriptor resources remain for their separate migrations.
The 74-line Host case passed in 29.15 seconds. The complete Host matrix then
passed 135 tests in 41 lifecycle groups, including each group's resource
cleanup. The final repository Rust CI gate passed after the last Rust edit.
The same test passed direct `runc` in 39.00 seconds through the production OCI
hook. Its resource cleanup passed. Use the `ioctl_observe_runc` suffix. No
runc fixture or production source changed.
Kubernetes passed in 92.49 seconds with the same test, actor, policy, and
assertions. Its namespace, pin, and lease cleanup passed. Use the
`ioctl_observe_kubernetes` suffix. The final Rust CI procedure passed.
The retirement deletes 10 Rust lines. Nine child regressions passed. The
final Rust CI procedure passed after the retirement edit. Its first command
failed in the unchanged Control log test recorded above. That test passed in
isolation, then the unchanged full procedure passed. No logging fix is claimed.

The [fd-exec test](src/effect/exec_fd_allow.rs) holds the Python actor and its
open executable descriptor before Node starts. After production recovery,
the actor calls file-descriptor exec. Its signed external role allows the
executable action but declares no entry for the executable. The test requires
the real syscall errno `EACCES`, fresh same-task `EXACT_POLICY_ALLOW` and
`UNSUPPORTED_OBJECT` evidence, and entry rule zero. The actor closes its
descriptor before it reports the errno through its task name. A release file
permits normal exit. An exec transport status is not an actor syscall result.
Run `effect::exec_fd_allow::exec_fd_allow_cannot_admit::exec_fd_recovery_host`
with the exact-test flags below. Use the `exec_fd_recovery_runc` or
`exec_fd_recovery_kubernetes` suffix for the other platforms. The test uses
the same actor, signed policy, and assertions on all three platforms.
The replacement has 82 lines. It removes the legacy allowed-exec dispatch,
stored descriptor, path field, and result flag after qualification. The
separate denied-fexecve actions remain. The legacy executable path fixture
remains for signed policy installation and independent mmap/mprotect Allow
lowering checks. The retirement deletes 57 Rust lines.
Nine focused child regressions and the final repository Rust CI procedure
passed after retirement. No production or Platform API changed.

The [cache-rebuild test](src/identity/scenarios/cache_rebuild.rs) repeats a
denied actor read after it decreases a READY cache row's mount count. It
requires a newer READY generation, fresh attributed path-tree denial, and
unchanged mount topology. It reuses `read_path.py`, the signed mount policy,
and the `mount_late` lifecycle. Run
`identity::scenarios::cache_rebuild::stale_cache_keeps_deny::mount_late_host`
with the exact-test flags below. See the
[source review](CACHE_REBUILD_REVIEW.md) for the fault input and map lifetime.
Use the `mount_late_runc` suffix for the qualified direct-`runc` case.
Use the `mount_late_kubernetes` suffix for the qualified real Kubernetes case.
Old-row collection remains in the legacy probe until a separate test passes.
The duplicate rebuild comparison, result flag, and VM result predicate are
removed after all three platforms passed. The collector still owns its old
corruption/read setup and its real Kubernetes rebuild readiness wait.

For example, the old direct-`runc` PreStop probe restarted its own kernel host,
started `/bin/dd`, scanned the admission map, and returned two literal-path
result flags for a shell gate. The 41-line
[`src/effect/prestop_path.rs`](src/effect/prestop_path.rs) test now starts
Control, Node, policy, and `ready.py`. It restarts Node, starts the declared
PreStop actor, and checks the observed role and installed admission rule. The
same test runs on Host, direct `runc`, and Kubernetes. The duplicate flags and
shell gates are gone. The separate file-denial and runtime-inventory omission
checks remain in the old probe until their own replacements pass.

For a small in-process check, run the ring-accounting test. It checks health
arithmetic without a VM. It does not replace a running-actor test:

```bash
cargo test -p mithril-e2e --lib \
  effect::support::tests::health_delta_preserves_ring_accounting -- --exact
```

From the repository root, build and list the standard tests, then check the
local harness:

```bash
cargo test -p mithril-e2e --lib --no-run
cargo test -p mithril-e2e --lib -- --list
bash crates/mithril-e2e/harness/vm/test.sh
```

Run the current disposable VM qualification lanes. These commands still run
legacy probes and selected shared lifecycles; they do not run every generated
test. Add `--with-k3s` for the Kubernetes lane:

```bash
crates/mithril-e2e/harness/vm/run.sh --output-directory /tmp/mithril-e2e-vm
crates/mithril-e2e/harness/vm/run.sh --with-k3s \
  --output-directory /tmp/mithril-e2e-k3s
```

For one Kubernetes test, start and enter a retained VM as shown in
[`harness/vm/README.md`](harness/vm/README.md#manual-testing-in-a-vm). In that
guest, run one exact generated test with the prepared environment:

```bash
sudo -i
. /var/tmp/mithril-manual.env
"$MITHRIL_TEST_BIN" \
  effect::prestop_path::prestop_uses_literal_path::node_restart_kubernetes \
  --exact --ignored --nocapture --test-threads=1
```

To run all tests in one lifecycle, filter by its full generated suffix, such
as `identity_host`, `identity_runc`, or `identity_kubernetes`. Run each suffix
in a separate test process. A broad `_host` filter mixes lifecycles and fails
their resource ownership check.

The same VM can run the matching Host and direct-`runc` cases. Use a new
output, pin, lease, and cgroup path for each run. The manual environment sets
`MITHRIL_TEST_ROOT`, `MITHRIL_TEST_BIN`, and `MITHRIL_BIN_DIRECTORY`.

```bash
env MITHRIL_TEST_OUTPUT=/var/tmp/mithril-prestop-host \
  MITHRIL_TEST_PIN=/sys/fs/bpf/mithril-prestop-host \
  MITHRIL_TEST_LEASE=/var/tmp/mithril-prestop-host/owner.lock \
  MITHRIL_TEST_CGROUP=/sys/fs/cgroup/mithril-prestop-host \
  "$MITHRIL_TEST_BIN" \
  effect::prestop_path::prestop_uses_literal_path::node_restart_host \
  --exact --ignored --nocapture --test-threads=1

env MITHRIL_TEST_OUTPUT=/var/tmp/mithril-prestop-runc \
  MITHRIL_TEST_PIN=/sys/fs/bpf/mithril-prestop-runc \
  MITHRIL_TEST_LEASE=/var/tmp/mithril-prestop-runc/owner.lock \
  MITHRIL_TEST_CGROUP=/sys/fs/cgroup/mithril-prestop-runc \
  MITHRIL_TEST_RUNC=/var/lib/rancher/k3s/data/current/bin/runc \
  MITHRIL_TEST_OCI_HOOK="$MITHRIL_BIN_DIRECTORY/mithril-oci-hook" \
  "$MITHRIL_TEST_BIN" \
  effect::prestop_path::prestop_uses_literal_path::node_restart_runc \
  --exact --ignored --nocapture --test-threads=1
```

Run one lifecycle and one platform per test process. After the final Rust or
verification-script edit, run the repository CI check:

```bash
bash .github/scripts/verify-rust-ci.sh
```

## In-Process Control And TLS Scenarios

### Intended result

A registered Node reconnects with a fresh nonce. Both registrations remain in
Control. Control acknowledges the complete trust generation. Each test calls
the production connector and checks production state without an actor or VM.
These protocol tests support physical qualification; they do not replace it.

### Source review

[MtlsFixture](src/control_fixture.rs) creates certificates, durable Control state, and a ready server.
  -> [registration_renews_nonce](src/control_tls/registration.rs) calls the production connector twice and drops the first connection before the second call.
  -> [NodeControlConnector::connect](../mithril-node/src/control.rs) awaits registration, installs trust, and awaits the trust acknowledgement.
  -> [ControlPlane](../mithril-control/src/service.rs) registers the nonce and calls the trust owner before returning each RPC response.
  -> [TrustBundleOwner::acknowledge](../mithril-control/src/trust.rs) persists the acknowledgement before returning success.
  -> [registration_renews_nonce](src/control_tls/registration.rs) checks the fresh nonce, two registrations, and complete acknowledged trust generation.
  -> [ControlServerFixture::shutdown](src/control_fixture.rs) stops and joins the server before the fixture removes its temporary files.

The fixture owns certificates and temporary files. The server fixture owns
the shutdown sender and server task. The test owns the connector, connections,
and trust cache. A dropped server fixture sends shutdown as a fallback. Normal
cleanup awaits shutdown and reports server errors. No production operation is
reproduced in a test helper. This flow has no BPF or kernel ABI changes.

At baseline `95775f48`, the test creates certificates and Control state in its
body, then polls after reconnect. The replacement uses the existing fixture
and checks the completed RPC results directly. All four baseline assertions
remain in the 38-line test file. To add another protocol case, reuse this
fixture and keep production requests and security assertions in the test.

Run the focused case, then its protocol regressions:

```bash
cargo test -p mithril-e2e --lib \
  control_tls::registration::registration_renews_nonce -- --exact
cargo test -p mithril-e2e --lib control_tls::
```

This source review covers the registration replacement based on `8915332c`.
The two ignored throughput and release-startup budgets remain separate checks.
No Host, direct-`runc`, or Kubernetes fixture changes are included.

## Quiet Runtime Event Reproduction

The lightweight CRI fixture can forward containerd events through a private
native endpoint. Set `MITHRIL_TEST_EVENT_SOCKET` to that endpoint. The fixture
keeps its typed CRI responses and publishes native update and delete events.
Do not use the K3s endpoint for these fixture events.
Use this endpoint for the focused quiet-stream test, not a complete lifecycle.
The endpoint does not receive actor task-exit events. The normal Host and
direct-`runc` fixtures retain their original inventory fallback. Real Kubernetes
uses the complete containerd event stream.

In the retained guest, start the separate event service and check readiness.
Reuse the service if `systemctl is-active mithril-events-test.service`
reports `active`.

```bash
sudo systemd-run --unit=mithril-events-test --collect \
  --property=Type=notify --property=TimeoutStartSec=5s \
  --property=RuntimeMaxSec=900 \
  /var/lib/rancher/k3s/data/current/bin/containerd \
  --address=/var/tmp/mithril-events-test.sock \
  --root=/var/tmp/mithril-events-test-root \
  --state=/var/tmp/mithril-events-test-state --log-level=error
sudo /var/lib/rancher/k3s/data/current/bin/ctr \
  --address=/var/tmp/mithril-events-test.sock --timeout=5s version
```

Run `identity::scenarios::evidence_gap::evidence_gap_recovers::identity_host`
with the Host environment shown above and
`MITHRIL_TEST_EVENT_SOCKET=/var/tmp/mithril-events-test.sock`. Keep K3s and the
VM running. Use the test binary from the current source. Require one test to
run; zero tests is not a pass. Stop only this service after the check:
`sudo systemctl stop mithril-events-test.service`.

[evidence_gap_recovers](src/identity/scenarios/evidence_gap.rs) denies a real incomplete exec and supplies one runtime update.
  -> [CriFixture](src/platform/cri.rs) forwards the native event to the quiet containerd stream.
  -> [NodeRun](../mithril-node/src/node/run.rs) starts binding reconciliation on that event.
  -> [EffectObservationStore](../mithril-node/src/observation.rs) records the gap and requires a durable recovery probe.
  -> [EffectObservationWorker](../mithril-node/src/observation.rs) writes the records to the local evidence log and signals progress.
  -> [NodeRun::resume_evidence](../mithril-node/src/node/run.rs) checks recovery and completes interrupted runtime work.
  -> [evidence_gap_recovers](src/identity/scenarios/evidence_gap.rs) requires recovery within four seconds before another actor starts.

The original lightweight run failed while the runtime event stream was quiet.
The approved Node change uses a retained `watch` notification from the evidence
owner. It confirms the recovery checkpoint with fresh kernel counters. If the
records are not yet durable, admission stays closed until evidence progress
wakes Node. A completed write before waiting is not lost. Healthy evidence
batches do not start binding reconciliation. Node completes only runtime work
that evidence health interrupted. Evidence recovery does not restore unverified
identity claims. Historical gap intervals remain in the durable coverage log.

The completion-order unit test and focused Host reproduction passed. The
final Host identity lifecycle passed all 65 tests in 705.64 seconds. The final
direct-`runc` lifecycle passed all 59 tests in 670.16 seconds. The focused
quiet-stream test passed in 42.51 seconds. Paired Kubernetes verification is
passing: the unchanged `stock_probes_are_entries` test passed in 84.28 seconds.
The complete Kubernetes identity lifecycle passed 59 tests and failed
`exited_peer_loses_authority` in 1593.46 seconds. Its first actor did not start.
Node returned `POLICY_CONVERGENCE_PENDING` because the new Pod did not resolve
to one signed scheduled target. The four-second staging deadline expired.
This is not the quiet-stream evidence failure. The cause of the missing target
is not yet known. The complete Kubernetes gate has not passed. Reproduce this
condition in lightweight before another production change or Kubernetes run.
BPF, production policy, assertions, and admission timeouts remain unchanged.

## Signed Target Delay Reproduction

Run `platform::shared::admission::signed_target_delay_is_closed` by its full
name with the Host VM environment shown above. Use
`--exact --ignored --nocapture --test-threads=1`. Unset
`MITHRIL_TEST_EVENT_SOCKET`. This case does not need the private containerd
event service. Use new output, pin, lease, and cgroup paths for each run.

The test uses the socket-stale policy and valid facts for its first worker.
Control has no workload target during the four-second staging deadline.
Node must answer a separate invalid Stage request during that wait. The valid
request must time out with no active target or runtime binding. The existing
fixture then supplies the matching workload target. The unchanged request
must succeed through signed production policy delivery and gRPC admission.
This case does not identify why the real Kubernetes target was absent.
The socket-stale actor scenario and all its security assertions remain.
The 99-line reproduction passed in the retained VM in 43.33 seconds.
Its output, pin root, lease, and cgroup were removed after the run.

## Required Order And Result Contract

Run the lightweight case before its physical Kubernetes case. Both cases must
report the same decision for every shared oracle. Dynamic values such as Pod
UIDs, candidate digests, Node names, and timestamps can differ. Their meaning,
state transitions, result fields, and pass or fail decisions must agree.

If the physical case detects a condition that the lightweight case did not
detect, stop the physical retry loop. Add the exact condition and expected
verdict to the lightweight case first. Fix the implementation until that case
passes. Then rerun the physical case.

This order makes a lightweight pass a useful prediction of the Kubernetes
result. A lightweight case that omits a known physical failure is incomplete.
