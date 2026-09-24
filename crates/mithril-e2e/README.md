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
inside a helper.

For example, the old anonymous-memory checks lived inside the large
`EffectTestRunner::physical_probe` function. The 69-line
`src/effect/executable_memory.rs` test uses `executable_memory.py` on all
three platforms. It checks two denied executable protections, one denied
executable mapping, two allowed read-only controls, and the attributed kernel
effects. Its actor creates the first mapping before Node protection. The
legacy Observe-mode block remains until it has the same shared qualification.

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
  effect::executable_memory::anonymous_exec_is_closed::memory_recovery_kubernetes \
  --exact --ignored --nocapture --test-threads=1
```

Run one lifecycle and one platform per test process. After the final Rust or
verification-script edit, run the repository CI check:

```bash
bash .github/scripts/verify-rust-ci.sh
```

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
