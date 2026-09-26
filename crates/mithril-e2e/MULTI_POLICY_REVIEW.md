# Simultaneous Policy Review

This guide covers the test-infrastructure changes after `cffabf5b`.
The test checks two policies and two live workloads on one Node.
It does not change production policy installation.

## Intended end state

One shared Rust test runs on Host, runc, and Kubernetes. Both workloads remain
alive. One policy denies a file read. The other policy allows the same read.
Both results refer to distinct active profiles on the same Node.

## Review route

[simultaneous_policies_are_isolated](src/identity/scenarios/multi_policy.rs) starts Control and Node once.
  -> [Shared::install_policy](src/platform/shared.rs) or [Kubernetes::install_policy](src/platform/kubernetes.rs) submits each policy through production APIs and returns its `matchLabels` map.
  -> [Platform::start_actor](src/platform.rs) receives that map. Host and runc supply it in workload facts. Kubernetes applies it to the actual Pod.
  -> [ProcessFixture](src/process.rs) owns each ready actor process.
  -> [read_path.py](fixtures/process/read_path.py) reads the requested path and writes the actual error number and byte count.
  -> [simultaneous_policies_are_isolated](src/identity/scenarios/multi_policy.rs) checks both results twice, active generations, separate bindings, and production evidence.

[Platform::stop](src/platform.rs) ends the scenario.
  -> [Host](src/platform/host.rs) or [Runc](src/platform/runc.rs) removes all owned runtime resources.
  -> [SharedState](src/platform/shared.rs) removes all runtime observations and workload targets, reconciles each policy, and waits for zero active targets.
  -> [KubernetesState](src/platform/kubernetes.rs) deletes the scenario namespace and waits for zero active targets.
  -> [Lifecycle](src/platform/lifecycle.rs) retains Control and Node for the next test in the same lifecycle and platform. Process exit performs their explicit cleanup through the registered callback.

## Owners and inputs

- `SharedState` owns one Control, Node, policy desired-state owner, and CRI
  fixture. It stores policy resources, runtime targets, and installed bindings
  separately. Its actor files contain only a directory, cgroup, and Pod UID.
  There is no `SharedWorkload` wrapper or saved workload context to swap.
- `CriFixture` supplies external runtime facts by container ID. A status read
  acknowledges that observation's revision only. Reading a newer observation
  from another container does not acknowledge the older observation.
- `Host` owns its rootfs mounts, bundles, and latest initial actor identity. Initial
  actors get separate PID and private mount namespaces. Additional actors
  enter the latest initial actor's namespaces. The production OCI hook submits
  declared entries from inside the actor's mount namespace.
- `Runc` retains one runtime state directory and hook installation. It owns a
  separate bundle and container ID for each workload. It uses `runc run`,
  `runc exec`, and `runc delete`; it does not call Host process operations.
- `KubernetesState` owns one scenario namespace. It creates separate Pods and
  policy resources in that namespace. The existing Helm release supplies the
  shared Control Deployment and Node DaemonSet. Labels, not separate namespaces,
  distinguish the two policy targets.
- Host and runc retain actor directories, cgroups, mounts, and containers for
  explicit cleanup. Starting the second actor does not stop the first actor or
  restart Control or Node. The workload wrappers and `select` methods are removed.
- Recovery tests read labels from the policy fixture before actor startup.
  They install policy at the original later step. Automatic label extraction
  accepts `matchLabels` only and rejects `matchExpressions`.

## Production and ABI boundaries

Control compiles and signs the submitted policy. Node installs the signed
candidate and handles runtime admission. BPF evaluates each actual file open.
The scenario does not publish a binding or edit a policy map.

`GenerationState` reads `active_profile_generations` and
`profile_generation_descriptors` through `KernelStateReader`. It uses the
existing checked `zerocopy` decoding. `Platform::task` reads the production
task snapshot. `Platform::snapshot` reads production effect observations.
No BPF program, map layout, public result schema, or production owner changes.

The first Host attempt failed at the second actor's entry preparation. Both
actors shared one mount namespace. Node rejected two different live roots in
that namespace. The fixture now supplies separate mount namespaces. Node's
validation remains unchanged.

## Run the proof

Build the Rust test binary and the production OCI hook:

```sh
cargo test -p mithril-e2e --lib --no-run
cargo build -p mithril-node --bin mithril-oci-hook
```

Use the retained VM setup and environment in [README.md](README.md).
Run the exact generated name below with `--exact --ignored --nocapture
--test-threads=1`. Replace the final suffix with `identity_runc` or
`identity_kubernetes` for the paired runs. Use a new output path for each run.

```text
identity::scenarios::multi_policy::simultaneous_policies_are_isolated::identity_host
```

The focused nonphysical CRI regression is:

```sh
cargo test -p mithril-e2e --lib \
  platform::cri::tests::observations_are_independent -- --exact
```

The privileged admission regression uses the same Host VM environment:

```text
platform::shared::tests::image_identity_is_required
```

It changes only the CRI image digest. Node must reject admission and publish
no runtime binding. The test restores the matching digest and checks admission
again. The production client confirms each receipt.

For a manually imported image, set `MITHRIL_TEST_ACTOR_IMAGE` to the actual
prepared image reference. Check `k3s ctr images list` and `k3s crictl inspecti`.
An imported manifest alias and a registry index alias for the same image can
make CRI report a different digest. Use the launcher's pinned image archive;
do not substitute a tag export. Do not change Node's identity check.

## Verification results and limits

The final focused runs contain `simultaneous_policies_are_isolated` and
`lifecycle_reuses_node` in one process per platform:

| Platform | Result | Time | Host log |
| --- | --- | --- | --- |
| Host | 2 passed | 48.25 seconds | `/tmp/mithril-labels-host.log` |
| runc | 2 passed | 139.13 seconds | `/tmp/mithril-labels-runc.log` |
| Kubernetes | 2 passed | 125.01 seconds | `/tmp/mithril-labels-kubernetes.log` |

The final Rust CI gate and VM harness checks passed. The full physical
platform matrix remains pending. These focused results do not qualify all
existing scenarios that use the changed platform fixtures.

After removal of the workload wrappers, earlier single-test Host and runc
runs also passed in 37.61 and 52.52 seconds.
One earlier Host attempt exceeded the 60-second Node start limit while the
Rust CI build ran. The limit was not changed.

The first Kubernetes run failed before the file reads. The configured Python
image used an index digest. The imported image also had a different manifest
digest, which CRI returned. Node rejected the identity mismatch.
The lightweight mismatch regression passed in 41.00 seconds
before the Kubernetes rerun. Its first attempt timed out during Node startup;
it did not reach admission. The next Kubernetes run also failed during Node
startup and did not reach either actor. The final Rust CI gate passed after
the regression test was added.

The old VM could not restart because its configured disk file was absent.
Its stopped definition was removed. The existing manual launcher created
`mithril-runtime-qualification-762734`, retained at
`/tmp/mithril-multi-policy-vms/mithril-vm-test.gzRI0i`. This VM has four CPUs;
the test deadlines remain unchanged. Record the final results in
[SCENARIO_MAINTAINABILITY_TODO.md](SCENARIO_MAINTAINABILITY_TODO.md).

This proof establishes simultaneous policy isolation for two workloads.
It does not establish independent installation cost, arbitrary policy count,
overlapping policy selection, or mixed Observe and Protect modes. Updating
one policy still processes the aggregate Node configuration. That change is
separate work.
