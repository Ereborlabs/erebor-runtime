# Effect Observation Manual Cases

## Manual Testing In A VM

Use the [retained-VM setup](../../crates/mithril-e2e/harness/vm/README.md#manual-shells-in-a-retained-vm)
to stage this directory and use the current guest binaries. Do not reuse a
container ID, Pod UID, or binding from a previous container.

## Direct CRI In A Retained VM

Use this recipe for `cri-file-observe.sh`. It creates the required fresh Pod,
live binding, and writable shared directory. It assumes the retained-VM setup
defined `provider`, `vm_name`, `remote_root`, `manual_id`, and `manual_root`.

Create a guest-local exact fixture. Continue only when `lsattr -v` prints a
nonzero generation for `secret`.

```bash
namespace=mithril-manual-$manual_id
fixture_root=/var/lib/mithril-manual-$manual_id
shared_directory=$fixture_root/shared
manifest=$(mktemp)

"$provider" run "$vm_name" sudo bash -ec '
  install -d -m 0700 -- "$1" "$2"
  printf "mithril manual secret\\n" >"$1/secret"
  chmod 0400 -- "$1/secret"
' bash "$fixture_root" "$shared_directory"
"$provider" run "$vm_name" sudo lsattr -v "$fixture_root/secret"

sed \
  -e "s|MITHRIL_MANUAL_NAMESPACE|$namespace|g" \
  -e "s|MITHRIL_MANUAL_SECRET_HOST_PATH|$fixture_root/secret|g" \
  -e "s|MITHRIL_MANUAL_SHARED_HOST_DIRECTORY|$shared_directory|g" \
  examples/mithril-effect-observation-manual/k3s-cri-manual-workload-v1.yaml \
  >"$manifest"
"$provider" put "$vm_name" "$manifest" "$manual_root/workload.yaml"
"$provider" run "$vm_name" sudo /usr/local/bin/k3s kubectl create namespace "$namespace"
"$provider" run "$vm_name" sudo /usr/local/bin/k3s kubectl apply -f "$manual_root/workload.yaml"
"$provider" run "$vm_name" sudo /usr/local/bin/k3s kubectl -n "$namespace" wait \
  --for=condition=Ready pod/mithril-runtime --timeout=300s
```

Create the binding from this live container. This uses the same CRI creation
time conversion as the harness.

```bash
container_ref=$("$provider" run "$vm_name" sudo /usr/local/bin/k3s kubectl \
  -n "$namespace" get pod mithril-runtime \
  -o jsonpath='{.status.containerStatuses[0].containerID}')
container_id=${container_ref#containerd://}
pod_uid=$("$provider" run "$vm_name" sudo /usr/local/bin/k3s kubectl \
  -n "$namespace" get pod mithril-runtime -o jsonpath='{.metadata.uid}')
container_json=$("$provider" run "$vm_name" sudo /usr/local/bin/k3s crictl inspect "$container_id")
created_at=$(jq -er '.status.createdAt' <<<"$container_json")
generation=$(date --utc --date "$created_at" +%s%N)
image_digest=$(jq -er '.status.imageRef' <<<"$container_json")
sandbox_id=$("$provider" run "$vm_name" sudo /usr/local/bin/k3s crictl ps \
  --id "$container_id" -o json | jq -er '.containers[0].podSandboxId')
node_config=$(mktemp)

sed \
  -e "s|/var/tmp/mithril-runtime-qualification-0|$manual_root|g" \
  -e "s|mithril-vm-qualification|$namespace|g" \
  -e "s|MITHRIL_CONTAINER_ID|$container_id|g" \
  -e "s|MITHRIL_POD_UID|$pod_uid|g" \
  -e "s|MITHRIL_SANDBOX_ID|$sandbox_id|g" \
  -e "s|MITHRIL_IMAGE_DIGEST|$image_digest|g" \
  -e "s|\"container_generation\": 1|\"container_generation\": $generation|" \
  crates/mithril-e2e/harness/vm/k3s-cri-effect-node-v1.json >"$node_config"
"$provider" put "$vm_name" "$node_config" "$manual_root/node.json"
rm -f -- "$manifest" "$node_config"
```

Run the shell. It must print its `PASS:` line.

```bash
"$provider" run "$vm_name" sudo env \
  "PATH=$manual_root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  "MITHRIL_BIN_DIRECTORY=$remote_root/bin" \
  "$manual_root/source/examples/mithril-effect-observation-manual/cri-file-observe.sh" \
  "$manual_root/node.json" "$container_id" /var/lib/mithril/secret \
  "$shared_directory" /var/lib/mithril/manual-shared
```

The shell removes its node, task, pins, lease, state, and probe files. After
you retain output, remove only the named namespace and fixture root:

```bash
"$provider" run "$vm_name" sudo /usr/local/bin/k3s kubectl delete namespace \
  "$namespace" --wait=true --timeout=120s
"$provider" run "$vm_name" sudo rm -rf -- "$fixture_root"
```

Keep `$manual_root` for its command and configuration record. Destroy the
retained guest after the final manual case.

## Operator Cases

These scripts run the real `mithril-node`; they are not wrappers around Rust
tests. Each case owns its temporary node state, observation socket, lease, BPF
pins, probe process, release gate, and any mount/file artifacts. A prepared
probe waits on its release gate while the node recovers the signed candidate.
The host does not signal the protected task. The EXIT trap removes all artifacts
on pass, failure, or interruption.

The effect probe starts under the identity-only node and blocks on its release
gate. The lifecycle opens the gate after it recovers the same pinned identity
state with the signed observe candidate. This is deliberate: starting `docker
exec` after activation would first test the new executable itself, not the
requested file or network effect.

Build once:

```sh
cargo build -p mithril-node --bins -p mithril-control --bin mithril-policy
```

For the automated privileged host oracle, build and run the self-cleaning Rust
probe instead:

```sh
cargo build -p mithril-e2e --bin mithril-effect-test
sudo target/debug/mithril-effect-test --repo-root . physical-probe \
  --output-directory /tmp/mithril-effect-observation-effect-final \
  --pin-root /sys/fs/bpf/erebor-mithril-effect-observation-effect-final \
  --lease-path /tmp/mithril-effect-observation-effect-final/owner.lock \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-effect-observation-effect-final
```

That one command asserts exact observe decisions, hard-link and later-bind
aliases, eight concurrent protected mount attempts, a privileged external
mount replacement over the exact path, DIRTY fail-closed behavior, rejection
of reconciliation against the replacement object, recovery after unmount,
ring saturation accounting, network hard safety, and baseline/observed open
latency. It removes its BPF pins, lease, cgroup, namespace mounts, processes,
and fixture files on success or failure; only the requested JSON result remains
in the output directory. The scripts below remain the runtime-specific manual
operator cases for real Docker and CRI daemons.

The host needs `jq`, `gawk`, `lsattr`, Docker (or `crictl` for the CRI case),
and a kernel-qualified BPF LSM host. The CRI file and CRI `nsenter` cases need
BusyBox `sh` and a writable run-scoped host directory mounted at a writable
absolute directory in the target container. The script verifies that mapping
before it starts Mithril. It removes only its run-specific marker, ready, and
release files. Remove the empty run-scoped host directory after the case. Other
cases that invoke `python3` need it in their target containers.

Cases:

- `compile-observe-policy.sh` compiles and verifies the signed observe candidate,
  then compares a normal simulated denial with a hard-safety denial.
- `docker-file-observe.sh <node.json> <container> <absolute-secret-path>`
  recovers Mithril with the candidate, releases an already-attributed process,
  and requires the read to succeed while the kernel reports `WOULD_DENY`.
- `cri-file-observe.sh <node.json> <container-id> <absolute-secret-path>
  <host-shared-directory> <container-shared-directory>` runs the same physical
  oracle through a configured CRI runtime. The host directory must be the
  run-scoped directory mounted at the container directory. It records the
  direct CRI task cookie and requires `WOULD_DENY`,
  `UNKNOWN_AFTER_PRE_EFFECT`, and exact object key `7` for the completed read.
- `nsenter-file-observe.sh` accepts either `<node.json> <container>
  <absolute-secret-path>` for Docker or `<node.json> <full-container-id>
  <absolute-secret-path> <host-shared-directory> <container-shared-directory>`
  for K3s/CRI. It joins the mount view with raw `nsenter`, moves the blocked
  process into the bound cgroup, and opens the exact secret before one read
  attempt. In K3s/CRI mode it requires the same probe's external-root task
  cookie in the `family=2`, `operation=2`, `WOULD_DENY`,
  `UNKNOWN_AFTER_PRE_EFFECT`, and exact object key `7` event.

For K3s/CRI, use the five-argument form with a full container ID and a fresh
writable shared directory:

```sh
sudo examples/mithril-effect-observation-manual/nsenter-file-observe.sh \
  <identity-node.json> <full-container-id> <absolute-secret-path> \
  <host-shared-directory> <container-shared-directory>
```

This is a raw `nsenter` and cgroup-placement case. It proves one exact
observation event for that process. It does not qualify `kubectl exec`, prove a
nonempty read, or complete the Phase 3 manual matrix.
- `docker-bind-alias.sh <node.json> <container>
  <mounted-secret-path> <alias-directory>` creates a later bind alias of the
  secret's existing mount root. Reading through the alias must still report the
  original path class and `WOULD_DENY`. The supplied secret directory must
  already be a distinct mount root; this is the Meta oldest-mount fixture.
- `docker-hardlink-alias.sh <node.json> <container>` reads a generated
  original path and then its pre-existing hard link. The original reports
  `WOULD_DENY`; the alias is `UNRESOLVED_OBJECT` because Version 1 has no final
  exact-object decision cache.
- `mount-attack-hard-deny.sh <node.json> <container>
  <absolute-secret-path>` moves a host-root `nsenter` probe into the protected
  cgroup and races eight `mount --bind` syscalls. Every mount must be physically
  denied, the view must pass through DIRTY reconciliation, and a later secret
  read must again reach observe-only `WOULD_DENY`.
- `unsupported-network-hard-deny.sh <node.json> <container>
  <absolute-secret-path>` starts the same observe candidate, then requires an
  already-attributed Python TCP connect to fail with an explicit
  `UNSUPPORTED_OBJECT` observation. Observe mode must not turn an unimplemented
  object classifier into allow.
- `docker-saturation-hard-safety.sh <node.json> <container>
  <absolute-secret-path> [opens]` stops the userspace ring reader, fills the
  bounded observation ring, and proves a later unsupported network effect is
  still physically denied. It requires `lost > 0` and `attempted > emitted`;
  loss is evidence health, never a decision input.
- `docker-open-latency.sh <node.json> <container>
  <absolute-secret-path> [opens]` prints a same-container baseline and live
  observe-only `open` measurement. It rejects the measurement if the kernel
  reports any ring loss.

The last two cases are observation evidence only. Local enforcement owns active
signed-policy denial under saturation and full mount CAS and propagation
enforcement. Durable evidence owns reader-loss, WAL, replay, and recovery
saturation. Release qualification owns the final multi-platform capacity and
latency proof.

The full case catalog and required oracles remain in the
[effect-observation acceptance plan](../../docs/plans/mithril-hugging-face-intrusion-prevention/manual-testing/phase-3-manual-acceptance.md).
The path/file cases have classified decisions in the current code. Positive
Unix-stream relationships remain unsupported because the current socket state
does not track descriptor transfer or socket activation. The protect example
proves that unmatched Unix-stream access is denied.
Unqualified network, device, IPC, and similar boundaries remain explicit
hard-safety results. The scripts do not relabel them as policy prevention.
