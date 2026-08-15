# Runtime Qualification VM Harness

This harness builds and runs the repository-owned kernel, identity,
effect-observation, and local-enforcement physical probes in one disposable VM.
It copies the JSON evidence to the host. It then destroys the VM on success or
failure.

The default provider uses libvirt and the official Ubuntu 24.04 cloud image.
It verifies the image with the published `SHA256SUMS` file. The guest must have
runtime BTF, cgroup v2, bpffs, and BPF in the active LSM list. Before a probe
runs, the repository inspector also proves that the guest filesystem returns
`STATX_MNT_ID_UNIQUE`. This record lane requires an x86-64 host and guest
because the checked result is `kernel-qualification-x86_64.json`.
The libvirt `default` network must exist and be active.

Run:

```bash
crates/mithril-e2e/harness/vm/run.sh \
  --output-directory /tmp/mithril-vm-test-evidence
```

Add the optional single-node k3s lane:

```bash
crates/mithril-e2e/harness/vm/run.sh --with-k3s \
  --skip-administrative-exec \
  --output-directory /tmp/mithril-k3s-vm-test-evidence
```

This option installs k3s only after the provider creates the disposable guest.
It uses the checked `k3s-config-v1.yaml`, k3s `v1.35.5+k3s1`, and an immutable
BusyBox image reference. It waits for the node and CRI, then proves Pod
readiness, direct CRI exec, `kubectl exec`, the CRI container ID and workload
root, an overlay root, and a projected service-account token. It then starts
the real `mithril-node` against the k3s containerd socket. The node binds the
exact Pod and CRI cgroup. The lane succeeds only if Mithril classifies the
pre-existing Pod root conservatively and classifies later direct CRI and
`kubectl exec` processes as restricted external roots. Each process reads the
exact secret before signed policy recovery, then reads it again after recovery.
In `OBSERVE`, each later read must complete. Its evidence must contain that
task cookie, exact object key, `WOULD_DENY`, and
`UNKNOWN_AFTER_PRE_EFFECT`. In `PROTECT`, each later read must receive an
exact-object denial. `kubectl exec` also reads a benign exact file after
recovery; that read must stay allowed. The hostPath file is only a
qualification fixture. It does not prove projected-token semantic
classification. An empty read-only hostPath release file holds the direct CRI
task until signed recovery. The host writes that file after recovery.

The CRI guest lane accepts only `MITHRIL_VM_CRI_EFFECT_MODE=OBSERVE|PROTECT`.
It uses `PROTECT` by default. The harness sets each mode explicitly and writes
the observe result before the protect result.

By default, the option also runs the administrative-exec product path. It
starts the real Control and node services. It uses a disposable HTTPS OIDC provider to test
authorization-code PKCE and explicit self-approval. `kubectl-mithril` obtains
one memory-only credential. The stock Kubernetes TokenReview and CONNECT
admission paths must arm one exact node slot. The matching runtime root must
receive the approved administrative role. Ordinary `kubectl exec` must fail
admission. A later direct-runtime task with the same executable must stay
restricted after slot consumption. This is the single-node physical
`ADMIN-EXEC-APPROVAL-001` path. Source and unit tests own its malformed,
replay, expiry, disconnect, and contention cases.

Use `--skip-administrative-exec` with `--with-k3s` to run the CRI checks
without the administrative path. The flag does not skip the runtime probes or
kernel qualification.

The administrative lane sets the k3s API audience to
`mithril-administrative-exec`. Control verifies the same audience in each
TokenReview. Kubernetes can repeat TokenReview while it completes one CONNECT.
The credential remains valid through its expiry, but Control accepts only the
original admission request. Do not use a different audience for this test.

The WebSocket exec client starts with an HTTP `GET`. The narrow test role grants
only `get` and `create` on `pods/exec`; current Kubernetes also checks `create`
for the CONNECT upgrade. The validating webhook stays fail-closed for both
permissions.

The lanes remove their namespaces, files, node and Control state, sockets,
leases, temporary trust, webhooks, RBAC, and BPF pins. The runtime probes then
run while k3s is active. Finally, the official k3s uninstall owner runs before
the provider destroys the guest.

The libvirt provider uses these optional variables:

| Variable | Default |
| --- | --- |
| `MITHRIL_LIBVIRT_URI` | `qemu:///system` |
| `MITHRIL_VM_SSH_PUBLIC_KEY` | `~/.ssh/id_rsa.pub` |
| `MITHRIL_VM_SSH_PRIVATE_KEY` | `~/.ssh/id_rsa` |
| `MITHRIL_VM_SSH_USER` | `ubuntu` |
| `MITHRIL_VM_KNOWN_HOSTS` | disposable harness work directory |
| `MITHRIL_VM_BASE_IMAGE_URL` | Ubuntu 24.04 amd64 cloud image |
| `MITHRIL_VM_IMAGE_CACHE` | user cache directory |
| `MITHRIL_VM_K3S_VERSION` | `v1.35.5+k3s1` |

The cache keeps only the verified base image. A download stays in the
disposable work directory until checksum validation succeeds. The harness removes its overlay,
cloud-init data, guest, BPF pins, cgroups, lease files, and guest test files.
The selected output directory keeps the platform manifest, the raw physical
probe and benchmark evidence, the generated kernel qualification record, and
the identity and effect results. With `--with-k3s`, it also keeps `k3s.txt` and
`k3s-cri-observe.txt` and `k3s-cri-effect.txt`. These files record the Pod
initial-root classification, the direct CRI and `kubectl exec` external-root
classifications, each matching exact-secret effect, and the observe and protect
file-open results. Unless
`--skip-administrative-exec` is set, it also keeps
`k3s-administrative-exec.txt`. That file records the product path, approved
role, admission denial, restricted non-winner, and measured pre-binding start
gap. A failed lane retains only a `.partial` host record. Guest destruction
remains the outer cleanup boundary.

For repeated manual work, add `--keep-vm`. The harness leaves the guest and
its k3s installation running, and writes `retained-vm.txt` in the output
directory. Keep that file. When the work is complete, destroy only that guest:

```bash
crates/mithril-e2e/harness/vm/providers/libvirt.sh destroy <vm_name> <work_directory>
```

Use the two values from `retained-vm.txt`. Without `--keep-vm`, the default
cleanup remains unchanged. If the administrative lane fails with `--keep-vm`,
the guest also keeps its lane directory and BPF pins. Inspect that state before
you start another administrative lane.

## Manual Testing In A Retained VM

Run the shell check. Then create one retained K3s guest:

```bash
bash crates/mithril-e2e/harness/vm/test.sh
crates/mithril-e2e/harness/vm/run.sh --with-k3s \
  --skip-administrative-exec \
  --keep-vm \
  --output-directory /tmp/mithril-manual-vm-evidence
```

`run.sh` leaves the current binaries and checked policy assets in
`/var/tmp/<vm_name>`. It does not leave a manual Pod, a live binding JSON, or
the current manual shell sources. Create these inputs for every manual case.
Run one Mithril owner at a time. Do not reuse a container ID, Pod UID, or
binding from an earlier run.

### Run A Manual Shell

Run these host commands from the repository root. They stage the current
identity and effect-observation shells. They do not copy the test signing key.
The guest reuses the harness-staged key.

```bash
set -a
. /tmp/mithril-manual-vm-evidence/retained-vm.txt
set +a
remote_root=/var/tmp/$vm_name
manual_id=$(date -u +%Y%m%dT%H%M%SZ)-$$
manual_root=/var/tmp/mithril-manual-$manual_id
archive=$(mktemp)

tar --exclude='examples/mithril-effect-observation-manual/test-signing-key.hex' \
  -czf "$archive" \
  examples/mithril-identity-manual \
  examples/mithril-effect-observation-manual
"$provider" run "$vm_name" mkdir -p "$manual_root/source" "$manual_root/bin"
"$provider" put "$vm_name" "$archive" "$manual_root/manual-scripts.tgz"
"$provider" run "$vm_name" sh -ec '
  tar -xzf "$1" -C "$2"
  ln -s /usr/local/bin/k3s "$3/crictl"
  ln -s "$4" "$2/examples/mithril-effect-observation-manual/test-signing-key.hex"
' sh "$manual_root/manual-scripts.tgz" "$manual_root/source" "$manual_root/bin" \
  "$remote_root/source/examples/mithril-effect-observation-manual/test-signing-key.hex"
rm -f -- "$archive"
```

For an identity-only case, run the staged entry shell from
`$manual_root/source/examples/mithril-identity-manual`. For an
effect-observation case, run the staged entry shell from
`$manual_root/source/examples/mithril-effect-observation-manual`. A local
enforcement case also needs its `mithril-local-enforcement-manual` directory.
Copy that directory with the same archive command when you need it. Each
entry shell sources its helper from its own directory. Do not copy only the
entry shell.

### Run The Direct CRI Observation Example

This is the complete retained-VM procedure for
`cri-file-observe.sh`. It creates a fresh Pod, a fresh live binding, and the
writable shared directory that the shell requires.

Create the exact host fixtures in the guest. Continue only when `lsattr -v`
prints a nonzero generation for `secret`.

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

Create the binding from that live container. Do not copy values from an older
Pod. This command uses the same CRI creation-time conversion as the harness.

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

Run the staged shell in the guest. `MITHRIL_BIN_DIRECTORY` selects the
binaries that the retained harness built. The run must print its `PASS:` line.

```bash
"$provider" run "$vm_name" sudo env \
  "PATH=$manual_root/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin" \
  "MITHRIL_BIN_DIRECTORY=$remote_root/bin" \
  "$manual_root/source/examples/mithril-effect-observation-manual/cri-file-observe.sh" \
  "$manual_root/node.json" "$container_id" /var/lib/mithril/secret \
  "$shared_directory" /var/lib/mithril/manual-shared
```

The shell owns its node, task, pins, lease, state, and probe files. The outer
operator owns the Pod and fixture. After you retain any output, remove only
the named namespace and fixture root. Keep `$manual_root` for the command and
configuration record, or destroy the retained VM after the final case.

```bash
"$provider" run "$vm_name" sudo /usr/local/bin/k3s kubectl delete namespace \
  "$namespace" --wait=true --timeout=120s
"$provider" run "$vm_name" sudo rm -rf -- "$fixture_root"
```

The manual script owns its node, pins, lease, and probe. The outer operator
owns the Pod, fixture, and guest. Use the `destroy` command above with the two
values from `retained-vm.txt` after the final manual case.

Reuse a retained guest and k3s installation for sequential probes. Do not run
two Mithril object owners at the same time. A different pin root does not
isolate BPF LSM links. The loader rejects a concurrent owner before attach. If
it reports `RetainedLsmLink`, restart with the original pin root or use a fresh
guest. Do not delete an unknown pinned link to continue a probe.

The current administrative lane reaches draft creation, admission, and slot
arm. Stock runc `1.4.2` then fails closed before target exec because its sealed
self-clone and inherited bootstrap channels are unsupported. Treat this as a
product blocker. Do not add a broad runc, pipe, or socket exception while you
investigate it.

The host compiles the disposable kernel qualification object with the existing
repository compiler. The guest loads that exact object. The record command
checks the copied source digest, the physical capability records, and every raw
benchmark distribution before it writes
`kernel-qualification-x86_64.json`. Copy that file into the checked result path
only after you review the complete evidence directory.

The benchmark opens the copied qualification source. This path is separate
from the physical deny target. Protected mode attaches the same qualification
object but does not install a deny entry for the benchmark file.

All harness-owned configuration is checked in beside this README:
`cloud-init-v1.yaml`, `k3s-config-v1.yaml`, `k3s-workload-v1.yaml`, and
the two k3s node templates. The narrow administrative policy authorizes only
the checked executable object for the restricted external role. The
`oidc-fixture.py` file is the credential-free disposable identity provider.
The templates contain no key, credential, or certificate. The provider
substitutes only the requested SSH public key into the checked cloud-init
template.

Run the local shell checks without creating a guest:

```bash
crates/mithril-e2e/harness/vm/test.sh
```

## Provider Contract

`run.sh` does not contain libvirt logic. A provider is one executable with six
commands:

| Command | Required result |
| --- | --- |
| `create NAME WORK_DIRECTORY PUBLIC_KEY` | Create one new isolated guest. Reject a name collision. |
| `wait NAME` | Return only after SSH, runtime BTF, cgroup v2, bpffs, and BPF LSM are ready. |
| `put NAME LOCAL REMOTE` | Copy one file to the guest. |
| `get NAME REMOTE LOCAL` | Copy one evidence file from the guest. |
| `run NAME COMMAND...` | Run the command in the guest and return its status. |
| `destroy NAME WORK_DIRECTORY` | Remove only the named guest and its provider-owned resources. Be idempotent. |

A cloud adapter can implement this contract with its official CLI or SDK. It
does not need changes to the test flow. Keep provider-specific credentials,
networks, images, and cleanup inside the adapter. Do not put cloud credentials
in this repository or in the evidence bundle.

The k3s option does not replace kernel qualification. It proves one exact local
file denial after CRI binding and one administrative exec transaction on one
node. It does not claim first-instruction binding: the record states that the
Pod ran before the snapshot binding. It does not prove projected-token
semantics or multi-node behavior. Those cases use separate fixtures.

This automated harness complements the operator-driven identity,
effect-observation, and local-enforcement examples. It does not replace those
manual cases.
