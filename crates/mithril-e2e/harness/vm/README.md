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
  --output-directory /tmp/mithril-k3s-vm-test-evidence
```

This option installs k3s only after the provider creates the disposable guest.
It uses the checked `k3s-config-v1.yaml`, k3s `v1.35.5+k3s1`, and an immutable
BusyBox image reference. It waits for the node and CRI, then proves Pod
readiness, `kubectl exec`, the CRI container ID and workload root, an overlay
root, and a projected service-account token. It then starts the real
`mithril-node` against the k3s containerd socket. The node binds the exact Pod
and CRI cgroup. The lane succeeds only if Mithril classifies the pre-existing
Pod root conservatively and classifies a later `kubectl exec` process as a
restricted external root. The same process must read one read-only hostPath
qualification file before PROTECT and receive an exact-object denial after
PROTECT. The denial evidence must contain that process task cookie. The
hostPath file is only a qualification fixture. It does not prove
projected-token semantic classification.

The option also runs the administrative-exec product path. It starts the real
Control and node services. It uses a disposable HTTPS OIDC provider to test
authorization-code PKCE and explicit self-approval. `kubectl-mithril` obtains
one memory-only credential. The stock Kubernetes TokenReview and CONNECT
admission paths must arm one exact node slot. The matching runtime root must
receive the approved administrative role. Ordinary `kubectl exec` must fail
admission. A later direct-runtime task with the same executable must stay
restricted after slot consumption. This is the single-node physical
`ADMIN-EXEC-APPROVAL-001` path. Source and unit tests own its malformed,
replay, expiry, disconnect, and contention cases.

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
`k3s-cri-effect.txt`. The second file records the Pod initial-root
classification, the `kubectl exec` external-root classification, and the exact
file-open denial. It also keeps `k3s-administrative-exec.txt`. That file records
the product path, approved role, admission denial, restricted non-winner, and
measured pre-binding start gap. A failed lane retains only a `.partial` host
record. Guest destruction remains the outer cleanup boundary.

For repeated manual work, add `--keep-vm`. The harness leaves the guest and
its k3s installation running, and writes `retained-vm.txt` in the output
directory. Keep that file. When the work is complete, destroy only that guest:

```bash
crates/mithril-e2e/harness/vm/providers/libvirt.sh destroy <vm_name> <work_directory>
```

Use the two values from `retained-vm.txt`. Without `--keep-vm`, the default
cleanup remains unchanged.

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
