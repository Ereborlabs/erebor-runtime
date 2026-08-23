# Runtime Qualification VM Harness

This harness builds and runs the repository-owned kernel, identity,
effect-observation, and local-enforcement physical probes in one disposable VM.
It copies the JSON evidence to the host. By default, it then destroys the VM
on success or failure. The `--keep-vm` option retains the VM for diagnosis.

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

Run the isolated Runtime Interceptor lane after VM provisioning is approved:

```bash
crates/mithril-e2e/harness/vm/run.sh --runtime-interceptor \
  --output-directory /tmp/erebor-runtime-interceptor-evidence
```

This option uses a separate branch-scoped VM name. It cannot run with
`--with-k3s` or `--manual`. The guest starts the installed `erebord` service
with delegated systemd containment and a branch-scoped bpffs pin root. It uses
the `codex-v1-fixture` Agent, three root-curated static-probe packages, and
seven dedicated policy packages. The execute-only static probe makes
`OpenRead` without a read syscall, inherited-PTY `Read`, or target `OpenWrite`
the first file operation in each negative case. The lane checks process
execution, file open, file read, file mutation, socket connect,
held-cgroup separation, first-exec denial, stop and kill cleanup, activation
cancellation, restart fencing, and evidence coverage. The App Server pipe and
interactive PTY cases are transport checks. They do not qualify exact pipe or
PTY policy semantics.

The lane writes `runtime-interceptor-physical-proof.json` only after all
oracles pass. A failed run can leave only the host `.partial` file. The
current source state has not run this VM lane. See the
[Runtime Interceptor VM proof review guide](../../../../docs/guides/runtime-interceptor-vm-proof.md)
before you qualify a result.

Add the optional single-node Kubernetes lane. The harness uses the K3s
distribution:

```bash
crates/mithril-e2e/harness/vm/run.sh --with-k3s \
  --skip-administrative-exec \
  --output-directory /tmp/mithril-k3s-vm-test-evidence
```

This option installs the K3s distribution only after the provider creates the
disposable guest. It uses the checked `k3s-config-v1.yaml`, K3s
`v1.35.5+k3s1`, Kubernetes `v1.35.5`, and an immutable BusyBox image
reference. It waits for the node and CRI, then proves Pod
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

Run the network-only two-node K3s companion with:

```bash
crates/mithril-e2e/harness/vm/two-node-network.sh \
  --output-directory /tmp/mithril-two-node-network
```

The companion creates two disposable VMs with different boot identities,
installs the pinned K3s version, and waits for two Ready nodes. It pins one peer
Pod to each node and starts the Rust peer server inside each Pod network
namespace. The opposite host runs the production physical network probe
against the remote Pod IP. Both directions must deliver allowed TCP and UDP,
deny the unapproved port without peer receipt, and pass all 13 network fixture
rows. The companion then removes its namespace, K3s installations, and owned
VMs.

This lane proves the tested K3s Flannel route. It does not prove Pod-origin
enforcement, another CNI, a service mesh, distributed causality, or the full
later-phase two-node lifecycle.

The administrative lane sets the k3s API audience to
`mithril-administrative-exec`. Control verifies the same audience in each
TokenReview. Kubernetes can repeat TokenReview while it completes one CONNECT.
The credential remains valid through its expiry, but Control accepts only the
original admission request. Do not use a different audience for this test.

The WebSocket exec client starts with an HTTP `GET`. The narrow test role grants
only `get` and `create` on `pods/exec`; current Kubernetes also checks `create`
for the CONNECT upgrade. The validating webhook stays fail-closed for both
permissions.

The lanes remove their Namespaces, files, node and Control state, sockets,
leases, temporary trust, webhooks, RBAC, and BPF pins. The native identity
probe runs before Kubernetes starts. The Kubernetes identity extension runs
after the effect probes and records the pre-existing Pod root, direct CRI
exec, and non-TTY `kubectl exec`. Finally, the official K3s uninstall owner
runs before the provider destroys the guest.

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
| `MITHRIL_VM_SOURCE_MOUNT` | unset; libvirt mounts this absolute host directory read-only at `/mnt/mithril-source` |

The cache keeps only the verified base image. A download stays in the
disposable work directory until checksum validation succeeds. The harness removes its overlay,
cloud-init data, guest, BPF pins, cgroups, lease files, and guest test files.
The selected output directory keeps the platform manifest, the raw physical
probe and benchmark evidence, the generated kernel qualification record, and
the identity, effect, and network results. The network result records the
single-host actor, destination, response-fence, and socket-lifetime oracles.
With `--with-k3s`, the directory also keeps `k3s.txt`, `k3s-cri-observe.txt`,
and `k3s-cri-effect.txt`. These files record the Pod
initial-root classification, the direct CRI and `kubectl exec` external-root
classifications, each matching exact-secret effect, and the observe and protect
file-open results. Unless
`--skip-administrative-exec` is set, it also keeps
`k3s-administrative-exec.txt`. That file records the product path, approved
role, admission denial, restricted non-winner, and measured pre-binding start
gap. A failed lane retains only a `.partial` host record. Guest destruction
remains the outer cleanup boundary.

`--keep-vm` retains a failed or diagnostic qualification guest. Use
`manual.sh` for manual work. It owns the VM name and the provider record.
`--keep-vm` writes `retained-vm.txt` for provider-level diagnosis.

The harness derives a bounded VM namespace from the current Git branch. The
namespace contains a readable branch prefix and a digest of the complete branch
name. The runner adds its lane, process, and node identity. Manual state uses
the same namespace under `${XDG_STATE_HOME:-$HOME/.local/state}`. Two worktrees
on different branches therefore create, inspect, reconnect to, and destroy only
their own VMs. A detached checkout uses its abbreviated commit ID.

## Manual Testing In A VM

On the host:

```bash
crates/mithril-e2e/harness/vm/manual.sh create
crates/mithril-e2e/harness/vm/manual.sh status
crates/mithril-e2e/harness/vm/manual.sh reconnect
```

`create` retains one Kubernetes VM through the K3s distribution, mounts the
current repository read-only at `/mnt/mithril-source`, and builds
`mithril-node`, `mithril-inspect`, and `mithril-policy`. Do not start a second
Mithril owner in this VM.

`status` prints the current branch, VM name, and provider state. `reconnect`
opens SSH for that branch's retained VM. The earlier `start` and `ssh` command
names remain aliases for existing runbooks.

In the guest:

```bash
sudo -i
. /var/tmp/mithril-manual.env
cd "$MITHRIL_MANUAL_SOURCE"
```

`MITHRIL_BIN_DIRECTORY` names the mounted binaries. `kubectl`, `crictl`,
`netstat`, and `k9s` are on `PATH`. K3s configuration is in
`/home/ubuntu/.kube/config` and `/root/.kube/config`. K9s uses the same
configuration. Do not set `KUBECONFIG`. Run `crictl` as `root` because the
containerd socket is root-owned.
Manual scripts start `mithril-node` on the guest host. Mithril is not a
Kubernetes Deployment.

```bash
kubectl get nodes -o name
crictl info
netstat -lnt
k9s version
```

The harness does not run manual cases. Run the command in the required example
README from this root guest shell. Each self-contained case creates and removes
its own Pod, live CRI binding, and fixture directory.

On the host, remove the VM after the manual checks:

```bash
crates/mithril-e2e/harness/vm/manual.sh destroy
```

`destroy` removes the VM and its local work directory.

For the two-node policy-convergence case, create and enter the retained
environment with:

```bash
crates/mithril-e2e/harness/vm/manual.sh create-convergence
crates/mithril-e2e/harness/vm/manual.sh status-convergence
crates/mithril-e2e/harness/vm/manual.sh reconnect-convergence
```

The environment contains two K3s Nodes, the installed Mithril chart, unique
node identities, the stock OCI hooks, and the repository mounted read-only at
`/mnt/mithril-source`. In the first guest, prepare the shell with:

```bash
sudo -i
. /var/tmp/mithril-convergence-manual.env
cd "$MITHRIL_MANUAL_SOURCE"
kubectl get nodes -o wide
kubectl -n mithril-system get pods -o wide
```

Run the scenario command from its example README. The harness does not select
or run the scenario. After the example reports that it removed its namespace
and RuntimeClasses, leave the guest and remove both VMs from the host:

```bash
crates/mithril-e2e/harness/vm/manual.sh destroy-convergence
```

The destroy command checks both retained provider ownership records before it
removes the VMs and their local work directories.

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
the two k3s node templates. `identity.sh` owns the branch key and bounded VM
name. The narrow administrative policy authorizes only
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

`run.sh` does not contain libvirt logic. A provider is one executable with
these commands:

| Command | Required result |
| --- | --- |
| `address NAME` | Return the exact provider address for one ready guest. |
| `create NAME WORK_DIRECTORY PUBLIC_KEY` | Create one new isolated guest. Reject a name collision. |
| `status NAME WORK_DIRECTORY` | Return the provider state only when the ownership record matches the live guest. |
| `wait NAME` | Return only after SSH, runtime BTF, cgroup v2, bpffs, and BPF LSM are ready. |
| `put NAME LOCAL REMOTE` | Copy one file to the guest. |
| `get NAME REMOTE LOCAL` | Copy one evidence file from the guest. |
| `run NAME COMMAND...` | Run the command in the guest and return its status. |
| `ssh NAME` | Open an interactive shell in one ready guest. |
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
