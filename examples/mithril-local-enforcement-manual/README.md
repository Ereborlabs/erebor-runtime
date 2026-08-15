# Local Enforcement Manual Cases

The separate [VM e2e harness](../../crates/mithril-e2e/harness/vm/README.md)
runs the automated privileged probe. Its optional `--with-k3s` lane runs the
same production probes beside a disposable single-node Kubernetes runtime.
The cases here remain operator-driven.

These are real `mithril-node` cases, not wrappers around Rust tests. Each script
uses the identity and observation lifecycle owner and its EXIT trap. Each
prepared probe waits on its own FIFO. The host does not signal a protected
task to release the test. The trap removes Mithril-owned BPF pins, leases,
child processes, mounts, sockets, FIFOs, and temporary files on success,
failure, or interruption. It leaves the supplied container and cgroup intact.

Build once:

```sh
cargo build -p mithril-node --bins -p mithril-control --bin mithril-policy \
  -p mithril-e2e --bin mithril-effect-test
```

## CRI Benign Allow

Run this operator-driven case against one running CRI container. It uses the
signed protect-mode runtime. It does not run the VM harness.

Prerequisites:

- Run the command as root with `sudo`.
- Build the binaries shown above. Install `crictl`, `jq`, and `timeout`.
- Give the node JSON exactly one workload binding for the CRI container ID.
  Its `container_runtime.socket_path` must name the active CRI socket.
- Give a secret path and a different benign path. Both paths must be absolute
  paths in the container. The benign file must contain `benign` followed by a
  newline. Both files must exist on a filesystem that reports a nonzero inode
  generation.
- Do not run another Mithril owner on this host.

Run:

```sh
sudo examples/mithril-local-enforcement-manual/cri-benign-allow.sh \
  /absolute/path/node.json \
  <cri-container-id> \
  /absolute/path/in-container/secret \
  /absolute/path/in-container/benign
```

Expected output includes:

```text
PASS: the CRI exact benign file remained readable and mappable in protect mode.
Mithril, tasks, pins, state, lease, config, and logs removed.
```

The script waits for an `EXACT_POLICY_ALLOW` observation. After policy
activation, its one CRI task reads and read-maps the exact benign file. The
secret path configures the signed policy. This script does not read the secret.

Cleanup: the EXIT trap removes the Mithril-owned processes, pins, state,
lease, sockets, FIFOs, and temporary files. It leaves the supplied container
and cgroup intact. Do not remove BPF pins that the script does not own.

Limit: this case proves one exact, non-rotating benign file in one CRI task. It
does not prove secret denial, projected-token semantics, token rotation, or
multi-node behavior.

Run the automated privileged host oracle first:

```sh
sudo target/debug/mithril-effect-test --repo-root . physical-probe \
  --protect \
  --output-directory /tmp/mithril-local-enforcement-effect-final \
  --pin-root /sys/fs/bpf/erebor-mithril-local-enforcement-effect-final \
  --lease-path /tmp/mithril-local-enforcement-effect-final/owner.lock \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-local-enforcement-effect-final
```

It proves signed exact file open, read, mmap, and mprotect decisions; exact
executable-image allow and deny decisions across `execve`, `execveat`,
`fexecve`, scripts, deleted files, and a non-leader thread; an fd acquired
before activation; exact concurrent N/N+1 exception consumption; an exact
PTMX ioctl that returns a PTY number; an exact device denial; a signal-zero
permission check; signal denial; ptrace denial; and unmatched Unix-stream
denial. It also proves one signed Unix-stream relationship across
two protected roots. It checks connect, send, and receive in both directions.
It then proves that peer exit removes the allow and that an undeclared peer
receives the unmatched deny. It also checks aliases, mount races,
DIRTY reconciliation, ring saturation, latency, and cleanup. The probe keeps
hard closure for unqualified objects. Each denial checks `EACCES` and the
physical postcondition. Only the requested JSON report remains.

The automated probe also sends secret and benign file descriptors over the
declared two-role Unix stream. A denied `SCM_RIGHTS` transfer returns its data
byte with `MSG_CTRUNC`. Linux does not return `EACCES` from `recvmsg` for this
case. Linux omits the control message and does not install the file descriptor.
The probe compares the recipient descriptor table before and after the call.
The benign control installs exactly one descriptor and reads one byte.

There is no operator shell for this two-role transfer. The current
`enforcement-runtime.sh` owner starts one protected role. A socket pair that a
task creates before activation does not test file acquisition because the IPC
gate stops the unqualified socket first. Use the automated probe until the
manual runtime can start the declared peer role.

Manual Docker, CRI, and raw-namespace cases:

- `docker-file-deny.sh <node.json> <container> <secret>` proves the
  mandatory `HF-008` first forbidden effect: no fd and no byte is returned.
- `nsenter-file-deny.sh <node.json> <container> <secret>` proves a raw
  mount-namespace join has the same task-first decision after cgroup placement.
- `docker-inherited-fd-deny.sh <node.json> <container> <secret>` opens
  the file before policy activation and proves a later read is still denied.
- `docker-mmap-deny.sh <node.json> <container> <secret>` opens the file
  before activation and proves a later file-backed mapping is denied.
- `docker-benign-allow.sh <node.json> <container> <secret> <benign>`
  proves an exact benign file remains readable and mappable by the same
  protected task.
  The benign file must already exist on a filesystem that exposes a nonzero
  inode generation, and it must not be the secret object.
- `cri-benign-allow.sh <node.json> <container-id> <secret> <benign>` proves
  the same exact benign read and mapping control through CRI. See
  [CRI Benign Allow](#cri-benign-allow) for prerequisites and limits.
- `bounded-exception-concurrency.sh <node.json> <container> <secret>`
  races eight preallocated consumers and proves exactly two obtain the signed
  write-open exception while six receive `EACCES`.
- `bounded-exception-restart.sh <node.json> <container> <secret>` uses
  both allowed writes, restarts the real node/loader on its retained pins, and
  proves the third write remains denied.
- `bounded-exception-expiry.sh <node.json> <container> <secret>` installs
  a signed one-second lifetime, waits past its monotonic deadline, and proves
  the first write-open is denied without consuming the exception.
- `docker-hardlink-deny.sh <node.json> <container> <secret>` proves an
  undeclared hard-link spelling cannot return a protected fd. The secret's
  parent directory must permit creation of the temporary hard link.
- `nsenter-bind-alias-deny.sh <node.json> <container> <secret>` creates
  a bind alias before activation and proves it canonicalizes to the same deny.
- `mount-attack-deny.sh <node.json> <container> <secret>` races eight
  protected bind mounts and proves no mutation or protected read succeeds.
- `external-mount-replacement-deny.sh <node.json> <container> <secret>
  <benign>` performs the hostile case from outside the protected cgroup and
  proves the namespace-wide DIRTY view returns no fd or bytes. The benign file
  has the same filesystem requirements as the benign allow case.
- `docker-exec-deny.sh <node.json> <container> <secret>
  <denied-executable>` proves a signed exact image cannot replace the prepared
  task.
- `docker-exec-allow.sh <node.json> <container> <secret>
  <allowed-executable>` proves a signed exact image can replace the prepared
  task. Use a static BusyBox executable. The script invokes it as
  `sh -c 'exit 0'`, which avoids a separate dynamic-loader image.
- `docker-anonymous-exec-deny.sh <node.json> <container> <secret>`
  prepares anonymous RW memory before activation and proves it cannot become
  executable afterward.
- `docker-file-create-deny.sh`, `docker-file-setattr-deny.sh`,
  `docker-file-truncate-deny.sh`, `docker-file-unlink-deny.sh`,
  `docker-file-link-deny.sh`, and `docker-file-rename-deny.sh` each use the
  same three arguments and prove the named mutation returns `EACCES` before
  its physical filesystem change.
- `docker-unix-stream-deny.sh <node.json> <container> <secret>` prepares a
  labeled listener and client and proves unmatched Unix-stream connect is
  denied.
- `docker-ipc-access-deny.sh <node.json> <container> <secret>` uses a private
  auto-removing SysV shared-memory segment and proves this unqualified IPC
  class remains hard closed.
- `docker-ptrace-deny.sh <node.json> <container> <secret>` proves the signed
  exact process-control rule denies ptrace of a labeled child.
- `docker-signal-allow.sh <node.json> <container> <secret>` proves the signed
  exact process-control rule allows the signal-zero permission check for a
  labeled child. This check does not deliver a signal.
- `docker-signal-deny.sh <node.json> <container> <secret>` proves the signed
  wildcard floor denies an unlisted `SIGCONT` argument. The target is already
  running, so an accidental `SIGCONT` does not change its state.
- `docker-device-ioctl-policy.sh <node.json> <container> <secret>` proves the
  exact `/dev/pts/ptmx` `TIOCGPTN` request succeeds and returns a PTY number.
  The same command receives `EACCES` for exact `/dev/zero` authority.
- `docker-namespace-deny.sh <node.json> <container> <secret>` prepares
  the task before activation and proves an unqualified UTS namespace cannot be
  created.
- `self-protect-link-deny.sh <node.json> <container> <secret>` moves a
  host probe into protected placement and proves it cannot unlink Mithril's
  real pinned file-open LSM link.

The full case catalog remains in the
[local-enforcement acceptance plan](../../docs/plans/mithril-hugging-face-intrusion-prevention/manual-testing/phase-4-manual-acceptance.md).
Advertise this local slice only after the current-source privileged VM probe
passes. The qualified policy-aware surfaces are exact regular-file effects,
exact executable images, exact character-device ioctls, conservative labeled
signal allow and deny, ptrace denial, and exact AF_UNIX `SOCK_STREAM` relationships with live
endpoint checks. Current-recipient regular-file acquisition through
`SCM_RIGHTS` is qualified by the automated probe. Positive process-control
remains incomplete. SysV shared memory, Unix datagrams, socket pairs, pipes,
general descriptor provenance, socket activation, async IPC, anonymous and
memfd image authority, namespace creation, BPF creation, and complete
self-protection stay unsupported or hard closed. Network destination
enforcement is separate work.
