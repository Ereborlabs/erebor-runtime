# Mithril Phase 4 Manual Cases

These are real `mithril-node` cases, not wrappers around Rust tests. Each script
uses the existing Phase 2/3 lifecycle owner and its EXIT trap, so BPF pins,
leases, cgroups, child processes, mounts, sockets, and temporary files are
removed on success, failure, or interruption.

Build once:

```sh
cargo build -p mithril-node --bins -p mithril-control --bin mithril-policy \
  -p mithril-e2e --bin mithril-effect-test
```

Run the automated privileged host oracle first:

```sh
sudo target/debug/mithril-effect-test --repo-root . physical-probe \
  --protect \
  --output-directory /tmp/mithril-phase4-effect-final \
  --pin-root /sys/fs/bpf/erebor-mithril-phase4-effect-final \
  --lease-path /tmp/mithril-phase4-effect-final/owner.lock \
  --cgroup-path /sys/fs/cgroup/erebor-mithril-phase4-effect-final
```

It proves signed exact open/read/mmap denial, a same-container exact allow, an
fd acquired before activation, exact concurrent N/N+1 exception consumption,
hard-link and bind aliases, concurrent protected mount denial, hostile external
mount replacement, DIRTY reconciliation and recovery, hard closure of the
currently unqualified exec/memory/mutation/IPC/process-control/device/BPF and
self-protection surfaces, policy correctness under ring saturation, latency,
and complete cleanup. Every denial checks the physical postcondition as well as
`EACCES`; the probe leaves only the requested JSON report in the output
directory.

Manual Docker/raw-namespace cases:

- `docker-file-deny.sh <phase2-node.json> <container> <secret>` proves the
  mandatory `HF-008` first forbidden effect: no fd and no byte is returned.
- `nsenter-file-deny.sh <phase2-node.json> <container> <secret>` proves a raw
  mount-namespace join has the same task-first decision after cgroup placement.
- `docker-inherited-fd-deny.sh <phase2-node.json> <container> <secret>` opens
  the file before policy activation and proves a later read is still denied.
- `docker-mmap-deny.sh <phase2-node.json> <container> <secret>` opens the file
  before activation and proves a later file-backed mapping is denied.
- `docker-benign-allow.sh <phase2-node.json> <container> <secret>` proves an
  exact benign file remains readable by the same protected task.
- `bounded-exception-concurrency.sh <phase2-node.json> <container> <secret>`
  races eight preallocated consumers and proves exactly two obtain the signed
  write-open exception while six receive `EACCES`.
- `bounded-exception-restart.sh <phase2-node.json> <container> <secret>` uses
  both allowed writes, restarts the real node/loader on its retained pins, and
  proves the third write remains denied.
- `bounded-exception-expiry.sh <phase2-node.json> <container> <secret>` installs
  a signed one-second lifetime, waits past its monotonic deadline, and proves
  the first write-open is denied without consuming the exception.
- `docker-hardlink-deny.sh <phase2-node.json> <container> <secret>` proves an
  undeclared hard-link spelling cannot return a protected fd. The secret's
  parent directory must permit creation of the temporary hard link.
- `nsenter-bind-alias-deny.sh <phase2-node.json> <container> <secret>` creates
  a bind alias before activation and proves it canonicalizes to the same deny.
- `mount-attack-deny.sh <phase2-node.json> <container> <secret>` races eight
  protected bind mounts and proves no mutation or protected read succeeds.
- `external-mount-replacement-deny.sh <phase2-node.json> <container> <secret>`
  performs the hostile case from outside the protected cgroup and proves the
  namespace-wide DIRTY view returns no fd or bytes.
- `docker-exec-deny.sh <phase2-node.json> <container> <secret>` proves an
  unqualified executable cannot replace a prepared task.
- `docker-anonymous-exec-deny.sh <phase2-node.json> <container> <secret>`
  prepares anonymous RW memory before activation and proves it cannot become
  executable afterward.
- `docker-file-create-deny.sh`, `docker-file-setattr-deny.sh`,
  `docker-file-truncate-deny.sh`, `docker-file-unlink-deny.sh`,
  `docker-file-link-deny.sh`, and `docker-file-rename-deny.sh` each use the
  same three arguments and prove the named mutation returns `EACCES` before
  its physical filesystem change.
- `docker-ipc-access-deny.sh <phase2-node.json> <container> <secret>` uses a
  private auto-removing SysV shared-memory segment and proves access is hard
  closed.
- `docker-ptrace-deny.sh` and `docker-signal-deny.sh` use the same three
  arguments, prepare their target before activation, and prove both
  process-control paths are denied without leaving a child process.
- `docker-device-ioctl-deny.sh <phase2-node.json> <container> <secret>` opens
  `/dev/null` before activation and proves the inherited fd cannot issue an
  ioctl.
- `docker-namespace-deny.sh <phase2-node.json> <container> <secret>` prepares
  the task before activation and proves an unqualified UTS namespace cannot be
  created.
- `self-protect-link-deny.sh <phase2-node.json> <container> <secret>` moves a
  host probe into protected placement and proves it cannot unlink Mithril's
  real pinned file-open LSM link.

The full case catalog remains in the
[Phase 4 acceptance plan](../../docs/plans/mithril-hugging-face-intrusion-prevention/manual-testing/phase-4-manual-acceptance.md).
Only the x86_64 exact-file slice can be advertised until its privileged probe
passes. The additional cases prove that unqualified local surfaces are
physically hard closed; they do not relabel those surfaces as policy-aware
allow/deny support. Network destination enforcement is owned by Phase 5.
