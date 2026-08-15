# Effect Observation Manual Cases

The separate [VM e2e harness](../../crates/mithril-e2e/harness/vm/README.md)
runs the automated privileged probe. The cases here remain operator-driven.

These scripts run the real `mithril-node`; they are not wrappers around Rust
tests. Each case owns its temporary node state, observation socket, lease, BPF
pins, probe process, FIFO, and any mount/file artifacts. A prepared probe waits
on its FIFO while the node recovers the signed candidate. The host does not
signal the protected task. The EXIT trap removes all artifacts on pass,
failure, or interruption.

The effect probe starts under the identity-only node and blocks on its FIFO.
The lifecycle opens the FIFO after it recovers the same pinned identity state
with the signed observe candidate. This is deliberate: starting `docker exec`
after activation would first test the new executable itself, not the requested
file or network effect.

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

The container needs Python 3. The host needs `jq`, `gawk`, `lsattr`, Docker (or
`crictl` for the CRI case), and a kernel-qualified BPF LSM host.

Cases:

- `compile-observe-policy.sh` compiles and verifies the signed observe candidate,
  then compares a normal simulated denial with a hard-safety denial.
- `docker-file-observe.sh <node.json> <container> <absolute-secret-path>`
  recovers Mithril with the candidate, releases an already-attributed process,
  and requires the read to succeed while the kernel reports `WOULD_DENY`.
- `cri-file-observe.sh <node.json> <container-id> <absolute-secret-path>`
  runs the same physical oracle through a configured CRI runtime. It records
  the direct CRI task cookie and requires `WOULD_DENY`,
  `UNKNOWN_AFTER_PRE_EFFECT`, and exact object key `7` for the completed read.
- `nsenter-file-observe.sh <node.json> <container>
  <absolute-secret-path>` joins the mount view with raw `nsenter`, moves the
  blocked process into the bound cgroup, and proves the same exact attribution.
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
