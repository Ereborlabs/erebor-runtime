# Mithril Network Enforcement Manual Probe

This example runs the single-host physical network probe. It loads the real
Mithril BPF programs, creates dedicated cgroups, installs a signed policy, and
runs managed children through the production enforcement path.

The probe proves these results:

- allowed and denied IPv4, IPv6, TCP, UDP, DNS destination, and socket-control
  operations have separate syscall and receipt results;
- a delegated request carries its request identity and final destination to
  the enforcing delegate;
- governed token reads keep read, network, and provider-write results separate;
- accepted and established sockets preserve authority after descriptor
  transfer between actors;
- a live socket transferred across a network namespace preserves creator and
  current-actor authority;
- an installed `nftables` rewrite cannot replace the authorized final
  destination;
- a whole-socket response fence denies every tested holder and prevents later
  bytes; and
- clone, fork, inherit, close, descriptor reuse, and generation-reference
  checks follow the kernel socket lifetime.

The result contains one `PASS` row for each of the 13 allocated fixtures. It
does not claim DNS payload parsing, TLS operation semantics, every network
topology, or every network protocol.

## Run

Use a kernel-qualified Linux host with cgroup v2, runtime BPF Type Format, a
mounted BPF filesystem, and BPF LSM enabled. Install `iproute2`, `nftables`,
and `jq`. Build as the normal workspace user, then run the physical probe as
root:

```sh
cargo build -p mithril-e2e --bin mithril-network-test
sudo examples/mithril-network-manual/run-network-probe.sh
```

The script rejects pre-existing run paths. On success, it keeps only this
result file:

```text
/tmp/mithril-network-manual/network-physical-probe.json
```

Set `MITHRIL_NETWORK_RUN_NAME` to use another isolated result and kernel-object
name. The value must contain only ASCII letters, digits, periods, underscores,
or hyphens.

```sh
sudo MITHRIL_NETWORK_RUN_NAME=review-1 \
  examples/mithril-network-manual/run-network-probe.sh
```

Inspect the result with:

```sh
jq . /tmp/mithril-network-review-1/network-physical-probe.json
```

The script exits with an error unless every Boolean physical oracle is `true`
and the exact 13-row fixture list contains only `PASS` results. The result does
not turn an untested product capability into a support claim.

## Two-Node Automation Boundary

The two-node K3s Flannel proof owns VM and cluster lifecycle. It is an
automated harness case, not a manual example. Use the
[VM harness instructions](../../crates/mithril-e2e/harness/vm/README.md) for
that proof. This example does not create, select, retain, or destroy a VM.
