# Mithril Network Enforcement Manual Probe

This example runs the Phase 5 single-host physical probe. It loads the real
Mithril BPF programs, creates a dedicated cgroup, installs a signed destination
policy, and moves one managed child into that cgroup.

The probe proves these results:

- an unclassified TCP connect is denied before the effect;
- an allowed loopback TCP connect, send, receive, and `TCP_NODELAY` operation
  succeed;
- the server receives the allowed bytes;
- a whole-socket response fence denies a later send and shutdown;
- the server does not receive the post-fence bytes;
- final socket release removes the retained policy-generation reference.

The probe does not install a network rewrite chain or move a socket between
actors or network namespaces. It reports those fixture cases as unsupported.
It selects the policy-resolved-address DNS mode. In this mode, the policy does
not authorize port 53 and does not claim DNS payload inspection.

## Run

Use a kernel-qualified Linux host with BPF LSM enabled. Build as the normal
workspace user, then run only the physical probe as root:

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

Every Boolean physical oracle must be `true`. The fixture list records `PASS`
only for behavior exercised by this probe. An `UNSUPPORTED` result is a closed
claim, not a passed physical test.

