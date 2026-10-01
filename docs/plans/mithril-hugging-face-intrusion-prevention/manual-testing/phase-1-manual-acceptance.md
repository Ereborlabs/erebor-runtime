# How To Manually Accept Phase 1

Status: Implemented companion checks; run the privileged Host lifecycle test on each supported physical host.

Phase: [One-Binary Node Chassis](../phase-1-one-binary-node-chassis.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md)

## Outcome

Prove one shared Interceptor owner, one `mithril-node`, one authenticated
`mithril-control`, truthful readiness, and Runtime coexistence without exposing
an effect-prevention claim.

## Automated Companion

```bash
cargo test -p erebor-interceptor -p erebor-runtime-ipc \
  -p erebor-runtime-client -p mithril-control -p mithril-node -p mithril-e2e \
  --all-targets --all-features
cargo test -p mithril-e2e --lib --no-run
```

Copy the test executable from the build output to the prepared VM. Set
`MITHRIL_TEST_BIN` in `/var/tmp/mithril-manual.env` to that executable.
Install `clang` and libbpf development headers in the VM. In a root shell,
run:

```bash
. /var/tmp/mithril-manual.env
env MITHRIL_TEST_OUTPUT=/var/tmp/mithril-clean-host \
  MITHRIL_TEST_PIN=/sys/fs/bpf/mithril-clean-host \
  MITHRIL_TEST_LEASE=/var/tmp/mithril-clean-host/owner.lock \
  MITHRIL_TEST_CGROUP=/sys/fs/cgroup/mithril-clean-host \
  "$MITHRIL_TEST_BIN" \
  identity::scenarios::clean_host::clean_host_restarts::identity_physical_host \
  --exact --ignored --nocapture --test-threads=1
```

The [standard Host test](../../../../crates/mithril-e2e/src/identity/scenarios/clean_host.rs)
uses the production `KernelHostOwner` and the original qualification object.
It requires an absent pin root, pinned maps and links, live manifest readback,
same-root rejection, exact lease rejection, and pin removal after each of two
shutdowns. It also verifies the unchanged worker fixture digest. It removes
only its temporary paths. This kernel-only test does not start Node or Control.

## Procedure

1. Install the Phase 1 development artifacts on a clean node.
2. Read back the pin-root lease, programs, links, maps, ABI, boot epoch,
   capability report, and readiness state.
3. Connect node and Control with valid mTLS, then exercise wrong identity,
   replay, sequence gap, outage, and reconnect variants.
4. Start Runtime-only, Mithril-only, and co-resident modes in separate runs.
5. Attempt a second loader and a stale/partial attach in each relevant mode.
6. Start, restart, and stop the unchanged worker while checking that no local
   prevention claim is exposed.

## Fixture And Manual-Test Matrix

| Test | Operator action | Required oracle and legitimate control |
| --- | --- | --- |
| `BOOT-ADMISSION-001` | race protected workload admission against incomplete node readiness | strict admission does not claim protection before complete readback; after readiness the unchanged worker starts |
| `SOURCE-KA-PARTIAL-ATTACH-001` rerun | inject one failed required attach | node is not ready and exposes no partial capability; clean complete attach succeeds |
| `SOURCE-KA-CAPACITY-005` rerun | start at declared map/link capacity and attempt N+1 | readiness/health reports exact exhaustion; existing owner state remains intact |
| exclusive owner | attempt Runtime and Mithril loaders against the same pin root | exactly one acquires the lease; loser cannot attach or mutate maps |
| stale pins | restart with stale/mismatched pinned objects | restart refuses readiness until exact recovery or explicit removal; valid matching restart succeeds |
| ABI/program mismatch | install one mismatched C/Rust ABI or program digest | readiness remains false; matching artifact set succeeds |
| mTLS wrong CA/node | connect using wrong CA, tenant, or node identity | registration rejects; valid run-scoped identity connects |
| expired/replayed registration | reuse expired identity or registration envelope | rejection is explicit; fresh identity/sequence registers once |
| stream sequence gap | drop, reorder, and duplicate control messages | gap/replay is detected; monotonic valid stream continues |
| Control outage | disconnect Control after a valid chassis state | no invented healthy control state; reconnect uses a new stream sequence without reusing boot identity |
| Runtime coexistence | subscribe through the cgroup-scoped Runtime client | in-scope observation works; loader, role, policy, exception, and response mutations reject |
| packaging lifecycle | start/restart/stop the one-container node package | one node process and clean link/map ownership throughout; ordinary worker lifecycle succeeds |

## Required Artifacts And Pass Rule

Retain install manifest, process inventory, lease/readback reports, mTLS
transcripts without secrets, registration/sequence results, Runtime scope
results, lifecycle logs, and unchanged-workload digest. Pass requires exactly
one loader/raw reader and truthful readiness in every tested mode.

## Troubleshooting

- If an old test owner holds the pin root, stop and identify that exact owner;
  never bypass the lease.
- If Control is down, distinguish installed local chassis health from missing
  Control-owned admission/trust state.
- If packaging needs a second privileged helper, Phase 1 is not complete.
