# How To Manually Accept Phase 5

Status: Verified runbook for the qualified x86_64 single-host network tier.

Phase: [Process-Aware Network Plane](../phase-5-process-aware-network-plane.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md), with BPF LSM and a disposable
cgroup
Closure: [Phase 5 closure matrix](../phase-5-closure-matrix.md)  
Runnable example: [Mithril network manual probe](../../../../examples/mithril-network-manual/README.md)

## Outcome

Prove current-actor and retained creator authority govern the advertised TCP
socket path. Prove a whole-socket fence denies later use, no later bytes reach
the server, and final close releases the retained generation reference. Keep
rewrite, cross-actor, cross-namespace, DNS payload, and TLS semantic results
outside this claim.

## Automated Companion

```sh
cargo build -p mithril-e2e --bin mithril-network-test
sudo examples/mithril-network-manual/run-network-probe.sh
```

Run the complete disposable-VM companion when the source, BPF object, kernel
qualification record, or harness changes:

```sh
crates/mithril-e2e/harness/vm/run.sh \
  --output-directory /tmp/mithril-network-vm-review
```

## Procedure

1. Use a kernel-qualified x86_64 Linux host with cgroup v2, runtime BPF Type
   Format, BPF filesystem, and BPF Linux Security Module support.
2. Confirm that the probe pin root, lease, cgroup, and output paths do not
   exist. The runner rejects a pre-existing path.
3. Build the network binary as the workspace user. Run the example script as
   root so it can load BPF programs and create the probe cgroup.
4. Check that all ten Boolean fields in `network-physical-probe.json` are
   `true`.
5. Check that the fixture array has eight `PASS` rows and five exact
   `UNSUPPORTED` rows. Compare every row with the
   [closure matrix](../phase-5-closure-matrix.md).
6. Confirm that the script removed the pin root, owner lease, cgroup, and
   fixture directory. Only the JSON output directory remains.
7. For release qualification, run the complete VM harness. Confirm that it
   also passes the kernel, identity, effect-observation, and local-enforcement
   probes and destroys only its disposable VM.

## Allocated Fixture Matrix

The [closure matrix](../phase-5-closure-matrix.md) is authoritative for the
current terminal result and claim limit. The stimuli below also describe the
future positive controls required for rows that are now unsupported.

| Fixture | Operator stimulus | Required physical oracle and control |
| --- | --- | --- |
| `FILE-DELEGATED-EGRESS-001` | use remote filesystem/local proxy/delegated I/O | acquisition is governed as egress and forbidden remote request is absent; approved remote object succeeds |
| `HF-004-RESULT-001` | run connect allowed/denied, send allowed/failed, packet emitted, and provider-write variants | each stage has exact result; payload unobservable unless authorized content oracle exists |
| `HF-011-READ-RESULT-001` | chain token read variants to failed send, emitted packet, and provider write | read/output/provider results stay separate; no inferred exfiltration |
| `HF-NET-001` | attempt API/IMDS/C2/alternate-resolver traffic from worker | forbidden connect/send/packet physically absent; approved result/controller traffic works |
| `IPC-LOCAL-INET-008` | use loopback, Pod IP, Unix, local IPv4/IPv6 channels | exact peer relationship or configured unmatched result; declared peer succeeds |
| `NET-ACCEPT-PASS-001` | accept then pass/use socket from narrower actor | creator/accepter/current-actor intersection prevents laundering; approved receiver works |
| `NET-DNS-EXFIL-001` | send bounded/malformed/compressed/multi-question/long/split/TCP/non-53/DoT/DoH/IP variants | forbidden query/destination gets no accepted packet; parser failure still hits IP floor; approved DNS works |
| `NET-NS-PASS-001` | pass/inherit socket across network namespaces | retained namespace/provenance remains authoritative; current namespace cannot widen egress |
| `NET-RECV-001` | receive on qualified and unqualified socket paths | advertised receive restriction has syscall/data oracle; unsupported path is explicit |
| `NET-REWRITE-001` | route through DNAT/SNAT/CNI/mesh/redirect/route-change variants | final post-rewrite forbidden destination receives no packet; allowed rewritten destination works |
| `NET-SHARED-RESPONSE-002` | share established socket/queued bytes across lineages, then respond | whole socket/flow/cgroup scope is disclosed and fenced; no false per-lineage queued-byte result |
| `NET-SOCKCTL-001` | bind/listen/accept/shutdown/setsockopt attempts | forbidden control changes no socket state; approved operation reads back |
| `NET-SOCKET-LIFE-001` | create/accept/inherit/pass/preconnect/reuse/destroy sockets | old state cannot attach to reused fd/cookie/live interval; valid live socket works |

## Encrypted-Channel Claim Limit

An approved and an out-of-profile operation can use the same legitimate TLS
process, token, destination, and channel. The kernel network plane can report
only the admitted channel activity. Only an authenticated server or provider
source can report the semantic operation and its result. Do not record a
kernel Layer 7 prevention result.

## Required Artifacts And Pass Rule

Retain the network JSON result, platform record, socket and flow identity,
syscall results, server receipt, response-fence result, reference-release
result, and cleanup result. The qualified tier passes only when all Boolean
oracles are true, all 13 fixture rows have their expected terminal status, and
the probe-owned resources are absent after cleanup.

A rewrite, cross-actor, cross-namespace, delegated-I/O, token-chain, or DNS
payload experiment needs its own negative oracle and legitimate positive
control. It cannot widen this runbook's pass rule.

## Troubleshooting

- A connect denial does not prove a packet-stage fence, and a packet drop does
  not prove a syscall denial. Record the actual boundary.
- If the packet hook lacks current-task context, use retained socket/flow state;
  never substitute a fictional task.
- Unsupported raw/TUN/AF_XDP/RDMA/vsock/SCTP/MPTCP paths narrow the claim.
