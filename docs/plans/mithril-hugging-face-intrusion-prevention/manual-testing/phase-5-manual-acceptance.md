# How To Manually Accept Phase 5

Status: Verified runbook for the qualified x86_64 network tier, including the
tested two-node K3s Flannel route.

Phase: [Process-Aware Network Plane](../phase-5-process-aware-network-plane.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md), with BPF LSM and a disposable
cgroup, plus the network-only two-node companion  
Closure: [Phase 5 closure matrix](../phase-5-closure-matrix.md)  
Runnable example: [Mithril network manual probe](../../../../examples/mithril-network-manual/README.md)

## Outcome

Prove current-actor and retained creator authority govern the advertised TCP
and UDP paths. Prove accepted-socket and cross-network-namespace transfers do
not widen authority. Prove the final destination remains authoritative after
the qualified rewrite. Prove delegated egress and token-read results stay
separate from provider receipt. Prove a whole-socket fence denies later use,
no later bytes reach the server, and final close releases the retained
generation reference. Keep DNS payload and TLS semantic results outside this
claim.

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

Run the bidirectional CNI companion when the network route, K3s harness, or
peer fixture changes:

```sh
crates/mithril-e2e/harness/vm/two-node-network.sh \
  --output-directory /tmp/mithril-network-two-node-review
```

## Procedure

1. Use a kernel-qualified x86_64 Linux host with cgroup v2, runtime BPF Type
   Format, BPF filesystem, and BPF Linux Security Module support.
2. Confirm that the probe pin root, lease, cgroup, and output paths do not
   exist. The runner rejects a pre-existing path.
3. Build the network binary as the workspace user. Run the example script as
   root so it can load BPF programs and create the probe cgroup.
4. Check that every Boolean physical oracle in
   `network-physical-probe.json` is `true`.
5. Check that the fixture array has the exact 13 allocated rows and that each
   row is `PASS`. Compare every row with the
   [closure matrix](../phase-5-closure-matrix.md).
6. Confirm that the script removed the pin root, owner lease, cgroup, and
   fixture directory. Only the JSON output directory remains.
7. For release qualification, run the complete VM harness. Confirm that it
   also passes the kernel, identity, effect-observation, and local-enforcement
   probes and destroys only its disposable VM.
8. Run the two-node companion. Confirm that Kubernetes reports exactly two
   Ready nodes with different boot identities and one peer Pod on each node.
9. Confirm that the source probe reaches the remote Pod IP through the Flannel
   CNI route in both directions. Allowed TCP and UDP must arrive. The denied
   port must have no peer receipt. All 13 fixture rows must pass in each
   direction.
10. Confirm that the harness removes its namespace, K3s installations, and
    both owned VMs. Do not remove an unrelated VM or ownership record.

## Allocated Fixture Matrix

The [closure matrix](../phase-5-closure-matrix.md) is authoritative for the
current terminal result and claim limit. Each stimulus below has a negative
oracle and a legitimate positive control in the physical probe.

| Fixture | Operator stimulus | Required physical oracle and control |
| --- | --- | --- |
| `FILE-DELEGATED-EGRESS-001` | send a request identity and final destination through the governed local proxy | the delegate denies the forbidden destination and the forbidden server receives nothing; the approved request reaches its server |
| `HF-004-RESULT-001` | run denied connect, allowed send, fenced send, and provider-write variants | each stage has a separate syscall or receipt result; no provider result is inferred from a network allow |
| `HF-011-READ-RESULT-001` | exercise zero, end-of-file, error, partial, mapped, inherited-descriptor, governed-read, and governed-map results | read, denied network, and provider receipt remain separate; no exfiltration result is inferred |
| `HF-NET-001` | exercise IPv4, IPv6, TCP, UDP, resolver destinations, and unrepresented families or protocols | signed paths succeed; denied destinations and unrepresented paths fail closed |
| `IPC-LOCAL-INET-008` | use local IPv4, IPv6, and Unix channels | Internet and Unix hooks retain separate policy owners; the declared relationships succeed |
| `NET-ACCEPT-PASS-001` | pass an accepted socket to a narrower actor and to an approved actor | the narrower actor cannot send or receive; the approved actor sends bytes that the client receives |
| `NET-DNS-EXFIL-001` | use port 53, an alternate resolver address, port 5353, and encrypted-resolver destination ports | the destination floor denies every tested resolver path; a signed non-DNS destination succeeds |
| `NET-NS-PASS-001` | duplicate a live accepted socket into actors in private network namespaces | the narrower actor cannot send; the approved actor sends, and evidence keeps distinct creator and current namespace identities |
| `NET-RECV-001` | receive on a signed connected socket and a passed socket held by a narrower actor | the signed receive succeeds; the narrower actor cannot receive |
| `NET-REWRITE-001` | install the probe-owned local-output DNAT rules for two documentation-range destinations | the policy mismatch denies the forbidden rewritten flow; the allowed rewritten flow reaches `127.0.0.4` |
| `NET-SHARED-RESPONSE-002` | retain an accepted socket in the accepter and approved receiver, then install a whole-socket fence | both holders cannot send and the client receives no post-fence bytes |
| `NET-SOCKCTL-001` | bind, listen, accept, set `TCP_NODELAY`, set `SO_MARK`, and shut down | represented safe controls succeed; `SO_MARK` fails; ordinary shutdown succeeds and fenced shutdown fails |
| `NET-SOCKET-LIFE-001` | create, clone, fork, inherit, close, reuse a descriptor, and create a new socket generation | live clones and inherited descriptors work; final close releases references; the new socket has a new generation |

## Encrypted-Channel Claim Limit

An approved and an out-of-profile operation can use the same legitimate TLS
process, token, destination, and channel. The kernel network plane can report
only the admitted channel activity. Only an authenticated server or provider
source can report the semantic operation and its result. Do not record a
kernel Layer 7 prevention result.

## Required Results And Pass Rule

Retain the network JSON result, platform record, socket and flow identity,
syscall results, server receipt, response-fence result, reference-release
result, and cleanup result. For the CNI companion, retain the two-node summary,
Kubernetes node inventory, both directional probe results, and both peer
results. The qualified tier passes only when all Boolean oracles are true, all
13 fixture rows have their expected terminal status in every required run, and
the probe-owned resources are absent after cleanup.

The pass rule applies only to the exact delegated-I/O, token-read,
accepted-socket, namespace-transfer, local-output DNAT, and
host-to-remote-Pod Flannel variants described above. A broader topology or
protocol needs its own negative oracle and legitimate positive control.

## Executed Acceptance Record

The current checked source passed the physical review on 2026-08-19. The
single-node Ubuntu 24.04 VM ran Linux `6.8.0-137-generic` on x86_64 with
cgroup v2, the BPF filesystem, runtime BPF Type Format, and BPF LSM active.
The identity, kernel-qualification, and both effect modes passed. The network
probe then passed all 13 fixture rows. Its result is in
`/tmp/mithril-phase5-simplify-single5-20260819/network-physical-probe.json`.
The probe removed its pin root, lease, cgroup, rewrite table, and fixture
paths. The harness destroyed the owned VM.

The two-node K3s `v1.35.5+k3s1` review reported two Ready nodes with distinct
boot identities. Node A reached Node B and Node B reached Node A through
Flannel. Each direction passed all 13 fixture rows, including exact TCP and
UDP payload receipt and denied-port absence. The results are in
`/tmp/mithril-phase5-simplify-two-node-20260819`. The harness removed the
namespace, both K3s installations, and both owned VMs.

## Troubleshooting

- A connect denial does not prove a packet-stage fence, and a packet drop does
  not prove a syscall denial. Record the actual boundary.
- If the packet hook lacks current-task context, use retained socket/flow state;
  never substitute a fictional task.
- Raw, TUN, AF_XDP, RDMA, vsock, SCTP, MPTCP, and other unadvertised paths
  fail closed and remain outside the qualified claim.
- The two-node result covers a host source and a remote peer Pod on K3s
  Flannel. Do not extend it to Pod-origin enforcement, another CNI, or a
  service mesh.
