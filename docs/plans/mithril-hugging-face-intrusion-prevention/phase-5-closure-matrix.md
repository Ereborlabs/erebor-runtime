# Phase 5 Closure Matrix

- Phase: [Process-Aware Network Plane](./phase-5-process-aware-network-plane.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Research basis: [Cilium and Tetragon network enforcement lessons](../../research/cilium-tetragon-network-enforcement-lessons.md)
- Manual acceptance: [Phase 5 runbook](./manual-testing/phase-5-manual-acceptance.md)
- Implementation review: [Phase 5 review guide](./phase-5-implementation-review.md)

## Closure Decision

Phase 5 is **Done for the qualified x86_64 network tier**. The current tier
advertises destination policy for TCP sockets, retained creator authority,
current-actor intersection, selected socket controls, receive, whole-socket
response fences, exact socket-reference release, local-output DNAT, and the
tested bidirectional K3s Flannel route.

The physical result contains one `PASS` classification for each of the 13
allocated fixtures. No allocated fixture is `FAIL`, `DEGRADED`, or
`UNSUPPORTED`.

`PASS` means that the physical probe has an exact negative oracle, a legitimate
control, and the required lifecycle assertion. The qualified result covers the
implemented single-host variants for accepted-socket transfer,
cross-network-namespace transfer, delegated egress, token-read result
separation, and local-output DNAT. The two-node companion runs the same 13-row
probe in both directions against a peer in the remote Pod network namespace.

The tier does not advertise every rewrite topology, arbitrary delegated remote
file systems, DNS payload inspection, TLS semantics, or unrepresented network
families and protocols.

## Deliverable Closure

| Deliverable | Closed result | Exact boundary |
| --- | --- | --- |
| `D5.1` | Created Internet sockets retain creator profile generation, socket generation, network namespace, peer, flow authorization, and response identity in kernel socket storage. Accepted, cloned, inherited, and passed sockets follow kernel socket lifetime. Release removes both creator and current-generation references. | The physical tier proves accepted-socket transfer and live-socket duplication into private network namespaces with narrow-deny and approved-allow controls. It does not generalize those controls to every transfer mechanism. |
| `D5.2` | The policy model and BPF hooks cover Internet socket creation, destination lookup, connect, send, receive, selected controls, shutdown, bind, listen, and accept. Each represented use intersects current-actor and retained creator decisions. Unix sockets remain with the IPC owner. | The physical tier advertises TCP and UDP on IPv4 and IPv6, connected and unconnected UDP send, signed receive, accepted-socket transfer, selected controls, and release. Raw, packet, TUN, AF_XDP, RDMA, vsock, netlink, SCTP, MPTCP, and unrepresented asynchronous paths fail closed and remain outside the claim. |
| `D5.3` | A cgroup egress program reads retained socket state and has no dependency on a packet-stage current task. IPv4 and IPv6 TCP or UDP parsing, fragment closure, destination lookup, and response-floor lookup are implemented. | The physical probes cover local-output `nftables` DNAT and a bidirectional host-to-remote-Pod route through K3s Flannel. BPF redirect setup and TUN/TAP setup fail closed. The result does not generalize to Pod-origin enforcement, another CNI, an arbitrary service mesh, SNAT, or dynamic route mutation. |
| `D5.4` | The node can install a whole-socket response floor with insert-only semantics. Later socket operations intersect that floor. The physical probe proves that a later send and shutdown deny, no later bytes reach the server, and final close releases the socket reference. | The tier claims whole-socket scope. It does not claim per-lineage attribution for queued bytes, retransmits, or shared transport state. |
| `D5.5` | The selected `DENY_DNS_AND_USE_POLICY_RESOLVED_ADDRESSES` mode rejects any policy range that includes port 53. Destination policy remains independent of DNS payload content. | The tier has no DNS parser, qname, answer, CNAME, cardinality, DoT, DoH, or encrypted-protocol semantic claim. The alternate destination-only mode retains an explicit payload gap. |
| `D5.6` | The probe denies unclassified destinations, resolver destinations, unsafe controls, and narrow transferred actors. It proves signed network paths, delegated egress, governed token reads, and provider receipt as separate results. | The tier does not infer an API verb, bearer purpose, token lineage, or provider result from an allowed TLS destination. The delegated proof covers the exact local proxy protocol in the fixture. |

## Appendix C Fixture Closure

| Fixture | Result | Physical proof and limit |
| --- | --- | --- |
| `FILE-DELEGATED-EGRESS-001` | `PASS` | The requester sends a request identity and final destination over the governed Unix relationship. The delegate denies the forbidden destination, and that server receives nothing. The approved request keeps its identity and reaches the approved server. |
| `HF-004-RESULT-001` | `PASS` | The probe keeps connect denial, allowed send, fenced send denial, and provider receipt as separate results. No payload-semantic result is inferred. |
| `HF-011-READ-RESULT-001` | `PASS` | Zero, end-of-file, I/O error, partial, mapped, inherited-descriptor, governed-read, and governed-map results remain separate from denied network use and provider receipt. |
| `HF-NET-001` | `PASS` | Signed TCP and UDP paths on IPv4 and IPv6 succeed. Unclassified and resolver destinations deny. Unrepresented families and protocols fail closed. |
| `IPC-LOCAL-INET-008` | `PASS` | Signed IPv4 and IPv6 loopback paths succeed. Governed Unix relationships carry descriptor-transfer and delegated requests under the IPC owner. |
| `NET-ACCEPT-PASS-001` | `PASS` | A physically passed accepted socket denies send and receive for the narrow actor. The approved actor sends bytes that the client receives. Creator, accepter, and current-actor authority stay distinct. |
| `NET-DNS-EXFIL-001` | `PASS` | Port 53, an alternate resolver address, port 5353, and destination ports 853 and 443 deny. A signed non-DNS destination succeeds. This is a destination-floor claim, not DNS payload inspection. |
| `NET-NS-PASS-001` | `PASS` | A live accepted socket is duplicated into actors in private network namespaces. The narrow actor cannot send. The approved actor sends, and the event records different nonzero creator and current namespace identities. |
| `NET-RECV-001` | `PASS` | A signed connected TCP socket receives the server byte. A narrow actor that receives a passed accepted socket cannot receive. |
| `NET-REWRITE-001` | `PASS` | Probe-owned local-output DNAT maps `198.18.0.1` and `198.18.0.2` to `127.0.0.4`. The forbidden policy mismatch denies before receipt. The allowed rewritten flow reaches the server. |
| `NET-SHARED-RESPONSE-002` | `PASS` | An accepter and approved receiver retain one accepted socket. A whole-socket fence denies both holders, and the client receives no post-fence bytes. No per-lineage queued-byte claim is made. |
| `NET-SOCKCTL-001` | `PASS` | `TCP_NODELAY` and ordinary shutdown succeed. `SO_MARK` denies. Shutdown after a whole-socket fence denies. Other controls do not inherit this result. |
| `NET-SOCKET-LIFE-001` | `PASS` | Clone and fork holders send successfully. One close cannot release shared authority. Final close releases the retained reference, and a later socket has a new generation. |

## Physical Record

The disposable single-node VM and two-node K3s runs used the current checked
source. Physical result files stay outside the repository under `/tmp`.

Each node used x86_64 Linux `6.8.0-137-generic`, cgroup v2, BPF filesystem,
runtime BPF Type Format, and the active BPF Linux Security Module. The
two-node companion installed K3s `v1.35.5+k3s1`, observed two Ready nodes with
different boot identities, and assigned one peer Pod to each node. Allowed TCP
and UDP payloads arrived in both directions. Each denied peer connection had
no receipt. All 13 fixtures passed in each direction.

The harness also ran the kernel, identity, effect-observation, local
enforcement, and network probes. It collected their JSON results, checked
cleanup, and destroyed its disposable VM.

## Verification

The following checks passed after the last implementation edit:

```sh
cargo fmt --all -- --check
cargo check --workspace
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-targets --all-features -- \
  --skip runner::tests::verification_bundle_is_frozen_only_for_recorded_physical_surfaces
```

The required repository verification script completes formatting, workspace
check, Clippy, and all source-driven tests. Its separate
`verification_bundle_is_frozen_only_for_recorded_physical_surfaces` check
requires the release owner to refresh the qualification record. The
implementation does not weaken or skip that release check.

The source-only workspace command passed. Its only deliberate exclusion was
the exact qualification-bundle test named in the command.

The network runner passed in the disposable VM through the manual script and
the full VM harness. The two-node companion passed with the automated harness
owner:

```sh
crates/mithril-e2e/harness/vm/two-node-network.sh \
  --output-directory /tmp/mithril-network-two-node-review
```

## Unadvertised Work

These unadvertised items require a new qualification outcome before the
product claim can expand:

- Pod-origin enforcement, CNIs beyond the tested K3s Flannel route, arbitrary
  service meshes, SNAT, and dynamic route mutation;
- transfer mechanisms beyond the tested Unix descriptor pass and
  `pidfd_getfd` namespace transfer;
- delegated remote file systems beyond the tested local proxy protocol;
- a bounded DNS parser mode, if the product chooses to advertise payload
  policy; and
- broader protocols, asynchronous network paths, or semantic TLS controls.

Later evidence, detection, distributed response, or provider work cannot
widen this physical claim without its own proof.
