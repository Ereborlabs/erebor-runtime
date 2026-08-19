# Phase 5 Closure Matrix

- Phase: [Process-Aware Network Plane](./phase-5-process-aware-network-plane.md)
- Architecture: [validated readable architecture](./policy-and-protection-algorithm-architecture-readable.md)
- Research basis: [Cilium and Tetragon network enforcement lessons](../../research/cilium-tetragon-network-enforcement-lessons.md)
- Manual acceptance: [Phase 5 runbook](./manual-testing/phase-5-manual-acceptance.md)
- Implementation review: [Phase 5 review guide](./phase-5-implementation-review.md)

## Closure Decision

Phase 5 is **Done for the qualified x86_64 single-host network tier**. The
current tier advertises destination policy for TCP sockets, retained creator
authority, current-actor intersection, selected socket controls, receive,
whole-socket response fences, and exact socket-reference release.

The physical result contains one terminal classification for all 13 allocated
fixtures:

- 8 fixtures are `PASS`.
- 5 fixtures are `UNSUPPORTED`.
- No fixture is `FAIL` or `DEGRADED`.

`PASS` means that the physical probe has an exact negative oracle, a legitimate
control, and the required lifecycle assertion. `UNSUPPORTED` means that the
operation is not part of this tier. A conservative denial does not turn an
unsupported capability into a positive support claim.

The tier does not advertise network-address rewrite qualification, cross-actor
accepted-socket transfer, cross-network-namespace positive authority,
delegated remote file I/O, token-to-egress causality, DNS payload inspection,
or TLS semantics.

## Deliverable Closure

| Deliverable | Closed result | Exact boundary |
| --- | --- | --- |
| `D5.1` | Created Internet sockets retain creator profile generation, socket generation, network namespace, peer, flow authorization, and response identity in kernel socket storage. Clone support follows the kernel socket lifetime. Release removes both creator and current-generation references. | The physical tier proves create, connected use, fence, close, and reference release. Cross-actor accept/pass and cross-network-namespace positive use remain unsupported. |
| `D5.2` | The policy model and BPF hooks cover Internet socket creation, destination lookup, connect, send, receive, selected controls, shutdown, bind, listen, and accept. Each supported use intersects current-actor and retained creator decisions. Unix sockets remain with the IPC owner. | The physical tier advertises TCP connect, send, receive, `TCP_NODELAY`, shutdown denial after a fence, and socket release. It does not advertise raw, packet, TUN, AF_XDP, RDMA, vsock, netlink, SCTP, MPTCP, or unrepresented asynchronous paths. |
| `D5.3` | A cgroup egress program reads retained socket state and has no dependency on a packet-stage current task. IPv4 and IPv6 TCP or UDP parsing, fragment closure, destination lookup, and response-floor lookup are implemented. | No rewrite chain was installed in the physical probe. NAT, CNI, mesh, redirect, route-change, and final rewritten-destination claims remain unsupported. |
| `D5.4` | The node can install a whole-socket response floor with insert-only semantics. Later socket operations intersect that floor. The physical probe proves that a later send and shutdown deny, no later bytes reach the server, and final close releases the socket reference. | The tier claims whole-socket scope. It does not claim per-lineage attribution for queued bytes, retransmits, or shared transport state. |
| `D5.5` | The selected `DENY_DNS_AND_USE_POLICY_RESOLVED_ADDRESSES` mode rejects any policy range that includes port 53. Destination policy remains independent of DNS payload content. | The tier has no DNS parser, qname, answer, CNAME, cardinality, DoT, DoH, or encrypted-protocol semantic claim. The alternate destination-only mode retains an explicit payload gap. |
| `D5.6` | The probe denies an unclassified destination before connect and proves an allowed signed loopback result service through connect, send, server receipt, and receive. | The tier does not infer an API verb, bearer purpose, token lineage, or provider result from an allowed TLS destination. Delegated I/O and token-read chains remain unsupported. |

## Appendix C Fixture Closure

| Fixture | Result | Physical proof and limit |
| --- | --- | --- |
| `FILE-DELEGATED-EGRESS-001` | `UNSUPPORTED` | Delegated remote file I/O has no qualified acquisition and remote-request oracle. Reason: `DELEGATED_REMOTE_FILE_IO_NOT_QUALIFIED`. |
| `HF-004-RESULT-001` | `PASS` | The probe keeps connect, send, packet path, and server receipt as separate results. The allowed server receives the approved bytes. No payload-semantic result is inferred. |
| `HF-011-READ-RESULT-001` | `UNSUPPORTED` | The probe does not bind a token read to a later network effect or provider result. Reason: `TOKEN_READ_CHAIN_NOT_PART_OF_NETWORK_PROBE`. |
| `HF-NET-001` | `PASS` | An unclassified loopback destination denies before connect. The signed result service connects, receives the approved bytes, and returns the application control byte. |
| `IPC-LOCAL-INET-008` | `PASS` | The qualified loopback IPv4 destination succeeds. Internet socket hooks leave Unix sockets with the existing IPC policy owner. This result does not advertise every local address family. |
| `NET-ACCEPT-PASS-001` | `UNSUPPORTED` | Accepted-socket state is implemented, but a physical cross-actor accept/pass positive and negative pair was not run. Reason: `CROSS_ACTOR_ACCEPT_PASS_PHYSICAL_PROBE_PENDING`. |
| `NET-DNS-EXFIL-001` | `PASS` | The selected policy-resolved-address mode cannot authorize port 53. The result is a destination-policy claim, not DNS payload inspection. |
| `NET-NS-PASS-001` | `UNSUPPORTED` | Socket state retains the network namespace, but the tier has no cross-namespace positive control. Reason: `CROSS_NETWORK_NAMESPACE_ALLOW_NOT_ADVERTISED`. |
| `NET-RECV-001` | `PASS` | A qualified connected TCP socket receives the server application byte under the creator and current-actor intersection. |
| `NET-REWRITE-001` | `UNSUPPORTED` | No NAT, CNI, mesh, redirect, or route-change chain was installed. Reason: `NO_REWRITE_CHAIN_INSTALLED_IN_SINGLE_HOST_PROBE`. |
| `NET-SHARED-RESPONSE-002` | `PASS` | A whole-socket fence inserts once, denies a later send and shutdown, and leaves the server without the post-fence bytes. No per-lineage queued-byte claim is made. |
| `NET-SOCKCTL-001` | `PASS` | `TCP_NODELAY` succeeds under the exact safe-control default. Unsupported options do not inherit this result. |
| `NET-SOCKET-LIFE-001` | `PASS` | Final socket close reduces the retained profile-generation socket reference to zero. File descriptor reuse does not own the socket state lifetime. |

## Physical Record

The disposable VM ran the repository VM harness against the current checked
source. The network result is retained at
`/tmp/mithril-phase5-vm-codex-013/network-physical-probe.json`.

The platform was x86_64 Linux `6.8.0-137-generic`, cgroup v2, BPF filesystem,
runtime BPF Type Format, and the active BPF Linux Security Module. Every
network Boolean oracle was `true`:

- the unclassified connect denied;
- the signed connect, send, receive, and safe socket control succeeded;
- the whole-socket fence installed;
- the post-fence send and shutdown denied;
- the server received no post-fence bytes; and
- final close released the socket reference.

The harness also ran the kernel, identity, effect-observation, local
enforcement, and network probes. It collected their JSON results, checked
cleanup, destroyed its disposable VM, and left an unrelated running VM
unchanged.

## Verification

The following checks passed after the last implementation edit:

```sh
cargo fmt --all -- --check
cargo clippy -p erebor-interceptor -p mithril-e2e --all-targets -- -D warnings
cargo test -p mithril-e2e --lib
bash .github/scripts/verify-rust-ci.sh
```

The complete repository CI script passed outside the restricted sandbox so
its localhost integration tests could bind sockets. The network runner also
passed in the disposable VM through the manual script and the full VM harness.

## Unadvertised Work

These items require a new qualification outcome before the product claim can
expand:

- a physical rewrite topology that proves the actual final address after NAT,
  CNI, mesh, redirect, and route changes;
- cross-actor accepted-socket transfer with an approved receiver control;
- cross-network-namespace positive authority and retained provenance;
- delegated remote file I/O and token-to-egress causality;
- a bounded DNS parser mode, if the product chooses to advertise payload
  policy; and
- broader protocols, asynchronous network paths, or semantic TLS controls.

Later evidence, detection, distributed response, or provider work cannot
convert one of these rows into a Phase 5 pass without its own physical proof.
