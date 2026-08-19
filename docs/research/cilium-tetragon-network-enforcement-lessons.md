# Cilium And Tetragon Network-Enforcement Lessons

## Purpose

This document records network-enforcement lessons from the local Cilium and
Tetragon source trees. It applies those lessons to the Mithril process-aware
network plane. It does not make either project a Mithril policy authority.

This study covers source structure, state ownership, hook placement, socket
lifetime, address rewrite, DNS handling, response, capability checks, and
physical tests. No Cilium or Tetragon code was copied or derived for this
study. Both source trees have an Apache-2.0 repository license. Individual BPF
files also contain GPL-2.0-only or BSD-2-Clause notices. A later adoption must
pass the repository upstream-adoption gate before implementation.

## Sources Examined

The study used these local source areas:

- Cilium socket hooks and reverse translation:
  `cilium/bpf/bpf_sock.c` and `cilium/bpf/lib/sock.h`.
- Cilium packet policy and connection tracking:
  `cilium/bpf/bpf_lxc.c`, `cilium/bpf/lib/policy.h`, and
  `cilium/bpf/lib/conntrack.h`.
- Cilium socket destruction and capability checks:
  `cilium/bpf/bpf_sock_term.c` and
  `cilium/pkg/datapath/sockets/`.
- Cilium socket-program lifecycle:
  `cilium/pkg/socketlb/socketlb.go` and
  `cilium/pkg/socketlb/cgroup.go`.
- Cilium DNS policy:
  `cilium/pkg/fqdn/dnsproxy/`.
- Cilium BPF tests:
  `cilium/bpf/tests/network_policy.c`,
  `cilium/bpf/tests/tc_lxc_policy_drop.c`,
  `cilium/bpf/tests/destroy_sock_socket_lb.c`, and
  `cilium/bpf/tests/host_only_socket_lb_test.c`.
- Tetragon socket extraction and userspace decoding:
  `tetragon/bpf/process/types/sock.h`,
  `tetragon/bpf/process/types/socket.h`,
  `tetragon/bpf/process/types/sockaddr.h`,
  `tetragon/bpf/process/types/tuple.h`, and
  `tetragon/pkg/reader/network/`.
- Tetragon socket tracking:
  `tetragon/bpf/process/types/basic.h`,
  `tetragon/bpf/process/generic_calls.h`, and
  `tetragon/pkg/sensors/tracing/consts.go`.
- Tetragon generic LSM enforcement:
  `tetragon/bpf/process/bpf_generic_lsm_core.c`, its output path, and
  `tetragon/pkg/sensors/tracing/genericlsm.go`.
- Tetragon network examples:
  `tetragon/examples/quickstart/network_egress_cluster_enforce.yaml`,
  `tetragon/examples/policylibrary/security-socket-connect-block-others.yaml`,
  `tetragon/examples/policylibrary/dns-only-specified-servers.yaml`, and the
  datagram socket-tracking examples.

The source paths are evidence for this study. They are not build inputs for
Mithril.

## Required Mithril Ownership

The source study supports the existing Mithril ownership split:

```text
signed policy generation
        |
        v
mithril-node -------------------- owns semantic validation and publication
        |
        v
Erebor Interceptor loader ------- owns load, attach, read-back, and recovery
        |
        v
Mithril BPF programs ------------ own pre-effect decisions and retained state
        |
        +-----------> socket actor-stage decision
        |
        +-----------> final packet destination floor
        |
        v
mithril-e2e --------------------- owns syscall, server, packet, and control proof
```

The loader must not decide policy. Packet code must not infer a current actor
when the hook does not have reliable task context. Userspace must not report a
denial until the physical oracle proves the claimed boundary.

## Cilium Lessons

### Split Hook Coverage By Effect

`cilium/bpf/bpf_sock.c` uses separate cgroup programs for IPv4 and IPv6
connect, send-message, receive-message, peer-name, bind, post-bind, and socket
release events. This split is important because one hook does not cover the
complete socket lifetime. In particular, a connect hook does not govern later
TCP packets, and a datagram send hook does not govern established TCP sends.

Mithril must define the exact effect for each hook. It must state whether the
hook denies a syscall, prevents a state transition, or drops a packet. A
successful test at one hook cannot qualify another hook.

### Use Stable Socket State, Then Remove It At Lifetime End

Cilium uses the kernel socket cookie as part of reverse-translation state. It
also removes state from its release path. The cookie avoids file-descriptor
identity, which is process-local and reusable. Release cleanup limits stale
state after socket destruction.

Mithril needs a stronger authority record than Cilium reverse translation. A
Mithril socket record must also include a birth generation, creator policy
generation, network namespace identity, family, type, protocol, destination or
flow generation, and response state. A cookie without a live-interval check is
not enough. Map insertion failure or missing state must fail closed for a
managed actor. An LRU eviction must never widen authority.

### Enforce The Post-Rewrite Destination

`cilium/bpf/bpf_lxc.c` applies service translation before it resolves the
destination security identity and runs egress policy. It then stores
connection state only after the decision permits the flow. This order prevents
a service address from hiding the selected backend from packet policy.

Mithril must keep the actor-stage requested destination and the packet-stage
final destination as separate facts. The packet floor must check the final
IPv4 or IPv6 destination after the qualified rewrite stages. The activation
path must inventory and read back the actual cgroup, traffic-control, CNI, NAT,
mesh, and redirect order. An unknown or changed order is an admission failure
for a strict network profile.

Cilium has valid product-specific shortcuts, including selected hairpin and
reply-path behavior. Mithril must not copy them without proving its own actor,
local-peer, and response contracts.

### Retain Only State That Has A Clear Lifetime

Cilium connection tracking retains protocol state, timeouts, reverse
translation, proxy state, and source identity. The implementation contains
explicit update and race handling. This is useful evidence that packet policy
needs retained flow state. It is not evidence that an unbounded or implicit
flow lifetime is safe.

Mithril flow state must name its creator socket generation, policy generation,
network namespace, tuple, protocol, direction, final destination, and response
generation. Creation must follow an allowed actor-stage decision. Retirement
must happen on close, timeout, policy retirement, namespace teardown, or
response. Unknown state and capacity failure must have a signed fail-closed
result.

### Treat Response As A Physical Operation

`cilium/bpf/bpf_sock_term.c` and `cilium/pkg/datapath/sockets/` show two useful
response patterns. One uses a BPF iterator and `bpf_sock_destroy`. The other
uses socket diagnostics as a fallback. The capability probe creates real TCP
and UDP sockets, finds them, destroys them, and checks kernel support.

Mithril must use the same proof discipline, but it needs a different semantic
contract. A shared socket or flow has one physical response scope. If several
lineages share it, response affects the complete socket, flow, or cgroup. The
system must disclose that blast radius before authorization. It must not claim
that queued bytes or retransmits belong to one current lineage. Socket
destruction is a response action; packet absence is the result oracle.

### Attach A Complete Program Set As One Generation

Cilium socket-program management loads a collection, attaches the selected
hook matrix, pins links, and commits after attachment succeeds. It also handles
defunct pins and uses atomic link updates where the kernel supports them.

Mithril must publish its actor, socket, packet, DNS, and response state as one
policy generation. Preparing state must not authorize traffic. Activation must
read back every required map and link. Recovery must reject a partial hook set,
an old program, an unexpected pin, or mixed generation state.

### DNS Is A Separate Parser And Policy Problem

Cilium DNS proxy policy combines endpoint identity, resolver destination,
transport, destination identity, query name, and policy rules. It preserves
UDP or TCP transport, bounds concurrency and time, and keeps restored rules
separate until live initialization. These are useful lifecycle and default-deny
patterns.

The helper in `cilium/pkg/fqdn/dnsproxy/helpers.go` selects the first DNS
question after it checks that a question exists. Mithril must not use that
behavior as proof for a multi-question message. The Phase 5 claim requires
bounded parsing and an explicit result for zero, one, and multiple questions;
compression loops; truncation; TCP framing; fragments; long labels; CNAME
chains; answer count; message size; rate; and cardinality.

DNS names are evidence. The final IP destination remains an independent
enforcement floor. Direct DNS-over-TLS and DNS-over-HTTPS content is encrypted,
so Mithril can govern the destination but cannot claim the query name.

### Test The Denial, Its Negative Case, And A Legitimate Control

Cilium BPF tests assert default denial, explicit allow, drop counters, exact
socket selection, non-matching socket survival, and network-namespace
distinctions. The socket-destruction probe also checks the actual destroyed
socket rather than a userspace intention.

Each Mithril network fixture needs the same three parts:

1. The forbidden effect has the declared syscall, state, server, or packet
   result.
2. A close negative case proves that a nearby socket, namespace, destination,
   or flow was not selected.
3. A legitimate control proves that the hook did not break all traffic.

## Tetragon Lessons

### Keep Requested And Live Socket Addresses Distinct

Tetragon extracts both `sockaddr` data supplied to a socket operation and
fields from the live kernel `sock`. Its readers handle address families,
protocol, state, local and remote addresses, ports, and byte order. These are
different facts: `sockaddr` describes a request, while `sock` describes kernel
state.

Mithril must preserve the requested address, retained socket destination, and
final packet tuple separately. A test must not substitute one for another.

### Socket Tracking Is Useful Evidence, But Not Authority

Tetragon `TrackSock` stores creator process data and a timestamp under a kernel
socket pointer. `UntrackSock` removes the entry. This demonstrates why a
datagram packet hook may need state captured at socket allocation.

The Tetragon documentation and implementation also show the limits. The map is
an LRU hash, so capacity pressure can evict entries. A shared socket continues
to report its creator even after another process receives it or the creator
exits. A raw pointer can also be reused unless the lifetime is verified.

Mithril must therefore reject creator-only attribution, raw-pointer identity
without a birth generation, and LRU eviction as an authorization rule. A use
is allowed only when the current actor decision intersects the retained socket
authority. Packet enforcement uses the retained authorized flow, not a claim
that the creator is the current sender.

### Hook Names And Available Context Change Across Kernels

The Tetragon datagram examples use different tracking and packet paths for
different kernel versions. This makes hook drift visible. A generic policy
example is not a capability manifest.

Mithril must qualify each supported kernel and runtime combination with the
loaded BTF signature, helper availability, attach result, hook order, state
fields, denial timing, and physical oracle. Unsupported kernels must stay out
of strict admission. They must not silently use a weaker hook.

### Generic Enforcement Is Not A Complete Network Plane

The Tetragon examples can observe `tcp_connect`, enforce at
`security_socket_connect`, or terminate a process from an output path. These
are useful probes, but they have different physical meanings. A signal after
an event is not a pre-packet denial. A TCP connect probe does not cover UDP,
established TCP traffic, shared sockets, or final rewritten destinations.

Mithril must keep the LSM return chain intact and preserve an earlier kernel
denial. It must also bind every program to one declared operation and result.
Generic tracing is evidence only when the exact hook and timing qualify the
claimed effect.

## Phase 5 Application Decisions

| Area | Use from the study | Mithril-specific rule |
| --- | --- | --- |
| Socket identity | Capture state at socket birth and clean it at release. | Add a non-reusable birth generation and fail closed on missing managed state. |
| Actor decision | Use request-time socket hooks for task context. | Intersect the current actor with retained creator and policy authority. |
| Local channels | Retain exact peer and namespace facts. | Resolve IPv4, IPv6, and Unix peers in the live namespace; independent roots do not merge. |
| Final flow | Check policy after address translation. | Packet code uses an authorized retained flow and the final tuple; it does not invent a current task. |
| Established traffic | Retain connection state with an explicit lifetime. | Fence future packets on response and state the whole shared-flow blast radius. |
| DNS | Bound parsing, concurrency, and state. | Reject or explicitly classify multiple questions and parser failures; always apply the resolver and final-IP floor. |
| Recovery | Attach and read back a complete program set. | Mixed generations, incomplete hooks, stale pins, and unknown order fail admission. |
| Proof | Use physical sockets and packets with close controls. | Record syscall, socket state, server receipt, packet counter or capture, and the legitimate control separately. |

## Required Fixture Consequences

The Phase 5 fixtures must prove these specific consequences:

- `NET-SOCKET-LIFE-001` checks creation, acceptance, inheritance, descriptor
  passing, preconnection, close, and reuse without stale authority.
- `NET-ACCEPT-PASS-001` and `NET-NS-PASS-001` prove that current actor and
  retained socket or namespace authority both remain restrictive.
- `IPC-LOCAL-INET-008` resolves each local IPv4, IPv6, and Unix peer in the
  live namespace and uses the signed unmatched result when resolution fails.
- `NET-REWRITE-001` records the requested and final tuples and proves that a
  forbidden post-rewrite destination receives no packet.
- `NET-SHARED-RESPONSE-002` discloses one physical response scope and proves
  future packet absence without false per-lineage attribution.
- `NET-DNS-EXFIL-001` covers UDP and TCP framing, compression, malformed and
  multi-question messages, non-standard ports, direct IP, alternate resolver,
  DNS-over-TLS, and DNS-over-HTTPS. Parser failure cannot bypass the IP floor.
- `NET-SOCKCTL-001` and `NET-RECV-001` report the exact supported hook and
  syscall or data oracle. An unsupported path narrows the claim.
- `FILE-DELEGATED-EGRESS-001`, `HF-004-RESULT-001`,
  `HF-011-READ-RESULT-001`, and `HF-NET-001` keep local acquisition, send,
  packet emission, remote receipt, and provider results as separate facts.

## Qualification Gates

The implementation is not complete until physical qualification answers all
of these questions:

- Which exact hooks cover TCP connect, established TCP packets, connected and
  unconnected UDP, receive, socket controls, accept, release, and final egress?
- Which hooks have trustworthy current-task context, and which must use only
  retained socket or flow state?
- What is the observed order of socket policy, CNI, service translation, NAT,
  mesh redirect, traffic control, and the final packet floor?
- What happens when every authoritative map reaches capacity or an update
  fails?
- How does policy generation retirement remove socket, flow, DNS, and response
  authority without a reuse window?
- Which kernel and runtime combinations support a pre-effect denial, a packet
  drop, socket destruction, and an authoritative packet-absence oracle?
- Which encrypted paths expose only destination metadata, and which separate
  authenticated provider source can prove the semantic operation?

An unanswered gate is an unsupported or blocked claim. It is not an inferred
success.
