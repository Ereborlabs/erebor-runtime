# Phase 5: Process-Aware Network Plane

Status: Not started.

Master plan: [Mithril Hugging Face Intrusion Prevention](./README.md)

## Purpose

Provide CNI-independent, process-role-aware network decisions for new socket
effects and a packet-level fence for established traffic, without TLS
interception or false application-operation semantics.

## Depends On

Phase 4 must be `Done`, including exact task roles, signed local generations,
physical denial postconditions, and approved performance budgets.

## Phase Scope

### Socket Decision Programs

Add and test the Phase 0-selected combination of:

- BPF LSM `socket_create`, `socket_connect`, `socket_bind`,
  `socket_listen`, `socket_accept`, and `socket_sendmsg` context where
  available;
- cgroup v2 IPv4/IPv6 `connect`, `bind`, and UDP `sendmsg` programs;
- use-time checks for inherited and passed sockets;
- socket-local BPF storage carrying creator and current-user lineage;
- DNS observation and resolver coverage;
- cgroup-skb or TC packet enforcement for established flows; and
- explicit denial/coverage for raw/packet sockets, TUN/TAP, AF_XDP, and
  BPF-based redirection.

The task-context path decides process-role effects. The packet path enforces
socket/cgroup state when no reliable current task exists. One mechanism does not
silently substitute for the other.

### Destination And Socket Identity

The policy owner compiles live destination classes from authoritative
configuration and inventory:

```text
kubernetes API:
  in-cluster Service IP
  every private/public control-plane address
  node-local proxy addresses
  IPv4 and IPv6

instance metadata:
  every configured IPv4/IPv6 address and route

approved workload destinations:
  actual address/port/protocol intervals
```

DNS names and answers are evidence. The decision evaluates the actual
destination. Map updates are generation-bound so stale DNS/service data cannot
silently authorize a new address.

Every socket record includes network namespace, socket cookie, protocol,
tuple/destination interval, creator task/process/role, current using
task/process/role where observed, cgroup/Pod/container, and policy/program
generation.

### Role Policy And Existing Authority

- A worker role with no legitimate API/IMDS need receives a synchronous
  destination deny.
- A legitimate controller role keeps its approved API destination.
- An unexpected child/helper in the same Pod/cgroup is denied by the
  process-role path.
- A same-process request over an allowed existing TLS connection is not assigned
  a verb/resource by the network layer.
- A destination/channel can be fenced as a whole only when the policy or
  approved incident response accepts that blast radius.

### Existing-Flow Fence

Create a generation-controlled socket-cookie fence and cgroup packet-fence
primitive:

- fence known sockets of one lineage where socket history is complete;
- deny future sockets/effects through the response-root path;
- widen to cgroup egress only as an explicit broader scope; and
- verify with a controlled packet sent through the same active map/program
  path.

Phase 9 adds response authorization and orchestration. Phase 5 exposes only
internal fixture-scoped actuation.

### CNI Coexistence

Mithril must work with a baseline Kubernetes CNI and coexist with advertised
Cilium, Calico, and Multus/secondary-interface configurations. It does not
become a CNI, route manager, service mesh, universal L7 parser, or TLS
terminator.

Existing CNI/Hubble observations may be corroborating evidence only after their
independent coverage is known.

## Hugging Face Test Increment

Promote:

- `HF-NET-001` to synchronous in-process TCP/UDP API/IMDS denial;
- `HF-NET-002` to use-time descriptor checks and established-flow fencing; and
- `HF-SEM-001` to the explicit allowed-channel/authoritative-audit boundary.

The Phase 5 incident gate uses two profile variants:

1. worker has no approved API/IMDS use: the connection or first send is
   `prevented` and no `HF-012` server action occurs;
2. legitimate controller has approved API use: ordinary API traffic succeeds,
   an unexpected child is denied, and a same-process semantic deviation is
   not falsely decoded by the kernel.

## Code-Backed Tests

- TCP/UDP, IPv4/IPv6, connect/send, bind/listen/accept, connected/unconnected
  send, and DNS change tests;
- public/private control-plane, Service IP, node-local proxy, metadata, hard
  coded address, and alternate resolver tests;
- socket creator exit, exec, inheritance, duplicate FD, `SCM_RIGHTS`, and
  shared-socket use-time role tests;
- `write`, `sendmsg`, `sendfile`, `splice`, `io_uring`, raw/packet sockets,
  TUN/TAP, AF_XDP, and redirection matrix;
- socket-cookie collision/reuse and network namespace reuse tests;
- established TCP and queued/continued packet-fence postconditions;
- incomplete socket history forcing broader/partial result;
- CNI coexistence, multiple interfaces, host-network and unsupported-path
  coverage tests;
- allowed controller and conversion traffic controls;
- direct TLS evidence operation-semantic rejection tests; and
- throughput/latency/loss against Phase 0 budgets.

## Live Probe

Run Probes A, B, and C, the network portion of Probe E, and relevant fault/CNI
cases from Probe G.

## Checkpoint

Run the common repository gates, the complete socket/send/packet bypass
matrix, CNI coexistence matrix, allowed-channel semantic-boundary tests,
physical established-flow fence probes, and applicable live probes. Preserve
destination/profile generations and packet verdict evidence.

## Acceptance

- prohibited new TCP/UDP effects are denied before connection/packet
  completion for every advertised path;
- hard-coded IP, DNS change, IPv6, and alternate endpoint inventory do not
  bypass the selected destination rule;
- unexpected child/helper use is distinguishable from the legitimate
  controller in one Pod/cgroup;
- inherited/passed sockets follow use-time policy;
- creator exit does not erase socket lineage;
- a socket-cookie fence stops covered established traffic;
- cgroup widening is explicit and physically verified;
- Mithril works without Cilium and coexists with advertised CNIs;
- missing resolver/interface/socket/packet coverage changes the coverage tier;
- no network finding claims clone, push, email, token minting, or API verb
  semantics from direct TLS; and
- `HF-NET-001`/`002` stop the protected fixture before their forbidden later
  stage.

## Explicit Stop Point

Stop after local network prevention and packet fences pass. Do not claim durable
fleet evidence or complete negative conclusions until Phase 6 proves loss,
spool, replay, and recovery truth.

## Phase Result

State: Not started.

Record exact hooks/attachments, socket/destination schemas, CNI matrix,
postconditions, incident results, unsupported paths, performance, and final
state.
