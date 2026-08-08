# How To Manually Accept Phase 5

Status: Proposed runbook; no Phase 5 implementation or test has been run.

Phase: [Process-Aware Network Plane](../phase-5-process-aware-network-plane.md)  
Setup: [`SINGLE-NODE`](./environment-setup.md), with isolated API, IMDS, DNS,
rewrite, and packet-capture targets

## Outcome

Prove actor and retained socket authority govern every advertised network path,
the final rewritten destination cannot bypass policy, and direct TLS semantics
remain honestly unknown.

## Automated Companion

```text
IMPLEMENTATION COMMAND REQUIRED: run Phase 5 socket-lifetime, local-peer,
connect/send/receive, NAT/CNI/mesh rewrite, DNS parser, packet fence,
established/shared-flow, delegated-egress, and HF network suites.
```

## Procedure

1. Record namespace, route, CNI, NAT, mesh, resolver, packet-hook, and capture
   manifests before traffic.
2. Start approved conversion/controller traffic and record the clean control.
3. Initiate each fixture from the existing interpreter, inherited/passed
   sockets, and independent roots as required.
4. Check syscall return, server receipt, packet capture/counters, socket state,
   final destination, and provider/audit result separately.
5. Fence an established flow and inspect the disclosed socket/cgroup blast
   radius and post-fence packet absence.

## Fixture Matrix

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

## Encrypted-Channel Manual Gate

Send one approved and one out-of-profile operation over the same legitimate
TLS process/token/destination/channel. The kernel/network result must remain
allowed channel activity. Only authenticated server/provider audit may report
the semantic operation and its actual result. This is not an L7 prevention
failure.

## Required Artifacts And Pass Rule

Retain socket/namespace/flow generations, route and rewrite traces, packet
captures or authoritative counters, syscall/server results, DNS parser cases,
shared-flow blast radius, coverage, and legitimate controls. Pass requires the
claimed packet/effect absence and no invented TLS verb.

## Troubleshooting

- A connect denial does not prove a packet-stage fence, and a packet drop does
  not prove a syscall denial. Record the actual boundary.
- If the packet hook lacks current-task context, use retained socket/flow state;
  never substitute a fictional task.
- Unsupported raw/TUN/AF_XDP/RDMA/vsock/SCTP/MPTCP paths narrow the claim.
