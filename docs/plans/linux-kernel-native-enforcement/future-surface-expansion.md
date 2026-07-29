# Future Surface Expansion Gate

Status: Proposed. This is an expansion gate, not authorization to implement a
network or other Surface.

Parent plan: [Linux Kernel-Native Effect Enforcement Master Plan](README.md)

## Purpose

Add a governed effect Surface without duplicating policy authority, weakening
the enforcement claim, or assuming that BPF LSM is the correct primitive for
every effect. A future Surface receives its own approved phase sequence and
must satisfy the common Session contract before a production tier can claim it.

## Required Surface Contract

Before implementation, the proposed Surface plan must name all of these
concrete owners and proofs:

| Contract | Required decision |
| --- | --- |
| Effect taxonomy | The exact operations governed and explicitly unsupported; never a catch-all label such as "network". |
| Subject binding | How an action is attributed to one Session and how descendants, shared descriptors, and cross-Session resources behave. |
| Object identity | Facts available at the enforcement boundary: e.g. inode/parent entry, address/port/protocol, executable identity, or mediated remote resource ID. |
| Enforcement boundary | The exact before-effect hook or Erebor-owned mediation point, its ordering, and why alternate APIs cannot bypass it. |
| Policy lowering | The immutable, digest-bearing representation accepted by that boundary; nonrepresentable policy rejects admission. |
| Evidence and fence | Event schema, ordering scope, bounded capacity, durable cursor, unhealthy behavior, and recovery/sealing result. |
| Host and privilege profile | Required kernel features, boot state, daemon authority, workload exclusions, and precise unsupported result. |
| Isolation and performance | How unrelated workloads remain unaffected, expected hot-path cost, and adversarial bypass tests. |

The proposed Surface must preserve one policy authority. It may share the
portable Session identity, policy selection, capability report shape, and
ledger contract with filesystem. It must not reuse filesystem hook assumptions,
write another general policy engine, or declare a generic BPF abstraction before
the shared owner is proven.

## Future Network Surface

Network is the first intended expansion, but it needs a new approved plan.
The likely kernel-level foundation is cgroup BPF, not filesystem BPF LSM:

```text
immutable PolicySet + Session network declaration
                    │ lower into endpoint policy image
                    ▼
Session cgroup -> socket-address/send-message/egress hook matrix
                    │ allow or deny before claimed network effect
                    ▼
ordered evidence -> ledger, fence, and recovery contract
```

Its capability phase must evaluate at least IPv4/IPv6 `connect` and `bind`, UDP
send-message behavior, egress packet behavior, Unix-domain sockets, proxy
interaction, listener/accept behavior, DNS resolution, and descendant process
inheritance. It must select only the hooks that prove the approved taxonomy;
`connect` alone is not a complete network enforcement claim.

The initial kernel-policy language can truthfully cover transport facts such as
address, port, protocol, direction, and Session cgroup. It cannot truthfully
promise hostname, HTTP method, SaaS object, or encrypted payload governance
merely because traffic reaches the network hook. Those semantic policies need
an Erebor-owned DNS resolver, proxy, gateway, or connector with its own
identity/evidence contract. A network namespace, firewall, or routing rule is
useful containment and may be required as defense in depth, but it is not a
substitute for that contract.

## Other Future Surfaces

- **Process and privilege:** LSM/task and execution hooks can constrain raw
  process effects, while seccomp and namespaces reduce available syscalls and
  ambient capability. Semantic command approval needs an approved
  Erebor-mediated execution surface; BPF cannot wait for an approval RPC.
- **Devices and host controls:** cgroup device controls, LSM hooks, namespaces,
  and capability removal may compose into a device/system-control surface. The
  plan must identify each device or kernel control and prevent access through
  inherited descriptors, mounts, or helper processes.
- **Browser, APIs, SaaS, desktop, and MCP:** these have higher-level resource
  identities and need an Erebor-owned governed endpoint, connector, or
  mediation path. Kernel observation may add attribution but cannot prove a
  remote API's effect on its own.

## Required Phase Shape For Each New Surface

1. **Capability and contract spike:** prove the real enforcement boundary,
   feature/privilege matrix, object facts, and a before-effect denial on an
   isolated test host.
2. **Policy lowering and admission:** define the typed image, unsupported
   result, and no-fallback rule.
3. **Enforcer or mediator:** implement the narrow owner, Session binding, and
   hostile bypass tests.
4. **Evidence, recovery, and fencing:** prove ordering, backpressure, crash
   recovery, and an honest incomplete result.
5. **Lifecycle integration and rollout:** integrate only after the user
   approves the preceding results; preserve lower-tier compatibility paths as
   explicitly labeled capabilities.

## Expansion Stop Point

Do not begin any future Surface implementation from this document alone. Create
a named child plan, obtain approval for its capability phase, and report its
result before changing shared policy, Session, audit, or runtime contracts.
