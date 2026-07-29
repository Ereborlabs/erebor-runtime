# Learning Guide: Erebor Runtime and the Future Erebor Defender

Status: living research and design guidance. This document authorizes no
implementation, dependency, deployment, or architecture change.

Related proposed work: [Linux Kernel-Native Effect Enforcement Master
Plan](../plans/linux-kernel-native-enforcement/README.md). That plan is the
candidate implementation plan for a Linux filesystem enforcement backend; this
guide explains the broader product and security reasoning that future Runtime
and Defender work should use.

## Purpose and product boundary

Erebor must govern the real effects of an existing agent harness without
requiring the harness to change. A governed agent still runs `git`, `curl`,
Python, a package manager, or a shell. Its stated intent is useful context, but
is not the enforcement boundary. Enforcement must instead happen where an
effect becomes physically possible: a filesystem object is changed, a process
is executed, a socket connects, a device is opened, or a provider accepts a
credentialed remote request.

This produces two related, but deliberately separate, products:

| Product | Owns | Does not own |
| --- | --- | --- |
| **Erebor Runtime** | Admission and isolation of a workload Session; local before-effect enforcement; Session-scoped capabilities; evidence that explains allowed and denied effects. | The agent harness's source, prompts, tools, or claim of intent. |
| **Erebor Defender** (future, separate project) | A defensive control plane for assets the defender is authorized to operate: evidence correlation, investigation, containment, approved remediation, and connectors. | An attacker’s Session, a model’s implicit authority, or arbitrary third-party infrastructure. |

A Runtime **Session** belongs to the workload being governed. Defender is not
an agent and does not receive a Session. A human responder, GLM, SIEM, or other
assistant is only a client of Defender. Defender must authenticate the client,
check its role and approval requirements, and then execute a narrow,
attributed action through a defender-owned connector.

```text
                         existing agent harness
                       git / curl / Python / shell
                                  │
                                  ▼
                         Erebor Runtime Session
                 local isolation + effect enforcement + evidence
                                  │
             signed, attributed events and capability lifecycle
                                  ▼
        ┌──────────────────── Erebor Defender ────────────────────┐
        │ evidence store │ correlation │ policy simulation │ tools │
        └─────────────────────────────────────────────────────────┘
                    ▲                         │
                    │                         ▼
           human / GLM / SIEM          authorized provider, cloud,
             read or request           identity, VCS, and cluster APIs
             an action only            execute the actual containment
```

The connector, not the client model, holds authority. A model may ask to
quarantine a workload; the Defender service decides whether that is allowed,
whether an approval is required, which exact resource it applies to, and how
the result is recorded.

## Correct interpretation of the Hugging Face incident

The [OpenAI evaluation incident](https://openai.com/index/hugging-face-model-evaluation-security-incident/)
had two distinct security domains:

1. An OpenAI evaluation workload found and exploited a vulnerability in its
   package-cache proxy, escaped the intended network boundary, and then used
   stolen credentials and further vulnerabilities against Hugging Face.
2. Hugging Face had to defend its own processing workers, cloud and cluster
   resources, credentials, and production estate. Its
   [incident report](https://huggingface.co/blog/security-incident-july-2026)
   describes remote-code execution through a dataset loader/template path,
   followed by access to node, cloud, and cluster credentials.

Those are not one Session. An Erebor Runtime deployment at OpenAI could govern
the OpenAI evaluation workload. An Erebor Defender deployment at Hugging Face
could investigate and contain Hugging Face resources. Neither system grants
one organization authority over the other. The practical lesson is that both
the source environment and the target environment need independent prevention,
evidence, and response capability.

## The ultimate Runtime: enforce effects in layers

No Linux primitive is a complete sandbox. The production shape is a composition
in which each layer has a narrow, testable job. This is stronger than choosing
one technology, and avoids incorrectly asking a filesystem control to solve a
network or SaaS problem.

```text
                policy, Session declaration, and capability leases
                                      │
                                      ▼
         strong execution substrate: microVM, VM, or assessed sandbox runtime
                                      │
      ┌─────────────┬─────────────────┼─────────────────┬─────────────┐
      ▼             ▼                 ▼                 ▼             ▼
 mount / pid /   Landlock          seccomp          BPF LSM       cgroup BPF,
 network ns      inherited        syscall/escape    filesystem    routing and
 visible world   static floor      mechanism floor   object effects network fence
      └─────────────┴─────────────────┴─────────────────┴─────────────┘
                                      │
                                      ▼
        provider-scoped credentials and, only when needed, a governed
                  application connector or gateway for remote semantics
                                      │
                                      ▼
             causal evidence, health fencing, recovery, and sealing
```

The layers overlap on purpose. An overlap is useful only if it closes a distinct
bypass or limits the blast radius when another component has a defect. Runtime
must name that purpose and prove it in hostile tests.

### 1. Execution substrate: contain hostile code, not just policy mistakes

For code that may exploit a kernel, container runtime, or local daemon,
namespace isolation on the host is not the desired final trust boundary. A
microVM or VM gives a separate kernel and a materially better blast-radius
boundary. An assessed application-kernel runtime such as
[gVisor](https://gvisor.dev/) may be an intermediate or alternative substrate,
but its compatibility, performance, device, and escape assumptions must be
measured for the exact workload.

The substrate should be chosen by threat tier. A trusted developer operation
may need a fast local tier. An untrusted model evaluation, untrusted package,
or remote-code data loader should default to a stronger, disposable tier with
no host credentials, container-runtime socket, cloud metadata route, or
privileged device exposure.

### 2. Mount namespaces: choose what exists in the workload's world

A mount namespace gives a process tree its own mount table. Combined with a
read-only root, explicit writable scratch/workspace mounts, a fresh `/proc`,
and a copy-on-write working view, it can make most of the host absent or
read-only.

It is the right control for these questions:

- Which roots are visible at all?
- Is the workspace a disposable copy-on-write view rather than the host
  checkout?
- Are `/var/run`, the container runtime socket, cloud credential paths, host
  `/proc`, and other sensitive mounts absent?
- Which writable locations are mounted for this Session?

It does **not** answer these questions once an object is visible and writable:

- May this particular process rename `workspace/release.toml`?
- May it create a new file under an otherwise writable directory?
- May it execute an executable that happens to be visible?
- Can a policy decision be attributed, audited, fenced on evidence failure, and
  recovered after daemon restart?

Mounts are a visibility and coarse writability boundary. They do not provide a
per-object, per-operation policy decision or a durable evidence contract. A
writable bind mount remains broadly writable unless another control narrows it.

### 3. Landlock: a static, inherited, no-take-backs filesystem floor

[Landlock](https://docs.kernel.org/userspace-api/landlock.html) lets an
unprivileged process voluntarily install a restrictive ruleset for itself and
its descendants. Once `no_new_privs` and the ruleset are in place, the process
cannot relax it. Its filesystem rights can restrict access below a path even if
the mount namespace makes that path visible and writable.

Landlock adds three useful properties that a mount namespace does not provide:

1. **Selective restriction inside a visible mount.** A Session may write a
   workspace but be unable to read `.env`, write `.git`, or execute selected
   binaries beneath it.
2. **Inheritance across the process tree.** A child spawned by Python or a
   shell receives the same irreversible floor without the Runtime interpreting
   every command.
3. **A low-privilege backstop.** The workload can never decide later that it
   wants broader rights. This is useful even when the central daemon is the
   normal policy authority.

Landlock is not a replacement for central Runtime enforcement. It is static
for the lifetime of the process tree, does not give Defender a central
per-effect ledger or dynamic containment lever, cannot express every required
filesystem semantic, and needs careful testing of file-descriptor inheritance
and ABI/kernel support. Runtime must query the available Landlock ABI at
admission and reject a policy that needs rights the host cannot enforce.

### 4. Seccomp: remove escape mechanisms, not filesystem semantics

Seccomp filters can allow or deny syscalls and, for many syscalls, inspect
arguments. It is the mechanism floor that stops a workload from acquiring new
control planes. Typical denied or tightly constrained operations include:

- `ptrace`, process-vm read/write, and similar cross-process inspection;
- `bpf`, `perf_event_open`, kernel module, keyring, and privileged tracing
  paths where the workload has no need for them;
- `mount`, `umount2`, `pivot_root`, `setns`, `unshare`, and user-namespace
  creation when those would create a new escape or authority path;
- privileged device and raw networking setup; and
- socket families or creation paths that would bypass the intended network
  topology.

Seccomp sees a syscall number and a limited argument shape, not a reliable
filesystem object identity or a high-level command. It cannot truthfully
implement a policy such as “allow writes to this resolved inode/path set, deny
all other mutations” across every VFS operation. It also cannot decide whether
`curl` means “send email” or “git push.” Use seccomp to remove mechanisms;
use the correct object or provider boundary for effects.

### 5. BPF LSM: selected, pre-effect filesystem object enforcement

BPF LSM programs run at Linux security hooks. For the filesystem Surface they
are a better fit than a ptrace syscall broker because the program can evaluate
the kernel object at the VFS/LSM boundary and return allow or deny before the
effect completes. It avoids stopping the tracee at syscall entry and exit,
copying arguments from tracee memory, making a userspace round trip, and then
resuming it for ordinary allowed operations.

This is a performance and correctness improvement for **kernel-checkable
filesystem effects**, not a general claim that BPF LSM is better than every
other control.

| BPF LSM brings | It does not bring |
| --- | --- |
| A direct, before-effect decision at selected LSM hooks. | A synchronous call to a human, daemon, or model while the syscall waits. |
| Cgroup/session filtering and bounded map lookups for an admitted policy image. | Arbitrary policy language, unbounded path traversal, large mutable data, or remote authorization. |
| Verifier-checked BPF memory/control-flow safety before program load. | Protection from a host-root-equivalent adversary with authority to alter BPF, LSM, mounts, or cgroups. |
| Lower hot-path overhead than `PTRACE_SYSCALL` plus durable userspace RPC for each observed operation. | A promise of zero overhead, complete hook coverage, or durable evidence by itself. |

Its host prerequisite is not simply “install a kernel module.” BPF LSM is a
kernel feature and boot/privilege configuration. Runtime must make a precise
capability report, including at least:

- kernel support for BPF and BPF LSM (`CONFIG_BPF_LSM`), relevant LSM/security
  configuration, and the active LSM order from
  `/sys/kernel/security/lsm`; BPF may be compiled in yet inactive because boot
  LSM ordering does not include `bpf`;
- BTF, required program type, helpers/kfuncs, verifier behavior, and the exact
  hook matrix needed by the policy;
- cgroup v2 and the viability and isolation semantics of the desired attachment
  model; a regular global LSM attachment may require cheap in-program Session
  filtering and has host-wide overhead that must be measured;
- daemon authority to load, pin, attach, and manage BPF objects, subject to
  kernel capability, lockdown, and distribution policy; and
- proof that the workload lacks BPF, mount, cgroup, namespace, and daemon
  control authority.

If any required capability is absent, a Session requiring BPF LSM must fail
admission with an exact unsupported-host result. It must never silently become
the slower ptrace implementation and still claim kernel enforcement. The
[kernel BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html)
should remain the primary source while the support matrix is developed.

### 6. Cgroup BPF, network namespaces, and routing: transport containment

Network namespaces and routing policy decide which interfaces, routes, and
local topology a Session can see. Cgroup BPF socket and packet hooks can
enforce some transport facts at the Session cgroup: address, port, protocol,
direction, socket operation, and selected packet behavior. This is the natural
kernel-level basis for an eventual Network Surface, not filesystem BPF LSM.

These mechanisms are valuable for default-deny egress, denying metadata IPs,
blocking private network ranges, allowing an artifact service, separating
workloads, and stopping a process from opening an arbitrary listener. They do
not see a trustworthy hostname, HTTP method, Git operation, email recipient,
or SaaS object inside an encrypted TLS connection.

That limitation is fundamental, not a missing BPF feature. If a direct TLS
connection can legitimately perform both `git clone` and `git push`, a kernel
or L3/L4 gateway sees the same endpoint/port/TLS stream. It cannot distinguish
the operations without terminating and interpreting the protocol.

## No TLS MITM: how semantic remote effects are still governed

Erebor should not terminate a user's ordinary TLS session merely to infer
application intent. Without that termination, it should make two honest claims:

1. **Transport policy:** Runtime can allow or deny destinations, routes,
   protocols, and connection establishment for a Session.
2. **Remote semantic policy:** Runtime can govern a remote action only when the
   remote service itself enforces a distinct capability, or when the user
   explicitly chooses an Erebor-owned application connector/gateway for that
   operation.

There is no third, transparent local mechanism that lets arbitrary `curl` or
Python send email while preventing only Git writes at the same encrypted
provider endpoint.

The preferred no-MITM model is **capability reduction at the server**:

```text
long-lived broad credential
        │ kept outside the Runtime Session; never exposed to the workload
        ▼
Erebor credential issuer / provider integration
        │ creates a narrow, short-lived, resource-bound capability
        ▼
Session receives only that capability
        │ normal git, curl, Python, etc. use it directly over TLS or SSH
        ▼
provider accepts allowed remote effects and rejects forbidden ones
```

For example, a Session that may read a Git repository but must not push needs a
read-only repository credential. GitHub does not provide a generic exchange of
an arbitrary write personal access token into a down-scoped HTTPS token. A
possible provider-specific design is for the daemon, outside the Session, to
generate a temporary SSH keypair, use an authorized GitHub credential to add a
repository deploy key marked `read_only`, expose only the generated private key
to the Session, and delete the deploy key at Session end or recovery. Normal
SSH clone/fetch succeeds and the Git server rejects push. The GitHub API
requires repository administration permission to create/delete deploy keys,
organization policy may prohibit it, and deploy keys do not provide native
expiry, so lifecycle cleanup and audit are mandatory. See GitHub's
[deploy-key API](https://docs.github.com/en/rest/deploy-keys/deploy-keys).

Where a provider supports it, a GitHub App installation token or an OAuth
provider-specific delegated token can be restricted to repositories,
permissions, and a short lifetime. GitHub installation tokens are one example
of a purpose-built short-lived scope, documented by GitHub
[here](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app).
These are provider integration choices, not a claim that every existing token
can be safely down-scoped.

The same rule applies to email. “May send mail but not push code” is enforceable
only if the mail service gives the Session a send-only/recipient-constrained
credential while the VCS credential is absent or read-only. If the user has
one broad bearer token that authorizes both effects and the provider cannot
mint a narrower token, the safe choices are to deny direct access, require a
governed semantic connector, or request a new provider integration. Giving the
broad token to the agent defeats the policy.

## The two filesystem combinations

Mount namespaces and Landlock solve different problems, so both combinations
have legitimate uses.

| Combination | What it protects well | What remains missing |
| --- | --- | --- |
| **Mount namespace without Landlock** | Hide host roots; make the base filesystem read-only; expose a COW workspace and scratch. Good coarse isolation and compatibility. | A writable mount is still broadly writable. No inherited fine-grained floor, central effect ledger, or dynamic object policy. |
| **Landlock without a mount namespace** | Irreversibly reduce a process tree's rights beneath selected paths, even without host-level mount setup. Useful low-privilege backstop. | The process still sees the host's mount world; policy must describe it safely; no COW view or coarse hiding of sensitive host resources. |
| **Mount namespace plus Landlock** | A small visible filesystem plus an irreversible fine-grained floor inside it. This is the intended baseline for many local tiers. | Still needs seccomp to remove escape mechanisms, BPF LSM for central before-effect object rules/evidence where needed, and a stronger substrate for hostile code. |

Adding BPF LSM to the last combination gives central Session attribution,
admission-time policy lowering, selected per-effect checks, health fencing, and
recovery. It does not make the first two layers redundant.

## Surface-by-surface enforcement model

Erebor must not call every policy “filesystem policy.” The enforcement boundary
must match the effect being claimed.

| Surface | Primary effect boundary | Other necessary layers | What cannot honestly be claimed |
| --- | --- | --- | --- |
| Filesystem | Selected BPF LSM/VFS hooks for kernel-checkable operations. | Mount view/COW, Landlock floor, seccomp escape restrictions. | Full filesystem governance from only `open*` syscall interception. |
| Process and privilege | `exec`/task policy, `no_new_privs`, capabilities, seccomp, and a strong substrate. | PID namespace, executable/mount view, LSM where proven. | Semantic command intent from an executable name alone. |
| Network transport | Cgroup BPF socket/packet matrix plus network namespace/routing. | DNS ownership if hostname claims are made; credentials. | HTTP/SaaS semantics from encrypted packets. |
| Devices and host control | Device allowlist and access-control hooks, with device nodes absent by default. | Mount/device namespaces, seccomp, dropped Linux capabilities, VM boundary. | Safety from hostile driver/kernel attack surface merely by hiding `/dev`. |
| Remote SaaS/API | Provider-enforced scoped credentials or an explicit governed connector. | Transport allowlist, short leases, evidence correlation. | “Allow email but deny push” with one broad direct bearer token and no provider scope. |
| Browser/desktop/MCP | Erebor-owned endpoint or connector that sees a resource/action identity. | Local OS isolation and network policy for the client. | That kernel observation alone proves a remote UI/API effect. |

### Commands are not effects

`git push`, `curl`, and Python are mechanisms. Banning a binary name is a weak
control: a different binary, library, shell built-in, or custom program can
produce the same network effect. Conversely, `curl` could call a harmless
read-only API, send mail, exfiltrate a secret, or invoke a destructive cloud
operation.

Runtime should use execution restrictions to reduce attack surface, such as
preventing execution from writable temporary directories or denying a known
dangerous helper. But a policy such as “do not publish a release” must be
enforced at the release provider through a narrow credential or a governed
release connector. This preserves existing harness behavior while placing the
decision at the actual remote-effect boundary.

### Devices and inherited handles

The device model must account for more than device paths. A workload can use a
device or host resource through an inherited file descriptor, a bind mount, a
Unix socket, a helper process, or a pre-existing broker connection. Admission
must start with no ambient host handles. It must explicitly model and test
standard I/O, passed descriptors, container/runtime sockets, GPU/device access,
FUSE, `/proc`, `/sys`, and Unix-domain sockets.

For hostile workloads, a VM boundary remains important because device drivers,
kernel interfaces, and a privileged host daemon sit outside the promise of a
workload cgroup or a device ACL.

## Runtime attack prevention and Defender response

The table distinguishes prevention, which happens before a physical effect,
from Defender response after suspicious activity is observed. Detection is not
substitute for prevention, but it is essential when prevention assumptions fail
or an authorized service is compromised.

| Attack or failure | Runtime prevention | Evidence/tripwire | Defender action on assets it owns |
| --- | --- | --- | --- |
| Untrusted package, model, dataset loader, or template executes code | Run loaders in a disposable, low-trust tier with no secrets; prefetch immutable approved artifacts; default-deny egress. | Executable/artifact digest, process tree, denied capability/route, policy digest. | Fence worker, snapshot disk/memory where allowed, block artifact hash, search fleet for the digest. |
| Package-cache/proxy escape | Do not give a generic proxy an implicit path to the Internet; isolate its identity and routes; no host or cloud credentials in the evaluation tier. | New route, unexpected DNS/socket target, proxy configuration/process change. | Isolate the local proxy/workload, revoke its credentials, preserve logs, patch/replace the affected component. |
| Cloud metadata or node credential theft | Metadata address and host mounts absent/denied; workload identity is narrow and short-lived. | Attempted metadata connection, credential file/socket access, token issuance/use chain. | Revoke/rotate affected local credentials, audit their use, remove trust bindings. |
| Lateral movement | No runtime socket, kubelet/container socket, host PID view, private routes, or broad service identity; segment with transport policy. | Connection attempts, process privilege changes, access to cluster/cloud endpoints. | Quarantine affected local workload/identity, tighten policy, search related resources. |
| Secret exfiltration | Do not mount or inject broad secrets; egress default deny; providers issue narrow credentials. | Secret-path access, unexpected allowed destination, unusual byte volume, failed denial burst. | Revoke the implicated secret/lease, block destination/artifact, scope notification and forensics. |
| Destructive VCS or cloud operation | Never expose broad credential; provider-side read-only/least-privilege token or connector; require approval for write classes. | Capability issuance, remote provider audit record, denied write. | Revoke lease, freeze service identity, use approved rollback/runbook only with attribution. |
| Persisting a foothold | Disposable root/COW workspace; no host mounts; process/exec and privilege floor. | New executable in writable path, unexpected service/socket, policy violation. | Preserve forensic snapshot, terminate/fence workload, rebuild from known image. |
| Kernel/container escape attempt | Stronger VM/microVM tier; deny namespace/mount/BPF/ptrace mechanisms; patch host. | Denied dangerous syscalls, anomalous kernel/interface access, integrity telemetry. | Contain affected host according to runbook, rotate host-attached credentials, conduct host IR. |
| Evidence pipeline failure or deliberate flooding | Bounded channel with a documented fence: no silent unrecorded allow for a policy that requires evidence. | Drop/backpressure/collector-health event and Session state transition. | Mark evidence incomplete, fence Session, preserve available records, remediate collector capacity. |
| Prompt injection against a defender tool | Treat artifacts, commands, logs, and model output as untrusted data; client model has no direct authority. | Tool request, policy/approval decision, connector result, data provenance. | Require human or signed runbook for remediation; never execute instructions embedded in incident content. |

## What the future Defender should be

Defender is an evidence and controlled-action service, not an autonomous agent
with a shell. Its core job is to let responders and their assistants act with
more context and less standing privilege.

### Server-owned action model

```text
human, GLM, SIEM, or responder UI
           │ authenticated query or action request
           ▼
    Defender authorization and approval policy
           │ validates tenant, asset, role, evidence, and change scope
           ▼
    action planner with a typed request and an idempotency key
           │
    ┌──────┼───────────┬──────────────┬───────────────┐
    ▼      ▼           ▼              ▼               ▼
 Runtime  cloud/IdP   Kubernetes      VCS         artifact store
 fence    revoke      isolate/scale   revoke       block/quarantine
```

The server should expose narrow tool families, for example:

- **Investigate:** reconstruct a causal timeline, find resource/credential/
  artifact relationships, and retrieve integrity-protected evidence.
- **Preserve:** seal a Session, request an approved snapshot, retain logs, and
  record chain of custody.
- **Contain:** fence a Runtime Session, remove egress, isolate a workload,
  revoke a specific lease, or temporarily block an artifact.
- **Remediate:** run a human-approved or signed runbook, rotate a credential,
  patch a policy, or restore a known-good deployment.
- **Simulate:** evaluate proposed containment/policy changes against prior
  evidence without changing production state.

Every request needs a tenant and resource scope, actor identity, reason,
evidence references, policy version, approval state, connector result, and an
idempotency key. “GLM said to do it” is never an authorization record.

### Authority levels

| Level | Examples | Default rule |
| --- | --- | --- |
| Observe | Search evidence, inspect an isolated copy, build a timeline. | Read-only by default. |
| Pre-approved contain | Fence a Session that violates a tripwire, revoke that Session's leased credential, block a known malicious artifact. | Allowed only by explicit policy with narrow resource scope and complete audit. |
| Remediate | Rotate shared production credentials, delete resources, change network policy, restore deployment. | Human approval or a signed, pre-authorized runbook; verify postcondition. |

This lets a defender assistant be useful without turning it into an unchecked
incident-response root account.

### Causal evidence, not a pile of logs

Defender needs relationships that make a response safe to explain. A useful
event chain has at least:

```text
artifact / prompt / input
       │ spawned or influenced
process and workload identity
       │ attempted a local or remote effect
policy image + capability lease + enforcement decision
       │ produced a provider or kernel result
evidence cursor, integrity state, and parent event identifiers
```

For each node, keep the stable resource ID, Session/workload identity, policy
digest, timestamp/ordering scope, enforcement or connector result, and source
of the claim. Preserve uncertainty: a dropped evidence channel or an external
API that cannot return a definitive result must produce an explicit incomplete
state, not a fabricated causal conclusion.

## Learning from the checked-out projects

The local clones are research material. The following is an evaluation guide,
not a decision to vendor, depend on, or run any of them. Before adopting a
component, separately evaluate its maintenance, license, security posture,
support model, threat assumptions, lifecycle ownership, and whether it can
meet Erebor's enforcement/evidence contract.

| Project | What it demonstrates | Learn or evaluate for Erebor | Boundary that must remain Erebor-owned |
| --- | --- | --- | --- |
| [AgentSight](https://github.com/eunomia-bpf/agentsight) | eBPF process/file/network observability and correlation with agent activity, including TLS plaintext capture. | Event correlation, process-tree attribution, local investigative UX, performance measurement techniques. | It observes after/beside effects and its TLS capture conflicts with the no-MITM/no-content-inspection preference. It is not inline enforcement or durable policy authority. |
| [Codex Linux sandbox](https://github.com/openai/codex/tree/main/codex-rs/linux-sandbox) | Bubblewrap mount/user/PID/network namespaces, `no_new_privs`, seccomp network filters, and a legacy Landlock path. | Layer ordering, writable-root construction, path carve-out and symlink tests, failure reporting. | Codex's sandbox settings are a harness-specific implementation; Runtime owns Session attribution, policy, evidence, recovery, and performance target. |
| [KubeArmor](https://github.com/kubearmor/KubeArmor) | Runtime file/process/network policy using LSMs with eBPF-enriched workload telemetry. | Policy-to-hook support matrix, operational packaging, kernel/LSM fallback reporting, policy test cases. | Its Kubernetes-centric resource model must not become Erebor's universal Session/effect model. |
| [Tetragon](https://github.com/cilium/tetragon) | eBPF security observability and reaction, with enriched process, I/O, and Kubernetes identity. | High-rate kernel event design, enrichment, selector ergonomics, fleet operations. | Observability/reaction output is not sole proof of before-effect enforcement or durable evidence. |
| [Falco](https://github.com/falcosecurity/falco) | Rule-based syscall/runtime detection and off-host alert delivery. | Detection-rule lifecycle, alert routing, SIEM integration, and how to distinguish detection from prevention. | A Falco-like alert must never be presented as a denial that happened before the physical effect. |
| [gVisor](https://github.com/google/gvisor) | An application-kernel isolation substrate for OCI workloads. | Isolation trade-offs, syscall compatibility testing, and an alternative to shared-host kernel exposure. | A substrate still needs Erebor policy lowering, credentials, evidence, and recovery. |
| [Sandbox0](https://github.com/sandbox0-ai/sandbox0) | Sandboxed agent-code execution with network and credential-management patterns. | Sandbox lifecycle and capability/credential ergonomics. | Do not automatically accept a proxy/credential path that changes the no-MITM or existing-harness requirements. |
| [OpenShell](https://github.com/NVIDIA/OpenShell) | Agent sandbox drivers and policy/gateway-oriented controls. | Multiple execution backends, policy evaluation, and isolation ergonomics. | A gateway is an explicit product choice; it cannot be silently introduced to claim semantic direct-TLS governance. |
| [SPIRE](https://github.com/spiffe/spire) | Attested workload identity and short-lived X.509/JWT SVID issuance. | Workload identity, attestation, rotation, and broker integration. | SPIRE identity is not a generic issuer for provider OAuth/VCS scopes; connector-specific authority remains a separate design. |
| [Velociraptor](https://github.com/Velocidex/velociraptor) | Endpoint visibility, hunts, artifacts, collection, and DFIR operator workflows. | Evidence collection UX, hunt/query structure, case-oriented investigations. | Collection/query clients must not gain broad automatic remediation authority. |
| [OpenSearch Security Analytics](https://github.com/opensearch-project/security-analytics) | Detector/rule, correlation, dashboard, and remediation workflow ideas. | Alert triage, detection content lifecycle, findings-to-case experience. | A dashboard is not the source of truth for Runtime effect decisions or connector authorization. |
| [herdr](https://github.com/ogulcancelik/herdr) | Terminal multiplexing and durable agent-pane lifecycle. | Operational UI ideas only. | A terminal multiplexer has no enforcement or response authority. |

### Reuse versus reimplementation

Erebor need not reimplement a mature component merely to claim ownership. It
should integrate a component when it provides a narrowly bounded capability and
Erebor can keep its own policy, Session identity, audit, lifecycle, and error
contracts around it. Candidates include a VM substrate, an identity issuer,
kernel loading support, or a fleet evidence source.

Erebor should implement the narrow pieces that make its product unique:

- immutable PolicySet selection and lowering into a specific enforcement
  boundary;
- Session admission and the no-silent-downgrade capability report;
- binding of local effects, credential leases, and remote connector actions to
  one Session/workload identity;
- health fencing, recovery, sealing, and causal evidence; and
- Defender's server-side authorization and approval model.

The decision gate for any integration is not “does it have the same feature?”
It is whether the component can prove the required effect boundary, attribution,
fail-closed behavior, evidence completeness, recovery, operational support,
and license. If it cannot, use it as a telemetry source or research reference,
not as the enforcement boundary.

## Design and test gates before claims are made

Before Runtime claims a new governed Surface, create a separate approved plan
and prove all of these in an isolated environment:

1. **Effect taxonomy:** Enumerate the exact allowed, denied, and unsupported
   operations. “Network governance” is not a taxonomy.
2. **Subject binding:** Prove that descendants, fork/exec, passed descriptors,
   sockets, and shared resources cannot lose Session attribution.
3. **Physical boundary:** Demonstrate a denied attempt causes no physical local
   or remote effect. For remote effects, obtain provider-side proof.
4. **Bypass matrix:** Test alternate syscalls, symlinks, hard links,
   `openat2`, inherited descriptors, `/proc`, Unix sockets, IPv4/IPv6, UDP,
   and helper processes where applicable.
5. **Evidence and health:** Show ordering, bounded capacity, drops/backpressure,
   crash/restart, fencing, and the exact incomplete/sealed outcome.
6. **Privilege and host matrix:** Report kernel/boot features, active LSMs,
   daemon privilege, workload exclusions, and unsupported reasons. Do not use
   a silent compatibility fallback.
7. **Performance:** Measure an interactive TUI and high-rate workload against
   the current ptrace pilot. Attribute time separately to syscall stops,
   userspace policy routing, audit durability, BPF/map lookup, event transfer,
   and storage flushes.
8. **Defender authorization:** For every future action tool, prove a read-only
   client cannot mutate, an unapproved client cannot contain, a model cannot
   escalate through incident text, and a successful result is tied to the
   intended resource and postcondition.

## Reading list

Primary sources used for this guide:

- [OpenAI: Hugging Face model evaluation security incident](https://openai.com/index/hugging-face-model-evaluation-security-incident/)
- [Hugging Face: Security incident report, July 2026](https://huggingface.co/blog/security-incident-july-2026)
- [NIST SP 800-207: Zero Trust Architecture](https://csrc.nist.gov/pubs/sp/800/207/final)
- [NIST SP 800-207A: Zero Trust Architecture Model for Access Control in Cloud-Native Applications](https://csrc.nist.gov/pubs/sp/800/207/a/final)
- [NIST SP 800-61r3: Incident Response Recommendations and Considerations for Cybersecurity Risk Management](https://csrc.nist.gov/pubs/sp/800/61/r3/final)
- [Linux kernel BPF LSM documentation](https://docs.kernel.org/bpf/prog_lsm.html)
- [Linux kernel Landlock userspace API](https://docs.kernel.org/userspace-api/landlock.html)
- [GitHub deploy keys REST API](https://docs.github.com/en/rest/deploy-keys/deploy-keys)
- [GitHub App installation access tokens](https://docs.github.com/en/apps/creating-github-apps/authenticating-with-a-github-app/generating-an-installation-access-token-for-a-github-app)

The checked-out project table above is intentionally a learning map rather than
a dependency list. Revisit it when a named Runtime or Defender phase has a
concrete contract to satisfy.
