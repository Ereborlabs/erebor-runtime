# Container And Kubernetes Execution Architecture

Status: Draft design. This is a separate future architecture line. It does not
change the scope, status, or acceptance criteria of the local daemon-client
phases.

## Purpose

Extend Erebor's existing ownership model from one Linux host to containers and
Kubernetes without turning the client into a container launcher, giving a
workload a Docker/Kubernetes escape path, or making a sidecar the policy
authority.

The stable rule is unchanged:

```text
Erebor client expresses intent.
Erebor control authority admits and owns the logical session.
The selected runner creates and governs the physical effect.
```

Docker and Kubernetes are execution substrates. They do not own policy,
package identity, the context DAG, or parent receive/reject decisions.

## Current Baseline

Today, the production daemon admits only the `linux-host` runner. `erebord`
owns its runtime-guard listener, package and policy stores, sessions, Codex
hook service, and context repository. The Linux runner projects the
daemon-owned runtime-guard endpoint into a private session namespace and
starts the process guard above the workload.

The source tree has a deferred `DockerRunnerDriver` and Docker controller, but
the daemon deliberately excludes it from its admitted runner registry. It is
not yet a correct guarded-container implementation: it does not register the
daemon-owned runtime guard and the Docker controller presently uses the
admitted workload command as the container entrypoint. It must not be enabled
merely because those components exist.

No Kubernetes runner, controller, node agent, remote client endpoint, or
Kubernetes admission integration exists today.

## Non-Goals

- Do not create a second direct `docker` or `kubectl` path in `erebor`.
- Do not give a workload `/var/run/docker.sock`, a container-runtime socket,
  unrestricted Kubernetes credentials, or the daemon-control socket.
- Do not replace Kubernetes Deployment, Job, StatefulSet, scheduling, or
  reconciliation ownership with an Erebor scheduler.
- Do not use a sidecar as the primary process-interception mechanism.
- Do not make OCI distribution, Notation, or authenticated external package
  installation a prerequisite for the local Linux daemon/client work. A
  future container artifact still needs an immutable image digest.

## Common Ownership Model

```text
erebor client
  -> Erebor control authority
       owns: identity, admission, policy, session records, context DAG,
             durable approvals, package identity, audit authority
  -> selected runner / node executor
       owns: physical lifecycle, runtime membership, recovery identity,
             local guard endpoint projection, output transport
  -> in-workload process guard
       owns: parenthood of the governed process tree and reports physical
             effects through its narrow runtime-guard channel
```

A session remains one durable admitted workload. An explicitly admitted child
agent receives a child session and child scope. Ordinary descendants such as
`ls` remain physical descendants of their enclosing session; they do not
become sessions merely because they run in a container or Pod.

The context DAG remains control-authority owned in every deployment model.
Node-local enforcement may report an effect or use a sealed policy snapshot,
but it never writes a context merge, receipt, package installation, or alias.

## Declared Workload Sources And Runner Bases

One source configuration declares the complete filesystem view that an Agent
may receive. It must name caller inputs rather than silently granting an
entire home directory. A local Codex configuration, for example, can declare
its Bash startup file, Codex state directory, source tree, and other working
directories as individual sources:

```text
sources
  caller-home/.bashrc       -> $HOME/.bashrc
  caller-home/.codex/       -> $HOME/.codex/
  caller-home/go/src/       -> $HOME/go/src/
  other declared directories -> their declared workload targets
```

Each source has a caller-relative source path, workload target, access mode,
and regular-file or directory-tree kind. The declaration is an admitted input
to the Session: it is not an untracked bind mount made by a client or runner.
`~/.bashrc` must be declared as a source and selected by the Bash startup
contract; mounting it alone does not cause a directly executed agent binary to
read it.

The source view is portable, but a runner base is not:

```text
LinuxHostRunner
  caller sources -> admitted host-path projections
  system base    -> host-system base, verified to provide required Bash/tools

DockerRunner
  caller sources -> admitted Docker mounts at the same workload targets
  system base    -> admitted immutable image, which provides Bash/tools
```

`host-system` is a Linux-host-only base. It is deliberately not a source list
of `/usr/bin/bash`, `/bin`, the dynamic loader, and shared libraries: that
dependency closure belongs to the host operating system. Docker must not copy
or bind the host system tree. Its image supplies the system base and must be
validated to meet the same declared shell/tool contract.

Generic filesystem sources accept only regular files and directory trees. A
Unix socket such as `~/.codex/ipc/ipc.sock` is a live authority, not a
snapshot-compatible source. Exposing one requires a separately admitted,
governed live binding; it cannot become an incidental consequence of mounting
the `.codex` tree.

## Docker Runner Design

For Docker on a single host, the existing `erebord` is both the control
authority and the node executor:

```text
erebor client
  -> host erebord
       -> RuntimeGuardService (one daemon-owned listener)
       -> DockerRunnerDriver / Docker controller
            -> Docker Engine
                 -> container
                      -> erebor-linux-process-guard (PID 1)
                           -> admitted agent command
```

The Docker runner must implement the same runtime-guard ownership relationship
as the Linux-host runner:

1. The daemon registers the session with its shared `RuntimeGuardService` and
   receives the per-session token and endpoint configuration.
2. The runner projects only that guard endpoint into the container. It must
   not project `daemon.sock` or the Docker socket.
3. The runner mounts the immutable guard binary and makes it the container
   entrypoint. The admitted image command becomes the guard's child command.
4. The container runs as the admitted UID, and its observed host UID must
   match the guard registration. Docker user-namespace remapping must either
   be explicitly mapped or fail admission.
5. The controller retains the container ID as opaque runner recovery data;
   the daemon retains the logical session, policy, context, and audit record.

The endpoint must remain reconnectable after a daemon restart. A direct bind
mount of a socket inode becomes stale when that inode is replaced. The runner
therefore needs a stable daemon-managed directory projection, or an equivalent
safe remount/recovery contract, so a reconnecting guard reaches the recovered
daemon listener.

The interactive path remains daemon-owned:

```text
erebor attach/run -> erebord input lease and stream -> Docker controller -> PTY/container
```

It must not degrade into `docker attach`, and a user with direct Docker-socket
access remains outside the workload trust boundary because that authority can
bypass Erebor with `docker exec`.

### Docker Completion Requirements

- Docker `prepare` registers the runtime guard and carries its environment and
  projection into the controller handoff.
- The controller mounts the guard and stable narrow endpoint, uses the guard
  as entrypoint, and preserves the admitted child command without a shell.
- The controller realizes the full admitted caller-source mapping at its
  declared workload targets. It substitutes the admitted image base for the
  Linux host-system base and verifies the declared Bash/tool contract there.
  It must not infer sources, bind the host system tree, or use a client-created
  mount.
- Image digest, command, mounts, user, capabilities, no-pull behavior, and
  recovery identity are revalidated from Docker inspection.
- TTY attach, cancellation, output, daemon-loss, restart/reconnect, and
  descendant interception are proven with a real container test.
- The container cannot use Docker/daemon control credentials, and unsupported
  Docker/user-namespace configurations fail closed.

## Kubernetes Design

Kubernetes requires two deployment roles. They may share code and release
artifacts, but they must have distinct names, credentials, and authority.

```text
erebor client
  -> Erebor controller (cluster endpoint)
       owns: logical sessions, policy, packages, context DAG, Git writes,
             cluster admission decisions, client streams
       -> desired workload binding / authenticated node channel
            -> Erebor node agent (DaemonSet on the scheduled node)
                 owns: node-local runtime-guard listener, Pod/container
                        identity verification, local enforcement, evidence
                 -> governed Pod
                      -> guard (PID 1 in application container)
                           -> application / agent process tree
```

The client never discovers or connects to a node-agent socket. A later cluster
client configuration needs a remote, mutually authenticated controller
endpoint; the current local `--socket` selector remains a local Unix-socket
mechanism and is not a remote-context design.

### Kubernetes Keeps Workload Ownership

Erebor must not create a replacement Deployment and patch it after the fact.
The user, GitOps system, or ordinary Kubernetes controller remains the owner
of the Deployment/Job/StatefulSet and of Pod scheduling.

An opted-in workload is enrolled through Kubernetes admission:

1. A workload declares an Erebor profile/opt-in reference.
2. The controller authorizes that reference and records an immutable
   `EreborWorkloadBinding` for each resulting Pod UID and container name.
3. A mutating admission webhook changes the generated **Pod**, not the source
   Deployment template. It injects only the guard installation, narrow
   runtime-guard projection, and admitted command wrapper needed to make the
   application container governed.
4. Kubernetes schedules and starts the Pod normally. The node agent resolves
   the binding after scheduling, verifies the Pod/container identity, and
   serves its guard requests.

Mutating the Pod avoids Deployment-template drift and covers Jobs,
StatefulSets, and other Pod-producing controllers. The controller may create
or reconcile the Erebor binding record; it does not become the application
workload scheduler.

Each Pod replica receives a unique physical session/recovery identity because
it has a unique Pod UID and container identity. A higher-level workload may
have a logical parent scope, but replicas do not share one process session.

### Guard Distribution And Pod Injection

Use an init container to distribute the guard, not a sidecar:

```text
init container: erebor-guard-install@sha256:...
  -> copies a static guard binary into an emptyDir

application container
  -> mounts the guard binary read-only
  -> guard is PID 1 / entrypoint
  -> original admitted application command is guard child
```

Kubernetes pulls and caches the immutable guard image on nodes. The init
container has no continuing policy or interception role and exits before the
application starts. It is solely a safe artifact-distribution mechanism.

Kubernetes does not expose OCI pre-start hooks through ordinary Pod specs. To
make a guard the parent process, the admission path must know the original
application command. Version one must require either:

- an explicit admitted `command`/`args` in the Pod; or
- an immutable package/image record that supplies the resolved image
  entrypoint and command.

It must not guess a mutable or implicit image `ENTRYPOINT`/`CMD` during
admission. A custom container runtime would be a different, much larger
architecture and is not the initial approach.

### Node Guard Endpoint

Each node agent owns one local runtime-guard service, multiplexed by session
registration and per-session credentials, just like the host daemon service.
The controller assigns the node agent a sealed binding containing at least:

- Pod UID and container name;
- expected host-visible workload UID;
- logical session and scope identities;
- immutable package, adapter, policy, and runner identities;
- the per-session guard credential; and
- daemon-loss and recovery policy.

The guarded application sees only its narrow runtime-guard endpoint and
credential. Its guard sends `ProcessExec` and lifecycle facts to the node
agent. The node agent validates the peer and binding, applies the admitted
local enforcement path, and sends evidence/results to the controller. The
controller remains the writer for context delivery receipts and merges.

For a trusted development cluster, a read-only, file-specific host socket
projection can prove this model. A production multi-tenant implementation
should use an Erebor CSI node plugin to provide a per-Pod view of the node
agent's endpoint rather than a broad `hostPath` such as `/run/erebor`. The CSI
plugin is a projection mechanism, not a policy sidecar or a second process
guard listener.

The node endpoint must survive node-agent recovery. Its stable projected path
and the guard's reconnect behavior must be tested; a one-time mount of an
unlinked socket inode is insufficient.

### Why A Shared-PID Sidecar Is Not The Guard

`shareProcessNamespace: true` lets sibling containers see each other's process
IDs. It does not make the sidecar the parent of the application process tree.
Consequently a sidecar has attach races, needs broad ptrace-like privileges,
cannot reliably decide before `exec`, and cannot provide correct PID-1 signal
and reaping semantics. It may be useful for diagnostics, but it is not the
primary enforcement boundary.

The application-container guard must remain the parent:

```text
guard (PID 1)
  -> application / Codex
       -> all governed physical descendants
```

### Kubernetes Trust Boundaries

- The controller uses a dedicated Kubernetes service account for admission and
  binding reconciliation; application containers do not receive it.
- Node agents authenticate outbound to the controller or watch only authorized
  binding objects. The controller does not need an unauthenticated inbound
  node socket.
- Direct `kubectl exec`, Pod patch, privileged Pod creation, or node access by
  a principal with corresponding Kubernetes RBAC is an operator-level bypass,
  analogous to direct Docker-socket or root access. Restrict those permissions
  if Erebor governance is meant to be meaningful.
- Client TTY and logs flow through the controller/node-agent session path, not
  raw `kubectl exec` or `kubectl logs` attachment as the governing channel.

## Future Work Sequence

This order is proposed only; no implementation phase is approved by this
draft.

1. Finish the current local Linux daemon/client and Codex Context DAG work.
2. Implement and prove the Docker guarded-container contract above, including
   daemon recovery and interactive TTY behavior.
3. Define the controller/node-agent protocol and immutable workload-binding
   model without introducing a public node API.
4. Build a single-node Kubernetes proof: admission mutation, init-container
   guard distribution, explicit command contract, node listener projection,
   and Pod lifecycle recovery.
5. Replace development `hostPath` projection with the CSI-based per-Pod
   projection and test multi-node rescheduling, node loss, UID mapping, and
   controller recovery.
6. Add production package/image provenance requirements as their own approved
   artifact-distribution phase.

## Acceptance Evidence For Any Future Implementation

- A client talks only to the controller endpoint and cannot select a node
  agent as a general daemon target.
- Kubernetes-native controllers create and recreate the workload; Erebor does
  not create a competing Deployment.
- A guarded application container has the process guard as PID 1, and direct,
  shell-spawned, and nested-agent descendants are intercepted.
- The Pod has no Docker/container-runtime socket, controller credential, or
  unrestricted Kubernetes API authority.
- A fake or wrong-Pod/wrong-container/wrong-UID/wrong-token guard connection
  fails closed.
- Controller restart, node-agent restart, Pod restart, reschedule, and node
  loss produce explicit tested recovery outcomes.
- Context delivery remains controller-owned: node evidence can cause a
  delivery to be published, but only the declared parent explicitly receives
  or rejects it and only the controller writes the Git receipt/merge.
- Multi-node tests verify that an agent cannot use a node-local endpoint to
  impersonate another Pod, session, or tenant.
