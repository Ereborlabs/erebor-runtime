# Code Review Suggestions

This note records only reviewed changes with a better replacement. A note does
not authorize implementation.

## Make the signed policy the source of path authority

Source:
[`lower_path_tables`](../../../crates/mithril-node/src/policy.rs#L3552),
[`ExactFileObjectConfig`](../../../crates/mithril-node/src/config.rs#L147), and
[`LocalObjectSelectorV1`](../../../crates/mithril-control/src/policy/source.rs#L716).

### Finding

`lower_path_tables` combines two independent inputs. The signed artifact
supplies path-tree `DENY` floors. `NodeConfig.exact_file_objects` supplies an
unsigned exact-object key, class, canonical path, and live mount and inode
identity. The signed artifact can refer only to `EXACT:<key>`.

This lets node configuration select the physical target for a signed file
rule. It also requires an object to be resolved before the current static
configuration can activate a policy. A Pod and its mount namespace can be
absent when Control distributes that policy.

The source has no production transition from a CRI container-start event to a
local exact-object resolution. The inspection command and the E2E fixtures
create `ExactFileObjectConfig` records outside that policy lifecycle.

### Probable solution

Make the signed policy the only source of file selectors, object classes,
operations, and dispositions. Do not use `NodeConfig` to select a protected
file or to give an exact-object key its policy meaning. Keep node configuration
only for local operation, such as transport endpoints, state storage, and BPF
loader settings.

Replace the source-policy `EXACT:<numeric-key>` selector with a signed path
selector identified by a policy rule ID. The selector names its canonical path
and whether it is exact or recursive. The existing signed rule disposition and
`operation_ids` state the permitted or denied operations. For example, the
policy can express `ALLOW OPEN_READ` for one exact path, `DENY OPEN_WRITE` for
that path, or `DENY OPEN_WRITE` recursively below a path. Do not add separate
open, read, and write configuration channels.

When Control distributes a policy, stage its path graph before the selected
container exists. At a trusted CRI container-start event, acquire the
container's held mount namespace and root. Resolve each signed exact-path
selector in that namespace. The result is node-owned measured state:

```text
signed path-selector rule ID
  -> mount namespace, selected mount, device, inode, inode generation,
     canonical components, and topology snapshot
```

Compile an opaque numeric handle from that signed rule ID only for the BPF map
ABI. It is not a policy selector and it is not node configuration. Stage and
read back the measured binding with the candidate generation before activation.
If an exact path is absent or cannot be resolved, do not grant its positive
authority. Re-resolve after a container replacement, mount-topology change, or
object replacement.

A signed recursive `DENY` path floor remains usable for a future file. It
matches the live canonical path and denies before exact-object lookup. An
exact-path `ALLOW` still requires the measured binding, so a replacement inode,
mount alias, or overlay copy-up cannot inherit the old allow.

Remove `NodeConfig.exact_file_objects` from policy activation. The inspection
command can remain diagnostic, but it must not produce an authority input. The
CRI resolution path owns the only production producer of measured exact-object
state.

### Required proof

- Changing a signed path, disposition, object class, or operation changes the
  canonical policy bytes and signature input.
- A policy can stage before its selected Pod exists.
- At CRI container start, the node resolves the signed exact path inside that
  container's mount namespace and activates its allow only after map readback.
- An absent or unresolved exact path grants no allow.
- A recursive signed deny blocks a file created after policy staging without an
  exact-object binding.
- Replacing an allowed file, changing its selected mount, or invalidating its
  mount view removes positive authority until a new signed-selector resolution
  completes.
- No node configuration field can map a signed file rule to a path, class, or
  exact-object key.

## Investigate child-directory bind-mount aliases before activation

Source:
[`canonical_mount_cache_build_step`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h#L304),
[`canonical_mount_path_walk_step`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h#L522), and
[`mount_mutation_effect`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L1148).

### Finding

The mount cache groups candidates by `candidate->mnt.mnt_root`. This handles
two mounts with the same mount-root dentry. It does not associate a bind mount
of a child directory with the mount that contains that child directory.

For example, one mount namespace can contain these mounts:

```text
M1, ID 10:  mounted at /                    mnt_root = D_root
M2, ID 100: mounted at /mnt/data            mnt_root = D_data
M3, ID 300: mounted at /backup/models       mnt_root = D_models
```

If `M3` comes from `mount --bind /mnt/data/models /backup/models`, `D_data`
and `D_models` differ. The cache has no entry that connects `M3` to `M2`.
When the path walker reaches `D_models`, it selects `M3`, crosses at
`/backup/models`, and produces `/backup/models/x` for that file.

A path-tree `DENY` rule for `/mnt/data/**` can therefore fail to match access
through `/backup/models/x` if the workload can create the bind mount and no
rule denies that alias. The reviewed source proves the missing association.
It does not prove that a managed workload can complete this sequence under the
active mount-operation policy. This needs a physical test.

`mount_mutation_effect` sends a mount operation to `identity_effect_gate`, but
passes no source or target path. The current mount gate can prevent the bind
operation. It cannot make this resolver associate a child-directory bind with
its source mount.

This is a release-blocking investigation. Preventing a protected directory
from becoming reachable through a later bind alias is a primary path-tree-deny
security property.

### Probable solution

For an identity subject to path-tree enforcement, deny post-exec mount topology
changes by default. The signed policy must explicitly grant a mount operation
only when the workload requires it. This prevents creation of a new bind alias
and keeps the current resolver safe for the common case.

If the product must allow a protected workload to create bind mounts after
exec, the resolver needs a source-aware mount-lineage design. Selecting the
lowest ID for an equal `mnt_root` is not sufficient. The design must preserve
the trusted source mount and source subtree for each permitted bind and use
that lineage when it canonicalizes a later path. It also needs lifecycle rules
for unmount, move, recursive bind, and namespace replacement. Do not enable
post-exec bind mounts for path-tree enforcement until that design and its
proofs exist.

### Required proof

- In a managed mount namespace, a workload that has the needed Linux mount
  privilege cannot create a post-exec bind alias when its signed policy does
  not grant that mount operation.
- With `DENY READ /mnt/data/**` and an explicit mount grant, a bind of
  `/mnt/data/models` to `/backup/models` cannot make `x` readable through
  `/backup/models/x`.
- Run the same test for a recursive bind and the new mount API path that ends
  in `move_mount`.
- A pre-exec container mount setup remains valid and does not grant a
  post-exec aliasing capability.
- The test uses the emitted BPF program and the policy activation path, not a
  unit-level model of the walker.
