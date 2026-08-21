# Code Review Suggestions

This note records only reviewed changes with a better replacement. A note does
not authorize implementation.

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
