# Code Review Suggestions

This note records only reviewed changes with a better replacement. A note does
not authorize implementation.

## Preserve path-tree denial after a successful child-directory bind mount

Status: **Implemented** for the path-tree denial claim.

Source:
[`canonical_mount_cache_build_step`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h),
[`canonical_mount_path_walk_step`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h), and
[`mount_mutation_effect`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L1162).

### Finding

Before this change, the mount cache grouped candidates by
`candidate->mnt.mnt_root`. This handled
two mounts with the same mount-root dentry. It did not associate a bind mount
of a child directory with the mount that contains that child directory.

For example, one mount namespace can contain these mounts:

```text
M1, ID 10:  mounted at /                    mnt_root = D_root
M2, ID 100: mounted at /mnt/data            mnt_root = D_data
M3, ID 300: mounted at /backup/models       mnt_root = D_models
```

If `M3` comes from `mount --bind /mnt/data/models /backup/models`, `D_data`
and `D_models` differ. The cache has no entry that connects `M3` to `M2`.
The old path walker selected `M3` at `D_models`, crossed at
`/backup/models`, and produced `/backup/models/x` for that file.

A path-tree `DENY` rule for `/mnt/data/**` can therefore fail to match access
through `/backup/models/x` after the bind succeeds. The successful bind can
exist before policy activation. It can also come from a separate mount owner
that can change the represented namespace. Mount policy can prevent one
mutation path, but it does not correct the path that the resolver constructs
from topology that already exists.

`mount_mutation_effect` sends a mount operation to `identity_effect_gate`, but
passes no source or target path. The current mount gate can prevent the bind
operation. It cannot make this resolver associate a child-directory bind with
its source mount.

The earlier physical test denied the mount syscall. That result proved mount
protection only. It did not exercise the resolver after a successful bind.

### Implemented algorithm correction

Keep mount protection as a separate restriction. Do not add a path-tree flag
that denies every Mount effect. The path resolver must remain correct for a
successful mount that is present in the namespace.

The implementation extends the existing live walk:

1. Keep the cached map from each mount-root dentry to the mount with the lowest
   nonzero `mnt_id_unique`.
2. Start at the accessed leaf. Probe the root-dentry cache at each dentry.
3. On a cache miss, record the current name and follow `d_parent`. Reject a
   miss at the current mount root.
4. On a cache hit, stop if the selected mount is the namespace root. This
   check prevents the walk from escaping the namespace root.
5. If the cached dentry has a non-self `d_parent`, record its name and follow
   the source `d_parent`. Do not cross the bind target mountpoint.
6. If the cached dentry has a self parent, cross through the selected mount's
   `mnt_parent` and `mnt_mountpoint`.
7. Reject a missing source-side mount, cycle, topology race, invalid name, or
   bound overflow. Do not repair uncertainty with the bind target path.

For the example, the walk must produce `/mnt/data/models/x` after access
through `/backup/models/x`. The graph matcher then applies the existing
`/mnt/data/**` terminal. The algorithm must use bounded state and the existing
mount epoch checks. A source-lineage map captured at mount time is an
alternative only if it has complete recovery and lifecycle ownership.

The published slides do not give pseudocode for this distinct-root case. Page
20 combines the oldest-root traversal with LSM protection of mount changes.
The reviewed inspired implementation is not a substitute: it follows
`d_parent` only to the filesystem root, and its mount hooks invalidate an inode
decision cache. It does not build the mount graph shown on pages 19 and 20.

The path-tree denial uses the reconstructed live names. It does not use inode
matching as its authority. The shared walker also supplies canonical mount
identity to the later exact-object branch. The Rust resolver mirrors the new
source walk so existing inode-based allows do not regress. This correction
does not create a second mount-policy owner.

### Implemented proof

The protected physical probe uses the emitted BPF program and the policy
activation path. It proves these results:

- A child-directory bind exists before policy activation. Access through the
  alias returns `PATH_TREE_POLICY_DENY`.
- A separate mount owner completes a bind after activation. The node
  reconciles the namespace. Access through the alias returns
  `PATH_TREE_POLICY_DENY`.
- A successful recursive bind and a successful `open_tree` plus `move_mount`
  attachment return `PATH_TREE_POLICY_DENY` for the protected alias.
- Matching allowed directory aliases remain readable for all three mount
  forms.
- The existing file outside the protected tree remains readable.
- The independent denied-mount test remains a mount-protection result.
