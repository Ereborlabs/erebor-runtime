# Code Review Suggestions

This note records only reviewed changes with a better replacement. A note does
not authorize implementation.

## Preserve path-tree denial after a successful child-directory bind mount

Status: **Open** and release-blocking for the path-tree denial claim.

Source:
[`canonical_mount_cache_build_step`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h#L304),
[`canonical_mount_path_walk_step`](../../../bpf/erebor-interceptor/programs/identity_path.bpf.h#L520), and
[`mount_mutation_effect`](../../../bpf/erebor-interceptor/programs/identity_effects.bpf.h#L1162).

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
through `/backup/models/x` after the bind succeeds. The successful bind can
exist before policy activation. It can also come from a separate mount owner
that can change the represented namespace. Mount policy can prevent one
mutation path, but it does not correct the path that the resolver constructs
from topology that already exists.

`mount_mutation_effect` sends a mount operation to `identity_effect_gate`, but
passes no source or target path. The current mount gate can prevent the bind
operation. It cannot make this resolver associate a child-directory bind with
its source mount.

The current physical test denies the mount syscall. That result proves mount
protection only. It does not exercise the resolver after a successful bind and
must not close this finding.

### Required algorithm correction

Keep mount protection as a separate restriction. Do not add a path-tree flag
that denies every Mount effect. The path resolver must remain correct for a
successful mount that is present in the namespace.

The preferred correction extends the existing live walk:

1. Keep the cached map from each mount-root dentry to the mount with the lowest
   nonzero `mnt_id_unique`.
2. Start at the accessed leaf. Before following a parent edge, stop if the
   current mount and dentry are the selected namespace root. This check
   prevents the canonical walk from escaping the namespace root.
3. Below a mount root, record the current name and follow `d_parent` as the
   current implementation does.
4. At a non-root mount root with a non-self `d_parent`, classify the edge as a
   child-directory bind. Record the bind-root name and follow its source
   `d_parent` chain. Do not cross the bind target mountpoint.
5. Inspect the root-dentry cache during the source-side walk. When it reaches
   the source filesystem root, select the oldest represented mount for that
   root dentry. Continue through that mount's parent and mountpoint.
6. Reject a missing source-side mount, cycle, topology race, invalid name, or
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

This correction supports later exact-object, mount-reconciliation, recursive
bind, and new mount API work. It does not create a second mount-policy owner.

### Required proof

- Create the child-directory bind before policy activation. Activate
  `DENY READ /mnt/data/**`. Access through `/backup/models/x` must deny with a
  path-tree decision.
- Let a separate qualified mount owner complete the bind after activation.
  Reconcile the namespace. Access through the alias must still deny.
- Run the same successful-topology test for a recursive bind and the new mount
  API path that ends in `move_mount`.
- Bind an allowed subtree through the same mount forms. Its signed file allow
  must still succeed. A deny-all result does not pass.
- Keep a file outside the protected tree readable before and after each
  successful mount.
- Keep the independent mount-denial test, but classify it as mount protection
  rather than path canonicalization proof.
- The test uses the emitted BPF program and the policy activation path, not a
  unit-level model of the walker.
