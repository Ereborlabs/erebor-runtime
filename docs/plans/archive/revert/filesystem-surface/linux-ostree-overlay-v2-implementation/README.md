# Filesystem Revert OSTree + OverlayFS V2 Subplan

Status: superseded design draft.

Superseded by:

- [`ostree-overlay-v3`](../ostree-overlay-v3/)

V2 imported each allowed host path into OSTree as a full base commit at session
start. That is not the preferred Linux default because allowed paths may be too
large to copy or may not be readable as a complete tree. V3 keeps the host path
as a read-only OverlayFS lowerdir and stores only normalized upperdir layers,
promotion preimages, and manifests in OSTree.

Plan type: architecture, implementation, and manual validation subplan.

Parent feature:

- [`docs/plans/revert`](../../)

Related plans:

- [`docs/plans/session-hypervisor/README.md`](../../../session-hypervisor/README.md)
- [`docs/plans/erebor-agent-task-boundary-guard/README.md`](../../../erebor-agent-task-boundary-guard/README.md)
- [`docs/governed-browser-and-terminal-plan.md`](../../../../governed-browser-and-terminal-plan.md)
- [`docs/plans/session-interception-backend-refactor/README.md`](../../../session-interception-backend-refactor/README.md)

External references:

- OSTree introduction: <https://ostreedev.github.io/ostree/introduction/>
- OSTree repository modes and object storage:
  <https://ostreedev.github.io/ostree/repo/>
- `ostree init`: <https://ostreedev.github.io/ostree/man/ostree-init.html>
- `ostree commit`: <https://ostreedev.github.io/ostree/man/ostree-commit.html>
- `ostree diff`: <https://ostreedev.github.io/ostree/man/ostree-diff.html>
- Linux OverlayFS: <https://www.kernel.org/doc/html/latest/filesystems/overlayfs.html>

## Summary

The filesystem revert surface should combine:

- actual OSTree repositories for durable filesystem generations
- OverlayFS for the live mutable session view on Linux and Docker/OCI
- Erebor metadata sidecars, stored in OSTree, for exact restore information not
  represented by OSTree itself
- allowed-path mounts so the agent sees only approved data roots through the
  reversible view

The core v2 design is:

```text
one governed session
  -> one real OSTree repo
  -> many filesystem volumes, one per allowed path
  -> one overlay mount per writable directory volume
  -> session-level checkpoints that contain per-volume layer/result commits
  -> session-level promotions that contain per-volume before/after commits
```

The OSTree repo is the durable store. OverlayFS is only the live working view.
Overlay directories, checkouts, and staging directories must never be placed
inside the OSTree repo.

## Product Goal

The filesystem surface should guarantee that protected non-code paths are not
permanently mutated by an agent until Erebor promotes a reversible filesystem
generation.

For v2, the guarantee is checkpoint, session, and promotion revert. This subplan
does not make arbitrary per-action revert the default guarantee.

```text
Allowed path enters session -> agent mutates overlay -> Erebor commits result
to OSTree -> Erebor promotes result to host -> rollback restores previous host
commit.
```

This is intended primarily for files Git does not reliably protect:

- `.env`, `.npmrc`, `.pypirc`, cloud credentials, and other local secrets
- shell profiles, Git hooks, editor config, and agent config
- ignored or untracked repository files
- generated local databases, caches, downloads, and local state
- user files outside a source repository

Git-tracked source files may still be audited and policy-checked, but Git should
remain the default revert mechanism for tracked code.

## Hard Boundaries

These boundaries are design invariants:

- The OSTree repo is only `repo/`.
- Overlay lower, upper, work, and merged directories live outside `repo/`.
- Checkouts live outside `repo/`.
- Staging directories live outside `repo/`.
- Nothing under `work/` becomes durable until Erebor commits it to OSTree.
- The original host path is not mounted directly into the agent's writable view.
- The agent receives the overlay merged view, not the host path.
- Promotion is the only path that mutates the host path.
- Rollback restores from OSTree refs created before promotion.

## Multi-Volume Reference Model

Multiple allowed paths are the primary model. A single allowed path is only the
degenerate case of one volume.

```text
session id: session-123

volume id: openclaw-config
host path:  /home/navid/.config/openclaw
session path: /home/navid/.config/openclaw

volume id: agent-output
host path:  /home/navid/Downloads/agent-output
session path: /home/navid/Downloads/agent-output
```

At session start, Erebor imports each allowed host path into the session OSTree
repo as that volume's base commit:

```sh
SESSION_FS=".erebor/sessions/session-123/filesystem"
REPO="$SESSION_FS/repo"

OPENCLAW_HOST="/home/navid/.config/openclaw"
OUTPUT_HOST="/home/navid/Downloads/agent-output"

ostree --repo="$REPO" init --mode=bare-user

ostree --repo="$REPO" commit \
  --branch="erebor/volumes/openclaw-config/base" \
  --subject="Erebor base for openclaw-config" \
  --tree=dir="$OPENCLAW_HOST"

ostree --repo="$REPO" commit \
  --branch="erebor/volumes/agent-output/base" \
  --subject="Erebor base for agent-output" \
  --tree=dir="$OUTPUT_HOST"
```

Yes, each allowed path's contents are copied into the per-session OSTree repo at
session start. Those copies are the base generations for the session. The
original host paths remain in place and are not used as live agent views.

Both volume commits are in the same OSTree repo because the repo is the
session's object database. They are separate commits addressed by separate refs:

```text
repo ref: erebor/volumes/openclaw-config/base
  logical tree from: /home/navid/.config/openclaw

repo ref: erebor/volumes/agent-output/base
  logical tree from: /home/navid/Downloads/agent-output
```

OSTree does not store these as normal directories like
`repo/openclaw-config/` and `repo/agent-output/`. It stores file objects under
`repo/objects/` and ref names under `repo/refs/`. To inspect the volume trees,
check out each ref to a normal directory outside the repo.

Manual inspection after the commits:

```sh
ostree --repo="$REPO" refs --list | sort
ostree --repo="$REPO" ls -R erebor/volumes/openclaw-config/base
ostree --repo="$REPO" ls -R erebor/volumes/agent-output/base
find "$REPO/refs" -type f -print | sort
```

Expected refs:

```text
erebor/volumes/agent-output/base
erebor/volumes/openclaw-config/base
```

Depending on OSTree repo mode and version, the physical ref files live under a
path like `repo/refs/heads/erebor/volumes/openclaw-config/base`, but the file
contents are commit checksums. The actual file contents are in the OSTree object
store under `repo/objects/`.

The important detail: volumes do not become different directories inside
`repo/`. OSTree stores commits and content-addressed objects. Erebor creates
different volume-specific refs in the same repo, then checks those refs out to
different working directories outside the repo.

Concrete mapping for the example above:

| Volume | Host source imported at session start | OSTree ref in the session repo | Checkout outside repo | Overlay merged path | Path mounted into agent |
| --- | --- | --- | --- | --- | --- |
| `openclaw-config` | `/home/navid/.config/openclaw` | `erebor/volumes/openclaw-config/base` | `.erebor/sessions/session-123/filesystem/work/volumes/openclaw-config/checkouts/base` | `.erebor/sessions/session-123/filesystem/work/volumes/openclaw-config/overlay/merged` | `/home/navid/.config/openclaw` |
| `agent-output` | `/home/navid/Downloads/agent-output` | `erebor/volumes/agent-output/base` | `.erebor/sessions/session-123/filesystem/work/volumes/agent-output/checkouts/base` | `.erebor/sessions/session-123/filesystem/work/volumes/agent-output/overlay/merged` | `/home/navid/Downloads/agent-output` |

Erebor then creates one live overlay mount per writable directory volume. These
commands are the exact continuation after the base commits above:

```sh
OPENCLAW_WORK="$SESSION_FS/work/volumes/openclaw-config"
OPENCLAW_REF="erebor/volumes/openclaw-config/base"
OPENCLAW_BASE="$OPENCLAW_WORK/checkouts/base"
OPENCLAW_UPPER="$OPENCLAW_WORK/overlay/upper"
OPENCLAW_OVERLAY_WORK="$OPENCLAW_WORK/overlay/workdir"
OPENCLAW_MERGED="$OPENCLAW_WORK/overlay/merged"

OUTPUT_WORK="$SESSION_FS/work/volumes/agent-output"
OUTPUT_REF="erebor/volumes/agent-output/base"
OUTPUT_BASE="$OUTPUT_WORK/checkouts/base"
OUTPUT_UPPER="$OUTPUT_WORK/overlay/upper"
OUTPUT_OVERLAY_WORK="$OUTPUT_WORK/overlay/workdir"
OUTPUT_MERGED="$OUTPUT_WORK/overlay/merged"

mkdir -p "$OPENCLAW_WORK/checkouts" "$OUTPUT_WORK/checkouts"

ostree --repo="$REPO" checkout "$OPENCLAW_REF" "$OPENCLAW_BASE"
ostree --repo="$REPO" checkout "$OUTPUT_REF" "$OUTPUT_BASE"

mkdir -p \
  "$OPENCLAW_UPPER" \
  "$OPENCLAW_OVERLAY_WORK" \
  "$OPENCLAW_MERGED" \
  "$OUTPUT_UPPER" \
  "$OUTPUT_OVERLAY_WORK" \
  "$OUTPUT_MERGED"
```

The actual Linux OverlayFS mounts are separate:

```sh
sudo mount -t overlay overlay \
  -o lowerdir="$OPENCLAW_BASE",upperdir="$OPENCLAW_UPPER",workdir="$OPENCLAW_OVERLAY_WORK" \
  "$OPENCLAW_MERGED"

sudo mount -t overlay overlay \
  -o lowerdir="$OUTPUT_BASE",upperdir="$OUTPUT_UPPER",workdir="$OUTPUT_OVERLAY_WORK" \
  "$OUTPUT_MERGED"
```

The resulting live mount mapping is:

| Overlay source on the host | Agent-visible path |
| --- | --- |
| `$OPENCLAW_MERGED` | `/home/navid/.config/openclaw` |
| `$OUTPUT_MERGED` | `/home/navid/Downloads/agent-output` |

Docker/OCI bind mounts:

```sh
docker run --rm -it \
  -v "$OPENCLAW_MERGED:/home/navid/.config/openclaw" \
  -v "$OUTPUT_MERGED:/home/navid/Downloads/agent-output" \
  alpine:3.20 sh
```

Linux mount namespace bind mounts:

```sh
sudo env \
  OPENCLAW_MERGED="$OPENCLAW_MERGED" \
  OUTPUT_MERGED="$OUTPUT_MERGED" \
  unshare --mount --fork /bin/sh -c '
    mount --make-rprivate /
    mkdir -p /home/navid/.config/openclaw
    mkdir -p /home/navid/Downloads/agent-output
    mount --bind "$OPENCLAW_MERGED" /home/navid/.config/openclaw
    mount --bind "$OUTPUT_MERGED" /home/navid/Downloads/agent-output
    findmnt /home/navid/.config/openclaw
    findmnt /home/navid/Downloads/agent-output
    exec /bin/sh
  '
```

Checkpoints and promotions are session-level objects. They collect per-volume
layer, result, metadata, and before/after refs that belong to one checkpoint or
promotion.

## Session Directory Layout

For one session:

```text
.erebor/sessions/session-123/
  audit.jsonl
  session.json
  filesystem/
    filesystem.json
    repo/
      config
      objects/
      refs/
      state/
      tmp/
    work/
      volumes/
        openclaw-config/
          volume.json
          checkouts/
            base/
          overlay/
            upper/
            workdir/
            merged/
        agent-output/
          volume.json
          checkouts/
            base/
          overlay/
            upper/
            workdir/
            merged/
      bootstrap/
        volumes/
          openclaw-config/
            metadata-base/
          agent-output/
            metadata-base/
      checkpoints/
        000001/
          manifest/
            erebor-checkpoint.json
          volumes/
            openclaw-config/
              layer/
                files/
                erebor-layer.json
              metadata/
              result/
            agent-output/
              layer/
                files/
                erebor-layer.json
              metadata/
              result/
      promotions/
        000001/
          manifest/
            erebor-promotion.json
          volumes/
            openclaw-config/
              before-checkout/
              after-checkout/
            agent-output/
              before-checkout/
              after-checkout/
```

Only `filesystem/repo/` is the OSTree repo. Everything under
`filesystem/work/` is ordinary working state outside the repo.

## OSTree Refs

Because the repo is per-session, refs do not need to include the session id.
The session id is already present in the parent directory. Refs should still use
an `erebor/` prefix so copied or exported repos are self-describing.

For one volume:

```text
erebor/volumes/openclaw-config/base
erebor/volumes/openclaw-config/metadata/base
```

For one session-level checkpoint:

```text
erebor/checkpoints/000001/manifest
erebor/checkpoints/000001/volumes/openclaw-config/layer
erebor/checkpoints/000001/volumes/openclaw-config/metadata
erebor/checkpoints/000001/volumes/openclaw-config/result
erebor/checkpoints/000001/volumes/agent-output/layer
erebor/checkpoints/000001/volumes/agent-output/metadata
erebor/checkpoints/000001/volumes/agent-output/result
```

For one session-level promotion:

```text
erebor/promotions/000001/manifest
erebor/promotions/000001/volumes/openclaw-config/before
erebor/promotions/000001/volumes/openclaw-config/after
erebor/promotions/000001/volumes/agent-output/before
erebor/promotions/000001/volumes/agent-output/after
```

## Volume Model

A filesystem volume is one allowed path in the governed session.

```json
{
  "schema_version": 1,
  "volume_id": "openclaw-config",
  "kind": "directory",
  "host_path": "/home/navid/.config/openclaw",
  "session_path": "/home/navid/.config/openclaw",
  "mode": "read_write_reversible",
  "ostree_refs": {
    "base": "erebor/volumes/openclaw-config/base",
    "base_metadata": "erebor/volumes/openclaw-config/metadata/base"
  }
}
```

Directory volumes are the primary v2 target. Single-file allowed paths are
modeled as file volumes:

```json
{
  "volume_id": "npmrc",
  "kind": "file",
  "host_path": "/home/navid/.npmrc",
  "session_path": "/home/navid/.npmrc",
  "mode": "read_write_reversible"
}
```

For file volumes, Erebor creates a synthetic volume tree containing only the
file basename. The agent receives a bind mount of the merged file, not the
whole parent directory. This prevents granting access to sibling files.

V2 implementation may start with directory volumes and explicitly reject file
volumes until file bind mounts are implemented.

## Allowed Paths And Mounting

The filesystem surface must have explicit allowed paths. The agent should not
see the user's whole home directory and rely on policy to deny dangerous paths
after lookup.

Example config shape:

```json
{
  "surfaces": {
    "filesystem": {
      "enabled": true,
      "backend": "ostree_overlay",
      "roots": [
        {
          "id": "openclaw-config",
          "host_path": "/home/navid/.config/openclaw",
          "session_path": "/home/navid/.config/openclaw",
          "mode": "read_write_reversible"
        },
        {
          "id": "agent-output",
          "host_path": "/home/navid/Downloads/agent-output",
          "session_path": "/home/navid/Downloads/agent-output",
          "mode": "read_write_reversible"
        }
      ]
    }
  }
}
```

Docker/OCI runner:

```sh
docker run --rm -it \
  -v "$OPENCLAW_WORK/overlay/merged:/home/navid/.config/openclaw" \
  -v "$OUTPUT_WORK/overlay/merged:/home/navid/Downloads/agent-output" \
  alpine:3.20 sh
```

Docker receives only the overlay merged paths as bind mounts. The original host
paths are not mounted into the container.

Linux host runner:

```sh
sudo env \
  OPENCLAW_MERGED="$OPENCLAW_WORK/overlay/merged" \
  OUTPUT_MERGED="$OUTPUT_WORK/overlay/merged" \
  unshare --mount --fork /bin/sh -c '
    mount --make-rprivate /
    mkdir -p /home/navid/.config/openclaw
    mkdir -p /home/navid/Downloads/agent-output
    mount --bind "$OPENCLAW_MERGED" /home/navid/.config/openclaw
    mount --bind "$OUTPUT_MERGED" /home/navid/Downloads/agent-output
    exec /bin/sh
  '
```

This shell is only a manual demonstration of the mount mapping. The production
Linux host runner would create the mount namespace, bind the merged paths,
attach the process/syscall guard, drop to the intended user where appropriate,
and then exec the agent command. Other user/data paths are absent, read-only, or
blocked by the filesystem backend. System paths such as `/usr`, `/bin`,
libraries, `/proc`, and `/tmp` are handled by the session runner policy and are
not filesystem revert volumes by default.

After-the-fact `session adopt --pid` cannot provide the same filesystem
guarantee because the process may already have cwd, file descriptors, mmap
handles, or a mount namespace. Filesystem revert v2 should require `session run`
or an exec-time enrollment path.

## Lifecycle

### 1. Initialize Session Filesystem State

Create:

```text
.erebor/sessions/<session-id>/filesystem/repo
.erebor/sessions/<session-id>/filesystem/work
```

Initialize the repo:

```sh
ostree --repo="$SESSION_FS/repo" init --mode=bare-user
```

Use `bare-user` for unprivileged developer mode. Use a rootful mode such as
`bare` or `bare-split-xattrs` only when the installed daemon can safely preserve
ownership, xattrs, capabilities, ACLs, and privileged metadata.

### 2. Import Base Volume

For each allowed path:

```text
host path -> OSTree base commit
metadata sidecar -> OSTree metadata commit
```

Refs:

```text
erebor/volumes/<volume-id>/base
erebor/volumes/<volume-id>/metadata/base
```

The base commit is the host state the session started from.

### 3. Checkout Base Outside The Repo

Checkout:

```text
repo ref erebor/volumes/<volume-id>/base
  -> work/volumes/<volume-id>/checkouts/base
```

This checkout becomes `lowerdir`.

### 4. Mount Overlay

Mount:

```text
lowerdir = work/volumes/<volume-id>/checkouts/base
upperdir = work/volumes/<volume-id>/overlay/upper
workdir  = work/volumes/<volume-id>/overlay/workdir
merged   = work/volumes/<volume-id>/overlay/merged
```

The agent sees only `merged`.

### 5. Agent Mutates Merged View

During the session:

- creates go to `overlay/upper`
- edits copy up into `overlay/upper`
- deletes become OverlayFS whiteouts in `overlay/upper`
- opaque directories are represented by OverlayFS opaque markers
- OSTree repo does not change on normal writes
- host path does not change on normal writes

### 6. Checkpoint V2

At checkpoint, Erebor normalizes the overlay upperdir into a layer staging tree:

```text
work/volumes/<volume-id>/overlay/upper
  -> work/checkpoints/000001/volumes/<volume-id>/layer/files
  -> work/checkpoints/000001/volumes/<volume-id>/layer/erebor-layer.json
  -> OSTree commit erebor/checkpoints/000001/volumes/<volume-id>/layer
```

The layer commit is a real OSTree commit. Its tree is not the full volume. It is
an Erebor layer tree containing changed files plus a manifest for deletes,
opaque directories, and layer metadata.

Then Erebor materializes a result tree:

```text
base + layer-000001
  -> work/checkpoints/000001/volumes/<volume-id>/result
  -> OSTree commit erebor/checkpoints/000001/volumes/<volume-id>/result
```

The result commit is a full logical volume state. Promotion and rollback should
use result commits, not raw layers.

After every volume has a layer/result pair, Erebor commits one session-level
checkpoint manifest:

```text
work/checkpoints/000001/manifest/erebor-checkpoint.json
  -> OSTree commit erebor/checkpoints/000001/manifest
```

### 7. Promotion

Before promotion, detect external drift:

```text
base commit = host state at session start
current host path = actual host path at promotion time
```

If `ostree diff base current-host-path` is non-empty, hold the promotion. V2
does not silently merge external host changes.

If there is no drift:

1. For every volume, commit current host path as promotion `before`.
2. Verify all volumes passed drift checks before mutating any host path.
3. For every volume, commit the checkpoint result as promotion `after`.
4. Apply result checkouts to host paths.
5. If any apply fails, restore already-applied volumes from their `before` refs.
6. Persist one session-level promotion manifest.

### 8. Rollback

Rollback restores the promotion `before` ref to the host path and reapplies
Erebor metadata sidecars.

```text
erebor/promotions/000001/volumes/<volume-id>/before
  -> host path
```

## Layer Commit Format

Layer staging tree:

```text
work/checkpoints/000001/volumes/openclaw-config/layer/
  files/
    settings.json
    generated/token.txt
  erebor-layer.json
```

`files/` contains changed or created file contents. It does not contain raw
OverlayFS whiteout device nodes. Erebor must normalize whiteouts into the JSON
manifest.

Example `erebor-layer.json`:

```json
{
  "schema_version": 1,
  "kind": "erebor.filesystem.layer",
  "volume_id": "openclaw-config",
  "layer_id": "000001",
  "base_ref": "erebor/volumes/openclaw-config/base",
  "parent_layer_ref": null,
  "files_root": "files",
  "changes": [
    {
      "path": "settings.json",
      "operation": "replace_file",
      "content_path": "files/settings.json"
    },
    {
      "path": "generated/token.txt",
      "operation": "create_file",
      "content_path": "files/generated/token.txt"
    },
    {
      "path": "old-cache.txt",
      "operation": "delete"
    }
  ],
  "opaque_directories": [],
  "metadata_ref": "erebor/checkpoints/000001/volumes/openclaw-config/metadata"
}
```

OverlayFS normalization rules:

- regular files, directories, and symlinks are copied into `files/`
- character device `0:0` whiteouts become `delete` operations
- `trusted.overlay.whiteout` markers become `delete` operations
- `trusted.overlay.opaque=y` directories become `opaque_directories`
- raw OverlayFS whiteout markers are not committed directly
- unsupported special files are denied by policy or represented only when an
  explicit privileged policy allows them

## Result Commit Format

A result commit is a normal full OSTree tree commit for one volume.

```text
base commit
  + layer 000001
  + layer 000002
  -> full result tree
  -> erebor/checkpoints/000002/volumes/<volume-id>/result
```

Result commits are used for:

- promotion
- rollback targets
- manual inspection
- drift comparison
- compacting multiple layers into a stable generation

## Metadata Sidecars

OSTree stores file content and many filesystem metadata fields depending on repo
mode, but it does not preserve timestamps as file metadata. Erebor needs exact
restore semantics for protected non-code files, so every base, layer, and result
should have a metadata sidecar committed to OSTree.

Metadata sidecar staging tree:

```text
work/checkpoints/000001/volumes/openclaw-config/metadata/
  metadata.cbor.zst
  metadata.json
```

The JSON form is for debugging. The canonical implementation format should be a
compact binary format such as CBOR, compressed if useful.

Metadata entry shape:

```json
{
  "path": "settings.json",
  "kind": "file",
  "mode": 420,
  "uid": 1000,
  "gid": 1000,
  "mtime_sec": 1780000000,
  "mtime_nsec": 123456789,
  "xattrs": {},
  "acl": null,
  "capabilities": null,
  "symlink_target": null
}
```

Security rules:

- setuid/setgid bits require explicit policy
- Linux file capabilities require explicit policy
- device nodes require explicit policy
- owner changes require privilege and explicit policy
- unknown xattrs should be preserved only for allowed namespaces
- metadata restore failures must be audited and should fail closed for exact
  rollback claims

## Checkpoint Commit

A checkpoint commit is an OSTree commit containing only a manifest, not a
filesystem volume.

```text
work/checkpoints/000001/manifest/
  erebor-checkpoint.json
```

Example:

```json
{
  "schema_version": 1,
  "kind": "erebor.filesystem.checkpoint",
  "checkpoint_id": "000001",
  "volumes": [
    {
      "volume_id": "openclaw-config",
      "base_ref": "erebor/volumes/openclaw-config/base",
      "layer_refs": [
        "erebor/checkpoints/000001/volumes/openclaw-config/layer"
      ],
      "result_ref": "erebor/checkpoints/000001/volumes/openclaw-config/result",
      "metadata_ref": "erebor/checkpoints/000001/volumes/openclaw-config/metadata"
    },
    {
      "volume_id": "agent-output",
      "base_ref": "erebor/volumes/agent-output/base",
      "layer_refs": [
        "erebor/checkpoints/000001/volumes/agent-output/layer"
      ],
      "result_ref": "erebor/checkpoints/000001/volumes/agent-output/result",
      "metadata_ref": "erebor/checkpoints/000001/volumes/agent-output/metadata"
    }
  ]
}
```

Ref:

```text
erebor/checkpoints/000001/manifest
```

## Promotion Commit

A promotion manifest is also an OSTree commit containing only metadata.

```text
work/promotions/000001/manifest/
  erebor-promotion.json
```

Example:

```json
{
  "schema_version": 1,
  "kind": "erebor.filesystem.promotion",
  "promotion_id": "000001",
  "checkpoint_ref": "erebor/checkpoints/000001",
  "volumes": [
    {
      "volume_id": "openclaw-config",
      "host_path": "/home/navid/.config/openclaw",
      "before_ref": "erebor/promotions/000001/volumes/openclaw-config/before",
      "after_ref": "erebor/promotions/000001/volumes/openclaw-config/after",
      "before_metadata_ref": "erebor/volumes/openclaw-config/metadata/base",
      "after_metadata_ref": "erebor/checkpoints/000001/volumes/openclaw-config/metadata"
    },
    {
      "volume_id": "agent-output",
      "host_path": "/home/navid/Downloads/agent-output",
      "before_ref": "erebor/promotions/000001/volumes/agent-output/before",
      "after_ref": "erebor/promotions/000001/volumes/agent-output/after",
      "before_metadata_ref": "erebor/volumes/agent-output/metadata/base",
      "after_metadata_ref": "erebor/checkpoints/000001/volumes/agent-output/metadata"
    }
  ]
}
```

Ref:

```text
erebor/promotions/000001/manifest
```

## Docker Backend

Docker backend setup for each writable directory volume:

1. Import host path to session OSTree repo.
2. Checkout base to `work/volumes/<id>/checkouts/base`.
3. Mount overlay merged path on host.
4. Run Docker with `merged` bind-mounted to the configured session path.
5. Do not mount the real host path into Docker.

Docker mount example:

```text
-v .erebor/sessions/session-123/filesystem/work/volumes/openclaw-config/overlay/merged:/home/navid/.config/openclaw
```

If a Docker container needs a broader workspace, that workspace should be a
separate volume with its own policy. Do not let a broad workspace mount bypass
the filesystem surface for protected paths.

## Linux Host Backend

Linux host backend setup:

1. Create a new mount namespace for the session process.
2. Make mounts private so changes do not leak to the host namespace.
3. Provide required system paths according to the session runner policy.
4. Bind-mount each volume's overlay merged path onto its session path.
5. Start the agent under the process/syscall guard.

The Linux ptrace backend may catch both process and filesystem syscalls, but
the surfaced event semantics should be different:

```text
execve/open process creation -> terminal/process event
openat/read/write/unlink/rename/chmod -> filesystem event
```

The filesystem surface owns file read/write/delete/revert policy. The
terminal/process surface provides initiating context such as command, cwd, pid,
parent pid, and actor.

## Manual Verification: OSTree-Only Flow

This verifies the OSTree refs, layer commit, result commit, promotion, and
rollback logic without requiring an OverlayFS mount. It simulates the overlay
upperdir manually.

Prerequisites:

```sh
command -v ostree
command -v rsync
```

Set up one allowed path:

```sh
export DEMO=/tmp/erebor-fs-ostree-v2-demo
export SESSION_ID=session-manual-001
export VOLUME_ID=openclaw-config
export SESSION_FS="$DEMO/.erebor/sessions/$SESSION_ID/filesystem"
export REPO="$SESSION_FS/repo"
export HOST="$DEMO/host/.config/openclaw"
export WORK="$SESSION_FS/work/volumes/$VOLUME_ID"

rm -rf "$DEMO"
mkdir -p "$HOST"
printf '{"theme":"light","safe":true}\n' > "$HOST/settings.json"
printf 'old-cache\n' > "$HOST/old-cache.txt"
```

Initialize the per-session OSTree repo:

```sh
mkdir -p "$REPO"
ostree --repo="$REPO" init --mode=bare-user
```

Commit the base host state:

```sh
export BASE_REF="erebor/volumes/$VOLUME_ID/base"
ostree --repo="$REPO" commit \
  --branch="$BASE_REF" \
  --subject="Erebor base for $VOLUME_ID" \
  --tree=dir="$HOST"

ostree --repo="$REPO" refs --list
```

Create and commit base metadata sidecar:

```sh
export META_BASE_STAGE="$WORK/staging/metadata-base"
mkdir -p "$META_BASE_STAGE"
(cd "$HOST" && find . -printf '%P\t%y\t%m\t%u\t%g\t%T@\t%l\n' | sort) \
  > "$META_BASE_STAGE/metadata.tsv"

ostree --repo="$REPO" commit \
  --branch="erebor/volumes/$VOLUME_ID/metadata/base" \
  --subject="Erebor base metadata for $VOLUME_ID" \
  --tree=dir="$META_BASE_STAGE"
```

Checkout the base outside the repo:

```sh
export BASE_CHECKOUT="$WORK/checkouts/base"
mkdir -p "$WORK/checkouts"
ostree --repo="$REPO" checkout "$BASE_REF" "$BASE_CHECKOUT"
find "$BASE_CHECKOUT" -type f -print | sort
```

Simulate one agent checkpoint by creating an upperdir:

```sh
export UPPER="$WORK/overlay/upper"
mkdir -p "$UPPER/generated"
printf '{"theme":"dark","safe":true}\n' > "$UPPER/settings.json"
printf 'session-token-placeholder\n' > "$UPPER/generated/token.txt"
```

Create a normalized layer staging tree:

```sh
export CHECKPOINT_ID=000001
export CHECKPOINT_WORK="$SESSION_FS/work/checkpoints/$CHECKPOINT_ID"
export LAYER_STAGE="$CHECKPOINT_WORK/volumes/$VOLUME_ID/layer"
mkdir -p "$LAYER_STAGE/files"
rsync -a "$UPPER"/ "$LAYER_STAGE/files"/

cat > "$LAYER_STAGE/erebor-layer.json" <<EOF
{
  "schema_version": 1,
  "kind": "erebor.filesystem.layer",
  "volume_id": "$VOLUME_ID",
  "checkpoint_id": "$CHECKPOINT_ID",
  "base_ref": "$BASE_REF",
  "parent_layer_ref": null,
  "files_root": "files",
  "changes": [
    {
      "path": "settings.json",
      "operation": "replace_file",
      "content_path": "files/settings.json"
    },
    {
      "path": "generated/token.txt",
      "operation": "create_file",
      "content_path": "files/generated/token.txt"
    },
    {
      "path": "old-cache.txt",
      "operation": "delete"
    }
  ],
  "opaque_directories": [],
  "metadata_ref": "erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_ID/metadata"
}
EOF
```

Commit the layer to OSTree:

```sh
export LAYER_REF="erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_ID/layer"
ostree --repo="$REPO" commit \
  --branch="$LAYER_REF" \
  --subject="Erebor checkpoint $CHECKPOINT_ID layer for $VOLUME_ID" \
  --tree=dir="$LAYER_STAGE"

ostree --repo="$REPO" ls -R "$LAYER_REF"
```

Materialize the result tree by applying the layer manifest:

```sh
export RESULT_STAGE="$CHECKPOINT_WORK/volumes/$VOLUME_ID/result"
rm -rf "$RESULT_STAGE"
mkdir -p "$RESULT_STAGE"
rsync -a "$BASE_CHECKOUT"/ "$RESULT_STAGE"/
rm -f "$RESULT_STAGE/old-cache.txt"
rsync -a "$LAYER_STAGE/files"/ "$RESULT_STAGE"/
find "$RESULT_STAGE" -type f -print | sort
```

Commit result metadata:

```sh
export META_RESULT_STAGE="$CHECKPOINT_WORK/volumes/$VOLUME_ID/metadata"
mkdir -p "$META_RESULT_STAGE"
(cd "$RESULT_STAGE" && find . -printf '%P\t%y\t%m\t%u\t%g\t%T@\t%l\n' | sort) \
  > "$META_RESULT_STAGE/metadata.tsv"

ostree --repo="$REPO" commit \
  --branch="erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_ID/metadata" \
  --subject="Erebor checkpoint $CHECKPOINT_ID metadata for $VOLUME_ID" \
  --tree=dir="$META_RESULT_STAGE"
```

Commit the full result tree:

```sh
export RESULT_REF="erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_ID/result"
ostree --repo="$REPO" commit \
  --branch="$RESULT_REF" \
  --subject="Erebor checkpoint $CHECKPOINT_ID result for $VOLUME_ID" \
  --tree=dir="$RESULT_STAGE"

ostree --repo="$REPO" diff "$BASE_REF" "$RESULT_REF"
```

Create a checkpoint manifest commit:

```sh
export CHECKPOINT_STAGE="$CHECKPOINT_WORK/manifest"
mkdir -p "$CHECKPOINT_STAGE"

cat > "$CHECKPOINT_STAGE/erebor-checkpoint.json" <<EOF
{
  "schema_version": 1,
  "kind": "erebor.filesystem.checkpoint",
  "checkpoint_id": "$CHECKPOINT_ID",
  "volumes": [
    {
      "volume_id": "$VOLUME_ID",
      "base_ref": "$BASE_REF",
      "layer_refs": ["$LAYER_REF"],
      "result_ref": "$RESULT_REF",
      "metadata_ref": "erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_ID/metadata"
    }
  ]
}
EOF

ostree --repo="$REPO" commit \
  --branch="erebor/checkpoints/$CHECKPOINT_ID/manifest" \
  --subject="Erebor checkpoint $CHECKPOINT_ID" \
  --tree=dir="$CHECKPOINT_STAGE"
```

Verify host drift before promotion:

```sh
ostree --repo="$REPO" diff "$BASE_REF" "$HOST" > "$WORK/drift.txt"
test ! -s "$WORK/drift.txt"
```

Commit promotion `before`, promote result to host, then commit promotion
`after`:

```sh
export PROMOTION_ID=000001
export BEFORE_REF="erebor/promotions/$PROMOTION_ID/volumes/$VOLUME_ID/before"
export AFTER_REF="erebor/promotions/$PROMOTION_ID/volumes/$VOLUME_ID/after"

ostree --repo="$REPO" commit \
  --branch="$BEFORE_REF" \
  --subject="Erebor promotion $PROMOTION_ID before $VOLUME_ID" \
  --tree=dir="$HOST"

rsync -a --delete "$RESULT_STAGE"/ "$HOST"/

ostree --repo="$REPO" commit \
  --branch="$AFTER_REF" \
  --subject="Erebor promotion $PROMOTION_ID after $VOLUME_ID" \
  --tree=dir="$HOST"

cat "$HOST/settings.json"
test -f "$HOST/generated/token.txt"
test ! -e "$HOST/old-cache.txt"
```

Create the promotion manifest:

```sh
export PROMOTION_WORK="$SESSION_FS/work/promotions/$PROMOTION_ID"
export PROMOTION_STAGE="$PROMOTION_WORK/manifest"
mkdir -p "$PROMOTION_STAGE"

cat > "$PROMOTION_STAGE/erebor-promotion.json" <<EOF
{
  "schema_version": 1,
  "kind": "erebor.filesystem.promotion",
  "promotion_id": "$PROMOTION_ID",
  "checkpoint_ref": "erebor/checkpoints/$CHECKPOINT_ID/manifest",
  "volumes": [
    {
      "volume_id": "$VOLUME_ID",
      "host_path": "$HOST",
      "before_ref": "$BEFORE_REF",
      "after_ref": "$AFTER_REF",
      "before_metadata_ref": "erebor/volumes/$VOLUME_ID/metadata/base",
      "after_metadata_ref": "erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_ID/metadata"
    }
  ]
}
EOF

ostree --repo="$REPO" commit \
  --branch="erebor/promotions/$PROMOTION_ID/manifest" \
  --subject="Erebor promotion $PROMOTION_ID manifest" \
  --tree=dir="$PROMOTION_STAGE"
```

Rollback:

```sh
export ROLLBACK_CHECKOUT="$PROMOTION_WORK/volumes/$VOLUME_ID/before-checkout"
rm -rf "$ROLLBACK_CHECKOUT"
ostree --repo="$REPO" checkout "$BEFORE_REF" "$ROLLBACK_CHECKOUT"
rsync -a --delete "$ROLLBACK_CHECKOUT"/ "$HOST"/

cat "$HOST/settings.json"
test -f "$HOST/old-cache.txt"
test ! -e "$HOST/generated/token.txt"
```

Expected final host state:

```text
settings.json contains "light"
old-cache.txt exists
generated/token.txt does not exist
```

## Manual Verification: Two-Volume Checkpoint Shape

This is a focused check for the multi-allowed-path structure. It uses one real
OSTree repo, two volume refs, two base checkouts, two OverlayFS mounts, and one
checkpoint manifest that references both volumes.

Set up two allowed paths:

```sh
export DEMO=/tmp/erebor-fs-ostree-v2-multi-demo
export SESSION_ID=session-manual-multi-001
export SESSION_FS="$DEMO/.erebor/sessions/$SESSION_ID/filesystem"
export REPO="$SESSION_FS/repo"
export CHECKPOINT_ID=000001
export CHECKPOINT_WORK="$SESSION_FS/work/checkpoints/$CHECKPOINT_ID"
export SESSION_ROOT="$DEMO/session-root"

export VOLUME_A=openclaw-config
export HOST_A="$DEMO/host/.config/openclaw"
export WORK_A="$SESSION_FS/work/volumes/$VOLUME_A"
export BASE_A="$WORK_A/checkouts/base"
export UPPER_A="$WORK_A/overlay/upper"
export OVERLAY_WORK_A="$WORK_A/overlay/workdir"
export MERGED_A="$WORK_A/overlay/merged"

export VOLUME_B=agent-output
export HOST_B="$DEMO/host/Downloads/agent-output"
export WORK_B="$SESSION_FS/work/volumes/$VOLUME_B"
export BASE_B="$WORK_B/checkouts/base"
export UPPER_B="$WORK_B/overlay/upper"
export OVERLAY_WORK_B="$WORK_B/overlay/workdir"
export MERGED_B="$WORK_B/overlay/merged"

rm -rf "$DEMO"
mkdir -p "$HOST_A" "$HOST_B" "$REPO"
printf '{"theme":"light"}\n' > "$HOST_A/settings.json"
printf 'initial report\n' > "$HOST_B/report.txt"
ostree --repo="$REPO" init --mode=bare-user
```

Commit both bases:

```sh
ostree --repo="$REPO" commit \
  --branch="erebor/volumes/$VOLUME_A/base" \
  --subject="Erebor base for $VOLUME_A" \
  --tree=dir="$HOST_A"

ostree --repo="$REPO" commit \
  --branch="erebor/volumes/$VOLUME_B/base" \
  --subject="Erebor base for $VOLUME_B" \
  --tree=dir="$HOST_B"
```

Check out both base commits outside the repo:

```sh
mkdir -p "$WORK_A/checkouts" "$WORK_B/checkouts"
ostree --repo="$REPO" checkout "erebor/volumes/$VOLUME_A/base" "$BASE_A"
ostree --repo="$REPO" checkout "erebor/volumes/$VOLUME_B/base" "$BASE_B"
```

Mount both overlays. This part requires root privileges on most Linux hosts:

```sh
mkdir -p "$UPPER_A" "$OVERLAY_WORK_A" "$MERGED_A"
mkdir -p "$UPPER_B" "$OVERLAY_WORK_B" "$MERGED_B"

sudo mount -t overlay overlay \
  -o lowerdir="$BASE_A",upperdir="$UPPER_A",workdir="$OVERLAY_WORK_A" \
  "$MERGED_A"

sudo mount -t overlay overlay \
  -o lowerdir="$BASE_B",upperdir="$UPPER_B",workdir="$OVERLAY_WORK_B" \
  "$MERGED_B"
```

The actual volume mapping is:

| Manual host source | Volume id | OSTree base ref | Base checkout | Overlay merged source | Production agent path |
| --- | --- | --- | --- | --- | --- |
| `$HOST_A` | `$VOLUME_A` | `erebor/volumes/openclaw-config/base` | `$BASE_A` | `$MERGED_A` | `/home/navid/.config/openclaw` |
| `$HOST_B` | `$VOLUME_B` | `erebor/volumes/agent-output/base` | `$BASE_B` | `$MERGED_B` | `/home/navid/Downloads/agent-output` |

For a safe manual mount check, use a fake session root under `/tmp` instead of
mounting over the real `/home/navid` paths. The production Linux runner does the
same bind-mount operation inside the agent's private mount namespace, with
`/home/navid/.config/openclaw` and `/home/navid/Downloads/agent-output` as the
targets.

```sh
mkdir -p \
  "$SESSION_ROOT/home/navid/.config/openclaw" \
  "$SESSION_ROOT/home/navid/Downloads/agent-output"

sudo env \
  MERGED_A="$MERGED_A" \
  MERGED_B="$MERGED_B" \
  SESSION_ROOT="$SESSION_ROOT" \
  unshare --mount --fork /bin/sh -c '
    mount --make-rprivate /
    mount --bind "$MERGED_A" "$SESSION_ROOT/home/navid/.config/openclaw"
    mount --bind "$MERGED_B" "$SESSION_ROOT/home/navid/Downloads/agent-output"
    findmnt "$SESSION_ROOT/home/navid/.config/openclaw"
    findmnt "$SESSION_ROOT/home/navid/Downloads/agent-output"
    printf "{\"theme\":\"dark\"}\n" > "$SESSION_ROOT/home/navid/.config/openclaw/settings.json"
    printf "generated report\n" > "$SESSION_ROOT/home/navid/Downloads/agent-output/report.txt"
  '
```

The command above writes through the mounted session paths. The same writes are
visible through the overlay merged paths:

```sh
sudo cat "$MERGED_A/settings.json"
sudo cat "$MERGED_B/report.txt"
```

Verify the real host paths did not change:

```sh
cat "$HOST_A/settings.json"
cat "$HOST_B/report.txt"
```

Expected host contents:

```text
{"theme":"light"}
initial report
```

Unmount and make the upperdirs readable by the current user for the rest of the
manual flow:

```sh
sudo umount "$MERGED_A"
sudo umount "$MERGED_B"
sudo chown -R "$(id -u):$(id -g)" "$UPPER_A" "$UPPER_B"
```

Create per-volume layer and result refs under the same checkpoint id from the
actual overlay upperdirs:

```sh
mkdir -p "$CHECKPOINT_WORK/volumes/$VOLUME_A/layer/files"
rsync -a "$UPPER_A"/ "$CHECKPOINT_WORK/volumes/$VOLUME_A/layer/files"/
cat > "$CHECKPOINT_WORK/volumes/$VOLUME_A/layer/erebor-layer.json" <<EOF
{
  "schema_version": 1,
  "kind": "erebor.filesystem.layer",
  "volume_id": "$VOLUME_A",
  "checkpoint_id": "$CHECKPOINT_ID",
  "base_ref": "erebor/volumes/$VOLUME_A/base",
  "files_root": "files",
  "changes": [
    {
      "path": "settings.json",
      "operation": "replace_file",
      "content_path": "files/settings.json"
    }
  ]
}
EOF

ostree --repo="$REPO" commit \
  --branch="erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_A/layer" \
  --subject="Erebor checkpoint $CHECKPOINT_ID layer for $VOLUME_A" \
  --tree=dir="$CHECKPOINT_WORK/volumes/$VOLUME_A/layer"

mkdir -p "$CHECKPOINT_WORK/volumes/$VOLUME_A/result"
rsync -a "$BASE_A"/ "$CHECKPOINT_WORK/volumes/$VOLUME_A/result"/
rsync -a "$CHECKPOINT_WORK/volumes/$VOLUME_A/layer/files"/ \
  "$CHECKPOINT_WORK/volumes/$VOLUME_A/result"/
ostree --repo="$REPO" commit \
  --branch="erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_A/result" \
  --subject="Erebor checkpoint $CHECKPOINT_ID result for $VOLUME_A" \
  --tree=dir="$CHECKPOINT_WORK/volumes/$VOLUME_A/result"

mkdir -p "$CHECKPOINT_WORK/volumes/$VOLUME_B/layer/files"
rsync -a "$UPPER_B"/ "$CHECKPOINT_WORK/volumes/$VOLUME_B/layer/files"/
cat > "$CHECKPOINT_WORK/volumes/$VOLUME_B/layer/erebor-layer.json" <<EOF
{
  "schema_version": 1,
  "kind": "erebor.filesystem.layer",
  "volume_id": "$VOLUME_B",
  "checkpoint_id": "$CHECKPOINT_ID",
  "base_ref": "erebor/volumes/$VOLUME_B/base",
  "files_root": "files",
  "changes": [
    {
      "path": "report.txt",
      "operation": "replace_file",
      "content_path": "files/report.txt"
    }
  ]
}
EOF

ostree --repo="$REPO" commit \
  --branch="erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_B/layer" \
  --subject="Erebor checkpoint $CHECKPOINT_ID layer for $VOLUME_B" \
  --tree=dir="$CHECKPOINT_WORK/volumes/$VOLUME_B/layer"

mkdir -p "$CHECKPOINT_WORK/volumes/$VOLUME_B/result"
rsync -a "$BASE_B"/ "$CHECKPOINT_WORK/volumes/$VOLUME_B/result"/
rsync -a "$CHECKPOINT_WORK/volumes/$VOLUME_B/layer/files"/ \
  "$CHECKPOINT_WORK/volumes/$VOLUME_B/result"/
ostree --repo="$REPO" commit \
  --branch="erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_B/result" \
  --subject="Erebor checkpoint $CHECKPOINT_ID result for $VOLUME_B" \
  --tree=dir="$CHECKPOINT_WORK/volumes/$VOLUME_B/result"
```

Create one checkpoint manifest that references both volumes:

```sh
mkdir -p "$CHECKPOINT_WORK/manifest"
cat > "$CHECKPOINT_WORK/manifest/erebor-checkpoint.json" <<EOF
{
  "schema_version": 1,
  "kind": "erebor.filesystem.checkpoint",
  "checkpoint_id": "$CHECKPOINT_ID",
  "volumes": [
    {
      "volume_id": "$VOLUME_A",
      "base_ref": "erebor/volumes/$VOLUME_A/base",
      "layer_refs": [
        "erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_A/layer"
      ],
      "result_ref": "erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_A/result"
    },
    {
      "volume_id": "$VOLUME_B",
      "base_ref": "erebor/volumes/$VOLUME_B/base",
      "layer_refs": [
        "erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_B/layer"
      ],
      "result_ref": "erebor/checkpoints/$CHECKPOINT_ID/volumes/$VOLUME_B/result"
    }
  ]
}
EOF

ostree --repo="$REPO" commit \
  --branch="erebor/checkpoints/$CHECKPOINT_ID/manifest" \
  --subject="Erebor checkpoint $CHECKPOINT_ID manifest" \
  --tree=dir="$CHECKPOINT_WORK/manifest"
```

Verify refs:

```sh
ostree --repo="$REPO" refs --list | sort
export CHECKPOINT_VERIFY="$CHECKPOINT_WORK/manifest-checkout"
rm -rf "$CHECKPOINT_VERIFY"
ostree --repo="$REPO" checkout \
  "erebor/checkpoints/$CHECKPOINT_ID/manifest" \
  "$CHECKPOINT_VERIFY"
cat "$CHECKPOINT_VERIFY/erebor-checkpoint.json"
```

Expected shape:

```text
erebor/checkpoints/000001/manifest
erebor/checkpoints/000001/volumes/agent-output/layer
erebor/checkpoints/000001/volumes/agent-output/result
erebor/checkpoints/000001/volumes/openclaw-config/layer
erebor/checkpoints/000001/volumes/openclaw-config/result
erebor/volumes/agent-output/base
erebor/volumes/openclaw-config/base
```

## Manual Verification: Rootful OverlayFS Flow

This verifies that the overlay upperdir captures live agent writes. It usually
requires root privileges for the mount operation.

Run the OSTree-only setup through the base checkout step, then:

```sh
export OVERLAY_DIR="$WORK/overlay"
export UPPER="$OVERLAY_DIR/upper"
export OVERLAY_WORK="$OVERLAY_DIR/workdir"
export MERGED="$OVERLAY_DIR/merged"

mkdir -p "$UPPER" "$OVERLAY_WORK" "$MERGED"
sudo mount -t overlay overlay \
  -o lowerdir="$BASE_CHECKOUT",upperdir="$UPPER",workdir="$OVERLAY_WORK" \
  "$MERGED"
```

Mutate the merged view:

```sh
sudo env MERGED="$MERGED" sh -c '
  printf "{\"theme\":\"dark\",\"safe\":true}\n" > "$MERGED/settings.json"
  mkdir -p "$MERGED/generated"
  printf "session-token-placeholder\n" > "$MERGED/generated/token.txt"
'
```

Verify the lower checkout and host path are unchanged:

```sh
cat "$BASE_CHECKOUT/settings.json"
cat "$HOST/settings.json"
```

Verify the upperdir has the changed files:

```sh
sudo find "$UPPER" -maxdepth 3 -printf '%y %p\n' | sort
```

Unmount before copying the upperdir into a layer stage:

```sh
sudo umount "$MERGED"
sudo chown -R "$(id -u):$(id -g)" "$UPPER"
```

Then continue from the OSTree-only "Create a normalized layer staging tree"
step. For this edit/create-only verification, `rsync -a "$UPPER"/
"$LAYER_STAGE/files"/` is sufficient. A real implementation must normalize
OverlayFS whiteouts and opaque directories as described in the layer format.

Delete verification can be added by deleting a file from `MERGED` before
unmounting and teaching the prototype normalizer to translate the resulting
whiteout into a JSON `delete` operation. Do not commit raw whiteout nodes.

## Implementation Phases

### Phase 1 - Model And Config

Deliverables:

- Add filesystem surface config with explicit allowed roots.
- Add `ExecutionSurface::Filesystem` or equivalent surface identity if the
  event model is split from `Terminal`.
- Keep `ActionKind::FileRead` and `ActionKind::FileWrite`, and add delete,
  rename, metadata, or generic file mutation action kinds if needed.
- Represent filesystem volumes in session state.
- Persist filesystem session state under the session registry directory.

Acceptance:

- Config rejects empty root ids, empty paths, duplicate ids, and paths outside
  policy scope.
- Session state clearly records host path, session path, volume kind, mode, and
  active backend.

### Phase 2 - Session OSTree Repo

Deliverables:

- Initialize one real OSTree repo per session under
  `.erebor/sessions/<id>/filesystem/repo`.
- Import each allowed path as a base commit.
- Commit metadata sidecars as OSTree commits.
- Checkout base commits outside the repo.

Acceptance:

- Manual validation can inspect refs with `ostree refs --list`.
- Deleting the session directory deletes all session-local filesystem revert
  material.
- No overlay directory is created inside the OSTree repo.

### Phase 3 - Overlay Volume Backend

Deliverables:

- For Docker, mount prepared `merged` directories into the container.
- For Linux host, create a mount namespace and bind each `merged` directory to
  its session path.
- Keep real host paths out of the agent writable view.
- Report capability status when overlay mounting is unavailable.

Acceptance:

- Agent writes modify `overlay/upper`, not the host path.
- Host path remains unchanged until promotion.
- Workspace or home-directory broad mounts cannot bypass protected root mounts.

### Phase 4 - Layer Normalization

Deliverables:

- Normalize OverlayFS upperdirs into layer staging trees.
- Translate whiteouts and opaque directories into `erebor-layer.json`.
- Commit normalized layers to OSTree.
- Reject or explicitly policy-gate unsupported special files.

Acceptance:

- Edits, creates, deletes, and directory opacity are represented in layer
  manifests.
- Raw OverlayFS whiteouts are not committed directly.
- Layer commits are inspectable with `ostree ls`.

### Phase 5 - Result Materialization

Deliverables:

- Apply base + layers into result staging trees.
- Commit result trees to OSTree.
- Commit result metadata sidecars.
- Commit checkpoint manifests.

Acceptance:

- `ostree diff base result` shows the expected changed, added, and deleted
  paths.
- Repeated checkpoints can reuse the previous result as the next base or can
  compact layer chains.

### Phase 6 - Promotion And Rollback

Deliverables:

- Detect host drift with `ostree diff base host-path`.
- Commit promotion `before` refs.
- Apply result commits to host paths.
- Commit promotion `after` refs and promotion manifests.
- Implement rollback from promotion `before` refs.

Acceptance:

- Promotion is blocked or mediated when host drift is detected.
- Rollback restores file contents and supported exact metadata.
- Promotion and rollback produce audit records linked to the session,
  checkpoint, volume ids, and refs.

## Open Decisions

- Whether v2 starts with directory volumes only or includes single-file bind
  mounts.
- Whether privileged Linux installs use `bare`, `bare-user`, or
  `bare-split-xattrs`.
- How much exact metadata is required for the first buyer-visible claim.
- Whether result commits are created at every checkpoint or only before
  promotion.
- Whether long-running sessions should reset the overlay upperdir after each
  successful checkpoint.
- How filesystem read allow/deny is enforced in the first Linux backend:
  mount namespace only, ptrace syscall authorization, fanotify permission
  events, BPF LSM, FUSE, or a staged combination.

## Non-Goals

- Do not fork OverlayFS for v2.
- Do not implement arbitrary per-action revert as the default guarantee.
- Do not use a single global OSTree repo for all sessions.
- Do not mount the user's whole home directory writable and rely on policy after
  the fact.
- Do not commit raw OverlayFS working directories directly into OSTree.
- Do not silently merge external host drift during promotion.

## Acceptance Criteria

- One allowed directory can be imported into a per-session OSTree repo.
- The base commit can be checked out outside the repo and used as overlay
  lowerdir.
- Agent writes land in overlay upperdir.
- A normalized layer commit can be created from the upperdir.
- A full result commit can be materialized from base + layer.
- A checkpoint manifest can tie result, layer, and metadata refs together.
- Promotion applies the result to the host only after drift detection.
- Rollback restores the pre-promotion host state.
- The manual verification commands in this document can reproduce the core
  flow on a Linux host with `ostree` installed, and the overlay-specific section
  can be verified where rootful OverlayFS mounts are available.
