# Live Lifecycle Probe

Status: Draft. Required for every implementation phase after Phase 0.

## Purpose

Prove that each phase works in a real governed Linux-host session, not only in
unit tests.

The probe must evolve with the implementation. A phase may only claim the parts
that exist after that phase, but it must keep all earlier assertions passing.

## Host Requirements

The full probe requires:

- Linux x86_64 host
- ptrace allowed for Erebor's Linux process guard
- Linux namespace and kernel OverlayFS mount capability. The Phase 5
  implementation first tries `unshare -U --map-current-user --keep-caps -m`
  so the governed command keeps the current session uid while mount setup has
  namespace capabilities. A mount-capable runtime path may also create mounts,
  but the governed session command must not run as root.
- `ostree`
- `findmnt`
- `stat`
- `rg`

If the host cannot run ptrace or Linux namespace/OverlayFS mount operations,
the implementation phase is blocked for lifecycle verification. Unit tests are
not a substitute for the lifecycle probe.

## Phase Assertion Matrix

| Phase | Required lifecycle proof |
| --- | --- |
| Phase 1 | Existing terminal/process lifecycle still works; filesystem config parses and appears in session plan diagnostics. |
| Phase 2 | Synthetic broker file-operation routing reaches the filesystem handler and writes auditable allow/deny decisions. |
| Phase 3 | Real Linux `cat` causes `file_read` denial and real shell redirection causes `file_mutation` denial through filesystem policy. |
| Phase 4 | Session filesystem storage layout is created under the prepared session and no host tree copy is made. |
| Phase 4a | Corrective carry-forward: real read denial, real mutation denial, and Phase 4 storage proof are all represented in checked tests and docs. |
| Phase 5 | The agent sees the overlay merged path; writes do not mutate the host path before promotion; attempts to use the raw host path cannot bypass the overlay. |
| Phase 6 | Upperdir changes normalize into a layer manifest with create, replace, and delete operations after the session is quiesced and no writer has an active fd in the merged mount. |
| Phase 7 | OSTree layer/checkpoint refs are committed and no `base` ref exists. |
| Phase 8 | Promotion stores preimages before host mutation; promotion applies committed checkpoint-layer bytes; rollback restores exact content for the one-volume case from committed preimage refs even after mutable promotion work files are removed. |
| Phase 9 | Two volumes promote and roll back together; failure in one volume blocks all host mutation. |
| Phase 10 | Transactions and subtransactions are listable, showable, renameable, and rollbackable through the approved operator workflow; rollback uses committed refs after mutable work files are removed, writes audit evidence, and has a documented repeat-run outcome. |
| Phase 11 | Supported Linux metadata and safe xattrs are restored exactly; unsupported metadata blocks before host mutation with audit evidence. |
| Phase 12 | Opaque directories promote and roll back exact hidden lower subtrees, or block before host mutation when the hidden preimage is unsafe or too large. |
| Phase 13 | Large preimages either use the reflink CoW backend or block before host mutation with a clear exact-rollback reason. |
| Phase 14 | Retention/list/prune operations preserve refs required for rollback, and rollback still works after safe pruning. |
| Phase 15 | User-issued session-work transactions and config-driven autocommit transactions are quiesced, carry lineage metadata, reject active writers, and can be reverted according to the approved semantics. |
| Phase 16 | No runtime behavior is added; lifecycle requirements are written for every approved backend phase before implementation starts. |
| Phase 17 | Rootless `fuse-overlayfs` support detection runs first, then the same direct OverlayFS success/failure/rollback story passes through an Erebor-owned FUSE merged view without making it the default backend. |
| Phase 18 | Docker/OCI support detection runs first, then a governed containerized session proves the same multi-volume success/failure/rollback story through Erebor-owned mount/volume paths without relying on Docker `overlay2` internals. |
| Phase 19 | Btrfs support detection runs first, then a configured Btrfs test path proves snapshot creation, retained snapshot identity, promotion refusal behavior, and rollback according to the approved backend contract. |
| Phase 20 | ZFS support detection runs first, then a configured ZFS test dataset proves snapshot creation, retained snapshot identity, promotion refusal behavior, and rollback according to the approved backend contract. |
| Phase 21 | macOS support detection runs first, then the native macOS filesystem surface proves governed reads, writes, session-work commit, promotion, and rollback with native metadata semantics. |
| Phase 22 | Windows support detection runs first, then the native Windows filesystem surface proves governed reads, writes, session-work commit, promotion, and rollback with Windows identity, ACL, ADS, and reparse-point semantics. |

## Checked Phase 5 Probe

Phase 5 added gated lifecycle tests that perform real Linux namespace and
OverlayFS mounts. They are intentionally opt-in so the default test suite does
not attempt host mount operations.

Run them with:

```sh
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_session_view -- --test-threads=1 --nocapture
```

If `ostree` is not installed in the default `PATH`, prepend the path that
contains it, for example:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_session_view -- --test-threads=1 --nocapture
```

## Checked Phase 6 And 7 Probe

Phase 6 added a gated lifecycle test that performs a real governed Linux-host
overlay session, then asserts the normalized `erebor-layer.json` contains
replace, delete, and create operations without raw whiteout marker content.
Phase 7 extended the same test to assert OSTree checkpoint refs, no V3 `base`
ref, committed layer content, and a committed checkpoint manifest.

Run it with:

```sh
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_layer_manifest -- --test-threads=1 --nocapture
```

If `ostree` is not installed in the default `PATH`, prepend the path that
contains it, for example:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_layer_manifest -- --test-threads=1 --nocapture
```

## Checked Phase 8 Probe

Phase 8 added a gated lifecycle test that performs a real governed Linux-host
overlay session with promotion enabled. It asserts the host receives promoted
replace, delete, and create operations only after preimage/promotion refs exist,
deletes the mutable local promotion work directory, then calls the filesystem
crate rollback API and verifies the host is restored to the original one-volume
state from committed rollback artifacts.

Run it with:

```sh
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_promotion_rollback -- --test-threads=1 --nocapture
```

If `ostree` is not installed in the default `PATH`, prepend the path that
contains it, for example:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle linux_host::overlay_promotion_rollback -- --test-threads=1 --nocapture
```

The checked Phase 8 rollback exposure is the crate API
`erebor_runtime_filesystem::rollback_promotion(...)`, exercised by the
lifecycle test. A transaction catalog and rollback operator workflow remain a
future explicit decision.

## Checked Phase 9 Probe

Phase 9 added gated lifecycle tests for two writable volumes. The success case
performs a real governed Linux-host session where filesystem policy denies a
`blocked.txt` mutation, then allows overlay writes in both `project` and
`cache`. The test asserts checkpoint and promotion refs for both volumes,
removes the local mutable promotion work directory, calls the filesystem crate
rollback API, and verifies both host directories are restored.

The failure case performs a second real governed Linux-host session where
`project` has a valid pending mutation but `cache` contains an unsupported
socket preimage. Promotion fails through the filesystem surface, and the test
asserts the `project` host mutation did not happen.

Run the Phase 9 multi-volume probe with:

```sh
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle overlay_multivolume -- --test-threads=1 --nocapture
```

If `ostree` is not installed in the default `PATH`, prepend the path that
contains it, for example:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle overlay_multivolume -- --test-threads=1 --nocapture
```

The full carry-forward lifecycle probe is:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle -- --test-threads=1 --nocapture
```

## Phase 9 Full Manual Probe

This manual probe is intentionally more verbose than the automated tests. It is
the human-readable lifecycle proof for the current Linux V3 shape:

- one real CLI-governed session with two writable volumes;
- filesystem policy denial and audit;
- allowed overlay writes in both volumes;
- checkpoint refs, promotion refs, layer content, preimage manifests, and
  promotion manifest inspection;
- promoted host state for both volumes;
- one real CLI-governed failure session where a later `cache` preimage failure
  blocks an earlier valid `project` mutation from reaching the host.

Rollback is still not a CLI command. The manual CLI probe therefore stops at
promoted host state for the success path. Rollback is proven by the checked
Rust lifecycle test, which reconstructs `FilesystemSessionStorage`, deletes the
mutable local promotion work directory, calls
`erebor_runtime_filesystem::rollback_promotion(...)`, and verifies both host
directories are restored from committed preimage refs.

```sh
set -eu

if ! command -v ostree >/dev/null 2>&1; then
  export PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH
fi

command -v ostree
command -v findmnt
command -v rg
unshare -U --map-current-user --keep-caps -m true >/dev/null 2>&1 || true

probe_dir="$(mktemp -d /tmp/erebor-fs-phase9.XXXXXX)"
success_root="$probe_dir/success"
failure_root="$probe_dir/failure"

run_success_probe() {
  host_root="$success_root/host"
  workspace="$success_root/workspace"
  project="$host_root/project"
  cache="$host_root/cache"
  mkdir -p "$workspace/project" "$workspace/cache" "$project" "$cache"
  printf 'light\n' > "$project/settings.txt"
  printf 'old cache\n' > "$project/old-cache.txt"
  printf 'cold\n' > "$cache/cache.txt"
  printf 'stale\n' > "$cache/stale.bin"

  cat >"$success_root/policy.json" <<'JSON'
{
  "rules": [
    {
      "id": "deny-blocked-project",
      "match": {
        "surface": "filesystem",
        "action": "file_mutation",
        "target_contains": "blocked.txt"
      },
      "decision": "deny",
      "reason": "blocked project writes are denied"
    }
  ]
}
JSON

  cat >"$success_root/config.json" <<JSON
{
  "policies": ["$success_root/policy.json"],
  "session": {
    "enabled": true,
    "actor": { "id": "filesystem-probe", "kind": "agent" },
    "workspace": "$workspace",
    "runner": { "kind": "linux_host" },
    "interception": {
      "enabled": true,
      "backend": "linux_ptrace",
      "operations": ["process_exec", "file_open", "file_read", "file_mutation"]
    }
  },
  "surfaces": {
    "terminal": { "enabled": true },
    "filesystem": {
      "enabled": true,
      "backend": { "kind": "linux_ostree_overlay" },
      "volumes": [
        {
          "id": "project",
          "host_path": "$project",
          "session_path": "$workspace/project",
          "mode": "writable"
        },
        {
          "id": "cache",
          "host_path": "$cache",
          "session_path": "$workspace/cache",
          "mode": "writable"
        }
      ],
      "revert": {
        "promote_on_session_finish": true,
        "retain_layers": true,
        "preimage_size_limit_bytes": 104857600
      }
    }
  }
}
JSON

  cargo run -p erebor-runtime-cli -- \
    session run \
    --runner linux-host \
    --config "$success_root/config.json" \
    -- sh -lc '
      cd project
      rg light settings.txt
      if printf blocked > blocked.txt; then exit 41; fi
      printf dark > settings.txt
      rm old-cache.txt
      mkdir -p generated
      printf token > generated/token.txt
      cd ../cache
      rg cold cache.txt
      printf warm > cache.txt
      rm stale.bin
      mkdir -p warmed
      printf index > warmed/index.txt
    '

  session_dir="$(find "$workspace/.erebor/sessions" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  session_id="$(basename "$session_dir")"
  repo="$session_dir/filesystem/repo"
  checkpoint_ref="erebor/checkpoints/$session_id/manifest"
  project_layer_ref="erebor/checkpoints/$session_id/volumes/project/layer"
  cache_layer_ref="erebor/checkpoints/$session_id/volumes/cache/layer"
  promotion_ref="erebor/promotions/$session_id/manifest"
  project_preimage_ref="erebor/promotions/$session_id/volumes/project/preimage"
  cache_preimage_ref="erebor/promotions/$session_id/volumes/cache/preimage"

  rg -n 'deny-blocked-project' "$session_dir/audit.jsonl"
  ! test -e "$project/blocked.txt"

  ostree --repo="$repo" refs --list | tee "$success_root/refs.txt"
  rg "^$checkpoint_ref$" "$success_root/refs.txt"
  rg "^$project_layer_ref$" "$success_root/refs.txt"
  rg "^$cache_layer_ref$" "$success_root/refs.txt"
  rg "^$promotion_ref$" "$success_root/refs.txt"
  rg "^$project_preimage_ref$" "$success_root/refs.txt"
  rg "^$cache_preimage_ref$" "$success_root/refs.txt"
  ! rg '/base$' "$success_root/refs.txt"

  ostree --repo="$repo" cat "$checkpoint_ref" /erebor-checkpoint.json \
    | tee "$success_root/checkpoint.json"
  rg '"volume_id": "project"' "$success_root/checkpoint.json"
  rg '"volume_id": "cache"' "$success_root/checkpoint.json"

  ostree --repo="$repo" cat "$promotion_ref" /erebor-promotion.json \
    | tee "$success_root/promotion.json"
  rg '"state": "applied"' "$success_root/promotion.json"
  rg '"preimage_ref": "erebor/promotions/.*/volumes/project/preimage"' "$success_root/promotion.json"
  rg '"preimage_ref": "erebor/promotions/.*/volumes/cache/preimage"' "$success_root/promotion.json"

  ostree --repo="$repo" cat "$project_layer_ref" /erebor-layer.json \
    | tee "$success_root/project-layer.json"
  ostree --repo="$repo" cat "$cache_layer_ref" /erebor-layer.json \
    | tee "$success_root/cache-layer.json"
  rg '"op": "replace"' "$success_root/project-layer.json"
  rg '"path": "settings.txt"' "$success_root/project-layer.json"
  rg '"op": "delete"' "$success_root/project-layer.json"
  rg '"path": "old-cache.txt"' "$success_root/project-layer.json"
  rg '"op": "replace"' "$success_root/cache-layer.json"
  rg '"path": "cache.txt"' "$success_root/cache-layer.json"
  rg '"op": "delete"' "$success_root/cache-layer.json"
  rg '"path": "stale.bin"' "$success_root/cache-layer.json"

  ostree --repo="$repo" cat "$project_layer_ref" /files/settings.txt | rg '^dark$'
  ostree --repo="$repo" cat "$project_layer_ref" /files/generated/token.txt | rg '^token$'
  ostree --repo="$repo" cat "$cache_layer_ref" /files/cache.txt | rg '^warm$'
  ostree --repo="$repo" cat "$cache_layer_ref" /files/warmed/index.txt | rg '^index$'

  ostree --repo="$repo" cat "$project_preimage_ref" /erebor-preimage.json \
    | tee "$success_root/project-preimage.json"
  ostree --repo="$repo" cat "$cache_preimage_ref" /erebor-preimage.json \
    | tee "$success_root/cache-preimage.json"
  rg '"path": "settings.txt"' "$success_root/project-preimage.json"
  rg '"path": "old-cache.txt"' "$success_root/project-preimage.json"
  rg '"path": "generated/token.txt"' "$success_root/project-preimage.json"
  rg '"path": "cache.txt"' "$success_root/cache-preimage.json"
  rg '"path": "stale.bin"' "$success_root/cache-preimage.json"
  rg '"path": "warmed/index.txt"' "$success_root/cache-preimage.json"

  cat "$project/settings.txt" | rg '^dark$'
  test ! -e "$project/old-cache.txt"
  cat "$project/generated/token.txt" | rg '^token$'
  cat "$cache/cache.txt" | rg '^warm$'
  test ! -e "$cache/stale.bin"
  cat "$cache/warmed/index.txt" | rg '^index$'

  findmnt --mountpoint "$workspace/project" >/dev/null 2>&1 && exit 42 || true
  findmnt --mountpoint "$workspace/cache" >/dev/null 2>&1 && exit 43 || true

  printf '%s\n' "$session_id" > "$success_root/session-id.txt"
}

run_failure_probe() {
  host_root="$failure_root/host"
  workspace="$failure_root/workspace"
  project="$host_root/project"
  cache="$host_root/cache"
  mkdir -p "$workspace/project" "$workspace/cache" "$project" "$cache"
  printf 'light\n' > "$project/settings.txt"
  printf 'cold\n' > "$cache/cache.txt"

  python3 - "$cache/stale.sock" <<'PY' &
import socket
import sys
import time

sock = socket.socket(socket.AF_UNIX)
sock.bind(sys.argv[1])
time.sleep(120)
PY
  socket_pid=$!
  trap 'kill "$socket_pid" 2>/dev/null || true' EXIT
  while ! test -S "$cache/stale.sock"; do
    sleep 0.05
  done

  cat >"$failure_root/policy.json" <<'JSON'
{ "rules": [] }
JSON

  cat >"$failure_root/config.json" <<JSON
{
  "policies": ["$failure_root/policy.json"],
  "session": {
    "enabled": true,
    "actor": { "id": "filesystem-probe", "kind": "agent" },
    "workspace": "$workspace",
    "runner": { "kind": "linux_host" },
    "interception": {
      "enabled": true,
      "backend": "linux_ptrace",
      "operations": ["process_exec", "file_open", "file_read", "file_mutation"]
    }
  },
  "surfaces": {
    "terminal": { "enabled": true },
    "filesystem": {
      "enabled": true,
      "backend": { "kind": "linux_ostree_overlay" },
      "volumes": [
        {
          "id": "project",
          "host_path": "$project",
          "session_path": "$workspace/project",
          "mode": "writable"
        },
        {
          "id": "cache",
          "host_path": "$cache",
          "session_path": "$workspace/cache",
          "mode": "writable"
        }
      ],
      "revert": {
        "promote_on_session_finish": true,
        "retain_layers": true,
        "preimage_size_limit_bytes": 104857600
      }
    }
  }
}
JSON

  set +e
  failure_output="$(
    cargo run -p erebor-runtime-cli -- \
      session run \
      --runner linux-host \
      --config "$failure_root/config.json" \
      -- sh -lc 'cd project && printf dark > settings.txt && cd ../cache && rm stale.sock' 2>&1
  )"
  failure_status=$?
  set -e
  test "$failure_status" -ne 0
  printf '%s\n' "$failure_output" | tee "$failure_root/failure-output.txt"
  rg 'unsupported special file|FilesystemSurface|preimage path' "$failure_root/failure-output.txt"

  session_dir="$(find "$workspace/.erebor/sessions" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
  session_id="$(basename "$session_dir")"
  repo="$session_dir/filesystem/repo"
  ostree --repo="$repo" refs --list | tee "$failure_root/refs.txt"
  rg "^erebor/checkpoints/$session_id/manifest$" "$failure_root/refs.txt"
  ! rg "^erebor/promotions/$session_id/manifest$" "$failure_root/refs.txt"
  cat "$project/settings.txt" | rg '^light$'
  test -S "$cache/stale.sock"

  kill "$socket_pid" 2>/dev/null || true
  trap - EXIT
}

run_success_probe
run_failure_probe

printf 'Phase 9 manual probe passed: %s\n' "$probe_dir"
```

Run the checked Rust rollback proof after the manual CLI probe:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle overlay_multivolume -- --test-threads=1 --nocapture
```

Checked on July 5, 2026:

- Manual CLI probe result: passed outside the sandbox.
- Probe workspace: `/tmp/erebor-fs-phase9.qzZZVh`.
- Success session id: `session-342411`.
- Failure session id: `session-343073`.
- The success probe verified:
  - denied `blocked.txt` mutation in filesystem audit;
  - checkpoint refs for `project` and `cache`;
  - promotion manifest plus preimage refs for both volumes;
  - layer manifests and layer content for replace/delete/create operations in
    both volumes;
  - preimage manifests for present and absent paths in both volumes;
  - promoted host state in both volumes;
  - session paths were not left mounted.
- The failure probe verified:
  - the CLI failed with
    `preimage path \`stale.sock\` is an unsupported special file`;
  - the checkpoint manifest ref existed;
  - the `project` preimage ref may exist because it is committed before the
    later `cache` failure;
  - no promotion manifest ref existed;
  - the `project` host file still contained `light`;
  - the host socket still existed.
- Checked Rust rollback proof after hardening:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle overlay_multivolume -- --test-threads=1 --nocapture
```

  - Result: 2 passed, 0 failed.

## Phase 10 Probe Growth

Phase 10 replaced the crate-only rollback proof with a transaction catalog and
operator workflow.

The checked probe now:

- runs a real two-volume promoted session;
- deletes mutable local promotion work files before rollback;
- invokes `erebor filesystem transactions list` and verifies one parent
  transaction with two volume subtransactions;
- invokes `erebor filesystem transactions show` for the parent and
  both subtransactions and verify changed paths are visible;
- renames one subtransaction and verifies the custom name appears while immutable
  ids remain stable;
- rolls back one subtransaction by generated or renamed handle and verifies only
  that volume is restored while the other volume remains promoted;
- rolls back the remaining transaction/subtransaction and verifies both host
  volumes are restored from committed promotion/preimage refs;
- verifies catalog metadata and JSONL journal entries for rename/rollback,
  including promotion id, outcomes, and committed manifest/preimage refs;
- reruns rollback for an already-restored subtransaction and verifies the
  documented idempotent or fail-closed outcome;
- keeps the Phase 9 multi-volume promotion-failure proof passing.

Automated lifecycle command:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle transaction_catalog -- --test-threads=1 --nocapture
```

Result: 1 passed, 0 failed.

## Planned Phase 11 Probe Growth

Phase 11 must add a metadata exactness case to the live lifecycle suite.

The checked probe must:

- seed host files and directories with non-default modes and mtimes;
- seed a safe `user.erebor_probe` xattr when the host supports user xattrs;
- include a symlink case with an explicit target assertion;
- promote and roll back replace, delete, and create operations;
- verify every metadata class that OSTree and the current host privileges can
  faithfully round-trip after rollback;
- run metadata cases that OSTree or current privileges cannot restore exactly
  and prove they fail closed before host mutation with audit evidence.

## Phase 12 Probe Growth

Phase 12 adds a gated lifecycle test for opaque directory behavior with a real
OverlayFS upperdir marker, not only synthetic manifests.

The probe:

- seed a host directory with nested children;
- run a governed session that replaces that directory tree and produces an
  opaque marker;
- verify the layer manifest records the opaque directory operation;
- verify promotion replaces the visible host subtree;
- verify rollback restores the hidden lower subtree and removes new children;
- relies on filesystem crate tests for the too-small hidden preimage failure
  and unsupported-special-hidden-preimage failure.

Automated lifecycle command:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle opaque -- --test-threads=1 --nocapture
```

Checked in the current sandbox on July 5, 2026:

- Result: 1 passed, 0 failed.
- The checked test was
  `linux_host_opaque_directory_promotion_and_rollback_restore_host`.
- The probe used real Linux-host interception and OverlayFS lifecycle flags.
- A first run failed because the host filesystem was at 98% usage and OSTree's
  default `core.min-free-space-percent=3` reserve refused a tiny checkpoint
  commit despite enough absolute free space. Erebor-created repos now configure
  `core.min-free-space-percent=0`, and the lifecycle probe passes with that
  repo configuration.

## Phase 13 Probe Result

Phase 13 makes large-file exactness visible in the lifecycle output.

The checked probe now:

- records host reflink capability detection output;
- configures a small `preimage_size_limit_bytes`;
- replaces a host file larger than that limit;
- proves promotion blocks before host mutation when the byte backend cannot
  store the preimage within the configured budget;
- runs reflink-backend lifecycle cases and, when the host reports unsupported
  reflink, skips the success branch with explicit capability output;
- covers backend artifact drift/loss fail-closed behavior through committed
  Rust tests that exercise the same rollback validation path.

Checked in the current sandbox on July 6, 2026:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle large_file -- --test-threads=1 --nocapture
```

- Result: 3 passed, 0 failed.
- The checked tests were:
  - `linux_host_large_file_without_reflink_blocks_promotion_before_host_mutation`
  - `linux_host_large_file_reflink_promotion_and_rollback`
  - `linux_host_large_file_reflink_artifact_drift_blocks_rollback`
- Host capability output reported reflink unsupported for the lifecycle
  workspaces on this ext4 host.
- Direct host probing also showed `cp --reflink=always` fails in `/tmp` with
  `Operation not supported`.
- Because reflink was unsupported, the live lifecycle proved the required
  large-file refusal path and did not claim reflink promotion success on this
  host.

## Phase 14 Probe Result

Phase 14 makes retention and pruning operationally testable through
`linux_host_retention_cli_prunes_restored_session_without_breaking_protected_rollback`.

The checked probe now:

- runs two promoted sessions in one workspace;
- lists retained transactions, subtransactions, checkpoint refs, promotion
  refs, and local artifacts with `filesystem retention list`;
- proves both sessions' rollback refs exist with `ostree refs --list`;
- attempts to prune the still-applied session and verifies the CLI fails with a
  protected-target error;
- rolls back one session, prunes that restored transaction through
  `filesystem retention prune tx@{0}`, and verifies its refs are gone;
- records retention prune events in
  `filesystem/retention/erebor-retention.jsonl`;
- runs `ostree prune --no-prune` before and after the safe prune operation;
- rolls back the protected second session after the prune path has run.

Verification:

```sh
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle retention -- --test-threads=1 --nocapture

PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle retention -- --test-threads=1 --nocapture
```

Result:

- The non-opt-in probe registers and skips unless
  `EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1` is set.
- The real lifecycle probe passed with the required environment outside the
  sandbox. The sandboxed run failed before the test body could prove retention
  because the runtime interception broker hit `Operation not permitted`.

## Checked Phase 15 Probe

Phase 15 added a gated lifecycle test for session-work transactions. It uses a
real governed Linux-host OverlayFS session with `promote_on_session_finish =
false` and a config-defined `session_finish` autocommit rule. The test then
uses the CLI against the session registry to exercise explicit user commit,
list/show, name lookup, active-writer refusal, and overlay-state rollback.

Run it with:

```sh
EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle session_work_transaction -- --test-threads=1 --nocapture
```

If `ostree` is not installed in the default `PATH`, prepend the path that
contains it, for example:

```sh
PATH=/tmp/erebor-ostree-deb.JOW1pw/root/usr/bin:$PATH \
  EREBOR_REQUIRE_FILESYSTEM_LIFECYCLE=1 \
  EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1 \
  cargo test -p erebor-runtime-session --test filesystem_surface_lifecycle session_work_transaction -- --test-threads=1 --nocapture
```

The checked probe verifies:

- config-driven `session_finish` autocommit writes
  `erebor/session-work/<session-id>/<session-id>.work-000001/manifest`;
- the session-work manifest records `source = autocommit`, the configured rule
  id, no parent for the first transaction, checkpoint ref, and volume layer
  refs;
- the host path is not promoted by session-work autocommit;
- `filesystem transactions list` and `show work@{0}` expose the autocommitted
  transaction and changed paths;
- `filesystem transactions commit --name ...` creates an explicit user
  transaction from the current session upperdir;
- a held writer fd causes explicit commit to fail closed with the active-writer
  reason from the normalizer;
- `filesystem transactions rollback work@{1}` restores overlay upperdir state
  to the autocommitted transaction and leaves host state untouched.

Result:

- The non-opt-in probe registers and skips unless
  `EREBOR_RUN_FILESYSTEM_OVERLAY_LIFECYCLE=1` is set.
- The sandboxed opt-in probe failed before lifecycle proof because the runtime
  interception broker hit `Operation not permitted`.
- The real opt-in lifecycle probe passed outside the sandbox with the required
  environment.

## Checked Phase 16 Decision Gate

Phase 16 is a planning phase for backend expansion inside this plan. It does
not add runtime behavior or a runnable lifecycle test by itself.

Every backend-expansion phase must add a real lifecycle probe before claiming
implementation success. A host skip is valid only when support detection fails
before the backend smoke test starts. Once support detection succeeds, the
phase must either pass the lifecycle story or report the exact failing command
and host error.

Backend support detection requirements:

- Phase 17 rootless `fuse-overlayfs`: find `fuse-overlayfs`, find
  `fusermount3` or `fusermount`, verify `/dev/fuse` is usable, and run a smoke
  mount/unmount before the governed session.
- Phase 18 Docker/OCI: verify the selected runtime is reachable, verify the
  approved image or rootfs can start, verify Erebor can inject the governed
  session mount/volume paths, and verify cleanup after a no-op session.
- Phase 19 Btrfs: verify the configured test path is Btrfs, verify the current
  process can create and remove a test subvolume/snapshot, and verify retained
  snapshot artifacts can be listed.
- Phase 20 ZFS: verify `zfs` tooling and a configured test dataset exist,
  verify the current process can create and destroy a test snapshot, and verify
  retained snapshot artifacts can be listed.
- Phase 21 macOS: verify the host OS and filesystem support the selected
  native backend, verify required entitlements or privileges are available,
  and run a no-op governed filesystem session before mutation tests.
- Phase 22 Windows: verify the host OS, filesystem type, privileges, and
  selected native backend capability, then run a no-op governed filesystem
  session before mutation tests.

All backend phases must carry forward these lifecycle stories unless the phase
document explicitly narrows the backend to a different approved contract:

- real read and mutation policy decisions are audited;
- writes do not mutate the protected host path before promotion;
- raw-host-path bypass attempts fail closed or are impossible by construction;
- committed transaction, promotion, and preimage artifacts remain inspectable;
- rollback works after mutable work files are removed;
- unsupported metadata, hidden subtree, large preimage, or backend artifact
  states block before host mutation with an auditable reason.

## Required Reporting

For every implementation phase after Phase 0, report:

- probe workspace path
- whether the existing terminal/process lifecycle still passed
- whether filesystem config/session setup passed
- whether real file syscall interception passed, once implemented
- whether real file mutation denial passed, once implemented
- whether overlay writes avoided host mutation before promotion, once
  implemented
- whether raw-host-path bypass prevention passed, once implemented
- whether OSTree refs existed and no base ref existed, once implemented
- whether promotion and rollback passed, once implemented
- whether transaction list/show/rename and rollback used the approved operator
  workflow, once implemented
- whether supported metadata/xattrs restored exactly, once implemented
- whether opaque directory support or refusal passed, once implemented
- whether large-file/CoW exactness or refusal passed, once implemented
- whether retention/prune protected rollback refs, once implemented
- whether session-work transaction/autocommit quiescence passed, once
  implemented
- whether backend support detection passed or skipped, once backend expansion
  phases start
- which backend smoke test command passed before the full lifecycle probe, once
  backend expansion phases start
- exact host error if ptrace, mount, or OSTree blocked the probe
