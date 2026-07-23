# Phase 6: Mount Topology Admission And Bypass Closure

Status: Proposed. Blocked on Phase 5 and explicit implementation approval.

## Purpose

Make the merged view the enforced filesystem path for newly launched macOS
sessions and close direct-path, descriptor, alias, and backing-store bypasses.

## Scope

- Add a `macos-host` session runner sibling to the existing `linux-host` and
  Docker runners. Do not rename or weaken the existing Linux runner.
- Make the runner acquire the filesystem view before spawning any governed
  process and release it only after the process tree is quiesced.
- Implement the Phase 0-selected topology:
  - exclusive path takeover acquires a durable exclusive workspace lease and
    covers the host path with the verified mount;
  - stable session path launches with its working directory and configured
    volume paths rewritten to the verified mount.
- Reject adopt mode for strict FSKit overlay sessions. The runner must not claim
  that attaching to an existing PID changes its cwd, descriptors, mappings, or
  watchers.
- Close all inherited descriptors except the explicit launch allowlist and
  verify the child cwd resolves inside the expected mount identity.
- Pass mount identity and epoch to runtime admission; reject launch when mount,
  native host, FSKit extension, or access guard health is stale.
- Implement or integrate the real Endpoint Security filesystem access guard
  proven in Phase 0.
- For governed process trees, allow writes only to configured merged mount
  identities and explicit non-filesystem-surface exceptions; deny writes to
  original workspace aliases, backing roots, mount-control resources, and
  out-of-policy paths.
- For every process, protect private lower/upper/meta/preimage/control roots;
  allow only exact signed Erebor lifecycle components for their required
  operations.
- Bind decisions to audit token/process identity, code identity requirements,
  session epoch, filesystem ID, and resolved object/path data. UID or basename
  alone is insufficient.
- Clear Endpoint Security decision caches on policy/epoch changes and handle
  deadlines fail closed.
- Detect host baseline drift caused by unrelated processes and preserve that
  evidence for Phase 7; do not silently overwrite it during promotion.
- Audit mount admission, process launch, every guard denial, guard timeout,
  health loss, process exit, and lease release.

## Bypass Matrix

Required negative cases include:

- open the configured host path before and after mount;
- use a saved cwd or directory/file descriptor from before mount;
- use `..`, symlinks, hardlinks, aliases, `/private` path variants, case and
  Unicode variants, and file-ID-based access where APIs permit it;
- discover or access the private backing path;
- spawn a child, helper, shell, IDE extension host, build tool, or detached
  process;
- launch after killing the FSKit extension, native host, or Endpoint Security
  guard;
- race unmount, freeze, policy reload, and process exec;
- attempt access from an ungoverned same-UID process.

The guard must distinguish FSKit's own backing I/O from a governed process's
direct backing access using the verified originating-process evidence from
Phase 0.

## Tests

- Core config and command-plan tests cover the new macOS runner and reject
  unsupported combinations/adoption.
- Native guard tests cover the event/operation matrix, identity rules, cache
  invalidation, deadline behavior, and protected roots.
- Real e2e launches a process tree through the macOS runner and proves allowed
  merged writes plus denied bypass attempts with audit evidence.
- Crash tests prove no new launch succeeds after loss of any required health
  component.
- Existing Linux-host and Docker runner tests remain unchanged.

## Checkpoint

```sh
cargo fmt
cargo test -p erebor-runtime-core --all-targets --all-features
cargo test -p erebor-runtime-session --all-targets --all-features
xcodebuild -project integrations/macos/erebor-filesystem-host/EreborFilesystemHost.xcodeproj \
  -scheme EreborFilesystemHost test
EREBOR_REQUIRE_FILESYSTEM_MACOS_LIFECYCLE=1 \
  cargo test -p erebor-runtime-e2e --test macos_filesystem_lifecycle \
  admission_and_bypass -- --test-threads=1 --nocapture
cargo test --workspace --all-targets --all-features
cargo clippy --workspace --all-targets --all-features -- -D warnings
git diff --check
```

## Acceptance

- Newly launched macOS session processes can mutate only through the verified
  merged view and explicit policy exceptions.
- Backing/original paths and stale descriptors cannot bypass the surface.
- Strict adopt mode is rejected honestly.
- Loss of mount or guard health blocks admission and promotion.

## Stop Point

Stop after the full bypass matrix passes on a real Mac. Wait for explicit
approval before Phase 7.

## Phase 6 Result

State: Not started.

