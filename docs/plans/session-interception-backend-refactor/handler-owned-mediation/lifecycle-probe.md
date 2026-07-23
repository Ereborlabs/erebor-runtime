# Phase 0 Live Probe

Status: Done. The independent process-A/process-B core happy path,
ordinary-user namespace-helper handoff, and complete negative fixture suite
passed on 2026-07-12.

## Purpose

Exercise the actual kernel sequence instead of proving only isolated APIs:

```text
fake IDE creates child stdio pipes and requests target exec
  -> fanotify holds executable permission
  -> ptrace attaches before target code
  -> original child FD 0 and FD 1 are copied with pidfd_getfd
  -> repeated injected syscalls create scratch memory and two pipes
  -> replacement FD 0 and FD 1 are installed
  -> target enters the prepared mount namespace
  -> original target exec is retried and verified
  -> broker relays one JSONL request and response
  -> target first-code marker appears only after final admission
```

The initial fixture combined the fake IDE launcher and interceptor in
`mitm-probe`; that version passed the core kernel transaction. The current
fixture uses one `mitm-probe` executable to fork a small harness plus sibling
processes A and B. Process A creates the target child and owns the original
pipe endpoints. Process B receives neither the PID nor those endpoints from
A, discovers the target through fanotify, and uses `pidfd_getfd` to become the
MITM.

## Host Requirements

- x86-64 Linux 5.6 or newer;
- `CAP_SYS_ADMIN` for fanotify permission events, mount namespaces, and mount;
- ptrace permission over the fixture child;
- permission to call `pidfd_getfd` under the host LSM/Yama profile;
- a kernel that permits the selected fanotify and ptrace composition.

Run the probe as root in a disposable development environment. The namespace
and mount operations are confined to fixture child namespaces and a temporary
directory. If the host denies a capability, record the exact error and keep
Phase 0 `Blocked`; do not report the theory as disproven or passed.

## Build

```sh
cargo fmt --manifest-path experiments/codex-stdio-mitm-probe/Cargo.toml
cargo check --manifest-path experiments/codex-stdio-mitm-probe/Cargo.toml --all-targets
cargo test --manifest-path experiments/codex-stdio-mitm-probe/Cargo.toml
cargo build --manifest-path experiments/codex-stdio-mitm-probe/Cargo.toml --bins
```

## Run

```sh
sudo experiments/codex-stdio-mitm-probe/target/debug/mitm-probe \
  experiments/codex-stdio-mitm-probe/target/debug/mitm-target
```

The probe prints one result for each checkpoint and exits non-zero on the first
failed invariant.

## Required Result

- The first-code marker has no bytes before final ptrace detach/resume.
- The retry exec has the same target object and PID as the held candidate.
- Target FD `0` and FD `1` are the replacement pipes.
- The fake IDE receives the target's response through both relay legs.
- The target reports the mount-namespace-only marker.
- EOF reaches both sides without hanging.
- Temporary target descriptors and broker copies close.
- Target exits successfully and the namespace keeper is terminated.

## Required Follow-Up Negative Fixtures

Before production Phase 0 is Done, extend or wrap the probe to cover:

- an independent fake IDE process that owns the original pipes, remains the
  target's parent, waits for its exit, and has no launch control channel to the
  separate interceptor;
- tracer death in every splice state with `PTRACE_O_EXITKILL`;
- broker endpoint handoff loss;
- duplicate original-stdio alias;
- fanotify retry-ticket replay;
- namespace-entry failure after FD replacement;
- concurrent candidate execs;
- unexpected signal and syscall result during injection.

The two-program probe initially established the happy path. The current probe
implements and verifies every fixture above on the documented host profile.

## Current Host Result

Date: 2026-07-12.

- Formatting, warning-denied Clippy, and both binary builds pass.
- A direct unprivileged run exits before setup with the explicit root/capability
  requirement. It does not start the candidate target.
- `sudo -n` cannot run the probe because this host requires an interactive
  password.
- Running in a disposable user and mount namespace successfully prepares the
  namespace keeper, then the kernel returns `EPERM` from
  `fanotify_init(FAN_CLASS_PRE_CONTENT)`. Capabilities in that nested user
  namespace are therefore insufficient for this permission-class watch. The
  early-failure path reaps the keeper and removes its temporary directory.
- That rootless attempt cannot exercise the held-exec, remote-syscall, FD
  splice, `setns`, retry, or relay sequence.

The first interactive privileged run reached:

```text
PASS: prepared mount namespace keeper
PASS: fanotify held initial target exec
```

It then hit the 30-second alarm. The target was still sleeping in the fanotify
permission wait, so waiting for `PTRACE_INTERRUPT` before answering fanotify
formed a deadlock: the ptrace stop could not become observable until the
fanotify wait was released.

The probe now uses this order:

```text
PTRACE_SEIZE
PTRACE_INTERRUPT                 queue the stop
fanotify FAN_DENY                release the blocked exec
waitpid PTRACE_EVENT_STOP        prove no return to userspace
PTRACE_GETREGS                   save and verify the original exec image
set orig_rax = -1                suppress automatic syscall restart
rewind RIP to verified syscall   begin injected-syscall transaction
```

A second privileged run proved the queued-interrupt ordering and
`pidfd_getfd`, but falsified the next assumption: the first later
`PTRACE_SYSCALL` stop was not reliably the denied exec syscall-exit. Linux may
restart an interrupted syscall when a tracee resumes. The probe no longer
waits for or depends on that ambiguous stop. It captures the original exec
register image directly at `PTRACE_EVENT_STOP`, verifies `orig_rax` and the
syscall instruction, neutralizes restart state, and starts injection there.

The third privileged run passed every core checkpoint:

```text
fanotify held initial target exec
queued interrupt stopped target before denied exec returned
original exec register image captured
original FD 0 and FD 1 copied with pidfd_getfd
two replacement pipes created inside the tracee
target FD 0 and FD 1 replaced
target entered the prepared mount namespace
exact original exec retried and admitted
both relay directions completed
fake IDE request and response crossed the broker exactly once
```

Independent process-A/process-B core result: `Passed`.

The privileged run proved:

```text
process B armed fanotify before A created the target
process A created the target with private stdin/stdout pipes
process B learned the target PID only from fanotify
process B copied, replaced, and relayed target FD 0 and FD 1
target entered the prepared namespace and retried the original exec
target reported process A as its parent after interception
process A received the target response through the broker relay
```

The fixture was run with `sudo`, so both process A and the target had root
credentials. That proves the FD topology and parentage contract, but it does
not prove that an ordinary IDE-owned target can perform the injected `setns`.
The production design's privileged namespace-entry helper and credential-drop
transaction remain required evidence.

The probe now models that transaction without modifying production code. Process
A drops to the invoking `sudo` UID/GID before creating the target. Process B
copies its own executable to the root-owned probe directory as a mode-`4711`
helper and writes a mode-`0400`, one-use ticket beside it. The ticket contains
the exact target, namespace, and original user identity. After replacing FD
`0` and FD `1`, B retries the helper through its own fanotify permission event.
The helper consumes and unlinks the ticket, enters the namespace while it has
set-id root privileges, drops its group and user credentials, sets
`no_new_privs`, and execs the original target. B holds that final exec again
and verifies the target namespace and all credential slots before admission.

The resulting standalone crate passes formatting, `cargo check --all-targets`,
five unit tests, warning-denied Clippy, and both binary builds. The corrected
privileged run passed the ordinary-user handoff:

```sh
sudo experiments/codex-stdio-mitm-probe/target/debug/mitm-probe \
  experiments/codex-stdio-mitm-probe/target/debug/mitm-target
```

The first user-run helper attempt reached `one-time privileged namespace helper
admitted`, then failed the helper's pre-entry credential assertion. The helper
is deliberately setuid-root (`4711`), not setgid-root: Linux elevated its
effective UID but correctly preserved the invoking effective GID. The probe had
mistakenly required an effective root GID. The assertion now accepts the
observed setuid credential shape, and a regression test covers it. The corrected
privileged run then passed namespace entry, credential drop, exact final exec,
both split relay directions, preserved Process A parentage, and cleanup.

The negative fixtures are now implemented in the same isolated binary. Run the
complete suite as root from the repository root:

```sh
sudo env MITM_PROBE_FIXTURE=suite \
  experiments/codex-stdio-mitm-probe/target/debug/mitm-probe \
  experiments/codex-stdio-mitm-probe/target/debug/mitm-target
```

The suite runs the happy path plus: duplicate original-stdio alias rejection;
broker endpoint-handoff loss; namespace helper failure after FD replacement;
unexpected injected syscall result; unexpected signal-delivery stop during
injection; one-time retry-ticket replay rejection; two simultaneous candidate
execs with one active transaction and one explicit denial; and `PTRACE_O_EXITKILL`
tracer death after each pre-helper splice state. Each negative case passes only
when the fake IDE observes no target first-code marker, no response, and a
non-successful target exit. The first privileged suite run passed the happy
path and six negative fixtures, then stopped in the concurrent-candidate case.
The second target's initial fanotify event arrived before the active target's
helper event; the fixture treated it as unexpected instead of denying it. The
event router now identifies helper and target events separately, denies the
non-active candidate, and continues waiting for the active helper. The change
has seven passing unit tests plus clean warning-denied Clippy and build checks.
The corrected complete suite then passed every fixture: the happy path,
duplicate alias, broker handoff loss, namespace entry failure, unexpected
syscall result, unexpected signal, retry replay, concurrent candidates, and
six `PTRACE_O_EXITKILL` tracer-death checkpoints. Phase result: `Done` for the
documented host and privilege profile. Production work remains subject to the
separate Phase 1 approval gate.
