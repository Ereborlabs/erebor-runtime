# Phase 0: Contract And Linux Capability Spike

Status: Proposed. Requires explicit approval before implementation.

Parent plan: [Linux Kernel-Native Effect Enforcement Master Plan](README.md)

## Purpose

Turn the proposed BPF LSM target into an evidence-backed production capability
contract before changing resources, policy documents, or the current ptrace
backend. This phase answers whether the exact Linux hooks, map shapes,
privileges, cgroup binding, and event channel required by Erebor are available
and semantically sufficient on the supported kernel profile.

## Scope

- Define one versioned `LinuxKernelEnforcementCapabilityReport` owned by the
  Linux enforcement implementation. It reports, at minimum, kernel release,
  active LSM order, BTF availability, regular and cgroup-LSM attach viability,
  cgroup v2 hierarchy semantics, required daemon authority, workload privilege
  exclusions, required helper/kfunc availability, and the supported filesystem
  hook matrix.
- Build a minimal Erebor-owned BPF LSM probe and loader in an isolated test
  environment. It may attach only to a harmless test hook and return allow; it
  must not govern production sessions.
- Prove the cgroup-LSM attach candidate can return a deliberate denial for a
  test Session cgroup while leaving an unrelated process unaffected. If a
  required hook is only usable through regular LSM attachment, prove its
  cgroup-filtered fast path and record its host-wide overhead separately.
- Evaluate, with committed tests rather than inference, the hooks needed for
  file open, create, remove, rename/link, truncate, metadata mutation,
  execution, descriptor use, and Session teardown. For each one, record its
  cgroup-LSM availability, regular-LSM fallback feasibility, or unsupported
  result explicitly.
- Evaluate BPF object build/loading approaches using normal upstream dependency
  due diligence. Select no dependency or build path until the phase result
  records the user-approved choice.
- Define the minimum supported production-host profile and the precise
  unsupported-host admission result. The observed local host is an initial
  negative fixture: BPF LSM is compiled but inactive at boot.

## Non-Negotiables

- Do not install a BPF program on an ordinary user host merely to make this
  phase pass. Use a dedicated privileged test host or VM.
- Do not alter `/proc/cmdline`, bootloader configuration, active LSM order,
  kernel configuration, or host privileges as part of repository work.
- Do not copy or invoke AgentSight or Codex assets. The test probe is Erebor
  source and stays within the selected Erebor crate boundary.
- Do not add a `linux_kernel` backend enum value, public configuration field,
  or policy migration in this phase.
- Do not claim a kernel version alone proves support. The capability report must
  verify the active boot state and a real attach/deny test.

## Checkpoint

- A privileged isolated test host produces the report and passes an attach,
  cgroup attribution, allow, deny, detach, and cleanup test.
- The repository host produces a structured unsupported result explaining that
  BPF LSM is absent from the active LSM order.
- The selected hook/action matrix names every unproven operation as blocked,
  rather than assuming parity with `open*` syscall interception.

## Acceptance

- The report differentiates: kernel config, active LSM order, BTF, BPF syscall,
  cgroup v2, program attach, required maps/helpers, daemon privileges, and
  workload privilege exclusion.
- Tests prove a BPF LSM denial occurs before a test physical effect and is
  restricted to the selected cgroup. A regular-LSM fallback may pass only with
  a separate unrelated-workload and overhead result.
- A written Phase Result names the exact kernel test image, commands run,
  supported features, unsupported features, dependency decision, and whether
  Phase 1 is `Done`, `Not done`, or `Blocked`.

## Stop Point

Do not begin Phase 1 until the user approves the feature profile, dependency
choice, and resulting host-support contract.

## Phase Result

Not started.
