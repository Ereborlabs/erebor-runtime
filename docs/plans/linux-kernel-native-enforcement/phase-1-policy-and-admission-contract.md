# Phase 1: Kernel-Representable Policy And Admission Contract

Status: Proposed. Requires Phase 0 and explicit approval.

Parent plan: [Linux Kernel-Native Effect Enforcement Master Plan](README.md)

## Purpose

Create one immutable, typed kernel policy image from the existing ordered
PolicySet and declared filesystem view. The image lets a BPF LSM program make
the same allowed/denied decision without a userspace policy RPC, while the
existing policy owner remains the sole rule-evaluation authority.

## Scope

- Introduce an owner-level `KernelFilesystemPolicyImage` and digest. Its exact
  module/crate location is the Phase 0-approved ownership result.
- Compile only policies that have a complete mapping to the Phase 0-proven
  object/action contract. Resolve objects against the admitted filesystem view,
  not caller-controlled path strings after launch.
- Represent separate object and parent-entry actions where the kernel requires
  them: open/use, create, unlink, rename, link, truncate, metadata mutation,
  execute, and descriptor access.
- Bind the image to one Session identity, cgroup identity, filesystem-view
  digest, and PolicySet revision. Persist those bindings in Session admission
  evidence.
- Add a structured admission error for a policy that cannot compile exactly.
  No residual clause may route to an allow-by-default ptrace or userspace path.
- Specify the contract for existing string-match rules. The phase must either
  prove an exact typed mapping or reject them. It must not reinterpret a rule
  such as `target_contains` as an approximate prefix/suffix match.

## Non-Negotiables

- `LayeredPolicySet` or its approved successor remains the policy authority.
  The policy image is compiled data, not a second evaluator.
- The workload cannot supply, replace, patch, or select a policy image.
- An approval or mediation decision for raw filesystem access is not compiled
  as a kernel allow. It is rejected pending a separately approved mediated
  capability Surface.
- Do not change the current PolicyPackage resource schema or CLI merely to make
  an example compile. Any migration requires the Phase Result and user approval.

## Checkpoint

- Unit tests compile representative allow and deny packages into a stable image
  digest and reject each unsupported action/matcher with a typed cause.
- Admission tests prove the cgroup, filesystem-view, Session, PolicySet, and
  image digest bindings cannot be mixed across Sessions.
- An e2e fixture proves a compiled denied-create rule is enforced through the
  Phase 0 test hook before filesystem mutation.

## Acceptance

- The supported policy subset, rejected subset, identity resolution rules, and
  effect/action matrix are documented in the Phase Result.
- Every admitted kernel-enforced Session has one stored image digest linked to
  the selected immutable PolicySet and filesystem binding.
- Unsupported hosts and unsupported policy shapes fail admission before a
  workload process starts.

## Stop Point

Do not install a production BPF LSM program until the user approves the policy
subset and any resulting policy-resource migration.

## Phase Result

Not started.
