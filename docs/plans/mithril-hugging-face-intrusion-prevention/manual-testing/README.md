# Mithril Platform Test Requirements

All acceptance scenarios belong in `crates/mithril-e2e`. Follow the
[binding acceptance rules](../../../../crates/mithril-e2e/SCENARIO_MAINTAINABILITY_TODO.md#binding-acceptance-rules),
including scenario shape, shared fixtures, lifecycle, and verification order.
Use the current TODO as the test-writing contract.

These guides specify the required behaviors, assertions, and commands for
those Rust tests. An operator runs the same tests and inspects their results.
Do not implement a second manual procedure or shell-owned scenario. Keep
existing qualification evidence in its result records.

Start with [environment setup](./environment-setup.md). Then use the guide for
the approved phase:

| Phase | Test requirements and execution guide |
| ---: | --- |
| 0 | [Feasibility, source, ABI, and fixture closure](./phase-0-manual-acceptance.md) |
| 1 | [Shared Interceptor, node, Control, and boot lifecycle](./phase-1-manual-acceptance.md) |
| 2 | [Exact task, process, exec, and runtime-root identity](./phase-2-manual-acceptance.md) |
| 3 | [Policy simulation, effect observation, and canonical paths](./phase-3-manual-acceptance.md) |
| 4 | [Signed local pre-effect enforcement](./phase-4-manual-acceptance.md) |
| 5 | [Process-aware network enforcement](./phase-5-manual-acceptance.md) |
| 6 | [Evidence, coverage, WAL, and recovery](./phase-6-manual-acceptance.md) |
| 6.1 | [gRPC service and IPC convergence](./phase-6-1-manual-acceptance.md) |
| 6.2 | [Control policy and evidence convergence](./phase-6-2-manual-acceptance.md) |
| 7 | [Mithril Control and detection packages](./phase-7-manual-acceptance.md) |
| 8 | [Kubernetes distributed causality and node floor](./phase-8-manual-acceptance.md) |
| 9 | [Local and distributed response](./phase-9-manual-acceptance.md) |
| 10 | [Provider connectors and recovery](./phase-10-manual-acceptance.md) |
| 11 | [Production installation and final conformance](./phase-11-manual-acceptance.md) |
| 12 | [Optional-surface evaluations](./phase-12-manual-acceptance.md) |

## Physical Environment

Use the [shared VM setup](../../../../crates/mithril-e2e/harness/vm/README.md#manual-testing-in-a-vm)
and the [environment requirements](environment-setup.md). The launcher
prepares VMs, runtimes, images, and the compiled test executable. It must not
own scenario actions or assertions. Run the exact Rust tests in that prepared
environment. A successful environment setup does not qualify a scenario.

## How To Read A Test Case

Each guide contains a fixture matrix. Every row names:

- the exact fixture or phase-owned test;
- the action the Rust scenario performs;
- the physical result the Rust test must assert; and
- the legitimate control that must still work.

Keep failure injection and security assertions in the Rust scenario. Shared
fixtures own only reusable environment and lifecycle mechanics. The launcher
prepares the environment and invokes the standard Rust test. An operator's
observation cannot replace an assertion or a missing physical test.

## Platform Test Shape

Write one small behavior in its `mithril-e2e/src` scenario module. Use a generic
`Platform` parameter and `#[platform_test(...)]` for the applicable platforms.
Put `#[lifecycle = name]` below the attribute. Keep setup, owner calls, actor
actions, assertions, and cleanup visible. Do not branch on the platform in
the scenario or reproduce production operations in a helper.

Follow the TODO's file-size, actor, fixture, and lifecycle rules. Reuse one
actor input for the same behavior across platforms. A file with one test must
stay below 100 lines. Do not hide assertions to meet that limit. Place inputs
under `fixtures/` and reuse the common platform implementations. Use ordinary
Rust tests for the lightweight checks that need no physical platform.

Use the standard Rust test harness. Do not add a custom case dispatcher or
replacement test registry. A fixture-ID map records coverage; it does not run
the scenarios. Keep VM, cluster, image, and binary preparation in `harness/`.
The shared Kubernetes fixture must supply real nodes for a multi-node case.
A provider case must use its required provider sandbox. A Host result cannot
replace either prerequisite.

## Standard Run Workflow

1. Create an isolated run using the environment guide and record its manifest.
2. Confirm the exact phase is approved and every dependency phase is `Done`.
3. Build and list the standard `mithril-e2e` Rust tests from the final source.
4. Run the exact tests for each required row. Run Host, then direct `runc`,
   then Kubernetes when those platforms apply. Include the legitimate control
   and the required failure variants in the Rust assertions.
5. Run one lifecycle and one platform per platform-test process. Check physical results,
   coverage, and cleanup through the test assertions.
6. Save the required artifacts under one run ID and calculate their digest.
7. Record fixture IDs, exact test names, commands, platform, failures, and
   artifact digests in the separate phase result file.

## Command Contract

For each required case, document its Rust source, exact generated test name,
platform, lifecycle, prerequisites, command, and expected result. Use
`cargo test -p mithril-e2e --lib --no-run` to build and
`cargo test -p mithril-e2e --lib -- --list` to inspect registration. Follow the
[shared scenario instructions](../../../../crates/mithril-e2e/README.md#add-and-run-a-shared-scenario)
for exact execution in the prepared environment.

Privileged tests use `--exact --ignored --nocapture --test-threads=1` and an
explicit ignore reason. Tests that need no privileges remain non-ignored. Require a
nonzero test count and successful cleanup. A phase cannot be Done while a
required scenario or its exact execution instructions are absent. Existing
test names in other result records do not prove a new case.

## Shared Result Rule

A row passes only when all of these agree:

```text
automated fixture result
Rust scenario assertions
physical syscall/packet/object/provider postcondition
coverage and capability state
legitimate control result
retained artifact digest
```

Any disagreement is `Not done` or `Blocked`, never a majority vote.

## Required Case Record

Record one immutable result per fixture or named phase test:

```text
run_id
phase and deliverable IDs
fixture/test ID and activation condition
candidate and platform-manifest digests
automated command and result
Rust source, exact test name, platform, and lifecycle
expected and observed physical result
coverage/capability state
legitimate control result
faults and timing
artifact locations and digest
status: pass | fail | blocked | not-applicable
reason and remaining branches
```

`not-applicable` requires the exact registry activation condition to be false;
it cannot mean that the environment or implementation was inconvenient.

## Related Contracts

- [Master plan](../README.md)
- [Validated readable architecture](../policy-and-protection-algorithm-architecture-readable.md)
- [Hugging Face adversarial acceptance](../hugging-face-adversarial-acceptance.md)
- [Live two-node lifecycle probe](../live-two-node-lifecycle-probe.md)
