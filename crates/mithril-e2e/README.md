# Mithril End-To-End Qualification

Mithril end-to-end qualification has two required layers. A deliverable is not
complete until both applicable layers pass in this order.

## Lightweight Qualification

Rust code in `src/` and the commands in `src/bin/` own the lightweight layer.
This layer runs production owners and fixture commands without a Kubernetes
cluster. It can use a stock local runtime, as `src/effect/runc.rs` does, when
the result needs a physical container boundary.

The lightweight case must reproduce the state transitions, failure condition,
and observable verdicts that the physical case will use. Owner-local unit and
integration tests can support this case, but they do not replace it.

## Physical Kubernetes Qualification

Scripts in `harness/` own automated physical qualification. Kubernetes
manifests and other inputs are in `fixtures/`. A script can use Bash or Python.
It must run the production Mithril images through the stock Kubernetes and OCI
paths that the deliverable claims.

The harness owns VM and cluster automation, scenario assertions, evidence
records, and cleanup. It must not read or execute files from `examples/`.
Manual operator examples remain a separate surface.

## Required Order And Result Contract

Run the lightweight case before its physical Kubernetes case. Both cases must
report the same decision for every shared oracle. Dynamic values such as Pod
UIDs, candidate digests, Node names, and timestamps can differ. Their meaning,
state transitions, result fields, and pass or fail decisions must agree.

If the physical case detects a condition that the lightweight case did not
detect, stop the physical retry loop. Add the exact condition and expected
verdict to the lightweight case first. Fix the implementation until that case
passes. Then rerun the physical case.

This order makes a lightweight pass a useful prediction of the Kubernetes
result. A lightweight case that omits a known physical failure is incomplete.
