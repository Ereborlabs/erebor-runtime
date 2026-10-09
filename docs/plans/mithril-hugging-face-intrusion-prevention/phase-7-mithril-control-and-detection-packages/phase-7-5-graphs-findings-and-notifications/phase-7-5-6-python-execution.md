# Phase 7.5.6: Optional Python Execution

Support Python algorithms and their libraries without requiring operators to
manage Python. Parent: [7.5](README.md). Require 7.5.5. This child is optional
for the core release and required only when Python support is advertised.

## Intended end state

Python implements the same named model contract as SQL, Wasm, and native code.
Araphor supplies a pinned interpreter. A built package contains its compatible
dependency closure. SQL, Wasm, and native-only installations start no interpreter.

## Implementation flow

```text
Admission checks a package with a Python target
  -> the package owner checks interpreter and locked dependency compatibility
  -> the worker supervisor creates a revision-specific environment from local artifacts
  -> the supervisor applies the qualified worker isolation and resource limits

The scheduler invokes an admitted Python export
  -> the SDK adapter supplies typed batches, evaluation context, and prior state
  -> the Python function returns declared outputs and next checkpoint
  -> the existing host validator checks the result before AnalysisStore commits it

Import, evaluation, or cancellation fails
  -> the supervisor discards partial results and terminates a stalled worker
  -> the package owner records a structured failure and incomplete coverage
  -> committed state remains available for a checked retry
```

## Scope and owners

Reuse the native worker supervisor and batch transport from 7.5.5. Add a Python
SDK binding to the same descriptor and state contract. Keep Python imports out
of Control; descriptor inspection must not execute decorators in Control.

Bundle one qualified CPython runtime for each advertised platform. Lock wheels
and native dependencies when building the package. Do not invoke `pip`, download
source, or compile dependencies during installation or evaluation. An isolated
environment resolves dependencies; OS isolation supplies the execution boundary.
Reject incompatible packages with an actionable error.

## Acceptance and verification

Run Rust or platform integration tests for offline import, missing dependencies,
native-wheel compatibility, invalid schemas, checkpoint replay, cancellation,
and worker failure. Compare equivalent Rust and Python fixture results under the
declared numeric contract. Show that core package cases pass with Python absent.
Run the shared Rust procedure after host or test changes.

## Exclusions and stop point

No mandatory Python-to-Wasm, system Python requirement, model server, or second
package lifecycle. Unsupported libraries remain explicit. Stop after the
advertised interpreter and package closure pass qualification.

## Result

**Not done.** Optional runtime support is planned. It does not block core closure.

## End scope and example

If selected, complete when a built Python package runs offline with the bundled
interpreter, locked dependencies, shared isolation, and the same result/state
contract. If Python is not advertised, this phase can remain Not done without
blocking 7.5.7, 7.5.8, or 7.5.9. Those phases must not depend on a Python-only
implementation for a required algorithm.

Example at completion: install a Python analysis package that calculates a
median from an authorized numeric dataset. The operator installs no system
Python and the worker downloads nothing. Restart restores its committed state.
A package with an incompatible wheel fails admission with the dependency named.
