# Shared package publication validation qualification

Result: **Done for the shared validation change**. Production replacement and
native successful publication remain **Not done**. Runtime source parent is
`80fb0a352`. The [source record](araphor-shared-publication-2026-11-09.json)
contains exact source hashes, commands, binary profile, and evidence hashes.

The DuckDB and native owners can now use the same output, checkpoint, selected
result, derived-context, domain, receipt, and retained-execution validation.
The shared functions use the existing SDK types, memory charges, and wire
records. Retained Graph identities are copied after their existing memory
charge and normalization. The expected attempt tenant remains an explicit
input to domain validation. Backend writes remain in their current owners.

The unchanged incident passes: **1 passed, 694 filtered**, with **14.22 seconds**
in the harness and **14.264993 seconds** for the process. Workload, assertions,
and timeouts are unchanged. The recorded source hashes match before and after
the build and run. The initial sandbox run failed with `Operation not permitted`.
The same binary passed in the authorized native environment.

| Boundary | First sequence | Second sequence | Third sequence |
| --- | ---: | ---: | ---: |
| Collector receipt to first durable creation | 447.624 ms | 543.485 ms | 756.530 ms |
| Public notification receipt | 486.363 ms | 779.997 ms | 843.579 ms |

The bulk operation retains **16,384 rows** and takes **2.143119 seconds**.
This correctness run uses the debug profile and the production DuckDB path.
It establishes no matched performance gain. The sub-100 ms and 100-fold targets
remain **Not done**. The frozen release control is separate from this run.

Selected-file formatting and the feature-off library check pass. Full CI does not run during iteration, as the user requires.
Native Graph journals, successful atomic publication, recovery, production
providers, CDC routing, notification batches, retention, capacity, backup, and
cutover remain **Not done**. Read the
[owner guide](../../guides/araphor-native-data-review.md#shared-package-publication-validation).
