# GDB stack diagnostic

This diagnostic runs the unchanged frozen `versioned-direct-scan` binary with
the existing `stable` workload. The binary identity and source commits are in
the [manifest](../native-read-comparison/direct-scan.json). GDB pauses the
process. All timing values in this directory are excluded from acceptance.

[`capture.py`](capture.py) records the exact commands, raw GDB MI responses,
and monotonic timestamps in [`gdb-diagnostic-stacks.jsonl`](gdb-diagnostic-stacks.jsonl).
GDB completed normally and captured 151 main-thread stacks. The
[diagnostic report](gdb-diagnostic-stable.json) passed the existing workload
assertions. The interval is 20 to 50 ms, with random seed 1937. The first pause
also captures short worker stacks. Main-thread and worker observations must
remain separate.

Run the script from this checkout after restoring the frozen binary at the
recorded path. The initial sandbox run failed with `ptrace: Operation not
permitted`. The approved run outside that sandbox traced only GDB's own child.
No system setting changed. GDB auto-loaded Python scripts and debuginfod were
disabled. The script adds no breakpoint or call into the target.

These are samples of paused execution positions, not CPU-cycle percentages.
The workload also executes flat-key controls, historical replay, metadata
checks, maintenance, and Neon cases. Their stacks do not prove the cost of
the versioned candidate's primary cycles. Sparse primary samples cannot
establish the cause of the measured median regression.

Review found ten primary capture stacks across all engines. One identifies
flat Fjall, three identify Neon, one identifies the candidate, and five have
no engine identity. Candidate primary observations include journal item LZ4
compression at sample 11 and index-iterator allocation during point lookup
at sample 143. Each occurs once. Neither observation ranks an owner or
estimates its cost. Other candidate index reads occur in historical replay,
metadata checks, result checks, or initialization and remain excluded.
