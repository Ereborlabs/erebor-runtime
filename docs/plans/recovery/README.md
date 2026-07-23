# Documentation Recovery Notes

## Method

Three lower-cost triage passes inspected only each candidate file's first 300
bytes, path, size, and full-file hash. That classified 199 Markdown candidates
from `recover/` without reading every document in full. Only selected master
plans, requested attribution/context candidates, and ambiguous phase families
were then read to establish the directory shape.

`recover/restore_docs_from_triage.zsh` is the reproducible, no-clobber copy
operation used to create the named tree. It copies from `recover/` and never
edits or removes raw recovery material.

## Classification

- `docs/plans/`: Erebor master plans, implementation subplans, and their
  canonical-looking phases.
- `docs/research/`: compliance, interview, market, and buyer research.
- `docs/research/generated/` and `docs/designs/`: assistant-generated research
  and product/design artifacts, intentionally distinct from implementation
  plans.
- `docs/guides/`, `docs/how-to/`, `docs/examples/`, and `docs/integrations/`:
  operational and adoption material.
- `docs/plans/recovery/superseded/`: earlier daemon/client and filesystem-plan
  revisions kept by recovered filename for comparison.

The following categories were intentionally **not** copied into project docs:

- Foreign repositories and retrieval noise: MeetAI/OpenClaw plugin phases,
  Comvest, Phaser, JUnit/Bazel/any-base documents, a Bitbucket template, and a
  LinkedIn scratchpad. Their raw files remain in `recover/`.
- Non-doc artefacts: two `Cargo.lock` copies renamed to `.md`, a Maven/doclint
  property block, a prompt/transcript fragment, a lifecycle-pointer fragment,
  and a short status stub.
- Exact foreign duplicates remain raw rather than being copied twice.

## Known Gaps

The expected `/tmp/erebor-doc-recovery/docs/plans` source did not exist in this
workspace. The recovered set also lacks the prior `docs/development-plan.md`,
`docs/browser-state-authority-plan.md`, the browser-level CDP subplan, the
Context Model V2 master plan. Codex Attribution V1 and Claude Attribution V1
are nested Context DAG subplans; only the Codex-specific implementation
material was separately recovered.

The existing `.agents/browser-cdp.md` and `.agents/verification.md` already
match recovered duplicate copies, so those copies were not restored under a
second name.

The separately recovered `codex-snapshots/scope-context-dag/` source supplied
the canonical Phase 6 and Phase 7 filenames for the Codex Attribution V1
subplan. The richer Phase 6 version is active under `context-dag/`; the earlier
shorter Phase 6 recovery remains in `recovery/superseded/context-dag/`.

The separately recovered `codex-snapshots/daemon-client/` source supplied the
active [Phase 3+ architectural-simplification decision record](../daemon-client/phase-3-onward-architectural-simplification.md).
