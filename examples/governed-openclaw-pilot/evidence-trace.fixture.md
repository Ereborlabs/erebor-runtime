# Governed OpenClaw Evidence Trace

## Executive Summary

This trace summarizes one governed OpenClaw run inside Erebor Runtime. The run
used a shared session audit to record browser CDP and terminal/process actions
under one session id. The strongest evidence in this report is action/resource
provenance: what resources were exposed, what the agent attempted, which policy
rule applied, and whether Erebor allowed, mediated, held, or denied the action.

No semantic PII classifier enabled. This v1 trace does not claim that the agent
never read personal data, does not certify GDPR/HIPAA compliance, and is not
legal advice.

## Session Purpose And Actor

| Field | Value |
| --- | --- |
| Purpose | OpenClaw support investigation of a local OAuth callback reproduction under Erebor governance. |
| Session id | session-fixture |
| Actor | openclaw (agent) |
| Session runner | linux_host |
| Audit window | 2026-06-17T12:00:00Z to 2026-06-17T12:00:03Z |
| Record count | 4 |
| Surfaces observed | browser_cdp: 3, terminal: 1 |
| Decisions observed | allow: 3, deny: 1 |

## Controls And Non-Claims

| Control | Label | Evidence |
| --- | --- | --- |
| Browser CDP endpoint | enforced | Browser CDP audit records are present. |
| OAuth callback handoff | enforced | Callback network request was blocked before local callback completion. |
| Terminal/process execution | enforced | Process execution records are present for the governed session process tree. |
| OpenClaw browser profile/login state | cooperative | The demo uses the normal OpenClaw browser profile; Erebor does not copy or certify cookies. |
| OAuth lab event stream | observed | Lab events are supporting evidence, not the enforcement boundary. |
| Semantic PII classifier | deferred | No semantic PII classifier enabled. This report proves governed action/resource provenance, not content classification. |
| Host-wide network/process containment | deferred | The pilot controls the governed session path and reports residual risk; it does not claim whole-device containment. |


## Governed Resources Exposed

- browser_cdp: OAuth lab repro (http://127.0.0.1:5105/repro)
- browser_cdp: browser-target
- terminal: google-chrome (ws://127.0.0.1:19134/)

## Allowed Action Timeline

| Time | Surface | Action | Target | Decision |
| --- | --- | --- | --- | --- |
| 2026-06-17T12:00:00Z | terminal | process_exec | google-chrome (ws://127.0.0.1:19134/) | allow (erebor-process-interception-managed-browser-cdp) |
| 2026-06-17T12:00:01Z | browser_cdp | browser_target_manage via Target.attachToTarget | browser-target | allow (allow-openclaw-target-management) |
| 2026-06-17T12:00:02Z | browser_cdp | browser_navigate via Page.navigate | OAuth lab repro (http://127.0.0.1:5105/repro) | allow (allow-oauth-lab-navigation) |


## Denied, Held, Or Mediated Authority Transitions

| Time | Surface | Action | Target | Decision |
| --- | --- | --- | --- | --- |
| 2026-06-17T12:00:00Z | terminal | process_exec | google-chrome (ws://127.0.0.1:19134/) | allow (erebor-process-interception-managed-browser-cdp) |
| 2026-06-17T12:00:03Z | browser_cdp | network_request via Fetch.requestPaused | fetch-callback-request (http://127.0.0.1:5105/oauth/callback?code=redacted&state=redacted) | deny (deny-oauth-callback-network-request) |


Summary counts: allowed=3, denied=1, held=0, mediated=1.

## Policy Package And Rule Evidence

| Rule id | Surface | Action | Decision | Reason |
| --- | --- | --- | --- | --- |
| allow-oauth-lab-navigation | browser_cdp | browser_navigate | allow |  |
| allow-openclaw-target-management | browser_cdp | browser_target_manage | allow |  |
| deny-oauth-callback-network-request | browser_cdp | network_request | deny | OAuth callback handoff must not reach the local callback without operator approval |
| erebor-process-interception-managed-browser-cdp | internal/runtime | n/a | observed | Runtime-generated decision id. |


## Residual Risk

- No semantic PII classifier enabled. The report proves governed
  action/resource provenance, not semantic content classification.
- Linux-host process governance applies to the enrolled session process tree and
  reports residual risk; it is not a claim of whole-host containment.
- The OpenClaw browser profile can contain existing cookies or login state. The
  demo should use a throwaway GitHub account and throwaway OAuth app.
- Browser URL/resource provenance comes from CDP commands/events and observed
  targets. The raw JSONL remains the evidence attachment for deeper review.
- This report is a technical evidence trace for privacy, GRC, security, and AI
  platform review. It is not legal advice, a DPIA, or a compliance certificate.

## Intended Reviewers And Retention

- Intended reviewers: DPO/privacy, GRC, security, AI platform, and counsel when
  an agent workflow approaches regulated or personal-data-bearing systems.
- Suggested retention: store the report with the JSONL audit, policy, config,
  and prompt artifacts for the same retention period as the reviewed support or
  incident workflow.
- Review question: would this evidence be enough to approve the agent workflow,
  or is semantic data classification, stronger sandboxing, or human approval
  still required?

## Artifact Integrity

| Artifact | Path | SHA-256 |
| --- | --- | --- |
| Audit JSONL | `examples/governed-openclaw-pilot/fixtures/evidence-trace-audit.jsonl` | `eb08529c44f65d31943a3e7ef40c8c78172a1d16e5e8a94ed59c9c3dff43de43` |
| Policy package | `examples/governed-openclaw-pilot/policy.json` | `436bb31a08451273323a2e4ebf3b23455857b02d3ea6192d47f600f9d9f54a0b` |
| Session config | `examples/governed-openclaw-pilot/session-config.json` | `c8f7bfb3e385406e48d5c5e0abc3fba96868af2608c6f1658310175148d03725` |
| Prompt | `examples/governed-openclaw-pilot/prompt.txt` | `aaa2d423753f49b176477976b1009fd85d5b9325f6b31ef21aa3377cd5755216` |

| Report body | generated markdown before this hash row | `3f3f5bc587496ea50bdfd8efc1ae61522f2b5c49d5632fddcda8c9202a2ab6a5` |

