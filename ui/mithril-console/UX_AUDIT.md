---
type: ux-audit
date: 2026-08-29
product: Mithril console fixture
journey: Observe workloads, apply protection, manage policy sets, and investigate a stopped cross-node intrusion
platform: responsive-web
screens: 25
open-findings-critical: 0
open-findings-major: 0
open-findings-minor: 0
---

# Mithril console UX re-audit

## Result

The re-audit found no open task-blocking or major usability defect in the fixture. The audited journey now works at 1440 px and 375 px. The browser suite also checks tablet and mobile graph sizes.

The baseline audit rated the design at 5/10. This re-audit rates the fixture at 9/10. The missing point covers product integration and manual assistive-technology testing. This fixture cannot prove those items.

## Scope and method

The audit covers Operations, Sessions, Findings, Policy rollout, Evidence, Response, Agent, Release, the session map, and the session ledger. It also covers these task states:

- Workload policy-set review
- Protect confirmation
- Observe policy suggestions
- Direct edge inspection
- The if-allowed counterfactual
- Incorrect-stop review

The visual review used 25 final screenshots. It used a 1440 by 900 desktop viewport and a 375 by 812 mobile viewport. Browser tests also used 768 by 1024 and graph-specific desktop sizes.

The review applied the Nielsen, Shneiderman, Gerhardt-Powals, Bastien and Scapin, Norman, Tognazzini, Fogg, Gestalt, WCAG, and content-design checks from the `ux-audit` workflow. The browser verification used Chromium and axe-core.

## Finding closure

| ID | Baseline severity | Finding | Resolution | Proof |
| --- | --- | --- | --- | --- |
| F-01 | 4 | Mobile hid Protect and suggested policies. | Mobile workload rows use task cards. Protect, mode, count, and disclosure stay in the viewport. | Mobile overflow test and Operations screenshot |
| F-02 | 3 | Mobile navigation used icons without labels and covered content. | Each item has a label and a 44 px target. The shell reserves bottom space. | All-workspace mobile navigation test |
| F-03 | 3 | Mobile Response clipped the target and execution boundary. | Response actions and the selected action stack at mobile size. | Response mobile screenshot and overflow test |
| F-04 | 3 | Mobile graph had no visible route to the stopped effect. | First event, Current event, Stopped effect, and All events remain visible. The ledger uses the same state. | Mobile graph navigation test |
| F-05 | 2 | Policy actions and operational text were too small. | Edit, Remove, form, and review actions use visible controls. Secondary text uses a contrast-safe shared color. | All-workspace axe test |
| F-06 | 2 | The first workload started expanded. | Every workload starts collapsed. | Operations screenshot and interaction tests |
| F-07 | 3 | Protect applied all suggestions on the first press. | The first press opens the exact policy set and a confirmation. The second action names the workload and rule count. | Protection interaction test |
| F-08 | 2 | The if-allowed branch appeared outside the graph frame. | Reveal selects the denied operation and moves the viewport to the hypothetical branch. | Counterfactual viewport test |
| F-09 | 2 | The incorrect-stop review led with internal vocabulary. | The review states that access stays denied and asks for the expected action first. Evidence identifiers use a disclosure section. | Incorrect-stop desktop and mobile tests |
| F-10 | 3 | Older secondary text failed contrast checks across all workspaces. | The shared secondary-text color now passes the automated scan. | Zero serious or critical axe violations on ten surfaces |
| F-11 | 2 | Mobile Protect opened its confirmation below the current frame. | Mobile Protect scrolls the decision card to the center. Reduced-motion preference disables smooth movement. | Mobile Protect viewport test |

## Journey result

The operator can now complete this sequence without leaving the workload context:

1. Compare observed workloads.
2. Select Protect.
3. Review current policies and new suggestions.
4. Add, edit, or remove a policy in the local set.
5. Confirm the exact suggestion count for one workload.
6. Open the related stopped effect.
7. Inspect operation and edge evidence in the session map or ledger.
8. Show the if-allowed path without changing evidence.
9. Submit an incorrect-stop exception for separate approval.

The console keeps Observe suggestions, policy drafts, protection changes, exception reviews, and Agent answers local to browser memory. Each mutation surface states this boundary.

## Accessibility and responsive result

- All eight navigation items have visible labels and targets of at least 44 by 44 px on a 375 px viewport.
- Every workspace has zero page-level horizontal overflow at 375 px. The graph keeps intentional scrolling inside its canvas.
- Operations, Sessions, Findings, Policies, Evidence, Response, Agent, Release, the session map, and the session ledger have no serious or critical axe violations.
- Result, proof, stop, and release states use text labels. Color is not the only state indicator.
- Reduced-motion preference disables automatic smooth movement for the graph, navigation, and mobile Protect framing.
- The ledger provides a synchronized text alternative to the spatial graph.

## Product boundaries

This result covers the isolated design fixture only. It does not prove durable graph storage, backend policy compilation, signing, delivery, activation, response execution, or exception authorization. A production review must test these flows with real APIs, live latency, a screen reader, high zoom, and the supported browser set.

## Verification

Run these commands from `ui/mithril-console`:

```sh
npm run check
npm test
npm run build
npm run test:e2e
```

The final suite contains 24 Chromium scenarios and 5 unit tests.
