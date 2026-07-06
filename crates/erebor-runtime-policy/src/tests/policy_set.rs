use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel};

use crate::{Decision, LocalPolicy, PolicyError, PolicyEvaluator, PolicySet};

use super::fixtures::PolicyEventFixture;

#[test]
fn policy_set_uses_first_matching_policy_across_files() -> Result<(), PolicyError> {
    let first = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "allow-nav",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_navigate"
              },
              "decision": "allow"
            }
          ]
        }
        "#,
    )?;
    let second = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "deny-nav",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_navigate"
              },
              "decision": "deny",
              "reason": "deny later"
            }
          ]
        }
        "#,
    )?;
    let policies = PolicySet::from_policies(vec![first, second]);

    let decision = policies.evaluate(&PolicyEventFixture::event(
        ExecutionSurface::BrowserCdp,
        ActionKind::BrowserNavigate,
        RiskLevel::Low,
    ))?;

    assert_eq!(
        decision,
        Decision::Allow {
            rule_id: Some(String::from("allow-nav"))
        }
    );
    Ok(())
}
