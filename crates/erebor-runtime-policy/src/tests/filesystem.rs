use erebor_runtime_events::{ActionKind, ExecutionSurface, RiskLevel, TargetRef};

use crate::{Decision, LocalPolicy, PolicyError, PolicyEvaluator};

use super::fixtures::PolicyEventFixture;

#[test]
fn filesystem_surface_and_file_actions_parse() -> Result<(), PolicyError> {
    let policy = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "deny-secret-open",
              "match": {
                "surface": "filesystem",
                "action": "file_open",
                "target_contains": "secret.txt"
              },
              "decision": "deny",
              "reason": "secret opens are denied"
            }
          ]
        }
        "#,
    )?;
    let mut file_open = PolicyEventFixture::event(
        ExecutionSurface::Filesystem,
        ActionKind::FileOpen,
        RiskLevel::Medium,
    );
    file_open.target = Some(TargetRef {
        label: Some(String::from("secret.txt")),
        uri: Some(String::from("file:///tmp/secret.txt")),
    });
    let decision = policy.evaluate(&file_open)?;

    assert_eq!(
        decision,
        Decision::Deny {
            reason: String::from("secret opens are denied"),
            rule_id: Some(String::from("deny-secret-open"))
        }
    );

    Ok(())
}
