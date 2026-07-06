use crate::{LocalPolicy, PolicyError};

#[test]
fn duplicate_rules_are_rejected() {
    let error = LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "duplicate",
              "match": { "surface": "terminal" },
              "decision": "deny"
            },
            {
              "id": "duplicate",
              "match": { "surface": "mcp" },
              "decision": "deny"
            }
          ]
        }
        "#,
    );

    assert!(matches!(
        error,
        Err(PolicyError::DuplicateRule { rule_id, .. }) if rule_id == "duplicate"
    ));
}
