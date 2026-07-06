use erebor_runtime_e2e::E2eError;
use erebor_runtime_policy::LocalPolicy;
use serde_json::json;

use super::error_helpers::external_error;

pub fn allow_all_policy() -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(r#"{ "rules": [] }"#)
        .map_err(|error| external_error("allow-all policy setup", error))
}

pub fn deny_script_eval_policy() -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "deny-script-eval",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_script_eval"
              },
              "decision": "deny",
              "reason": "script evaluation denied by e2e policy"
            }
          ]
        }
        "#,
    )
    .map_err(|error| external_error("deny-script-eval policy setup", error))
}

pub fn require_approval_script_eval_policy() -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        r#"
        {
          "rules": [
            {
              "id": "approve-script-eval",
              "match": {
                "surface": "browser_cdp",
                "action": "browser_script_eval"
              },
              "decision": "require_approval",
              "reason": "script evaluation requires approval by e2e policy"
            }
          ]
        }
        "#,
    )
    .map_err(|error| external_error("require-approval-script-eval policy setup", error))
}

pub fn deny_payload_script_eval_policy(needle: &str) -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        &json!({
            "rules": [
                {
                    "id": "deny-payload-script-eval",
                    "match": {
                        "surface": "browser_cdp",
                        "action": "browser_script_eval",
                        "payload_contains": needle
                    },
                    "decision": "deny",
                    "reason": "script payload denied by e2e policy"
                }
            ]
        })
        .to_string(),
    )
    .map_err(|error| external_error("deny-payload-script-eval policy setup", error))
}

pub fn deny_target_script_eval_policy(target: &str) -> Result<LocalPolicy, E2eError> {
    LocalPolicy::from_json_str(
        &json!({
            "rules": [
                {
                    "id": "deny-target-script-eval",
                    "match": {
                        "surface": "browser_cdp",
                        "action": "browser_script_eval",
                        "target_contains": target
                    },
                    "decision": "deny",
                    "reason": "script evaluation denied for this page"
                }
            ]
        })
        .to_string(),
    )
    .map_err(|error| external_error("deny-target-script-eval policy setup", error))
}
