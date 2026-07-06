use std::{fs, io};

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, RuntimeConfig,
    SessionInterceptionDecision,
};

use crate::TerminalProcessExecValidator;

use super::fixtures::TestMediationCapability;

#[test]
fn terminal_process_interception_handlers_own_surface_decisions(
) -> Result<(), Box<dyn std::error::Error>> {
    let fixture = TerminalMediationConfigFixture::new()?;
    let config = RuntimeConfig::from_json_str(&fixture.config_source())?;
    let terminal = config
        .surface_start_plan()?
        .terminal()
        .ok_or_else(|| io::Error::other("expected terminal surface config"))?
        .clone();
    let mut validator = TerminalProcessExecValidator::from_config(&terminal)?;
    validator.set_process_mediation_capability(TestMediationCapability);
    let argv = vec![String::from("google-chrome")];

    let (decision, rule_id, _reason, mediation) = validator
        .decide_process_exec(&ProcessExecInterceptionRequest::new(
            "google-chrome",
            &argv,
            "allow-browser",
        ))
        .into_parts();
    assert_eq!(decision, SessionInterceptionDecision::Allow);
    assert_eq!(rule_id, "allow-browser");
    assert_eq!(mediation, None);

    let (decision, rule_id, _reason, mediation) = validator
        .decide_process_exec(&ProcessExecInterceptionRequest::new(
            "google-chrome",
            &argv,
            "deny-browser",
        ))
        .into_parts();
    assert_eq!(decision, SessionInterceptionDecision::Deny);
    assert_eq!(rule_id, "deny-browser");
    assert_eq!(mediation, None);

    let (decision, rule_id, _reason, mediation) = validator
        .decide_process_exec(&ProcessExecInterceptionRequest::new(
            "google-chrome",
            &argv,
            "approve-browser",
        ))
        .into_parts();
    assert_eq!(decision, SessionInterceptionDecision::RequireApproval);
    assert_eq!(rule_id, "approve-browser");
    assert_eq!(mediation, None);

    let (decision, rule_id, reason, mediation) = validator
        .decide_process_exec(&ProcessExecInterceptionRequest::new(
            "google-chrome",
            &argv,
            "mediate-browser",
        ))
        .into_parts();
    assert_eq!(decision, SessionInterceptionDecision::Mediate);
    assert_eq!(rule_id, "mediate-browser");
    assert_eq!(
        reason,
        "process launch mediated by terminal process surface"
    );
    assert!(mediation.is_some());

    Ok(())
}

struct TerminalMediationConfigFixture {
    policy_path: std::path::PathBuf,
}

impl TerminalMediationConfigFixture {
    fn new() -> Result<Self, std::io::Error> {
        let policy_path = std::env::temp_dir().join(format!(
            "erebor-terminal-mediation-policy-{}.json",
            std::process::id()
        ));
        fs::write(&policy_path, r#"{"rules":[]}"#)?;
        Ok(Self { policy_path })
    }

    fn config_source(&self) -> String {
        r#"
            {
              "policies": ["__POLICY_PATH__"],
              "session": {
                "interception": {
                  "enabled": true
                }
              },
              "surfaces": {
                "terminal": {
                  "enabled": true,
                  "process_interception": {
                    "enabled": true,
                    "handlers": [
                      {
                        "id": "allow-browser",
                        "decision": "allow",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] }
                      },
                      {
                        "id": "deny-browser",
                        "decision": "deny",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] }
                      },
                      {
                        "id": "approve-browser",
                        "decision": "require_approval",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] }
                      },
                      {
                        "id": "mediate-browser",
                        "decision": "mediate",
                        "kind": "managed_browser_cdp",
                        "match": { "executables": ["google-chrome"] },
                        "compatibility": {
                          "print_devtools_listening_line": true,
                          "keepalive": true
                        }
                      }
                    ]
                  }
                },
                "browser_cdp": {
                  "enabled": true,
                  "listen": "127.0.0.1:9222"
                }
              }
            }
            "#
        .replace("__POLICY_PATH__", &self.policy_path.display().to_string())
    }
}

impl Drop for TerminalMediationConfigFixture {
    fn drop(&mut self) {
        let _result = fs::remove_file(&self.policy_path);
    }
}
