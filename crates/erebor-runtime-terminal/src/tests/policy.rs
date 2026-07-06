use std::{fs, io};

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, RuntimeConfig,
    SessionInterceptionDecision,
};

use crate::{TerminalProcessExecValidator, TerminalProcessGuardDecision, TerminalProcessPolicy};

#[test]
fn terminal_policy_compiles_deny_rules_for_process_guard() -> Result<(), Box<dyn std::error::Error>>
{
    let fixture = TerminalPolicyFixture::new()?;
    let runtime = RuntimeConfig::from_json_str(&format!(
        r#"{{
              "policies": ["{}"],
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
        fixture.path().display()
    ))?;
    let start_plan = runtime.surface_start_plan()?;
    let terminal = start_plan
        .terminal()
        .ok_or_else(|| io::Error::other("expected terminal surface config"))?;
    let policy = TerminalProcessPolicy::from_config(terminal)?;
    let rules = policy.rules();

    assert_eq!(rules.rules().len(), 3);
    assert_eq!(rules.rules()[0].match_token(), "remote-debugging-port");
    assert_eq!(rules.rules()[0].reason(), "raw CDP is denied");
    assert_eq!(rules.rules()[0].rule_id(), "deny-raw-cdp");
    assert_eq!(
        rules.rules()[0].decision(),
        TerminalProcessGuardDecision::Deny
    );
    assert_eq!(rules.rules()[1].match_token(), "git push");
    assert_eq!(
        rules.rules()[1].reason(),
        "git push needs operator verification"
    );
    assert_eq!(rules.rules()[1].rule_id(), "approve-git-push");
    assert_eq!(
        rules.rules()[1].decision(),
        TerminalProcessGuardDecision::RequireApproval
    );
    assert_eq!(rules.rules()[2].match_token(), "ls -la");
    assert_eq!(
        rules.rules()[2].decision(),
        TerminalProcessGuardDecision::Allow
    );

    let decision = policy
        .decide_process_exec(
            "google-chrome",
            &[String::from("--remote-debugging-port=9222")],
        )
        .ok_or_else(|| io::Error::other("expected terminal process decision"))?;
    assert_eq!(decision.rule_id(), "deny-raw-cdp");
    assert_eq!(decision.reason(), "raw CDP is denied");
    assert_eq!(decision.decision(), TerminalProcessGuardDecision::Deny);

    let validator = TerminalProcessExecValidator::from_config(terminal)?;
    let argv = vec![String::from("--remote-debugging-port=9222")];
    let request = ProcessExecInterceptionRequest::new("google-chrome", &argv, "");
    let (decision, rule_id, reason, mediation) =
        validator.decide_process_exec(&request).into_parts();
    assert_eq!(decision, SessionInterceptionDecision::Deny);
    assert_eq!(rule_id, "deny-raw-cdp");
    assert_eq!(reason, "raw CDP is denied");
    assert_eq!(mediation, None);

    Ok(())
}

struct TerminalPolicyFixture {
    path: std::path::PathBuf,
}

impl TerminalPolicyFixture {
    fn new() -> Result<Self, std::io::Error> {
        let path = std::env::temp_dir().join(format!(
            "erebor-terminal-policy-{}.json",
            std::process::id()
        ));
        fs::write(&path, Self::source())?;
        Ok(Self { path })
    }

    fn path(&self) -> &std::path::Path {
        &self.path
    }

    fn source() -> &'static str {
        r#"
            {
              "rules": [
                {
                  "id": "deny-raw-cdp",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "remote-debugging-port"
                  },
                  "decision": "deny",
                  "reason": "raw CDP is denied"
                },
                {
                  "id": "approve-git-push",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "command_contains": "git push"
                  },
                  "decision": "require_approval",
                  "reason": "git push needs operator verification"
                },
                {
                  "id": "allow-ls",
                  "match": {
                    "surface": "terminal",
                    "action": "process_exec",
                    "payload_contains": "ls -la"
                  },
                  "decision": "allow"
                }
              ]
            }
            "#
    }
}

impl Drop for TerminalPolicyFixture {
    fn drop(&mut self) {
        let _result = fs::remove_file(&self.path);
    }
}
