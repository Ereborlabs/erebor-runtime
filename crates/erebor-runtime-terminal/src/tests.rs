use std::{fs, io};

use erebor_runtime_core::{
    ProcessExecInterceptionRequest, ProcessExecSurfaceHandler, RuntimeConfig,
    SessionInterceptionDecision, SurfaceMediationDecision,
};

use crate::{
    compile_terminal_process_guard_rules, TerminalProcessExecValidator,
    TerminalProcessGuardDecision, TerminalProcessGuardRule, TerminalProcessGuardRules,
    TerminalProcessMediationCapability, TerminalProcessPolicy,
};

#[test]
fn guard_rules_serialize_for_docker_environment() {
    let rules = TerminalProcessGuardRules::new(vec![
        TerminalProcessGuardRule::new(
            "/tmp/erebor/shims/google-chrome",
            "managed shim launch",
            "allow-mediated-browser",
            TerminalProcessGuardDecision::Allow,
        ),
        TerminalProcessGuardRule::new(
            "remote-debugging-port",
            "raw CDP\nis denied",
            "deny\tcdp",
            TerminalProcessGuardDecision::Deny,
        ),
    ]);

    assert_eq!(
            rules.to_docker_env_value(),
            "/tmp/erebor/shims/google-chrome\tmanaged shim launch\tallow-mediated-browser\tallow\nremote-debugging-port\traw CDP is denied\tdeny cdp\tdeny"
        );
}

#[test]
fn terminal_policy_compiles_deny_rules_for_process_guard() -> Result<(), Box<dyn std::error::Error>>
{
    let policy_path = std::env::temp_dir().join(format!(
        "erebor-terminal-policy-{}.json",
        std::process::id()
    ));
    fs::write(
        &policy_path,
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
            "#,
    )?;

    let runtime = RuntimeConfig::from_json_str(&format!(
        r#"{{
              "policies": ["{}"],
              "surfaces": {{
                "terminal": {{
                  "enabled": true
                }}
              }}
            }}"#,
        policy_path.display()
    ))?;
    let start_plan = runtime.surface_start_plan()?;
    let terminal = start_plan
        .terminal()
        .ok_or_else(|| io::Error::other("expected terminal surface config"))?;
    let rules = compile_terminal_process_guard_rules(terminal)?;

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

    let policy = TerminalProcessPolicy::from_config(terminal)?;
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

    fs::remove_file(policy_path)?;
    Ok(())
}

#[test]
fn guard_rules_can_prepend_generated_allow_rules() {
    let mut rules = TerminalProcessGuardRules::new(vec![TerminalProcessGuardRule::new(
        "remote-debugging-port",
        "raw CDP is denied",
        "deny-raw-cdp",
        TerminalProcessGuardDecision::Deny,
    )]);

    rules.prepend(vec![TerminalProcessGuardRule::new(
        "/tmp/erebor/shims/google-chrome",
        "managed browser launch shim",
        "allow-managed-browser-cdp-shim",
        TerminalProcessGuardDecision::Allow,
    )]);

    assert_eq!(rules.rules().len(), 2);
    assert_eq!(
        rules.rules()[0].decision(),
        TerminalProcessGuardDecision::Allow
    );
    assert_eq!(
        rules.rules()[1].decision(),
        TerminalProcessGuardDecision::Deny
    );
}

#[test]
fn terminal_process_interception_handlers_own_surface_decisions(
) -> Result<(), Box<dyn std::error::Error>> {
    let policy_path = std::env::temp_dir().join(format!(
        "erebor-terminal-mediation-policy-{}.json",
        std::process::id()
    ));
    fs::write(&policy_path, r#"{"rules":[]}"#)?;

    let config_source = r#"
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
    .replace("__POLICY_PATH__", &policy_path.display().to_string());
    let config = RuntimeConfig::from_json_str(&config_source)?;
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

    fs::remove_file(policy_path)?;
    Ok(())
}

struct TestMediationCapability;

impl TerminalProcessMediationCapability for TestMediationCapability {
    fn mediate_process_exec(
        &self,
        _request: &ProcessExecInterceptionRequest<'_>,
        handler: &erebor_runtime_core::ProcessMediationHandlerConfig,
    ) -> Result<SurfaceMediationDecision, String> {
        Ok(SurfaceMediationDecision::new(
            handler.kind().as_str(),
            "browser_cdp",
            "ws://127.0.0.1:9222/",
        ))
    }
}
