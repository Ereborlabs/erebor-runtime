use erebor_runtime_policy::LocalPolicy;

use super::support::{context, ApproveAll};
use crate::{
    CdpCommandDecoder, CdpCommandEnforcer, CdpEnforcementAction, CdpSessionState,
    ClientTargetSessions,
};

#[test]
fn forwards_ungoverned_messages() -> Result<(), Box<dyn std::error::Error>> {
    let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
    let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
    let command = CdpCommandDecoder::decode(r#"{ "id": 1, "method": "Browser.getVersion" }"#)?;

    let action = CdpCommandEnforcer::enforce(&engine, &context(), &command)?;

    assert_eq!(action, CdpEnforcementAction::Forward);
    Ok(())
}

#[test]
fn blocks_denied_governed_messages() -> Result<(), Box<dyn std::error::Error>> {
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "deny-script-eval",
          "match": { "surface": "browser_cdp", "action": "browser_script_eval" },
          "decision": "deny",
          "reason": "script evaluation denied"
        }] }"#,
    )?;
    let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
    let command = CdpCommandDecoder::decode(
        r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce(&engine, &context(), &command)?;

    assert_eq!(
        action,
        CdpEnforcementAction::Block {
            reason: String::from("script evaluation denied")
        }
    );
    Ok(())
}

#[test]
fn blocks_denied_target_management_messages() -> Result<(), Box<dyn std::error::Error>> {
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "deny-target-management",
          "match": { "surface": "browser_cdp", "action": "browser_target_manage" },
          "decision": "deny",
          "reason": "target management denied"
        }] }"#,
    )?;
    let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
    let command = CdpCommandDecoder::decode(
        r#"{ "id": 4, "method": "Target.setAutoAttach", "params": { "autoAttach": true, "waitForDebuggerOnStart": false, "flatten": true } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce(&engine, &context(), &command)?;

    assert_eq!(
        action,
        CdpEnforcementAction::Block {
            reason: String::from("target management denied")
        }
    );
    Ok(())
}

#[test]
fn ambiguous_browser_level_session_commands_fail_closed() -> Result<(), Box<dyn std::error::Error>>
{
    let policy = LocalPolicy::from_json_str(r#"{ "rules": [] }"#)?;
    let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
    let command = CdpCommandDecoder::decode(
        r#"{ "id": 12, "sessionId": "missing-session", "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce_for_client_state(
        &engine,
        &context(),
        &command,
        &CdpSessionState::default(),
        Some(&ClientTargetSessions::default()),
    )?;

    assert_eq!(
        action,
        CdpEnforcementAction::Block {
            reason: String::from("browser target is unknown for CDP session")
        }
    );
    Ok(())
}

#[test]
fn pauses_approval_required_governed_messages() -> Result<(), Box<dyn std::error::Error>> {
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "approve-script-eval",
          "match": { "surface": "browser_cdp", "action": "browser_script_eval" },
          "decision": "require_approval",
          "reason": "script evaluation requires approval"
        }] }"#,
    )?;
    let engine = erebor_runtime_core::LocalEnforcementEngine::with_hooks(
        policy,
        ApproveAll,
        erebor_runtime_core::NoopAuditSink,
    );
    let command = CdpCommandDecoder::decode(
        r#"{ "id": 1, "method": "Runtime.evaluate", "params": { "expression": "1 + 1" } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce(&engine, &context(), &command)?;

    assert_eq!(
        action,
        CdpEnforcementAction::AwaitApproval {
            reason: String::from("script evaluation requires approval")
        }
    );
    Ok(())
}

#[test]
fn script_eval_policy_can_match_active_page_context() -> Result<(), Box<dyn std::error::Error>> {
    let policy = LocalPolicy::from_json_str(
        r#"{ "rules": [{
          "id": "deny-email-send",
          "match": {
            "surface": "browser_cdp",
            "action": "browser_script_eval",
            "target_contains": "mail.example.test"
          },
          "decision": "deny",
          "reason": "email send is not allowed from this page"
        }] }"#,
    )?;
    let engine = erebor_runtime_core::LocalEnforcementEngine::new(policy);
    let state = CdpSessionState::from_browser_url("ws://127.0.0.1:1/devtools/page/page-1");
    let navigate = CdpCommandDecoder::decode(
        r#"{ "id": 1, "method": "Page.navigate", "params": { "url": "https://mail.example.test/compose" } }"#,
    )?;
    state.record_provisional_forwarded_command(
        navigate
            .protocol_command()
            .ok_or_else(|| std::io::Error::other("missing navigate command"))?,
    );
    let send = CdpCommandDecoder::decode(
        r#"{ "id": 2, "method": "Runtime.evaluate", "params": { "expression": "send()" } }"#,
    )?;

    let action = CdpCommandEnforcer::enforce_for_session_state(&engine, &context(), &send, &state)?;

    assert_eq!(
        action,
        CdpEnforcementAction::Block {
            reason: String::from("email send is not allowed from this page")
        }
    );
    Ok(())
}
