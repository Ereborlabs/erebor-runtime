#[allow(dead_code)]
#[path = "support/cli.rs"]
mod cli;
#[path = "support/cli_commands.rs"]
mod cli_commands;

use erebor_runtime_e2e::{error::JsonSnafu, E2eError};
use serde_json::Value;
use snafu::ResultExt;

use crate::{
    cli::{E2eWorkspace, EreborCliFixture},
    cli_commands::CliCommandFixture,
};

#[test]
fn cli_policy_and_audit_commands_use_real_session_fixtures() -> Result<(), E2eError> {
    let erebor_runtime = EreborCliFixture::build()?;
    let workspace = E2eWorkspace::create("cli-command-owners")?;
    let fixture = CliCommandFixture::write(workspace.path())?;
    let policy_path = fixture.policy_path().to_string_lossy().into_owned();
    let event_path = fixture.event_path().to_string_lossy().into_owned();
    let prompt_path = fixture.prompt_path().to_string_lossy().into_owned();

    let policy_stdout = erebor_runtime.run_in(
        workspace.path(),
        [
            "policy",
            "test",
            "--policy",
            policy_path.as_str(),
            "--event",
            event_path.as_str(),
        ],
    )?;
    let decision: Value = serde_json::from_str(policy_stdout.trim()).context(JsonSnafu)?;
    assert_eq!(
        decision.pointer("/type").and_then(Value::as_str),
        Some("deny")
    );
    assert_eq!(
        decision.pointer("/rule_id").and_then(Value::as_str),
        Some("deny-rm")
    );
    assert_eq!(
        decision.pointer("/reason").and_then(Value::as_str),
        Some("destructive shell command denied")
    );

    let tail = erebor_runtime.run_in(workspace.path(), ["audit", "tail", fixture.session_id()])?;
    let lines = tail
        .lines()
        .filter(|line| !line.trim().is_empty())
        .collect::<Vec<_>>();
    assert_eq!(lines.len(), 1);
    let record: Value = serde_json::from_str(lines[0]).context(JsonSnafu)?;
    assert_eq!(
        record
            .pointer("/event/payload/argv_summary")
            .and_then(Value::as_str),
        Some("sh -lc rm -rf /tmp/erebor-cli-fixture")
    );
    assert_eq!(
        record
            .pointer("/final_decision/type")
            .and_then(Value::as_str),
        Some("deny")
    );
    assert_eq!(
        record
            .pointer("/final_decision/rule_id")
            .and_then(Value::as_str),
        Some("deny-rm")
    );

    let report = erebor_runtime.run_in(
        workspace.path(),
        [
            "audit",
            "evidence-trace",
            fixture.session_id(),
            "--prompt",
            prompt_path.as_str(),
            "--purpose",
            "Daemon CLI command-owner e2e fixture",
        ],
    )?;
    assert!(report.contains("# Governed OpenClaw Evidence Trace"));
    assert!(report.contains("session-cli-command-owners"));
    assert!(report.contains("deny-rm"));
    assert!(report.contains("destructive shell command denied"));
    assert!(report.contains("Policy package"));

    Ok(())
}
