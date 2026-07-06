use std::time::{SystemTime, UNIX_EPOCH};

use clap::{CommandFactory, Parser};

use super::{test_support::RegistrySessionFixture, Cli};

#[test]
fn rejects_unknown_arguments() {
    let error = Cli::try_parse_from(["erebor-runtime", "start", "--unknown"]);

    assert!(error.is_err());
}

#[test]
fn accepts_single_runtime_command_with_config() {
    let cli = Cli::try_parse_from(["erebor-runtime", "start", "--config", "erebor.json"]);

    assert!(cli.is_ok());
}

#[test]
fn requires_config_for_runtime_start() {
    let error = Cli::try_parse_from(["erebor-runtime", "start"]);

    assert!(error.is_err());
}

#[test]
fn accepts_session_run_and_diagnose_commands() {
    let run = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "run",
        "--runner",
        "docker",
        "--config",
        "pilot-session.json",
        "openclaw",
        "--help",
    ]);
    let diagnose = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "diagnose",
        "--runner",
        "docker",
        "--config",
        "pilot-session.json",
        "list-workspace",
    ]);

    assert!(run.is_ok());
    assert!(diagnose.is_ok());
}

#[test]
fn rejects_session_run_tty_flag() {
    let error = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "run",
        "--runner",
        "docker",
        "--tty",
        "--config",
        "pilot-session.json",
        "openclaw",
    ]);

    assert!(error.is_err());
}

#[test]
fn accepts_and_rejects_session_adopt_targets() {
    let pid = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "adopt",
        "--runner",
        "linux-host",
        "--config",
        "pilot-session.json",
        "--pid",
        "1234",
    ]);
    let by_match = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "adopt",
        "--runner",
        "linux-host",
        "--config",
        "pilot-session.json",
        "--match",
        "openclaw",
    ]);
    let multiple = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "adopt",
        "--runner",
        "linux-host",
        "--config",
        "pilot-session.json",
        "--pid",
        "1234",
        "--match",
        "openclaw",
    ]);
    let missing = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "adopt",
        "--runner",
        "linux-host",
        "--config",
        "pilot-session.json",
    ]);

    assert!(pid.is_ok());
    assert!(by_match.is_ok());
    assert!(multiple.is_err());
    assert!(missing.is_err());
}

#[test]
fn accepts_registry_session_review_commands_and_rejects_old_flags() {
    let ls = Cli::try_parse_from(["erebor-runtime", "session", "ls"]);
    let show = Cli::try_parse_from(["erebor-runtime", "session", "show", "session-1"]);
    let describe = Cli::try_parse_from(["erebor-runtime", "session", "describe", "session-1"]);
    let old_ls = Cli::try_parse_from(["erebor-runtime", "session", "ls", "--audit", "audit"]);
    let old_show = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "show",
        "session-1",
        "--audit",
        "audit.jsonl",
    ]);

    assert!(ls.is_ok());
    assert!(show.is_ok());
    assert!(describe.is_ok());
    assert!(old_ls.is_err());
    assert!(old_show.is_err());
}

#[test]
fn accepts_session_review_json_format() {
    let ls = Cli::try_parse_from(["erebor-runtime", "session", "ls", "--format", "json"]);
    let show = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "show",
        "session-1",
        "--format",
        "json",
    ]);
    let describe = Cli::try_parse_from([
        "erebor-runtime",
        "session",
        "describe",
        "session-1",
        "--format",
        "json",
    ]);

    assert!(ls.is_ok());
    assert!(show.is_ok());
    assert!(describe.is_ok());
}

#[test]
fn accepts_filesystem_transaction_catalog_commands() {
    let list = Cli::try_parse_from([
        "erebor-runtime",
        "filesystem",
        "transactions",
        "list",
        "--registry",
        ".erebor/sessions",
        "--session",
        "session-1",
    ]);
    let rollback = Cli::try_parse_from([
        "erebor-runtime",
        "filesystem",
        "transactions",
        "rollback",
        "--registry",
        ".erebor/sessions",
        "--session",
        "session-1",
        "tx@{0}.sub@{1}",
    ]);

    assert!(list.is_ok());
    assert!(rollback.is_ok());
}

#[test]
fn accepts_policy_and_audit_commands() {
    let policy = Cli::try_parse_from([
        "erebor-runtime",
        "policy",
        "test",
        "--policy",
        "policy.json",
        "--event",
        "event.json",
    ]);
    let evidence = Cli::try_parse_from([
        "erebor-runtime",
        "audit",
        "evidence-trace",
        "session-1",
        "--prompt",
        "prompt.txt",
        "--out",
        "evidence-trace.md",
    ]);

    assert!(policy.is_ok());
    assert!(evidence.is_ok());
}

#[test]
fn rejects_invalid_dev_and_audit_options() {
    let cdp = Cli::try_parse_from([
        "erebor-runtime",
        "dev",
        "proxy-cdp",
        "--browser-url",
        "http://localhost:9222",
        "--policy",
        "policy.json",
    ]);
    let audit = Cli::try_parse_from([
        "erebor-runtime",
        "audit",
        "evidence-trace",
        "session-1",
        "--registry",
        ".erebor/sessions",
    ]);

    assert!(cdp.is_err());
    assert!(audit.is_err());
}

#[test]
fn accepts_restrictive_global_log_level() {
    let cli = Cli::try_parse_from([
        "erebor-runtime",
        "--log-level",
        "debug",
        "start",
        "--config",
        "erebor.json",
    ]);

    assert!(cli.is_ok());
}

#[test]
fn rejects_unknown_log_level() {
    let error = Cli::try_parse_from([
        "erebor-runtime",
        "--log-level",
        "verbose",
        "start",
        "--config",
        "erebor.json",
    ]);

    assert!(error.is_err());
}

#[test]
fn audit_tail_rejects_invalid_jsonl() -> Result<(), Box<dyn std::error::Error>> {
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let session_id = format!("session-invalid-audit-{nanos}-{}", std::process::id());
    let _fixture = RegistrySessionFixture::write_invalid_audit(&session_id)?;
    let cli = Cli::try_parse_from(["erebor-runtime", "audit", "tail", session_id.as_str()])?;

    assert!(cli.execute().is_err());
    Ok(())
}

#[test]
fn clap_debug_assertions_pass() {
    Cli::command().debug_assert();
}
