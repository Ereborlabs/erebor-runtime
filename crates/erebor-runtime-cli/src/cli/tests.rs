use std::time::{SystemTime, UNIX_EPOCH};

use clap::{CommandFactory, Parser};

use super::{test_support::RegistrySessionFixture, Cli};

#[test]
fn rejects_unknown_arguments() {
    let error = Cli::try_parse_from(["erebor", "start", "--unknown"]);

    assert!(error.is_err());
}

#[test]
fn accepts_single_runtime_command_with_config() {
    let cli = Cli::try_parse_from(["erebor", "start", "--config", "erebor.json"]);

    assert!(cli.is_ok());
}

#[test]
fn requires_config_for_runtime_start() {
    let error = Cli::try_parse_from(["erebor", "start"]);

    assert!(error.is_err());
}

#[test]
fn accepts_transitional_codex_run_and_daemon_generic_run() {
    let run = Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--runner",
        "docker",
        "--config",
        "pilot-session.json",
        "--",
        "/opt/codex/codex",
        "--help",
    ]);
    let generic = Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--package-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--installation-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--adapter-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--policy-set-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--idempotency-key",
        "run-1",
        "--",
        "/usr/bin/true",
    ]);

    assert!(run.is_ok());
    assert!(generic.is_ok());
}

#[test]
fn generic_session_run_accepts_admitted_tty_request() {
    let run = Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--package-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--installation-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--adapter-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--policy-set-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--idempotency-key",
        "run-1",
        "--tty",
        "--",
        "/usr/bin/true",
    ]);

    assert!(run.is_ok());
}

#[test]
fn rejects_session_adoption() {
    assert!(Cli::try_parse_from(["erebor", "session", "adopt", "--pid", "1234"]).is_err());
}

#[test]
fn session_reviews_use_the_daemon_session_api() {
    assert!(Cli::try_parse_from(["erebor", "session", "ps"]).is_ok());
    assert!(Cli::try_parse_from(["erebor", "session", "ls"]).is_ok());
    assert!(Cli::try_parse_from(["erebor", "session", "inspect", "session-1"]).is_ok());
    assert!(Cli::try_parse_from(["erebor", "session", "show", "session-1"]).is_err());
    assert!(Cli::try_parse_from(["erebor", "session", "describe", "session-1"]).is_err());
}

#[test]
fn accepts_filesystem_transaction_catalog_commands() {
    let list = Cli::try_parse_from([
        "erebor",
        "filesystem",
        "transactions",
        "list",
        "--registry",
        ".erebor/sessions",
        "--session",
        "session-1",
    ]);
    let commit = Cli::try_parse_from([
        "erebor",
        "filesystem",
        "transactions",
        "commit",
        "--registry",
        ".erebor/sessions",
        "--session",
        "session-1",
        "--name",
        "before risky edit",
    ]);
    let rollback = Cli::try_parse_from([
        "erebor",
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
    assert!(commit.is_ok());
    assert!(rollback.is_ok());
}

#[test]
fn accepts_filesystem_retention_commands() {
    let list = Cli::try_parse_from([
        "erebor",
        "filesystem",
        "retention",
        "list",
        "--registry",
        ".erebor/sessions",
        "--session",
        "session-1",
    ]);
    let prune = Cli::try_parse_from([
        "erebor",
        "filesystem",
        "retention",
        "prune",
        "--registry",
        ".erebor/sessions",
        "--session",
        "session-1",
        "tx@{0}",
    ]);
    let json = Cli::try_parse_from([
        "erebor",
        "filesystem",
        "retention",
        "list",
        "--registry",
        ".erebor/sessions",
        "--session",
        "session-1",
        "--format",
        "json",
    ]);

    assert!(list.is_ok());
    assert!(prune.is_ok());
    assert!(json.is_ok());
}

#[test]
fn accepts_policy_and_audit_commands() {
    let policy = Cli::try_parse_from([
        "erebor",
        "policy",
        "test",
        "--policy",
        "policy.json",
        "--event",
        "event.json",
    ]);
    let evidence = Cli::try_parse_from([
        "erebor",
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
        "erebor",
        "dev",
        "proxy-cdp",
        "--browser-url",
        "http://localhost:9222",
        "--policy",
        "policy.json",
    ]);
    let audit = Cli::try_parse_from([
        "erebor",
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
        "erebor",
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
        "erebor",
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
    let cli = Cli::try_parse_from(["erebor", "audit", "tail", session_id.as_str()])?;

    assert!(cli.execute().is_err());
    Ok(())
}

#[test]
fn clap_debug_assertions_pass() {
    Cli::command().debug_assert();
}
