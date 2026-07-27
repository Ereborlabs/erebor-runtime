use clap::{CommandFactory, Parser};

use super::{Cli, DaemonSocketArgs};

#[test]
fn socket_override_is_available_to_each_daemon_client_command() {
    for arguments in [
        vec![
            "erebor",
            "--socket",
            "/tmp/erebor.sock",
            "agent",
            "load",
            "codex-v1",
            "--from",
            "/tmp/codex",
            "--adapter",
            "codex-v1",
            "--name",
            "local-codex",
        ],
        vec![
            "erebor",
            "--socket",
            "/tmp/erebor.sock",
            "run",
            "--policy",
            "fixture",
            "codex",
        ],
        vec!["erebor", "--socket", "/tmp/erebor.sock", "session", "ps"],
        vec![
            "erebor",
            "--socket",
            "/tmp/erebor.sock",
            "policy",
            "package",
            "ls",
        ],
        vec!["erebor", "--socket", "/tmp/erebor.sock", "runner", "ls"],
        vec![
            "erebor",
            "--socket",
            "/tmp/erebor.sock",
            "audit",
            "tail",
            "session-1",
        ],
        vec!["erebor", "--socket", "/tmp/erebor.sock", "approval", "ls"],
        vec!["erebor", "--socket", "/tmp/erebor.sock", "daemon", "status"],
    ] {
        let parsed = Cli::try_parse_from(arguments);
        assert!(parsed.is_ok(), "{parsed:?}");
    }
    assert!(
        Cli::try_parse_from(["erebor", "--socket", "relative.sock", "daemon", "status"]).is_err()
    );
}

#[test]
fn socket_override_rejects_unmigrated_foreground_commands() {
    let selected = DaemonSocketArgs {
        socket: Some("/tmp/erebor.sock".into()),
    };
    assert!(selected.validate_legacy_command("erebor start").is_err());
    assert!(selected
        .validate_legacy_command("erebor filesystem")
        .is_err());
    assert!(DaemonSocketArgs { socket: None }
        .validate_legacy_command("erebor start")
        .is_ok());
}

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
fn accepts_daemon_owned_codex_run_and_generic_run() {
    let run = Cli::try_parse_from(["erebor", "run", "--policy", "engineering", "local-codex"]);
    let generic = Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--idempotency-key",
        "run-1",
        "--",
        "/usr/bin/true",
    ]);

    assert!(run.is_ok());
    assert!(generic.is_ok());
}

#[test]
fn agent_load_is_the_only_public_codex_enrollment_verb() {
    let load = Cli::try_parse_from([
        "erebor",
        "agent",
        "load",
        "codex-v1-fixture",
        "--from",
        "/opt/codex-v1-fixture",
        "--adapter",
        "codex-v1",
        "--name",
        "local-codex",
    ]);
    let stale_install = Cli::try_parse_from([
        "erebor",
        "agent",
        "install",
        "codex-v1-fixture",
        "--from",
        "/opt/codex-v1-fixture",
    ]);

    assert!(load.is_ok());
    assert!(stale_install.is_err());
}

#[test]
fn named_codex_agents_do_not_accept_raw_arguments() {
    let raw_argv = Cli::try_parse_from([
        "erebor",
        "run",
        "--policy",
        "fixture",
        "local-codex",
        "--",
        "--escape-daemon-entrypoint",
    ]);

    assert!(raw_argv.is_err());
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
        "--idempotency-key",
        "run-1",
        "--tty",
        "--",
        "/usr/bin/true",
    ]);

    assert!(run.is_ok());
}

#[test]
fn phase_five_rejects_raw_identity_flags_and_retired_policy_set_aliases() {
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--package-digest",
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "--idempotency-key",
        "run-1",
        "--",
        "/usr/bin/true",
    ])
    .is_err());
    assert!(
        Cli::try_parse_from(["erebor", "policy", "set", "alias", "fixture", "anything",]).is_err()
    );
    assert!(Cli::try_parse_from([
        "erebor",
        "policyset",
        "create",
        "--name",
        "fixture",
        "--package",
        "host-minimum",
        "--idempotency-key",
        "policyset-1",
    ])
    .is_ok());
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
fn surface_commands_use_named_independent_resources() {
    assert!(Cli::try_parse_from([
        "erebor",
        "surface",
        "create",
        "engineering-browser",
        "--type",
        "browser_cdp",
        "--idempotency-key",
        "surface-1",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["erebor", "surface", "ls"]).is_ok());
    assert!(Cli::try_parse_from(["erebor", "surface", "inspect", "engineering-browser"]).is_ok());
}

#[test]
fn accepts_daemon_owned_session_alias_commands() {
    let set = Cli::try_parse_from([
        "erebor",
        "session",
        "alias",
        "set",
        "demo",
        "session-1",
        "--idempotency-key",
        "alias-set-1",
    ]);
    let remove = Cli::try_parse_from([
        "erebor",
        "session",
        "alias",
        "remove",
        "demo",
        "--idempotency-key",
        "alias-remove-1",
    ]);
    let list = Cli::try_parse_from(["erebor", "session", "alias", "ls"]);

    assert!(set.is_ok());
    assert!(remove.is_ok());
    assert!(list.is_ok());
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
        "--after-sequence",
        "4",
        "--maximum-records",
        "8",
    ]);
    let tail = Cli::try_parse_from([
        "erebor",
        "audit",
        "tail",
        "session-1",
        "--after-sequence",
        "4",
        "--maximum-records",
        "8",
    ]);

    assert!(policy.is_ok());
    assert!(evidence.is_ok());
    assert!(tail.is_ok());
}

#[test]
fn accepts_daemon_owned_policy_catalog_commands() {
    for command in [
        vec!["erebor", "policy", "package", "ls"],
        vec!["erebor", "policy", "package", "inspect", "workspace-write"],
        vec!["erebor", "policy", "package", "verify", "workspace-write"],
        vec!["erebor", "policyset", "ls"],
        vec!["erebor", "policyset", "inspect", "company-workspace"],
        vec!["erebor", "policyset", "verify", "company-workspace"],
    ] {
        assert!(Cli::try_parse_from(command).is_ok());
    }
}

#[test]
fn policy_package_apply_requires_an_explicit_resource_name() {
    assert!(Cli::try_parse_from([
        "erebor",
        "policy",
        "package",
        "apply",
        "/work/fixture-baseline",
        "--name",
        "fixture-baseline",
        "--idempotency-key",
        "policy-package-1",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "erebor",
        "policy",
        "package",
        "apply",
        "/work/fixture-baseline",
        "--idempotency-key",
        "policy-package-1",
    ])
    .is_err());
}

#[test]
fn rejects_removed_dev_and_invalid_audit_options() {
    let dev = Cli::try_parse_from(["erebor", "dev"]);
    let audit = Cli::try_parse_from([
        "erebor",
        "audit",
        "evidence-trace",
        "session-1",
        "--registry",
        ".erebor/sessions",
    ]);

    assert!(dev.is_err());
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
fn clap_debug_assertions_pass() {
    Cli::command().debug_assert();
}
