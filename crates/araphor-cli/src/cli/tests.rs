use clap::{CommandFactory, Parser};

use super::{Cli, DaemonSocketArgs};

#[test]
fn socket_override_is_available_to_each_daemon_client_command() {
    for arguments in [
        vec![
            "araphor",
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
            "araphor",
            "--socket",
            "/tmp/erebor.sock",
            "run",
            "--policy",
            "fixture",
            "codex",
        ],
        vec!["araphor", "--socket", "/tmp/erebor.sock", "session", "ps"],
        vec![
            "araphor",
            "--socket",
            "/tmp/erebor.sock",
            "policy",
            "package",
            "ls",
        ],
        vec!["araphor", "--socket", "/tmp/erebor.sock", "runner", "ls"],
        vec![
            "araphor",
            "--socket",
            "/tmp/erebor.sock",
            "audit",
            "tail",
            "session-1",
        ],
        vec!["araphor", "--socket", "/tmp/erebor.sock", "approval", "ls"],
        vec![
            "araphor",
            "--socket",
            "/tmp/erebor.sock",
            "daemon",
            "status",
        ],
    ] {
        let parsed = Cli::try_parse_from(arguments);
        assert!(parsed.is_ok(), "{parsed:?}");
    }
    assert!(
        Cli::try_parse_from(["araphor", "--socket", "relative.sock", "daemon", "status"]).is_err()
    );
}

#[test]
fn socket_override_rejects_unmigrated_foreground_commands() {
    let selected = DaemonSocketArgs {
        socket: Some("/tmp/erebor.sock".into()),
    };
    assert!(selected.validate_foreground("araphor start").is_err());
    assert!(selected.validate_foreground("araphor filesystem").is_err());
    assert!(DaemonSocketArgs { socket: None }
        .validate_foreground("araphor start")
        .is_ok());
}

#[test]
fn rejects_unknown_arguments() {
    let error = Cli::try_parse_from(["araphor", "start", "--unknown"]);

    assert!(error.is_err());
}

#[test]
fn accepts_single_runtime_command_with_config() {
    let cli = Cli::try_parse_from(["araphor", "start", "--config", "erebor.json"]);

    assert!(cli.is_ok());
}

#[test]
fn requires_config_for_runtime_start() {
    let error = Cli::try_parse_from(["araphor", "start"]);

    assert!(error.is_err());
}

#[test]
fn accepts_daemon_owned_codex_run_and_generic_run() {
    let run = Cli::try_parse_from(["araphor", "run", "--policy", "engineering", "local-codex"]);
    let generic = Cli::try_parse_from([
        "araphor",
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
        "araphor",
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
        "araphor",
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
        "araphor",
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
        "araphor",
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
        "araphor",
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
        Cli::try_parse_from(["araphor", "policy", "set", "alias", "fixture", "anything",]).is_err()
    );
    assert!(Cli::try_parse_from([
        "araphor",
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
    assert!(Cli::try_parse_from(["araphor", "session", "adopt", "--pid", "1234"]).is_err());
}

#[test]
fn session_reviews_use_the_daemon_session_api() {
    assert!(Cli::try_parse_from(["araphor", "session", "ps"]).is_ok());
    assert!(Cli::try_parse_from(["araphor", "session", "ls"]).is_ok());
    assert!(Cli::try_parse_from(["araphor", "session", "inspect", "session-1"]).is_ok());
    assert!(Cli::try_parse_from(["araphor", "session", "show", "session-1"]).is_err());
    assert!(Cli::try_parse_from(["araphor", "session", "describe", "session-1"]).is_err());
}

#[test]
fn surface_commands_use_named_independent_resources() {
    assert!(Cli::try_parse_from([
        "araphor",
        "surface",
        "create",
        "engineering-browser",
        "--type",
        "browser_cdp",
        "--idempotency-key",
        "surface-1",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["araphor", "surface", "ls"]).is_ok());
    assert!(Cli::try_parse_from(["araphor", "surface", "inspect", "engineering-browser"]).is_ok());
}

#[test]
fn accepts_daemon_owned_session_alias_commands() {
    let set = Cli::try_parse_from([
        "araphor",
        "session",
        "alias",
        "set",
        "demo",
        "session-1",
        "--idempotency-key",
        "alias-set-1",
    ]);
    let remove = Cli::try_parse_from([
        "araphor",
        "session",
        "alias",
        "remove",
        "demo",
        "--idempotency-key",
        "alias-remove-1",
    ]);
    let list = Cli::try_parse_from(["araphor", "session", "alias", "ls"]);

    assert!(set.is_ok());
    assert!(remove.is_ok());
    assert!(list.is_ok());
}

#[test]
fn accepts_filesystem_transaction_catalog_commands() {
    let list = Cli::try_parse_from([
        "araphor",
        "filesystem",
        "transactions",
        "list",
        "--session",
        "session-1",
    ]);
    let commit = Cli::try_parse_from([
        "araphor",
        "filesystem",
        "transactions",
        "commit",
        "--session",
        "session-1",
        "--name",
        "before risky edit",
        "--idempotency-key",
        "transaction-commit-1",
    ]);
    let rollback = Cli::try_parse_from([
        "araphor",
        "filesystem",
        "transactions",
        "rollback",
        "--session",
        "session-1",
        "tx@{0}.sub@{1}",
        "--idempotency-key",
        "transaction-rollback-1",
    ]);

    assert!(list.is_ok());
    assert!(commit.is_ok());
    assert!(rollback.is_ok());
}

#[test]
fn accepts_filesystem_retention_commands() {
    let list = Cli::try_parse_from([
        "araphor",
        "filesystem",
        "retention",
        "list",
        "--session",
        "session-1",
    ]);
    let prune = Cli::try_parse_from([
        "araphor",
        "filesystem",
        "retention",
        "prune",
        "--session",
        "session-1",
        "tx@{0}",
        "--idempotency-key",
        "retention-prune-1",
    ]);
    let json = Cli::try_parse_from([
        "araphor",
        "filesystem",
        "retention",
        "list",
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
        "araphor",
        "policy",
        "test",
        "--policy",
        "policy.json",
        "--event",
        "event.json",
    ]);
    let evidence = Cli::try_parse_from([
        "araphor",
        "audit",
        "evidence-trace",
        "session-1",
        "--after-sequence",
        "4",
        "--maximum-records",
        "8",
    ]);
    let tail = Cli::try_parse_from([
        "araphor",
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
        vec!["araphor", "policy", "package", "ls"],
        vec!["araphor", "policy", "package", "inspect", "workspace-write"],
        vec!["araphor", "policy", "package", "verify", "workspace-write"],
        vec!["araphor", "policyset", "ls"],
        vec!["araphor", "policyset", "inspect", "company-workspace"],
        vec!["araphor", "policyset", "verify", "company-workspace"],
    ] {
        assert!(Cli::try_parse_from(command).is_ok());
    }
}

#[test]
fn policy_package_apply_requires_an_explicit_resource_name() {
    assert!(Cli::try_parse_from([
        "araphor",
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
        "araphor",
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
    let dev = Cli::try_parse_from(["araphor", "dev"]);
    let audit = Cli::try_parse_from([
        "araphor",
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
        "araphor",
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
        "araphor",
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

#[test]
fn shared_command_tree() {
    let cli = Cli::command();
    assert_eq!(cli.get_name(), "araphor");
    let mut names: Vec<_> = cli
        .get_subcommands()
        .map(|command| command.get_name())
        .collect();
    names.sort_unstable();
    assert_eq!(
        names,
        [
            "agent",
            "approval",
            "audit",
            "catalog",
            "daemon",
            "filesystem",
            "policy",
            "policyset",
            "run",
            "runner",
            "session",
            "sql",
            "start",
            "surface",
            "trace",
        ]
    );
    assert!(Cli::try_parse_from(["araphor", "araphor", "sql", "SELECT 1"]).is_err());
}

#[test]
fn transport_options_are_separate() -> Result<(), Box<dyn std::error::Error>> {
    for command in [
        vec!["sql", "SELECT 1"],
        vec!["catalog"],
        vec![
            "trace",
            "--recipe",
            "failed-opens@1",
            "--target",
            "pod/ns/name",
        ],
    ] {
        let args: Vec<_> = ["araphor", "--socket", "/run/erebor/daemon.sock"]
            .into_iter()
            .chain(command.iter().copied())
            .collect();
        let cli = Cli::try_parse_from(args)?;
        assert!(
            matches!(cli.validate_route(), Err(error) if error.exit_code() == 2),
            "query or trace cannot select a daemon socket"
        );
        let args: Vec<_> = ["araphor", "--profile", "client.json", "--output", "jsonl"]
            .into_iter()
            .chain(command)
            .collect();
        let cli = Cli::try_parse_from(args)?;
        assert!(cli.validate_route().is_ok());
    }
    for (flag, value) in [
        ("--profile", "client.json"),
        ("--endpoint", "https://localhost:443"),
        ("--output", "jsonl"),
    ] {
        let cli = Cli::try_parse_from(["araphor", "daemon", "status", flag, value])?;
        assert!(
            matches!(cli.validate_route(), Err(error) if error.exit_code() == 2),
            "Runtime requires its own transport"
        );
    }
    let cli = Cli::try_parse_from([
        "araphor",
        "--socket",
        "/tmp/runtime.sock",
        "daemon",
        "status",
    ])?;
    assert!(cli.validate_route().is_ok());
    Ok(())
}
