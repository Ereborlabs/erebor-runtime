use clap::Parser;

use crate::cli::Cli;

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn generic_session_commands_accept_the_daemon_installed_package_or_exact_identities() {
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--idempotency-key",
        "create-built-in",
        "--",
        "/usr/bin/true",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--package-digest",
        DIGEST,
        "--installation-digest",
        DIGEST,
        "--adapter-digest",
        DIGEST,
        "--policy-set-digest",
        DIGEST,
        "--idempotency-key",
        "create-1",
        "--",
        "/usr/bin/true",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--package-digest",
        DIGEST,
        "--installation-digest",
        DIGEST,
        "--adapter-digest",
        DIGEST,
        "--policy-set-digest",
        DIGEST,
        "--",
        "/usr/bin/true",
    ])
    .is_err());
}

#[test]
fn session_lifecycle_is_a_daemon_command_family() {
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--package-digest",
        DIGEST,
        "--installation-digest",
        DIGEST,
        "--adapter-digest",
        DIGEST,
        "--policy-set-digest",
        DIGEST,
        "--idempotency-key",
        "run-1",
        "--env",
        "LANG=C",
        "--secret",
        "provider://secret",
        "--",
        "/usr/bin/true",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["erebor", "session", "start", "session-1"]).is_err());
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "start",
        "session-1",
        "--idempotency-key",
        "start-1",
    ])
    .is_ok());
    assert!(Cli::try_parse_from(["erebor", "session", "adopt", "--pid", "1"]).is_err());
    assert!(Cli::try_parse_from(["erebor", "session", "diagnose", "test"]).is_err());
}

#[test]
fn codex_runs_only_through_a_daemon_owned_alias_request() {
    assert!(Cli::try_parse_from([
        "erebor",
        "run",
        "--policy",
        "engineering",
        "codex-app-server",
    ])
    .is_ok());
    assert!(
        Cli::try_parse_from(["erebor", "run", "--policy", "engineering", "--tty", "codex",])
            .is_err()
    );
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--config",
        "codex-runtime.json",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--idempotency-key",
        "legacy-codex",
        "--",
        "/opt/codex/codex",
        "app-server",
    ])
    .is_err());
}
