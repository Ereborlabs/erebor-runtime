use clap::Parser;

use super::SessionCommandOwner;
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
fn context_graph_accepts_a_short_session_reference_and_keeps_scope_labels_readable() {
    assert!(
        Cli::try_parse_from(["erebor", "session", "context", "graph", "23f741c3-5ce",]).is_ok()
    );
    assert_eq!(
        SessionCommandOwner::short_scope(
            "refs/scopes/session-23f741c3-5cea-4285-8a0a-e46da1c5465c/root",
        ),
        "root"
    );
    assert_eq!(
        SessionCommandOwner::short_scope(
            "refs/scopes/session-23f741c3-5cea-4285-8a0a-e46da1c5465c/scope/codex-operation-1234567890abcdef",
        ),
        "codex-operation-1234567890ab"
    );
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
