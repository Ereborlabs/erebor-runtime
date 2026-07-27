use clap::Parser;
use erebor_runtime_ipc::v1::{ContextGraphActivity, ContextGraphResponse, ContextScopeGraphNode};

use super::{args::SessionCommand, SessionCommandOwner};
use crate::cli::{Cli, Command};

const DIGEST: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

#[test]
fn generic_session_commands_use_the_daemon_installed_admission(
) -> Result<(), Box<dyn std::error::Error>> {
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
        "--",
        "/usr/bin/true",
    ])
    .is_err());
    let cli = Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--agent",
        "local-codex",
        "--policy",
        "company-workspace",
        "--failure-mode",
        "continue",
        "--idempotency-key",
        "static-legacy-field",
    ])?;
    let Command::Session(session) = cli.command else {
        return Err("expected a session command".into());
    };
    let SessionCommand::Create(args) = session.command else {
        return Err("expected session create".into());
    };
    assert!(args.request.to_request().is_err());
    Ok(())
}

#[test]
fn static_session_association_uses_only_named_resources() {
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--agent",
        "local-codex",
        "--policy",
        "company-workspace",
        "--surface",
        "engineering-browser",
        "--idempotency-key",
        "session-static-1",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "run",
        "--agent",
        "local-codex",
        "--policy",
        "company-workspace",
        "--surface",
        "engineering-browser",
        "--idempotency-key",
        "session-static-2",
    ])
    .is_ok());
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--idempotency-key",
        "missing-request-shape",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--agent",
        "local-codex",
        "--idempotency-key",
        "missing-policy",
    ])
    .is_err());
    assert!(Cli::try_parse_from([
        "erebor",
        "session",
        "create",
        "--runner",
        "linux-host",
        "--workspace",
        "/work",
        "--agent",
        "local-codex",
        "--policy",
        "company-workspace",
        "--idempotency-key",
        "mixed-request-shape",
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
fn context_graph_nests_an_operation_under_its_source_tool_and_keeps_parent_merges_visible() {
    let root = String::from("refs/scopes/session-graph/root");
    let child = String::from("refs/scopes/session-graph/scope/codex-operation-q");
    let lines = SessionCommandOwner::context_graph_lines(ContextGraphResponse {
        root_scope: root.clone(),
        nodes: vec![
            ContextScopeGraphNode {
                scope: root.clone(),
                parent_scope: String::new(),
                head_commit: String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                fork_parent_commit: String::new(),
                source_identity: String::new(),
                execution_binding: String::new(),
                depth: 0,
                source_tool_use_id: String::new(),
            },
            ContextScopeGraphNode {
                scope: child.clone(),
                parent_scope: root.clone(),
                head_commit: String::from("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"),
                fork_parent_commit: String::from("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                source_identity: String::from("codex-v1:operation:q"),
                execution_binding: String::from("native-logical"),
                depth: 1,
                source_tool_use_id: String::from("q-tool"),
            },
        ],
        activities: vec![
            ContextGraphActivity {
                scope: root.clone(),
                summary: String::from("tool bash command=\"q\""),
                tool_use_id: String::from("q-tool"),
            },
            ContextGraphActivity {
                scope: root.clone(),
                summary: String::from("tool bash command=\"ls\""),
                tool_use_id: String::from("ls-tool"),
            },
            ContextGraphActivity {
                scope: root.clone(),
                summary: String::from("exec /usr/bin/ls allowed pid=2 via bash ls-tool"),
                tool_use_id: String::new(),
            },
            ContextGraphActivity {
                scope: root,
                summary: String::from("merge received delivery #1 from codex-operation-q"),
                tool_use_id: String::new(),
            },
            ContextGraphActivity {
                scope: child,
                summary: String::from("delivery result #1 queued"),
                tool_use_id: String::new(),
            },
        ],
    });
    let rendered = lines.join("\n");
    assert!(rendered
        .contains("├─ tool bash command=\"q\"\n│  └─● codex-operation-q  HEAD bbbbbbbbbbbb"));
    assert!(rendered.contains(
        "├─ tool bash command=\"ls\"\n├─ exec /usr/bin/ls allowed pid=2 via bash ls-tool"
    ));
    assert!(rendered.contains("└─ merge received delivery #1 from codex-operation-q"));
}

#[test]
fn codex_runs_only_through_a_daemon_owned_named_agent_request() {
    assert!(
        Cli::try_parse_from(["erebor", "run", "--policy", "engineering", "local-codex",]).is_ok()
    );
    assert!(Cli::try_parse_from([
        "erebor",
        "run",
        "--policy",
        "engineering",
        "--tty",
        "local-codex",
    ])
    .is_err());
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
