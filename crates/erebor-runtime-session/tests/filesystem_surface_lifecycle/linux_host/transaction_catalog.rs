use std::{fs, path::Path};

use erebor_runtime_core::{RuntimeConfig, SessionRunPlan, SessionRunnerKind};
use erebor_runtime_events::SessionId;
use erebor_runtime_session::SessionExecutionService;

use super::{
    overlay_multivolume_support::{assert_promoted, assert_restored, cleanup, LifecycleFixture},
    support, transaction_catalog_cli as cli,
};

#[test]
fn linux_host_transaction_catalog_cli_rolls_back_subtransactions(
) -> Result<(), Box<dyn std::error::Error>> {
    if !support::require_overlay_lifecycle(
        "linux_host_transaction_catalog_cli_rolls_back_subtransactions",
    )? {
        return Ok(());
    }

    let fixture = LifecycleFixture::new("transaction-catalog")?;
    fixture.seed()?;
    let policy_path = support::write_empty_policy(&fixture.root)?;
    let session_id = "session-filesystem-transaction-catalog";
    let command =
        "ostree --repo=\"$EREBOR_FILESYSTEM_REPO\" config set core.min-free-space-percent 0 && \
        cd project && rg light settings.txt && \
        printf dark > settings.txt && rm old-cache.txt && \
        mkdir -p generated && printf token > generated/token.txt && \
        cd ../cache && rg cold cache.txt && printf warm > cache.txt && \
        rm stale.bin && mkdir -p warmed && printf index > warmed/index.txt";
    let config_path = fixture.root.join("transaction-catalog-config.json");
    fs::write(
        &config_path,
        cli::config_source(&fixture, &policy_path, "transaction-catalog", command),
    )?;
    let config = RuntimeConfig::from_json_str(&fs::read_to_string(&config_path)?)?;
    let plan = SessionRunPlan::from_diagnostic(
        &config,
        SessionRunnerKind::LinuxHost,
        SessionId::new(session_id),
        "transaction-catalog",
    )?
    .with_config_path(config_path);

    SessionExecutionService::run_diagnostic(&config, &plan)?;
    assert_promoted(&fixture)?;

    let registry = fixture.workspace.join(".erebor/sessions");
    let filesystem = support::session_filesystem_path(&fixture.workspace, session_id);
    fs::remove_dir_all(filesystem.join("work/promotions").join(session_id))?;
    let binary = cli::erebor_runtime_binary()?;

    let list = cli::run(
        &binary,
        &fixture.root,
        &[
            "filesystem",
            "transactions",
            "list",
            "--registry",
            registry.to_str().unwrap_or_default(),
            "--session",
            session_id,
        ],
    )?;
    assert!(list.contains("HANDLE"));
    assert!(list.contains("tx@{0}"));
    assert!(list.contains("applied"));
    assert!(list.contains("subtransaction"));
    assert!(list.contains("project"));
    assert!(list.contains("cache"));

    let show_parent = show(&binary, &fixture, &registry, session_id, "tx@{0}")?;
    assert_changed_paths(
        &show_parent,
        ["settings.txt", "cache.txt", "warmed/index.txt"],
    );
    let (project_handle, cache_handle) =
        subtransaction_handles(&binary, &fixture, &registry, session_id)?;

    let rename = cli::run(
        &binary,
        &fixture.root,
        &cli::transaction_args(
            &registry,
            session_id,
            ["rename", &project_handle, "project restore"],
        ),
    )?;
    assert!(rename.contains("renamed"));
    let renamed = show(&binary, &fixture, &registry, session_id, "project restore")?;
    assert!(renamed.contains("project restore"));
    assert_changed_paths(&renamed, ["settings.txt", "old-cache.txt"]);

    let project_rollback = cli::run(
        &binary,
        &fixture.root,
        &cli::transaction_args(&registry, session_id, ["rollback", "project restore"]),
    )?;
    assert!(project_rollback.contains("rolled_back"));
    assert!(project_rollback.contains("project restore"));
    assert_project_restored_cache_promoted(&fixture)?;

    let partial = cli::run(
        &binary,
        &fixture.root,
        &cli::transaction_args(&registry, session_id, ["list"]),
    )?;
    assert!(partial.contains("partially_restored"));
    assert!(partial.contains(&project_handle));
    assert!(partial.contains("restored"));
    assert!(partial.contains(&cache_handle));
    assert!(partial.contains("applied"));

    let parent_rollback = cli::run(
        &binary,
        &fixture.root,
        &cli::transaction_args(&registry, session_id, ["rollback", "tx@{0}"]),
    )?;
    assert!(parent_rollback.contains("rolled_back"));
    assert!(parent_rollback.contains("tx@{0}"));
    assert!(parent_rollback.contains("cache"));
    assert_restored(&fixture)?;

    let repeat = cli::run(
        &binary,
        &fixture.root,
        &cli::transaction_args(&registry, session_id, ["rollback", "project restore"]),
    )?;
    assert!(repeat.contains("already_restored"));
    assert!(repeat.contains("project restore"));
    assert!(filesystem
        .join("transaction-catalog/erebor-transaction-catalog.json")
        .is_file());
    let journal = fs::read_to_string(
        filesystem.join("transaction-catalog/erebor-transaction-catalog.jsonl"),
    )?;
    assert!(journal.contains("\"event\":\"rename\""));
    assert!(journal.contains("\"event\":\"rollback\""));
    assert!(journal.contains("\"outcome\":\"success\""));
    assert!(journal.contains("\"outcome\":\"already_restored\""));
    assert!(journal.contains(session_id));
    assert!(journal.contains(&format!("erebor/promotions/{session_id}/manifest")));
    assert!(journal.contains(&format!(
        "erebor/promotions/{session_id}/volumes/project/preimage"
    )));
    assert!(journal.contains(&format!(
        "erebor/promotions/{session_id}/volumes/cache/preimage"
    )));
    assert!(!filesystem.join("work/promotions").join(session_id).exists());

    fixture.assert_unmounted()?;
    cleanup(&fixture, session_id)?;
    Ok(())
}

fn subtransaction_handles(
    cli: &Path,
    fixture: &LifecycleFixture,
    registry: &Path,
    session_id: &str,
) -> Result<(String, String), Box<dyn std::error::Error>> {
    let first = show(cli, fixture, registry, session_id, "tx@{0}.sub@{0}")?;
    let second = show(cli, fixture, registry, session_id, "tx@{0}.sub@{1}")?;
    if first.contains("project") && second.contains("cache") {
        return Ok((
            String::from("tx@{0}.sub@{0}"),
            String::from("tx@{0}.sub@{1}"),
        ));
    }
    if first.contains("cache") && second.contains("project") {
        return Ok((
            String::from("tx@{0}.sub@{1}"),
            String::from("tx@{0}.sub@{0}"),
        ));
    }
    Err(std::io::Error::other("could not identify catalog subtransaction handles").into())
}

fn show(
    cli: &Path,
    fixture: &LifecycleFixture,
    registry: &Path,
    session_id: &str,
    target: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    cli::run(
        cli,
        &fixture.root,
        &cli::transaction_args(registry, session_id, ["show", target]),
    )
}

fn assert_project_restored_cache_promoted(
    fixture: &LifecycleFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("settings.txt"))?,
        "light\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("old-cache.txt"))?,
        "old cache\n"
    );
    assert!(!fixture.host_project.join("generated").exists());
    assert_eq!(
        fs::read_to_string(fixture.host_cache.join("cache.txt"))?,
        "warm"
    );
    assert!(!fixture.host_cache.join("stale.bin").exists());
    assert_eq!(
        fs::read_to_string(fixture.host_cache.join("warmed/index.txt"))?,
        "index"
    );
    Ok(())
}

fn assert_changed_paths<const N: usize>(output: &str, paths: [&str; N]) {
    for path in paths {
        assert!(
            output.contains(path),
            "missing changed path {path}: {output}"
        );
    }
}
