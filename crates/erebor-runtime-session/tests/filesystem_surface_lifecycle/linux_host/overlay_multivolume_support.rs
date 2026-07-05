use std::{
    fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
    process::Command,
};

use erebor_runtime_core::RuntimeConfig;
use erebor_runtime_filesystem::{
    FilesystemSessionStorage, FilesystemVolumeMode, FilesystemVolumeStorageRequest,
};
use serde_json::Value;

use super::support;

pub(super) struct LifecycleFixture {
    pub(super) root: PathBuf,
    pub(super) workspace: PathBuf,
    pub(super) host_project: PathBuf,
    pub(super) host_cache: PathBuf,
    session_project: PathBuf,
    session_cache: PathBuf,
}

impl LifecycleFixture {
    pub(super) fn new(name: &str) -> Result<Self, Box<dyn std::error::Error>> {
        let root = support::test_dir(name)?;
        let workspace = root.join("workspace");
        let host_project = root.join("host/project");
        let host_cache = root.join("host/cache");
        let session_project = workspace.join("project");
        let session_cache = workspace.join("cache");
        for path in [&host_project, &host_cache, &session_project, &session_cache] {
            fs::create_dir_all(path)?;
        }
        Ok(Self {
            root,
            workspace,
            host_project,
            host_cache,
            session_project,
            session_cache,
        })
    }

    pub(super) fn seed(&self) -> Result<(), Box<dyn std::error::Error>> {
        fs::write(self.host_project.join("settings.txt"), "light\n")?;
        fs::write(self.host_project.join("old-cache.txt"), "old cache\n")?;
        fs::write(self.host_cache.join("cache.txt"), "cold\n")?;
        fs::write(self.host_cache.join("stale.bin"), "stale\n")?;
        Ok(())
    }

    pub(super) fn assert_unmounted(&self) -> Result<(), Box<dyn std::error::Error>> {
        support::assert_not_mountpoint(&self.session_project)?;
        support::assert_not_mountpoint(&self.session_cache)?;
        support::assert_not_mountpoint(&self.host_project)?;
        support::assert_not_mountpoint(&self.host_cache)?;
        Ok(())
    }
}

pub(super) fn assert_promoted(
    fixture: &LifecycleFixture,
) -> Result<(), Box<dyn std::error::Error>> {
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("settings.txt"))?,
        "dark"
    );
    assert!(!fixture.host_project.join("old-cache.txt").exists());
    assert!(!fixture.host_project.join("blocked.txt").exists());
    assert_eq!(
        fs::read_to_string(fixture.host_project.join("generated/token.txt"))?,
        "token"
    );
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

pub(super) fn assert_restored(
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
    assert!(!fixture.host_project.join("blocked.txt").exists());
    assert_eq!(
        fs::read_to_string(fixture.host_cache.join("cache.txt"))?,
        "cold\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host_cache.join("stale.bin"))?,
        "stale\n"
    );
    assert!(!fixture.host_cache.join("warmed").exists());
    Ok(())
}

pub(super) fn assert_refs(
    fixture: &LifecycleFixture,
    session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let repo = support::session_filesystem_path(&fixture.workspace, session_id).join("repo");
    let refs = ostree_output(&repo, &["refs", "--list"])?;
    for reference in [
        format!("erebor/checkpoints/{session_id}/manifest"),
        format!("erebor/checkpoints/{session_id}/volumes/project/layer"),
        format!("erebor/checkpoints/{session_id}/volumes/cache/layer"),
        format!("erebor/promotions/{session_id}/manifest"),
        format!("erebor/promotions/{session_id}/volumes/project/preimage"),
        format!("erebor/promotions/{session_id}/volumes/cache/preimage"),
    ] {
        assert!(refs.lines().any(|line| line == reference));
    }
    assert!(!refs.contains("/base"));
    let promotion_ref = format!("erebor/promotions/{session_id}/manifest");
    let promotion = ostree_output(&repo, &["cat", &promotion_ref, "/erebor-promotion.json"])?;
    let promotion: Value = serde_json::from_str(&promotion)?;
    assert_eq!(promotion["state"], "applied");
    assert_eq!(promotion["volumes"].as_array().map(Vec::len), Some(2));
    Ok(())
}

pub(super) fn reopen_storage(
    fixture: &LifecycleFixture,
    session_id: &str,
) -> Result<FilesystemSessionStorage, Box<dyn std::error::Error>> {
    Ok(FilesystemSessionStorage::open_existing(
        fixture.workspace.join(".erebor/sessions").join(session_id),
        volume_requests(fixture)?,
    )?)
}

fn volume_requests(
    fixture: &LifecycleFixture,
) -> Result<Vec<FilesystemVolumeStorageRequest>, Box<dyn std::error::Error>> {
    Ok(vec![
        FilesystemVolumeStorageRequest::new(
            "project",
            &fixture.host_project,
            &fixture.session_project,
            FilesystemVolumeMode::Writable,
        )?,
        FilesystemVolumeStorageRequest::new(
            "cache",
            &fixture.host_cache,
            &fixture.session_cache,
            FilesystemVolumeMode::Writable,
        )?,
    ])
}

pub(super) fn multivolume_config(
    fixture: &LifecycleFixture,
    policy_path: &Path,
    diagnostic_name: &str,
    shell_command: &str,
    promote: bool,
) -> Result<RuntimeConfig, Box<dyn std::error::Error>> {
    Ok(RuntimeConfig::from_json_str(&format!(
        r#"{{
          "policies": ["{}"],
          "session": {{
            "enabled": true,
            "actor": {{ "id": "openclaw" }},
            "workspace": "{}",
            "diagnostics": [{{ "name": "{}", "command": ["sh", "-lc", "{}"] }}],
            "runner": {{ "kind": "linux_host" }},
            "interception": {{
              "enabled": true,
              "backend": "linux_ptrace",
              "operations": ["process_exec", "file_open", "file_read", "file_mutation"]
            }}
          }},
          "surfaces": {{
            "terminal": {{ "enabled": true }},
            "filesystem": {{
              "enabled": true,
              "backend": {{ "kind": "linux_ostree_overlay" }},
              "volumes": [
                {{ "id": "project", "host_path": "{}", "session_path": "{}", "mode": "writable" }},
                {{ "id": "cache", "host_path": "{}", "session_path": "{}", "mode": "writable" }}
              ],
              "revert": {{
                "promote_on_session_finish": {},
                "retain_layers": true,
                "preimage_size_limit_bytes": 104857600
              }}
            }}
          }}
        }}"#,
        policy_path.display(),
        fixture.workspace.display(),
        diagnostic_name,
        json_escape(shell_command),
        fixture.host_project.display(),
        fixture.session_project.display(),
        fixture.host_cache.display(),
        fixture.session_cache.display(),
        promote
    ))?)
}

pub(super) fn cleanup(
    fixture: &LifecycleFixture,
    session_id: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let root = support::session_filesystem_path(&fixture.workspace, session_id);
    for volume_id in ["project", "cache"] {
        let private_work = root.join(format!("work/volumes/{volume_id}/overlay/workdir/work"));
        if private_work.exists() {
            fs::set_permissions(&private_work, fs::Permissions::from_mode(0o700))?;
        }
    }
    fs::remove_dir_all(&fixture.root)?;
    Ok(())
}

pub(super) fn ostree_output(
    repo: &Path,
    args: &[&str],
) -> Result<String, Box<dyn std::error::Error>> {
    let output = Command::new("ostree")
        .arg(format!("--repo={}", repo.display()))
        .args(args)
        .output()?;
    assert!(
        output.status.success(),
        "ostree {:?} failed: {}",
        args,
        String::from_utf8_lossy(&output.stderr)
    );
    Ok(String::from_utf8(output.stdout)?)
}

pub(super) fn sorted(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values
}

fn json_escape(value: &str) -> String {
    value.replace('\\', "\\\\").replace('"', "\\\"")
}
