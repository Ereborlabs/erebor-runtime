use std::{
    fs,
    os::unix::net::UnixListener,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    checkpoint::commit_normalized_session_checkpoint_with_runner,
    normalizer::normalize_session_layers,
    promotion::{
        promote_with_hook, rollback_promotion_with_runner, FilesystemPromotionOptions,
        PromotionHook,
    },
    storage::prepare_with_initializer,
    FilesystemError, FilesystemLayerManifest, FilesystemSessionStorage, FilesystemVolumeMode,
    FilesystemVolumeStorageRequest,
};

use super::support::{FakeOstreeRunner, TestResult};

#[test]
fn multivolume_promotion_and_rollback_restore_all_volumes() -> TestResult {
    let fixture = MultiVolumeFixture::new()?;
    fixture.seed_host("project", "settings.txt", "light\n")?;
    fixture.seed_host("project", "old-cache.txt", "old cache\n")?;
    fixture.seed_host("cache", "cache.txt", "cold\n")?;
    fixture.seed_host("cache", "stale.bin", "stale\n")?;
    write_upper(&fixture, "project", "settings.txt", "dark\n")?;
    fs::write(fixture.upper("project")?.join(".wh.old-cache.txt"), "")?;
    write_upper(&fixture, "project", "generated/token.txt", "token\n")?;
    write_upper(&fixture, "cache", "cache.txt", "warm\n")?;
    fs::write(fixture.upper("cache")?.join(".wh.stale.bin"), "")?;
    write_upper(&fixture, "cache", "warmed/index.txt", "index\n")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();
    commit_checkpoint(&fixture.storage, &manifests, &runner)?;

    let promotion = promote_with_hook(
        &fixture.storage,
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    )?;

    assert_eq!(volume_ids(promotion.volumes()), ["cache", "project"]);
    assert_eq!(
        fs::read_to_string(fixture.host("project")?.join("settings.txt"))?,
        "dark\n"
    );
    assert!(!fixture.host("project")?.join("old-cache.txt").exists());
    assert_eq!(
        fs::read_to_string(fixture.host("cache")?.join("cache.txt"))?,
        "warm\n"
    );
    assert!(!fixture.host("cache")?.join("stale.bin").exists());
    assert_command_branch(
        &runner,
        "erebor/promotions/session-1/volumes/project/preimage",
    );
    assert_command_branch(
        &runner,
        "erebor/promotions/session-1/volumes/cache/preimage",
    );
    fs::remove_dir_all(fixture.storage.work_path().join("promotions/session-1"))?;

    let rollback = rollback_promotion_with_runner(&fixture.storage, "session-1", &runner)?;

    assert_eq!(
        sorted_strings(rollback.restored_volumes()),
        ["cache", "project"]
    );
    assert_eq!(
        fs::read_to_string(fixture.host("project")?.join("settings.txt"))?,
        "light\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host("project")?.join("old-cache.txt"))?,
        "old cache\n"
    );
    assert!(!fixture.host("project")?.join("generated").exists());
    assert_eq!(
        fs::read_to_string(fixture.host("cache")?.join("cache.txt"))?,
        "cold\n"
    );
    assert_eq!(
        fs::read_to_string(fixture.host("cache")?.join("stale.bin"))?,
        "stale\n"
    );
    assert!(!fixture.host("cache")?.join("warmed").exists());
    Ok(())
}

#[test]
fn multivolume_preimage_failure_blocks_all_host_mutation() -> TestResult {
    let fixture = MultiVolumeFixture::new()?;
    fixture.seed_host("project", "settings.txt", "light\n")?;
    let socket = fixture.host("cache")?.join("stale.sock");
    let listener = UnixListener::bind(&socket)?;
    write_upper(&fixture, "project", "settings.txt", "dark\n")?;
    fs::write(fixture.upper("cache")?.join(".wh.stale.sock"), "")?;
    let manifests = normalize_session_layers(&fixture.storage)?;
    let runner = FakeOstreeRunner::successful();
    commit_checkpoint(&fixture.storage, &manifests, &runner)?;

    let result = promote_with_hook(
        &fixture.storage,
        "session-1",
        "erebor/checkpoints/session-1/manifest",
        &manifests,
        FilesystemPromotionOptions::new(1024 * 1024),
        &runner,
        &NoopHook,
    );

    assert!(matches!(
        result,
        Err(FilesystemError::UnsupportedLayer { .. })
    ));
    assert_eq!(
        fs::read_to_string(fixture.host("project")?.join("settings.txt"))?,
        "light\n"
    );
    assert!(socket.exists());
    drop(listener);
    Ok(())
}

struct MultiVolumeFixture {
    storage: FilesystemSessionStorage,
    root: PathBuf,
    host_project: PathBuf,
    host_cache: PathBuf,
}

impl MultiVolumeFixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = std::env::temp_dir().join(format!(
            "erebor-filesystem-multivolume-{}-{}",
            std::process::id(),
            nonce()
        ));
        let _result = fs::remove_dir_all(&root);
        let host_project = root.join("host/project");
        let host_cache = root.join("host/cache");
        let session_project = root.join("workspace/project");
        let session_cache = root.join("workspace/cache");
        for path in [&host_project, &host_cache, &session_project, &session_cache] {
            fs::create_dir_all(path)?;
        }
        let requests = vec![
            FilesystemVolumeStorageRequest::new(
                "project",
                &host_project,
                &session_project,
                FilesystemVolumeMode::Writable,
            )?,
            FilesystemVolumeStorageRequest::new(
                "cache",
                &host_cache,
                &session_cache,
                FilesystemVolumeMode::Writable,
            )?,
        ];
        let storage = prepare_with_initializer(&root.join("session"), requests, |_| Ok(()))?;
        Ok(Self {
            storage,
            root,
            host_project,
            host_cache,
        })
    }

    fn host(&self, volume_id: &str) -> Result<&Path, std::io::Error> {
        match volume_id {
            "project" => Ok(self.host_project.as_path()),
            "cache" => Ok(self.host_cache.as_path()),
            _ => Err(std::io::Error::other(format!(
                "unknown test volume {volume_id}"
            ))),
        }
    }

    fn upper(&self, volume_id: &str) -> Result<PathBuf, std::io::Error> {
        self.storage
            .volumes()
            .iter()
            .find(|volume| volume.id() == volume_id)
            .map(|volume| volume.overlay().upper_path().to_path_buf())
            .ok_or_else(|| std::io::Error::other(format!("unknown test volume {volume_id}")))
    }

    fn seed_host(&self, volume_id: &str, relative: &str, source: &str) -> TestResult {
        write_file(self.host(volume_id)?.join(relative), source)
    }
}

impl Drop for MultiVolumeFixture {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.root);
    }
}

fn commit_checkpoint(
    storage: &FilesystemSessionStorage,
    manifests: &[FilesystemLayerManifest],
    runner: &FakeOstreeRunner,
) -> crate::Result<()> {
    commit_normalized_session_checkpoint_with_runner(storage, "session-1", manifests, runner)?;
    Ok(())
}

fn write_upper(
    fixture: &MultiVolumeFixture,
    volume_id: &str,
    relative: &str,
    source: &str,
) -> TestResult {
    write_file(fixture.upper(volume_id)?.join(relative), source)
}

fn write_file(path: PathBuf, source: &str) -> TestResult {
    let parent = path
        .parent()
        .ok_or_else(|| std::io::Error::other("test path has no parent"))?;
    fs::create_dir_all(parent)?;
    fs::write(path, source)?;
    Ok(())
}

fn assert_command_branch(runner: &FakeOstreeRunner, branch: &str) {
    assert!(runner
        .commands
        .borrow()
        .iter()
        .any(|args| args.iter().any(|arg| arg == &format!("--branch={branch}"))));
}

fn volume_ids(volumes: &[crate::promotion::FilesystemPromotionVolume]) -> Vec<String> {
    sorted_strings(
        &volumes
            .iter()
            .map(|volume| volume.volume_id.clone())
            .collect::<Vec<_>>(),
    )
}

fn sorted_strings(values: &[String]) -> Vec<String> {
    let mut values = values.to_vec();
    values.sort();
    values
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

struct NoopHook;

impl PromotionHook for NoopHook {}
