use std::{
    fs::{self, File},
    os::unix::{fs::symlink, net::UnixListener},
    path::{Path, PathBuf},
    process,
    time::{SystemTime, UNIX_EPOCH},
};

use rustix::fs::{lsetxattr, XattrFlags};

use crate::{
    manifest::{FilesystemLayerEntry, FilesystemLayerOperation},
    storage::FilesystemStoragePreparer,
    FilesystemError, FilesystemVolumeMode, FilesystemVolumeStorageRequest,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn normalizes_create_replace_delete_symlink_and_metadata() -> TestResult {
    let fixture = fixture()?;
    fixture.seed_lower("settings.json", "{\"theme\":\"light\"}\n")?;
    fixture.seed_lower("old-cache.txt", "old\n")?;
    fs::write(
        fixture.upper().join("settings.json"),
        "{\"theme\":\"dark\"}\n",
    )?;
    set_existing_marker(fixture.upper().join("settings.json"), "user.overlay.origin")?;
    fs::create_dir_all(fixture.upper().join("generated"))?;
    fs::write(fixture.upper().join("generated/token.txt"), "token\n")?;
    symlink("generated/token.txt", fixture.upper().join("shortcut"))?;
    File::create(fixture.upper().join(".wh.old-cache.txt"))?;
    fixture.seed_lower("xattr-deleted.txt", "gone\n")?;
    set_marker(
        fixture.upper().join("xattr-deleted.txt"),
        "user.overlay.whiteout",
    )?;

    let manifests = fixture.storage.normalize_layers()?;

    assert_eq!(manifests.len(), 1);
    let manifest = read_manifest(fixture.volume().layer_manifest_path())?;
    assert!(manifest.promotable);
    assert_operation(&manifest.operations, "replace", "settings.json");
    assert_operation(&manifest.operations, "create", "generated");
    assert_operation(&manifest.operations, "create", "generated/token.txt");
    assert_operation(&manifest.operations, "delete", "old-cache.txt");
    assert_operation(&manifest.operations, "delete", "xattr-deleted.txt");
    assert!(manifest.metadata_sidecars.iter().any(|sidecar| {
        sidecar.path == "settings.json" && sidecar.name == "user.overlay.origin"
    }));
    let symlink_entry = manifest
        .operations
        .iter()
        .find_map(|operation| match operation {
            FilesystemLayerOperation::Create { path, entry } if path == "shortcut" => Some(entry),
            _ => None,
        });
    assert!(matches!(
        symlink_entry,
        Some(FilesystemLayerEntry::Symlink { target, .. }) if target == "generated/token.txt"
    ));
    Ok(())
}

#[test]
fn opaque_xattr_directory_writes_promotable_opaque_replace() -> TestResult {
    let fixture = fixture()?;
    fs::create_dir_all(fixture.upper().join("opaque"))?;
    fs::write(fixture.upper().join("opaque/new.txt"), "new\n")?;
    File::create(fixture.upper().join("opaque/.wh.old.txt"))?;
    set_existing_marker(fixture.upper().join("opaque"), "user.overlay.opaque")?;

    let manifests = fixture.storage.normalize_layers()?;

    assert_eq!(manifests.len(), 1);
    let manifest = read_manifest(fixture.volume().layer_manifest_path())?;
    assert!(manifest.promotable);
    assert!(manifest.unsupported.is_empty());
    let operation = manifest
        .operations
        .iter()
        .find(|operation| operation.path() == "opaque")
        .ok_or_else(|| std::io::Error::other("missing opaque operation"))?;
    assert!(matches!(
        operation,
        FilesystemLayerOperation::OpaqueReplace {
            marker,
            replacement_entry_count: 1,
            ..
        } if marker.kind == "xattr" && marker.name == "user.overlay.opaque"
    ));
    assert_eq!(manifest.operations.len(), 1);
    assert!(!manifest
        .operations
        .iter()
        .any(|operation| operation.path().contains(".wh.")));
    Ok(())
}

#[test]
fn opaque_marker_file_writes_promotable_opaque_replace() -> TestResult {
    let fixture = fixture()?;
    fs::create_dir_all(fixture.upper().join("opaque/nested"))?;
    File::create(fixture.upper().join("opaque/.wh..wh..opq"))?;
    File::create(fixture.upper().join("opaque/nested/.wh..wh..opq"))?;
    fs::write(fixture.upper().join("opaque/nested/new.txt"), "new\n")?;

    let manifests = fixture.storage.normalize_layers()?;

    assert_eq!(manifests.len(), 1);
    let manifest = read_manifest(fixture.volume().layer_manifest_path())?;
    assert!(manifest.promotable);
    assert!(manifest.unsupported.is_empty());
    assert!(matches!(
        manifest.operations.as_slice(),
        [FilesystemLayerOperation::OpaqueReplace {
            path,
            marker,
            replacement_entry_count: 2,
            ..
        }] if path == "opaque" && marker.kind == "whiteout_file"
    ));
    Ok(())
}

#[test]
fn symlink_traversal_writes_manifest_and_fails_closed() -> TestResult {
    let fixture = fixture()?;
    symlink("../outside", fixture.upper().join("escape"))?;

    let error = normalize_error(&fixture)?;

    assert!(matches!(error, FilesystemError::UnsupportedLayer { .. }));
    let manifest = read_manifest(fixture.volume().layer_manifest_path())?;
    assert!(!manifest.promotable);
    assert!(manifest
        .unsupported
        .iter()
        .any(|entry| entry.path == "escape" && entry.reason.contains("escapes")));
    Ok(())
}

#[test]
fn unsupported_special_entry_writes_manifest_and_fails_closed() -> TestResult {
    let fixture = fixture()?;
    let listener = UnixListener::bind(fixture.upper().join("socket"))?;
    drop(listener);

    let error = normalize_error(&fixture)?;

    assert!(matches!(error, FilesystemError::UnsupportedLayer { .. }));
    let manifest = read_manifest(fixture.volume().layer_manifest_path())?;
    assert!(!manifest.promotable);
    assert!(manifest
        .unsupported
        .iter()
        .any(|entry| entry.path == "socket" && entry.reason.contains("special file")));
    Ok(())
}

#[test]
fn active_writer_fd_refuses_exact_checkpoint() -> TestResult {
    let fixture = fixture()?;
    let writer = File::create(fixture.session_path.join("live.txt"))?;

    let error = normalize_error(&fixture)?;

    drop(writer);
    assert!(matches!(error, FilesystemError::ActiveLayerWriter { .. }));
    assert!(!fixture.volume().layer_manifest_path().exists());
    Ok(())
}

struct Fixture {
    storage: crate::FilesystemSessionStorage,
    root: PathBuf,
    host_path: PathBuf,
    session_path: PathBuf,
}

impl Fixture {
    fn volume(&self) -> &crate::FilesystemVolumeStorage {
        &self.storage.volumes()[0]
    }

    fn upper(&self) -> &Path {
        self.volume().overlay().upper_path()
    }

    fn seed_lower(&self, relative: &str, source: &str) -> TestResult {
        let path = self.host_path.join(relative);
        let parent = path
            .parent()
            .ok_or_else(|| std::io::Error::other("seed path has no parent"))?;
        fs::create_dir_all(parent)?;
        fs::write(path, source)?;
        Ok(())
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.root);
    }
}

fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root =
        std::env::temp_dir().join(format!("efn-{}-{}", process::id(), nonce() % 1_000_000_000));
    let session_dir = root.join("session");
    let host_path = root.join("host/project");
    let session_path = root.join("workspace/project");
    fs::create_dir_all(&host_path)?;
    fs::create_dir_all(&session_path)?;
    let request = FilesystemVolumeStorageRequest::new(
        "project",
        &host_path,
        &session_path,
        FilesystemVolumeMode::Writable,
    )?;
    let storage =
        FilesystemStoragePreparer::new(&session_dir, vec![request]).prepare(|_| Ok(()))?;
    Ok(Fixture {
        storage,
        root,
        host_path,
        session_path,
    })
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

fn set_marker(path: PathBuf, name: &str) -> TestResult {
    File::create(&path)?;
    set_existing_marker(path, name)
}

fn set_existing_marker(path: PathBuf, name: &str) -> TestResult {
    lsetxattr(&path, name, b"y", XattrFlags::empty()).map_err(std::io::Error::from)?;
    Ok(())
}

fn read_manifest(
    path: PathBuf,
) -> Result<crate::FilesystemLayerManifest, Box<dyn std::error::Error>> {
    let source = fs::read_to_string(path)?;
    Ok(serde_json::from_str(&source)?)
}

fn normalize_error(fixture: &Fixture) -> Result<FilesystemError, Box<dyn std::error::Error>> {
    match fixture.storage.normalize_layers() {
        Ok(manifests) => Err(format!("expected normalization error, got {manifests:#?}").into()),
        Err(error) => Ok(error),
    }
}

fn assert_operation(operations: &[FilesystemLayerOperation], kind: &str, expected: &str) {
    let found = operations.iter().any(|operation| match operation {
        FilesystemLayerOperation::Create { path, .. } => kind == "create" && path == expected,
        FilesystemLayerOperation::Replace { path, .. } => kind == "replace" && path == expected,
        FilesystemLayerOperation::Delete { path } => kind == "delete" && path == expected,
        FilesystemLayerOperation::OpaqueReplace { path, .. } => {
            kind == "opaque_replace" && path == expected
        }
    });
    assert!(
        found,
        "missing {kind} operation for {expected}: {operations:#?}"
    );
}
