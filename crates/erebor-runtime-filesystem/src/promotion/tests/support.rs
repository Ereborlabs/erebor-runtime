use std::{
    cell::RefCell,
    fs,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    ostree::{OstreeCommandOutput, OstreeCommandRunner},
    storage::prepare_with_initializer,
    FilesystemVolumeMode, FilesystemVolumeStorageRequest,
};

pub(super) type TestResult = Result<(), Box<dyn std::error::Error>>;

pub(super) struct Fixture {
    pub storage: crate::FilesystemSessionStorage,
    root: PathBuf,
    host_path: PathBuf,
}

impl Fixture {
    pub(super) fn upper(&self) -> &Path {
        self.storage.volumes()[0].overlay().upper_path()
    }

    pub(super) fn host(&self) -> &Path {
        &self.host_path
    }

    pub(super) fn seed_host(&self, relative: &str, source: &str) -> TestResult {
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

pub(super) fn fixture() -> Result<Fixture, Box<dyn std::error::Error>> {
    let root = std::env::temp_dir().join(format!(
        "erebor-filesystem-promotion-{}-{}",
        std::process::id(),
        nonce()
    ));
    let _result = fs::remove_dir_all(&root);
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
    let storage = prepare_with_initializer(&root.join("session"), vec![request], |_| Ok(()))?;
    Ok(Fixture {
        storage,
        root,
        host_path,
    })
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

pub(super) struct FakeOstreeRunner {
    pub commands: RefCell<Vec<Vec<String>>>,
}

impl FakeOstreeRunner {
    pub(super) fn successful() -> Self {
        Self {
            commands: RefCell::new(Vec::new()),
        }
    }
}

impl OstreeCommandRunner for FakeOstreeRunner {
    fn run(&self, _repo: &Path, args: &[String]) -> crate::Result<OstreeCommandOutput> {
        self.commands.borrow_mut().push(args.to_owned());
        Ok(OstreeCommandOutput::new(true, Some(0), ""))
    }
}
