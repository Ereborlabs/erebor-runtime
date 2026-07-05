use std::{
    cell::RefCell,
    fs,
    os::unix::fs::symlink,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use crate::{
    checkpoint::commit_normalized_session_checkpoint_with_runner,
    ostree::{OstreeCommandOutput, OstreeCommandRunner},
    storage::prepare_with_initializer,
    FilesystemError, FilesystemLayerManifest, FilesystemVolumeMode, FilesystemVolumeStorageRequest,
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

pub(super) fn commit_checkpoint(
    fixture: &Fixture,
    manifests: &[FilesystemLayerManifest],
    runner: &FakeOstreeRunner,
) -> crate::Result<()> {
    commit_normalized_session_checkpoint_with_runner(
        &fixture.storage,
        "session-1",
        manifests,
        runner,
    )?;
    Ok(())
}

fn nonce() -> u128 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| duration.as_nanos())
}

pub(super) struct FakeOstreeRunner {
    pub commands: RefCell<Vec<Vec<String>>>,
    outputs: RefCell<Vec<OstreeCommandOutput>>,
    refs: RefCell<Vec<String>>,
    root: PathBuf,
}

impl FakeOstreeRunner {
    pub(super) fn successful() -> Self {
        Self::with_outputs(Vec::new())
    }

    pub(super) fn with_outputs(outputs: Vec<OstreeCommandOutput>) -> Self {
        let root = std::env::temp_dir().join(format!(
            "erebor-fake-ostree-{}-{}",
            std::process::id(),
            nonce()
        ));
        let _result = fs::remove_dir_all(&root);
        Self {
            commands: RefCell::new(Vec::new()),
            outputs: RefCell::new(outputs),
            refs: RefCell::new(Vec::new()),
            root,
        }
    }

    fn commit_path(&self, ref_name: &str) -> PathBuf {
        self.root.join("commits").join(ref_name)
    }

    fn mirror_successful_command(&self, args: &[String]) -> crate::Result<()> {
        match args.first().map(String::as_str) {
            Some("commit") => self.mirror_commit(args),
            Some("checkout") => self.mirror_checkout(args),
            _ => Ok(()),
        }
    }

    fn mirror_commit(&self, args: &[String]) -> crate::Result<()> {
        let ref_name = arg_value(args, "--branch=")?;
        let tree = PathBuf::from(arg_value(args, "--tree=dir=")?);
        let mut refs = self.refs.borrow_mut();
        if !refs.iter().any(|existing| existing == ref_name) {
            refs.push(ref_name.to_owned());
        }
        copy_tree(&tree, &self.commit_path(ref_name))
    }

    fn mirror_checkout(&self, args: &[String]) -> crate::Result<()> {
        let ref_name = args
            .get(2)
            .ok_or_else(|| test_io("fake ostree checkout missing ref", &self.root))?;
        let target = args
            .get(3)
            .ok_or_else(|| test_io("fake ostree checkout missing target", &self.root))?;
        copy_tree(&self.commit_path(ref_name), Path::new(target))
    }
}

impl Drop for FakeOstreeRunner {
    fn drop(&mut self) {
        let _result = fs::remove_dir_all(&self.root);
    }
}

impl OstreeCommandRunner for FakeOstreeRunner {
    fn run(&self, _repo: &Path, args: &[String]) -> crate::Result<OstreeCommandOutput> {
        self.commands.borrow_mut().push(args.to_owned());
        if args.len() == 2 && args[0] == "refs" && args[1] == "--list" {
            let mut refs = self.refs.borrow().clone();
            refs.sort();
            return Ok(OstreeCommandOutput::with_stdout(
                true,
                Some(0),
                refs.join("\n"),
                "",
            ));
        }
        let mut outputs = self.outputs.borrow_mut();
        let output = if outputs.is_empty() {
            OstreeCommandOutput::new(true, Some(0), "")
        } else {
            outputs.remove(0)
        };
        if output.success() {
            self.mirror_successful_command(args)?;
        }
        Ok(output)
    }
}

fn arg_value<'a>(args: &'a [String], prefix: &str) -> crate::Result<&'a str> {
    args.iter()
        .find_map(|arg| arg.strip_prefix(prefix))
        .ok_or_else(|| test_io("fake ostree command missing argument", Path::new(prefix)))
}

fn copy_tree(source: &Path, target: &Path) -> crate::Result<()> {
    if target.exists() {
        fs::remove_dir_all(target)
            .map_err(|error| test_io_source("remove fake tree", target, error))?;
    }
    fs::create_dir_all(target)
        .map_err(|error| test_io_source("create fake tree", target, error))?;
    for entry in
        fs::read_dir(source).map_err(|error| test_io_source("read fake tree", source, error))?
    {
        let entry = entry.map_err(|error| test_io_source("read fake tree entry", source, error))?;
        let source_path = entry.path();
        let target_path = target.join(entry.file_name());
        let metadata = fs::symlink_metadata(&source_path)
            .map_err(|source| test_io_source("inspect fake tree", &source_path, source))?;
        if metadata.is_dir() {
            copy_tree(&source_path, &target_path)?;
        } else if metadata.is_file() {
            fs::copy(&source_path, &target_path)
                .map_err(|source| test_io_source("copy fake tree file", &source_path, source))?;
        } else if metadata.file_type().is_symlink() {
            let link = fs::read_link(&source_path)
                .map_err(|source| test_io_source("read fake tree symlink", &source_path, source))?;
            symlink(link, &target_path)
                .map_err(|source| test_io_source("copy fake tree symlink", &target_path, source))?;
        }
    }
    Ok(())
}

fn test_io(reason: &'static str, path: &Path) -> FilesystemError {
    test_io_source(reason, path, std::io::Error::other(reason))
}

fn test_io_source(action: &'static str, path: &Path, source: std::io::Error) -> FilesystemError {
    FilesystemError::PromotionIo {
        action,
        path: path.to_path_buf(),
        source,
        location: snafu::Location::default(),
    }
}
