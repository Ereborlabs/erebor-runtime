use std::{
    env, fs,
    path::{Path, PathBuf},
    process::Command,
};

use mithril_node::OciBaseSpecOwner;

use crate::platform::{Platform, TestResult, PROCESS_FIXTURES};
use crate::process::ProcessFixture;

pub(crate) struct OciBundle {
    pub(crate) bundle: PathBuf,
    pub(crate) state: PathBuf,
    pub(crate) markers: PathBuf,
    pub(crate) group: PathBuf,
    pub(crate) id: String,
    runtime: PathBuf,
    hook: PathBuf,
    fixtures: PathBuf,
}

impl OciBundle {
    pub(crate) fn new(env: &impl Platform, name: &str) -> TestResult<Self> {
        let result = Self {
            bundle: env.work().join("bundle"),
            state: env.work().join("state"),
            markers: env.work().join("markers"),
            group: PathBuf::from(
                env::var_os("MITHRIL_TEST_CGROUP").ok_or("cgroup is not supplied")?,
            ),
            id: crate::DigestV1::of(name.as_bytes()).to_hex(),
            runtime: PathBuf::from(env::var_os("MITHRIL_TEST_RUNC").ok_or("runc is not supplied")?),
            hook: PathBuf::from(
                env::var_os("MITHRIL_TEST_OCI_HOOK").ok_or("hook is not supplied")?,
            ),
            fixtures: env.source().join(PROCESS_FIXTURES),
        };
        fs::create_dir_all(result.bundle.join("rootfs"))?;
        fs::create_dir(&result.state)?;
        fs::create_dir(&result.markers)?;
        Ok(result)
    }

    pub(crate) fn manifest(&self, input: &str) -> TestResult<PathBuf> {
        let path = self.bundle.join("recovery-manifest.json");
        fs::write(&path, serde_json::to_vec(&self.bind(input)?)?)?;
        Ok(path)
    }

    pub(crate) fn spawn(&self, input: &str, manifest: &Path) -> TestResult<ProcessFixture> {
        let spec = self.bind(input)?;
        let root = self.bundle.join("rootfs");
        for mount in spec["mounts"].as_array().ok_or("OCI mounts are missing")? {
            let destination = mount["destination"]
                .as_str()
                .ok_or("OCI mount has no destination")?;
            let target = root.join(Path::new(destination).strip_prefix("/")?);
            let source = Path::new(mount["source"].as_str().ok_or("OCI mount has no source")?);
            if mount["type"] == "bind" && source.is_file() {
                fs::create_dir_all(target.parent().ok_or("mount target has no parent")?)?;
                fs::copy(source, &target)?;
            } else {
                fs::create_dir_all(&target)?;
            }
        }
        let socket = self.bundle.join("absent-runtime.sock");
        if socket.try_exists()? {
            return Err(format!("runtime endpoint must be absent: {socket:?}").into());
        }
        let config = OciBaseSpecOwner::build(
            &serde_json::to_vec(&spec)?,
            &self.hook,
            manifest,
            &socket,
            100,
            2,
            "info",
        )?;
        fs::write(self.bundle.join("config.json"), config)?;
        let mut command = Command::new(&self.runtime);
        command
            .arg("--root")
            .arg(&self.state)
            .args(["run", "--bundle"])
            .arg(&self.bundle)
            .arg(&self.id);
        let mut actor = ProcessFixture::spawn(&mut command, &self.bundle)?;
        actor.set_group(&self.group);
        Ok(actor)
    }

    fn bind(&self, input: &str) -> TestResult<serde_json::Value> {
        let mut input = input.to_owned();
        for (key, path) in [
            ("MITHRIL_FIXTURES", self.fixtures.as_path()),
            ("MITHRIL_WORK", self.markers.as_path()),
            ("MITHRIL_CGROUP", self.group.strip_prefix("/sys/fs/cgroup")?),
        ] {
            input = input.replace(key, path.to_str().ok_or("OCI input path is not UTF-8")?);
        }
        Ok(serde_json::from_str(
            &input.replace("MITHRIL_ID", &self.id),
        )?)
    }

    pub(crate) fn containers(&self) -> TestResult<Vec<serde_json::Value>> {
        let runtime = Command::new(&self.runtime)
            .arg("--root")
            .arg(&self.state)
            .args(["list", "--format", "json"])
            .output()?;
        if !runtime.status.success() || !runtime.stderr.is_empty() {
            return Err(format!("read runtime containers failed: {runtime:?}").into());
        }
        Ok(
            serde_json::from_slice::<Option<Vec<serde_json::Value>>>(&runtime.stdout)?
                .unwrap_or_default(),
        )
    }
}
