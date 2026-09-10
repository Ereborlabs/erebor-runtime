use std::env;
use std::fs;
use std::os::unix::fs::PermissionsExt as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use erebor_interceptor::KernelStateReader;
use mithril_node::OciBaseSpecOwner;
use serde_json::{json, Value};

use super::{Host, Platform, Task, TestResult};
use crate::physical::ProbeDirectory;
use crate::process::ProcessFixture;

pub(crate) struct Runc {
    host: Host,
    runc_path: PathBuf,
    state_path: PathBuf,
    bundle_path: PathBuf,
    hook_path: PathBuf,
    manifest_path: PathBuf,
    cleanup: Option<ProbeDirectory>,
    container_id: Option<String>,
}

impl Runc {
    fn run(command: &mut Command, name: &Path) -> TestResult<Vec<u8>> {
        let output = command.output()?;
        if !output.status.success() {
            return Err(format!(
                "{} failed with {}; stderr: {}",
                name.display(),
                output.status,
                String::from_utf8_lossy(&output.stderr).trim()
            )
            .into());
        }
        Ok(output.stdout)
    }

    fn mount(config: &mut Value, source: &Path, target: &str, writable: bool) -> TestResult<()> {
        let mounts = config["mounts"]
            .as_array_mut()
            .ok_or("the runc config has no mount array")?;
        mounts.push(json!({
            "destination": target,
            "type": "bind",
            "source": source,
            "options": if writable {
                vec!["rbind", "rprivate", "rw"]
            } else {
                vec!["rbind", "rprivate", "ro"]
            },
        }));
        Ok(())
    }

    fn state(&self, id: &str) -> TestResult<Value> {
        let mut command = Command::new(&self.runc_path);
        command
            .arg("--root")
            .arg(&self.state_path)
            .args(["state", id]);
        Ok(serde_json::from_slice(&Self::run(
            &mut command,
            &self.runc_path,
        )?)?)
    }

    fn close(&mut self) -> TestResult<()> {
        let deleted = if let Some(id) = self.container_id.take() {
            let mut command = Command::new(&self.runc_path);
            command
                .arg("--root")
                .arg(&self.state_path)
                .args(["delete", "--force", &id]);
            Self::run(&mut command, &self.runc_path).map(|_| ())
        } else {
            Ok(())
        };
        if let Some(cleanup) = self.cleanup.take() {
            cleanup.cleanup()?;
        }
        self.host.stop()?;
        deleted
    }
}

impl Platform for Runc {
    fn setup(name: &str) -> TestResult<Self> {
        let mut host = Host::setup(name)?;
        let runc_path = env::var_os("MITHRIL_TEST_RUNC")
            .map(PathBuf::from)
            .ok_or("MITHRIL_TEST_RUNC is not set")?;
        if !runc_path.is_file() {
            return Err(format!("runc is missing: {}", runc_path.display()).into());
        }
        let dir_path = host.output().join("runc");
        let cleanup = ProbeDirectory::create(&dir_path)?;
        let state_path = dir_path.join("state");
        let bundle_path = dir_path.join("bundle");
        let hook_dir = dir_path.join("hook");
        fs::create_dir(&state_path)?;
        fs::create_dir(&bundle_path)?;
        fs::create_dir(&hook_dir)?;
        fs::create_dir(bundle_path.join("rootfs"))?;
        let hook_src = env::var_os("MITHRIL_TEST_OCI_HOOK")
            .map(PathBuf::from)
            .ok_or("MITHRIL_TEST_OCI_HOOK is not set")?;
        if !hook_src.is_file() {
            return Err(format!("OCI hook is missing: {}", hook_src.display()).into());
        }
        let hook_path = hook_dir.join("mithril-oci-hook");
        fs::copy(&hook_src, &hook_path)?;
        fs::set_permissions(&hook_path, fs::Permissions::from_mode(0o755))?;
        let manifest_src = host
            .source()
            .join("crates/mithril-e2e/fixtures/convergence/direct-runc-recovery-v1.json");
        let manifest_path = hook_dir.join("runtime-recovery.json");
        fs::copy(&manifest_src, &manifest_path)?;
        host.set_hook(&hook_path);
        let mut command = Command::new(&runc_path);
        command.arg("spec").arg("--bundle").arg(&bundle_path);
        Self::run(&mut command, &runc_path)?;
        Ok(Self {
            host,
            runc_path,
            state_path,
            bundle_path,
            hook_path,
            manifest_path,
            cleanup: Some(cleanup),
            container_id: None,
        })
    }

    fn start_control(&mut self) -> TestResult<()> {
        self.host.start_control()
    }

    fn start_node(&mut self) -> TestResult<()> {
        self.host.start_node()
    }

    fn install_policy(&mut self) -> TestResult<()> {
        self.host.install_policy()
    }

    fn sync_policy(&mut self) -> TestResult<()> {
        self.host.sync_policy()
    }

    fn node_ready(&mut self) -> TestResult<()> {
        self.host.node_ready()
    }

    fn start_actor(&mut self, name: &str, extra: &[&str]) -> TestResult<ProcessFixture> {
        if self.container_id.is_some() {
            return Err("the runc actor is already started".into());
        }
        let rootfs = self.bundle_path.join("rootfs");
        for name in ["usr", "lib", "lib64", "fixtures", "work"] {
            fs::create_dir_all(rootfs.join(name))?;
        }
        let script = ProcessFixture::script(self.host.source(), name)?;
        let fixtures = script
            .parent()
            .ok_or("the actor has no fixture directory")?;

        let path = self.bundle_path.join("config.json");
        let mut config: Value = serde_json::from_slice(&fs::read(&path)?)?;
        let mut args = vec![
            "/usr/bin/python3".to_owned(),
            format!("/fixtures/{name}"),
            "/work".to_owned(),
        ];
        args.extend(extra.iter().map(|arg| (*arg).to_owned()));
        config["process"]["terminal"] = json!(false);
        config["process"]["args"] = json!(args);
        config["process"]["cwd"] = json!("/work");
        config["process"]["env"] = json!(["PATH=/usr/bin", "PYTHONDONTWRITEBYTECODE=1"]);
        let caps = json!(["CAP_CHECKPOINT_RESTORE", "CAP_SYS_ADMIN"]);
        config["process"]["capabilities"] = json!({
            "bounding": caps,
            "effective": caps,
            "permitted": caps,
        });
        config["root"]["path"] = json!("rootfs");
        config["root"]["readonly"] = json!(false);
        let cgroup = self
            .host
            .cgroup()
            .strip_prefix("/sys/fs/cgroup")?
            .to_string_lossy();
        config["linux"]["cgroupsPath"] = json!(cgroup.as_ref());
        if let Some(paths) = config["linux"]["readonlyPaths"].as_array_mut() {
            paths.retain(|path| path.as_str() != Some("/proc/sys"));
        }
        for path in ["/usr", "/lib", "/lib64"] {
            let source = Path::new(path);
            if source.exists() {
                Self::mount(&mut config, source, path, false)?;
            }
        }
        Self::mount(&mut config, fixtures, "/fixtures", false)?;
        Self::mount(&mut config, self.host.work(), "/work", true)?;
        let config = if self.host.has_policy() {
            config["annotations"] = json!(self.host.annotations()?);
            for (source, writable) in [
                (
                    self.hook_path
                        .parent()
                        .ok_or("the OCI hook has no parent directory")?,
                    false,
                ),
                (
                    self.host
                        .admit_path()
                        .parent()
                        .ok_or("the admission socket has no parent directory")?,
                    true,
                ),
            ] {
                let relative = source.strip_prefix("/")?;
                fs::create_dir_all(rootfs.join(relative))?;
                let target = source
                    .to_str()
                    .ok_or("a runc mount path is not valid UTF-8")?;
                Self::mount(&mut config, source, target, writable)?;
            }
            self.host.observe()?;
            OciBaseSpecOwner::build(
                &serde_json::to_vec(&config)?,
                &self.hook_path,
                &self.manifest_path,
                self.host.admit_path(),
                5_000,
                6,
                "info",
            )?
        } else {
            serde_json::to_vec_pretty(&config)?
        };
        fs::write(&path, config)?;

        let id = self.host.actor_id().to_owned();
        self.container_id = Some(id.clone());
        let mut command = Command::new(&self.runc_path);
        command
            .arg("--root")
            .arg(&self.state_path)
            .args(["run", "--bundle"])
            .arg(&self.bundle_path)
            .arg(&id);
        let mut actor = ProcessFixture::start(&mut command, &script)?;
        let parent = actor.id();
        let state = self.state(&id)?;
        let pid = state["pid"]
            .as_u64()
            .and_then(|pid| u32::try_from(pid).ok())
            .filter(|pid| *pid > 0)
            .ok_or("runc state has no actor PID")?;
        self.host.move_out(parent)?;
        actor.set_init(pid)?;
        Ok(actor)
    }

    fn place(&mut self, pid: u32) -> TestResult<()> {
        let path = PathBuf::from(format!("/proc/{pid}/cgroup"));
        let state = fs::read_to_string(&path)?;
        let actual = state
            .lines()
            .find_map(|line| line.split_once("::").map(|(_, path)| path))
            .ok_or("the runc actor has no unified cgroup")?;
        let expected = Path::new("/").join(self.host.cgroup().strip_prefix("/sys/fs/cgroup")?);
        if Path::new(actual) != expected {
            return Err(format!(
                "runc actor cgroup is {actual}; expected {}",
                expected.display()
            )
            .into());
        }
        Ok(())
    }

    fn stage(&mut self) -> TestResult<()> {
        let id = self
            .container_id
            .as_deref()
            .ok_or("the runc actor is not started")?;
        let state = self.state(id)?;
        if state["status"].as_str() != Some("running") {
            return Err(format!("the admitted runc actor is not running: {state}").into());
        }
        Ok(())
    }

    fn admit(&mut self, pid: u32) -> TestResult<()> {
        let task = self.host.task(pid, "direct runc admission")?;
        let binding = task
            .snapshot
            .runtime_binding
            .ok_or("the direct runc actor has no runtime binding")?;
        if binding.lifecycle_state != "active" {
            return Err(format!("the direct runc binding is not active: {binding:?}").into());
        }
        Ok(())
    }

    fn running(&mut self, pid: u32) -> TestResult<()> {
        self.host.running(pid)
    }

    fn task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.host.task(pid, name)
    }

    fn recovered(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.host.recovered(pid, name)
    }

    fn maps(&self) -> (&Path, &KernelStateReader) {
        self.host.maps()
    }

    fn work(&self) -> &Path {
        self.host.work()
    }

    fn output(&self) -> &Path {
        self.host.output()
    }

    fn stop(&mut self) -> TestResult<()> {
        self.close()
    }
}

impl Drop for Runc {
    fn drop(&mut self) {
        let _result = self.close();
    }
}
