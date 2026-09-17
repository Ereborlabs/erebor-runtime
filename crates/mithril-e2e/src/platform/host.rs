use std::ffi::OsString;
use std::fs::{self, File};
use std::os::fd::AsRawFd as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelStateReader;
use erebor_runtime_ipc::v1::MithrilObservationSnapshot;
use mithril_node::RuntimeAdmissionOperationV1;
use snafu::{ensure, ResultExt as _};

use super::shared::Shared;
use super::{Platform, Task, TestResult, PROCESS_FIXTURES};
use crate::error::{InvalidInputSnafu, IoSnafu};
use crate::physical::ProbeDirectory;
use crate::process::ProcessFixture;

pub(crate) struct Host {
    shared: Shared,
    bundle: Option<ProbeDirectory>,
    init_pid: Option<u32>,
    staged: bool,
    admitted: bool,
    mounts: Vec<PathBuf>,
}

impl Host {
    fn bind(&mut self, source: &Path, target: &Path) -> TestResult<()> {
        fs::create_dir_all(target).context(IoSnafu { path: target })?;
        rustix::mount::mount_bind(source, target)
            .map_err(std::io::Error::from)
            .context(IoSnafu { path: target })?;
        self.mounts.push(target.to_owned());
        Ok(())
    }

    fn actor_root(&mut self) -> TestResult<PathBuf> {
        let bundle_path = self.shared.output().join("bundle");
        let rootfs = bundle_path.join("rootfs");
        if self.bundle.is_some() {
            return Ok(rootfs);
        }
        let bundle = ProbeDirectory::create(&bundle_path)?;
        fs::create_dir_all(rootfs.join("bundle"))?;
        self.bind(&rootfs, &rootfs)?;
        for path in ["/usr", "/lib", "/lib64", "/proc"] {
            let source = Path::new(path);
            if source.exists() {
                self.bind(source, &rootfs.join(path.trim_start_matches('/')))?;
            }
        }
        let fixtures = self.shared.source().join(PROCESS_FIXTURES);
        self.bind(&fixtures, &rootfs.join("fixtures"))?;
        let work = self.shared.work().to_owned();
        self.bind(&work, &rootfs.join("work"))?;
        self.bundle = Some(bundle);
        Ok(rootfs)
    }

    fn stage_entries(&self, rootfs: &Path) -> TestResult<()> {
        let config = rootfs.join("bundle/config.json");
        fs::write(&config, br#"{"root":{"path":"/"}}"#).context(IoSnafu { path: &config })?;
        let root = File::open(rootfs).context(IoSnafu { path: rootfs })?;
        let mut request = self
            .shared
            .request(RuntimeAdmissionOperationV1::PrepareDeclaredEntries, None)?;
        request.oci_bundle = Some(PathBuf::from("/bundle"));
        request.oci_root_fd = Some(u32::try_from(root.as_raw_fd())?);
        let response = self.shared.submit(&request)?;
        ensure!(
            response.allowed && response.reason_code == "DECLARED_ENTRY_CANDIDATE_STAGED",
            InvalidInputSnafu {
                path: self.shared.admit_path(),
                reason: format!("Node rejected declared entries: {response:?}"),
            }
        );
        Ok(())
    }

    fn start_entry(&mut self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        let init = self.init_pid.ok_or("the initial actor is not running")?;
        let maps_path = PathBuf::from(format!("/proc/{init}/maps"));
        let maps = fs::read(&maps_path).context(IoSnafu { path: &maps_path })?;
        ensure!(
            !maps.is_empty(),
            InvalidInputSnafu {
                path: &maps_path,
                reason: "the runtime read an empty initial actor map",
            }
        );
        let rootfs = self.shared.output().join("bundle/rootfs");
        let program = Path::new(command);
        let mut actor = ProcessFixture::held_cgroup(program, args, self.shared.cgroup(), &rootfs)?;
        let pid = actor.id();
        let placement = self
            .shared
            .node_running()
            .then(|| self.shared.task(pid, "added actor placement"))
            .transpose()?;
        actor.release()?;
        if let Err(source) = actor.wait_command(pid, command) {
            if let Some(placement) = placement {
                return Err(format!(
                    "{source}; pre-exec PID: {}; snapshot: {:?}; coordinate: {:?}; identity health: {:?}",
                    placement.pid,
                    placement.snapshot,
                    placement.coordinate,
                    self.shared.health()?
                )
                .into());
            }
            return Err(source.into());
        }
        Ok(actor)
    }

    fn close(&mut self) -> TestResult<()> {
        for target in self.mounts.drain(..).rev() {
            rustix::mount::unmount(&target, rustix::mount::UnmountFlags::DETACH)
                .map_err(std::io::Error::from)
                .context(IoSnafu { path: &target })?;
        }
        if let Some(bundle) = self.bundle.take() {
            bundle.cleanup()?;
        }
        self.init_pid = None;
        self.staged = false;
        self.admitted = false;
        self.shared.stop()
    }
}

impl Platform for Host {
    fn source(&self) -> &Path {
        self.shared.source()
    }

    fn setup(name: &str) -> TestResult<Self> {
        Ok(Self {
            shared: Shared::setup(name)?,
            bundle: None,
            init_pid: None,
            staged: false,
            admitted: false,
            mounts: Vec::new(),
        })
    }

    fn start_control(&mut self) -> TestResult<()> {
        self.shared.start_control()
    }

    fn start_node(&mut self) -> TestResult<()> {
        self.shared.start_node()
    }

    fn stop_node(&mut self) -> TestResult<()> {
        self.shared.stop_node()
    }

    fn install_policy(&mut self, name: &str) -> TestResult<()> {
        self.shared.install_policy(name)
    }

    fn sync_policy(&mut self) -> TestResult<()> {
        self.shared.sync_policy()
    }

    fn node_ready(&mut self) -> TestResult<()> {
        self.shared.node_ready()
    }

    fn start_actor(&mut self, name: &str, extra: &[&str]) -> TestResult<ProcessFixture> {
        ensure!(
            self.init_pid.is_none(),
            InvalidInputSnafu {
                path: self.shared.work(),
                reason: "the initial actor is already running",
            }
        );
        let protected = self.shared.protected();
        let rootfs = self.actor_root()?;
        let mut args = vec![OsString::from("/work")];
        args.extend(extra.iter().map(OsString::from));
        args.insert(0, OsString::from(format!("/fixtures/{name}")));
        let mut actor = ProcessFixture::held_pidns(
            Path::new("/usr/bin/python3"),
            args,
            self.shared.cgroup(),
            &rootfs,
            Path::new(name),
        )?;
        let pid = actor.id();
        self.init_pid = Some(pid);
        if protected {
            self.stage()?;
            self.admit(pid)?;
            self.stage_entries(&rootfs)?;
        }
        actor.release()?;
        if let Err(source) = actor.ready() {
            if protected {
                return Err(format!("{source}; identity health: {:?}", self.health()?).into());
            }
            return Err(source.into());
        }
        if protected {
            self.running(pid)?;
        }
        Ok(actor)
    }

    fn add_actor(&mut self, command: &str, args: &[&str]) -> TestResult<ProcessFixture> {
        self.start_entry(command, args)
    }

    fn approve(&mut self, command: &str, args: &[&str]) -> TestResult<()> {
        self.shared.approve(command, args)
    }

    fn place(&mut self, pid: u32) -> TestResult<()> {
        self.shared.place(pid)
    }

    fn stage(&mut self) -> TestResult<()> {
        if self.staged {
            return Ok(());
        }
        self.shared.observe()?;
        let request = self
            .shared
            .request(RuntimeAdmissionOperationV1::StageRuntimeFacts, None)?;
        let response = self.shared.submit(&request)?;
        ensure!(
            response.allowed && response.reason_code == "RUNTIME_FACTS_STAGING",
            InvalidInputSnafu {
                path: self.shared.admit_path(),
                reason: format!("Node rejected runtime staging: {response:?}"),
            }
        );
        self.staged = true;
        Ok(())
    }

    fn admit(&mut self, pid: u32) -> TestResult<()> {
        if self.admitted {
            ensure!(
                self.init_pid == Some(pid),
                InvalidInputSnafu {
                    path: self.shared.admit_path(),
                    reason: "the admitted actor PID changed",
                }
            );
            return Ok(());
        }
        let request = self
            .shared
            .request(RuntimeAdmissionOperationV1::PrepareContainer, Some(pid))?;
        let response = self.shared.submit(&request)?;
        ensure!(
            response.allowed && response.reason_code == "ACTIVE_POLICY_AND_BINDING_VERIFIED",
            InvalidInputSnafu {
                path: self.shared.admit_path(),
                reason: format!("Node rejected runtime preparation: {response:?}"),
            }
        );
        self.admitted = true;
        Ok(())
    }

    fn running(&mut self, pid: u32) -> TestResult<()> {
        self.shared.running(pid)
    }

    fn health(&self) -> TestResult<mithril_node::ReconciliationReportV1> {
        self.shared.health()
    }

    fn move_task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.shared.move_task(pid, name)
    }

    fn task(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.shared.task(pid, name)
    }

    fn wait_exec(
        &mut self,
        actor: &mut ProcessFixture,
        pid: u32,
        cookie: u64,
        before: &Task,
        name: &str,
    ) -> TestResult<Task> {
        self.shared.wait_exec(actor, pid, cookie, before, name)
    }

    fn wait_pid_exec(
        &mut self,
        pid: u32,
        cookie: u64,
        before: &Task,
        name: &str,
    ) -> TestResult<Task> {
        self.shared.wait_pid_exec(pid, cookie, before, name)
    }

    fn recovered(&mut self, pid: u32, name: &str) -> TestResult<Task> {
        self.shared.recovered(pid, name)
    }

    fn snapshot(&self) -> TestResult<MithrilObservationSnapshot> {
        self.shared.snapshot()
    }

    fn maps(&self) -> (&Path, &KernelStateReader) {
        self.shared.maps()
    }

    fn work(&self) -> &Path {
        self.shared.work()
    }

    fn actor_group(&self) -> TestResult<&Path> {
        Ok(self.shared.cgroup())
    }

    fn stop(&mut self) -> TestResult<()> {
        self.close()
    }
}

impl Drop for Host {
    fn drop(&mut self) {
        let _result = self.close();
    }
}
