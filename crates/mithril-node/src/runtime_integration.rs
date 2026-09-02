use std::fs::{self, File};
use std::io::{self, Read as _, Write as _};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use crate::runtime_gate::{
    RuntimeControlRecoveryEntryV1, RuntimeRecoveryEntryV1, RuntimeRecoveryManifestV1,
    RuntimeRecoveryMountDestinationV1, RuntimeRecoveryMountV1, MAXIMUM_RECOVERY_ARGUMENTS,
};
use serde_json::{Map, Value};

const MAXIMUM_OWNED_FILE_BYTES: u64 = 536_870_912;

pub struct RuntimeIntegrationInstallV1 {
    pub owner: String,
    pub hook_source: PathBuf,
    pub hook_mount_directory: PathBuf,
    pub hook_host_directory: PathBuf,
    pub containerd_mount_directory: PathBuf,
    pub containerd_host_directory: PathBuf,
    pub containerd_drop_in_directory: String,
    pub runtime_cli_mount_path: PathBuf,
    pub runtime_cli_host_path: PathBuf,
    pub runtime_cli_args: Vec<String>,
    pub runtime_services: Vec<String>,
    pub installer_executable: PathBuf,
    pub installer_args: Vec<String>,
    pub node_mounts: Vec<RuntimeRecoveryMountInputV1>,
    pub control_uid: u32,
    pub control_gid: u32,
    pub control_mounts: Vec<RuntimeControlRecoveryMountInputV1>,
    pub socket: PathBuf,
    pub timeout_ms: u64,
    pub runtime_timeout_seconds: u64,
    pub log_filter: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeRecoveryMountInputV1 {
    pub source: PathBuf,
    pub destination: PathBuf,
    pub read_only: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeControlRecoveryMountInputV1 {
    pub destination: PathBuf,
    pub read_only: bool,
}

pub struct RuntimeIntegrationInstallResultV1 {
    pub restart_required: bool,
    pub base_spec_host_path: PathBuf,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeIntegrationDecommissionV1 {
    pub owner: String,
    pub hook_directory: PathBuf,
    pub containerd_config_directory: PathBuf,
    pub containerd_drop_in_directory: String,
    pub runtime_services: Vec<String>,
}

pub struct RuntimeIntegrationOwner {
    install: RuntimeIntegrationInstallV1,
}

pub struct OciBaseSpecOwner;

impl RuntimeIntegrationOwner {
    pub fn new(install: RuntimeIntegrationInstallV1) -> io::Result<Self> {
        let owner_is_valid =
            (1..=253).contains(&install.owner.len()) && !install.owner.contains(['\r', '\n']);
        let paths_are_valid = [
            &install.hook_source,
            &install.hook_mount_directory,
            &install.hook_host_directory,
            &install.containerd_mount_directory,
            &install.containerd_host_directory,
            &install.runtime_cli_mount_path,
            &install.runtime_cli_host_path,
            &install.installer_executable,
            &install.socket,
        ]
        .into_iter()
        .all(|path| Self::clean_absolute(path));
        let args_are_valid = (2..=MAXIMUM_RECOVERY_ARGUMENTS)
            .contains(&install.installer_args.len())
            && install
                .installer_args
                .first()
                .is_some_and(|arg| Path::new(arg) == install.installer_executable)
            && install
                .installer_args
                .iter()
                .all(|arg| !arg.is_empty() && arg.len() <= 4_096);
        let mounts_are_valid = (1..=32).contains(&install.node_mounts.len())
            && install.node_mounts.iter().all(|mount| {
                Self::clean_absolute(&mount.source) && Self::clean_absolute(&mount.destination)
            });
        let mut control_destinations = std::collections::BTreeSet::new();
        let control_mounts_are_valid = (1..=32).contains(&install.control_mounts.len())
            && install.control_mounts.iter().all(|mount| {
                Self::clean_absolute(&mount.destination)
                    && control_destinations.insert(mount.destination.clone())
            });
        if !owner_is_valid
            || !paths_are_valid
            || !args_are_valid
            || !mounts_are_valid
            || install.control_uid == 0
            || install.control_gid == 0
            || !control_mounts_are_valid
            || !Self::valid_drop_in_directory(&install.containerd_drop_in_directory)
            || install.runtime_cli_args.is_empty()
            || install.runtime_cli_args.len() > 8
            || install
                .runtime_cli_args
                .iter()
                .any(|arg| arg.is_empty() || arg.len() > 128 || arg.contains(['\0', '\r', '\n']))
            || !Self::valid_runtime_services(&install.runtime_services)
            || !(100..=30_000).contains(&install.timeout_ms)
            || install.runtime_timeout_seconds * 1_000 <= install.timeout_ms
            || install.runtime_timeout_seconds > 30
            || install.log_filter.is_empty()
            || install.log_filter.len() > 1_024
            || install.log_filter.contains(['\r', '\n'])
        {
            return Err(Self::invalid(
                "runtime integration input is not canonical and bounded",
            ));
        }
        Ok(Self { install })
    }

    pub fn install(&self) -> io::Result<RuntimeIntegrationInstallResultV1> {
        let default_spec = Command::new("/usr/bin/nsenter")
            .args(["--target", "1", "--mount", "--"])
            .arg(&self.install.runtime_cli_host_path)
            .args(&self.install.runtime_cli_args)
            .output()?;
        if !default_spec.status.success() || default_spec.stdout.is_empty() {
            return Err(Self::invalid(
                "host runtime CLI did not produce the stock containerd OCI spec",
            ));
        }
        self.install_from_spec(&default_spec.stdout)
    }

    pub fn read_back(&self) -> io::Result<()> {
        let generated =
            fs::read_to_string(self.install.containerd_mount_directory.join("config.toml"))?;
        let expected = format!(
            "imports = [\"{}/{}/*.toml\"]",
            self.install.containerd_host_directory.display(),
            self.install.containerd_drop_in_directory
        );
        if !generated.lines().any(|line| line.trim() == expected) {
            return Err(Self::invalid(
                "containerd did not import the owned drop-in directory",
            ));
        }
        let base_spec = self.base_spec_mount_path();
        let recovery = self.recovery_mount_path();
        let hook = self.hook_mount_path();
        let fragment = self.fragment_mount_path();
        self.read_back_owned(&hook, &Self::read_bounded(&self.install.hook_source)?)?;
        self.read_back_owned(
            &recovery,
            &serde_json::to_vec(&self.recovery_manifest()?)
                .map_err(|error| Self::invalid(&format!("recovery manifest failed: {error}")))?,
        )?;
        self.read_back_owned(&fragment, self.fragment().as_bytes())?;
        self.read_back_marker(&base_spec)?;
        OciBaseSpecOwner::read_back(
            &fs::read(base_spec)?,
            &self.hook_host_path(),
            &self.recovery_host_path(),
            &self.install.socket,
            self.install.timeout_ms,
            self.install.runtime_timeout_seconds,
            &self.install.log_filter,
        )?;
        Ok(())
    }

    pub fn restart(&self) -> io::Result<String> {
        Self::restart_runtime(&self.install.runtime_services)
    }

    pub fn decommission(input: &RuntimeIntegrationDecommissionV1) -> io::Result<String> {
        Self::decommission_with_restart(input, || Self::restart_runtime(&input.runtime_services))
    }

    fn decommission_with_restart(
        input: &RuntimeIntegrationDecommissionV1,
        restart: impl FnOnce() -> io::Result<String>,
    ) -> io::Result<String> {
        Self::validate_decommission(input)?;
        let targets = Self::decommission_targets(input);
        for target in &targets {
            let marker = Self::decommission_marker(target)?;
            let target_kind = fs::symlink_metadata(target).map(|value| value.file_type());
            let marker_kind = fs::symlink_metadata(&marker).map(|value| value.file_type());
            match (target_kind, marker_kind) {
                (Err(target_error), Err(marker_error))
                    if target_error.kind() == io::ErrorKind::NotFound
                        && marker_error.kind() == io::ErrorKind::NotFound => {}
                (Ok(target_kind), Ok(marker_kind))
                    if target_kind.is_file()
                        && marker_kind.is_file()
                        && fs::read_to_string(&marker)?.trim_end() == input.owner => {}
                (Err(target_error), Ok(marker_kind))
                    if target_error.kind() == io::ErrorKind::NotFound
                        && marker_kind.is_file()
                        && fs::read_to_string(&marker)?.trim_end() == input.owner => {}
                _ => {
                    return Err(Self::invalid(&format!(
                        "refusing to remove unowned or partial runtime path {}",
                        target.display()
                    )))
                }
            }
        }
        for target in &targets {
            Self::remove_owned_target(target)?;
        }
        let service = restart()?;
        Self::read_back_decommissioned(input)?;
        Ok(service)
    }

    pub fn read_back_decommissioned(input: &RuntimeIntegrationDecommissionV1) -> io::Result<()> {
        Self::validate_decommission(input)?;
        for target in Self::decommission_targets(input) {
            if target.exists() || Self::decommission_marker(&target)?.exists() {
                return Err(Self::invalid(
                    "runtime integration removal readback found an owned path",
                ));
            }
        }
        let config = fs::read_to_string(input.containerd_config_directory.join("config.toml"))?;
        let owned_base_spec = format!(
            "\"{}\"",
            input
                .containerd_config_directory
                .join("mithril-base-spec.json")
                .display()
        );
        let mut in_default_runtime = false;
        for line in config.lines().map(str::trim) {
            if line.starts_with('[') {
                in_default_runtime =
                    line == "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]";
            } else if in_default_runtime
                && line.starts_with("base_runtime_spec")
                && line.ends_with(&owned_base_spec)
            {
                return Err(Self::invalid(
                    "containerd default runtime still invokes the Mithril base spec",
                ));
            }
        }
        Ok(())
    }

    pub fn restart_runtime(services: &[String]) -> io::Result<String> {
        if !Self::valid_runtime_services(services) {
            return Err(Self::invalid("runtime service list is invalid"));
        }
        for service in services {
            let active = Command::new("/usr/bin/nsenter")
                .args([
                    "--target",
                    "1",
                    "--mount",
                    "--uts",
                    "--ipc",
                    "--net",
                    "--pid",
                    "--",
                    "/usr/bin/systemctl",
                    "is-active",
                    "--quiet",
                    service,
                ])
                .status()?;
            if !active.success() {
                continue;
            }
            let restarted = Command::new("/usr/bin/nsenter")
                .args([
                    "--target",
                    "1",
                    "--mount",
                    "--uts",
                    "--ipc",
                    "--net",
                    "--pid",
                    "--",
                    "/usr/bin/systemctl",
                    "restart",
                    service,
                ])
                .status()?;
            if restarted.success() {
                return Ok(service.clone());
            }
            return Err(Self::invalid("container runtime restart failed"));
        }
        Err(Self::invalid(
            "no configured container runtime service is active on the host",
        ))
    }

    fn validate_decommission(input: &RuntimeIntegrationDecommissionV1) -> io::Result<()> {
        if !(1..=253).contains(&input.owner.len())
            || input.owner.contains(['\r', '\n'])
            || !Self::clean_absolute(&input.hook_directory)
            || !Self::clean_absolute(&input.containerd_config_directory)
            || !Self::valid_drop_in_directory(&input.containerd_drop_in_directory)
            || !Self::valid_runtime_services(&input.runtime_services)
        {
            return Err(Self::invalid(
                "runtime integration decommission input is not canonical and bounded",
            ));
        }
        Ok(())
    }

    fn decommission_targets(input: &RuntimeIntegrationDecommissionV1) -> [PathBuf; 4] {
        [
            input
                .containerd_config_directory
                .join(&input.containerd_drop_in_directory)
                .join("99-mithril.toml"),
            input
                .containerd_config_directory
                .join("mithril-base-spec.json"),
            input
                .containerd_config_directory
                .join("mithril-recovery.json"),
            input.hook_directory.join("mithril-oci-hook"),
        ]
    }

    fn decommission_marker(target: &Path) -> io::Result<PathBuf> {
        let name = target
            .file_name()
            .ok_or_else(|| Self::invalid("owned path has no file name"))?
            .to_string_lossy();
        Ok(target.with_file_name(format!(".{name}.mithril-owner")))
    }

    fn remove_owned_target(target: &Path) -> io::Result<()> {
        let marker = Self::decommission_marker(target)?;
        match fs::remove_file(target) {
            Ok(()) => Self::sync_parent(target)?,
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(error),
        }
        match fs::remove_file(&marker) {
            Ok(()) => Self::sync_parent(&marker),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn sync_parent(path: &Path) -> io::Result<()> {
        File::open(
            path.parent()
                .ok_or_else(|| Self::invalid("owned path has no parent"))?,
        )?
        .sync_all()
    }

    fn install_from_spec(
        &self,
        default_spec: &[u8],
    ) -> io::Result<RuntimeIntegrationInstallResultV1> {
        fs::create_dir_all(&self.install.hook_mount_directory)?;
        fs::create_dir_all(&self.install.containerd_mount_directory)?;
        let dropin_directory = self
            .install
            .containerd_mount_directory
            .join(&self.install.containerd_drop_in_directory);
        fs::create_dir_all(&dropin_directory)?;

        self.reject_foreign_base_spec()?;
        let hook_target = self.hook_mount_path();
        let recovery_target = self.recovery_mount_path();
        let base_spec_target = self.base_spec_mount_path();
        let fragment_target = dropin_directory.join("99-mithril.toml");

        let manifest = self.recovery_manifest()?;
        let manifest_bytes = serde_json::to_vec(&manifest)
            .map_err(|error| Self::invalid(&format!("recovery manifest failed: {error}")))?;
        let base_spec_bytes = OciBaseSpecOwner::build(
            default_spec,
            &self.hook_host_path(),
            &self.recovery_host_path(),
            &self.install.socket,
            self.install.timeout_ms,
            self.install.runtime_timeout_seconds,
            &self.install.log_filter,
        )?;
        let fragment = self.fragment();

        self.publish_owned(
            &hook_target,
            &Self::read_bounded(&self.install.hook_source)?,
            0o755,
        )?;
        self.publish_owned(&recovery_target, &manifest_bytes, 0o600)?;
        let base_spec_changed = self.publish_owned(&base_spec_target, &base_spec_bytes, 0o600)?;
        let fragment_changed = self.publish_owned(&fragment_target, fragment.as_bytes(), 0o600)?;
        Ok(RuntimeIntegrationInstallResultV1 {
            restart_required: base_spec_changed || fragment_changed,
            base_spec_host_path: self.base_spec_host_path(),
        })
    }

    fn read_back_owned(&self, path: &Path, expected: &[u8]) -> io::Result<()> {
        self.read_back_marker(path)?;
        if fs::read(path)? != expected {
            return Err(Self::invalid("runtime integration content readback failed"));
        }
        Ok(())
    }

    fn read_back_marker(&self, path: &Path) -> io::Result<()> {
        if !path.is_file()
            || fs::read_to_string(self.marker_for(path)?)?.trim_end() != self.install.owner
        {
            return Err(Self::invalid(
                "runtime integration ownership readback failed",
            ));
        }
        Ok(())
    }

    fn recovery_manifest(&self) -> io::Result<RuntimeRecoveryManifestV1> {
        let installer_mounts = vec![
            RuntimeRecoveryMountV1 {
                source: self.install.hook_host_directory.clone(),
                destination: self.install.hook_mount_directory.clone(),
                read_only: false,
            },
            RuntimeRecoveryMountV1 {
                source: self.install.containerd_host_directory.clone(),
                destination: self.install.containerd_mount_directory.clone(),
                read_only: false,
            },
            RuntimeRecoveryMountV1 {
                source: self.install.runtime_cli_host_path.clone(),
                destination: self.install.runtime_cli_mount_path.clone(),
                read_only: true,
            },
        ];
        let node_mounts = self
            .install
            .node_mounts
            .iter()
            .map(|mount| RuntimeRecoveryMountV1 {
                source: mount.source.clone(),
                destination: mount.destination.clone(),
                read_only: mount.read_only,
            })
            .collect();
        let control_mounts = self
            .install
            .control_mounts
            .iter()
            .map(|mount| RuntimeRecoveryMountDestinationV1 {
                destination: mount.destination.clone(),
                read_only: mount.read_only,
            })
            .collect();
        Ok(RuntimeRecoveryManifestV1 {
            version: 1,
            entries: vec![
                RuntimeRecoveryEntryV1 {
                    executable: self.install.installer_executable.clone(),
                    args: self.install.installer_args.clone(),
                    required_mounts: installer_mounts,
                },
                RuntimeRecoveryEntryV1 {
                    executable: PathBuf::from("/usr/local/bin/mithril-node"),
                    args: vec![
                        "/usr/local/bin/mithril-node".to_owned(),
                        "--config".to_owned(),
                        "/etc/mithril/node.json".to_owned(),
                    ],
                    required_mounts: node_mounts,
                },
            ],
            control_entries: vec![RuntimeControlRecoveryEntryV1 {
                executable: PathBuf::from("/usr/local/bin/mithril-control"),
                args: vec![
                    "/usr/local/bin/mithril-control".to_owned(),
                    "--config".to_owned(),
                    "/etc/mithril/control.json".to_owned(),
                ],
                uid: self.install.control_uid,
                gid: self.install.control_gid,
                required_mounts: control_mounts,
            }],
        })
    }

    fn reject_foreign_base_spec(&self) -> io::Result<()> {
        let config = self.install.containerd_mount_directory.join("config.toml");
        if !config.exists() {
            return Ok(());
        }
        let expected = format!("\"{}\"", self.base_spec_host_path().display());
        let default_runtime_header =
            "[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]";
        let mut in_default_runtime = false;
        for line in fs::read_to_string(config)?.lines() {
            let line = line.trim();
            if line.starts_with('[') {
                in_default_runtime = line == default_runtime_header;
            } else if in_default_runtime
                && line.starts_with("base_runtime_spec")
                && !line.ends_with(&expected)
            {
                return Err(Self::invalid(
                    "default containerd runtime already has an unowned base spec",
                ));
            }
        }
        Ok(())
    }

    fn publish_owned(&self, target: &Path, bytes: &[u8], mode: u32) -> io::Result<bool> {
        let marker = self.marker_for(target)?;
        if target.exists() || marker.exists() {
            if !target.is_file()
                || !marker.is_file()
                || fs::read_to_string(&marker)?.trim_end() != self.install.owner
            {
                return Err(Self::invalid(&format!(
                    "refusing to replace unowned path {}",
                    target.display()
                )));
            }
            if fs::read(target)? == bytes {
                return Ok(false);
            }
        }
        self.atomic_write(
            &marker,
            format!("{}\n", self.install.owner).as_bytes(),
            0o600,
        )?;
        self.atomic_write(target, bytes, mode)?;
        Ok(true)
    }

    fn atomic_write(&self, target: &Path, bytes: &[u8], mode: u32) -> io::Result<()> {
        use std::os::unix::fs::OpenOptionsExt as _;

        let parent = target
            .parent()
            .ok_or_else(|| Self::invalid("owned path has no parent"))?;
        let temporary = parent.join(format!(
            ".{}.mithril-tmp-{}",
            target
                .file_name()
                .ok_or_else(|| Self::invalid("owned path has no file name"))?
                .to_string_lossy(),
            std::process::id()
        ));
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(mode)
            .open(&temporary)?;
        if let Err(error) = (|| {
            file.write_all(bytes)?;
            file.sync_all()?;
            fs::rename(&temporary, target)?;
            File::open(parent)?.sync_all()
        })() {
            let _result = fs::remove_file(&temporary);
            return Err(error);
        }
        Ok(())
    }

    fn marker_for(&self, target: &Path) -> io::Result<PathBuf> {
        let name = target
            .file_name()
            .ok_or_else(|| Self::invalid("owned path has no file name"))?
            .to_string_lossy();
        Ok(target.with_file_name(format!(".{name}.mithril-owner")))
    }

    fn hook_host_path(&self) -> PathBuf {
        self.install.hook_host_directory.join("mithril-oci-hook")
    }

    fn hook_mount_path(&self) -> PathBuf {
        self.install.hook_mount_directory.join("mithril-oci-hook")
    }

    fn recovery_host_path(&self) -> PathBuf {
        self.install
            .containerd_host_directory
            .join("mithril-recovery.json")
    }

    fn recovery_mount_path(&self) -> PathBuf {
        self.install
            .containerd_mount_directory
            .join("mithril-recovery.json")
    }

    fn base_spec_host_path(&self) -> PathBuf {
        self.install
            .containerd_host_directory
            .join("mithril-base-spec.json")
    }

    fn base_spec_mount_path(&self) -> PathBuf {
        self.install
            .containerd_mount_directory
            .join("mithril-base-spec.json")
    }

    fn fragment_mount_path(&self) -> PathBuf {
        self.install
            .containerd_mount_directory
            .join(&self.install.containerd_drop_in_directory)
            .join("99-mithril.toml")
    }

    fn fragment(&self) -> String {
        format!(
            "version = 3\n\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]\nbase_runtime_spec = \"{}\"\npod_annotations = [\"mithril.erebor.dev/*\"]\ncontainer_annotations = [\"mithril.erebor.dev/*\"]\n",
            self.base_spec_host_path().display()
        )
    }

    fn read_bounded(path: &Path) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(MAXIMUM_OWNED_FILE_BYTES + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > MAXIMUM_OWNED_FILE_BYTES as usize {
            return Err(Self::invalid("owned source exceeds its byte limit"));
        }
        Ok(bytes)
    }

    fn clean_absolute(path: &Path) -> bool {
        path.is_absolute()
            && path.as_os_str().as_encoded_bytes().len() <= 4_096
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    }

    fn valid_drop_in_directory(value: &str) -> bool {
        !value.is_empty()
            && value.len() <= 255
            && Path::new(value).components().count() == 1
            && Path::new(value)
                .components()
                .all(|component| matches!(component, Component::Normal(_)))
    }

    fn valid_runtime_services(services: &[String]) -> bool {
        !services.is_empty()
            && services.len() <= 8
            && services.iter().all(|service| {
                !service.is_empty()
                    && service.len() <= 253
                    && service
                        .bytes()
                        .all(|byte| byte.is_ascii_alphanumeric() || b"-_.@".contains(&byte))
            })
    }

    fn invalid(reason: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, reason)
    }
}

impl OciBaseSpecOwner {
    pub fn build(
        default_spec: &[u8],
        hook_path: &Path,
        recovery_manifest: &Path,
        socket: &Path,
        timeout_ms: u64,
        runtime_timeout_seconds: u64,
        log_filter: &str,
    ) -> io::Result<Vec<u8>> {
        let mut spec: Value = serde_json::from_slice(default_spec)
            .map_err(|error| Self::invalid(&format!("OCI base spec is invalid: {error}")))?;
        let hooks = spec
            .as_object_mut()
            .ok_or_else(|| Self::invalid("OCI base spec is not an object"))?
            .entry("hooks")
            .or_insert_with(|| serde_json::json!({}))
            .as_object_mut()
            .ok_or_else(|| Self::invalid("OCI base spec hooks are not an object"))?;
        Self::prepend_hooks(
            hooks,
            "createRuntime",
            [
                Self::hook_document(
                    "stage-runtime-facts",
                    hook_path,
                    recovery_manifest,
                    socket,
                    timeout_ms,
                    runtime_timeout_seconds,
                    log_filter,
                ),
                Self::hook_document(
                    "prepare-container",
                    hook_path,
                    recovery_manifest,
                    socket,
                    timeout_ms,
                    runtime_timeout_seconds,
                    log_filter,
                ),
            ],
        )?;
        Self::prepend_hooks(
            hooks,
            "createContainer",
            [Self::hook_document(
                "prepare-declared-entries",
                hook_path,
                recovery_manifest,
                socket,
                timeout_ms,
                runtime_timeout_seconds,
                log_filter,
            )],
        )?;
        serde_json::to_vec(&spec)
            .map_err(|error| Self::invalid(&format!("OCI base spec failed: {error}")))
    }

    fn read_back(
        base_spec: &[u8],
        hook_path: &Path,
        recovery_manifest: &Path,
        socket: &Path,
        timeout_ms: u64,
        runtime_timeout_seconds: u64,
        log_filter: &str,
    ) -> io::Result<()> {
        let actual: Value = serde_json::from_slice(base_spec)
            .map_err(|error| Self::invalid(&format!("OCI base spec is invalid: {error}")))?;
        let expected: Value = serde_json::from_slice(&Self::build(
            b"{}",
            hook_path,
            recovery_manifest,
            socket,
            timeout_ms,
            runtime_timeout_seconds,
            log_filter,
        )?)
        .map_err(|error| Self::invalid(&format!("OCI base spec is invalid: {error}")))?;
        for (stage, count) in [("createRuntime", 2), ("createContainer", 1)] {
            let actual = actual["hooks"][stage]
                .as_array()
                .ok_or_else(|| Self::invalid("OCI base spec hook stage is missing"))?;
            let expected = expected["hooks"][stage]
                .as_array()
                .ok_or_else(|| Self::invalid("expected OCI hook stage is missing"))?;
            if actual.get(..count) != expected.get(..count) {
                return Err(Self::invalid("OCI base spec hook readback failed"));
            }
        }
        Ok(())
    }

    fn hook_document(
        stage: &str,
        hook_path: &Path,
        recovery_manifest: &Path,
        socket: &Path,
        timeout_ms: u64,
        runtime_timeout_seconds: u64,
        log_filter: &str,
    ) -> Value {
        serde_json::json!({
            "path": hook_path,
            "args": [
                "mithril-oci-hook", "run", "--stage", stage,
                "--socket", socket,
                "--recovery-manifest", recovery_manifest,
                "--timeout-ms", timeout_ms.to_string()
            ],
            "env": [format!("RUST_LOG={log_filter}")],
            "timeout": runtime_timeout_seconds
        })
    }

    fn prepend_hooks<const N: usize>(
        hooks: &mut Map<String, Value>,
        stage: &str,
        additions: [Value; N],
    ) -> io::Result<()> {
        let entries = hooks
            .entry(stage)
            .or_insert_with(|| serde_json::json!([]))
            .as_array_mut()
            .ok_or_else(|| Self::invalid("OCI base spec hook stage is not an array"))?;
        entries.splice(0..0, additions);
        Ok(())
    }

    fn invalid(reason: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, reason)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use serde_json::Value;

    use crate::runtime_gate::RetainedRuntimeGate;

    use super::{
        RuntimeControlRecoveryMountInputV1, RuntimeIntegrationDecommissionV1,
        RuntimeIntegrationInstallV1, RuntimeIntegrationOwner, RuntimeRecoveryMountInputV1,
    };

    #[test]
    fn owner_installs_one_default_runtime_spec_and_exact_recovery_manifest(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let hook_mount = directory.path().join("hook");
        let containerd_mount = directory.path().join("containerd");
        let hook_source = directory.path().join("mithril-oci-hook-source");
        let runtime_cli = directory.path().join("ctr");
        fs::write(&hook_source, b"hook")?;
        fs::write(&runtime_cli, b"ctr")?;
        fs::create_dir_all(&containerd_mount)?;
        fs::write(
            containerd_mount.join("config.toml"),
            "version = 3\nimports = [\"/etc/containerd/conf.d/*.toml\"]\n",
        )?;
        let mut installer_args = vec![
            "/usr/local/bin/mithril-oci-hook".to_owned(),
            "install".to_owned(),
        ];
        installer_args.extend((0..36).map(|index| format!("installer-argument-{index}")));
        let install = RuntimeIntegrationInstallV1 {
            owner: "mithril-system/mithril".to_owned(),
            hook_source,
            hook_mount_directory: hook_mount.clone(),
            hook_host_directory: "/usr/libexec/oci/hooks.d".into(),
            containerd_mount_directory: containerd_mount.clone(),
            containerd_host_directory: "/etc/containerd".into(),
            containerd_drop_in_directory: "conf.d".to_owned(),
            runtime_cli_mount_path: runtime_cli,
            runtime_cli_host_path: "/usr/bin/ctr".into(),
            runtime_cli_args: vec!["oci".to_owned(), "spec".to_owned()],
            runtime_services: vec!["containerd".to_owned()],
            installer_executable: "/usr/local/bin/mithril-oci-hook".into(),
            installer_args,
            node_mounts: vec![RuntimeRecoveryMountInputV1 {
                source: "/etc/mithril/node.json".into(),
                destination: "/etc/mithril/node.json".into(),
                read_only: true,
            }],
            control_uid: 65_532,
            control_gid: 65_532,
            control_mounts: vec![
                RuntimeControlRecoveryMountInputV1 {
                    destination: "/etc/mithril".into(),
                    read_only: true,
                },
                RuntimeControlRecoveryMountInputV1 {
                    destination: "/var/lib/mithril-control".into(),
                    read_only: false,
                },
            ],
            socket: "/run/mithril/runtime-admission.sock".into(),
            timeout_ms: 4_000,
            runtime_timeout_seconds: 5,
            log_filter: "info".to_owned(),
        };
        let owner = RuntimeIntegrationOwner::new(install)?;
        let result = owner.install_from_spec(br#"{"ociVersion":"1.2.0"}"#)?;
        assert!(result.restart_required);

        let base: Value =
            serde_json::from_slice(&fs::read(containerd_mount.join("mithril-base-spec.json"))?)?;
        assert_eq!(
            base["hooks"]["createRuntime"].as_array().map(Vec::len),
            Some(2)
        );
        assert_eq!(
            base["hooks"]["createContainer"].as_array().map(Vec::len),
            Some(1)
        );
        let recovery: Value =
            serde_json::from_slice(&fs::read(containerd_mount.join("mithril-recovery.json"))?)?;
        assert_eq!(recovery["entries"].as_array().map(Vec::len), Some(2));
        assert_eq!(recovery["controlEntries"].as_array().map(Vec::len), Some(1));
        assert!(recovery["entries"][0].get("executableSha256").is_none());
        assert!(recovery["entries"][1].get("executableSha256").is_none());
        assert!(recovery["controlEntries"][0]
            .get("executableSha256")
            .is_none());
        assert_eq!(
            recovery["entries"][0]["args"].as_array().map(Vec::len),
            Some(38)
        );
        RetainedRuntimeGate::open(&containerd_mount.join("mithril-recovery.json"))?;
        assert!(hook_mount.join("mithril-oci-hook").is_file());
        owner.read_back()?;

        fs::write(
            containerd_mount.join("conf.d/99-mithril.toml"),
            "version = 3\n",
        )?;
        assert!(owner.read_back().is_err());

        let result = owner.install_from_spec(br#"{"ociVersion":"1.2.0"}"#)?;
        assert!(result.restart_required);
        owner.read_back()?;

        let decommission = RuntimeIntegrationDecommissionV1 {
            owner: "mithril-system/mithril".to_owned(),
            hook_directory: hook_mount,
            containerd_config_directory: containerd_mount.clone(),
            containerd_drop_in_directory: "conf.d".to_owned(),
            runtime_services: vec!["containerd".to_owned()],
        };
        let fragment = containerd_mount.join("conf.d/99-mithril.toml");
        fs::remove_file(&fragment)?;
        fs::write(
            containerd_mount.join("config.toml"),
            format!(
                "version = 3\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]\nbase_runtime_spec = \"{}\"\n",
                containerd_mount.join("mithril-base-spec.json").display()
            ),
        )?;
        let restarted = RuntimeIntegrationOwner::decommission_with_restart(&decommission, || {
            fs::write(
                containerd_mount.join("config.toml"),
                "version = 3\n[plugins.'io.containerd.cri.v1.runtime'.containerd.runtimes.runc]\n",
            )?;
            Ok("containerd".to_owned())
        })?;
        assert_eq!(restarted, "containerd");
        RuntimeIntegrationOwner::read_back_decommissioned(&decommission)?;
        Ok(())
    }
}
