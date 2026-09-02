use std::collections::{BTreeMap, BTreeSet};
use std::fs::File;
use std::io::{self, Read as _};
use std::os::unix::fs::MetadataExt as _;
use std::path::{Component, Path, PathBuf};

use crate::PROFILE_ID_ANNOTATION;
use serde::{Deserialize, Serialize};

const MAXIMUM_OCI_CONFIG_BYTES: u64 = 1_048_576;
pub(crate) const MAXIMUM_RECOVERY_ARGUMENTS: usize = 64;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RetainedRuntimeDecisionV1 {
    AllowHealthy,
    AllowInstaller,
    AllowRecovery,
    AllowSandbox,
    AdmitProtected,
    DenyHostile,
    DenyUnavailable,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RuntimeRecoveryMountV1 {
    pub(crate) source: PathBuf,
    pub(crate) destination: PathBuf,
    pub(crate) read_only: bool,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RuntimeRecoveryManifestV1 {
    pub(crate) version: u8,
    pub(crate) entries: Vec<RuntimeRecoveryEntryV1>,
    #[serde(default)]
    pub(crate) control_entries: Vec<RuntimeControlRecoveryEntryV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RuntimeRecoveryEntryV1 {
    pub(crate) executable: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) required_mounts: Vec<RuntimeRecoveryMountV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RuntimeControlRecoveryEntryV1 {
    pub(crate) executable: PathBuf,
    pub(crate) args: Vec<String>,
    pub(crate) uid: u32,
    pub(crate) gid: u32,
    pub(crate) required_mounts: Vec<RuntimeRecoveryMountDestinationV1>,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields, rename_all = "camelCase")]
pub(crate) struct RuntimeRecoveryMountDestinationV1 {
    pub(crate) destination: PathBuf,
    pub(crate) read_only: bool,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciRuntimeConfigV1 {
    process: OciProcessV1,
    root: OciRootV1,
    #[serde(default)]
    mounts: Vec<OciMountV1>,
    #[serde(default)]
    linux: OciLinuxV1,
    #[serde(default)]
    annotations: BTreeMap<String, String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciProcessV1 {
    args: Vec<String>,
    #[serde(default)]
    user: OciUserV1,
    #[serde(default)]
    capabilities: OciCapabilitiesV1,
    #[serde(default)]
    no_new_privileges: bool,
}

#[derive(Debug, Default, Deserialize)]
struct OciCapabilitiesV1 {
    #[serde(default)]
    bounding: Vec<String>,
    #[serde(default)]
    effective: Vec<String>,
    #[serde(default)]
    permitted: Vec<String>,
    #[serde(default)]
    inheritable: Vec<String>,
    #[serde(default)]
    ambient: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
#[serde(rename_all = "camelCase")]
struct OciUserV1 {
    uid: u32,
    gid: u32,
    #[serde(default)]
    additional_gids: Vec<u32>,
}

#[derive(Debug, Deserialize)]
struct OciRootV1 {
    #[serde(default)]
    readonly: bool,
}

#[derive(Debug, Deserialize)]
struct OciMountV1 {
    destination: PathBuf,
    #[serde(default)]
    source: PathBuf,
    #[serde(rename = "type", default)]
    kind: String,
    #[serde(default)]
    options: Vec<String>,
}

#[derive(Debug, Default, Deserialize)]
struct OciLinuxV1 {
    #[serde(default)]
    namespaces: Vec<OciNamespaceV1>,
}

#[derive(Debug, Deserialize)]
struct OciNamespaceV1 {
    #[serde(rename = "type")]
    kind: String,
    #[serde(default)]
    path: Option<PathBuf>,
}

pub struct RetainedRuntimeGate {
    recovery: RuntimeRecoveryManifestV1,
}

impl RetainedRuntimeGate {
    pub fn open(path: &Path) -> io::Result<Self> {
        let bytes = Self::read_bounded(path, MAXIMUM_OCI_CONFIG_BYTES)?;
        let recovery: RuntimeRecoveryManifestV1 = serde_json::from_slice(&bytes)
            .map_err(|error| Self::invalid(&format!("recovery manifest is invalid: {error}")))?;
        recovery.validate()?;
        Ok(Self { recovery })
    }

    pub fn decide(
        &self,
        bundle: &Path,
        state_annotations: &BTreeMap<String, String>,
        endpoint_available: bool,
    ) -> io::Result<RetainedRuntimeDecisionV1> {
        let config_path = bundle.join("config.json");
        let bytes = Self::read_bounded(&config_path, MAXIMUM_OCI_CONFIG_BYTES)?;
        let config: OciRuntimeConfigV1 = serde_json::from_slice(&bytes)
            .map_err(|error| Self::invalid(&format!("OCI runtime config is invalid: {error}")))?;

        if config.is_hostile_incident() {
            return Ok(RetainedRuntimeDecisionV1::DenyHostile);
        }
        if config.is_protected(state_annotations) {
            return Ok(RetainedRuntimeDecisionV1::AdmitProtected);
        }
        if endpoint_available {
            return Ok(RetainedRuntimeDecisionV1::AllowHealthy);
        }
        if config.is_cri_sandbox(state_annotations) {
            return Ok(RetainedRuntimeDecisionV1::AllowSandbox);
        }
        if let Some(decision) = self.recovery.recovery_decision(&config)? {
            return Ok(decision);
        }
        Ok(RetainedRuntimeDecisionV1::DenyUnavailable)
    }

    fn read_bounded(path: &Path, maximum: u64) -> io::Result<Vec<u8>> {
        let mut bytes = Vec::new();
        File::open(path)?
            .take(maximum + 1)
            .read_to_end(&mut bytes)?;
        if bytes.is_empty() || bytes.len() > maximum as usize {
            return Err(Self::invalid("runtime gate input exceeds its byte limit"));
        }
        Ok(bytes)
    }

    fn invalid(reason: &str) -> io::Error {
        io::Error::new(io::ErrorKind::InvalidData, reason)
    }
}

impl RuntimeRecoveryManifestV1 {
    fn validate(&self) -> io::Result<()> {
        let mut identities = BTreeSet::new();
        let entries_are_valid = (1..=4).contains(&self.entries.len())
            && self.entries.iter().all(|entry| {
                entry.validate()
                    && identities.insert((entry.executable.clone(), entry.args.clone()))
            });
        let control_entries_are_valid = self.control_entries.len() <= 1
            && self.control_entries.iter().all(|entry| {
                entry.validate()
                    && identities.insert((entry.executable.clone(), entry.args.clone()))
            });
        if self.version != 1 || !entries_are_valid || !control_entries_are_valid {
            return Err(RetainedRuntimeGate::invalid(
                "recovery manifest is not canonical and bounded",
            ));
        }
        Ok(())
    }

    fn recovery_decision(
        &self,
        config: &OciRuntimeConfigV1,
    ) -> io::Result<Option<RetainedRuntimeDecisionV1>> {
        for entry in &self.entries {
            if entry.matches_installer(config)? {
                return Ok(Some(RetainedRuntimeDecisionV1::AllowInstaller));
            }
            if entry.matches(config)? {
                return Ok(Some(RetainedRuntimeDecisionV1::AllowRecovery));
            }
        }
        for entry in &self.control_entries {
            if entry.matches(config)? {
                return Ok(Some(RetainedRuntimeDecisionV1::AllowRecovery));
            }
        }
        Ok(None)
    }

    fn clean_absolute(path: &Path) -> bool {
        path.is_absolute()
            && path.as_os_str().as_encoded_bytes().len() <= 4_096
            && path
                .components()
                .all(|component| matches!(component, Component::RootDir | Component::Normal(_)))
    }
}

impl RuntimeControlRecoveryEntryV1 {
    fn validate(&self) -> bool {
        let args_are_valid = (1..=MAXIMUM_RECOVERY_ARGUMENTS).contains(&self.args.len())
            && self.args.first().is_some_and(|arg| {
                Path::new(arg) == self.executable
                    && RuntimeRecoveryManifestV1::clean_absolute(&self.executable)
            })
            && self
                .args
                .iter()
                .all(|arg| !arg.is_empty() && arg.len() <= 4_096);
        let mut destinations = BTreeSet::new();
        let mounts_are_valid = (1..=32).contains(&self.required_mounts.len())
            && self.required_mounts.iter().all(|mount| {
                RuntimeRecoveryManifestV1::clean_absolute(&mount.destination)
                    && destinations.insert(mount.destination.clone())
            });
        args_are_valid && self.uid != 0 && self.gid != 0 && mounts_are_valid
    }

    fn matches(&self, config: &OciRuntimeConfigV1) -> io::Result<bool> {
        if config.process.args != self.args
            || config.process.user.uid != self.uid
            || config.process.user.gid != self.gid
            || config.process.user.additional_gids.as_slice() != [self.gid]
            || !config.process.no_new_privileges
            || !config.process.capabilities.is_empty()
            || !config.root.readonly
            || config.linux.shares_host_pid_namespace()?
            || !self.mounts_match(&config.mounts)
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn mounts_match(&self, actual: &[OciMountV1]) -> bool {
        let required_match = self.required_mounts.iter().all(|required| {
            actual.iter().any(|mount| {
                mount.is_bind()
                    && mount.destination == required.destination
                    && mount.is_read_only() == required.read_only
            })
        });
        required_match
            && actual.iter().filter(|mount| mount.is_bind()).all(|mount| {
                self.required_mounts
                    .iter()
                    .any(|required| required.destination == mount.destination)
                    || mount.is_standard_kubernetes_mount()
            })
    }
}

impl RuntimeRecoveryEntryV1 {
    fn validate(&self) -> bool {
        let args_are_valid = (1..=MAXIMUM_RECOVERY_ARGUMENTS).contains(&self.args.len())
            && self.args.first().is_some_and(|arg| {
                Path::new(arg) == self.executable
                    && RuntimeRecoveryManifestV1::clean_absolute(&self.executable)
            })
            && self
                .args
                .iter()
                .all(|arg| !arg.is_empty() && arg.len() <= 4_096);
        let mut destinations = BTreeSet::new();
        let mounts_are_valid = (1..=32).contains(&self.required_mounts.len())
            && self.required_mounts.iter().all(|mount| {
                RuntimeRecoveryManifestV1::clean_absolute(&mount.source)
                    && RuntimeRecoveryManifestV1::clean_absolute(&mount.destination)
                    && destinations.insert(mount.destination.clone())
            });
        args_are_valid && mounts_are_valid
    }

    fn matches(&self, config: &OciRuntimeConfigV1) -> io::Result<bool> {
        if config.process.args != self.args
            || config.process.no_new_privileges
            || !config.process.capabilities.contains("CAP_SYS_ADMIN")
            || !config.linux.shares_host_pid_namespace()?
            || !self.mounts_match(&config.mounts)
        {
            return Ok(false);
        }
        Ok(true)
    }

    fn matches_installer(&self, config: &OciRuntimeConfigV1) -> io::Result<bool> {
        if self.executable != Path::new("/usr/local/bin/mithril-oci-hook")
            || self.args.get(1).map(String::as_str) != Some("install")
            || config.process.args.first().map(Path::new) != Some(self.executable.as_path())
            || config.process.args.get(1).map(String::as_str) != Some("install")
            || !(2..=MAXIMUM_RECOVERY_ARGUMENTS).contains(&config.process.args.len())
            || config.process.no_new_privileges
            || !config.process.capabilities.contains("CAP_SYS_ADMIN")
            || !config.linux.shares_host_pid_namespace()?
        {
            return Ok(false);
        }
        for option in [
            "--owner",
            "--hook-host-directory",
            "--containerd-host-directory",
            "--socket",
        ] {
            match (
                self.unique_option(option),
                Self::unique_option_in(&config.process.args, option),
            ) {
                (Some(retained), Some(actual)) if retained == actual => {}
                _ => return Ok(false),
            }
        }
        Ok(self
            .required_mounts
            .iter()
            .filter(|mount| !mount.read_only)
            .all(|required| {
                config.mounts.iter().any(|mount| {
                    mount.is_bind()
                        && mount.source == required.source
                        && mount.destination == required.destination
                        && !mount.is_read_only()
                })
            }))
    }

    fn unique_option(&self, option: &str) -> Option<&str> {
        Self::unique_option_in(&self.args, option)
    }

    fn unique_option_in<'a>(args: &'a [String], option: &str) -> Option<&'a str> {
        let mut values = args
            .windows(2)
            .filter(|pair| pair[0] == option)
            .map(|pair| pair[1].as_str());
        let value = values.next()?;
        values.next().is_none().then_some(value)
    }

    fn mounts_match(&self, actual: &[OciMountV1]) -> bool {
        let required_match = self.required_mounts.iter().all(|required| {
            actual.iter().any(|mount| {
                mount.is_bind()
                    && mount.source == required.source
                    && mount.destination == required.destination
                    && mount.is_read_only() == required.read_only
            })
        });
        required_match
            && actual.iter().filter(|mount| mount.is_bind()).all(|mount| {
                self.required_mounts
                    .iter()
                    .any(|required| required.destination == mount.destination)
                    || mount.is_standard_kubernetes_mount()
            })
    }
}

impl OciRuntimeConfigV1 {
    fn is_cri_sandbox(&self, state_annotations: &BTreeMap<String, String>) -> bool {
        let annotation = |name: &str| {
            self.annotations
                .get(name)
                .or_else(|| state_annotations.get(name))
                .map(String::as_str)
        };
        annotation("io.kubernetes.cri.container-type") == Some("sandbox")
            && annotation("io.kubernetes.cri.podsandbox.image-name")
                .is_some_and(|value| !value.is_empty() && value.len() <= 4_096)
            && annotation("io.kubernetes.cri.sandbox-id").is_some_and(|value| {
                value.len() == 64
                    && value
                        .bytes()
                        .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
            })
            && self.process.args == ["/pause"]
            && self.process.no_new_privileges
            && !self.process.capabilities.contains("CAP_SYS_ADMIN")
            && self.root.readonly
            && self
                .mounts
                .iter()
                .filter(|mount| mount.is_bind())
                .all(OciMountV1::is_read_only)
    }

    fn is_protected(&self, state_annotations: &BTreeMap<String, String>) -> bool {
        self.annotations
            .get(PROFILE_ID_ANNOTATION)
            .or_else(|| state_annotations.get(PROFILE_ID_ANNOTATION))
            .is_some_and(|profile| !profile.is_empty())
    }

    fn is_hostile_incident(&self) -> bool {
        self.process.capabilities.contains("CAP_SYS_ADMIN")
            && self.mounts.iter().any(|mount| {
                mount.is_bind()
                    && mount.source == Path::new("/")
                    && mount.destination == Path::new("/host")
            })
    }
}

impl OciCapabilitiesV1 {
    fn contains(&self, capability: &str) -> bool {
        [&self.bounding, &self.effective, &self.permitted]
            .into_iter()
            .any(|set| set.iter().any(|entry| entry == capability))
    }

    fn is_empty(&self) -> bool {
        [
            &self.bounding,
            &self.effective,
            &self.permitted,
            &self.inheritable,
            &self.ambient,
        ]
        .into_iter()
        .all(Vec::is_empty)
    }
}

impl OciLinuxV1 {
    fn shares_host_pid_namespace(&self) -> io::Result<bool> {
        let Some(namespace) = self
            .namespaces
            .iter()
            .find(|namespace| namespace.kind == "pid")
        else {
            return Ok(true);
        };
        let Some(path) = &namespace.path else {
            return Ok(false);
        };
        if !path.is_absolute() {
            return Ok(false);
        }
        // containerd records hostPID as a path to a process that already uses
        // the host PID namespace. Compare the namespace identity, not its PID.
        let actual = std::fs::metadata(path).map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot inspect PID namespace {}: {error}", path.display()),
            )
        })?;
        let host = std::fs::metadata("/proc/1/ns/pid").map_err(|error| {
            io::Error::new(
                error.kind(),
                format!("cannot inspect the host PID namespace: {error}"),
            )
        })?;
        Ok(actual.dev() == host.dev() && actual.ino() == host.ino())
    }
}

impl OciMountV1 {
    fn is_bind(&self) -> bool {
        self.kind == "bind"
            || self
                .options
                .iter()
                .any(|option| option == "bind" || option == "rbind")
    }

    fn is_read_only(&self) -> bool {
        self.options.iter().any(|option| option == "ro")
    }

    fn is_standard_kubernetes_mount(&self) -> bool {
        matches!(
            self.destination.to_str(),
            Some(
                "/dev/shm"
                    | "/dev/termination-log"
                    | "/etc/hostname"
                    | "/etc/hosts"
                    | "/etc/resolv.conf"
                    | "/var/run/secrets/kubernetes.io/serviceaccount"
            )
        )
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::fs;

    use tempfile::TempDir;

    use super::{RetainedRuntimeDecisionV1, RetainedRuntimeGate};

    struct Fixture {
        _directory: TempDir,
        bundle: std::path::PathBuf,
        manifest: std::path::PathBuf,
    }

    impl Fixture {
        fn new() -> Result<Self, Box<dyn std::error::Error>> {
            let directory = tempfile::tempdir()?;
            let bundle = directory.path().join("bundle");
            let executable = bundle.join("rootfs/usr/local/bin/mithril-node");
            fs::create_dir_all(
                executable
                    .parent()
                    .ok_or_else(|| std::io::Error::other("test executable has no parent"))?,
            )?;
            fs::write(&executable, b"mithril-node-v1")?;
            let control = bundle.join("rootfs/usr/local/bin/mithril-control");
            fs::write(&control, b"mithril-control-v1")?;
            let manifest = directory.path().join("recovery.json");
            fs::write(
                &manifest,
                serde_json::to_vec(&serde_json::json!({
                    "version": 1,
                    "entries": [
                        {
                            "executable": "/usr/local/bin/mithril-node",
                            "args": ["/usr/local/bin/mithril-node", "--config", "/etc/mithril/node.json"],
                            "requiredMounts": [
                                {"source": "/etc/mithril/node.json", "destination": "/etc/mithril/node.json", "readOnly": true},
                                {"source": "/sys/fs/bpf", "destination": "/sys/fs/bpf", "readOnly": false}
                            ]
                        },
                        {
                            "executable": "/usr/local/bin/mithril-oci-hook",
                            "args": [
                                "/usr/local/bin/mithril-oci-hook", "install",
                                "--owner", "mithril-system/mithril",
                                "--hook-host-directory", "/usr/libexec/oci/hooks.d",
                                "--containerd-host-directory", "/var/lib/containerd",
                                "--socket", "/run/mithril/runtime-admission.sock"
                            ],
                            "requiredMounts": [
                                {"source": "/usr/libexec/oci/hooks.d", "destination": "/host-hook-bin", "readOnly": false},
                                {"source": "/var/lib/containerd", "destination": "/host-containerd", "readOnly": false},
                                {"source": "/usr/bin/ctr", "destination": "/host-ctr", "readOnly": true}
                            ]
                        }
                    ],
                    "controlEntries": [
                        {
                            "executable": "/usr/local/bin/mithril-control",
                            "args": ["/usr/local/bin/mithril-control", "--config", "/etc/mithril/control.json"],
                            "uid": 65532,
                            "gid": 65532,
                            "requiredMounts": [
                                {"destination": "/etc/mithril", "readOnly": true},
                                {"destination": "/var/lib/mithril-control", "readOnly": false},
                                {"destination": "/etc/mithril/admission-tls", "readOnly": true}
                            ]
                        }
                    ]
                }))?,
            )?;
            fs::write(bundle.join("config.json"), Self::recovery_config()?)?;
            Ok(Self {
                _directory: directory,
                bundle,
                manifest,
            })
        }

        fn recovery_config() -> Result<Vec<u8>, serde_json::Error> {
            serde_json::to_vec(&serde_json::json!({
                "process": {
                    "args": ["/usr/local/bin/mithril-node", "--config", "/etc/mithril/node.json"],
                    "capabilities": {
                        "bounding": ["CAP_SYS_ADMIN"],
                        "effective": ["CAP_SYS_ADMIN"],
                        "permitted": ["CAP_SYS_ADMIN"]
                    },
                    "noNewPrivileges": false
                },
                "root": {"path": "rootfs"},
                "mounts": [
                    {"destination": "/etc/mithril/node.json", "source": "/etc/mithril/node.json", "type": "bind", "options": ["rbind", "ro"]},
                    {"destination": "/sys/fs/bpf", "source": "/sys/fs/bpf", "type": "bind", "options": ["rbind", "rw"]},
                    {"destination": "/etc/hosts", "source": "/var/lib/kubelet/pods/uid/etc-hosts", "type": "bind", "options": ["bind", "rw"]}
                ],
                "linux": {"namespaces": [
                    {"type": "mount"},
                    {"type": "network"},
                    {"type": "ipc"},
                    {"type": "uts"}
                ]},
                "annotations": {}
            }))
        }

        fn upgraded_installer_config() -> serde_json::Value {
            serde_json::json!({
                "process": {
                    "args": [
                        "/usr/local/bin/mithril-oci-hook", "install",
                        "--owner", "mithril-system/mithril",
                        "--hook-host-directory", "/usr/libexec/oci/hooks.d",
                        "--containerd-host-directory", "/var/lib/containerd",
                        "--runtime-cli-host-path", "/usr/bin/ctr",
                        "--runtime-cli-arg", "plugins",
                        "--socket", "/run/mithril/runtime-admission.sock"
                    ],
                    "capabilities": {
                        "bounding": ["CAP_SYS_ADMIN"],
                        "effective": ["CAP_SYS_ADMIN"],
                        "permitted": ["CAP_SYS_ADMIN"]
                    },
                    "noNewPrivileges": false
                },
                "root": {"path": "rootfs"},
                "mounts": [
                    {"destination": "/host-hook-bin", "source": "/usr/libexec/oci/hooks.d", "type": "bind", "options": ["rbind", "rw"]},
                    {"destination": "/host-containerd", "source": "/var/lib/containerd", "type": "bind", "options": ["rbind", "rw"]},
                    {"destination": "/host-runtime-cli", "source": "/usr/bin/ctr", "type": "bind", "options": ["bind", "ro"]}
                ],
                "linux": {"namespaces": [
                    {"type": "mount"},
                    {"type": "network"}
                ]},
                "annotations": {}
            })
        }

        fn control_config() -> serde_json::Value {
            serde_json::json!({
                "process": {
                    "args": ["/usr/local/bin/mithril-control", "--config", "/etc/mithril/control.json"],
                    "user": {"uid": 65532, "gid": 65532, "additionalGids": [65532]},
                    "capabilities": {
                        "bounding": [],
                        "effective": [],
                        "permitted": [],
                        "inheritable": [],
                        "ambient": []
                    },
                    "noNewPrivileges": true
                },
                "root": {"path": "rootfs", "readonly": true},
                "mounts": [
                    {"destination": "/etc/mithril", "source": "/var/lib/kubelet/pods/uid/volumes/config", "type": "bind", "options": ["rbind", "ro"]},
                    {"destination": "/var/lib/mithril-control", "source": "/var/lib/kubelet/pods/uid/volumes/state", "type": "bind", "options": ["rbind", "rw"]},
                    {"destination": "/etc/mithril/admission-tls", "source": "/var/lib/kubelet/pods/uid/volumes/tls", "type": "bind", "options": ["rbind", "ro"]},
                    {"destination": "/var/run/secrets/kubernetes.io/serviceaccount", "source": "/var/lib/kubelet/pods/uid/volumes/kube-api-access", "type": "bind", "options": ["rbind", "ro"]},
                    {"destination": "/etc/hosts", "source": "/var/lib/kubelet/pods/uid/etc-hosts", "type": "bind", "options": ["bind", "rw"]}
                ],
                "linux": {"namespaces": [
                    {"type": "pid"},
                    {"type": "mount"},
                    {"type": "network"},
                    {"type": "ipc"},
                    {"type": "uts"}
                ]},
                "annotations": {}
            })
        }

        fn cri_sandbox_config() -> serde_json::Value {
            serde_json::json!({
                "process": {
                    "args": ["/pause"],
                    "capabilities": {
                        "bounding": ["CAP_CHOWN", "CAP_NET_RAW"],
                        "effective": ["CAP_CHOWN", "CAP_NET_RAW"],
                        "permitted": ["CAP_CHOWN", "CAP_NET_RAW"]
                    },
                    "noNewPrivileges": true
                },
                "root": {"path": "rootfs", "readonly": true},
                "mounts": [
                    {"destination": "/etc/resolv.conf", "source": "/var/lib/kubelet/pods/uid/resolv.conf", "type": "bind", "options": ["rbind", "ro"]}
                ],
                "linux": {"namespaces": [
                    {"type": "pid"},
                    {"type": "mount"},
                    {"type": "network"}
                ]},
                "annotations": {
                    "io.kubernetes.cri.container-type": "sandbox",
                    "io.kubernetes.cri.podsandbox.image-name": "registry.k8s.io/pause:3.10",
                    "io.kubernetes.cri.sandbox-id": "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                }
            })
        }

        fn gate(&self) -> Result<RetainedRuntimeGate, Box<dyn std::error::Error>> {
            Ok(RetainedRuntimeGate::open(&self.manifest)?)
        }
    }

    #[test]
    fn unavailable_gate_allows_version_changed_node_with_exact_oci_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::AllowRecovery
        );

        fs::write(
            fixture.bundle.join("rootfs/usr/local/bin/mithril-node"),
            b"mithril-node-v2",
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::AllowRecovery
        );
        Ok(())
    }

    #[test]
    fn unavailable_gate_allows_version_changed_control_with_exact_oci_shape(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&Fixture::control_config())?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::AllowRecovery
        );

        fs::write(
            fixture.bundle.join("rootfs/usr/local/bin/mithril-control"),
            b"mithril-control-v2",
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::AllowRecovery
        );

        let mut changed_group = Fixture::control_config();
        changed_group["process"]["user"]["additionalGids"] = serde_json::json!([65531]);
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&changed_group)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::DenyUnavailable
        );

        let mut privileged = Fixture::control_config();
        privileged["process"]["capabilities"]["effective"] = serde_json::json!(["CAP_SYS_ADMIN"]);
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&privileged)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::DenyUnavailable
        );

        let mut extra_mount = Fixture::control_config();
        extra_mount["mounts"]
            .as_array_mut()
            .ok_or_else(|| std::io::Error::other("control test mounts are not an array"))?
            .push(serde_json::json!({
                "destination": "/unexpected",
                "source": "/tmp",
                "type": "bind",
                "options": ["rbind", "ro"]
            }));
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&extra_mount)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::DenyUnavailable
        );
        Ok(())
    }

    #[test]
    fn unavailable_gate_allows_the_retained_owner_to_install_a_new_mithril_version(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&Fixture::upgraded_installer_config())?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::AllowInstaller
        );

        let mut wrong_owner = Fixture::upgraded_installer_config();
        wrong_owner["process"]["args"][3] = serde_json::json!("attacker/other");
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&wrong_owner)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::DenyUnavailable
        );
        Ok(())
    }

    #[test]
    fn unavailable_gate_allows_only_an_inert_cri_sandbox() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        let mut config = Fixture::cri_sandbox_config();
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&config)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::AllowSandbox
        );

        config["process"]["args"] = serde_json::json!(["/bin/sh", "-c", "true"]);
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&config)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::DenyUnavailable
        );
        Ok(())
    }

    #[test]
    fn changed_recovery_mount_is_not_bootstrap_authority() -> Result<(), Box<dyn std::error::Error>>
    {
        let fixture = Fixture::new()?;
        let mut config: serde_json::Value =
            serde_json::from_slice(&fs::read(fixture.bundle.join("config.json"))?)?;
        config["mounts"][0]["source"] = serde_json::json!("/tmp/attacker.json");
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&config)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), false)?,
            RetainedRuntimeDecisionV1::DenyUnavailable
        );
        Ok(())
    }

    #[test]
    fn exact_hostile_shape_denies_before_endpoint_or_metadata(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        let hostile = serde_json::json!({
            "process": {
                "args": ["/bin/sh", "-c", "cat /host/etc/shadow"],
                "capabilities": {"effective": ["CAP_SYS_ADMIN"]}
            },
            "root": {"path": "rootfs"},
            "mounts": [{"destination": "/host", "source": "/", "type": "bind", "options": ["rbind", "rw"]}],
            "linux": {"namespaces": [
                {"type": "pid", "path": "/proc/1/ns/pid"},
                {"type": "mount"},
                {"type": "network"}
            ]},
            "annotations": {"mithril.erebor.dev/profile-id": "forged"}
        });
        fs::write(
            fixture.bundle.join("config.json"),
            serde_json::to_vec(&hostile)?,
        )?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), true)?,
            RetainedRuntimeDecisionV1::DenyHostile
        );
        Ok(())
    }

    #[test]
    fn healthy_gate_routes_only_protected_containers_to_node_admission(
    ) -> Result<(), Box<dyn std::error::Error>> {
        let fixture = Fixture::new()?;
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &BTreeMap::new(), true)?,
            RetainedRuntimeDecisionV1::AllowHealthy
        );
        let annotations = BTreeMap::from([(
            "mithril.erebor.dev/profile-id".to_owned(),
            "profile".to_owned(),
        )]);
        assert_eq!(
            fixture
                .gate()?
                .decide(&fixture.bundle, &annotations, true)?,
            RetainedRuntimeDecisionV1::AdmitProtected
        );
        Ok(())
    }
}
