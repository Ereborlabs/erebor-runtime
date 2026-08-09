use std::fs;
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::{KernelHost, KernelHostConfig, KernelHostOwner};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{InterceptorSnafu, InvalidInputSnafu, IoSnafu};
use crate::{DigestV1, Result};

const FILE_PROBE_TARGETS: &str = "file_probe_targets";
const RUNTIME_BTF: &str = "/sys/kernel/btf/vmlinux";
const PHASE0_BOOT_ID: &str = "phase0-qualification-boot";

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BpfMapLayoutV1 {
    pub name: String,
    pub map_type: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BpfObjectLayoutV1 {
    pub maps: Vec<BpfMapLayoutV1>,
    pub lsm_programs: Vec<String>,
    pub other_programs: Vec<String>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct BpfLinkRecordV1 {
    pub program: String,
    pub link_id: u32,
    pub program_id: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PhysicalFileOpenProbeV1 {
    pub object_layout: BpfObjectLayoutV1,
    pub links: Vec<BpfLinkRecordV1>,
    pub target: PathBuf,
    pub target_inode: u64,
    pub allowed_before_target_install: bool,
    pub denied_after_target_install: bool,
    pub allowed_after_target_clear: bool,
}

pub struct BpfPhase0Loader {
    object_path: PathBuf,
}

impl BpfPhase0Loader {
    #[must_use]
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
        }
    }

    pub fn inspect(&self) -> Result<BpfObjectLayoutV1> {
        let owner = self.owner()?;
        let layout = owner.inspect().context(InterceptorSnafu)?;
        let mut lsm_programs = Vec::new();
        let mut other_programs = Vec::new();
        for program in layout.programs {
            if program.section.starts_with("lsm/") {
                lsm_programs.push(program.name);
            } else {
                other_programs.push(program.name);
            }
        }
        let layout = BpfObjectLayoutV1 {
            maps: layout
                .maps
                .into_iter()
                .map(|map| BpfMapLayoutV1 {
                    name: map.name,
                    map_type: map.map_type,
                    key_size: map.key_size,
                    value_size: map.value_size,
                    max_entries: map.max_entries,
                })
                .collect(),
            lsm_programs,
            other_programs,
        };
        Self::validate_layout(&self.object_path, &layout)?;
        Ok(layout)
    }

    pub fn attach(&self) -> Result<KernelHost> {
        self.owner()?.start().context(InterceptorSnafu)
    }

    pub fn run_file_open_probe(&self, output_directory: &Path) -> Result<PhysicalFileOpenProbeV1> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory,
        })?;
        let target = output_directory.join("phase0-file-open-deny-target");
        fs::write(&target, b"phase 0 physical BPF LSM probe\n")
            .context(IoSnafu { path: &target })?;
        let target_inode = fs::metadata(&target)
            .context(IoSnafu { path: &target })?
            .ino();
        let object_layout = self.inspect()?;
        let attachment = self.attach()?;
        let allowed_before_target_install = File::open(&target).is_ok();
        ensure!(
            allowed_before_target_install,
            InvalidInputSnafu {
                path: &target,
                reason: "the file-open control failed before the deny target was installed",
            }
        );
        Self::update_file_open_target(&attachment, target_inode)?;
        let denied_after_target_install = matches!(
            File::open(&target),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
        );
        ensure!(
            denied_after_target_install,
            InvalidInputSnafu {
                path: &target,
                reason: "the attached file_open hook did not return EACCES for its target",
            }
        );
        Self::update_file_open_target(&attachment, 0)?;
        let allowed_after_target_clear = File::open(&target).is_ok();
        ensure!(
            allowed_after_target_clear,
            InvalidInputSnafu {
                path: &target,
                reason: "the file-open control did not recover after clearing the deny target",
            }
        );
        let links = attachment
            .manifest()
            .links
            .iter()
            .map(|link| BpfLinkRecordV1 {
                program: link.program.clone(),
                link_id: link.link_id,
                program_id: link.program_id,
            })
            .collect();
        Ok(PhysicalFileOpenProbeV1 {
            object_layout,
            links,
            target,
            target_inode,
            allowed_before_target_install,
            denied_after_target_install,
            allowed_after_target_clear,
        })
    }

    fn owner(&self) -> Result<KernelHostOwner> {
        let bytes = fs::read(&self.object_path).context(IoSnafu {
            path: &self.object_path,
        })?;
        let digest = DigestV1::of(bytes).to_hex();
        Ok(KernelHostOwner::new(KernelHostConfig::qualification(
            &self.object_path,
            digest,
            RUNTIME_BTF,
            self.object_path.with_extension("owner.lock"),
            None,
            PHASE0_BOOT_ID,
            1,
        )))
    }

    fn validate_layout(object_path: &Path, layout: &BpfObjectLayoutV1) -> Result<()> {
        ensure!(
            layout.maps.iter().any(|map| {
                map.name == FILE_PROBE_TARGETS
                    && map.map_type == "Array"
                    && map.key_size == 4
                    && map.value_size == 8
                    && map.max_entries == 1
            }),
            InvalidInputSnafu {
                path: object_path,
                reason: "file_probe_targets must remain a one-entry u32-to-u64 array",
            }
        );
        ensure!(
            layout
                .lsm_programs
                .iter()
                .any(|program| program == "qualification_file_open"),
            InvalidInputSnafu {
                path: object_path,
                reason: "the feasibility object has no qualification_file_open LSM program",
            }
        );
        Ok(())
    }

    fn update_file_open_target(host: &KernelHost, inode: u64) -> Result<()> {
        let key = 0_u32.to_le_bytes();
        let value = inode.to_le_bytes();
        host.update_map(FILE_PROBE_TARGETS, &key, &value)
            .context(InterceptorSnafu)?;
        let readback = host
            .lookup_map(FILE_PROBE_TARGETS, &key)
            .context(InterceptorSnafu)?;
        ensure!(
            readback.as_deref() == Some(value.as_slice()),
            InvalidInputSnafu {
                path: PathBuf::from(FILE_PROBE_TARGETS),
                reason: "file-open probe target did not read back exactly",
            }
        );
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use snafu::ResultExt as _;

    use erebor_interceptor::{Error as InterceptorError, KernelHostConfig, KernelHostOwner};

    use super::{BpfPhase0Loader, RUNTIME_BTF};
    use crate::capability::BpfPrototypeCompiler;
    use crate::error::IoSnafu;

    #[test]
    fn direct_libbpf_inspection_validates_the_owned_feasibility_object() -> crate::Result<()> {
        let output = tempfile::tempdir().context(IoSnafu {
            path: PathBuf::from("temporary libbpf object inspection directory"),
        })?;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let object = BpfPrototypeCompiler::new(root).compile(output.path())?;
        let layout = BpfPhase0Loader::new(object.object_path).inspect()?;
        assert!(layout
            .lsm_programs
            .iter()
            .any(|program| program == "qualification_file_open"));
        assert!(layout.maps.iter().any(|map| {
            map.name == "file_probe_targets"
                && map.map_type == "Array"
                && map.key_size == 4
                && map.value_size == 8
                && map.max_entries == 1
        }));
        Ok(())
    }

    #[test]
    fn changed_digest_and_stale_pin_root_fail_before_privileged_load() -> crate::Result<()> {
        let output = tempfile::tempdir().context(IoSnafu {
            path: PathBuf::from("temporary stale pin qualification directory"),
        })?;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let object = BpfPrototypeCompiler::new(root).compile(output.path())?;
        let wrong_digest = KernelHostOwner::new(KernelHostConfig::qualification(
            &object.object_path,
            "0".repeat(64),
            RUNTIME_BTF,
            output.path().join("wrong-digest.lock"),
            None,
            "qualification-boot",
            1,
        ));
        assert!(matches!(
            wrong_digest.start(),
            Err(InterceptorError::ManifestMismatch { .. })
        ));

        let pin_root = output.path().join("pins");
        fs::create_dir(&pin_root).context(IoSnafu {
            path: pin_root.clone(),
        })?;
        fs::write(pin_root.join("stale"), b"stale").context(IoSnafu {
            path: pin_root.clone(),
        })?;
        let stale = KernelHostOwner::new(KernelHostConfig::qualification(
            &object.object_path,
            &object.object_sha256,
            RUNTIME_BTF,
            output.path().join("stale.lock"),
            Some(pin_root),
            "qualification-boot",
            1,
        ));
        assert!(matches!(
            stale.start(),
            Err(InterceptorError::StalePinRoot { .. })
        ));
        Ok(())
    }
}
