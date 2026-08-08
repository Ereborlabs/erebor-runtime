use std::ffi::OsStr;
use std::fs;
use std::fs::File;
use std::os::unix::fs::MetadataExt as _;
use std::path::{Path, PathBuf};

use libbpf_rs::{Link, MapCore as _, MapFlags, Object, ObjectBuilder, OpenObject, ProgramType};
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{InvalidInputSnafu, IoSnafu, LibbpfSnafu};
use crate::Result;

const FILE_PROBE_TARGETS: &str = "file_probe_targets";
const RUNTIME_BTF: &str = "/sys/kernel/btf/vmlinux";

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

pub struct BpfPhase0Attachment {
    object_path: PathBuf,
    object: Object,
    links: Vec<Link>,
    records: Vec<BpfLinkRecordV1>,
}

impl BpfPhase0Loader {
    #[must_use]
    pub fn new(object_path: impl Into<PathBuf>) -> Self {
        Self {
            object_path: object_path.into(),
        }
    }

    pub fn inspect(&self) -> Result<BpfObjectLayoutV1> {
        let open_object = self.open()?;
        Self::describe_open_object(&self.object_path, &open_object)
    }

    pub fn attach(&self) -> Result<BpfPhase0Attachment> {
        let runtime_btf = Path::new(RUNTIME_BTF);
        ensure!(
            runtime_btf.is_file(),
            InvalidInputSnafu {
                path: runtime_btf.to_path_buf(),
                reason: "the running kernel does not expose vmlinux BTF".to_owned(),
            }
        );
        let mut builder = ObjectBuilder::default();
        builder.btf_custom_path(runtime_btf).context(LibbpfSnafu {
            action: "set runtime BTF".to_owned(),
            path: runtime_btf.to_path_buf(),
        })?;
        let open_object = builder.open_file(&self.object_path).context(LibbpfSnafu {
            action: "open BPF object".to_owned(),
            path: self.object_path.clone(),
        })?;
        let layout = Self::describe_open_object(&self.object_path, &open_object)?;
        let object = open_object.load().context(LibbpfSnafu {
            action: "load BPF object".to_owned(),
            path: self.object_path.clone(),
        })?;

        let mut links = Vec::with_capacity(layout.lsm_programs.len());
        let mut records = Vec::with_capacity(layout.lsm_programs.len());
        for program in object.progs_mut() {
            if !program.section().to_string_lossy().starts_with("lsm/") {
                continue;
            }
            let program_name = program.name().to_string_lossy().into_owned();
            ensure!(
                program.prog_type() == ProgramType::Lsm,
                InvalidInputSnafu {
                    path: self.object_path.clone(),
                    reason: format!(
                        "`{program_name}` has an LSM section but not the LSM program type"
                    ),
                }
            );
            let link = program.attach_lsm().context(LibbpfSnafu {
                action: format!("attach LSM program `{program_name}`"),
                path: self.object_path.clone(),
            })?;
            let link_info = link.info().context(LibbpfSnafu {
                action: format!("read back LSM link `{program_name}`"),
                path: self.object_path.clone(),
            })?;
            ensure!(
                link_info.id != 0 && link_info.prog_id != 0,
                InvalidInputSnafu {
                    path: self.object_path.clone(),
                    reason: format!("`{program_name}` attached without a readable link/program ID"),
                }
            );
            records.push(BpfLinkRecordV1 {
                program: program_name,
                link_id: link_info.id,
                program_id: link_info.prog_id,
            });
            links.push(link);
        }
        ensure!(
            !links.is_empty(),
            InvalidInputSnafu {
                path: self.object_path.clone(),
                reason: "the BPF object has no attached LSM programs".to_owned(),
            }
        );
        Ok(BpfPhase0Attachment {
            object_path: self.object_path.clone(),
            object,
            links,
            records,
        })
    }

    pub fn run_file_open_probe(&self, output_directory: &Path) -> Result<PhysicalFileOpenProbeV1> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory.to_path_buf(),
        })?;
        let target = output_directory.join("phase0-file-open-deny-target");
        fs::write(&target, b"phase 0 physical BPF LSM probe\n").context(IoSnafu {
            path: target.clone(),
        })?;
        let target_inode = fs::metadata(&target)
            .context(IoSnafu {
                path: target.clone(),
            })?
            .ino();
        let object_layout = self.inspect()?;
        let attachment = self.attach()?;
        let allowed_before_target_install = File::open(&target).is_ok();
        ensure!(
            allowed_before_target_install,
            InvalidInputSnafu {
                path: target.clone(),
                reason: "the file-open control failed before the deny target was installed"
                    .to_owned(),
            }
        );
        attachment.set_file_open_deny(target_inode)?;
        let denied_after_target_install = matches!(
            File::open(&target),
            Err(error) if error.kind() == std::io::ErrorKind::PermissionDenied
        );
        ensure!(
            denied_after_target_install,
            InvalidInputSnafu {
                path: target.clone(),
                reason: "the attached file_open hook did not return EACCES for its target"
                    .to_owned(),
            }
        );
        attachment.clear_file_open_deny()?;
        let allowed_after_target_clear = File::open(&target).is_ok();
        ensure!(
            allowed_after_target_clear,
            InvalidInputSnafu {
                path: target.clone(),
                reason: "the file-open control did not recover after clearing the deny target"
                    .to_owned(),
            }
        );
        Ok(PhysicalFileOpenProbeV1 {
            object_layout,
            links: attachment.records.clone(),
            target,
            target_inode,
            allowed_before_target_install,
            denied_after_target_install,
            allowed_after_target_clear,
        })
    }

    fn open(&self) -> Result<OpenObject> {
        ObjectBuilder::default()
            .open_file(&self.object_path)
            .context(LibbpfSnafu {
                action: "inspect BPF object".to_owned(),
                path: self.object_path.clone(),
            })
    }

    fn describe_open_object(object_path: &Path, object: &OpenObject) -> Result<BpfObjectLayoutV1> {
        let maps = object
            .maps()
            .map(|map| BpfMapLayoutV1 {
                name: map.name().to_string_lossy().into_owned(),
                map_type: format!("{:?}", map.map_type()),
                key_size: map.key_size(),
                value_size: map.value_size(),
                max_entries: map.max_entries(),
            })
            .collect::<Vec<_>>();
        let mut lsm_programs = Vec::new();
        let mut other_programs = Vec::new();
        for program in object.progs() {
            let name = program.name().to_string_lossy().into_owned();
            if program.section().to_string_lossy().starts_with("lsm/") {
                ensure!(
                    program.prog_type() == ProgramType::Lsm,
                    InvalidInputSnafu {
                        path: object_path.to_path_buf(),
                        reason: format!("`{name}` has an LSM section but not the LSM program type"),
                    }
                );
                lsm_programs.push(name);
            } else {
                other_programs.push(name);
            }
        }
        let layout = BpfObjectLayoutV1 {
            maps,
            lsm_programs,
            other_programs,
        };
        Self::validate_layout(object_path, &layout)?;
        Ok(layout)
    }

    fn validate_layout(object_path: &Path, layout: &BpfObjectLayoutV1) -> Result<()> {
        let file_targets = layout
            .maps
            .iter()
            .find(|map| map.name == FILE_PROBE_TARGETS);
        ensure!(
            matches!(
                file_targets,
                Some(BpfMapLayoutV1 {
                    map_type,
                    key_size: 4,
                    value_size: 8,
                    max_entries: 1,
                    ..
                }) if map_type == "Array"
            ),
            InvalidInputSnafu {
                path: object_path.to_path_buf(),
                reason: "file_probe_targets must remain a one-entry u32-to-u64 array".to_owned(),
            }
        );
        ensure!(
            layout
                .lsm_programs
                .iter()
                .any(|program| program == "phase0_file_open"),
            InvalidInputSnafu {
                path: object_path.to_path_buf(),
                reason: "the feasibility object has no phase0_file_open LSM program".to_owned(),
            }
        );
        Ok(())
    }
}

impl BpfPhase0Attachment {
    fn set_file_open_deny(&self, inode: u64) -> Result<()> {
        self.update_file_open_target(inode)
    }

    fn clear_file_open_deny(&self) -> Result<()> {
        self.update_file_open_target(0)
    }

    fn update_file_open_target(&self, inode: u64) -> Result<()> {
        let map = self
            .object
            .maps()
            .find(|map| map.name() == OsStr::new(FILE_PROBE_TARGETS))
            .ok_or_else(|| {
                InvalidInputSnafu {
                    path: self.object_path.clone(),
                    reason: "loaded object has no file_probe_targets map".to_owned(),
                }
                .build()
            })?;
        let key = 0_u32.to_le_bytes();
        let value = inode.to_le_bytes();
        map.update(&key, &value, MapFlags::ANY)
            .context(LibbpfSnafu {
                action: "update file-open probe target".to_owned(),
                path: self.object_path.clone(),
            })?;
        let readback = map.lookup(&key, MapFlags::ANY).context(LibbpfSnafu {
            action: "read back file-open probe target".to_owned(),
            path: self.object_path.clone(),
        })?;
        ensure!(
            readback.as_deref() == Some(value.as_slice()),
            InvalidInputSnafu {
                path: self.object_path.clone(),
                reason: "file-open probe target did not read back exactly".to_owned(),
            }
        );
        Ok(())
    }
}

impl Drop for BpfPhase0Attachment {
    fn drop(&mut self) {
        self.links.clear();
    }
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use snafu::ResultExt as _;

    use super::BpfPhase0Loader;
    use crate::error::IoSnafu;
    use crate::BpfPrototypeCompiler;

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
            .any(|program| program == "phase0_file_open"));
        assert!(layout.maps.iter().any(|map| {
            map.name == "file_probe_targets"
                && map.map_type == "Array"
                && map.key_size == 4
                && map.value_size == 8
                && map.max_entries == 1
        }));
        Ok(())
    }
}
