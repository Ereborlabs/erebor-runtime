use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use erebor_interceptor::KernelPlatformProbe;
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{CommandSnafu, InterceptorSnafu, IoSnafu};
use crate::{DigestV1, Result};

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct PlatformProbeV1 {
    pub kernel_release: String,
    pub architecture: String,
    pub active_lsm_order: String,
    pub bpf_lsm_active: bool,
    pub btf_sha256: Option<String>,
    pub cgroup_v2: bool,
    pub prerequisite_result: String,
}

impl PlatformProbeV1 {
    pub fn inspect() -> Result<PlatformProbeV1> {
        let platform = KernelPlatformProbe::inspect(Path::new("/sys/kernel/btf/vmlinux"))
            .context(InterceptorSnafu)?;
        let prerequisite_result = if platform.bpf_lsm_active
            && platform.runtime_btf_sha256.is_some()
            && platform.cgroup_v2
        {
            "READY_FOR_PRIVILEGED_LOAD"
        } else {
            "MISSING_BPF_LSM_BTF_OR_CGROUP_V2"
        };
        Ok(PlatformProbeV1 {
            kernel_release: platform.kernel_release,
            architecture: platform.architecture,
            active_lsm_order: platform.active_lsm_order,
            bpf_lsm_active: platform.bpf_lsm_active,
            btf_sha256: platform.runtime_btf_sha256,
            cgroup_v2: platform.cgroup_v2,
            prerequisite_result: prerequisite_result.to_owned(),
        })
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct CompileRecordV1 {
    pub source_sha256: String,
    pub object_sha256: String,
    pub object_path: PathBuf,
    pub clang_stderr: String,
}

pub struct BpfPrototypeCompiler {
    repo_root: PathBuf,
}

#[derive(Clone, Copy)]
enum BpfTargetArchitecture {
    X86,
    Arm64,
    Arm,
    Riscv,
}

impl BpfTargetArchitecture {
    #[cfg(test)]
    const ALL: [Self; 4] = [Self::X86, Self::Arm64, Self::Arm, Self::Riscv];

    fn for_host() -> Result<Self> {
        match std::env::consts::ARCH {
            "x86_64" => Ok(Self::X86),
            "aarch64" => Ok(Self::Arm64),
            "arm" => Ok(Self::Arm),
            "riscv64" => Ok(Self::Riscv),
            other => CommandSnafu {
                program: "clang".to_owned(),
                reason: format!("no checked-in vmlinux header for `{other}`"),
            }
            .fail(),
        }
    }

    const fn clang_define(self) -> &'static str {
        match self {
            Self::X86 => "-D__TARGET_ARCH_x86",
            Self::Arm64 => "-D__TARGET_ARCH_arm64",
            Self::Arm => "-D__TARGET_ARCH_arm",
            Self::Riscv => "-D__TARGET_ARCH_riscv",
        }
    }
}

impl BpfPrototypeCompiler {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn compile(&self, output_directory: &Path) -> Result<CompileRecordV1> {
        self.compile_for(output_directory, BpfTargetArchitecture::for_host()?)
    }

    fn compile_for(
        &self,
        output_directory: &Path,
        target: BpfTargetArchitecture,
    ) -> Result<CompileRecordV1> {
        self.compile_source_for(
            output_directory,
            target,
            "qualification/feasibility.bpf.c",
            "feasibility.bpf.o",
        )
    }

    #[cfg(test)]
    fn compile_identity_for(
        &self,
        output_directory: &Path,
        target: BpfTargetArchitecture,
    ) -> Result<CompileRecordV1> {
        self.compile_source_for(
            output_directory,
            target,
            "programs/identity.bpf.c",
            "erebor-interceptor.bpf.o",
        )
    }

    fn compile_source_for(
        &self,
        output_directory: &Path,
        target: BpfTargetArchitecture,
        relative_source: &str,
        object_name: &str,
    ) -> Result<CompileRecordV1> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory.to_path_buf(),
        })?;
        let repo_root = fs::canonicalize(&self.repo_root).context(IoSnafu {
            path: self.repo_root.clone(),
        })?;
        let output_directory = fs::canonicalize(output_directory).context(IoSnafu {
            path: output_directory.to_path_buf(),
        })?;
        let bpf_root = repo_root.join("bpf/erebor-interceptor");
        let source = bpf_root.join(relative_source);
        let source_bytes = fs::read(&source).context(IoSnafu {
            path: source.clone(),
        })?;
        let kernel_release_path = Path::new("/proc/sys/kernel/osrelease");
        let kernel_release = fs::read_to_string(kernel_release_path)
            .context(IoSnafu {
                path: kernel_release_path.to_path_buf(),
            })?
            .trim()
            .to_owned();
        let interceptor_headers = bpf_root.join("include");
        let interceptor_programs = bpf_root.join("programs");
        let bpf_headers = PathBuf::from(format!(
            "/lib/modules/{kernel_release}/build/tools/bpf/resolve_btfids/libbpf/include"
        ));
        let object = output_directory.join(object_name);
        let compile_output = Command::new("clang")
            .args([
                "-g",
                "-O2",
                "-target",
                "bpfel",
                target.clang_define(),
                "-D__BPF__",
                "-Wall",
                "-Werror",
                "-I",
            ])
            .arg(&interceptor_headers)
            .arg("-I")
            .arg(&interceptor_programs)
            .arg(format!("-fdebug-prefix-map={}=/src", repo_root.display()))
            .arg(format!(
                "-fdebug-prefix-map={}=/build",
                output_directory.display()
            ))
            .arg("-fdebug-compilation-dir=/src")
            .arg("-I")
            .arg(&bpf_headers)
            .arg("-c")
            .arg(&source)
            .arg("-o")
            .arg(&object)
            .output()
            .context(IoSnafu {
                path: PathBuf::from("clang"),
            })?;
        ensure_success("clang BPF compile", &compile_output)?;
        let object_bytes = fs::read(&object).context(IoSnafu {
            path: object.clone(),
        })?;
        Ok(CompileRecordV1 {
            source_sha256: DigestV1::of(source_bytes).to_hex(),
            object_sha256: DigestV1::of(object_bytes).to_hex(),
            object_path: object,
            clang_stderr: String::from_utf8_lossy(&compile_output.stderr).into_owned(),
        })
    }
}

fn ensure_success(program: &str, output: &Output) -> Result<()> {
    ensure!(
        output.status.success(),
        CommandSnafu {
            program: program.to_owned(),
            reason: String::from_utf8_lossy(&output.stderr).into_owned()
        }
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use snafu::ResultExt as _;

    use super::{BpfPrototypeCompiler, BpfTargetArchitecture, PlatformProbeV1};
    use crate::error::IoSnafu;

    #[test]
    fn qualification_object_compiles_against_the_checked_in_vmlinux_header() -> crate::Result<()> {
        let first_output = tempfile::tempdir().context(IoSnafu {
            path: PathBuf::from("temporary BPF build directory"),
        })?;
        let second_output = tempfile::tempdir().context(IoSnafu {
            path: PathBuf::from("second temporary BPF build directory"),
        })?;
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let compiler = BpfPrototypeCompiler::new(root);
        let first = compiler.compile(first_output.path())?;
        let second = compiler.compile(second_output.path())?;
        assert!(first.object_path.is_file());
        assert!(!first_output.path().join("vmlinux.h").exists());
        assert!(!first_output
            .path()
            .join("erebor_interceptor_abi_v1.h")
            .exists());
        assert_eq!(first.source_sha256.len(), 64);
        assert_eq!(first.object_sha256, second.object_sha256);
        Ok(())
    }

    #[test]
    fn every_checked_in_vmlinux_header_compiles_the_feasibility_object() -> crate::Result<()> {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let compiler = BpfPrototypeCompiler::new(root);
        for target in BpfTargetArchitecture::ALL {
            let output = tempfile::tempdir().context(IoSnafu {
                path: PathBuf::from("temporary cross-architecture BPF build directory"),
            })?;
            assert!(compiler
                .compile_for(output.path(), target)?
                .object_path
                .is_file());
        }
        Ok(())
    }

    #[test]
    fn every_checked_in_vmlinux_header_compiles_the_production_identity_object() -> crate::Result<()>
    {
        let root = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..");
        let compiler = BpfPrototypeCompiler::new(root);
        for target in BpfTargetArchitecture::ALL {
            let output = tempfile::tempdir().context(IoSnafu {
                path: PathBuf::from("temporary production BPF build directory"),
            })?;
            assert!(compiler
                .compile_identity_for(output.path(), target)?
                .object_path
                .is_file());
        }
        Ok(())
    }

    #[test]
    fn platform_probe_reports_bpf_lsm_as_a_measured_prerequisite() -> crate::Result<()> {
        let probe = PlatformProbeV1::inspect()?;
        assert!(!probe.kernel_release.is_empty());
        assert!(probe.btf_sha256.is_some());
        assert!(probe.cgroup_v2);
        assert_eq!(
            probe.prerequisite_result == "READY_FOR_PRIVILEGED_LOAD",
            probe.bpf_lsm_active
        );
        Ok(())
    }
}
