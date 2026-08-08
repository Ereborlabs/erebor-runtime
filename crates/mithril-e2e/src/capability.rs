use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use erebor_interceptor_abi::C_HEADER_V1;
use serde::Serialize;
use snafu::{ensure, ResultExt as _};

use crate::error::{CommandSnafu, IoSnafu};
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

pub struct PlatformProbe;

impl PlatformProbe {
    pub fn inspect() -> Result<PlatformProbeV1> {
        let kernel_release = command_text(Command::new("uname").arg("-r"), "uname")?;
        let active_lsm_order = fs::read_to_string("/sys/kernel/security/lsm")
            .context(IoSnafu {
                path: PathBuf::from("/sys/kernel/security/lsm"),
            })?
            .trim()
            .to_owned();
        let btf_path = Path::new("/sys/kernel/btf/vmlinux");
        let btf_sha256 = if btf_path.is_file() {
            Some(
                DigestV1::of(fs::read(btf_path).context(IoSnafu {
                    path: btf_path.to_path_buf(),
                })?)
                .to_hex(),
            )
        } else {
            None
        };
        let mounts = fs::read_to_string("/proc/mounts").context(IoSnafu {
            path: PathBuf::from("/proc/mounts"),
        })?;
        let bpf_lsm_active = active_lsm_order.split(',').any(|lsm| lsm == "bpf");
        let cgroup_v2 = mounts
            .lines()
            .any(|line| line.split_whitespace().nth(2) == Some("cgroup2"));
        let prerequisite_result = if bpf_lsm_active && btf_sha256.is_some() && cgroup_v2 {
            "READY_FOR_PRIVILEGED_LOAD"
        } else {
            "MISSING_BPF_LSM_BTF_OR_CGROUP_V2"
        };
        Ok(PlatformProbeV1 {
            kernel_release,
            architecture: std::env::consts::ARCH.to_owned(),
            active_lsm_order,
            bpf_lsm_active,
            btf_sha256,
            cgroup_v2,
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

impl BpfPrototypeCompiler {
    #[must_use]
    pub fn new(repo_root: impl Into<PathBuf>) -> Self {
        Self {
            repo_root: repo_root.into(),
        }
    }

    pub fn compile(&self, output_directory: &Path) -> Result<CompileRecordV1> {
        fs::create_dir_all(output_directory).context(IoSnafu {
            path: output_directory.to_path_buf(),
        })?;
        let repo_root = fs::canonicalize(&self.repo_root).context(IoSnafu {
            path: self.repo_root.clone(),
        })?;
        let output_directory = fs::canonicalize(output_directory).context(IoSnafu {
            path: output_directory.to_path_buf(),
        })?;
        let source = repo_root.join("bpf/erebor-interceptor/phase0/feasibility.bpf.c");
        let source_bytes = fs::read(&source).context(IoSnafu {
            path: source.clone(),
        })?;
        let vmlinux = output_directory.join("vmlinux.h");
        let btf_output = Command::new("bpftool")
            .args([
                "btf",
                "dump",
                "file",
                "/sys/kernel/btf/vmlinux",
                "format",
                "c",
            ])
            .output()
            .context(IoSnafu {
                path: PathBuf::from("bpftool"),
            })?;
        ensure_success("bpftool btf dump", &btf_output)?;
        fs::write(&vmlinux, btf_output.stdout).context(IoSnafu {
            path: vmlinux.clone(),
        })?;
        let abi_header = output_directory.join("erebor_interceptor_abi_v1.h");
        fs::write(&abi_header, C_HEADER_V1).context(IoSnafu {
            path: abi_header.clone(),
        })?;

        let kernel_release = command_text(Command::new("uname").arg("-r"), "uname")?;
        let bpf_headers = PathBuf::from(format!(
            "/lib/modules/{kernel_release}/build/tools/bpf/resolve_btfids/libbpf/include"
        ));
        let object = output_directory.join("phase0-feasibility.bpf.o");
        let target_define = match std::env::consts::ARCH {
            "x86_64" => "-D__TARGET_ARCH_x86",
            "aarch64" => "-D__TARGET_ARCH_arm64",
            other => {
                return CommandSnafu {
                    program: "clang".to_owned(),
                    reason: format!("unsupported BPF target architecture `{other}`"),
                }
                .fail();
            }
        };
        let compile_output = Command::new("clang")
            .args(["-g", "-O2", "-target", "bpfel", target_define, "-I"])
            .arg(&output_directory)
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

fn command_text(command: &mut Command, program: &str) -> Result<String> {
    let output = command.output().context(IoSnafu {
        path: PathBuf::from(program),
    })?;
    ensure_success(program, &output)?;
    Ok(String::from_utf8_lossy(&output.stdout).trim().to_owned())
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

    use super::{BpfPrototypeCompiler, PlatformProbe};
    use crate::error::IoSnafu;

    #[test]
    fn phase0_owned_core_object_compiles_against_the_live_btf() -> crate::Result<()> {
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
        assert_eq!(first.source_sha256.len(), 64);
        assert_eq!(first.object_sha256, second.object_sha256);
        Ok(())
    }

    #[test]
    fn platform_probe_reports_bpf_lsm_as_a_measured_prerequisite() -> crate::Result<()> {
        let probe = PlatformProbe::inspect()?;
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
