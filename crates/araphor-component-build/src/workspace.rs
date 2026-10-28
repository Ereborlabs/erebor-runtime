use std::path::{Path, PathBuf};
use std::process::Command;

use snafu::ResultExt as _;

use crate::{error, ComponentBuilder, Result};

const TARGET: &str = "wasm32-unknown-unknown";
const GUESTS: &[(&str, &str, &str)] = &[
    (
        "araphor-discovery-component",
        "crates/araphor-analysis-builtins/components/discovery",
        "discovery.wasm",
    ),
    (
        "araphor-process-component",
        "crates/araphor-analysis-builtins/components/process",
        "process.wasm",
    ),
    (
        "araphor-credentials-component",
        "crates/araphor-analysis-builtins/components/credentials",
        "credentials.wasm",
    ),
    (
        "araphor-kubernetes-component",
        "crates/araphor-analysis-builtins/components/kubernetes",
        "kubernetes.wasm",
    ),
    (
        "araphor-detector-example",
        "crates/araphor-detector-example",
        "detector.wasm",
    ),
    (
        "araphor-component-fixture",
        "crates/araphor-analysis-sdk/tests/component",
        "runtime.wasm",
    ),
];
const SHARED: &[&str] = &[
    "crates/araphor-analysis-sdk",
    "crates/araphor-analysis-builtins",
    "crates/araphor-component-build",
    "crates/erebor-runtime-error",
    "crates/erebor-interceptor-abi",
];

impl ComponentBuilder {
    pub fn workspace(root: &Path, target: &Path, output: &Path) -> Result<()> {
        let root = root.canonicalize().context(error::IoSnafu { path: root })?;
        let target = Self::workspace_path(&root, target);
        let output = Self::workspace_path(&root, output);
        let status = Self::workspace_command(&root, &target)
            .status()
            .context(error::BuildSnafu { path: &root })?;
        if !status.success() {
            return error::BuildFailedSnafu {
                path: &root,
                status,
            }
            .fail();
        }
        std::fs::create_dir_all(&output).context(error::IoSnafu { path: &output })?;
        let cores = target.join(TARGET).join("release");
        for &(package, _, filename) in GUESTS {
            let core = cores.join(format!("{}.wasm", package.replace('-', "_")));
            Self::build(&core, &output.join(filename))?;
        }
        Ok(())
    }

    pub fn workspace_native(root: &Path, target: &Path, output: &Path) -> Result<()> {
        let root = root.canonicalize().context(error::IoSnafu { path: root })?;
        let target = Self::workspace_path(&root, target);
        let output = Self::workspace_path(&root, output);
        let triple = Self::host_target()?;
        let status = Self::target_command(&root, &target, &triple)
            .status()
            .context(error::BuildSnafu { path: &root })?;
        if !status.success() {
            return error::BuildFailedSnafu {
                path: &root,
                status,
            }
            .fail();
        }
        std::fs::create_dir_all(&output).context(error::IoSnafu { path: &output })?;
        for &(package, _, filename) in GUESTS {
            let library = format!(
                "{}{}{}",
                std::env::consts::DLL_PREFIX,
                package.replace('-', "_"),
                std::env::consts::DLL_SUFFIX
            );
            let source = target.join(&triple).join("release").join(library);
            let destination = output
                .join(filename)
                .with_extension(std::env::consts::DLL_EXTENSION);
            std::fs::copy(&source, &destination).context(error::IoSnafu { path: &source })?;
        }
        Ok(())
    }

    pub fn host_target() -> Result<String> {
        let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
        let output = Command::new(&rustc)
            .arg("-vV")
            .output()
            .context(error::BuildSnafu {
                path: Path::new(&rustc),
            })?;
        if !output.status.success() {
            return error::BuildFailedSnafu {
                path: Path::new(&rustc),
                status: output.status,
            }
            .fail();
        }
        let target = std::str::from_utf8(&output.stdout)
            .ok()
            .and_then(|text| text.lines().find_map(|line| line.strip_prefix("host: ")))
            .filter(|target| !target.is_empty())
            .ok_or_else(|| std::io::Error::other("rustc did not report a host target"))
            .context(error::IoSnafu {
                path: Path::new(&rustc),
            })?;
        Ok(target.to_owned())
    }

    pub fn inputs(root: &Path) -> Vec<PathBuf> {
        let mut paths = vec![root.join("Cargo.toml"), root.join("Cargo.lock")];
        for directory in SHARED
            .iter()
            .copied()
            .chain(GUESTS.iter().map(|(_, directory, _)| *directory))
        {
            paths.push(root.join(directory).join("Cargo.toml"));
            paths.push(root.join(directory).join("src"));
            let build = root.join(directory).join("build.rs");
            if build.is_file() {
                paths.push(build);
            }
        }
        for filename in [
            ".cargo/config.toml",
            ".cargo/config",
            "rust-toolchain.toml",
            "rust-toolchain",
        ] {
            let path = root.join(filename);
            if path.is_file() {
                paths.push(path);
            }
        }
        paths
    }

    fn workspace_path(root: &Path, path: &Path) -> PathBuf {
        if path.is_absolute() {
            path.to_owned()
        } else {
            root.join(path)
        }
    }

    fn workspace_command(root: &Path, target: &Path) -> Command {
        Self::target_command(root, target, TARGET)
    }

    fn target_command(root: &Path, target: &Path, triple: &str) -> Command {
        let mut command = Command::new(std::env::var_os("CARGO").unwrap_or_else(|| "cargo".into()));
        command.current_dir(root).args([
            "build",
            "--locked",
            "--lib",
            "--release",
            "--target",
            triple,
            "--jobs",
            "1",
            "--target-dir",
        ]);
        command.arg(target);
        for &(package, _, _) in GUESTS {
            command.args(["--package", package]);
        }
        for key in [
            "CARGO_MAKEFLAGS",
            "MAKEFLAGS",
            "MFLAGS",
            "CARGO_TARGET_DIR",
            "CARGO_BUILD_TARGET_DIR",
            "CARGO_BUILD_BUILD_DIR",
            "RUSTFLAGS",
            "CARGO_ENCODED_RUSTFLAGS",
            "CARGO_BUILD_RUSTFLAGS",
            "RUSTC_WRAPPER",
            "RUSTC_WORKSPACE_WRAPPER",
            "CARGO_BUILD_RUSTC_WRAPPER",
            "CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER",
            "CLIPPY_ARGS",
        ] {
            command.env_remove(key);
        }
        for (key, _) in std::env::vars_os() {
            if key.to_str().is_some_and(|key| {
                key.starts_with("CARGO_PROFILE_")
                    || (key.starts_with("CARGO_TARGET_") && key.ends_with("_RUSTFLAGS"))
            }) {
                command.env_remove(key);
            }
        }
        command
            .env("CARGO_INCREMENTAL", "0")
            .env("CONST_RANDOM_SEED", "araphor-analysis-v1");
        command
    }
}

#[cfg(test)]
mod tests;
