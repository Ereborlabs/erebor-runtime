use std::{
    fs,
    path::{Path, PathBuf},
};

#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;

use sha2::{Digest, Sha256};

pub(crate) const V1_HOOK_EVENTS: [&str; 8] = [
    "SessionStart",
    "UserPromptSubmit",
    "PreToolUse",
    "PermissionRequest",
    "PostToolUse",
    "SubagentStart",
    "SubagentStop",
    "Stop",
];

const HOOK_FILENAME: &str = "erebor-codex-hook";
const MANAGED_HOOK_DIRECTORY: &str = "/usr/lib/erebor/codex-hooks";

pub(crate) struct CodexLinuxV1RequirementsArtifact {
    requirements_path: PathBuf,
    hook_directory: PathBuf,
    requirements_sha256: String,
    hook_sha256: String,
}

impl CodexLinuxV1RequirementsArtifact {
    pub(crate) fn create(root: &Path, hook_binary: &Path) -> TestResult<Self> {
        let requirements_path = root.join("requirements.toml");
        let hook_directory = root.join("codex-hooks");
        fs::create_dir_all(&hook_directory)?;

        let copied_hook = hook_directory.join(HOOK_FILENAME);
        fs::copy(hook_binary, &copied_hook)?;
        set_read_only_executable(&copied_hook)?;

        fs::write(&requirements_path, requirements_contents())?;
        set_read_only_file(&requirements_path)?;

        Ok(Self {
            requirements_sha256: sha256_file(&requirements_path)?,
            hook_sha256: sha256_file(&copied_hook)?,
            requirements_path,
            hook_directory,
        })
    }

    pub(crate) fn assert_complete(&self) -> TestResult<()> {
        let requirements = fs::read_to_string(&self.requirements_path)?;
        assert!(requirements.contains("allow_managed_hooks_only = true"));
        assert!(requirements.contains("allow_remote_control = false"));
        assert!(requirements.contains("hooks = true"));
        assert!(requirements.contains(MANAGED_HOOK_DIRECTORY));
        for event in V1_HOOK_EVENTS {
            assert!(requirements.contains(&format!("[[hooks.{event}]]")));
            assert!(requirements.contains(&format!(
                "[[hooks.{event}.hooks]]\ntype = \"command\"\ncommand = \"{MANAGED_HOOK_DIRECTORY}/{HOOK_FILENAME}\""
            )));
        }
        Ok(())
    }

    pub(crate) fn requirements_path(&self) -> &Path {
        &self.requirements_path
    }

    pub(crate) fn hook_directory(&self) -> &Path {
        &self.hook_directory
    }

    pub(crate) fn requirements_sha256(&self) -> &str {
        &self.requirements_sha256
    }

    pub(crate) fn hook_sha256(&self) -> &str {
        &self.hook_sha256
    }
}

fn requirements_contents() -> String {
    let mut requirements = String::from(
        "allow_managed_hooks_only = true\nallow_remote_control = false\n\n[features]\nhooks = true\n\n[hooks]\nmanaged_dir = \"/usr/lib/erebor/codex-hooks\"\n",
    );
    for event in V1_HOOK_EVENTS {
        requirements.push_str(&format!(
            "\n[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = \"command\"\ncommand = \"{MANAGED_HOOK_DIRECTORY}/{HOOK_FILENAME}\"\ntimeout = 10\n"
        ));
    }
    requirements
}

fn sha256_file(path: &Path) -> TestResult<String> {
    Ok(format!("{:x}", Sha256::digest(fs::read(path)?)))
}

#[cfg(unix)]
fn set_read_only_executable(path: &Path) -> TestResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o555))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_read_only_executable(_path: &Path) -> TestResult<()> {
    Ok(())
}

#[cfg(unix)]
fn set_read_only_file(path: &Path) -> TestResult<()> {
    fs::set_permissions(path, fs::Permissions::from_mode(0o444))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_read_only_file(_path: &Path) -> TestResult<()> {
    Ok(())
}

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
