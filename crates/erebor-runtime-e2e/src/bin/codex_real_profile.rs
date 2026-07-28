//! Root-only fixture configurator for the real Codex Phase 5.5 acceptance.

use std::{
    collections::BTreeMap,
    env, fs,
    os::unix::fs::PermissionsExt,
    path::{Path, PathBuf},
};

use erebor_runtime_core::AgentAdapterDescriptor;
use erebor_runtime_packages::{
    AgentPackageManifest, CanonicalEncoding, CodexArtifact, CodexEntrypoint, CodexHookContract,
    CodexHookEventName, CodexHookExec, CodexHookShell, CodexManagedArtifacts,
    CodexPackageDefinition, CodexSupportedPlatform, ContentDigest, InstallationRecord,
    PolicyPackageRevision, PolicySetRevision,
};
use serde_json::json;

const PACKAGE_NAME: &str = "codex-cli-0-145-0";
const REQUIREMENTS_TARGET: &str = "/etc/codex/requirements.toml";
const MANAGED_HOOK_TARGET: &str = "/usr/lib/erebor/codex-hooks/erebor-codex-hook";
const SHELL_STARTUP_TARGET: &str = "/usr/lib/erebor/codex-hooks/shell-startup";
const POLICY_NAME: &str = "codex-runtime-guardrail";

type ProfileResult<T> = Result<T, Box<dyn std::error::Error>>;

fn main() -> ProfileResult<()> {
    let options = ConfigureOptions::parse(env::args().skip(1).collect())?;
    options.configure()
}

struct ConfigureOptions {
    config: PathBuf,
    trust_root: PathBuf,
    socket_group_gid: u32,
    owner_uids: Vec<u32>,
    codex_executable: PathBuf,
    managed_hook: PathBuf,
    linux_runner_containment: String,
    linux_runner_controller: Option<PathBuf>,
    linux_process_guard: Option<PathBuf>,
    descriptor_broker: Option<PathBuf>,
    systemd_run: Option<PathBuf>,
}

impl ConfigureOptions {
    fn parse(arguments: Vec<String>) -> ProfileResult<Self> {
        let mut config = None;
        let mut trust_root = None;
        let mut socket_group_gid = None;
        let mut owner_uids = Vec::new();
        let mut codex_executable = None;
        let mut managed_hook = None;
        let mut linux_runner_containment = String::from("direct");
        let mut linux_runner_controller = None;
        let mut linux_process_guard = None;
        let mut descriptor_broker = None;
        let mut systemd_run = None;
        let mut index = 0;
        while let Some(option) = arguments.get(index) {
            let value = arguments
                .get(index.saturating_add(1))
                .ok_or_else(|| format!("{option} requires a value"))?;
            match option.as_str() {
                "--config" => config = Some(absolute_path(option, value)?),
                "--trust-root" => trust_root = Some(absolute_path(option, value)?),
                "--socket-group-gid" => socket_group_gid = Some(value.parse()?),
                "--owner-uid" => owner_uids.push(value.parse()?),
                "--codex-executable" => codex_executable = Some(absolute_path(option, value)?),
                "--managed-hook" => managed_hook = Some(absolute_path(option, value)?),
                "--linux-runner-containment" => {
                    if !matches!(value.as_str(), "direct" | "systemd") {
                        return Err(format!(
                            "--linux-runner-containment must be `direct` or `systemd`, got `{value}`"
                        )
                        .into());
                    }
                    linux_runner_containment = value.clone();
                }
                "--linux-runner-controller" => {
                    linux_runner_controller = Some(absolute_path(option, value)?);
                }
                "--linux-process-guard" => {
                    linux_process_guard = Some(absolute_path(option, value)?);
                }
                "--descriptor-broker" => {
                    descriptor_broker = Some(absolute_path(option, value)?);
                }
                "--systemd-run" => systemd_run = Some(absolute_path(option, value)?),
                _ => return Err(format!("unknown configure option `{option}").into()),
            }
            index += 2;
        }
        Ok(Self {
            config: config.ok_or("--config is required")?,
            trust_root: trust_root.ok_or("--trust-root is required")?,
            socket_group_gid: socket_group_gid.ok_or("--socket-group-gid is required")?,
            owner_uids,
            codex_executable: codex_executable.ok_or("--codex-executable is required")?,
            managed_hook: managed_hook.ok_or("--managed-hook is required")?,
            linux_runner_containment,
            linux_runner_controller,
            linux_process_guard,
            descriptor_broker,
            systemd_run,
        })
    }

    fn configure(&self) -> ProfileResult<()> {
        if !self.codex_executable.is_file() {
            return Err(format!(
                "--codex-executable is not a regular file: {}",
                self.codex_executable.display()
            )
            .into());
        }
        if !self.managed_hook.is_file() {
            return Err(format!(
                "--managed-hook is not a regular file: {}",
                self.managed_hook.display()
            )
            .into());
        }
        fs::create_dir_all(&self.trust_root)?;
        let requirements = self.trust_root.join("requirements.toml");
        let hook = self.trust_root.join("erebor-codex-hook");
        let shell_startup = self.trust_root.join("shell-startup");
        fs::write(&requirements, requirements_contents())?;
        fs::copy(&self.managed_hook, &hook)?;
        fs::write(&shell_startup, "#!/bin/sh\n")?;
        for artifact in [&requirements, &hook, &shell_startup] {
            fs::set_permissions(artifact, fs::Permissions::from_mode(0o755))?;
        }

        let definition = self.package_definition(&requirements, &hook, &shell_startup)?;
        let package = package_manifest(&definition)?;
        let root_policy = root_policy()?;
        let admissions = self
            .owner_uids
            .iter()
            .map(|owner_uid| root_admission(*owner_uid, &root_policy))
            .collect::<ProfileResult<Vec<_>>>()?;
        let policy_path = write_guardrail_policy(&self.trust_root)?;
        let configuration = json!({
            "socket_group_gid": self.socket_group_gid,
            "linux_runner": {
                "containment": self.linux_runner_containment,
                "controller_path": self.linux_runner_controller,
                "process_guard_path": self.linux_process_guard,
                "descriptor_broker_path": self.descriptor_broker,
                "systemd_run_path": self.systemd_run,
            },
            "root_curated_admissions": admissions,
            "root_curated_codex_packages": [{
                "package": package,
                "definition": definition,
                "trust_root": self.trust_root,
            }],
        });
        let parent = self
            .config
            .parent()
            .ok_or("--config must have a parent directory")?;
        fs::create_dir_all(parent)?;
        fs::write(&self.config, serde_json::to_vec_pretty(&configuration)?)?;
        fs::set_permissions(&self.config, fs::Permissions::from_mode(0o640))?;
        println!("package_name={PACKAGE_NAME}");
        println!("policy_path={}", policy_path.display());
        Ok(())
    }

    fn package_definition(
        &self,
        requirements: &Path,
        hook: &Path,
        shell_startup: &Path,
    ) -> ProfileResult<CodexPackageDefinition> {
        let managed_artifacts = CodexManagedArtifacts::new(
            artifact(requirements)?,
            REQUIREMENTS_TARGET.into(),
            artifact(hook)?,
            MANAGED_HOOK_TARGET.into(),
            artifact(shell_startup)?,
            SHELL_STARTUP_TARGET.into(),
            None,
            None,
        )?;
        CodexPackageDefinition::new(
            PACKAGE_NAME,
            digest_file(&self.codex_executable)?,
            CodexSupportedPlatform::LinuxX86_64,
            vec![
                CodexEntrypoint::new("codex", Vec::new(), false)?,
                CodexEntrypoint::new(
                    "codex-app-server",
                    vec![String::from("app-server"), String::from("--stdio")],
                    true,
                )?,
            ],
            managed_artifacts,
            CodexHookContract::new(
                CodexHookShell::Bash,
                vec![
                    CodexHookExec::InstalledExecutable,
                    CodexHookExec::AbsolutePath(PathBuf::from("/usr/bin/bash")),
                    CodexHookExec::ManagedHook,
                ],
                vec![
                    CodexHookEventName::SessionStart,
                    CodexHookEventName::UserPromptSubmit,
                    CodexHookEventName::PreToolUse,
                    CodexHookEventName::PermissionRequest,
                    CodexHookEventName::PostToolUse,
                    CodexHookEventName::SubagentStart,
                    CodexHookEventName::SubagentStop,
                    CodexHookEventName::Stop,
                ],
                None,
            )?,
        )
        .map_err(Into::into)
    }
}

fn absolute_path(option: &str, value: &str) -> ProfileResult<PathBuf> {
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(format!("{option} must name an absolute path, got `{value}`").into())
    }
}

fn artifact(path: &Path) -> ProfileResult<CodexArtifact> {
    Ok(CodexArtifact::new(path.to_path_buf(), digest_file(path)?)?)
}

fn digest_file(path: &Path) -> ProfileResult<ContentDigest> {
    Ok(ContentDigest::from_canonical_bytes(&fs::read(path)?))
}

fn package_manifest(definition: &CodexPackageDefinition) -> ProfileResult<AgentPackageManifest> {
    let descriptor = AgentAdapterDescriptor::codex_v1()?;
    let artifacts = definition.managed_artifacts();
    AgentPackageManifest::with_adapter_and_config(
        PACKAGE_NAME,
        descriptor.id(),
        env!("CARGO_PKG_VERSION"),
        vec![String::from("codex"), String::from("codex-app-server")],
        ContentDigest::new(descriptor.sha256()?)?,
        definition.canonical_digest()?,
        vec![
            artifacts.requirements_source().sha256().clone(),
            artifacts.managed_hook_source().sha256().clone(),
            artifacts.shell_startup_source().sha256().clone(),
        ],
    )
    .map_err(Into::into)
}

fn root_admission(
    owner_uid: u32,
    policy: &PolicyPackageRevision,
) -> ProfileResult<serde_json::Value> {
    let descriptor = AgentAdapterDescriptor::generic_process_v1()?;
    let package = AgentPackageManifest::with_adapter_and_config(
        "codex-real-profile-root",
        descriptor.id(),
        env!("CARGO_PKG_VERSION"),
        vec![String::from("<argv>")],
        ContentDigest::new(descriptor.sha256()?)?,
        ContentDigest::from_canonical_bytes(b"codex-real-profile-root-config"),
        Vec::new(),
    )?;
    let policy_digest = policy.canonical_digest()?;
    Ok(json!({
        "package": package,
        "installation": InstallationRecord::new(owner_uid, package.canonical_digest()?, 0),
        "policy_set": PolicySetRevision::new(vec![policy_digest])?,
        "policies": [policy],
    }))
}

fn root_policy() -> ProfileResult<PolicyPackageRevision> {
    PolicyPackageRevision::new(
        "codex-real-profile-host-minimum",
        b"name = \"codex-real-profile-host-minimum\"\n".to_vec(),
        BTreeMap::from([
            (
                String::from("filesystem.json"),
                br#"{"rules":[{"id":"allow-filesystem","match":{"surface":"filesystem"},"decision":"allow"}]}"#.to_vec(),
            ),
            (
                String::from("terminal.json"),
                br#"{"rules":[{"id":"allow-terminal","match":{"surface":"terminal"},"decision":"allow"}]}"#.to_vec(),
            ),
        ]),
        BTreeMap::new(),
        BTreeMap::from([
            (String::from("filesystem.json"), br#"{}"#.to_vec()),
            (String::from("terminal.json"), br#"{}"#.to_vec()),
        ]),
        b"# Real Codex acceptance host minimum\n".to_vec(),
    )
    .map_err(Into::into)
}

fn write_guardrail_policy(trust_root: &Path) -> ProfileResult<PathBuf> {
    let package = trust_root.join(POLICY_NAME);
    fs::create_dir_all(package.join("rules"))?;
    fs::create_dir_all(package.join("examples"))?;
    fs::create_dir_all(package.join("tests"))?;
    fs::write(
        package.join("policy.toml"),
        format!("name = \"{POLICY_NAME}\"\n"),
    )?;
    fs::write(
        package.join("rules").join("terminal.json"),
        br#"{"rules":[{"id":"allow-codex-terminal-processes","match":{"surface":"terminal","action":"process_exec"},"decision":"allow"}]}"#,
    )?;
    fs::write(
        package.join("rules").join("filesystem.json"),
        br#"{"rules":[{"id":"deny-governed-marker-write","match":{"surface":"filesystem","action":"file_write","target_contains":".erebor-denied"},"decision":"deny","reason":"the governed denied marker must never be written"},{"id":"deny-governed-marker-mutation","match":{"surface":"filesystem","action":"file_mutation","target_contains":".erebor-denied"},"decision":"deny","reason":"the governed denied marker must never be created, renamed, or removed"},{"id":"allow-filesystem-open","match":{"surface":"filesystem","action":"file_open"},"decision":"allow"},{"id":"allow-filesystem-read","match":{"surface":"filesystem","action":"file_read"},"decision":"allow"},{"id":"allow-filesystem-write","match":{"surface":"filesystem","action":"file_write"},"decision":"allow"},{"id":"allow-filesystem-mutation","match":{"surface":"filesystem","action":"file_mutation"},"decision":"allow"}]}"#,
    )?;
    fs::write(package.join("tests").join("terminal.json"), "{}\n")?;
    fs::write(package.join("tests").join("filesystem.json"), "{}\n")?;
    fs::write(
        package.join("README.md"),
        "# Codex Runtime Guardrail\n\nPhase 5.5 real Codex acceptance policy.\n",
    )?;
    Ok(package)
}

fn requirements_contents() -> String {
    let mut requirements = String::from(
        "allow_managed_hooks_only = true\nallow_remote_control = false\n\n[features]\nhooks = true\n\n[hooks]\nmanaged_dir = \"/usr/lib/erebor/codex-hooks\"\n",
    );
    for event in [
        "SessionStart",
        "UserPromptSubmit",
        "PreToolUse",
        "PermissionRequest",
        "PostToolUse",
        "SubagentStart",
        "SubagentStop",
        "Stop",
    ] {
        requirements.push_str(&format!(
            "\n[[hooks.{event}]]\n[[hooks.{event}.hooks]]\ntype = \"command\"\ncommand = \"{MANAGED_HOOK_TARGET}\"\ntimeout = 10\n"
        ));
    }
    requirements
}
