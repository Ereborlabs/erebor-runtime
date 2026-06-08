use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use erebor_runtime_events::{ActorKind, SessionId};
use serde::Deserialize;

use crate::RuntimeConfigError;

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct RuntimeConfig {
    pub policies: Vec<PathBuf>,
    #[serde(default)]
    pub audit: RuntimeAuditConfig,
    #[serde(default)]
    pub session: SessionLayerConfig,
    #[serde(default)]
    pub governance: GovernanceLayers,
}

impl RuntimeConfig {
    pub fn from_json_str(source: &str) -> Result<Self, RuntimeConfigError> {
        if source.trim().is_empty() {
            return Err(RuntimeConfigError::empty_config());
        }

        let config: Self =
            serde_json::from_str(source).map_err(RuntimeConfigError::invalid_json)?;
        config.validate()?;

        Ok(config)
    }

    pub fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.policies.is_empty() {
            return Err(RuntimeConfigError::missing_policy());
        }

        if self
            .policies
            .iter()
            .any(|policy| policy.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::empty_policy_path());
        }

        if self
            .audit
            .jsonl
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::empty_audit_jsonl_path());
        }

        if self.session.enabled {
            self.session.validate()?;
        }

        if self.governance.enabled_layers().is_empty() && !self.session.enabled {
            return Err(RuntimeConfigError::no_governance_layers());
        }

        if self.governance.browser_cdp.enabled {
            if let Some(browser_url) = self.governance.browser_cdp.browser_url.as_deref() {
                if !browser_url.starts_with("ws://") {
                    return Err(RuntimeConfigError::browser_cdp_invalid_browser_url());
                }
            }
        }

        Ok(())
    }

    #[must_use]
    pub fn enabled_layers(&self) -> Vec<GovernanceLayer> {
        self.governance.enabled_layers()
    }

    pub fn start_plan(&self) -> Result<RuntimeStartPlan, RuntimeConfigError> {
        RuntimeStartPlan::from_config(self)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeStartPlan {
    policies: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    layers: Vec<GovernanceLayer>,
    browser_cdp: Option<BrowserCdpRuntimeConfig>,
}

impl RuntimeStartPlan {
    pub fn from_config(config: &RuntimeConfig) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            audit: config.audit.clone(),
            layers: config.enabled_layers(),
            browser_cdp: config
                .governance
                .browser_cdp
                .enabled
                .then(|| BrowserCdpRuntimeConfig {
                    listen: config.governance.browser_cdp.listen,
                    browser_url: config.governance.browser_cdp.browser_url.clone(),
                    browser: config.governance.browser_cdp.browser.clone().into(),
                }),
        })
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub fn layers(&self) -> &[GovernanceLayer] {
        &self.layers
    }

    #[must_use]
    pub fn contains_layer(&self, layer: GovernanceLayer) -> bool {
        self.layers.contains(&layer)
    }

    #[must_use]
    pub fn browser_cdp(&self) -> Option<&BrowserCdpRuntimeConfig> {
        self.browser_cdp.as_ref()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct RuntimeAuditConfig {
    #[serde(default)]
    pub jsonl: Option<PathBuf>,
}

impl RuntimeAuditConfig {
    #[must_use]
    pub fn jsonl(&self) -> Option<&Path> {
        self.jsonl.as_deref()
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct SessionLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub actor: SessionActorLayerConfig,
    #[serde(default)]
    pub workspace: Option<PathBuf>,
    #[serde(default)]
    pub runtime: SessionRuntimeLayerConfig,
}

impl SessionLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.actor.id.trim().is_empty() {
            return Err(RuntimeConfigError::empty_session_actor_id());
        }

        if self
            .workspace
            .as_ref()
            .is_some_and(|path| path.as_os_str().is_empty())
        {
            return Err(RuntimeConfigError::empty_session_workspace());
        }

        self.runtime.validate()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct SessionActorLayerConfig {
    #[serde(default = "default_session_actor_id")]
    pub id: String,
    #[serde(default = "default_session_actor_kind")]
    pub kind: ActorKind,
}

impl Default for SessionActorLayerConfig {
    fn default() -> Self {
        Self {
            id: default_session_actor_id(),
            kind: default_session_actor_kind(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct SessionRuntimeLayerConfig {
    #[serde(default = "default_session_runtime_kind")]
    pub kind: SessionRuntimeKind,
    #[serde(default)]
    pub docker: DockerSessionRuntimeLayerConfig,
}

impl Default for SessionRuntimeLayerConfig {
    fn default() -> Self {
        Self {
            kind: default_session_runtime_kind(),
            docker: DockerSessionRuntimeLayerConfig::default(),
        }
    }
}

impl SessionRuntimeLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        match self.kind {
            SessionRuntimeKind::Docker => self.docker.validate(),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionRuntimeKind {
    Docker,
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct DockerSessionRuntimeLayerConfig {
    #[serde(default = "default_docker_session_image")]
    pub image: String,
    #[serde(default = "default_docker_session_network")]
    pub network: String,
    #[serde(default = "default_docker_session_workdir")]
    pub workdir: PathBuf,
}

impl Default for DockerSessionRuntimeLayerConfig {
    fn default() -> Self {
        Self {
            image: default_docker_session_image(),
            network: default_docker_session_network(),
            workdir: default_docker_session_workdir(),
        }
    }
}

impl DockerSessionRuntimeLayerConfig {
    fn validate(&self) -> Result<(), RuntimeConfigError> {
        if self.image.trim().is_empty() {
            return Err(RuntimeConfigError::empty_docker_session_image());
        }

        if self.network.trim().is_empty() {
            return Err(RuntimeConfigError::empty_docker_session_network());
        }

        Ok(())
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRunPlan {
    policies: Vec<PathBuf>,
    audit: RuntimeAuditConfig,
    session_id: SessionId,
    actor: SessionActorLayerConfig,
    workspace: Option<PathBuf>,
    runtime: SessionRuntimeConfig,
    command: Vec<String>,
}

impl SessionRunPlan {
    pub fn from_config(
        config: &RuntimeConfig,
        runtime_kind: SessionRuntimeKind,
        session_id: SessionId,
        command: Vec<String>,
    ) -> Result<Self, RuntimeConfigError> {
        config.validate()?;

        if command.is_empty() {
            return Err(RuntimeConfigError::empty_session_command());
        }

        let mut runtime = config.session.runtime.clone();
        runtime.kind = runtime_kind;
        runtime.validate()?;

        Ok(Self {
            policies: config.policies.clone(),
            audit: config.audit.clone(),
            session_id,
            actor: config.session.actor.clone(),
            workspace: config.session.workspace.clone(),
            runtime: runtime.into(),
            command,
        })
    }

    #[must_use]
    pub fn policies(&self) -> &[PathBuf] {
        &self.policies
    }

    #[must_use]
    pub const fn audit(&self) -> &RuntimeAuditConfig {
        &self.audit
    }

    #[must_use]
    pub const fn session_id(&self) -> &SessionId {
        &self.session_id
    }

    #[must_use]
    pub const fn actor(&self) -> &SessionActorLayerConfig {
        &self.actor
    }

    #[must_use]
    pub fn workspace(&self) -> Option<&Path> {
        self.workspace.as_deref()
    }

    #[must_use]
    pub const fn runtime(&self) -> &SessionRuntimeConfig {
        &self.runtime
    }

    #[must_use]
    pub fn command(&self) -> &[String] {
        &self.command
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionRuntimeConfig {
    kind: SessionRuntimeKind,
    docker: DockerSessionRuntimeConfig,
}

impl SessionRuntimeConfig {
    #[must_use]
    pub const fn kind(&self) -> SessionRuntimeKind {
        self.kind
    }

    #[must_use]
    pub const fn docker(&self) -> &DockerSessionRuntimeConfig {
        &self.docker
    }
}

impl From<SessionRuntimeLayerConfig> for SessionRuntimeConfig {
    fn from(config: SessionRuntimeLayerConfig) -> Self {
        Self {
            kind: config.kind,
            docker: config.docker.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionRuntimeConfig {
    image: String,
    network: String,
    workdir: PathBuf,
}

impl DockerSessionRuntimeConfig {
    #[must_use]
    pub fn image(&self) -> &str {
        &self.image
    }

    #[must_use]
    pub fn network(&self) -> &str {
        &self.network
    }

    #[must_use]
    pub fn workdir(&self) -> &Path {
        &self.workdir
    }
}

impl From<DockerSessionRuntimeLayerConfig> for DockerSessionRuntimeConfig {
    fn from(config: DockerSessionRuntimeLayerConfig) -> Self {
        Self {
            image: config.image,
            network: config.network,
            workdir: config.workdir,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DockerSessionLaunchPlan {
    program: String,
    args: Vec<String>,
}

impl DockerSessionLaunchPlan {
    #[must_use]
    pub fn from_session_run_plan(plan: &SessionRunPlan) -> Self {
        let docker = plan.runtime().docker();
        let mut args = vec![
            String::from("run"),
            String::from("--rm"),
            String::from("--name"),
            docker_container_name(plan.session_id()),
            String::from("--label"),
            format!("dev.erebor.session_id={}", plan.session_id().as_str()),
            String::from("--label"),
            format!("dev.erebor.actor_id={}", plan.actor().id),
            String::from("--network"),
            docker.network().to_owned(),
            String::from("-e"),
            format!("EREBOR_SESSION_ID={}", plan.session_id().as_str()),
            String::from("-e"),
            format!("EREBOR_ACTOR_ID={}", plan.actor().id),
            String::from("-e"),
            String::from("EREBOR_SESSION_RUNTIME=docker"),
        ];

        if let Some(workspace) = plan.workspace() {
            args.push(String::from("-v"));
            args.push(format!(
                "{}:{}",
                workspace.display(),
                docker.workdir().display()
            ));
            args.push(String::from("-w"));
            args.push(docker.workdir().display().to_string());
        }

        args.push(docker.image().to_owned());
        args.extend(plan.command().iter().cloned());

        Self {
            program: String::from("docker"),
            args,
        }
    }

    #[must_use]
    pub fn program(&self) -> &str {
        &self.program
    }

    #[must_use]
    pub fn args(&self) -> &[String] {
        &self.args
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct GovernanceLayers {
    #[serde(default)]
    pub browser_cdp: BrowserCdpLayerConfig,
    #[serde(default)]
    pub mcp: GovernanceLayerConfig,
    #[serde(default)]
    pub terminal: GovernanceLayerConfig,
    #[serde(default)]
    pub network: GovernanceLayerConfig,
    #[serde(default)]
    pub saas: GovernanceLayerConfig,
    #[serde(default)]
    pub desktop: GovernanceLayerConfig,
    #[serde(default)]
    pub internal_system: GovernanceLayerConfig,
}

impl GovernanceLayers {
    #[must_use]
    pub fn enabled_layers(&self) -> Vec<GovernanceLayer> {
        let candidates = [
            (GovernanceLayer::BrowserCdp, self.browser_cdp.enabled),
            (GovernanceLayer::Mcp, self.mcp.enabled),
            (GovernanceLayer::Terminal, self.terminal.enabled),
            (GovernanceLayer::Network, self.network.enabled),
            (GovernanceLayer::Saas, self.saas.enabled),
            (GovernanceLayer::Desktop, self.desktop.enabled),
            (
                GovernanceLayer::InternalSystem,
                self.internal_system.enabled,
            ),
        ];

        candidates
            .into_iter()
            .filter_map(|(layer, enabled)| enabled.then_some(layer))
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct BrowserCdpLayerConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub browser_url: Option<String>,
    #[serde(default = "default_browser_cdp_listen")]
    pub listen: SocketAddr,
    #[serde(default)]
    pub browser: BrowserLaunchLayerConfig,
}

impl Default for BrowserCdpLayerConfig {
    fn default() -> Self {
        Self {
            enabled: false,
            browser_url: None,
            listen: default_browser_cdp_listen(),
            browser: BrowserLaunchLayerConfig::default(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Deserialize)]
pub struct BrowserLaunchLayerConfig {
    #[serde(default)]
    pub executable: Option<PathBuf>,
    #[serde(default)]
    pub user_data_dir: Option<PathBuf>,
    #[serde(default = "default_browser_headless")]
    pub headless: bool,
}

impl Default for BrowserLaunchLayerConfig {
    fn default() -> Self {
        Self {
            executable: None,
            user_data_dir: None,
            headless: default_browser_headless(),
        }
    }
}

#[derive(Clone, Debug, Default, Eq, PartialEq, Deserialize)]
pub struct GovernanceLayerConfig {
    #[serde(default)]
    pub enabled: bool,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserCdpRuntimeConfig {
    listen: SocketAddr,
    browser_url: Option<String>,
    browser: BrowserLaunchConfig,
}

impl BrowserCdpRuntimeConfig {
    #[must_use]
    pub fn listen(&self) -> SocketAddr {
        self.listen
    }

    #[must_use]
    pub fn browser_url(&self) -> Option<&str> {
        self.browser_url.as_deref()
    }

    #[must_use]
    pub const fn browser(&self) -> &BrowserLaunchConfig {
        &self.browser
    }

    #[must_use]
    pub const fn owns_browser(&self) -> bool {
        self.browser_url.is_none()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BrowserLaunchConfig {
    executable: Option<PathBuf>,
    user_data_dir: Option<PathBuf>,
    headless: bool,
}

impl BrowserLaunchConfig {
    #[must_use]
    pub fn executable(&self) -> Option<&Path> {
        self.executable.as_deref()
    }

    #[must_use]
    pub fn user_data_dir(&self) -> Option<&Path> {
        self.user_data_dir.as_deref()
    }

    #[must_use]
    pub const fn headless(&self) -> bool {
        self.headless
    }
}

impl From<BrowserLaunchLayerConfig> for BrowserLaunchConfig {
    fn from(config: BrowserLaunchLayerConfig) -> Self {
        Self {
            executable: config.executable,
            user_data_dir: config.user_data_dir,
            headless: config.headless,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GovernanceLayer {
    BrowserCdp,
    Mcp,
    Terminal,
    Network,
    Saas,
    Desktop,
    InternalSystem,
}

impl GovernanceLayer {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::BrowserCdp => "browser_cdp",
            Self::Mcp => "mcp",
            Self::Terminal => "terminal",
            Self::Network => "network",
            Self::Saas => "saas",
            Self::Desktop => "desktop",
            Self::InternalSystem => "internal_system",
        }
    }
}

pub fn validate_policy_path(path: &Path) -> Result<(), RuntimeConfigError> {
    if path.as_os_str().is_empty() {
        Err(RuntimeConfigError::empty_policy_path())
    } else {
        Ok(())
    }
}

fn default_browser_cdp_listen() -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], 0))
}

const fn default_browser_headless() -> bool {
    true
}

fn default_session_actor_id() -> String {
    String::from("agent")
}

const fn default_session_actor_kind() -> ActorKind {
    ActorKind::Agent
}

const fn default_session_runtime_kind() -> SessionRuntimeKind {
    SessionRuntimeKind::Docker
}

fn default_docker_session_image() -> String {
    String::from("alpine:3.20")
}

fn default_docker_session_network() -> String {
    String::from("bridge")
}

fn default_docker_session_workdir() -> PathBuf {
    PathBuf::from("/workspace")
}

fn docker_container_name(session_id: &SessionId) -> String {
    let suffix = session_id
        .as_str()
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || matches!(character, '-' | '_'))
        .collect::<String>();

    if suffix.is_empty() {
        String::from("erebor-session")
    } else {
        format!("erebor-{suffix}")
    }
}

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, path::Path};

    use erebor_runtime_events::SessionId;

    use crate::{
        DockerSessionLaunchPlan, GovernanceLayer, RuntimeConfig, RuntimeConfigError,
        SessionRunPlan, SessionRuntimeKind,
    };

    #[test]
    fn loads_config_with_multiple_governance_layers() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;

        assert_eq!(
            config.enabled_layers(),
            vec![GovernanceLayer::BrowserCdp, GovernanceLayer::Terminal]
        );

        Ok(())
    }

    #[test]
    fn rejects_config_without_policies() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": [],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::MissingPolicy { .. })
        ));
    }

    #[test]
    fn rejects_empty_policy_paths() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": [""],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptyPolicyPath { .. })
        ));
    }

    #[test]
    fn rejects_config_without_enabled_governance_layers() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {}
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::NoGovernanceLayers { .. })
        ));
    }

    #[test]
    fn creates_start_plan_from_config() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json", "policies/terminal.json"],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "ws://127.0.0.1:9222/devtools/browser/demo",
                  "listen": "127.0.0.1:3738"
                },
                "terminal": { "enabled": true }
              }
            }
            "#,
        )?;
        let plan = config.start_plan()?;

        assert_eq!(plan.policies().len(), 2);
        assert_eq!(plan.audit().jsonl(), None);
        assert!(plan.contains_layer(GovernanceLayer::BrowserCdp));
        assert!(plan.contains_layer(GovernanceLayer::Terminal));
        assert!(!plan.contains_layer(GovernanceLayer::Mcp));
        assert_eq!(
            plan.browser_cdp().map(|config| config.browser_url()),
            Some(Some("ws://127.0.0.1:9222/devtools/browser/demo"))
        );
        assert_eq!(
            plan.browser_cdp().map(|config| config.listen()),
            Some(SocketAddr::from(([127, 0, 0, 1], 3738)))
        );

        Ok(())
    }

    #[test]
    fn creates_session_run_plan_from_config() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "audit": { "jsonl": "audit/pilot.jsonl" },
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw", "kind": "agent" },
                "workspace": "/tmp/erebor-workspace",
                "runtime": {
                  "kind": "docker",
                  "docker": {
                    "image": "erebor/openclaw-pilot:local",
                    "network": "none",
                    "workdir": "/work"
                  }
                }
              }
            }
            "#,
        )?;

        let plan = SessionRunPlan::from_config(
            &config,
            SessionRuntimeKind::Docker,
            SessionId::new("session-1"),
            vec![String::from("openclaw"), String::from("--help")],
        )?;

        assert_eq!(plan.policies(), &[Path::new("policies/browser.json")]);
        assert_eq!(plan.audit().jsonl(), Some(Path::new("audit/pilot.jsonl")));
        assert_eq!(plan.session_id().as_str(), "session-1");
        assert_eq!(plan.actor().id, "openclaw");
        assert_eq!(plan.workspace(), Some(Path::new("/tmp/erebor-workspace")));
        assert_eq!(plan.runtime().kind(), SessionRuntimeKind::Docker);
        assert_eq!(
            plan.runtime().docker().image(),
            "erebor/openclaw-pilot:local"
        );
        assert_eq!(plan.runtime().docker().network(), "none");
        assert_eq!(plan.runtime().docker().workdir(), Path::new("/work"));
        assert_eq!(plan.command(), ["openclaw", "--help"]);

        Ok(())
    }

    #[test]
    fn docker_launch_plan_wraps_session_command() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "actor": { "id": "openclaw" },
                "workspace": "/tmp/erebor-workspace",
                "runtime": {
                  "docker": {
                    "image": "erebor/openclaw-pilot:local",
                    "network": "none",
                    "workdir": "/work"
                  }
                }
              }
            }
            "#,
        )?;
        let plan = SessionRunPlan::from_config(
            &config,
            SessionRuntimeKind::Docker,
            SessionId::new("session-1"),
            vec![String::from("openclaw"), String::from("--help")],
        )?;

        let launch = DockerSessionLaunchPlan::from_session_run_plan(&plan);

        assert_eq!(launch.program(), "docker");
        assert_eq!(
            launch.args(),
            &[
                "run",
                "--rm",
                "--name",
                "erebor-session-1",
                "--label",
                "dev.erebor.session_id=session-1",
                "--label",
                "dev.erebor.actor_id=openclaw",
                "--network",
                "none",
                "-e",
                "EREBOR_SESSION_ID=session-1",
                "-e",
                "EREBOR_ACTOR_ID=openclaw",
                "-e",
                "EREBOR_SESSION_RUNTIME=docker",
                "-v",
                "/tmp/erebor-workspace:/work",
                "-w",
                "/work",
                "erebor/openclaw-pilot:local",
                "openclaw",
                "--help"
            ]
        );
        Ok(())
    }

    #[test]
    fn rejects_empty_session_command() -> Result<(), RuntimeConfigError> {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": { "enabled": true }
            }
            "#,
        )?;

        let error = SessionRunPlan::from_config(
            &config,
            SessionRuntimeKind::Docker,
            SessionId::new("session-1"),
            Vec::new(),
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptySessionCommand { .. })
        ));
        Ok(())
    }

    #[test]
    fn rejects_empty_docker_session_image() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "session": {
                "enabled": true,
                "runtime": { "docker": { "image": "" } }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::EmptyDockerSessionImage { .. })
        ));
    }

    #[test]
    fn creates_owned_browser_runtime_config_without_browser_url() -> Result<(), RuntimeConfigError>
    {
        let config = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser": {
                    "headless": false,
                    "user_data_dir": "/tmp/erebor-browser-profile"
                  }
                }
              }
            }
            "#,
        )?;
        let start_plan = config.start_plan()?;
        let browser_cdp = start_plan
            .browser_cdp()
            .ok_or_else(RuntimeConfigError::no_governance_layers)?;

        assert_eq!(browser_cdp.browser_url(), None);
        assert!(browser_cdp.owns_browser());
        assert!(!browser_cdp.browser().headless());
        assert_eq!(
            browser_cdp.browser().user_data_dir(),
            Some(Path::new("/tmp/erebor-browser-profile"))
        );
        Ok(())
    }

    #[test]
    fn rejects_browser_cdp_without_local_ws_url() {
        let error = RuntimeConfig::from_json_str(
            r#"
            {
              "policies": ["policies/browser.json"],
              "governance": {
                "browser_cdp": {
                  "enabled": true,
                  "browser_url": "wss://browser.example/ws"
                }
              }
            }
            "#,
        );

        assert!(matches!(
            error,
            Err(RuntimeConfigError::BrowserCdpInvalidBrowserUrl { .. })
        ));
    }
}
