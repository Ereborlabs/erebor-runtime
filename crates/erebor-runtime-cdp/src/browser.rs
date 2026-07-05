mod devtools;
mod diagnostics;
mod executable;
mod http_json;
mod launch;
mod page_target;
mod process;
mod profile;

use std::{net::SocketAddr, path::PathBuf};

use erebor_runtime_core::{BrowserCdpSurfaceConfig, LocalEnforcementEngine, RuntimeAuditConfig};
use erebor_runtime_events::{ActorIdentity, SessionId};
use erebor_runtime_policy::PolicySet;
use erebor_runtime_telemetry::info;

use self::process::{BrowserUpstream, OwnedBrowserProcess};
use crate::{CdpError, CdpProxyServer, CdpProxyServerConfig, CdpSessionContext};

pub struct BrowserSessionManager {
    config: BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<PathBuf>,
    audit: RuntimeAuditConfig,
}

impl BrowserSessionManager {
    #[must_use]
    pub fn new(
        config: BrowserCdpSurfaceConfig,
        policy_set: PolicySet,
        context: CdpSessionContext,
    ) -> Self {
        Self {
            config,
            policy_set,
            context,
            audit_jsonl: None,
            audit: RuntimeAuditConfig::default(),
        }
    }

    pub fn set_audit_jsonl(&mut self, path: impl Into<PathBuf>) {
        self.audit_jsonl = Some(path.into());
    }

    pub fn set_audit_config(&mut self, audit: RuntimeAuditConfig) {
        self.audit = audit;
    }

    pub async fn create_session(self) -> Result<GovernedBrowserSession, CdpError> {
        let upstream = BrowserUpstream::prepare(&self.config)?;
        let policy_set_label = format!("local:{} policies", self.policy_set.policy_count());
        let engine = LocalEnforcementEngine::new(self.policy_set);
        let audit_sink_label = self.audit_jsonl.as_ref().map_or_else(
            || String::from("runtime"),
            |path| path.display().to_string(),
        );
        let server = CdpProxyServer::bind(
            CdpProxyServerConfig {
                listen: self.config.listen(),
                browser_url: upstream.endpoint().to_owned(),
                context: self.context.clone(),
                audit_jsonl: self.audit_jsonl,
                audit: self.audit,
            },
            engine,
        )
        .await?;
        let public_endpoint = GovernedEndpoint::from_address(server.local_addr()?);
        let lease_id = SessionLease::from_context(&self.context);
        let metadata = BrowserSessionMetadata {
            session_id: self.context.session_id.clone(),
            actor: self.context.actor.clone(),
            agent: Some(self.context.actor.id.clone()),
            workspace: std::env::current_dir().ok(),
            policy_set: policy_set_label,
            browser_profile: upstream.browser_profile(),
            approval_channel: String::from("deferred"),
            audit_sink: audit_sink_label,
            public_endpoint: public_endpoint.clone(),
            owned_browser: upstream.owns_browser(),
            lease_id: lease_id.clone(),
        };

        info!(
            session_id = %metadata.session_id.as_str(),
            endpoint = %public_endpoint,
            owned_browser = metadata.owned_browser,
            lease_id = %lease_id,
            "created governed browser session"
        );

        Ok(GovernedBrowserSession {
            server,
            owned_browser: upstream.into_owned_browser(),
            metadata,
            public_endpoint,
            lease_id,
        })
    }
}

pub struct GovernedBrowserSession {
    server: CdpProxyServer,
    owned_browser: Option<OwnedBrowserProcess>,
    metadata: BrowserSessionMetadata,
    public_endpoint: String,
    lease_id: String,
}

impl GovernedBrowserSession {
    #[must_use]
    pub fn public_endpoint(&self) -> &str {
        &self.public_endpoint
    }

    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub const fn metadata(&self) -> &BrowserSessionMetadata {
        &self.metadata
    }

    #[must_use]
    pub const fn owns_browser(&self) -> bool {
        self.owned_browser.is_some()
    }

    pub(crate) async fn run(self) -> Result<(), CdpError> {
        let browser_guard = self.owned_browser;
        let result = self.server.run().await;
        drop(browser_guard);
        result
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct BrowserSessionMetadata {
    pub session_id: SessionId,
    pub actor: ActorIdentity,
    pub agent: Option<String>,
    pub workspace: Option<PathBuf>,
    pub policy_set: String,
    pub browser_profile: Option<PathBuf>,
    pub approval_channel: String,
    pub audit_sink: String,
    pub public_endpoint: String,
    pub owned_browser: bool,
    pub lease_id: String,
}

struct GovernedEndpoint;

impl GovernedEndpoint {
    fn from_address(address: SocketAddr) -> String {
        format!("ws://{address}/")
    }
}

struct SessionLease;

impl SessionLease {
    fn from_context(context: &CdpSessionContext) -> String {
        format!("browser-{}", Self::sanitize(context.session_id.as_str()))
    }

    fn sanitize(value: &str) -> String {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() {
                    character
                } else {
                    '-'
                }
            })
            .collect()
    }
}
