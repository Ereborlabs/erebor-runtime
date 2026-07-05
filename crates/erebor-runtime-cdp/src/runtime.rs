use erebor_runtime_core::{
    BrowserCdpSurfaceConfig, RunningSessionSurface, RuntimeAuditConfig, RuntimeError,
    SessionSurfaceFailure, SessionSurfaceFailureSender, SessionSurfaceKind, SessionSurfaceService,
};
use erebor_runtime_policy::PolicySet;
use erebor_runtime_telemetry::{debug, info};
use snafu::Location;
use tokio::runtime::Runtime;

use crate::{BrowserSessionManager, CdpSessionContext};

pub struct BrowserCdpSurface {
    config: BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<std::path::PathBuf>,
    audit: RuntimeAuditConfig,
}

impl BrowserCdpSurface {
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

    #[must_use]
    pub fn with_audit_jsonl(mut self, path: impl Into<std::path::PathBuf>) -> Self {
        self.audit_jsonl = Some(path.into());
        self
    }

    #[must_use]
    pub fn with_audit_config(mut self, audit: RuntimeAuditConfig) -> Self {
        self.audit = audit;
        self
    }
}

impl SessionSurfaceService for BrowserCdpSurface {
    fn surface(&self) -> SessionSurfaceKind {
        SessionSurfaceKind::BrowserCdp
    }

    fn start(
        self: Box<Self>,
        runtime: &Runtime,
        failures: SessionSurfaceFailureSender,
    ) -> Result<RunningSessionSurface, RuntimeError> {
        let surface = self.surface();
        info!(
            listen = %self.config.listen(),
            surface = surface.as_str(),
            "starting browser CDP session surface"
        );
        if let Some(browser_url) = self.config.browser_url() {
            debug!(
                browser_url = %browser_url,
                surface = surface.as_str(),
                "using configured CDP upstream"
            );
        } else {
            debug!(
                headless = self.config.browser().headless(),
                surface = surface.as_str(),
                "launching owned browser for CDP session surface"
            );
        }
        let mut manager = BrowserSessionManager::new(self.config, self.policy_set, self.context);
        manager.set_audit_config(self.audit);
        if let Some(audit_jsonl) = self.audit_jsonl {
            manager.set_audit_jsonl(audit_jsonl);
        }
        let session = runtime
            .block_on(manager.create_session())
            .map_err(|error| RuntimeError::SurfaceStart {
                surface: surface.as_str().to_owned(),
                reason: error.to_string(),
                location: Location::default(),
            })?;
        let endpoint = session.public_endpoint().to_owned();

        let handle = runtime.spawn(async move {
            if let Err(error) = session.run().await {
                let _result = failures.send(SessionSurfaceFailure::new(surface, error.to_string()));
            }
        });
        drop(handle);

        Ok(RunningSessionSurface::new(surface, endpoint))
    }
}
