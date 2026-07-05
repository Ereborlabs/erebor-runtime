mod audit;
mod browser_observer;
mod client_text;
mod connection;
mod fetch;
mod http_discovery;
mod observer_wire;
mod page_observer;

use std::{net::SocketAddr, path::PathBuf, sync::Arc};

use erebor_runtime_core::{LocalEnforcementEngine, RuntimeAuditConfig};
use erebor_runtime_policy::PolicySet;
use erebor_runtime_telemetry::{debug, info, warn};
use snafu::ResultExt;
use tokio::net::TcpListener;

use self::{
    audit::CdpAuditRecorder, browser_observer::BrowserStateObserver,
    connection::CdpClientConnection, page_observer::PageStateObserver,
};
use crate::{error::IoSnafu, CdpError, CdpSessionContext, CdpSessionState};

pub(crate) type CdpEngine = LocalEnforcementEngine<PolicySet>;

#[derive(Clone, Debug, PartialEq)]
pub struct CdpProxyServerConfig {
    pub listen: SocketAddr,
    pub browser_url: String,
    pub context: CdpSessionContext,
    pub audit_jsonl: Option<PathBuf>,
    pub audit: RuntimeAuditConfig,
}

pub struct CdpProxyServer {
    listener: TcpListener,
    browser_url: String,
    engine: Arc<CdpEngine>,
    context: CdpSessionContext,
    session_state: CdpSessionState,
    audit_recorder: Option<CdpAuditRecorder>,
}

impl CdpProxyServer {
    pub async fn bind(config: CdpProxyServerConfig, engine: CdpEngine) -> Result<Self, CdpError> {
        let listener = TcpListener::bind(config.listen).await.context(IoSnafu)?;
        let local_addr = listener.local_addr().context(IoSnafu)?;

        info!(
            listen = %local_addr,
            session_id = %config.context.session_id.as_str(),
            "CDP proxy server bound"
        );

        let session_state = CdpSessionState::from_browser_url(&config.browser_url);
        let engine = Arc::new(engine);
        let audit_recorder = config
            .audit_jsonl
            .clone()
            .map(|path| CdpAuditRecorder::new(path, config.audit.clone()));

        if BrowserStateObserver::should_start(&config.browser_url) {
            BrowserStateObserver::spawn(
                config.browser_url.clone(),
                config.context.clone(),
                session_state.clone(),
                Arc::clone(&engine),
                audit_recorder.clone(),
            );
        } else if PageStateObserver::should_start(&config.browser_url) {
            PageStateObserver::spawn(
                config.browser_url.clone(),
                config.context.clone(),
                session_state.clone(),
                Arc::clone(&engine),
                audit_recorder.clone(),
            );
        }

        Ok(Self {
            listener,
            browser_url: config.browser_url,
            engine,
            context: config.context,
            session_state,
            audit_recorder,
        })
    }

    pub fn local_addr(&self) -> Result<SocketAddr, CdpError> {
        self.listener.local_addr().context(IoSnafu)
    }

    pub async fn run(self) -> Result<(), CdpError> {
        let local_addr = self.local_addr()?;
        info!(
            listen = %local_addr,
            session_id = %self.context.session_id.as_str(),
            "CDP proxy server accepting connections"
        );

        loop {
            let (stream, address) = self.listener.accept().await.context(IoSnafu)?;
            let connection = CdpClientConnection::new(
                stream,
                local_addr,
                self.browser_url.clone(),
                Arc::clone(&self.engine),
                self.context.clone(),
                self.session_state.clone(),
                self.audit_recorder.clone(),
            );
            let session_id = self.context.session_id.as_str().to_owned();
            debug!(
                client = %address,
                session_id = %session_id,
                "accepted CDP proxy connection"
            );
            let handle = tokio::spawn(async move {
                match connection.run().await {
                    Ok(()) => debug!(
                        client = %address,
                        session_id = %session_id,
                        "CDP proxy connection closed"
                    ),
                    Err(error) => warn!(
                        error;
                        "CDP proxy connection failed",
                        client = %address,
                        session_id = %session_id
                    ),
                }
            });
            drop(handle);
        }
    }
}
