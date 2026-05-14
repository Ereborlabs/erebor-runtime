use erebor_runtime_core::{
    BrowserCdpRuntimeConfig, GovernanceLayer, GovernanceRuntime, LocalEnforcementEngine,
    RunningRuntime, RuntimeError, RuntimeFailure, RuntimeFailureSender,
};
use erebor_runtime_policy::PolicySet;
use tokio::runtime::Runtime;
use tracing::{debug, error, info};

use crate::{CdpProxyServer, CdpProxyServerConfig, CdpSessionContext};

pub struct BrowserCdpRuntime {
    config: BrowserCdpRuntimeConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
}

impl BrowserCdpRuntime {
    #[must_use]
    pub fn new(
        config: BrowserCdpRuntimeConfig,
        policy_set: PolicySet,
        context: CdpSessionContext,
    ) -> Self {
        Self {
            config,
            policy_set,
            context,
        }
    }
}

impl GovernanceRuntime for BrowserCdpRuntime {
    fn layer(&self) -> GovernanceLayer {
        GovernanceLayer::BrowserCdp
    }

    fn start(
        self: Box<Self>,
        runtime: &Runtime,
        failures: RuntimeFailureSender,
    ) -> Result<RunningRuntime, RuntimeError> {
        let layer = self.layer();
        let engine = LocalEnforcementEngine::new(self.policy_set);
        let config = CdpProxyServerConfig {
            listen: self.config.listen(),
            browser_url: self.config.browser_url().to_owned(),
            context: self.context,
        };
        info!(
            listen = %config.listen,
            layer = layer.as_str(),
            "starting CDP governance runtime"
        );
        debug!(
            browser_url = %config.browser_url,
            layer = layer.as_str(),
            "configured CDP upstream"
        );
        let server = runtime
            .block_on(CdpProxyServer::bind(config, engine))
            .map_err(|error| RuntimeError::runtime_start(layer.as_str(), error.to_string()))?;
        let endpoint = server
            .local_addr()
            .map_err(|error| RuntimeError::runtime_start(layer.as_str(), error.to_string()))?;

        let handle = runtime.spawn(async move {
            if let Err(error) = server.run().await {
                error!(
                    layer = layer.as_str(),
                    error = %error,
                    "CDP governance runtime failed"
                );
                let _result = failures.send(RuntimeFailure::new(layer, error.to_string()));
            }
        });
        drop(handle);

        Ok(RunningRuntime::new(layer, endpoint.to_string()))
    }
}
