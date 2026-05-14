use erebor_runtime_core::{
    BrowserCdpRuntimeConfig, GovernanceLayer, GovernanceRuntime, RunningRuntime, RuntimeError,
    RuntimeFailure, RuntimeFailureSender,
};
use erebor_runtime_policy::PolicySet;
use tokio::runtime::Runtime;
use tracing::{debug, error, info};

use crate::{BrowserSessionManager, CdpSessionContext};

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
        info!(
            listen = %self.config.listen(),
            layer = layer.as_str(),
            "starting CDP governance runtime"
        );
        if let Some(browser_url) = self.config.browser_url() {
            debug!(
                browser_url = %browser_url,
                layer = layer.as_str(),
                "using configured CDP upstream"
            );
        } else {
            debug!(
                headless = self.config.browser().headless(),
                layer = layer.as_str(),
                "launching owned browser for CDP runtime"
            );
        }
        let session = runtime
            .block_on(
                BrowserSessionManager::new(self.config, self.policy_set, self.context)
                    .create_session(),
            )
            .map_err(|error| RuntimeError::runtime_start(layer.as_str(), error.to_string()))?;
        let endpoint = session.public_endpoint().to_owned();
        let lease_id = session.lease_id().to_owned();

        let handle = runtime.spawn(async move {
            if let Err(error) = session.run().await {
                error!(
                    layer = layer.as_str(),
                    lease_id = %lease_id,
                    error = %error,
                    "CDP governance runtime failed"
                );
                let _result = failures.send(RuntimeFailure::new(layer, error.to_string()));
            }
        });
        drop(handle);

        Ok(RunningRuntime::new(layer, endpoint))
    }
}
