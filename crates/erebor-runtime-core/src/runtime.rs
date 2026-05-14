use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::mpsc::{self, Receiver, Sender},
};

use tokio::runtime::Runtime;

use crate::{BrowserCdpRuntimeConfig, GovernanceLayer, RuntimeError, RuntimeStartPlan};

pub type RuntimeFailureSender = Sender<RuntimeFailure>;

pub trait GovernanceRuntime: Send {
    fn layer(&self) -> GovernanceLayer;

    fn start(
        self: Box<Self>,
        runtime: &Runtime,
        failures: RuntimeFailureSender,
    ) -> Result<RunningRuntime, RuntimeError>;
}

pub struct RuntimeLauncher {
    control_listen: SocketAddr,
    runtimes: Vec<Box<dyn GovernanceRuntime>>,
}

impl RuntimeLauncher {
    #[must_use]
    pub fn new(control_listen: SocketAddr) -> Self {
        Self {
            control_listen,
            runtimes: Vec::new(),
        }
    }

    pub fn add_runtime<R>(&mut self, runtime: R)
    where
        R: GovernanceRuntime + 'static,
    {
        self.runtimes.push(Box::new(runtime));
    }

    pub fn start(self) -> Result<RuntimeSupervisor, RuntimeError> {
        if self.runtimes.is_empty() {
            return Err(RuntimeError::no_governance_runtimes());
        }

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .map_err(RuntimeError::build_async_runtime)?;
        let (failures, failure_rx) = mpsc::channel();
        let mut running = Vec::new();

        for governance_runtime in self.runtimes {
            running.push(governance_runtime.start(&runtime, failures.clone())?);
        }
        drop(failures);

        Ok(RuntimeSupervisor {
            control_listen: self.control_listen,
            running,
            failure_rx,
            _runtime: runtime,
        })
    }
}

pub struct RuntimeSupervisor {
    control_listen: SocketAddr,
    running: Vec<RunningRuntime>,
    failure_rx: Receiver<RuntimeFailure>,
    _runtime: Runtime,
}

impl RuntimeSupervisor {
    #[must_use]
    pub fn control_listen(&self) -> SocketAddr {
        self.control_listen
    }

    #[must_use]
    pub fn running(&self) -> &[RunningRuntime] {
        &self.running
    }

    pub fn wait(self) -> Result<(), RuntimeError> {
        let failure = self
            .failure_rx
            .recv()
            .map_err(|_| RuntimeError::no_governance_runtimes())?;

        Err(RuntimeError::runtime_exited(
            failure.layer.as_str(),
            failure.reason,
        ))
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeLaunchPlan {
    control_listen: SocketAddr,
    policy_paths: Vec<PathBuf>,
    definitions: Vec<RuntimeDefinition>,
}

impl RuntimeLaunchPlan {
    pub fn from_start_plan(
        control_listen: SocketAddr,
        plan: &RuntimeStartPlan,
    ) -> Result<Self, RuntimeError> {
        let mut definitions = Vec::new();

        for layer in plan.layers() {
            match layer {
                GovernanceLayer::BrowserCdp => {
                    let Some(browser_cdp) = plan.browser_cdp().cloned() else {
                        return Err(RuntimeError::unsupported_governance_layer(layer.as_str()));
                    };
                    definitions.push(RuntimeDefinition::BrowserCdp(browser_cdp));
                }
                GovernanceLayer::Mcp
                | GovernanceLayer::Terminal
                | GovernanceLayer::Network
                | GovernanceLayer::Saas
                | GovernanceLayer::Desktop
                | GovernanceLayer::InternalSystem => {
                    return Err(RuntimeError::unsupported_governance_layer(layer.as_str()));
                }
            }
        }

        Ok(Self {
            control_listen,
            policy_paths: plan.policies().to_vec(),
            definitions,
        })
    }

    #[must_use]
    pub fn control_listen(&self) -> SocketAddr {
        self.control_listen
    }

    #[must_use]
    pub fn policy_paths(&self) -> &[PathBuf] {
        &self.policy_paths
    }

    #[must_use]
    pub fn definitions(&self) -> &[RuntimeDefinition] {
        &self.definitions
    }

    #[must_use]
    pub fn layers(&self) -> Vec<GovernanceLayer> {
        self.definitions
            .iter()
            .map(RuntimeDefinition::layer)
            .collect()
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum RuntimeDefinition {
    BrowserCdp(BrowserCdpRuntimeConfig),
}

impl RuntimeDefinition {
    #[must_use]
    pub fn layer(&self) -> GovernanceLayer {
        match self {
            Self::BrowserCdp(_) => GovernanceLayer::BrowserCdp,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RuntimeFailure {
    layer: GovernanceLayer,
    reason: String,
}

impl RuntimeFailure {
    #[must_use]
    pub fn new(layer: GovernanceLayer, reason: impl Into<String>) -> Self {
        Self {
            layer,
            reason: reason.into(),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RunningRuntime {
    layer: GovernanceLayer,
    endpoint: String,
}

impl RunningRuntime {
    #[must_use]
    pub fn new(layer: GovernanceLayer, endpoint: impl Into<String>) -> Self {
        Self {
            layer,
            endpoint: endpoint.into(),
        }
    }

    #[must_use]
    pub fn layer(&self) -> GovernanceLayer {
        self.layer
    }

    #[must_use]
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }
}
