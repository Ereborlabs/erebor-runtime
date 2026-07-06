use std::{
    collections::HashMap,
    fmt, io,
    net::SocketAddr,
    path::PathBuf,
    sync::{mpsc, Arc, Mutex},
};

use erebor_runtime_cdp::{BrowserCdpSurface, CdpSessionContext};
use erebor_runtime_core::{
    BrowserCdpSurfaceConfig, ProcessExecInterceptionRequest, ProcessMediationHandlerConfig,
    ProcessMediationPrivateEndpointConfig, ProcessMediationPrivatePortStrategy,
    ProcessMediationReplacementSurface, RunningSessionSurface, RuntimeAuditConfig,
    SessionSurfaceService, SurfaceMediationDecision,
};
use erebor_runtime_policy::PolicySet;
use erebor_runtime_terminal::TerminalProcessMediationCapability;
use tokio::runtime::Runtime;

#[derive(Clone)]
pub struct BrowserCdpProcessMediationCapability {
    mode: BrowserCdpMediationMode,
}

#[derive(Clone)]
enum BrowserCdpMediationMode {
    FixedEndpoint { endpoint: String },
    LazySurface(Arc<LazyBrowserCdpMediation>),
}

struct LazyBrowserCdpMediation {
    config_template: BrowserCdpSurfaceConfig,
    policy_set: PolicySet,
    context: CdpSessionContext,
    audit_jsonl: Option<PathBuf>,
    audit: RuntimeAuditConfig,
    runtime: Runtime,
    running: Mutex<HashMap<u16, RunningSessionSurface>>,
}

impl BrowserCdpProcessMediationCapability {
    #[must_use]
    pub fn new(endpoint: impl Into<String>) -> Self {
        Self {
            mode: BrowserCdpMediationMode::FixedEndpoint {
                endpoint: endpoint.into(),
            },
        }
    }

    pub fn lazy(
        config_template: BrowserCdpSurfaceConfig,
        policy_set: PolicySet,
        context: CdpSessionContext,
        audit_jsonl: Option<PathBuf>,
        audit: RuntimeAuditConfig,
    ) -> Result<Self, io::Error> {
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()?;

        Ok(Self {
            mode: BrowserCdpMediationMode::LazySurface(Arc::new(LazyBrowserCdpMediation {
                config_template,
                policy_set,
                context,
                audit_jsonl,
                audit,
                runtime,
                running: Mutex::new(HashMap::new()),
            })),
        })
    }
}

impl fmt::Debug for BrowserCdpProcessMediationCapability {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.mode {
            BrowserCdpMediationMode::FixedEndpoint { endpoint } => formatter
                .debug_struct("BrowserCdpProcessMediationCapability")
                .field("mode", &"fixed_endpoint")
                .field("endpoint", endpoint)
                .finish(),
            BrowserCdpMediationMode::LazySurface(_) => formatter
                .debug_struct("BrowserCdpProcessMediationCapability")
                .field("mode", &"lazy_surface")
                .finish(),
        }
    }
}

impl TerminalProcessMediationCapability for BrowserCdpProcessMediationCapability {
    fn mediate_process_exec(
        &self,
        request: &ProcessExecInterceptionRequest<'_>,
        handler: &ProcessMediationHandlerConfig,
    ) -> Result<SurfaceMediationDecision, String> {
        match handler.replacement().surface() {
            ProcessMediationReplacementSurface::BrowserCdp => {}
        }

        let mediation_request = BrowserCdpMediationRequest::new(request, handler);
        let endpoint = match &self.mode {
            BrowserCdpMediationMode::FixedEndpoint { endpoint } => {
                mediation_request.fixed_endpoint(endpoint)?
            }
            BrowserCdpMediationMode::LazySurface(lazy) => {
                let requested_port = mediation_request.require_requested_remote_debugging_port()?;
                mediation_request.validate_requested_port(requested_port)?;
                lazy.endpoint_for_requested_port(requested_port, handler)?
            }
        };

        Ok(mediation_request.mediation_decision(&endpoint))
    }
}

impl LazyBrowserCdpMediation {
    fn endpoint_for_requested_port(
        &self,
        requested_port: u16,
        handler: &ProcessMediationHandlerConfig,
    ) -> Result<String, String> {
        let mut running = self
            .running
            .lock()
            .map_err(|_| String::from("browser CDP mediation state is poisoned"))?;
        if let Some(surface) = running.get(&requested_port) {
            return Ok(surface.endpoint().to_owned());
        }

        let listen = SocketAddr::new(self.config_template.listen().ip(), requested_port);
        let private_remote_debugging_port =
            PrivateRemoteDebuggingPort::new(handler.replacement().private_endpoint())
                .for_requested_port(requested_port)?;
        let mut surface = BrowserCdpSurface::new(
            BrowserCdpSurfaceConfig::from_template_for_runtime_browser(
                &self.config_template,
                listen,
                private_remote_debugging_port,
            ),
            self.policy_set.clone(),
            self.context.clone(),
        )
        .with_audit_config(self.audit.clone());
        if let Some(audit_jsonl) = self.audit_jsonl.as_ref() {
            surface = surface.with_audit_jsonl(audit_jsonl.clone());
        }
        let (failures, _failure_rx) = mpsc::channel();
        let running_surface = Box::new(surface)
            .start(&self.runtime, failures)
            .map_err(|error| error.to_string())?;
        let endpoint = running_surface.endpoint().to_owned();
        running.insert(requested_port, running_surface);
        Ok(endpoint)
    }
}

struct BrowserCdpMediationRequest<'a> {
    request: &'a ProcessExecInterceptionRequest<'a>,
    handler: &'a ProcessMediationHandlerConfig,
}

impl<'a> BrowserCdpMediationRequest<'a> {
    const fn new(
        request: &'a ProcessExecInterceptionRequest<'a>,
        handler: &'a ProcessMediationHandlerConfig,
    ) -> Self {
        Self { request, handler }
    }

    fn fixed_endpoint(&self, endpoint: &str) -> Result<String, String> {
        if let Some(requested_port) = self.requested_remote_debugging_port() {
            BrowserCdpFixedEndpoint::new(endpoint, self.handler)
                .validate_requested_port(requested_port)?;
        }
        Ok(endpoint.to_owned())
    }

    fn require_requested_remote_debugging_port(&self) -> Result<u16, String> {
        self.requested_remote_debugging_port().ok_or_else(|| {
            String::from("managed browser CDP mediation requires --remote-debugging-port")
        })
    }

    fn validate_requested_port(&self, requested_port: u16) -> Result<(), String> {
        BrowserCdpAllowedPorts::new(self.handler).validate_requested_port(requested_port)
    }

    fn mediation_decision(&self, endpoint: &str) -> SurfaceMediationDecision {
        SurfaceMediationDecision::from_parts(
            self.handler.kind().as_str(),
            "browser_cdp",
            endpoint,
            format!("{}-lease", self.handler.id()),
            self.print_line(endpoint),
            self.handler.compatibility().keepalive(),
        )
    }

    fn requested_remote_debugging_port(&self) -> Option<u16> {
        RemoteDebuggingArguments::new(self.request.argv()).remote_debugging_port()
    }

    fn print_line(&self, endpoint: &str) -> String {
        if self.handler.compatibility().print_devtools_listening_line() {
            format!(
                "DevTools listening on {}",
                BrowserCdpMediationEndpoint::new(endpoint).devtools_browser_url()
            )
        } else {
            String::new()
        }
    }
}

struct BrowserCdpFixedEndpoint<'a> {
    endpoint: &'a str,
    handler: &'a ProcessMediationHandlerConfig,
}

impl<'a> BrowserCdpFixedEndpoint<'a> {
    const fn new(endpoint: &'a str, handler: &'a ProcessMediationHandlerConfig) -> Self {
        Self { endpoint, handler }
    }

    fn validate_requested_port(&self, requested_port: u16) -> Result<(), String> {
        if self.handler.requested_endpoint().allowed_ports().is_empty() {
            let endpoint_port = BrowserCdpMediationEndpoint::new(self.endpoint)
                .port()
                .ok_or_else(|| {
                    String::from("browser_cdp mediation endpoint does not include a parseable port")
                })?;
            if endpoint_port == requested_port {
                return Ok(());
            }
            return Err(format!(
                "requested remote debugging port {requested_port} is not allowed"
            ));
        }

        BrowserCdpAllowedPorts::new(self.handler).validate_requested_port(requested_port)
    }
}

struct BrowserCdpAllowedPorts<'a> {
    handler: &'a ProcessMediationHandlerConfig,
}

impl<'a> BrowserCdpAllowedPorts<'a> {
    const fn new(handler: &'a ProcessMediationHandlerConfig) -> Self {
        Self { handler }
    }

    fn validate_requested_port(&self, requested_port: u16) -> Result<(), String> {
        if !self.handler.requested_endpoint().allowed_ports().is_empty()
            && !self
                .handler
                .requested_endpoint()
                .allowed_ports()
                .contains(&requested_port)
        {
            return Err(format!(
                "requested remote debugging port {requested_port} is not allowed"
            ));
        }
        Ok(())
    }
}

pub(crate) struct PrivateRemoteDebuggingPort<'a> {
    private_endpoint: &'a ProcessMediationPrivateEndpointConfig,
}

impl<'a> PrivateRemoteDebuggingPort<'a> {
    pub(crate) const fn new(private_endpoint: &'a ProcessMediationPrivateEndpointConfig) -> Self {
        Self { private_endpoint }
    }

    pub(crate) fn for_requested_port(&self, requested_port: u16) -> Result<Option<u16>, String> {
        match self.private_endpoint.port_strategy() {
            ProcessMediationPrivatePortStrategy::Ephemeral => Ok(None),
            ProcessMediationPrivatePortStrategy::RequestedPlusOffset => {
                let offset = self.private_endpoint.port_offset();
                requested_port.checked_add(offset).map(Some).ok_or_else(|| {
                    format!(
                        "requested remote debugging port {requested_port} plus private endpoint offset {offset} exceeds u16"
                    )
                })
            }
        }
    }
}

struct BrowserCdpMediationEndpoint<'a> {
    endpoint: &'a str,
}

impl<'a> BrowserCdpMediationEndpoint<'a> {
    const fn new(endpoint: &'a str) -> Self {
        Self { endpoint }
    }

    fn port(&self) -> Option<u16> {
        let endpoint = self
            .endpoint
            .strip_prefix("ws://")
            .or_else(|| self.endpoint.strip_prefix("http://"))?;
        let host = endpoint.split('/').next().unwrap_or(endpoint);
        host.rsplit_once(':')?.1.parse().ok()
    }

    fn devtools_browser_url(&self) -> String {
        format!(
            "{}/devtools/browser/erebor-managed-browser",
            self.endpoint.trim_end_matches('/')
        )
    }
}

struct RemoteDebuggingArguments<'a> {
    args: &'a [String],
}

impl<'a> RemoteDebuggingArguments<'a> {
    const fn new(args: &'a [String]) -> Self {
        Self { args }
    }

    fn remote_debugging_port(&self) -> Option<u16> {
        let mut iter = self.args.iter().peekable();
        while let Some(argument) = iter.next() {
            if let Some(port) = argument.strip_prefix("--remote-debugging-port=") {
                return port.parse().ok();
            }
            if argument == "--remote-debugging-port" {
                return iter.peek().and_then(|port| port.parse().ok());
            }
        }
        None
    }
}
