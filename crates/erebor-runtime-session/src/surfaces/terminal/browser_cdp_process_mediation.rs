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

        let endpoint = match &self.mode {
            BrowserCdpMediationMode::FixedEndpoint { endpoint } => {
                let allowed_ports = effective_browser_cdp_allowed_ports(handler, endpoint)?;
                if let Some(requested_port) = remote_debugging_port(request.argv()) {
                    if !allowed_ports.contains(&requested_port) {
                        return Err(format!(
                            "requested remote debugging port {requested_port} is not allowed"
                        ));
                    }
                }
                endpoint.clone()
            }
            BrowserCdpMediationMode::LazySurface(lazy) => {
                let requested_port = remote_debugging_port(request.argv()).ok_or_else(|| {
                    String::from("managed browser CDP mediation requires --remote-debugging-port")
                })?;
                validate_requested_port(handler, requested_port)?;
                lazy.endpoint_for_requested_port(requested_port, handler)?
            }
        };

        Ok(
            SurfaceMediationDecision::new(handler.kind().as_str(), "browser_cdp", &endpoint)
                .with_lease_id(format!("{}-lease", handler.id()))
                .with_print_line(if handler.compatibility().print_devtools_listening_line() {
                    format!("DevTools listening on {}", devtools_browser_url(&endpoint))
                } else {
                    String::new()
                })
                .with_keepalive(handler.compatibility().keepalive()),
        )
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
        let private_remote_debugging_port = private_remote_debugging_port_for_request(
            handler.replacement().private_endpoint(),
            requested_port,
        )?;
        let mut surface = BrowserCdpSurface::new(
            self.config_template
                .clone()
                .with_listen(listen)
                .with_browser_remote_debugging_port(private_remote_debugging_port),
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

fn remote_debugging_port(args: &[String]) -> Option<u16> {
    let mut iter = args.iter().peekable();
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

fn effective_browser_cdp_allowed_ports(
    handler: &ProcessMediationHandlerConfig,
    endpoint: &str,
) -> Result<Vec<u16>, String> {
    if !handler.requested_endpoint().allowed_ports().is_empty() {
        return Ok(handler.requested_endpoint().allowed_ports().to_vec());
    }
    Ok(vec![endpoint_port(endpoint).ok_or_else(|| {
        String::from("browser_cdp mediation endpoint does not include a parseable port")
    })?])
}

fn validate_requested_port(
    handler: &ProcessMediationHandlerConfig,
    requested_port: u16,
) -> Result<(), String> {
    if !handler.requested_endpoint().allowed_ports().is_empty()
        && !handler
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

pub(crate) fn private_remote_debugging_port_for_request(
    private_endpoint: &ProcessMediationPrivateEndpointConfig,
    requested_port: u16,
) -> Result<Option<u16>, String> {
    match private_endpoint.port_strategy() {
        ProcessMediationPrivatePortStrategy::Ephemeral => Ok(None),
        ProcessMediationPrivatePortStrategy::RequestedPlusOffset => {
            let offset = private_endpoint.port_offset();
            requested_port.checked_add(offset).map(Some).ok_or_else(|| {
                format!(
                    "requested remote debugging port {requested_port} plus private endpoint offset {offset} exceeds u16"
                )
            })
        }
    }
}

fn endpoint_port(endpoint: &str) -> Option<u16> {
    let endpoint = endpoint
        .strip_prefix("ws://")
        .or_else(|| endpoint.strip_prefix("http://"))?;
    let host = endpoint.split('/').next().unwrap_or(endpoint);
    host.rsplit_once(':')?.1.parse().ok()
}

fn devtools_browser_url(endpoint: &str) -> String {
    format!(
        "{}/devtools/browser/erebor-managed-browser",
        endpoint.trim_end_matches('/')
    )
}
