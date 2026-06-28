use std::{collections::HashMap, fmt, sync::Arc};

use erebor_runtime_core::ProcessMediationPrivateEndpointConfig;
use erebor_runtime_ipc::v1::InterceptionRequest;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SessionMediationIntent {
    kind: String,
    replacement_surface: String,
    lease_id: String,
    allowed_ports: Vec<u16>,
    private_endpoint: ProcessMediationPrivateEndpointConfig,
    emit_compatibility_line: bool,
    keepalive: bool,
}

impl SessionMediationIntent {
    #[must_use]
    pub fn new(kind: impl Into<String>, replacement_surface: impl Into<String>) -> Self {
        Self {
            kind: kind.into(),
            replacement_surface: replacement_surface.into(),
            lease_id: String::new(),
            allowed_ports: Vec::new(),
            private_endpoint: ProcessMediationPrivateEndpointConfig::default(),
            emit_compatibility_line: false,
            keepalive: false,
        }
    }

    #[must_use]
    pub fn with_lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = lease_id.into();
        self
    }

    #[must_use]
    pub fn with_allowed_ports(mut self, ports: Vec<u16>) -> Self {
        self.allowed_ports = ports;
        self
    }

    #[must_use]
    pub const fn with_private_endpoint(
        mut self,
        private_endpoint: ProcessMediationPrivateEndpointConfig,
    ) -> Self {
        self.private_endpoint = private_endpoint;
        self
    }

    #[must_use]
    pub const fn with_compatibility_line(mut self, enabled: bool) -> Self {
        self.emit_compatibility_line = enabled;
        self
    }

    #[must_use]
    pub const fn with_keepalive(mut self, keepalive: bool) -> Self {
        self.keepalive = keepalive;
        self
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn replacement_surface(&self) -> &str {
        &self.replacement_surface
    }

    #[must_use]
    pub fn lease_id(&self) -> &str {
        &self.lease_id
    }

    #[must_use]
    pub fn allowed_ports(&self) -> &[u16] {
        &self.allowed_ports
    }

    #[must_use]
    pub const fn private_endpoint(&self) -> &ProcessMediationPrivateEndpointConfig {
        &self.private_endpoint
    }

    #[must_use]
    pub const fn emit_compatibility_line(&self) -> bool {
        self.emit_compatibility_line
    }

    #[must_use]
    pub const fn keepalive(&self) -> bool {
        self.keepalive
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SurfaceMediationOutcome {
    pub(super) kind: String,
    pub(super) replacement_surface: String,
    pub(super) endpoint: String,
    pub(super) lease_id: String,
    pub(super) print_line: String,
    pub(super) keepalive: bool,
}

impl SurfaceMediationOutcome {
    #[must_use]
    pub fn new(
        kind: impl Into<String>,
        replacement_surface: impl Into<String>,
        endpoint: impl Into<String>,
    ) -> Self {
        Self {
            kind: kind.into(),
            replacement_surface: replacement_surface.into(),
            endpoint: endpoint.into(),
            lease_id: String::new(),
            print_line: String::new(),
            keepalive: false,
        }
    }

    #[must_use]
    pub fn with_lease_id(mut self, lease_id: impl Into<String>) -> Self {
        self.lease_id = lease_id.into();
        self
    }

    #[must_use]
    pub fn with_print_line(mut self, print_line: impl Into<String>) -> Self {
        self.print_line = print_line.into();
        self
    }

    #[must_use]
    pub const fn with_keepalive(mut self, keepalive: bool) -> Self {
        self.keepalive = keepalive;
        self
    }
}

pub trait SurfaceMediationHandler: Send + Sync {
    fn surface(&self) -> &str;

    fn mediate(
        &self,
        request: &InterceptionRequest,
        intent: &SessionMediationIntent,
    ) -> Result<SurfaceMediationOutcome, String>;
}

#[derive(Clone, Default)]
pub struct SessionMediationRegistry {
    handlers: HashMap<String, Arc<dyn SurfaceMediationHandler>>,
}

impl SessionMediationRegistry {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn with_handler(mut self, handler: impl SurfaceMediationHandler + 'static) -> Self {
        self.register_handler(handler);
        self
    }

    pub fn register_handler(&mut self, handler: impl SurfaceMediationHandler + 'static) {
        self.handlers
            .insert(handler.surface().to_owned(), Arc::new(handler));
    }

    pub(super) fn mediate(
        &self,
        request: &InterceptionRequest,
        intent: &SessionMediationIntent,
    ) -> Result<SurfaceMediationOutcome, String> {
        let Some(handler) = self.handlers.get(intent.replacement_surface()) else {
            return Err(format!(
                "no mediation handler is registered for replacement surface `{}`",
                intent.replacement_surface()
            ));
        };
        handler.mediate(request, intent)
    }
}

impl fmt::Debug for SessionMediationRegistry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionMediationRegistry")
            .field("surfaces", &self.handlers.keys().collect::<Vec<_>>())
            .finish()
    }
}
