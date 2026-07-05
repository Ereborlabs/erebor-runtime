//! Browser/CDP enforcement surface contracts for erebor-runtime.

mod browser;
mod error;
mod message;
mod method;
mod protocol;
mod proxy;
mod runtime;
mod server;
mod state;
mod target_graph;

pub use browser::{BrowserSessionManager, BrowserSessionMetadata, GovernedBrowserSession};
pub use error::CdpError;
pub use message::{
    CdpCommandEnforcer, CdpEnforcementAction, CdpEnforcementOutcome, CdpEventEnforcer,
    CdpEventObserver, CdpSessionContext,
};
pub use method::{CdpCommandClassification, CdpMethodRegistry, CdpMethodRole};
pub use protocol::{CdpCommand, CdpCommandDecoder, CdpEvent, CdpEventDecoder, GovernedCdpCommand};
pub use proxy::{CdpBackend, CdpBackendResponse, CdpMessageProxy, CdpProxyAction};
pub use runtime::BrowserCdpSurface;
pub use server::{CdpProxyServer, CdpProxyServerConfig};
pub use state::{CdpSessionSnapshot, CdpSessionState, PageStatus, PageStatusKind};
pub use target_graph::{
    BrowserTarget, BrowserTargetGraph, BrowserTargetId, BrowserTargetKind, BrowserTargetStatus,
    ClientTargetSessions, ExecutionContextState, FrameId, FrameState,
};
