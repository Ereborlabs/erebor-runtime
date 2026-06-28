mod browser_cdp_mediation;
mod client;
mod constants;
mod decision;
mod endpoint;
mod handlers;
mod mediation;
mod platform;
mod server;
mod wire;

pub use browser_cdp_mediation::BrowserCdpMediationHandler;
pub use client::InterceptionBrokerClient;
pub use endpoint::RuntimeInterceptionEndpoint;
pub use handlers::{SessionInterceptionHandler, SessionInterceptionRouter};
pub use mediation::{
    SessionMediationIntent, SessionMediationRegistry, SurfaceMediationHandler,
    SurfaceMediationOutcome,
};
pub use server::{
    RuntimeInterceptionBroker, RuntimeInterceptionBrokerError, SessionInterceptionRegistration,
};

#[cfg(test)]
mod tests;
