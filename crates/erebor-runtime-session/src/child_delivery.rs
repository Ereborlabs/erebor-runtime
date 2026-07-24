use std::sync::{Arc, Mutex};

/// A bounded child-owned Codex result accepted only from the existing
/// authenticated hook route. This is an in-process daemon callback, not a
/// workload socket or a second process-guard protocol.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ChildContextDelivery {
    child_session_id: String,
    sequence: u64,
    kind: String,
    mode: String,
    selected_bytes: Vec<u8>,
}

impl ChildContextDelivery {
    #[must_use]
    pub fn new(
        child_session_id: impl Into<String>,
        sequence: u64,
        kind: impl Into<String>,
        mode: impl Into<String>,
        selected_bytes: Vec<u8>,
    ) -> Self {
        Self {
            child_session_id: child_session_id.into(),
            sequence,
            kind: kind.into(),
            mode: mode.into(),
            selected_bytes,
        }
    }

    #[must_use]
    pub fn child_session_id(&self) -> &str {
        &self.child_session_id
    }

    #[must_use]
    pub const fn sequence(&self) -> u64 {
        self.sequence
    }

    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    #[must_use]
    pub fn mode(&self) -> &str {
        &self.mode
    }

    #[must_use]
    pub fn selected_bytes(&self) -> &[u8] {
        &self.selected_bytes
    }
}

pub trait ChildContextDeliveryHandler: Send + Sync {
    fn publish_delivery(&self, delivery: ChildContextDelivery) -> std::result::Result<(), String>;
}

/// Startup-bound forwarding seam between the authenticated hook broker and
/// the daemon coordinator. It intentionally has no listener or wire format.
#[derive(Default)]
pub struct ChildContextDeliveryDispatcher {
    handler: Mutex<Option<Arc<dyn ChildContextDeliveryHandler>>>,
}

impl ChildContextDeliveryDispatcher {
    pub fn install(
        &self,
        handler: Arc<dyn ChildContextDeliveryHandler>,
    ) -> std::result::Result<(), String> {
        let mut installed = self
            .handler
            .lock()
            .map_err(|_error| String::from("child-delivery dispatcher state is unavailable"))?;
        if installed.is_some() {
            return Err(String::from("child-delivery dispatcher is already bound"));
        }
        *installed = Some(handler);
        Ok(())
    }
}

impl ChildContextDeliveryHandler for ChildContextDeliveryDispatcher {
    fn publish_delivery(&self, delivery: ChildContextDelivery) -> std::result::Result<(), String> {
        let handler = self
            .handler
            .lock()
            .map_err(|_error| String::from("child-delivery dispatcher state is unavailable"))?
            .clone()
            .ok_or_else(|| String::from("child-delivery dispatcher is not bound"))?;
        handler.publish_delivery(delivery)
    }
}
