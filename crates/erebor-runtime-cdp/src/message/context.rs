use erebor_runtime_events::{ActorIdentity, SessionId};

#[derive(Clone, Debug, PartialEq)]
pub struct CdpSessionContext {
    pub session_id: SessionId,
    pub actor: ActorIdentity,
    pub timestamp: String,
}
