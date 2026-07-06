use std::sync::Arc;

use erebor_runtime_cdp::CdpSessionContext;
use erebor_runtime_e2e::JsonWebSocketHandler;
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};
use serde_json::json;

pub fn session_context() -> CdpSessionContext {
    CdpSessionContext {
        session_id: SessionId::new("e2e-cdp-session"),
        actor: ActorIdentity {
            id: String::from("erebor-runtime-cdp-e2e"),
            kind: ActorKind::System,
        },
        timestamp: String::from("2026-05-14T00:00:00Z"),
    }
}

pub fn mini_cdp_handler() -> JsonWebSocketHandler {
    Arc::new(|command| {
        command.get("id").cloned().map(|id| {
            json!({
                "id": id,
                "result": {
                    "ereborMiniCdp": true
                }
            })
        })
    })
}
