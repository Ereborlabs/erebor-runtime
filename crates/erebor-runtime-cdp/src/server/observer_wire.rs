use cdp_protocol::{types::CallId, types::Method};
use erebor_runtime_core::AuditRecord;
use erebor_runtime_events::{
    ActionKind, EventId, ExecutionSurface, RiskLevel, RiskMetadata, TargetRef,
};
use erebor_runtime_policy::Decision;
use erebor_runtime_telemetry::{debug, warn};
use futures_util::SinkExt;
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use snafu::{Location, ResultExt};
use tokio::net::TcpStream;
use tokio_tungstenite::{
    tungstenite::{Error as WebSocketError, Message},
    MaybeTlsStream, WebSocketStream,
};

use super::{audit::CdpAuditRecorder, CdpEngine};
use crate::{
    error::{BrowserStateSyncSnafu, InvalidProtocolSnafu},
    BrowserTargetId, CdpError, CdpSessionContext,
};

pub(super) type BrowserSocket = WebSocketStream<MaybeTlsStream<TcpStream>>;
pub(super) const BOOTSTRAP_RESPONSE_TIMEOUT: tokio::time::Duration =
    tokio::time::Duration::from_secs(10);
pub(super) const RECONNECT_DELAY: tokio::time::Duration = tokio::time::Duration::from_millis(250);
pub(super) const SET_DISCOVER_TARGETS_ID: CallId = 10_000;
pub(super) const SET_AUTO_ATTACH_ID: CallId = 10_001;
pub(super) const GET_TARGETS_ID: CallId = 10_002;
pub(super) const PAGE_ENABLE_ID: CallId = 10_003;
pub(super) const RUNTIME_ENABLE_ID: CallId = 10_004;
pub(super) const GET_FRAME_TREE_ID: CallId = 10_005;
pub(super) const FETCH_ENABLE_ID: CallId = 10_006;
const TARGET_COMMAND_ID_START: CallId = 20_000;

pub(super) struct ObserverSocket;

impl ObserverSocket {
    pub(super) async fn send_method<T>(
        socket: &mut BrowserSocket,
        method: T,
        id: CallId,
    ) -> Result<(), CdpError>
    where
        T: Method + Serialize,
    {
        let payload =
            serde_json::to_string(&method.to_method_call(id)).context(InvalidProtocolSnafu)?;
        socket
            .send(Message::Text(payload.into()))
            .await
            .map_err(WebSocketFailure::from_error)
    }

    pub(super) async fn send_session_method<T>(
        socket: &mut BrowserSocket,
        method: T,
        id: CallId,
        session_id: &str,
    ) -> Result<(), CdpError>
    where
        T: Method + Serialize,
    {
        let mut payload =
            serde_json::to_value(method.to_method_call(id)).context(InvalidProtocolSnafu)?;
        payload["sessionId"] = Value::String(session_id.to_owned());
        socket
            .send(Message::Text(payload.to_string().into()))
            .await
            .map_err(WebSocketFailure::from_error)
    }

    pub(super) async fn send_target_method<T>(
        socket: &mut BrowserSocket,
        method: T,
        id: CallId,
        session_id: Option<&str>,
    ) -> Result<(), CdpError>
    where
        T: Method + Serialize,
    {
        if let Some(session_id) = session_id {
            Self::send_session_method(socket, method, id, session_id).await
        } else {
            Self::send_method(socket, method, id).await
        }
    }
}

#[derive(Debug, Default)]
pub(super) struct FrameTreeRequests {
    requests: std::collections::HashMap<CallId, BrowserTargetId>,
}

impl FrameTreeRequests {
    pub(super) fn insert(&mut self, id: CallId, target_id: BrowserTargetId) {
        self.requests.insert(id, target_id);
    }

    pub(super) fn remove(&mut self, id: CallId) -> Option<BrowserTargetId> {
        self.requests.remove(&id)
    }

    pub(super) fn remove_for_response(
        &mut self,
        source: &str,
    ) -> Result<Option<BrowserTargetId>, CdpError> {
        let response: ObserverBootstrapMessageHead =
            serde_json::from_str(source).context(InvalidProtocolSnafu)?;
        Ok(response.id.and_then(|id| self.remove(id)))
    }
}

#[derive(Debug)]
pub(super) struct ObserverCommandIds {
    next: CallId,
}

impl Default for ObserverCommandIds {
    fn default() -> Self {
        Self {
            next: TARGET_COMMAND_ID_START,
        }
    }
}

impl ObserverCommandIds {
    pub(super) fn next(&mut self) -> CallId {
        let id = self.next;
        self.next = self.next.saturating_add(1);
        id
    }
}

pub(super) struct InternalResponseParser;

impl InternalResponseParser {
    pub(super) fn parse<M>(source: &str) -> Result<M::ReturnObject, CdpError>
    where
        M: Method,
    {
        let response: ObserverBootstrapMethodResponse<M::ReturnObject> =
            serde_json::from_str(source).context(InvalidProtocolSnafu)?;
        if let Some(error) = response.error {
            return BrowserStateSyncSnafu {
                reason: format!("{} failed: {}", M::NAME, error.message),
            }
            .fail();
        }

        response.result.ok_or_else(|| {
            BrowserStateSyncSnafu {
                reason: format!("{} did not return a result", M::NAME),
            }
            .build()
        })
    }
}

pub(super) struct StateRecoveryAuditor;

impl StateRecoveryAuditor {
    pub(super) fn audit(
        engine: &CdpEngine,
        audit_recorder: Option<&CdpAuditRecorder>,
        context: &CdpSessionContext,
        trigger: &'static str,
        target_id: Option<&BrowserTargetId>,
    ) {
        let target = target_id.map(|target_id| TargetRef {
            label: Some(target_id.as_str().to_owned()),
            uri: None,
        });
        let event = erebor_runtime_events::RuntimeEvent {
            id: EventId::new(format!(
                "cdp-state-recovery-{trigger}-{}",
                target_id.map_or("browser", BrowserTargetId::as_str)
            )),
            session_id: context.session_id.clone(),
            actor: context.actor.clone(),
            surface: ExecutionSurface::BrowserCdp,
            action: ActionKind::BrowserStateRecovery,
            target,
            payload: json!({
                "kind": "state_recovery",
                "trigger": trigger,
                "target_id": target_id.map(BrowserTargetId::as_str),
            }),
            risk: RiskMetadata {
                level: RiskLevel::Low,
                reasons: vec![String::from("CDP observer state recovery")],
            },
            timestamp: context.timestamp.clone(),
        };
        let decision = Decision::Allow {
            rule_id: Some(String::from("cdp-state-maintenance")),
        };
        let record = AuditRecord {
            event,
            policy_decision: decision.clone(),
            final_decision: decision,
            context_pin: None,
        };

        if let Some(error) = engine.record_audit_record(&record) {
            warn!(
                error;
                "failed to audit CDP state recovery",
                trigger = %trigger,
                session_id = %context.session_id.as_str()
            );
        } else {
            debug!(
                "audited CDP state recovery",
                trigger = %trigger,
                session_id = %context.session_id.as_str()
            );
        }

        CdpAuditRecorder::record_optional(audit_recorder, Some(&record));
    }
}

#[derive(Debug, Deserialize)]
pub(super) struct ObserverBootstrapMessageHead {
    pub(super) id: Option<CallId>,
    pub(super) method: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ObserverBootstrapMethodResponse<T> {
    result: Option<T>,
    error: Option<ObserverBootstrapMethodError>,
}

#[derive(Debug, Deserialize)]
struct ObserverBootstrapMethodError {
    message: String,
}

pub(super) struct WebSocketFailure;

impl WebSocketFailure {
    pub(super) fn from_error(error: WebSocketError) -> CdpError {
        CdpError::WebSocket {
            source: Box::new(error),
            location: Location::default(),
        }
    }
}
