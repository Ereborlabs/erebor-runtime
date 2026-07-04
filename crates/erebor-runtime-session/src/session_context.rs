use std::time::{SystemTime, UNIX_EPOCH};

use erebor_runtime_cdp::CdpSessionContext;
use erebor_runtime_core::{
    RuntimeAuditConfig, SessionActorLayerConfig, SessionAdoptPlan, SessionRunPlan,
    SessionRunnerKind,
};
use erebor_runtime_events::{ActorIdentity, ActorKind, SessionId};

pub(crate) trait SessionPlanContext {
    fn audit(&self) -> &RuntimeAuditConfig;
    fn session_id(&self) -> &SessionId;
    fn actor(&self) -> &SessionActorLayerConfig;
    fn runner_kind(&self) -> SessionRunnerKind;
}

impl SessionPlanContext for SessionRunPlan {
    fn audit(&self) -> &RuntimeAuditConfig {
        self.audit()
    }

    fn session_id(&self) -> &SessionId {
        self.session_id()
    }

    fn actor(&self) -> &SessionActorLayerConfig {
        self.actor()
    }

    fn runner_kind(&self) -> SessionRunnerKind {
        self.runner().kind()
    }
}

impl SessionPlanContext for SessionAdoptPlan {
    fn audit(&self) -> &RuntimeAuditConfig {
        self.audit()
    }

    fn session_id(&self) -> &SessionId {
        self.session_id()
    }

    fn actor(&self) -> &SessionActorLayerConfig {
        self.actor()
    }

    fn runner_kind(&self) -> SessionRunnerKind {
        self.runner().kind()
    }
}

pub(crate) struct CdpSessionContexts;

impl CdpSessionContexts {
    pub(crate) fn from_plan(plan: &impl SessionPlanContext) -> CdpSessionContext {
        CdpSessionContext {
            session_id: plan.session_id().clone(),
            actor: ActorIdentity {
                id: plan.actor().id.clone(),
                kind: plan.actor().kind.clone(),
            },
            timestamp: Self::timestamp(),
        }
    }

    pub(crate) fn runtime(session_prefix: &str) -> CdpSessionContext {
        CdpSessionContext {
            session_id: SessionId::new(format!("{session_prefix}-{}", std::process::id())),
            actor: ActorIdentity {
                id: String::from("erebor-runtime-session"),
                kind: ActorKind::System,
            },
            timestamp: Self::timestamp(),
        }
    }

    fn timestamp() -> String {
        let seconds = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |duration| duration.as_secs());

        format!("unix:{seconds}")
    }
}
