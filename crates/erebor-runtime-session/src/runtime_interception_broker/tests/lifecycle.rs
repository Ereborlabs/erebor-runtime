use erebor_runtime_ipc::v1::{
    GuardLifecycleEvent, GuardLifecycleEventKind, GuardLifecycleReply, GuardLifecycleReplyKind,
};

use super::super::{GuardLifecycleHandler, SessionInterceptionRouter};

struct HoldManagedHook;

impl GuardLifecycleHandler for HoldManagedHook {
    fn decide_guard_lifecycle(&self, event: &GuardLifecycleEvent) -> GuardLifecycleReply {
        let decision = if GuardLifecycleEventKind::try_from(event.event).ok()
            == Some(GuardLifecycleEventKind::Exec)
        {
            GuardLifecycleReplyKind::Hold
        } else {
            GuardLifecycleReplyKind::Ignore
        };
        GuardLifecycleReply {
            request_id: event.request_id,
            decision: decision as i32,
            reason: String::from("test lifecycle handler reply"),
        }
    }
}

#[test]
fn broker_router_dispatches_generic_lifecycle_facts_to_the_managed_handler() {
    let router = SessionInterceptionRouter::new().with_guard_lifecycle_handler(HoldManagedHook);
    let event = GuardLifecycleEvent {
        request_id: 51,
        event: GuardLifecycleEventKind::Exec as i32,
        pid: 801,
        exec_history: vec![String::from("/usr/lib/erebor/hook")],
        parent_pid: 800,
        child_pid: 0,
        exited_successfully: false,
    };

    let reply = router.route_guard_lifecycle(&event);

    assert_eq!(reply.request_id, event.request_id);
    assert_eq!(reply.decision, GuardLifecycleReplyKind::Hold as i32);
}

#[test]
fn broker_router_ignores_lifecycle_facts_without_a_managed_handler() {
    let event = GuardLifecycleEvent {
        request_id: 52,
        event: GuardLifecycleEventKind::Exit as i32,
        pid: 801,
        exec_history: Vec::new(),
        parent_pid: 0,
        child_pid: 0,
        exited_successfully: true,
    };

    let reply = SessionInterceptionRouter::new().route_guard_lifecycle(&event);

    assert_eq!(reply.request_id, event.request_id);
    assert_eq!(reply.decision, GuardLifecycleReplyKind::Ignore as i32);
}
