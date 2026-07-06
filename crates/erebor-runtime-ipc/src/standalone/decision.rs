use super::{
    codec::{read_bytes, read_string, read_varint, skip_field},
    InterceptionDecision, InterceptionDecisionKind, MediateDecision,
};

pub(super) const KIND_GUARD_HELLO_ACK: &str = "erebor.runtime.ipc.v1.GuardHelloAck";
pub(super) const KIND_INTERCEPTION_DECISION: &str = "erebor.runtime.ipc.v1.InterceptionDecision";

const DECISION_ALLOW: i32 = 1;
const DECISION_DENY: i32 = 2;
const DECISION_REQUIRE_APPROVAL: i32 = 3;
const DECISION_MEDIATE: i32 = 4;

#[derive(Clone, Debug, Eq, PartialEq)]
pub(super) struct GuardHelloAck {
    pub(super) accepted: bool,
    pub(super) reason: String,
}

pub(super) fn decode_guard_hello_ack(bytes: &[u8]) -> Result<GuardHelloAck, String> {
    let mut cursor = 0;
    let mut ack = GuardHelloAck {
        accepted: false,
        reason: String::new(),
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (3, 0) => ack.accepted = read_varint(bytes, &mut cursor)? != 0,
            (4, 2) => ack.reason = read_string(bytes, &mut cursor)?,
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(ack)
}

pub(super) fn decode_interception_decision(bytes: &[u8]) -> Result<InterceptionDecision, String> {
    let mut cursor = 0;
    let mut decision = InterceptionDecision {
        request_id: 0,
        kind: InterceptionDecisionKind::Unknown,
        rule_id: String::new(),
        reason: String::new(),
        allow_exec_target: None,
        deny_exit_code: None,
        mediate: None,
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 0) => decision.request_id = read_varint(bytes, &mut cursor)?,
            (2, 0) => {
                decision.kind = match read_varint(bytes, &mut cursor)? as i32 {
                    DECISION_ALLOW => InterceptionDecisionKind::Allow,
                    DECISION_DENY => InterceptionDecisionKind::Deny,
                    DECISION_REQUIRE_APPROVAL => InterceptionDecisionKind::RequireApproval,
                    DECISION_MEDIATE => InterceptionDecisionKind::Mediate,
                    _ => InterceptionDecisionKind::Unknown,
                };
            }
            (3, 2) => decision.rule_id = read_string(bytes, &mut cursor)?,
            (4, 2) => decision.reason = read_string(bytes, &mut cursor)?,
            (6, 2) => {
                let allow = read_bytes(bytes, &mut cursor)?;
                decision.allow_exec_target = decode_allow_decision(&allow)?;
            }
            (7, 2) => {
                let deny = read_bytes(bytes, &mut cursor)?;
                decision.deny_exit_code = decode_deny_decision(&deny)?;
            }
            (8, 2) => {
                let mediate = read_bytes(bytes, &mut cursor)?;
                decision.mediate = Some(decode_mediate_decision(&mediate)?);
            }
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(decision)
}

fn decode_allow_decision(bytes: &[u8]) -> Result<Option<String>, String> {
    let mut cursor = 0;
    let mut exec_target = None;
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => exec_target = Some(read_string(bytes, &mut cursor)?),
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(exec_target)
}

fn decode_deny_decision(bytes: &[u8]) -> Result<Option<i32>, String> {
    let mut cursor = 0;
    let mut exit_code = None;
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 0) => exit_code = Some(read_varint(bytes, &mut cursor)? as i32),
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(exit_code)
}

fn decode_mediate_decision(bytes: &[u8]) -> Result<MediateDecision, String> {
    let mut cursor = 0;
    let mut decision = MediateDecision {
        kind: String::new(),
        replacement_surface: String::new(),
        endpoint: String::new(),
        lease_id: String::new(),
        print_line: String::new(),
        keepalive: false,
    };
    while cursor < bytes.len() {
        let key = read_varint(bytes, &mut cursor)?;
        let field = key >> 3;
        let wire = key & 0x07;
        match (field, wire) {
            (1, 2) => decision.kind = read_string(bytes, &mut cursor)?,
            (2, 2) => decision.replacement_surface = read_string(bytes, &mut cursor)?,
            (3, 2) => decision.endpoint = read_string(bytes, &mut cursor)?,
            (4, 2) => decision.lease_id = read_string(bytes, &mut cursor)?,
            (5, 2) => decision.print_line = read_string(bytes, &mut cursor)?,
            (6, 0) => decision.keepalive = read_varint(bytes, &mut cursor)? != 0,
            (_, wire) => skip_field(bytes, &mut cursor, wire)?,
        }
    }
    Ok(decision)
}
