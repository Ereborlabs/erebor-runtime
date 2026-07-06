use prost::Message;

use crate::v1;

use super::super::{
    codec::{write_bytes_field, write_string_field, write_varint_field},
    decision::{decode_interception_decision, KIND_INTERCEPTION_DECISION},
    envelope::{decode_envelope, encode_envelope},
    Envelope, InterceptionDecisionKind,
};

#[test]
fn decodes_mediate_decision_payload() -> Result<(), String> {
    let mut mediate = Vec::new();
    write_string_field(&mut mediate, 1, "managed_browser_cdp");
    write_string_field(&mut mediate, 2, "browser_cdp");
    write_string_field(&mut mediate, 3, "ws://127.0.0.1:9222/");
    write_string_field(
        &mut mediate,
        5,
        "DevTools listening on ws://127.0.0.1:9222/devtools/browser/erebor",
    );
    write_varint_field(&mut mediate, 6, 1);

    let mut payload = Vec::new();
    write_varint_field(&mut payload, 1, 7);
    write_varint_field(&mut payload, 2, 4);
    write_string_field(&mut payload, 3, "mediate-browser");
    write_string_field(&mut payload, 4, "browser mediated");
    write_bytes_field(&mut payload, 8, &mediate);
    let decision = decode_interception_decision(&payload)?;

    assert_eq!(decision.request_id, 7);
    assert_eq!(decision.kind, InterceptionDecisionKind::Mediate);
    assert_eq!(
        decision
            .mediate
            .ok_or_else(|| String::from("missing mediation decision"))?
            .replacement_surface,
        "browser_cdp"
    );

    let envelope = Envelope {
        message_id: 3,
        correlation_id: 7,
        message_kind: String::from(KIND_INTERCEPTION_DECISION),
        payload,
        headers: Vec::new(),
    };
    assert_eq!(
        decode_envelope(&encode_envelope(&envelope))?.message_kind,
        KIND_INTERCEPTION_DECISION
    );
    Ok(())
}

#[test]
fn standalone_decision_decoder_accepts_canonical_prost_decision() -> Result<(), String> {
    let decision = v1::InterceptionDecision {
        request_id: 7,
        decision: v1::DecisionKind::Mediate as i32,
        rule_id: String::from("mediate-browser"),
        reason: String::from("browser mediated"),
        timeout_ms: 25,
        allow: None,
        deny: None,
        mediate: Some(v1::MediateDecision {
            kind: String::from("managed_browser_cdp"),
            replacement_surface: String::from("browser_cdp"),
            endpoint: String::from("ws://127.0.0.1:9222/"),
            lease_id: String::from("lease-fixture"),
            print_line: String::from(
                "DevTools listening on ws://127.0.0.1:9222/devtools/browser/erebor",
            ),
            keepalive: true,
        }),
    };

    let decoded = decode_interception_decision(&decision.encode_to_vec())?;
    let mediation = decoded
        .mediate
        .ok_or_else(|| String::from("missing decoded mediation"))?;

    assert_eq!(decoded.request_id, decision.request_id);
    assert_eq!(decoded.kind, InterceptionDecisionKind::Mediate);
    assert_eq!(decoded.rule_id, decision.rule_id);
    assert_eq!(decoded.reason, decision.reason);
    assert_eq!(mediation.kind, "managed_browser_cdp");
    assert_eq!(mediation.replacement_surface, "browser_cdp");
    assert_eq!(mediation.endpoint, "ws://127.0.0.1:9222/");
    assert_eq!(mediation.lease_id, "lease-fixture");
    assert!(mediation.keepalive);
    Ok(())
}
