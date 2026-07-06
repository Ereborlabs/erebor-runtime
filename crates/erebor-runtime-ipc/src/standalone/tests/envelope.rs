use prost::Message;

use crate::v1;

use super::{
    super::{
        decision::KIND_INTERCEPTION_DECISION,
        envelope::{decode_envelope, encode_envelope},
        request::KIND_INTERCEPTION_REQUEST,
        Envelope, Header,
    },
    decode_prost,
};

#[test]
fn envelope_round_trips_without_session_id() -> Result<(), String> {
    let envelope = Envelope {
        message_id: 2,
        correlation_id: 1,
        message_kind: String::from(KIND_INTERCEPTION_REQUEST),
        payload: vec![1, 2, 3],
        headers: vec![Header {
            key: String::from("interception_token"),
            value: String::from("token"),
        }],
    };

    let decoded = decode_envelope(&encode_envelope(&envelope))?;

    assert_eq!(decoded, envelope);
    Ok(())
}

#[test]
fn standalone_envelope_encoding_matches_canonical_prost_contract() -> Result<(), String> {
    let envelope = Envelope {
        message_id: 2,
        correlation_id: 1,
        message_kind: String::from(KIND_INTERCEPTION_REQUEST),
        payload: vec![1, 2, 3],
        headers: vec![Header {
            key: String::from("interception_token"),
            value: String::from("token"),
        }],
    };

    let decoded: v1::Envelope = decode_prost(&encode_envelope(&envelope))?;

    assert_eq!(decoded.protocol_version, v1::PROTOCOL_VERSION);
    assert_eq!(decoded.message_id, envelope.message_id);
    assert_eq!(decoded.correlation_id, envelope.correlation_id);
    assert_eq!(decoded.message_kind, envelope.message_kind);
    assert_eq!(decoded.payload, envelope.payload);
    assert_eq!(decoded.headers.len(), 1);
    assert_eq!(decoded.headers[0].key, "interception_token");
    assert_eq!(decoded.headers[0].value, "token");
    Ok(())
}

#[test]
fn canonical_prost_envelope_decodes_through_standalone_adapter() -> Result<(), String> {
    let envelope = v1::Envelope {
        protocol_version: v1::PROTOCOL_VERSION,
        message_id: 3,
        correlation_id: 2,
        message_kind: String::from(KIND_INTERCEPTION_DECISION),
        payload: vec![4, 5, 6],
        headers: vec![v1::Header {
            key: String::from("interception_token"),
            value: String::from("token"),
        }],
    };

    let decoded = decode_envelope(&envelope.encode_to_vec())?;

    assert_eq!(decoded.message_id, envelope.message_id);
    assert_eq!(decoded.correlation_id, envelope.correlation_id);
    assert_eq!(decoded.message_kind, envelope.message_kind);
    assert_eq!(decoded.payload, envelope.payload);
    assert_eq!(decoded.headers.len(), 1);
    assert_eq!(decoded.headers[0].key, "interception_token");
    assert_eq!(decoded.headers[0].value, "token");
    Ok(())
}
