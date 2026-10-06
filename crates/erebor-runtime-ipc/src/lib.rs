//! Generated Runtime and Araphor gRPC contracts and bounded Runtime Unix transport.

pub mod transport;
pub mod v1;

pub mod araphor {
    tonic::include_proto!("erebor.mithril.control.v1");
}

#[cfg(test)]
mod tests {
    use prost::Message as _;

    use super::araphor;

    #[test]
    fn trace_metadata_roundtrip() -> Result<(), prost::DecodeError> {
        let detail: Box<araphor::TraceDetail> = araphor::TraceDetail {
            source: b"BEGIN { printf(\"ready\\n\"); }".to_vec(),
            requested: Some(araphor::InputSelection {
                target: "pod/ns/name".into(),
                ..Default::default()
            }),
            ..Default::default()
        }
        .into();
        let frame = araphor::TraceFrame {
            payload: Some(araphor::trace_frame::Payload::Metadata(detail)),
            ..Default::default()
        };
        let bytes = frame.encode_to_vec();
        assert_eq!(araphor::TraceFrame::decode(bytes.as_slice())?, frame);
        Ok(())
    }
}
