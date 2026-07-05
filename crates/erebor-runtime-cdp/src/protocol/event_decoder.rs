use cdp_protocol::types::Event as ProtocolEvent;

use super::{
    wire::{IncomingEventHead, ProtocolWire},
    CdpEvent,
};
use crate::{error::UnsupportedMethodSnafu, CdpError, CdpMethodRegistry};

pub struct CdpEventDecoder;

impl CdpEventDecoder {
    pub fn decode(source: &str) -> Result<Option<CdpEvent>, CdpError> {
        let head: IncomingEventHead = ProtocolWire::deserialize(source)?;
        let Some(method) = head.method else {
            return Ok(None);
        };

        if !CdpMethodRegistry::is_context(&method) {
            return Ok(None);
        }

        let event: ProtocolEvent = ProtocolWire::deserialize(source)?;
        CdpEvent::from_protocol(event, head.session_id)?
            .ok_or_else(|| UnsupportedMethodSnafu { method }.build())
            .map(Some)
    }
}
