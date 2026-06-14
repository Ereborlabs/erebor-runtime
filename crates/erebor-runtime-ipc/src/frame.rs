use prost::Message;

use crate::IpcProtocolError;

pub const MAGIC: [u8; 4] = *b"ERB1";
pub const HEADER_LEN: usize = 12;
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u16)]
pub enum MessageType {
    GuardHello = 1,
    GuardHelloAck = 2,
    InterceptionRequest = 3,
    InterceptionDecision = 4,
    GuardEvent = 5,
    GuardGoodbye = 6,
}

impl TryFrom<u16> for MessageType {
    type Error = IpcProtocolError;

    fn try_from(value: u16) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::GuardHello),
            2 => Ok(Self::GuardHelloAck),
            3 => Ok(Self::InterceptionRequest),
            4 => Ok(Self::InterceptionDecision),
            5 => Ok(Self::GuardEvent),
            6 => Ok(Self::GuardGoodbye),
            value => Err(IpcProtocolError::unknown_message_type(value)),
        }
    }
}

impl From<MessageType> for u16 {
    fn from(value: MessageType) -> Self {
        value as u16
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EreborIpcFrame {
    message_type: MessageType,
    flags: u16,
    payload: Vec<u8>,
}

impl EreborIpcFrame {
    pub fn new(
        message_type: MessageType,
        flags: u16,
        payload: Vec<u8>,
    ) -> Result<Self, IpcProtocolError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(IpcProtocolError::payload_too_large(
                payload.len(),
                MAX_PAYLOAD_LEN,
            ));
        }

        Ok(Self {
            message_type,
            flags,
            payload,
        })
    }

    pub fn from_message<T: Message>(
        message_type: MessageType,
        message: &T,
    ) -> Result<Self, IpcProtocolError> {
        let mut payload = Vec::with_capacity(message.encoded_len());
        message
            .encode(&mut payload)
            .map_err(IpcProtocolError::encode_payload)?;
        Self::new(message_type, 0, payload)
    }

    #[must_use]
    pub const fn message_type(&self) -> MessageType {
        self.message_type
    }

    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn decode_payload<T: Message + Default>(
        &self,
        expected: MessageType,
    ) -> Result<T, IpcProtocolError> {
        if self.message_type != expected {
            return Err(IpcProtocolError::message_type_mismatch(
                expected,
                self.message_type,
            ));
        }

        T::decode(self.payload.as_slice()).map_err(IpcProtocolError::decode_payload)
    }

    pub fn encode(&self) -> Result<Vec<u8>, IpcProtocolError> {
        if self.payload.len() > MAX_PAYLOAD_LEN {
            return Err(IpcProtocolError::payload_too_large(
                self.payload.len(),
                MAX_PAYLOAD_LEN,
            ));
        }

        let payload_len = u32::try_from(self.payload.len()).map_err(|_error| {
            IpcProtocolError::payload_too_large(self.payload.len(), MAX_PAYLOAD_LEN)
        })?;
        let mut output = Vec::with_capacity(HEADER_LEN + self.payload.len());
        output.extend_from_slice(&MAGIC);
        output.extend_from_slice(&u16::from(self.message_type).to_le_bytes());
        output.extend_from_slice(&self.flags.to_le_bytes());
        output.extend_from_slice(&payload_len.to_le_bytes());
        output.extend_from_slice(&self.payload);

        Ok(output)
    }

    pub fn decode(source: &[u8]) -> Result<Self, IpcProtocolError> {
        if source.len() < HEADER_LEN {
            return Err(IpcProtocolError::frame_too_short(source.len(), HEADER_LEN));
        }

        if source[0..4] != MAGIC {
            return Err(IpcProtocolError::InvalidMagic);
        }

        let message_type = MessageType::try_from(u16::from_le_bytes([source[4], source[5]]))?;
        let flags = u16::from_le_bytes([source[6], source[7]]);
        let payload_len =
            u32::from_le_bytes([source[8], source[9], source[10], source[11]]) as usize;
        let available = source.len() - HEADER_LEN;

        if payload_len > MAX_PAYLOAD_LEN {
            return Err(IpcProtocolError::payload_too_large(
                payload_len,
                MAX_PAYLOAD_LEN,
            ));
        }

        if payload_len != available {
            return Err(IpcProtocolError::invalid_payload_length(
                payload_len,
                available,
            ));
        }

        Self::new(
            message_type,
            flags,
            source[HEADER_LEN..HEADER_LEN + payload_len].to_vec(),
        )
    }
}

#[cfg(test)]
mod tests {
    use crate::IpcProtocolError;

    use super::{EreborIpcFrame, MessageType, HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN};

    #[test]
    fn frame_header_round_trips_payload() -> Result<(), IpcProtocolError> {
        let frame = EreborIpcFrame::new(MessageType::InterceptionRequest, 7, vec![1, 2, 3, 4])?;
        let encoded = frame.encode()?;
        let decoded = EreborIpcFrame::decode(&encoded)?;

        assert_eq!(decoded.message_type(), MessageType::InterceptionRequest);
        assert_eq!(decoded.flags(), 7);
        assert_eq!(decoded.payload(), &[1, 2, 3, 4]);
        Ok(())
    }

    #[test]
    fn frame_decode_rejects_malformed_contract_inputs() -> Result<(), IpcProtocolError> {
        let short = vec![0; HEADER_LEN - 1];
        assert!(matches!(
            EreborIpcFrame::decode(&short),
            Err(IpcProtocolError::FrameTooShort { .. })
        ));

        let mut invalid_magic = Vec::from([0, 0, 0, 0]);
        invalid_magic.extend_from_slice(&1u16.to_le_bytes());
        invalid_magic.extend_from_slice(&0u16.to_le_bytes());
        invalid_magic.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            EreborIpcFrame::decode(&invalid_magic),
            Err(IpcProtocolError::InvalidMagic)
        ));

        let mut unknown_type = Vec::from(MAGIC);
        unknown_type.extend_from_slice(&99u16.to_le_bytes());
        unknown_type.extend_from_slice(&0u16.to_le_bytes());
        unknown_type.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            EreborIpcFrame::decode(&unknown_type),
            Err(IpcProtocolError::UnknownMessageType { message_type: 99 })
        ));

        let mut oversized = Vec::from(MAGIC);
        oversized.extend_from_slice(&1u16.to_le_bytes());
        oversized.extend_from_slice(&0u16.to_le_bytes());
        oversized.extend_from_slice(&((MAX_PAYLOAD_LEN + 1) as u32).to_le_bytes());
        assert!(matches!(
            EreborIpcFrame::decode(&oversized),
            Err(IpcProtocolError::PayloadTooLarge { .. })
        ));

        let mut wrong_len = Vec::from(MAGIC);
        wrong_len.extend_from_slice(&1u16.to_le_bytes());
        wrong_len.extend_from_slice(&0u16.to_le_bytes());
        wrong_len.extend_from_slice(&2u32.to_le_bytes());
        wrong_len.push(1);
        assert!(matches!(
            EreborIpcFrame::decode(&wrong_len),
            Err(IpcProtocolError::InvalidPayloadLength { .. })
        ));

        Ok(())
    }
}
