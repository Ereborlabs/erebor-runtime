use prost::Message;

use crate::IpcProtocolError;

pub const MAGIC: [u8; 4] = *b"ERB1";
pub const FRAME_VERSION: u16 = 1;
pub const HEADER_LEN: usize = 12;
pub const MAX_PAYLOAD_LEN: usize = 64 * 1024;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EreborIpcFrame {
    flags: u16,
    payload: Vec<u8>,
}

impl EreborIpcFrame {
    pub fn new(flags: u16, payload: Vec<u8>) -> Result<Self, IpcProtocolError> {
        if payload.len() > MAX_PAYLOAD_LEN {
            return Err(IpcProtocolError::payload_too_large(
                payload.len(),
                MAX_PAYLOAD_LEN,
            ));
        }

        Ok(Self { flags, payload })
    }

    pub fn from_message<T: Message>(message: &T) -> Result<Self, IpcProtocolError> {
        let mut payload = Vec::with_capacity(message.encoded_len());
        message
            .encode(&mut payload)
            .map_err(IpcProtocolError::encode_payload)?;
        Self::new(0, payload)
    }

    #[must_use]
    pub const fn flags(&self) -> u16 {
        self.flags
    }

    #[must_use]
    pub fn payload(&self) -> &[u8] {
        &self.payload
    }

    pub fn decode_payload<T: Message + Default>(&self) -> Result<T, IpcProtocolError> {
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
        output.extend_from_slice(&FRAME_VERSION.to_le_bytes());
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

        let version = u16::from_le_bytes([source[4], source[5]]);
        if version != FRAME_VERSION {
            return Err(IpcProtocolError::unsupported_frame_version(version));
        }

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

        Self::new(flags, source[HEADER_LEN..HEADER_LEN + payload_len].to_vec())
    }
}

#[cfg(test)]
mod tests {
    use crate::IpcProtocolError;

    use super::{EreborIpcFrame, FRAME_VERSION, HEADER_LEN, MAGIC, MAX_PAYLOAD_LEN};

    #[test]
    fn frame_header_round_trips_opaque_payload() -> Result<(), IpcProtocolError> {
        let frame = EreborIpcFrame::new(7, vec![1, 2, 3, 4])?;
        let encoded = frame.encode()?;
        let decoded = EreborIpcFrame::decode(&encoded)?;

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
        invalid_magic.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        invalid_magic.extend_from_slice(&0u16.to_le_bytes());
        invalid_magic.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            EreborIpcFrame::decode(&invalid_magic),
            Err(IpcProtocolError::InvalidMagic)
        ));

        let mut unsupported_version = Vec::from(MAGIC);
        unsupported_version.extend_from_slice(&99u16.to_le_bytes());
        unsupported_version.extend_from_slice(&0u16.to_le_bytes());
        unsupported_version.extend_from_slice(&0u32.to_le_bytes());
        assert!(matches!(
            EreborIpcFrame::decode(&unsupported_version),
            Err(IpcProtocolError::UnsupportedFrameVersion { version: 99 })
        ));

        let mut oversized = Vec::from(MAGIC);
        oversized.extend_from_slice(&FRAME_VERSION.to_le_bytes());
        oversized.extend_from_slice(&0u16.to_le_bytes());
        oversized.extend_from_slice(&((MAX_PAYLOAD_LEN + 1) as u32).to_le_bytes());
        assert!(matches!(
            EreborIpcFrame::decode(&oversized),
            Err(IpcProtocolError::PayloadTooLarge { .. })
        ));

        let mut wrong_len = Vec::from(MAGIC);
        wrong_len.extend_from_slice(&FRAME_VERSION.to_le_bytes());
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
