#[cfg(test)]
pub(crate) mod catalog_tests;
mod error;
mod model;
mod policy;

pub use error::{EvidenceModelError, EvidenceModelResult};
pub use model::*;
pub use policy::*;

use prost::{bytes::Buf, Message as _};
use snafu::ResultExt as _;

use crate::{Error, EvidenceDecodeSnafu, EvidenceFrameSnafu, Result};

include!(concat!(env!("OUT_DIR"), "/erebor.mithril.control.v1.rs"));

impl EvidenceRecord {
    /// Decode one bounded frame and return its consumed byte count.
    pub fn decode_prefix(mut input: impl Buf + AsRef<[u8]>) -> Result<(Self, usize)> {
        let bytes = input.as_ref();
        let length = bytes.first_chunk::<4>().ok_or_else(|| {
            EvidenceFrameSnafu {
                reason: "evidence record frame length is incomplete",
                input_bytes: bytes.len(),
            }
            .build()
        })?;
        let payload_bytes = u32::from_be_bytes(*length) as usize;
        if payload_bytes == 0 {
            return EvidenceFrameSnafu {
                reason: "evidence record frame is outside its size bound",
                input_bytes: bytes.len(),
            }
            .fail();
        }
        let frame_bytes = payload_bytes.checked_add(8).ok_or_else(|| {
            EvidenceFrameSnafu {
                reason: "evidence record frame length is not representable",
                input_bytes: bytes.len(),
            }
            .build()
        })?;
        let frame = bytes.get(..frame_bytes).ok_or_else(|| {
            EvidenceFrameSnafu {
                reason: "evidence record frame payload is incomplete",
                input_bytes: bytes.len(),
            }
            .build()
        })?;
        let payload_end = frame_bytes - 4;
        let expected = u32::from_be_bytes(frame[payload_end..].try_into().unwrap_or_default());
        if crc32c::crc32c(&frame[..payload_end]) != expected {
            return EvidenceFrameSnafu {
                reason: "evidence record frame checksum is invalid",
                input_bytes: bytes.len(),
            }
            .fail();
        }
        input.advance(4);
        let record =
            Self::decode(input.take(payload_bytes)).context(EvidenceDecodeSnafu { frame_bytes })?;
        Ok((record, frame_bytes))
    }
}

impl TryFrom<&[u8]> for EvidenceRecord {
    type Error = Error;

    fn try_from(frame: &[u8]) -> Result<Self> {
        let (record, consumed) = Self::decode_prefix(frame)?;
        if consumed != frame.len() {
            return EvidenceFrameSnafu {
                reason: "evidence record frame has trailing bytes",
                input_bytes: frame.len(),
            }
            .fail();
        }
        Ok(record)
    }
}

impl TryFrom<&EvidenceRecord> for Vec<u8> {
    type Error = Error;

    fn try_from(record: &EvidenceRecord) -> Result<Self> {
        let length = record.encoded_len();
        if length == 0 {
            return EvidenceFrameSnafu {
                reason: "evidence record frame is outside its size bound",
                input_bytes: length,
            }
            .fail();
        }
        let payload = u32::try_from(length).map_err(|_| {
            EvidenceFrameSnafu {
                reason: "evidence record frame length is not representable",
                input_bytes: length,
            }
            .build()
        })?;
        let capacity = length.checked_add(8).ok_or_else(|| {
            EvidenceFrameSnafu {
                reason: "evidence record frame length is not representable",
                input_bytes: length,
            }
            .build()
        })?;
        let mut frame = Vec::with_capacity(capacity);
        frame.extend_from_slice(&payload.to_be_bytes());
        record.encode(&mut frame).map_err(|_| {
            EvidenceFrameSnafu {
                reason: "evidence record frame encoding failed",
                input_bytes: length,
            }
            .build()
        })?;
        frame.extend_from_slice(&crc32c::crc32c(&frame).to_be_bytes());
        Ok(frame)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut bytes = (payload.len() as u32).to_be_bytes().to_vec();
        bytes.extend_from_slice(payload);
        bytes.extend_from_slice(&crc32c::crc32c(&bytes).to_be_bytes());
        bytes
    }

    #[test]
    fn query_input_values() -> Result<()> {
        let mut record = EvidenceRecord {
            observed_boottime_ns: u64::MAX,
            ingested_utc_ns: i64::MIN,
            coverage_interval_id: vec![0, 255, 7].into(),
            profile_generation_ref_id: Some(0),
            task_cookie: u64::MAX,
            process_lineage_id: vec![128, 0].into(),
            reason: u32::MAX,
            decision: u32::MAX,
            effect_family: u32::MAX,
            operation: u32::MAX,
            configured_errno: i32::MIN,
            kernel_result: i32::MAX,
            temporal_coverage: -17,
            target_task_cookie: Some(0),
            operation_argument: Some(0),
            decision_context: Some(EvidenceDecisionContext {
                schema_version: u32::MAX,
                original_kernel_sequence: u64::MAX,
                process_instance_id: vec![255, 0],
                exact_file_object: Some(EvidenceExactFileObject {
                    inode: u64::MAX,
                    ..Default::default()
                }),
                catalog_json: vec![0, 255],
                catalog_state: "FUTURE_STATE".into(),
                ..Default::default()
            }),
            ..Default::default()
        };
        for present in [true, false] {
            if !present {
                record.profile_generation_ref_id = None;
                record.target_task_cookie = None;
                record.operation_argument = None;
                record.decision_context = None;
            }
            let bytes = frame(&record.encode_to_vec());
            assert_eq!(Vec::<u8>::try_from(&record)?, bytes);
            assert_eq!(EvidenceRecord::try_from(bytes.as_slice())?, record);
            let mut batch = bytes.clone();
            batch.extend_from_slice(&bytes);
            let (decoded, consumed) = EvidenceRecord::decode_prefix(batch.as_slice())?;
            assert_eq!(decoded, record);
            assert_eq!(consumed, bytes.len());
            assert_eq!(EvidenceRecord::try_from(&batch[consumed..])?, record);
            assert!(EvidenceRecord::try_from(batch.as_slice()).is_err());
        }
        Ok(())
    }

    #[test]
    fn query_input_size_bounds() -> Result<()> {
        let record = EvidenceRecord {
            task_cookie: 7,
            ..Default::default()
        };
        for size in [128 * 1_024 - 1, 128 * 1_024, 17 * 1_024 * 1_024] {
            let mut payload = record.encode_to_vec();
            let mut padding = vec![0; size - payload.len()];
            let overhead = prost::encoding::bytes::encoded_len(100, &padding) - padding.len();
            padding.truncate(padding.len() - overhead);
            prost::encoding::bytes::encode(100, &padding, &mut payload);
            assert_eq!(payload.len(), size);
            let bytes = frame(&payload);
            assert_eq!(EvidenceRecord::try_from(bytes.as_slice())?, record);
        }
        Ok(())
    }

    #[test]
    fn query_input_shared_bytes() -> Result<()> {
        let expected = vec![7; 16];
        let bytes = prost::bytes::Bytes::from(frame(
            &EvidenceRecord {
                coverage_interval_id: expected.clone().into(),
                ..Default::default()
            }
            .encode_to_vec(),
        ));
        let start = bytes.as_ptr() as usize;
        let end = start + bytes.len();
        let (record, consumed) = EvidenceRecord::decode_prefix(bytes.clone())?;
        let field = record.coverage_interval_id.as_ptr() as usize;
        assert!(field >= start && field + expected.len() <= end);
        assert_eq!(consumed, bytes.len());
        drop(bytes);
        assert_eq!(record.coverage_interval_id.as_ref(), expected.as_slice());
        Ok(())
    }

    #[test]
    fn query_input_invalid_frames() {
        let valid = frame(
            &EvidenceRecord {
                task_cookie: 7,
                ..Default::default()
            }
            .encode_to_vec(),
        );
        for end in 0..valid.len() {
            assert!(EvidenceRecord::try_from(&valid[..end]).is_err());
        }
        assert!(EvidenceRecord::try_from(frame(&[]).as_slice()).is_err());
        let mut corrupt = valid.clone();
        corrupt[4] ^= 1;
        assert!(matches!(
            EvidenceRecord::try_from(corrupt.as_slice()),
            Err(Error::EvidenceFrame {
                reason: "evidence record frame checksum is invalid",
                ..
            })
        ));
        assert!(matches!(
            EvidenceRecord::try_from(frame(&[255]).as_slice()),
            Err(Error::EvidenceDecode { .. })
        ));
        let mut trailing = valid;
        trailing.push(0);
        assert!(matches!(
            EvidenceRecord::try_from(trailing.as_slice()),
            Err(Error::EvidenceFrame {
                reason: "evidence record frame has trailing bytes",
                ..
            })
        ));
        assert!(EvidenceRecord::try_from(u32::MAX.to_be_bytes().as_slice()).is_err());
    }
}
