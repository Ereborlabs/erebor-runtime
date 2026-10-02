use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ensure;

use crate::{Result, TraceInvalidSnafu};

pub const MAX_TRACE_SOURCE_BYTES: usize = 64 * 1024;
pub const MAX_TRACE_FRAME_BYTES: usize = 1024 * 1024;
pub const MAX_TRACE_OUTPUT_BYTES: u64 = 16 * 1024 * 1024;
pub const MAX_TRACE_TARGETS: usize = 16;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceIdentityV1 {
    pub tenant_id: [u8; 16],
    pub node_id: String,
    pub node_boot_id: [u8; 16],
    pub request_id: [u8; 16],
    pub execution_id: [u8; 16],
    pub source_sha256: [u8; 32],
}

impl TraceIdentityV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.tenant_id != [0; 16]
                && crate::node_id_is_valid(&self.node_id)
                && self.node_boot_id != [0; 16]
                && self.request_id != [0; 16]
                && self.execution_id != [0; 16]
                && self.source_sha256 != [0; 32],
            TraceInvalidSnafu {
                reason: "trace source identity is invalid",
            }
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceSourceV1 {
    pub bytes: Vec<u8>,
    pub sha256: [u8; 32],
}

impl TraceSourceV1 {
    pub fn new(bytes: Vec<u8>) -> Result<Self> {
        let source = Self {
            sha256: Sha256::digest(&bytes).into(),
            bytes,
        };
        source.validate()?;
        Ok(source)
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.bytes.is_empty()
                && self.bytes.len() <= MAX_TRACE_SOURCE_BYTES
                && !self.bytes.contains(&0)
                && std::str::from_utf8(&self.bytes).is_ok()
                && self.sha256 == <[u8; 32]>::from(Sha256::digest(&self.bytes)),
            TraceInvalidSnafu {
                reason: "trace source is empty, invalid, too large, or changed",
            }
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceFrameKindV1 {
    Metadata,
    Data,
    Diagnostic,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceFrameV1 {
    pub execution_id: [u8; 16],
    pub sequence: u64,
    pub kind: TraceFrameKindV1,
    pub bytes: Vec<u8>,
}

impl TraceFrameV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.execution_id != [0; 16]
                && self.sequence != 0
                && !self.bytes.is_empty()
                && self.bytes.len() <= MAX_TRACE_FRAME_BYTES,
            TraceInvalidSnafu {
                reason: "trace output identity, sequence, or frame size is invalid",
            }
        );
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceTerminalReasonV1 {
    Completed,
    Cancelled,
    Deadline,
    PreparationFailed,
    TargetChanged,
    OutputLimit,
    ConsumerSlow,
    NodeRestarted,
    StorageFailure,
    BackendFailed,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceCleanupV1 {
    Verified,
    Failed,
    Unknown,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceTerminalV1 {
    pub execution_id: [u8; 16],
    pub reason: TraceTerminalReasonV1,
    pub last_sequence: u64,
    pub output_bytes: u64,
    pub output_incomplete: bool,
    pub kernel_lost_events: Option<u64>,
    pub ready_at_unix_ns: Option<u64>,
    pub exit_code: Option<i32>,
    pub forced_kill: bool,
    pub cleanup: TraceCleanupV1,
}

impl TraceTerminalV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.execution_id != [0; 16]
                && self.last_sequence <= 4096
                && self.output_bytes >= self.last_sequence
                && self.output_bytes <= MAX_TRACE_OUTPUT_BYTES
                && !(self.forced_kill && !self.output_incomplete),
            TraceInvalidSnafu {
                reason: "trace terminal identity, output size, or loss state is invalid",
            }
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceBatchV1 {
    pub execution_id: [u8; 16],
    pub frames: Vec<TraceFrameV1>,
    pub terminal: Option<TraceTerminalV1>,
}

impl TraceBatchV1 {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.execution_id != [0; 16]
                && self.frames.len() <= 200
                && (!self.frames.is_empty() || self.terminal.is_some()),
            TraceInvalidSnafu {
                reason: "trace batch is empty or too large",
            }
        );
        let mut bytes = 0;
        for (index, frame) in self.frames.iter().enumerate() {
            frame.validate()?;
            bytes += frame.bytes.len();
            ensure!(
                frame.execution_id == self.execution_id
                    && frame.sequence <= 4096
                    && (index == 0 || self.frames[index - 1].sequence + 1 == frame.sequence),
                TraceInvalidSnafu {
                    reason: "trace batch identity or sequence changed",
                }
            );
        }
        ensure!(
            bytes <= 1024 * 1024,
            TraceInvalidSnafu {
                reason: "trace batch exceeds 1 MiB",
            }
        );
        if let Some(terminal) = &self.terminal {
            terminal.validate()?;
            ensure!(
                terminal.execution_id == self.execution_id,
                TraceInvalidSnafu {
                    reason: "trace terminal names another execution",
                }
            );
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceMeasurementV1 {
    pub execution_id: [u8; 16],
    pub sequence: u64,
    pub ordinal: u16,
    pub syscall_id: Option<u32>,
    pub errno: i64,
    pub count: u64,
    pub cumulative: bool,
    pub atomic_snapshot: bool,
    pub unit: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_backend_source_pins_exact_bytes() -> Result<()> {
        let mut source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
        source.bytes.push(b' ');
        assert!(source.validate().is_err());
        assert!(TraceSourceV1::new(vec![b'x'; MAX_TRACE_SOURCE_BYTES + 1]).is_err());
        assert!(TraceSourceV1::new(vec![0xff]).is_err());
        assert!(TraceSourceV1::new(vec![0]).is_err());
        Ok(())
    }

    #[test]
    fn observability_backend_output_limits_and_unknown_loss() -> Result<()> {
        let mut terminal = TraceTerminalV1 {
            execution_id: [1; 16],
            reason: TraceTerminalReasonV1::Completed,
            last_sequence: 0,
            output_bytes: 0,
            output_incomplete: false,
            kernel_lost_events: None,
            ready_at_unix_ns: None,
            exit_code: Some(0),
            forced_kill: false,
            cleanup: TraceCleanupV1::Unknown,
        };
        terminal.validate()?;
        terminal.forced_kill = true;
        assert!(terminal.validate().is_err());
        assert!(TraceFrameV1 {
            execution_id: [1; 16],
            sequence: 0,
            kind: TraceFrameKindV1::Data,
            bytes: vec![1]
        }
        .validate()
        .is_err());
        Ok(())
    }

    #[test]
    fn observability_contract_identity() -> Result<()> {
        let identity = TraceIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            request_id: [3; 16],
            execution_id: [4; 16],
            source_sha256: [5; 32],
        };
        identity.validate()?;
        for changed in [
            TraceIdentityV1 {
                tenant_id: [0; 16],
                ..identity.clone()
            },
            TraceIdentityV1 {
                node_boot_id: [0; 16],
                ..identity.clone()
            },
            TraceIdentityV1 {
                request_id: [0; 16],
                ..identity.clone()
            },
            TraceIdentityV1 {
                execution_id: [0; 16],
                ..identity.clone()
            },
            TraceIdentityV1 {
                source_sha256: [0; 32],
                ..identity.clone()
            },
        ] {
            assert!(changed.validate().is_err());
        }
        for node in [
            "".into(),
            "../node".into(),
            "node a".into(),
            "a".repeat(crate::MAX_NODE_ID_BYTES + 1),
        ] {
            assert!(TraceIdentityV1 {
                node_id: node,
                ..identity.clone()
            }
            .validate()
            .is_err());
        }
        Ok(())
    }

    #[test]
    fn observability_contract_batch() -> Result<()> {
        let frame = TraceFrameV1 {
            execution_id: [1; 16],
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: vec![7; MAX_TRACE_FRAME_BYTES],
        };
        let mut batch = TraceBatchV1 {
            execution_id: frame.execution_id,
            frames: vec![frame.clone()],
            terminal: None,
        };
        batch.validate()?;
        batch.frames.push(TraceFrameV1 {
            sequence: 2,
            bytes: vec![7],
            ..frame.clone()
        });
        assert!(batch.validate().is_err());
        batch.frames[0].bytes = vec![7];
        batch.validate()?;
        batch.frames[1].sequence = 3;
        assert!(batch.validate().is_err());
        batch.frames[1].sequence = 2;
        batch.frames[1].execution_id = [2; 16];
        assert!(batch.validate().is_err());
        batch.frames = (1..=201)
            .map(|sequence| TraceFrameV1 {
                sequence,
                bytes: vec![7],
                ..frame.clone()
            })
            .collect();
        assert!(batch.validate().is_err());
        batch.frames.truncate(200);
        batch.validate()?;
        batch.frames.clear();
        assert!(batch.validate().is_err());
        Ok(())
    }

    #[test]
    fn observability_contract_wire() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let execution = [1_u8; 16];
        let batch = TraceBatchV1 {
            execution_id: execution,
            frames: vec![TraceFrameV1 {
                execution_id: execution,
                sequence: 1,
                kind: TraceFrameKindV1::Diagnostic,
                bytes: b"a\n".to_vec(),
            }],
            terminal: Some(TraceTerminalV1 {
                execution_id: execution,
                reason: TraceTerminalReasonV1::NodeRestarted,
                last_sequence: 1,
                output_bytes: 2,
                output_incomplete: true,
                kernel_lost_events: None,
                ready_at_unix_ns: Some(17),
                exit_code: None,
                forced_kill: false,
                cleanup: TraceCleanupV1::Unknown,
            }),
        };
        let expected = serde_json::json!({
            "execution_id": execution,
            "frames": [{"execution_id": execution, "sequence": 1, "kind": "Diagnostic", "bytes": [97, 10]}],
            "terminal": {
                "execution_id": execution, "reason": "NodeRestarted", "last_sequence": 1,
                "output_bytes": 2, "output_incomplete": true, "kernel_lost_events": null,
                "ready_at_unix_ns": 17, "exit_code": null, "forced_kill": false, "cleanup": "Unknown"
            }
        });
        assert_eq!(serde_json::to_value(&batch)?, expected);
        assert_eq!(
            serde_json::from_value::<TraceBatchV1>(expected.clone())?,
            batch
        );
        let mut unknown = expected;
        unknown["frames"][0]["extra"] = serde_json::json!(true);
        assert!(serde_json::from_value::<TraceBatchV1>(unknown).is_err());
        Ok(())
    }
}
