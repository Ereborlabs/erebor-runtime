use serde::{Deserialize, Serialize};

use crate::{DiscoveryDigestV1, Result, TraceFrameKindV1, TraceFrameV1, TraceSourceV1};

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

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum TraceRecipeV1 {
    SyscallErrors,
    FailedOpens,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct TraceRecipeManifestV1 {
    pub recipe: TraceRecipeV1,
    pub version: u32,
    pub source: TraceSourceV1,
    pub parameter: String,
    pub attribution: String,
    pub sensitivity: String,
    pub hook: String,
    pub measurement_keys: Vec<String>,
    pub unit: String,
    pub cumulative: bool,
    pub atomic_snapshot: bool,
    pub maximum_probes: u16,
    pub maximum_map_keys: u32,
    pub return_code_semantics: String,
}

impl TraceRecipeV1 {
    pub fn measurements(self, frame: &TraceFrameV1) -> Option<Vec<TraceMeasurementV1>> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct MapOutput {
            #[serde(rename = "type")]
            kind: String,
            data: std::collections::BTreeMap<String, std::collections::BTreeMap<String, u64>>,
        }
        if frame.kind != TraceFrameKindV1::Data || frame.validate().is_err() {
            return None;
        }
        let output: MapOutput = serde_json::from_slice(&frame.bytes).ok()?;
        if output.kind != "map" || output.data.len() != 1 {
            return None;
        }
        let entries = output.data.get("@errors")?;
        if entries.len() > 4096 {
            return None;
        }
        entries
            .iter()
            .enumerate()
            .map(|(ordinal, (key, count))| {
                let (syscall_id, errno) = match self {
                    Self::SyscallErrors => {
                        let (id, errno) = key.split_once(',')?;
                        let id = id.parse::<i64>().ok()?;
                        let errno = errno.parse::<i64>().ok()?;
                        if key != &format!("{id},{errno}") {
                            return None;
                        }
                        let id = if id == -1 {
                            None
                        } else {
                            Some(u32::try_from(id).ok()?)
                        };
                        (id, errno)
                    }
                    Self::FailedOpens => {
                        let errno = key.parse::<i64>().ok()?;
                        if key != &errno.to_string() {
                            return None;
                        }
                        (None, errno)
                    }
                };
                if !(-4095..=-1).contains(&errno) {
                    return None;
                }
                Some(TraceMeasurementV1 {
                    execution_id: frame.execution_id,
                    sequence: frame.sequence,
                    ordinal: ordinal as u16,
                    syscall_id,
                    errno,
                    count: *count,
                    cumulative: true,
                    atomic_snapshot: false,
                    unit: "count".into(),
                })
            })
            .collect()
    }

    pub fn manifest(self) -> Result<TraceRecipeManifestV1> {
        let (source, hook, keys): (&[u8], &str, &[&str]) = match self {
            Self::SyscallErrors => (
                include_bytes!("../../../mithril-e2e/fixtures/observability/syscall-errors.bt"),
                "tracepoint:raw_syscalls:sys_exit",
                &["syscall_id", "errno"],
            ),
            Self::FailedOpens => (
                include_bytes!("../../../mithril-e2e/fixtures/observability/failed-opens.bt"),
                "tracepoint:syscalls:sys_exit_openat",
                &["errno"],
            ),
        };
        Ok(TraceRecipeManifestV1 {
            recipe: self,
            version: 1,
            source: TraceSourceV1::new(source.to_vec())?,
            parameter: "node-owned cgroup-v2 ID in $1".into(),
            attribution: "current task at syscall exit; one frozen container lifetime".into(),
            sensitivity: "workload syscall IDs and negative return codes".into(),
            hook: hook.into(),
            measurement_keys: keys.iter().map(|key| (*key).into()).collect(),
            unit: "count".into(),
            cumulative: true,
            atomic_snapshot: false,
            maximum_probes: 2,
            maximum_map_keys: 4096,
            return_code_semantics: "Negative kernel return codes, not final userspace failures. Codes -512, -513, -514, and -516 request a syscall restart. Syscall ID -1 is unknown and projects as null.".into(),
        })
    }

    pub fn digest(self) -> Result<DiscoveryDigestV1> {
        DiscoveryDigestV1::of(&self.manifest()?)
    }

    pub fn identify(source: &TraceSourceV1) -> Result<Option<Self>> {
        source.validate()?;
        for recipe in [Self::SyscallErrors, Self::FailedOpens] {
            if recipe.manifest()?.source == *source {
                return Ok(Some(recipe));
            }
        }
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_projection_retains_k3s_unknown_syscall_with_valid_counts() {
        let frame = TraceFrameV1 {
            execution_id: [1; 16],
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: include_bytes!(
                "../../../mithril-e2e/fixtures/observability/k3s-syscall-map.json"
            )
            .to_vec(),
        };
        let measurements = TraceRecipeV1::SyscallErrors.measurements(&frame);
        assert!(measurements.is_some());
        let measurements = measurements.unwrap_or_default();
        assert_eq!(measurements.len(), 12);
        assert!(measurements
            .iter()
            .any(|row| row.syscall_id == Some(257) && row.errno == -2 && row.count == 11));
        assert!(measurements
            .iter()
            .any(|row| row.syscall_id.is_none() && row.errno == -4 && row.count == 2));
    }

    #[test]
    fn observability_projection_rejects_unknown_or_spoofed_schema(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let mut frame = TraceFrameV1 {
            execution_id: [1; 16],
            sequence: 1,
            kind: TraceFrameKindV1::Data,
            bytes: Vec::new(),
        };
        for bytes in [
            br#"{"type":"printf","data":{"@errors":{"257,-2":7}}}"#.as_slice(),
            br#"{"type":"map","data":{"@errors":{"257,-2":"7"}}}"#.as_slice(),
            br#"{"type":"map","data":{"@errors":{"257,-2,3":7}}}"#.as_slice(),
            br#"{"type":"map","data":{"@errors":{"257,2":7}}}"#.as_slice(),
            br#"{"type":"map","data":{"@errors":{"-2,-2":7}}}"#.as_slice(),
            br#"{"type":"map","data":{"@full":{"0":1}}}"#.as_slice(),
            b"not-json".as_slice(),
        ] {
            frame.bytes = bytes.to_vec();
            assert!(TraceRecipeV1::SyscallErrors.measurements(&frame).is_none());
        }
        frame.bytes = br#"{"type":"map","data":{"@errors":{"-2":7}}}"#.to_vec();
        let rows = TraceRecipeV1::FailedOpens
            .measurements(&frame)
            .ok_or("reviewed map output absent")?;
        assert_eq!(rows[0].count, 7);
        assert_eq!(rows[0].syscall_id, None);
        frame.kind = TraceFrameKindV1::Diagnostic;
        assert!(TraceRecipeV1::FailedOpens.measurements(&frame).is_none());
        Ok(())
    }
}
