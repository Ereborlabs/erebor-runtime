use std::time::{Duration, SystemTime, UNIX_EPOCH};

use araphor_analysis_sdk as sdk;
use serde::{Deserialize, Serialize};
use tokio::sync::watch;

use crate::{AnalysisSelectionV1, Result};

use super::{PackageArtifactIdentityV1, PackageBundleRef, PackageBundleV1};

mod request;

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageErrorCodeV1 {
    Invalid,
    Limit,
    Denied,
    Conflict,
    Missing,
    Unsupported,
    Incomplete,
}

impl PackageErrorCodeV1 {
    pub fn error(self, field: &'static str) -> crate::Error {
        crate::PackageSnafu { code: self, field }.build()
    }
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PackageGrantV1 {
    pub principal: String,
    pub revision: u64,
    pub selection: AnalysisSelectionV1,
    pub expires_utc_ns: Option<u64>,
    pub authorization_id: Option<String>,
}

impl PackageGrantV1 {
    pub(crate) fn validate(&self) -> Result<()> {
        if self.principal.is_empty()
            || self.principal.len() > 256
            || self.revision == 0
            || !self.selection.valid()
        {
            return Err(PackageErrorCodeV1::Denied.error("package grant"));
        }
        Ok(())
    }

    pub fn remaining(&self) -> Result<Option<Duration>> {
        self.validate()?;
        let Some(expiry) = self.expires_utc_ns else {
            return Ok(None);
        };
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|time| u64::try_from(time.as_nanos()).ok())
            .ok_or_else(|| PackageErrorCodeV1::Incomplete.error("system time"))?;
        let remaining = expiry
            .checked_sub(now)
            .filter(|remaining| *remaining > 0)
            .ok_or_else(|| PackageErrorCodeV1::Denied.error("package grant"))?;
        Ok(Some(Duration::from_nanos(remaining)))
    }

    pub fn permitted_by(&self, selection: &AnalysisSelectionV1) -> Result<()> {
        if *selection != self.selection
            && *selection != AnalysisSelectionV1::tenant(self.selection.tenant_id)
        {
            return Err(PackageErrorCodeV1::Denied.error("whole package scope"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub enum ClockDependency {
    None,
    Inputs,
    Model,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
pub struct InstalledContext {
    pub grant: PackageGrantV1,
    pub root: super::PackageRefV1,
    pub parameters: Option<serde_json::Value>,
    pub readiness: PackageReadinessV1,
    pub status_checkpoint: u64,
    pub prepared: bool,
    pub clock: ClockDependency,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
pub struct ResultContext {
    #[serde(default = "ResultContext::sql_target")]
    pub target: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<PackageArtifactIdentityV1>,
    pub context: sdk::EvaluationContext,
    pub inputs: Vec<sdk::Revision>,
    pub input_coverage: Vec<sdk::Coverage>,
    pub coverage: sdk::Coverage,
}

impl ResultContext {
    fn sql_target() -> String {
        "sql".into()
    }

    pub fn matches(&self, inputs: &[sdk::Input]) -> bool {
        self.inputs
            .iter()
            .eq(inputs.iter().map(|input| &input.revision))
            && self
                .input_coverage
                .iter()
                .eq(inputs.iter().map(|input| &input.coverage))
    }

    pub fn new(id: &str, now: u64, model: &sdk::Model, inputs: &[sdk::Input]) -> Self {
        let input_coverage: Vec<_> = inputs.iter().map(|input| input.coverage.clone()).collect();
        let coverage = Self::coverage(&input_coverage);
        Self {
            target: Self::sql_target(),
            artifact: None,
            context: sdk::EvaluationContext {
                id: id.into(),
                time_utc_ns: now as i64,
                seed: None,
                limits: model.limits,
            },
            inputs: inputs.iter().map(|input| input.revision.clone()).collect(),
            input_coverage,
            coverage,
        }
    }
    pub fn coverage(input_coverage: &[sdk::Coverage]) -> sdk::Coverage {
        let (mut state, mut limits) = (sdk::CoverageState::Complete, Vec::new());
        for coverage in input_coverage {
            if coverage.state == sdk::CoverageState::Unknown
                || (coverage.state == sdk::CoverageState::Gapped
                    && state == sdk::CoverageState::Complete)
            {
                state = coverage.state;
            }
            limits.extend(coverage.limits.iter().cloned());
        }
        limits.sort();
        limits.dedup();
        sdk::Coverage { state, limits }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PackageActionV1 {
    Inspect,
    Install,
    Run,
    Update,
    Rollback,
    Remove,
    Test,
}

pub trait PackageAuthorization: Send + Sync + 'static {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> Result<()>;
    fn admit(&self, grant: &PackageGrantV1, bundle: &PackageBundleRef<'_>) -> Result<()>;
    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()>;
    fn changes(&self) -> watch::Receiver<u64>;

    fn changes_for(&self, _grant: &PackageGrantV1) -> watch::Receiver<u64> {
        self.changes()
    }

    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, Option<&PackageBundleRef<'_>>)],
        action: PackageActionV1,
        operation: &mut dyn FnMut() -> Result<()>,
    ) -> Result<()> {
        let [(grant, Some(bundle))] = grants else {
            return Err(PackageErrorCodeV1::Unsupported.error("atomic package authority set"));
        };
        self.commit(grant, action, bundle, operation)
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "operation", rename_all = "snake_case", deny_unknown_fields)]
pub enum PackageRequestV1 {
    AdmitDefinition {
        definition: araphor_discovery_definition::Definition,
    },
    InspectDefinition {
        name: String,
        revision: Option<String>,
    },
    InstallImage {
        #[serde(skip_serializing)]
        bundle: PackageBundleV1,
    },
    InspectImage {
        package_id: String,
        revision: Option<String>,
    },
    InspectInstance {
        instance_id: String,
    },
    InspectInstanceHistory {
        instance_id: String,
    },
    ReadInstanceResult {
        instance_id: String,
        result_id: String,
    },
    QueryInstanceResult {
        instance_id: String,
        result_id: String,
        sql: String,
    },
}

impl PackageRequestV1 {
    pub fn action(&self) -> PackageActionV1 {
        match self {
            Self::AdmitDefinition { .. } | Self::InstallImage { .. } => PackageActionV1::Install,
            Self::InspectDefinition { .. }
            | Self::InspectImage { .. }
            | Self::InspectInstance { .. }
            | Self::InspectInstanceHistory { .. }
            | Self::ReadInstanceResult { .. }
            | Self::QueryInstanceResult { .. } => PackageActionV1::Inspect,
        }
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceStatusV1 {
    pub id: String,
    pub definition_revision: String,
    pub generation: u64,
    pub lifecycle: u64,
    pub running: bool,
    pub progress: u64,
    pub readiness: PackageReadinessV1,
    pub status_progress: u64,
}

impl TryFrom<crate::ManagedStatus> for InstanceStatusV1 {
    type Error = crate::Error;

    fn try_from(status: crate::ManagedStatus) -> Result<Self> {
        Ok(Self {
            definition_revision: status.instance.spec.definition.digest()?,
            id: status.instance.spec.id,
            generation: status.instance.generation,
            lifecycle: status.instance.lifecycle,
            running: status.instance.running,
            progress: status.instance.progress,
            readiness: status.readiness,
            status_progress: status.status_progress,
        })
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct InstanceResultV1 {
    pub instance_id: String,
    pub result_id: String,
    pub image: araphor_discovery_definition::ImagePin,
    pub package: super::PackageRefV1,
    pub export: String,
    pub context: ResultContext,
    pub limits: sdk::Limits,
    pub commit_revision: u64,
    pub current: bool,
    pub output: sdk::wire::Output,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case", deny_unknown_fields)]
pub enum PackageResponseV1 {
    Definition(araphor_discovery_definition::ResolvedDefinition),
    Image(araphor_package::PackageImageV1),
    Instance(InstanceStatusV1),
    History(Vec<crate::ManagedReceipt>),
    Output(sdk::wire::Dataset),
    Result(Box<InstanceResultV1>),
}

impl PackageResponseV1 {
    pub fn encode(&self) -> Result<Vec<u8>> {
        use snafu::ResultExt as _;

        let mut bytes = Vec::new();
        let mut serializer = rmp_serde::Serializer::new(&mut bytes)
            .with_struct_map()
            .with_bytes(rmp_serde::config::BytesMode::ForceIterables);
        self.serialize(&mut serializer)
            .context(crate::PackageResponseEncodeSnafu)?;
        Ok(bytes)
    }

    pub fn from_bytes(bytes: &[u8]) -> Result<Self> {
        use snafu::ResultExt as _;

        let mut decoder = rmp_serde::Deserializer::new(std::io::Cursor::new(bytes));
        let response =
            Self::deserialize(&mut decoder).context(crate::PackageResponseDecodeSnafu)?;
        if decoder.position() != bytes.len() as u64 {
            return Err(PackageErrorCodeV1::Invalid.error("package response trailing bytes"));
        }
        Ok(response)
    }
}

impl TryFrom<&sdk::Dataset> for PackageResponseV1 {
    type Error = crate::Error;

    fn try_from(data: &sdk::Dataset) -> Result<Self> {
        use snafu::ResultExt as _;

        let schema = data
            .batches
            .first()
            .ok_or_else(|| PackageErrorCodeV1::Incomplete.error("retained query schema"))?
            .schema();
        let output = sdk::wire::Dataset::encode(data, &schema, sdk::Limits::default())
            .context(crate::AnalysisContractSnafu)?;
        Ok(Self::Output(output))
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PackageReadinessV1 {
    Ready,
    Inactive,
    MissingInput {
        input: String,
    },
    Unsupported {
        target: String,
    },
    Failed {
        code: PackageErrorCodeV1,
        field: String,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> PackageGrantV1 {
        PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant([1; 16]),
            expires_utc_ns: None,
            authorization_id: None,
        }
    }

    #[test]
    fn grant_has_optional_deadline() -> Result<()> {
        let mut grant = grant();
        assert_eq!(grant.remaining()?, None);
        grant.principal = "x".repeat(256);
        grant.expires_utc_ns = Some(u64::MAX);
        assert!(grant
            .remaining()?
            .is_some_and(|remaining| !remaining.is_zero()));
        Ok(())
    }

    #[test]
    fn grant_rejects_invalid_shapes() {
        for case in 0..4 {
            let mut grant = grant();
            match case {
                0 => grant.principal.clear(),
                1 => grant.principal = "x".repeat(257),
                2 => grant.revision = 0,
                _ => grant.selection.tenant_id = [0; 16],
            }
            assert!(matches!(
                grant.remaining(),
                Err(crate::Error::Package {
                    code: PackageErrorCodeV1::Denied,
                    field: "package grant",
                    ..
                })
            ));
        }
    }

    #[test]
    fn grant_rejects_expired_deadline() {
        let mut grant = grant();
        for expired in [0, 1] {
            grant.expires_utc_ns = Some(expired);
            assert!(matches!(
                grant.remaining(),
                Err(crate::Error::Package {
                    code: PackageErrorCodeV1::Denied,
                    field: "package grant",
                    ..
                })
            ));
        }
    }
}

#[cfg(test)]
mod inspection_tests {
    use super::*;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    #[test]
    fn status_hides_saved_authority() -> TestResult {
        let definition: araphor_discovery_definition::Definition =
            serde_json::from_value(serde_json::json!({
                "name": "counts",
                "program": {"kind":"sql", "source":{"inline":"SELECT 1"}}
            }))?;
        let definition = araphor_discovery_definition::ResolvedDefinition::new(
            definition,
            "SELECT 1".into(),
            Vec::new(),
        )?;
        let revision = definition.digest()?;
        let status = crate::ManagedStatus {
            instance: crate::ManagedInstance {
                spec: crate::ManagedSpec {
                    tenant: [1; 16],
                    id: "counts".into(),
                    grant: PackageGrantV1 {
                        principal: "saved-run-principal".into(),
                        revision: 7,
                        selection: crate::AnalysisSelectionV1::tenant([1; 16]),
                        expires_utc_ns: Some(99),
                        authorization_id: Some("saved-run-session".into()),
                    },
                    definition,
                    manifest: crate::ManagedManifest {
                        format: 1,
                        planner: "native".into(),
                        definition: revision.clone(),
                        calls: Default::default(),
                    },
                },
                generation: 10,
                progress: 12,
                running: false,
                lifecycle: 14,
            },
            readiness: PackageReadinessV1::Failed {
                code: PackageErrorCodeV1::Invalid,
                field: "model evaluation".into(),
            },
            status_progress: 12,
        };
        let status = InstanceStatusV1::try_from(status)?;
        assert_eq!(
            serde_json::to_value(&status)?,
            serde_json::json!({
                "id":"counts", "definition_revision":revision,
                "generation":10, "lifecycle":14, "running":false,
                "progress":12, "status_progress":12,
                "readiness":{"state":"failed", "code":"invalid", "field":"model evaluation"}
            }),
        );
        Ok(())
    }

    #[test]
    fn selected_wire_preserves_schema() -> TestResult {
        for empty in [false, true] {
            let schema =
                sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
            let batch = if empty {
                sdk::RecordBatch::new_empty(std::sync::Arc::new(schema.clone()))
            } else {
                crate::decode_parameters(&schema, Some(&serde_json::json!({"value":u64::MAX})))?
                    .ok_or("value batch")?
            };
            let data = sdk::Dataset {
                name: "query".into(),
                batches: vec![batch],
            };
            let response = PackageResponseV1::try_from(&data)?;
            let bytes = response.encode()?;
            let PackageResponseV1::Output(output) = PackageResponseV1::from_bytes(&bytes)? else {
                return Err("selected output variant".into());
            };
            let decoded = output.decode_any(Default::default())?;
            assert_eq!(decoded.name, data.name);
            assert_eq!(decoded.batches, data.batches);
            assert_eq!(decoded.batches[0].schema().as_ref(), &schema);
        }
        assert!(PackageResponseV1::try_from(&sdk::Dataset {
            name: "query".into(),
            batches: Vec::new()
        })
        .is_err());
        Ok(())
    }

    #[test]
    fn binary_response_keeps_bytes() -> TestResult {
        let data = sdk::wire::Dataset {
            name: "query".into(),
            arrow_ipc: vec![255; 4096],
        };
        let bytes = PackageResponseV1::Output(data.clone()).encode()?;
        assert!(bytes
            .windows(data.arrow_ipc.len())
            .any(|value| value == data.arrow_ipc));
        assert!(bytes.len() < data.arrow_ipc.len() + 64);
        let PackageResponseV1::Output(returned) = PackageResponseV1::from_bytes(&bytes)? else {
            return Err("binary output variant".into());
        };
        assert_eq!(returned, data);
        Ok(())
    }

    #[test]
    fn binary_ids_keep_shape() -> TestResult {
        #[derive(Debug, Deserialize, PartialEq, Serialize)]
        struct Fixed {
            id: [u8; 16],
            payload: Vec<u8>,
        }
        let value = Fixed {
            id: [255; 16],
            payload: vec![255; 128],
        };
        let mut bytes = Vec::new();
        value.serialize(
            &mut rmp_serde::Serializer::new(&mut bytes)
                .with_struct_map()
                .with_bytes(rmp_serde::config::BytesMode::ForceIterables),
        )?;
        assert_eq!(rmp_serde::from_slice::<Fixed>(&bytes)?, value);
        assert!(bytes
            .windows(value.payload.len())
            .any(|bytes| bytes == value.payload));
        Ok(())
    }

    #[test]
    fn response_rejects_invalid_frames() -> TestResult {
        let output = sdk::wire::Dataset {
            name: "query".into(),
            arrow_ipc: vec![255; 16],
        };
        let bytes = PackageResponseV1::Output(output.clone()).encode()?;
        for invalid in [
            &[][..],
            &[0xc1][..],
            &bytes[..bytes.len() - 1],
            b"{}".as_slice(),
        ] {
            assert!(matches!(
                PackageResponseV1::from_bytes(invalid),
                Err(crate::Error::PackageResponseDecode { .. })
            ));
        }
        for suffix in [vec![0], bytes.clone()] {
            let mut invalid = bytes.clone();
            invalid.extend(suffix);
            assert!(matches!(
                PackageResponseV1::from_bytes(&invalid),
                Err(crate::Error::Package {
                    code: PackageErrorCodeV1::Invalid,
                    field: "package response trailing bytes",
                    ..
                })
            ));
        }
        for invalid in [
            serde_json::json!({}),
            serde_json::json!({"unknown": {}}),
            serde_json::json!({"output": output, "instance": {}}),
            serde_json::json!({"output": {"name":"query", "arrow_ipc": [], "unknown": true}}),
        ] {
            let bytes = rmp_serde::to_vec_named(&invalid)?;
            assert!(matches!(
                PackageResponseV1::from_bytes(&bytes),
                Err(crate::Error::PackageResponseDecode { .. })
            ));
        }
        Ok(())
    }

    #[test]
    fn response_errors_keep_categories() -> TestResult {
        use erebor_runtime_error::{ErrorExt as _, RetryHint, StatusCode};

        let decode = PackageResponseV1::from_bytes(&[0xc1])
            .err()
            .ok_or("invalid frame accepted")?;
        assert!(matches!(decode, crate::Error::PackageResponseDecode { .. }));
        assert_eq!(decode.status_code(), StatusCode::InvalidArguments);
        assert_eq!(decode.retry_hint(), RetryHint::NonRetryable);
        assert!(std::error::Error::source(&decode)
            .is_some_and(|source| source.is::<rmp_serde::decode::Error>()));
        let encode = snafu::IntoError::into_error(
            crate::PackageResponseEncodeSnafu,
            rmp_serde::encode::Error::InvalidDataModel("fixture"),
        );
        assert_eq!(encode.status_code(), StatusCode::Internal);
        assert_eq!(encode.retry_hint(), RetryHint::NonRetryable);
        assert!(std::error::Error::source(&encode)
            .is_some_and(|source| source.is::<rmp_serde::encode::Error>()));
        Ok(())
    }
}
