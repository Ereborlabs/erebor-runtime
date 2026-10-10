use std::collections::HashMap;
use std::sync::Arc;

use araphor_analysis_sdk as sdk;
use sdk::arrow_array::builder::{ListBuilder, StringBuilder};
use sdk::arrow_array::{ArrayRef, BinaryArray, StringArray};
use snafu::ResultExt as _;

use super::{FindingReasonV1, FindingV1, GraphAndFindingOwner};
use crate::{AnalysisContractSnafu, GraphEncodingSnafu, GraphInvalidSnafu, Result};

impl GraphAndFindingOwner {
    pub fn analysis_package(package_id: &str) -> Result<sdk::Package> {
        Self::contract_id(package_id)?;
        let inputs = vec![
            sdk::Port::new(
                "records",
                sdk::Schema::new(vec![
                    Self::host_field("record_id", "DiscoveryRecordIdV1", "serde-json-v1"),
                    sdk::Field::new("original_kernel_sequence", sdk::DataType::UInt64, true),
                    Self::host_field("wire_record", "EvidenceRecord", "protobuf-v1"),
                ]),
            ),
            Self::host_port("coverage", "DiscoveryCoverageV1", sdk::OutputKind::Table),
            Self::host_port(
                "coverage_keys",
                "GraphCoverageKeyV1",
                sdk::OutputKind::Table,
            ),
            Self::host_port("facts", "AnalysisContextVersionV1", sdk::OutputKind::Table),
            sdk::Port::new(
                "manifest",
                sdk::Schema::new(vec![
                    Self::host_field("source", "EvidenceIntakeIdentityV1", "serde-json-v1"),
                    Self::host_field("revision", "GraphRevisionV1", "serde-json-v1"),
                ]),
            ),
        ];
        let mut findings = Self::host_port("findings", "FindingV1", sdk::OutputKind::Findings);
        findings.evidence_required = true;
        let outputs = vec![
            Self::host_port("subjects", "GraphSubjectKeyV1", sdk::OutputKind::Subjects),
            Self::host_port(
                "relationships",
                "GraphEdgeV1",
                sdk::OutputKind::Relationships,
            ),
            findings,
            Self::host_port("branches", "GraphBranchV1", sdk::OutputKind::Table),
        ];
        let mut model = sdk::Model::new("detect", inputs, outputs);
        model.reasons = Self::reasons(package_id)
            .iter()
            .map(|reason| {
                Ok(sdk::Reason {
                    code: reason.analysis_code(package_id)?,
                    details: Self::reason_schema(),
                })
            })
            .collect::<Result<_>>()?;
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![Self::host_port(
                "state",
                "GraphPackageCheckpointV1",
                sdk::OutputKind::Table,
            )],
        });
        let package = sdk::Package::new(package_id, "1", vec![model]);
        package.validate().context(AnalysisContractSnafu)?;
        Ok(package)
    }

    fn contract_id(package_id: &str) -> Result<()> {
        if FindingV1::PACKAGES.contains(&package_id) {
            Ok(())
        } else {
            GraphInvalidSnafu {
                field: "analysis package identity",
            }
            .fail()
        }
    }

    fn reasons(package_id: &str) -> &'static [FindingReasonV1] {
        use FindingReasonV1 as Reason;
        match package_id {
            "HF-PROC-001" => &[
                Reason::UnexpectedEffect,
                Reason::AuditedRoleDeviation,
                Reason::LineageCoverageGap,
                Reason::Contradiction,
                Reason::OutsideAuthority,
                Reason::InMemoryOnly,
                Reason::PayloadUnobservable,
            ],
            "HF-DW-001" => &[
                Reason::CredentialPivot,
                Reason::ContextualCredentialPivot,
                Reason::MissingAuthorityProof,
                Reason::Contradiction,
            ],
            "HF-XNODE-001" => &[Reason::KubernetesProofMissing],
            _ => &[],
        }
    }

    fn host_field(name: &str, host_type: &str, encoding: &str) -> sdk::Field {
        sdk::Field::new(name, sdk::DataType::Binary, false).with_metadata(HashMap::from([
            ("araphor.host_type".into(), host_type.into()),
            ("araphor.encoding".into(), encoding.into()),
        ]))
    }

    fn host_port(name: &str, host_type: &str, kind: sdk::OutputKind) -> sdk::Port {
        let mut port = sdk::Port::new(
            name,
            sdk::Schema::new(vec![Self::host_field("value", host_type, "serde-json-v1")]),
        );
        port.kind = kind;
        port
    }

    fn reason_schema() -> sdk::Schema {
        sdk::Schema::new(vec![
            sdk::Field::new("finding_id", sdk::DataType::Utf8, false),
            Self::host_field("subject_key", "GraphSubjectKeyV1", "serde-json-v1"),
            sdk::Field::new("state", sdk::DataType::Utf8, false),
            sdk::Field::new("severity", sdk::DataType::Utf8, false),
            sdk::Field::new("sensitivity", sdk::DataType::Utf8, false),
            sdk::Field::new("required_action", sdk::DataType::Utf8, true),
            sdk::Field::new(
                "limits",
                sdk::DataType::List(Arc::new(sdk::Field::new(
                    "item",
                    sdk::DataType::Utf8,
                    false,
                ))),
                false,
            ),
        ])
    }
}

impl FindingReasonV1 {
    pub fn analysis_code(self, package_id: &str) -> Result<String> {
        GraphAndFindingOwner::contract_id(package_id)?;
        let value = serde_json::to_value(self).context(GraphEncodingSnafu)?;
        let code = value.as_str().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "analysis reason spelling",
            }
            .build()
        })?;
        Ok(format!("{package_id}.{code}"))
    }

    pub fn from_analysis_code(package_id: &str, code: &str) -> Result<Self> {
        GraphAndFindingOwner::contract_id(package_id)?;
        let local = code
            .strip_prefix(&format!("{package_id}."))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "analysis reason namespace",
                }
                .build()
            })?;
        serde_json::from_value(serde_json::Value::String(local.into())).map_err(|_| {
            GraphInvalidSnafu {
                field: "analysis reason code",
            }
            .build()
        })
    }
}

impl FindingV1 {
    pub fn analysis_reason(&self, row: u64) -> Result<sdk::ReasonValue> {
        self.validate()?;
        let subject = serde_json::to_vec(&self.subject_id).context(GraphEncodingSnafu)?;
        let mut limits = ListBuilder::new(StringBuilder::new()).with_field(Arc::new(
            sdk::Field::new("item", sdk::DataType::Utf8, false),
        ));
        for limit in &self.limits {
            limits.values().append_value(limit);
        }
        limits.append(true);
        let columns: Vec<ArrayRef> = vec![
            Arc::new(StringArray::from(vec![self.finding_id.as_str()])),
            Arc::new(BinaryArray::from(vec![subject.as_slice()])),
            Arc::new(StringArray::from(vec![Self::enum_text(&self.state)?])),
            Arc::new(StringArray::from(vec![Self::enum_text(&self.severity)?])),
            Arc::new(StringArray::from(vec![Self::enum_text(&self.sensitivity)?])),
            Arc::new(StringArray::from(vec![self.required_action.as_deref()])),
            Arc::new(limits.finish()),
        ];
        let details =
            sdk::RecordBatch::try_new(Arc::new(GraphAndFindingOwner::reason_schema()), columns)
                .map_err(|source| sdk::Error::Batch {
                    source,
                    location: snafu::location!(),
                })
                .context(AnalysisContractSnafu)?;
        Ok(sdk::ReasonValue {
            output: sdk::RowRef {
                dataset: "findings".into(),
                row,
            },
            code: self.reason.analysis_code(&self.package_id)?,
            details,
        })
    }

    fn enum_text(value: &impl serde::Serialize) -> Result<String> {
        match serde_json::to_value(value).context(GraphEncodingSnafu)? {
            serde_json::Value::String(value) => Ok(value),
            _ => GraphInvalidSnafu {
                field: "analysis detail enum",
            }
            .fail(),
        }
    }
}

#[cfg(test)]
mod tests;
