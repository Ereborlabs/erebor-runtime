use super::*;

#[derive(Clone, Debug, serde::Deserialize, Eq, PartialEq, serde::Serialize)]
pub struct ReasonDetails {
    pub record: u32,
    pub context: Option<u32>,
    pub reason: String,
    pub confirmed: bool,
    pub evidence: Vec<u32>,
    pub limits: Vec<String>,
}

impl ReasonDetails {
    pub fn port() -> sdk::Port {
        use sdk::{DataType as Type, Field};
        sdk::Port::new(
            "reason_details",
            sdk::Schema::new(vec![
                Field::new("record", Type::UInt32, false),
                Field::new("context", Type::UInt32, true),
                Field::new("reason", Type::Utf8, false),
                Field::new("confirmed", Type::Boolean, false),
                Field::new(
                    "evidence",
                    Type::List(std::sync::Arc::new(Field::new("item", Type::UInt32, false))),
                    false,
                ),
                Field::new(
                    "limits",
                    Type::List(std::sync::Arc::new(Field::new("item", Type::Utf8, false))),
                    false,
                ),
            ]),
        )
    }

    pub fn from_finding(
        finding: &Finding,
        records: &BTreeMap<&crate::discovery::DiscoveryRecordIdV1, u32>,
    ) -> sdk::Result<Self> {
        let prefix = format!("{}.", finding.package_id);
        let reason = finding
            .reason_code
            .strip_prefix(&prefix)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| Computation::invalid("graph reason namespace"))?;
        Ok(Self {
            record: finding.record,
            context: finding.context,
            reason: reason.into(),
            confirmed: finding.state == FindingStateV1::Confirmed,
            evidence: finding
                .evidence
                .iter()
                .map(|id| {
                    records
                        .get(id)
                        .copied()
                        .ok_or_else(|| Computation::invalid("graph reason evidence"))
                })
                .collect::<sdk::Result<_>>()?,
            limits: finding.limits.clone(),
        })
    }

    pub fn encode(rows: &[Self]) -> sdk::Result<sdk::Dataset> {
        let port = Self::port();
        Ok(sdk::Dataset {
            name: port.name,
            batches: vec![
                serde_arrow::to_record_batch(port.schema.fields(), &rows).map_err(Self::error)?
            ],
        })
    }

    pub fn decode(data: &sdk::Dataset) -> sdk::Result<Vec<Self>> {
        let mut rows = Vec::new();
        for batch in &data.batches {
            rows.extend(serde_arrow::from_record_batch::<Vec<Self>>(batch).map_err(Self::error)?);
        }
        Ok(rows)
    }

    fn error(error: serde_arrow::Error) -> sdk::Error {
        sdk::arrow_schema::ArrowError::ExternalError(Box::new(error)).into()
    }
}

impl Detector {
    pub const fn id(self) -> &'static str {
        match self {
            Self::Process => "HF-PROC-001",
            Self::Credentials => "HF-DW-001",
            Self::Kubernetes => "HF-XNODE-001",
        }
    }

    pub fn from_id(id: &str) -> sdk::Result<Self> {
        match id {
            "HF-PROC-001" => Ok(Self::Process),
            "HF-DW-001" => Ok(Self::Credentials),
            "HF-XNODE-001" => Ok(Self::Kubernetes),
            _ => Err(sdk::Error::contract(
                sdk::ErrorCode::Incompatible,
                "graph package",
            )),
        }
    }

    pub(super) fn reasons(self) -> &'static [&'static str] {
        match self {
            Self::Process => &[
                "UNEXPECTED_EFFECT",
                "AUDITED_ROLE_DEVIATION",
                "LINEAGE_COVERAGE_GAP",
                "CONTRADICTION",
                "OUTSIDE_AUTHORITY",
                "IN_MEMORY_ONLY",
                "PAYLOAD_UNOBSERVABLE",
            ],
            Self::Credentials => &[
                "CREDENTIAL_PIVOT",
                "CONTEXTUAL_CREDENTIAL_PIVOT",
                "MISSING_AUTHORITY_PROOF",
                "CONTRADICTION",
            ],
            Self::Kubernetes => &["KUBERNETES_PROOF_MISSING"],
        }
    }
}
