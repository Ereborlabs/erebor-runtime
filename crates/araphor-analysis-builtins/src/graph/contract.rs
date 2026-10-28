use std::sync::OnceLock;

use super::*;
use crate::Rows;

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

    pub fn descriptor(self) -> sdk::Package {
        self.declaration().clone()
    }

    fn declaration(self) -> &'static sdk::Package {
        static PROCESS: OnceLock<sdk::Package> = OnceLock::new();
        static CREDENTIALS: OnceLock<sdk::Package> = OnceLock::new();
        static KUBERNETES: OnceLock<sdk::Package> = OnceLock::new();
        let declaration = match self {
            Self::Process => &PROCESS,
            Self::Credentials => &CREDENTIALS,
            Self::Kubernetes => &KUBERNETES,
        };
        declaration.get_or_init(|| self.build_descriptor())
    }

    pub fn inputs() -> &'static [sdk::Port] {
        static INPUTS: OnceLock<Vec<sdk::Port>> = OnceLock::new();
        INPUTS.get_or_init(|| vec![Observation::port(), Fact::port(), Manifest::port()])
    }

    fn build_descriptor(self) -> sdk::Package {
        let inputs = Self::inputs().to_vec();
        let mut findings = Finding::port();
        findings.kind = sdk::OutputKind::Findings;
        findings.evidence_required = true;
        let details = ReasonDetails::port().schema;
        let mut subjects = Subject::port();
        subjects.kind = sdk::OutputKind::Subjects;
        let mut relationships = Relationship::port();
        relationships.kind = sdk::OutputKind::Relationships;
        let mut model = sdk::Model::new(
            "detect",
            inputs,
            vec![
                subjects,
                relationships,
                findings,
                GraphBranchV1::port(),
                Metadata::port(),
            ],
        );
        model.reasons = self
            .reasons()
            .iter()
            .map(|reason| sdk::Reason {
                code: format!("{}.{}", self.id(), reason),
                details: details.clone(),
            })
            .collect();
        model.checkpoint = Some(sdk::CheckpointSpec {
            resume_input_changes: true,
            version: 1,
            datasets: vec![
                Rows::port::<State>("state", "graph.state.v1"),
                Progress::port(),
            ],
        });
        sdk::Package::new(self.id(), "1", vec![model])
    }

    pub fn evaluate(self, evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        self.declaration()
            .check_evaluation(evaluation)?
            .evaluate(|input| self.compute(input))
    }

    pub fn compute(self, checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        if checked.package() != self.declaration() {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Incompatible,
                "graph package",
            ));
        }
        let package = checked.package();
        let evaluation = checked.evaluation();
        let model = checked.model();
        if let Some(checkpoint) = &evaluation.checkpoint {
            let declaration = model.checkpoint.as_ref().ok_or_else(|| {
                sdk::Error::contract(sdk::ErrorCode::Invalid, "graph checkpoint declaration")
            })?;
            let state = &declaration.datasets[0];
            let data = checkpoint
                .datasets
                .iter()
                .find(|data| data.name == state.name)
                .ok_or_else(|| Computation::invalid("graph checkpoint state"))?;
            let states: Vec<State> = Rows::decode(state, data)?;
            if states.len() != 1 {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Invalid,
                    "graph checkpoint rows",
                ));
            }
        }
        let records = Observation::read(checked)?;
        let facts = Fact::read(checked)?;
        let mut manifests = Manifest::read(checked)?;
        if manifests.len() != 1 {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "graph manifest count",
            ));
        }
        let mut computation = Computation::new(records, facts, manifests.remove(0), self)?;
        computation.update(evaluation)?;
        computation.output(package)
    }

    fn reasons(self) -> &'static [&'static str] {
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
