use std::sync::OnceLock;

use super::*;
use crate::Rows;

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
        INPUTS.get_or_init(|| {
            vec![
                Rows::port::<Observation>("records", "graph.observation.v1"),
                Rows::port::<Fact>("facts", "graph.fact.v1"),
                Rows::port::<Manifest>("manifest", "graph.manifest.v1"),
            ]
        })
    }

    fn build_descriptor(self) -> sdk::Package {
        let inputs = Self::inputs().to_vec();
        let mut findings = Rows::port::<Finding>("findings", "graph.finding-candidate.v1");
        findings.kind = sdk::OutputKind::Findings;
        findings.evidence_required = true;
        let details = findings.schema.clone();
        let mut subjects = Rows::port::<Subject>("subjects", "graph.subject-selection.v1");
        subjects.kind = sdk::OutputKind::Subjects;
        let mut relationships =
            Rows::port::<Relationship>("relationships", "graph.relationship-candidate.v1");
        relationships.kind = sdk::OutputKind::Relationships;
        let mut model = sdk::Model::new("detect", inputs, vec![subjects, relationships, findings]);
        model.reasons = self
            .reasons()
            .iter()
            .map(|reason| sdk::Reason {
                code: format!("{}.{}", self.id(), reason),
                details: details.clone(),
            })
            .collect();
        model.checkpoint = Some(sdk::CheckpointSpec {
            resume_input_changes: false,
            version: 1,
            datasets: vec![Rows::port::<State>("state", "graph.state.v1")],
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
            let states: Vec<State> =
                Rows::decode(&declaration.datasets[0], &checkpoint.datasets[0])?;
            if states.len() != 1 {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Invalid,
                    "graph checkpoint rows",
                ));
            }
        }
        let records = Rows::input(checked, "records")?;
        let facts = Rows::input(checked, "facts")?;
        let mut manifests = Rows::input(checked, "manifest")?;
        if manifests.len() != 1 {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "graph manifest count",
            ));
        }
        // Each evaluation replays its complete retained window.
        let mut computation = Computation::new(records, facts, manifests.remove(0), self)?;
        match self {
            Self::Process => computation.process()?,
            Self::Credentials => computation.credentials()?,
            Self::Kubernetes => computation.kubernetes()?,
        }
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

impl Computation {
    pub(super) fn output(mut self, package: &sdk::Package) -> sdk::Result<sdk::Output> {
        for evidence in self.edges.iter_mut().map(|edge| &mut edge.evidence).chain(
            self.findings
                .iter_mut()
                .map(|finding| &mut finding.evidence),
        ) {
            Self::canonical(evidence);
        }
        let model = &package.exports[0];
        let mut output = sdk::Output {
            datasets: vec![
                Rows::encode(&model.outputs[0], &self.subjects)?,
                Rows::encode(&model.outputs[1], &self.edges)?,
                Rows::encode(&model.outputs[2], &self.findings)?,
            ],
            ..Default::default()
        };
        for (row, finding) in self.findings.iter().enumerate() {
            let reference = sdk::RowRef {
                dataset: "findings".into(),
                row: row as u64,
            };
            for &row in &finding.evidence {
                output.evidence.push(sdk::EvidenceLink {
                    output: reference.clone(),
                    input: sdk::RowRef {
                        dataset: "records".into(),
                        row,
                    },
                });
            }
            let details = Rows::encode(&model.outputs[2], std::slice::from_ref(finding))?
                .batches
                .remove(0);
            output.reasons.push(sdk::ReasonValue {
                output: reference,
                code: format!("{}.{}", package.id, finding.reason),
                details,
            });
        }
        let checkpoint = model.checkpoint.as_ref().ok_or_else(|| {
            sdk::Error::contract(sdk::ErrorCode::Invalid, "graph checkpoint descriptor")
        })?;
        output.checkpoint = Some(sdk::Checkpoint {
            version: 1,
            datasets: vec![Rows::encode(&checkpoint.datasets[0], &[self.state])?],
        });
        Ok(output)
    }

    pub(super) fn canonical(evidence: &mut Vec<u64>) {
        evidence.sort_unstable();
        evidence.dedup();
    }
}
