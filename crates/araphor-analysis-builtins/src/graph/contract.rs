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
        let inputs = vec![
            Rows::port::<Observation>("records", "graph.observation.v1"),
            Rows::port::<Fact>("facts", "graph.fact.v1"),
            Rows::port::<Manifest>("manifest", "graph.manifest.v1"),
        ];
        let mut findings = Rows::port::<Finding>("findings", "graph.finding-candidate.v1");
        findings.kind = sdk::OutputKind::Findings;
        findings.evidence_required = true;
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
                details: Rows::port::<Finding>("details", "graph.finding-candidate.v1").schema,
            })
            .collect();
        model.checkpoint = Some(sdk::CheckpointSpec {
            version: 1,
            datasets: vec![Rows::port::<State>("state", "graph.state.v1")],
        });
        sdk::Package::new(self.id(), "1", vec![model])
    }

    pub fn evaluate(self, evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        let package = self.descriptor();
        package.validate_evaluation(evaluation)?;
        let model = &package.exports[0];
        if let Some(checkpoint) = &evaluation.checkpoint {
            let declaration = model.checkpoint.as_ref().ok_or_else(|| {
                sdk::Error::contract(sdk::ErrorCode::Invalid, "graph checkpoint declaration")
            })?;
            let states: Vec<State> = Rows::decode(
                &declaration.datasets[0],
                &checkpoint.datasets[0],
                evaluation.context.limits,
            )?;
            if states.len() != 1 {
                return Err(sdk::Error::contract(
                    sdk::ErrorCode::Invalid,
                    "graph checkpoint rows",
                ));
            }
        }
        let records = Rows::decode(
            &model.inputs[0],
            &evaluation.input("records")?.data,
            evaluation.context.limits,
        )?;
        let facts: Vec<Fact> = Rows::decode(
            &model.inputs[1],
            &evaluation.input("facts")?.data,
            evaluation.context.limits,
        )?;
        let mut manifests = Rows::decode(
            &model.inputs[2],
            &evaluation.input("manifest")?.data,
            evaluation.context.limits,
        )?;
        if manifests.len() != 1 {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "graph manifest count",
            ));
        }
        // Each evaluation replays its complete retained window.
        let mut computation = Computation {
            records,
            facts,
            manifest: manifests.remove(0),
            subjects: Vec::new(),
            edges: Vec::new(),
            findings: Vec::new(),
            state: State {
                value: match self {
                    Self::Kubernetes => "KUBERNETES_PROOF_MISSING",
                    _ => "WAITING",
                }
                .into(),
            },
        };
        for fact in &computation.facts {
            computation.record(fact.record)?;
        }
        match self {
            Self::Process => computation.process()?,
            Self::Credentials => computation.credentials()?,
            Self::Kubernetes => computation.kubernetes()?,
        }
        let output = computation.output(&package, evaluation.context.limits)?;
        package.validate_output(evaluation, &output)?;
        Ok(output)
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
    fn output(self, package: &sdk::Package, limits: sdk::Limits) -> sdk::Result<sdk::Output> {
        let model = &package.exports[0];
        let mut output = sdk::Output {
            datasets: vec![
                Rows::encode(&model.outputs[0], &self.subjects, limits)?,
                Rows::encode(&model.outputs[1], &self.edges, limits)?,
                Rows::encode(&model.outputs[2], &self.findings, limits)?,
            ],
            ..Default::default()
        };
        for (row, finding) in self.findings.iter().enumerate() {
            let reference = sdk::RowRef {
                dataset: "findings".into(),
                row: row as u64,
            };
            let evidence: std::collections::BTreeSet<_> =
                finding.evidence.iter().copied().collect();
            for row in evidence {
                output.evidence.push(sdk::EvidenceLink {
                    output: reference.clone(),
                    input: sdk::RowRef {
                        dataset: "records".into(),
                        row,
                    },
                });
            }
            let details = Rows::encode(
                &Rows::port::<Finding>("details", "graph.finding-candidate.v1"),
                std::slice::from_ref(finding),
                limits,
            )?
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
            datasets: vec![Rows::encode(
                &checkpoint.datasets[0],
                &[self.state],
                limits,
            )?],
        });
        Ok(output)
    }
}
