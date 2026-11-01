use std::sync::OnceLock;

use super::{credential::CredentialIndex, *};

impl Detector {
    pub fn descriptor(self) -> sdk::Package {
        self.declaration().clone()
    }

    pub fn supports_units(model: &sdk::Model) -> bool {
        let expected = &Self::Process.declaration().exports[0];
        model.input_mode == sdk::InputMode::Resolved
            && model.checkpoint.is_none()
            && model.change_inputs == expected.change_inputs
            && model
                .inputs
                .iter()
                .map(|input| &input.port)
                .eq(expected.inputs.iter().map(|input| &input.port))
            && model.outputs == expected.outputs
            && model
                .inputs
                .iter()
                .enumerate()
                .all(|(slot, input)| match slot {
                    0 => matches!(input.source, sdk::InputSource::Query(_)),
                    3 | 4 => matches!(input.source, sdk::InputSource::Lookup(_)),
                    _ => input.source == expected.inputs[slot].source,
                })
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
        declaration.get_or_init(|| self.build_units())
    }

    fn build_units(self) -> sdk::Package {
        let mut subjects = SubjectChange::port();
        subjects.kind = sdk::OutputKind::Subjects;
        let mut relationships = RelationshipChange::port();
        relationships.kind = sdk::OutputKind::Relationships;
        let mut findings = FindingChange::port();
        findings.kind = sdk::OutputKind::Findings;
        findings.evidence_required = true;
        let mut model = sdk::Model::new(
            "detect",
            vec![
                Unit::port(),
                Unit::removals_port(),
                sdk::ChangeInputs::reset_port("reset"),
                Observation::port(),
                Fact::port(),
                Unit::affected_port(),
            ],
            vec![
                subjects,
                relationships,
                findings,
                Contribution::port(),
                GraphPackageStateV1::port(),
            ],
        );
        let support = match self {
            Self::Credentials => include_str!("units/credential.sql"),
            _ => "SELECT record_row AS root_row, record_row AS support_row FROM qualified",
        };
        model.inputs[0].source = sdk::InputSource::Query(format!(
            include_str!("units/selection.sql"),
            support = support
        ));
        model.inputs[1].source = sdk::InputSource::Query(
            "SELECT prior.* FROM before.units prior JOIN affected \
             ON prior.record = affected.record ORDER BY prior.record"
                .into(),
        );
        model.inputs[3].source = sdk::InputSource::Lookup(include_str!("units/records.sql").into());
        model.inputs[4].source = sdk::InputSource::Lookup(include_str!("units/facts.sql").into());
        model.inputs[5].source = sdk::InputSource::Query(
            "SELECT record FROM inserted.units UNION SELECT record FROM removed.units".into(),
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.change_inputs = Some(sdk::ChangeInputs {
            reset: "reset".into(),
            ports: vec![sdk::ChangeInput {
                affected: "affected".into(),
                before: "unit_removals".into(),
                after: "units".into(),
            }],
        });
        model.reasons = self
            .reasons()
            .iter()
            .map(|reason| sdk::Reason {
                code: format!("{}.{}", self.id(), reason),
                details: ReasonDetails::port().schema,
            })
            .collect();
        sdk::Package::new(self.id(), "1", vec![model])
    }

    pub fn evaluate(self, evaluation: &sdk::Evaluation) -> sdk::Result<sdk::Output> {
        self.declaration()
            .check_evaluation(evaluation)?
            .evaluate(|checked| self.compute(checked))
    }

    pub fn compute(self, checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<sdk::Output> {
        if checked.package() != self.declaration() {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Incompatible,
                "graph unit package",
            ));
        }
        let units = Unit::decode(&checked.evaluation().input("units")?.data)?;
        let records = Observation::read(checked)?;
        let facts = Fact::read(checked)?;
        Computation::indexed(records, facts, Manifest { window_ns: 0 }, self)?.unit_output(units)
    }
}

impl Unit {
    fn rows(
        &self,
        records: &BTreeMap<&crate::discovery::DiscoveryRecordIdV1, u32>,
        computation: &Computation,
    ) -> sdk::Result<BTreeSet<u32>> {
        if self
            .support
            .windows(2)
            .any(|pair| pair[0].record >= pair[1].record)
        {
            return Err(Computation::invalid("graph unit support order"));
        }
        let mut rows = BTreeSet::new();
        for support in &self.support {
            let &row = records
                .get(&support.record)
                .ok_or_else(|| Computation::invalid("graph unit support record"))?;
            if support.proof != computation.record(row)?.proof_quality
                || support.facts.windows(2).any(|pair| pair[0] >= pair[1])
                || !support
                    .facts
                    .iter()
                    .eq(computation.facts(row).map(|(_, fact)| &fact.key))
            {
                return Err(Computation::invalid("graph unit support value"));
            }
            rows.insert(row);
        }
        let row = records
            .get(&self.record)
            .ok_or_else(|| Computation::invalid("graph unit record"))?;
        if !rows.contains(row) {
            return Err(Computation::invalid("graph unit root support"));
        }
        Ok(rows)
    }
}

impl Computation {
    fn unit_output(mut self, units: Vec<Unit>) -> sdk::Result<sdk::Output> {
        let record_ids = self
            .records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>();
        let record_rows = record_ids
            .iter()
            .enumerate()
            .map(|(row, id)| (id, row as u32))
            .collect::<BTreeMap<_, _>>();
        let index = match self.detector {
            Detector::Credentials => Some(CredentialIndex::new(&self)?),
            _ => None,
        };
        let mut subjects = Vec::new();
        let mut relationships = Vec::new();
        let mut findings = Vec::new();
        let mut contributions = Vec::with_capacity(units.len());
        let mut output = sdk::Output::default();
        let mut seen = BTreeSet::new();
        for unit in units {
            if !seen.insert(unit.record.clone()) {
                return Err(Self::invalid("graph duplicate unit"));
            }
            self.allowed_rows = Some(unit.rows(&record_rows, &self)?);
            self.manifest.window_ns = unit.window_ns;
            let row = *record_rows
                .get(&unit.record)
                .ok_or_else(|| Self::invalid("graph unit record"))?;
            let state = match self.detector {
                Detector::Process => self
                    .process_unit(row)?
                    .map(|marker| {
                        Ok::<_, sdk::Error>(UnitState {
                            state: GraphPackageStateV1::from_marker(&marker)?,
                            position: self.records[row as usize].position,
                            fact: None,
                        })
                    })
                    .transpose()?,
                Detector::Credentials => self
                    .credential_event(
                        row,
                        index
                            .as_ref()
                            .ok_or_else(|| Self::invalid("graph credential index"))?,
                    )?
                    .map(|marker| {
                        Ok::<_, sdk::Error>(UnitState {
                            state: GraphPackageStateV1::from_marker(&marker)?,
                            position: self.records[row as usize].position,
                            fact: None,
                        })
                    })
                    .transpose()?,
                Detector::Kubernetes => self.kubernetes_unit(row)?,
            };
            let mut contribution = Contribution {
                record: unit.record,
                subjects: Vec::new(),
                relationships: Vec::new(),
                findings: Vec::new(),
                state,
            };
            let keys = self
                .subjects
                .iter()
                .map(|subject| subject.key.clone())
                .collect::<Vec<_>>();
            for subject in self.subjects.drain(..) {
                contribution.subjects.push(subjects.len() as u64);
                subjects.push(SubjectChange {
                    anchor: Anchor::from_positions(
                        subject.record,
                        subject.context,
                        &record_ids,
                        &self.facts,
                    )?,
                    key: subject.key,
                });
            }
            self.subject_indices.clear();
            for value in std::mem::take(&mut self.edges).into_values() {
                contribution.relationships.push(relationships.len() as u64);
                relationships.push(RelationshipChange {
                    anchor: Anchor::from_positions(
                        value.record,
                        value.fact,
                        &record_ids,
                        &self.facts,
                    )?,
                    key: RelationshipIdentity::from_keys(&value.edge.key, &keys, &record_ids)?,
                    proof_quality: value.edge.proof_quality,
                    required_coverage_interval_ids: value.edge.required_coverage_interval_ids,
                    first_boottime_ns: value.edge.first_boottime_ns,
                    last_boottime_ns: value.edge.last_boottime_ns,
                });
            }
            for mut finding in std::mem::take(&mut self.findings).into_values() {
                finding.sensitivity = if unit.restricted {
                    ContextSensitivityV1::HostRestricted
                } else {
                    ContextSensitivityV1::Tenant
                };
                let reference = sdk::RowRef {
                    dataset: "findings".into(),
                    row: findings.len() as u64,
                };
                let details = ReasonDetails::from_finding(&finding, &record_rows)?;
                for &row in &details.evidence {
                    output.evidence.push(sdk::EvidenceLink {
                        output: reference.clone(),
                        input: sdk::RowRef {
                            dataset: "records".into(),
                            row: u64::from(row),
                        },
                    });
                }
                output.reasons.push(sdk::ReasonValue {
                    output: reference,
                    code: finding.reason_code.clone(),
                    details: ReasonDetails::encode(&[details])?.batches.remove(0),
                });
                let anchor = Anchor::from_positions(
                    finding.record,
                    finding.context,
                    &record_ids,
                    &self.facts,
                )?;
                contribution.findings.push(findings.len() as u64);
                findings.push(FindingChange::from_local(finding, anchor));
            }
            contributions.push(contribution);
        }
        let state = GraphPackageStateV1::from_marker(match self.detector {
            Detector::Kubernetes => "KUBERNETES_PROOF_MISSING",
            _ => "WAITING",
        })?;
        output.datasets = vec![
            SubjectChange::encode(&subjects)?,
            RelationshipChange::encode(&relationships)?,
            FindingChange::encode(&findings)?,
            Contribution::encode(&contributions)?,
            GraphPackageStateV1::encode(&[state])?,
        ];
        Ok(output)
    }
}
