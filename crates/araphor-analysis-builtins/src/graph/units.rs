use std::sync::{Arc, OnceLock};

use super::{credential::CredentialIndex, *};

impl Detector {
    pub fn descriptor(self) -> sdk::Package {
        self.declaration().clone()
    }

    pub fn supports_units(model: &sdk::Model) -> bool {
        [Self::Credentials].into_iter().any(|detector| {
            let expected = &detector.declaration().exports[0];
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
        })
    }

    fn unit_query(image: &str, scoped: bool) -> String {
        include_str!("units/selection.sql")
            .replace(
                "{scope}",
                if scoped {
                    "JOIN affected ON affected.record = source.record"
                } else {
                    ""
                },
            )
            .replace("{image}", image)
    }

    fn declaration(self) -> &'static sdk::Package {
        static CREDENTIALS: OnceLock<sdk::Package> = OnceLock::new();
        let declaration = match self {
            Self::Credentials => &CREDENTIALS,
        };
        declaration.get_or_init(|| self.build_units())
    }

    fn build_units(self) -> sdk::Package {
        let mut subjects = SubjectChange::port();
        subjects.kind = sdk::OutputKind::Subjects;
        let mut model = sdk::Model::new(
            "detect",
            vec![
                Unit::port(),
                Unit::removals_port(),
                sdk::ChangeInputs::reset_port("reset"),
                Observation::port(),
                Fact::port(),
                Unit::affected_port(),
                Unit::window_port(),
            ],
            vec![subjects],
        );
        let mut relations = araphor_analysis_types::DomainRelations::declarations();
        if matches!(self, Self::Credentials) {
            relations.push(credential::CandidateInput::relation());
        }
        model.graph = Some(sdk::GraphSpec {
            access: sdk::GraphAccess::ReadWrite,
            relations,
        });
        model.inputs[0].source = sdk::InputSource::Query(Self::unit_query("", false));
        model.inputs[1].source = sdk::InputSource::Query(Self::unit_query("before.", true));
        model.inputs[3].source =
            sdk::InputSource::Lookup(include_str!("units/candidates.sql").replace(
                "{network}",
                &(erebor_interceptor_abi::KernelEffectFamilyV1::Network as u32).to_string(),
            ));
        model.inputs[4].source = sdk::InputSource::Lookup(include_str!("units/facts.sql").into());
        model.inputs[5].source = sdk::InputSource::Query("SELECT record FROM graph_dirty".into());
        model.inputs[6].source =
            sdk::InputSource::Table(sdk::TableRef::Named("graph_window".into()));
        model.input_mode = sdk::InputMode::Resolved;
        model.change_inputs = Some(sdk::ChangeInputs {
            reset: "reset".into(),
            ports: vec![sdk::ChangeInput {
                affected: "affected".into(),
                before: "unit_removals".into(),
                after: "units".into(),
                current: Some(Self::unit_query("after.", true)),
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
        let graph = checked.graph()?;
        if Unit::expired(&checked.evaluation().input("window")?.data)? {
            return super::commands::GraphCommands::expire(&graph);
        }
        let units = Unit::decode(&checked.evaluation().input("units")?.data)?;
        let records = Observation::read(checked)?;
        let facts = Fact::read(checked)?;
        let removals = Unit::decode(&checked.evaluation().input("unit_removals")?.data)?;
        let reset = checked
            .model()
            .change_inputs
            .as_ref()
            .ok_or_else(|| Computation::invalid("graph change contract"))?
            .is_reset(checked.evaluation())?;
        let mut owners = units
            .iter()
            .chain(&removals)
            .map(|unit| araphor_analysis_types::DomainRelations::key(&unit.record))
            .collect::<sdk::Result<BTreeSet<_>>>()?;
        owners.insert(araphor_analysis_types::DomainRelations::key(
            &Option::<crate::discovery::DiscoveryRecordIdV1>::None,
        )?);
        if reset {
            graph.clear_scope().map_err(sdk::Error::backend)?;
        } else if !owners.is_empty() {
            graph
                .clear_owners(sdk::arrow_array::BinaryArray::from_iter_values(
                    owners.iter().map(Vec::as_slice),
                ))
                .map_err(sdk::Error::backend)?;
        }
        Computation::indexed(records, facts, Manifest { window_ns: 0 }, self)?
            .unit_output(units, &graph)
    }
}

impl Unit {
    pub fn window_port() -> sdk::Port {
        sdk::Port::new(
            "window",
            sdk::Schema::new(vec![
                sdk::Field::new("source_key", sdk::DataType::Binary, false),
                sdk::Field::new("first_cursor", sdk::DataType::UInt64, false),
                sdk::Field::new("witness_deadline_utc_ns", sdk::DataType::UInt64, false),
                sdk::Field::new("window_ns", sdk::DataType::UInt64, false),
                sdk::Field::new("expired", sdk::DataType::Boolean, false),
            ]),
        )
    }

    pub fn window_data(
        source: &[u8],
        first: u64,
        deadline: u64,
        expired: bool,
    ) -> sdk::Result<sdk::Dataset> {
        if source.is_empty() || first == 0 || deadline == 0 {
            return Err(sdk::Error::contract(
                sdk::ErrorCode::Invalid,
                "graph window configuration",
            ));
        }
        let port = Self::window_port();
        Ok(sdk::Dataset {
            name: port.name,
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(port.schema),
                vec![
                    Arc::new(sdk::arrow_array::BinaryArray::from_vec(vec![source])),
                    Arc::new(sdk::arrow_array::UInt64Array::from(vec![first])),
                    Arc::new(sdk::arrow_array::UInt64Array::from(vec![deadline])),
                    Arc::new(sdk::arrow_array::UInt64Array::from(vec![GRAPH_WINDOW_NS])),
                    Arc::new(sdk::arrow_array::BooleanArray::from(vec![expired])),
                ],
            )?],
        })
    }

    pub fn expired(data: &sdk::Dataset) -> sdk::Result<bool> {
        use sdk::arrow_array::Array as _;
        if data
            .batches
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>()
            != 1
        {
            return Err(Computation::invalid("graph window row"));
        }
        let batch = data
            .batches
            .iter()
            .find(|batch| batch.num_rows() != 0)
            .ok_or_else(|| Computation::invalid("graph window row"))?;
        let expired = batch
            .column_by_name("expired")
            .and_then(|array| {
                array
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::BooleanArray>()
            })
            .filter(|array| !array.is_null(0))
            .ok_or_else(|| Computation::invalid("graph window retention"))?;
        Ok(expired.value(0))
    }

    fn rows(
        &self,
        records: &BTreeMap<&crate::discovery::DiscoveryRecordIdV1, u32>,
        computation: &Computation,
    ) -> sdk::Result<BTreeSet<u32>> {
        let &row = records
            .get(&self.record)
            .ok_or_else(|| Computation::invalid("graph unit record"))?;
        let mut rows = BTreeSet::from([row]);
        for (_, fact) in computation.facts(row) {
            if let FactValue::Policy(policy) = &fact.value {
                for id in &policy.observations {
                    rows.insert(
                        *records
                            .get(id)
                            .ok_or_else(|| Computation::invalid("graph policy support record"))?,
                    );
                }
            }
        }
        Ok(rows)
    }
}

impl Computation {
    fn unit_output(
        mut self,
        units: Vec<Unit>,
        graph: &araphor_graph::Transaction<sdk::GraphTransport<'_>>,
    ) -> sdk::Result<sdk::Output> {
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
        let index = Some(CredentialIndex::new(&self)?);
        let mut subjects = Vec::new();
        let mut commands = super::commands::GraphCommands::default();
        commands.state(
            &araphor_analysis_types::DomainRelations::key(
                &Option::<crate::discovery::DiscoveryRecordIdV1>::None,
            )?,
            araphor_analysis_types::GraphStateMember {
                record: None,
                position: None,
                fact: None,
                state: GraphPackageStateV1::Waiting,
            },
        )?;
        let mut seen = BTreeSet::new();
        for unit in &units {
            if !seen.insert(unit.record.clone()) {
                return Err(Self::invalid("graph duplicate unit"));
            }
        }
        if matches!(self.detector, Detector::Credentials) {
            let rows = units
                .iter()
                .map(|unit| {
                    record_rows
                        .get(&unit.record)
                        .copied()
                        .ok_or_else(|| Self::invalid("graph unit record"))
                })
                .collect::<sdk::Result<Vec<_>>>()?;
            credential::CandidateInput::stage(&self, rows, graph)?;
        }
        for unit in units {
            let mut support = unit.rows(&record_rows, &self)?;
            self.allowed_rows = None;
            self.manifest.window_ns = unit.window_ns;
            let row = *record_rows
                .get(&unit.record)
                .ok_or_else(|| Self::invalid("graph unit record"))?;
            if let Some(index) = &index {
                support.extend(index.support(&self, row)?);
            }
            let references = support
                .iter()
                .flat_map(|&row| self.facts(row))
                .filter_map(|(_, fact)| match &fact.value {
                    FactValue::Policy(policy) => Some(policy.observations.iter()),
                    _ => None,
                })
                .flatten()
                .filter_map(|id| record_rows.get(id).copied())
                .collect::<Vec<_>>();
            support.extend(references);
            self.allowed_rows = Some(support);
            match self.detector {
                Detector::Credentials => {
                    if let Some(marker) = self.credential_event(
                        row,
                        index
                            .as_ref()
                            .ok_or_else(|| Self::invalid("graph credential index"))?,
                    )? {
                        commands.state(
                            &araphor_analysis_types::DomainRelations::key(&unit.record)?,
                            araphor_analysis_types::GraphStateMember {
                                record: Some(unit.record.clone()),
                                position: Some(self.record(row)?.position),
                                fact: None,
                                state: GraphPackageStateV1::from_marker(&marker)?,
                            },
                        )?;
                    }
                }
            }
            let owner = araphor_analysis_types::DomainRelations::key(&unit.record)?;
            let keys = self
                .subjects
                .iter()
                .map(|subject| subject.key.clone())
                .collect::<Vec<_>>();
            for subject in self.subjects.drain(..) {
                let value = SubjectChange {
                    anchor: Anchor::from_positions(
                        subject.record,
                        subject.context,
                        &record_ids,
                        &self.facts,
                    )?,
                    key: subject.key,
                };
                commands.subject(&owner, value.clone())?;
                subjects.push(value);
            }
            self.subject_indices.clear();
            for value in std::mem::take(&mut self.edges).into_values() {
                commands.edge(
                    &owner,
                    RelationshipChange {
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
                    },
                )?;
            }
            for mut finding in std::mem::take(&mut self.findings).into_values() {
                finding.sensitivity = if unit.restricted {
                    ContextSensitivityV1::HostRestricted
                } else {
                    ContextSensitivityV1::Tenant
                };
                let anchor = Anchor::from_positions(
                    finding.record,
                    finding.context,
                    &record_ids,
                    &self.facts,
                )?;
                let reason =
                    FindingReasonV1::from_analysis_code(&finding.package_id, &finding.reason_code)?;
                commands.finding(
                    &owner,
                    araphor_analysis_types::FindingMember {
                        anchor,
                        value: finding.into_finding(reason),
                    },
                )?;
            }
        }
        commands.stage(graph)?;
        Ok(sdk::Output {
            datasets: vec![SubjectChange::encode(&subjects)?],
            ..Default::default()
        })
    }
}
