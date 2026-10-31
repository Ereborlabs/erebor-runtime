use super::*;

pub(super) struct Changes {
    subjects: Vec<algorithm::SubjectChange>,
    edges: Vec<algorithm::RelationshipChange>,
    findings: Vec<(FindingV1, algorithm::Anchor)>,
    package: GraphPackageCheckpointV1,
}

impl Changes {
    fn dataset<'a>(values: &'a [sdk::Dataset], name: &str) -> Result<&'a sdk::Dataset> {
        values
            .iter()
            .find(|value| value.name == name)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph output dataset",
                }
                .build()
            })
    }
}

impl Graph<'_> {
    pub(super) fn validate_output(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
    ) -> Result<GraphPackageCheckpointV1> {
        let changes = self.changes(package, evaluation, output)?;
        Ok(changes.package)
    }

    fn changes(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
    ) -> Result<Changes> {
        let model = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph export",
                }
                .build()
            })?;
        Self::require(
            algorithm::Detector::supports_units(model),
            "graph unit contract",
        )?;
        let state = Changes::dataset(&output.datasets, "state")?;
        let states = GraphPackageStateV1::decode(state).context(AnalysisContractSnafu)?;
        Self::require(states.len() == 1, "graph checkpoint rows")?;
        Self::require(
            !matches!(&states[0], GraphPackageStateV1::Declared(value) if value.is_empty()),
            "graph declared checkpoint state",
        )?;
        let accepted = self
            .input
            .records
            .last()
            .map_or(0, |record| record.id.durable_cursor);
        let observed = self
            .observations
            .iter()
            .map(|row| row.observed_boottime_ns)
            .max()
            .unwrap_or(0);
        let checkpoint = GraphPackageCheckpointV1::from_package(
            package,
            model,
            states[0].clone(),
            accepted,
            observed,
        );
        let subjects =
            algorithm::SubjectChange::decode(Changes::dataset(&output.datasets, "subjects")?)
                .context(AnalysisContractSnafu)?;
        let edges = algorithm::RelationshipChange::decode(Changes::dataset(
            &output.datasets,
            "relationships",
        )?)
        .context(AnalysisContractSnafu)?;
        let additions =
            algorithm::FindingChange::decode(Changes::dataset(&output.datasets, "findings")?)
                .context(AnalysisContractSnafu)?;
        for row in &subjects {
            let (record, context) = self.positions(&row.anchor)?;
            self.validate_subject(&algorithm::Subject {
                record,
                context,
                key: row.key.clone(),
            })?;
        }
        let indices = self
            .input
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| (record.id.clone(), index as u32))
            .collect::<BTreeMap<_, _>>();
        for row in &edges {
            Self::require(
                row.key.package_id == package.id,
                "graph relationship addition",
            )?;
            let (record, fact) = self.positions(&row.anchor)?;
            let evidence = row
                .key
                .evidence
                .iter()
                .map(|id| {
                    indices.get(id).copied().ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph edge evidence",
                        }
                        .build()
                    })
                })
                .collect::<Result<Vec<_>>>()?;
            let local = [
                algorithm::Subject {
                    record,
                    context: fact,
                    key: row.key.from.clone(),
                },
                algorithm::Subject {
                    record,
                    context: fact,
                    key: row.key.to.clone(),
                },
            ];
            self.validate_edge(
                &algorithm::Relationship {
                    record,
                    fact,
                    edge: GraphEdgeV1 {
                        key: GraphEdgeKeyV1 {
                            from: 0,
                            to: 1,
                            edge_type: row.key.edge_type,
                            package_id: row.key.package_id.clone(),
                            evidence,
                            cause: row.key.cause,
                        },
                        proof_quality: row.proof_quality,
                        required_coverage_interval_ids: row.required_coverage_interval_ids.clone(),
                        first_boottime_ns: row.first_boottime_ns,
                        last_boottime_ns: row.last_boottime_ns,
                    },
                },
                &local,
            )?;
        }
        let input_records = algorithm::Observation::decode(
            &evaluation
                .input("records")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let input_rows = input_records
            .iter()
            .enumerate()
            .map(|(index, record)| (&record.id, index as u32))
            .collect::<BTreeMap<_, _>>();
        let input_facts = algorithm::Fact::decode(
            &evaluation
                .input("facts")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let fact_rows = input_facts
            .iter()
            .enumerate()
            .map(|(index, fact)| (&fact.key, index as u32))
            .collect::<BTreeMap<_, _>>();
        let local = additions
            .iter()
            .map(|row| {
                Self::require(row.prior_reason.is_none(), "graph untrusted prior reason")?;
                let record = input_rows.get(&row.anchor.record).copied().ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph lookup finding record",
                    }
                    .build()
                })?;
                let fact = row
                    .anchor
                    .fact
                    .as_ref()
                    .map(|fact| {
                        fact_rows.get(&fact.key).copied().ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "graph lookup finding fact",
                            }
                            .build()
                        })
                    })
                    .transpose()?;
                Ok(row.local(record, fact))
            })
            .collect::<Result<Vec<_>>>()?;
        Self::finding_evidence(&local, &input_rows, &output.evidence)?;
        let reasons = Self::finding_reasons(package, &local, &input_rows, &output.reasons)?;
        let findings = additions
            .into_iter()
            .zip(reasons)
            .map(|(row, reason)| {
                Self::require(
                    row.package_id == package.id
                        && row.package_version == 1
                        && row.tenant_id == self.input.source.tenant_id,
                    "graph finding package",
                )?;
                let (record, context) = self.positions(&row.anchor)?;
                let anchor = row.anchor.clone();
                let finding = row.into_finding(reason);
                self.validate_finding(record, context, &finding)?;
                Ok((finding, anchor))
            })
            .collect::<Result<Vec<_>>>()?;
        Ok(Changes {
            subjects,
            edges,
            findings,
            package: checkpoint,
        })
    }

    pub(super) fn apply_output(
        &mut self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
    ) -> Result<()> {
        let mut changes = self.changes(package, evaluation, output)?;
        let contract = package
            .exports
            .iter()
            .find(|model| model.name == evaluation.export)
            .and_then(|model| model.change_inputs.as_ref())
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph change declaration",
                }
                .build()
            })?;
        Self::require(
            contract
                .is_reset(evaluation)
                .context(AnalysisContractSnafu)?,
            "complete Graph input",
        )?;
        let counts = [
            changes.subjects.len(),
            changes.edges.len(),
            changes.findings.len(),
        ];
        changes.package.state =
            Self::unit_state(evaluation, output, changes.package.state, counts)?;
        let mut subjects = BTreeMap::<_, algorithm::SubjectChange>::new();
        let mut edges = BTreeMap::<_, algorithm::RelationshipChange>::new();
        let mut findings = BTreeMap::<_, (FindingV1, algorithm::Anchor)>::new();
        for row in changes.subjects {
            let entry = subjects
                .entry(row.key.clone())
                .or_insert_with(|| row.clone());
            if self.positions(&row.anchor)? < self.positions(&entry.anchor)? {
                *entry = row;
            }
        }
        for row in changes.edges {
            if let Some(old) = edges.get_mut(&row.key) {
                let mut value = row.clone();
                value.anchor = old.anchor.clone();
                Self::require(&value == old, "conflicting edge value")?;
                if self.positions(&row.anchor)? < self.positions(&old.anchor)? {
                    *old = row;
                }
            } else {
                edges.insert(row.key.clone(), row);
            }
        }
        for (row, anchor) in changes.findings {
            if let Some((old, prior)) = findings.get_mut(&row.finding_id) {
                Self::require(old == &row, "conflicting finding value")?;
                if self.positions(&anchor)? < self.positions(prior)? {
                    *prior = anchor;
                }
            } else {
                findings.insert(row.finding_id.clone(), (row, anchor));
            }
        }
        for row in subjects.into_values() {
            let (record, context) = self.positions(&row.anchor)?;
            self.validate_subject(&algorithm::Subject {
                record,
                context,
                key: row.key.clone(),
            })?;
            self.insert_subject(row.key)?;
        }
        let indices = self
            .input
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| (record.id.clone(), index as u32))
            .collect::<BTreeMap<_, _>>();
        for row in edges.into_values() {
            Self::require(
                row.key.package_id == package.id,
                "graph relationship addition",
            )?;
            let (record, fact) = self.positions(&row.anchor)?;
            let from = self.subjects.get(&row.key.from).copied().ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph edge endpoint",
                }
                .build()
            })?;
            let to = self.subjects.get(&row.key.to).copied().ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph edge endpoint",
                }
                .build()
            })?;
            let evidence: Vec<u32> = row
                .key
                .evidence
                .iter()
                .map(|id| {
                    indices.get(id).copied().ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph edge evidence",
                        }
                        .build()
                    })
                })
                .collect::<Result<_>>()?;
            let local = [
                algorithm::Subject {
                    record,
                    context: fact,
                    key: row.key.from.clone(),
                },
                algorithm::Subject {
                    record,
                    context: fact,
                    key: row.key.to.clone(),
                },
            ];
            let check = GraphEdgeV1 {
                key: GraphEdgeKeyV1 {
                    from: 0,
                    to: 1,
                    edge_type: row.key.edge_type,
                    package_id: row.key.package_id.clone(),
                    evidence: evidence.clone(),
                    cause: row.key.cause,
                },
                proof_quality: row.proof_quality,
                required_coverage_interval_ids: row.required_coverage_interval_ids.clone(),
                first_boottime_ns: row.first_boottime_ns,
                last_boottime_ns: row.last_boottime_ns,
            };
            self.validate_edge(
                &algorithm::Relationship {
                    record,
                    fact,
                    edge: check,
                },
                &local,
            )?;
            let value = GraphEdgeV1 {
                key: GraphEdgeKeyV1 {
                    from,
                    to,
                    edge_type: row.key.edge_type,
                    package_id: row.key.package_id,
                    evidence,
                    cause: row.key.cause,
                },
                proof_quality: row.proof_quality,
                required_coverage_interval_ids: row.required_coverage_interval_ids,
                first_boottime_ns: row.first_boottime_ns,
                last_boottime_ns: row.last_boottime_ns,
            };
            Self::require(
                self.edges.get(&value.key).is_none_or(|old| old == &value),
                "conflicting edge value",
            )?;
            self.edges.insert(value.key.clone(), value);
        }
        for (key, (finding, anchor)) in findings {
            Self::require(
                finding.package_id == package.id
                    && finding.package_version == 1
                    && finding.tenant_id == self.input.source.tenant_id,
                "graph finding package",
            )?;
            let (record, context) = self.positions(&anchor)?;
            self.validate_finding(record, context, &finding)?;
            Self::require(
                self.findings.get(&key).is_none_or(|old| old == &finding),
                "conflicting finding value",
            )?;
            self.findings.insert(key, finding);
        }
        self.packages.push(changes.package);
        Ok(())
    }

    fn unit_state(
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
        default: GraphPackageStateV1,
        counts: [usize; 3],
    ) -> Result<GraphPackageStateV1> {
        let contributions =
            algorithm::Contribution::decode(Changes::dataset(&output.datasets, "contributions")?)
                .context(AnalysisContractSnafu)?;
        let units = algorithm::Unit::decode(
            &evaluation
                .input("units")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let records = algorithm::Observation::decode(
            &evaluation
                .input("records")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        let facts = algorithm::Fact::decode(
            &evaluation
                .input("facts")
                .context(AnalysisContractSnafu)?
                .data,
        )
        .context(AnalysisContractSnafu)?;
        algorithm::Contribution::validate(&units, &records, &facts, &contributions, counts)
            .context(AnalysisContractSnafu)?;
        let mut selected: Option<(&DiscoveryRecordIdV1, &algorithm::UnitState)> = None;
        for contribution in &contributions {
            let Some(state) = &contribution.state else {
                continue;
            };
            if let Some((record, prior)) = selected {
                Self::require(
                    prior.fact.is_some() == state.fact.is_some(),
                    "graph state order",
                )?;
                let newer = match (&prior.fact, &state.fact) {
                    (Some(prior), Some(current)) => current > prior,
                    (None, None) => &contribution.record > record,
                    _ => false,
                };
                if !newer {
                    continue;
                }
            }
            selected = Some((&contribution.record, state));
        }
        selected
            .map(|(_, state)| Ok(state.state.clone()))
            .unwrap_or(Ok(default))
    }

    fn insert_subject(&mut self, key: GraphSubjectKeyV1) -> Result<u32> {
        let index = u32::try_from(self.subjects.len()).map_err(|_| {
            GraphInvalidSnafu {
                field: "graph subject count",
            }
            .build()
        })?;
        Ok(*self.subjects.entry(key).or_insert(index))
    }

    fn finding_evidence(
        findings: &[algorithm::Finding],
        indices: &BTreeMap<&DiscoveryRecordIdV1, u32>,
        links: &[sdk::EvidenceLink],
    ) -> Result<()> {
        let mut expected = BTreeSet::new();
        for (index, finding) in findings.iter().enumerate() {
            for id in &finding.evidence {
                let row = indices.get(id).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph output evidence",
                    }
                    .build()
                })?;
                expected.insert((index as u64, u64::from(*row)));
            }
        }
        let mut actual = BTreeSet::new();
        for link in links {
            Self::require(
                link.output.dataset == "findings" && link.input.dataset == "records",
                "graph candidate evidence",
            )?;
            actual.insert((link.output.row, link.input.row));
        }
        Self::require(expected == actual, "graph candidate evidence")
    }

    fn finding_reasons(
        package: &sdk::Package,
        findings: &[algorithm::Finding],
        indices: &BTreeMap<&DiscoveryRecordIdV1, u32>,
        values: &[sdk::ReasonValue],
    ) -> Result<Vec<FindingReasonV1>> {
        let mut reasons = BTreeMap::new();
        for value in values {
            Self::require(
                value.output.dataset == "findings"
                    && reasons.insert(value.output.row, value).is_none(),
                "graph candidate reason",
            )?;
        }
        Self::require(reasons.len() == findings.len(), "graph candidate reason")?;
        findings
            .iter()
            .enumerate()
            .map(|(index, finding)| {
                let value = reasons.get(&(index as u64)).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph candidate reason",
                    }
                    .build()
                })?;
                FindingReasonV1::from_output(&package.id, finding, indices, value).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph candidate reason",
                    }
                    .build()
                })
            })
            .collect()
    }
}
