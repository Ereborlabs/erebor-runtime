use super::*;

impl Graph<'_> {
    pub(super) fn apply_output(
        &mut self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
        retained: bool,
        host_prior: Option<&[sdk::Dataset]>,
    ) -> Result<()> {
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
        fn dataset<'a>(datasets: &'a [sdk::Dataset], name: &str) -> Result<&'a sdk::Dataset> {
            datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph output dataset",
                    }
                    .build()
                })
        }
        let checkpoint = output.checkpoint.as_ref().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph checkpoint output",
            }
            .build()
        })?;
        let declaration = model.checkpoint.as_ref().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph checkpoint declaration",
            }
            .build()
        })?;
        let state = &declaration.datasets[0];
        let state = checkpoint
            .datasets
            .iter()
            .find(|data| data.name == state.name)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph checkpoint state",
                }
                .build()
            })?;
        let states = GraphPackageStateV1::decode(state).context(AnalysisContractSnafu)?;
        Self::require(states.len() == 1, "graph checkpoint rows")?;
        if let GraphPackageStateV1::Declared(value) = &states[0] {
            Self::require(!value.is_empty(), "graph declared checkpoint state")?;
        }

        let previous = host_prior.unwrap_or(&evaluation.previous_outputs);
        Self::require(!retained || !previous.is_empty(), "retained Graph prior")?;
        let mut subjects = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut findings = BTreeMap::new();
        if !previous.is_empty() {
            Self::require(
                algorithm::SubjectRemoval::decode(dataset(previous, "subject_removals")?)
                    .context(AnalysisContractSnafu)?
                    .is_empty()
                    && algorithm::RelationshipRemoval::decode(dataset(
                        previous,
                        "relationship_removals",
                    )?)
                    .context(AnalysisContractSnafu)?
                    .is_empty()
                    && algorithm::FindingRemoval::decode(dataset(previous, "finding_removals")?)
                        .context(AnalysisContractSnafu)?
                        .is_empty()
                    && algorithm::ProgressRemoval::decode(dataset(previous, "progress_removals")?)
                        .context(AnalysisContractSnafu)?
                        .is_empty(),
                "graph previous normalized output",
            )?;
            for row in algorithm::SubjectChange::decode(dataset(previous, "subjects")?)
                .context(AnalysisContractSnafu)?
            {
                Self::require(
                    subjects.insert(row.key.clone(), row).is_none(),
                    "graph prior subject identity",
                )?;
            }
            for row in algorithm::RelationshipChange::decode(dataset(previous, "relationships")?)
                .context(AnalysisContractSnafu)?
            {
                Self::require(
                    edges.insert(row.key.clone(), row).is_none(),
                    "graph prior relationship identity",
                )?;
            }
            for row in algorithm::FindingChange::decode(dataset(previous, "findings")?)
                .context(AnalysisContractSnafu)?
            {
                Self::require(
                    row.prior_reason.is_some()
                        && findings.insert(row.finding_id.clone(), row).is_none(),
                    "graph prior finding identity",
                )?;
            }
        }

        let indices = self
            .input
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| {
                u32::try_from(index)
                    .map(|index| (record.id.clone(), index))
                    .map_err(|_| {
                        GraphInvalidSnafu {
                            field: "graph output evidence",
                        }
                        .build()
                    })
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        if !retained {
            let mut removed = BTreeSet::new();
            for row in
                algorithm::SubjectRemoval::decode(dataset(&output.datasets, "subject_removals")?)
                    .context(AnalysisContractSnafu)?
            {
                Self::require(
                    removed.insert(row.key.clone()) && subjects.remove(&row.key).is_some(),
                    "graph subject removal",
                )?;
            }
            for row in algorithm::SubjectChange::decode(dataset(&output.datasets, "subjects")?)
                .context(AnalysisContractSnafu)?
            {
                Self::require(
                    subjects.insert(row.key.clone(), row).is_none(),
                    "graph subject addition",
                )?;
            }
            let mut removed = BTreeSet::new();
            for row in algorithm::RelationshipRemoval::decode(dataset(
                &output.datasets,
                "relationship_removals",
            )?)
            .context(AnalysisContractSnafu)?
            {
                Self::require(
                    removed.insert(row.key.clone()) && edges.remove(&row.key).is_some(),
                    "graph relationship removal",
                )?;
            }
            for row in
                algorithm::RelationshipChange::decode(dataset(&output.datasets, "relationships")?)
                    .context(AnalysisContractSnafu)?
            {
                Self::require(
                    row.key.package_id == package.id
                        && edges.insert(row.key.clone(), row).is_none(),
                    "graph relationship addition",
                )?;
            }

            let additions =
                algorithm::FindingChange::decode(dataset(&output.datasets, "findings")?)
                    .context(AnalysisContractSnafu)?;
            let local = additions
                .iter()
                .map(|row| {
                    Self::require(row.prior_reason.is_none(), "graph untrusted prior reason")?;
                    let (record, context) = self.positions(&row.anchor)?;
                    Ok(row.local(record, context))
                })
                .collect::<Result<Vec<_>>>()?;
            let index_refs = indices.iter().map(|(id, &row)| (id, row)).collect();
            Self::finding_evidence(&local, &index_refs, &output.evidence)?;
            let reasons = Self::finding_reasons(package, &local, &index_refs, &output.reasons)?;
            let mut removed = BTreeSet::new();
            for row in
                algorithm::FindingRemoval::decode(dataset(&output.datasets, "finding_removals")?)
                    .context(AnalysisContractSnafu)?
            {
                Self::require(
                    removed.insert(row.finding_id.clone())
                        && findings.remove(&row.finding_id).is_some(),
                    "graph finding removal",
                )?;
            }
            for (mut row, reason) in additions.into_iter().zip(reasons) {
                Self::require(
                    row.package_id == package.id
                        && row.package_version == 1
                        && row.tenant_id == self.input.source.tenant_id,
                    "graph finding package",
                )?;
                row.prior_reason = Some(reason);
                Self::require(
                    findings.insert(row.finding_id.clone(), row).is_none(),
                    "graph finding addition",
                )?;
            }
        }

        let mut local_subjects = Vec::new();
        let mut subject_indices = BTreeMap::new();
        let mut merged = Vec::new();
        for (key, row) in subjects {
            let (record, context) = self.positions(&row.anchor)?;
            let local = algorithm::Subject {
                record,
                context,
                key: key.clone(),
            };
            self.validate_subject(&local)?;
            let index = u32::try_from(local_subjects.len()).map_err(|_| {
                GraphInvalidSnafu {
                    field: "graph subject count",
                }
                .build()
            })?;
            subject_indices.insert(key.clone(), index);
            merged.push(self.insert_subject(key)?);
            local_subjects.push(local);
        }
        for (_, row) in edges {
            let (record, fact) = self.positions(&row.anchor)?;
            let from = *subject_indices.get(&row.key.from).ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph edge endpoint",
                }
                .build()
            })?;
            let to = *subject_indices.get(&row.key.to).ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph edge endpoint",
                }
                .build()
            })?;
            Self::require(
                row.key.evidence.windows(2).all(|pair| pair[0] < pair[1]),
                "graph edge evidence identity",
            )?;
            let mut evidence = row
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
            evidence.sort_unstable();
            evidence.dedup();
            let local = algorithm::Relationship {
                record,
                fact,
                edge: GraphEdgeV1 {
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
                },
            };
            self.validate_edge(&local, &local_subjects)?;
            let mut edge = local.edge;
            edge.key.from = merged[from as usize];
            edge.key.to = merged[to as usize];
            self.insert_edge(edge)?;
        }
        for (_, row) in findings {
            Self::require(
                row.package_id == package.id
                    && row.package_version == 1
                    && row.tenant_id == self.input.source.tenant_id,
                "graph finding package",
            )?;
            let (record, context) = self.positions(&row.anchor)?;
            let reason = row.prior_reason.clone().ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph prior finding reason",
                }
                .build()
            })?;
            let finding = row.into_finding(reason);
            self.validate_finding(record, context, &finding)?;
            Self::require(
                self.findings
                    .get(&finding.finding_id)
                    .is_none_or(|prior| prior == &finding),
                "conflicting finding value",
            )?;
            self.findings.insert(finding.finding_id.clone(), finding);
        }
        let accepted = self
            .input
            .records
            .last()
            .map_or(0, |record| record.id.durable_cursor);
        let observed = self
            .input
            .records
            .iter()
            .map(|record| record.decode().map(|wire| wire.observed_boottime_ns))
            .collect::<Result<Vec<_>>>()?
            .into_iter()
            .max()
            .unwrap_or(0);
        self.packages.push(GraphPackageCheckpointV1::from_package(
            package,
            model,
            states[0].clone(),
            accepted,
            observed,
        ));
        Ok(())
    }

    fn positions(&self, anchor: &algorithm::Anchor) -> Result<(u32, Option<u32>)> {
        let record = self
            .input
            .records
            .binary_search_by(|row| row.id.cmp(&anchor.record))
            .ok()
            .and_then(|index| u32::try_from(index).ok())
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph anchor record",
                }
                .build()
            })?;
        let context = match &anchor.fact {
            Some(fact) => {
                let index = self
                    .input
                    .facts
                    .binary_search_by(|source| source.key.cmp(&fact.key))
                    .ok()
                    .filter(|&index| {
                        self.facts[index].record_id == fact.record
                            && self.input.facts[index].sensitivity == fact.sensitivity
                            && self.facts[index].value == fact.value
                    })
                    .and_then(|index| u32::try_from(index).ok())
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph anchor fact",
                        }
                        .build()
                    })?;
                Some(index)
            }
            None => None,
        };
        Ok((record, context))
    }

    fn finding_evidence(
        findings: &[algorithm::Finding],
        indices: &BTreeMap<&DiscoveryRecordIdV1, u32>,
        links: &[sdk::EvidenceLink],
    ) -> Result<()> {
        let mut expected = BTreeSet::new();
        for (row, finding) in findings.iter().enumerate() {
            for id in &finding.evidence {
                let input = indices.get(id).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph output evidence",
                    }
                    .build()
                })?;
                expected.insert((row as u64, u64::from(*input)));
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
        for reason in values {
            Self::require(
                reason.output.dataset == "findings"
                    && reasons.insert(reason.output.row, reason).is_none(),
                "graph candidate reason",
            )?;
        }
        Self::require(reasons.len() == findings.len(), "graph candidate reason")?;
        findings
            .iter()
            .enumerate()
            .map(|(row, finding)| {
                let reason = reasons.get(&(row as u64)).ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph candidate reason",
                    }
                    .build()
                })?;
                FindingReasonV1::from_output(&package.id, finding, indices, reason).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph candidate reason",
                    }
                    .build()
                })
            })
            .collect()
    }
}
