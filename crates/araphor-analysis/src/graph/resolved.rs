use super::*;

impl Graph<'_> {
    pub(super) fn apply_output(
        &mut self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
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
        let dataset = |name: &str| {
            output
                .datasets
                .iter()
                .find(|data| data.name == name)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph output dataset",
                    }
                    .build()
                })
        };
        let mut metadata =
            algorithm::Metadata::decode(dataset("metadata")?).context(AnalysisContractSnafu)?;
        Self::require(metadata.len() == 1, "graph metadata count")?;
        let metadata = metadata.remove(0);
        Self::require(
            metadata
                .record_ids
                .iter()
                .eq(self.input.records.iter().map(|record| &record.id))
                && metadata.facts.len() == self.facts.len()
                && metadata
                    .facts
                    .iter()
                    .zip(self.facts.iter().zip(&self.input.facts))
                    .all(|(actual, (fact, context))| {
                        self.input
                            .records
                            .get(actual.record as usize)
                            .is_some_and(|record| record.id == fact.record_id)
                            && actual.key == context.key
                            && actual.sensitivity == context.sensitivity
                            && actual.value == fact.value
                    }),
            "graph output metadata",
        )?;
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
        Self::require(
            metadata.package
                == GraphPackageCheckpointV1::from_package(
                    package,
                    model,
                    metadata.package.state.clone(),
                    accepted,
                    observed,
                ),
            "graph package metadata",
        )?;
        if let GraphPackageStateV1::Declared(value) = &metadata.package.state {
            Self::require(
                !value.is_empty() && value.len() <= 128,
                "graph declared checkpoint state",
            )?;
        }
        let declaration = model.checkpoint.as_ref().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph checkpoint declaration",
            }
            .build()
        })?;
        let checkpoint = output.checkpoint.as_ref().ok_or_else(|| {
            GraphInvalidSnafu {
                field: "graph checkpoint output",
            }
            .build()
        })?;
        let state = &declaration.datasets[0];
        let data = checkpoint
            .datasets
            .iter()
            .find(|data| data.name == state.name)
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph checkpoint state",
                }
                .build()
            })?;
        let states = GraphPackageStateV1::decode(data).context(AnalysisContractSnafu)?;
        Self::require(states.len() == 1, "graph checkpoint rows")?;
        Self::require(
            states[0] == metadata.package.state,
            "graph package checkpoint state",
        )?;

        let subjects =
            algorithm::Subject::decode(dataset("subjects")?).context(AnalysisContractSnafu)?;
        let mut mapping = Vec::with_capacity(subjects.len());
        for subject in &subjects {
            self.validate_subject(subject)?;
            mapping.push(self.insert_subject(subject.key.clone())?);
        }
        for row in algorithm::Relationship::decode(dataset("relationships")?)
            .context(AnalysisContractSnafu)?
        {
            Self::require(row.edge.key.package_id == package.id, "graph edge package")?;
            self.validate_edge(&row, &subjects)?;
            let mut edge = row.edge;
            edge.key.from = mapping[edge.key.from as usize];
            edge.key.to = mapping[edge.key.to as usize];
            edge.key.evidence = edge
                .key
                .evidence
                .iter()
                .map(|index| {
                    self.revision
                        .evidence
                        .binary_search(&metadata.record_ids[*index as usize])
                        .ok()
                        .and_then(|index| u32::try_from(index).ok())
                        .ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "graph output evidence",
                            }
                            .build()
                        })
                })
                .collect::<Result<Vec<_>>>()?;
            edge.key.evidence.sort_unstable();
            edge.key.evidence.dedup();
            self.insert_edge(edge)?;
        }
        let findings =
            algorithm::Finding::decode(dataset("findings")?).context(AnalysisContractSnafu)?;
        let indices = metadata
            .record_ids
            .iter()
            .enumerate()
            .map(|(index, id)| {
                u32::try_from(index).map(|index| (id, index)).map_err(|_| {
                    GraphInvalidSnafu {
                        field: "graph output evidence",
                    }
                    .build()
                })
            })
            .collect::<Result<BTreeMap<_, _>>>()?;
        Self::finding_evidence(&findings, &indices, &output.evidence)?;
        let reasons = Self::finding_reasons(package, &findings, &indices, &output.reasons)?;
        let mut expected_branches = Vec::new();
        for (row, reason) in findings.into_iter().zip(reasons) {
            expected_branches.push(GraphBranchV1::from_finding(&row, &reason));
            Self::require(
                row.package_id == package.id
                    && row.package_version == 1
                    && row.tenant_id == self.input.source.tenant_id,
                "graph finding package",
            )?;
            let record = row.record;
            let context = row.context;
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
        let branches =
            algorithm::Branch::decode(dataset("branches")?).context(AnalysisContractSnafu)?;
        Self::require(
            branches
                .iter()
                .all(|branch| expected_branches.contains(branch))
                && expected_branches
                    .iter()
                    .all(|branch| branches.contains(branch)),
            "graph branch authority",
        )?;
        self.branches.extend(branches);
        self.packages.push(metadata.package);
        Ok(())
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
                Self::require(
                    reason.code == finding.reason_code
                        && reason
                            .code
                            .strip_prefix(&format!("{}.", package.id))
                            .is_some_and(|value| !value.is_empty()),
                    "graph candidate reason",
                )?;
                if let Some(known) = FindingV1::PACKAGES
                    .contains(&package.id.as_str())
                    .then(|| FindingReasonV1::from_analysis_code(&package.id, &reason.code).ok())
                    .flatten()
                    .filter(|_| {
                        reason.details.schema().as_ref() == &algorithm::ReasonDetails::port().schema
                    })
                {
                    let details = algorithm::ReasonDetails::decode(&sdk::Dataset {
                        name: algorithm::ReasonDetails::port().name,
                        batches: vec![reason.details.clone()],
                    })
                    .context(AnalysisContractSnafu)?;
                    let expected = algorithm::ReasonDetails::from_finding(finding, indices)
                        .context(AnalysisContractSnafu)?;
                    Self::require(details == [expected], "graph candidate reason")?;
                    Ok(known)
                } else {
                    Ok(FindingReasonV1::Declared(
                        DeclaredFindingReasonV1::from_value(reason)
                            .context(AnalysisContractSnafu)?,
                    ))
                }
            })
            .collect()
    }
}
