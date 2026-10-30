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
        retained: bool,
    ) -> Result<GraphPackageCheckpointV1> {
        let changes = self.changes(package, evaluation, output, retained)?;
        Ok(changes.package)
    }

    fn changes(
        &self,
        package: &sdk::Package,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
        retained: bool,
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
        let declaration = model
            .checkpoint
            .as_ref()
            .and_then(|state| state.datasets.first())
            .ok_or_else(|| {
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
        let state = Changes::dataset(&checkpoint.datasets, &declaration.name)?;
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
        if retained {
            return Ok(Changes {
                subjects: Vec::new(),
                edges: Vec::new(),
                findings: Vec::new(),
                package: checkpoint,
            });
        }
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
        let mut seen = BTreeSet::new();
        for row in &subjects {
            Self::require(seen.insert(&row.key), "graph subject addition")?;
            let (record, context) = self.positions(&row.anchor)?;
            self.validate_subject(&algorithm::Subject {
                record,
                context,
                key: row.key.clone(),
            })?;
        }
        let mut seen = BTreeSet::new();
        let indices = self
            .input
            .records
            .iter()
            .enumerate()
            .map(|(index, record)| (record.id.clone(), index as u32))
            .collect::<BTreeMap<_, _>>();
        for row in &edges {
            Self::require(
                row.key.package_id == package.id && seen.insert(&row.key),
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
        let local = additions
            .iter()
            .map(|row| {
                Self::require(row.prior_reason.is_none(), "graph untrusted prior reason")?;
                let (record, fact) = self.positions(&row.anchor)?;
                Ok(row.local(record, fact))
            })
            .collect::<Result<Vec<_>>>()?;
        let index_refs = indices.iter().map(|(id, &index)| (id, index)).collect();
        Self::finding_evidence(&local, &index_refs, &output.evidence)?;
        let reasons = Self::finding_reasons(package, &local, &index_refs, &output.reasons)?;
        let mut seen = BTreeSet::new();
        let findings = additions
            .into_iter()
            .zip(reasons)
            .map(|(row, reason)| {
                Self::require(
                    row.package_id == package.id
                        && row.package_version == 1
                        && row.tenant_id == self.input.source.tenant_id
                        && seen.insert(row.finding_id.clone()),
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
        retained: bool,
        host_prior: Option<&[sdk::Dataset]>,
    ) -> Result<()> {
        let changes = self.changes(package, evaluation, output, retained)?;
        let previous = host_prior.unwrap_or(&evaluation.previous_outputs);
        Self::require(!retained || !previous.is_empty(), "retained Graph prior")?;
        let mut subjects = BTreeMap::new();
        let mut edges = BTreeMap::new();
        let mut findings = BTreeMap::new();
        if !previous.is_empty() {
            for name in [
                "subject_removals",
                "relationship_removals",
                "finding_removals",
                "progress_removals",
            ] {
                Self::require(
                    Changes::dataset(previous, name)?.rows() == 0,
                    "graph previous normalized output",
                )?;
            }
            for row in algorithm::SubjectChange::decode(Changes::dataset(previous, "subjects")?)
                .context(AnalysisContractSnafu)?
            {
                Self::require(
                    subjects.insert(row.key.clone(), row).is_none(),
                    "graph prior subject identity",
                )?;
            }
            for row in
                algorithm::RelationshipChange::decode(Changes::dataset(previous, "relationships")?)
                    .context(AnalysisContractSnafu)?
            {
                Self::require(
                    edges.insert(row.key.clone(), row).is_none(),
                    "graph prior relationship identity",
                )?;
            }
            for row in algorithm::FindingChange::decode(Changes::dataset(previous, "findings")?)
                .context(AnalysisContractSnafu)?
            {
                let reason = row.prior_reason.clone().ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph prior finding reason",
                    }
                    .build()
                })?;
                let anchor = row.anchor.clone();
                let value = row.into_finding(reason);
                Self::require(
                    findings
                        .insert(value.finding_id.clone(), (value, anchor))
                        .is_none(),
                    "graph prior finding identity",
                )?;
            }
        }
        if !retained {
            let mut removed = BTreeSet::new();
            for row in algorithm::SubjectRemoval::decode(Changes::dataset(
                &output.datasets,
                "subject_removals",
            )?)
            .context(AnalysisContractSnafu)?
            {
                Self::require(
                    removed.insert(row.key.clone()) && subjects.remove(&row.key).is_some(),
                    "graph subject removal",
                )?;
            }
            let mut removed = BTreeSet::new();
            for row in algorithm::RelationshipRemoval::decode(Changes::dataset(
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
            let mut removed = BTreeSet::new();
            for row in algorithm::FindingRemoval::decode(Changes::dataset(
                &output.datasets,
                "finding_removals",
            )?)
            .context(AnalysisContractSnafu)?
            {
                Self::require(
                    removed.insert(row.finding_id.clone())
                        && findings.remove(&row.finding_id).is_some(),
                    "graph finding removal",
                )?;
            }
            for row in changes.subjects {
                Self::require(
                    subjects.insert(row.key.clone(), row).is_none(),
                    "graph subject addition",
                )?;
            }
            for row in changes.edges {
                Self::require(
                    edges.insert(row.key.clone(), row).is_none(),
                    "graph relationship addition",
                )?;
            }
            for (row, anchor) in changes.findings {
                Self::require(
                    findings
                        .insert(row.finding_id.clone(), (row, anchor))
                        .is_none(),
                    "graph finding addition",
                )?;
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
