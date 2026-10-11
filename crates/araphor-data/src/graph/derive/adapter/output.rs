use super::*;

impl GraphDerivation<'_> {
    pub(super) fn apply_output(
        &mut self,
        detector: algorithm::Detector,
        evaluation: &sdk::Evaluation,
        output: &sdk::Output,
    ) -> Result<()> {
        let package = detector.descriptor();
        package
            .validate_output(evaluation, output)
            .context(AnalysisContractSnafu)?;
        let model = &package.exports[0];
        let dataset = |name: &str| {
            output
                .datasets
                .iter()
                .find(|dataset| dataset.name == name)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph output dataset",
                    }
                    .build()
                })
        };
        let subjects: Vec<algorithm::Subject> = Rows::decode(
            &model.outputs[0],
            dataset("subjects")?,
            evaluation.context.limits,
        )
        .context(AnalysisContractSnafu)?;
        for subject in subjects {
            self.selected_subject(subject.record, subject.context)?;
        }
        let edges: Vec<algorithm::Relationship> = Rows::decode(
            &model.outputs[1],
            dataset("relationships")?,
            evaluation.context.limits,
        )
        .context(AnalysisContractSnafu)?;
        for edge in edges {
            self.selected_edge(detector.id(), edge)?;
        }
        let findings: Vec<algorithm::Finding> = Rows::decode(
            &model.outputs[2],
            dataset("findings")?,
            evaluation.context.limits,
        )
        .context(AnalysisContractSnafu)?;
        Self::finding_evidence(&findings, &output.evidence)?;
        let reasons = Self::finding_reasons(
            detector.id(),
            &model.outputs[2],
            &findings,
            &output.reasons,
            evaluation.context.limits,
        )?;
        for (finding, reason) in findings.into_iter().zip(reasons) {
            let record = self.selected_record(finding.record)?.clone();
            let subject = self.selected_subject(finding.record, finding.context)?;
            let evidence = self.selected_evidence(&finding.evidence)?;
            self.finding(
                detector.id(),
                &record,
                subject,
                reason,
                if finding.confirmed {
                    FindingStateV1::Confirmed
                } else {
                    FindingStateV1::CoverageInsufficient
                },
                evidence,
                finding.limits,
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
        let states: Vec<algorithm::State> = Rows::decode(
            &declaration.datasets[0],
            &checkpoint.datasets[0],
            evaluation.context.limits,
        )
        .context(AnalysisContractSnafu)?;
        if states.len() != 1 {
            return GraphInvalidSnafu {
                field: "graph checkpoint rows",
            }
            .fail();
        }
        let index = match detector {
            algorithm::Detector::Process => 0,
            algorithm::Detector::Credentials => 1,
            algorithm::Detector::Kubernetes => 2,
        };
        self.states[index] =
            serde_json::from_value(serde_json::Value::String(states[0].value.clone()))
                .context(GraphEncodingSnafu)?;
        Ok(())
    }

    fn finding_evidence(
        findings: &[algorithm::Finding],
        links: &[sdk::EvidenceLink],
    ) -> Result<()> {
        let invalid = || {
            GraphInvalidSnafu {
                field: "graph candidate evidence",
            }
            .build()
        };
        let expected: BTreeSet<_> = findings
            .iter()
            .enumerate()
            .flat_map(|(row, finding)| {
                finding
                    .evidence
                    .iter()
                    .map(move |record| (row as u64, *record))
            })
            .collect();
        let mut actual = BTreeSet::new();
        for link in links {
            if link.output.dataset != "findings" || link.input.dataset != "records" {
                return Err(invalid());
            }
            actual.insert((link.output.row, link.input.row));
        }
        if expected != actual {
            return Err(invalid());
        }
        Ok(())
    }

    fn finding_reasons(
        package: &str,
        port: &sdk::Port,
        findings: &[algorithm::Finding],
        values: &[sdk::ReasonValue],
        limits: sdk::Limits,
    ) -> Result<Vec<FindingReasonV1>> {
        let invalid = || {
            GraphInvalidSnafu {
                field: "graph candidate reason",
            }
            .build()
        };
        let mut reasons = BTreeMap::new();
        for reason in values {
            if reason.output.dataset != port.name
                || reasons.insert(reason.output.row, reason).is_some()
            {
                return Err(invalid());
            }
        }
        if reasons.len() != findings.len() {
            return Err(invalid());
        }
        findings
            .iter()
            .enumerate()
            .map(|(row, finding)| {
                let reason = reasons.get(&(row as u64)).ok_or_else(invalid)?;
                let details: Vec<algorithm::Finding> = Rows::decode(
                    port,
                    &sdk::Dataset {
                        name: port.name.clone(),
                        batches: vec![reason.details.clone()],
                    },
                    limits,
                )
                .context(AnalysisContractSnafu)?;
                if reason.code != format!("{package}.{}", finding.reason)
                    || details.as_slice() != std::slice::from_ref(finding)
                {
                    return Err(invalid());
                }
                FindingReasonV1::from_analysis_code(package, &reason.code)
            })
            .collect()
    }

    pub(super) fn selected_record(&self, row: u64) -> Result<&DiscoveryRecordV1> {
        usize::try_from(row)
            .ok()
            .and_then(|row| self.input.records.get(row))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph output record",
                }
                .build()
            })
    }

    pub(super) fn selected_fact(&self, row: Option<u64>) -> Result<&GraphFactV1> {
        row.and_then(|row| usize::try_from(row).ok())
            .and_then(|row| self.facts.get(row))
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "graph output fact",
                }
                .build()
            })
    }

    pub(super) fn selected_evidence(&self, rows: &[u64]) -> Result<Vec<DiscoveryRecordIdV1>> {
        rows.iter()
            .map(|row| self.selected_record(*row).map(|record| record.id.clone()))
            .collect()
    }

    fn selected_subject(&mut self, row: u64, context: Option<u64>) -> Result<GraphSubjectKeyV1> {
        let record = self.selected_record(row)?.clone();
        if let Some(index) = context {
            let fact = self.selected_fact(Some(index))?;
            if fact.record_id == record.id {
                if let GraphFactValueV1::Context { subject, .. } = &fact.value {
                    let subject = subject.clone();
                    self.subjects.insert(subject.clone());
                    return Ok(subject);
                }
            }
            return GraphInvalidSnafu {
                field: "graph context selection",
            }
            .fail();
        }
        let wire = record.decode()?;
        Ok(self.task(&record, &wire))
    }
}
