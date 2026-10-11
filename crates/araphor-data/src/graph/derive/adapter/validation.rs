use super::*;

impl GraphDerivation<'_> {
    pub(super) fn validate_edge(&self, edge: &algorithm::Relationship) -> Result<()> {
        let record = self.selected_record(edge.record)?;
        if !edge.evidence.contains(&edge.record) {
            return GraphInvalidSnafu {
                field: "graph edge evidence",
            }
            .fail();
        }
        if !matches!(edge.cause, algorithm::Cause::Direct) {
            return Ok(());
        }
        let observation = self.observation(record)?;
        let qualified = match edge.kind {
            algorithm::EdgeKind::Process
            | algorithm::EdgeKind::ExecutionSet
            | algorithm::EdgeKind::Object => observation.exact_identity,
            algorithm::EdgeKind::Parent => {
                let index = edge
                    .fact
                    .and_then(|row| usize::try_from(row).ok())
                    .ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph output fact",
                        }
                        .build()
                    })?;
                let fact = self.selected_fact(edge.fact)?;
                match self.algorithm_fact(index, fact)?.value {
                    algorithm::FactValue::Parent {
                        child_task,
                        child_process,
                        qualified,
                    } => {
                        qualified
                            && fact.record_id == record.id
                            && ((observation.task > 0 && child_task == Some(observation.task))
                                || (observation.process.is_some()
                                    && child_process == observation.process))
                    }
                    _ => false,
                }
            }
            algorithm::EdgeKind::Authority => {
                let fact = self.selected_fact(edge.fact)?;
                match Self::authority_fact(&fact.value)? {
                    algorithm::FactValue::Authority(authority) => {
                        observation.exact_identity
                            && authority.direct
                            && ((observation.task > 0 && authority.task == Some(observation.task))
                                || (observation.process.is_some()
                                    && authority.process == observation.process))
                            && authority
                                .credential
                                .is_some_and(|object| observation.object == object)
                            && edge.evidence.iter().any(|row| {
                                self.selected_record(*row)
                                    .is_ok_and(|record| record.id == fact.record_id)
                            })
                    }
                    _ => false,
                }
            }
            algorithm::EdgeKind::Kubernetes => false,
        };
        if !qualified {
            return GraphInvalidSnafu {
                field: "graph direct cause proof",
            }
            .fail();
        }
        Ok(())
    }

    pub(super) fn validate_finding(&self, finding: &algorithm::Finding) -> Result<()> {
        if !finding.evidence.contains(&finding.record) {
            return GraphInvalidSnafu {
                field: "graph finding evidence",
            }
            .fail();
        }
        if finding.confirmed {
            let observation = self.observation(self.selected_record(finding.record)?)?;
            if finding.context.is_some() || !observation.exact_identity || !observation.complete {
                return GraphInvalidSnafu {
                    field: "graph confirmed finding proof",
                }
                .fail();
            }
            for row in &finding.evidence {
                if !self.observation(self.selected_record(*row)?)?.complete {
                    return GraphInvalidSnafu {
                        field: "graph finding coverage",
                    }
                    .fail();
                }
            }
        }
        Ok(())
    }
}
