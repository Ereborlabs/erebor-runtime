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
                let fact = self.selected_fact(edge.fact)?;
                match &fact.value {
                    GraphFactValueV1::NativeParent {
                        child,
                        proof_quality,
                        ..
                    } => {
                        proof_quality.parent_qualified()
                            && fact.record_id == record.id
                            && child.matches_local(observation.task, observation.process)
                    }
                    _ => false,
                }
            }
            algorithm::EdgeKind::Authority => {
                let fact = self.selected_fact(edge.fact)?;
                let GraphFactValueV1::AuthorityUse {
                    task_cookie,
                    process_instance_id,
                    credential_object_id,
                    proof_quality,
                    ..
                } = &fact.value
                else {
                    return GraphInvalidSnafu {
                        field: "graph AuthorityUse input",
                    }
                    .fail();
                };
                observation.exact_identity
                    && proof_quality.authority_direct()
                    && ((observation.task > 0 && *task_cookie == Some(observation.task))
                        || (observation.process.is_some()
                            && *process_instance_id == observation.process))
                    && credential_object_id.is_some_and(|object| observation.object == object)
                    && edge.evidence.iter().any(|row| {
                        self.selected_record(*row)
                            .is_ok_and(|record| record.id == fact.record_id)
                    })
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
