use super::*;

impl Computation {
    fn subject_index(
        &mut self,
        key: GraphSubjectKeyV1,
        record: u32,
        context: Option<u32>,
    ) -> sdk::Result<u32> {
        if let Some(index) = self.subject_indices.get(&key) {
            return Ok(*index);
        }
        let index =
            u32::try_from(self.subjects.len()).map_err(|_| Self::invalid("graph subject count"))?;
        self.subject_indices.insert(key.clone(), index);
        self.subjects.push(Subject {
            record,
            context,
            key,
        });
        Ok(index)
    }

    pub(super) fn subject(
        &mut self,
        row: u32,
        context: Option<u32>,
    ) -> sdk::Result<GraphSubjectKeyV1> {
        let key = if let Some(index) = context {
            let fact = self
                .facts
                .get(index as usize)
                .filter(|fact| fact.record == row)
                .ok_or_else(|| Self::invalid("graph context selection"))?;
            let FactValue::Context { subject, .. } = &fact.value else {
                return Err(Self::invalid("graph context selection"));
            };
            subject.clone()
        } else {
            self.record(row)?.task_subject()
        };
        self.subject_index(key.clone(), row, context)?;
        Ok(key)
    }

    pub(super) fn edge(
        &mut self,
        row: u32,
        fact_index: Option<u32>,
        kind: EdgeKind,
        cause: Cause,
        mut evidence: Vec<u32>,
    ) -> sdk::Result<()> {
        Self::canonical(&mut evidence);
        for row in &evidence {
            self.record(*row)?;
        }
        let record = self.record(row)?;
        let task = record.task_subject();
        let native = |kind, identity| GraphSubjectKeyV1::native(&record.id.stream, kind, identity);
        let fact = fact_index.and_then(|index| self.facts.get(index as usize));
        let (from, to, edge_type, proof, from_context, to_context) = match kind {
            EdgeKind::Process => (
                task,
                native(
                    GraphSubjectKindV1::Process,
                    record
                        .process_instance_id
                        .ok_or_else(|| Self::invalid("graph process selection"))?
                        .to_vec(),
                ),
                GraphEdgeTypeV1::TaskInProcess,
                record.proof_quality,
                None,
                None,
            ),
            EdgeKind::ExecutionSet => (
                task,
                native(
                    GraphSubjectKindV1::ExecutionSet,
                    record.effect.execution_set_id.to_vec(),
                ),
                GraphEdgeTypeV1::TaskInExecutionSet,
                record.proof_quality,
                None,
                None,
            ),
            EdgeKind::Object => {
                let mut identity = record.effect.exact_object_id.to_vec();
                identity.extend_from_slice(
                    &record
                        .profile_generation_ref_id
                        .unwrap_or_default()
                        .to_be_bytes(),
                );
                (
                    task,
                    native(
                        if record.network() {
                            GraphSubjectKindV1::Socket
                        } else {
                            GraphSubjectKindV1::Artifact
                        },
                        identity,
                    ),
                    GraphEdgeTypeV1::NativeEffect,
                    record.proof_quality,
                    None,
                    None,
                )
            }
            EdgeKind::Parent => match fact {
                Some(Fact {
                    record: anchor,
                    value:
                        FactValue::NativeParent {
                            parent,
                            child,
                            proof_quality,
                        },
                    ..
                }) if *anchor == row => (
                    parent.clone(),
                    child.clone(),
                    GraphEdgeTypeV1::NativeParent,
                    *proof_quality,
                    fact_index,
                    fact_index,
                ),
                _ => return Err(Self::invalid("graph parent selection")),
            },
            EdgeKind::Authority => match fact.map(|fact| &fact.value) {
                Some(FactValue::AuthorityUse {
                    authority_id,
                    request_id,
                    principal_id,
                    operation_id,
                    proof_quality,
                    ..
                }) => (
                    task,
                    GraphSubjectKeyV1 {
                        tenant_id: record.id.stream.tenant_id,
                        authority: GraphSubjectAuthorityV1::Provider {
                            authority_id: authority_id.clone(),
                        },
                        kind: if request_id.is_some() {
                            GraphSubjectKindV1::Request
                        } else {
                            GraphSubjectKindV1::ProviderObject
                        },
                        identity: serde_json::to_vec(&(request_id, principal_id, operation_id))
                            .map_err(Self::json_error)?,
                    },
                    GraphEdgeTypeV1::CredentialAuthority,
                    *proof_quality,
                    None,
                    fact_index,
                ),
                _ => return Err(Self::invalid("graph authority selection")),
            },
            EdgeKind::Kubernetes => match fact {
                Some(Fact {
                    record: anchor,
                    value: FactValue::Kubernetes(stage),
                    ..
                }) if *anchor == row => (
                    task,
                    GraphSubjectKeyV1 {
                        tenant_id: record.id.stream.tenant_id,
                        authority: GraphSubjectAuthorityV1::Kubernetes {
                            cluster_id: stage.cluster_id.clone(),
                        },
                        kind: GraphSubjectKindV1::KubernetesObject,
                        identity: serde_json::to_vec(&(
                            stage.object_uid.as_ref().ok_or_else(|| {
                                Self::invalid("graph Kubernetes object selection")
                            })?,
                            &stage.resource_version,
                        ))
                        .map_err(Self::json_error)?,
                    },
                    GraphEdgeTypeV1::KubernetesExpansion,
                    stage.proof_quality,
                    None,
                    fact_index,
                ),
                _ => return Err(Self::invalid("graph Kubernetes selection")),
            },
        };
        let coverage = record
            .coverage_interval_id
            .as_slice()
            .try_into()
            .map_err(|_| Self::invalid("edge coverage interval"))?;
        let boottime = record.observed_boottime_ns;
        let from_record = from_context.map_or(row, |index| self.facts[index as usize].record);
        let to_record = to_context.map_or(row, |index| self.facts[index as usize].record);
        let from = self.subject_index(from, from_record, from_context)?;
        let to = self.subject_index(to, to_record, to_context)?;
        let key = GraphEdgeKeyV1 {
            from,
            to,
            edge_type,
            package_id: self.detector.id().into(),
            evidence,
            cause: match cause {
                Cause::Direct => GraphCauseV1::Direct,
                Cause::Contextual => GraphCauseV1::Contextual,
                Cause::Contradicted => GraphCauseV1::Contradicted,
            },
        };
        let edge = GraphEdgeV1 {
            key: key.clone(),
            proof_quality: proof,
            required_coverage_interval_ids: vec![coverage],
            first_boottime_ns: boottime,
            last_boottime_ns: boottime,
        };
        if let Some(previous) = self.edges.get_mut(&key) {
            if previous.edge != edge {
                if key.cause != GraphCauseV1::Contradicted {
                    return Err(Self::invalid("conflicting edge value"));
                }
                previous.edge.proof_quality.operation_result_authority =
                    OperationResultAuthorityV1::Unknown;
            }
        } else {
            self.edges.insert(
                key,
                Relationship {
                    record: row,
                    fact: fact_index,
                    edge,
                },
            );
        }
        Ok(())
    }
}
