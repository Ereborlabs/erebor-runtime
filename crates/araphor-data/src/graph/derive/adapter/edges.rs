use super::*;

type EdgeSelection = (
    GraphSubjectKeyV1,
    GraphSubjectKeyV1,
    GraphEdgeTypeV1,
    ProofQualityV1,
);

impl GraphDerivation<'_> {
    pub(super) fn selected_edge(
        &mut self,
        package: &str,
        edge: algorithm::Relationship,
    ) -> Result<()> {
        let record = self.selected_record(edge.record)?.clone();
        let wire = record.decode()?;
        let task = self.task(&record, &wire);
        let effect = self.effect(&record, &wire);
        let (from, to, edge_type, proof) = match edge.kind {
            algorithm::EdgeKind::Process
            | algorithm::EdgeKind::ExecutionSet
            | algorithm::EdgeKind::Object => self.native_selection(&edge, task, &wire, &effect)?,
            _ => self.fact_selection(&edge, task, &record)?,
        };
        from.validate()?;
        to.validate()?;
        self.subjects.insert(from.clone());
        self.subjects.insert(to.clone());
        self.edge(
            GraphEdgeKeyV1 {
                from,
                to,
                edge_type,
                package_id: package.into(),
                evidence: self.selected_evidence(&edge.evidence)?,
                cause: match edge.cause {
                    algorithm::Cause::Direct => GraphCauseV1::Direct,
                    algorithm::Cause::Contextual => GraphCauseV1::Contextual,
                    algorithm::Cause::Contradicted => GraphCauseV1::Contradicted,
                },
            },
            proof,
            &wire,
        )
    }
    fn native_selection(
        &mut self,
        edge: &algorithm::Relationship,
        task: GraphSubjectKeyV1,
        wire: &EvidenceRecord,
        effect: &GraphEffectV1,
    ) -> Result<EdgeSelection> {
        Ok(match edge.kind {
            algorithm::EdgeKind::Process => {
                let process = effect.process_instance_id.ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "graph process selection",
                    }
                    .build()
                })?;
                (
                    task,
                    self.subject(GraphSubjectKindV1::Process, process.to_vec()),
                    GraphEdgeTypeV1::TaskInProcess,
                    effect.proof_quality,
                )
            }
            algorithm::EdgeKind::ExecutionSet => (
                task,
                self.subject(
                    GraphSubjectKindV1::ExecutionSet,
                    wire.execution_set_id.to_vec(),
                ),
                GraphEdgeTypeV1::TaskInExecutionSet,
                effect.proof_quality,
            ),
            algorithm::EdgeKind::Object => {
                let mut identity = wire.exact_object_id.to_vec();
                identity.extend_from_slice(
                    &wire
                        .profile_generation_ref_id
                        .unwrap_or_default()
                        .to_be_bytes(),
                );
                let kind = if wire.effect_family == KernelEffectFamilyV1::Network as u32 {
                    GraphSubjectKindV1::Socket
                } else {
                    GraphSubjectKindV1::Artifact
                };
                (
                    task,
                    self.subject(kind, identity),
                    GraphEdgeTypeV1::NativeEffect,
                    effect.proof_quality,
                )
            }
            _ => {
                return GraphInvalidSnafu {
                    field: "native edge selection",
                }
                .fail()
            }
        })
    }

    fn fact_selection(
        &self,
        edge: &algorithm::Relationship,
        task: GraphSubjectKeyV1,
        record: &DiscoveryRecordV1,
    ) -> Result<EdgeSelection> {
        Ok(match edge.kind {
            algorithm::EdgeKind::Parent => {
                let fact = self.selected_fact(edge.fact)?;
                match &fact.value {
                    GraphFactValueV1::NativeParent {
                        parent,
                        child,
                        proof_quality,
                    } if fact.record_id == record.id => (
                        parent.clone(),
                        child.clone(),
                        GraphEdgeTypeV1::NativeParent,
                        *proof_quality,
                    ),
                    _ => {
                        return GraphInvalidSnafu {
                            field: "graph parent selection",
                        }
                        .fail()
                    }
                }
            }
            algorithm::EdgeKind::Authority => match &self.selected_fact(edge.fact)?.value {
                GraphFactValueV1::AuthorityUse {
                    authority_id,
                    request_id,
                    principal_id,
                    operation_id,
                    proof_quality,
                    ..
                } => {
                    let subject = GraphSubjectKeyV1 {
                        tenant_id: self.input.source.tenant_id,
                        authority: GraphSubjectAuthorityV1::Provider {
                            authority_id: authority_id.clone(),
                        },
                        kind: if request_id.is_some() {
                            GraphSubjectKindV1::Request
                        } else {
                            GraphSubjectKindV1::ProviderObject
                        },
                        identity: serde_json::to_vec(&(request_id, principal_id, operation_id))
                            .context(GraphEncodingSnafu)?,
                    };
                    (
                        task,
                        subject,
                        GraphEdgeTypeV1::CredentialAuthority,
                        *proof_quality,
                    )
                }
                _ => {
                    return GraphInvalidSnafu {
                        field: "graph authority selection",
                    }
                    .fail()
                }
            },
            algorithm::EdgeKind::Kubernetes => {
                let fact = self.selected_fact(edge.fact)?;
                match &fact.value {
                    GraphFactValueV1::Kubernetes(stage) if fact.record_id == record.id => {
                        let uid = stage.object_uid.as_ref().ok_or_else(|| {
                            GraphInvalidSnafu {
                                field: "graph Kubernetes object selection",
                            }
                            .build()
                        })?;
                        let subject = GraphSubjectKeyV1 {
                            tenant_id: self.input.source.tenant_id,
                            authority: GraphSubjectAuthorityV1::Kubernetes {
                                cluster_id: stage.cluster_id.clone(),
                            },
                            kind: GraphSubjectKindV1::KubernetesObject,
                            identity: serde_json::to_vec(&(uid, &stage.resource_version))
                                .context(GraphEncodingSnafu)?,
                        };
                        (
                            task,
                            subject,
                            GraphEdgeTypeV1::KubernetesExpansion,
                            stage.proof_quality,
                        )
                    }
                    _ => {
                        return GraphInvalidSnafu {
                            field: "graph Kubernetes selection",
                        }
                        .fail()
                    }
                }
            }
            _ => {
                return GraphInvalidSnafu {
                    field: "fact edge selection",
                }
                .fail()
            }
        })
    }
}
