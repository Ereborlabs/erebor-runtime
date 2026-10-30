use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, GraphFactV1,
    GraphFactValueV1, GraphPolicyActivationV1, GraphValidate, PolicyObservationProvenanceV1,
    PolicyProvenanceStateV1,
};

use super::*;

mod retained;
pub(super) use retained::GraphCandidate;
use retained::GraphContext;

impl GraphContext {
    pub fn facts(
        &self,
        record: &araphor_data::DiscoveryRecordV1,
    ) -> Result<Vec<AnalysisContextVersionV1>> {
        let stream = &record.id.stream;
        let wire = record.decode()?;
        let Some(context) = wire.decision_context.as_ref() else {
            return Ok(Vec::new());
        };
        let Some(catalog) =
            crate::EvidenceDecisionCatalogV1::from_context(context).map_err(|error| {
                crate::error::DiscoverySnafu {
                    code: "GRAPH_CATALOG",
                    reason: error.to_string(),
                }
                .build()
            })?
        else {
            return Ok(Vec::new());
        };
        if context.process_instance_id.as_slice() == [0; 16]
            || context.entry_instance_id.as_slice() == [0; 16]
            || context.binding_id.as_slice() == [0; 16]
            || context.entry_rule_id == 0
        {
            return Ok(Vec::new());
        }
        crate::ObservationEnvelopeV1::from_wire_record(
            stream.tenant_id.into(),
            stream.node_boot_id.into(),
            stream.source_id.into(),
            stream.source_epoch,
            record.id.durable_cursor,
            record.id.cpu_id,
            &wire,
        )
        .map_err(|error| {
            crate::error::DiscoverySnafu {
                code: "GRAPH_OBSERVATION",
                reason: error.to_string(),
            }
            .build()
        })?;
        let tenant = uuid::Uuid::from_bytes(stream.tenant_id).to_string();
        let boot = hex::encode(stream.node_boot_id);
        let execution = <[u8; 16]>::try_from(wire.execution_set_id.as_ref())
            .ok()
            .map(uuid::Uuid::from_bytes)
            .map(|id| id.to_string());
        let authority = <[u8; 16]>::try_from(wire.authority_domain_id.as_ref())
            .ok()
            .map(uuid::Uuid::from_bytes)
            .map(|id| id.to_string());
        let mut facts = Vec::new();
        for ((key, version), ack) in &self.acknowledgements {
            if key.node_id != stream.node_id {
                continue;
            }
            let Some(material) = self.candidates.get(&key.candidate_content_id) else {
                continue;
            };
            let candidate = &material.candidate;
            if material.source_tenant != tenant
                || candidate.tenant_id != tenant
                || material.profile_id != catalog.profile_id
                || material.profile_version != catalog.profile_version
                || material.policy_digest != catalog.policy_document_digest
            {
                continue;
            }
            let Some(cell) = material
                .cells
                .iter()
                .find(|cell| cell.key == catalog.static_key)
            else {
                continue;
            };
            let matched_workloads: Vec<_> = candidate
                .exact_target
                .workload_targets
                .iter()
                .filter(|workload| {
                    workload.kubernetes.as_ref().is_some_and(|identity| {
                        workload.node_id == stream.node_id
                            && identity.node_boot_id == boot
                            && identity.label_epoch == stream.label_epoch
                            && catalog.matches_binding(workload)
                            && identity.profile_id == catalog.profile_id
                            && identity.policy_source_revision_id
                                == candidate.policy_source_revision_id
                            && Some(&workload.execution_set_id) == execution.as_ref()
                            && identity.protected_scope_id == catalog.static_key.protected_scope_id
                            && identity.workload_selector_id
                                == catalog.static_key.workload_selector_id
                            && authority.as_ref().is_none_or(|authority| {
                                authority == &catalog.static_key.protected_scope_id
                            })
                            && material
                                .execution_sets
                                .contains(&catalog.static_key.execution_set_id)
                    })
                })
                .collect();
            if matched_workloads.len() != 1 {
                continue;
            }
            let workload = matched_workloads[0];
            if crate::workload_target_fact_digest(workload)?
                != workload.workload_binding_generation_digest
            {
                continue;
            }
            let mut lifetime = stream.exact_key();
            lifetime.extend_from_slice(&record.id.cpu_id.to_be_bytes());
            lifetime.extend_from_slice(&record.id.durable_cursor.to_be_bytes());
            let ack_key = AnalysisContextKeyV1 {
                tenant_id: stream.tenant_id,
                owner_id: "mithril-control/policy-ack".into(),
                entity_key: key.candidate_content_id.as_bytes().to_vec(),
                lifetime_key: lifetime.clone(),
                owner_revision: *version,
            };
            let exact_fields = ack.tenant_id == tenant
                && ack.node_id == stream.node_id
                && ack.node_boot_id.as_slice() == stream.node_boot_id
                && ack.label_epoch == stream.label_epoch
                && ack.candidate_content_id == candidate.candidate_content_id
                && ack.policy_source_revision_id == candidate.policy_source_revision_id
                && ack.target_snapshot_digest == candidate.target_snapshot_digest
                && ack.profile_generation_ref_id == wire.profile_generation_ref_id;
            let observed_generation = ack.profile_generation_ref_id.is_some()
                && ack.profile_generation_ref_id == wire.profile_generation_ref_id;
            let state = if exact_fields
                && observed_generation
                && ack.state == PolicyActivationStateV1::Active
                && ack.node_bound_generation_digest.is_some()
                && ack.readback_digest.is_some()
                && ack.probe_result_digest.is_some()
            {
                PolicyProvenanceStateV1::Exact
            } else if observed_generation
                && (!exact_fields
                    || matches!(
                        ack.state,
                        PolicyActivationStateV1::Rejected | PolicyActivationStateV1::Stale
                    ))
            {
                PolicyProvenanceStateV1::Contradicted
            } else {
                PolicyProvenanceStateV1::Missing
            };
            let mut limits = Vec::new();
            if !exact_fields {
                limits.push("ACTIVATION_FIELDS_MISSING_OR_MISMATCHED".into());
            }
            if ack.state != PolicyActivationStateV1::Active {
                limits.push("ACTIVATION_NOT_ACTIVE".into());
            }
            if ack.node_bound_generation_digest.is_none()
                || ack.readback_digest.is_none()
                || ack.probe_result_digest.is_none()
            {
                limits.push("ACTIVATION_RESULT_PROOF_MISSING".into());
            }
            limits.sort();
            let provenance = PolicyObservationProvenanceV1 {
                source: stream.clone(),
                profile_generation_ref_id: wire.profile_generation_ref_id.unwrap_or_default(),
                observations: vec![record.id.clone()],
                policy_source_revision_id: Some(candidate.policy_source_revision_id.clone()),
                candidate_content_id: Some(candidate.candidate_content_id.clone()),
                target_snapshot_digest: Some(candidate.target_snapshot_digest.clone()),
                node_bound_generation_digest: ack.node_bound_generation_digest.clone(),
                activation_acknowledgement: Some(ack_key.clone()),
                state,
                limits,
            };
            let activation = GraphPolicyActivationV1 {
                tenant_id: ack.tenant_id.clone(),
                node_id: ack.node_id.clone(),
                node_boot_id: ack.node_boot_id.clone(),
                label_epoch: ack.label_epoch,
                candidate_content_id: ack.candidate_content_id.clone(),
                policy_source_revision_id: ack.policy_source_revision_id.clone(),
                target_snapshot_digest: ack.target_snapshot_digest.clone(),
                state: match ack.state {
                    PolicyActivationStateV1::Received => "RECEIVED",
                    PolicyActivationStateV1::Staged => "STAGED",
                    PolicyActivationStateV1::Active => "ACTIVE",
                    PolicyActivationStateV1::Rejected => "REJECTED",
                    PolicyActivationStateV1::Stale => "STALE",
                    PolicyActivationStateV1::Unknown => "UNKNOWN",
                }
                .into(),
                node_bound_generation_digest: ack.node_bound_generation_digest.clone(),
                profile_generation_ref_id: ack.profile_generation_ref_id,
                readback_digest: ack.readback_digest.clone(),
                probe_result_digest: ack.probe_result_digest.clone(),
                reason_code: ack.reason_code.clone(),
                observed_utc_ns: ack.observed_utc_ns,
            };
            facts.push(graph_fact(
                record,
                ack_key,
                GraphFactValueV1::Activation(activation),
            )?);
            if ack.profile_generation_ref_id.is_some() && !observed_generation {
                continue;
            }
            if ack.profile_generation_ref_id.is_none()
                && self.acknowledgements.iter().any(|((other_key, _), other)| {
                    other_key == key
                        && other.profile_generation_ref_id.is_some()
                        && other.profile_generation_ref_id == wire.profile_generation_ref_id
                })
            {
                continue;
            }
            if state == PolicyProvenanceStateV1::Missing
                && self.acknowledgements.iter().any(|((other_key, _), other)| {
                    other_key == key
                        && other.state == PolicyActivationStateV1::Active
                        && other.profile_generation_ref_id.is_some()
                        && other.profile_generation_ref_id == wire.profile_generation_ref_id
                        && other.tenant_id == tenant
                        && other.node_id == stream.node_id
                        && other.node_boot_id.as_slice() == stream.node_boot_id
                        && other.label_epoch == stream.label_epoch
                        && other.policy_source_revision_id == candidate.policy_source_revision_id
                        && other.target_snapshot_digest == candidate.target_snapshot_digest
                        && other.node_bound_generation_digest.is_some()
                        && other.readback_digest.is_some()
                        && other.probe_result_digest.is_some()
                })
            {
                continue;
            }
            let fact_key = |owner: &str| AnalysisContextKeyV1 {
                tenant_id: stream.tenant_id,
                owner_id: owner.into(),
                entity_key: candidate.candidate_content_id.as_bytes().to_vec(),
                lifetime_key: lifetime.clone(),
                owner_revision: *version,
            };
            facts.push(graph_fact(
                record,
                fact_key("mithril-control/graph-policy"),
                GraphFactValueV1::Policy(provenance),
            )?);
            facts.push(graph_fact(
                record,
                fact_key("mithril-control/graph-baseline"),
                GraphFactValueV1::Baseline {
                    role_id: catalog.role_id,
                    state_id: catalog.state_id,
                    outside_reviewed_baseline: matches!(
                        cell.physical_result,
                        crate::CompiledPhysicalResultV1::DenyEffect
                            | crate::CompiledPhysicalResultV1::SimulatablePolicyDeny
                    ),
                    reviewed_policy_revision: candidate.policy_source_revision_id.clone(),
                },
            )?);
            if material
                .credential_objects
                .contains(&catalog.static_key.object_selector)
            {
                if let Ok(object_id) = <[u8; 16]>::try_from(wire.exact_object_id.as_ref()) {
                    facts.push(graph_fact(
                        record,
                        fact_key("mithril-control/graph-credential"),
                        GraphFactValueV1::Credential {
                            object_id,
                            expected_access: matches!(
                                cell.physical_result,
                                crate::CompiledPhysicalResultV1::AllowEffect
                                    | crate::CompiledPhysicalResultV1::AuditAllowEffect
                            ),
                            reviewed_policy_revision: candidate.policy_source_revision_id.clone(),
                            completion: None,
                            proof_quality: araphor_data::ProofQualityV1::kernel_decision(
                                araphor_data::TemporalCoverageV1::Unknown,
                            ),
                            principal_id: Some(format!(
                                "kubernetes-serviceaccount-uid:{}",
                                workload.service_account_uid
                            )),
                        },
                    )?);
                }
            }
        }
        facts.sort_by(|left, right| left.key.cmp(&right.key));
        Ok(facts)
    }
}

fn graph_fact(
    record: &araphor_data::DiscoveryRecordV1,
    key: AnalysisContextKeyV1,
    value: GraphFactValueV1,
) -> Result<AnalysisContextVersionV1> {
    let fact = GraphFactV1 {
        record_id: record.id.clone(),
        value,
    };
    fact.validate()?;
    let body = fact.encode_context().map_err(|error| {
        crate::error::DiscoverySnafu {
            code: "GRAPH_CONTEXT_ENCODING",
            reason: error.to_string(),
        }
        .build()
    })?;
    Ok(AnalysisContextVersionV1 {
        key,
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body,
    })
}

impl araphor_analysis::GraphFacts for super::context::ControlContextOwner {
    fn context_owners(&self) -> Option<&'static [&'static str]> {
        Some(&[
            "mithril-control/policy-candidate",
            "mithril-control/activation-ack",
            "mithril-control/graph-policy",
            "mithril-control/graph-baseline",
            "mithril-control/graph-credential",
            "mithril-control/policy-ack",
        ])
    }

    fn facts(
        &self,
        contexts: &[arrow_array::RecordBatch],
        records: &[araphor_data::DiscoveryRecordV1],
    ) -> araphor_data::Result<(
        Vec<AnalysisContextVersionV1>,
        Vec<araphor_data::AnalysisContextRefV1>,
    )> {
        let (context, mut proofs) = GraphContext::capture(contexts, records)?;
        let mut facts = Vec::new();
        for record in records {
            facts.extend(context.facts(record).map_err(|source| {
                araphor_data::Error::GraphContext {
                    source: Box::new(source),
                    location: snafu::location!(),
                }
            })?);
        }
        let consulted = facts
            .iter()
            .filter(|fact| fact.key.owner_id == "mithril-control/policy-ack")
            .flat_map(|fact| {
                let original = |owner: &str, revision| AnalysisContextKeyV1 {
                    tenant_id: fact.key.tenant_id,
                    owner_id: owner.into(),
                    entity_key: fact.key.entity_key.clone(),
                    lifetime_key: records[0].id.stream.node_id.as_bytes().to_vec(),
                    owner_revision: revision,
                };
                [
                    original("mithril-control/policy-candidate", 1),
                    original("mithril-control/activation-ack", fact.key.owner_revision),
                ]
            })
            .collect::<std::collections::BTreeSet<_>>();
        proofs.retain(|proof| consulted.contains(&proof.key));
        Ok((facts, proofs))
    }
}

#[cfg(test)]
mod tests {
    mod retained;

    use super::super::tests::{
        kubernetes_target, rollout_transaction, signed_artifact, source_revision,
    };
    use super::*;
    use crate::PolicyDeliveryOperationV1;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

    fn fixture(
        path: &std::path::Path,
    ) -> std::result::Result<
        (
            ControlStore,
            araphor_data::DiscoveryRecordV1,
            PolicyBundleV1,
            PolicyRolloutStateV1,
        ),
        Box<dyn std::error::Error>,
    > {
        fixture_version(path, 1)
    }

    fn fixture_version(
        path: &std::path::Path,
        version: u64,
    ) -> std::result::Result<
        (
            ControlStore,
            araphor_data::DiscoveryRecordV1,
            PolicyBundleV1,
            PolicyRolloutStateV1,
        ),
        Box<dyn std::error::Error>,
    > {
        populate_version(ControlStore::open(path)?, version)
    }

    fn populate_version(
        store: ControlStore,
        version: u64,
    ) -> std::result::Result<
        (
            ControlStore,
            araphor_data::DiscoveryRecordV1,
            PolicyBundleV1,
            PolicyRolloutStateV1,
        ),
        Box<dyn std::error::Error>,
    > {
        let mut document = PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../tests/fixtures/policy-v1.yaml"),
        )?;
        document.metadata.profile_version = version;
        document.rollout.rollout_generation = version;
        if version > 1 {
            document.metadata.profile_id = uuid::Uuid::from_u128(u128::from(version)).to_string();
        }
        populate_document(store, document)
    }

    fn populate_document(
        store: ControlStore,
        document: PolicyDocumentV1,
    ) -> std::result::Result<
        (
            ControlStore,
            araphor_data::DiscoveryRecordV1,
            PolicyBundleV1,
            PolicyRolloutStateV1,
        ),
        Box<dyn std::error::Error>,
    > {
        let version = document.metadata.profile_version;
        store.register_node_physical_session(
            "node-a",
            &[1; 16],
            1,
            None,
            &super::super::startup_absence_proof_digest("node-a", &[1; 16], 1, true, true),
            true,
            true,
            1,
        )?;
        let mut source = source_revision(
            &document,
            PolicySourceStateV1::Accepted,
            version,
            if version == 1 { '8' } else { '9' },
        )?;
        if version > 1 {
            source.object_uid = uuid::Uuid::from_u128(u128::from(version)).to_string();
            source.object_name = format!("profile-{version}");
            source.policy_source_revision_id = format!("{version:064x}");
        }
        let artifact = signed_artifact(&document, version)?;
        let static_key = artifact
            .compiled_profile
            .compiled_cells
            .first()
            .ok_or("cell")?
            .key
            .clone();
        store.accept_compiled_source_revision(
            source.clone(),
            document.clone(),
            artifact.clone(),
        )?;
        let mut target = kubernetes_target(
            &source,
            &document,
            "aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
            1,
            1,
        )?;
        let workload = target.workload_targets.first_mut().ok_or("workload")?;
        let identity = workload.kubernetes.as_mut().ok_or("identity")?;
        identity.protected_scope_id = static_key.protected_scope_id.clone();
        identity.workload_selector_id = static_key.workload_selector_id.clone();
        identity.binding_id = araphor_data::KubernetesWorkloadIdentityV1::authority_binding_id(
            &workload.pod_uid,
            &workload.container_name,
        );
        workload.container_id = format!("scheduled:{}", "1".repeat(64));
        let binding_id = uuid::Uuid::parse_str(&identity.binding_id)?.into_bytes();
        workload.workload_binding_generation_digest = crate::workload_target_fact_digest(workload)?;
        target.workload_binding_generation_digests =
            vec![workload.workload_binding_generation_digest.clone()];
        let workload = workload.clone();
        let rollout = rollout_transaction(
            &source,
            &artifact,
            vec![(target, None)],
            PolicyDeliveryOperationV1::Activate,
            version,
            version,
            &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
        )?;
        let bundle = rollout.bundles.first().ok_or("bundle")?.clone();
        let state = rollout.rollout_states.first().ok_or("state")?.clone();
        store.create_rollout(
            rollout.target_snapshot,
            rollout.bundles,
            rollout.rollout_states,
        )?;
        let manifest = araphor_data::DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let mut record = manifest.records.first().ok_or("record")?.clone();
        record.id.stream.tenant_id = uuid::Uuid::parse_str(&source.tenant_id)?.into_bytes();
        record.id.stream.node_id = "node-a".into();
        record.id.stream.node_boot_id = [1; 16];
        record.id.stream.label_epoch = 1;
        let mut observation = crate::ObservationEnvelopeV1::from_wire_record(
            record.id.stream.tenant_id.into(),
            record.id.stream.node_boot_id.into(),
            record.id.stream.source_id.into(),
            record.id.stream.source_epoch,
            record.id.durable_cursor,
            record.id.cpu_id,
            &record.decode()?,
        )?;
        observation.profile_generation_ref_id = Some(8);
        observation.effect.decision =
            erebor_interceptor_abi::EffectPhysicalResultV1::DeniedBeforeEffect as u8;
        observation.effect.execution_set_id = Some(
            uuid::Uuid::parse_str(&workload.execution_set_id)?
                .into_bytes()
                .into(),
        );
        observation.effect.authority_domain_id = Some(
            uuid::Uuid::parse_str(&static_key.protected_scope_id)?
                .into_bytes()
                .into(),
        );
        let operation = crate::CompiledOperationV1::try_from(static_key.operation_id.as_str())?;
        observation.effect.effect_family =
            erebor_interceptor_abi::KernelEffectFamilyV1::from(static_key.effect_family) as u16;
        observation.effect.operation = operation.kernel_id as u16;
        observation.effect.operation_argument =
            (operation.argument != 0).then_some(operation.argument);
        observation.effect.policy_rule_id = Some(23);
        let object = crate::EvidenceExactFileObject {
            profile_generation_ref_id: 8,
            mount_id_unique: 21,
            inode: 22,
            inode_generation: 23,
            mount_namespace_inode: 24,
            filesystem_device: 25,
        };
        observation.effect.exact_object_id =
            Some(crate::EvidenceFileObjectV1::from(&object).observation_id(26));
        let catalog = crate::EvidenceDecisionCatalogV1 {
            node_boot_id: observation.node_boot_id,
            profile_id: artifact.header.profile_id.clone(),
            profile_version: artifact.header.profile_version,
            policy_document_digest: artifact.header.policy_document_digest.clone(),
            profile_generation_ref_id: 8,
            binding_id: binding_id.into(),
            runtime_binding: None,
            role_id: 1,
            state_id: 2,
            entry_rule_id: 3,
            exact_file_object: object,
            exact_object_key_id: 26,
            composite_atom_id: 23,
            static_key,
            digest: crate::DiscoveryDigestV1([0; 32]),
        };
        observation.decision_context = Some(crate::EvidenceDecisionContext {
            schema_version: 1,
            original_kernel_sequence: 101,
            process_instance_id: vec![27; 16],
            entry_instance_id: vec![28; 16],
            binding_id: binding_id.to_vec(),
            profile_generation_ref_id: 8,
            role_id: 1,
            state_id: 2,
            entry_rule_id: 3,
            exact_file_object: Some(object),
            exact_object_key_id: 26,
            composite_atom_id: 23,
            catalog_json: catalog.seal()?,
            catalog_state: "AVAILABLE".into(),
        });
        let wire = observation.to_wire_record()?;
        let record = araphor_data::DiscoveryRecordV1::try_from((
            record.id,
            Vec::<u8>::try_from(&wire)?.as_slice(),
        ))?;
        Ok((store, record, bundle, state))
    }

    fn acknowledge(
        store: &ControlStore,
        bundle: &PolicyBundleV1,
        rollout: &mut PolicyRolloutStateV1,
        state: PolicyActivationStateV1,
        generation: Option<u64>,
        digest: char,
    ) -> TestResult {
        let active = state == PolicyActivationStateV1::Active;
        rollout.transition_version += 1;
        rollout.latest_acknowledgement_version = Some(rollout.transition_version);
        rollout.updated_utc_ns = i64::try_from(rollout.transition_version)?;
        rollout.state = match state {
            PolicyActivationStateV1::Received => PolicyRolloutStatusV1::Delivered,
            PolicyActivationStateV1::Staged => PolicyRolloutStatusV1::Staged,
            PolicyActivationStateV1::Active => PolicyRolloutStatusV1::Active,
            PolicyActivationStateV1::Rejected => PolicyRolloutStatusV1::Rejected,
            PolicyActivationStateV1::Stale => PolicyRolloutStatusV1::Stale,
            PolicyActivationStateV1::Unknown => PolicyRolloutStatusV1::Unknown,
        };
        store.acknowledge_policy(
            PolicyActivationAcknowledgementV1 {
                tenant_id: bundle.candidate.tenant_id.clone(),
                node_id: "node-a".into(),
                node_boot_id: vec![1; 16],
                label_epoch: 1,
                candidate_content_id: bundle.candidate.candidate_content_id.clone(),
                policy_source_revision_id: bundle.candidate.policy_source_revision_id.clone(),
                target_snapshot_digest: bundle.candidate.target_snapshot_digest.clone(),
                state,
                node_bound_generation_digest: active.then(|| digest.to_string().repeat(64)),
                profile_generation_ref_id: generation,
                readback_digest: active.then(|| "2".repeat(64)),
                probe_result_digest: active.then(|| "3".repeat(64)),
                reason_code: None,
                observed_utc_ns: rollout.updated_utc_ns,
            },
            rollout.clone(),
        )?;
        Ok(())
    }

    fn policies(
        facts: &[AnalysisContextVersionV1],
    ) -> araphor_data::Result<Vec<PolicyObservationProvenanceV1>> {
        Ok(facts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<araphor_data::Result<Vec<_>>>()?
            .into_iter()
            .filter_map(|fact| match fact.value {
                GraphFactValueV1::Policy(policy) => Some(policy),
                _ => None,
            })
            .collect())
    }

    #[test]
    fn control_graph_control_store_qualifies_immutable_generation_chain() -> TestResult {
        let directory = tempfile::tempdir()?;
        let (store, record, bundle, mut rollout) = fixture(directory.path())?;
        let data = Arc::new(araphor_data::AnalysisStore::open(
            directory.path().join("data"),
        )?);
        let mut copy = retained::owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?;
        assert!(retained::facts(&mut copy, &data, &record)?.is_empty());
        acknowledge(
            &store,
            &bundle,
            &mut rollout,
            PolicyActivationStateV1::Received,
            None,
            '1',
        )?;
        acknowledge(
            &store,
            &bundle,
            &mut rollout,
            PolicyActivationStateV1::Staged,
            Some(8),
            '1',
        )?;
        assert!(policies(&retained::facts(&mut copy, &data, &record)?)?
            .iter()
            .all(|policy| policy.state == PolicyProvenanceStateV1::Missing));
        acknowledge(
            &store,
            &bundle,
            &mut rollout,
            PolicyActivationStateV1::Active,
            Some(7),
            '1',
        )?;
        assert!(policies(&retained::facts(&mut copy, &data, &record)?)?
            .iter()
            .all(|policy| policy.state != PolicyProvenanceStateV1::Contradicted));
        acknowledge(
            &store,
            &bundle,
            &mut rollout,
            PolicyActivationStateV1::Active,
            Some(8),
            '4',
        )?;
        let facts = retained::facts(&mut copy, &data, &record)?;
        let selected = policies(&facts)?;
        assert_eq!(selected.len(), 1);
        assert_eq!(selected[0].state, PolicyProvenanceStateV1::Exact);
        assert_eq!(
            selected[0].policy_source_revision_id.as_deref(),
            Some(bundle.candidate.policy_source_revision_id.as_str())
        );
        assert_eq!(
            selected[0].candidate_content_id.as_deref(),
            Some(bundle.candidate.candidate_content_id.as_str())
        );
        assert_eq!(
            selected[0].target_snapshot_digest.as_deref(),
            Some(bundle.candidate.target_snapshot_digest.as_str())
        );
        let acknowledgement = selected[0]
            .activation_acknowledgement
            .as_ref()
            .ok_or("ACK reference")?;
        assert_eq!(acknowledgement.owner_revision, rollout.transition_version);
        assert!(facts.iter().any(|fact| &fact.key == acknowledgement));
        assert_eq!(
            facts
                .iter()
                .filter(|fact| matches!(
                    GraphFactV1::try_from(*fact).map(|fact| fact.value),
                    Ok(GraphFactValueV1::Activation(_))
                ))
                .count(),
            4
        );
        let original = facts.clone();
        acknowledge(
            &store,
            &bundle,
            &mut rollout,
            PolicyActivationStateV1::Active,
            Some(8),
            '5',
        )?;
        let mixed = policies(&retained::facts(&mut copy, &data, &record)?)?;
        assert_eq!(mixed.len(), 2);
        assert_ne!(
            mixed[0].node_bound_generation_digest,
            mixed[1].node_bound_generation_digest
        );
        for fact in original {
            assert!(retained::facts(&mut copy, &data, &record)?.contains(&fact));
        }
        let mut foreign = record.clone();
        foreign.id.stream.node_boot_id = [99; 16];
        assert!(retained::facts(&mut copy, &data, &foreign).is_err());
        let directory = tempfile::tempdir()?;
        let (store, record, bundle, mut rollout) = fixture(directory.path())?;
        let data = Arc::new(araphor_data::AnalysisStore::open(
            directory.path().join("data"),
        )?);
        let mut copy = retained::owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?;
        acknowledge(
            &store,
            &bundle,
            &mut rollout,
            PolicyActivationStateV1::Stale,
            Some(8),
            '1',
        )?;
        assert_eq!(
            policies(&retained::facts(&mut copy, &data, &record)?)?
                .first()
                .ok_or("stale")?
                .state,
            PolicyProvenanceStateV1::Contradicted
        );
        Ok(())
    }
}
