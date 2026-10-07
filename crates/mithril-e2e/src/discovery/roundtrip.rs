use std::{
    collections::BTreeSet,
    error::Error as StdError,
    fs,
    path::{Path, PathBuf},
    sync::{
        atomic::{AtomicBool, AtomicUsize, Ordering},
        Arc,
    },
};

use mithril_control::{ControlStore, EvidenceIdV1, EvidenceIntakeIdentityV1, NodeRegistration};
use mithril_node::{
    EffectObservationStore, EvidenceWalLimits, NodeControlMessage, ObservationCanonicalizer,
    TrustCache,
};
use snafu::ensure;
use zerocopy::IntoBytes as _;

use crate::{
    control_fixture::{
        reopen_control_store, MtlsFixture, OutagePolicyFixture, OUTAGE_NAMESPACE_UID,
    },
    error::InvalidInputSnafu,
};

pub struct DiscoveryQualificationRunner {
    output: PathBuf,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RoundtripCase {
    EvidenceRestart,
    ContextRoundtrip,
    ProfileRestart,
}

struct DelayedContext {
    store: ControlStore,
    available: AtomicBool,
    calls: AtomicUsize,
}

impl araphor_data::DiscoveryContextProvider for DelayedContext {
    fn revision(&self, _source: &EvidenceIntakeIdentityV1) -> araphor_data::Result<u64> {
        Ok(if self.available.load(Ordering::Acquire) {
            2
        } else {
            1
        })
    }

    fn context(
        &self,
        record: &araphor_data::DiscoveryRecordV1,
    ) -> araphor_data::Result<araphor_data::DiscoveryContextJoinV1> {
        self.calls.fetch_add(1, Ordering::SeqCst);
        if self.available.load(Ordering::Acquire) {
            araphor_data::DiscoveryContextProvider::context(&self.store, record)
        } else {
            Ok(araphor_data::DiscoveryContextJoinV1::Unresolved(
                araphor_data::DiscoveryContextUnavailableV1::MissingWorkloadFact,
            ))
        }
    }
}

impl DiscoveryQualificationRunner {
    pub fn new(output: PathBuf) -> Self {
        Self { output }
    }

    pub async fn evidence_restart(&self) -> Result<(), Box<dyn StdError>> {
        self.roundtrip(RoundtripCase::EvidenceRestart).await
    }

    pub async fn context_roundtrip(&self) -> Result<(), Box<dyn StdError>> {
        self.roundtrip(RoundtripCase::ContextRoundtrip).await
    }

    pub async fn profile_restart(&self) -> Result<(), Box<dyn StdError>> {
        self.roundtrip(RoundtripCase::ProfileRestart).await
    }

    pub async fn owner_isolation(&self) -> Result<(), Box<dyn StdError>> {
        super::isolation::run(&self.output).await
    }

    async fn roundtrip(&self, case: RoundtripCase) -> Result<(), Box<dyn StdError>> {
        ensure!(
            !self.output.exists(),
            InvalidInputSnafu {
                path: &self.output,
                reason: "the qualification output already exists",
            }
        );
        let signed_context = case != RoundtripCase::EvidenceRestart;
        let tls = MtlsFixture::new(false)?;
        let root = tls.path().join("control-store");
        let store = ControlStore::open(&root)?;
        let control = tls.control_with_store(store.clone(), 1)?;
        let data = control.analysis_store().ok_or("the data owner is absent")?;
        let server = tls.start(control).await?;
        let boot = EvidenceIdV1::from([7; 16]);
        let source = EvidenceIdV1::new(3, 4);
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(EvidenceIdV1::new(1, 2), source, 1, boot)?,
        )?;
        let process = EvidenceIdV1::new(8, 9);
        let entry = EvidenceIdV1::new(10, 11);
        let mut raw = erebor_interceptor_abi::EffectObservationV1 {
            observed_boottime_ns: 102,
            source_sequence: 101,
            source_cpu_id: 3,
            task_cookie: 7,
            process_instance_id: process,
            entry_instance_id: entry,
            reason: 9,
            physical_result: 1,
            effect_family: 1,
            operation: 1,
            ..Default::default()
        };
        let expected_workload = if signed_context {
            let (catalog, exact, workload) = signed_catalog(&store, tls.path(), boot)?;
            raw.binding_id = exact.binding_id;
            raw.execution_set_id = exact.execution_set_id;
            raw.authority_domain_id = exact.authority_domain_id;
            raw.profile_generation_ref_id = exact.profile_generation_ref_id;
            raw.active_role_id = exact.active_role_id;
            raw.process_state_vector_id = exact.process_state_vector_id;
            raw.admitted_entry_rule_id = exact.admitted_entry_rule_id;
            raw.effect_family = exact.effect_family;
            raw.operation = exact.operation;
            raw.file_object = exact.file_object;
            raw.exact_object_key_id = exact.exact_object_key_id;
            raw.composite_atom_id = exact.composite_atom_id;
            observations.set_discovery_context(Some(Arc::new(catalog)));
            Some(workload)
        } else {
            None
        };
        observations.record_bytes(raw.as_bytes());
        drop(observations);
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(EvidenceIdV1::new(1, 2), source, 1, boot)?,
        )?;
        let batch = observations
            .next_evidence_batch()
            .ok_or("Node WAL has no evidence")?;
        let original = batch.decode_records()?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        let mut trust = TrustCache::load(&tls.path().join("trust"))?;
        let mut connection = tls
            .connector(&server, "node-a", boot.to_be_bytes())
            .connect(
                NodeRegistration {
                    platform_digest: "a".repeat(64),
                    program_digest: "b".repeat(64),
                    label_epoch: 1,
                    kernel_ready: true,
                    effect_prevention_claims_enabled: false,
                    kubernetes_node_name: String::new(),
                    startup_absence_proof_digest: mithril_control::startup_absence_proof_digest(
                        "node-a",
                        &boot.to_be_bytes(),
                        1,
                        true,
                        true,
                    ),
                    policy_authority_absent: true,
                    exception_authority_absent: true,
                    capabilities: vec![mithril_control::CapabilityRecord {
                        capability_id: "KERNEL_LSM_CHASSIS".into(),
                        state: "UNSUPPORTED".into(),
                        reason_code: "SYNTHETIC_INPUT_ONLY".into(),
                    }],
                    workload_targets: Vec::new(),
                },
                false,
                &mut trust,
            )
            .await?;
        connection.send_evidence_batch(batch).await?;
        let ack = tokio::time::timeout(std::time::Duration::from_secs(5), async {
            loop {
                if let NodeControlMessage::EvidenceAck(ack) = connection.next_message().await? {
                    return Ok::<_, mithril_node::Error>(ack);
                }
            }
        })
        .await??;
        ensure!(
            ack.contiguous_cursor == 1,
            InvalidInputSnafu {
                path: &self.output,
                reason: "the durable evidence cursor differs",
            }
        );
        observations.acknowledge_evidence(ack)?;
        let stream = EvidenceIntakeIdentityV1 {
            tenant_id: EvidenceIdV1::new(1, 2).to_be_bytes(),
            node_id: "node-a".into(),
            node_boot_id: boot.to_be_bytes(),
            label_epoch: 1,
            source_id: wire.source_id.as_slice().try_into()?,
            source_epoch: wire.source_epoch,
        };
        let retained = {
            let page = data.read_page(&stream, 1)?;
            page.records
                .iter()
                .map(|record| {
                    araphor_data::EvidenceRecord::try_from(record.framed_record.as_slice())
                })
                .collect::<Result<Vec<_>, _>>()?
        };
        ensure!(
            retained == original && retained.len() == 1,
            InvalidInputSnafu {
                path: &self.output,
                reason: "Control changed the retained Node record",
            }
        );
        let context = retained[0]
            .decision_context
            .as_ref()
            .ok_or("raw context absent")?;
        ensure!(
            !signed_context || context.catalog_state == "AVAILABLE",
            InvalidInputSnafu {
                path: &self.output,
                reason: format!("the signed catalog state is {}", context.catalog_state),
            }
        );
        ensure!(
            context.original_kernel_sequence == 101
                && context.original_kernel_sequence != wire.first_cursor
                && context.process_instance_id.as_slice() == process.to_be_bytes()
                && context.entry_instance_id.as_slice() == entry.to_be_bytes()
                && context.profile_generation_ref_id == raw.profile_generation_ref_id
                && context.role_id == raw.active_role_id
                && context.state_id == raw.process_state_vector_id
                && context.entry_rule_id == raw.admitted_entry_rule_id
                && context.exact_object_key_id == raw.exact_object_key_id
                && context.composite_atom_id == raw.composite_atom_id,
            InvalidInputSnafu {
                path: &self.output,
                reason: "raw context differs after the transport roundtrip",
            }
        );
        let joined = araphor_data::DiscoveryRecordV1 {
            id: araphor_data::DiscoveryRecordIdV1 {
                stream: stream.clone(),
                cpu_id: wire.cpu_id,
                durable_cursor: 1,
            },
            original_kernel_sequence: Some(context.original_kernel_sequence),
            wire_record: wire.framed_records.to_vec(),
        };
        let pin = store.discovery_context(&joined)?;
        if let Some(workload) = expected_workload {
            let araphor_data::DiscoveryContextJoinV1::Available(context) = &pin else {
                return Err("the signed context was not resolved".into());
            };
            ensure!(
                context.workload == workload
                    && context.binding.process_instance_id == process.to_be_bytes()
                    && context.binding.entry_instance_id == entry.to_be_bytes()
                    && context.binding.binding_id == raw.binding_id.to_be_bytes()
                    && context.binding.role_id == raw.active_role_id
                    && context.binding.state_id == raw.process_state_vector_id
                    && context.binding.entry_rule_id == raw.admitted_entry_rule_id,
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "the signed workload pin differs",
                }
            );
            let catalog = mithril_control::EvidenceDecisionCatalogV1::from_context(
                retained[0]
                    .decision_context
                    .as_ref()
                    .ok_or("context absent")?,
            )?
            .ok_or("signed catalog absent")?;
            ensure!(
                context.binding.static_key
                    == araphor_data::DiscoveryPolicyKeyV1::try_from(&catalog.static_key)?
                    && catalog.node_boot_id == boot
                    && context.binding.policy_revision.profile_id == catalog.profile_id
                    && context.binding.policy_revision.profile_version == catalog.profile_version
                    && context.binding.policy_revision.source_revision_id
                        == context.policy_source_revision_id
                    && context.binding.policy_revision.signed_profile_digest
                        == context.signed_profile_digest,
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "the signed policy key or provenance differs",
                }
            );
        }
        let receipt = data
            .source_receipt(&stream)?
            .ok_or("the data receipt is absent")?;
        ensure!(
            observations.pending_evidence_records() == 0,
            InvalidInputSnafu {
                path: &self.output,
                reason: "Node retained acknowledged input",
            }
        );
        let profile_config = araphor_data::DiscoveryConfigV1 {
            interval_records: 1,
            ..Default::default()
        };
        let now = 1_800_000_000_000_000_000;
        let (profile, unresolved) = if case == RoundtripCase::ProfileRestart {
            let provider = Arc::new(DelayedContext {
                store: store.clone(),
                available: AtomicBool::new(false),
                calls: AtomicUsize::new(0),
            });
            let owner =
                araphor_data::DiscoveryOwner::new(data.clone(), provider.clone(), profile_config)?;
            ensure!(
                owner.process(now)? == 1,
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "the live owner did not consume one accepted record",
                }
            );
            let unresolved = owner.profile(&stream)?.ok_or("live profile absent")?;
            ensure!(
                unresolved.sealed
                    && unresolved.snapshot.accepted_records == 1
                    && unresolved.snapshot.included_records == 0
                    && unresolved.snapshot.unresolved_records == 1
                    && unresolved.context_refs.len() == 1
                    && unresolved.facts_revision == 1
                    && owner.process(now + 1)? == 0
                    && owner.profile(&stream)? == Some(unresolved.clone()),
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "the unavailable context did not remain unresolved",
                }
            );
            provider.available.store(true, Ordering::Release);
            ensure!(
                owner.process(now + 2)? == 0,
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "the late context repeated raw input consumption",
                }
            );
            let profile = owner.profile(&stream)?.ok_or("refreshed profile absent")?;
            let frozen = data
                .read_result(stream.tenant_id, &unresolved.profile_id)?
                .ok_or("the frozen unresolved result is absent")?;
            ensure!(
                profile.sealed
                    && profile.profile_id != unresolved.profile_id
                    && profile.interval_id == unresolved.interval_id
                    && profile.revision == unresolved.revision + 1
                    && profile.facts_revision == 2
                    && profile.snapshot.accepted_records == 1
                    && profile.snapshot.included_records == 1
                    && profile.snapshot.unresolved_records == 0
                    && profile.snapshot.atoms.len() == 1
                    && profile.snapshot.atoms[0].count == 1
                    && profile.context_refs.len() == 2
                    && araphor_data::DiscoveryProfileV1::try_from(frozen.as_slice())? == unresolved
                    && data
                        .processor_health(&profile.scope)?
                        .is_some_and(|health| health.consumed_cursor == 1)
                    && !owner.refresh(&stream, now + 3)?
                    && owner.process(now + 4)? == 0
                    && owner.profile(&stream)? == Some(profile.clone()),
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "the live profile, context, progress, or replay count differs",
                }
            );
            let calls = provider.calls.load(Ordering::SeqCst);
            ensure!(
                owner.replay(&profile)?
                    == araphor_data::DiscoveryReplayV1::Available(Box::new(
                        profile.snapshot.clone()
                    ))
                    && owner.replay(&unresolved)?
                        == araphor_data::DiscoveryReplayV1::Available(Box::new(
                            unresolved.snapshot.clone()
                        ))
                    && provider.calls.load(Ordering::SeqCst) == calls,
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "frozen replay changed its snapshot or queried current context",
                }
            );
            (Some(profile), Some(unresolved))
        } else {
            (None, None)
        };
        drop(data);
        drop(connection);
        server.shutdown().await?;
        drop(store);
        let store = reopen_control_store(&root).await?;
        let recovered = Arc::new(
            super::data_store::DataStoreQualification::reopen_data(&root.join("analysis")).await?,
        );
        let page = recovered.read_page(&stream, 1)?;
        ensure!(
            page.records.len() == 1
                && page.records[0].framed_record == wire.framed_records.as_ref()
                && recovered.source_receipt(&stream)? == Some(receipt)
                && store.discovery_context(&joined)? == pin
                && !root.join("evidence/segments-v2").exists()
                && !root.join("discovery").exists()
                && !root.join("discovery-index.sqlite").exists(),
            InvalidInputSnafu {
                path: &self.output,
                reason: "retained evidence or context changed after restart",
            }
        );
        if let Some(profile) = &profile {
            let provider = Arc::new(DelayedContext {
                store,
                available: AtomicBool::new(true),
                calls: AtomicUsize::new(0),
            });
            let owner = araphor_data::DiscoveryOwner::new(
                recovered.clone(),
                provider.clone(),
                profile_config,
            )?;
            ensure!(
                owner.profile(&stream)? == Some(profile.clone())
                    && owner.process(now + 5)? == 0
                    && owner.profile(&stream)? == Some(profile.clone())
                    && owner.replay(profile)?
                        == araphor_data::DiscoveryReplayV1::Available(Box::new(
                            profile.snapshot.clone()
                        ))
                    && provider.calls.load(Ordering::SeqCst) == 0,
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "restart changed the live profile or replay count",
                }
            );
            let unresolved = unresolved
                .as_ref()
                .ok_or("the unresolved profile is absent")?;
            let frozen = recovered
                .read_result(stream.tenant_id, &unresolved.profile_id)?
                .ok_or("the frozen unresolved result is absent after restart")?;
            ensure!(
                araphor_data::DiscoveryProfileV1::try_from(frozen.as_slice())? == *unresolved
                    && owner.replay(unresolved)?
                        == araphor_data::DiscoveryReplayV1::Available(Box::new(
                            unresolved.snapshot.clone()
                        ))
                    && provider.calls.load(Ordering::SeqCst) == 0,
                InvalidInputSnafu {
                    path: &self.output,
                    reason: "restart changed the frozen unresolved revision",
                }
            );
        }
        fs::create_dir(&self.output)?;
        if let Some(profile) = &profile {
            super::write_json(&self.output.join("profile.json"), profile)?;
        }
        if let Some(unresolved) = &unresolved {
            super::write_json(&self.output.join("profile-unresolved.json"), unresolved)?;
        }
        let mut checks = vec![
            "node-wal",
            "mtls-intake",
            "exact-retained-frame",
            "raw-context",
            "data-restart",
            "no-control-raw-writer",
            "no-discovery-copy",
        ];
        if profile.is_some() {
            checks.extend([
                "live-owner-profile",
                "atomic-profile-progress",
                "profile-restart-replay",
                "late-context-auto-refresh",
                "immutable-sealed-revision",
                "frozen-replay-no-provider",
            ]);
        }
        super::write_json(
            &self.output.join("result.json"),
            &serde_json::json!({
                "schema_version": 1,
                "case": match case {
                    RoundtripCase::EvidenceRestart => "evidence-restart",
                    RoundtripCase::ContextRoundtrip => "context-roundtrip",
                    RoundtripCase::ProfileRestart => "profile-restart",
                },
                "result": "PASS", "qualification": "LIGHTWEIGHT",
                "input": "synthetic kernel record", "production_authority": false,
                "physical_action_attempted": false, "physical_profiles_qualified": false,
                "deterministic_profiles_qualified": profile.is_some(),
                "signed_context_resolved": signed_context, "durable_cursor": 1,
                "live_profile_persisted": profile.is_some(),
                "late_context_resolved": profile.is_some(),
                "original_kernel_sequence": context.original_kernel_sequence,
                "decision_context": context,
                "asserted_contracts": checks,
            }),
        )?;
        Ok(())
    }
}

fn fixture_handle<'a>(
    values: impl Iterator<Item = &'a str>,
    selected: &str,
) -> Result<u32, Box<dyn StdError>> {
    Ok(values
        .collect::<BTreeSet<_>>()
        .into_iter()
        .position(|value| value == selected)
        .ok_or("the synthetic kernel handle is absent")? as u32
        + 1)
}

pub(super) fn signed_catalog(
    store: &ControlStore,
    root: &Path,
    boot: EvidenceIdV1,
) -> Result<
    (
        mithril_node::NodeDiscoveryContextCatalog,
        erebor_interceptor_abi::EffectObservationV1,
        mithril_control::WorkloadTargetFactV1,
    ),
    Box<dyn StdError>,
> {
    let fixture = OutagePolicyFixture::new(store.clone());
    let resource = fixture.resource(1)?;
    let mut inventory = fixture.inventory(&resource)?;
    let now = 1_800_000_000_000_000_000;
    let result = fixture
        .owner
        .reconcile(&resource, OUTAGE_NAMESPACE_UID, &inventory, now)?;
    let bundle = result
        .bundles
        .first()
        .ok_or("the policy bundle is absent")?;
    let artifact_path = root.join("signed-profile.json");
    super::write_json(&artifact_path, &bundle.profile_artifact)?;
    let key_path = root.join("policy-public-key");
    fs::write(
        &key_path,
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[7; 32])
                .verifying_key()
                .to_bytes(),
        ),
    )?;
    let artifact = mithril_control::PolicyArtifactOwner::default().load_verified_at(
        &artifact_path,
        &key_path,
        now,
    )?;
    let document = &artifact.policy_document;
    let workload = inventory.remove(0);
    let identity = workload
        .kubernetes
        .as_ref()
        .ok_or("the workload identity is absent")?;
    let assignment = document
        .entry_role_assignments
        .iter()
        .find(|assignment| assignment.admission_execution_rule_id.is_some())
        .ok_or("the application entry is absent")?;
    let cell = artifact
        .compiled_profile
        .compiled_cells
        .iter()
        .find(|cell| {
            cell.key.role_id == assignment.resulting_role_id
                && cell.key.object_selector.starts_with("PATH:")
                && cell.key.operation_id == "OPEN_READ"
                && assignment.entry_kinds.contains(&cell.key.entry_kind)
        })
        .ok_or("the file-read policy cell is absent")?;
    let selector = document
        .path_selectors
        .iter()
        .find(|selector| cell.key.object_selector == format!("PATH:{}", selector.path_selector_id))
        .ok_or("the signed path selector is absent")?;
    let binding = mithril_node::WorkloadBindingConfig {
        binding_id: identity.binding_id.clone(),
        scheduled_binding_authority_id: Some("synthetic-scheduled-authority".into()),
        scheduled_target_digest: Some(workload.workload_binding_generation_digest.clone()),
        execution_set_id: workload.execution_set_id.clone(),
        protected_scope_id: identity.protected_scope_id.clone(),
        workload_selector_id: identity.workload_selector_id.clone(),
        profile_id: artifact.header.profile_id.clone(),
        container_id: workload.container_id.clone(),
        namespace: identity.namespace_name.clone(),
        cluster_uid: workload.cluster_uid.clone(),
        namespace_uid: workload.namespace_uid.clone(),
        controller_uid: workload.controller_uid.clone(),
        service_account_uid: workload.service_account_uid.clone(),
        pod_labels: workload.pod_labels.clone(),
        pod_uid: workload.pod_uid.clone(),
        sandbox_id: "synthetic-sandbox".into(),
        container_name: workload.container_name.clone(),
        image_digest: workload.image_digest.clone(),
        container_kind: mithril_node::ContainerKindV1::Application,
        container_generation: 1,
        root_cgroup_path: None,
        lifecycle_generation: 1,
        active_profile_generation_ref_id: 8,
        initial_role_id: 1,
        external_role_id: 1,
        arm_initial_root: false,
    };
    let object = mithril_node::ExactFileObjectConfig {
        profile_generation_ref_id: 8,
        exact_object_key_id: selector.kernel_handle(),
        object_class_id: selector.object_class_id.clone(),
        mount_namespace_inode: 24,
        mount_id_unique: 21,
        filesystem_device: 25,
        inode: 22,
        inode_generation: 23,
        device: None,
        canonical_component_hex: vec![],
        mount_relative_component_count: 0,
        mount_root_filesystem_device: 25,
        mount_root_inode: 1,
        selected_mount_id_unique: 21,
        mount_snapshot_digest_id: 1,
        mount_topology_generation: 1,
        mount_view_root_pid: 1,
    };
    let operation = mithril_control::CompiledOperationV1::try_from(cell.key.operation_id.as_str())?;
    let raw = erebor_interceptor_abi::EffectObservationV1 {
        binding_id: uuid::Uuid::parse_str(&binding.binding_id)?
            .into_bytes()
            .into(),
        execution_set_id: uuid::Uuid::parse_str(&binding.execution_set_id)?
            .into_bytes()
            .into(),
        authority_domain_id: uuid::Uuid::parse_str(&binding.protected_scope_id)?
            .into_bytes()
            .into(),
        profile_generation_ref_id: 8,
        active_role_id: fixture_handle(
            document.roles.iter().map(|role| role.role_id.as_str()),
            &cell.key.role_id,
        )?,
        process_state_vector_id: fixture_handle(
            document
                .process_state_definitions
                .iter()
                .map(|state| state.process_state_id.as_str()),
            &cell.key.process_state_id,
        )?,
        admitted_entry_rule_id: fixture_handle(
            document
                .entry_role_assignments
                .iter()
                .map(|entry| entry.assignment_id.as_str()),
            &assignment.assignment_id,
        )?,
        effect_family: erebor_interceptor_abi::KernelEffectFamilyV1::from(cell.key.effect_family)
            as u16,
        operation: operation.kernel_id as u16,
        file_object: erebor_interceptor_abi::ExactFileObjectKeyV1 {
            profile_generation_ref_id: 8,
            mount_id_unique: object.mount_id_unique,
            inode: object.inode,
            inode_generation: object.inode_generation,
            mount_namespace_inode: object.mount_namespace_inode,
            filesystem_device: object.filesystem_device,
        },
        exact_object_key_id: object.exact_object_key_id,
        composite_atom_id: u64::from(fixture_handle(
            document
                .protected_universe
                .object_class_ids
                .iter()
                .map(String::as_str),
            &selector.object_class_id,
        )?),
        ..Default::default()
    };
    let mut catalog = mithril_node::NodeDiscoveryContextCatalog::default();
    catalog.add_verified_binding(&artifact, &binding, &[object], boot);
    Ok((catalog, raw, workload))
}

#[cfg(test)]
mod tests {
    #[tokio::test]
    async fn discovery_live_profile_restart() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        let runner = super::DiscoveryQualificationRunner::new(output.clone());
        runner.profile_restart().await?;
        let before = std::fs::read(output.join("profile.json"))?;
        assert!(runner.profile_restart().await.is_err());
        assert_eq!(std::fs::read(output.join("profile.json"))?, before);
        Ok(())
    }

    #[tokio::test]
    async fn discovery_context_mtls_roundtrip() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        super::DiscoveryQualificationRunner::new(directory.path().join("proof"))
            .context_roundtrip()
            .await?;
        Ok(())
    }

    #[tokio::test]
    async fn evidence_restart_retains_context() -> Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let output = directory.path().join("proof");
        let runner = super::DiscoveryQualificationRunner::new(output.clone());
        runner.evidence_restart().await?;
        let before = std::fs::read(output.join("result.json"))?;
        assert!(runner.evidence_restart().await.is_err());
        assert_eq!(std::fs::read(output.join("result.json"))?, before);
        Ok(())
    }
}
