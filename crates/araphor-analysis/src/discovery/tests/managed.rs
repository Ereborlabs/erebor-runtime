use std::time::{SystemTime, UNIX_EPOCH};

use araphor_data::{AnalysisReadControl, ManagedDestination, ManagedRequest};

use super::*;

mod retention;

#[tokio::test]
async fn profile_conversion_failure_finishes() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let mut image = Package::discovery_bundle()?;
    image.root.revision = "conversion".into();
    let artifact = image.artifacts.first_mut().ok_or("profile artifact")?;
    artifact.descriptor.revision = "conversion".into();
    let PackageImplementationV1::Sql { program, .. } = artifact
        .implementations
        .first_mut()
        .ok_or("profile implementation")?
    else {
        return Err("profile implementation is not SQL".into());
    };
    let sql = program.outputs.get_mut("snapshot").ok_or("profile SQL")?;
    *sql = format!(
        "SELECT * REPLACE (CASE WHEN consumed_cursor = 1 THEN CAST(2 AS BIGINT UNSIGNED) ELSE expected_cursor END AS expected_cursor) FROM ({sql})"
    );
    let instance = fixture.managed_image("conversion", image).await?;
    let control = AnalysisReadControl::default();
    let input = Fixture::request("invalid-progress")?;
    let failure = instance
        .run(input.clone(), &control)
        .await
        .err()
        .ok_or("invalid Profile progress published")?;
    assert!(
        format!("{failure:?}").contains("profile captured progress"),
        "{failure:?}"
    );
    let saved = fixture
        .store
        .managed_attempt(fixture.source.tenant_id, "conversion", &input.id, &control)?
        .ok_or("Profile conversion attempt")?;
    assert_eq!(
        saved.terminal().ok_or("Profile conversion terminal")?.exit,
        araphor_data::ManagedExit::Failed(Code::Conflict)
    );
    assert!(saved.receipt().is_none());
    assert!(fixture.profile()?.is_none());
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("Profile processor")?
            .consumed_cursor,
        0
    );
    let current = fixture
        .store
        .managed_instance(fixture.source.tenant_id, "conversion", &control)?
        .ok_or("Profile instance")?;
    assert_eq!(current.progress, 0);
    assert!(fixture
        .store
        .managed_history(&current.grant.selection, "conversion", &control)?
        .is_empty());
    assert!(fixture
        .store
        .managed_selected(fixture.source.tenant_id, "conversion", &input.id, &control)?
        .is_none());
    let before = fixture.store.meta()?;
    assert!(matches!(
        instance.run(input, &control).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Conflict,
                field: "managed attempt terminated",
                ..
            }
        })
    ));
    assert_eq!(fixture.store.meta()?, before);
    fixture.append(2)?;
    let receipt = instance
        .run(Fixture::request("recovered")?, &control)
        .await?;
    assert_eq!(receipt.results.len(), 1);
    assert_eq!(
        fixture
            .profile()?
            .ok_or("recovered Profile")?
            .snapshot
            .accepted_records,
        2
    );
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("recovered Profile processor")?
            .consumed_cursor,
        2
    );
    drop((saved, instance));
    fixture.released()?;
    Ok(())
}

impl Fixture {
    async fn managed(&self, id: &str) -> TestResult<Arc<crate::Instance>> {
        self.managed_image(id, Package::discovery_bundle()?).await
    }

    pub(super) async fn managed_image(
        &self,
        id: &str,
        image: PackageBundleV1,
    ) -> TestResult<Arc<crate::Instance>> {
        self.managed_package(id, image, "live", "snapshot", true)
            .await
    }

    pub(super) async fn managed_package(
        &self,
        id: &str,
        image: PackageBundleV1,
        export: &str,
        output: &str,
        register: bool,
    ) -> TestResult<Arc<crate::Instance>> {
        self.managed_with_selection(
            id,
            image,
            export,
            output,
            register,
            AnalysisSelectionV1::new(self.source.tenant_id, vec![self.source.clone()]),
        )
        .await
    }

    async fn managed_with_selection(
        &self,
        id: &str,
        image: PackageBundleV1,
        export: &str,
        output: &str,
        register: bool,
        selection: AnalysisSelectionV1,
    ) -> TestResult<Arc<crate::Instance>> {
        let authority: Arc<dyn PackageAuthorization> = Arc::new(Authority(watch::channel(0).0));
        let grant = PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection,
            expires_utc_ns: None,
            authorization_id: None,
        };
        let image = Arc::new(PackageBundle::try_from(image)?);
        self.store
            .install_package_image(self.source.tenant_id, &image, || Ok(()))?;
        let package = Package::new(
            Arc::clone(&self.query),
            Arc::clone(&authority),
            grant.clone(),
            image,
            export,
            output,
        )?;
        let (prepared, call) = package.prepared().await?;
        if register {
            self.store
                .ensure_optional_processor_guarded(&self.scope(), || Ok(()))?;
        }
        let session =
            self.query
                .session(grant.selection.clone(), &AnalysisReadControl::default(), 0)?;
        let host = crate::InstanceHost::new(Arc::clone(&self.query), authority);
        Ok(host
            .admit_prepared(
                session,
                grant,
                id.into(),
                prepared.clone(),
                ManagedDestination::DiscoveryProfile {
                    source: self.source.clone(),
                    call: call.id(),
                    output: call.output().into(),
                },
            )
            .await?)
    }

    fn catalog_facts(&mut self) -> TestResult<Vec<araphor_data::AnalysisContextVersionV1>> {
        use araphor_data::{
            AnalysisContextKeyV1, AnalysisContextVersionV1, CompiledPolicyContextV1,
            ContainerKindV1, ContextSensitivityV1, EvidenceDecisionCatalogV1,
            EvidenceDecisionContext, EvidenceExactFileObject, EvidenceFileObjectV1,
            KubernetesWorkloadIdentityV1, TargetContextV1, WorkloadTargetFactV1,
        };
        let manifest = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let binding = manifest.contexts.first().ok_or("catalog binding")?;
        let key = binding.static_key.clone();
        let exact = EvidenceExactFileObject {
            profile_generation_ref_id: 8,
            mount_id_unique: 21,
            inode: 22,
            inode_generation: 23,
            mount_namespace_inode: 24,
            filesystem_device: 25,
        };
        let catalog = EvidenceDecisionCatalogV1 {
            runtime_binding: None,
            node_boot_id: self.source.node_boot_id.into(),
            profile_id: binding.policy_revision.profile_id.clone(),
            profile_version: binding.policy_revision.profile_version,
            policy_document_digest: binding.configuration_digest.clone(),
            profile_generation_ref_id: 8,
            binding_id: binding.binding_id.into(),
            role_id: binding.role_id,
            state_id: binding.state_id,
            entry_rule_id: binding.entry_rule_id,
            exact_file_object: exact,
            exact_object_key_id: 26,
            composite_atom_id: 23,
            static_key: (&key).try_into()?,
            digest: araphor_data::DiscoveryDigestV1([0; 32]),
        };
        for record in self.records.values_mut() {
            let mut wire = record.decode()?;
            wire.profile_generation_ref_id = Some(8);
            wire.policy_rule_id = 23;
            wire.effect_family = key.effect_family.into();
            wire.operation = key.operation.into();
            wire.operation_argument =
                (key.operation_argument != 0).then_some(key.operation_argument);
            wire.execution_set_id = uuid::Uuid::parse_str(&key.execution_set_id)?
                .as_bytes()
                .to_vec()
                .into();
            wire.authority_domain_id = uuid::Uuid::parse_str(&key.protected_scope_id)?
                .as_bytes()
                .to_vec()
                .into();
            wire.exact_object_id = EvidenceFileObjectV1::from(&exact)
                .observation_id(26)
                .to_be_bytes()
                .to_vec()
                .into();
            wire.decision_context = Some(EvidenceDecisionContext {
                schema_version: 1,
                original_kernel_sequence: record
                    .original_kernel_sequence
                    .ok_or("catalog kernel sequence")?,
                profile_generation_ref_id: 8,
                process_instance_id: binding.process_instance_id.to_vec(),
                entry_instance_id: binding.entry_instance_id.to_vec(),
                binding_id: binding.binding_id.to_vec(),
                role_id: binding.role_id,
                state_id: binding.state_id,
                entry_rule_id: binding.entry_rule_id,
                exact_file_object: Some(exact),
                exact_object_key_id: 26,
                composite_atom_id: 23,
                catalog_json: catalog.clone().seal()?,
                catalog_state: "AVAILABLE".into(),
            });
            *record = DiscoveryRecordV1::try_from((
                record.id.clone(),
                Vec::<u8>::try_from(&wire)?.as_slice(),
            ))?;
        }
        let proof = CompiledPolicyContextV1 {
            source_revision_id: binding.policy_revision.source_revision_id.clone(),
            signed_profile_digest: binding.policy_revision.signed_profile_digest.clone(),
            profile_id: catalog.profile_id.clone(),
            profile_version: catalog.profile_version,
            policy_document_digest: catalog.policy_document_digest.clone(),
            execution_set_ids: vec![key.execution_set_id.clone()],
            compiled_keys: vec![key.clone()],
        };
        let target = TargetContextV1 {
            workload: WorkloadTargetFactV1 {
                node_id: self.source.node_id.clone(),
                workload_binding_generation_digest: binding.subject_revision.clone(),
                execution_set_id: key.execution_set_id.clone(),
                cluster_uid: "cluster".into(),
                namespace_uid: "namespace".into(),
                controller_uid: "controller".into(),
                service_account_uid: "account".into(),
                pod_uid: "pod".into(),
                container_id: "container".into(),
                container_name: "worker".into(),
                container_kind: ContainerKindV1::Application,
                image_digest: binding.image_digest.clone(),
                pod_labels: BTreeMap::new(),
                kubernetes: Some(KubernetesWorkloadIdentityV1 {
                    namespace_name: "default".into(),
                    pod_name: "worker".into(),
                    profile_id: proof.profile_id.clone(),
                    policy_source_revision_id: proof.source_revision_id.clone(),
                    binding_id: uuid::Uuid::from_bytes(binding.binding_id).to_string(),
                    protected_scope_id: key.protected_scope_id,
                    workload_selector_id: key.workload_selector_id,
                    kubernetes_node_name: self.source.node_id.clone(),
                    kubernetes_node_uid: "node".into(),
                    node_boot_id: uuid::Uuid::from_bytes(self.source.node_boot_id).to_string(),
                    label_epoch: self.source.label_epoch,
                }),
            },
            workload_digest_valid: true,
            policy_source_revision_id: proof.source_revision_id.clone(),
            target_snapshot_digest: "a".repeat(64),
            signed_profile_digest: proof.signed_profile_digest.clone(),
        };
        [
            ("mithril-control/target", serde_json::to_vec(&target)?),
            ("mithril-control/compiled-policy", proof.encode()?),
        ]
        .into_iter()
        .map(|(owner, body)| {
            Ok(AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: self.source.tenant_id,
                    owner_id: owner.into(),
                    entity_key: proof.source_revision_id.as_bytes().to_vec(),
                    lifetime_key: proof.signed_profile_digest.as_bytes().to_vec(),
                    owner_revision: 1,
                },
                valid_from_utc_ns: None,
                valid_until_utc_ns: None,
                sensitivity: ContextSensitivityV1::Tenant,
                body,
            })
        })
        .collect()
    }

    pub(super) fn request(id: &str) -> TestResult<ManagedRequest> {
        let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
        Ok(ManagedRequest {
            id: id.into(),
            time_utc_ns: now,
            seed: None,
            rebuild: false,
            witness_expiry: now
                .checked_add(7 * 24 * 60 * 60 * 1_000_000_000)
                .ok_or("witness deadline")?,
            frontier: None,
        })
    }
}

#[tokio::test]
async fn managed_window_frontier() -> TestResult {
    let bin = "date_bin(INTERVAL '2 seconds', CURRENT_TIMESTAMP, TIMESTAMP '1970-01-01')";
    assert_managed_frontier(
        &format!("received_at >= {bin} AND received_at < {bin} + INTERVAL '2 seconds'"),
        true,
    )
    .await
}

#[tokio::test]
async fn managed_filtered_frontier() -> TestResult {
    assert_managed_frontier("source_cursor = 1", false).await
}

async fn assert_managed_frontier(predicate: &str, close: bool) -> TestResult {
    let fixture = Fixture::new(Limits {
        global_evaluations: Some(1),
        tenant_evaluations: Some(1),
        ..Default::default()
    })?;
    let mut request = Fixture::request("old-window")?;
    let start = request.time_utc_ns / 2_000_000_000 * 2_000_000_000 - 20_000_000_000;
    request.time_utc_ns = start + 1_000_000_000;
    request.witness_expiry = request.time_utc_ns + 7 * 24 * 60 * 60 * 1_000_000_000;
    fixture.append_at(1, start + 100_000_000)?;
    fixture.append_at(2, start + 2_100_000_000)?;
    let mut image = Package::discovery_bundle()?;
    image.root.revision = "window".into();
    image.artifacts[0].descriptor.revision = "window".into();
    let input = image.artifacts[0].descriptor.exports[0]
        .inputs
        .iter_mut()
        .find(|input| input.port.name == "events")
        .ok_or("event input")?;
    let columns = input
        .port
        .schema
        .fields()
        .iter()
        .map(|field| field.name().as_str())
        .collect::<Vec<_>>()
        .join(", ");
    input.source =
        sdk::InputSource::Query(format!("SELECT {columns} FROM events WHERE {predicate}"));
    let instance = fixture.managed_image("window-frontier", image).await?;
    let receipt = instance
        .run(request, &AnalysisReadControl::default())
        .await?;
    let profile = fixture.profile()?.ok_or("window profile")?;
    assert_eq!(profile.snapshot.accepted_records, 1);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("window processor")?
            .consumed_cursor,
        1
    );
    assert_eq!(receipt.results.len(), 1);
    assert_eq!(
        fixture
            .store
            .source_receipt(&fixture.source)?
            .ok_or("source receipt")?
            .contiguous_cursor,
        2
    );
    if close {
        assert!(!profile.sealed);
        let original = fixture
            .store
            .read_result(fixture.source.tenant_id, &profile.profile_id)?
            .ok_or("open window body")?;
        let source = fixture.store.source_receipt(&fixture.source)?;
        let authority: Arc<dyn PackageAuthorization> = Arc::new(Authority(watch::channel(0).0));
        let host = crate::InstanceHost::new(Arc::clone(&fixture.query), authority);
        let control = AnalysisReadControl::default();
        let running = host
            .start(
                Arc::clone(&instance),
                instance.admitted().lifecycle,
                &control,
            )
            .await?;
        let held = fixture.query.reserve_evaluation(fixture.source.tenant_id)?;
        let progress = fixture.store.processor_health(&fixture.scope())?;
        let mut waiting = running.subscribe(
            Arc::new(AnalysisReadControl::default()),
            Fixture::request("window-witness")?.witness_expiry,
            running.admitted().lifecycle,
        )?;
        assert!(futures_util::poll!(waiting.next()).is_pending());
        assert_eq!(fixture.profile()?, Some(profile.clone()));
        assert_eq!(fixture.store.processor_health(&fixture.scope())?, progress);
        tokio::time::timeout(Duration::from_secs(30), waiting.cancel_and_join(&control)).await??;
        assert_eq!(fixture.profile()?, Some(profile.clone()));
        assert_eq!(fixture.store.processor_health(&fixture.scope())?, progress);
        drop(held);
        let mut stream = running.subscribe(
            Arc::new(AnalysisReadControl::default()),
            Fixture::request("window-close")?.witness_expiry,
            running.admitted().lifecycle,
        )?;
        tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("window close subscription ended")??;
        let sealed = fixture.profile()?.ok_or("closed window profile")?;
        assert!(sealed.sealed);
        assert_eq!(sealed.interval_id, profile.interval_id);
        assert_eq!(sealed.revision, profile.revision + 1);
        assert_eq!(sealed.snapshot, profile.snapshot);
        assert_eq!(sealed.context_refs, profile.context_refs);
        assert_eq!(sealed.created_utc_ns, profile.created_utc_ns);
        assert!(sealed.updated_utc_ns >= start + 2_000_000_000);
        assert_eq!(sealed.input_bytes, profile.input_bytes);
        assert_eq!(sealed.incomplete, profile.incomplete);
        assert_eq!(sealed.gaps, profile.gaps);
        assert_eq!(fixture.store.source_receipt(&fixture.source)?, source);
        assert_eq!(
            fixture
                .store
                .processor_health(&fixture.scope())?
                .ok_or("closed window progress")?
                .consumed_cursor,
            1
        );
        assert_eq!(
            fixture
                .store
                .read_result(fixture.source.tenant_id, &profile.profile_id)?,
            Some(original)
        );
        stream.cancel_and_join(&control).await?;
        drop((running, host));
    }
    drop(instance);
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn managed_profile_versions() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let instance = fixture.managed("profile-versions").await?;
    assert!(!instance.admitted().running);
    assert!(fixture.profile()?.is_none());
    let first = instance
        .run(Fixture::request("first")?, &AnalysisReadControl::default())
        .await?;
    let original = fixture.profile()?.ok_or("first profile")?;
    assert_eq!(original.snapshot.accepted_records, 1);
    assert_eq!(original.revision, 1);
    assert_eq!(first.results.len(), 1);
    let original_ref = fixture.store.package_result_refs(
        fixture.source.tenant_id,
        std::slice::from_ref(&original.profile_id),
    )?;
    assert_eq!(original_ref[0].commit_revision, first.commit_revision);
    let (original_witnesses, _) = fixture.store.package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&original.profile_id),
    )?;
    assert_eq!(
        original_witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [1]
    );
    fixture.append(2)?;
    let mut mutable = original.clone();
    mutable.revision += 1;
    mutable.updated_utc_ns += 1;
    let rewrite = araphor_data::AnalysisResultCommitV1 {
        scope: original.scope.clone(),
        expected_cursor: 1,
        consumed_cursor: 1,
        coverage_revision: original.coverage_revision,
        context_revision: original
            .context_refs
            .iter()
            .map(|reference| reference.commit_revision)
            .max()
            .unwrap_or(0),
        result_id: original.profile_id.clone(),
        body: Vec::new(),
        created_utc_ns: mutable.updated_utc_ns,
        witnesses: original_witnesses.clone(),
        context_refs: original.context_refs.clone(),
    };
    let before = fixture.store.meta()?;
    assert!(matches!(
        fixture.store.commit_working_profile(
            rewrite,
            araphor_data::analysis::PreparedProfile::new(mutable)?,
            Some(original_ref[0].commit_revision),
        ),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(fixture.profile()?, Some(original.clone()));
    let second = instance
        .run(Fixture::request("second")?, &AnalysisReadControl::default())
        .await?;
    let current = fixture.profile()?.ok_or("second profile")?;
    assert_ne!(original.profile_id, current.profile_id);
    assert_eq!(original.interval_id, current.interval_id);
    assert_eq!(current.revision, original.revision + 1);
    assert_eq!(current.snapshot.accepted_records, 2);
    let (current_witnesses, _) = fixture.store.package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&current.profile_id),
    )?;
    assert_eq!(
        current_witnesses
            .iter()
            .map(|witness| witness.cursor)
            .collect::<Vec<_>>(),
        [1, 2]
    );
    assert!(second.commit_revision > first.commit_revision);
    let retained = fixture
        .store
        .read_result(fixture.source.tenant_id, &original.profile_id)?
        .ok_or("original profile body")?;
    assert_eq!(DiscoveryProfileV1::try_from(retained.as_slice())?, original);
    let third = instance
        .run(
            Fixture::request("unchanged")?,
            &AnalysisReadControl::default(),
        )
        .await?;
    assert!(third.commit_revision > second.commit_revision);
    assert_eq!(fixture.profile()?, Some(current));
    assert_eq!(
        fixture
            .store
            .package_evidence(
                fixture.source.tenant_id,
                std::slice::from_ref(&original.profile_id)
            )?
            .0,
        original_witnesses
    );
    drop(instance);
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn code_cut_keeps_evidence() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let initial = fixture.managed("code-old").await?;
    initial
        .run(Fixture::request("first")?, &AnalysisReadControl::default())
        .await?;
    let previous = fixture.profile()?.ok_or("original profile")?;
    let original_evidence = fixture.store.package_evidence(
        fixture.source.tenant_id,
        std::slice::from_ref(&previous.profile_id),
    )?;
    fixture.append(2)?;
    let mut image = Package::discovery_bundle()?;
    image.root.revision = "next".into();
    image.artifacts[0].descriptor.revision = "next".into();
    let replacement = fixture.managed_image("code-new", image).await?;
    replacement
        .run(Fixture::request("cut")?, &AnalysisReadControl::default())
        .await?;
    let closed = fixture.profile()?.ok_or("closed profile")?;
    assert!(closed.sealed);
    assert_ne!(closed.profile_id, previous.profile_id);
    assert_eq!(closed.interval_id, previous.interval_id);
    assert_eq!(closed.revision, previous.revision + 1);
    assert_eq!(closed.snapshot, previous.snapshot);
    assert_eq!(closed.context_refs, previous.context_refs);
    assert_eq!(closed.coverage_revision, previous.coverage_revision);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("processor")?
            .consumed_cursor,
        1
    );
    assert_eq!(
        fixture.store.package_evidence(
            fixture.source.tenant_id,
            std::slice::from_ref(&closed.profile_id)
        )?,
        original_evidence
    );
    replacement
        .run(
            Fixture::request("new-interval")?,
            &AnalysisReadControl::default(),
        )
        .await?;
    let next = fixture.profile()?.ok_or("new interval")?;
    assert_ne!(next.interval_id, closed.interval_id);
    assert_eq!(next.revision, 1);
    assert_eq!(next.snapshot.accepted_records, 1);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("processor")?
            .consumed_cursor,
        2
    );
    drop((initial, replacement));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn sealed_repair_keeps_head() -> TestResult {
    let mut fixture = Fixture::new(Limits::default())?;
    let facts = fixture.catalog_facts()?;
    let mut newer = facts[1].clone();
    newer.key.owner_revision += 1;
    let mut selection =
        AnalysisSelectionV1::new(fixture.source.tenant_id, vec![fixture.source.clone()]);
    selection.contexts = araphor_data::Selection::Exact(
        facts
            .iter()
            .map(|fact| fact.key.clone())
            .chain(std::iter::once(newer.key.clone()))
            .collect(),
    );
    let control = AnalysisReadControl::default();
    fixture.append(1)?;
    let original = fixture
        .managed_with_selection(
            "repair-original",
            Package::discovery_bundle()?,
            "live",
            "snapshot",
            true,
            selection.clone(),
        )
        .await?;
    original
        .run(Fixture::request("original")?, &control)
        .await?;
    let open = fixture.profile()?.ok_or("original open profile")?;
    assert_eq!(
        (
            open.snapshot.accepted_records,
            open.snapshot.unresolved_records
        ),
        (1, 1)
    );
    let mut image = Package::discovery_bundle()?;
    image.root.revision = "repair-next".into();
    image.artifacts[0].descriptor.revision = "repair-next".into();
    let next = fixture
        .managed_with_selection("repair-next", image, "live", "snapshot", true, selection)
        .await?;
    next.run(Fixture::request("close-original")?, &control)
        .await?;
    let sealed = fixture.profile()?.ok_or("original sealed profile")?;
    assert!(sealed.sealed);
    let old_body = fixture
        .store
        .read_result(fixture.source.tenant_id, &sealed.profile_id)?
        .ok_or("saved sealed body")?;
    let producer = fixture.store.discovery_producer(
        &original.admitted().grant.selection,
        &sealed,
        &control,
    )?;
    assert_eq!(producer.spec.id, "repair-original");
    fixture.append(2)?;
    next.run(Fixture::request("next-interval")?, &control)
        .await?;
    let next_open = fixture.profile()?.ok_or("next open profile")?;
    assert!(!next_open.sealed);
    assert!(open
        .context_refs
        .iter()
        .all(|reference| next_open.context_refs.contains(reference)));
    assert_eq!(
        fixture
            .store
            .discovery_producer(&next.admitted().grant.selection, &next_open, &control)?
            .spec,
        next.admitted().spec
    );
    original
        .run(Fixture::request("close-next")?, &control)
        .await?;
    let head = fixture
        .store
        .processor_result(&fixture.scope())?
        .ok_or("current sealed head")?;
    let current = DiscoveryProfileV1::try_from(head.body.as_slice())?;
    assert!(current.sealed);
    assert_ne!(current.interval_id, sealed.interval_id);
    let progress = fixture
        .store
        .processor_health(&fixture.scope())?
        .ok_or("current source progress")?;
    assert_eq!(progress.consumed_cursor, 2);
    let refs = fixture.store.commit_contexts(&facts)?;
    let revision = refs
        .iter()
        .map(|reference| reference.commit_revision)
        .max()
        .ok_or("fact revision")?;
    let pending = fixture
        .store
        .profile_notices(&fixture.scope(), revision, 0)?;
    assert_eq!(pending.len(), 2);
    fixture.store.set_commit_hook(
        araphor_data::AnalysisCommitStage::BeforeResultCommit,
        || Err(Code::Conflict.error("historical publication guard")),
    )?;
    let failed = original
        .run(Fixture::request("failed-repair")?, &control)
        .await
        .err()
        .ok_or("historical publication guard was ignored")?;
    assert!(
        format!("{failed:?}").contains("historical publication guard"),
        "{failed:?}"
    );
    assert_eq!(
        fixture.store.processor_result(&fixture.scope())?,
        Some(head.clone())
    );
    assert_eq!(
        fixture.store.processor_health(&fixture.scope())?,
        Some(araphor_data::ProcessorHealthV1 {
            read_revision: fixture.store.meta()?.commit_revision,
            ..progress
        })
    );
    assert_eq!(
        fixture
            .store
            .profile_notices(&fixture.scope(), revision, 0)?,
        pending
    );
    let revision = fixture.store.commit_context(&newer)?;
    let authority: Arc<dyn PackageAuthorization> = Arc::new(Authority(watch::channel(0).0));
    let host = crate::InstanceHost::new(Arc::clone(&fixture.query), authority);
    let running = host
        .start(
            Arc::clone(&original),
            original.admitted().lifecycle,
            &control,
        )
        .await?;
    let mut stream = running.subscribe(
        Arc::new(AnalysisReadControl::default()),
        Fixture::request("witness")?.witness_expiry,
        running.admitted().lifecycle,
    )?;
    for step in 0..2 {
        let receipt =
            tokio::time::timeout(Duration::from_secs(90), stream.next())
                .await
                .map_err(|error| {
                    format!(
                    "Historical repair {step}: {error}; notices={:?}; status={:?}; history={:?}",
                    fixture.store.profile_notices(&fixture.scope(), revision, 0),
                    fixture.store.managed_status(
                        &running.admitted().grant.selection,
                        &running.admitted().spec.id,
                        &control,
                    ).map(|status| (status.readiness, status.instance.progress)),
                    fixture
                        .store
                        .managed_history(
                            &running.admitted().grant.selection,
                            &running.admitted().spec.id,
                            &control,
                        )
                        .map(|history| (
                            history.len(),
                            history.last().map(|receipt| receipt.commit_revision)
                        )),
                )
                })?
                .ok_or("historical repair subscription ended")??;
        if step == 0 {
            assert!(receipt
                .frontier
                .as_ref()
                .is_some_and(|frontier| frontier.pending));
            let result = receipt
                .results
                .values()
                .next()
                .ok_or("repair call receipt")?;
            let evaluation = fixture.store.managed_evaluation(
                running.admitted(),
                &result.result_id,
                &control,
            )?;
            for name in ["targets", "compiled_policies"] {
                let input = evaluation
                    .inputs
                    .iter()
                    .find(|input| input.data.name == name)
                    .ok_or("repair facts input")?;
                assert!(
                    input.data.batches.iter().any(|batch| batch.num_rows() > 0),
                    "{name}"
                );
            }
            let work = evaluation
                .inputs
                .iter()
                .find(|input| input.data.name == "discovery_state")
                .and_then(|input| input.data.batches.first())
                .ok_or("repair work input")?;
            let facts = work
                .column_by_name("required_facts")
                .and_then(|column| column.as_any().downcast_ref::<UInt64Array>())
                .ok_or("repair facts revision")?;
            assert_eq!(facts.values().as_ref(), &[revision]);
            stream.cancel_and_join(&control).await?;
            stream = running.subscribe(
                Arc::new(AnalysisReadControl::default()),
                Fixture::request("witness")?.witness_expiry,
                running.admitted().lifecycle,
            )?;
        }
    }
    stream.cancel_and_join(&control).await?;
    assert_eq!(
        fixture.store.processor_result(&fixture.scope())?,
        Some(head)
    );
    assert_eq!(
        fixture.store.processor_health(&fixture.scope())?,
        Some(araphor_data::ProcessorHealthV1 {
            read_revision: fixture.store.meta()?.commit_revision,
            ..progress
        })
    );
    assert_eq!(
        fixture
            .store
            .read_result(fixture.source.tenant_id, &sealed.profile_id)?,
        Some(old_body)
    );
    assert!(fixture
        .store
        .profile_notices(&fixture.scope(), revision, 0)?
        .is_empty());
    let profiles = fixture
        .store
        .profile_notices(&fixture.scope(), u64::MAX, u64::MAX)?;
    let mut repaired = None;
    for (id, commit) in profiles {
        let body = fixture
            .store
            .read_result(fixture.source.tenant_id, &id)?
            .ok_or("latest profile body")?;
        let profile = DiscoveryProfileV1::try_from(body.as_slice())?;
        if profile.interval_id == sealed.interval_id {
            repaired = Some((profile, commit));
        }
    }
    let (repaired, commit) = repaired.ok_or("repaired sealed interval")?;
    assert_ne!(repaired.profile_id, sealed.profile_id);
    assert!(repaired.sealed);
    assert_eq!(repaired.revision, sealed.revision + 1);
    assert_eq!(repaired.created_utc_ns, sealed.created_utc_ns);
    assert_eq!(
        (
            repaired.snapshot.accepted_records,
            repaired.snapshot.included_records,
            repaired.snapshot.unresolved_records
        ),
        (1, 1, 0)
    );
    assert_eq!(repaired.input_bytes, sealed.input_bytes);
    assert!(sealed
        .context_refs
        .iter()
        .all(|reference| repaired.context_refs.contains(reference)));
    let replacement = fixture.store.discovery_producer(
        &running.admitted().grant.selection,
        &repaired,
        &control,
    )?;
    assert_eq!(replacement.spec, producer.spec);
    assert!(replacement.result.commit_revision > producer.result.commit_revision);
    assert_eq!(
        fixture.store.package_result_refs(
            fixture.source.tenant_id,
            std::slice::from_ref(&repaired.profile_id)
        )?[0]
            .commit_revision,
        commit
    );
    let evidence = fixture
        .store
        .package_evidence(
            fixture.source.tenant_id,
            std::slice::from_ref(&repaired.profile_id),
        )?
        .0;
    assert!(evidence.iter().any(|witness| witness.cursor == 1));
    let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
    assert_eq!(
        owner.replay(&repaired, &control).await?,
        araphor_data::DiscoveryReplayV1::Available(Box::new(repaired.snapshot.clone()))
    );
    drop((owner, running, host, original, next));
    fixture.released()?;
    Ok(())
}
