use super::*;
use crate::ControlContextOwner;
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadControl, AnalysisReadModeV1, AnalysisSelectionV1,
    AnalysisStore, AnalysisTableRead, AnalysisTableRequests,
};
use arrow_array::{Array, BinaryArray, StringArray, UInt64Array};
use std::sync::Arc;

mod runtime;

type TestValue<T> = std::result::Result<T, Box<dyn std::error::Error>>;

fn capture(
    data: &AnalysisStore,
    tenant: [u8; 16],
) -> TestValue<(u64, Vec<AnalysisContextVersionV1>)> {
    let fields = AnalysisStore::table_schemas()["context_versions"]
        .fields()
        .len();
    let requests =
        AnalysisTableRequests::from([("context_versions".into(), Some((0..fields).collect()))]);
    let page = data.read_tables(
        &AnalysisSelectionV1::tenant(tenant),
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            inputs: None,
            mode: AnalysisReadModeV1::Complete,
            now: 1,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let mut contexts = Vec::new();
    for batch in page.tables.get("context_versions").into_iter().flatten() {
        let binary = |name: &str| -> TestValue<&BinaryArray> {
            batch
                .column_by_name(name)
                .and_then(|column| column.as_any().downcast_ref())
                .ok_or_else(|| format!("missing {name}").into())
        };
        let text = |name: &str| -> TestValue<&StringArray> {
            batch
                .column_by_name(name)
                .and_then(|column| column.as_any().downcast_ref())
                .ok_or_else(|| format!("missing {name}").into())
        };
        let number = |name: &str| -> TestValue<&UInt64Array> {
            batch
                .column_by_name(name)
                .and_then(|column| column.as_any().downcast_ref())
                .ok_or_else(|| format!("missing {name}").into())
        };
        for row in 0..batch.num_rows() {
            contexts.push(AnalysisContextVersionV1 {
                key: AnalysisContextKeyV1 {
                    tenant_id: binary("tenant_id")?.value(row).try_into()?,
                    owner_id: text("owner_id")?.value(row).into(),
                    entity_key: binary("entity_key")?.value(row).into(),
                    lifetime_key: binary("lifetime_key")?.value(row).into(),
                    owner_revision: number("owner_revision")?.value(row),
                },
                valid_from_utc_ns: (!number("valid_from_utc_ns")?.is_null(row))
                    .then(|| number("valid_from_utc_ns").map(|values| values.value(row)))
                    .transpose()?,
                valid_until_utc_ns: (!number("valid_until_utc_ns")?.is_null(row))
                    .then(|| number("valid_until_utc_ns").map(|values| values.value(row)))
                    .transpose()?,
                sensitivity: ContextSensitivityV1::try_from(text("sensitivity")?.value(row))
                    .map_err(|_| "invalid sensitivity")?,
                body: binary("body")?.value(row).into(),
            });
        }
    }
    Ok((page.extraction.meta.commit_revision, contexts))
}

pub(super) fn owner(
    store: &ControlStore,
    data: Arc<AnalysisStore>,
    tenant: [u8; 16],
) -> Result<ControlContextOwner> {
    ControlContextOwner::new(
        store.clone(),
        data,
        &[crate::AllowedNodeIdentity {
            node_id: "node-a".into(),
            certificate_sha256: "a".repeat(64),
            tenant_id: uuid::Uuid::from_bytes(tenant).to_string(),
        }],
    )
}

pub(super) fn facts(
    copy: &mut ControlContextOwner,
    data: &AnalysisStore,
    record: &araphor_data::DiscoveryRecordV1,
) -> TestValue<Vec<AnalysisContextVersionV1>> {
    copy.reconcile()?;
    Ok(GraphContext::new(&capture(data, record.id.stream.tenant_id)?.1)?.facts(record)?)
}

#[test]
fn retained_graph_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let control_path = directory.path().join("control");
    let data_path = directory.path().join("data");
    let (store, record, bundle, mut rollout) = fixture(&control_path)?;
    let tenant = record.id.stream.tenant_id;
    let data = Arc::new(AnalysisStore::open(&data_path)?);
    let mut copy = owner(&store, Arc::clone(&data), tenant)?;
    assert_eq!(copy.reconcile()?, 5);
    let before = data.meta()?;
    let mut changes = store.subscribe_context()?;
    let mut data_changes = data.subscribe_revision();
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
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(7),
        '1',
    )?;
    assert!(changes.has_changed()?);
    assert!(!data_changes.has_changed()?);
    assert_eq!(copy.reconcile()?, 4);
    assert_eq!(data.meta()?.commit_revision, before.commit_revision + 1);
    changes.borrow_and_update();
    data_changes.borrow_and_update();
    let (_, staged) = capture(&data, tenant)?;
    assert!(policies(&GraphContext::new(&staged)?.facts(&record)?)?
        .iter()
        .all(|policy| policy.state == PolicyProvenanceStateV1::Missing));
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '4',
    )?;
    assert_eq!(copy.reconcile()?, 2);
    let (revision, captured) = capture(&data, tenant)?;
    let frozen = GraphContext::new(&captured)?;
    let original = frozen.facts(&record)?;
    assert_eq!(facts(&mut copy, &data, &record)?, original);
    let exact = policies(&original)?;
    assert_eq!(exact.len(), 1);
    assert_eq!(exact[0].state, PolicyProvenanceStateV1::Exact);
    assert_eq!(
        exact[0]
            .activation_acknowledgement
            .as_ref()
            .ok_or("ACK")?
            .owner_revision,
        rollout.transition_version
    );
    assert_eq!(
        original
            .iter()
            .filter(|fact| matches!(
                GraphFactV1::try_from(*fact).map(|fact| fact.value),
                Ok(GraphFactValueV1::Activation(_))
            ))
            .count(),
        4
    );
    let candidate = captured
        .iter()
        .find(|context| context.key.owner_id == "mithril-control/policy-candidate")
        .ok_or("candidate")?;
    let material: super::super::retained::GraphCandidate = serde_json::from_slice(&candidate.body)?;
    assert_eq!(material.candidate, bundle.candidate);
    assert!(!material.cells.is_empty());
    assert!(!String::from_utf8(candidate.body.clone())?.contains("canonical_policy"));
    assert!(capture(&data, [99; 16])?.1.is_empty());
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '5',
    )?;
    assert_eq!(copy.reconcile()?, 2);
    let (next, latest) = capture(&data, tenant)?;
    assert!(next > revision);
    assert_eq!(frozen.facts(&record)?, original);
    let refreshed = GraphContext::new(&latest)?.facts(&record)?;
    let exact = policies(&refreshed)?;
    assert_eq!(exact.len(), 2);
    assert!(exact
        .iter()
        .all(|policy| policy.state == PolicyProvenanceStateV1::Exact));
    assert_ne!(
        exact[0].node_bound_generation_digest,
        exact[1].node_bound_generation_digest
    );
    for fact in &original {
        assert!(refreshed.contains(fact));
    }
    assert_eq!(copy.reconcile()?, 0);
    drop(copy);
    drop(store);
    drop(data);
    let data = Arc::new(AnalysisStore::open(data_path)?);
    assert_eq!(
        GraphContext::new(&capture(&data, tenant)?.1)?.facts(&record)?,
        refreshed
    );
    let store = ControlStore::open(control_path)?;
    let mut copy = owner(&store, Arc::clone(&data), tenant)?;
    let before = data.meta()?;
    assert_eq!(copy.reconcile()?, 10);
    assert_eq!(data.meta()?, before);
    assert_eq!(
        GraphContext::new(&capture(&data, tenant)?.1)?.facts(&record)?,
        refreshed
    );
    assert_eq!(facts(&mut copy, &data, &record)?, refreshed);
    assert_eq!(copy.reconcile()?, 0);
    Ok(())
}

#[test]
fn retained_graph_reviews() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (store, record, bundle, mut rollout) = fixture(&directory.path().join("control"))?;
    let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '4',
    )?;
    owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?.reconcile()?;
    let (_, contexts) = capture(&data, record.id.stream.tenant_id)?;
    let retained = GraphContext::new(&contexts)?;
    let facts = retained.facts(&record)?;
    let decoded = facts
        .iter()
        .map(GraphFactV1::try_from)
        .collect::<araphor_data::Result<Vec<_>>>()?;
    assert!(decoded.iter().any(|fact| matches!(&fact.value, GraphFactValueV1::Baseline { outside_reviewed_baseline: true, reviewed_policy_revision, role_id: 1, state_id: 2 } if reviewed_policy_revision == &bundle.candidate.policy_source_revision_id)));
    let credential = decoded
        .iter()
        .find_map(|fact| match &fact.value {
            GraphFactValueV1::Credential {
                object_id,
                expected_access,
                reviewed_policy_revision,
                completion,
                proof_quality,
                principal_id,
            } => Some((
                object_id,
                expected_access,
                reviewed_policy_revision,
                completion,
                proof_quality,
                principal_id,
            )),
            _ => None,
        })
        .ok_or("credential")?;
    assert_eq!(
        credential.0.as_slice(),
        record.decode()?.exact_object_id.as_ref()
    );
    assert!(!credential.1);
    assert_eq!(credential.2, &bundle.candidate.policy_source_revision_id);
    assert!(credential.3.is_none());
    assert_eq!(
        credential.4.temporal_coverage,
        araphor_data::TemporalCoverageV1::Unknown
    );
    assert_eq!(
        credential.5.as_deref(),
        Some(
            format!(
                "kubernetes-serviceaccount-uid:{}",
                bundle.candidate.exact_target.workload_targets[0].service_account_uid
            )
            .as_str()
        )
    );
    let mut foreign = record.clone();
    foreign.id.stream.node_boot_id = [99; 16];
    assert!(retained.facts(&foreign).is_err());
    foreign = record.clone();
    foreign.id.stream.node_id = "other-node".into();
    assert!(retained.facts(&foreign)?.is_empty());
    let mut lifetime = record.id.stream.exact_key();
    lifetime.extend_from_slice(&record.id.cpu_id.to_be_bytes());
    lifetime.extend_from_slice(&record.id.durable_cursor.to_be_bytes());
    for fact in &facts {
        assert_eq!(fact.key.lifetime_key, lifetime);
    }
    let (store, record, bundle, mut rollout) = fixture(&directory.path().join("stale"))?;
    let data = Arc::new(AnalysisStore::open(directory.path().join("stale-data"))?);
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Stale,
        Some(8),
        '1',
    )?;
    owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?.reconcile()?;
    assert_eq!(
        policies(
            &GraphContext::new(&capture(&data, record.id.stream.tenant_id)?.1)?.facts(&record)?
        )?[0]
            .state,
        PolicyProvenanceStateV1::Contradicted
    );
    Ok(())
}

#[test]
fn retained_graph_conflicts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (store, record, bundle, mut rollout) = fixture(&directory.path().join("control"))?;
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '4',
    )?;
    let captured = Arc::new(AnalysisStore::open(directory.path().join("captured"))?);
    owner(&store, Arc::clone(&captured), record.id.stream.tenant_id)?.reconcile()?;
    let (_, contexts) = capture(&captured, record.id.stream.tenant_id)?;
    let ack = contexts
        .iter()
        .find(|context| context.key.owner_id == "mithril-control/activation-ack")
        .ok_or("ACK")?;
    let mut conflict = ack.clone();
    let mut body: PolicyActivationAcknowledgementV1 = serde_json::from_slice(&conflict.body)?;
    body.readback_digest = Some("f".repeat(64));
    conflict.body = serde_json::to_vec(&body)?;
    let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    data.commit_context(&conflict)?;
    let before = data.meta()?;
    let mut copy = owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?;
    let mut changes = data.subscribe_revision();
    assert!(
        matches!(copy.reconcile(), Err(crate::Error::DataStore { source, .. }) if matches!(*source, araphor_data::Error::AnalysisConflict { .. }))
    );
    assert_eq!(data.meta()?, before);
    assert!(!changes.has_changed()?);
    assert_eq!(data.context_version(&conflict.key)?, Some(conflict.clone()));
    let candidate = contexts
        .iter()
        .find(|context| context.key.owner_id == "mithril-control/policy-candidate")
        .ok_or("candidate")?;
    assert!(data.context_version(&candidate.key)?.is_none());
    let mut changed = contexts.clone();
    changed.push(conflict);
    assert!(GraphContext::new(&changed).is_err());
    for field in ["tenant", "entity", "node", "revision"] {
        let mut bad = ack.clone();
        match field {
            "tenant" => bad.key.tenant_id = [99; 16],
            "entity" => bad.key.entity_key.push(0),
            "node" => bad.key.lifetime_key.push(0),
            "revision" => bad.key.owner_revision = 0,
            _ => unreachable!(),
        }
        assert!(GraphContext::new(&[bad]).is_err(), "{field}");
    }
    let mut bad = candidate.clone();
    let mut changed = contexts;
    let mut material: super::super::retained::GraphCandidate = serde_json::from_slice(&bad.body)?;
    material.policy_digest = "e".repeat(64);
    bad.body = serde_json::to_vec(&material)?;
    changed.push(bad);
    assert!(GraphContext::new(&changed).is_err());
    changes.borrow_and_update();
    Ok(())
}

#[test]
fn retained_graph_notice_rollback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let (store, record, bundle, mut rollout) = fixture(&directory.path().join("control"))?;
    let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let mut copy = owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?;
    copy.reconcile()?;
    let mut changes = store.subscribe_context()?;
    let before = store.commit_index();
    let pending = store.evidence_lock()?.state_file.temporary.clone();
    std::fs::create_dir(&pending)?;
    let original = rollout.clone();
    assert!(acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '4'
    )
    .is_err());
    assert_eq!(store.commit_index(), before);
    assert!(!changes.has_changed()?);
    assert!(facts(&mut copy, &data, &record)?.is_empty());
    assert!(store
        .evidence_lock()?
        .context_index
        .sources
        .keys()
        .all(|source| !matches!(
            source,
            super::super::super::context::ContextSource::Acknowledgement(_, _)
        )));
    std::fs::remove_dir(&pending)?;
    rollout = original;
    acknowledge(
        &store,
        &bundle,
        &mut rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '4',
    )?;
    assert!(changes.has_changed()?);
    assert_eq!(
        policies(&facts(&mut copy, &data, &record)?)?[0].state,
        PolicyProvenanceStateV1::Exact
    );
    changes.borrow_and_update();
    Ok(())
}

struct GraphAuthority(
    tokio::sync::watch::Sender<u64>,
    std::sync::Mutex<Option<ControlContextOwner>>,
);

impl GraphAuthority {
    fn new() -> Self {
        Self(
            tokio::sync::watch::channel(0).0,
            std::sync::Mutex::new(None),
        )
    }
}

impl araphor_data::PackageAuthorization for GraphAuthority {
    fn check(
        &self,
        grant: &araphor_data::PackageGrantV1,
        _: araphor_data::PackageActionV1,
    ) -> araphor_data::Result<()> {
        grant.remaining()?;
        Ok(())
    }
    fn admit(
        &self,
        grant: &araphor_data::PackageGrantV1,
        _: &araphor_data::PackageBundle,
    ) -> araphor_data::Result<()> {
        grant.remaining()?;
        Ok(())
    }
    fn commit(
        &self,
        grant: &araphor_data::PackageGrantV1,
        action: araphor_data::PackageActionV1,
        image: &araphor_data::PackageBundle,
        callback: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.commit_many(
            &[(grant, action, None), (grant, action, Some(image))],
            callback,
        )
    }
    fn commit_many(
        &self,
        grants: &[(
            &araphor_data::PackageGrantV1,
            araphor_data::PackageActionV1,
            Option<&araphor_data::PackageBundle>,
        )],
        callback: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        if grants.is_empty() || !grants.iter().any(|(_, _, image)| image.is_none()) {
            return Err(araphor_data::PackageErrorCodeV1::Denied.error("graph authority fixture"));
        }
        for (grant, _, _) in grants {
            grant.remaining()?;
        }
        if let Some(mut feed) = self
            .1
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
        {
            feed.reconcile().map_err(|_| {
                araphor_data::PackageErrorCodeV1::Invalid.error("graph feed fixture")
            })?;
        }
        callback()
    }
    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.0.subscribe()
    }
}

struct CapturedFacts {
    owner: ControlContextOwner,
    authority: Arc<GraphAuthority>,
    update: std::sync::Mutex<Option<ControlContextOwner>>,
}

impl araphor_analysis::GraphFacts for CapturedFacts {
    fn facts(
        &self,
        contexts: &[arrow_array::RecordBatch],
        records: &[araphor_data::DiscoveryRecordV1],
    ) -> araphor_data::Result<(
        Vec<AnalysisContextVersionV1>,
        Vec<araphor_data::AnalysisContextRefV1>,
    )> {
        let facts = araphor_analysis::GraphFacts::facts(&self.owner, contexts, records)?;
        let update = self
            .update
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .take()
            .ok_or_else(|| {
                araphor_data::PackageErrorCodeV1::Invalid.error("graph update fixture")
            })?;
        *self
            .authority
            .1
            .lock()
            .unwrap_or_else(|error| error.into_inner()) = Some(update);
        Ok(facts)
    }
}

#[tokio::test]
async fn managed_captures_control_proofs() -> TestValue<()> {
    use araphor_analysis::{GraphProgram, GraphPublication};
    use araphor_analysis_builtins::{components, graph::Detector};
    use araphor_data::{
        ManagedRequest, PackageActionV1, PackageArtifactV1, PackageAuthorization as _,
        PackageBundleV1, PackageGrantV1, PackageImplementationV1, ProcessorScopeV1,
        ValidatedEvidenceBatchV1,
    };
    use araphor_discovery_definition::{Definition, Program, Source};
    use araphor_query::execution::Engine;
    use std::time::{SystemTime, UNIX_EPOCH};

    let directory = tempfile::tempdir()?;
    let (control, record, bundle, mut rollout) = fixture(&directory.path().join("control"))?;
    let tenant = record.id.stream.tenant_id;
    let data = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let mut feed = owner(&control, Arc::clone(&data), tenant)?;
    let mut expected_versions = std::collections::BTreeSet::new();
    for (state, generation, digest) in [
        (PolicyActivationStateV1::Received, None, '1'),
        (PolicyActivationStateV1::Staged, Some(7), '2'),
        (PolicyActivationStateV1::Active, Some(8), '4'),
    ] {
        acknowledge(&control, &bundle, &mut rollout, state, generation, digest)?;
        expected_versions.insert(rollout.transition_version);
    }
    feed.reconcile()?;
    let _graph = data.lease_graph(vec![araphor_data::AnalysisSelectionV1::tenant(tenant)])?;
    data.register_graph(&record.id.stream)?;
    data.accept_validated_batch(
        record.id.stream.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: record.id.durable_cursor,
            last_cursor: record.id.durable_cursor,
            intake_utc_ns: 1,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    for (detector, bytes) in [
        (Detector::Process, components::PROCESS),
        (Detector::Credentials, components::CREDENTIALS),
        (Detector::Kubernetes, components::KUBERNETES),
    ] {
        let artifact = PackageArtifactV1 {
            descriptor: detector.descriptor(),
            implementations: vec![PackageImplementationV1::Wasm {
                exports: vec!["detect".into()],
                artifact: bytes.to_vec(),
            }],
            fixtures: Vec::new(),
        };
        data.install_package_image(
            tenant,
            &araphor_data::PackageBundle::try_from(PackageBundleV1 {
                schema_version: 1,
                root: artifact.reference(),
                artifacts: vec![artifact],
            })?,
            || Ok(()),
        )?;
    }
    let query = Engine::new(Arc::clone(&data), Default::default())?;
    let selection = AnalysisSelectionV1::tenant(tenant);
    let read = AnalysisReadControl::default();
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let sql = araphor_data::FindingV1::PACKAGES.iter().map(|id| format!(
        "SELECT * FROM \"{id}\".\"1\".detect('subjects', records => (SELECT * FROM records), facts => (SELECT * FROM facts), manifest => (SELECT * FROM manifest))"
    )).collect::<Vec<_>>().join(" UNION ALL ");
    let definition = Definition {
        name: "control-graph-capture".into(),
        description: String::new(),
        labels: Default::default(),
        program: Program::Sql {
            source: Source::Inline { inline: sql },
        },
    };
    let authority = Arc::new(GraphAuthority::new());
    let grant = PackageGrantV1 {
        principal: "control-graph-fixture".into(),
        revision: 1,
        selection: selection.clone(),
        expires_utc_ns: None,
        authorization_id: None,
    };
    let facts = Arc::new(feed);
    let program = GraphProgram::prepare(
        query.session(selection.clone(), &read, now)?,
        authority.clone(),
        grant.clone(),
        "SELECT * FROM events".into(),
        definition,
        facts.clone(),
    )
    .await?;
    authority.commit_many(&[(&grant, PackageActionV1::Install, None)], &mut || {
        data.admit_definition(tenant, &program.definition, || read.check())?;
        Ok(())
    })?;
    let instance = GraphPublication::admit(
        Arc::clone(&query),
        authority,
        facts,
        grant.clone(),
        "control-proofs".into(),
        record.id.stream.clone(),
        program.events_sql.clone(),
        program.definition.clone(),
        &read,
    )
    .await?;
    let scope = ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: record.id.stream.clone(),
    };
    let domain = || {
        let mut history = Vec::new();
        let mut after = None;
        loop {
            let page =
                data.graph_snapshots(tenant, Some(&record.id.stream), after.as_deref(), false)?;
            if page.is_empty() {
                break;
            }
            for (id, graph, revision) in page {
                after = Some(id.clone());
                history.push((
                    id.clone(),
                    graph,
                    revision,
                    data.read_result(tenant, &id)?,
                    data.package_evidence(tenant, std::slice::from_ref(&id))?,
                ));
            }
        }
        Ok::<_, Box<dyn std::error::Error>>((
            data.processor_result(&scope)?,
            data.graph_window_headers(&record.id.stream, None)?,
            history,
        ))
    };
    let mut input = ManagedRequest {
        id: "control-proof".into(),
        time_utc_ns: now,
        seed: Some(17),
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    };
    let first = instance.run(input.clone(), &read).await?;
    assert_eq!(first.results.len(), 3);
    let original_head = data.processor_result(&scope)?.ok_or("native Graph head")?;
    let id = original_head.result_id.clone();
    let retained = data.graph_result(tenant, &id)?.ok_or("graph result")?;
    let first_cursor = retained.first_cursor;
    let policies = retained
        .graph
        .facts
        .iter()
        .filter_map(|fact| match &fact.value {
            GraphFactValueV1::Policy(policy) => Some(policy),
            _ => None,
        })
        .collect::<Vec<_>>();
    assert_eq!(policies.len(), 1);
    assert_eq!(policies[0].state, PolicyProvenanceStateV1::Exact);
    assert_eq!(
        policies[0]
            .activation_acknowledgement
            .as_ref()
            .ok_or("exact ACK")?
            .owner_revision,
        rollout.transition_version
    );
    let (_, refs) = data.package_evidence(tenant, std::slice::from_ref(&id))?;
    assert!(refs
        .iter()
        .any(|pin| pin.key.owner_id == "mithril-control/policy-candidate"));
    assert_eq!(
        refs.iter()
            .filter(|pin| pin.key.owner_id == "mithril-control/activation-ack")
            .map(|pin| pin.key.owner_revision)
            .collect::<std::collections::BTreeSet<_>>(),
        expected_versions
    );
    assert!(refs
        .iter()
        .any(|pin| pin.key.owner_id == "native-package-v1"));
    let original = retained.clone();
    let original_body = data.read_result(tenant, &id)?;
    let original_evidence = data.package_evidence(tenant, std::slice::from_ref(&id))?;
    assert_eq!(domain()?.2.len(), 1);
    assert_eq!(
        data.managed_history(&selection, "control-proofs", &read)?,
        vec![first.clone()]
    );
    let (same_control, unrelated_record, unrelated_bundle, mut unrelated_rollout) =
        populate_version(control.clone(), 2)?;
    assert_ne!(
        unrelated_bundle.candidate.candidate_content_id,
        bundle.candidate.candidate_content_id
    );
    assert_ne!(
        unrelated_bundle.profile_artifact.header.profile_id,
        bundle.profile_artifact.header.profile_id
    );
    assert_ne!(
        unrelated_bundle.candidate.policy_source_revision_id,
        bundle.candidate.policy_source_revision_id
    );
    assert_eq!(
        same_control.bundle_for_candidate("node-a", &bundle.candidate.candidate_content_id)?,
        Some(bundle.clone())
    );
    assert_eq!(unrelated_record.id.stream, record.id.stream);
    acknowledge(
        &same_control,
        &unrelated_bundle,
        &mut unrelated_rollout,
        PolicyActivationStateV1::Active,
        Some(8),
        '6',
    )?;
    let mut feed = owner(&same_control, Arc::clone(&data), tenant)?;
    feed.reconcile()?;
    let before = domain()?;
    input.id = "unrelated-policy".into();
    input.time_utc_ns = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let unchanged = instance.run(input.clone(), &read).await?;
    assert_eq!(domain()?, before);
    assert_eq!(
        data.graph_result(tenant, &id)?.ok_or("graph result")?,
        retained
    );
    assert_eq!(
        data.package_evidence(tenant, std::slice::from_ref(&id))?.1,
        refs
    );
    assert_eq!(
        data.managed_history(&selection, "control-proofs", &read)?,
        vec![first.clone(), unchanged.clone()]
    );

    let source = same_control
        .source_revision(&bundle.candidate.policy_source_revision_id)?
        .ok_or("original source")?;
    let replacement = rollout_transaction(
        &source,
        &bundle.profile_artifact,
        vec![(
            bundle.candidate.exact_target.clone(),
            Some(bundle.candidate.candidate_content_id.clone()),
        )],
        PolicyDeliveryOperationV1::Replace,
        bundle
            .profile_artifact
            .policy_document
            .rollout
            .rollout_generation,
        bundle
            .candidate
            .distribution_sequence
            .checked_add(1)
            .ok_or("replacement sequence")?,
        &ed25519_dalek::SigningKey::from_bytes(&[7; 32]),
    )?;
    let next_bundle = replacement
        .bundles
        .first()
        .ok_or("replacement bundle")?
        .clone();
    let mut next_rollout = replacement
        .rollout_states
        .first()
        .ok_or("replacement rollout")?
        .clone();
    same_control.create_rollout(
        replacement.target_snapshot,
        replacement.bundles,
        replacement.rollout_states,
    )?;
    assert_eq!(
        next_bundle
            .candidate
            .predecessor_candidate_content_id
            .as_deref(),
        Some(bundle.candidate.candidate_content_id.as_str())
    );
    acknowledge(
        &same_control,
        &next_bundle,
        &mut next_rollout,
        PolicyActivationStateV1::Stale,
        Some(8),
        '7',
    )?;
    let mut feed = owner(&same_control, Arc::clone(&data), tenant)?;
    feed.reconcile()?;
    let before = data.meta()?;
    let domain_before = domain()?;
    let mut restricted = selection.clone();
    restricted.contexts = araphor_data::Selection::Exact(
        refs.iter()
            .filter(|reference| reference.key.owner_id != "native-package-v1")
            .map(|reference| reference.key.clone())
            .collect(),
    );
    let denied = GraphPublication::admit(
        Arc::clone(&query),
        Arc::new(GraphAuthority::new()),
        Arc::new(feed),
        PackageGrantV1 {
            selection: restricted,
            ..grant.clone()
        },
        "control-restricted".into(),
        record.id.stream.clone(),
        program.events_sql.clone(),
        program.definition.clone(),
        &read,
    )
    .await;
    let Err(denied) = denied else {
        return Err("restricted context history was admitted".into());
    };
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&denied),
        erebor_runtime_error::StatusCode::PermissionDenied
    );
    assert_eq!(data.meta()?, before);
    assert_eq!(domain()?, domain_before);

    input.id = "contradictory-ack".into();
    input.time_utc_ns = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let changed = instance.run(input.clone(), &read).await?;
    let (contradicted, _, revision) = data
        .graph_window_headers(&record.id.stream, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == first_cursor)
        .ok_or("contradicted native Graph window")?;
    assert_eq!(revision, changed.commit_revision);
    assert_eq!(data.processor_result(&scope)?, Some(original_head.clone()));
    assert_ne!(contradicted, id);
    let retained = data
        .graph_result(tenant, &contradicted)?
        .ok_or("contradicted graph")?;
    assert!(
        retained.graph.facts.iter().any(|fact| matches!(&fact.value,
        GraphFactValueV1::Policy(policy) if policy.state == PolicyProvenanceStateV1::Contradicted))
    );
    assert!(retained.packages.iter().any(|package| package.package_id
        == araphor_data::FindingV1::PACKAGES[0]
        && package.state == araphor_data::GraphPackageStateV1::Contradicted));
    let (_, refs) = data.package_evidence(tenant, std::slice::from_ref(&contradicted))?;
    assert!(refs
        .iter()
        .any(|pin| pin.key.owner_id == "mithril-control/activation-ack"
            && pin.key.owner_revision == rollout.transition_version));
    assert!(refs.iter().any(|pin| {
        pin.key.owner_id == "mithril-control/activation-ack"
            && pin.key.entity_key.as_slice()
                == next_bundle.candidate.candidate_content_id.as_bytes()
            && pin.key.owner_revision == next_rollout.transition_version
    }));
    assert_eq!(
        same_control.bundle_for_candidate("node-a", &bundle.candidate.candidate_content_id)?,
        Some(bundle.clone())
    );
    let (same_control, _, later_bundle, _) = populate_version(same_control.clone(), 3)?;
    assert_ne!(
        later_bundle.profile_artifact.header.profile_id,
        bundle.profile_artifact.header.profile_id
    );
    assert_ne!(
        later_bundle.profile_artifact.header.profile_id,
        unrelated_bundle.profile_artifact.header.profile_id
    );
    assert_ne!(
        later_bundle.candidate.policy_source_revision_id,
        unrelated_bundle.candidate.policy_source_revision_id
    );
    assert_eq!(
        same_control.bundle_for_candidate("node-a", &bundle.candidate.candidate_content_id)?,
        Some(bundle.clone())
    );
    assert_eq!(data.graph_result(tenant, &id)?, Some(original));
    assert_eq!(data.read_result(tenant, &id)?, original_body);
    assert_eq!(
        data.package_evidence(tenant, std::slice::from_ref(&id))?,
        original_evidence
    );
    assert_eq!(domain()?.2.len(), 2);
    assert_eq!(
        data.managed_history(&selection, "control-proofs", &read)?,
        vec![first, unchanged, changed]
    );
    let authority = Arc::new(GraphAuthority::new());
    let publication_feed = CapturedFacts {
        owner: owner(&same_control, Arc::clone(&data), tenant)?,
        authority: Arc::clone(&authority),
        update: std::sync::Mutex::new(Some(owner(&same_control, Arc::clone(&data), tenant)?)),
    };
    let publication = GraphPublication::admit(
        Arc::clone(&query),
        authority.clone(),
        Arc::new(publication_feed),
        grant.clone(),
        "control-race".into(),
        record.id.stream.clone(),
        program.events_sql.clone(),
        program.definition.clone(),
        &read,
    )
    .await?;
    let before = domain()?;
    input.id = "context-after-capture".into();
    input.time_utc_ns = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let denied = publication
        .run(input.clone(), &read)
        .await
        .err()
        .ok_or("changed captured context was published")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&denied),
        erebor_runtime_error::StatusCode::AlreadyExists
    );
    let mut source: Option<&(dyn std::error::Error + 'static)> = Some(&denied);
    let mut conflict = false;
    while let Some(error) = source {
        conflict |= matches!(
            error.downcast_ref::<araphor_data::Error>(),
            Some(araphor_data::Error::AnalysisConflict { .. })
        );
        source = if let Some(araphor_analysis::Error::Data { source }) =
            error.downcast_ref::<araphor_analysis::Error>()
        {
            Some(source)
        } else if let Some(araphor_analysis::Error::Query { source }) =
            error.downcast_ref::<araphor_analysis::Error>()
        {
            Some(source)
        } else if let Some(araphor_query::Error::Data { source }) =
            error.downcast_ref::<araphor_query::Error>()
        {
            Some(source)
        } else {
            error.source()
        };
    }
    assert!(conflict, "{denied:?}");
    assert!(authority
        .1
        .lock()
        .unwrap_or_else(|error| error.into_inner())
        .is_none());
    assert_eq!(domain()?, before);
    assert_eq!(data.graph_result(tenant, &contradicted)?, Some(retained));
    assert!(data
        .managed_history(&selection, "control-race", &read)?
        .is_empty());
    if let Some(attempt) = data.managed_attempt(tenant, "control-race", &input.id, &read)? {
        assert!(attempt.receipt().is_none());
    }

    let publication = GraphPublication::admit(
        Arc::clone(&query),
        Arc::new(GraphAuthority::new()),
        Arc::new(owner(&same_control, Arc::clone(&data), tenant)?),
        grant,
        "control-fresh".into(),
        record.id.stream.clone(),
        program.events_sql,
        program.definition,
        &read,
    )
    .await?;
    let before = domain()?;
    input.id = "fresh-context-noop".into();
    input.time_utc_ns = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    let fresh = publication.run(input, &read).await?;
    assert_eq!(domain()?, before);
    let (unchanged, _, _) = data
        .graph_window_headers(&record.id.stream, None)?
        .into_iter()
        .find(|(_, header, _)| header.first_cursor == first_cursor)
        .ok_or("fresh native Graph window")?;
    assert_eq!(unchanged, contradicted);
    assert_eq!(data.processor_result(&scope)?, Some(original_head));
    assert_eq!(
        data.managed_history(&selection, "control-fresh", &read)?,
        vec![fresh]
    );
    data.verify_state()?;
    Ok(())
}

#[test]
fn retained_credential_selectors() -> TestResult {
    use crate::{LocalObjectSelectorV1, ObjectClassifierSelectorV1, PathSelectorV1, RuleMatchV1};

    let directory = tempfile::tempdir()?;
    for (index, selector, expected) in [
        (0, None, true),
        (1, Some("credential-path"), true),
        (2, Some("projected-token"), false),
    ] {
        let mut document = PolicyDocumentV1::parse(
            std::path::Path::new("policy-v1.yaml"),
            include_bytes!("../../../../tests/fixtures/policy-v1.yaml"),
        )?;
        document
            .protected_universe
            .object_class_ids
            .push("PUBLIC_DATA".into());
        let mut binding = document.classifier_bindings[0].clone();
        binding.classifier_binding_id = "public-binding".into();
        binding.object_class_id = "PUBLIC_DATA".into();
        binding.selector = ObjectClassifierSelectorV1::ImmutableArtifact {
            artifact_digests: vec!["a".repeat(64)],
        };
        document.classifier_bindings.push(binding);
        document.path_selectors = vec![
            PathSelectorV1::exact("credential-path", "/var/run/token", "PROJECTED_TOKEN"),
            PathSelectorV1::exact("projected-token", "/var/run/public", "PUBLIC_DATA"),
        ];
        if let Some(selector) = selector {
            let RuleMatchV1::LocalPreEffect(effect) = &mut document.rules[0].rule_match else {
                return Err("local rule".into());
            };
            effect.object = LocalObjectSelectorV1::PathSelectors {
                path_selector_ids: vec![selector.into()],
            };
        }
        let path = directory.path().join(index.to_string());
        let (store, record, bundle, mut rollout) =
            populate_document(ControlStore::open(&path)?, document)?;
        acknowledge(
            &store,
            &bundle,
            &mut rollout,
            PolicyActivationStateV1::Active,
            Some(8),
            '4',
        )?;
        let data = Arc::new(AnalysisStore::open(path.join("data"))?);
        owner(&store, Arc::clone(&data), record.id.stream.tenant_id)?.reconcile()?;
        let (_, contexts) = capture(&data, record.id.stream.tenant_id)?;
        let context = contexts
            .iter()
            .find(|context| context.key.owner_id == "mithril-control/policy-candidate")
            .ok_or("candidate")?;
        let material: super::super::retained::GraphCandidate =
            serde_json::from_slice(&context.body)?;
        assert_eq!(
            material.credential_objects,
            ["CLASS:PROJECTED_TOKEN", "PATH:credential-path"]
        );
        let retained = GraphContext::new(&contexts)?;
        let facts = retained.facts(&record)?;
        let policy = policies(&facts)?;
        assert_eq!(policy.len(), 1);
        assert_eq!(policy[0].state, PolicyProvenanceStateV1::Exact);
        let credentials = facts
            .iter()
            .map(GraphFactV1::try_from)
            .collect::<araphor_data::Result<Vec<_>>>()?
            .into_iter()
            .filter(|fact| matches!(fact.value, GraphFactValueV1::Credential { .. }))
            .count();
        assert_eq!(credentials, usize::from(expected), "{selector:?}");
        for selector in [
            "PROJECTED_TOKEN",
            "CLASS:PROJECTED_TOKEN_EXTRA",
            "PATH:credential-path-extra",
        ] {
            let mut wire = record.decode()?;
            let context = wire.decision_context.as_mut().ok_or("context")?;
            let mut catalog =
                crate::EvidenceDecisionCatalogV1::from_context(context)?.ok_or("catalog")?;
            catalog.static_key.object_selector = selector.into();
            context.catalog_json = catalog.seal()?;
            let raw = araphor_data::DiscoveryRecordV1::try_from((
                record.id.clone(),
                Vec::<u8>::try_from(&wire)?.as_slice(),
            ))?;
            assert!(retained.facts(&raw)?.is_empty(), "{selector}");
        }
    }
    Ok(())
}
