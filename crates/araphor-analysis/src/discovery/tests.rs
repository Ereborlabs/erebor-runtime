use std::collections::BTreeMap;
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_analysis_sdk::arrow_array::{RecordBatch, UInt64Array};
use araphor_data::{
    AnalysisSelectionV1, AnalysisStore, DiscoveryInputManifestV1, DiscoveryProfileV1,
    DiscoveryRecordV1, PackageActionV1, PackageAuthorization, PackageBundle, PackageGrantV1,
    ProcessorClassV1, ProcessorRetirementV1, ProcessorScopeV1, ValidatedEvidenceBatchV1,
    DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
    SqlReasonV1,
};
use araphor_query::execution::{Engine, Limits};
use araphor_query::follow::{Operation, Update};
use futures_util::StreamExt as _;

use super::feed::{Members, Updates};
use super::*;
use araphor_data::AnalysisReadControl;
use tokio::sync::watch;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

mod finite;
mod managed;
mod replay;
mod sources;

struct Authority(watch::Sender<u64>);

impl PackageAuthorization for Authority {
    fn check(&self, _: &PackageGrantV1, _: PackageActionV1) -> araphor_data::Result<()> {
        Ok(())
    }
    fn admit(&self, _: &PackageGrantV1, _: &PackageBundle) -> araphor_data::Result<()> {
        Ok(())
    }
    fn commit(
        &self,
        _: &PackageGrantV1,
        _: PackageActionV1,
        _: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        operation()
    }
    fn commit_many(
        &self,
        grants: &[(&PackageGrantV1, PackageActionV1, Option<&PackageBundle>)],
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        if grants.is_empty() || !grants.iter().any(|(_, _, image)| image.is_none()) {
            return Err(Code::Denied.error("discovery fixture authority set"));
        }
        for (grant, action, image) in grants {
            grant.remaining()?;
            self.check(grant, *action)?;
            if let Some(image) = image {
                image.bundle().validate()?;
                self.admit(grant, image)?;
            }
        }
        operation()
    }
    fn changes(&self) -> watch::Receiver<u64> {
        self.0.subscribe()
    }
}

struct Fixture {
    store: Arc<AnalysisStore>,
    query: Arc<Engine>,
    source: EvidenceIntakeIdentityV1,
    records: BTreeMap<u64, DiscoveryRecordV1>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(limits: Limits) -> TestResult<Self> {
        Self::retention(limits, Default::default())
    }

    fn retention(limits: Limits, retention: araphor_data::RetentionLimitsV1) -> TestResult<Self> {
        let manifest = DiscoveryInputManifestV1::try_from(
            include_bytes!("../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
        )?;
        let records = manifest
            .records
            .into_iter()
            .map(|record| (record.id.durable_cursor, record))
            .collect::<BTreeMap<_, _>>();
        let source = records
            .first_key_value()
            .ok_or("fixture record absent")?
            .1
            .id
            .stream
            .clone();
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open_with_limits(
            directory.path().join("data"),
            retention,
            Default::default(),
        )?);
        store.install_package_image(
            source.tenant_id,
            &PackageBundle::try_from(Package::discovery_bundle()?)?,
            || Ok(()),
        )?;
        let mut query = Engine::new(
            Arc::clone(&store),
            Limits {
                global_streams: Some(2),
                tenant_streams: Some(2),
                extract_timeout: Some(Duration::from_secs(30)),
                ..limits
            },
        )?;
        Arc::get_mut(&mut query)
            .ok_or("query already shared")?
            .register_views(araphor_analysis_builtins::discovery::sql::VIEWS_SQL)?;
        Ok(Self {
            store,
            query,
            source,
            records,
            _directory: directory,
        })
    }

    fn owner(&self, selection: AnalysisSelectionV1) -> TestResult<DiscoveryOwner> {
        let authority: Arc<dyn PackageAuthorization> = Arc::new(Authority(watch::channel(0).0));
        let host = InstanceHost::new(Arc::clone(&self.query), Arc::clone(&authority));
        Ok(DiscoveryOwner::new(
            vec![Package::new(
                Arc::clone(&self.query),
                authority,
                PackageGrantV1 {
                    principal: "fixture".into(),
                    revision: 1,
                    selection,
                    expires_utc_ns: None,
                    authorization_id: None,
                },
                Arc::new(PackageBundle::try_from(crate::Package::discovery_bundle()?)?),
                "live",
                "snapshot",
            )?],
            host,
        )?)
    }

    fn constant_bundle(sql: &str) -> TestResult<PackageBundleV1> {
        let input = sdk::Port::new(
            "events",
            sdk::Schema::new(vec![AnalysisStore::table_schemas()["events"]
                .field_with_name("source_cursor")?
                .clone()]),
        );
        let output = sdk::Port::new(
            "data",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        );
        let mut model = sdk::Model::new("constant", vec![input], vec![output]);
        model.input_mode = sdk::InputMode::Resolved;
        let bundle = PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: "setup-fixture".into(),
                revision: "1".into(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor: sdk::Package::new("setup-fixture", "1", vec![model]),
                implementations: vec![PackageImplementationV1::Sql {
                    export: "constant".into(),
                    program: SqlModelV1 {
                        outputs: BTreeMap::from([("data".into(), sql.into())]),
                        ..Default::default()
                    },
                }],
                fixtures: Vec::new(),
            }],
        };
        Ok(bundle)
    }

    fn constant_owner(&self, sql: &str) -> TestResult<DiscoveryOwner> {
        let bundle = Arc::new(PackageBundle::try_from(Self::constant_bundle(sql)?)?);
        self.store
            .install_package_image(self.source.tenant_id, &bundle, || Ok(()))?;
        let authority: Arc<dyn PackageAuthorization> = Arc::new(Authority(watch::channel(0).0));
        let host = InstanceHost::new(Arc::clone(&self.query), Arc::clone(&authority));
        Ok(DiscoveryOwner::new(
            vec![Package::new(
                Arc::clone(&self.query),
                authority,
                PackageGrantV1 {
                    principal: "fixture".into(),
                    revision: 1,
                    selection: AnalysisSelectionV1::tenant(self.source.tenant_id),
                    expires_utc_ns: None,
                    authorization_id: None,
                },
                bundle,
                "constant",
                "data",
            )?],
            host,
        )?)
    }

    fn scope(&self) -> ProcessorScopeV1 {
        ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
            identity: self.source.clone(),
        }
    }

    fn append(&self, cursor: u64) -> TestResult {
        self.append_at(cursor, cursor * 1_000_000_000)
    }

    fn append_at(&self, cursor: u64, received: u64) -> TestResult {
        let record = self.records.get(&cursor).ok_or("fixture cursor absent")?;
        self.store.accept_validated_batch(
            self.source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: received,
                frame_ends: vec![record.wire_record.len()],
                framed_records: record.wire_record.clone().into(),
            },
        )?;
        Ok(())
    }

    fn profile(&self) -> TestResult<Option<DiscoveryProfileV1>> {
        self.store
            .processor_result(&self.scope())?
            .map(|result| DiscoveryProfileV1::try_from(result.body.as_slice()).map_err(Into::into))
            .transpose()
    }

    fn released(&self) -> TestResult {
        let first = self.query.reserve_stream(self.source.tenant_id)?;
        let second = self.query.reserve_stream(self.source.tenant_id)?;
        assert!(self.query.reserve_stream(self.source.tenant_id).is_err());
        drop((first, second));
        drop(self.query.reserve_evaluation(self.source.tenant_id)?);
        if let Some(capacity) = self.query.limits().input_capacity {
            drop(self.query.memory().reserve_input(capacity)?);
        }
        if let Some(capacity) = self.query.limits().output_capacity {
            drop(self.query.memory().reserve_output(capacity)?);
        }
        Ok(())
    }
}

async fn registry(streams: &mut Updates, tenant: [u8; 16]) -> TestResult<Update> {
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let (current, update) = streams.next().await.ok_or("registry ended")?;
            assert_eq!(current, tenant);
            let update = update?;
            if update.batches.is_some() {
                assert_eq!(update.operation, Operation::Replace);
                return Ok(update);
            }
        }
    })
    .await?
}

#[tokio::test]
async fn native_finite_progress() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let owner = fixture.owner(AnalysisSelectionV1::new(
        fixture.source.tenant_id,
        vec![fixture.source.clone()],
    ))?;
    assert!(owner.profile(&fixture.source)?.is_none());
    let control = AnalysisReadControl::default();
    let instance = owner
        .admit(&fixture.source, &control)
        .await?
        .ok_or("finite instance")?;
    assert!(!instance.admitted().running);
    assert!(owner.profile(&fixture.source)?.is_none());
    let committed = instance
        .run(Fixture::request("finite-first")?, &control)
        .await?;
    let first = owner.profile(&fixture.source)?.ok_or("first profile")?;
    assert_eq!(first.snapshot.accepted_records, 1);
    let before = fixture.store.meta()?;
    let references = fixture.store.package_result_refs(
        fixture.source.tenant_id,
        std::slice::from_ref(&first.profile_id),
    )?;
    assert_eq!(references.len(), 1);
    assert_eq!(references[0].result_id, first.profile_id);
    assert_eq!(references[0].commit_revision, committed.commit_revision);
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("finite processor")?
            .consumed_cursor,
        1
    );
    let unchanged = instance
        .run(Fixture::request("finite-unchanged")?, &control)
        .await?;
    assert!(unchanged.commit_revision > before.commit_revision);
    assert_eq!(owner.profile(&fixture.source)?, Some(first.clone()));
    fixture.append(2)?;
    instance
        .run(Fixture::request("finite-second")?, &control)
        .await?;
    let next = owner.profile(&fixture.source)?.ok_or("next profile")?;
    assert_ne!(next.profile_id, first.profile_id);
    assert_eq!(next.interval_id, first.interval_id);
    assert_eq!(next.revision, first.revision + 1);
    assert_eq!(next.snapshot.accepted_records, 2);
    assert!(next.updated_utc_ns >= first.updated_utc_ns);
    let retained = fixture
        .store
        .read_result(fixture.source.tenant_id, &first.profile_id)?
        .ok_or("first retained profile")?;
    assert_eq!(DiscoveryProfileV1::try_from(retained.as_slice())?, first);
    let mut other = fixture.source.clone();
    other.node_id.push_str("-other");
    let before = fixture.store.meta()?;
    assert!(owner.profile(&other).is_err());
    assert!(owner.admit(&other, &control).await.is_err());
    assert_eq!(fixture.store.meta()?, before);
    drop((instance, owner));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_source_stream_lifecycle() -> TestResult {
    let fixture = Fixture::new(Limits {
        input_capacity: Some(128 * 1024 * 1024),
        output_capacity: Some(16 * 1024 * 1024),
        ..Default::default()
    })?;
    let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
    let tenant = fixture.source.tenant_id;
    assert!(owner.profile(&fixture.source)?.is_none());
    let mut other_source = fixture.source.clone();
    other_source.tenant_id = [99; 16];
    assert!(matches!(
        owner.profile(&other_source),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                ..
            }
        })
    ));
    let control = Arc::new(AnalysisReadControl::default());
    let mut streams = owner.sources(&control).await?;
    let mut members = Members::new();
    assert!(streams
        .iter()
        .all(|entry| entry.stream.moving_resolution_ns().is_none()));
    let empty = registry(&mut streams, tenant).await?;
    assert!(DiscoveryOwner::identities(&empty)?.is_empty());
    owner.derive(&mut members, tenant, &empty, &control).await?;
    assert_eq!(streams.len(), 1);
    assert!(members.is_empty());
    fixture
        .store
        .register_processor(&fixture.scope(), ProcessorClassV1::Required, 1)?;
    fixture.append(1)?;
    let mut added = registry(&mut streams, tenant).await?;
    assert_eq!(
        DiscoveryOwner::identities(&added)?.as_slice(),
        std::slice::from_ref(&fixture.source)
    );
    added.limited = true;
    let before = fixture.store.meta()?;
    assert!(owner
        .derive(&mut members, tenant, &added, &control)
        .await
        .is_err());
    assert_eq!(fixture.store.meta()?, before);
    assert!(members.is_empty());
    added.limited = false;
    owner.derive(&mut members, tenant, &added, &control).await?;
    let registered = fixture.store.meta()?;
    owner.derive(&mut members, tenant, &added, &control).await?;
    assert_eq!(fixture.store.meta()?, registered);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("processor")?
            .class,
        ProcessorClassV1::Required
    );
    assert_eq!(streams.len(), 1);
    assert_eq!(members.len(), 1);
    assert!(members.contains(&fixture.source));
    let instance = fixture
        .store
        .managed_instance(
            tenant,
            &DiscoveryOwner::instance_id(&fixture.source),
            &control,
        )?
        .ok_or("managed source")?;
    assert!(instance.running);
    assert_eq!(
        instance.spec.id,
        DiscoveryOwner::instance_id(&fixture.source)
    );
    assert!(fixture.profile()?.is_none());
    let available = fixture.query.reserve_stream(tenant)?;
    assert!(fixture.query.reserve_stream(tenant).is_err());
    drop(available);
    fixture.store.retire_required(&ProcessorRetirementV1 {
        scope: fixture.scope(),
        change_id: "retire-native".into(),
        reason: "Retire this source processor.".into(),
        expected_cursor: 0,
        cutoff_cursor: 1,
    })?;
    let removed = registry(&mut streams, tenant).await?;
    assert!(DiscoveryOwner::identities(&removed)?.is_empty());
    owner
        .derive(&mut members, tenant, &removed, &control)
        .await?;
    assert!(members.is_empty());
    assert_eq!(streams.len(), 1);
    let saved = fixture
        .store
        .managed_instance(
            tenant,
            &DiscoveryOwner::instance_id(&fixture.source),
            &control,
        )?
        .ok_or("retained source")?;
    assert!(!saved.running);
    let before = fixture.store.meta()?;
    assert!(fixture
        .store
        .register_processor(&fixture.scope(), ProcessorClassV1::Required, 1)
        .is_err());
    assert_eq!(fixture.store.meta()?, before);
    drop((streams, empty, added, removed, owner));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_membership_restores_intent() -> TestResult {
    for retire in [false, true] {
        let fixture = Fixture::new(Limits::default())?;
        fixture.append(1)?;
        fixture
            .store
            .register_processor(&fixture.scope(), ProcessorClassV1::Required, 1)?;
        let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
        let control = Arc::new(AnalysisReadControl::default());
        let mut streams = owner.sources(&control).await?;
        let mut members = Members::new();
        let update = registry(&mut streams, fixture.source.tenant_id).await?;
        owner
            .derive(&mut members, fixture.source.tenant_id, &update, &control)
            .await?;
        assert!(members.contains(&fixture.source));
        let admitted = owner
            .admit(&fixture.source, &control)
            .await?
            .ok_or("admitted source")?;
        assert!(admitted.admitted().running);
        let generation = admitted.admitted().generation;
        if retire {
            fixture.store.retire_required(&ProcessorRetirementV1 {
                scope: fixture.scope(),
                change_id: "retire-while-down".into(),
                reason: "Retire this source before feed recovery.".into(),
                expected_cursor: 0,
                cutoff_cursor: 1,
            })?;
        } else {
            owner
                .host
                .stop(
                    Arc::clone(&admitted),
                    admitted.admitted().lifecycle,
                    &control,
                )
                .await?;
        }
        drop((streams, members, update));
        let before = fixture.store.meta()?;
        let mut streams = owner.sources(&control).await?;
        let mut members = Members::new();
        let restored = registry(&mut streams, fixture.source.tenant_id).await?;
        owner
            .derive(&mut members, fixture.source.tenant_id, &restored, &control)
            .await?;
        let saved = fixture
            .store
            .managed_instance(
                fixture.source.tenant_id,
                &DiscoveryOwner::instance_id(&fixture.source),
                &control,
            )?
            .ok_or("retained source")?;
        assert!(!saved.running);
        assert_eq!(saved.generation, generation);
        assert_eq!(members.len(), usize::from(!retire));
        assert_eq!(
            fixture.store.meta()?.commit_revision,
            before.commit_revision + u64::from(retire)
        );
        assert!(fixture.profile()?.is_none());
        drop((streams, members, restored, admitted, owner));
        fixture.released()?;
    }
    Ok(())
}

#[tokio::test]
async fn native_run_stops() -> TestResult {
    erebor_telemetry::init_test_logging();
    let fixture = Fixture::new(Limits {
        input_capacity: Some(128 * 1024 * 1024),
        output_capacity: Some(16 * 1024 * 1024),
        ..Default::default()
    })?;
    let owner = Arc::new(fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?);
    let (stop, stopped) = watch::channel(false);
    let mut notices = fixture.store.subscribe_revision();
    let expiry = u64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)?
            .as_nanos(),
    )? + 7 * 24 * 60 * 60 * 1_000_000_000;
    let feed = Arc::clone(&owner);
    let host = Arc::clone(&owner.host);
    let mut worker = tokio::spawn(async move {
        tokio::try_join!(feed.run(stopped.clone()), host.serve(stopped, expiry))?;
        Ok::<_, crate::Error>(())
    });
    for cursor in [1, 2] {
        fixture.append(cursor)?;
        tokio::time::timeout(Duration::from_secs(90), async {
            loop {
                notices.borrow_and_update();
                if fixture
                    .profile()?
                    .is_some_and(|profile| profile.snapshot.accepted_records == cursor)
                {
                    return Ok::<_, Box<dyn std::error::Error + Send + Sync>>(());
                }
                tokio::select! {
                    result = &mut worker => return Err(format!("owner ended: {result:?}").into()),
                    changed = notices.changed() => { changed?; }
                }
            }
        })
        .await
        .map_err(|error| format!("publication cursor {cursor}: {error}"))??;
    }
    let profile = fixture.profile()?.ok_or("profile absent")?;
    assert_eq!(profile.snapshot.accepted_records, 2);
    assert_eq!(profile.snapshot.unresolved.len(), 2);
    let before = fixture.store.meta()?;
    assert!(tokio::time::timeout(Duration::from_millis(40), &mut worker)
        .await
        .is_err());
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(fixture.profile()?, Some(profile));
    stop.send_replace(true);
    tokio::time::timeout(Duration::from_secs(90), worker)
        .await
        .map_err(|error| format!("stop: {error}"))???;
    let saved = fixture
        .store
        .managed_instance(
            fixture.source.tenant_id,
            &DiscoveryOwner::instance_id(&fixture.source),
            &AnalysisReadControl::default(),
        )?
        .ok_or("running source intent")?;
    assert!(saved.running);
    drop(owner);
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_source_scope_rejection() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let tenant = fixture.source.tenant_id;
    let unregistered = fixture
        .managed_package(
            "unregistered-profile",
            Package::discovery_bundle()?,
            "live",
            "snapshot",
            false,
        )
        .await?;
    assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
    let before = fixture.store.meta()?;
    let error = unregistered
        .run(
            Fixture::request("unregistered")?,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("unregistered Profile published")?;
    assert!(
        format!("{error:?}").contains("profile captured progress"),
        "{error:?}"
    );
    finite::assert_failed_profile(&fixture, &unregistered, "unregistered", Code::Conflict, 0)?;
    assert_eq!(
        fixture.store.meta()?.commit_revision,
        before.commit_revision + 2
    );
    assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
    assert!(fixture.profile()?.is_none());
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    let mut image = Package::discovery_bundle()?;
    image.root.revision = "foreign-source".into();
    image.artifacts[0].descriptor.revision = "foreign-source".into();
    let PackageImplementationV1::Sql { program, .. } = &mut image.artifacts[0].implementations[0]
    else {
        return Err("native Profile SQL absent".into());
    };
    let original = program
        .outputs
        .get("snapshot")
        .ok_or("Profile output absent")?;
    program.outputs.insert("snapshot".into(), format!("SELECT * REPLACE (named_struct('tenant_id', source['tenant_id'], 'node_id', source['node_id'], 'node_boot_id', source['node_boot_id'], 'label_epoch', source['label_epoch'], 'source_id', decode('08080808080808080808080808080808', 'hex'), 'source_epoch', source['source_epoch']) AS source) FROM ({original}) AS profile"));
    let forged = fixture.managed_image("foreign-profile", image).await?;
    let health = fixture
        .store
        .processor_health(&fixture.scope())?
        .ok_or("registered processor health")?;
    let before = fixture.store.meta()?;
    assert_eq!(health.read_revision, before.commit_revision);
    let error = forged
        .run(
            Fixture::request("foreign-source")?,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("foreign Profile source published")?;
    assert!(
        format!("{error:?}").contains("profile output source"),
        "{error:?}"
    );
    finite::assert_failed_profile(&fixture, &forged, "foreign-source", Code::Invalid, 0)?;
    assert_eq!(
        fixture.store.meta()?.commit_revision,
        before.commit_revision + 2
    );
    assert_eq!(
        fixture.store.processor_health(&fixture.scope())?,
        Some(araphor_data::ProcessorHealthV1 {
            read_revision: before.commit_revision + 2,
            ..health
        })
    );
    assert!(fixture.profile()?.is_none());
    let selected = fixture.owner(AnalysisSelectionV1::new(
        tenant,
        vec![fixture.source.clone()],
    ))?;
    let before = fixture.store.meta()?;
    assert!(selected
        .admit(&other, &AnalysisReadControl::default())
        .await
        .is_err());
    let foreign_tenant = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..fixture.source.clone()
    };
    assert!(selected
        .admit(&foreign_tenant, &AnalysisReadControl::default())
        .await
        .is_err());
    assert_eq!(fixture.store.meta()?, before);
    drop((selected, unregistered, forged));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_unchanged_return_rejected() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let input = sdk::Port::new(
        "events",
        sdk::Schema::new(vec![AnalysisStore::table_schemas()["events"]
            .field_with_name("source_cursor")?
            .clone()]),
    );
    let output = sdk::Port::new(
        "data",
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
    );
    let mut model = sdk::Model::new("constant", vec![input], vec![output]);
    model.input_mode = sdk::InputMode::Resolved;
    model.reasons.push(sdk::Reason {
        code: "publisher-fixture.changed".into(),
        details: sdk::Schema::new(vec![sdk::Field::new(
            "source_cursor",
            sdk::DataType::UInt64,
            false,
        )]),
    });
    let artifact = PackageArtifactV1 {
        descriptor: sdk::Package::new("publisher-fixture", "1", vec![model]),
        implementations: vec![PackageImplementationV1::Sql {
            export: "constant".into(),
            program: SqlModelV1 {
                outputs: BTreeMap::from([(
                    "data".into(),
                    "SELECT CAST(1 AS BIGINT UNSIGNED) AS value".into(),
                )]),
                reasons: vec![SqlReasonV1 {
                    output: "data".into(),
                    code: "publisher-fixture.changed".into(),
                    sql: "SELECT CAST(0 AS BIGINT UNSIGNED) AS output_row, source_cursor FROM events WHERE source_cursor = 2".into(),
                }],
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    let bundle = PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: "publisher-fixture".into(),
            revision: "1".into(),
        },
        artifacts: vec![artifact],
    };
    let bundle = Arc::new(PackageBundle::try_from(bundle)?);
    fixture
        .store
        .install_package_image(fixture.source.tenant_id, &bundle, || Ok(()))?;
    let package = Arc::new(Package::new(
        Arc::clone(&fixture.query),
        Arc::new(Authority(watch::channel(0).0)),
        PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant(fixture.source.tenant_id),
            expires_utc_ns: None,
            authorization_id: None,
        },
        Arc::clone(&bundle),
        "constant",
        "data",
    )?);
    let mut stream = package.subscribe(Some(&fixture.source), true).await?;
    let first = tokio::time::timeout(Duration::from_secs(90), stream.next())
        .await?
        .ok_or("first package update absent")??;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(first.calls.len(), 1);
    let (_, call) = package.prepared().await?;
    assert!(first
        .calls
        .get(&call.id())
        .is_some_and(|returned| returned.belongs_to(call)));
    assert!(first.calls.values().all(|returned| {
        let output = returned.output();
        output.checkpoint.is_none() && output.reasons.is_empty() && output.evidence.is_empty()
    }));
    let batch = first
        .batches
        .as_ref()
        .and_then(|batches| batches.first())
        .ok_or("constant output absent")?;
    let values = batch
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("constant output type")?;
    assert_eq!(values.values().as_ref(), &[1]);
    drop(first);
    fixture.append(2)?;
    let second = tokio::time::timeout(Duration::from_secs(90), stream.next())
        .await?
        .ok_or("second package update absent")??;
    assert_eq!(second.operation, Operation::Replace);
    assert!(second.batches.is_none());
    assert_eq!(second.calls.len(), 1);
    let returned = second
        .calls
        .values()
        .next()
        .ok_or("package return absent")?;
    assert_eq!(returned.output().reasons.len(), 1);
    let reason = returned
        .output()
        .reasons
        .first()
        .ok_or("changed reason absent")?;
    assert_eq!(reason.code, "publisher-fixture.changed");
    assert_eq!(reason.output.dataset, "data");
    assert_eq!(reason.output.row, 0);
    let cursors = reason
        .details
        .column(0)
        .as_any()
        .downcast_ref::<UInt64Array>()
        .ok_or("reason detail type")?;
    assert_eq!(cursors.values().as_ref(), &[2]);
    let instance = fixture
        .managed_package(
            "auxiliary-profile",
            bundle.bundle().clone(),
            "constant",
            "data",
            true,
        )
        .await?;
    let health = fixture
        .store
        .processor_health(&fixture.scope())?
        .ok_or("registered processor health")?;
    let before = fixture.store.meta()?;
    assert_eq!(health.read_revision, before.commit_revision);
    let error = instance
        .run(
            Fixture::request("auxiliary-return")?,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("Profile auxiliary return published")?;
    assert!(
        format!("{error:?}").contains("discovery auxiliary return"),
        "{error:?}"
    );
    finite::assert_failed_profile(
        &fixture,
        &instance,
        "auxiliary-return",
        Code::Unsupported,
        0,
    )?;
    assert_eq!(
        fixture.store.meta()?.commit_revision,
        before.commit_revision + 2
    );
    assert_eq!(
        fixture.store.processor_health(&fixture.scope())?,
        Some(araphor_data::ProcessorHealthV1 {
            read_revision: before.commit_revision + 2,
            ..health
        })
    );
    assert!(fixture.profile()?.is_none());
    drop((stream, second, instance, package));
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_setup_admission_guard() -> TestResult {
    for (sql, error_field) in [
        ("SELECT missing_field AS value FROM events", Some("missing_field")),
        (
            "SELECT CASE WHEN now() IS NOT NULL THEN CAST(1 AS BIGINT UNSIGNED) ELSE CAST(2 AS BIGINT UNSIGNED) END AS value",
            None,
        ),
        ("SELECT CAST(1 AS BIGINT UNSIGNED) AS value", None),
    ] {
        let fixture = Fixture::new(Limits::default())?;
        fixture.append(1)?;
        let owner = fixture.constant_owner(sql)?;
        let tenant = fixture.source.tenant_id;
        let control = Arc::new(AnalysisReadControl::default());
        let mut members = Members::new();
        let mut streams = owner.sources(&control).await?;
        let update = registry(&mut streams, tenant).await?;
        assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
        let before = fixture.store.meta()?;
        let result = owner.derive(&mut members, tenant, &update, &control).await;
        if let Some(field) = error_field {
            let error = result.err().ok_or("invalid package admitted")?;
            assert!(format!("{error:?}").contains(field), "{error:?}");
            assert_eq!(fixture.store.meta()?, before);
            assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
            assert_eq!(streams.len(), 1);
        } else {
            result?;
            let registered = fixture.store.meta()?;
            assert_eq!(registered.commit_revision, before.commit_revision + 4);
            let health = fixture
                .store
                .processor_health(&fixture.scope())?
                .ok_or("optional processor absent")?;
            assert_eq!(health.class, ProcessorClassV1::Optional);
            assert_eq!(health.accepted_cursor, 1);
            assert_eq!(health.consumed_cursor, 0);
            assert!(fixture.store.processor_result(&fixture.scope())?.is_none());
            assert_eq!(streams.len(), 1);
            assert_eq!(members.len(), 1);
            assert!(members.contains(&fixture.source));
            assert!(fixture.store.managed_instance(
                tenant, &DiscoveryOwner::instance_id(&fixture.source), &control,
            )?.ok_or("managed source")?.running);
            owner.derive(&mut members, tenant, &update, &control).await?;
            assert_eq!(fixture.store.meta()?, registered);
            let mut profile = owner.package(tenant)?.subscribe(Some(&fixture.source), false).await?;
            let first = tokio::time::timeout(Duration::from_secs(90), profile.next())
                .await?
                .ok_or("first package update absent")??;
            assert_eq!(first.calls.len(), 1);
            let (_, call) = owner.package(tenant)?.prepared().await?;
            assert!(first.calls.get(&call.id()).is_some_and(|returned| returned.belongs_to(call)));
            assert!(first.calls.values().all(|returned| {
                let output = returned.output();
                output.checkpoint.is_none() && output.reasons.is_empty() && output.evidence.is_empty()
            }));
            assert_eq!(
                first
                    .batches
                    .as_ref()
                    .ok_or("constant output absent")?
                    .iter()
                    .map(RecordBatch::num_rows)
                    .sum::<usize>(),
                1
            );
            assert_eq!(fixture.store.meta()?, registered);
            assert!(fixture.store.processor_result(&fixture.scope())?.is_none());
            drop(first);
        }
        drop((streams, members, update, owner));
        fixture.released()?;
    }
    Ok(())
}

#[tokio::test]
async fn native_setup_skips_retirement() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    fixture
        .store
        .register_processor(&fixture.scope(), ProcessorClassV1::Required, 1)?;
    let owner = fixture.constant_owner("SELECT CAST(1 AS BIGINT UNSIGNED) AS value")?;
    let tenant = fixture.source.tenant_id;
    let control = Arc::new(AnalysisReadControl::default());
    let mut members = Members::new();
    let mut streams = owner.sources(&control).await?;
    let active = registry(&mut streams, tenant).await?;
    assert_eq!(
        DiscoveryOwner::identities(&active)?.as_slice(),
        std::slice::from_ref(&fixture.source)
    );
    fixture.store.retire_required(&ProcessorRetirementV1 {
        scope: fixture.scope(),
        change_id: "retire-before-setup".into(),
        reason: "Stop this source before setup.".into(),
        expected_cursor: 0,
        cutoff_cursor: 1,
    })?;
    let retired = fixture.store.meta()?;
    let retirement = fixture.store.processor_retirement(&fixture.scope())?;
    owner
        .derive(&mut members, tenant, &active, &control)
        .await?;
    assert_eq!(streams.len(), 1);
    assert!(members.is_empty());
    assert_eq!(fixture.store.meta()?, retired);
    assert_eq!(
        fixture.store.processor_retirement(&fixture.scope())?,
        retirement
    );
    let available = fixture.query.reserve_stream(tenant)?;
    assert!(fixture.query.reserve_stream(tenant).is_err());
    drop(available);
    let removed = registry(&mut streams, tenant).await?;
    assert!(DiscoveryOwner::identities(&removed)?.is_empty());
    owner
        .derive(&mut members, tenant, &removed, &control)
        .await?;
    assert_eq!(streams.len(), 1);
    assert_eq!(fixture.store.meta()?, retired);
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    let record = fixture.records.get(&1).ok_or("fixture record absent")?;
    fixture.store.accept_validated_batch(
        other.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1_000_000_000,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    let added = registry(&mut streams, tenant).await?;
    assert_eq!(
        DiscoveryOwner::identities(&added)?.as_slice(),
        std::slice::from_ref(&other)
    );
    owner.derive(&mut members, tenant, &added, &control).await?;
    assert_eq!(streams.len(), 1);
    assert_eq!(members.len(), 1);
    assert!(members.contains(&other));
    assert!(
        fixture
            .store
            .managed_instance(tenant, &DiscoveryOwner::instance_id(&other), &control,)?
            .ok_or("replacement source")?
            .running
    );
    let mut profile = owner
        .package(tenant)?
        .subscribe(Some(&other), false)
        .await?;
    let update = tokio::time::timeout(Duration::from_secs(90), profile.next())
        .await?
        .ok_or("replacement source update absent")??;
    assert_eq!(update.calls.len(), 1);
    let (_, call) = owner.package(tenant)?.prepared().await?;
    assert!(update
        .calls
        .get(&call.id())
        .is_some_and(|returned| returned.belongs_to(call)));
    assert!(update.calls.values().all(|returned| {
        let output = returned.output();
        output.checkpoint.is_none() && output.reasons.is_empty() && output.evidence.is_empty()
    }));
    assert_eq!(
        update
            .batches
            .as_ref()
            .ok_or("replacement source output absent")?
            .iter()
            .map(RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    assert_eq!(
        fixture.store.processor_retirement(&fixture.scope())?,
        retirement
    );
    profile.cancel_and_join().await?;
    drop((update, streams, members, active, removed, added, owner));
    fixture.released()?;
    Ok(())
}

#[test]
fn owner_registration_is_balanced() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    let other = Fixture::new(Limits::default())?;
    other.store.install_package_image(
        [42; 16],
        &PackageBundle::try_from(Package::discovery_bundle()?)?,
        || Ok(()),
    )?;
    let authority: Arc<dyn PackageAuthorization> = Arc::new(Authority(watch::channel(0).0));
    let host = InstanceHost::new(Arc::clone(&fixture.query), Arc::clone(&authority));
    let package = |query: &Arc<Engine>, tenant| {
        Package::new(
            Arc::clone(query),
            Arc::clone(&authority),
            PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant(tenant),
                expires_utc_ns: None,
                authorization_id: None,
            },
            Arc::new(PackageBundle::try_from(Package::discovery_bundle()?)?),
            "live",
            "snapshot",
        )
    };
    assert!(!fixture.store.discovery_enabled());
    assert!(matches!(
        DiscoveryOwner::new(Vec::new(), Arc::clone(&host)),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Invalid,
                field: "discovery packages",
                ..
            }
        })
    ));
    assert!(matches!(
        DiscoveryOwner::new(
            vec![
                package(&fixture.query, fixture.source.tenant_id)?,
                package(&fixture.query, fixture.source.tenant_id)?,
            ],
            Arc::clone(&host)
        ),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Invalid,
                field: "duplicate discovery tenant",
                ..
            }
        })
    ));
    assert!(matches!(
        DiscoveryOwner::new(
            vec![
                package(&fixture.query, fixture.source.tenant_id)?,
                package(&other.query, [42; 16])?,
            ],
            Arc::clone(&host)
        ),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Invalid,
                field: "discovery query owner",
                ..
            }
        })
    ));
    let owned = package(&fixture.query, fixture.source.tenant_id)?;
    let before = fixture.store.meta()?;
    let other_before = other.store.meta()?;
    assert!(matches!(
        DiscoveryOwner::new(
            vec![owned],
            InstanceHost::new(Arc::clone(&other.query), Arc::clone(&authority)),
        ),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Conflict,
                field: "managed host query owner",
                ..
            }
        })
    ));
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(other.store.meta()?, other_before);
    let mut expired = package(&fixture.query, fixture.source.tenant_id)?;
    expired.grant.expires_utc_ns = Some(0);
    assert!(matches!(
        DiscoveryOwner::new(vec![expired], Arc::clone(&host)),
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Denied,
                field: "package grant",
                ..
            }
        })
    ));
    assert!(!fixture.store.discovery_enabled());
    assert!(!other.store.discovery_enabled());
    let first = DiscoveryOwner::new(
        vec![package(&fixture.query, fixture.source.tenant_id)?],
        Arc::clone(&host),
    )?;
    let second = DiscoveryOwner::new(
        vec![package(&fixture.query, fixture.source.tenant_id)?],
        host,
    )?;
    assert!(fixture.store.discovery_enabled());
    drop(first);
    assert!(fixture.store.discovery_enabled());
    drop(second);
    assert!(!fixture.store.discovery_enabled());
    fixture.released()?;
    other.released()?;
    Ok(())
}

#[tokio::test]
async fn removed_source_keeps_sibling() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    fixture
        .store
        .register_processor(&fixture.scope(), ProcessorClassV1::Required, 1)?;
    let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
    let control = Arc::new(AnalysisReadControl::default());
    let mut streams = owner.sources(&control).await?;
    let initial = registry(&mut streams, fixture.source.tenant_id).await?;
    let mut members = Members::new();
    owner
        .derive(&mut members, fixture.source.tenant_id, &initial, &control)
        .await?;
    let package = owner.package(fixture.source.tenant_id)?;
    let id = DiscoveryOwner::instance_id(&fixture.source);
    let admitted = fixture
        .store
        .managed_instance(fixture.source.tenant_id, &id, &control)?
        .ok_or("source job")?;
    let removed = owner
        .host
        .remove(
            package.grant.clone(),
            id.clone(),
            admitted.lifecycle,
            &control,
        )
        .await?;
    assert!(removed.removed);
    assert!(!removed.running);
    members.clear();
    let before = fixture.store.meta()?;
    owner
        .derive(&mut members, fixture.source.tenant_id, &initial, &control)
        .await?;
    assert!(members.contains(&fixture.source));
    assert_eq!(fixture.store.meta()?, before);
    assert_eq!(
        fixture
            .store
            .managed_instance(fixture.source.tenant_id, &id, &control)?,
        Some(removed.clone())
    );
    let sibling = EvidenceIntakeIdentityV1 {
        source_id: [44; 16],
        ..fixture.source.clone()
    };
    let record = fixture.records.get(&1).ok_or("fixture record")?;
    fixture.store.accept_validated_batch(
        sibling.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: record.id.cpu_id,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 2,
            frame_ends: vec![record.wire_record.len()],
            framed_records: record.wire_record.clone().into(),
        },
    )?;
    let added = loop {
        let update = registry(&mut streams, fixture.source.tenant_id).await?;
        if DiscoveryOwner::identities(&update)?.contains(&sibling) {
            break update;
        }
    };
    owner
        .derive(&mut members, fixture.source.tenant_id, &added, &control)
        .await?;
    assert!(members.contains(&fixture.source));
    assert!(members.contains(&sibling));
    assert!(
        fixture
            .store
            .managed_instance(
                fixture.source.tenant_id,
                &DiscoveryOwner::instance_id(&sibling),
                &control
            )?
            .ok_or("sibling job")?
            .running
    );
    assert_eq!(
        fixture
            .store
            .managed_instance(fixture.source.tenant_id, &id, &control)?,
        Some(removed.clone())
    );
    fixture.store.retire_required(&ProcessorRetirementV1 {
        scope: fixture.scope(),
        change_id: "retire-removed".into(),
        reason: "Retire this source processor.".into(),
        expected_cursor: 0,
        cutoff_cursor: 1,
    })?;
    let retired = loop {
        let update = registry(&mut streams, fixture.source.tenant_id).await?;
        if !DiscoveryOwner::identities(&update)?.contains(&fixture.source) {
            break update;
        }
    };
    owner
        .derive(&mut members, fixture.source.tenant_id, &retired, &control)
        .await?;
    assert!(!members.contains(&fixture.source));
    assert!(members.contains(&sibling));
    assert_eq!(
        fixture
            .store
            .managed_instance(fixture.source.tenant_id, &id, &control)?,
        Some(removed)
    );
    drop((streams, owner));
    fixture.released()?;
    Ok(())
}
