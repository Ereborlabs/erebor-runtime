use std::collections::BTreeMap;
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_analysis_sdk::arrow_array::{RecordBatch, StructArray, UInt64Array};
use araphor_analysis_sdk::DataType;
use araphor_data::{
    AnalysisSelectionV1, AnalysisStore, DiscoveryInputManifestV1, DiscoveryProfileV1,
    DiscoveryRecordV1, PackageActionV1, PackageAuthorization, PackageBundleRef, PackageGrantV1,
    ProcessorClassV1, ProcessorRetirementV1, ProcessorScopeV1, ValidatedEvidenceBatchV1,
    DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};
use araphor_package::{
    PackageArtifactV1, PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
    SqlReasonV1,
};
use araphor_query::execution::{Engine, Limits};
use araphor_query::follow::Operation;

use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error + Send + Sync>>;

struct Authority(watch::Sender<u64>);

impl PackageAuthorization for Authority {
    fn check(&self, _: &PackageGrantV1, _: PackageActionV1) -> araphor_data::Result<()> {
        Ok(())
    }
    fn admit(&self, _: &PackageGrantV1, _: &PackageBundleRef<'_>) -> araphor_data::Result<()> {
        Ok(())
    }
    fn commit(
        &self,
        _: &PackageGrantV1,
        _: PackageActionV1,
        _: &PackageBundleRef<'_>,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
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
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        store.install_package_image(source.tenant_id, &Package::discovery_bundle()?, || Ok(()))?;
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
        Ok(DiscoveryOwner::new(vec![Package::new(
            Arc::clone(&self.query),
            Arc::new(Authority(watch::channel(0).0)),
            PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection,
                expires_utc_ns: None,
                authorization_id: None,
            },
            crate::Package::discovery_bundle()?,
            "live",
            "snapshot",
        )?])?)
    }

    fn constant_owner(&self, sql: &str) -> TestResult<DiscoveryOwner> {
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
        self.store
            .install_package_image(self.source.tenant_id, &bundle, || Ok(()))?;
        Ok(DiscoveryOwner::new(vec![Package::new(
            Arc::clone(&self.query),
            Arc::new(Authority(watch::channel(0).0)),
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
        )?])?)
    }

    fn scope(&self) -> ProcessorScopeV1 {
        ProcessorScopeV1 {
            processor_id: DISCOVERY_PROCESSOR.into(),
            method_version: u64::from(DISCOVERY_SCHEMA_VERSION),
            identity: self.source.clone(),
        }
    }

    fn append(&self, cursor: u64) -> TestResult {
        let record = self.records.get(&cursor).ok_or("fixture cursor absent")?;
        self.store.accept_validated_batch(
            self.source.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: record.id.cpu_id,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor * 1_000_000_000,
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
    let stream = streams
        .iter_mut()
        .find_map(|entry| (entry.key == Pipeline::Sources(tenant)).then_some(&mut entry.stream))
        .ok_or("registry absent")?;
    tokio::time::timeout(Duration::from_secs(90), async {
        loop {
            let update = stream.next().await.ok_or("registry ended")??;
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
    assert_eq!(owner.process(&fixture.source).await?, 1);
    let first = owner.profile(&fixture.source)?.ok_or("first profile")?;
    assert_eq!(first.snapshot.accepted_records, 1);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("finite processor")?
            .consumed_cursor,
        1
    );
    let before = fixture.store.meta()?;
    assert_eq!(owner.process(&fixture.source).await?, 0);
    assert_eq!(fixture.store.meta()?, before);
    fixture.append(2)?;
    assert_eq!(owner.process(&fixture.source).await?, 1);
    let next = owner.profile(&fixture.source)?.ok_or("next profile")?;
    assert_eq!(next.profile_id, first.profile_id);
    assert_eq!(next.revision, first.revision + 1);
    assert_eq!(next.snapshot.accepted_records, 2);
    assert!(next.updated_utc_ns >= first.updated_utc_ns);
    let mut other = fixture.source.clone();
    other.node_id.push_str("-other");
    let before = fixture.store.meta()?;
    assert!(owner.profile(&other).is_err());
    assert!(owner.process(&other).await.is_err());
    assert_eq!(fixture.store.meta()?, before);
    drop(owner);
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
    let mut streams = owner.sources().await?;
    assert!(streams
        .iter()
        .all(|entry| entry.stream.moving_resolution_ns().is_none()));
    let empty = registry(&mut streams, tenant).await?;
    assert!(DiscoveryOwner::identities(&empty)?.is_empty());
    owner.derive(&mut streams, tenant, &empty).await?;
    drop(empty);
    assert_eq!(streams.len(), 1);
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
    assert!(owner.derive(&mut streams, tenant, &added).await.is_err());
    assert_eq!(streams.len(), 1);
    added.limited = false;
    let registered = fixture.store.meta()?;
    owner.derive(&mut streams, tenant, &added).await?;
    owner.derive(&mut streams, tenant, &added).await?;
    assert_eq!(fixture.store.meta()?, registered);
    assert_eq!(
        fixture
            .store
            .processor_health(&fixture.scope())?
            .ok_or("required processor absent")?
            .class,
        ProcessorClassV1::Required
    );
    drop(added);
    assert_eq!(streams.len(), 2);
    assert!(streams
        .iter()
        .any(|entry| entry.key == Pipeline::Profile(fixture.source.clone())));
    assert!(streams
        .iter()
        .all(|entry| entry.stream.moving_resolution_ns().is_none()));
    assert!(fixture.query.reserve_stream(tenant).is_err());
    let update = tokio::time::timeout(
        Duration::from_secs(90),
        streams
            .iter_mut()
            .find_map(|entry| {
                (entry.key == Pipeline::Profile(fixture.source.clone()))
                    .then_some(&mut entry.stream)
            })
            .ok_or("profile stream absent")?
            .next(),
    )
    .await?
    .ok_or("profile stream ended")??;
    assert_eq!(
        DiscoveryOwner::publish(Arc::clone(owner.package(tenant)?), update).await?,
        1
    );
    let profile = fixture.profile()?.ok_or("profile absent")?;
    assert_eq!(owner.profile(&fixture.source)?, Some(profile.clone()));
    assert_eq!(profile.snapshot.accepted_records, 1);
    assert_eq!(profile.snapshot.unresolved_records, 1);
    assert!(!profile.snapshot.coverage.is_empty());
    fixture.append(2)?;
    let stale = tokio::time::timeout(
        Duration::from_secs(90),
        streams
            .iter_mut()
            .find_map(|entry| {
                (entry.key == Pipeline::Profile(fixture.source.clone()))
                    .then_some(&mut entry.stream)
            })
            .ok_or("profile stream absent")?
            .next(),
    )
    .await?
    .ok_or("profile stream ended")??;
    assert!(stale.batches.is_some());
    assert!(stale
        .snapshot
        .page
        .extraction
        .sources
        .iter()
        .any(|source| source.receipt.contiguous_cursor == 2));
    fixture.store.retire_required(&ProcessorRetirementV1 {
        scope: fixture.scope(),
        change_id: "retire-native".into(),
        reason: "Retire this source processor.".into(),
        expected_cursor: 1,
        cutoff_cursor: 2,
    })?;
    let retired = fixture.store.meta()?;
    assert!(matches!(
        DiscoveryOwner::publish(Arc::clone(owner.package(tenant)?), stale).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::AnalysisConflict { .. }
        })
    ));
    assert_eq!(fixture.store.meta()?, retired);
    assert_eq!(fixture.profile()?, Some(profile));
    let removed = registry(&mut streams, tenant).await?;
    assert!(DiscoveryOwner::identities(&removed)?.is_empty());
    owner.derive(&mut streams, tenant, &removed).await?;
    drop(removed);
    assert!(!streams
        .iter()
        .any(|entry| entry.key == Pipeline::Profile(fixture.source.clone())));
    assert_eq!(streams.len(), 1);
    let available = fixture.query.reserve_stream(tenant)?;
    assert!(fixture.query.reserve_stream(tenant).is_err());
    drop(available);
    let before = fixture.store.meta()?;
    assert!(fixture
        .store
        .register_processor(&fixture.scope(), ProcessorClassV1::Required, 1)
        .is_err());
    assert_eq!(fixture.store.meta()?, before);
    drop(streams);
    drop(owner);
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_run_stops() -> TestResult {
    let fixture = Fixture::new(Limits {
        input_capacity: Some(128 * 1024 * 1024),
        output_capacity: Some(16 * 1024 * 1024),
        ..Default::default()
    })?;
    let owner = Arc::new(fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?);
    let (stop, stopped) = watch::channel(false);
    let mut notices = fixture.store.subscribe_revision();
    let mut worker = tokio::spawn(Arc::clone(&owner).run(stopped));
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
    drop(owner);
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_source_scope_rejection() -> TestResult {
    let fixture = Fixture::new(Limits::default())?;
    fixture.append(1)?;
    let tenant = fixture.source.tenant_id;
    let owner = fixture.owner(AnalysisSelectionV1::tenant(tenant))?;
    let package = owner.package(tenant)?;
    let mut stream = package.subscribe(Some(&fixture.source), false).await?;
    let update = tokio::time::timeout(Duration::from_secs(90), stream.next())
        .await?
        .ok_or("profile stream ended")??;
    let other = EvidenceIntakeIdentityV1 {
        source_id: [8; 16],
        ..fixture.source.clone()
    };
    let batch = update
        .batches
        .as_ref()
        .and_then(|batches| batches.first())
        .ok_or("publication absent")?;
    let unregistered: Vec<Publication> = serde_arrow::from_record_batch(batch)?;
    assert_eq!(unregistered.len(), 1);
    let before = fixture.store.meta()?;
    assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
    for row in unregistered {
        assert!(matches!(
            row.commit(package, &update),
            Err(crate::Error::Data {
                source: araphor_data::Error::AnalysisConflict { .. }
            })
        ));
    }
    assert_eq!(fixture.store.meta()?, before);
    assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
    let source = batch.schema().index_of("source")?;
    let DataType::Struct(fields) = batch.schema().field(source).data_type().clone() else {
        return Err("source schema is not a struct".into());
    };
    let foreign = serde_arrow::to_record_batch(&fields, &std::slice::from_ref(&other))?;
    let mut columns = batch.columns().to_vec();
    columns[source] = Arc::new(StructArray::from(foreign));
    let changed = RecordBatch::try_new(batch.schema(), columns)?;
    let rows: Vec<Publication> = serde_arrow::from_record_batch(&changed)?;
    assert_eq!(rows.len(), 1);
    let before = fixture.store.meta()?;
    for row in rows {
        assert!(matches!(
            row.commit(package, &update),
            Err(crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Denied,
                    field: "captured discovery source",
                    ..
                }
            })
        ));
    }
    assert_eq!(fixture.store.meta()?, before);
    let selected = fixture.owner(AnalysisSelectionV1::new(
        tenant,
        vec![fixture.source.clone()],
    ))?;
    assert!(selected
        .package(tenant)?
        .subscribe(Some(&other), false)
        .await
        .is_err());
    let foreign_tenant = EvidenceIntakeIdentityV1 {
        tenant_id: [9; 16],
        ..fixture.source.clone()
    };
    assert!(package
        .subscribe(Some(&foreign_tenant), false)
        .await
        .is_err());
    drop((stream, update));
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
        bundle,
        "constant",
        "data",
    )?);
    let mut stream = package.subscribe(Some(&fixture.source), true).await?;
    let first = tokio::time::timeout(Duration::from_secs(90), stream.next())
        .await?
        .ok_or("first package update absent")??;
    assert_eq!(first.operation, Operation::Replace);
    assert_eq!(first.calls.len(), 1);
    assert!(package.check_return(&first)?.output().reasons.is_empty());
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
    let before = fixture.store.meta()?;
    assert!(matches!(
        DiscoveryOwner::publish(package, second).await,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: Code::Unsupported,
                field: "discovery auxiliary return",
                ..
            }
        })
    ));
    assert_eq!(fixture.store.meta()?, before);
    drop(stream);
    fixture.released()?;
    Ok(())
}

#[tokio::test]
async fn native_setup_admission_guard() -> TestResult {
    for (sql, error_field) in [
        ("SELECT missing_field AS value FROM events", Some("missing_field")),
        (
            "SELECT CASE WHEN now() IS NOT NULL THEN CAST(1 AS BIGINT UNSIGNED) ELSE CAST(2 AS BIGINT UNSIGNED) END AS value",
            Some("follow clock filter"),
        ),
        ("SELECT CAST(1 AS BIGINT UNSIGNED) AS value", None),
    ] {
        let fixture = Fixture::new(Limits::default())?;
        fixture.append(1)?;
        let owner = fixture.constant_owner(sql)?;
        let tenant = fixture.source.tenant_id;
        let mut streams = owner.sources().await?;
        let update = registry(&mut streams, tenant).await?;
        assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
        let before = fixture.store.meta()?;
        let result = owner.derive(&mut streams, tenant, &update).await;
        if let Some(field) = error_field {
            let error = result.err().ok_or("invalid package admitted")?;
            assert!(format!("{error:?}").contains(field), "{error:?}");
            assert_eq!(fixture.store.meta()?, before);
            assert!(fixture.store.processor_health(&fixture.scope())?.is_none());
            assert_eq!(streams.len(), 1);
        } else {
            result?;
            let registered = fixture.store.meta()?;
            assert_eq!(registered.commit_revision, before.commit_revision + 1);
            let health = fixture
                .store
                .processor_health(&fixture.scope())?
                .ok_or("optional processor absent")?;
            assert_eq!(health.class, ProcessorClassV1::Optional);
            assert_eq!(health.accepted_cursor, 1);
            assert_eq!(health.consumed_cursor, 0);
            assert!(fixture.store.processor_result(&fixture.scope())?.is_none());
            assert_eq!(streams.len(), 2);
            owner.derive(&mut streams, tenant, &update).await?;
            assert_eq!(fixture.store.meta()?, registered);
            let profile = streams
                .iter_mut()
                .find_map(|entry| {
                    (entry.key == Pipeline::Profile(fixture.source.clone()))
                        .then_some(&mut entry.stream)
                })
                .ok_or("profile subscription absent")?;
            let first = tokio::time::timeout(Duration::from_secs(90), profile.next())
                .await?
                .ok_or("first package update absent")??;
            assert_eq!(first.calls.len(), 1);
            owner.package(tenant)?.check_return(&first)?;
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
        drop((streams, update, owner));
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
    let mut streams = owner.sources().await?;
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
    owner.derive(&mut streams, tenant, &active).await?;
    assert_eq!(streams.len(), 1);
    assert!(streams
        .iter()
        .all(|entry| matches!(&entry.key, Pipeline::Sources(_))));
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
    owner.derive(&mut streams, tenant, &removed).await?;
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
    owner.derive(&mut streams, tenant, &added).await?;
    assert_eq!(streams.len(), 2);
    let profile = streams
        .iter_mut()
        .find_map(|entry| {
            (entry.key == Pipeline::Profile(other.clone())).then_some(&mut entry.stream)
        })
        .ok_or("replacement source subscription absent")?;
    let update = tokio::time::timeout(Duration::from_secs(90), profile.next())
        .await?
        .ok_or("replacement source update absent")??;
    assert_eq!(update.calls.len(), 1);
    owner.package(tenant)?.check_return(&update)?;
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
    drop((update, streams, active, removed, added, owner));
    fixture.released()?;
    Ok(())
}
