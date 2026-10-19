use std::collections::BTreeMap;
use std::time::Duration;

use araphor_analysis_sdk::arrow_array::{RecordBatch, StructArray};
use araphor_analysis_sdk::DataType;
use araphor_data::{
    AnalysisSelectionV1, AnalysisStore, DiscoveryInputManifestV1, DiscoveryProfileV1,
    DiscoveryRecordV1, PackageActionV1, PackageAuthorization, PackageBundleRef, PackageGrantV1,
    ProcessorClassV1, ProcessorRetirementV1, ProcessorScopeV1, ValidatedEvidenceBatchV1,
    DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
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
async fn native_source_stream_lifecycle() -> TestResult {
    let fixture = Fixture::new(Limits {
        input_capacity: Some(128 * 1024 * 1024),
        output_capacity: Some(16 * 1024 * 1024),
        ..Default::default()
    })?;
    let owner = fixture.owner(AnalysisSelectionV1::tenant(fixture.source.tenant_id))?;
    let tenant = fixture.source.tenant_id;
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
    owner.derive(&mut streams, tenant, &added).await?;
    owner.derive(&mut streams, tenant, &added).await?;
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
        .await??;
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
    tokio::time::timeout(Duration::from_secs(90), worker).await???;
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
