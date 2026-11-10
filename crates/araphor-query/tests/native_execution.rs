#![cfg(feature = "native-store")]

use std::{collections::BTreeMap, sync::Arc, time::Duration};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::native::NativeStore, AnalysisContextKeyV1, AnalysisContextVersionV1,
    AnalysisReadControl, AnalysisSelectionV1, ContextSensitivityV1, EvidenceIntakeIdentityV1,
    EvidenceRecord, ManagedCall, ManagedDestination, ManagedManifest, ManagedSpec,
    PackageErrorCodeV1 as Code, PackageGrantV1, ValidatedEvidenceBatchV1,
};
use araphor_discovery_definition::{Definition, Program, Source};
use araphor_package::{
    PackageArtifactV1, PackageBundle, PackageBundleV1, PackageImplementationV1, SqlModelV1,
};
use araphor_query::{
    definition::{PackageCall, PreparedDefinition},
    execution::{Engine, Limits},
    follow::{Subscription, SystemClock, Update},
};
use datafusion::logical_expr::UserDefinedLogicalNodeCore as _;
use futures_util::StreamExt as _;
use sdk::arrow_array::{Array, UInt64Array};

#[path = "native_execution/graph.rs"]
mod graph;
#[path = "native_execution/publication.rs"]
mod publication;
#[path = "native_execution/version.rs"]
mod version;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error + Send + Sync>>;
const TENANT: [u8; 16] = [1; 16];
const NOW: u64 = 1_700_000_000_123_456_789;

fn source(tenant: [u8; 16]) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: tenant,
        node_id: "native-query".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn event(store: &NativeStore, tenant: [u8; 16], cursor: u64) -> araphor_data::Result<()> {
    let frame = Vec::<u8>::try_from(&EvidenceRecord {
        task_cookie: cursor,
        observed_boottime_ns: cursor,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        source(tenant),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: cursor,
            last_cursor: cursor,
            intake_utc_ns: NOW + cursor,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    Ok(())
}

fn context(owner: &str, revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: TENANT,
            owner_id: owner.into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    }
}

fn route_context(revision: u64) -> araphor_data::Result<AnalysisContextVersionV1> {
    use araphor_data::{
        ApprovedNotificationRouteV1, NotificationGrantV1, NotificationOperationV1,
        NotificationPolicyV1, NotificationPrincipalV1, NotificationPriorityV1,
        NOTIFICATION_ROUTE_OWNER,
    };
    let route = ApprovedNotificationRouteV1 {
        policy: NotificationPolicyV1 {
            tenant_id: TENANT,
            route_id: "human".into(),
            revision,
            package_ids: vec!["native-fixture".into()],
            minimum_priority: NotificationPriorityV1::Info,
            acknowledgement_ns: 100,
            retry_limit: 3,
            retry_delay_ns: 10,
            escalation_route_id: "human".into(),
            max_sensitivity: ContextSensitivityV1::Tenant,
            allow_concerns: false,
        },
        grant: NotificationGrantV1 {
            tenant_id: TENANT,
            principal_id: [2; 16],
            principal: NotificationPrincipalV1::Human,
            authorization_revision: 1,
            routes: vec!["human".into()],
            operations: vec![NotificationOperationV1::Configure],
            max_sensitivity: ContextSensitivityV1::HostRestricted,
            expires_utc_ns: u64::MAX,
        },
        approved_utc_ns: 1,
    };
    let mut value = context(NOTIFICATION_ROUTE_OWNER, revision);
    value.key.entity_key = b"human".to_vec();
    value.key.lifetime_key = b"route".to_vec();
    value.sensitivity = ContextSensitivityV1::HostRestricted;
    value.body = route.encode()?;
    Ok(value)
}

fn sql(inline: impl Into<String>) -> Definition {
    Definition {
        name: "native-query".into(),
        description: String::new(),
        labels: BTreeMap::new(),
        program: Program::Sql {
            source: Source::Inline {
                inline: inline.into(),
            },
        },
    }
}

fn image() -> araphor_package::Result<PackageBundle> {
    let schema = sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]);
    let descriptor = sdk::Package::new(
        "native-fixture",
        "1",
        vec![sdk::Model::new(
            "copy",
            vec![sdk::Port::new("input", schema.clone())],
            vec![sdk::Port::new("rows", schema)],
        )],
    );
    PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: araphor_package::PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Sql {
                export: "copy".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([("rows".into(), "SELECT value FROM input".into())]),
                    ..Default::default()
                },
            }],
            fixtures: Vec::new(),
        }],
    })
}

async fn specification(
    engine: &Arc<Engine>,
    image: &PackageBundle,
    definition: &Definition,
) -> TestResult<(PreparedDefinition, ManagedSpec)> {
    engine
        .store()
        .install_package_image(TENANT, image, || Ok(()))?;
    let control = AnalysisReadControl::default();
    let definition = engine
        .prepare_definition(TENANT, definition, Arc::new(control))
        .await?;
    let revision = engine
        .store()
        .admit_definition(TENANT, definition.resolved(), || Ok(()))?;
    let mut definition =
        definition.bind_revision(engine, revision, &AnalysisReadControl::default())?;
    engine
        .session(
            AnalysisSelectionV1::tenant(TENANT),
            &AnalysisReadControl::default(),
            NOW,
        )?
        .prepare_execution(&mut definition)
        .await?;
    let mut calls = BTreeMap::new();
    PackageCall::any(definition.plan(), &mut |_, call| {
        let artifact = image
            .bundle()
            .artifacts
            .iter()
            .find(|artifact| {
                artifact.descriptor.id == call.package().package_id
                    && artifact.descriptor.revision == call.package().revision
            })
            .ok_or_else(|| datafusion::common::DataFusionError::Plan("package artifact".into()))?;
        let implementation = artifact
            .implementation(call.export())
            .map_err(|error| datafusion::common::DataFusionError::External(Box::new(error)))?;
        let mut dependencies = std::collections::BTreeSet::new();
        for input in call.inputs() {
            PackageCall::any(input, &mut |_, dependency| {
                if call.id() != dependency.id() {
                    dependencies.insert(dependency.id());
                }
                Ok(false)
            })?;
        }
        calls.insert(
            call.id(),
            ManagedCall {
                image: call.image().clone(),
                package: call.package().clone(),
                export: call.export().into(),
                target: implementation.target().into(),
                artifact: implementation.identity().map_err(|error| {
                    datafusion::common::DataFusionError::External(Box::new(error))
                })?,
                arguments: call.arguments().to_vec(),
                dependencies,
            },
        );
        Ok(false)
    })?;
    let spec = ManagedSpec {
        destination: ManagedDestination::Selected,
        tenant: TENANT,
        id: "native-query".into(),
        definition: definition.resolved().clone(),
        manifest: ManagedManifest {
            format: 1,
            planner: "datafusion-55/sql-call-1".into(),
            definition: revision,
            calls,
            selected_schema: definition.plan().schema().as_arrow().clone(),
        },
    };
    Ok((definition, spec))
}

async fn prepare(
    engine: &Arc<Engine>,
    image: &PackageBundle,
    definition: &Definition,
) -> TestResult<(PreparedDefinition, Arc<publication::Publication>)> {
    let (definition, spec) = specification(engine, image, definition).await?;
    let instance = engine.store().admit_managed(
        &spec,
        &PackageGrantV1 {
            principal: "native-query".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant(TENANT),
            expires_utc_ns: None,
            authorization_id: Some("native-query".into()),
        },
        || Ok(()),
    )?;
    engine.store().set_managed_running(
        TENANT,
        &instance.spec.id,
        instance.lifecycle,
        true,
        || Ok(()),
    )?;
    let publication =
        publication::Publication::new(engine, definition.plan().schema().inner().clone());
    Ok((definition, publication))
}

fn subscribe(
    engine: &Arc<Engine>,
    definition: PreparedDefinition,
    publication: Arc<publication::Publication>,
) -> araphor_query::Result<Subscription> {
    let resume =
        engine
            .store()
            .managed_resume(TENANT, "native-query", &AnalysisReadControl::default())?;
    Subscription::managed(
        engine.session(
            AnalysisSelectionV1::tenant(TENANT),
            &AnalysisReadControl::default(),
            NOW,
        )?,
        definition,
        publication,
        b"native-query",
        resume.frontier,
        Arc::new(SystemClock::default()),
    )
}

async fn next(stream: &mut Subscription) -> TestResult<Update> {
    tokio::time::timeout(Duration::from_secs(10), stream.next())
        .await?
        .ok_or_else(|| "native subscription stopped".into())
        .and_then(|result| result.map_err(Into::into))
}

fn values(batches: &[sdk::RecordBatch]) -> TestResult<Vec<u64>> {
    batches
        .iter()
        .map(|batch| {
            Ok(batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("value")?
                .values()
                .to_vec())
        })
        .collect::<TestResult<Vec<_>>>()
        .map(|chunks| chunks.into_iter().flatten().collect())
}

#[tokio::test]
async fn retained_plan_commits_consumed_inputs_and_resumes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = Arc::new(NativeStore::open(&root)?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    event(&store, TENANT, 1)?;
    store.commit_contexts(&[context("watched", 1)])?;
    let (definition, publication) = prepare(
        &engine,
        &image()?,
        &sql(r#"SELECT * FROM "native-fixture"."1".copy(input => (
            SELECT source_cursor AS value FROM events))
        UNION ALL SELECT * FROM "native-fixture"."1".copy(input => (
            SELECT owner_revision AS value FROM context_versions WHERE owner_id = 'watched'))"#),
    )
    .await?;
    let mut stream = subscribe(&engine, definition.clone(), publication.clone())?;
    let first = next(&mut stream).await?;
    assert_eq!(first.calls.len(), 2);
    publication.assert_consumed(first.cursor.position())?;
    assert!(futures_util::poll!(stream.next()).is_pending());
    event(&store, [9; 16], 1)?;
    store.commit_contexts(&[context("unrelated", 1)])?;
    store.checkpoint_inputs()?;
    assert!(futures_util::poll!(stream.next()).is_pending());
    event(&store, TENANT, 2)?;
    let second = next(&mut stream).await?;
    assert_eq!(second.calls.len(), 2);
    let mut inputs = second
        .calls
        .iter()
        .map(|(id, call)| {
            assert_eq!(
                values(&first.calls[id].evaluation().inputs[0].data.batches)?,
                [1]
            );
            values(&call.evaluation().inputs[0].data.batches)
        })
        .collect::<TestResult<Vec<_>>>()?;
    inputs.sort();
    assert_eq!(inputs, [vec![1], vec![1, 2]]);
    publication.assert_consumed(second.cursor.position())?;
    let mut actual = values(&publication.selected())?;
    actual.sort_unstable();
    assert_eq!(actual, [1, 1, 2]);
    stream.cancel_and_join().await?;
    event(&store, TENANT, 3)?;
    let resolved = definition.resolved().clone();
    let revision = definition.revision();
    drop((first, second, definition, publication, engine, store));
    let store = Arc::new(NativeStore::open(&root)?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    let mut definition = engine
        .session(
            AnalysisSelectionV1::tenant(TENANT),
            &AnalysisReadControl::default(),
            NOW,
        )?
        .prepare_resolved(&resolved, revision, None)
        .await?;
    engine
        .session(
            AnalysisSelectionV1::tenant(TENANT),
            &AnalysisReadControl::default(),
            NOW,
        )?
        .prepare_execution(&mut definition)
        .await?;
    let publication =
        publication::Publication::new(&engine, definition.plan().schema().inner().clone());
    publication
        .later
        .store(4, std::sync::atomic::Ordering::SeqCst);
    let mut stream = subscribe(&engine, definition, publication.clone())?;
    let restored = next(&mut stream).await?;
    publication.assert_consumed(restored.cursor.position())?;
    let mut actual = values(&publication.selected())?;
    actual.sort_unstable();
    assert_eq!(actual, [1, 1, 2, 3]);
    assert!(store.view()?.revision() > restored.cursor.position().commit_revision);
    let later = next(&mut stream).await?;
    publication.assert_consumed(later.cursor.position())?;
    let mut actual = values(&publication.selected())?;
    actual.sort_unstable();
    assert_eq!(actual, [1, 1, 2, 3, 4]);
    stream.cancel_and_join().await?;
    Ok(())
}

#[tokio::test]
async fn mixed_context_tables_consume_the_watched_owner_without_extra_wakes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(NativeStore::open(&directory.path().join("data"))?);
    let engine = Engine::new(store.clone(), Limits::default())?;
    store.commit_contexts(&[context("watched", 1)])?;
    store.commit_contexts(&[route_context(5)?])?;
    let (definition, publication) = prepare(
        &engine,
        &image()?,
        &sql(r#"SELECT * FROM "native-fixture"."1".copy(input => (
            SELECT owner_revision AS value FROM context_versions WHERE owner_id = 'watched'))
        UNION ALL SELECT * FROM "native-fixture"."1".copy(input => (
            SELECT route_revision AS value FROM notification_routes))"#),
    )
    .await?;
    let mut stream = subscribe(&engine, definition, publication.clone())?;
    let first = next(&mut stream).await?;
    publication.assert_consumed(first.cursor.position())?;
    let mut selected = values(&publication.selected())?;
    selected.sort_unstable();
    assert_eq!(selected, [1, 5]);
    assert!(futures_util::poll!(stream.next()).is_pending());
    store.commit_contexts(&[context("unrelated", 1)])?;
    store.checkpoint_inputs()?;
    assert!(futures_util::poll!(stream.next()).is_pending());
    store.commit_contexts(&[context("watched", 2)])?;
    let second = next(&mut stream).await?;
    publication.assert_consumed(second.cursor.position())?;
    let mut selected = values(&publication.selected())?;
    selected.sort_unstable();
    assert_eq!(selected, [1, 2, 5]);
    store.commit_contexts(&[route_context(6)?])?;
    let route_change = next(&mut stream).await?;
    publication.assert_consumed(route_change.cursor.position())?;
    let mut selected = values(&publication.selected())?;
    selected.sort_unstable();
    assert_eq!(selected, [1, 2, 5, 6]);
    stream.cancel_and_join().await?;
    Ok(())
}
