use super::*;

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use araphor_analysis_sdk as sdk;
use araphor_data::{
    AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1, PackageRefV1,
};
use araphor_package::{PackageArtifactV1, PackageBundleV1, PackageImplementationV1, SqlModelV1};
use araphor_query::follow::{Subscription, Update};
use futures_util::{FutureExt as _, StreamExt as _};
use sdk::arrow_array::UInt64Array;

struct Grant {
    digest: String,
    revoked: AtomicBool,
    trusted: AtomicBool,
    changes: tokio::sync::watch::Sender<u64>,
}

impl PackageAuthorization for Grant {
    fn check(&self, grant: &PackageGrantV1, action: PackageActionV1) -> araphor_data::Result<()> {
        if self.revoked.load(Ordering::SeqCst) || action != PackageActionV1::Run {
            return Err(Code::Denied.error("subscription fixture authority"));
        }
        grant.remaining().map(|_| ())
    }

    fn admit(&self, _: &PackageGrantV1, bundle: &PackageBundle) -> araphor_data::Result<()> {
        if !self.trusted.load(Ordering::SeqCst) || bundle.digest() != self.digest {
            return Err(Code::Denied.error("subscription fixture trust"));
        }
        Ok(())
    }

    fn commit(
        &self,
        grant: &PackageGrantV1,
        action: PackageActionV1,
        bundle: &PackageBundle,
        operation: &mut dyn FnMut() -> araphor_data::Result<()>,
    ) -> araphor_data::Result<()> {
        self.check(grant, action)?;
        self.admit(grant, bundle)?;
        operation()
    }

    fn changes(&self) -> tokio::sync::watch::Receiver<u64> {
        self.changes.subscribe()
    }
}

struct Fixture {
    package: Package,
    authority: Arc<Grant>,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new(bundle: PackageBundleV1, export: &str, output: &str) -> TestResult<Self> {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        let bundle = Arc::new(PackageBundle::try_from(bundle)?);
        store.install_package_image([1; 16], &bundle, || Ok(()))?;
        store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: [1; 16],
                owner_id: "subscription-fixture".into(),
                entity_key: vec![7],
                lifetime_key: vec![1],
                owner_revision: 7,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            body: vec![7],
        })?;
        let authority = Arc::new(Grant {
            digest: bundle.digest().into(),
            revoked: AtomicBool::new(false),
            trusted: AtomicBool::new(true),
            changes: tokio::sync::watch::channel(0).0,
        });
        let package = Package::new(
            Engine::new(store, Default::default())?,
            authority.clone(),
            PackageGrantV1 {
                principal: "fixture".into(),
                revision: 1,
                selection: AnalysisSelectionV1::tenant([1; 16]),
                expires_utc_ns: None,
                authorization_id: None,
            },
            bundle,
            export,
            output,
        )?;
        Ok(Self {
            package,
            authority,
            _directory: directory,
        })
    }

    fn bundle(target: &str) -> TestResult<PackageBundleV1> {
        let schema = sdk::Schema::new(vec![AnalysisStore::table_schemas()["context_versions"]
            .field_with_name("owner_revision")?
            .clone()]);
        let port = sdk::Port::new("context_versions", schema);
        let metadata = sdk::Port::new(
            "metadata",
            sdk::Schema::new(vec![
                sdk::Field::new("dataset", sdk::DataType::Utf8, false),
                sdk::Field::new("revision", sdk::DataType::Utf8, false),
                sdk::Field::new("coverage", sdk::DataType::Utf8, false),
            ]),
        );
        let mut model = sdk::Model::new("echo-inputs", vec![port.clone()], vec![port, metadata]);
        model.input_mode = sdk::InputMode::Resolved;
        let implementation = match target {
            "sql" => PackageImplementationV1::Sql {
                export: model.name.clone(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([
                        ("context_versions".into(), "SELECT owner_revision FROM context_versions".into()),
                        ("metadata".into(), "SELECT CAST('context_versions' AS VARCHAR) AS dataset, CAST('sql' AS VARCHAR) AS revision, CAST('sql' AS VARCHAR) AS coverage".into()),
                    ]),
                    ..Default::default()
                },
            },
            "wasm" => PackageImplementationV1::Wasm {
                exports: vec![model.name.clone()],
                artifact: araphor_analysis_builtins::components::RUNTIME.to_vec(),
            },
            _ => return Err("fixture target".into()),
        };
        Ok(PackageBundleV1 {
            schema_version: 1,
            root: PackageRefV1 {
                package_id: "runtime-fixture".into(),
                revision: "1".into(),
            },
            artifacts: vec![PackageArtifactV1 {
                descriptor: sdk::Package::new("runtime-fixture", "1", vec![model]),
                implementations: vec![implementation],
                fixtures: Vec::new(),
            }],
        })
    }

    async fn next(stream: &mut Subscription) -> TestResult<Update> {
        tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("subscription ended")?
            .map_err(Into::into)
    }
}

#[tokio::test]
async fn subscriptions_use_native_calls() -> TestResult {
    for target in ["sql", "wasm"] {
        captures_inputs(target).await?;
    }
    Ok(())
}

async fn captures_inputs(target: &str) -> TestResult {
    let fixture = Fixture::new(Fixture::bundle(target)?, "echo-inputs", "context_versions")?;
    let package = &fixture.package;
    let initial = package.query.store().meta()?;
    let mut stream = package.subscribe(None, true).await?;
    let update = Fixture::next(&mut stream).await?;
    let (prepared, call) = package.prepared.get().ok_or("admission")?;
    let returned = update.calls.get(&call.id()).ok_or("admitted call return")?;
    assert!(returned.belongs_to(call), "{target}");
    assert!(
        update.calls.values().all(|returned| {
            let output = returned.output();
            output.checkpoint.is_none() && output.reasons.is_empty() && output.evidence.is_empty()
        }),
        "{target}"
    );
    assert_eq!(update.calls.len(), 1);
    assert_eq!(returned.output().datasets.len(), 2, "{target}");
    let mut revisions = returned.evaluation().inputs[0]
        .data
        .batches
        .iter()
        .map(|batch| {
            batch
                .column(0)
                .as_any()
                .downcast_ref::<UInt64Array>()
                .ok_or("UInt64 input")
                .map(|array| array.values().to_vec())
        })
        .collect::<std::result::Result<Vec<_>, _>>()?
        .into_iter()
        .flatten()
        .collect::<Vec<_>>();
    revisions.sort_unstable();
    assert_eq!(revisions, [1, 7], "{target}");
    assert!(prepared.sources().contains_key("context_versions"));
    assert_eq!(
        update.snapshot.page.extraction.meta.commit_revision,
        initial.commit_revision
    );
    let contexts = update.snapshot.contexts().collect::<Vec<_>>();
    assert_eq!(contexts.len(), 2);
    assert!(contexts.iter().any(|reference| {
        reference.key.tenant_id == [1; 16]
            && reference.key.owner_id == "subscription-fixture"
            && reference.key.entity_key == [7]
            && reference.key.lifetime_key == [1]
            && reference.key.owner_revision == 7
            && reference.commit_revision <= initial.commit_revision
    }));
    let expected = AnalysisContextVersionV1::from_package(
        &package.bundle,
        package.grant.selection.tenant_id,
        &package.bundle.bundle().root,
        &package.export,
        &package.output,
    )?;
    assert_eq!(
        package.query.store().context_version(&expected.key)?,
        Some(expected.clone())
    );
    let retained = package.query.store().intern_context(&expected)?;
    assert_eq!(package.query.store().meta()?, initial);
    assert!(contexts.iter().any(|reference| **reference == retained));
    assert_eq!(
        prepared.resolved().images[0].image,
        package.bundle.bundle().root
    );
    assert_eq!(
        prepared.resolved().images[0].digest,
        package.bundle.digest()
    );
    let digest = prepared.resolved().digest()?;
    assert_eq!(
        package.query.store().definition(
            [1; 16],
            &prepared.resolved().definition.name,
            Some(&digest),
            &AnalysisReadControl::default()
        )?,
        None
    );
    assert_eq!(package.query.store().meta()?, initial);
    let saved = prepared as *const PreparedDefinition;
    let before = package.query.store().meta()?;
    let second = package.subscribe(None, false).await?;
    assert_eq!(
        saved,
        &package.prepared.get().ok_or("readmission")?.0 as *const PreparedDefinition
    );
    assert_eq!(package.query.store().meta()?, before);
    drop(second);
    assert!(stream.next().now_or_never().is_none(), "{target}");
    drop(stream);
    Ok(())
}

#[tokio::test]
async fn subscription_retains_current_authority() -> TestResult {
    let fixture = Fixture::new(Fixture::bundle("wasm")?, "echo-inputs", "context_versions")?;
    let mut stream = fixture.package.subscribe(None, true).await?;
    let update = Fixture::next(&mut stream).await?;
    let (_, call) = fixture.package.prepared.get().ok_or("admission")?;
    assert!(update
        .calls
        .get(&call.id())
        .is_some_and(|returned| returned.belongs_to(call)));
    assert!(update.calls.values().all(|returned| {
        let output = returned.output();
        output.checkpoint.is_none() && output.reasons.is_empty() && output.evidence.is_empty()
    }));
    drop(update);
    assert!(stream.next().now_or_never().is_none());
    let before = fixture.package.query.store().meta()?;
    fixture.authority.revoked.store(true, Ordering::SeqCst);
    fixture.authority.changes.send_replace(1);
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("revoked subscription ended")?
        .err()
        .ok_or("revoked subscription continued")?;
    assert_eq!(
        araphor_query::Failure::from(&error),
        araphor_query::Failure::Denied
    );
    let mut called = false;
    assert!(fixture
        .package
        .commit(|| {
            called = true;
            Ok(())
        })
        .is_err());
    assert!(!called);
    assert!(fixture.package.subscribe(None, false).await.is_err());
    assert_eq!(fixture.package.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn subscription_expiry_reaches_stream() -> TestResult {
    let mut fixture = Fixture::new(Fixture::bundle("sql")?, "echo-inputs", "context_versions")?;
    let mut warm = fixture.package.subscribe(None, false).await?;
    Fixture::next(&mut warm).await?;
    drop(warm);
    let before = fixture.package.query.store().meta()?;
    let now = u64::try_from(SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos())?;
    fixture.package.grant.expires_utc_ns = Some(now.checked_add(50_000_000).ok_or("expiry")?);
    let mut stream = fixture.package.subscribe(None, true).await?;
    let mut result = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("expiry stream ended")?;
    if result.is_ok() {
        result = tokio::time::timeout(Duration::from_secs(30), stream.next())
            .await?
            .ok_or("expiry stream ended")?;
    }
    assert_eq!(
        araphor_query::Failure::from(&result.err().ok_or("expiry ignored")?),
        araphor_query::Failure::DeadlineExceeded
    );
    assert_eq!(fixture.package.query.store().meta()?, before);
    Ok(())
}

#[tokio::test]
async fn subscription_checks_return_admission() -> TestResult {
    let first = Fixture::new(Fixture::bundle("sql")?, "echo-inputs", "context_versions")?;
    let second = Fixture::new(Fixture::bundle("sql")?, "echo-inputs", "context_versions")?;
    let mut first_stream = first.package.subscribe(None, false).await?;
    let mut second_stream = second.package.subscribe(None, false).await?;
    let mut update = Fixture::next(&mut first_stream).await?;
    let (_, call) = first.package.prepared.get().ok_or("admission")?;
    assert!(update
        .calls
        .get(&call.id())
        .is_some_and(|returned| returned.belongs_to(call)));
    assert!(update.calls.values().all(|returned| {
        let output = returned.output();
        output.checkpoint.is_none() && output.reasons.is_empty() && output.evidence.is_empty()
    }));
    update.calls = Fixture::next(&mut second_stream).await?.calls;
    assert!(update
        .calls
        .get(&call.id())
        .is_none_or(|returned| !returned.belongs_to(call)));
    Ok(())
}

#[tokio::test]
async fn subscription_rejects_reachable_state() -> TestResult {
    for dependency in [false, true] {
        let mut bundle = Fixture::bundle("sql")?;
        let artifact = &mut bundle.artifacts[0];
        let schema = artifact.descriptor.exports[0].outputs[0].schema.clone();
        let spec = sdk::CheckpointSpec {
            version: 1,
            datasets: vec![sdk::Port::new("state", schema)],
        };
        if dependency {
            let mut inner = artifact.descriptor.exports[0].clone();
            inner.name = "inner".into();
            inner.outputs.truncate(1);
            inner.checkpoint = Some(spec);
            artifact.descriptor.exports[0].inputs[0].source =
                sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
                    package: bundle.root.package_id.clone(),
                    revision: bundle.root.revision.clone(),
                    export: "inner".into(),
                    output: "context_versions".into(),
                }));
            artifact.descriptor.exports.push(inner);
            artifact.implementations.push(PackageImplementationV1::Sql {
                export: "inner".into(),
                program: SqlModelV1 {
                    outputs: BTreeMap::from([(
                        "context_versions".into(),
                        "SELECT owner_revision FROM context_versions".into(),
                    )]),
                    checkpoint: BTreeMap::from([(
                        "state".into(),
                        "SELECT owner_revision FROM output_context_versions".into(),
                    )]),
                    ..Default::default()
                },
            });
        } else {
            artifact.descriptor.exports[0].checkpoint = Some(spec);
            let PackageImplementationV1::Sql { program, .. } = &mut artifact.implementations[0]
            else {
                return Err("SQL".into());
            };
            program.checkpoint.insert(
                "state".into(),
                "SELECT owner_revision FROM output_context_versions".into(),
            );
        }
        let fixture = Fixture::new(bundle, "echo-inputs", "context_versions")?;
        let before = fixture.package.query.store().meta()?;
        let error = fixture
            .package
            .subscribe(None, false)
            .await
            .err()
            .ok_or("stateful subscription admitted")?;
        assert!(
            format!("{error:?}").contains("subscription checkpoint"),
            "{error:?}"
        );
        assert!(fixture.package.prepared.get().is_none());
        assert_eq!(fixture.package.query.store().meta()?, before);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_subscription_uses_package() -> TestResult {
    let mut descriptor = araphor_analysis_builtins::discovery::Discovery::package();
    descriptor.exports.retain(|model| model.name == "groups");
    let model = descriptor.exports.first_mut().ok_or("groups")?;
    model.input_mode = sdk::InputMode::Resolved;
    for input in &mut model.inputs {
        input.source =
            sdk::InputSource::Query("SELECT arrow_cast('', 'Binary') AS value WHERE FALSE".into());
    }
    let directory = std::path::PathBuf::from(
        std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR")?,
    );
    let artifact =
        std::fs::read(directory.join(format!("discovery.{}", std::env::consts::DLL_EXTENSION)))?;
    let qualification = araphor_package::Qualification::inspect(
        &artifact,
        vec!["groups".into()],
        std::env::var("ARAPHOR_NATIVE_TARGET")?,
    )?;
    let bundle = PackageBundleV1 {
        schema_version: 1,
        root: PackageRefV1 {
            package_id: descriptor.id.clone(),
            revision: descriptor.revision.clone(),
        },
        artifacts: vec![PackageArtifactV1 {
            descriptor,
            implementations: vec![PackageImplementationV1::Native {
                export: "groups".into(),
                artifact,
                qualification: Some(qualification),
            }],
            fixtures: Vec::new(),
        }],
    };
    let fixture = Fixture::new(bundle, "groups", "groups")?;
    let mut stream = fixture.package.subscribe(None, false).await?;
    let update = Fixture::next(&mut stream).await?;
    let (_, call) = fixture.package.prepared.get().ok_or("admission")?;
    let returned = update.calls.get(&call.id()).ok_or("admitted call return")?;
    assert!(returned.belongs_to(call));
    assert!(update.calls.values().all(|returned| {
        let output = returned.output();
        output.checkpoint.is_none() && output.reasons.is_empty() && output.evidence.is_empty()
    }));
    assert_eq!(update.calls.len(), 1);
    assert_eq!(returned.output().datasets.len(), 1);
    assert_eq!(returned.output().datasets[0].name, "groups");
    assert_eq!(
        returned.output().datasets[0]
            .batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        0
    );
    Ok(())
}

#[tokio::test]
async fn subscription_rechecks_image_trust() -> TestResult {
    let fixture = Fixture::new(Fixture::bundle("sql")?, "echo-inputs", "context_versions")?;
    let mut stream = fixture.package.subscribe(None, true).await?;
    Fixture::next(&mut stream).await?;
    let before = fixture.package.query.store().meta()?;
    fixture.authority.trusted.store(false, Ordering::SeqCst);
    fixture.authority.changes.send_replace(1);
    let error = tokio::time::timeout(Duration::from_secs(30), stream.next())
        .await?
        .ok_or("untrusted subscription ended")?
        .err()
        .ok_or("untrusted subscription continued")?;
    assert_eq!(
        araphor_query::Failure::from(&error),
        araphor_query::Failure::Denied
    );
    assert!(fixture.package.subscribe(None, false).await.is_err());
    let mut committed = false;
    assert!(fixture
        .package
        .commit(|| {
            committed = true;
            Ok(())
        })
        .is_err());
    assert!(!committed);
    assert!(fixture.package.prepared.get().is_some());
    assert_eq!(fixture.package.query.store().meta()?, before);
    Ok(())
}

#[test]
fn package_requires_installed_image() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let bundle = Arc::new(PackageBundle::try_from(Fixture::bundle("sql")?)?);
    let authority = Arc::new(Grant {
        digest: bundle.digest().into(),
        revoked: AtomicBool::new(false),
        trusted: AtomicBool::new(true),
        changes: tokio::sync::watch::channel(0).0,
    });
    let before = store.meta()?;
    let result = Package::new(
        Engine::new(Arc::clone(&store), Default::default())?,
        authority,
        PackageGrantV1 {
            principal: "fixture".into(),
            revision: 1,
            selection: AnalysisSelectionV1::tenant([1; 16]),
            expires_utc_ns: None,
            authorization_id: None,
        },
        Arc::clone(&bundle),
        "echo-inputs",
        "context_versions",
    );
    assert!(result.is_err());
    assert!(store
        .package_image(
            [1; 16],
            &bundle.bundle().root.package_id,
            Some(&bundle.bundle().root.revision),
            &AnalysisReadControl::default()
        )?
        .is_none());
    assert_eq!(store.meta()?, before);
    Ok(())
}

#[tokio::test]
async fn cold_subscribe_requires_installation() -> TestResult {
    use erebor_runtime_error::{ErrorExt as _, StatusCode};

    for target in ["sql", "wasm"] {
        let fixture = Fixture::new(Fixture::bundle(target)?, "echo-inputs", "context_versions")?;
        let package = &fixture.package;
        let store = package.query.store();
        assert!(package.prepared.get().is_none());
        let pin = araphor_discovery_definition::ImagePin {
            image: package.bundle.bundle().root.clone(),
            digest: package.bundle.digest().into(),
        };
        let context = AnalysisContextVersionV1::from_package(
            &package.bundle,
            package.grant.selection.tenant_id,
            &pin.image,
            &package.export,
            &package.output,
        )?;
        let original = store
            .context_version(&context.key)?
            .ok_or("package context")?;
        assert_eq!(original, context);
        let rows = store.package_revisions([1; 16])?;
        assert!(!rows.is_empty());
        assert!(store.uninstall_package_image([1; 16], &pin, || Ok(()))?);
        assert!(store
            .package_image(
                [1; 16],
                &pin.image.package_id,
                Some(&pin.image.revision),
                &AnalysisReadControl::default(),
            )?
            .is_none());
        let retained = store
            .retained_package_image([1; 16], &pin, &AnalysisReadControl::default())?
            .ok_or("retained package image")?;
        assert_eq!(
            (
                retained.bundle().schema_version,
                &retained.bundle().root,
                &retained.bundle().artifacts,
            ),
            (
                package.bundle.bundle().schema_version,
                &package.bundle.bundle().root,
                &package.bundle.bundle().artifacts,
            )
        );
        assert_eq!(retained.digest(), pin.digest);
        assert_eq!(store.context_version(&context.key)?, Some(original.clone()));
        assert_eq!(store.package_revisions([1; 16])?, rows);
        let before = store.meta()?;
        let reserved = package.query.memory().input_reserved();
        assert_eq!(reserved, 0);
        let error = package
            .subscribe(None, false)
            .await
            .err()
            .ok_or("cold uninstalled package ran")?;
        assert_eq!(error.status_code(), StatusCode::NotFound);
        assert!(matches!(
            error,
            crate::Error::Query {
                source: araphor_query::Error::Data {
                    source: araphor_data::Error::Package {
                        code: Code::Missing,
                        field: "definition image revision",
                        ..
                    }
                }
            }
        ));
        assert!(package.prepared.get().is_none());
        assert_eq!(package.query.memory().input_reserved(), reserved);
        assert_eq!(store.meta()?, before);
        assert_eq!(store.package_revisions([1; 16])?, rows);
        assert_eq!(store.context_version(&context.key)?, Some(original.clone()));

        store.install_package_image([1; 16], &package.bundle, || Ok(()))?;
        let installed = store.meta()?;
        fixture.authority.trusted.store(false, Ordering::SeqCst);
        let error = package
            .subscribe(None, false)
            .await
            .err()
            .ok_or("untrusted retry ran")?;
        assert!(matches!(
            error,
            crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Denied,
                    field: "subscription fixture trust",
                    ..
                }
            }
        ));
        assert!(package.prepared.get().is_none());
        assert_eq!(package.query.memory().input_reserved(), reserved);
        assert_eq!(store.meta()?, installed);
        assert_eq!(store.package_revisions([1; 16])?, rows);
        fixture.authority.trusted.store(true, Ordering::SeqCst);
        let mut stream = package.subscribe(None, false).await?;
        let update = Fixture::next(&mut stream).await?;
        let (prepared, call) = package.prepared.get().ok_or("retried admission")?;
        assert_eq!(prepared.resolved().images, [pin]);
        assert!(update
            .calls
            .get(&call.id())
            .is_some_and(|result| result.belongs_to(call)));
        assert_eq!(update.calls.len(), 1);
        assert!(update.batches.as_ref().is_some_and(|batches| batches
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>()
            == 2));
        assert_eq!(store.meta()?, installed);
        assert_eq!(store.package_revisions([1; 16])?, rows);
        assert_eq!(store.context_version(&context.key)?, Some(original));
        stream.cancel_and_join().await?;
        fixture.authority.revoked.store(true, Ordering::SeqCst);
        let error = package
            .subscribe(None, false)
            .await
            .err()
            .ok_or("revoked warm package ran")?;
        assert!(matches!(
            error,
            crate::Error::Data {
                source: araphor_data::Error::Package {
                    code: Code::Denied,
                    field: "subscription fixture authority",
                    ..
                }
            }
        ));
        assert_eq!(store.meta()?, installed);
    }
    Ok(())
}
