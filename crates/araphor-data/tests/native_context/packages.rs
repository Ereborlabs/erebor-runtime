use super::*;
use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::PackageRevisionV1, AnalysisReadControl, PackageArtifactV1, PackageBundle,
    PackageBundleV1, PackageImplementationV1, PackageRefV1, SqlModelV1,
};

#[path = "packages/closure.rs"]
mod closure;
#[path = "packages/corruption.rs"]
mod corruption;

#[derive(Clone, serde::Deserialize, serde::Serialize)]
struct StoredContext {
    root: PackageRefV1,
    digest: String,
    package: PackageRefV1,
    export: String,
    output: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    generation: Option<u64>,
}

impl StoredContext {
    fn from_context(context: &AnalysisContextVersionV1) -> Result<Self, rmp_serde::decode::Error> {
        rmp_serde::from_slice(&context.body)
    }

    fn encode(&self) -> Result<Vec<u8>, rmp_serde::encode::Error> {
        rmp_serde::to_vec_named(self)
    }
}

fn artifact(id: &str, revision: &str) -> PackageArtifactV1 {
    let mut descriptor = sdk::Package::new(
        id,
        revision,
        vec![sdk::Model::new(
            "model",
            Vec::new(),
            vec![sdk::Port::new("rows", sdk::Schema::empty())],
        )],
    );
    descriptor.exports[0].input_mode = sdk::InputMode::Resolved;
    PackageArtifactV1 {
        descriptor,
        implementations: vec![PackageImplementationV1::Sql {
            export: "model".into(),
            program: SqlModelV1 {
                outputs: std::collections::BTreeMap::from([("rows".into(), "SELECT 1".into())]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    }
}

fn bundle() -> araphor_data::Result<PackageBundle> {
    let mut root = artifact("native-root", "v1");
    let dependency = artifact("native-dependency", "v1");
    root.descriptor.exports[0].inputs.push(sdk::InputPort {
        port: sdk::Port::new("source", sdk::Schema::empty()),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: dependency.descriptor.id.clone(),
            revision: dependency.descriptor.revision.clone(),
            export: "model".into(),
            output: "rows".into(),
        })),
    });
    Ok(PackageBundle::try_from(PackageBundleV1 {
        schema_version: 1,
        root: root.reference(),
        artifacts: vec![root, dependency],
    })?)
}

fn replace_context(store: &NativeStore, input: &AnalysisContextVersionV1) -> TestResult {
    let view = store.view()?;
    for entry in view.snapshot().prefix(b"\0data/C") {
        let (key, bytes) = entry?;
        let (row, revision): (AnalysisContextVersionV1, u64) = rmp_serde::from_slice(&bytes[1..])?;
        if row.key == input.key {
            let mut tx = store.write()?;
            tx.native().insert(
                key,
                [vec![0], rmp_serde::to_vec(&(input, revision))?].concat(),
            );
            tx.commit([])?;
            return Ok(());
        }
    }
    Err("context row absent".into())
}

fn retained(store: &NativeStore, expected: &[PackageRevisionV1]) -> TestResult {
    let view = store.view()?;
    let mut count = 0;
    for entry in view.snapshot().prefix(b"\0data/P") {
        let (key, _) = entry?;
        if key.len() == 15 {
            count += 1;
        }
    }
    assert_eq!(count, expected.len());
    for row in expected {
        assert_eq!(
            view.package_revision(
                row.tenant_id,
                &row.package_id,
                &row.revision,
                &AnalysisReadControl::default(),
            )?,
            Some(row.clone())
        );
    }
    Ok(())
}

#[test]
fn collection_keeps_tenant_scope() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path().join("data"))?;
    let bundle = bundle()?;
    for tenant in [1, 2] {
        store.install_package(
            &PackageRevisionV1::from_bundle(&bundle, [tenant; 16])?,
            || Ok(()),
        )?;
    }
    let mut context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    store.commit_context(&context)?;
    context.body = vec![0xc1];
    replace_context(&store, &context)?;
    store.collect_package([2; 16], "native-root", "v1")?;
    let view = store.view()?;
    let control = AnalysisReadControl::default();
    for package in ["native-root", "native-dependency"] {
        assert!(view
            .package_revision([2; 16], package, "v1", &control)?
            .is_none());
        assert!(view
            .package_revision([1; 16], package, "v1", &control)?
            .is_some());
    }
    Ok(())
}

#[test]
fn collection_failure_rolls_back() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path().join("data"))?;
    let bundle = bundle()?;
    let revisions = PackageRevisionV1::from_bundle(&bundle, [1; 16])?;
    store.install_package(&revisions, || Ok(()))?;
    let context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    store.commit_context(&context)?;
    let mut corrupt = context.clone();
    corrupt.body = vec![0xc1];
    replace_context(&store, &corrupt)?;
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    assert!(store.collect_package_admissions().is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    retained(&store, &revisions)?;
    replace_context(&store, &context)?;
    let repaired = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    store.collect_package_admissions()?;
    assert_eq!(store.meta()?, repaired);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    retained(&store, &revisions)?;
    assert_eq!(store.context_version(&context.key)?, Some(context));
    Ok(())
}

#[test]
fn roots_keep_tenant_closure() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path().join("data"))?;
    let bundle = bundle()?;
    for tenant in [1, 2] {
        store.install_package(
            &PackageRevisionV1::from_bundle(&bundle, [tenant; 16])?,
            || Ok(()),
        )?;
    }
    let context = AnalysisContextVersionV1::from_package(
        &bundle,
        [2; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    store.intern_context(&context)?;
    let before = store.meta()?;
    let mut notice = store.subscribe_revision();
    notice.borrow_and_update();
    store.collect_package_admissions()?;
    let after = store.meta()?;
    assert_eq!(after.commit_revision, before.commit_revision + 1);
    assert!(notice.has_changed()?);
    assert_eq!(*notice.borrow_and_update(), after.commit_revision);
    retained(&store, &PackageRevisionV1::from_bundle(&bundle, [2; 16])?)?;
    let view = store.view()?;
    for package in ["native-root", "native-dependency"] {
        assert!(view
            .package_revision([1; 16], package, "v1", &AnalysisReadControl::default())?
            .is_none());
    }
    store.collect_package([2; 16], "native-root", "v1")?;
    store.collect_package_admissions()?;
    assert_eq!(store.meta()?, after);
    assert!(!notice.has_changed()?);
    Ok(())
}

#[test]
fn exact_retry_keeps_revision() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let bundle = bundle()?;
    store.install_package(
        &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    let context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    let revision = store.commit_context(&context)?;
    let committed = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    for _ in 0..2 {
        assert_eq!(store.commit_context(&context)?, revision);
        assert_eq!(store.meta()?, committed);
        assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
        assert_eq!(store.database().inner().journal_head()?, cursor);
    }
    drop(store);
    let reopened = NativeStore::open(&root)?;
    let before = reopened.meta()?;
    assert_eq!(reopened.commit_context(&context)?, revision);
    assert_eq!(reopened.meta()?, before);
    Ok(())
}

#[test]
fn context_checks_package_fields() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path().join("data"))?;
    let bundle = bundle()?;
    store.install_package(
        &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    let context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    let original = StoredContext::from_context(&context)?;
    let initial = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    for change in 0..7 {
        let mut candidate = context.clone();
        let mut body = original.clone();
        match change {
            0 => body.digest = "wrong".into(),
            1 => body.root.package_id = "absent".into(),
            2 => body.export = "absent".into(),
            3 => body.output = "absent".into(),
            4 => body.generation = Some(1),
            5 => candidate.key.tenant_id = [2; 16],
            _ => candidate.sensitivity = ContextSensitivityV1::Public,
        }
        candidate.body = body.encode()?;
        candidate.key.entity_key = rmp_serde::to_vec(&(&body.package, &body.export, &body.output))?;
        candidate.key.lifetime_key = body.digest.as_bytes().to_vec();
        assert!(store.intern_context(&candidate).is_err(), "change {change}");
        assert_eq!(store.meta()?, initial);
        assert_eq!(store.database().inner().journal_head()?, cursor);
    }
    Ok(())
}

#[test]
fn context_rejects_invalid_binary() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path().join("data"))?;
    let bundle = bundle()?;
    store.install_package(
        &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    let context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    store.intern_context(&context)?;
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    let mut trailing = context.clone();
    trailing.body.push(0);
    assert!(matches!(
        store.intern_context(&trailing),
        Err(Error::Package {
            code: Code::Invalid,
            field: "native package context trailing bytes",
            ..
        })
    ));
    let mut malformed = context;
    malformed.body = vec![0xc1];
    assert!(store.intern_context(&malformed).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    Ok(())
}

#[test]
fn context_pins_dependency_artifact() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let bundle = bundle()?;
    store.install_package_image([1; 16], &bundle, || Ok(()))?;
    let dependency = bundle.bundle().artifacts[1].reference();
    let context =
        AnalysisContextVersionV1::from_package(&bundle, [1; 16], &dependency, "model", "rows")?;
    let mut invalid = bundle.bundle().clone();
    invalid.schema_version = 0;
    assert!(matches!(
        PackageBundle::try_from(invalid).map_err(Error::from),
        Err(Error::Package {
            code: Code::Invalid,
            field: "bundle version or package count",
            ..
        })
    ));
    let root_context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    assert_ne!(context.key, root_context.key);
    let body = StoredContext::from_context(&context)?;
    assert_eq!(body.root, bundle.bundle().root);
    assert_eq!(body.package, dependency);
    let pin = store.intern_context(&context)?;
    for (package, export, output) in [
        (
            PackageRefV1 {
                package_id: "missing".into(),
                revision: "v1".into(),
            },
            "model",
            "rows",
        ),
        (
            PackageRefV1 {
                revision: "missing".into(),
                ..dependency.clone()
            },
            "model",
            "rows",
        ),
        (dependency.clone(), "missing", "rows"),
        (dependency.clone(), "model", "missing"),
    ] {
        assert!(
            AnalysisContextVersionV1::from_package(&bundle, [1; 16], &package, export, output)
                .is_err()
        );
    }
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    let mut forged = context.clone();
    let mut body = body;
    body.package.revision = "missing".into();
    forged.body = body.encode()?;
    forged.key.entity_key = rmp_serde::to_vec(&(&body.package, &body.export, &body.output))?;
    assert!(store.intern_context(&forged).is_err());
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    drop(store);
    let store = NativeStore::open(root)?;
    assert_eq!(store.context_version(&pin.key)?, Some(context));
    Ok(())
}
