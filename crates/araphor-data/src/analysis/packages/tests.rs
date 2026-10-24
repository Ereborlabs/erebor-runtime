use super::*;
use crate::AnalysisStore;
use snafu::ResultExt as _;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

mod context;
mod image;

fn package(id: &str, revision: &str) -> crate::Result<PackageRevisionV1> {
    let mut descriptor = araphor_analysis_sdk::Package::new(
        id,
        revision,
        vec![araphor_analysis_sdk::Model::new(
            "model",
            Vec::new(),
            vec![araphor_analysis_sdk::Port::new(
                "rows",
                araphor_analysis_sdk::Schema::empty(),
            )],
        )],
    );
    descriptor.exports[0].input_mode = araphor_analysis_sdk::InputMode::Resolved;
    let source = crate::PackageArtifactV1 {
        descriptor: descriptor.clone(),
        implementations: vec![crate::PackageImplementationV1::Sql {
            export: "model".into(),
            program: crate::SqlModelV1 {
                outputs: std::collections::BTreeMap::from([("rows".into(), "SELECT 1".into())]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    let artifact = source.encode()?;
    Ok(PackageRevisionV1 {
        tenant_id: [1; 16],
        package_id: id.into(),
        revision: revision.into(),
        descriptor: serde_json::to_vec(&descriptor).context(crate::PackageEncodingSnafu)?,
        artifact,
        dependencies: Vec::new(),
    })
}

#[test]
fn packages_charge_stored_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let revision = package("bytes", "v1")?;
    let expected = (256
        + revision.package_id.len()
        + revision.revision.len()
        + revision.descriptor.len()
        + revision.artifact.len()
        + serde_json::to_vec(&revision.dependencies)?.len()) as u64;
    for _ in 0..2 {
        store.install_package(std::slice::from_ref(&revision), || Ok(()))?;
        assert_eq!(
            store.read_snapshot(
                |reader| AnalysisStore::logical_usage(reader, [1; 16]).map(|usage| usage.1)
            )?,
            expected
        );
    }
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(
        store.read_snapshot(
            |reader| AnalysisStore::logical_usage(reader, [1; 16]).map(|usage| usage.1)
        )?,
        expected
    );
    assert_eq!(
        store.package_revision([1; 16], "bytes", "v1")?,
        Some(revision)
    );
    Ok(())
}

#[test]
fn packages_unused_artifacts_release() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    store.install_package(&[package("first", "v1")?], || Ok(()))?;
    let unrelated = package("unrelated", "v1")?;
    store.install_package(std::slice::from_ref(&unrelated), || Ok(()))?;
    store.collect_package([1; 16], "first", "v1")?;
    assert!(store.package_revision([1; 16], "first", "v1")?.is_none());
    assert_eq!(
        store.package_revision([1; 16], "unrelated", "v1")?,
        Some(unrelated)
    );
    Ok(())
}

#[test]
fn oci_descriptor_mismatch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let original = package("descriptor", "v1")?;
    let mut changed = original.clone();
    let mut descriptor: araphor_analysis_sdk::Package =
        serde_json::from_slice(&changed.descriptor)?;
    descriptor.exports[0].name = "changed".into();
    changed.descriptor = serde_json::to_vec(&descriptor)?;
    assert!(matches!(
        changed.decode_artifact(),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Invalid,
            field: "retained package descriptor",
            ..
        })
    ));
    let before = store.meta()?;
    assert!(store
        .install_package(std::slice::from_ref(&changed), || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    assert!(store
        .package_revision([1; 16], "descriptor", "v1")?
        .is_none());
    store.install_package(&[original], || Ok(()))?;
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute(
            "UPDATE package_revisions SET descriptor = ? WHERE package_id = ?",
            duckdb::params![changed.descriptor, "descriptor"],
        )?;
    }
    drop(store);
    assert!(AnalysisStore::open(&root).is_err());
    Ok(())
}
