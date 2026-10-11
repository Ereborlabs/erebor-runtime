use araphor_analysis_sdk as sdk;

use crate::package::owner::InstalledContext;
use crate::package::tests::{bundle, Fixture, TestResult};
use crate::package::{PackageBundleV1, PackageImplementationV1, PackageRequestV1};

fn consumer(name: &str, dependency: &PackageBundleV1) -> PackageBundleV1 {
    let mut package = bundle("v1", "SELECT count FROM upstream");
    package.root.package_id = name.into();
    let artifact = &mut package.artifacts[0];
    artifact.descriptor.id = name.into();
    artifact.descriptor.exports[0].inputs.push(sdk::Port::new(
        "upstream",
        dependency.artifacts[0].descriptor.exports[0].outputs[0]
            .schema
            .clone(),
    ));
    artifact.descriptor.dependencies.push(sdk::Dependency {
        model: "count".into(),
        input: "upstream".into(),
        package: dependency.root.package_id.clone(),
        revision: dependency.root.revision.clone(),
        export: "count".into(),
        output: "rows".into(),
    });
    package.artifacts.extend(dependency.artifacts.clone());
    package
}

async fn remove(fixture: &Fixture, package: &str) -> TestResult {
    fixture
        .execute(PackageRequestV1::Remove {
            scope_id: "test".into(),
            package_id: package.into(),
        })
        .await?;
    Ok(())
}

#[tokio::test]
async fn removal_releases_exclusive_models() -> TestResult {
    let fixture = Fixture::new()?;
    let dependency = bundle("v1", "SELECT 1::UBIGINT AS count");
    fixture
        .install(consumer("test.consumer", &dependency), None)
        .await?;
    let prior = fixture.store.package_activations([1; 16], "test", None)?;
    assert_eq!(prior.len(), 2);
    remove(&fixture, "test.consumer").await?;
    assert!(fixture
        .store
        .package_activations([1; 16], "test", None)?
        .is_empty());
    for activation in prior {
        let result = fixture
            .store
            .package_result(
                [1; 16],
                activation.result_id.as_deref().ok_or("result absent")?,
            )?
            .ok_or("historical result absent")?;
        assert!(result.stale);
        assert!(fixture
            .store
            .package_revision([1; 16], &activation.key.package_id, &activation.revision)?
            .is_some());
    }
    Ok(())
}

#[tokio::test]
async fn removal_retains_shared_models() -> TestResult {
    let fixture = Fixture::new()?;
    let dependency = bundle("v1", "SELECT 1::UBIGINT AS count");
    fixture
        .install(consumer("test.first", &dependency), None)
        .await?;
    fixture
        .install(consumer("test.second", &dependency), None)
        .await?;
    remove(&fixture, "test.first").await?;
    let retained = fixture
        .store
        .package_activations([1; 16], "test", Some("test.model"))?;
    assert_eq!(retained.len(), 1);
    let context: InstalledContext = serde_json::from_slice(&retained[0].metadata)?;
    assert_eq!(context.root.package_id, "test.second");
    assert!(!fixture.store.package_results(&retained[0].key)?[0].stale);
    assert!(remove(&fixture, "test.model").await.is_err());
    remove(&fixture, "test.second").await?;
    assert!(fixture
        .store
        .package_activations([1; 16], "test", None)?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn removal_retains_explicit_dependency() -> TestResult {
    let fixture = Fixture::new()?;
    let dependency = bundle("v1", "SELECT 1::UBIGINT AS count");
    fixture
        .install(consumer("test.consumer", &dependency), None)
        .await?;
    fixture.install(dependency, None).await?;
    remove(&fixture, "test.consumer").await?;
    let retained = fixture.store.package_activations([1; 16], "test", None)?;
    assert_eq!(retained.len(), 1);
    assert_eq!(retained[0].key.package_id, "test.model");
    let context: InstalledContext = serde_json::from_slice(&retained[0].metadata)?;
    assert_eq!(context.root.package_id, "test.model");
    remove(&fixture, "test.model").await?;
    assert!(fixture
        .store
        .package_activations([1; 16], "test", None)?
        .is_empty());
    Ok(())
}

#[tokio::test]
async fn removal_releases_unused_artifacts() -> TestResult {
    let fixture = Fixture::new()?;
    let dependency = bundle("v1", "SELECT 1::UBIGINT AS count");
    let mut package = consumer("test.consumer", &dependency);
    for artifact in &mut package.artifacts {
        artifact.implementations = vec![PackageImplementationV1::Wasm {
            export: "count".into(),
            artifact: vec![0],
        }];
    }
    fixture.install(package.clone(), None).await?;
    let prior = fixture.store.package_activations([1; 16], "test", None)?;
    fixture.install(package, None).await?;
    assert_eq!(
        prior,
        fixture.store.package_activations([1; 16], "test", None)?
    );
    let root = prior
        .iter()
        .find(|active| active.key.package_id == "test.consumer")
        .ok_or("root activation absent")?;
    fixture
        .store
        .remove_package(&root.key, root.generation, || Ok(()))?;
    remove(&fixture, "test.consumer").await?;
    assert!(fixture
        .store
        .package_activations([1; 16], "test", None)?
        .is_empty());
    assert!(fixture.store.package_revisions([1; 16])?.is_empty());
    Ok(())
}

#[tokio::test]
async fn removal_reconciles_upgrade_orphan() -> TestResult {
    let fixture = Fixture::new()?;
    let dependency = bundle("v1", "SELECT 1::UBIGINT AS count");
    fixture
        .install(consumer("test.consumer", &dependency), None)
        .await?;
    let prior = fixture
        .store
        .package_activations([1; 16], "test", Some("test.model"))?
        .pop()
        .ok_or("dependency absent")?;
    let mut replacement = bundle("v2", "SELECT 2::UBIGINT AS count");
    replacement.root.package_id = "test.consumer".into();
    replacement.artifacts[0].descriptor.id = "test.consumer".into();
    fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: replacement,
        })
        .await?;
    let removed = fixture
        .store
        .package_activation(&prior.key)?
        .ok_or("removed state absent")?;
    let orphan = fixture
        .store
        .activate_package(&prior, Some(removed.generation), None, || Ok(()))?;
    assert!(fixture.owner.prune_orphans(&orphan)?.is_none());
    let remaining = fixture.store.package_activations([1; 16], "test", None)?;
    assert_eq!(remaining.len(), 1);
    assert_eq!(remaining[0].revision, "v2");
    Ok(())
}
