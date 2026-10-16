use super::*;

#[test]
fn shared_executable_checks_sql() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = component("1");
    let artifact = &mut package.artifacts[0];
    let mut second = artifact.descriptor.exports[0].clone();
    second.name = "second".into();
    artifact.descriptor.exports.push(second.clone());
    let PackageImplementationV1::Wasm { exports, .. } = &mut artifact.implementations[0] else {
        return Err("Wasm fixture absent".into());
    };
    exports.push(second.name.clone());
    fixture
        .owner
        .admit_artifact(artifact, &crate::AnalysisReadControl::default())?;
    drop(crate::package::installed::snapshot::InstalledBundle::new(
        &fixture.owner.query,
        package.clone(),
    )?);

    second.name = "invalid-sql".into();
    let artifact = &mut package.artifacts[0];
    artifact.descriptor.exports.push(second);
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: "invalid-sql".into(),
        program: crate::SqlModelV1 {
            outputs: BTreeMap::from([("data".into(), "DROP TABLE events".into())]),
            ..Default::default()
        },
    });
    assert!(matches!(
        crate::package::installed::snapshot::InstalledBundle::new(&fixture.owner.query, package),
        Err(crate::Error::QueryInvalid { .. })
    ));
    Ok(())
}

#[test]
fn package_metadata_digest_stable() -> TestResult {
    let mut package = component("1");
    package.artifacts[0].descriptor.exports[0].outputs[0].schema =
        sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)
            .with_metadata(
                [
                    ("z".into(), "last".into()),
                    ("a".into(), "first".into()),
                    ("m".into(), "middle".into()),
                ]
                .into(),
            )]);
    let artifact = &package.artifacts[0];
    let descriptor = artifact.descriptor.interfaces()?.descriptor_json;
    assert_eq!(artifact.descriptor_bytes()?, descriptor.as_bytes());
    let encoded = package.encode()?;
    let digest = package.digest()?;
    for _ in 0..8 {
        let bytes = package.encode()?;
        assert_eq!(bytes, encoded);
        package = PackageBundleV1::from_bytes(&bytes)?;
        assert_eq!(package.digest()?, digest);
    }
    Ok(())
}

#[test]
fn sql_oci_metadata_unchanged() -> TestResult {
    let package = crate::package::tests::bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
    let content = sdk::oci::Content::from_bytes(&package.encode()?)?;
    assert!(content.layers.is_empty());
    assert_eq!(
        serde_json::to_value(content.package::<PackageBundleV1>()?)?,
        serde_json::to_value(&package)?
    );
    Ok(())
}

#[tokio::test]
async fn wasm_metadata_install_retry() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = AnalysisPackageOwner::required_bundles()
        .into_iter()
        .find(|bundle| bundle.root.package_id == crate::DISCOVERY_PROCESSOR)
        .ok_or("discovery component absent")?;
    let installed = fixture.install(package.clone(), None).await?;
    let inspected = fixture
        .execute(PackageRequestV1::Inspect {
            scope_id: "test".into(),
            package_id: package.root.package_id.clone(),
        })
        .await?;
    assert_eq!(
        serde_json::to_value(&installed)?,
        serde_json::to_value(&inspected)?
    );
    let before = fixture.store.package_revision(
        [1; 16],
        &package.root.package_id,
        &package.root.revision,
    )?;
    for _ in 0..4 {
        package = PackageBundleV1::from_bytes(&package.encode()?)?;
        let installed = fixture.install(package.clone(), None).await?;
        assert!(installed.exports.iter().all(|export| export.active));
        let inspected = fixture
            .execute(PackageRequestV1::Inspect {
                scope_id: "test".into(),
                package_id: package.root.package_id.clone(),
            })
            .await?;
        assert_eq!(
            serde_json::to_value(&installed)?,
            serde_json::to_value(&inspected)?
        );
        assert_eq!(
            fixture.store.package_revision(
                [1; 16],
                &package.root.package_id,
                &package.root.revision
            )?,
            before
        );
    }
    let fixture = fixture.reopen()?;
    let installed = fixture
        .install(PackageBundleV1::from_bytes(&package.encode()?)?, None)
        .await?;
    let inspected = fixture
        .execute(PackageRequestV1::Inspect {
            scope_id: "test".into(),
            package_id: package.root.package_id.clone(),
        })
        .await?;
    assert_eq!(
        serde_json::to_value(&installed)?,
        serde_json::to_value(&inspected)?
    );
    assert_eq!(
        fixture.store.package_revision(
            [1; 16],
            &package.root.package_id,
            &package.root.revision
        )?,
        before
    );
    Ok(())
}

#[tokio::test]
async fn mixed_metadata_install_retry() -> TestResult {
    let fixture = Fixture::new()?;
    let mut package = AnalysisPackageOwner::required_bundles()
        .into_iter()
        .find(|bundle| bundle.root.package_id == crate::DISCOVERY_PROCESSOR)
        .ok_or("discovery component absent")?;
    let output = package.artifacts[0]
        .descriptor
        .exports
        .iter()
        .find(|model| model.name == "atoms")
        .ok_or("atoms export absent")?
        .outputs[0]
        .clone();
    let mut source = crate::package::tests::bundle("1", "SELECT value FROM input WHERE false")
        .artifacts
        .remove(0);
    source.descriptor.id = "sql.rows".into();
    source.descriptor.exports[0].inputs =
        vec![sdk::Port::new("input", output.schema.clone()).into()];
    source.descriptor.exports[0].outputs[0].schema = output.schema;
    source.descriptor.exports[0].inputs[0].source =
        sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: package.root.package_id.clone(),
            revision: package.root.revision.clone(),
            export: "atoms".into(),
            output: output.name,
        }));
    package.root = source.reference();
    package.artifacts.push(source);
    let digest = package.digest()?;
    let installed = fixture.install(package.clone(), None).await?;
    assert!(matches!(
        installed.exports[0].readiness,
        PackageReadinessV1::MissingInput { .. }
    ));
    let inspected = fixture
        .execute(PackageRequestV1::Inspect {
            scope_id: "test".into(),
            package_id: package.root.package_id.clone(),
        })
        .await?;
    assert_eq!(
        serde_json::to_value(&installed)?,
        serde_json::to_value(&inspected)?
    );
    let retained = fixture.store.package_revision([1; 16], "sql.rows", "1")?;
    for _ in 0..8 {
        package = PackageBundleV1::from_bytes(&package.encode()?)?;
        assert_eq!(package.digest()?, digest);
        let installed = fixture.install(package.clone(), None).await?;
        let inspected = fixture
            .execute(PackageRequestV1::Inspect {
                scope_id: "test".into(),
                package_id: package.root.package_id.clone(),
            })
            .await?;
        assert_eq!(
            serde_json::to_value(&installed)?,
            serde_json::to_value(&inspected)?
        );
        assert_eq!(
            fixture.store.package_revision([1; 16], "sql.rows", "1")?,
            retained
        );
    }
    let fixture = fixture.reopen()?;
    assert_eq!(
        fixture
            .owner
            .load_bundle([1; 16], &package.root)?
            .digest()?,
        digest
    );
    let installed = fixture
        .install(PackageBundleV1::from_bytes(&package.encode()?)?, None)
        .await?;
    let inspected = fixture
        .execute(PackageRequestV1::Inspect {
            scope_id: "test".into(),
            package_id: package.root.package_id.clone(),
        })
        .await?;
    assert_eq!(
        serde_json::to_value(&installed)?,
        serde_json::to_value(&inspected)?
    );
    assert_eq!(
        fixture.store.package_revision([1; 16], "sql.rows", "1")?,
        retained
    );
    let source = package
        .artifacts
        .iter_mut()
        .find(|artifact| artifact.descriptor.id == "sql.rows")
        .ok_or("SQL artifact absent")?;
    let PackageImplementationV1::Sql { program, .. } = &mut source.implementations[0] else {
        return Err("SQL implementation absent".into());
    };
    program.outputs.insert(
        "rows".into(),
        "SELECT 'changed'::BLOB AS value WHERE false".into(),
    );
    assert!(matches!(
        fixture.install(package, None).await,
        Err(crate::Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        fixture.store.package_revision([1; 16], "sql.rows", "1")?,
        retained
    );
    Ok(())
}
