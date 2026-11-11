use super::*;
use araphor_data::analysis::PackageRevisionRefV1;

#[path = "catalogue/images.rs"]
mod images;
#[path = "catalogue/lifecycle.rs"]
mod lifecycle;
#[path = "catalogue/rows.rs"]
mod rows;

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
                outputs: BTreeMap::from([("rows".into(), "SELECT 1".into())]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    }
}

fn dependency(root: &mut PackageArtifactV1, dependency: &PackageArtifactV1, port: &str) {
    root.descriptor.exports[0].inputs.push(sdk::InputPort {
        port: sdk::Port::new(port, sdk::Schema::empty()),
        source: sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
            package: dependency.descriptor.id.clone(),
            revision: dependency.descriptor.revision.clone(),
            export: "model".into(),
            output: "rows".into(),
        })),
    });
}

fn package(id: &str, revision: &str) -> Result<PackageRevisionV1, Box<dyn std::error::Error>> {
    let artifact = artifact(id, revision);
    let mut row = PackageRevisionV1::from_artifact(&artifact, [1; 16])?;
    row.artifact = artifact.encode()?;
    Ok(row)
}

fn image(revision: &str) -> Result<PackageBundleV1, Box<dyn std::error::Error>> {
    let mut root = artifact("image-root", revision);
    let mut item = artifact("image-dependency", "v1");
    item.implementations = vec![PackageImplementationV1::Wasm {
        exports: vec!["model".into()],
        artifact: (0u8..=255).cycle().take(8193).collect(),
    }];
    dependency(&mut root, &item, "source");
    Ok(PackageBundleV1 {
        schema_version: 1,
        root: root.reference(),
        artifacts: vec![root, item],
    })
}

fn inspect(
    store: &NativeStore,
    revision: Option<&str>,
) -> Result<PackageBundle, Box<dyn std::error::Error>> {
    store
        .package_image(
            [1; 16],
            "image-root",
            revision,
            &AnalysisReadControl::default(),
        )?
        .ok_or_else(|| "installed image absent".into())
}

fn revisions(
    store: &NativeStore,
    tenant: [u8; 16],
) -> Result<Vec<PackageRevisionV1>, Box<dyn std::error::Error>> {
    let view = store.view()?;
    let mut rows = Vec::new();
    for entry in view.snapshot().prefix(b"\0data/P") {
        let (key, bytes) = entry?;
        if key.len() != 15 {
            continue;
        }
        let (row, _, _): (PackageRevisionV1, u64, u64) = rmp_serde::from_slice(&bytes[1..])?;
        if row.tenant_id == tenant {
            rows.push(
                view.package_revision(
                    tenant,
                    &row.package_id,
                    &row.revision,
                    &AnalysisReadControl::default(),
                )?
                .ok_or("retained package row")?,
            );
        }
    }
    rows.sort_by(|left, right| {
        (&left.package_id, &left.revision).cmp(&(&right.package_id, &right.revision))
    });
    Ok(rows)
}

fn assert_no_execution(store: &NativeStore) -> TestResult {
    let view = store.view()?;
    for kind in [b'J', b'Z', b'Q', b'a', b'G', b'X'] {
        let prefix = [b"\0data/".as_slice(), &[kind]].concat();
        assert!(
            view.snapshot().prefix(prefix).next().is_none(),
            "execution record {kind}"
        );
    }
    assert!(view
        .snapshot()
        .prefix(b"\0data/@progress/result/")
        .next()
        .is_none());
    assert!(!store.discovery_enabled());
    Ok(())
}
