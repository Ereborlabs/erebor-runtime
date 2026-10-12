use std::collections::BTreeMap;

use araphor_analysis_sdk as sdk;

use super::*;

fn mixed_bundle() -> TestResult<PackageBundleV1> {
    let mut bundle = process_bundle("2")?;
    let artifact = &mut bundle.artifacts[0];
    let graph = artifact.descriptor.exports[0].clone();
    let auxiliary = sdk::Model::new(
        "aux",
        Vec::new(),
        vec![sdk::Port::new("rows", graph.inputs[0].schema.clone())],
    );
    artifact.descriptor.dependencies.push(sdk::Dependency {
        model: graph.name.clone(),
        input: graph.inputs[0].name.clone(),
        package: artifact.descriptor.id.clone(),
        revision: artifact.descriptor.revision.clone(),
        export: auxiliary.name.clone(),
        output: auxiliary.outputs[0].name.clone(),
    });
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: auxiliary.name.clone(),
        inputs: BTreeMap::new(),
        program: SqlModelV1 {
            outputs: BTreeMap::from([(
                "rows".into(),
                "SELECT ''::BLOB AS value WHERE false".into(),
            )]),
            ..Default::default()
        },
    });
    artifact.descriptor.exports.push(auxiliary);
    let mut sql = graph;
    sql.name = "sql-graph".into();
    let queries = |ports: &[sdk::Port]| {
        ports
            .iter()
            .map(|port| {
                (
                    port.name.clone(),
                    "SELECT ''::BLOB AS value WHERE false".into(),
                )
            })
            .collect()
    };
    artifact.implementations.push(PackageImplementationV1::Sql {
        export: sql.name.clone(),
        inputs: queries(&sql.inputs),
        program: SqlModelV1 {
            outputs: queries(&sql.outputs),
            checkpoint: queries(&sql.checkpoint.as_ref().ok_or("graph checkpoint")?.datasets),
            ..Default::default()
        },
    });
    artifact.descriptor.exports.push(sql);
    bundle.validate()?;
    Ok(bundle)
}

#[tokio::test]
async fn mixed_graph_exports_derive() -> TestResult {
    let input = credential_input()?;
    let execution = InstalledAnalysis::testing(None, input.source.tenant_id)?;
    let mut expected = GraphAndFindingOwner::derive(&input, &execution)?;
    let bundle = mixed_bundle()?;
    let descriptor = bundle.artifacts[0].descriptor.clone();
    assert!(GraphAndFindingOwner::supports_analysis(
        descriptor
            .exports
            .iter()
            .find(|model| model.name == "sql-graph")
            .ok_or("SQL graph export absent")?
    ));
    execute(
        &execution,
        PackageRequestV1::Update {
            scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
            bundle,
        },
    )
    .await?;
    let selected = execution.snapshot(input.source.tenant_id)?;
    let packages = selected.descriptors(input.source.tenant_id)?;
    let package = packages
        .iter()
        .find(|package| package.id == descriptor.id)
        .ok_or("selected graph package absent")?;
    package.validate()?;
    assert_eq!(package, &descriptor);
    assert_eq!(
        selected
            .prepared_models(package)
            .map(|model| model.name.as_str())
            .collect::<Vec<_>>(),
        ["detect"]
    );
    let references = selected.refs()?;
    let references = references
        .iter()
        .filter(|reference| reference.package_id == descriptor.id)
        .collect::<Vec<_>>();
    assert_eq!(references.len(), 1);
    assert_eq!(references[0].export, "detect");
    assert_eq!(references[0].revision, "2");
    let inspected = execution.testing_owner().execute_sync(
        grant(),
        PackageRequestV1::Inspect {
            scope_id: AnalysisPackageOwner::DOMAIN_SCOPE.into(),
            package_id: descriptor.id.clone(),
        },
        &AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?,
    )?;
    let sql = inspected
        .exports
        .iter()
        .find(|model| model.descriptor.name == "sql-graph")
        .ok_or("SQL graph activation absent")?;
    assert!(!sql.active);
    assert!(matches!(
        &sql.readiness,
        PackageReadinessV1::Unsupported { target } if target == "domain output adapter"
    ));
    expected
        .packages
        .iter_mut()
        .find(|package| package.package_id == descriptor.id)
        .ok_or("baseline process checkpoint absent")?
        .replay_contract_id = "HF-PROC-001/v2".into();
    let actual = GraphAndFindingOwner::derive(&input, &selected)?;
    assert!(!actual.findings.is_empty());
    assert_eq!(actual, expected);
    Ok(())
}
