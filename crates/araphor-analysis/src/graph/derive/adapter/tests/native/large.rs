use super::*;

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_process_large_input() -> NativeResult {
    let input = large_input()?;
    let tenant = input.source.tenant_id;
    let owner = GraphDerivation::new(&input)?;
    let package = algorithm::Detector::Process.descriptor();
    let evaluation = owner.evaluation_for(&package.exports[0])?;
    assert_eq!(evaluation.input("records")?.data.batches[0].num_rows(), 185);
    let directory = PathBuf::from(
        std::env::var_os("ARAPHOR_NATIVE_DIR").ok_or("ARAPHOR_NATIVE_DIR is required")?,
    );
    let bytes =
        std::fs::read(directory.join(format!("process.{}", std::env::consts::DLL_EXTENSION)))?;
    let qualification = Qualification::inspect(
        &bytes,
        vec!["detect".into()],
        env!("ARAPHOR_NATIVE_TARGET").into(),
    )?;
    let artifact = PackageArtifactV1 {
        descriptor: package.clone(),
        implementations: vec![PackageImplementationV1::Native {
            export: "detect".into(),
            artifact: bytes,
            qualification: Some(qualification),
        }],
        fixtures: Vec::new(),
    };
    let mut fixture = Fixture::new()?;
    fixture.grant.selection = crate::AnalysisSelectionV1::tenant(tenant);
    fixture
        .owner
        .execute(
            fixture.grant.clone(),
            PackageRequestV1::Install {
                scope_id: "test".into(),
                bundle: PackageBundleV1 {
                    schema_version: 1,
                    root: artifact.reference(),
                    artifacts: vec![artifact],
                },
                parameters: None,
            },
            Arc::new(crate::AnalysisReadControl::with_timeout(
                Duration::from_secs(30),
            )?),
        )
        .await?;
    let native = crate::InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let wasm = crate::InstalledAnalysis::testing(None, tenant)?;
    let control = crate::AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    let trusted = algorithm::Detector::Process.evaluate(&evaluation)?;
    let expected = wasm.evaluate(tenant, &package.id, &evaluation, &control)?;
    let actual = native.evaluate(tenant, &package.id, &evaluation, &control)?;
    assert_eq!(actual.target, "native");
    assert!(actual.artifact.is_some());
    assert_eq!(actual.output.reasons.len(), 185);
    assert!(!actual.output.evidence.is_empty());
    assert!(actual.output.checkpoint.is_some());
    assert_eq!(
        encoded(&package, &evaluation, &trusted)?,
        encoded(&package, &evaluation, &actual.output)?
    );
    assert_eq!(
        encoded(&package, &evaluation, &expected.output)?,
        encoded(&package, &evaluation, &actual.output)?
    );
    assert_eq!(actual.evaluation.inputs.len(), evaluation.inputs.len());
    for (saved, supplied) in actual.evaluation.inputs.iter().zip(&evaluation.inputs) {
        assert_eq!(saved.data.batches, supplied.data.batches);
        assert_eq!(saved.revision, supplied.revision);
        assert_eq!(saved.coverage, supplied.coverage);
    }
    assert_eq!(actual.evaluation.context, evaluation.context);
    Ok(())
}
