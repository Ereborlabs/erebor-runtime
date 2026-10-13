use super::super::*;

#[tokio::test]
#[ignore = "requires native artifacts, target metadata, and Python unavailable on PATH"]
async fn installed_native_detector_contract() -> Result<()> {
    let directory = tempfile::tempdir()?;
    let output = directory.path().join("proof");
    let qualification = AnalysisPackageQualification::new(output.clone());
    qualification.run_native().await?;
    let before = fs::read(output.join("result.json"))?;
    let result: serde_json::Value = serde_json::from_slice(&before)?;
    assert_eq!(result["result"], "PASS");
    assert_eq!(result["python_unavailable"], true);
    assert_eq!(
        result["installed_native_detector"]["execution_target"],
        "native"
    );
    assert_eq!(
        result["installed_native_detector"]["matching_evidence_records"],
        3
    );
    assert_eq!(result["installed_native_detector"]["checkpoint"], "4");
    assert_eq!(result["installed_native_detector"]["host_rebuild"], false);
    assert_eq!(
        result["installed_native_detector"]["migrated_native_algorithms"]["replay_equal"],
        true
    );
    assert!(qualification.run_native().await.is_err());
    assert_eq!(fs::read(output.join("result.json"))?, before);
    Ok(())
}
