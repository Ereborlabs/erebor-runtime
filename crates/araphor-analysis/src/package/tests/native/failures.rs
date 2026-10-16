use super::*;

#[test]
fn native_caps_defer_admission() -> TestResult {
    use crate::AnalysisReadControl;
    use araphor_analysis_sdk as sdk;

    for (bytes, code, field) in [
        (
            0,
            PackageErrorCodeV1::Invalid,
            "native resource configuration",
        ),
        (
            1024,
            PackageErrorCodeV1::Unsupported,
            "in-process native resource limits",
        ),
    ] {
        let fixture = Fixture::new_backend_limits(
            Default::default(),
            crate::AnalysisLimits {
                native: crate::NativeLimits {
                    memory_bytes: Some(bytes),
                    cpu_seconds: None,
                },
                ..Default::default()
            },
        )?;
        let mut bundle = super::super::bundle("1", "SELECT 1::BIGINT UNSIGNED AS count");
        let artifact = &mut bundle.artifacts[0];
        artifact.implementations = vec![PackageImplementationV1::Native {
            export: "count".into(),
            artifact: b"invalid".to_vec(),
            qualification: Some(araphor_data::Qualification {
                exports: vec!["count".into()],
                target: "foreign-target".into(),
                cpu_features: Vec::new(),
                contract_version: 1,
                system_libraries: Vec::new(),
                dependencies: Vec::new(),
            }),
        }];
        let model = &artifact.descriptor.exports[0];
        let admitted =
            crate::model::AdmittedExport::compile(&fixture.owner.query, artifact, model)?;
        let evaluation = sdk::Evaluation {
            export: "count".into(),
            inputs: Vec::new(),
            parameters: None,
            checkpoint: None,
            context: sdk::EvaluationContext {
                id: "native-cap".into(),
                time_utc_ns: 0,
                seed: None,
                limits: model.limits,
            },
        };
        let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
        for error in [
            fixture.owner.admit_artifact(artifact, &control).err(),
            fixture
                .owner
                .evaluate_artifact([1; 16], artifact, &admitted, &evaluation, &control)
                .err(),
        ] {
            assert!(matches!(
                error,
                Some(crate::Error::Data {
                    source: araphor_data::Error::Package {
                        code: actual,
                        field: actual_field,
                        ..
                    }
                }) if actual == code && actual_field == field
            ));
        }
        control.cancel()?;
        assert!(matches!(
            fixture.owner.admit_artifact(artifact, &control),
            Err(crate::Error::Data {
                source: araphor_data::Error::AnalysisReadCancelled { .. }
            })
        ));
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_errors_commit_no_output() -> TestResult {
    for (mode, code) in [
        ("trap", PackageErrorCodeV1::Incomplete),
        ("limit", PackageErrorCodeV1::Limit),
        ("denied", PackageErrorCodeV1::Denied),
        ("invalid-name", PackageErrorCodeV1::Invalid),
        ("invalid-evidence", PackageErrorCodeV1::Invalid),
        ("oversized", PackageErrorCodeV1::Invalid),
    ] {
        let fixture = Fixture::new()?;
        assert!(fixture
            .install(native(component("1"))?, Some(parameters(mode)))
            .await
            .is_err());
        let inspected = fixture
            .execute(PackageRequestV1::Inspect {
                scope_id: "test".into(),
                package_id: "runtime-fixture".into(),
            })
            .await?;
        assert!(inspected.exports[0].results.is_empty());
        assert!(
            matches!(inspected.exports[0].readiness, PackageReadinessV1::Failed { code: failed, .. } if failed == code)
        );
        assert_eq!(fixture.owner.operations.available_permits(), 4);
        let fixture = fixture.reopen()?;
        assert!(fixture.execute(evaluate("retry-error")).await.is_err());
        let active = fixture.activation("runtime-fixture")?;
        assert!(active.result_id.is_none());
        assert_eq!(active.checkpoint_revision, 0);
    }
    Ok(())
}

#[tokio::test]
#[ignore = "requires source-built native artifacts in ARAPHOR_NATIVE_DIR"]
async fn native_caps_leave_other_targets_available() -> TestResult {
    let fixture = Fixture::new_backend_limits(
        Default::default(),
        crate::AnalysisLimits {
            native: crate::package::native::NativeLimits {
                memory_bytes: Some(1024),
                cpu_seconds: None,
            },
            ..Default::default()
        },
    )?;
    let sql = fixture
        .install(
            super::super::bundle("1", "SELECT 3::BIGINT UNSIGNED AS count"),
            None,
        )
        .await?;
    assert_eq!(sql.exports[0].results[0].target, "sql");
    let wasm = fixture
        .install(component("1"), Some(parameters("echo")))
        .await?;
    assert_eq!(wasm.exports[0].results[0].target, "wasm");
    let failure = fixture
        .execute(PackageRequestV1::Update {
            scope_id: "test".into(),
            bundle: native(component("2"))?,
        })
        .await;
    assert!(matches!(
        failure,
        Err(crate::Error::Data {
            source: araphor_data::Error::Package {
                code: PackageErrorCodeV1::Unsupported,
                ..
            }
        })
    ));
    let unchanged = fixture.activation("runtime-fixture")?;
    assert_eq!(unchanged.revision, "1");
    assert_eq!(
        unchanged.result_id.as_deref(),
        Some(wasm.exports[0].results[0].result_id.as_str())
    );
    Ok(())
}
