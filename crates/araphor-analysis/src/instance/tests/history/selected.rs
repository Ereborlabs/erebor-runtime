use super::*;

#[tokio::test]
async fn selected_sql_prql_references() -> TestResult {
    for (name, program) in [
        (
            "sql",
            Program::Sql {
                source: Source::Inline {
                    inline: "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                },
            },
        ),
        (
            "empty",
            Program::Sql {
                source: Source::Inline {
                    inline: "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE false".into(),
                },
            },
        ),
        (
            "prql",
            Program::Prql {
                source: Source::Inline {
                    inline: "from s\"SELECT CAST(7 AS BIGINT UNSIGNED) AS value\"".into(),
                },
            },
        ),
    ] {
        let fixture = Fixture::new(Default::default())?;
        let definition = fixture
            .query
            .admit_definition(
                [1; 16],
                Definition {
                    name: name.into(),
                    description: String::new(),
                    labels: BTreeMap::new(),
                    program,
                },
                Arc::new(AnalysisReadControl::default()),
            )
            .await?;
        fixture
            .query
            .store()
            .admit_definition([1; 16], &definition, || Ok(()))?;
        let instance = Instance::admit(
            Arc::clone(&fixture.query),
            fixture.authority.clone(),
            fixture.grant.clone(),
            name.into(),
            definition,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert!(instance.admitted().spec.manifest.calls.is_empty());
        let receipt = instance
            .run(request("first"), &AnalysisReadControl::default())
            .await?;
        instance
            .run(request("later"), &AnalysisReadControl::default())
            .await?;
        assert!(receipt.results.is_empty());
        let captured = fixture
            .query
            .store()
            .managed_attempt([1; 16], name, "first", &AnalysisReadControl::default())?
            .ok_or("selected attempt")?;
        fixture.authority.set(false);
        let reader = Arc::new(Reader::new(fixture.grant.clone()));
        let before = fixture.query.store().meta()?;
        let result = Instance::read_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            name,
            &receipt.selected.result_id,
            &AnalysisReadControl::default(),
        )
        .await?;
        assert!(matches!(
            result.kind,
            araphor_data::InstanceResultKindV1::Selected
        ));
        assert_eq!(result.result, receipt.selected);
        assert_eq!(result.receipt, receipt);
        assert_eq!(result.source.store_uuid, before.store_uuid);
        assert_eq!(result.source.schema_version, before.schema_version);
        assert_eq!(result.source.recovery_epoch, before.recovery_epoch);
        assert_eq!(result.source.commit_revision, captured.captured_revision());
        assert_eq!(result.time_utc_ns, request("first").time_utc_ns);
        assert_eq!(
            result.definition_revision,
            instance.admitted().spec.manifest.definition.to_string()
        );
        assert!(!result.current);
        assert!(serde_json::to_value(&result)?.get("output").is_none());
        assert_eq!(fixture.query.store().meta()?, before);
    }
    Ok(())
}

#[tokio::test]
async fn selected_scope_precedes_integrity() -> TestResult {
    let fixture = Fixture::new(Default::default())?;
    let instance = fixture
        .admit(
            "selected-scope",
            "SELECT CAST(7 AS BIGINT UNSIGNED) AS value",
        )
        .await?;
    fixture.admit("foreign", "SELECT 1").await?;
    let receipt = instance
        .run(request("scope"), &AnalysisReadControl::default())
        .await?;
    fixture.query.store().fault_write(
        "UPDATE analysis_results SET commit_revision = commit_revision + 1 WHERE result_id = ?",
        &[&receipt.selected.result_id],
    )?;
    let before = fixture.query.store().meta()?;
    for case in 0..4 {
        let mut reader = Reader::new(fixture.grant.clone());
        if case == 0 {
            reader.allowed.store(false, Ordering::SeqCst);
        }
        if case == 1 {
            reader.grant.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
        }
        let reader = Arc::new(reader);
        let name = if case == 2 {
            "foreign"
        } else {
            "selected-scope"
        };
        let error = Instance::read_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            name,
            &receipt.selected.result_id,
            &AnalysisReadControl::default(),
        )
        .await
        .err()
        .ok_or("invalid selected reference returned")?;
        if case < 3 {
            assert_eq!(
                error.status_code(),
                erebor_runtime_error::StatusCode::PermissionDenied,
                "{error:?}"
            );
        } else {
            assert_ne!(
                error.status_code(),
                erebor_runtime_error::StatusCode::PermissionDenied,
                "{error:?}"
            );
        }
    }
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
