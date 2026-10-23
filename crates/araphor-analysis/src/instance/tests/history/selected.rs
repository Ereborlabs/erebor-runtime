use super::*;

#[tokio::test]
async fn selected_sql_prql_reads() -> TestResult {
    for (name, program, rows) in [
        (
            "sql",
            Program::Sql {
                source: Source::Inline {
                    inline: "SELECT CAST(7 AS BIGINT UNSIGNED) AS value".into(),
                },
            },
            1,
        ),
        (
            "empty",
            Program::Sql {
                source: Source::Inline {
                    inline: "SELECT CAST(7 AS BIGINT UNSIGNED) AS value WHERE false".into(),
                },
            },
            0,
        ),
        (
            "prql",
            Program::Prql {
                source: Source::Inline {
                    inline: "from s\"SELECT CAST(7 AS BIGINT UNSIGNED) AS value\"".into(),
                },
            },
            1,
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
        let original = fixture
            .query
            .store()
            .managed_selected([1; 16], name, "first", &AnalysisReadControl::default())?
            .ok_or("selected original")?;
        fixture.authority.set(false);
        let reader = Arc::new(Reader::new(fixture.grant.clone()));
        let before = fixture.query.store().meta()?;
        let araphor_data::PackageResponseV1::Output(packet) = Instance::read_output(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            name,
            &receipt.selected.result_id,
            &AnalysisReadControl::default(),
        )
        .await?
        else {
            return Err("selected output variant".into());
        };
        let data = packet.decode_any()?;
        assert_eq!(data.name, "selected");
        assert_eq!(data.rows(), rows);
        assert_eq!(data.batches, original.data.batches);
        assert_eq!(
            data.batches[0].schema_ref().as_ref(),
            &instance.admitted().spec.manifest.selected_schema
        );
        let output = Instance::query_result(
            Arc::clone(&fixture.query),
            reader.clone(),
            reader.grant.clone(),
            name,
            Some(&receipt.selected.result_id),
            "SELECT value, __row_index FROM selected",
            &AnalysisReadControl::default(),
        )
        .await?;
        assert_eq!(output.data.rows(), rows);
        assert_eq!(output.data.batches[0].num_columns(), 2);
        if rows != 0 {
            assert_eq!(values(&output.data.batches)?, [7]);
            assert_eq!(
                output.data.batches[0]
                    .column(1)
                    .as_any()
                    .downcast_ref::<UInt64Array>()
                    .ok_or("row index")?
                    .value(0),
                0
            );
        }
        for sql in ["SELECT * FROM events", "DELETE FROM selected"] {
            assert!(Instance::query_result(
                Arc::clone(&fixture.query),
                reader.clone(),
                reader.grant.clone(),
                name,
                Some(&receipt.selected.result_id),
                sql,
                &AnalysisReadControl::default(),
            )
            .await
            .is_err());
        }
        assert_eq!(fixture.query.store().meta()?, before);
    }
    Ok(())
}

#[tokio::test]
async fn selected_scope_precedes_arrow() -> TestResult {
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
        "UPDATE managed_arrow SET ipc = 'invalid'::BLOB WHERE result_id = ? AND role = 'selected'",
        &[&receipt.selected.result_id],
    )?;
    let before = fixture.query.store().meta()?;
    for (query, latest) in [(false, false), (true, false), (true, true)] {
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
            let control = AnalysisReadControl::default();
            let error = if query {
                Instance::query_result(
                    Arc::clone(&fixture.query),
                    reader.clone(),
                    reader.grant.clone(),
                    name,
                    if latest {
                        None
                    } else {
                        Some(&receipt.selected.result_id)
                    },
                    "SELECT * FROM selected",
                    &control,
                )
                .await
                .err()
            } else {
                Instance::read_output(
                    Arc::clone(&fixture.query),
                    reader.clone(),
                    reader.grant.clone(),
                    name,
                    &receipt.selected.result_id,
                    &control,
                )
                .await
                .err()
            }
            .ok_or("corrupt selected result returned")?;
            if latest && case == 2 {
                assert_eq!(
                    error.status_code(),
                    erebor_runtime_error::StatusCode::NotFound,
                    "{error:?}"
                );
            } else if case < 3 {
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
    }
    assert_eq!(fixture.query.store().meta()?, before);
    Ok(())
}
