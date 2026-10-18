use sdk::arrow_array::StringArray;

use super::*;

fn sql_bundle(sql: &str) -> PackageBundleV1 {
    let mut selected = crate::package::tests::bundle("1", sql);
    let model = &mut selected.artifacts[0].descriptor.exports[0];
    model.input_mode = sdk::InputMode::Provided;
    model.inputs.push(
        sdk::Port::new(
            "input",
            sdk::Schema::new(vec![sdk::Field::new("value", sdk::DataType::UInt64, false)]),
        )
        .into(),
    );
    selected
}

#[test]
fn prepared_sql_oci() -> TestResult {
    let sql = "WITH totals AS (
        SELECT CAST(COALESCE(SUM(value), 0) AS BIGINT UNSIGNED) AS count FROM input
    ) SELECT count FROM totals";
    let selected = sql_bundle(sql);
    selected.validate()?;
    assert!(selected.artifacts[0].prepared("count"));
    let restored = PackageBundleV1::from_bytes(&selected.encode()?)?;
    assert_eq!(restored.root, selected.root);
    assert_eq!(restored.artifacts, selected.artifacts);
    assert_eq!(restored.digest()?, selected.digest()?);
    let PackageImplementationV1::Sql { program, .. } = &restored.artifacts[0].implementations[0]
    else {
        return Err("retained SQL implementation is absent".into());
    };
    assert_eq!(program.outputs["rows"], sql);
    let mut changed = restored;
    let PackageImplementationV1::Sql { program, .. } = &mut changed.artifacts[0].implementations[0]
    else {
        return Err("retained SQL implementation is absent".into());
    };
    program
        .outputs
        .insert("rows".into(), format!("{sql} WHERE count > 0"));
    assert_eq!(changed.root, selected.root);
    assert_ne!(changed.digest()?, selected.digest()?);
    let mut resolved = selected;
    resolved.artifacts[0].descriptor.exports[0].input_mode = sdk::InputMode::Resolved;
    assert!(!resolved.artifacts[0].prepared("count"));
    Ok(())
}

#[test]
fn prepared_requires_target() {
    let mut selected = sql_bundle("SELECT value AS count FROM input");
    let artifact = &mut selected.artifacts[0];
    for implementation in [
        PackageImplementationV1::Native {
            export: "count".into(),
            artifact: vec![1],
            qualification: None,
        },
        PackageImplementationV1::Python {
            export: "count".into(),
            artifact: vec![1],
        },
    ] {
        artifact.implementations = vec![implementation];
        assert!(artifact.implementation("count").is_err());
        assert!(!artifact.prepared("count"));
    }
    let mut selected = sql_bundle("SELECT value AS count FROM input");
    selected.artifacts[0]
        .implementations
        .push(PackageImplementationV1::Wasm {
            exports: vec!["count".into()],
            artifact: vec![1],
        });
    assert!(selected.artifacts[0].implementation("count").is_err());
    assert!(!selected.artifacts[0].prepared("count"));
    assert!(!selected.artifacts[0].prepared("absent"));
}

#[test]
fn prepared_sql_inputs() -> TestResult {
    let fixture = Fixture::new()?;
    let selected =
        sql_bundle("SELECT CAST(COALESCE(SUM(value), 0) AS BIGINT UNSIGNED) AS count FROM input");
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: selected.clone(),
            parameters: None,
        },
        &control,
    )?;
    let active = fixture.activation(&selected.root.package_id)?;
    assert!(active.active);
    assert!(active.result_id.is_none());
    assert_eq!(active.checkpoint_revision, 0);
    let execution = InstalledAnalysis::new(fixture.owner.clone(), "test")?.snapshot([1; 16])?;
    let references = execution.refs()?;
    assert_eq!(references.len(), 1);
    assert_eq!(references[0].root, selected.root);
    assert_eq!(references[0].target.as_deref(), Some("sql"));
    let mut input = evaluation(&selected)?;
    let schema = Arc::new(
        selected.artifacts[0].descriptor.exports[0].inputs[0]
            .port
            .schema
            .clone(),
    );
    let cases = [
        (vec![vec![2, 3], vec![5]], 10),
        (vec![vec![11]], 11),
        (Vec::new(), 0),
        (vec![Vec::new()], 0),
    ];
    for (index, (chunks, expected)) in cases.into_iter().enumerate() {
        input.context.id = format!("provided:{index}");
        input.inputs[0].revision.id = input.context.id.clone();
        input.inputs[0].data.batches = chunks
            .into_iter()
            .map(|values| {
                sdk::RecordBatch::try_new(
                    Arc::clone(&schema),
                    vec![Arc::new(UInt64Array::from(values))],
                )
            })
            .collect::<std::result::Result<Vec<_>, _>>()?;
        let result = execution.evaluate([1; 16], &selected.root.package_id, &input, &control)?;
        assert_eq!(result.target, "sql");
        assert_eq!(result.revision, selected.root.revision);
        assert_eq!(result.descriptor, selected.artifacts[0].descriptor);
        assert_eq!(result.output.datasets.len(), 1);
        assert_eq!(result.output.datasets[0].name, "rows");
        let batches = &result.output.datasets[0].batches;
        assert_eq!(
            batches
                .iter()
                .map(sdk::RecordBatch::num_rows)
                .sum::<usize>(),
            1
        );
        let values = batches[0]
            .column(0)
            .as_any()
            .downcast_ref::<UInt64Array>()
            .ok_or("prepared SQL output type is invalid")?;
        assert_eq!(values.values().as_ref(), &[expected]);
    }
    assert_eq!(fixture.activation(&selected.root.package_id)?, active);
    Ok(())
}

#[test]
fn prepared_sql_schema() -> TestResult {
    let fixture = Fixture::new()?;
    let selected = sql_bundle("SELECT value AS count FROM input");
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    fixture.owner.execute_sync(
        fixture.grant.clone(),
        PackageRequestV1::Install {
            scope_id: "test".into(),
            bundle: selected.clone(),
            parameters: None,
        },
        &control,
    )?;
    let execution = InstalledAnalysis::new(fixture.owner.clone(), "test")?;
    let original = evaluation(&selected)?;
    let mut wrong = original.clone();
    wrong.inputs[0].data.batches = vec![sdk::RecordBatch::try_new(
        Arc::new(sdk::Schema::new(vec![sdk::Field::new(
            "value",
            sdk::DataType::Utf8,
            false,
        )])),
        vec![Arc::new(StringArray::from(vec!["seven"]))],
    )?];
    let mut missing = original.clone();
    missing.inputs.clear();
    let mut undeclared = original.clone();
    let mut extra = original.inputs[0].clone();
    extra.data.name = "undeclared".into();
    undeclared.inputs.push(extra);
    for input in [wrong, missing, undeclared] {
        assert!(matches!(
            execution.evaluate([1; 16], &selected.root.package_id, &input, &control),
            Err(crate::Error::AnalysisContract { .. })
        ));
    }
    let result = execution.evaluate([1; 16], &selected.root.package_id, &original, &control)?;
    assert_eq!(result.output.datasets[0].batches[0].num_rows(), 1);
    Ok(())
}

#[test]
fn prepared_sql_sources() -> TestResult {
    let fixture = Fixture::new()?;
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(60))?;
    let selected = sql_bundle("SELECT CAST(COUNT(*) AS BIGINT UNSIGNED) AS count FROM events");
    assert!(fixture
        .owner
        .execute_sync(
            fixture.grant.clone(),
            PackageRequestV1::Install {
                scope_id: "test".into(),
                bundle: selected.clone(),
                parameters: None,
            },
            &control,
        )
        .is_err());
    assert!(fixture
        .owner
        .activations([1; 16], "test", &selected.root.package_id)?
        .is_empty());
    Ok(())
}
