use super::*;

fn large_spec(fixture: &Fixture) -> TestResult<ManagedSpec> {
    let mut spec = fixture.instance.spec.clone();
    spec.id = "large-contract".into();
    spec.definition.definition.description = "x".repeat(17 * 1024 * 1024);
    spec.manifest.definition = spec.definition.digest()?;
    Ok(spec)
}

fn large_outputs(fixture: &Fixture) -> TestResult<[sdk::Output; 2]> {
    let mut outputs = [fixture.output(2)?, fixture.output(3)?];
    outputs[0].reasons[0].details = sdk::RecordBatch::try_new(
        Arc::new(fixture.model.reasons[0].details.clone()),
        vec![Arc::new(sdk::arrow_array::StringArray::from(vec![
            "r".repeat(16 * 1024 * 1024 + 1)
        ]))],
    )?;
    Ok(outputs)
}

fn attempt_bytes(store: &AnalysisStore, instance: &str, attempt: &str) -> TestResult<Vec<u8>> {
    Ok(store.read_snapshot(|reader| {
        reader.query_row(
            "SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = ? AND attempt_id = ?",
            params![[1u8; 16].as_slice(), instance, attempt],
            |row| row.get(0),
        ).context(crate::AnalysisDatabaseSnafu { operation: "read managed contract bytes" })
    })?)
}

fn call_heads(
    store: &AnalysisStore,
    instance: &str,
) -> TestResult<Vec<(u64, u64, Option<String>)>> {
    Ok(store.read_snapshot(|reader| {
        let mut statement = reader.prepare(
            "SELECT call_id, state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? ORDER BY call_id",
        ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed rollback heads" })?;
        let rows = statement.query_map(params![[1u8; 16].as_slice(), instance], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        }).context(crate::AnalysisDatabaseSnafu { operation: "read managed rollback heads" })?;
        rows.collect::<duckdb::Result<Vec<_>>>()
            .context(crate::AnalysisDatabaseSnafu { operation: "decode managed rollback heads" })
    })?)
}

fn verify_publication(store: &AnalysisStore, receipt: &ManagedReceipt) -> TestResult {
    Ok(store.read_snapshot(|reader| {
        let references = [&receipt.results[&10], &receipt.results[&11], &receipt.selected];
        let mut rows = reader.prepare(
            "SELECT result_id, processor_id, body, request_meta FROM analysis_results WHERE result_id IN (?, ?, ?)",
        ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed charge rows" })?;
        let rows = rows.query_map(
            params![references[0].result_id, references[1].result_id, references[2].result_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?, row.get::<_, Vec<u8>>(3)?)),
        ).context(crate::AnalysisDatabaseSnafu { operation: "read managed charge rows" })?;
        let mut count = 0;
        for row in rows {
            let (id, processor, body, metadata) = row.context(crate::AnalysisDatabaseSnafu { operation: "decode managed charge row" })?;
            assert!(!id.is_empty() && !processor.is_empty() && !body.is_empty() && !metadata.is_empty());
            count += 1;
        }
        assert_eq!(count, 3);
        let mut payloads = reader.prepare(
            "SELECT result_id, role, ipc FROM managed_arrow WHERE result_id IN (?, ?, ?)",
        ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed charge payloads" })?;
        let payloads = payloads.query_map(
            params![references[0].result_id, references[1].result_id, references[2].result_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?, row.get::<_, Vec<u8>>(2)?)),
        ).context(crate::AnalysisDatabaseSnafu { operation: "read managed charge payloads" })?;
        let mut roles = BTreeMap::<String, usize>::new();
        let mut large = 0;
        for payload in payloads {
            let (id, role, ipc) = payload.context(crate::AnalysisDatabaseSnafu { operation: "decode managed charge payload" })?;
            assert!(!id.is_empty() && !role.is_empty() && !ipc.is_empty());
            if role == "reason" && ipc.len() > 16 * 1024 * 1024 {
                large += 1;
            }
            *roles.entry(role).or_default() += 1;
        }
        assert_eq!(large, 1);
        assert_eq!(roles, BTreeMap::from([
            ("checkpoint".into(), 2), ("input".into(), 2), ("output".into(), 2),
            ("parameters".into(), 2), ("reason".into(), 2), ("selected".into(), 1),
        ]));
        let mut edges = reader.prepare(
            "SELECT result_id, dependency_id FROM managed_edges WHERE result_id IN (?, ?, ?)",
        ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed charge edges" })?;
        let edges = edges.query_map(
            params![references[0].result_id, references[1].result_id, references[2].result_id],
            |row| Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?)),
        ).context(crate::AnalysisDatabaseSnafu { operation: "read managed charge edges" })?;
        let mut actual = BTreeSet::new();
        for edge in edges {
            let (id, dependency) = edge.context(crate::AnalysisDatabaseSnafu { operation: "decode managed charge edge" })?;
            actual.insert((id, dependency));
        }
        assert_eq!(actual, receipt.results.values().map(|reference| (receipt.selected.result_id.clone(), reference.result_id.clone())).collect());
        let mut heads = reader.prepare(
            "SELECT call_id, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ?",
        ).context(crate::AnalysisDatabaseSnafu { operation: "prepare managed charge heads" })?;
        let heads = heads.query_map(
            params![[1u8; 16].as_slice(), receipt.instance],
            |row| Ok((row.get::<_, u64>(0)?, row.get::<_, String>(1)?)),
        ).context(crate::AnalysisDatabaseSnafu { operation: "read managed charge heads" })?;
        let mut actual = BTreeMap::new();
        for head in heads {
            let (call, id) = head.context(crate::AnalysisDatabaseSnafu { operation: "decode managed charge head" })?;
            actual.insert(call, id);
        }
        assert_eq!(actual, receipt.results.iter().map(|(call, reference)| (*call, reference.result_id.clone())).collect());
        let references: (u64, u64) = reader.query_row(
            "SELECT (SELECT count(*) FROM evidence_refs), (SELECT count(*) FROM context_refs)",
            [], |row| Ok((row.get(0)?, row.get(1)?)),
        ).context(crate::AnalysisDatabaseSnafu { operation: "read empty managed reference charge" })?;
        assert_eq!(references, (0, 0));
        Ok(())
    })?)
}

#[test]
fn large_contract_preserves_bytes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let mut fixture = Fixture::admit(&store)?;
    let spec = large_spec(&fixture)?;
    store.admit_definition([1; 16], &spec.definition, || Ok(()))?;
    let definition: Vec<u8> = store.read_snapshot(|reader| reader.query_row(
        "SELECT definition FROM discovery_definitions WHERE tenant_id = ? AND name = ? AND revision = ?",
        params![[1u8; 16].as_slice(), spec.definition.definition.name, spec.manifest.definition],
        |row| row.get(0),
    ).context(crate::AnalysisDatabaseSnafu { operation: "read admitted definition bytes" }))?;
    assert_eq!(definition, serde_json::to_vec(&spec.definition)?);
    let grant = fixture.instance.grant.clone();
    fixture.instance = store.admit_managed(&spec, &grant, || Ok(()))?;
    let (version, scope, authority): (Vec<u8>, Vec<u8>, Vec<u8>) = store.read_snapshot(|reader| reader.query_row(
        "SELECT v.spec, v.scope, i.authority FROM managed_versions v JOIN managed_instances i USING (tenant_id, instance_id, generation) WHERE i.tenant_id = ? AND i.instance_id = ?",
        params![[1u8; 16].as_slice(), spec.id],
        |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
    ).context(crate::AnalysisDatabaseSnafu { operation: "read admitted managed bytes" }))?;
    assert!(!version.is_empty() && !scope.is_empty() && !authority.is_empty());
    let captured = fixture.capture(&store, false)?;
    let input = request("large-publication");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, None)?,
        fixture.evaluation(&input, 11, None)?,
    ];
    let outputs = large_outputs(&fixture)?;
    let pending = store
        .managed_attempt(
            [1; 16],
            &spec.id,
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending attempt absent")?;
    assert!(pending.receipt().is_none());
    let pending_bytes = attempt_bytes(&store, &spec.id, &input.id)?;
    let instance = fixture.current(&store)?;
    let heads = call_heads(&store, &spec.id)?;
    assert_eq!(heads, vec![(10, 0, None), (11, 0, None)]);
    let before = store.meta()?;
    let mut checked = false;
    let denied = fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            checked = true;
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .err()
        .ok_or("denied publication succeeded")?;
    assert!(checked);
    assert!(matches!(
        denied.downcast_ref::<crate::Error>(),
        Some(crate::Error::AnalysisReadDenied { .. })
    ));
    assert_eq!(store.meta()?, before);
    assert_eq!(fixture.current(&store)?, instance);
    assert_eq!(call_heads(&store, &spec.id)?, heads);
    let pending = store
        .managed_attempt(
            [1; 16],
            &spec.id,
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending attempt absent")?;
    assert_eq!(serde_json::to_vec(&pending.0)?, pending_bytes);
    let rows: (u64, u64) = store.read_snapshot(|reader| {
        reader.query_row(
        "SELECT (SELECT count(*) FROM analysis_results), (SELECT count(*) FROM managed_arrow)",
        [], |row| Ok((row.get(0)?, row.get(1)?)),
    ).context(crate::AnalysisDatabaseSnafu { operation: "read denied managed publication" })
    })?;
    assert_eq!(rows, (0, 0));
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    verify_publication(&store, &receipt)?;
    let ids = vec![receipt.results[&10].result_id.clone(); 65];
    assert_eq!(
        store.package_result_refs([1; 16], &ids)?,
        vec![receipt.results[&10].clone(); 65]
    );
    assert_eq!(
        store.package_evidence([1; 16], &ids)?,
        (Vec::new(), Vec::new())
    );
    assert!(store.package_result_refs([2; 16], &ids).is_err());
    assert_eq!(
        store.package_evidence([2; 16], &ids)?,
        (Vec::new(), Vec::new())
    );
    let committed = store.meta()?;
    assert_eq!(
        store
            .register_managed_attempt(&captured, &input, || Ok(()))?
            .receipt(),
        Some(&receipt)
    );
    assert_eq!(store.meta()?, committed);
    let backup = root.join("backups/large-managed");
    store.backup(&backup)?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    for store in [&reopened, &restored] {
        let retained = store
            .definition(
                [1; 16],
                &spec.definition.definition.name,
                Some(&spec.manifest.definition),
                &AnalysisReadControl::default(),
            )?
            .ok_or("definition absent")?;
        assert_eq!(retained, spec.definition);
        assert!(retained.definition.description.len() > 16 * 1024 * 1024);
        let current = fixture.current(store)?;
        assert_eq!(current.spec, spec);
        for call in [10, 11] {
            let saved = store.managed_result(
                &current,
                &receipt.results[&call].result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            let expected = &outputs[(call - 10) as usize];
            assert_eq!(saved.commit_revision, receipt.commit_revision);
            assert_eq!(
                saved.output.datasets[0].batches,
                expected.datasets[0].batches
            );
            assert_eq!(saved.output.evidence, expected.evidence);
            assert_eq!(saved.output.reasons[0].details, expected.reasons[0].details);
            assert_eq!(
                saved
                    .output
                    .checkpoint
                    .as_ref()
                    .ok_or("checkpoint absent")?
                    .datasets[0]
                    .batches,
                expected
                    .checkpoint
                    .as_ref()
                    .ok_or("expected checkpoint absent")?
                    .datasets[0]
                    .batches
            );
        }
        assert_eq!(
            store.managed_history(
                &current.grant.selection,
                &spec.id,
                &AnalysisReadControl::default()
            )?,
            vec![receipt.clone()]
        );
        let before = store.meta()?;
        assert!(store
            .register_managed_attempt(&captured, &input, || crate::AnalysisReadDeniedSnafu.fail())
            .is_err());
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store
                .register_managed_attempt(&captured, &input, || Ok(()))?
                .receipt(),
            Some(&receipt)
        );
        assert_eq!(store.meta()?, before);
        assert_eq!(
            store.package_result_refs([1; 16], &ids)?,
            vec![receipt.results[&10].clone(); 65]
        );
        assert_eq!(
            store.package_evidence([1; 16], &ids)?,
            (Vec::new(), Vec::new())
        );
    }
    Ok(())
}
