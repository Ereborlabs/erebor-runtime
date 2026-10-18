use super::*;

#[test]
fn packages_commit_contract_bytes() -> TestResult {
    let input = commit(activation("first", "v1"), "result");
    let expected = br#"{"activation":{"key":{"tenant_id":[1,1,1,1,1,1,1,1,1,1,1,1,1,1,1,1],"scope_id":"scope","package_id":"first","export":"model"},"revision":"v1","generation":0,"checkpoint_revision":0,"result_id":null,"grant_id":"grant","metadata":[123,125],"active":true},"checkpoint_revision":0,"window_id":"window","result_id":"result","dependencies":[],"source_revisions":[],"witnesses":[],"context_refs":[],"created_utc_ns":1}"#;
    assert_eq!(AnalysisStore::package_contract(&input)?, expected);
    let mut restored: PackageCommitV1 = serde_json::from_slice(expected)?;
    assert!(restored.request.is_empty());
    assert!(restored.metadata.is_empty());
    assert!(restored.datasets.is_empty());
    assert!(restored.checkpoint.is_empty());
    restored.request = input.request.clone();
    restored.metadata = input.metadata.clone();
    restored.datasets = input.datasets.clone();
    restored.checkpoint = input.checkpoint.clone();
    assert_eq!(restored, input);
    Ok(())
}

#[test]
fn packages_retry_full_contract() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let input = commit(active, "result");
    let receipt = store.commit_package(&input, || Ok(()))?;
    assert_eq!(
        store
            .package_result([1; 16], "result")?
            .ok_or("result")?
            .commit,
        input
    );
    let before = store.meta()?;
    for change in 0..12 {
        let mut changed = input.clone();
        match change {
            0 => changed.request.push(1),
            1 => changed.metadata.push(1),
            2 => changed.datasets.push(1),
            3 => changed.checkpoint.push(1),
            4 => changed.activation.grant_id.push('x'),
            5 => changed.expected_checkpoint_revision += 1,
            6 => changed.window_id.push('x'),
            7 => changed.dependencies.push(PackageResultRefV1 {
                result_id: "other".into(),
                commit_revision: 1,
            }),
            8 => changed.source_revisions.push(("events".into(), 0)),
            9 => changed.witnesses.push(crate::AnalysisWitnessV1 {
                identity: crate::EvidenceIntakeIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "node".into(),
                    node_boot_id: [2; 16],
                    label_epoch: 1,
                    source_id: [3; 16],
                    source_epoch: 1,
                }
                .into(),
                cursor: 1,
                expires_utc_ns: 2,
            }),
            10 => changed.context_refs.push(crate::AnalysisContextRefV1 {
                key: crate::AnalysisContextKeyV1 {
                    tenant_id: [1; 16],
                    owner_id: "context".into(),
                    entity_key: b"entity".to_vec(),
                    lifetime_key: b"lifetime".to_vec(),
                    owner_revision: 1,
                },
                commit_revision: 1,
            }),
            _ => changed.created_utc_ns += 1,
        }
        assert!(
            matches!(
                store.commit_package(&changed, || Ok(())),
                Err(crate::Error::AnalysisConflict { .. })
            ),
            "change {change}"
        );
        assert_eq!(store.meta()?, before);
    }
    assert!(store
        .commit_package(&input, || crate::AnalysisConflictSnafu.fail())
        .is_err());
    assert_eq!(store.commit_package(&input, || Ok(()))?, receipt);
    Ok(())
}

fn dependencies(store: &AnalysisStore) -> crate::Result<PackageCommitV1> {
    let first = start(store, "first")?;
    let second = start(store, "second")?;
    let dependent = start(store, "dependent")?;
    let first = store.commit_package(&commit(first, "first"), || Ok(()))?;
    let second = store.commit_package(&commit(second, "second"), || Ok(()))?;
    let mut input = commit(dependent, "result");
    input.dependencies = vec![second, first];
    store.commit_package(&input, || Ok(()))?;
    Ok(input)
}

#[test]
fn packages_dependency_contract_roundtrip() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let input = dependencies(&store)?;
    assert_eq!(
        store
            .package_result([1; 16], "result")?
            .ok_or("result")?
            .commit,
        input
    );
    let mut changed = input.clone();
    changed.dependencies.reverse();
    assert!(matches!(
        store.commit_package(&changed, || Ok(())),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    AnalysisStore::validate_state(store.writer()?.get()?, &store.root)?;
    drop(store);
    let reopened = AnalysisStore::open(&root)?;
    assert_eq!(
        reopened
            .package_result([1; 16], "result")?
            .ok_or("result")?
            .commit,
        input
    );
    let backup = root.join("backups/dependencies");
    reopened.backup(&backup)?;
    let restored = AnalysisStore::restore(&backup, &directory.path().join("restored"))?;
    assert_eq!(
        restored
            .package_result([1; 16], "result")?
            .ok_or("result")?
            .commit,
        input
    );
    Ok(())
}

#[test]
fn packages_native_result_indexes() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let input = dependencies(&store)?;
    let mut writer = store.writer()?;
    assert!(
        AnalysisStore::package_result_from(writer.get()?, [9; 16], "result", &store.root)?
            .is_none()
    );
    for mutation in [
        "UPDATE package_results SET scope_id = 'other' WHERE result_id = 'result'",
        "UPDATE package_results SET package_id = 'other' WHERE result_id = 'result'",
        "UPDATE package_results SET export_name = 'other' WHERE result_id = 'result'",
        "UPDATE package_results SET revision = 'other' WHERE result_id = 'result'",
        "UPDATE package_results SET window_id = 'other' WHERE result_id = 'result'",
    ] {
        let transaction = writer.get_mut()?.transaction()?;
        transaction.execute(mutation, [])?;
        assert!(
            matches!(AnalysisStore::package_result_from(&transaction, [1; 16], "result", &store.root),
            Err(crate::Error::AnalysisState { reason, .. }) if reason == "the retained package result key differs"),
            "{mutation}"
        );
        transaction.rollback()?;
    }
    for change in 0..2 {
        let mut changed = input.clone();
        if change == 0 {
            changed.result_id = "other".into();
        } else {
            changed.activation.key.tenant_id = [9; 16];
        }
        let transaction = writer.get_mut()?.transaction()?;
        transaction.execute(
            "UPDATE package_results SET commit_meta = ? WHERE result_id = 'result'",
            duckdb::params![AnalysisStore::package_contract(&changed)?],
        )?;
        assert!(
            matches!(AnalysisStore::package_result_from(&transaction, [1; 16], "result", &store.root),
            Err(crate::Error::AnalysisState { reason, .. }) if reason == "the retained package result contract differs")
        );
        transaction.rollback()?;
    }
    Ok(())
}

#[test]
fn packages_result_charge() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let active = start(&store, "first")?;
    let input = commit(active, "result");
    let before = store.read_snapshot(|reader| {
        AnalysisStore::logical_usage(reader, [1; 16]).map(|usage| usage.1)
    })?;
    store.commit_package(&input, || Ok(()))?;
    let key = &input.activation.key;
    let row = 256
        + input.result_id.len()
        + key.scope_id.len()
        + key.package_id.len()
        + key.export.len()
        + input.activation.revision.len()
        + input.window_id.len()
        + input.datasets.len()
        + input.checkpoint.len()
        + AnalysisStore::package_contract(&input)?.len();
    let head = 256
        + key.scope_id.len()
        + key.package_id.len()
        + key.export.len()
        + input.window_id.len()
        + input.result_id.len();
    let after = store.read_snapshot(|reader| {
        AnalysisStore::logical_usage(reader, [1; 16]).map(|usage| usage.1)
    })?;
    let receipt = 256
        + input.result_id.len()
        + "analysis-package".len()
        + input.metadata.len()
        + input.request.len();
    assert_eq!(
        after - before,
        (row + head + input.result_id.len() + receipt) as u64
    );
    AnalysisStore::validate_state(store.writer()?.get()?, &store.root)?;
    Ok(())
}

#[test]
fn packages_dependency_corruption() -> TestResult {
    for change in 0..8 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        let input = dependencies(&store)?;
        let mut contract = serde_json::to_value(&input)?;
        let mut bytes = None;
        match change {
            0 => {
                contract
                    .as_object_mut()
                    .ok_or("contract")?
                    .remove("dependencies");
            }
            1 => contract["dependencies"] = serde_json::json!(true),
            2 => contract["dependencies"] = serde_json::json!([]),
            3 => contract["dependencies"][0]["result_id"] = serde_json::json!("absent"),
            4 => contract["dependencies"][0]["commit_revision"] = serde_json::json!(1),
            5 => contract["dependencies"][0] = contract["dependencies"][1].clone(),
            6 => bytes = Some(b"{".to_vec()),
            _ => {
                contract["dependencies"][0]["result_id"] =
                    serde_json::json!("x".repeat(1024 * 1024))
            }
        }
        let bytes = bytes.unwrap_or(serde_json::to_vec(&contract)?);
        {
            let mut writer = store.writer()?;
            writer.get_mut()?.execute(
                "UPDATE package_results SET commit_meta = ? WHERE result_id = 'result'",
                duckdb::params![bytes],
            )?;
        }
        if matches!(change, 0 | 1 | 6) {
            assert!(
                matches!(
                    store.package_result([1; 16], "result"),
                    Err(crate::Error::AnalysisDatabase {
                        source: duckdb::Error::FromSqlConversionFailure(
                            11,
                            duckdb::types::Type::Blob,
                            _
                        ),
                        ..
                    })
                ),
                "change {change}"
            );
        }
        drop(store);
        let reopened = AnalysisStore::open(&root);
        if matches!(change, 0 | 1 | 6) {
            assert!(
                matches!(reopened, Err(crate::Error::Json { .. })),
                "change {change}"
            );
        } else {
            assert!(
                matches!(reopened, Err(crate::Error::AnalysisState { .. })),
                "change {change}"
            );
        }
    }
    Ok(())
}

#[test]
fn packages_dependency_reference_corruption() -> TestResult {
    for mutation in [
        "DELETE FROM package_dependencies WHERE result_id = 'result' AND dependency_id = 'first'",
        "UPDATE package_dependencies SET commit_revision = commit_revision + 1 WHERE result_id = 'result' AND dependency_id = 'first'",
        "INSERT INTO package_dependencies SELECT tenant_id, 'result', result_id, commit_revision FROM analysis_results WHERE result_id = 'result'",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("store");
        let store = AnalysisStore::open(&root)?;
        dependencies(&store)?;
        store.writer()?.get_mut()?.execute(mutation, [])?;
        drop(store);
        assert!(AnalysisStore::open(&root).is_err(), "{mutation}");
    }
    Ok(())
}
