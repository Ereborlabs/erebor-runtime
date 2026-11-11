use super::*;

#[derive(serde::Deserialize, serde::Serialize)]
struct PackageRecord {
    value: araphor_data::analysis::PackageRevisionV1,
    revision: u64,
    body_bytes: u64,
}

#[test]
fn descriptor_error_order() -> TestResult {
    for mode in [
        "equivalent",
        "changed",
        "malformed",
        "wrong-id",
        "wrong-revision",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = Fixture::new(&store, [1; 16], "contracts", false)?;
        let instance = fixture.admit(&store)?;
        let page = super::super::attempts::capture(&store, &instance, false)?;
        let attempt = store.register_managed_attempt(
            &page.state,
            &super::super::attempts::request("descriptor", false),
            || Ok(()),
        )?;
        let schema = instance.spec.manifest.selected_schema.clone();
        let model = sdk::Model::new("count", Vec::new(), vec![sdk::Port::new("rows", schema)]);
        let evaluation = evaluation(&attempt);
        let output = output(&model)?;
        let returns = [ManagedReturn {
            call: 10,
            evaluation: &evaluation,
            output: &output,
            changes: None,
            graph: None,
            retained: None,
        }];
        let control = AnalysisReadControl::default();
        let input = ManagedCommit {
            control: &control,
            budget: &super::super::graph::Budget,
            attempt: &attempt,
            completed: true,
            now_utc_ns: 1000,
            returns: &returns,
            selected: &output.datasets[0],
            selected_schema: &instance.spec.manifest.selected_schema,
        };
        let prepared = store.prepare_managed(&input)?;
        let view = store.view()?;
        let (key, original) = view
            .snapshot()
            .prefix(b"\0data/P")
            .next()
            .ok_or("package metadata")??;
        let mut row: PackageRecord = rmp_serde::from_slice(&original[1..])?;
        let mut package: sdk::Package = serde_json::from_slice(&row.value.descriptor)?;
        row.value.descriptor = match mode {
            "equivalent" => serde_json::to_vec_pretty(&package)?,
            "changed" => {
                package.exports[0].name = "different".into();
                serde_json::to_vec(&package)?
            }
            "wrong-id" => {
                package.id = "different".into();
                serde_json::to_vec(&package)?
            }
            "wrong-revision" => {
                package.revision = "different".into();
                serde_json::to_vec(&package)?
            }
            _ => b"{".to_vec(),
        };
        let mut bytes = vec![0];
        bytes.extend(rmp_serde::to_vec_named(&row)?);
        let mut tx = store.write()?;
        tx.native().insert(key.as_ref(), bytes);
        tx.commit([])?;
        let before = store.meta()?;
        let journal = store.database().inner().journal_head()?;
        let mut guarded = false;
        let error = store
            .commit_managed(prepared, || {
                guarded = true;
                Err(Code::Denied.error("contract guard"))
            })
            .err()
            .ok_or("mutated descriptor passed the guard")?;
        match mode {
            "equivalent" => {
                assert!(guarded);
                assert!(matches!(
                    error,
                    Error::Package {
                        code: Code::Denied,
                        field: "contract guard",
                        ..
                    }
                ));
            }
            "changed" => {
                assert!(!guarded);
                assert!(matches!(error, Error::AnalysisConflict { .. }));
            }
            "malformed" => {
                assert!(!guarded);
                assert!(matches!(error, Error::PackageEncoding { .. }));
            }
            _ => {
                assert!(!guarded);
                assert!(matches!(
                    error,
                    Error::Package {
                        code: Code::Invalid,
                        field: "managed SDK descriptor pin",
                        ..
                    }
                ));
            }
        }
        assert_eq!(store.meta()?, before, "{mode}");
        assert_eq!(store.database().inner().journal_head()?, journal, "{mode}");
        assert!(store
            .view()?
            .snapshot()
            .prefix(b"\0data/X")
            .next()
            .is_none());
        let mut tx = store.write()?;
        tx.native().insert(key, original);
        tx.commit([])?;
        let receipt = store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?;
        assert_eq!(receipt.results.len(), 1);
        drop((view, attempt, page, store));
        let store = NativeStore::open(&root)?;
        assert_eq!(
            store
                .managed_result(&instance, &receipt.results[&10].result_id, 1000, &control)?
                .receipt,
            receipt
        );
    }
    Ok(())
}
