use super::*;

fn package_key(store: &NativeStore, package: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    for entry in store.view()?.snapshot().prefix(b"\0data/P") {
        let (key, bytes) = entry?;
        if key.len() != 15 {
            continue;
        }
        let (row, _, _): (PackageRevisionV1, u64, u64) = rmp_serde::from_slice(&bytes[1..])?;
        if row.package_id == package {
            return Ok(key.to_vec());
        }
    }
    Err("package row absent".into())
}

#[test]
fn reads_reject_stored_corruption() -> TestResult {
    for fault in ["context", "artifact", "descriptor", "body"] {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("data");
        let store = NativeStore::open(&root)?;
        let bundle = bundle()?;
        store.install_package(
            &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
            || Ok(()),
        )?;
        let context = AnalysisContextVersionV1::from_package(
            &bundle,
            [1; 16],
            &bundle.bundle().root,
            "model",
            "rows",
        )?;
        store.commit_context(&context)?;
        assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
        if fault == "context" {
            let mut corrupt = context.clone();
            let mut body = StoredContext::from_context(&context)?;
            body.output = "changed".into();
            corrupt.body = body.encode()?;
            replace_context(&store, &corrupt)?;
        } else {
            let key = package_key(&store, "native-root")?;
            let view = store.view()?;
            let mut tx = store.write()?;
            match fault {
                "artifact" => tx.native().remove(key),
                "descriptor" => {
                    let bytes = view.snapshot().get(&key)?.ok_or("package row")?;
                    let mut row: (PackageRevisionV1, u64, u64) =
                        rmp_serde::from_slice(&bytes[1..])?;
                    let mut descriptor: sdk::Package = serde_json::from_slice(&row.0.descriptor)?;
                    descriptor.exports[0].name = "changed".into();
                    row.0.descriptor = serde_json::to_vec(&descriptor)?;
                    tx.native()
                        .insert(key, [vec![0], rmp_serde::to_vec(&row)?].concat());
                }
                "body" => {
                    let key = [b"\0data/@package-body/".as_slice(), &key[7..]].concat();
                    let bytes = view.snapshot().get(&key)?.ok_or("package body")?;
                    let mut artifact = PackageArtifactV1::from_bytes(&bytes[1..])?;
                    let PackageImplementationV1::Sql { program, .. } =
                        &mut artifact.implementations[0]
                    else {
                        return Err("SQL implementation absent".into());
                    };
                    program.outputs.insert("rows".into(), "SELECT 2".into());
                    let changed = [vec![0], artifact.encode()?].concat();
                    assert_eq!(changed.len(), bytes.len());
                    tx.native().insert(key, changed);
                }
                _ => unreachable!(),
            }
            tx.commit([])?;
        }
        let before = store.meta()?;
        let cursor = store.database().inner().journal_head()?;
        if fault == "context" {
            let failure = store
                .commit_context(&context)
                .err()
                .ok_or("corrupt context accepted")?;
            assert_eq!(
                erebor_runtime_error::ErrorExt::status_code(&failure),
                erebor_runtime_error::StatusCode::IllegalState
            );
            assert_eq!(
                erebor_runtime_error::ErrorExt::retry_hint(&failure),
                erebor_runtime_error::RetryHint::NonRetryable
            );
            assert!(
                matches!(failure, Error::StoredArtifact { source, .. } if matches!(source.as_ref(), Error::Package {
                    code: Code::Invalid, field: "native package context identity", ..
                }))
            );
        }
        assert!(store.context_version(&context.key).is_err(), "{fault}");
        assert!(
            store
                .context_head_page([1; 16], "native-package-v1", None)
                .is_err(),
            "{fault}"
        );
        assert_eq!(store.meta()?, before);
        assert_eq!(store.database().inner().journal_head()?, cursor);
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "{fault}");
    }
    Ok(())
}

#[test]
fn warm_retry_checks_dependency() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(dir.path().join("data"))?;
    let bundle = bundle()?;
    store.install_package(
        &PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    let context = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "model",
        "rows",
    )?;
    store.commit_context(&context)?;
    assert_eq!(store.context_version(&context.key)?, Some(context.clone()));
    let dependency = package_key(&store, "native-dependency")?;
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    let mut tx = store.write()?;
    tx.context(&context, None)?;
    tx.native().remove(dependency);
    let failure = tx
        .context(&context, None)
        .err()
        .ok_or("missing dependency accepted on warm retry")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&failure),
        erebor_runtime_error::StatusCode::IllegalState
    );
    assert!(
        matches!(failure, Error::StoredArtifact { source, .. } if matches!(source.as_ref(), Error::Package {
            code: Code::Missing, field: "installed image artifact", ..
        }))
    );
    tx.rollback();
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let dependency = package_key(&store, "native-dependency")?;
    let mut tx = store.write()?;
    tx.native().remove(dependency);
    tx.commit([])?;
    let before = store.meta()?;
    let cursor = store.database().inner().journal_head()?;
    let failure = store
        .commit_context(&context)
        .err()
        .ok_or("missing dependency accepted on exact retry")?;
    assert_eq!(
        erebor_runtime_error::ErrorExt::status_code(&failure),
        erebor_runtime_error::StatusCode::IllegalState
    );
    assert!(
        matches!(failure, Error::StoredArtifact { source, .. } if matches!(source.as_ref(), Error::Package {
            code: Code::Missing, field: "installed image artifact", ..
        }))
    );
    assert_eq!(store.meta()?, before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store.context_version(&context.key).is_err());
    Ok(())
}
