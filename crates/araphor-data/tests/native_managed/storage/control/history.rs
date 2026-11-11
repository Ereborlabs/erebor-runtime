use super::*;
use araphor_data::PackageErrorCodeV1 as Code;

#[test]
fn history_keeps_original_receipts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = fixture(&store)?;
    let selection = &fixture.instance.grant.selection;
    let control = AnalysisReadControl::default();
    assert!(store
        .managed_history(selection, "counter", &control)?
        .is_empty());
    let mut expected = Vec::new();
    for id in ["second-name", "first-name"] {
        let capture = fixture.capture(&store)?;
        let input = request(id);
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let evaluations = [
            fixture.continued(&input, 10, Some(&capture))?,
            fixture.continued(&input, 11, Some(&capture))?,
        ];
        expected.push(fixture.publish(
            &store,
            &attempt,
            &evaluations,
            &[fixture.output(2)?, fixture.output(3)?],
        )?);
    }
    for (id, exit) in [
        ("failed", ManagedExit::Failed(Code::Invalid)),
        ("cancelled", ManagedExit::Cancelled),
    ] {
        let capture = fixture.capture(&store)?;
        let attempt = store.register_managed_attempt(&capture, &request(id), || Ok(()))?;
        store.finish_managed(&attempt, exit, || Ok(()))?;
    }
    let capture = fixture.capture(&store)?;
    let pending = store.register_managed_attempt(&capture, &request("pending"), || Ok(()))?;
    let current = fixture.current(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", current.lifecycle, true, || Ok(()))?;
    store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    let before = store.meta()?;
    for _ in 0..2 {
        let history = store.managed_history(selection, "counter", &control)?;
        assert_eq!(history, expected);
        let encoded = araphor_data::PackageResponseV1::History(history).encode()?;
        let araphor_data::PackageResponseV1::History(returned) =
            araphor_data::PackageResponseV1::from_bytes(&encoded)?
        else {
            return Err("history response variant".into());
        };
        assert_eq!(returned, expected);
    }
    assert_eq!(store.meta()?, before);
    assert!(pending.receipt().is_none());
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(
        store.managed_history(selection, "counter", &control)?,
        expected
    );
    assert!(store
        .managed_history(&AnalysisSelectionV1::tenant([2; 16]), "counter", &control)
        .is_err());
    let mut narrowed = selection.clone();
    narrowed.nodes = vec!["ungranted-node".into()];
    assert!(matches!(
        store.managed_history(&narrowed, "counter", &control),
        Err(araphor_data::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    control.cancel()?;
    assert!(matches!(
        store.managed_history(selection, "counter", &control),
        Err(araphor_data::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn history_checks_stored_binding() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = fixture(&store)?;
    let capture = fixture.capture(&store)?;
    let input = request("original");
    let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
    let receipt = fixture.publish(
        &store,
        &attempt,
        &[
            fixture.continued(&input, 10, Some(&capture))?,
            fixture.continued(&input, 11, Some(&capture))?,
        ],
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let (key, original) = attempt_record(&store, "original")?;
    let (ended, owner) = single(&store, b"\0data/E")?;
    assert_eq!(
        &ended[ended.len() - 8..],
        receipt.commit_revision.to_be_bytes()
    );
    assert_eq!(owner.as_slice(), &key[7..]);
    for case in 0..9 {
        let mut value: Value = rmp_serde::from_slice(&original[1..])?;
        let mut completed = receipt.commit_revision;
        match case {
            0 => {
                *mut_field(&mut value, &["capture", "tenant"])? = serde_value::to_value([2u8; 16])?
            }
            1 => {
                *mut_field(&mut value, &["capture", "instance"])? = Value::String("foreign".into())
            }
            2 => *mut_field(&mut value, &["request", "id"])? = Value::String("foreign".into()),
            3 => {
                *mut_field(&mut value, &["capture", "generation"])? =
                    Value::U64(fixture.instance.generation + 1)
            }
            4 | 5 | 7 => {
                let mut changed = receipt.clone();
                match case {
                    4 => changed.instance = "foreign".into(),
                    5 => changed.attempt = "foreign".into(),
                    _ => changed.results.get_mut(&10).ok_or("call")?.commit_revision -= 1,
                }
                *mut_field(&mut value, &["receipt"])? = serde_value::to_value(changed)?;
            }
            6 => completed += 1,
            _ => completed = 0,
        }
        let mut changed = ended.clone();
        let offset = changed.len() - 8;
        changed[offset..].copy_from_slice(&completed.to_be_bytes());
        let mut tx = store.write()?;
        tx.native().insert(&key, framed(&value)?);
        tx.native().remove(&ended);
        tx.native().insert(&changed, &owner);
        tx.commit([])?;
        assert!(
            matches!(
                store.managed_history(
                    &fixture.instance.grant.selection,
                    "counter",
                    &AnalysisReadControl::default()
                ),
                Err(Error::Package {
                    code: Code::Invalid,
                    ..
                })
            ),
            "case {case}"
        );
        let mut tx = store.write()?;
        tx.native().remove(&changed);
        tx.native().insert(&ended, &owner);
        tx.native().insert(&key, &original);
        tx.commit([])?;
    }
    assert_eq!(
        store.managed_history(
            &fixture.instance.grant.selection,
            "counter",
            &AnalysisReadControl::default()
        )?,
        vec![receipt]
    );
    Ok(())
}
