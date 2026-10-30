use super::super::model::Attempt;
use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn history_keeps_original_receipts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = AnalysisStore::open(&root)?;
    let fixture = Fixture::admit(&store)?;
    let selection = &fixture.instance.grant.selection;
    let control = AnalysisReadControl::default();
    assert!(store
        .managed_history(selection, "counter", &control)?
        .is_empty());
    let mut expected = Vec::new();
    for id in ["second-name", "first-name"] {
        let capture = fixture.capture(&store, false)?;
        let input = request(id);
        let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&capture))?,
            fixture.evaluation(&input, 11, Some(&capture))?,
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
        let capture = fixture.capture(&store, false)?;
        let attempt = store.register_managed_attempt(&capture, &request(id), || Ok(()))?;
        store.finish_managed(&attempt, exit, || Ok(()))?;
    }
    let capture = fixture.capture(&store, false)?;
    let pending = store.register_managed_attempt(&capture, &request("pending"), || Ok(()))?;
    let current = fixture.current(&store)?;
    let running =
        store.set_managed_running([1; 16], "counter", current.lifecycle, true, || Ok(()))?;
    store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    let before = store.meta()?;
    for _ in 0..2 {
        let history = store.managed_history(selection, "counter", &control)?;
        assert_eq!(history, expected);
        let encoded = crate::PackageResponseV1::History(history).encode()?;
        let crate::PackageResponseV1::History(returned) =
            crate::PackageResponseV1::from_bytes(&encoded)?
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
        Err(crate::Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    control.cancel()?;
    assert!(matches!(
        store.managed_history(selection, "counter", &control),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}

#[test]
fn history_checks_stored_binding() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let capture = fixture.capture(&store, false)?;
    let input = request("original");
    let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
    let receipt = fixture.publish(
        &store,
        &attempt,
        &[
            fixture.evaluation(&input, 10, Some(&capture))?,
            fixture.evaluation(&input, 11, Some(&capture))?,
        ],
        &[fixture.output(2)?, fixture.output(3)?],
    )?;
    let original = {
        let mut writer = store.writer()?;
        writer.get_mut()?.query_row("SELECT contract FROM managed_attempts WHERE tenant_id = ? AND instance_id = 'counter' AND attempt_id = 'original'", params![[1u8;16].as_slice()], |row| row.get::<_, Vec<u8>>(0))?
    };
    for case in 0..9 {
        let mut value: Attempt = ManagedCodec::decode(&original)?;
        let mut completed = receipt.commit_revision;
        match case {
            0 => value.capture.tenant = [2; 16],
            1 => value.capture.instance = "foreign".into(),
            2 => value.request.id = "foreign".into(),
            3 => value.capture.generation += 1,
            4 => value.receipt.as_mut().ok_or("receipt")?.instance = "foreign".into(),
            5 => value.receipt.as_mut().ok_or("receipt")?.attempt = "foreign".into(),
            6 => completed += 1,
            7 => {
                value
                    .receipt
                    .as_mut()
                    .ok_or("receipt")?
                    .results
                    .get_mut(&10)
                    .ok_or("call")?
                    .commit_revision -= 1
            }
            _ => completed = 0,
        }
        {
            let mut writer = store.writer()?;
            writer.get_mut()?.execute("UPDATE managed_attempts SET contract = ?, completed = ? WHERE tenant_id = ? AND instance_id = 'counter' AND attempt_id = 'original'", params![ManagedCodec::encode(&value)?, completed, [1u8;16].as_slice()])?;
        }
        assert!(
            matches!(
                store.managed_history(
                    &fixture.instance.grant.selection,
                    "counter",
                    &AnalysisReadControl::default()
                ),
                Err(crate::Error::Package {
                    code: Code::Invalid,
                    ..
                })
            ),
            "case {case}"
        );
    }
    {
        let mut writer = store.writer()?;
        writer.get_mut()?.execute("UPDATE managed_attempts SET contract = ?, completed = ? WHERE tenant_id = ? AND instance_id = 'counter' AND attempt_id = 'original'", params![original, receipt.commit_revision, [1u8;16].as_slice()])?;
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
