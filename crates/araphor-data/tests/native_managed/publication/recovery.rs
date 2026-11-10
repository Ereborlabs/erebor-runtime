use super::*;

#[test]
fn recovery_rejects_zero_or_stale_successful_progress() -> TestResult {
    for zero in [true, false] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let (instance, model) = super::super::graph::fixture(&store)?;
        let control = AnalysisReadControl::default();
        let mut receipts = Vec::new();
        for step in 0..2 {
            let resume = store.managed_resume([1; 16], &instance.spec.id, &control)?;
            let page = if step == 0 {
                super::super::attempts::capture(&store, &resume.instance, false)?
            } else {
                capture(&store, &resume)?
            };
            let attempt = Arc::new(store.register_managed_attempt(
                &page.state,
                &super::super::attempts::request(&format!("success-{step}"), true),
                || Ok(()),
            )?);
            let journals = journals(&store, &attempt, &model, step != 0)?;
            receipts.push(publish(&store, &attempt, &model, &journals, false)?);
        }
        let resume = store.managed_resume([1; 16], &instance.spec.id, &control)?;
        let page = capture(&store, &resume)?;
        store.register_managed_attempt(
            &page.state,
            &super::super::attempts::request("pending", false),
            || Ok(()),
        )?;
        let snapshot = store.view()?;
        let mut tx = store.write()?;
        let mut changed = false;
        for entry in snapshot.snapshot().prefix(b"\0data/a") {
            let (key, bytes) = entry?;
            if key.len() != 15 {
                continue;
            }
            let mut value: serde_value::Value = rmp_serde::from_slice(&bytes[1..])?;
            if super::super::attempts::field(&mut value, &["request", "id"])?
                != &serde_value::Value::String("pending".into())
            {
                continue;
            }
            let progress = if zero { 0 } else { receipts[0].commit_revision };
            *super::super::attempts::field(&mut value, &["capture", "progress"])? =
                serde_value::Value::U64(progress);
            if zero {
                *super::super::attempts::field(&mut value, &["capture", "completed"])? =
                    serde_value::Value::U64(0);
            }
            tx.native()
                .insert(key, [vec![0], rmp_serde::to_vec(&value)?].concat());
            changed = true;
        }
        assert!(changed);
        tx.commit([])?;
        drop(snapshot);
        drop(page);
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "accepted zero={zero}");
    }
    Ok(())
}
