use super::super::super::attempts::field;
use super::*;
use serde_value::Value;

#[test]
fn prior_state_rejects_corruption() -> TestResult {
    for case in 0..3 {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("store"))?;
        let fixture = fixture(&store, false)?;
        let mut receipts = Vec::new();
        for name in ["initial", "continued"] {
            let capture = fixture.capture(&store)?;
            let input = request(name);
            let attempt = store.register_managed_attempt(&capture, &input, || Ok(()))?;
            let evaluations = [
                fixture.continued(&input, 10, Some(&capture))?,
                fixture.continued(&input, 11, Some(&capture))?,
            ];
            receipts.push(fixture.publish(
                &store,
                &attempt,
                &evaluations,
                &[fixture.output(2)?, fixture.output(3)?],
            )?);
        }
        let id = &receipts[1].results[&10].result_id;
        let current = fixture.current(&store)?;
        let (mut key, bytes) = super::super::output::result_record(store.view()?.as_ref(), id)?;
        let corrupted = if case == 2 {
            key[6] = b'U';
            let bytes = store
                .view()?
                .snapshot()
                .get(&key)?
                .ok_or("prior checkpoint")?;
            let mut wire: Option<sdk::wire::Checkpoint> = rmp_serde::from_slice(&bytes[1..])?;
            wire.as_mut().ok_or("prior checkpoint")?.version += 1;
            rmp_serde::to_vec_named(&wire)?
        } else {
            let mut record: Value = rmp_serde::from_slice(&bytes[1..])?;
            if case == 0 {
                *field(
                    &mut record,
                    &["body", "Call", "context", "context", "time_utc_ns"],
                )? = serde_value::to_value(11i64)?;
            } else {
                *field(&mut record, &["body", "Call", "call"])? = serde_value::to_value(11u64)?;
            }
            rmp_serde::to_vec(&record)?
        };
        let mut writer = store.write()?;
        writer.native().insert(key, [vec![0], corrupted].concat());
        writer.commit([])?;
        let before = store.meta()?;
        if case == 2 {
            assert!(fixture.capture(&store).is_err(), "case {case}");
        } else {
            assert!(
                store
                    .managed_result(&current, id, 10, &AnalysisReadControl::default())
                    .is_err(),
                "case {case}"
            );
        }
        assert_eq!(store.meta()?, before);
    }
    Ok(())
}
