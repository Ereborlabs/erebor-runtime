use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn history_keeps_saved_scope() -> TestResult {
    let Saved {
        _directory,
        mut store,
        fixture,
        receipt,
        inputs,
        requests,
        ..
    } = Saved::new()?;
    let control = AnalysisReadControl::default();
    let original = fixture.current(&store)?;
    let broad = original.grant.selection.clone();
    let call = &receipt.results[&10].result_id;
    let selected = &receipt.selected.result_id;
    let ManagedOutput::Call {
        result: expected, ..
    } = store.managed_query_output(&broad, &original.spec.id, Some(call), 10, &control)?
    else {
        return Err("original call output absent".into());
    };
    let ManagedOutput::Selected {
        data: expected_rows,
        ..
    } = store.managed_query_output(&broad, &original.spec.id, Some(selected), 10, &control)?
    else {
        return Err("original selected output absent".into());
    };
    let removed = store.remove_managed(&original, || Ok(()))?;
    let mut grant = original.grant.clone();
    grant.revision += 1;
    grant.selection.nodes = vec!["node-a".into()];
    let recreated = store.recreate_managed(&removed, &removed.spec, &grant, || Ok(()))?;
    assert_ne!(recreated.generation, original.generation);
    assert_eq!(recreated.grant, grant);
    assert_eq!(recreated.progress, 0);
    assert!(!recreated.running);
    let mut unrelated = grant.selection.clone();
    unrelated.nodes = vec!["node-b".into()];
    let root = _directory.path().join("store");
    for reopen in [false, true] {
        if reopen {
            drop(store);
            store = Arc::new(AnalysisStore::open_with_limits(
                &root,
                Default::default(),
                crate::StorageLimitsV1 {
                    reader_admissions: Some(2),
                    ..Default::default()
                },
            )?);
        }
        assert_eq!(fixture.current(&store)?, recreated);
        for selection in [&grant.selection, &unrelated] {
            for id in [call, selected] {
                assert!(matches!(
                    store.managed_query_output(
                        selection,
                        &original.spec.id,
                        Some(id),
                        10,
                        &control,
                    ),
                    Err(crate::Error::Package {
                        code: Code::Denied,
                        field: "whole package scope",
                        ..
                    })
                ));
            }
        }
        assert!(matches!(
            store.managed_query_output(
                &AnalysisSelectionV1::tenant([2; 16]),
                &original.spec.id,
                Some(call),
                10,
                &control,
            ),
            Err(crate::Error::Package {
                code: Code::Missing,
                field: "managed instance",
                ..
            })
        ));
        let ManagedOutput::Call { result, .. } =
            store.managed_query_output(&broad, &original.spec.id, Some(call), 10, &control)?
        else {
            return Err("historical call output absent".into());
        };
        assert!(!result.current);
        assert_eq!(result.output, expected.output);
        assert_eq!(result.context, expected.context);
        assert_eq!(result.commit_revision, expected.commit_revision);
        let ManagedOutput::Selected { data, .. } =
            store.managed_query_output(&broad, &original.spec.id, Some(selected), 10, &control)?
        else {
            return Err("historical selected output absent".into());
        };
        assert_eq!(data.name, expected_rows.name);
        assert_eq!(data.batches, expected_rows.batches);
        assert_eq!(
            store.managed_history(&broad, &original.spec.id, &control)?,
            std::slice::from_ref(&receipt)
        );
        assert!(store
            .managed_history(&grant.selection, &original.spec.id, &control)?
            .is_empty());
        let retained = store
            .managed_attempt([1; 16], &original.spec.id, &receipt.attempt, &control)?
            .ok_or("original attempt absent")?;
        assert_eq!(retained.instance().grant, original.grant);
        assert_eq!(retained.receipt(), Some(&receipt));
        assert!(matches!(
            store.read_tables(
                &broad,
                AnalysisTableRead {
                    requests: &requests,
                    event_ranges: None,
                    inputs: Some(crate::AnalysisInputTables {
                        authorized: &broad,
                        outputs: &inputs,
                    }),
                    mode: AnalysisReadModeV1::Complete,
                    now: 10,
                },
                AnalysisExtractLimits::default(),
                &control,
            ),
            Err(crate::Error::AnalysisConflict { .. })
        ));
        assert_eq!(
            store
                .read_slots
                .as_ref()
                .ok_or("reader admissions absent")?
                .available_permits(),
            2
        );
    }
    Ok(())
}
