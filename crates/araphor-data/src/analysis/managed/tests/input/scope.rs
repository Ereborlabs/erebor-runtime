use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn history_keeps_saved_scope() -> TestResult {
    let Saved {
        _directory,
        mut store,
        fixture,
        receipt,
        ..
    } = Saved::new()?;
    let control = AnalysisReadControl::default();
    let original = fixture.current(&store)?;
    let broad = original.grant.selection.clone();
    let call = &receipt.results[&10].result_id;
    let selected = &receipt.selected.result_id;
    let expected = store.managed_result(&original, call, 10, &control)?;
    let expected_selected = store.managed_result(&original, selected, 10, &control)?;
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
            store = Arc::new(AnalysisStore::open_with_retention(
                &root,
                Default::default(),
            )?);
        }
        assert_eq!(fixture.current(&store)?, recreated);
        for selection in [&grant.selection, &unrelated] {
            for id in [call, selected] {
                let mut scoped = recreated.clone();
                scoped.grant.selection = selection.clone();
                assert!(matches!(
                    store.managed_result(&scoped, id, 10, &control),
                    Err(crate::Error::Package {
                        code: Code::Denied,
                        field: "whole package scope",
                        ..
                    })
                ));
            }
        }
        let mut foreign = recreated.clone();
        foreign.spec.tenant = [2; 16];
        foreign.grant.selection = AnalysisSelectionV1::tenant([2; 16]);
        assert!(matches!(
            store.managed_result(&foreign, call, 10, &control),
            Err(crate::Error::Package {
                code: Code::Missing,
                ..
            })
        ));
        let mut permitted = recreated.clone();
        permitted.grant.selection = broad.clone();
        let result = store.managed_result(&permitted, call, 10, &control)?;
        assert!(!result.current);
        let mut expected = expected.clone();
        expected.current = false;
        assert_eq!(
            serde_json::to_value(&result)?,
            serde_json::to_value(&expected)?
        );
        let selected_result = store.managed_result(&permitted, selected, 10, &control)?;
        assert_eq!(selected_result.result, expected_selected.result);
        assert_eq!(selected_result.receipt, expected_selected.receipt);
        assert_eq!(selected_result.source, expected_selected.source);
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
    }
    Ok(())
}
