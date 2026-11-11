use super::*;

#[test]
fn source_rejects_rebound_positions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    append(&store, 2)?;
    let page = super::super::super::attempts::capture(&store, &instance, false)?;
    let input = select(&store, &page, &[1, 2], None)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::super::attempts::request("positions", true),
        || Ok(()),
    )?;
    let frame = page.state.source().ok_or("source frame")?;
    let derived = frame.seal_derived(&input, &BTreeMap::new(), &[], None, Arc::new(()))?;
    let before = store.view()?;
    let journal = store.database().inner().journal_head()?;
    let records = before
        .snapshot()
        .prefix(b"\0data/")
        .collect::<Result<Vec<_>, _>>()?;
    for future in [true, false] {
        let mut rebound = input.clone();
        if future {
            rebound.input_positions[0].1.commit_revision = page.state.revision() + 1;
        } else {
            let first = rebound.input_positions[0].1;
            rebound.input_positions[0].1 = rebound.input_positions[1].1;
            rebound.input_positions[1].1 = first;
        }
        assert!(matches!(
            frame.seal_derived(&rebound, &BTreeMap::new(), &[], None, Arc::new(())),
            Err(Error::Package {
                code: Code::Denied,
                field: "derived canonical event mismatch",
                ..
            })
        ));
        assert!(matches!(
            frame.select_graph_input(
                &page.state,
                None,
                &rebound,
                &derived,
                None,
                (1, 2, 2000),
                (false, false, false),
                Arc::new(())
            ),
            Err(Error::Package {
                code: Code::Denied,
                field: "native source selection handle",
                ..
            })
        ));
        let current = store.view()?;
        assert_eq!(current.meta(), before.meta());
        assert_eq!(store.database().inner().journal_head()?, journal);
        assert_eq!(
            current
                .snapshot()
                .prefix(b"\0data/")
                .collect::<Result<Vec<_>, _>>()?,
            records
        );
    }
    let receipt = publish(&store, &attempt, false)?;
    assert_eq!(receipt.graph, Some(receipt.selected.clone()));
    let head = store.processor_result(&scope())?.ok_or("processor head")?;
    assert_eq!(head.result_id, receipt.selected.result_id);
    assert_eq!(
        store
            .processor_health(&scope())?
            .ok_or("processor health")?
            .consumed_cursor,
        2
    );
    let saved = store
        .managed_attempt(
            [1; 16],
            "source",
            "positions",
            &AnalysisReadControl::default(),
        )?
        .ok_or("saved attempt")?;
    assert_eq!(
        store.graph_record_keys(
            &page.state,
            Some(&saved),
            &receipt.selected,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )?,
        input
            .records
            .iter()
            .map(|record| record.id.clone())
            .collect::<Vec<_>>()
    );
    let selection = frame.input_selection()?.ok_or("source selection")?;
    assert_eq!(selection.records(), input.input_positions);
    assert_eq!(
        store.graph_window_headers(&identity(), None)?[0].0,
        receipt.selected.result_id
    );
    Ok(())
}
