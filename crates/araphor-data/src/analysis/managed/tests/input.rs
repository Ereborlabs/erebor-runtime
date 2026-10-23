use super::*;

#[test]
fn retained_header_skips_ipc() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit(&store)?;
    let capture = fixture.capture(&store, false)?;
    let request = request("header");
    let attempt = store.register_managed_attempt(&capture, &request, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&request, 10, None)?,
        fixture.evaluation(&request, 11, None)?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let reference = &receipt.results[&10];
    store
        .writer()?
        .get_mut()?
        .execute(
            "UPDATE managed_arrow SET ipc = ? WHERE result_id = ?",
            params![b"invalid IPC".as_slice(), reference.result_id],
        )
        .context(crate::AnalysisDatabaseSnafu {
            operation: "corrupt test managed payload",
        })?;
    let before = store.meta()?;
    let (pin, port) = store.managed_input(
        &fixture.instance.grant.selection,
        &fixture.instance.spec.id,
        reference,
        "rows",
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(pin.result(), reference);
    assert_eq!(pin.output().package, "managed-fixture");
    assert_eq!(port.schema, fixture.model.outputs[0].schema);
    let inputs = [(
        crate::AnalysisInputSource::Managed(Arc::new(pin)),
        Arc::new(port.schema),
    )];
    let requests = AnalysisTableRequests::new();
    for mode in [AnalysisReadModeV1::Metadata, AnalysisReadModeV1::Complete] {
        let read = store.read_tables(
            &fixture.instance.grant.selection,
            AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                inputs: Some(crate::AnalysisInputTables {
                    authorized: &fixture.instance.grant.selection,
                    scope: "",
                    outputs: &inputs,
                }),
                mode,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        );
        if matches!(mode, AnalysisReadModeV1::Metadata) {
            let page = read?;
            assert!(page.packages.is_empty());
            assert_eq!(
                page.extraction
                    .references
                    .iter()
                    .filter_map(|entry| entry.result())
                    .collect::<Vec<_>>(),
                [reference]
            );
        } else {
            assert!(matches!(read, Err(crate::Error::AnalysisContract { .. })));
        }
    }
    assert_eq!(store.meta()?, before);
    Ok(())
}
