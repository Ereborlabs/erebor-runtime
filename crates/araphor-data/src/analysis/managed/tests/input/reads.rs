use std::sync::atomic::{AtomicBool, Ordering};

use super::*;

fn values(batches: &[sdk::RecordBatch], column: &str) -> TestResult<Vec<u64>> {
    let mut output = Vec::new();
    for batch in batches {
        let values = batch
            .column_by_name(column)
            .ok_or("selected column absent")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("selected column is not UInt64")?;
        output.extend_from_slice(values.values());
    }
    Ok(output)
}

impl Saved {
    pub(super) fn original(
        &self,
        page: &crate::AnalysisPositionPageV1,
        meta: &crate::AnalysisStoreMetaV1,
    ) -> TestResult {
        assert_eq!(&page.extraction.meta, meta);
        assert_eq!(values(&page.tables["events"], "source_cursor")?, [1]);
        let (schema, batches, coverage) = page.packages.get(&0).ok_or("saved rows absent")?;
        assert_eq!(schema.as_ref(), &self.fixture.model.outputs[0].schema);
        assert_eq!(values(batches, "value")?, [7]);
        assert_eq!(
            coverage,
            &sdk::Coverage {
                state: sdk::CoverageState::Complete,
                limits: Vec::new(),
            }
        );
        assert_eq!(page.packages.len(), 1);
        assert_eq!(page.extraction.references.len(), 2);
        assert_eq!(
            page.extraction
                .references
                .iter()
                .filter_map(|entry| entry.result())
                .collect::<Vec<_>>(),
            [&self.receipt.results[&10]]
        );
        assert_eq!(
            page.extraction
                .references
                .iter()
                .filter_map(|entry| entry.context())
                .collect::<Vec<_>>(),
            [&self.context]
        );
        assert_eq!(
            page.extraction.witnesses,
            [
                crate::AnalysisWitnessV1 {
                    identity: crate::analysis::tests::identity().into(),
                    cursor: 1,
                    expires_utc_ns: 0,
                },
                crate::AnalysisWitnessV1 {
                    identity: crate::analysis::tests::identity().into(),
                    cursor: 1,
                    expires_utc_ns: 100,
                },
            ]
        );
        Ok(())
    }

    pub(super) fn permits(&self) -> TestResult {
        assert_eq!(
            self.store
                .read_slots
                .as_ref()
                .ok_or("reader admissions absent")?
                .available_permits(),
            2
        );
        Ok(())
    }
}

#[test]
fn retained_snapshot() -> TestResult {
    let saved = Arc::new(Saved::new()?);
    let before = saved.store.meta()?;
    let control = AnalysisReadControl::default();
    let writer = Arc::clone(&saved);
    control.on_read_step(move || {
        let publish = || -> TestResult {
            Saved::append(&writer.store, 2)?;
            let captured = writer.capture()?;
            let mut input = request("saved-next");
            input.witness_expiry = 100;
            let attempt = writer
                .store
                .register_managed_attempt(&captured, &input, || Ok(()))?;
            let evaluations = [
                writer.fixture.evaluation(&input, 10, Some(&captured))?,
                writer.fixture.evaluation(&input, 11, Some(&captured))?,
            ];
            let outputs = [writer.fixture.output(8)?, writer.fixture.output(3)?];
            writer
                .fixture
                .publish(&writer.store, &attempt, &evaluations, &outputs)?;
            Ok(())
        };
        publish().map_err(|error| match error.downcast::<crate::Error>() {
            Ok(error) => *error,
            Err(error) => writer.store.state_error(&error.to_string()),
        })
    })?;
    let selection = &saved.fixture.instance.grant.selection;
    let page = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    saved.original(&page, &before)?;
    assert!(matches!(
        saved.read(
            selection,
            selection,
            &saved.inputs,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::Package {
            code: crate::PackageErrorCodeV1::Incomplete,
            field: "managed input freshness",
            ..
        })
    ));
    let captured = saved.capture()?;
    let prior = captured.prior(10).ok_or("latest native call absent")?;
    let reference = crate::analysis::PackageResultRefV1 {
        result_id: prior.result.clone(),
        commit_revision: prior.revision,
    };
    assert_ne!(reference, saved.receipt.results[&10]);
    assert!(reference.commit_revision > before.commit_revision);
    let (pin, port) = saved.store.managed_input(
        selection,
        &saved.fixture.instance.spec.id,
        &reference,
        "rows",
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let inputs = [(Arc::new(pin), Arc::new(port.schema))];
    let next = saved.read(
        selection,
        selection,
        &inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(next.extraction.meta.commit_revision > before.commit_revision);
    assert_eq!(values(&next.tables["events"], "source_cursor")?, [1, 2]);
    let (schema, batches, coverage) = next.packages.get(&0).ok_or("latest rows absent")?;
    assert_eq!(schema.as_ref(), &saved.fixture.model.outputs[0].schema);
    assert_eq!(values(batches, "value")?, [8]);
    assert_eq!(coverage.state, sdk::CoverageState::Complete);
    assert_eq!(
        next.extraction
            .references
            .iter()
            .filter_map(|entry| entry.result())
            .collect::<Vec<_>>(),
        [&reference]
    );
    saved.permits()?;
    Ok(())
}

#[test]
fn retained_payload_bound() -> TestResult {
    let saved = Saved::new()?;
    let selection = &saved.fixture.instance.grant.selection;
    let reference = &saved.receipt.results[&10];
    let limits = AnalysisExtractLimits {
        input_bytes: 16 * 1024,
        ..Default::default()
    };
    let before = saved.store.meta()?;
    let page = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        limits,
        &AnalysisReadControl::default(),
    )?;
    saved.original(&page, &before)?;
    let original: Vec<u8> = saved.store.read_snapshot(|reader| {
        reader
            .query_row(
                "SELECT ipc FROM managed_arrow WHERE result_id = ? AND role = 'output' AND slot = 0",
                params![reference.result_id],
                |row| row.get(0),
            )
            .context(crate::AnalysisDatabaseSnafu {
                operation: "read saved test payload",
            })
    })?;
    assert_eq!(
        saved.store.writer()?.get_mut()?.execute(
            "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'output' AND slot = 0",
            params![vec![b'x'; 32 * 1024 + 1], reference.result_id],
        )?,
        1
    );
    let (pin, port) = saved.store.managed_input(
        selection,
        &saved.fixture.instance.spec.id,
        reference,
        "rows",
        limits,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(pin.result(), reference);
    assert_eq!(port.schema, saved.fixture.model.outputs[0].schema);
    let inputs = [(Arc::new(pin), Arc::new(port.schema))];
    let metadata = saved.read(
        selection,
        selection,
        &inputs,
        AnalysisReadModeV1::Metadata,
        limits,
        &AnalysisReadControl::default(),
    )?;
    assert!(metadata.packages.is_empty());
    assert!(metadata.tables.values().all(Vec::is_empty));
    assert_eq!(metadata.extraction.meta, before);
    assert_eq!(
        metadata
            .extraction
            .references
            .iter()
            .filter_map(|entry| entry.result())
            .collect::<Vec<_>>(),
        [reference]
    );
    assert!(matches!(
        saved.read(
            selection,
            selection,
            &inputs,
            AnalysisReadModeV1::Complete,
            limits,
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::AnalysisInputTooLarge {
            resource: "selected input bytes",
            ..
        })
    ));
    assert!(matches!(
        saved.read(
            selection,
            selection,
            &inputs,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        ),
        Err(crate::Error::AnalysisContract { .. })
    ));
    assert_eq!(saved.store.meta()?, before);
    saved.permits()?;
    assert_eq!(
        saved.store.writer()?.get_mut()?.execute(
            "UPDATE managed_arrow SET ipc = ? WHERE result_id = ? AND role = 'output' AND slot = 0",
            params![original, reference.result_id],
        )?,
        1
    );
    let page = saved.read(
        selection,
        selection,
        &inputs,
        AnalysisReadModeV1::Complete,
        limits,
        &AnalysisReadControl::default(),
    )?;
    saved.original(&page, &before)?;
    assert_eq!(saved.store.meta()?, before);
    saved.permits()?;
    Ok(())
}

#[test]
fn retained_cancellation() -> TestResult {
    let saved = Saved::new()?;
    let selection = &saved.fixture.instance.grant.selection;
    let before = saved.store.meta()?;
    let parent = AnalysisReadControl::default();
    let child = Arc::new(parent.operation()?);
    let observed = Arc::new(AtomicBool::new(false));
    let entered = Arc::clone(&observed);
    let cancelled = Arc::clone(&child);
    child.on_read_step(move || {
        entered.store(true, Ordering::Release);
        cancelled.cancel()
    })?;
    assert!(matches!(
        saved.read(
            selection,
            selection,
            &saved.inputs,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &child,
        ),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    assert!(observed.load(Ordering::Acquire));
    assert!(matches!(
        child.check(),
        Err(crate::Error::AnalysisReadCancelled { .. })
    ));
    parent.check()?;
    assert_eq!(saved.store.meta()?, before);
    saved.permits()?;
    let retry = parent.operation()?;
    let page = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &retry,
    )?;
    saved.original(&page, &before)?;
    retry.check()?;
    parent.check()?;
    assert_eq!(saved.store.meta()?, before);
    saved.permits()?;
    Ok(())
}
