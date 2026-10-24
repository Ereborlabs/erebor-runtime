use super::*;
use crate::PackageErrorCodeV1 as Code;

#[test]
fn current_reads_check_storage() -> TestResult {
    let saved = Saved::new()?;
    let selection = &saved.fixture.instance.grant.selection;
    let control = AnalysisReadControl::default();
    let baseline = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    let references = |page: &crate::AnalysisPositionPageV1| {
        page.extraction
            .references
            .iter()
            .map(|entry| {
                (
                    entry.context().cloned(),
                    entry.result().cloned(),
                    entry.origins().to_vec(),
                )
            })
            .collect::<Vec<_>>()
    };
    let reference = &saved.receipt.results[&10];
    let (spec, state, head) = {
        let writer = saved.store.writer()?;
        let reader = writer.get()?;
        let spec: Vec<u8> = reader.query_row(
            "SELECT spec FROM managed_versions WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
            params![selection.tenant_id.as_slice(), saved.fixture.instance.spec.id, saved.fixture.instance.generation],
            |row| row.get(0),
        )?;
        let (state, head): (u64, Option<String>) = reader.query_row(
            "SELECT state_revision, result_id FROM managed_calls WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
            params![selection.tenant_id.as_slice(), saved.fixture.instance.spec.id],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )?;
        (spec, state, head)
    };
    assert_eq!(state, reference.commit_revision);
    assert_eq!(head.as_deref(), Some(reference.result_id.as_str()));
    let mut wrong: ManagedSpec = serde_json::from_slice(&spec)?;
    wrong
        .manifest
        .calls
        .get_mut(&10)
        .ok_or("saved call absent")?
        .package
        .revision = "wrong".into();
    let changed = serde_json::to_vec(&wrong)?;
    for fault in ["revision", "state", "head", "result", "owner"] {
        {
            let mut writer = saved.store.writer()?;
            let writer = writer.get_mut()?;
            let key = params![
                selection.tenant_id.as_slice(),
                saved.fixture.instance.spec.id
            ];
            match fault {
                "revision" => {
                    writer.execute(
                        "UPDATE managed_versions SET spec = ? WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
                        params![changed, selection.tenant_id.as_slice(), saved.fixture.instance.spec.id, saved.fixture.instance.generation],
                    )?;
                }
                "state" => {
                    writer.execute(
                        "UPDATE managed_calls SET state_revision = state_revision + 1 WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
                "head" => {
                    writer.execute(
                        "DELETE FROM managed_calls WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
                "result" => {
                    writer.execute(
                        "UPDATE managed_calls SET result_id = 'absent' WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
                _ => {
                    writer.execute(
                        "UPDATE managed_calls SET instance_id = 'absent-instance' WHERE tenant_id = ? AND instance_id = ? AND call_id = 10",
                        key,
                    )?;
                }
            }
        }
        for mode in [AnalysisReadModeV1::Metadata, AnalysisReadModeV1::Complete] {
            let result = saved.read(
                selection,
                selection,
                &saved.inputs,
                mode,
                AnalysisExtractLimits::default(),
                &control,
            );
            if fault == "revision" {
                assert!(
                    matches!(result, Err(crate::Error::AnalysisConflict { .. })),
                    "{fault}: {mode:?}"
                );
            } else {
                assert!(
                    matches!(
                        result,
                        Err(crate::Error::Package {
                            code: Code::Incomplete,
                            field: "managed input freshness",
                            ..
                        })
                    ),
                    "{fault}: {mode:?}"
                );
            }
        }
        {
            let mut writer = saved.store.writer()?;
            let writer = writer.get_mut()?;
            writer.execute(
                "UPDATE managed_versions SET spec = ? WHERE tenant_id = ? AND instance_id = ? AND generation = ?",
                params![spec, selection.tenant_id.as_slice(), saved.fixture.instance.spec.id, saved.fixture.instance.generation],
            )?;
            writer.execute(
                "DELETE FROM managed_calls WHERE tenant_id = ? AND call_id = 10 AND instance_id IN (?, 'absent-instance')",
                params![selection.tenant_id.as_slice(), saved.fixture.instance.spec.id],
            )?;
            writer.execute(
                "INSERT INTO managed_calls VALUES (?, ?, 10, ?, ?)",
                params![
                    selection.tenant_id.as_slice(),
                    saved.fixture.instance.spec.id,
                    state,
                    head
                ],
            )?;
        }
        for mode in [AnalysisReadModeV1::Metadata, AnalysisReadModeV1::Complete] {
            let restored = saved.read(
                selection,
                selection,
                &saved.inputs,
                mode,
                AnalysisExtractLimits::default(),
                &control,
            )?;
            assert_eq!(references(&restored), references(&baseline));
            if matches!(mode, AnalysisReadModeV1::Complete) {
                assert_eq!(restored.packages, baseline.packages);
            } else {
                assert!(restored.packages.is_empty());
            }
        }
    }
    let mut forged = reference.clone();
    forged.commit_revision += 1;
    assert!(matches!(
        saved.store.managed_input(
            selection,
            &saved.fixture.instance.spec.id,
            &forged,
            "rows",
            AnalysisExtractLimits::default(),
            &control,
        ),
        Err(crate::Error::Package {
            code: Code::Missing,
            field: "managed input result",
            ..
        })
    ));
    let current = saved.fixture.current(&saved.store)?;
    let running = saved.store.set_managed_running(
        selection.tenant_id,
        &current.spec.id,
        current.lifecycle,
        true,
        || Ok(()),
    )?;
    let stopped = saved.store.set_managed_running(
        selection.tenant_id,
        &current.spec.id,
        running.lifecycle,
        false,
        || Ok(()),
    )?;
    assert!(!stopped.running);
    assert_eq!(stopped.progress, saved.receipt.commit_revision);
    let paused = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(references(&paused), references(&baseline));
    assert_eq!(paused.packages, baseline.packages);
    let restarted = saved.store.set_managed_running(
        selection.tenant_id,
        &current.spec.id,
        stopped.lifecycle,
        true,
        || Ok(()),
    )?;
    assert!(restarted.running);
    assert_eq!(restarted.progress, saved.receipt.commit_revision);
    let restored = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(references(&restored), references(&baseline));
    assert_eq!(restored.packages, baseline.packages);
    saved.permits()?;
    Ok(())
}

#[test]
fn retained_record_checks_identity() -> TestResult {
    let saved = Saved::new()?;
    let selection = &saved.fixture.instance.grant.selection;
    let control = AnalysisReadControl::default();
    let reference = &saved.receipt.results[&10];
    let metadata: Vec<u8> = saved.store.writer()?.get()?.query_row(
        "SELECT request_meta FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
        params![selection.tenant_id.as_slice(), reference.result_id],
        |row| row.get(0),
    )?;
    let mut record: model::Record = serde_json::from_slice(&metadata)?;
    record.instance = "absent-instance".into();
    saved.store.writer()?.get_mut()?.execute(
        "UPDATE analysis_results SET request_meta = ? WHERE tenant_id = ? AND result_id = ?",
        params![
            serde_json::to_vec(&record)?,
            selection.tenant_id.as_slice(),
            reference.result_id
        ],
    )?;
    assert!(matches!(
        saved.store.managed_input(
            selection,
            &saved.fixture.instance.spec.id,
            reference,
            "rows",
            AnalysisExtractLimits::default(),
            &control,
        ),
        Err(crate::Error::Package {
            code: Code::Missing,
            field: "managed result attempt",
            ..
        })
    ));
    assert!(matches!(
        saved.read(
            selection,
            selection,
            &saved.inputs,
            AnalysisReadModeV1::Complete,
            AnalysisExtractLimits::default(),
            &control,
        ),
        Err(crate::Error::Package {
            code: Code::Invalid,
            field: "captured managed input identity",
            ..
        })
    ));
    saved.store.writer()?.get_mut()?.execute(
        "UPDATE analysis_results SET request_meta = ? WHERE tenant_id = ? AND result_id = ?",
        params![
            metadata,
            selection.tenant_id.as_slice(),
            reference.result_id
        ],
    )?;
    let (pin, schema) = saved.store.managed_input(
        selection,
        &saved.fixture.instance.spec.id,
        reference,
        "rows",
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(pin.result(), reference);
    assert_eq!(&schema.schema, saved.inputs[0].1.as_ref());
    let restored = saved.read(
        selection,
        selection,
        &saved.inputs,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
        &control,
    )?;
    assert_eq!(
        restored.packages[&0].1,
        saved.fixture.output(7)?.datasets[0].batches
    );
    saved.permits()?;
    Ok(())
}
