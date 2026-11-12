use super::*;
use crate::analysis::raw::tests::{trace_intent, trace_terminal};
use crate::analysis::raw::RawIdentity;
use crate::{EvidenceIntakeIdentityV1, ValidatedEvidenceBatchV1};
use std::path::PathBuf;

#[test]
fn empty_terminal_releases_reserve() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("data"))?;
    let mut intent = trace_intent()?;
    intent.bindings[0].identity.node_id = "n".repeat(128);
    let identity = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let receipt = store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: Vec::new(),
            terminal: Some(trace_terminal(0, 0)),
        },
        200,
    )?;
    assert_eq!((receipt.last_sequence, receipt.output_bytes), (0, 0));
    let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
    assert_eq!(raw.budget.trace_reserve, 0);
    Ok(())
}

#[test]
fn expired_trace_keeps_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let mut store = AnalysisStore::open_with_retention(
        &root,
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            ..Default::default()
        },
    )?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    let source = RawIdentity::Diagnostic(identity.clone());
    store.accept_trace(&intent)?;
    store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: TraceFrameKindV1::Data,
                bytes: vec![7],
            }],
            terminal: None,
        },
        100,
    )?;
    let path = {
        let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
        let entry = raw
            .index
            .entries
            .values()
            .find(|entry| entry.identity == source)
            .ok_or("trace entry")?;
        raw.segment_path(entry.reference.id)?.to_path_buf()
    };
    let removed = crate::EvidenceRetentionOwner::new(&store).retain_trace(identity, 102)?;
    assert_eq!((removed.removed_records, removed.retained_floor), (1, 1));
    let receipt = store.trace_receipt(identity)?.ok_or("trace receipt")?;
    assert_eq!(
        (
            receipt.last_sequence,
            receipt.output_bytes,
            receipt.retained_floor
        ),
        (1, 1, 1)
    );
    for reopen in [false, true] {
        if reopen {
            drop(store);
            store = AnalysisStore::open(&root)?;
        }
        {
            let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
            assert!(raw.index.sources[&source.key()].active.is_none());
            let entries = raw
                .index
                .entries
                .values()
                .filter(|entry| entry.identity == source)
                .collect::<Vec<_>>();
            assert!(!entries.is_empty());
            assert!(entries
                .iter()
                .all(|entry| raw.index.expired.contains_key(&entry.reference.id)));
            assert!(entries
                .iter()
                .all(|entry| !raw.segments.contains_key(&entry.reference.id)));
        }
        assert!(!path.exists());
        assert!(matches!(
            store.read_trace(identity, 1, &AnalysisReadControl::default()),
            Err(crate::Error::RetainedRangeExpired { .. })
        ));
        assert_eq!(store.trace_receipt(identity)?, Some(receipt.clone()));
    }
    Ok(())
}

#[test]
fn observability_terminal_pin() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::{
        AnalysisReadControl, AnalysisResultCommitV1, AnalysisWitnessV1, ProcessorClassV1,
        ProcessorScopeV1,
    };

    if let Some(root) = std::env::var_os("ARAPHOR_CRASH_ROOT") {
        let root = PathBuf::from(root);
        let intent = trace_intent()?;
        let identity = &intent.bindings[0].identity;
        let store = AnalysisStore::open(&root)?;
        store.append_trace(
            identity,
            &crate::TraceBatchV1 {
                execution_id: identity.execution_id,
                frames: vec![],
                terminal: Some(trace_terminal(1, 1)),
            },
            204,
        )?;
        return Err("the reserved terminal crash did not occur".into());
    }
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let frame = crate::TraceFrameV1 {
        execution_id: identity.execution_id,
        sequence: 1,
        kind: crate::TraceFrameKindV1::Data,
        bytes: vec![7],
    };
    let batch = crate::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![frame.clone()],
        terminal: None,
    };
    store.append_trace(identity, &batch, 200)?;
    let evidence = EvidenceIntakeIdentityV1 {
        tenant_id: identity.tenant_id,
        node_id: identity.node_id.clone(),
        node_boot_id: identity.node_boot_id,
        source_id: [5; 16],
        ..crate::analysis::tests::identity()
    };
    store.accept_validated_batch(
        evidence.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 200,
            framed_records: vec![1].into(),
            frame_ends: vec![1],
        },
    )?;
    let scope = ProcessorScopeV1 {
        processor_id: "trace-witness".into(),
        method_version: 1,
        identity: evidence,
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    store.commit_result(&AnalysisResultCommitV1 {
        body: vec![1],
        created_utc_ns: 201,
        witnesses: vec![AnalysisWitnessV1 {
            identity: identity.clone().into(),
            cursor: 1,
            expires_utc_ns: 1_000,
        }],
        ..crate::analysis::tests::result(scope, "trace-result".into())
    })?;
    let usage = store.witness_usage(identity.tenant_id, 202)?;
    drop(store);
    let status = std::process::Command::new(std::env::current_exe()?)
        .args([
            "--exact",
            "analysis::native::trace::tests::raw_cases::observability_terminal_pin",
        ])
        .env("ARAPHOR_CRASH_ROOT", &root)
        .env("ARAPHOR_CRASH_POINT", "segment.reserved")
        .status()?;
    assert_eq!(status.code(), Some(73));
    let store = AnalysisStore::open(&root)?;
    let terminal = trace_terminal(1, 1);
    let combined = crate::TraceBatchV1 {
        terminal: Some(terminal.clone()),
        ..batch
    };
    let receipt = store.append_trace(identity, &combined, 204)?;
    assert_eq!(receipt.terminal, Some(terminal.clone()));
    let page = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame.clone()]);
    assert_eq!(page.terminal, Some(terminal.clone()));
    {
        let raw = store.raw.lock().map_err(|_| "raw lock poisoned")?;
        assert_ne!(
            raw.index.entries[&page.positions[0].commit_revision]
                .reference
                .id,
            raw.index.entries[&page
                .terminal_position
                .ok_or("terminal position absent")?
                .commit_revision]
                .reference
                .id
        );
    }
    assert_eq!(
        store.witness_usage(identity.tenant_id, 205)?.charged_bytes,
        usage.charged_bytes
    );
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.append_trace(identity, &combined, 206)?, receipt);
    let page = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame]);
    assert_eq!(page.terminal, Some(terminal));
    assert_eq!(
        store.witness_usage(identity.tenant_id, 207)?.charged_bytes,
        usage.charged_bytes
    );
    Ok(())
}

#[test]
fn observability_read_retention() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::sync::{mpsc, TryLockError};
    use std::time::{Duration, Instant};

    use crate::{AnalysisCommitStage, AnalysisReadControl, EvidenceRetentionOwner};

    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open_with_retention(
        directory.path().join("data"),
        crate::RetentionLimitsV1 {
            raw_max_age_ns: Some(50),
            ..Default::default()
        },
    )?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let frame = crate::TraceFrameV1 {
        execution_id: identity.execution_id,
        sequence: 1,
        kind: crate::TraceFrameKindV1::Data,
        bytes: vec![7],
    };
    let mut batch = crate::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![frame.clone()],
        terminal: None,
    };
    store.append_trace(identity, &batch, 100)?;
    let (freeze, frozen) = mpsc::channel();
    let (release, released) = mpsc::channel();
    store.set_commit_hook(AnalysisCommitStage::AfterTraceFreeze, move || {
        freeze
            .send(())
            .map_err(|_| crate::AnalysisReadCancelledSnafu.build())?;
        released
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| crate::AnalysisReadDeadlineSnafu.build())
    })?;
    std::thread::scope(
        |scope| -> std::result::Result<(), Box<dyn std::error::Error>> {
            let resume = release;
            let reader =
                scope.spawn(|| store.read_trace(identity, 1, &AnalysisReadControl::default()));
            frozen.recv_timeout(Duration::from_secs(5))?;
            assert!(matches!(
                store.maintenance.try_write(),
                Err(TryLockError::WouldBlock)
            ));
            batch.frames[0].sequence = 2;
            store.append_trace(identity, &batch, 101)?;
            let retention =
                scope.spawn(|| EvidenceRetentionOwner::new(&store).retain_trace(identity, 200));
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                match store.writer.try_lock() {
                    Err(TryLockError::WouldBlock) => break,
                    Err(TryLockError::Poisoned(_)) => return Err("writer poisoned".into()),
                    Ok(guard) => drop(guard),
                }
                if Instant::now() >= deadline {
                    return Err("retention did not acquire the writer".into());
                }
                std::thread::yield_now();
            }
            resume.send(())?;
            let page = reader.join().map_err(|_| "reader failed")??;
            let removed = retention.join().map_err(|_| "retention failed")??;
            assert_eq!(page.frames, vec![frame]);
            assert_eq!(page.next_cursor, None);
            assert_eq!(removed.removed_records, 2);
            assert_eq!(removed.retained_floor, 2);
            Ok(())
        },
    )?;
    assert!(matches!(
        store.read_trace(identity, 1, &AnalysisReadControl::default()),
        Err(crate::Error::RetainedRangeExpired { .. })
    ));
    Ok(())
}

#[test]
fn observability_rotation_totals() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use crate::{AnalysisReadControl, EvidenceRetentionOwner, RetentionLimitsV1};

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(50),
        ..Default::default()
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let mut batch = crate::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![crate::TraceFrameV1 {
            execution_id: identity.execution_id,
            sequence: 1,
            kind: crate::TraceFrameKindV1::Data,
            bytes: vec![7; 1024 * 1024 + 1],
        }],
        terminal: None,
    };
    for sequence in 1..=16 {
        batch.frames[0].sequence = sequence;
        let receipt = store.append_trace(identity, &batch, 100 + sequence)?;
        assert_eq!(receipt.last_sequence, sequence);
        assert_eq!(receipt.output_bytes, sequence * (1024 * 1024 + 1) as u64);
    }
    let terminal = crate::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![],
        terminal: Some(trace_terminal(16, 16 * (1024 * 1024 + 1) as u64)),
    };
    let receipt = store.append_trace(identity, &terminal, 117)?;
    let first = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
    let last = store.read_trace(identity, 16, &AnalysisReadControl::default())?;
    {
        let raw = store.raw.lock().map_err(|_| "raw lock poisoned")?;
        assert_ne!(
            raw.index.entries[&first.positions[0].commit_revision]
                .reference
                .id,
            raw.index.entries[&last.positions[0].commit_revision]
                .reference
                .id
        );
    }
    assert_eq!(last.frames, batch.frames);
    assert_eq!(last.terminal, terminal.terminal);
    let removed = EvidenceRetentionOwner::new(&store).retain_trace(
        identity,
        116 + limits
            .raw_max_age_ns
            .ok_or("the configured age is absent")?,
    )?;
    assert_eq!((removed.removed_records, removed.retained_floor), (15, 15));
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let restored = store.trace_receipt(identity)?.ok_or("receipt absent")?;
    assert_eq!(restored.last_sequence, receipt.last_sequence);
    assert_eq!(restored.output_bytes, receipt.output_bytes);
    assert_eq!(restored.terminal, receipt.terminal);
    assert_eq!(restored.retained_floor, 15);
    assert!(matches!(
        store.read_trace(identity, 1, &AnalysisReadControl::default()),
        Err(crate::Error::RetainedRangeExpired { .. })
    ));
    let page = store.read_trace(identity, 16, &AnalysisReadControl::default())?;
    assert_eq!(page.frames, batch.frames);
    assert_eq!(page.terminal, terminal.terminal);
    let removed = EvidenceRetentionOwner::new(&store).retain_trace(identity, 201)?;
    assert_eq!((removed.removed_records, removed.retained_floor), (2, 17));
    let expired = store.trace_receipt(identity)?.ok_or("receipt absent")?;
    assert_eq!(store.append_trace(identity, &terminal, 202)?, expired);
    assert!(matches!(
        store.append_trace(identity, &batch, 202),
        Err(crate::Error::RetainedRangeExpired { .. })
    ));
    let mut changed = terminal.clone();
    changed.terminal.as_mut().ok_or("terminal absent")?.reason =
        crate::TraceTerminalReasonV1::Cancelled;
    assert!(matches!(
        store.append_trace(identity, &changed, 202),
        Err(crate::Error::AnalysisConflict { .. })
    ));
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    assert_eq!(store.append_trace(identity, &terminal, 203)?, expired);
    assert_eq!(store.trace_receipt(identity)?, Some(expired));
    Ok(())
}
