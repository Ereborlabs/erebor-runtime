#![cfg(feature = "test-fixtures")]

use super::*;
use araphor_data::analysis::native::NativeStore as AnalysisStore;
use araphor_data::TraceOutputReceiptV1;
use std::collections::BTreeMap;

type TraceResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn inventory(store: &NativeStore) -> TraceResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    store
        .view()?
        .snapshot()
        .prefix(b"")
        .map(|entry| {
            let (key, bytes) = entry?;
            Ok((key.to_vec(), bytes.to_vec()))
        })
        .collect()
}

fn stored_receipt(store: &NativeStore) -> TraceResult<(Vec<u8>, TraceOutputReceiptV1)> {
    let view = store.view()?;
    let rows = view
        .snapshot()
        .prefix(b"\0data/@trace/receipt/")
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(rows.len(), 1);
    let (key, bytes) = &rows[0];
    assert_eq!(bytes.first(), Some(&0));
    Ok((key.to_vec(), rmp_serde::from_slice(&bytes[1..])?))
}

fn trace_intent() -> araphor_data::Result<araphor_data::TraceIntentV1> {
    let source = araphor_data::TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    Ok(araphor_data::TraceIntentV1 {
        tenant_id: [1; 16],
        request_id: [3; 16],
        bindings: vec![araphor_data::TraceBindingV1 {
            binding_id: [9; 16],
            identity: araphor_data::TraceIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                request_id: [3; 16],
                execution_id: [4; 16],
                source_sha256: source.sha256,
            },
            namespace_uid: "namespace-a".into(),
        }],
        source,
        authority: b"accepted".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 10_000,
        host_sensitive: false,
    })
}

fn trace_terminal(sequence: u64, bytes: u64) -> araphor_data::TraceTerminalV1 {
    araphor_data::TraceTerminalV1 {
        execution_id: [4; 16],
        reason: araphor_data::TraceTerminalReasonV1::Completed,
        last_sequence: sequence,
        output_bytes: bytes,
        output_incomplete: false,
        kernel_lost_events: None,
        ready_at_unix_ns: None,
        exit_code: Some(0),
        forced_kill: false,
        cleanup: araphor_data::TraceCleanupV1::Unknown,
    }
}

#[test]
fn observability_raw_recovery() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    let state = store.accept_trace(&intent)?;
    assert!(store
        .read_trace(identity, 1, &araphor_data::AnalysisReadControl::default())?
        .frames
        .is_empty());
    let frame = araphor_data::TraceFrameV1 {
        execution_id: identity.execution_id,
        sequence: 1,
        kind: araphor_data::TraceFrameKindV1::Metadata,
        bytes: b"metadata".to_vec(),
    };
    let batch = araphor_data::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![frame.clone()],
        terminal: None,
    };
    let receipt = store.append_trace(identity, &batch, 200)?;
    assert_eq!((receipt.last_sequence, receipt.output_bytes), (1, 8));
    assert_eq!(store.append_trace(identity, &batch, 201)?, receipt);
    let page = store.read_trace(identity, 1, &araphor_data::AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame.clone()]);
    assert_eq!(page.positions.len(), 1);
    assert_eq!(page.next_cursor, None);
    {
        let view = store.view()?;
        let head = view.snapshot().get(b"\0data/head")?.ok_or("native head")?;
        assert_eq!(
            u64::from_be_bytes(head.as_ref().try_into()?),
            state.revision
        );
        assert_eq!(stored_receipt(&store)?.1.last_sequence, 0);
    }
    let mut conflict = batch.clone();
    conflict.frames[0].kind = araphor_data::TraceFrameKindV1::Data;
    assert!(matches!(
        store.append_trace(identity, &conflict, 202),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    let mut gap = batch.clone();
    gap.frames[0].sequence = 3;
    assert!(matches!(
        store.append_trace(identity, &gap, 202),
        Err(araphor_data::Error::TraceInvalid { .. })
    ));
    let invalid = araphor_data::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![],
        terminal: Some(trace_terminal(1, 9)),
    };
    assert!(matches!(
        store.append_trace(identity, &invalid, 202),
        Err(araphor_data::Error::TraceInvalid { .. })
    ));
    let terminal = trace_terminal(1, 8);
    let combined = araphor_data::TraceBatchV1 {
        terminal: Some(terminal.clone()),
        ..batch
    };
    let receipt = store.append_trace(identity, &combined, 203)?;
    assert_eq!(receipt.terminal, Some(terminal.clone()));
    assert_eq!(store.append_trace(identity, &combined, 204)?, receipt);
    assert!(matches!(
        store.append_trace(identity, &gap, 204),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    let mut changed = combined.clone();
    changed.terminal.as_mut().ok_or("terminal absent")?.reason =
        araphor_data::TraceTerminalReasonV1::Cancelled;
    assert!(matches!(
        store.append_trace(identity, &changed, 204),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    let page = store.read_trace(identity, 2, &araphor_data::AnalysisReadControl::default())?;
    assert!(page.frames.is_empty());
    assert_eq!(page.terminal, Some(terminal.clone()));
    assert!(page.terminal_position.is_some());
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.trace_receipt(identity)?, Some(receipt));
    let page = store.read_trace(identity, 1, &araphor_data::AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame]);
    assert_eq!(page.terminal, Some(terminal));
    Ok(())
}

#[test]
fn observability_empty_recovery() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let mut intent = trace_intent()?;
    intent.bindings[0].identity.node_id = "n".repeat(128);
    let identity = &intent.bindings[0].identity;
    let store = AnalysisStore::open(&root)?;
    let batch = araphor_data::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![],
        terminal: Some(trace_terminal(0, 0)),
    };
    assert!(store.append_trace(identity, &batch, 100).is_err());
    let state = store.accept_trace(&intent)?;
    assert_eq!(store.accept_trace(&intent)?, state);
    assert!(store.trace_receipt(identity)?.is_some());
    let receipt = store.append_trace(identity, &batch, 200)?;
    assert_eq!((receipt.last_sequence, receipt.output_bytes), (0, 0));
    assert!(receipt.terminal.is_some());
    let page = store.read_trace(identity, 1, &araphor_data::AnalysisReadControl::default())?;
    assert!(page.frames.is_empty());
    assert_eq!(page.terminal, batch.terminal);
    assert_eq!(page.next_cursor, None);
    assert_eq!(store.append_trace(identity, &batch, 201)?, receipt);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.append_trace(identity, &batch, 202)?, receipt);
    assert_eq!(store.trace_receipt(identity)?, Some(receipt));
    Ok(())
}

#[test]
fn observability_frame_bound() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("data"))?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let frame = araphor_data::TraceFrameV1 {
        execution_id: identity.execution_id,
        sequence: 1,
        kind: araphor_data::TraceFrameKindV1::Data,
        bytes: vec![7; 1024 * 1024],
    };
    let batch = araphor_data::TraceBatchV1 {
        execution_id: identity.execution_id,
        frames: vec![frame.clone()],
        terminal: Some(trace_terminal(1, (1024 * 1024) as u64)),
    };
    store.append_trace(identity, &batch, 200)?;
    let page = store.read_trace(identity, 1, &araphor_data::AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame]);
    assert_eq!(page.terminal, batch.terminal);
    for changed in [
        araphor_data::TraceIdentityV1 {
            node_id: "node-b".into(),
            ..identity.clone()
        },
        araphor_data::TraceIdentityV1 {
            node_boot_id: [9; 16],
            ..identity.clone()
        },
        araphor_data::TraceIdentityV1 {
            request_id: [9; 16],
            ..identity.clone()
        },
        araphor_data::TraceIdentityV1 {
            source_sha256: [9; 32],
            ..identity.clone()
        },
    ] {
        assert!(store.append_trace(&changed, &batch, 201).is_err());
        assert!(store
            .read_trace(&changed, 1, &araphor_data::AnalysisReadControl::default())
            .is_err());
    }
    Ok(())
}

#[test]
fn observability_receipt_cursor() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use araphor_data::{EvidenceRetentionOwner, RetentionLimitsV1};

    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open_with_retention(
        &root,
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            ..Default::default()
        },
    )?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    store.append_trace(
        identity,
        &araphor_data::TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![araphor_data::TraceFrameV1 {
                execution_id: identity.execution_id,
                sequence: 1,
                kind: araphor_data::TraceFrameKindV1::Data,
                bytes: vec![7],
            }],
            terminal: None,
        },
        100,
    )?;
    let removed = EvidenceRetentionOwner::new(&store).retain_trace(identity, 102)?;
    assert_eq!((removed.removed_records, removed.retained_floor), (1, 1));
    assert!(matches!(
        store.read_trace(identity, 1, &AnalysisReadControl::default()),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    let (key, mut receipt) = stored_receipt(&store)?;
    assert_eq!(
        (
            receipt.last_sequence,
            receipt.output_bytes,
            receipt.retained_floor
        ),
        (1, 1, 1)
    );
    assert!(receipt.terminal.is_none());
    receipt.last_sequence = u64::MAX;
    receipt.output_bytes = u64::MAX;
    let mut write = store.write()?;
    write
        .native()
        .insert(key, [vec![0], rmp_serde::to_vec_named(&receipt)?].concat());
    write.commit([])?;
    assert!(matches!(
        store.trace_receipt(identity),
        Err(araphor_data::Error::NativeState {
            field: "trace receipt bounds",
            ..
        })
    ));
    drop(store);
    assert!(matches!(
        AnalysisStore::open(&root),
        Err(araphor_data::Error::NativeState {
            field: "trace receipt bounds",
            ..
        })
    ));
    Ok(())
}

#[test]
fn raw_acceptance_defers_catalogue() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let identity = super::identity();
    let before = store.view()?;
    let journal = store.database().inner().journal_head()?;
    let records = inventory(&store)?;
    for cursor in 1..=4 {
        let outcome = store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: cursor,
                framed_records: vec![cursor as u8].into(),
                frame_ends: vec![1],
            },
        )?;
        assert_eq!(outcome, EvidenceStoreOutcomeV1::Accepted);
        assert_eq!(
            store
                .source_receipt(&identity)?
                .ok_or("receipt absent")?
                .contiguous_cursor,
            cursor
        );
        assert_eq!(
            store.source_binding(
                identity.tenant_id,
                &identity.node_id,
                identity.source_id,
                identity.source_epoch
            )?,
            Some(identity.clone())
        );
        assert_eq!(
            store.read_page(&identity, 1)?.records.len(),
            cursor as usize
        );
        let current = store.view()?;
        assert_eq!(current.snapshot().revision(), before.snapshot().revision());
        assert_eq!(store.database().inner().journal_head()?, journal);
        assert_eq!(inventory(&store)?, records);
        let head = current
            .snapshot()
            .get(b"\0data/head")?
            .ok_or("native head")?;
        assert_eq!(u64::from_be_bytes(head.as_ref().try_into()?), 0);
    }
    drop(before);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.meta()?.commit_revision, 4);
    let page = store.read_page(&identity, 1)?;
    assert_eq!(page.records.len(), 4);
    for (index, record) in page.records.iter().enumerate() {
        assert_eq!(record.cursor, index as u64 + 1);
        assert_eq!(record.framed_record, [index as u8 + 1]);
    }
    Ok(())
}
