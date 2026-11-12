#![cfg(feature = "test-fixtures")]

use super::*;
use araphor_data::analysis::native::NativeStore as AnalysisStore;
use araphor_data::{
    AnalysisCommitStage, AnalysisResultCommitV1, AnalysisWitnessV1, EvidenceRetentionOwner,
    PackageErrorCodeV1 as Code, ProcessorClassV1, ProcessorScopeV1, RetentionLimitsV1,
};
use serde_value::Value;
use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
};

type SegmentResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn source() -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        node_id: "segment-node".into(),
        ..super::identity()
    }
}

fn segment(root: &Path, id: u64) -> SegmentResult<PathBuf> {
    let prefix = format!("{id:016x}.");
    for entry in fs::read_dir(root.join("segments"))? {
        let entry = entry?;
        if entry.file_name().to_string_lossy().starts_with(&prefix) {
            return Ok(entry.path());
        }
    }
    Err("segment file".into())
}

fn native_rows(root: &Path) -> SegmentResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    let db = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
        .versioned()
        .open()?;
    let branch = db.branch("data")?.ok_or("Data branch")?;
    branch
        .snapshot()?
        .prefix(b"")
        .map(|entry| {
            let (key, bytes) = entry?;
            Ok((key.to_vec(), bytes.to_vec()))
        })
        .collect()
}

fn slot<'a>(value: &'a mut Value, path: &[usize]) -> SegmentResult<&'a mut Value> {
    if path.is_empty() {
        return Ok(value);
    }
    let Value::Seq(values) = value else {
        return Err("authority tuple".into());
    };
    let value = values.get_mut(path[0]).ok_or("authority tuple slot")?;
    slot(value, &path[1..])
}

#[test]
fn segment_batch_requires_full_expiry() -> SegmentResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open_with_retention(
        &root,
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            ..Default::default()
        },
    )?;
    for epoch in 1..=2 {
        store.accept_validated_batch(
            EvidenceIntakeIdentityV1 {
                source_epoch: epoch,
                ..source()
            },
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: epoch,
                intake_utc_ns: 100,
                framed_records: vec![7; epoch as usize].into(),
                frame_ends: (1..=epoch as usize).collect(),
            },
        )?;
    }
    store.set_commit_hook(AnalysisCommitStage::AfterMetadataSync, || {
        Err(Code::Denied.error("staged deletion"))
    })?;
    let error = EvidenceRetentionOwner::new(&store)
        .step(201)
        .err()
        .ok_or("deletion hook did not run")?;
    assert!(
        matches!(
            error,
            araphor_data::Error::Package {
                code: Code::Denied,
                field: "staged deletion",
                ..
            }
        ),
        "{error:?}"
    );
    let files = [segment(&root, 1)?, segment(&root, 2)?];
    let original = [fs::read(&files[0])?, fs::read(&files[1])?];
    drop(store);
    let db = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
        .versioned()
        .open()?;
    let branch = db.branch("data")?.ok_or("Data branch")?;
    let snapshot = branch.snapshot()?;
    let markers = snapshot
        .prefix(b"\0data/@retention/deleting/")
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(markers.len(), 2);
    let expired = snapshot
        .prefix(b"\0data/@retention/expired/")
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(expired.len(), 2);
    let (key, bytes) = &expired[1];
    assert_eq!(u64::from_be_bytes(key[key.len() - 8..].try_into()?), 2);
    assert_eq!(bytes.first(), Some(&0));
    let mut record: Value = rmp_serde::from_slice(&bytes[1..])?;
    let last = slot(&mut record, &[4, 0, 1, 3, 0, 1])?;
    assert!(matches!(
        last,
        Value::U8(2) | Value::U16(2) | Value::U32(2) | Value::U64(2)
    ));
    *last = Value::U8(1);
    let mut changed = vec![0];
    changed.extend(rmp_serde::to_vec(&record)?);
    assert_eq!(rmp_serde::from_slice::<Value>(&changed[1..])?, record);
    let mut tx = branch.write_tx()?;
    let head = tx.get(b"\0data/head")?.ok_or("Data head")?;
    tx.insert(key.as_ref(), changed);
    tx.commit_stamped([[b"\0data/cut/".as_slice(), head.as_ref()].concat()])?;
    drop((snapshot, branch, db));
    let before = native_rows(&root)?;
    assert_eq!(
        before
            .keys()
            .filter(|key| key.starts_with(b"\0data/@retention/deleting/"))
            .count(),
        2
    );
    let error = AnalysisStore::open(&root)
        .err()
        .ok_or("partial expiry accepted")?;
    assert!(
        matches!(error, araphor_data::Error::AnalysisState { ref reason, .. } if reason == "the deleting segment commits differ from their authority"),
        "{error:?}"
    );
    assert_eq!(native_rows(&root)?, before);
    for (file, bytes) in files.iter().zip(original) {
        assert!(
            file.exists(),
            "segment removed before whole-batch validation: {}",
            file.display()
        );
        assert_eq!(fs::read(file)?, bytes);
    }
    Ok(())
}

#[test]
fn segment_batch_checks_files() -> SegmentResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open_with_retention(
        &root,
        RetentionLimitsV1 {
            raw_max_age_ns: Some(1),
            ..Default::default()
        },
    )?;
    for epoch in 1..=2 {
        store.accept_validated_batch(
            EvidenceIntakeIdentityV1 {
                source_epoch: epoch,
                ..source()
            },
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: epoch,
                intake_utc_ns: 100,
                framed_records: vec![7; epoch as usize].into(),
                frame_ends: (1..=epoch as usize).collect(),
            },
        )?;
    }
    let (sender, receiver) = std::sync::mpsc::channel();
    let owned = root.clone();
    store.set_commit_hook(AnalysisCommitStage::AfterMetadataSync, move || {
        let files = [
            segment(&owned, 1).expect("first sealed segment"),
            segment(&owned, 2).expect("second sealed segment"),
        ];
        let mut expected = [
            fs::read(&files[0]).expect("first segment bytes"),
            fs::read(&files[1]).expect("second segment bytes"),
        ];
        *expected[1].last_mut().expect("second segment body") ^= 1;
        fs::write(&files[1], &expected[1]).expect("second segment fault");
        sender
            .send((files, expected))
            .map_err(|_| Code::Invalid.error("segment fault channel"))
    })?;
    assert!(EvidenceRetentionOwner::new(&store).step(201).is_err());
    let (files, expected) = receiver.try_recv()?;
    for (file, bytes) in files.iter().zip(expected) {
        assert_eq!(fs::read(file)?, bytes);
    }
    assert_eq!(
        store
            .view()?
            .snapshot()
            .prefix(b"\0data/@retention/deleting/")
            .collect::<Result<Vec<_>, _>>()?
            .len(),
        2
    );
    Ok(())
}

#[test]
fn checkpoint_preserves_raw_positions() -> SegmentResult {
    struct Budget;
    impl araphor_data::ManagedBudget for Budget {
        fn limit(&self) -> usize {
            usize::MAX
        }
        fn check(&self) -> araphor_data::Result<()> {
            Ok(())
        }
        fn reserve(&self, _: usize) -> araphor_data::Result<Box<dyn std::any::Any + Send + Sync>> {
            Ok(Box::new(()))
        }
    }
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("analysis"))?;
    let intent = super::trace::trace_intent()?;
    let trace = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let base = store.view()?;
    store.accept_validated_batch(
        source(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    let receipt = store.append_trace(
        trace,
        &araphor_data::TraceBatchV1 {
            execution_id: trace.execution_id,
            frames: vec![araphor_data::TraceFrameV1 {
                execution_id: trace.execution_id,
                sequence: 1,
                kind: araphor_data::TraceFrameKindV1::Data,
                bytes: vec![7],
            }],
            terminal: None,
        },
        100,
    )?;
    let raw = store.read_page(&source(), 1)?.records;
    let frames = store.read_trace(trace, 1, &AnalysisReadControl::default())?;
    let mut selected = AnalysisSelectionV1::new([1; 16], vec![source()]);
    selected.traces = araphor_data::Selection::Exact(vec![trace.clone()]);
    let requests = araphor_data::AnalysisTableRequests::from([
        ("events".into(), None),
        ("trace_output".into(), None),
    ]);
    let control = AnalysisReadControl::default();
    let inputs = store.subscribe_inputs_at(&base, &selected, &requests, None, &control, &Budget)?;
    let position = inputs.position();
    assert_eq!(position, frames.positions[0]);
    assert_eq!(position.commit_revision, receipt.commit_revision);
    assert_eq!(position.ordinal, 0);
    let before = store.meta()?;
    store.checkpoint()?;
    assert_eq!(store.meta()?.commit_revision, before.commit_revision + 1);
    assert_eq!(store.read_page(&source(), 1)?.records, raw);
    let after = store.read_trace(trace, 1, &control)?;
    assert_eq!(after.frames, frames.frames);
    assert_eq!(after.positions, frames.positions);
    assert_eq!(store.trace_receipt(trace)?, Some(receipt));
    let current = store.view()?;
    let _barrier =
        store.subscribe_inputs_at(&current, &selected, &requests, None, &control, &Budget)?;
    assert_eq!(inputs.position(), position);
    let checkpoint = store.meta()?;
    let journal = store.database().inner().journal_head()?;
    store.checkpoint()?;
    assert_eq!(store.meta()?, checkpoint);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(inputs.position(), position);
    Ok(())
}

#[test]
fn segment_recovery_checks_ownership() -> std::result::Result<(), Box<dyn std::error::Error>> {
    use std::io::Write as _;
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let identity = source();
    assert_eq!(store.meta()?.commit_revision, 0);
    store.accept_validated_batch(
        identity.clone(),
        ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: b"frame".to_vec().into(),
            frame_ends: vec![5],
        },
    )?;
    let live = segment(&root, 1)?;
    let length = fs::metadata(&live)?.len();
    let mut tail = fs::OpenOptions::new().append(true).open(&live)?;
    tail.write_all(&[0, 0])?;
    tail.sync_all()?;
    drop(tail);
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(fs::metadata(&live)?.len(), length);
    assert_eq!(
        store.read_page(&identity, 1)?.records[0].framed_record,
        b"frame"
    );
    drop(store);
    let unknown = root.join("segments/ffffffffffffffff.seg");
    fs::write(&unknown, b"unknown")?;
    assert!(AnalysisStore::open(&root).is_err());
    assert_eq!(fs::read(&unknown)?, b"unknown");
    assert_eq!(fs::metadata(&live)?.len(), length);
    Ok(())
}

#[test]
fn segment_recovery_rejects_corruption() -> std::result::Result<(), Box<dyn std::error::Error>> {
    for fault in ["missing", "short", "header", "changed"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("analysis");
        let store = AnalysisStore::open(&root)?;
        store.accept_validated_batch(
            source(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: 1,
                last_cursor: 1,
                intake_utc_ns: 100,
                framed_records: b"frame".to_vec().into(),
                frame_ends: vec![5],
            },
        )?;
        store.checkpoint()?;
        drop(store);
        let file = segment(&root, 1)?;
        let mut bytes = fs::read(&file)?;
        match fault {
            "missing" => fs::rename(&file, directory.path().join("saved"))?,
            "short" => {
                bytes.pop();
                fs::write(&file, &bytes)?;
            }
            "header" => {
                bytes[0] ^= 1;
                fs::write(&file, &bytes)?;
            }
            "changed" => {
                *bytes.last_mut().ok_or("segment is empty")? ^= 1;
                fs::write(&file, &bytes)?;
            }
            _ => return Err("unknown fault".into()),
        }
        for _ in 0..2 {
            assert!(AnalysisStore::open(&root).is_err(), "{fault}");
            if fault == "missing" {
                assert!(!file.exists());
                assert_eq!(fs::read(directory.path().join("saved"))?, bytes);
            } else {
                assert_eq!(fs::read(&file)?, bytes, "{fault}");
            }
        }
    }
    Ok(())
}

#[test]
fn segment_retention_keeps_witnesses() -> std::result::Result<(), Box<dyn std::error::Error>> {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let limits = RetentionLimitsV1 {
        raw_max_age_ns: Some(100),
        raw_max_bytes: Some(64 * 1024 * 1024),
    };
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let identity = source();
    for group in 0..4_u64 {
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: group * 1024 + 1,
                last_cursor: (group + 1) * 1024,
                intake_utc_ns: 100,
                framed_records: vec![group as u8; 4 * 1024 * 1024].into(),
                frame_ends: (1..=1024).map(|index| index * 4096).collect(),
            },
        )?;
    }
    let scope = ProcessorScopeV1 {
        processor_id: "witness".into(),
        method_version: 1,
        identity: identity.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
    store.commit_result(&AnalysisResultCommitV1 {
        consumed_cursor: 4096,
        created_utc_ns: 101,
        witnesses: vec![AnalysisWitnessV1 {
            identity: identity.clone().into(),
            cursor: 1,
            expires_utc_ns: 300,
        }],
        scope,
        expected_cursor: 0,
        coverage_revision: 0,
        context_revision: 0,
        result_id: "pin-first-segment".into(),
        body: b"finding".to_vec(),
        context_refs: Vec::new(),
    })?;
    let retention = EvidenceRetentionOwner::new(&store);
    let removed = retention.retain(&identity, 201)?;
    assert_eq!(removed.removed_records, 1024);
    assert_eq!(removed.retained_floor, 0);
    assert_eq!(
        store.read_page(&identity, 1)?.records[0].framed_record,
        vec![0; 4096]
    );
    assert!(matches!(
        store.read_page(&identity, 3073),
        Err(araphor_data::Error::RetainedRangeExpired { .. })
    ));
    assert_eq!(fs::read_dir(root.join("segments"))?.count(), 1);
    drop(store);
    let store = AnalysisStore::open_with_retention(&root, limits)?;
    let removed = EvidenceRetentionOwner::new(&store).retain(&identity, 301)?;
    assert_eq!(removed.removed_records, 3072);
    assert_eq!(removed.retained_floor, 4096);
    assert_eq!(removed.retained_bytes, 0);
    assert_eq!(fs::read_dir(root.join("segments"))?.count(), 0);
    drop(store);
    AnalysisStore::open_with_retention(&root, limits)?;
    Ok(())
}
