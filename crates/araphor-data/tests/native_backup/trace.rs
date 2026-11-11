use super::*;
use araphor_data::{
    TraceBatchV1, TraceBindingV1, TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1,
    TraceIntentV1, TraceSourceV1, TraceTerminalReasonV1, TraceTerminalV1,
};

fn intent() -> araphor_data::Result<TraceIntentV1> {
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    Ok(TraceIntentV1 {
        tenant_id: [1; 16],
        request_id: [3; 16],
        bindings: vec![TraceBindingV1 {
            binding_id: [9; 16],
            identity: TraceIdentityV1 {
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

fn terminal(sequence: u64, bytes: u64) -> TraceTerminalV1 {
    TraceTerminalV1 {
        execution_id: [4; 16],
        reason: TraceTerminalReasonV1::Completed,
        last_sequence: sequence,
        output_bytes: bytes,
        output_incomplete: false,
        kernel_lost_events: None,
        ready_at_unix_ns: None,
        exit_code: Some(0),
        forced_kill: false,
        cleanup: TraceCleanupV1::Unknown,
    }
}

#[test]
fn incomplete_trace_backup_restores() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = AnalysisStore::open(&root)?;
    store.accept_validated_batch(identity(), batch(1))?;
    let intent = intent()?;
    let trace = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let frame = TraceFrameV1 {
        execution_id: trace.execution_id,
        sequence: 1,
        kind: TraceFrameKindV1::Data,
        bytes: b"output".to_vec(),
    };
    let mut input = TraceBatchV1 {
        execution_id: trace.execution_id,
        frames: vec![frame.clone()],
        terminal: None,
    };
    let receipt = store.append_trace(trace, &input, 200)?;
    let before = store.read_trace(trace, 1, &AnalysisReadControl::default())?;
    let backup = root.join("backups/saved");
    let manifest = store.backup(&backup)?;
    assert_eq!(manifest.segments.len(), 2);
    let file = manifest
        .segments
        .iter()
        .find(|segment| segment.file_name.split('.').nth(1) == Some("d"))
        .ok_or("diagnostic segment")?;
    let path = backup.join("segments").join(&file.file_name);
    let moved = directory.path().join("saved-segment");
    fs::rename(&path, &moved)?;
    let target = directory.path().join("restored");
    assert!(AnalysisStore::restore(&backup, &target).is_err());
    assert!(!target.exists());
    fs::rename(&moved, &path)?;
    input.frames[0].sequence = 2;
    store.append_trace(trace, &input, 201)?;
    let restored = AnalysisStore::restore(&backup, &target)?;
    assert_eq!(restored.meta()?.store_uuid.to_string(), manifest.store_uuid);
    assert_eq!(restored.meta()?.recovery_epoch, manifest.recovery_epoch + 1);
    assert_eq!(restored.meta()?.commit_revision, manifest.commit_revision);
    assert_eq!(restored.trace_receipt(trace)?, Some(receipt));
    assert_eq!(
        restored
            .trace_intent(intent.tenant_id, intent.request_id)?
            .ok_or("intent")?
            .1,
        intent
    );
    assert_eq!(restored.read_page(&identity(), 1)?.records.len(), 1);
    let page = restored.read_trace(trace, 1, &AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame.clone()]);
    assert_eq!(page.positions, before.positions);
    assert_eq!(page.terminal, None);
    let terminal = TraceBatchV1 {
        execution_id: trace.execution_id,
        frames: vec![],
        terminal: Some(terminal(1, 6)),
    };
    let receipt = restored.append_trace(trace, &terminal, 202)?;
    assert_eq!(
        store.trace_receipt(trace)?.ok_or("receipt")?.last_sequence,
        2
    );
    assert!(store
        .trace_receipt(trace)?
        .ok_or("receipt")?
        .terminal
        .is_none());
    drop(restored);
    let restored = AnalysisStore::open(&target)?;
    assert_eq!(restored.append_trace(trace, &terminal, 203)?, receipt);
    let page = restored.read_trace(trace, 1, &AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame]);
    assert_eq!(page.terminal, terminal.terminal);
    Ok(())
}
