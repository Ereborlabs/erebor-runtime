use std::sync::Arc;
use std::time::Duration;

use araphor_data::{
    AnalysisReadControl, AnalysisSelectionV1, Selection, TraceBatchV1, TraceBindingV1,
    TraceCleanupV1, TraceFrameKindV1, TraceFrameV1, TraceIdentityV1, TraceIntentV1, TraceSourceV1,
    TraceTerminalReasonV1, TraceTerminalV1,
};
use datafusion::common::ScalarValue;

use super::{next, values, Cursor, Fixture, Limits, Operation, TestClock, Update};

#[tokio::test]
async fn interleaved_trace_pages() {
    let fixture = Fixture::new(Limits {
        output_rows: 2,
        ..Default::default()
    });
    let source = TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec()).unwrap();
    let a = TraceIdentityV1 {
        tenant_id: fixture.source.tenant_id,
        node_id: "trace-a".into(),
        node_boot_id: [2; 16],
        request_id: [5; 16],
        execution_id: [9; 16],
        source_sha256: source.sha256,
    };
    let b = TraceIdentityV1 {
        node_id: "trace-b".into(),
        execution_id: [4; 16],
        ..a.clone()
    };
    fixture
        .store
        .accept_trace(&TraceIntentV1 {
            tenant_id: a.tenant_id,
            request_id: a.request_id,
            source,
            bindings: vec![
                TraceBindingV1 {
                    identity: b.clone(),
                    binding_id: [6; 16],
                    namespace_uid: "namespace-b".into(),
                },
                TraceBindingV1 {
                    identity: a.clone(),
                    binding_id: [7; 16],
                    namespace_uid: "namespace-a".into(),
                },
            ],
            authority: b"accepted".to_vec(),
            accepted_unix_ns: 100,
            deadline_unix_ns: 10_000,
            host_sensitive: false,
        })
        .unwrap();
    let frame = |identity: &TraceIdentityV1, sequence, kind, bytes: &[u8]| TraceFrameV1 {
        execution_id: identity.execution_id,
        sequence,
        kind,
        bytes: bytes.to_vec(),
    };
    let terminal = |identity: &TraceIdentityV1, last_sequence, output_bytes| TraceTerminalV1 {
        execution_id: identity.execution_id,
        reason: TraceTerminalReasonV1::Completed,
        last_sequence,
        output_bytes,
        output_incomplete: false,
        kernel_lost_events: None,
        ready_at_unix_ns: None,
        exit_code: Some(0),
        forced_kill: false,
        cleanup: TraceCleanupV1::Unknown,
    };
    for (identity, frames, terminal, intake) in [
        (
            &a,
            vec![
                frame(&a, 1, TraceFrameKindV1::Metadata, b"a-meta"),
                frame(&a, 2, TraceFrameKindV1::Data, b"a-two"),
            ],
            None,
            200,
        ),
        (
            &b,
            vec![frame(&b, 1, TraceFrameKindV1::Diagnostic, b"b-note")],
            None,
            300,
        ),
        (
            &a,
            vec![frame(&a, 3, TraceFrameKindV1::Data, b"a-three")],
            Some(terminal(&a, 3, 18)),
            400,
        ),
        (
            &b,
            vec![frame(&b, 2, TraceFrameKindV1::Data, b"b-two")],
            Some(terminal(&b, 2, 11)),
            500,
        ),
    ] {
        fixture
            .store
            .append_trace(
                identity,
                &TraceBatchV1 {
                    execution_id: identity.execution_id,
                    frames,
                    terminal,
                },
                intake,
            )
            .unwrap();
    }
    let mut expected = Vec::new();
    for (identity, target_index) in [(&a, 1), (&b, 0)] {
        let stored = fixture
            .store
            .read_trace(
                identity,
                1,
                &AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap(),
            )
            .unwrap();
        assert_eq!(stored.frames.len(), stored.positions.len());
        for (frame, position) in stored.frames.into_iter().zip(stored.positions) {
            let kind = match frame.kind {
                TraceFrameKindV1::Metadata => "metadata",
                TraceFrameKindV1::Data => "data",
                TraceFrameKindV1::Diagnostic => "diagnostic",
            };
            expected.push((
                position,
                frame.execution_id,
                frame.sequence,
                target_index,
                kind,
                frame.bytes,
            ));
        }
        let terminal = stored.terminal.unwrap();
        expected.push((
            stored.terminal_position.unwrap(),
            terminal.execution_id,
            terminal.last_sequence + 1,
            target_index,
            "terminal",
            serde_json::to_vec(&terminal).unwrap(),
        ));
    }
    expected.sort_by_key(|row| row.0);
    assert_eq!(
        expected
            .iter()
            .map(|row| (row.1, row.2, row.3))
            .collect::<Vec<_>>(),
        vec![
            (a.execution_id, 1, 1),
            (a.execution_id, 2, 1),
            (b.execution_id, 1, 0),
            (a.execution_id, 3, 1),
            (a.execution_id, 4, 1),
            (b.execution_id, 2, 0),
            (b.execution_id, 3, 0),
        ]
    );
    assert!(expected.windows(2).all(|rows| rows[0].0 < rows[1].0));
    assert_eq!(expected[3].0.commit_revision, expected[4].0.commit_revision);
    assert_eq!((expected[3].0.ordinal, expected[4].0.ordinal), (0, 1));
    let check = |update: &Update, range: std::ops::Range<usize>| {
        let rows = &expected[range];
        assert_eq!(update.operation, Operation::Append);
        assert_eq!(
            update.positions,
            rows.iter().map(|row| row.0).collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 0),
            rows.iter()
                .map(|row| ScalarValue::Binary(Some(row.1.to_vec())))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 1),
            rows.iter()
                .map(|row| ScalarValue::UInt64(Some(row.2)))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 2),
            rows.iter()
                .map(|row| ScalarValue::UInt32(Some(row.3)))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 3),
            rows.iter()
                .map(|row| ScalarValue::Utf8(Some(row.4.into())))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            values(update, 4),
            rows.iter()
                .map(|row| ScalarValue::Binary(Some(row.5.clone())))
                .collect::<Vec<_>>()
        );
        assert!(update
            .batches
            .as_ref()
            .unwrap()
            .iter()
            .all(|batch| batch.num_columns() == 5));
    };
    let mut selection = AnalysisSelectionV1::new(a.tenant_id, vec![]);
    selection.traces = Selection::Exact(vec![a.clone(), b.clone()]);
    let clock = TestClock::new(1_000);
    let sql = "SELECT execution_id, sequence, target_index, kind, bytes FROM trace_output";
    let mut subscription = fixture
        .engine
        .subscribe(
            sql,
            vec![],
            selection.clone(),
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
            b"ordered trace principal",
            None,
            clock.clone(),
            true,
        )
        .await
        .unwrap();
    let first = next(&mut subscription).await;
    check(&first, 0..2);
    assert!(first.limited && !first.exhausted);
    assert_eq!(first.cursor.position(), expected[1].0);
    let second = next(&mut subscription).await;
    check(&second, 2..4);
    assert!(second.limited && !second.exhausted);
    assert_eq!(second.cursor.position(), expected[3].0);
    let resume = Cursor::decode(&second.cursor.encode().unwrap()).unwrap();
    subscription.cancel().unwrap();
    let mut resumed = fixture
        .engine
        .subscribe(
            sql,
            vec![],
            selection,
            Arc::new(AnalysisReadControl::with_timeout(Duration::from_secs(20)).unwrap()),
            b"ordered trace principal",
            Some(resume),
            clock,
            true,
        )
        .await
        .unwrap();
    let third = next(&mut resumed).await;
    check(&third, 4..6);
    assert!(third.limited && !third.exhausted);
    assert_eq!(third.cursor.position(), expected[5].0);
    let last = next(&mut resumed).await;
    check(&last, 6..7);
    assert!(!last.limited && last.exhausted);
    assert_eq!(last.cursor.position(), last.snapshot.page.scanned_through);
    assert!(last.cursor.position() > expected[6].0);
    resumed.cancel().unwrap();
}
