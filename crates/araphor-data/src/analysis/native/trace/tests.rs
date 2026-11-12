use super::NativeStore as AnalysisStore;
use crate::analysis::quota::TRACE_RESERVE;
use crate::{AnalysisReadControl, TraceBatchV1, TraceFrameKindV1, TraceFrameV1};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "tests/raw.rs"]
mod raw_cases;

#[test]
fn raw_projection_keeps_terminal_reserves() -> TestResult {
    use crate::analysis::raw::tests::{trace_intent, trace_terminal};
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = AnalysisStore::open(&root)?;
    let intent = trace_intent()?;
    let identity = &intent.bindings[0].identity;
    store.accept_trace(&intent)?;
    let frame = |sequence, byte| TraceFrameV1 {
        execution_id: identity.execution_id,
        sequence,
        kind: TraceFrameKindV1::Data,
        bytes: vec![byte],
    };
    store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![frame(1, 7)],
            terminal: None,
        },
        101,
    )?;
    {
        let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
        assert_eq!(
            (raw.budget.trace_reserve, raw.budget.trace_slots),
            (TRACE_RESERVE, 1)
        );
    }
    let terminal = trace_terminal(2, 2);
    let receipt = store.append_trace(
        identity,
        &TraceBatchV1 {
            execution_id: identity.execution_id,
            frames: vec![frame(2, 8)],
            terminal: Some(terminal.clone()),
        },
        102,
    )?;
    {
        let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
        assert_eq!((raw.budget.trace_reserve, raw.budget.trace_slots), (0, 0));
    }
    assert_eq!((receipt.last_sequence, receipt.output_bytes), (2, 2));
    let page = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame(1, 7), frame(2, 8)]);
    assert_eq!(page.terminal, Some(terminal.clone()));
    drop(store);
    let store = AnalysisStore::open(&root)?;
    assert_eq!(store.trace_receipt(identity)?, Some(receipt));
    let page = store.read_trace(identity, 1, &AnalysisReadControl::default())?;
    assert_eq!(page.frames, vec![frame(1, 7), frame(2, 8)]);
    assert_eq!(page.terminal, Some(terminal));
    let raw = store.raw.lock().map_err(|_| "raw poisoned")?;
    assert_eq!((raw.budget.trace_reserve, raw.budget.trace_slots), (0, 0));
    Ok(())
}
