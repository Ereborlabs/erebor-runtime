use super::*;
use araphor_data::{ManagedExit, ManagedFrontier, ManagedTerminal, PackageReadinessV1};
use std::collections::BTreeSet;

fn native_request(id: &str) -> ManagedRequest {
    let mut input = request(id);
    input.frontier = Some(ManagedFrontier {
        pending: false,
        cursor: id.as_bytes().to_vec(),
        next_change: Some(30),
    });
    input
}

fn capture_target(
    store: &NativeStore,
    current: &ManagedInstance,
    target: &ManagedInstance,
) -> Result<ManagedCapture, Box<dyn std::error::Error>> {
    let requests = BTreeMap::new();
    Ok(store
        .read_managed_tables_filtered(
            &current.grant.selection,
            &ManagedRead {
                instance: target.clone(),
                expected: Some(current.clone()),
                rebuild: false,
                follow: false,
                completed: None,
                execution: None,
                source: None,
            },
            araphor_data::AnalysisTableRead {
                requests: &requests,
                event_ranges: None,
                mode: araphor_data::AnalysisReadModeV1::Complete,
                now: 10,
            },
            Default::default(),
            &AnalysisReadControl::default(),
            None,
        )?
        .state)
}

fn attempt_record(
    view: &DataView,
    id: &str,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct Header {
        request: ManagedRequest,
    }
    for (key, bytes) in records(view, b"\0data/a")? {
        assert_eq!(bytes.first(), Some(&0));
        let header: Header = rmp_serde::from_slice(&bytes[1..])?;
        if header.request.id == id {
            return Ok((key, bytes));
        }
    }
    Err("attempt record".into())
}

fn terminal_bytes(
    pending: &[u8],
    terminal: &ManagedTerminal,
) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    assert_eq!(pending.first(), Some(&0));
    let mut suffix = rmp_serde::to_vec_named(&"terminal")?;
    suffix.push(0xc0);
    assert!(pending.ends_with(&suffix));
    let mut bytes = pending[..pending.len() - 1].to_vec();
    bytes.extend(rmp_serde::to_vec_named(terminal)?);
    Ok(bytes)
}

fn data_state(
    store: &NativeStore,
) -> Result<
    (
        araphor_data::AnalysisStoreMetaV1,
        BTreeMap<Vec<u8>, Vec<u8>>,
    ),
    Box<dyn std::error::Error>,
> {
    let view = store.view()?;
    Ok((view.meta(), records(&view, b"\0data/")?))
}

impl StorageFixture {
    fn assert_retained(
        &self,
        store: &NativeStore,
        receipt: &ManagedReceipt,
        evaluations: &[sdk::Evaluation],
        outputs: &[sdk::Output],
    ) -> TestResult {
        let current = self.current(store)?;
        for (index, call) in [10, 11].into_iter().enumerate() {
            let reference = &receipt.results[&call];
            let result = store.managed_result(
                &current,
                &reference.result_id,
                10,
                &AnalysisReadControl::default(),
            )?;
            assert_eq!(result.result, *reference);
            assert_eq!(result.receipt, *receipt);
            let context = super::calls::call_context(&result)?;
            assert_eq!(context.context, evaluations[index].context);
            assert!(context.matches(&evaluations[index].inputs));
            let checkpoint = self.checkpoint(store, reference)?;
            let expected = outputs[index]
                .checkpoint
                .as_ref()
                .ok_or("expected checkpoint")?;
            assert_eq!(checkpoint.version, expected.version);
            assert_eq!(checkpoint.datasets.len(), expected.datasets.len());
            for (actual, expected) in checkpoint.datasets.iter().zip(&expected.datasets) {
                assert_eq!(actual.name, expected.name);
                assert_eq!(actual.batches, expected.batches);
            }
        }
        assert_eq!(
            Self::receipt(
                store,
                [1; 16],
                "counter",
                &receipt.attempt,
                &AnalysisReadControl::default()
            )?,
            Some(receipt.clone())
        );
        assert_eq!(Self::rows(store, &receipt.selected)?, 1);
        Ok(())
    }
}

#[test]
fn terminal_keeps_successful_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let mut first = request("complete");
    first.frontier = Some(ManagedFrontier {
        pending: false,
        cursor: vec![1, 2, 3],
        next_change: Some(99),
    });
    let captured = fixture.capture(&store)?;
    let attempt = store.register_managed_attempt(&captured, &first, || Ok(()))?;
    let evaluations = [
        fixture.continued(&first, 10, Some(&captured))?,
        fixture.continued(&first, 11, Some(&captured))?,
    ];
    let outputs = [
        fixture.output(2, "exact context")?,
        fixture.output(3, "exact context")?,
    ];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
    let prior = fixture.capture(&store)?;
    let failed = request("failed");
    let attempt = store.register_managed_attempt(&prior, &failed, || Ok(()))?;
    let results = records(store.view()?.as_ref(), b"\0data/X")?;
    let checkpoints = records(store.view()?.as_ref(), b"\0data/U")?;
    assert_eq!(results.len(), 3);
    assert_eq!(checkpoints.len(), 2);
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &control),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let before = store.view()?.revision();
    let exit = ManagedExit::Failed(Code::Invalid);
    let terminal = store.finish_managed(&attempt, exit, || Ok(()))?;
    assert_eq!(terminal.revision, before + 1);
    assert_eq!(terminal.instance, "counter");
    assert_eq!(terminal.attempt, failed.id);
    assert_eq!(terminal.exit, exit);
    assert!(!terminal.suspended);
    let resume = store.managed_resume([1; 16], "counter", &control)?;
    assert_eq!(resume.instance.progress, receipt.commit_revision);
    assert_eq!(resume.frontier, receipt.frontier);
    let after = fixture.capture(&store)?;
    for call in [10, 11] {
        let original = prior.prior(call).ok_or("prior call")?;
        let retained = after.prior(call).ok_or("retained call")?;
        assert_eq!(retained.revision, original.revision);
        assert_eq!(retained.result, original.result);
        let original = original.checkpoint.as_ref().ok_or("prior checkpoint")?;
        let retained = retained.checkpoint.as_ref().ok_or("retained checkpoint")?;
        assert_eq!(retained.version, original.version);
        assert_eq!(retained.datasets.len(), original.datasets.len());
        for (retained, original) in retained.datasets.iter().zip(&original.datasets) {
            assert_eq!(retained.name, original.name);
            assert_eq!(retained.batches, original.batches);
        }
    }
    assert!(StorageFixture::receipt(&store, [1; 16], "counter", &failed.id, &control)?.is_none());
    let before = data_state(&store)?;
    let journal = store.database().inner().journal_head()?;
    let mut checked = false;
    assert_eq!(
        store.finish_managed(&attempt, exit, || {
            checked = true;
            Ok(())
        })?,
        terminal
    );
    assert!(checked);
    assert!(matches!(
        store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        store
            .register_managed_attempt(&prior, &failed, || Ok(()))?
            .terminal(),
        Some(&terminal)
    );
    assert!(fixture
        .publish(&store, &attempt, &evaluations, &outputs, || Ok(()))
        .is_err());
    assert_eq!(data_state(&store)?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    drop((captured, prior, after));
    drop(store);
    let store = NativeStore::open(&root)?;
    let saved = store
        .managed_attempt([1; 16], "counter", &failed.id, &control)?
        .ok_or("saved terminal")?;
    assert_eq!(saved.terminal(), Some(&terminal));
    assert!(saved.receipt().is_none());
    let before = data_state(&store)?;
    let journal = store.database().inner().journal_head()?;
    let mut checked = false;
    assert_eq!(
        store.finish_managed(&saved, exit, || {
            checked = true;
            Ok(())
        })?,
        terminal
    );
    assert!(checked);
    assert_eq!(store.finish_managed(&attempt, exit, || Ok(()))?, terminal);
    assert!(store
        .finish_managed(
            &saved,
            exit,
            || Err(Code::Denied.error("historical caller"))
        )
        .is_err());
    assert_eq!(data_state(&store)?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert_eq!(
        store.managed_resume([1; 16], "counter", &control)?.frontier,
        receipt.frontier
    );
    assert_eq!(records(store.view()?.as_ref(), b"\0data/X")?, results);
    assert_eq!(records(store.view()?.as_ref(), b"\0data/U")?, checkpoints);
    fixture.assert_retained(&store, &receipt, &evaluations, &outputs)?;
    Ok(())
}

#[test]
fn unknown_claim_cannot_finish() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let captured = fixture.capture(&store)?;
    let input = request("pending");
    let original = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let control = AnalysisReadControl::default();
    let loaded = store
        .managed_attempt([1; 16], "counter", &input.id, &control)?
        .ok_or("pending attempt")?;
    let before = data_state(&store)?;
    let journal = store.database().inner().journal_head()?;
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    let diagnostic = AnalysisReadControl::default();
    diagnostic.cancel()?;
    assert!(store
        .finish_managed(&original, ManagedExit::Cancelled, || diagnostic.check())
        .is_err());
    assert_eq!(data_state(&store)?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(store.managed_resume([1; 16], "counter", &control).is_err());
    let terminal = store.finish_managed(&original, ManagedExit::Cancelled, || Ok(()))?;
    assert!(!terminal.suspended);
    let resume = store.managed_resume([1; 16], "counter", &control)?;
    assert_eq!(resume.instance.progress, 0);
    assert!(resume.frontier.is_none());
    assert_eq!(resume.instance.lifecycle, fixture.instance.lifecycle);
    assert!(!resume.instance.running);
    let captured = fixture.capture(&store)?;
    let input = request("recovered-pending");
    let original = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let before = data_state(&store)?;
    let (_, contract) = attempt_record(store.view()?.as_ref(), &input.id)?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [
        fixture.output(2, "exact context")?,
        fixture.output(3, "exact context")?,
    ];
    drop(captured);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(data_state(&store)?, before);
    let journal = store.database().inner().journal_head()?;
    assert!(matches!(
        fixture.publish(&store, &original, &evaluations, &outputs, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    assert!(matches!(
        store.finish_managed(&original, ManagedExit::Cancelled, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    let loaded = store
        .managed_attempt([1; 16], "counter", &input.id, &control)?
        .ok_or("recovered pending")?;
    assert!(matches!(
        store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert!(loaded.terminal().is_none());
    assert!(store.managed_resume([1; 16], "counter", &control).is_err());
    assert_eq!(
        attempt_record(store.view()?.as_ref(), &input.id)?.1,
        contract
    );
    assert_eq!(data_state(&store)?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    Ok(())
}

#[tokio::test]
async fn denied_exit_fences_lifecycle() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let running =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let captured = fixture.capture(&store)?;
    let stale = store.register_managed_attempt(&captured, &request("stale"), || Ok(()))?;
    let stopped =
        store.set_managed_running([1; 16], "counter", running.lifecycle, false, || Ok(()))?;
    let restarted =
        store.set_managed_running([1; 16], "counter", stopped.lifecycle, true, || Ok(()))?;
    let mut notices = store.subscribe_activations()?;
    let terminal = store.finish_managed(&stale, ManagedExit::Failed(Code::Denied), || Ok(()))?;
    assert!(!terminal.suspended);
    assert!(!notices.has_changed()?);
    let control = AnalysisReadControl::default();
    assert_eq!(
        store.managed_resume([1; 16], "counter", &control)?.instance,
        restarted
    );
    let captured = fixture.capture(&store)?;
    let attempt = store.register_managed_attempt(&captured, &request("denied"), || Ok(()))?;
    let before = data_state(&store)?;
    let journal = store.database().inner().journal_head()?;
    assert!(store
        .finish_managed(&attempt, ManagedExit::Failed(Code::Denied), || Err(
            Code::Denied.error("diagnostic authority")
        ))
        .is_err());
    assert_eq!(data_state(&store)?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(!notices.has_changed()?);
    let terminal = store.finish_managed(&attempt, ManagedExit::Failed(Code::Denied), || Ok(()))?;
    assert!(terminal.suspended);
    assert!(notices.has_changed()?);
    tokio::time::timeout(std::time::Duration::from_secs(30), notices.changed()).await??;
    assert_eq!(notices.position(), terminal.revision);
    let current = store.managed_resume([1; 16], "counter", &control)?.instance;
    assert!(!current.running);
    assert_eq!(current.lifecycle, terminal.revision);
    assert_eq!(current.generation, fixture.instance.generation);
    assert_eq!(current.progress, 0);
    assert!(store.active_managed(&control)?.1.is_empty());
    Ok(())
}

#[test]
fn recovery_checks_terminal_contract() -> TestResult {
    for fault in 0..5 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = StorageFixture::new(&store, "counter", String::new())?;
        let capture = fixture.capture(&store)?;
        let attempt = store.register_managed_attempt(&capture, &request("corrupt"), || Ok(()))?;
        let terminal = store.finish_managed(&attempt, ManagedExit::Cancelled, || Ok(()))?;
        let (key, bytes) = attempt_record(store.view()?.as_ref(), "corrupt")?;
        let mut tx = store.write()?;
        if fault == 4 {
            let (key, bytes) = store
                .view()?
                .snapshot()
                .prefix(b"\0data/o")
                .next()
                .ok_or("outcome")??;
            let mut bytes = bytes.to_vec();
            bytes[..8].copy_from_slice(&(terminal.revision - 1).to_be_bytes());
            tx.native().insert(key, bytes);
        } else {
            use serde_value::Value;
            let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
            let field = super::super::attempts::field;
            match fault {
                0 => {
                    *field(&mut saved, &["terminal", "attempt"])? =
                        Value::String("different".into())
                }
                1 => {
                    let registered = field(&mut saved, &["registered"])?.clone();
                    *field(&mut saved, &["terminal", "revision"])? = registered;
                }
                2 => *field(&mut saved, &["terminal", "suspended"])? = Value::Bool(true),
                3 => {
                    *field(&mut saved, &["receipt"])? = serde_value::to_value(ManagedReceipt {
                        frontier: None,
                        instance: "counter".into(),
                        attempt: "corrupt".into(),
                        commit_revision: terminal.revision,
                        selected: PackageResultRefV1 {
                            result_id: "forged".into(),
                            commit_revision: terminal.revision,
                        },
                        results: BTreeMap::new(),
                        graph: None,
                    })?
                }
                _ => unreachable!(),
            }
            tx.native()
                .insert(key, [vec![0], rmp_serde::to_vec(&saved)?].concat());
        }
        tx.commit([])?;
        drop(capture);
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "terminal fault {fault}");
    }
    Ok(())
}

#[test]
fn live_recovery_keeps_claim() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let captured = fixture.capture(&store)?;
    let input = native_request("live-recovery");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let before = data_state(&store)?;
    let journal = store.database().inner().journal_head()?;
    let lifecycle = store.subscribe_activations()?;
    store.recover()?;
    assert_eq!(data_state(&store)?, before);
    assert_eq!(store.database().inner().journal_head()?, journal);
    assert!(!lifecycle.has_changed()?);
    let control = AnalysisReadControl::default();
    assert!(store
        .managed_attempt([1; 16], "counter", &input.id, &control)?
        .ok_or("live intent")?
        .terminal()
        .is_none());
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &control),
        Err(Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [
        fixture.output(2, "exact context")?,
        fixture.output(3, "exact context")?,
    ];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
    assert_eq!(receipt.commit_revision, before.0.commit_revision + 1);
    assert_eq!(receipt.results.len(), 2);
    assert_eq!(receipt.frontier, input.frontier);
    assert_eq!(
        store.managed_resume([1; 16], "counter", &control)?.frontier,
        receipt.frontier
    );
    fixture.assert_retained(&store, &receipt, &evaluations, &outputs)?;
    assert!(!lifecycle.has_changed()?);
    Ok(())
}

#[test]
fn startup_cancels_promoted_attempts() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let current =
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
    let mut spec = current.spec.clone();
    spec.definition.definition.description = "Retain simultaneous candidate intents.".into();
    spec.manifest.definition = store.admit_definition([1; 16], &spec.definition, || Ok(()))?;
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let captured = capture_target(&store, &current, &target)?;
    let inputs = [
        native_request("candidate-a"),
        native_request("candidate-b"),
        native_request("candidate-commit"),
    ];
    let attempts = inputs
        .iter()
        .map(|input| store.register_managed_attempt(&captured, input, || Ok(())))
        .collect::<araphor_data::Result<Vec<_>>>()?;
    let evaluations = [
        fixture.evaluation(&inputs[2], 10)?,
        fixture.evaluation(&inputs[2], 11)?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempts[2],
        &evaluations,
        &[
            fixture.output(12, "exact context")?,
            fixture.output(103, "exact context")?,
        ],
        || Ok(()),
    )?;
    let current = fixture.current(&store)?;
    assert_eq!(current.generation, target.generation);
    assert_ne!(current.generation, fixture.instance.generation);
    assert!(current.running);
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &control),
        Err(Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let view = store.view()?;
    let results = records(&view, b"\0data/X")?;
    let checkpoints = records(&view, b"\0data/U")?;
    assert_eq!(results.len(), 3);
    assert_eq!(checkpoints.len(), 2);
    let contracts = records(&view, b"\0data/a")?;
    let outcomes = records(&view, b"\0data/E")?;
    let before = view.meta();
    drop((view, captured));
    drop(store);
    let store = NativeStore::open(&root)?;
    let mut expected = before.clone();
    expected.commit_revision += 2;
    assert_eq!(store.view()?.meta(), expected);
    assert_eq!(
        records(&store.read_at(before.commit_revision)?, b"\0data/a")?,
        contracts
    );
    assert_eq!(
        records(&store.read_at(before.commit_revision)?, b"\0data/E")?,
        outcomes
    );
    assert_eq!(
        records(store.view()?.as_ref(), b"\0data/E")?.len(),
        outcomes.len() + 2
    );
    assert_eq!(fixture.current(&store)?, current);
    let settled = records(store.view()?.as_ref(), b"\0data/a")?;
    assert_eq!(settled.len(), contracts.len());
    let mut revisions = BTreeSet::new();
    for (input, original) in inputs.iter().zip(&attempts).take(2) {
        let loaded = store
            .managed_attempt([1; 16], "counter", &input.id, &control)?
            .ok_or("settled candidate")?;
        let terminal = loaded.terminal().ok_or("candidate cancellation")?;
        assert_eq!(terminal.exit, ManagedExit::Cancelled);
        assert!(!terminal.suspended);
        assert!(loaded.receipt().is_none());
        assert_eq!(loaded.request(), original.request());
        assert_eq!(loaded.captured_revision(), original.captured_revision());
        let (key, pending) = attempt_record(&store.read_at(before.commit_revision)?, &input.id)?;
        assert_eq!(
            settled.get(&key),
            Some(&terminal_bytes(&pending, terminal)?)
        );
        assert!(revisions.insert(terminal.revision));
        assert_eq!(
            store.finish_managed(original, ManagedExit::Cancelled, || Ok(()))?,
            *terminal
        );
    }
    assert_eq!(
        revisions,
        BTreeSet::from([before.commit_revision + 1, before.commit_revision + 2])
    );
    let (key, bytes) = attempt_record(&store.read_at(before.commit_revision)?, &inputs[2].id)?;
    assert_eq!(settled.get(&key), Some(&bytes));
    let resume = store.managed_resume([1; 16], "counter", &control)?;
    assert_eq!(resume.instance, current);
    assert_eq!(resume.frontier, receipt.frontier);
    assert_eq!(resume.completed, expected.commit_revision);
    let status = store.managed_status(&current.grant.selection, "counter", &control)?;
    assert_eq!(status.instance, current);
    assert_eq!(status.status_progress, receipt.commit_revision);
    assert!(matches!(status.readiness, PackageReadinessV1::Ready));
    assert_eq!(
        store.managed_history(&current.grant.selection, "counter", &control)?,
        [receipt]
    );
    let view = store.view()?;
    assert_eq!(records(&view, b"\0data/X")?, results);
    assert_eq!(records(&view, b"\0data/U")?, checkpoints);
    assert_eq!(
        *store.subscribe_revision().borrow(),
        expected.commit_revision
    );
    drop(view);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.meta(), expected);
    assert_eq!(store.managed_resume([1; 16], "counter", &control)?, resume);
    Ok(())
}

#[test]
fn startup_keeps_committed_state() -> TestResult {
    for stopped in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = StorageFixture::new(&store, "counter", String::new())?;
        store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
            Ok(())
        })?;
        let captured = fixture.capture(&store)?;
        let input = native_request("committed");
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let evaluations = [
            fixture.continued(&input, 10, Some(&captured))?,
            fixture.continued(&input, 11, Some(&captured))?,
        ];
        let outputs = [
            fixture.output(2, "exact context")?,
            fixture.output(3, "exact context")?,
        ];
        let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
        if !stopped {
            let captured = fixture.capture(&store)?;
            let failed =
                store.register_managed_attempt(&captured, &request("known-failure"), || Ok(()))?;
            store.finish_managed(&failed, ManagedExit::Failed(Code::Invalid), || Ok(()))?;
        }
        let captured = fixture.capture(&store)?;
        let interrupted = native_request("interrupted");
        let pending = store.register_managed_attempt(&captured, &interrupted, || Ok(()))?;
        if stopped {
            store.set_managed_running(
                [1; 16],
                "counter",
                captured.instance().lifecycle,
                false,
                || Ok(()),
            )?;
        }
        let current = fixture.current(&store)?;
        let prior = fixture.capture(&store)?;
        let view = store.view()?;
        let failure = records(&view, b"\0data/Y")?;
        let results = records(&view, b"\0data/X")?;
        let checkpoints = records(&view, b"\0data/U")?;
        assert_eq!(results.len(), 3);
        assert_eq!(checkpoints.len(), 2);
        let dependencies = records(&view, b"\0data/ref/dependency/")?;
        assert_eq!(dependencies.len(), 2);
        let contracts = records(&view, b"\0data/a")?;
        let (key, contract) = attempt_record(&view, &interrupted.id)?;
        let before = view.meta();
        drop((view, captured));
        drop(store);
        let store = NativeStore::open(&root)?;
        let mut expected = before.clone();
        expected.commit_revision += 1;
        assert_eq!(store.view()?.meta(), expected);
        assert_eq!(fixture.current(&store)?, current);
        assert_eq!(
            records(&store.read_at(before.commit_revision)?, b"\0data/a")?,
            contracts
        );
        let control = AnalysisReadControl::default();
        let loaded = store
            .managed_attempt([1; 16], "counter", &interrupted.id, &control)?
            .ok_or("interrupted intent")?;
        assert_eq!(loaded.request(), &interrupted);
        assert_eq!(loaded.instance(), pending.instance());
        assert!(loaded.receipt().is_none());
        let terminal = loaded.terminal().ok_or("startup cancellation")?;
        assert_eq!(terminal.exit, ManagedExit::Cancelled);
        assert!(!terminal.suspended);
        assert_eq!(terminal.revision, expected.commit_revision);
        assert_eq!(
            store
                .view()?
                .snapshot()
                .get(&key)?
                .ok_or("settled contract")?
                .as_ref(),
            terminal_bytes(&contract, terminal)?
        );
        let resume = store.managed_resume([1; 16], "counter", &control)?;
        assert_eq!(resume.instance, current);
        assert_eq!(resume.frontier, receipt.frontier);
        assert_eq!(resume.completed, terminal.revision);
        let status = store.managed_status(&current.grant.selection, "counter", &control)?;
        assert_eq!(status.instance, current);
        assert_eq!(status.status_progress, receipt.commit_revision);
        if stopped {
            assert!(matches!(status.readiness, PackageReadinessV1::Inactive));
        } else {
            assert!(matches!(
                status.readiness,
                PackageReadinessV1::Failed {
                    code: Code::Invalid,
                    ..
                }
            ));
        }
        assert_eq!(records(store.view()?.as_ref(), b"\0data/Y")?, failure);
        assert_eq!(
            store.managed_history(&current.grant.selection, "counter", &control)?,
            [receipt.clone()]
        );
        let after = fixture.capture(&store)?;
        for call in [10, 11] {
            let original = prior.prior(call).ok_or("prior call")?;
            let retained = after.prior(call).ok_or("retained call")?;
            assert_eq!(retained.revision, original.revision);
            assert_eq!(retained.result, original.result);
            let original = original.checkpoint.as_ref().ok_or("prior checkpoint")?;
            let retained = retained.checkpoint.as_ref().ok_or("retained checkpoint")?;
            assert_eq!(retained.version, original.version);
            assert_eq!(retained.datasets.len(), original.datasets.len());
            for (actual, expected) in retained.datasets.iter().zip(&original.datasets) {
                assert_eq!(actual.name, expected.name);
                assert_eq!(actual.batches, expected.batches);
            }
        }
        fixture.assert_retained(&store, &receipt, &evaluations, &outputs)?;
        let view = store.view()?;
        assert_eq!(records(&view, b"\0data/X")?, results);
        assert_eq!(records(&view, b"\0data/U")?, checkpoints);
        assert_eq!(records(&view, b"\0data/ref/dependency/")?, dependencies);
        store.recover()?;
        drop((view, prior, after));
        drop(store);
        let store = NativeStore::open(&root)?;
        assert_eq!(store.view()?.meta(), expected);
        assert_eq!(fixture.current(&store)?, current);
        assert_eq!(store.managed_resume([1; 16], "counter", &control)?, resume);
    }
    Ok(())
}

#[test]
fn startup_filters_generations() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let old_capture = fixture.capture(&store)?;
    let current = fixture.current(&store)?;
    let mut spec = current.spec.clone();
    spec.definition.definition.description = "Promote one genuine target.".into();
    spec.manifest.definition = store.admit_definition([1; 16], &spec.definition, || Ok(()))?;
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let captured = capture_target(&store, &current, &target)?;
    let input = native_request("promote");
    let promoted = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let old =
        store.register_managed_attempt(&old_capture, &native_request("old-native"), || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [
        fixture.output(2, "exact context")?,
        fixture.output(3, "exact context")?,
    ];
    let receipt = fixture.publish(&store, &promoted, &evaluations, &outputs, || Ok(()))?;
    let current = fixture.current(&store)?;
    let mut spec = current.spec.clone();
    spec.definition.definition.description = "Keep this target prospective.".into();
    spec.manifest.definition = store.admit_definition([1; 16], &spec.definition, || Ok(()))?;
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let captured = capture_target(&store, &current, &target)?;
    let prospective =
        store.register_managed_attempt(&captured, &native_request("prospective"), || Ok(()))?;
    let captured = fixture.capture(&store)?;
    let native =
        store.register_managed_attempt(&captured, &native_request("current-native"), || Ok(()))?;
    let unknown =
        store.register_managed_attempt(&captured, &request("current-unknown"), || Ok(()))?;
    let view = store.view()?;
    let contracts = records(&view, b"\0data/a")?;
    let pending = records(&view, b"\0data/p")?;
    let (settled_key, _) = attempt_record(&view, &native.request().id)?;
    let before = view.meta();
    drop((view, captured, old_capture));
    drop(store);
    let store = NativeStore::open(&root)?;
    let mut expected = before.clone();
    expected.commit_revision += 1;
    assert_eq!(store.view()?.meta(), expected);
    assert_eq!(fixture.current(&store)?, current);
    let control = AnalysisReadControl::default();
    let settled = store
        .managed_attempt([1; 16], "counter", &native.request().id, &control)?
        .ok_or("settled current")?;
    let terminal = settled.terminal().ok_or("current cancellation")?;
    assert_eq!(terminal.exit, ManagedExit::Cancelled);
    assert_eq!(terminal.revision, expected.commit_revision);
    assert_eq!(
        store
            .view()?
            .snapshot()
            .get(&settled_key)?
            .ok_or("settled bytes")?
            .as_ref(),
        terminal_bytes(&contracts[&settled_key], terminal)?
    );
    for original in [&old, &prospective, &unknown] {
        let loaded = store
            .managed_attempt([1; 16], "counter", &original.request().id, &control)?
            .ok_or("preserved intent")?;
        let (key, bytes) = attempt_record(store.view()?.as_ref(), &original.request().id)?;
        assert_eq!(contracts.get(&key), Some(&bytes));
        assert!(loaded.terminal().is_none());
        assert!(loaded.receipt().is_none());
        assert!(matches!(
            store.finish_managed(&loaded, ManagedExit::Cancelled, || Ok(())),
            Err(Error::Package {
                code: Code::Incomplete,
                ..
            })
        ));
        assert!(matches!(
            store.finish_managed(original, ManagedExit::Cancelled, || Ok(())),
            Err(Error::AnalysisConflict { .. })
        ));
    }
    let remaining = records(store.view()?.as_ref(), b"\0data/p")?;
    assert_eq!(remaining.len() + 1, pending.len());
    for (key, bytes) in &remaining {
        assert_eq!(pending.get(key), Some(bytes));
    }
    assert!(matches!(
        store.managed_resume([1; 16], "counter", &control),
        Err(Error::Package {
            code: Code::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    assert!(matches!(
        store.prepare_managed_version(&current, &spec, || Ok(())),
        Err(Error::Package {
            code: Code::Incomplete,
            ..
        })
    ));
    assert_eq!(
        store.managed_history(&current.grant.selection, "counter", &control)?,
        [receipt]
    );
    assert_eq!(store.view()?.meta(), expected);
    store.recover()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.meta(), expected);
    assert_eq!(fixture.current(&store)?, current);
    Ok(())
}

#[test]
fn startup_restores_native_intent() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("source");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    store.set_managed_running([1; 16], "counter", fixture.instance.lifecycle, true, || {
        Ok(())
    })?;
    let captured = fixture.capture(&store)?;
    let input = native_request("before-backup");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    let outputs = [
        fixture.output(2, "exact context")?,
        fixture.output(3, "exact context")?,
    ];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
    let current = fixture.current(&store)?;
    let captured = fixture.capture(&store)?;
    let pending_input = native_request("live-through-backup");
    let pending = store.register_managed_attempt(&captured, &pending_input, || Ok(()))?;
    let pending_evaluations = [
        fixture.continued(&pending_input, 10, Some(&captured))?,
        fixture.continued(&pending_input, 11, Some(&captured))?,
    ];
    let before = data_state(&store)?;
    let view = store.view()?;
    let results = records(&view, b"\0data/X")?;
    let checkpoints = records(&view, b"\0data/U")?;
    assert_eq!(results.len(), 3);
    assert_eq!(checkpoints.len(), 2);
    let dependencies = records(&view, b"\0data/ref/dependency/")?;
    assert_eq!(dependencies.len(), 2);
    let contracts = records(&view, b"\0data/a")?;
    let (key, contract) = attempt_record(&view, &pending_input.id)?;
    let backup = root.join("backups/native-pending");
    let manifest = store.backup(&backup)?;
    assert_eq!(manifest.commit_revision, before.0.commit_revision);
    assert_eq!(manifest.recovery_epoch, before.0.recovery_epoch);
    assert_eq!(data_state(&store)?, before);
    let target = directory.path().join("restored");
    let restored = NativeStore::restore(&backup, &target)?;
    let mut expected = before.0.clone();
    expected.recovery_epoch += 1;
    expected.commit_revision += 1;
    assert_eq!(restored.view()?.meta(), expected);
    assert!(!target.join("restore.pending").exists());
    assert_eq!(fixture.current(&restored)?, current);
    let control = AnalysisReadControl::default();
    let recovered = restored
        .managed_attempt([1; 16], "counter", &pending_input.id, &control)?
        .ok_or("restored intent")?;
    let terminal = recovered.terminal().ok_or("restored cancellation")?;
    assert_eq!(terminal.exit, ManagedExit::Cancelled);
    assert!(!terminal.suspended);
    assert_eq!(terminal.revision, expected.commit_revision);
    assert!(recovered.receipt().is_none());
    assert_eq!(
        restored
            .view()?
            .snapshot()
            .get(&key)?
            .ok_or("restored bytes")?
            .as_ref(),
        terminal_bytes(&contract, terminal)?
    );
    assert_eq!(
        records(&restored.read_at(before.0.commit_revision)?, b"\0data/a")?,
        contracts
    );
    let resumed = restored.managed_resume([1; 16], "counter", &control)?;
    assert_eq!(resumed.instance, current);
    assert_eq!(resumed.frontier, receipt.frontier);
    assert_eq!(resumed.completed, terminal.revision);
    assert_eq!(
        restored.managed_history(&current.grant.selection, "counter", &control)?,
        [receipt.clone()]
    );
    fixture.assert_retained(&restored, &receipt, &evaluations, &outputs)?;
    let selected = StorageFixture::receipt(&restored, [1; 16], "counter", &input.id, &control)?
        .ok_or("restored success")?;
    assert_eq!(selected, receipt);
    assert_eq!(StorageFixture::rows(&restored, &selected.selected)?, 1);
    assert!(matches!(
        fixture.publish(&restored, &pending, &pending_evaluations, &outputs, || Ok(
            ()
        )),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(restored.view()?.meta(), expected);
    assert_eq!(data_state(&store)?, before);
    assert_eq!(fixture.current(&store)?, current);
    let source_pending = store
        .managed_attempt([1; 16], "counter", &pending_input.id, &control)?
        .ok_or("source intent")?;
    assert!(source_pending.terminal().is_none());
    assert_eq!(
        attempt_record(store.view()?.as_ref(), &pending_input.id)?.1,
        contract
    );
    let source_outputs = [
        fixture.output(22, "exact context")?,
        fixture.output(33, "exact context")?,
    ];
    let published = fixture.publish(
        &store,
        &pending,
        &pending_evaluations,
        &source_outputs,
        || Ok(()),
    )?;
    assert_eq!(published.commit_revision, before.0.commit_revision + 1);
    assert_eq!(published.results.len(), 2);
    assert_eq!(
        store.managed_resume([1; 16], "counter", &control)?.frontier,
        published.frontier
    );
    assert_eq!(restored.view()?.meta(), expected);
    assert_eq!(fixture.current(&restored)?, current);
    assert_eq!(
        restored.managed_history(&current.grant.selection, "counter", &control)?,
        [receipt.clone()]
    );
    assert_eq!(records(restored.view()?.as_ref(), b"\0data/X")?, results);
    assert_eq!(
        records(restored.view()?.as_ref(), b"\0data/U")?,
        checkpoints
    );
    assert_eq!(
        records(restored.view()?.as_ref(), b"\0data/ref/dependency/")?,
        dependencies
    );
    restored.recover()?;
    store.recover()?;
    let source_state = data_state(&store)?;
    let source_history = store.managed_history(&current.grant.selection, "counter", &control)?;
    assert_eq!(source_history.len(), 2);
    assert!(source_history.contains(&receipt));
    assert!(source_history.contains(&published));
    let restored_state = data_state(&restored)?;
    drop((view, captured));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(data_state(&store)?, source_state);
    assert_eq!(
        store.managed_history(&current.grant.selection, "counter", &control)?,
        source_history
    );
    fixture.assert_retained(&store, &published, &pending_evaluations, &source_outputs)?;
    assert_eq!(data_state(&restored)?, restored_state);
    drop(restored);
    let restored = NativeStore::open(&target)?;
    assert_eq!(data_state(&restored)?, restored_state);
    assert_eq!(restored.view()?.meta(), expected);
    assert_eq!(fixture.current(&restored)?, current);
    assert_eq!(
        restored.managed_resume([1; 16], "counter", &control)?,
        resumed
    );
    fixture.assert_retained(&restored, &receipt, &evaluations, &outputs)?;
    Ok(())
}
