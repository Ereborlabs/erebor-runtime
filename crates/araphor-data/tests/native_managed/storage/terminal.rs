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
