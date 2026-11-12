use super::*;
use serde::Serialize as _;

struct Artifact {
    key: Vec<u8>,
    header: Vec<u8>,
    body_key: Vec<u8>,
    body: Vec<u8>,
}

impl Artifact {
    fn load(store: &AnalysisStore) -> TestResult<Self> {
        let view = store.view()?;
        for row in view.snapshot().prefix(b"\0data/P") {
            let (key, bytes) = row?;
            if key.len() != 15 {
                continue;
            }
            assert_eq!(bytes.first(), Some(&0));
            let header: (crate::analysis::PackageRevisionV1, u64, u64) =
                rmp_serde::from_slice(&bytes[1..])?;
            if header.0.package_id != "managed-fixture" {
                continue;
            }
            let body_key = [b"\0data/@package-body/".as_slice(), &key[7..]].concat();
            let body = view.snapshot().get(&body_key)?.ok_or("package body")?;
            assert_eq!(body.first(), Some(&0));
            assert_eq!(body.len() as u64 - 1, header.2);
            return Ok(Self {
                key: key.to_vec(),
                header: bytes.to_vec(),
                body_key,
                body: body.to_vec(),
            });
        }
        Err("retained package header".into())
    }

    fn replace(&self, store: &AnalysisStore, body: &[u8]) -> TestResult {
        let mut header: (crate::analysis::PackageRevisionV1, u64, u64) =
            rmp_serde::from_slice(&self.header[1..])?;
        header.2 = body.len() as u64;
        let mut bytes = vec![0];
        header.serialize(
            &mut rmp_serde::Serializer::new(&mut bytes)
                .with_bytes(rmp_serde::config::BytesMode::ForceIterables),
        )?;
        let mut tx = store.write()?;
        tx.native().insert(self.key.clone(), bytes);
        tx.native()
            .insert(self.body_key.clone(), [b"\0", body].concat());
        tx.commit([])?;
        Ok(())
    }

    fn restore(&self, store: &AnalysisStore) -> TestResult {
        let mut tx = store.write()?;
        tx.native().insert(self.key.clone(), self.header.clone());
        tx.native().insert(self.body_key.clone(), self.body.clone());
        tx.commit([])?;
        Ok(())
    }
}

#[test]
fn execution_retains_only_committed_state() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_model(&store, false, AnalysisSelectionV1::tenant([1; 16]), true)?;
    let execution = Arc::new(ManagedExecution::default());
    let declaration = &fixture.instance.spec.manifest.calls[&10];
    let bundle = store
        .retained_package_image([1; 16], &declaration.image, &AnalysisReadControl::default())?
        .ok_or("execution package image")?;
    let context = crate::AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &declaration.package,
        &declaration.export,
        "rows",
    )?;
    let reference = store.intern_context(&context)?;
    let mut captured = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    captured.contract.contexts.push(reference.clone());
    let input = request("retained-first");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    assert!(fixture
        .publish_checked(&store, &attempt, &evaluations, &outputs, || {
            crate::AnalysisReadDeniedSnafu.fail()
        })
        .is_err());
    let unchanged = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(unchanged.prior(10).is_none());
    assert_eq!(execution.metadata_bytes(), 0);
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let mut warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(
        execution
            .packages(&warm.instance, &warm.contract)
            .metadata_bytes()
            > 0
    );
    let mut recovered = warm.contract.clone();
    recovered.recovery += 1;
    assert_eq!(
        execution
            .packages(&warm.instance, &recovered)
            .metadata_bytes(),
        0
    );
    warm.contract.contexts.push(reference.clone());
    let cold = fixture.capture(&store, false)?;
    for call in [10, 11] {
        let warm = warm.prior(call).ok_or("warm prior")?;
        let cold = cold.prior(call).ok_or("cold prior")?;
        assert_eq!(warm.result, receipt.results[&call].result_id);
        assert_eq!(warm.context, cold.context);
        assert!(cold.retained.is_none());
        let checkpoint = warm.checkpoint.as_ref().ok_or("warm checkpoint")?;
        let stored = cold.checkpoint.as_ref().ok_or("cold checkpoint")?;
        assert_eq!(
            sdk::wire::Checkpoint::encode(checkpoint, &fixture.model)?,
            sdk::wire::Checkpoint::encode(stored, &fixture.model)?
        );
        let warm = warm.retained.as_ref().ok_or("warm output")?;
        assert!(Arc::ptr_eq(
            outputs[(call - 10) as usize].datasets[0].batches[0].column(0),
            warm.output.datasets[0].batches[0].column(0)
        ));
        assert!(!Arc::ptr_eq(
            checkpoint.datasets[0].batches[0].column(0),
            stored.datasets[0].batches[0].column(0)
        ));
        assert!(warm.evaluation.checkpoint.is_none());
        assert!(warm.evaluation.previous_outputs.is_empty());
        assert_eq!(
            warm.output.datasets[0].batches,
            outputs[(call - 10) as usize].datasets[0].batches
        );
    }
    let idle = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let proofs = execution.packages(&idle.instance, &idle.contract);
    assert!(proofs.metadata_bytes() > 0);
    let attempt = store.register_managed_attempt(&idle, &request("retained-empty"), || Ok(()))?;
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: vec![sdk::RecordBatch::new_empty(Arc::new(
            fixture.model.outputs[0].schema.clone(),
        ))],
    };
    let empty = Fixture::commit(
        &store,
        &ManagedCommit {
            control: &crate::AnalysisReadControl::default(),
            budget: &crate::analysis::managed::tests::TestBudget,
            completed: true,
            attempt: &attempt,
            now_utc_ns: 10,
            returns: &[],
            selected: &selected,
            selected_schema: &fixture.model.outputs[0].schema,
        },
        || Ok(()),
    )?;
    assert!(empty.results.is_empty());
    warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(proofs.shares_roots(&execution.packages(&warm.instance, &warm.contract)));
    for removed in [false, true] {
        let mut changed = warm.instance.clone();
        if removed {
            changed.spec.manifest.calls.remove(&10);
        } else {
            changed
                .spec
                .manifest
                .calls
                .get_mut(&10)
                .ok_or("active call")?
                .image
                .image
                .revision
                .push_str("-changed");
        }
        assert_eq!(
            execution
                .packages(&changed, &warm.contract)
                .metadata_bytes(),
            0
        );
    }
    warm.contract.contexts.push(reference.clone());
    let next = request("retained-next");
    let attempt = store.register_managed_attempt(&warm, &next, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&next, 10, Some(&warm))?,
        fixture.evaluation(&next, 11, Some(&warm))?,
    ];
    assert!(evaluations
        .iter()
        .all(|evaluation| evaluation.checkpoint.is_some()));
    let changed = Fixture::batch(&fixture.model.parameters, 99)?;
    assert!(warm
        .prior(10)
        .ok_or("parameter prior")?
        .state(
            &fixture.model,
            &evaluations[0].inputs,
            Some(&changed),
            false
        )?
        .0
        .is_none());
    let outputs = [fixture.output(4)?, fixture.output(5)?];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let mut current = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(proofs.shares_roots(&execution.packages(&current.instance, &current.contract)));
    assert_eq!(
        current.prior(10).ok_or("current prior")?.result,
        receipt.results[&10].result_id
    );
    assert!(current
        .prior(10)
        .and_then(|prior| prior.retained.as_ref())
        .is_some_and(|retained| retained.evaluation.previous_outputs.is_empty()));
    current.contract.contexts.push(reference);
    Artifact::load(&store)?.replace(&store, b"changed")?;
    assert!(store
        .register_managed_attempt(&current, &request("retained-tampered"), || Ok(()))
        .is_err());
    execution.clear();
    assert_eq!(execution.metadata_bytes(), 0);
    Ok(())
}

#[test]
fn execution_checks_heads_and_recovery_epoch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_model(&store, false, AnalysisSelectionV1::tenant([1; 16]), true)?;
    let execution = Arc::new(ManagedExecution::default());
    let mut receipts = Vec::new();
    for value in [2, 4] {
        let captured = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
        let input = request(&format!("retained-{value}"));
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        let evaluations = [
            fixture.evaluation(&input, 10, Some(&captured))?,
            fixture.evaluation(&input, 11, Some(&captured))?,
        ];
        receipts.push(fixture.publish(
            &store,
            &attempt,
            &evaluations,
            &[fixture.output(value)?, fixture.output(value + 1)?],
        )?);
    }
    let warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let last = warm.prior(10).ok_or("last prior")?;
    let first = &receipts[0].results[&10];
    #[derive(serde::Deserialize, serde::Serialize)]
    struct Head {
        revision: u64,
        result: Option<String>,
    }
    let view = store.view()?;
    let mut heads = view.snapshot().prefix(b"\0data/Q");
    let mut head = None;
    for row in &mut heads {
        let (key, bytes) = row?;
        if key.len() == 23 && key[15..] == 10u64.to_be_bytes() {
            assert!(head.is_none());
            head = Some((key, bytes));
        }
    }
    let (head_key, head_bytes) = head.ok_or("call 10 head")?;
    assert_eq!(head_bytes.first(), Some(&0));
    let original: Head = rmp_serde::from_slice(&head_bytes[1..])?;
    assert_eq!(original.revision, receipts[1].results[&10].commit_revision);
    assert_eq!(original.result.as_deref(), Some(last.result.as_str()));
    let mut bytes = vec![0];
    bytes.extend(rmp_serde::to_vec_named(&Head {
        revision: first.commit_revision,
        result: Some(first.result_id.clone()),
    })?);
    let mut tx = store.write()?;
    tx.native().insert(head_key.clone(), bytes);
    tx.commit([])?;
    drop(heads);
    drop(view);
    let changed = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let previous = changed.prior(10).ok_or("changed prior")?;
    assert_eq!(previous.result, first.result_id);
    assert_ne!(previous.result, last.result);
    assert!(previous.retained.is_none());
    assert!(previous.checkpoint.is_some());
    let before = changed.prior(11).ok_or("retained prior")?;
    assert!(before.retained.is_some());
    let mut tx = store.write()?;
    tx.native().insert(head_key, head_bytes);
    tx.commit([])?;
    drop(store);
    let reopened = AnalysisStore::open(directory.path().join("store"))?;
    let mut meta = reopened.meta()?;
    meta.recovery_epoch += 1;
    assert!(execution
        .calls(
            &ManagedRead {
                source: None,
                execution: Some(Arc::clone(&execution)),
                instance: fixture.current(&reopened)?,
                expected: None,
                rebuild: false,
                follow: false,
                completed: None,
            },
            &meta
        )
        .is_empty());
    let recovered = fixture.capture_execution(
        &reopened,
        false,
        Some(Arc::new(ManagedExecution::default())),
    )?;
    let after = recovered.prior(11).ok_or("recovered prior")?;
    assert!(after.retained.is_none());
    let before = before.checkpoint.as_ref().ok_or("prior checkpoint")?;
    let after = after.checkpoint.as_ref().ok_or("recovered checkpoint")?;
    assert_eq!(
        sdk::wire::Checkpoint::encode(before, &fixture.model)?,
        sdk::wire::Checkpoint::encode(after, &fixture.model)?
    );
    assert!(!Arc::ptr_eq(
        before.datasets[0].batches[0].column(0),
        after.datasets[0].batches[0].column(0)
    ));
    Ok(())
}

#[test]
fn execution_checks_package_restore() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("store"))?;
    let fixture = Fixture::admit_model(&store, false, AnalysisSelectionV1::tenant([1; 16]), true)?;
    let execution = Arc::new(ManagedExecution::default());
    let captured = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    let input = request("retained-package");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10, Some(&captured))?,
        fixture.evaluation(&input, 11, Some(&captured))?,
    ];
    let outputs = [fixture.output(2)?, fixture.output(3)?];
    fixture.publish(&store, &attempt, &evaluations, &outputs)?;
    let artifact = Artifact::load(&store)?;
    artifact.replace(&store, b"invalid")?;
    let warm = fixture.capture_execution(&store, false, Some(Arc::clone(&execution)))?;
    assert!(Arc::ptr_eq(
        outputs[0].datasets[0].batches[0].column(0),
        warm.prior(10)
            .and_then(|prior| prior.retained.as_ref())
            .ok_or("retained output")?
            .output
            .datasets[0]
            .batches[0]
            .column(0)
    ));
    let pin = fixture
        .instance
        .spec
        .definition
        .images
        .first()
        .ok_or("managed image pin")?;
    let control = AnalysisReadControl::default();
    assert!(store
        .retained_package_image([1; 16], pin, &control)
        .is_err());
    artifact.restore(&store)?;
    assert_eq!(
        store
            .retained_package_image([1; 16], pin, &control)?
            .ok_or("restored package image")?
            .digest(),
        pin.digest
    );
    let mut tx = store.write()?;
    tx.native().remove(artifact.key);
    tx.commit([])?;
    assert!(fixture.capture(&store, false).is_err());
    Ok(())
}
