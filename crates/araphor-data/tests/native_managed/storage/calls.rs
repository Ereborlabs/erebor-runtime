use super::*;

fn call_context(
    result: &araphor_data::InstanceResultV1,
) -> Result<&araphor_data::ResultContext, Box<dyn std::error::Error>> {
    let araphor_data::InstanceResultKindV1::Call { context, .. } = &result.kind else {
        return Err("call reference kind".into());
    };
    Ok(context)
}

impl StorageFixture {
    fn continued(
        &self,
        request: &ManagedRequest,
        call: u64,
        capture: Option<&ManagedCapture>,
    ) -> Result<sdk::Evaluation, Box<dyn std::error::Error>> {
        let mut evaluation = self.evaluation(request, call)?;
        if let Some(prior) = capture.and_then(|capture| capture.prior(call)) {
            (evaluation.checkpoint, evaluation.previous_outputs) = prior.state(
                &self.model,
                &evaluation.inputs,
                evaluation.parameters.as_ref(),
                request.rebuild,
            )?;
        }
        Ok(evaluation)
    }

    fn receipt(
        store: &NativeStore,
        tenant: [u8; 16],
        instance: &str,
        attempt: &str,
        control: &AnalysisReadControl,
    ) -> araphor_data::Result<Option<ManagedReceipt>> {
        Ok(store
            .managed_attempt(tenant, instance, attempt, control)?
            .and_then(|attempt| attempt.receipt().cloned()))
    }

    fn checkpoint(
        &self,
        store: &NativeStore,
        reference: &PackageResultRefV1,
    ) -> Result<sdk::Checkpoint, Box<dyn std::error::Error>> {
        let view = store.view()?;
        for (key, bytes) in records(&view, b"\0data/X")? {
            let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
            if stored.id == reference.result_id {
                assert_eq!(stored.revision, reference.commit_revision);
                assert!(matches!(stored.body, Body::Call { .. }));
                let key = [b"\0data/U".as_slice(), &key[7..]].concat();
                let bytes = view.snapshot().get(key)?.ok_or("checkpoint")?;
                let wire: Option<sdk::wire::Checkpoint> = rmp_serde::from_slice(&bytes[1..])?;
                return Ok(wire.ok_or("checkpoint")?.decode_model(&self.model)?);
            }
        }
        Err("checkpoint result".into())
    }

    fn rows(
        store: &NativeStore,
        reference: &PackageResultRefV1,
    ) -> Result<u64, Box<dyn std::error::Error>> {
        for bytes in records(store.view()?.as_ref(), b"\0data/X")?.values() {
            let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
            if stored.id == reference.result_id {
                assert_eq!(stored.revision, reference.commit_revision);
                let Body::Selected { rows, .. } = stored.body else {
                    return Err("selected result kind".into());
                };
                return Ok(rows);
            }
        }
        Err("selected result".into())
    }
}

#[test]
fn call_references_keep_descriptor() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let captured = fixture.capture(&store)?;
    let request = request("retained-writer");
    let attempt = store.register_managed_attempt(&captured, &request, || Ok(()))?;
    let evaluations = [
        fixture.continued(&request, 10, None)?,
        fixture.continued(&request, 11, None)?,
    ];
    let receipt = fixture.publish(
        &store,
        &attempt,
        &evaluations,
        &[
            fixture.output(12, "exact context")?,
            fixture.output(103, "exact context")?,
        ],
        || Ok(()),
    )?;
    for (call, reference) in &receipt.results {
        let result = store.managed_result(
            &fixture.instance,
            &reference.result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        let araphor_data::InstanceResultKindV1::Call {
            image,
            package,
            export,
            context,
            ..
        } = &result.kind
        else {
            return Err("call reference kind".into());
        };
        let expected = &fixture.instance.spec.manifest.calls[call];
        assert_eq!(context.context.id, request.id);
        assert_eq!(
            (image, package, export),
            (&expected.image, &expected.package, &expected.export)
        );
        assert_eq!(result.result, *reference);
        assert_eq!(result.receipt, receipt);
        assert_eq!(
            fixture.checkpoint(&store, reference)?.datasets[0].batches[0]
                .schema()
                .as_ref(),
            &fixture
                .model
                .checkpoint
                .as_ref()
                .ok_or("checkpoint declaration")?
                .datasets[0]
                .schema
        );
    }
    Ok(())
}

#[test]
fn managed_calls_commit_atomically() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("store");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let mut checked = false;
    assert_eq!(
        store.admit_managed(&fixture.instance.spec, &fixture.instance.grant, || {
            checked = true;
            Ok(())
        })?,
        fixture.instance
    );
    assert!(checked);
    let mut changed = fixture.instance.spec.clone();
    changed
        .manifest
        .calls
        .get_mut(&10)
        .ok_or("call absent")?
        .arguments
        .push("changed => 1".into());
    assert!(matches!(
        store.admit_managed(&changed, &fixture.instance.grant, || Ok(())),
        Err(araphor_data::Error::AnalysisConflict { .. })
    ));
    let captured = fixture.capture(&store)?;
    assert!(captured.prior(10).is_none());
    assert!(captured.prior(11).is_none());
    let input = request("step-1");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    assert!(matches!(
        store.register_managed_attempt(&captured, &input, || Ok(())),
        Err(araphor_data::Error::Package {
            code: araphor_data::PackageErrorCodeV1::Incomplete,
            field: "managed pending attempt",
            ..
        })
    ));
    let evaluations = [
        fixture.continued(&input, 10, None)?,
        fixture.continued(&input, 11, None)?,
    ];
    let outputs = [
        fixture.output(12, "exact context")?,
        fixture.output(103, "exact context")?,
    ];
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs, || Ok(()))?;
    assert_eq!(receipt.results.len(), 2);
    assert_eq!(receipt.selected.commit_revision, receipt.commit_revision);
    let after = store.meta()?;
    assert!(fixture
        .publish(&store, &attempt, &evaluations, &outputs, || Ok(()))
        .is_err());
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                &input.id,
                &AnalysisReadControl::default()
            )?
            .and_then(|attempt| attempt.receipt().cloned()),
        Some(receipt.clone())
    );
    assert_eq!(store.meta()?, after);
    for call in [10, 11] {
        let retained = store.managed_result(
            &fixture.instance,
            &receipt.results[&call].result_id,
            10,
            &AnalysisReadControl::default(),
        )?;
        assert!(retained.current);
        assert_eq!(retained.result, receipt.results[&call]);
        assert_eq!(retained.receipt, receipt);
        assert_eq!(
            call_context(&retained)?.context,
            evaluations[(call - 10) as usize].context
        );
        assert_eq!(
            fixture
                .checkpoint(&store, &receipt.results[&call])?
                .datasets[0]
                .batches,
            outputs[(call - 10) as usize]
                .checkpoint
                .as_ref()
                .ok_or("expected checkpoint")?
                .datasets[0]
                .batches
        );
    }
    let selected = StorageFixture::receipt(
        &store,
        [1; 16],
        "counter",
        "step-1",
        &AnalysisReadControl::default(),
    )?
    .ok_or("selected result absent")?;
    assert_eq!(selected, receipt);
    assert_eq!(StorageFixture::rows(&store, &selected.selected)?, 1);
    assert!(StorageFixture::receipt(
        &store,
        [2; 16],
        "counter",
        "step-1",
        &AnalysisReadControl::default()
    )?
    .is_none());
    let mut next = fixture.capture(&store)?;
    for (call, evaluation) in [10, 11].into_iter().zip(&evaluations) {
        next.hydrate_prior(
            call,
            &fixture.model,
            evaluation.parameters.as_ref().map(|batch| sdk::Dataset {
                name: "parameters".into(),
                batches: vec![batch.clone()],
            }),
            None,
        )?;
    }
    assert_eq!(next.instance().progress, receipt.commit_revision);
    assert_ne!(
        next.prior(10).ok_or("first prior absent")?.result,
        next.prior(11).ok_or("second prior absent")?.result
    );
    assert_eq!(
        fixture
            .continued(&request("step-2"), 10, Some(&next))?
            .checkpoint
            .ok_or("first state absent")?
            .datasets[0]
            .batches,
        outputs[0]
            .checkpoint
            .as_ref()
            .ok_or("state absent")?
            .datasets[0]
            .batches
    );
    assert_eq!(
        fixture
            .continued(&request("step-2"), 11, Some(&next))?
            .checkpoint
            .ok_or("second state absent")?
            .datasets[0]
            .batches,
        outputs[1]
            .checkpoint
            .as_ref()
            .ok_or("state absent")?
            .datasets[0]
            .batches
    );
    let view = store.view()?;
    let results = records(&view, b"\0data/X")?.len();
    let attempts = records(&view, b"\0data/a")?.len();
    assert_eq!((results, attempts), (3, 1));
    drop(view);
    let second = request("step-2");
    let second_attempt = store.register_managed_attempt(&next, &second, || Ok(()))?;
    let second_evaluations = [
        fixture.continued(&second, 10, Some(&next))?,
        fixture.continued(&second, 11, Some(&next))?,
    ];
    let second_outputs = [
        fixture.output(22, "exact context")?,
        fixture.output(203, "exact context")?,
    ];
    let second_receipt = fixture.publish(
        &store,
        &second_attempt,
        &second_evaluations,
        &second_outputs,
        || Ok(()),
    )?;
    assert!(second_receipt.commit_revision > receipt.commit_revision);
    let before_collection = store.meta()?;
    for pin in &fixture.instance.spec.definition.images {
        store.collect_package([1; 16], &pin.image.package_id, &pin.image.revision)?;
    }
    store.collect_package_admissions()?;
    assert_eq!(store.meta()?, before_collection);
    let backup = root.join("backups/managed");
    store.backup(&backup)?;
    drop(store);
    let reopened = NativeStore::open(&root)?;
    let retry = reopened
        .managed_attempt(
            [1; 16],
            "counter",
            "step-1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("attempt absent")?;
    assert_eq!(retry.receipt().cloned(), Some(receipt.clone()));
    let mut latest = fixture.capture(&reopened)?;
    assert_eq!(latest.instance().progress, second_receipt.commit_revision);
    for call in [10, 11] {
        let retained = reopened.managed_result(
            &fixture.instance,
            &receipt.results[&call].result_id,
            second.time_utc_ns,
            &AnalysisReadControl::default(),
        )?;
        assert!(!retained.current);
        assert_eq!(retained.result, receipt.results[&call]);
        assert_eq!(retained.receipt, receipt);
        assert_eq!(
            call_context(&retained)?.context,
            evaluations[(call - 10) as usize].context
        );
        assert_eq!(
            fixture
                .checkpoint(&reopened, &receipt.results[&call])?
                .datasets[0]
                .batches,
            outputs[(call - 10) as usize]
                .checkpoint
                .as_ref()
                .ok_or("expected checkpoint")?
                .datasets[0]
                .batches
        );
        latest.hydrate_prior(
            call,
            &fixture.model,
            second_evaluations[(call - 10) as usize]
                .parameters
                .as_ref()
                .map(|batch| sdk::Dataset {
                    name: "parameters".into(),
                    batches: vec![batch.clone()],
                }),
            None,
        )?;
        let prior = latest.prior(call).ok_or("current checkpoint absent")?;
        assert_eq!(prior.result, second_receipt.results[&call].result_id);
        assert_eq!(
            prior.revision,
            second_receipt.results[&call].commit_revision
        );
        assert_eq!(
            prior
                .state(
                    &fixture.model,
                    &second_evaluations[(call - 10) as usize].inputs,
                    second_evaluations[(call - 10) as usize].parameters.as_ref(),
                    false,
                )?
                .0
                .ok_or("eligible current checkpoint absent")?
                .datasets[0]
                .batches,
            second_outputs[(call - 10) as usize]
                .checkpoint
                .as_ref()
                .ok_or("expected current checkpoint absent")?
                .datasets[0]
                .batches
        );
    }
    let historical_selected = StorageFixture::receipt(
        &reopened,
        [1; 16],
        "counter",
        "step-1",
        &AnalysisReadControl::default(),
    )?
    .ok_or("historical selected result absent")?;
    assert_eq!(historical_selected, receipt);
    assert_eq!(
        StorageFixture::rows(&reopened, &historical_selected.selected)?,
        1
    );
    for pin in &fixture.instance.spec.definition.images {
        let image = reopened
            .package_image(
                [1; 16],
                &pin.image.package_id,
                Some(&pin.image.revision),
                &AnalysisReadControl::default(),
            )?
            .ok_or("retained image absent")?;
        assert_eq!(image.bundle().root, pin.image);
        assert_eq!(image.digest(), pin.digest);
    }
    let restored = NativeStore::restore(&backup, &directory.path().join("restored"))?;
    let retry = restored
        .managed_attempt(
            [1; 16],
            "counter",
            "step-1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("restored attempt absent")?;
    assert_eq!(retry.receipt().cloned(), Some(receipt.clone()));
    Ok(())
}

#[test]
fn managed_capture_keeps_guards() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let captured = fixture.capture(&store)?;
    let first = request("first");
    let attempt = store.register_managed_attempt(&captured, &first, || Ok(()))?;
    let second = request("second");
    let stale = store.register_managed_attempt(&captured, &second, || Ok(()))?;
    let eval = [
        fixture.continued(&first, 10, None)?,
        fixture.continued(&first, 11, None)?,
    ];
    let outputs = [
        fixture.output(12, "exact context")?,
        fixture.output(13, "exact context")?,
    ];
    fixture.publish(&store, &attempt, &eval, &outputs, || Ok(()))?;
    let stale_eval = [
        fixture.continued(&second, 10, None)?,
        fixture.continued(&second, 11, None)?,
    ];
    let before = store.meta()?;
    assert!(fixture
        .publish(&store, &stale, &stale_eval, &outputs, || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    let mut captured = fixture.capture(&store)?;
    for (call, evaluation) in [10, 11].into_iter().zip(&eval) {
        captured.hydrate_prior(
            call,
            &fixture.model,
            evaluation.parameters.as_ref().map(|batch| sdk::Dataset {
                name: "parameters".into(),
                batches: vec![batch.clone()],
            }),
            None,
        )?;
    }
    let input = request("guarded");
    let evaluation = fixture.continued(&input, 10, Some(&captured))?;
    let prior = captured.prior(10).ok_or("prior absent")?;
    assert!(prior
        .state(
            &fixture.model,
            &evaluation.inputs,
            evaluation.parameters.as_ref(),
            false
        )?
        .0
        .is_some());
    let mut version = prior.clone();
    version
        .checkpoint
        .as_mut()
        .ok_or("checkpoint absent")?
        .version += 1;
    let mut dataset = prior.clone();
    dataset
        .checkpoint
        .as_mut()
        .ok_or("checkpoint absent")?
        .datasets[0]
        .name = "unknown-state".into();
    let mut schema = prior.clone();
    schema
        .checkpoint
        .as_mut()
        .ok_or("checkpoint absent")?
        .datasets[0]
        .batches = vec![StorageFixture::batch(
        &sdk::Schema::new(vec![sdk::Field::new("other", sdk::DataType::UInt64, false)]),
        12,
    )?];
    for incompatible in [version, dataset, schema] {
        assert!(incompatible
            .state(
                &fixture.model,
                &evaluation.inputs,
                evaluation.parameters.as_ref(),
                false
            )?
            .0
            .is_none());
    }
    let mut changed = evaluation.inputs.clone();
    changed[0].revision.id.push_str("-changed");
    assert!(prior
        .state(
            &fixture.model,
            &changed,
            evaluation.parameters.as_ref(),
            false
        )?
        .0
        .is_none());
    let mut changed = evaluation.inputs.clone();
    changed[0].coverage.state = sdk::CoverageState::Gapped;
    assert!(prior
        .state(
            &fixture.model,
            &changed,
            evaluation.parameters.as_ref(),
            false
        )?
        .0
        .is_none());
    let parameters = StorageFixture::batch(&fixture.model.parameters, 99)?;
    assert!(prior
        .state(&fixture.model, &evaluation.inputs, Some(&parameters), false)?
        .0
        .is_none());
    assert!(prior
        .state(
            &fixture.model,
            &evaluation.inputs,
            evaluation.parameters.as_ref(),
            true
        )?
        .0
        .is_none());
    let mut changed = input.clone();
    changed.seed = Some(9);
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    assert!(store
        .register_managed_attempt(&captured, &changed, || Ok(()))
        .is_err());
    let recovered = store
        .managed_attempt(
            [1; 16],
            "counter",
            &input.id,
            &AnalysisReadControl::default(),
        )?
        .ok_or("pending attempt absent")?;
    let eval = [
        fixture.continued(&input, 10, Some(&captured))?,
        fixture.continued(&input, 11, Some(&captured))?,
    ];
    assert!(fixture
        .publish(&store, &recovered, &eval, &outputs, || Ok(()))
        .is_err());
    let before = store.meta()?;
    for coverage in [false, true] {
        let mut changed = eval.clone();
        assert!(changed[0].checkpoint.is_some());
        if coverage {
            changed[0].inputs[0].coverage.state = sdk::CoverageState::Gapped;
        } else {
            changed[0].inputs[0].revision.id.push_str("-changed");
        }
        let error = fixture
            .publish(&store, &attempt, &changed, &outputs, || Ok(()))
            .err()
            .ok_or("changed inputs reused captured state")?;
        assert!(matches!(
            error,
            araphor_data::Error::Package {
                code: araphor_data::PackageErrorCodeV1::Conflict,
                field: "managed captured checkpoint",
                ..
            }
        ));
        assert_eq!(store.meta()?, before);
    }
    fixture.publish(&store, &attempt, &eval, &outputs, || Ok(()))?;
    Ok(())
}

#[test]
fn managed_failure_is_atomic() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(directory.path().join("store"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let captured = fixture.capture(&store)?;
    let input = request("atomic");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let evaluations = [
        fixture.evaluation(&input, 10)?,
        fixture.evaluation(&input, 11)?,
    ];
    let mut outputs = [
        fixture.output(2, "exact context")?,
        fixture.output(3, "exact context")?,
    ];
    let before = store.meta()?;
    let mut changed = evaluations.clone();
    changed[0].context.time_utc_ns += 1;
    let error = fixture
        .publish(&store, &attempt, &changed, &outputs, || Ok(()))
        .err()
        .ok_or("wrong evaluation time was published")?;
    assert!(matches!(
        error,
        Error::Package {
            code: Code::Invalid,
            field: "managed evaluation request",
            ..
        }
    ));
    assert_eq!(store.meta()?, before);
    outputs[1].evidence[0].input.row = 1;
    assert!(fixture
        .publish(&store, &attempt, &evaluations, &outputs, || Ok(()))
        .is_err());
    assert_eq!(store.meta()?, before);
    let state = fixture.capture(&store)?;
    assert!(state.prior(10).is_none());
    assert!(state.prior(11).is_none());
    assert!(records(store.view()?.as_ref(), b"\0data/X")?.is_empty());
    assert!(records(store.view()?.as_ref(), b"\0data/U")?.is_empty());
    outputs[1].evidence[0].input.row = 0;
    let mut checked = 0;
    assert!(matches!(
        fixture.publish(&store, &attempt, &evaluations, &outputs, || {
            checked += 1;
            Err(Error::AnalysisReadDenied {
                location: snafu::location!(),
            })
        }),
        Err(Error::AnalysisReadDenied { .. })
    ));
    assert_eq!(checked, 1);
    assert_eq!(store.meta()?, before);
    let receipt = fixture.publish(&store, &attempt, &evaluations, &outputs, || {
        checked += 1;
        Ok(())
    })?;
    assert_eq!(checked, 2);
    let after = store.meta()?;
    assert!(fixture
        .publish(&store, &attempt, &evaluations, &outputs, || {
            checked += 1;
            Err(Error::AnalysisReadDenied {
                location: snafu::location!(),
            })
        })
        .is_err());
    assert_eq!(checked, 2);
    assert_eq!(store.meta()?, after);
    assert!(matches!(
        fixture.publish(&store, &attempt, &evaluations, &outputs, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(
        store
            .managed_attempt(
                [1; 16],
                "counter",
                "atomic",
                &AnalysisReadControl::default()
            )?
            .and_then(|attempt| attempt.receipt().cloned()),
        Some(receipt)
    );
    let mut conflicting = outputs.clone();
    conflicting[1] = fixture.output(99, "exact context")?;
    assert!(matches!(
        fixture.publish(&store, &attempt, &evaluations, &conflicting, || Ok(())),
        Err(Error::AnalysisConflict { .. })
    ));
    assert_eq!(store.meta()?, after);
    Ok(())
}
