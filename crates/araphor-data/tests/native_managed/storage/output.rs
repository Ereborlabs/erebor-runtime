use super::*;
use serde_value::Value;

impl StorageFixture {
    fn selected_receipt(
        &self,
        store: &NativeStore,
        id: &str,
        value: u64,
    ) -> Result<ManagedReceipt, Box<dyn std::error::Error>> {
        let captured = self.capture(store)?;
        let input = request(id);
        let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
        self.publish(
            store,
            &attempt,
            &[
                self.continued(&input, 10, Some(&captured))?,
                self.continued(&input, 11, Some(&captured))?,
            ],
            &[
                self.output(value, "exact context")?,
                self.output(value + 1, "exact context")?,
            ],
            || Ok(()),
        )
        .map_err(Into::into)
    }
}

fn result_record(
    view: &DataView,
    name: &str,
) -> Result<(Vec<u8>, Vec<u8>), Box<dyn std::error::Error>> {
    #[derive(serde::Deserialize)]
    struct Header {
        id: String,
    }
    for (key, bytes) in records(view, b"\0data/X")? {
        assert_eq!(key.len(), 15);
        assert_eq!(bytes.first(), Some(&0));
        let header: Header = rmp_serde::from_slice(&bytes[1..])?;
        if header.id == name {
            return Ok((key, bytes));
        }
    }
    Err("result record".into())
}

fn dependency_records(
    view: &DataView,
    receipt: &ManagedReceipt,
) -> Result<BTreeMap<Vec<u8>, Vec<u8>>, Box<dyn std::error::Error>> {
    let (selected, _) = result_record(view, &receipt.selected.result_id)?;
    receipt
        .results
        .values()
        .map(|reference| {
            let (call, _) = result_record(view, &reference.result_id)?;
            Ok((
                [
                    b"\0data/ref/dependency/".as_slice(),
                    &selected[7..],
                    &call[7..],
                ]
                .concat(),
                reference.commit_revision.to_be_bytes().to_vec(),
            ))
        })
        .collect()
}

#[test]
fn selected_rejects_call_swap() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let receipt = fixture.selected_receipt(&store, "swapped-calls", 2)?;
    let current = fixture.current(&store)?;
    let control = AnalysisReadControl::default();
    assert!(matches!(
        store
            .managed_result(&current, &receipt.selected.result_id, 10, &control)?
            .kind,
        araphor_data::InstanceResultKindV1::Selected
    ));
    let view = store.view()?;
    let dependencies = records(&view, b"\0data/ref/dependency/")?;
    assert_eq!(dependencies.len(), 2);
    assert_eq!(dependencies, dependency_records(&view, &receipt)?);
    let (key, bytes) = super::terminal::attempt_record(&view, "swapped-calls")?;
    let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
    let mut swapped = receipt.clone();
    let first = swapped.results.remove(&10).ok_or("first call")?;
    let second = swapped.results.remove(&11).ok_or("second call")?;
    assert_ne!(first.result_id, second.result_id);
    swapped.results.insert(10, second);
    swapped.results.insert(11, first);
    assert_eq!(
        swapped.results.keys().collect::<Vec<_>>(),
        receipt.results.keys().collect::<Vec<_>>()
    );
    let references = |receipt: &ManagedReceipt| {
        receipt
            .results
            .values()
            .map(|reference| (reference.result_id.clone(), reference.commit_revision))
            .collect::<BTreeMap<_, _>>()
    };
    assert_eq!(references(&swapped), references(&receipt));
    *super::super::attempts::field(&mut saved, &["receipt"])? = serde_value::to_value(swapped)?;
    let mut tx = store.write()?;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec(&saved)?].concat());
    tx.commit([])?;
    assert_eq!(
        records(store.view()?.as_ref(), b"\0data/ref/dependency/")?,
        dependencies
    );
    let before = store.view()?;
    let result = store.managed_result(&current, &receipt.selected.result_id, 10, &control);
    assert!(result.is_err(), "accepted swapped call bindings");
    assert!(matches!(
        result,
        Err(Error::Package {
            code: Code::Invalid,
            field: "managed selected call binding",
            ..
        })
    ));
    assert_eq!(store.view()?.meta(), before.meta());
    assert_eq!(
        records(store.view()?.as_ref(), b"\0data/")?,
        records(&before, b"\0data/")?
    );
    drop((before, view));
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

#[test]
fn selected_edges_reject_corruption() -> TestResult {
    for fault in ["missing", "revision", "replacement", "extra"] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = StorageFixture::new(&store, "counter", String::new())?;
        let first = fixture.selected_receipt(&store, "first", 2)?;
        let second = fixture.selected_receipt(&store, "second", 2)?;
        let current = fixture.current(&store)?;
        let control = AnalysisReadControl::default();
        let original = &first.results[&10];
        let replacement = &second.results[&10];
        assert_ne!(original.result_id, replacement.result_id);
        assert_ne!(original.commit_revision, replacement.commit_revision);
        let call = store.managed_result(&current, &original.result_id, 10, &control)?;
        assert!(!call.current);
        assert_eq!(&call.result, original);
        let selected = store.managed_result(&current, &first.selected.result_id, 10, &control)?;
        assert_eq!(selected.result, first.selected);
        assert_eq!(selected.receipt, first);
        let view = store.view()?;
        let (selected_key, _) = result_record(&view, &first.selected.result_id)?;
        let (original_key, _) = result_record(&view, &original.result_id)?;
        let (replacement_key, _) = result_record(&view, &replacement.result_id)?;
        let prefix = [b"\0data/ref/dependency/".as_slice(), &selected_key[7..]].concat();
        let key = [prefix.as_slice(), &original_key[7..]].concat();
        let replacement_key = [prefix.as_slice(), &replacement_key[7..]].concat();
        assert_eq!(records(&view, &prefix)?.len(), 2);
        assert_eq!(records(&view, &prefix)?, dependency_records(&view, &first)?);
        assert_eq!(
            view.snapshot().get(&key)?.ok_or("original edge")?.as_ref(),
            original.commit_revision.to_be_bytes()
        );
        let mut tx = store.write()?;
        match fault {
            "missing" => tx.native().remove(&key),
            "revision" => tx
                .native()
                .insert(&key, replacement.commit_revision.to_be_bytes()),
            "replacement" => {
                tx.native().remove(&key);
                tx.native()
                    .insert(&replacement_key, replacement.commit_revision.to_be_bytes());
            }
            "extra" => tx
                .native()
                .insert(&replacement_key, replacement.commit_revision.to_be_bytes()),
            _ => unreachable!(),
        }
        tx.commit([])?;
        let expected = match fault {
            "missing" => 1,
            "extra" => 3,
            _ => 2,
        };
        let before = store.view()?;
        assert_eq!(records(&before, &prefix)?.len(), expected);
        if matches!(fault, "replacement" | "extra") {
            assert_eq!(
                before
                    .snapshot()
                    .get(&replacement_key)?
                    .ok_or("valid replacement edge")?
                    .as_ref(),
                replacement.commit_revision.to_be_bytes()
            );
            assert_eq!(
                store
                    .managed_result(&current, &replacement.result_id, 10, &control)?
                    .result,
                *replacement
            );
        }
        let result = store.managed_result(&current, &first.selected.result_id, 10, &control);
        assert!(
            result.is_err(),
            "{fault}: accepted changed dependency records"
        );
        assert!(
            matches!(
                result,
                Err(Error::Package {
                    code: Code::Invalid,
                    field: "managed selected edges",
                    ..
                })
            ),
            "{fault}"
        );
        let retained = store.managed_result(&current, &original.result_id, 10, &control)?;
        assert_eq!(
            serde_json::to_value(&retained)?,
            serde_json::to_value(&call)?
        );
        assert_eq!(store.view()?.meta(), before.meta());
        assert_eq!(
            records(store.view()?.as_ref(), b"\0data/")?,
            records(&before, b"\0data/")?
        );
        drop((before, view));
        drop(store);
        let error = NativeStore::open(&root)
            .err()
            .ok_or("accepted damaged dependency index")?;
        let expected = if fault == "missing" {
            Code::Missing
        } else {
            Code::Invalid
        };
        assert!(
            matches!(error, Error::Package {code, field: "managed result reference index", ..} if code == expected),
            "{fault}: {error:?}"
        );
    }
    Ok(())
}

#[test]
fn call_reference_keeps_pin() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let first = fixture.selected_receipt(&store, "first", 2)?;
    fixture.selected_receipt(&store, "second", 2)?;
    let control = AnalysisReadControl::default();
    let current = fixture.current(&store)?;
    let before = store.view()?;
    for (call, reference) in &first.results {
        let result = store.managed_result(&current, &reference.result_id, 10, &control)?;
        let araphor_data::InstanceResultKindV1::Call {
            image,
            package,
            export,
            context,
            call: id,
        } = &result.kind
        else {
            return Err("call reference kind".into());
        };
        assert_eq!(id, call);
        assert_eq!(result.instance_id, current.spec.id);
        assert_eq!(&result.result, reference);
        assert_eq!(result.receipt, first);
        assert_eq!(image, &current.spec.manifest.calls[call].image);
        assert_eq!(package, &current.spec.manifest.calls[call].package);
        assert_eq!(export, "count");
        assert_eq!(context.target, "sql");
        assert_eq!(context.artifact, None);
        assert_eq!(context.context.id, "first");
        assert_eq!(
            result.definition_revision,
            current.spec.manifest.definition.to_string()
        );
        assert_eq!(result.generation, current.generation);
        assert_eq!(result.source.store_uuid, before.meta().store_uuid);
        assert!(result.source.commit_revision < result.result.commit_revision);
        assert!(!result.current);
        let cancelled = AnalysisReadControl::default();
        cancelled.cancel()?;
        assert!(matches!(
            store.managed_result(&current, &reference.result_id, 10, &cancelled),
            Err(Error::AnalysisReadCancelled { .. })
        ));
    }
    assert_eq!(store.view()?.meta(), before.meta());
    assert_eq!(
        records(store.view()?.as_ref(), b"\0data/")?,
        records(&before, b"\0data/")?
    );
    Ok(())
}

#[test]
fn selected_reference_keeps_receipt() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let receipt = fixture.selected_receipt(&store, "original", 2)?;
    fixture.selected_receipt(&store, "later", 2)?;
    let current = fixture.current(&store)?;
    let control = AnalysisReadControl::default();
    let before = store.view()?;
    let result = store.managed_result(&current, &receipt.selected.result_id, 10, &control)?;
    assert_eq!(result.result, receipt.selected);
    assert_eq!(result.receipt, receipt);
    assert!(matches!(
        result.kind,
        araphor_data::InstanceResultKindV1::Selected
    ));
    assert_eq!(StorageFixture::rows(&store, &receipt.selected)?, 1);
    assert!(!result.current);
    assert!(store
        .managed_result(&current, "missing", 10, &control)
        .is_err());
    assert_eq!(store.view()?.meta(), before.meta());
    assert_eq!(
        records(store.view()?.as_ref(), b"\0data/")?,
        records(&before, b"\0data/")?
    );
    Ok(())
}

#[test]
fn selected_scope_precedes_integrity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new_scope(
        &store,
        "counter",
        String::new(),
        AnalysisSelectionV1::tenant([1; 16]),
    )?;
    let receipt = fixture.selected_receipt(&store, "scoped", 2)?;
    let control = AnalysisReadControl::default();
    let mut current = fixture.current(&store)?;
    let (key, bytes) = result_record(store.view()?.as_ref(), &receipt.selected.result_id)?;
    let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
    *super::super::attempts::field(&mut saved, &["revision"])? =
        Value::U64(receipt.commit_revision + 1);
    let mut tx = store.write()?;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec(&saved)?].concat());
    tx.commit([])?;
    let before = store.view()?;
    current.grant.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    assert!(matches!(
        store.managed_result(&current, &receipt.selected.result_id, 10, &control),
        Err(Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    current.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    assert!(store
        .managed_result(&current, &receipt.selected.result_id, 10, &control)
        .is_err());
    assert_eq!(store.view()?.meta(), before.meta());
    assert_eq!(
        records(store.view()?.as_ref(), b"\0data/")?,
        records(&before, b"\0data/")?
    );
    Ok(())
}

#[test]
fn selected_rejects_corruption() -> TestResult {
    for fault in [
        "revision",
        "instance",
        "attempt",
        "receipt",
        "generation",
        "edges",
        "call",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = StorageFixture::new(&store, "counter", String::new())?;
        let receipt = fixture.selected_receipt(&store, "corrupt", 2)?;
        let control = AnalysisReadControl::default();
        let current = fixture.current(&store)?;
        let field = super::super::attempts::field;
        let mut tx = store.write()?;
        match fault {
            "revision" | "instance" | "attempt" => {
                let (key, bytes) =
                    result_record(store.view()?.as_ref(), &receipt.selected.result_id)?;
                let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
                if fault == "revision" {
                    *field(&mut saved, &["revision"])? = Value::U64(receipt.commit_revision + 1);
                } else {
                    *field(&mut saved, &["body", "Selected", fault])? =
                        Value::String("foreign".into());
                }
                tx.native()
                    .insert(key, [vec![0], rmp_serde::to_vec(&saved)?].concat());
            }
            "edges" => {
                let dependencies = records(store.view()?.as_ref(), b"\0data/ref/dependency/")?;
                assert_eq!(dependencies.len(), 2);
                for key in dependencies.keys() {
                    tx.native().remove(key);
                }
            }
            _ => {
                let (key, bytes) =
                    super::terminal::attempt_record(store.view()?.as_ref(), "corrupt")?;
                let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
                if fault == "generation" {
                    *field(&mut saved, &["capture", "generation"])? =
                        Value::U64(current.generation + 1);
                } else {
                    let mut changed = receipt.clone();
                    if fault == "receipt" {
                        changed.selected.commit_revision += 1;
                    } else {
                        let reference = changed.results.remove(&10).ok_or("call")?;
                        changed.results.insert(99, reference);
                    }
                    *field(&mut saved, &["receipt"])? = serde_value::to_value(changed)?;
                }
                tx.native()
                    .insert(key, [vec![0], rmp_serde::to_vec(&saved)?].concat());
            }
        }
        tx.commit([])?;
        let before = store.view()?;
        assert!(
            store
                .managed_result(&current, &receipt.selected.result_id, 10, &control)
                .is_err(),
            "{fault}"
        );
        assert_eq!(store.view()?.meta(), before.meta());
        assert_eq!(
            records(store.view()?.as_ref(), b"\0data/")?,
            records(&before, b"\0data/")?
        );
        drop(before);
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "{fault}");
    }
    Ok(())
}

#[test]
fn selected_uses_saved_schema() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let original = fixture.selected_receipt(&store, "original-schema", 2)?;
    let current = fixture.current(&store)?;
    let mut spec = current.spec.clone();
    spec.definition.definition.description = "Change the selected schema.".into();
    spec.manifest.definition = store.admit_definition([1; 16], &spec.definition, || Ok(()))?;
    let schema = sdk::Schema::new(vec![sdk::Field::new(
        "changed",
        sdk::DataType::UInt64,
        false,
    )]);
    spec.manifest.selected_schema = schema.clone();
    let target = store.prepare_managed_version(&current, &spec, || Ok(()))?;
    let captured = super::terminal::capture_target(&store, &current, &target)?;
    let input = request("changed-schema");
    let attempt = store.register_managed_attempt(&captured, &input, || Ok(()))?;
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: vec![StorageFixture::batch(&schema, 5)?],
    };
    let control = AnalysisReadControl::default();
    let commit = ManagedCommit {
        control: &control,
        budget: &super::super::graph::Budget,
        completed: true,
        attempt: &attempt,
        now_utc_ns: 10,
        returns: &[],
        selected: &selected,
        selected_schema: &current.spec.manifest.selected_schema,
    };
    assert!(matches!(
        store.prepare_managed(&commit),
        Err(Error::Package {
            code: Code::Invalid,
            field: "managed selected schema",
            ..
        })
    ));
    let commit = ManagedCommit {
        selected_schema: &schema,
        ..commit
    };
    let changed = store.commit_managed(store.prepare_managed(&commit)?, || Ok(()))?;
    let current = fixture.current(&store)?;
    assert_eq!(current.generation, target.generation);
    for (reference, expected) in [
        (&original.selected, &fixture.model.outputs[0].schema),
        (&changed.selected, &schema),
    ] {
        let result = store.managed_result(&current, &reference.result_id, 10, &control)?;
        let version = store.managed_version([1; 16], "counter", result.generation, &control)?;
        assert_eq!(&version.manifest.selected_schema, expected);
        assert_eq!(&result.result, reference);
        assert_eq!(
            result.definition_revision,
            version.manifest.definition.to_string()
        );
    }
    Ok(())
}

#[test]
fn successful_receipt_keeps_head() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let fixture = StorageFixture::new(&store, "counter", String::new())?;
    let control = AnalysisReadControl::default();
    let selection = &fixture.instance.grant.selection;
    assert!(StorageFixture::receipt(&store, [1; 16], "counter", "first", &control)?.is_none());
    let mut receipts = Vec::new();
    for (id, value) in [("first", 2), ("later", 7)] {
        let receipt = fixture.selected_receipt(&store, id, value)?;
        let current = fixture.current(&store)?;
        let before = store.view()?;
        let result = store.managed_result(&current, &receipt.selected.result_id, 10, &control)?;
        assert_eq!(result.result, receipt.selected);
        assert_eq!(result.receipt, receipt);
        assert_eq!(StorageFixture::rows(&store, &receipt.selected)?, 1);
        assert_eq!(
            fixture.checkpoint(&store, &receipt.results[&10])?.datasets[0].batches,
            fixture
                .output(value, "exact context")?
                .checkpoint
                .ok_or("state")?
                .datasets[0]
                .batches
        );
        assert!(matches!(
            store.managed_result(&current, "", 10, &control),
            Err(Error::Package {
                code: Code::Missing,
                ..
            })
        ));
        assert_eq!(store.view()?.meta(), before.meta());
        assert_eq!(
            records(store.view()?.as_ref(), b"\0data/")?,
            records(&before, b"\0data/")?
        );
        receipts.push(receipt);
    }
    let captured = fixture.capture(&store)?;
    let failed = store.register_managed_attempt(&captured, &request("failed"), || Ok(()))?;
    store.finish_managed(
        &failed,
        araphor_data::ManagedExit::Failed(Code::Incomplete),
        || Ok(()),
    )?;
    let status = store.managed_status(selection, "counter", &control)?;
    assert_eq!(status.status_progress, receipts[1].commit_revision);
    assert!(matches!(
        status.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Incomplete,
            ..
        }
    ));
    let before = store.view()?;
    let result = store.managed_result(
        &status.instance,
        &receipts[1].selected.result_id,
        10,
        &control,
    )?;
    assert_eq!(result.receipt, receipts[1]);
    assert_eq!(
        StorageFixture::receipt(&store, [1; 16], "counter", "later", &control)?,
        Some(receipts[1].clone())
    );
    assert!(StorageFixture::receipt(&store, [1; 16], "counter", "failed", &control)?.is_none());
    let retained = store.managed_status(selection, "counter", &control)?;
    assert_eq!(retained.instance, status.instance);
    assert_eq!(retained.status_progress, status.status_progress);
    assert!(matches!(
        retained.readiness,
        araphor_data::PackageReadinessV1::Failed {
            code: Code::Incomplete,
            ..
        }
    ));
    assert_eq!(store.view()?.meta(), before.meta());
    let cancelled = AnalysisReadControl::default();
    cancelled.cancel()?;
    assert!(matches!(
        store.managed_result(
            &status.instance,
            &receipts[1].selected.result_id,
            10,
            &cancelled
        ),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    let (key, bytes) = super::terminal::attempt_record(&before, "later")?;
    let mut saved: Value = rmp_serde::from_slice(&bytes[1..])?;
    let mut changed = receipts[1].clone();
    changed.selected.result_id = receipts[0].selected.result_id.clone();
    *super::super::attempts::field(&mut saved, &["receipt"])? = serde_value::to_value(changed)?;
    let mut tx = store.write()?;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec(&saved)?].concat());
    tx.commit([])?;
    let before = store.view()?;
    assert!(matches!(
        store.managed_result(
            &status.instance,
            &receipts[1].selected.result_id,
            10,
            &control
        ),
        Err(Error::Package {
            code: Code::Invalid,
            ..
        })
    ));
    assert_eq!(store.view()?.meta(), before.meta());
    assert_eq!(
        records(store.view()?.as_ref(), b"\0data/")?,
        records(&before, b"\0data/")?
    );
    Ok(())
}
