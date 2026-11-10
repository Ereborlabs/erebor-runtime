use super::*;
use araphor_data::analysis::native::{ManagedCommit, ManagedReturn};
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisTableRead, AnalysisTableRequests,
    ManagedRead, ManagedReceipt, ValidatedCoverageV1,
};

fn requests() -> AnalysisTableRequests {
    ["events", "context_versions"]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                Some(
                    (0..araphor_data::AnalysisStore::table_schemas()[name]
                        .fields()
                        .len())
                        .collect(),
                ),
            )
        })
        .collect()
}

fn publish(
    store: &NativeStore,
    instance: &ManagedInstance,
    name: &str,
    requests: &AnalysisTableRequests,
) -> Result<ManagedReceipt, Box<dyn std::error::Error>> {
    let control = AnalysisReadControl::default();
    let resume = store.managed_resume(instance.spec.tenant, &instance.spec.id, &control)?;
    let selection = instance.grant.selection.project(requests)?;
    let page = store.read_managed_tables_filtered(
        &selection,
        &ManagedRead {
            instance: resume.instance,
            expected: None,
            rebuild: false,
            follow: false,
            completed: Some(resume.completed),
            execution: None,
            source: None,
        },
        AnalysisTableRead {
            requests,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::attempts::request(name, true),
        || Ok(()),
    )?;
    let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
    let model = sdk::Model::new("count", Vec::new(), vec![sdk::Port::new("rows", schema)]);
    let evaluation = super::publication::evaluation(&attempt);
    let output = super::publication::output(&model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
        retained: None,
    }];
    let budget = super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    Ok(store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?)
}

#[test]
fn native_result_metadata_and_replay_keep_the_captured_view() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut fixture = Fixture::new(&store, [1; 16], "reads", false)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let admitted = fixture.admit(&store)?;
    let instance =
        store.set_managed_running([1; 16], "reads", admitted.lifecycle, true, || Ok(()))?;
    super::attempts::append(&store, 1)?;
    let first = publish(&store, &instance, "first", &requests())?;
    let held = store.view()?;
    let control = AnalysisReadControl::default();
    let first_call = &first.results[&10].result_id;
    assert!(
        store
            .managed_result(&instance, first_call, 1000, &control)?
            .current
    );
    let (reference, call, current) =
        store.managed_reference(&instance, &first.selected.result_id, 1000, &control)?;
    assert_eq!(call, None);
    assert!(current);
    super::attempts::append(&store, 2)?;
    assert!(
        !store
            .managed_result(&instance, first_call, 1000, &control)?
            .current
    );
    assert!(
        store
            .managed_result_at(&held, &instance, first_call, 1000, &control)?
            .current
    );
    assert!(
        store
            .managed_result_at(
                &store.read_at(held.revision())?,
                &instance,
                first_call,
                1000,
                &control
            )?
            .current
    );
    let second = publish(&store, &instance, "second", &requests())?;
    assert!(
        !store
            .managed_result(&instance, &first.selected.result_id, 1000, &control)?
            .current
    );
    assert!(
        store
            .managed_result(&instance, &second.selected.result_id, 1000, &control)?
            .current
    );
    assert!(
        store
            .managed_result_at(&held, &instance, &first.selected.result_id, 1000, &control)?
            .current
    );
    let tables = requests();
    let selection = instance.grant.selection.project(&tables)?;
    let page = store.read_managed_reference(
        &selection,
        &reference,
        AnalysisTableRead {
            requests: &tables,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert_eq!(page.page.extraction.meta, reference.source_meta());
    assert_eq!(
        page.page.tables["events"]
            .iter()
            .map(sdk::RecordBatch::num_rows)
            .sum::<usize>(),
        1
    );
    assert!(page.state.prior(10).is_none());
    assert!(page.state.source().is_some());
    let metadata = AnalysisTableRequests::new();
    let page = store.read_managed_reference(
        &AnalysisSelectionV1::new([1; 16], Vec::new()),
        &reference,
        AnalysisTableRead {
            requests: &metadata,
            mode: AnalysisReadModeV1::Metadata,
            now: 1001,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &control,
        None,
    )?;
    assert!(page.state.source().is_none());
    drop((page, held));
    drop(store);
    let store = NativeStore::open(&root)?;
    assert!(
        store
            .managed_result_at(
                &store.read_at(first.commit_revision)?,
                &instance,
                first_call,
                1000,
                &control
            )?
            .current
    );
    assert!(
        !store
            .managed_result(&instance, first_call, 1000, &control)?
            .current
    );
    assert!(
        store
            .managed_result(&instance, &second.selected.result_id, 1000, &control)?
            .current
    );
    Ok(())
}

#[test]
fn native_binding_freshness_keeps_original_births_after_reopen() -> TestResult {
    for coverage_first in [false, true] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let mut fixture = Fixture::new(&store, [1; 16], "binding", false)?;
        fixture.grant.selection.nodes = vec!["node-a".into()];
        let instance = fixture.admit(&store)?;
        let instance =
            store.set_managed_running([1; 16], "binding", instance.lifecycle, true, || Ok(()))?;
        if coverage_first {
            store.accept_validated_coverage(ValidatedCoverageV1 {
                identity: araphor_data::EvidenceIntakeIdentityV1 {
                    tenant_id: [1; 16],
                    node_id: "node-a".into(),
                    node_boot_id: [2; 16],
                    label_epoch: 1,
                    source_id: [3; 16],
                    source_epoch: 1,
                },
                cpu_id: 0,
                revision: 1,
                encoded_report: vec![1],
            })?;
        }
        let receipt = publish(&store, &instance, "birth", &AnalysisTableRequests::new())?;
        super::attempts::append(&store, 1)?;
        let raw = store.view()?;
        let cut = raw.revision();
        let control = AnalysisReadControl::default();
        assert_eq!(
            store
                .managed_result_at(
                    &raw,
                    &instance,
                    &receipt.results[&10].result_id,
                    1000,
                    &control
                )?
                .current,
            coverage_first
        );
        let mut tx = store.write()?;
        tx.native().insert(b"ordinary", [1u8]);
        tx.commit([])?;
        drop(raw);
        drop(store);
        let store = NativeStore::open(&root)?;
        assert_eq!(
            store
                .managed_result_at(
                    &store.read_at(cut)?,
                    &instance,
                    &receipt.results[&10].result_id,
                    1000,
                    &control
                )?
                .current,
            coverage_first
        );
    }
    Ok(())
}

#[test]
fn native_metadata_skips_checkpoints_and_checks_scope_before_integrity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let mut fixture = Fixture::new(&store, [1; 16], "metadata", false)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    let instance = fixture.admit(&store)?;
    let instance =
        store.set_managed_running([1; 16], "metadata", instance.lifecycle, true, || Ok(()))?;
    let receipt = publish(&store, &instance, "metadata", &requests())?;
    let control = AnalysisReadControl::default();
    let (key, _) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/U")
        .next()
        .ok_or("checkpoint")??;
    let mut tx = store.write()?;
    tx.native().insert(key, [255u8]);
    tx.commit([])?;
    assert!(
        store
            .managed_result(&instance, &receipt.results[&10].result_id, 1000, &control)?
            .current
    );
    assert!(
        store
            .managed_result(&instance, &receipt.selected.result_id, 1000, &control)?
            .current
    );
    let view = store.view()?;
    let mut changed = false;
    for row in view.snapshot().prefix(b"\0data/X") {
        let (key, bytes) = row?;
        if key.len() != 15 {
            continue;
        }
        let serde_value::Value::Map(mut value) = rmp_serde::from_slice(&bytes[1..])? else {
            return Err("result map".into());
        };
        if value.get(&serde_value::Value::String("id".into()))
            != Some(&serde_value::Value::String(
                receipt.selected.result_id.clone(),
            ))
        {
            continue;
        }
        value.insert(
            serde_value::Value::String("revision".into()),
            serde_value::Value::U64(0),
        );
        let mut encoded = vec![0];
        encoded.extend(rmp_serde::to_vec_named(&serde_value::Value::Map(value))?);
        let mut tx = store.write()?;
        tx.native().insert(key, encoded);
        tx.commit([])?;
        changed = true;
        break;
    }
    assert!(changed);
    let mut narrow = instance.clone();
    narrow.grant.selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    assert!(matches!(
        store.managed_result(&narrow, &receipt.selected.result_id, 1000, &control),
        Err(Error::Package {
            code: Code::Denied,
            ..
        })
    ));
    assert!(matches!(
        store.managed_result(&instance, &receipt.selected.result_id, 1000, &control),
        Err(Error::Package {
            code: Code::Invalid,
            ..
        })
    ));
    let other = NativeStore::open(&directory.path().join("other"))?;
    assert!(matches!(
        other.managed_result_at(
            &view,
            &instance,
            &receipt.selected.result_id,
            1000,
            &control
        ),
        Err(Error::Package {
            code: Code::Conflict,
            ..
        })
    ));
    control.cancel()?;
    assert!(matches!(
        store.managed_reference(&instance, &receipt.selected.result_id, 1000, &control),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    Ok(())
}
