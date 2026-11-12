use super::*;
use araphor_data::AnalysisTableRequests;
use serde_value::Value;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

fn inventory(store: &NativeStore, prefix: &[u8]) -> TestResult<BTreeMap<Vec<u8>, Vec<u8>>> {
    store
        .view()?
        .snapshot()
        .prefix(prefix)
        .map(|entry| {
            let (key, value) = entry?;
            Ok((key.to_vec(), value.to_vec()))
        })
        .collect()
}

fn result_record(store: &NativeStore, name: &str) -> TestResult<(Vec<u8>, Vec<u8>)> {
    #[derive(serde::Deserialize)]
    struct Header {
        id: String,
    }
    for (key, bytes) in inventory(store, b"\0data/X")? {
        assert_eq!(key.len(), 15);
        assert_eq!(bytes.first(), Some(&0));
        let header: Header = rmp_serde::from_slice(&bytes[1..])?;
        if header.id == name {
            return Ok((key, bytes));
        }
    }
    Err("selected result".into())
}

fn attempt_record(store: &NativeStore, name: &str) -> TestResult<(Vec<u8>, Vec<u8>)> {
    #[derive(serde::Deserialize)]
    struct Header {
        request: araphor_data::ManagedRequest,
    }
    for (key, bytes) in inventory(store, b"\0data/a")? {
        assert_eq!(key.len(), 15);
        assert_eq!(bytes.first(), Some(&0));
        let header: Header = rmp_serde::from_slice(&bytes[1..])?;
        if header.request.id == name {
            return Ok((key, bytes));
        }
    }
    Err("Source attempt".into())
}

#[test]
fn graph_empty_step_has_no_publication() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    let control = AnalysisReadControl::default();
    let resume = store.managed_resume([1; 16], "source", &control)?;
    let page = follow(&store, &resume, &Arc::default())?;
    assert!(page.state.follows_graph());
    let mut input = super::super::attempts::request("empty-follow", true);
    input.frontier.as_mut().ok_or("frontier")?.cursor = vec![1];
    let attempt = store.register_managed_attempt(&page.state, &input, || Ok(()))?;
    let mut selection = instance.grant.selection.clone();
    selection.select_graphs(araphor_data::Selection::All, None)?;
    let requests = AnalysisTableRequests::from([
        ("events".into(), None),
        ("graph_manifest".into(), None),
        ("graph_state".into(), None),
    ]);
    let before = store.view()?;
    let raw = store.source_receipt(&identity())?;
    let source = inventory(&store, b"\0data/@source/")?;
    let graph = inventory(&store, b"\0data/graph/publication/")?;
    let budget = super::super::graph::Budget;
    let inputs =
        store.subscribe_inputs_at(&before, &selection, &requests, None, &control, &budget)?;
    let position = inputs.position();
    let selected = sdk::Dataset {
        name: "selected".into(),
        batches: Vec::new(),
    };
    let commit = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: input.time_utc_ns,
        returns: &[],
        selected: &selected,
        selected_schema: &instance.spec.manifest.selected_schema,
    };
    let (receipt, progress) =
        store.commit_managed_graph(store.prepare_managed(&commit)?, || Ok(()))?;
    assert!(receipt.results.is_empty());
    assert!(receipt.graph.is_none());
    assert!(progress.is_none());
    assert!(store.meta()?.commit_revision > before.revision());
    assert_eq!(store.source_receipt(&identity())?, raw);
    assert_eq!(inventory(&store, b"\0data/@source/")?, source);
    assert_eq!(inventory(&store, b"\0data/graph/publication/")?, graph);
    assert!(store.processor_result(&scope())?.is_none());
    assert!(store.graph_window_headers(&identity(), None)?.is_empty());
    let replay =
        store.subscribe_inputs_at(&before, &selection, &requests, None, &control, &budget)?;
    assert_eq!(inputs.position(), position);
    assert_eq!(replay.position(), position);
    let current = store.managed_resume([1; 16], "source", &control)?.instance;
    assert!(matches!(
        store
            .managed_result(&current, &receipt.selected.result_id, 1000, &control)?
            .kind,
        araphor_data::InstanceResultKindV1::Selected
    ));
    let (key, bytes) = result_record(&store, &receipt.selected.result_id)?;
    let mut record: Value = rmp_serde::from_slice(&bytes[1..])?;
    *super::super::attempts::field(&mut record, &["body", "Selected", "rows"])? =
        serde_value::to_value(1u64)?;
    let mut write = store.write()?;
    write
        .native()
        .insert(&key, [vec![0], rmp_serde::to_vec(&record)?].concat());
    write.commit([])?;
    assert!(matches!(
        store.managed_result(&current, &receipt.selected.result_id, 1000, &control),
        Err(Error::Package {
            code: Code::Invalid,
            field: "managed success destination",
            ..
        })
    ));
    drop((page, attempt, before, inputs, replay));
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::Package {
            code: Code::Invalid,
            field: "managed success destination",
            ..
        })
    ));
    let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
        .versioned()
        .open()?;
    let branch = database.branch("data")?.ok_or("repair branch")?;
    let mut transaction = branch.write_tx()?;
    let head = transaction.get(b"\0data/head")?.ok_or("repair head")?;
    transaction.insert(&key, &bytes);
    transaction.commit_stamped([[b"\0data/cut/".as_slice(), head.as_ref()].concat()])?;
    drop((branch, database));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        result_record(&store, &receipt.selected.result_id)?,
        (key, bytes)
    );
    assert!(matches!(
        store
            .managed_result(&current, &receipt.selected.result_id, 1000, &control)?
            .kind,
        araphor_data::InstanceResultKindV1::Selected
    ));
    assert_eq!(
        store
            .managed_attempt([1; 16], "source", &input.id, &control)?
            .ok_or("repaired receipt")?
            .receipt(),
        Some(&receipt)
    );
    assert_eq!(inventory(&store, b"\0data/@source/")?, source);
    assert_eq!(inventory(&store, b"\0data/graph/publication/")?, graph);
    Ok(())
}

#[test]
fn graph_selected_rejects_wrong_publication_binding() -> TestResult {
    for fault in [
        "missing_header",
        "rebound_header",
        "captured_cut",
        "wrong_receipt",
        "invalid_header",
        "foreign_record",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let instance = instance(&store)?;
        store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
        append(&store, 1)?;
        let control = AnalysisReadControl::default();
        let page = super::super::attempts::capture(&store, &instance, false)?;
        select(&store, &page, &[1], None)?;
        let first = store.register_managed_attempt(
            &page.state,
            &super::super::attempts::request("binding-first", true),
            || Ok(()),
        )?;
        let receipt = publish(&store, &first, false)?;
        assert_eq!(receipt.graph.as_ref(), Some(&receipt.selected));
        let resume = store.managed_resume([1; 16], "source", &control)?;
        let later_page = capture(&store, &resume)?;
        select(&store, &later_page, &[1], Some(&receipt.selected))?;
        let mut input = super::super::attempts::request("binding-later", true);
        input.rebuild = true;
        let second = store.register_managed_attempt(&later_page.state, &input, || Ok(()))?;
        let later = publish(&store, &second, false)?;
        let current = store.managed_resume([1; 16], "source", &control)?.instance;
        let saved = store
            .managed_attempt([1; 16], "source", "binding-first", &control)?
            .ok_or("first saved attempt")?;
        let original =
            store.managed_result(&current, &receipt.selected.result_id, 1000, &control)?;
        assert!(matches!(
            original.kind,
            araphor_data::InstanceResultKindV1::Selected
        ));
        assert_eq!(original.result, receipt.selected);
        assert_eq!(original.receipt, receipt);
        assert!(!original.current);
        assert_eq!(
            store.graph_record_keys(
                &page.state,
                Some(&saved),
                &receipt.selected,
                AnalysisExtractLimits::default(),
                &control,
            )?,
            records(&[1])
        );
        if fault == "wrong_receipt" {
            assert_eq!(
                store.graph_source([9; 16], &receipt.selected.result_id)?,
                None
            );
            assert!(store
                .graph_record_keys(
                    &page.state,
                    Some(&saved),
                    &receipt.results[&10],
                    AnalysisExtractLimits::default(),
                    &control,
                )
                .is_err());
            let mut wrong = receipt.selected.clone();
            wrong.commit_revision += 1;
            assert!(store
                .graph_record_keys(
                    &page.state,
                    Some(&saved),
                    &wrong,
                    AnalysisExtractLimits::default(),
                    &control,
                )
                .is_err());
            let mut spec = instance.spec.clone();
            spec.id = "foreign-source".into();
            let ManagedDestination::Graph { source, .. } = &mut spec.destination else {
                return Err("Graph destination".into());
            };
            source.source_id = [93; 16];
            let foreign = store.admit_managed(&spec, &instance.grant, || Ok(()))?;
            let requests = AnalysisTableRequests::new();
            let selection = foreign
                .spec
                .destination
                .selection(&foreign.grant.selection)?
                .project(&requests)?;
            let foreign_page = store.read_managed_tables_filtered(
                &selection,
                &araphor_data::ManagedRead {
                    instance: foreign,
                    expected: None,
                    rebuild: false,
                    follow: false,
                    completed: None,
                    source: None,
                    execution: None,
                },
                araphor_data::AnalysisTableRead {
                    requests: &requests,
                    mode: araphor_data::AnalysisReadModeV1::Metadata,
                    now: 1000,
                    event_ranges: None,
                },
                AnalysisExtractLimits::default(),
                &control,
                None,
            )?;
            assert!(matches!(
                store.graph_record_keys(
                    &foreign_page.state,
                    None,
                    &receipt.selected,
                    AnalysisExtractLimits::default(),
                    &control,
                ),
                Err(Error::Package {
                    code: Code::Denied,
                    field: "frozen source publication",
                    ..
                })
            ));
        }
        let (selected, selected_bytes) = result_record(&store, &receipt.selected.result_id)?;
        let first_key = [b"\0data/@source/header/".as_slice(), &selected[7..]].concat();
        let (later_key, _) = result_record(&store, &later.selected.result_id)?;
        let later_key = [b"\0data/@source/header/".as_slice(), &later_key[7..]].concat();
        let view = store.view()?;
        let first_header = view
            .snapshot()
            .get(&first_key)?
            .ok_or("first Source header")?;
        let later_header = view
            .snapshot()
            .get(&later_key)?
            .ok_or("later Source header")?;
        assert_ne!(first_header, later_header);
        let (key, bytes, changed) = if fault == "wrong_receipt" {
            let (key, bytes) = attempt_record(&store, "binding-first")?;
            let mut record: Value = rmp_serde::from_slice(&bytes[1..])?;
            *super::super::attempts::field(&mut record, &["receipt", "graph"])? =
                serde_value::to_value(Some(later.selected.clone()))?;
            (
                key,
                bytes,
                Some([vec![0], rmp_serde::to_vec(&record)?].concat()),
            )
        } else if fault == "foreign_record" {
            let mut record: Value = rmp_serde::from_slice(&selected_bytes[1..])?;
            let Value::Seq(rows) = super::super::attempts::field(
                &mut record,
                &["body", "Selected", "source", "records"],
            )?
            else {
                return Err("Source record rows".into());
            };
            assert_eq!(rows.len(), 1);
            let Value::Seq(pair) = &mut rows[0] else {
                return Err("Source record position".into());
            };
            assert_eq!(pair.len(), 2);
            *super::super::attempts::field(&mut pair[0], &["stream", "source_id"])? =
                serde_value::to_value([93u8; 16])?;
            (
                selected,
                selected_bytes,
                Some([vec![0], rmp_serde::to_vec(&record)?].concat()),
            )
        } else {
            let changed = match fault {
                "missing_header" => None,
                "rebound_header" => Some(later_header.to_vec()),
                "captured_cut" => {
                    assert!(first.captured_revision() > 1);
                    let mut header: Value = rmp_serde::from_slice(&first_header[1..])?;
                    *super::super::attempts::field(
                        &mut header,
                        &["captured", "commit_revision"],
                    )? = serde_value::to_value(first.captured_revision() - 1)?;
                    Some([vec![0], rmp_serde::to_vec(&header)?].concat())
                }
                "invalid_header" => Some(vec![0, 0]),
                _ => unreachable!(),
            };
            (first_key, first_header.to_vec(), changed)
        };
        let mut write = store.write()?;
        if let Some(changed) = changed {
            write.native().insert(&key, changed);
        } else {
            write.native().remove(&key);
        }
        write.commit([])?;
        let meta = store.meta()?;
        let error = store
            .managed_result(&current, &receipt.selected.result_id, 1000, &control)
            .err()
            .ok_or_else(|| format!("live Source read accepted {fault}"))?;
        let expected = match fault {
            "missing_header" => matches!(
                error,
                Error::Package {
                    code: Code::Missing,
                    field: "source publication header",
                    ..
                }
            ),
            "rebound_header" | "captured_cut" => matches!(
                error,
                Error::Package {
                    code: Code::Invalid,
                    field: "source selected authority",
                    ..
                }
            ),
            "wrong_receipt" => matches!(
                error,
                Error::Package {
                    code: Code::Invalid,
                    field: "managed success destination",
                    ..
                }
            ),
            "invalid_header" => matches!(error, Error::ManagedDecoding { .. }),
            "foreign_record" => matches!(
                error,
                Error::Package {
                    code: Code::Denied,
                    field: "source member authority",
                    ..
                }
            ),
            _ => unreachable!(),
        };
        assert!(expected, "{fault}: {error:?}");
        assert_eq!(store.meta()?, meta);
        drop((page, first, later_page, second, saved, view));
        drop(store);
        let reopened = NativeStore::open(&root);
        if fault == "captured_cut" {
            assert!(matches!(
                reopened,
                Err(Error::Package {
                    code: Code::Invalid,
                    field: "source selected authority",
                    ..
                })
            ));
        } else {
            assert!(reopened.is_err(), "{fault}");
        }
        let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
            .versioned()
            .open()?;
        let branch = database.branch("data")?.ok_or("repair branch")?;
        let mut transaction = branch.write_tx()?;
        let head = transaction.get(b"\0data/head")?.ok_or("repair head")?;
        transaction.insert(&key, &bytes);
        transaction.commit_stamped([[b"\0data/cut/".as_slice(), head.as_ref()].concat()])?;
        drop((branch, database));
        let store = NativeStore::open(&root)?;
        assert_eq!(
            store
                .view()?
                .snapshot()
                .get(&key)?
                .ok_or("repaired bytes")?
                .as_ref(),
            bytes
        );
        let restored =
            store.managed_result(&current, &receipt.selected.result_id, 1000, &control)?;
        assert_eq!(restored.result, original.result);
        assert_eq!(restored.receipt, original.receipt);
        assert!(matches!(
            restored.kind,
            araphor_data::InstanceResultKindV1::Selected
        ));
        assert_eq!(
            store
                .managed_attempt([1; 16], "source", "binding-first", &control)?
                .ok_or("repaired attempt")?
                .receipt(),
            Some(&receipt)
        );
    }
    Ok(())
}
