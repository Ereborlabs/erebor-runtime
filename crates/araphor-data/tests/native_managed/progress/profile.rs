use super::*;
use araphor_data::{
    analysis::{
        native::{ManagedCommit, ManagedReturn},
        PackageResultRefV1, PreparedProfile, ProfileCommit,
    },
    BehaviorSnapshotV1, DiscoveryProfileV1, DISCOVERY_PROCESSOR, DISCOVERY_SCHEMA_VERSION,
};

fn profile(name: &str) -> DiscoveryProfileV1 {
    let mut scope = scope();
    scope.processor_id = DISCOVERY_PROCESSOR.into();
    scope.method_version = DISCOVERY_SCHEMA_VERSION.into();
    DiscoveryProfileV1 {
        schema_version: DISCOVERY_SCHEMA_VERSION,
        scope,
        profile_id: name.into(),
        interval_id: name.into(),
        revision: 1,
        facts_revision: 0,
        coverage_revision: 0,
        created_utc_ns: 1000,
        updated_utc_ns: 1000,
        sealed: false,
        input_bytes: 0,
        incomplete: false,
        gaps: Vec::new(),
        context_refs: Vec::new(),
        snapshot: BehaviorSnapshotV1 {
            schema_version: DISCOVERY_SCHEMA_VERSION,
            tenant_id: [1; 16],
            source_revision: "live-v1".into(),
            proof_kind: araphor_data::DiscoveryProofKindV1::ObservedRuntime,
            accepted_records: 0,
            included_records: 0,
            unresolved_records: 0,
            excluded_records: 0,
            coverage: Vec::new(),
            atoms: Vec::new(),
            unresolved: Vec::new(),
            excluded: Vec::new(),
            lifecycle: araphor_data::DiscoveryLifecycleCaseV1::ALL
                .into_iter()
                .map(|case| araphor_data::DiscoveryLifecycleEntryV1 {
                    case,
                    state: araphor_data::DiscoveryLifecycleStateV1::Missing,
                })
                .collect(),
        },
    }
}

fn instance(
    store: &NativeStore,
) -> Result<(ManagedInstance, sdk::Model), Box<dyn std::error::Error>> {
    let mut fixture = Fixture::new(store, [1; 16], "profile", false)?;
    fixture.grant.selection = AnalysisSelectionV1::tenant([1; 16]);
    fixture.spec.destination = ManagedDestination::DiscoveryProfile {
        source: profile("first").scope.identity,
        call: 10,
        output: "rows".into(),
    };
    let admitted = fixture.admit(store)?;
    let instance =
        store.set_managed_running([1; 16], "profile", admitted.lifecycle, true, || Ok(()))?;
    let descriptor = store
        .view()?
        .package_revision(
            [1; 16],
            "managed-count",
            "1",
            &AnalysisReadControl::default(),
        )?
        .ok_or("descriptor")?;
    let descriptor: sdk::Package = serde_json::from_slice(&descriptor.descriptor)?;
    Ok((instance, descriptor.exports[0].clone()))
}

fn packet(
    profile: DiscoveryProfileV1,
    previous: Option<PackageResultRefV1>,
    head: Option<PackageResultRefV1>,
    first: u64,
    last: u64,
) -> araphor_data::Result<ProfileCommit> {
    Ok(ProfileCommit {
        request: AnalysisResultCommitV1 {
            scope: profile.scope.clone(),
            expected_cursor: first,
            consumed_cursor: last,
            coverage_revision: profile.coverage_revision,
            context_revision: profile
                .context_refs
                .iter()
                .map(|reference| reference.commit_revision)
                .max()
                .unwrap_or(0),
            result_id: profile.profile_id.clone(),
            created_utc_ns: 1000,
            body: Vec::new(),
            witnesses: Vec::new(),
            context_refs: profile.context_refs.clone(),
        },
        profile: PreparedProfile::new(profile)?,
        previous,
        head,
        notice: None,
    })
}

fn attempt(store: &NativeStore, name: &str) -> araphor_data::Result<araphor_data::ManagedAttempt> {
    let resume = store.managed_resume([1; 16], "profile", &AnalysisReadControl::default())?;
    let requests: araphor_data::AnalysisTableRequests = ["events", "context_versions"]
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
        .collect();
    let selection = resume
        .instance
        .spec
        .destination
        .selection(&resume.instance.grant.selection)?
        .project(&requests)?;
    let page = store.read_managed_tables_filtered(
        &selection,
        &araphor_data::ManagedRead {
            instance: resume.instance,
            expected: None,
            rebuild: false,
            follow: false,
            completed: Some(resume.completed),
            execution: None,
            source: None,
        },
        araphor_data::AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: araphor_data::AnalysisReadModeV1::Complete,
            now: 1000,
        },
        araphor_data::AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )?;
    store.register_managed_attempt(
        &page.state,
        &super::super::attempts::request(name, true),
        || Ok(()),
    )
}

fn publish(
    store: &NativeStore,
    attempt: &araphor_data::ManagedAttempt,
    model: &sdk::Model,
    packet: Option<ProfileCommit>,
    reject: bool,
) -> Result<
    (
        araphor_data::ManagedReceipt,
        Option<araphor_data::AnalysisResultReceiptV1>,
    ),
    Box<dyn std::error::Error>,
> {
    let evaluation = super::super::publication::evaluation(attempt);
    let output = super::super::publication::output(model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
        retained: None,
    }];
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &attempt.instance().spec.manifest.selected_schema,
    };
    Ok(
        store.commit_managed_profile(store.prepare_managed(&input)?, packet, || {
            if reject {
                Err(Code::Denied.error("guard"))
            } else {
                Ok(())
            }
        })?,
    )
}

#[test]
fn profile_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_instance, model) = instance(&store)?;
    let first = profile("first");
    store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
    super::super::attempts::append(&store, 1)?;
    let initial = attempt(&store, "first")?;
    let before = store.view()?;
    let cursor = store.database().inner().journal_head()?;
    assert!(publish(
        &store,
        &initial,
        &model,
        Some(packet(first.clone(), None, None, 0, 1)?),
        true
    )
    .is_err());
    assert_eq!(store.view()?.revision(), before.revision());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store.processor_result(&first.scope)?.is_none());
    let (published, receipt) = publish(
        &store,
        &initial,
        &model,
        Some(packet(first.clone(), None, None, 0, 1)?),
        false,
    )?;
    let receipt = receipt.ok_or("profile receipt")?;
    assert_eq!(published.commit_revision, receipt.commit_revision);
    let first_ref = PackageResultRefV1 {
        result_id: first.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    assert_eq!(
        store
            .discovery_producer(
                &AnalysisSelectionV1::tenant([1; 16]),
                &first,
                &AnalysisReadControl::default()
            )?
            .result,
        published.results[&10]
    );
    let mut narrow = AnalysisSelectionV1::new([1; 16], vec![first.scope.identity.clone()]);
    narrow.nodes = vec!["node-a".into()];
    assert!(store
        .discovery_producer(&narrow, &first, &AnalysisReadControl::default())
        .is_err());
    let mut sealed = first.clone();
    sealed.profile_id = "sealed".into();
    sealed.revision = 2;
    sealed.sealed = true;
    super::super::attempts::append(&store, 2)?;
    let closing = attempt(&store, "closing")?;
    let (closing_result, closed) = publish(
        &store,
        &closing,
        &model,
        Some(packet(
            sealed.clone(),
            Some(first_ref.clone()),
            Some(first_ref),
            1,
            1,
        )?),
        false,
    )?;
    let closed = closed.ok_or("closed")?;
    #[derive(serde::Deserialize)]
    struct Saved {
        request: AnalysisResultCommitV1,
    }
    let records = store.view()?;
    let requests = records
        .snapshot()
        .prefix(b"\0data/@progress/result/")
        .map(|row| {
            let (key, bytes) = row?;
            let row: Saved = rmp_serde::from_slice(&bytes[1..])?;
            Ok::<_, Box<dyn std::error::Error>>((row.request.result_id.clone(), (key, row)))
        })
        .collect::<Result<BTreeMap<_, _>, _>>()?;
    assert_eq!(
        requests["first"].1.request.witnesses,
        requests["sealed"].1.request.witnesses
    );
    #[derive(serde::Deserialize)]
    struct Stored {
        id: String,
        body: Body,
    }
    #[derive(serde::Deserialize)]
    enum Body {
        Call {
            witnesses: Vec<araphor_data::AnalysisWitnessV1>,
        },
        Selected {},
    }
    let closing_witnesses = records
        .snapshot()
        .prefix(b"\0data/X")
        .map(|row| {
            let (_, bytes) = row?;
            let row: Stored = rmp_serde::from_slice(&bytes[1..])?;
            Ok::<_, Box<dyn std::error::Error>>(row)
        })
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .find_map(|row| match row.body {
            Body::Call { witnesses } if row.id == closing_result.results[&10].result_id => {
                Some(witnesses)
            }
            _ => None,
        })
        .ok_or("closing witnesses")?;
    assert!(!requests["first"].1.request.witnesses.is_empty());
    assert!(closing_witnesses.len() > requests["first"].1.request.witnesses.len());

    let producer = store.discovery_producer(
        &AnalysisSelectionV1::tenant([1; 16]),
        &sealed,
        &AnalysisReadControl::default(),
    )?;
    assert_eq!(producer.result, published.results[&10]);
    assert_ne!(producer.result, closing_result.results[&10]);
    let sealed_ref = PackageResultRefV1 {
        result_id: sealed.profile_id.clone(),
        commit_revision: closed.commit_revision,
    };
    let second = profile("second");
    let next = attempt(&store, "next")?;
    let (_, next_receipt) = publish(
        &store,
        &next,
        &model,
        Some(packet(
            second.clone(),
            Some(sealed_ref.clone()),
            Some(sealed_ref.clone()),
            1,
            1,
        )?),
        false,
    )?;
    let next_receipt = next_receipt.ok_or("next")?;
    let next_ref = PackageResultRefV1 {
        result_id: second.profile_id.clone(),
        commit_revision: next_receipt.commit_revision,
    };
    let mut repair = sealed.clone();
    repair.profile_id = "repair".into();
    repair.revision = 3;
    let fixing = attempt(&store, "fix")?;
    let (_, repaired) = publish(
        &store,
        &fixing,
        &model,
        Some(packet(
            repair.clone(),
            Some(sealed_ref),
            Some(next_ref),
            1,
            1,
        )?),
        false,
    )?;
    assert!(repaired.is_some());
    assert_eq!(
        store
            .processor_result(&first.scope)?
            .ok_or("current")?
            .result_id,
        second.profile_id
    );
    #[derive(serde::Deserialize)]
    struct History {
        history: Vec<araphor_data::DiscoveryHistoryRowV1>,
    }
    let history = |view: &araphor_data::analysis::native::DataView| -> Result<
        Vec<araphor_data::DiscoveryHistoryRowV1>,
        Box<dyn std::error::Error>,
    > {
        let page = state(&store, view, &["history"])?;
        let mut rows: Vec<History> =
            serde_arrow::from_record_batch(&page.tables["discovery_state"][0])?;
        Ok(rows.remove(0).history)
    };
    assert_eq!(
        history(store.view()?.as_ref())?
            .iter()
            .map(|row| row.result_id.as_str())
            .collect::<Vec<_>>(),
        vec!["repair"]
    );
    assert_eq!(
        history(&store.read_at(closed.commit_revision)?)?
            .iter()
            .map(|row| row.result_id.as_str())
            .collect::<Vec<_>>(),
        vec!["sealed"]
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().rotate_journal()?;
    store.database().inner().major_compact()?;
    drop((records, before, initial, closing, next, fixing, store));
    let store = NativeStore::open(&root)?;
    let page = state(&store, store.view()?.as_ref(), &["history"])?;
    let history: Vec<History> = serde_arrow::from_record_batch(&page.tables["discovery_state"][0])?;
    assert_eq!(history[0].history[0].result_id, "repair");
    assert_eq!(
        store
            .processor_result(&first.scope)?
            .ok_or("reopened current")?
            .result_id,
        second.profile_id
    );
    assert_eq!(
        store
            .read_at(receipt.commit_revision)?
            .processor_result(&first.scope)?
            .ok_or("historical current")?
            .result_id,
        first.profile_id
    );
    assert!(!store
        .discovery_producer(
            &AnalysisSelectionV1::tenant([1; 16]),
            &repair,
            &AnalysisReadControl::default()
        )?
        .result
        .result_id
        .is_empty());
    Ok(())
}

#[test]
fn result_name_collisions() -> TestResult {
    for selected in [false, true] {
        let directory = tempfile::tempdir()?;
        let store = NativeStore::open(&directory.path().join("data"))?;
        let (_, model) = instance(&store)?;
        let first = profile("first");
        store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
        let generic = scope();
        store.register_processor(&generic, ProcessorClassV1::Required, 1)?;
        super::super::attempts::append(&store, 1)?;
        let attempt = attempt(&store, "collision")?;
        let revision = store.view()?.revision() + 2;
        let name = if selected {
            format!("managed-{revision}-selected")
        } else {
            format!("managed-{revision}-call-10")
        };
        let request = AnalysisResultCommitV1 {
            scope: generic.clone(),
            expected_cursor: 0,
            consumed_cursor: 1,
            coverage_revision: 0,
            context_revision: 0,
            result_id: name.clone(),
            body: vec![1],
            created_utc_ns: 1000,
            witnesses: Vec::new(),
            context_refs: Vec::new(),
        };
        store.commit_result(&request)?;
        let before = store.view()?.revision();
        assert!(publish(
            &store,
            &attempt,
            &model,
            Some(packet(first.clone(), None, None, 0, 1)?),
            false
        )
        .is_err());
        assert_eq!(store.view()?.revision(), before);
        store.finish_managed(&attempt, araphor_data::ManagedExit::Cancelled, || Ok(()))?;
        let next = self::attempt(&store, "next")?;
        let (published, _) = publish(
            &store,
            &next,
            &model,
            Some(packet(first, None, None, 0, 1)?),
            false,
        )?;
        for tenant in [[1; 16], [9; 16]] {
            let mut collision = request.clone();
            collision.scope.identity.tenant_id = tenant;
            collision.result_id = published.results[&10].result_id.clone();
            assert!(store.commit_result(&collision).is_err());
            collision.result_id = published.selected.result_id.clone();
            assert!(store.commit_result(&collision).is_err());
        }
        assert!(store.read_result([9; 16], &name)?.is_none());
        assert_eq!(
            store.processor_result(&generic)?.ok_or("generic")?.body,
            vec![1]
        );
        #[derive(serde::Deserialize, serde::Serialize)]
        struct Header {
            stream_key: Option<Vec<u8>>,
            method_version: Option<u64>,
            interval_id: Option<String>,
            profile_revision: Option<u64>,
            facts_revision: Option<u64>,
            coverage_revision: Option<u64>,
            first_cursor: Option<u64>,
        }
        #[derive(serde::Deserialize, serde::Serialize)]
        struct Saved {
            revision: u64,
            request: AnalysisResultCommitV1,
            producer: Option<PackageResultRefV1>,
            header: Header,
            body_bytes: u64,
        }
        let view = store.view()?;
        let mut stored = view
            .snapshot()
            .prefix(b"\0data/@progress/result/")
            .map(|row| {
                let (_, bytes) = row?;
                Ok::<_, Box<dyn std::error::Error>>(rmp_serde::from_slice::<Saved>(&bytes[1..])?)
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|row| row.request.result_id == name)
            .ok_or("generic row")?;
        #[derive(serde::Deserialize)]
        struct Identity {
            id: String,
        }
        let key = view
            .snapshot()
            .prefix(b"\0data/X")
            .map(|row| {
                let (key, bytes) = row?;
                Ok::<_, Box<dyn std::error::Error>>((
                    key,
                    rmp_serde::from_slice::<Identity>(&bytes[1..])?,
                ))
            })
            .collect::<Result<Vec<_>, _>>()?
            .into_iter()
            .find(|(_, row)| row.id == published.selected.result_id)
            .ok_or("selected key")?
            .0;
        stored.request.result_id = published.selected.result_id.clone();
        let mut bytes = vec![0];
        bytes.extend(rmp_serde::to_vec_named(&stored)?);
        let mut key = key.to_vec();
        key.drain(..7);
        let mut processor = b"\0data/@progress/result/".to_vec();
        processor.extend(key);
        let mut tx = store.write()?;
        tx.native().insert(processor, bytes);
        tx.commit([])?;
        drop((view, attempt, next, store));
        assert!(matches!(
            NativeStore::open(&directory.path().join("data")),
            Err(Error::Package {
                code: Code::Invalid,
                field: "multiple result owners",
                ..
            })
        ));
    }
    Ok(())
}

fn requests(fields: &[&str]) -> araphor_data::AnalysisTableRequests {
    let schema = &araphor_data::AnalysisStore::table_schemas()["discovery_state"];
    [(
        "discovery_state".into(),
        Some(
            fields
                .iter()
                .map(|field| schema.index_of(field).expect("field"))
                .collect(),
        ),
    )]
    .into()
}

fn state(
    store: &NativeStore,
    view: &araphor_data::analysis::native::DataView,
    fields: &[&str],
) -> Result<araphor_data::AnalysisPositionPageV1, Box<dyn std::error::Error>> {
    let requests = requests(fields);
    let selection = AnalysisSelectionV1::new([1; 16], vec![profile("unused").scope.identity])
        .project(&requests)?;
    Ok(store.read_tables_at(
        view,
        &selection,
        araphor_data::AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: araphor_data::AnalysisReadModeV1::Complete,
            now: 1000,
        },
        araphor_data::AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )?)
}

#[test]
fn profile_notice_views() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model) = instance(&store)?;
    let first = profile("first");
    store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
    super::super::attempts::append(&store, 1)?;
    let initial = attempt(&store, "first")?;
    let mut input = packet(first.clone(), None, None, 0, 1)?;
    let context = super::super::attempts::context(1);
    input.profile = PreparedProfile::captured(first.clone(), vec![context.clone()])?;
    let (_, receipt) = publish(&store, &initial, &model, Some(input), false)?;
    let receipt = receipt.ok_or("receipt")?;
    let saved = store
        .processor_result(&first.scope)?
        .ok_or("saved profile")?;
    let first = DiscoveryProfileV1::try_from(saved.body.as_slice())?;
    assert_eq!(first.context_refs.len(), 1);
    assert_eq!(
        first.context_refs[0].commit_revision,
        receipt.commit_revision
    );
    assert_eq!(
        store
            .view()?
            .context(&context.key)?
            .ok_or("captured context")?
            .1,
        receipt.commit_revision
    );
    let pinned = store.view()?;
    let head = PackageResultRefV1 {
        result_id: first.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    let notice = attempt(&store, "notice")?;
    let mut input = packet(first.clone(), Some(head.clone()), Some(head.clone()), 1, 1)?;
    input.notice = Some((10, 20));
    let (_, result) = publish(&store, &notice, &model, Some(input), false)?;
    assert!(result.is_none());
    let notice_revision = store.view()?.revision();
    let fields = [
        "current_result_id",
        "profile_revision",
        "notice_facts_revision",
        "notice_coverage_revision",
    ];
    let historical = state(&store, &pinned, &fields)?;
    let current = state(&store, store.view()?.as_ref(), &fields)?;
    let facts = |page: &araphor_data::AnalysisPositionPageV1| {
        page.tables["discovery_state"][0]
            .column_by_name("notice_facts_revision")
            .expect("facts column")
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .expect("facts")
            .value(0)
    };
    assert_eq!(facts(&historical), 0);
    assert_eq!(facts(&current), 10);
    let noop = attempt(&store, "notice-noop")?;
    let mut input = packet(first.clone(), Some(head.clone()), Some(head), 1, 1)?;
    input.notice = Some((1, 2));
    publish(&store, &noop, &model, Some(input), false)?;
    let (_, notice_bytes) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/@progress/notice/")
        .next()
        .ok_or("notice")??;
    #[derive(serde::Deserialize)]
    struct Notice {
        revision: u64,
    }
    let row: Notice = rmp_serde::from_slice(&notice_bytes[1..])?;
    assert_eq!(row.revision, notice_revision);
    assert_eq!(
        store
            .processor_result(&first.scope)?
            .ok_or("unchanged body")?
            .body,
        saved.body
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((pinned, initial, notice, noop, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(
        facts(&state(
            &store,
            &store.read_at(receipt.commit_revision)?,
            &fields
        )?),
        0
    );
    assert_eq!(facts(&state(&store, store.view()?.as_ref(), &fields)?), 10);
    let (body, _) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/@progress/body/")
        .next()
        .ok_or("body")??;
    let mut tx = store.write()?;
    tx.native().insert(body, [0, b'x']);
    tx.commit([])?;
    assert_eq!(facts(&state(&store, store.view()?.as_ref(), &fields)?), 10);
    assert!(state(&store, store.view()?.as_ref(), &["snapshot"]).is_err());
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

#[tokio::test]
async fn profile_input_replay() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model) = instance(&store)?;
    let first = profile("first");
    super::super::attempts::append(&store, 1)?;
    let demands = [("discovery_state".into(), None)].into();
    let selection = AnalysisSelectionV1::new([1; 16], vec![first.scope.identity.clone()]);
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let mut inputs = store.subscribe_inputs(&selection, &demands, None, &control, &budget)?;
    let mut other = first.scope.clone();
    other.identity.node_id = "other".into();
    store.register_processor(&other, ProcessorClassV1::Optional, 1)?;
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(25), inputs.changed())
            .await
            .is_err()
    );
    store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
    let registered = store.view()?.revision();
    assert_eq!(inputs.changed().await?.commit_revision, registered);
    let cut = store.view()?;
    let initial = attempt(&store, "first")?;
    let (_, receipt) = publish(
        &store,
        &initial,
        &model,
        Some(packet(first.clone(), None, None, 0, 1)?),
        false,
    )?;
    let receipt = receipt.ok_or("receipt")?;
    assert_eq!(
        inputs.changed().await?.commit_revision,
        receipt.commit_revision
    );
    let mut replay =
        store.subscribe_inputs_at(&cut, &selection, &demands, None, &control, &budget)?;
    assert_eq!(
        replay.changed().await?.commit_revision,
        receipt.commit_revision
    );
    drop((inputs, replay, cut, initial, store));
    let store = NativeStore::open(&root)?;
    let cut = store.read_at(registered)?;
    let mut replay =
        store.subscribe_inputs_at(&cut, &selection, &demands, None, &control, &budget)?;
    assert_eq!(
        replay.changed().await?.commit_revision,
        receipt.commit_revision
    );
    let head = PackageResultRefV1 {
        result_id: first.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    let notice = attempt(&store, "notice")?;
    let mut input = packet(first.clone(), Some(head.clone()), Some(head), 1, 1)?;
    input.notice = Some((10, 20));
    publish(&store, &notice, &model, Some(input), false)?;
    assert_eq!(
        replay.changed().await?.commit_revision,
        store.view()?.revision()
    );
    Ok(())
}

fn managed_state(
    store: &NativeStore,
    instance: &ManagedInstance,
    expected: Option<&ManagedInstance>,
    fields: &[&str],
) -> araphor_data::Result<araphor_data::ManagedPage> {
    let requests = requests(fields);
    let selection = instance
        .spec
        .destination
        .selection(&instance.grant.selection)?
        .project(&requests)?;
    store.read_managed_tables_filtered(
        &selection,
        &araphor_data::ManagedRead {
            instance: instance.clone(),
            expected: expected.cloned(),
            rebuild: expected.is_some(),
            follow: false,
            completed: None,
            execution: None,
            source: None,
        },
        araphor_data::AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: araphor_data::AnalysisReadModeV1::Complete,
            now: 1000,
        },
        araphor_data::AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )
}

#[test]
fn profile_candidate_capture() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (_, model) = instance(&store)?;
    let first = profile("first");
    store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
    super::super::attempts::append(&store, 1)?;
    let initial = attempt(&store, "first")?;
    let (_, receipt) = publish(
        &store,
        &initial,
        &model,
        Some(packet(first.clone(), None, None, 0, 1)?),
        false,
    )?;
    let receipt = receipt.ok_or("receipt")?;
    let live = store
        .managed_resume([1; 16], "profile", &AnalysisReadControl::default())?
        .instance;
    let compatible = |page: &araphor_data::ManagedPage| {
        page.page.tables["discovery_state"][0]
            .column_by_name("current_compatible")
            .expect("compatibility column")
            .as_any()
            .downcast_ref::<sdk::arrow_array::BooleanArray>()
            .expect("compatibility")
            .value(0)
    };
    assert!(compatible(&managed_state(
        &store,
        &live,
        None,
        &["current_compatible"]
    )?));
    let mut spec = live.spec.clone();
    spec.manifest.planner = "native-test-other".into();
    let candidate = store.prepare_managed_version(&live, &spec, || Ok(()))?;
    assert!(!compatible(&managed_state(
        &store,
        &candidate,
        Some(&live),
        &["current_compatible"]
    )?));
    let rollback = store.prepare_managed_version(&live, &live.spec, || Ok(()))?;
    assert!(compatible(&managed_state(
        &store,
        &rollback,
        Some(&live),
        &["current_compatible"]
    )?));
    let mut fixture = Fixture::new(&store, [1; 16], "reader", false)?;
    fixture.grant.selection = AnalysisSelectionV1::new([1; 16], vec![first.scope.identity.clone()]);
    let reader = fixture.admit(&store)?;
    let reader = store.set_managed_running([1; 16], "reader", reader.lifecycle, true, || Ok(()))?;
    let fields = ["current_result_id", "notice_facts_revision"];
    let captured = managed_state(&store, &reader, None, &fields)?;
    let head = PackageResultRefV1 {
        result_id: first.profile_id.clone(),
        commit_revision: receipt.commit_revision,
    };
    let notice = attempt(&store, "notice")?;
    let mut input = packet(first.clone(), Some(head.clone()), Some(head), 1, 1)?;
    input.notice = Some((10, 20));
    publish(&store, &notice, &model, Some(input), false)?;
    let before = store.view()?.revision();
    assert!(matches!(
        store.register_managed_attempt(
            &captured.state,
            &super::super::attempts::request("stale", true),
            || Ok(())
        ),
        Err(Error::AnalysisSourceChanged { .. })
    ));
    assert_eq!(store.view()?.revision(), before);
    let page = managed_state(&store, &reader, None, &fields)?;
    let attempt = store.register_managed_attempt(
        &page.state,
        &super::super::attempts::request("fresh", true),
        || Ok(()),
    )?;
    let evaluation = super::super::publication::evaluation(&attempt);
    let output = super::super::publication::output(&model)?;
    let returns = [ManagedReturn {
        call: 10,
        evaluation: &evaluation,
        output: &output,
        changes: None,
        graph: None,
        retained: None,
    }];
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let input = ManagedCommit {
        control: &control,
        budget: &budget,
        attempt: &attempt,
        completed: true,
        now_utc_ns: 1000,
        returns: &returns,
        selected: &output.datasets[0],
        selected_schema: &reader.spec.manifest.selected_schema,
    };
    store.commit_managed(store.prepare_managed(&input)?, || Ok(()))?;
    Ok(())
}

#[test]
fn profile_gap_rollback() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let (_, model) = instance(&store)?;
    let mut first = profile("first");
    first.incomplete = true;
    first.gaps.push(araphor_data::AnalysisGapV1 {
        first_cursor: 1,
        last_cursor: 1,
        commit_revision: 1,
    });
    store.register_processor(&first.scope, ProcessorClassV1::Optional, 1)?;
    super::super::attempts::append(&store, 1)?;
    let attempt = attempt(&store, "unproved")?;
    let before = store.view()?.revision();
    let cursor = store.database().inner().journal_head()?;
    assert!(publish(
        &store,
        &attempt,
        &model,
        Some(packet(first.clone(), None, None, 0, 1)?),
        false
    )
    .is_err());
    assert_eq!(store.view()?.revision(), before);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store.processor_result(&first.scope)?.is_none());
    Ok(())
}
