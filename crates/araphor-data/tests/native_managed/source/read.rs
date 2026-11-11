use super::*;
use araphor_data::{
    AnalysisContextRefV1, AnalysisPositionPageV1, AnalysisReadModeV1, AnalysisTableRead,
    AnalysisTableRequests, NotificationFindingRefV1, Selection,
};

#[path = "read/damage.rs"]
mod damage;
#[path = "read/proofs.rs"]
mod proofs;

#[derive(Debug, serde::Deserialize)]
pub(super) struct Manifest {
    pub graph_result_id: String,
    pub graph_revision: GraphRevisionV1,
    pub first_cursor: u64,
    pub last_cursor: u64,
    pub previous_result_id: Option<String>,
    pub notice_context_revision: u64,
    pub witness_deadline_utc_ns: u64,
    pub retained_input_expired: bool,
    pub subject_count: u64,
    pub relationship_count: u64,
    pub context_refs: Vec<AnalysisContextRefV1>,
}

pub(super) fn page(
    store: &NativeStore,
    view: Option<&araphor_data::analysis::native::DataView>,
    selection: &AnalysisSelectionV1,
) -> Result<AnalysisPositionPageV1, Box<dyn std::error::Error>> {
    let schemas = araphor_data::AnalysisStore::table_schemas();
    let requests: AnalysisTableRequests = ["findings", "graph_manifest"]
        .into_iter()
        .map(|name| {
            (
                name.to_owned(),
                Some(
                    schemas[name]
                        .fields()
                        .iter()
                        .enumerate()
                        .filter_map(|(index, field)| {
                            (!matches!(field.name().as_str(), "snapshot" | "metadata"))
                                .then_some(index)
                        })
                        .collect(),
                ),
            )
        })
        .collect();
    let read = AnalysisTableRead {
        requests: &requests,
        mode: AnalysisReadModeV1::Complete,
        now: 1000,
        event_ranges: None,
    };
    Ok(if let Some(view) = view {
        store.read_tables_at(
            view,
            selection,
            read,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
            None,
        )?
    } else {
        store.read_tables(
            selection,
            read,
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )?
    })
}

pub(super) fn manifests(
    page: &AnalysisPositionPageV1,
) -> Result<Vec<Manifest>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for batch in &page.tables["graph_manifest"] {
        rows.extend(serde_arrow::from_record_batch::<Vec<Manifest>>(batch)?);
    }
    Ok(rows)
}

fn values(
    page: &AnalysisPositionPageV1,
    field: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error>> {
    let mut rows = Vec::new();
    for batch in &page.tables["findings"] {
        let values = batch
            .column_by_name(field)
            .and_then(|array| {
                array
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::StringArray>()
            })
            .ok_or("finding string field")?;
        rows.extend(values.iter().flatten().map(str::to_owned));
    }
    Ok(rows)
}

#[test]
fn source_finding_revision_reads() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let (_, model, source, observation) = super::super::domain::fixture_source(&store, true)?;
    let scope = ProcessorScopeV1 {
        processor_id: araphor_data::GRAPH_PROCESSOR.into(),
        method_version: u64::from(araphor_data::GRAPH_SCHEMA_VERSION),
        identity: source.clone(),
    };
    store.register_processor(&scope, ProcessorClassV1::Required, 1)?;
    super::super::domain::commit(&store, &model, &observation, 0)?;
    let held = store.view()?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let first = page(&store, Some(&held), &selection)?;
    let first_rows = manifests(&first)?;
    assert_eq!(first_rows.len(), 1);
    let manifest = &first_rows[0];
    assert_eq!((manifest.first_cursor, manifest.last_cursor), (1, 1));
    assert_eq!(
        (manifest.subject_count, manifest.relationship_count),
        (2, 1)
    );
    assert_eq!(manifest.witness_deadline_utc_ns, 2000);
    assert!(!manifest.retained_input_expired);
    assert!(manifest.previous_result_id.is_none());
    assert!(manifest.notice_context_revision > 0);
    assert_eq!(
        manifest.graph_revision.evidence,
        vec![observation.id.clone()]
    );
    assert_eq!(
        manifest
            .context_refs
            .iter()
            .map(|value| value.key.clone())
            .collect::<Vec<_>>(),
        manifest.graph_revision.context
    );
    assert!(manifest
        .graph_revision
        .context
        .iter()
        .any(|key| key.owner_revision == 99));
    let ids = values(&first, "finding_id")?;
    assert_eq!(ids.len(), 1);
    for batch in &first.tables["findings"] {
        let keys = batch
            .column_by_name("source_key")
            .and_then(|array| {
                array
                    .as_any()
                    .downcast_ref::<sdk::arrow_array::BinaryArray>()
            })
            .ok_or("source key")?;
        assert!(keys.iter().flatten().all(|key| key == source.key()));
    }
    let reference = NotificationFindingRefV1 {
        result_id: manifest.graph_result_id.clone(),
        finding_id: ids[0].clone(),
    };
    assert!(first
        .extraction
        .graph_coverage(&reference.result_id)
        .is_some());
    let schemas = araphor_data::AnalysisStore::table_schemas();
    let only_findings: AnalysisTableRequests = [(
        "findings".into(),
        Some((0..schemas["findings"].fields().len()).collect()),
    )]
    .into();
    let findings = store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &only_findings,
            mode: AnalysisReadModeV1::Complete,
            now: 1000,
            event_ranges: None,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    assert!(findings
        .extraction
        .graph_coverage(&reference.result_id)
        .is_some());
    assert!(findings
        .extraction
        .references
        .iter()
        .filter_map(|reference| reference.result())
        .any(|result| result.result_id == reference.result_id));
    assert!(!findings.tables.contains_key("graph_manifest"));
    let original = store.graph_finding_batch([1; 16], &[reference.clone()])?;
    assert_eq!(original[&reference.result_id].0, manifest.graph_revision);
    let control = AnalysisReadControl::default();
    let budget = super::super::graph::Budget;
    let batch =
        store.prepare_notifications([1; 16], &[reference.clone()], &[], &control, &budget)?;
    assert_eq!(batch.heads()[&reference.finding_id], reference.result_id);
    assert_eq!(
        batch
            .historical(&reference)?
            .ok_or("source historical finding")?
            .1,
        &manifest.graph_revision
    );
    drop(batch);
    super::super::domain::commit(&store, &model, &observation, 1)?;
    let second = page(&store, None, &selection)?;
    let second_rows = manifests(&second)?;
    assert_eq!(second_rows.len(), 1);
    assert_ne!(second_rows[0].graph_result_id, reference.result_id);
    assert_eq!(
        second_rows[0].previous_result_id.as_deref(),
        Some(reference.result_id.as_str())
    );
    let latest = NotificationFindingRefV1 {
        result_id: second_rows[0].graph_result_id.clone(),
        finding_id: reference.finding_id.clone(),
    };
    let batch = store.prepare_notifications(
        [1; 16],
        &[latest.clone(), reference.clone()],
        &[],
        &control,
        &budget,
    )?;
    assert_eq!(batch.heads()[&reference.finding_id], latest.result_id);
    assert_eq!(
        store.graph_finding_batch([1; 16], &[reference.clone()])?,
        original
    );
    drop(batch);
    assert_eq!(
        values(&page(&store, Some(&held), &selection)?, "graph_result_id")?,
        vec![reference.result_id.clone()]
    );
    let mut exact = selection.clone();
    exact.select_graphs(Selection::Exact(vec![reference.result_id.clone()]), None)?;
    assert_eq!(
        values(&page(&store, None, &exact)?, "graph_result_id")?,
        vec![reference.result_id.clone()]
    );
    super::super::domain::commit(&store, &model, &observation, 2)?;
    super::super::domain::commit(&store, &model, &observation, 4)?;
    let changed = manifests(&page(&store, None, &selection)?)?.remove(0);
    let latest = NotificationFindingRefV1 {
        result_id: changed.graph_result_id.clone(),
        finding_id: reference.finding_id.clone(),
    };
    let batch = store.prepare_notifications([1; 16], &[latest.clone()], &[], &control, &budget)?;
    assert_ne!(
        batch.finding(&latest)?.severity,
        original[&reference.result_id].1[&reference.finding_id].severity
    );
    drop(batch);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(held);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store.graph_finding_batch([1; 16], &[reference.clone()])?,
        original
    );
    assert_eq!(
        manifests(&page(&store, None, &selection)?)?[0].graph_result_id,
        latest.result_id
    );
    Ok(())
}

#[test]
fn source_append_origins() -> TestResult {
    use prost::Message as _;
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    append(&store, 1)?;
    let source = identity();
    let report = araphor_data::CoverageReport {
        source_id: source.source_id.to_vec(),
        source_epoch: source.source_epoch,
        cpu_id: 0,
        revision: 1,
        intervals: vec![araphor_data::CoverageInterval {
            interval_id: vec![4; 16],
            source_epoch: 1,
            revision: 1,
            state: "CLOSED".into(),
            first_sequence: 1,
            last_sequence: Some(2),
            opening_counters: Some(Default::default()),
            closing_counters: Some(araphor_data::CoverageCounters {
                next_sequence: 3,
                ..Default::default()
            }),
            ..Default::default()
        }],
    };
    store.accept_validated_coverage(araphor_data::ValidatedCoverageV1 {
        identity: source,
        cpu_id: 0,
        revision: 1,
        encoded_report: report.encode_to_vec(),
    })?;
    let execution = Arc::new(araphor_data::ManagedExecution::default());
    let resume =
        store.managed_resume([1; 16], &instance.spec.id, &AnalysisReadControl::default())?;
    let first_page = follow(&store, &resume, &execution)?;
    select(&store, &first_page, &[1], None)?;
    let attempt = store.register_managed_attempt(
        &first_page.state,
        &super::super::attempts::request("first", true),
        || Ok(()),
    )?;
    let first = publish(&store, &attempt, false)?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let before = manifests(&page(&store, None, &selection)?)?.remove(0);
    assert_eq!(before.graph_revision.evidence, records(&[1]));
    assert_eq!((before.subject_count, before.relationship_count), (0, 0));
    append(&store, 2)?;
    let resume = store.managed_resume([1; 16], "source", &AnalysisReadControl::default())?;
    let second_page = follow(&store, &resume, &execution)?;
    select(&store, &second_page, &[2], Some(&first.selected))?;
    let request = super::super::attempts::request("append", false);
    let attempt = store.register_managed_attempt(&second_page.state, &request, || Ok(()))?;
    let second = publish(&store, &attempt, false)?;
    let after = manifests(&page(&store, None, &selection)?)?.remove(0);
    assert_eq!(after.graph_revision.evidence, records(&[1, 2]));
    assert!(before
        .graph_revision
        .context
        .iter()
        .all(|key| after.graph_revision.context.contains(key)));
    assert!(after.graph_revision.context.len() > before.graph_revision.context.len());
    assert_eq!(
        after
            .context_refs
            .iter()
            .map(|value| value.key.clone())
            .collect::<Vec<_>>(),
        after.graph_revision.context
    );
    assert_eq!(after.graph_result_id, second.selected.result_id);
    drop((first_page, second_page, attempt));
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let current = manifests(&page(&store, None, &selection)?)?.remove(0);
    assert_eq!(current.graph_revision, after.graph_revision);
    let mut exact = selection;
    exact.select_graphs(Selection::Exact(vec![first.selected.result_id]), None)?;
    assert_eq!(
        manifests(&page(&store, None, &exact)?)?[0].graph_revision,
        before.graph_revision
    );
    Ok(())
}

#[test]
fn source_window_instance_selection() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let instance = instance(&store)?;
    store.register_processor(&scope(), ProcessorClassV1::Required, 1)?;
    for cursor in 1..=2 {
        append(&store, cursor)?;
    }
    let initial = super::super::attempts::capture(&store, &instance, false)?;
    fixtures::select_window(&store, &initial, &[1], None, 1)?;
    let first_attempt = store.register_managed_attempt(
        &initial.state,
        &super::super::attempts::request("first", true),
        || Ok(()),
    )?;
    let first = publish(&store, &first_attempt, false)?;
    let resume = store.managed_resume([1; 16], "source", &AnalysisReadControl::default())?;
    let later = capture(&store, &resume)?;
    fixtures::select_window(&store, &later, &[2], Some(&first.selected), 2)?;
    let mut request = super::super::attempts::request("later", true);
    request.rebuild = true;
    let later_attempt = store.register_managed_attempt(&later.state, &request, || Ok(()))?;
    let second = publish(&store, &later_attempt, false)?;
    let mut spec = instance.spec.clone();
    spec.id = "other-source".into();
    let other = store.admit_managed(&spec, &instance.grant, || Ok(()))?;
    let other =
        store.set_managed_running([1; 16], "other-source", other.lifecycle, true, || Ok(()))?;
    let other_page = super::super::attempts::capture(&store, &other, false)?;
    fixtures::select_window(&store, &other_page, &[1], None, 1)?;
    let other_attempt = store.register_managed_attempt(
        &other_page.state,
        &super::super::attempts::request("other", true),
        || Ok(()),
    )?;
    let third = publish(&store, &other_attempt, false)?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let names = manifests(&page(&store, None, &selection)?)?
        .into_iter()
        .map(|row| row.graph_result_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            first.selected.result_id.clone(),
            second.selected.result_id.clone(),
            third.selected.result_id.clone()
        ])
    );
    let resume = store.managed_resume([1; 16], "source", &AnalysisReadControl::default())?;
    let replacement = capture(&store, &resume)?;
    fixtures::select_window(&store, &replacement, &[2], Some(&second.selected), 2)?;
    let mut request = super::super::attempts::request("replace", true);
    request.rebuild = true;
    let replacement_attempt =
        store.register_managed_attempt(&replacement.state, &request, || Ok(()))?;
    let replacement_result = publish(&store, &replacement_attempt, false)?;
    let names = manifests(&page(&store, None, &selection)?)?
        .into_iter()
        .map(|row| row.graph_result_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(
        names,
        BTreeSet::from([
            first.selected.result_id,
            replacement_result.selected.result_id,
            third.selected.result_id
        ])
    );
    let mut exact = selection.clone();
    exact.select_graphs(
        Selection::Exact(vec![second.selected.result_id.clone()]),
        None,
    )?;
    assert_eq!(
        manifests(&page(&store, None, &exact)?)?[0].graph_result_id,
        second.selected.result_id
    );
    drop((
        initial,
        later,
        other_page,
        replacement,
        first_attempt,
        later_attempt,
        other_attempt,
        replacement_attempt,
    ));
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    let reopened = manifests(&page(&store, None, &selection)?)?
        .into_iter()
        .map(|row| row.graph_result_id)
        .collect::<BTreeSet<_>>();
    assert_eq!(reopened, names);
    Ok(())
}
