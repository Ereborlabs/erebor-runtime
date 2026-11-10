#![cfg(feature = "native-store")]

use std::{
    collections::{BTreeMap, BTreeSet},
    ops::Bound,
};

use araphor_analysis_sdk as sdk;
use araphor_data::{
    analysis::native::NativeStore, AnalysisContextKeyV1, AnalysisContextVersionV1,
    AnalysisExtractLimits, AnalysisPositionPageV1, AnalysisReadControl, AnalysisReadModeV1,
    AnalysisSelectionV1, AnalysisStore, AnalysisTableRead, AnalysisTableRequests,
    ContextSensitivityV1, CoverageReport, Error, EvidenceIntakeIdentityV1, EvidenceRecord,
    PackageErrorCodeV1 as Code, Selection, StorePositionV1, ValidatedCoverageV1,
    ValidatedEvidenceBatchV1,
};
use prost::Message as _;
use sdk::arrow_array::{Array, StringArray, UInt64Array};

type TestResult = Result<(), Box<dyn std::error::Error>>;

#[path = "native_extraction/append.rs"]
mod append;

#[path = "native_extraction/recovery.rs"]
mod recovery;

fn identity(node: &str) -> EvidenceIntakeIdentityV1 {
    EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: node.into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

fn batch(first: u64, count: u64, intake: u64) -> araphor_data::Result<ValidatedEvidenceBatchV1> {
    let mut framed_records = Vec::new();
    let mut frame_ends = Vec::new();
    for cursor in first..first + count {
        framed_records.extend(Vec::<u8>::try_from(&EvidenceRecord {
            task_cookie: cursor,
            observed_boottime_ns: cursor,
            ..Default::default()
        })?);
        frame_ends.push(framed_records.len());
    }
    Ok(ValidatedEvidenceBatchV1 {
        cpu_id: 0,
        first_cursor: first,
        last_cursor: first + count - 1,
        intake_utc_ns: intake,
        framed_records: framed_records.into(),
        frame_ends,
    })
}

fn context(owner: &str, entity: u8, revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: owner.into(),
            entity_key: vec![entity],
            lifetime_key: vec![7],
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![entity; 16],
    }
}

fn requests(names: &[(&str, &[&str])]) -> araphor_data::Result<AnalysisTableRequests> {
    names
        .iter()
        .map(|(name, fields)| {
            let schema = &AnalysisStore::table_schemas()[*name];
            let columns = fields
                .iter()
                .map(|field| {
                    schema
                        .index_of(field)
                        .map_err(|source| Error::PackageArrow {
                            source,
                            location: snafu::location!(),
                        })
                })
                .collect::<araphor_data::Result<_>>()?;
            Ok(((*name).into(), Some(columns)))
        })
        .collect()
}

fn read<'a>(
    requests: &'a AnalysisTableRequests,
    mode: AnalysisReadModeV1,
) -> AnalysisTableRead<'a> {
    AnalysisTableRead {
        requests,
        mode,
        now: 1000,
        event_ranges: None,
    }
}

struct Pair {
    native: NativeStore,
    old: AnalysisStore,
    _directory: tempfile::TempDir,
}

impl Pair {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        Ok(Self {
            native: NativeStore::open(&directory.path().join("native"))?,
            old: AnalysisStore::open(directory.path().join("old"))?,
            _directory: directory,
        })
    }

    fn append(
        &self,
        source: &EvidenceIntakeIdentityV1,
        first: u64,
        count: u64,
        intake: u64,
    ) -> araphor_data::Result<()> {
        self.native
            .accept_validated_batch(source.clone(), batch(first, count, intake)?)?;
        self.old
            .accept_validated_batch(source.clone(), batch(first, count, intake)?)?;
        Ok(())
    }

    fn contexts(&self, contexts: &[AnalysisContextVersionV1]) -> araphor_data::Result<()> {
        self.native.commit_contexts(contexts)?;
        self.old.commit_contexts(contexts)?;
        Ok(())
    }

    fn coverage(&self, source: &EvidenceIntakeIdentityV1) -> araphor_data::Result<()> {
        let report = CoverageReport {
            source_id: source.source_id.to_vec(),
            source_epoch: source.source_epoch,
            cpu_id: 0,
            revision: 1,
            ..Default::default()
        };
        let input = || ValidatedCoverageV1 {
            identity: source.clone(),
            cpu_id: 0,
            revision: 1,
            encoded_report: report.encode_to_vec(),
        };
        self.native.accept_validated_coverage(input())?;
        self.old.accept_validated_coverage(input())?;
        Ok(())
    }

    fn compare(
        &self,
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        mode: AnalysisReadModeV1,
        limits: AnalysisExtractLimits,
    ) -> Result<AnalysisPositionPageV1, Box<dyn std::error::Error>> {
        let control = AnalysisReadControl::default();
        let native = self
            .native
            .read_tables(selection, read(requests, mode), limits, &control)?;
        let old = self
            .old
            .read_tables(selection, read(requests, mode), limits, &control)?;
        assert_eq!(native.tables, old.tables);
        assert_eq!(native.scanned_through, old.scanned_through);
        assert_eq!(native.exhausted, old.exhausted);
        assert_eq!(native.received_min, old.received_min);
        assert_eq!(native.extraction.witnesses, old.extraction.witnesses);
        assert_eq!(
            native.extraction.missing_contexts,
            old.extraction.missing_contexts
        );
        let refs = |page: &AnalysisPositionPageV1| {
            page.extraction
                .references
                .iter()
                .map(|reference| {
                    (
                        reference.context().cloned(),
                        reference.result().cloned(),
                        reference.origins().to_vec(),
                    )
                })
                .collect::<Vec<_>>()
        };
        assert_eq!(refs(&native), refs(&old));
        assert_eq!(
            native.extraction.meta.commit_revision,
            old.extraction.meta.commit_revision
        );
        assert_eq!(
            native.extraction.meta.schema_version,
            old.extraction.meta.schema_version
        );
        assert_eq!(
            native.extraction.sources.len(),
            old.extraction.sources.len()
        );
        let head = native.extraction.meta.commit_revision;
        for (native, old) in native
            .extraction
            .sources
            .iter()
            .zip(&old.extraction.sources)
        {
            assert_eq!(native.receipt, old.receipt);
            assert!(native.commit_revision <= old.commit_revision);
            assert!(old.commit_revision <= head);
            assert_eq!(native.pending, old.pending);
            assert_eq!(native.coverage_report, old.coverage_report);
        }
        Ok(native)
    }
}

#[test]
fn native_arrow_matches_current_inputs_and_headers() -> TestResult {
    let pair = Pair::new()?;
    let a = identity("a");
    let b = identity("b");
    pair.append(&a, 1, 3, 10)?;
    pair.append(&b, 1, 2, 20)?;
    pair.append(&a, 5, 1, 30)?;
    pair.coverage(&a)?;
    pair.contexts(&[
        context("zeta", 2, 1),
        context("alpha", 3, 2),
        context("alpha", 1, 0),
    ])?;
    let requests = requests(&[
        (
            "events",
            &[
                "node_id",
                "task_cookie",
                "source_cursor",
                "commit_revision",
                "ordinal",
                "received_utc_ns",
            ],
        ),
        (
            "coverage",
            &[
                "node_id",
                "source_epoch",
                "kind",
                "state",
                "first_cursor",
                "last_cursor",
                "coverage_revision",
            ],
        ),
        (
            "context_versions",
            &[
                "owner_id",
                "entity_key",
                "owner_revision",
                "commit_revision",
                "body",
            ],
        ),
    ])?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let page = pair.compare(
        &selection,
        &requests,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
    )?;
    assert_eq!(
        page.extraction
            .sources
            .iter()
            .map(|source| (
                source.receipt.identity.node_id.as_str(),
                source.commit_revision
            ))
            .collect::<BTreeMap<_, _>>(),
        BTreeMap::from([("a", 4), ("b", 2)]),
    );
    assert_eq!(
        page.tables["events"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        6
    );
    assert_eq!(
        page.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        3
    );
    let owners = page.tables["context_versions"]
        .iter()
        .map(|batch| {
            let owners = batch
                .column_by_name("owner_id")
                .and_then(|array| array.as_any().downcast_ref::<StringArray>())
                .ok_or("owners")?;
            Ok::<_, Box<dyn std::error::Error>>(
                (0..owners.len())
                    .map(|row| owners.value(row).to_owned())
                    .collect::<Vec<_>>(),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    assert_eq!(
        owners,
        vec![vec![
            "alpha".to_owned(),
            "alpha".to_owned(),
            "zeta".to_owned()
        ]]
    );
    Ok(())
}

#[test]
fn pages_filters_and_consumed_ordinals_match() -> TestResult {
    let pair = Pair::new()?;
    let a = identity("a");
    pair.append(&a, 1, 6, 10)?;
    pair.append(&a, 7, 3, 20)?;
    let requests = requests(&[(
        "events",
        &[
            "source_cursor",
            "commit_revision",
            "ordinal",
            "received_utc_ns",
        ],
    )])?;
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![a]);
    selection.cursor_from = Bound::Included(2);
    selection.cursor_until = Bound::Included(8);
    let limits = AnalysisExtractLimits {
        page_rows: 2,
        ..Default::default()
    };
    let mut after = None;
    let mut cursors = Vec::new();
    loop {
        let page = pair.compare(
            &selection,
            &requests,
            AnalysisReadModeV1::Page(after),
            limits,
        )?;
        for batch in page.tables.get("events").into_iter().flatten() {
            let values = batch
                .column_by_name("source_cursor")
                .and_then(|array| array.as_any().downcast_ref::<UInt64Array>())
                .ok_or("cursor")?;
            cursors.extend((0..values.len()).map(|row| values.value(row)));
        }
        after = Some(page.scanned_through);
        if page.exhausted {
            break;
        }
    }
    assert_eq!(cursors, (2..=8).collect::<Vec<_>>());
    selection.received_from = Bound::Included(20);
    let page = pair.compare(
        &selection,
        &requests,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
    )?;
    assert_eq!(
        page.tables["events"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        2
    );
    Ok(())
}

#[test]
fn changes_use_sorted_headers_and_exact_historical_cut() -> TestResult {
    let pair = Pair::new()?;
    let source = identity("a");
    pair.append(&source, 1, 1, 10)?;
    pair.contexts(&[context("zeta", 4, 1)])?;
    let before = pair.native.view()?;
    pair.append(&source, 2, 1, 20)?;
    pair.contexts(&[
        context("zeta", 3, 2),
        context("alpha", 2, 2),
        context("alpha", 1, 1),
    ])?;
    let middle = pair.native.view()?;
    pair.contexts(&[context("alpha", 9, 3)])?;
    let requests = requests(&[
        ("events", &["source_cursor", "commit_revision", "ordinal"]),
        (
            "context_versions",
            &[
                "owner_id",
                "entity_key",
                "owner_revision",
                "commit_revision",
            ],
        ),
    ])?;
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    let after = StorePositionV1 {
        commit_revision: before.revision(),
        ordinal: u32::MAX,
    };
    let page = pair.compare(
        &selection,
        &requests,
        AnalysisReadModeV1::Changes(after),
        AnalysisExtractLimits::default(),
    )?;
    assert_eq!(
        page.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        4
    );
    let historical = pair.native.read_tables_at(
        &middle,
        &selection,
        read(&requests, AnalysisReadModeV1::Changes(after)),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        Some(&BTreeSet::from(["alpha".to_owned()])),
    )?;
    assert_eq!(
        historical.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        2
    );
    assert_eq!(
        historical.extraction.meta.commit_revision,
        middle.revision()
    );
    assert_eq!(
        historical.scanned_through.commit_revision,
        middle.revision()
    );
    assert!(historical.exhausted);
    let first = pair.native.read_tables_at(
        &before,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )?;
    assert_eq!(
        first.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    Ok(())
}

#[test]
fn missing_keys_cancellation_and_limits_are_not_silent() -> TestResult {
    let pair = Pair::new()?;
    let source = identity("a");
    pair.append(&source, 1, 2, 10)?;
    pair.contexts(&[context("native", 1, 1)])?;
    let request = requests(&[("context_versions", &["owner_id", "entity_key"])])?;
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.contexts = Selection::Exact(vec![context("missing", 2, 1).key]);
    let page = pair.compare(
        &selection,
        &request,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
    )?;
    assert_eq!(page.extraction.missing_contexts.len(), 1);
    let control = AnalysisReadControl::default();
    control.cancel()?;
    assert!(matches!(
        pair.native.read_tables(
            &selection,
            read(&request, AnalysisReadModeV1::Complete),
            AnalysisExtractLimits::default(),
            &control
        ),
        Err(Error::AnalysisReadCancelled { .. })
    ));
    let selection = AnalysisSelectionV1::tenant([1; 16]);
    for limits in [
        AnalysisExtractLimits {
            input_bytes: 1,
            ..Default::default()
        },
        AnalysisExtractLimits {
            keys: Some(0),
            ..Default::default()
        },
    ] {
        assert!(pair
            .native
            .read_tables(
                &selection,
                read(&request, AnalysisReadModeV1::Complete),
                limits,
                &AnalysisReadControl::default()
            )
            .is_err());
    }
    let events = requests(&[("events", &["task_cookie"])])?;
    assert!(pair
        .native
        .read_tables(
            &selection,
            read(&events, AnalysisReadModeV1::Complete),
            AnalysisExtractLimits {
                scan_bytes: 1,
                ..Default::default()
            },
            &AnalysisReadControl::default()
        )
        .is_err());
    let notifications = BTreeMap::from([("notifications".to_owned(), None)]);
    assert!(matches!(
        pair.native.read_tables(
            &selection,
            read(&notifications, AnalysisReadModeV1::Metadata),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        ),
        Err(Error::AnalysisUnavailable {
            relation: "notifications",
            ..
        })
    ));
    pair.native.enable_notification_owner()?;
    assert!(pair
        .native
        .read_tables(
            &selection,
            read(&notifications, AnalysisReadModeV1::Metadata),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )
        .is_ok());
    let unsupported = BTreeMap::from([("traces".to_owned(), None)]);
    assert!(matches!(
        pair.native.read_tables(
            &selection,
            read(&unsupported, AnalysisReadModeV1::Metadata),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        ),
        Err(Error::Package {
            code: Code::Unsupported,
            ..
        })
    ));
    Ok(())
}

#[test]
fn fragmented_payload_is_bounded_before_assembly() -> TestResult {
    let pair = Pair::new()?;
    pair.contexts(&[context("native", 1, 1)])?;
    let (key, _) = pair
        .native
        .view()?
        .snapshot()
        .prefix(b"\0data/C")
        .next()
        .ok_or("context")??;
    let mut manifest = vec![1];
    manifest.extend_from_slice(&(u64::from(u32::MAX) + 1).to_be_bytes());
    let mut tx = pair.native.write()?;
    tx.native().insert(key, manifest);
    tx.commit([])?;
    let request = requests(&[("context_versions", &["body"])])?;
    let error = pair
        .native
        .read_tables(
            &AnalysisSelectionV1::tenant([1; 16]),
            read(&request, AnalysisReadModeV1::Complete),
            AnalysisExtractLimits {
                input_bytes: 1024 * 1024,
                ..Default::default()
            },
            &AnalysisReadControl::default(),
        )
        .err()
        .ok_or("unbounded payload")?;
    assert!(matches!(
        error,
        Error::AnalysisInputTooLarge {
            resource: "selected input bytes",
            ..
        }
    ));
    Ok(())
}

#[test]
fn context_headers_release_temporary_storage() -> TestResult {
    let pair = Pair::new()?;
    let contexts = (1..=20)
        .map(|entity| context("native", entity, 1))
        .collect::<Vec<_>>();
    pair.contexts(&contexts)?;
    let requests = requests(&[("context_versions", &["owner_id", "entity_key", "body"])])?;
    let all = AnalysisSelectionV1::tenant([1; 16]);
    let mut exact = all.clone();
    exact.contexts = Selection::Exact(contexts.iter().map(|context| context.key.clone()).collect());
    let extract = |selection: &AnalysisSelectionV1| {
        pair.native.read_tables(
            selection,
            read(&requests, AnalysisReadModeV1::Complete),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default(),
        )
    };
    let all_page = extract(&all)?;
    let exact_page = extract(&exact)?;
    assert_eq!(all_page.tables, exact_page.tables);
    assert_eq!(
        all_page.extraction.input_bytes - all.project(&requests)?.allocation_bytes(),
        exact_page.extraction.input_bytes - exact.project(&requests)?.allocation_bytes()
    );
    Ok(())
}

#[test]
fn native_metadata_and_indexes_survive_compaction_and_reopen() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("store");
    let store = NativeStore::open(&root)?;
    let initial = store.view()?.meta();
    assert_eq!(
        initial.schema_version,
        araphor_data::analysis::ANALYSIS_SCHEMA_VERSION as u32
    );
    assert_eq!(initial.recovery_epoch, 1);
    store.commit_contexts(&[context("beta", 1, 1), context("alpha", 2, 1)])?;
    let revision = store.view()?.revision();
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.meta().recovery_epoch, initial.recovery_epoch);
    assert_eq!(store.view()?.meta().store_uuid, initial.store_uuid);
    let requests = requests(&[("context_versions", &["owner_id", "body"])])?;
    let page = store.read_tables_at(
        &store.read_at(revision)?,
        &AnalysisSelectionV1::tenant([1; 16]),
        read(&requests, AnalysisReadModeV1::Complete),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )?;
    assert_eq!(
        page.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        2
    );
    Ok(())
}

#[test]
fn recovery_rejects_missing_or_extra_context_headers() -> TestResult {
    for prefix in [
        b"\0data/context/tenant/".as_slice(),
        b"\0data/context/owner/",
    ] {
        for extra in [false, true] {
            let dir = tempfile::tempdir()?;
            let root = dir.path().join("store");
            let store = NativeStore::open(&root)?;
            store.commit_contexts(&[context("native", 1, 1)])?;
            let (key, value) = store
                .view()?
                .snapshot()
                .prefix(prefix)
                .next()
                .ok_or("header")??;
            let mut tx = store.write()?;
            if extra {
                let mut changed = key.to_vec();
                let last = changed.last_mut().ok_or("key")?;
                *last = last.wrapping_add(1);
                tx.native().insert(changed, value);
            } else {
                tx.native().remove(key);
            }
            tx.commit([])?;
            drop(store);
            assert!(NativeStore::open(&root).is_err());
        }
    }
    Ok(())
}
