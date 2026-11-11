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
use sdk::arrow_array::{Array, ArrayRef, BinaryArray, StringArray, UInt32Array, UInt64Array};
use std::sync::Arc;

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

fn assert_table(
    page: &AnalysisPositionPageV1,
    name: &str,
    columns: Vec<(&str, ArrayRef)>,
) -> TestResult {
    let schema = &AnalysisStore::table_schemas()[name];
    let mut columns = columns
        .into_iter()
        .map(|(name, array)| Ok((schema.index_of(name)?, array)))
        .collect::<Result<Vec<_>, sdk::arrow_schema::ArrowError>>()?;
    columns.sort_by_key(|(index, _)| *index);
    let schema =
        Arc::new(schema.project(&columns.iter().map(|(index, _)| *index).collect::<Vec<_>>())?);
    let expected = sdk::RecordBatch::try_new(
        schema,
        columns.into_iter().map(|(_, array)| array).collect(),
    )?;
    assert_eq!(page.tables.get(name).ok_or("table absent")?, &[expected]);
    Ok(())
}

fn assert_witnesses(page: &AnalysisPositionPageV1, expected: Vec<(EvidenceIntakeIdentityV1, u64)>) {
    let expected = expected
        .into_iter()
        .map(|(identity, cursor)| araphor_data::AnalysisWitnessV1 {
            identity: identity.into(),
            cursor,
            expires_utc_ns: 0,
        })
        .collect::<Vec<_>>();
    assert_eq!(page.extraction.witnesses, expected);
}

fn assert_contexts(page: &AnalysisPositionPageV1, expected: &[araphor_data::AnalysisContextRefV1]) {
    assert_eq!(page.extraction.references.len(), expected.len());
    for (actual, expected) in page.extraction.references.iter().zip(expected) {
        assert_eq!(actual.context(), Some(expected));
        assert!(actual.result().is_none());
        assert_eq!(
            actual.origins(),
            &[araphor_data::AnalysisReferenceOriginV1::Context]
        );
    }
}

struct Fixture {
    native: NativeStore,
    _directory: tempfile::TempDir,
}

impl Fixture {
    fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        Ok(Self {
            native: NativeStore::open(&directory.path().join("native"))?,
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
        Ok(())
    }

    fn contexts(&self, contexts: &[AnalysisContextVersionV1]) -> araphor_data::Result<()> {
        self.native.commit_contexts(contexts)?;
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
        Ok(())
    }

    fn capture(
        &self,
        selection: &AnalysisSelectionV1,
        requests: &AnalysisTableRequests,
        mode: AnalysisReadModeV1,
        limits: AnalysisExtractLimits,
    ) -> Result<AnalysisPositionPageV1, Box<dyn std::error::Error>> {
        let page = self.native.read_tables(
            selection,
            read(requests, mode),
            limits,
            &AnalysisReadControl::default(),
        )?;
        assert_eq!(page.extraction.meta, self.native.view()?.meta());
        assert!(page.extraction.missing_results.is_empty());
        Ok(page)
    }
}

#[test]
fn native_arrow_matches_current_inputs_and_headers() -> TestResult {
    let fixture = Fixture::new()?;
    let a = identity("a");
    let b = identity("b");
    fixture.append(&a, 1, 3, 10)?;
    fixture.append(&b, 1, 2, 20)?;
    fixture.append(&a, 5, 1, 30)?;
    fixture.coverage(&a)?;
    fixture.contexts(&[
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
    let page = fixture.capture(
        &selection,
        &requests,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
    )?;
    assert_table(
        &page,
        "events",
        vec![
            (
                "node_id",
                Arc::new(StringArray::from(vec!["a", "a", "a", "b", "b", "a"])),
            ),
            (
                "task_cookie",
                Arc::new(UInt64Array::from(vec![1, 2, 3, 1, 2, 5])),
            ),
            (
                "source_cursor",
                Arc::new(UInt64Array::from(vec![1, 2, 3, 1, 2, 5])),
            ),
            (
                "commit_revision",
                Arc::new(UInt64Array::from(vec![1, 1, 1, 2, 2, 3])),
            ),
            (
                "ordinal",
                Arc::new(UInt32Array::from(vec![0, 1, 2, 0, 1, 0])),
            ),
            (
                "received_utc_ns",
                Arc::new(UInt64Array::from(vec![10, 10, 10, 20, 20, 30])),
            ),
        ],
    )?;
    assert_table(
        &page,
        "coverage",
        vec![
            ("node_id", Arc::new(StringArray::from(vec!["a", "a", "b"]))),
            ("source_epoch", Arc::new(UInt64Array::from(vec![1, 1, 1]))),
            (
                "kind",
                Arc::new(StringArray::from(vec!["receipt", "pending", "receipt"])),
            ),
            (
                "state",
                Arc::new(StringArray::from(vec!["reported", "pending", "unknown"])),
            ),
            (
                "first_cursor",
                Arc::new(UInt64Array::from(vec![None, Some(4), None])),
            ),
            (
                "last_cursor",
                Arc::new(UInt64Array::from(vec![None, Some(4), None])),
            ),
            (
                "coverage_revision",
                Arc::new(UInt64Array::from(vec![1, 1, 0])),
            ),
        ],
    )?;
    assert_table(
        &page,
        "context_versions",
        vec![
            (
                "owner_id",
                Arc::new(StringArray::from(vec!["alpha", "alpha", "zeta"])),
            ),
            (
                "entity_key",
                Arc::new(BinaryArray::from_iter_values([vec![1], vec![3], vec![2]])),
            ),
            ("owner_revision", Arc::new(UInt64Array::from(vec![0, 2, 1]))),
            (
                "commit_revision",
                Arc::new(UInt64Array::from(vec![5, 5, 5])),
            ),
            (
                "body",
                Arc::new(BinaryArray::from_iter_values([
                    vec![1; 16],
                    vec![3; 16],
                    vec![2; 16],
                ])),
            ),
        ],
    )?;
    assert_witnesses(
        &page,
        (1..=3)
            .map(|cursor| (a.clone(), cursor))
            .chain((1..=2).map(|cursor| (b.clone(), cursor)))
            .chain([(a.clone(), 5)])
            .collect(),
    );
    let contexts = [
        context("alpha", 1, 0),
        context("alpha", 3, 2),
        context("zeta", 2, 1),
    ]
    .into_iter()
    .map(|context| araphor_data::AnalysisContextRefV1 {
        key: context.key,
        commit_revision: 5,
    })
    .collect::<Vec<_>>();
    assert_contexts(&page, &contexts);
    assert!(page.extraction.missing_contexts.is_empty());
    assert_eq!(page.received_min, Some(10));
    assert_eq!(
        page.scanned_through,
        StorePositionV1 {
            commit_revision: 5,
            ordinal: u32::MAX
        }
    );
    assert!(page.exhausted);
    for (source, identity, contiguous, coverage) in [
        (&page.extraction.sources[0], &a, 3, 1),
        (&page.extraction.sources[1], &b, 2, 0),
    ] {
        assert_eq!(
            source.receipt,
            araphor_data::AnalysisSourceReceiptV1 {
                identity: identity.clone(),
                cpu_id: 0,
                contiguous_cursor: contiguous,
                coverage_revision: coverage,
                retained_floor: 0,
            }
        );
        assert!(source.expired.is_empty());
        assert!(source.recovery.is_empty());
    }
    assert_eq!(
        page.extraction.sources[0].pending,
        [araphor_data::AnalysisGapV1 {
            first_cursor: 4,
            last_cursor: 4,
            commit_revision: 5
        }]
    );
    assert!(page.extraction.sources[1].pending.is_empty());
    assert_eq!(
        page.extraction.sources[0].coverage_report,
        Some(
            CoverageReport {
                source_id: a.source_id.to_vec(),
                source_epoch: 1,
                cpu_id: 0,
                revision: 1,
                ..Default::default()
            }
            .encode_to_vec()
        )
    );
    assert_eq!(page.extraction.sources[1].coverage_report, None);
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
    let fixture = Fixture::new()?;
    let a = identity("a");
    fixture.append(&a, 1, 6, 10)?;
    fixture.append(&a, 7, 3, 20)?;
    let requests = requests(&[(
        "events",
        &[
            "source_cursor",
            "commit_revision",
            "ordinal",
            "received_utc_ns",
        ],
    )])?;
    let mut selection = AnalysisSelectionV1::new([1; 16], vec![a.clone()]);
    selection.cursor_from = Bound::Included(2);
    selection.cursor_until = Bound::Included(8);
    let limits = AnalysisExtractLimits {
        page_rows: 2,
        ..Default::default()
    };
    let mut after = None;
    let mut cursors = Vec::new();
    let mut pages = [vec![2, 3], vec![4, 5], vec![6, 7], vec![8]].into_iter();
    loop {
        let page = fixture.capture(
            &selection,
            &requests,
            AnalysisReadModeV1::Page(after),
            limits,
        )?;
        let expected = pages.next().ok_or("extra page")?;
        let revisions = expected
            .iter()
            .map(|cursor| if *cursor <= 6 { 1 } else { 2 })
            .collect::<Vec<_>>();
        let ordinals = expected
            .iter()
            .map(|cursor| {
                if *cursor <= 6 {
                    *cursor as u32 - 1
                } else {
                    *cursor as u32 - 7
                }
            })
            .collect::<Vec<_>>();
        let received = expected
            .iter()
            .map(|cursor| if *cursor <= 6 { 10 } else { 20 })
            .collect::<Vec<_>>();
        assert_table(
            &page,
            "events",
            vec![
                (
                    "source_cursor",
                    Arc::new(UInt64Array::from(expected.clone())),
                ),
                (
                    "commit_revision",
                    Arc::new(UInt64Array::from(revisions.clone())),
                ),
                ("ordinal", Arc::new(UInt32Array::from(ordinals.clone()))),
                (
                    "received_utc_ns",
                    Arc::new(UInt64Array::from(received.clone())),
                ),
            ],
        )?;
        assert_witnesses(
            &page,
            expected.iter().map(|cursor| (a.clone(), *cursor)).collect(),
        );
        assert_contexts(&page, &[]);
        assert!(page.extraction.missing_contexts.is_empty());
        assert_eq!(page.received_min, received.iter().copied().min());
        let source = &page.extraction.sources[0];
        assert_eq!(
            source.receipt,
            araphor_data::AnalysisSourceReceiptV1 {
                identity: a.clone(),
                cpu_id: 0,
                contiguous_cursor: 9,
                coverage_revision: 0,
                retained_floor: 0,
            }
        );
        assert_eq!(source.commit_revision, 2);
        assert!(
            source.pending.is_empty() && source.expired.is_empty() && source.recovery.is_empty()
        );
        assert_eq!(source.coverage_report, None);
        assert_eq!(
            page.scanned_through,
            if page.exhausted {
                StorePositionV1 {
                    commit_revision: 2,
                    ordinal: u32::MAX,
                }
            } else {
                StorePositionV1 {
                    commit_revision: *revisions.last().ok_or("revision")?,
                    ordinal: *ordinals.last().ok_or("ordinal")?,
                }
            }
        );
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
    assert!(pages.next().is_none());
    assert_eq!(cursors, (2..=8).collect::<Vec<_>>());
    selection.received_from = Bound::Included(20);
    let page = fixture.capture(
        &selection,
        &requests,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
    )?;
    assert_table(
        &page,
        "events",
        vec![
            ("source_cursor", Arc::new(UInt64Array::from(vec![7, 8]))),
            ("commit_revision", Arc::new(UInt64Array::from(vec![2, 2]))),
            ("ordinal", Arc::new(UInt32Array::from(vec![0, 1]))),
            ("received_utc_ns", Arc::new(UInt64Array::from(vec![20, 20]))),
        ],
    )?;
    assert_witnesses(&page, vec![(a.clone(), 7), (a.clone(), 8)]);
    assert_contexts(&page, &[]);
    assert_eq!(page.received_min, Some(20));
    assert!(page.exhausted);
    assert_eq!(
        page.scanned_through,
        StorePositionV1 {
            commit_revision: 2,
            ordinal: u32::MAX
        }
    );
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
    let fixture = Fixture::new()?;
    let source = identity("a");
    fixture.append(&source, 1, 1, 10)?;
    fixture.contexts(&[context("zeta", 4, 1)])?;
    let before = fixture.native.view()?;
    fixture.append(&source, 2, 1, 20)?;
    fixture.contexts(&[
        context("zeta", 3, 2),
        context("alpha", 2, 2),
        context("alpha", 1, 1),
    ])?;
    let middle = fixture.native.view()?;
    fixture.contexts(&[context("alpha", 9, 3)])?;
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
    let page = fixture.capture(
        &selection,
        &requests,
        AnalysisReadModeV1::Changes(after),
        AnalysisExtractLimits::default(),
    )?;
    assert_table(
        &page,
        "events",
        vec![
            ("source_cursor", Arc::new(UInt64Array::from(vec![2]))),
            ("commit_revision", Arc::new(UInt64Array::from(vec![3]))),
            ("ordinal", Arc::new(UInt32Array::from(vec![0]))),
        ],
    )?;
    assert_table(
        &page,
        "context_versions",
        vec![
            (
                "owner_id",
                Arc::new(StringArray::from(vec!["alpha", "alpha", "zeta", "alpha"])),
            ),
            (
                "entity_key",
                Arc::new(BinaryArray::from_iter_values([
                    vec![1],
                    vec![2],
                    vec![3],
                    vec![9],
                ])),
            ),
            (
                "owner_revision",
                Arc::new(UInt64Array::from(vec![1, 2, 2, 3])),
            ),
            (
                "commit_revision",
                Arc::new(UInt64Array::from(vec![4, 4, 4, 5])),
            ),
        ],
    )?;
    let references = [
        ("alpha", 1, 1, 4),
        ("alpha", 2, 2, 4),
        ("alpha", 9, 3, 5),
        ("zeta", 3, 2, 4),
    ]
    .into_iter()
    .map(
        |(owner, entity, revision, commit_revision)| araphor_data::AnalysisContextRefV1 {
            key: context(owner, entity, revision).key,
            commit_revision,
        },
    )
    .collect::<Vec<_>>();
    assert_contexts(&page, &references);
    assert_witnesses(&page, vec![(source.clone(), 2)]);
    assert!(page.extraction.missing_contexts.is_empty());
    assert_eq!(page.received_min, Some(20));
    assert_eq!(
        page.scanned_through,
        StorePositionV1 {
            commit_revision: 5,
            ordinal: u32::MAX
        }
    );
    assert!(page.exhausted);
    assert_eq!(page.extraction.sources.len(), 1);
    assert_eq!(page.extraction.sources[0].commit_revision, 3);
    assert_eq!(page.extraction.sources[0].receipt.contiguous_cursor, 2);
    assert!(page.extraction.sources[0].pending.is_empty());
    assert_eq!(
        page.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        4
    );
    let historical = fixture.native.read_tables_at(
        &middle,
        &selection,
        read(&requests, AnalysisReadModeV1::Changes(after)),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        Some(&BTreeSet::from(["alpha".to_owned()])),
    )?;
    assert_table(
        &historical,
        "events",
        vec![
            ("source_cursor", Arc::new(UInt64Array::from(vec![2]))),
            ("commit_revision", Arc::new(UInt64Array::from(vec![3]))),
            ("ordinal", Arc::new(UInt32Array::from(vec![0]))),
        ],
    )?;
    assert_table(
        &historical,
        "context_versions",
        vec![
            (
                "owner_id",
                Arc::new(StringArray::from(vec!["alpha", "alpha"])),
            ),
            (
                "entity_key",
                Arc::new(BinaryArray::from_iter_values([vec![1], vec![2]])),
            ),
            ("owner_revision", Arc::new(UInt64Array::from(vec![1, 2]))),
            ("commit_revision", Arc::new(UInt64Array::from(vec![4, 4]))),
        ],
    )?;
    assert_contexts(&historical, &references[..2]);
    assert_witnesses(&historical, vec![(source.clone(), 2)]);
    assert_eq!(historical.received_min, Some(20));
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
    let first = fixture.native.read_tables_at(
        &before,
        &selection,
        read(&requests, AnalysisReadModeV1::Complete),
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
        None,
    )?;
    assert_table(
        &first,
        "events",
        vec![
            ("source_cursor", Arc::new(UInt64Array::from(vec![1]))),
            ("commit_revision", Arc::new(UInt64Array::from(vec![1]))),
            ("ordinal", Arc::new(UInt32Array::from(vec![0]))),
        ],
    )?;
    assert_table(
        &first,
        "context_versions",
        vec![
            ("owner_id", Arc::new(StringArray::from(vec!["zeta"]))),
            (
                "entity_key",
                Arc::new(BinaryArray::from_iter_values([vec![4]])),
            ),
            ("owner_revision", Arc::new(UInt64Array::from(vec![1]))),
            ("commit_revision", Arc::new(UInt64Array::from(vec![2]))),
        ],
    )?;
    assert_contexts(
        &first,
        &[araphor_data::AnalysisContextRefV1 {
            key: context("zeta", 4, 1).key,
            commit_revision: 2,
        }],
    );
    assert_witnesses(&first, vec![(source.clone(), 1)]);
    assert_eq!(
        first.scanned_through,
        StorePositionV1 {
            commit_revision: 2,
            ordinal: u32::MAX
        }
    );
    assert_eq!(first.received_min, Some(10));
    assert!(first.exhausted);
    assert_eq!(
        first.tables["context_versions"]
            .iter()
            .map(|batch| batch.num_rows())
            .sum::<usize>(),
        1
    );
    for (page, revision, contiguous) in [(&page, 3, 2), (&historical, 3, 2), (&first, 1, 1)] {
        assert_eq!(page.extraction.sources.len(), 1);
        let header = &page.extraction.sources[0];
        assert_eq!(
            header.receipt,
            araphor_data::AnalysisSourceReceiptV1 {
                identity: source.clone(),
                cpu_id: 0,
                contiguous_cursor: contiguous,
                coverage_revision: 0,
                retained_floor: 0,
            }
        );
        assert_eq!(header.commit_revision, revision);
        assert!(
            header.pending.is_empty() && header.expired.is_empty() && header.recovery.is_empty()
        );
        assert_eq!(header.coverage_report, None);
    }
    Ok(())
}

#[test]
fn missing_keys_cancellation_and_limits_are_not_silent() -> TestResult {
    let fixture = Fixture::new()?;
    let source = identity("a");
    fixture.append(&source, 1, 2, 10)?;
    fixture.contexts(&[context("native", 1, 1)])?;
    let request = requests(&[("context_versions", &["owner_id", "entity_key"])])?;
    let mut selection = AnalysisSelectionV1::new([1; 16], Vec::new());
    selection.contexts = Selection::Exact(vec![context("missing", 2, 1).key]);
    let page = fixture.capture(
        &selection,
        &request,
        AnalysisReadModeV1::Complete,
        AnalysisExtractLimits::default(),
    )?;
    assert!(page.tables.is_empty());
    assert_eq!(
        page.extraction.missing_contexts,
        [context("missing", 2, 1).key]
    );
    assert_contexts(&page, &[]);
    assert_witnesses(&page, Vec::new());
    assert!(page.extraction.sources.is_empty());
    assert_eq!(page.received_min, None);
    assert_eq!(
        page.scanned_through,
        StorePositionV1 {
            commit_revision: 2,
            ordinal: u32::MAX
        }
    );
    assert!(page.exhausted);
    assert_eq!(page.extraction.missing_contexts.len(), 1);
    let control = AnalysisReadControl::default();
    control.cancel()?;
    assert!(matches!(
        fixture.native.read_tables(
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
        assert!(fixture
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
    assert!(fixture
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
        fixture.native.read_tables(
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
    fixture.native.enable_notification_owner()?;
    assert!(fixture
        .native
        .read_tables(
            &selection,
            read(&notifications, AnalysisReadModeV1::Metadata),
            AnalysisExtractLimits::default(),
            &AnalysisReadControl::default()
        )
        .is_ok());
    let source = araphor_data::TraceSourceV1::new(b"BEGIN { @x = count(); }".to_vec())?;
    let intent = araphor_data::TraceIntentV1 {
        tenant_id: [1; 16],
        request_id: [3; 16],
        bindings: vec![araphor_data::TraceBindingV1 {
            binding_id: [9; 16],
            namespace_uid: "namespace-a".into(),
            identity: araphor_data::TraceIdentityV1 {
                tenant_id: [1; 16],
                node_id: "node-a".into(),
                node_boot_id: [2; 16],
                request_id: [3; 16],
                execution_id: [3; 16],
                source_sha256: source.sha256,
            },
        }],
        source,
        authority: b"authorized-input".to_vec(),
        accepted_unix_ns: 100,
        deadline_unix_ns: 10_000,
        host_sensitive: false,
    };
    let state = fixture.native.accept_trace(&intent)?;
    let request = requests(&[(
        "traces",
        &[
            "request_id",
            "request_revision",
            "cancel_requested",
            "last_sequence",
        ],
    )])?;
    let page = fixture.capture(
        &selection,
        &request,
        AnalysisReadModeV1::Metadata,
        Default::default(),
    )?;
    assert_table(
        &page,
        "traces",
        vec![
            (
                "request_id",
                Arc::new(BinaryArray::from_iter_values([[3; 16]])),
            ),
            (
                "request_revision",
                Arc::new(UInt64Array::from(vec![state.revision])),
            ),
            (
                "cancel_requested",
                Arc::new(sdk::arrow_array::BooleanArray::from(vec![false])),
            ),
            ("last_sequence", Arc::new(UInt64Array::from(vec![0]))),
        ],
    )?;
    assert_eq!(page.extraction.trace_reads(), &[[3; 16]]);
    assert_contexts(&page, &[]);
    assert_witnesses(&page, Vec::new());
    let elided = BTreeMap::from([("traces".to_owned(), None)]);
    let page = fixture.capture(
        &selection,
        &elided,
        AnalysisReadModeV1::Metadata,
        Default::default(),
    )?;
    assert!(page.tables.is_empty());
    Ok(())
}

#[test]
fn fragmented_payload_is_bounded_before_assembly() -> TestResult {
    let fixture = Fixture::new()?;
    fixture.contexts(&[context("native", 1, 1)])?;
    let (key, _) = fixture
        .native
        .view()?
        .snapshot()
        .prefix(b"\0data/C")
        .next()
        .ok_or("context")??;
    let mut manifest = vec![1];
    manifest.extend_from_slice(&(u64::from(u32::MAX) + 1).to_be_bytes());
    let mut tx = fixture.native.write()?;
    tx.native().insert(key, manifest);
    tx.commit([])?;
    let request = requests(&[("context_versions", &["body"])])?;
    let error = fixture
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
    let fixture = Fixture::new()?;
    let contexts = (1..=20)
        .map(|entity| context("native", entity, 1))
        .collect::<Vec<_>>();
    fixture.contexts(&contexts)?;
    let requests = requests(&[("context_versions", &["owner_id", "entity_key", "body"])])?;
    let all = AnalysisSelectionV1::tenant([1; 16]);
    let mut exact = all.clone();
    exact.contexts = Selection::Exact(contexts.iter().map(|context| context.key.clone()).collect());
    let extract = |selection: &AnalysisSelectionV1| {
        fixture.native.read_tables(
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
