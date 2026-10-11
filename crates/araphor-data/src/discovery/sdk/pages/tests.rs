use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn input(cursors: &[u64], expected: u64, last: u64) -> Result<DiscoveryInputManifestV1> {
    let mut input = DiscoveryInputManifestV1::try_from(
        include_bytes!("../../../../../mithril-e2e/fixtures/discovery/manifest.json").as_slice(),
    )?;
    let record = input.records[0].clone();
    let context = input.contexts[0].clone();
    input.records.clear();
    input.contexts.clear();
    input.exclusions.clear();
    input.lifecycle.clear();
    input.coverage.truncate(1);
    input.coverage[0].first_cursor = 1;
    input.coverage[0].last_cursor = last;
    input.coverage[0].expected_records = expected;
    for &cursor in cursors {
        let mut record = record.clone();
        record.id.durable_cursor = cursor;
        let mut context = context.clone();
        context.record_id = record.id.clone();
        input.records.push(record);
        input.contexts.push(context);
    }
    Ok(input)
}

fn pages(input: &DiscoveryInputManifestV1, size: usize) -> Result<Vec<DiscoveryInputManifestV1>> {
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let pages = RecordedPages::new(input, size, &control)?.collect::<Result<Vec<_>>>()?;
    for page in &pages {
        page.validate()?;
    }
    Ok(pages)
}

#[test]
fn sparse_expected_keeps_capacity() -> TestResult {
    let mut input = input(&[1, 10_000], 10_000, 10_000)?;
    input.coverage[0].state = crate::DiscoveryCoverageStateV1::Unknown;
    input.coverage[0].gap_reasons = vec!["RECORDED_UNKNOWN".into()];
    let pages = pages(&input, 1)?;
    assert_eq!(pages.len(), 2);
    let ranges: Vec<_> = pages.iter().flat_map(|page| &page.coverage).collect();
    assert_eq!(
        (
            ranges[0].first_cursor,
            ranges[0].last_cursor,
            ranges[0].expected_records
        ),
        (1, 9999, 9999)
    );
    assert_eq!(
        (
            ranges[1].first_cursor,
            ranges[1].last_cursor,
            ranges[1].expected_records
        ),
        (10_000, 10_000, 1)
    );
    for range in ranges {
        assert_eq!(range.state, input.coverage[0].state);
        assert_eq!(range.gap_reasons, input.coverage[0].gap_reasons);
        assert_eq!(range.coverage_revision, input.coverage[0].coverage_revision);
        assert_eq!(
            range.coverage_interval_id,
            input.coverage[0].coverage_interval_id
        );
    }
    Ok(())
}

#[test]
fn expected_preserves_mismatches() -> TestResult {
    for expected in [0, 1, 2, 3, 10_000] {
        let input = input(&[1, 10_000], expected, 10_000)?;
        let pages = pages(&input, 1)?;
        let ranges: Vec<_> = pages.iter().flat_map(|page| &page.coverage).collect();
        assert_eq!(
            ranges
                .iter()
                .map(|range| range.expected_records)
                .sum::<u64>(),
            expected
        );
        assert_eq!(
            ranges.iter().any(|range| range.expected_records != 1),
            expected != 2
        );
        assert_eq!(ranges[0].last_cursor + 1, ranges[1].first_cursor);
        assert!(ranges
            .iter()
            .all(|range| range.expected_records <= range.last_cursor - range.first_cursor + 1));
    }
    Ok(())
}

#[test]
fn multiple_empty_ranges_survive() -> TestResult {
    let mut input = input(&[2, 4], 2, 4)?;
    let mut other = input.records[1].id.stream.clone();
    other.node_id = "zz-other-node".into();
    input.records[1].id.stream = other.clone();
    input.contexts[1].record_id = input.records[1].id.clone();
    input.coverage[0].last_cursor = 2;
    input.coverage[0].expected_records = 1;
    let mut range = input.coverage[0].clone();
    range.stream = other;
    range.last_cursor = 4;
    input.coverage.push(range);
    let mut empty = input.coverage[0].clone();
    empty.cpu_id += 1;
    empty.last_cursor = 8;
    empty.expected_records = 3;
    empty.state = crate::DiscoveryCoverageStateV1::Closed;
    input.coverage.push(empty.clone());
    input.records.reverse();
    input.contexts.reverse();
    let pages = pages(&input, 1)?;
    assert_eq!(pages.len(), 2);
    assert!(pages[0].records[0].id < pages[1].records[0].id);
    let ranges: Vec<_> = pages.iter().flat_map(|page| &page.coverage).collect();
    assert_eq!(ranges.len(), 3);
    assert_eq!(ranges.iter().filter(|range| ***range == empty).count(), 1);
    assert!(pages[0].coverage.contains(&empty));
    for original in &input.coverage {
        assert!(ranges.contains(&original));
    }
    Ok(())
}

#[test]
fn duplicate_groups_stay_together() -> TestResult {
    let mut input = input(&[2, 1, 2, 1, 3], 3, 3)?;
    let exclusion = DiscoveryUnresolvedV1 {
        record_id: input.records[1].id.clone(),
        reason: "EXCLUDED".into(),
    };
    input.exclusions = vec![exclusion.clone(), exclusion];
    let pages = pages(&input, 2)?;
    assert_eq!(pages.len(), 2);
    assert_eq!(
        pages[0]
            .records
            .iter()
            .map(|record| record.id.durable_cursor)
            .collect::<Vec<_>>(),
        vec![1, 1, 2, 2]
    );
    assert_eq!(pages[0].contexts.len(), 4);
    assert_eq!(pages[0].exclusions.len(), 2);
    assert_eq!(pages[1].records.len(), 1);
    for page in &pages {
        assert_eq!(page.schema_version, input.schema_version);
        assert_eq!(page.tenant_id, input.tenant_id);
        assert_eq!(page.source_revision, input.source_revision);
        assert_eq!(page.proof_kind, input.proof_kind);
        for record in &page.records {
            assert_eq!(
                page.records
                    .iter()
                    .filter(|candidate| candidate.id == record.id)
                    .count(),
                input
                    .records
                    .iter()
                    .filter(|candidate| candidate.id == record.id)
                    .count()
            );
        }
    }
    Ok(())
}

#[test]
fn orphan_rows_are_rejected() -> TestResult {
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let mut context = input(&[1], 1, 2)?;
    context.contexts[0].record_id.durable_cursor = 2;
    assert!(matches!(
        RecordedPages::new(&context, 1, &control),
        Err(crate::Error::DiscoveryInvalid {
            field: "orphan context",
            ..
        })
    ));
    let mut exclusion = input(&[1], 1, 2)?;
    let mut id = exclusion.records[0].id.clone();
    id.durable_cursor = 2;
    exclusion.exclusions.push(DiscoveryUnresolvedV1 {
        record_id: id,
        reason: "EXCLUDED".into(),
    });
    assert!(matches!(
        RecordedPages::new(&exclusion, 1, &control),
        Err(crate::Error::DiscoveryInvalid {
            field: "orphan exclusion",
            ..
        })
    ));
    Ok(())
}

#[test]
fn lifecycle_refs_follow_pages() -> TestResult {
    use crate::DiscoveryLifecycleCaseV1 as Case;
    let mut input = input(&[1, 2, 3], 3, 3)?;
    input.lifecycle = vec![
        DiscoveryLifecycleEntryV1 {
            case: Case::Startup,
            state: DiscoveryLifecycleStateV1::Recorded {
                records: vec![input.records[0].id.clone(), input.records[2].id.clone()],
            },
        },
        DiscoveryLifecycleEntryV1 {
            case: Case::SteadyWork,
            state: DiscoveryLifecycleStateV1::Declared {
                reason: "DECLARED".into(),
            },
        },
        DiscoveryLifecycleEntryV1 {
            case: Case::Shutdown,
            state: DiscoveryLifecycleStateV1::NotApplicable {
                reason: "NO_STOP".into(),
            },
        },
        DiscoveryLifecycleEntryV1 {
            case: Case::Restart,
            state: DiscoveryLifecycleStateV1::Unsupported {
                reason: "UNSUPPORTED".into(),
            },
        },
        DiscoveryLifecycleEntryV1 {
            case: Case::Recovery,
            state: DiscoveryLifecycleStateV1::Missing,
        },
    ];
    let pages = pages(&input, 1)?;
    assert_eq!(pages.len(), 3);
    assert_eq!(
        pages[1].lifecycle[0].state,
        DiscoveryLifecycleStateV1::Missing
    );
    for index in [0, 2] {
        assert_eq!(
            pages[index].lifecycle[0].state,
            DiscoveryLifecycleStateV1::Recorded {
                records: vec![input.records[index].id.clone()]
            }
        );
    }
    for page in &pages {
        assert_eq!(&page.lifecycle[1..], &input.lifecycle[1..]);
    }
    Ok(())
}

#[test]
fn empty_input_yields_page() -> TestResult {
    let mut input = input(&[], 0, 8)?;
    input.coverage.clear();
    let pages = pages(&input, 64)?;
    assert_eq!(pages, vec![input]);
    Ok(())
}

#[test]
fn empty_records_keep_range() -> TestResult {
    let input = input(&[], 3, 8)?;
    let pages = pages(&input, 64)?;
    assert_eq!(pages, vec![input]);
    Ok(())
}

#[test]
fn cancellation_stops_iteration() -> TestResult {
    let input = input(&[1, 2], 2, 2)?;
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    let mut pages = RecordedPages::new(&input, 1, &control)?;
    assert!(pages.next().transpose()?.is_some());
    control.cancel()?;
    assert!(matches!(
        pages.next(),
        Some(Err(crate::Error::AnalysisReadCancelled { .. }))
    ));
    assert!(pages.next().is_none());
    Ok(())
}

#[test]
fn zero_size_is_rejected() -> TestResult {
    let input = input(&[1], 1, 1)?;
    let control = AnalysisReadControl::with_timeout(std::time::Duration::from_secs(30))?;
    assert!(matches!(
        RecordedPages::new(&input, 0, &control),
        Err(crate::Error::DiscoveryInvalid {
            field: "recorded page size",
            ..
        })
    ));
    Ok(())
}
