use super::*;
use araphor_data::{
    AnalysisStreamIdentityV1, AnalysisWitnessV1, EvidenceRecord, ValidatedEvidenceBatchV1,
};

const RAW: &[u8] = b"\0data/ref/raw/";
const SEGMENT: &[u8] = b"\0data/ref/segment/";

struct PinsFixture {
    request: AnalysisResultCommitV1,
    sizes: BTreeMap<u64, u64>,
}

impl PinsFixture {
    fn new(store: &NativeStore) -> Result<Self, Box<dyn std::error::Error>> {
        let scope = scope();
        store.register_processor(&scope, ProcessorClassV1::Optional, 1)?;
        let mut sizes = BTreeMap::new();
        for cursor in 1..=9 {
            if cursor == 6 {
                store.checkpoint()?;
            }
            let frame = Vec::<u8>::try_from(&EvidenceRecord {
                task_cookie: cursor,
                observed_boottime_ns: cursor,
                ..Default::default()
            })?;
            sizes.insert(cursor, frame.len() as u64);
            store.accept_validated_batch(
                scope.identity.clone(),
                ValidatedEvidenceBatchV1 {
                    cpu_id: 0,
                    first_cursor: cursor,
                    last_cursor: cursor,
                    intake_utc_ns: 100,
                    frame_ends: vec![frame.len()],
                    framed_records: frame.into(),
                },
            )?;
        }
        let request = AnalysisResultCommitV1 {
            scope: scope.clone(),
            expected_cursor: 0,
            consumed_cursor: 9,
            coverage_revision: 0,
            context_revision: 0,
            result_id: "grouped-pins".into(),
            body: vec![1, 2, 3],
            created_utc_ns: 1000,
            witnesses: [1, 2, 4, 5, 6, 7, 9]
                .into_iter()
                .map(|cursor| AnalysisWitnessV1 {
                    identity: AnalysisStreamIdentityV1::Evidence(scope.identity.clone()),
                    cursor,
                    expires_utc_ns: if [5, 9].contains(&cursor) { 3000 } else { 2000 },
                })
                .collect(),
            context_refs: Vec::new(),
        };
        store.commit_result(&request)?;
        Ok(Self { request, sizes })
    }

    fn check(&self, store: &NativeStore, results: usize) -> TestResult {
        let view = store.view()?;
        let mut actual = Vec::new();
        for entry in view.snapshot().prefix(RAW) {
            let (key, value) = entry?;
            assert_eq!(key.len(), RAW.len() + 24);
            let words = key[RAW.len()..]
                .chunks_exact(8)
                .map(|bytes| u64::from_be_bytes(bytes.try_into().unwrap()))
                .collect::<Vec<_>>();
            let ranges: Vec<(u64, u64)> = rmp_serde::from_slice(&value[1..])?;
            let reverse = [
                SEGMENT,
                &words[1].to_be_bytes(),
                &words[0].to_be_bytes(),
                &words[2].to_be_bytes(),
            ]
            .concat();
            assert_eq!(
                view.snapshot().get(reverse)?.as_deref(),
                Some(words[2].to_be_bytes().as_slice())
            );
            actual.push((words[1], words[2], ranges));
        }
        assert_eq!(actual.len(), 4 * results);
        assert_eq!(view.snapshot().prefix(SEGMENT).count(), 4 * results);
        let segments = actual
            .iter()
            .map(|value| value.0)
            .collect::<std::collections::BTreeSet<_>>();
        assert_eq!(segments.len(), 2);
        let mut actual = actual
            .into_iter()
            .map(|(_, expires, ranges)| (expires, ranges))
            .collect::<Vec<_>>();
        actual.sort();
        let mut expected = (0..results)
            .flat_map(|_| {
                [
                    (2000, vec![(1, 2), (4, 4)]),
                    (2000, vec![(6, 7)]),
                    (3000, vec![(5, 5)]),
                    (3000, vec![(9, 9)]),
                ]
            })
            .collect::<Vec<_>>();
        expected.sort();
        assert_eq!(actual, expected);
        #[derive(serde::Deserialize)]
        struct Saved {
            request: AnalysisResultCommitV1,
        }
        let mut found = 0;
        for entry in view.snapshot().prefix(b"\0data/@progress/result/") {
            let (key, value) = entry?;
            if key.len() != b"\0data/@progress/result/".len() + 8 {
                continue;
            }
            let saved: Saved = rmp_serde::from_slice(&value[1..])?;
            assert_eq!(saved.request.witnesses, self.request.witnesses);
            found += 1;
        }
        assert_eq!(found, results);
        for (now, cursors) in [
            (1500, vec![1, 2, 4, 5, 6, 7, 9]),
            (2500, vec![5, 9]),
            (3500, Vec::new()),
        ] {
            let usage = store.witness_usage([1; 16], now)?;
            assert_eq!(
                usage.referenced_bytes,
                cursors.iter().map(|cursor| self.sizes[cursor]).sum::<u64>()
            );
            assert_eq!(
                usage.segment_bytes - usage.extra_segment_bytes,
                usage.referenced_bytes
            );
        }
        assert_eq!(store.witness_usage([2; 16], 1500)?.referenced_bytes, 0);
        Ok(())
    }
}

#[test]
fn grouped_pins_preserve_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let limits = araphor_data::RetentionLimitsV1 {
        raw_max_age_ns: Some(50),
        ..Default::default()
    };
    let store = NativeStore::open_with_retention(&root, limits)?;
    let fixture = PinsFixture::new(&store)?;
    fixture.check(&store, 1)?;
    let historical = store.view()?;
    let mut second = fixture.request.clone();
    second.scope.processor_id = "second-pins".into();
    second.result_id = "second-pins".into();
    store.register_processor(&second.scope, ProcessorClassV1::Optional, 1)?;
    store.commit_result(&second)?;
    assert_eq!(historical.snapshot().prefix(RAW).count(), 4);
    fixture.check(&store, 2)?;
    store.checkpoint()?;
    assert_eq!(
        araphor_data::EvidenceRetentionOwner::new(&store)
            .step(2500)?
            .removed_records,
        0
    );
    let backup = root.join("backups/pins");
    store.backup(&backup)?;
    drop(historical);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open_with_retention(&root, limits)?;
    fixture.check(&store, 2)?;
    let restored = NativeStore::restore(&backup, &directory.path().join("restored"))?;
    fixture.check(&restored, 2)?;
    let expired = araphor_data::EvidenceRetentionOwner::new(&store).step(3500)?;
    assert_eq!(expired.removed_records, 9);
    assert_eq!(store.witness_usage([1; 16], 3500)?.referenced_bytes, 0);
    drop(store);
    let store = NativeStore::open_with_retention(&root, limits)?;
    assert_eq!(store.witness_usage([1; 16], 3500)?.referenced_bytes, 0);
    assert_eq!(
        store
            .processor_result(&fixture.request.scope)?
            .ok_or("result")?
            .body,
        fixture.request.body
    );
    Ok(())
}

#[test]
fn grouped_pins_reject_corruption() -> TestResult {
    for fault in [
        "bounds", "overlap", "adjacent", "extra", "missing", "reverse",
    ] {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let fixture = PinsFixture::new(&store)?;
        fixture.check(&store, 1)?;
        let view = store.view()?;
        let mut selected = None;
        for entry in view.snapshot().prefix(RAW) {
            let (key, value) = entry?;
            let ranges: Vec<(u64, u64)> = rmp_serde::from_slice(&value[1..])?;
            if ranges == vec![(1, 2), (4, 4)] {
                selected = Some(key);
                break;
            }
        }
        let key = selected.ok_or("sparse group")?;
        let mut tx = store.write()?;
        match fault {
            "missing" => tx.native().remove(key),
            "reverse" => {
                let suffix = &key[RAW.len()..];
                let reverse = [SEGMENT, &suffix[8..16], &suffix[..8], &suffix[16..]].concat();
                tx.native().remove(reverse);
            }
            _ => {
                let ranges = match fault {
                    "bounds" => vec![(1u64, u64::MAX)],
                    "overlap" => vec![(1, 2), (2, 4)],
                    "adjacent" => vec![(1, 1), (2, 2), (4, 4)],
                    _ => vec![(1, 4)],
                };
                let mut value = vec![0];
                value.extend(rmp_serde::to_vec(&ranges)?);
                tx.native().insert(key, value);
            }
        }
        tx.commit([])?;
        if matches!(fault, "bounds" | "overlap" | "adjacent") {
            assert!(store.witness_usage([1; 16], 1500).is_err(), "{fault}");
        }
        drop((view, store));
        assert!(NativeStore::open(&root).is_err(), "{fault}");
    }
    Ok(())
}

#[test]
fn old_pin_format_rejects() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut tx = store.write()?;
    tx.native().insert(b"\0data/format", 10u64.to_be_bytes());
    assert!(matches!(
        tx.commit([]),
        Err(Error::NativeState { field: "format version", .. })
    ));
    drop(store);
    assert!(matches!(
        NativeStore::open(&root),
        Err(Error::NativeState {
            field: "format version",
            ..
        })
    ));
    Ok(())
}
