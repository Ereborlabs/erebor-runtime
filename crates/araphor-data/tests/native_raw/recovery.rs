use super::*;
use araphor_data::{AnalysisGapV1, AnalysisRecoveryStatusV1};

#[test]
fn recovery_keeps_missing_input() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("data");
    let store = NativeStore::open(&root)?;
    let source = identity();
    let initial = store.view()?;
    assert_eq!(
        store.record_recovery_floor(&source, 2)?,
        AnalysisRecoveryStatusV1::Partial {
            first_cursor: 1,
            last_cursor: 2
        }
    );
    let first = store.view()?;
    assert!(first.source_receipt(&source)?.is_none());
    assert!(first
        .source_binding(
            source.tenant_id,
            &source.node_id,
            source.source_id,
            source.source_epoch
        )?
        .is_none());
    let gap = AnalysisGapV1 {
        first_cursor: 1,
        last_cursor: 2,
        commit_revision: first.revision(),
    };
    assert_eq!(store.recovery_gaps(&source, 0)?, vec![gap]);
    assert_eq!(store.recovery_gaps(&source, 1)?, vec![gap]);
    assert!(store.recovery_gaps(&source, 2)?.is_empty());
    assert!(initial.recovery_gaps(&source, 0)?.is_empty());
    let head = store.database().inner().journal_head()?;
    store.record_recovery_floor(&source, 2)?;
    store.record_recovery_floor(&source, 1)?;
    assert_eq!(store.view()?.revision(), first.revision());
    assert_eq!(store.database().inner().journal_head()?, head);
    store.accept_validated_batch(source.clone(), batch(3))?;
    assert_eq!(
        store
            .view()?
            .source_receipt(&source)?
            .ok_or("receipt")?
            .contiguous_cursor,
        0
    );
    store.record_recovery_floor(&source, 4)?;
    let second = store.view()?.revision();
    assert_eq!(
        store.recovery_gaps(&source, 2)?,
        vec![AnalysisGapV1 {
            first_cursor: 3,
            last_cursor: 4,
            commit_revision: second,
        }]
    );
    store.accept_validated_batch(source.clone(), batch(1))?;
    store.accept_validated_batch(source.clone(), batch(2))?;
    assert_eq!(
        store
            .view()?
            .source_receipt(&source)?
            .ok_or("receipt")?
            .contiguous_cursor,
        3
    );
    assert_eq!(
        store.record_recovery_floor(&source, 3)?,
        AnalysisRecoveryStatusV1::Complete
    );
    assert_eq!(
        store.record_recovery_floor(&source, 4)?,
        AnalysisRecoveryStatusV1::Partial {
            first_cursor: 4,
            last_cursor: 4,
        }
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop((initial, first, store));
    let store = NativeStore::open(&root)?;
    assert_eq!(store.read_at(1)?.recovery_gaps(&source, 0)?, vec![gap]);
    assert_eq!(store.recovery_gaps(&source, 0)?.len(), 2);
    assert_eq!(
        store
            .view()?
            .source_receipt(&source)?
            .ok_or("reopened receipt")?
            .contiguous_cursor,
        3
    );
    Ok(())
}

#[test]
fn recovery_cursor_bounds() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = NativeStore::open(&directory.path().join("data"))?;
    let source = identity();
    for last in 1..=258 {
        store.record_recovery_floor(&source, last)?;
    }
    let page = store.recovery_gaps(&source, 0)?;
    assert_eq!(
        page.len(),
        araphor_data::analysis::MAX_ANALYSIS_PAGE_RECORDS
    );
    assert_eq!(
        (
            page[0].first_cursor,
            page.last().ok_or("last gap")?.last_cursor
        ),
        (1, 256)
    );
    let rest = store.recovery_gaps(&source, 256)?;
    assert_eq!(
        rest.iter().map(|gap| gap.first_cursor).collect::<Vec<_>>(),
        vec![257, 258]
    );
    assert!(store.recovery_gaps(&source, u64::MAX)?.is_empty());
    let mut other = source.clone();
    other.tenant_id = [4; 16];
    assert!(store.recovery_gaps(&other, 0)?.is_empty());
    store.record_recovery_floor(&other, u64::MAX)?;
    assert_eq!(
        store.recovery_gaps(&other, u64::MAX - 1)?[0].last_cursor,
        u64::MAX
    );
    let revision = store.view()?.revision();
    store.record_recovery_floor(&other, u64::MAX)?;
    assert_eq!(store.view()?.revision(), revision);
    other.node_id.clear();
    assert!(store.record_recovery_floor(&other, 1).is_err());
    assert!(store.recovery_gaps(&other, 0).is_err());
    assert_eq!(store.view()?.revision(), revision);
    Ok(())
}

#[test]
fn recovery_rejects_corruption() -> TestResult {
    for case in 0..9 {
        let directory = tempfile::tempdir()?;
        let root = directory.path().join("data");
        let store = NativeStore::open(&root)?;
        let source = identity();
        store.record_recovery_floor(&source, 2)?;
        store.record_recovery_floor(&source, 4)?;
        let mut gap = AnalysisGapV1 {
            first_cursor: 3,
            last_cursor: 4,
            commit_revision: 2,
        };
        let mut record_source = source.clone();
        match case {
            0 => gap.first_cursor = 0,
            1 => gap.first_cursor = 5,
            2 => gap.commit_revision = 99,
            3 => record_source.tenant_id = [9; 16],
            4 => gap.first_cursor = 2,
            5 => gap.commit_revision = 1,
            _ => (),
        }
        let key = [
            b"\0data/@source-recovery/".as_slice(),
            &source.key(),
            &4u64.to_be_bytes(),
        ]
        .concat();
        let mut bytes = vec![0];
        serde::Serialize::serialize(
            &(record_source, gap),
            &mut rmp_serde::Serializer::new(&mut bytes)
                .with_bytes(rmp_serde::config::BytesMode::ForceIterables),
        )?;
        let mut write = store.write()?;
        write.native().insert(key, bytes);
        let notice = b"\0data/relation/recovery_gaps";
        match case {
            6 => write.native().remove(notice),
            7 => write.native().insert(notice, 1u64.to_be_bytes()),
            8 => write.native().insert(notice, 99u64.to_be_bytes()),
            _ => (),
        }
        write.commit([])?;
        drop(store);
        assert!(NativeStore::open(&root).is_err(), "case {case}");
    }
    Ok(())
}
