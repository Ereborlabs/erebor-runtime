use super::*;
use crate::analysis::native::context::ContextRecord;
use crate::{AnalysisContextKeyV1, AnalysisContextVersionV1, ContextSensitivityV1};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn usage_tracks_transactions() -> TestResult {
    let directory = tempfile::tempdir()?;
    let root = directory.path().join("analysis");
    let store = NativeStore::open(&root)?;
    let context = |tenant| AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [tenant; 16],
            owner_id: "p".into(),
            entity_key: vec![1],
            lifetime_key: vec![1],
            owner_revision: 1,
        },
        valid_from_utc_ns: Some(1),
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![1],
    };
    let first = context(1);
    let second = context(2);
    store.commit_context(&first)?;
    let before = store.view()?;
    let entries = before.snapshot.iter().collect::<fjall::Result<Vec<_>>>()?;
    let cursor = before.snapshot.cursor()?;
    let sequence = store.database.inner().visible_seqno();
    let inventory = |tx: &fjall::BranchWriteTransaction<'_>| -> TestResult<[u64; 3]> {
        let mut counts = [0; 3];
        for entry in tx.prefix(b"\0data/C") {
            let (key, _) = entry?;
            assert_eq!(key.len(), 15);
            let id = NativeStore::number(&key[7..])?;
            let row = ContextRecord::load(id, |key| Records::staged(key, tx))?;
            let tenant = usize::from(row.version.key.tenant_id[0]);
            assert!(matches!(tenant, 1 | 2));
            assert_eq!(row.version.key.tenant_id, [tenant as u8; 16]);
            counts[0] += 1;
            counts[tenant] += 1;
        }
        Ok(counts)
    };
    for (tenant, expected) in [(0, [0, 1, 0]), (1, [0, 1, 0]), (2, [0; 3])] {
        assert_eq!(
            RevisionCounts::read([tenant; 16], |key| Records::read(key, &before.snapshot))?,
            expected
        );
    }
    let mut tx = store.write()?;
    tx.context(&second, None)?;
    assert_eq!(inventory(&tx.transaction)?, [2, 1, 1]);
    for (tenant, expected) in [(0, [0, 2, 0]), (1, [0, 1, 0]), (2, [0, 1, 0])] {
        assert_eq!(
            RevisionCounts::read([tenant; 16], |key| Records::staged(key, &tx.transaction))?,
            expected
        );
    }
    assert_eq!(before.context(&second.key)?, None);
    assert_eq!(
        RevisionCounts::read([0; 16], |key| Records::read(key, &before.snapshot))?,
        [0, 1, 0]
    );
    let id = ContextRecord::id(&first.key, |key| Records::staged(key, &tx.transaction))?
        .ok_or("first context")?;
    Records::remove(&mut tx.transaction, Records::key(b'C', id))?;
    for tenant in [[0; 16], [1; 16]] {
        let mut counts = RevisionCounts::read(tenant, |key| Records::staged(key, &tx.transaction))?;
        counts[1] -= 1;
        Records::stage(
            &mut tx.transaction,
            RevisionCounts::key(tenant),
            Records::encode(&counts)?,
        );
    }
    assert_eq!(inventory(&tx.transaction)?, [1, 0, 1]);
    for (tenant, expected) in [(0, [0, 1, 0]), (1, [0; 3]), (2, [0, 1, 0])] {
        assert_eq!(
            RevisionCounts::read([tenant; 16], |key| Records::staged(key, &tx.transaction))?,
            expected
        );
    }
    tx.rollback();
    assert_eq!(store.meta()?, before.meta());
    let current = store.view()?;
    assert_eq!(
        current.snapshot.iter().collect::<fjall::Result<Vec<_>>>()?,
        entries
    );
    assert_eq!(current.snapshot.revision(), before.snapshot.revision());
    assert_eq!(current.snapshot.cursor()?, cursor);
    assert_eq!(store.database.inner().visible_seqno(), sequence);
    assert_eq!(current.context(&first.key)?, Some((first.clone(), 1)));
    assert_eq!(current.context(&second.key)?, None);
    drop(current);
    drop(before);
    drop(store);
    let store = NativeStore::open(&root)?;
    let view = store.view()?;
    assert_eq!(
        view.snapshot.iter().collect::<fjall::Result<Vec<_>>>()?,
        entries
    );
    assert_eq!(view.context(&first.key)?, Some((first, 1)));
    assert_eq!(view.context(&second.key)?, None);
    Ok(())
}
