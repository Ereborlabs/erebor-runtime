#![cfg(feature = "native-store")]

use araphor_data::{
    analysis::native::NativeStore, AnalysisContextKeyV1, AnalysisContextVersionV1,
    ContextSensitivityV1, Error, PackageErrorCodeV1 as Code,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn context(entity: &[u8], revision: u64) -> AnalysisContextVersionV1 {
    AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "discovery-facts-v1".into(),
            entity_key: entity.to_vec(),
            lifetime_key: b"source".to_vec(),
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: b"observed".to_vec(),
    }
}

fn image(sql: &str) -> araphor_data::Result<araphor_data::PackageBundle> {
    use araphor_analysis_sdk as sdk;
    let artifact = araphor_data::PackageArtifactV1 {
        descriptor: sdk::Package::new(
            "context-image",
            "1",
            vec![sdk::Model::new(
                "count",
                Vec::new(),
                vec![sdk::Port::new(
                    "rows",
                    sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]),
                )],
            )],
        ),
        implementations: vec![araphor_data::PackageImplementationV1::Sql {
            export: "count".into(),
            program: araphor_data::SqlModelV1 {
                outputs: std::collections::BTreeMap::from([("rows".into(), sql.into())]),
                ..Default::default()
            },
        }],
        fixtures: Vec::new(),
    };
    Ok(araphor_data::PackageBundle::try_from(
        araphor_data::PackageBundleV1 {
            schema_version: 1,
            root: artifact.reference(),
            artifacts: vec![artifact],
        },
    )?)
}

#[test]
fn guarded_batches_keep_original_references() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut checked = 0;
    assert!(store
        .commit_contexts_guarded(&[], || {
            checked += 1;
            Ok(())
        })?
        .is_empty());
    assert_eq!(checked, 1);
    let first = context(b"first", 0);
    let one = store.commit_context(&first)?;
    let second = context(b"second", 0);
    let references = store.commit_contexts(&[first.clone(), second.clone()])?;
    assert_eq!(references[0].commit_revision, one);
    assert_eq!(references[1].commit_revision, one + 1);
    let cursor = store.database().inner().journal_head()?;
    store.commit_contexts_guarded(&[first.clone(), second.clone()], || {
        checked += 1;
        Ok(())
    })?;
    assert_eq!(checked, 2);
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let third = context(b"third", 1);
    assert!(store
        .commit_contexts_guarded(std::slice::from_ref(&third), || Err(
            Code::Denied.error("context guard")
        ))
        .is_err());
    assert!(store.view()?.context(&third.key)?.is_none());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    let mut conflict = first.clone();
    conflict.body.push(255);
    assert!(matches!(
        store.commit_contexts(&[third.clone(), conflict]),
        Err(Error::AnalysisConflict { .. })
    ));
    assert!(store.view()?.context(&third.key)?.is_none());
    let mut next = first.clone();
    next.key.owner_revision = 1;
    next.body = b"later".to_vec();
    assert!(matches!(
        store.commit_context_checked(&next, 8),
        Err(Error::AnalysisConflict { .. })
    ));
    let two = store.commit_context_checked(&next, 0)?;
    assert_eq!(store.commit_context_checked(&first, 99)?, one);
    assert_eq!(
        store.view()?.context_head(&first.key)?.ok_or("head")?.key,
        next.key
    );
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.view()?.context(&first.key)?, Some((first, one)));
    assert_eq!(store.view()?.context(&next.key)?, Some((next, two)));
    Ok(())
}

#[test]
fn interning_uses_staged_scope_and_lexical_entity() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let z = context(b"z", 4);
    let a = context(b"a", 7);
    store.commit_contexts(&[z.clone(), a.clone()])?;
    let input = context(b"requested", 1);
    let saved = store.intern_context(&input)?;
    assert_eq!(saved.key, a.key);
    assert_eq!(store.view()?.revision(), 1);
    let mut b = context(b"b", 1);
    b.body = b"new equivalence".to_vec();
    let mut c = b.clone();
    c.key.entity_key = b"c".to_vec();
    let batch = store.intern_contexts_guarded(&[b.clone(), c.clone()], || Ok(()))?;
    assert_eq!(batch[0], batch[1]);
    assert_eq!(batch[0].key, b.key);
    assert!(store.view()?.context(&c.key)?.is_none());
    let mut bounded = input.clone();
    bounded.valid_from_utc_ns = Some(1);
    let different = store.intern_context(&bounded)?;
    assert_eq!(different.key, bounded.key);
    let mut forbidden = input.clone();
    forbidden.key.owner_id = "other-owner".into();
    assert!(store.intern_context(&forbidden).is_err());
    let before = store.view()?.revision();
    let mut checked = false;
    assert!(store
        .intern_context_guarded(&input, || {
            checked = true;
            Err(Code::Denied.error("intern guard"))
        })
        .is_err());
    assert!(checked);
    assert_eq!(store.view()?.revision(), before);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.intern_context(&input)?, saved);
    Ok(())
}

#[test]
fn retained_package_proof_does_not_require_installation() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let bundle = image("SELECT 1::BIGINT UNSIGNED AS count")?;
    let input = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "count",
        "rows",
    )?;
    assert!(matches!(
        store.commit_context(&input),
        Err(Error::Package {
            code: Code::Missing,
            ..
        })
    ));
    store.install_package(
        &araphor_data::analysis::PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    let committed = store.intern_context(&input)?;
    let conflicting = image("SELECT 2::BIGINT UNSIGNED AS count")?;
    let wrong = AnalysisContextVersionV1::from_package(
        &conflicting,
        [1; 16],
        &conflicting.bundle().root,
        "count",
        "rows",
    )?;
    assert!(store.commit_contexts(&[context(b"new", 1), wrong]).is_err());
    assert!(store.view()?.context(&context(b"new", 1).key)?.is_none());
    assert_eq!(
        store.view()?.context(&committed.key)?,
        Some((input.clone(), committed.commit_revision))
    );
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.intern_context(&input)?, committed);
    let (key, bytes) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/P")
        .next()
        .ok_or("retained package")??;
    let (row, _): (araphor_data::analysis::PackageRevisionV1, u64) =
        rmp_serde::from_slice(&bytes[1..])?;
    let mut tx = store.write()?;
    let future = tx.revision() + 1;
    tx.native()
        .insert(key, [vec![0], rmp_serde::to_vec(&(row, future))?].concat());
    tx.commit([])?;
    store.accept_validated_batch(
        araphor_data::EvidenceIntakeIdentityV1 {
            tenant_id: [1; 16],
            node_id: "node-a".into(),
            node_boot_id: [2; 16],
            label_epoch: 1,
            source_id: [3; 16],
            source_epoch: 1,
        },
        araphor_data::ValidatedEvidenceBatchV1 {
            cpu_id: 7,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 100,
            framed_records: vec![255].into(),
            frame_ends: vec![1],
        },
    )?;
    assert_eq!(store.view()?.revision(), future);
    let cursor = store.database().inner().journal_head()?;
    let next = context(b"blocked", 1);
    assert!(store.commit_contexts(&[next.clone(), input]).is_err());
    assert!(store.view()?.context(&next.key)?.is_none());
    assert_eq!(store.database().inner().journal_head()?, cursor);
    Ok(())
}

fn fact() -> Result<AnalysisContextVersionV1, Box<dyn std::error::Error>> {
    use araphor_data::{
        DiscoveryRecordIdV1, EvidenceIntakeIdentityV1, GraphFactV1, GraphFactValueV1,
    };
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let value = GraphFactV1 {
        record_id: DiscoveryRecordIdV1 {
            stream: source,
            cpu_id: 7,
            durable_cursor: 1,
        },
        value: GraphFactValueV1::Baseline {
            role_id: 1,
            state_id: 1,
            outside_reviewed_baseline: false,
            reviewed_policy_revision: "retained".into(),
        },
    };
    let mut input = context(b"canonical", 1);
    input.body = value.encode_context()?;
    Ok(input)
}

#[test]
fn canonical_facts_share_the_commit_and_retries_check_the_index() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let input = fact()?;
    let cursor = store.database().inner().journal_head()?;
    let mut tx = store.write()?;
    tx.context(&input, None)?;
    tx.native().insert(b"result", b"committed");
    tx.native().insert(b"progress", b"committed");
    assert!(store.view()?.context(&input.key)?.is_none());
    tx.commit([])?;
    let mut feed = store.database().inner().journal_feed(cursor)?;
    let batch = feed.next_batch()?.ok_or("atomic fact batch")?;
    for prefix in [b"\0data/C".as_slice(), b"\0data/K", b"result", b"progress"] {
        assert!(batch.items.iter().any(|item| item.key.starts_with(prefix)));
    }
    assert!(feed.next_batch()?.is_none());
    drop(feed);
    let (key, _) = store
        .view()?
        .snapshot()
        .prefix(b"\0data/K")
        .next()
        .ok_or("fact index")??;
    let mut tx = store.write()?;
    tx.native().remove(key);
    tx.commit([])?;
    assert!(matches!(
        store.commit_context(&input),
        Err(Error::Package {
            code: Code::Invalid,
            field: "canonical fact index",
            ..
        })
    ));
    assert!(matches!(
        store.intern_context(&input),
        Err(Error::Package {
            code: Code::Invalid,
            field: "canonical fact index",
            ..
        })
    ));
    drop(store);
    assert!(NativeStore::open(&root).is_err());
    Ok(())
}

#[test]
fn imported_history_reads_staged_revisions() -> TestResult {
    use araphor_data::{
        DiscoveryContextDocumentV1, DiscoveryContextKindV1, DiscoveryContextRevisionV1,
        DiscoveryMethodV1,
    };
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let mut imported = DiscoveryContextRevisionV1 {
        imported_utc_ns: 1,
        document: DiscoveryContextDocumentV1 {
            schema_version: araphor_data::DISCOVERY_SCHEMA_VERSION,
            tenant_id: [1; 16],
            id: "runbook".into(),
            revision: 1,
            kind: DiscoveryContextKindV1::Runbook,
            subject: context(b"subject", 1).key,
            method: DiscoveryMethodV1 {
                id: "fixture".into(),
                revision: 1,
            },
            origin: "fixture".into(),
            valid_from_utc_ns: 1,
            valid_until_utc_ns: None,
            sensitivity: ContextSensitivityV1::Tenant,
            approver: None,
            text: "first".into(),
        },
    };
    let first = AnalysisContextVersionV1::try_from(&imported)?;
    imported.document.revision = 3;
    assert!(store
        .commit_contexts(&[
            first.clone(),
            AnalysisContextVersionV1::try_from(&imported)?
        ])
        .is_err());
    assert_eq!(store.view()?.revision(), 0);
    imported.document.revision = 2;
    imported.imported_utc_ns = 2;
    imported.document.text = "second".into();
    let second = AnalysisContextVersionV1::try_from(&imported)?;
    let references = store.commit_contexts(&[first.clone(), second.clone()])?;
    assert!(references.iter().all(|row| row.commit_revision == 1));
    imported.document.revision = 3;
    imported.document.subject.lifetime_key = b"foreign".to_vec();
    assert!(store
        .commit_context(&AnalysisContextVersionV1::try_from(&imported)?)
        .is_err());
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(store.commit_context(&first)?, 1);
    assert_eq!(
        store.view()?.context(&second.key)?.ok_or("imported")?.0,
        second
    );
    Ok(())
}

#[test]
fn legacy_shared_validation_still_admits_package_contexts() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = araphor_data::AnalysisStore::open(&root)?;
    let bundle = image("SELECT 1::BIGINT UNSIGNED AS count")?;
    store.install_package(
        &araphor_data::analysis::PackageRevisionV1::from_bundle(&bundle, [1; 16])?,
        || Ok(()),
    )?;
    let input = AnalysisContextVersionV1::from_package(
        &bundle,
        [1; 16],
        &bundle.bundle().root,
        "count",
        "rows",
    )?;
    let reference = store.intern_context(&input)?;
    store.commit_context(&fact()?)?;
    assert_eq!(store.intern_context(&input)?, reference);
    drop(store);
    let store = araphor_data::AnalysisStore::open(&root)?;
    assert_eq!(store.context_version(&input.key)?, Some(input));
    Ok(())
}

#[test]
fn borrowed_batch_error_discards_staged_rows() -> TestResult {
    let dir = tempfile::tempdir()?;
    let store = NativeStore::open(&dir.path().join("data"))?;
    let first = context(b"first", 1);
    store.commit_context(&first)?;
    let cursor = store.database().inner().journal_head()?;
    let next = context(b"next", 1);
    let mut conflict = first.clone();
    conflict.body.push(255);
    let mut tx = store.write()?;
    assert!(tx.contexts(&[next.clone(), conflict]).is_err());
    tx.rollback();
    assert_eq!(store.database().inner().journal_head()?, cursor);
    assert!(store.view()?.context(&next.key)?.is_none());
    let mut tx = store.write()?;
    tx.contexts(std::slice::from_ref(&next))?;
    tx.commit([])?;
    assert!(store.view()?.context(&next.key)?.is_some());
    Ok(())
}

fn notice(revision: u64) -> araphor_data::Result<AnalysisContextVersionV1> {
    use araphor_data::{
        NotificationFindingRefV1, NotificationKeyV1, NotificationObligationV1,
        NotificationPriorityV1, NotificationSinkHealthV1,
    };
    let state = NotificationObligationV1 {
        schema_version: 1,
        key: NotificationKeyV1 {
            tenant_id: [1; 16],
            notification_id: [4; 16],
        },
        revision,
        finding: Some(NotificationFindingRefV1 {
            finding_id: "finding".into(),
            result_id: "result".into(),
        }),
        unconfirmed_concern: None,
        finding_revision: 1,
        package_id: "package".into(),
        required_action: None,
        sensitivity: ContextSensitivityV1::Tenant,
        source_priority: NotificationPriorityV1::Info,
        minimum_priority: NotificationPriorityV1::Info,
        route: None,
        escalation: None,
        first_seen_utc_ns: 1,
        deadline_utc_ns: None,
        overdue_since_utc_ns: None,
        attempt_sequence: 0,
        attempts: Vec::new(),
        sink_health: NotificationSinkHealthV1::Unknown,
        failure: None,
        human_acknowledgement: None,
        agent_receipt: None,
        advisory: None,
    };
    Ok(AnalysisContextVersionV1 {
        key: AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: araphor_data::NOTIFICATION_STATE_OWNER.into(),
            entity_key: state.key.notification_id.to_vec(),
            lifetime_key: b"obligation".to_vec(),
            owner_revision: revision,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: state.sensitivity,
        body: state.encode()?,
    })
}

#[test]
fn notification_cas_uses_the_context_head() -> TestResult {
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let first = notice(1)?;
    let one = store.commit_context_checked(&first, 0)?;
    let second = notice(2)?;
    assert!(matches!(
        store.commit_context_checked(&second, 0),
        Err(Error::AnalysisConflict { .. })
    ));
    let two = store.commit_context_checked(&second, 1)?;
    assert_eq!(store.commit_context_checked(&first, 0)?, one);
    assert_eq!(
        store
            .view()?
            .context_head(&first.key)?
            .ok_or("notice head")?
            .key,
        second.key
    );
    let mut invalid = notice(3)?;
    invalid.key.lifetime_key = b"other".to_vec();
    assert!(store.commit_context(&invalid).is_err());
    let mut route = context(b"route", 1);
    route.key.owner_id = araphor_data::NOTIFICATION_ROUTE_OWNER.into();
    assert!(store.commit_context(&route).is_err());
    assert_eq!(store.view()?.revision(), two);
    drop(store);
    let store = NativeStore::open(&root)?;
    assert_eq!(
        store
            .view()?
            .context_head(&first.key)?
            .ok_or("recovered head")?
            .key,
        second.key
    );
    assert_eq!(
        store
            .read_at(one)?
            .context_head(&first.key)?
            .ok_or("historical head")?
            .key,
        first.key
    );
    Ok(())
}

#[test]
fn context_history_binds_raw_prefixes() -> TestResult {
    use araphor_data::{EvidenceIntakeIdentityV1, ValidatedEvidenceBatchV1};
    let dir = tempfile::tempdir()?;
    let root = dir.path().join("data");
    let store = NativeStore::open(&root)?;
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let batch = |cursor| ValidatedEvidenceBatchV1 {
        cpu_id: 7,
        first_cursor: cursor,
        last_cursor: cursor,
        intake_utc_ns: 100,
        framed_records: vec![255].into(),
        frame_ends: vec![1],
    };
    store.accept_validated_batch(source.clone(), batch(1))?;
    let input = context(b"between", 1);
    let committed = store.commit_context(&input)?;
    assert_eq!(committed, 2);
    store.accept_validated_batch(source.clone(), batch(2))?;
    assert_eq!(store.view()?.revision(), 3);
    store.database().inner().flush_memtables()?;
    store.database().inner().major_compact()?;
    drop(store);
    let store = NativeStore::open(&root)?;
    assert!(store.read_at(1)?.context(&input.key)?.is_none());
    for (revision, cursor) in [(2, 1), (3, 2)] {
        let view = store.read_at(revision)?;
        assert_eq!(view.context(&input.key)?, Some((input.clone(), 2)));
        assert_eq!(
            view.source_receipt(&source)?
                .ok_or("source prefix")?
                .contiguous_cursor,
            cursor
        );
    }
    assert_eq!(store.commit_context(&input)?, committed);
    assert_eq!(store.view()?.revision(), 3);
    Ok(())
}

#[test]
fn recovery_rejects_missing_context_indexes() -> TestResult {
    for prefix in [b"\0data/H".as_slice(), b"\0data/V"] {
        let dir = tempfile::tempdir()?;
        let root = dir.path().join("data");
        let store = NativeStore::open(&root)?;
        store.commit_context(&context(b"indexed", 1))?;
        let (key, _) = store
            .view()?
            .snapshot()
            .prefix(prefix)
            .next()
            .ok_or("context index")??;
        let mut tx = store.write()?;
        tx.native().remove(key);
        tx.commit([])?;
        drop(store);
        assert!(NativeStore::open(&root).is_err());
    }
    Ok(())
}
