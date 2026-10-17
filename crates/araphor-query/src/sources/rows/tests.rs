use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;
use std::time::Duration;

use araphor_data::{
    AnalysisContextRefV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
    AnalysisStore, ContextSensitivityV1, Selection,
};
use datafusion::arrow::array::BinaryArray;
use futures_util::TryStreamExt as _;

use super::{ArrowSnapshot, SourceSnapshot};
use crate::execution::{Engine, Limits, Read};
use crate::parser::Parser;

type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

#[test]
fn witnesses_keep_source_receipt() -> TestResult {
    use araphor_data::{AnalysisExtractLimits, AnalysisStreamIdentityV1, AnalysisWitnessV1};

    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let source = araphor_data::EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let frame = Vec::<u8>::try_from(&araphor_data::EvidenceRecord {
        observed_boottime_ns: 1,
        ..Default::default()
    })?;
    store.accept_validated_batch(
        source.clone(),
        araphor_data::ValidatedEvidenceBatchV1 {
            cpu_id: 0,
            first_cursor: 1,
            last_cursor: 1,
            intake_utc_ns: 1,
            frame_ends: vec![frame.len()],
            framed_records: frame.into(),
        },
    )?;
    let context = AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: source.tenant_id,
            owner_id: "witness-test".into(),
            entity_key: vec![4],
            lifetime_key: vec![5],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![6],
    };
    let revision = store.commit_context(&context)?;
    let mut selection = AnalysisSelectionV1::new(source.tenant_id, vec![source]);
    selection.contexts = Selection::Exact(vec![context.key.clone()]);
    let capacity = 32 * 1024;
    let memory = crate::memory::Memory::new(capacity, 1024);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let snapshot = super::SourceSnapshot::new(
        store,
        selection,
        None,
        AnalysisExtractLimits {
            input_bytes: 16 * 1024,
            ..Default::default()
        },
        control.within(control.remaining()?)?,
        Duration::from_secs(30),
        1,
        Arc::clone(&memory),
    );
    let mut captured = snapshot.read(
        &BTreeMap::from([
            ("events".to_owned(), None),
            ("context_versions".to_owned(), None),
        ]),
        None,
        super::ReadMode::Snapshot,
        &control,
    )?;
    assert!(captured.receipt.page.tables.is_empty());
    assert!(captured.receipt.page.packages.is_empty());
    assert!(captured.receipt.page.removals.is_empty());
    let previous = captured.receipt._metadata.size();
    let old = captured.receipt.witnesses.capacity() * std::mem::size_of::<AnalysisWitnessV1>()
        + captured
            .receipt
            .witnesses
            .iter()
            .map(|witness| match &witness.identity {
                AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.capacity(),
            })
            .sum::<usize>();
    let mut witnesses = Vec::with_capacity(7);
    let mut witness = captured.receipt.witnesses[0].clone();
    if let AnalysisStreamIdentityV1::Evidence(identity) = &mut witness.identity {
        identity.node_id.reserve_exact(64);
    }
    witnesses.push(witness);
    let mut node = String::with_capacity(96);
    node.push_str("node-b");
    witnesses.push(AnalysisWitnessV1 {
        identity: AnalysisStreamIdentityV1::Diagnostic(araphor_data::TraceIdentityV1 {
            tenant_id: [1; 16],
            node_id: node,
            node_boot_id: [2; 16],
            request_id: [3; 16],
            execution_id: [4; 16],
            source_sha256: [5; 32],
        }),
        cursor: 2,
        expires_utc_ns: 0,
    });
    let added = witnesses.capacity() * std::mem::size_of::<AnalysisWitnessV1>()
        + witnesses
            .iter()
            .map(|witness| match &witness.identity {
                AnalysisStreamIdentityV1::Evidence(identity) => identity.node_id.capacity(),
                AnalysisStreamIdentityV1::Diagnostic(identity) => identity.node_id.capacity(),
            })
            .sum::<usize>();
    captured.set_witnesses(witnesses)?;
    let expected = previous - old + added;
    assert_eq!(captured.receipt._metadata.size(), expected);
    assert_eq!(captured.receipt.witnesses.len(), 2);
    let reference = captured
        .receipt
        .contexts()
        .next()
        .ok_or("context reference")?;
    assert_eq!(reference.key, context.key);
    assert_eq!(reference.commit_revision, revision);
    assert_eq!(captured.receipt.page.extraction.sources.len(), 1);
    let shared = Arc::clone(&captured.receipt);
    assert!(matches!(
        captured.set_witnesses(Vec::new()),
        Err(datafusion::common::DataFusionError::Internal(_))
    ));
    assert_eq!(captured.receipt._metadata.size(), expected);
    assert_eq!(shared.witnesses.len(), 2);
    drop(shared);
    let held = memory.reserve_input(capacity - expected)?;
    let mut larger = Vec::with_capacity(64);
    larger.extend(captured.receipt.witnesses.iter().cloned());
    let error = captured
        .set_witnesses(larger)
        .err()
        .ok_or("shared input must be exhausted")?;
    assert!(
        matches!(error, datafusion::common::DataFusionError::External(source)
        if matches!(source.downcast_ref::<crate::Error>(), Some(crate::Error::Capacity { resource: "shared input", .. })))
    );
    assert_eq!(captured.receipt._metadata.size(), expected);
    assert_eq!(captured.receipt.witnesses.len(), 2);
    drop(held);
    captured.set_witnesses(Vec::new())?;
    assert_eq!(captured.receipt._metadata.size(), previous - old);
    assert!(captured.receipt.witnesses.is_empty());
    assert_eq!(
        captured
            .receipt
            .contexts()
            .next()
            .ok_or("context reference")?
            .key,
        context.key
    );
    drop(captured);
    assert!(memory.reserve_input(capacity).is_ok());
    Ok(())
}

#[tokio::test]
async fn receipt_releases_binary_scratch() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let context = AnalysisContextVersionV1 {
        key: araphor_data::AnalysisContextKeyV1 {
            tenant_id: [1; 16],
            owner_id: "receipt-test".into(),
            entity_key: vec![2; 16],
            lifetime_key: vec![3; 16],
            owner_revision: 1,
        },
        valid_from_utc_ns: None,
        valid_until_utc_ns: None,
        sensitivity: ContextSensitivityV1::Tenant,
        body: vec![7; 24 * 1024],
    };
    let revision = store.commit_context(&context)?;
    let engine = Engine::new(
        Arc::clone(&store),
        Limits {
            input_bytes: 2 * 1024 * 1024,
            input_capacity: 2 * 1024 * 1024,
            output_capacity: 2 * 1024 * 1024,
            extract_timeout: Duration::from_secs(5),
            evaluate_timeout: Duration::from_secs(5),
            ..Default::default()
        },
    )?;
    let state = engine.catalog(SourceSnapshot::providers())?;
    let statement = Parser::default().parse("SELECT body FROM context_versions")?;
    let sources: araphor_data::AnalysisTableRequests = state
        .resolve_table_references(&statement)?
        .into_iter()
        .map(|source| (source.table().to_owned(), None))
        .collect();
    let plan = engine.plan(&state, statement, vec![])?;
    let mut selection = AnalysisSelectionV1::new(context.key.tenant_id, vec![]);
    selection.contexts = Selection::Exact(vec![context.key.clone()]);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
    let session = engine.session(selection, &control, 1)?;
    let (receipt, mut stream) = session.stream(&plan, &sources, Read::Snapshot).await?;
    assert!(receipt.page.tables.is_empty());
    assert!(receipt.page.packages.is_empty());
    assert!(receipt.page.removals.is_empty());
    let batch = stream.try_next().await?.ok_or("context batch is absent")?;
    let body = batch
        .column(0)
        .as_any()
        .downcast_ref::<BinaryArray>()
        .ok_or("context body is not native binary")?;
    assert_eq!(body.value(0), context.body);
    let payload = batch.column(0).to_data().buffers()[1].clone();
    assert!(stream.try_next().await?.is_none());
    assert_eq!(receipt.contexts().count(), 1);
    let reference = receipt.contexts().next().ok_or("context reference")?;
    assert_eq!(reference.key, context.key);
    assert_eq!(reference.commit_revision, revision);
    let metadata = receipt._metadata.size();
    assert!(
        metadata
            >= std::mem::size_of::<ArrowSnapshot>()
                + std::mem::size_of::<AnalysisContextRefV1>()
                + context.key.owner_id.capacity()
                + context.key.entity_key.capacity()
                + context.key.lifetime_key.capacity()
    );
    assert!(metadata < context.body.len());
    assert!(receipt.page.extraction.input_bytes > context.body.len() * 2);
    drop(batch);
    drop(stream);
    drop(session);
    let capacity = engine.limits().input_capacity;
    assert!(engine.memory().reserve_input(capacity - metadata).is_err());
    drop(payload);
    let available = engine.memory().reserve_input(capacity - metadata)?;
    assert!(engine.memory().reserve_input(1).is_err());
    drop(available);
    assert!(engine.memory().reserve_input(capacity).is_err());
    assert!(engine
        .memory()
        .reserve_output(engine.limits().output_capacity)
        .is_ok());
    drop(receipt);
    assert!(engine.memory().reserve_input(capacity).is_ok());
    Ok(())
}

#[test]
fn catalog_native_preflight() -> TestResult {
    use araphor_data::AnalysisExtractLimits;
    use datafusion::arrow::array::{BooleanArray, StringArray, UInt32Array};

    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let capacity = 2 * 1024 * 1024;
    let memory = crate::memory::Memory::new(capacity, 1024);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let source = super::SourceSnapshot::new(
        Arc::clone(&store),
        AnalysisSelectionV1::tenant([1; 16]),
        None,
        AnalysisExtractLimits {
            input_bytes: capacity,
            ..Default::default()
        },
        control.within(control.remaining()?)?,
        Duration::from_secs(30),
        1,
        Arc::clone(&memory),
    );
    let schemas = super::SourceSnapshot::schemas();
    let schema = schemas.get("catalog").ok_or("catalog schema")?;
    let indices = (0..schema.fields().len()).collect::<Vec<_>>();
    let requests = BTreeMap::from([(
        "catalog".to_owned(),
        Some(indices.iter().copied().collect()),
    )]);
    let captured = source.read(&requests, None, super::ReadMode::Snapshot, &control)?;
    let batches = captured.project(
        &super::SourceOrigin::Durable("catalog".into()),
        &indices,
        schema,
    )?;
    assert_eq!(batches.len(), 1);
    let batch = batches.first().ok_or("catalog rows")?;
    assert_eq!(batch.schema(), *schema);
    assert_eq!(
        batch.num_rows(),
        schemas
            .values()
            .map(|schema| schema.fields().len())
            .sum::<usize>()
    );
    assert!(batch
        .columns()
        .iter()
        .all(|column| column.null_count() == 0));
    let (relation, declared) = schemas.first_key_value().ok_or("source schemas")?;
    let first = declared.field(0);
    assert_eq!(
        batch
            .column(0)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("relation strings")?
            .value(0),
        relation
    );
    assert_eq!(
        batch
            .column(1)
            .as_any()
            .downcast_ref::<UInt32Array>()
            .ok_or("ordinal values")?
            .value(0),
        0
    );
    assert_eq!(
        batch
            .column(2)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("column strings")?
            .value(0),
        first.name()
    );
    assert_eq!(
        batch
            .column(3)
            .as_any()
            .downcast_ref::<StringArray>()
            .ok_or("type strings")?
            .value(0),
        first.data_type().to_string()
    );
    assert_eq!(
        batch
            .column(5)
            .as_any()
            .downcast_ref::<BooleanArray>()
            .ok_or("nullable values")?
            .value(0),
        first.is_nullable()
    );
    let readiness = batch
        .column(9)
        .as_any()
        .downcast_ref::<StringArray>()
        .ok_or("readiness strings")?;
    assert_eq!(relation, "behaviors");
    assert_eq!(readiness.value(0), "disabled");
    assert!(captured.receipt.page.tables.is_empty());
    assert!(captured.receipt.page.packages.is_empty());
    assert!(captured.receipt.page.removals.is_empty());
    let required = captured.receipt.page.extraction.input_bytes;
    drop(batches);
    drop(captured);
    let source = super::SourceSnapshot::new(
        store,
        AnalysisSelectionV1::tenant([1; 16]),
        None,
        AnalysisExtractLimits {
            input_bytes: required - 1,
            ..Default::default()
        },
        control.within(control.remaining()?)?,
        Duration::from_secs(30),
        1,
        Arc::clone(&memory),
    );
    let error = source
        .read(&requests, None, super::ReadMode::Snapshot, &control)
        .err()
        .ok_or("catalog capacity must be checked before allocation")?;
    assert!(
        matches!(error, datafusion::common::DataFusionError::External(source)
        if matches!(source.downcast_ref::<araphor_data::Error>(), Some(araphor_data::Error::AnalysisInputTooLarge { resource: "selected input bytes", .. })))
    );
    let captured = source.read(
        &BTreeMap::from([("catalog".to_owned(), Some(BTreeSet::new()))]),
        None,
        super::ReadMode::Snapshot,
        &control,
    )?;
    let empty = Arc::new(schema.project(&[])?);
    let batches = captured.project(&super::SourceOrigin::Durable("catalog".into()), &[], &empty)?;
    assert_eq!(batches.len(), 1);
    assert_eq!(batches[0].num_columns(), 0);
    assert_eq!(
        batches[0].num_rows(),
        schemas
            .values()
            .map(|schema| schema.fields().len())
            .sum::<usize>()
    );
    drop(batches);
    drop(captured);
    drop(memory.reserve_input(capacity)?);
    Ok(())
}

#[test]
fn catalog_content_contract() -> TestResult {
    let expected: [[u8; 32]; 8] = [
        [
            141, 121, 148, 19, 109, 17, 178, 3, 54, 140, 176, 87, 201, 43, 252, 250, 31, 30, 39,
            57, 127, 29, 63, 195, 91, 148, 168, 168, 148, 241, 106, 231,
        ],
        [
            118, 12, 125, 97, 149, 64, 175, 65, 28, 249, 177, 146, 238, 122, 77, 160, 24, 62, 170,
            15, 62, 184, 14, 77, 10, 135, 20, 192, 35, 34, 170, 163,
        ],
        [
            196, 126, 9, 143, 225, 198, 211, 144, 152, 8, 189, 1, 133, 132, 123, 199, 111, 136, 17,
            70, 200, 39, 110, 243, 104, 93, 65, 233, 60, 190, 134, 98,
        ],
        [
            18, 189, 79, 203, 160, 230, 14, 167, 131, 78, 127, 11, 108, 104, 230, 218, 17, 215,
            167, 100, 57, 254, 34, 180, 72, 107, 149, 98, 54, 149, 56, 82,
        ],
        [
            33, 190, 57, 8, 21, 202, 134, 139, 171, 45, 227, 226, 16, 177, 111, 19, 147, 255, 173,
            214, 70, 250, 222, 231, 37, 141, 234, 15, 118, 211, 55, 117,
        ],
        [
            187, 150, 127, 202, 137, 11, 81, 255, 180, 176, 144, 17, 97, 27, 2, 233, 23, 30, 151,
            77, 90, 94, 169, 94, 65, 125, 123, 49, 143, 154, 119, 234,
        ],
        [
            163, 227, 194, 223, 215, 16, 133, 248, 185, 97, 72, 117, 78, 221, 174, 9, 83, 221, 173,
            92, 19, 38, 152, 199, 184, 28, 207, 85, 40, 124, 230, 222,
        ],
        [
            82, 160, 160, 223, 52, 84, 164, 45, 51, 222, 83, 62, 31, 197, 89, 206, 251, 139, 251,
            191, 216, 92, 183, 179, 12, 94, 67, 87, 204, 4, 61, 155,
        ],
    ];
    use std::hash::Hash as _;

    use araphor_data::AnalysisExtractLimits;
    use datafusion::common::ScalarValue;

    for enabled in 0..8u8 {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        if enabled & 1 != 0 {
            store.register_discovery_owner();
        }
        if enabled & 2 != 0 {
            store.enable_graph_owner()?;
        }
        if enabled & 4 != 0 {
            store.enable_notification_owner()?;
        }
        let capacity = 2 * 1024 * 1024;
        let memory = crate::memory::Memory::new(capacity, 1024);
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
        let source = SourceSnapshot::new(
            store,
            AnalysisSelectionV1::tenant([1; 16]),
            None,
            AnalysisExtractLimits {
                input_bytes: capacity,
                ..Default::default()
            },
            control.within(control.remaining()?)?,
            Duration::from_secs(30),
            1,
            Arc::clone(&memory),
        );
        let schemas = SourceSnapshot::schemas();
        let schema = schemas.get("catalog").ok_or("catalog schema")?;
        let indices = (0..schema.fields().len()).collect::<Vec<_>>();
        let captured = source.read(
            &BTreeMap::from([("catalog".into(), Some(indices.iter().copied().collect()))]),
            None,
            super::ReadMode::Snapshot,
            &control,
        )?;
        let batches = captured.project(
            &super::SourceOrigin::Durable("catalog".into()),
            &indices,
            schema,
        )?;
        assert_eq!(batches.len(), 1);
        let batch = &batches[0];
        assert_eq!(batch.schema(), *schema);
        assert_eq!(
            batch.num_rows(),
            schemas
                .values()
                .map(|schema| schema.fields().len())
                .sum::<usize>()
        );
        let mut hash = crate::stream::physical::Fingerprint::new();
        schema.hash(&mut hash);
        batch.num_rows().hash(&mut hash);
        for row in 0..batch.num_rows() {
            for column in batch.columns() {
                ScalarValue::try_from_array(column, row)?.hash(&mut hash);
            }
        }
        let digest = hash.finish_digest();
        assert_eq!(
            digest,
            expected[usize::from(enabled)],
            "feature mask {enabled}"
        );
        let borrowed = Arc::clone(batch.column(2));
        drop(batches);
        drop(captured);
        assert!(memory.reserve_input(capacity).is_err());
        assert_eq!(
            borrowed.len(),
            schemas
                .values()
                .map(|schema| schema.fields().len())
                .sum::<usize>()
        );
        drop(borrowed);
        drop(memory.reserve_input(capacity)?);
    }
    Ok(())
}

mod notification {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::time::Duration;

    use araphor_data::{
        AnalysisContextKeyV1, AnalysisContextVersionV1, AnalysisReadControl, AnalysisSelectionV1,
        AnalysisStore, ContextSensitivityV1, NotificationAcknowledgementV1, NotificationKeyV1,
        NotificationObligationV1, NotificationPriorityV1, NotificationSinkHealthV1, Selection,
        UnconfirmedNotificationConcernV1, NOTIFICATION_STATE_OWNER,
    };
    use datafusion::common::ScalarValue;

    use crate::execution::{Engine, Limits};
    use crate::parser::Parser;
    use crate::sources::SourceSnapshot;

    type TestResult = std::result::Result<(), Box<dyn std::error::Error + Send + Sync>>;

    fn obligation() -> NotificationObligationV1 {
        NotificationObligationV1 {
            schema_version: 1,
            key: NotificationKeyV1 {
                tenant_id: [1; 16],
                notification_id: [7; 16],
            },
            revision: 1,
            finding: None,
            unconfirmed_concern: Some(UnconfirmedNotificationConcernV1 {
                concern_id: [9; 16],
                model_label: "clock".into(),
                summary: "Review this concern".into(),
                context: Vec::new(),
                sensitivity: ContextSensitivityV1::Tenant,
                suggested_priority: NotificationPriorityV1::Info,
            }),
            finding_revision: 1,
            package_id: "clock".into(),
            required_action: None,
            sensitivity: ContextSensitivityV1::Tenant,
            source_priority: NotificationPriorityV1::Info,
            minimum_priority: NotificationPriorityV1::Info,
            route: None,
            escalation: None,
            first_seen_utc_ns: 1,
            deadline_utc_ns: Some(100),
            overdue_since_utc_ns: None,
            attempt_sequence: 0,
            attempts: Vec::new(),
            sink_health: NotificationSinkHealthV1::Unknown,
            failure: None,
            human_acknowledgement: None,
            agent_receipt: None,
            advisory: None,
        }
    }

    fn retain(store: &AnalysisStore, value: &NotificationObligationV1) -> TestResult {
        value.validate()?;
        store.commit_context(&AnalysisContextVersionV1 {
            key: AnalysisContextKeyV1 {
                tenant_id: value.key.tenant_id,
                owner_id: NOTIFICATION_STATE_OWNER.into(),
                entity_key: value.key.notification_id.to_vec(),
                lifetime_key: b"obligation".to_vec(),
                owner_revision: value.revision,
            },
            valid_from_utc_ns: None,
            valid_until_utc_ns: None,
            sensitivity: value.sensitivity,
            body: serde_json::to_vec(value)?,
        })?;
        Ok(())
    }

    #[tokio::test]
    async fn obligation_source_deadline() -> TestResult {
        let directory = tempfile::tempdir()?;
        let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
        store.enable_notification_owner()?;
        let engine = Engine::new(Arc::clone(&store), Limits::default())?;
        let mut value = obligation();
        retain(&store, &value)?;
        let state = engine.catalog(SourceSnapshot::providers())?;
        let statement = Parser::default().parse("SELECT overdue FROM notifications")?;
        let sources = state
            .resolve_table_references(&statement)?
            .into_iter()
            .map(|reference| (reference.table().to_owned(), None))
            .collect::<araphor_data::AnalysisTableRequests>();
        let plan = Arc::new(engine.plan(&state, statement, vec![])?);
        let selection = AnalysisSelectionV1::tenant([1; 16]);
        for (now, overdue, next_change) in
            [(99, false, Some(100)), (100, true, None), (101, true, None)]
        {
            let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
            let (snapshot, batches) = engine
                .session(selection.clone(), &control, now)?
                .execute(Arc::clone(&plan), &sources)?;
            assert_eq!(
                batches.iter().map(|batch| batch.num_rows()).sum::<usize>(),
                1
            );
            assert_eq!(
                ScalarValue::try_from_array(batches[0].column(0), 0)?,
                ScalarValue::Boolean(Some(overdue))
            );
            assert_eq!(snapshot.next_change, next_change);
            let permit = engine.reserve_evaluation([1; 16])?;
            let metadata = engine
                .metadata(selection.clone(), &sources, &control, now)
                .await?;
            assert_eq!(metadata.next_change, next_change);
            assert_eq!(
                metadata.page.extraction.scanned_bytes,
                serde_json::to_vec(&value)?.len()
            );
            assert_eq!(metadata.contexts().count(), 1);
            let reference = metadata.contexts().next().ok_or("notification reference")?;
            assert_eq!(reference.key.owner_id, NOTIFICATION_STATE_OWNER);
            assert_eq!(reference.key.owner_revision, value.revision);
            drop(permit);
        }
        let mut scoped = selection.clone();
        scoped.sources = Selection::Exact(Vec::new());
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
        let (snapshot, batches) = engine
            .session(scoped, &control, 99)?
            .execute(Arc::clone(&plan), &sources)?;
        assert!(batches.iter().all(|batch| batch.num_rows() == 0));
        assert!(snapshot.contexts().next().is_none());
        assert_eq!(snapshot.next_change, None);
        value.revision = 2;
        value.human_acknowledgement = Some(NotificationAcknowledgementV1 {
            request_id: [3; 16],
            principal_id: [4; 16],
            authorization_revision: 1,
            finding_revision: 1,
            acknowledged_utc_ns: 50,
        });
        retain(&store, &value)?;
        let control = AnalysisReadControl::with_timeout(Duration::from_secs(10))?;
        let complete = engine
            .metadata(selection.clone(), &sources, &control, 99)
            .await?;
        assert_eq!(complete.next_change, None);
        value.revision = 3;
        value.finding_revision = 2;
        retain(&store, &value)?;
        let changed = engine
            .metadata(selection.clone(), &sources, &control, 99)
            .await?;
        assert_eq!(changed.next_change, Some(100));
        value.revision = 4;
        value.deadline_utc_ns = Some(u64::MAX);
        value.human_acknowledgement = None;
        retain(&store, &value)?;
        for (now, expected) in [(u64::MAX - 1, Some(u64::MAX)), (u64::MAX, None)] {
            let metadata = engine
                .metadata(selection.clone(), &sources, &control, now)
                .await?;
            assert_eq!(metadata.next_change, expected);
            let (_, batches) = engine
                .session(selection.clone(), &control, now)?
                .execute(Arc::clone(&plan), &sources)?;
            assert_eq!(
                ScalarValue::try_from_array(batches[0].column(0), 0)?,
                ScalarValue::Boolean(Some(now == u64::MAX))
            );
        }
        let absent = engine
            .metadata(selection, &BTreeMap::new(), &control, 99)
            .await?;
        assert_eq!(absent.next_change, None);
        Ok(())
    }
}

#[test]
fn retirement_map_charges_once() -> TestResult {
    use std::mem::size_of;

    use araphor_data::{
        AnalysisExtractLimits, AnalysisGapV1, AnalysisStreamIdentityV1, EvidenceIntakeIdentityV1,
        EvidenceRecord, EvidenceRetentionOwner, StorePositionV1, ValidatedEvidenceBatchV1,
    };

    let directory = tempfile::tempdir()?;
    let store = Arc::new(AnalysisStore::open(directory.path().join("data"))?);
    let identity = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "retirement-budget".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let frame = Vec::<u8>::try_from(&EvidenceRecord {
        observed_boottime_ns: 1,
        ..Default::default()
    })?;
    for cursor in 1..=2 {
        store.accept_validated_batch(
            identity.clone(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: cursor,
                last_cursor: cursor,
                intake_utc_ns: 1,
                frame_ends: vec![frame.len()],
                framed_records: frame.clone().into(),
            },
        )?;
        if cursor == 1 {
            store.backup(&directory.path().join("data/backups/sealed"))?;
        }
    }
    let frontier = StorePositionV1 {
        commit_revision: store.meta()?.commit_revision,
        ordinal: u32::MAX,
    };
    assert_eq!(
        EvidenceRetentionOwner::new(store.as_ref())
            .retain(&identity, u64::MAX)?
            .removed_records,
        2
    );
    assert!(store
        .replay_floor(identity.tenant_id)?
        .is_some_and(|floor| floor <= frontier));
    let capacity = 64 * 1024;
    let memory = crate::memory::Memory::new(capacity, 1024);
    let control = AnalysisReadControl::with_timeout(Duration::from_secs(30))?;
    let source = SourceSnapshot::new(
        store,
        AnalysisSelectionV1::new(identity.tenant_id, vec![identity.clone()]),
        None,
        AnalysisExtractLimits {
            input_bytes: capacity,
            ..Default::default()
        },
        control.within(control.remaining()?)?,
        Duration::from_secs(30),
        1,
        Arc::clone(&memory),
    );
    let captured = source.read(
        &BTreeMap::from([("events".into(), Some(BTreeSet::new()))]),
        None,
        super::ReadMode::Changes(frontier),
        &control,
    )?;
    assert!(captured.receipt.page.tables.is_empty());
    assert!(captured.receipt.page.removals.is_empty());
    assert_eq!(captured.removals.len(), 1);
    assert_eq!(captured.source_bytes, 0);
    let gaps = captured
        .removals
        .get(&AnalysisStreamIdentityV1::Evidence(identity.clone()))
        .ok_or("retirement map is absent")?;
    assert_eq!(gaps.len(), 2);
    assert_eq!(
        gaps.iter()
            .map(|gap| (gap.first_cursor, gap.last_cursor))
            .collect::<Vec<_>>(),
        [(1, 1), (2, 2)]
    );
    let removed = size_of::<(AnalysisStreamIdentityV1, Vec<AnalysisGapV1>)>()
        + identity.node_id.len()
        + gaps.capacity() * size_of::<AnalysisGapV1>();
    assert_eq!(captured._memory.size(), removed);
    let receipt = Arc::clone(&captured.receipt);
    let metadata = receipt._metadata.size();
    let available = memory.reserve_input(capacity - metadata - removed)?;
    assert!(memory.reserve_input(1).is_err());
    drop(available);
    drop(captured);
    let available = memory.reserve_input(capacity - metadata)?;
    assert!(memory.reserve_input(1).is_err());
    drop(available);
    drop(receipt);
    drop(memory.reserve_input(capacity)?);
    Ok(())
}
