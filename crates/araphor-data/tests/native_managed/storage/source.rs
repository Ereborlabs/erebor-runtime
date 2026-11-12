#![cfg(feature = "test-fixtures")]

use super::super::attempts::field;
use super::StorageFixture as Fixture;
use super::*;
use araphor_data::{
    AnalysisExtractLimits, AnalysisReadModeV1, AnalysisStore, AnalysisTableRead,
    AnalysisTableRequests, AnalysisWitnessV1, EvidenceRecord, ManagedExecution, ManagedPage,
    ManagedSourceRead, ManagedSourceRef, StorePositionV1, ValidatedEvidenceBatchV1,
};
use serde_value::Value;
use std::collections::BTreeSet;

#[path = "source/follow.rs"]
mod follow;

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;

pub(super) fn identity() -> araphor_data::EvidenceIntakeIdentityV1 {
    araphor_data::EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    }
}

pub(super) fn request(id: &str) -> ManagedRequest {
    ManagedRequest {
        id: id.into(),
        time_utc_ns: 10,
        seed: Some(7),
        rebuild: false,
        witness_expiry: u64::MAX,
        frontier: None,
    }
}

fn framed(value: &impl serde::Serialize) -> TestResult<Vec<u8>> {
    Ok([vec![0], rmp_serde::to_vec_named(value)?].concat())
}

fn witnesses(
    store: &AnalysisStore,
    selected: &PackageResultRefV1,
) -> TestResult<Vec<AnalysisWitnessV1>> {
    #[derive(serde::Deserialize)]
    struct Stored {
        body: Body,
    }
    #[derive(serde::Deserialize)]
    enum Body {
        Selected(Step),
    }
    #[derive(serde::Deserialize)]
    struct Step {
        witnesses: Vec<AnalysisWitnessV1>,
    }
    let (_, bytes) = super::output::result_record(store.view()?.as_ref(), &selected.result_id)?;
    let stored: Stored = rmp_serde::from_slice(&bytes[1..])?;
    let Body::Selected(step) = stored.body;
    Ok(step.witnesses)
}

fn repair(root: &std::path::Path, key: &[u8], bytes: &[u8]) -> TestResult {
    let database = fjall::SingleWriterTxDatabase::builder(root.join("fjall"))
        .versioned()
        .open()?;
    let branch = database.branch("data")?.ok_or("repair branch")?;
    let mut transaction = branch.write_tx()?;
    let head = transaction.get(b"\0data/head")?.ok_or("repair head")?;
    let revision = u64::from_be_bytes(head.as_ref().try_into()?);
    transaction.insert(key, bytes);
    transaction.commit_stamped([[b"\0data/cut/".as_slice(), &revision.to_be_bytes()].concat()])?;
    Ok(())
}

fn pending_rows(store: &AnalysisStore) -> TestResult<Vec<(u64, u64, u32)>> {
    let requests = AnalysisTableRequests::from([(
        "events".into(),
        Some(
            ["source_cursor", "commit_revision", "ordinal"]
                .into_iter()
                .map(|name| AnalysisStore::table_schemas()["events"].index_of(name))
                .collect::<Result<BTreeSet<_>, _>>()?,
        ),
    )]);
    let selection = AnalysisSelectionV1::new([1; 16], vec![identity()]).project(&requests)?;
    let page = store.read_tables(
        &selection,
        AnalysisTableRead {
            requests: &requests,
            event_ranges: None,
            mode: AnalysisReadModeV1::Changes(StorePositionV1 {
                commit_revision: 0,
                ordinal: u32::MAX,
            }),
            now: 10,
        },
        AnalysisExtractLimits::default(),
        &AnalysisReadControl::default(),
    )?;
    let mut rows = Vec::new();
    for batch in &page.tables["events"] {
        let cursors = batch
            .column_by_name("source_cursor")
            .ok_or("cursor")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("cursor type")?;
        let revisions = batch
            .column_by_name("commit_revision")
            .ok_or("revision")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt64Array>()
            .ok_or("revision type")?;
        let ordinals = batch
            .column_by_name("ordinal")
            .ok_or("ordinal")?
            .as_any()
            .downcast_ref::<sdk::arrow_array::UInt32Array>()
            .ok_or("ordinal type")?;
        for row in 0..batch.num_rows() {
            rows.push((
                cursors.value(row),
                revisions.value(row),
                ordinals.value(row),
            ));
        }
    }
    Ok(rows)
}

#[path = "source/frames.rs"]
mod frames;
#[path = "source/projection.rs"]
mod projection;
#[path = "source/retention.rs"]
mod retention;

struct SourceFixture {
    fixture: Fixture,
    execution: Arc<ManagedExecution>,
    requests: AnalysisTableRequests,
}

impl SourceFixture {
    fn admit(store: &AnalysisStore, selection: AnalysisSelectionV1) -> TestResult<Fixture> {
        Fixture::new_scope(
            store,
            "counter",
            "Retain independent call state.".into(),
            selection,
        )
    }
    fn new(store: &AnalysisStore) -> TestResult<Self> {
        let source = identity();
        let selection = AnalysisSelectionV1::new(source.tenant_id, vec![source]);
        let columns = Self::columns("events")?;
        Ok(Self {
            fixture: Self::admit(store, selection)?,
            execution: Arc::default(),
            requests: BTreeMap::from([("events".into(), Some(columns))]),
        })
    }

    fn columns(name: &str) -> TestResult<BTreeSet<usize>> {
        let schema = &araphor_data::AnalysisStore::table_schemas()[name];
        let names = schema.fields()[0].metadata()["araphor.join_keys"].split(',');
        let mut columns = names
            .map(|name| schema.index_of(name))
            .collect::<std::result::Result<BTreeSet<_>, _>>()?;
        for name in ["commit_revision", "ordinal", "received_utc_ns"] {
            if let Ok(index) = schema.index_of(name) {
                columns.insert(index);
            }
        }
        Ok(columns)
    }

    fn append(store: &AnalysisStore, first: u64, count: usize) -> araphor_data::Result<()> {
        let mut bytes = Vec::new();
        let mut ends = Vec::new();
        for cursor in first..first + count as u64 {
            bytes.extend(Vec::<u8>::try_from(&EvidenceRecord {
                observed_boottime_ns: cursor,
                ..Default::default()
            })?);
            ends.push(bytes.len());
        }
        store.accept_validated_batch(
            identity(),
            ValidatedEvidenceBatchV1 {
                cpu_id: 0,
                first_cursor: first,
                last_cursor: first + count as u64 - 1,
                intake_utc_ns: first,
                framed_records: bytes.into(),
                frame_ends: ends,
            },
        )?;
        Ok(())
    }

    fn read(
        &self,
        store: &AnalysisStore,
        source: ManagedSourceRead,
        control: &AnalysisReadControl,
    ) -> TestResult<ManagedPage> {
        self.read_owners(store, source, control, None)
    }

    fn read_owners(
        &self,
        store: &AnalysisStore,
        source: ManagedSourceRead,
        control: &AnalysisReadControl,
        owners: Option<&BTreeSet<String>>,
    ) -> TestResult<ManagedPage> {
        let instance = self.fixture.current(store)?;
        let mode = source
            .after()
            .map_or(AnalysisReadModeV1::Complete, AnalysisReadModeV1::Changes);
        Ok(store.read_managed_tables_filtered(
            &instance
                .spec
                .destination
                .selection(&instance.grant.selection)?
                .project(&self.requests)?,
            &ManagedRead {
                source: Some(source),
                execution: Some(Arc::clone(&self.execution)),
                instance: instance.clone(),
                expected: None,
                rebuild: false,
                follow: false,
                completed: None,
            },
            AnalysisTableRead {
                requests: &self.requests,
                event_ranges: None,
                mode,
                now: 10,
            },
            AnalysisExtractLimits::default(),
            control,
            owners,
        )?)
    }

    fn restore(
        &self,
        store: &AnalysisStore,
        result: &araphor_data::analysis::PackageResultRefV1,
        limits: AnalysisExtractLimits,
        control: &AnalysisReadControl,
    ) -> TestResult<ManagedPage> {
        let instance = self.fixture.current(store)?;
        let (reference, call, _) =
            store.managed_reference(&instance, &result.result_id, 10, control)?;
        assert!(call.is_none());
        Ok(store.read_managed_reference(
            &instance
                .spec
                .destination
                .selection(&instance.grant.selection)?
                .project(&self.requests)?,
            &reference,
            AnalysisTableRead {
                requests: &self.requests,
                event_ranges: None,
                mode: AnalysisReadModeV1::Complete,
                now: reference.request().time_utc_ns,
            },
            limits,
            control,
            None,
        )?)
    }

    fn publish(
        &self,
        store: &AnalysisStore,
        capture: &ManagedCapture,
        id: &str,
    ) -> TestResult<ManagedReceipt> {
        let request = request(id);
        let attempt = store.register_managed_attempt(capture, &request, || Ok(()))?;
        let evaluations = [
            self.fixture.continued(&request, 10, Some(capture))?,
            self.fixture.continued(&request, 11, Some(capture))?,
        ];
        Ok(self.fixture.publish_checked(
            store,
            &attempt,
            &evaluations,
            &[self.fixture.output(2)?, self.fixture.output(3)?],
            || Ok(()),
        )?)
    }

    fn reference(
        capture: &ManagedCapture,
        receipt: &ManagedReceipt,
    ) -> TestResult<ManagedSourceRef> {
        Ok(ManagedSourceRef {
            result: receipt.selected.clone(),
            position: capture.source().ok_or("source frame absent")?.position(),
        })
    }
}
