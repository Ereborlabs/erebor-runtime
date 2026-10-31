use araphor_analysis_builtins::{discovery::DiscoveryRecordIdV1, graph::*};
use duckdb::{params, Connection};
use std::collections::BTreeMap;

use super::NativeRows;
use crate::{RelationshipRows, RelationshipValue, SubjectRows};

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

struct ValueFixture {
    subjects: Vec<GraphSubjectKeyV1>,
    records: Vec<DiscoveryRecordIdV1>,
    edges: Vec<RelationshipValue>,
}

impl ValueFixture {
    fn new() -> TestResult<Self> {
        let value: serde_json::Value = serde_json::from_str(include_str!(
            "../../../araphor-data/src/analysis/graph_rows/tests/graph.json"
        ))?;
        let subjects: Vec<GraphSubjectKeyV1> =
            serde_json::from_value(value["graph"]["subjects"].clone())?;
        let finding: FindingV1 = serde_json::from_value(value["findings"][0].clone())?;
        let records = finding.evidence;
        let edges: Vec<GraphEdgeV1> = serde_json::from_value(value["graph"]["edges"].clone())?;
        let edges = edges
            .into_iter()
            .map(|edge| {
                Ok(RelationshipValue {
                    key: RelationshipIdentity::from_keys(&edge.key, &subjects, &records)?,
                    proof_quality: edge.proof_quality,
                    required_coverage_interval_ids: edge.required_coverage_interval_ids,
                    first_boottime_ns: edge.first_boottime_ns,
                    last_boottime_ns: edge.last_boottime_ns,
                })
            })
            .collect::<TestResult<_>>()?;
        Ok(Self {
            subjects,
            records,
            edges,
        })
    }

    fn schema(writer: &Connection) -> TestResult {
        writer.execute_batch(
            "CREATE TABLE graph_test_members(result_id VARCHAR NOT NULL,member_kind UTINYINT NOT NULL,value_ref UBIGINT NOT NULL);
             CREATE VIEW graph_selected_members AS SELECT DISTINCT * FROM graph_test_members;
             CREATE TABLE graph_evidence(evidence_id UBIGINT PRIMARY KEY,cpu_id UINTEGER NOT NULL,durable_cursor UBIGINT NOT NULL)",
        )?;
        writer.execute_batch(SubjectRows::SCHEMA)?;
        writer.execute_batch(RelationshipRows::SCHEMA)?;
        Ok(())
    }

    fn records(&self, writer: &Connection) -> TestResult<BTreeMap<DiscoveryRecordIdV1, u64>> {
        let mut records = BTreeMap::new();
        for (index, record) in self.records.iter().enumerate() {
            let id = index as u64 + 1;
            writer.execute(
                "INSERT INTO graph_evidence VALUES(?,?,?)",
                params![id, record.cpu_id, record.durable_cursor],
            )?;
            records.insert(record.clone(), id);
        }
        Ok(records)
    }

    fn publish(
        writer: &Connection,
        result: &str,
        subjects: &BTreeMap<GraphSubjectKeyV1, u64>,
        records: &BTreeMap<DiscoveryRecordIdV1, u64>,
        edges: &[u64],
    ) -> TestResult {
        for (kind, ids) in [
            (0u8, records.values().copied().collect::<Vec<_>>()),
            (2, subjects.values().copied().collect()),
            (3, edges.to_vec()),
        ] {
            for id in ids {
                writer.execute(
                    "INSERT INTO graph_test_members VALUES(?,?,?)",
                    params![result, kind, id],
                )?;
            }
        }
        Ok(())
    }

    fn selected(writer: &Connection, result: &str) -> TestResult<Vec<GraphEdgeV1>> {
        let mut statement = writer.prepare(&format!(
            "SELECT {} FROM graph_relationships WHERE result_id=? ORDER BY ordinal",
            RelationshipRows::COLUMNS
        ))?;
        let mut rows = statement.query(params![result])?;
        let mut edges = Vec::new();
        while let Some(row) = rows.next()? {
            assert_eq!(row.get::<_, u32>(0)?, edges.len() as u32);
            edges.push(RelationshipRows::decode(row)?);
        }
        Ok(edges)
    }

    fn evidence(
        records: &BTreeMap<DiscoveryRecordIdV1, u64>,
    ) -> BTreeMap<u64, DiscoveryRecordIdV1> {
        records
            .iter()
            .map(|(record, id)| (*id, record.clone()))
            .collect()
    }
}

#[test]
fn native_values_keep_identity_properties_and_history() -> TestResult {
    let fixture = ValueFixture::new()?;
    let writer = Connection::open_in_memory()?;
    ValueFixture::schema(&writer)?;
    let records = fixture.records(&writer)?;
    let subjects = SubjectRows::intern(&writer, &fixture.subjects)?;
    assert_eq!(SubjectRows::intern(&writer, &fixture.subjects)?, subjects);
    let mut second = fixture.edges[0].clone();
    second.key.to = fixture.subjects[2].clone();
    let mut changed = second.clone();
    changed.last_boottime_ns += 1;
    let edges = vec![fixture.edges[0].clone(), second.clone(), changed.clone()];
    let ids = RelationshipRows::intern(&writer, &subjects, &records, &edges)?;
    assert_eq!(
        RelationshipRows::intern(&writer, &subjects, &records, &edges)?,
        ids
    );
    assert_ne!(ids[0], ids[1]);
    assert_ne!(ids[1], ids[2]);
    ValueFixture::publish(&writer, "old", &subjects, &records, &ids[..2])?;
    ValueFixture::publish(&writer, "new", &subjects, &records, &[ids[0], ids[2]])?;
    let old = ValueFixture::selected(&writer, "old")?;
    let new = ValueFixture::selected(&writer, "new")?;
    assert_eq!(old.len(), 2);
    assert_eq!(new.len(), 2);
    assert_eq!(old[1].last_boottime_ns + 1, new[1].last_boottime_ns);
    let counts: (u64, u64) = writer.query_row(
        "SELECT (SELECT count(*) FROM graph_edge_properties),(SELECT count(*) FROM graph_edge_values)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(counts, (1, 3));
    let registry = SubjectRows::registry(&writer)?;
    let keys = RelationshipRows::registry(&writer, &registry, &ValueFixture::evidence(&records))?;
    assert_eq!(keys[&ids[1]], second.key);
    assert_eq!(keys[&ids[2]], changed.key);
    let mut statement = writer.prepare(&format!(
        "SELECT {} FROM graph_subjects WHERE result_id='old' ORDER BY ordinal",
        SubjectRows::COLUMNS
    ))?;
    let mut rows = statement.query([])?;
    let mut selected = Vec::new();
    while let Some(row) = rows.next()? {
        assert_eq!(row.get::<_, u32>(0)?, selected.len() as u32);
        selected.push(SubjectRows::decode(row)?);
    }
    assert_eq!(selected, fixture.subjects);
    Ok(())
}

#[test]
fn native_direct_edges_keep_empty_evidence() -> TestResult {
    let fixture = ValueFixture::new()?;
    let writer = Connection::open_in_memory()?;
    ValueFixture::schema(&writer)?;
    let subjects = SubjectRows::intern(&writer, &fixture.subjects)?;
    let mut edge = fixture.edges[0].clone();
    edge.key.evidence.clear();
    assert_eq!(edge.key.cause, GraphCauseV1::Direct);
    let ids = RelationshipRows::intern(&writer, &subjects, &BTreeMap::new(), &[edge])?;
    ValueFixture::publish(&writer, "direct", &subjects, &BTreeMap::new(), &ids)?;
    let selected = ValueFixture::selected(&writer, "direct")?;
    assert_eq!(selected.len(), 1);
    assert!(selected[0].key.evidence.is_empty());
    assert_eq!(selected[0].key.cause, GraphCauseV1::Direct);
    RelationshipRows::registry(&writer, &SubjectRows::registry(&writer)?, &BTreeMap::new())?;
    Ok(())
}

#[test]
fn native_subjects_reject_invalid_authority_and_kind() -> TestResult {
    let fixture = ValueFixture::new()?;
    let writer = Connection::open_in_memory()?;
    ValueFixture::schema(&writer)?;
    SubjectRows::intern(&writer, &fixture.subjects)?;
    for fault in [
        "tenant_id='short'::BLOB",
        "authority_rank=255",
        "authority_rank=1",
        "authority_boot='short'::BLOB",
        "authority_epoch=0",
        "authority_text=''",
        "identity=''::BLOB",
        "subject_kind=255",
    ] {
        writer.execute_batch("BEGIN TRANSACTION")?;
        writer.execute_batch(&format!(
            "UPDATE graph_subject_values SET {fault} WHERE subject_id=1"
        ))?;
        assert!(SubjectRows::registry(&writer).is_err(), "accepted {fault}");
        writer.execute_batch("ROLLBACK")?;
    }
    Ok(())
}

#[test]
fn native_relationships_reject_corruption() -> TestResult {
    let fixture = ValueFixture::new()?;
    let writer = Connection::open_in_memory()?;
    ValueFixture::schema(&writer)?;
    let records = fixture.records(&writer)?;
    let subjects = SubjectRows::intern(&writer, &fixture.subjects)?;
    RelationshipRows::intern(&writer, &subjects, &records, &fixture.edges)?;
    let subjects = SubjectRows::registry(&writer)?;
    let evidence = ValueFixture::evidence(&records);
    for fault in [
        "UPDATE graph_edge_values SET from_ref=4294967295",
        "UPDATE graph_edge_values SET property_ref=4294967295",
        "UPDATE graph_edge_values SET evidence_refs=[4294967295]::UBIGINT[]",
        "UPDATE graph_edge_values SET evidence_refs=[NULL]::UBIGINT[]",
        "UPDATE graph_edge_values SET value_hash=from_hex(repeat('00',32))",
        "UPDATE graph_edge_values SET last_boottime_ns=last_boottime_ns+1",
        "UPDATE graph_edge_properties SET property_hash=from_hex(repeat('00',32))",
        "UPDATE graph_edge_properties SET edge_type='INVALID'",
        "UPDATE graph_edge_properties SET edge_rank=255",
        "UPDATE graph_edge_properties SET cause_rank=255",
        "UPDATE graph_edge_properties SET proof_quality=struct_update(proof_quality, source_authority := 255::UTINYINT)",
        "UPDATE graph_edge_properties SET proof_quality=struct_update(proof_quality, integrity := NULL::UTINYINT)",
        "UPDATE graph_edge_properties SET required_coverage_interval_ids=['short'::BLOB]",
        "UPDATE graph_edge_properties SET required_coverage_interval_ids=[NULL]::BLOB[]",
    ] {
        writer.execute_batch("BEGIN TRANSACTION")?;
        writer.execute_batch(fault)?;
        assert!(RelationshipRows::registry(&writer, &subjects, &evidence).is_err(), "accepted {fault}");
        writer.execute_batch("ROLLBACK")?;
    }
    Ok(())
}

#[test]
fn native_relationships_check_full_equality() -> TestResult {
    let fixture = ValueFixture::new()?;
    let writer = Connection::open_in_memory()?;
    ValueFixture::schema(&writer)?;
    let records = fixture.records(&writer)?;
    let subjects = SubjectRows::intern(&writer, &fixture.subjects)?;
    let values = RelationshipRows::intern(&writer, &subjects, &records, &fixture.edges)?;
    writer.execute_batch("BEGIN TRANSACTION")?;
    writer.execute_batch("UPDATE graph_edge_properties SET package_id=package_id || '-tamper'")?;
    assert!(RelationshipRows::intern(&writer, &subjects, &records, &fixture.edges).is_err());
    writer.execute_batch("ROLLBACK")?;
    let mut changed = fixture.edges[0].clone();
    changed.last_boottime_ns += 1;
    let collision = NativeRows::hash(&NativeRows::encode(&(
        &changed.key,
        changed.proof_quality,
        &changed.required_coverage_interval_ids,
        changed.first_boottime_ns,
        changed.last_boottime_ns,
    ))?);
    writer.execute_batch("BEGIN TRANSACTION")?;
    writer.execute(
        "UPDATE graph_edge_values SET value_hash=? WHERE edge_id=?",
        params![collision, values[0]],
    )?;
    assert!(RelationshipRows::intern(&writer, &subjects, &records, &[changed]).is_err());
    writer.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn native_values_follow_borrowed_transaction_and_reopen() -> TestResult {
    let fixture = ValueFixture::new()?;
    let root = tempfile::tempdir()?;
    let path = root.path().join("values.duckdb");
    let mut writer = Connection::open(&path)?;
    ValueFixture::schema(&writer)?;
    let records = fixture.records(&writer)?;
    {
        let transaction = writer.transaction()?;
        let subjects = SubjectRows::intern(&transaction, &fixture.subjects)?;
        let edges = RelationshipRows::intern(&transaction, &subjects, &records, &fixture.edges)?;
        ValueFixture::publish(&transaction, "rollback", &subjects, &records, &edges)?;
    }
    assert_eq!(
        writer
            .query_row::<u64, _, _>("SELECT count(*) FROM graph_subject_values", [], |row| row
                .get(0))?,
        0
    );
    assert_eq!(
        writer.query_row::<u64, _, _>("SELECT count(*) FROM graph_edge_values", [], |row| row
            .get(0))?,
        0
    );
    {
        let transaction = writer.transaction()?;
        let subjects = SubjectRows::intern(&transaction, &fixture.subjects)?;
        let edges = RelationshipRows::intern(&transaction, &subjects, &records, &fixture.edges)?;
        ValueFixture::publish(&transaction, "committed", &subjects, &records, &edges)?;
        transaction.commit()?;
    }
    let before = ValueFixture::selected(&writer, "committed")?;
    drop(writer);
    let reader = Connection::open(&path)?;
    assert_eq!(ValueFixture::selected(&reader, "committed")?, before);
    RelationshipRows::registry(
        &reader,
        &SubjectRows::registry(&reader)?,
        &ValueFixture::evidence(&records),
    )?;
    Ok(())
}
