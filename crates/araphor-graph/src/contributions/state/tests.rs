use super::*;
use crate::{Contributions, Member, Replacement};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Fixture;

impl Fixture {
    fn schema(writer: &Connection) -> TestResult {
        writer.execute_batch(include_str!(
            "../../../../araphor-data/src/analysis/graph_rows/schema.sql"
        ))?;
        writer.execute_batch(StateRows::SCHEMA)?;
        let fixture: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../araphor-data/src/analysis/graph_rows/tests/graph.json"
        ))?;
        let source: EvidenceIntakeIdentityV1 =
            serde_json::from_value(fixture["scope"]["identity"].clone())?;
        writer.execute(
            "INSERT INTO graph_sources VALUES(10,?,?,?)",
            params![
                source.key(),
                source.tenant_id.as_slice(),
                StateRows::encode(&source)?
            ],
        )?;
        writer.execute_batch(
            "INSERT INTO graph_evidence VALUES(101,10,2,1),(102,10,0,99),(103,10,1,2)",
        )?;
        writer.execute("INSERT INTO graph_producer_scopes VALUES(1,?,10,0,'instance',1,'package','revision','image',1,1)",params![source.tenant_id.as_slice()])?;
        Ok(())
    }

    fn state(
        writer: &Connection,
        unit: u64,
        state: GraphPackageStateV1,
        position: u64,
        fact: Option<&str>,
    ) -> TestResultValue<Replacement> {
        let record=writer.query_row("SELECT source.identity,evidence.cpu_id,evidence.durable_cursor FROM graph_evidence evidence JOIN graph_sources source USING(source_ref) WHERE evidence.evidence_id=?",params![unit],|row|Ok((row.get::<_,Vec<u8>>(0)?,row.get(1)?,row.get(2)?)))?;
        let record = DiscoveryRecordIdV1 {
            stream: StateRows::decode_body(&record.0)?,
            cpu_id: record.1,
            durable_cursor: record.2,
        };
        let key = fact.map(|owner| AnalysisContextKeyV1 {
            tenant_id: record.stream.tenant_id,
            owner_id: owner.into(),
            entity_key: vec![1],
            lifetime_key: vec![2],
            owner_revision: 1,
        });
        let anchor = key.clone().map(|key| FactAnchor {
            record: record.clone(),
            key,
            sensitivity: araphor_analysis_builtins::graph::ContextSensitivityV1::Tenant,
            value: araphor_analysis_builtins::graph::GraphFactValueV1::Baseline {
                role_id: 1,
                state_id: 1,
                outside_reviewed_baseline: true,
                reviewed_policy_revision: "policy".into(),
            },
        });
        let value = StateValue {
            unit,
            state: UnitState {
                state,
                position: Position {
                    commit_revision: position,
                    ordinal: 0,
                },
                fact: key,
            },
            anchor,
        };
        let id = StateRows::intern(writer, std::slice::from_ref(&value))?[0];
        Ok(Replacement {
            unit: Some(unit),
            members: vec![Member {
                kind: 8,
                key: StateRows::hash(&StateRows::encode(&record)?),
                value: id,
                record: Some(unit),
                fact: value.anchor.as_ref().map(StateRows::encode).transpose()?,
                reason: None,
                ordinal: 0,
            }],
        })
    }

    fn publish(
        writer: &Connection,
        revision: u64,
        rows: &[Replacement],
        reset: bool,
    ) -> TestResult {
        Self::publish_default(writer, revision, rows, reset, &GraphPackageStateV1::Waiting)
    }

    fn publish_default(
        writer: &Connection,
        revision: u64,
        rows: &[Replacement],
        reset: bool,
        default: &GraphPackageStateV1,
    ) -> TestResult {
        writer.execute_batch("BEGIN TRANSACTION")?;
        let result: TestResult = (|| {
            writer.execute(
                "INSERT INTO graph_producer_versions VALUES(?,1,?,?,0,0,0,0,NULL)",
                params![
                    format!("version-{revision}"),
                    revision,
                    (revision > 1).then(|| format!("version-{}", revision - 1))
                ],
            )?;
            Contributions::apply(writer, 1, revision, rows, reset)?;
            StateRows::finish(writer, 1, revision, default)?;
            Ok(())
        })();
        writer.execute_batch(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })?;
        result
    }

    fn empty(unit: u64) -> Replacement {
        Replacement {
            unit: Some(unit),
            members: Vec::new(),
        }
    }
    fn current(writer: &Connection, revision: u64) -> TestResultValue<GraphPackageStateV1> {
        Ok(StateRows::current(writer, 1, revision)?)
    }
}

type TestResultValue<T> = std::result::Result<T, Box<dyn std::error::Error>>;

#[test]
fn record_state_orders_history() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("state.duckdb");
    let mut writer = Connection::open(&path)?;
    Fixture::schema(&writer)?;
    let first = Fixture::state(&writer, 101, GraphPackageStateV1::NativeEffect, 1, None)?;
    let second = Fixture::state(
        &writer,
        102,
        GraphPackageStateV1::CredentialObserved,
        100,
        None,
    )?;
    Fixture::publish(&writer, 1, &[first.clone(), second], false)?;
    assert_eq!(
        Fixture::current(&writer, 1)?,
        GraphPackageStateV1::NativeEffect
    );
    let middle = Fixture::state(
        &writer,
        103,
        GraphPackageStateV1::AuthorityChannel,
        200,
        None,
    )?;
    Fixture::publish(&writer, 2, &[middle], false)?;
    assert_eq!(
        Fixture::current(&writer, 2)?,
        GraphPackageStateV1::NativeEffect
    );
    Fixture::publish(&writer, 3, &[Fixture::empty(101)], false)?;
    assert_eq!(
        Fixture::current(&writer, 3)?,
        GraphPackageStateV1::AuthorityChannel
    );
    let fact = Fixture::state(
        &writer,
        103,
        GraphPackageStateV1::KubernetesAudit,
        1,
        Some("owner"),
    )?;
    assert!(Fixture::publish(&writer, 4, &[fact], false).is_err());
    assert_eq!(
        Fixture::current(&writer, 3)?,
        GraphPackageStateV1::AuthorityChannel
    );
    Fixture::publish(&writer, 4, &[Fixture::empty(103)], false)?;
    assert_eq!(
        Fixture::current(&writer, 4)?,
        GraphPackageStateV1::CredentialObserved
    );
    Fixture::publish(&writer, 5, &[Fixture::empty(102)], false)?;
    assert_eq!(Fixture::current(&writer, 5)?, GraphPackageStateV1::Waiting);
    Fixture::publish(&writer, 6, &[first], true)?;
    assert_eq!(
        Fixture::current(&writer, 6)?,
        GraphPackageStateV1::NativeEffect
    );
    StateRows::validate(&writer)?;
    for fault in ["UPDATE graph_producer_versions SET selected_state_ref=NULL WHERE commit_revision=2","UPDATE graph_unit_state_values SET state_tag='WAITING' WHERE state_tag='NATIVE_EFFECT'","UPDATE graph_producer_members SET anchor_record_id=102 WHERE member_kind=8 AND unit_ref=101","UPDATE graph_producer_members SET member_key='bad'::BLOB WHERE member_kind=8 AND unit_ref=101"] {
        let transaction=writer.transaction()?;transaction.execute_batch(fault)?;assert!(StateRows::validate(&transaction).is_err(),"accepted {fault}");
    }
    drop(writer);
    let writer = Connection::open(&path)?;
    StateRows::validate(&writer)?;
    for (revision, state) in [
        (1, GraphPackageStateV1::NativeEffect),
        (3, GraphPackageStateV1::AuthorityChannel),
        (4, GraphPackageStateV1::CredentialObserved),
        (5, GraphPackageStateV1::Waiting),
        (6, GraphPackageStateV1::NativeEffect),
    ] {
        assert_eq!(Fixture::current(&writer, revision)?, state);
    }
    Ok(())
}

#[test]
fn context_state_orders_keys() -> TestResult {
    let mut writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    let first = Fixture::state(
        &writer,
        101,
        GraphPackageStateV1::KubernetesAudit,
        100,
        Some("aa"),
    )?;
    let second = Fixture::state(
        &writer,
        102,
        GraphPackageStateV1::KubernetesObject,
        1,
        Some("z"),
    )?;
    Fixture::publish(&writer, 1, &[first, second], false)?;
    assert_eq!(
        Fixture::current(&writer, 1)?,
        GraphPackageStateV1::KubernetesObject
    );
    Fixture::publish(&writer, 2, &[Fixture::empty(102)], false)?;
    assert_eq!(
        Fixture::current(&writer, 2)?,
        GraphPackageStateV1::KubernetesAudit
    );
    StateRows::validate(&writer)?;
    for fault in ["UPDATE graph_producer_members SET anchor_fact=anchor_fact || from_hex('00') WHERE member_kind=8","UPDATE graph_unit_state_values SET fact_owner='other'","UPDATE graph_unit_state_values SET fact_hash=from_hex(repeat('00',32))"] {
        let transaction=writer.transaction()?;transaction.execute_batch(fault)?;assert!(StateRows::validate(&transaction).is_err(),"accepted {fault}");
    }
    Ok(())
}

#[test]
fn declared_state_retains_type() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    let earlier = Fixture::state(
        &writer,
        102,
        GraphPackageStateV1::Declared("2".into()),
        100,
        None,
    )?;
    Fixture::publish(&writer, 1, &[earlier], false)?;
    assert_eq!(
        Fixture::current(&writer, 1)?,
        GraphPackageStateV1::Declared("2".into())
    );
    let later = Fixture::state(
        &writer,
        101,
        GraphPackageStateV1::Declared("9".into()),
        1,
        None,
    )?;
    Fixture::publish(&writer, 2, &[later], false)?;
    assert_eq!(
        Fixture::current(&writer, 2)?,
        GraphPackageStateV1::Declared("9".into())
    );
    Fixture::publish(&writer, 3, &[Fixture::empty(101)], false)?;
    assert_eq!(
        Fixture::current(&writer, 3)?,
        GraphPackageStateV1::Declared("2".into())
    );
    Fixture::publish_default(
        &writer,
        4,
        &[],
        true,
        &GraphPackageStateV1::Declared("0".into()),
    )?;
    assert_eq!(
        StateRows::current(&writer, 1, 4)?,
        GraphPackageStateV1::Declared("0".into())
    );
    let builtin = Fixture::state(&writer, 103, GraphPackageStateV1::Waiting, 1, None)?;
    let declared = Fixture::state(
        &writer,
        103,
        GraphPackageStateV1::Declared("WAITING".into()),
        1,
        None,
    )?;
    assert_ne!(builtin.members[0].value, declared.members[0].value);
    StateRows::validate(&writer)?;
    Ok(())
}

#[test]
fn empty_state_retains_value() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("defaults.duckdb");
    let mut writer = Connection::open(&path)?;
    Fixture::schema(&writer)?;
    let states = [
        GraphPackageStateV1::Declared("WAITING".into()),
        GraphPackageStateV1::Waiting,
        GraphPackageStateV1::Declared("DIRECT_PIVOT".into()),
    ];
    for (index, state) in states.iter().enumerate() {
        Fixture::publish_default(&writer, index as u64 + 1, &[], index == 2, state)?;
        assert_eq!(Fixture::current(&writer, index as u64 + 1)?, *state);
    }
    assert_eq!(writer.query_row("SELECT count(*) FROM graph_unit_state_values WHERE unit_ref IS NULL AND position_revision IS NULL AND position_ordinal IS NULL",[],|row|row.get::<_,u64>(0))?,3);
    assert_eq!(
        writer.query_row(
            "SELECT count(DISTINCT selected_state_ref) FROM graph_producer_versions",
            [],
            |row| row.get::<_, u64>(0)
        )?,
        3
    );
    let unit = Fixture::state(&writer, 101, GraphPackageStateV1::NativeEffect, 1, None)?;
    Fixture::publish(&writer, 4, &[unit], false)?;
    Fixture::publish_default(&writer, 5, &[Fixture::empty(101)], false, &states[0])?;
    assert_eq!(Fixture::current(&writer, 5)?, states[0]);
    StateRows::validate(&writer)?;
    for fault in [
        "UPDATE graph_producer_versions SET selected_state_ref=NULL WHERE commit_revision=1",
        "UPDATE graph_producer_versions SET selected_state_ref=(SELECT selected_state_ref FROM graph_producer_versions WHERE commit_revision=4) WHERE commit_revision=1",
        "UPDATE graph_producer_versions SET state_count=1 WHERE commit_revision=1",
        "UPDATE graph_unit_state_values SET value_hash=from_hex(repeat('00',32)) WHERE state_declared='WAITING'",
        "UPDATE graph_unit_state_values SET state_tag='UNKNOWN' WHERE state_declared='WAITING'",
        "UPDATE graph_unit_state_values SET state_declared='' WHERE state_declared='WAITING'",
    ] {
        let transaction = writer.transaction()?;
        assert_eq!(transaction.execute(fault,[])?,1,"{fault}");
        assert!(StateRows::validate(&transaction).is_err(),"accepted {fault}");
    }
    drop(writer);
    let reader = Connection::open(&path)?;
    StateRows::validate(&reader)?;
    for (index, state) in states.iter().enumerate() {
        assert_eq!(StateRows::current(&reader, 1, index as u64 + 1)?, *state);
    }
    assert_eq!(StateRows::current(&reader, 1, 5)?, states[0]);
    Ok(())
}
