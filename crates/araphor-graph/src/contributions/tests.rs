use duckdb::{params, Connection, OptionalExt as _};

use super::{Contributions, Member, Replacement};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

struct Fixture;

impl Fixture {
    fn schema(writer: &Connection) -> TestResult {
        writer.execute_batch(include_str!(
            "../../../araphor-data/src/analysis/graph_rows/schema.sql"
        ))?;
        writer.execute_batch(
            "INSERT INTO graph_sources VALUES (10, 'first'::BLOB, 'tenant'::BLOB, 'identity'::BLOB),
                (20, 'second'::BLOB, 'tenant'::BLOB, 'identity'::BLOB);
            INSERT INTO graph_evidence VALUES (101,10,0,1), (102,10,0,2), (103,10,0,3), (201,20,0,1);
            INSERT INTO graph_producer_scopes VALUES
                (1,'tenant'::BLOB,10,0,'instance',1,'package','revision','image',1,1)",
        )?;
        Ok(())
    }

    fn member(kind: u8, key: u8, value: u64, record: u64) -> Member {
        Member {
            kind,
            key: vec![key],
            value,
            record: Some(record),
            fact: Some(vec![record as u8]),
            reason: Some(format!("record-{record}")),
            ordinal: u32::from(key),
        }
    }

    fn unit(unit: u64, members: Vec<Member>) -> Replacement {
        Replacement {
            unit: Some(unit),
            members,
        }
    }

    fn version(writer: &Connection, revision: u64) -> TestResult {
        let base: Option<String> = writer
            .query_row(
                "SELECT result_id FROM graph_producer_versions WHERE scope_id = 1
                    ORDER BY commit_revision DESC LIMIT 1",
                [],
                |row| row.get(0),
            )
            .optional()?;
        writer.execute(
            "INSERT INTO graph_producer_versions VALUES (?,1,?,?,0,0,0,0,NULL)",
            params![format!("version-{revision}"), revision, base],
        )?;
        Ok(())
    }

    fn publish(
        writer: &Connection,
        revision: u64,
        replacements: &[Replacement],
        reset: bool,
    ) -> TestResult {
        writer.execute_batch("BEGIN TRANSACTION")?;
        let result: TestResult = (|| {
            Self::version(writer, revision)?;
            Contributions::apply(writer, 1, revision, replacements, reset)?;
            Ok(())
        })();
        writer.execute_batch(if result.is_ok() { "COMMIT" } else { "ROLLBACK" })?;
        result
    }

    fn counts(writer: &Connection, revision: u64) -> Result<[u64; 4], duckdb::Error> {
        writer.query_row(
            "SELECT subject_count, edge_count, finding_count, progress_count
                FROM graph_producer_versions WHERE scope_id = 1 AND commit_revision = ?",
            params![revision],
            |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
        )
    }

    fn values(writer: &Connection, revision: u64) -> Result<Vec<u64>, duckdb::Error> {
        let mut statement = writer.prepare(
            "SELECT DISTINCT value_ref FROM graph_producer_members WHERE scope_id = 1
                AND valid_from <= ? AND (valid_to IS NULL OR valid_to > ?) ORDER BY value_ref",
        )?;
        let values = statement
            .query_map(params![revision, revision], |row| row.get(0))?
            .collect();
        values
    }

    fn anchor(writer: &Connection, revision: u64) -> Result<Member, duckdb::Error> {
        writer.query_row(
            "SELECT m.member_kind, m.member_key, m.value_ref, m.anchor_record_id,
                m.anchor_fact, m.reason_code, m.ordinal
            FROM graph_producer_members m JOIN graph_evidence e ON e.evidence_id = m.anchor_record_id
            WHERE m.scope_id = 1 AND m.member_kind = 2 AND m.valid_from <= ?
                AND (m.valid_to IS NULL OR m.valid_to > ?)
            ORDER BY e.cpu_id, e.durable_cursor, m.unit_ref LIMIT 1",
            params![revision, revision],
            |row| {
                Ok(Member {
                    kind: row.get(0)?,
                    key: row.get(1)?,
                    value: row.get(2)?,
                    record: row.get(3)?,
                    fact: row.get(4)?,
                    reason: row.get(5)?,
                    ordinal: row.get(6)?,
                })
            },
        )
    }
}

#[test]
fn shared_member_keeps_surviving_anchor() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    let first = Fixture::member(2, 1, 11, 101);
    let second = Fixture::member(2, 1, 11, 102);
    Fixture::publish(
        &writer,
        1,
        &[
            Fixture::unit(101, vec![first.clone()]),
            Fixture::unit(102, vec![second.clone()]),
        ],
        false,
    )?;
    assert_eq!(Fixture::counts(&writer, 1)?, [1, 0, 0, 0]);
    assert_eq!(Fixture::anchor(&writer, 1)?, first);
    Fixture::publish(&writer, 2, &[Fixture::unit(101, vec![])], false)?;
    assert_eq!(Fixture::counts(&writer, 2)?, [1, 0, 0, 0]);
    assert_eq!(Fixture::values(&writer, 2)?, vec![11]);
    assert_eq!(Fixture::anchor(&writer, 2)?, second);
    assert_eq!(Fixture::anchor(&writer, 1)?, first);
    Fixture::publish(&writer, 3, &[Fixture::unit(102, vec![])], false)?;
    assert_eq!(Fixture::counts(&writer, 3)?, [0; 4]);
    assert!(Fixture::values(&writer, 3)?.is_empty());
    assert_eq!(Fixture::values(&writer, 1)?, vec![11]);
    assert_eq!(Fixture::values(&writer, 2)?, vec![11]);
    let intervals: Vec<(u64, u64, u64)> = writer
        .prepare(
            "SELECT unit_ref,valid_from,valid_to FROM graph_producer_members ORDER BY unit_ref",
        )?
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))?
        .collect::<Result<_, _>>()?;
    assert_eq!(intervals, vec![(101, 1, 2), (102, 1, 3)]);
    Ok(())
}

#[test]
fn empty_untouched_and_reset_are_distinct() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    Fixture::publish(
        &writer,
        1,
        &[
            Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)]),
            Fixture::unit(102, vec![Fixture::member(2, 2, 12, 102)]),
        ],
        false,
    )?;
    Fixture::publish(&writer, 2, &[Fixture::unit(101, vec![])], false)?;
    assert_eq!(Fixture::values(&writer, 2)?, vec![12]);
    Fixture::publish(&writer, 3, &[], false)?;
    assert_eq!(Fixture::values(&writer, 3)?, vec![12]);
    assert_eq!(Fixture::counts(&writer, 3)?, [1, 0, 0, 0]);
    let retained: (u64, Option<u64>) = writer.query_row(
        "SELECT valid_from,valid_to FROM graph_producer_members WHERE unit_ref = 102",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(retained, (1, None));
    Fixture::publish(
        &writer,
        4,
        &[Fixture::unit(103, vec![Fixture::member(2, 3, 13, 103)])],
        true,
    )?;
    assert_eq!(Fixture::values(&writer, 4)?, vec![13]);
    assert_eq!(Fixture::counts(&writer, 4)?, [1, 0, 0, 0]);
    Fixture::publish(&writer, 5, &[], true)?;
    assert!(Fixture::values(&writer, 5)?.is_empty());
    assert_eq!(Fixture::counts(&writer, 5)?, [0; 4]);
    assert_eq!(Fixture::values(&writer, 1)?, vec![11, 12]);
    Ok(())
}

#[test]
fn unchanged_members_keep_exact_intervals() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    let mut replacement = Fixture::unit(
        101,
        (2..=5)
            .map(|kind| Fixture::member(kind, kind, 10 + u64::from(kind), 101))
            .collect(),
    );
    Fixture::publish(&writer, 1, std::slice::from_ref(&replacement), false)?;
    Fixture::publish(&writer, 2, std::slice::from_ref(&replacement), false)?;
    let total: u64 =
        writer.query_row("SELECT count(*) FROM graph_producer_members", [], |row| {
            row.get(0)
        })?;
    assert_eq!(total, 4);
    assert_eq!(Fixture::counts(&writer, 2)?, [1; 4]);
    let original = replacement.members[0].clone();
    replacement.members[0].fact = Some(vec![0, 1]);
    replacement.members[0].reason = Some("changed".into());
    replacement.members[0].ordinal = 20;
    Fixture::publish(&writer, 3, std::slice::from_ref(&replacement), false)?;
    assert_eq!(Fixture::counts(&writer, 3)?, [1; 4]);
    assert_eq!(Fixture::anchor(&writer, 2)?, original);
    assert_eq!(Fixture::anchor(&writer, 3)?, replacement.members[0]);
    let intervals: (u64, u64) = writer.query_row(
        "SELECT count(*), count(*) FILTER(WHERE valid_from = 1 AND valid_to IS NULL)
            FROM graph_producer_members",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(intervals, (5, 3));
    Ok(())
}

#[test]
fn replacements_remove_all_owners_before_new_value() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    Fixture::publish(
        &writer,
        1,
        &[
            Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)]),
            Fixture::unit(102, vec![Fixture::member(2, 1, 11, 102)]),
        ],
        false,
    )?;
    Fixture::publish(
        &writer,
        2,
        &[
            Fixture::unit(103, vec![Fixture::member(2, 1, 12, 103)]),
            Fixture::unit(101, vec![]),
            Fixture::unit(102, vec![]),
        ],
        false,
    )?;
    assert_eq!(Fixture::values(&writer, 2)?, vec![12]);
    assert_eq!(Fixture::counts(&writer, 2)?, [1, 0, 0, 0]);
    assert_eq!(Fixture::values(&writer, 1)?, vec![11]);
    Ok(())
}

#[test]
fn conflicting_values_roll_back_whole_transaction() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    Fixture::publish(
        &writer,
        1,
        &[Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)])],
        false,
    )?;
    assert!(Fixture::publish(
        &writer,
        2,
        &[Fixture::unit(102, vec![Fixture::member(2, 1, 12, 102)])],
        false,
    )
    .is_err());
    let version: u64 = writer.query_row(
        "SELECT max(commit_revision) FROM graph_producer_versions",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(version, 1);
    assert_eq!(Fixture::values(&writer, 2)?, vec![11]);
    Fixture::publish(
        &writer,
        2,
        &[
            Fixture::unit(101, vec![]),
            Fixture::unit(102, vec![Fixture::member(2, 1, 12, 102)]),
        ],
        false,
    )?;
    assert_eq!(Fixture::values(&writer, 2)?, vec![12]);
    Ok(())
}

#[test]
fn conflicting_new_owners_leave_no_members() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    assert!(Fixture::publish(
        &writer,
        1,
        &[
            Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)]),
            Fixture::unit(102, vec![Fixture::member(2, 1, 12, 102)]),
        ],
        false,
    )
    .is_err());
    assert!(Fixture::values(&writer, 1)?.is_empty());
    Ok(())
}

#[test]
fn invalid_units_and_members_are_rejected() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    let member = Fixture::member(2, 1, 11, 101);
    for replacements in [
        vec![Fixture::unit(101, vec![]), Fixture::unit(101, vec![])],
        vec![Fixture::unit(101, vec![member.clone(), member.clone()])],
        vec![Fixture::unit(0, vec![])],
        vec![Fixture::unit(201, vec![])],
        vec![Fixture::unit(999, vec![])],
        vec![Fixture::unit(101, vec![Fixture::member(2, 1, 11, 201)])],
    ] {
        assert!(Fixture::publish(&writer, 1, &replacements, false).is_err());
        assert!(Fixture::values(&writer, 1)?.is_empty());
    }
    Fixture::publish(&writer, 1, &[Fixture::unit(101, vec![member])], false)?;
    Ok(())
}

#[test]
fn duplicate_requests_fail_before_database_reads() -> TestResult {
    let writer = Connection::open_in_memory()?;
    for replacements in [
        vec![Fixture::unit(101, vec![]), Fixture::unit(101, vec![])],
        vec![Fixture::unit(
            101,
            vec![
                Fixture::member(2, 1, 11, 101),
                Fixture::member(2, 1, 11, 101),
            ],
        )],
    ] {
        assert!(matches!(
            Contributions::apply(&writer, 1, 1, &replacements, false),
            Err(crate::Error::Invalid { .. })
        ));
    }
    Ok(())
}

#[test]
fn publication_members_require_empty_unit() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    writer.execute_batch(
        "BEGIN TRANSACTION;
        INSERT INTO graph_producer_scopes VALUES
            (2,'tenant'::BLOB,10,1,NULL,NULL,NULL,NULL,NULL,1,1),
            (3,'tenant'::BLOB,10,2,NULL,NULL,NULL,NULL,NULL,1,1);
        INSERT INTO graph_producer_versions VALUES
            ('publication',2,1,NULL,0,0,0,0,NULL), ('metadata',3,1,NULL,0,0,0,0,NULL)",
    )?;
    for (scope, kinds) in [(2, vec![2, 3, 4, 6]), (3, vec![0, 1, 7])] {
        assert!(
            Contributions::apply(&writer, scope, 1, &[Fixture::unit(101, vec![])], false).is_err()
        );
        let members = kinds
            .into_iter()
            .map(|kind| Member {
                kind,
                key: vec![kind],
                value: 10 + u64::from(kind),
                record: None,
                fact: None,
                reason: None,
                ordinal: u32::from(kind),
            })
            .collect();
        Contributions::apply(
            &writer,
            scope,
            1,
            &[Replacement {
                unit: None,
                members,
            }],
            true,
        )?;
    }
    writer.execute_batch("COMMIT")?;
    let invalid: bool = writer.query_row(
        "SELECT EXISTS(SELECT 1 FROM graph_producer_members WHERE unit_ref <> 0)",
        [],
        |row| row.get(0),
    )?;
    assert!(!invalid);
    let counts: [u64; 4] = writer.query_row(
        "SELECT subject_count,edge_count,finding_count,progress_count
            FROM graph_producer_versions WHERE scope_id = 2",
        [],
        |row| Ok([row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?]),
    )?;
    assert_eq!(counts, [1, 1, 1, 0]);
    Ok(())
}

#[test]
fn exact_current_version_and_base_are_required() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    assert!(Contributions::apply(&writer, 1, 1, &[], false).is_err());
    Fixture::publish(&writer, 1, &[], false)?;
    writer.execute_batch("BEGIN TRANSACTION")?;
    Fixture::version(&writer, 2)?;
    assert!(Contributions::apply(&writer, 1, 1, &[], false).is_err());
    writer.execute_batch(
        "UPDATE graph_producer_versions SET base_result_id = NULL WHERE commit_revision = 2",
    )?;
    assert!(Contributions::apply(&writer, 1, 2, &[], false).is_err());
    writer.execute_batch("ROLLBACK")?;
    Fixture::publish(&writer, 2, &[], false)?;
    writer.execute_batch("BEGIN TRANSACTION")?;
    Fixture::version(&writer, 3)?;
    writer.execute_batch(
        "UPDATE graph_producer_versions SET base_result_id = 'version-1' WHERE commit_revision = 3",
    )?;
    assert!(Contributions::apply(&writer, 1, 3, &[], false).is_err());
    writer.execute_batch("ROLLBACK")?;
    Ok(())
}

#[test]
fn changed_members_require_newer_revision() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    Fixture::publish(
        &writer,
        1,
        &[Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)])],
        false,
    )?;
    writer.execute_batch("BEGIN TRANSACTION")?;
    assert!(Contributions::apply(&writer, 1, 1, &[Fixture::unit(101, vec![])], false).is_err());
    assert!(Contributions::apply(
        &writer,
        1,
        1,
        &[Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)])],
        false,
    )
    .is_err());
    writer.execute_batch("ROLLBACK")?;
    assert_eq!(Fixture::values(&writer, 1)?, vec![11]);
    Fixture::publish(&writer, 2, &[Fixture::unit(101, vec![])], false)?;
    writer.execute_batch("BEGIN TRANSACTION")?;
    assert!(Contributions::apply(&writer, 1, 2, &[Fixture::unit(101, vec![])], false).is_err());
    writer.execute_batch("ROLLBACK")?;
    assert_eq!(Fixture::counts(&writer, 2)?, [0; 4]);
    Ok(())
}

#[test]
fn legacy_empty_unit_uses_same_owner() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    let replacement = Replacement {
        unit: None,
        members: vec![Fixture::member(2, 1, 11, 101)],
    };
    Fixture::publish(&writer, 1, std::slice::from_ref(&replacement), false)?;
    Fixture::publish(&writer, 2, &[replacement], false)?;
    let stored: (u64, u64) = writer.query_row(
        "SELECT unit_ref,valid_from FROM graph_producer_members",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(stored, (0, 1));
    Fixture::publish(
        &writer,
        3,
        &[Replacement {
            unit: None,
            members: vec![],
        }],
        false,
    )?;
    assert!(Fixture::values(&writer, 3)?.is_empty());
    Ok(())
}

#[test]
fn overlapping_active_intervals_are_rejected() -> TestResult {
    let writer = Connection::open_in_memory()?;
    Fixture::schema(&writer)?;
    let replacement = Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)]);
    Fixture::publish(&writer, 1, std::slice::from_ref(&replacement), false)?;
    Fixture::publish(&writer, 2, std::slice::from_ref(&replacement), false)?;
    writer.execute_batch(
        "INSERT INTO graph_producer_members
            (scope_id,unit_ref,member_kind,member_key,value_ref,anchor_record_id,
                anchor_fact,reason_code,ordinal,valid_from,valid_to)
        SELECT scope_id,unit_ref,member_kind,member_key,value_ref,anchor_record_id,
            anchor_fact,reason_code,ordinal,2,NULL FROM graph_producer_members",
    )?;
    assert!(Fixture::publish(&writer, 3, &[replacement], false).is_err());
    let total: u64 =
        writer.query_row("SELECT count(*) FROM graph_producer_members", [], |row| {
            row.get(0)
        })?;
    assert_eq!(total, 2);
    Ok(())
}

#[test]
fn rollback_and_reopen_keep_committed_owners() -> TestResult {
    let directory = tempfile::tempdir()?;
    let path = directory.path().join("graph.duckdb");
    {
        let writer = Connection::open(&path)?;
        Fixture::schema(&writer)?;
        Fixture::publish(
            &writer,
            1,
            &[Fixture::unit(101, vec![Fixture::member(2, 1, 11, 101)])],
            false,
        )?;
        writer.execute_batch("BEGIN TRANSACTION")?;
        Fixture::version(&writer, 2)?;
        Contributions::apply(&writer, 1, 2, &[Fixture::unit(101, vec![])], false)?;
        assert!(Fixture::values(&writer, 2)?.is_empty());
        writer.execute_batch("ROLLBACK")?;
    }
    let writer = Connection::open(&path)?;
    assert_eq!(Fixture::values(&writer, 1)?, vec![11]);
    assert_eq!(Fixture::values(&writer, 2)?, vec![11]);
    assert_eq!(Fixture::counts(&writer, 1)?, [1, 0, 0, 0]);
    Fixture::publish(&writer, 2, &[Fixture::unit(101, vec![])], false)?;
    assert!(Fixture::values(&writer, 2)?.is_empty());
    assert_eq!(Fixture::values(&writer, 1)?, vec![11]);
    Ok(())
}
