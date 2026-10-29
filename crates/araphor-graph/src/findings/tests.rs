use araphor_analysis_builtins::graph::{
    DeclaredFindingReasonV1, FindingReasonV1, FindingSeverityV1, FindingStateV1, FindingV1,
};
use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection};

use super::{FindingRefs, FindingRows, StoredReason};

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn finding_values_follow_versions() -> TestResult {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../araphor-data/src/analysis/graph_rows/tests/graph.json"
    ))?;
    let finding: FindingV1 = serde_json::from_value(fixture["findings"][0].clone())?;
    let tenant = finding.tenant_id;
    let writer = Connection::open_in_memory()?;
    writer.execute_batch(
        "CREATE TABLE graph_versions (
            result_id VARCHAR PRIMARY KEY, lineage_id UBIGINT NOT NULL,
            commit_revision UBIGINT NOT NULL)",
    )?;
    writer.execute_batch(FindingRows::SCHEMA)?;
    let version = |name: &str, lineage: u64, revision: u64, values: &[FindingV1]| {
        writer.execute(
            "INSERT INTO graph_versions VALUES (?, ?, ?)",
            params![name, lineage, revision],
        )?;
        let references = values
            .iter()
            .map(|finding| FindingRefs {
                finding,
                subject: 17,
                evidence: (0..finding.evidence.len() as u64).collect(),
            })
            .collect::<Vec<_>>();
        FindingRows::apply(&writer, tenant, lineage, revision, &references, 1)?;
        Ok::<_, Box<dyn std::error::Error>>(())
    };
    version("first", 1, 1, std::slice::from_ref(&finding))?;
    version("unchanged", 1, 2, std::slice::from_ref(&finding))?;
    let mut changed = finding.clone();
    changed.limits.push("NEW_PROOF".into());
    version("changed", 1, 3, std::slice::from_ref(&changed))?;
    let mut earlier = finding.clone();
    earlier.finding_id.insert(0, '0');
    version("earlier", 1, 4, &[earlier.clone(), changed.clone()])?;
    version("removed-earlier", 1, 5, std::slice::from_ref(&changed))?;
    version("empty", 1, 6, &[])?;
    version("reentered", 1, 7, std::slice::from_ref(&changed))?;
    version("independent", 8, 8, std::slice::from_ref(&changed))?;
    FindingRows::validate(&writer)?;
    let totals: (u64, u64) = writer.query_row(
        "SELECT (SELECT count(*)::UBIGINT FROM graph_finding_values),
            (SELECT count(*)::UBIGINT FROM graph_finding_membership)",
        [],
        |row| Ok((row.get(0)?, row.get(1)?)),
    )?;
    assert_eq!(totals, (3, 5));
    for (result, expected) in [
        ("first", vec![finding.clone()]),
        ("unchanged", vec![finding.clone()]),
        ("changed", vec![changed.clone()]),
        ("earlier", vec![earlier, changed.clone()]),
        ("removed-earlier", vec![changed.clone()]),
        ("empty", vec![]),
        ("reentered", vec![changed.clone()]),
        ("independent", vec![changed]),
    ] {
        let mut statement = writer.prepare(&format!(
            "SELECT {} FROM graph_findings WHERE result_id = ? ORDER BY ordinal",
            FindingRows::COLUMNS
        ))?;
        let mut rows = statement.query(params![result])?;
        let mut actual = Vec::new();
        while let Some(row) = rows.next()? {
            assert_eq!(row.get::<_, u32>(0)?, actual.len() as u32);
            let selected = &expected[actual.len()];
            assert_eq!(
                FindingRows::references(row)?,
                (17, (0..selected.evidence.len() as u64).collect())
            );
            actual.push(FindingRows::decode(
                row,
                selected.subject_id.clone(),
                selected.evidence.clone(),
            )?);
        }
        assert_eq!(actual, expected, "{result}");
    }
    let mut first_new = finding.clone();
    first_new.finding_id = "multi-a".into();
    let mut second_new = finding.clone();
    second_new.finding_id = "multi-b".into();
    version("multi", 9, 9, &[first_new.clone(), second_new.clone()])?;
    let mut statement = writer.prepare(&format!(
        "SELECT {} FROM graph_findings WHERE result_id = 'multi' ORDER BY ordinal",
        FindingRows::COLUMNS
    ))?;
    let mut rows = statement.query([])?;
    for expected in [&first_new, &second_new] {
        let row = rows.next()?.ok_or("missing multi-batch finding")?;
        assert_eq!(
            FindingRows::decode(row, expected.subject_id.clone(), expected.evidence.clone())?,
            *expected
        );
    }
    assert!(rows.next()?.is_none());
    drop(rows);
    drop(statement);
    let values: u64 = writer.query_row(
        "SELECT count(*)::UBIGINT FROM graph_finding_values",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(values, 5);
    let original_id: u64 = writer.query_row(
        "SELECT value_id FROM graph_finding_values WHERE finding_id = ? AND len(limits) = ?",
        params![finding.finding_id, finding.limits.len() as u64],
        |row| row.get(0),
    )?;
    writer.execute(
        "INSERT INTO graph_finding_membership VALUES (1, ?, 7, NULL)",
        params![original_id],
    )?;
    assert!(FindingRows::validate(&writer).is_err());
    assert!(FindingRows::apply(&writer, tenant, 1, 9, &[], 1).is_err());
    Ok(())
}

#[test]
fn indexed_finding_values_keep_exact_identity() -> TestResult {
    use std::collections::HashMap;

    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../araphor-data/src/analysis/graph_rows/tests/graph.json"
    ))?;
    let mut finding: FindingV1 = serde_json::from_value(fixture["findings"][0].clone())?;
    let tenant = finding.tenant_id;
    let mut first = HashMap::new();
    first.insert("z".into(), "last".into());
    first.insert("a".into(), "first".into());
    let mut second = HashMap::new();
    second.insert("a".into(), "first".into());
    second.insert("z".into(), "last".into());
    let reason = |metadata| {
        FindingReasonV1::Declared(DeclaredFindingReasonV1 {
            code: "HF-PROC-001.EXACT".into(),
            schema: sdk::Schema::new(vec![sdk::Field::new(
                "detail",
                sdk::DataType::UInt64,
                false,
            )
            .with_metadata(metadata)]),
            ipc: vec![1, 2, 3],
        })
    };
    finding.reason = reason(first);
    let mut reordered = finding.clone();
    reordered.reason = reason(second);
    assert_eq!(finding, reordered);
    let evidence = vec![9; finding.evidence.len()];
    let refs = FindingRefs {
        finding: &finding,
        subject: 17,
        evidence: evidence.clone(),
    };
    let reordered_refs = FindingRefs {
        finding: &reordered,
        subject: 17,
        evidence: evidence.clone(),
    };
    assert_eq!(
        FindingRows::value_hash(&refs)?,
        FindingRows::value_hash(&reordered_refs)?
    );
    assert_ne!(
        FindingRows::value_hash(&refs)?,
        FindingRows::value_hash(&FindingRefs {
            finding: &finding,
            subject: 18,
            evidence: evidence.clone()
        })?
    );
    assert_ne!(
        FindingRows::value_hash(&refs)?,
        FindingRows::value_hash(&FindingRefs {
            finding: &finding,
            subject: 17,
            evidence: vec![8; finding.evidence.len()]
        })?
    );

    let mut writer = Connection::open_in_memory()?;
    writer.execute_batch("CREATE TABLE graph_versions (
        result_id VARCHAR PRIMARY KEY, lineage_id UBIGINT NOT NULL, commit_revision UBIGINT NOT NULL);
        INSERT INTO graph_versions VALUES ('first', 1, 1), ('same', 1, 2), ('changed', 1, 3)")?;
    writer.execute_batch(FindingRows::SCHEMA)?;
    FindingRows::apply(&writer, tenant, 1, 1, &[refs], 1)?;
    FindingRows::apply(&writer, tenant, 1, 2, &[reordered_refs], 1)?;
    let count: u64 = writer.query_row(
        "SELECT count(*)::UBIGINT FROM graph_finding_values",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 1);

    let mut changed = finding.clone();
    changed.limits.push("NEW_PROOF".into());
    let changed_refs = FindingRefs {
        finding: &changed,
        subject: 17,
        evidence,
    };
    writer.execute(
        "UPDATE graph_finding_values SET value_hash = ?",
        params![FindingRows::value_hash(&changed_refs)?.as_slice()],
    )?;
    FindingRows::apply(&writer, tenant, 1, 3, &[changed_refs], 1)?;
    let count: u64 = writer.query_row(
        "SELECT count(*)::UBIGINT FROM graph_finding_values",
        [],
        |row| row.get(0),
    )?;
    assert_eq!(count, 2);
    let mut statement = writer.prepare(&format!(
        "SELECT {} FROM graph_findings WHERE result_id = ?",
        FindingRows::COLUMNS
    ))?;
    for (id, expected) in [
        ("first", &finding),
        ("same", &finding),
        ("changed", &changed),
    ] {
        let actual = statement.query_row(params![id], |row| {
            Ok(FindingRows::decode(
                row,
                expected.subject_id.clone(),
                expected.evidence.clone(),
            ))
        })??;
        assert_eq!(&actual, expected);
    }
    drop(statement);
    {
        let transaction = writer.transaction()?;
        transaction.execute(
            "INSERT INTO graph_versions VALUES ('rolled-back', 1, 4)",
            [],
        )?;
        FindingRows::apply(&transaction, tenant, 1, 4, &[], 1)?;
    }
    assert_eq!(
        writer.query_row::<u64, _, _>(
            "SELECT count(*)::UBIGINT FROM graph_finding_membership",
            [],
            |row| row.get(0)
        )?,
        2
    );
    assert_eq!(
        writer.query_row::<u64, _, _>(
            "SELECT count(*)::UBIGINT FROM graph_versions",
            [],
            |row| row.get(0)
        )?,
        3
    );
    Ok(())
}

#[test]
fn reason_codec_keeps_details() -> TestResult {
    use sdk::arrow_array::UInt64Array;
    use std::sync::Arc;

    let schema = sdk::Schema::new(vec![sdk::Field::new("count", sdk::DataType::UInt64, false)]);
    let details =
        sdk::RecordBatch::try_new(Arc::new(schema), vec![Arc::new(UInt64Array::from(vec![3]))])?;
    let value = sdk::ReasonValue {
        output: sdk::RowRef {
            dataset: "findings".into(),
            row: 0,
        },
        code: "example-detector.THRESHOLD".into(),
        details,
    };
    let declared = DeclaredFindingReasonV1::from_value(&value)?;
    assert_eq!(
        FindingRows::decode_bytes::<DeclaredFindingReasonV1>(&FindingRows::encode(&declared)?)?,
        declared
    );
    let reason = FindingReasonV1::Declared(declared);
    assert_eq!(FindingRows::reason_label(&reason)?, value.code);
    assert_eq!(
        FindingRows::restore_reason(FindingRows::decode_bytes(&FindingRows::reason(&reason)?)?)?,
        reason
    );
    assert_eq!(
        FindingRows::restore_reason(FindingRows::decode_bytes(&FindingRows::reason(
            &FindingReasonV1::UnexpectedEffect,
        )?)?)?,
        FindingReasonV1::UnexpectedEffect
    );
    Ok(())
}

#[test]
fn native_labels_roundtrip() -> TestResult {
    let writer = Connection::open_in_memory()?;
    for state in [
        FindingStateV1::Provisional,
        FindingStateV1::Confirmed,
        FindingStateV1::Superseded,
        FindingStateV1::Retracted,
        FindingStateV1::CoverageInsufficient,
    ] {
        let label = FindingRows::state_label(state);
        let mut statement = writer.prepare("SELECT ?")?;
        let mut rows = statement.query(params![label])?;
        assert_eq!(
            FindingRows::label_column::<FindingStateV1>(rows.next()?.ok_or("state row")?, 0)?,
            state
        );
    }
    for severity in [
        FindingSeverityV1::Info,
        FindingSeverityV1::Warning,
        FindingSeverityV1::High,
        FindingSeverityV1::Critical,
    ] {
        let label = FindingRows::severity_label(severity);
        let mut statement = writer.prepare("SELECT ?")?;
        let mut rows = statement.query(params![label])?;
        assert_eq!(
            FindingRows::label_column::<FindingSeverityV1>(rows.next()?.ok_or("severity row")?, 0)?,
            severity
        );
    }
    for (reason, label) in [
        (FindingReasonV1::UnexpectedEffect, "UNEXPECTED_EFFECT"),
        (
            FindingReasonV1::AuditedRoleDeviation,
            "AUDITED_ROLE_DEVIATION",
        ),
        (FindingReasonV1::LineageCoverageGap, "LINEAGE_COVERAGE_GAP"),
        (FindingReasonV1::CredentialPivot, "CREDENTIAL_PIVOT"),
        (
            FindingReasonV1::ContextualCredentialPivot,
            "CONTEXTUAL_CREDENTIAL_PIVOT",
        ),
        (
            FindingReasonV1::MissingAuthorityProof,
            "MISSING_AUTHORITY_PROOF",
        ),
        (FindingReasonV1::Contradiction, "CONTRADICTION"),
        (
            FindingReasonV1::KubernetesProofMissing,
            "KUBERNETES_PROOF_MISSING",
        ),
        (FindingReasonV1::OutsideAuthority, "OUTSIDE_AUTHORITY"),
        (FindingReasonV1::InMemoryOnly, "IN_MEMORY_ONLY"),
        (FindingReasonV1::PayloadUnobservable, "PAYLOAD_UNOBSERVABLE"),
    ] {
        assert_eq!(FindingRows::reason_label(&reason)?, label);
        assert_eq!(
            FindingRows::restore_reason(FindingRows::decode_bytes(&FindingRows::reason(
                &reason
            )?)?)?,
            reason
        );
    }
    Ok(())
}

#[test]
fn binary_codec_rejects_corruption() -> TestResult {
    let reason = FindingReasonV1::UnexpectedEffect;
    let encoded = FindingRows::reason(&reason)?;
    for length in 0..encoded.len() {
        assert!(
            FindingRows::decode_bytes::<StoredReason<DeclaredFindingReasonV1>>(&encoded[..length])
                .is_err()
        );
    }
    let mut trailing = encoded;
    trailing.push(0);
    assert!(matches!(
        FindingRows::decode_bytes::<StoredReason<DeclaredFindingReasonV1>>(&trailing),
        Err(crate::Error::Invalid {
            field: "graph finding trailing bytes",
            ..
        })
    ));
    assert!(FindingRows::decode_bytes::<StoredReason<DeclaredFindingReasonV1>>(&[0xc1]).is_err());
    assert!(
        FindingRows::decode_bytes::<StoredReason<DeclaredFindingReasonV1>>(
            b"\"UNEXPECTED_EFFECT\""
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn native_lists_preserve_values() -> TestResult {
    let fixture: serde_json::Value = serde_json::from_str(include_str!(
        "../../../araphor-data/src/analysis/graph_rows/tests/graph.json"
    ))?;
    let mut finding: FindingV1 = serde_json::from_value(fixture["findings"][0].clone())?;
    let record = finding.evidence.first().ok_or("finding evidence")?.clone();
    finding.evidence = vec![record.clone(), record.clone(), record];
    finding.required_coverage_interval_ids = vec![[2; 16], [1; 16], [2; 16]];
    finding.limits = vec![
        "é\n😀".into(),
        "quote\" slash\\ brackets[],:".into(),
        "é\n😀".into(),
    ];
    let writer = Connection::open_in_memory()?;
    writer.execute_batch("CREATE TABLE graph_versions (
        result_id VARCHAR PRIMARY KEY, lineage_id UBIGINT NOT NULL, commit_revision UBIGINT NOT NULL);
        INSERT INTO graph_versions VALUES ('result', 1, 1)")?;
    writer.execute_batch(FindingRows::SCHEMA)?;
    FindingRows::apply(
        &writer,
        finding.tenant_id,
        1,
        1,
        &[FindingRefs {
            finding: &finding,
            subject: 17,
            evidence: vec![9, 4, 9],
        }],
        1,
    )?;
    let types: (String, String, String, String, String) = writer.query_row(
        "SELECT typeof(subject_ref), typeof(evidence_refs),
            typeof(required_coverage_interval_ids), typeof(limits), typeof(reason)
         FROM graph_finding_values",
        [],
        |row| {
            Ok((
                row.get(0)?,
                row.get(1)?,
                row.get(2)?,
                row.get(3)?,
                row.get(4)?,
            ))
        },
    )?;
    assert_eq!(
        types,
        (
            "UBIGINT".into(),
            "UBIGINT[]".into(),
            "BLOB[]".into(),
            "VARCHAR[]".into(),
            "BLOB".into()
        )
    );
    let mut statement = writer.prepare(&format!(
        "SELECT {} FROM graph_findings",
        FindingRows::COLUMNS
    ))?;
    let mut rows = statement.query([])?;
    let row = rows.next()?.ok_or("finding row")?;
    assert_eq!(FindingRows::references(row)?, (17, vec![9, 4, 9]));
    assert_eq!(
        FindingRows::decode(row, finding.subject_id.clone(), finding.evidence.clone())?,
        finding
    );
    drop(rows);
    drop(statement);
    for fault in [
        "state = 'INVALID'",
        "severity = 'INVALID'",
        "sensitivity = 'INVALID'",
        "evidence_refs = [NULL]::UBIGINT[]",
        "required_coverage_interval_ids = [NULL]::BLOB[]",
        "required_coverage_interval_ids = ['short'::BLOB]",
        "limits = [NULL]::VARCHAR[]",
        "policy_provenance = from_hex('c1')",
        "effects = from_hex('c1')",
        "reason = from_hex('c1')",
        "policy_provenance = policy_provenance || from_hex('00')",
        "effects = effects || from_hex('00')",
        "reason = reason || from_hex('00')",
    ] {
        writer.execute_batch("BEGIN TRANSACTION")?;
        writer.execute_batch(&format!("UPDATE graph_finding_values SET {fault}"))?;
        {
            let mut statement = writer.prepare(&format!(
                "SELECT {} FROM graph_findings",
                FindingRows::COLUMNS
            ))?;
            let mut rows = statement.query([])?;
            let row = rows.next()?.ok_or("damaged finding row")?;
            let restored = FindingRows::references(row).and_then(|_| {
                FindingRows::decode(row, finding.subject_id.clone(), finding.evidence.clone())
            });
            assert!(restored.is_err(), "accepted {fault}");
        }
        writer.execute_batch("ROLLBACK")?;
    }
    Ok(())
}
