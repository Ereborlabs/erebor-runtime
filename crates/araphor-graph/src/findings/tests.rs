use araphor_analysis_builtins::graph::{DeclaredFindingReasonV1, FindingReasonV1, FindingV1};
use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection};

use super::FindingRows;

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
        FindingRows::apply(&writer, tenant, lineage, revision, values)?;
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
            actual.push(FindingRows::decode(row)?);
        }
        assert_eq!(actual, expected, "{result}");
    }
    let original_id: u64 = writer.query_row(
        "SELECT value_id FROM graph_finding_values WHERE finding_id = ? AND limits = ?",
        params![finding.finding_id, serde_json::to_vec(&finding.limits)?],
        |row| row.get(0),
    )?;
    writer.execute(
        "INSERT INTO graph_finding_membership VALUES (1, ?, 7, NULL)",
        params![original_id],
    )?;
    assert!(FindingRows::validate(&writer).is_err());
    assert!(FindingRows::apply(&writer, tenant, 1, 9, &[]).is_err());
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
    let reason = FindingReasonV1::Declared(DeclaredFindingReasonV1::from_value(&value)?);
    assert_eq!(FindingRows::reason_label(&reason)?, value.code);
    assert_eq!(
        FindingRows::restore_reason(&FindingRows::reason(&reason)?)?,
        reason
    );
    assert_eq!(
        FindingRows::restore_reason("UNEXPECTED_EFFECT")?,
        FindingReasonV1::UnexpectedEffect
    );
    Ok(())
}
