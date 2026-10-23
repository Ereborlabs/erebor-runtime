use araphor_data::DiscoverySnapshotRowV1 as NativeSnapshot;

use super::*;

fn subset(first: u64, last: u64) -> Recorded {
    let mut fixture = Recorded::new(last);
    fixture
        .records
        .retain(|record| record.id.durable_cursor >= first);
    fixture
        .contexts
        .retain(|binding| binding.record_id.durable_cursor >= first);
    fixture.coverage[0].first_cursor = first;
    fixture.coverage[0].expected_records = last - first + 1;
    fixture
}

fn native_row(value: Snapshot) -> TestResult<NativeSnapshot> {
    let mut value = serde_json::to_value(value)?;
    value
        .as_object_mut()
        .ok_or("snapshot object")?
        .remove("duplicate_deliveries");
    Ok(serde_json::from_value(value)?)
}

fn evaluation(datasets: Vec<sdk::Dataset>) -> sdk::Evaluation {
    sdk::Evaluation {
        export: "merge".into(),
        inputs: datasets
            .into_iter()
            .map(|data| sdk::Input {
                data,
                revision: sdk::Revision {
                    owner: "native-merge-test".into(),
                    id: "1".into(),
                    window: None,
                },
                coverage: sdk::Coverage {
                    state: sdk::CoverageState::Unknown,
                    limits: Vec::new(),
                },
            })
            .collect(),
        parameters: None,
        checkpoint: None,
        context: sdk::EvaluationContext {
            id: "merge".into(),
            time_utc_ns: 1,
            seed: None,
        },
    }
}

fn oracle(left: &NativeSnapshot, right: &NativeSnapshot) -> TestResult<NativeSnapshot> {
    let metadata = [left, right].map(|snapshot| builtin::Snapshot {
        tenant_id: snapshot.tenant_id,
        source_revision: snapshot.source_revision.clone(),
        proof_kind: snapshot.proof_kind,
        counts: builtin::Counts {
            duplicates: 0,
            accepted: snapshot.accepted_records,
            included: snapshot.included_records,
            unresolved: snapshot.unresolved_records,
            excluded: snapshot.excluded_records,
        },
    });
    macro_rules! sides {
        ($field:ident) => {
            left.$field
                .iter()
                .cloned()
                .map(|value| builtin::Side { side: 0, value })
                .chain(
                    right
                        .$field
                        .iter()
                        .cloned()
                        .map(|value| builtin::Side { side: 1, value }),
                )
                .collect::<Vec<_>>()
        };
    }
    let lifecycle = [left, right]
        .into_iter()
        .enumerate()
        .flat_map(|(side, snapshot)| {
            snapshot.lifecycle.iter().cloned().map(move |value| {
                Ok(builtin::Side {
                    side: side as u8,
                    value: Lifecycle::try_from(value)?,
                })
            })
        })
        .collect::<araphor_data::Result<Vec<_>>>()?;
    macro_rules! input {
        ($ty:ty, $name:literal, $values:expr) => {
            Rows::encode(&Discovery::port::<$ty>($name), &$values)?
        };
    }
    let output = Discovery::evaluate(&evaluation(vec![
        input!(builtin::Snapshot, "snapshots", metadata),
        input!(builtin::Side<BehaviorAtomV1>, "atoms", sides!(atoms)),
        input!(builtin::Side<Coverage>, "coverage", sides!(coverage)),
        input!(builtin::Side<Disposition>, "unresolved", sides!(unresolved)),
        input!(builtin::Side<Disposition>, "excluded", sides!(excluded)),
        input!(builtin::Side<Lifecycle>, "lifecycle", lifecycle),
    ]))?;
    macro_rules! rows {
        ($ty:ty, $name:literal) => {
            Rows::decode::<$ty>(
                &Discovery::port::<$ty>($name),
                output
                    .datasets
                    .iter()
                    .find(|data| data.name == $name)
                    .ok_or("merge dataset")?,
            )?
        };
    }
    let counts = rows!(builtin::Counts, "counts")
        .pop()
        .ok_or("merge counts")?;
    Ok(NativeSnapshot {
        schema_version: left.schema_version,
        tenant_id: left.tenant_id,
        source_revision: left.source_revision.clone(),
        proof_kind: left.proof_kind,
        accepted_records: counts.accepted,
        included_records: counts.included,
        unresolved_records: counts.unresolved,
        excluded_records: counts.excluded,
        atoms: rows!(BehaviorAtomV1, "atoms"),
        coverage: rows!(Coverage, "coverage"),
        unresolved: rows!(Disposition, "unresolved"),
        excluded: rows!(Disposition, "excluded"),
        lifecycle: rows!(Lifecycle, "lifecycle")
            .into_iter()
            .map(Into::into)
            .collect(),
    })
}

async fn query(
    left: Option<&NativeSnapshot>,
    right: &NativeSnapshot,
) -> TestResult<NativeSnapshot> {
    let context = SessionContext::new();
    let schema = Arc::new(NativeSnapshot::schema().clone());
    for (name, rows) in [
        ("left_snapshot", left.into_iter().collect::<Vec<_>>()),
        ("right_snapshot", vec![right]),
    ] {
        let batch = serde_arrow::to_record_batch(schema.fields(), &rows)?;
        context.register_table(
            name,
            Arc::new(MemTable::try_new(schema.clone(), vec![vec![batch]])?),
        )?;
    }
    let frame = native_frame(&context, MERGE_SQL).await?;
    frame.logical_plan().apply_with_subqueries(|plan| {
        assert!(!matches!(plan, LogicalPlan::Extension(_)));
        Ok(TreeNodeRecursion::Continue)
    })?;
    let schema = Arc::new(frame.schema().as_arrow().clone());
    let batches = frame.collect().await?;
    let mut values: Vec<NativeSnapshot> =
        serde_arrow::from_record_batch(&concat_batches(&schema, &batches)?)?;
    assert_eq!(values.len(), 1);
    Ok(values.remove(0))
}

#[tokio::test]
async fn merge_matches_builtin() -> TestResult {
    let left = native_row(subset(1, 2).oracle()?)?;
    let right = native_row(subset(3, 5).oracle()?)?;
    assert_eq!(query(Some(&left), &right).await?, oracle(&left, &right)?);
    assert_eq!(query(Some(&right), &left).await?, oracle(&right, &left)?);
    assert_eq!(query(Some(&left), &left).await?, left);
    assert_eq!(query(None, &right).await?, right);
    Ok(())
}

#[tokio::test]
async fn merge_keeps_witness_order() -> TestResult {
    let mut left = subset(1, 12);
    let mut right = subset(13, 24);
    for fixture in [&mut left, &mut right] {
        for record in &mut fixture.records {
            record.effect.target_task_cookie = (record.id.durable_cursor % 2 == 0).then_some(0);
        }
    }
    let left = native_row(left.oracle()?)?;
    let right = native_row(right.oracle()?)?;
    let merged = query(Some(&left), &right).await?;
    assert_eq!(merged, oracle(&left, &right)?);
    assert_eq!(merged.atoms.len(), 2);
    assert!(merged
        .atoms
        .iter()
        .all(|atom| atom.evidence_sample.len() == 8));
    assert!(merged.atoms[0].key.effect.target_task_cookie.is_none());
    Ok(())
}

#[tokio::test]
async fn merge_zips_unequal_lists() -> TestResult {
    let mut left = subset(1, 40);
    let mut right = subset(41, 80);
    for fixture in [&mut left, &mut right] {
        for record in &mut fixture.records {
            record.effect.task_cookie = record.id.durable_cursor;
        }
    }
    let left = native_row(left.oracle()?)?;
    let right = native_row(right.oracle()?)?;
    let merged = query(Some(&left), &right).await?;
    assert_eq!(merged, oracle(&left, &right)?);
    assert_eq!(merged.atoms.len(), 80);
    let empty = native_row(Recorded::new(0).oracle()?)?;
    assert_eq!(query(None, &empty).await?, empty);
    assert_eq!(query(Some(&empty), &empty).await?, empty);
    Ok(())
}

#[tokio::test]
async fn merge_preserves_range_boundaries() -> TestResult {
    let mut left = native_row(subset(1, 2).oracle()?)?;
    left.coverage[0].state = CoverageState::Gapped;
    left.coverage[0].gap_reasons = vec!["z".into(), "a".into(), "z".into()];
    let mut right = native_row(subset(3, 4).oracle()?)?;
    right.coverage[0].state = CoverageState::Unknown;
    right.coverage[0].gap_reasons = vec!["b".into()];
    assert_eq!(query(Some(&left), &right).await?, oracle(&left, &right)?);
    for change in ["revision", "interval", "cpu"] {
        let mut changed = right.clone();
        match change {
            "revision" => changed.coverage[0].coverage_revision += 1,
            "interval" => changed.coverage[0].coverage_interval_id = [9; 16],
            "cpu" => changed.coverage[0].cpu_id += 1,
            _ => unreachable!(),
        }
        let merged = query(Some(&left), &changed).await?;
        assert_eq!(merged, oracle(&left, &changed)?);
        assert_eq!(merged.coverage[0].gap_reasons, left.coverage[0].gap_reasons);
    }
    Ok(())
}

#[tokio::test]
async fn merge_rejects_conflicts() -> TestResult {
    let left = native_row(subset(1, 3).oracle()?)?;
    let overlap = native_row(subset(2, 4).oracle()?)?;
    assert!(query(Some(&left), &overlap)
        .await
        .unwrap_err()
        .to_string()
        .contains("snapshot overlap"));
    let mut right = native_row(subset(4, 5).oracle()?)?;
    right.source_revision.push_str("-other");
    assert!(query(Some(&left), &right)
        .await
        .unwrap_err()
        .to_string()
        .contains("snapshot source"));
    let mut left = left;
    right.source_revision = left.source_revision.clone();
    left.lifecycle[0] = Lifecycle {
        case: Case::Startup,
        state: State::Declared {
            reason: "left".into(),
        },
    }
    .into();
    right.lifecycle[0] = Lifecycle {
        case: Case::Startup,
        state: State::Declared {
            reason: "right".into(),
        },
    }
    .into();
    assert!(query(Some(&left), &right)
        .await
        .unwrap_err()
        .to_string()
        .contains("lifecycle state"));
    Ok(())
}

#[tokio::test]
async fn merge_checks_counter_overflow() -> TestResult {
    let mut left = native_row(subset(1, 1).oracle()?)?;
    let mut right = native_row(subset(2, 2).oracle()?)?;
    left.accepted_records = u64::MAX;
    left.included_records = u64::MAX;
    left.atoms[0].count = u64::MAX;
    assert!(query(Some(&left), &right)
        .await
        .unwrap_err()
        .to_string()
        .contains("count"));
    left.accepted_records = 1;
    left.included_records = 1;
    left.atoms[0].count = 1;
    left.coverage[0].expected_records = u64::MAX;
    right.coverage[0].expected_records = 1;
    assert!(query(Some(&left), &right)
        .await
        .unwrap_err()
        .to_string()
        .contains("count"));
    Ok(())
}
