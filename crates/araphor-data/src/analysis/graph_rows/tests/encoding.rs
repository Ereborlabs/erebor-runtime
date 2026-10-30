use super::super::header::HeaderMetadata;
use super::*;

#[test]
fn native_header_encoding_roundtrip() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot.clone();
    snapshot.previous_result_id = Some("graph:previous".into());
    snapshot.context_notice_revision = 7;
    snapshot.missing_ranges = vec![(1, 1)];
    snapshot.input_manifest.missing_ranges = snapshot.missing_ranges.clone();
    snapshot.input_manifest.coverage[0].gap_reasons = vec!["quote\" slash\\ é\n😀".into()];
    snapshot.input_manifest.context = vec![crate::AnalysisContextKeyV1 {
        tenant_id: snapshot.scope.identity.tenant_id,
        owner_id: "context".into(),
        entity_key: vec![1, 2],
        lifetime_key: vec![3, 4],
        owner_revision: 1,
    }];
    snapshot.graph.branches = vec![crate::GraphBranchV1 {
        package_id: snapshot.packages[0].package_id.clone(),
        seed: snapshot.graph.subjects[0].clone(),
        evidence: snapshot.input_manifest.evidence.clone(),
        state: crate::GraphBranchStateV1::CoverageUnknown,
        missing_fields: vec!["native-parent".into()],
    }];
    snapshot.graph.facts = vec![
        crate::GraphFactV1 {
            record_id: snapshot.input_manifest.evidence[0].clone(),
            value: crate::GraphFactValueV1::Baseline {
                role_id: 1,
                state_id: 1,
                outside_reviewed_baseline: true,
                reviewed_policy_revision: "policy:1".into(),
            },
        },
        crate::GraphFactV1 {
            record_id: snapshot.input_manifest.evidence[0].clone(),
            value: crate::GraphFactValueV1::NativeParent {
                parent: snapshot.graph.subjects[0].clone(),
                child: snapshot.graph.subjects[1].clone(),
                proof_quality: snapshot.graph.edges[0].proof_quality,
            },
        },
    ];
    snapshot.packages[1].state = crate::GraphPackageStateV1::Declared("CUSTOM".into());
    snapshot.input_positions = vec![(
        snapshot.input_manifest.evidence[0].clone(),
        crate::StorePositionV1 {
            commit_revision: 1,
            ordinal: 0,
        },
    )];
    let encoded = GraphRows::encode(&snapshot)?;
    let header = GraphHeader::decode(&encoded)?;
    let mut metadata = snapshot.clone();
    metadata.graph.subjects.clear();
    metadata.graph.edges.clear();
    metadata.graph.branches.clear();
    metadata.graph.facts.clear();
    metadata.findings.clear();
    metadata.input_manifest.evidence.clear();
    metadata.input_positions.clear();
    assert_eq!(header.snapshot, metadata);
    assert_eq!(
        CanonicalGraph::new(snapshot.clone())?.into_snapshot(),
        snapshot
    );
    assert_eq!(header.notice, (7, 1));
    assert_eq!(header.evidence_count, 1);
    assert_eq!(header.position_count, 1);
    assert_eq!(header.branch_count, 1);
    assert!(!header.branches_loaded);
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(5));
    let mut fields = [0u32; 4];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let decoded: HeaderMetadata = rmp_serde::from_slice(decoder.bytes()?)?;
    let mut metadata = serde_json::to_value(decoded)?;
    metadata
        .get_mut("metadata")
        .and_then(serde_json::Value::as_object_mut)
        .ok_or("header metadata")?
        .remove("input_manifest");
    let mut damaged = minicbor::Encoder::new(Vec::new());
    damaged.array(5)?;
    for field in fields {
        damaged.u32(field)?;
    }
    damaged.bytes(&rmp_serde::to_vec_named(&metadata)?)?;
    assert!(GraphHeader::decode(&damaged.into_writer()).is_err());
    Ok(())
}

#[test]
fn native_header_encoding_bounds() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut encoded = GraphRows::encode(&fixture.snapshot)?;
    encoded.push(0);
    assert!(GraphHeader::decode(&encoded).is_err());
    encoded.pop();
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(5));
    let mut fields = [0u32; 4];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let metadata = decoder.bytes()?;
    let mut duplicate = metadata.to_vec();
    assert!((0x80..=0x8e).contains(&duplicate[0]));
    duplicate[0] += 1;
    duplicate.extend(rmp_serde::to_vec(&"evidence_count")?);
    duplicate.extend(rmp_serde::to_vec(&1u32)?);
    for (index, damaged) in [
        Vec::new(),
        vec![0xc1],
        metadata[..metadata.len() - 1].to_vec(),
        [metadata, &[0]].concat(),
        [metadata, metadata].concat(),
        duplicate,
    ]
    .into_iter()
    .enumerate()
    {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(5)?;
        for field in fields {
            encoder.u32(field)?;
        }
        encoder.bytes(&damaged)?;
        let error = GraphHeader::decode(&encoder.into_writer())
            .err()
            .ok_or_else(|| std::io::Error::other(format!("accepted damaged header {index}")))?;
        assert!(
            matches!(
                &error,
                crate::Error::GraphInvalid {
                    field: "graph header format",
                    ..
                }
            ),
            "damaged header {index}: {error:?}"
        );
    }
    let mut snapshot = fixture.snapshot;
    snapshot.input_manifest.coverage[0].gap_reasons = vec!["x".repeat(1024)];
    assert_eq!(
        CanonicalGraph::new(snapshot.clone())?.into_snapshot(),
        snapshot
    );
    Ok(())
}

#[test]
fn native_header_row_counts() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    snapshot
        .input_manifest
        .coverage
        .first_mut()
        .ok_or("coverage")?
        .gap_reasons = vec!["x".repeat(64 * 1024)];
    snapshot.validate()?;
    let encoded = GraphRows::encode(&snapshot)?;
    let header = GraphHeader::decode(&encoded)?;
    assert!(encoded.len() > 64 * 1024);
    header.check_shape(
        header.subject_count as u64,
        header.edge_count as u64,
        header.finding_count as u64,
    )?;
    assert!(matches!(
        header.check_shape(
            (header.subject_count + 1) as u64,
            header.edge_count as u64,
            header.finding_count as u64
        ),
        Err(crate::Error::GraphInvalid {
            field: "graph row counts",
            ..
        })
    ));
    Ok(())
}

#[test]
fn native_json_string_spans() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot.clone();
    snapshot.findings[0].limits = vec!["quote\" slash\\ brackets[],:".into(), "é\n😀".into()];
    snapshot.findings[0].limits.sort();
    let mut request = fixture.request.clone();
    request.body.clear();
    fixture.store.commit_graph_snapshot(
        request,
        CanonicalGraph::new(snapshot.clone())?,
        &[],
        &[],
        &[],
        true,
        || Ok(()),
    )?;
    assert_eq!(
        fixture.store.graph_result(
            snapshot.scope.identity.tenant_id,
            &fixture.request.result_id
        )?,
        Some(snapshot)
    );
    Ok(())
}

#[test]
fn native_header_metadata_current_format() -> TestResult {
    let fixture = CommitFixture::new()?;
    let snapshot = &fixture.snapshot;
    let encoded = GraphRows::encode(snapshot)?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(5));
    assert_eq!(decoder.u32()?, 2);
    assert_eq!(decoder.u32()? as usize, snapshot.graph.subjects.len());
    assert_eq!(decoder.u32()? as usize, snapshot.graph.edges.len());
    assert_eq!(decoder.u32()? as usize, snapshot.findings.len());
    let decoded: HeaderMetadata = rmp_serde::from_slice(decoder.bytes()?)?;
    let metadata = serde_json::to_value(decoded)?;
    assert!(metadata.get("findings").is_none());
    assert!(metadata["graph"].get("subjects").is_none());
    assert!(metadata["graph"].get("edges").is_none());
    assert!(metadata["graph"].get("branches").is_none());
    assert!(metadata["graph"].get("revision").is_none());
    assert!(metadata["input_manifest"].get("evidence").is_none());
    assert!(metadata.get("input_positions").is_none());
    assert_eq!(
        metadata["evidence_count"],
        snapshot.input_manifest.evidence.len()
    );
    assert_eq!(metadata["position_count"], snapshot.input_positions.len());
    assert_eq!(metadata["branch_count"], snapshot.graph.branches.len());
    assert_eq!(decoder.position(), encoded.len());
    assert_eq!(
        GraphHeader::decode(&encoded)?.evidence_count,
        snapshot.input_manifest.evidence.len()
    );
    let public = serde_json::to_value(snapshot)?;
    assert!(public["graph"].get("revision").is_none());
    assert!(public["findings"]
        .as_array()
        .ok_or("findings")?
        .iter()
        .all(|finding| finding.get("revision").is_none()));
    Ok(())
}

#[test]
fn native_header_integer_format() -> TestResult {
    let fixture = CommitFixture::new()?;
    let encoded = GraphRows::encode(&fixture.snapshot)?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(5));
    let mut fields = [0u64; 4];
    for field in &mut fields {
        *field = decoder.u64()?;
    }
    let metadata = decoder.bytes()?;
    for index in 1..4 {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(5)?;
        for (at, field) in fields.iter().enumerate() {
            if at == index {
                encoder.u64(u64::from(u32::MAX) + 1)?;
            } else {
                encoder.u64(*field)?;
            }
        }
        encoder.bytes(metadata)?;
        let decoded = GraphHeader::decode(&encoder.into_writer());
        if let Ok(expected) = usize::try_from(u64::from(u32::MAX) + 1) {
            let decoded = decoded?;
            let counts = [
                decoded.subject_count,
                decoded.edge_count,
                decoded.finding_count,
            ];
            assert_eq!(counts[index - 1], expected);
        } else {
            assert!(decoded.is_err());
        }
    }
    for index in 1..4 {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(5)?;
        for (at, field) in fields.iter().enumerate() {
            if at == index {
                encoder.i64(-1)?;
            } else {
                encoder.u64(*field)?;
            }
        }
        encoder.bytes(metadata)?;
        assert!(matches!(
            GraphHeader::decode(&encoder.into_writer()),
            Err(crate::Error::GraphInvalid {
                field: "graph header format",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn native_header_explicit_findings() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    let finding_count = snapshot.findings.len();
    snapshot.findings.clear();
    let encoded = GraphHeader::encode(
        &GraphManifest::from_snapshot(&snapshot),
        (
            snapshot.graph.subjects.len(),
            snapshot.graph.edges.len(),
            finding_count,
            snapshot.graph.branches.len(),
        ),
    )?;
    let header = GraphHeader::decode(&encoded)?;
    assert_eq!(header.finding_count, finding_count);
    assert!(header.snapshot.findings.is_empty());
    header.check_shape(
        snapshot.graph.subjects.len() as u64,
        snapshot.graph.edges.len() as u64,
        finding_count as u64,
    )?;
    if let Ok(count) = usize::try_from(u64::from(u32::MAX) + 1) {
        let encoded = GraphHeader::encode(
            &GraphManifest::from_snapshot(&snapshot),
            (
                snapshot.graph.subjects.len(),
                snapshot.graph.edges.len(),
                count,
                snapshot.graph.branches.len(),
            ),
        )?;
        assert_eq!(GraphHeader::decode(&encoded)?.finding_count, count);
    }
    Ok(())
}

#[test]
fn native_header_metadata_rejection() -> TestResult {
    let fixture = CommitFixture::new()?;
    let encoded = GraphRows::encode(&fixture.snapshot)?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(5));
    let mut fields = [0u32; 4];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let decoded: HeaderMetadata = rmp_serde::from_slice(decoder.bytes()?)?;
    let metadata = serde_json::to_value(decoded)?;
    for (pointer, value) in [
        ("/evidence_count", serde_json::json!(-1)),
        ("/position_count", serde_json::json!("1")),
        ("/branch_count", serde_json::json!(-1)),
        ("/fact_count", serde_json::json!("1")),
        ("/metadata/schema_version", serde_json::json!(2)),
        ("/metadata/scope/method_version", serde_json::json!(2)),
        (
            "/metadata/scope/identity/source_epoch",
            serde_json::json!(0),
        ),
        ("/metadata/first_cursor", serde_json::json!(0)),
        ("/metadata/last_cursor", serde_json::json!(0)),
        ("/metadata/previous_result_id", serde_json::json!("")),
        ("/metadata/packages", serde_json::json!([])),
        ("/metadata/packages/0/package_version", serde_json::json!(0)),
        ("/metadata/missing_ranges", serde_json::json!([[1, 1]])),
        (
            "/metadata/input_manifest/missing_ranges",
            serde_json::json!([[2, 1]]),
        ),
    ] {
        let mut damaged = metadata.clone();
        *damaged.pointer_mut(pointer).ok_or("metadata field")? = value;
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(5)?;
        for field in fields {
            encoder.u32(field)?;
        }
        encoder.bytes(&rmp_serde::to_vec_named(&damaged)?)?;
        assert!(
            GraphHeader::decode(&encoder.into_writer()).is_err(),
            "accepted damaged metadata at {pointer}"
        );
    }
    for (pointer, field) in [
        ("", "findings"),
        ("", "input_positions"),
        ("/metadata/input_manifest", "evidence"),
        ("/metadata", "graph"),
        ("/metadata", "subjects"),
        ("/metadata", "branches"),
        ("/metadata", "revision"),
    ] {
        let mut damaged = metadata.clone();
        damaged
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("metadata object")?
            .insert(
                field.into(),
                if pointer == "/metadata/input_manifest" && field == "evidence" {
                    serde_json::json!([fixture.snapshot.input_manifest.evidence[0].clone()])
                } else {
                    serde_json::json!([])
                },
            );
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(5)?;
        for field in fields {
            encoder.u32(field)?;
        }
        encoder.bytes(&rmp_serde::to_vec_named(&damaged)?)?;
        assert!(
            GraphHeader::decode(&encoder.into_writer()).is_err(),
            "accepted duplicate rows at {pointer}/{field}"
        );
    }
    Ok(())
}
