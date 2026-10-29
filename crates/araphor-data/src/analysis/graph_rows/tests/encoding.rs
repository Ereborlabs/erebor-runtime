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
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(5));
    let mut fields = [0u32; 4];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let decoded: HeaderMetadata = rmp_serde::from_slice(decoder.bytes()?)?;
    let mut metadata = serde_json::to_value(decoded)?;
    metadata
        .as_object_mut()
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
    assert_eq!(duplicate[0], 0x8d);
    duplicate[0] = 0x8e;
    duplicate.extend(rmp_serde::to_vec(&"evidence_count")?);
    duplicate.extend(rmp_serde::to_vec(&1u32)?);
    for damaged in [
        Vec::new(),
        vec![0xc1],
        metadata[..metadata.len() - 1].to_vec(),
        [metadata, &[0]].concat(),
        [metadata, metadata].concat(),
        duplicate,
    ] {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(5)?;
        for field in fields {
            encoder.u32(field)?;
        }
        encoder.bytes(&damaged)?;
        assert!(matches!(
            GraphHeader::decode(&encoder.into_writer()),
            Err(crate::Error::GraphInvalid {
                field: "graph header format",
                ..
            })
        ));
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
    assert!(metadata["graph"].get("revision").is_none());
    assert!(metadata["input_manifest"].get("evidence").is_none());
    assert!(metadata.get("input_positions").is_none());
    assert_eq!(
        metadata["evidence_count"],
        snapshot.input_manifest.evidence.len()
    );
    assert_eq!(metadata["position_count"], snapshot.input_positions.len());
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
    let mut fields = [0u32; 4];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let metadata = decoder.bytes()?;
    for index in 1..4 {
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(5)?;
        for (at, field) in fields.iter().enumerate() {
            if at == index {
                encoder.u64(u64::from(u32::MAX) + 1)?;
            } else {
                encoder.u32(*field)?;
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
    let encoded = GraphHeader::encode_with_finding_count(&snapshot, finding_count)?;
    let header = GraphHeader::decode(&encoded)?;
    assert_eq!(header.finding_count, finding_count);
    assert!(header.snapshot.findings.is_empty());
    header.check_shape(
        snapshot.graph.subjects.len() as u64,
        snapshot.graph.edges.len() as u64,
        finding_count as u64,
    )?;
    if let Ok(count) = usize::try_from(u64::from(u32::MAX) + 1) {
        assert!(GraphHeader::encode_with_finding_count(&snapshot, count).is_err());
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
        (
            "/evidence_count",
            serde_json::json!(u64::from(u32::MAX) + 1),
        ),
        (
            "/position_count",
            serde_json::json!(u64::from(u32::MAX) + 1),
        ),
        ("/evidence_count", serde_json::json!(-1)),
        ("/position_count", serde_json::json!("1")),
        ("/schema_version", serde_json::json!(2)),
        ("/scope/method_version", serde_json::json!(2)),
        ("/scope/identity/source_epoch", serde_json::json!(0)),
        ("/first_cursor", serde_json::json!(0)),
        ("/last_cursor", serde_json::json!(0)),
        ("/previous_result_id", serde_json::json!("")),
        ("/packages", serde_json::json!([])),
        ("/packages/0/package_version", serde_json::json!(0)),
        ("/missing_ranges", serde_json::json!([[1, 1]])),
        (
            "/input_manifest/missing_ranges",
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
        ("/input_manifest", "evidence"),
        ("/graph", "subjects"),
        ("/graph", "edges"),
        ("/graph", "revision"),
    ] {
        let mut damaged = metadata.clone();
        damaged
            .pointer_mut(pointer)
            .and_then(serde_json::Value::as_object_mut)
            .ok_or("metadata object")?
            .insert(field.into(), serde_json::json!([]));
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
