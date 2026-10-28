use super::*;

#[test]
fn native_json_encoding_roundtrip() -> TestResult {
    let fixture = CommitFixture::new()?;
    let snapshot = &fixture.snapshot;
    let encoded = GraphRows::encode(snapshot)?;
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
        *snapshot
    );
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(5));
    let mut fields = [0u32; 4];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let mut metadata: serde_json::Value = serde_json::from_slice(decoder.bytes()?)?;
    metadata
        .as_object_mut()
        .ok_or("header metadata")?
        .remove("input_manifest");
    let mut damaged = minicbor::Encoder::new(Vec::new());
    damaged.array(5)?;
    for field in fields {
        damaged.u32(field)?;
    }
    damaged.bytes(&serde_json::to_vec(&metadata)?)?;
    assert!(GraphHeader::decode(&damaged.into_writer()).is_err());
    Ok(())
}

#[test]
fn native_json_encoding_bounds() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut encoded = GraphRows::encode(&fixture.snapshot)?;
    encoded.push(0);
    assert!(GraphHeader::decode(&encoded).is_err());
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
    let metadata: serde_json::Value = serde_json::from_slice(decoder.bytes()?)?;
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
