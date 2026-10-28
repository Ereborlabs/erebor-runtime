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
    assert_eq!(header.snapshot, metadata);
    assert_eq!(header.row_bytes, GraphRows::row_bytes(snapshot)?);
    assert_eq!(
        CanonicalGraph::new(snapshot.clone())?.into_snapshot(),
        *snapshot
    );
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(6));
    let mut fields = [0u64; 5];
    for field in &mut fields {
        *field = decoder.u64()?;
    }
    let mut metadata: serde_json::Value = serde_json::from_slice(decoder.bytes()?)?;
    metadata
        .as_object_mut()
        .ok_or("header metadata")?
        .remove("input_manifest");
    let mut damaged = minicbor::Encoder::new(Vec::new());
    damaged.array(6)?;
    for field in fields {
        damaged.u64(field)?;
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
    assert!(matches!(
        CanonicalGraph::bounded(snapshot.clone(), 512),
        Err(crate::Error::GraphInvalid {
            field: "graph output bytes",
            ..
        })
    ));
    assert_eq!(
        CanonicalGraph::bounded(snapshot.clone(), usize::MAX)?.into_snapshot(),
        snapshot
    );
    Ok(())
}

#[test]
fn native_header_row_bounds() -> TestResult {
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
    let mut header = GraphHeader::decode(&encoded)?;
    assert!(encoded.len() > header.row_bytes);
    let count = header.subject_count + header.edge_count + header.finding_count;
    let stored = header.row_bytes + count * (256 + "result".len());
    header.check_bytes("result", stored as u64)?;
    header.check_bytes("result", stored as u64 - 1)?;
    assert!(matches!(
        header.check_bytes("result", stored as u64 + 1),
        Err(crate::Error::GraphInvalid {
            field: "graph storage byte bound",
            ..
        })
    ));
    let native = header.subject_count * size_of::<crate::GraphSubjectKeyV1>()
        + header.edge_count * size_of::<crate::GraphEdgeV1>()
        + header.finding_count * size_of::<crate::FindingV1>();
    assert_eq!(header.allocation_bytes()?, header.row_bytes * 2 + native);
    header.row_bytes = usize::MAX;
    assert!(matches!(
        header.allocation_bytes(),
        Err(crate::Error::GraphInvalid {
            field: "graph allocation byte bound",
            ..
        })
    ));
    assert!(matches!(
        header.check_bytes("result", 0),
        Err(crate::Error::GraphInvalid {
            field: "graph storage byte bound",
            ..
        })
    ));
    header.row_bytes = 0;
    header.subject_count = usize::MAX;
    assert!(header.allocation_bytes().is_err());
    assert!(header.check_bytes("result", 0).is_err());
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
    assert_eq!(decoder.array()?, Some(6));
    assert_eq!(decoder.u32()?, 2);
    assert_eq!(decoder.u32()? as usize, snapshot.graph.subjects.len());
    assert_eq!(decoder.u32()? as usize, snapshot.graph.edges.len());
    assert_eq!(decoder.u32()? as usize, snapshot.findings.len());
    assert_eq!(decoder.u64()? as usize, GraphRows::row_bytes(snapshot)?);
    let metadata: serde_json::Value = serde_json::from_slice(decoder.bytes()?)?;
    assert!(metadata.get("findings").is_none());
    assert!(metadata["graph"].get("subjects").is_none());
    assert!(metadata["graph"].get("edges").is_none());
    assert!(metadata["graph"].get("revision").is_none());
    assert_eq!(
        metadata["input_manifest"],
        serde_json::to_value(&snapshot.input_manifest)?
    );
    assert_eq!(decoder.position(), encoded.len());
    assert_eq!(
        GraphHeader::decode(&encoded)?.snapshot.input_manifest,
        snapshot.input_manifest
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
    assert_eq!(decoder.array()?, Some(6));
    let mut fields = [0u64; 5];
    for field in &mut fields {
        *field = decoder.u64()?;
    }
    let metadata = decoder.bytes()?;
    for index in 1..4 {
        let mut damaged = fields;
        damaged[index] = u64::from(u32::MAX) + 1;
        let mut encoder = minicbor::Encoder::new(Vec::new());
        encoder.array(6)?;
        for field in damaged {
            encoder.u64(field)?;
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
    let mut encoder = minicbor::Encoder::new(Vec::new());
    encoder.array(6)?;
    for field in &fields[..4] {
        encoder.u64(*field)?;
    }
    encoder.u64(u64::MAX)?.bytes(metadata)?;
    let result = GraphHeader::decode(&encoder.into_writer());
    match result {
        Ok(header) => assert!(header.allocation_bytes().is_err()),
        Err(crate::Error::GraphInvalid {
            field: "graph header format",
            ..
        }) => {}
        _ => return Err("unexpected native byte bound result".into()),
    }
    Ok(())
}
