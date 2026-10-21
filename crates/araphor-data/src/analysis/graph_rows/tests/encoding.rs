use super::*;

#[test]
fn native_json_encoding_roundtrip() -> TestResult {
    let fixture = CommitFixture::new()?;
    let snapshot = &fixture.snapshot;
    let canonical = serde_json::to_vec(snapshot)?;
    let encoded_header = GraphRows::encode_body(snapshot, &canonical)?;
    assert_eq!(
        GraphHeader::decode(&encoded_header)?.body(snapshot)?,
        canonical
    );
    for source in [
        serde_json::to_vec_pretty(snapshot)?,
        [b" ".as_slice(), &canonical].concat(),
    ] {
        assert!(matches!(
            GraphRows::encode_body(snapshot, &source),
            Err(crate::Error::GraphInvalid {
                field: "graph canonical bytes",
                ..
            })
        ));
    }
    let mut omitted = serde_json::to_value(snapshot)?;
    omitted
        .as_object_mut()
        .ok_or("snapshot")?
        .remove("previous_result_id");
    assert!(GraphRows::encode_body(snapshot, &serde_json::to_vec(&omitted)?).is_err());
    let mut changed = snapshot.clone();
    changed.context_notice_revision += 1;
    assert!(GraphRows::encode_body(snapshot, &serde_json::to_vec(&changed)?).is_err());
    Ok(())
}

#[test]
fn native_json_encoding_bounds() -> TestResult {
    let fixture = CommitFixture::new()?;
    let encoded_header = GraphRows::encode(&fixture.snapshot)?;
    let mut encoded = encoded_header.clone();
    encoded.push(0);
    assert!(GraphHeader::decode(&encoded).is_err());
    let mut snapshot = fixture.snapshot;
    snapshot.input_manifest.coverage[0].gap_reasons = vec!["x".repeat(1024)];
    snapshot.graph.revision = snapshot.input_manifest.clone();
    for finding in &mut snapshot.findings {
        finding.revision = snapshot.input_manifest.clone();
    }
    assert!(matches!(
        CanonicalGraph::bounded(snapshot, 512),
        Err(crate::Error::GraphInvalid {
            field: "graph output bytes",
            ..
        })
    ));
    Ok(())
}

#[test]
fn native_header_finding_bound() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    snapshot
        .input_manifest
        .coverage
        .first_mut()
        .ok_or("coverage")?
        .gap_reasons = vec!["x".repeat(64 * 1024)];
    snapshot.graph.revision = snapshot.input_manifest.clone();
    for finding in &mut snapshot.findings {
        finding.revision = snapshot.input_manifest.clone();
    }
    snapshot.validate()?;
    let encoded_header = GraphRows::encode(&snapshot)?;
    GraphHeader::decode(&encoded_header)?;
    let mut decoder = minicbor::Decoder::new(&encoded_header);
    assert_eq!(decoder.array()?, Some(6));
    let mut fields = [0_u32; 5];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let metadata = decoder.bytes()?;
    for (index, value, expected) in [
        (3, 1024, "graph finding byte bound"),
        (4, metadata.len() as u32 - 1, "graph header format"),
    ] {
        let mut changed = fields;
        changed[index] = value;
        let mut damaged = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut damaged);
        encoder.array(6)?;
        for field in changed {
            encoder.u32(field)?;
        }
        encoder.bytes(metadata)?;
        assert!(matches!(
            GraphHeader::decode(&damaged),
            Err(crate::Error::GraphInvalid { field, .. }) if field == expected
        ));
    }
    Ok(())
}

#[test]
fn native_json_string_spans() -> TestResult {
    let fixture = CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    snapshot.findings[0].limits = vec!["quote\" slash\\ brackets[],:".into(), "é\n😀".into()];
    snapshot.findings[0].limits.sort();
    let canonical = serde_json::to_vec(&snapshot)?;
    let encoded_header = GraphRows::encode_body(&snapshot, &canonical)?;
    assert_eq!(
        GraphHeader::decode(&encoded_header)?.body(&snapshot)?,
        canonical
    );
    Ok(())
}

#[test]
fn native_header_metadata_current_format() -> TestResult {
    let fixture = CommitFixture::new()?;
    let snapshot = &fixture.snapshot;
    let encoded_header = GraphRows::encode(snapshot)?;
    let mut decoder = minicbor::Decoder::new(&encoded_header);
    assert_eq!(decoder.array()?, Some(6));
    assert_eq!(decoder.u32()?, 2);
    assert_eq!(decoder.u32()? as usize, snapshot.graph.subjects.len());
    assert_eq!(decoder.u32()? as usize, snapshot.graph.edges.len());
    assert_eq!(decoder.u32()? as usize, snapshot.findings.len());
    assert_eq!(decoder.u32()? as usize, serde_json::to_vec(snapshot)?.len());
    let metadata: serde_json::Value = serde_json::from_slice(decoder.bytes()?)?;
    assert!(metadata.get("findings").is_none());
    assert!(metadata["graph"].get("subjects").is_none());
    assert!(metadata["graph"].get("edges").is_none());
    assert_eq!(decoder.position(), encoded_header.len());
    assert_eq!(
        GraphHeader::decode(&encoded_header)?.body(snapshot)?,
        serde_json::to_vec(snapshot)?
    );
    Ok(())
}

#[test]
fn native_header_integer_format() -> TestResult {
    let fixture = CommitFixture::new()?;
    let encoded = GraphRows::encode(&fixture.snapshot)?;
    let mut decoder = minicbor::Decoder::new(&encoded);
    assert_eq!(decoder.array()?, Some(6));
    let mut fields = [0u32; 5];
    for field in &mut fields {
        *field = decoder.u32()?;
    }
    let metadata = decoder.bytes()?;
    for index in 1..5 {
        let mut bytes = Vec::new();
        let mut encoder = minicbor::Encoder::new(&mut bytes);
        encoder.array(6)?;
        for (position, field) in fields.iter().enumerate() {
            encoder.u64(if position == index {
                u64::from(u32::MAX) + 1
            } else {
                u64::from(*field)
            })?;
        }
        encoder.bytes(metadata)?;
        assert!(matches!(
            GraphHeader::decode(&bytes),
            Err(crate::Error::GraphInvalid {
                field: "graph header format",
                ..
            })
        ));
    }
    Ok(())
}
