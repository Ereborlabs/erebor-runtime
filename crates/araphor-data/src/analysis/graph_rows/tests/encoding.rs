use super::*;

#[test]
fn native_json_encoding_roundtrip() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let snapshot = &fixture.snapshot;
    let canonical = serde_json::to_vec(snapshot)?;
    let mut reordered = serde_json::to_value(snapshot)?;
    reordered
        .as_object_mut()
        .ok_or("object")?
        .remove("previous_result_id");
    let reordered = serde_json::to_vec(&reordered)?;
    let escaped = String::from_utf8(reordered.clone())?.replace("\"scope\"", "\"\\u0073cope\"");
    for source in [
        canonical.clone(),
        serde_json::to_vec_pretty(snapshot)?,
        reordered,
        escaped.into_bytes(),
        [b" \r\n".as_slice(), &canonical, b"\t "].concat(),
    ] {
        let rows = GraphRows::encode_body(snapshot, &source)?;
        let header = GraphHeader::decode(rows.header())?;
        assert_eq!(header.body(snapshot, rows.encoding())?, source);
        assert_eq!(rows.encoding().is_empty(), source == canonical);
        assert!(!rows
            .header()
            .windows(canonical.len())
            .any(|bytes| bytes == canonical));
    }
    let mut changed = snapshot.clone();
    changed.context_notice_revision += 1;
    assert!(GraphRows::encode_body(snapshot, &serde_json::to_vec(&changed)?).is_err());
    Ok(())
}

#[test]
fn native_json_optional_boundary() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let source_limit = crate::analysis::MAX_RESULT_BYTES;
    let body = |gap: String| -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
        let mut snapshot = fixture.snapshot.clone();
        snapshot.input_manifest.coverage[0].gap_reasons = vec![gap];
        snapshot.graph.revision = snapshot.input_manifest.clone();
        for finding in &mut snapshot.findings {
            finding.revision = snapshot.input_manifest.clone();
        }
        let mut value = serde_json::to_value(&snapshot)?;
        value
            .as_object_mut()
            .ok_or("snapshot")?
            .remove("previous_result_id");
        Ok(serde_json::to_vec(&value)?)
    };
    let base = body(String::new())?.len();
    let copies = 2 + fixture.snapshot.findings.len();
    let mut source = body("x".repeat((source_limit - base) / copies))?;
    source.resize(source_limit, b' ');
    let snapshot = GraphSnapshotV1::try_from(source.as_slice())?;
    let canonical = serde_json::to_vec(&snapshot)?;
    assert_eq!(source.len(), source_limit);
    assert!(canonical.len() > source_limit);
    assert!(canonical.len() <= GraphRows::MAX_CANONICAL_BYTES);
    let rows = GraphRows::encode_body(&snapshot, &source)?;
    assert_eq!(
        GraphHeader::decode(rows.header())?.body(&snapshot, rows.encoding())?,
        source
    );
    source.push(b' ');
    assert!(GraphRows::encode_body(&snapshot, &source).is_err());
    Ok(())
}

#[test]
fn native_json_encoding_bounds() -> TestResult {
    use super::super::layout::JsonLayout;
    assert!(JsonLayout::replay(&[], b"12", 1).is_err());
    assert!(JsonLayout::replay(&[], b"1", crate::analysis::MAX_RESULT_BYTES + 1).is_err());
    let mut tape = Vec::new();
    minicbor::Encoder::new(&mut tape)
        .array(2)?
        .u32(u32::MAX)?
        .u32(2)?;
    assert!(JsonLayout::replay(&tape, b"1", 1).is_err());
    tape.clear();
    minicbor::Encoder::new(&mut tape).bytes(b"12")?;
    assert!(JsonLayout::replay(&tape, b"1", 1).is_err());
    assert!(JsonLayout::replay(&tape, b"1", 3).is_err());
    assert!(JsonLayout::replay(&[0x9f], b"1", 1).is_err());
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let rows = GraphRows::encode(&fixture.snapshot)?;
    let mut encoded = rows.header().to_vec();
    encoded.push(0);
    assert!(GraphHeader::decode(&encoded).is_err());
    Ok(())
}

#[test]
fn native_header_finding_bound() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
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
    let rows = GraphRows::encode(&snapshot)?;
    GraphHeader::decode(rows.header())?;
    let mut decoder = minicbor::Decoder::new(rows.header());
    assert_eq!(decoder.array()?, Some(7));
    let mut fields = [0_u32; 6];
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
        encoder.array(7)?;
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
fn native_json_layout_authority() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let rows = GraphRows::encode(&fixture.snapshot)?;
    let mut decoder = minicbor::Decoder::new(rows.header());
    assert_eq!(decoder.array()?, Some(7));
    for _ in 0..6 {
        let _ = decoder.u32()?;
    }
    let _ = decoder.bytes()?;
    assert_eq!(decoder.position(), rows.header().len());
    let mut changed = fixture.snapshot.clone();
    changed.context_notice_revision += 1;
    let mut tape = Vec::new();
    minicbor::Encoder::new(&mut tape).bytes(&serde_json::to_vec(&changed)?)?;
    assert!(GraphHeader::decode(rows.header())?
        .body(&fixture.snapshot, &tape)
        .is_err());
    Ok(())
}

#[test]
fn native_json_string_spans() -> TestResult {
    let fixture = crate::graph::tests::native_storage::CommitFixture::new()?;
    let mut snapshot = fixture.snapshot;
    snapshot.findings[0].limits = vec!["quote\" slash\\ brackets[],:".into(), "é\n😀".into()];
    snapshot.findings[0].limits.sort();
    snapshot.validate()?;
    let source = serde_json::to_string_pretty(&snapshot)?
        .replace('é', "\\u00e9")
        .replace('😀', "\\ud83d\\ude00")
        .replace("\\n", "\\u000a");
    let rows = GraphRows::encode_body(&snapshot, source.as_bytes())?;
    assert_eq!(
        GraphHeader::decode(rows.header())?.body(&snapshot, rows.encoding())?,
        source.as_bytes()
    );
    Ok(())
}
