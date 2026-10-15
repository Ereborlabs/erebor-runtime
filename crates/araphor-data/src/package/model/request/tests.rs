use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

fn envelope(
    metadata: &[u8],
    archive: &[u8],
) -> std::result::Result<Vec<u8>, Box<dyn std::error::Error>> {
    let mut encoder = Encoder::new(Vec::new());
    encoder.array(3)?.u32(1)?.bytes(metadata)?.bytes(archive)?;
    Ok(encoder.into_writer())
}

#[test]
fn package_request_archive_roundtrip() -> TestResult {
    let bundle = crate::package::tests::bundle("1", "SELECT 1::UBIGINT AS value");
    let digest = bundle.digest()?;
    for operation in [
        PackageRequestV1::Install {
            scope_id: "team".into(),
            bundle: bundle.clone(),
            parameters: Some(serde_json::json!({"threshold":3})),
        },
        PackageRequestV1::Update {
            scope_id: "team".into(),
            bundle,
        },
    ] {
        let metadata = serde_json::to_vec(&operation)?;
        assert!(!String::from_utf8(metadata)?.contains("bundle"));
        let bytes = operation.encode()?;
        let actual = PackageRequestV1::from_bytes(&bytes)?;
        match actual {
            PackageRequestV1::Install {
                scope_id,
                bundle,
                parameters,
            } => {
                assert_eq!(scope_id, "team");
                assert_eq!(bundle.digest()?, digest);
                assert_eq!(parameters, Some(serde_json::json!({"threshold":3})));
            }
            PackageRequestV1::Update { scope_id, bundle } => {
                assert_eq!(scope_id, "team");
                assert_eq!(bundle.digest()?, digest);
            }
            _ => return Err("operation changed".into()),
        }
    }
    Ok(())
}

#[test]
fn package_request_archive_mismatch() -> TestResult {
    for (metadata, archive) in [
        (
            br#"{"operation":"install","scope_id":"team","parameters":null}"#.as_slice(),
            b"".as_slice(),
        ),
        (
            br#"{"operation":"install","scope_id":"team","bundle":{},"parameters":null}"#
                .as_slice(),
            b"archive".as_slice(),
        ),
        (
            br#"{"operation":"inspect","scope_id":"team","package_id":"example"}"#.as_slice(),
            b"archive".as_slice(),
        ),
    ] {
        assert!(PackageRequestV1::from_bytes(&envelope(metadata, archive)?).is_err());
    }
    let operation = PackageRequestV1::Inspect {
        scope_id: "team".into(),
        package_id: "example".into(),
    };
    assert!(matches!(
        PackageRequestV1::from_bytes(&operation.encode()?)?,
        PackageRequestV1::Inspect { .. }
    ));
    assert!(PackageRequestV1::from_bytes(&serde_json::to_vec(&operation)?).is_err());
    let mut bytes = operation.encode()?;
    bytes.push(0);
    assert!(PackageRequestV1::from_bytes(&bytes).is_err());
    Ok(())
}

#[test]
fn package_request_metadata_roundtrip() -> TestResult {
    for operation in [
        PackageRequestV1::Inspect {
            scope_id: "team".into(),
            package_id: "example".into(),
        },
        PackageRequestV1::Run {
            scope_id: "team".into(),
            package_id: "example".into(),
            export: Some("count".into()),
            evaluation_id: "run-1".into(),
            parameters: Some(serde_json::json!({"limit": 2})),
        },
        PackageRequestV1::Rollback {
            scope_id: "team".into(),
            package_id: "example".into(),
            revision: "1".into(),
        },
        PackageRequestV1::Remove {
            scope_id: "team".into(),
            package_id: "example".into(),
        },
        PackageRequestV1::Test {
            scope_id: "team".into(),
            package_id: "example".into(),
            fixture: Some("sample".into()),
        },
        PackageRequestV1::Query {
            scope_id: "team".into(),
            package_id: "example".into(),
            export: "count".into(),
            result_id: Some("result-1".into()),
            sql: "SELECT * FROM data".into(),
        },
    ] {
        let bytes = operation.encode()?;
        let actual = PackageRequestV1::from_bytes(&bytes)?;
        assert_eq!(
            serde_json::to_value(&actual)?,
            serde_json::to_value(&operation)?
        );
        assert_eq!(actual.action(), operation.action());
        assert!(PackageRequestV1::from_bytes(&bytes[..bytes.len() - 1]).is_err());
        let mut invalid = bytes;
        invalid[1] = 2;
        assert!(PackageRequestV1::from_bytes(&invalid).is_err());
        invalid[0] = 0x82;
        assert!(PackageRequestV1::from_bytes(&invalid).is_err());
    }
    Ok(())
}
