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
    let bundle = crate::package::tests::bundle("1", "SELECT 1::BIGINT UNSIGNED AS value");
    let digest = bundle.digest()?;
    let operation = PackageRequestV1::InstallImage { bundle };
    let metadata = serde_json::to_vec(&operation)?;
    assert!(!String::from_utf8(metadata)?.contains("bundle"));
    let actual = PackageRequestV1::from_bytes(&operation.encode()?)?;
    let PackageRequestV1::InstallImage { bundle } = actual else {
        return Err("operation changed".into());
    };
    assert_eq!(bundle.digest()?, digest);
    assert_eq!(operation.action(), crate::PackageActionV1::Install);
    Ok(())
}

#[test]
fn package_request_archive_mismatch() -> TestResult {
    for (metadata, archive) in [
        (
            br#"{"operation":"install_image"}"#.as_slice(),
            b"".as_slice(),
        ),
        (
            br#"{"operation":"install_image","bundle":{}}"#.as_slice(),
            b"archive".as_slice(),
        ),
        (
            br#"{"operation":"install_image","scope_id":"team"}"#.as_slice(),
            b"archive".as_slice(),
        ),
        (
            br#"{"operation":"inspect_image","package_id":"example","revision":null}"#.as_slice(),
            b"archive".as_slice(),
        ),
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
    let operation = PackageRequestV1::InspectImage {
        package_id: "example".into(),
        revision: None,
    };
    assert!(matches!(
        PackageRequestV1::from_bytes(&operation.encode()?)?,
        PackageRequestV1::InspectImage { .. }
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
        PackageRequestV1::AdmitDefinition {
            definition: araphor_discovery_definition::Definition {
                name: "counts".into(),
                description: "Count selected records.".into(),
                labels: std::collections::BTreeMap::from([("team".into(), "security".into())]),
                program: araphor_discovery_definition::Program::Sql {
                    source: araphor_discovery_definition::Source::Inline {
                        inline: "SELECT 1 AS count".into(),
                    },
                },
            },
        },
        PackageRequestV1::InspectDefinition {
            name: "counts".into(),
            revision: None,
        },
        PackageRequestV1::InspectDefinition {
            name: "counts".into(),
            revision: Some(format!("sha256:{}", "1".repeat(64))),
        },
        PackageRequestV1::InspectImage {
            package_id: "example".into(),
            revision: None,
        },
        PackageRequestV1::InspectInstanceHistory {
            instance_id: "counts".into(),
        },
        PackageRequestV1::InspectInstance {
            instance_id: "counts".into(),
        },
        PackageRequestV1::ReadInstanceResult {
            instance_id: "counts".into(),
            result_id: "retained-result".into(),
        },
        PackageRequestV1::QueryInstanceResult {
            instance_id: "counts".into(),
            result_id: Some("retained-result".into()),
            sql: "SELECT value, __row_index FROM rows".into(),
        },
        PackageRequestV1::QueryInstanceResult {
            instance_id: "counts".into(),
            result_id: None,
            sql: "SELECT value FROM selected".into(),
        },
        PackageRequestV1::InspectImage {
            package_id: "example".into(),
            revision: Some("1".into()),
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
    for operation in [
        "install", "update", "inspect", "run", "rollback", "remove", "test", "query",
    ] {
        let metadata = serde_json::to_vec(&serde_json::json!({"operation":operation}))?;
        assert!(PackageRequestV1::from_bytes(&envelope(&metadata, &[])?).is_err());
    }
    Ok(())
}

#[test]
fn image_request_runtime_fields() -> TestResult {
    let archive =
        crate::package::tests::bundle("1", "SELECT 1::BIGINT UNSIGNED AS value").encode()?;
    for metadata in [
        br#"{"operation":"install_image","scope_id":"team"}"#.as_slice(),
        br#"{"operation":"install_image","parameters":{}}"#.as_slice(),
        br#"{"operation":"install_image","bundle":{}}"#.as_slice(),
    ] {
        assert!(PackageRequestV1::from_bytes(&envelope(metadata, &archive)?).is_err());
    }
    for metadata in [
        br#"{"operation":"inspect_image","package_id":"example","scope_id":"team"}"#.as_slice(),
        br#"{"operation":"inspect_image","package_id":"example","parameters":{}}"#.as_slice(),
    ] {
        assert!(PackageRequestV1::from_bytes(&envelope(metadata, &[])?).is_err());
    }
    assert_eq!(
        PackageRequestV1::InspectImage {
            package_id: "example".into(),
            revision: None,
        }
        .action(),
        crate::PackageActionV1::Inspect
    );
    Ok(())
}

#[test]
fn instance_requests_are_readonly() -> TestResult {
    for operation in [
        PackageRequestV1::InspectInstanceHistory {
            instance_id: "counts".into(),
        },
        PackageRequestV1::InspectInstance {
            instance_id: "counts".into(),
        },
        PackageRequestV1::ReadInstanceResult {
            instance_id: "counts".into(),
            result_id: "retained-result".into(),
        },
        PackageRequestV1::QueryInstanceResult {
            instance_id: "counts".into(),
            result_id: Some("retained-result".into()),
            sql: "SELECT * FROM rows".into(),
        },
        PackageRequestV1::QueryInstanceResult {
            instance_id: "counts".into(),
            result_id: None,
            sql: "SELECT value FROM selected".into(),
        },
    ] {
        assert_eq!(operation.action(), crate::PackageActionV1::Inspect);
        let mut value = serde_json::to_value(&operation)?;
        for field in ["grant", "parameters", "running", "revision"] {
            value[field] = serde_json::json!({"unexpected": true});
            assert!(
                PackageRequestV1::from_bytes(&envelope(&serde_json::to_vec(&value)?, &[],)?)
                    .is_err()
            );
            value.as_object_mut().ok_or("request object")?.remove(field);
        }
        assert!(PackageRequestV1::from_bytes(&envelope(
            &serde_json::to_vec(&operation)?,
            b"unexpected archive",
        )?)
        .is_err());
    }
    Ok(())
}

#[test]
fn image_test_request() -> TestResult {
    for name in [None, Some("equal".to_owned())] {
        for artifact in [
            None,
            Some(crate::PackageRefV1 {
                package_id: "child".into(),
                revision: "nested-exact".into(),
            }),
        ] {
            let operation = PackageRequestV1::TestImage {
                image: crate::PackageRefV1 {
                    package_id: "fixture".into(),
                    revision: "exact".into(),
                },
                artifact,
                fixture: name.clone(),
            };
            assert_eq!(operation.action(), crate::PackageActionV1::Test);
            let bytes = operation.encode()?;
            let actual = PackageRequestV1::from_bytes(&bytes)?;
            assert_eq!(
                serde_json::to_value(&actual)?,
                serde_json::to_value(&operation)?
            );
            assert_eq!(actual.action(), crate::PackageActionV1::Test);
            assert!(PackageRequestV1::from_bytes(&bytes[..bytes.len() - 1]).is_err());
            assert!(PackageRequestV1::from_bytes(&[bytes.as_slice(), &[0]].concat()).is_err());
            assert!(PackageRequestV1::from_bytes(&envelope(
                &serde_json::to_vec(&operation)?,
                b"archive"
            )?)
            .is_err());
        }
    }
    for metadata in [
        serde_json::json!({"operation":"test_image","fixture":null}),
        serde_json::json!({"operation":"test_image","image":{"package_id":"fixture"}}),
        serde_json::json!({"operation":"test_image","image":{"package_id":"fixture","revision":"exact","extra":true}}),
        serde_json::json!({"operation":"test_image","image":{"package_id":"fixture","revision":"exact"},"scope":"team"}),
        serde_json::json!({"operation":"test_image","image":{"package_id":"fixture","revision":"exact"},"artifact":{"package_id":"child"}}),
        serde_json::json!({"operation":"test_image","image":{"package_id":"fixture","revision":"exact"},"artifact":{"package_id":"child","revision":"exact","extra":true}}),
    ] {
        assert!(
            PackageRequestV1::from_bytes(&envelope(&serde_json::to_vec(&metadata)?, &[])?).is_err()
        );
    }
    Ok(())
}

#[test]
fn removal_requests_are_explicit() -> TestResult {
    let image = araphor_discovery_definition::ImagePin {
        image: crate::PackageRefV1 {
            package_id: "example".into(),
            revision: "1".into(),
        },
        digest: format!("sha256:{}", "1".repeat(64)),
    };
    for (request, action) in [
        (
            PackageRequestV1::AdmitInstance {
                instance_id: "counts".into(),
                definition_name: "counts".into(),
                definition_revision: format!("sha256:{}", "2".repeat(64)),
            },
            crate::PackageActionV1::Run,
        ),
        (
            PackageRequestV1::StartInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 17,
            },
            crate::PackageActionV1::Run,
        ),
        (
            PackageRequestV1::StopInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 17,
            },
            crate::PackageActionV1::Run,
        ),
        (
            PackageRequestV1::RunInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 17,
                evaluation_id: "once".into(),
                rebuild: false,
            },
            crate::PackageActionV1::Run,
        ),
        (
            PackageRequestV1::RenewInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 17,
            },
            crate::PackageActionV1::Run,
        ),
        (
            PackageRequestV1::UpdateInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 17,
                definition_name: "count-events".into(),
                definition_revision: "exact".into(),
                rebuild: true,
            },
            crate::PackageActionV1::Update,
        ),
        (
            PackageRequestV1::RollbackInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 17,
                generation: 11,
                rebuild: true,
            },
            crate::PackageActionV1::Rollback,
        ),
        (
            PackageRequestV1::UninstallImage {
                image: image.clone(),
            },
            crate::PackageActionV1::Remove,
        ),
        (
            PackageRequestV1::RemoveInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 17,
            },
            crate::PackageActionV1::Remove,
        ),
        (
            PackageRequestV1::RecreateInstance {
                instance_id: "counts".into(),
                expected_lifecycle: 19,
                definition_name: "counts".into(),
                definition_revision: format!("sha256:{}", "2".repeat(64)),
            },
            crate::PackageActionV1::Run,
        ),
    ] {
        let encoded = request.encode()?;
        let decoded = PackageRequestV1::from_bytes(&encoded)?;
        assert_eq!(
            serde_json::to_value(&decoded)?,
            serde_json::to_value(&request)?
        );
        assert_eq!(decoded.action(), action);
        let mut value = serde_json::to_value(&request)?;
        for field in ["grant", "running", "force"] {
            value[field] = serde_json::json!(true);
            assert!(
                PackageRequestV1::from_bytes(&envelope(&serde_json::to_vec(&value)?, &[])?)
                    .is_err()
            );
            value.as_object_mut().ok_or("request object")?.remove(field);
        }
        assert!(PackageRequestV1::from_bytes(&envelope(
            &serde_json::to_vec(&request)?,
            b"archive"
        )?)
        .is_err());
    }
    for value in [
        serde_json::json!({"operation":"remove_instance", "instance_id":"counts"}),
        serde_json::json!({"operation":"recreate_instance", "instance_id":"counts", "expected_lifecycle":19, "definition_name":"counts"}),
        serde_json::json!({"operation":"uninstall_image", "image":{"image":{"package_id":"example","revision":"1"}}}),
    ] {
        assert!(
            PackageRequestV1::from_bytes(&envelope(&serde_json::to_vec(&value)?, &[])?).is_err()
        );
    }
    let response = crate::PackageResponseV1::Uninstalled(image.clone());
    assert!(
        matches!(crate::PackageResponseV1::from_bytes(&response.encode()?)?, crate::PackageResponseV1::Uninstalled(actual) if actual == image)
    );
    Ok(())
}
