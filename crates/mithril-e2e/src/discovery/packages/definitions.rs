use std::collections::BTreeMap;

use araphor_discovery_definition::{Definition, ImagePin, PackageCall, Program};
use erebor_runtime_ipc::araphor::PackageOperationRequest;

use super::*;

#[tokio::test]
async fn definition_file_admission_roundtrip() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let oidc = OidcFixture::start(&tls.files, "definition-operator").await?;
    let bundle = Denials::bundle("definition-1", 2, false);
    let expected_image = bundle.metadata()?;
    assert_eq!(bundle.artifacts.len(), 2);
    assert!(bundle.artifacts.iter().any(|artifact| {
        artifact.descriptor.id == "denials.count"
            && artifact
                .descriptor
                .exports
                .iter()
                .any(|model| model.checkpoint.is_some())
    }));
    let mut config = oidc.auth(
        "https://localhost:44444",
        Some([1; 16]),
        tls.files.ca.clone(),
    );
    config.package_managers = config.investigators.clone();
    config.package_trust = vec![PackageTrustPinV1 {
        tenant_id: uuid::Uuid::from_bytes([1; 16]).to_string(),
        bundle_digest: bundle.digest()?,
    }];
    let auth = Arc::new(ClientAuth::load(&config).await?);
    let root = tls.path().join("definition-control");
    let fixture = Fixture::open(&root, auth)?;
    let data = fixture
        .control
        .analysis_store()
        .ok_or("definition store absent")?;
    let activations = data.package_activation_page(None)?;
    let discovery = data.discovery_enabled();
    let source = root.join("captured.sql");
    let path = root.join("definition.json");
    let sql = "SELECT count(*) AS count FROM events\n";
    fs::write(&source, sql)?;
    fs::write(
        &path,
        serde_json::to_vec(&json!({
            "name":"captured-sql", "description":"Count retained events.",
            "labels":{"owner":"analysis","team":"security"},
            "program":{"kind":"sql","source":{"file":"captured.sql"}}
        }))?,
    )?;
    let captured = Definition::read(&path)?;
    fs::write(&source, "SELECT 99 AS count\n")?;
    assert_eq!(captured.program.sql()?.as_deref(), Some(sql));
    fs::remove_file(&source)?;
    let labels = BTreeMap::from([("team".into(), "security".into())]);
    let definitions = [
        captured,
        Definition {
            name: "inline-prql".into(),
            description: "Count retained events with PRQL.".into(),
            labels: labels.clone(),
            program: Program::Prql {
                source: araphor_discovery_definition::Source::Inline {
                    inline: "from events\naggregate {count = count this}".into(),
                },
            },
        },
        Definition {
            name: "package-call".into(),
            description: "Select the repeated denial output.".into(),
            labels,
            program: Program::Package {
                call: PackageCall {
                    image: bundle.root.clone(),
                    export: "repeated".into(),
                    inputs: BTreeMap::new(),
                    parameters: json!({}),
                    window: None,
                    output: Some("rows".into()),
                },
            },
        },
    ];
    let credential = root.join("definition-token");
    fs::write(&credential, b"fixture-access")?;
    let (client, server) = fixture.client(&tls, &config, &credential).await?;
    let reply = client
        .package_operation(PackageOperationRequest {
            definition: PackageRequestV1::InstallImage {
                bundle: bundle.clone(),
            }
            .encode()?,
            selection: None,
        })
        .await?;
    let installed: PackageResponseV1 = serde_json::from_slice(&reply.result_json)?;
    assert_eq!(installed.image, Some(expected_image));
    assert!(
        installed.exports.is_empty() && installed.tests.is_empty() && installed.output.is_none()
    );
    assert_eq!(data.package_activation_page(None)?, activations);
    assert_eq!(data.discovery_enabled(), discovery);
    for definition in definitions {
        let expected = definition.clone();
        let reply = client
            .package_operation(PackageOperationRequest {
                definition: PackageRequestV1::AdmitDefinition { definition }.encode()?,
                selection: None,
            })
            .await?;
        let response: PackageResponseV1 = serde_json::from_slice(&reply.result_json)?;
        assert!(
            response.image.is_none()
                && response.exports.is_empty()
                && response.tests.is_empty()
                && response.output.is_none()
        );
        let admitted = response.definition.ok_or("admitted definition absent")?;
        assert_eq!(admitted.definition, expected);
        match &expected.program {
            Program::Sql { .. } | Program::Prql { .. } => {
                assert_eq!(Some(admitted.sql.clone()), expected.program.sql()?);
                assert!(admitted.images.is_empty());
            }
            Program::Package { .. } => assert_eq!(
                admitted.images,
                vec![ImagePin {
                    image: bundle.root.clone(),
                    digest: bundle.digest()?,
                }]
            ),
        }
        let revision = admitted.digest()?;
        let reply = client
            .package_operation(PackageOperationRequest {
                definition: PackageRequestV1::InspectDefinition {
                    name: expected.name,
                    revision: Some(revision.clone()),
                }
                .encode()?,
                selection: None,
            })
            .await?;
        let inspected: PackageResponseV1 = serde_json::from_slice(&reply.result_json)?;
        let inspected = inspected.definition.ok_or("inspected definition absent")?;
        assert_eq!(inspected.digest()?, revision);
        assert_eq!(inspected, admitted);
        assert_eq!(data.package_activation_page(None)?, activations);
        assert_eq!(data.discovery_enabled(), discovery);
    }
    drop(client);
    server.shutdown().await?;
    drop(data);
    drop(fixture);
    oidc.shutdown().await?;
    Ok(())
}
