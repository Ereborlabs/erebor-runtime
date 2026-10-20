use std::collections::BTreeMap;

use araphor_discovery_definition::{Definition, ImagePin};
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
    let sql = "SELECT count(*) AS count FROM events\n";
    let prql = "from events\naggregate {count = count this}\n";
    let counts = "SELECT lifetime_key AS subject, body AS resource, CAST(2 AS BIGINT UNSIGNED) AS count FROM context_versions\n";
    let call_sql = "SELECT * FROM \"denials.repeated\".\"definition-1\".repeated()";
    let call_prql = format!("from s\"{}\"", call_sql.replace('"', "\\\""));
    let image_pin = ImagePin {
        image: bundle.root.clone(),
        digest: bundle.digest()?,
    };
    let files = [
        (
            "captured-sql",
            "Count retained events.",
            "sql:\n  file: captured.sql\n".into(),
            Some(("captured.sql", sql)),
            Vec::new(),
        ),
        (
            "captured-prql",
            "Count retained events with PRQL.",
            "prql:\n  file: captured.prql\n".into(),
            Some(("captured.prql", prql)),
            Vec::new(),
        ),
        (
            "package-call",
            "Select the repeated denial output.",
            format!("sql: |\n  {call_sql}\n"),
            None,
            vec![image_pin.clone()],
        ),
        (
            "prql-package-call",
            "Select the repeated denial output through PRQL.",
            format!("prql: |\n  {call_prql}\n"),
            None,
            vec![image_pin.clone()],
        ),
        (
            "direct-package-call",
            "Select the bound denial counts.",
            "call:\n  package: denials.repeated\n  revision: definition-1\n  export: repeated\n  inputs:\n    counts:\n      file: captured-counts.sql\n  output: rows\n".into(),
            Some(("captured-counts.sql", counts)),
            vec![image_pin],
        ),
    ];
    let labels = BTreeMap::from([
        ("owner".into(), "analysis".into()),
        ("team".into(), "security".into()),
    ]);
    let mut definitions = Vec::new();
    for (name, description, program, source, images) in files {
        let path = root.join(format!("{name}.yaml"));
        if let Some((filename, text)) = source {
            fs::write(root.join(filename), text)?;
        }
        fs::write(&path, format!("name: {name}\ndescription: {description}\nlabels:\n  owner: analysis\n  team: security\n{program}"))?;
        let captured = Definition::read(&path)?;
        assert_eq!(captured.name, name);
        assert_eq!(captured.description, description);
        assert_eq!(captured.labels, labels);
        if let Some((filename, text)) = source {
            if name != "direct-package-call" {
                assert_eq!(captured.program.source().inline()?, text);
            }
            let source = root.join(filename);
            fs::write(&source, "SELECT absent FROM events\n")?;
            fs::remove_file(&source)?;
            assert!(!captured.program.source().inline()?.contains(filename));
        }
        fs::remove_file(&path)?;
        definitions.push((captured, images));
    }
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
    let PackageResponseV1::Image(installed) = PackageResponseV1::from_bytes(&reply.result)? else {
        return Err("installed image variant".into());
    };
    assert_eq!(installed, expected_image);
    assert_eq!(
        serde_json::to_value(PackageResponseV1::from_bytes(&reply.result)?)?,
        serde_json::json!({"image": installed}),
    );
    assert_eq!(data.package_activation_page(None)?, activations);
    assert_eq!(data.discovery_enabled(), discovery);
    for (definition, images) in definitions {
        let expected = definition.clone();
        let reply = client
            .package_operation(PackageOperationRequest {
                definition: PackageRequestV1::AdmitDefinition { definition }.encode()?,
                selection: None,
            })
            .await?;
        let PackageResponseV1::Definition(admitted) = PackageResponseV1::from_bytes(&reply.result)?
        else {
            return Err("admitted definition variant".into());
        };
        assert_eq!(
            serde_json::to_value(PackageResponseV1::from_bytes(&reply.result)?)?,
            serde_json::json!({"definition": admitted}),
        );
        assert_eq!(admitted.definition, expected);
        assert_eq!(admitted.sql, expected.program.sql()?);
        assert_eq!(admitted.images, images);
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
        let PackageResponseV1::Definition(inspected) =
            PackageResponseV1::from_bytes(&reply.result)?
        else {
            return Err("inspected definition variant".into());
        };
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
