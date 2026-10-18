use erebor_runtime_ipc::araphor::PackageOperationRequest;

use super::*;

#[tokio::test]
async fn image_install_roundtrip() -> Result<()> {
    let tls = MtlsFixture::new(false)?;
    let oidc = OidcFixture::start(&tls.files, "image-operator").await?;
    let bundle = wasm::bundle();
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
    let root = tls.path().join("image-control");
    let fixture = Fixture::open(&root, auth.clone())?;
    let data = fixture
        .control
        .analysis_store()
        .ok_or("image store absent")?;
    let before = data.package_activation_page(None)?;
    let layout = root.join("image");
    bundle.write_layout(&layout)?;
    let local = PackageBundleV1::read(&layout)?;
    let expected = local.metadata()?;
    let credential = root.join("image-token");
    fs::write(&credential, b"fixture-access")?;
    let (client, server) = fixture.client(&tls, &config, &credential).await?;
    let reply = client
        .package_operation(PackageOperationRequest {
            definition: PackageRequestV1::InstallImage {
                bundle: local.clone(),
            }
            .encode()?,
            selection: None,
        })
        .await?;
    let installed: PackageResponseV1 = serde_json::from_slice(&reply.result_json)?;
    assert_eq!(installed.image, Some(expected.clone()));
    assert!(
        installed.exports.is_empty() && installed.tests.is_empty() && installed.output.is_none()
    );
    assert_eq!(data.package_activation_page(None)?, before);
    let revision = *data.subscribe_revision().borrow();
    fixture
        .operation(PackageRequestV1::InstallImage {
            bundle: local.clone(),
        })
        .await?;
    assert_eq!(*data.subscribe_revision().borrow(), revision);
    drop(client);
    server.shutdown().await?;
    drop(data);
    drop(fixture);
    let fixture = Fixture::open(&root, auth)?;
    let inspected = fixture
        .operation(PackageRequestV1::InspectImage {
            package_id: bundle.root.package_id.clone(),
            revision: Some(bundle.root.revision.clone()),
        })
        .await?;
    assert_eq!(inspected.image, Some(expected));
    let data = fixture
        .control
        .analysis_store()
        .ok_or("reopened image store absent")?;
    assert_eq!(data.package_activation_page(None)?.len(), before.len());
    assert!(data
        .package_activation_page(None)?
        .iter()
        .all(|activation| activation.key.package_id != bundle.root.package_id));
    let retained = data
        .package_image(
            [1; 16],
            &bundle.root.package_id,
            Some(&bundle.root.revision),
            &Default::default(),
        )?
        .ok_or("retained image absent")?;
    assert_eq!(retained.artifacts, bundle.artifacts);
    oidc.shutdown().await?;
    Ok(())
}
