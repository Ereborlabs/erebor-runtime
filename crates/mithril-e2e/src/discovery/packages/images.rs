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
    let before = data.active_managed(&Default::default())?.1;
    let lifecycle = data.subscribe_activations();
    let layout = root.join("image");
    bundle.write_layout(&layout)?;
    let local = PackageBundleV1::read(&layout)?;
    let expected = local.metadata()?;
    let credential = root.join("image-token");
    fs::write(&credential, b"fixture-access")?;
    let (client, server) = fixture.client(&tls, &config, &credential, [1; 16]).await?;
    let reply = client
        .package_operation(PackageOperationRequest {
            definition: PackageRequestV1::InstallImage {
                bundle: local.clone(),
            }
            .encode()?,
            selection: None,
        })
        .await?;
    let PackageResponseV1::Image(installed) = PackageResponseV1::from_bytes(&reply.result)? else {
        return Err("installed image variant".into());
    };
    assert_eq!(installed, expected);
    assert_eq!(
        serde_json::to_value(PackageResponseV1::from_bytes(&reply.result)?)?,
        serde_json::json!({"image": installed}),
    );
    assert_eq!(data.active_managed(&Default::default())?.1, before);
    assert!(!lifecycle.has_changed()?);
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
    let PackageResponseV1::Image(inspected) = inspected else {
        return Err("inspected image variant".into());
    };
    assert_eq!(inspected, expected);
    let data = fixture
        .control
        .analysis_store()
        .ok_or("reopened image store absent")?;
    assert_eq!(data.active_managed(&Default::default())?.1, before);
    let retained = data
        .package_image(
            [1; 16],
            &bundle.root.package_id,
            Some(&bundle.root.revision),
            &Default::default(),
        )?
        .ok_or("retained image absent")?;
    assert_eq!(retained.bundle().artifacts, bundle.artifacts);
    oidc.shutdown().await?;
    Ok(())
}
