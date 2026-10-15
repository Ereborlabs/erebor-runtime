use super::*;

type TestResult = std::result::Result<(), Box<dyn std::error::Error>>;

#[test]
fn oci_authoring_replaces_layout() -> TestResult {
    let directory = tempfile::tempdir()?;
    let metadata = serde_json::json!({"id": "authoring"});
    let first = Layout::new(
        &metadata,
        &[Layer {
            media_type: WASM_MEDIA_TYPE,
            bytes: b"first-code",
        }],
    )?;
    first.write(directory.path())?;
    first.write(directory.path())?;
    let latest = Layout::new(
        &metadata,
        &[Layer {
            media_type: WASM_MEDIA_TYPE,
            bytes: b"changed-code",
        }],
    )?;
    latest.write(directory.path())?;
    let content = Content::read_files(|name| {
        let path = directory.path().join(name);
        std::fs::read(&path).context(IoSnafu { path: &path })
    })?;
    assert!(latest.matches(&content));
    assert!(!first.matches(&content));
    assert_ne!(latest.digest(), first.digest());
    assert_eq!(content.layers[0].bytes, b"changed-code");
    Ok(())
}

#[test]
fn oci_identity() -> TestResult {
    #[derive(Serialize)]
    struct Metadata {
        z: u32,
        a: u32,
    }
    let raw = (0_u8..=255).cycle().take(8193).collect::<Vec<_>>();
    let layers = [Layer {
        media_type: WASM_MEDIA_TYPE,
        bytes: &raw,
    }];
    let layout = Layout::new(&Metadata { z: 2, a: 1 }, &layers)?;
    let bytes = layout.encode()?;
    assert_eq!(
        Layout::new(&serde_json::json!({"a":1,"z":2}), &layers)?.encode()?,
        bytes
    );
    let decoded = Content::from_bytes(&bytes)?;
    assert_eq!(decoded.layers[0].bytes, raw);
    assert_eq!(
        layout.digest(),
        format!("sha256:{:x}", Sha256::digest(&decoded.manifest))
    );
    Ok(())
}

#[test]
fn oci_rejects_noncanonical_config() -> TestResult {
    let layout = Layout::new(&serde_json::json!({"a": 1}), &[])?;
    let mut files = layout
        .files
        .iter()
        .map(|(name, bytes)| (name.clone(), bytes.to_vec()))
        .collect::<BTreeMap<_, _>>();
    let config: serde_json::Value = serde_json::from_slice(layout.config())?;
    let config = serde_json::to_vec_pretty(&config)?;
    let config_descriptor = Layout::descriptor(CONFIG_MEDIA_TYPE, &config)?;
    files.insert(Layout::blob_path(&config_descriptor)?, config);
    let mut index: ImageIndex = serde_json::from_slice(&files["index.json"])?;
    let mut manifest: ImageManifest =
        serde_json::from_slice(&files[&Layout::blob_path(&index.manifests()[0])?])?;
    manifest.set_config(config_descriptor);
    let manifest = Layout::json(&manifest)?;
    let manifest_descriptor = Layout::descriptor(MediaType::ImageManifest.as_ref(), &manifest)?;
    files.insert(Layout::blob_path(&manifest_descriptor)?, manifest);
    index.set_manifests(vec![manifest_descriptor]);
    files.insert("index.json".into(), Layout::json(&index)?);
    assert!(matches!(Content::read_files(
        |name| files.get(name).cloned().ok_or_else(|| Layout::invalid("missing")),
    ), Err(Error::Contract { code: ErrorCode::Invalid, field, .. })
        if field == "noncanonical Araphor OCI artifact"));
    Ok(())
}

#[test]
fn oci_rejects_blob_changes() -> TestResult {
    let layout = Layout::new(
        &serde_json::json!({}),
        &[Layer {
            media_type: NATIVE_MEDIA_TYPE,
            bytes: b"native-code",
        }],
    )?;
    let mut files = layout
        .files
        .iter()
        .map(|(name, bytes)| (name.clone(), bytes.to_vec()))
        .collect::<BTreeMap<_, _>>();
    let raw_path = files
        .iter()
        .find(|(_, bytes)| bytes.as_slice() == b"native-code")
        .map(|(name, _)| name.clone())
        .ok_or("raw blob absent")?;
    files.insert(raw_path.clone(), b"changed-code".to_vec());
    assert!(Content::read_files(|name| files
        .get(name)
        .cloned()
        .ok_or_else(|| Layout::invalid("missing")))
    .is_err());
    files.remove(&raw_path);
    assert!(Content::read_files(|name| files
        .get(name)
        .cloned()
        .ok_or_else(|| Layout::invalid("missing")))
    .is_err());
    Ok(())
}

#[test]
fn oci_archive_rejections() -> TestResult {
    for (name, kind) in [
        ("index.json", tar::EntryType::Symlink),
        ("../index.json", tar::EntryType::Regular),
        ("index.json", tar::EntryType::Fifo),
    ] {
        let mut archive = tar::Builder::new(Vec::new());
        let mut header = tar::Header::new_ustar();
        header.set_size(0);
        header.set_entry_type(kind);
        header.as_mut_bytes()[..name.len()].copy_from_slice(name.as_bytes());
        header.set_cksum();
        archive.append(&header, &[][..])?;
        assert!(Content::from_bytes(&archive.into_inner()?).is_err());
    }
    let mut archive = tar::Builder::new(Vec::new());
    for _ in 0..2 {
        let mut header = tar::Header::new_ustar();
        header.set_size(2);
        header.set_mode(0o644);
        header.set_cksum();
        archive.append_data(&mut header, "index.json", &b"{}"[..])?;
    }
    assert!(Content::from_bytes(&archive.into_inner()?).is_err());
    let layout = Layout::new(&serde_json::json!({}), &[])?;
    let mut archive = layout.encode()?;
    archive.extend_from_slice(b"hidden");
    assert!(Content::from_bytes(&archive).is_err());
    assert!(Content::from_bytes(b"{\"schema_version\":1}").is_err());
    Ok(())
}
