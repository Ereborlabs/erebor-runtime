use super::*;

fn grow(value: &mut String) -> usize {
    let before = value.capacity();
    value.reserve(1024);
    value.capacity() - before
}

#[test]
fn metadata_counts_spare_capacity() -> TestResult {
    let directory = tempfile::tempdir()?;
    let store = AnalysisStore::open(directory.path().join("data"))?;
    let fixture = Fixture::admit(&store)?;
    let mut spec = fixture.instance.spec;
    spec.grant.authorization_id = Some("authority".into());
    spec.grant.selection.nodes = vec!["node".into()];
    spec.grant.selection.results = vec!["result".into()];
    spec.definition
        .definition
        .labels
        .insert("label".into(), "value".into());
    spec.manifest
        .calls
        .values_mut()
        .next()
        .ok_or("manifest call absent")?
        .artifact = Some(araphor_package::PackageArtifactIdentityV1 {
        digest: "digest".into(),
        closure_digest: Some("closure".into()),
        platform: Some("platform".into()),
    });
    let encoded = serde_json::to_vec(&spec)?;
    let before = spec.allocation_bytes().ok_or("metadata size")?;
    let mut growth = grow(&mut spec.id) + grow(&mut spec.grant.principal);
    growth += grow(
        spec.grant
            .authorization_id
            .as_mut()
            .ok_or("authorization absent")?,
    );
    for values in [
        &mut spec.grant.selection.nodes,
        &mut spec.grant.selection.results,
    ] {
        let before = values.capacity();
        values.reserve(32);
        growth += (values.capacity() - before) * std::mem::size_of::<String>();
        for value in values {
            growth += grow(value);
        }
    }
    let (mut key, mut value) = spec
        .definition
        .definition
        .labels
        .pop_first()
        .ok_or("label absent")?;
    growth += grow(&mut key) + grow(&mut value);
    spec.definition.definition.labels.insert(key, value);
    growth += grow(&mut spec.definition.definition.name);
    growth += grow(&mut spec.definition.definition.description);
    growth += grow(&mut spec.definition.sql);
    let source = match &mut spec.definition.definition.program {
        Program::Sql { source } | Program::Prql { source } => source,
    };
    let Source::Inline { inline } = source else {
        return Err("captured source absent".into());
    };
    growth += grow(inline);
    let pins = spec.definition.images.capacity();
    spec.definition.images.reserve(32);
    growth += (spec.definition.images.capacity() - pins) * std::mem::size_of::<ImagePin>();
    let pin = spec
        .definition
        .images
        .first_mut()
        .ok_or("image pin absent")?;
    growth +=
        grow(&mut pin.image.package_id) + grow(&mut pin.image.revision) + grow(&mut pin.digest);
    growth += grow(&mut spec.manifest.planner) + grow(&mut spec.manifest.definition);
    let call = spec
        .manifest
        .calls
        .values_mut()
        .next()
        .ok_or("manifest call absent")?;
    growth += grow(&mut call.image.image.package_id)
        + grow(&mut call.image.image.revision)
        + grow(&mut call.image.digest);
    growth += grow(&mut call.package.package_id) + grow(&mut call.package.revision);
    growth += grow(&mut call.export) + grow(&mut call.target);
    let identity = call.artifact.as_mut().ok_or("artifact identity absent")?;
    growth += grow(&mut identity.digest);
    growth += grow(identity.closure_digest.as_mut().ok_or("closure absent")?);
    growth += grow(identity.platform.as_mut().ok_or("platform absent")?);
    let arguments = call.arguments.capacity();
    call.arguments.reserve(32);
    growth += (call.arguments.capacity() - arguments) * std::mem::size_of::<String>();
    for value in &mut call.arguments {
        growth += grow(value);
    }
    assert_eq!(serde_json::to_vec(&spec)?, encoded);
    assert_eq!(
        spec.allocation_bytes().ok_or("grown metadata size")?,
        before + growth
    );
    Ok(())
}
