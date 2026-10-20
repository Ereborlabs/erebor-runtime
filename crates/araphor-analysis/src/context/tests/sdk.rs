use super::*;

#[tokio::test]
async fn context_sdk_packet() -> TestResult<()> {
    let (request, revision) = input()?;
    let expected = select(&request, std::slice::from_ref(&revision)).await?;
    let input = context_input(&request, std::slice::from_ref(&revision)).await?;
    assert_eq!(Context::decode_context(&input)?, expected);
    assert_eq!(input.revision.owner, "discovery-context-v1");
    assert_eq!(input.revision.id.len(), 64);
    let window = input.revision.window.as_ref().ok_or("window absent")?;
    assert_eq!(window.start_utc_ns as u64, request.from_utc_ns);
    assert_eq!(window.end_utc_ns as u64, request.cutoff_utc_ns);
    let mut reordered = request;
    reordered.records.reverse();
    reordered.owner_facts.reverse();
    assert_eq!(
        context_input(&reordered, &[revision]).await?.revision,
        input.revision
    );
    Ok(())
}

#[tokio::test]
async fn context_sdk_metadata() -> TestResult<()> {
    let (request, revision) = input()?;
    let input = context_input(&request, &[revision]).await?;
    let mut altered = input.clone();
    altered.revision.id.push('a');
    assert!(Context::decode_context(&altered).is_err());
    altered = input.clone();
    altered
        .revision
        .window
        .as_mut()
        .ok_or("window absent")?
        .end_utc_ns += 1;
    assert!(Context::decode_context(&altered).is_err());
    altered = input;
    altered.coverage.limits.push("UNDECLARED_LIMIT".into());
    assert!(Context::decode_context(&altered).is_err());
    Ok(())
}

#[tokio::test]
async fn context_sdk_version() -> TestResult<()> {
    use araphor_analysis_builtins::{discovery as builtin, Rows};

    let (request, revision) = input()?;
    let mut input = context_input(&request, &[revision]).await?;
    let mut view = Context::decode_context(&input)?;
    view.selector_version = 2;
    input.revision.id = araphor_data::InputRevision::of(&view)?;
    input.data = Rows::encode(
        &builtin::Discovery::port::<builtin::ContextSelection>("context"),
        &[builtin::ContextSelection {
            selector_version: 2,
            from_utc_ns: view.from_utc_ns,
            cutoff_utc_ns: view.cutoff_utc_ns,
            host_packet: serde_json::to_string(&view)?,
        }],
        builtin::Discovery::limits(),
    )?;
    assert!(Context::decode_context(&input).is_err());
    Ok(())
}
