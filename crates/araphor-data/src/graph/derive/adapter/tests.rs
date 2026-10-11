use super::*;

type TestResult<T = ()> = std::result::Result<T, Box<dyn std::error::Error>>;

fn input() -> Result<GraphReplayInputV1> {
    let mut input = crate::graph::tests::credential_input()?;
    input.facts.sort_by(|left, right| left.key.cmp(&right.key));
    Ok(input)
}

fn computation(
    input: &GraphReplayInputV1,
) -> TestResult<(GraphDerivation<'_>, sdk::Evaluation, sdk::Output)> {
    let owner = GraphDerivation::new(input)?;
    let evaluation = owner.evaluation()?;
    let output = algorithm::Detector::Credentials.evaluate(&evaluation)?;
    Ok((owner, evaluation, output))
}

#[test]
fn candidate_reason_matches_contract() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    output.datasets.reverse();
    output.reasons.reverse();
    output.evidence.reverse();
    let package = GraphAndFindingOwner::analysis_package("HF-DW-001")?;
    package.validate_output(&evaluation, &output)?;
    assert!(!output.reasons.is_empty());
    for reason in &output.reasons {
        let declared = package.exports[0]
            .reasons
            .iter()
            .find(|declared| declared.code == reason.code)
            .ok_or("declared reason")?;
        assert_eq!(reason.details.schema().as_ref(), &declared.details);
    }
    owner.apply_output(algorithm::Detector::Credentials, &evaluation, &output)?;
    let expected = GraphAndFindingOwner::derive(&input)?;
    let findings: Vec<_> = expected
        .findings
        .iter()
        .filter(|finding| finding.package_id == "HF-DW-001")
        .collect();
    assert_eq!(owner.findings.values().collect::<Vec<_>>(), findings);
    Ok(())
}

#[test]
fn candidate_requires_host_validation() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let port = &package.exports[0].outputs[0];
    let mut subjects: Vec<algorithm::Subject> =
        Rows::decode(port, &output.datasets[0], evaluation.context.limits)?;
    subjects.first_mut().ok_or("subject candidate")?.record = u64::from(u32::MAX) + 1;
    output.datasets[0] = Rows::encode(port, &subjects, evaluation.context.limits)?;
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(algorithm::Detector::Credentials, &evaluation, &output),
        Err(crate::Error::GraphInvalid {
            field: "graph output record",
            ..
        })
    ));
    Ok(())
}

#[test]
fn candidate_reason_is_exact() -> TestResult {
    let input = input()?;
    let (_, evaluation, output) = computation(&input)?;
    let package = algorithm::Detector::Credentials.descriptor();
    let port = &package.exports[0].outputs[2];
    let mut missing = output.clone();
    missing.reasons.clear();
    let mut wrong_code = output.clone();
    let reason = wrong_code.reasons.first_mut().ok_or("candidate reason")?;
    reason.code = if reason.code.ends_with(".CONTRADICTION") {
        "HF-DW-001.MISSING_AUTHORITY_PROOF"
    } else {
        "HF-DW-001.CONTRADICTION"
    }
    .into();
    let mut wrong_detail = output.clone();
    let reason = wrong_detail.reasons.first_mut().ok_or("candidate reason")?;
    let mut details: Vec<algorithm::Finding> = Rows::decode(
        port,
        &sdk::Dataset {
            name: port.name.clone(),
            batches: vec![reason.details.clone()],
        },
        evaluation.context.limits,
    )?;
    let finding = details.first_mut().ok_or("candidate detail")?;
    finding.confirmed = !finding.confirmed;
    reason.details = Rows::encode(port, &details, evaluation.context.limits)?
        .batches
        .remove(0);
    for altered in [missing, wrong_code, wrong_detail] {
        package.validate_output(&evaluation, &altered)?;
        let mut owner = GraphDerivation::new(&input)?;
        assert!(matches!(
            owner.apply_output(algorithm::Detector::Credentials, &evaluation, &altered),
            Err(crate::Error::GraphInvalid {
                field: "graph candidate reason",
                ..
            })
        ));
    }
    Ok(())
}

#[test]
fn candidate_evidence_is_exact() -> TestResult {
    let input = input()?;
    let (mut owner, evaluation, mut output) = computation(&input)?;
    output.evidence.pop().ok_or("candidate evidence")?;
    let package = algorithm::Detector::Credentials.descriptor();
    package.validate_output(&evaluation, &output)?;
    assert!(matches!(
        owner.apply_output(algorithm::Detector::Credentials, &evaluation, &output),
        Err(crate::Error::GraphInvalid {
            field: "graph candidate evidence",
            ..
        })
    ));
    Ok(())
}
