use super::super::*;

#[test]
fn local_inputs_preserve_proof() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    for (offset, name) in [
        "activation-missing",
        "activation-exact",
        "entry-rule-missing",
        "initial-health-missing",
    ]
    .into_iter()
    .enumerate()
    {
        let mut denied = GraphNotificationQualification::native(1, true);
        if name == "entry-rule-missing" {
            denied.admitted_entry_rule_id = 0;
        }
        let source = fixture.accept_node(
            u8::try_from(91 + offset)?,
            &[denied],
            &fixture.authenticated,
            name != "initial-health-missing",
        )?;
        if name == "activation-exact" {
            fixture.policy(&fixture.record(&source, 1)?)?;
        }
        for _ in 0..32 {
            fixture.graph.process(fixture.now)?;
            if fixture.graph.snapshot(&source)?.is_some() {
                break;
            }
        }
        let snapshot = fixture
            .graph
            .snapshot(&source)?
            .ok_or("local graph absent")?;
        let finding = snapshot.findings.first().ok_or("local finding absent")?;
        let expected = if matches!(name, "entry-rule-missing" | "initial-health-missing") {
            FindingStateV1::CoverageInsufficient
        } else {
            FindingStateV1::Confirmed
        };
        assert_eq!(finding.state, expected, "{name}");
    }
    Ok(())
}
