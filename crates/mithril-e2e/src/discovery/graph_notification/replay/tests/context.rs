use super::super::*;

#[test]
fn recorded_context_stays_external() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let cards = ReplayQualification::incident_cards()?;
    assert_eq!(cards.len(), 12);
    for (index, card) in cards.into_iter().enumerate() {
        assert_eq!(card.id, format!("HF-{:03}", index + 1));
        let source = fixture.card_input(&card, u8::try_from(index + 40)?)?;
        for _ in 0..32 {
            fixture.graph.process(fixture.now)?;
            if fixture.graph.snapshot(&source)?.is_some() {
                break;
            }
        }
        let snapshot = fixture
            .graph
            .snapshot(&source)?
            .ok_or("card graph absent")?;
        let native = snapshot
            .findings
            .iter()
            .find(|finding| {
                finding
                    .effects
                    .iter()
                    .any(|effect| effect.evidence.durable_cursor == 1)
            })
            .ok_or("native finding absent")?;
        assert_eq!(native.state, FindingStateV1::Confirmed);
        assert_eq!(
            native.effects[0].physical_result,
            GraphPhysicalResultV1::Prevented
        );
        assert!(snapshot
            .findings
            .iter()
            .filter(|finding| finding.subject_id.kind != GraphSubjectKindV1::External)
            .all(|finding| !finding.evidence.iter().any(|id| id.durable_cursor == 2)));
        for (action, classification) in &card.contexts {
            let context = snapshot
                .findings
                .iter()
                .find(|finding| finding.subject_id.identity == action.as_bytes())
                .ok_or("context finding absent")?;
            assert!(context.effects.is_empty());
            assert!(context.policy_provenance.is_empty());
            if *classification == GraphContextActionV1::OutsideAuthority {
                assert!(snapshot.graph.branches.iter().any(|branch| {
                    branch.seed == context.subject_id
                        && branch.state == GraphBranchStateV1::OutsideAuthority
                }));
            }
        }
        let input = GraphNotificationQualification::replay(&fixture.data, &source, &snapshot)?;
        let mut reordered = input.clone();
        reordered.records.reverse();
        reordered.records.extend(input.records.clone());
        reordered.facts.reverse();
        reordered.facts.extend(input.facts.clone());
        let replay = GraphAndFindingOwner::derive(&reordered, &fixture.execution)?;
        assert_eq!(replay.graph, snapshot.graph);
        assert_eq!(replay.findings, snapshot.findings);
        assert_eq!(
            serde_json::to_vec(&replay.findings)?,
            serde_json::to_vec(&snapshot.findings)?
        );
        let mut foreign = input.clone();
        foreign.source.tenant_id = [99; 16];
        assert!(GraphAndFindingOwner::derive(&foreign, &fixture.execution).is_err());
        let mut conflict = input.clone();
        let mut changed = conflict.records[0].clone();
        changed.original_kernel_sequence = Some(999);
        conflict.records.push(changed);
        assert!(GraphAndFindingOwner::derive(&conflict, &fixture.execution).is_err());
        let mut gap = input;
        gap.coverage[0].state = DiscoveryCoverageStateV1::Gapped;
        gap.coverage[0].gap_reasons = vec!["RING_LOSS".into()];
        gap.coverage_keys[0].state = DiscoveryCoverageStateV1::Gapped;
        gap.coverage_keys[0].gap_reasons = vec!["RING_LOSS".into()];
        let gapped = GraphAndFindingOwner::derive(&gap, &fixture.execution)?;
        assert!(gapped
            .findings
            .iter()
            .filter(|finding| !finding.effects.is_empty())
            .all(|finding| finding.state == FindingStateV1::CoverageInsufficient));
        gap.records.reverse();
        gap.facts.reverse();
        assert_eq!(
            gapped.findings,
            GraphAndFindingOwner::derive(&gap, &fixture.execution)?.findings
        );
    }
    Ok(())
}

#[test]
fn device_denial_stays_native() -> crate::platform::TestResult<()> {
    let fixture = ReplayQualification::new(1_791_400_000_000_000_000)?;
    let mut device = GraphNotificationQualification::native(1, true);
    device.effect_family = KernelEffectFamilyV1::Device as u16;
    device.operation = KernelEffectOperationV1::OpenRead as u16;
    let source = fixture.accept(90, &[device])?;
    assert_eq!(fixture.graph.process(fixture.now)?, 1);
    let snapshot = fixture
        .graph
        .snapshot(&source)?
        .ok_or("device graph absent")?;
    assert_eq!(
        snapshot.findings[0].effects[0].physical_result,
        GraphPhysicalResultV1::Prevented
    );
    Ok(())
}
