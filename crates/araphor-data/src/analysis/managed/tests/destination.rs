use super::*;

#[test]
fn managed_destination_selection() -> TestResult {
    let source = crate::analysis::tests::identity();
    let destinations = [
        ManagedDestination::DiscoveryProfile {
            source: source.clone(),
            call: 10,
            output: "profile".into(),
        },
        ManagedDestination::Graph {
            source: source.clone(),
            events_sql: "SELECT * FROM events".into(),
            calls: BTreeSet::from([10]),
            operation: ManagedGraphOperation::Evaluate,
        },
    ];
    let mut grant = AnalysisSelectionV1::tenant(source.tenant_id);
    grant.select_targets(true, true)?;
    grant.select_profiles(crate::Selection::Exact(vec!["retained-profile".into()]))?;
    grant.select_graphs(crate::Selection::Exact(vec!["retained-graph".into()]), None)?;
    grant.select_notifications(crate::Selection::All)?;
    grant.nodes = vec![source.node_id.clone()];
    grant.binding_ids = vec![[7; 16]];
    grant.results = vec!["retained-result".into()];
    grant.received_from = std::ops::Bound::Included(11);
    grant.received_until = std::ops::Bound::Excluded(13);
    grant.cursor_from = std::ops::Bound::Included(21);
    grant.cursor_until = std::ops::Bound::Included(22);
    assert_eq!(ManagedDestination::Selected.selection(&grant)?, grant);
    for destination in destinations {
        let mut expected = grant.clone();
        expected.sources = crate::Selection::Exact(vec![source.clone()]);
        assert_eq!(destination.selection(&grant)?, expected);
        let mut exact = grant.clone();
        let mut other = source.clone();
        other.source_id = [9; 16];
        exact.sources = crate::Selection::Exact(vec![other.clone(), source.clone()]);
        let original = exact.clone();
        assert_eq!(destination.selection(&exact)?, expected);
        assert_eq!(exact, original);
        exact.sources = crate::Selection::Exact(vec![other]);
        assert!(destination.selection(&exact).is_err());
        exact.sources = crate::Selection::Exact(Vec::new());
        assert!(destination.selection(&exact).is_err());
        let mut foreign = grant.clone();
        foreign.tenant_id = [9; 16];
        assert!(destination.selection(&foreign).is_err());
    }
    let invalid = ManagedDestination::DiscoveryProfile {
        source: crate::EvidenceIntakeIdentityV1 {
            source_id: [0; 16],
            ..source
        },
        call: 10,
        output: "profile".into(),
    };
    assert!(invalid.selection(&grant).is_err());
    Ok(())
}
