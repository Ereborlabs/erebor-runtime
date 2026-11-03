use super::*;
use araphor_data::AnalysisSelectionV1;
#[test]
fn scopes_have_one_program() -> crate::Result<()> {
    let source = EvidenceIntakeIdentityV1 {
        tenant_id: [1; 16],
        node_id: "node-a".into(),
        node_boot_id: [2; 16],
        label_epoch: 1,
        source_id: [3; 16],
        source_epoch: 1,
    };
    let all = AnalysisSelectionV1::tenant(source.tenant_id);
    let exact = AnalysisSelectionV1::new(source.tenant_id, vec![source.clone()]);
    let mut first_node = all.clone();
    first_node.nodes = vec![source.node_id.clone()];
    let mut other_node = all.clone();
    other_node.nodes = vec!["node-b".into()];
    let mut excluded = exact.clone();
    excluded.nodes = other_node.nodes.clone();
    let other = AnalysisSelectionV1::new(
        source.tenant_id,
        vec![EvidenceIntakeIdentityV1 {
            source_epoch: 2,
            ..source
        }],
    );
    for (left, right, expected) in [
        (all.clone(), all.clone(), true),
        (all.clone(), exact.clone(), true),
        (first_node.clone(), exact.clone(), true),
        (first_node.clone(), other_node, false),
        (first_node, excluded, false),
        (exact, other, false),
        (
            all.clone(),
            AnalysisSelectionV1::new(all.tenant_id, Vec::new()),
            false,
        ),
        (all, AnalysisSelectionV1::tenant([4; 16]), false),
    ] {
        assert!(left.valid());
        assert!(right.valid());
        assert_eq!(GraphProgram::selections_overlap(&left, &right), expected);
        assert_eq!(GraphProgram::selections_overlap(&right, &left), expected);
    }
    Ok(())
}
