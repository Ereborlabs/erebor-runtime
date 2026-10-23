use super::*;
use araphor_data::AnalysisSelectionV1;
use araphor_discovery_definition::{Definition, Program, Source};

fn program(selection: AnalysisSelectionV1) -> crate::Result<GraphProgram> {
    let sql = "SELECT 1 AS value";
    Ok(GraphProgram {
        grant: PackageGrantV1 {
            principal: "Graph scope fixture".into(),
            revision: 1,
            selection,
            expires_utc_ns: None,
            authorization_id: None,
        },
        definition: ResolvedDefinition::new(
            Definition {
                name: "graph-scope-fixture".into(),
                description: String::new(),
                labels: Default::default(),
                program: Program::Sql {
                    source: Source::Inline { inline: sql.into() },
                },
            },
            sql.into(),
            Vec::new(),
        )
        .map_err(araphor_data::Error::from)?,
        events_sql: "SELECT * FROM events".into(),
    })
}

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
        let left = program(left)?;
        let right = program(right)?;
        assert_eq!(left.overlaps(&right), expected);
        assert_eq!(right.overlaps(&left), expected);
    }
    Ok(())
}
