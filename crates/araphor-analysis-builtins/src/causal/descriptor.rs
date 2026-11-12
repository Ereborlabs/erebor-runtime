use std::sync::OnceLock;

use araphor_analysis_types::DomainRelations;

use super::{io::*, model::Audit, sdk, state::Edits, Causal};

impl Causal {
    pub const ID: &'static str = "HF-CAUSAL-001";
    pub const REVISION: &'static str = "1";

    pub fn descriptor() -> sdk::Package {
        Self::declaration().clone()
    }

    pub(super) fn declaration() -> &'static sdk::Package {
        static PACKAGE: OnceLock<sdk::Package> = OnceLock::new();
        PACKAGE.get_or_init(|| {
            sdk::Package::new(
                Self::ID,
                Self::REVISION,
                vec![Self::index_model(), Self::detect_model()],
            )
        })
    }

    fn index_model() -> sdk::Model {
        let mut model = sdk::Model::new(
            "index",
            vec![
                ContextRow::port("audit_after"),
                ContextRow::port("audit_before"),
                ContextKey::port("audit_affected"),
                CoverageRow::port("coverage_after"),
                CoverageRow::port("coverage_before"),
                CoverageKey::port("coverage_affected"),
                sdk::ChangeInputs::reset_port("reset"),
            ],
            vec![FrontierRow::port(), Control::port()],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.graph = Some(sdk::GraphSpec {
            access: sdk::GraphAccess::ReadWrite,
            relations: Edits::relations(),
        });
        model.change_inputs = Some(sdk::ChangeInputs {
            reset: "reset".into(),
            ports: vec![
                sdk::ChangeInput {
                    affected: "audit_affected".into(),
                    before: "audit_before".into(),
                    after: "audit_after".into(),
                    current: Some(Self::audit_query("after.", true)),
                },
                sdk::ChangeInput {
                    affected: "coverage_affected".into(),
                    before: "coverage_before".into(),
                    after: "coverage_after".into(),
                    current: Some(Self::coverage_query("after.")),
                },
            ],
        });
        let queries = [
            Self::audit_query("", false), Self::audit_query("before.", true),
            "SELECT key FROM inserted.audit_after UNION SELECT key FROM removed.audit_after".into(),
            Self::coverage_query(""), Self::coverage_query("before."),
            "SELECT source, cpu_id FROM inserted.coverage_after UNION SELECT source, cpu_id FROM removed.coverage_after".into(),
        ];
        for (input, sql) in model.inputs.iter_mut().zip(queries) {
            input.source = sdk::InputSource::Query(sql);
        }
        model
    }

    fn detect_model() -> sdk::Model {
        let mut model = sdk::Model::new(
            "detect",
            vec![
                FrontierRow::port(),
                Control::port(),
                araphor_analysis_types::values::Observation::port(),
                ContextRow::port("audits"),
            ],
            vec![Summary::port()],
        );
        model.input_mode = sdk::InputMode::Resolved;
        model.graph = Some(sdk::GraphSpec {
            access: sdk::GraphAccess::ReadWrite,
            relations: vec![sdk::GraphRelation {
                name: DomainRelations::FINDINGS.into(),
                kind: sdk::GraphKind::Node,
                properties: araphor_analysis_types::FindingMember::port().schema,
            }],
        });
        for input in &mut model.inputs[..2] {
            input.source = sdk::InputSource::Table(sdk::TableRef::Output(sdk::OutputRef {
                package: Self::ID.into(),
                revision: Self::REVISION.into(),
                export: "index".into(),
                output: input.port.name.clone(),
            }));
        }
        model.inputs[2].source = sdk::InputSource::Query(include_str!("records.sql").into());
        model.inputs[3].source = sdk::InputSource::Query(format!(
            "SELECT context.key, context.commit_revision, context.sensitivity, context.body
             FROM ({}) context JOIN frontier ON context.key = frontier.context
                AND context.commit_revision = frontier.commit_revision",
            Self::audit_query("after.", false)
        ));
        model.reasons = vec![sdk::Reason {
            code: format!("{}.CROSS_NODE_PRIVILEGED_WORKLOAD", Self::ID),
            details: super::detect::Details::port().schema,
        }];
        model
    }

    fn source_expr(alias: &str) -> String {
        format!(
            "named_struct('tenant_id', {alias}.tenant_id, 'node_id', {alias}.node_id,
            'node_boot_id', {alias}.node_boot_id, 'label_epoch', {alias}.label_epoch,
            'source_id', {alias}.source_id, 'source_epoch', {alias}.source_epoch)"
        )
    }

    fn audit_query(image: &str, scoped: bool) -> String {
        format!(
            "SELECT source.* FROM (
            SELECT named_struct('tenant_id', context.tenant_id, 'owner_id', context.owner_id,
                'entity_key', context.entity_key, 'lifetime_key', context.lifetime_key,
                'owner_revision', context.owner_revision) AS key,
                context.commit_revision, context.sensitivity, context.body
            FROM {image}context_versions context WHERE context.owner_id = '{}'
            ) source {}",
            Audit::OWNER,
            if scoped {
                "JOIN audit_affected affected ON source.key = affected.key"
            } else {
                ""
            }
        )
    }

    fn coverage_query(image: &str) -> String {
        format!(
            "SELECT {} AS source, receipt.cpu_id, receipt.coverage_revision, receipt.retained_floor,
                receipt.kind, receipt.first_cursor, receipt.last_cursor
            FROM {image}coverage receipt WHERE receipt.kind IN ('receipt','expired','recovery','pending')",
            Self::source_expr("receipt")
        )
    }
}
