use std::path::Path;

use super::*;
use crate::analysis::AnalysisStore;

impl GraphCallRows {
    pub(in crate::analysis) fn validate(reader: &Connection, root: &Path) -> Result<()> {
        let invalid: bool = reader
            .query_row(
                "SELECT EXISTS (
                SELECT 1 FROM graph_call_scopes s
                LEFT JOIN managed_instances i ON i.tenant_id = s.tenant_id
                    AND i.instance_id = s.instance_id
                WHERE i.instance_id IS NULL OR octet_length(s.tenant_id) <> 16
                    OR s.instance_id = '' OR s.package_id = '' OR s.package_revision = ''
                    OR s.image_digest = '' OR s.created_revision = 0
                    OR NOT EXISTS (SELECT 1 FROM graph_call_versions v
                        WHERE v.scope_id = s.scope_id
                            AND v.commit_revision = s.created_revision)
                UNION ALL
                SELECT 1 FROM graph_call_versions v
                LEFT JOIN graph_call_scopes s USING (scope_id)
                LEFT JOIN analysis_results r ON r.result_id = v.result_id
                LEFT JOIN analysis_results base ON base.result_id = v.base_result_id
                WHERE s.scope_id IS NULL OR r.result_id IS NULL
                    OR r.tenant_id <> s.tenant_id
                    OR r.processor_id <> 'managed-package-v1'
                    OR v.commit_revision <> r.commit_revision
                    OR v.commit_revision < s.created_revision
                    OR (v.base_result_id IS NOT NULL AND
                        (base.result_id IS NULL OR base.tenant_id <> s.tenant_id
                            OR base.processor_id <> 'managed-package-v1'
                            OR base.commit_revision >= v.commit_revision))
                    OR v.commit_revision > COALESCE((SELECT last_changed_revision
                        FROM relation_revisions WHERE relation_name = 'graph_call_versions'), 0)
            )",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "validate Graph call scopes",
            })?;
        if invalid {
            return AnalysisStore::reject_path(root, "a Graph call scope or version is invalid");
        }
        for (table, key, value) in [
            ("graph_call_subjects", "subject_id", "graph_subject_values"),
            ("graph_call_edges", "edge_id", "graph_edge_values"),
            ("graph_call_findings", "value_id", "graph_finding_values"),
            ("graph_call_progress", "evidence_id", "graph_evidence"),
        ] {
            let anchor = if table == "graph_call_progress" {
                "m.evidence_id"
            } else {
                "m.anchor_record_id"
            };
            let invalid: bool = reader
                .query_row(
                    &format!(
                        "SELECT EXISTS (SELECT 1 FROM {table} m
                    LEFT JOIN graph_call_scopes s USING (scope_id)
                    LEFT JOIN {value} v ON v.{key} = m.{key}
                    LEFT JOIN graph_evidence anchor ON anchor.evidence_id = {anchor}
                    LEFT JOIN graph_call_versions opened ON opened.scope_id = m.scope_id
                        AND opened.commit_revision = m.valid_from
                    LEFT JOIN graph_call_versions closed ON closed.scope_id = m.scope_id
                        AND closed.commit_revision = m.valid_to
                    WHERE s.scope_id IS NULL OR v.{key} IS NULL
                        OR anchor.evidence_id IS NULL OR opened.result_id IS NULL
                        OR (m.valid_to IS NOT NULL AND closed.result_id IS NULL)
                        OR (m.valid_to IS NOT NULL AND m.valid_to <= m.valid_from))"
                    ),
                    [],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "validate Graph call membership",
                })?;
            if invalid {
                return AnalysisStore::reject_path(
                    root,
                    "a Graph call row has an invalid reference",
                );
            }
            let overlap: bool = reader
                .query_row(
                    &format!(
                        "SELECT EXISTS (SELECT 1 FROM (
                    SELECT m.scope_id, m.{key}, m.valid_from,
                        lag(m.valid_from) OVER (PARTITION BY m.scope_id, m.{key}
                            ORDER BY m.valid_from) AS prior_from,
                        lag(m.valid_to) OVER (PARTITION BY m.scope_id, m.{key}
                            ORDER BY m.valid_from) AS prior_to
                    FROM {table} m
                ) ranges WHERE prior_from IS NOT NULL
                    AND (prior_to IS NULL OR prior_to > valid_from))"
                    ),
                    [],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "validate Graph call intervals",
                })?;
            if overlap {
                return AnalysisStore::reject_path(root, "Graph call row intervals overlap");
            }
        }
        Ok(())
    }
}
