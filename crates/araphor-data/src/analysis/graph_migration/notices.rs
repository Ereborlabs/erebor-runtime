use super::*;

impl AnalysisStore {
    pub(in crate::analysis) fn migrate_graph_notices(
        writer: &mut Connection,
        root: &Path,
    ) -> Result<()> {
        Self::validate_tables(writer)?;
        Self::validate_state(writer, root)?;
        let transaction = writer.transaction().context(AnalysisDatabaseSnafu {
            operation: "begin graph notice migration",
        })?;
        let mut after = String::new();
        while let Some((id, tenant, _)) = Self::next_graph(&transaction, &after, false)? {
            let tenant = tenant.try_into().map_err(|_| {
                crate::GraphInvalidSnafu {
                    field: "graph notice tenant",
                }
                .build()
            })?;
            let header = GraphRows::read_header(&transaction, tenant, &id)?.ok_or_else(|| {
                crate::GraphInvalidSnafu {
                    field: "graph notice header",
                }
                .build()
            })?;
            let changed = transaction
                .execute(
                    "UPDATE analysis_results SET facts_revision = ?
                    WHERE result_id = ? AND tenant_id = ? AND processor_id = ?
                        AND stream_key = ? AND method_version = ? AND first_cursor = ?",
                    params![
                        header.snapshot.context_notice_revision,
                        id,
                        tenant.as_slice(),
                        crate::GRAPH_PROCESSOR,
                        header.snapshot.scope.identity.key().as_slice(),
                        header.snapshot.scope.method_version,
                        header.snapshot.first_cursor
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "convert graph fact notice",
                })?;
            if changed != 1 {
                return crate::AnalysisConflictSnafu.fail();
            }
            after = id;
        }
        let changed = transaction
            .execute(
                "UPDATE store_meta SET schema_version = ? WHERE schema_version = ?",
                params![
                    ANALYSIS_SCHEMA_VERSION,
                    super::super::GRAPH_NOTICE_LEGACY_VERSION
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "set graph notice schema version",
            })?;
        if changed != 1 {
            return crate::AnalysisConflictSnafu.fail();
        }
        Self::validate_state(&transaction, root)?;
        transaction.commit().context(AnalysisDatabaseSnafu {
            operation: "commit graph notice migration",
        })
    }
}
