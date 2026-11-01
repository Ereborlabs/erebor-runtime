use super::*;

impl AnalysisStore {
    pub(super) fn retired_source(
        &self,
        reader: &Connection,
        receipt: &AnalysisSourceReceiptV1,
        through: u64,
        physical: u64,
        control: &AnalysisReadControl,
        output: &mut AnalysisExtractionV1,
    ) -> Result<Vec<AnalysisGapV1>> {
        if through >= physical {
            return Ok(Vec::new());
        }
        let catalog: String = reader
            .query_row("SELECT current_database()", [], |row| row.get(0))
            .context(AnalysisDatabaseSnafu {
                operation: "read source history catalog",
            })?;
        let base = format!("\"{}\".main", catalog.replace('"', "\"\""));
        let mut statement = reader
            .prepare(&format!(
                "SELECT first_cursor, last_cursor, source_revision, received_utc_ns, commit_revision
                 FROM {base}.expired_ranges WHERE stream_key = ? AND tenant_id = ?
                    AND source_revision <= ? AND commit_revision > ? ORDER BY first_cursor"
            ))
            .context(AnalysisDatabaseSnafu {
                operation: "prepare retired source headers",
            })?;
        let mut rows = statement
            .query(params![
                receipt.identity.key(),
                receipt.identity.tenant_id.as_slice(),
                through,
                through
            ])
            .context(AnalysisDatabaseSnafu {
                operation: "read retired source headers",
            })?;
        let mut spans = Vec::new();
        let mut allocated = 0usize;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance retired source headers",
        })? {
            control.check()?;
            output.scan(size_of::<[u64; 5]>())?;
            let span = AnalysisGapV1 {
                first_cursor: row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "read retired source start",
                })?,
                last_cursor: row.get(1).context(AnalysisDatabaseSnafu {
                    operation: "read retired source end",
                })?,
                commit_revision: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "read retired source acceptance",
                })?,
            };
            let intake: u64 = row.get(3).context(AnalysisDatabaseSnafu {
                operation: "read retired source intake",
            })?;
            let retired: u64 = row.get(4).context(AnalysisDatabaseSnafu {
                operation: "read retired source revision",
            })?;
            if span.first_cursor == 0
                || span.last_cursor < span.first_cursor
                || span.commit_revision == 0
                || span.commit_revision > through
                || intake == 0
                || retired <= through
                || retired <= span.commit_revision
            {
                return self.reject("the retired source header is invalid");
            }
            allocated += AnalysisExtractionV1::grow(
                &mut spans,
                output.input_bytes.saturating_add(allocated),
                output.limits.input_bytes,
            )?;
            spans.push(span);
        }
        Ok(spans)
    }

    pub(super) fn check_selected_source(
        &self,
        receipt: &AnalysisSourceReceiptV1,
        covered: u64,
    ) -> Result<()> {
        if covered != receipt.contiguous_cursor {
            return self.reject("the selected source has an unrecorded input gap");
        }
        Ok(())
    }
}
