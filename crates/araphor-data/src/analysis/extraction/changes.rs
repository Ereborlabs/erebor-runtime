use super::*;

#[cfg(test)]
mod tests;

pub(super) struct RemovedRange {
    pub(super) identity: RawIdentity,
    pub(super) first: u64,
    pub(super) last: u64,
    pub(super) revision: u64,
}

impl AnalysisStore {
    pub(super) fn raw_removals(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        traces: &[SelectedTrace<'_>],
        after: StorePositionV1,
        control: &AnalysisReadControl,
        output: &mut AnalysisExtractionV1,
    ) -> Result<Vec<RemovedRange>> {
        let mut removed = Vec::new();
        let mut statement = snapshot
            .prepare(
                "SELECT first_cursor, last_cursor, commit_revision FROM expired_ranges
                 WHERE stream_key = ? AND tenant_id = ?
                     AND commit_revision > ? AND commit_revision <= ?
                 ORDER BY commit_revision, first_cursor, last_cursor, segment_id",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare raw retirements",
            })?;
        let identities = selection
            .sources
            .as_slice()
            .iter()
            .cloned()
            .map(RawIdentity::Evidence)
            .chain(
                traces
                    .iter()
                    .filter(|trace| trace.selected)
                    .map(|trace| RawIdentity::Diagnostic(trace.identity.clone())),
            );
        for identity in identities {
            control.check()?;
            let key = identity.key();
            output.charge(key.capacity())?;
            let rows = statement
                .query_map(
                    params![
                        key.as_slice(),
                        selection.tenant_id.as_slice(),
                        after.commit_revision,
                        output.meta.commit_revision,
                    ],
                    |row| {
                        Ok((
                            row.get::<_, u64>(0)?,
                            row.get::<_, u64>(1)?,
                            row.get::<_, u64>(2)?,
                        ))
                    },
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "read raw retirements",
                })?;
            for row in rows {
                control.check()?;
                let (first, last, revision) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode raw retirement",
                })?;
                if first == 0
                    || last < first
                    || revision <= after.commit_revision
                    || revision > output.meta.commit_revision
                {
                    return self.reject("the raw retirement range or revision is invalid");
                }
                let added = AnalysisExtractionV1::grow(
                    &mut removed,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?;
                output.charge(added)?;
                let identity = identity.clone();
                output.charge(match &identity {
                    RawIdentity::Evidence(identity) => identity.node_id.capacity(),
                    RawIdentity::Diagnostic(identity) => identity.node_id.capacity(),
                })?;
                removed.push(RemovedRange {
                    identity,
                    first,
                    last,
                    revision,
                });
            }
        }
        removed.sort_unstable_by(|left, right| {
            (left.revision, &left.identity, left.first, left.last).cmp(&(
                right.revision,
                &right.identity,
                right.first,
                right.last,
            ))
        });
        Ok(removed)
    }
}

impl AnalysisExtractionV1 {
    pub(super) fn remove_raw(
        &mut self,
        capture: &mut super::tables::Capture<'_>,
        removed: &RemovedRange,
        control: &AnalysisReadControl,
    ) -> Result<()> {
        control.check()?;
        capture.remove(
            &removed.identity,
            AnalysisGapV1 {
                first_cursor: removed.first,
                last_cursor: removed.last,
                commit_revision: removed.revision,
            },
            &mut self.sink(control),
        )
    }
}
