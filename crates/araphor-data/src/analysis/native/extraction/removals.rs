use super::*;
use crate::analysis::native::retention::ExpiredSegment;
use crate::analysis::{extraction::changes::RemovedRange, raw::RawIdentity};
use snafu::ResultExt as _;

impl DataView {
    pub(super) fn raw_removals(
        &self,
        selection: &AnalysisSelectionV1,
        traces: &[crate::analysis::extraction::SelectedTrace<'_>],
        mode: AnalysisReadModeV1,
        output: &mut AnalysisExtractionV1,
        control: &AnalysisReadControl,
    ) -> Result<Vec<RemovedRange>> {
        let mut removals = Vec::new();
        let AnalysisReadModeV1::Changes(after) = mode else {
            return Ok(removals);
        };
        for (&id, expired) in self.raw.expired.iter() {
            control.check()?;
            let revision = expired.revision;
            if revision <= after.commit_revision || revision > self.metadata_revision {
                continue;
            }
            let selected = match &expired.identity {
                RawIdentity::Evidence(identity) => selection.sources.as_slice().contains(identity),
                RawIdentity::Diagnostic(identity) => traces
                    .iter()
                    .any(|trace| trace.selected && trace.identity == identity),
            };
            if !selected {
                continue;
            }
            let saved = output.input_bytes;
            let capacity = removals.capacity();
            let mut names = 0;
            let record = ExpiredSegment::read_charged(&self.snapshot, id, &mut |bytes| {
                output.charge(bytes)
            })?;
            for entry in record.entries {
                let selected = match &entry.identity {
                    RawIdentity::Evidence(identity) => {
                        selection.sources.as_slice().contains(identity)
                            && selection.time_range().is_some_and(|(from, until)| {
                                from <= entry.commit.intake && entry.commit.intake <= until
                            })
                    }
                    RawIdentity::Diagnostic(identity) => traces
                        .iter()
                        .any(|trace| trace.selected && trace.identity == identity),
                };
                if !selected {
                    continue;
                }
                for span in entry.commit.spans {
                    control.check()?;
                    let (first, last) = if entry.identity.evidence().is_some() {
                        let Some((first, last)) = selection.cursor_range() else {
                            continue;
                        };
                        (span.first.max(first), span.last.min(last))
                    } else {
                        (span.first, span.last)
                    };
                    if first > last {
                        continue;
                    }
                    output.charge(AnalysisExtractionV1::grow(
                        &mut removals,
                        output.input_bytes,
                        output.limits.input_bytes,
                    )?)?;
                    let bytes = match &entry.identity {
                        RawIdentity::Evidence(identity) => identity.node_id.len(),
                        RawIdentity::Diagnostic(identity) => identity.node_id.len(),
                    };
                    output.charge(bytes)?;
                    names += bytes;
                    removals.push(RemovedRange {
                        identity: entry.identity.clone(),
                        first,
                        last,
                        revision,
                    });
                }
            }
            output.input_bytes =
                saved + (removals.capacity() - capacity) * size_of::<RemovedRange>() + names;
        }
        let events = super::super::events::Events::new(self);
        for source in selection.sources.as_slice() {
            for row in events.spans(source, 0, u64::MAX)? {
                control.check()?;
                let (key, value) = row.context(crate::NativeStorageSnafu {
                    operation: "read removed evidence spans",
                })?;
                let (start, index) =
                    super::super::events::Events::decode_span(source, &key, &value)?;
                let Some(expiry) = events.expiry(index.revision)? else {
                    continue;
                };
                if expiry.revision <= after.commit_revision {
                    continue;
                }
                let batch = events.batch(index.revision)?;
                batch.check_span(source, start, &index)?;
                if !selection.time_range().is_some_and(|(from, until)| {
                    from <= batch.meta.intake && batch.meta.intake <= until
                }) {
                    continue;
                }
                let Some((first, last)) = selection.cursor_range() else {
                    continue;
                };
                let span = &batch.meta.spans[index.slot];
                let (first, last) = (span.first.max(first), span.last.min(last));
                if first > last {
                    continue;
                }
                output.charge(AnalysisExtractionV1::grow(
                    &mut removals,
                    output.input_bytes,
                    output.limits.input_bytes,
                )?)?;
                output.charge(source.node_id.len())?;
                removals.push(RemovedRange {
                    identity: source.clone().into(),
                    first,
                    last,
                    revision: expiry.revision,
                });
            }
        }
        removals.sort_by(|left, right| {
            (left.revision, &left.identity, left.first).cmp(&(
                right.revision,
                &right.identity,
                right.first,
            ))
        });
        Ok(removals)
    }
}
