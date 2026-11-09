use std::collections::BTreeSet;

use super::DataView;
use crate::analysis::{context::VerifiedPackages, extraction::tables::Capture};
use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisExtractionV1, AnalysisReadControl,
    AnalysisReadModeV1, AnalysisReferenceOriginV1, AnalysisSelectionV1, AnalysisTableRead,
    NativeStateSnafu, Result,
};

pub(super) struct ContextRead<'a> {
    view: &'a DataView,
    output: &'a mut AnalysisExtractionV1,
    control: &'a AnalysisReadControl,
    verified: VerifiedPackages,
}

impl<'a> ContextRead<'a> {
    pub(super) fn new(
        view: &'a DataView,
        output: &'a mut AnalysisExtractionV1,
        control: &'a AnalysisReadControl,
    ) -> Self {
        Self {
            view,
            output,
            control,
            verified: VerifiedPackages::default(),
        }
    }

    pub(super) fn capture(
        &mut self,
        selection: &AnalysisSelectionV1,
        read: &AnalysisTableRead<'_>,
        owners: Option<&BTreeSet<String>>,
        capture: &mut Capture<'_>,
    ) -> Result<()> {
        let after = match read.mode {
            AnalysisReadModeV1::Changes(after) => Some(after.commit_revision),
            _ => None,
        };
        if after.is_some() && read.projected("context_versions").is_none() {
            return Ok(());
        }
        if after.is_some() || selection.contexts.is_all() {
            let headers =
                self.view
                    .context_headers(selection, owners, after, self.output, self.control)?;
            let slots = headers.capacity() * std::mem::size_of::<AnalysisContextRefV1>();
            for header in headers {
                let bytes = header.key.allocated_bytes();
                self.context(&header.key, Some(&header), capture, after.is_some())?;
                drop(header);
                self.output.input_bytes -= bytes;
            }
            self.output.input_bytes -= slots;
        } else {
            for key in selection.contexts.as_slice() {
                if owners.is_some_and(|owners| !owners.contains(&key.owner_id))
                    || selection.targets_only && key.owner_id != "mithril-control/target"
                {
                    continue;
                }
                self.context(key, None, capture, false)?;
            }
        }
        Ok(())
    }

    fn context(
        &mut self,
        key: &AnalysisContextKeyV1,
        expected: Option<&AnalysisContextRefV1>,
        capture: &mut Capture<'_>,
        changes: bool,
    ) -> Result<()> {
        self.control.check()?;
        let mut transient = 0usize;
        let value = self.view.context_charged(key, &mut |bytes| {
            self.output.charge(bytes)?;
            transient = transient.saturating_add(bytes);
            Ok(())
        })?;
        if let Some((context, revision)) = value {
            if expected.is_some_and(|expected| expected.commit_revision != revision) {
                return NativeStateSnafu {
                    field: "context header revision",
                }
                .fail();
            }
            self.verified
                .check_context(&context, |tenant, package, revision| {
                    self.view
                        .package_revision(tenant, package, revision, self.control)
                })
                .map_err(crate::Error::stored_artifact)?;
            if changes {
                self.output.scan(context.body.len())?;
            }
            self.output.reference_context(
                &context.key,
                revision,
                AnalysisReferenceOriginV1::Context,
            )?;
            capture.context(&context, revision, &mut self.output.sink(self.control))?;
            drop(context);
            self.output.input_bytes -= transient;
        } else if expected.is_some() {
            return NativeStateSnafu {
                field: "context header value",
            }
            .fail();
        } else {
            let added = AnalysisExtractionV1::grow(
                &mut self.output.missing_contexts,
                self.output.input_bytes,
                self.output.limits.input_bytes,
            )?;
            self.output.charge(added)?;
            self.output.charge(key.allocated_bytes())?;
            self.output.missing_contexts.push(key.clone());
        }
        Ok(())
    }
}
