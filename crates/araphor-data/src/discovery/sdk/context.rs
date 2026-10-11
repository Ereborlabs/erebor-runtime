use araphor_analysis_builtins::{discovery as builtin, Rows};
use araphor_analysis_sdk as sdk;
use snafu::ResultExt as _;

use super::Adapter;
use crate::*;

impl DiscoveryOwner {
    pub fn context_input(
        request: &DiscoveryContextRequestV1,
        revisions: &[DiscoveryContextRevisionV1],
    ) -> Result<sdk::Input> {
        let view = Self::select_context(request, revisions)?;
        let selection = builtin::ContextSelection {
            selector_version: view.selector_version,
            from_utc_ns: view.from_utc_ns,
            cutoff_utc_ns: view.cutoff_utc_ns,
            host_packet: Adapter::json(&view)?,
        };
        let data = Rows::encode(
            &builtin::Discovery::port::<builtin::ContextSelection>("context"),
            &[selection],
            Adapter::context_limits(),
        )
        .context(AnalysisContractSnafu)?;
        let (revision, coverage) = Adapter::context_metadata(&view)?;
        Ok(sdk::Input {
            data,
            revision,
            coverage,
        })
    }
}

impl TryFrom<&sdk::Input> for DiscoveryContextViewV1 {
    type Error = Error;

    fn try_from(input: &sdk::Input) -> Result<Self> {
        let mut rows: Vec<builtin::ContextSelection> = Rows::decode(
            &builtin::Discovery::port::<builtin::ContextSelection>("context"),
            &input.data,
            Adapter::context_limits(),
        )
        .context(AnalysisContractSnafu)?;
        crate::discovery::model::require(rows.len() == 1, "analysis context packet")?;
        let row = rows.remove(0);
        crate::discovery::model::require(row.selector_version == 1, "analysis context selector")?;
        crate::discovery::model::require(
            row.host_packet.len() <= CONTEXT_PACKET_BYTES,
            "analysis context bytes",
        )?;
        let view: Self = Adapter::decode(&row.host_packet)?;
        let (revision, coverage) = Adapter::context_metadata(&view)?;
        crate::discovery::model::same(
            input.revision == revision
                && input.coverage == coverage
                && row.selector_version == view.selector_version
                && row.from_utc_ns == view.from_utc_ns
                && row.cutoff_utc_ns == view.cutoff_utc_ns,
            "analysis context revision",
        )?;
        Ok(view)
    }
}

impl Adapter {
    fn context_limits() -> sdk::Limits {
        sdk::Limits {
            max_batches: 1,
            max_rows: 1,
            max_bytes: 4 * 1024 * 1024,
            max_checkpoint_bytes: 1,
        }
    }

    fn context_metadata(view: &DiscoveryContextViewV1) -> Result<(sdk::Revision, sdk::Coverage)> {
        let mut limits: Vec<_> = view
            .omissions
            .keys()
            .chain(&view.missing_facts)
            .cloned()
            .collect();
        limits.sort();
        limits.dedup();
        let time = |value| {
            i64::try_from(value).map_err(|_| {
                DiscoveryInvalidSnafu {
                    field: "analysis context time",
                }
                .build()
            })
        };
        Ok((
            sdk::Revision {
                owner: "discovery-context-v1".into(),
                id: Self::revision(view)?,
                window: Some(sdk::SourceWindow {
                    source: Self::json(&view.access.subject)?.into_bytes(),
                    start_utc_ns: time(view.from_utc_ns)?,
                    end_utc_ns: time(view.cutoff_utc_ns)?,
                }),
            },
            sdk::Coverage {
                state: if limits.is_empty() {
                    sdk::CoverageState::Complete
                } else {
                    sdk::CoverageState::Gapped
                },
                limits,
            },
        ))
    }
}
