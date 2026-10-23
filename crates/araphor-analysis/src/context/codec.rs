use araphor_analysis_builtins::{discovery as builtin, Rows};

use super::*;

impl Context {
    pub async fn context_input(
        &self,
        request: &DiscoveryContextRequestV1,
        control: &AnalysisReadControl,
    ) -> Result<sdk::Input> {
        self.select_context(request, control)
            .await
            .and_then(|view| Self::input(&view))
    }

    pub(super) fn input(view: &DiscoveryContextViewV1) -> Result<sdk::Input> {
        let row = builtin::ContextSelection {
            selector_version: view.selector_version,
            from_utc_ns: view.from_utc_ns,
            cutoff_utc_ns: view.cutoff_utc_ns,
            host_packet: Self::json(view)?,
        };
        let port = builtin::Discovery::port::<builtin::ContextSelection>("context");
        let data = Rows::encode(&port, &[row]).context(AnalysisContractSnafu)?;
        let (revision, coverage) = Self::metadata(view)?;
        Ok(sdk::Input {
            data,
            revision,
            coverage,
        })
    }

    pub fn decode_context(input: &sdk::Input) -> Result<DiscoveryContextViewV1> {
        let port = builtin::Discovery::port::<builtin::ContextSelection>("context");
        let mut rows: Vec<builtin::ContextSelection> =
            Rows::decode(&port, &input.data).context(AnalysisContractSnafu)?;
        Self::require(rows.len() == 1, "analysis context packet")?;
        let row = rows.remove(0);
        Self::require(row.selector_version == 1, "analysis context selector")?;
        let view: DiscoveryContextViewV1 = Self::decode(&row.host_packet)?;
        let (revision, coverage) = Self::metadata(&view)?;
        if input.revision != revision
            || input.coverage != coverage
            || row.selector_version != view.selector_version
            || row.from_utc_ns != view.from_utc_ns
            || row.cutoff_utc_ns != view.cutoff_utc_ns
        {
            return Err(DiscoveryConflictSnafu {
                kind: "analysis context revision",
            }
            .build()
            .into());
        }
        Ok(view)
    }

    fn metadata(
        view: &DiscoveryContextViewV1,
    ) -> araphor_data::Result<(sdk::Revision, sdk::Coverage)> {
        let mut limits = view
            .omissions
            .keys()
            .chain(&view.missing_facts)
            .cloned()
            .collect::<Vec<_>>();
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
                id: InputRevision::of(view).context(DiscoveryEncodingSnafu)?,
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
