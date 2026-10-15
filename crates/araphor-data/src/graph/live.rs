use super::*;
use crate::{EvidenceIntakeIdentityV1, GraphInvalidSnafu, ProcessorScopeV1};

impl GraphAndFindingOwner {
    pub fn process(&self, now: u64) -> Result<usize> {
        if now == 0 {
            return GraphInvalidSnafu { field: "clock" }.fail();
        }
        let mut operation = self.operation.lock().map_err(|_| {
            GraphInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        let (after, installed) = &mut *operation;
        let mut sources = Vec::new();
        if let Some(source) = after.as_ref() {
            sources.extend(self.store.source_page(source.tenant_id, Some(source))?);
        }
        for tenant in self
            .store
            .tenant_page(after.as_ref().map(|source| source.tenant_id))?
        {
            sources.extend(self.store.source_page(tenant, None)?);
            if sources.len() >= crate::analysis::MAX_ANALYSIS_PAGE_RECORDS {
                break;
            }
        }
        sources.truncate(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS);
        *after = sources.last().cloned();
        let mut count = 0;
        let mut failure = None;
        for source in sources {
            let result = self
                .process_source(&source, now, installed)
                .and_then(|processed| {
                    self.store.graph_set_health(&source, false)?;
                    Ok(processed)
                });
            match result {
                Ok(processed) => count += processed,
                Err(error) => {
                    let _health = self.store.graph_set_health(&source, true);
                    failure.get_or_insert(error);
                }
            }
        }
        failure.map_or(Ok(count), Err)
    }

    fn process_source(
        &self,
        source: &EvidenceIntakeIdentityV1,
        now: u64,
        installed: &mut Option<crate::InstalledAnalysis>,
    ) -> Result<usize> {
        self.store.register_graph(source)?;
        let scope = Self::scope(source);
        let health = self.store.processor_health(&scope)?.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "required processor",
            }
            .build()
        })?;
        let consumed = health.consumed_cursor.max(health.resume_floor);
        let failed = health.state == crate::ProcessorStateV1::ProcessingFailed;
        let mut changed = if failed {
            self.refresh_source(source, now, true, installed)?
        } else {
            false
        };
        if consumed < health.accepted_cursor {
            let step = GRAPH_WINDOW_RECORDS / 2;
            let next = consumed / step * step;
            let first = next.saturating_sub(step) + 1;
            let last = next
                .checked_add(step)
                .ok_or_else(|| {
                    GraphInvalidSnafu {
                        field: "window cursor",
                    }
                    .build()
                })?
                .min(health.accepted_cursor);
            changed |=
                self.commit_window(source, first, last, consumed, true, now, false, installed)?;
        } else if !failed {
            changed |= self.refresh_source(source, now, false, installed)?;
        }
        Ok(usize::from(changed))
    }

    pub fn refresh(&self, source: &EvidenceIntakeIdentityV1, now: u64) -> Result<bool> {
        if now == 0 || !source.valid() {
            return GraphInvalidSnafu {
                field: "refresh source",
            }
            .fail();
        }
        let mut operation = self.operation.lock().map_err(|_| {
            GraphInvalidSnafu {
                field: "worker lock",
            }
            .build()
        })?;
        let result = self.refresh_source(source, now, true, &mut operation.1);
        if result.is_err() {
            let _health = self.store.graph_set_health(source, true);
        }
        let changed = result?;
        self.store.graph_set_health(source, false)?;
        Ok(changed)
    }

    fn refresh_source(
        &self,
        source: &EvidenceIntakeIdentityV1,
        now: u64,
        force: bool,
        installed: &mut Option<crate::InstalledAnalysis>,
    ) -> Result<bool> {
        let health = self
            .store
            .processor_health(&Self::scope(source))?
            .ok_or_else(|| {
                GraphInvalidSnafu {
                    field: "required processor",
                }
                .build()
            })?;
        let consumed = health.consumed_cursor.max(health.resume_floor);
        let status = self.store.source_status(source)?.ok_or_else(|| {
            GraphInvalidSnafu {
                field: "source status",
            }
            .build()
        })?;
        let mut after = None;
        let mut changed = false;
        loop {
            let page = self.store.graph_window_headers(source, after)?;
            if page.is_empty() {
                break;
            }
            after = page.last().map(|row| row.1.first_cursor);
            for (id, header, revision) in page {
                if !force
                    && header.witness_deadline_utc_ns > now
                    && header.first_cursor > status.receipt.retained_floor
                    && self.store.graph_notice(&header.scope, &id, revision)?
                        == Some((
                            self.provider.revision(source)?,
                            status.receipt.coverage_revision,
                        ))
                    && self.installed_current(&id, &header, installed)?
                {
                    continue;
                }
                changed |= self.commit_window(
                    source,
                    header.first_cursor,
                    header.last_cursor,
                    consumed,
                    false,
                    now,
                    force,
                    installed,
                )?;
            }
        }
        Ok(changed)
    }

    pub(super) fn scope(source: &EvidenceIntakeIdentityV1) -> ProcessorScopeV1 {
        ProcessorScopeV1 {
            processor_id: GRAPH_PROCESSOR.into(),
            method_version: u64::from(GRAPH_SCHEMA_VERSION),
            identity: source.clone(),
        }
    }
}
