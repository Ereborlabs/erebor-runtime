use serde::{Deserialize, Serialize};

use super::*;

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct CoverageReportRef {
    pub source: EvidenceIntakeIdentityV1,
    pub revision: u64,
    pub position: StorePositionV1,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageRecord {
    pub reference: CoverageReportRef,
    pub encoded_report: Vec<u8>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CoverageChanges {
    pub meta: AnalysisStoreMetaV1,
    pub reports: Vec<CoverageRecord>,
}

impl CoverageReportRef {
    fn valid(&self) -> bool {
        self.source.valid()
            && self.revision != 0
            && self.position.commit_revision != 0
            && self.position.ordinal == 0
    }
}

impl AnalysisStore {
    const COVERAGE_CHANGES_SQL: &'static str =
        "SELECT stream_key, tenant_id, revision, commit_revision, ordinal
         FROM coverage WHERE commit_revision > ? ORDER BY commit_revision";
    const COVERAGE_REPORT_SQL: &'static str =
        "SELECT stream_key, tenant_id, revision, commit_revision, ordinal, report
         FROM coverage WHERE commit_revision = ?";

    pub fn coverage_changes(
        &self,
        selection: &AnalysisSelectionV1,
        after: StorePositionV1,
        control: &AnalysisReadControl,
    ) -> Result<CoverageChanges> {
        if !selection.valid() || after.ordinal != u32::MAX {
            return self.reject("the coverage change scope or input position is invalid");
        }
        let (coordinator, mut reader) = self.coordinated_reader(control)?;
        control.run(&mut reader, |snapshot| {
            let meta = Self::read_meta_from(snapshot, &self.root.join("analysis.duckdb"))?;
            drop(coordinator);
            #[cfg(test)]
            control.test_snapshot()?;
            if after.commit_revision > meta.commit_revision {
                return self.reject("the coverage read starts beyond its captured revision");
            }
            let reports = self.coverage_changes_from(
                snapshot,
                selection,
                after.commit_revision,
                meta.commit_revision,
                control,
            )?;
            Ok(CoverageChanges { meta, reports })
        })
    }

    pub fn coverage_report(
        &self,
        selection: &AnalysisSelectionV1,
        reference: &CoverageReportRef,
        control: &AnalysisReadControl,
    ) -> Result<CoverageRecord> {
        if !selection.valid() || !reference.valid() {
            return self.reject("the coverage report scope or reference is invalid");
        }
        if !selection.includes_source(&reference.source) {
            return Err(crate::PackageErrorCodeV1::Denied.error("coverage report scope"));
        }
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |snapshot| {
            let meta = Self::read_meta_from(snapshot, &self.root.join("analysis.duckdb"))?;
            if reference.position.commit_revision > meta.commit_revision {
                return self.reject("the coverage reference exceeds its captured revision");
            }
            self.coverage_report_from(snapshot, reference)
        })
    }

    pub(in crate::analysis) fn coverage_changes_from(
        &self,
        snapshot: &Connection,
        selection: &AnalysisSelectionV1,
        after: u64,
        through: u64,
        control: &AnalysisReadControl,
    ) -> Result<Vec<CoverageRecord>> {
        if selection.sources.is_empty() {
            return Ok(Vec::new());
        }
        let mut statement = snapshot
            .prepare_cached(Self::COVERAGE_CHANGES_SQL)
            .context(AnalysisDatabaseSnafu {
                operation: "prepare coverage change headers",
            })?;
        let mut rows = statement
            .query(params![after])
            .context(AnalysisDatabaseSnafu {
                operation: "read coverage change headers",
            })?;
        let mut reports = Vec::new();
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance coverage change headers",
        })? {
            control.check()?;
            let tenant: Vec<u8> = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "decode coverage change tenant",
            })?;
            if tenant != selection.tenant_id {
                continue;
            }
            let key: Vec<u8> = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode coverage change source",
            })?;
            let source = self
                .raw
                .until(control)?
                .sources
                .get(&key)
                .and_then(|source| source.receipt.evidence())
                .map(|receipt| receipt.identity.clone())
                .ok_or_else(|| self.state_error("the coverage source identity is absent"))?;
            if source.key() != key || source.tenant_id != selection.tenant_id {
                return self.reject("the coverage source differs from its indexed identity");
            }
            if !selection.includes_source(&source) {
                continue;
            }
            let reference = CoverageReportRef {
                source,
                revision: row.get(2).context(AnalysisDatabaseSnafu {
                    operation: "decode coverage change revision",
                })?,
                position: StorePositionV1 {
                    commit_revision: row.get(3).context(AnalysisDatabaseSnafu {
                        operation: "decode coverage change commit",
                    })?,
                    ordinal: row.get(4).context(AnalysisDatabaseSnafu {
                        operation: "decode coverage change ordinal",
                    })?,
                },
            };
            if !reference.valid()
                || reference.position.commit_revision <= after
                || reference.position.commit_revision > through
            {
                return self.reject("the coverage change exceeds its captured interval");
            }
            control.check()?;
            reports.push(self.coverage_report_from(snapshot, &reference)?);
            #[cfg(any(test, feature = "test-fixtures"))]
            control.test_read_step()?;
        }
        Ok(reports)
    }

    fn coverage_report_from(
        &self,
        snapshot: &Connection,
        reference: &CoverageReportRef,
    ) -> Result<CoverageRecord> {
        let mut statement =
            snapshot
                .prepare_cached(Self::COVERAGE_REPORT_SQL)
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare exact coverage report",
                })?;
        let stored = statement
            .query_row(params![reference.position.commit_revision], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, Vec<u8>>(1)?,
                    row.get::<_, u64>(2)?,
                    row.get::<_, u64>(3)?,
                    row.get::<_, u32>(4)?,
                    row.get::<_, Vec<u8>>(5)?,
                ))
            })
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read exact coverage report",
            })?
            .ok_or_else(|| self.state_error("the referenced coverage report is absent"))?;
        if stored.0 != reference.source.key()
            || stored.1 != reference.source.tenant_id
            || stored.2 != reference.revision
            || stored.3 != reference.position.commit_revision
            || stored.4 != reference.position.ordinal
            || stored.5.is_empty()
        {
            return self.reject("the stored coverage report differs from its reference");
        }
        Ok(CoverageRecord {
            reference: reference.clone(),
            encoded_report: stored.5,
        })
    }
}

#[cfg(test)]
mod tests;
