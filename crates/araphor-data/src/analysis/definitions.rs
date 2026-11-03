use std::path::Path;

use araphor_discovery_definition::ResolvedDefinition;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, AnalysisStore, PackageErrorCodeV1 as Code, Result,
};

impl AnalysisStore {
    pub fn admit_definition(
        &self,
        tenant: [u8; 16],
        definition: &ResolvedDefinition,
        check: impl FnOnce() -> Result<()>,
    ) -> Result<u64> {
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("definition tenant"));
        }
        definition.validate()?;
        let bytes = definition.encode()?;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin definition admission",
            })?;
        Self::definition_images(&transaction, tenant, definition, true)?;
        if let Some(committed) = Self::definition_revision_from(
            &transaction,
            tenant,
            &definition.definition.name,
            &bytes,
        )? {
            check()?;
            return Ok(committed);
        }
        let committed = self.package_next(&transaction)?;
        transaction
            .execute(
                "INSERT INTO discovery_definitions VALUES (?, ?, ?, ?)",
                params![
                    tenant.as_slice(),
                    definition.definition.name,
                    bytes,
                    committed
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert definition",
            })?;
        self.check_revision_limits(&transaction, tenant)?;
        Self::record_revision(&transaction, committed, &["discovery_definitions"])?;
        check()?;
        self.commit_metadata(transaction, "commit definition admission")?;
        self.revision.send_replace(committed);
        Ok(committed)
    }

    pub fn definition(
        &self,
        tenant: [u8; 16],
        name: &str,
        revision: Option<u64>,
        control: &AnalysisReadControl,
    ) -> Result<Option<(ResolvedDefinition, u64)>> {
        if tenant == [0; 16] || revision == Some(0) {
            return Err(Code::Invalid.error("definition reference"));
        }
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let saved: Option<(Vec<u8>, u64, u64)> = reader
                .query_row(
                    "SELECT definition, commit_revision,
                        (SELECT commit_revision FROM store_meta) FROM discovery_definitions
                     WHERE tenant_id = ? AND name = ? AND (? OR commit_revision = ?)
                     ORDER BY commit_revision DESC LIMIT 1",
                    params![
                        tenant.as_slice(),
                        name,
                        revision.is_none(),
                        revision.unwrap_or_default()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "inspect definition",
                })?;
            saved
                .map(|(bytes, committed, head)| {
                    let definition = ResolvedDefinition::from_bytes(&bytes)?;
                    if definition.definition.name != name
                        || committed == 0
                        || committed > head
                        || definition.encode()? != bytes
                    {
                        return Err(Code::Invalid.error("retained definition identity"));
                    }
                    Self::definition_images(reader, tenant, &definition, false)?;
                    Ok((definition, committed))
                })
                .transpose()
        })
    }

    pub fn definition_revision(
        &self,
        tenant: [u8; 16],
        definition: &ResolvedDefinition,
        control: &AnalysisReadControl,
    ) -> Result<Option<u64>> {
        if tenant == [0; 16] {
            return Err(Code::Invalid.error("definition tenant"));
        }
        let bytes = definition.encode()?;
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let revision = Self::definition_revision_from(
                reader,
                tenant,
                &definition.definition.name,
                &bytes,
            )?;
            if revision.is_some() {
                Self::definition_images(reader, tenant, definition, false)?;
            }
            Ok(revision)
        })
    }

    fn definition_revision_from(
        reader: &Connection,
        tenant: [u8; 16],
        name: &str,
        bytes: &[u8],
    ) -> Result<Option<u64>> {
        let mut statement = reader
            .prepare(
                "WITH candidates AS MATERIALIZED (
                SELECT * FROM discovery_definitions WHERE definition = ?
             ) SELECT commit_revision, (SELECT commit_revision FROM store_meta)
             FROM candidates WHERE tenant_id = ? AND name = ?",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare definition value",
            })?;
        let mut rows = statement
            .query(params![bytes, tenant.as_slice(), name])
            .context(AnalysisDatabaseSnafu {
                operation: "read definition value",
            })?;
        let mut selected = None;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "read definition value row",
        })? {
            let revision: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode definition revision",
            })?;
            let head: u64 = row.get(1).context(AnalysisDatabaseSnafu {
                operation: "decode definition head",
            })?;
            if selected.replace(revision).is_some() || revision == 0 || revision > head {
                return Err(Code::Invalid.error("retained definition identity"));
            }
        }
        Ok(selected)
    }

    pub(in crate::analysis) fn definition_images(
        reader: &Connection,
        tenant: [u8; 16],
        definition: &ResolvedDefinition,
        installed: bool,
    ) -> Result<()> {
        for pin in &definition.images {
            let found: bool = reader
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM package_images
                 WHERE tenant_id = ? AND package_id = ? AND revision = ? AND digest = ? AND (NOT ? OR installed))",
                    params![
                        tenant.as_slice(),
                        pin.image.package_id,
                        pin.image.revision,
                        pin.digest,
                        installed,
                    ],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "check definition image",
                })?;
            if !found {
                return Err(Code::Missing.error("definition image"));
            }
        }
        Ok(())
    }

    pub(in crate::analysis) fn validate_definitions(
        reader: &Connection,
        root: &Path,
    ) -> Result<()> {
        let mut statement = reader
            .prepare(
                "SELECT tenant_id, name, definition, commit_revision FROM discovery_definitions",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare saved definitions",
            })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, Vec<u8>>(2)?,
                    row.get::<_, u64>(3)?,
                ))
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read saved definitions",
            })?;
        let head: u64 = reader
            .query_row("SELECT commit_revision FROM store_meta", [], |row| {
                row.get(0)
            })
            .context(AnalysisDatabaseSnafu {
                operation: "read definition store revision",
            })?;
        for row in rows {
            let (tenant, name, bytes, committed) = row.context(AnalysisDatabaseSnafu {
                operation: "decode saved definition",
            })?;
            let tenant: [u8; 16] = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("definition tenant"))?;
            let definition = ResolvedDefinition::from_bytes(&bytes)?;
            if tenant == [0; 16]
                || committed == 0
                || committed > head
                || definition.definition.name != name
                || definition.encode()? != bytes
            {
                return Self::reject_path(root, "the saved definition is invalid");
            }
            Self::definition_images(reader, tenant, &definition, false)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests;
