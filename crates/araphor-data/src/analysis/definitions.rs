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
        let revision = definition.digest()?;
        let bytes = serde_json::to_vec(definition).context(crate::PackageEncodingSnafu)?;
        let mut writer = self.writer()?;
        let transaction = writer
            .get_mut()?
            .transaction()
            .context(AnalysisDatabaseSnafu {
                operation: "begin definition admission",
            })?;
        Self::definition_images(&transaction, tenant, definition, true)?;
        let existing: Option<(Vec<u8>, u64)> = transaction
            .query_row(
                "SELECT definition, commit_revision FROM discovery_definitions
             WHERE tenant_id = ? AND name = ? AND revision = ?",
                params![tenant.as_slice(), definition.definition.name, revision],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .context(AnalysisDatabaseSnafu {
                operation: "read definition admission",
            })?;
        if let Some((saved, committed)) = existing {
            if saved != bytes {
                return crate::AnalysisConflictSnafu.fail();
            }
            check()?;
            return Ok(committed);
        }
        let committed = self.package_next(&transaction)?;
        transaction
            .execute(
                "INSERT INTO discovery_definitions VALUES (?, ?, ?, ?, ?)",
                params![
                    tenant.as_slice(),
                    definition.definition.name,
                    revision,
                    bytes,
                    committed
                ],
            )
            .context(AnalysisDatabaseSnafu {
                operation: "insert definition",
            })?;
        self.check_logical(&transaction, tenant, false)?;
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
        revision: Option<&str>,
        control: &AnalysisReadControl,
    ) -> Result<Option<ResolvedDefinition>> {
        let mut reader = self.reader_until(control)?;
        control.run(&mut reader, |reader| {
            let saved: Option<(String, Vec<u8>)> = reader
                .query_row(
                    "SELECT revision, definition FROM discovery_definitions
                 WHERE tenant_id = ? AND name = ? AND (? OR revision = ?)
                 ORDER BY commit_revision DESC, revision DESC LIMIT 1",
                    params![
                        tenant.as_slice(),
                        name,
                        revision.is_none(),
                        revision.unwrap_or_default()
                    ],
                    |row| Ok((row.get(0)?, row.get(1)?)),
                )
                .optional()
                .context(AnalysisDatabaseSnafu {
                    operation: "inspect definition",
                })?;
            saved
                .map(|(revision, bytes)| {
                    let definition: ResolvedDefinition =
                        serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
                    definition.validate()?;
                    if definition.definition.name != name || definition.digest()? != revision {
                        return Err(Code::Invalid.error("retained definition identity"));
                    }
                    Self::definition_images(reader, tenant, &definition, false)?;
                    Ok(definition)
                })
                .transpose()
        })
    }

    fn definition_images(
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
        let mut statement = reader.prepare(
            "SELECT tenant_id, name, revision, definition, commit_revision FROM discovery_definitions",
        ).context(AnalysisDatabaseSnafu { operation: "prepare saved definitions" })?;
        let rows = statement
            .query_map([], |row| {
                Ok((
                    row.get::<_, Vec<u8>>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Vec<u8>>(3)?,
                    row.get::<_, u64>(4)?,
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
            let (tenant, name, revision, bytes, committed) =
                row.context(AnalysisDatabaseSnafu {
                    operation: "decode saved definition",
                })?;
            let tenant: [u8; 16] = tenant
                .try_into()
                .map_err(|_| Code::Invalid.error("definition tenant"))?;
            let definition: ResolvedDefinition =
                serde_json::from_slice(&bytes).context(crate::PackageEncodingSnafu)?;
            definition.validate()?;
            if tenant == [0; 16]
                || committed == 0
                || committed > head
                || definition.definition.name != name
                || definition.digest()? != revision
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
