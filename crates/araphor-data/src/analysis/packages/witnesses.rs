use duckdb::{params, Connection, OptionalExt as _, Transaction};
use snafu::ResultExt as _;

use crate::{
    AnalysisContextKeyV1, AnalysisContextRefV1, AnalysisDatabaseSnafu, AnalysisStore,
    AnalysisWitnessV1, JsonSnafu, Result,
};

use super::PackageResultRefV1;

type PackageEvidence = (Vec<AnalysisWitnessV1>, Vec<AnalysisContextRefV1>);

impl AnalysisStore {
    pub fn package_contexts(
        &self,
        tenant: [u8; 16],
        keys: &[AnalysisContextKeyV1],
    ) -> Result<Vec<AnalysisContextRefV1>> {
        if keys.len() > 256
            || keys
                .iter()
                .any(|key| key.tenant_id != tenant || !key.valid())
        {
            return self.reject("the package context keys are invalid");
        }
        if keys.is_empty() {
            return Ok(Vec::new());
        }
        self.read_snapshot(|reader| {
            keys.iter()
                .map(|key| {
                    let (_, commit_revision) = Self::read_context_from(reader, &self.root, key)?
                        .ok_or_else(|| self.state_error("the package context is absent"))?;
                    Ok(AnalysisContextRefV1 {
                        key: key.clone(),
                        commit_revision,
                    })
                })
                .collect()
        })
    }

    pub fn package_result_refs(
        &self,
        tenant: [u8; 16],
        ids: &[String],
    ) -> Result<Vec<PackageResultRefV1>> {
        if ids.len() > 64 {
            return self.reject("the package result references exceed their limit");
        }
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        self.read_snapshot(|reader| {
            ids.iter()
                .map(|id| {
                    let revision = self.package_source_revision(reader, tenant, id)?;
                    Ok(PackageResultRefV1 {
                        result_id: id.clone(),
                        commit_revision: revision,
                    })
                })
                .collect()
        })
    }

    pub(in crate::analysis) fn package_source_revision(
        &self,
        reader: &Connection,
        tenant: [u8; 16],
        id: &str,
    ) -> Result<u64> {
        let (revision, body) = reader.query_row("SELECT commit_revision,
            CASE WHEN processor_id = 'discovery' THEN body ELSE NULL END FROM analysis_results WHERE tenant_id = ? AND result_id = ?",
            params![tenant.as_slice(), id], |row| Ok((row.get::<_, u64>(0)?, row.get::<_, Option<Vec<u8>>>(1)?)),
        ).optional().context(AnalysisDatabaseSnafu { operation: "resolve package result reference" })?
            .ok_or_else(|| self.state_error("the package result reference is absent"))?;
        if let Some(body) = body {
            if !crate::DiscoveryProfileV1::try_from(body.as_slice())?.sealed {
                return Err(crate::PackageErrorCodeV1::Unsupported.error("mutable discovery input"));
            }
        }
        Ok(revision)
    }

    pub fn package_evidence(&self, tenant: [u8; 16], ids: &[String]) -> Result<PackageEvidence> {
        if ids.len() > 64 {
            return self.reject("the package evidence sources exceed their limit");
        }
        if ids.is_empty() {
            return Ok((Vec::new(), Vec::new()));
        }
        let encoded = serde_json::to_string(ids).context(JsonSnafu {
            path: "<package-evidence>",
        })?;
        self.read_snapshot(|reader| {
            let bytes: u64 = reader
                .query_row(
                    "SELECT COALESCE(SUM(octet_length(CASE WHEN x.processor_id = 'analysis-package'
                    THEN p.commit_meta ELSE x.request_meta END)), 0)::UBIGINT
                 FROM analysis_results x LEFT JOIN package_results p USING (result_id)
                 WHERE x.tenant_id = ? AND x.result_id IN (SELECT unnest(CAST(? AS VARCHAR[])))",
                    params![tenant.as_slice(), encoded],
                    |row| row.get(0),
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "bound package evidence manifests",
                })?;
            if bytes > Self::RESULT_READ_BYTES {
                return self.reject("the package evidence manifests exceed their byte limit");
            }
            let mut statement = reader
                .prepare(
                    "SELECT x.processor_id, CASE WHEN x.processor_id = 'analysis-package'
                    THEN p.commit_meta ELSE x.request_meta END
                 FROM analysis_results x LEFT JOIN package_results p USING (result_id)
                 WHERE x.tenant_id = ? AND x.result_id IN (SELECT unnest(CAST(? AS VARCHAR[])))",
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare package evidence manifests",
                })?;
            let rows = statement
                .query_map(params![tenant.as_slice(), encoded], |row| {
                    Ok((row.get::<_, String>(0)?, row.get::<_, Vec<u8>>(1)?))
                })
                .context(AnalysisDatabaseSnafu {
                    operation: "read package evidence manifests",
                })?;
            let mut witnesses = std::collections::BTreeMap::new();
            let mut contexts = Vec::new();
            for row in rows {
                let (processor, metadata) = row.context(AnalysisDatabaseSnafu {
                    operation: "decode package evidence manifest",
                })?;
                let (source_witnesses, source_contexts) =
                    Self::decode_evidence(&processor, &metadata)?;
                for witness in source_witnesses {
                    let prior = witnesses
                        .entry((witness.identity.clone(), witness.cursor))
                        .or_insert(witness.clone());
                    prior.expires_utc_ns = prior.expires_utc_ns.min(witness.expires_utc_ns);
                }
                contexts.extend(source_contexts);
                contexts.sort_by(|left, right| {
                    left.key
                        .cmp(&right.key)
                        .then(left.commit_revision.cmp(&right.commit_revision))
                });
                contexts.dedup();
                if witnesses.len() > 8192 || contexts.len() > 256 {
                    return self.reject("the package evidence references exceed their count limit");
                }
            }
            Ok((witnesses.into_values().collect(), contexts))
        })
    }

    pub(in crate::analysis) fn decode_evidence(
        processor: &str,
        metadata: &[u8],
    ) -> Result<PackageEvidence> {
        if processor == "analysis-package" {
            let contract: super::PackageCommitV1 =
                serde_json::from_slice(metadata).context(JsonSnafu {
                    path: "<package-evidence>",
                })?;
            Ok((contract.witnesses, contract.context_refs))
        } else {
            crate::AnalysisResultCommitV1::request_refs(metadata).context(JsonSnafu {
                path: "<native-evidence>",
            })
        }
    }

    pub(in crate::analysis) fn resolve_witnesses(
        &self,
        witnesses: &[AnalysisWitnessV1],
        revision: u64,
    ) -> Result<Vec<u64>> {
        let mut segments = Vec::with_capacity(witnesses.len());
        let mut cached = Vec::<crate::AnalysisRecordV1>::new();
        let mut source = None;
        let mut segment = 0;
        for witness in witnesses {
            if source != Some(&witness.identity)
                || cached
                    .first()
                    .is_none_or(|record| witness.cursor < record.cursor)
                || cached
                    .last()
                    .is_none_or(|record| witness.cursor > record.cursor)
            {
                let ranges = self
                    .raw
                    .lock()
                    .map_err(|_| self.state_error("the raw owner lock is poisoned"))?
                    .select_ranges(
                        &witness.identity,
                        witness.cursor,
                        witness.cursor,
                        revision,
                        None,
                        2,
                    )?;
                if ranges.len() != 1 {
                    return self.reject("the result witness is not retained exactly once");
                }
                cached = ranges[0].read(&self.root)?;
                segment = ranges[0].segment_id;
                source = Some(&witness.identity);
            }
            cached
                .binary_search_by_key(&witness.cursor, |record| record.cursor)
                .map_err(|_| self.state_error("the result witness is not retained"))?;
            segments.push(segment);
        }
        Ok(segments)
    }

    pub(in crate::analysis) fn insert_references(
        transaction: &Transaction<'_>,
        id: &str,
        witnesses: &[AnalysisWitnessV1],
        segments: &[u64],
        contexts: &[AnalysisContextRefV1],
    ) -> Result<i64> {
        let mut bytes = 0;
        for (witness, segment) in witnesses.iter().zip(segments) {
            transaction
                .execute(
                    "INSERT INTO evidence_refs VALUES (?, ?, ?, ?, ?, ?)",
                    params![
                        id,
                        witness.identity.tenant().as_slice(),
                        witness.identity.key().as_slice(),
                        witness.cursor,
                        witness.expires_utc_ns,
                        segment
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert exact witness",
                })?;
            bytes += 256 + witness.identity.key().len() as i64 + id.len() as i64;
        }
        for reference in contexts {
            transaction
                .execute(
                    "INSERT INTO context_refs VALUES (?, ?, ?, ?, ?, ?, ?)",
                    params![
                        id,
                        reference.key.tenant_id.as_slice(),
                        reference.key.owner_id,
                        reference.key.entity_key.as_slice(),
                        reference.key.lifetime_key.as_slice(),
                        reference.key.owner_revision,
                        reference.commit_revision
                    ],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "insert exact result context",
                })?;
            bytes += (256
                + id.len()
                + reference.key.owner_id.len()
                + reference.key.entity_key.len()
                + reference.key.lifetime_key.len()) as i64;
        }
        Ok(bytes)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_provenance_reads() -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = AnalysisStore::open(directory.path().join("analysis"))?;
        let mut held = Vec::new();
        while let Ok(permit) = store.reserve_reader() {
            held.push(permit);
        }
        assert!(!held.is_empty());
        assert!(store.package_contexts([1; 16], &[])?.is_empty());
        assert!(store.package_result_refs([1; 16], &[])?.is_empty());
        assert_eq!(
            store.package_evidence([1; 16], &[])?,
            (Vec::new(), Vec::new())
        );
        let excess = vec!["result".to_owned(); 65];
        assert!(store.package_result_refs([1; 16], &excess).is_err());
        assert!(store.package_evidence([1; 16], &excess).is_err());
        Ok(())
    }
}
