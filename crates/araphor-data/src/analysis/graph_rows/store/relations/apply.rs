use crate::analysis::graph_rows::store::{
    error::DatabaseSnafu, native::NativeRows, GraphHeader, GraphManifest, GraphPackageStateV1,
    Relations, Result,
};
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;
use std::collections::{BTreeMap, BTreeSet};

pub struct ProducerChanges {
    pub diff: Option<super::Changes>,
    pub cuts: Vec<(String, u64, u64)>,
    pub previous: Option<GraphHeader>,
    pub metadata_scope: u64,
    pub metadata_base: Option<String>,
    pub metadata_members: Vec<crate::analysis::graph_rows::store::Replacement>,
    pub metadata_reset: bool,
    pub metadata_changed: bool,
    pub metadata_removed: BTreeSet<(u8, Vec<u8>, u64)>,
    pub restricted: u64,
    pub captured: u64,
    pub full_check: bool,
    pub touched: BTreeSet<(u8, Vec<u8>)>,
    pub states: BTreeMap<(String, u64), GraphPackageStateV1>,
    pub work: (u64, u64, u64),
    pub root_cursors: BTreeMap<u64, (u64, u64)>,
}

pub struct VersionPin<'a> {
    pub package: &'a str,
    pub revision: &'a str,
    pub image: &'a str,
}

impl ProducerChanges {
    pub fn resolve_metadata(&self, metadata: &mut GraphManifest) -> Result<()> {
        for ((id, version), state) in &self.states {
            let mut matches = metadata
                .packages
                .iter_mut()
                .filter(|package| &package.package_id == id && package.package_version == *version);
            let package = matches
                .next()
                .ok_or_else(|| NativeRows::invalid("graph unit package metadata"))?;
            if matches.next().is_some() {
                return Err(NativeRows::invalid("graph unit package metadata"));
            }
            package.state = state.clone();
        }
        Ok(())
    }
}

impl Relations<'_> {
    pub fn bind_result(writer: &Connection, graph: &str, producer: &str) -> Result<()> {
        writer
            .execute(
                "INSERT INTO graph_result_producers VALUES(?,?)",
                params![graph, producer],
            )
            .context(DatabaseSnafu {
                operation: "bind Graph producer result",
            })?;
        Ok(())
    }

    pub fn version(
        writer: &Connection,
        result: &str,
        scope: u64,
        revision: u64,
        base: Option<&str>,
    ) -> Result<()> {
        Self::producer_version(writer, result, scope, revision, base, None)
    }

    pub fn producer_version(
        writer: &Connection,
        result: &str,
        scope: u64,
        revision: u64,
        base: Option<&str>,
        pin: Option<VersionPin<'_>>,
    ) -> Result<()> {
        let latest: Option<(String,u64)> = writer
            .query_row(
                "SELECT result_id,commit_revision FROM graph_producer_versions WHERE scope_id=? ORDER BY commit_revision DESC LIMIT 1",
                params![scope],
                |row| Ok((row.get(0)?,row.get(1)?)),
            )
            .optional()
            .context(DatabaseSnafu {
                operation: "read Graph producer frontier",
            })?;
        if let Some((id, cut)) = latest {
            if base != Some(id.as_str()) || cut >= revision {
                return Err(NativeRows::invalid("graph producer stale base"));
            }
        } else {
            let created: u64 = writer
                .query_row(
                    "SELECT created_revision FROM graph_producer_scopes WHERE scope_id=?",
                    params![scope],
                    |row| row.get(0),
                )
                .context(DatabaseSnafu {
                    operation: "check new Graph producer scope",
                })?;
            if base.is_some() || created != revision {
                return Err(NativeRows::invalid("graph producer fresh base"));
            }
        }
        writer
            .execute(
                "INSERT INTO graph_producer_versions
                    (result_id,scope_id,commit_revision,base_result_id,subject_count,edge_count,
                        finding_count,state_count,selected_state_ref,package_id,package_revision,image_digest)
                 VALUES(?,?,?,?,0,0,0,0,NULL,?,?,?)",
                params![result, scope, revision, base,
                    pin.as_ref().map(|pin| pin.package), pin.as_ref().map(|pin| pin.revision),
                    pin.as_ref().map(|pin| pin.image)],
            )
            .context(DatabaseSnafu {
                operation: "insert Graph producer version",
            })?;
        Ok(())
    }

    pub fn unchanged(
        &self,
        prior: &str,
        metadata: &GraphManifest,
        changes: &mut ProducerChanges,
    ) -> Result<bool> {
        let Some(previous) = changes.previous.as_ref() else {
            return Ok(false);
        };
        if metadata.previous_result_id.as_deref() != Some(prior) {
            return Err(NativeRows::invalid("graph unchanged base"));
        }
        let previous = &previous.snapshot;
        if changes.metadata_changed
            || metadata.schema_version != previous.schema_version
            || metadata.scope != previous.scope
            || metadata.first_cursor != previous.first_cursor
            || metadata.last_cursor != previous.last_cursor
            || metadata.input_manifest.coverage != previous.input_manifest.coverage
            || metadata.missing_ranges != previous.missing_ranges
            || metadata.packages != previous.packages
            || metadata.witness_deadline_utc_ns != previous.witness_deadline_utc_ns
        {
            return Ok(false);
        }
        let before = self.value_cuts(prior)?;
        let diff = self.changes(
            &before,
            &changes.cuts,
            (!changes.full_check).then_some(&changes.touched),
        )?;
        let unchanged = diff.members.is_empty();
        changes.diff = Some(diff);
        Ok(unchanged)
    }

    pub fn apply(
        &self,
        result: &str,
        revision: u64,
        metadata: &GraphManifest,
        mut changes: ProducerChanges,
    ) -> Result<(Vec<u8>, (u64, u64, u64), (u64, u64), usize)> {
        let writer = self.transaction;
        let diff = match changes.diff.take() {
            Some(diff) => diff,
            None => {
                let before = match metadata.previous_result_id.as_deref() {
                    Some(prior) => self.value_cuts(prior)?,
                    None => Vec::new(),
                };
                self.changes(
                    &before,
                    &changes.cuts,
                    (!changes.full_check).then_some(&changes.touched),
                )?
            }
        };
        for (kind, key, _) in &changes.metadata_removed {
            for (_, scope, cut) in &changes.cuts {
                let retained:bool=writer.query_row(
                    "SELECT EXISTS(SELECT 1 FROM graph_producer_members WHERE scope_id=? AND member_kind=?
                     AND member_key=? AND valid_from<=? AND (valid_to IS NULL OR valid_to>?))",
                    params![scope,if *kind==0 {9}else{10},key,cut,cut],|row|row.get(0),
                ).context(DatabaseSnafu { operation:"check removed Graph support" })?;
                if retained {
                    return Err(NativeRows::invalid("graph removed shared support"));
                }
            }
        }
        let metadata_id = format!("{}:metadata", result);
        Self::version(
            writer,
            &metadata_id,
            changes.metadata_scope,
            revision,
            changes.metadata_base.as_deref(),
        )?;
        let mut work = changes.work;
        let metadata_work = crate::analysis::graph_rows::store::Contributions::apply(
            writer,
            revision,
            &BTreeMap::from([(
                changes.metadata_scope,
                (
                    changes.metadata_reset,
                    std::mem::take(&mut changes.metadata_members),
                ),
            )]),
        )?
        .remove(&changes.metadata_scope)
        .ok_or_else(|| NativeRows::invalid("graph producer work"))?;
        work.0 = work.0.saturating_add(metadata_work.0);
        work.1 = work.1.saturating_add(metadata_work.1);
        work.2 = work.2.saturating_add(metadata_work.2);
        writer
            .execute(
                "UPDATE graph_producer_versions SET restricted_count=?,captured_revision=? WHERE result_id=?",
                params![changes.restricted,changes.captured, metadata_id],
            )
            .context(DatabaseSnafu {
                operation: "store Graph metadata sensitivity",
            })?;
        let inputs:(usize,usize,usize)=writer.query_row(
            "SELECT evidence_count,position_count,fact_count FROM graph_producer_versions WHERE result_id=?",
            params![metadata_id],|row|Ok((row.get(0)?,row.get(1)?,row.get(2)?)),
        ).context(DatabaseSnafu { operation:"read Graph metadata counts" })?;
        writer
            .execute(
                "INSERT INTO graph_versions VALUES(?,?,?,true,false)",
                params![result, revision, metadata_id],
            )
            .context(DatabaseSnafu {
                operation: "insert public Graph version",
            })?;
        Self::bind_result(writer, &result, &metadata_id)?;
        for (producer, _, _) in &changes.cuts {
            Self::bind_result(writer, &result, producer)?;
        }
        if changes.full_check {
            self.check_union(result)?;
        } else {
            self.check_changes(result, &changes.touched)?;
        }
        let previous = changes.previous.as_ref().map_or([0; 3], |header| {
            [
                header.subject_count as u64,
                header.edge_count as u64,
                header.finding_count as u64,
            ]
        });
        let [subjects, edges, findings] = diff.counts(previous)?;
        let mut compact = metadata.clone();
        compact.input_manifest.context.clear();
        let body = GraphHeader::encode(
            &compact,
            (subjects as usize, edges as usize, findings as usize, 0),
            inputs,
        )?;
        Ok((body, work, (metadata_work.1, metadata_work.2), inputs.0))
    }

    fn value_cuts(&self, result: &str) -> Result<Vec<(String, u64, u64)>> {
        let mut statement = self.transaction.prepare(
            "SELECT v.result_id,v.scope_id,v.commit_revision FROM graph_result_producers b
             JOIN graph_producer_versions v ON v.result_id=b.producer_result_id
             JOIN graph_producer_scopes s USING(scope_id) WHERE b.result_id=? AND s.producer_kind IN (0,1) ORDER BY v.scope_id"
        ).context(DatabaseSnafu {operation:"prepare selected Graph producer cuts"})?;
        statement
            .query_map(params![result], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .context(DatabaseSnafu {
                operation: "read selected Graph producer cuts",
            })?
            .collect::<duckdb::Result<_>>()
            .context(DatabaseSnafu {
                operation: "decode selected Graph producer cuts",
            })
    }
}
