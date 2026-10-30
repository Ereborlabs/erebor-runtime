use std::collections::{BTreeMap, BTreeSet};
use std::io::Cursor;

use araphor_analysis_builtins::graph::*;
use araphor_analysis_sdk as sdk;
use duckdb::{params, Connection, OptionalExt as _, Row};
use serde::{de::DeserializeOwned, Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use snafu::ResultExt as _;

use super::{AnalysisReadControl, GraphManifest, ManagedCommit, PackageResultRefV1};
use crate::{AnalysisDatabaseSnafu, GraphInvalidSnafu, GraphSnapshotV1, Result};

mod calls;
mod header;
mod history;
mod intern;
mod progress;
mod publication;
mod read;
mod registry;
mod schema;
mod stage;
#[cfg(test)]
pub(in crate::analysis) mod tests;
mod validation;
mod values;

pub(in crate::analysis) use calls::{GraphCallRows, GraphCallState};
pub(in crate::analysis) use header::GraphHeader;
use intern::EdgeValue;

pub(super) struct GraphRows;

pub(in crate::analysis) enum GraphWrite<'a> {
    Managed {
        commit: &'a ManagedCommit<'a>,
        producers: &'a [(u64, PackageResultRefV1)],
    },
    Direct(&'a GraphSnapshotV1),
    Expiry(&'a PackageResultRefV1),
}

pub struct CanonicalGraph {
    snapshot: GraphSnapshotV1,
}

impl CanonicalGraph {
    pub fn new(snapshot: GraphSnapshotV1) -> Result<Self> {
        snapshot.validate()?;
        Ok(Self { snapshot })
    }

    pub fn snapshot(&self) -> &GraphSnapshotV1 {
        &self.snapshot
    }

    pub(in crate::analysis) fn into_snapshot(self) -> GraphSnapshotV1 {
        self.snapshot
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum MemberKind {
    Evidence = 0,
    Position = 1,
    Subject = 2,
    Edge = 3,
    Finding = 4,
    Progress = 5,
    Branch = 6,
    Fact = 7,
}

impl TryFrom<u8> for MemberKind {
    type Error = crate::Error;
    fn try_from(value: u8) -> Result<Self> {
        match value {
            0 => Ok(Self::Evidence),
            1 => Ok(Self::Position),
            2 => Ok(Self::Subject),
            3 => Ok(Self::Edge),
            4 => Ok(Self::Finding),
            5 => Ok(Self::Progress),
            6 => Ok(Self::Branch),
            7 => Ok(Self::Fact),
            _ => Err(GraphRows::invalid("graph member kind")),
        }
    }
}

impl GraphRows {
    fn invalid(field: &'static str) -> crate::Error {
        GraphInvalidSnafu { field }.build()
    }

    fn encode_value(value: &impl Serialize) -> Result<Vec<u8>> {
        let mut bytes = Vec::new();
        value
            .serialize(&mut rmp_serde::Serializer::new(&mut bytes).with_struct_map())
            .map_err(|_| Self::invalid("graph typed value"))?;
        Ok(bytes)
    }

    fn decode_value<T: DeserializeOwned>(bytes: &[u8]) -> Result<T> {
        let mut decoder = rmp_serde::Deserializer::new(Cursor::new(bytes));
        let value = T::deserialize(&mut decoder).map_err(|_| Self::invalid("graph typed value"))?;
        if decoder.position() != bytes.len() as u64 {
            return Err(Self::invalid("graph trailing bytes"));
        }
        Ok(value)
    }

    fn hash(bytes: &[u8]) -> Vec<u8> {
        Sha256::digest(bytes).to_vec()
    }

    fn member_key(value: &impl Serialize) -> Result<Vec<u8>> {
        Ok(Self::hash(&Self::encode_value(value)?))
    }

    fn column<T: duckdb::types::FromSql>(row: &Row<'_>, index: usize) -> Result<T> {
        row.get(index).context(AnalysisDatabaseSnafu {
            operation: "decode Graph row",
        })
    }

    fn next_id(writer: &Connection, table: &str) -> Result<u64> {
        writer
            .query_row(&format!("SELECT nextval('{table}_seq')"), [], |row| {
                row.get(0)
            })
            .context(AnalysisDatabaseSnafu {
                operation: "allocate Graph identity",
            })
    }

    fn check(control: Option<&AnalysisReadControl>) -> Result<()> {
        if let Some(control) = control {
            control.check()?;
        }
        Ok(())
    }
}
