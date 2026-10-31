use std::collections::{BTreeMap, BTreeSet};

use araphor_analysis_builtins::graph::*;
use duckdb::{params, Connection, Row};
use snafu::ResultExt as _;

use crate::{error::DatabaseSnafu, native::NativeRows, Result};

pub struct SubjectRows;

impl SubjectRows {
    pub const SCHEMA: &str = include_str!("subjects.sql");
    pub const COLUMNS: &str = "ordinal,tenant_id,authority_rank,authority_text,authority_boot,authority_epoch,subject_kind,identity";

    pub fn intern(
        writer: &Connection,
        subjects: &[GraphSubjectKeyV1],
    ) -> Result<BTreeMap<GraphSubjectKeyV1, u64>> {
        let subjects = subjects.iter().collect::<BTreeSet<_>>();
        if subjects.is_empty() {
            return Ok(BTreeMap::new());
        }
        writer.execute_batch("CREATE TEMP TABLE graph_value_subjects AS SELECT * EXCLUDE(subject_id) FROM graph_subject_values WHERE false").context(DatabaseSnafu {operation:"create Graph subject candidates"})?;
        {
            let mut appender = writer
                .appender("graph_value_subjects")
                .context(DatabaseSnafu {
                    operation: "open Graph subject candidates",
                })?;
            for subject in &subjects {
                Self::validate(subject)?;
                let (rank, text, boot, epoch) = Self::authority(&subject.authority);
                appender
                    .append_row(params![
                        subject.tenant_id.as_slice(),
                        rank,
                        text,
                        boot,
                        epoch,
                        subject.kind as u8,
                        subject.identity
                    ])
                    .context(DatabaseSnafu {
                        operation: "append Graph subject candidate",
                    })?;
            }
            appender.flush().context(DatabaseSnafu {
                operation: "flush Graph subject candidates",
            })?;
        }
        let equal="v.tenant_id=c.tenant_id AND v.authority_rank=c.authority_rank AND v.authority_text=c.authority_text AND v.authority_boot=c.authority_boot AND v.authority_epoch=c.authority_epoch AND v.subject_kind=c.subject_kind AND v.identity=c.identity";
        writer.execute_batch(&format!("INSERT INTO graph_subject_values SELECT nextval('graph_subject_values_seq'),c.* FROM graph_value_subjects c WHERE NOT EXISTS(SELECT 1 FROM graph_subject_values v WHERE {equal})")).context(DatabaseSnafu {operation:"intern Graph subject candidates"})?;
        let mut statement = writer
            .prepare(&format!(
                "SELECT v.* FROM graph_value_subjects c JOIN graph_subject_values v ON {equal}"
            ))
            .context(DatabaseSnafu {
                operation: "prepare Graph subject references",
            })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph subject references",
        })?;
        let mut values = BTreeMap::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph subject references",
        })? {
            if values
                .insert(Self::decode(row)?, NativeRows::column(row, 0)?)
                .is_some()
            {
                return Err(NativeRows::invalid("graph duplicate subject value"));
            }
        }
        drop(rows);
        drop(statement);
        writer
            .execute_batch("DROP TABLE graph_value_subjects")
            .context(DatabaseSnafu {
                operation: "release Graph subject candidates",
            })?;
        if values.len() != subjects.len() {
            return Err(NativeRows::invalid("graph subject candidate count"));
        }
        Ok(values)
    }

    fn authority(authority: &GraphSubjectAuthorityV1) -> (u8, &str, &[u8], u64) {
        match authority {
            GraphSubjectAuthorityV1::Native {
                node_id,
                node_boot_id,
                label_epoch,
            } => (0, node_id, node_boot_id, *label_epoch),
            GraphSubjectAuthorityV1::Provider { authority_id } => (1, authority_id, &[], 0),
            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => (2, cluster_id, &[], 0),
            GraphSubjectAuthorityV1::External { authority_id } => (3, authority_id, &[], 0),
        }
    }

    pub fn decode(row: &Row<'_>) -> Result<GraphSubjectKeyV1> {
        let tenant: Vec<u8> = NativeRows::column(row, 1)?;
        let rank: u8 = NativeRows::column(row, 2)?;
        let text = NativeRows::column(row, 3)?;
        let boot: Vec<u8> = NativeRows::column(row, 4)?;
        let epoch: u64 = NativeRows::column(row, 5)?;
        let kind: u8 = NativeRows::column(row, 6)?;
        if rank != 0 && (!boot.is_empty() || epoch != 0) {
            return Err(NativeRows::invalid("graph subject authority"));
        }
        let authority = match rank {
            0 => GraphSubjectAuthorityV1::Native {
                node_id: text,
                node_boot_id: boot
                    .try_into()
                    .map_err(|_| NativeRows::invalid("graph subject authority"))?,
                label_epoch: epoch,
            },
            1 => GraphSubjectAuthorityV1::Provider { authority_id: text },
            2 => GraphSubjectAuthorityV1::Kubernetes { cluster_id: text },
            3 => GraphSubjectAuthorityV1::External { authority_id: text },
            _ => return Err(NativeRows::invalid("graph subject authority")),
        };
        let kinds = [
            GraphSubjectKindV1::Task,
            GraphSubjectKindV1::Process,
            GraphSubjectKindV1::ExecutionSet,
            GraphSubjectKindV1::Socket,
            GraphSubjectKindV1::Artifact,
            GraphSubjectKindV1::Request,
            GraphSubjectKindV1::CredentialLease,
            GraphSubjectKindV1::KubernetesObject,
            GraphSubjectKindV1::ProviderObject,
            GraphSubjectKindV1::External,
        ];
        let subject = GraphSubjectKeyV1 {
            tenant_id: tenant
                .try_into()
                .map_err(|_| NativeRows::invalid("graph subject tenant"))?,
            authority,
            kind: *kinds
                .get(kind as usize)
                .ok_or_else(|| NativeRows::invalid("graph subject kind"))?,
            identity: NativeRows::column(row, 7)?,
        };
        Self::validate(&subject)?;
        Ok(subject)
    }

    pub fn validate(subject: &GraphSubjectKeyV1) -> Result<()> {
        let valid_authority = match &subject.authority {
            GraphSubjectAuthorityV1::Native {
                node_id,
                node_boot_id,
                label_epoch,
            } => !node_id.is_empty() && *node_boot_id != [0; 16] && *label_epoch > 0,
            GraphSubjectAuthorityV1::Provider { authority_id }
            | GraphSubjectAuthorityV1::External { authority_id } => !authority_id.is_empty(),
            GraphSubjectAuthorityV1::Kubernetes { cluster_id } => !cluster_id.is_empty(),
        };
        if subject.tenant_id == [0; 16] || !valid_authority || subject.identity.is_empty() {
            return Err(NativeRows::invalid("subject lifetime"));
        }
        Ok(())
    }

    pub fn registry(reader: &Connection) -> Result<BTreeMap<u64, GraphSubjectKeyV1>> {
        let mut statement = reader.prepare("SELECT subject_id,tenant_id,authority_rank,authority_text,authority_boot,authority_epoch,subject_kind,identity FROM graph_subject_values")
            .context(DatabaseSnafu { operation: "prepare Graph subject registry" })?;
        let mut rows = statement.query([]).context(DatabaseSnafu {
            operation: "read Graph subject registry",
        })?;
        let mut subjects = BTreeMap::new();
        let mut values = BTreeSet::new();
        while let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance Graph subject registry",
        })? {
            let id: u64 = NativeRows::column(row, 0)?;
            let subject = Self::decode(row)?;
            if id == 0 || !values.insert(subject.clone()) || subjects.insert(id, subject).is_some()
            {
                return Err(NativeRows::invalid("graph duplicate subject value"));
            }
        }
        Ok(subjects)
    }
}
