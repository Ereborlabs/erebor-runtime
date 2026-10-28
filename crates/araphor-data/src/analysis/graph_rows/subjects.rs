use super::GraphRows;
use crate::GraphValidate as _;
use crate::{
    AnalysisDatabaseSnafu, AnalysisReadControl, GraphInvalidSnafu, GraphSubjectAuthorityV1,
    GraphSubjectKeyV1, GraphSubjectKindV1, Result,
};
use duckdb::{params, params_from_iter, types::Value, Connection, Row};
use serde::Deserialize as _;
use snafu::ResultExt as _;
use std::collections::{BTreeMap, BTreeSet};

const COLUMNS: &str = "ordinal, tenant_id, authority_rank, authority_text,
    authority_boot, authority_epoch, subject_kind, identity";

impl GraphRows {
    pub(super) fn insert_subjects(
        writer: &Connection,
        subjects: &[GraphSubjectKeyV1],
        lineage: u64,
        revision: u64,
    ) -> Result<()> {
        let mut known = BTreeMap::new();
        for selected in subjects.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            let placeholders = std::iter::repeat_n("(?, ?, ?, ?, ?, ?, ?)", selected.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut parameters = Vec::with_capacity(selected.len() * 7);
            for subject in selected {
                parameters.extend(Self::subject_fields(subject));
            }
            let mut statement = writer
                .prepare(&format!(
                    "WITH requested(tenant_id, authority_rank, authority_text,
                        authority_boot, authority_epoch, subject_kind, identity)
                     AS (VALUES {placeholders})
                     SELECT s.subject_id, s.tenant_id, s.authority_rank,
                         s.authority_text, s.authority_boot, s.authority_epoch,
                         s.subject_kind, s.identity
                     FROM graph_subject_values s JOIN requested USING
                         (tenant_id, authority_rank, authority_text, authority_boot,
                          authority_epoch, subject_kind, identity)"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare shared graph subjects",
                })?;
            let mut rows = statement
                .query(params_from_iter(parameters.iter()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read shared graph subjects",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance shared graph subjects",
            })? {
                let id: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                    operation: "decode shared graph subject ID",
                })?;
                let subject = Self::decode_subject(row)?;
                if known.insert(subject, id).is_some() {
                    return GraphInvalidSnafu {
                        field: "graph subject identity",
                    }
                    .fail();
                }
            }
        }
        let mut next: u64 = writer
            .query_row(
                "SELECT coalesce(max(subject_id), 0) FROM graph_subject_values",
                [],
                |row| row.get(0),
            )
            .context(AnalysisDatabaseSnafu {
                operation: "read next graph subject ID",
            })?;
        let mut selected = BTreeSet::new();
        {
            let mut appender =
                writer
                    .appender("graph_subject_values")
                    .context(AnalysisDatabaseSnafu {
                        operation: "prepare shared graph subject insert",
                    })?;
            for subject in subjects {
                let id = if let Some(id) = known.get(subject) {
                    *id
                } else {
                    next = next.checked_add(1).ok_or_else(|| {
                        GraphInvalidSnafu {
                            field: "graph subject ID",
                        }
                        .build()
                    })?;
                    let (rank, text, boot, epoch) = Self::subject_sort(subject);
                    appender
                        .append_row(params![
                            next,
                            subject.tenant_id.as_slice(),
                            rank,
                            text,
                            boot,
                            epoch,
                            subject.kind as u8,
                            &subject.identity
                        ])
                        .context(AnalysisDatabaseSnafu {
                            operation: "insert shared graph subject",
                        })?;
                    known.insert(subject.clone(), next);
                    next
                };
                if !selected.insert(id) {
                    return GraphInvalidSnafu {
                        field: "graph subject membership",
                    }
                    .fail();
                }
            }
            appender.flush().context(AnalysisDatabaseSnafu {
                operation: "flush shared graph subjects",
            })?;
        }
        let mut active = BTreeSet::new();
        let mut statement = writer
            .prepare(
                "SELECT subject_id FROM graph_subject_membership
                 WHERE lineage_id = ? AND valid_to IS NULL",
            )
            .context(AnalysisDatabaseSnafu {
                operation: "prepare active graph subjects",
            })?;
        let mut rows = statement
            .query(params![lineage])
            .context(AnalysisDatabaseSnafu {
                operation: "read active graph subjects",
            })?;
        while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
            operation: "advance active graph subjects",
        })? {
            let id: u64 = row.get(0).context(AnalysisDatabaseSnafu {
                operation: "decode active graph subject",
            })?;
            if !active.insert(id) {
                return GraphInvalidSnafu {
                    field: "graph subject membership",
                }
                .fail();
            }
        }
        drop(rows);
        drop(statement);
        for id in active.difference(&selected) {
            let changed = writer
                .execute(
                    "UPDATE graph_subject_membership SET valid_to = ?
                     WHERE lineage_id = ? AND subject_id = ? AND valid_to IS NULL",
                    params![revision, lineage, id],
                )
                .context(AnalysisDatabaseSnafu {
                    operation: "close graph subject membership",
                })?;
            if changed != 1 {
                return GraphInvalidSnafu {
                    field: "graph subject membership",
                }
                .fail();
            }
        }
        let mut appender =
            writer
                .appender("graph_subject_membership")
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare graph subject membership insert",
                })?;
        for id in selected.difference(&active) {
            appender
                .append_row(params![lineage, id, revision, None::<u64>])
                .context(AnalysisDatabaseSnafu {
                    operation: "insert graph subject membership",
                })?;
        }
        appender.flush().context(AnalysisDatabaseSnafu {
            operation: "flush graph subject membership",
        })?;
        Ok(())
    }

    pub(super) fn subject_sort(subject: &GraphSubjectKeyV1) -> (u8, &str, &[u8], u64) {
        match &subject.authority {
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

    pub(in crate::analysis) fn decode_subject(row: &Row<'_>) -> Result<GraphSubjectKeyV1> {
        let rank: u8 = Self::column(row, 2)?;
        let text: String = Self::column(row, 3)?;
        let boot: Vec<u8> = Self::column(row, 4)?;
        let epoch: u64 = Self::column(row, 5)?;
        let authority = match rank {
            0 => GraphSubjectAuthorityV1::Native {
                node_id: text,
                node_boot_id: boot.try_into().map_err(|_| {
                    GraphInvalidSnafu {
                        field: "subject boot bytes",
                    }
                    .build()
                })?,
                label_epoch: epoch,
            },
            1..=3 if boot.is_empty() && epoch == 0 => match rank {
                1 => GraphSubjectAuthorityV1::Provider { authority_id: text },
                2 => GraphSubjectAuthorityV1::Kubernetes { cluster_id: text },
                _ => GraphSubjectAuthorityV1::External { authority_id: text },
            },
            _ => {
                return GraphInvalidSnafu {
                    field: "subject authority",
                }
                .fail();
            }
        };
        let kind: u8 = Self::column(row, 6)?;
        let kind = GraphSubjectKindV1::deserialize(serde::de::value::U32Deserializer::<
            serde::de::value::Error,
        >::new(u32::from(kind)))
        .map_err(|_| {
            GraphInvalidSnafu {
                field: "subject kind",
            }
            .build()
        })?;
        let subject = GraphSubjectKeyV1 {
            tenant_id: Self::borrowed(row, 1, |value| value.as_blob())?
                .try_into()
                .map_err(|_| {
                    GraphInvalidSnafu {
                        field: "subject tenant bytes",
                    }
                    .build()
                })?,
            kind,
            authority,
            identity: Self::column(row, 7)?,
        };
        subject.validate()?;
        Ok(subject)
    }
    pub(in crate::analysis) fn subject_permission(binding_scope: bool) -> &'static str {
        if !binding_scope {
            return "TRUE";
        }
        "EXISTS (
            SELECT 1 FROM graph_findings finding
            WHERE finding.result_id = subject.result_id AND finding.subject_id = seed.subject_id
         ) OR EXISTS (
            SELECT 1 FROM graph_relationships edge
            WHERE edge.result_id = subject.result_id AND array_length(edge.evidence) > 0
                AND (edge.from_subject_id = subject.ordinal OR edge.to_subject_id = subject.ordinal)
         )"
    }

    pub(in crate::analysis) fn subject_fields(subject: &GraphSubjectKeyV1) -> [Value; 7] {
        let (rank, text, boot, epoch) = Self::subject_sort(subject);
        [
            Value::Blob(subject.tenant_id.to_vec()),
            Value::UTinyInt(rank),
            Value::Text(text.to_owned()),
            Value::Blob(boot.to_vec()),
            Value::UBigInt(epoch),
            Value::UTinyInt(subject.kind as u8),
            Value::Blob(subject.identity.clone()),
        ]
    }

    pub(in crate::analysis) fn selected_subjects(
        reader: &Connection,
        result_id: &str,
        keys: &[GraphSubjectKeyV1],
        control: &AnalysisReadControl,
        binding_scope: bool,
    ) -> Result<Vec<(GraphSubjectKeyV1, u32)>> {
        let mut selected = Vec::new();
        for keys in keys.chunks(crate::analysis::MAX_ANALYSIS_PAGE_RECORDS) {
            control.check()?;
            let values = std::iter::repeat_n("(?, ?, ?, ?, ?, ?, ?, ?)", keys.len())
                .collect::<Vec<_>>()
                .join(", ");
            let mut parameters = Vec::new();
            for key in keys {
                parameters.push(Value::Blob(Self::json(key)?));
                parameters.extend(Self::subject_fields(key));
            }
            parameters.push(Value::Text(result_id.to_owned()));
            let columns = COLUMNS
                .split(',')
                .map(|column| format!("subject.{}", column.trim()))
                .collect::<Vec<_>>()
                .join(", ");
            let permission = Self::subject_permission(binding_scope);
            let mut statement = reader
                .prepare(&format!(
                    "WITH requested(subject_id, tenant_id, authority_rank, authority_text,
                        authority_boot, authority_epoch, subject_kind, identity)
                 AS (VALUES {values})
                 SELECT {columns} FROM graph_subjects subject JOIN requested seed
                 USING (tenant_id, authority_rank, authority_text, authority_boot,
                     authority_epoch, subject_kind, identity)
                 WHERE subject.result_id = ? AND ({permission})
                 ORDER BY subject.ordinal"
                ))
                .context(AnalysisDatabaseSnafu {
                    operation: "prepare selected graph subjects",
                })?;
            let mut rows = statement
                .query(params_from_iter(parameters.iter()))
                .context(AnalysisDatabaseSnafu {
                    operation: "read selected graph subjects",
                })?;
            while let Some(row) = rows.next().context(AnalysisDatabaseSnafu {
                operation: "advance selected graph subjects",
            })? {
                control.check()?;
                selected.push((
                    Self::column_operation(
                        Self::decode_subject(row),
                        "decode selected graph subject columns",
                    )?,
                    Self::column(row, 0)?,
                ));
            }
        }
        selected.sort_by(|left, right| left.0.cmp(&right.0));
        control.check()?;
        Ok(selected)
    }

    pub(in crate::analysis) fn read_subjects(
        writer: &Connection,
        result_id: &str,
        expected_count: usize,
        control: Option<&AnalysisReadControl>,
    ) -> Result<Vec<GraphSubjectKeyV1>> {
        Self::load(
            writer,
            "graph_subjects",
            COLUMNS,
            result_id,
            expected_count,
            control,
            Self::decode_subject,
        )
    }
}
