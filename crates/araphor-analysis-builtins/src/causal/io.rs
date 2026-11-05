use std::sync::{Arc, OnceLock};

use araphor_analysis_types::{
    arrow::{
        self,
        views::{ContextKeyRow, RecordIdRow, SourceRow},
    },
    source::DiscoveryRecordIdV1,
    values::ContextSensitivityV1,
};
use serde::{Deserialize, Serialize};
use serde_bytes::ByteBuf;

use super::{model::Audit, sdk, state::Reference};

#[derive(Deserialize, Serialize)]
pub(super) struct ContextRow {
    pub key: ContextKeyRow,
    pub commit_revision: u64,
    pub sensitivity: String,
    pub body: ByteBuf,
}

pub(super) struct Context {
    pub reference: Reference,
    pub audit: Audit,
}

impl ContextRow {
    pub(super) fn port(name: &str) -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        let mut port = arrow::port::<Self>("audit_contexts", &PORT);
        port.name = name.into();
        port
    }

    pub(super) fn read(
        checked: &sdk::CheckedEvaluation<'_>,
        name: &str,
    ) -> sdk::Result<Vec<Context>> {
        arrow::decode::<Self, _>(
            Self::port(name),
            &checked.evaluation().input(name)?.data,
            |row| {
                let key: araphor_analysis_types::values::AnalysisContextKeyV1 =
                    row.key.try_into()?;
                let sensitivity = ContextSensitivityV1::try_from(row.sensitivity.as_str())
                    .map_err(|_| Audit::invalid("causal context sensitivity"))?;
                let audit = Audit::decode(&row.body)?;
                if key.owner_id != Audit::OWNER
                    || key.tenant_id != audit.record.stream.tenant_id
                    || key.owner_revision == 0
                    || row.commit_revision == 0
                {
                    return Err(Audit::invalid("causal context authority"));
                }
                Ok(Context {
                    reference: Reference {
                        record: audit.record.clone(),
                        context: key,
                        revision: row.commit_revision,
                        restricted: sensitivity == ContextSensitivityV1::HostRestricted,
                    },
                    audit,
                })
            },
        )
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct ContextKey {
    pub key: ContextKeyRow,
}

impl ContextKey {
    pub(super) fn port(name: &str) -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        let mut port = arrow::port::<Self>("context_keys", &PORT);
        port.name = name.into();
        port
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct CoverageKey {
    pub source: SourceRow,
    pub cpu_id: u32,
}

impl CoverageKey {
    pub(super) fn port(name: &str) -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        let mut port = arrow::port::<Self>("coverage_keys", &PORT);
        port.name = name.into();
        port
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct CoverageRow {
    pub source: SourceRow,
    pub cpu_id: u32,
    pub coverage_revision: u64,
    pub retained_floor: u64,
    pub kind: String,
    pub first_cursor: Option<u64>,
    pub last_cursor: Option<u64>,
}

impl CoverageRow {
    pub(super) fn port(name: &str) -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        let mut port = arrow::port::<Self>("coverage_receipts", &PORT);
        port.name = name.into();
        port
    }

    pub(super) fn read(checked: &sdk::CheckedEvaluation<'_>, name: &str) -> sdk::Result<Vec<Self>> {
        arrow::decode::<Self, _>(
            Self::port(name),
            &checked.evaluation().input(name)?.data,
            Ok,
        )
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct FrontierRow {
    pub record: RecordIdRow,
    pub context: ContextKeyRow,
    pub commit_revision: u64,
}

impl FrontierRow {
    pub(super) fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<Self>("frontier", &PORT)
    }

    pub(super) fn encode(rows: &[Reference]) -> sdk::Result<sdk::Dataset> {
        let keys = rows
            .iter()
            .map(|row| (&row.record, &row.context, row.revision))
            .collect::<std::collections::BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        arrow::encode(Self::port(), &keys, |row| Self {
            record: RecordIdRow::from(row.0),
            context: ContextKeyRow::from(row.1),
            commit_revision: row.2,
        })
    }

    pub(super) fn read(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<Vec<Reference>> {
        arrow::decode::<Self, _>(
            Self::port(),
            &checked.evaluation().input("frontier")?.data,
            |row| {
                Ok(Reference {
                    record: row.record.try_into()?,
                    context: row.context.try_into()?,
                    revision: row.commit_revision,
                    restricted: false,
                })
            },
        )
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct Summary {
    pub findings: u64,
}

impl Summary {
    pub(super) fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<Self>("summary", &PORT)
    }

    pub(super) fn encode(findings: u64) -> sdk::Result<sdk::Dataset> {
        arrow::encode(Self::port(), &[Self { findings }], |row| row)
    }
}

#[derive(Deserialize, Serialize)]
pub(super) struct Control {
    pub reset: bool,
    pub restricted: bool,
}

impl Control {
    pub(super) fn port() -> sdk::Port {
        static PORT: OnceLock<sdk::Port> = OnceLock::new();
        arrow::port::<Self>("control", &PORT)
    }

    pub(super) fn encode(self) -> sdk::Result<sdk::Dataset> {
        Ok(sdk::Dataset {
            name: "control".into(),
            batches: vec![sdk::RecordBatch::try_new(
                Arc::new(Self::port().schema),
                vec![
                    Arc::new(sdk::arrow_array::BooleanArray::from(vec![self.reset])),
                    Arc::new(sdk::arrow_array::BooleanArray::from(vec![self.restricted])),
                ],
            )?],
        })
    }

    pub(super) fn read(checked: &sdk::CheckedEvaluation<'_>) -> sdk::Result<Self> {
        let mut rows = arrow::decode::<Self, _>(
            Self::port(),
            &checked.evaluation().input("control")?.data,
            Ok,
        )?;
        if rows.len() != 1 {
            return Err(Audit::invalid("causal control row"));
        }
        rows.pop()
            .ok_or_else(|| Audit::invalid("causal control row"))
    }
}
