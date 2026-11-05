use crate::analysis::graph_rows::store::source::EvidenceIntakeIdentityV1;
use crate::analysis::graph_rows::store::values::GraphPackageStateV1;
use duckdb::{params, Connection, OptionalExt as _};
use snafu::ResultExt as _;

use crate::analysis::graph_rows::store::{
    error::DatabaseSnafu, native::NativeRows, GraphHeader, Result, GRAPH_PROCESSOR,
    GRAPH_SCHEMA_VERSION,
};

mod apply;
mod frozen;
mod read;
mod schema;
pub use apply::{ProducerChanges, VersionPin};
pub use frozen::{FrozenContext, FrozenInput, FrozenProof};
mod changes;
pub use changes::{Changes, MembershipChange};

pub struct Relations<'a> {
    transaction: &'a Connection,
}

pub struct GraphHead {
    pub result_id: String,
    pub commit_revision: u64,
}

pub struct Snapshot<'a> {
    transaction: &'a Connection,
    pub head: GraphHead,
    pub header: GraphHeader,
}

impl<'a> Relations<'a> {
    pub fn new(transaction: &'a Connection) -> Self {
        Self { transaction }
    }

    pub fn head(&self, source: &EvidenceIntakeIdentityV1, cut: u64) -> Result<Option<GraphHead>> {
        if !source.valid() {
            return Err(NativeRows::invalid("graph head source"));
        }
        if cut == 0 {
            return Ok(None);
        }
        self.transaction.query_row(
            "SELECT r.result_id,r.commit_revision FROM analysis_results r JOIN graph_versions v USING(result_id)
             WHERE r.tenant_id=? AND r.stream_key=? AND r.processor_id=? AND r.method_version=?
                AND r.commit_revision<=? ORDER BY r.commit_revision DESC,r.result_id DESC LIMIT 1",
            params![source.tenant_id.as_slice(),source.key(),GRAPH_PROCESSOR,GRAPH_SCHEMA_VERSION,cut],
            |row| Ok(GraphHead { result_id: row.get(0)?, commit_revision: row.get(1)? }),
        ).optional().context(DatabaseSnafu {operation:"read scoped Graph head"})
    }

    pub fn snapshot(&self, tenant: [u8; 16], result: &str) -> Result<Option<Snapshot<'a>>> {
        self.read_snapshot(tenant, result, &mut |_, _| Ok(()))
    }

    pub fn read_snapshot<E>(
        &self,
        tenant: [u8; 16],
        result: &str,
        charge: &mut impl FnMut(usize, usize) -> std::result::Result<(), E>,
    ) -> std::result::Result<Option<Snapshot<'a>>, E>
    where
        E: From<crate::analysis::graph_rows::store::Error>,
    {
        let mut statement=self.transaction.prepare(
            "SELECT r.body,r.stream_key,r.method_version,r.first_cursor,r.facts_revision,r.coverage_revision,
                r.commit_revision,g.expired,g.derive_branches,v.evidence_count,v.position_count,v.fact_count,
                v.restricted_count,g.commit_revision,v.commit_revision,octet_length(r.body)
             FROM analysis_result_state r LEFT JOIN graph_versions g ON g.result_id=r.result_id
             LEFT JOIN graph_producer_versions v ON v.result_id=g.metadata_result_id
             WHERE r.result_id=? AND r.tenant_id=? AND r.processor_id=?"
        ).context(DatabaseSnafu {operation:"prepare exact Graph snapshot"})?;
        let mut rows = statement
            .query(params![result, tenant.as_slice(), GRAPH_PROCESSOR])
            .context(DatabaseSnafu {
                operation: "read exact Graph snapshot",
            })?;
        let Some(row) = rows.next().context(DatabaseSnafu {
            operation: "advance exact Graph snapshot",
        })?
        else {
            return Ok(None);
        };
        let length = usize::try_from(NativeRows::column::<u64>(row, 15)?).unwrap_or(usize::MAX);
        charge(length, length.saturating_mul(2))?;
        let mut header = GraphHeader::decode(&NativeRows::column::<Vec<u8>>(row, 0)?)?;
        header.check_index(
            tenant,
            &NativeRows::column::<Vec<u8>>(row, 1)?,
            NativeRows::column(row, 2)?,
            NativeRows::column(row, 3)?,
        )?;
        header.notice = (NativeRows::column(row, 4)?, NativeRows::column(row, 5)?);
        let revision = NativeRows::column::<u64>(row, 6)?;
        header.expired = NativeRows::column(row, 7)?;
        header.derive_branches = NativeRows::column(row, 8)?;
        let counts = (
            NativeRows::column::<u64>(row, 9)?,
            NativeRows::column::<u64>(row, 10)?,
            NativeRows::column::<u64>(row, 11)?,
        );
        header.restricted_count = NativeRows::column(row, 12)?;
        if counts
            != (
                header.evidence_count as u64,
                header.position_count as u64,
                header.fact_count as u64,
            )
            || NativeRows::column::<u64>(row, 13)? != revision
            || NativeRows::column::<u64>(row, 14)? > revision
        {
            return Err(E::from(NativeRows::invalid(
                "graph metadata summary counts",
            )));
        }
        if header.expired
            && header
                .snapshot
                .packages
                .iter()
                .any(|package| package.state != GraphPackageStateV1::CoverageInsufficient)
        {
            return Err(E::from(NativeRows::invalid("graph expired package state")));
        }
        if rows
            .next()
            .context(DatabaseSnafu {
                operation: "check exact Graph snapshot uniqueness",
            })?
            .is_some()
        {
            return Err(E::from(NativeRows::invalid("graph snapshot identity")));
        }
        Ok(Some(Snapshot {
            transaction: self.transaction,
            head: GraphHead {
                result_id: result.into(),
                commit_revision: revision,
            },
            header,
        }))
    }
}
