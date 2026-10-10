use rustix::fs::{Mode, OFlags};
use std::io::{Seek as _, Write as _};

use super::*;

impl<'a> GraphMigration<'a> {
    pub(super) fn new(root: &'a Path) -> Result<Self> {
        let file = rustix::fs::open(
            root,
            OFlags::TMPFILE | OFlags::RDWR | OFlags::CLOEXEC,
            Mode::RUSR | Mode::WUSR,
        )
        .map_err(std::io::Error::from)
        .context(IoSnafu { path: root })?;
        Ok(Self {
            root,
            file: File::from(file),
            count: 0,
            bytes: 0,
            rows: 0,
            tenants: BTreeSet::new(),
        })
    }

    pub(super) fn stage(&mut self, writer: &Connection, storage: StorageLimitsV1) -> Result<()> {
        let usage = AnalysisStore::storage_at(self.root, 0, 0)?;
        let mut after = String::new();
        while let Some((id, tenant, body)) = AnalysisStore::next_graph(writer, &after, true)? {
            let snapshot = GraphSnapshotV1::try_from(body.as_slice())?;
            let tenant = tenant.try_into().map_err(|_| {
                crate::AnalysisStateSnafu {
                    path: self.root,
                    reason: "the retained graph tenant is invalid",
                }
                .build()
            })?;
            if snapshot.scope.identity.tenant_id != tenant {
                return AnalysisStore::reject_path(self.root, "the retained graph tenant differs");
            }
            let rows = GraphRows::encode_body(&snapshot, &body)?;
            self.rows = self
                .rows
                .checked_add(
                    rows.bytes(&id)? as u64
                        + rows.header().len() as u64
                        + rows.encoding().len() as u64,
                )
                .ok_or_else(|| {
                    crate::StorageCapacitySnafu {
                        resource: "graph migration bytes",
                    }
                    .build()
                })?;
            let bytes = serde_json::to_vec(&StagedGraph {
                result_id: id.clone(),
                tenant,
                rows,
            })
            .context(JsonSnafu { path: self.root })?;
            if bytes.len() > STAGED_LIMIT {
                return crate::StorageCapacitySnafu {
                    resource: "graph migration record",
                }
                .fail();
            }
            self.bytes = self
                .bytes
                .checked_add(bytes.len() as u64 + 4)
                .ok_or_else(|| {
                    crate::StorageCapacitySnafu {
                        resource: "graph migration bytes",
                    }
                    .build()
                })?;
            let reserve = self
                .rows
                .checked_mul(2)
                .and_then(|rows| rows.checked_add(self.bytes))
                .and_then(|rows| rows.checked_add(SPILL_RESERVE))
                .ok_or_else(|| {
                    crate::StorageCapacitySnafu {
                        resource: "graph migration bytes",
                    }
                    .build()
                })?;
            storage.check_terminal(usage, reserve)?;
            self.file
                .write_all(&(bytes.len() as u32).to_le_bytes())
                .context(IoSnafu { path: self.root })?;
            self.file
                .write_all(&bytes)
                .context(IoSnafu { path: self.root })?;
            self.tenants.insert(tenant);
            self.count += 1;
            after = id;
        }
        self.file.rewind().context(IoSnafu { path: self.root })
    }
}
