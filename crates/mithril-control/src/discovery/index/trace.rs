use super::*;
use crate::{
    TraceAcceptedV1, TraceBatchV1, TraceErrorCodeV1, TraceFrameV1, TraceMeasurementV1, TraceOwner,
    TraceReadAccessV1, TraceRevisionV1,
};

impl DiscoveryIndex {
    pub(super) fn project_trace(
        &self,
        head: &DiscoveryHeadV1,
        revision: &TraceRevisionV1,
        accepted: &TraceAcceptedV1,
    ) -> Result<()> {
        let _admission = self.writes.try_acquire().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_WRITE_LIMIT",
                reason: "the writer and eight pending slots are in use",
            }
            .build()
        })?;
        self.store
            .reserve_discovery_index_tenant(head.key.tenant_id)?;
        let batch = revision
            .batch
            .as_ref()
            .map(|reference| TraceOwner::read_artifact::<TraceBatchV1>(&self.store, reference))
            .transpose()?;
        let tenant = head.key.tenant_id;
        let request = accepted.request.request_id;
        let target = revision.target_index.map_or(-1, i64::from);
        let mut writer = self.writer.lock().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: "the writer is poisoned",
            }
            .build()
        })?;
        self.reserve_write(&writer)?;
        let transaction = writer.transaction().context(DiscoveryDatabaseSnafu {
            operation: "begin trace projection",
        })?;
        let previous: Option<Vec<u8>> = transaction
            .query_row(
                "SELECT head FROM traces WHERE tenant=?1 AND request=?2 AND target=?3",
                params![tenant, request, target],
                |row| row.get(0),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "read trace predecessor",
            })?;
        let encoded = Self::encode_context_head(head)?;
        if previous.as_ref() == Some(&encoded) {
            return Ok(());
        }
        TraceErrorCodeV1::Integrity.require(
            previous
                == revision
                    .previous
                    .as_ref()
                    .map(Self::encode_context_head)
                    .transpose()?,
            "trace index predecessor changed",
        )?;
        transaction
            .execute(
                "INSERT INTO traces VALUES(?1,?2,?3,?4)
            ON CONFLICT(tenant,request,target) DO UPDATE SET head=excluded.head",
                params![tenant, request, target, encoded],
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "advance trace projection",
            })?;
        if let Some(batch) = batch {
            batch.validate()?;
            for frame in batch.frames {
                let bytes = Self::trace_encode(&frame)?;
                transaction
                    .execute(
                        "INSERT INTO trace_output VALUES(?1,?2,?3,?4,?5)",
                        params![tenant, request, target, frame.sequence, bytes],
                    )
                    .context(DiscoveryDatabaseSnafu {
                        operation: "project trace output",
                    })?;
                if let Some(measurements) = accepted
                    .recipe
                    .and_then(|recipe| recipe.measurements(&frame))
                {
                    for measurement in measurements {
                        let bytes = Self::trace_encode(&measurement)?;
                        transaction
                            .execute(
                                "INSERT INTO trace_measurements VALUES(?1,?2,?3,?4,?5,?6,?7,?8,?9)",
                                params![
                                    tenant,
                                    request,
                                    target,
                                    measurement.sequence,
                                    measurement.ordinal,
                                    measurement.syscall_id,
                                    measurement.errno,
                                    measurement.count.to_be_bytes(),
                                    bytes
                                ],
                            )
                            .context(DiscoveryDatabaseSnafu {
                                operation: "project trace measurement",
                            })?;
                    }
                }
            }
        }
        transaction.commit().context(DiscoveryDatabaseSnafu {
            operation: "commit trace projection",
        })
    }

    fn trace_encode(value: &impl Serialize) -> Result<Vec<u8>> {
        rmp_serde::to_vec_named(value).map_err(|error| {
            DiscoverySnafu {
                code: "TRACE_PROJECTION_ENCODING",
                reason: error.to_string(),
            }
            .build()
        })
    }

    fn trace_head(
        &self,
        request: [u8; 16],
        index: Option<u16>,
        access: &TraceReadAccessV1,
        now: u64,
    ) -> Result<Option<DiscoveryHeadV1>> {
        let (_, accepted) =
            TraceOwner::new(self.store.clone()).read(access.tenant_id, request, access, now)?;
        if let Some(index) = index {
            accepted.execution_id(index)?;
        }
        let current =
            self.store
                .discovery_head(&TraceRevisionV1::key(access.tenant_id, request, index)?)?;
        let reader = self.reader()?;
        let projected: Option<Vec<u8>> = reader
            .query_row(
                "SELECT head FROM traces WHERE tenant=?1 AND request=?2 AND target=?3",
                params![access.tenant_id, request, index.map_or(-1, i64::from)],
                |row| row.get(0),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "read trace projection",
            })?;
        let projected = projected
            .as_deref()
            .map(Self::decode_context_head)
            .transpose()?;
        TraceErrorCodeV1::Capacity
            .require(current == projected, "trace projection has not caught up")?;
        Ok(current)
    }
}

impl DiscoveryOwner {
    pub fn trace_state(
        &self,
        request: [u8; 16],
        target_index: Option<u16>,
        access: &TraceReadAccessV1,
        now: u64,
    ) -> Result<Option<TraceRevisionV1>> {
        self.live
            .index
            .trace_head(request, target_index, access, now)?
            .as_ref()
            .map(|head| TraceRevisionV1::read(&self.live.store, head).map(|(revision, _)| revision))
            .transpose()
    }

    pub fn trace_output(
        &self,
        request: [u8; 16],
        target_index: u16,
        access: &TraceReadAccessV1,
        now: u64,
        after: u64,
    ) -> Result<Vec<TraceFrameV1>> {
        TraceErrorCodeV1::Invalid.require(after <= 4096, "trace cursor exceeds the frame bound")?;
        let through = self
            .trace_state(request, Some(target_index), access, now)?
            .map_or(0, |revision| revision.last_sequence);
        let reader = self.live.index.reader()?;
        let mut query = reader.prepare("SELECT frame FROM trace_output
            WHERE tenant=?1 AND request=?2 AND target=?3 AND sequence>?4 AND sequence<=?5 ORDER BY sequence LIMIT 200")
            .context(DiscoveryDatabaseSnafu { operation: "prepare trace output page" })?;
        let mut rows = query
            .query(params![
                access.tenant_id,
                request,
                target_index,
                after,
                through
            ])
            .context(DiscoveryDatabaseSnafu {
                operation: "read trace output page",
            })?;
        let mut result = Vec::new();
        let mut budget = 1024 * 1024;
        while let Some(row) = rows.next().context(DiscoveryDatabaseSnafu {
            operation: "read trace output row",
        })? {
            let bytes: Vec<u8> = row.get(0).context(DiscoveryDatabaseSnafu {
                operation: "read trace output bytes",
            })?;
            let frame: TraceFrameV1 = TraceOwner::decode(&bytes)?;
            frame.validate()?;
            if frame.bytes.len() > budget {
                break;
            }
            budget -= frame.bytes.len();
            result.push(frame);
        }
        Ok(result)
    }

    pub fn trace_measurements(
        &self,
        request: [u8; 16],
        target_index: u16,
        access: &TraceReadAccessV1,
        now: u64,
        after: Option<(u64, u16)>,
    ) -> Result<Vec<TraceMeasurementV1>> {
        let after = after.unwrap_or_default();
        TraceErrorCodeV1::Invalid.require(
            after.0 <= 4096 && after.1 <= 4095,
            "trace measurement cursor is invalid",
        )?;
        let through = self
            .trace_state(request, Some(target_index), access, now)?
            .map_or(0, |revision| revision.last_sequence);
        let reader = self.live.index.reader()?;
        let mut query = reader
            .prepare(
                "SELECT measurement FROM trace_measurements
            WHERE tenant=?1 AND request=?2 AND target=?3 AND (sequence,ordinal)>(?4,?5) AND sequence<=?6
            ORDER BY sequence,ordinal LIMIT 200",
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "prepare trace measurement page",
            })?;
        let rows = query
            .query_map(
                params![
                    access.tenant_id,
                    request,
                    target_index,
                    after.0,
                    after.1,
                    through
                ],
                |row| row.get::<_, Vec<u8>>(0),
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "read trace measurement page",
            })?;
        rows.map(|row| {
            TraceOwner::decode(&row.context(DiscoveryDatabaseSnafu {
                operation: "read trace measurement row",
            })?)
        })
        .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn observability_projection_rebuild_preserves_cumulative_snapshots_and_read_grants(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let discovery = DiscoveryOwner::open(store.clone())?;
        let traces = TraceOwner::new(store.clone());
        let request = crate::observability::owner::tests::request()?;
        let access = crate::observability::owner::tests::access();
        traces.accept(
            request,
            crate::observability::owner::tests::grant()?,
            None,
            1,
        )?;
        let (_, accepted) = traces.read([1; 16], [6; 16], &access, 2)?;
        let execution_id = accepted.execution_id(0)?;
        let frames: Vec<_> = (1..=2)
            .map(|sequence| TraceFrameV1 {
                execution_id,
                sequence,
                kind: crate::TraceFrameKindV1::Data,
                bytes: br#"{"type":"map","data":{"@errors":{"257,-2":7}}}"#.to_vec(),
            })
            .collect();
        traces.append(
            [1; 16],
            [6; 16],
            0,
            "node-a",
            [2; 16],
            TraceBatchV1 {
                execution_id,
                frames: frames.clone(),
                terminal: None,
            },
        )?;
        assert!(discovery.trace_output([6; 16], 0, &access, 2, 0).is_err());
        while !discovery.project_revisions()? {}
        assert_eq!(discovery.trace_output([6; 16], 0, &access, 2, 0)?, frames);
        let measurements = discovery.trace_measurements([6; 16], 0, &access, 2, None)?;
        assert_eq!(measurements.len(), 2);
        assert!(measurements.iter().all(|row| row.count == 7
            && row.cumulative
            && !row.atomic_snapshot
            && row.execution_id == execution_id
            && row.syscall_id == Some(257)));
        drop(discovery);
        let discovery = DiscoveryOwner::rebuild_index(store)?;
        assert_eq!(discovery.trace_output([6; 16], 0, &access, 2, 0)?, frames);
        assert_eq!(
            discovery.trace_measurements([6; 16], 0, &access, 2, None)?,
            measurements
        );
        let mut revoked = access.clone();
        revoked.revoked = true;
        assert!(discovery.trace_state([6; 16], None, &revoked, 2).is_err());
        assert!(discovery.trace_output([6; 16], 0, &revoked, 2, 0).is_err());
        assert!(discovery
            .trace_measurements([6; 16], 0, &revoked, 2, None)
            .is_err());
        traces.cancel([1; 16], [6; 16], "operator", true)?;
        assert!(discovery.trace_output([6; 16], 0, &access, 2, 0).is_err());
        Ok(())
    }
}
