use super::*;
use crate::discovery::{context::ContextRevision, runtime::StreamCheckpoint};

#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRevisionPositionV1 {
    pub commit_index: u64,
    pub ordinal: u16,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "SCREAMING_SNAKE_CASE", deny_unknown_fields)]
pub enum DiscoveryRevisionKindV1 {
    Observation {
        stream: EvidenceIntakeIdentityV1,
        cursor: u64,
        cpu_id: Option<u32>,
        original_kernel_sequence: Option<u64>,
        payload_digest: DiscoveryDigestV1,
    },
    Coverage {
        stream: EvidenceIntakeIdentityV1,
        revision: u64,
        report_digest: DiscoveryDigestV1,
    },
    RetainedRangeExpired {
        stream: EvidenceIntakeIdentityV1,
        first: u64,
        last: u64,
    },
    Profile {
        content_digest: DiscoveryDigestV1,
        state: DiscoveryProfileStateV1,
        replaces: Option<DiscoveryHeadV1>,
    },
    Context {
        id: String,
        revision: u64,
        document_digest: DiscoveryDigestV1,
        trust: DiscoveryContextTrustV1,
    },
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRevisionEventV1 {
    pub id: DiscoveryDigestV1,
    pub position: DiscoveryRevisionPositionV1,
    pub origin: DiscoveryHeadV1,
    pub change: DiscoveryRevisionKindV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryRevisionPageV1 {
    pub complete_through: u64,
    pub events: Vec<DiscoveryRevisionEventV1>,
    pub next: Option<DiscoveryRevisionPositionV1>,
}

pub(super) enum RevisionPayload {
    Export(DiscoveryExportPageV1),
    Profile(DiscoveryProfileV1),
    Context(ContextRevision),
    Checkpoint(StreamCheckpoint),
}

impl RevisionPayload {
    pub(super) fn read(owner: &DiscoveryOwner, head: &DiscoveryHeadV1) -> Result<Self> {
        let live = owner.live()?;
        let artifact = live.store.read_discovery_artifact(&head.artifact)?;
        if rmp_serde::from_slice::<DiscoveryExportPageV1>(&artifact.payload).is_ok() {
            let page = live.index.export(head)?;
            page.prepare()?;
            if let Some(previous) = &page.previous {
                let prior = live.index.export(previous)?;
                DiscoveryInputManifestV1::require(
                    prior.stream == page.stream && prior.next_cursor()? == page.first_cursor,
                    "REVISION_EXPORT_GAP",
                )?;
            }
            return Ok(Self::Export(page));
        }
        if rmp_serde::from_slice::<DiscoveryProfileV1>(&artifact.payload).is_ok() {
            return Ok(Self::Profile(owner.profile(head)?));
        }
        if rmp_serde::from_slice::<ContextRevision>(&artifact.payload).is_ok() {
            return Ok(Self::Context(ContextRevision::read(&live.store, head)?));
        }
        if let Ok(checkpoint) = rmp_serde::from_slice::<StreamCheckpoint>(&artifact.payload) {
            DiscoveryInputManifestV1::require(
                checkpoint.schema_version == 1
                    && checkpoint.next_interval_cursor > 0
                    && checkpoint.stream.tenant_id == head.key.tenant_id
                    && StreamCheckpoint::key(&checkpoint.stream)? == head.key
                    && checkpoint.snapshot.key.tenant_id == head.key.tenant_id
                    && checkpoint.snapshot.commit_index < head.commit_index
                    && artifact.dependencies == vec![checkpoint.snapshot.artifact.clone()],
                "CHECKPOINT_INTEGRITY",
            )?;
            return Ok(Self::Checkpoint(checkpoint));
        }
        DiscoverySnafu {
            code: "REVISION_OWNER_UNSUPPORTED",
            reason: "a committed discovery head has an unknown payload",
        }
        .fail()
    }

    fn previous(&self) -> Option<&DiscoveryHeadV1> {
        match self {
            Self::Export(page) => page.previous.as_ref(),
            Self::Context(revision) => revision.previous.as_ref(),
            Self::Profile(_) | Self::Checkpoint(_) => None,
        }
    }

    fn events(&self, head: &DiscoveryHeadV1) -> Result<Vec<DiscoveryRevisionEventV1>> {
        let mut changes = Vec::new();
        match self {
            Self::Export(page) => {
                for (ordinal, record) in page.records.iter().enumerate() {
                    let wire =
                        EvidenceRecord::decode(record.wire_record.as_slice()).map_err(|error| {
                            DiscoverySnafu {
                                code: "REVISION_RECORD",
                                reason: error.to_string(),
                            }
                            .build()
                        })?;
                    let cursor =
                        page.first_cursor
                            .checked_add(ordinal as u64)
                            .ok_or_else(|| {
                                DiscoverySnafu {
                                    code: "REVISION_POSITION",
                                    reason: "the record cursor is exhausted",
                                }
                                .build()
                            })?;
                    changes.push((
                        ordinal as u16,
                        DiscoveryRevisionKindV1::Observation {
                            stream: page.stream.clone(),
                            cursor,
                            cpu_id: page
                                .cpu_binding
                                .filter(|binding| cursor >= binding.first_cursor)
                                .map(|binding| binding.cpu_id),
                            original_kernel_sequence: wire
                                .decision_context
                                .map(|context| context.original_kernel_sequence),
                            payload_digest: DiscoveryDigestV1::of(&record.wire_record)?,
                        },
                    ));
                }
                if let Some(bytes) = &page.coverage_record {
                    let report =
                        crate::CoverageReport::decode(bytes.as_slice()).map_err(|error| {
                            DiscoverySnafu {
                                code: "REVISION_COVERAGE",
                                reason: error.to_string(),
                            }
                            .build()
                        })?;
                    changes.push((
                        256,
                        DiscoveryRevisionKindV1::Coverage {
                            stream: page.stream.clone(),
                            revision: report.revision,
                            report_digest: DiscoveryDigestV1::of(bytes)?,
                        },
                    ));
                }
                if let Some(last) = page.expired_through {
                    changes.push((
                        257,
                        DiscoveryRevisionKindV1::RetainedRangeExpired {
                            stream: page.stream.clone(),
                            first: page.first_cursor,
                            last,
                        },
                    ));
                }
            }
            Self::Profile(profile) => changes.push((
                0,
                DiscoveryRevisionKindV1::Profile {
                    content_digest: profile.content_digest.clone(),
                    state: profile.state,
                    replaces: profile.replaces.clone(),
                },
            )),
            Self::Context(revision) => changes.push((
                0,
                DiscoveryRevisionKindV1::Context {
                    id: revision.document.id.clone(),
                    revision: revision.document.revision,
                    document_digest: DiscoveryDigestV1::of(&revision.document)?,
                    trust: revision.document.trust,
                },
            )),
            Self::Checkpoint(_) => {}
        }
        changes
            .into_iter()
            .map(|(ordinal, change)| {
                let id = match &change {
                    DiscoveryRevisionKindV1::Observation { stream, cursor, .. } => {
                        DiscoveryDigestV1::of(&("observation", stream, cursor))?
                    }
                    DiscoveryRevisionKindV1::Coverage {
                        stream, revision, ..
                    } => DiscoveryDigestV1::of(&("coverage", stream, revision))?,
                    _ => DiscoveryDigestV1::of(&(&head.key, head.revision, ordinal))?,
                };
                Ok(DiscoveryRevisionEventV1 {
                    id,
                    position: DiscoveryRevisionPositionV1 {
                        commit_index: head.commit_index,
                        ordinal,
                    },
                    origin: head.clone(),
                    change,
                })
            })
            .collect()
    }
}

impl DiscoveryOwner {
    pub fn project_revisions(&self) -> Result<bool> {
        let live = self.live()?;
        let _operation = live.operation.try_lock().map_err(|_| {
            DiscoverySnafu {
                code: "DISCOVERY_BUSY",
                reason: "another interval operation is active",
            }
            .build()
        })?;
        let (cutoff, heads) = live.store.discovery_catalog()?;
        let mut remaining = 32;
        for tip in heads {
            if live.index.revision_origin(&tip)? {
                continue;
            }
            let mut chain = Vec::new();
            let mut cursor = Some(tip.clone());
            while let Some(head) = cursor {
                if live.index.revision_origin(&head)? {
                    break;
                }
                DiscoveryInputManifestV1::require(chain.len() < 8192, "REVISION_CHAIN_LIMIT")?;
                cursor = RevisionPayload::read(self, &head)?.previous().cloned();
                chain.push(head);
            }
            for head in chain.into_iter().rev() {
                if remaining == 0 {
                    return Ok(false);
                }
                let payload = RevisionPayload::read(self, &head)?;
                match &payload {
                    RevisionPayload::Context(_) => {
                        live.index.replay_context(&tip)?;
                    }
                    RevisionPayload::Profile(_) => {
                        live.index.publish_snapshot(&head)?;
                    }
                    RevisionPayload::Checkpoint(checkpoint) => {
                        self.profile(&checkpoint.snapshot)?;
                    }
                    RevisionPayload::Export(_) => {}
                }
                live.index
                    .publish_revisions(&head, &payload.events(&head)?)?;
                remaining -= 1;
            }
        }
        live.index.publish_revision_prefix(cutoff)?;
        Ok(true)
    }

    pub fn read_revisions(
        &self,
        tenant: crate::EvidenceIdV1,
        after: Option<DiscoveryRevisionPositionV1>,
    ) -> Result<DiscoveryRevisionPageV1> {
        DiscoveryInputManifestV1::require(!tenant.is_zero(), "REVISION_TENANT")?;
        self.live()?.index.read_revisions(tenant, after)
    }
}

impl DiscoveryIndex {
    pub(in crate::discovery) fn require_export_reference(
        &self,
        head: &DiscoveryHeadV1,
    ) -> Result<()> {
        DiscoveryInputManifestV1::require(
            self.store.discovery_head(&head.key)?.as_ref() == Some(head)
                || self.revision_origin(head)?,
            "EXPORT_NOT_COMMITTED",
        )
    }
    pub(in crate::discovery) fn revision_origin(&self, head: &DiscoveryHeadV1) -> Result<bool> {
        let reader = self.reader()?;
        let stored: Option<Vec<u8>> = reader
            .query_row(
                "SELECT head FROM revision_origin WHERE tenant=?1 AND commit_index=?2",
                params![head.key.tenant_id, head.commit_index.to_be_bytes()],
                |row| row.get(0),
            )
            .optional()
            .context(DiscoveryDatabaseSnafu {
                operation: "check revision origin",
            })?;
        if let Some(bytes) = stored {
            DiscoveryInputManifestV1::require(
                Self::decode_context_head(&bytes)? == *head,
                "REVISION_ORIGIN_CONFLICT",
            )?;
            return Ok(true);
        }
        Ok(false)
    }

    fn publish_revisions(
        &self,
        head: &DiscoveryHeadV1,
        events: &[DiscoveryRevisionEventV1],
    ) -> Result<()> {
        let _admission = self.writes.try_acquire().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_WRITE_LIMIT",
                reason: "the writer and eight pending slots are in use",
            }
            .build()
        })?;
        let mut writer = self.writer.lock().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: "the writer is poisoned",
            }
            .build()
        })?;
        self.reserve_write(&writer)?;
        self.store
            .reserve_discovery_index_tenant(head.key.tenant_id)?;
        let transaction = writer.transaction().context(DiscoveryDatabaseSnafu {
            operation: "begin revision projection",
        })?;
        for event in events {
            let payload_digest = match &event.change {
                DiscoveryRevisionKindV1::Observation { payload_digest, .. } => {
                    payload_digest.clone()
                }
                _ => DiscoveryDigestV1::of(&event.change)?,
            };
            let bytes = rmp_serde::to_vec_named(event).map_err(|error| {
                DiscoverySnafu {
                    code: "REVISION_ENCODING",
                    reason: error.to_string(),
                }
                .build()
            })?;
            DiscoveryInputManifestV1::require(bytes.len() <= 8192, "REVISION_ROW_LIMIT")?;
            let known: Option<([u8;32], [u8;8], u16)> = transaction.query_row("SELECT payload_digest,commit_index,ordinal FROM revision_event WHERE tenant=?1 AND id=?2",
                params![head.key.tenant_id, event.id.0], |row| Ok((row.get(0)?,row.get(1)?,row.get(2)?))).optional().context(DiscoveryDatabaseSnafu { operation: "deduplicate revision" })?;
            if let Some((digest, commit, ordinal)) = known {
                DiscoveryInputManifestV1::require(
                    digest == payload_digest.0,
                    "REVISION_PAYLOAD_CONFLICT",
                )?;
                if (u64::from_be_bytes(commit), ordinal)
                    <= (event.position.commit_index, event.position.ordinal)
                {
                    continue;
                }
                let prefix: [u8; 8] = transaction
                    .query_row(
                        "SELECT commit_index FROM revision_prefix WHERE id=1",
                        [],
                        |row| row.get(0),
                    )
                    .context(DiscoveryDatabaseSnafu {
                        operation: "check published revision position",
                    })?;
                DiscoveryInputManifestV1::require(
                    event.position.commit_index > u64::from_be_bytes(prefix),
                    "REVISION_PUBLISHED_POSITION_CONFLICT",
                )?;
            }
            transaction.execute("INSERT INTO revision_event VALUES(?1,?2,?3,?4,?5,?6) ON CONFLICT(tenant,id) DO UPDATE SET commit_index=excluded.commit_index,ordinal=excluded.ordinal,event=excluded.event",
                params![head.key.tenant_id, event.id.0, event.position.commit_index.to_be_bytes(), event.position.ordinal, payload_digest.0, bytes])
                .context(DiscoveryDatabaseSnafu { operation: "insert revision event" })?;
        }
        transaction
            .execute(
                "INSERT INTO revision_origin VALUES(?1,?2,?3)",
                params![
                    head.key.tenant_id,
                    head.commit_index.to_be_bytes(),
                    Self::encode_context_head(head)?
                ],
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "commit revision origin",
            })?;
        transaction.commit().context(DiscoveryDatabaseSnafu {
            operation: "commit revision projection",
        })
    }

    fn publish_revision_prefix(&self, cutoff: u64) -> Result<()> {
        let writer = self.writer.lock().map_err(|_| {
            DiscoverySnafu {
                code: "INDEX_OWNER",
                reason: "the writer is poisoned",
            }
            .build()
        })?;
        self.reserve_write(&writer)?;
        writer
            .execute(
                "UPDATE revision_prefix SET commit_index=?1 WHERE id=1 AND commit_index<?1",
                [cutoff.to_be_bytes()],
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "publish complete revision prefix",
            })?;
        Ok(())
    }

    fn read_revisions(
        &self,
        tenant: crate::EvidenceIdV1,
        after: Option<DiscoveryRevisionPositionV1>,
    ) -> Result<DiscoveryRevisionPageV1> {
        let mut reader = self.reader()?;
        let transaction = reader.transaction().context(DiscoveryDatabaseSnafu {
            operation: "freeze revision prefix",
        })?;
        let prefix: [u8; 8] = transaction
            .query_row(
                "SELECT commit_index FROM revision_prefix WHERE id=1",
                [],
                |row| row.get(0),
            )
            .context(DiscoveryDatabaseSnafu {
                operation: "read revision prefix",
            })?;
        let cutoff = u64::from_be_bytes(prefix);
        let after = after.unwrap_or_default();
        DiscoveryInputManifestV1::require(
            after.commit_index <= cutoff,
            "REVISION_INDEX_BEHIND_CURSOR",
        )?;
        let mut query = transaction.prepare("SELECT event,id,commit_index,ordinal FROM revision_event WHERE tenant=?1 AND (commit_index,ordinal)>(?2,?3) AND commit_index<=?4 ORDER BY commit_index,ordinal LIMIT 201")
            .context(DiscoveryDatabaseSnafu { operation: "prepare revision page" })?;
        let mut rows = query
            .query(params![
                tenant.to_be_bytes(),
                after.commit_index.to_be_bytes(),
                after.ordinal,
                prefix
            ])
            .context(DiscoveryDatabaseSnafu {
                operation: "read revision page",
            })?;
        let mut page = DiscoveryRevisionPageV1 {
            complete_through: cutoff,
            events: Vec::new(),
            next: None,
        };
        let mut budget = InputByteLimit(1024 * 1024 - 256);
        while let Some(row) = rows.next().context(DiscoveryDatabaseSnafu {
            operation: "read revision row",
        })? {
            if page.events.len() == 200 {
                page.next = page.events.last().map(|event| event.position);
                break;
            }
            let bytes: Vec<u8> = row.get(0).context(DiscoveryDatabaseSnafu {
                operation: "decode revision row",
            })?;
            DiscoveryInputManifestV1::require(bytes.len() <= 8192, "REVISION_ROW_LIMIT")?;
            let event: DiscoveryRevisionEventV1 =
                rmp_serde::from_slice(&bytes).map_err(|error| {
                    DiscoverySnafu {
                        code: "REVISION_ENCODING",
                        reason: error.to_string(),
                    }
                    .build()
                })?;
            let indexed_id: [u8; 32] = row.get(1).context(DiscoveryDatabaseSnafu {
                operation: "read revision identity",
            })?;
            let indexed_commit: [u8; 8] = row.get(2).context(DiscoveryDatabaseSnafu {
                operation: "read revision commit",
            })?;
            let indexed_ordinal: u16 = row.get(3).context(DiscoveryDatabaseSnafu {
                operation: "read revision ordinal",
            })?;
            DiscoveryInputManifestV1::require(
                event.origin.key.tenant_id == tenant.to_be_bytes()
                    && event.id.0 == indexed_id
                    && event.position.commit_index == u64::from_be_bytes(indexed_commit)
                    && event.position.ordinal == indexed_ordinal
                    && event.origin.commit_index == event.position.commit_index
                    && event.position.commit_index <= cutoff
                    && event.position > after
                    && page
                        .events
                        .last()
                        .is_none_or(|previous| previous.position < event.position),
                "REVISION_POSITION",
            )?;
            if serde_json::to_writer(&mut budget, &event).is_err() || budget.0 == 0 {
                DiscoveryInputManifestV1::require(!page.events.is_empty(), "REVISION_ROW_LIMIT")?;
                page.next = page.events.last().map(|event| event.position);
                break;
            }
            budget.0 -= 1;
            page.events.push(event);
        }
        Ok(page)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn discovery_index_revision_rejects_gaps_and_changed_native_positions(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let owner = DiscoveryOwner::open(store.clone())?;
        let mut page = super::super::tests::resolved_page()?;
        let tenant = page.stream.tenant_id;
        let key = crate::DiscoveryHeadKeyV1 {
            tenant_id: tenant,
            id: DiscoveryDigestV1::of(&"revision gap")?,
        };
        let head = store.commit_discovery_head(
            key.clone(),
            None,
            store.put_discovery_artifact(&page.artifact()?)?,
        )?;
        assert!(owner.project_revisions()?);
        let before = owner.read_revisions(tenant.into(), None)?;
        let mut changed = before.events[0].clone();
        changed.position.commit_index = 0;
        assert!(owner
            .live()?
            .index
            .publish_revisions(&head, &[changed.clone()])
            .is_err());
        assert_eq!(owner.read_revisions(tenant.into(), None)?, before);
        changed = before.events[0].clone();
        changed.origin.commit_index += 1;
        {
            let writer = owner
                .live()?
                .index
                .writer
                .lock()
                .map_err(|_| "writer poisoned")?;
            writer.execute(
                "UPDATE revision_event SET event=?1 WHERE tenant=?2 AND id=?3",
                params![rmp_serde::to_vec_named(&changed)?, tenant, changed.id.0],
            )?;
        }
        assert!(owner.read_revisions(tenant.into(), None).is_err());
        {
            let writer = owner
                .live()?
                .index
                .writer
                .lock()
                .map_err(|_| "writer poisoned")?;
            writer.execute(
                "UPDATE revision_event SET event=?1 WHERE tenant=?2 AND id=?3",
                params![
                    rmp_serde::to_vec_named(&before.events[0])?,
                    tenant,
                    changed.id.0
                ],
            )?;
        }
        page.previous = Some(head.clone());
        page.first_cursor = 5;
        for (ordinal, record) in page.records.iter_mut().enumerate() {
            if let DiscoveryContextJoinV1::Available(pin) = &mut record.context {
                pin.binding.record_id.durable_cursor = 5 + ordinal as u64;
            }
        }
        store.commit_discovery_head(
            key,
            Some(&head),
            store.put_discovery_artifact(&page.artifact()?)?,
        )?;
        assert!(owner.project_revisions().is_err());
        assert_eq!(owner.read_revisions(tenant.into(), None)?, before);
        Ok(())
    }

    #[test]
    fn discovery_index_revision_prefix_pages_and_rebuild_preserve_positions(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let owner = DiscoveryOwner::open(store.clone())?;
        let mut page = super::super::tests::resolved_page()?;
        let tenant: crate::EvidenceIdV1 = page.stream.tenant_id.into();
        let key = crate::DiscoveryHeadKeyV1 {
            tenant_id: page.stream.tenant_id,
            id: DiscoveryDigestV1::of(&"feed test")?,
        };
        let mut tip = None;
        let mut first = None;
        for _ in 0..84 {
            page.previous = tip.clone();
            let artifact = store.put_discovery_artifact(&page.artifact()?)?;
            let head = store.commit_discovery_head(key.clone(), tip.as_ref(), artifact)?;
            if first.is_none() {
                first = Some(head.clone());
            }
            tip = Some(head);
            page.first_cursor += 3;
            for record in &mut page.records {
                if let DiscoveryContextJoinV1::Available(pin) = &mut record.context {
                    pin.binding.record_id.durable_cursor += 3;
                }
            }
        }
        assert!(owner.read_revisions(tenant, None)?.events.is_empty());
        assert!(!owner.project_revisions()?);
        assert_eq!(owner.read_revisions(tenant, None)?.complete_through, 0);
        while !owner.project_revisions()? {}
        let first = first.ok_or("first absent")?;
        owner.live()?.index.require_export_reference(&first)?;
        let first_page = owner.read_revisions(tenant, None)?;
        assert_eq!(first_page.events.len(), 200);
        assert_eq!(first_page.events[0].origin, first);
        assert_eq!(first_page.events[0].position.ordinal, 0);
        let second_page = owner.read_revisions(tenant, first_page.next)?;
        assert_eq!(second_page.events.len(), 52);
        assert!(second_page.next.is_none());
        assert!(owner
            .read_revisions(crate::EvidenceIdV1::new(9, 9), None)?
            .events
            .is_empty());
        assert!(owner.project_revisions()?);
        assert_eq!(owner.read_revisions(tenant, None)?, first_page);
        drop(owner);
        drop(store);
        std::fs::remove_file(directory.path().join("discovery-index.sqlite"))?;
        let store = ControlStore::open(directory.path())?;
        let owner = DiscoveryOwner::open(store.clone())?;
        assert!(owner.read_revisions(tenant, first_page.next).is_err());
        while !owner.project_revisions()? {}
        assert_eq!(owner.read_revisions(tenant, None)?, first_page);
        assert_eq!(owner.read_revisions(tenant, first_page.next)?, second_page);
        let unknown_key = crate::DiscoveryHeadKeyV1 {
            tenant_id: tenant.to_be_bytes(),
            id: DiscoveryDigestV1::of(&"unsupported owner")?,
        };
        let artifact = store.put_discovery_artifact(&DiscoveryArtifactV1 {
            schema_version: 1,
            tenant_id: tenant.to_be_bytes(),
            dependencies: Vec::new(),
            payload: vec![1, 2, 3],
        })?;
        store.commit_discovery_head(unknown_key, None, artifact)?;
        assert!(owner.project_revisions().is_err());
        assert_eq!(owner.read_revisions(tenant, None)?, first_page);
        Ok(())
    }
}
