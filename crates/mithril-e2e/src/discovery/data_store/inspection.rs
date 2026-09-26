use std::io::Read as _;

use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

use super::*;

const MAX_INSPECT_SOURCES: usize = 1024;
const MAX_INSPECT_BYTES: u64 = 256 * 1024 * 1024;

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct StoreProof {
    schema_version: u32,
    tenant_id: [u8; 16],
    store_uuid: [u8; 16],
    recovery_epoch: u64,
    commit_revision: u64,
    database_bytes: u64,
    wal_bytes: u64,
    file_bytes: u64,
    allocated_bytes: u64,
    sources: Vec<SourceProof>,
}

#[derive(Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
struct SourceProof {
    identity: EvidenceIntakeIdentityV1,
    cpu_id: u32,
    first_cursor: u64,
    last_cursor: u64,
    record_count: u64,
    frame_bytes: u64,
    frames_sha256: [u8; 32],
}

impl SourceProof {
    fn read(
        data: &AnalysisStore,
        identity: EvidenceIntakeIdentityV1,
        first_cursor: u64,
        last_cursor: u64,
        read_bytes: &mut u64,
    ) -> Result<Self> {
        let receipt = data.source_receipt(&identity)?.ok_or("source absent")?;
        if first_cursor == 0
            || last_cursor < first_cursor - 1
            || first_cursor <= receipt.retained_floor
            || last_cursor > receipt.contiguous_cursor
            || last_cursor - (first_cursor - 1) > 1_000_000
        {
            return Err(
                "the inspected range is expired, invalid, or exceeds one million records".into(),
            );
        }
        let mut proof = Self {
            identity,
            cpu_id: receipt.cpu_id,
            first_cursor,
            last_cursor,
            record_count: 0,
            frame_bytes: 0,
            frames_sha256: [0; 32],
        };
        let mut cursor = first_cursor;
        let mut digest = Sha256::new();
        while cursor <= last_cursor {
            let page = data.read_page(&proof.identity, cursor)?;
            if page.records.is_empty() {
                return Err("the inspected range has no retained page".into());
            }
            *read_bytes += page.encoded_bytes as u64;
            if *read_bytes > MAX_INSPECT_BYTES {
                return Err("inspection exceeds 256 MiB of framed records".into());
            }
            for record in page
                .records
                .into_iter()
                .take_while(|record| record.cursor <= last_cursor)
            {
                if record.cursor != cursor {
                    return Err("the inspected range has a missing cursor".into());
                }
                digest.update(&record.framed_record);
                proof.frame_bytes += record.framed_record.len() as u64;
                proof.record_count += 1;
                cursor = cursor.checked_add(1).ok_or("inspection cursor exhausted")?;
            }
        }
        proof.frames_sha256 = digest.finalize().into();
        Ok(proof)
    }
}

impl DataStoreQualification {
    pub fn inspect(&self, root: &Path, tenant_id: [u8; 16], baseline: Option<&Path>) -> Result<()> {
        self.check(
            !self.output.exists(),
            "the inspection output already exists",
        )?;
        self.check(
            fs::symlink_metadata(root.join("analysis.duckdb"))?
                .file_type()
                .is_file(),
            "inspection requires an existing data file",
        )?;
        let data = AnalysisStore::open(root)?;
        let meta = data.meta()?;
        let mut read_bytes = 0;
        if let Some(path) = baseline {
            let mut bytes = Vec::new();
            fs::File::open(path)?
                .take(1024 * 1024 + 1)
                .read_to_end(&mut bytes)?;
            self.check(
                bytes.len() <= 1024 * 1024,
                "the inspection baseline exceeds one MiB",
            )?;
            let prior: StoreProof = serde_json::from_slice(&bytes)?;
            self.check(
                prior.schema_version == 1
                    && prior.tenant_id == tenant_id
                    && prior.store_uuid == *meta.store_uuid.as_bytes()
                    && prior.recovery_epoch == meta.recovery_epoch
                    && prior.commit_revision <= meta.commit_revision
                    && !prior.sources.is_empty()
                    && prior.sources.len() <= MAX_INSPECT_SOURCES,
                "the inspection baseline has a different store, epoch, tenant, or bound",
            )?;
            let mut seen = std::collections::BTreeSet::new();
            for expected in prior.sources {
                self.check(
                    expected.identity.tenant_id == tenant_id
                        && seen.insert(expected.identity.clone()),
                    "the inspection baseline has a foreign or duplicate source",
                )?;
                let actual = SourceProof::read(
                    &data,
                    expected.identity.clone(),
                    expected.first_cursor,
                    expected.last_cursor,
                    &mut read_bytes,
                )?;
                self.check(actual == expected, "a retained evidence prefix changed")?;
            }
        }
        let usage = data.storage_usage()?;
        let mut proof = StoreProof {
            schema_version: 1,
            tenant_id,
            store_uuid: *meta.store_uuid.as_bytes(),
            recovery_epoch: meta.recovery_epoch,
            commit_revision: meta.commit_revision,
            database_bytes: Self::file_size(&root.join("analysis.duckdb"))?,
            wal_bytes: Self::file_size(&root.join("analysis.duckdb.wal"))?,
            file_bytes: usage.file_bytes,
            allocated_bytes: usage.allocated_bytes,
            sources: Vec::new(),
        };
        loop {
            let page = data.source_page(
                tenant_id,
                proof.sources.last().map(|source| &source.identity),
            )?;
            if page.is_empty() {
                break;
            }
            self.check(
                proof.sources.len() + page.len() <= MAX_INSPECT_SOURCES,
                "inspection exceeds 1024 sources",
            )?;
            for identity in page {
                let receipt = data.source_receipt(&identity)?.ok_or("source absent")?;
                proof.sources.push(SourceProof::read(
                    &data,
                    identity,
                    receipt
                        .retained_floor
                        .checked_add(1)
                        .ok_or("retained floor exhausted")?,
                    receipt.contiguous_cursor,
                    &mut read_bytes,
                )?);
            }
        }
        self.check(
            proof.sources.iter().any(|source| source.record_count > 0),
            "inspection found no retained evidence",
        )?;
        self.check(data.meta()? == meta, "inspection changed data metadata")?;
        drop(data);
        self.check(
            serde_json::to_vec_pretty(&proof)?.len() <= 1024 * 1024,
            "the inspection proof exceeds one MiB",
        )?;
        fs::create_dir(&self.output)?;
        super::super::write_json(&self.output.join("result.json"), &proof)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn data_inspection_recovery() -> Result<()> {
        let tls = MtlsFixture::new(false)?;
        let root = tls.path().join("evidence/analysis");
        let tenant = EvidenceIdV1::new(1, 2).to_be_bytes();
        let case = DataStoreQualification::new(tls.path().join("baseline"));
        let parts = tls.configuration()?.into_parts()?;
        let data = parts.control.analysis_store().ok_or("data owner absent")?;
        let server = tls.start(parts.control).await?;
        assert!(case.inspect(&root, tenant, None).is_err());
        assert!(!case.output.exists());
        let observations = EffectObservationStore::durable(
            8,
            tls.path().join("wal"),
            EvidenceWalLimits::default(),
            ObservationCanonicalizer::new(
                EvidenceIdV1::new(1, 2),
                EvidenceIdV1::new(3, 4),
                1,
                [7; 16].into(),
            )?,
        )?;
        for cursor in 1..=300 {
            DataStoreQualification::record(&observations, cursor);
        }
        let batch = observations.next_evidence_batch().ok_or("batch absent")?;
        let wire: mithril_control::EvidenceBatch = batch.clone().into();
        let mut connection = case.connect(&tls, &server).await?;
        connection.send_evidence_batch(batch).await?;
        let ack = DataStoreQualification::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, 300);
        observations.acknowledge_evidence(ack)?;
        drop(connection);
        server.shutdown().await?;
        drop(data);
        drop(DataStoreQualification::reopen_data(&root).await?);
        drop(reopen_control_store(&tls.path().join("control-store")).await?);

        case.inspect(&root, tenant, None)?;
        let baseline = case.output.join("result.json");
        let bytes = fs::read(&baseline)?;
        let mut proof: StoreProof = serde_json::from_slice(&bytes)?;
        assert_eq!(proof.sources.len(), 1);
        assert_eq!(proof.sources[0].record_count, 300);
        assert_eq!(proof.sources[0].first_cursor, 1);
        assert_eq!(proof.sources[0].last_cursor, 300);
        assert!(proof.database_bytes > 0);
        assert!(proof.file_bytes >= proof.database_bytes + proof.wal_bytes);
        assert_eq!(
            proof.sources[0].frames_sha256,
            <[u8; 32]>::from(Sha256::digest(&wire.framed_records))
        );
        assert!(case.inspect(&root, tenant, None).is_err());
        assert_eq!(fs::read(&baseline)?, bytes);
        let refused = DataStoreQualification::new(tls.path().join("refused"));
        assert!(refused.inspect(&root, [9; 16], None).is_err());
        assert!(refused
            .inspect(&tls.path().join("absent"), tenant, None)
            .is_err());
        assert!(!tls.path().join("absent").exists());
        let invalid = tls.path().join("invalid.json");
        proof.sources[0].frames_sha256 = [0; 32];
        fs::write(&invalid, serde_json::to_vec(&proof)?)?;
        assert!(refused.inspect(&root, tenant, Some(&invalid)).is_err());
        proof = serde_json::from_slice(&bytes)?;
        proof.sources[0].identity.tenant_id = [9; 16];
        fs::write(&invalid, serde_json::to_vec(&proof)?)?;
        assert!(refused.inspect(&root, tenant, Some(&invalid)).is_err());
        proof = serde_json::from_slice(&bytes)?;
        proof.store_uuid = [0; 16];
        fs::write(&invalid, serde_json::to_vec(&proof)?)?;
        assert!(refused.inspect(&root, tenant, Some(&invalid)).is_err());
        fs::write(&invalid, vec![b' '; 1024 * 1024 + 1])?;
        assert!(refused.inspect(&root, tenant, Some(&invalid)).is_err());
        assert!(!refused.output.exists());

        let parts = tls.configuration()?.into_parts()?;
        let data = parts.control.analysis_store().ok_or("data owner absent")?;
        let server = tls.start(parts.control).await?;
        let mut connection = case.connect(&tls, &server).await?;
        DataStoreQualification::record(&observations, 301);
        connection
            .send_evidence_batch(observations.next_evidence_batch().ok_or("batch absent")?)
            .await?;
        let ack = DataStoreQualification::ack(&mut connection).await?;
        assert_eq!(ack.contiguous_cursor, 301);
        observations.acknowledge_evidence(ack)?;
        drop(connection);
        server.shutdown().await?;
        drop(data);
        drop(DataStoreQualification::reopen_data(&root).await?);
        let recovered = DataStoreQualification::new(tls.path().join("recovered"));
        recovered.inspect(&root, tenant, Some(&baseline))?;
        let current: StoreProof =
            serde_json::from_slice(&fs::read(recovered.output.join("result.json"))?)?;
        assert_eq!(current.sources[0].record_count, 301);
        assert_eq!(current.sources[0].last_cursor, 301);
        let store = AnalysisStore::open(&root)?;
        let mut read_bytes = MAX_INSPECT_BYTES;
        assert!(SourceProof::read(
            &store,
            current.sources[0].identity.clone(),
            1,
            301,
            &mut read_bytes
        )
        .is_err());
        assert!(
            EvidenceRetentionOwner::new(&store, store.retention_limits())?
                .retain(&current.sources[0].identity, u64::MAX)?
                .removed_records
                > 0
        );
        let before = store.meta()?;
        drop(store);
        assert!(refused.inspect(&root, tenant, Some(&baseline)).is_err());
        assert!(!refused.output.exists());
        assert_eq!(AnalysisStore::open(&root)?.meta()?, before);
        Ok(())
    }
}
