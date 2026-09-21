use std::io::Read as _;
use std::os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _};

use super::*;
use crate::{error::DiscoverySnafu, DiscoveryDigestV1};

pub const MAX_DISCOVERY_SEGMENT_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_DISCOVERY_HEADS: usize = 4096;
pub const MAX_DISCOVERY_TENANT_HEADS: usize = 1024;
pub const MAX_DISCOVERY_HEAD_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_DISCOVERY_ARTIFACT_BYTES: u64 = 8 * 1024 * 1024 * 1024;
pub const MAX_DISCOVERY_TENANT_ARTIFACT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub(crate) const MAX_DISCOVERY_ACTIVE_INDEX_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_ARTIFACT_DEPENDENCIES: usize = 8192;
const MAX_ARTIFACT_FILES: usize = 131_072;

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryHeadKeyV1 {
    pub tenant_id: [u8; 16],
    pub id: DiscoveryDigestV1,
}

#[derive(Clone, Debug, Deserialize, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryArtifactRefV1 {
    pub tenant_id: [u8; 16],
    pub sha256: [u8; 32],
    pub bytes: u64,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryHeadV1 {
    pub key: DiscoveryHeadKeyV1,
    pub revision: u64,
    pub commit_index: u64,
    pub artifact: DiscoveryArtifactRefV1,
}

#[derive(Clone, Debug, Deserialize, Eq, PartialEq, Serialize)]
#[serde(deny_unknown_fields)]
pub struct DiscoveryArtifactV1 {
    pub schema_version: u32,
    pub tenant_id: [u8; 16],
    pub dependencies: Vec<DiscoveryArtifactRefV1>,
    pub payload: Vec<u8>,
}

impl DiscoveryArtifactV1 {
    fn validate(&self) -> Result<()> {
        if self.schema_version != 1
            || self.tenant_id == [0; 16]
            || self.payload.len() > MAX_DISCOVERY_SEGMENT_BYTES
            || self.dependencies.len() > MAX_ARTIFACT_DEPENDENCIES
            || self.dependencies.iter().any(|reference| {
                reference.tenant_id != self.tenant_id
                    || reference.bytes == 0
                    || reference.bytes > MAX_DISCOVERY_SEGMENT_BYTES as u64
            })
            || self.dependencies.windows(2).any(|pair| pair[0] >= pair[1])
        {
            return DiscoverySnafu {
                code: "ARTIFACT_SCHEMA",
                reason: "discovery artifact identity, order, or limits are invalid",
            }
            .fail();
        }
        Ok(())
    }
}

pub(super) struct DiscoveryFiles {
    root: PathBuf,
    usage: Option<BTreeMap<[u8; 16], u64>>,
    file_count: usize,
}

impl DiscoveryFiles {
    fn index_reserve(&self) -> Result<u64> {
        let root = self.root.parent().ok_or_else(|| {
            DiscoverySnafu {
                code: "ARTIFACT_PATH",
                reason: "the discovery store has no parent",
            }
            .build()
        })?;
        // ponytail: charge the full shared index bound per tenant; add page attribution if this restricts capacity.
        for name in [
            "discovery-index.sqlite",
            "discovery-index.rebuild.sqlite",
            "discovery-index.previous.sqlite",
        ] {
            let path = root.join(name);
            if path.try_exists().context(IoSnafu { path })? {
                return Ok(MAX_DISCOVERY_ACTIVE_INDEX_BYTES);
            }
        }
        Ok(0)
    }

    pub(super) fn new(root: &Path) -> Self {
        Self {
            root: root.join("discovery"),
            usage: None,
            file_count: 0,
        }
    }

    fn directory(&self, tenant: &[u8; 16]) -> PathBuf {
        self.root.join(hex::encode(tenant))
    }

    fn path(&self, reference: &DiscoveryArtifactRefV1) -> PathBuf {
        self.directory(&reference.tenant_id)
            .join(format!("{}.bin", hex::encode(reference.sha256)))
    }

    fn create_directory(path: &Path) -> Result<()> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_dir() => return Ok(()),
            Ok(_) => {
                return DiscoverySnafu {
                    code: "ARTIFACT_PATH",
                    reason: "discovery requires a real directory",
                }
                .fail()
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(source) => return Err(source).context(IoSnafu { path }),
        }
        fs::DirBuilder::new()
            .mode(0o700)
            .create(path)
            .context(IoSnafu { path })?;
        if let Some(parent) = path.parent() {
            File::open(parent)
                .and_then(|directory| directory.sync_all())
                .context(IoSnafu { path: parent })?;
        }
        Ok(())
    }

    fn measure(&mut self) -> Result<()> {
        Self::create_directory(&self.root)?;
        let mut usage = BTreeMap::<[u8; 16], u64>::new();
        let mut file_count = 0;
        for entry in fs::read_dir(&self.root).context(IoSnafu { path: &self.root })? {
            let entry = entry.context(IoSnafu { path: &self.root })?;
            let name = entry.file_name();
            let tenant = name
                .to_str()
                .and_then(|name| hex::decode(name).ok())
                .and_then(|bytes| <[u8; 16]>::try_from(bytes).ok());
            let Some(tenant) = tenant.filter(|tenant| {
                Some(hex::encode(tenant).as_str()) == name.to_str() && *tenant != [0; 16]
            }) else {
                return DiscoverySnafu {
                    code: "ARTIFACT_PATH",
                    reason: "discovery contains an unknown tenant directory",
                }
                .fail();
            };
            let directory = entry.path();
            if !entry
                .file_type()
                .context(IoSnafu { path: &directory })?
                .is_dir()
            {
                return DiscoverySnafu {
                    code: "ARTIFACT_PATH",
                    reason: "discovery tenant path is not a directory",
                }
                .fail();
            }
            let mut bytes = 0_u64;
            for file in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
                file_count += 1;
                if file_count > MAX_ARTIFACT_FILES {
                    return DiscoverySnafu {
                        code: "ARTIFACT_LIMIT",
                        reason: "discovery file count exceeds its bound",
                    }
                    .fail();
                }
                let file = file.context(IoSnafu { path: &directory })?;
                if !file
                    .file_type()
                    .context(IoSnafu { path: file.path() })?
                    .is_file()
                {
                    return DiscoverySnafu {
                        code: "ARTIFACT_PATH",
                        reason: "discovery contains a non-file artifact",
                    }
                    .fail();
                }
                bytes = bytes
                    .checked_add(
                        file.metadata()
                            .context(IoSnafu { path: file.path() })?
                            .len(),
                    )
                    .ok_or_else(|| {
                        DiscoverySnafu {
                            code: "ARTIFACT_QUOTA",
                            reason: "discovery byte accounting overflowed",
                        }
                        .build()
                    })?;
            }
            usage.insert(tenant, bytes);
            if usage.len() > MAX_ARTIFACT_FILES {
                return DiscoverySnafu {
                    code: "ARTIFACT_LIMIT",
                    reason: "discovery directory count exceeds its bound",
                }
                .fail();
            }
        }
        self.file_count = file_count;
        self.usage = Some(usage);
        Ok(())
    }

    fn read(&self, reference: &DiscoveryArtifactRefV1) -> Result<DiscoveryArtifactV1> {
        if reference.tenant_id == [0; 16]
            || reference.bytes == 0
            || reference.bytes > MAX_DISCOVERY_SEGMENT_BYTES as u64
        {
            return DiscoverySnafu {
                code: "ARTIFACT_REFERENCE",
                reason: "discovery artifact reference is invalid",
            }
            .fail();
        }
        let path = self.path(reference);
        let mut file = OpenOptions::new()
            .read(true)
            .custom_flags(rustix::fs::OFlags::NOFOLLOW.bits() as i32)
            .open(&path)
            .context(IoSnafu { path: &path })?;
        let metadata = file.metadata().context(IoSnafu { path: &path })?;
        if !metadata.is_file() || metadata.len() != reference.bytes {
            return DiscoverySnafu {
                code: "ARTIFACT_INTEGRITY",
                reason: "discovery artifact size differs",
            }
            .fail();
        }
        let mut bytes = vec![0; reference.bytes as usize];
        file.read_exact(&mut bytes)
            .context(IoSnafu { path: &path })?;
        if Sha256::digest(&bytes).as_slice() != reference.sha256 {
            return DiscoverySnafu {
                code: "ARTIFACT_INTEGRITY",
                reason: "discovery artifact checksum differs",
            }
            .fail();
        }
        let artifact: DiscoveryArtifactV1 = rmp_serde::from_slice(&bytes).map_err(|error| {
            DiscoverySnafu {
                code: "ARTIFACT_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })?;
        artifact.validate()?;
        if artifact.tenant_id != reference.tenant_id {
            return DiscoverySnafu {
                code: "ARTIFACT_TENANT",
                reason: "discovery artifact tenant differs",
            }
            .fail();
        }
        Ok(artifact)
    }

    fn write(&mut self, artifact: &DiscoveryArtifactV1) -> Result<DiscoveryArtifactRefV1> {
        artifact.validate()?;
        let bytes = rmp_serde::to_vec_named(artifact).map_err(|error| {
            DiscoverySnafu {
                code: "ARTIFACT_SCHEMA",
                reason: error.to_string(),
            }
            .build()
        })?;
        if bytes.len() > MAX_DISCOVERY_SEGMENT_BYTES {
            return DiscoverySnafu {
                code: "ARTIFACT_LIMIT",
                reason: "encoded discovery artifact exceeds 16 MiB",
            }
            .fail();
        }
        let reference = DiscoveryArtifactRefV1 {
            tenant_id: artifact.tenant_id,
            sha256: Sha256::digest(&bytes).into(),
            bytes: bytes.len() as u64,
        };
        if self.usage.is_none() {
            self.measure()?;
        }
        let directory = self.directory(&artifact.tenant_id);
        Self::create_directory(&directory)?;
        let path = self.path(&reference);
        if path.try_exists().context(IoSnafu { path: &path })? {
            self.read(&reference)?;
            File::open(&directory)
                .and_then(|directory| directory.sync_all())
                .context(IoSnafu { path: &directory })?;
            return Ok(reference);
        }
        for dependency in &artifact.dependencies {
            self.read(dependency)?;
        }
        let usage = self.usage.as_ref().ok_or_else(|| {
            DiscoverySnafu {
                code: "ARTIFACT_OWNER",
                reason: "artifact usage is not measured",
            }
            .build()
        })?;
        let total = usage
            .values()
            .try_fold(0_u64, |sum, value| sum.checked_add(*value))
            .unwrap_or(u64::MAX);
        let index_reserve = self.index_reserve()?;
        if self.file_count >= MAX_ARTIFACT_FILES
            || usage
                .get(&artifact.tenant_id)
                .copied()
                .unwrap_or(0)
                .saturating_add(reference.bytes)
                .saturating_add(index_reserve)
                > MAX_DISCOVERY_TENANT_ARTIFACT_BYTES
            || total.saturating_add(reference.bytes) > MAX_DISCOVERY_ARTIFACT_BYTES
        {
            return DiscoverySnafu {
                code: "ARTIFACT_QUOTA",
                reason: "discovery artifact quota is exhausted",
            }
            .fail();
        }
        let temporary = directory.join(format!("{}.tmp", uuid::Uuid::new_v4()));
        let result = (|| {
            let mut file = OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&temporary)
                .context(IoSnafu { path: &temporary })?;
            file.write_all(&bytes)
                .context(IoSnafu { path: &temporary })?;
            file.sync_all().context(IoSnafu { path: &temporary })?;
            fs::hard_link(&temporary, &path).context(IoSnafu { path: &path })?;
            fs::remove_file(&temporary).context(IoSnafu { path: &temporary })?;
            File::open(&directory)
                .and_then(|directory| directory.sync_all())
                .context(IoSnafu { path: &directory })?;
            Ok(())
        })();
        if let Err(error) = result {
            self.usage = None;
            return Err(error);
        }
        *self
            .usage
            .as_mut()
            .ok_or_else(|| {
                DiscoverySnafu {
                    code: "ARTIFACT_OWNER",
                    reason: "artifact usage was lost during write",
                }
                .build()
            })?
            .entry(artifact.tenant_id)
            .or_default() += reference.bytes;
        self.file_count += 1;
        Ok(reference)
    }

    pub(super) fn apply_head(
        state: &mut ControlStoreState,
        head: &DiscoveryHeadV1,
        expected: Option<&DiscoveryHeadV1>,
    ) -> Result<()> {
        if head.key.tenant_id == [0; 16]
            || head.artifact.tenant_id != head.key.tenant_id
            || head.artifact.bytes == 0
            || head.artifact.bytes > MAX_DISCOVERY_SEGMENT_BYTES as u64
            || head.revision
                != expected
                    .map_or(Some(1), |head| head.revision.checked_add(1))
                    .unwrap_or(0)
            || head.revision == 0
            || state.discovery_heads.get(&head.key) != expected
            || head.commit_index != state.commit_index.checked_add(1).unwrap_or(0)
        {
            return DiscoverySnafu {
                code: "HEAD_CONFLICT",
                reason: "discovery head identity or expected revision differs",
            }
            .fail();
        }
        state.discovery_heads.insert(head.key.clone(), head.clone());
        if state.discovery_heads.len() > MAX_DISCOVERY_HEADS
            || state
                .discovery_heads
                .keys()
                .filter(|key| key.tenant_id == head.key.tenant_id)
                .count()
                > MAX_DISCOVERY_TENANT_HEADS
        {
            return DiscoverySnafu {
                code: "HEAD_LIMIT",
                reason: "discovery head count is exhausted",
            }
            .fail();
        }
        let bytes = rmp_serde::to_vec_named(&state.discovery_heads).map_err(|error| {
            DiscoverySnafu {
                code: "HEAD_ENCODING",
                reason: error.to_string(),
            }
            .build()
        })?;
        if bytes.len() > MAX_DISCOVERY_HEAD_BYTES {
            return DiscoverySnafu {
                code: "HEAD_LIMIT",
                reason: "discovery head bytes are exhausted",
            }
            .fail();
        }
        Ok(())
    }
}

impl ControlStore {
    pub(crate) fn reserve_discovery_index_tenant(&self, tenant: [u8; 16]) -> Result<()> {
        let mut files = self.discovery_files.lock().map_err(|_| {
            DiscoverySnafu {
                code: "ARTIFACT_OWNER",
                reason: "discovery file owner is poisoned",
            }
            .build()
        })?;
        if files.usage.is_none() {
            files.measure()?;
        }
        let bytes = files
            .usage
            .as_ref()
            .and_then(|usage| usage.get(&tenant))
            .copied()
            .unwrap_or(0);
        if bytes.saturating_add(MAX_DISCOVERY_ACTIVE_INDEX_BYTES)
            > MAX_DISCOVERY_TENANT_ARTIFACT_BYTES
        {
            return DiscoverySnafu {
                code: "INDEX_TENANT_QUOTA",
                reason: "artifacts and the active index exceed the tenant quota",
            }
            .fail();
        }
        Ok(())
    }

    pub fn recover_discovery_artifacts(&self) -> Result<usize> {
        let mut files = self.discovery_files.lock().map_err(|_| {
            DiscoverySnafu {
                code: "ARTIFACT_OWNER",
                reason: "discovery file owner is poisoned",
            }
            .build()
        })?;
        if files.usage.is_some() {
            return DiscoverySnafu {
                code: "ARTIFACT_BUSY",
                reason: "artifact recovery must run before admission",
            }
            .fail();
        }
        let mut pending = self
            .evidence_lock()?
            .state
            .discovery_heads
            .values()
            .map(|head| head.artifact.clone())
            .collect::<BTreeSet<_>>();
        let mut retained = BTreeSet::new();
        while let Some(reference) = pending.pop_first() {
            if retained.insert(reference.clone()) {
                if retained.len() > MAX_ARTIFACT_FILES {
                    return DiscoverySnafu {
                        code: "ARTIFACT_LIMIT",
                        reason: "artifact recovery exceeds its reference bound",
                    }
                    .fail();
                }
                pending.extend(
                    files
                        .read(&reference)?
                        .dependencies
                        .into_iter()
                        .filter(|reference| !retained.contains(reference)),
                );
                if pending.len() > MAX_ARTIFACT_FILES {
                    return DiscoverySnafu {
                        code: "ARTIFACT_LIMIT",
                        reason: "artifact recovery queue exceeds its reference bound",
                    }
                    .fail();
                }
            }
        }
        files.measure()?;
        let mut remove = Vec::new();
        for tenant in files
            .usage
            .as_ref()
            .ok_or_else(|| {
                DiscoverySnafu {
                    code: "ARTIFACT_OWNER",
                    reason: "artifact usage is not measured",
                }
                .build()
            })?
            .keys()
        {
            let directory = files.directory(tenant);
            for file in fs::read_dir(&directory).context(IoSnafu { path: &directory })? {
                let file = file.context(IoSnafu { path: &directory })?;
                let path = file.path();
                let name = file.file_name();
                let name = name.to_str().unwrap_or_default();
                let referenced = if let Some(hash) = name.strip_suffix(".bin") {
                    let digest = hex::decode(hash)
                        .ok()
                        .and_then(|bytes| <[u8; 32]>::try_from(bytes).ok())
                        .filter(|digest| hex::encode(digest) == hash)
                        .ok_or_else(|| {
                            DiscoverySnafu {
                                code: "ARTIFACT_PATH",
                                reason: "discovery contains an unknown artifact name",
                            }
                            .build()
                        })?;
                    retained.contains(&DiscoveryArtifactRefV1 {
                        tenant_id: *tenant,
                        sha256: digest,
                        bytes: file.metadata().context(IoSnafu { path: &path })?.len(),
                    })
                } else if name
                    .strip_suffix(".tmp")
                    .is_some_and(|id| uuid::Uuid::parse_str(id).is_ok())
                {
                    false
                } else {
                    files.usage = None;
                    return DiscoverySnafu {
                        code: "ARTIFACT_PATH",
                        reason: "discovery contains an unknown artifact name",
                    }
                    .fail();
                };
                if !referenced {
                    remove.push(path);
                }
                if remove.len() > MAX_ARTIFACT_FILES {
                    files.usage = None;
                    return DiscoverySnafu {
                        code: "ARTIFACT_LIMIT",
                        reason: "orphan cleanup exceeds its path bound",
                    }
                    .fail();
                }
            }
        }
        let mut directories = BTreeSet::new();
        files.usage = None;
        for path in &remove {
            fs::remove_file(path).context(IoSnafu { path })?;
            if let Some(parent) = path.parent() {
                directories.insert(parent);
            }
        }
        for directory in directories {
            File::open(directory)
                .and_then(|file| file.sync_all())
                .context(IoSnafu { path: directory })?;
        }
        files.measure()?;
        Ok(remove.len())
    }

    pub fn put_discovery_artifact(
        &self,
        artifact: &DiscoveryArtifactV1,
    ) -> Result<DiscoveryArtifactRefV1> {
        self.discovery_files
            .lock()
            .map_err(|_| {
                DiscoverySnafu {
                    code: "ARTIFACT_OWNER",
                    reason: "discovery file owner is poisoned",
                }
                .build()
            })?
            .write(artifact)
    }

    pub fn read_discovery_artifact(
        &self,
        reference: &DiscoveryArtifactRefV1,
    ) -> Result<DiscoveryArtifactV1> {
        self.discovery_files
            .lock()
            .map_err(|_| {
                DiscoverySnafu {
                    code: "ARTIFACT_OWNER",
                    reason: "discovery file owner is poisoned",
                }
                .build()
            })?
            .read(reference)
    }

    pub fn discovery_heads(&self, tenant_id: [u8; 16]) -> Result<Vec<DiscoveryHeadV1>> {
        Ok(self
            .evidence_lock()?
            .state
            .discovery_heads
            .values()
            .filter(|head| head.key.tenant_id == tenant_id)
            .cloned()
            .collect())
    }

    pub(crate) fn discovery_catalog(&self) -> Result<(u64, Vec<DiscoveryHeadV1>)> {
        let inner = self.evidence_lock()?;
        Ok((
            inner.state.commit_index,
            inner.state.discovery_heads.values().cloned().collect(),
        ))
    }

    pub fn discovery_head(&self, key: &DiscoveryHeadKeyV1) -> Result<Option<DiscoveryHeadV1>> {
        Ok(self
            .evidence_lock()?
            .state
            .discovery_heads
            .get(key)
            .cloned())
    }

    pub fn commit_discovery_head(
        &self,
        key: DiscoveryHeadKeyV1,
        expected: Option<&DiscoveryHeadV1>,
        artifact: DiscoveryArtifactRefV1,
    ) -> Result<DiscoveryHeadV1> {
        let files = self.discovery_files.lock().map_err(|_| {
            DiscoverySnafu {
                code: "ARTIFACT_OWNER",
                reason: "discovery file owner is poisoned",
            }
            .build()
        })?;
        files.read(&artifact)?;
        let mut inner = self.evidence_lock()?;
        if let Some(current) = inner.state.discovery_heads.get(&key) {
            if current.artifact == artifact {
                return Ok(current.clone());
            }
        }
        let head = DiscoveryHeadV1 {
            key,
            revision: expected
                .map_or(Some(1), |head| head.revision.checked_add(1))
                .ok_or_else(|| {
                    DiscoverySnafu {
                        code: "HEAD_LIMIT",
                        reason: "discovery revision is exhausted",
                    }
                    .build()
                })?,
            commit_index: checked_store_increment(
                inner.state.commit_index,
                &inner.root,
                "Control commit index is exhausted",
            )?,
            artifact,
        };
        commit(
            &mut inner,
            ControlTransactionV1::DiscoveryHeadCommitted {
                head: head.clone(),
                expected: expected.cloned(),
            },
        )?;
        Ok(head)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn artifact(value: u8) -> DiscoveryArtifactV1 {
        DiscoveryArtifactV1 {
            schema_version: 1,
            tenant_id: [1; 16],
            dependencies: vec![],
            payload: vec![value],
        }
    }

    fn key(value: u8) -> DiscoveryHeadKeyV1 {
        DiscoveryHeadKeyV1 {
            tenant_id: [1; 16],
            id: DiscoveryDigestV1([value; 32]),
        }
    }

    #[test]
    fn discovery_store_commits_only_synced_artifacts_and_recovers_orphans(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        assert_eq!(store.recover_discovery_artifacts()?, 0);
        let first = store.put_discovery_artifact(&artifact(1))?;
        let head = store.commit_discovery_head(key(1), None, first.clone())?;
        assert_eq!((head.revision, head.commit_index), (1, 1));
        assert_eq!(
            store.commit_discovery_head(key(1), None, first.clone())?,
            head
        );
        assert_eq!(store.commit_index(), 1);
        assert!(store.recover_discovery_artifacts().is_err());
        let mut second = artifact(2);
        second.dependencies.push(first.clone());
        let second = store.put_discovery_artifact(&second)?;
        assert!(store
            .commit_discovery_head(key(1), None, second.clone())
            .is_err());
        assert_eq!(store.discovery_heads([1; 16])?, vec![head.clone()]);
        fs::create_dir(directory.path().join("state.tmp"))?;
        assert!(store
            .commit_discovery_head(key(1), Some(&head), second.clone())
            .is_err());
        assert_eq!(store.discovery_heads([1; 16])?, vec![head.clone()]);
        fs::remove_dir(directory.path().join("state.tmp"))?;
        drop(store);
        let store = ControlStore::open(directory.path())?;
        assert_eq!(store.discovery_heads([1; 16])?, vec![head.clone()]);
        assert!(store.discovery_heads([2; 16])?.is_empty());
        assert_eq!(store.recover_discovery_artifacts()?, 1);
        assert!(store.read_discovery_artifact(&second).is_err());
        assert_eq!(store.read_discovery_artifact(&first)?, artifact(1));
        let mut other_tenant = first.clone();
        other_tenant.tenant_id = [2; 16];
        assert!(store.read_discovery_artifact(&other_tenant).is_err());
        let mut malformed = artifact(3);
        malformed.dependencies.push(other_tenant);
        assert!(store.put_discovery_artifact(&malformed).is_err());
        let mut second = artifact(2);
        second.dependencies.push(first.clone());
        let second = store.put_discovery_artifact(&second)?;
        let current = store.commit_discovery_head(key(1), Some(&head), second.clone())?;
        assert_eq!((current.revision, current.commit_index), (2, 2));
        drop(store);
        let store = ControlStore::open(directory.path())?;
        assert_eq!(store.recover_discovery_artifacts()?, 0);
        assert_eq!(store.discovery_heads([1; 16])?, vec![current]);
        let path = store
            .discovery_files
            .lock()
            .map_err(|_| "poisoned")?
            .path(&first);
        fs::write(&path, b"corrupt")?;
        assert!(store.read_discovery_artifact(&first).is_err());
        drop(store);
        let store = ControlStore::open(directory.path())?;
        assert!(store.recover_discovery_artifacts().is_err());
        assert_eq!(store.commit_index(), 2);
        Ok(())
    }

    #[test]
    fn discovery_store_enforces_segment_quota_and_head_boundaries(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let mut value = artifact(0);
        value.payload.clear();
        let overhead = rmp_serde::to_vec_named(&value)?.len() + 4;
        value
            .payload
            .resize(MAX_DISCOVERY_SEGMENT_BYTES - overhead, 0);
        assert_eq!(
            rmp_serde::to_vec_named(&value)?.len(),
            MAX_DISCOVERY_SEGMENT_BYTES
        );
        let large = store.put_discovery_artifact(&value)?;
        assert_eq!(large.bytes, MAX_DISCOVERY_SEGMENT_BYTES as u64);
        value.payload.push(0);
        assert!(store.put_discovery_artifact(&value).is_err());
        let next = artifact(2);
        let bytes = rmp_serde::to_vec_named(&next)?.len() as u64;
        {
            let mut files = store.discovery_files.lock().map_err(|_| "poisoned")?;
            files.usage = Some(BTreeMap::from([(
                [1; 16],
                MAX_DISCOVERY_TENANT_ARTIFACT_BYTES - bytes,
            )]));
        }
        let reference = store.put_discovery_artifact(&next)?;
        assert!(store.put_discovery_artifact(&artifact(3)).is_err());
        assert_eq!(store.put_discovery_artifact(&next)?, reference);
        {
            let mut files = store.discovery_files.lock().map_err(|_| "poisoned")?;
            files.usage = Some(BTreeMap::from([(
                [2; 16],
                MAX_DISCOVERY_ARTIFACT_BYTES - bytes,
            )]));
        }
        store.put_discovery_artifact(&artifact(3))?;
        assert!(store.put_discovery_artifact(&artifact(4)).is_err());
        {
            let mut files = store.discovery_files.lock().map_err(|_| "poisoned")?;
            files.usage = Some(BTreeMap::new());
            files.file_count = MAX_ARTIFACT_FILES - 1;
        }
        store.put_discovery_artifact(&artifact(4))?;
        assert!(store.put_discovery_artifact(&artifact(5)).is_err());
        let mut state = ControlStoreState::default();
        for number in 0..MAX_DISCOVERY_TENANT_HEADS {
            let mut key = key(0);
            key.id = DiscoveryDigestV1::of(&number)?;
            let head = DiscoveryHeadV1 {
                key,
                revision: 1,
                commit_index: 1,
                artifact: reference.clone(),
            };
            DiscoveryFiles::apply_head(&mut state, &head, None)?;
        }
        let overflow = DiscoveryHeadV1 {
            key: key(255),
            revision: 1,
            commit_index: 1,
            artifact: reference,
        };
        assert!(DiscoveryFiles::apply_head(&mut state.clone(), &overflow, None).is_err());
        assert_eq!(state.discovery_heads.len(), MAX_DISCOVERY_TENANT_HEADS);
        state.discovery_heads.clear();
        for number in 0..MAX_DISCOVERY_HEADS - 1 {
            let tenant_id = [1 + (number / MAX_DISCOVERY_TENANT_HEADS) as u8; 16];
            let mut head = overflow.clone();
            head.key.tenant_id = tenant_id;
            head.key.id = DiscoveryDigestV1::of(&number)?;
            head.artifact.tenant_id = tenant_id;
            state.discovery_heads.insert(head.key.clone(), head);
        }
        let mut last = overflow.clone();
        last.key.tenant_id = [4; 16];
        last.artifact.tenant_id = [4; 16];
        DiscoveryFiles::apply_head(&mut state, &last, None)?;
        assert_eq!(state.discovery_heads.len(), MAX_DISCOVERY_HEADS);
        assert!(rmp_serde::to_vec_named(&state.discovery_heads)?.len() <= MAX_DISCOVERY_HEAD_BYTES);
        last.key.tenant_id = [5; 16];
        last.artifact.tenant_id = [5; 16];
        assert!(DiscoveryFiles::apply_head(&mut state.clone(), &last, None).is_err());
        Ok(())
    }

    #[test]
    fn discovery_store_charges_shared_index_reserve_to_tenant_artifacts(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        store.put_discovery_artifact(&artifact(1))?;
        let index = crate::DiscoveryIndex::open(store.clone())?;
        let next = artifact(2);
        let bytes = rmp_serde::to_vec_named(&next)?.len() as u64;
        {
            let mut files = store.discovery_files.lock().map_err(|_| "poisoned")?;
            assert_eq!(files.index_reserve()?, MAX_DISCOVERY_ACTIVE_INDEX_BYTES);
            files.usage = Some(BTreeMap::from([(
                [1; 16],
                MAX_DISCOVERY_TENANT_ARTIFACT_BYTES - MAX_DISCOVERY_ACTIVE_INDEX_BYTES - bytes,
            )]));
        }
        let reference = store.put_discovery_artifact(&next)?;
        store.reserve_discovery_index_tenant([1; 16])?;
        assert!(store.put_discovery_artifact(&artifact(3)).is_err());
        assert_eq!(store.put_discovery_artifact(&next)?, reference);
        {
            let mut files = store.discovery_files.lock().map_err(|_| "poisoned")?;
            files.usage.as_mut().ok_or("usage absent")?.insert(
                [1; 16],
                MAX_DISCOVERY_TENANT_ARTIFACT_BYTES - MAX_DISCOVERY_ACTIVE_INDEX_BYTES + 1,
            );
        }
        assert!(store.reserve_discovery_index_tenant([1; 16]).is_err());
        store.reserve_discovery_index_tenant([2; 16])?;
        let mut other = artifact(3);
        other.tenant_id = [2; 16];
        store.put_discovery_artifact(&other)?;
        drop(index);
        drop(store);
        let store = ControlStore::open(directory.path())?;
        assert_eq!(
            store
                .discovery_files
                .lock()
                .map_err(|_| "poisoned")?
                .index_reserve()?,
            MAX_DISCOVERY_ACTIVE_INDEX_BYTES
        );
        store.recover_discovery_artifacts()?;
        store.reserve_discovery_index_tenant([1; 16])?;
        Ok(())
    }

    #[test]
    fn discovery_migration_preserves_schema_five_cpu_metadata(
    ) -> std::result::Result<(), Box<dyn std::error::Error>> {
        let directory = tempfile::tempdir()?;
        let store = ControlStore::open(directory.path())?;
        let input = crate::DiscoveryInputManifestV1::from_json(include_bytes!(
            "../../../mithril-e2e/fixtures/discovery/manifest.json"
        ))?;
        let identity = input.records[0].id.stream.clone();
        let record = input.records[0].observation.to_wire_record()?;
        store.accept_evidence_batch(
            identity.clone(),
            crate::EvidenceBatchInputV1::encode(1, vec![record])?,
        )?;
        let binding = store.evidence_cpu_binding(&identity)?;
        let state = store.evidence_lock()?.state.clone();
        drop(store);
        let encoded = rmp_serde::to_vec_named(&DurableControlStateV1 {
            schema_version: 5,
            state,
        })?;
        let mut bytes = Sha256::digest(&encoded).to_vec();
        bytes.extend(encoded);
        fs::write(directory.path().join("state.bin"), &bytes)?;
        let store = ControlStore::open(directory.path())?;
        assert_eq!(store.evidence_cpu_binding(&identity)?, binding);
        assert_eq!(fs::read(directory.path().join("state-v5.bin"))?, bytes);
        assert!(store.discovery_heads(identity.tenant_id)?.is_empty());
        Ok(())
    }
}
