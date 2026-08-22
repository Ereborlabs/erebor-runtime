use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::{Path, PathBuf};

use erebor_interceptor::KernelHost;
use erebor_interceptor_abi::{Id128V1, ProfileGenerationDescriptorV1};
use serde::{Deserialize, Serialize};
use snafu::{ensure, ResultExt as _};
use zerocopy::IntoBytes as _;

use crate::error::{IdentityStateSnafu, InterceptorSnafu, IoSnafu, JsonSnafu};
use crate::Result;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GenerationAllocationV1 {
    profile_id: [u8; 16],
    owner_generation: u64,
    table_digest: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
struct GenerationAllocatorStateV1 {
    node_boot_id: [u8; 16],
    label_epoch: u64,
    high_water: u64,
    allocations: BTreeMap<u64, GenerationAllocationV1>,
}

pub(super) struct GenerationHandleAllocator {
    path: PathBuf,
    state: GenerationAllocatorStateV1,
}

impl GenerationHandleAllocator {
    pub(super) fn load(
        path: impl Into<PathBuf>,
        host: &KernelHost,
        node_boot_id: Id128V1,
        label_epoch: u64,
    ) -> Result<Self> {
        let path = path.into();
        let node_boot_id = id_bytes(node_boot_id);
        let pinned_handles = pinned_generation_handles(host)?;
        let state = match fs::read(&path) {
            Ok(bytes) => {
                let state: GenerationAllocatorStateV1 =
                    serde_json::from_slice(&bytes).context(JsonSnafu { path: &path })?;
                if state.node_boot_id == node_boot_id && state.label_epoch == label_epoch {
                    ensure!(
                        state.high_water > 0 || state.allocations.is_empty(),
                        IdentityStateSnafu {
                            reason:
                                "generation allocator has allocations without a high-water mark",
                        }
                    );
                    ensure!(
                        state
                            .allocations
                            .keys()
                            .all(|handle| { *handle > 0 && *handle <= state.high_water }),
                        IdentityStateSnafu {
                            reason: "generation allocator contains an invalid or future handle",
                        }
                    );
                    for handle in &pinned_handles {
                        ensure!(
                            state.allocations.contains_key(handle),
                            IdentityStateSnafu {
                                reason: format!(
                                    "pinned generation {handle} has no durable allocator record"
                                ),
                            }
                        );
                    }
                    state
                } else {
                    ensure!(
                        pinned_handles.is_empty(),
                        IdentityStateSnafu {
                            reason: "generation allocator epoch changed while pinned generations survive",
                        }
                    );
                    GenerationAllocatorStateV1 {
                        node_boot_id,
                        label_epoch,
                        high_water: 0,
                        allocations: BTreeMap::new(),
                    }
                }
            }
            Err(source) if source.kind() == std::io::ErrorKind::NotFound => {
                ensure!(
                    pinned_handles.is_empty(),
                    IdentityStateSnafu {
                        reason:
                            "generation allocator state is missing while pinned generations survive",
                    }
                );
                GenerationAllocatorStateV1 {
                    node_boot_id,
                    label_epoch,
                    high_water: 0,
                    allocations: BTreeMap::new(),
                }
            }
            Err(source) => return Err(source).context(IoSnafu { path: &path }),
        };
        Ok(Self { path, state })
    }

    pub(super) fn reserve(&mut self, descriptor: &ProfileGenerationDescriptorV1) -> Result<()> {
        let handle = descriptor.profile_generation_ref_id;
        ensure!(
            handle > 0,
            IdentityStateSnafu {
                reason: "generation handle must be nonzero",
            }
        );
        let allocation = GenerationAllocationV1 {
            profile_id: id_bytes(descriptor.profile_id),
            owner_generation: descriptor.owner_generation,
            table_digest: descriptor.table_digest,
        };
        if let Some(existing) = self.state.allocations.get(&handle) {
            ensure!(
                existing == &allocation,
                IdentityStateSnafu {
                    reason: format!(
                        "generation handle {handle} is already reserved for different content"
                    ),
                }
            );
            return Ok(());
        }
        ensure!(
            handle > self.state.high_water,
            IdentityStateSnafu {
                reason: format!(
                    "generation handle {handle} does not advance durable high-water {}",
                    self.state.high_water
                ),
            }
        );
        self.state.high_water = handle;
        self.state.allocations.insert(handle, allocation);
        self.persist()
    }

    pub(super) fn next_handle(&self) -> Result<u64> {
        self.state.high_water.checked_add(1).ok_or_else(|| {
            IdentityStateSnafu {
                reason: "the durable generation handle space is exhausted".to_owned(),
            }
            .build()
        })
    }

    fn persist(&self) -> Result<()> {
        let parent = self.path.parent().unwrap_or_else(|| Path::new("."));
        fs::create_dir_all(parent).context(IoSnafu { path: parent })?;
        let temporary = self.path.with_extension("tmp");
        let bytes = serde_json::to_vec(&self.state).context(JsonSnafu { path: &self.path })?;
        let mut file = OpenOptions::new()
            .create(true)
            .truncate(true)
            .write(true)
            .open(&temporary)
            .context(IoSnafu { path: &temporary })?;
        file.write_all(&bytes)
            .context(IoSnafu { path: &temporary })?;
        file.sync_all().context(IoSnafu { path: &temporary })?;
        fs::rename(&temporary, &self.path).context(IoSnafu { path: &self.path })?;
        OpenOptions::new()
            .read(true)
            .open(parent)
            .context(IoSnafu { path: parent })?
            .sync_all()
            .context(IoSnafu { path: parent })
    }
}

fn pinned_generation_handles(host: &KernelHost) -> Result<Vec<u64>> {
    host.map_keys("profile_generation_descriptors")
        .context(InterceptorSnafu)?
        .into_iter()
        .map(|bytes| {
            let bytes: [u8; 8] = bytes.try_into().map_err(|_| {
                IdentityStateSnafu {
                    reason: "pinned generation descriptor has an invalid key size".to_owned(),
                }
                .build()
            })?;
            Ok(u64::from_ne_bytes(bytes))
        })
        .collect()
}

fn id_bytes(id: Id128V1) -> [u8; 16] {
    let mut bytes = [0; 16];
    bytes.copy_from_slice(id.as_bytes());
    bytes
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use snafu::ResultExt as _;
    use tempfile::tempdir;

    use super::{GenerationAllocatorStateV1, GenerationHandleAllocator};
    use crate::error::IoSnafu;
    use erebor_interceptor_abi::{
        Id128V1, PolicyGenerationModeV1, PolicyGenerationStateV1, ProfileGenerationDescriptorV1,
    };

    fn descriptor(handle: u64, digest_byte: u8) -> ProfileGenerationDescriptorV1 {
        ProfileGenerationDescriptorV1 {
            node_boot_id: Id128V1 { high: 1, low: 2 },
            profile_id: Id128V1 { high: 3, low: 4 },
            label_epoch: 1,
            profile_generation_ref_id: handle,
            owner_generation: 1,
            row_count: 1,
            default_count: 0,
            state: PolicyGenerationStateV1::Preparing,
            mode: PolicyGenerationModeV1::Protect,
            reserved: [0; 6],
            table_digest: [digest_byte; 32],
            transition_version: 1,
        }
    }

    #[test]
    fn durable_allocator_never_reuses_or_moves_backwards() -> crate::Result<()> {
        let directory = tempdir().context(IoSnafu {
            path: PathBuf::from("temporary generation allocator directory"),
        })?;
        let path = directory.path().join("generation-handles-v1.json");
        let state = GenerationAllocatorStateV1 {
            node_boot_id: [1; 16],
            label_epoch: 9,
            high_water: 0,
            allocations: Default::default(),
        };
        let mut allocator = GenerationHandleAllocator { path, state };
        allocator.reserve(&descriptor(7, 1))?;
        allocator.reserve(&descriptor(7, 1))?;
        assert!(allocator.reserve(&descriptor(6, 2)).is_err());
        assert!(allocator.reserve(&descriptor(7, 2)).is_err());
        allocator.reserve(&descriptor(8, 2))?;
        assert_eq!(allocator.state.high_water, 8);
        Ok(())
    }
}
