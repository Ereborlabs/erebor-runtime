use std::path::PathBuf;

use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelPlatformProbeV1 {
    pub kernel_release: String,
    pub architecture: String,
    pub active_lsm_order: String,
    pub bpf_lsm_active: bool,
    pub runtime_btf_sha256: Option<String>,
    pub cgroup_v2: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelPreflightV1 {
    pub kernel_release: String,
    pub active_lsm_order: String,
    pub runtime_btf_sha256: String,
    pub cgroup_v2: bool,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelMapManifestV1 {
    pub name: String,
    pub map_type: String,
    pub id: u32,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
    pub pin_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelMapLayoutV1 {
    pub name: String,
    pub map_type: String,
    pub key_size: u32,
    pub value_size: u32,
    pub max_entries: u32,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelLinkManifestV1 {
    pub program: String,
    pub link_id: u32,
    pub program_id: u32,
    pub pin_path: Option<PathBuf>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelProgramLayoutV1 {
    pub name: String,
    pub section: String,
    pub program_type: String,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelObjectLayoutV1 {
    pub maps: Vec<KernelMapLayoutV1>,
    pub programs: Vec<KernelProgramLayoutV1>,
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct KernelObjectManifestV1 {
    pub schema_version: u32,
    pub node_boot_id: String,
    pub label_epoch: u64,
    pub preflight: KernelPreflightV1,
    pub object_sha256: String,
    pub maps: Vec<KernelMapManifestV1>,
    pub links: Vec<KernelLinkManifestV1>,
    pub ready: bool,
}
