include!(concat!(env!("OUT_DIR"), "/erebor.runtime.ipc.v1.rs"));

pub const FILE_DESCRIPTOR_SET: &[u8] = tonic::include_file_descriptor_set!("erebor.runtime.ipc.v1");
