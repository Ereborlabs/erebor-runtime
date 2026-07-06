#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct FileOperation {
    pub(crate) kind: FileOperationKind,
    pub(crate) path: String,
    pub(crate) resolved_identity: Option<FileIdentity>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FileOperationKind {
    Open,
    Read,
    Mutation,
}

impl FileOperationKind {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "file_open",
            Self::Read => "file_read",
            Self::Mutation => "file_mutation",
        }
    }

    pub(crate) const fn as_i32(self) -> i32 {
        match self {
            Self::Open => 1,
            Self::Read => 2,
            Self::Mutation => 3,
        }
    }

    pub(crate) const fn interception_operation(self) -> super::InterceptionOperation {
        match self {
            Self::Open => super::InterceptionOperation::FileOpen,
            Self::Read => super::InterceptionOperation::FileRead,
            Self::Mutation => super::InterceptionOperation::FileMutation,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct FileIdentity {
    pub(crate) device: u64,
    pub(crate) inode: u64,
}

pub(crate) fn encode_file_operation(file: &FileOperation) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, file.kind.as_i32() as u64);
    write_string_field(&mut output, 2, &file.path);
    if let Some(identity) = file.resolved_identity {
        write_bytes_field(&mut output, 3, &encode_file_identity(identity));
    }
    output
}

fn encode_file_identity(identity: FileIdentity) -> Vec<u8> {
    let mut output = Vec::new();
    write_varint_field(&mut output, 1, identity.device);
    write_varint_field(&mut output, 2, identity.inode);
    output
}
use super::codec::{write_bytes_field, write_string_field, write_varint_field};
