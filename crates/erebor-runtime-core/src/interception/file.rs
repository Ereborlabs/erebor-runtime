use super::SurfaceInterceptionDecision;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FileInterceptionOperationKind {
    Open,
    Read,
    Mutation,
}

impl FileInterceptionOperationKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Open => "file_open",
            Self::Read => "file_read",
            Self::Mutation => "file_mutation",
        }
    }
}

#[derive(Clone, Copy, Debug)]
pub struct FileInterceptionRequest<'a> {
    operation: FileInterceptionOperationKind,
    path: &'a str,
    cwd: &'a str,
    pid: i64,
    ppid: i64,
}

impl<'a> FileInterceptionRequest<'a> {
    #[must_use]
    pub const fn new(
        operation: FileInterceptionOperationKind,
        path: &'a str,
        cwd: &'a str,
        pid: i64,
        ppid: i64,
    ) -> Self {
        Self {
            operation,
            path,
            cwd,
            pid,
            ppid,
        }
    }

    #[must_use]
    pub const fn operation(&self) -> FileInterceptionOperationKind {
        self.operation
    }

    #[must_use]
    pub const fn path(&self) -> &'a str {
        self.path
    }

    #[must_use]
    pub const fn cwd(&self) -> &'a str {
        self.cwd
    }

    #[must_use]
    pub const fn pid(&self) -> i64 {
        self.pid
    }

    #[must_use]
    pub const fn ppid(&self) -> i64 {
        self.ppid
    }
}

pub trait FileOperationSurfaceHandler: Send + Sync {
    fn surface(&self) -> &str;
    fn decide_file_operation(
        &self,
        request: &FileInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision;
}
