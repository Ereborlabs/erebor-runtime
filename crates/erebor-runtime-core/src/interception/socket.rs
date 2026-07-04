use super::SurfaceInterceptionDecision;

#[derive(Clone, Copy, Debug)]
pub struct SocketConnectInterceptionRequest<'a> {
    scheme: &'a str,
    host: &'a str,
    port: u32,
    path: &'a str,
    cwd: &'a str,
    pid: i64,
    ppid: i64,
}

impl<'a> SocketConnectInterceptionRequest<'a> {
    #[must_use]
    pub const fn new(
        scheme: &'a str,
        host: &'a str,
        port: u32,
        path: &'a str,
        cwd: &'a str,
        pid: i64,
        ppid: i64,
    ) -> Self {
        Self {
            scheme,
            host,
            port,
            path,
            cwd,
            pid,
            ppid,
        }
    }

    #[must_use]
    pub const fn scheme(&self) -> &'a str {
        self.scheme
    }

    #[must_use]
    pub const fn host(&self) -> &'a str {
        self.host
    }

    #[must_use]
    pub const fn port(&self) -> u32 {
        self.port
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

pub trait SocketConnectSurfaceHandler: Send + Sync {
    fn surface(&self) -> &str;
    fn decide_socket_connect(
        &self,
        request: &SocketConnectInterceptionRequest<'_>,
    ) -> SurfaceInterceptionDecision;
}
