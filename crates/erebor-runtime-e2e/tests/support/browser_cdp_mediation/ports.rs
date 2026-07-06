use std::net::{IpAddr, Ipv4Addr, SocketAddr, TcpListener};

use erebor_runtime_e2e::{error::IoSnafu, E2eError};
use snafu::ResultExt;

use crate::cli::external_error;

#[derive(Clone, Copy)]
pub struct PortPair {
    governed: u16,
    private: u16,
}

impl PortPair {
    pub fn allocate() -> Result<Self, E2eError> {
        for _attempt in 0..32 {
            let governed = free_port()?;
            let Some(private) = governed.checked_add(1) else {
                continue;
            };
            if TcpListener::bind(SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), private)).is_ok()
            {
                return Ok(Self { governed, private });
            }
        }

        Err(external_error(
            "allocate governed/private CDP ports",
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "could not reserve adjacent loopback ports",
            ),
        ))
    }

    pub const fn governed(self) -> u16 {
        self.governed
    }

    pub const fn private(self) -> u16 {
        self.private
    }
}

fn free_port() -> Result<u16, E2eError> {
    let listener = TcpListener::bind(SocketAddr::from(([127, 0, 0, 1], 0))).context(IoSnafu)?;
    Ok(listener.local_addr().context(IoSnafu)?.port())
}
