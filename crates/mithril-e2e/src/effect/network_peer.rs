use std::cell::RefCell;
use std::fs;
use std::io::{self, Read as _};
use std::net::{IpAddr, SocketAddr, TcpListener, UdpSocket};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use snafu::{ensure, ResultExt as _};

use super::network::{
    NetworkPeerServerResultV1, NETWORK_PEER_TCP_PAYLOAD, NETWORK_PEER_UDP_PAYLOAD,
};
use crate::error::{InvalidInputSnafu, IoSnafu, JsonSnafu};
use crate::physical::{wait_for, ProbeFile};
use crate::Result;

const PEER_LIMIT: Duration = Duration::from_secs(120);
const QUIET_TIME: Duration = Duration::from_millis(500);

pub struct NetworkPeerServer {
    tcp: TcpListener,
    udp: UdpSocket,
    denied: TcpListener,
    ready: PathBuf,
    tcp_seen: bool,
    udp_seen: bool,
    completed: Option<Instant>,
}

impl NetworkPeerServer {
    pub fn bind(
        address: IpAddr,
        tcp_port: u16,
        udp_port: u16,
        denied_port: u16,
        ready: &Path,
    ) -> Result<Self> {
        Self::validate(tcp_port, udp_port, denied_port)?;
        let tcp = TcpListener::bind(SocketAddr::new(address, tcp_port)).context(IoSnafu {
            path: Path::new("two-node TCP peer"),
        })?;
        let udp = UdpSocket::bind(SocketAddr::new(address, udp_port)).context(IoSnafu {
            path: Path::new("two-node UDP peer"),
        })?;
        let denied = TcpListener::bind(SocketAddr::new(address, denied_port)).context(IoSnafu {
            path: Path::new("two-node denied peer"),
        })?;
        Self::from_sockets(tcp, udp, denied, ready)
    }

    fn from_sockets(
        tcp: TcpListener,
        udp: UdpSocket,
        denied: TcpListener,
        ready: &Path,
    ) -> Result<Self> {
        tcp.set_nonblocking(true).context(IoSnafu {
            path: Path::new("two-node TCP peer"),
        })?;
        udp.set_nonblocking(true).context(IoSnafu {
            path: Path::new("two-node UDP peer"),
        })?;
        denied.set_nonblocking(true).context(IoSnafu {
            path: Path::new("two-node denied peer"),
        })?;
        Ok(Self {
            tcp,
            udp,
            denied,
            ready: ready.to_owned(),
            tcp_seen: false,
            udp_seen: false,
            completed: None,
        })
    }

    pub fn run_to(mut self, output: &Path) -> Result<NetworkPeerServerResultV1> {
        ensure!(
            !self.ready.exists(),
            InvalidInputSnafu {
                path: &self.ready,
                reason: "the peer ready file already exists",
            }
        );
        ensure!(
            !output.exists(),
            InvalidInputSnafu {
                path: output,
                reason: "the peer result file already exists",
            }
        );
        let ready = ProbeFile::new(&self.ready);
        let result_file = ProbeFile::new(output);
        fs::write(&self.ready, b"ready\n").context(IoSnafu { path: &self.ready })?;
        let last = RefCell::new(self.status());
        let ready_path = self.ready.clone();
        let value = wait_for(
            &ready_path,
            "network peer traffic",
            PEER_LIMIT,
            || {
                let value = self.poll()?;
                *last.borrow_mut() = self.status();
                Ok(value)
            },
            || last.borrow().clone(),
        )?;
        fs::write(
            output,
            serde_json::to_vec_pretty(&value).context(JsonSnafu { path: output })?,
        )
        .context(IoSnafu { path: output })?;
        ready.cleanup()?;
        result_file.keep();
        Ok(value)
    }

    pub(super) fn validate(tcp: u16, udp: u16, denied: u16) -> Result<()> {
        ensure!(
            tcp != 0 && udp != 0 && denied != 0 && tcp != udp && tcp != denied && udp != denied,
            InvalidInputSnafu {
                path: Path::new("two-node network peer"),
                reason: "the TCP, UDP, and denied ports must be distinct and nonzero",
            }
        );
        Ok(())
    }

    fn poll(&mut self) -> Result<Option<NetworkPeerServerResultV1>> {
        match self.denied.accept() {
            Ok(_) => {
                return InvalidInputSnafu {
                    path: Path::new("two-node denied peer"),
                    reason: "the denied peer accepted a connection",
                }
                .fail();
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
            Err(source) => {
                return Err(crate::Error::Io {
                    path: PathBuf::from("two-node denied peer"),
                    source,
                    location: snafu::Location::default(),
                });
            }
        }
        if !self.tcp_seen {
            match self.tcp.accept() {
                Ok((mut stream, _)) => {
                    stream
                        .set_read_timeout(Some(Duration::from_secs(5)))
                        .context(IoSnafu {
                            path: Path::new("two-node TCP peer"),
                        })?;
                    let mut payload = [0_u8; NETWORK_PEER_TCP_PAYLOAD.len()];
                    stream.read_exact(&mut payload).context(IoSnafu {
                        path: Path::new("two-node TCP peer"),
                    })?;
                    self.tcp_seen = payload == NETWORK_PEER_TCP_PAYLOAD;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(source) => {
                    return Err(crate::Error::Io {
                        path: PathBuf::from("two-node TCP peer"),
                        source,
                        location: snafu::Location::default(),
                    });
                }
            }
        }
        if !self.udp_seen {
            let mut payload = [0_u8; NETWORK_PEER_UDP_PAYLOAD.len()];
            match self.udp.recv_from(&mut payload) {
                Ok((length, _)) => {
                    self.udp_seen = length == payload.len() && payload == NETWORK_PEER_UDP_PAYLOAD;
                }
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(source) => {
                    return Err(crate::Error::Io {
                        path: PathBuf::from("two-node UDP peer"),
                        source,
                        location: snafu::Location::default(),
                    });
                }
            }
        }
        if self.tcp_seen && self.udp_seen {
            let completed = self.completed.get_or_insert_with(Instant::now);
            if completed.elapsed() >= QUIET_TIME {
                return Ok(Some(NetworkPeerServerResultV1 {
                    schema_version: 1,
                    tcp_payload_received: true,
                    udp_payload_received: true,
                    denied_connection_absent: true,
                }));
            }
        }
        Ok(None)
    }

    fn status(&self) -> String {
        format!(
            "tcp_received={}, udp_received={}, denied_connection_absent=true",
            self.tcp_seen, self.udp_seen
        )
    }
}

#[cfg(test)]
mod tests {
    use std::io::{self, Write as _};
    use std::net::{SocketAddr, TcpListener, TcpStream, UdpSocket};
    use std::thread;
    use std::time::Duration;

    use snafu::ResultExt as _;

    use super::NetworkPeerServer;
    use crate::effect::network::{NETWORK_PEER_TCP_PAYLOAD, NETWORK_PEER_UDP_PAYLOAD};
    use crate::error::IoSnafu;
    use crate::physical::wait_for;

    #[test]
    fn peer_requires_controls() -> crate::Result<()> {
        let dir = tempfile::tempdir().context(IoSnafu {
            path: "temporary network peer",
        })?;
        let address = SocketAddr::from(([127, 0, 0, 1], 0));
        let tcp = TcpListener::bind(address).context(IoSnafu {
            path: "temporary TCP peer port",
        })?;
        let udp = UdpSocket::bind(address).context(IoSnafu {
            path: "temporary UDP peer port",
        })?;
        let denied = TcpListener::bind(address).context(IoSnafu {
            path: "temporary denied peer port",
        })?;
        let tcp_port = tcp.local_addr().context(IoSnafu {
            path: "temporary TCP peer port",
        })?;
        let udp_port = udp.local_addr().context(IoSnafu {
            path: "temporary UDP peer port",
        })?;
        let ready = dir.path().join("ready");
        let output = dir.path().join("result.json");
        let server = NetworkPeerServer::from_sockets(tcp, udp, denied, &ready)?;
        let server_task = {
            let output = output.clone();
            thread::spawn(move || server.run_to(&output))
        };
        wait_for(
            &ready,
            "network peer readiness",
            Duration::from_secs(5),
            || Ok(ready.is_file().then_some(())),
            || "the ready file is absent".to_owned(),
        )?;
        TcpStream::connect(tcp_port)
            .context(IoSnafu {
                path: "temporary TCP peer",
            })?
            .write_all(NETWORK_PEER_TCP_PAYLOAD)
            .context(IoSnafu {
                path: "temporary TCP peer",
            })?;
        UdpSocket::bind(address)
            .context(IoSnafu {
                path: "temporary UDP peer",
            })?
            .send_to(NETWORK_PEER_UDP_PAYLOAD, udp_port)
            .context(IoSnafu {
                path: "temporary UDP peer",
            })?;
        let result = server_task.join().map_err(|_| crate::Error::Io {
            path: "network peer server thread".into(),
            source: io::Error::other("the thread panicked"),
            location: snafu::Location::default(),
        })??;
        assert!(result.tcp_payload_received);
        assert!(result.udp_payload_received);
        assert!(result.denied_connection_absent);
        assert!(!ready.exists());
        assert!(output.is_file());
        Ok(())
    }
}
