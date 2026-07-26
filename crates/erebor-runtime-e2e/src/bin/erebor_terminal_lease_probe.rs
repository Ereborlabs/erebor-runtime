//! Privileged-test probe for the daemon's interactive input-lease boundary.
//!
//! This is not a user-facing command. The systemd fixture invokes it as an
//! ordinary admitted UID while another client owns the TTY lease.

use std::error::Error;

use clap::Parser;
use erebor_runtime_client::DaemonClient;
use erebor_runtime_ipc::v1::{
    SessionAttachRequest, SessionInputRequest, SessionTerminalResizeRequest,
};

#[derive(Parser)]
struct Arguments {
    session_id: String,
}

struct ObserverLeaseProbe {
    client: DaemonClient,
    session_id: String,
}

impl ObserverLeaseProbe {
    fn new(session_id: String) -> Self {
        Self {
            client: DaemonClient::local(),
            session_id,
        }
    }

    async fn prove_rejected(&self) -> Result<(), Box<dyn Error>> {
        let observer = self
            .client
            .session_attach(
                SessionAttachRequest {
                    session_id: self.session_id.clone(),
                    after_output_sequence: 0,
                    request_input_lease: false,
                    client_instance_id: String::from("phase4-tty-observer"),
                },
                "phase4-tty-observer-attach",
            )
            .await?;
        if !observer.read_only || !observer.input_lease_id.is_empty() {
            return Err("observer unexpectedly acquired an interactive input lease".into());
        }
        if self
            .client
            .session_input(SessionInputRequest {
                session_id: self.session_id.clone(),
                input_lease_id: String::from("observer-has-no-lease"),
                client_instance_id: String::from("phase4-tty-observer"),
                data: b"observer-write-must-not-reach-workload\n".to_vec(),
            })
            .await
            .is_ok()
        {
            return Err("observer interactive input reached the workload".into());
        }
        if self
            .client
            .session_terminal_resize(SessionTerminalResizeRequest {
                session_id: self.session_id.clone(),
                input_lease_id: String::from("observer-has-no-lease"),
                client_instance_id: String::from("phase4-tty-observer"),
                rows: 61,
                columns: 161,
            })
            .await
            .is_ok()
        {
            return Err("observer terminal resize reached the workload".into());
        }
        println!("observer_input=denied observer_resize=denied");
        Ok(())
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn Error>> {
    let arguments = Arguments::parse();
    ObserverLeaseProbe::new(arguments.session_id)
        .prove_rejected()
        .await
}
