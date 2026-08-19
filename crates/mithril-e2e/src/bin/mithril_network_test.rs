use std::path::PathBuf;
use std::{net::IpAddr, path::Path};

use clap::{Parser, Subcommand};
use mithril_e2e::{
    run_effect_child, run_network_peer_server, NetworkPeerTargetV1, NetworkTestRunner, Result,
    NETWORK_PEER_DENIED_PORT, NETWORK_PEER_TCP_PORT, NETWORK_PEER_UDP_PORT,
};

#[derive(Parser)]
#[command(name = "mithril-network-test")]
struct Cli {
    #[arg(long, default_value = ".")]
    repo_root: PathBuf,
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    PhysicalProbe {
        #[arg(long)]
        output_directory: PathBuf,
        #[arg(long)]
        pin_root: PathBuf,
        #[arg(long)]
        lease_path: PathBuf,
        #[arg(long)]
        cgroup_path: PathBuf,
        #[arg(long)]
        peer_address: Option<IpAddr>,
        #[arg(long, default_value_t = NETWORK_PEER_TCP_PORT)]
        peer_tcp_port: u16,
        #[arg(long, default_value_t = NETWORK_PEER_UDP_PORT)]
        peer_udp_port: u16,
        #[arg(long, default_value_t = NETWORK_PEER_DENIED_PORT)]
        peer_denied_port: u16,
    },
    PeerServer {
        #[arg(long, default_value = "0.0.0.0")]
        bind_address: IpAddr,
        #[arg(long, default_value_t = NETWORK_PEER_TCP_PORT)]
        tcp_port: u16,
        #[arg(long, default_value_t = NETWORK_PEER_UDP_PORT)]
        udp_port: u16,
        #[arg(long, default_value_t = NETWORK_PEER_DENIED_PORT)]
        denied_port: u16,
        #[arg(long)]
        ready_path: PathBuf,
        #[arg(long)]
        output: PathBuf,
    },
    #[command(hide = true)]
    Child {
        #[arg(long)]
        fixture_root: PathBuf,
        #[arg(long)]
        mailbox_path: PathBuf,
    },
}

fn main() {
    if let Err(error) = run() {
        eprintln!("{error}");
        std::process::exit(1);
    }
}

fn run() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::PhysicalProbe {
            output_directory,
            pin_root,
            lease_path,
            cgroup_path,
            peer_address,
            peer_tcp_port,
            peer_udp_port,
            peer_denied_port,
        } => {
            let runner = NetworkTestRunner::new(cli.repo_root);
            let peer = peer_address.map(|address| NetworkPeerTargetV1 {
                address,
                tcp_port: peer_tcp_port,
                udp_port: peer_udp_port,
                denied_port: peer_denied_port,
            });
            let bundle = runner.physical_probe(
                &output_directory,
                &pin_root,
                &lease_path,
                &cgroup_path,
                peer,
            )?;
            runner.write_json(
                &output_directory.join("network-physical-probe.json"),
                &bundle,
            )?;
            println!("Mithril network physical probe passed");
            Ok(())
        }
        Command::PeerServer {
            bind_address,
            tcp_port,
            udp_port,
            denied_port,
            ready_path,
            output,
        } => {
            let result = run_network_peer_server(
                bind_address,
                tcp_port,
                udp_port,
                denied_port,
                &ready_path,
            )?;
            NetworkTestRunner::new(Path::new(".")).write_json(&output, &result)?;
            println!("Mithril network peer server passed");
            Ok(())
        }
        Command::Child {
            fixture_root,
            mailbox_path,
        } => run_effect_child(&fixture_root, &mailbox_path),
    }
}
