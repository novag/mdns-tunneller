pub mod config;
pub mod mdns;
pub mod tunnel;

use anyhow::Result;
use async_channel::Receiver;
use clap::Parser;
use pnet::datalink::{self, NetworkInterface};
use std::sync::Arc;
use tokio::{net::TcpListener, sync::Mutex};
use tokio::{
    net::TcpStream,
    sync::mpsc::{self, UnboundedReceiver},
};
use tokio_util::codec::{Framed, LengthDelimitedCodec};
use tracing::{info, warn, Level};
use tunnel::TunnelPeer;

use crate::config::get_filter_domains;

#[derive(Parser)]
enum Args {
    Server {
        #[clap(short, long)]
        addr: String,
        #[clap(short, long)]
        interface: String,
        #[clap(short, long)]
        verbose: bool,
    },
    Client {
        #[clap(short, long)]
        addr: String,
        #[clap(short, long)]
        interface: String,
        #[clap(short, long)]
        verbose: bool,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    let args = Args::parse();
    let (is_client, addr, iface_name, verbose) = match args {
        Args::Server { addr, interface, verbose } => (false, addr, interface, verbose),
        Args::Client { addr, interface, verbose } => (true, addr, interface, verbose),
    };

    let max_level = if verbose { Level::DEBUG } else { Level::INFO };
    tracing_subscriber::fmt().with_max_level(max_level).init();
    info!(?is_client, ?addr, ?iface_name);

    let interface_names_match = |iface: &NetworkInterface| iface.name == iface_name;

    // Find the network interface with the provided name
    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(interface_names_match)
        .next()
        .unwrap_or_else(|| panic!("No such network interface: {}", iface_name));

    let (channel_tx, channel_rx) = mpsc::unbounded_channel();
    let (mdns_sender, mut mdns_listener) = mdns::pair(&interface, channel_tx, get_filter_domains());

    let mdns_sender = Arc::new(Mutex::new(mdns_sender));
    let channel_rx = forward(channel_rx);

    if is_client {
        tokio::task::spawn_blocking(move || mdns_listener.listen());

        let mut backoff = 1u64;
        loop {
            match TcpStream::connect(&addr).await {
                Ok(tcp) => {
                    info!("connected");
                    backoff = 1;
                    let tunnel = TunnelPeer {
                        mdns_sender: mdns_sender.clone(),
                        channel_rx: channel_rx.clone(),
                        tcp: Framed::new(tcp, LengthDelimitedCodec::new()),
                        socket_addr: None,
                    };
                    tunnel.select_run().await;
                    warn!("disconnected from server, reconnecting...");
                }
                Err(e) => {
                    warn!(?e, backoff_secs = backoff, "failed to connect, retrying...");
                }
            }
            tokio::time::sleep(std::time::Duration::from_secs(backoff)).await;
            backoff = (backoff * 2).min(30);
        }
    } else {
        let listener = TcpListener::bind(&addr).await?;
        info!("start listening");

        tokio::task::spawn_blocking(move || mdns_listener.listen());

        while let Ok((con, addr)) = listener.accept().await {
            info!(?addr, "connected");

            let mdns_sender = mdns_sender.clone();
            let channel_rx = channel_rx.clone();

            tokio::spawn(async move {
                let tunnel = TunnelPeer {
                    mdns_sender,
                    channel_rx,
                    tcp: Framed::new(con, LengthDelimitedCodec::new()),
                    socket_addr: Some(addr),
                };
                tunnel.select_run().await;
            });
        }
    }

    Ok(())
}

fn forward(mut sc_rx: UnboundedReceiver<Vec<u8>>) -> Receiver<Vec<u8>> {
    let (tx, rx) = async_channel::unbounded();
    tokio::spawn(async move {
        while let Some(packet) = sc_rx.recv().await {
            if tx.send(packet).await.is_err() {
                break;
            }
        }
    });
    rx
}
