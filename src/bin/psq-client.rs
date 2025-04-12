
#[macro_use]
extern crate log;

use clap::Parser;

use pasque::{
    client::PsqClient,
    stream::{iptunnel::IpTunnel, udptunnel::UdpTunnel},
};

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();

    // Create an HTTP/3 connection to URL given on
    // command line `-d` or `--dest` argument.
    let mut psqconn = PsqClient::connect(
        args.dest(),
        args.ignore_cert(),
    ).await.unwrap();

    // Triggers a CONNECT request to "ip" endpoint at the server.
    // The call blocks until server has replied and tunnel is established.
    if args.ip() {
        match IpTunnel::connect(&mut psqconn,
            "ip",
            "tun-c",
        ).await {
            Ok(iptunnel) => {
                info!("IpTunnel set up with local address {}", iptunnel.local_addr().unwrap());
            },
            Err(e) => {
                error!("Error connecting IpTunnel: {}", e);
                return;
            }
        }
    }

    // Make CONNECT request for UDP tunnel at "udp" endpoint, for UDP socket at
    // 127.0.0.1, port 9000. Creates a local socket from which data is forwarded
    // to HTTP tunnel.
    let udptunnel = UdpTunnel::connect(
        &mut psqconn,
        "udp",
        "127.0.0.1",
        9000,
        "127.0.0.1:0".parse().unwrap(),
    ).await.unwrap();

    println!(
        "UDP datagrams to {} are forwarded to HTTP tunnel.",
        udptunnel.sockaddr().unwrap(),
    );

    // Loop forever processing tunnel traffic between QUIC connection
    // and the TUN interface.
    while psqconn.process().await.is_ok() {
        // Just repeat until an error occurs
    }
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Configuration file to read.
    #[arg(short, long, default_value = "config.json")]
    config: String,

    /// URL to connect.
    #[arg(short, long)]
    dest: String,

    /// Do not verify the certificate from server. Use only for development!
    #[arg(long, action = clap::ArgAction::SetTrue)]
    ignore_cert: bool,

    /// If set, request an IP tunnel from server
    #[arg(short, long, action = clap::ArgAction::SetTrue)]
    ip: bool,
}


impl Args {
    pub fn new() -> Args {
        let args = Args::parse();

        args
    }

    pub fn config(&self) -> &String {
        &self.config
    }

    pub fn dest(&self) -> &String {
       &self.dest
    }

    pub fn ignore_cert(&self) -> bool {
        self.ignore_cert
    }

    pub fn ip(&self) -> bool {
        self.ip
    }
}
