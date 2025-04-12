#[macro_use]
extern crate log;

use clap::Parser;

use pasque::{
    server::{
        config::Config,
        PsqServer
    },
    stream::{
        iptunnel::IpEndpoint,
        udptunnel::UdpEndpoint
    },
};


#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();
    let config = match Config::read_from_file(args.config()) {
        Ok(c) => c,
        Err(e) => {
            warn!(
                "Could not read config '{}': {}. Applying default configuration.",
                args.config(),
                e,
            );
            Config::create_default()
        }
    };

    // Start server, bind to IPv4 any address, listen to UDP port 4433.
    let mut psqserver = PsqServer::start(
        "0.0.0.0:4433",
        &config,
    ).await.unwrap();

    // Add "ip" endpoint that opens a IP tunnel for incoming CONNECT requests.
    // For example, if you start server with option `--ip 10.76.0.1/24`, the
    // server side of the tunnel has IP address 10.76.0.1, and clients are
    // assigned IP addresses in the 10.76.0.0/24 network, as deliver in
    // ADDRESS_ASSIGN capsule in CONNECT response.
    if args.ip().len() > 0 {
        psqserver.add_endpoint("ip",
            IpEndpoint::new(
                args.ip(),
                "tun-s",
            ).unwrap()
        ).await;
    }

    // Add "udp" endpoint for proxying UDP sessions. 
    psqserver.add_endpoint("udp",
        UdpEndpoint::new().unwrap()
    ).await;

    // Loop forever to process incoming QUIC traffic.
    loop {
        psqserver.process().await.unwrap();
    }
}


#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Configuration file to read.
    #[arg(short, long, default_value = "server.json")]
    config: String,

    /// IP prefix of IP tunnel endpoint. If not given, IP tunnel is not started.
    #[arg(short, long, default_value = "")]
    ip: String,
}


impl Args {
    pub fn new() -> Args {
        let args = Args::parse();

        args
    }

    pub fn config(&self) -> &String {
        &self.config
    }

    pub fn ip(&self) -> &String {
        &self.ip
    }
}