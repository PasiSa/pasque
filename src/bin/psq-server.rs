#[macro_use]
extern crate log;

use std::net::IpAddr;

use clap::Parser;

use pasque::{
    UdpEndpoint,
    IpEndpoint,
    PsqServer,
    server::Config,
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
        &args.address(),
        &config,
    ).await.unwrap();

    // Add "ip" endpoint that opens a IP tunnel for incoming CONNECT requests.
    // For example, if you start server with option `--ip 10.76.0.1/24`, the
    // server side of the tunnel has IP address 10.76.0.1, and clients are
    // assigned IP addresses in the 10.76.0.0/24 network, as deliver in
    // ADDRESS_ASSIGN capsule in CONNECT response.
    if args.ip().len() > 0 {
        let mut ip_endpoint = IpEndpoint::new(
            args.ip().as_str().parse().expect("Invalid IP"),
            "tun-s"
        ).unwrap();
        
        // This is just a temporary demonstrator of how add_route works.
        // It will be removed a bit later.
        ip_endpoint.add_route(
            &"10.76.0.1".parse::<IpAddr>().unwrap(),
            &"10.76.0.255".parse::<IpAddr>().unwrap(),
        ).unwrap();

        ip_endpoint.add_route(
            &"1.1.1.1".parse::<IpAddr>().unwrap(),
            &"1.1.1.255".parse::<IpAddr>().unwrap(),
        ).unwrap();

        ip_endpoint.add_addresspool("fd76:0212:dead::1/48".parse().unwrap()).unwrap();

        ip_endpoint.add_route(
            &"fd76:0212:dead::1".parse::<IpAddr>().unwrap(),
            &"fd76:0212:dead::ffff:ffff:ffff".parse::<IpAddr>().unwrap(),
        ).unwrap();

        psqserver.add_endpoint("ip", Box::new(ip_endpoint)).await;
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
    /// Local IP address and UDP port to bind.
    #[arg(short, long, default_value = "0.0.0.0:443")]
    address: String,

    /// Configuration file to read.
    #[arg(short, long, default_value = "src/bin/server-example.json")]
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

    pub fn address(&self) -> &String {
        &self.address
    }

    pub fn config(&self) -> &String {
        &self.config
    }

    pub fn ip(&self) -> &String {
        &self.ip
    }
}