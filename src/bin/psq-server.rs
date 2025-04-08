#[macro_use]
extern crate log;

use pasque::{
    server::{PsqServer, args::Args, config::Config},
    stream::iptunnel::IpEndpoint,
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
    // Server side of the tunnel has IP address 10.76.0.1. Clients are assigned IP
    // addresses in the 10.76.0.0/24 network, as deliver in ADDRESS_ASSIGN capsule
    // in CONNECT response.
    psqserver.add_endpoint("ip",
        IpEndpoint::new(
            "10.76.0.1/24",
            "tun-s",
        ).unwrap()
    ).await;

    // Loop forever to process incoming QUIC traffic.
    loop {
        psqserver.process().await.unwrap();
    }
}
