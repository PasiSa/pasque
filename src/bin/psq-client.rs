
#[macro_use]
extern crate log;

use pasque::{
    client::{PsqClient, args::Args},
    stream::iptunnel::IpTunnel,
};

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();

    // Create an HTTP/3 connection to URL given on
    // command line `-d` or `--dest` argument.
    let mut psqconn = PsqClient::connect(
        args.dest(),
    ).await.unwrap();

    // Triggers a CONNECT request to "ip" endpoint at the server.
    // The call blocks until server has replied and tunnel is established.
    match IpTunnel::connect(&mut psqconn, "ip", "tun-c").await {
        Ok(iptunnel) => {
            info!("IpTunnel set up with local address {}", iptunnel.local_addr().unwrap());
        },
        Err(e) => {
            error!("Error connecting IpTunnel: {}", e);
            return;
        }
    }

    // Loop forever processing tunnel traffic between QUIC connection
    // and the TUN interface.
    while psqconn.process().await.is_ok() {
        // Just repeat until an error occurs
    }
}
