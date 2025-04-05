
#[macro_use]
extern crate log;

use pasque::{
    args::Args,
    connection::PsqConnection,
    stream::iptunnel::IpTunnel,
};

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();

    let mut psqconn = PsqConnection::connect(
        args.dest(),
    ).await.unwrap();

    match IpTunnel::connect(&mut psqconn, "ip", "tun-c").await {
        Ok(iptunnel) => {
            info!("IpTunnel set up with local address {}", iptunnel.local_addr().unwrap());
        },
        Err(e) => {
            error!("Error connecting IpTunnel: {}", e);
            return;
        }
    }

    while psqconn.process().await.is_ok() {
        // Just repeat until an error occurs
    }
}
