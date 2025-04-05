
extern crate log;

use pasque::{
    server::PsqServer,
    stream::iptunnel::IpEndpoint,
};


#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut psqserver = PsqServer::start("0.0.0.0:4433").await.unwrap();
    psqserver.add_endpoint("ip",
        IpEndpoint::new(
            "10.76.0.1/24",
            "tun-s",
        ).unwrap()
    ).await;

    loop {
        psqserver.process().await.unwrap();
    }
}
