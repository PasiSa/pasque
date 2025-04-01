
#[macro_use]
#[cfg(not(feature = "tuntest"))]
extern crate log;

#[cfg(not(feature = "tuntest"))]
use pasque::{
    args::Args, config::Config, connection::PsqConnection, iptunnel::IpTunnel,
};

#[tokio::main]
#[cfg(not(feature = "tuntest"))]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();
    let config = match Config::read_from_file(args.config()) {
        Ok(c) => c,
        Err(e) => {
            warn!("Applying default configuration: {}", e);
            Config::create_default()
        }
    };

    let mut psqconn = PsqConnection::connect(
        args.dest(),
        config,
    ).await.unwrap();

    let _iptunnel = IpTunnel::connect(&mut psqconn, "ip").await;

    while psqconn.process().await.is_ok() {
        // Just repeat until an error occurs
    }
}

#[cfg(feature = "tuntest")]
fn main() {
}
