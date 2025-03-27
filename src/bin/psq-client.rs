
#[macro_use]
extern crate log;

use pasque::{
    args::Args, config::Config, connection::PsqConnection, stream::IpStream,
};

#[tokio::main]
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
    ).await;

    let _ipstream = IpStream::connect(&mut psqconn, "ip").await;

    loop {
        psqconn.process().await;
    }
}
