
#[macro_use]
extern crate log;

use pasque::{
    args::Args, config::Config, connection::PsqConnection,
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

    let psqconn = PsqConnection::connect(
        args.dest(),
        config,
    ).await;

    loop {
        let mut conn = psqconn.lock().await;
        conn.process().await;
    }
}
