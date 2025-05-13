#[macro_use]
extern crate log;

use clap::Parser;

use pasque::{
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

    let mut psqserver = PsqServer::start(
        &args.address(),
        &config,
    ).await.unwrap();

    loop {
        if let Err(e) = psqserver.process().await {
            error!("PsqServer error: {}", e);
        }
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
}