#[macro_use]
extern crate log;

use clap::Parser;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
};

use pasque::{server::Config, PsqServer};

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();

    let config = if let Some(config_path) = args.config_path() {
        Config::read_from_file(config_path).expect("unable to read config file")
    } else {
        warn!("No config specified, using default configuration.");
        Config::create_default()
    };

    let mut psqserver = PsqServer::start(&args.address(), &config).await.unwrap();

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
    #[arg(short, long, default_value = "0.0.0.0:443", value_delimiter = ' ', num_args = 1..)]
    address: Vec<SocketAddr>,

    /// Configuration file to read.
    #[arg(short, long)]
    config: Option<PathBuf>,
}

impl Args {
    pub fn new() -> Args {
        let args = Args::parse();

        args
    }

    pub fn address(&self) -> &Vec<SocketAddr> {
        &self.address
    }

    pub fn config_path(&self) -> Option<&Path> {
        self.config.as_ref().map(PathBuf::as_path)
    }
}
