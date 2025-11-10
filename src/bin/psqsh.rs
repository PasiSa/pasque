#[macro_use]
extern crate log;

use clap::Parser;

use pasque::PtyClient;

#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();

    let mut ptyclient = PtyClient::connect(
        args.dest(),
        args.ignore_cert(),
        args.token(),
        "pty",
        args.command(),
        Box::new(tokio::io::stdout()),
        Some(Box::new(tokio::io::stdin())),
    )
    .await
    .unwrap();

    debug!("ptystream set up");

    while ptyclient.process().await.is_ok() {
        // Just repeat until error occurs
    }
}

#[derive(Parser, Debug)]
#[command(version, about, long_about = None)]
pub struct Args {
    /// Command to execute at remote terminal.
    #[arg(short, long, default_value = "bash")]
    command: String,

    /// URL to connect.
    #[arg(short, long)]
    dest: String,

    /// Do not verify the certificate from server. Use only for development!
    #[arg(long, action = clap::ArgAction::SetTrue)]
    ignore_cert: bool,

    /// Optional JWT token to authenticate the client
    #[arg(long)]
    token: Option<String>,
}

impl Args {
    pub fn new() -> Args {
        let args = Args::parse();

        args
    }

    pub fn command(&self) -> &String {
        &self.command
    }

    pub fn dest(&self) -> &String {
        &self.dest
    }

    pub fn ignore_cert(&self) -> bool {
        self.ignore_cert
    }

    pub fn token(&self) -> Option<&String> {
        self.token.as_ref()
    }
}
