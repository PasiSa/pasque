
extern crate log;

use pasque::server::PsqServer;


#[tokio::main]
async fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let mut args = std::env::args();

    let cmd = &args.next().unwrap();

    if args.len() != 0 {
        println!("Usage: {cmd}");
        println!("\nSee tools/apps/ for more complete implementations.");
        return;
    }

    let mut psqserver = PsqServer::start("0.0.0.0:4433").await;

    loop {
        psqserver.process().await;
    }
}
