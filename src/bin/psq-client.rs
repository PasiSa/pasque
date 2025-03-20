
#[macro_use]
extern crate log;

use pasque::{
    args::Args,
    config::Config,
    session::PsqSession,
};


fn main() {
    env_logger::builder().format_timestamp_nanos().init();

    let args = Args::new();
    let config = match Config::read_from_file(args.config()) {
        Ok(c) => c,
        Err(e) => {
            warn!("Applying default configuration: {}", e);
            Config::create_default()
        }
    };

    // Setup the event loop.
    let mut poll = mio::Poll::new().unwrap();
    let mut events = mio::Events::with_capacity(1024);

    let mut session = PsqSession::connect(
        args.dest(),
        config,
    );

    loop {
        session.set_mio_poll(&poll);
        poll.poll(&mut events, session.get_timeout()).unwrap();

        session.process_events(&events);

        if session.connection().is_closed() {
            info!("connection closed, {:?}", session.connection().stats());
            break;
        }

        session.send_packets();

        if session.connection().is_closed() {
            info!("connection closed, {:?}", session.connection().stats());
            break;
        }
    }
}
