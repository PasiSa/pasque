//! [Pasque] is an UDP over HTTP/3 ([RFC 9298]) and IP over HTTP/3
//! implementation ([RFC 9484]). Built using [Quiche] as the HTTP/3 & QUIC
//! implementation and [Tokio] for async operations. The project is yet under
//! construction, and some features from the RFCs are still missing.
//! 
//! [Pasque]: https://github.com/PasiSa/pasque
//! [Quiche]: https://crates.io/crates/quiche
//! [Tokio]: https://crates.io/crates/tokio
//! [RFC 9298]: https://datatracker.ietf.org/doc/html/rfc9298/
//! [RFC 9484]: https://datatracker.ietf.org/doc/html/rfc9484/
//! 
//! ## Starting a server
//! 
//! [psq-server.rs] is a simple example of a server implementation using Pasque.
//! For example, to start an UDP tunnel endpoint at path "udp", you could have:
//! 
//! ```no_run
//! use pasque::{server::Config, PsqServer, UdpEndpoint};
//! #[tokio::main]
//! async fn main() {
//!     let config = Config::read_from_file("server.json").unwrap();
//!     let mut psqserver = PsqServer::start("0.0.0.0:4433", &config).await.unwrap();
//!     psqserver.add_endpoint("udp", UdpEndpoint::new().unwrap()).await;
//! }
//! ```
//! 
//! (of course with proper error handling). First, certificate information is
//! read from a config file, then HTTP/3 / QUIC server is started, binding to
//! UDP port 4433. And a [`UdpEndpoint`] is added for proxying UDP datagrams.
//! [`IpEndpoint`] can be used for proxying IP packets from TUN interface (needs
//! sudo privilege, only tested on Linux for the time being).
//! 
//! [psq-server.rs]: https://github.com/PasiSa/pasque/blob/main/src/bin/psq-server.rs
//! 
//! ## Starting a client
//! 
//! [psq-client.rs] is an example of a client implementation using Pasque. To
//! match the above server example, a client-end of the UDP tunnel would be:
//!  
//! [psq-client.rs]: https://github.com/PasiSa/pasque/blob/main/src/bin/psq-client.rs
//!
//! ```no_run
//! use pasque::{PsqClient, UdpTunnel};
//! #[tokio::main]
//! async fn main() {
//!     let mut psqconn = PsqClient::connect("https://localhost:4433/", false).await.unwrap();
//!     let udptunnel = UdpTunnel::connect(
//!         &mut psqconn,
//!         "udp",
//!         "130.233.224.196", 9000,
//!         "127.0.0.1:0".parse().unwrap(),
//!     ).await.unwrap();
//!     println!("UDP datagrams to {} are forwarded to HTTP tunnel.", udptunnel.sockaddr().unwrap());
//! }
//! ```
//! 
//! The above first opens a HTTP/3 / QUIC connection to given server. Then UDP
//! tunnel is connected to "udp" endpoint, for destination address
//! 130.233.224.196, UDP port 9000. The client opens a local UDP socket that is
//! used to deliver packets to and from the the tunnel. User can specify the
//! address and port to bind, or if none is given, the bound address can be
//! queried using the [`UdpTunnel::sockaddr()`] function.
//! 
//! [`IpTunnel`] is available for establishing IP tunnels from TUN interface
//! (requires sudo privileges, tested only on Linux).

#[macro_use]
extern crate log;

use quiche::ConnectionId;
use thiserror::Error;

pub use crate::{
    client::PsqClient,
    server::PsqServer,
    stream::{
        iptunnel::{ IpTunnel, IpEndpoint },
        udptunnel::{ UdpTunnel, UdpEndpoint },
    },
};

const VERSION_IDENTIFICATION: &str = env!("CARGO_PKG_VERSION");


#[derive(Error, Debug)]
pub enum PsqError {

    #[error("HTTP/3 capsule error: {0}")]
    H3Capsule(String),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("HTTP response error: {0}")]
    HttpResponse(u16, String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

    #[error("IP Address parse error: {0}")]
    AddressParse(#[from] ipnetwork::IpNetworkError),

    #[error("QUIC error: {0}")]
    Quiche(#[from] quiche::Error),

    #[error("HTTP/3 error: {0}")]
    Http3(#[from] quiche::h3::Error),

    #[error("Octets buffer error: {0}")]
    Octets(#[from] octets::BufferTooShortError),

    #[error("TUN interface error: {0}")]
    Tun(#[from] tun::Error),

    #[error("UTF8 parsing error: {0}")]
    Utf8(#[from] std::str::Utf8Error),

    #[error("Custom error: {0}")]
    Custom(String),
}


pub fn set_qlog(conn: &mut quiche::Connection, scid: &ConnectionId<'_>) {
    if let Some(dir) = std::env::var_os("QLOGDIR") {
        let id = format!("{scid:?}");
        let writer = make_qlog_writer(&dir, "client", &id);

        conn.set_qlog(
            std::boxed::Box::new(writer),
            "quiche-client qlog".to_string(),
            format!("{} id={}", "quiche-client qlog", id),
        );
    }
}


fn make_qlog_writer(
    dir: &std::ffi::OsStr, role: &str, id: &str,
) -> std::io::BufWriter<std::fs::File> {
    let mut path = std::path::PathBuf::from(dir);
    let filename = format!("{role}-{id}.sqlog");
    path.push(filename);

    match std::fs::File::create(&path) {
        Ok(f) => std::io::BufWriter::new(f),

        Err(e) => panic!(
            "Error creating qlog file attempted path was {:?}: {}",
            path, e
        ),
    }
}


pub mod client;
pub mod server;
pub mod stream;

mod util;

pub mod test_utils;