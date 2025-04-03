#[macro_use]
extern crate log;

use quiche::ConnectionId;
use thiserror::Error;


const VERSION_IDENTIFICATION: &str = env!("CARGO_PKG_VERSION");


#[derive(Error, Debug)]
pub enum PsqError {

    #[error("HTTP/3 capsule error: {0}")]
    H3Capsule(String),

    #[error("Not supported: {0}")]
    NotSupported(String),

    #[error("HTTP response error: {0}")]
    HttpResponse(String),

    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("URL parse error: {0}")]
    UrlParse(#[from] url::ParseError),

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


pub mod args;
pub mod config;
pub mod connection;
pub mod filestream;
pub mod iptunnel;
pub mod server;
pub mod util;