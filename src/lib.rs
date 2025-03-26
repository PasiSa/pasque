#[macro_use]
extern crate log;

use quiche::ConnectionId;


pub fn process_connect(_request: &[quiche::h3::Header]) -> (Vec<quiche::h3::Header>, Vec<u8>) {
    debug!("CONNECT received!");
    let (status, body) = (200, Vec::from("Moi".as_bytes()));

    // TODO: parse request

    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(b"server", b"quiche"),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(
            b"content-length",
            body.len().to_string().as_bytes(),
        ),
    ];
    (headers, body)
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
pub mod server;
pub mod stream;
pub mod util;