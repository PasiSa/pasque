#[macro_use]
extern crate log;

use quiche::ConnectionId;
use quiche::h3::NameValue;


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


// Sends one HTTP/3 datagram
pub fn send_h3_dgram(conn: &mut quiche::Connection, stream_id: u64, buf: &[u8]) -> Result<(), String> {
    // TODO: real, efficient implementation
    
    // Quarter stream ID
    let mut data = make_varint(stream_id);
    
    // Context ID = 0
    data.push(0);

    // Data
    data.extend(buf);

    conn.dgram_send(&data).unwrap();
    Ok(())
}


fn make_varint(i: u64) -> Vec<u8> {
    // TODO: real implementation
    let ret: u8 = (i % 63) as u8;
    vec![ret]
}


pub fn hdrs_to_strings(hdrs: &[quiche::h3::Header]) -> Vec<(String, String)> {
    hdrs.iter()
        .map(|h| {
            let name = String::from_utf8_lossy(h.name()).to_string();
            let value = String::from_utf8_lossy(h.value()).to_string();

            (name, value)
        })
        .collect()
}


pub mod args;
pub mod config;
pub mod session;
