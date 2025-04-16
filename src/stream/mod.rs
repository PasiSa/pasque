use std::{
    any::Any,
    sync::Arc,
};

use async_trait::async_trait;
use quiche::h3::NameValue;
use tokio::{
    net::UdpSocket,
    sync::Mutex,
};

use crate::{
    client::PsqClient,
    PsqError,
    VERSION_IDENTIFICATION,
    util::MAX_DATAGRAM_SIZE,
};


pub (crate) enum Capsule {
    Datagram = 0x00,
    AddressAssign = 0x01,
}

#[async_trait]
/// Base trait for different tunnel/proxy stream types.
pub trait PsqStream: Any + Send + Sync {

    /// Process an incoming HTTP/3 datagram, content in `buf`.
    async fn process_datagram(&mut self, buf: &[u8]) -> Result<(), PsqError>;

    /// Returns true if the stream is ready to be used,
    /// after HTTP request and response have been processed.
    fn is_ready(&self) -> bool;

    fn as_any(&self) -> &dyn Any;

    async fn process_h3_response(
        &mut self,
        h3_conn: &mut quiche::h3::Connection,
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        event: quiche::h3::Event,
        buf: &mut [u8],
    ) -> Result<(), PsqError>;
}


/// Build headers for HTTP/3 requests. If `method` is "CONNECT", `protocol`` needs
/// to be specified. For other methods it can be empty string.
fn prepare_h3_request(
    method: &str,
    protocol: &str,
    url: &url::Url,
) -> Vec<quiche::h3::Header> {

    let mut path = String::from(url.path());

    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut headers = vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(
            b":authority",
            url.host_str().unwrap().as_bytes(),
        ),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(b"user-agent", format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes()),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    if !protocol.is_empty() {
        headers.push(quiche::h3::Header::new(b":protocol", protocol.as_bytes()));
    }

    headers

}


/// Currently accepts just HTTP/3 Datagram and returns just (stream_id, offset).
/// Context ID and capsule length are ignored.
pub (crate) fn process_h3_datagram(buf: &[u8]) -> Result<(u64, usize), PsqError>{
    let mut octets = octets::Octets::with_slice(buf);

    if octets.get_u8()? != Capsule::Datagram as u8 {
        // Not HTTP datagram
        return Err(PsqError::H3Capsule("Not HTTP Datagram".to_string()))
    }

    let _length = octets.get_varint()?;  // not in use at the moment

    let stream_id: u64 = octets.get_varint()? * 4;

    let _context_id = octets.get_varint()?;  // not in use at the moment

    Ok((stream_id, octets.off()))
}


/// Validate request header assuming a CONNECT request, and check that
/// `protocol` matches the header. Caller of the function calls it one
/// at a time, for each header received.
fn check_common_headers(
    header: &quiche::h3::Header,
    protocol: &str,
) -> Result<(), PsqError> {

    match header.name() {
        b":method" => {
            if header.value() != b"CONNECT" {
                return Err(PsqError::HttpResponse(
                    405,
                    "Only CONNECT method supported for this endpoint".to_string(),
                ))
            }
        },
        b":protocol" => {
            if header.value() != protocol.as_bytes() {
                return Err(PsqError::HttpResponse(
                    406,  // what would be a proper status code?
                    format!("Only protocol '{}' supported at this endpoint", protocol),
                ))
            }
        }
        b"capsule-protocol" => {
            if header.value() != b"?1" {
                return Err(PsqError::HttpResponse(
                    406,  // what would be a proper status code?
                    "Unsupported capsule protocol".to_string(),
                ))
            }
        }
        _ => {},
    }

    Ok(())
}


/// Extracts the HTTP/3 status code from the headers.
/// Returns the status code as u8 if found and valid, otherwise returns PsqError.
fn get_h3_status(headers: &[quiche::h3::Header]) -> Result<u16, PsqError> {
    for hdr in headers {
        if hdr.name() == b":status" {
            let status_str = String::from_utf8_lossy(hdr.value());
            return match status_str.parse::<u16>() {
                Ok(status) if status <= u16::MAX as u16 => Ok(status as u16),
                Ok(_) => Err(PsqError::HttpResponse(500, "Status code out of range".to_string())),
                Err(_) => Err(PsqError::HttpResponse(500, "Invalid :status header".to_string())),
            };
        }
    }
    Err(PsqError::HttpResponse(500, "Missing :status header".to_string()))
}


async fn start_connection<'a>(
    pconn: &'a mut PsqClient,
    url: &url::Url,
    protocol: &str,
) -> Result<u64, PsqError> {

    // TODO: unit test for unsupported protocol
    let req = prepare_h3_request(
        "CONNECT",
        protocol,
        &url,
    );
    info!("sending HTTP request {:?}", req);

    let a = pconn.connection();
    let mut conn = a.lock().await;
    let h3_conn = pconn.h3_connection().as_mut().unwrap();

    let stream_id = h3_conn
        .send_request(&mut *conn, &req, false)?;

    Ok(stream_id)
}


/// Sends one HTTP/3 Datagram Capsule.
fn send_h3_dgram(
    conn: &mut quiche::Connection,
    stream_id: u64,
    buf: &[u8],
) -> Result<(), PsqError> {
    
    // currently we limit to stream IDs of max 16383 * 4
    //let mut data: Vec<u8> = Vec::with_capacity(6 + buf.len());
    let mut data: [u8; MAX_DATAGRAM_SIZE] = [0; MAX_DATAGRAM_SIZE];
    let off = 6;

    {
        let mut octets = octets::OctetsMut::with_slice(data.as_mut_slice());

        octets.put_varint_with_len(Capsule::Datagram as u64, 1)?;

        // Datagram capsule length
        octets.put_varint_with_len(buf.len() as u64, 2)?;

        // Quarter stream ID
        // Currently supporting only 2-byte stream IDs, to be extended later
        octets.put_varint_with_len(stream_id / 4, 2)?;

        // Context ID = 0
        octets.put_varint_with_len(0, 1)?;
    }

    // Data
    let end = off + buf.len();
    data[off..end].copy_from_slice(buf);

    conn.dgram_send(&data[..end])?;
    Ok(())
}

pub mod iptunnel;
pub mod filestream;
pub mod udptunnel;
