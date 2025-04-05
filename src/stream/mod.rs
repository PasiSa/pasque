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
    PsqError,
    VERSION_IDENTIFICATION,
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
pub (crate) fn prepare_h3_request(
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
pub(crate) fn process_h3_datagram(buf: &[u8]) -> Result<(u64, usize), PsqError>{
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


/// Validate request headers assuming a CONNECT request, and check that
/// `protocol` matches the header.
pub (crate) fn check_request_headers(
    request: &[quiche::h3::Header],
    protocol: &str,
) -> Result<(), PsqError> {

    for hdr in request {
        match hdr.name() {
            b":method" => {
                if hdr.value() != b"CONNECT" {
                    return Err(PsqError::HttpResponse(
                        405,
                        "Only CONNECT method suppored for this endpoint".to_string(),
                    ))
                }
            },
            b":protocol" => {
                if hdr.value() != protocol.as_bytes() {
                    return Err(PsqError::HttpResponse(
                        406,  // what would be a proper status code?
                        format!("Only protocol '{}' supported at this endpoint", protocol),
                    ))
                }
            }
            b"capsule-protocol" => {
                if hdr.value() != b"?1" {
                    return Err(PsqError::HttpResponse(
                        406,  // what would be a proper status code?
                        "Unsupported capsule protocol".to_string(),
                    ))
                }
            }
            _ => {},
        }
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

pub mod iptunnel;
pub mod filestream;
