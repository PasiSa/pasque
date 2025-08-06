//! The client and server side logic for different types of tunnel endpoints
//!
//! In addition to MASQUE tunnels based on CONNECT, there is a simple endpoint
//! for sharing files. Designed to be generic based on [PsqStream] trait that
//! represents one kind of tunnel between client and server.

use std::{any::Any, sync::Arc};

use async_trait::async_trait;
use quiche::h3::{Header, NameValue};
use tokio::{net::UdpSocket, sync::Mutex};

use crate::{
    client::PsqClient, jwt::Jwt, util::MAX_DATAGRAM_SIZE, PsqError, VERSION_IDENTIFICATION,
};

pub(crate) enum Capsule {
    AddressAssign = 0x01,
    RouteAdvertisement = 0x03,
}

impl TryFrom<u64> for Capsule {
    type Error = PsqError;

    fn try_from(value: u64) -> Result<Self, Self::Error> {
        match value {
            0x01 => Ok(Capsule::AddressAssign),
            0x03 => Ok(Capsule::RouteAdvertisement),
            _ => Err(PsqError::H3Capsule(format!(
                "Unknown capsule type: {}",
                value
            ))),
        }
    }
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

    /// Process headers from HTTP/3 response at the client.
    ///
    /// Status is parsed already earlier. Only headers specific to the current
    /// type of stream should be processed. `list` contains incoming headers.
    fn process_h3_headers(
        &mut self,
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        list: &Vec<Header>,
    ) -> Result<(), PsqError>;

    /// Process HTTP/3 response data following the headers at the client.
    ///
    /// This is only called if the status code in response was 200 OK. In other
    /// cases, The calling function does the error processing.
    async fn process_h3_response(
        &mut self,
        h3_conn: &Arc<Mutex<quiche::h3::Connection>>,
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        buf: &mut [u8],
    ) -> Result<(), PsqError>;

    /// Process stream data after connect. Both ends.
    async fn process_data(&mut self, buf: &[u8]) -> Result<(), PsqError>;

    /// Stream ID of the CONNECT request that initiated this tunnel or proxy session.
    ///
    /// The stream remains open until the tunnel is closed, as required by RFC.
    fn stream_id(&self) -> u64;
}

/// Build headers for HTTP/3 requests. If `method` is "CONNECT", `protocol`` needs
/// to be specified. For other methods it can be empty string.
fn prepare_h3_request(
    method: &str,
    protocol: &str,
    url: &url::Url,
    token: &Option<String>,
) -> Vec<quiche::h3::Header> {
    let mut path = String::from(url.path());

    if let Some(query) = url.query() {
        path.push('?');
        path.push_str(query);
    }

    let mut headers = vec![
        quiche::h3::Header::new(b":method", method.as_bytes()),
        quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
        quiche::h3::Header::new(b":authority", url.host_str().unwrap().as_bytes()),
        quiche::h3::Header::new(b":path", path.as_bytes()),
        quiche::h3::Header::new(
            b"user-agent",
            format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes(),
        ),
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
    ];
    if !protocol.is_empty() {
        headers.push(quiche::h3::Header::new(b":protocol", protocol.as_bytes()));
    }
    if let Some(token) = token {
        headers.push(quiche::h3::Header::new(
            b"authorization",
            format!("Bearer {}", token).as_bytes(),
        ));
    }

    headers
}

/// Currently accepts just HTTP/3 Datagram and returns just (stream_id, offset).
/// Context ID and capsule length are ignored.
pub(crate) fn process_h3_datagram(buf: &[u8]) -> Result<(u64, usize), PsqError> {
    let mut octets = octets::Octets::with_slice(buf);

    let stream_id: u64 = octets.get_varint()? * 4;

    let _context_id = octets.get_varint()?; // not in use at the moment

    Ok((stream_id, octets.off()))
}

/// Validate request header assuming a CONNECT request, and check that
/// `protocol` matches the header. Caller of the function calls it one
/// at a time, for each header received.
fn check_common_headers(header: &quiche::h3::Header, protocol: &str) -> Result<(), PsqError> {
    match header.name() {
        b":method" => {
            if header.value() != b"CONNECT" {
                return Err(PsqError::HttpResponse(
                    405,
                    "Only CONNECT method supported for this endpoint".to_string(),
                ));
            }
        }
        b":protocol" => {
            if header.value() != protocol.as_bytes() {
                return Err(PsqError::HttpResponse(
                    406, // what would be a proper status code?
                    format!("Only protocol '{}' supported at this endpoint", protocol),
                ));
            }
        }
        b"capsule-protocol" => {
            if header.value() != b"?1" {
                return Err(PsqError::HttpResponse(
                    406, // what would be a proper status code?
                    "Unsupported capsule protocol".to_string(),
                ));
            }
        }
        _ => {}
    }

    Ok(())
}

/// Check if this is "authorization" header, in that case validate the JWT token
/// in header. `permission` is the required permission label that should be included
/// in token claims. `jwt_secret` is the secret used to decode the token.
fn check_authorized(
    header: &quiche::h3::Header,
    permission: &String,
    jwt_secret: &Vec<u8>,
) -> Result<bool, PsqError> {
    if header.name() == b"authorization" {
        let value = String::from_utf8_lossy(header.value());
        if let Some(token) = value.strip_prefix("Bearer ") {
            match Jwt::verify_token(token, jwt_secret) {
                Ok(token) => {
                    if token.claims.has_permission(permission) {
                        info!("Received valid token: {:?}", token.claims);
                        return Ok(true);
                    } else {
                        info!(
                            "Received token with insufficient permissions: {:?}",
                            token.claims
                        );
                        return Err(PsqError::HttpResponse(403, "Permission denied".to_string()));
                    }
                }
                Err(err) => {
                    warn!("Received invalid JWT token");
                    return Err(PsqError::HttpResponse(
                        401,
                        format!("Invalid token: {}", err),
                    ));
                }
            }
        }
    }
    Ok(false)
}

async fn start_connection<'a>(
    pconn: &'a mut PsqClient,
    url: &url::Url,
    protocol: &str,
) -> Result<u64, PsqError> {
    // TODO: unit test for unsupported protocol
    let req = prepare_h3_request("CONNECT", protocol, &url, pconn.token());
    info!("sending HTTP request {:?}", req);

    let a = pconn.connection();
    let mut conn = a.lock().await;
    let b = pconn.h3_connection().as_ref().unwrap();
    let mut h3_conn = b.lock().await;

    let stream_id = h3_conn.send_request(&mut *conn, &req, false)?;

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
    let off = 3;

    {
        let mut octets = octets::OctetsMut::with_slice(data.as_mut_slice());

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

pub mod filestream;
pub mod iptunnel;
pub mod pty;
mod terminal;
mod terminal_unix;
pub mod udptunnel;
