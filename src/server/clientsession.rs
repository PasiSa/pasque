use std::{
    collections::HashMap,
    sync::Arc,
};

use quiche::h3::NameValue;
use tokio::{
    net::UdpSocket,
    sync::{watch, Mutex},
    time::Duration,
};

use crate::{
    PsqError,
    server::Endpoints,
    stream::{
        process_h3_datagram,
        PsqStream,
    },
    util::{
        build_h3_headers,
        build_h3_response,
        hdrs_to_strings,
    },
};


/// One client session at the server.
pub (crate) struct ClientSession {
    socket: Arc<UdpSocket>,
    conn: Arc<Mutex<quiche::Connection>>,
    http3_conn: Option<quiche::h3::Connection>,
    partial_responses: HashMap<u64, PartialResponse>,
    timeout_tx: watch::Sender<Option<Duration>>,
    streams: HashMap<u64, Box<dyn PsqStream>>,
    endpoints: Arc<Mutex<Endpoints>>,
}

impl ClientSession {
    pub (crate) fn new(
        socket: &Arc<UdpSocket>,
        conn: quiche::Connection,
        timeout_tx: watch::Sender<Option<Duration>>,
        endpoints: &Arc<Mutex<Endpoints>>,
    ) -> ClientSession {
        ClientSession {
            socket: Arc::clone(socket),
            conn: Arc::new(Mutex::new(conn)),
            http3_conn: None,
            partial_responses: HashMap::new(),
            timeout_tx: timeout_tx,
            streams: HashMap::new(),
            endpoints: Arc::clone(endpoints),
        }
    }


    pub (crate) fn connection(&self) -> &Arc<Mutex<quiche::Connection>> {
        &self.conn
    }


    pub (crate) fn h3_connection(&self) -> &Option<quiche::h3::Connection> {
        &self.http3_conn
    }

    pub (crate) async fn process_data(&mut self, pkt_buf: &mut [u8], recv_info: quiche::RecvInfo) {
        self.set_timeout().await;

        let mut conn = self.conn.lock().await;
        // Process potentially coalesced packets.
        let _read = match conn.recv(pkt_buf, recv_info) {
            Ok(v) => v,

            Err(e) => {
                error!("{} recv failed: {:?}", conn.trace_id(), e);
                return;
            },
        };

        // Create a new HTTP/3 connection as soon as the QUIC connection
        // is established.
        if (conn.is_in_early_data() || conn.is_established()) &&
            self.http3_conn.is_none()
        {
            debug!(
                "{} QUIC handshake completed, now trying HTTP/3",
                conn.trace_id()
            );

            let mut h3_config = quiche::h3::Config::new().unwrap();
            h3_config.enable_extended_connect(true);
            let h3_conn = match quiche::h3::Connection::with_transport(
                &mut conn,
                &h3_config,
            ) {
                Ok(v) => v,

                Err(e) => {
                    error!("failed to create HTTP/3 connection: {}", e);
                    return;
                },
            };

            // TODO: sanity check h3 connection before adding to map
            self.http3_conn = Some(h3_conn);
        }

        let mut buf = [0; 10000];  // TODO: change proper size
        match conn.dgram_recv(&mut buf) {
            Ok(n) => {
                debug!("Datagram received, {} bytes", n);
                let (stream_id, offset) = match process_h3_datagram(&buf) {
                    Ok((stream, off)) => (stream, off),
                    Err(e) => {
                        error!("Error processing HTTP/3 capsule: {}", e);
                        return;
                    },
                };

                let stream = self.streams.get_mut(&stream_id);
                if stream.is_none() {
                    warn!("Datagram received but no matching stream ID: {}", stream_id);
                } else {
                    if let Err(e) = stream.unwrap().process_datagram(&buf[offset..n]).await {
                        warn!("Error with received datagram: {}", e);
                    }
                }
            },
            Err(e) => {
                if e != quiche::Error::Done {
                    error!("Error receiving datagram: {}", e);
                }
            },
        }
    }


    pub (crate) async fn handle_h3_requests(&mut self) {
        self.handle_writable().await;

        // Process HTTP/3 events.
        loop {
            match self.poll_helper().await {
                Ok((
                    stream_id,
                    quiche::h3::Event::Headers { list, .. },
                )) => {
                    self.handle_request(stream_id, &list).await;
                },

                Ok((stream_id, quiche::h3::Event::Data)) => {
                    info!(
                        "{} got data on stream id {}",
                        self.conn.lock().await.trace_id(),
                        stream_id
                    );
                },

                Ok((_stream_id, quiche::h3::Event::Finished)) => (),

                Ok((_stream_id, quiche::h3::Event::Reset { .. })) => (),

                Ok((
                    _prioritized_element_id,
                    quiche::h3::Event::PriorityUpdate,
                )) => (),

                Ok((_goaway_id, quiche::h3::Event::GoAway)) => (),

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!(
                        "{} HTTP/3 error {:?}",
                        self.conn.lock().await.trace_id(),
                        e
                    );

                    break;
                },
            }
        }
    }


    /// Handles incoming HTTP/3 requests.
    async fn handle_request(
        &mut self, stream_id: u64, headers: &[quiche::h3::Header],
    ) {
        info!(
            "{} got request {:?} on stream id {}",
            self.conn.lock().await.trace_id(),
            hdrs_to_strings(headers),
            stream_id
        );

        // We decide the response based on headers alone, so stop reading the
        // request stream so that any body is ignored and pointless Data events
        // are not generated.
        self.conn.lock().await.stream_shutdown(stream_id, quiche::Shutdown::Read, 0)
            .unwrap();

        let (headers, body) = self.build_response(stream_id, headers).await;

        let conn = &mut self.conn.lock().await;
        let http3_conn = &mut self.http3_conn.as_mut().unwrap();
        match http3_conn.send_response(conn, stream_id, &headers, false) {
            Ok(v) => v,

            Err(quiche::h3::Error::StreamBlocked) => {
                let response = PartialResponse {
                    headers: Some(headers),
                    body,
                    written: 0,
                };

                self.partial_responses.insert(stream_id, response);
                return;
            },

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        }

        let written = match http3_conn.send_body(conn, stream_id, &body, true) {
            Ok(v) => v,

            Err(quiche::h3::Error::Done) => 0,

            Err(e) => {
                error!("{} stream send failed {:?}", conn.trace_id(), e);
                return;
            },
        };

        if written < body.len() {
            let response = PartialResponse {
                headers: None,
                body,
                written,
            };

            self.partial_responses.insert(stream_id, response);
        }
    }


    async fn poll_helper(&mut self) -> Result<(u64, quiche::h3::Event), quiche::h3::Error> {
        let mut conn = &mut *self.conn.lock().await;
        self.http3_conn.as_mut().unwrap().poll(&mut conn)
    }


    async fn set_timeout(&self) {
        let new_duration = self.conn.lock().await.timeout();
        let _ = self.timeout_tx.send(new_duration);
    }

    /// Handles newly writable streams.
    async fn handle_writable(&mut self) {
        let conn = &mut self.conn.lock().await;

        for stream_id in conn.writable() {
            let http3_conn = &mut self.http3_conn.as_mut().unwrap();

            if !self.partial_responses.contains_key(&stream_id) {
                return;
            }

            let resp = self.partial_responses.get_mut(&stream_id).unwrap();

            if let Some(ref headers) = resp.headers {
                match http3_conn.send_response(conn, stream_id, headers, false) {
                    Ok(_) => (),

                    Err(quiche::h3::Error::StreamBlocked) => {
                        return;
                    },

                    Err(e) => {
                        error!("{} stream send failed {:?}", conn.trace_id(), e);
                        return;
                    },
                }
            }

            resp.headers = None;

            let body = &resp.body[resp.written..];

            let written = match http3_conn.send_body(conn, stream_id, body, true) {
                Ok(v) => v,

                Err(quiche::h3::Error::Done) => 0,

                Err(e) => {
                    self.partial_responses.remove(&stream_id);

                    error!("{} stream send failed {:?}", conn.trace_id(), e);
                    return;
                },
            };

            resp.written += written;

            if resp.written == resp.body.len() {
                self.partial_responses.remove(&stream_id);
            }
        }
    }


    /// Builds an HTTP/3 response given a request.
    async fn build_response(
        &mut self,
        stream_id: u64,
        request: &[quiche::h3::Header],
    ) -> (Vec<quiche::h3::Header>, Vec<u8>) {

        let mut path = std::path::Path::new("");

        // Look for the request's path and method.
        for hdr in request {
            match hdr.name() {
                b":path" => {
                    let s = std::str::from_utf8(hdr.value());
                    if s.is_err() {
                        warn!("Invalid path");
                        return build_h3_response(400, "Invalid path!")
                    }
                    path = std::path::Path::new(s.unwrap())
                },
                _ => (),
            }
        }

        let ep = path.components().nth(1);
        if ep.is_none() {
            return build_h3_response(404, "Not Found (empty path)")
        }
        let string = ep.unwrap().as_os_str().to_string_lossy().to_string();
        match self.endpoints.lock().await.get_mut(&string) {
            Some(endpoint) => {
                let (status, body) = match endpoint.process_request(
                        request,
                        &self.conn,
                        &self.socket,
                        stream_id
                ).await {
                    Ok((stream, body)) => {
                        if stream.is_some() {
                            // In some cases we do not create a new stream,
                            // if the stream can be fully served right away.
                            self.streams.insert(stream_id, stream.unwrap());
                        }
                        (200, body)
                    },
                    Err(PsqError::HttpResponse(status, body)) => {
                        warn!("Http Response with error {}: {}", status, body);
                        (status, body.as_bytes().to_vec())
                    },
                    Err(e) => {
                        error!("Error processing request: {}", e);
                        (500, format!("Error processing request: {}", e).as_bytes().to_vec())
                    },
                };
                (build_h3_headers(status, &body), body)
            }
            None => {
                let body = format!("Not Found: {}", string).as_bytes().to_vec();
                (build_h3_headers(404, &body), body)
                }
        }
    }
}


struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body: Vec<u8>,
    written: usize,
}
