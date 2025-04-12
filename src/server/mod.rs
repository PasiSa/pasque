use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use quiche::h3::NameValue;
use ring::rand::SystemRandom;
use tokio::{
    net::UdpSocket,
    sync::{watch, Mutex},
    time::Duration,
};

use crate::{
    PsqError,
    server::config::Config,
    stream::{
        process_h3_datagram,
        PsqStream,
    },
    util::{
        MAX_DATAGRAM_SIZE,
        build_h3_headers,
        build_h3_response,
        hdrs_to_strings,
        send_quic_packets,
        timeout_watcher,
    },
    VERSION_IDENTIFICATION,
};


type ClientMap = HashMap<quiche::ConnectionId<'static>, Client>;


/// The main server that listens to incoming connections.
pub struct PsqServer {
    socket: Arc<UdpSocket>,
    qconfig: quiche::Config,
    conn_id_seed: ring::hmac::Key,
    clients: ClientMap,
    endpoints: Arc<Mutex<Endpoints>>,
}

impl PsqServer {

    /// Configure and start the server at given address and port.
    pub async fn start(address: &str, config: &Config) -> Result<PsqServer, PsqError> {
        info!("Pasque server version {} starting", VERSION_IDENTIFICATION);
        let socket =
            tokio::net::UdpSocket::bind(address).await?;

        // Create the configuration for the QUIC connections.
        let mut qconfig = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        debug!("Loading cert from: {}", config.cert_file());
        qconfig
            .load_cert_chain_from_pem_file(&config.cert_file())?;
        debug!("Loading key from: {}", config.key_file());
        qconfig
            .load_priv_key_from_pem_file(&config.key_file())?;

        qconfig
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

        // TODO: need idle timeout and have some keep-alive to clean up disappeared clients
        //config.set_max_idle_timeout(5000);
        qconfig.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        qconfig.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        qconfig.set_initial_max_data(10_000_000);
        qconfig.set_initial_max_stream_data_bidi_local(1_000_000);
        qconfig.set_initial_max_stream_data_bidi_remote(1_000_000);
        qconfig.set_initial_max_stream_data_uni(1_000_000);
        qconfig.set_initial_max_streams_bidi(100);
        qconfig.set_initial_max_streams_uni(100);
        qconfig.set_disable_active_migration(true);
        qconfig.enable_early_data();

        qconfig.enable_dgram(true, 30000, 30000);

        let rng = SystemRandom::new();
        let conn_id_seed =
            ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        Ok( PsqServer {
            socket: Arc::new(socket),
            qconfig,
            conn_id_seed,
            clients: ClientMap::new(),
            endpoints: Arc::new(Mutex::new(HashMap::new())),
        })
    }


    pub async fn process(&mut self) -> Result<(), PsqError> {
        let mut buf = [0; 65535];

        //let (len, from) = self.socket.recv_from(&mut buf).await?;
        let (len, from) = match self.socket.recv_from(&mut buf).await {
            Ok(v) => v,

            Err(e) => {
                error!("recv() failed: {:?}", e);
                return Err(PsqError::Io(e))
            },
        };

        let pkt_buf = &mut buf[..len];

        // Parse the QUIC packet's header.
        let hdr = match quiche::Header::from_slice(
            pkt_buf,
            quiche::MAX_CONN_ID_LEN,
        ) {
            Ok(v) => v,

            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                return Err(PsqError::Quiche(e))
            },
        };

        trace!("got packet {:?}", hdr);

        let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
        let conn_id = conn_id.to_vec().into();

        // Lookup a connection based on the packet's connection ID. If there
        // is no connection matching, create a new one.
        let client = if !self.clients.contains_key(&hdr.dcid) &&
            !self.clients.contains_key(&conn_id)
        {
            let mut out = [0; MAX_DATAGRAM_SIZE];

            if hdr.ty != quiche::Type::Initial {
                error!("Packet is not Initial");
                return Err(PsqError::Custom("Packet not initial".to_string()))
            }

            if !quiche::version_is_supported(hdr.version) {
                warn!("Doing version negotiation");

                let len =
                    quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out)
                        .unwrap();

                let out = &out[..len];

                if let Err(e) = self.socket.send_to(out, from).await {
                    error!("send() failed: {:?}", e);
                    return Err(PsqError::Io(e))
                }
                return Ok(())
            }

            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            scid.copy_from_slice(&conn_id);

            let scid = quiche::ConnectionId::from_ref(&scid);

            // Token is always present in Initial packets.
            let token = hdr.token.as_ref().unwrap();

            // Do stateless retry if the client didn't send a token.
            if token.is_empty() {
                warn!("Doing stateless retry");

                let new_token = Self::mint_token(&hdr, &from);

                let len = quiche::retry(
                    &hdr.scid,
                    &hdr.dcid,
                    &scid,
                    &new_token,
                    hdr.version,
                    &mut out,
                )
                .unwrap();

                let out = &out[..len];

                if let Err(e) = self.socket.send_to(out, from).await {
                    error!("send() failed: {:?}", e);
                    return Err(PsqError::Io(e))
                }
                return Ok(())
            }

            let odcid = Self::validate_token(&from, token);

            // The token was not valid, meaning the retry failed, so
            // drop the packet.
            if odcid.is_none() {
                error!("Invalid address validation token");
                return Err(PsqError::Custom("Invalid address validation token".to_string()))
            }

            if scid.len() != hdr.dcid.len() {
                error!("Invalid destination connection ID");
                return Err(PsqError::Custom("Invalid destination connection ID".to_string()))
            }

            // Reuse the source connection ID we sent in the Retry packet,
            // instead of changing it again.
            let scid = hdr.dcid.clone();

            debug!("New connection: dcid={:?} scid={:?}", hdr.dcid, scid);

            let local_addr = self.socket.local_addr().unwrap();
            let conn = quiche::accept(
                &scid,
                odcid.as_ref(),
                local_addr,
                from,
                &mut self.qconfig,
            )
            .unwrap();

            let (tx, rx) = watch::channel(conn.timeout());
            let client = Client {
                socket: Arc::clone(&self.socket),
                conn: Arc::new(Mutex::new(conn)),
                http3_conn: None,
                partial_responses: HashMap::new(),
                timeout_tx: tx,
                streams: HashMap::new(),
                endpoints: Arc::clone(&self.endpoints),
            };
            timeout_watcher(
                Arc::clone(&client.conn),
                Arc::clone(&self.socket),
                rx,
            );

            self.clients.insert(scid.clone(), client);
            self.clients.get_mut(&scid).unwrap()
        } else {
            match self.clients.get_mut(&hdr.dcid) {
                Some(v) => v,

                None => self.clients.get_mut(&conn_id).unwrap(),
            }
        };

        let recv_info = quiche::RecvInfo {
            to: self.socket.local_addr().unwrap(),
            from,
        };

        client.process_data(pkt_buf, recv_info).await;

        if client.http3_conn.is_some() {
            client.handle_h3_requests().await;
        }

        self.send_packets().await;

        // Garbage collect closed connections.
        self.collect_garbage().await;

        Ok(())
    }


    /// Add new endpoint to the server with given path.
    pub async fn add_endpoint(&mut self, path: &str, endpoint: Box<dyn Endpoint>) {
        self.endpoints.lock().await.insert(path.to_string(), endpoint);
    }


    async fn collect_garbage(&mut self) {
        let mut remove_keys = Vec::new();
    
        for (key, client) in &self.clients {
            let conn = client.conn.lock().await;
            if conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    conn.trace_id(),
                    conn.stats()
                );
                remove_keys.push(key.clone()); // assuming K: Clone
            }
        }
    
        for key in remove_keys {
            self.clients.remove(&key);
        }
    }


    async fn send_packets(&mut self) {
        // Generate outgoing QUIC packets for all active connections and send
        // them on the UDP socket, until quiche reports that there are no more
        // packets to be sent.
        for client in self.clients.values_mut() {
            if let Err(e) = send_quic_packets(&client.conn, &self.socket).await {
                error!("Error sending packets: {}", e);
                // TODO: Close client connection
            }
        }
    }


    /// This is taken from Quiche examples, and should be replaced, as said below
    /// 
    /// Generate a stateless retry token.
    ///
    /// The token includes the static string `"quiche"` followed by the IP address
    /// of the client and by the original destination connection ID generated by the
    /// client.
    ///
    /// Note that this function is only an example and doesn't do any cryptographic
    /// authenticate of the token. *It should not be used in production system*.
    fn mint_token(hdr: &quiche::Header, src: &SocketAddr) -> Vec<u8> {
        let mut token = Vec::new();

        token.extend_from_slice(b"quiche");

        let addr = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        token.extend_from_slice(&addr);
        token.extend_from_slice(&hdr.dcid);

        token
    }


    /// This is taken from Quiche examples, and should be replaced, as said below
    /// 
    /// Validates a stateless retry token.
    ///
    /// This checks that the ticket includes the `"quiche"` static string, and that
    /// the client IP address matches the address stored in the ticket.
    ///
    /// Note that this function is only an example and doesn't do any cryptographic
    /// authenticate of the token. *It should not be used in production system*.
    fn validate_token<'a>(
        src: &SocketAddr, token: &'a [u8],
    ) -> Option<quiche::ConnectionId<'a>> {
        if token.len() < 6 {
            return None;
        }

        if &token[..6] != b"quiche" {
            return None;
        }

        let token = &token[6..];

        let addr = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        if token.len() < addr.len() || &token[..addr.len()] != addr.as_slice() {
            return None;
        }

        Some(quiche::ConnectionId::from_ref(&token[addr.len()..]))
    }
}


struct PartialResponse {
    headers: Option<Vec<quiche::h3::Header>>,
    body: Vec<u8>,
    written: usize,
}


type Endpoints = HashMap<String, Box<dyn Endpoint>>;

/// One client session at the server.
struct Client {
    socket: Arc<UdpSocket>,
    conn: Arc<Mutex<quiche::Connection>>,
    http3_conn: Option<quiche::h3::Connection>,
    partial_responses: HashMap<u64, PartialResponse>,
    timeout_tx: watch::Sender<Option<Duration>>,
    streams: HashMap<u64, Box<dyn PsqStream>>,
    endpoints: Arc<Mutex<Endpoints>>,
}

impl Client {
    async fn process_data(&mut self, pkt_buf: &mut [u8], recv_info: quiche::RecvInfo) {
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


    async fn handle_h3_requests(&mut self) {
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


#[async_trait]
/// Base trait for different Endpoint types at the server.
pub trait Endpoint: Send + Sync {

    /// Process incoming HTTP/3 request.
    /// 
    /// If succesful, returns a [`PsqStream`]-derived object for handling
    /// the follow-up processing of the stream (and related datagrams),
    /// and body that can include, for example, capsules for additional
    /// tunnel attributes.
    /// Commonly, on unsuccesful cases it returns [`PsqError::HttpResponse`]
    /// with status code and message, that will be propagated to client.
    async fn process_request(
        &mut self,
        request: &[quiche::h3::Header],
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        stream_id: u64,
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>),
                PsqError>;
}

pub mod args;
pub mod config;