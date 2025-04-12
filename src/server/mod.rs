use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::Arc,
};

use async_trait::async_trait;
use ring::rand::SystemRandom;
use tokio::{
    net::UdpSocket,
    sync::{watch, Mutex},
};

use crate::{
    PsqError,
    server::{
        config::Config,
        clientsession::ClientSession,
    },
    stream::PsqStream,
    util::{
        MAX_DATAGRAM_SIZE,
        send_quic_packets,
        timeout_watcher,
    },
    VERSION_IDENTIFICATION,
};


type ClientMap = HashMap<quiche::ConnectionId<'static>, ClientSession>;
type Endpoints = HashMap<String, Box<dyn Endpoint>>;


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
            let client = ClientSession::new(
                &self.socket,
                conn,
                tx,
                &self.endpoints,
            );
            /*let client = ClientSession {
                socket: Arc::clone(&self.socket),
                conn: Arc::new(Mutex::new(conn)),
                http3_conn: None,
                partial_responses: HashMap::new(),
                timeout_tx: tx,
                streams: HashMap::new(),
                endpoints: Arc::clone(&self.endpoints),
            };*/
            timeout_watcher(
                Arc::clone(&client.connection()),
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

        if client.h3_connection().is_some() {
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
            let conn = client.connection().lock().await;
            if conn.is_closed() {
                info!(
                    "{} connection collected {:?}",
                    conn.trace_id(),
                    conn.stats()
                );
                remove_keys.push(key.clone());
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
            if let Err(e) = send_quic_packets(&client.connection(), &self.socket).await {
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

pub mod clientsession;
pub mod config;
