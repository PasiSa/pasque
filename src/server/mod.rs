//! The server side operations for incoming HTTP/3 connections

use std::{any::Any, collections::HashMap, fmt::Debug, net::SocketAddr, sync::Arc};

use async_trait::async_trait;
use futures::stream::{FuturesUnordered, StreamExt};
use ring::{hmac::Key, rand::SystemRandom};
use tokio::{
    net::UdpSocket,
    sync::{watch, Mutex},
};

pub use crate::server::config::Config;

use crate::{
    server::clientsession::ClientSession,
    stream::PsqStream,
    util::{send_quic_packets, timeout_watcher, MAX_DATAGRAM_SIZE},
    PsqError, VERSION_IDENTIFICATION,
};

const HMAC_TAG_LEN: usize = 32;

type ClientMap = HashMap<quiche::ConnectionId<'static>, ClientSession>;
type Endpoints = HashMap<String, Box<dyn Endpoint>>;

/// The main server that listens to incoming connections.
pub struct PsqServer {
    sockets: Vec<Arc<UdpSocket>>,
    qconfig: quiche::Config,
    conn_id_seed: ring::hmac::Key,
    clients: ClientMap,
    endpoints: Arc<Mutex<Endpoints>>,
    jwt_secret: Vec<u8>,
    retry_token_key: Key,
}

impl PsqServer {
    /// Initializes and starts the server, binding to the specified socket
    /// addresses.
    ///
    /// Certificates and endpoints are configured based on the provided `config`
    /// (see [Config] for details). To support both IPv4 and IPv6, the `address`
    /// vector typically includes entries like 0.0.0.0:443 and [::]:443.
    pub async fn start(
        addresses: &Vec<SocketAddr>,
        config: &Config,
    ) -> Result<PsqServer, PsqError> {
        info!("Pasque server version {} starting", VERSION_IDENTIFICATION);
        let mut sockets = Vec::new();
        for addr in addresses {
            let socket = UdpSocket::bind(addr)
                .await
                .map_err(|e| PsqError::Custom(format!("Failed to bind to {}: {}", addr, e)))?;
            sockets.push(Arc::new(socket));
        }

        // Create the configuration for the QUIC connections.
        let mut qconfig = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        debug!("Loading cert from: {}", config.cert_file());
        qconfig.load_cert_chain_from_pem_file(&config.cert_file())?;
        debug!("Loading key from: {}", config.key_file());
        qconfig.load_priv_key_from_pem_file(&config.key_file())?;

        qconfig.set_application_protos(quiche::h3::APPLICATION_PROTOCOL)?;

        // TODO: need idle timeout and have some keep-alive to clean up disappeared clients
        qconfig.set_max_idle_timeout(10 * 60 * 1000); // 10 minutes
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
        let conn_id_seed = ring::hmac::Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap();

        let mut server = PsqServer {
            sockets,
            qconfig,
            conn_id_seed,
            clients: ClientMap::new(),
            endpoints: Arc::new(Mutex::new(HashMap::new())),
            jwt_secret: config.jwt_secret().as_bytes().to_vec(),
            retry_token_key: Key::generate(ring::hmac::HMAC_SHA256, &rng).unwrap(),
        };

        config.set_server_endpoints(&mut server).await?;

        Ok(server)
    }

    /// Process incoming UDP datagrams.
    pub async fn process(&mut self) -> Result<(), PsqError> {
        let mut futures = FuturesUnordered::new();
        let socket_count = self.sockets.len();

        for i in 0..socket_count {
            let socket = Arc::clone(&self.sockets[i]);
            futures.push(async move {
                let mut buf = [0u8; MAX_DATAGRAM_SIZE];
                let res = socket.recv_from(&mut buf).await;
                (res, buf, socket)
            });
        }

        if let Some((res, buf, socket)) = futures.next().await {
            let (len, from) = res.map_err(PsqError::Io)?;
            let mut pkt_buf = buf[..len].to_vec();
            self.process_udp(&socket, &mut pkt_buf, from).await?;
        }

        Ok(())
    }

    async fn process_udp(
        &mut self,
        socket: &Arc<UdpSocket>,
        pkt_buf: &mut [u8],
        from: SocketAddr,
    ) -> Result<(), PsqError> {
        // Parse the QUIC packet's header.
        let hdr = match quiche::Header::from_slice(pkt_buf, quiche::MAX_CONN_ID_LEN) {
            Ok(v) => v,

            Err(e) => {
                error!("Parsing packet header failed: {:?}", e);
                return Err(PsqError::Quiche(e));
            }
        };

        trace!("got packet {:?}", hdr);

        let conn_id = ring::hmac::sign(&self.conn_id_seed, &hdr.dcid);
        let conn_id = &conn_id.as_ref()[..quiche::MAX_CONN_ID_LEN];
        let conn_id = conn_id.to_vec().into();

        // Lookup a connection based on the packet's connection ID. If there
        // is no connection matching, create a new one.
        let client = if !self.clients.contains_key(&hdr.dcid)
            && !self.clients.contains_key(&conn_id)
        {
            let mut out = [0; MAX_DATAGRAM_SIZE];

            if hdr.ty != quiche::Type::Initial {
                error!("Packet is not Initial");
                return Err(PsqError::Custom("Packet not initial".to_string()));
            }

            if !quiche::version_is_supported(hdr.version) {
                warn!("Doing version negotiation");

                let len = quiche::negotiate_version(&hdr.scid, &hdr.dcid, &mut out).unwrap();

                let out = &out[..len];

                if let Err(e) = socket.send_to(out, from).await {
                    error!("send() failed: {:?}", e);
                    return Err(PsqError::Io(e));
                }
                return Ok(());
            }

            let mut scid = [0; quiche::MAX_CONN_ID_LEN];
            scid.copy_from_slice(&conn_id);

            let scid = quiche::ConnectionId::from_ref(&scid);

            // Token is always present in Initial packets.
            let token = hdr.token.as_ref().unwrap();

            // Do stateless retry if the client didn't send a token.
            if token.is_empty() {
                warn!("Doing stateless retry");

                let new_token = self.mint_token(&hdr, &from);

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

                if let Err(e) = socket.send_to(out, from).await {
                    error!("send() failed: {:?}", e);
                    return Err(PsqError::Io(e));
                }
                return Ok(());
            }

            let odcid = self.validate_token(&from, token);

            // The token was not valid, meaning the retry failed, so
            // drop the packet.
            if odcid.is_none() {
                error!("Invalid address validation token");
                return Err(PsqError::Custom(
                    "Invalid address validation token".to_string(),
                ));
            }

            if scid.len() != hdr.dcid.len() {
                error!("Invalid destination connection ID");
                return Err(PsqError::Custom(
                    "Invalid destination connection ID".to_string(),
                ));
            }

            // Reuse the source connection ID we sent in the Retry packet,
            // instead of changing it again.
            let scid = hdr.dcid.clone();

            info!(
                "New connection: IP={} dcid={:?} scid={:?}",
                from, hdr.dcid, hdr.scid
            );

            let local_addr = socket.local_addr().unwrap();
            let conn =
                quiche::accept(&scid, odcid.as_ref(), local_addr, from, &mut self.qconfig).unwrap();

            let (tx, rx) = watch::channel(conn.timeout());
            let client = ClientSession::new(
                &Arc::clone(socket),
                conn,
                tx,
                &self.endpoints,
                &self.jwt_secret,
            );

            timeout_watcher(Arc::clone(&client.connection()), Arc::clone(&socket), rx);

            self.clients.insert(scid.clone(), client);
            self.clients.get_mut(&scid).unwrap()
        } else {
            match self.clients.get_mut(&hdr.dcid) {
                Some(v) => v,

                None => self.clients.get_mut(&conn_id).unwrap(),
            }
        };

        let recv_info = quiche::RecvInfo {
            to: socket.local_addr().unwrap(),
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
        self.endpoints
            .lock()
            .await
            .insert(path.to_string(), endpoint);
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
            client.send_packets().await;
        }
    }

    /// Generate a stateless retry token.
    fn mint_token(&self, hdr: &quiche::Header, src: &SocketAddr) -> Vec<u8> {
        let mut token = Vec::new();

        token.extend_from_slice(VERSION_IDENTIFICATION.as_bytes());

        let addr = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        token.extend_from_slice(&addr);
        token.extend_from_slice(&hdr.dcid);

        let tag = ring::hmac::sign(&self.retry_token_key, &token);
        token.extend_from_slice(tag.as_ref());

        token
    }

    /// Validates a stateless retry token.
    ///
    /// This checks the format and integrity of the token using HMAC authentication.
    fn validate_token<'a>(
        &self,
        src: &SocketAddr,
        token: &'a [u8],
    ) -> Option<quiche::ConnectionId<'a>> {
        let prefix = VERSION_IDENTIFICATION.as_bytes();

        if token.len() < prefix.len() {
            return None;
        }

        if &token[..prefix.len()] != prefix {
            return None;
        }

        let addr_bytes = match src.ip() {
            std::net::IpAddr::V4(a) => a.octets().to_vec(),
            std::net::IpAddr::V6(a) => a.octets().to_vec(),
        };

        let min_len = prefix.len() + addr_bytes.len() + 1 + HMAC_TAG_LEN;
        if token.len() < min_len {
            return None;
        }

        let hmac_offset = token.len() - HMAC_TAG_LEN;
        let (data, tag) = token.split_at(hmac_offset);

        if ring::hmac::verify(&self.retry_token_key, data, tag).is_err() {
            return None;
        }

        let dcid_offset = prefix.len() + addr_bytes.len();
        let dcid_len = token.len() - dcid_offset - HMAC_TAG_LEN;
        let dcid = &token[dcid_offset..dcid_offset + dcid_len];

        Some(quiche::ConnectionId::from_ref(dcid))
    }
}

fn build_h3_resp_headers(status: u16, body: &Vec<u8>) -> Vec<quiche::h3::Header> {
    let headers = vec![
        quiche::h3::Header::new(b":status", status.to_string().as_bytes()),
        quiche::h3::Header::new(
            b"server",
            format!("pasque/{}", VERSION_IDENTIFICATION).as_bytes(),
        ),
        // lazily include capsule-protocol in all responses (also GET)
        quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        quiche::h3::Header::new(b"content-length", body.len().to_string().as_bytes()),
    ];
    headers
}

fn build_h3_response(status: u16, msg: &str) -> (Vec<quiche::h3::Header>, Vec<u8>, bool) {
    let body = msg.as_bytes().to_vec();
    (build_h3_resp_headers(status, &body), body, true)
}

#[async_trait]
/// Base trait for different Endpoint types at the server.
pub trait Endpoint: Send + Sync + Debug + Any {
    /// Process incoming HTTP/3 request.
    ///
    /// If successful, returns a [`PsqStream`]-derived object for handling
    /// the follow-up processing of the stream (and related datagrams),
    /// and body that can include, for example, capsules for additional
    /// tunnel attributes.
    /// Commonly, on unsuccessful cases it returns [`PsqError::HttpResponse`]
    /// with status code and message, that will be propagated to client.
    async fn process_request(
        &mut self,
        request: &[quiche::h3::Header],
        conn: &Arc<Mutex<quiche::Connection>>,
        socket: &Arc<UdpSocket>,
        stream_id: u64,
        jwt_secret: &Vec<u8>,
    ) -> Result<(Option<Box<dyn PsqStream + Send + Sync + 'static>>, Vec<u8>), PsqError>;

    fn as_any(&self) -> &dyn Any;
}

pub mod clientsession;
pub mod config;

#[cfg(test)]
mod tests {
    use crate::{Files, IpEndpoint, UdpEndpoint};

    use super::*;

    #[tokio::test]
    async fn read_endpoint_config() {
        let config = Config::read_from_file("tests/endpoints.json").unwrap();
        let psqserver = PsqServer::start(&vec!["0.0.0.0:4433".parse().unwrap()], &config)
            .await
            .unwrap();
        let endpoints = psqserver.endpoints.lock().await;

        let ip = endpoints
            .get("ip")
            .unwrap()
            .as_any()
            .downcast_ref::<IpEndpoint>()
            .unwrap();
        assert!(format!("{:?}", ip) == "IpEndpoint(tun-s0 10.76.0.1/24 fd76:212:dead::1/48)");

        let udp = endpoints
            .get("udp")
            .unwrap()
            .as_any()
            .downcast_ref::<UdpEndpoint>()
            .unwrap();
        assert!(format!("{:?}", udp) == "UdpEndpoint()");

        let files = endpoints
            .get("files")
            .unwrap()
            .as_any()
            .downcast_ref::<Files>()
            .unwrap();
        assert!(format!("{:?}", files) == "Files(.)");
    }
}
