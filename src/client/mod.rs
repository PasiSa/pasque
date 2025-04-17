use std::{
    collections::HashMap,
    sync::Arc,
};

use ring::rand::*;

use tokio::{
    net::UdpSocket,
    time::Duration,
    sync::{watch, Mutex},
};

use crate::{
    PsqError,
    stream::{process_h3_datagram, PsqStream},
    util::{send_quic_packets, timeout_watcher},
};

const MAX_DATAGRAM_SIZE: usize = 1350;

/// HTTP/3 & QUIC connection that is used to set up streams for different
/// proxy / tunnel sessions.
pub struct PsqClient {
    socket: Arc<UdpSocket>,
    conn: Arc<Mutex<quiche::Connection>>,
    h3_conn: Option<quiche::h3::Connection>,
    url: url::Url,
    streams: HashMap<u64, Box<dyn PsqStream>>,
    timeout_tx: watch::Sender<Option<Duration>>,
}

impl PsqClient {
    pub async fn connect(
        urlstr: &str,
        ignore_cert: bool,
    ) -> Result<PsqClient, PsqError> {

        let url = url::Url::parse(&urlstr).unwrap();

        // Resolve server address.
        let peer_addr = url.socket_addrs(|| None).unwrap()[0];

        // Bind to INADDR_ANY or IN6ADDR_ANY depending on the IP family of the
        // server address. This is needed on macOS and BSD variants that don't
        // support binding to IN6ADDR_ANY for both v4 and v6.
        let bind_addr = match peer_addr {
            std::net::SocketAddr::V4(_) => "0.0.0.0:0",
            std::net::SocketAddr::V6(_) => "[::]:0",
        };

        let socket =
            tokio::net::UdpSocket::bind(bind_addr).await.unwrap();

        // Create the configuration for the QUIC connection.
        let mut qconfig = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        qconfig.verify_peer(!ignore_cert);

        qconfig
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        qconfig.set_max_recv_udp_payload_size(MAX_DATAGRAM_SIZE);
        qconfig.set_max_send_udp_payload_size(MAX_DATAGRAM_SIZE);
        qconfig.set_initial_max_data(10_000_000);
        qconfig.set_initial_max_stream_data_bidi_local(1_000_000);
        qconfig.set_initial_max_stream_data_bidi_remote(1_000_000);
        qconfig.set_initial_max_stream_data_uni(1_000_000);
        qconfig.set_initial_max_streams_bidi(100);
        qconfig.set_initial_max_streams_uni(100);
        qconfig.set_disable_active_migration(true);

        qconfig.enable_dgram(true, 30000, 30000);

        // Generate a random source connection ID for the connection.
        let mut scid = [0; quiche::MAX_CONN_ID_LEN];
        SystemRandom::new().fill(&mut scid[..]).unwrap();

        let scid = quiche::ConnectionId::from_ref(&scid);

        // Get local address.
        let local_addr = socket.local_addr().unwrap();

        // Create a QUIC connection and initiate handshake.
        let mut conn =
            quiche::connect(url.domain(), &scid, local_addr, peer_addr, &mut qconfig)
                .unwrap();
        crate::set_qlog(&mut conn, &scid);

        info!(
            "connecting to {:} from {:} with scid {}",
            peer_addr,
            socket.local_addr().unwrap(),
            hex_dump(&scid)
        );

        let mut out = [0; MAX_DATAGRAM_SIZE];
        let (write, send_info) = conn.send(&mut out).expect("initial send failed");

        if let Err(e) = socket.send_to(&out[..write], send_info.to).await {
            panic!("send() failed: {:?}", e);
        }
        let (tx, rx) = watch::channel(conn.timeout());
        let mut this = PsqClient {
            socket: Arc::new(socket),
            conn: Arc::new(Mutex::new(conn)),
            h3_conn: None,
            url,
            streams: HashMap::new(),
            timeout_tx: tx,
        };
        timeout_watcher(
            Arc::clone(&this.conn),
            Arc::clone(&this.socket),
            rx,
        );
        this.finish_connect().await?;   // complete when HTTP/3 connection is set up

        Ok(this)
    }


    async fn finish_connect(&mut self) -> Result<(), PsqError> {
        while self.h3_conn.is_none() {
            self.process().await?;
        }
        Ok(())
    }


    pub async fn process(&mut self) -> Result<(), PsqError> {
        let mut buf = [0; 65535];

        self.set_timeout(self.conn.lock().await.timeout());

        let (len, from) = match self.socket.recv_from(&mut buf).await {
            Ok(v) => v,

            Err(e) => {
                panic!("recv() failed: {:?}", e);
            },
        };
        //debug!("from socket {} bytes", len);

        let local_addr = self.socket.local_addr().unwrap();
        let recv_info = quiche::RecvInfo {
            to: local_addr,
            from,
        };

        // Process potentially coalesced packets.
        let _read = match self.conn.lock().await.recv(&mut buf[..len], recv_info) {
            Ok(v) => v,

            Err(e) => {
                error!("recv failed: {:?}", e);
                return Err(PsqError::Quiche(e))
            },
        };

        if self.conn.lock().await.is_closed() {
            info!("connection closed, {:?}", self.conn.lock().await.stats());
            return Ok(())
        }
        self.process_h3(&mut buf).await?;

        // Process Datagrams
        let mut buf = [0; 10000];
        match self.conn.lock().await.dgram_recv(&mut buf) {
            Ok(n) => {
                //debug!("Datagram received, {} bytes", n);
                let (stream_id, offset) = match process_h3_datagram(&buf) {
                    Ok((stream, off)) => (stream, off),
                    Err(e) => {
                        error!("Error processing HTTP/3 capsule: {}", e);
                        return send_quic_packets(&self.conn, &self.socket).await
                    },
                };

                let stream = self.streams.get_mut(&stream_id);
                if stream.is_none() {
                    warn!("Datagram received but no matching stream");
                } else {
                    if let Err(e) = stream.unwrap().process_datagram(&buf[offset..n]).await {
                        error!("Error processing HTTP datagram: {}", e);
                    }
                }
            },
            Err(e) => {
                if e != quiche::Error::Done {
                    error!("Error receiving datagram: {}", e);
                }
            },
        }

        send_quic_packets(&self.conn, &self.socket).await
    }


    pub fn connection(&mut self) -> Arc<Mutex<quiche::Connection>> {
        self.conn.clone()
    }


    // TODO: Remove option, replace it with Result with error if connection not specified
    pub fn h3_connection(&mut self) -> &mut Option<quiche::h3::Connection> {
        &mut self.h3_conn
    }


    pub fn get_url(&self) -> &url::Url {
        &self.url
    }


    /// Adds new stream to connection. Blocks until HTTP request is replied.
    pub (crate) async fn add_stream(
        &mut self,
        stream_id: u64,
        stream: Box<dyn PsqStream>,
    ) -> Result<&Box<dyn PsqStream>, PsqError> {

        self.streams.insert(stream_id, stream);

        // Ensure that the HTTP request gets actually sent
        send_quic_packets(&self.conn, &self.socket).await?;
        loop {
            let pstream = match self.streams.get(&stream_id) {
                Some(pstream) => pstream,
                None => return Err(
                    PsqError::StreamClose(format!("Stream {} removed", stream_id))
                ),
            };
            if pstream.is_ready() {
                break;
            }
            self.process().await?;
        }
        Ok(self.streams.get(&stream_id).unwrap())
    }


    fn set_timeout(&self, new_duration: Option<Duration>) {
        let _ = self.timeout_tx.send(new_duration);
    }


    async fn process_h3(&mut self, buf: &mut [u8]) -> Result<(), PsqError> {
        // Create a new HTTP/3 connection once the QUIC connection is established.
        {
            let mut conn = self.conn.lock().await;
            if conn.is_established() && self.h3_conn.is_none() {
                let mut h3_config = quiche::h3::Config::new().unwrap();
                h3_config.enable_extended_connect(true);
        
                self.h3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }

            if self.h3_conn.is_none() {
                // No HTTP/3 connection yet ==> nothing further to process
                return Ok(());
            }
        }

        // Process HTTP/3 events.
        loop {
            match self.poll_helper().await {
                Ok((stream_id, event)) => {
                    let stream = self.streams.get_mut(&stream_id);
                    if stream.is_some() {
                        if let Err(e) = stream.unwrap().process_h3_response(
                            &mut self.h3_conn.as_mut().unwrap(),
                            &self.conn,
                            &self.socket,
                            event,
                            buf
                        ).await {
                            match e {
                                PsqError::StreamClose(_) => {
                                    self.remove_stream(stream_id).await;
                                },
                                _ => return Err(e)
                            }
                        }
                    } else {
                        error!("Received unknown stream ID: {}", stream_id);
                        continue;
                    }
                },

                Err(quiche::h3::Error::Done) => {
                    return Ok(())
                },

                Err(e) => {
                    error!("HTTP/3 processing failed: {:?}", e);
                    return Err(PsqError::Http3(e))
                },
            }
        }
    }


    /// Shuts down stream with given stream ID.
    /// 
    /// Also cleans up all resources used by the stream. If the given stream is not
    /// active anymore, this function does not do anything.
    pub async fn remove_stream(&mut self, stream_id: u64) {
        debug!("Removing stream: {}", stream_id);
        if let Err(e) = self.conn.lock().await.stream_shutdown(stream_id, quiche::Shutdown::Read, 0) {
            warn!("Could not send shutdown message: {}", e);
        }
        self.streams.remove(&stream_id);
    }


    async fn poll_helper(&mut self) -> Result<(u64, quiche::h3::Event), quiche::h3::Error> {
        let mut conn = &mut *self.conn.lock().await;
        self.h3_conn.as_mut().unwrap().poll(&mut conn)
    }

}


fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}
