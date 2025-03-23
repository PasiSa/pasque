use std::sync::Arc;

use ring::rand::*;
use tokio::net::UdpSocket;
use tokio::time::{sleep, Duration};
use tokio::sync::{watch, Mutex};

use crate::config::Config;
use crate::stream::PsqStream;

const MAX_DATAGRAM_SIZE: usize = 1350;

/// HTTP/3 & QUIC connection that is used to set up streams for different
/// proxy / tunnel sessions.
pub struct PsqConnection {
    config: Config,
    socket: UdpSocket,
    conn: Arc<Mutex<quiche::Connection>>,
    h3_conn: Option<quiche::h3::Connection>,
    url: url::Url,
    req_sent: bool,
    psqstream: Option<PsqStream>,
    timeout_tx: watch::Sender<Option<Duration>>,
}

impl PsqConnection {
    pub async fn connect(urlstr: &str, config: Config) -> Arc<Mutex<PsqConnection>> {
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

        // *CAUTION*: this should not be set to `false` in production!!!
        qconfig.verify_peer(false);

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
        let this = Arc::new(Mutex::new(
            PsqConnection {
                config,
                socket,
                conn: Arc::new(Mutex::new(conn)),
                h3_conn: None,
                url,
                req_sent: false,
                psqstream: None,
                timeout_tx: tx,
            }
        ));
        Self::timeout_watcher(Arc::clone(&this), rx);
        this
    }


    pub async fn process(&mut self) {
        let mut buf = [0; 65535];

        self.set_timeout(self.conn.lock().await.timeout());

        let (len, from) = match self.socket.recv_from(&mut buf).await {
            Ok(v) => v,

            Err(e) => {
                panic!("recv() failed: {:?}", e);
            },
        };
        debug!("from socket {} bytes", len);

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
                return;
            },
        };

        if self.conn.lock().await.is_closed() {
            info!("connection closed, {:?}", self.conn.lock().await.stats());
            return;
        }
        self.process_h3(&mut buf).await;
        self.send_packets().await;
    }


    fn timeout_watcher(this: Arc<Mutex<Self>>, mut rx: watch::Receiver<Option<Duration>>) {
        tokio::spawn(async move {
            loop {
                let duration = *rx.borrow_and_update();
                // if we do not have timeout to set, sleep for 100 years.
                // Maybe someday we have proper implementation.
                let sleep_future = sleep(duration.unwrap_or(Duration::from_secs(100 * 365 * 24 * 60 * 60)));
                tokio::pin!(sleep_future);

                tokio::select! {
                    _ = &mut sleep_future => {
                        let mut locked = this.lock().await;
                        locked.on_timeout().await;
                        // Optionally break or restart loop
                        break;
                    }
                    changed = rx.changed() => {
                        if changed.is_ok() {
                            // New duration was received, loop will recreate sleep
                            println!("[Watcher] Timeout changed to {:?}", *rx.borrow());
                            continue;
                        } else {
                            break; // channel closed
                        }
                    }
                }
            }
        });
    }


    async fn on_timeout(&mut self) {
        debug!("timeout occurred");
        self.conn.lock().await.on_timeout();
    }


    fn set_timeout(&self, new_duration: Option<Duration>) {
        let _ = self.timeout_tx.send(new_duration);
    }


    async fn send_packets(&mut self) {
        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        let mut out = [0; MAX_DATAGRAM_SIZE];
        loop {
            let (write, send_info) = match self.conn.lock().await.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    //debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    self.conn.lock().await.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = self.socket.send_to(&out[..write], send_info.to).await {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }
        }
    }


    async fn process_h3(&mut self, buf: &mut [u8]) {
        // Create a new HTTP/3 connection once the QUIC connection is established.
        {
            debug!("process_h3");
            let mut conn = self.conn.lock().await;
            if conn.is_established() && self.h3_conn.is_none() {
                let mut h3_config = quiche::h3::Config::new().unwrap();
                h3_config.enable_extended_connect(true);
        
                self.h3_conn = Some(
                    quiche::h3::Connection::with_transport(&mut conn, &h3_config)
                    .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
                );
            }
            debug!("h3_conn exists");

            if self.h3_conn.is_none() {
                // No HTTP/3 connection yet ==> nothing further to process
                return;
            }
            // Send HTTP requests once the QUIC connection is established, and until
            // all requests have been sent.
            if !self.req_sent {
                self.psqstream = Some(PsqStream::h3_request(
                    &mut self.h3_conn.as_mut().unwrap(),
                    &mut conn,
                    &self.url,
                ));

                self.req_sent = true;
            }
        }
        // Process HTTP/3 events.
        loop {
            match self.poll_helper().await {
                Ok((_stream_id, event)) => {
                    // Currently assuming only one stream, will be changed in future
                    self.psqstream.as_mut().unwrap().process_h3_response(
                        &mut self.h3_conn.as_mut().unwrap(),
                        Arc::clone(&self.conn),
                        &self.config,
                        event,
                        buf
                    ).await;
                },

                Err(quiche::h3::Error::Done) => {
                    break;
                },

                Err(e) => {
                    error!("HTTP/3 processing failed: {:?}", e);

                    break;
                },
            }
        }
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
