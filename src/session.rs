use mio::net::UdpSocket;
use ring::rand::*;

use crate::config::Config;

const MAX_DATAGRAM_SIZE: usize = 1350;

pub struct PsqSession {
    config: Config,
    socket: UdpSocket,
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    url: url::Url,
    req_sent: bool,
}

impl PsqSession {
    pub fn connect(urlstr: &str, config: Config) -> PsqSession {
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
            mio::net::UdpSocket::bind(bind_addr.parse().unwrap()).unwrap();

            // Create the configuration for the QUIC connection.
        let mut qconfig = quiche::Config::new(quiche::PROTOCOL_VERSION).unwrap();

        // *CAUTION*: this should not be set to `false` in production!!!
        qconfig.verify_peer(false);

        qconfig
            .set_application_protos(quiche::h3::APPLICATION_PROTOCOL)
            .unwrap();

        qconfig.set_max_idle_timeout(5000);
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

        while let Err(e) = socket.send_to(&out[..write], send_info.to) {
            if e.kind() == std::io::ErrorKind::WouldBlock {
                debug!("send() would block");
                continue;
            }

            panic!("send() failed: {:?}", e);
        }
        PsqSession { config, socket, conn, h3_conn: None, url, req_sent: false }

    }


    pub fn register_mio_poll(&mut self, poll: &mio::Poll) {
        // TODO: to suppress warning of unused config member, remove later...
        debug!("TUN IP local is {}", self.config.tun_ip_local());  
        poll.registry()
            .register(&mut self.socket, mio::Token(0), mio::Interest::READABLE)
            .unwrap();
    }


    pub fn process_events(&mut self, events: &mio::Events) {
        let mut buf = [0; 65535];

        if events.is_empty() {
            debug!("timed out");

            self.conn.on_timeout();
            return;
        }

        for event in events {
            if event.token() == mio::Token(0) {
                'read: loop {
                    let (len, from) = match self.socket.recv_from(&mut buf) {
                        Ok(v) => v,

                        Err(e) => {
                            // There are no more UDP packets to read, so end the read
                            // loop.
                            if e.kind() == std::io::ErrorKind::WouldBlock {
                                debug!("recv() would block");
                                break 'read;
                            }

                            panic!("recv() failed: {:?}", e);
                        },
                    };

                    let local_addr = self.socket.local_addr().unwrap();
                    let recv_info = quiche::RecvInfo {
                        to: local_addr,
                        from,
                    };

                    // Process potentially coalesced packets.
                    let _read = match self.conn.recv(&mut buf[..len], recv_info) {
                        Ok(v) => v,

                        Err(e) => {
                            error!("recv failed: {:?}", e);
                            continue 'read;
                        },
                    };
                }
                self.process(&mut buf);
            }
        }
    }


    pub fn send_packets(&mut self) {
        // Generate outgoing QUIC packets and send them on the UDP socket, until
        // quiche reports that there are no more packets to be sent.
        let mut out = [0; MAX_DATAGRAM_SIZE];
        loop {
            let (write, send_info) = match self.conn.send(&mut out) {
                Ok(v) => v,

                Err(quiche::Error::Done) => {
                    //debug!("done writing");
                    break;
                },

                Err(e) => {
                    error!("send failed: {:?}", e);

                    self.conn.close(false, 0x1, b"fail").ok();
                    break;
                },
            };

            if let Err(e) = self.socket.send_to(&out[..write], send_info.to) {
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    debug!("send() would block");
                    break;
                }

                panic!("send() failed: {:?}", e);
            }
        }
    }


    pub fn connection(&mut self) -> &mut quiche::Connection {
        &mut self.conn
    }

    fn process(&mut self, buf: &mut [u8]) {
        // Create a new HTTP/3 connection once the QUIC connection is established.
        if self.conn.is_established() && self.h3_conn.is_none() {
            let mut h3_config = quiche::h3::Config::new().unwrap();
            h3_config.enable_extended_connect(true);
    
            self.h3_conn = Some(
                quiche::h3::Connection::with_transport(&mut self.conn, &h3_config)
                .expect("Unable to create HTTP/3 connection, check the server's uni stream limit and window size"),
            );
        }

        // Send HTTP requests once the QUIC connection is established, and until
        // all requests have been sent.
        if let Some(h3_conn) = &mut self.h3_conn {
            if !self.req_sent {
                let req = Self::prepare_request(&self.url);
                info!("sending HTTP request {:?}", req);

                h3_conn.send_request(&mut self.conn, &req, true).unwrap();

                self.req_sent = true;
            }
        }

        if let Some(http3_conn) = &mut self.h3_conn {
            // Process HTTP/3 events.
            loop {
                match http3_conn.poll(&mut self.conn) {
                    Ok((stream_id, quiche::h3::Event::Headers { list, .. })) => {
                        info!(
                            "got response headers {:?} on stream id {}",
                            crate::hdrs_to_strings(&list),
                            stream_id
                        );
                        crate::send_h3_dgram(&mut self.conn, stream_id, b"Hello").unwrap();
                    },

                    Ok((stream_id, quiche::h3::Event::Data)) => {
                        while let Ok(read) =
                            http3_conn.recv_body(&mut self.conn, stream_id, buf)
                        {
                            debug!(
                                "got {} bytes of response data on stream {}",
                                read, stream_id
                            );

                            print!("{}", unsafe {
                                std::str::from_utf8_unchecked(&buf[..read])
                            });
                        }
                    },

                    Ok((_stream_id, quiche::h3::Event::Finished)) => {
                        info!(
                            "response received in XX, closing..."
                        );
                    },

                    Ok((_stream_id, quiche::h3::Event::Reset(e))) => {
                        error!(
                            "request was reset by peer with {}, closing...",
                            e
                        );

                        self.conn.close(true, 0x100, b"kthxbye").unwrap();
                    },

                    Ok((_, quiche::h3::Event::PriorityUpdate)) => unreachable!(),

                    Ok((goaway_id, quiche::h3::Event::GoAway)) => {
                        info!("GOAWAY id={}", goaway_id);
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
    }


    pub fn get_timeout(&self) -> Option<std::time::Duration> {
        self.conn.timeout()
    }


    fn prepare_request(url: &url::Url) -> Vec<quiche::h3::Header> {
        let mut path = String::from(url.path());

        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }
    
        vec![
            quiche::h3::Header::new(b":method", b"CONNECT"),
            quiche::h3::Header::new(b":protocol", b"connect-ip"),
            quiche::h3::Header::new(b":scheme", url.scheme().as_bytes()),
            quiche::h3::Header::new(
                b":authority",
                url.host_str().unwrap().as_bytes(),
            ),
            quiche::h3::Header::new(b":path", path.as_bytes()),
            quiche::h3::Header::new(b"user-agent", b"pasque"),
            quiche::h3::Header::new(b"capsule-protocol", b"?1"),
        ]
    }    
}


fn hex_dump(buf: &[u8]) -> String {
    let vec: Vec<String> = buf.iter().map(|b| format!("{b:02x}")).collect();

    vec.join("")
}
