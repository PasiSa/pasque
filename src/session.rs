pub struct PsqSession {
    conn: quiche::Connection,
    h3_conn: Option<quiche::h3::Connection>,
    url: url::Url,
    req_sent: bool,
}

impl PsqSession {
    pub fn new(conn: quiche::Connection, urlstr: &str) -> PsqSession {
        let url = url::Url::parse(&urlstr).unwrap();
            
        // Prepare request.
        let mut path = String::from(url.path());
    
        if let Some(query) = url.query() {
            path.push('?');
            path.push_str(query);
        }

        PsqSession { conn, h3_conn: None, url, req_sent: false }
    }


    pub fn connection(&mut self) -> &mut quiche::Connection {
        &mut self.conn
    }

    pub fn process(&mut self, buf: &mut [u8]) {

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
